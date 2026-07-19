"""
tasks/sandbox_analysis.py
==========================
Stage 2 of the AEGIS Celery pipeline: detonates a URL in an isolated
Playwright sandbox container and waits for the result artifacts.

Security hardening (finding #3 fix):
  The Docker SDK/CLI now communicates with the sandbox container via the
  docker_socket_proxy service (Tecnativa/docker-socket-proxy) rather than
  the raw /var/run/docker.sock mount. The DOCKER_HOST environment variable
  in the celery_worker container is set to tcp://docker_socket_proxy:2375,
  so `docker run` commands issued here automatically route through the proxy
  instead of the host daemon socket.

  The proxy only exposes CONTAINERS=1 and POST=1 — enough to create and
  start the sandbox container but nothing else (no exec, no image pull,
  no host-level escape vectors).

Network isolation (finding #9 fix):
  The sandbox container is attached to `sandbox_net` only (defined in
  docker-compose.yml). It cannot reach aegis_net, Postgres, or Redis even
  if Chromium is fully compromised. The Celery worker that invokes it lives
  on aegis_net and communicates only via the shared_scans volume.
"""

import asyncio
import glob
import json
import logging
import os
import urllib.request
import urllib.error
from typing import Tuple

from celery_worker import celery
from config import settings
from services.malware_scanner import scan_file_clamav
from database.database import get_db_session
from database.models import Scan, NetworkActivity, TLSConnection, FormMetrics, Download, Redirect, EvasionTechnique
from tasks import validate_scan_id

logger = logging.getLogger(__name__)

SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", settings.SANDBOX_IMAGE)
SHARED_VOLUME_NAME = os.environ.get("SHARED_SCANS_VOLUME", settings.SHARED_SCANS_VOLUME)
SANDBOX_RUNNER_URL = os.environ.get("SANDBOX_RUNNER_URL", "http://aegis_sandbox_runner:8002/detonate")
SANDBOX_RUNNER_SECRET = os.environ.get("SANDBOX_RUNNER_SECRET", settings.SANDBOX_RUNNER_SECRET)


def _scan_dir(scan_id: str) -> str:
    validate_scan_id(scan_id)
    return os.path.join(settings.SHARED_DIR, scan_id)


def _mark_status(scan_id: str, status: str) -> None:
    try:
        with get_db_session() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = status
                db.commit()
    except Exception:
        logger.exception("Failed to update scan status to %s for %s", status, scan_id)


def _get_scan_url(scan_id: str) -> str:
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None or not scan.url:
            raise ValueError(f"Scan {scan_id} has no URL to detonate")
        return scan.url


async def _run_sandbox_container(scan_id: str, target_url: str, timeout_sec: int) -> None:
    """
    Invoke the aegis_sandbox_runner microservice over HTTP (`POST /detonate`)
    instead of calling `docker run` directly.

    Security Hardening (DevSecOps Critical Finding #1):
      Celery workers process untrusted screenshots and image bytes. By offloading
      container detonation to the single-purpose `aegis_sandbox_runner` service,
      the Celery worker has ZERO access to the Docker API (`docker_socket_proxy`).
      If an attacker achieves parser RCE inside the worker via pytesseract or
      OpenCV, they cannot call `docker run -v /:/host` or `privileged: true`.
    """
    logger.info("[%s] Requesting admission control detonation via %s", scan_id, SANDBOX_RUNNER_URL)

    payload = json.dumps({
        "scan_id": scan_id,
        "target_url": target_url,
        "timeout_sec": timeout_sec,
    }).encode("utf-8")

    def _do_rpc():
        req = urllib.request.Request(
            SANDBOX_RUNNER_URL,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Runner-Auth": SANDBOX_RUNNER_SECRET,
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout_sec + 15) as resp:  # nosec B310
            return json.loads(resp.read().decode("utf-8"))

    try:
        resp_data = await asyncio.to_thread(_do_rpc)
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="ignore")[:1000]
        raise RuntimeError(f"Sandbox runner service failed (HTTP {e.code}) for scan {scan_id}: {err_body}")
    except Exception as e:
        raise RuntimeError(f"Could not reach sandbox runner service for scan {scan_id}: {e}")

    if resp_data.get("status") != "success" or resp_data.get("returncode") != 0:
        raise RuntimeError(f"Sandbox detonation failed for scan {scan_id}: {resp_data}")

    logger.debug("[%s] Sandbox runner response: %s", scan_id, resp_data)


def _find_result_by_request_id(scan_id: str) -> Tuple[str, dict]:
    """
    Returns (json_path, data) for the sandbox result whose
    scans.request_id matches our scan_id. Raises FileNotFoundError if
    no match is found.
    """
    validate_scan_id(scan_id)
    scan_dir = os.path.join(settings.SHARED_DIR, scan_id)
    exact_path = os.path.join(scan_dir, f"scan_{scan_id}.json")
    if os.path.exists(exact_path):
        try:
            with open(exact_path) as f:
                data = json.load(f)
            if data.get("scans", {}).get("request_id") == scan_id:
                return exact_path, data
        except (json.JSONDecodeError, OSError):
            pass

    # Check any scan_*.json inside scan_dir before volume-wide globbing
    if os.path.isdir(scan_dir):
        for path in glob.glob(os.path.join(scan_dir, "scan_*.json")):
            if path == exact_path:
                continue
            try:
                with open(path) as f:
                    data = json.load(f)
                if data.get("scans", {}).get("request_id") == scan_id:
                    return path, data
            except (json.JSONDecodeError, OSError):
                continue

    if getattr(settings, "ALLOW_GLOB_FALLBACK", False):
        candidates = glob.glob(os.path.join(settings.SHARED_DIR, "scan_*.json")) + glob.glob(os.path.join(settings.SHARED_DIR, "*", "scan_*.json"))
        for path in candidates:
            try:
                with open(path) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            if data.get("scans", {}).get("request_id") == scan_id:
                return path, data
    raise FileNotFoundError(f"No sandbox result found for scan {scan_id} in {settings.SHARED_DIR}")


def _cleanup_sandbox_root_files(json_path: str, sandbox_result: dict) -> None:
    """
    The sandbox container writes its own JSON and BOTH screenshots flat
    into the shared volume ROOT or per-scan subdirectory -- only the homepage
    screenshot gets renamed/moved to sandbox.png by the caller below.
    Delete leftover raw JSON and full-page screenshots after processing.
    """
    candidates = [json_path]
    full_page_path = sandbox_result.get("screenshots", {}).get("fullpage_screenshot_path")
    if full_page_path:
        if not os.path.exists(full_page_path):
            req_id = sandbox_result.get("scans", {}).get("request_id") or ""
            for worker_full in (
                os.path.join(settings.SHARED_DIR, req_id, os.path.basename(full_page_path)) if req_id else None,
                os.path.join(settings.SHARED_DIR, os.path.basename(full_page_path)),
            ):
                if worker_full and os.path.exists(worker_full):
                    full_page_path = worker_full
                    break
        candidates.append(full_page_path)

    for path in candidates:
        try:
            if path and os.path.exists(path):
                os.remove(path)
        except OSError:
            logger.warning("Could not remove leftover sandbox file %s", path, exc_info=True)


def _call_sandbox(scan_id: str) -> dict:
    target_url = _get_scan_url(scan_id)
    timeout_sec = getattr(settings, "SANDBOX_TIMEOUT_SEC", 120)

    asyncio.run(_run_sandbox_container(scan_id, target_url, timeout_sec))
    json_path, sandbox_result = _find_result_by_request_id(scan_id)
    sandbox_result["_source_json_path"] = json_path  # internal only, stripped before persisting

    # Anti-malware check (ClamAV) on generated artifacts & downloads
    is_clean, details = scan_file_clamav(json_path)
    full_page_path = sandbox_result.get("screenshots", {}).get("fullpage_screenshot_path")
    if full_page_path:
        if not os.path.exists(full_page_path):
            for cand in (
                os.path.join(settings.SHARED_DIR, scan_id, os.path.basename(full_page_path)),
                os.path.join(settings.SHARED_DIR, os.path.basename(full_page_path)),
            ):
                if os.path.exists(cand):
                    full_page_path = cand
                    break
        if os.path.exists(full_page_path):
            clean_screenshot, scr_details = scan_file_clamav(full_page_path)
            if not clean_screenshot:
                is_clean = False
                details += f" | Screenshot: {scr_details}"

    for drow in sandbox_result.get("downloads", []):
        qpath = drow.get("quarantined_path")
        if qpath:
            if not os.path.exists(qpath):
                for qcand in (
                    os.path.join(settings.SHARED_DIR, scan_id, "quarantine", os.path.basename(qpath)),
                    os.path.join(settings.SHARED_DIR, "quarantine", os.path.basename(qpath)),
                ):
                    if os.path.exists(qcand):
                        qpath = qcand
                        break
            if os.path.exists(qpath):
                clean_dl, dl_details = scan_file_clamav(qpath)
                drow["malware_scan"] = {"is_clean": clean_dl, "details": dl_details}
                if not clean_dl:
                    is_clean = False
                    details += f" | Download '{drow.get('file_name', 'bin')}': {dl_details}"

    sandbox_result["malware_scan"] = {
        "is_clean": is_clean,
        "details": details
    }
    if not is_clean:
        logger.warning("[ClamAV Alert] Scan %s produced malicious artifact: %s", scan_id, details)

    return sandbox_result


@celery.task(
    bind=True,
    name="tasks.sandbox_analysis",
    queue="sandbox",
    max_retries=3,
    default_retry_delay=15,
    acks_late=True,
)
def sandbox_analysis_task(self, scan_id: str):
    validate_scan_id(scan_id)
    logger.info("[%s] Stage 2 (sandbox_analysis) started", scan_id)
    _mark_status(scan_id, "sandbox_analysis_running")

    scan_dir = _scan_dir(scan_id)
    os.makedirs(scan_dir, exist_ok=True)
    try:
        os.chmod(scan_dir, 0o770)  # nosec B103
    except OSError:
        pass

    try:
        sandbox_result = _call_sandbox(scan_id)
        if sandbox_result.get("error"):
            raise ValueError(f"Sandbox returned an error: {sandbox_result['error']}")
    except Exception as exc:
        logger.exception("[%s] Sandbox call failed", scan_id)
        if self.request.retries >= self.max_retries:
            _mark_status(scan_id, "sandbox_analysis_failed")
        else:
            _mark_status(scan_id, "sandbox_analysis_retrying")
        raise self.retry(exc=exc)

    source_json_path = sandbox_result.pop("_source_json_path", None)

    metadata_path = os.path.join(scan_dir, "sandbox_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(sandbox_result, f, indent=2, default=str)

    try:
        _save_telemetry_to_postgres(scan_id, sandbox_result)
    except Exception:
        logger.exception("[%s] Failed to ingest sandbox telemetry to Postgres", scan_id)

    screenshots = sandbox_result.get("screenshots", {})
    for key, dst_name in (("homepage_screenshot_path", "sandbox.png"),):
        src = screenshots.get(key)
        if src and not os.path.exists(src):
            for cand in (
                os.path.join(scan_dir, os.path.basename(src)),
                os.path.join(settings.SHARED_DIR, os.path.basename(src)),
            ):
                if os.path.exists(cand):
                    src = cand
                    break
        if src and os.path.exists(src):
            dst = os.path.join(scan_dir, dst_name)
            if os.path.abspath(src) != os.path.abspath(dst):
                os.replace(src, dst)

    if source_json_path:
        _cleanup_sandbox_root_files(source_json_path, sandbox_result)

    logger.info("[%s] sandbox artifacts written", scan_id)
    _mark_status(scan_id, "sandbox_analysis_done")

    from tasks.consistency import consistency_task
    try:
        consistency_task.delay(scan_id)
    except Exception:
        logger.exception("[%s] Failed to dispatch consistency_task", scan_id)
        _mark_status(scan_id, "consistency_dispatch_failed")

    return {"scan_id": scan_id, "status": "sandbox_analysis_done"}


def _save_telemetry_to_postgres(scan_id: str, sandbox_result: dict) -> None:
    with get_db_session() as db:
        # Ingest Network Activity
        for req in sandbox_result.get("network_activity", []):
            db.add(NetworkActivity(
                scan_id=scan_id,
                method=req.get("method"),
                url=req.get("url"),
                domain=req.get("domain"),
                ip_address=req.get("ip_address"),
                status=req.get("status"),
                headers=req.get("headers")
            ))
            
        # Ingest TLS Connections
        for tls in sandbox_result.get("tls_connections", []):
            db.add(TLSConnection(
                scan_id=scan_id,
                domain=tls.get("domain"),
                protocol=tls.get("protocol"),
                cipher=tls.get("cipher"),
                issuer=tls.get("issuer"),
                is_suspicious=tls.get("is_suspicious", False),
                cert_chain=tls.get("cert_chain")
            ))
            
        # Ingest Form Metrics
        form_metrics = sandbox_result.get("form_metrics", {})
        if form_metrics:
            db.add(FormMetrics(
                scan_id=scan_id,
                action_url=form_metrics.get("action_url"),
                input_types=form_metrics.get("input_types"),
                has_password_field=form_metrics.get("has_password_field", False)
            ))
            
        # Ingest Downloads
        for dl in sandbox_result.get("downloads", []):
            db.add(Download(
                scan_id=scan_id,
                url=dl.get("url"),
                mime_type=dl.get("mime_type"),
                filename=dl.get("filename"),
                size_bytes=dl.get("size_bytes")
            ))
            
        # Ingest Redirects
        for rdr in sandbox_result.get("redirects", []):
            db.add(Redirect(
                scan_id=scan_id,
                from_url=rdr.get("from_url"),
                to_url=rdr.get("to_url"),
                status_code=rdr.get("status_code")
            ))
            
        # Ingest Evasion Techniques
        for ev in sandbox_result.get("evasion_techniques", []):
            db.add(EvasionTechnique(
                scan_id=scan_id,
                technique_name=ev.get("technique_name"),
                evidence_snippet=ev.get("evidence_snippet")
            ))
            
        db.commit()