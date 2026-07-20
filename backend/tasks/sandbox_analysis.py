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


def _cleanup_sandbox_root_files(json_path: str, sandbox_result: dict, scan_dir: str = None) -> None:
    """
    Delete leftover raw JSON and temporary screenshots after processing, while preserving
    final scan artifacts inside scan_dir.
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
                if scan_dir and os.path.abspath(os.path.dirname(path)) == os.path.abspath(scan_dir):
                    continue
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


# ── Pipeline Stage (Diagram → Code) ──────────────────────────────────────────
# Diagram Stage 5 (Sandbox Detonation) | Code internal name: "Stage 2 / sandbox_analysis"
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

    sandbox_result = None
    try:
        sandbox_result = _call_sandbox(scan_id)
        if sandbox_result.get("error"):
            raise ValueError(f"Sandbox returned an error: {sandbox_result['error']}")
    except Exception as exc:
        logger.exception("[%s] Sandbox call failed", scan_id)
        is_timeout = "504" in str(exc) or "timeout" in str(exc).lower()
        if not is_timeout and self.request.retries < self.max_retries:
            _mark_status(scan_id, "sandbox_analysis_retrying")
            raise self.retry(exc=exc)
        # Timeout or max retries exhausted — write a graceful fallback so the pipeline
        # (consistency + risk_fusion) can still run with reduced confidence
        # rather than dead-ending with no verdict at all.
        logger.warning(
            "[%s] Sandbox timeout or retries exhausted, writing fallback sandbox_metadata.json "
            "and continuing pipeline with reduced confidence.",
            scan_id, self.max_retries,
        )
        sandbox_result = {
            "error": str(exc),
            "sandbox_available": False,
            "network_requests": [],
            "screenshots": {},
            "dom": {},
        }
        fallback_path = os.path.join(scan_dir, "sandbox_metadata.json")
        with open(fallback_path, "w") as _f:
            json.dump(sandbox_result, _f, indent=2, default=str)
        _mark_status(scan_id, "sandbox_analysis_failed")
        # Continue the pipeline with reduced confidence — consistency and
        # risk_fusion still run, they handle sandbox_available=False gracefully.
        from tasks.consistency import consistency_task
        try:
            consistency_task.delay(scan_id)
        except Exception:
            logger.exception("[%s] Failed to dispatch consistency_task after sandbox fallback", scan_id)
        return {"scan_id": scan_id, "status": "sandbox_analysis_failed_gracefully"}

    source_json_path = sandbox_result.pop("_source_json_path", None)

    metadata_path = os.path.join(scan_dir, "sandbox_metadata.json")
    tmp_path = metadata_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(sandbox_result, f, indent=2, default=str)
    os.replace(tmp_path, metadata_path)  # atomic on Linux — prevents partial-read by downstream tasks

    try:
        _save_telemetry_to_postgres(scan_id, sandbox_result)
    except Exception:
        logger.exception("[%s] Failed to ingest sandbox telemetry to Postgres", scan_id)

    screenshots = sandbox_result.get("screenshots", {})
    for key, dst_name in (
        ("homepage_screenshot_path", "sandbox.png"),
        ("fullpage_screenshot_path", "sandbox_fullpage.png"),
    ):
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
        _cleanup_sandbox_root_files(source_json_path, sandbox_result, scan_dir=scan_dir)

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
    from urllib.parse import urlparse

    def _domain_of(u: str) -> str:
        if not u:
            return ""
        try:
            return urlparse(u).hostname or ""
        except Exception:
            return ""

    with get_db_session() as db:
        source_url = sandbox_result.get("scans", {}).get("source_url") or ""
        final_url = sandbox_result.get("pages", {}).get("final_url") or source_url

        # Ingest Network Activity
        raw_net = sandbox_result.get("network_activity", [])
        if isinstance(raw_net, dict):
            if raw_net.get("is_truncated"):
                logger.warning("[%s] Ingesting truncated network telemetry (first 100 requests of %s total)", scan_id, raw_net.get("total_request_count"))
            net_list = raw_net.get("rows", [])
        elif isinstance(raw_net, list):
            net_list = raw_net
        else:
            net_list = []

        for req in net_list:
            if not isinstance(req, dict):
                continue
            url = req.get("url") or final_url
            if not url:
                continue
            domain = req.get("domain") or _domain_of(url)
            db.add(NetworkActivity(
                scan_id=scan_id,
                method=(req.get("method") or "GET")[:16],
                url=url[:2048],
                domain=domain[:255] if domain else None,
                ip_address=req.get("ip_address", "")[:64] if req.get("ip_address") else None,
                status=req.get("status"),
                headers=req.get("headers")
            ))
            
        # Ingest TLS Connections
        raw_tls = sandbox_result.get("tls_connections", [])
        if isinstance(raw_tls, dict):
            tls_list = raw_tls.get("rows", [])
            if not tls_list and (raw_tls.get("domain") or raw_tls.get("protocol_used") or raw_tls.get("certificate_issuer")):
                domain = raw_tls.get("domain") or _domain_of(final_url)
                if domain:
                    tls_list = [{
                        "domain": domain,
                        "protocol": raw_tls.get("protocol") or raw_tls.get("protocol_used") or raw_tls.get("tls_version"),
                        "cipher": raw_tls.get("cipher"),
                        "issuer": raw_tls.get("issuer") or raw_tls.get("certificate_issuer"),
                        "valid_from": raw_tls.get("valid_from") or raw_tls.get("certificate_issued_date"),
                        "valid_to": raw_tls.get("valid_to"),
                        "is_suspicious": raw_tls.get("is_suspicious", False),
                        "cert_chain": raw_tls.get("cert_chain")
                    }]
        elif isinstance(raw_tls, list):
            tls_list = raw_tls
        else:
            tls_list = []

        for tls in tls_list:
            if not isinstance(tls, dict):
                continue
            domain = tls.get("domain") or _domain_of(final_url)
            if not domain:
                continue
            db.add(TLSConnection(
                scan_id=scan_id,
                domain=domain[:255],
                protocol=(tls.get("protocol") or tls.get("protocol_used") or tls.get("tls_version", ""))[:64] if (tls.get("protocol") or tls.get("protocol_used") or tls.get("tls_version")) else None,
                cipher=tls.get("cipher", "")[:128] if tls.get("cipher") else None,
                issuer=(tls.get("issuer") or tls.get("certificate_issuer", ""))[:512] if (tls.get("issuer") or tls.get("certificate_issuer")) else None,
                is_suspicious=bool(tls.get("is_suspicious", False)),
                cert_chain=tls.get("cert_chain")
            ))
            
        # Ingest Form Metrics
        form_metrics = sandbox_result.get("form_metrics", {})
        if isinstance(form_metrics, dict) and form_metrics:
            has_pw = form_metrics.get("has_password_field")
            if has_pw is None:
                has_pw = bool((form_metrics.get("password_field_count") or 0) > 0)
            db.add(FormMetrics(
                scan_id=scan_id,
                action_url=(form_metrics.get("action_url") or final_url)[:2048] if (form_metrics.get("action_url") or final_url) else None,
                input_types=form_metrics.get("input_types", form_metrics.get("non_credential_field_count", [])),
                has_password_field=bool(has_pw)
            ))
            
        # Ingest Downloads
        raw_dl = sandbox_result.get("downloads", [])
        if isinstance(raw_dl, dict):
            dl_list = raw_dl.get("rows", [])
        elif isinstance(raw_dl, list):
            dl_list = raw_dl
        else:
            dl_list = []

        for dl in dl_list:
            if not isinstance(dl, dict):
                continue
            dl_url = dl.get("url") or dl.get("download_url") or final_url
            if not dl_url:
                continue
            filename = dl.get("filename") or dl.get("file_name")
            size = dl.get("size_bytes") if dl.get("size_bytes") is not None else dl.get("file_size")
            db.add(Download(
                scan_id=scan_id,
                url=dl_url[:2048],
                mime_type=dl.get("mime_type", "")[:128] if dl.get("mime_type") else None,
                filename=filename[:255] if filename else None,
                size_bytes=size
            ))
            
        # Ingest Redirects
        raw_rdr = sandbox_result.get("redirects", [])
        if isinstance(raw_rdr, dict):
            rdr_list = raw_rdr.get("rows", [])
        elif isinstance(raw_rdr, list):
            rdr_list = raw_rdr
        else:
            rdr_list = []

        for rdr in rdr_list:
            if not isinstance(rdr, dict):
                continue
            to_u = rdr.get("to_url") or rdr.get("redirect_url")
            from_u = rdr.get("from_url") or source_url
            if not to_u or not from_u:
                continue
            status = rdr.get("status_code") if rdr.get("status_code") is not None else rdr.get("http_status_code")
            db.add(Redirect(
                scan_id=scan_id,
                from_url=from_u[:2048],
                to_url=to_u[:2048],
                status_code=status
            ))
            
        # Ingest Evasion Techniques
        raw_ev = sandbox_result.get("evasion_techniques", [])
        if isinstance(raw_ev, dict):
            ev_list = raw_ev.get("rows", [])
        elif isinstance(raw_ev, list):
            ev_list = raw_ev
        else:
            ev_list = []

        for ev in ev_list:
            if not isinstance(ev, dict):
                continue
            if ev.get("evasion_technique_flags") is False:
                continue
            t_name = ev.get("technique_name")
            if not t_name:
                continue
            snippet = ev.get("evidence_snippet") or f"Detected technique: {t_name}"
            db.add(EvasionTechnique(
                scan_id=scan_id,
                technique_name=t_name[:128],
                evidence_snippet=snippet[:2048]
            ))
            
        db.commit()