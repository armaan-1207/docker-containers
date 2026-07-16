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
from typing import Tuple

from celery_worker import celery
from config import settings
from database.database import get_db_session
from database.models import Scan

logger = logging.getLogger(__name__)

SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", settings.SANDBOX_IMAGE)
SHARED_VOLUME_NAME = os.environ.get("SHARED_SCANS_VOLUME", settings.SHARED_SCANS_VOLUME)

# Network to attach the sandbox container to (must be isolated from aegis_net)
SANDBOX_NETWORK = os.environ.get("SANDBOX_NETWORK", "project-docker-containers_sandbox_net")


def _scan_dir(scan_id: str) -> str:
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
    Spawn the aegis-sandbox container via `docker run`.

    The Docker client inside the Celery worker reads DOCKER_HOST from the
    environment (set to tcp://docker_socket_proxy:2375 in docker-compose.yml)
    so all Docker API calls are routed through the scoped socket proxy rather
    than the raw host socket.

    Security: sandbox container is attached to SANDBOX_NETWORK (sandbox_net)
    which has zero routing path to aegis_net / Postgres / Redis.
    """
    cmd = [
        "docker", "run", "--rm",
        "--network", SANDBOX_NETWORK,           # isolated network (finding #9)
        "--cap-drop", "ALL",                    # drop all Linux capabilities
        "--security-opt", "no-new-privileges:true",
        "--pids-limit", "512",
        "--memory", "2g",
        "--cpus", "1.0",
        "-v", f"{SHARED_VOLUME_NAME}:/app/output",
        SANDBOX_IMAGE,
        target_url,
        "--output-dir", "/app/output",
        "--request-id", scan_id,
    ]
    logger.info("[%s] spawning sandbox container: %s", scan_id, " ".join(cmd))

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"sandbox container for scan {scan_id} exceeded {timeout_sec}s")

    if proc.returncode != 0:
        raise RuntimeError(
            f"sandbox container exited {proc.returncode} for scan {scan_id}: "
            f"{stderr.decode(errors='ignore')[:2000]}"
        )
    logger.debug("[%s] sandbox container stdout: %s", scan_id, stdout.decode(errors="ignore")[:500])


def _find_result_by_request_id(scan_id: str) -> Tuple[str, dict]:
    """
    Returns (json_path, data) for the sandbox result whose
    scans.request_id matches our scan_id. Raises FileNotFoundError if
    no match is found.
    """
    candidates = glob.glob(os.path.join(settings.SHARED_DIR, "scan_*.json"))
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
    into the shared volume ROOT (not the per-scan subdirectory) --
    only the homepage screenshot ever gets moved into scan_dir by the
    caller below. Left alone, the raw JSON and the full-page screenshot
    accumulate at the volume root forever, across every scan ever run.
    Delete them once we've extracted what we actually need.
    """
    candidates = [json_path]
    full_page_path = sandbox_result.get("screenshots", {}).get("fullpage_screenshot_path")
    if full_page_path:
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
    return sandbox_result


@celery.task(
    bind=True,
    name="tasks.sandbox_analysis",
    max_retries=3,
    default_retry_delay=15,
    acks_late=True,
)
def sandbox_analysis_task(self, scan_id: str):

    logger.info("[%s] Stage 2 (sandbox_analysis) started", scan_id)
    _mark_status(scan_id, "sandbox_analysis_running")

    scan_dir = _scan_dir(scan_id)
    os.makedirs(scan_dir, exist_ok=True)

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

    screenshots = sandbox_result.get("screenshots", {})
    for key, dst_name in (("homepage_screenshot_path", "sandbox.png"),):
        src = screenshots.get(key)
        if src and os.path.exists(src):
            dst = os.path.join(scan_dir, dst_name)
            if os.path.abspath(src) != os.path.abspath(dst):
                os.replace(src, dst)

    if source_json_path:
        _cleanup_sandbox_root_files(source_json_path, sandbox_result)

    logger.info("[%s] sandbox artifacts written", scan_id)
    _mark_status(scan_id, "sandbox_analysis_done")

    from tasks.consistency import consistency_task
    consistency_task.delay(scan_id)

    return {"scan_id": scan_id, "status": "sandbox_analysis_done"}