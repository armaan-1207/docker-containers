"""
tasks/sandbox_analysis.py
==========================

PATCH NOTES (integration fix):
  The previous implementation POSTed to f"{SANDBOX_SERVICE_URL}/detonate"
  -- but the sandbox container (see sandbox/README.md and
  sandbox/docker/Dockerfile) is explicitly a single-shot CLI tool with
  NO persistent API service, no port, and no /detonate route. That
  request would fail on every real invocation.

  Switched to "Option A" from sandbox/DOCKER_ARCHITECTURE_IDEATION.md:
  spawn a fresh sandbox container per job via the Docker socket (already
  mounted read-only into this worker -- see docker-compose.yml), mount
  the same shared_scans volume the sandbox writes into, and read the
  atomically-written scan_<id>.json + screenshots back off it once the
  container exits. This matches the container-per-job isolation pattern
  the rest of this repo already documents and gives up nothing compared
  to the old (nonexistent) HTTP path.

  If you'd rather use Option B (import backend/phishing_sandbox_scan.py
  directly into this worker image and call scan_url() in-process --
  see DOCKER_ARCHITECTURE_IDEATION.md's tradeoffs table), replace
  _call_sandbox() below with a direct `await scan_url(...)` call and
  drop the subprocess/Docker-socket dependency entirely.
"""

import asyncio
import glob
import json
import logging
import os

from celery_worker import celery
from config import settings
from database.database import get_db_session
from database.models import Scan

logger = logging.getLogger(__name__)

SANDBOX_IMAGE = os.environ.get("SANDBOX_IMAGE", "aegis-sandbox:latest")
SHARED_VOLUME_NAME = os.environ.get("SHARED_SCANS_VOLUME", "shared_scans")


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
    Spawns `docker run --rm -v shared_scans:/app/output <image> <url>
    --output-dir /app/output --request-id <scan_id>` and waits for it to
    exit. The sandbox container writes scan_<request_id>.json (using
    ITS OWN internally-generated scan_id, stamped with our request_id)
    atomically into the shared volume -- we locate that file by request_id
    rather than assuming any particular scan_id, since the sandbox
    container's scan_id is independent of ours.
    """
    cmd = [
        "docker", "run", "--rm",
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


def _find_result_by_request_id(scan_id: str) -> dict:
    """
    The sandbox container's OWN scan_id (not ours) is embedded in its
    output filename (scan_<its_id>.json), but every result's
    scans.request_id field is stamped with the --request-id we passed
    in (our scan_id) -- see phishing_sandbox_scan.py's scan_url(). Scan
    the shared dir's JSON files for the one whose request_id matches.
    """
    candidates = glob.glob(os.path.join(settings.SHARED_DIR, "scan_*.json"))
    for path in candidates:
        try:
            with open(path) as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            continue
        if data.get("scans", {}).get("request_id") == scan_id:
            return data
    raise FileNotFoundError(f"No sandbox result found for scan {scan_id} in {settings.SHARED_DIR}")


def _call_sandbox(scan_id: str) -> dict:
    target_url = _get_scan_url(scan_id)
    timeout_sec = getattr(settings, "SANDBOX_TIMEOUT_SEC", 120)

    asyncio.run(_run_sandbox_container(scan_id, target_url, timeout_sec))
    return _find_result_by_request_id(scan_id)


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
        _mark_status(scan_id, "sandbox_analysis_failed")
        raise self.retry(exc=exc)

    # Persist metadata (the full sandbox telemetry -- screenshots are
    # already sitting in the shared volume next to the JSON, written
    # atomically by the sandbox container itself).
    metadata_path = os.path.join(scan_dir, "sandbox_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(sandbox_result, f, indent=2, default=str)

    # Record screenshot paths so downstream stages (consistency.py) can
    # find them -- the sandbox container already wrote these into the
    # shared volume; this just points sandbox.png / sandbox.html-shaped
    # consumers at the sandbox's own output naming.
    screenshots = sandbox_result.get("screenshots", {})
    for key, dst_name in (("homepage_screenshot_path", "sandbox.png"),):
        src = screenshots.get(key)
        if src and os.path.exists(src):
            dst = os.path.join(scan_dir, dst_name)
            if os.path.abspath(src) != os.path.abspath(dst):
                os.replace(src, dst)

    logger.info("[%s] sandbox artifacts written", scan_id)
    _mark_status(scan_id, "sandbox_analysis_done")

    # Queue Stage 3 - Consistency
    from tasks.consistency import consistency_task
    consistency_task.delay(scan_id)

    return {"scan_id": scan_id, "status": "sandbox_analysis_done"}
