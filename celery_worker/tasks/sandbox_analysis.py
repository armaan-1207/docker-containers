"""
tasks/sandbox_analysis.py
==========================
"""

import base64
import json
import logging
import os

import requests

from celery_worker import celery
from config import settings
from database.database import get_db_session
from database.models import Scan

logger = logging.getLogger(__name__)


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


def _call_sandbox(scan_id: str) -> dict:
    
    url = f"{settings.SANDBOX_SERVICE_URL}/detonate"
    resp = requests.post(
        url,
        json={"scan_id": scan_id},
        timeout=getattr(settings, "SANDBOX_TIMEOUT_SEC", 120),
    )
    resp.raise_for_status()
    return resp.json()


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

        missing = [k for k in ("screenshot_base64", "html") if k not in sandbox_result]
        if missing:
            raise ValueError(f"Sandbox response missing required key(s): {missing}")

        screenshot_bytes = base64.b64decode(sandbox_result["screenshot_base64"])
        html_content = sandbox_result["html"]
    except Exception as exc:
        logger.exception("[%s] Sandbox call failed", scan_id)
        _mark_status(scan_id, "sandbox_analysis_failed")
        raise self.retry(exc=exc)

    # Persist sandbox.png
    png_path = os.path.join(scan_dir, "sandbox.png")
    with open(png_path, "wb") as f:
        f.write(screenshot_bytes)

    # Persist sandbox.html
    html_path = os.path.join(scan_dir, "sandbox.html")
    with open(html_path, "w") as f:
        f.write(html_content)

    # Persist metadata
    metadata_path = os.path.join(scan_dir, "sandbox_metadata.json")
    with open(metadata_path, "w") as f:
        json.dump(sandbox_result.get("metadata", {}), f, indent=2, default=str)

    logger.info("[%s] sandbox artifacts written", scan_id)
    _mark_status(scan_id, "sandbox_analysis_done")

    # Queue Stage 3 - Consistency
    from tasks.consistency import consistency_task
    consistency_task.delay(scan_id)

    return {"scan_id": scan_id, "status": "sandbox_analysis_done"}
