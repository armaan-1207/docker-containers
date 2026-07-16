"""
services/stage2_analysis.py
=============================
"""

import base64
import logging
import os

from database.models import Scan
from config import settings
from schemas.stage2 import Stage2Request, Stage2Response, JobStatus

logger = logging.getLogger(__name__)


def _scan_dir(scan_id: str) -> str:
    return os.path.join(settings.SHARED_DIR, scan_id)


async def run_stage2_analysis(payload: Stage2Request, user, db) -> Stage2Response:
    url = str(payload.url)

    scan = Scan(
        user_id=user.id,
        url=url,
        status="created",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_id = scan.id
    scan_dir = _scan_dir(scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    try:
        screenshot_bytes = base64.b64decode(payload.screenshot_base64)
    except Exception as exc:
        raise ValueError(f"screenshot_base64 is not valid base64: {exc}")

    png_path = os.path.join(scan_dir, "browser.png")
    with open(png_path, "wb") as f:
        f.write(screenshot_bytes)

    html_path = os.path.join(scan_dir, "browser.html")
    with open(html_path, "w") as f:
        f.write(payload.html if payload.html else "<html><body></body></html>")

    from tasks.browser_features import browser_features_task
    async_result = browser_features_task.delay(scan_id)

    scan.status = "browser_features_running"
    db.commit()

    return Stage2Response(
        scan_id=scan_id,
        job_id=async_result.id,
        status=JobStatus.QUEUED,
        url=url,
        screenshot_saved_path=png_path,
    )
