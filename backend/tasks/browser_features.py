"""
tasks/browser_features.py
==========================
"""

import json
import logging
import os

from celery.utils.log import get_task_logger

from celery_worker import celery
from config import settings

from ai_engine.ocr import extract_text
from ai_engine.vision import analyze_screenshot
from ai_engine.dom_extractor import extract_features

from database.database import get_db_session
from database.models import Scan

logger = get_task_logger(__name__)


from tasks import validate_scan_id


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


@celery.task(
    bind=True,
    name="tasks.browser_features",
    queue="default",
    max_retries=3,
    default_retry_delay=10,
    acks_late=True,
)
def browser_features_task(self, scan_id: str):
    validate_scan_id(scan_id)
    logger.info("[%s] Stage 1 (browser_features) started", scan_id)
    _mark_status(scan_id, "browser_features_running")

    scan_dir = _scan_dir(scan_id)
    png_path = os.path.join(scan_dir, "browser.png")
    html_path = os.path.join(scan_dir, "browser.html")

    if not os.path.exists(png_path) or not os.path.exists(html_path):
        logger.error("[%s] Missing browser artifacts in %s", scan_id, scan_dir)
        _mark_status(scan_id, "browser_features_failed")
        raise FileNotFoundError(f"browser.png / browser.html not found for scan {scan_id}")

    scan_url = ""
    try:
        with get_db_session() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan and scan.url:
                scan_url = scan.url
    except Exception:
        logger.exception("[%s] Could not look up scan.url", scan_id)

    try:
        ocr_text = extract_text(png_path)
        vision_result = analyze_screenshot(png_path)
        dom_features = extract_features(html_path, final_url=scan_url)
    except Exception as exc:
        logger.exception("[%s] Feature extraction failed", scan_id)
        # Only mark permanently "failed" once retries are actually
        # exhausted -- otherwise a transient failure that recovers on
        # attempt 2 leaves the DB showing "failed" for no reason.
        if self.request.retries >= self.max_retries:
            _mark_status(scan_id, "browser_features_failed")
        else:
            _mark_status(scan_id, "browser_features_retrying")
        raise self.retry(exc=exc)

    browser_features = {
        "scan_id": scan_id,
        "url": scan_url,
        "ocr_text": ocr_text,
        "vision": vision_result,
        "dom": dom_features,
    }

    out_path = os.path.join(scan_dir, "browser_features.json")
    with open(out_path, "w") as f:
        json.dump(browser_features, f, indent=2, default=str)

    logger.info("[%s] browser_features.json written", scan_id)
    _mark_status(scan_id, "browser_features_done")

    from tasks.sandbox_analysis import sandbox_analysis_task
    try:
        sandbox_analysis_task.delay(scan_id)
    except Exception:
        logger.exception("[%s] Failed to dispatch sandbox_analysis_task", scan_id)
        _mark_status(scan_id, "sandbox_analysis_dispatch_failed")

    return {"scan_id": scan_id, "status": "browser_features_done"}