"""
tasks/consistency.py
=====================
"""

import json
import logging
import os

from celery_worker import celery
from config import settings
from database.database import get_db_session
from database.models import Scan

from consistency_engine.consistency_engine import ConsistencyEngine

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


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


@celery.task(
    bind=True,
    name="tasks.consistency",
    max_retries=2,
    default_retry_delay=10,
    acks_late=True,
)
def consistency_task(self, scan_id: str):
    
    logger.info("[%s] Stage 3 (consistency) started", scan_id)
    _mark_status(scan_id, "consistency_running")

    scan_dir = _scan_dir(scan_id)

    try:
        browser_artifacts = {
            "features": _load_json(os.path.join(scan_dir, "browser_features.json")),
            "png_path": os.path.join(scan_dir, "browser.png"),
            "html_path": os.path.join(scan_dir, "browser.html"),
        }
        sandbox_artifacts = {
            "metadata": _load_json(os.path.join(scan_dir, "sandbox_metadata.json")),
            "png_path": os.path.join(scan_dir, "sandbox.png"),
            "html_path": os.path.join(scan_dir, "sandbox.html"),
        }
    except Exception as exc:
        logger.exception("[%s] Missing artifacts for consistency check", scan_id)
        _mark_status(scan_id, "consistency_failed")
        raise self.retry(exc=exc)

    try:
        # Task starts the work; engine does the work.
        engine = ConsistencyEngine()
        consistency_report = engine.analyze(browser_artifacts, sandbox_artifacts)
    except Exception as exc:
        logger.exception("[%s] ConsistencyEngine.analyze() failed", scan_id)
        _mark_status(scan_id, "consistency_failed")
        raise self.retry(exc=exc)

    report_path = os.path.join(scan_dir, "consistency_report.json")
    with open(report_path, "w") as f:
        json.dump(consistency_report, f, indent=2, default=str)

    logger.info("[%s] consistency_report.json written", scan_id)
    _mark_status(scan_id, "consistency_done")

    # Queue Stage 4 - Risk Fusion
    from tasks.risk_fusion import risk_fusion_task
    risk_fusion_task.delay(scan_id)

    return {"scan_id": scan_id, "status": "consistency_done"}
