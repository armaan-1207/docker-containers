"""
tasks/consistency.py
=====================
Stage 3 of the AEGIS Celery pipeline: compares browser vs sandbox views
using the ConsistencyEngine to detect cloaking.

Bug fix:
  The original code passed sandbox_html_path pointing to sandbox.html
  which the sandbox container NEVER writes. The sandbox writes only:
    - sandbox.png  (homepage screenshot)
    - sandbox_metadata.json (page metadata, DOM data, telemetry)
  Attempting to open a non-existent sandbox.html caused a FileNotFoundError
  that crashed the task on every Stage 2 scan.

  Fix: if sandbox.html is absent (which is always the case in the current
  sandbox architecture), fall back to the browser's own DOM snapshot
  (browser.html) and set sandbox_html_available=False in the artifacts dict.
  ConsistencyEngine.compare_dom() will treat this as indeterminate and
  exclude the DOM channel from the weighted consistency score automatically,
  which is correct — we cannot compare browser DOM vs sandbox DOM if the
  sandbox did not produce an independent HTML snapshot.
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
    queue="default",
    max_retries=2,
    default_retry_delay=10,
    acks_late=True,
)
def consistency_task(self, scan_id: str):

    logger.info("[%s] Stage 3 (consistency) started", scan_id)
    _mark_status(scan_id, "consistency_running")

    scan_dir = _scan_dir(scan_id)

    try:
        browser_features_data = _load_json(os.path.join(scan_dir, "browser_features.json"))
        browser_png   = os.path.join(scan_dir, "browser.png")
        browser_html  = os.path.join(scan_dir, "browser.html")
        sandbox_meta  = _load_json(os.path.join(scan_dir, "sandbox_metadata.json"))
        sandbox_png   = os.path.join(scan_dir, "sandbox.png")

        # Bug fix: the sandbox container never writes sandbox.html.
        # It writes its DOM data into sandbox_metadata.json["dom_content"].
        # Fall back to browser.html when sandbox.html is absent, and flag it
        # so ConsistencyEngine marks the DOM channel as indeterminate.
        sandbox_html_candidate = os.path.join(scan_dir, "sandbox.html")
        sandbox_html_available = os.path.exists(sandbox_html_candidate)
        sandbox_html = sandbox_html_candidate if sandbox_html_available else browser_html

        browser_artifacts = {
            "features": browser_features_data,
            "png_path": browser_png,
            "html_path": browser_html,
        }
        sandbox_artifacts = {
            "metadata": sandbox_meta,
            "png_path": sandbox_png,
            "html_path": sandbox_html,
            # Downstream consistency_engine uses this flag to mark DOM
            # comparison as indeterminate when no independent sandbox HTML
            # snapshot was produced.
            "sandbox_html_available": sandbox_html_available,
        }
    except Exception as exc:
        logger.exception("[%s] Missing artifacts for consistency check", scan_id)
        if self.request.retries >= self.max_retries:
            _mark_status(scan_id, "consistency_failed")
        else:
            _mark_status(scan_id, "consistency_retrying")
        raise self.retry(exc=exc)

    try:
        engine = ConsistencyEngine()
        consistency_report = engine.analyze(browser_artifacts, sandbox_artifacts)
    except Exception as exc:
        logger.exception("[%s] ConsistencyEngine.analyze() failed", scan_id)
        if self.request.retries >= self.max_retries:
            _mark_status(scan_id, "consistency_failed")
        else:
            _mark_status(scan_id, "consistency_retrying")
        raise self.retry(exc=exc)

    report_path = os.path.join(scan_dir, "consistency_report.json")
    with open(report_path, "w") as f:
        json.dump(consistency_report, f, indent=2, default=str)

    logger.info("[%s] consistency_report.json written", scan_id)
    _mark_status(scan_id, "consistency_done")

    from tasks.risk_fusion import risk_fusion_task
    risk_fusion_task.delay(scan_id)

    return {"scan_id": scan_id, "status": "consistency_done"}