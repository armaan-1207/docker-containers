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


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


# ── Pipeline Stage (Diagram → Code) ──────────────────────────────────────────
# Diagram Stage N/A (Consistency) | Code internal name: "Stage 3 / consistency"
@celery.task(
    bind=True,
    name="tasks.consistency",
    queue="default",
    max_retries=2,
    default_retry_delay=10,
    acks_late=True,
)
def consistency_task(self, scan_id: str):
    validate_scan_id(scan_id)
    logger.info("[%s] Stage 3 (consistency) started", scan_id)
    _mark_status(scan_id, "consistency_running")

    scan_dir = _scan_dir(scan_id)

    try:
        browser_features_data = _load_json(os.path.join(scan_dir, "browser_features.json"))
        browser_png   = os.path.join(scan_dir, "browser.png")
        browser_html  = os.path.join(scan_dir, "browser.html")

        # Load Sandbox DOM hash
        try:
            sandbox_meta  = _load_json(os.path.join(scan_dir, "sandbox_metadata.json"))
            sandbox_available = sandbox_meta.get("sandbox_available", True)
        except (FileNotFoundError, json.JSONDecodeError):
            logger.warning("[%s] sandbox_metadata.json missing (likely sandbox skipped or crashed)", scan_id)
            sandbox_meta = {}
            sandbox_available = False

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
    tmp_path = report_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(consistency_report, f, indent=2, default=str)
    os.replace(tmp_path, report_path)  # atomic on Linux — prevents partial-read by downstream tasks

    # ── V8/V10: Write ece_report.json (V10 Page 5 canonical artifact name) ──
    # consistency_report.json is kept as the primary file — risk_fusion_task
    # and the artifact API endpoint both reference it by that name.
    # ece_report.json is an identical V8/V10-spec alias written alongside it.
    ece_report_path = os.path.join(scan_dir, "ece_report.json")
    ece_tmp_path = ece_report_path + ".tmp"
    try:
        with open(ece_tmp_path, "w") as _f:
            json.dump(consistency_report, _f, indent=2, default=str)
        os.replace(ece_tmp_path, ece_report_path)
        logger.info("[%s] ece_report.json written (V8/V10 alias)", scan_id)
    except Exception:
        logger.exception("[%s] Failed to write ece_report.json alias — consistency_report.json is intact", scan_id)

    logger.info("[%s] consistency_report.json written", scan_id)
    _mark_status(scan_id, "consistency_done")

    from tasks.risk_fusion import risk_fusion_task
    try:
        risk_fusion_task.delay(scan_id)
    except Exception:
        logger.exception("[%s] Failed to dispatch risk_fusion_task", scan_id)
        _mark_status(scan_id, "risk_fusion_dispatch_failed")

    return {"scan_id": scan_id, "status": "consistency_done"}