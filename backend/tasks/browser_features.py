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


# ── Pipeline Stage (Diagram → Code) ──────────────────────────────────────────
# Diagram Stage 2 (Visual+OCR+DOM) | Code internal name: "Stage 1 / browser_features"
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
    tmp_path = out_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(browser_features, f, indent=2, default=str)
    os.replace(tmp_path, out_path)  # atomic on Linux — prevents partial-read by downstream tasks

    logger.info("[%s] browser_features.json written", scan_id)
    _mark_status(scan_id, "browser_features_done")

    # ── Conditional Sandbox Dispatch ─────────────────────────────────────────
    # Skip sandbox entirely for trusted/allowlisted domains — known-safe and
    # the 45-second detonation is not worth it for them.
    from tasks.sandbox_analysis import sandbox_analysis_task
    from tasks.consistency import consistency_task

    allowlisted = any(
        scan_url.rstrip("/").endswith(d)
        for d in settings.TRUSTED_ALLOWLIST_DOMAINS
    )

    if not allowlisted:
        preliminary_score = 0
        if dom_features.get("script_count", 0) > 10:
            preliminary_score += 20
        if dom_features.get("form_count", 0) > 0:
            preliminary_score += 15
        if dom_features.get("external_link_count", 0) > 20:
            preliminary_score += 10
        phishing_keywords = {"login", "password", "account", "verify", "secure", "update", "signin"}
        if any(kw in (ocr_text or "").lower() for kw in phishing_keywords):
            preliminary_score += 30
    else:
        preliminary_score = 0
        logger.info("[%s] URL is allowlisted (%s), skipping sandbox detonation", scan_id, scan_url)

    threshold = getattr(settings, "SANDBOX_PRELIMINARY_THRESHOLD", 0)

    if not allowlisted and (threshold == 0 or preliminary_score >= threshold):
        try:
            logger.info("[%s] Preliminary score %s >= %s — dispatching sandbox", scan_id, preliminary_score, threshold)
            sandbox_analysis_task.delay(scan_id)
        except Exception:
            logger.exception("[%s] Failed to dispatch sandbox_analysis_task", scan_id)
            _mark_status(scan_id, "sandbox_analysis_dispatch_failed")
    else:
        try:
            logger.info("[%s] Skipping sandbox (allowlisted=%s score=%s) — dispatching consistency directly", scan_id, allowlisted, preliminary_score)
            consistency_task.delay(scan_id)
        except Exception:
            logger.exception("[%s] Failed to dispatch consistency_task", scan_id)
            _mark_status(scan_id, "consistency_dispatch_failed")

    return {"scan_id": scan_id, "status": "browser_features_done"}