"""
tasks/risk_fusion.py
=========================
"""

import asyncio
import json
import logging
import os

import redis

from celery_worker import celery
from config import settings
from database.database import get_db_session
from database.models import Scan

from risk_fusion import RiskFusionEngine  # root-level ML engine, NOT this file
from cyberintel.runner import run_cyberintel
from websocket.websocket_manager import websocket_manager

logger = logging.getLogger(__name__)

_redis_client = redis.from_url(settings.REDIS_URL)

ALERT_SEVERITIES = {"HIGH", "CRITICAL"}


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


def _get_scan_fields(scan_id: str) -> dict:
    """Small DB lookup used to get fields (url, user_id) that never made it
    into the JSON artifacts on disk."""
    with get_db_session() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan is None:
            raise ValueError(f"Scan {scan_id} not found")
        return {"url": scan.url, "user_id": scan.user_id}


def _get_cyberintel(scan_id: str, browser_features: dict) -> dict:
    
    cache_path = os.path.join(_scan_dir(scan_id), "cyberintel.json")
    if os.path.exists(cache_path):
        return _load_json(cache_path)

    target = browser_features.get("target") or browser_features.get("url")
    if not target:
        try:
            target = _get_scan_fields(scan_id)["url"]
        except Exception:
            logger.exception("[%s] Could not look up scan.url as a cyberintel fallback", scan_id)
            target = None

    cyberintel = run_cyberintel(target) if target else {}

    with open(cache_path, "w") as f:
        json.dump(cyberintel, f, indent=2, default=str)
    return cyberintel


def _push_websocket_update(scan_id: str, payload: dict) -> None:
    
    user_id = None
    try:
        user_id = _get_scan_fields(scan_id).get("user_id")
    except Exception:
        logger.exception("[%s] Could not look up user_id for dashboard broadcast", scan_id)

    try:
        asyncio.run(websocket_manager.broadcast_risk_update(scan_id, payload, user_id=user_id))
    except Exception:
        logger.exception("[%s] WebSocket push failed (non-fatal)", scan_id)


@celery.task(
    bind=True,
    name="tasks.risk_fusion",
    max_retries=2,
    default_retry_delay=10,
    acks_late=True,
)
def risk_fusion_task(self, scan_id: str):
    
    logger.info("[%s] Stage 4 (risk_fusion) started", scan_id)
    _mark_status(scan_id, "risk_fusion_running")

    scan_dir = _scan_dir(scan_id)

    try:
        browser_features = _load_json(os.path.join(scan_dir, "browser_features.json"))
        sandbox_features = _load_json(os.path.join(scan_dir, "sandbox_metadata.json"))
        consistency_report = _load_json(os.path.join(scan_dir, "consistency_report.json"))
        cyberintel = _get_cyberintel(scan_id, browser_features)
    except Exception as exc:
        logger.exception("[%s] Missing inputs for risk fusion", scan_id)
        _mark_status(scan_id, "risk_fusion_failed")
        raise self.retry(exc=exc)

    try:
        engine = RiskFusionEngine()
        risk_report = engine.compute(
            cyberintel=cyberintel,
            browser_features=browser_features,
            sandbox_features=sandbox_features,
            consistency_report=consistency_report,
        )
    except Exception as exc:
        logger.exception("[%s] RiskFusionEngine.compute() failed", scan_id)
        _mark_status(scan_id, "risk_fusion_failed")
        raise self.retry(exc=exc)

    risk_report["scan_id"] = scan_id

    # Persist to disk (audit trail)
    report_path = os.path.join(scan_dir, "risk_report.json")
    with open(report_path, "w") as f:
        json.dump(risk_report, f, indent=2, default=str)

    # 1. Redis cache
    _redis_client.set(f"risk:{scan_id}", json.dumps(risk_report, default=str))

    # 2. WebSocket push - "Done" from the user's point of view
    _push_websocket_update(scan_id, risk_report)

    logger.info(
        "[%s] risk_fusion complete - score=%s severity=%s",
        scan_id,
        risk_report.get("risk_score"),
        risk_report.get("severity"),
    )
    _mark_status(scan_id, "risk_fusion_done")


    if risk_report.get("severity") in ALERT_SEVERITIES:
        from tasks.alert_pipeline import alert_pipeline_task
        alert_pipeline_task.delay(scan_id, risk_report)

    return {"scan_id": scan_id, "status": "risk_fusion_done", "severity": risk_report.get("severity")}
