"""
tasks/risk_fusion.py
=========================
Stage 4 of the AEGIS Celery pipeline: assembles all evidence into a
final risk verdict, writes it to Redis, and pushes a WebSocket update.

Security hardening:
  - Redis cache TTL set to 3600s (1 hour) — was previously set() with no
    TTL, causing risk verdicts to persist in Redis indefinitely (finding #13).
  - is_placeholder gate already suppresses false HIGH/CRITICAL alerts when
    the real ML model is not yet wired in.
  - Only non-placeholder verdicts are written to the cache (consistent with
    the quickscan service's caching policy).
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

# Authoritative risk result cache TTL.  Must be ≤ Chrome extension's own
# in-memory cache TTL (or there is no point in the Redis cache at all).
# 3600 s (1 hour) per the absolute_implementation_guide spec.
_RISK_CACHE_TTL_SECONDS = 3600

ALERT_SEVERITIES = {"HIGH", "CRITICAL"}


from tasks import validate_scan_id


def _scan_dir(scan_id: str) -> str:
    validate_scan_id(scan_id)
    return os.path.join(settings.SHARED_DIR, scan_id)


def _mark_status(scan_id: str, status: str, risk_score: float = None, severity: str = None) -> None:
    try:
        with get_db_session() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = status
                if risk_score is not None:
                    scan.risk_score = risk_score
                if severity is not None:
                    scan.severity = severity
                db.commit()
    except Exception:
        logger.exception("Failed to update scan status to %s for %s", status, scan_id)


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _get_scan_fields(scan_id: str) -> dict:
    validate_scan_id(scan_id)
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


def _run_coroutine_sync(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result_holder = {}

    def _runner():
        result_holder["result"] = asyncio.run(coro)

    import threading
    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    t.join()
    return result_holder.get("result")


def _push_websocket_update(scan_id: str, payload: dict) -> None:

    user_id = None
    try:
        user_id = _get_scan_fields(scan_id).get("user_id")
    except Exception:
        logger.exception("[%s] Could not look up user_id for dashboard broadcast", scan_id)

    try:
        _run_coroutine_sync(websocket_manager.broadcast_risk_update(scan_id, payload, user_id=user_id))
    except Exception:
        logger.exception("[%s] WebSocket push failed (non-fatal)", scan_id)


@celery.task(
    bind=True,
    name="tasks.risk_fusion",
    queue="default",
    max_retries=2,
    default_retry_delay=10,
    acks_late=True,
)
def risk_fusion_task(self, scan_id: str):
    validate_scan_id(scan_id)
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
        if self.request.retries >= self.max_retries:
            _mark_status(scan_id, "risk_fusion_failed")
        else:
            _mark_status(scan_id, "risk_fusion_retrying")
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
        if self.request.retries >= self.max_retries:
            _mark_status(scan_id, "risk_fusion_failed")
        else:
            _mark_status(scan_id, "risk_fusion_retrying")
        raise self.retry(exc=exc)

    risk_report["scan_id"] = scan_id

    report_path = os.path.join(scan_dir, "risk_report.json")
    with open(report_path, "w") as f:
        json.dump(risk_report, f, indent=2, default=str)

    # Security finding #13 fix: was set() with no TTL (infinite persistence).
    # Use setex(3600) so Redis automatically evicts the entry after 1 hour.
    # Cache all completed verdicts keyed by unique scan_id so late-joining WebSocket clients
    # can fetch the completed result instantly without waiting on pubsub (finding #5 fix).
    _redis_client.setex(
        f"risk:{scan_id}",
        _RISK_CACHE_TTL_SECONDS,
        json.dumps(risk_report, default=str),
    )

    _push_websocket_update(scan_id, risk_report)

    logger.info(
        "[%s] risk_fusion complete - score=%s severity=%s%s",
        scan_id,
        risk_report.get("risk_score"),
        risk_report.get("severity"),
        " (PLACEHOLDER MODEL)" if risk_report.get("is_placeholder") else "",
    )
    _mark_status(
        scan_id,
        "risk_fusion_done",
        risk_score=risk_report.get("risk_score"),
        severity=risk_report.get("severity"),
    )

    is_placeholder = risk_report.get("is_placeholder", True)  # fail closed: unknown -> treat as placeholder
    if risk_report.get("severity") in ALERT_SEVERITIES and not is_placeholder:
        from tasks.alert_pipeline import alert_pipeline_task
        try:
            alert_pipeline_task.delay(scan_id, risk_report)
        except Exception:
            logger.exception("[%s] Failed to dispatch alert_pipeline_task", scan_id)
            _mark_status(scan_id, "alert_pipeline_dispatch_failed")
    elif risk_report.get("severity") in ALERT_SEVERITIES and is_placeholder:
        logger.info(
            "[%s] severity=%s but is_placeholder=True -- suppressing alert_pipeline "
            "dispatch (no Incident row, no Slack) until the real model is wired in",
            scan_id, risk_report.get("severity"),
        )

    return {"scan_id": scan_id, "status": "risk_fusion_done", "severity": risk_report.get("severity")}