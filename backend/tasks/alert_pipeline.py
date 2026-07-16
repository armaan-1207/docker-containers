"""
tasks/alert_pipeline.py
=========================
Stage 5 of the AEGIS Celery pipeline: creates Incident + IOC database rows
and fires a Slack notification for HIGH and CRITICAL risk verdicts.

Security hardening:
  Defense-in-depth is_placeholder guard added at task entry point.
  risk_fusion.py already suppresses dispatch when is_placeholder=True, but
  this guard ensures correctness even if that gate is bypassed in future
  code paths (e.g. direct task invocation in tests, Celery task retry edge
  cases, or bulk replay scripts). No Incident row or Slack alert is ever
  created from a random-number placeholder score.
"""

import logging

import requests

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert as pg_insert

from celery_worker import celery
from config import settings
from database.database import get_db_session
from database.models import Incident, IOC, Statistics

logger = logging.getLogger(__name__)


def _mark_status(scan_id: str, status: str) -> None:
    try:
        with get_db_session() as db:
            from database.models import Scan
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.status = status
                db.commit()
    except Exception:
        logger.exception("Failed to update scan status to %s for %s", status, scan_id)


def _extract_iocs(risk_report: dict) -> list:
    return risk_report.get("iocs", [])


def _create_incident(db, scan_id: str, risk_report: dict) -> "Incident":
    incident = Incident(
        scan_id=scan_id,
        severity=risk_report.get("severity"),
        risk_score=risk_report.get("risk_score"),
        summary=risk_report.get("explanations"),
    )
    db.add(incident)
    db.flush()
    return incident


def _store_iocs(db, incident, iocs: list) -> None:
    for entry in iocs:
        db.add(
            IOC(
                incident_id=incident.id,
                ioc_type=entry.get("type"),
                value=entry.get("value"),
            )
        )


def _update_statistics(db, severity: str) -> None:

    critical_inc = 1 if severity == "CRITICAL" else 0
    high_inc = 1 if severity == "HIGH" else 0

    stmt = pg_insert(Statistics).values(
        id=1,
        total_incidents=1,
        critical_count=critical_inc,
        high_count=high_inc,
    )
    stmt = stmt.on_conflict_do_update(
        index_elements=[Statistics.id],
        set_={
            "total_incidents": Statistics.total_incidents + 1,
            "critical_count": Statistics.critical_count + critical_inc,
            "high_count": Statistics.high_count + high_inc,
            "updated_at": func.now(),
        },
    )
    db.execute(stmt)


def _send_slack_notification(scan_id: str, risk_report: dict) -> None:
    webhook_url = getattr(settings, "SLACK_WEBHOOK_URL", None)
    if not webhook_url:
        return

    severity = risk_report.get("severity")
    score = risk_report.get("risk_score")
    message = {
        "text": (
            f":rotating_light: *{severity} risk detected*\n"
            f"Scan `{scan_id}` scored *{score}*.\n"
            f"See incident details in the dashboard."
        )
    }
    try:
        requests.post(webhook_url, json=message, timeout=5)
    except Exception:
        logger.exception("[%s] Slack notification failed (non-fatal)", scan_id)


@celery.task(
    bind=True,
    name="tasks.alert_pipeline",
    max_retries=3,
    default_retry_delay=10,
    acks_late=True,
)
def alert_pipeline_task(self, scan_id: str, risk_report: dict):

    logger.info(
        "[%s] Stage 5 (alert_pipeline) started - severity=%s",
        scan_id,
        risk_report.get("severity"),
    )

    # ── Defense-in-depth: is_placeholder guard ─────────────────────────────
    # risk_fusion.py already blocks dispatch when is_placeholder=True, but
    # guard here as well so direct invocations (tests, replays) cannot
    # accidentally write Incident rows or fire Slack alerts from random scores.
    if risk_report.get("is_placeholder", True):
        logger.warning(
            "[%s] alert_pipeline called with is_placeholder=True — aborting "
            "(no Incident row, no Slack). This should not happen via normal "
            "pipeline flow. Check risk_fusion.py dispatch gate.",
            scan_id,
        )
        return {"scan_id": scan_id, "status": "alert_skipped", "reason": "is_placeholder"}

    try:
        with get_db_session() as db:
            incident = _create_incident(db, scan_id, risk_report)
            _store_iocs(db, incident, _extract_iocs(risk_report))
            _update_statistics(db, risk_report.get("severity"))
            db.commit()
    except Exception as exc:
        logger.exception("[%s] alert_pipeline DB work failed", scan_id)
        if self.request.retries >= self.max_retries:
            _mark_status(scan_id, "alert_pipeline_failed")
        else:
            _mark_status(scan_id, "alert_pipeline_retrying")
        raise self.retry(exc=exc)

    _send_slack_notification(scan_id, risk_report)

    logger.info("[%s] alert_pipeline complete", scan_id)
    _mark_status(scan_id, "alert_pipeline_done")
    return {"scan_id": scan_id, "status": "alert_pipeline_done"}