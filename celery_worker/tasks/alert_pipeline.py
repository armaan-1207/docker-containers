"""
tasks/alert_pipeline.py
=========================
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
    db.flush()  # get incident.id without committing yet
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
        return  # Slack is optional; skip silently if not configured

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
        # Slack failures must never break the alert pipeline.
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

    try:
        with get_db_session() as db:
            incident = _create_incident(db, scan_id, risk_report)
            _store_iocs(db, incident, _extract_iocs(risk_report))
            _update_statistics(db, risk_report.get("severity"))
            db.commit()
    except Exception as exc:
        logger.exception("[%s] alert_pipeline DB work failed", scan_id)
        raise self.retry(exc=exc)

    _send_slack_notification(scan_id, risk_report)

    logger.info("[%s] alert_pipeline complete", scan_id)
    return {"scan_id": scan_id, "status": "alert_pipeline_done"}
