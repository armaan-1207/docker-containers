"""
tasks/job_reconciliation.py
===========================
Periodic task to reconcile and clean up jobs lost mid-pipeline due to
worker crashes, Redis broker restarts, or unexpected timeouts (Fixes Medium #7).
"""

import logging
from datetime import datetime, timezone, timedelta
from celery_worker import celery
from database.database import get_db_session
from database.models import Scan

logger = logging.getLogger(__name__)

RUNNING_STATUSES = {
    "created",
    "submitted",
    "browser_features_running",
    "browser_features_done",
    "sandbox_analysis_running",
    "sandbox_analysis_done",
    "consistency_running",
    "consistency_done",
    "risk_fusion_running",
    "alert_pipeline_running",
    "alert_pipeline_retrying",
}


@celery.task(
    bind=True,
    name="tasks.job_reconciliation",
    queue="default",
    max_retries=1,
)
def job_reconciliation_task(self, timeout_minutes: int = 30) -> dict:
    """
    Find scans stuck in a running status for longer than `timeout_minutes`
    and transition them to `failed_timeout` so they don't hang indefinitely.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=timeout_minutes)
    reconciled_count = 0
    stuck_ids = []

    try:
        with get_db_session() as db:
            stuck_scans = db.query(Scan).filter(
                Scan.status.in_(RUNNING_STATUSES),
                Scan.updated_at < cutoff,
            ).all()

            for scan in stuck_scans:
                logger.error(
                    "[job_reconciliation] Scan %s stuck in status '%s' since %s — marking failed_timeout",
                    scan.id,
                    scan.status,
                    scan.updated_at,
                )
                stuck_ids.append(scan.id)
                scan.status = "failed_timeout"
                reconciled_count += 1

            if reconciled_count > 0:
                db.commit()
                logger.warning("[job_reconciliation] Reconciled %d stuck scans: %s", reconciled_count, stuck_ids)
            else:
                logger.debug("[job_reconciliation] No stuck jobs found.")
    except Exception:
        logger.exception("[job_reconciliation] Error reconciling stuck jobs")
        return {"status": "error", "reconciled": 0}

    return {"status": "success", "reconciled": reconciled_count, "stuck_ids": stuck_ids}
