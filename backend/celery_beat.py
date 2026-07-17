"""
celery_beat.py
==============
Celery Beat periodic scheduler for AEGIS.

Run via:
    celery -A celery_beat beat --loglevel=info

Beat sends task messages to the broker on a schedule — the actual task
code runs in the celery_worker process. Beat does NOT need to import the
task modules itself; it just sends strings (task names) to Redis.

Registered task names (must match @celery.task(name=...) in tasks/):
    "tasks.browser_features"
    "tasks.sandbox_analysis"
    "tasks.consistency"
    "tasks.risk_fusion"
    "tasks.alert_pipeline"
    "tasks.file_cleanup"   ← NEW (finding #8 fix)
    "tasks.db_backup"      ← NEW (Finding #6 fix)

Security fix (finding #8):
  The previous beat_schedule was empty ({}) which meant scan artifacts
  (browser.png, browser.html, sandbox.png, *.json) would accumulate on
  the shared_scans volume indefinitely. With enough scans this would hit
  100% disk usage, corrupting databases and causing a platform-wide
  outage. The hourly file_cleanup task purges per-scan subdirectories
  older than ARTIFACT_RETENTION_DAYS (default: 14 days) and also removes
  any orphaned root-level scan_*.json / scan_*.png files left behind by
  crashed mid-scan jobs.
"""

from celery import Celery
from celery.schedules import crontab

from config import settings


# Beat uses the same broker — app name can differ from worker's
celery = Celery(
    "aegis_beat",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    # Beat doesn't run tasks — worker does. No include= needed here.
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,
)

# -------------------------------------------------------
# Periodic schedules
# -------------------------------------------------------
celery.conf.beat_schedule = {

    # ── Artifact cleanup (finding #8 fix) ──────────────────────────────────
    # Runs every hour. Walks the shared_scans directory tree and removes:
    #   • Per-scan subdirectories older than ARTIFACT_RETENTION_DAYS
    #   • Orphan files (scan_*.json, scan_*.png) at the volume root that
    #     were left behind by crashes or incomplete scans
    # This prevents disk exhaustion (High severity, Service Availability)
    # that would otherwise corrupt databases and cause a platform outage.
    "hourly-file-cleanup": {
        "task": "tasks.file_cleanup",
        "schedule": crontab(minute=0),          # top of every hour
        "kwargs": {
            "retention_days": getattr(settings, "ARTIFACT_RETENTION_DAYS", 14),
        },
        "options": {"queue": "default"},
    },

    # ── Job reconciliation (finding #7 fix) ────────────────────────────────
    # Runs every 10 minutes. Finds scans stuck in non-terminal running states
    # due to worker crashes or broker bounces and transitions them to failed_timeout.
    "periodic-job-reconciliation": {
        "task": "tasks.job_reconciliation",
        "schedule": crontab(minute="*/10"),     # every 10 minutes
        "kwargs": {"timeout_minutes": 30},
        "options": {"queue": "default"},
    },

    # ── Automated DB backup (Finding #6 fix) ───────────────────────────────
    # Runs daily at 03:00 UTC. Executes logical database backup (pg_dump -F c)
    # into /shared/scans/db_backups/ and automatically purges dumps older than 7 days.
    "daily-db-backup": {
        "task": "tasks.db_backup",
        "schedule": crontab(hour=3, minute=0),  # daily at 03:00 UTC
        "kwargs": {"retention_days": 7},
        "options": {"queue": "default"},
    },
}

if __name__ == "__main__":
    # Run via: celery -A celery_beat beat --loglevel=info
    celery.start()