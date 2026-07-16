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
)

# -------------------------------------------------------
# Periodic schedules
# -------------------------------------------------------
# NOTE: The pipeline tasks (browser_features, sandbox_analysis, etc.)
# require a scan_id and are triggered by the API — not beat.
# Beat fires periodic "sweep" tasks that maintain system health.
# Add your sweep tasks here as you build them out.
# -------------------------------------------------------
celery.conf.beat_schedule = {

}

if __name__ == "__main__":
    # Run via: celery -A celery_beat beat --loglevel=info
    celery.start()