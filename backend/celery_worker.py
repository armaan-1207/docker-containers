"""
celery_worker.py
================
Celery application entry point for the AEGIS worker process.

Run via:
    celery -A celery_worker worker --loglevel=info --concurrency=2

Architecture note:
  - The `include` list tells Celery which modules to import when the worker
    starts. Celery imports them AFTER this module finishes loading, so task
    files can safely do `from celery_worker import celery` without a circular
    import.
  - DO NOT use autodiscover_tasks([...], related_name=None) — it breaks in
    Celery 5.x with `ModuleNotFoundError: No module named 'tasks'`.
"""

from celery import Celery
from config import settings


celery = Celery(
    "aegis_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    # include= is the correct Celery 5.x pattern for explicit task discovery.
    # Each entry is the dotted module path of a file containing @celery.task
    # decorated functions.
    include=[
        "tasks.browser_features",
        "tasks.sandbox_analysis",
        "tasks.consistency",
        "tasks.risk_fusion",
        "tasks.alert_pipeline",
        "tasks.file_cleanup",     # periodic artifact retention (finding #8 fix)
        "tasks.job_reconciliation", # periodic stuck job reconciliation (finding #7 fix)
        "tasks.db_backup",        # automated daily PostgreSQL logical backups (Finding #6)
    ],
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,
    # Suppress Celery 5.x deprecation warning — explicit setting for 6.0 compat
    broker_connection_retry_on_startup=True,
    task_default_queue="default",
    task_routes={
        "tasks.browser_features": {"queue": "default"},
        "tasks.sandbox_analysis": {"queue": "sandbox"},
        "tasks.consistency": {"queue": "default"},
        "tasks.risk_fusion": {"queue": "default"},
        "tasks.alert_pipeline": {"queue": "alerts"},
        "tasks.file_cleanup": {"queue": "default"},
        "tasks.job_reconciliation": {"queue": "default"},
        "tasks.db_backup": {"queue": "default"},
    },
)

if __name__ == "__main__":
    # Run via: celery -A celery_worker worker --loglevel=info
    celery.start()
