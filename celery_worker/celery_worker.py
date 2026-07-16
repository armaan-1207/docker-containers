from celery import Celery

from config import settings


celery = Celery(
    "aegis_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)

celery.autodiscover_tasks(
    [
        "tasks.browser_features",
        "tasks.sandbox_analysis",
        "tasks.consistency",
        "tasks.risk_fusion",
        "tasks.alert_pipeline",
    ]
)

if __name__ == "__main__":
    # Run via: celery -A celery_worker worker --loglevel=info
    celery.start()
