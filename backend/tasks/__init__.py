"""
tasks/
======
Every module in this package is exactly one Celery task, in pipeline order:

    1. browser_features.py   - OCR + Vision + DOM extraction
    2. sandbox_analysis.py   - Call the sandbox container, receive artifacts
    3. consistency.py        - Compare browser vs sandbox via consistency_engine
    4. risk_fusion.py        - ML fusion -> Redis cache -> WebSocket ("Done")
    5. alert_pipeline.py     - HIGH/CRITICAL only: Incident + IOC + Slack

Nothing in this package is a plain helper function - if it's here, Celery
can be told (directly or via Redis) to execute it.

CHANGE: the old single celery_app.py (one Celery() instance shared by
everything) was split into two root-level entry points:

    celery_worker.py   - `celery -A celery_worker worker --loglevel=info`
    celery_beat.py      - `celery -A celery_beat beat --loglevel=info`

Both instantiate their own Celery() app (pointed at the same broker/backend
from config.py), and each calls:

    celery.autodiscover_tasks([...], related_name=None)

against this same list of task modules. Task modules therefore import their
Celery app from celery_worker (`from celery_worker import celery`), not from
a shared celery_app module anymore - celery_app.py no longer exists.
"""

import re

# UUID pattern for path-traversal protection across Celery tasks
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def validate_scan_id(scan_id: str) -> None:
    """Guard against path-traversal: scan_id must be a canonical UUID."""
    if not scan_id or not isinstance(scan_id, str) or not _UUID_RE.match(scan_id):
        raise ValueError(f"scan_id '{scan_id}' is not a valid UUID — rejected to prevent path traversal")

