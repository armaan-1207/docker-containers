"""
tasks/db_backup.py
==================
Celery periodic task for automated logical PostgreSQL backups (`pg_dump`) with
retention management (`RETENTION_DAYS=7`).

Addresses DevSecOps Review Finding #6:
  `postgres/README.md` documents `pg_dump` commands and retention policy, but
  previously required manual execution via cron or Task Scheduler on the host.
  This task runs inside the `celery_worker` (which now includes `postgresql-client`)
  and executes daily logical backups directly against `postgres:5432`, storing compressed
  dumps in `/shared/scans/db_backups/` and automatically pruning dumps older than 7 days.
"""

import glob
import logging
import os
import subprocess
import time
from datetime import datetime, timezone

from celery_worker import celery
from config import settings

logger = logging.getLogger(__name__)


@celery.task(
    bind=True,
    name="tasks.db_backup",
    queue="default",
    max_retries=2,
    default_retry_delay=60,
    acks_late=True,
)
def db_backup_task(self, retention_days: int = 7) -> dict:
    """
    Execute pg_dump against the primary Postgres container and clean up backups
    older than retention_days.
    """
    logger.info("[db_backup] Starting automated logical database backup (retention=%d days)", retention_days)

    backup_dir = os.path.join(settings.SHARED_DIR, "db_backups")
    os.makedirs(backup_dir, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dump_filename = f"aegis_db_{timestamp}.dump"
    dump_path = os.path.join(backup_dir, dump_filename)

    db_password = getattr(settings, "AEGIS_DB_PASSWORD", "")
    if not db_password:
        logger.error("[db_backup] AEGIS_DB_PASSWORD not set — cannot authenticate to postgres")
        raise RuntimeError("AEGIS_DB_PASSWORD is empty")

    env = os.environ.copy()
    env["PGPASSWORD"] = db_password

    # Use pg_dump custom format (-F c) for compressed, restorable archives
    cmd = [
        "pg_dump",
        "-h", "postgres",
        "-p", "5432",
        "-U", "aegis_user",
        "-F", "c",
        "-b",
        "-v",
        "-f", dump_path,
        "aegis_db",
    ]

    try:
        proc = subprocess.run(
            cmd,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
            timeout=300,
        )
        logger.info("[db_backup] Database backup created successfully: %s (%d bytes)", dump_path, os.path.getsize(dump_path))
    except subprocess.CalledProcessError as exc:
        err_msg = exc.stderr.decode(errors="ignore")[:1000]
        logger.error("[db_backup] pg_dump failed (exit code %d): %s", exc.returncode, err_msg)
        if os.path.exists(dump_path):
            try:
                os.remove(dump_path)
            except OSError:
                pass
        raise self.retry(exc=exc)
    except Exception as exc:
        logger.exception("[db_backup] Unexpected error executing pg_dump")
        raise self.retry(exc=exc)

    # Prune expired backups
    cutoff_time = time.time() - (retention_days * 86400)
    removed_count = 0
    for file_path in glob.glob(os.path.join(backup_dir, "aegis_db_*.dump")):
        try:
            if os.path.getmtime(file_path) < cutoff_time:
                os.remove(file_path)
                removed_count += 1
                logger.info("[db_backup] Pruned expired backup: %s", file_path)
        except Exception as e:
            logger.warning("[db_backup] Could not check/prune %s: %s", file_path, e)

    return {
        "status": "success",
        "backup_path": dump_path,
        "size_bytes": os.path.getsize(dump_path),
        "pruned_expired_count": removed_count,
    }
