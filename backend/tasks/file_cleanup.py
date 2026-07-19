"""
tasks/file_cleanup.py
======================
Periodic retention and cleanup task (security finding #8 fix).

Responsibility:
  Prevent disk exhaustion on the shared_scans volume, which would corrupt
  databases and cause a platform-wide outage. This task is scheduled hourly
  by celery_beat.py. Also enforces dual-tier database retention so high-value
  incident history is preserved long-term while scratch records and files are pruned.

What it cleans:
  1. Per-scan subdirectories under SHARED_DIR/<scan_id>/ that are older
     than `retention_days` days (default 14). Each subdirectory contains
     browser.png, browser.html, sandbox.png, sandbox_fullpage.png,
     browser_features.json, sandbox_metadata.json, consistency_report.json,
     risk_report.json, cyberintel.json — safe to purge after scan pipeline completion.

  2. Orphan files at the SHARED_DIR root that match scan_*.json or
     scan_*.png — left behind by the sandbox container on crashed /
     incomplete scan jobs.

  3. Quarantined samples inside SHARED_DIR/quarantine older than `retention_days`.

  4. Database Purge (Dual-Tier Retention):
     - Scans without any associated security Incidents (`~Scan.incidents.any()`)
       are pruned after `retention_days` (default 14 days).
     - Scans associated with actual security Incidents (and their child Incident/IOC
       records) are kept much longer, determined by `incident_retention_days`
       (default 365 days, or configured via settings.INCIDENT_RETENTION_DAYS).
     - Whenever rows are purged, `Statistics` counters (total_incidents, critical_count,
       high_count) are re-synchronized via COUNT() queries to prevent drift.

Failure modes:
  - Individual file/directory removal errors are logged as warnings and skipped.
  - The task itself is safe to run multiple times concurrently (idempotent).
"""

import glob
import logging
import os
import shutil
import time

from celery_worker import celery
from config import settings
from tasks import _UUID_RE
from database.database import SessionLocal
from database.models import Scan, Incident, Statistics
from datetime import datetime, timedelta, timezone
from sqlalchemy import func

logger = logging.getLogger(__name__)

_SECONDS_PER_DAY = 86_400


@celery.task(
    bind=True,
    name="tasks.file_cleanup",
    queue="default",
    max_retries=1,
    acks_late=True,
)
def file_cleanup_task(self, retention_days: int = 14, incident_retention_days: int = None) -> dict:
    """
    Purge scan artifacts older than `retention_days` days from the shared
    scans volume. Also purges old database Scan/Incident records according to
    dual-tier retention and re-synchronizes Statistics counters.
    """
    if incident_retention_days is None:
        incident_retention_days = getattr(settings, "INCIDENT_RETENTION_DAYS", 365)

    shared_dir = settings.SHARED_DIR
    cutoff_seconds = retention_days * _SECONDS_PER_DAY
    now = time.time()
    cutoff_ts = now - cutoff_seconds

    logger.info(
        "[file_cleanup] Starting sweep of %s — retention=%d days, incident_retention=%d days, cutoff=%s",
        shared_dir,
        retention_days,
        incident_retention_days,
        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(cutoff_ts)),
    )

    dirs_removed = 0
    dirs_skipped = 0
    orphans_removed = 0
    errors = 0

    # ── 1. Per-scan subdirectories ─────────────────────────────────────────
    try:
        entries = os.scandir(shared_dir)
    except OSError:
        logger.exception("[file_cleanup] Cannot scan %s — volume not mounted?", shared_dir)
        return {"status": "error", "detail": "Cannot scan shared_dir"}
    with entries:
        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                continue  # orphan files handled below

            if not _UUID_RE.match(entry.name):
                logger.debug("[file_cleanup] Skipping non-UUID directory: %s", entry.name)
                continue

            try:
                mtime = entry.stat(follow_symlinks=False).st_mtime
            except OSError:
                logger.warning("[file_cleanup] Cannot stat %s — skipping", entry.path)
                errors += 1
                continue

            if mtime > cutoff_ts:
                dirs_skipped += 1
                continue

            # Directory is older than retention threshold — remove it
            try:
                shutil.rmtree(entry.path, ignore_errors=False)
                logger.info("[file_cleanup] Removed scan dir: %s (age=%dh)",
                            entry.path, int((now - mtime) / 3600))
                dirs_removed += 1
            except OSError:
                logger.warning("[file_cleanup] Failed to remove %s", entry.path, exc_info=True)
                errors += 1

    # ── 2. Orphan files at the volume root ────────────────────────────────
    for pattern in ("scan_*.json", "scan_*.png"):
        for path in glob.glob(os.path.join(shared_dir, pattern)):
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue

            if mtime > cutoff_ts:
                continue  # within retention window

            try:
                os.remove(path)
                logger.info("[file_cleanup] Removed orphan file: %s", path)
                orphans_removed += 1
            except OSError:
                logger.warning("[file_cleanup] Failed to remove orphan %s", path, exc_info=True)
                errors += 1

    # ── 3. Quarantined download samples inside shared_dir/quarantine ──────
    quarantine_dir = os.path.join(shared_dir, "quarantine")
    if os.path.exists(quarantine_dir):
        try:
            with os.scandir(quarantine_dir) as qentries:
                for qentry in qentries:
                    if qentry.is_file(follow_symlinks=False):
                        try:
                            if qentry.stat(follow_symlinks=False).st_mtime <= cutoff_ts:
                                os.remove(qentry.path)
                                orphans_removed += 1
                        except OSError:
                            errors += 1
        except OSError:
            pass

    # ── 4. Database Purge (Dual-Tier Retention) ──────
    db_records_removed = 0
    cutoff_datetime_artifacts = datetime.now(timezone.utc) - timedelta(days=retention_days)
    cutoff_datetime_incidents = datetime.now(timezone.utc) - timedelta(days=incident_retention_days)
    try:
        with SessionLocal() as db:
            # 1. Purge scans WITHOUT incidents older than ARTIFACT_RETENTION_DAYS
            del_scans = db.query(Scan).filter(
                Scan.created_at <= cutoff_datetime_artifacts,
                ~Scan.incidents.any()
            ).delete(synchronize_session=False)

            # 2. Purge old scans/incidents older than INCIDENT_RETENTION_DAYS
            del_incidents_scans = db.query(Scan).filter(
                Scan.created_at <= cutoff_datetime_incidents
            ).delete(synchronize_session=False)

            db_records_removed = del_scans + del_incidents_scans

            # 3. Re-synchronize Statistics table via accurate COUNT() queries to prevent drift
            total_inc = db.query(func.count(Incident.id)).scalar() or 0
            crit_inc = db.query(func.count(Incident.id)).filter(Incident.severity == "CRITICAL").scalar() or 0
            high_inc = db.query(func.count(Incident.id)).filter(Incident.severity == "HIGH").scalar() or 0

            stats = db.query(Statistics).filter(Statistics.id == 1).first()
            if not stats:
                stats = Statistics(id=1, total_incidents=total_inc, critical_count=crit_inc, high_count=high_inc)
                db.add(stats)
            else:
                stats.total_incidents = total_inc
                stats.critical_count = crit_inc
                stats.high_count = high_inc
                stats.updated_at = func.now()

            db.commit()
            logger.info("[file_cleanup] Purged %d old scans (non-inc=%d, old-inc=%d). Statistics synced: total=%d, crit=%d, high=%d.",
                        db_records_removed, del_scans, del_incidents_scans, total_inc, crit_inc, high_inc)
    except Exception as e:
        logger.error("[file_cleanup] Failed to purge old scans or sync statistics from database: %s", e)
        errors += 1

    summary = {
        "status": "ok",
        "shared_dir": shared_dir,
        "retention_days": retention_days,
        "incident_retention_days": incident_retention_days,
        "dirs_removed": dirs_removed,
        "dirs_skipped": dirs_skipped,
        "orphans_removed": orphans_removed,
        "db_records_removed": db_records_removed,
        "errors": errors,
    }
    logger.info("[file_cleanup] Sweep complete: %s", summary)
    return summary
