"""
tasks/file_cleanup.py
======================
Periodic artifact retention task (security finding #8 fix).

Responsibility:
  Prevent disk exhaustion on the shared_scans volume, which would corrupt
  databases and cause a platform-wide outage. This task is scheduled hourly
  by celery_beat.py.

What it cleans:
  1. Per-scan subdirectories under SHARED_DIR/<scan_id>/ that are older
     than `retention_days` days (default 14). Each subdirectory contains
     browser.png, browser.html, sandbox.png, sandbox.html,
     browser_features.json, sandbox_metadata.json, consistency_report.json,
     risk_report.json, cyberintel.json — all are safe to purge after the
     scan pipeline has completed and the results are in the database.

  2. Orphan files at the SHARED_DIR root that match scan_*.json or
     scan_*.png — left behind by the sandbox container on crashed /
     incomplete scan jobs. The normal cleanup path in sandbox_analysis.py
     removes these, but crashes can bypass that path.

What it does NOT touch:
  - Any file / directory whose mtime is within the retention window.
  - Non-scan files at the volume root (nothing else is written there).
  - The database — this is a filesystem-only purge.

Failure modes:
  - Individual file/directory removal errors are logged as warnings and
    skipped — a single unremovable file does not abort the entire sweep.
  - The task itself is safe to run multiple times concurrently (idempotent);
    missing files are silently ignored.
"""

import glob
import logging
import os
import shutil
import time

from celery_worker import celery
from config import settings

logger = logging.getLogger(__name__)

# How old (in seconds) a scan directory must be before it is pruned.
# Computed from retention_days at task call time so it can be changed
# via the beat_schedule kwargs without redeploying code.
_SECONDS_PER_DAY = 86_400


@celery.task(
    bind=True,
    name="tasks.file_cleanup",
    max_retries=1,
    acks_late=True,
)
def file_cleanup_task(self, retention_days: int = 14) -> dict:
    """
    Purge scan artifacts older than `retention_days` days from the shared
    scans volume. Also removes orphan files at the volume root.
    """
    shared_dir = settings.SHARED_DIR
    cutoff_seconds = retention_days * _SECONDS_PER_DAY
    now = time.time()
    cutoff_ts = now - cutoff_seconds

    logger.info(
        "[file_cleanup] Starting sweep of %s — retention=%d days, cutoff=%s",
        shared_dir,
        retention_days,
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
    # Sandbox containers write scan_<id>.json and scan_<id>.png flat into
    # the shared volume root. sandbox_analysis.py normally deletes these
    # after ingestion, but crashes bypass that path.
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

    summary = {
        "status": "ok",
        "shared_dir": shared_dir,
        "retention_days": retention_days,
        "dirs_removed": dirs_removed,
        "dirs_skipped": dirs_skipped,
        "orphans_removed": orphans_removed,
        "errors": errors,
    }
    logger.info("[file_cleanup] Sweep complete: %s", summary)
    return summary
