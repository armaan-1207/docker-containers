"""
Unit tests for file_cleanup task across retention threshold pruning, UUID matching,
orphan root files, and quarantine sample cleanup.
"""

import os
import time
import pytest
from unittest.mock import patch, MagicMock

from tasks.file_cleanup import file_cleanup_task
import tasks.file_cleanup as cleanup_module


def test_file_cleanup_oserror_on_scandir():
    with patch.object(cleanup_module.settings, "SHARED_DIR", "/fake/shared"):
        with patch("os.scandir", side_effect=OSError("Volume unmounted")):
            result = file_cleanup_task(retention_days=14)
            assert result["status"] == "error"
            assert "Cannot scan" in result["detail"]


def test_file_cleanup_prunes_expired_and_preserves_recent(tmp_path):
    shared_dir = tmp_path / "shared_scans"
    shared_dir.mkdir()
    
    # 1. Expired UUID directory
    expired_uuid = "123e4567-e89b-12d3-a456-426614174000"
    expired_dir = shared_dir / expired_uuid
    expired_dir.mkdir()
    
    # 2. Recent UUID directory
    recent_uuid = "987fcdeb-51a2-43d7-9012-345678901234"
    recent_dir = shared_dir / recent_uuid
    recent_dir.mkdir()
    
    # 3. Non-UUID directory (e.g. system or internal folder)
    non_uuid_dir = shared_dir / "internal_cache"
    non_uuid_dir.mkdir()
    
    # 4. Orphan files at root (expired vs recent)
    expired_orphan = shared_dir / "scan_1111.json"
    expired_orphan.write_text("{}")
    recent_orphan = shared_dir / "scan_2222.png"
    recent_orphan.write_text("png")
    
    # 5. Quarantine directory and sample
    quarantine_dir = shared_dir / "quarantine"
    quarantine_dir.mkdir()
    expired_quarantine = quarantine_dir / "sample_old.exe"
    expired_quarantine.write_text("malware")
    recent_quarantine = quarantine_dir / "sample_new.exe"
    recent_quarantine.write_text("malware")

    now = time.time()
    cutoff_seconds = 14 * 86400
    expired_mtime = now - cutoff_seconds - 3600  # 1 hour older than retention
    recent_mtime = now - 3600                    # 1 hour old

    os.utime(expired_dir, (expired_mtime, expired_mtime))
    os.utime(recent_dir, (recent_mtime, recent_mtime))
    os.utime(non_uuid_dir, (expired_mtime, expired_mtime))
    os.utime(expired_orphan, (expired_mtime, expired_mtime))
    os.utime(recent_orphan, (recent_mtime, recent_mtime))
    os.utime(expired_quarantine, (expired_mtime, expired_mtime))
    os.utime(recent_quarantine, (recent_mtime, recent_mtime))

    with patch.object(cleanup_module.settings, "SHARED_DIR", str(shared_dir)):
        summary = file_cleanup_task(retention_days=14)
        
        assert summary["status"] == "ok"
        assert summary["dirs_removed"] == 1
        assert summary["dirs_skipped"] == 1
        assert summary["orphans_removed"] == 2  # expired_orphan + expired_quarantine
        
        assert not expired_dir.exists()
        assert recent_dir.exists()
        assert non_uuid_dir.exists()  # non-UUID skipped
        assert not expired_orphan.exists()
        assert recent_orphan.exists()
        assert not expired_quarantine.exists()
        assert recent_quarantine.exists()
