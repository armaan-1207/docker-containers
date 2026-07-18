"""
Unit tests for `_find_result_by_request_id` (`tasks/sandbox_analysis.py`),
verifying that glob fallback check is gated behind `ALLOW_GLOB_FALLBACK`.
"""

import os
import json
import pytest
from unittest.mock import patch, MagicMock

from tasks.sandbox_analysis import _find_result_by_request_id
import tasks.sandbox_analysis as sandbox_module


def test_glob_fallback_disabled_by_default(tmp_path):
    scan_id = "12345678-1234-1234-1234-123456789abc"
    # Create a candidate file in root that matches request_id via glob
    candidate_path = tmp_path / "scan_candidate.json"
    candidate_data = {"scans": {"request_id": scan_id}}
    candidate_path.write_text(json.dumps(candidate_data))

    with patch.object(sandbox_module.settings, "SHARED_DIR", str(tmp_path)):
        with patch.object(sandbox_module.settings, "ALLOW_GLOB_FALLBACK", False, create=True):
            with pytest.raises(FileNotFoundError, match="No sandbox result found"):
                _find_result_by_request_id(scan_id)


def test_glob_fallback_enabled(tmp_path):
    scan_id = "12345678-1234-1234-1234-123456789abc"
    # Create exact path location that does NOT exist
    # and candidate file in root that matches via glob
    candidate_path = tmp_path / "scan_candidate.json"
    candidate_data = {"scans": {"request_id": scan_id}}
    candidate_path.write_text(json.dumps(candidate_data))

    with patch.object(sandbox_module.settings, "SHARED_DIR", str(tmp_path)):
        with patch.object(sandbox_module.settings, "ALLOW_GLOB_FALLBACK", True, create=True):
            found_path, data = _find_result_by_request_id(scan_id)
            assert found_path == str(candidate_path)
            assert data["scans"]["request_id"] == scan_id
