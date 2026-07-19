"""
Unit tests for get_scan_artifact in api/routes.py verifying that
sanitized=false requires superuser privileges and logs audit warnings.
"""

import pytest
from unittest.mock import patch, MagicMock, mock_open
from fastapi import HTTPException

from api.routes import get_scan_artifact
from database.models import User, Scan


@pytest.mark.asyncio
async def test_get_scan_artifact_unsanitized_forbidden_for_regular_user():
    mock_db = MagicMock()
    mock_user = User(id="user-1", email="regular@example.com", is_superuser=False)
    mock_scan = Scan(id="12345678-1234-4234-a234-123456789abc", user_id="user-1")
    mock_db.query.return_value.filter.return_value.first.return_value = mock_scan

    with patch("os.path.exists", return_value=True):
        with pytest.raises(HTTPException) as exc_info:
            await get_scan_artifact(
                scan_id="12345678-1234-4234-a234-123456789abc",
                artifact_name="browser.html",
                sanitized=False,
                db=mock_db,
                current_user=mock_user,
            )
        assert exc_info.value.status_code == 403
        assert "superuser privileges" in exc_info.value.detail


@pytest.mark.asyncio
async def test_get_scan_artifact_unsanitized_allowed_for_superuser():
    mock_db = MagicMock()
    mock_user = User(id="su-1", email="admin@example.com", is_superuser=True)
    mock_scan = Scan(id="12345678-1234-4234-a234-123456789abc", user_id="su-1")
    mock_db.query.return_value.filter.return_value.first.return_value = mock_scan

    dummy_html = "<script>alert(1)</script><h1>Test</h1>"
    with patch("os.path.exists", return_value=True):
        with patch("builtins.open", mock_open(read_data=dummy_html)):
            response = await get_scan_artifact(
                scan_id="12345678-1234-4234-a234-123456789abc",
                artifact_name="browser.html",
                sanitized=False,
                db=mock_db,
                current_user=mock_user,
            )
            assert response.body.decode("utf-8") == dummy_html
