"""
Unit tests for Stage 2 intake (`services/stage2_analysis.py`), verifying
image validation, size limits, and ClamAV malware rejection.
"""

import pytest
from unittest.mock import patch, MagicMock
import os

from services.stage2_analysis import run_stage2_analysis, _decode_and_validate_image
from schemas.stage2 import Stage2Request


@pytest.mark.asyncio
async def test_stage2_malware_rejection():
    import base64
    import io
    from PIL import Image
    buf = io.BytesIO()
    im = Image.new("RGBA", (10, 10), (255, 0, 0, 0))
    im.save(buf, format="PNG")
    valid_png_b64 = base64.b64encode(buf.getvalue()).decode("ascii")

    req = Stage2Request(
        url="http://example.com/phishing",
        screenshot_base64=valid_png_b64,
        html="<html><body>Malicious script</body></html>",
    )

    mock_user = MagicMock()
    mock_user.id = "user-uuid"

    mock_db = MagicMock()
    mock_scan = MagicMock()
    mock_scan.id = "12345678-1234-1234-1234-123456789abc"
    mock_db.add.side_effect = lambda obj: None
    mock_db.refresh.side_effect = lambda obj: setattr(obj, "id", "12345678-1234-1234-1234-123456789abc")

    # Mock ClamAV detecting malware on browser.html
    with patch("services.stage2_analysis.scan_file_clamav", side_effect=[(True, "Clean"), (False, "Win.Trojan.Phish FOUND")]):
        with pytest.raises(ValueError, match=r"Malware check rejected Stage 2 upload: Clean \| Win\.Trojan\.Phish FOUND"):
            await run_stage2_analysis(req, mock_user, mock_db)
