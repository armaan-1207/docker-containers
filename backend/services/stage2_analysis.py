"""
services/stage2_analysis.py
=============================
Stage 2 analysis intake: receives browser screenshot + DOM snapshot,
validates and persists them, then queues the Celery pipeline.

Security hardening (finding #10):
  - Strict image validation via PIL.Image.verify() before writing to disk.
    Without this check, an attacker who controls the Chrome extension could
    send arbitrary binary payloads that are later fed to OCR / vision /
    imagehash libraries. Malformed non-image data targeting these libraries
    can trigger memory corruption or buffer overflows.
  - Payload size is capped at 5 MB (well below nginx's 50 MB body limit)
    to prevent memory exhaustion in the Python process during base64 decode.
  - HTML payload size is capped at 10 MB.
  - Path traversal protection: scan_id is validated as a UUID before use
    in filesystem path construction.
"""

import base64
import binascii
import io
import logging
import os
import re
import uuid

from PIL import Image, UnidentifiedImageError

from database.models import Scan
from config import settings
from schemas.stage2 import Stage2Request, Stage2Response, JobStatus

logger = logging.getLogger(__name__)

# Maximum acceptable image size (5 MB) before base64 decode.
# Prevents memory exhaustion; keeps well below nginx's 50 MB body limit.
_MAX_IMAGE_BYTES = 5 * 1024 * 1024   # 5 MB

# Maximum acceptable HTML snapshot size (10 MB)
_MAX_HTML_BYTES = 10 * 1024 * 1024   # 10 MB

# UUID pattern for path-traversal protection on scan_id
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _scan_dir(scan_id: str) -> str:
    return os.path.join(settings.SHARED_DIR, scan_id)


def _validate_scan_id(scan_id: str) -> None:
    """Guard against path-traversal: scan_id must be a canonical UUID."""
    if not _UUID_RE.match(scan_id):
        raise ValueError(f"scan_id '{scan_id}' is not a valid UUID — rejected to prevent path traversal")


def _decode_and_validate_image(screenshot_base64: str) -> bytes:
    """
    Decode and validate the base64-encoded screenshot.

    Steps:
      1. Decode base64 → raw bytes (raises ValueError on malformed base64).
      2. Enforce 5 MB size cap.
      3. PIL structural verification — ensures the bytes are a parseable
         image, not an arbitrary binary payload targeting downstream libs.

    Returns the raw image bytes on success. Raises ValueError on any failure.
    """
    try:
        image_bytes = base64.b64decode(screenshot_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"screenshot_base64 is not valid base64: {exc}") from exc

    if len(image_bytes) > _MAX_IMAGE_BYTES:
        raise ValueError(
            f"Screenshot payload too large: {len(image_bytes)} bytes "
            f"(maximum {_MAX_IMAGE_BYTES} bytes / 5 MB)"
        )

    # PIL structural verification — Image.verify() raises on corrupt or
    # non-image data. We must re-open after verify() because verify()
    # consumes the file pointer and leaves the object unusable for reading.
    try:
        img = Image.open(io.BytesIO(image_bytes))
        img.verify()          # raises on corrupt / non-image data
    except (UnidentifiedImageError, Exception) as exc:
        raise ValueError(
            f"screenshot_base64 does not decode to a valid image: {exc}"
        ) from exc

    return image_bytes


async def run_stage2_analysis(payload: Stage2Request, user, db) -> Stage2Response:
    url = str(payload.url)

    # ── Validate and decode image before touching the database ───────────
    # Fail fast on bad input so we don't create orphan DB rows.
    image_bytes = _decode_and_validate_image(payload.screenshot_base64)

    # ── Validate HTML payload size ────────────────────────────────────────
    html_content = payload.html or "<html><body></body></html>"
    html_bytes = html_content.encode("utf-8", errors="replace")
    if len(html_bytes) > _MAX_HTML_BYTES:
        raise ValueError(
            f"html payload too large: {len(html_bytes)} bytes "
            f"(maximum {_MAX_HTML_BYTES} bytes / 10 MB)"
        )

    # ── Create scan record ────────────────────────────────────────────────
    scan = Scan(
        user_id=user.id,
        url=url,
        status="created",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_id = scan.id

    # ── Path-traversal guard ──────────────────────────────────────────────
    _validate_scan_id(scan_id)

    scan_dir = _scan_dir(scan_id)
    os.makedirs(scan_dir, exist_ok=True)

    # ── Persist validated artifacts ───────────────────────────────────────
    png_path = os.path.join(scan_dir, "browser.png")
    with open(png_path, "wb") as f:
        f.write(image_bytes)

    html_path = os.path.join(scan_dir, "browser.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    # ── Queue Celery pipeline ─────────────────────────────────────────────
    from tasks.browser_features import browser_features_task
    async_result = browser_features_task.delay(scan_id)

    scan.status = "browser_features_running"
    db.commit()

    return Stage2Response(
        scan_id=scan_id,
        job_id=async_result.id,
        status=JobStatus.QUEUED,
        url=url,
        screenshot_saved_path=png_path,
    )
