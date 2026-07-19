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

from PIL import Image, UnidentifiedImageError

# High #4 fix: Cap total image pixels to prevent decompression bombs across Pillow decodes
Image.MAX_IMAGE_PIXELS = 25_000_000  # 5,000 x 5,000 px limit (~100MB max RGBA memory)

from database.models import Scan
from config import settings
from schemas.stage2 import Stage2Request, Stage2Response, JobStatus
from services.malware_scanner import scan_file_clamav

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


def _decode_and_validate_image(b64_string: str) -> bytes:
    """
    Validates base64 string, checks byte size, and performs Pillow structural
    and dimensional verification. Returns raw image bytes on success.
    Raises ValueError with a safe message on any error.
    """
    try:
        # Strip data URI scheme if provided, e.g. "data:image/png;base64,..."
        if "," in b64_string[:64]:
            b64_string = b64_string.split(",", 1)[1]

        image_bytes = base64.b64decode(b64_string, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"screenshot_base64 is not valid base64: {exc}") from exc

    if len(image_bytes) > _MAX_IMAGE_BYTES:
        raise ValueError(
            f"Screenshot payload too large: {len(image_bytes)} bytes "
            f"(maximum {_MAX_IMAGE_BYTES} bytes / 5 MB)"
        )

    # PIL structural and dimensional verification — Image.verify() raises on corrupt or
    # non-image data. Check dimensions explicitly to prevent decompression bombs.
    try:
        img = Image.open(io.BytesIO(image_bytes))
        width, height = img.size
        if width * height > Image.MAX_IMAGE_PIXELS:
            raise ValueError(
                f"Image dimensions ({width}x{height} = {width*height} px) exceed limit "
                f"of {Image.MAX_IMAGE_PIXELS} pixels (decompression bomb protection)."
            )
        img.verify()          # raises on corrupt / non-image data
    except (UnidentifiedImageError, Exception) as exc:
        if isinstance(exc, ValueError) and "decompression bomb" in str(exc).lower():
            raise
        raise ValueError(
            f"screenshot_base64 does not decode to a valid image: {exc}"
        ) from exc

    return image_bytes


def run_stage2_analysis(payload: Stage2Request, user, db) -> Stage2Response:
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
    try:
        os.chmod(scan_dir, 0o770)  # nosec B103
    except OSError:
        pass

    # ── Persist validated artifacts ───────────────────────────────────────
    png_path = os.path.join(scan_dir, "browser.png")
    with open(png_path, "wb") as f:
        f.write(image_bytes)

    html_path = os.path.join(scan_dir, "browser.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)

    # ── Malware verification via ClamAV (security finding #2) ─────────────
    clean_png, png_details = scan_file_clamav(png_path)
    clean_html, html_details = scan_file_clamav(html_path)
    if not clean_png or not clean_html:
        # Delete unverified / malicious files before rejecting request
        for p in (png_path, html_path):
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass
        if "scanner unavailable" in png_details.lower() or "scanner unavailable" in html_details.lower() or "initializing" in png_details.lower() or "initializing" in html_details.lower():
            from fastapi import HTTPException, status
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Anti-malware scanner (ClamAV) is currently initializing or unavailable. Please retry shortly.",
            )
        raise ValueError(
            f"Malware check rejected Stage 2 upload: {png_details} | {html_details}"
        )

    # ── Queue Celery pipeline ─────────────────────────────────────────────
    from tasks.browser_features import browser_features_task
    try:
        async_result = browser_features_task.delay(scan_id)
        scan.status = "browser_features_running"
        db.commit()
    except Exception as exc:
        scan.status = "stage2_dispatch_failed"
        db.commit()
        logger.exception("Failed to dispatch browser_features_task for scan %s", scan_id)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Task dispatch queue is currently unavailable. Please retry shortly.",
        ) from exc

    return Stage2Response(
        scan_id=scan_id,
        job_id=async_result.id,
        status=JobStatus.QUEUED,
        url=url,
        screenshot_saved_path=png_path,
    )
