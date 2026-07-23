"""
ai_engine/ocr.py
=================
OCR text extraction from screenshot images using Tesseract / pytesseract.

Previously a placeholder that returned an empty string for every image.
Now implements real OCR via pytesseract so the consistency engine's
compare_ocr() method has actual text to compare between browser and
sandbox screenshots instead of two empty strings (which would always be
indeterminate and always skipped from the consistency score).

Requirements: pytesseract>=0.3.13, tesseract-ocr installed in the container.
The backend Dockerfile.worker installs tesseract-ocr via apt-get (`extract_text` executes inside `celery_worker`).
"""

import logging

from PIL import Image
Image.MAX_IMAGE_PIXELS = 25_000_000  # 5,000 x 5,000 px limit (~100MB max RGBA memory)

logger = logging.getLogger(__name__)


def extract_text(image_path: str) -> str:
    """
    Extract text from an image using Tesseract OCR.

    Returns the extracted text as a string. Returns an empty string on
    error (e.g., file not found, corrupt image) rather than raising —
    the consistency engine handles empty-string cases gracefully.
    """
    try:
        import pytesseract  # type: ignore[import-untyped]
    except ImportError:
        logger.error(
            "pytesseract is not installed — cannot extract text from %s. "
            "Add pytesseract to requirements.txt and rebuild the container.",
            image_path,
        )
        return ""

    try:
        img = Image.open(image_path)
        text = pytesseract.image_to_string(img)
        logger.debug(
            "OCR extracted %d chars from %s", len(text), image_path
        )
        return text
    except FileNotFoundError:
        logger.warning("OCR: image file not found: %s", image_path)
        return ""
    except Exception:
        logger.exception("OCR extraction failed for %s — returning empty string", image_path)
        return ""
