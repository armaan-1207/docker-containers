"""
ai_engine/ocr.py
=================
STATUS: PLACEHOLDER. This whole ai_engine package was missing from the
uploaded project despite being imported by tasks/browser_features.py and
consistency_engine/consistency_engine.py:

    from ai_engine.ocr import extract_text

Both call sites already document the expected contract:
    extract_text(image_path: str) -> str

TODO (whoever owns the AI/vision layer): swap this for a real OCR engine,
e.g. pytesseract:

    import pytesseract
    from PIL import Image
    def extract_text(image_path: str) -> str:
        return pytesseract.image_to_string(Image.open(image_path))
"""

import logging

logger = logging.getLogger(__name__)


def extract_text(image_path: str) -> str:
    logger.warning("ai_engine.ocr.extract_text is a placeholder - returning empty string for %s", image_path)
    return ""
