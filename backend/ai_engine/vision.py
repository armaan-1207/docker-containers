"""
ai_engine/vision.py
====================
STATUS: PLACEHOLDER. Missing from the uploaded project despite being
imported by tasks/browser_features.py and consistency_engine.py:

    from ai_engine.vision import analyze_screenshot

Expected contract (per both call sites' docstrings):
    analyze_screenshot(image_path: str) -> dict
    Expected to include something like:
        {"logo": {"brand": str, "bbox": [...]}, "labels": [...]}

TODO (whoever owns the AI/vision layer): wire this up to a real
brand/logo-detection model.
"""

import logging

logger = logging.getLogger(__name__)


def analyze_screenshot(image_path: str) -> dict:
    logger.warning("ai_engine.vision.analyze_screenshot is a placeholder - returning empty result for %s", image_path)
    return {"logo": None, "labels": []}
