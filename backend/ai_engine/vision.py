"""
ai_engine/vision.py
====================
Image analysis and brand impersonation detection via perceptual hashing.
"""

import json
import logging
import os
from pathlib import Path

import imagehash
from PIL import Image

# Prevent decompression bombs
Image.MAX_IMAGE_PIXELS = 25_000_000

logger = logging.getLogger(__name__)

DEFAULT_SIMILARITY_THRESHOLD = 0.90

class BrandMatcher:
    def __init__(self, reference_hashes: dict):
        self._reference = {}
        for brand, hex_str in reference_hashes.items():
            try:
                self._reference[brand] = imagehash.hex_to_hash(hex_str)
            except Exception as e:
                logger.warning("Skipping malformed hash for brand %s: %s", brand, e)

    @classmethod
    def from_file(cls, path):
        path = Path(path)
        if not path.exists():
            logger.info("No brand reference set at %s — brand-impersonation check skipped.", path)
            return cls({})
        with open(path) as f:
            return cls(json.load(f))

    def match(self, screenshot_path, threshold=DEFAULT_SIMILARITY_THRESHOLD):
        if not self._reference or not screenshot_path:
            return None
        try:
            target_hash = imagehash.phash(Image.open(screenshot_path))
        except Exception as e:
            logger.warning("Could not hash screenshot %s: %s", screenshot_path, e)
            return None

        best_brand, best_similarity = None, 0.0
        for brand, ref_hash in self._reference.items():
            distance = target_hash - ref_hash
            hash_bits = len(ref_hash)
            similarity = 1 - (distance / hash_bits)
            if similarity > best_similarity:
                best_brand, best_similarity = brand, similarity

        if best_brand and best_similarity >= threshold:
            logger.debug("Brand match: %s at similarity %.3f", best_brand, best_similarity)
            return {"brand": best_brand, "similarity": round(best_similarity, 3)}
        return None

# Load references once at startup (assuming backend runs relative to project root or uses absolute paths)
# Try standard locations where reference_hashes.json might be depending on execution context.
_REFERENCE_PATH = os.environ.get(
    "BRAND_REFERENCE_JSON", 
    os.path.join(os.path.dirname(__file__), "../../sandbox/backend/reference_hashes.json")
)
_matcher = BrandMatcher.from_file(_REFERENCE_PATH)

def analyze_screenshot(image_path: str) -> dict:
    """
    Analyzes a screenshot for brand impersonation and extracts labels.
    Returns:
        {"logo": {"brand": str, "similarity": float} | None, "labels": list}
    """
    if not os.path.exists(image_path):
        logger.warning("analyze_screenshot called on missing file: %s", image_path)
        return {"logo": None, "labels": []}
        
    logo_match = _matcher.match(image_path)
    
    return {
        "logo": logo_match,
        "labels": []  # Extendable for object detection later
    }
