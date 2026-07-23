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
                if not isinstance(hex_str, str) or not hex_str.strip():
                    continue
                self._reference[brand] = imagehash.hex_to_hash(hex_str)
            except Exception as e:
                logger.warning("Skipping malformed hash for brand %s: %s", brand, e)

    @classmethod
    def from_file(cls, path):
        path = Path(path)
        if not path.exists():
            logger.info("No brand reference set at %s — brand-impersonation check skipped.", path)
            return cls({})
        try:
            with open(path) as f:
                data = json.load(f)
            if not isinstance(data, dict):
                logger.warning("Brand reference set at %s is not a JSON dict", path)
                return cls({})
            return cls(data)
        except Exception as e:
            logger.warning("Failed to load brand reference set from %s: %s", path, e)
            return cls({})

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
            try:
                distance = target_hash - ref_hash
                hash_bits = len(ref_hash)
                if not hash_bits or hash_bits <= 0:
                    continue
                similarity = 1.0 - (distance / hash_bits)
                similarity = max(0.0, min(1.0, float(similarity)))
                if similarity > best_similarity:
                    best_brand, best_similarity = brand, similarity
            except (TypeError, ValueError) as e:
                logger.warning("Skipping incompatible hash comparison for brand %s: %s", brand, e)
            except Exception as e:
                logger.warning("Unexpected error matching brand %s: %s", brand, e)

        if best_brand and best_similarity >= threshold:
            logger.debug("Brand match: %s at similarity %.3f", best_brand, best_similarity)
            return {"brand": best_brand, "similarity": round(best_similarity, 3)}
        return None

# Load references once at startup.
# Look first in adjacent ai_engine directory where reference_hashes.json is baked during Docker builds,
# falling back to ../../sandbox/backend/reference_hashes.json for local out-of-container dev runs.
_local_reference = os.path.join(os.path.dirname(__file__), "reference_hashes.json")
_fallback_reference = os.path.join(os.path.dirname(__file__), "../../sandbox/backend/reference_hashes.json")
_REFERENCE_PATH = os.environ.get(
    "BRAND_REFERENCE_JSON",
    _local_reference if os.path.exists(_local_reference) else _fallback_reference,
)
try:
    _matcher = BrandMatcher.from_file(_REFERENCE_PATH)
except Exception as e:
    logger.warning("Failed to initialize BrandMatcher from %s: %s", _REFERENCE_PATH, e)
    _matcher = BrandMatcher({})

def analyze_screenshot(image_path: str) -> dict:
    """
    Analyzes a screenshot for brand impersonation and extracts labels.
    Returns:
        {"logo": {"brand": str, "similarity": float} | None, "labels": list}
    """
    if not os.path.exists(image_path):
        logger.warning("analyze_screenshot called on missing file: %s", image_path)
        return {"logo": None, "labels": []}
        
    try:
        logo_match = _matcher.match(image_path)
    except Exception as e:
        logger.warning("Brand matching failed during analyze_screenshot(%s): %s", image_path, e)
        logo_match = None
    
    return {
        "logo": logo_match,
        "labels": []  # Extendable for object detection later
    }
