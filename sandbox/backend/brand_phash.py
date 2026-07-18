"""

USAGE
-----
    # one-time setup, run yourself against your own reference screenshots:
    python build_reference_set.py --out reference_hashes.json \\
        microsoft=/path/to/microsoft_login.png \\
        paypal=/path/to/paypal_login.png

    # at scan time:
    matcher = BrandMatcher.from_file("reference_hashes.json")
    match = matcher.match(screenshot_path)
    # -> {"brand": "microsoft", "similarity": 0.94} or None
"""

import json
import logging
from pathlib import Path

import imagehash
from PIL import Image
Image.MAX_IMAGE_PIXELS = 25_000_000  # 5,000 x 5,000 px limit (~100MB max RGBA memory)

logger = logging.getLogger("phishing_sandbox.brand_phash")

# Hamming-distance-derived similarity below this is not reported as a
# match. pHash distances run 0 (identical) to 64 (maximally different)
# for the default 8x8 hash; this threshold is a starting guess, not a
# validated cutoff — tune against your own reference set.
DEFAULT_SIMILARITY_THRESHOLD = 0.90
HASH_BITS = 64  # imagehash.phash default size (8x8 -> 64-bit hash)


class BrandMatcher:
    def __init__(self, reference_hashes: dict):
        # reference_hashes: {"microsoft": "a1b2c3...", "paypal": "..."}
        self._reference = {}
        for brand, hex_str in reference_hashes.items():
            try:
                if not isinstance(hex_str, str) or not hex_str.strip():
                    continue
                h = imagehash.hex_to_hash(hex_str)
                self._reference[brand] = h
            except Exception as e:
                logger.warning("Skipping malformed hash for brand %s: %s", brand, e)

    @classmethod
    def from_file(cls, path):
        path = Path(path)
        if not path.exists():
            logger.info("No brand reference set at %s — brand-impersonation "
                        "check will be skipped for this scan.", path)
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
                distance = target_hash - ref_hash  # Hamming distance
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

        if best_brand:
            logger.debug("Best candidate brand match: %s at similarity %.3f", best_brand, best_similarity)
            if best_similarity >= threshold:
                return {"brand": best_brand, "similarity": round(best_similarity, 3)}
        return None
