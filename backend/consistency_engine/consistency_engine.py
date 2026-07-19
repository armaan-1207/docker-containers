"""
consistency_engine/consistency_engine.py
==========================================
Compares the browser's view of a URL against the sandbox's independent
view to detect cloaking — the core AEGIS detection primitive.

Bug fix:
  compare_dom() previously hardcoded indeterminate=False. The sandbox
  container never writes an independent sandbox.html file (its DOM data
  lives in sandbox_metadata.json). Passing browser.html as a fallback
  for the sandbox DOM comparison produced a trivial similarity=1.0 every
  time (comparing the HTML file with itself). Fixed: analyze() now reads
  sandbox_html_available from sandbox_artifacts and passes it to
  compare_dom(), which returns indeterminate=True when False, causing
  the DOM channel to be excluded from the weighted score entirely.
"""

import difflib
import logging
from typing import Optional

from PIL import Image
Image.MAX_IMAGE_PIXELS = 25_000_000  # 5,000 x 5,000 px limit (~100MB max RGBA memory)

try:
    import imagehash
    _HAS_IMAGEHASH = True
except ImportError:
    _HAS_IMAGEHASH = False

import numpy as np

from ai_engine.ocr import extract_text
from ai_engine.vision import analyze_screenshot
from ai_engine.dom_extractor import extract_features

logger = logging.getLogger(__name__)

MISMATCH_THRESHOLD = 0.6

WEIGHTS = {
    "screenshot": 0.25,
    "ocr": 0.20,
    "dom": 0.20,
    "metadata": 0.15,
    "logo": 0.20,
}


class ConsistencyEngine:

    def compare_screenshots(self, browser_png_path: str, sandbox_png_path: str) -> dict:
        try:
            similarity = self._compare_images(browser_png_path, sandbox_png_path)
        except Exception:
            logger.exception("Screenshot comparison failed")
            similarity = 0.0

        return {
            "similarity": similarity,
            "method": "phash" if _HAS_IMAGEHASH else "pixel_diff",
            "indeterminate": False,  # screenshots are always real captured pixels, never placeholder
        }

    def _compare_images(self, path_a: str, path_b: str) -> float:
        if _HAS_IMAGEHASH:
            hash_a = imagehash.average_hash(Image.open(path_a))
            hash_b = imagehash.average_hash(Image.open(path_b))
            max_distance = len(hash_a.hash) ** 2
            distance = hash_a - hash_b
            return max(0.0, 1.0 - (distance / max_distance))

        img_a = np.asarray(Image.open(path_a).convert("L").resize((64, 64)), dtype=float)
        img_b = np.asarray(Image.open(path_b).convert("L").resize((64, 64)), dtype=float)
        mean_abs_diff = np.mean(np.abs(img_a - img_b)) / 255.0
        return max(0.0, 1.0 - mean_abs_diff)

    def compare_ocr(self, browser_ocr_text: str, sandbox_png_path: str) -> dict:
        try:
            sandbox_ocr_text = extract_text(sandbox_png_path)
        except Exception:
            logger.exception("Sandbox OCR extraction failed")
            sandbox_ocr_text = ""

        browser_stripped = (browser_ocr_text or "").strip()
        sandbox_stripped = (sandbox_ocr_text or "").strip()


        indeterminate = not browser_stripped and not sandbox_stripped

        similarity = difflib.SequenceMatcher(
            None, browser_stripped, sandbox_stripped
        ).ratio()

        return {
            "similarity": similarity,
            "sandbox_ocr_text": sandbox_ocr_text,
            "indeterminate": indeterminate,
        }

    def compare_dom(self, browser_dom: dict, sandbox_html_path: str,
                    sandbox_html_available: bool = True, final_url: str = "") -> dict:
        """Compare browser DOM features against sandbox DOM features.

        Args:
            browser_dom: DOM feature dict extracted from browser.html.
            sandbox_html_path: Path to sandbox HTML snapshot. Only used
                when sandbox_html_available=True.
            sandbox_html_available: Set False when the sandbox did not
                produce an independent HTML snapshot (current architecture).
                Returns indeterminate=True so the DOM channel is excluded
                from the weighted consistency score.
            final_url: The final URL after redirects, needed by extract_features.
        """
        if not sandbox_html_available:
            # Sandbox never wrote sandbox.html — DOM comparison impossible.
            # Return indeterminate so this channel drops out of weighted score.
            logger.debug("DOM comparison skipped — sandbox_html_available=False")
            return {
                "similarity": 1.0,   # neutral placeholder (not used when indeterminate)
                "sandbox_dom": {},
                "indeterminate": True,
                "reason": "sandbox_html_not_available",
            }

        try:
            sandbox_dom = extract_features(sandbox_html_path, final_url=final_url)
        except Exception:
            logger.exception("Sandbox DOM extraction failed")
            sandbox_dom = {}

        similarity = self._compare_dicts(browser_dom or {}, sandbox_dom)
        return {"similarity": similarity, "sandbox_dom": sandbox_dom, "indeterminate": False}

    def _compare_dicts(self, dict_a: dict, dict_b: dict) -> float:
        keys = set(dict_a.keys()) | set(dict_b.keys())
        if not keys:
            return 1.0

        matches = 0
        for key in keys:
            val_a, val_b = dict_a.get(key), dict_b.get(key)
            if isinstance(val_a, list) or isinstance(val_b, list):
                set_a, set_b = set(val_a or []), set(val_b or [])
                union = set_a | set_b
                matches += (len(set_a & set_b) / len(union)) if union else 1.0
            else:
                matches += 1.0 if val_a == val_b else 0.0

        return matches / len(keys)

    def compare_metadata(self, browser_dom: dict, sandbox_metadata: dict) -> dict:
        browser_title = (browser_dom or {}).get("title", "")
        sandbox_pages = (sandbox_metadata or {}).get("pages", {})
        sandbox_title = sandbox_pages.get("page_title", "") or (sandbox_metadata or {}).get("title", "")
        title_similarity = difflib.SequenceMatcher(
            None, browser_title.strip(), sandbox_title.strip()
        ).ratio()

        browser_url = (browser_dom or {}).get("final_url", "")
        sandbox_url = sandbox_pages.get("final_url", "") or (sandbox_metadata or {}).get("final_url", "")
        if not browser_url and not sandbox_url:
            url_match = 1.0
        else:
            url_match = 1.0 if browser_url and browser_url == sandbox_url else 0.0

        similarity = (title_similarity + url_match) / 2
        return {
            "similarity": similarity,
            "title_similarity": title_similarity,
            "final_url_match": bool(url_match),
            "indeterminate": False,
        }

    def compare_logo(self, browser_vision: dict, sandbox_png_path: str) -> dict:
        try:
            sandbox_vision = analyze_screenshot(sandbox_png_path)
        except Exception:
            logger.exception("Sandbox vision analysis failed")
            sandbox_vision = {}

        browser_brand = self._logo_signature(browser_vision)
        sandbox_brand = self._logo_signature(sandbox_vision)

        # Same reasoning as compare_ocr: both-None is ambiguous between
        # "neither page has a detectable logo" and "vision.py is a
        # placeholder that always returns None" -- indeterminate rather
        # than a confident match.
        indeterminate = browser_brand is None and sandbox_brand is None

        if indeterminate:
            similarity = 1.0
        elif browser_brand == sandbox_brand:
            similarity = 1.0
        else:
            similarity = 0.0

        return {
            "similarity": similarity,
            "browser_brand": browser_brand,
            "sandbox_brand": sandbox_brand,
            "indeterminate": indeterminate,
        }

    def _logo_signature(self, vision_result: dict) -> Optional[str]:
        logo = (vision_result or {}).get("logo") or {}
        return logo.get("brand")

    def generate_consistency_report(self, comparisons: dict) -> dict:
        # Dynamically drop the weight of any comparison flagged
        # indeterminate FOR THIS SCAN, renormalizing the rest so they
        # still sum to 1.0. A category stops being droppable the moment
        # its underlying extractor (ocr.py / vision.py) returns real,
        # non-empty output -- no static config to update later.
        active_weights = {
            name: weight
            for name, weight in WEIGHTS.items()
            if not comparisons[name].get("indeterminate", False)
        }
        indeterminate_categories = [
            name for name in WEIGHTS if comparisons[name].get("indeterminate", False)
        ]

        if not active_weights:
            # Everything indeterminate (e.g. both OCR and vision are
            # placeholders AND this particular page had no meaningful
            # DOM/metadata differences either) -- report as fully
            # low-confidence rather than dividing by zero.
            overall_score = comparisons["screenshot"]["similarity"]
            reduced_confidence = True
        else:
            weight_sum = sum(active_weights.values())
            overall_score = sum(
                comparisons[name]["similarity"] * (weight / weight_sum)
                for name, weight in active_weights.items()
            )
            reduced_confidence = bool(indeterminate_categories)

        mismatches = [
            name for name in active_weights
            if comparisons[name]["similarity"] < MISMATCH_THRESHOLD
        ]

        cloaking_suspected = (
            overall_score < MISMATCH_THRESHOLD or "logo" in mismatches
        )

        return {
            "consistency_score": round(overall_score, 4),
            "comparisons": comparisons,
            "mismatches": mismatches,
            "cloaking_suspected": cloaking_suspected,
            # New fields -- surfaced so risk_fusion.py / a future
            # dashboard can flag "this score is based on partial data"
            # rather than presenting it as equally reliable to a
            # fully-populated comparison.
            "reduced_confidence": reduced_confidence,
            "indeterminate_categories": indeterminate_categories,
        }

    def analyze(self, browser_artifacts: dict, sandbox_artifacts: dict) -> dict:
        browser_features = browser_artifacts.get("features", {})
        browser_dom = browser_features.get("dom", {})
        browser_ocr_text = browser_features.get("ocr_text", "")
        browser_vision = browser_features.get("vision", {})

        sandbox_png_path = sandbox_artifacts["png_path"]
        sandbox_html_path = sandbox_artifacts["html_path"]
        sandbox_metadata = sandbox_artifacts.get("metadata", {})
        # Bug fix: read the availability flag set by tasks/consistency.py.
        # When False, compare_dom() returns indeterminate=True and the DOM
        # channel is excluded from the weighted consistency score.
        sandbox_html_available = sandbox_artifacts.get("sandbox_html_available", True)

        final_url = browser_dom.get("final_url", "") or sandbox_metadata.get("final_url", "")
        comparisons = {
            "screenshot": self.compare_screenshots(
                browser_artifacts["png_path"], sandbox_png_path
            ),
            "ocr": self.compare_ocr(browser_ocr_text, sandbox_png_path),
            "dom": self.compare_dom(
                browser_dom, sandbox_html_path,
                sandbox_html_available=sandbox_html_available,
                final_url=final_url,
            ),
            "metadata": self.compare_metadata(browser_dom, sandbox_metadata),
            "logo": self.compare_logo(browser_vision, sandbox_png_path),
        }

        return self.generate_consistency_report(comparisons)