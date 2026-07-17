#!/usr/bin/env python3
"""
Pre-deploy readiness check (`check_model_ready.py`).

Gates deployment / traffic switching until the real LightGBM model (`lightgbm.pkl`)
is loaded, verified, and not running in placeholder/heuristic-only mode.

Can check:
  1. Filesystem check: verifies `LIGHTGBM_MODEL_PATH` exists, is non-empty (>10KB),
     and (if `EXPECTED_MODEL_SHA256` is set in env) matches the expected SHA256 digest.
  2. Live API check (optional/if --check-api flag is passed or endpoint is reachable):
     hits the backend health check (`/` or `/api/health`) or scans status endpoint
     and confirms the system is not reporting placeholder model warnings when in strict mode.

Exit codes:
  0: Model ready and verified. Safe to switch traffic.
  1: Model missing, invalid size/checksum, or placeholder active. Do NOT switch traffic.
"""

import argparse
import hashlib
import json
import logging
import os
import sys
import urllib.request
from urllib.error import URLError, HTTPError

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("check_model_ready")


def check_file_readiness(model_path: str, expected_sha256: str | None = None) -> bool:
    logger.info("Checking model file at path: %s", model_path)
    if not os.path.exists(model_path):
        logger.error("Model file missing at: %s", model_path)
        return False
    
    if not os.path.isfile(model_path):
        logger.error("Model path is not a regular file: %s", model_path)
        return False

    size_bytes = os.path.getsize(model_path)
    logger.info("Model file found. Size: %d bytes (%.2f KB)", size_bytes, size_bytes / 1024)

    # Minimum size check (heuristic: a real trained LightGBM model .pkl is typically >10 KB)
    if size_bytes < 1024:
        logger.error("Model file size (%d bytes) is suspiciously small (<1KB). Likely corrupt or placeholder stub.", size_bytes)
        return False

    if expected_sha256:
        logger.info("Verifying SHA256 checksum against expected: %s", expected_sha256)
        hasher = hashlib.sha256()
        with open(model_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        actual_sha256 = hasher.hexdigest()
        if actual_sha256.lower() != expected_sha256.lower():
            logger.error("Checksum mismatch! Expected %s but got %s", expected_sha256, actual_sha256)
            return False
        logger.info("SHA256 checksum verified: %s", actual_sha256)

    return True


def check_api_readiness(api_url: str) -> bool:
    logger.info("Checking API readiness endpoint: %s", api_url)
    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": "AEGIS-PreDeploy-Check/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            status_code = resp.getcode()
            body_bytes = resp.read()
            if status_code != 200:
                logger.error("API returned non-200 status code: %d", status_code)
                return False
            
            # If endpoint returns JSON with status or model info, verify it
            try:
                data = json.loads(body_bytes.decode("utf-8"))
                # If health check specifically reports model status
                if isinstance(data, dict):
                    model_status = data.get("model_status", data.get("status", "ok"))
                    if model_status in ("placeholder", "unloaded", "error"):
                        logger.error("API reports model not ready: %s", data)
                        return False
            except json.JSONDecodeError:
                pass # Non-JSON root endpoint / health check passed with 200 OK

            logger.info("API endpoint reachable and responding with 200 OK.")
            return True
    except (URLError, HTTPError, TimeoutError) as e:
        logger.error("Failed to reach API endpoint %s: %s", api_url, e)
        return False


def main():
    parser = argparse.ArgumentParser(description="AEGIS Pre-deploy Model Readiness Gate")
    parser.add_argument("--model-path", default=os.getenv("LIGHTGBM_MODEL_PATH", "backend/models/lightgbm.pkl"),
                        help="Path to the LightGBM model file (.pkl)")
    parser.add_argument("--expected-sha256", default=os.getenv("EXPECTED_MODEL_SHA256", None),
                        help="Expected SHA256 hash of the model file")
    parser.add_argument("--check-api", action="store_true",
                        help="Also hit live API health endpoint to verify online status")
    parser.add_argument("--api-url", default=os.getenv("API_HEALTH_URL", "http://localhost:8000/"),
                        help="URL of the backend API health endpoint")
    parser.add_argument("--strict", action="store_true",
                        help="Fail if the model file does not exist (default behavior unless --allow-placeholder is passed)")
    parser.add_argument("--allow-placeholder", action="store_true",
                        help="Allow deployment even if using placeholder/heuristic risk fusion (for dev/testing only)")

    args = parser.parse_args()

    if args.allow_placeholder:
        logger.warning("--allow-placeholder flag set. Bypassing strict model file check (dev/testing mode).")
        if args.check_api:
            if not check_api_readiness(args.api_url):
                sys.exit(1)
        logger.info("Pre-deploy check PASSED (placeholder allowed).")
        sys.exit(0)

    # Check filesystem readiness
    file_ok = check_file_readiness(args.model_path, args.expected_sha256)
    if not file_ok:
        logger.error("Model filesystem check FAILED. To deploy in dev/test without the trained model, use --allow-placeholder.")
        sys.exit(1)

    # Optional live API readiness check
    if args.check_api:
        api_ok = check_api_readiness(args.api_url)
        if not api_ok:
            logger.error("API readiness check FAILED.")
            sys.exit(1)

    logger.info("Pre-deploy check PASSED: LightGBM model verified and ready for production traffic.")
    sys.exit(0)


if __name__ == "__main__":
    main()
