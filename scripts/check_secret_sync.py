#!/usr/bin/env python3
"""
CI / pre-deploy check to verify zero secret drift between root .env and backend/.env.
Ensures AEGIS_DB_PASSWORD, REDIS_PASSWORD, REDIS_SECURITY_PASSWORD, and SANDBOX_RUNNER_SECRET
match exactly across both configuration layers (DevSecOps Finding #4).
"""

import os
import sys

SECRETS_TO_CHECK = [
    "AEGIS_DB_PASSWORD",
    "REDIS_PASSWORD",
    "REDIS_SECURITY_PASSWORD",
    "SANDBOX_RUNNER_SECRET",
]


def parse_env_file(filepath: str) -> dict:
    env_vars = {}
    if not os.path.exists(filepath):
        return env_vars
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line:
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                env_vars[key] = val
    return env_vars


def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    root_env_path = os.path.join(root_dir, ".env")
    backend_env_path = os.path.join(root_dir, "backend", ".env")

    root_env = parse_env_file(root_env_path)
    backend_env = parse_env_file(backend_env_path)

    if not root_env and not backend_env:
        print("[check-secret-sync] WARNING: Neither .env nor backend/.env found. Skipping check.", file=sys.stderr)
        sys.exit(0)

    drift_found = False
    for key in SECRETS_TO_CHECK:
        root_val = root_env.get(key)
        backend_val = backend_env.get(key)
        if root_val is not None and backend_val is not None and root_val != backend_val:
            print(
                f"[check-secret-sync] ERROR: Secret drift detected for '{key}'!\n"
                f"  - root .env        : {root_val!r}\n"
                f"  - backend/.env     : {backend_val!r}\n"
                "Because docker-compose passes root .env values into container environments,\n"
                "root .env values override backend/.env at runtime. Keep them synchronized.",
                file=sys.stderr,
            )
            drift_found = True

    if drift_found:
        sys.exit(1)

    print("[check-secret-sync] SUCCESS: All shared secrets between root .env and backend/.env are synchronized.")
    sys.exit(0)


if __name__ == "__main__":
    main()
