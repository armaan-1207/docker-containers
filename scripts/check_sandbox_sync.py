#!/usr/bin/env python3
"""
CI check to verify zero drift between docker-compose.yml sandbox definitions
and backend/services/sandbox_runner_svc.py runtime execution arguments.
"""

import os
import re
import sys

def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    compose_path = os.path.join(root_dir, "docker-compose.yml")
    runner_path = os.path.join(root_dir, "backend", "services", "sandbox_runner_svc.py")

    if not os.path.exists(compose_path) or not os.path.exists(runner_path):
        print("[check-sandbox-sync] ERROR: Required target files not found.", file=sys.stderr)
        sys.exit(1)

    with open(compose_path, "r", encoding="utf-8") as f:
        compose_content = f.read().replace("\r\n", "\n")
    with open(runner_path, "r", encoding="utf-8") as f:
        runner_content = f.read().replace("\r\n", "\n")

    # Required flags in sandbox_runner_svc.py
    required_runner_flags = [
        "\"--cap-drop\", \"ALL\"",
        "\"--security-opt\", \"no-new-privileges:true\"",
        "\"--read-only\"",
        "\"--pids-limit\", \"512\"",
        "\"--memory\", \"2g\"",
        "\"--cpus\", \"1.5\"",
        "\"--shm-size\", \"1gb\"",
        "\"--tmpfs\", \"/tmp:rw,noexec,nosuid,size=64m\"",
        "\"--tmpfs\", \"/home/sandbox/.config:rw,noexec,nosuid,size=32m\"",
        "\"--tmpfs\", \"/home/sandbox/.pki:rw,noexec,nosuid,size=16m\"",
        "\"--tmpfs\", \"/home/sandbox/.local:rw,noexec,nosuid,size=32m\"",
    ]

    missing_in_runner = []
    for flag in required_runner_flags:
        if flag not in runner_content:
            missing_in_runner.append(flag)

    if missing_in_runner:
        print("[check-sandbox-sync] ERROR: sandbox_runner_svc.py is missing required hardening flags:", file=sys.stderr)
        for flag in missing_in_runner:
            print(f"  - {flag}", file=sys.stderr)
        sys.exit(1)

    # Required sections in docker-compose.yml under sandbox:
    sandbox_compose_match = re.search(r'^\s{2}sandbox:\s*\n(.*?)(?=\n\s{2}[a-zA-Z0-9_-]+:|\n[a-zA-Z0-9_-]+:|\Z)', compose_content, re.DOTALL | re.MULTILINE)
    if not sandbox_compose_match:
        print("[check-sandbox-sync] ERROR: Could not locate 'sandbox:' service in docker-compose.yml", file=sys.stderr)
        sys.exit(1)

    sandbox_block = sandbox_compose_match.group(1)
    required_compose_strings = [
        "cap_drop:\n      - ALL",
        "security_opt:\n      - no-new-privileges:true",
        "read_only: true",
        "cpus: \"1.5\"",
        "memory: 2048M",
        "pids: 512",
        "shm_size: \"1gb\"",
        "/tmp:rw,noexec,nosuid,size=64m",
        "/home/sandbox/.config:rw,noexec,nosuid,size=32m",
        "/home/sandbox/.pki:rw,noexec,nosuid,size=16m",
        "/home/sandbox/.local:rw,noexec,nosuid,size=32m",
    ]

    missing_in_compose = []
    for s in required_compose_strings:
        if s not in sandbox_block:
            missing_in_compose.append(s)

    if missing_in_compose:
        print("[check-sandbox-sync] ERROR: docker-compose.yml 'sandbox' service is missing required hardening settings:", file=sys.stderr)
        for s in missing_in_compose:
            print(f"  - {repr(s)}", file=sys.stderr)
        sys.exit(1)

    print("[check-sandbox-sync] SUCCESS: sandbox_runner_svc.py and docker-compose.yml sandbox definitions are fully synchronized.")

if __name__ == "__main__":
    main()
