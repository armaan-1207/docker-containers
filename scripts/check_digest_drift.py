#!/usr/bin/env python3
"""
CI check to verify zero drift across SANDBOX_IMAGE definitions.
Ensures backend/.env.example, docker-compose.yml, backend/config.py, and backend/services/sandbox_runner_svc.py
all reference the exact same pinned SANDBOX_IMAGE sha256 digest.
"""

import os
import re
import sys

def get_digest(content, pattern):
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        return None
    return match.group(1)

_SANDBOX_IMAGE_PATTERN = r'aegis-sandbox(?::[^\s@]+)?@sha256:[a-f0-9]{64}'


def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    files_to_check = {
        "backend/.env.example": (
            os.path.join(root_dir, "backend", ".env.example"),
            rf'SANDBOX_IMAGE=({_SANDBOX_IMAGE_PATTERN})'
        ),
        "docker-compose.yml (runner)": (
            os.path.join(root_dir, "docker-compose.yml"),
            rf'SANDBOX_IMAGE:\s*\$\{{SANDBOX_IMAGE:-({_SANDBOX_IMAGE_PATTERN})\}}'
        ),
        "docker-compose.yml (sandbox)": (
            os.path.join(root_dir, "docker-compose.yml"),
            rf'image:\s*\$\{{SANDBOX_IMAGE:-({_SANDBOX_IMAGE_PATTERN})\}}'
        ),
        "backend/config.py": (
            os.path.join(root_dir, "backend", "config.py"),
            rf'SANDBOX_IMAGE:\s*str\s*=\s*"({_SANDBOX_IMAGE_PATTERN})"'
        ),
        "backend/services/sandbox_runner_svc.py": (
            os.path.join(root_dir, "backend", "services", "sandbox_runner_svc.py"),
            rf'SANDBOX_IMAGE\s*=\s*os\.environ\.get\(\s*"SANDBOX_IMAGE",\s*"({_SANDBOX_IMAGE_PATTERN})"'
        )
    }

    digests = {}
    for name, (path, pattern) in files_to_check.items():
        if not os.path.exists(path):
            print(f"[check-digest-drift] ERROR: File not found: {path}", file=sys.stderr)
            sys.exit(1)
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        digest = get_digest(content, pattern)
        if not digest:
            print(f"[check-digest-drift] ERROR: Could not extract pinned SANDBOX_IMAGE digest from {name}", file=sys.stderr)
            sys.exit(1)
        digests[name] = digest

    unique_digests = set(digests.values())
    if len(unique_digests) > 1:
        print("[check-digest-drift] ERROR: Drift detected in SANDBOX_IMAGE digests across project files:", file=sys.stderr)
        for name, digest in digests.items():
            print(f"  - {name}: {digest}", file=sys.stderr)
        sys.exit(1)

    print(f"[check-digest-drift] SUCCESS: All files are synchronized with pinned SANDBOX_IMAGE digest: {list(unique_digests)[0]}")
    sys.exit(0)

if __name__ == "__main__":
    main()
