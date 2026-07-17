#!/usr/bin/env python3
"""
Automated Sandbox Image Pinning Script (Fixes Medium #4).

Builds the sandbox image locally, extracts its immutable sha256 digest
from Docker, and automatically updates SANDBOX_IMAGE in the local .env file.
"""

import subprocess
import re
import os
import sys

IMAGE_NAME = "aegis-sandbox:v1.0.0"
ENV_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")

def run(cmd):
    print(f"[pin-sandbox] Running: {' '.join(cmd)}")
    return subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode().strip()

def main():
    print(f"[pin-sandbox] Building {IMAGE_NAME} from ./sandbox/docker/Dockerfile...")
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dockerfile = os.path.join(root_dir, "sandbox", "docker", "Dockerfile")
    context = os.path.join(root_dir, "sandbox")
    
    try:
        subprocess.check_call(["docker", "build", "-t", IMAGE_NAME, "-f", dockerfile, context])
    except subprocess.CalledProcessError as e:
        print(f"[pin-sandbox] ERROR: Docker build failed: {e}", file=sys.stderr)
        sys.exit(1)

    print("[pin-sandbox] Inspecting image repo digests / ID...")
    try:
        inspect_out = run(["docker", "inspect", "--format={{range .RepoDigests}}{{.}} {{end}}", IMAGE_NAME])
        digest = inspect_out.split()[0] if inspect_out.strip() else None
    except Exception:
        digest = None

    if not digest or "sha256:" not in digest:
        # If not pushed to repo, get image ID sha256
        inspect_id = run(["docker", "inspect", "--format={{.Id}}", IMAGE_NAME])
        sha = inspect_id.split(":")[-1]
        digest = f"{IMAGE_NAME.split(':')[0]}@sha256:{sha}"

    print(f"[pin-sandbox] Resolved digest: {digest}")

    # Update .env
    env_lines = []
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8") as f:
            env_lines = f.readlines()

    updated = False
    new_lines = []
    for line in env_lines:
        if line.strip().startswith("SANDBOX_IMAGE="):
            new_lines.append(f"SANDBOX_IMAGE={digest}\n")
            updated = True
        else:
            new_lines.append(line)

    if not updated:
        new_lines.append(f"\nSANDBOX_IMAGE={digest}\n")

    with open(ENV_PATH, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

    print(f"[pin-sandbox] Successfully updated SANDBOX_IMAGE in {ENV_PATH} to {digest}")

if __name__ == "__main__":
    main()
