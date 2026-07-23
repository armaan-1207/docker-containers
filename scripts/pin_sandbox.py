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
    dockerfile = os.path.join(root_dir, "containers", "sandbox", "docker", "Dockerfile")
    context = os.path.join(root_dir, "containers")
    
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
        # If not pushed to repo, get image ID sha256.
        # DevSecOps Hardening (Finding #2): For local-only images without a RepoDigest,
        # constructing 'aegis-sandbox@sha256:<sha>' creates an un-runnable reference in Docker.
        # Using 'sha256:<sha>' directly resolves cleanly for both 'docker inspect' and 'docker run'.
        inspect_id = run(["docker", "inspect", "--format={{.Id}}", IMAGE_NAME])
        sha = inspect_id.split(":")[-1]
        digest = f"sha256:{sha}"

    print(f"[pin-sandbox] Resolved digest: {digest}")

    # Update .env files across the project
    target_files = [
        os.path.join(root_dir, ".env"),
        os.path.join(root_dir, "backend", ".env"),
        os.path.join(root_dir, "backend", ".env.example"),
    ]

    for target_path in target_files:
        env_lines = []
        if os.path.exists(target_path):
            with open(target_path, "r", encoding="utf-8") as f:
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

        with open(target_path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)

        print(f"[pin-sandbox] Successfully updated SANDBOX_IMAGE in {target_path} to {digest}")

    # Also update code fallback defaults in docker-compose.yml, config.py, and sandbox_runner_svc.py
    _digest_pattern = r'(?:aegis-sandbox(?::[^\s@]+)?@sha256:[a-f0-9]{64}|sha256:[a-f0-9]{64})'
    code_targets = [
        (os.path.join(root_dir, "docker-compose.yml"), rf'(SANDBOX_IMAGE:\s*\$\{{SANDBOX_IMAGE:-){_digest_pattern}(\}})', rf'\g<1>{digest}\g<2>'),
        (os.path.join(root_dir, "docker-compose.yml"), rf'(image:\s*\$\{{SANDBOX_IMAGE:-){_digest_pattern}(\}})', rf'\g<1>{digest}\g<2>'),
        (os.path.join(root_dir, "containers", "backend", "config.py"), rf'(SANDBOX_IMAGE:\s*str\s*=\s*"){_digest_pattern}(")', rf'\g<1>{digest}\g<2>'),
        (os.path.join(root_dir, "containers", "backend", "services", "sandbox_runner_svc.py"), rf'("SANDBOX_IMAGE",\s*"){_digest_pattern}(")', rf'\g<1>{digest}\g<2>')
    ]
    for target_path, pattern, repl in code_targets:
        if os.path.exists(target_path):
            with open(target_path, "r", encoding="utf-8") as f:
                content = f.read()
            new_content = re.sub(pattern, repl, content)
            if new_content != content:
                with open(target_path, "w", encoding="utf-8") as f:
                    f.write(new_content)
                print(f"[pin-sandbox] Successfully updated fallback default in {target_path} to {digest}")

if __name__ == "__main__":
    main()
