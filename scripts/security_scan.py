#!/usr/bin/env python3
"""
Local Security Pipeline Runner (Fixes Medium #5).

Runs security scanning tools locally (or in pre-commit / CI):
- gitleaks (secrets scanning using .gitleaks.toml)
- bandit (SAST for Python files)
- pip-audit / safety (dependency vulnerability checks)
- trivy (container image vulnerability scanning)
"""

import subprocess
import shutil
import sys
import os

def check_and_run(tool_name, cmd_args, description):
    print(f"\n=======================================================================")
    print(f" [{tool_name.upper()}] {description}")
    print(f"=======================================================================")
    if not shutil.which(tool_name):
        print(f"[SKIP] '{tool_name}' not found on PATH. Install {tool_name} to enable this check.")
        return True
    
    try:
        res = subprocess.run([tool_name] + cmd_args)
        if res.returncode != 0:
            print(f"[FAIL] {tool_name} reported security findings (exit code {res.returncode}).")
            return False
        print(f"[PASS] {tool_name} passed without issues.")
        return True
    except Exception as e:
        print(f"[ERROR] Failed to run {tool_name}: {e}")
        return False

def main():
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    os.chdir(root_dir)

    success = True
    
    # 1. Gitleaks Secrets Scan
    success &= check_and_run(
        "gitleaks",
        ["detect", "--no-git", "-c", ".gitleaks.toml", "-v"],
        "Scanning codebase for leaked API keys, tokens, and credentials"
    )

    # 2. Bandit SAST Scan
    success &= check_and_run(
        "bandit",
        ["-r", "backend/", "sandbox/backend/", "-ll", "-ii"],
        "Static Application Security Testing (SAST) on Python code"
    )

    # 3. Pip-Audit / Safety on backend & sandbox requirements
    if shutil.which("pip-audit"):
        success &= check_and_run(
            "pip-audit",
            ["-r", "backend/requirements.txt", "-r", "sandbox/requirements.txt"],
            "Auditing Python dependencies for known CVEs"
        )
    elif shutil.which("safety"):
        success &= check_and_run(
            "safety",
            ["check", "-r", "backend/requirements.txt", "-r", "sandbox/requirements.txt"],
            "Auditing Python dependencies with Safety"
        )
    else:
        print("\n[SKIP] Neither 'pip-audit' nor 'safety' found on PATH for dependency checks.")

    # 4. Trivy Container Image Scan
    if shutil.which("trivy"):
        for img in ["aegis-backend:ci", "aegis-sandbox:v1.0.0"]:
            success &= check_and_run(
                "trivy",
                ["image", "--severity", "HIGH,CRITICAL", img],
                f"Scanning container image {img} for OS/package vulnerabilities"
            )
    else:
        print("\n[SKIP] 'trivy' not found on PATH for container image vulnerability scanning.")

    if not success:
        print("\n[FAILED] One or more security checks reported findings.")
        sys.exit(1)
    
    print("\n[SUCCESS] All security scans passed or skipped.")
    sys.exit(0)

if __name__ == "__main__":
    main()
