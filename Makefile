# ==============================================================================
# AEGIS Pipeline — Developer & DevSecOps Makefile
# ==============================================================================

.PHONY: help pin-sandbox security-scan test run-scan deploy-prep

help:
	@echo "Available commands:"
	@echo "  make pin-sandbox    - Build sandbox image & pin exact sha256 digest into .env"
	@echo "  make security-scan  - Run local security suite (gitleaks, bandit, pip-audit, trivy)"
	@echo "  make run-scan       - Run E2E integration test scanner against local stack"
	@echo "  make deploy-prep    - Pin sandbox and verify infrastructure prerequisites before deployment"

pin-sandbox:
	python scripts/pin_sandbox.py

security-scan:
	python scripts/security_scan.py

run-scan:
	python run_scan.py

deploy-prep: pin-sandbox
	@echo "[deploy-prep] Sandbox image pinned. Verifying host firewall script..."
	@if [ ! -f scripts/setup_host_firewall.sh ]; then echo "ERROR: scripts/setup_host_firewall.sh not found!"; exit 1; fi
	@echo "[deploy-prep] REMINDER: Ensure 'sudo bash scripts/setup_host_firewall.sh' has been executed on the host kernel before running 'docker compose up -d' in staging/production."
