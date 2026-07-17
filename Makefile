# ==============================================================================
# AEGIS Pipeline — Developer & DevSecOps Makefile
# ==============================================================================

.PHONY: help pin-sandbox security-scan test run-scan

help:
	@echo "Available commands:"
	@echo "  make pin-sandbox    - Build sandbox image & pin exact sha256 digest into .env"
	@echo "  make security-scan  - Run local security suite (gitleaks, bandit, pip-audit, trivy)"
	@echo "  make run-scan       - Run E2E integration test scanner against local stack"

pin-sandbox:
	python scripts/pin_sandbox.py

security-scan:
	python scripts/security_scan.py

run-scan:
	python run_scan.py
