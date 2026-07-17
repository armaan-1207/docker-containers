# Security Policy

## Supported Versions

Only the `main` branch is actively supported with security updates. 

| Version | Supported          |
| ------- | ------------------ |
| `main`  | :white_check_mark: |
| `< 1.0` | :x:                |

## Threat Model

AEGIS is designed to handle extremely hostile input (live phishing URLs and attacker-controlled documents). The security architecture relies on:
1. **Network Isolation**: The detonation sandbox (`aegis_sandbox_runner`) operates on a strictly isolated network (`sandbox_net`) with egress controlled by egress proxy pinning.
2. **Privilege Dropping**: The sandbox drops all capabilities (`cap-drop: ALL`), enforces `no-new-privileges`, uses read-only root filesystems, and strict resource limits.
3. **SSRF Defense**: The backend implements strict SSRF protection for all external domain resolution, with kernel-level `DOCKER-USER` firewall rules as defense-in-depth against DNS rebinding.

## Reporting a Vulnerability

If you discover a security vulnerability in this project, please report it privately. **Do not disclose it as a public issue.**

Please email security reports to `security@example.com` (placeholder). We will acknowledge receipt within 48 hours and provide a timeline for the fix.

## Scope

The following areas are in-scope for security reports:
- Sandbox escapes or container breakouts.
- Server-Side Request Forgery (SSRF) bypasses.
- Authentication/Authorization bypasses.
- Remote Code Execution (RCE) in the backend or Celery workers.
- SQL Injection or database exposure.

The following are **out of scope**:
- Missing security headers (already tracked and enforced via Nginx).
- Findings from automated SAST/DAST tools without a reproducible proof-of-concept.
- Denial of Service (DoS) attacks requiring massive external resources.
