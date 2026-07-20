# 🛡️ AEGIS — Phishing Intelligence Platform

<div align="center">

[![Docker](https://img.shields.io/badge/Docker-Security_Hardened-2496ED?style=for-the-badge&logo=docker&logoColor=white)](#architecture)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](#)
[![FastAPI](https://img.shields.io/badge/FastAPI-Async_API-009688?style=for-the-badge&logo=fastapi&logoColor=white)](#api-endpoints)
[![Celery](https://img.shields.io/badge/Celery-Pipeline_Workers-37814A?style=for-the-badge&logo=celery&logoColor=white)](#pipeline-stages)
[![ClamAV](https://img.shields.io/badge/ClamAV-Malware_Engine-FF6600?style=for-the-badge)](#security-controls)

**Self-contained, multi-network container platform for real-time phishing URL detonation, DOM/Vision/OCR risk analysis, and automated IOC extraction.**

</div>

---

## What Is AEGIS?

AEGIS is a three-tier system:

| Tier | Owner | Status |
|---|---|---|
| **Browser Extension** | Extension Team | In progress — sends screenshot + DOM to this API |
| **Backend / API / Celery** | This repo | ✅ Production-ready |
| **Sandbox Container** | This repo | ✅ Built and pinned |

This repo covers tiers 2 and 3. The extension plugs into the existing `POST /api/scans/stage2` endpoint. Everything also works standalone without the extension via `POST /api/scans/full`.

---

## Architecture

```
                           ┌────────────────────────────────────────────────────┐
                           │                   aegis_net                        │
  Browser / Extension      │                                                    │
  ────────────────►  Nginx ─► Backend (FastAPI) ─► Redis (Celery Broker)       │
  POST /api/scans/full     │       │                      │                     │
  POST /api/scans/stage2   │       ▼                      ▼                     │
  POST /api/scans/quick    │   Postgres            Celery Worker                │
                           │   (Users/Scans)       (OCR → DOM → Risk Fusion)    │
                           └───────────────────────────┬────────────────────────┘
                                                       │ HTTP RPC (port 8002)
                           ┌───────────────────────────▼────────────────────────┐
                           │              docker_proxy_net                       │
                           │   Sandbox Runner ──► Docker Socket Proxy           │
                           └───────────────────────────┬────────────────────────┘
                                                       │ docker run (scoped)
                           ┌───────────────────────────▼────────────────────────┐
                           │                 sandbox_net (isolated)              │
                           │       Playwright Container (ephemeral, read-only)  │
                           └────────────────────────────────────────────────────┘
```

### Containers

| Container | Image | Role |
|---|---|---|
| `aegis_nginx` | `nginx:1.27-alpine` | TLS termination, reverse proxy |
| `aegis_backend` | `desktop-backend` | FastAPI API + auth |
| `aegis_postgres` | `postgres:16-alpine` | Users, Scans, IOCs, Incidents |
| `aegis_redis` | `redis:7.2-alpine` | Celery broker + URL verdict cache |
| `aegis_redis_security` | `redis:7.2-alpine` | JWT revocation store (isolated) |
| `aegis_celery_worker` | `desktop-celery_worker` | OCR, DOM, Risk Fusion pipeline stages |
| `aegis_celery_beat` | `desktop-celery_beat` | Scheduler (cleanup, backups, reconciliation) |
| `aegis_sandbox_runner` | `desktop-aegis_sandbox_runner` | Admission controller + Docker RPC gateway |
| `aegis_clamav` | `clamav/clamav:stable` | Malware scanning sidecar |
| `aegis_socket_proxy` | `tecnativa/docker-socket-proxy` | Scoped Docker API proxy (no raw socket) |
| `aegis_sandbox_net_holder` | `alpine:3.19` | Keeps `sandbox_net` alive between detonations |

---

## Pipeline Stages

A URL submitted for deep analysis flows through these stages:

```
[Stage 1 — CyberIntel Gate]  < 3s  · VirusTotal / Google Safe Browsing / AbuseIPDB
        │  score ≥ 75 → IMMEDIATE BLOCK (no further processing)
        ▼
[Stage 2 — Visual + OCR + DOM]  < 5s  · OCR text, vision hashing, DOM feature extraction
        │  allowlisted domain OR low preliminary score → skip Stage 5
        ▼
[Stage 5 — Sandbox Detonation]  ~ 45s  · Playwright headless, isolated network
        │  timeout after retries → graceful fallback (pipeline continues with reduced confidence)
        ▼
[Stage 3 — Consistency Check]  < 1s  · Cloaking detection (browser vs sandbox diff)
        ▼
[Stage 4 — Risk Fusion]  < 1s  · LightGBM ensemble (placeholder until ML model ships)
        ▼
[Stage N — Alert Pipeline]  · Slack webhook + Incident DB row (suppressed while placeholder model active)
```

> **Note on Stage numbering:** Diagram stages (1–5) and Celery internal names differ for historical reasons. Each task file has a `Pipeline Stage (Diagram → Code)` comment at the top mapping the two.

> **Note on ML Model:** `risk_fusion.py` currently returns a random placeholder score. The `is_placeholder=True` flag suppresses all real alerts and Incident rows until the ML team wires in the trained LightGBM model. Everything else is real logic.

> **Note on Sandbox Timeout:** Sandbox detonation times out after ~120s. On timeout (HTTP 504), the task immediately writes a graceful fallback `sandbox_metadata.json` (`sandbox_available: false`) and continues the pipeline at reduced confidence — no retries, no pipeline stall. Sites on the trusted allowlist also skip the sandbox and receive a dummy metadata file so downstream stages never crash.

---

## Scan Modes

### Mode A — With Browser Extension (Full fidelity)
Extension captures real screenshot + DOM → `POST /api/scans/stage2`

### Mode B — URL only, no extension (Testing / CI)
Server captures real HTML via `requests`, generates placeholder screenshot → `POST /api/scans/full`

> OCR / visual brand checks are limited in Mode B (no real browser render). The sandbox (Stage 5) independently navigates the real page regardless of mode.

### Mode C — Quick cache check (Extension pre-check)
Extension polls before each page load → `POST /api/scans/quick`  
Returns cached verdict in < 50ms if URL was recently scanned. Does **not** trigger the Celery pipeline.

### Mode D — Direct sandbox detonation
```bash
python sandbox/backend/phishing_sandbox_scan.py <url>
```
Bypasses the API and Celery entirely — useful for raw telemetry capture.

---

## Quick Start (Local Development)

### Prerequisites
- Docker Desktop 4.x+
- Python 3.11 (for `run_scan.py` and scripts, not needed for the containers)

### 1. Clone and configure

```bash
git clone <repo-url>
cd aegis

# Copy env templates and fill in values
cp .env.example .env
cp backend/.env.example backend/.env
# Edit both files — minimum: set AEGIS_DB_PASSWORD, REDIS_PASSWORD,
# REDIS_SECURITY_PASSWORD, SECRET_KEY, SANDBOX_RUNNER_SECRET
```

### 2. Pin the sandbox image

```bash
# Build the sandbox container and write its sha256 digest into .env
python scripts/pin_sandbox.py
```

> This is required once after cloning, and again whenever `sandbox/docker/Dockerfile` changes. The sandbox runner refuses to start in production if the digest is still the placeholder value.

### 3. Start the stack

```bash
docker-compose up -d --build
```

Check everything is healthy:

```bash
docker-compose ps
# All containers should show "healthy"
```

### 4. Run a test scan

```bash
python run_scan.py \
  --host https://localhost \
  --email analyst@test.com \
  --password 'YourPassword' \
  --insecure \
  --url https://example.com/
```

The script polls the database every 2 seconds for up to **300 seconds** — enough for complex sites (e.g. Cloudflare's bot-challenge pages) that take ~120s in the sandbox. A clear timeout message with the manual DB query is shown if the limit is ever exceeded.

Or hit the Swagger UI at `https://localhost/docs` (only available when `DEBUG=true`).

---

## API Endpoints

All endpoints require a JWT bearer token except `/api/auth/register` and `/api/auth/login`.

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/auth/register` | Create account |
| `POST` | `/api/auth/login` | Get JWT token |
| `POST` | `/api/scans/quick` | Fast cache check (< 50ms, no pipeline) |
| `POST` | `/api/scans/full` | Full pipeline — URL only, no extension needed |
| `POST` | `/api/scans/stage2` | Full pipeline — with real screenshot + HTML (extension mode) |
| `GET` | `/api/scans/{scan_id}` | Get scan result and risk report |
| `GET` | `/api/scans/{scan_id}/artifacts/{name}` | Fetch a scan artifact (PNG, HTML, JSON) |
| `WS` | `/ws/scan/{scan_id}` | Real-time pipeline progress updates |
| `GET` | `/health` | Stack health check |

---

## Environment Variables

Copy `backend/.env.example` to `backend/.env` and configure:

```bash
# Required — generate strong random values
SECRET_KEY=<32+ char random>
AEGIS_DB_PASSWORD=<32+ char random>
REDIS_PASSWORD=<32+ char random>
REDIS_SECURITY_PASSWORD=<32+ char random>
SANDBOX_RUNNER_SECRET=<32+ char random>

# Environment (controls security guardrails)
ENVIRONMENT=development          # or: production, staging

# Threat Intelligence APIs (all optional — system fails-open if unconfigured)
VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_API_KEY=
URLSCAN_API_KEY=
ABUSEIPDB_API_KEY=
OPENPHISH_API_KEY=

# Alerting (optional)
SLACK_WEBHOOK_URL=

# Sandbox (auto-set by pin_sandbox.py — do not edit manually)
SANDBOX_IMAGE=aegis-sandbox@sha256:<digest>

# Pipeline tuning
SANDBOX_PRELIMINARY_THRESHOLD=25   # 0 = always detonate; 25 = skip clearly benign pages
ARTIFACT_RETENTION_DAYS=14
```

Root `.env` (one level up from `backend/`) is for Docker Compose variable interpolation only and needs the same password variables.

---

## Security Controls

| Control | Implementation |
|---|---|
| No raw Docker socket | Celery worker has zero Docker access. Sandbox runner talks only to `docker_socket_proxy` (scoped to `CONTAINERS=1, POST=1`) |
| Immutable sandbox image | `SANDBOX_IMAGE` must be a pinned `sha256` digest. Mutable tags rejected at startup |
| Host firewall probe | Sandbox runner actively tests that `169.254.169.254` is unreachable from `sandbox_net` on startup in production |
| ClamAV malware scan | Every uploaded screenshot + HTML is scanned before being written to the shared volume |
| Image payload validation | PIL structural verify + decompression bomb protection (25MP pixel limit) before any disk write |
| JWT revocation | Separate Redis instance (`redis_security`) for blacklist; fail-closed if unavailable |
| CORS allowlist | No wildcard `*` — explicit list required in production |
| Trusted host middleware | `ALLOWED_HOSTS` enforced via FastAPI `TrustedHostMiddleware` |
| Artifact path traversal | `scan_id` validated as UUID before use in any filesystem path |
| Secure-by-default startup | Config raises `RuntimeError` on weak secrets, placeholder digest, missing CORS, missing TLS cert enforcement in production |
| HTML sanitization | `nh3` sanitizes captured HTML before serving in analyst dashboard |
| Rate limiting (auth) | `MAX_LOGIN_ATTEMPTS=5` with `LOCKOUT_DURATION_SECONDS=900` |

---

## DevSecOps Scripts

```bash
# Verify secrets in .env match what's expected across all configs
python scripts/check_secret_sync.py

# Verify SANDBOX_IMAGE digest hasn't drifted from what's running
python scripts/check_digest_drift.py

# Check sandbox container config vs docker-compose
python scripts/check_sandbox_sync.py

# Check if ML model is ready (or still placeholder)
python scripts/check_model_ready.py

# Broad security scan (bandit, pip-audit, gitleaks stub)
python scripts/security_scan.py

# Re-pin sandbox after rebuilding
python scripts/pin_sandbox.py

# Apply host kernel iptables rules (Linux production only)
sudo bash scripts/setup_host_firewall.sh
```

---

## For the Extension Team

Your extension should:

1. **Quick check first** — `POST /api/scans/quick` with `{url}` on every page load. If response `risk_level` is `SAFE` or `LOW` and it's a cache hit, show green and skip step 2.

2. **Full scan** — If not cached or risk is unknown: let the page load, then call `POST /api/scans/stage2` with:
   ```json
   {
     "url": "https://...",
     "tab_id": 123,
     "screenshot_base64": "<base64 PNG from chrome.tabs.captureVisibleTab()>",
     "html": "<document.documentElement.outerHTML>"
   }
   ```

3. **Live updates** — Connect to `WS /ws/scan/{scan_id}` for real-time pipeline progress. The socket requires a `{"type":"auth","token":"<JWT>"}` frame within 3 seconds of connecting — the token must **not** be passed in the URL query string.

4. **Auth** — All endpoints need `Authorization: Bearer <JWT>`. Get the token from `POST /api/auth/login`.

5. **CORS** — Add your extension origin (`chrome-extension://<id>`) to `CORS_ALLOWED_ORIGINS` in `backend/.env`.



---

## Production Checklist

- [ ] `ENVIRONMENT=production` in root `.env`
- [ ] All 5 secret fields set to 32+ character random values
- [ ] `python scripts/pin_sandbox.py` run after any sandbox rebuild
- [ ] `sudo bash scripts/setup_host_firewall.sh` applied on the host
- [ ] Real TLS certificate mounted at `nginx/certs/` and `REQUIRE_REAL_CERT=true`
- [ ] `CORS_ALLOWED_ORIGINS` set to your extension ID and dashboard domain
- [ ] `ALLOWED_HOSTS` set to your public API hostname
- [ ] `DEBUG=false`
- [ ] Threat intelligence API keys configured
- [ ] `SLACK_WEBHOOK_URL` configured for alerts

---

## Repository Layout

```text
.
├── .env
├── .env.example
├── .gitignore
├── .gitleaks.toml
├── .trivyignore
├── aegis.ps1
├── docker-compose.prod.yml
├── docker-compose.yml
├── DOCKER_ARCHITECTURE_IDEATION.md
├── Makefile
├── PROJECT_DOCUMENTATION.md
├── README.md
├── renovate.json
├── run_scan.py
├── SECURITY.md
├── .kiro/
│   └── specs/
│       └── deployment-readiness/
├── backend/
│   ├── .dockerignore
│   ├── .env
│   ├── .env.example
│   ├── alembic.ini
│   ├── celery_beat.py
│   ├── celery_entrypoint.sh
│   ├── celery_worker.py
│   ├── config.py
│   ├── Dockerfile
│   ├── Dockerfile.runner
│   ├── Dockerfile.worker
│   ├── entrypoint.sh
│   ├── main.py
│   ├── README.md
│   ├── requirements.in
│   ├── requirements.runner.in
│   ├── requirements.runner.txt
│   ├── requirements.txt
│   ├── risk_fusion.py
│   ├── runner_entrypoint.sh
│   ├── __init__.py
│   ├── ai_engine/
│   │   ├── dom_extractor.py
│   │   ├── ocr.py
│   │   ├── reference_hashes.json
│   │   ├── vision.py
│   │   └── __init__.py
│   ├── alembic/
│   │   ├── env.py
│   │   ├── README
│   │   ├── script.py.mako
│   │   └── versions/
│   │       ├── 7b3a56a313b4_initial_baseline.py
│   │       ├── c8f12a456789_add_ondelete_cascade_to_fks.py
│   │       ├── d2575a9c427f_add_sandbox_telemetry_tables.py
│   │       └── d9a23b567890_add_is_superuser_to_users.py
│   ├── api/
│   │   ├── routes.py
│   │   └── __init__.py
│   ├── auth/
│   │   ├── dependencies.py
│   │   ├── jwt.py
│   │   ├── routes.py
│   │   ├── security.py
│   │   └── __init__.py
│   ├── consistency_engine/
│   │   ├── consistency_engine.py
│   │   └── __init__.py
│   ├── cyberintel/
│   │   ├── runner.py
│   │   └── __init__.py
│   ├── database/
│   │   ├── database.py
│   │   ├── models.py
│   │   └── __init__.py
│   ├── schemas/
│   │   ├── auth.py
│   │   ├── full_scan.py
│   │   ├── quick_scan.py
│   │   ├── responses.py
│   │   ├── stage2.py
│   │   └── __init__.py
│   ├── services/
│   │   ├── capture.py
│   │   ├── malware_scanner.py
│   │   ├── quickscan.py
│   │   ├── sandbox_runner_svc.py
│   │   ├── stage2_analysis.py
│   │   └── __init__.py
│   ├── tasks/
│   │   ├── alert_pipeline.py
│   │   ├── browser_features.py
│   │   ├── consistency.py
│   │   ├── db_backup.py
│   │   ├── file_cleanup.py
│   │   ├── job_reconciliation.py
│   │   ├── risk_fusion.py
│   │   ├── sandbox_analysis.py
│   │   └── __init__.py
│   ├── tests/
│   │   ├── requirements-test.txt
│   │   ├── test_alert_pipeline.py
│   │   ├── test_artifact_sanitization_opt_out.py
│   │   ├── test_auth_security.py
│   │   ├── test_consistency_engine.py
│   │   ├── test_cyberintel_runner.py
│   │   ├── test_file_cleanup.py
│   │   ├── test_lockout_and_hibp.py
│   │   ├── test_malware_scanner.py
│   │   ├── test_quickscan.py
│   │   ├── test_risk_fusion_placeholder.py
│   │   ├── test_sandbox_glob_fallback.py
│   │   └── test_stage2_intake.py
│   └── websocket/
│       ├── websocket_manager.py
│       └── __init__.py
├── nginx/
│   ├── Dockerfile
│   ├── generate-ssl.sh
│   ├── nginx.conf
│   └── README.md
├── postgres/
│   ├── init.sh
│   └── README.md
├── sandbox/
│   ├── pytest.ini
│   ├── README.md
│   ├── backend/
│   │   ├── brand_phash.py
│   │   ├── egress_proxy.py
│   │   ├── phishing_sandbox_scan.py
│   │   ├── reference_hashes.json
│   │   ├── ssrf_guard.py
│   │   └── __init__.py
│   ├── docker/
│   │   ├── docker-compose.yml
│   │   ├── Dockerfile
│   │   ├── requirements.in
│   │   └── requirements.txt
│   └── tests/
│       ├── requirements-test.txt
│       └── test_sandbox_security.py
└── scripts/
    ├── check_digest_drift.py
    ├── check_model_ready.py
    ├── check_sandbox_sync.py
    ├── check_secret_sync.py
    ├── pin_sandbox.py
    ├── security_scan.py
    └── setup_host_firewall.sh
```