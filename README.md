# AEGIS — Docker Containers

Complete, self-contained Docker infrastructure for the **AEGIS Phishing Intelligence Platform**.

---

## Stack at a Glance

| Container | Image | Role | Port |
|-----------|-------|------|------|
| `aegis_nginx` | nginx:1.27-alpine | Receptionist — routes REST + WebSocket | `80`, `443` (host) |
| `aegis_backend` | desktop-backend | FastAPI / Uvicorn — API + auth + DB | internal |
| `aegis_postgres` | postgres:16-alpine | Primary datastore | internal |
| `aegis_redis` | redis:7.2-alpine | Celery broker + URL cache | internal |
| `aegis_celery_worker` | desktop-celery_worker | Pipeline task runner | internal |
| `aegis_celery_beat` | desktop-celery_beat | Periodic scheduler | internal |
| `aegis_sandbox` | desktop-sandbox | Playwright detonation (per-job) | internal |

## Architecture Flow 

```
Browser Extension / Client
       │
       ▼  :80 / :443
┌──────────────────┐
│   aegis_nginx    │  ← Receptionist
└────────┬─────────┘    /api/*   → backend:8000
         │              /ws/*    → backend:8000 (WebSocket upgrade)
         ▼ proxy_pass
┌──────────────────────────────────────────┐
│   aegis_backend  (FastAPI / Uvicorn)     │
│  → validates request & authenticates     │
│  → queues Celery pipeline tasks via Redis│
└────┬───────────────────┬─────────────────┘
     │ SQLAlchemy        │ Redis enqueue
     ▼                   ▼
┌──────────┐    ┌──────────────────────┐
│ Postgres │    │       Redis          │
│ users    │    │  Celery broker       │
│ scans    │    │  URL scan cache      │
└──────────┘    └──────────┬───────────┘
                           │ dequeue
                ┌──────────▼───────────┐
                │  aegis_celery_worker │
                │  Runs 5-stage scan   │
                └──────────┬───────────┘
                           │  shared_scans volume
                           ▼
                ┌──────────────────────┐
                │   aegis_sandbox      │
                │  Playwright Stage 5  │
                └──────────────────────┘
```

---

## Shared Volume — `shared_scans`

The central data bus connecting all containers that process scan artifacts:

```
shared_scans/
├── <scan_id>/
│   ├── browser.png              ← Stage 1: browser screenshot
│   ├── browser.html             ← Stage 1: page HTML
│   ├── browser_features.json    ← Stage 1: OCR + Vision + DOM
│   ├── sandbox.png              ← Stage 2: sandbox screenshot
│   ├── sandbox.html             ← Stage 2: sandbox HTML
│   ├── sandbox_metadata.json    ← Stage 2: sandbox telemetry
│   ├── consistency_report.json  ← Stage 3: diff report
│   ├── cyberintel.json          ← Stage 4: threat intel
│   └── risk_report.json         ← Stage 4: final risk score
```

---

## Quick Start

```powershell
# From this folder (docker containers/):

# 1. Start all core services
docker compose up -d nginx backend redis postgres celery_worker celery_beat

# 2. Check health
docker compose ps

# 3. Follow logs
docker compose logs -f

# Or using the PowerShell helper script:
.\aegis.ps1 up
.\aegis.ps1 status
.\aegis.ps1 logs
```

## Commands Reference

```powershell
.\aegis.ps1 up                        # Start core services
.\aegis.ps1 down                      # Stop services
.\aegis.ps1 logs                      # Follow all logs
.\aegis.ps1 build                     # Rebuild all images
.\aegis.ps1 status                    # Show health + ports
.\aegis.ps1 sandbox https://site.com  # Run one sandbox scan
.\aegis.ps1 shell                     # Backend bash shell
.\aegis.ps1 reset                     # DESTRUCTIVE: wipe volumes
```

---

## Folder Structure

```
docker containers/
├── docker-compose.yml       ← Master orchestration (start here)
├── aegis.ps1                ← PowerShell management helper
├── README.md                ← This file
│
├── backend/                 ← FastAPI app + all Python source
│   ├── Dockerfile           ← Multi-stage build (builder + runtime)
│   ├── Dockerfile.worker    ← Worker runtime image with ClamAV
│   ├── requirements.txt     ← All Python dependencies
│   ├── entrypoint.sh        ← Waits for DB, runs migrations, starts Uvicorn
│   ├── celery_entrypoint.sh ← Waits for Redis+DB, starts Celery
│   ├── .env                 ← Active environment (gitignored)
│   ├── .env.example         ← Template
│   ├── main.py              ← FastAPI app entry point
│   ├── config.py            ← Pydantic settings
│   ├── celery_worker.py     ← Celery worker setup
│   ├── celery_beat.py       ← Beat scheduler
│   ├── api/                 ← Route handlers
│   ├── auth/                ← JWT auth logic
│   ├── tasks/               ← Celery task modules (pipeline stages)
│   ├── ai_engine/           ← OCR, Vision, DOM extractor
│   ├── cyberintel/          ← Threat intel runners
│   ├── consistency_engine/  ← Browser vs Sandbox diff engine
│   ├── database/            ← SQLAlchemy models + session
│   ├── schemas/             ← Pydantic schemas
│   ├── services/            ← Business logic & ClamAV malware scanner
│   ├── websocket/           ← WebSocket manager
│   └── models/              ← ML model files (.pkl)
│
├── nginx/                   ← Nginx Receptionist & reverse proxy
├── postgres/                ← PostgreSQL datastore & initialization scripts
├── redis/                   ← Redis broker & cache documentation
└── sandbox/                 ← Playwright sandbox (Stage 5 detonation)
```

---

## Security & DevSecOps Highlights

- **Least Privilege Architecture:** All services (`nginx`, `backend`, `celery_worker`, `celery_beat`, `redis`, `clamav`, `sandbox`) run with `cap_drop: ALL` and `no-new-privileges: true`.
- **Non-Root Execution:** Application services run under the dedicated non-root `aegis` user (UID 1001).
- **Socket Isolation:** Celery workers do not have raw access to the Docker socket; they communicate strictly through a scoped `docker_socket_proxy` (`CONTAINERS=1`, `POST=1`, `IMAGES=0`, `NETWORKS=0`, `VOLUMES=0`, `EXEC=0`). For strict zero-trust multi-tenant setups, placing an admission-controlled gRPC job runner in front of the proxy is recommended.
- **Malware & Artifact Protection:** Uploaded files and DOM snapshots are scanned via a dedicated ClamAV sidecar (`aegis_clamav`) over TCP socket (`INSTREAM` protocol) with automatic signature updates (`freshclam`). `CLAMAV_FAIL_CLOSED=True` is strictly enforced when `DEBUG=False`.
- **Dynamic Runtime TLS:** Nginx dynamically generates self-signed TLS certificates (`generate-ssl.sh`) at container startup on first boot, eliminating static build-time private keys baked into image layers. Production deployments can volume-mount real certificates directly over `/etc/nginx/ssl/`.
- **SSRF & Network Protection:** Detonation requests and cloaking checks are guarded against Server-Side Request Forgery using version-independent network blocklists (explicitly covering CGNAT `100.64.0.0/10` and all IANA special-purpose ranges).
- **Path Traversal Protection:** All Celery pipeline tasks (`browser_features`, `sandbox_analysis`, `consistency`, `risk_fusion`, `alert_pipeline`, `file_cleanup`) rigorously validate `scan_id` against strict UUID regex (`_UUID_RE`) before performing any filesystem operations.
- **Job Reconciliation & Redis Persistence:** Redis is configured with persistence (`--appendonly yes`, `--save 60 1`) and a persistent volume (`redis_data`). Periodic job reconciliation (`tasks.job_reconciliation` every 10 mins) automatically detects jobs stuck mid-pipeline due to worker crashes or broker restarts and cleanly transitions them to `failed_timeout`.
- **Automated Security Tooling:** Integrated `Makefile` and cross-platform `scripts/` provide immediate DevSecOps automation (`make security-scan` for `gitleaks`, `bandit`, `pip-audit`, and `trivy`; `make pin-sandbox` to automatically build and pin exact SHA256 image digests into `.env`).

---

## DevSecOps & Commands Reference

```powershell
# DevSecOps Automation (Makefile or Python scripts)
make pin-sandbox                      # Build & pin immutable SANDBOX_IMAGE sha256 digest into .env
make security-scan                    # Run local SAST/dependency/secrets scan (gitleaks, bandit, pip-audit, trivy)
make run-scan                         # Run E2E integration verification scan (run_scan.py)

# PowerShell Helper
.\aegis.ps1 up                        # Start core services
.\aegis.ps1 down                      # Stop services
.\aegis.ps1 logs                      # Follow all logs
.\aegis.ps1 status                    # Show health + ports
```