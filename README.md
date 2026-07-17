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
| `aegis_sandbox_runner`| desktop-aegis_sandbox_runner | Admission control API gateway for Docker socket | internal (`8002`) |
| `aegis_clamav` | clamav/clamav:stable | Anti-malware sidecar daemon | internal (`3310`) |
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

## Pipeline Scan Duration & Timing Breakdown

An end-to-end URL scan through the 5-stage Celery pipeline typically completes in **10 to 20 seconds**. Below is the stage-by-stage timing breakdown:

| Pipeline Stage | What Happens | Typical Duration | Worst-Case / Timeout |
| :--- | :--- | :--- | :--- |
| **Stage 1: `browser_features.py`** | Extracts initial DOM features, runs `pytesseract` OCR, and calculates OpenCV image hashes. | **2 – 5 sec** | ~10 sec |
| **Stage 2: `sandbox_analysis.py`** | **Container Detonation (`aegis-sandbox`):** Headless Playwright/Chromium navigates the URL over isolated `sandbox_net`, captures network telemetry, downloads, and screenshots.<br>**Malware Scan (`ClamAV`):** Daemon sidecar (`aegis_clamav:3310`) scans generated artifacts and quarantined downloads. | **6 – 15 sec** | **45 sec** (Chromium timeout) or<br>**120 sec** (`SANDBOX_TIMEOUT_SEC` hard ceiling) |
| **Stage 3: `consistency.py`** | Compares Stage 1 DOM features vs Stage 2 sandbox telemetry to detect **cloaking** (e.g., site serving benign content to bots but phishing pages to normal users). | **0.2 – 0.8 sec** | ~2 sec |
| **Stage 4: `risk_fusion.py`** | ML Risk Ensemble scoring (`0-100` verdict), updates `Postgres`, caches result in `Redis`, and emits final `WebSocket` event (`"Done"`). | **0.3 – 0.7 sec** | ~2 sec |
| **Stage 5: `alert_pipeline.py`** | *(Only triggered if risk score is HIGH / CRITICAL)* Creates Incident & IOC records and dispatches Slack/SIEM alerts. | **Async (~1 sec)** | Non-blocking (runs after user gets verdict) |

### Turnaround Scenarios
- **Normal Fast Path (~10 to 18 seconds):** Standard web pages load and render rapidly; final verdict is returned over WebSocket in under 20 seconds.
- **Bot-Challenged Path (~25 to 35 seconds):** If a target site uses Cloudflare or bot-check interstitials, the sandbox automatically waits up to **10 seconds** (`challenge_wait_seconds`) for the interstitial to self-clear before capturing artifacts.
- **Timeout Protection (120 seconds):** If a target server hangs indefinitely (`Tarpit`), the `aegis_sandbox_runner` microservice forcefully terminates the container after 120 seconds (`SANDBOX_TIMEOUT_SEC`).

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

- **Least Privilege Architecture:** All services (`nginx`, `backend`, `celery_worker`, `celery_beat`, `redis`, `clamav`, `sandbox_runner`, `sandbox`) run with `cap_drop: ALL` and `no-new-privileges: true`.
- **Non-Root Execution:** Application services run under the dedicated non-root `aegis` user (UID 1001) and `runner` user (UID 1002).
- **Socket Isolation & Purpose-Built Admission Control (`aegis_sandbox_runner`):** Celery workers (`celery_worker`) have zero network access to the Docker socket or `docker_socket_proxy`. A dedicated, hardened FastAPI gateway (`aegis_sandbox_runner:8002`) on `docker_proxy_net` validates scan UUIDs (`_UUID_RE`) and constructs exact, immutable `docker run` commands with mandatory security options (`read-only`, `cap-drop ALL`, CPU/memory limits).
- **Sandbox Egress Hardening & WebRTC/QUIC Protection:** Sandbox detonation (`phishing_sandbox_scan.py`) runs with strict Chromium launch flags (`--disable-webrtc`, `--disable-quic`, `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`) to prevent internal host IP leaks via mDNS or UDP routing bypasses. `egress_proxy.py` enforces local IP pinning against DNS rebinding TOCTOU attacks with bounded concurrency (`asyncio.Semaphore(50)`).
- **Malware & Quarantine Protection:** Downloaded binaries from detonation are persisted into `shared_scans/quarantine/` across ephemeral container exits and scanned by a dedicated ClamAV sidecar (`aegis_clamav:3310`) via `INSTREAM` protocol (`CLAMAV_NO_FRESHCLAM=false`). Aging samples are pruned automatically according to configured retention schedules (`file_cleanup.py`).
- **Dynamic Runtime TLS:** Nginx dynamically generates ephemeral 4096-bit self-signed TLS certificates (`generate-ssl.sh`) at startup when real certificates are absent, preventing private keys from being baked into deterministic container layers. Production deployments can volume-mount Let's Encrypt certificates directly over `/etc/nginx/certs/`.
- **SSRF & Network Protection:** Detonation requests and cloaking checks are guarded against Server-Side Request Forgery using version-independent network blocklists (explicitly covering CGNAT `100.64.0.0/10` and all IANA special-purpose ranges).
- **Path Traversal Protection:** All Celery pipeline tasks (`browser_features`, `sandbox_analysis`, `consistency`, `risk_fusion`, `alert_pipeline`, `file_cleanup`) rigorously validate `scan_id` against strict UUID regex (`_UUID_RE`) before performing any filesystem operations.
- **Job Reconciliation & Redis Persistence:** Redis is configured with persistence (`--appendonly yes`, `--save 60 1`) and a persistent volume (`redis_data`). Periodic job reconciliation (`tasks.job_reconciliation` every 10 mins) automatically detects jobs stuck mid-pipeline due to worker crashes or broker restarts and cleanly transitions them to `failed_timeout`.
- **Automated CI/CD DevSecOps Pipeline (`.github/workflows/devsecops.yml`):** Automated pull-request gates enforce mandatory secrets scanning (`Gitleaks`), Python SAST (`Bandit`), dependency CVE audits (`pip-audit`), and container vulnerability scans (`Aquasecurity Trivy`) on `aegis-sandbox:ci` and `aegis-backend:ci` across pushes, PRs, and weekly scheduled sweeps (`0 4 * * 1`).
- **Supply Chain Automation (`renovate.json`):** Automated upkeep pinpoints exact SHA256 digests (`@sha256:...`) across all base Docker images and Python dependencies, opening automated PRs validated by CI when upstream security patches are released.

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