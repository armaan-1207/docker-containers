<div align="center">

# 🛡️ AEGIS Phishing Intelligence Platform
### Enterprise-Grade, Zero-Trust DevSecOps & Hardened Container Infrastructure

[![Docker Security Hardened](https://img.shields.io/badge/Docker-Security_Hardened-2496ED?style=for-the-badge&logo=docker&logoColor=white)](#-7-layer-defense-in-depth-architecture)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)](#)
[![Playwright Detonation](https://img.shields.io/badge/Detonation-Playwright_Stage_2-2EAD33?style=for-the-badge&logo=playwright&logoColor=white)](#-pipeline-scan-duration--timing-breakdown)
[![ClamAV Malware Engine](https://img.shields.io/badge/Malware_Engine-ClamAV_Sidecar-FF6600?style=for-the-badge&logo=clamav&logoColor=white)](#-shared-data-bus--shared_scans-volume)
[![Zero Network Drift](https://img.shields.io/badge/Network-Strict_Isolation-00C853?style=for-the-badge&logo=linux&logoColor=white)](#-7-layer-defense-in-depth-architecture)

*A self-contained, multi-network container ecosystem engineered for high-speed, zero-leakage phishing detonation, multi-modal DOM/vision risk fusion, and automated IOC extraction.*

</div>

---

## 🌟 Executive Summary & Overview

The **AEGIS Phishing Intelligence Platform** is a secure orchestration suite and analysis pipeline designed to ingest, detonate, and classify suspicious URLs, credential harvesting pages, and drive-by downloads in real time. 

Traditional sandbox architectures suffer from structural vulnerabilities: workers processing untrusted web content frequently have direct access to the host's `docker.sock` (allowing trivial container escape to host root), or headless browsers leak internal infrastructure addresses via WebRTC, mDNS, and DNS rebinding (`TOCTOU` attacks). Furthermore, shared detonation networks often allow compromised browser containers to probe administrative or admission control endpoints.

AEGIS eliminates these attack vectors by enforcing a **7-Layer Defense-in-Depth Architecture**. Every component operates within strict least-privilege boundaries across three physically and logically isolated Docker bridge networks (`aegis_net`, `aegis_docker_proxy_net`, and `aegis_sandbox_net`), backed by kernel-level host firewall rules, active startup isolation probing, local proxy inspection, and strict secret segregation.

---

## 🚀 Getting Started & Go-Live Prerequisites

Before running `docker compose up` in staging or production, AEGIS requires two mandatory security guardrails to be initialized. The admission controller (`aegis_sandbox_runner`) performs active checks for both on startup:

### Step 1: Pin Immutable Sandbox Image Digest (`SANDBOX_IMAGE`)
By default, configuration files reference a placeholder digest (`@sha256:454a...`). To prevent supply-chain spoofing or unverified container execution, you must build and cryptographically pin the Playwright detonation image:

```bash
# Build the local sandbox image and rewrite the exact sha256 digest into .env
make pin-sandbox
# Or run the Python utility directly:
python scripts/pin_sandbox.py
```
> **Startup Guard:** If `aegis_sandbox_runner` starts up in production (`ENVIRONMENT=production`) while `SANDBOX_IMAGE` still contains the default placeholder digest, it raises a fatal `RuntimeError` and refuses to accept detonation requests.

### Step 2: Enforce Host Kernel Firewall (`DOCKER-USER` Chain)
Detonation containers inside `aegis_sandbox_net` require internet egress to navigate external URLs. To prevent SSRF attacks against host loopback, private networks, or cloud metadata services (`169.254.169.254`), install the host kernel iptables rules:

```bash
# Apply host kernel rules blocking private IP egress from aegis_sandbox_net
sudo bash scripts/setup_host_firewall.sh
```
> **Active Startup Probe:** Upon launch, `aegis_sandbox_runner` spawns a quick, unprivileged `busybox` probe inside `aegis_sandbox_net` attempting to reach `169.254.169.254:80`. If the probe succeeds (meaning iptables rules are missing or bypassed), the runner logs a `[CRITICAL SECURITY WARNING]` and halts immediately in production environments.

### Step 3: Launch the Stack
Once pinned and isolated, start the entire orchestration suite:

```bash
# Start all services (Backend, Workers, Runner, ClamAV, Redis, Postgres, Nginx)
docker compose up -d

# Check cluster status and health checks
docker compose ps
```

---

## 🏗️ Stack at a Glance

| Service | Container Name | Base Image | Role & Security Profile | Internal / Host Port |
| :--- | :--- | :--- | :--- | :--- |
| **Receptionist** | `aegis_nginx` | `nginx:1.27-alpine` | Reverse proxy, WebSocket router, & TLS termination. Ephemeral 4096-bit TLS generation (`cap_drop: ALL`, non-root). Supports `REQUIRE_REAL_CERT=true` in staging/production. | `80`, `443` (Host) |
| **API & Auth** | `aegis_backend` | `desktop-backend` | FastAPI / Uvicorn API server. JWT auth with SHA-256 pre-hashing & bcrypt (`UID 1001`). Enforces strict CORS and payload limits. Waits for ClamAV readiness on boot. | Internal (`8000`) |
| **Database** | `aegis_postgres` | `postgres:16-alpine` | Primary relational datastore for Users, Scans, IOCs, and Incidents (`UID 999`). Isolated strictly on `aegis_net`. | Internal (`5432`) |
| **Broker & Cache** | `aegis_redis` | `redis:7.2-alpine` | Celery message broker & URL scan cache with AOF persistence (`--appendonly yes`). Protected by `REDIS_PASSWORD`. | Internal (`6379`) |
| **Worker Engine** | `aegis_celery_worker`| `desktop-celery_worker`| Executes Stages 1–4 of the scan pipeline (`pytesseract` OCR, OpenCV, ML Risk Ensemble). **Zero Docker CLI/socket access.** | Internal |
| **Scheduler** | `aegis_celery_beat` | `desktop-celery_beat` | Periodic task scheduler (hourly retention cleanup, 10-minute job reconciliation, daily PostgreSQL backups). | Internal |
| **Admission Control**| `aegis_sandbox_runner`| `desktop-aegis_sandbox_runner`| **RPC Gateway to Docker Socket.** Enforces `X-Runner-Auth` bearer token, UUID validation, & concurrency limits (`8002`). Severed from `sandbox_net`. | Internal (`8002`) |
| **Network Holder** | `aegis_sandbox_net_holder` | `alpine:3.19` | Lightweight unprivileged holder (`tail -f /dev/null`, `UID 65534`) keeping `aegis_sandbox_net` active without exposing the runner. | Internal |
| **Malware Engine** | `aegis_clamav` | `clamav/clamav:stable` | Isolated `INSTREAM` virus scanning sidecar (`start_period: 300s`) for quarantined browser artifacts & Stage 2 uploads. | Internal (`3310`) |
| **Detonation Node** | `aegis_sandbox` | `desktop-sandbox` | Ephemeral, read-only Playwright/Chromium container spawned per scan job over isolated network (`--cap-drop ALL`, `--read-only`). | Ephemeral |

---

## 🔒 7-Layer Defense-in-Depth Architecture

```
                      [ Browser Extension / Client ]
                                    │
                                    ▼  HTTPS (:443) / WSS (:443)
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  RECEPTIONIST LAYER: aegis_nginx (Non-root, cap_drop: ALL, Ephemeral/Real TLS)       │
└───────────────────────────────────┬──────────────────────────────────────────────────┘
                                    │ /api/* & /ws/* (Proxy Pass)
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  CORE APPLICATION NETWORK: aegis_net (Isolated from Sandbox & Proxy Socket)          │
│                                                                                      │
│  ┌──────────────────────┐      SQLAlchemy      ┌──────────────────────────────────┐  │
│  │    aegis_backend     │ ───────────────────► │          aegis_postgres          │  │
│  │ (FastAPI / Uvicorn)  │                      └──────────────────────────────────┘  │
│  └──────────┬───────────┘                                                            │
│             │ Enqueue Task                                                           │
│             ▼                                                                        │
│  ┌──────────────────────┐      Dequeue Task    ┌──────────────────────────────────┐  │
│  │     aegis_redis      │ ◄─────────────────── │       aegis_celery_worker        │  │
│  │  (Celery Broker/AOF) │                      │    (Stages 1-4: OCR / Vision)    │  │
│  └──────────────────────┘                      └─────────────────┬────────────────┘  │
└──────────────────────────────────────────────────────────────────┼───────────────────┘
                                                                   │ Authenticated RPC
                                                                   │ (X-Runner-Auth + UUID)
                                                                   ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  ADMISSION CONTROL LAYER: aegis_sandbox_runner (FastAPI on docker_proxy_net)         │
│  • Enforces concurrency semaphore (MAX_CONCURRENT_DETONATIONS = 10 -> HTTP 429)      │
│  • Constructs exact, hardcoded, immutable `docker run --cap-drop ALL --read-only`    │
│  • Strictly isolated from aegis_sandbox_net (cannot be reached by detonation nodes)  │
└───────────────────────────────────┬──────────────────────────────────────────────────┘
                                    │ Filtered Socket API
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  PROXY SOCKET LAYER: docker_socket_proxy (tecnativa/docker-socket-proxy)            │
│  • Severed from Celery workers. Only accessible by aegis_sandbox_runner.            │
└───────────────────────────────────┬──────────────────────────────────────────────────┘
                                    │ Spawn Ephemeral Container
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  DETONATION NETWORK: aegis_sandbox_net (Held active by aegis_sandbox_net_holder)     │
│                                                                                      │
│  ┌────────────────────────────────────────────────────────────────────────────────┐  │
│  │ aegis_sandbox (Chromium Playwright)                                            │  │
│  │ • Read-only rootfs + tmpfs mounts | pids-limit: 512 | memory: 2g | cpus: 1.5   │  │
│  │ • WebRTC/QUIC disabled (--force-webrtc-ip-handling-policy=disable_non_proxied) │  │
│  │ • Chained through local egress_proxy.py (asyncio.Semaphore(50) tunnel limit)   │  │
│  └───────────────────────────────────────┬────────────────────────────────────────┘  │
│                                          │ INSTREAM Malware Check                    │
│                                          ▼                                           │
│  ┌────────────────────────────────────────────────────────────────────────────────┐  │
│  │ aegis_clamav:3310 (ClamAV Quarantine & Artifact Scanner - Fail-Closed Gate)    │  │
│  └────────────────────────────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│  HOST KERNEL LAYER: Linux iptables DOCKER-USER Chain (scripts/setup_host_firewall.sh)│
│  • Drops all outbound packets from aegis_sandbox_net to:                              │
│    - Cloud Metadata: 169.254.169.254/32 & 169.254.0.0/16                             │
│    - Host Gateways & Loopback: 127.0.0.0/8 & 0.0.0.0/8                               │
│    - RFC 1918 & RFC 6598 (CGNAT): 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16          │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### 🔑 Security Highlights & Deep Architectural Controls

1. **Strict Secret Segregation Across Trust Boundaries**
   * **No Shared Secrets**: Each trust boundary maintains its own independent cryptographic credential. The PostgreSQL database credentials (`AEGIS_DB_PASSWORD`) are completely separated from the RPC bearer token (`SANDBOX_RUNNER_SECRET`) required to communicate with `aegis_sandbox_runner`.
   * **Production Environment Enforcement**: When `ENVIRONMENT="production"`, `config.py` enforces strict startup validation: all secrets must be at least 32 characters (`len >= 32`), not equal to default development strings, `SANDBOX_IMAGE` must be pinned (`@sha256:` format), and all CORS/Host settings (`ALLOWED_HOSTS`, `CORS_ALLOWED_ORIGINS`) must be explicitly defined without wildcards (`*`).

2. **Complete Socket Severance & Admission Control (`aegis_sandbox_runner`)**
   * **Zero Docker API Exposure for Workers**: Celery workers processing untrusted web content via OCR (`pytesseract`) and computer vision (`OpenCV`) run inside `aegis_net` with **zero Docker CLI binaries and zero access to the Docker socket**.
   * **Authenticated RPC Gateway & Network Decoupling**: When a worker needs to detonate a URL, it sends an HTTP POST request to `aegis_sandbox_runner:8002/detonate`. The runner attaches only to `aegis_net` and `docker_proxy_net` — **it does not join `aegis_sandbox_net`**. This guarantees that no container inside the detonation network can ever connect back to the runner or attempt API abuse.
   * **Immutable Container Command & Concurrency Limits**: The runner constructs a hardcoded, immutable Docker run invocation (`--cap-drop ALL`, `--read-only`, `--tmpfs`, `--security-opt no-new-privileges:true`). It enforces a strict concurrency ceiling (`MAX_CONCURRENT_DETONATIONS = 10`) via an `asyncio.Semaphore`, returning `HTTP 429 Too Many Requests` when saturated.

3. **Kernel-Level & Application-Layer SSRF Protection**
   * **Host Kernel `DOCKER-USER` Firewall**: `scripts/setup_host_firewall.sh` inserts rules directly into the Linux host `DOCKER-USER` chain. Even if an attacker achieves Remote Code Execution inside the Chromium container, the host kernel drops any traffic originating from `aegis_sandbox_net` destined for **Cloud Metadata (`169.254.169.254`)**, loopback (`127.0.0.0/8`), or private IP ranges (`RFC 1918` / `RFC 6598 CGNAT`).
   * **`egress_proxy.py` & `ssrf_guard.py`**: Inside the detonation container, Chromium routes all traffic through a local `asyncio` egress proxy (`127.0.0.1:8888`). The proxy resolves destination hostnames using `ssrf_guard.is_safe_url()`, checking resolved IP addresses against an extensive table of blocked networks (`0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`). It prevents `TOCTOU` DNS rebinding by connecting directly to the verified `(safe_ip, port)` tuple using robust hostname parsing (`urlparse(url).hostname`).

4. **ClamAV Anti-Malware Sidecar (`INSTREAM` Socket & Health Gating)**
   * Every file downloaded by the browser during detonation or raw DOM structure captured is written to `shared_scans/quarantine/` and verified before processing.
   * The `aegis_clamav` container (`TCP 3310`) inspects artifacts using ClamAV's streaming `INSTREAM` protocol. The backend and celery worker `depends_on` hooks wait for ClamAV's `service_healthy` check (`start_period: 300s`), ensuring the virus database is fully updated before serving traffic. If `CLAMAV_FAIL_CLOSED=True` is set in production and the scanner daemon is unreachable, the platform fails closed cleanly (`HTTP 503 Service Unavailable`).

5. **Authentication Hardening, Account Lockout & HIBP Breached Password Check**
   * **SHA-256 Pre-hashing & Timing-Attack Protection**: To safely handle long passwords and prevent `bcrypt` truncation vulnerabilities (`>72 bytes`), all user passwords are pre-hashed with SHA-256 before `bcrypt` rounds. Login flows use constant-time dummy comparisons (`_DUMMY_HASH`) on unknown users to prevent account enumeration.
   * **k-Anonymity Breached Password Validation**: During user registration, the backend queries Have I Been Pwned using only the first 5 hex characters of the SHA-1 hash. Known breached passwords are rejected immediately.
   * **Redis-Backed Account Lockout & Frame-Based WebSocket Auth**: Repeated failed logins trigger an automatic temporary lockout per IP and email. On explicit logout or password reset, the JWT `jti` is added to a Redis blacklist. Real-time WebSocket clients authenticate via a strict JSON first-frame (`{"type": "auth", "token": "<JWT>"}`) rather than URL query parameters, eliminating token exposure in server access logs and proxy history.

6. **Automated File, Job, & Database Backup Management**
   * **Disk Exhaustion Prevention**: Celery beat triggers `file_cleanup_task` every hour, removing per-scan `UUID` directories and quarantined samples older than `ARTIFACT_RETENTION_DAYS` (default 14 days).
   * **Job Reconciliation**: Every 10 minutes, `reconcile_stale_jobs_task` inspects PostgreSQL for any scan tasks stuck in pending or running states longer than 30 minutes, cleanly transitioning orphaned jobs to `failed_timeout`.
   * **Automated Daily Backups**: Celery beat schedules daily logical PostgreSQL backups (`pg_dump`) at **03:00 UTC**. Backups are written to the `aegis_db_backups` Docker volume (`0o770` permissions) and automatically pruned after **7 days**.

7. **Robust Browser Lifecycle, pHash Mismatch & Atomicity Safeguards**
   * **Leak-Proof Browser Cleanup**: Playwright detonation in `phishing_sandbox_scan.py` is wrapped in structured outer `try/finally` blocks, ensuring the browser daemon process (`browser.close()`) is always terminated and cleaned up regardless of navigation or page initialization failures.
   * **Background Task Tracking**: Tracks and cleanly cancels any background response/page tasks created via `asyncio.create_task` during the scan session, preventing task leakage or unawaited task exception warnings.
   * **pHash Shape & Bounds Hardening**: The perceptual-hash comparison loop in `BrandMatcher` guards against shape mismatches (e.g. 16x16 vs 8x8 hashes) and value overflows, skipping incompatible comparison targets dynamically via granular `try/except` handlers and clamping output similarity strictly to the `[0.0, 1.0]` boundary.
   * **Cross-Platform Atomicity & Multi-Worker State**: Replaced `os.rename` with `os.replace` in `_atomic_write_json` to support atomic JSON results replacement seamlessly on both Windows and POSIX-compliant deployment environments. WebSocket connection tracking supports multi-worker Uvicorn scaling via worker-scoped Redis keys (`ws_worker:{user_id}:{worker_id}`).

---

## ⚡ Pipeline Scan Duration & Timing Breakdown

An end-to-end URL detonation through the Celery pipeline completes in **10 to 20 seconds** on standard web targets. Below is the exact execution flow across each stage:

| Pipeline Stage | Module & Tasks Performed | Typical Duration | Timeout / Safety Ceiling |
| :--- | :--- | :--- | :--- |
| **Stage 1: Feature Extraction** | `browser_features.py`<br>Fetches initial page HTML, extracts DOM feature metrics, runs `pytesseract` OCR recognition on initial visual captures, and computes perceptual image hashes. | **2 – 5 sec** | ~10 sec |
| **Stage 2: Sandbox & Malware** | `sandbox_analysis.py`<br>**Container Detonation:** Issues RPC `POST /detonate` to `aegis_sandbox_runner:8002`, spawning an ephemeral read-only `aegis-sandbox` container over `aegis_sandbox_net` to navigate the target URL, wait for DOM stability, capture network HAR files, and collect screenshots.<br>**Malware Inspection:** Streams downloaded binaries and DOM dumps to `aegis_clamav:3310` via `INSTREAM`. | **6 – 15 sec** | **45 sec** (Chromium navigation timeout)<br>or **120 sec** (`SANDBOX_TIMEOUT_SEC` hard ceiling) |
| **Stage 3: Cloaking Detection** | `consistency.py`<br>Runs `ConsistencyEngine` (`consistency_engine.py`) to perform structural and visual diffing (`phash` / pixel difference) between Stage 1 initial browser features and Stage 2 deep sandbox telemetry, identifying **cloaking** (sites serving benign pages to bots but phishing kits to real users). | **0.2 – 0.8 sec** | ~2 sec |
| **Stage 4: ML Risk Ensemble** | `risk_fusion.py`<br>Aggregates multi-modal signals across OCR, DOM structure, URL heuristics, and cloaking similarity into a unified risk verdict (`0–100`). Updates PostgreSQL, caches real verdicts in Redis (`300s` Stage 1 -> `3600s` authoritative), and emits real-time `"Done"` event via WebSocket.<br>*(Note: Model weights are currently placeholder (`is_placeholder=True`) while the ML ensemble is trained externally).* | **0.3 – 0.7 sec** | ~2 sec |
| **Stage 5: Incident Alerting** | `alert_pipeline.py`<br>*(Triggered asynchronously when risk level is `HIGH` or `CRITICAL`)*. Generates formal `Incident` and `IOC` records in PostgreSQL and dispatches SIEM/Slack notifications without delaying user UI responses. Marks status as `alert_pipeline_running` on execution start. | **Async (~1 sec)** | Non-blocking |

### 🕒 Execution Scenarios
* **Fast Path (~10 to 18 seconds):** Standard responsive landing pages load and settle quickly; the final classification is emitted over WebSocket almost immediately.
* **Bot-Challenged Path (~25 to 35 seconds):** When encountering Cloudflare or anti-bot interstitials, Playwright automatically waits up to **10 seconds** (`challenge_wait_seconds`) for the challenge to clear before capturing final DOM and screenshot evidence.
* **Tarpit Protection (120 seconds):** If a malicious server holds open connections indefinitely (`HTTP Tarpit`), `aegis_sandbox_runner` forcefully terminates the container after exactly `SANDBOX_TIMEOUT_SEC` (120s).

---

## 💾 Shared Data Bus — `shared_scans` Volume

All stages communicate cleanly without passing multi-megabyte image payloads through Redis memory by mounting the `aegis_shared_scans` Docker volume (`0o770` permissions) across `aegis_backend`, `celery_worker`, `aegis_sandbox_runner`, and the ephemeral `aegis_sandbox` containers.

### Schema Ingestion & Telemetry Mapping

During **Stage 2 (Sandbox & Malware)**, detailed execution logs captured by the Playwright engine (`sandbox_metadata.json`) are structured and automatically ingested into PostgreSQL relational tables. This supports high-performance querying and analytics across six database entities:

* **`NetworkActivity`**: Raw logs of all HTTP/HTTPS requests triggered during detonation, capturing URLs, resource types, methods, and status codes.
* **`TLSConnection`**: Full cryptographic profiles of connections established, tracking TLS versions, cipher suites, certificate details, and key exchange algorithms.
* **`FormMetrics`**: Extraction of form tags, field types (e.g. password, email, text), target action URLs, and submission hooks to detect credential harvesting traps.
* **`Download`**: Quarantined files, file names, SHA-256 hashes, MIME types, and destination paths processed by `aegis_clamav`.
* **`Redirect`**: Full browser navigation timeline logs capturing HTTP redirects, JavaScript routing, and window-open hooks.
* **`EvasionTechnique`**: Flagged anomalies indicating anti-sandbox evasion (e.g., debugger statements, viewport inspection, browser fingerprinting, and virtualization checks).

### Local Storage Layout
```
shared_scans/
├── quarantine/                  ← ClamAV quarantined downloads and dropped binary artifacts
└── <scan_id>/                   ← Canonical UUID directory per detonation job (chmod 0o770)
    ├── browser.png              ← Stage 1: Initial browser viewport screenshot
    ├── browser.html             ← Stage 1: Initial raw page HTML
    ├── browser_features.json    ← Stage 1: OCR text, vision hashes, and DOM feature metrics
    ├── sandbox.png              ← Stage 2: Sandbox viewport screenshot after challenges
    ├── sandbox_fullpage.png     ← Stage 2: Sandbox full-page screenshot after challenges
    ├── sandbox.html             ← Stage 2: Sandbox rendered DOM HTML
    ├── sandbox_metadata.json    ← Stage 2: Network HAR requests, redirect chains, & TLS details
    ├── consistency_report.json  ← Stage 3: Cloaking and behavioral diff evaluation metrics
    ├── cyberintel.json          ← Stage 4: External threat intelligence feed aggregations
    └── risk_report.json         ← Stage 4: Final ensemble score & classification verdict
```

---

## 🧰 Local Security & Automation Verification Suite

AEGIS includes a local DevSecOps automation suite via `Makefile`, Python audit scripts (`scripts/`), and PowerShell helpers (`aegis.ps1`) to verify zero configuration drift and maintain strict container security before deployment:

```bash
# ==============================================================================
# 1. DevSecOps Verification & Synchronization Suite (Linux / macOS / WSL)
# ==============================================================================
make pin-sandbox                      # Build & pin immutable SANDBOX_IMAGE sha256 digest into .env
python scripts/check_digest_drift.py  # Verify zero drift across SANDBOX_IMAGE definitions
python scripts/check_sandbox_sync.py  # Verify exact runner RPC vs docker-compose flag sync
python scripts/security_scan.py       # Run local SAST (Bandit), dependency audits, & Trivy scans

# ==============================================================================
# 2. Host Kernel Firewall Setup (Linux Deployment Hosts)
# ==============================================================================
sudo bash scripts/setup_host_firewall.sh 172.28.0.0/16  # Enforce DOCKER-USER chain isolation
```

```powershell
# ==============================================================================
# 3. PowerShell Management Helper (Windows / PowerShell)
# ==============================================================================
.\aegis.ps1 up                        # Start all core services in background
.\aegis.ps1 status                    # Display container health, ports, and memory usage
.\aegis.ps1 logs                      # Follow aggregated colorized logs across all containers
.\aegis.ps1 sandbox https://site.com  # Trigger an immediate test detonation via API
.\aegis.ps1 build                     # Rebuild all local Docker images cleanly
.\aegis.ps1 shell                     # Open interactive bash shell inside aegis_backend
.\aegis.ps1 reset                     # DESTRUCTIVE: Stop containers and wipe shared volumes
```

---

## 📂 Repository Directory Structure

```
docker containers/
├── docker-compose.yml       ← Master multi-network orchestration suite & volume definitions
├── Makefile                 ← DevSecOps automation (digest pinning & local vulnerability scanning)
├── aegis.ps1                ← Windows PowerShell management helper
├── README.md                ← This document
├── .env.example             ← Root configuration template (Postgres, Redis, & Runner secrets)
│
├── backend/                 ← FastAPI backend server & Celery task workers
│   ├── Dockerfile           ← Multi-stage optimized API build (builder + runtime, non-root UID 1001)
│   ├── Dockerfile.worker    ← Worker engine build with ClamAV client integration
│   ├── Dockerfile.runner    ← Purpose-built admission control microservice build
│   ├── requirements.txt     ← Pinned Python requirements
│   ├── main.py              ← FastAPI API entrypoint & middleware configuration
│   ├── config.py            ← Pydantic settings & environment validation guardrails
│   ├── celery_worker.py     ← Celery application instance & queue routing
│   ├── celery_beat.py       ← Periodic scheduler configuration (file cleanup & job reconciliation)
│   ├── api/                 ← REST route handlers (/api/auth, /api/scan, /api/ioc)
│   ├── auth/                ← SHA-256 pre-hashed bcrypt + JWT authentication & HIBP checking
│   ├── tasks/               ← 5-Stage Celery pipeline modules & validation guards
│   ├── ai_engine/           ← pytesseract OCR, OpenCV vision, & DOM extractor
│   ├── services/            ← Business logic, ClamAV scanner, & sandbox_runner_svc.py
│   ├── consistency_engine/  ← Stage 3 Diff engine (browser vs sandbox telemetry)
│   ├── database/            ← SQLAlchemy PostgreSQL models & session setup
│   ├── tests/               ← Complete backend pytest regression suite across services and tasks
│   └── websocket/           ← Real-time WebSocket connection manager
│
├── sandbox/                 ← Stage 2 Playwright Detonation Engine
│   ├── docker/              ← Chromium Dockerfile & browser dependencies
│   ├── backend/             
│   │   ├── egress_proxy.py  ← Hardened local proxy with asyncio.Semaphore(50) tunnel limits
│   │   └── ssrf_guard.py    ← Version-independent SSRF blocklists & CGNAT RFC 6598 protection
│   └── tests/               ← Comprehensive async regression suite (test_sandbox_security.py)
│
├── scripts/                 ← Administrative & DevSecOps validation utilities
│   ├── setup_host_firewall.sh ← Kernel-level DOCKER-USER chain isolation script
│   ├── pin_sandbox.py       ← Automated Docker image digest resolver
│   ├── security_scan.py     ← Local vulnerability sweep runner (Bandit, Trivy, pip-audit)
│   ├── check_digest_drift.py← Zero-drift validation utility for pinned container digests
│   ├── check_sandbox_sync.py← Zero-drift validation utility for runner RPC vs Compose sync
│   └── check_model_ready.py ← ML ensemble model verification utility
│
├── nginx/                   ← Receptionist reverse proxy & dynamic/real TLS termination
└── postgres/                ← Database init scripts, schema creation, & README
```

---

<div align="center">
  <b>AEGIS Phishing Intelligence Platform</b> — Built with zero-trust isolation, hardened container boundaries, and automated DevSecOps validation.
</div>