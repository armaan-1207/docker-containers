# AEGIS Backend & Celery Worker Architecture

## Overview
The `backend/` directory contains the FastAPI application server, Celery task processing pipeline (`celery_worker`), Celery beat periodic scheduler (`celery_beat`), and the admission control runner service (`aegis_sandbox_runner`). All components are built with strict least-privilege principles, hardened configurations, and zero-trust data flow between tiers.

## Entry Point (`entrypoint.sh`)
When the `aegis_backend` container launches, `entrypoint.sh` executes the following startup sequence:
1. **Database Readiness Check:** Polls PostgreSQL over TCP (`psycopg2`) until the database daemon accepts connections.
2. **Alembic Database Migrations:** Checks the `public` schema. If tables exist from legacy deployments without an `alembic_version` table, it stamps the schema at `head` to prevent data loss. Otherwise, it runs `alembic upgrade head` to apply all pending schema migrations cleanly. (`SQLAlchemy create_all()` is **not** used at runtime).
3. **Application Server Launch:** Execs `uvicorn main:app` in resource-saver mode (`workers=2` or configured (`WORKER_COUNT`)) after verifying ClamAV sidecar health.

## Key Files & Modules
| File / Directory | Purpose & Security Controls |
| :--- | :--- |
| `main.py` | FastAPI root application. Mounts REST routers (`/api/auth`, `/api/scan`, `/api/ioc`), WebSocket endpoints, and CORS middleware. Enforces strict payload ceilings. |
| `config.py` | Pydantic Settings reading environment variables (`backend/.env`). Enforces production guardrails on boot (`ENVIRONMENT=production` requires secret length $\ge 32$, pinned `@sha256:` sandbox image, no wildcard origins). |
| `celery_worker.py` | Celery app instance configured with AOF-backed Redis broker (`acks_late=True`, `reject_on_worker_lost=True`). Executes Stages 1–4 without Docker socket access (`UID 1001`). |
| `celery_beat.py` | Celery Beat periodic scheduler configuration: runs `file_cleanup_task` hourly, `reconcile_stale_jobs_task` every 10m, and daily `pg_dump` backups at 03:00 UTC. |
| `api/routes.py` | REST route handlers: `POST /api/scan/quick` (pre-flight check), `POST /api/scan/full` (asynchronous pipeline initiation), `GET /api/stats`. |
| `auth/` (`routes.py`, `jwt.py`, `dependencies.py`) | Authentication engine using SHA-256 pre-hashing before bcrypt (prevents $>72$ byte truncation). Enforces k-Anonymity HIBP breached password validation on registration, constant-time dummy comparisons, Redis token revocation blacklist (`jti`), and case-insensitive email matching. |
| `schemas/` | Pydantic request/response models validating incoming JSON structures and enum constraints. |
| `database/` | SQLAlchemy ORM models (`users`, `scans`, `incidents`, `iocs`, `statistics`) and connection pooling (`pool_pre_ping=True`). |
| `services/quickscan.py` | Synchronous pre-flight threat assessment. Caches non-placeholder verdicts in Redis keyed by full normalized URL (`quickscan:url:{scheme}://{host}{path}{query}`) for 5 minutes (`300s`). **Never caches random placeholder scores.** |
| `services/sandbox_runner_svc.py` | Core engine for `aegis_sandbox_runner` admission controller (`POST /detonate`). Validates bearer token (`X-Runner-Auth`), verifies local image existence, limits concurrency via `asyncio.Semaphore(10)`, and spawns isolated ephemeral containers via `docker_socket_proxy`. |
| `tasks/` | 5-Stage Celery pipeline modules (`browser_features.py`, `sandbox_analysis.py`, `consistency.py`, `risk_fusion.py`, `alert_pipeline.py`) plus maintenance jobs (`file_cleanup.py`, `job_reconciliation.py`, `db_backup.py`). |
| `ai_engine/` | Visual OCR (`pytesseract`), OpenCV image processing, and DOM feature extraction utilities. |
| `consistency_engine/` | Stage 3 diffing engine evaluating structural and visual cloaking between Stage 1 browser checks and Stage 2 sandbox telemetry. |
| `websocket/websocket_manager.py` | Multi-worker WebSocket manager using non-blocking Redis `SCAN` cursor iteration (`ws_worker:{user_id}:{worker_id}`) to reconcile active sessions without locking the broker. Authenticates clients via first-frame JSON (`{"type": "auth", "token": "<JWT>"}`). |

## 5-Stage Celery Analysis Pipeline
```
Stage 1: Feature Extraction (browser_features.py)
   ├─ Fetch initial page HTML, compute perceptual hashes (pHash), extract DOM structure
   └─ Run OCR and Vision classification
Stage 2: Sandbox Detonation & Malware Scan (sandbox_analysis.py)
   ├─ POST /detonate to aegis_sandbox_runner:8002 (no Docker socket on worker)
   ├─ Ephemeral Chromium container navigates URL, captures HAR logs & downloads inside aegis_sandbox_net
   ├─ Writes scan directory to shared_scans/<scan_id>/ (chmod 0o770, UID 1001)
   └─ Streams downloaded binaries and artifacts to ClamAV sidecar (INSTREAM TCP 3310)
Stage 3: Cloaking & Diff Analysis (consistency.py)
   └─ Compares Stage 1 vs Stage 2 telemetry to uncover bot cloaking behavior
Stage 4: ML Risk Fusion (risk_fusion.py)
   ├─ Assembles cyberintel, vision, DOM, and consistency features into final verdict (0–100)
   ├─ Caches authoritative result in Redis under `risk:{scan_id}` with 1-hour (`3600s`) TTL
   └─ Broadcasts WebSocket completion payload (`{"status": "risk_fusion_done", ...}`)
Stage 5: Incident & Alerting (alert_pipeline.py)
   └─ Non-blocking dispatch generating Incident/IOC records and Slack alerts for HIGH/CRITICAL threats (suppressed when `is_placeholder=True`)
```

## Volume & User Permissions Architecture
To eliminate data leaks across boundaries, all storage volumes share strict Unix ownership and mode restrictions:
* **User & Group:** The `aegis` runtime user in `backend` and `celery_worker` runs as `UID 1001 / GID 1001`. The `sandbox` user inside the Stage 2 Chromium container also runs as `UID 1001 / GID 1001`.
* **Shared Scans Directory (`shared_scans:/app/output`)**: Every scan creates an isolated subdirectory (`shared_scans/<scan_id>/`) with permissions set explicitly to `0o770` (`rwxrwx---`). Because the Celery worker and the ephemeral Playwright container share `UID/GID 1001`, both can freely read and write artifacts without requiring root access (`UID 0`) or world-writable permissions (`0o777`).

## Environment Variables (`backend/.env`)
```ini
DATABASE_URL=postgresql+psycopg2://aegis_user:aegis_pass@postgres:5432/aegis_db
AEGIS_DB_PASSWORD=<change-this-32-chars-min>
REDIS_URL=redis://redis:6379/0
REDIS_PASSWORD=<change-this-32-chars-min>
SECRET_KEY=<change-this-32-chars-min>
SANDBOX_RUNNER_SECRET=<change-this-32-chars-min>
SANDBOX_NETWORK=dockercontainers_sandbox_net
SANDBOX_IMAGE=aegis-sandbox@sha256:<pinned-sha256-hash>
SHARED_DIR=/shared/scans
ENVIRONMENT=production
```

## Security & Verification Utilities
See the root `Makefile` and `scripts/` directory for automated local CI validation:
* `python scripts/check_digest_drift.py`: Verifies zero drift between `SANDBOX_IMAGE` across `config.py`, `.env.example`, `docker-compose.yml`, and runner defaults.
* `python scripts/check_sandbox_sync.py`: Verifies runner RPC flags (`--cap-drop=ALL`, `--security-opt no-new-privileges:true`) match Compose security profiles.
* `python scripts/security_scan.py`: Runs local Bandit SAST and dependency audits.
