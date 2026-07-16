# AEGIS Backend Container

## What runs here
FastAPI application served by **Uvicorn** (2 workers in resource-saver mode).

## Entry point
`entrypoint.sh` → waits for Postgres → runs SQLAlchemy `create_all` → starts Uvicorn

## Key files
| File | Purpose |
|------|---------|
| `main.py` | FastAPI app, mounts all routers, WebSocket endpoint |
| `config.py` | Pydantic Settings — reads from `.env` |
| `celery_worker.py` | Celery app instance (`include=` task discovery) |
| `celery_beat.py` | Beat scheduler + periodic task schedule |
| `api/routes.py` | `/api/scan/quick`, `/api/scan/full`, `/api/stats` |
| `auth/routes.py` | `/api/auth/login`, `/api/auth/register` |
| `auth/jwt.py` | JWT encode/decode (HS256) |
| `auth/dependencies.py` | `get_current_user` FastAPI dependency |
| `schemas/` | Pydantic request/response models |
| `database/models.py` | SQLAlchemy ORM (users, scans, incidents, iocs, statistics) |
| `database/database.py` | Engine + session factory + `init_db()` |
| `tasks/` | Celery pipeline task modules (see below) |
| `ai_engine/` | OCR, Vision, DOM feature extraction |
| `cyberintel/runner.py` | VirusTotal + Safe Browsing + WHOIS intel |
| `consistency_engine/` | Browser vs Sandbox diff engine |
| `risk_fusion.py` | LightGBM risk scoring engine |
| `websocket/websocket_manager.py` | WebSocket connection manager + broadcast |

## Celery pipeline stages
```
browser_features  →  sandbox_analysis  →  consistency  →  risk_fusion  →  alert_pipeline
    Stage 1               Stage 2           Stage 3          Stage 4          Stage 5
```

## Environment variables (backend/.env)
```
DATABASE_URL=postgresql+psycopg2://aegis_user:aegis_pass@postgres:5432/aegis_db
AEGIS_DB_PASSWORD=<change-this-32-chars-min>
REDIS_URL=redis://redis:6379/0
REDIS_PASSWORD=<change-this-32-chars-min>
SECRET_KEY=<change-this-32-chars-min>
SANDBOX_NETWORK=dockercontainers_sandbox_net
VIRUSTOTAL_API_KEY=<your-key>
GOOGLE_SAFE_BROWSING_API_KEY=<your-key>
SHARED_DIR=/shared/scans
```

> **Note on Database Password Drift & Troubleshooting:**
> If you encounter `FATAL: password authentication failed for user "aegis_user"`, check:
> 1. Whether `AEGIS_DB_PASSWORD` in `backend/.env` matches the password embedded in `DATABASE_URL` and root `.env`.
> 2. If you updated `.env`, ensure you recreate the container (`docker compose up -d --force-recreate backend`) and that `backend/.dockerignore` excludes `.env` to prevent stale secrets in Docker image layers.
> 3. Verify no host OS environment variable (`env | grep AEGIS_DB_PASSWORD` / Windows Environment Variables) is overriding the Compose environment.

## Docker image
Multi-stage build:
- **builder** stage: installs all Python deps with pip
- **runtime** stage: minimal python:3.11-slim, non-root `aegis` user (uid 1001)

## Exposed
Port `8000` (internal only — Nginx proxies to it)
