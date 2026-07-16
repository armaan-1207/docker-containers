# AEGIS — Docker Containers

Complete, self-contained Docker infrastructure for the **AEGIS Phishing Intelligence Platform**.

---

## Stack at a Glance

| Container | Image | Role | Port |
|-----------|-------|------|------|
| `aegis_nginx` | nginx:1.27-alpine | Receptionist — routes REST + WebSocket | `80` (host) |
| `aegis_backend` | desktop-backend | FastAPI / Uvicorn — API + auth + DB | internal |
| `aegis_postgres` | postgres:16-alpine | Primary datastore | internal |
| `aegis_redis` | redis:7.2-alpine | Celery broker + URL cache | internal |
| `aegis_celery_worker` | desktop-celery_worker | Pipeline task runner | internal |
| `aegis_celery_beat` | desktop-celery_beat | Periodic scheduler | internal |
| `aegis_sandbox` | desktop-sandbox | Playwright detonation (per-job) | internal |

## Architecture Flow 

```
Browser Extension
      │
      ▼  :80
┌──────────────────┐
│   aegis_nginx    │  ← Receptionist
│   (port 80)      │    /api/*   → backend:8000
└────────┬─────────┘    /ws/*    → backend:8000 (WebSocket upgrade)
         │
         ▼ proxy_pass
┌──────────────────────────────────────────┐
│   aegis_backend  (FastAPI / Uvicorn)      │
│                                          │
│  auth.py ──── JWT decode ───► Postgres  │  ①②
│  schemas/ ─── Pydantic validate          │  ③
│  api/routes/ ─ QuickScan, FullScan       │  ②
│  → queue Celery task via Redis           │
└────┬───────────────────┬─────────────────┘
     │ SQLAlchemy         │ Redis enqueue
     ▼                    ▼
┌──────────┐    ┌──────────────────────┐
│ Postgres │    │       Redis          │
│ users    │    │  Celery broker       │
│ scans    │    │  URL scan cache      │
│ incidents│    └──────────┬───────────┘
│ iocs     │               │ dequeue
│ statistics│   ┌──────────▼───────────┐
└──────────┘    │  aegis_celery_worker  │
                │  Stage 1: browser_features   │
                │  Stage 2: sandbox_analysis   │
                │  Stage 3: consistency        │
                │  Stage 4: risk_fusion        │
                │  Stage 5: alert_pipeline     │
                └──────────┬───────────────────┘
                           │  shared_scans volume
                           ▼
                ┌──────────────────────┐
                │   aegis_sandbox      │
                │  Playwright Stage 5  │
                │  Writes scan_*.json  │
                │  Writes scan_*.png   │
                └──────────────────────┘

Separately:
┌──────────────────────┐
│  aegis_celery_beat   │  Fires sweep tasks every 5/15/60 min
└──────────────────────┘
```

---

## Shared Volume — `shared_scans`

The central data bus connecting all containers that process scan artefacts:

```
shared_scans/
├── <scan_id>/
│   ├── browser.png              ← Stage 1: browser screenshot
│   ├── browser.html             ← Stage 1: page HTML
│   ├── browser_features.json   ← Stage 1: OCR + Vision + DOM
│   ├── sandbox.png              ← Stage 2: sandbox screenshot
│   ├── sandbox.html             ← Stage 2: sandbox HTML
│   ├── sandbox_metadata.json   ← Stage 2: sandbox telemetry
│   ├── consistency_report.json ← Stage 3: diff report
│   ├── cyberintel.json          ← Stage 4: threat intel
│   └── risk_report.json        ← Stage 4: final risk score
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

# Using the helper script:
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
├── docker-compose.yml      ← Master orchestration (start here)
├── aegis.ps1               ← PowerShell management helper
├── .gitignore
├── README.md               ← This file
│
├── backend/                ← FastAPI app + all Python source
│   ├── Dockerfile          ← Multi-stage build (builder + runtime)
│   ├── requirements.txt    ← All Python deps
│   ├── entrypoint.sh       ← Waits for DB, runs create_all, starts Uvicorn
│   ├── celery_entrypoint.sh← Waits for Redis+DB, starts Celery
│   ├── .env                ← Active environment (gitignored)
│   ├── .env.example        ← Template (commit this)
│   ├── main.py             ← FastAPI app entry point
│   ├── config.py           ← Pydantic settings
│   ├── celery_worker.py    ← Celery app (include= task discovery)
│   ├── celery_beat.py      ← Beat scheduler + periodic tasks
│   ├── api/                ← Route handlers
│   ├── auth/                ← JWT auth
│   ├── tasks/               ← Celery task modules (pipeline stages)
│   ├── ai_engine/            ← OCR, Vision, DOM extractor
│   ├── cyberintel/           ← Threat intel runners
│   ├── consistency_engine/  ← Browser vs Sandbox diff engine
│   ├── database/             ← SQLAlchemy models + session
│   ├── schemas/               ← Pydantic request/response schemas
│   ├── services/               ← Business logic services
│   ├── websocket/               ← WebSocket manager
│   └── models/                   ← ML model files (.pkl)
│
├── nginx/                  ← Nginx Receptionist
│   ├── Dockerfile
│   └── nginx.conf
│
├── postgres/               ← PostgreSQL datastore
│   └── init.sql            ← Creates aegis_user, aegis_db, extensions
│
├── redis/                  ← Redis broker + cache
│   └── README.md
│
└── sandbox/                ← Playwright sandbox (Stage 5 detonation)
    └── README.md           ← Build instructions
```

## Resource Usage (Docker Desktop Resource-Saver Mode)

| Container | RAM Limit | CPU Limit |
|-----------|-----------|-----------|
| nginx | 128 MB | 0.5 |
| backend | 512 MB | 1.0 |
| redis | 300 MB | 0.5 |
| postgres | 512 MB | 1.0 |
| celery_worker | 768 MB | 1.5 |
| celery_beat | 256 MB | 0.5 |
| sandbox | 2 GB | 1.5 |
| **Total** | **~4.4 GB** | **6.5 cores** |

---

## Security

- Backend and Celery run as non-root `aegis` user (uid 1001)
- Sandbox: `cap_drop: ALL`, `no-new-privileges`, `pids_limit: 512`
- Celery worker mounts Docker socket **read-only** (spawns sandbox per job)
- API keys stored in `backend/.env` only — never committed

> **Before going live:** Change `SECRET_KEY` in `.env` to a 32+ char random string  
> and add your threat intel API keys (VirusTotal, Google Safe Browsing, etc.)
