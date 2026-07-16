# AEGIS Celery Worker Container

## Role
Async pipeline task runner. Pulls jobs from Redis and executes them in order.

## Pipeline (5 stages — executed sequentially per scan)

```
API queues browser_features
        │
        ▼ Stage 1
tasks/browser_features.py
  - Reads browser.png + browser.html from shared_scans
  - OCR (Tesseract) → extracts text
  - Vision (OpenCV) → analyzes screenshot layout
  - DOM extractor → pulls form fields, links, scripts
  - Writes browser_features.json
  - Queues → sandbox_analysis
        │
        ▼ Stage 2
tasks/sandbox_analysis.py
  - Calls sandbox container via HTTP POST /detonate
  - Receives screenshot_base64 + html + metadata
  - Writes sandbox.png, sandbox.html, sandbox_metadata.json
  - Queues → consistency
        │
        ▼ Stage 3
tasks/consistency.py
  - Compares browser artifacts vs sandbox artifacts
  - ConsistencyEngine → diff analysis (URL, forms, scripts)
  - Writes consistency_report.json
  - Queues → risk_fusion
        │
        ▼ Stage 4
tasks/risk_fusion.py
  - Loads all 3 prior JSONs + runs cyberintel (VT, SafeBrowsing, WHOIS)
  - RiskFusionEngine → LightGBM model → risk_score (0-100)
  - Writes risk_report.json, caches in Redis
  - Pushes live update via WebSocket
  - If HIGH/CRITICAL → queues alert_pipeline
        │
        ▼ Stage 5
tasks/alert_pipeline.py
  - Creates Incident record in Postgres
  - Stores IOCs in Postgres
  - Updates Statistics (upsert)
  - Sends Slack notification (if configured)
```

## Celery config (celery_worker.py)
```python
celery = Celery(
    "aegis_worker",
    broker="redis://redis:6379/0",
    backend="redis://redis:6379/0",
    include=[
        "tasks.browser_features",
        "tasks.sandbox_analysis",
        "tasks.consistency",
        "tasks.risk_fusion",
        "tasks.alert_pipeline",
    ]
)
```

Key settings:
- `task_acks_late=True` — acks only after successful completion
- `task_reject_on_worker_lost=True` — requeues on crash
- `worker_prefetch_multiplier=1` — one task at a time per process
- `concurrency=2` — 2 worker processes

## Docker socket
The worker mounts `/var/run/docker.sock:ro` to spawn the sandbox container per job.
In production, replace with a scoped Docker API proxy (e.g., Tecnativa Docker Socket Proxy).

## Queues
| Queue | Purpose |
|-------|---------|
| `default` | Main pipeline tasks |
| `sandbox` | Sandbox analysis tasks (can be isolated) |
| `alerts` | Alert pipeline tasks |
