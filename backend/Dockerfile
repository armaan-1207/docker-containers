# ===================================================
# AEGIS Backend Container
# Stage 1: Build deps (cached layer)
# Stage 2: Runtime image — non-root, hardened
# ===================================================

# --- Build stage: install Python deps ---
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93 AS builder

WORKDIR /app

# System build deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# --- Runtime stage: minimal, non-root ---
FROM python:3.11-slim@sha256:db3ff2e1800a8581e2c48a27c3995339d47bdf046da21c7627accd3d51053a93 AS runtime

# Security: non-root user
RUN groupadd --gid 1001 aegis \
    && useradd --uid 1001 --gid aegis --shell /bin/bash --create-home aegis

WORKDIR /app

# Runtime system deps only — docker-cli removed, this image never
# talks to docker_socket_proxy (only celery_worker does — see
# backend/Dockerfile.worker)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    tesseract-ocr \
    libzbar0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY --chown=aegis:aegis . .

# Shared volume mount point — Backend writes screenshots here,
# Celery worker and Sandbox container read from this same volume.
RUN mkdir -p /shared/scans && chown -R aegis:aegis /shared/scans && chmod 1777 /shared/scans
VOLUME ["/shared/scans"]

# Models directory (LightGBM .pkl lives here)
RUN mkdir -p /app/models && chown -R aegis:aegis /app/models

COPY --chown=aegis:aegis entrypoint.sh /app/entrypoint.sh
COPY --chown=aegis:aegis celery_entrypoint.sh /app/celery_entrypoint.sh
RUN chmod +x /app/entrypoint.sh /app/celery_entrypoint.sh

# Pre-create the beat schedule directory so the volume mount
# inherits the aegis ownership rather than defaulting to root.
RUN mkdir -p /app/celerybeat-schedule && \
    chown -R aegis:aegis /app/celerybeat-schedule

USER aegis

EXPOSE 8000

# Health check — hits the root endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=5 \
    CMD curl -f http://localhost:8000/ || exit 1

# entrypoint: waits for Postgres, runs db init, then execs CMD
ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--log-level", "info"]
