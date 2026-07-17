"""
services/sandbox_runner_svc.py
=================================
Purpose-built admission-control microservice (`aegis_sandbox_runner`) that sits
in front of `docker_socket_proxy`.

Security Hardening (DevSecOps Critical Finding #1):
  - `celery_worker` processes untrusted image data (via OpenCV / pytesseract / Vision).
    Previously, `celery_worker` had direct access to `docker_socket_proxy` with
    `CONTAINERS=1, POST=1`, allowing any parser RCE inside the worker to call
    `POST /containers/create` with `Binds: ["/:/host"]` or `Privileged: true`.
  - By replacing direct worker proxy access with this tiny single-purpose RPC service,
    `celery_worker` is completely severed from `docker_socket_proxy` (`docker_proxy_net`).
  - This service accepts ONLY `POST /detonate` with `{scan_id, target_url, timeout_sec}`.
  - It strictly enforces canonical UUID format (`_UUID_RE`), validates target URL format,
    and constructs one exact, immutable, hardcoded `docker run` command (`--cap-drop ALL`,
    `--security-opt no-new-privileges:true`, `--read-only`, `--network aegis_sandbox_net`).
"""

import asyncio
import logging
import os
import re
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, HttpUrl

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sandbox_runner_svc")

app = FastAPI(title="AEGIS Sandbox Runner Service", version="1.0.0")

_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

SANDBOX_IMAGE = os.environ.get(
    "SANDBOX_IMAGE",
    "aegis-sandbox:v1.0.0@sha256:45b23deeeec969acba3ef1ba0f7ee7cd8312e75e921ebad966d58dc787943cc9",
)
SANDBOX_NETWORK = os.environ.get("SANDBOX_NETWORK", "aegis_sandbox_net")
SHARED_VOLUME_NAME = os.environ.get("SHARED_SCANS_VOLUME", "aegis_shared_scans")
SANDBOX_RUNNER_SECRET = os.environ.get("SANDBOX_RUNNER_SECRET", "aegis-runner-internal-secret-token")
_MAX_CONCURRENT_DETONATIONS = int(os.environ.get("MAX_CONCURRENT_DETONATIONS", "10"))
_detonate_sem = None


def _get_semaphore() -> asyncio.Semaphore:
    global _detonate_sem
    if _detonate_sem is None:
        _detonate_sem = asyncio.Semaphore(_MAX_CONCURRENT_DETONATIONS)
    return _detonate_sem


class DetonateRequest(BaseModel):
    scan_id: str
    target_url: str
    timeout_sec: int = 120


class DetonateResponse(BaseModel):
    status: str
    scan_id: str
    returncode: int
    output_snippet: str


@app.post("/detonate", response_model=DetonateResponse)
async def detonate(request: DetonateRequest, x_runner_auth: str = Header(None)):
    if not x_runner_auth or x_runner_auth != SANDBOX_RUNNER_SECRET:
        logger.warning("[admission-control] Unauthorized detonation attempt rejected")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-Runner-Auth token",
        )

    sem = _get_semaphore()
    if sem.locked():
        logger.warning("[admission-control] Concurrency limit (%d) reached — rejecting request", _MAX_CONCURRENT_DETONATIONS)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Sandbox runner at maximum concurrency limit",
        )

    async with sem:
        scan_id = request.scan_id.strip()
        if not _UUID_RE.match(scan_id):
            logger.warning("[admission-control] Rejected invalid scan_id: %r", scan_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="scan_id must be a canonical UUIDv4",
            )

        target_url = request.target_url.strip()
        if not target_url.startswith(("http://", "https://")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="target_url must start with http:// or https://",
            )

        timeout_sec = min(max(request.timeout_sec, 10), 300)

        # Hardcoded immutable container shape (Critical Finding #1)
        cmd = [
            "docker", "run", "--rm",
            "--network", SANDBOX_NETWORK,
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true",
            "--read-only",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "--tmpfs", "/home/sandbox/.config:rw,noexec,nosuid,size=32m",
            "--tmpfs", "/home/sandbox/.pki:rw,noexec,nosuid,size=16m",
            "--tmpfs", "/home/sandbox/.local:rw,noexec,nosuid,size=32m",
            "--pids-limit", "512",
            "--memory", "2g",
            "--cpus", "1.5",
            "--shm-size", "1gb",
            "-v", f"{SHARED_VOLUME_NAME}:/app/output",
            SANDBOX_IMAGE,
            target_url,
            "--output-dir", "/app/output",
            "--request-id", scan_id,
        ]

        logger.info("[%s] Admission control executing exact sandbox shape: %s", scan_id, " ".join(cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except OSError:
                pass
            await proc.wait()
            logger.error("[%s] Sandbox detonation timed out after %ds", scan_id, timeout_sec)
            raise HTTPException(
                status_code=status.HTTP_504_GATEWAY_TIMEOUT,
                detail=f"Sandbox detonation timed out after {timeout_sec}s",
            )

        if proc.returncode != 0:
            err_msg = stderr.decode(errors="ignore")[:2000]
            logger.error("[%s] Sandbox container exited %d: %s", scan_id, proc.returncode, err_msg)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Sandbox exited with returncode {proc.returncode}: {err_msg}",
            )

        out_msg = stdout.decode(errors="ignore")[:500]
        return DetonateResponse(
            status="success",
            scan_id=scan_id,
            returncode=proc.returncode,
            output_snippet=out_msg,
        )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)
