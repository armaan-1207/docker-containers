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
import hmac
import logging
import os
import re
from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel, HttpUrl

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sandbox_runner_svc")

app = FastAPI(title="AEGIS Sandbox Runner Service", version="1.0.0")




_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

SANDBOX_IMAGE = os.environ.get(
    "SANDBOX_IMAGE",
    "aegis-sandbox@sha256:74aaa52be1a8f5a00e462a0b3ec7b2c2dbc108ff46fd02d6fde36de69d12acf5",
)
SANDBOX_NETWORK = os.environ.get("SANDBOX_NETWORK", "aegis_sandbox_net")
SHARED_VOLUME_NAME = os.environ.get("SHARED_SCANS_VOLUME", "aegis_shared_scans")
SANDBOX_RUNNER_SECRET = os.environ.get("SANDBOX_RUNNER_SECRET", "")
_MAX_CONCURRENT_DETONATIONS = int(os.environ.get("MAX_CONCURRENT_DETONATIONS", "10"))
_detonate_sem = None


def _get_semaphore() -> asyncio.Semaphore:
    global _detonate_sem
    if _detonate_sem is None:
        _detonate_sem = asyncio.Semaphore(_MAX_CONCURRENT_DETONATIONS)
    return _detonate_sem


class DetonateRequest(BaseModel):
    scan_id: str
    target_url: HttpUrl
    timeout_sec: int = 120


class DetonateResponse(BaseModel):
    status: str
    scan_id: str
    returncode: int
    output_snippet: str


@app.on_event("startup")
async def verify_host_firewall_and_image():
    """
    Check on startup if SANDBOX_IMAGE is pinned, Docker Engine supports volume-subpath,
    and test active network isolation.
    """
    is_prod = os.environ.get("ENVIRONMENT", "").lower() == "production"
    if is_prod and "454a806c1149eb37e1c09003c2aa2a86ec5d9c5d5c9650a23308117eb2d00f9c" in SANDBOX_IMAGE:
        raise RuntimeError(
            "CRITICAL: SANDBOX_IMAGE is set to the default placeholder digest in production! "
            "Run 'make pin-sandbox' or 'python scripts/pin_sandbox.py' before starting."
        )

    # Verify Docker Engine version supports volume-subpath (Docker Engine 24.0.0+)
    try:
        ver_proc = await asyncio.create_subprocess_exec(
            "docker", "version", "--format", "{{.Server.Version}}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        ver_out, ver_err = await ver_proc.communicate()
        if ver_proc.returncode == 0:
            server_version = ver_out.decode().strip()
            # Parse major version (e.g. "24.0.5" -> 24)
            parts = re.split(r"[^0-9]", server_version)
            major = int(parts[0]) if parts and parts[0].isdigit() else 0
            if major > 0 and major < 24:
                msg = (
                    f"CRITICAL: Host Docker Engine version is {server_version} (< 24.0.0). "
                    "AEGIS Stage 2 sandbox detonation requires volume-subpath mounts supported in Docker Engine 24.0+. "
                    "Please upgrade the host Docker Engine."
                )
                logger.error(msg)
                if is_prod:
                    raise RuntimeError(msg)
            else:
                logger.info("[startup] Verified host Docker Engine version %s (supports volume-subpath).", server_version)
        else:
            logger.warning("[startup] Could not query Docker Server version: %s", ver_err.decode().strip())
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise
        logger.debug("[startup] Could not check Docker Server version: %s", e)

    # Verify SANDBOX_IMAGE exists locally (now possible with IMAGES: 1 on docker_socket_proxy)
    try:
        inspect_proc = await asyncio.create_subprocess_exec(
            "docker", "inspect", "--type=image", SANDBOX_IMAGE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, inspect_err = await inspect_proc.communicate()
        if inspect_proc.returncode != 0:
            err_msg = inspect_err.decode().strip() or "Image not found"
            logger.warning("[startup] SANDBOX_IMAGE '%s' not found locally via Docker API (%s). Ensure it is built ('make pin-sandbox') before running scans.", SANDBOX_IMAGE, err_msg)
            if is_prod:
                raise RuntimeError(
                    f"CRITICAL: SANDBOX_IMAGE '{SANDBOX_IMAGE}' not found locally via Docker API ({err_msg}). "
                    "You must run 'make pin-sandbox' (or 'python scripts/pin_sandbox.py') before starting in production."
                )
        else:
            logger.info("[startup] Verified SANDBOX_IMAGE '%s' exists locally.", SANDBOX_IMAGE)
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise
        logger.debug("[startup] Could not verify SANDBOX_IMAGE presence via docker inspect: %s", e)

    try:
        # Use SANDBOX_IMAGE with explicit --entrypoint=python3 override to bypass phishing_sandbox_scan.py entrypoint
        probe_script = (
            "import socket, sys\n"
            "try:\n"
            "    socket.create_connection(('169.254.169.254', 80), timeout=2)\n"
            "    sys.exit(0)\n"
            "except OSError:\n"
            "    sys.exit(1)\n"
        )
        cmd = [
            "docker", "run", "--rm",
            "--entrypoint=python3",
            "--network", SANDBOX_NETWORK,
            "--cap-drop=ALL",
            "--security-opt", "no-new-privileges:true",
            SANDBOX_IMAGE,
            "-c", probe_script
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        _, stderr_data = await proc.communicate()
        stderr_text = stderr_data.decode(errors="replace").strip()

        if proc.returncode == 0:
            msg = (
                f"[CRITICAL SECURITY WARNING] Host firewall rules (scripts/setup_host_firewall.sh) "
                f"appear to NOT be enforced on network '{SANDBOX_NETWORK}'! A test probe successfully connected "
                f"to AWS/GCP metadata service (169.254.169.254). Please run 'sudo bash scripts/setup_host_firewall.sh' immediately."
            )
            logger.error(msg)
            if is_prod:
                raise RuntimeError(msg)
        elif proc.returncode == 1:
            # Returncode 1 means python3 ran our probe script inside container and caught OSError (timeout/refused/no route)
            logger.info("[startup] Host firewall / network isolation verified for %s (probe rejected connection with code 1)", SANDBOX_NETWORK)
        elif proc.returncode >= 125 or proc.returncode > 1:
            # 125=docker run failed, 126=cannot invoke, 127=command not found, >1=python runtime/arg parse error
            logger.warning("[startup] Active firewall probe execution failed (return code %s): %s", proc.returncode, stderr_text)
            if is_prod:
                raise RuntimeError(
                    f"CRITICAL: Active firewall probe failed to execute correctly inside container (return code {proc.returncode}): {stderr_text}. "
                    "Ensure 'make pin-sandbox' and 'sudo bash scripts/setup_host_firewall.sh' have run."
                )
        else:
            logger.info("[startup] Host firewall / network isolation probe finished with code %s (%s)", proc.returncode, stderr_text)
    except Exception as e:
        if isinstance(e, RuntimeError):
            raise
        logger.debug("[startup] Could not run active firewall probe check (non-fatal): %s", e)


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.post("/detonate", response_model=DetonateResponse)
async def detonate(request: DetonateRequest, x_runner_auth: str = Header(None)):
    if not x_runner_auth or not hmac.compare_digest(x_runner_auth, SANDBOX_RUNNER_SECRET):
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

    try:
        await asyncio.wait_for(sem.acquire(), timeout=0.001)
    except asyncio.TimeoutError:
        logger.warning("[admission-control] Concurrency limit (%d) reached (race resolved) — rejecting request", _MAX_CONCURRENT_DETONATIONS)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Sandbox runner at maximum concurrency limit",
        )

    try:
        scan_id = request.scan_id.strip()
        if not _UUID_RE.match(scan_id):
            logger.warning("[admission-control] Rejected invalid scan_id: %r", scan_id)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="scan_id must be a canonical UUIDv4",
            )

        target_url = str(request.target_url).strip()
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
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",  # nosec B108
            "--tmpfs", "/home/sandbox/.config:rw,noexec,nosuid,size=32m",
            "--tmpfs", "/home/sandbox/.pki:rw,noexec,nosuid,size=16m",
            "--tmpfs", "/home/sandbox/.local:rw,noexec,nosuid,size=32m",
            "--pids-limit", "512",
            "--memory", "2g",
            "--cpus", "1.5",
            "--shm-size", "1gb",
            "--mount", f"type=volume,source={SHARED_VOLUME_NAME},target=/app/output,volume-subpath={scan_id}",
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
            if "volume-subpath" in err_msg or "invalid mount option" in err_msg.lower() or "unknown flag: --mount" in err_msg.lower():
                detail_msg = (
                    f"Host Docker Engine does not support 'volume-subpath' mount option (requires Docker Engine >= 24.0.0). "
                    f"Error: {err_msg}"
                )
            elif proc.returncode == 125 or "No such image" in err_msg or "not found" in err_msg.lower():
                detail_msg = (
                    f"Sandbox image '{SANDBOX_IMAGE}' not found locally or failed docker run check (exit code {proc.returncode}). "
                    "You must run 'make pin-sandbox' (or 'python scripts/pin_sandbox.py') to build and pin the sandbox image before running scans."
                )
            else:
                detail_msg = f"Sandbox exited with returncode {proc.returncode}: {err_msg}"
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=detail_msg,
            )

        out_msg = stdout.decode(errors="ignore")[:500]
        return DetonateResponse(
            status="success",
            scan_id=scan_id,
            returncode=proc.returncode,
            output_snippet=out_msg,
        )
    finally:
        sem.release()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)  # nosec B104
