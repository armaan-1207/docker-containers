#!/bin/bash
set -e

# Base64 encode the basic auth string
export PROXY_BASIC_AUTH_B64=$(echo -n "$PROXY_BASIC_AUTH" | base64)

# Run the tiny HAProxy sidecar in the background to inject Basic Auth headers
haproxy -f /etc/haproxy/haproxy.cfg &
HAPROXY_PID=$!

# Supervise HAProxy: if it dies, exit immediately to trigger container restart
(
  while true; do
    sleep 5
    if ! kill -0 "$HAPROXY_PID" 2>/dev/null; then
      echo "[runner_entrypoint] CRITICAL: HAProxy sidecar ($HAPROXY_PID) exited unexpectedly! Terminating runner to trigger container restart." >&2
      kill -TERM $$ 2>/dev/null || exit 1
    fi
  done
) &

# Reroute docker client to the local sidecar
export DOCKER_HOST="tcp://127.0.0.1:2375"

# Give HAProxy a moment to bind
sleep 1

# Start the actual sandbox runner service
exec python /app/sandbox_runner_svc.py
