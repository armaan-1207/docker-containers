#!/bin/bash
set -e

# Base64 encode the basic auth string
export PROXY_BASIC_AUTH_B64=$(echo -n "$PROXY_BASIC_AUTH" | base64)

# Run the tiny HAProxy sidecar in the background to inject Basic Auth headers
haproxy -f /etc/haproxy/haproxy.cfg &

# Reroute docker client to the local sidecar
export DOCKER_HOST="tcp://127.0.0.1:2375"

# Give HAProxy a moment to bind
sleep 1

# Start the actual sandbox runner service
exec python /app/sandbox_runner_svc.py
