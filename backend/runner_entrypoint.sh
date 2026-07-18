#!/bin/bash
set -e

# The docker_socket_proxy service (Tecnativa) ignores Basic Auth.
# Security is provided by network isolation (docker_proxy_net).
# Point DOCKER_HOST directly to the proxy instead of using an HAProxy sidecar.
export DOCKER_HOST="tcp://docker_socket_proxy:2375"

# Start the actual sandbox runner service
exec python /app/sandbox_runner_svc.py
