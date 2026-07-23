#!/bin/sh
# ==============================================================================
# AEGIS Nginx Startup Script — Dynamic TLS Certificate Generation
# ==============================================================================
# If /etc/nginx/certs/server.key does not exist (i.e. not mounted from a real CA
# or Let's Encrypt volume in production), generate a fresh self-signed cert
# dynamically at container startup. This ensures private keys are NEVER baked
# into deterministic build layers or shared across container deployments.
# ==============================================================================

set -e

mkdir -p /etc/nginx/certs

if [ ! -f /etc/nginx/certs/server.key ] || [ ! -f /etc/nginx/certs/server.crt ]; then
    if [ "$REQUIRE_REAL_CERT" = "true" ] || [ "$REQUIRE_REAL_CERT" = "1" ]; then
        echo "[nginx-ssl-gen] CRITICAL: REQUIRE_REAL_CERT is set ($REQUIRE_REAL_CERT), but TLS certificates are missing from /etc/nginx/certs/." >&2
        echo "[nginx-ssl-gen] CRITICAL: Refusing to start with self-signed fallback in secure/production environment. Mount valid certificates and try again." >&2
        exit 1
    fi
    echo "[nginx-ssl-gen] No TLS cert/key found at /etc/nginx/certs/. Generating fresh self-signed RSA-4096 cert..."
    openssl req -x509 -nodes -days 365 \
        -subj "/C=US/ST=Dev/L=Dev/O=AEGIS/CN=localhost" \
        -newkey rsa:4096 \
        -keyout /etc/nginx/certs/server.key \
        -out    /etc/nginx/certs/server.crt \
        2>/dev/null
    chmod 600 /etc/nginx/certs/server.key
    chmod 644 /etc/nginx/certs/server.crt
    echo "[nginx-ssl-gen] Self-signed certificate generated successfully."
else
    echo "[nginx-ssl-gen] Using existing/mounted TLS certificates in /etc/nginx/certs/."
fi
