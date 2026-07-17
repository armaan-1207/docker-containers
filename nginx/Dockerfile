# ===================================================
# AEGIS Nginx Container — Security Hardened
# Receptionist: routes REST API + WebSocket traffic
# to the Backend (Uvicorn) container.
#
# TLS: generates a self-signed cert at build time for
# development. In production, mount real certs from
# Let's Encrypt (or your CA) over /etc/nginx/certs/.
# ===================================================

FROM nginx:1.27-alpine@sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10

# curl: needed for HEALTHCHECK
# openssl: needed to generate self-signed TLS cert
RUN apk add --no-cache curl openssl

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Create directory for TLS certificates
RUN mkdir -p /etc/nginx/certs

# Install dynamic cert generation script into docker-entrypoint.d so nginx
# generates a unique self-signed cert on container start (if none mounted)
# instead of baking a private key into the built image layers.
COPY generate-ssl.sh /docker-entrypoint.d/99-generate-ssl.sh
RUN chmod +x /docker-entrypoint.d/99-generate-ssl.sh

# Copy our hardened config
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80 443

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsk https://localhost/nginx-health || exit 1
