# ===================================================
# AEGIS Nginx Container
# Receptionist — routes REST API + WebSocket traffic
# to the Backend (Uvicorn) container
# ===================================================

FROM nginx:1.27-alpine

# curl is available on nginx:alpine — needed for HEALTHCHECK
RUN apk add --no-cache curl

# Remove default config
RUN rm /etc/nginx/conf.d/default.conf

# Copy our custom config
COPY nginx.conf /etc/nginx/nginx.conf

EXPOSE 80

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fs http://localhost/nginx-health || exit 1

