#!/usr/bin/env bash
# scripts/setup_host_firewall.sh
# ==============================================================================
# Host-Layer Defense-in-Depth for AEGIS Sandbox Network (Critical Finding #4)
# ==============================================================================
# Purpose:
#   Application-layer guards (`ssrf_guard.py` and `egress_proxy.py`) block SSRF
#   in well-behaved requests or proxied browsers. However, defense-in-depth
#   mandates kernel-level filtering in the `DOCKER-USER` iptables chain so that
#   if an attacker achieves RCE inside the sandbox container and attempts raw
#   socket connections bypassing the HTTP proxy, the host kernel drops the packets.
#
# Usage:
#   sudo bash scripts/setup_host_firewall.sh [SANDBOX_SUBNET]
#   Example: sudo bash scripts/setup_host_firewall.sh 172.28.0.0/16
#
# Note on Docker networking:
#   Docker inserts rules into the `DOCKER-USER` chain before any standard `FORWARD`
#   or `INPUT` rules. Rules added here take precedence over Docker's auto-routing.
# ==============================================================================

set -euo pipefail

SANDBOX_SUBNET="${1:-}"

if [[ -z "${SANDBOX_SUBNET}" ]]; then
    echo "[-] Error: SANDBOX_SUBNET not specified."
    echo "Usage: sudo $0 <sandbox-subnet-cidr>"
    echo "Example: sudo $0 172.28.0.0/16"
    echo ""
    echo "To inspect the current subnet for aegis_sandbox_net:"
    echo "  docker network inspect aegis_sandbox_net -f '{{range .IPAM.Config}}{{.Subnet}}{{end}}'"
    exit 1
fi

echo "[+] Configuring DOCKER-USER iptables chain for sandbox subnet: ${SANDBOX_SUBNET}"

# Ensure DOCKER-USER chain exists (created by Docker Daemon)
iptables -N DOCKER-USER 2>/dev/null || true

# 1. Allow established and related connections back to the sandbox
iptables -I DOCKER-USER -i docker0 -o docker0 -j RETURN 2>/dev/null || true
iptables -I DOCKER-USER -s "${SANDBOX_SUBNET}" -m state --state ESTABLISHED,RELATED -j RETURN

# 2. Block Cloud Metadata endpoints (169.254.169.254 / fe80::/10)
echo "[+] Adding rules to block cloud metadata service (AWS/GCP/Azure)..."
iptables -A DOCKER-USER -s "${SANDBOX_SUBNET}" -d 169.254.169.254/32 -j DROP
iptables -A DOCKER-USER -s "${SANDBOX_SUBNET}" -d 169.254.0.0/16 -j DROP

# 3. Block loopback and host gateway interfaces
echo "[+] Adding rules to block host loopback and internal gateways..."
iptables -A DOCKER-USER -s "${SANDBOX_SUBNET}" -d 127.0.0.0/8 -j DROP
iptables -A DOCKER-USER -s "${SANDBOX_SUBNET}" -d 0.0.0.0/8 -j DROP

# 4. Block RFC 1918 Private Address Spaces (Internal networks / databases / redis / worker / CGNAT)
echo "[+] Adding rules to block RFC 1918 & RFC 6598 (CGNAT) internal IP ranges..."
iptables -A DOCKER-USER -s "${SANDBOX_SUBNET}" -d 10.0.0.0/8 -j DROP
iptables -A DOCKER-USER -s "${SANDBOX_SUBNET}" -d 172.16.0.0/12 -j DROP
iptables -A DOCKER-USER -s "${SANDBOX_SUBNET}" -d 192.168.0.0/16 -j DROP
iptables -A DOCKER-USER -s "${SANDBOX_SUBNET}" -d 100.64.0.0/10 -j DROP  # RFC 6598 Carrier-Grade NAT

# 5. Allow all other outbound traffic to public Internet (for live phishing detonation)
# (Any packets not dropped by the above rules fall through to Docker's standard NAT rules)
echo "[+] Host-layer firewall configuration applied successfully to DOCKER-USER."
echo "[+] Active rules for ${SANDBOX_SUBNET}:"
iptables -L DOCKER-USER -n -v | grep "${SANDBOX_SUBNET}" || true
