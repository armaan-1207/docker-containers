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

if [[ $# -eq 0 ]]; then
    echo "[-] Error: No subnet CIDRs specified."
    echo "Usage: sudo $0 <sandbox-subnet-cidr> [aegis-net-subnet-cidr ...]"
    echo "Example: sudo $0 172.28.0.0/16 172.29.0.0/16"
    echo ""
    echo "To inspect the current subnets for both aegis_sandbox_net and aegis_net:"
    echo "  docker network inspect aegis_sandbox_net aegis_net -f '{{.Name}}: {{range .IPAM.Config}}{{.Subnet}}{{end}}'"
    exit 1
fi

iptables -N DOCKER-USER 2>/dev/null || true
# Note: Custom bridge subnets (e.g., aegis_sandbox_net, aegis_net) are filtered by CIDR argument below.

for SUBNET in "$@"; do
    echo "[+] Configuring DOCKER-USER iptables chain for subnet: ${SUBNET}"

    # 1. Allow established and related connections back to the subnet
    iptables -I DOCKER-USER -s "${SUBNET}" -m state --state ESTABLISHED,RELATED -j RETURN

    # 2. Allow intra-subnet traffic between containers on the same network bridge
    #    (Required for aegis_net so backend/celery_worker can communicate with postgres/redis/clamav)
    iptables -A DOCKER-USER -s "${SUBNET}" -d "${SUBNET}" -j RETURN

    # 3. Block Cloud Metadata endpoints (169.254.169.254 / fe80::/10)
    echo "[+] Adding rules to block cloud metadata service (AWS/GCP/Azure) for ${SUBNET}..."
    iptables -A DOCKER-USER -s "${SUBNET}" -d 169.254.169.254/32 -j DROP
    iptables -A DOCKER-USER -s "${SUBNET}" -d 169.254.0.0/16 -j DROP

    # 4. Block loopback and host gateway interfaces
    echo "[+] Adding rules to block host loopback and internal gateways for ${SUBNET}..."
    iptables -A DOCKER-USER -s "${SUBNET}" -d 127.0.0.0/8 -j DROP
    iptables -A DOCKER-USER -s "${SUBNET}" -d 0.0.0.0/8 -j DROP

    # 5. Block RFC 1918 Private Address Spaces (Internal networks / databases / redis / worker / CGNAT)
    echo "[+] Adding rules to block RFC 1918 & RFC 6598 (CGNAT) internal IP ranges for ${SUBNET}..."
    iptables -A DOCKER-USER -s "${SUBNET}" -d 10.0.0.0/8 -j DROP
    iptables -A DOCKER-USER -s "${SUBNET}" -d 172.16.0.0/12 -j DROP
    iptables -A DOCKER-USER -s "${SUBNET}" -d 192.168.0.0/16 -j DROP
    iptables -A DOCKER-USER -s "${SUBNET}" -d 100.64.0.0/10 -j DROP  # RFC 6598 Carrier-Grade NAT

    echo "[+] Active rules for ${SUBNET}:"
    iptables -L DOCKER-USER -n -v | grep "${SUBNET}" || true
done

echo "[+] Host-layer firewall configuration applied successfully to DOCKER-USER across all specified subnets."
