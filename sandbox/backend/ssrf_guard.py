"""
Shared SSRF primitives: DNS resolution + private/reserved-IP blocking.

Used by:
  - phishing_sandbox_scan.py — the upfront check before navigating, and
    the per-request `context.route()` recheck (catches redirects/
    subresources the upfront check alone wouldn't see).
  - egress_proxy.py — the IP-pinning local proxy. A route-level recheck
    closes most of the gap but Python's check and Chromium's own later
    DNS resolution are still two separate lookups with a real (if tiny)
    time gap between them — that's the textbook DNS-rebinding TOCTOU.
    egress_proxy.py closes that gap completely by making the SAME
    resolution that gets validated the SAME one that gets connected to;
    see its module docstring.

"""

import asyncio
import ipaddress
import logging
import socket
import time
from urllib.parse import urlparse

logger = logging.getLogger("phishing_sandbox.ssrf_guard")

_DNS_CACHE_MAX_ENTRIES = 2000
_DNS_CACHE_TTL_SECONDS = 300  # 5 minutes — successful resolutions
_DNS_FAILURE_TTL_SECONDS = 10  # failed resolutions — short, so a transient
                                # DNS blip doesn't block a legit target for
                                # anywhere close to the full 5 minutes
_dns_cache = {}  # hostname -> (ips: list[str], expiry: float monotonic time)
_dns_cache_lock = asyncio.Lock()


async def _resolve_all_ips(hostname):
    now = time.monotonic()
    async with _dns_cache_lock:
        cached = _dns_cache.get(hostname)
        if cached and cached[1] > now:
            return cached[0]

    loop = asyncio.get_running_loop()
    try:
        infos = await loop.run_in_executor(None, socket.getaddrinfo, hostname, None)
        ips = list({info[4][0] for info in infos})
    except Exception as e:
        logger.warning("DNS resolution failed for %s: %s", hostname, e, exc_info=True)
        ips = []

    async with _dns_cache_lock:
        ttl = _DNS_CACHE_TTL_SECONDS if ips else _DNS_FAILURE_TTL_SECONDS
        if len(_dns_cache) >= _DNS_CACHE_MAX_ENTRIES and hostname not in _dns_cache:
            _dns_cache.pop(next(iter(_dns_cache)))
        _dns_cache[hostname] = (ips, time.monotonic() + ttl)
    return ips


def _is_blocked_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable -> fail closed


    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped

    return (
        ip.is_private or ip.is_loopback or ip.is_link_local or
        ip.is_multicast or ip.is_reserved or ip.is_unspecified
    )


def _is_fast_path_blocked_hostname(host):
    host = host.lower()
    return host == "localhost" or host == "::1" or host == "[::1]"


async def is_target_allowed(url, allow_private_targets=False):
    if allow_private_targets:
        return True
    host = urlparse(url).hostname
    if not host:
        return False
    if _is_fast_path_blocked_hostname(host):
        return False
    ips = await _resolve_all_ips(host)
    if not ips:
        return False
    return not any(_is_blocked_ip(ip) for ip in ips)


def _sort_ips_ipv4_first(ips):
    def sort_key(ip_str):
        try:
            return 0 if ipaddress.ip_address(ip_str).version == 4 else 1
        except ValueError:
            return 2
    return sorted(ips, key=sort_key)


async def resolve_validated_ip(hostname, allow_private_targets=False):
    if _is_fast_path_blocked_hostname(hostname) and not allow_private_targets:
        return None
    ips = await _resolve_all_ips(hostname)
    if allow_private_targets:
        return ips[0] if ips else None
    for ip in _sort_ips_ipv4_first(ips):
        if not _is_blocked_ip(ip):
            return ip
    return None