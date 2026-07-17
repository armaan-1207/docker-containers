import asyncio
import pytest
import sys
import os

# Add sandbox/backend to sys.path so tests can import ssrf_guard and egress_proxy
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))

from ssrf_guard import _is_blocked_ip, _is_fast_path_blocked_hostname, is_target_allowed, resolve_validated_ip
from egress_proxy import start_egress_proxy


@pytest.mark.asyncio
async def test_ssrf_guard_blocked_ips():
    """Verify that private, loopback, reserved, and cloud metadata IPs are correctly blocked."""
    # Loopback
    assert _is_blocked_ip("127.0.0.1") is True
    assert _is_blocked_ip("::1") is True
    
    # RFC 1918 Private
    assert _is_blocked_ip("10.0.0.1") is True
    assert _is_blocked_ip("172.16.0.1") is True
    assert _is_blocked_ip("192.168.1.100") is True
    
    # Link-local / Cloud Metadata (169.254.169.254)
    assert _is_blocked_ip("169.254.169.254") is True
    assert _is_blocked_ip("fe80::1") is True
    
    # IPv4-mapped IPv6 private
    assert _is_blocked_ip("::ffff:127.0.0.1") is True
    assert _is_blocked_ip("::ffff:10.0.0.1") is True
    assert _is_blocked_ip("::ffff:169.254.169.254") is True

    # Public safe IPs
    assert _is_blocked_ip("8.8.8.8") is False
    assert _is_blocked_ip("1.1.1.1") is False


@pytest.mark.asyncio
async def test_ssrf_guard_fast_path_hostnames():
    """Verify fast path blocked hostnames."""
    assert _is_fast_path_blocked_hostname("localhost") is True
    assert _is_fast_path_blocked_hostname("::1") is True
    assert _is_fast_path_blocked_hostname("example.com") is False


@pytest.mark.asyncio
async def test_is_target_allowed():
    """Verify is_target_allowed blocks private targets and fast path hostnames."""
    assert await is_target_allowed("http://localhost:8000/foo") is False
    assert await is_target_allowed("http://127.0.0.1:8000/foo") is False
    assert await is_target_allowed("http://169.254.169.254/latest/meta-data/") is False
    assert await is_target_allowed("http://10.0.0.1/admin") is False
    assert await is_target_allowed("http://127.0.0.1/admin", allow_private_targets=True) is True


@pytest.mark.asyncio
async def test_resolve_validated_ip():
    """Verify resolve_validated_ip returns valid IP or None when blocked."""
    assert await resolve_validated_ip("localhost") is None
    assert await resolve_validated_ip("127.0.0.1") is None
    assert await resolve_validated_ip("169.254.169.254") is None


@pytest.mark.asyncio
async def test_egress_proxy_blocks_connect_to_private():
    """Verify egress proxy blocks CONNECT attempts to private or reserved IPs."""
    server = await start_egress_proxy(port=0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        # Attempt CONNECT to cloud metadata or private address
        writer.write(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: 169.254.169.254:80\r\n\r\n")
        await writer.drain()
        response = await reader.read(1024)
        assert b"403 Forbidden" in response or b"Bad Gateway" in response or b"400 Bad Request" in response
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_egress_proxy_blocks_plain_http_to_private():
    """Verify egress proxy blocks plain HTTP requests targeting private/internal endpoints."""
    server = await start_egress_proxy(port=0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET http://10.0.0.1/admin HTTP/1.1\r\nHost: 10.0.0.1\r\n\r\n")
        await writer.drain()
        response = await reader.read(1024)
        assert b"403 Forbidden" in response or b"Bad Gateway" in response or b"400 Bad Request" in response
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_quic_and_websocket_ssrf_blocked():
    """Regression test ensuring synthetic HTTP/3 QUIC / WebSocket origins pointing to private IPs are blocked."""
    assert await is_target_allowed("https://10.0.0.1:443/quic-endpoint") is False
    assert await is_target_allowed("wss://127.0.0.1:8080/ws") is False
    assert await resolve_validated_ip("169.254.169.254") is None


@pytest.mark.asyncio
async def test_egress_proxy_handle_client_end_to_end():
    """Regression test specifically verifying egress_proxy imports cleanly and _handle_client executes properly."""
    import egress_proxy
    server = await egress_proxy.start_egress_proxy(port=0)
    port = server.sockets[0].getsockname()[1]
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(b"GET http://127.0.0.1:8000/test HTTP/1.1\r\nHost: 127.0.0.1:8000\r\n\r\n")
        await writer.drain()
        response = await reader.read(1024)
        assert b"403 Forbidden" in response or b"Bad Gateway" in response or b"400 Bad Request" in response
        writer.close()
        await writer.wait_closed()
    finally:
        server.close()
        await server.wait_closed()

