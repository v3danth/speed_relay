"""Minimal SOCKS5 client (RFC 1928) with Tor's extended error codes."""

from __future__ import annotations

import socket

from torrelay.util import recv_exact

SOCKS_ERRORS = {
    0x01: "general SOCKS server failure",
    0x02: "connection not allowed by ruleset",
    0x03: "network unreachable",
    0x04: "host unreachable",
    0x05: "connection refused",
    0x06: "TTL expired",
    0x07: "command not supported",
    0x08: "address type not supported",
    # Tor ExtendedErrors (SocksPort flag), see tor's socks-extensions.txt.
    0xF0: "onion service descriptor not found",
    0xF1: "onion service descriptor invalid",
    0xF2: "onion service introduction failed",
    0xF3: "onion service rendezvous failed",
    0xF4: "onion service client authorization missing",
    0xF5: "onion service client authorization wrong",
    0xF6: "invalid onion address",
    0xF7: "onion service introduction timed out",
}

_ADDR_LEN = {0x01: 4, 0x04: 16}


def connect_request(host: str, port: int) -> bytes:
    """Build a CONNECT request using a domain-name address (ATYP 3)."""
    name = host.encode("idna")
    if len(name) > 255:
        raise ValueError("hostname too long for SOCKS5")
    return (b"\x05\x01\x00\x03" + bytes([len(name)]) + name
            + port.to_bytes(2, "big"))


def _skip_bound_address(sock: socket.socket, atyp: int) -> None:
    length = _ADDR_LEN.get(atyp)
    if length is None:
        length = recv_exact(sock, 1)[0]
    recv_exact(sock, length + 2)


def socks5_connect(proxy_port: int, host: str, port: int,
                   timeout: float = 120.0,
                   proxy_host: str = "127.0.0.1") -> socket.socket:
    """Return a connected socket tunnelled through the SOCKS5 proxy."""
    sock = socket.create_connection((proxy_host, proxy_port), timeout=5)
    try:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise ConnectionError("SOCKS5 no-auth negotiation rejected")
        sock.sendall(connect_request(host, port))
        _, status, _, atyp = recv_exact(sock, 4)
        if status != 0:
            reason = SOCKS_ERRORS.get(status, f"code {status:#x}")
            raise ConnectionError(f"SOCKS5: {reason}")
        _skip_bound_address(sock, atyp)
        sock.settimeout(None)
        return sock
    except BaseException:
        sock.close()
        raise
