"""Minimal SOCKS5 client (RFC 1928) that understands Tor's error codes."""

from __future__ import annotations

import socket

from torrelay import util

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

_GREETING_NO_AUTH = b"\x05\x01\x00"
_REPLY_NO_AUTH = b"\x05\x00"
_FIXED_ADDRESS_LENGTHS = {0x01: 4, 0x04: 16}  # IPv4, IPv6
_PROXY_CONNECT_TIMEOUT = 5.0


def connect_request(host: str, port: int) -> bytes:
    """Builds a SOCKS5 CONNECT request with a domain-name address.

    Sending the name (ATYP 3) instead of an IP lets Tor resolve it, which is
    required for .onion addresses and avoids DNS leaks for clearnet hosts.

    Args:
        host: Hostname to connect to.
        port: TCP port.

    Returns:
        The encoded request.

    Raises:
        ValueError: If the hostname is longer than SOCKS5 allows.
    """
    name = host.encode("idna")
    if len(name) > 255:
        raise ValueError("hostname too long for SOCKS5")
    return (b"\x05\x01\x00\x03" + bytes([len(name)]) + name
            + port.to_bytes(2, "big"))


def describe_status(status: int) -> str:
    """Turns a SOCKS5 reply code into a human-readable reason.

    Args:
        status: The REP byte of a SOCKS5 reply.

    Returns:
        A description, including Tor's onion-specific extended errors.
    """
    return SOCKS_ERRORS.get(status, f"code {status:#x}")


def _negotiate_no_auth(sock: socket.socket) -> None:
    """Performs the SOCKS5 greeting, offering only "no authentication".

    Args:
        sock: Socket connected to the proxy.

    Raises:
        ConnectionError: If the proxy refuses unauthenticated access.
    """
    sock.sendall(_GREETING_NO_AUTH)
    if util.recv_exact(sock, 2) != _REPLY_NO_AUTH:
        raise ConnectionError("SOCKS5 no-auth negotiation rejected")


def _skip_bound_address(sock: socket.socket, address_type: int) -> None:
    """Consumes the bound address in a CONNECT reply.

    The address is irrelevant to us, but it must be read so the stream is
    positioned at the start of the tunnelled data.

    Args:
        sock: Socket connected to the proxy.
        address_type: The reply's ATYP byte.
    """
    length = _FIXED_ADDRESS_LENGTHS.get(address_type)
    if length is None:
        length = util.recv_exact(sock, 1)[0]
    util.recv_exact(sock, length + 2)  # address + port


def _request_connect(sock: socket.socket, host: str, port: int) -> None:
    """Asks the proxy to open a stream and checks the reply.

    Args:
        sock: Socket that has completed the greeting.
        host: Destination hostname.
        port: Destination port.

    Raises:
        ConnectionError: If the proxy reports a failure.
    """
    sock.sendall(connect_request(host, port))
    _, status, _, address_type = util.recv_exact(sock, 4)
    if status != 0:
        raise ConnectionError(f"SOCKS5: {describe_status(status)}")
    _skip_bound_address(sock, address_type)


def socks5_connect(proxy_port: int, host: str, port: int,
                   timeout: float = 120.0,
                   proxy_host: str = "127.0.0.1") -> socket.socket:
    """Opens a TCP stream to ``host:port`` through a SOCKS5 proxy.

    This is the single entry point the rest of torrelay uses to reach a
    target through Tor.

    Args:
        proxy_port: The proxy's port (e.g. Tor's SocksPort).
        host: Destination hostname.
        port: Destination port.
        timeout: Seconds to wait for the proxy to build the stream.
        proxy_host: The proxy's address.

    Returns:
        A connected, blocking socket carrying the tunnelled stream.

    Raises:
        OSError: If the proxy is unreachable or the stream fails.
    """
    sock = socket.create_connection((proxy_host, proxy_port),
                                    timeout=_PROXY_CONNECT_TIMEOUT)
    try:
        sock.settimeout(timeout)
        _negotiate_no_auth(sock)
        _request_connect(sock, host, port)
        sock.settimeout(None)
        return sock
    except BaseException:
        sock.close()
        raise
