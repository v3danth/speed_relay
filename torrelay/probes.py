"""Routes (how to reach a target) and probes (what to measure).

A route is a strategy for opening a TCP stream: through a fresh Tor
instance, through an existing SOCKS port, or directly. A probe runs over a
route and returns a plain dict of measurements, which bench.py folds into
immutable Results.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import http.client
import socket
import ssl
import statistics
import subprocess
from typing import Callable, Iterator, Optional

import torrelay
from torrelay import proxy
from torrelay import socks
from torrelay import target as target_lib
from torrelay import tor
from torrelay import util

CONNECT_TIMEOUT = 180.0
IO_TIMEOUT = 120.0
SSH_TIMEOUT = 240.0
CHUNK = 64 * 1024
MIB = 1024 * 1024
MIN_SPEED_BYTES = 128 * 1024  # Smaller bodies say nothing about bandwidth.

Target = target_lib.Target
Connector = Callable[[str, int, float], socket.socket]
Fields = dict
Handshake = Callable[[Target, socket.socket], tuple[socket.socket, Fields]]


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Route:
    """A way to open TCP streams, plus what we know about it.

    Attributes:
        name: Display name, e.g. ``tor2``, ``socks:9050`` or ``direct``.
        connect: Opens a stream: ``(host, port, timeout) -> socket``.
        socks_port: SOCKS port for tools such as ssh; None when direct.
        control: Control port for circuit lookups, when we own the Tor.
        bootstrap_s: How long the route's Tor took to start.
        pinned: Human-readable description of pinned relays.
    """

    name: str
    connect: Connector
    socks_port: Optional[int] = None
    control: Optional[tor.ControlEndpoint] = None
    bootstrap_s: Optional[float] = None
    pinned: str = ""


def _direct_connect(host: str, port: int, timeout: float) -> socket.socket:
    """Opens a plain TCP connection, for the no-Tor baseline.

    Args:
        host: Destination host.
        port: Destination port.
        timeout: Connect timeout in seconds.

    Returns:
        The connected socket.
    """
    return socket.create_connection((host, port), timeout=timeout)


def tor_route(node: tor.TorNode, pinned: str = "") -> Route:
    """Builds a route through a Tor instance that torrelay started.

    Args:
        node: The running instance.
        pinned: Description of relays pinned for this instance.

    Returns:
        A route that can also report its circuit.
    """
    return Route(node.name,
                 functools.partial(socks.socks5_connect, node.socks_port),
                 node.socks_port, node.control, node.bootstrap_s, pinned)


def socks_route(port: int) -> Route:
    """Builds a route through an already-running SOCKS proxy.

    Args:
        port: Proxy port on 127.0.0.1 (e.g. system Tor's 9050).

    Returns:
        A route without circuit introspection.
    """
    return Route(f"socks:{port}",
                 functools.partial(socks.socks5_connect, port), port)


def direct_route() -> Route:
    """Builds a no-Tor route, used as a speed baseline.

    Returns:
        A route that connects directly.
    """
    return Route("direct", _direct_connect)


def circuit_of(route: Route, target: Target) -> tuple[tor.Hop, ...]:
    """Looks up which relays carry our stream, when the route allows it.

    Best effort: a failed lookup must never fail the measurement itself.

    Args:
        route: The route the stream was opened on.
        target: The stream's destination.

    Returns:
        The circuit's hops, or ``()`` if unknown.
    """
    if route.control is None:
        return ()
    try:
        hops = tor.stream_hops(route.control, target.host, target.port)
        if not hops and target.is_onion:
            hops = tor.rendezvous_hops(route.control)
        return hops
    except (OSError, RuntimeError):
        return ()


@contextlib.contextmanager
def open_stream(target: Target,
                route: Route) -> Iterator[tuple[socket.socket, float]]:
    """Opens a timed stream to the target and guarantees it is closed.

    Shared by every probe so connection setup and cleanup behave the same
    everywhere.

    Args:
        target: Destination.
        route: How to reach it.

    Yields:
        ``(socket, seconds_to_connect)``.
    """
    connect_s, sock = util.timed(
        lambda: route.connect(target.host, target.port, CONNECT_TIMEOUT))
    try:
        sock.settimeout(IO_TIMEOUT)
        yield sock, connect_s
    finally:
        sock.close()


# --------------------------------------------------------------------------
# Protocol handshakes: (target, open socket) -> (socket to use, fields)
# --------------------------------------------------------------------------

def tls_context(target: Target) -> ssl.SSLContext:
    """Creates the TLS context for a target, honouring ``--insecure``.

    Args:
        target: Destination; ``insecure`` disables verification.

    Returns:
        A client SSL context.
    """
    context = ssl.create_default_context()
    if target.insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def handshake_tcp(target: Target,
                  sock: socket.socket) -> tuple[socket.socket, Fields]:
    """Accepts a bare TCP connection as success (tcp:// targets).

    Args:
        target: Unused; present for a uniform handshake signature.
        sock: The connected stream.

    Returns:
        The socket and a status detail.
    """
    del target  # Unused; all handshakes share one signature.
    return sock, {"detail": "connected"}


def handshake_tls(target: Target,
                  sock: socket.socket) -> tuple[socket.socket, Fields]:
    """Performs a TLS handshake and reports what was negotiated.

    Args:
        target: Destination, for SNI and verification settings.
        sock: The connected stream.

    Returns:
        The TLS socket, the handshake time, and protocol/cipher detail.
    """
    elapsed, tls_sock = util.timed(lambda: tls_context(target).wrap_socket(
        sock, server_hostname=target.host))
    return tls_sock, {"handshake_s": elapsed,
                      "detail": f"{tls_sock.version()} {tls_sock.cipher()[0]}"}


def handshake_ssh(target: Target,
                  sock: socket.socket) -> tuple[socket.socket, Fields]:
    """Reads the SSH banner, proving an SSH server answers.

    This needs no credentials, so connectivity can be tested on its own.

    Args:
        target: Unused; present for a uniform handshake signature.
        sock: The connected stream.

    Returns:
        The socket, banner time, and the banner text.

    Raises:
        ConnectionError: If the server is not speaking SSH.
    """
    del target  # Unused; all handshakes share one signature.
    elapsed, banner = util.timed(lambda: sock.makefile("rb").readline())
    if not banner.startswith(b"SSH-"):
        raise ConnectionError(f"not an SSH server: {banner[:40]!r}")
    return sock, {"handshake_s": elapsed,
                  "detail": banner.decode(errors="replace").strip()}


def http_request(target: Target) -> bytes:
    """Builds a minimal HTTP/1.1 GET request for the target.

    Identity encoding keeps byte counts honest for throughput.

    Args:
        target: Destination; its path is requested.

    Returns:
        The encoded request.
    """
    default_port = 443 if target.uses_tls else 80
    host = (target.host if target.port == default_port
            else f"{target.host}:{target.port}")
    return (f"GET {target.path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: torrelay/{torrelay.__version__}\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n").encode()


def start_http(target: Target,
               sock: socket.socket) -> tuple[socket.socket, Fields]:
    """Upgrades to TLS when the target needs it, for http and https alike.

    Args:
        target: Destination.
        sock: The connected stream.

    Returns:
        The socket to speak HTTP on, plus any TLS fields.
    """
    return handshake_tls(target, sock) if target.uses_tls else (sock, {})


def send_request(target: Target,
                 sock: socket.socket) -> http.client.HTTPResponse:
    """Sends the GET request and parses the response headers.

    Args:
        target: Destination.
        sock: Stream ready for HTTP.

    Returns:
        The response, positioned at the start of the body.
    """
    sock.sendall(http_request(target))
    response = http.client.HTTPResponse(sock, method="GET")
    response.begin()
    return response


def handshake_http(target: Target,
                   sock: socket.socket) -> tuple[socket.socket, Fields]:
    """Measures time to first byte and the status of an HTTP(S) request.

    Args:
        target: Destination.
        sock: The connected stream.

    Returns:
        The socket and TLS/TTFB/status fields.
    """
    sock, tls_fields = start_http(target, sock)
    elapsed, response = util.timed(
        functools.partial(send_request, target, sock))
    response.close()
    return sock, {**tls_fields, "ttfb_ms": elapsed * 1000,
                  "detail": f"HTTP {response.status} {response.reason}"}


HANDSHAKES: dict[str, Handshake] = {
    "tcp": handshake_tcp,
    "tls": handshake_tls,
    "ssh": handshake_ssh,
    "http": handshake_http,
    "https": handshake_http,
}


def probe(target: Target, route: Route) -> Fields:
    """Tests connectivity: opens a stream, records its circuit, handshakes.

    Args:
        target: Destination; its scheme selects the handshake.
        route: How to reach it.

    Returns:
        Connect time, circuit hops, and the handshake's fields.
    """
    with open_stream(target, route) as (sock, connect_s):
        hops = circuit_of(route, target)
        sock, fields = HANDSHAKES[target.scheme](target, sock)
        sock.close()
    return {"connect_s": connect_s, "hops": hops, **fields}


# --------------------------------------------------------------------------
# Throughput helpers
# --------------------------------------------------------------------------

def drain(read: Callable[[int], bytes], limit: int) -> int:
    """Reads and discards up to ``limit`` bytes from a stream.

    Args:
        read: A ``read(n)`` function returning ``b""`` at EOF.
        limit: Maximum bytes to read.

    Returns:
        Bytes actually read.
    """
    total = 0
    while total < limit and (chunk := read(min(CHUNK, limit - total))):
        total += len(chunk)
    return total


def timed_body(read: Callable[[int], bytes], limit: int) -> tuple[float, int]:
    """Times a download from its first byte, excluding setup latency.

    Args:
        read: A ``read(n)`` function.
        limit: Maximum bytes to read.

    Returns:
        ``(seconds, bytes_read)``.
    """
    first = read(1)
    if not first:
        return 0.0, 0
    elapsed, rest = util.timed(functools.partial(drain, read, limit - 1))
    return elapsed, 1 + rest


def http_download(target: Target, route: Route, size_mib: int) -> Fields:
    """Measures HTTP(S) download speed through a route.

    Args:
        target: Destination; point it at a large file for meaningful speed.
        route: How to reach it.
        size_mib: Maximum MiB to read.

    Returns:
        Download speed (when the body was big enough) and a status detail.
    """
    with open_stream(target, route) as (sock, _):
        sock, _ = start_http(target, sock)
        response = send_request(target, sock)
        elapsed, total = timed_body(response.read, size_mib * MIB)
        sock.close()
    if total < MIN_SPEED_BYTES:
        return {"detail": f"HTTP {response.status}, body {total} B "
                          "(too small to measure speed; use a bigger URL)"}
    return {"down_kib": util.kib_per_second(total, elapsed),
            "detail": f"HTTP {response.status}, {total / MIB:.1f} MiB"}


# --------------------------------------------------------------------------
# SSH (login, latency, throughput) via the system ssh client
# --------------------------------------------------------------------------

def ssh_cmd(target: Target, socks_port: Optional[int],
            remote: str) -> list[str]:
    """Builds an ssh command line that bypasses the user's ssh_config tricks.

    Connection sharing is disabled so every measurement uses a fresh
    connection over the intended route. ssh keeps the first value it sees
    for an option, so the order below encodes precedence: forced options,
    then the user's, then defaults.

    Args:
        target: Destination and credentials.
        socks_port: Route's SOCKS port, or None for a direct connection.
        remote: Command to run on the server.

    Returns:
        argv for ``subprocess``.
    """
    proxy_option = (proxy.proxy_command((socks_port,)) if socks_port
                    else "none")
    forced = (f"ProxyCommand={proxy_option}", "ControlMaster=no",
              "ControlPath=none", "BatchMode=yes")
    identity = ("IdentitiesOnly=yes",) if target.key else ()
    defaults = ("StrictHostKeyChecking=accept-new", "ConnectTimeout=180",
                "Compression=no")  # Zeros compress to nothing.
    options = (*forced, *identity, *target.ssh_options, *defaults)
    return [
        "ssh",
        *(("-i", target.key) if target.key else ()),
        "-p", str(target.port),
        *(arg for option in options for arg in ("-o", option)),
        target.destination,
        remote,
    ]


def _ssh_popen(target: Target, route: Route, remote: str,
               **kwargs) -> subprocess.Popen:
    """Starts ssh over a route; the single place ssh processes are created.

    Args:
        target: Destination and credentials.
        route: How to reach it.
        remote: Command to run on the server.
        **kwargs: Passed to ``subprocess.Popen`` (pipes etc.).

    Returns:
        The ssh process.
    """
    return subprocess.Popen(  # pylint: disable=consider-using-with
        ssh_cmd(target, route.socks_port, remote), **kwargs)


def ssh_login(target: Target, route: Route) -> Fields:
    """Measures a full SSH login (circuit + key exchange + auth).

    Args:
        target: Destination and credentials.
        route: How to reach it.

    Returns:
        The login time.

    Raises:
        RuntimeError: With ssh's own error if login fails.
    """
    def login() -> None:
        """Runs ``true`` remotely and raises ssh's error on failure."""
        proc = subprocess.run(ssh_cmd(target, route.socks_port, "true"),
                              capture_output=True, timeout=SSH_TIMEOUT,
                              check=False)
        if proc.returncode != 0:
            raise RuntimeError(util.last_line(proc.stderr.decode(),
                                              "ssh login failed"))

    elapsed, _ = util.timed(login)
    return {"login_s": elapsed}


def ssh_rtt(target: Target, route: Route, samples: int) -> Fields:
    """Measures interactive latency by echoing lines through remote ``cat``.

    This is what typing in a shell feels like, which ping-style tests
    through Tor cannot measure.

    Args:
        target: Destination and credentials.
        route: How to reach it.
        samples: Number of round trips to time.

    Returns:
        Median round trip and its standard deviation, in milliseconds.
    """
    proc = _ssh_popen(target, route, "cat", bufsize=0,
                      stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def round_trip(index: int) -> float:
        """Times one echoed line; raises if the session ended."""
        elapsed, line = util.timed(
            lambda: (proc.stdin.write(f"{index}\n".encode()),
                     proc.stdout.readline())[1])
        if not line:
            raise ConnectionError("ssh session closed")
        return elapsed * 1000

    try:
        round_trip(-1)  # Warm-up; includes login.
        values = list(map(round_trip, range(samples)))
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)
    return {"rtt_ms": statistics.median(values),
            "jitter_ms": statistics.pstdev(values)}


def ssh_download(target: Target, route: Route, size_mib: int) -> Fields:
    """Measures server-to-client throughput over SSH.

    Args:
        target: Destination and credentials.
        route: How to reach it.
        size_mib: MiB of zeros to transfer.

    Returns:
        Download speed in KiB/s.

    Raises:
        ConnectionError: If the transfer ends early.
    """
    nbytes = size_mib * MIB
    proc = _ssh_popen(target, route, f"head -c {nbytes} /dev/zero",
                      stdout=subprocess.PIPE)
    elapsed, received = timed_body(proc.stdout.read, nbytes)
    proc.wait()
    if received < nbytes:
        raise ConnectionError(f"short download {received}/{nbytes} bytes")
    return {"down_kib": util.kib_per_second(received, elapsed)}


def ssh_upload(target: Target, route: Route, size_mib: int) -> Fields:
    """Measures client-to-server throughput over SSH.

    The server prints ``ready`` after login so login time is excluded, and
    ``done`` after consuming everything so we time the full transfer.

    Args:
        target: Destination and credentials.
        route: How to reach it.
        size_mib: MiB of zeros to transfer.

    Returns:
        Upload speed in KiB/s.

    Raises:
        ConnectionError: If the session ends before the server confirms.
    """
    nbytes = size_mib * MIB
    proc = _ssh_popen(target, route, "echo ready; cat > /dev/null; echo done",
                      stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    if not proc.stdout.readline():
        raise ConnectionError("ssh session closed before upload")

    def push() -> bytes:
        """Streams the payload and returns the server's acknowledgement."""
        block = bytes(CHUNK)
        for _ in range(nbytes // CHUNK):
            proc.stdin.write(block)
        proc.stdin.close()
        return proc.stdout.read()

    elapsed, ack = util.timed(push)
    proc.wait()
    if b"done" not in ack:
        raise ConnectionError("upload not acknowledged")
    return {"up_kib": util.kib_per_second(nbytes, elapsed)}
