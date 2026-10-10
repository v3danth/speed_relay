"""Routes (how to reach a target) and protocol probes (what to measure).

A *route* is a strategy for opening a TCP stream: through a fresh Tor
instance, through an existing SOCKS port, or directly. A *probe* runs over a
route and returns a plain dict of measurements; bench.py folds those dicts
into immutable Results.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import statistics
import subprocess
from dataclasses import dataclass
from functools import partial
from typing import Callable, Optional

from torrelay import __version__
from torrelay.proxy import proxy_command
from torrelay.socks import socks5_connect
from torrelay.target import Target
from torrelay.tor import Hop, TorNode, rendezvous_hops, stream_hops
from torrelay.util import timed

CONNECT_TIMEOUT = 180.0
IO_TIMEOUT = 120.0
CHUNK = 64 * 1024
MIB = 1024 * 1024
MIN_SPEED_BYTES = 128 * 1024  # smaller bodies say nothing about bandwidth

Connector = Callable[[str, int, float], socket.socket]
Fields = dict


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Route:
    name: str
    connect: Connector
    socks_port: Optional[int] = None
    ctrl: Optional[tuple[int, str]] = None  # (control port, data dir)
    bootstrap_s: Optional[float] = None
    pinned: str = ""


def _direct(host: str, port: int, timeout: float) -> socket.socket:
    return socket.create_connection((host, port), timeout=timeout)


def tor_route(node: TorNode, pinned: str = "") -> Route:
    return Route(node.name, partial(socks5_connect, node.socks_port),
                 node.socks_port, (node.ctrl_port, node.data_dir),
                 node.bootstrap_s, pinned)


def socks_route(port: int) -> Route:
    return Route(f"socks:{port}", partial(socks5_connect, port), port)


def direct_route() -> Route:
    return Route("direct", _direct)


def circuit_of(route: Route, target: Target) -> tuple[Hop, ...]:
    """Relays carrying our stream, if the route exposes a control port."""
    if route.ctrl is None:
        return ()
    ctrl_port, data_dir = route.ctrl
    try:
        hops = stream_hops(ctrl_port, data_dir, target.host, target.port)
        if not hops and target.is_onion:
            hops = rendezvous_hops(ctrl_port, data_dir)
        return hops
    except (OSError, RuntimeError):
        return ()


# --------------------------------------------------------------------------
# Protocol handshakes: (open socket) -> (socket to keep using, fields)
# --------------------------------------------------------------------------

def tls_context(target: Target) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if target.insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def handshake_tcp(target: Target,
                  sock: socket.socket) -> tuple[socket.socket, Fields]:
    return sock, {"detail": "connected"}


def handshake_tls(target: Target,
                  sock: socket.socket) -> tuple[socket.socket, Fields]:
    elapsed, tls = timed(lambda: tls_context(target).wrap_socket(
        sock, server_hostname=target.host))
    return tls, {"handshake_s": elapsed,
                 "detail": f"{tls.version()} {tls.cipher()[0]}"}


def handshake_ssh(target: Target,
                  sock: socket.socket) -> tuple[socket.socket, Fields]:
    elapsed, banner = timed(lambda: sock.makefile("rb").readline())
    if not banner.startswith(b"SSH-"):
        raise ConnectionError(f"not an SSH server: {banner[:40]!r}")
    return sock, {"handshake_s": elapsed,
                  "detail": banner.decode(errors="replace").strip()}


def http_request(target: Target) -> bytes:
    default = 443 if target.uses_tls else 80
    host = (target.host if target.port == default
            else f"{target.host}:{target.port}")
    return (f"GET {target.path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: torrelay/{__version__}\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n\r\n").encode()


def send_request(target: Target,
                 sock: socket.socket) -> http.client.HTTPResponse:
    sock.sendall(http_request(target))
    response = http.client.HTTPResponse(sock, method="GET")
    response.begin()
    return response


def handshake_http(target: Target,
                   sock: socket.socket) -> tuple[socket.socket, Fields]:
    sock, tls_fields = (handshake_tls(target, sock) if target.uses_tls
                        else (sock, {}))
    elapsed, response = timed(partial(send_request, target, sock))
    response.close()
    return sock, {**tls_fields, "ttfb_ms": elapsed * 1000,
                  "detail": f"HTTP {response.status} {response.reason}"}


HANDSHAKES: dict[str, Callable[[Target, socket.socket],
                               tuple[socket.socket, Fields]]] = {
    "tcp": handshake_tcp,
    "tls": handshake_tls,
    "ssh": handshake_ssh,
    "http": handshake_http,
    "https": handshake_http,
}


def probe(target: Target, route: Route) -> Fields:
    """Open a stream, record its circuit, run the protocol handshake."""
    connect_s, sock = timed(lambda: route.connect(
        target.host, target.port, CONNECT_TIMEOUT))
    try:
        hops = circuit_of(route, target)
        sock.settimeout(IO_TIMEOUT)
        sock, fields = HANDSHAKES[target.scheme](target, sock)
        return {"connect_s": connect_s, "hops": hops, **fields}
    finally:
        sock.close()


# --------------------------------------------------------------------------
# HTTP throughput
# --------------------------------------------------------------------------

def drain(read: Callable[[int], bytes], limit: int) -> int:
    """Read up to ``limit`` bytes in chunks; return the count."""
    total = 0
    while total < limit and (chunk := read(min(CHUNK, limit - total))):
        total += len(chunk)
    return total


def http_download(target: Target, route: Route, size_mib: int) -> Fields:
    limit = size_mib * MIB
    sock = route.connect(target.host, target.port, CONNECT_TIMEOUT)
    try:
        sock.settimeout(IO_TIMEOUT)
        if target.uses_tls:
            sock, _ = handshake_tls(target, sock)
        response = send_request(target, sock)
        first = response.read(1)  # start the clock at the first body byte
        elapsed, rest = timed(partial(drain, response.read,
                                      limit - len(first)))
        total = len(first) + rest
    finally:
        sock.close()
    if total < MIN_SPEED_BYTES:
        return {"detail": f"HTTP {response.status}, body {total} B "
                          "(too small to measure speed; use a bigger URL)"}
    return {"down_kib": total / max(elapsed, 1e-6) / 1024,
            "detail": f"HTTP {response.status}, {total / MIB:.1f} MiB"}


# --------------------------------------------------------------------------
# SSH (login, latency, throughput) via the system ssh client
# --------------------------------------------------------------------------

def ssh_cmd(target: Target, socks_port: Optional[int],
            remote: str) -> list[str]:
    proxy = proxy_command((socks_port,)) if socks_port else "none"
    forced = (f"ProxyCommand={proxy}", "ControlMaster=no",
              "ControlPath=none", "BatchMode=yes")
    defaults = ("StrictHostKeyChecking=accept-new", "ConnectTimeout=180",
                "Compression=no")  # zeros compress to nothing
    identity = ("IdentitiesOnly=yes",) if target.key else ()
    # ssh keeps the first value it sees, so order encodes precedence.
    options = (*forced, *identity, *target.ssh_options, *defaults)
    dest = f"{target.user}@{target.host}" if target.user else target.host
    return [
        "ssh",
        *(("-i", target.key) if target.key else ()),
        "-p", str(target.port),
        *(arg for opt in options for arg in ("-o", opt)),
        dest,
        remote,
    ]


def ssh_login(target: Target, route: Route) -> Fields:
    def run() -> None:
        proc = subprocess.run(ssh_cmd(target, route.socks_port, "true"),
                              capture_output=True, timeout=240)
        if proc.returncode != 0:
            lines = proc.stderr.decode().strip().splitlines()
            raise RuntimeError(lines[-1] if lines else "ssh login failed")

    elapsed, _ = timed(run)
    return {"login_s": elapsed}


def ssh_rtt(target: Target, route: Route, samples: int) -> Fields:
    """Median/stdev of line echoes through a remote ``cat``."""
    proc = subprocess.Popen(ssh_cmd(target, route.socks_port, "cat"),
                            bufsize=0, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE)

    def round_trip(i: int) -> float:
        elapsed, line = timed(lambda: (proc.stdin.write(f"{i}\n".encode()),
                                       proc.stdout.readline())[1])
        if not line:
            raise ConnectionError("ssh session closed")
        return elapsed * 1000

    try:
        round_trip(-1)  # warm-up: includes login
        values = list(map(round_trip, range(samples)))
    finally:
        proc.stdin.close()
        proc.wait(timeout=30)
    return {"rtt_ms": statistics.median(values),
            "jitter_ms": statistics.pstdev(values)}


def ssh_download(target: Target, route: Route, size_mib: int) -> Fields:
    nbytes = size_mib * MIB
    proc = subprocess.Popen(
        ssh_cmd(target, route.socks_port, f"head -c {nbytes} /dev/zero"),
        stdout=subprocess.PIPE)
    first = proc.stdout.read(1)  # exclude login from the timing
    elapsed, rest = timed(partial(drain, proc.stdout.read, nbytes - 1))
    proc.wait()
    received = len(first) + rest
    if received < nbytes:
        raise ConnectionError(f"short download {received}/{nbytes} bytes")
    return {"down_kib": received / max(elapsed, 1e-6) / 1024}


def ssh_upload(target: Target, route: Route, size_mib: int) -> Fields:
    nbytes = size_mib * MIB
    proc = subprocess.Popen(
        ssh_cmd(target, route.socks_port,
                "echo ready; cat > /dev/null; echo done"),
        stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    if not proc.stdout.readline():  # wait for login so it isn't timed
        raise ConnectionError("ssh session closed before upload")

    def push() -> bytes:
        block = bytes(CHUNK)
        for _ in range(nbytes // CHUNK):
            proc.stdin.write(block)
        proc.stdin.close()
        return proc.stdout.read()

    elapsed, ack = timed(push)
    proc.wait()
    if b"done" not in ack:
        raise ConnectionError("upload not acknowledged")
    return {"up_kib": nbytes / max(elapsed, 1e-6) / 1024}
