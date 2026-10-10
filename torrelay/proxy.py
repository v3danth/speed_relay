"""SSH ProxyCommand: SOCKS5 through Tor with ordered failover.

ssh runs ``torrelay proxy --profile NAME %h %p``. We try each SOCKS port in
order (pinned instance first, then fallbacks) and splice stdin/stdout onto
the first stream that connects.
"""

from __future__ import annotations

import os
import pathlib
import shlex
import shutil
import socket
import sys
import threading
from typing import Iterable, Optional, Sequence

from torrelay import socks
from torrelay import util

_CHUNK = 64 * 1024
_SHIM = pathlib.Path(__file__).resolve().parent.parent / "bin" / "torrelay"


def self_command() -> tuple[str, ...]:
    """Finds how to re-invoke torrelay from a ProxyCommand.

    ssh runs ProxyCommand through a shell that may not have torrelay on
    PATH, so prefer the checkout's shim, then an installed script, then
    ``python -m``.

    Returns:
        argv prefix that runs torrelay.
    """
    if _SHIM.exists():
        return (str(_SHIM),)
    installed = shutil.which("torrelay")
    return (installed,) if installed else (sys.executable, "-m", "torrelay")


def proxy_command(socks_ports: Iterable[int] = (),
                  profile: Optional[str] = None) -> str:
    """Renders a ProxyCommand string for ssh_config or ``ssh -o``.

    Args:
        socks_ports: Explicit SOCKS ports to try, in order.
        profile: Profile whose ports to use instead.

    Returns:
        A shell-quoted command ending in ``%h %p`` for ssh to fill in.
    """
    args = (
        *self_command(),
        "proxy",
        *(("--profile", profile) if profile else ()),
        *(arg for port in socks_ports for arg in ("--socks", str(port))),
    )
    return " ".join(map(shlex.quote, args)) + " %h %p"


def _try_port(host: str, port: int, timeout: float,
              socks_port: int) -> Optional[socket.socket]:
    """Attempts one SOCKS port, logging rather than raising on failure.

    Args:
        host: Destination host.
        port: Destination port.
        timeout: Seconds to wait for the stream.
        socks_port: Proxy port to try.

    Returns:
        A connected socket, or None if this port failed.
    """
    try:
        return socks.socks5_connect(socks_port, host, port, timeout)
    except OSError as exc:
        util.log(f"torrelay: via 127.0.0.1:{socks_port} failed: {exc}")
        return None


def connect_first(socks_ports: Sequence[int], host: str, port: int,
                  timeout: float) -> Optional[socket.socket]:
    """Connects through the first SOCKS port that works.

    Ports are tried lazily, so a healthy pinned instance costs nothing
    extra and fallbacks are only touched when needed.

    Args:
        socks_ports: Ports in priority order.
        host: Destination host.
        port: Destination port.
        timeout: Seconds to wait per attempt.

    Returns:
        A connected socket, or None if every port failed.
    """
    attempts = (_try_port(host, port, timeout, socks_port)
                for socks_port in socks_ports)
    return next(filter(None, attempts), None)


def _write_all(fd: int, data: bytes) -> None:
    """Writes all of ``data`` to a file descriptor.

    ``os.write`` may accept only part of the buffer on a pipe.

    Args:
        fd: Destination descriptor.
        data: Bytes to write.
    """
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _pump_stdin(sock: socket.socket) -> None:
    """Copies stdin to the socket, then half-closes it on EOF.

    The half-close tells the server we are done sending while still
    letting its remaining output reach us.

    Args:
        sock: Connected stream.
    """
    try:
        while data := os.read(sys.stdin.fileno(), _CHUNK):
            sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def _pump_socket(sock: socket.socket) -> None:
    """Copies the socket to stdout until the server closes.

    Args:
        sock: Connected stream.
    """
    try:
        while data := sock.recv(_CHUNK):
            _write_all(sys.stdout.fileno(), data)
    except OSError:
        pass


def splice(sock: socket.socket) -> None:
    """Joins this process's stdio to ``sock`` in both directions.

    Args:
        sock: Connected stream; closed when the server side ends.
    """
    threading.Thread(target=_pump_stdin, args=(sock,), daemon=True).start()
    try:
        _pump_socket(sock)
    finally:
        sock.close()


def run(host: str, port: int, socks_ports: Sequence[int],
        timeout: float) -> int:
    """Implements ``torrelay proxy``: connect with failover, then splice.

    Args:
        host: Destination host (ssh's ``%h``).
        port: Destination port (ssh's ``%p``).
        socks_ports: Ports in priority order.
        timeout: Seconds to wait per attempt.

    Returns:
        Process exit status.
    """
    sock = connect_first(socks_ports, host, port, timeout)
    if sock is None:
        util.log("torrelay: all SOCKS ports failed")
        return 1
    splice(sock)
    return 0
