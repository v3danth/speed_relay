"""SSH ProxyCommand: SOCKS5 through Tor with ordered failover.

ssh runs ``torrelay proxy --profile NAME %h %p``; we try each SOCKS port in
order (pinned instance first, then fallbacks) and splice stdin/stdout onto
the first stream that connects.
"""

from __future__ import annotations

import os
import shlex
import shutil
import socket
import sys
import threading
from pathlib import Path
from typing import Iterable, Optional, Sequence

from torrelay.socks import socks5_connect
from torrelay.util import log

CHUNK = 64 * 1024


def self_command() -> tuple[str, ...]:
    """How to invoke this tool from a ProxyCommand (no PATH required)."""
    shim = Path(__file__).resolve().parent.parent / "bin" / "torrelay"
    if shim.exists():
        return (str(shim),)
    installed = shutil.which("torrelay")
    return (installed,) if installed else (sys.executable, "-m", "torrelay")


def proxy_command(socks_ports: Iterable[int] = (),
                  profile: Optional[str] = None) -> str:
    """Render a ProxyCommand string for ssh_config or ``ssh -o``."""
    args = (
        *self_command(),
        "proxy",
        *(("--profile", profile) if profile else ()),
        *(arg for port in socks_ports for arg in ("--socks", str(port))),
    )
    return " ".join(map(shlex.quote, args)) + " %h %p"


def connect_first(ports: Sequence[int], host: str, port: int,
                  timeout: float) -> Optional[socket.socket]:
    """Try each SOCKS port lazily, in order; return the first success."""
    def attempt(socks_port: int) -> Optional[socket.socket]:
        try:
            return socks5_connect(socks_port, host, port, timeout)
        except OSError as exc:
            log(f"torrelay: via 127.0.0.1:{socks_port} failed: {exc}")
            return None

    return next(filter(None, map(attempt, ports)), None)


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _stdin_to_socket(sock: socket.socket) -> None:
    try:
        while data := os.read(sys.stdin.fileno(), CHUNK):
            sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def splice(sock: socket.socket) -> None:
    """Bidirectional copy between this process's stdio and ``sock``."""
    threading.Thread(target=_stdin_to_socket, args=(sock,),
                     daemon=True).start()
    try:
        while data := sock.recv(CHUNK):
            _write_all(sys.stdout.fileno(), data)
    except OSError:
        pass
    finally:
        sock.close()


def run(host: str, port: int, socks_ports: Sequence[int],
        timeout: float) -> int:
    sock = connect_first(socks_ports, host, port, timeout)
    if sock is None:
        log("torrelay: all SOCKS ports failed")
        return 1
    splice(sock)
    return 0
