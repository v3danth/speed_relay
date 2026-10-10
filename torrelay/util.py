"""Small functional helpers shared across modules."""

from __future__ import annotations

import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Sequence, TypeVar

T = TypeVar("T")
R = TypeVar("R")

_log_lock = threading.Lock()


def log(msg: str) -> None:
    """Thread-safe progress logging to stderr (stdout is for results)."""
    with _log_lock:
        print(msg, file=sys.stderr, flush=True)


def pmap(fn: Callable[[T], R], items: Sequence[T]) -> list[R]:
    """Parallel, order-preserving map with one thread per item."""
    if not items:
        return []
    with ThreadPoolExecutor(len(items)) as pool:
        return list(pool.map(fn, items))


def timed(fn: Callable[[], T]) -> tuple[float, T]:
    """Return (elapsed seconds, value) for a zero-argument call."""
    start = time.monotonic()
    value = fn()
    return time.monotonic() - start, value


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly ``n`` bytes or raise ConnectionError."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed mid-read")
        data += chunk
    return data
