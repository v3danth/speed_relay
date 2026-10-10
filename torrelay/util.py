"""Small, dependency-free helpers shared by every torrelay module."""

from __future__ import annotations

from concurrent import futures
import socket
import sys
import threading
import time
from typing import Callable, Sequence, TypeVar

T = TypeVar("T")
R = TypeVar("R")

_LOG_LOCK = threading.Lock()


def log(message: str) -> None:
    """Prints progress to stderr so stdout stays clean for results.

    Many routes run in parallel threads; the lock keeps their lines from
    interleaving mid-line.

    Args:
        message: Text to print.
    """
    with _LOG_LOCK:
        print(message, file=sys.stderr, flush=True)


def pmap(fn: Callable[[T], R], items: Sequence[T]) -> list[R]:
    """Maps ``fn`` over ``items`` concurrently, preserving order.

    Network probes spend almost all their time waiting, so one thread per
    item gives true parallelism without the complexity of asyncio.

    Args:
        fn: Function applied to each item.
        items: Inputs; an empty sequence returns an empty list.

    Returns:
        The results, in the same order as ``items``.
    """
    if not items:
        return []
    with futures.ThreadPoolExecutor(len(items)) as pool:
        return list(pool.map(fn, items))


def timed(fn: Callable[[], T]) -> tuple[float, T]:
    """Measures how long a zero-argument call takes.

    Centralises timing so every measurement uses the same monotonic clock.

    Args:
        fn: The call to time.

    Returns:
        A ``(elapsed_seconds, return_value)`` pair.
    """
    start = time.monotonic()
    value = fn()
    return time.monotonic() - start, value


def kib_per_second(nbytes: int, seconds: float) -> float:
    """Converts a byte count and duration into KiB/s.

    Guards against division by zero for transfers that finish instantly.

    Args:
        nbytes: Bytes transferred.
        seconds: Time taken.

    Returns:
        Throughput in KiB per second.
    """
    return nbytes / max(seconds, 1e-6) / 1024


def last_line(text: str, default: str) -> str:
    """Returns the last non-empty line of ``text`` or ``default``.

    Tools such as ssh and tor print their real error on the final line, so
    this keeps error messages short and relevant.

    Args:
        text: Multi-line output.
        default: Fallback when there is no output.

    Returns:
        The final line, stripped.
    """
    lines = text.strip().splitlines()
    return lines[-1].strip() if lines else default


def recv_exact(sock: socket.socket, nbytes: int) -> bytes:
    """Reads exactly ``nbytes`` from a socket.

    ``socket.recv`` may return fewer bytes than asked for; protocol parsers
    need fixed-size fields, so they read through this.

    Args:
        sock: A connected socket.
        nbytes: Number of bytes required.

    Returns:
        Exactly ``nbytes`` bytes.

    Raises:
        ConnectionError: If the peer closes before enough data arrives.
    """
    data = b""
    while len(data) < nbytes:
        chunk = sock.recv(nbytes - len(data))
        if not chunk:
            raise ConnectionError("connection closed mid-read")
        data += chunk
    return data
