"""Rendering benchmark results as a table or JSON-ready dicts."""

from __future__ import annotations

import dataclasses
from typing import Iterable, Optional

from torrelay import bench
from torrelay import target as target_lib
from torrelay import tor

GUARD_KEY = "guard_fingerprint"
EXIT_KEY = "exit_fingerprint"

_COLUMNS = (  # (header, width, Result attribute, decimals)
    ("conn s", 7, "connect_s", 1),
    ("hs s", 6, "handshake_s", 1),
    ("lat ms", 8, "latency_ms", 0),
    ("down KiB", 9, "down_kib", 0),
    ("up KiB", 8, "up_kib", 0),
)
_NAME_TITLE = "route"
_NAME_WIDTH = 11


def number(value: Optional[float], width: int, decimals: int) -> str:
    """Right-aligns a number, or ``-`` when it was not measured.

    Args:
        value: The measurement.
        width: Column width.
        decimals: Digits after the decimal point.

    Returns:
        The formatted cell.
    """
    if value is None:
        return "-".rjust(width)
    return f"{value:>{width}.{decimals}f}"


def _status(result: bench.Result) -> str:
    """Renders the trailing status column: path and detail, or the error.

    Args:
        result: One route's result.

    Returns:
        ``OK <path> [detail]`` or ``FAIL <error>``.
    """
    if result.error:
        return f"FAIL {result.error}"
    path = tor.format_path(result.hops) or "(no circuit info)"
    detail = f"  [{result.detail}]" if result.detail else ""
    return f"OK   {path}{detail}"


def format_row(result: bench.Result) -> str:
    """Renders one result as a table row.

    Args:
        result: One route's result.

    Returns:
        The row text.
    """
    cells = "".join(number(getattr(result, attr), width, decimals)
                    for _, width, attr, decimals in _COLUMNS)
    return f"{result.name:<{_NAME_WIDTH}}{cells}  {_status(result)}"


def format_header() -> str:
    """Renders the table header matching ``format_row``.

    Returns:
        The header text.
    """
    cells = "".join(f"{title:>{width}}" for title, width, _, _ in _COLUMNS)
    return f"{_NAME_TITLE:<{_NAME_WIDTH}}{cells}  status / path"


def format_table(results: Iterable[bench.Result]) -> str:
    """Renders results as an aligned text table for the terminal.

    Args:
        results: Results, already ranked.

    Returns:
        The table text.
    """
    return "\n".join((format_header(), *map(format_row, results)))


def exit_fingerprint(result: bench.Result,
                     target: target_lib.Target) -> Optional[str]:
    """Identifies the exit relay of a clearnet circuit.

    Onion circuits end at a rendezvous point, which is not an exit and
    cannot be pinned, so they have none.

    Args:
        result: One route's result.
        target: The benchmarked destination.

    Returns:
        The exit's fingerprint, or None.
    """
    if target.is_onion or len(result.hops) < 3:
        return None
    return result.hops[-1].fingerprint


def to_dict(result: bench.Result, target: target_lib.Target) -> dict:
    """Serialises a result for ``--json`` and saved results.

    Args:
        result: One route's result.
        target: The benchmarked destination.

    Returns:
        A JSON-ready dict including derived fields used for pinning.
    """
    return {
        **dataclasses.asdict(result),
        "ok": result.ok,
        "latency_ms": result.latency_ms,
        GUARD_KEY: result.hops[0].fingerprint if result.hops else None,
        EXIT_KEY: exit_fingerprint(result, target),
    }


def top_relays(rows: Iterable[dict], count: int,
               key: str = GUARD_KEY) -> tuple[str, ...]:
    """Picks the best distinct relays from ranked rows, for pinning.

    Args:
        rows: Serialised results, best first.
        count: How many relays to return.
        key: ``GUARD_KEY`` or ``EXIT_KEY``.

    Returns:
        Up to ``count`` fingerprints from successful rows.
    """
    fingerprints = (row[key] for row in rows if row.get("ok") and row.get(key))
    return tuple(dict.fromkeys(fingerprints))[:count]
