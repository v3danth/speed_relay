"""Rendering benchmark results as a table or JSON-ready dicts."""

from __future__ import annotations

from dataclasses import asdict
from typing import Iterable, Optional

from torrelay.bench import Result
from torrelay.target import Target


def _num(value: Optional[float], width: int, digits: int = 0) -> str:
    if value is None:
        return "-".rjust(width)
    return f"{value:>{width}.{digits}f}"


def format_row(result: Result) -> str:
    cells = "".join((
        f"{result.name:<11}",
        _num(result.connect_s, 7, 1),
        _num(result.handshake_s, 6, 1),
        _num(result.latency_ms, 8),
        _num(result.down_kib, 9),
        _num(result.up_kib, 8),
    ))
    if result.error:
        return f"{cells}  FAIL {result.error}"
    path = " -> ".join(h.label for h in result.hops) or "(no circuit info)"
    detail = f"  [{result.detail}]" if result.detail else ""
    return f"{cells}  OK   {path}{detail}"


def format_table(results: Iterable[Result]) -> str:
    header = (f"{'route':<11}{'conn s':>7}{'hs s':>6}{'lat ms':>8}"
              f"{'down KiB':>9}{'up KiB':>8}  status / path")
    return "\n".join((header, *map(format_row, results)))


def to_dict(result: Result, target: Target) -> dict:
    """JSON-ready row; exits only exist for clearnet circuits."""
    hops = result.hops
    exit_fp = (hops[-1].fingerprint
               if len(hops) >= 3 and not target.is_onion else None)
    return {**asdict(result), "ok": result.ok,
            "latency_ms": result.latency_ms,
            "guard_fingerprint": hops[0].fingerprint if hops else None,
            "exit_fingerprint": exit_fp}


def top_relays(rows: Iterable[dict], n: int,
               key: str = "guard_fingerprint") -> tuple[str, ...]:
    """First ``n`` distinct fingerprints under ``key`` of successful rows."""
    fps = (r[key] for r in rows if r.get("ok") and r.get(key))
    return tuple(dict.fromkeys(fps))[:n]
