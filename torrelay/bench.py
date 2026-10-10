"""Race a target across many routes (Tor circuits, SOCKS ports, direct).

A run is two phases over a list of routes:

1. latency: every route at once (connectivity, handshake, rtt);
2. throughput: one route at a time by default, so they don't compete.

Each phase is a fold of named steps over an immutable Result; the first
failing step records its error and short-circuits the rest.
"""

from __future__ import annotations

import os
import shutil
import statistics
import tempfile
from dataclasses import dataclass, replace
from functools import partial, reduce
from typing import Callable, Iterable, Optional, Sequence, Union

from torrelay import probes
from torrelay.probes import Route
from torrelay.target import Target
from torrelay.tor import Hop, TorNode, launch_ephemeral, stop
from torrelay.util import log, pmap


@dataclass(frozen=True)
class BenchOptions:
    instances: int = 6
    size_mib: int = 4
    rtt_samples: int = 10
    parallel_throughput: bool = False
    bootstrap_timeout: float = 180
    guards: tuple[str, ...] = ()  # one pinned guard per instance
    exits: tuple[str, ...] = ()   # one pinned exit per instance
    connect_only: bool = False
    direct: bool = False          # add a no-Tor baseline route


@dataclass(frozen=True)
class Result:
    """Measurements for one route; fields fill in as steps succeed."""

    name: str
    bootstrap_s: Optional[float] = None
    connect_s: Optional[float] = None
    handshake_s: Optional[float] = None
    ttfb_ms: Optional[float] = None
    login_s: Optional[float] = None
    rtt_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    down_kib: Optional[float] = None
    up_kib: Optional[float] = None
    hops: tuple[Hop, ...] = ()
    detail: str = ""
    pinned: str = ""
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.connect_s is not None

    @property
    def guard(self) -> Optional[Hop]:
        return self.hops[0] if self.hops else None

    @property
    def latency_ms(self) -> Optional[float]:
        """Best available latency signal: rtt, else ttfb, else setup."""
        if self.rtt_ms is not None:
            return self.rtt_ms
        if self.ttfb_ms is not None:
            return self.ttfb_ms
        if self.connect_s is None:
            return None
        return (self.connect_s + (self.handshake_s or 0)) * 1000


Step = tuple[str, Callable[[], dict]]

_FIELD_FORMATS = {
    "connect_s": "connect {:.2f}s",
    "handshake_s": "handshake {:.2f}s",
    "ttfb_ms": "ttfb {:.0f}ms",
    "login_s": "login {:.2f}s",
    "rtt_ms": "rtt {:.0f}ms",
    "jitter_ms": "±{:.0f}ms",
    "down_kib": "down {:.0f} KiB/s",
    "up_kib": "up {:.0f} KiB/s",
    "detail": "{}",
}


def describe(fields: dict) -> str:
    """Human summary of a probe's fields, in a stable order."""
    parts = [fmt.format(fields[k]) for k, fmt in _FIELD_FORMATS.items()
             if fields.get(k) is not None]
    hops = fields.get("hops")
    if hops:
        parts.append("path " + " -> ".join(h.label for h in hops))
    return "  ".join(parts)


# --------------------------------------------------------------------------
# Step combinators
# --------------------------------------------------------------------------

def attempt(result: Result, step: Step) -> Result:
    if result.error:
        return result
    label, fn = step
    try:
        fields = fn()
    except Exception as exc:  # noqa: BLE001 - recorded per route
        message = str(exc) or type(exc).__name__
        log(f"[{result.name}] {label} failed: {message}")
        return replace(result, error=f"{label}: {message}")
    log(f"[{result.name}] {label}: {describe(fields)}")
    return replace(result, **fields)


def run_steps(result: Result, steps: Iterable[Step]) -> Result:
    return reduce(attempt, steps, result)


def latency_plan(target: Target, opts: BenchOptions,
                 route: Route) -> tuple[Step, ...]:
    connect = (("connect", partial(probes.probe, target, route)),)
    if target.scheme != "ssh" or opts.connect_only:
        return connect
    return (*connect,
            ("login", partial(probes.ssh_login, target, route)),
            ("rtt", partial(probes.ssh_rtt, target, route,
                            opts.rtt_samples)))


def throughput_plan(target: Target, opts: BenchOptions,
                    route: Route) -> tuple[Step, ...]:
    if opts.connect_only:
        return ()
    plans: dict[str, tuple[Step, ...]] = {
        "ssh": (
            ("download", partial(probes.ssh_download, target, route,
                                 opts.size_mib)),
            ("upload", partial(probes.ssh_upload, target, route,
                               opts.size_mib)),
        ),
        "http": (("download", partial(probes.http_download, target, route,
                                      opts.size_mib)),),
    }
    plans["https"] = plans["http"]
    return plans.get(target.scheme, ())


# --------------------------------------------------------------------------
# Ranking
# --------------------------------------------------------------------------

def score(result: Result) -> float:
    """Higher is better: mean throughput minus a latency penalty."""
    if not result.ok:
        return float("-inf")
    speeds = [v for v in (result.down_kib, result.up_kib) if v is not None]
    throughput = statistics.mean(speeds) if speeds else 0.0
    return throughput - 0.5 * (result.latency_ms or 0.0)


def rank(results: Iterable[Result]) -> list[Result]:
    return sorted(results, key=score, reverse=True)


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def measure(target: Target, opts: BenchOptions, routes: Sequence[Route],
            failed: Sequence[Result] = ()) -> list[Result]:
    """Run both phases over ``routes`` and return ranked results."""
    def fresh(route: Route) -> Result:
        return Result(route.name, bootstrap_s=route.bootstrap_s,
                      pinned=route.pinned)

    plural = "route" if len(routes) == 1 else "routes simultaneously"
    log(f"\n== Connectivity & latency: {target.url} "
        f"({len(routes)} {plural}) ==")
    latency = pmap(lambda r: run_steps(
        fresh(r), latency_plan(target, opts, r)), routes)

    pairs = list(zip(routes, latency))
    if any(throughput_plan(target, opts, r) for r in routes):
        mode = "parallel" if opts.parallel_throughput else "sequential"
        log(f"\n== Throughput ({mode}, up to {opts.size_mib} MiB) ==")

    def throughput(pair: tuple[Route, Result]) -> Result:
        route, result = pair
        return run_steps(result, throughput_plan(target, opts, route))

    final = (pmap(throughput, pairs) if opts.parallel_throughput
             else list(map(throughput, pairs)))
    return rank([*final, *failed])


Spec = tuple[str, tuple[str, ...], str]


def instance_specs(opts: BenchOptions) -> tuple[Spec, ...]:
    """(name, extra torrc lines, pin label) for each Tor instance."""
    count = max(len(opts.guards), len(opts.exits)) or opts.instances

    def spec(i: int) -> Spec:
        guard = opts.guards[i] if i < len(opts.guards) else None
        exit_ = opts.exits[i] if i < len(opts.exits) else None
        lines = ((f"EntryNodes ${guard}",) if guard else ()) + (
            (f"ExitNodes ${exit_}",) if exit_ else ())
        label = " ".join(filter(None, (
            f"guard={guard[:8]}" if guard else "",
            f"exit={exit_[:8]}" if exit_ else "")))
        return f"tor{i}", lines, label

    return tuple(map(spec, range(count)))


Launched = tuple[TorNode, str]


def _launch(base_dir: str, timeout: float,
            spec: Spec) -> Union[Launched, Result]:
    name, lines, label = spec
    try:
        node = launch_ephemeral(name, os.path.join(base_dir, name), timeout,
                                lines)
        log(f"[{name}] bootstrapped in {node.bootstrap_s:.1f}s"
            + (f" ({label})" if label else ""))
        return node, label
    except Exception as exc:  # noqa: BLE001
        log(f"[{name}] {exc}")
        return Result(name, pinned=label, error=f"bootstrap: {exc}")


def run(target: Target, opts: BenchOptions) -> list[Result]:
    """Launch fresh Tor instances in parallel, measure, tear down."""
    base_dir = tempfile.mkdtemp(prefix="torrelay_")
    specs = instance_specs(opts)
    launched: list[Union[Launched, Result]] = []
    try:
        log(f"Launching {len(specs)} Tor instances in parallel ...")
        launched = pmap(partial(_launch, base_dir, opts.bootstrap_timeout),
                        specs)
        routes = [probes.tor_route(*x) for x in launched
                  if isinstance(x, tuple)]
        failed = [x for x in launched if isinstance(x, Result)]
        extra = [probes.direct_route()] if opts.direct else []
        return measure(target, opts, [*routes, *extra], failed)
    finally:
        for item in launched:
            if isinstance(item, tuple):
                stop(item[0].proc)
        shutil.rmtree(base_dir, ignore_errors=True)


def check(target: Target, opts: BenchOptions,
          socks_ports: Sequence[int]) -> list[Result]:
    """Measure through already-running SOCKS proxies (no bootstrap)."""
    routes = [*map(probes.socks_route, socks_ports),
              *([probes.direct_route()] if opts.direct else [])]
    return measure(target, opts, routes)
