"""Race a target across many routes (Tor circuits, SOCKS ports, direct).

A run is two phases over a list of routes:

1. latency: every route at once (connectivity, handshake, rtt);
2. throughput: one route at a time by default, so routes don't compete.

Each phase folds named steps over an immutable Result; the first failing
step records its error and the remaining steps are skipped.
"""

from __future__ import annotations

import dataclasses
import functools
import os
import shutil
import statistics
import tempfile
from typing import Callable, Iterable, Optional, Sequence

from torrelay import probes
from torrelay import target as target_lib
from torrelay import tor
from torrelay import util

Route = probes.Route
Target = target_lib.Target

_LATENCY_WEIGHT = 0.5  # KiB/s of throughput worth 1 ms of latency.


@dataclasses.dataclass(frozen=True)
class BenchOptions:
    """How to run a benchmark.

    Attributes:
        instances: Fresh Tor instances to race (ignored with pins).
        size_mib: Maximum MiB per throughput test.
        rtt_samples: SSH echo round trips to time.
        parallel_throughput: Overlap throughput tests across routes.
        bootstrap_timeout: Seconds allowed for each Tor to start.
        guards: One pinned guard fingerprint per instance.
        exits: One pinned exit fingerprint per instance.
        connect_only: Only test connectivity and handshake.
        direct: Add a no-Tor baseline route.
    """

    instances: int = 6
    size_mib: int = 4
    rtt_samples: int = 10
    parallel_throughput: bool = False
    bootstrap_timeout: float = 180
    guards: tuple[str, ...] = ()
    exits: tuple[str, ...] = ()
    connect_only: bool = False
    direct: bool = False


@dataclasses.dataclass(frozen=True)
class Result:
    """Measurements for one route; fields fill in as steps succeed.

    Attributes:
        name: Route name.
        bootstrap_s: Seconds the route's Tor took to start.
        connect_s: Seconds to open the stream (includes circuit setup).
        handshake_s: Seconds for the TLS handshake or SSH banner.
        ttfb_ms: HTTP time to first byte.
        login_s: SSH login time.
        rtt_ms: Median SSH echo round trip.
        jitter_ms: Standard deviation of the round trips.
        down_kib: Download speed in KiB/s.
        up_kib: Upload speed in KiB/s.
        hops: Relays that carried the stream.
        detail: Protocol detail, e.g. ``HTTP 200 OK``.
        pinned: Description of relays pinned for this route.
        error: Why the route failed, if it did.
    """

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
    hops: tuple[tor.Hop, ...] = ()
    detail: str = ""
    pinned: str = ""
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        """Whether the route connected and no step failed."""
        return self.error is None and self.connect_s is not None

    @property
    def latency_ms(self) -> Optional[float]:
        """Best available latency signal: rtt, else ttfb, else setup time."""
        if self.rtt_ms is not None:
            return self.rtt_ms
        if self.ttfb_ms is not None:
            return self.ttfb_ms
        if self.connect_s is None:
            return None
        return (self.connect_s + (self.handshake_s or 0)) * 1000


@dataclasses.dataclass(frozen=True)
class InstanceSpec:
    """What to start for one fresh Tor instance.

    Attributes:
        name: Display name, e.g. ``tor0``.
        torrc_lines: Extra torrc lines (pins).
        label: Human-readable description of the pins.
    """

    name: str
    torrc_lines: tuple[str, ...] = ()
    label: str = ""


Step = tuple[str, Callable[[], dict]]
Launch = tuple[InstanceSpec, Optional[tor.TorNode], Optional[str]]

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
    """Summarises a step's measurements for the progress log.

    Args:
        fields: Fields returned by a probe.

    Returns:
        A one-line summary in a stable order.
    """
    parts = [fmt.format(fields[key]) for key, fmt in _FIELD_FORMATS.items()
             if fields.get(key) is not None]
    if fields.get("hops"):
        parts.append("path " + tor.format_path(fields["hops"]))
    return "  ".join(parts)


# --------------------------------------------------------------------------
# Step combinators
# --------------------------------------------------------------------------

def attempt(result: Result, step: Step) -> Result:
    """Runs one step unless an earlier step failed.

    Errors are captured per route so one bad circuit never aborts the
    whole benchmark.

    Args:
        result: Measurements so far.
        step: ``(label, fn)`` where ``fn`` returns new fields.

    Returns:
        ``result`` updated with the step's fields or its error.
    """
    if result.error:
        return result
    label, fn = step
    try:
        fields = fn()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # Any failure (socket, ssl, ssh, http) is a result, not a crash.
        message = str(exc) or type(exc).__name__
        util.log(f"[{result.name}] {label} failed: {message}")
        return dataclasses.replace(result, error=f"{label}: {message}")
    util.log(f"[{result.name}] {label}: {describe(fields)}")
    return dataclasses.replace(result, **fields)


def run_steps(result: Result, steps: Iterable[Step]) -> Result:
    """Folds steps over a result, short-circuiting after a failure.

    Args:
        result: Starting measurements.
        steps: Steps in order.

    Returns:
        The final result.
    """
    return functools.reduce(attempt, steps, result)


def latency_plan(target: Target, opts: BenchOptions,
                 route: Route) -> tuple[Step, ...]:
    """Chooses the latency-phase steps for a target's protocol.

    Args:
        target: Destination.
        opts: Benchmark options.
        route: Route the steps will use.

    Returns:
        Steps that are safe to run on all routes at once.
    """
    connect = (("connect", functools.partial(probes.probe, target, route)),)
    if target.scheme != "ssh" or opts.connect_only:
        return connect
    return (*connect,
            ("login", functools.partial(probes.ssh_login, target, route)),
            ("rtt", functools.partial(probes.ssh_rtt, target, route,
                                      opts.rtt_samples)))


def throughput_plan(target: Target, opts: BenchOptions,
                    route: Route) -> tuple[Step, ...]:
    """Chooses the throughput-phase steps for a target's protocol.

    Args:
        target: Destination.
        opts: Benchmark options.
        route: Route the steps will use.

    Returns:
        Bandwidth steps, or ``()`` if the protocol has none.
    """
    if opts.connect_only:
        return ()
    if target.scheme == "ssh":
        return (
            ("download", functools.partial(probes.ssh_download, target,
                                           route, opts.size_mib)),
            ("upload", functools.partial(probes.ssh_upload, target, route,
                                         opts.size_mib)),
        )
    if target.is_http:
        return (("download", functools.partial(
            probes.http_download, target, route, opts.size_mib)),)
    return ()


# --------------------------------------------------------------------------
# Ranking
# --------------------------------------------------------------------------

def score(result: Result) -> float:
    """Scores a result so better routes sort first.

    Mean throughput minus a latency penalty; failures sort last.

    Args:
        result: Measurements for one route.

    Returns:
        Higher is better.
    """
    if not result.ok:
        return float("-inf")
    speeds = [v for v in (result.down_kib, result.up_kib) if v is not None]
    throughput = statistics.mean(speeds) if speeds else 0.0
    return throughput - _LATENCY_WEIGHT * (result.latency_ms or 0.0)


def rank(results: Iterable[Result]) -> list[Result]:
    """Orders results best first.

    Args:
        results: Results to order.

    Returns:
        Sorted results.
    """
    return sorted(results, key=score, reverse=True)


# --------------------------------------------------------------------------
# Phases
# --------------------------------------------------------------------------

def _fresh_result(route: Route) -> Result:
    """Creates the empty result a route's measurements start from.

    Args:
        route: The route being measured.

    Returns:
        A result carrying only the route's identity.
    """
    return Result(route.name, bootstrap_s=route.bootstrap_s,
                  pinned=route.pinned)


def latency_phase(target: Target, opts: BenchOptions,
                  routes: Sequence[Route]) -> list[Result]:
    """Tests connectivity and latency on every route simultaneously.

    Args:
        target: Destination.
        opts: Benchmark options.
        routes: Routes to test.

    Returns:
        One result per route, in route order.
    """
    plural = "route" if len(routes) == 1 else "routes simultaneously"
    util.log(f"\n== Connectivity & latency: {target.url} "
             f"({len(routes)} {plural}) ==")
    return util.pmap(lambda route: run_steps(
        _fresh_result(route), latency_plan(target, opts, route)), routes)


def throughput_phase(target: Target, opts: BenchOptions,
                     routes: Sequence[Route],
                     results: Sequence[Result]) -> list[Result]:
    """Measures bandwidth, sequentially unless asked to overlap.

    Sequential runs stop routes from competing for the same uplink, which
    would otherwise make every route look slow.

    Args:
        target: Destination.
        opts: Benchmark options.
        routes: Routes, aligned with ``results``.
        results: Latency-phase results.

    Returns:
        Updated results, in route order.
    """
    if any(throughput_plan(target, opts, route) for route in routes):
        mode = "parallel" if opts.parallel_throughput else "sequential"
        util.log(f"\n== Throughput ({mode}, up to {opts.size_mib} MiB) ==")

    def measure_one(pair: tuple[Route, Result]) -> Result:
        """Runs the throughput steps for one route."""
        route, result = pair
        return run_steps(result, throughput_plan(target, opts, route))

    pairs = list(zip(routes, results))
    if opts.parallel_throughput:
        return util.pmap(measure_one, pairs)
    return list(map(measure_one, pairs))


def measure(target: Target, opts: BenchOptions, routes: Sequence[Route],
            failed: Sequence[Result] = ()) -> list[Result]:
    """Runs both phases over ``routes`` and ranks the outcome.

    Args:
        target: Destination.
        opts: Benchmark options.
        routes: Routes to test.
        failed: Results for routes that never started (ranked last).

    Returns:
        All results, best first.
    """
    latency = latency_phase(target, opts, routes)
    final = throughput_phase(target, opts, routes, latency)
    return rank([*final, *failed])


def baseline_routes(opts: BenchOptions) -> list[Route]:
    """Returns the optional no-Tor route used for comparison.

    Args:
        opts: Benchmark options.

    Returns:
        ``[direct_route()]`` with ``--direct``, else ``[]``.
    """
    return [probes.direct_route()] if opts.direct else []


# --------------------------------------------------------------------------
# Fresh Tor instances
# --------------------------------------------------------------------------

def _pin_lines(guard: Optional[str], exit_: Optional[str]) -> tuple[str, ...]:
    """Renders torrc pin lines for one instance.

    Args:
        guard: Guard fingerprint or None.
        exit_: Exit fingerprint or None.

    Returns:
        ``EntryNodes``/``ExitNodes`` lines.
    """
    return ((f"EntryNodes ${guard}",) if guard else ()) + (
        (f"ExitNodes ${exit_}",) if exit_ else ())


def _pin_label(guard: Optional[str], exit_: Optional[str]) -> str:
    """Describes one instance's pins for logs and tables.

    Args:
        guard: Guard fingerprint or None.
        exit_: Exit fingerprint or None.

    Returns:
        e.g. ``guard=0824D7C7 exit=CC7643FA``.
    """
    return " ".join(filter(None, (
        f"guard={guard[:8]}" if guard else "",
        f"exit={exit_[:8]}" if exit_ else "")))


def _nth(items: Sequence[str], index: int) -> Optional[str]:
    """Returns ``items[index]`` or None past the end.

    Args:
        items: Sequence to index.
        index: Position.

    Returns:
        The item or None.
    """
    return items[index] if index < len(items) else None


def instance_specs(opts: BenchOptions) -> tuple[InstanceSpec, ...]:
    """Decides how many Tor instances to start and what each pins.

    With ``--guard``/``--exit``, there is one instance per pinned relay;
    otherwise ``opts.instances`` unpinned ones.

    Args:
        opts: Benchmark options.

    Returns:
        One spec per instance.
    """
    count = max(len(opts.guards), len(opts.exits)) or opts.instances

    def spec(index: int) -> InstanceSpec:
        """Builds the spec for instance ``index``."""
        guard, exit_ = _nth(opts.guards, index), _nth(opts.exits, index)
        return InstanceSpec(f"tor{index}", _pin_lines(guard, exit_),
                            _pin_label(guard, exit_))

    return tuple(map(spec, range(count)))


def _launch(base_dir: str, timeout: float, spec: InstanceSpec) -> Launch:
    """Starts one instance, capturing failure instead of raising.

    Args:
        base_dir: Parent directory for the instance's data.
        timeout: Bootstrap timeout in seconds.
        spec: What to start.

    Returns:
        ``(spec, node, None)`` on success, ``(spec, None, error)`` otherwise.
    """
    try:
        node = tor.launch_ephemeral(spec.name,
                                    os.path.join(base_dir, spec.name),
                                    timeout, spec.torrc_lines)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # A Tor that won't start is reported as a failed route.
        util.log(f"[{spec.name}] {exc}")
        return spec, None, str(exc)
    suffix = f" ({spec.label})" if spec.label else ""
    util.log(f"[{spec.name}] bootstrapped in {node.bootstrap_s:.1f}s{suffix}")
    return spec, node, None


def _failed_result(launch: Launch) -> Result:
    """Turns a failed launch into a ranked-last result.

    Args:
        launch: A launch outcome with an error.

    Returns:
        A failed result for the table.
    """
    spec, _, error = launch
    return Result(spec.name, pinned=spec.label, error=f"bootstrap: {error}")


def run(target: Target, opts: BenchOptions) -> list[Result]:
    """Races fresh Tor instances (plus optional baseline) to a target.

    Instances are always stopped and their data removed, even on Ctrl-C.

    Args:
        target: Destination.
        opts: Benchmark options.

    Returns:
        Results, best first.
    """
    base_dir = tempfile.mkdtemp(prefix="torrelay_")
    specs = instance_specs(opts)
    launches: list[Launch] = []
    try:
        util.log(f"Launching {len(specs)} Tor instances in parallel ...")
        launches = util.pmap(functools.partial(
            _launch, base_dir, opts.bootstrap_timeout), specs)
        routes = [probes.tor_route(node, spec.label)
                  for spec, node, _ in launches if node]
        failed = [_failed_result(item) for item in launches if not item[1]]
        return measure(target, opts, [*routes, *baseline_routes(opts)],
                       failed)
    finally:
        for _, node, _ in launches:
            if node:
                tor.stop(node.proc)
        shutil.rmtree(base_dir, ignore_errors=True)


def check(target: Target, opts: BenchOptions,
          socks_ports: Sequence[int]) -> list[Result]:
    """Measures through already-running SOCKS proxies (no bootstrap).

    Args:
        target: Destination.
        opts: Benchmark options.
        socks_ports: Proxies to test, e.g. ``(9050,)``.

    Returns:
        Results, best first.
    """
    routes = [*map(probes.socks_route, socks_ports), *baseline_routes(opts)]
    return measure(target, opts, routes)
