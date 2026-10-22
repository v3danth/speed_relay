"""Race a target across many routes (Tor circuits, SOCKS ports, direct).

Every route runs its own pipeline, all routes at once:

1. start: bootstrap a fresh Tor (one at a time unless asked to overlap);
2. latency: connectivity, handshake, rtt, as soon as the route is up;
3. throughput: one route at a time by default, so routes don't compete.

Each stage folds named steps over an immutable Result; the first failing
step records its error and the remaining steps are skipped. An Observer
sees every stage change, which is what drives the live dashboard.
"""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import os
import shutil
import statistics
import tempfile
import threading
from typing import Callable, ContextManager, Iterable, Optional, Sequence

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
        parallel_bootstrap: Start all Tor instances at once.
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
    parallel_bootstrap: bool = False
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


@dataclasses.dataclass(frozen=True)
class Lane:
    """One route still to be brought up and measured.

    Attributes:
        name: Display name, e.g. ``tor0``.
        start: Brings the route up (e.g. bootstraps Tor); may raise.
        pinned: Description of relays pinned for this route.
    """

    name: str
    start: Callable[[], Route]
    pinned: str = ""


class Observer:
    """Receives live progress from a run; this base class ignores it.

    Plain runs report through the log; the live dashboard subclasses this.
    Methods are called from many threads at once.
    """

    def begin(self, names: Sequence[str]) -> None:
        """Announces the routes about to run, in display order.

        Args:
            names: Route names.
        """

    def stage(self, name: str, stage: str,
              percent: Optional[int] = None) -> None:
        """Reports that a route moved to a new stage.

        Args:
            name: Route name.
            stage: What it is doing, e.g. ``connect`` or ``done``.
            percent: Progress through the stage, when known.
        """

    def update(self, result: Result) -> None:
        """Reports a route's latest measurements.

        Args:
            result: The route's result so far.
        """


QUIET = Observer()
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

def attempt(result: Result, step: Step,
            observer: Observer = QUIET) -> Result:
    """Runs one step unless an earlier step failed.

    Errors are captured per route so one bad circuit never aborts the
    whole benchmark.

    Args:
        result: Measurements so far.
        step: ``(label, fn)`` where ``fn`` returns new fields.
        observer: Told when the step starts and what it measured.

    Returns:
        ``result`` updated with the step's fields or its error.
    """
    if result.error:
        return result
    label, fn = step
    observer.stage(result.name, label)
    try:
        fields = fn()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # Any failure (socket, ssl, ssh, http) is a result, not a crash.
        message = str(exc) or type(exc).__name__
        util.log(f"[{result.name}] {label} failed: {message}")
        updated = dataclasses.replace(result, error=f"{label}: {message}")
    else:
        util.log(f"[{result.name}] {label}: {describe(fields)}")
        updated = dataclasses.replace(result, **fields)
    observer.update(updated)
    return updated


def run_steps(result: Result, steps: Iterable[Step],
              observer: Observer = QUIET) -> Result:
    """Folds steps over a result, short-circuiting after a failure.

    Args:
        result: Starting measurements.
        steps: Steps in order.
        observer: Receives progress from each step.

    Returns:
        The final result.
    """
    return functools.reduce(
        lambda done, step: attempt(done, step, observer), steps, result)


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

def _gate(parallel: bool) -> ContextManager:
    """Returns a context that serialises a stage unless it may overlap.

    Args:
        parallel: Whether lanes may run the stage at the same time.

    Returns:
        A no-op context, or a lock shared by all lanes.
    """
    return contextlib.nullcontext() if parallel else threading.Lock()


def _ready(route: Route) -> Lane:
    """Wraps a route that is already up (SOCKS port, direct) as a lane.

    Args:
        route: The route.

    Returns:
        A lane whose start returns ``route`` immediately.
    """
    return Lane(route.name, lambda: route, route.pinned)


def race(target: Target, opts: BenchOptions, lanes: Sequence[Lane],
         observer: Observer = QUIET) -> list[Result]:
    """Runs every lane through start, latency and throughput, then ranks.

    Lanes are pipelined: each is measured as soon as it is up, so fast
    starters never wait for slow ones. Throughput tests still take turns
    unless asked to overlap, so routes don't compete for the uplink.

    Args:
        target: Destination.
        opts: Benchmark options.
        lanes: Routes to bring up and measure.
        observer: Receives live progress.

    Returns:
        All results, best first.
    """
    mode = "parallel" if opts.parallel_throughput else "one at a time"
    util.log(f"== {target.url}: {len(lanes)} routes; each is tested as "
             f"soon as it is up (speed tests {mode}) ==")
    observer.begin([lane.name for lane in lanes])
    throughput_gate = _gate(opts.parallel_throughput)

    def one(lane: Lane) -> Result:
        """Takes one lane from start to its final result."""
        result = Result(lane.name, pinned=lane.pinned)
        try:
            route = lane.start()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            # A route that won't come up is reported, not raised.
            util.log(f"[{lane.name}] {exc}")
            result = dataclasses.replace(result, error=f"bootstrap: {exc}")
        else:
            result = run_steps(
                dataclasses.replace(result, bootstrap_s=route.bootstrap_s),
                latency_plan(target, opts, route), observer)
            steps = throughput_plan(target, opts, route)
            if steps and result.ok:
                observer.stage(lane.name, "waiting to speed test")
                with throughput_gate:
                    result = run_steps(result, steps, observer)
        observer.update(result)
        observer.stage(lane.name, "done" if result.ok else "failed")
        return result

    return rank(util.pmap(one, lanes))


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


def _tor_lane(spec: InstanceSpec, base_dir: str, opts: BenchOptions,
              gate: ContextManager, nodes: list[tor.TorNode],
              observer: Observer) -> Lane:
    """Builds the lane that bootstraps one fresh Tor instance.

    Args:
        spec: What to start.
        base_dir: Parent directory for the instance's data.
        opts: Benchmark options (bootstrap timeout).
        gate: Held while bootstrapping, to take turns unless parallel.
        nodes: Started instances are added here so they can be stopped.
        observer: Receives bootstrap progress.

    Returns:
        The lane.
    """
    def progress(percent: int, summary: str) -> None:
        """Forwards one Tor bootstrap log line to the observer."""
        observer.stage(spec.name, f"bootstrap: {summary}", percent)

    def start() -> Route:
        """Bootstraps the instance and returns a route through it."""
        observer.stage(spec.name, "queued")
        with gate:
            observer.stage(spec.name, "bootstrap", 0)
            node = tor.launch_ephemeral(
                spec.name, os.path.join(base_dir, spec.name),
                opts.bootstrap_timeout, spec.torrc_lines, progress)
        nodes.append(node)
        suffix = f" ({spec.label})" if spec.label else ""
        util.log(f"[{spec.name}] bootstrapped in {node.bootstrap_s:.1f}s"
                 f"{suffix}")
        return probes.tor_route(node, spec.label)

    return Lane(spec.name, start, spec.label)


def run(target: Target, opts: BenchOptions,
        observer: Observer = QUIET) -> list[Result]:
    """Races fresh Tor instances (plus optional baseline) to a target.

    Instances are always stopped and their data removed, even on Ctrl-C.

    Args:
        target: Destination.
        opts: Benchmark options.
        observer: Receives live progress.

    Returns:
        Results, best first.
    """
    base_dir = tempfile.mkdtemp(prefix="torrelay_")
    nodes: list[tor.TorNode] = []
    # Taking turns keeps instances from competing for bandwidth while
    # fetching the consensus; the first one up is tested meanwhile.
    gate = _gate(opts.parallel_bootstrap)
    lanes = [_tor_lane(spec, base_dir, opts, gate, nodes, observer)
             for spec in instance_specs(opts)]
    try:
        return race(target, opts,
                    [*lanes, *map(_ready, baseline_routes(opts))], observer)
    finally:
        for node in nodes:
            tor.stop(node.proc)
        shutil.rmtree(base_dir, ignore_errors=True)


def check(target: Target, opts: BenchOptions, socks_ports: Sequence[int],
          observer: Observer = QUIET) -> list[Result]:
    """Measures through already-running SOCKS proxies (no bootstrap).

    Args:
        target: Destination.
        opts: Benchmark options.
        socks_ports: Proxies to test, e.g. ``(9050,)``.
        observer: Receives live progress.

    Returns:
        Results, best first.
    """
    routes = [*map(probes.socks_route, socks_ports), *baseline_routes(opts)]
    return race(target, opts, list(map(_ready, routes)), observer)
