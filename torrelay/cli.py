"""Command-line interface.

Targets are URLs (tcp://, tls://, ssh://, http://, https://) for .onion or
clearnet hosts, or the name of a saved profile.

    torrelay check https://example.com                 # can I connect?
    torrelay bench https://example.com/10MB.bin -n 6   # race 6 circuits
    torrelay init pi ssh://luffy@XXXX.onion --key ~/.ssh/id_ed25519
    torrelay bench pi --apply 2                        # pin top 2 guards
    torrelay up pi && torrelay ssh-config pi --alias pi-fast
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import json
import os
import sys
from typing import Callable, ContextManager, Optional, Sequence

import torrelay
from torrelay import bench
from torrelay import daemon
from torrelay import live
from torrelay import profile as profile_lib
from torrelay import proxy
from torrelay import report
from torrelay import target as target_lib
from torrelay import tor
from torrelay import util

Profile = profile_lib.Profile
Target = target_lib.Target
Pins = tuple[Optional[tuple[str, ...]], Optional[tuple[str, ...]]]

_SYSTEM_TOR_PORT = 9050
_EXIT_CODE_USAGE = 2
_EXIT_CODE_INTERRUPTED = 130


class CliError(Exception):
    """A user-facing error, printed without a traceback."""


# --------------------------------------------------------------------------
# Shared helpers
# --------------------------------------------------------------------------

def find_profile(spec: str) -> Optional[Profile]:
    """Interprets a target argument as a profile name, if it is one.

    Args:
        spec: A profile name or URL.

    Returns:
        The saved profile, or None if ``spec`` is not one.
    """
    try:
        return profile_lib.load(spec) if profile_lib.exists(spec) else None
    except ValueError:  # Not a valid profile name, so it must be a URL.
        return None


def _overrides(ns: argparse.Namespace) -> dict:
    """Collects target fields given explicitly on the command line.

    Args:
        ns: Parsed arguments.

    Returns:
        Target field overrides, omitting options that were not given.
    """
    candidates = {
        "user": ns.user,
        "key": os.path.expanduser(ns.key) if ns.key else None,
        "ssh_options": tuple(ns.ssh_option) if ns.ssh_option else None,
        "insecure": ns.insecure or None,
    }
    return {key: value for key, value in candidates.items()
            if value is not None}


def resolve(spec: str,
            ns: argparse.Namespace) -> tuple[Target, Optional[Profile]]:
    """Turns a target argument into a Target, applying CLI overrides.

    Args:
        spec: A profile name or URL.
        ns: Parsed arguments.

    Returns:
        The target, and the profile it came from (if any).
    """
    profile = find_profile(spec)
    target = profile.target if profile else target_lib.parse_target(spec)
    return dataclasses.replace(target, **_overrides(ns)), profile


def require_exits_possible(target: Target) -> None:
    """Rejects exit pinning for onion targets, which have no exits.

    Args:
        target: The destination.

    Raises:
        CliError: For onion targets.
    """
    if target.is_onion:
        raise CliError("onion circuits have no exit relay to pin")


def require_direct_possible(target: Target, direct: bool) -> None:
    """Rejects a no-Tor baseline for onions, which only Tor can reach.

    Args:
        target: The destination.
        direct: Whether ``--direct`` was given.

    Raises:
        CliError: For onion targets with ``--direct``.
    """
    if direct and target.is_onion:
        raise CliError("--direct cannot reach .onion addresses")


def require_profile(profile: Optional[Profile], flag: str) -> Profile:
    """Ensures an option that saves state was used with a profile.

    Args:
        profile: The resolved profile, if any.
        flag: The option name, for the error message.

    Returns:
        The profile.

    Raises:
        CliError: If there is no profile.
    """
    if profile is None:
        raise CliError(f"{flag} needs a profile (torrelay init)")
    return profile


def with_pins(profile: Profile, guards: Optional[Sequence[str]],
              exits: Optional[Sequence[str]]) -> Profile:
    """Returns a copy of a profile with new pins (None keeps current).

    Args:
        profile: The profile.
        guards: New guard fingerprints, or None.
        exits: New exit fingerprints, or None.

    Returns:
        The updated profile.
    """
    return dataclasses.replace(
        profile,
        pinned=profile.pinned if guards is None else tuple(guards),
        pinned_exits=profile.pinned_exits if exits is None else tuple(exits))


def _join_or(items: Sequence[str], empty: str = "any") -> str:
    """Joins items for display, with a placeholder when there are none.

    Args:
        items: Values to show.
        empty: Text to show for an empty sequence.

    Returns:
        Comma-separated items, or ``empty``.
    """
    return ", ".join(items) or empty


def _log_pins(profile: Profile, reloaded: bool) -> None:
    """Reports the pins now in force and whether Tor picked them up.

    Args:
        profile: The updated profile.
        reloaded: Whether a running Tor was reloaded.
    """
    when = "[reloaded]" if reloaded else "[takes effect on: up]"
    util.log(f"{profile.name}: guards -> {_join_or(profile.pinned)}")
    util.log(f"{profile.name}: exits  -> {_join_or(profile.pinned_exits)}"
             f"  {when}")


def pin(profile: Profile, guards: Optional[Sequence[str]] = None,
        exits: Optional[Sequence[str]] = None) -> Profile:
    """Persists pins and hot-reloads the dedicated Tor if it is running.

    Args:
        profile: The profile.
        guards: New guard fingerprints, or None to keep.
        exits: New exit fingerprints, or None to keep.

    Returns:
        The saved profile.
    """
    updated = profile_lib.save(with_pins(profile, guards, exits))
    profile_lib.write_tor_files(updated)
    _log_pins(updated, daemon.reload(updated))
    return updated


def pins_from(rows: Sequence[dict], target: Target, top: int,
              with_exits: bool) -> Pins:
    """Chooses relays to pin from ranked benchmark rows.

    Args:
        rows: Serialised results, best first.
        target: The benchmarked destination.
        top: How many relays of each kind.
        with_exits: Whether to pin exits too.

    Returns:
        ``(guards, exits)``; exits is None when not requested.

    Raises:
        CliError: If nothing succeeded or exits are impossible.
    """
    if with_exits:
        require_exits_possible(target)
    guards = report.top_relays(rows, top)
    if not guards:
        raise CliError("no successful circuits; nothing pinned")
    if not with_exits:
        return guards, None
    return guards, report.top_relays(rows, top, report.EXIT_KEY)


def emit(results: Sequence[bench.Result], target: Target,
         profile: Optional[Profile], as_json: bool) -> list[dict]:
    """Prints results and, for profiles, saves them for ``apply``.

    Args:
        results: Ranked results.
        target: The benchmarked destination.
        profile: Profile to save results to, if any.
        as_json: Print JSON instead of a table.

    Returns:
        The serialised rows.
    """
    rows = [report.to_dict(result, target) for result in results]
    print(json.dumps(rows, indent=2) if as_json
          else "\n" + report.format_table(results))
    if profile:
        saved = profile_lib.save_results(
            profile, {"target": target.url, "results": rows})
        util.log(f"\nresults saved to {saved}")
    return rows


def _fingerprints(values: Optional[Sequence[str]]) -> tuple[str, ...]:
    """Normalises fingerprints given on the command line.

    Args:
        values: Raw values, or None.

    Returns:
        Canonical fingerprints.
    """
    return tuple(map(tor.normalize_fingerprint, values or ()))


def bench_options(ns: argparse.Namespace, **overrides) -> bench.BenchOptions:
    """Builds benchmark options from ``bench`` or ``check`` arguments.

    Args:
        ns: Parsed arguments (``check`` lacks some ``bench`` options).
        **overrides: Options to force.

    Returns:
        The options.
    """
    return bench.BenchOptions(**{
        "instances": getattr(ns, "instances", 1),
        "size_mib": ns.size,
        "rtt_samples": ns.rtt_samples,
        "parallel_throughput": getattr(ns, "parallel_throughput", False),
        "parallel_bootstrap": getattr(ns, "parallel_bootstrap", False),
        "bootstrap_timeout": getattr(ns, "bootstrap_timeout", 180),
        "guards": _fingerprints(getattr(ns, "guard", None)),
        "exits": _fingerprints(getattr(ns, "exit", None)),
        "connect_only": ns.connect_only,
        "direct": ns.direct,
        **overrides,
    })


def exit_status(results: Sequence[bench.Result]) -> int:
    """Maps results to a process exit status: 0 if anything connected.

    Args:
        results: Benchmark results.

    Returns:
        0 or 1.
    """
    return 0 if any(result.ok for result in results) else 1


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_init(ns: argparse.Namespace) -> int:
    """Implements ``torrelay init``: save a target as a profile.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    if profile_lib.exists(ns.name) and not ns.force:
        raise CliError(f"profile {ns.name!r} exists (use --force)")
    target, _ = resolve(ns.target, ns)
    others = [p for p in profile_lib.list_all() if p.name != ns.name]
    socks, ctrl = ((ns.socks_port, ns.socks_port + 1) if ns.socks_port
                   else profile_lib.next_ports(others))
    fallbacks = tuple(ns.fallback or profile_lib.DEFAULT_FALLBACK_PORTS)
    created = profile_lib.save(profile_lib.from_target(
        ns.name, target, socks_port=socks, ctrl_port=ctrl,
        fallback_ports=fallbacks))
    profile_lib.write_tor_files(created)
    print(f"created profile {created.name!r} -> {target.url}")
    print(f"  dedicated tor: socks :{socks}  control :{ctrl}  "
          f"fallback {list(created.fallback_ports)}")
    return 0


def cmd_list(ns: argparse.Namespace) -> int:
    """Implements ``torrelay list``: one line per profile.

    Args:
        ns: Parsed arguments (unused).

    Returns:
        Exit status.
    """
    del ns  # Unused; all commands share one signature.
    profiles = profile_lib.list_all()
    if not profiles:
        print("no profiles (run: torrelay init NAME URL)")
    for p in profiles:
        state = "running" if daemon.read_pid(p) else "stopped"
        print(f"{p.name:<12} {state:<8} :{p.socks_port:<6} "
              f"guards={len(p.pinned)} exits={len(p.pinned_exits)}  "
              f"{p.target.url}")
    return 0


def watch(ns: argparse.Namespace, command: str,
          target: Target) -> ContextManager[bench.Observer]:
    """Chooses how to show a run's progress: live view or plain log.

    Args:
        ns: Parsed arguments.
        command: Command name, for the view's title.
        target: The destination being measured.

    Returns:
        A context yielding the run's observer.
    """
    if ns.no_live or not live.wanted():
        return contextlib.nullcontext(bench.QUIET)
    return live.Dashboard(f"torrelay {command}  {target.url}")


def cmd_bench(ns: argparse.Namespace) -> int:
    """Implements ``torrelay bench``: race fresh circuits, optionally pin.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    target, profile = resolve(ns.target, ns)
    require_direct_possible(target, ns.direct)
    if ns.apply:
        require_profile(profile, "--apply")
    with watch(ns, "bench", target) as observer:
        results = bench.run(target, bench_options(ns), observer)
    rows = emit(results, target, profile, ns.json)
    if ns.apply:
        pin(profile, *pins_from(rows, target, ns.apply, ns.exits))
    return exit_status(results)


def cmd_check(ns: argparse.Namespace) -> int:
    """Implements ``torrelay check``: test via already-running Tor.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    target, profile = resolve(ns.target, ns)
    require_direct_possible(target, ns.direct)
    default_ports = profile.socks_chain if profile else (_SYSTEM_TOR_PORT,)
    ports = tuple(ns.socks or ()) or default_ports
    with watch(ns, "check", target) as observer:
        results = bench.check(
            target, bench_options(ns, connect_only=not ns.full), ports,
            observer)
    emit(results, target, None, ns.json)
    return exit_status(results)


def cmd_apply(ns: argparse.Namespace) -> int:
    """Implements ``torrelay apply``: pin from the last saved benchmark.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    profile = profile_lib.load(ns.profile)
    rows = profile_lib.load_results(profile)["results"]
    pin(profile, *pins_from(rows, profile.target, ns.top, ns.exits))
    return 0


def cmd_pin(ns: argparse.Namespace) -> int:
    """Implements ``torrelay pin``: pin relays by fingerprint.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    profile = profile_lib.load(ns.profile)
    if ns.clear:
        pin(profile, (), ())
        return 0
    if not ns.fingerprint and not ns.exit:
        raise CliError("give guard fingerprints, --exit FP, or --clear")
    if ns.exit:
        require_exits_possible(profile.target)
    pin(profile, _fingerprints(ns.fingerprint) or None,
        _fingerprints(ns.exit) or None)
    return 0


def require_not_launchd(profile: Profile) -> None:
    """Stops ``up``/``down`` from fighting launchd over the same Tor.

    Args:
        profile: The profile.

    Raises:
        CliError: If launchd manages this profile.
    """
    if daemon.service_installed(profile):
        raise CliError("managed by launchd; use: torrelay service "
                       f"uninstall {profile.name}")


def cmd_up(ns: argparse.Namespace) -> int:
    """Implements ``torrelay up``: start the dedicated Tor.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    profile = profile_lib.load(ns.profile)
    require_not_launchd(profile)
    pid = daemon.start(profile, ns.timeout)
    print(f"{profile.name}: up (pid {pid}) socks 127.0.0.1:"
          f"{profile.socks_port}")
    return 0


def cmd_down(ns: argparse.Namespace) -> int:
    """Implements ``torrelay down``: stop the dedicated Tor.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    profile = profile_lib.load(ns.profile)
    require_not_launchd(profile)
    state = "stopped" if daemon.stop(profile) else "was not running"
    print(f"{profile.name}: {state}")
    return 0


def _static_status(profile: Profile, pid: Optional[int]) -> list[str]:
    """Describes a profile's configuration and process state.

    Args:
        profile: The profile.
        pid: Running Tor's PID, or None.

    Returns:
        Status lines.
    """
    state = f"running pid {pid}" if pid else "stopped"
    launchd = "  [launchd]" if daemon.service_installed(profile) else ""
    return [
        f"profile   {profile.name}  ({profile_lib.paths(profile).root})",
        f"target    {profile.target.url}",
        f"tor       {state}  socks :{profile.socks_port}{launchd}",
        f"guards    {_join_or(profile.pinned)}",
        f"exits     {_join_or(profile.pinned_exits)}",
    ]


def _live_status(profile: Profile) -> list[str]:
    """Asks the running Tor which relays it is actually using.

    Args:
        profile: The profile (its Tor must be running).

    Returns:
        Status lines; a single error line if the control port fails.
    """
    try:
        guards = tor.entry_guards(profile.control)
        hops = (tor.rendezvous_hops(profile.control)
                if profile.target.is_onion else ())
    except (OSError, RuntimeError) as exc:
        return [f"control   unavailable: {exc}"]
    in_use = _join_or([f"{guard.label} ({state})"
                       for guard, state in guards[:3]], empty="?")
    lines = [f"bootstrap {daemon.progress(profile)}%",
             f"in use    {in_use}"]
    if hops:
        lines.append(f"circuit   {tor.format_path(hops)}")
    return lines


def cmd_status(ns: argparse.Namespace) -> int:
    """Implements ``torrelay status``: configuration plus live state.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    profile = profile_lib.load(ns.profile)
    pid = daemon.read_pid(profile)
    lines = _static_status(profile, pid)
    if pid:
        lines += _live_status(profile)
    print("\n".join(lines))
    return 0


def ssh_config_options(p: Profile) -> list[tuple[str, str]]:
    """Lists ssh_config options that route a profile through torrelay.

    Connection sharing keeps one circuit warm so later sessions skip the
    slow onion circuit setup.

    Args:
        p: An ssh profile.

    Returns:
        ``(keyword, value)`` pairs.
    """
    identity = ([("IdentityFile", p.key), ("IdentitiesOnly", "yes")]
                if p.key else [])
    return [
        ("HostName", p.host),
        ("Port", str(p.port)),
        *([("User", p.user)] if p.user else []),
        *identity,
        ("ProxyCommand", proxy.proxy_command(profile=p.name)),
        ("ControlMaster", "auto"),
        ("ControlPath", "~/.ssh/cm-%C"),
        ("ControlPersist", "10m"),
        ("ServerAliveInterval", "30"),
        ("ServerAliveCountMax", "5"),
        *(tuple(option.split("=", 1)) for option in p.ssh_options),
    ]


def cmd_ssh_config(ns: argparse.Namespace) -> int:
    """Implements ``torrelay ssh-config``: print a Host block.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    p = profile_lib.load(ns.profile)
    if p.scheme != "ssh":
        raise CliError(f"profile is {p.scheme}://, not ssh; "
                       f"see: torrelay env {p.name}")
    print(f"# torrelay profile {p.name!r}: place above any 'Host *' block")
    print(f"Host {ns.alias or p.name}")
    print("\n".join(f"    {key} {value}"
                    for key, value in ssh_config_options(p)))
    return 0


def cmd_env(ns: argparse.Namespace) -> int:
    """Implements ``torrelay env``: proxy settings for any SOCKS tool.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    p = profile_lib.load(ns.profile)
    socks = f"127.0.0.1:{p.socks_port}"
    print(f"# Route tools through profile {p.name!r} (pinned Tor). "
          "socks5h = resolve DNS via Tor.")
    print(f"export ALL_PROXY=socks5h://{socks}")
    print(f"# e.g. curl --socks5-hostname {socks} {p.target.url}")
    return 0


def cmd_proxy(ns: argparse.Namespace) -> int:
    """Implements ``torrelay proxy``, the ssh ProxyCommand.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    profile = profile_lib.load(ns.profile) if ns.profile else None
    ports = tuple(ns.socks or ()) or (profile.socks_chain if profile else ())
    if not ports:
        raise CliError("give --profile or --socks")
    return proxy.run(ns.host, ns.port, ports, ns.timeout)


def cmd_service(ns: argparse.Namespace) -> int:
    """Implements ``torrelay service``: manage the launchd agent.

    Args:
        ns: Parsed arguments.

    Returns:
        Exit status.
    """
    profile = profile_lib.load(ns.profile)
    if ns.action == "install":
        path = daemon.install_service(profile)
        print(f"{profile.name}: launchd agent installed ({path}); "
              "starts at login, restarts on crash")
        return 0
    removed = daemon.uninstall_service(profile)
    print(f"{profile.name}: "
          + ("launchd agent removed" if removed else "not installed"))
    return 0


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

Handler = Callable[[argparse.Namespace], int]


def _add_target_args(parser: argparse.ArgumentParser) -> None:
    """Adds options that refine a target (credentials, TLS).

    Args:
        parser: Subcommand parser.
    """
    parser.add_argument("--user", help="ssh user (or user@ in the URL)")
    parser.add_argument("--key", help="ssh private key")
    parser.add_argument("-o", "--ssh-option", action="append",
                        metavar="KEY=VALUE",
                        help="extra ssh -o option (repeatable)")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS certificate verification")


def _add_measure_args(parser: argparse.ArgumentParser) -> None:
    """Adds options shared by ``check`` and ``bench``.

    Args:
        parser: Subcommand parser.
    """
    parser.add_argument("target", help="URL or profile name")
    _add_target_args(parser)
    parser.add_argument("--size", type=int, default=4,
                        help="max MiB per throughput test (default 4)")
    parser.add_argument("--rtt-samples", type=int, default=10)
    parser.add_argument("--direct", action="store_true",
                        help="add a no-Tor baseline (clearnet only)")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--no-live", action="store_true",
                        help="print a plain log instead of the live view")


def _add_check(sub: argparse._SubParsersAction) -> None:
    """Defines ``torrelay check``.

    Args:
        sub: Subparsers to add to.
    """
    p = _command(sub, "check", cmd_check,
                 "quick connectivity test via running Tor (no bootstrap)")
    _add_measure_args(p)
    p.add_argument("--socks", type=int, action="append",
                   help="SOCKS port(s) to test (default 9050 or profile's)")
    p.add_argument("--full", action="store_true",
                   help="also measure login/rtt/throughput")
    p.set_defaults(connect_only=True)


def _add_bench(sub: argparse._SubParsersAction) -> None:
    """Defines ``torrelay bench``.

    Args:
        sub: Subparsers to add to.
    """
    p = _command(sub, "bench", cmd_bench,
                 "race N fresh Tor circuits and rank them")
    _add_measure_args(p)
    p.add_argument("-n", "--instances", type=int, default=6)
    p.add_argument("--guard", action="append", metavar="FP",
                   help="test specific guard(s), one instance each")
    p.add_argument("--exit", action="append", metavar="FP",
                   help="test specific exit(s), one instance each")
    p.add_argument("--connect-only", action="store_true",
                   help="only test connectivity and handshake")
    p.add_argument("--parallel-throughput", action="store_true")
    p.add_argument("--parallel-bootstrap", action="store_true",
                   help="start all Tor instances at once")
    p.add_argument("--bootstrap-timeout", type=float, default=180)
    p.add_argument("--apply", type=int, metavar="N",
                   help="pin the top N relays into the profile")
    p.add_argument("--exits", action="store_true",
                   help="with --apply: also pin exits (clearnet)")


def _add_profile_commands(sub: argparse._SubParsersAction) -> None:
    """Defines commands that create or change profiles.

    Args:
        sub: Subparsers to add to.
    """
    p = _command(sub, "init", cmd_init, "save a target as a named profile")
    p.add_argument("name")
    p.add_argument("target", help="URL, e.g. ssh://user@host.onion")
    _add_target_args(p)
    p.add_argument("--socks-port", type=int,
                   help="dedicated SOCKS port (control = +1)")
    p.add_argument("--fallback", type=int, action="append",
                   help="fallback SOCKS port(s), default 9050")
    p.add_argument("--force", action="store_true")

    _command(sub, "list", cmd_list, "list profiles")

    p = _command(sub, "apply", cmd_apply,
                 "pin top relays from the last bench")
    p.add_argument("profile")
    p.add_argument("--top", type=int, default=2)
    p.add_argument("--exits", action="store_true",
                   help="also pin exits (clearnet)")

    p = _command(sub, "pin", cmd_pin, "pin specific relays by fingerprint")
    p.add_argument("profile")
    p.add_argument("fingerprint", nargs="*", help="guard fingerprints")
    p.add_argument("--exit", action="append", metavar="FP")
    p.add_argument("--clear", action="store_true")


def _add_runtime_commands(sub: argparse._SubParsersAction) -> None:
    """Defines commands that run or use a profile's dedicated Tor.

    Args:
        sub: Subparsers to add to.
    """
    p = _command(sub, "up", cmd_up, "start the profile's dedicated Tor")
    p.add_argument("profile")
    p.add_argument("--timeout", type=float, default=180)

    for name, handler, help_text in (
            ("down", cmd_down, "stop the profile's dedicated Tor"),
            ("status", cmd_status, "show Tor state and pinned relays"),
            ("env", cmd_env,
             "print proxy settings to route any tool via a profile")):
        _command(sub, name, handler, help_text).add_argument("profile")

    p = _command(sub, "ssh-config", cmd_ssh_config,
                 "print an ssh_config Host block (ssh profiles)")
    p.add_argument("profile")
    p.add_argument("--alias")

    p = _command(sub, "proxy", cmd_proxy,
                 "ProxyCommand with failover (ssh calls this)")
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("--profile")
    p.add_argument("--socks", type=int, action="append")
    p.add_argument("--timeout", type=float, default=120)

    p = _command(sub, "service", cmd_service, "manage the launchd agent")
    p.add_argument("action", choices=("install", "uninstall"))
    p.add_argument("profile")


def _command(sub: argparse._SubParsersAction, name: str, handler: Handler,
             help_text: str) -> argparse.ArgumentParser:
    """Registers a subcommand and the function that implements it.

    Args:
        sub: Subparsers to add to.
        name: Command name.
        handler: Implementation, called with the parsed arguments.
        help_text: One-line description.

    Returns:
        The subcommand's parser, for adding arguments.
    """
    parser = sub.add_parser(name, help=help_text, description=help_text)
    parser.set_defaults(handler=handler)
    return parser


def build_parser() -> argparse.ArgumentParser:
    """Builds the full argument parser.

    Returns:
        The top-level parser.
    """
    parser = argparse.ArgumentParser(
        prog="torrelay", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version",
                        version=f"torrelay {torrelay.__version__}")
    sub = parser.add_subparsers(dest="command", required=True,
                                metavar="COMMAND")
    _add_check(sub)
    _add_bench(sub)
    _add_profile_commands(sub)
    _add_runtime_commands(sub)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Runs the CLI; user errors print one line instead of a traceback.

    Args:
        argv: Arguments, defaulting to ``sys.argv[1:]``.

    Returns:
        Process exit status.
    """
    ns = build_parser().parse_args(argv)
    try:
        return ns.handler(ns)
    except (CliError, FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"torrelay: {exc}", file=sys.stderr)
        return _EXIT_CODE_USAGE
    except KeyboardInterrupt:
        return _EXIT_CODE_INTERRUPTED
