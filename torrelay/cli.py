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
import json
import os
import sys
from dataclasses import replace
from typing import Callable, Optional, Sequence

from torrelay import __version__, bench, daemon, report
from torrelay import profile as profiles
from torrelay import proxy
from torrelay.profile import Profile
from torrelay.target import Target, parse_target
from torrelay.tor import entry_guards, normalize_fingerprint, rendezvous_hops
from torrelay.util import log


class CliError(Exception):
    """User-facing error: printed without a traceback."""


# --------------------------------------------------------------------------
# Shared operations
# --------------------------------------------------------------------------

def find_profile(spec: str) -> Optional[Profile]:
    """The saved profile called ``spec``, or None if it isn't one."""
    try:
        exists = (profiles.profile_dir(spec) / "profile.json").exists()
    except ValueError:
        return None
    return profiles.load(spec) if exists else None


def resolve(spec: str,
            ns: argparse.Namespace) -> tuple[Target, Optional[Profile]]:
    """Target from a profile name or URL, with CLI overrides applied."""
    profile = find_profile(spec)
    target = profile.target if profile else parse_target(spec)
    overrides = {
        "user": ns.user,
        "key": os.path.expanduser(ns.key) if ns.key else None,
        "ssh_options": tuple(ns.ssh_option) if ns.ssh_option else None,
        "insecure": ns.insecure or None,
    }
    return replace(target, **{k: v for k, v in overrides.items()
                              if v is not None}), profile


def pin(profile: Profile, guards: Optional[Sequence[str]] = None,
        exits: Optional[Sequence[str]] = None) -> Profile:
    """Persist pins (None keeps current), regenerate torrc, hot-reload."""
    updated = profiles.save(replace(
        profile,
        pinned=profile.pinned if guards is None else tuple(guards),
        pinned_exits=profile.pinned_exits if exits is None else tuple(exits),
    ))
    profiles.write_tor_files(updated)
    reloaded = daemon.reload(updated)
    log(f"{updated.name}: guards -> {', '.join(updated.pinned) or 'any'}")
    log(f"{updated.name}: exits  -> {', '.join(updated.pinned_exits) or 'any'}"
        + ("  [reloaded]" if reloaded else "  [takes effect on: up]"))
    return updated


def emit(results: Sequence[bench.Result], target: Target,
         profile: Optional[Profile], as_json: bool) -> list[dict]:
    rows = [report.to_dict(r, target) for r in results]
    if as_json:
        print(json.dumps(rows, indent=2))
    else:
        print("\n" + report.format_table(results))
    if profile:
        saved = profiles.save_results(profile, {"target": target.url,
                                                "results": rows})
        log(f"\nresults saved to {saved}")
    return rows


def pins_from(rows: Sequence[dict], target: Target, top: int,
              with_exits: bool) -> tuple[tuple[str, ...],
                                         Optional[tuple[str, ...]]]:
    if with_exits and target.is_onion:
        raise CliError("onion circuits have no exit relay to pin")
    guards = report.top_relays(rows, top)
    if not guards:
        raise CliError("no successful circuits; nothing pinned")
    exits = (report.top_relays(rows, top, "exit_fingerprint")
             if with_exits else None)
    return guards, exits


def bench_options(ns: argparse.Namespace, **overrides) -> bench.BenchOptions:
    return bench.BenchOptions(**{
        "instances": getattr(ns, "instances", 1),
        "size_mib": ns.size,
        "rtt_samples": ns.rtt_samples,
        "parallel_throughput": getattr(ns, "parallel_throughput", False),
        "bootstrap_timeout": getattr(ns, "bootstrap_timeout", 180),
        "guards": tuple(map(normalize_fingerprint,
                            getattr(ns, "guard", None) or ())),
        "exits": tuple(map(normalize_fingerprint,
                           getattr(ns, "exit", None) or ())),
        "connect_only": ns.connect_only,
        "direct": ns.direct,
        **overrides,
    })


def require_clearnet_for_direct(target: Target, direct: bool) -> None:
    if direct and target.is_onion:
        raise CliError("--direct cannot reach .onion addresses")


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------

def cmd_init(ns: argparse.Namespace) -> int:
    path = profiles.profile_dir(ns.name) / "profile.json"
    if path.exists() and not ns.force:
        raise CliError(f"profile '{ns.name}' exists (use --force)")
    target, _ = resolve(ns.target, ns)
    others = [p for p in profiles.list_all() if p.name != ns.name]
    socks, ctrl = ((ns.socks_port, ns.socks_port + 1) if ns.socks_port
                   else profiles.next_ports(others))
    created = profiles.save(profiles.from_target(
        ns.name, target, socks_port=socks, ctrl_port=ctrl,
        fallback_ports=tuple(ns.fallback or (9050,))))
    profiles.write_tor_files(created)
    print(f"created profile '{created.name}' -> {target.url}")
    print(f"  dedicated tor: socks :{socks}  control :{ctrl}  "
          f"fallback {list(created.fallback_ports)}")
    return 0


def cmd_list(_: argparse.Namespace) -> int:
    rows = profiles.list_all()
    if not rows:
        print("no profiles (run: torrelay init NAME URL)")
    for p in rows:
        state = "running" if daemon.read_pid(p) else "stopped"
        print(f"{p.name:<12} {state:<8} :{p.socks_port:<6} "
              f"guards={len(p.pinned)} exits={len(p.pinned_exits)}  "
              f"{p.target.url}")
    return 0


def cmd_bench(ns: argparse.Namespace) -> int:
    target, profile = resolve(ns.target, ns)
    require_clearnet_for_direct(target, ns.direct)
    if ns.apply and not profile:
        raise CliError("--apply needs a profile (torrelay init)")
    results = bench.run(target, bench_options(ns))
    rows = emit(results, target, profile, ns.json)
    if ns.apply:
        pin(profile, *pins_from(rows, target, ns.apply, ns.exits))
    return 0 if any(r.ok for r in results) else 1


def cmd_check(ns: argparse.Namespace) -> int:
    target, profile = resolve(ns.target, ns)
    require_clearnet_for_direct(target, ns.direct)
    ports = tuple(ns.socks or ()) or (
        (profile.socks_port, *profile.fallback_ports) if profile
        else (9050,))
    results = bench.check(target, bench_options(
        ns, connect_only=not ns.full), ports)
    emit(results, target, None, ns.json)
    return 0 if any(r.ok for r in results) else 1


def cmd_apply(ns: argparse.Namespace) -> int:
    profile = profiles.load(ns.profile)
    rows = profiles.load_results(profile)["results"]
    pin(profile, *pins_from(rows, profile.target, ns.top, ns.exits))
    return 0


def cmd_pin(ns: argparse.Namespace) -> int:
    profile = profiles.load(ns.profile)
    if ns.clear:
        pin(profile, (), ())
        return 0
    if not ns.fingerprint and not ns.exit:
        raise CliError("give guard fingerprints, --exit FP, or --clear")
    if ns.exit and profile.target.is_onion:
        raise CliError("onion circuits have no exit relay to pin")
    pin(profile,
        tuple(map(normalize_fingerprint, ns.fingerprint)) or None,
        tuple(map(normalize_fingerprint, ns.exit or ())) or None)
    return 0


def _not_launchd(profile: Profile) -> None:
    if daemon.service_installed(profile):
        raise CliError("managed by launchd; use: torrelay service "
                       f"uninstall {profile.name}")


def cmd_up(ns: argparse.Namespace) -> int:
    profile = profiles.load(ns.profile)
    _not_launchd(profile)
    pid = daemon.start(profile, ns.timeout)
    print(f"{profile.name}: up (pid {pid}) socks 127.0.0.1:"
          f"{profile.socks_port}")
    return 0


def cmd_down(ns: argparse.Namespace) -> int:
    profile = profiles.load(ns.profile)
    _not_launchd(profile)
    print(f"{profile.name}: "
          + ("stopped" if daemon.stop(profile) else "was not running"))
    return 0


def cmd_status(ns: argparse.Namespace) -> int:
    profile = profiles.load(ns.profile)
    pid = daemon.read_pid(profile)
    data_dir = str(profiles.paths(profile)["data"])
    print(f"profile   {profile.name}  ({profiles.paths(profile)['root']})")
    print(f"target    {profile.target.url}")
    print(f"tor       {'running pid ' + str(pid) if pid else 'stopped'}"
          f"  socks :{profile.socks_port}"
          f"{'  [launchd]' if daemon.service_installed(profile) else ''}")
    print(f"guards    {', '.join(profile.pinned) or 'any'}")
    print(f"exits     {', '.join(profile.pinned_exits) or 'any'}")
    if not pid:
        return 0
    print(f"bootstrap {daemon.progress(profile)}%")
    try:
        guards = entry_guards(profile.ctrl_port, data_dir)
        print("in use    " + (", ".join(f"{g.label} ({state})"
                                        for g, state in guards[:3]) or "?"))
        hops = (rendezvous_hops(profile.ctrl_port, data_dir)
                if profile.target.is_onion else ())
        if hops:
            print(f"circuit   {' -> '.join(h.label for h in hops)}")
    except (OSError, RuntimeError) as exc:
        print(f"control   unavailable: {exc}")
    return 0


def cmd_ssh_config(ns: argparse.Namespace) -> int:
    p = profiles.load(ns.profile)
    if p.scheme != "ssh":
        raise CliError(f"profile is {p.scheme}://, not ssh; "
                       f"see: torrelay env {p.name}")
    options = (
        ("HostName", p.host),
        ("Port", str(p.port)),
        *((("User", p.user),) if p.user else ()),
        *((("IdentityFile", p.key), ("IdentitiesOnly", "yes"))
          if p.key else ()),
        ("ProxyCommand", proxy.proxy_command(profile=p.name)),
        ("ControlMaster", "auto"),
        ("ControlPath", "~/.ssh/cm-%C"),
        ("ControlPersist", "10m"),
        ("ServerAliveInterval", "30"),
        ("ServerAliveCountMax", "5"),
        *(tuple(opt.split("=", 1)) for opt in p.ssh_options),
    )
    print(f"# torrelay profile '{p.name}': place above any 'Host *' block")
    print(f"Host {ns.alias or p.name}")
    print("\n".join(f"    {k} {v}" for k, v in options))
    return 0


def cmd_env(ns: argparse.Namespace) -> int:
    p = profiles.load(ns.profile)
    socks = f"127.0.0.1:{p.socks_port}"
    print(f"# Route tools through profile '{p.name}' (pinned Tor). "
          "socks5h = resolve DNS via Tor.")
    print(f"export ALL_PROXY=socks5h://{socks}")
    print(f"# e.g. curl --socks5-hostname {socks} {p.target.url}")
    return 0


def cmd_proxy(ns: argparse.Namespace) -> int:
    profile = profiles.load(ns.profile) if ns.profile else None
    ports = tuple(ns.socks or ()) or (
        (profile.socks_port, *profile.fallback_ports) if profile else ())
    if not ports:
        raise CliError("give --profile or --socks")
    return proxy.run(ns.host, ns.port, ports, ns.timeout)


def cmd_service(ns: argparse.Namespace) -> int:
    profile = profiles.load(ns.profile)
    if ns.action == "install":
        path = daemon.install_service(profile)
        print(f"{profile.name}: launchd agent installed ({path}); "
              "starts at login, restarts on crash")
    else:
        removed = daemon.uninstall_service(profile)
        print(f"{profile.name}: "
              + ("launchd agent removed" if removed else "not installed"))
    return 0


# --------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------

def _add_target_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--user", help="ssh user (or user@ in the URL)")
    parser.add_argument("--key", help="ssh private key")
    parser.add_argument("-o", "--ssh-option", action="append",
                        metavar="KEY=VALUE",
                        help="extra ssh -o option (repeatable)")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS certificate verification")


def _add_measure_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--size", type=int, default=4,
                        help="max MiB per throughput test (default 4)")
    parser.add_argument("--rtt-samples", type=int, default=10)
    parser.add_argument("--direct", action="store_true",
                        help="add a no-Tor baseline (clearnet only)")
    parser.add_argument("--json", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="torrelay", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", action="version",
                        version=f"torrelay {__version__}")
    sub = parser.add_subparsers(dest="command", required=True,
                                metavar="COMMAND")

    def command(name: str, handler: Callable[[argparse.Namespace], int],
                help_text: str) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, description=help_text)
        p.set_defaults(handler=handler)
        return p

    p = command("check", cmd_check,
                "quick connectivity test via running Tor (no bootstrap)")
    p.add_argument("target", help="URL or profile name")
    _add_target_args(p)
    _add_measure_args(p)
    p.add_argument("--socks", type=int, action="append",
                   help="SOCKS port(s) to test (default 9050 or profile's)")
    p.add_argument("--full", action="store_true",
                   help="also measure login/rtt/throughput")
    p.set_defaults(connect_only=True)

    p = command("bench", cmd_bench,
                "race N fresh Tor circuits in parallel and rank them")
    p.add_argument("target", help="URL or profile name")
    _add_target_args(p)
    _add_measure_args(p)
    p.add_argument("-n", "--instances", type=int, default=6)
    p.add_argument("--guard", action="append", metavar="FP",
                   help="test specific guard(s), one instance each")
    p.add_argument("--exit", action="append", metavar="FP",
                   help="test specific exit(s), one instance each")
    p.add_argument("--connect-only", action="store_true",
                   help="only test connectivity and handshake")
    p.add_argument("--parallel-throughput", action="store_true")
    p.add_argument("--bootstrap-timeout", type=float, default=180)
    p.add_argument("--apply", type=int, metavar="N",
                   help="pin the top N relays into the profile")
    p.add_argument("--exits", action="store_true",
                   help="with --apply: also pin exits (clearnet)")

    p = command("init", cmd_init, "save a target as a named profile")
    p.add_argument("name")
    p.add_argument("target", help="URL, e.g. ssh://user@host.onion")
    _add_target_args(p)
    p.add_argument("--socks-port", type=int,
                   help="dedicated SOCKS port (control = +1)")
    p.add_argument("--fallback", type=int, action="append",
                   help="fallback SOCKS port(s), default 9050")
    p.add_argument("--force", action="store_true")

    command("list", cmd_list, "list profiles")

    p = command("apply", cmd_apply, "pin top relays from the last bench")
    p.add_argument("profile")
    p.add_argument("--top", type=int, default=2)
    p.add_argument("--exits", action="store_true",
                   help="also pin exits (clearnet)")

    p = command("pin", cmd_pin, "pin specific relays by fingerprint")
    p.add_argument("profile")
    p.add_argument("fingerprint", nargs="*", help="guard fingerprints")
    p.add_argument("--exit", action="append", metavar="FP")
    p.add_argument("--clear", action="store_true")

    p = command("up", cmd_up, "start the profile's dedicated Tor")
    p.add_argument("profile")
    p.add_argument("--timeout", type=float, default=180)

    p = command("down", cmd_down, "stop the profile's dedicated Tor")
    p.add_argument("profile")

    p = command("status", cmd_status, "show Tor state and pinned relays")
    p.add_argument("profile")

    p = command("ssh-config", cmd_ssh_config,
                "print an ssh_config Host block (ssh profiles)")
    p.add_argument("profile")
    p.add_argument("--alias")

    p = command("env", cmd_env,
                "print proxy settings to route any tool via a profile")
    p.add_argument("profile")

    p = command("proxy", cmd_proxy,
                "ProxyCommand with failover (ssh calls this)")
    p.add_argument("host")
    p.add_argument("port", type=int)
    p.add_argument("--profile")
    p.add_argument("--socks", type=int, action="append")
    p.add_argument("--timeout", type=float, default=120)

    p = command("service", cmd_service, "manage the launchd agent")
    p.add_argument("action", choices=("install", "uninstall"))
    p.add_argument("profile")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    ns = build_parser().parse_args(argv)
    try:
        return ns.handler(ns)
    except (CliError, FileNotFoundError, ValueError, RuntimeError) as exc:
        print(f"torrelay: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
