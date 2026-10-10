"""Named profiles: one target plus one dedicated, pinnable Tor instance.

Layout under ``$XDG_CONFIG_HOME/torrelay/<name>/`` (default ~/.config)::

    profile.json   target, ports and pinned relays (source of truth)
    torrc          generated; %includes pinned.conf
    pinned.conf    generated; EntryNodes/ExitNodes (reloaded via SIGHUP)
    results.json   last benchmark, ranked
    data/          Tor DataDirectory
    tor.pid tor.log
"""

from __future__ import annotations

import dataclasses
import json
import os
import pathlib
import re
import time
from typing import Any, Iterable, Optional, Sequence

from torrelay import target as target_lib
from torrelay import tor

DEFAULT_SOCKS_PORT = 9060
DEFAULT_FALLBACK_PORTS = (9050,)

_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
_TUPLE_FIELDS = ("fallback_ports", "ssh_options", "pinned", "pinned_exits")


@dataclasses.dataclass(frozen=True)
class Profile:
    """A saved target and the dedicated Tor instance that serves it.

    Attributes:
        name: Profile name (letters, digits, ``_`` and ``-``).
        host: Target hostname.
        scheme: Target protocol.
        port: Target port.
        path: HTTP path.
        user: SSH user.
        key: SSH private key path.
        insecure: Skip TLS verification.
        socks_port: Dedicated Tor's SOCKS port.
        ctrl_port: Dedicated Tor's control port.
        fallback_ports: SOCKS ports to try when the dedicated Tor is down.
        ssh_options: Extra ``ssh -o`` options.
        pinned: Pinned guard fingerprints.
        pinned_exits: Pinned exit fingerprints (clearnet only).
    """

    name: str
    host: str
    scheme: str = "ssh"
    port: int = 22
    path: str = "/"
    user: Optional[str] = None
    key: Optional[str] = None
    insecure: bool = False
    socks_port: int = DEFAULT_SOCKS_PORT
    ctrl_port: int = DEFAULT_SOCKS_PORT + 1
    fallback_ports: tuple[int, ...] = DEFAULT_FALLBACK_PORTS
    ssh_options: tuple[str, ...] = ()
    pinned: tuple[str, ...] = ()
    pinned_exits: tuple[str, ...] = ()

    @property
    def target(self) -> target_lib.Target:
        """The saved target, ready to benchmark."""
        return target_lib.Target(self.scheme, self.host, self.port,
                                 self.path, self.user, self.key,
                                 self.ssh_options, self.insecure)

    @property
    def socks_chain(self) -> tuple[int, ...]:
        """SOCKS ports in failover order: dedicated Tor, then fallbacks."""
        return (self.socks_port, *self.fallback_ports)

    @property
    def control(self) -> tor.ControlEndpoint:
        """Control-port endpoint of the dedicated Tor."""
        return tor.ControlEndpoint(self.ctrl_port, str(paths(self).data))


@dataclasses.dataclass(frozen=True)
class ProfilePaths:
    """Filesystem locations belonging to one profile.

    Attributes:
        root: Profile directory.
        json: Saved profile.
        torrc: Generated Tor config.
        pinned: Generated pin include file.
        results: Last benchmark results.
        data: Tor DataDirectory.
        pid: Tor PidFile.
        log: Tor log file.
    """

    root: pathlib.Path
    json: pathlib.Path
    torrc: pathlib.Path
    pinned: pathlib.Path
    results: pathlib.Path
    data: pathlib.Path
    pid: pathlib.Path
    log: pathlib.Path


def from_target(name: str, target: target_lib.Target,
                **settings: Any) -> Profile:
    """Creates a profile for a parsed target.

    Args:
        name: Profile name.
        target: What the profile reaches.
        **settings: Extra Profile fields such as ports.

    Returns:
        The new (unsaved) profile.
    """
    return Profile(name=name, host=target.host, scheme=target.scheme,
                   port=target.port, path=target.path, user=target.user,
                   key=target.key, insecure=target.insecure,
                   ssh_options=target.ssh_options, **settings)


# --------------------------------------------------------------------------
# Paths
# --------------------------------------------------------------------------

def config_root() -> pathlib.Path:
    """Returns torrelay's config directory, honouring XDG_CONFIG_HOME.

    Returns:
        ``$XDG_CONFIG_HOME/torrelay`` or ``~/.config/torrelay``.
    """
    base = os.environ.get("XDG_CONFIG_HOME") or pathlib.Path.home() / ".config"
    return pathlib.Path(base) / "torrelay"


def validate_name(name: str) -> str:
    """Rejects names that are unsafe as directory names.

    Args:
        name: Proposed profile name.

    Returns:
        The name, unchanged.

    Raises:
        ValueError: If the name has disallowed characters.
    """
    if not _NAME_RE.match(name):
        raise ValueError(f"invalid profile name {name!r} "
                         "(letters, digits, _ and - only)")
    return name


def profile_dir(name: str) -> pathlib.Path:
    """Returns the directory for a profile name.

    Args:
        name: Profile name.

    Returns:
        The profile's directory (may not exist yet).
    """
    return config_root() / validate_name(name)


def paths(profile: Profile) -> ProfilePaths:
    """Returns every file location belonging to a profile.

    Args:
        profile: The profile.

    Returns:
        Its paths.
    """
    root = profile_dir(profile.name)
    return ProfilePaths(
        root=root,
        json=root / "profile.json",
        torrc=root / "torrc",
        pinned=root / "pinned.conf",
        results=root / "results.json",
        data=root / "data",
        pid=root / "tor.pid",
        log=root / "tor.log",
    )


# --------------------------------------------------------------------------
# Pure rendering
# --------------------------------------------------------------------------

def render_torrc(profile: Profile) -> str:
    """Renders the dedicated Tor's config.

    Pins live in a separate ``%include`` file so they can change and be
    hot-reloaded without rewriting this file.

    Args:
        profile: The profile.

    Returns:
        torrc text.
    """
    files = paths(profile)
    return "\n".join((
        f"# Generated by torrelay for profile {profile.name!r}. "
        "Edit profile.json instead.",
        f"SocksPort 127.0.0.1:{profile.socks_port} ExtendedErrors",
        f"ControlPort 127.0.0.1:{profile.ctrl_port}",
        "CookieAuthentication 1",
        f"DataDirectory {files.data}",
        f"PidFile {files.pid}",
        f"Log notice file {files.log}",
        f"%include {files.pinned}",
        "",
    ))


def _node_line(option: str, fingerprints: Sequence[str]) -> str:
    """Renders one ``EntryNodes``/``ExitNodes`` torrc line.

    Args:
        option: torrc option name.
        fingerprints: Relays to list.

    Returns:
        The line, or an empty string for no relays.
    """
    if not fingerprints:
        return ""
    return f"{option} " + ",".join(f"${fp}" for fp in fingerprints) + "\n"


def render_pinned(guards: Sequence[str], exits: Sequence[str] = ()) -> str:
    """Renders the pin include file.

    Args:
        guards: Guard fingerprints.
        exits: Exit fingerprints.

    Returns:
        File text; a comment when nothing is pinned.
    """
    body = _node_line("EntryNodes", guards) + _node_line("ExitNodes", exits)
    return body or "# Nothing pinned; Tor chooses its own relays.\n"


def next_ports(existing: Iterable[Profile]) -> tuple[int, int]:
    """Allocates a (socks, control) port pair no other profile uses.

    Pairs stay aligned to even SOCKS ports starting at 9060 so ports are
    predictable.

    Args:
        existing: Other profiles.

    Returns:
        ``(socks_port, control_port)``.
    """
    used = [port for profile in existing
            for port in (profile.socks_port, profile.ctrl_port)]
    socks = max([DEFAULT_SOCKS_PORT - 2, *used]) + 1
    socks += socks % 2 != DEFAULT_SOCKS_PORT % 2
    return socks, socks + 1


# --------------------------------------------------------------------------
# I/O
# --------------------------------------------------------------------------

def _write_json(path: pathlib.Path, data: dict) -> pathlib.Path:
    """Writes pretty-printed JSON, the format for all saved state.

    Args:
        path: Destination file.
        data: JSON-serialisable data.

    Returns:
        ``path``.
    """
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def _read_json(path: pathlib.Path, missing: str) -> dict:
    """Reads saved JSON state with a helpful error when it is absent.

    Args:
        path: File to read.
        missing: Error message if the file does not exist.

    Returns:
        The parsed data.

    Raises:
        FileNotFoundError: With ``missing`` as the message.
    """
    if not path.exists():
        raise FileNotFoundError(missing)
    return json.loads(path.read_text(encoding="utf-8"))


def _from_dict(data: dict) -> Profile:
    """Rebuilds a Profile from JSON, tolerating unknown or missing keys.

    Args:
        data: Parsed ``profile.json``.

    Returns:
        The profile.
    """
    known = {field.name for field in dataclasses.fields(Profile)}
    clean = {key: value for key, value in data.items() if key in known}
    tuples = {key: tuple(clean[key]) for key in _TUPLE_FIELDS if key in clean}
    return Profile(**{**clean, **tuples})


def exists(name: str) -> bool:
    """Whether a profile with this name has been saved.

    Args:
        name: Profile name.

    Returns:
        True if saved.
    """
    return (profile_dir(name) / "profile.json").exists()


def load(name: str) -> Profile:
    """Loads a saved profile.

    Args:
        name: Profile name.

    Returns:
        The profile.

    Raises:
        FileNotFoundError: If no such profile exists.
    """
    data = _read_json(profile_dir(name) / "profile.json",
                      f"no profile {name!r} (run: torrelay init)")
    return _from_dict(data)


def list_all() -> list[Profile]:
    """Loads every saved profile, sorted by name.

    Returns:
        All profiles.
    """
    root = config_root()
    if not root.exists():
        return []
    names = sorted(entry.name for entry in root.iterdir()
                   if (entry / "profile.json").exists())
    return list(map(load, names))


def save(profile: Profile) -> Profile:
    """Persists a profile.

    Args:
        profile: The profile.

    Returns:
        The same profile, for chaining.
    """
    files = paths(profile)
    files.root.mkdir(mode=0o700, parents=True, exist_ok=True)
    _write_json(files.json, dataclasses.asdict(profile))
    return profile


def write_tor_files(profile: Profile) -> None:
    """Regenerates the dedicated Tor's torrc and pin file from the profile.

    Args:
        profile: The profile.
    """
    files = paths(profile)
    files.data.mkdir(mode=0o700, parents=True, exist_ok=True)
    files.torrc.write_text(render_torrc(profile), encoding="utf-8")
    files.pinned.write_text(
        render_pinned(profile.pinned, profile.pinned_exits),
        encoding="utf-8")


def save_results(profile: Profile, payload: dict) -> pathlib.Path:
    """Saves the latest benchmark so pins can be applied later.

    Args:
        profile: The profile benchmarked.
        payload: Results to save.

    Returns:
        Path of the results file.
    """
    return _write_json(paths(profile).results,
                       {"timestamp": time.time(), **payload})


def load_results(profile: Profile) -> dict:
    """Loads the latest saved benchmark.

    Args:
        profile: The profile.

    Returns:
        The saved payload.

    Raises:
        FileNotFoundError: If the profile was never benchmarked.
    """
    return _read_json(
        paths(profile).results,
        f"no results for {profile.name!r} "
        f"(run: torrelay bench {profile.name})")
