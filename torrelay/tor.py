"""Tor process lifecycle and control-port queries."""

from __future__ import annotations

import collections
import dataclasses
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from typing import IO, Optional, Sequence

TOR_BIN = shutil.which("tor") or "/opt/homebrew/bin/tor"
BOOTSTRAP_DONE = "Bootstrapped 100%"

_FINGERPRINT_RE = re.compile(r"^\$?([0-9A-Fa-f]{40})$")
_CONTROL_TIMEOUT = 10.0
_REND_PURPOSE = "HS_CLIENT_REND"


@dataclasses.dataclass(frozen=True)
class Hop:
    """One relay in a circuit.

    Attributes:
        fingerprint: 40-character upper-case hex relay identity.
        nickname: Relay nickname, if Tor reported one.
    """

    fingerprint: str
    nickname: str = ""

    @property
    def label(self) -> str:
        """Short display name: the nickname, else a fingerprint prefix."""
        return self.nickname or self.fingerprint[:8]


@dataclasses.dataclass(frozen=True)
class ControlEndpoint:
    """How to reach and authenticate to a Tor control port.

    Attributes:
        port: Control port on 127.0.0.1.
        data_dir: Tor DataDirectory holding ``control_auth_cookie``.
    """

    port: int
    data_dir: str


@dataclasses.dataclass(frozen=True)
class TorNode:
    """A running, bootstrapped Tor process started by torrelay.

    Attributes:
        name: Display name, e.g. ``tor3``.
        socks_port: SOCKS port Tor is listening on.
        control: Control-port endpoint.
        proc: The Tor process.
        bootstrap_s: Seconds Tor took to bootstrap.
    """

    name: str
    socks_port: int
    control: ControlEndpoint
    proc: subprocess.Popen
    bootstrap_s: float


GuardState = tuple[Hop, str]
CircuitTable = dict[str, tuple[str, tuple[Hop, ...]]]


# --------------------------------------------------------------------------
# Pure parsing and formatting
# --------------------------------------------------------------------------

def normalize_fingerprint(text: str) -> str:
    """Validates and canonicalises a relay fingerprint from user input.

    Tor accepts several spellings; storing one canonical form keeps pins
    comparable and torrc output predictable.

    Args:
        text: ``$abcd...`` or ``ABCD...`` (40 hex characters).

    Returns:
        The fingerprint as 40 upper-case hex characters.

    Raises:
        ValueError: If ``text`` is not a fingerprint (e.g. a nickname).
    """
    match = _FINGERPRINT_RE.match(text.strip())
    if not match:
        raise ValueError(f"not a relay fingerprint: {text!r}")
    return match.group(1).upper()


def parse_hop(token: str) -> Hop:
    """Parses one relay token from control-port output.

    Args:
        token: ``$FP~nick``, ``$FP=nick`` or ``$FP``.

    Returns:
        The parsed hop.
    """
    fingerprint, _, nickname = (
        token.lstrip("$").replace("=", "~", 1).partition("~"))
    return Hop(fingerprint.upper(), nickname)


def format_path(hops: Sequence[Hop]) -> str:
    """Renders a circuit as ``a -> b -> c`` for logs and tables.

    Args:
        hops: Relays in circuit order.

    Returns:
        The rendered path, or an empty string for no hops.
    """
    return " -> ".join(hop.label for hop in hops)


def _rows(lines: Sequence[str], key: str) -> list[list[str]]:
    """Splits GETINFO lines into fields, dropping the ``250-key=`` tag.

    Tor puts the first record on the tag line when there is only one, so
    the tag must be stripped rather than the line skipped.

    Args:
        lines: Raw reply lines.
        key: The GETINFO key, e.g. ``circuit-status``.

    Returns:
        One list of whitespace-separated fields per line.
    """
    return [re.sub(rf"^250[+-]{key}=", "", line).split() for line in lines]


def _purpose(fields: Sequence[str]) -> str:
    """Extracts the ``PURPOSE=`` value from circuit-status fields.

    Args:
        fields: One circuit's fields.

    Returns:
        The purpose, or an empty string if absent.
    """
    return next((field.split("=", 1)[1] for field in fields
                 if field.startswith("PURPOSE=")), "")


def parse_circuit_table(lines: Sequence[str]) -> CircuitTable:
    """Indexes BUILT circuits by id from ``GETINFO circuit-status``.

    Args:
        lines: Raw reply lines.

    Returns:
        Mapping of circuit id to ``(purpose, hops)``.
    """
    return {
        fields[0]: (_purpose(fields),
                    tuple(map(parse_hop, fields[2].split(","))))
        for fields in _rows(lines, "circuit-status")
        if len(fields) > 2 and fields[1] == "BUILT"
        and fields[2].startswith("$")
    }


def parse_circuits(lines: Sequence[str],
                   purpose: str) -> tuple[tuple[Hop, ...], ...]:
    """Selects the paths of BUILT circuits with a given purpose.

    Args:
        lines: Raw ``circuit-status`` reply lines.
        purpose: e.g. ``GENERAL`` or ``HS_CLIENT_REND``.

    Returns:
        The matching circuits' hops.
    """
    return tuple(hops for kind, hops in parse_circuit_table(lines).values()
                 if kind == purpose)


def parse_stream_circuit(lines: Sequence[str], host: str,
                         port: int) -> Optional[str]:
    """Finds the circuit carrying our open stream to ``host:port``.

    Tor rewrites a clearnet stream's target to the exit-resolved IP once
    connected, so when no target matches exactly we accept the only
    succeeded stream on that port.

    Args:
        lines: Raw ``stream-status`` reply lines.
        host: Hostname we connected to.
        port: Port we connected to.

    Returns:
        The circuit id, or None if it cannot be determined unambiguously.
    """
    streams = [fields for fields in _rows(lines, "stream-status")
               if len(fields) >= 4 and fields[1] == "SUCCEEDED"]
    wanted = f"{host}:{port}".lower()
    exact = [fields for fields in streams if fields[3].lower() == wanted]
    by_port = [fields for fields in streams
               if fields[3].endswith(f":{port}")]
    match = exact or (by_port if len(by_port) == 1 else [])
    return match[0][2] if match else None


def ephemeral_torrc(data_dir: str, extra: Sequence[str] = ()) -> str:
    """Renders the torrc for a throwaway benchmark instance.

    Ports are ``auto`` so any number of instances can run side by side
    without colliding with each other or with existing services.

    Args:
        data_dir: The instance's private DataDirectory.
        extra: Additional torrc lines, e.g. ``EntryNodes``.

    Returns:
        torrc text.
    """
    control_port_file = os.path.join(data_dir, "control_port")
    return "\n".join((
        "SocksPort 127.0.0.1:auto ExtendedErrors",
        "ControlPort 127.0.0.1:auto",
        f"ControlPortWriteToFile {control_port_file}",
        "CookieAuthentication 1",
        f"DataDirectory {data_dir}",
        "Log notice stdout",
        "AvoidDiskWrites 1",
        *extra,
        "",
    ))


# --------------------------------------------------------------------------
# Control port
# --------------------------------------------------------------------------

def _is_data_start(line: str) -> bool:
    """Whether a reply line opens a multi-line ``+`` data block."""
    return len(line) >= 4 and line[3] == "+"


def _is_final(line: str) -> bool:
    """Whether a reply line is the final ``NNN text`` status line."""
    return len(line) >= 4 and line[3] == " "


def read_reply(reader: IO[str]) -> list[str]:
    """Reads one complete control-port reply.

    Data blocks are consumed up to their ``.`` terminator so that lines
    inside them that happen to look like status lines (``123 BUILT``) do
    not end the reply early.

    Args:
        reader: Text stream over the control socket.

    Returns:
        All reply lines, ending with the final status line.

    Raises:
        ConnectionError: If Tor closes the connection mid-reply.
    """
    lines: list[str] = []
    while True:
        raw = reader.readline()
        if not raw:
            raise ConnectionError("control port closed")
        line = raw.rstrip("\r\n")
        lines.append(line)
        if _is_data_start(line):
            while (data := reader.readline().rstrip("\r\n")) != ".":
                lines.append(data)
        elif _is_final(line):
            return lines


def _exchange(sock: socket.socket, reader: IO[str],
              command: str) -> list[str]:
    """Sends one command and returns its successful reply.

    Args:
        sock: Connected control socket.
        reader: Text stream over ``sock``.
        command: Control-protocol command.

    Returns:
        The reply lines.

    Raises:
        RuntimeError: If Tor answers with a non-250 status.
    """
    sock.sendall(f"{command}\r\n".encode())
    reply = read_reply(reader)
    if not reply[-1].startswith("250"):
        raise RuntimeError(f"control: {reply[-1]}")
    return reply


def control_query(endpoint: ControlEndpoint, command: str) -> list[str]:
    """Runs one authenticated control-port command.

    Each query uses a fresh connection; queries are rare and this keeps
    callers free of connection state.

    Args:
        endpoint: Which Tor to talk to.
        command: e.g. ``GETINFO circuit-status``.

    Returns:
        The reply lines.

    Raises:
        OSError: If the control port is unreachable.
        RuntimeError: If Tor rejects the command.
    """
    cookie_path = pathlib.Path(endpoint.data_dir, "control_auth_cookie")
    cookie = cookie_path.read_bytes().hex()
    with socket.create_connection(("127.0.0.1", endpoint.port),
                                  _CONTROL_TIMEOUT) as sock:
        reader = sock.makefile("r", encoding="utf-8", newline="\r\n")
        _exchange(sock, reader, f"AUTHENTICATE {cookie}")
        return _exchange(sock, reader, command)


def rendezvous_hops(endpoint: ControlEndpoint) -> tuple[Hop, ...]:
    """Returns the client half of the current onion rendezvous circuit.

    Used when the stream lookup cannot identify the circuit (e.g. after
    the stream closed) so onion targets still show a path.

    Args:
        endpoint: Which Tor to ask.

    Returns:
        Guard, middle and rendezvous hops, or ``()`` if none is built.
    """
    lines = control_query(endpoint, "GETINFO circuit-status")
    circuits = parse_circuits(lines, _REND_PURPOSE)
    return circuits[0] if circuits else ()


def stream_hops(endpoint: ControlEndpoint, host: str,
                port: int) -> tuple[Hop, ...]:
    """Returns the relays carrying our open stream to ``host:port``.

    This is how torrelay reports the real circuit used: guard -> middle ->
    exit for clearnet, the client half of the rendezvous for onions.

    Args:
        endpoint: Which Tor to ask.
        host: Target hostname.
        port: Target port.

    Returns:
        The hops, or ``()`` if the stream cannot be identified.
    """
    streams = control_query(endpoint, "GETINFO stream-status")
    circuit_id = parse_stream_circuit(streams, host, port)
    if circuit_id is None:
        return ()
    table = parse_circuit_table(
        control_query(endpoint, "GETINFO circuit-status"))
    return table.get(circuit_id, ("", ()))[1]


def bootstrap_progress(endpoint: ControlEndpoint) -> int:
    """Reports how far Tor has bootstrapped, for readiness polling.

    Args:
        endpoint: Which Tor to ask.

    Returns:
        Percentage from 0 to 100.
    """
    lines = control_query(endpoint, "GETINFO status/bootstrap-phase")
    match = re.search(r"PROGRESS=(\d+)", " ".join(lines))
    return int(match.group(1)) if match else 0


def entry_guards(endpoint: ControlEndpoint) -> tuple[GuardState, ...]:
    """Lists Tor's guards and their state, to verify pins took effect.

    Args:
        endpoint: Which Tor to ask.

    Returns:
        ``(guard, state)`` pairs in Tor's preference order.
    """
    lines = control_query(endpoint, "GETINFO entry-guards")
    matches = (re.match(r"^(?:250[+-]entry-guards=)?(\$\S+) (\S+)", line)
               for line in lines)
    return tuple((parse_hop(m.group(1)), m.group(2)) for m in matches if m)


def socks_listener_port(endpoint: ControlEndpoint) -> int:
    """Discovers which port an ``auto`` SocksPort was bound to.

    Args:
        endpoint: Which Tor to ask.

    Returns:
        The SOCKS port.

    Raises:
        RuntimeError: If Tor reports no SOCKS listener.
    """
    lines = control_query(endpoint, "GETINFO net/listeners/socks")
    match = re.search(r':(\d+)"', " ".join(lines))
    if not match:
        raise RuntimeError("could not determine SOCKS port")
    return int(match.group(1))


# --------------------------------------------------------------------------
# Ephemeral instances (benchmarking)
# --------------------------------------------------------------------------

def write_torrc(data_dir: str, text: str) -> str:
    """Creates a private DataDirectory and writes its torrc.

    Args:
        data_dir: Directory to create (mode 0700, as Tor requires).
        text: torrc contents.

    Returns:
        Path of the written torrc.
    """
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    torrc = pathlib.Path(data_dir, "torrc")
    torrc.write_text(text, encoding="utf-8")
    return str(torrc)


def spawn(torrc: str) -> subprocess.Popen:
    """Starts Tor in the foreground with its log on a pipe.

    A new session lets us signal Tor without affecting our own process
    group (e.g. Ctrl-C handling).

    Args:
        torrc: Path to the config file.

    Returns:
        The running process; its stdout yields log lines.
    """
    return subprocess.Popen(  # pylint: disable=consider-using-with
        [TOR_BIN, "-f", torrc],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )


def wait_for_bootstrap(proc: subprocess.Popen, timeout: float) -> None:
    """Blocks until Tor logs that it has fully bootstrapped.

    A watchdog kills Tor at the deadline, which ends the log stream and
    turns a hang into an error.

    Args:
        proc: Process started by ``spawn``.
        timeout: Seconds to allow.

    Raises:
        RuntimeError: If Tor exits or times out first, with its last log.
    """
    watchdog = threading.Timer(timeout, proc.kill)
    watchdog.start()
    last = "no output"
    try:
        for line in proc.stdout:
            last = line.strip()
            if BOOTSTRAP_DONE in line:
                return
    finally:
        watchdog.cancel()
    raise RuntimeError(f"bootstrap failed: {last}")


def drain_output(proc: subprocess.Popen) -> None:
    """Discards Tor's log in the background after bootstrap.

    Without this, a full stdout pipe would eventually block Tor.

    Args:
        proc: Process started by ``spawn``.
    """
    threading.Thread(target=collections.deque, args=(proc.stdout, 0),
                     daemon=True).start()


def read_control_port(data_dir: str) -> int:
    """Reads the port Tor wrote for an ``auto`` ControlPort.

    Args:
        data_dir: Directory containing the ``control_port`` file.

    Returns:
        The control port.
    """
    text = pathlib.Path(data_dir, "control_port").read_text(encoding="utf-8")
    return int(text.strip().rsplit(":", 1)[1])


def launch_ephemeral(name: str, data_dir: str, timeout: float,
                     extra: Sequence[str] = ()) -> TorNode:
    """Starts a private Tor instance and waits until it is usable.

    Each benchmark instance gets its own guard and circuits, which is what
    lets torrelay compare many independent paths at once.

    Args:
        name: Display name for logs.
        data_dir: Fresh directory for this instance.
        timeout: Seconds allowed for bootstrapping.
        extra: Additional torrc lines (e.g. pinned relays).

    Returns:
        The running instance.

    Raises:
        RuntimeError: If Tor fails to bootstrap.
    """
    torrc = write_torrc(data_dir, ephemeral_torrc(data_dir, extra))
    start = time.monotonic()
    proc = spawn(torrc)
    try:
        wait_for_bootstrap(proc, timeout)
        drain_output(proc)
        endpoint = ControlEndpoint(read_control_port(data_dir), data_dir)
        return TorNode(name, socks_listener_port(endpoint), endpoint, proc,
                       time.monotonic() - start)
    except BaseException:
        stop(proc)
        raise


def stop(proc: subprocess.Popen) -> None:
    """Terminates a Tor process started by ``spawn`` if still running.

    Args:
        proc: The process to stop.
    """
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
