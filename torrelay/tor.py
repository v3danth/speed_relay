"""Tor process lifecycle and control-port queries."""

from __future__ import annotations

import collections
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

TOR_BIN = shutil.which("tor") or "/opt/homebrew/bin/tor"
_FINGERPRINT_RE = re.compile(r"^\$?([0-9A-Fa-f]{40})$")


@dataclass(frozen=True)
class Hop:
    """One relay in a circuit."""

    fingerprint: str
    nickname: str = ""

    @property
    def label(self) -> str:
        return self.nickname or self.fingerprint[:8]


@dataclass(frozen=True)
class TorNode:
    """A running, bootstrapped Tor process."""

    name: str
    socks_port: int
    ctrl_port: int
    data_dir: str
    proc: subprocess.Popen
    bootstrap_s: float


# --------------------------------------------------------------------------
# Pure helpers
# --------------------------------------------------------------------------

def normalize_fingerprint(text: str) -> str:
    """'$abcd...' or 'ABCD...' -> 'ABCD...' (40 upper-case hex chars)."""
    match = _FINGERPRINT_RE.match(text.strip())
    if not match:
        raise ValueError(f"not a relay fingerprint: {text!r}")
    return match.group(1).upper()


def parse_hop(token: str) -> Hop:
    """Parse '$FP~nick', '$FP=nick' or '$FP' from control-port output."""
    fingerprint, _, nickname = token.lstrip("$").replace(
        "=", "~", 1).partition("~")
    return Hop(fingerprint.upper(), nickname)


def _rows(lines: Sequence[str], key: str) -> list[list[str]]:
    """Split GETINFO data lines into fields, dropping the '250-key=' tag."""
    return [re.sub(rf"^250[+-]{key}=", "", line).split() for line in lines]


def _purpose(fields: Sequence[str]) -> str:
    return next((f.split("=", 1)[1] for f in fields
                 if f.startswith("PURPOSE=")), "")


def parse_circuit_table(
        lines: Sequence[str]) -> dict[str, tuple[str, tuple[Hop, ...]]]:
    """circuit id -> (purpose, hops) for BUILT circuits."""
    return {
        fields[0]: (_purpose(fields),
                    tuple(map(parse_hop, fields[2].split(","))))
        for fields in _rows(lines, "circuit-status")
        if len(fields) > 2 and fields[1] == "BUILT"
        and fields[2].startswith("$")
    }


def parse_circuits(lines: Sequence[str],
                   purpose: str) -> tuple[tuple[Hop, ...], ...]:
    """Paths of BUILT circuits with the given PURPOSE."""
    return tuple(hops for kind, hops in parse_circuit_table(lines).values()
                 if kind == purpose)


def parse_stream_circuit(lines: Sequence[str], host: str,
                         port: int) -> Optional[str]:
    """Circuit id carrying an open stream to host:port, if any.

    Tor rewrites a clearnet stream's target to the exit-resolved IP once
    connected, so fall back to the only succeeded stream on that port.
    """
    streams = [fields for fields in _rows(lines, "stream-status")
               if len(fields) >= 4 and fields[1] == "SUCCEEDED"]
    exact = [f for f in streams if f[3].lower() == f"{host}:{port}".lower()]
    by_port = [f for f in streams if f[3].endswith(f":{port}")]
    match = exact or (by_port if len(by_port) == 1 else [])
    return match[0][2] if match else None


def ephemeral_torrc(data_dir: str, extra: Sequence[str] = ()) -> str:
    """torrc for a throwaway benchmark instance on auto-assigned ports."""
    return "\n".join((
        "SocksPort 127.0.0.1:auto ExtendedErrors",
        "ControlPort 127.0.0.1:auto",
        f"ControlPortWriteToFile {os.path.join(data_dir, 'control_port')}",
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

def _read_reply(reader) -> list[str]:
    """Read one control-port reply, including multi-line '+' data blocks."""
    lines: list[str] = []
    while True:
        raw = reader.readline()
        if not raw:
            raise ConnectionError("control port closed")
        line = raw.rstrip("\r\n")
        lines.append(line)
        if len(line) >= 4 and line[3] == "+":
            while (data := reader.readline().rstrip("\r\n")) != ".":
                lines.append(data)
        elif len(line) >= 4 and line[3] == " ":
            return lines


def control_query(ctrl_port: int, data_dir: str, command: str) -> list[str]:
    """Authenticate with the cookie in ``data_dir`` and run one command."""
    cookie = Path(data_dir, "control_auth_cookie").read_bytes().hex()
    with socket.create_connection(("127.0.0.1", ctrl_port), 10) as sock:
        reader = sock.makefile("r", encoding="utf-8", newline="\r\n")

        def exchange(cmd: str) -> list[str]:
            sock.sendall(f"{cmd}\r\n".encode())
            reply = _read_reply(reader)
            if not reply[-1].startswith("250"):
                raise RuntimeError(f"control: {reply[-1]}")
            return reply

        exchange(f"AUTHENTICATE {cookie}")
        return exchange(command)


def rendezvous_hops(ctrl_port: int, data_dir: str) -> tuple[Hop, ...]:
    """Client-side hops (guard, middle, rendezvous) of the onion circuit."""
    lines = control_query(ctrl_port, data_dir, "GETINFO circuit-status")
    circuits = parse_circuits(lines, "HS_CLIENT_REND")
    return circuits[0] if circuits else ()


def stream_hops(ctrl_port: int, data_dir: str, host: str,
                port: int) -> tuple[Hop, ...]:
    """Hops of the circuit carrying our open stream to host:port.

    For clearnet this is guard -> middle -> exit; for onion services it is
    the client half of the rendezvous circuit.
    """
    streams = control_query(ctrl_port, data_dir, "GETINFO stream-status")
    circuit_id = parse_stream_circuit(streams, host, port)
    if circuit_id is None:
        return ()
    table = parse_circuit_table(
        control_query(ctrl_port, data_dir, "GETINFO circuit-status"))
    return table.get(circuit_id, ("", ()))[1]


def bootstrap_progress(ctrl_port: int, data_dir: str) -> int:
    lines = control_query(ctrl_port, data_dir,
                          "GETINFO status/bootstrap-phase")
    match = re.search(r"PROGRESS=(\d+)", " ".join(lines))
    return int(match.group(1)) if match else 0


GuardState = tuple[Hop, str]


def entry_guards(ctrl_port: int,
                 data_dir: str) -> tuple[GuardState, ...]:
    """(guard, status) pairs in Tor's preference order."""
    lines = control_query(ctrl_port, data_dir, "GETINFO entry-guards")
    pairs = (re.match(r"^(?:250[+-]entry-guards=)?(\$\S+) (\S+)", line)
             for line in lines)
    return tuple((parse_hop(m.group(1)), m.group(2)) for m in pairs if m)


# --------------------------------------------------------------------------
# Ephemeral instances (benchmarking)
# --------------------------------------------------------------------------

def _listener_port(ctrl_port: int, data_dir: str) -> int:
    lines = control_query(ctrl_port, data_dir, "GETINFO net/listeners/socks")
    match = re.search(r':(\d+)"', " ".join(lines))
    if not match:
        raise RuntimeError("could not determine SOCKS port")
    return int(match.group(1))


def launch_ephemeral(name: str, data_dir: str, timeout: float,
                     extra: Sequence[str] = ()) -> TorNode:
    """Start Tor and block until bootstrapped; raises on failure."""
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    torrc = os.path.join(data_dir, "torrc")
    Path(torrc).write_text(ephemeral_torrc(data_dir, extra), encoding="utf-8")

    start = time.monotonic()
    proc = subprocess.Popen(
        [TOR_BIN, "-f", torrc],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        start_new_session=True,
    )
    watchdog = threading.Timer(timeout, proc.kill)
    watchdog.start()
    tail: collections.deque[str] = collections.deque(maxlen=3)
    try:
        for line in proc.stdout:
            tail.append(line.strip())
            if "Bootstrapped 100%" in line:
                # Keep draining so tor never blocks on a full stdout pipe.
                threading.Thread(target=collections.deque,
                                 args=(proc.stdout, 0), daemon=True).start()
                ctrl = int(Path(data_dir, "control_port").read_text()
                           .strip().rsplit(":", 1)[1])
                return TorNode(name, _listener_port(ctrl, data_dir), ctrl,
                               data_dir, proc, time.monotonic() - start)
    except BaseException:
        stop(proc)
        raise
    finally:
        watchdog.cancel()
    stop(proc)
    raise RuntimeError("bootstrap failed: " + " | ".join(tail))


def stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
