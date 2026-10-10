"""Runs a profile's dedicated Tor, as an ad hoc daemon or a launchd agent."""

from __future__ import annotations

import os
import pathlib
import plistlib
import signal
import subprocess
import time
from typing import Optional

from torrelay import profile as profile_lib
from torrelay import tor
from torrelay import util

Profile = profile_lib.Profile

LAUNCHD_PREFIX = "com.torrelay."
_POLL_INTERVAL = 1.0
_PORT_RELEASE_DELAY = 2.0


# --------------------------------------------------------------------------
# Process state
# --------------------------------------------------------------------------

def _pid_from_file(path: pathlib.Path) -> Optional[int]:
    """Reads a PID file.

    Args:
        path: PidFile written by Tor.

    Returns:
        The PID, or None if the file is missing or malformed.
    """
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _is_alive(pid: int) -> bool:
    """Whether a process exists, without affecting it.

    Args:
        pid: Process id.

    Returns:
        True if the process exists (even if owned by another user).
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def read_pid(profile: Profile) -> Optional[int]:
    """Finds the PID of the profile's running Tor, ignoring stale files.

    Args:
        profile: The profile.

    Returns:
        The PID, or None if Tor is not running.
    """
    pid = _pid_from_file(profile_lib.paths(profile).pid)
    return pid if pid and _is_alive(pid) else None


def progress(profile: Profile) -> Optional[int]:
    """Reports the dedicated Tor's bootstrap percentage.

    Args:
        profile: The profile.

    Returns:
        0-100, or None if the control port is unreachable.
    """
    try:
        return tor.bootstrap_progress(profile.control)
    except (OSError, RuntimeError):
        return None


def wait_bootstrapped(profile: Profile, timeout: float) -> bool:
    """Polls until the dedicated Tor is fully bootstrapped.

    Args:
        profile: The profile.
        timeout: Seconds to wait.

    Returns:
        True if Tor reached 100% in time.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if progress(profile) == 100:
            return True
        time.sleep(_POLL_INTERVAL)
    return False


def _signal(profile: Profile, signum: int) -> bool:
    """Sends a signal to the profile's running Tor, if any.

    Args:
        profile: The profile.
        signum: Signal to send.

    Returns:
        True if Tor was running and was signalled.
    """
    pid = read_pid(profile)
    if not pid:
        return False
    os.kill(pid, signum)
    return True


# --------------------------------------------------------------------------
# Ad hoc daemon
# --------------------------------------------------------------------------

def _spawn_daemon(profile: Profile) -> None:
    """Launches Tor detached; it writes its own PidFile and log.

    Args:
        profile: The profile whose torrc to use.

    Raises:
        RuntimeError: With Tor's last output if it refuses to start.
    """
    torrc = str(profile_lib.paths(profile).torrc)
    proc = subprocess.run([tor.TOR_BIN, "-f", torrc, "--RunAsDaemon", "1"],
                          capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(util.last_line(proc.stdout + proc.stderr,
                                          "tor failed to start"))


def start(profile: Profile, timeout: float = 180) -> int:
    """Starts the profile's dedicated Tor and waits until it is usable.

    Idempotent: an already-running Tor is left alone.

    Args:
        profile: The profile.
        timeout: Seconds to wait for bootstrap.

    Returns:
        Tor's PID.

    Raises:
        RuntimeError: If Tor fails to start or bootstrap.
    """
    profile_lib.write_tor_files(profile)
    pid = read_pid(profile)
    if pid:
        util.log(f"{profile.name}: already running (pid {pid})")
        return pid
    _spawn_daemon(profile)
    util.log(f"{profile.name}: tor started, bootstrapping ...")
    if not wait_bootstrapped(profile, timeout):
        log_file = profile_lib.paths(profile).log
        raise RuntimeError(f"bootstrap timed out; see {log_file}")
    return read_pid(profile) or 0


def stop(profile: Profile) -> bool:
    """Stops the profile's dedicated Tor.

    Args:
        profile: The profile.

    Returns:
        True if it was running.
    """
    return _signal(profile, signal.SIGTERM)


def reload(profile: Profile) -> bool:
    """Makes Tor re-read torrc and pins without dropping connections.

    Args:
        profile: The profile.

    Returns:
        True if Tor was running and reloaded.
    """
    return _signal(profile, signal.SIGHUP)


# --------------------------------------------------------------------------
# launchd (start at login, restart on crash)
# --------------------------------------------------------------------------

def launchd_label(profile: Profile) -> str:
    """Returns the launchd job label for a profile.

    Args:
        profile: The profile.

    Returns:
        e.g. ``com.torrelay.pi``.
    """
    return LAUNCHD_PREFIX + profile.name


def plist_path(profile: Profile) -> pathlib.Path:
    """Returns where the profile's LaunchAgent plist lives.

    Args:
        profile: The profile.

    Returns:
        Path under ``~/Library/LaunchAgents``.
    """
    return (pathlib.Path.home() / "Library" / "LaunchAgents"
            / f"{launchd_label(profile)}.plist")


def render_plist(profile: Profile) -> bytes:
    """Renders the LaunchAgent that keeps the dedicated Tor running.

    Args:
        profile: The profile.

    Returns:
        plist bytes.
    """
    files = profile_lib.paths(profile)
    return plistlib.dumps({
        "Label": launchd_label(profile),
        "ProgramArguments": [tor.TOR_BIN, "-f", str(files.torrc)],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardErrorPath": str(files.log),
    })


def _launchctl(*args: str) -> subprocess.CompletedProcess:
    """Runs launchctl, returning its result for the caller to inspect.

    Args:
        *args: launchctl arguments.

    Returns:
        The completed process.
    """
    return subprocess.run(["launchctl", *args], capture_output=True,
                          text=True, check=False)


def _gui_domain() -> str:
    """Returns the launchd domain for the current user's session.

    Returns:
        e.g. ``gui/501``.
    """
    return f"gui/{os.getuid()}"


def install_service(profile: Profile) -> pathlib.Path:
    """Installs and loads a LaunchAgent for the dedicated Tor.

    Any ad hoc instance is stopped first so the ports are free.

    Args:
        profile: The profile.

    Returns:
        Path of the installed plist.

    Raises:
        RuntimeError: If launchctl refuses the job.
    """
    profile_lib.write_tor_files(profile)
    if stop(profile):
        time.sleep(_PORT_RELEASE_DELAY)
    path = plist_path(profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(render_plist(profile))
    _launchctl("bootout", f"{_gui_domain()}/{launchd_label(profile)}")
    result = _launchctl("bootstrap", _gui_domain(), str(path))
    if result.returncode != 0:
        raise RuntimeError(f"launchctl bootstrap: {result.stderr.strip()}")
    return path


def uninstall_service(profile: Profile) -> bool:
    """Unloads and removes the profile's LaunchAgent.

    Args:
        profile: The profile.

    Returns:
        True if a plist was removed.
    """
    _launchctl("bootout", f"{_gui_domain()}/{launchd_label(profile)}")
    path = plist_path(profile)
    if not path.exists():
        return False
    path.unlink()
    return True


def service_installed(profile: Profile) -> bool:
    """Whether launchd manages this profile's Tor.

    Args:
        profile: The profile.

    Returns:
        True if the plist exists.
    """
    return plist_path(profile).exists()
