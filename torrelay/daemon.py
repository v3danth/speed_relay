"""Run a profile's dedicated Tor instance: ad hoc daemon or launchd agent."""

from __future__ import annotations

import os
import plistlib
import signal
import subprocess
import time
from pathlib import Path
from typing import Optional

from torrelay import profile as profiles
from torrelay.profile import Profile
from torrelay.tor import TOR_BIN, bootstrap_progress
from torrelay.util import log

LAUNCHD_PREFIX = "com.torrelay."


# --------------------------------------------------------------------------
# Process state
# --------------------------------------------------------------------------

def read_pid(profile: Profile) -> Optional[int]:
    path = profiles.paths(profile)["pid"]
    try:
        pid = int(path.read_text().strip())
    except (OSError, ValueError):
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        pass  # exists, owned by someone else
    return pid


def progress(profile: Profile) -> Optional[int]:
    try:
        return bootstrap_progress(profile.ctrl_port,
                                  str(profiles.paths(profile)["data"]))
    except (OSError, RuntimeError):
        return None


def wait_bootstrapped(profile: Profile, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if progress(profile) == 100:
            return True
        time.sleep(1)
    return False


# --------------------------------------------------------------------------
# Ad hoc daemon
# --------------------------------------------------------------------------

def start(profile: Profile, timeout: float = 180) -> int:
    profiles.write_tor_files(profile)
    pid = read_pid(profile)
    if pid:
        log(f"{profile.name}: already running (pid {pid})")
        return pid
    torrc = str(profiles.paths(profile)["torrc"])
    proc = subprocess.run([TOR_BIN, "-f", torrc, "--RunAsDaemon", "1"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError((proc.stdout + proc.stderr).strip()
                           .splitlines()[-1])
    log(f"{profile.name}: tor started, bootstrapping ...")
    if not wait_bootstrapped(profile, timeout):
        raise RuntimeError(f"bootstrap timed out; see "
                           f"{profiles.paths(profile)['log']}")
    return read_pid(profile) or 0


def stop(profile: Profile) -> bool:
    pid = read_pid(profile)
    if not pid:
        return False
    os.kill(pid, signal.SIGTERM)
    return True


def reload(profile: Profile) -> bool:
    """SIGHUP: Tor re-reads torrc (and pinned.conf) without restarting."""
    pid = read_pid(profile)
    if not pid:
        return False
    os.kill(pid, signal.SIGHUP)
    return True


# --------------------------------------------------------------------------
# launchd (start at login, restart on crash)
# --------------------------------------------------------------------------

def launchd_label(profile: Profile) -> str:
    return LAUNCHD_PREFIX + profile.name


def plist_path(profile: Profile) -> Path:
    return (Path.home() / "Library" / "LaunchAgents"
            / f"{launchd_label(profile)}.plist")


def render_plist(profile: Profile) -> bytes:
    p = profiles.paths(profile)
    return plistlib.dumps({
        "Label": launchd_label(profile),
        "ProgramArguments": [TOR_BIN, "-f", str(p["torrc"])],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardErrorPath": str(p["log"]),
    })


def _launchctl(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["launchctl", *args], capture_output=True,
                          text=True)


def install_service(profile: Profile) -> Path:
    profiles.write_tor_files(profile)
    if stop(profile):
        time.sleep(2)  # free the ports before launchd starts its copy
    path = plist_path(profile)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(render_plist(profile))
    domain = f"gui/{os.getuid()}"
    _launchctl("bootout", f"{domain}/{launchd_label(profile)}")
    result = _launchctl("bootstrap", domain, str(path))
    if result.returncode != 0:
        raise RuntimeError(f"launchctl bootstrap: {result.stderr.strip()}")
    return path


def uninstall_service(profile: Profile) -> bool:
    path = plist_path(profile)
    _launchctl("bootout", f"gui/{os.getuid()}/{launchd_label(profile)}")
    if path.exists():
        path.unlink()
        return True
    return False


def service_installed(profile: Profile) -> bool:
    return plist_path(profile).exists()
