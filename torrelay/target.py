"""Targets expressed as URLs: tcp://, tls://, ssh://, http://, https://.

A bare ``host:port`` means ``tcp://host:port``.
"""

from __future__ import annotations

import dataclasses
from typing import Optional
from urllib import parse

DEFAULT_PORTS: dict[str, Optional[int]] = {
    "tcp": None,
    "tls": 443,
    "ssh": 22,
    "http": 80,
    "https": 443,
}
_HTTP_SCHEMES = ("http", "https")
_TLS_SCHEMES = ("tls", "https")


@dataclasses.dataclass(frozen=True)
class Target:
    """Where to connect and which protocol probe to run.

    Attributes:
        scheme: One of ``DEFAULT_PORTS``; selects the probe.
        host: Hostname (.onion or clearnet).
        port: TCP port.
        path: HTTP path including any query string.
        user: SSH login name.
        key: Path to an SSH private key.
        ssh_options: Extra ``ssh -o`` options as ``KEY=VALUE``.
        insecure: Skip TLS certificate verification.
    """

    scheme: str
    host: str
    port: int
    path: str = "/"
    user: Optional[str] = None
    key: Optional[str] = None
    ssh_options: tuple[str, ...] = ()
    insecure: bool = False

    @property
    def is_onion(self) -> bool:
        """Whether the host is a Tor onion service (no exit, no DNS)."""
        return self.host.lower().rstrip(".").endswith(".onion")

    @property
    def uses_tls(self) -> bool:
        """Whether the protocol runs over TLS."""
        return self.scheme in _TLS_SCHEMES

    @property
    def is_http(self) -> bool:
        """Whether the protocol is HTTP or HTTPS."""
        return self.scheme in _HTTP_SCHEMES

    @property
    def destination(self) -> str:
        """``user@host`` (or ``host``) as ssh expects it."""
        return f"{self.user}@{self.host}" if self.user else self.host

    @property
    def url(self) -> str:
        """Canonical URL, used for display and for saved results."""
        user = f"{self.user}@" if self.user else ""
        port = ("" if self.port == DEFAULT_PORTS[self.scheme]
                else f":{self.port}")
        path = self.path if self.is_http else ""
        return f"{self.scheme}://{user}{self.host}{port}{path}"


def parse_target(text: str) -> Target:
    """Parses a target URL given on the command line.

    URLs keep the CLI uniform across protocols: one argument says what to
    reach and how.

    Args:
        text: A URL, or ``host:port`` for plain TCP.

    Returns:
        The parsed target.

    Raises:
        ValueError: If the scheme is unsupported or the host/port missing.
    """
    parts = parse.urlsplit(text if "://" in text else f"tcp://{text}")
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise ValueError(f"unsupported scheme {scheme!r}; use one of "
                         + ", ".join(DEFAULT_PORTS))
    if not parts.hostname:
        raise ValueError(f"no host in {text!r}")
    port = parts.port or DEFAULT_PORTS[scheme]
    if port is None:
        raise ValueError(f"{text!r} needs a port, e.g. tcp://host:25")
    query = f"?{parts.query}" if parts.query else ""
    return Target(scheme, parts.hostname, port, (parts.path or "/") + query,
                  parts.username)
