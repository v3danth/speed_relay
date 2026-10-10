"""Targets as URLs: tcp://, tls://, ssh://, http://, https:// (any host).

``host:port`` without a scheme means ``tcp://host:port``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlsplit

DEFAULT_PORTS: dict[str, Optional[int]] = {
    "tcp": None,
    "tls": 443,
    "ssh": 22,
    "http": 80,
    "https": 443,
}


@dataclass(frozen=True)
class Target:
    """Where to connect and which protocol probe to run."""

    scheme: str
    host: str
    port: int
    path: str = "/"
    user: Optional[str] = None
    key: Optional[str] = None
    ssh_options: tuple[str, ...] = ()
    insecure: bool = False  # skip TLS certificate verification

    @property
    def is_onion(self) -> bool:
        return self.host.lower().rstrip(".").endswith(".onion")

    @property
    def uses_tls(self) -> bool:
        return self.scheme in ("tls", "https")

    @property
    def url(self) -> str:
        user = f"{self.user}@" if self.user else ""
        default = DEFAULT_PORTS[self.scheme]
        port = "" if self.port == default else f":{self.port}"
        path = self.path if self.scheme in ("http", "https") else ""
        return f"{self.scheme}://{user}{self.host}{port}{path}"


def parse_target(text: str) -> Target:
    """Parse a target URL; raises ValueError with a helpful message."""
    raw = text if "://" in text else f"tcp://{text}"
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    if scheme not in DEFAULT_PORTS:
        raise ValueError(f"unsupported scheme {scheme!r}; use one of "
                         + ", ".join(DEFAULT_PORTS))
    if not parts.hostname:
        raise ValueError(f"no host in {text!r}")
    port = parts.port or DEFAULT_PORTS[scheme]
    if port is None:
        raise ValueError(f"{text!r} needs a port, e.g. tcp://host:25")
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return Target(scheme, parts.hostname, port, path, parts.username)
