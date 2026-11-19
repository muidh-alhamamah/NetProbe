"""Input validation at the trust boundary (CLI args -> system tools / sockets)."""

from __future__ import annotations

import ipaddress
import re

from netprobe.errors import InvalidTargetError

# RFC 1123 hostname. Labels cannot start with '-', which also blocks option injection into tools.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)


def validate_host(host: str) -> str:
    """Return the host if it is a valid IPv4/IPv6 address or hostname, else raise."""
    host = host.strip()
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(host):
        raise InvalidTargetError(f"invalid host: {host!r}")
    return host


def validate_port(port: int) -> int:
    if not 1 <= port <= 65535:
        raise InvalidTargetError(f"port must be 1-65535, got {port}")
    return port


def validate_range(name: str, value: float, minimum: float, maximum: float) -> float:
    if not minimum <= value <= maximum:
        raise InvalidTargetError(f"{name} must be between {minimum} and {maximum}, got {value}")
    return value
