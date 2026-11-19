"""DNS A/AAAA lookup through the OS resolver (stdlib only)."""

from __future__ import annotations

import socket
import time

from netprobe.models import CheckResult
from netprobe.validation import validate_host


def first_address(host: str) -> str:
    """Resolve host to a single IP address via the OS resolver. Raises socket.gaierror."""
    return socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)[0][4][0]


def resolve(host: str) -> CheckResult:
    # shortcut: OS resolver gives A/AAAA only; add dnspython when MX/TXT/NS or a custom server is needed.
    host = validate_host(host)
    start = time.perf_counter()
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return CheckResult("dns", host, False, error=str(exc),
                           duration_ms=(time.perf_counter() - start) * 1000)
    addresses = sorted({info[4][0] for info in infos})
    return CheckResult("dns", host, True, details={"addresses": addresses},
                       duration_ms=(time.perf_counter() - start) * 1000)
