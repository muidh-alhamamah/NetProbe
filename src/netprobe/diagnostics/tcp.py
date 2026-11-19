"""TCP connectivity check (can a connection be opened to host:port?)."""

from __future__ import annotations

import socket
import time

from netprobe.models import CheckResult
from netprobe.validation import validate_host, validate_port


def check_tcp(host: str, port: int, timeout: float = 3.0) -> CheckResult:
    host = validate_host(host)
    port = validate_port(port)
    target = f"{host}:{port}"
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            peer = sock.getpeername()[0]
    except OSError as exc:  # refused, unreachable, timeout, DNS failure
        return CheckResult("tcp", target, False, error=str(exc) or type(exc).__name__,
                           duration_ms=(time.perf_counter() - start) * 1000)
    return CheckResult("tcp", target, True, details={"peer": peer},
                       duration_ms=(time.perf_counter() - start) * 1000)
