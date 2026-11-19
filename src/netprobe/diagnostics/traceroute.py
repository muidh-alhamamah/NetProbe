"""Traceroute via the system tool: `tracert` on Windows, `traceroute` on Linux."""

from __future__ import annotations

import ipaddress
import re
import socket
import sys
import time
from typing import Any

from netprobe.diagnostics import dns
from netprobe.errors import CommandNotFoundError, CommandTimeoutError
from netprobe.models import CheckResult
from netprobe.runner import run_command
from netprobe.validation import validate_host

# Hop lines start with the hop number on both platforms:
#   Windows: "  2     8 ms     7 ms     *     10.20.0.1"
#   Linux:   " 2  10.20.0.1  9.104 ms  9.311 ms !H  *"
_HOP_RE = re.compile(r"^\s*(\d+)\s+(.*)$")
_TOKEN_RE = re.compile(r"\*|(<)?(\d+(?:\.\d+)?)\s*ms\b|(\S+)", re.I)
# traceroute annotations meaning "unreachable": !H host, !N network, !P protocol, !X/!A/!C prohibited.
_UNREACHABLE_FLAGS = {"!H", "!N", "!P", "!X", "!A", "!C", "!S", "!V"}


def build_traceroute_command(
    host: str, max_hops: int, timeout: float, platform: str | None = None
) -> list[str]:
    if (platform or sys.platform) == "win32":
        return ["tracert", "-d", "-h", str(max_hops), "-w", str(int(timeout * 1000)), host]
    return ["traceroute", "-n", "-m", str(max_hops), "-w", str(max(1, int(timeout))), host]


def _as_ip(token: str) -> str | None:
    try:
        return str(ipaddress.ip_address(token.strip("[]()")))
    except ValueError:
        return None


def parse_traceroute_output(output: str) -> list[dict[str, Any]]:
    """Return hops as {hop, address, rtts_ms, unreachable}. A '*' probe is None in rtts_ms."""
    hops: list[dict[str, Any]] = []
    for line in output.splitlines():
        match = _HOP_RE.match(line)
        if not match:
            continue
        address: str | None = None
        rtts: list[float | None] = []
        unreachable = "unreachable" in line.lower()  # Windows: "... reports: Destination host unreachable."
        for token in _TOKEN_RE.finditer(match.group(2)):
            word = token.group(3)
            if token.group(0) == "*":
                rtts.append(None)
            elif token.group(2):
                # Windows prints "<1 ms"; report the upper bound.
                rtts.append(1.0 if token.group(1) else float(token.group(2)))
            elif word.startswith("!"):
                unreachable = unreachable or word in _UNREACHABLE_FLAGS
            elif address is None:
                address = _as_ip(word)  # first IP only; extra IPs (load-balanced paths) are ignored
        hops.append({"hop": int(match.group(1)), "address": address, "rtts_ms": rtts,
                     "unreachable": unreachable})
    return hops


def classify(hops: list[dict[str, Any]], destination: str) -> tuple[str, str | None]:
    """Return (status, error message). Status: ok | unreachable | incomplete | error."""
    if not hops:
        return "error", "no hops in traceroute output"
    if any(h["address"] == destination for h in hops):
        return "ok", None
    if any(h["unreachable"] for h in hops):
        return "unreachable", "destination unreachable"
    return "incomplete", f"destination not reached within {hops[-1]['hop']} hops"


def traceroute(host: str, max_hops: int = 30, timeout: float = 2.0) -> CheckResult:
    host = validate_host(host)
    start = time.perf_counter()

    def result(status: str, error: str | None, address: str | None = None,
               hops: list[dict[str, Any]] | None = None, raw: str = "") -> CheckResult:
        details = {"status": status, "address": address, "hops": hops or [], "raw_output": raw}
        return CheckResult("traceroute", host, status == "ok", details, error,
                           (time.perf_counter() - start) * 1000)

    try:
        address = _as_ip(dns.first_address(host)) or host
    except socket.gaierror as exc:
        return result("dns_failure", f"cannot resolve {host}: {exc}")
    try:
        cmd = run_command(build_traceroute_command(address, max_hops, timeout),
                          timeout=max_hops * timeout * 3 + 10)
    except CommandTimeoutError as exc:
        return result("timeout", str(exc), address)
    except CommandNotFoundError as exc:
        return result("tool_missing", str(exc), address)

    hops = parse_traceroute_output(cmd.stdout)
    status, error = classify(hops, address)
    if status == "error":
        tool_lines = (cmd.stderr or cmd.stdout).strip().splitlines()
        error = tool_lines[-1].strip() if tool_lines else error
    return result(status, error, address, hops, cmd.stdout.strip())
