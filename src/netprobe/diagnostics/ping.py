"""ICMP ping via the system `ping` tool (no raw sockets, so no admin/root needed)."""

from __future__ import annotations

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

# Windows output is localized, so these match structure ("= N, ... = N") instead of words.
# "Packets: Sent = 4, Received = 4, Lost = 0" / "Pakete: Gesendet = 4, Empfangen = 4, Verloren = 0"
_WIN_COUNTS_RE = re.compile(r"=\s*(\d+),\s*[^=\n]+=\s*(\d+),\s*[^=\n]+=\s*(\d+)")
# "Minimum = 12ms, Maximum = 15ms, Average = 13ms" (order: min, max, avg)
_WIN_RTT_RE = re.compile(r"=\s*(\d+)\s*ms,\s*[^=\n]+=\s*(\d+)\s*ms,\s*[^=\n]+=\s*(\d+)\s*ms", re.I)
# An echo reply line carries "time=12ms" / "time<1ms" / "Zeit=12ms"; unreachable replies do not.
_WIN_REPLY_RE = re.compile(r"[=<]\s*\d+\s*ms", re.I)

# "4 packets transmitted, 3 received, ..." (iputils) / "..., 3 packets received, ..." (BusyBox)
_LINUX_COUNTS_RE = re.compile(r"(\d+) packets transmitted, (\d+) (?:packets )?received")
# "rtt min/avg/max/mdev = 11.8/12.2/12.9/0.4 ms" / "round-trip min/avg/max = 0.1/0.2/0.3 ms"
_LINUX_RTT_RE = re.compile(r"min/avg/max\S*\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)")


def build_ping_command(host: str, count: int, timeout: float, platform: str | None = None) -> list[str]:
    if (platform or sys.platform) == "win32":
        return ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host]
    # Linux iputils: -W is per-reply timeout in seconds.
    return ["ping", "-c", str(count), "-W", str(max(1, int(timeout))), host]


def empty_stats() -> dict[str, Any]:
    return {"sent": None, "received": None, "packet_loss": None,
            "min_ms": None, "avg_ms": None, "max_ms": None}


def parse_ping_output(output: str, platform: str | None = None) -> dict[str, Any]:
    """Extract sent/received/loss/latency. Fields stay None when the output has no statistics."""
    stats = empty_stats()
    if (platform or sys.platform) == "win32":
        counts = _WIN_COUNTS_RE.search(output)
        if counts:
            sent = int(counts.group(1))
            # Windows counts "Destination host unreachable" replies as received, so count real
            # echo replies instead. Statistic lines contain commas; reply lines do not.
            replies = sum(
                1 for line in output.splitlines()
                if _WIN_REPLY_RE.search(line) and "," not in line and "،" not in line
            )
            stats.update(sent=sent, received=min(replies, sent))
        rtt = _WIN_RTT_RE.search(output)
        if rtt:
            low, high, avg = (float(v) for v in rtt.groups())
            stats.update(min_ms=low, avg_ms=avg, max_ms=high)
    else:
        counts = _LINUX_COUNTS_RE.search(output)
        if counts:
            stats.update(sent=int(counts.group(1)), received=int(counts.group(2)))
        rtt = _LINUX_RTT_RE.search(output)
        if rtt:
            low, avg, high = (float(v) for v in rtt.groups())
            stats.update(min_ms=low, avg_ms=avg, max_ms=high)

    if stats["sent"]:
        stats["packet_loss"] = round((stats["sent"] - stats["received"]) / stats["sent"] * 100, 1)
    if not stats["received"]:
        stats.update(min_ms=None, avg_ms=None, max_ms=None)
    return stats


def classify(stats: dict[str, Any], output: str, returncode: int) -> tuple[str, str | None]:
    """Return (status, error message). Status: ok | timeout | unreachable | error."""
    if stats["sent"] is None:
        last = next((ln.strip() for ln in reversed(output.splitlines()) if ln.strip()), "")
        return "error", last or f"ping exited with code {returncode}"
    if stats["received"]:
        return "ok", None
    if "unreachable" in output.lower():
        return "unreachable", "destination unreachable"
    return "timeout", "no reply (request timed out)"


def ping(host: str, count: int = 4, timeout: float = 2.0) -> CheckResult:
    host = validate_host(host)
    start = time.perf_counter()

    def result(status: str, error: str | None, address: str | None = None,
               stats: dict[str, Any] | None = None, raw: str = "") -> CheckResult:
        details = {"status": status, "address": address, **(stats or empty_stats()), "raw_output": raw}
        return CheckResult("ping", host, status == "ok", details, error,
                           (time.perf_counter() - start) * 1000)

    try:
        address = dns.first_address(host)
    except socket.gaierror as exc:
        return result("dns_failure", f"cannot resolve {host}: {exc}")
    try:
        cmd = run_command(build_ping_command(address, count, timeout), timeout=count * (timeout + 1) + 5)
    except CommandTimeoutError as exc:
        return result("timeout", str(exc), address)
    except CommandNotFoundError as exc:
        return result("tool_missing", str(exc), address)

    stats = parse_ping_output(cmd.stdout, sys.platform)
    status, error = classify(stats, f"{cmd.stdout}\n{cmd.stderr}", cmd.returncode)
    return result(status, error, address, stats, cmd.stdout.strip())
