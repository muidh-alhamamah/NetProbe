"""Render CheckResults as text or JSON, and run multi-check diagnostic reports."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from typing import Any

from netprobe.diagnostics import dns, interfaces, ping, tcp, traceroute
from netprobe.models import CheckResult

CHECKS = ("dns", "ping", "tcp", "trace", "iface")
DEFAULT_PORTS = (80, 443)


def run_report(host: str | None, checks: Sequence[str] = CHECKS,
               ports: Sequence[int] = DEFAULT_PORTS) -> list[CheckResult]:
    """Run the selected checks in order. A check that raises becomes a failed result."""
    jobs: list[tuple[str, str, Callable[[], CheckResult]]] = []
    for check in dict.fromkeys(checks):  # dedupe, keep order
        if check == "dns":
            jobs.append(("dns", f"{host}", lambda: dns.resolve(host)))
        elif check == "ping":
            jobs.append(("ping", f"{host}", lambda: ping.ping(host)))
        elif check == "tcp":
            jobs.extend(("tcp", f"{host}:{port}", lambda port=port: tcp.check_tcp(host, port))
                        for port in dict.fromkeys(ports))
        elif check == "trace":
            jobs.append(("traceroute", f"{host}", lambda: traceroute.traceroute(host)))
        elif check == "iface":
            jobs.append(("interfaces", "local", interfaces.list_interfaces))
        else:
            raise ValueError(f"unknown check: {check}")
    return [_run_isolated(*job) for job in jobs]


def _run_isolated(check: str, target: str, func: Callable[[], CheckResult]) -> CheckResult:
    start = time.perf_counter()
    try:
        return func()
    except Exception as exc:  # one broken check (missing tool, bug, ...) must not abort the report
        return CheckResult(check, target, False, error=str(exc) or type(exc).__name__,
                           duration_ms=(time.perf_counter() - start) * 1000)


def summarize(results: Sequence[CheckResult]) -> dict[str, Any]:
    passed = sum(r.ok for r in results)
    return {
        "total": len(results),
        "passed": passed,
        "failed": len(results) - passed,
        "duration_ms": sum(r.duration_ms or 0 for r in results),
        "failed_checks": [f"{r.check} {r.target}" for r in results if not r.ok],
    }


def render_report_json(target: str | None, results: Sequence[CheckResult]) -> str:
    report = {"target": target, "generated_at": _now(), "summary": summarize(results),
              "results": [r.to_dict() for r in results]}
    return json.dumps(report, indent=2)  # ASCII-only, see render_json


def render_report_text(target: str | None, results: Sequence[CheckResult]) -> str:
    s = summarize(results)
    lines = [
        f"NetProbe report for {target or 'local machine'} ({_now()})",
        f"Summary: {s['passed']}/{s['total']} passed, {s['failed']} failed ({s['duration_ms']:.0f} ms)",
    ]
    lines.extend(f"  failed: {name}" for name in s["failed_checks"])
    return "\n".join([*lines, "", render_text(results)])


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def render_json(results: Sequence[CheckResult]) -> str:
    # ASCII-only (\uXXXX escapes): stays valid JSON whatever code page stdout/redirection uses.
    return json.dumps([r.to_dict() for r in results], indent=2)


def render_text(results: Sequence[CheckResult]) -> str:
    lines: list[str] = []
    for r in results:
        status = "OK  " if r.ok else "FAIL"
        timing = f" ({r.duration_ms:.0f} ms)" if r.duration_ms is not None else ""
        lines.append(f"[{status}] {r.check} {r.target}{timing}")
        for key, value in r.details.items():
            if key == "raw_output" or value is None:  # raw output stays available via --json
                continue
            if isinstance(value, list) and value and isinstance(value[0], dict):
                lines.append(f"  {key}:")
                for item in value:
                    fields = (f"{k}={_fmt(v)}" for k, v in item.items() if v not in (None, False, []))
                    lines.append("    " + " ".join(fields))
            else:
                lines.append(f"  {key}: {_fmt(value)}")
        if r.error:
            lines.append(f"  error: {r.error}")
    return "\n".join(lines)


def _fmt(value: object) -> str:
    if value is None:
        return "*"
    if isinstance(value, float):
        return f"{value:g}"
    if isinstance(value, list):
        return " ".join(map(_fmt, value)) if value else "-"
    return str(value)
