"""Command-line entry point.

Exit codes: 0 all checks passed, 1 a check failed or a runtime error, 2 invalid usage.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

from netprobe import __version__
from netprobe.diagnostics import dns, interfaces, ping, tcp, traceroute
from netprobe.errors import NetProbeError
from netprobe.models import CheckResult
from netprobe.report import (CHECKS, DEFAULT_PORTS, render_json, render_report_json,
                             render_report_text, render_text, run_report)
from netprobe.validation import validate_host, validate_port, validate_range


def _arg(validator: Callable[[object], object], cast: Callable[[str], object] = str):
    """Adapt a validator to argparse so bad input exits with code 2 and a clean message."""
    def parse(value: str) -> object:
        try:
            return validator(cast(value))
        except (ValueError, NetProbeError) as exc:
            raise argparse.ArgumentTypeError(str(exc)) from exc
    return parse


HOST = _arg(validate_host)
PORT = _arg(validate_port, int)


def _bounded(name: str, cast: Callable[[str], float], lo: float, hi: float):
    return _arg(lambda v: cast(validate_range(name, v, lo, hi)), cast)


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="output JSON instead of text")

    parser = argparse.ArgumentParser(prog="netprobe", description="Network diagnostic CLI.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ping", parents=[common], help="ICMP ping a host")
    p.add_argument("host", type=HOST)
    p.add_argument("-c", "--count", type=_bounded("count", int, 1, 100), default=4)
    p.add_argument("-t", "--timeout", type=_bounded("timeout", float, 0.1, 60), default=2.0)
    p.set_defaults(func=lambda a: [ping.ping(a.host, a.count, a.timeout)])

    p = sub.add_parser("trace", parents=[common], help="trace the route to a host")
    p.add_argument("host", type=HOST)
    p.add_argument("-m", "--max-hops", type=_bounded("max-hops", int, 1, 64), default=30)
    p.add_argument("-t", "--timeout", type=_bounded("timeout", float, 0.1, 60), default=2.0)
    p.set_defaults(func=lambda a: [traceroute.traceroute(a.host, a.max_hops, a.timeout)])

    p = sub.add_parser("dns", parents=[common], help="resolve a hostname")
    p.add_argument("host", type=HOST)
    p.set_defaults(func=lambda a: [dns.resolve(a.host)])

    p = sub.add_parser("tcp", parents=[common], help="test TCP connectivity to host:port")
    p.add_argument("host", type=HOST)
    p.add_argument("port", type=PORT, nargs="?", help="TCP port (or use -p)")
    p.add_argument("-p", "--port", dest="port_opt", type=PORT, metavar="PORT", help="TCP port, same as the positional")
    p.add_argument("-t", "--timeout", type=_bounded("timeout", float, 0.1, 60), default=3.0)
    p.set_defaults(func=lambda a: [tcp.check_tcp(a.host, a.port, a.timeout)])

    p = sub.add_parser("iface", parents=[common], help="show local network interfaces")
    p.set_defaults(func=lambda a: [interfaces.list_interfaces()])

    p = sub.add_parser("report", parents=[common], help="run several checks and summarize them")
    p.add_argument("host", type=HOST, nargs="?", help="target host (not needed for iface only)")
    p.add_argument("-c", "--checks", nargs="+", choices=CHECKS, default=list(CHECKS), metavar="CHECK",
                   help=f"checks to run: {', '.join(CHECKS)} (default: all)")
    p.add_argument("-p", "--port", dest="ports", type=PORT, action="append",
                   help="TCP port to test, repeatable (default: 80 and 443)")
    p.set_defaults(func=lambda a: run_report(a.host, a.checks, a.ports or DEFAULT_PORTS))

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "report" and args.host is None and set(args.checks) != {"iface"}:
        parser.error("report: a host is required unless only 'iface' is checked")
    if args.command == "tcp":
        if (args.port is None) == (args.port_opt is None):
            parser.error("tcp: give the port once, either as 'tcp HOST PORT' or 'tcp HOST -p PORT'")
        args.port = args.port if args.port is not None else args.port_opt
    try:
        results: list[CheckResult] = args.func(args)
    except NetProbeError as exc:
        print(f"netprobe: error: {exc}", file=sys.stderr)
        return 1
    # Interface names can hold characters the console code page cannot encode; never crash on print.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    if args.command == "report":
        print((render_report_json if args.json else render_report_text)(args.host, results))
    else:
        print(render_json(results) if args.json else render_text(results))
    return 0 if all(r.ok for r in results) else 1
