import socket
import unittest
from pathlib import Path
from unittest import mock

from netprobe.diagnostics import traceroute
from netprobe.errors import CommandNotFoundError, CommandTimeoutError
from netprobe.runner import CommandResult

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def hop(n, address, rtts, unreachable=False):
    return {"hop": n, "address": address, "rtts_ms": rtts, "unreachable": unreachable}


class BuildCommandTests(unittest.TestCase):
    def test_windows(self) -> None:
        self.assertEqual(traceroute.build_traceroute_command("h.com", 10, 2, "win32"),
                         ["tracert", "-d", "-h", "10", "-w", "2000", "h.com"])

    def test_linux(self) -> None:
        self.assertEqual(traceroute.build_traceroute_command("h.com", 10, 2, "linux"),
                         ["traceroute", "-n", "-m", "10", "-w", "2", "h.com"])


class ParseTests(unittest.TestCase):
    def test_windows_complete(self) -> None:
        hops = traceroute.parse_traceroute_output(fixture("tracert_windows_complete.txt"))
        self.assertEqual(hops, [
            hop(1, "192.168.1.1", [1.0, 1.0, 1.0]),
            hop(2, "10.20.0.1", [8.0, 7.0, 9.0]),
            hop(3, None, [None, None, None]),
            hop(4, "8.8.8.8", [12.0, 11.0, 12.0]),
        ])
        self.assertEqual(traceroute.classify(hops, "8.8.8.8"), ("ok", None))

    def test_windows_incomplete(self) -> None:
        hops = traceroute.parse_traceroute_output(fixture("tracert_windows_incomplete.txt"))
        self.assertEqual(hops[1], hop(2, "10.20.0.1", [8.0, None, 9.0]))
        self.assertEqual(len(hops), 4)
        self.assertEqual(traceroute.classify(hops, "203.0.113.9"),
                         ("incomplete", "destination not reached within 4 hops"))

    def test_windows_unreachable(self) -> None:
        hops = traceroute.parse_traceroute_output(fixture("tracert_windows_unreachable.txt"))
        self.assertEqual(hops, [hop(1, "192.168.1.5", [], True)])
        self.assertEqual(traceroute.classify(hops, "192.168.1.10")[0], "unreachable")

    def test_linux_complete_with_multiple_ips_per_hop(self) -> None:
        hops = traceroute.parse_traceroute_output(fixture("traceroute_linux_complete.txt"))
        self.assertEqual(hops, [
            hop(1, "192.168.1.1", [0.512, 0.48, 0.455]),
            hop(2, None, [None, None, None]),
            hop(3, "10.20.0.1", [9.104, 9.311, 9.502]),
            hop(4, "8.8.8.8", [12.118, 12.004, 11.987]),
        ])
        self.assertEqual(traceroute.classify(hops, "8.8.8.8")[0], "ok")

    def test_linux_unreachable_flags(self) -> None:
        hops = traceroute.parse_traceroute_output(fixture("traceroute_linux_unreachable.txt"))
        self.assertEqual(hops, [hop(1, "192.168.1.5", [3005.112, 3005.02, None], True)])
        self.assertEqual(traceroute.classify(hops, "192.168.1.10")[0], "unreachable")

    def test_header_lines_are_not_hops(self) -> None:
        self.assertEqual(traceroute.parse_traceroute_output("traceroute to x (1.2.3.4), 30 hops max\n"), [])
        self.assertEqual(traceroute.classify([], "1.2.3.4")[0], "error")


class TracerouteTests(unittest.TestCase):
    def test_success(self) -> None:
        fake = CommandResult(("tracert",), 0, fixture("tracert_windows_complete.txt"), "")
        with mock.patch.object(traceroute.sys, "platform", "win32"), \
                mock.patch.object(traceroute, "run_command", return_value=fake) as run:
            result = traceroute.traceroute("8.8.8.8", max_hops=30)
        self.assertTrue(result.ok)
        self.assertEqual(result.details["status"], "ok")
        self.assertEqual(len(result.details["hops"]), 4)
        self.assertEqual(run.call_args.args[0][0], "tracert")

    def test_incomplete_is_failure(self) -> None:
        fake = CommandResult(("traceroute",), 0, fixture("tracert_windows_incomplete.txt"), "")
        with mock.patch.object(traceroute, "run_command", return_value=fake):
            result = traceroute.traceroute("203.0.113.9")
        self.assertFalse(result.ok)
        self.assertEqual(result.details["status"], "incomplete")

    def test_tool_error_uses_stderr(self) -> None:
        fake = CommandResult(("traceroute",), 1, "", "connect: Network is unreachable\n")
        with mock.patch.object(traceroute, "run_command", return_value=fake):
            result = traceroute.traceroute("8.8.8.8")
        self.assertEqual(result.details["status"], "error")
        self.assertEqual(result.error, "connect: Network is unreachable")

    def test_dns_failure(self) -> None:
        with mock.patch.object(traceroute.dns, "first_address", side_effect=socket.gaierror("x")), \
                mock.patch.object(traceroute, "run_command") as run:
            result = traceroute.traceroute("nosuch.example")
        run.assert_not_called()
        self.assertEqual(result.details["status"], "dns_failure")
        self.assertEqual(result.details["hops"], [])

    def test_missing_tool(self) -> None:
        with mock.patch.object(traceroute, "run_command",
                               side_effect=CommandNotFoundError("required tool not found on PATH: traceroute")):
            result = traceroute.traceroute("127.0.0.1")
        self.assertFalse(result.ok)
        self.assertEqual(result.details, {"status": "tool_missing", "address": "127.0.0.1",
                                          "hops": [], "raw_output": ""})
        self.assertEqual(result.error, "required tool not found on PATH: traceroute")

    def test_command_timeout(self) -> None:
        with mock.patch.object(traceroute, "run_command", side_effect=CommandTimeoutError("t/o")):
            result = traceroute.traceroute("8.8.8.8")
        self.assertFalse(result.ok)
        self.assertEqual(result.details["status"], "timeout")


if __name__ == "__main__":
    unittest.main()
