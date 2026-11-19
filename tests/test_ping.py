import socket
import unittest
from pathlib import Path
from unittest import mock

from netprobe.diagnostics import ping
from netprobe.errors import CommandNotFoundError, CommandTimeoutError, InvalidTargetError
from netprobe.runner import CommandResult

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


class BuildCommandTests(unittest.TestCase):
    def test_windows(self) -> None:
        self.assertEqual(ping.build_ping_command("1.1.1.1", 3, 1.5, "win32"),
                         ["ping", "-n", "3", "-w", "1500", "1.1.1.1"])

    def test_linux(self) -> None:
        self.assertEqual(ping.build_ping_command("1.1.1.1", 3, 1.5, "linux"),
                         ["ping", "-c", "3", "-W", "1", "1.1.1.1"])


class ParseTests(unittest.TestCase):
    cases = {
        # fixture: (platform, sent, received, loss, min, avg, max, status)
        "ping_windows_success.txt": ("win32", 4, 4, 0.0, 12.0, 13.0, 15.0, "ok"),
        "ping_windows_partial.txt": ("win32", 4, 2, 50.0, 20.0, 21.0, 22.0, "ok"),
        "ping_windows_timeout.txt": ("win32", 4, 0, 100.0, None, None, None, "timeout"),
        "ping_windows_unreachable.txt": ("win32", 4, 0, 100.0, None, None, None, "unreachable"),
        "ping_windows_ipv6.txt": ("win32", 2, 2, 0.0, 0.0, 0.0, 0.0, "ok"),
        "ping_windows_german.txt": ("win32", 3, 2, 33.3, 11.0, 12.0, 13.0, "ok"),
        "ping_windows_dns_failure.txt": ("win32", None, None, None, None, None, None, "error"),
        "ping_linux_success.txt": ("linux", 4, 4, 0.0, 11.8, 12.275, 12.9, "ok"),
        "ping_linux_partial.txt": ("linux", 4, 3, 25.0, 20.4, 21.333, 22.6, "ok"),
        "ping_linux_timeout.txt": ("linux", 4, 0, 100.0, None, None, None, "timeout"),
        "ping_linux_unreachable.txt": ("linux", 4, 0, 100.0, None, None, None, "unreachable"),
        "ping_busybox_success.txt": ("linux", 2, 2, 0.0, 0.061, 0.077, 0.094, "ok"),
    }

    def test_fixtures(self) -> None:
        for name, (platform, sent, received, loss, low, avg, high, status) in self.cases.items():
            with self.subTest(fixture=name):
                output = fixture(name)
                stats = ping.parse_ping_output(output, platform)
                self.assertEqual(
                    (stats["sent"], stats["received"], stats["packet_loss"],
                     stats["min_ms"], stats["avg_ms"], stats["max_ms"]),
                    (sent, received, loss, low, avg, high),
                )
                self.assertEqual(ping.classify(stats, output, 1)[0], status)

    def test_empty_output(self) -> None:
        stats = ping.parse_ping_output("", "linux")
        self.assertEqual(stats, ping.empty_stats())
        self.assertEqual(ping.classify(stats, "", 2), ("error", "ping exited with code 2"))


class PingTests(unittest.TestCase):
    def run_ping(self, name: str, platform: str, host: str = "8.8.8.8", returncode: int = 0,
                 stderr: str = ""):
        fake = CommandResult(("ping",), returncode, fixture(name), stderr)
        with mock.patch.object(ping.sys, "platform", platform), \
                mock.patch.object(ping, "run_command", return_value=fake) as run:
            return ping.ping(host, count=4), run

    def test_success(self) -> None:
        result, run = self.run_ping("ping_windows_success.txt", "win32")
        self.assertTrue(result.ok)
        self.assertIsNone(result.error)
        self.assertEqual(result.details["status"], "ok")
        self.assertEqual(result.details["address"], "8.8.8.8")
        self.assertEqual(result.details["avg_ms"], 13.0)
        self.assertIn("Reply from", result.details["raw_output"])
        self.assertEqual(run.call_args.args[0], ["ping", "-n", "4", "-w", "2000", "8.8.8.8"])

    def test_windows_unreachable_with_exit_code_zero_is_failure(self) -> None:
        result, _ = self.run_ping("ping_windows_unreachable.txt", "win32", returncode=0)
        self.assertFalse(result.ok)
        self.assertEqual(result.details["status"], "unreachable")
        self.assertEqual(result.error, "destination unreachable")

    def test_linux_timeout(self) -> None:
        result, _ = self.run_ping("ping_linux_timeout.txt", "linux", returncode=1)
        self.assertFalse(result.ok)
        self.assertEqual(result.details["status"], "timeout")
        self.assertEqual(result.details["packet_loss"], 100.0)

    def test_tool_error_uses_stderr(self) -> None:
        fake = CommandResult(("ping",), 2, "", "ping: sendmsg: Network is unreachable\n")
        with mock.patch.object(ping, "run_command", return_value=fake):
            result = ping.ping("8.8.8.8")
        self.assertEqual(result.details["status"], "error")
        self.assertEqual(result.error, "ping: sendmsg: Network is unreachable")

    def test_hostname_is_resolved_before_ping(self) -> None:
        fake = CommandResult(("ping",), 0, fixture("ping_linux_success.txt"), "")
        with mock.patch.object(ping.dns, "first_address", return_value="8.8.8.8"), \
                mock.patch.object(ping.sys, "platform", "linux"), \
                mock.patch.object(ping, "run_command", return_value=fake) as run:
            result = ping.ping("dns.google")
        self.assertEqual(result.target, "dns.google")
        self.assertEqual(result.details["address"], "8.8.8.8")
        self.assertEqual(run.call_args.args[0][-1], "8.8.8.8")

    def test_dns_failure_does_not_run_ping(self) -> None:
        with mock.patch.object(ping.dns, "first_address", side_effect=socket.gaierror("not known")), \
                mock.patch.object(ping, "run_command") as run:
            result = ping.ping("nosuch.example")
        run.assert_not_called()
        self.assertFalse(result.ok)
        self.assertEqual(result.details["status"], "dns_failure")
        self.assertIn("cannot resolve nosuch.example", result.error)
        self.assertIsNone(result.details["sent"])

    def test_command_timeout_is_a_result_not_a_crash(self) -> None:
        with mock.patch.object(ping, "run_command", side_effect=CommandTimeoutError("ping timed out")):
            result = ping.ping("8.8.8.8")
        self.assertFalse(result.ok)
        self.assertEqual(result.details["status"], "timeout")
        self.assertEqual(result.error, "ping timed out")

    def test_missing_tool_is_a_result_not_a_crash(self) -> None:
        with mock.patch.object(ping, "run_command",
                               side_effect=CommandNotFoundError("required tool not found on PATH: ping")):
            result = ping.ping("8.8.8.8")
        self.assertFalse(result.ok)
        self.assertEqual(result.details["status"], "tool_missing")
        self.assertEqual(set(result.details), {"status", "address", "sent", "received", "packet_loss",
                                               "min_ms", "avg_ms", "max_ms", "raw_output"})
        self.assertEqual(result.error, "required tool not found on PATH: ping")

    def test_invalid_host_never_reaches_runner(self) -> None:
        with mock.patch.object(ping, "run_command") as run, self.assertRaises(InvalidTargetError):
            ping.ping("-t evil")
        run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
