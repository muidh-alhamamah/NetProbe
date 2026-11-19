import contextlib
import io
import json
import socket
import unittest
from pathlib import Path
from unittest import mock

from netprobe.cli import main
from netprobe.diagnostics import dns, interfaces, ping, tcp, traceroute
from netprobe.models import CheckResult
from netprobe.runner import CommandResult

FIXTURES = Path(__file__).parent / "fixtures"


def run(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as exc:  # argparse usage errors
            code = int(exc.code or 0)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def test_tcp_json_success(self) -> None:
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            code, out, _ = run(["tcp", "127.0.0.1", str(port), "--json"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)[0]["ok"])

    def test_dns_text(self) -> None:
        code, out, _ = run(["dns", "localhost"])
        self.assertEqual(code, 0)
        self.assertIn("[OK  ] dns localhost", out)

    def test_invalid_host_is_usage_error(self) -> None:
        code, _, err = run(["ping", "a;whoami"])
        self.assertEqual(code, 2)
        self.assertIn("invalid host", err)

    def test_tcp_port_option_and_positional(self) -> None:
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(5)  # connections are never accepted, so the backlog must fit all three
            port = str(server.getsockname()[1])
            for argv in (["tcp", "127.0.0.1", "-p", port], ["tcp", "127.0.0.1", "--port", port],
                         ["tcp", "127.0.0.1", port]):
                with self.subTest(argv=argv):
                    code, out, _ = run([*argv, "--json"])
                    self.assertEqual(code, 0)
                    self.assertEqual(json.loads(out)[0]["target"], f"127.0.0.1:{port}")

    def test_tcp_port_missing_or_given_twice(self) -> None:
        for argv in (["tcp", "127.0.0.1"], ["tcp", "127.0.0.1", "80", "-p", "80"]):
            with self.subTest(argv=argv):
                code, _, err = run(argv)
                self.assertEqual(code, 2)
                self.assertIn("give the port once", err)
        self.assertEqual(run(["tcp", "127.0.0.1", "-p", "70000"])[0], 2)

    def test_invalid_port_is_usage_error(self) -> None:
        self.assertEqual(run(["tcp", "localhost", "70000"])[0], 2)
        self.assertEqual(run(["tcp", "localhost", "http"])[0], 2)

    def test_out_of_range_option(self) -> None:
        self.assertEqual(run(["ping", "localhost", "-c", "0"])[0], 2)

    def test_trace_json_when_tool_missing(self) -> None:
        # lookup finds nothing -> the real runner raises CommandNotFoundError
        with mock.patch("netprobe.runner.find_executable", return_value=None):
            code, out, err = run(["trace", "127.0.0.1", "--json"])
        self.assertEqual(code, 1)
        self.assertEqual(err, "")
        [result] = json.loads(out)
        self.assertEqual(result["details"]["status"], "tool_missing")
        self.assertIn("not found on PATH", result["error"])

    def test_report_usage_errors(self) -> None:
        code, _, err = run(["report"])
        self.assertEqual(code, 2)
        self.assertIn("a host is required", err)
        self.assertEqual(run(["report", "localhost", "--checks", "bogus"])[0], 2)
        self.assertEqual(run(["report", "localhost", "-p", "0"])[0], 2)

    def test_report_text_with_partial_failure(self) -> None:
        ok = CheckResult("dns", "example.com", True, {"addresses": ["192.0.2.1"]}, None, 5.0)
        with mock.patch.object(dns, "resolve", return_value=ok), \
                mock.patch.object(tcp, "check_tcp", side_effect=lambda h, p: CheckResult(
                    "tcp", f"{h}:{p}", p == 443, {}, None if p == 443 else "refused", 10.0)):
            code, out, _ = run(["report", "example.com", "-c", "dns", "tcp", "-p", "22", "-p", "443"])
        self.assertEqual(code, 1)
        self.assertIn("NetProbe report for example.com", out)
        self.assertIn("Summary: 2/3 passed, 1 failed (25 ms)", out)
        self.assertIn("  failed: tcp example.com:22", out)
        self.assertIn("[OK  ] tcp example.com:443", out)
        self.assertIn("error: refused", out)

    def test_report_iface_only_json_needs_no_host(self) -> None:
        fake = CommandResult(("ip",), 0, (FIXTURES / "interfaces_linux.json").read_text("utf-8"), "")
        with mock.patch.object(interfaces.sys, "platform", "linux"), \
                mock.patch.object(interfaces, "run_command", return_value=fake):
            code, out, _ = run(["report", "--checks", "iface", "--json"])
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertIsNone(report["target"])
        self.assertEqual(report["summary"]["passed"], 1)
        self.assertEqual(report["results"][0]["check"], "interfaces")

    def test_iface_text_and_json(self) -> None:
        fake = CommandResult(("ip",), 0, (FIXTURES / "interfaces_linux.json").read_text("utf-8"), "")
        with mock.patch.object(interfaces.sys, "platform", "linux"), \
                mock.patch.object(interfaces, "run_command", return_value=fake):
            code, out, _ = run(["iface"])
            json_code, json_out, _ = run(["iface", "--json"])
        self.assertEqual((code, json_code), (0, 0))
        self.assertIn("[OK  ] interfaces local", out)
        self.assertIn("name=lo status=up loopback=True ipv4=127.0.0.1/8 ipv6=::1/128", out)
        self.assertIn("name=wlan0 status=down mac=aa:bb:cc:dd:ee:ff", out)
        self.assertEqual(json.loads(json_out)[0]["details"]["interfaces"][1]["name"], "eth0")

    def test_no_command(self) -> None:
        self.assertEqual(run([])[0], 2)

    def test_ping_json_and_text(self) -> None:
        fake = CommandResult(("ping",), 0, (FIXTURES / "ping_linux_partial.txt").read_text("utf-8"), "")
        with mock.patch.object(ping.sys, "platform", "linux"), \
                mock.patch.object(ping, "run_command", return_value=fake):
            code, out, _ = run(["ping", "203.0.113.7", "--json"])
            text_code, text, _ = run(["ping", "203.0.113.7"])
        self.assertEqual(code, 0)
        details = json.loads(out)[0]["details"]
        self.assertEqual((details["sent"], details["received"], details["packet_loss"]), (4, 3, 25.0))
        self.assertIn("raw_output", details)
        self.assertEqual(text_code, 0)
        self.assertIn("packet_loss: 25", text)
        self.assertNotIn("raw_output", text)

    def test_trace_failure_exit_code_and_hops_text(self) -> None:
        fake = CommandResult(("tracert",), 0,
                             (FIXTURES / "tracert_windows_incomplete.txt").read_text("utf-8"), "")
        with mock.patch.object(traceroute, "run_command", return_value=fake):
            code, out, _ = run(["trace", "203.0.113.9"])
        self.assertEqual(code, 1)
        self.assertIn("[FAIL] traceroute 203.0.113.9", out)
        self.assertIn("hop=2 address=10.20.0.1 rtts_ms=8 * 9", out)
        self.assertIn("hop=3 rtts_ms=* * *", out)


if __name__ == "__main__":
    unittest.main()
