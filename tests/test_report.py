import json
import unittest
from pathlib import Path
from unittest import mock

from netprobe import report
from netprobe.errors import CommandNotFoundError
from netprobe.models import CheckResult
from netprobe.runner import CommandResult

FIXTURES = Path(__file__).parent / "fixtures"


def ok(check, target, ms=10.0):
    return CheckResult(check, target, True, {}, None, ms)


class RunReportTests(unittest.TestCase):
    def setUp(self) -> None:
        patches = {
            "dns": mock.patch.object(report.dns, "resolve", side_effect=lambda h: ok("dns", h)),
            "ping": mock.patch.object(report.ping, "ping", side_effect=lambda h: ok("ping", h)),
            "tcp": mock.patch.object(report.tcp, "check_tcp", side_effect=lambda h, p: ok("tcp", f"{h}:{p}")),
            "trace": mock.patch.object(report.traceroute, "traceroute", side_effect=lambda h: ok("traceroute", h)),
            "iface": mock.patch.object(report.interfaces, "list_interfaces", side_effect=lambda: ok("interfaces", "local")),
        }
        self.mocks = {name: p.start() for name, p in patches.items()}
        self.addCleanup(mock.patch.stopall)

    def test_default_runs_every_check_with_default_ports(self) -> None:
        results = report.run_report("example.com")
        self.assertEqual([f"{r.check} {r.target}" for r in results], [
            "dns example.com", "ping example.com", "tcp example.com:80", "tcp example.com:443",
            "traceroute example.com", "interfaces local",
        ])
        self.assertTrue(all(r.ok for r in results))

    def test_selected_checks_in_given_order_deduplicated(self) -> None:
        results = report.run_report("h.com", ["tcp", "dns", "tcp"], ports=[22, 22])
        self.assertEqual([f"{r.check} {r.target}" for r in results], ["tcp h.com:22", "dns h.com"])
        self.mocks["ping"].assert_not_called()
        self.mocks["trace"].assert_not_called()

    def test_raising_check_becomes_failed_result_and_report_continues(self) -> None:
        self.mocks["ping"].side_effect = CommandNotFoundError("required tool not found on PATH: ping")
        self.mocks["iface"].side_effect = RuntimeError()
        results = report.run_report("h.com", ["ping", "dns", "iface"])
        self.assertEqual([r.ok for r in results], [False, True, False])
        self.assertEqual(results[0].check, "ping")
        self.assertEqual(results[0].error, "required tool not found on PATH: ping")
        self.assertEqual(results[2].error, "RuntimeError")
        self.assertIsNotNone(results[0].duration_ms)

    def test_unknown_check(self) -> None:
        with self.assertRaises(ValueError):
            report.run_report("h.com", ["bogus"])


class WiringTests(unittest.TestCase):
    def test_real_ping_module_with_fixture_output(self) -> None:
        fake = CommandResult(("ping",), 1, (FIXTURES / "ping_linux_timeout.txt").read_text("utf-8"), "")
        with mock.patch.object(report.ping.sys, "platform", "linux"), \
                mock.patch.object(report.ping, "run_command", return_value=fake):
            [result] = report.run_report("10.255.255.1", ["ping"])
        self.assertFalse(result.ok)
        self.assertEqual(result.details["status"], "timeout")


class RenderTests(unittest.TestCase):
    results = [
        CheckResult("dns", "h.com", True, {"addresses": ["192.0.2.1"]}, None, 12.0),
        CheckResult("ping", "h.com", False, {"status": "timeout"}, "no reply", 3000.0),
        CheckResult("tcp", "h.com:443", True, {"peer": "192.0.2.1"}, None, None),
    ]

    def test_summary(self) -> None:
        self.assertEqual(report.summarize(self.results), {
            "total": 3, "passed": 2, "failed": 1, "duration_ms": 3012.0, "failed_checks": ["ping h.com"],
        })

    def test_json(self) -> None:
        data = json.loads(report.render_report_json("h.com", self.results))
        self.assertEqual(set(data), {"target", "generated_at", "summary", "results"})
        self.assertEqual(data["target"], "h.com")
        self.assertEqual(data["summary"]["failed"], 1)
        self.assertEqual(data["results"][1]["error"], "no reply")

    def test_text(self) -> None:
        text = report.render_report_text("h.com", self.results)
        self.assertTrue(text.startswith("NetProbe report for h.com ("))
        self.assertIn("Summary: 2/3 passed, 1 failed (3012 ms)", text)
        self.assertIn("  failed: ping h.com", text)
        self.assertIn("[FAIL] ping h.com (3000 ms)\n  status: timeout\n  error: no reply", text)
        self.assertIn("[OK  ] tcp h.com:443\n", text)

    def test_json_is_ascii_and_lossless_for_non_ascii_names(self) -> None:
        results = [CheckResult("interfaces", "local", True, {"interfaces": [{"name": "شبكة Wi-Fi"}]})]
        for output in (report.render_json(results), report.render_report_json(None, results)):
            output.encode("ascii")  # raises if any non-ASCII byte would depend on the code page
            self.assertIn("شبكة Wi-Fi", json.dumps(json.loads(output), ensure_ascii=False))

    def test_text_without_target(self) -> None:
        self.assertIn("NetProbe report for local machine", report.render_report_text(None, []))


if __name__ == "__main__":
    unittest.main()
