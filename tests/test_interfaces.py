import json
import unittest
from pathlib import Path
from unittest import mock

from netprobe.diagnostics import interfaces
from netprobe.errors import CommandNotFoundError, CommandTimeoutError
from netprobe.runner import CommandResult

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def iface(name, status, mac=None, ipv4=(), ipv6=(), loopback=False):
    return {"name": name, "status": status, "loopback": loopback, "mac": mac,
            "ipv4": list(ipv4), "ipv6": list(ipv6)}


WINDOWS_EXPECTED = [
    iface("شبكة Wi-Fi", "up", "02:11:22:00:00:18", ["192.168.1.20/24"], ["fe80::1234:5678:9abc:def0/64"]),
    iface("Ethernet", "down", "00:15:5d:00:00:01"),
    iface("Wi-Fi 3", "down"),
    # hidden adapter kept because it has an address; its real status (down) wins
    iface("Wi-Fi 2", "down", "02:11:22:00:00:1a", ["169.254.10.20/16"]),
    iface("Loopback Pseudo-Interface 1", "up", None, ["127.0.0.1/8"], ["::1/128"], loopback=True),
]

LINUX_EXPECTED = [
    iface("lo", "up", None, ["127.0.0.1/8"], ["::1/128"], loopback=True),
    iface("eth0", "up", "52:54:00:12:34:56", ["10.0.2.15/24"], ["fe80::5054:ff:fe12:3456/64"]),
    iface("wlan0", "down", "aa:bb:cc:dd:ee:ff"),
    iface("tun0", "up", None, ["10.8.0.2/24"]),
]


class BuildCommandTests(unittest.TestCase):
    def test_windows_uses_constant_powershell_script(self) -> None:
        cmd = interfaces.build_interfaces_command("win32")
        self.assertEqual(cmd[:4], ["powershell", "-NoProfile", "-NonInteractive", "-Command"])
        self.assertIn("Get-NetAdapter -IncludeHidden", cmd[4])

    def test_linux(self) -> None:
        self.assertEqual(interfaces.build_interfaces_command("linux"), ["ip", "-j", "addr", "show"])


class ParseTests(unittest.TestCase):
    def test_windows(self) -> None:
        self.assertEqual(interfaces.parse_windows(json.loads(fixture("interfaces_windows.json"))),
                         WINDOWS_EXPECTED)

    def test_windows_single_objects_instead_of_arrays(self) -> None:
        data = {"adapters": {"Name": "Ethernet", "InterfaceIndex": 7, "InterfaceOperationalStatus": 1,
                             "PermanentAddress": "00-15-5D-00-00-01", "NetworkAddresses": "00155D000002"},
                "addresses": {"InterfaceIndex": 7, "InterfaceAlias": "Ethernet",
                              "IPAddress": "10.1.1.5", "PrefixLength": 16}}
        self.assertEqual(interfaces.parse_windows(data),
                         [iface("Ethernet", "up", "00:15:5d:00:00:02", ["10.1.1.5/16"])])

    def test_linux(self) -> None:
        self.assertEqual(interfaces.parse_linux(json.loads(fixture("interfaces_linux.json"))),
                         LINUX_EXPECTED)

    def test_mac_normalization(self) -> None:
        for raw, expected in [("00-15-5D-AB-CD-EF", "00:15:5d:ab:cd:ef"), ("001122334455", "00:11:22:33:44:55"),
                              ("00:00:00:00:00:00", None), ("", None), (None, None), ("12:34", None)]:
            with self.subTest(raw=raw):
                self.assertEqual(interfaces._normalize_mac(raw), expected)


class ListInterfacesTests(unittest.TestCase):
    def run_with(self, platform: str, **kwargs):
        with mock.patch.object(interfaces.sys, "platform", platform), \
                mock.patch.object(interfaces, "run_command", **kwargs) as run:
            return interfaces.list_interfaces(), run

    def test_windows_success_with_bom(self) -> None:
        fake = CommandResult(("powershell",), 0, "\ufeff" + fixture("interfaces_windows.json"), "")
        result, run = self.run_with("win32", return_value=fake)
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.check, "interfaces")
        self.assertEqual(result.details["interfaces"], WINDOWS_EXPECTED)
        self.assertEqual(run.call_args.args[0][0], "powershell")

    def test_linux_success(self) -> None:
        fake = CommandResult(("ip",), 0, fixture("interfaces_linux.json"), "")
        result, _ = self.run_with("linux", return_value=fake)
        self.assertTrue(result.ok)
        self.assertEqual(result.details["interfaces"], LINUX_EXPECTED)

    def test_tool_error(self) -> None:
        fake = CommandResult(("ip",), 255, "", 'Option "-j" is unknown, try "ip -help".\n')
        result, _ = self.run_with("linux", return_value=fake)
        self.assertFalse(result.ok)
        self.assertEqual(result.error, 'Option "-j" is unknown, try "ip -help".')
        self.assertEqual(result.details["interfaces"], [])

    def test_garbage_output(self) -> None:
        for output in ("not json", '{"unexpected": 1', '[{"no_ifname": true}]'):
            with self.subTest(output=output):
                result, _ = self.run_with("linux", return_value=CommandResult(("ip",), 0, output, ""))
                self.assertFalse(result.ok)
                self.assertIn("unexpected interface data", result.error)

    def test_empty_list(self) -> None:
        result, _ = self.run_with("linux", return_value=CommandResult(("ip",), 0, "[]", ""))
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "no network interfaces found")

    def test_missing_tool(self) -> None:
        result, _ = self.run_with("linux", side_effect=CommandNotFoundError("required tool not found on PATH: ip"))
        self.assertFalse(result.ok)
        self.assertEqual(result.details, {"interfaces": []})
        self.assertEqual(result.error, "required tool not found on PATH: ip")

    def test_timeout(self) -> None:
        result, _ = self.run_with("win32", side_effect=CommandTimeoutError("powershell timed out"))
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "powershell timed out")


if __name__ == "__main__":
    unittest.main()
