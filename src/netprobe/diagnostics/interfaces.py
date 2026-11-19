"""Local network interface information.

Both platforms ask the OS for JSON, so nothing depends on the display language:
  Windows: Get-NetAdapter + CIM MSFT_NetIPAddress via PowerShell (numeric enums)
  Linux:   `ip -j addr` (iproute2)
"""

from __future__ import annotations

import ipaddress
import json
import re
import sys
import time
from typing import Any

from netprobe.errors import CommandNotFoundError, CommandTimeoutError
from netprobe.models import CheckResult
from netprobe.runner import run_command

# Constant script, no user input. Get-NetAdapter -IncludeHidden is needed because plain CIM queries
# skip hidden adapters that may still hold addresses; CIM for addresses avoids loading another module.
_PS_SCRIPT = (
    "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; "
    "$ns = 'root/StandardCimv2'; "
    "@{ adapters = @(Get-NetAdapter -IncludeHidden | "
    "Select-Object Name, InterfaceIndex, InterfaceOperationalStatus, PermanentAddress, NetworkAddresses, Hidden); "
    "addresses = @(Get-CimInstance -Namespace $ns MSFT_NetIPAddress | "
    "Select-Object InterfaceIndex, InterfaceAlias, IPAddress, PrefixLength) } "
    "| ConvertTo-Json -Depth 3 -Compress"
)
_IF_OPER_STATUS_UP = 1  # IF_OPER_STATUS enum: 1 up, 2 down, ..., 6 not present, 7 lower layer down


def build_interfaces_command(platform: str | None = None) -> list[str]:
    if (platform or sys.platform) == "win32":
        return ["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS_SCRIPT]
    # shortcut: `ip -j` needs iproute2 >= 4.14 (2017); parse plain `ip addr` if older distros matter.
    return ["ip", "-j", "addr", "show"]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _normalize_mac(mac: str | None) -> str | None:
    digits = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    if len(digits) != 12 or int(digits, 16) == 0:
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def _interface(name: str, up: bool, mac: str | None) -> dict[str, Any]:
    # Windows prefixes RTL names with invisible direction marks.
    return {"name": name.strip("\u200e\u200f "), "status": "up" if up else "down",
            "loopback": False, "mac": _normalize_mac(mac), "ipv4": [], "ipv6": []}


def _add_address(iface: dict[str, Any], address: str | None, prefix: int | None) -> None:
    if not address:
        return
    address = address.split("%")[0]  # drop IPv6 zone id ("fe80::1%37")
    ip = ipaddress.ip_address(address)
    iface["ipv4" if ip.version == 4 else "ipv6"].append(f"{address}/{prefix}" if prefix is not None else address)
    iface["loopback"] = iface["loopback"] or ip.is_loopback


def parse_windows(data: dict[str, Any]) -> list[dict[str, Any]]:
    addresses = _as_list(data.get("addresses"))
    indexes_with_addresses = {addr["InterfaceIndex"] for addr in addresses}
    by_index: dict[int, dict[str, Any]] = {}
    for adapter in _as_list(data.get("adapters")):
        index = adapter["InterfaceIndex"]
        # Hidden adapters (Wi-Fi Direct, Teredo, ...) are noise unless they carry an address.
        if adapter.get("Hidden") and index not in indexes_with_addresses:
            continue
        mac = (_as_list(adapter.get("NetworkAddresses")) or [adapter.get("PermanentAddress")])[0]
        by_index[index] = _interface(
            adapter["Name"], adapter.get("InterfaceOperationalStatus") == _IF_OPER_STATUS_UP, mac)
    for addr in addresses:
        index = addr["InterfaceIndex"]
        if index not in by_index:
            # Only the loopback pseudo-interface has no NetAdapter; it is always up.
            by_index[index] = _interface(addr["InterfaceAlias"], True, None)
        _add_address(by_index[index], addr.get("IPAddress"), addr.get("PrefixLength"))
    return list(by_index.values())


def parse_linux(data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    interfaces = []
    for link in _as_list(data):
        flags = link.get("flags", [])
        # Loopback reports operstate UNKNOWN; LOWER_UP means the link is actually up.
        iface = _interface(link["ifname"], link.get("operstate") == "UP" or "LOWER_UP" in flags,
                           link.get("address"))
        iface["loopback"] = "LOOPBACK" in flags
        for addr in link.get("addr_info", []):
            _add_address(iface, addr.get("local"), addr.get("prefixlen"))
        interfaces.append(iface)
    return interfaces


def list_interfaces() -> CheckResult:
    start = time.perf_counter()
    windows = sys.platform == "win32"

    def result(interfaces: list[dict[str, Any]], error: str | None) -> CheckResult:
        return CheckResult("interfaces", "local", error is None, {"interfaces": interfaces}, error,
                           (time.perf_counter() - start) * 1000)

    try:
        cmd = run_command(build_interfaces_command(), timeout=30)
    except (CommandTimeoutError, CommandNotFoundError) as exc:
        return result([], str(exc))
    if cmd.returncode != 0:
        lines = (cmd.stderr or cmd.stdout).strip().splitlines()
        return result([], lines[-1].strip() if lines else f"exited with code {cmd.returncode}")
    try:
        data = json.loads(cmd.stdout.lstrip("\ufeff"))
        interfaces = parse_windows(data) if windows else parse_linux(data)
    except (ValueError, KeyError, TypeError, AttributeError) as exc:  # JSONDecodeError is a ValueError
        return result([], f"unexpected interface data: {exc}")
    return result(interfaces, None if interfaces else "no network interfaces found")
