# NetProbe

Network diagnostic CLI in Python: ping, traceroute, DNS lookup, TCP connectivity, network
interfaces and combined diagnostic reports. Standard library only; supports Windows and Linux.

## Requirements

- Python 3.10 or newer.
- **Windows** 8 / Server 2012 or newer: uses the built-in `ping.exe`, `tracert.exe` and Windows
  PowerShell (`Get-NetAdapter`, CIM) for interface information.
- **Linux**: `ping` (iputils or BusyBox), `traceroute` and `ip` from iproute2 4.14+.
  `traceroute` is often not installed by default (e.g. Ubuntu: `sudo apt install traceroute`).
  Without it, `trace` reports `status: tool_missing` instead of failing.
- macOS is not supported.

## Installation

```
pip install .
```

This installs the `netprobe` command. Without installing, run it from the repository root with
`PYTHONPATH=src python -m netprobe ...` (PowerShell: `$env:PYTHONPATH="src"; python -m netprobe ...`).

## Usage

```
netprobe ping example.com -c 4
netprobe trace example.com -m 20
netprobe dns example.com --json
netprobe tcp example.com 443                 # or: netprobe tcp example.com -p 443
netprobe iface
netprobe report example.com                  # dns, ping, tcp 80/443, trace, iface
netprobe report example.com -c dns tcp -p 22 -p 443 --json
netprobe report -c iface                     # no host needed
```

Run `netprobe <command> --help` for all options.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | all checks passed |
| `1` | at least one check failed, or a runtime error |
| `2` | invalid usage (bad host, port, option or missing argument) |

### JSON output

`--json` prints ASCII-only JSON (non-ASCII text is `\uXXXX`-escaped), so it stays valid
whatever console code page or redirection is used.

- Single commands print a list of results: `[{"check", "target", "ok", "details", "error", "duration_ms"}]`.
- `report` prints `{"target", "generated_at", "summary", "results"}`; `summary` holds `total`,
  `passed`, `failed`, `duration_ms` (sum of the check durations) and `failed_checks`.
- `ping` and `trace` results carry `details.status`:
  - ping: `ok`, `timeout`, `unreachable`, `dns_failure`, `tool_missing`, `error`
  - trace: `ok`, `incomplete`, `unreachable`, `timeout`, `dns_failure`, `tool_missing`, `error`

  Other checks report failure through `ok` and `error` only.

## Features and limits

| Feature | Details |
|---|---|
| Ping | sent, received, packet loss, min/avg/max latency. Windows output is parsed by structure, so localized Windows versions work (tested with English and German output). |
| Traceroute | hops with IP and per-probe RTT (`*` = no reply). Windows `<1 ms` is reported as `1`. |
| DNS | A/AAAA records through the OS resolver (no MX/TXT, no custom DNS server). |
| TCP | whether a connection to host:port can be opened. |
| Interfaces | name, up/down, loopback flag, MAC, IPv4/IPv6 with prefix length. |
| Report | runs the selected checks in order; a failing check never stops the others. |

- Hostnames must be ASCII (RFC 1123); internationalized domain names are rejected.
- On Linux, ping/traceroute timeouts are whole seconds (fractions are truncated, minimum 1 s).

## Security

- System tools are always run with an argument list and `shell=False`; hosts are validated
  before use, and a host can never be read as a command-line option.
- On Windows, tools are looked up only as `.exe` files in absolute `PATH` directories, never
  in the current directory, so a planted `ping.bat` cannot be executed.

## Development

```
pip install -e ".[dev]"
pytest
```

Without installing anything, from the repository root:

```
PYTHONPATH=src python -m unittest discover -s tests
```

PowerShell: `$env:PYTHONPATH="src"; python -m unittest discover -s tests`

Tests use saved tool output (`tests/fixtures/`) and mocks; they need no network access.

## Layout

```
src/netprobe/
  cli.py          argparse entry point and exit codes
  validation.py   host/port/range validation (trust boundary)
  runner.py       the only subprocess call site (tool lookup, shell=False, timeout, decoding)
  models.py       CheckResult, returned by every diagnostic
  report.py       text / JSON rendering and multi-check reports
  errors.py       NetProbeError hierarchy
  diagnostics/    ping, traceroute, dns, tcp, interfaces
tests/
```

## License

MIT, see [LICENSE](LICENSE).
