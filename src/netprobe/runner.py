"""The only place NetProbe starts external processes.

Commands are always an argument list run with shell=False, so user input is never
interpreted by a shell.
"""

from __future__ import annotations

import codecs
import locale
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass

from netprobe.errors import CommandNotFoundError, CommandTimeoutError


@dataclass(frozen=True)
class CommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


def run_command(args: Sequence[str], timeout: float = 30.0) -> CommandResult:
    if not args:
        raise ValueError("args must not be empty")
    executable = find_executable(args[0])
    if executable is None:
        raise CommandNotFoundError(f"required tool not found on PATH: {args[0]}")
    argv = [executable, *args[1:]]
    # On POSIX force the C locale so tool output is English and parseable.
    # Windows tools cannot be forced; parsers there rely on numbers/structure, not words.
    env = None if sys.platform == "win32" else {**os.environ, "LC_ALL": "C"}
    try:
        proc = subprocess.run(
            argv, capture_output=True, timeout=timeout, check=False, shell=False, env=env
        )
    except subprocess.TimeoutExpired as exc:
        raise CommandTimeoutError(f"{args[0]} timed out after {timeout}s") from exc
    return CommandResult(tuple(argv), proc.returncode, decode_output(proc.stdout), decode_output(proc.stderr))


def find_executable(name: str) -> str | None:
    """Locate a system tool. On Windows only absolute PATH entries and only .exe files are used."""
    if sys.platform != "win32":
        return shutil.which(name)
    if os.path.isabs(name):  # explicit absolute path: no search, nothing to hijack
        return name if os.path.isfile(name) else None
    # shutil.which on Windows searches the current directory first (unless the
    # NoDefaultCurrentDirectoryInExePath variable is set), so a planted ping.bat in the working
    # directory would run instead of System32\ping.exe. All tools NetProbe needs are .exe files.
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        directory = directory.strip().strip('"')
        if not os.path.isabs(directory):  # skips "", "." and other relative entries
            continue
        candidate = os.path.join(directory, f"{name}.exe")
        if os.path.isfile(candidate):
            return candidate
    return None


def decode_output(data: bytes | None) -> str:
    """Decode tool output: UTF-8 if valid, else the console/OEM code page (Windows) or locale."""
    if not data:
        return ""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode(_fallback_encoding(), errors="replace")
    return text.replace("\r\n", "\n")


def _fallback_encoding() -> str:
    if sys.platform == "win32":
        # Console tools (ping, tracert) write in the console output code page, usually the OEM one
        # (e.g. cp720 Arabic, cp850 Western Europe) - not the ANSI code page Python assumes.
        name = f"cp{_windows_code_page()}"
    else:
        name = locale.getpreferredencoding(False)
    try:
        codecs.lookup(name)
    except LookupError:
        return "latin-1"  # decodes any byte; better garbled than a crash
    return name


def _windows_code_page() -> int:
    import ctypes

    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    return kernel32.GetConsoleOutputCP() or kernel32.GetOEMCP()  # 0 when no console attached
