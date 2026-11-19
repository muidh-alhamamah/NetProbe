import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from netprobe import runner
from netprobe.errors import CommandNotFoundError, CommandTimeoutError
from netprobe.runner import decode_output, run_command


class RunCommandTests(unittest.TestCase):
    def test_shell_metacharacters_are_passed_literally(self) -> None:
        payload = "a && echo pwned; | $(id) %PATH%"
        result = run_command([sys.executable, "-c", "import sys; print(sys.argv[1])", payload])
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), payload)

    def test_nonzero_exit_is_returned_not_raised(self) -> None:
        result = run_command([sys.executable, "-c", "import sys; sys.exit(3)"])
        self.assertEqual(result.returncode, 3)

    def test_missing_tool(self) -> None:
        with self.assertRaises(CommandNotFoundError):
            run_command(["netprobe-no-such-tool-xyz"])

    def test_timeout(self) -> None:
        with self.assertRaises(CommandTimeoutError):
            run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.5)

    def test_empty_args(self) -> None:
        with self.assertRaises(ValueError):
            run_command([])


class FindExecutableTests(unittest.TestCase):
    def test_windows_ignores_current_directory_and_scripts(self) -> None:
        with tempfile.TemporaryDirectory() as cwd, tempfile.TemporaryDirectory() as system:
            for planted in ("ping.bat", "ping.cmd", "ping.exe"):
                Path(cwd, planted).write_text("@echo HIJACKED")
            Path(system, "ping.bat").write_text("@echo not an exe")
            real = Path(system, "ping.exe")
            real.write_bytes(b"")
            path = os.pathsep.join([".", "", "relative\\dir", f'"{system}"'])
            previous = os.getcwd()
            os.chdir(cwd)  # contextlib.chdir needs Python 3.11; the project supports 3.10
            try:
                with mock.patch.object(runner.sys, "platform", "win32"), \
                        mock.patch.dict(runner.os.environ, {"PATH": path}):
                    self.assertEqual(runner.find_executable("ping"), str(real))
                    self.assertIsNone(runner.find_executable("tracert"))
                    self.assertEqual(runner.find_executable(str(real)), str(real))
                    self.assertIsNone(runner.find_executable(str(Path(system, "missing.exe"))))
            finally:
                os.chdir(previous)

    def test_posix_uses_shutil_which(self) -> None:
        with mock.patch.object(runner.sys, "platform", "linux"), \
                mock.patch.object(runner.shutil, "which", return_value="/usr/bin/ping") as which:
            self.assertEqual(runner.find_executable("ping"), "/usr/bin/ping")
        which.assert_called_once_with("ping")


class DecodeOutputTests(unittest.TestCase):
    def test_utf8_and_crlf(self) -> None:
        self.assertEqual(decode_output("Zeitüberschreitung\r\nok\r\n".encode("utf-8")),
                         "Zeitüberschreitung\nok\n")

    def test_windows_oem_code_page(self) -> None:
        arabic = "الرد من 8.8.8.8: وقت=12ms\r\n"
        with mock.patch.object(runner.sys, "platform", "win32"), \
                mock.patch.object(runner, "_windows_code_page", return_value=720):
            self.assertEqual(decode_output(arabic.encode("cp720")), arabic.replace("\r\n", "\n"))

    def test_unknown_code_page_never_raises(self) -> None:
        with mock.patch.object(runner.sys, "platform", "win32"), \
                mock.patch.object(runner, "_windows_code_page", return_value=99999):
            self.assertEqual(decode_output(b"\xff\xfeok"), "\xff\xfeok")

    def test_empty(self) -> None:
        self.assertEqual(decode_output(b""), "")
        self.assertEqual(decode_output(None), "")


if __name__ == "__main__":
    unittest.main()
