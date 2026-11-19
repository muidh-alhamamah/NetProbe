import unittest

from netprobe.errors import InvalidTargetError
from netprobe.validation import validate_host, validate_port, validate_range


class ValidateHostTests(unittest.TestCase):
    def test_accepts_valid_targets(self) -> None:
        for host in ["example.com", "localhost", "a-b.c.d.", "8.8.8.8", "::1", "2001:db8::1"]:
            with self.subTest(host=host):
                self.assertTrue(validate_host(host))

    def test_rejects_injection_and_garbage(self) -> None:
        bad = ["", "-c 1", "-n", "host;rm -rf /", "a && b", "a|b", "$(id)", "has space",
               "bad_underscore.com", "-leading.com", "a" * 64 + ".com", "x." * 130]
        for host in bad:
            with self.subTest(host=host), self.assertRaises(InvalidTargetError):
                validate_host(host)

    def test_normalises_ip(self) -> None:
        self.assertEqual(validate_host(" 2001:DB8:0::1 "), "2001:db8::1")


class ValidateNumberTests(unittest.TestCase):
    def test_port_bounds(self) -> None:
        self.assertEqual(validate_port(1), 1)
        self.assertEqual(validate_port(65535), 65535)
        for port in (0, -1, 65536):
            with self.subTest(port=port), self.assertRaises(InvalidTargetError):
                validate_port(port)

    def test_range(self) -> None:
        self.assertEqual(validate_range("n", 5, 1, 10), 5)
        with self.assertRaises(InvalidTargetError):
            validate_range("n", 11, 1, 10)


if __name__ == "__main__":
    unittest.main()
