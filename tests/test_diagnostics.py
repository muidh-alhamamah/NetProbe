import socket
import unittest
from unittest import mock

from netprobe.diagnostics import dns, tcp


class DnsTests(unittest.TestCase):
    def test_first_address_of_ip_literal(self) -> None:
        self.assertEqual(dns.first_address("127.0.0.1"), "127.0.0.1")

    def test_localhost_resolves(self) -> None:
        result = dns.resolve("localhost")
        self.assertTrue(result.ok, result.error)
        self.assertTrue(result.details["addresses"])

    def test_resolution_failure(self) -> None:
        with mock.patch.object(dns.socket, "getaddrinfo", side_effect=socket.gaierror("nope")):
            result = dns.resolve("missing.example")
        self.assertFalse(result.ok)
        self.assertEqual(result.error, "nope")


class TcpTests(unittest.TestCase):
    def test_open_port(self) -> None:
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            result = tcp.check_tcp("127.0.0.1", port, timeout=2)
        self.assertTrue(result.ok, result.error)
        self.assertEqual(result.target, f"127.0.0.1:{port}")

    def test_closed_port(self) -> None:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]  # bound but not listening -> refused
            result = tcp.check_tcp("127.0.0.1", port, timeout=2)
        self.assertFalse(result.ok)
        self.assertTrue(result.error)


if __name__ == "__main__":
    unittest.main()
