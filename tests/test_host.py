import socket
import unittest
from unittest.mock import patch

from looking_glass.net.host import resolve_probe_host
from looking_glass.net.tls import _resolve


def _v4_info(ip, port=None):
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))


class ResolveProbeHostTests(unittest.TestCase):
    def test_hosts_loopback_falls_back_to_dns(self):
        def fake_gai(name, port, *args, **kwargs):
            if str(name) == "192.0.2.1":
                return [_v4_info("192.0.2.1", port)]
            return [_v4_info("127.0.1.1", port)]

        with (
            patch("looking_glass.net.host.socket.getaddrinfo", side_effect=fake_gai),
            patch(
                "looking_glass.net.host.dns_public_host",
                return_value=("192.0.2.1", socket.AF_INET),
            ),
        ):
            ip, family, sockaddr = resolve_probe_host("example.com", port=443)
        self.assertEqual(ip, "192.0.2.1")
        self.assertEqual(family, socket.AF_INET)
        self.assertEqual(sockaddr[0], "192.0.2.1")

    def test_tls_resolve_skips_debian_hosts_alias(self):
        def fake_gai(name, port, *args, **kwargs):
            if str(name) == "192.0.2.1":
                return [_v4_info("192.0.2.1", port)]
            return [_v4_info("127.0.1.1", port)]

        with (
            patch("looking_glass.net.host.socket.getaddrinfo", side_effect=fake_gai),
            patch(
                "looking_glass.net.host.dns_public_host",
                return_value=("192.0.2.1", socket.AF_INET),
            ),
        ):
            ip, family, name = _resolve("example.com")
        self.assertEqual(ip, "192.0.2.1")
        self.assertEqual(family, socket.AF_INET)
        self.assertEqual(name, "example.com")

    def test_loopback_literal_stays(self):
        with (
            patch(
                "looking_glass.net.host.socket.getaddrinfo",
                return_value=[_v4_info("127.0.0.1", 443)],
            ),
            patch("looking_glass.net.host.dns_public_host") as dns,
        ):
            ip, family, _sockaddr = resolve_probe_host("127.0.0.1", port=443)
        dns.assert_not_called()
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(family, socket.AF_INET)
