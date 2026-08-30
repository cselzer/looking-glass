import platform
import socket
import unittest
from unittest.mock import patch

from looking_glass import observe


class _FakeSock:
    def __init__(self, ip: str):
        self._ip = ip

    def connect(self, _addr):
        if self._ip is None:
            raise OSError("no route")
        return None

    def getsockname(self):
        return (self._ip, 0)

    def close(self):
        return None


def _fake_socket(mapping):
    def factory(family, _type):
        ip = mapping.get(family)
        if ip is False:
            raise OSError("no family")
        return _FakeSock(ip)

    return factory


class EgressAddrTests(unittest.TestCase):
    def test_both_families(self):
        fake = _fake_socket(
            {socket.AF_INET: "192.0.2.10", socket.AF_INET6: "2001:db8::1"}
        )
        with patch("looking_glass.observe.socket.socket", side_effect=fake):
            addrs = observe.egress_addrs()
            self.assertEqual(addrs["ipv4"], "192.0.2.10")
            self.assertEqual(addrs["ipv6"], "2001:db8::1")
            self.assertEqual(observe.egress_ip(), "192.0.2.10")

    def test_ipv6_only(self):
        fake = _fake_socket({socket.AF_INET: False, socket.AF_INET6: "2001:db8::9"})
        with patch("looking_glass.observe.socket.socket", side_effect=fake):
            addrs = observe.egress_addrs()
            self.assertIsNone(addrs["ipv4"])
            self.assertEqual(addrs["ipv6"], "2001:db8::9")
            self.assertEqual(observe.egress_ip(), "2001:db8::9")

    def test_ipv4_only(self):
        fake = _fake_socket({socket.AF_INET: "203.0.113.8", socket.AF_INET6: False})
        with patch("looking_glass.observe.socket.socket", side_effect=fake):
            addrs = observe.egress_addrs()
            self.assertEqual(addrs["ipv4"], "203.0.113.8")
            self.assertIsNone(addrs["ipv6"])
            self.assertEqual(observe.egress_ip(), "203.0.113.8")

    def test_link_local_is_usable_fallback(self):
        fake = _fake_socket({socket.AF_INET: "169.254.1.1", socket.AF_INET6: "fe80::1"})
        with patch("looking_glass.observe.socket.socket", side_effect=fake):
            addrs = observe.egress_addrs()
        self.assertEqual(addrs["ipv4"], "169.254.1.1")
        self.assertEqual(addrs["ipv6"], "fe80::1")

    def test_skips_loopback(self):
        fake = _fake_socket({socket.AF_INET: "127.0.0.1", socket.AF_INET6: "::1"})
        with patch("looking_glass.observe.socket.socket", side_effect=fake):
            addrs = observe.egress_addrs()
            self.assertIsNone(addrs["ipv4"])
            self.assertIsNone(addrs["ipv6"])
            self.assertIsNone(observe.egress_ip())


class HostOsTests(unittest.TestCase):
    def test_kernel_is_platform_release(self):
        got = observe.host_os()
        self.assertIn("kernel", got)
        self.assertEqual(got["kernel"], platform.release() or None)
