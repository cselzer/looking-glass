import errno
import socket
import unittest
from unittest.mock import MagicMock, patch

from looking_glass.net import tcpcheck
from looking_glass.net.host import format_hostport, pick_addrinfo, unbracket_host


def _v4_info(ip="1.1.1.1", port=443):
    return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))


class TcpCheckTests(unittest.TestCase):
    def test_parse_strips_brackets(self):
        self.assertEqual(
            tcpcheck.parse_tcp_path("/tcp/[2606:4700:4700::1111]/443"),
            ("2606:4700:4700::1111", 443),
        )
        self.assertEqual(
            tcpcheck.parse_tcp_path("/tcp/2606:4700:4700::1111/443"),
            ("2606:4700:4700::1111", 443),
        )

    def test_parse_rejects_https_url(self):
        with self.assertRaises(ValueError):
            tcpcheck.parse_tcp_path("/tcp/https:/example.com/443")
        with self.assertRaises(ValueError):
            tcpcheck.parse_tcp_path("/tcp/https://example.com/443")
        with self.assertRaises(ValueError):
            tcpcheck.parse_tcp_path("/tcp/https://example.com:8443")

    def test_refused(self):
        err = ConnectionRefusedError("Connection refused")
        err.errno = errno.ECONNREFUSED
        sock = MagicMock()
        sock.connect.side_effect = err
        with (
            patch("looking_glass.net.host.socket.getaddrinfo", return_value=[_v4_info()]),
            patch("looking_glass.net.tcpcheck.socket.socket", return_value=sock),
        ):
            payload = tcpcheck.check_tcp("example.com", 443, timeout=0.2)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["result"]["status"], "refused")
        self.assertIsNotNone(payload["result"]["rtt_ms"])
        self.assertTrue(payload["result"]["error"])

    def test_timeout(self):
        sock = MagicMock()
        sock.connect.side_effect = TimeoutError("timed out")
        with (
            patch("looking_glass.net.host.socket.getaddrinfo", return_value=[_v4_info()]),
            patch("looking_glass.net.tcpcheck.socket.socket", return_value=sock),
        ):
            payload = tcpcheck.check_tcp("example.com", 443, timeout=0.2)
        self.assertEqual(payload["result"]["status"], "timeout")
        self.assertIsNotNone(payload["result"]["rtt_ms"])

    def test_resolve(self):
        with patch(
            "looking_glass.net.host.socket.getaddrinfo",
            side_effect=socket.gaierror(-2, "Name or service not known"),
        ):
            payload = tcpcheck.check_tcp("no.such.host", 443, timeout=0.2)
        self.assertEqual(payload["result"]["status"], "resolve")

    def test_ok_status(self):
        sock = MagicMock()
        sock.getpeername.return_value = ("1.1.1.1", 443)
        sock.recv.return_value = b""
        with (
            patch("looking_glass.net.host.socket.getaddrinfo", return_value=[_v4_info()]),
            patch("looking_glass.net.tcpcheck.socket.socket", return_value=sock),
        ):
            payload = tcpcheck.check_tcp("example.com", 443)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["status"], "ok")
        self.assertEqual(payload["result"]["peer"], "1.1.1.1:443")

    def test_skips_loopback_when_public_exists(self):
        infos = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.1.1", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 443)),
        ]
        picked = pick_addrinfo(infos)
        self.assertEqual(picked[4][0], "1.1.1.1")

    def test_hosts_loopback_uses_public_dns(self):
        sock = MagicMock()
        sock.getpeername.return_value = ("192.0.2.1", 443)
        sock.recv.return_value = b""

        def fake_gai(name, port, *args, **kwargs):
            port = port or 443
            if str(name) == "192.0.2.1":
                return [_v4_info("192.0.2.1", port)]
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.1.1", port))]

        with (
            patch("looking_glass.net.host.socket.getaddrinfo", side_effect=fake_gai),
            patch(
                "looking_glass.net.host.dns_public_host",
                return_value=("192.0.2.1", socket.AF_INET),
            ),
            patch("looking_glass.net.tcpcheck.socket.socket", return_value=sock),
        ):
            payload = tcpcheck.check_tcp("example.com", 443)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["peer"], "192.0.2.1:443")

    def test_loopback_literal_is_kept(self):
        sock = MagicMock()
        sock.connect.side_effect = ConnectionRefusedError("Connection refused")
        with (
            patch(
                "looking_glass.net.host.socket.getaddrinfo",
                return_value=[_v4_info("127.0.0.1")],
            ),
            patch("looking_glass.net.host.dns_public_host") as dns,
            patch("looking_glass.net.tcpcheck.socket.socket", return_value=sock),
        ):
            payload = tcpcheck.check_tcp("127.0.0.1", 443, timeout=0.2)
        dns.assert_not_called()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["result"]["host"], "127.0.0.1")

    def test_ipv6_peer_is_bracketed(self):
        self.assertEqual(format_hostport("2606:4700:4700::1111", 443), "[2606:4700:4700::1111]:443")
        self.assertEqual(unbracket_host("[2606:4700:4700::1111]"), "2606:4700:4700::1111")


class TcpPlanTests(unittest.TestCase):
    def test_collapsed_https_envelope_is_rejected(self):
        from looking_glass.http.site import _plan

        err, kind, value, _base = _plan(
            "wsgi", "1.1.1.1", "/tcp/https:/example.com/443", {}, ""
        )
        self.assertIsNotNone(err)
        self.assertIsNone(kind)
        status, _ctype, body = err
        self.assertEqual(status, 400)
