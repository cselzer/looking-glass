import asyncio
import errno
import inspect
import ipaddress
import select
import socket
import struct
import tempfile
import time
import unittest
from unittest.mock import patch

from looking_glass.net import probe
from looking_glass.net.probe import ProbeHit


class ProbePathTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(probe.parse_probe_path("/ping/1.1.1.1"), ("ping", "1.1.1.1"))
        self.assertEqual(
            probe.parse_probe_path("/traceroute/example.com"), ("traceroute", "example.com")
        )
        self.assertEqual(probe.parse_probe_path("mtr/2001:db8::1"), ("mtr", "2001:db8::1"))
        self.assertEqual(
            probe.parse_probe_path("/ping/[2001:db8::1]"),
            ("ping", "2001:db8::1"),
        )
        with self.assertRaises(ValueError):
            probe.parse_probe_path("/ping")
        with self.assertRaises(ValueError):
            probe.parse_probe_path("/dns/example.com")

    def test_parse_tcp_trace(self):
        self.assertEqual(probe.parse_tcp_trace_path("/tcptraceroute/1.1.1.1"), ("1.1.1.1", 443))
        self.assertEqual(
            probe.parse_tcp_trace_path("/tcptraceroute/example.com/22"),
            ("example.com", 22),
        )
        with self.assertRaises(ValueError):
            probe.parse_tcp_trace_path("/tcptraceroute")
        with self.assertRaises(ValueError):
            probe.parse_tcp_trace_path("/tcptraceroute/1.1.1.1/70000")
        with self.assertRaises(ValueError):
            probe.parse_tcp_trace_path("/tcptraceroute/1.1.1.1%2F32")
        self.assertEqual(
            probe.parse_tcp_trace_path("/tcptraceroute/1.1.1.1/443"),
            ("1.1.1.1", 443),
        )

    def test_guard_ip(self):
        self.assertEqual(probe.guard_ip("8.8.8.8"), "8.8.8.8")
        with self.assertRaises(ValueError):
            probe.guard_ip("224.0.0.1")
        with self.assertRaises(ValueError):
            probe.guard_ip("0.0.0.0")


class IcmpCodecTests(unittest.TestCase):
    def test_checksum_zero_on_built_echo(self):
        packet = probe.build_echo(socket.AF_INET, 1, 2, b"abcd")
        self.assertEqual(probe.internet_checksum(packet), 0)
        self.assertEqual(packet[0], probe.ICMP_ECHO)

    def test_parse_echo_reply_with_and_without_ip_header(self):
        ident, seq = 7, 9
        icmp = struct.pack("!BBHHH", probe.ICMP_ECHOREPLY, 0, 0, ident, seq) + b"abcd"
        parsed = probe.parse_icmp(socket.AF_INET, icmp, ("1.1.1.1", 0))
        self.assertEqual(parsed["kind"], "reply")
        self.assertEqual(parsed["ident"], ident)
        self.assertEqual(parsed["seq"], seq)
        self.assertEqual(parsed["addr"], "1.1.1.1")

        ip = b"\x45" + b"\x00" * 11 + socket.inet_aton("9.9.9.9") + b"\x00" * 4
        parsed = probe.parse_icmp(socket.AF_INET, ip + icmp, ("8.8.8.8", 0))
        self.assertEqual(parsed["addr"], "9.9.9.9")
        self.assertEqual(parsed["seq"], seq)

    def test_parse_ttl_exceeded_wraps_echo(self):
        ident, seq = 3, 4
        inner_ip = b"\x45" + b"\x00" * 19
        inner_icmp = struct.pack("!BBHHH", probe.ICMP_ECHO, 0, 0, ident, seq)
        icmp = struct.pack("!BBHI", probe.ICMP_TIMXCEED, 0, 0, 0) + inner_ip + inner_icmp
        parsed = probe.parse_icmp(socket.AF_INET, icmp, ("10.0.0.1", 0))
        self.assertEqual(parsed["kind"], "ttl")
        self.assertEqual(parsed["ident"], ident)
        self.assertEqual(parsed["seq"], seq)
        self.assertEqual(parsed["addr"], "10.0.0.1")

    def test_dgram_matches_seq_even_if_ident_rewritten(self):
        parsed = {"kind": "reply", "ident": 999, "seq": 4, "addr": "1.1.1.1"}
        self.assertTrue(probe.probe_matches(parsed, ident=1, seq=4, dgram=True))
        self.assertFalse(probe.probe_matches(parsed, ident=1, seq=4, dgram=False))
        self.assertFalse(probe.probe_matches(parsed, ident=1, seq=5, dgram=True))

    def test_parse_errqueue_offender_is_hop(self):
        ee = struct.pack("@IBBBBII", errno.EHOSTUNREACH, 2, probe.ICMP_TIMXCEED, 0, 0, 0, 0)
        sa = struct.pack("@HH", socket.AF_INET, 0) + socket.inet_aton("169.254.169.254")
        hop, kind = probe._parse_errqueue(
            [(socket.IPPROTO_IP, getattr(socket, "IP_RECVERR", 11), ee + sa)],
            ("1.1.1.1", 33435),
            "1.1.1.1",
        )
        self.assertEqual(kind, "ttl")
        self.assertEqual(hop, "169.254.169.254")

    def test_parse_errqueue_port_unreach_is_reply(self):
        ee = struct.pack("@IBBBBII", errno.ECONNREFUSED, 2, probe.ICMP_UNREACH, 3, 0, 0, 0)
        sa = struct.pack("@HH", socket.AF_INET, 0) + socket.inet_aton("1.1.1.1")
        hop, kind = probe._parse_errqueue(
            [(socket.IPPROTO_IP, getattr(socket, "IP_RECVERR", 11), ee + sa)],
            ("1.1.1.1", 33442),
            "1.1.1.1",
        )
        self.assertEqual(kind, "reply")
        self.assertEqual(hop, "1.1.1.1")

    def test_enable_recverr_ipv4_without_cpython_constant(self):
        calls = []

        class Sock:
            def setsockopt(self, level, opt, val):
                calls.append((level, opt, val))

        with (
            patch.object(probe.sys, "platform", "linux"),
            patch.object(socket, "IP_RECVERR", None, create=True),
        ):
            ok = probe._enable_recverr(Sock(), socket.AF_INET)
        self.assertTrue(ok)
        self.assertEqual(calls, [(socket.IPPROTO_IP, 11, 1)])

    def test_enable_recverr_ipv6_without_cpython_constant(self):
        calls = []

        class Sock:
            def setsockopt(self, level, opt, val):
                calls.append((level, opt, val))

        with (
            patch.object(probe.sys, "platform", "linux"),
            patch.object(socket, "IPV6_RECVERR", None, create=True),
        ):
            ok = probe._enable_recverr(Sock(), socket.AF_INET6)
        self.assertTrue(ok)
        self.assertEqual(calls, [(socket.IPPROTO_IPV6, 25, 1)])

    def test_parse_errqueue_without_cpython_recverr_attrs(self):
        ee = struct.pack("@IBBBBII", errno.EHOSTUNREACH, 2, probe.ICMP_TIMXCEED, 0, 0, 0, 0)
        sa = struct.pack("@HH", socket.AF_INET, 0) + socket.inet_aton("10.0.0.1")
        with (
            patch.object(socket, "IP_RECVERR", None, create=True),
            patch.object(socket, "IPV6_RECVERR", None, create=True),
        ):
            hop, kind = probe._parse_errqueue(
                [(socket.IPPROTO_IP, 11, ee + sa)],
                ("1.1.1.1", 33435),
                "1.1.1.1",
            )
        self.assertEqual(kind, "ttl")
        self.assertEqual(hop, "10.0.0.1")

    def test_parse_errqueue_ipv6_type_25_without_cpython_constant(self):
        ee = struct.pack("@IBBBBII", errno.EHOSTUNREACH, 3, probe.ICMP6_TIMXCEED, 0, 0, 0, 0)
        sa = struct.pack("@HHI", socket.AF_INET6, 0, 0) + socket.inet_pton(
            socket.AF_INET6, "2001:db8::1"
        )
        with patch.object(socket, "IPV6_RECVERR", None, create=True):
            hop, kind = probe._parse_errqueue(
                [(socket.IPPROTO_IPV6, 25, ee + sa)],
                ("2001:db8::2", 33435, 0, 0),
                "2001:db8::2",
            )
        self.assertEqual(kind, "ttl")
        self.assertEqual(hop, "2001:db8::1")

    def test_quoted_udp_time_exceeded_is_hop(self):
        inner_ip = bytearray(20)
        inner_ip[0] = 0x45
        inner_ip[9] = 17
        inner_ip[12:16] = socket.inet_aton("192.0.2.8")
        inner_ip[16:20] = socket.inet_aton("8.8.8.8")
        inner_udp = struct.pack("!HHHH", 54321, 33437, 8, 0)
        icmp = struct.pack("!BBHI", probe.ICMP_TIMXCEED, 0, 0, 0) + bytes(inner_ip) + inner_udp
        outer = bytearray(20)
        outer[0] = 0x45
        outer[9] = 1
        outer[12:16] = socket.inet_aton("10.0.0.1")
        outer[16:20] = socket.inet_aton("192.0.2.8")
        matched = probe._match_udp_trace(
            socket.AF_INET, bytes(outer) + icmp, ("10.0.0.1", 0), "8.8.8.8", 54321, 33437
        )
        self.assertEqual(matched, ("ttl", "10.0.0.1"))
        miss = probe._match_udp_trace(
            socket.AF_INET, bytes(outer) + icmp, ("10.0.0.1", 0), "8.8.8.8", 1, 2
        )
        self.assertIsNone(miss)

    def test_quoted_udp_port_unreach_is_dest(self):
        inner_ip = bytearray(20)
        inner_ip[0] = 0x45
        inner_ip[9] = 17
        inner_ip[16:20] = socket.inet_aton("8.8.8.8")
        inner_udp = struct.pack("!HHHH", 40000, 33434, 8, 0)
        icmp = (
            struct.pack("!BBHI", probe.ICMP_UNREACH, probe.ICMP_UNREACH_PORT, 0, 0)
            + bytes(inner_ip)
            + inner_udp
        )
        matched = probe._match_udp_trace(
            socket.AF_INET, icmp, ("8.8.8.8", 0), "8.8.8.8", 40000, 33434
        )
        self.assertEqual(matched, ("reply", "8.8.8.8"))

    def test_udp_err_poll_mask_uses_pri_not_only_err(self):
        mask = probe._udp_err_poll_mask()
        self.assertTrue(mask & select.POLLIN)
        pri = getattr(select, "POLLPRI", 0)
        if pri:
            self.assertTrue(mask & pri)
        self.assertFalse(mask & getattr(select, "POLLERR", 0))

    def test_ipv6_echo_type_and_checksum(self):
        packet = probe.build_echo(
            socket.AF_INET6,
            1,
            2,
            b"abcd",
            src="2001:db8::1",
            dst="2001:db8::2",
        )
        self.assertEqual(packet[0], probe.ICMP6_ECHO)
        self.assertNotEqual(packet[2:4], b"\x00\x00")
        rebuilt = probe.apply_icmp6_checksum(packet, "2001:db8::1", "2001:db8::2")
        self.assertEqual(rebuilt, packet)

    def test_dest_tuple_is_family_aware(self):
        self.assertEqual(probe._dest("1.1.1.1", socket.AF_INET, 33434), ("1.1.1.1", 33434))
        self.assertEqual(
            probe._dest("2001:db8::1", socket.AF_INET6, 33434),
            ("2001:db8::1", 33434, 0, 0),
        )

    def test_udp_wait_uses_ipv6_socket(self):
        if not hasattr(socket, "MSG_ERRQUEUE"):
            self.skipTest("no MSG_ERRQUEUE on this platform")
        families = []

        def fake_socket(family, typ, *args, **kwargs):
            families.append(family)
            raise OSError("test")

        with patch("socket.socket", side_effect=fake_socket):
            hit = probe._udp_probe_wait("2001:db8::1", 1, 1, 0.01, socket.AF_INET6)
        self.assertIn(socket.AF_INET6, families)
        self.assertEqual(hit.kind, "timeout")

    def test_read_udp_error_source_does_not_recvfrom(self):
        src = inspect.getsource(probe._read_udp_error)
        self.assertNotIn(".recvfrom", src)
        self.assertNotIn("recvfrom(", src)
        wait_src = inspect.getsource(probe._udp_probe_wait)
        self.assertNotIn(".recvfrom", wait_src)
        self.assertNotIn("recvfrom(", wait_src)
        self.assertNotIn("select.select", wait_src)
        self.assertIn("poll", wait_src)

    def test_read_udp_error_does_not_recvfrom(self):
        ee = struct.pack("@IBBBBII", errno.EHOSTUNREACH, 2, probe.ICMP_TIMXCEED, 0, 0, 0, 0)
        sa = struct.pack("@HH", socket.AF_INET, 0) + socket.inet_aton("10.0.0.1")
        anc = [(socket.IPPROTO_IP, getattr(socket, "IP_RECVERR", 11), ee + sa)]
        msg_err = getattr(socket, "MSG_ERRQUEUE", 0x2000)

        class Sock:
            def __init__(self):
                self.recvfrom_calls = 0
                self.recvmsg_flags = []

            def recvmsg(self, *args, **kwargs):
                flags = args[2] if len(args) > 2 else kwargs.get("flags", 0)
                self.recvmsg_flags.append(flags)
                return b"", anc, 0, ("1.1.1.1", 33435)

            def recvfrom(self, *_a, **_k):
                self.recvfrom_calls += 1
                raise AssertionError("recvfrom must not wait for a UDP payload")

        sock = Sock()
        with patch.object(socket, "MSG_ERRQUEUE", msg_err, create=True):
            hop, kind = probe._read_udp_error(sock, "1.1.1.1")
        self.assertEqual(kind, "ttl")
        self.assertEqual(hop, "10.0.0.1")
        self.assertEqual(sock.recvfrom_calls, 0)
        self.assertEqual(sock.recvmsg_flags, [msg_err])

    def test_read_udp_error_empty_queue_does_not_recvfrom(self):
        msg_err = getattr(socket, "MSG_ERRQUEUE", 0x2000)

        class Sock:
            def recvmsg(self, *_a, **_k):
                raise BlockingIOError(errno.EAGAIN, "resource temporarily unavailable")

            def recvfrom(self, *_a, **_k):
                raise AssertionError("recvfrom must not wait for a UDP payload")

        with patch.object(socket, "MSG_ERRQUEUE", msg_err, create=True):
            hop, kind = probe._read_udp_error(Sock(), "1.1.1.1")
        self.assertIsNone(hop)
        self.assertIsNone(kind)

    def test_udp_probe_wait_reads_errqueue_hop(self):
        ee = struct.pack("@IBBBBII", errno.EHOSTUNREACH, 2, probe.ICMP_TIMXCEED, 0, 0, 0, 0)
        sa = struct.pack("@HH", socket.AF_INET, 0) + socket.inet_aton("169.254.169.254")
        anc = [(socket.IPPROTO_IP, getattr(socket, "IP_RECVERR", 11), ee + sa)]
        msg_err = getattr(socket, "MSG_ERRQUEUE", 0x2000)
        opened = []

        class FakeSock:
            def __init__(self):
                self.recvfrom_calls = 0

            def setsockopt(self, *_a, **_k):
                return None

            def connect(self, *_a):
                return None

            def send(self, *_a):
                return 32

            def setblocking(self, *_a):
                return None

            def close(self):
                return None

            def fileno(self):
                return 7

            def recvmsg(self, *args, **kwargs):
                flags = args[2] if len(args) > 2 else kwargs.get("flags", 0)
                self.assertEqual(flags, msg_err)
                return b"", anc, 0, ("1.1.1.1", 33435)

            def recvfrom(self, *_a, **_k):
                self.recvfrom_calls += 1
                raise AssertionError("recvfrom must not wait for a UDP payload")

        fake = FakeSock()
        fake.assertEqual = self.assertEqual

        def fake_socket(family, typ, *args, **kwargs):
            opened.append((family, typ))
            return fake

        class FakePoller:
            def register(self, *_a, **_k):
                return None

            def poll(self, *_a, **_k):
                raise AssertionError("errqueue already readable; poll not required")

        with (
            patch.object(socket, "MSG_ERRQUEUE", msg_err, create=True),
            patch.object(probe, "_enable_recverr", return_value=True),
            patch("socket.socket", side_effect=fake_socket),
            patch.object(probe.select, "poll", return_value=FakePoller()),
            patch.object(probe.select, "select", side_effect=AssertionError("select")),
        ):
            hit = probe._udp_probe_wait("1.1.1.1", 1, 1, 0.5)
        self.assertEqual(hit.kind, "ttl")
        self.assertEqual(hit.addr, "169.254.169.254")
        self.assertEqual(hit.via, "udp")
        self.assertEqual(fake.recvfrom_calls, 0)
        self.assertEqual(opened, [(socket.AF_INET, socket.SOCK_DGRAM)])
        self.assertNotIn(socket.SOCK_RAW, [typ for _fam, typ in opened])

    def test_udp_probe_wait_poll_then_errqueue(self):
        ee = struct.pack("@IBBBBII", errno.EHOSTUNREACH, 2, probe.ICMP_TIMXCEED, 0, 0, 0, 0)
        sa = struct.pack("@HH", socket.AF_INET, 0) + socket.inet_aton("10.0.0.1")
        anc = [(socket.IPPROTO_IP, getattr(socket, "IP_RECVERR", 11), ee + sa)]
        msg_err = getattr(socket, "MSG_ERRQUEUE", 0x2000)
        replies = [
            BlockingIOError(errno.EAGAIN, "resource temporarily unavailable"),
            (b"", anc, 0, ("1.1.1.1", 33435)),
        ]
        polls = []

        class FakeSock:
            def setsockopt(self, *_a, **_k):
                return None

            def connect(self, *_a):
                return None

            def send(self, *_a):
                return 32

            def setblocking(self, *_a):
                return None

            def close(self):
                return None

            def fileno(self):
                return 7

            def recvmsg(self, *args, **kwargs):
                flags = args[2] if len(args) > 2 else kwargs.get("flags", 0)
                self.assertEqual(flags, msg_err)
                item = replies.pop(0)
                if isinstance(item, BaseException):
                    raise item
                return item

            def recvfrom(self, *_a, **_k):
                raise AssertionError("recvfrom must not wait for a UDP payload")

        fake = FakeSock()
        fake.assertEqual = self.assertEqual

        class FakePoller:
            def register(self, fd, mask=0):
                self.mask = mask

            def poll(self, timeout=-1):
                polls.append(timeout)
                return [(7, getattr(select, "POLLERR", 0) or select.POLLIN)]

        with (
            patch.object(socket, "MSG_ERRQUEUE", msg_err, create=True),
            patch.object(probe, "_enable_recverr", return_value=True),
            patch("socket.socket", return_value=fake),
            patch.object(probe.select, "poll", return_value=FakePoller()),
            patch.object(probe.select, "select", side_effect=AssertionError("select")),
        ):
            hit = probe._udp_probe_wait("1.1.1.1", 2, 1, 0.5)
        self.assertEqual(hit.kind, "ttl")
        self.assertEqual(hit.addr, "10.0.0.1")
        self.assertEqual(hit.via, "udp")
        self.assertEqual(len(polls), 1)

    def test_udp_probe_wait_send_error_drains_errqueue(self):
        ee = struct.pack("@IBBBBII", errno.EHOSTUNREACH, 2, probe.ICMP_TIMXCEED, 0, 0, 0, 0)
        sa = struct.pack("@HH", socket.AF_INET, 0) + socket.inet_aton("169.254.169.254")
        anc = [(socket.IPPROTO_IP, 11, ee + sa)]
        msg_err = getattr(socket, "MSG_ERRQUEUE", 0x2000)

        class FakeSock:
            def setsockopt(self, *_a, **_k):
                return None

            def connect(self, *_a):
                return None

            def send(self, *_a):
                raise OSError(errno.EHOSTUNREACH, "No route to host")

            def setblocking(self, *_a):
                raise AssertionError("should return from errqueue before wait")

            def close(self):
                return None

            def fileno(self):
                return 7

            def recvmsg(self, *_a, **_k):
                return b"", anc, 0, ("1.1.1.1", 33435)

            def recvfrom(self, *_a, **_k):
                raise AssertionError("recvfrom must not wait for a UDP payload")

        fake = FakeSock()
        with (
            patch.object(socket, "MSG_ERRQUEUE", msg_err, create=True),
            patch.object(probe, "_enable_recverr", return_value=True),
            patch("socket.socket", return_value=fake),
        ):
            hit = probe._udp_probe_wait("1.1.1.1", 1, 1, 0.5)
        self.assertEqual(hit.kind, "ttl")
        self.assertEqual(hit.addr, "169.254.169.254")
        self.assertEqual(hit.via, "udp")

    def test_errqueue_hop_shares_udp_recv(self):
        ee = struct.pack("@IBBBBII", errno.EHOSTUNREACH, 2, probe.ICMP_TIMXCEED, 0, 0, 0, 0)
        sa = struct.pack("@HH", socket.AF_INET, 0) + socket.inet_aton("10.0.0.1")
        anc = [(socket.IPPROTO_IP, getattr(socket, "IP_RECVERR", 11), ee + sa)]
        msg_err = getattr(socket, "MSG_ERRQUEUE", 0x2000)

        class Sock:
            def recvmsg(self, *_a, **_k):
                return b"", anc, 0, ("1.1.1.1", 443)

            def recvfrom(self, *_a, **_k):
                raise AssertionError("recvfrom must not wait for a UDP payload")

        with patch.object(socket, "MSG_ERRQUEUE", msg_err, create=True):
            hop = probe._errqueue_hop(Sock(), "1.1.1.1")
        self.assertEqual(hop, "10.0.0.1")


class Ipv6ResolveTests(unittest.IsolatedAsyncioTestCase):
    async def test_literal_ipv6(self):
        engine = probe.SocketEngine()
        ip, family, name = await engine.resolve("2001:db8::1")
        self.assertEqual(ip, "2001:db8::1")
        self.assertEqual(family, socket.AF_INET6)

    async def test_hostname_keeps_getaddrinfo_order(self):
        engine = probe.SocketEngine()
        infos = [
            (socket.AF_INET6, socket.SOCK_DGRAM, 0, "", ("2001:db8::8", 0, 0, 0)),
            (socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("192.0.2.8", 0)),
        ]
        loop = asyncio.get_running_loop()

        async def fake_gai(*_a, **_k):
            return infos

        with patch.object(loop, "getaddrinfo", side_effect=fake_gai):
            ip, family, _name = await engine.resolve("dual.example")
        self.assertEqual(family, socket.AF_INET6)
        self.assertEqual(ip, "2001:db8::8")

    async def test_hosts_loopback_uses_public_dns(self):
        engine = probe.SocketEngine()
        infos = [
            (socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("127.0.1.1", 0)),
        ]
        loop = asyncio.get_running_loop()

        async def fake_gai(*_a, **_k):
            return infos

        with (
            patch.object(loop, "getaddrinfo", side_effect=fake_gai),
            patch(
                "looking_glass.net.probe.dns_public_host",
                return_value=("192.0.2.1", socket.AF_INET),
            ),
        ):
            ip, family, name = await engine.resolve("example.com")
        self.assertEqual(ip, "192.0.2.1")
        self.assertEqual(family, socket.AF_INET)
        self.assertEqual(name, "example.com")

    async def test_echo_or_udp_races_udp_on_ipv6(self):
        engine = probe.SocketEngine()
        miss = ProbeHit("timeout", None, None, 1, 1, "timeout", via="udp")
        with (
            patch.object(probe, "_icmp_ttl_probe_sync") as icmp,
            patch.object(probe, "_udp_probe_wait", return_value=miss) as udp,
            patch.object(probe, "_tcp_probe_sync") as tcp,
        ):
            await engine.echo_or_udp(
                "2001:db8::1",
                socket.AF_INET6,
                ttl=1,
                ident=1,
                seq=1,
                timeout=0.05,
                payload=b"x",
            )
        udp.assert_called()
        self.assertEqual(udp.call_args[0][4], socket.AF_INET6)
        tcp.assert_not_called()
        icmp.assert_not_called()


class PmtuFamilyTests(unittest.TestCase):
    def test_ipv6_literal_uses_v6_ping(self):
        from looking_glass.net import pmtu

        with patch.object(pmtu.shutil, "which", side_effect=lambda name: "/sbin/" + name):
            cmd = pmtu._ping_cmd("2001:db8::1", 56)
        self.assertIsNotNone(cmd)
        self.assertTrue(cmd[-1] == "2001:db8::1")
        self.assertTrue("-6" in cmd or cmd[0].endswith("ping6"))
        self.assertTrue(pmtu._is_ipv6_host("2001:db8::1"))
        self.assertFalse(pmtu._is_ipv6_host("1.1.1.1"))


class MtrCycleClampTests(unittest.TestCase):
    def test_clamp_mtr_cycles(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.config.get_root", return_value=tmp):
                self.assertEqual(probe.clamp_mtr_cycles(None), 10)
                self.assertEqual(probe.clamp_mtr_cycles(""), 10)
                self.assertEqual(probe.clamp_mtr_cycles("foo"), 10)
                self.assertEqual(probe.clamp_mtr_cycles(0), 1)
                self.assertEqual(probe.clamp_mtr_cycles(-3), 1)
                self.assertEqual(probe.clamp_mtr_cycles(3), 3)
                self.assertEqual(probe.clamp_mtr_cycles(999), 30)
                self.assertEqual(probe.clamp_mtr_cycles("999"), 30)


class FakeEngine:
    def __init__(self, ip="1.1.1.1"):
        self.ip = ip
        self.family = socket.AF_INET
        self.calls = []

    async def resolve(self, target):
        return self.ip, self.family, str(target).rstrip(".")

    async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
        self.calls.append({"ttl": ttl, "seq": seq, "ident": ident})
        if ttl >= 64:
            return ProbeHit("reply", ip, 12.5, seq, ttl)
        if ttl == 1:
            return ProbeHit("ttl", "10.0.0.1", 1.2, seq, ttl)
        if ttl == 2:
            return ProbeHit("ttl", "10.1.0.1", 4.4, seq, ttl)
        if ttl == 3:
            return ProbeHit("reply", ip, 11.0, seq, ttl)
        return ProbeHit("timeout", None, None, seq, ttl, "timeout")


class TimeoutEngine:
    """Every hop times out, like a dest that never answers ICMP or UDP."""

    def __init__(self, delay=0.0):
        self.delay = delay
        self.calls = []

    async def resolve(self, target):
        return "24.154.32.53", socket.AF_INET, str(target)

    async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
        self.calls.append({"ttl": ttl, "seq": seq})
        if self.delay:
            await asyncio.sleep(self.delay)
        return ProbeHit("timeout", None, None, seq, ttl, "timeout")


class PartialPathEngine:
    """Hops 1–last_hop reply; the dest never answers (home ISP / blackhole)."""

    def __init__(self, last_hop=7):
        self.last_hop = last_hop

    async def resolve(self, target):
        return "24.154.32.53", socket.AF_INET, str(target)

    async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
        if ttl <= self.last_hop:
            return ProbeHit("ttl", f"10.0.0.{ttl}", 1.0, seq, ttl)
        return ProbeHit("timeout", None, None, seq, ttl, "timeout")


class ProbeRunTests(unittest.IsolatedAsyncioTestCase):
    async def test_ping(self):
        engine = FakeEngine()
        payload = await probe.ping_async("example.com", count=3, engine=engine)
        self.assertTrue(payload["ok"])
        result = payload["result"]
        self.assertEqual(result["ip"], "1.1.1.1")
        self.assertEqual(result["transmitted"], 3)
        self.assertEqual(result["received"], 3)
        self.assertEqual(result["loss_percent"], 0.0)
        self.assertEqual(result["via"], "python-icmp")
        self.assertEqual(len(result["probes"]), 3)
        self.assertTrue(all(row["ok"] for row in result["probes"]))

    async def test_traceroute_reaches_dest(self):
        payload = await probe.traceroute_async("1.1.1.1", engine=FakeEngine())
        self.assertTrue(payload["ok"])
        hops = payload["result"]["hops"]
        self.assertEqual([row["hop"] for row in hops], [1, 2, 3])
        self.assertEqual(hops[-1]["host"], "1.1.1.1")
        self.assertEqual(hops[-1]["status"], "reply")
        self.assertTrue(payload["result"]["reached"])
        self.assertEqual(payload["result"]["via"], "python-udp")
        self.assertEqual(payload["result"]["probe"], "udp")
        self.assertTrue(payload["result"]["summary"]["reached"])

    async def test_traceroute_dest_host_prefers_target(self):
        class CfThenTarget(FakeEngine):
            def __init__(self):
                super().__init__()
                self._n = {}

            async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
                n = self._n.get(ttl, 0)
                self._n[ttl] = n + 1
                if ttl == 1:
                    return ProbeHit("ttl", "10.0.0.1", 1.0, seq, ttl)
                if ttl == 2:
                    return ProbeHit("ttl", "10.1.0.1", 1.0, seq, ttl)
                if n == 0:
                    return ProbeHit("reply", "162.158.61.50", 1.0, seq, ttl)
                return ProbeHit("reply", ip, 1.0, seq, ttl)

        payload = await probe.traceroute_async("1.1.1.1", engine=CfThenTarget())
        hops = payload["result"]["hops"]
        dest = hops[-1]
        self.assertEqual(dest["status"], "reply")
        self.assertEqual(dest["host"], "1.1.1.1")
        self.assertIn("162.158.61.50", dest["hosts"])
        self.assertIn("1.1.1.1", dest["hosts"])

    async def test_traceroute_mixed_hop_keeps_ttl_and_continues(self):
        class MixedThenDest(FakeEngine):
            def __init__(self):
                super().__init__()
                self._n = {}

            async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
                n = self._n.get(ttl, 0)
                self._n[ttl] = n + 1
                if ttl < 7:
                    return ProbeHit("ttl", f"10.0.0.{ttl}", 1.0, seq, ttl)
                if ttl == 7:
                    if n == 0:
                        return ProbeHit("ttl", "162.158.61.1", 1.0, seq, ttl)
                    return ProbeHit("reply", "162.158.61.99", 1.0, seq, ttl)
                if ttl == 8:
                    if n == 0:
                        return ProbeHit("reply", "162.158.61.50", 1.0, seq, ttl)
                    return ProbeHit("reply", ip, 1.0, seq, ttl)
                return ProbeHit("timeout", None, None, seq, ttl, "timeout")

        payload = await probe.traceroute_async("1.1.1.1", engine=MixedThenDest())
        hops = payload["result"]["hops"]
        self.assertEqual([row["hop"] for row in hops], list(range(1, 9)))
        hop7 = hops[6]
        self.assertEqual(hop7["status"], "ttl")
        self.assertEqual(hop7["host"], "162.158.61.1")
        self.assertEqual(hop7["hosts"], ["162.158.61.1"])
        dest = hops[-1]
        self.assertEqual(dest["hop"], 8)
        self.assertEqual(dest["status"], "reply")
        self.assertEqual(dest["host"], "1.1.1.1")
        self.assertTrue(payload["result"]["reached"])

    async def test_mtr_dest_host_prefers_target(self):
        class CfThenTarget(FakeEngine):
            def __init__(self):
                super().__init__()
                self._n = {}

            async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
                n = self._n.get(ttl, 0)
                self._n[ttl] = n + 1
                if ttl == 1:
                    return ProbeHit("ttl", "10.0.0.1", 1.0, seq, ttl)
                if ttl == 2:
                    return ProbeHit("ttl", "10.1.0.1", 1.0, seq, ttl)
                if n == 0:
                    return ProbeHit("reply", "162.158.61.50", 1.0, seq, ttl)
                return ProbeHit("reply", ip, 1.0, seq, ttl)

        payload = await probe.mtr_async("1.1.1.1", cycles=2, engine=CfThenTarget())
        dest = payload["result"]["hops"][-1]
        self.assertEqual(dest["host"], "1.1.1.1")
        self.assertIn("162.158.61.50", dest["hosts"])
        self.assertEqual(dest["sent"], 2)

    async def test_mtr_aggregates_cycles(self):
        payload = await probe.mtr_async("example.com", cycles=2, engine=FakeEngine())
        self.assertTrue(payload["ok"])
        hops = payload["result"]["hops"]
        self.assertEqual(len(hops), 3)
        dest = hops[-1]
        self.assertEqual(dest["host"], "1.1.1.1")
        self.assertEqual(dest["sent"], 2)
        self.assertEqual(dest["recv"], 2)
        self.assertEqual(dest["loss_percent"], 0.0)
        self.assertIsNotNone(dest["avg_ms"])
        self.assertEqual(payload["result"]["via"], "python-udp")
        self.assertEqual(payload["result"]["probe"], "udp")
        self.assertTrue(payload["result"]["summary"]["reached"])
        self.assertEqual(payload["result"]["summary"]["loss_percent"], 0.0)

    async def test_mtr_dest_sent_equals_cycles(self):
        for n in (3, 30):
            payload = await probe.mtr_async("example.com", cycles=n, engine=FakeEngine())
            dest = payload["result"]["hops"][-1]
            self.assertEqual(len(payload["result"]["hops"]), 3)
            self.assertEqual(payload["result"]["cycles"], n)
            self.assertEqual(dest["host"], "1.1.1.1")
            self.assertEqual(dest["sent"], n)

    async def test_mtr_stops_on_anycast_dest_unreach(self):
        class AnycastEngine(FakeEngine):
            def __init__(self):
                super().__init__(ip="2606:4700:4700::1111")
                self.family = socket.AF_INET6

            async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
                if ttl < 3:
                    return ProbeHit("ttl", f"2001:db8::{ttl}", 1.0, seq, ttl)
                return ProbeHit("unreach", "2400:cb00::1", 1.0, seq, ttl)

        payload = await probe.mtr_async(
            "2606:4700:4700::1111", cycles=2, engine=AnycastEngine()
        )
        hops = payload["result"]["hops"]
        self.assertTrue(payload["result"]["reached"])
        self.assertEqual(hops[-1]["hop"], 3)
        self.assertEqual(hops[-1]["host"], "2400:cb00::1")
        self.assertEqual(hops[-1]["sent"], 2)
        self.assertLess(len(hops), 10)

    async def test_mtr_keeps_dest_sent_when_path_shortens(self):
        class FlapEngine(FakeEngine):
            def __init__(self):
                super().__init__()
                self._saw_dest = False

            async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
                if ttl <= 7:
                    return ProbeHit("ttl", f"10.0.0.{ttl}", 1.0, seq, ttl)
                if ttl == 8:
                    if self._saw_dest:
                        return ProbeHit("reply", "162.158.61.8", 1.0, seq, ttl)
                    return ProbeHit("ttl", "10.0.0.8", 1.0, seq, ttl)
                if ttl == 9:
                    self._saw_dest = True
                    return ProbeHit("reply", ip, 1.0, seq, ttl)
                return ProbeHit("timeout", None, None, seq, ttl, "timeout")

        payload = await probe.mtr_async("1.1.1.1", cycles=3, engine=FlapEngine())
        hops = payload["result"]["hops"]
        dest = hops[-1]
        self.assertEqual(dest["hop"], 9)
        self.assertEqual(dest["host"], "1.1.1.1")
        self.assertEqual(dest["sent"], 3)
        self.assertEqual(payload["result"]["cycles"], 3)

    async def test_mtr_clamps_cycles(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.config.get_root", return_value=tmp):
                zero = await probe.mtr_async("example.com", cycles=0, engine=FakeEngine())
                self.assertEqual(zero["result"]["cycles"], 1)
                self.assertEqual(zero["result"]["hops"][-1]["sent"], 1)
                high = await probe.mtr_async("example.com", cycles=999, engine=FakeEngine())
                self.assertEqual(high["result"]["cycles"], 30)
                self.assertEqual(high["result"]["hops"][-1]["sent"], 30)
                omitted = await probe.mtr_async("example.com", engine=FakeEngine())
                self.assertEqual(omitted["result"]["cycles"], 10)
                self.assertEqual(omitted["result"]["hops"][-1]["sent"], 10)
                self.assertEqual(len(omitted["result"]["hops"]), 3)

    async def test_mtr_stops_at_first_dest_hop(self):
        class DestBeyondEngine(FakeEngine):
            async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
                if ttl < 8:
                    return ProbeHit("ttl", f"10.0.0.{ttl}", 1.0, seq, ttl)
                return ProbeHit("reply", ip, 12.0, seq, ttl)

        for n in (3, 30):
            payload = await probe.mtr_async("1.1.1.1", cycles=n, engine=DestBeyondEngine())
            hops = payload["result"]["hops"]
            dest = hops[-1]
            self.assertEqual(len(hops), 8)
            self.assertEqual([row["hop"] for row in hops], list(range(1, 9)))
            self.assertEqual(dest["hop"], 8)
            self.assertEqual(dest["host"], "1.1.1.1")
            self.assertEqual(dest["sent"], n)
            self.assertEqual(payload["result"]["cycles"], n)
            self.assertTrue(payload["result"]["reached"])
            self.assertEqual(payload["result"]["summary"]["latency_ms"], dest["avg_ms"])

        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.config.get_root", return_value=tmp):
                omitted = await probe.mtr_async("1.1.1.1", engine=DestBeyondEngine())
                self.assertEqual(len(omitted["result"]["hops"]), 8)
                self.assertEqual(omitted["result"]["hops"][-1]["sent"], 10)
                high = await probe.mtr_async("1.1.1.1", cycles=999, engine=DestBeyondEngine())
                self.assertEqual(len(high["result"]["hops"]), 8)
                self.assertEqual(high["result"]["hops"][-1]["sent"], 30)

    async def test_mtr_drops_later_dest_row_when_lower_hop_is_target(self):
        class LateLowerDest(FakeEngine):
            def __init__(self):
                super().__init__()
                self._saw_dest = False

            async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
                if ttl < 8:
                    return ProbeHit("ttl", f"10.0.0.{ttl}", 1.0, seq, ttl)
                if ttl == 8:
                    if self._saw_dest:
                        return ProbeHit("reply", ip, 11.0, seq, ttl)
                    return ProbeHit("ttl", "10.0.0.8", 1.0, seq, ttl)
                self._saw_dest = True
                return ProbeHit("reply", ip, 12.0, seq, ttl)

        for n in (3, 10, 30):
            payload = await probe.mtr_async("1.1.1.1", cycles=n, engine=LateLowerDest())
            hops = payload["result"]["hops"]
            dest = hops[-1]
            self.assertEqual(len(hops), 8)
            self.assertEqual([row["hop"] for row in hops], list(range(1, 9)))
            self.assertEqual(dest["hop"], 8)
            self.assertEqual(dest["host"], "1.1.1.1")
            self.assertEqual(dest["sent"], n)
            self.assertEqual(payload["result"]["cycles"], n)
            self.assertTrue(payload["result"]["reached"])

    async def test_traceroute_via_is_the_tool_not_hop_tcp(self):
        class UdpHops(FakeEngine):
            async def echo(self, *args, **kwargs):
                raise AssertionError("UDP traceroute must not fall back to ICMP echo")

            async def echo_or_udp(self, ip, family, *, ttl, ident, seq, timeout, payload):
                hit = await FakeEngine.echo(
                    self,
                    ip,
                    family,
                    ttl=ttl,
                    ident=ident,
                    seq=seq,
                    timeout=timeout,
                    payload=payload,
                )
                return ProbeHit(hit.kind, hit.addr, hit.rtt_ms, hit.seq, hit.ttl, hit.error, via="udp")

        payload = await probe.traceroute_async("1.1.1.1", engine=UdpHops())
        self.assertEqual(payload["result"]["via"], "python-udp")
        hop_vias = [row["via"] for row in payload["result"]["hops"] if row.get("via")]
        self.assertTrue(hop_vias)
        self.assertTrue(all(via == "python-udp" for via in hop_vias))
        self.assertFalse(any("tcp" in via for via in hop_vias))

    async def test_traceroute_walks_max_hops_when_every_hop_is_silent(self):
        payload = await probe.traceroute_async(
            "24.154.32.53", timeout=0.05, max_hops=8, engine=TimeoutEngine()
        )
        hops = payload["result"]["hops"]
        self.assertEqual(len(hops), 8)
        self.assertTrue(all(row["status"] == "timeout" for row in hops))
        self.assertFalse(payload["result"]["reached"])

    async def test_traceroute_silent_path_is_one_wait_not_stacked(self):
        engine = TimeoutEngine(delay=0.2)
        t0 = time.perf_counter()
        payload = await probe.traceroute_async(
            "24.154.32.53", timeout=0.25, max_hops=5, engine=engine
        )
        elapsed = time.perf_counter() - t0
        self.assertEqual(len(payload["result"]["hops"]), 5)
        # Sequential hops × 3 probes × 0.2s is 3s; stacked UDP/ICMP/TCP was ~9s.
        # Hops in flight like traceroute -N should finish in about one probe wait.
        self.assertLess(elapsed, 0.7)

    async def test_traceroute_stops_after_path_goes_silent(self):
        payload = await probe.traceroute_async(
            "24.154.32.53", timeout=0.05, engine=PartialPathEngine(last_hop=7)
        )
        hops = payload["result"]["hops"]
        self.assertEqual(len(hops), 7 + probe.TRACE_STOP_TIMEOUTS)
        self.assertEqual([row["status"] for row in hops[:7]], ["ttl"] * 7)
        self.assertTrue(all(row["status"] == "timeout" for row in hops[7:]))
        self.assertFalse(payload["result"]["reached"])

    async def test_mtr_does_not_stop_on_leading_timeouts(self):
        payload = await probe.mtr_async(
            "24.154.32.53", cycles=2, timeout=0.05, max_hops=8, engine=TimeoutEngine()
        )
        hops = payload["result"]["hops"]
        self.assertEqual(len(hops), 8)
        self.assertFalse(payload["result"]["reached"])
        self.assertEqual(hops[-1]["sent"], 2)

    async def test_mtr_caps_after_last_reply(self):
        payload = await probe.mtr_async(
            "24.154.32.53", cycles=2, timeout=0.05, engine=PartialPathEngine(last_hop=7)
        )
        hops = payload["result"]["hops"]
        self.assertEqual(len(hops), 7 + probe.MTR_STOP_TIMEOUTS)
        self.assertEqual(hops[6]["host"], "10.0.0.7")
        self.assertFalse(payload["result"]["reached"])

    async def test_echo_or_udp_timeout_does_not_stack_icmp_or_tcp(self):
        engine = probe.SocketEngine()
        miss = ProbeHit("timeout", None, None, 1, 3, "timeout", via="udp")

        with (
            patch.object(probe, "_icmp_ttl_probe_sync") as icmp,
            patch.object(probe, "_udp_probe_wait", return_value=miss),
            patch.object(probe, "_tcp_probe_sync") as tcp,
        ):
            hit = await engine.echo_or_udp(
                "24.154.32.53",
                socket.AF_INET,
                ttl=3,
                ident=1,
                seq=1,
                timeout=0.2,
                payload=b"x",
            )
        self.assertEqual(hit.kind, "timeout")
        tcp.assert_not_called()
        icmp.assert_not_called()

    async def test_echo_or_udp_does_not_start_tcp(self):
        engine = probe.SocketEngine()
        udp_hit = ProbeHit("ttl", "10.0.0.1", 1.2, 1, 1, via="udp")

        with (
            patch.object(probe, "_udp_probe_wait", return_value=udp_hit) as udp,
            patch.object(probe, "_tcp_probe_sync") as tcp,
            patch.object(probe, "_icmp_ttl_probe_sync") as icmp,
        ):
            hit = await engine.echo_or_udp(
                "8.8.8.8",
                socket.AF_INET,
                ttl=1,
                ident=1,
                seq=1,
                timeout=0.2,
                payload=b"x",
            )
        self.assertEqual(hit.addr, "10.0.0.1")
        self.assertEqual(hit.via, "udp")
        udp.assert_called_once()
        tcp.assert_not_called()
        icmp.assert_not_called()

    async def test_traceroute_stops_repeating_the_same_hop(self):
        class StickyEngine(FakeEngine):
            async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
                if ttl <= 2:
                    return ProbeHit("ttl", f"10.0.0.{ttl}", 1.0, seq, ttl)
                return ProbeHit("ttl", "203.119.105.59", 1.0, seq, ttl)

        payload = await probe.traceroute_async("8.8.8.8", engine=StickyEngine())
        hops = payload["result"]["hops"]
        self.assertEqual(hops[0]["host"], "10.0.0.1")
        self.assertEqual(hops[1]["host"], "10.0.0.2")
        sticky = [row["host"] for row in hops[2:]]
        self.assertTrue(sticky)
        self.assertTrue(all(host == "203.119.105.59" for host in sticky))
        self.assertLessEqual(len(hops), 5)

    async def test_mtr_stops_repeating_the_same_hop(self):
        class StickyEngine(FakeEngine):
            async def echo(self, ip, family, *, ttl, ident, seq, timeout, payload):
                if ttl <= 2:
                    return ProbeHit("ttl", f"10.0.0.{ttl}", 1.0, seq, ttl)
                return ProbeHit("ttl", "203.119.105.59", 1.0, seq, ttl)

        payload = await probe.mtr_async("8.8.8.8", cycles=1, engine=StickyEngine())
        hops = payload["result"]["hops"]
        self.assertEqual(hops[0]["host"], "10.0.0.1")
        self.assertLessEqual(len(hops), 5)
        self.assertEqual(hops[-1]["host"], "203.119.105.59")

    async def test_ping_uses_echo_or_udp_when_present(self):
        class TcpEngine(FakeEngine):
            async def echo(self, *args, **kwargs):
                raise AssertionError("ICMP should not be required")

            async def echo_or_udp(self, ip, family, *, ttl, ident, seq, timeout, payload):
                return ProbeHit("reply", ip, 2.5, seq, ttl, via="tcp")

        payload = await probe.ping_async("example.com", count=1, engine=TcpEngine())
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["via"], "python-tcp")
        self.assertEqual(payload["result"]["received"], 1)

    async def test_enrich_attaches_asn_and_flag(self):
        result = {
            "ip": "1.1.1.1",
            "probes": [{"seq": 1, "from": "1.1.1.1", "ok": True, "rtt_ms": 1.0}],
            "hops": [{"hop": 1, "host": "10.0.0.1"}],
        }

        async def fake_lookup(ips):
            self.assertEqual(ips, ["1.1.1.1", "10.0.0.1"])
            return {
                "1.1.1.1": {
                    "asn": 13335,
                    "org_name": "CLOUDFLARENET",
                    "country": "AU",
                    "flag": "🇦🇺",
                    "flag_url": "https://flagcdn.com/au.svg",
                    "country_name": "Australia",
                },
                "10.0.0.1": {
                    "asn": 64496,
                    "country": "US",
                    "flag_url": "https://flagcdn.com/us.svg",
                },
            }

        async def _noop_ptr(_result):
            return None

        with patch("looking_glass.net.probe.lookup_path_intel", new=fake_lookup), patch(
            "looking_glass.net.probe._attach_ptr_names", new=_noop_ptr
        ):
            out = await probe.enrich_probe_result(result)
        self.assertEqual(out["asn"], 13335)
        self.assertEqual(out["org_name"], "CLOUDFLARENET")
        self.assertEqual(out["probes"][0]["flag_url"], "https://flagcdn.com/au.svg")
        self.assertEqual(out["hops"][0]["asn"], 64496)

    def test_intel_fills_flag_from_country(self):
        intel = probe._intel_from_daemon(
            {"ok": True, "result": {"asn": 13335, "country": "AU", "org_name": "CLOUDFLARENET"}}
        )
        self.assertEqual(intel["asn"], 13335)
        self.assertIn("flagcdn.com/au.svg", intel["flag_url"])
        self.assertIn("<img", intel["flag_html"])

    def test_classify_private_and_special_hops(self):
        self.assertEqual(probe.classify_ip("10.64.4.29", local_nets=())["scope"], "private")
        self.assertEqual(probe.classify_ip("10.64.4.29", local_nets=())["scope_label"], "RFC1918")
        self.assertFalse(probe.classify_ip("10.64.4.29", local_nets=())["lan"])
        self.assertEqual(
            probe.classify_ip("10.64.4.29", local_nets=())["scope_detail"],
            "Private/internal network address (RFC 1918)",
        )
        self.assertEqual(probe.classify_ip("100.64.0.1", local_nets=())["scope"], "cgnat")
        self.assertEqual(probe.classify_ip("169.254.169.254", local_nets=())["scope"], "cloud-gateway")
        self.assertFalse(probe.classify_ip("192.168.1.1", local_nets=())["lan"])
        self.assertEqual(probe.classify_ip("192.168.1.1", local_nets=())["scope_label"], "RFC1918")
        lan = (ipaddress.ip_network("10.0.0.0/24"),)
        self.assertEqual(probe.classify_ip("10.0.0.5", local_nets=lan)["scope"], "lan")
        self.assertEqual(probe.classify_ip("10.0.0.5", local_nets=lan)["scope_label"], "LAN")
        self.assertTrue(probe.classify_ip("10.0.0.5", local_nets=lan)["lan"])
        self.assertFalse(probe.classify_ip("10.64.4.29", local_nets=lan)["lan"])
        self.assertEqual(probe.classify_ip("1.1.1.1", local_nets=())["scope"], "public")
        self.assertEqual(probe.classify_ip(None)["scope"], "none")

    def test_hosts_detail_classifies_each_alternate_ip(self):
        result = {
            "hops": [
                {
                    "hop": 6,
                    "host": "10.64.0.250",
                    "hosts": ["10.64.0.250", "63.218.9.241"],
                }
            ]
        }
        with patch("looking_glass.net.probe.local_networks", return_value=()):
            probe.annotate_scopes(result)
        hop = result["hops"][0]
        self.assertEqual(hop["scope_label"], "RFC1918")
        self.assertFalse(hop["lan"])
        by_ip = {entry["ip"]: entry for entry in hop["hosts_detail"]}
        self.assertEqual(by_ip["10.64.0.250"]["scope_label"], "RFC1918")
        self.assertEqual(by_ip["63.218.9.241"]["scope"], "public")
        self.assertEqual(by_ip["63.218.9.241"]["scope_label"], "Public")

    def test_infer_place_from_router_hostnames(self):
        lax = probe.infer_place("hu0-0-0-3.br05.lax04.as3491.net")
        self.assertEqual(lax["place"], "Los Angeles")
        self.assertEqual(lax["place_country"], "US")
        self.assertEqual(
            probe.infer_place("i-1113.sydp-core03.telstraglobal.net")["place"], "Sydney"
        )
        self.assertEqual(
            probe.infer_place("bundle-ether7.hay-core30.sydney.telstra.net")["place"],
            "Sydney",
        )
        self.assertIsNone(probe.infer_place("63.218.9.241"))
        self.assertIsNone(probe.infer_place("63-218-51-150.static.as3491.net"))

    def test_interpret_path_splits_geoip_and_hostname_cities(self):
        result = {
            "reached": True,
            "hops": [
                {
                    "hop": 7,
                    "host": "63.218.50.245",
                    "name": "hu0-0-0-3.br05.lax04.as3491.net",
                    "asn": 3491,
                    "country": "HK",
                    "country_name": "Hong Kong",
                    "place": "Los Angeles",
                    "place_country": "US",
                    "scope": "public",
                },
                {
                    "hop": 11,
                    "host": "202.84.141.46",
                    "name": "i-1113.sydp-core03.telstraglobal.net",
                    "asn": 4637,
                    "country": "HK",
                    "country_name": "Hong Kong",
                    "place": "Sydney",
                    "place_country": "AU",
                    "scope": "public",
                },
                {
                    "hop": 12,
                    "host": "203.50.6.107",
                    "name": "bundle-ether7.hay-core30.sydney.telstra.net",
                    "asn": 1221,
                    "country": "AU",
                    "country_name": "Australia",
                    "place": "Sydney",
                    "place_country": "AU",
                    "scope": "public",
                    "avg_ms": 214.809,
                },
            ],
        }
        summary = probe.interpret_path(result)
        self.assertEqual(summary["route_text"], "Hong Kong → Australia")
        self.assertEqual(summary["inferred_text"], "Los Angeles → Sydney")

    def test_interpret_path_countries_as_and_icmp_loss_note(self):
        result = {
            "reached": True,
            "hops": [
                {"hop": 1, "host": "169.254.169.254", **probe.classify_ip("169.254.169.254", local_nets=())},
                {"hop": 2, "host": "10.64.10.169", **probe.classify_ip("10.64.10.169", local_nets=())},
                {
                    "hop": 7,
                    "host": "173.205.45.233",
                    "asn": 3257,
                    "country": "US",
                    "country_name": "United States",
                    "loss_percent": 0.0,
                    **probe.classify_ip("173.205.45.233", local_nets=()),
                },
                {
                    "hop": 10,
                    "host": "129.250.2.1",
                    "asn": 2914,
                    "country": "US",
                    "country_name": "United States",
                    "loss_percent": 20.0,
                    **probe.classify_ip("129.250.2.1", local_nets=()),
                },
                {
                    "hop": 12,
                    "host": "168.209.1.1",
                    "asn": 3741,
                    "country": "ZA",
                    "country_name": "South Africa",
                    "loss_percent": 0.0,
                    **probe.classify_ip("168.209.1.1", local_nets=()),
                },
                {
                    "hop": 15,
                    "host": "196.216.2.1",
                    "asn": 33764,
                    "country": "MU",
                    "country_name": "Mauritius",
                    "loss_percent": 0.0,
                    "avg_ms": 225.517,
                    **probe.classify_ip("196.216.2.1", local_nets=()),
                },
            ],
        }
        summary = probe.interpret_path(result)
        self.assertEqual(
            summary["route_text"],
            "United States → South Africa → Mauritius",
        )
        self.assertEqual(summary["as_text"], "AS3257 → AS2914 → AS3741 → AS33764")
        self.assertTrue(summary["reached"])
        self.assertEqual(summary["loss_percent"], 0.0)
        self.assertEqual(summary["latency_ms"], 225.517)
        self.assertTrue(
            any("Intermediate ICMP loss" in note for note in summary["warnings"])
        )

    def test_interpret_path_uses_public_alternate_on_private_hop(self):
        result = {
            "reached": True,
            "hops": [
                {
                    "hop": 1,
                    "host": "10.64.10.169",
                    "scope": "private",
                    "hosts_detail": [
                        {"ip": "10.64.10.169", "scope": "private"},
                        {
                            "ip": "63.218.9.241",
                            "scope": "public",
                            "asn": 3491,
                            "country_name": "Hong Kong",
                        },
                    ],
                },
                {
                    "hop": 2,
                    "host": "1.1.1.1",
                    "scope": "public",
                    "asn": 13335,
                    "country_name": "Australia",
                    "status": "reply",
                    "rtt_ms": 2.4,
                },
            ],
        }
        summary = probe.interpret_path(result)
        self.assertEqual(summary["route_text"], "Hong Kong → Australia")
        self.assertEqual(summary["as_text"], "AS3491 → AS13335")


if __name__ == "__main__":
    unittest.main()
