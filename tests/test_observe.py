import platform
import socket
import tempfile
import unittest
from pathlib import Path
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


class HostResourcesTests(unittest.TestCase):
    def _proc(self, tmp: str) -> Path:
        root = Path(tmp)
        (root / "self").mkdir()
        (root / "net").mkdir()
        (root / "meminfo").write_text(
            "MemTotal:        2015288 kB\n"
            "MemAvailable:     550808 kB\n"
            "SwapTotal:       6451200 kB\n"
            "SwapFree:        6450944 kB\n",
            encoding="utf-8",
        )
        (root / "self" / "status").write_text("Name:\tpython\nVmRSS:\t  10184 kB\n", encoding="utf-8")
        (root / "vmstat").write_text(
            "pgpgin 494232\n"
            "pgpgout 1788261\n"
            "pswpin 0\n"
            "pswpout 13\n"
            "pgmajfault 1183\n"
            "nr_free_pages 99\n",
            encoding="utf-8",
        )
        (root / "diskstats").write_text(
            "   1       0 ram0 0 0 0 0 0 0 0 0 0 0 0\n"
            "   8       0 vda 16477 0 988465 0 112952 0 11144178 0 0 0 0 0 0 0\n"
            " 259       0 nvme0n1 10 0 20 0 30 0 40 0 0 0 0 0 0 0\n",
            encoding="utf-8",
        )
        (root / "net" / "dev").write_text(
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
            "    lo: 1 1 0 0 0 0 0 0 1 1 0 0 0 0 0 0\n"
            "  docker0: 9 9 0 0 0 0 0 0 9 9 0 0 0 0 0 0\n"
            "  veth0: 8 8 0 0 0 0 0 0 8 8 0 0 0 0 0 0\n"
            "  br-abc: 7 7 0 0 0 0 0 0 7 7 0 0 0 0 0 0\n"
            "enp1s0: 334757487 78920 0 0 0 0 0 0 26332325 57547 0 0 0 0 0 0\n",
            encoding="utf-8",
        )
        return root

    def test_parses_proc_fixture(self):
        with tempfile.TemporaryDirectory() as tmp:
            got = observe.host_resources(proc_root=self._proc(tmp))
        self.assertEqual(got["memory"]["total"], 2015288 * 1024)
        self.assertEqual(got["memory"]["available"], 550808 * 1024)
        self.assertEqual(got["memory"]["used"], (2015288 - 550808) * 1024)
        self.assertEqual(got["memory"]["rss"], 10184 * 1024)
        self.assertEqual(got["vm"]["pgpgin"], 494232)
        self.assertEqual(got["vm"]["pswpout"], 13)
        self.assertEqual(got["vm"]["pgmajfault"], 1183)
        self.assertEqual(got["io"]["vda"]["reads"], 16477)
        self.assertEqual(got["io"]["vda"]["wsec"], 11144178)
        self.assertEqual(got["io"]["nvme0n1"]["writes"], 30)
        self.assertNotIn("ram0", got["io"])
        self.assertEqual(got["net"]["enp1s0"]["rx_bytes"], 334757487)
        self.assertEqual(got["net"]["enp1s0"]["tx_bytes"], 26332325)
        self.assertNotIn("lo", got["net"])
        self.assertNotIn("docker0", got["net"])
        self.assertNotIn("veth0", got["net"])
        self.assertNotIn("br-abc", got["net"])

    def test_missing_proc_omits_sections(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(observe.host_resources(proc_root=Path(tmp)), {})

    def test_never_raises(self):
        self.assertIsInstance(observe.host_resources(proc_root=Path("/no/such/proc")), dict)

    def test_live_cache_ttl(self):
        observe.clear_host_resources_cache()
        self.addCleanup(observe.clear_host_resources_cache)
        mem = {"total": 1, "available": 0, "used": 1, "swap_total": 0, "swap_free": 0, "rss": 0}
        with (
            patch("looking_glass.observe._parse_meminfo", return_value=mem) as parse_mem,
            patch("looking_glass.observe._parse_vmstat", return_value=None),
            patch("looking_glass.observe._parse_diskstats", return_value=None),
            patch("looking_glass.observe._parse_netdev", return_value=None),
        ):
            first = observe.host_resources(now=10.0)
            second = observe.host_resources(now=10.5)
            self.assertEqual(first["memory"]["total"], 1)
            self.assertEqual(second["memory"]["total"], 1)
            self.assertEqual(parse_mem.call_count, 1)
            observe.host_resources(now=11.1)
            self.assertEqual(parse_mem.call_count, 2)

