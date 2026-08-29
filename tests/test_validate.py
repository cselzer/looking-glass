import ipaddress
import json
import os
import random
import tempfile
import unittest
from array import array
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass.cli.entry import cli, _format_elapsed, _run_validate, _sample_iana_rows
from looking_glass.intel import iana as iana_mod


class FormatElapsedTests(unittest.TestCase):
    def test_units(self):
        self.assertEqual(_format_elapsed(0), "<1 µs")
        self.assertEqual(_format_elapsed(5e-6), "5 µs")
        self.assertEqual(_format_elapsed(0.0123), "12.3 ms")
        self.assertEqual(_format_elapsed(0.745), "745 ms")
        self.assertEqual(_format_elapsed(1.5), "1.50 s")


class ValidateMissingCacheTests(unittest.TestCase):
    def test_empty_data_dir_fails(self):
        with tempfile.TemporaryDirectory() as tmp:

            def cache_path(name: str) -> str:
                return os.path.join(tmp, name)

            with patch("looking_glass.cli.entry.get_data_dir", return_value=tmp), patch(
                "looking_glass.cli.entry.get_cache_path", side_effect=cache_path
            ):
                report = _run_validate()
        self.assertFalse(report["ok"])
        self.assertGreater(report["failed"], 0)
        self.assertIn("elapsed", report)
        self.assertGreaterEqual(report["elapsed_s"], 0)
        self.assertIn("seed", report)
        file_checks = [row for row in report["checks"] if row["id"].startswith("file.")]
        self.assertTrue(all(row["status"] == "failed" for row in file_checks))
        self.assertTrue(all(row["detail"] == "missing" for row in file_checks))
        for row in report["checks"]:
            self.assertIn("started", row)
            self.assertIn("finished", row)
            self.assertIn("elapsed", row)
            self.assertGreaterEqual(row["elapsed_s"], 0)
            self.assertRegex(row["elapsed"], r"(µs|ms|s)$")

    def test_cli_json_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:

            def cache_path(name: str) -> str:
                return os.path.join(tmp, name)

            runner = CliRunner()
            with patch("looking_glass.cli.entry.get_data_dir", return_value=tmp), patch(
                "looking_glass.cli.entry.get_cache_path", side_effect=cache_path
            ):
                result = runner.invoke(cli, ["--json", "validate"])
        self.assertEqual(result.exit_code, 2)
        payload = json.loads(result.output)
        self.assertFalse(payload["ok"])
        self.assertIn("elapsed_s", payload)
        self.assertIn("elapsed", payload["checks"][0])
        self.assertIn("seed", payload)
        ids = {row["id"] for row in payload["checks"]}
        self.assertTrue(any(i.startswith("sample.") for i in ids), ids)

    def test_cli_streams_sections(self):
        with tempfile.TemporaryDirectory() as tmp:

            def cache_path(name: str) -> str:
                return os.path.join(tmp, name)

            runner = CliRunner()
            with patch("looking_glass.cli.entry.get_data_dir", return_value=tmp), patch(
                "looking_glass.cli.entry.get_cache_path", side_effect=cache_path
            ):
                result = runner.invoke(cli, ["--json", "validate"])
        self.assertEqual(result.exit_code, 2)
        payload = json.loads(result.output)
        self.assertFalse(payload["ok"])
        ids = {row["id"] for row in payload["checks"]}
        self.assertTrue(any(i.startswith("file.") for i in ids), ids)
        self.assertTrue(any(i.startswith("sample.") for i in ids), ids)
        self.assertIn("seed", payload)

    def test_sample_titles_include_the_ip(self):
        fake_file = {"path": "x", "state": "ok", "size": 99, "mtime": 1.0}
        with (
            patch(
                "looking_glass.cli.entry._file_validate_row",
                return_value=fake_file,
            ),
            patch("looking_glass.cli.entry._read_refresh_policy", return_value={"days": {}}),
            patch("looking_glass.intel.iana.load", return_value=True),
            patch("looking_glass.dns.resolve.load", return_value=True),
            patch("looking_glass.intel.rir.load", return_value=True),
            patch("looking_glass.intel.asn_org.load", return_value=True),
            patch("looking_glass.intel.asn.load", return_value=True),
            patch(
                "looking_glass.cli.entry._sample_iana_rows",
                return_value=[
                    {"ip": "2001:db8::1", "expect": {"cidr": "2001:db8::/32"}}
                ],
            ),
            patch("looking_glass.cli.entry._sample_rir_rows", return_value=[]),
            patch("looking_glass.cli.entry._sample_asn_rows", return_value=[]),
            patch(
                "looking_glass.cli.entry._lookup_ip",
                return_value={
                    "ok": True,
                    "result": {
                        "source": "iana",
                        "iana": {"cidr": "2001:db8::/32"},
                    },
                },
            ),
        ):
            report = _run_validate(seed=1)
        titles = [
            row["check"]
            for row in report["checks"]
            if str(row["id"]).startswith("sample.iana.")
        ]
        self.assertEqual(titles, ["IANA 2001:db8::1"])


class LookupCliTests(unittest.TestCase):
    def test_commands_are_consolidated(self):
        self.assertEqual(
            set(cli.commands),
            {
                "build",
                "validate",
                "docs",
                "locale",
                "config",
                "auth",
                "lookup-server",
                "https",
                "status",
                "restart",
                "boot",
                "lookup",
                "ip",
                "asn",
                "dns",
                "dnssec",
                "tls",
                "apex",
                "register",
                "ping",
                "traceroute",
                "mtr",
                "tcptraceroute",
                "rdap",
                "whois",
                "reputation",
                "bgp",
                "dnstrace",
                "http",
                "ptr",
                "mail",
                "tcp",
                "pmtu",
                "cache",
                "wall",
                "logs",
            },
        )
        self.assertEqual(set(cli.commands["lookup"].commands), {"query", "bench"})

    def test_old_commands_removed(self):
        runner = CliRunner()
        for name in ("status", "clear"):
            result = runner.invoke(cli, [name])
            self.assertNotEqual(result.exit_code, 0)

    def test_rejects_garbage(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["lookup", "not a name"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("not an IP address, ASN, country code, or DNS name", result.output)

    def test_dns_name_json(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "name": "example.com.",
            "qtype": "AAAA",
            "result": {"status": "NOERROR", "qtype": "AAAA", "answers": []},
            "error": None,
        }
        with patch("looking_glass.dns.resolve.lookup_dns", return_value=fake):
            result = runner.invoke(cli, ["--json", "lookup", "example.com", "--type", "AAAA"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["qtype"], "AAAA")
        self.assertEqual(payload["result"]["status"], "NOERROR")

    def test_type_flag_requires_dns_name(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["lookup", "1.1.1.1", "--type", "AAAA"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--type only applies to DNS names", result.output)

    def test_local_fallback_json(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "ip": "1.1.1.1",
            "result": {
                "ip": "1.1.1.1",
                "source": "rir",
                "country": "AU",
                "asn": 13335,
            },
        }
        with patch("looking_glass.cli.entry._daemon_running", return_value=False), patch(
            "looking_glass.cli.entry._lookup_ip", return_value=fake
        ):
            result = runner.invoke(cli, ["--json", "lookup", "1.1.1.1"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["via"], "local")
        self.assertFalse(payload["intel"]["running"])
        self.assertEqual(payload["result"]["country"], "AU")

    def test_daemon_path_is_silent(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "ip": "1.1.1.1",
            "result": {"ip": "1.1.1.1", "country": "AU", "asn": 13335},
        }
        with patch(
            "looking_glass.cli.entry._lookup_prefer_daemon", return_value=(fake, "intel")
        ):
            result = runner.invoke(cli, ["--json", "lookup", "1.1.1.1"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["via"], "intel")
        self.assertTrue(payload["intel"]["running"])
        self.assertNotIn("not running", result.output.lower())

    def test_bulk_file_jsonl(self):
        runner = CliRunner()

        def fake_lookup(ip, load=False):
            return {"ok": True, "ip": ip, "result": {"ip": ip, "country": "AU"}}

        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("1.1.1.1\n# skip\n8.8.8.8\nnot a name\n")
            path = fh.name
        try:
            with patch("looking_glass.cli.entry._daemon_running", return_value=False), patch(
                "looking_glass.cli.entry._warmup"
            ), patch("looking_glass.cli.entry._lookup_ip", side_effect=fake_lookup):
                result = runner.invoke(cli, ["--json", "lookup", "--file", path, "-c", "2"])
        finally:
            os.unlink(path)
        self.assertEqual(result.exit_code, 0, result.output)
        rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(len(rows), 3)
        self.assertTrue(rows[0]["ok"])
        self.assertEqual(rows[0]["ip"], "1.1.1.1")
        self.assertTrue(rows[1]["ok"])
        self.assertEqual(rows[1]["ip"], "8.8.8.8")
        self.assertFalse(rows[2]["ok"])
        self.assertEqual(rows[2]["query"], "not a name")


class ServeCliTests(unittest.TestCase):
    def test_status_not_running_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            from looking_glass.intel_server import app as lookup_mod

            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()
                runner = CliRunner()
                result = runner.invoke(cli, ["--json", "lookup-server", "status"])
                lookup_mod._data_dir_path.cache_clear()
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertFalse(payload["running"])
        self.assertFalse(payload["ready"])
        self.assertNotIn("https", payload)
        self.assertIn("lookup.sock", payload["socket"])
        self.assertIn(tmp, payload["data"])


class SampleFromSourceTests(unittest.TestCase):
    def test_iana_samples_come_from_loaded_range(self):
        start = int(ipaddress.IPv4Address("192.0.2.0"))
        end = int(ipaddress.IPv4Address("192.0.2.255"))
        meta = [{"cidr": "192.0.2.0/24", "designation": "TEST-NET-1"}]
        with (
            patch.object(iana_mod, "_starts_v4", array("I", [start])),
            patch.object(iana_mod, "_ends_v4", array("I", [end])),
            patch.object(iana_mod, "_meta_v4", meta),
            patch.object(iana_mod, "_starts_v6", None),
            patch.object(iana_mod, "_meta_v6", None),
        ):
            rng = random.Random(7)
            rows = _sample_iana_rows(rng, 3)
            again = _sample_iana_rows(random.Random(7), 3)
        self.assertEqual(len(rows), 3)
        self.assertEqual([row["ip"] for row in rows], [row["ip"] for row in again])
        net = ipaddress.ip_network("192.0.2.0/24")
        for row in rows:
            self.assertIn(ipaddress.ip_address(row["ip"]), net)
            self.assertEqual(row["expect"]["cidr"], "192.0.2.0/24")


class IanaOverlapTests(unittest.TestCase):
    def test_covering_range_not_shadowed_by_later_start(self):
        saved = (
            iana_mod._starts_v4,
            iana_mod._ends_v4,
            iana_mod._meta_v4,
            iana_mod._starts_v6,
            iana_mod._ends_v6,
            iana_mod._meta_v6,
            iana_mod._built,
        )
        try:
            iana_mod._build_arrays_from_entries(
                [
                    {"cidr": "192.88.99.0/24", "designation": "6to4"},
                    {"cidr": "192.88.99.2/32", "designation": "6a44"},
                ]
            )
            wide = iana_mod.find_for_ip("192.88.99.100")
            host = iana_mod.find_for_ip("192.88.99.2")
            miss = iana_mod.find_for_ip("1.1.1.1")
        finally:
            (
                iana_mod._starts_v4,
                iana_mod._ends_v4,
                iana_mod._meta_v4,
                iana_mod._starts_v6,
                iana_mod._ends_v6,
                iana_mod._meta_v6,
                iana_mod._built,
            ) = saved
        self.assertIsNotNone(wide)
        self.assertEqual(wide["cidr"], "192.88.99.0/24")
        self.assertIsNotNone(host)
        self.assertEqual(host["cidr"], "192.88.99.2/32")
        self.assertIsNone(miss)


class FlagDisplayTests(unittest.TestCase):
    def test_console_and_web(self):
        from looking_glass.intel.flags import flag_html, flag_info, flag_url, country_to_flag

        au = flag_info("au")
        self.assertEqual(au.code, "AU")
        self.assertEqual(au.emoji, country_to_flag("AU"))
        self.assertEqual(au.name, "Australia")
        self.assertEqual(au.url, "https://flagcdn.com/au.svg")
        self.assertIn("AU  Australia", au.text())
        html = flag_html("AU")
        self.assertIn("<img", html)
        self.assertIn("flagcdn.com/au.svg", html)
        self.assertIn("Australia", html)
        self.assertEqual(flag_url("UK"), "https://flagcdn.com/gb.svg")
        unknown = flag_info("??")
        self.assertIsNone(unknown.url)
        self.assertEqual(unknown.emoji, "❓")

    def test_supported_countries_catalog(self):
        from looking_glass.intel.flags import supported_countries

        rows = supported_countries()
        codes = {row["code"] for row in rows}
        self.assertIn("AU", codes)
        self.assertIn("US", codes)
        self.assertIn("GB", codes)
        au = next(row for row in rows if row["code"] == "AU")
        self.assertEqual(au["name"], "Australia")
        self.assertIn("flagcdn.com/au.svg", au.get("flag_url") or "")
        self.assertNotIn("ZZ", codes)


if __name__ == "__main__":
    unittest.main()
