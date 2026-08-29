import json
import os
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass.cli.entry import cli


def _looks_json_object(text: str) -> bool:
    blob = (text or "").lstrip()
    return blob.startswith("{")


class CliRenderTests(unittest.TestCase):
    def test_default_is_not_json_dump(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "ip": "1.1.1.1",
            "via": "local",
            "result": {"ip": "1.1.1.1", "country": "AU", "asn": 13335},
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.cli.entry._daemon_running", return_value=False),
                patch("looking_glass.cli.entry._lookup_ip", return_value=fake),
            ):
                listed = runner.invoke(cli, ["wall", "list"])
                looked = runner.invoke(cli, ["lookup", "1.1.1.1"])
        self.assertEqual(listed.exit_code, 0, listed.output)
        self.assertEqual(looked.exit_code, 0, looked.output)
        self.assertFalse(_looks_json_object(listed.stdout), listed.stdout)
        self.assertFalse(_looks_json_object(looked.stdout), looked.stdout)
        self.assertNotIn('"country_catalog"', listed.stdout)
        self.assertIn("AU", looked.stdout)

    def test_json_flag_parses(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "ip": "1.1.1.1",
            "via": "local",
            "intel": {"running": False},
            "result": {"ip": "1.1.1.1", "country": "AU", "asn": 13335},
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.cli.entry._daemon_running", return_value=False),
                patch("looking_glass.cli.entry._lookup_ip", return_value=fake),
            ):
                listed = runner.invoke(cli, ["--json", "wall", "list"])
                looked = runner.invoke(cli, ["--json", "lookup", "1.1.1.1"])
                after = runner.invoke(cli, ["wall", "list", "--json"])
        self.assertEqual(listed.exit_code, 0, listed.output)
        self.assertEqual(looked.exit_code, 0, looked.output)
        self.assertEqual(after.exit_code, 0, after.output)
        wall_payload = json.loads(listed.stdout)
        self.assertTrue(wall_payload["ok"])
        self.assertIn("ip", wall_payload)
        lookup_payload = json.loads(looked.stdout)
        self.assertEqual(lookup_payload["result"]["country"], "AU")
        self.assertEqual(json.loads(after.stdout)["ok"], True)

    def test_looking_glass_json_env(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.wall.lists.get_data_dir", return_value=tmp):
                with patch.dict(os.environ, {"LOOKING_GLASS_JSON": "1"}, clear=False):
                    result = runner.invoke(cli, ["wall", "list"])
                with patch.dict(os.environ, {"LOOKING_GLASS_JSON": "0"}, clear=False):
                    off = runner.invoke(cli, ["wall", "list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(json.loads(result.stdout)["ok"])
        self.assertEqual(off.exit_code, 0, off.output)
        self.assertFalse(_looks_json_object(off.stdout), off.stdout)


def _intel_report(**extra):
    payload = {
        "ok": True,
        "running": True,
        "ready": True,
        "state": "started",
        "pid": 9818,
        "uptime": 0.12,
        "socket": "/tmp/lookup.sock",
    }
    payload.update(extra)
    return payload


def _https_report(**extra):
    payload = {
        "ok": True,
        "running": True,
        "state": "started",
        "pid": 9823,
        "port": 5555,
        "uptime": 1.11,
        "days_left": 89,
        "fullchain": "/tmp/fullchain.pem",
        "privkey": "/tmp/privkey.pem",
    }
    payload.update(extra)
    return payload


class DaemonCliTests(unittest.TestCase):
    def test_status_is_compact_not_json(self):
        runner = CliRunner()
        with (
            patch("looking_glass.cli.boot.units_enabled", return_value=False),
            patch("looking_glass.intel_server.app.status", return_value=_intel_report()),
            patch("looking_glass.http.https_serve.status", return_value=_https_report()),
        ):
            human = runner.invoke(cli, ["status"])
            blob = runner.invoke(cli, ["--json", "status"])
        self.assertEqual(human.exit_code, 0, human.output)
        self.assertFalse(_looks_json_object(human.stdout), human.stdout)
        self.assertIn("intel", human.stdout)
        self.assertIn("https", human.stdout)
        self.assertIn("pid 9818", human.stdout)
        self.assertIn(":5555", human.stdout)
        self.assertIn("up 0s", human.stdout)
        self.assertIn("cert 89d", human.stdout)
        self.assertIn("/tmp/fullchain.pem", human.stdout)
        self.assertIn("/tmp/privkey.pem", human.stdout)
        self.assertNotIn("pidfile", human.stdout)
        self.assertEqual(blob.exit_code, 0, blob.output)
        payload = json.loads(blob.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["intel"]["pid"], 9818)
        self.assertEqual(payload["https"]["port"], 5555)

    def test_restart_calls_stop_then_start(self):
        runner = CliRunner()
        order = []

        def rec(name, payload):
            def inner(*_a, **_k):
                order.append(name)
                return dict(payload)

            return inner

        with (
            patch("looking_glass.cli.boot.units_enabled", return_value=False),
            patch("looking_glass.http.https_serve.stop", side_effect=rec("https.stop", {"ok": True, "running": False, "state": "stopped"})),
            patch("looking_glass.intel_server.app.stop", side_effect=rec("intel.stop", {"ok": True, "running": False, "state": "stopped"})),
            patch("looking_glass.intel_server.app.start", side_effect=rec("intel.start", _intel_report())),
            patch("looking_glass.http.https_serve.start", side_effect=rec("https.start", _https_report())),
        ):
            result = runner.invoke(cli, ["restart"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(order, ["https.stop", "intel.stop", "intel.start", "https.start"])
        self.assertFalse(_looks_json_object(result.stdout), result.stdout)
        self.assertIn("intel", result.stdout)
        self.assertIn("https", result.stdout)

    def test_restart_starts_from_stopped(self):
        runner = CliRunner()
        with (
            patch("looking_glass.cli.boot.units_enabled", return_value=False),
            patch("looking_glass.http.https_serve.stop", return_value={"ok": True, "running": False, "state": "stopped"}),
            patch("looking_glass.intel_server.app.stop", return_value={"ok": True, "running": False, "state": "stopped"}),
            patch("looking_glass.intel_server.app.start", return_value=_intel_report()) as intel_start,
            patch("looking_glass.http.https_serve.start", return_value=_https_report()) as https_start,
        ):
            result = runner.invoke(cli, ["restart"])
        self.assertEqual(result.exit_code, 0, result.output)
        intel_start.assert_called_once()
        https_start.assert_called_once()

    def test_restart_exits_1_when_start_fails(self):
        runner = CliRunner()
        with (
            patch("looking_glass.cli.boot.units_enabled", return_value=False),
            patch("looking_glass.http.https_serve.stop", return_value={"ok": True, "state": "stopped"}),
            patch("looking_glass.intel_server.app.stop", return_value={"ok": True, "state": "stopped"}),
            patch("looking_glass.intel_server.app.start", return_value=_intel_report()),
            patch("looking_glass.http.https_serve.start", return_value={"ok": False, "error": "no cert", "running": False}),
        ):
            result = runner.invoke(cli, ["restart"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("https", result.stdout)

    def test_https_renew_issued_shows_paths(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "running": False,
            "state": "issued",
            "issued": True,
            "port": 5555,
            "days_left": 89,
            "fullchain": "/tmp/fullchain.pem",
            "privkey": "/tmp/privkey.pem",
        }
        with patch("looking_glass.http.https_serve.renew", return_value=fake):
            result = runner.invoke(cli, ["https", "renew"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("issued", result.stdout)
        self.assertIn("/tmp/fullchain.pem", result.stdout)
        self.assertIn("/tmp/privkey.pem", result.stdout)


def _ip_payload():
    return {
        "ok": True,
        "kind": "ip",
        "query": "1.1.1.1",
        "ip": "1.1.1.1",
        "via": "intel",
        "result": {
            "ip": "1.1.1.1",
            "country": "AU",
            "country_name": "Australia",
            "source": "rir",
            "flag": "🇦🇺",
            "flag_url": "https://flagcdn.com/au.svg",
            "flag_html": '<img src="https://flagcdn.com/au.svg" alt="🇦🇺 Australia">',
            "asn": 13335,
        },
        "total_ms": 1.2,
    }


def _ping_payload(*, received=4):
    probes = []
    for seq in range(1, 5):
        probes.append(
            {
                "seq": seq,
                "from": "1.1.1.1",
                "rtt_ms": 12.3 if seq <= received else None,
                "ok": seq <= received,
                "error": None if seq <= received else "timeout",
                "via": "tcp",
            }
        )
    return {
        "ok": received > 0,
        "kind": "ping",
        "query": "1.1.1.1",
        "result": {
            "target": "1.1.1.1",
            "ip": "1.1.1.1",
            "transmitted": 4,
            "received": received,
            "loss_percent": round(100.0 * (4 - received) / 4, 1),
            "min_ms": 12.3 if received else None,
            "avg_ms": 12.3 if received else None,
            "max_ms": 12.3 if received else None,
            "probes": probes,
            "via": "python-tcp",
            "flag_html": '<img src="https://flagcdn.com/au.svg">',
        },
        "error": None if received else "100% loss",
    }


class HumanModeTests(unittest.TestCase):
    def setUp(self):
        self.runner = CliRunner()

    def test_ip_one_line_no_html(self):
        fake = _ip_payload()
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.cli.tools.lookup_classified", return_value=fake),
            ):
                human = self.runner.invoke(cli, ["ip", "1.1.1.1"])
                blob = self.runner.invoke(cli, ["--json", "ip", "1.1.1.1"])
        self.assertEqual(human.exit_code, 0, human.output)
        self.assertIn("1.1.1.1", human.stdout)
        self.assertIn("AU", human.stdout)
        self.assertIn("Australia", human.stdout)
        self.assertNotIn("<img", human.stdout)
        self.assertNotIn("ok true", human.stdout)
        self.assertNotIn("flag_html", human.stdout)
        payload = json.loads(blob.stdout)
        self.assertIn("<img", payload["result"]["flag_html"])

    def test_ping_seq_rtt_and_help(self):
        fake = _ping_payload()
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.cli.tools.lookup_classified", return_value=fake),
            ):
                human = self.runner.invoke(cli, ["ping", "1.1.1.1"])
        self.assertEqual(human.exit_code, 0, human.output)
        self.assertIn("PING 1.1.1.1", human.stdout)
        self.assertIn("seq 1", human.stdout)
        self.assertIn("12.3", human.stdout)
        self.assertIn("via tcp", human.stdout)
        self.assertNotIn("ok true", human.stdout)
        self.assertNotIn("<img", human.stdout)
        help_txt = self.runner.invoke(cli, ["ping", "--help"]).output
        self.assertNotIn("ICMP ping", help_txt)
        self.assertNotIn("same as GET", help_txt)
        self.assertIn("TCP", help_txt)

    def test_ping_rejects_bogus_and_junk_hosts(self):
        cases = (
            ["ping", "1.2.3"],
            ["ping", "javascript:"],
            ["ping", "169.254.169.254"],
            ["ping", "fe80::1%eth0"],
            ["tcptraceroute", "1.1.1.1/32"],
        )
        for args in cases:
            with self.subTest(args=args):
                result = self.runner.invoke(cli, args)
                self.assertEqual(result.exit_code, 2, result.output)
                self.assertIn("Error:", result.output)
                self.assertNotIn("[Errno", result.output)
                self.assertNotIn("Name or service not known", result.output)

    def test_register_default_skips_board(self):
        squares = [{"tld": "com", "status": "has-ns"}, {"tld": "accountant", "status": "no-dns"}]
        squares += [{"tld": f"xn--mgb{i}", "status": "unknown"} for i in range(20)]
        fake = {
            "ok": True,
            "kind": "register",
            "query": "example",
            "result": {
                "label": "example",
                "tlds": len(squares),
                "no_dns": 1,
                "has_ns": 1,
                "unknown": 20,
                "squares": squares,
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.cli.tools.lookup_classified", return_value=fake),
            ):
                human = self.runner.invoke(cli, ["register", "example"])
                board = self.runner.invoke(cli, ["register", "--all", "example"])
        self.assertEqual(human.exit_code, 0, human.output)
        self.assertIn("has_ns", human.stdout)
        self.assertNotIn("xn--mgb", human.stdout)
        self.assertIn("legend  green=no-dns", board.stdout)
        self.assertIn("accountant", board.stdout)
        self.assertNotIn("account ", board.stdout)

    def test_dns_help_has_docstring(self):
        listed = self.runner.invoke(cli, ["--help"])
        dns = self.runner.invoke(cli, ["dns", "--help"])
        self.assertEqual(listed.exit_code, 0, listed.output)
        self.assertIn("dns", listed.output)
        self.assertNotIn("same as GET", listed.output)
        self.assertIn("Query like dig", listed.output)
        self.assertIn("looking-glass dns @1.1.1.1 example.com A", dns.output)
        self.assertIn("Default nameserver", dns.output)
        bench = self.runner.invoke(cli, ["lookup", "bench", "--help"])
        self.assertNotIn("GET /{ip}", bench.output)
        self.assertNotIn("Hammer GET", bench.output)

    def test_config_no_key_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.config.path", return_value=tmp + "/config.json"):
                with patch(
                    "looking_glass.cli.config_cmd.load",
                    return_value={
                        "locale": "en",
                        "cache": {"ttl_days": 7, "gui": True},
                        "wall": {
                            "default": "allow",
                            "headers": {
                                "decision": True,
                                "reason": True,
                                "asn": True,
                                "org": True,
                                "prefix": True,
                                "country": True,
                                "flag_url": True,
                                "timings": True,
                                "iana": True,
                            },
                        },
                    },
                ):
                    human = self.runner.invoke(cli, ["config"])
        self.assertEqual(human.exit_code, 0, human.output)
        self.assertNotIn("{2 keys}", human.stdout)
        self.assertNotIn("{7 keys}", human.stdout)
        self.assertNotIn("{9 keys}", human.stdout)
        self.assertIn("wall.headers", human.stdout)
        self.assertIn("all true", human.stdout)

    def test_boot_check_three_lines(self):
        fake = {
            "ok": False,
            "linger": {"enabled": False, "error": "loginctl: command not found"},
            "intel": {"present": False},
            "https": {"present": False},
            "target": {"present": False},
        }
        with patch("looking_glass.cli.boot.check", return_value=fake):
            human = self.runner.invoke(cli, ["boot", "check"])
            blob = self.runner.invoke(cli, ["--json", "boot", "check"])
        self.assertIn("linger  off", human.output)
        self.assertIn("loginctl not found", human.output)
        self.assertIn("intel  no unit", human.output)
        self.assertIn("https  no unit", human.output)
        self.assertNotIn("'enabled': False", human.output)
        self.assertTrue(json.loads(blob.stdout)["linger"]["error"])

    def test_logs_stats_empty(self):
        empty = {"day": {}, "week": {}, "totals": {}, "step": 900}
        with patch("looking_glass.http.weblog.stats_payload", return_value=empty):
            human = self.runner.invoke(cli, ["logs", "stats"])
        self.assertEqual(human.exit_code, 0, human.output)
        self.assertIn("logs stats: empty (step 900s)", human.stdout)
        self.assertNotIn("window", human.stdout)

    def test_dnssec_bogus_not_green_ok(self):
        fake = {
            "ok": True,
            "kind": "dnssec",
            "query": "example.com",
            "result": {"status": "bogus", "secure": False, "broken": True, "qname": "example.com"},
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.cli.tools.lookup_classified", return_value=fake),
            ):
                human = self.runner.invoke(cli, ["dnssec", "example.com"])
        self.assertNotIn("ok true", human.stdout)
        self.assertIn("bogus", human.stdout)

    def test_status_https_stopped_no_paths(self):
        with (
            patch("looking_glass.cli.boot.units_enabled", return_value=False),
            patch("looking_glass.intel_server.app.status", return_value=_intel_report()),
            patch(
                "looking_glass.http.https_serve.status",
                return_value={
                    "ok": True,
                    "running": False,
                    "state": "stopped",
                    "fullchain": "/tmp/fullchain.pem",
                    "privkey": "/tmp/privkey.pem",
                },
            ),
        ):
            human = self.runner.invoke(cli, ["status"])
        self.assertIn("https  stopped", human.stdout)
        self.assertNotIn("/tmp/fullchain.pem", human.stdout)
        self.assertNotIn("/tmp/privkey.pem", human.stdout)

    def test_docs_wrote_prefix(self):
        with patch("looking_glass.docs.generate.write_docs", return_value="/tmp/docs.html"):
            human = self.runner.invoke(cli, ["docs", "/tmp/docs.html"])
        self.assertEqual(human.exit_code, 0, human.output)
        self.assertIn("wrote /tmp/docs.html", human.stdout)

    def test_validate_one_line_no_wrap(self):
        ipv6 = "fc03:3b85:794c:2737:c204:ec3c:ce08:3744"
        report = {
            "ok": False,
            "failed": 1,
            "warned": 0,
            "checks": [
                {
                    "status": "ok",
                    "check": f"IANA {ipv6}",
                    "detail": "unique-local [rfc4193] [rfc8190]",
                },
                {
                    "status": "ok",
                    "check": "IANA 203.0.113.206",
                    "detail": "documentation (test-net-3) [rfc5737] 203.0.113.0/24",
                },
                {
                    "status": "failed",
                    "check": "ASN origin prefixes",
                    "detail": "missing 2001:67c:22e8:0000:0000:0000:0000:0000/48",
                },
            ],
        }
        from rich.console import Console as RichConsole

        with patch("looking_glass.cli.entry._run_validate", return_value=report):
            with patch.dict(os.environ, {"COLUMNS": "80"}, clear=False):
                with patch(
                    "looking_glass.cli.render._console",
                    lambda: RichConsole(width=80, highlight=False, soft_wrap=True, emoji=True),
                ):
                    human = self.runner.invoke(cli, ["validate"])
        self.assertEqual(human.exit_code, 2, human.output)
        lines = [ln.rstrip("\n") for ln in human.stdout.splitlines() if ln.strip()]
        for ln in lines:
            self.assertLessEqual(len(ln), 80, repr(ln))
        self.assertNotIn(ipv6, human.stdout)
        self.assertIn("IANA fc03:3b85:794c:2737:", human.stdout)
        self.assertIn("…", human.stdout)
        rfc_lines = [ln for ln in lines if "rfc8190" in ln]
        self.assertTrue(rfc_lines, human.stdout)
        self.assertTrue(any("[rfc8190]" in ln for ln in rfc_lines), rfc_lines)
        ipv4_lines = [ln for ln in human.stdout.splitlines() if "IANA 203.0.113.206" in ln]
        self.assertTrue(ipv4_lines, human.stdout)
        self.assertFalse(ipv4_lines[0].startswith(" "), ipv4_lines[0])
        fail = [ln for ln in lines if "ASN origin prefixes" in ln]
        self.assertTrue(fail, human.stdout)
        self.assertIn("ASN origin prefixes  FAIL", fail[0])
        self.assertEqual(len(fail), 1)
        self.assertNotIn("ok true", human.stdout)

    def test_apex_prints_immediately(self):
        fake = {"ok": True, "kind": "apex", "query": "example.com", "result": {"mx": []}}
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.cli.tools.lookup_classified", return_value=fake),
            ):
                human = self.runner.invoke(cli, ["apex", "example.com"])
        self.assertIn("apex example.com", human.output)

