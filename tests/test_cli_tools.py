import json
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass.cli.entry import cli
from looking_glass.cli.tools import parse_dig_args


class DigArgsTests(unittest.TestCase):
    def test_name_and_type(self):
        self.assertEqual(parse_dig_args(("example.com",)), (None, "example.com", None))
        self.assertEqual(parse_dig_args(("example.com", "DS")), (None, "example.com", "DS"))
        self.assertEqual(
            parse_dig_args(("@1.1.1.1", "example.com", "MX")),
            ("1.1.1.1", "example.com", "MX"),
        )
        self.assertEqual(
            parse_dig_args(("example.com", "A", "@8.8.8.8:5353")),
            ("8.8.8.8:5353", "example.com", "A"),
        )

    def test_rejects_empty_and_double_server(self):
        with self.assertRaises(Exception):
            parse_dig_args(())
        with self.assertRaises(Exception):
            parse_dig_args(("@1.1.1.1", "@8.8.8.8", "example.com"))


class ToolCliTests(unittest.TestCase):
    def setUp(self):
        hist = patch("looking_glass.auth.history.append", return_value=None)
        hist.start()
        self.addCleanup(hist.stop)

    def test_dns_cli_dig_style(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "name": "example.com.",
            "qtype": "DS",
            "result": {
                "status": "NOERROR",
                "qtype": "DS",
                "answers": [{"type": "DS", "data": "370 13 2 ab"}],
            },
            "error": None,
        }
        with patch("looking_glass.cli.tools.lookup_classified", return_value=fake) as lookup:
            result = runner.invoke(cli, ["--json", "dns", "@1.1.1.1:5353", "example.com", "DS"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["qtype"], "DS")
        self.assertTrue(payload["result"]["answers"])
        lookup.assert_called_once_with(
            "dns",
            "example.com",
            qtype="DS",
            server="1.1.1.1",
            ns_port=5353,
            timeout=5.0,
        )

    def test_dns_cli_port_flag(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "name": "example.com.",
            "qtype": "A",
            "result": {"status": "NOERROR", "answers": []},
            "error": None,
        }
        with patch("looking_glass.cli.tools.lookup_classified", return_value=fake) as lookup:
            result = runner.invoke(
                cli, ["dns", "example.com", "--server", "8.8.8.8", "-p", "5353"]
            )
        self.assertEqual(result.exit_code, 0, result.output)
        kwargs = lookup.call_args.kwargs
        self.assertEqual(lookup.call_args.args[0], "dns")
        self.assertEqual(kwargs.get("server"), "8.8.8.8")
        self.assertEqual(kwargs.get("ns_port"), 5353)
        self.assertEqual(kwargs.get("timeout"), 5.0)

    def test_dns_cli_default_uses_system_resolver(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "name": "example.com.",
            "qtype": "A",
            "result": {"status": "NOERROR", "answers": []},
            "error": None,
        }
        with patch("looking_glass.cli.tools.lookup_classified", return_value=fake) as lookup:
            result = runner.invoke(cli, ["dns", "example.com"])
        self.assertEqual(result.exit_code, 0, result.output)
        kwargs = lookup.call_args.kwargs
        self.assertEqual(lookup.call_args.args[0], "dns")
        self.assertIsNone(kwargs.get("server"))
        self.assertIsNone(kwargs.get("ns_port"))
        self.assertEqual(kwargs.get("timeout"), 5.0)

    def test_ip_cli_classifies_country(self):
        runner = CliRunner()
        fake = {"ok": True, "country": "AU", "result": {"country": "AU"}, "error": None}
        with patch("looking_glass.cli.tools.lookup_classified", return_value=fake) as classified:
            result = runner.invoke(cli, ["ip", "AU"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(classified.call_args.args[0], "country")
        self.assertEqual(classified.call_args.args[1], "AU")

    def test_mtr_cli_cycles(self):
        runner = CliRunner()
        fake = {"ok": True, "result": {"cycles": 3, "hops": []}, "error": None}
        with patch("looking_glass.cli.tools.lookup_classified", return_value=fake) as lookup:
            result = runner.invoke(cli, ["mtr", "1.1.1.1", "-c", "3"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(lookup.call_args.args[0], "mtr")
        self.assertEqual(lookup.call_args.args[1], "1.1.1.1")
        self.assertEqual(lookup.call_args.kwargs.get("cycles"), 3)

    def test_gui_tools_have_cli_commands(self):
        runner = CliRunner()
        fake = {"ok": True, "result": {"host": "example.com"}, "error": None}
        mapping = {
            "ip": (["ip", "1.1.1.1"], "ip", "1.1.1.1"),
            "asn": (["asn", "AS13335"], "asn", "13335"),
            "dnssec": (["dnssec", "example.com"], "dnssec", "example.com"),
            "tls": (["tls", "example.com", "-p", "8443"], "tls", "example.com"),
            "apex": (["apex", "example.com"], "apex", "example.com"),
            "register": (["register", "example"], "register", "example"),
            "ping": (["ping", "1.1.1.1"], "ping", "1.1.1.1"),
            "traceroute": (["traceroute", "1.1.1.1"], "traceroute", "1.1.1.1"),
            "mtr": (["mtr", "1.1.1.1"], "mtr", "1.1.1.1"),
            "tcptraceroute": (["tcptraceroute", "1.1.1.1", "-p", "443"], "tcptraceroute", "1.1.1.1"),
            "rdap": (["rdap", "1.1.1.1"], "rdap", "1.1.1.1"),
            "whois": (["whois", "example.com", "--legacy"], "whois", "example.com"),
            "reputation": (["reputation", "example.com"], "reputation", "example.com"),
            "bgp": (["bgp", "1.1.1.1"], "bgp", "1.1.1.1"),
            "dnstrace": (["dnstrace", "example.com"], "dnstrace", "example.com"),
            "http": (["http", "example.com"], "http", "example.com"),
            "ptr": (["ptr", "1.1.1.1"], "ptr", "1.1.1.1"),
            "mail": (["mail", "example.com"], "mail", "example.com"),
            "tcp": (["tcp", "example.com", "-p", "25"], "tcp", "example.com"),
            "pmtu": (["pmtu", "1.1.1.1"], "pmtu", "1.1.1.1"),
        }
        with patch("looking_glass.cli.tools.lookup_classified", return_value=fake) as classified:
            for argv, kind, value in mapping.values():
                result = runner.invoke(cli, argv)
                self.assertEqual(result.exit_code, 0, result.output)
                self.assertEqual(classified.call_args.args[0], kind)
                self.assertEqual(classified.call_args.args[1], value)
        help_result = runner.invoke(cli, ["--help"])
        self.assertEqual(help_result.exit_code, 0)
        for name in mapping:
            self.assertIn(name, help_result.output)
        self.assertIn("lookup-server", help_result.output)
        self.assertIn("https", help_result.output)
        self.assertIn("restart", help_result.output)
        self.assertIn("boot", help_result.output)
        self.assertRegex(help_result.output, r"(?m)^\s+status\s+")
        self.assertNotIn("looking-glass serve start", help_result.output)
        self.assertNotIn("erso-wall", help_result.output)
        group = runner.invoke(cli, ["lookup-server", "--help"])
        self.assertEqual(group.exit_code, 0, group.output)
        self.assertIn("start", group.output)
        self.assertNotIn("looking-glass serve start", group.output)
        self.assertNotIn("erso-wall", group.output)
        https_group = runner.invoke(cli, ["https", "--help"])
        self.assertEqual(https_group.exit_code, 0, https_group.output)
        self.assertIn("start", https_group.output)
        self.assertIn("status", https_group.output)
        self.assertIn("logs", https_group.output)
        self.assertIn("renew", https_group.output)
