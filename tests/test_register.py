import json
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from click.testing import CliRunner

from looking_glass.cli.entry import cli
from looking_glass.dns import register as tlds
from looking_glass.http.cli_text import wall_cli
from looking_glass.http.site import _plan
from looking_glass.i18n.messages import INVENTORY


class _NS:
    rdtype = 2


class _Msg:
    def __init__(self, ns=False):
        self.answer = [_NS()] if ns else []


class ParseTldsTests(unittest.TestCase):
    def test_skips_comments_and_arpa(self):
        text = "# Version 20240101\nCOM\nARPA\nXYZ\nXN--P1AI\n"
        rows = tlds.parse_tlds_text(text)
        self.assertEqual(rows, ["com", "xyz", "xn--p1ai"])
        self.assertNotIn("arpa", rows)

    def test_display_decodes_punycode(self):
        self.assertEqual(tlds.tld_display("com"), "com")
        self.assertEqual(tlds.tld_display("xn--p1ai"), "рф")


class ParseLabelTests(unittest.TestCase):
    def test_rejects_dotted_names(self):
        self.assertEqual(tlds.parse_label("Example"), "example")
        self.assertEqual(tlds.parse_label("münchen"), "münchen")
        self.assertEqual(tlds.parse_label("xn--mnchen-3ya"), "münchen")
        with self.assertRaises(ValueError):
            tlds.parse_label("example.com")
        with self.assertRaises(ValueError):
            tlds.parse_label("999.999.999.999")

    def test_rejects_urls(self):
        with self.assertRaises(ValueError) as caught:
            tlds.parse_label("https://google.com")
        self.assertIn("label", str(caught.exception))
        with self.assertRaises(ValueError):
            tlds.parse_label("http://google.com")
        with self.assertRaises(ValueError):
            tlds.parse_label("javascript:alert(1)")
        with self.assertRaises(ValueError):
            tlds.parse_label(tlds.parse_register_path("/register/http%3A%2F%2Fgoogle.com"))
        with self.assertRaises(ValueError):
            tlds.parse_label(tlds.parse_register_path("/register/http://google.com"))

    def test_accepts_63_char_label(self):
        label = "a" * 63
        self.assertEqual(tlds.parse_label(label), label)
        with self.assertRaises(ValueError):
            tlds.parse_label("a" * 64)

    def test_rejects_ip_and_empty(self):
        with self.assertRaises(ValueError):
            tlds.parse_label("1.1.1.1")
        with self.assertRaises(ValueError):
            tlds.parse_label("")
        with self.assertRaises(ValueError):
            tlds.parse_label("*.example")
        with self.assertRaises(ValueError):
            tlds.parse_label("not a domain")

    def test_parse_path(self):
        self.assertEqual(tlds.parse_register_path("/register/example"), "example")
        with self.assertRaises(ValueError):
            tlds.parse_register_path("/register")
        with self.assertRaises(ValueError):
            tlds.parse_register_path("/register/a/b")


class CheckRegisterTests(unittest.IsolatedAsyncioTestCase):
    async def test_rcode_to_status(self):
        async def fake_query(qname, rdtype, timeout, server, *, port=None):
            if qname.startswith("example.com"):
                return _Msg(ns=True), "NOERROR", None
            if qname.startswith("example.test"):
                return _Msg(), "NXDOMAIN", None
            if qname.startswith("example.org"):
                return _Msg(ns=False), "NOERROR", None
            return None, "ERROR", "timeout"

        with (
            patch("looking_glass.dns.register._query", side_effect=fake_query),
            patch("looking_glass.dns.register._apply_rdap", new=AsyncMock()),
        ):
            payload = await tlds.check_register_async(
                "example",
                tlds=["com", "test", "org", "xyz"],
            )
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["kind"], "register")
        self.assertEqual(payload["query"], "example")
        result = payload["result"]
        self.assertEqual(result["label"], "example")
        self.assertEqual(result["ascii"], "example")
        self.assertEqual(result["no_dns"], 1)
        self.assertEqual(result["has_ns"], 1)
        self.assertEqual(result["unknown"], 2)
        by_tld = {row["tld"]: row for row in result["squares"]}
        self.assertEqual(by_tld["com"]["status"], "has-ns")
        self.assertEqual(by_tld["com"]["reason"], "ns")
        self.assertEqual(by_tld["com"]["rcode"], "NOERROR")
        self.assertEqual(by_tld["com"]["dns"], "delegated")
        self.assertEqual(by_tld["test"]["status"], "no-dns")
        self.assertEqual(by_tld["test"]["reason"], "nxdomain")
        self.assertEqual(by_tld["test"]["rcode"], "NXDOMAIN")
        self.assertEqual(by_tld["org"]["status"], "unknown")
        self.assertEqual(by_tld["org"]["reason"], "nodata")
        self.assertEqual(by_tld["xyz"]["status"], "unknown")
        self.assertEqual(result["squares"][0]["name"], "example.com")

    async def test_wildcard_gov_never_has_ns(self):
        async def fake_query(qname, rdtype, timeout, server, *, port=None):
            return _Msg(ns=True), "NOERROR", None

        with (
            patch("looking_glass.dns.register._query", side_effect=fake_query),
            patch("looking_glass.dns.register._apply_rdap", new=AsyncMock()),
        ):
            payload = await tlds.check_register_async("hopproof", tlds=["gov", "com"])
        by_tld = {row["tld"]: row for row in payload["result"]["squares"]}
        self.assertEqual(by_tld["gov"]["status"], "unknown")
        self.assertEqual(by_tld["gov"]["reason"], "wildcard")
        self.assertEqual(by_tld["com"]["status"], "has-ns")

    async def test_rdap_registered_nxdomain(self):
        async def fake_query(qname, rdtype, timeout, server, *, port=None):
            return _Msg(), "NXDOMAIN", None

        async def fake_rdap(target, *, force=False):
            if str(target).endswith(".pw"):
                return {"ok": True, "result": {"handle": "D949924-CNIC", "status": ["inactive"]}}
            return {"ok": False, "result": None, "error": "not found"}

        with (
            patch("looking_glass.dns.register._query", side_effect=fake_query),
            patch("looking_glass.intel.rdap.lookup_rdap_async", side_effect=fake_rdap),
        ):
            payload = await tlds.check_register_async("google", tlds=["pw", "test"])
        by_tld = {row["tld"]: row for row in payload["result"]["squares"]}
        self.assertEqual(by_tld["pw"]["status"], "unknown")
        self.assertEqual(by_tld["pw"]["reason"], "rdap-registered")
        self.assertEqual(by_tld["pw"]["dns"], "nxdomain")
        self.assertEqual(by_tld["test"]["status"], "no-dns")
        self.assertEqual(by_tld["test"]["reason"], "nxdomain")

    async def test_idn_unicode_label_punycode_wire(self):
        async def fake_query(qname, rdtype, timeout, server, *, port=None):
            self.assertTrue(qname.startswith("xn--mnchen-3ya."))
            return _Msg(), "NXDOMAIN", None

        with (
            patch("looking_glass.dns.register._query", side_effect=fake_query),
            patch("looking_glass.dns.register._apply_rdap", new=AsyncMock()),
        ):
            payload = await tlds.check_register_async("münchen", tlds=["de"])
        self.assertEqual(payload["query"], "münchen")
        self.assertEqual(payload["result"]["label"], "münchen")
        self.assertEqual(payload["result"]["ascii"], "xn--mnchen-3ya")
        self.assertEqual(payload["result"]["squares"][0]["name"], "xn--mnchen-3ya.de")


class RegisterHttpCliTests(unittest.TestCase):
    def test_plan_rejects_ip(self):
        err, kind, value, _base = _plan("wsgi", "127.0.0.1", "/register/1.1.1.1", {}, "")
        self.assertIsNotNone(err)
        self.assertIsNone(kind)
        status, _ctype, body = err
        self.assertEqual(status, 400)
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "register")
        self.assertIn("label", payload["error"])

    def test_plan_rejects_dotted_names(self):
        err, kind, value, _base = _plan("wsgi", "127.0.0.1", "/register/example.com", {}, "")
        self.assertIsNotNone(err)
        self.assertIsNone(kind)
        status, _ctype, body = err
        self.assertEqual(status, 400)
        err, kind, value, base = _plan("wsgi", "127.0.0.1", "/register/google", {}, "")
        self.assertIsNone(err)
        self.assertEqual(kind, "register")
        self.assertEqual(value, "google")
        self.assertEqual(base["query"], "google")

    def test_plan_url_is_not_a_label(self):
        err, kind, value, _base = _plan("wsgi", "127.0.0.1", "/register/http://google.com", {}, "")
        self.assertIsNotNone(err)
        self.assertIsNone(kind)
        status, _ctype, body = err
        self.assertEqual(status, 400)
        payload = json.loads(body)
        self.assertIn("label", payload["error"])
        self.assertIn("http://google.com", payload.get("query") or "")
        err, kind, value, _base = _plan(
            "wsgi", "127.0.0.1", "/register/http%3A%2F%2Fgoogle.com", {}, ""
        )
        self.assertIsNotNone(err)
        self.assertIsNone(kind)
        status, _ctype, body = err
        self.assertEqual(status, 400)
        payload = json.loads(body)
        self.assertIn("label", payload["error"])
        err, kind, value, _base = _plan(
            "wsgi", "127.0.0.1", "/register/https%3A%2F%2Fgoogle.com", {}, ""
        )
        self.assertIsNotNone(err)
        status, _ctype, body = err
        self.assertEqual(status, 400)

    def test_plan_tlds_query(self):
        err, kind, value, base = _plan("wsgi", "127.0.0.1", "/register/hopproof", {}, "tlds=com,net")
        self.assertIsNone(err)
        self.assertEqual(kind, "register")
        self.assertEqual(value, "hopproof")
        self.assertEqual(base["tlds"], ["com", "net"])

    def test_plan_unknown_query_key(self):
        err, kind, value, _base = _plan("wsgi", "127.0.0.1", "/register/hopproof", {}, "foo=1")
        self.assertIsNotNone(err)
        self.assertIsNone(kind)
        status, _ctype, body = err
        self.assertEqual(status, 400)
        payload = json.loads(body)
        self.assertIn("unknown query key", payload["error"])

    def test_cli_json(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "kind": "register",
            "query": "example",
            "result": {
                "label": "example",
                "ascii": "example",
                "tlds": 1,
                "no_dns": 0,
                "has_ns": 1,
                "unknown": 0,
                "squares": [{"tld": "com", "name": "example.com", "status": "has-ns", "label": "com"}],
            },
            "error": None,
        }
        with (
            patch("looking_glass.auth.history.append", return_value=None),
            patch("looking_glass.cli.tools.lookup_classified", return_value=fake) as lookup,
        ):
            result = runner.invoke(cli, ["--json", "register", "example.com"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["kind"], "register")
        self.assertEqual(payload["result"]["has_ns"], 1)
        lookup.assert_called_once_with("register", "example.com")

    def test_cli_tlds_flag(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "kind": "register",
            "query": "hopproof",
            "result": {"label": "hopproof", "tlds": 1, "no_dns": 0, "has_ns": 1, "unknown": 0, "squares": []},
            "error": None,
        }
        with (
            patch("looking_glass.auth.history.append", return_value=None),
            patch("looking_glass.cli.tools.lookup_classified", return_value=fake) as lookup,
        ):
            result = runner.invoke(cli, ["--json", "register", "hopproof", "--tlds", "com,net"])
        self.assertEqual(result.exit_code, 0, result.output)
        lookup.assert_called_once_with("register", "hopproof", tlds=["com", "net"])

    def test_human_board_skips_square_dump(self):
        fake = {
            "ok": True,
            "kind": "register",
            "query": "example",
            "result": {
                "label": "example",
                "tlds": 2,
                "no_dns": 1,
                "has_ns": 1,
                "unknown": 0,
                "squares": [
                    {"tld": "com", "name": "example.com", "status": "has-ns", "label": "com"},
                    {"tld": "xyz", "name": "example.xyz", "status": "no-dns", "label": "xyz"},
                ],
            },
            "error": None,
        }
        runner = CliRunner()
        with (
            patch("looking_glass.auth.history.append", return_value=None),
            patch("looking_glass.cli.tools.lookup_classified", return_value=fake),
        ):
            result = runner.invoke(cli, ["register", "example"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn('"squares"', result.output)
        self.assertIn("com", result.output)
        self.assertIn("xyz", result.output)
        self.assertIn("no_dns", result.output)

    def test_howto_cli(self):
        self.assertEqual(wall_cli("/register/example"), "looking-glass register example")
        self.assertEqual(
            wall_cli("/register/hopproof?tlds=com,net"),
            "looking-glass register hopproof --tlds com,net",
        )

    def test_gui_strings_and_board_css(self):
        self.assertIn("gui.register.tab", INVENTORY)
        self.assertIn("gui.register.filter.no-dns", INVENTORY)
        self.assertNotIn("gui.register.filter.open", INVENTORY)
        css = (Path("looking_glass/http/static/gui.css")).read_text(encoding="utf-8")
        html = (Path("looking_glass/http/templates/index.html")).read_text(encoding="utf-8")
        js = (Path("looking_glass/http/static/gui.js")).read_text(encoding="utf-8")
        self.assertIn(".register-board", css)
        self.assertIn(".register-cell[hidden]", css)
        self.assertIn("form-register", html)
        self.assertIn("renderRegister", js)
        self.assertIn("register-cell", js)
        self.assertIn("encodeURIComponent(label)", js)
        self.assertIn("encodeURIComponent(raw)", js)
        self.assertNotIn("new URL(withScheme).hostname", js)
