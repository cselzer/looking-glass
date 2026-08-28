import json
import unittest
from unittest.mock import patch

from looking_glass.dns.trace import parse_dnstrace_path
from looking_glass.http.site import respond
from looking_glass.intel_server.pipeline import classify_query


def _json(path, query=""):
    status, _, body, *_ = respond(
        "wsgi",
        "127.0.0.1",
        path,
        {},
        accept="application/json",
        query_string=query,
    )
    return status, json.loads(body.decode("utf-8"))


class BogusIpv4Tests(unittest.TestCase):
    def test_numeric_lookalike_is_400(self):
        for path in (
            "/dns/999.999.999.999/A",
            "/apex/999.999.999.999",
            "/mail/999.999.999.999",
            "/reputation/999.999.999.999",
            "/ping/999.999.999.999",
            "/tls/999.999.999.999",
            "/tcp/999.999.999.999/443",
            "/pmtu/999.999.999.999",
        ):
            status, payload = _json(path)
            self.assertEqual(status, 400, path)
            self.assertFalse(payload["ok"])
            self.assertNotIn("result", payload)


class RegisterDotsTests(unittest.TestCase):
    def test_dotted_and_bogus_ip_are_400(self):
        for path in ("/register/google.com", "/register/999.999.999.999"):
            status, payload = _json(path)
            self.assertEqual(status, 400, path)
            self.assertFalse(payload["ok"])
            self.assertNotIn("result", payload)


class DnstraceParseTests(unittest.TestCase):
    def test_name_and_known_type(self):
        self.assertEqual(parse_dnstrace_path("/dnstrace/example.com"), ("example.com", "A"))
        self.assertEqual(parse_dnstrace_path("/dnstrace/example.com/AAAA"), ("example.com", "AAAA"))
        self.assertEqual(
            parse_dnstrace_path("/dnstrace/example.com%2FAAAA"),
            ("example.com", "AAAA"),
        )

    def test_scheme_and_dotdot_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_dnstrace_path("/dnstrace/https://google.com")
        with self.assertRaises(ValueError):
            parse_dnstrace_path("/dnstrace/../../etc/passwd")
        with self.assertRaises(ValueError):
            parse_dnstrace_path("/dnstrace/google.com/A/extra")

    def test_http_400(self):
        for path in (
            "/dnstrace/https://google.com",
            "/dnstrace/../../etc/passwd",
            "/dnstrace/google.com/notatype",
        ):
            status, payload = _json(path)
            self.assertEqual(status, 400, path)
            self.assertFalse(payload["ok"])
            self.assertNotIn("result", payload)


class HostNotUrlTests(unittest.TestCase):
    def test_tls_tcp_reject_schemes(self):
        for path in (
            "/tls/https://example.com",
            "/tcp/https://example.com/443",
        ):
            status, payload = _json(path)
            self.assertEqual(status, 400, path)
            self.assertFalse(payload["ok"])
            self.assertNotIn("result", payload)


class LinkLocalTests(unittest.TestCase):
    def test_probe_rejects_zone_and_link_local(self):
        for path in (
            "/ping/fe80::1",
            "/tls/fe80::1",
            "/tcp/169.254.1.1/443",
            "/pmtu/fe80::1%eth0",
            "/traceroute/fe80::1",
            "/mtr/169.254.0.1",
        ):
            status, payload = _json(path)
            self.assertEqual(status, 400, path)
            self.assertFalse(payload["ok"])
            self.assertNotIn("result", payload)

    def test_intel_zone_id_is_400(self):
        status, payload = _json("/fe80::1%eth0")
        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertNotIn("result", payload)

    def test_rdap_zone_id_is_400(self):
        status, payload = _json("/rdap/fe80::1%eth0")
        self.assertEqual(status, 400)
        self.assertFalse(payload["ok"])
        self.assertNotIn("result", payload)


class HttpSchemeTests(unittest.TestCase):
    def test_non_http_schemes_are_400(self):
        for path, query in (
            ("/http/javascript:alert(1)", ""),
            ("/http/data:text/html,x", ""),
            ("/http", "url=javascript:alert(1)"),
            ("/http", "url=file:/etc/passwd"),
        ):
            status, payload = _json(path, query)
            self.assertEqual(status, 400, (path, query))
            self.assertFalse(payload["ok"])
            self.assertNotIn("result", payload)


class MtrCyclesTests(unittest.TestCase):
    def test_bad_cycles_are_400(self):
        for query in ("cycles=99999", "cycles=0", "cycles=-1", "cycles=abc"):
            with patch("looking_glass.http.site.run_probe") as run:
                status, payload = _json("/mtr/1.1.1.1", query)
            run.assert_not_called()
            self.assertEqual(status, 400, query)
            self.assertFalse(payload["ok"])
            self.assertNotIn("result", payload)

    def test_omitted_cycles_still_runs(self):
        fake = {"ok": True, "result": {"target": "1.1.1.1", "cycles": 10}, "error": None}
        with patch("looking_glass.http.site.run_probe", return_value=fake) as run:
            status, payload = _json("/mtr/1.1.1.1")
        self.assertEqual(status, 200)
        self.assertTrue(payload["ok"])
        self.assertIsNone(run.call_args.kwargs.get("cycles"))


class RdapAsnTests(unittest.TestCase):
    def test_overflow_is_400(self):
        for path in ("/rdap/AS99999999999", "/rdap/4294967296", "/AS99999999999", "/4294967296"):
            status, payload = _json(path)
            self.assertEqual(status, 400, path)
            self.assertFalse(payload["ok"])
            self.assertNotIn("result", payload)

    def test_classify_overflow(self):
        with self.assertRaises(ValueError):
            classify_query("AS99999999999")
        with self.assertRaises(ValueError):
            classify_query("4294967296")
        self.assertEqual(classify_query("AS13335"), ("asn", "13335"))
        self.assertEqual(classify_query("13335"), ("asn", "13335"))
