import json
import re
import tempfile
import unittest
from unittest.mock import patch

from looking_glass.auth import session
from looking_glass.config import set_value
from looking_glass.http.security import parse_controller_origins
from looking_glass.http.site import respond
from looking_glass.wall.challenge import set_cookie_header as challenge_cookie


def _hdrs(extra):
    return {name: value for name, value in extra}


def _script_src(csp: str) -> str:
    for part in csp.split(";"):
        item = part.strip()
        if item.startswith("script-src"):
            return item
    return ""


_DNS_HIT = {
    "ok": True,
    "result": {"qname": "example.com", "qtype": "A", "answers": []},
}
_RDAP_HIT = {
    "ok": True,
    "result": {"query": "1.1.1.1", "object_class": "ip network"},
}


class SecurityHeadersTests(unittest.TestCase):
    def _assert_core(self, extra, *, https=True):
        headers = _hdrs(extra)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertEqual(headers["Referrer-Policy"], "no-referrer")
        self.assertEqual(
            headers["Permissions-Policy"],
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        )
        self.assertEqual(headers["Cross-Origin-Opener-Policy"], "same-origin")
        self.assertIn(headers["Cross-Origin-Resource-Policy"], {"same-origin", "cross-origin"})
        self.assertNotIn("Cross-Origin-Embedder-Policy", headers)
        csp = headers["Content-Security-Policy"]
        self.assertIn("default-src 'none'", csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertIn("form-action 'self'", csp)
        self.assertIn("img-src 'self' data: https://flagcdn.com", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("upgrade-insecure-requests", csp)
        script = _script_src(csp)
        self.assertIn("'self'", script)
        self.assertIn("'nonce-", script)
        self.assertNotIn("'unsafe-inline'", script)
        self.assertNotIn("'unsafe-eval'", script)
        self.assertNotIn("https:", script.replace("https://flagcdn.com", ""))
        if https:
            self.assertEqual(headers["Strict-Transport-Security"], "max-age=15552000")
            self.assertNotIn("includeSubDomains", headers["Strict-Transport-Security"])
            self.assertNotIn("preload", headers["Strict-Transport-Security"])
        else:
            self.assertNotIn("Strict-Transport-Security", headers)

    def test_index_html_has_security_headers_and_nonce(self):
        status, ctype, body, extra = respond(
            "wsgi",
            "127.0.0.1",
            "/",
            {},
            accept="text/html",
            host="lg.example.com",
            scheme="https",
        )
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("text/html"))
        self._assert_core(extra, https=True)
        text = body.decode("utf-8")
        headers = _hdrs(extra)
        nonce = re.search(r"'nonce-([^']+)'", headers["Content-Security-Policy"])
        self.assertIsNotNone(nonce)
        self.assertIn(f'<script nonce="{nonce.group(1)}">', text)
        self.assertIn("window.t =", text)
        self.assertIn("/i18n/", text)
        self.assertIn("/static/gui.js", text)
        self.assertIn("<form ", text)
        self.assertIsNone(re.search(r"<form[^>]+action=\"https?://", text))

    def test_dns_html_report_has_headers_and_payload_script(self):
        with patch("looking_glass.http.site.lookup_classified", return_value=_DNS_HIT):
            status, ctype, body, extra = respond(
                "wsgi",
                "127.0.0.1",
                "/dns/example.com/A",
                {},
                accept="text/html",
                host="lg.example.com",
                scheme="https",
            )
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("text/html"))
        self._assert_core(extra, https=True)
        text = body.decode("utf-8")
        headers = _hdrs(extra)
        nonce = re.search(r"'nonce-([^']+)'", headers["Content-Security-Policy"]).group(1)
        self.assertIn(f'<script nonce="{nonce}">', text)
        self.assertIn("window.t =", text)
        self.assertIn('<script type="application/json" id="report-payload">', text)
        self.assertIn("window.paintInspect", text)

    def test_rdap_json_has_nosniff_deny_csp_hsts(self):
        with patch("looking_glass.http.site.lookup_classified", return_value=_RDAP_HIT):
            status, ctype, body, extra = respond(
                "wsgi",
                "127.0.0.1",
                "/rdap/1.1.1.1",
                {},
                accept="application/json",
                host="lg.example.com",
                scheme="https",
            )
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("application/json"))
        headers = _hdrs(extra)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("Content-Security-Policy", headers)
        self.assertEqual(headers["Strict-Transport-Security"], "max-age=15552000")
        self._assert_core(extra, https=True)

    def test_http_omits_hsts(self):
        status, _, _, extra = respond(
            "wsgi",
            "127.0.0.1",
            "/",
            {},
            accept="text/html",
            host="lg.example.com",
            scheme="http",
        )
        self.assertEqual(status, 200)
        self._assert_core(extra, https=False)

    def test_gui_assets_load(self):
        js_st, _, js, _ = respond("wsgi", "127.0.0.1", "/static/gui.js", {}, scheme="https")
        i18n_st, _, i18n, _ = respond("wsgi", "127.0.0.1", "/i18n/en.js", {}, scheme="https")
        self.assertEqual(js_st, 200)
        self.assertEqual(i18n_st, 200)
        self.assertIn(b"window.lookingGlassWindows", js)
        self.assertIn(b"window.__i18n", i18n)

    def test_xss_payload_stays_escaped(self):
        from looking_glass.http.site import _encode

        nasty = "<script>alert(1)</script>"
        _, _, body = _encode(
            200,
            {"ok": True, "kind": "dns", "query": nasty, "result": {"ok": True}},
            html=True,
            path="/dns/x",
            host="lg.example.com",
            scheme="https",
            csp_nonce_value="testnonce",
        )
        text = body.decode("utf-8")
        self.assertNotIn("<script>alert(1)</script>", text)
        self.assertIn("\\u003c", text)
        self.assertIn('id="report-payload"', text)

    def test_controller_origins_relax_cors_and_csp(self):
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.config.get_root", return_value=tmp),
                patch("looking_glass.utility.get_root", return_value=tmp),
            ):
                set_value("http.controller_origins", ["https://ctrl.example"])
                _, _, _, allowed = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/",
                    {},
                    accept="text/html",
                    scheme="https",
                    origin="https://ctrl.example",
                )
                _, _, _, other = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/",
                    {},
                    accept="text/html",
                    scheme="https",
                    origin="https://evil.example",
                )
        allow = _hdrs(allowed)
        deny = _hdrs(other)
        self.assertIn("https://ctrl.example", allow["Content-Security-Policy"])
        self.assertEqual(allow["Access-Control-Allow-Origin"], "https://ctrl.example")
        self.assertEqual(allow["Vary"], "Origin")
        self.assertEqual(allow["Cross-Origin-Resource-Policy"], "cross-origin")
        self.assertNotIn("Access-Control-Allow-Origin", deny)
        self.assertEqual(deny["Cross-Origin-Resource-Policy"], "same-origin")

    def test_controller_origin_parser_rejects_wildcards(self):
        self.assertEqual(parse_controller_origins(["https://ctrl.example/path"]), ["https://ctrl.example"])
        with self.assertRaises(ValueError):
            parse_controller_origins(["*"], strict=True)
        with self.assertRaises(ValueError):
            parse_controller_origins(["https://ok.example https://no.example"], strict=True)

    def test_cookies_are_httponly_samesite_secure(self):
        session_https = session.cookie_header("tok", scheme="https")
        session_http = session.cookie_header("tok", scheme="http")
        challenge_https = challenge_cookie("tok", 60, scheme="https")
        challenge_http = challenge_cookie("tok", 60, scheme="http")
        for hdr in (session_https, challenge_https):
            self.assertIn("HttpOnly", hdr)
            self.assertIn("SameSite=Lax", hdr)
            self.assertIn("Path=/", hdr)
            self.assertIn("Secure", hdr)
        self.assertNotIn("Secure", session_http)
        self.assertNotIn("Secure", challenge_http)

    def test_wall_challenge_html_has_csp_nonce(self):
        from looking_glass.wall import wall

        def inner(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/plain")])
            return [b"ok"]

        app = wall(inner, lists=None, challenge_ips=["198.51.100.9"])
        captured = {}

        def start_response(status, headers, exc_info=None):
            captured["headers"] = headers

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/",
            "QUERY_STRING": "",
            "CONTENT_LENGTH": "0",
            "SERVER_NAME": "test",
            "SERVER_PORT": "443",
            "wsgi.input": __import__("io").BytesIO(b""),
            "wsgi.errors": __import__("io").StringIO(),
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "https",
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
            "REMOTE_ADDR": "198.51.100.9",
            "HTTP_ACCEPT": "text/html",
        }
        body = b"".join(app(environ, start_response))
        headers = _hdrs(captured["headers"])
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        self.assertIn("max-age=15552000", headers["Strict-Transport-Security"])
        nonce = re.search(r"'nonce-([^']+)'", headers["Content-Security-Policy"])
        self.assertIsNotNone(nonce)
        text = body.decode("utf-8")
        self.assertIn(f'<script nonce="{nonce.group(1)}">', text)
        self.assertIn(f'<style nonce="{nonce.group(1)}">', text)
        self.assertIn("Checking your browser", text)
