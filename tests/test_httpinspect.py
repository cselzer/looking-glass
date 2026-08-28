import asyncio
import json
import ssl
import unittest
from http.client import BadStatusLine
from unittest.mock import patch

from looking_glass.http.cli_text import wall_cli
from looking_glass.http.site import _finish, _kind_plan, _plan, path_token
from looking_glass.net.httpinspect import (
    _split_target,
    http_envelope_query,
    inspect_http,
    inspect_http_async,
    parse_http_path,
)


class ParseHttpPathTests(unittest.TestCase):
    def test_encoded_slashes_unquote_to_url(self):
        self.assertEqual(
            parse_http_path("/http/https%3A%2F%2Fexample.com"),
            "https://example.com",
        )
        err, kind, value, base = _kind_plan(
            "wsgi",
            "1.1.1.1",
            "http/https%3A%2F%2Fexample.com",
            "http",
            parse_http_path,
            "",
        )
        self.assertIsNone(err)
        self.assertEqual(value, "https://example.com")
        self.assertEqual(base["query"], "https://example.com")

    def test_empty_path_is_ok(self):
        self.assertEqual(parse_http_path("/http"), "")
        self.assertEqual(parse_http_path("/http/"), "")

    def test_empty_without_url_is_400(self):
        err, kind, value, base = _kind_plan(
            "wsgi",
            "1.1.1.1",
            "http",
            "http",
            parse_http_path,
            "",
        )
        self.assertIsNotNone(err)
        self.assertIsNone(kind)
        status, _ctype, body = err
        self.assertEqual(status, 400)

    def test_url_query_without_path(self):
        err, kind, value, base = _kind_plan(
            "wsgi",
            "1.1.1.1",
            "http",
            "http",
            parse_http_path,
            "url=https://example.com",
        )
        self.assertIsNone(err)
        self.assertEqual(value, "https://example.com")
        self.assertEqual(base["query"], "https://example.com")


class SplitTargetTests(unittest.TestCase):
    def test_bare_host(self):
        self.assertEqual(_split_target("example.com"), ("https", "example.com", 443, "/"))

    def test_https_url(self):
        self.assertEqual(
            _split_target("https://example.com"),
            ("https", "example.com", 443, "/"),
        )
        self.assertEqual(
            _split_target("https://example.com/foo?bar=1"),
            ("https", "example.com", 443, "/foo?bar=1"),
        )
        self.assertEqual(
            _split_target("example.com/foo?bar=1"),
            ("https", "example.com", 443, "/foo?bar=1"),
        )

    def test_http_url_keeps_scheme(self):
        self.assertEqual(_split_target("http://example.com"), ("http", "example.com", 80, "/"))

    def test_bare_port_80_is_http(self):
        self.assertEqual(_split_target("example.com:80"), ("http", "example.com", 80, "/"))

    def test_unbracketed_ipv6(self):
        self.assertEqual(
            _split_target("2606:4700:4700::1111"),
            ("https", "2606:4700:4700::1111", 443, "/"),
        )
        self.assertEqual(
            _split_target("[2606:4700:4700::1111]"),
            ("https", "2606:4700:4700::1111", 443, "/"),
        )

    def test_collapsed_slashes_do_not_lookup_https(self):
        self.assertEqual(
            _split_target("https:/example.com"),
            ("https", "example.com", 443, "/"),
        )
        self.assertEqual(
            _split_target("https://https:/example.com"),
            ("https", "example.com", 443, "/"),
        )

    def test_bare_scheme_is_not_a_hostname(self):
        with self.assertRaises(ValueError):
            _split_target("https:")
        with self.assertRaises(ValueError):
            _split_target("http:")


class HttpKindPlanTests(unittest.TestCase):
    def test_scheme_query_keeps_http(self):
        err, kind, value, base = _kind_plan(
            "wsgi",
            "1.1.1.1",
            "http/example.com",
            "http",
            parse_http_path,
            "scheme=http",
        )
        self.assertIsNone(err)
        self.assertEqual(kind, "http")
        self.assertEqual(value, "http://example.com")
        self.assertEqual(base["query"], "http://example.com")

    def test_collapsed_https_path_restores_slashes(self):
        err, kind, value, base = _kind_plan(
            "wsgi",
            "1.1.1.1",
            "http/https:/example.com",
            "http",
            parse_http_path,
            "",
        )
        self.assertIsNone(err)
        self.assertEqual(value, "https://example.com")
        self.assertEqual(base["query"], "https://example.com")

    def test_url_query_is_canonical(self):
        err, kind, value, base = _kind_plan(
            "wsgi",
            "1.1.1.1",
            "http/https:/example.com",
            "http",
            parse_http_path,
            "url=https://example.com",
        )
        self.assertIsNone(err)
        self.assertEqual(value, "https://example.com")
        self.assertEqual(base["query"], "https://example.com")

    def test_host_only_stays_bare(self):
        err, kind, value, base = _kind_plan(
            "wsgi",
            "1.1.1.1",
            "http/example.com",
            "http",
            parse_http_path,
            "",
        )
        self.assertIsNone(err)
        self.assertEqual(value, "example.com")
        self.assertEqual(base["query"], "example.com")

    def test_http_envelope_query_helper(self):
        self.assertEqual(http_envelope_query("https:/example.com"), "https://example.com")
        self.assertEqual(http_envelope_query("example.com"), "example.com")
        self.assertEqual(
            http_envelope_query("example.com", "url=https://example.com"),
            "https://example.com",
        )
        self.assertEqual(
            http_envelope_query("", "url=https://example.com"),
            "https://example.com",
        )
        with self.assertRaises(ValueError):
            http_envelope_query("", "")
        with self.assertRaises(ValueError):
            http_envelope_query("ftp:/example.com")
        with self.assertRaises(ValueError):
            http_envelope_query("ftp://example.com")


class HttpFtpSchemeTests(unittest.TestCase):
    def test_collapsed_ftp_path_is_400(self):
        self.assertEqual(path_token("/http/ftp:/example.com"), "http/ftp://example.com")
        err, kind, value, base = _kind_plan(
            "wsgi",
            "1.1.1.1",
            "http/ftp:/example.com",
            "http",
            parse_http_path,
            "",
        )
        self.assertIsNotNone(err)
        status, _ctype, body = err[:3]
        self.assertEqual(status, 400)
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(payload["query"], "ftp://example.com")
        self.assertIn("http or https", payload["error"])
        self.assertIsNone(kind)
        self.assertIsNone(value)

    def test_url_param_ftp_echoes_submitted_url(self):
        err, kind, value, base = _plan(
            "wsgi", "1.1.1.1", "/http/", {}, "url=ftp://example.com"
        )
        self.assertIsNotNone(err)
        status, _ctype, body = err[:3]
        self.assertEqual(status, 400)
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(payload["query"], "ftp://example.com")
        self.assertNotEqual(payload["query"], "http")
        self.assertIn("http or https", payload["error"])

    def test_encoded_ftp_path_query_is_decoded(self):
        err, kind, value, base = _plan(
            "wsgi", "1.1.1.1", "/http/ftp%3A%2F%2Fexample.com", {}, ""
        )
        self.assertIsNotNone(err)
        status, _ctype, body = err[:3]
        self.assertEqual(status, 400)
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(payload["query"], "ftp://example.com")
        self.assertNotIn("%2F", payload["query"])


class HttpCliTests(unittest.TestCase):
    def test_path_and_scheme(self):
        self.assertEqual(wall_cli("/http/example.com/path"), "looking-glass http example.com/path")
        self.assertEqual(wall_cli("/http/example.com?scheme=http"), "looking-glass http http://example.com")
        self.assertEqual(
            wall_cli("/http/https://example.com"),
            "looking-glass http https://example.com",
        )
        self.assertEqual(
            wall_cli("/http?url=https%3A%2F%2Fexample.com"),
            "looking-glass http https://example.com",
        )


class InspectHttpAsyncTests(unittest.TestCase):
    def test_forwards_max_redirects(self):
        async def run():
            with patch(
                "looking_glass.net.httpinspect.inspect_http",
                return_value={"ok": True, "result": None, "error": None},
            ) as sync:
                await inspect_http_async("example.com", 4.0, 3)
            sync.assert_called_once_with("example.com", 4.0, 3)

        asyncio.run(run())


_SETTINGS = b"\x00\x00\x12\x04\x00\x00\x00\x00\x00"


class _FakeHttpConn:
    sock = None

    def connect(self):
        return None

    def close(self):
        return None


class InspectHttpErrorTests(unittest.TestCase):
    def test_bad_status_line_is_printable(self):
        with (
            patch("looking_glass.net.httpinspect.HTTPSConnection", return_value=_FakeHttpConn()),
            patch(
                "looking_glass.net.httpinspect._read_response",
                side_effect=BadStatusLine(_SETTINGS),
            ),
        ):
            out = inspect_http("example.com")
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "http2_handshake_failed")
        self.assertNotIn("\x00", out["error"])
        json.dumps(out)

    def test_alpn_offers_http11_only(self):
        captured = {}
        real_create = ssl.create_default_context

        def fake_create(*args, **kwargs):
            ctx = real_create(*args, **kwargs)
            orig = ctx.set_alpn_protocols

            def capture(protos):
                captured["alpn"] = list(protos)
                return orig(protos)

            ctx.set_alpn_protocols = capture
            return ctx

        with (
            patch("looking_glass.net.httpinspect.ssl.create_default_context", side_effect=fake_create),
            patch("looking_glass.net.httpinspect.HTTPSConnection", return_value=_FakeHttpConn()),
            patch("looking_glass.net.httpinspect._read_response", side_effect=OSError("stop")),
        ):
            inspect_http("example.com")
        self.assertEqual(captured.get("alpn"), ["http/1.1"])


class FinishHttpTests(unittest.TestCase):
    def test_http_protocol_mismatch_is_200(self):
        status, body = _finish(
            {"ok": False, "result": None, "error": "http2_handshake_failed"},
            "http",
            "example.com",
            {"protocol": "wsgi", "visitor": "1.1.1.1"},
        )
        self.assertEqual(status, 200)
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "http2_handshake_failed")
        encoded = json.dumps(body)
        self.assertNotIn("\x00", encoded)

    def test_http_timeout_is_200(self):
        status, body = _finish(
            {"ok": False, "result": None, "error": "timeout"},
            "http",
            "example.com",
            {"protocol": "wsgi", "visitor": "1.1.1.1"},
        )
        self.assertEqual(status, 200)
        self.assertFalse(body["ok"])

    def test_tcp_timeout_is_200(self):
        status, body = _finish(
            {"ok": False, "result": None, "error": "timed out"},
            "tcp",
            "1.1.1.1",
            {"protocol": "wsgi", "visitor": "1.1.1.1"},
        )
        self.assertEqual(status, 200)
        self.assertFalse(body["ok"])
