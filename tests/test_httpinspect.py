import asyncio
import json
import socket
import ssl
import unittest
from http.client import BadStatusLine
from unittest.mock import Mock, patch

from looking_glass.http.cli_text import wall_cli
from looking_glass.http.site import _finish, _kind_plan, _plan, path_token
from looking_glass.net.httpinspect import (
    _dial,
    _probe_error,
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

    def test_path_in_tail_stays_on_example(self):
        err, kind, value, base = _kind_plan(
            "wsgi",
            "1.1.1.1",
            "http/example.com/foo/bar",
            "http",
            parse_http_path,
            "",
        )
        self.assertIsNone(err)
        self.assertEqual(kind, "http")
        self.assertEqual(value, "example.com/foo/bar")
        self.assertEqual(base["query"], "example.com/foo/bar")
        self.assertEqual(
            _split_target("example.com/foo/bar"),
            ("https", "example.com", 443, "/foo/bar"),
        )
        self.assertEqual(http_envelope_query("example.com/foo/bar"), "example.com/foo/bar")

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
        with self.assertRaises(ValueError):
            http_envelope_query("javascript:alert(1)")
        with self.assertRaises(ValueError):
            http_envelope_query("data:text/html,x")
        with self.assertRaises(ValueError):
            http_envelope_query("", "url=javascript:alert(1)")


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


_PUBLIC_SOCKADDR = ("93.184.216.34", 2, ("93.184.216.34", 443))


class InspectHttpErrorTests(unittest.TestCase):
    def test_bad_status_line_is_printable(self):
        with (
            patch(
                "looking_glass.net.httpinspect._resolve_http_hop",
                return_value=_PUBLIC_SOCKADDR,
            ),
            patch(
                "looking_glass.net.httpinspect._dial",
                return_value=(_FakeHttpConn(), None),
            ),
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
            ctx.wrap_socket = lambda sock, **kw: sock
            return ctx

        with (
            patch("looking_glass.net.httpinspect.ssl.create_default_context", side_effect=fake_create),
            patch(
                "looking_glass.net.httpinspect.resolve_probe_host",
                return_value=_PUBLIC_SOCKADDR,
            ),
            patch("looking_glass.net.httpinspect.socket.socket", return_value=Mock()),
            patch("looking_glass.net.httpinspect._read_response", side_effect=OSError("stop")),
        ):
            inspect_http("example.com")
        self.assertEqual(captured.get("alpn"), ["http/1.1"])


class ProbeErrorTests(unittest.TestCase):
    def test_unpack_is_inspect_failed(self):
        self.assertEqual(
            _probe_error(ValueError("too many values to unpack (expected 2)")),
            "inspect failed",
        )
        self.assertEqual(_probe_error(TypeError("expected 2")), "inspect failed")

    def test_timeout_h2_oserror_unchanged(self):
        self.assertEqual(_probe_error(TimeoutError()), "timeout")
        self.assertEqual(_probe_error(BadStatusLine(_SETTINGS)), "http2_handshake_failed")
        self.assertEqual(_probe_error(OSError("connection refused")), "connection refused")


class _FakeSock:
    def __init__(self, connected):
        self._connected = connected

    def settimeout(self, _timeout):
        return None

    def connect(self, addr):
        self._connected.append(addr)

    def close(self):
        return None


_IPV6_SA = ("2606:4700:4700::1111", 443, 0, 0)
_HOP_OK = {
    "status": 200,
    "reason": "OK",
    "http_version": "HTTP/1.1",
    "headers": {},
    "location": None,
    "ttfb_ms": 1.0,
    "elapsed_ms": 1.0,
    "hsts": None,
    "body_len": 0,
}
_HOP_301 = {
    "status": 301,
    "reason": "Moved Permanently",
    "http_version": "HTTP/1.1",
    "headers": {"Location": "https://one.one.one.one/"},
    "location": "https://one.one.one.one/",
    "ttfb_ms": 1.0,
    "elapsed_ms": 1.0,
    "hsts": None,
    "body_len": 0,
}


class InspectHttpDialTests(unittest.TestCase):
    def test_dial_connects_ipv6_4tuple(self):
        connected = []
        with (
            patch(
                "looking_glass.net.httpinspect.socket.socket",
                return_value=_FakeSock(connected),
            ),
            patch("looking_glass.net.httpinspect.socket.create_connection") as create,
        ):
            _dial("http", "example.com", 80, socket.AF_INET6, _IPV6_SA, 8.0)
        create.assert_not_called()
        self.assertEqual(connected, [_IPV6_SA])

    def test_inspect_aaaa_does_not_unpack(self):
        connected = []

        def fake_dial(scheme, host, port, family, sockaddr, timeout):
            self.assertEqual(family, socket.AF_INET6)
            connected.append(sockaddr)
            return _FakeHttpConn(), None

        with (
            patch(
                "looking_glass.net.httpinspect.resolve_probe_host",
                return_value=("2606:4700:4700::1111", socket.AF_INET6, _IPV6_SA),
            ),
            patch("looking_glass.net.httpinspect._dial", side_effect=fake_dial),
            patch("looking_glass.net.httpinspect.socket.create_connection") as create,
            patch("looking_glass.net.httpinspect._read_response", return_value=dict(_HOP_OK)),
        ):
            out = inspect_http("https://example.com/")
        create.assert_not_called()
        self.assertEqual(connected, [_IPV6_SA])
        self.assertTrue(out["ok"])
        self.assertIsNone(out["error"])
        self.assertNotIn("unpack", json.dumps(out))
        self.assertIn("chain", out["result"])

    def test_ipv4_redirect_then_aaaa(self):
        connected = []
        resolves = [
            ("1.1.1.1", socket.AF_INET, ("1.1.1.1", 80)),
            ("2606:4700:4700::1111", socket.AF_INET6, _IPV6_SA),
        ]
        reads = [dict(_HOP_301), dict(_HOP_OK)]

        def fake_dial(scheme, host, port, family, sockaddr, timeout):
            connected.append(sockaddr)
            return _FakeHttpConn(), None

        with (
            patch(
                "looking_glass.net.httpinspect._resolve_http_hop",
                side_effect=lambda host, port: resolves.pop(0),
            ),
            patch("looking_glass.net.httpinspect._dial", side_effect=fake_dial),
            patch("looking_glass.net.httpinspect.socket.create_connection") as create,
            patch(
                "looking_glass.net.httpinspect._read_response",
                side_effect=lambda *a, **k: reads.pop(0),
            ),
        ):
            out = inspect_http("http://1.1.1.1/")
        create.assert_not_called()
        self.assertEqual(connected[0], ("1.1.1.1", 80))
        self.assertEqual(connected[1], _IPV6_SA)
        self.assertTrue(out["ok"])
        self.assertIsNone(out["error"])
        self.assertEqual(len(out["result"]["chain"]), 2)
        self.assertNotIn("unpack", json.dumps(out))


class InspectHttpDestPolicyTests(unittest.TestCase):
    def test_literal_link_local_is_denied(self):
        with self.assertRaises(ValueError) as ctx:
            _split_target("http://169.254.169.254/")
        self.assertEqual(str(ctx.exception), "link-local is not a probe target")
        out = inspect_http("http://169.254.169.254/")
        self.assertFalse(out["ok"])
        self.assertIsNone(out["result"])
        self.assertEqual(out["error"], "link-local is not a probe target")

    def test_literal_fe80_is_denied(self):
        with self.assertRaises(ValueError) as ctx:
            _split_target("http://[fe80::1]/")
        self.assertEqual(str(ctx.exception), "link-local is not a probe target")
        out = inspect_http("http://[fe80::1]/")
        self.assertFalse(out["ok"])
        self.assertIsNone(out["result"])
        self.assertEqual(out["error"], "link-local is not a probe target")

    def test_resolved_link_local_is_denied(self):
        with (
            patch(
                "looking_glass.net.httpinspect.resolve_probe_host",
                return_value=("169.254.169.254", 2, ("169.254.169.254", 80)),
            ),
            patch("looking_glass.net.httpinspect.socket.create_connection") as conn,
        ):
            out = inspect_http("http://metadata.google.internal/")
        conn.assert_not_called()
        self.assertFalse(out["ok"])
        self.assertIsNone(out["result"])
        self.assertEqual(out["error"], "link-local is not a probe target")

    def _redirect_hop(self, location: str, status: int = 302) -> dict:
        return {
            "status": status,
            "reason": "Found",
            "http_version": "HTTP/1.1",
            "headers": {"Location": location},
            "location": location,
            "ttfb_ms": 1.0,
            "elapsed_ms": 1.0,
            "hsts": None,
            "body_len": 0,
        }

    def test_redirect_to_link_local_is_not_fetched(self):
        hop = {
            "status": 302,
            "reason": "Found",
            "http_version": "HTTP/1.1",
            "headers": {"Location": "http://169.254.169.254/"},
            "location": "http://169.254.169.254/",
            "ttfb_ms": 1.0,
            "elapsed_ms": 1.0,
            "hsts": None,
            "body_len": 0,
        }
        dials = []

        def fake_dial(scheme, host, port, *rest):
            dials.append(host)
            return _FakeHttpConn(), None

        for status in (301, 302):
            hop["status"] = status
            dials.clear()
            with (
                patch(
                    "looking_glass.net.httpinspect._resolve_http_hop",
                    return_value=("93.184.216.34", 2, ("93.184.216.34", 80)),
                ),
                patch("looking_glass.net.httpinspect._dial", side_effect=fake_dial),
                patch("looking_glass.net.httpinspect._read_response", return_value=dict(hop)),
            ):
                out = inspect_http("http://example.com/")
            self.assertEqual(dials, ["example.com"], status)
            self.assertFalse(out["ok"])
            self.assertIsNone(out["result"])
            self.assertEqual(out["error"], "link-local is not a probe target")

    def test_redirect_to_fe80_is_not_fetched(self):
        dials = []

        def fake_dial(scheme, host, port, *rest):
            dials.append(host)
            return _FakeHttpConn(), None

        def fake_resolve(name, *, port=None, socktype=None):
            self.assertNotIn("fe80", str(name).lower())
            return ("93.184.216.34", 2, ("93.184.216.34", 80))

        with (
            patch(
                "looking_glass.net.httpinspect.resolve_probe_host",
                side_effect=fake_resolve,
            ),
            patch("looking_glass.net.httpinspect._dial", side_effect=fake_dial),
            patch(
                "looking_glass.net.httpinspect._read_response",
                return_value=self._redirect_hop("http://[fe80::1]/"),
            ),
        ):
            out = inspect_http("http://example.com/")
        self.assertEqual(dials, ["example.com"])
        self.assertFalse(out["ok"])
        self.assertIsNone(out["result"])
        self.assertEqual(out["error"], "link-local is not a probe target")

    def test_redirect_hostname_a_record_link_local_is_not_fetched(self):
        dials = []
        resolves = []

        def fake_resolve(name, *, port=None, socktype=None):
            resolves.append(name)
            if name == "linklocal.example":
                return ("169.254.169.254", 2, ("169.254.169.254", 80))
            return ("93.184.216.34", 2, ("93.184.216.34", 80))

        def fake_dial(scheme, host, port, *rest):
            dials.append(host)
            self.assertNotEqual(host, "linklocal.example")
            self.assertNotEqual(host, "169.254.169.254")
            return _FakeHttpConn(), None

        with (
            patch(
                "looking_glass.net.httpinspect.resolve_probe_host",
                side_effect=fake_resolve,
            ),
            patch("looking_glass.net.httpinspect._dial", side_effect=fake_dial),
            patch(
                "looking_glass.net.httpinspect._read_response",
                return_value=self._redirect_hop("http://linklocal.example/"),
            ),
        ):
            out = inspect_http("http://example.com/")
        self.assertEqual(dials, ["example.com"])
        self.assertIn("linklocal.example", resolves)
        self.assertFalse(out["ok"])
        self.assertIsNone(out["result"])
        self.assertEqual(out["error"], "link-local is not a probe target")

    def test_loopback_and_rfc1918_hosts_are_allowed(self):
        self.assertEqual(_split_target("http://127.0.0.1/")[1], "127.0.0.1")
        self.assertEqual(_split_target("http://10.0.0.1/")[1], "10.0.0.1")

    def test_path_in_tail_finish_is_200(self):
        status, body = _finish(
            {
                "ok": True,
                "result": {"status": 200, "chain": [], "query": "example.com/foo/bar"},
                "error": None,
            },
            "http",
            "example.com/foo/bar",
            {"protocol": "wsgi", "visitor": "1.1.1.1"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertEqual(body["query"], "example.com/foo/bar")
        self.assertNotEqual(body.get("error"), "link-local is not a probe target")


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

    def test_link_local_is_400(self):
        status, body = _finish(
            {"ok": False, "result": None, "error": "link-local is not a probe target"},
            "http",
            "http://metadata.google.internal/",
            {"protocol": "wsgi", "visitor": "1.1.1.1"},
        )
        self.assertEqual(status, 400)
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "link-local is not a probe target")
        self.assertNotIn("result", body)
