import asyncio
import gzip
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import brotli
from click.testing import CliRunner

from looking_glass.cli.entry import cli
from looking_glass.config import known_keys, load, set_value
from looking_glass.http.compress import (
    CompressSettings,
    apply_response,
    choose_codec,
    compress,
    decode_request_body,
    encode_body,
    merge_vary,
    parse_accept_encoding,
)
from looking_glass.wall import wall
from looking_glass.wall.lists import default_lists_path


def _pad_json() -> bytes:
    return json.dumps({"ok": True, "pad": "x" * 2000}).encode("utf-8")


def _json_app(environ, start_response):
    body = _pad_json()
    start_response(
        "200 OK",
        [
            ("Content-Type", "application/json"),
            ("Content-Length", str(len(body))),
        ],
    )
    return [body]


async def _json_asgi(scope, receive, send):
    if scope["type"] != "http":
        return
    await receive()
    body = _pad_json()
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _echo_app(environ, start_response):
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except (TypeError, ValueError):
        length = 0
    raw = environ["wsgi.input"].read(length) if length > 0 else b""
    start_response(
        "200 OK",
        [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(raw)))],
    )
    return [raw]


def _hdr(headers, name):
    want = name.lower()
    if isinstance(headers, dict):
        items = headers.items()
    else:
        items = headers
    for key, value in items:
        if str(key).lower() == want:
            return value
    return None


def _wsgi(
    app,
    *,
    path="/",
    method="GET",
    accept_encoding=None,
    content_encoding=None,
    body=b"",
    extra_environ=None,
):
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers

    raw = body if isinstance(body, (bytes, bytearray)) else str(body or "").encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_LENGTH": str(len(raw)),
        "SERVER_NAME": "test",
        "SERVER_PORT": "80",
        "wsgi.input": io.BytesIO(raw),
        "wsgi.errors": io.StringIO(),
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": "http",
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "REMOTE_ADDR": "127.0.0.1",
    }
    if accept_encoding is not None:
        environ["HTTP_ACCEPT_ENCODING"] = accept_encoding
    if content_encoding is not None:
        environ["HTTP_CONTENT_ENCODING"] = content_encoding
    if extra_environ:
        environ.update(extra_environ)
    out = b"".join(app(environ, start_response))
    headers = list(captured.get("headers") or [])
    status = int(str(captured["status"]).split()[0])
    return status, headers, out


def _asgi(
    app,
    *,
    path="/",
    method="GET",
    accept_encoding=None,
    content_encoding=None,
    body=b"",
):
    headers = []
    if accept_encoding is not None:
        headers.append((b"accept-encoding", accept_encoding.encode("latin-1")))
    if content_encoding is not None:
        headers.append((b"content-encoding", content_encoding.encode("latin-1")))
    raw = body if isinstance(body, (bytes, bytearray)) else str(body or "").encode("utf-8")
    if raw:
        headers.append((b"content-length", str(len(raw)).encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
        "scheme": "http",
    }
    messages = []

    async def receive():
        return {"type": "http.request", "body": raw, "more_body": False}

    async def send(message):
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    out = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.response.body")
    hdrs = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in start.get("headers") or []]
    return start["status"], hdrs, out


def _root(tmp: str):
    return patch("looking_glass.config.get_root", return_value=tmp)


class NegotiateTests(unittest.TestCase):
    def test_parse_q_values_and_x_gzip(self):
        parsed = parse_accept_encoding("br;q=0.8, gzip, x-gzip;q=0.5")
        self.assertEqual(parsed["br"], 0.8)
        self.assertEqual(parsed["gzip"], 1.0)

    def test_missing_header_does_not_negotiate(self):
        self.assertIsNone(parse_accept_encoding(None))
        codec, reject = choose_codec(None, CompressSettings())
        self.assertIsNone(codec)
        self.assertFalse(reject)

    def test_prefer_brotli_on_tie(self):
        codec, reject = choose_codec("br, gzip", CompressSettings())
        self.assertEqual(codec, "br")
        self.assertFalse(reject)

    def test_honor_higher_gzip_q(self):
        codec, reject = choose_codec("gzip;q=1, br;q=0.4", CompressSettings())
        self.assertEqual(codec, "gzip")
        self.assertFalse(reject)

    def test_operator_toggles(self):
        both = CompressSettings(gzip=True, brotli=True)
        gzip_only = CompressSettings(gzip=True, brotli=False)
        br_only = CompressSettings(gzip=False, brotli=True)
        off = CompressSettings(gzip=False, brotli=False)
        self.assertEqual(choose_codec("br, gzip", both)[0], "br")
        self.assertEqual(choose_codec("br, gzip", gzip_only)[0], "gzip")
        self.assertEqual(choose_codec("br, gzip", br_only)[0], "br")
        self.assertIsNone(choose_codec("br, gzip", off)[0])
        self.assertIsNone(choose_codec("br", gzip_only)[0])

    def test_identity_q0_is_406(self):
        codec, reject = choose_codec("identity;q=0", CompressSettings())
        self.assertIsNone(codec)
        self.assertTrue(reject)

    def test_star_q(self):
        codec, reject = choose_codec("*;q=0.5", CompressSettings(gzip=True, brotli=False))
        self.assertEqual(codec, "gzip")
        self.assertFalse(reject)


class ApplyResponseTests(unittest.TestCase):
    def test_brotli_round_trip_and_vary(self):
        body = _pad_json()
        status, headers, out = apply_response(
            status=200,
            headers=[("Content-Type", "application/json"), ("Vary", "Origin")],
            body=body,
            path="/1.1.1.1",
            accept_encoding="br, gzip",
            settings=CompressSettings(),
        )
        self.assertEqual(status, 200)
        self.assertEqual(_hdr(headers, "Content-Encoding"), "br")
        self.assertEqual(_hdr(headers, "Content-Length"), str(len(out)))
        self.assertIn("Origin", _hdr(headers, "Vary"))
        self.assertIn("Accept-Encoding", _hdr(headers, "Vary"))
        self.assertEqual(brotli.decompress(out), body)
        self.assertLess(len(out), len(body))

    def test_gzip_when_brotli_disabled(self):
        body = _pad_json()
        status, headers, out = apply_response(
            status=200,
            headers=[("Content-Type", "application/json")],
            body=body,
            path="/",
            accept_encoding="br, gzip",
            settings=CompressSettings(gzip=True, brotli=False),
        )
        self.assertEqual(_hdr(headers, "Content-Encoding"), "gzip")
        self.assertEqual(gzip.decompress(out), body)

    def test_both_off_stays_plain(self):
        body = _pad_json()
        status, headers, out = apply_response(
            status=200,
            headers=[("Content-Type", "application/json")],
            body=body,
            path="/",
            accept_encoding="br, gzip",
            settings=CompressSettings(gzip=False, brotli=False),
        )
        self.assertEqual(status, 200)
        self.assertIsNone(_hdr(headers, "Content-Encoding"))
        self.assertEqual(out, body)

    def test_skip_small_set_cookie_acme_and_packed(self):
        small = b'{"ok":true}'
        _, headers, out = apply_response(
            status=200,
            headers=[("Content-Type", "application/json")],
            body=small,
            path="/",
            accept_encoding="gzip",
            settings=CompressSettings(min_bytes=1024),
        )
        self.assertEqual(out, small)
        self.assertIsNone(_hdr(headers, "Content-Encoding"))

        cookie_body = b"x" * 2000
        _, headers, out = apply_response(
            status=200,
            headers=[("Content-Type", "text/html"), ("Set-Cookie", "a=b")],
            body=cookie_body,
            path="/",
            accept_encoding="gzip",
            settings=CompressSettings(min_bytes=100),
        )
        self.assertEqual(out, cookie_body)
        self.assertIsNone(_hdr(headers, "Content-Encoding"))

        acme = b"token-value" * 200
        _, headers, out = apply_response(
            status=200,
            headers=[("Content-Type", "text/plain")],
            body=acme,
            path="/.well-known/acme-challenge/abc",
            accept_encoding="gzip",
            settings=CompressSettings(min_bytes=10),
        )
        self.assertEqual(out, acme)
        self.assertIsNone(_hdr(headers, "Content-Encoding"))

        png = b"\x89PNG" + b"\x00" * 2000
        _, headers, out = apply_response(
            status=200,
            headers=[("Content-Type", "image/png")],
            body=png,
            path="/x.png",
            accept_encoding="gzip",
            settings=CompressSettings(min_bytes=10),
        )
        self.assertEqual(out, png)

    def test_no_transform_and_existing_encoding(self):
        body = _pad_json()
        _, headers, out = apply_response(
            status=200,
            headers=[
                ("Content-Type", "application/json"),
                ("Cache-Control", "no-transform"),
            ],
            body=body,
            path="/",
            accept_encoding="gzip",
            settings=CompressSettings(),
        )
        self.assertEqual(out, body)
        self.assertIsNone(_hdr(headers, "Content-Encoding"))

        _, headers, out = apply_response(
            status=200,
            headers=[
                ("Content-Type", "application/json"),
                ("Content-Encoding", "gzip"),
            ],
            body=body,
            path="/",
            accept_encoding="br",
            settings=CompressSettings(),
        )
        self.assertEqual(out, body)
        self.assertEqual(_hdr(headers, "Content-Encoding"), "gzip")

    def test_no_expansion(self):
        body = os.urandom(2048)
        encoded = encode_body("gzip", body)
        self.assertTrue(encoded is None or len(encoded) < len(body))
        status, headers, out = apply_response(
            status=200,
            headers=[("Content-Type", "text/plain")],
            body=body,
            path="/",
            accept_encoding="gzip",
            settings=CompressSettings(min_bytes=10),
        )
        if encoded is None:
            self.assertIsNone(_hdr(headers, "Content-Encoding"))
            self.assertEqual(out, body)
        self.assertEqual(status, 200)

    def test_406(self):
        status, headers, body = apply_response(
            status=200,
            headers=[("Content-Type", "application/json")],
            body=_pad_json(),
            path="/",
            accept_encoding="identity;q=0",
            settings=CompressSettings(),
        )
        self.assertEqual(status, 406)
        self.assertIn(b"not acceptable", body)

    def test_merge_vary_dedupes(self):
        headers = merge_vary([("Vary", "Origin"), ("Vary", "Accept-Encoding")])
        self.assertEqual(_hdr(headers, "Vary"), "Origin, Accept-Encoding")


class DecodeRequestTests(unittest.TestCase):
    def test_gzip_and_br(self):
        raw = b'{"hello":"wall"}'
        got, err = decode_request_body("gzip", gzip.compress(raw))
        self.assertIsNone(err)
        self.assertEqual(got, raw)
        got, err = decode_request_body("br", brotli.compress(raw))
        self.assertIsNone(err)
        self.assertEqual(got, raw)

    def test_unknown_and_nested(self):
        _, err = decode_request_body("deflate", b"xxxx")
        self.assertEqual(err, 415)
        _, err = decode_request_body("gzip, br", gzip.compress(b"ab"))
        self.assertEqual(err, 415)

    def test_zip_bomb(self):
        huge = b"a" * (1024 * 1024 + 50)
        packed = gzip.compress(huge)
        self.assertLess(len(packed), 1024 * 1024)
        _, err = decode_request_body("gzip", packed, max_bytes=1024 * 1024)
        self.assertEqual(err, 413)

    def test_identity_passthrough(self):
        got, err = decode_request_body("identity", b"abc")
        self.assertIsNone(got)
        self.assertIsNone(err)
        got, err = decode_request_body(None, b"abc")
        self.assertIsNone(got)
        self.assertIsNone(err)


class MiddlewareTests(unittest.TestCase):
    def test_wsgi_brotli_and_gzip(self):
        app = compress(_json_app, {"gzip": True, "brotli": True, "min_bytes": 100})
        status, headers, body = _wsgi(app, accept_encoding="br, gzip")
        self.assertEqual(status, 200)
        self.assertEqual(_hdr(headers, "Content-Encoding"), "br")
        self.assertEqual(int(_hdr(headers, "Content-Length")), len(body))
        self.assertIn("Accept-Encoding", _hdr(headers, "Vary"))
        self.assertEqual(brotli.decompress(body), _pad_json())

        app = compress(_json_app, {"gzip": True, "brotli": False, "min_bytes": 100})
        status, headers, body = _wsgi(app, accept_encoding="br, gzip")
        self.assertEqual(_hdr(headers, "Content-Encoding"), "gzip")
        self.assertEqual(gzip.decompress(body), _pad_json())

    def test_wsgi_no_accept_encoding(self):
        app = compress(_json_app, {"gzip": True, "brotli": True, "min_bytes": 100})
        status, headers, body = _wsgi(app)
        self.assertEqual(status, 200)
        self.assertIsNone(_hdr(headers, "Content-Encoding"))
        self.assertEqual(body, _pad_json())

    def test_asgi_brotli(self):
        app = compress(_json_asgi, {"gzip": True, "brotli": True, "min_bytes": 100})
        status, headers, body = _asgi(app, accept_encoding="br")
        self.assertEqual(status, 200)
        self.assertEqual(_hdr(headers, "Content-Encoding"), "br")
        self.assertEqual(int(_hdr(headers, "Content-Length")), len(body))
        self.assertEqual(brotli.decompress(body), _pad_json())

    def test_inbound_gzip_echo(self):
        app = compress(_echo_app, {"gzip": True, "brotli": True})
        raw = b'{"ok":true,"note":"challenge"}'
        status, _, body = _wsgi(
            app,
            method="POST",
            content_encoding="gzip",
            body=gzip.compress(raw),
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, raw)

    def test_inbound_too_large(self):
        app = compress(_echo_app, {"gzip": True, "brotli": True, "max_request_bytes": 1024})
        packed = gzip.compress(b"a" * 4000)
        status, _, body = _wsgi(
            app,
            method="POST",
            content_encoding="gzip",
            body=packed,
        )
        self.assertEqual(status, 413)
        self.assertIn(b"payload too large", body)

    def test_lists_path_forwards(self):
        from looking_glass.http import asgi, wsgi

        for app in (wsgi.app, asgi.app):
            self.assertEqual(app.lists_path, default_lists_path())


class SiteStackTests(unittest.TestCase):
    def _wsgi_site(self, **cfg):
        from looking_glass.http.wsgi import inner

        return compress(wall(inner, lists=None), cfg)

    def _asgi_site(self, **cfg):
        from looking_glass.http.asgi import inner

        return compress(wall(inner, lists=None), cfg)

    def test_static_css_wsgi_and_asgi(self):
        wsgi_app = self._wsgi_site(gzip=True, brotli=True, min_bytes=1024)
        status, headers, body = _wsgi(
            wsgi_app, path="/static/gui.css", accept_encoding="br, gzip"
        )
        self.assertEqual(status, 200)
        self.assertEqual(_hdr(headers, "Content-Encoding"), "br")
        text = brotli.decompress(body).decode("utf-8")
        self.assertIn(".asn-pop", text)
        self.assertEqual(int(_hdr(headers, "Content-Length")), len(body))

        asgi_app = self._asgi_site(gzip=True, brotli=True, min_bytes=1024)
        status, headers, body = _asgi(
            asgi_app, path="/static/gui.css", accept_encoding="gzip"
        )
        self.assertEqual(status, 200)
        self.assertEqual(_hdr(headers, "Content-Encoding"), "gzip")
        self.assertIn(".asn-pop", gzip.decompress(body).decode("utf-8"))

    def test_json_lookup_path(self):
        from looking_glass.intel_server.client import IPContext

        fake = {"ok": True, "result": {"ip": "1.1.1.1", "pad": "x" * 2000}}
        app = self._wsgi_site(gzip=True, brotli=True, min_bytes=100)
        ctx = IPContext(ip="1.1.1.1")
        with patch("looking_glass.http.site.lookup_classified", return_value=fake), patch(
            "looking_glass.intel_server.client.lookup_ip", return_value=ctx
        ):
            status, headers, body = _wsgi(
                app, path="/1.1.1.1", accept_encoding="gzip"
            )
        self.assertEqual(status, 200)
        self.assertEqual(_hdr(headers, "Content-Encoding"), "gzip")
        payload = json.loads(gzip.decompress(body))
        self.assertEqual(payload["query"], "1.1.1.1")


class ConfigToggleTests(unittest.TestCase):
    def test_set_value_and_cli(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp, _root(tmp), patch(
            "looking_glass.utility.get_root", return_value=tmp
        ):
            cfg = set_value("http.compress.gzip", False)
            self.assertFalse(cfg["http"]["compress"]["gzip"])
            self.assertTrue(cfg["http"]["compress"]["brotli"])
            self.assertEqual(cfg["http"]["compress"]["min_bytes"], 1024)
            again = load()
            self.assertFalse(again["http"]["compress"]["gzip"])
            result = runner.invoke(
                cli, ["--json", "config", "set", "http.compress.brotli", "false"]
            )
            self.assertEqual(result.exit_code, 0, result.output)
            payload = json.loads(result.stdout)
            self.assertFalse(payload["http"]["compress"]["brotli"])
            got = runner.invoke(cli, ["--json", "config", "get", "http.compress.gzip"])
            self.assertEqual(json.loads(got.stdout)["value"], False)

    def test_admin_fields_include_compress_keys(self):
        keys = set(known_keys())
        src = (
            Path(__file__).resolve().parents[1]
            / "looking_glass"
            / "http"
            / "static"
            / "admin.js"
        ).read_text(encoding="utf-8")
        for key in (
            "http.compress.gzip",
            "http.compress.brotli",
            "http.compress.min_bytes",
        ):
            self.assertIn(key, keys)
            self.assertIn(f'field("{key}"', src.replace(" ", ""))
