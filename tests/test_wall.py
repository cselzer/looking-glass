import asyncio
import inspect
import io
import json
import os
import tempfile
import threading
import unittest
from unittest.mock import AsyncMock, patch

from looking_glass.intel_server.client import IPContext
from looking_glass.wall import Decision, WallASGI, WallWSGI, wall
from looking_glass.wall import lists as wall_lists


def _ok_wsgi(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"ok"]


async def _ok_asgi(scope, receive, send):
    if scope["type"] != "http":
        return
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
    await send({"type": "http.response.body", "body": b"ok"})


def _wrap(**config):
    cfg = {"lists": None}
    cfg.update(config)
    return wall(_ok_wsgi, cfg)


def _ctx(**kwargs):
    kwargs.setdefault("ip", "203.0.113.1")
    return IPContext(**kwargs)


def _wsgi_get(app, remote="127.0.0.1", path="/", forwarded=None, accept=None, host=None, query=None, method="GET", accept_language=None, cookie=None, body=b"", correlation=None, scheme="http", forwarded_proto=None):
    captured = {}

    def start_response(status, headers, exc_info=None):
        captured["status"] = status
        captured["headers"] = headers

    if query is None and "?" in path:
        path, query = path.split("?", 1)
    raw = body if isinstance(body, (bytes, bytearray)) else str(body or "").encode("utf-8")
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query or "",
        "CONTENT_LENGTH": str(len(raw)),
        "SERVER_NAME": "test",
        "SERVER_PORT": "80",
        "wsgi.input": io.BytesIO(raw),
        "wsgi.errors": io.StringIO(),
        "wsgi.version": (1, 0),
        "wsgi.url_scheme": scheme or "http",
        "wsgi.multithread": False,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
        "REMOTE_ADDR": remote,
    }
    if forwarded:
        environ["HTTP_X_FORWARDED_FOR"] = forwarded
    if forwarded_proto:
        environ["HTTP_X_FORWARDED_PROTO"] = forwarded_proto
    if accept:
        environ["HTTP_ACCEPT"] = accept
    if host:
        environ["HTTP_HOST"] = host
    if accept_language:
        environ["HTTP_ACCEPT_LANGUAGE"] = accept_language
    if cookie:
        environ["HTTP_COOKIE"] = cookie
    if correlation:
        environ["HTTP_X_CORRELATION_ID"] = correlation
    if method.upper() == "POST":
        environ["CONTENT_TYPE"] = "application/json"
    body = b"".join(app(environ, start_response))
    headers = {k: v for k, v in captured["headers"]}
    status = int(captured["status"].split()[0])
    return status, headers, body


def _with_static(html: bytes | str) -> str:
    from looking_glass.http.site import respond

    text = html.decode("utf-8") if isinstance(html, (bytes, bytearray)) else html
    for name in ("gui.css", "gui.js", "index.js", "admin.js"):
        if f"/static/{name}" not in text:
            continue
        status, _, body, *_ = respond("wsgi", "127.0.0.1", f"/static/{name}", {})
        if int(status) == 200:
            text += "\n" + body.decode("utf-8")
    pos = 0
    seen = set()
    marker = 'src="/i18n/'
    while True:
        start = text.find(marker, pos)
        if start < 0:
            break
        end = text.find('"', start + 5)
        pos = start + 1
        if end < 0:
            break
        path = text[start + 5 : end]
        if path in seen:
            continue
        seen.add(path)
        status, _, body, *_ = respond("wsgi", "127.0.0.1", path, {})
        if int(status) == 200:
            text += "\n" + body.decode("utf-8")
    return text


def _without_i18n(text: str) -> str:
    start = text.find("window.__i18n = ")
    if start < 0:
        return text
    end = text.find("</script>", start)
    if end >= 0:
        return text[:start] + text[end:]
    semi = text.find(";\n", start)
    if semi >= 0:
        return text[:start] + text[semi + 1 :]
    return text[:start]


def _asgi_get(app, peer="127.0.0.1", path="/", forwarded=None):
    headers = []
    if forwarded:
        headers.append((b"x-forwarded-for", forwarded.encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": b"",
        "headers": headers,
        "client": (peer, 12345),
        "server": ("test", 80),
        "scheme": "http",
    }
    messages = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        messages.append(message)

    asyncio.run(app(scope, receive, send))
    start = next(m for m in messages if m["type"] == "http.response.start")
    body = b"".join(
        m.get("body", b"") for m in messages if m["type"] == "http.response.body"
    )
    hdrs = {k.decode("latin-1"): v.decode("latin-1") for k, v in start.get("headers") or []}
    return start["status"], hdrs, body


class CheckDecisionTests(unittest.TestCase):
    def test_allow_ip_overrides_block(self):
        w = _wrap(allow_ips=["203.0.113.8"], block_ips=["203.0.113.0/24"])
        decision, meta = w.check(ip="203.0.113.8", ctx=_ctx(asn=666))
        self.assertEqual(decision, Decision.ALLOW)
        self.assertEqual(meta["reason"], "allow_ip")

    def test_block_ip_cidr(self):
        w = _wrap(block_ips=["203.0.113.0/24"])
        decision, meta = w.check(ip="203.0.113.50")
        self.assertEqual(decision, Decision.BLOCK)
        self.assertEqual(meta["reason"], "block_ip")

    def test_block_asn_from_lookup(self):
        w = _wrap(block_asns=["AS13335", 666])
        decision, meta = w.check(ip="1.1.1.1", ctx=_ctx(ip="1.1.1.1", asn=13335))
        self.assertEqual(decision, Decision.BLOCK)
        self.assertEqual(meta["reason"], "block_asn")
        self.assertEqual(meta["asn"], 13335)

    def test_challenge_ip_and_asn(self):
        w = _wrap(challenge_ips=["198.51.100.9"], challenge_asns=[64500])
        ip_decision, ip_meta = w.check(ip="198.51.100.9")
        self.assertEqual(ip_decision, Decision.CHALLENGE)
        self.assertEqual(ip_meta["reason"], "challenge_ip")
        asn_decision, asn_meta = w.check(
            ip="198.51.100.10", ctx=_ctx(ip="198.51.100.10", asn=64500)
        )
        self.assertEqual(asn_decision, Decision.CHALLENGE)
        self.assertEqual(asn_meta["reason"], "challenge_asn")

    def test_unknown_visitor_is_allowed(self):
        w = _wrap()
        decision, meta = w.check(ip="203.0.113.1")
        self.assertEqual(decision, Decision.ALLOW)
        self.assertEqual(meta["reason"], "default")

    def test_default_block_loopback_and_acme(self):
        w = _wrap(default="block")
        decision, meta = w.check(ip="203.0.113.1")
        self.assertEqual(decision, Decision.BLOCK)
        self.assertEqual(meta["reason"], "default")
        decision, meta = w.check(ip="127.0.0.1")
        self.assertEqual(decision, Decision.ALLOW)
        self.assertEqual(meta["reason"], "loopback")
        decision, meta = w.check(
            ip="203.0.113.1",
            path="/.well-known/acme-challenge/token",
        )
        self.assertEqual(decision, Decision.ALLOW)
        self.assertEqual(meta["reason"], "acme")
        allowed = _wrap(default="block", allow_ips=["203.0.113.1"])
        decision, meta = allowed.check(ip="203.0.113.1")
        self.assertEqual(decision, Decision.ALLOW)
        self.assertEqual(meta["reason"], "allow_ip")

    def test_iana_documentation_is_allowed(self):
        w = _wrap()
        ctx = _ctx(
            ip="192.0.2.1",
            source="iana",
            asn=False,
            iana={"designation": "Documentation", "cidr": "192.0.2.0/24"},
        )
        decision, meta = w.check(ip="192.0.2.1", ctx=ctx)
        self.assertEqual(decision, Decision.ALLOW)
        self.assertEqual(meta["reason"], "default")

    def test_invalid_ip_is_blocked(self):
        w = _wrap()
        decision, meta = w.check(ip="not-an-ip")
        self.assertEqual(decision, Decision.BLOCK)
        self.assertEqual(meta["reason"], "invalid_ip")

    def test_allow_cidr_skips_country_block(self):
        w = _wrap(
            allow_ips=["10.0.0.0/8"],
            block_countries=["US"],
            block_asns=[15169],
        )
        decision, meta = w.check(
            ip="10.1.2.3",
            ctx=_ctx(ip="10.1.2.3", asn=15169, country="US"),
        )
        self.assertEqual(decision, Decision.ALLOW)
        self.assertEqual(meta["reason"], "allow_ip")

    def test_more_specific_block_beats_allow_cidr(self):
        w = _wrap(allow_ips=["10.0.0.0/8"], block_ips=["10.1.1.1"])
        blocked, _ = w.check(ip="10.1.1.1")
        allowed, _ = w.check(ip="10.2.2.2")
        self.assertEqual(blocked, Decision.BLOCK)
        self.assertEqual(allowed, Decision.ALLOW)

    def test_ipv6_cidr_and_mixed_families(self):
        w = _wrap(block_ips=["2001:db8::/32", "203.0.113.0/24"])
        v6, _ = w.check(ip="2001:db8:1::5")
        v4, _ = w.check(ip="203.0.113.9")
        other, meta = w.check(ip="fe80::1")
        self.assertEqual(v6, Decision.BLOCK)
        self.assertEqual(v4, Decision.BLOCK)
        self.assertEqual(other, Decision.ALLOW)
        self.assertEqual(meta["reason"], "default")

    def test_block_country_from_lookup(self):
        w = _wrap(block_countries=["uk"])
        decision, meta = w.check(ip="1.2.3.4", ctx=_ctx(ip="1.2.3.4", country="GB"))
        self.assertEqual(decision, Decision.BLOCK)
        self.assertEqual(meta["reason"], "block_country")
        self.assertEqual(meta["country"], "GB")

    def test_lists_file_and_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wall.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"block_ips": ["198.51.100.1"]}, fh)
            w = _wrap(lists=path)
            decision, _ = w.check(ip="198.51.100.1")
            self.assertEqual(decision, Decision.BLOCK)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"challenge_ips": ["198.51.100.1"]}, fh)
            w.reload_lists()
            decision, meta = w.check(ip="198.51.100.1")
            self.assertEqual(decision, Decision.CHALLENGE)
            self.assertEqual(meta["reason"], "challenge_ip")

    def test_corrupt_lists_keep_last_good(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wall.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"block_ips": ["198.51.100.1"]}, fh)
            w = _wrap(lists=path)
            self.assertEqual(w.check(ip="198.51.100.1")[0], Decision.BLOCK)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("not json {")
            w.reload_lists()
            self.assertEqual(w.check(ip="198.51.100.1")[0], Decision.BLOCK)
        from looking_glass.wall import traffic as wall_traffic
        wall_traffic.configure(None)

    def test_missing_lists_keep_last_good(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wall.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"block_ips": ["198.51.100.1"]}, fh)
            w = _wrap(lists=path)
            self.assertEqual(w.check(ip="198.51.100.1")[0], Decision.BLOCK)
            os.remove(path)
            w.reload_lists()
            self.assertEqual(w.check(ip="198.51.100.1")[0], Decision.BLOCK)
            status, headers, _ = _wsgi_get(w, remote="198.51.100.1")
            self.assertEqual(status, 403)
            self.assertEqual(headers.get("X-Wall-Reason"), "block_ip")
        from looking_glass.wall import traffic as wall_traffic
        wall_traffic.configure(None)

    def test_concurrent_adds_keep_both(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wall.json")
            errors = []

            def one(ip):
                try:
                    wall_lists.add("block", "ip", ip, path=path)
                except Exception as err:
                    errors.append(err)

            t1 = threading.Thread(target=one, args=("203.0.113.1",))
            t2 = threading.Thread(target=one, args=("203.0.113.2",))
            t1.start()
            t2.start()
            t1.join()
            t2.join()
            self.assertEqual(errors, [])
            data = wall_lists.load_lists(path)
            self.assertEqual(sorted(data["block_ips"]), ["203.0.113.1", "203.0.113.2"])

    def test_traffic_ring_survives_memory_reset(self):
        from looking_glass.wall import traffic as wall_traffic

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wall.json")
            wall_lists.save_lists({key: [] for key in wall_lists.DEFAULT_LISTS}, path)
            wall_traffic.configure(path)
            wall_traffic.reset()
            row = wall_traffic.record(
                id="abc123",
                peer="203.0.113.9",
                method="GET",
                path="/",
                decision="allow",
                status=200,
                ms=1.2,
            )
            wall_traffic.reset()
            rows = wall_traffic.tail()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["id"], row["id"])
            self.assertEqual(rows[0]["peer"], "203.0.113.9")
        wall_traffic.configure(None)
        wall_traffic.reset()

    def test_lookup_ip_does_not_cache_none(self):
        from looking_glass.intel_server import client as lookup_client

        lookup_client.lookup_ip.cache_clear()
        ctx = _ctx(ip="203.0.113.9", asn=64496)
        try:
            with patch(
                "looking_glass.intel_server.client.lookup_ip_async", new_callable=AsyncMock
            ) as mocked:
                mocked.return_value = None
                self.assertIsNone(lookup_client.lookup_ip("203.0.113.9"))
                mocked.return_value = ctx
                got = lookup_client.lookup_ip("203.0.113.9")
            self.assertEqual(got.asn, 64496)
            self.assertEqual(mocked.call_count, 2)
        finally:
            lookup_client.lookup_ip.cache_clear()


class WrapTests(unittest.TestCase):
    def test_block_skips_lookup_and_returns_403(self):
        app = _wrap(block_ips=["203.0.113.9"])
        with patch("looking_glass.intel_server.client.lookup_ip") as mocked:
            status, headers, body = _wsgi_get(app, remote="203.0.113.9")
        mocked.assert_not_called()
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("X-Wall-Decision"), "block")
        self.assertEqual(headers.get("X-Wall-Reason"), "block_ip")
        self.assertEqual(json.loads(body)["decision"], "block")

    def test_header_toggles(self):
        app = _wrap(
            block_ips=["203.0.113.9"],
            headers={"asn": False, "reason": False, "decision": True},
        )
        with patch("looking_glass.intel_server.client.lookup_ip") as mocked:
            status, headers, _body = _wsgi_get(app, remote="203.0.113.9")
        mocked.assert_not_called()
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("X-Wall-Decision"), "block")
        self.assertIsNone(headers.get("X-Wall-Reason"))
        self.assertIsNone(headers.get("X-Wall-ASN"))
        self.assertTrue(headers.get("X-Correlation-Id"))

    def test_forwarded_for_cannot_spoof_client(self):
        app = _wrap(block_ips=["203.0.113.9"])
        asgi = wall(_ok_asgi, lists=None, block_ips=["203.0.113.9"])
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=None),
            patch(
                "looking_glass.intel_server.client.lookup_ip_async",
                new=AsyncMock(return_value=None),
            ),
        ):
            status, _, body = _wsgi_get(
                app, remote="127.0.0.1", forwarded="203.0.113.9"
            )
            self.assertEqual(status, 200)
            self.assertEqual(body, b"ok")
            status, headers, _ = _wsgi_get(
                app, remote="203.0.113.9", forwarded="8.8.8.8"
            )
            self.assertEqual(status, 403)
            self.assertEqual(headers.get("X-Wall-Decision"), "block")
            status, _, body = _asgi_get(
                asgi, peer="127.0.0.1", forwarded="203.0.113.9"
            )
            self.assertEqual(status, 200)
            self.assertEqual(body, b"ok")

    def test_challenge_returns_json(self):
        app = _wrap(challenge_ips=["198.51.100.9"])
        status, headers, body = _wsgi_get(app, remote="198.51.100.9")
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("X-Wall-Decision"), "challenge")
        payload = json.loads(body)
        self.assertEqual(payload["ok"], False)
        self.assertEqual(payload["decision"], "challenge")
        self.assertEqual(payload["reason"], "challenge_ip")
        self.assertIn("ticket", payload)

    def test_allowed_request_gets_lookup_headers(self):
        app = _wrap()
        ctx = _ctx(
            ip="1.1.1.1",
            asn=13335,
            country="AU",
            flag_url="https://flagcdn.com/au.svg",
            org_name="Cloudflare",
        )
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=ctx):
            status, headers, body = _wsgi_get(app, remote="1.1.1.1")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")
        self.assertEqual(headers.get("X-Wall-Decision"), "allow")
        self.assertEqual(headers.get("X-Wall-ASN"), "13335")
        self.assertEqual(headers.get("X-Wall-Country"), "AU")

    def test_allow_list_skips_lookup(self):
        app = _wrap(allow_ips=["10.0.0.0/8"])
        with patch("looking_glass.intel_server.client.lookup_ip") as mocked:
            status, headers, body = _wsgi_get(app, remote="10.9.9.9")
        mocked.assert_not_called()
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")
        self.assertEqual(headers.get("X-Wall-Decision"), "allow")
        self.assertEqual(headers.get("X-Wall-Reason"), "allow_ip")

    def test_asgi_block_does_not_call_app(self):
        called = {"n": 0}

        async def inner(scope, receive, send):
            called["n"] += 1
            await _ok_asgi(scope, receive, send)

        app = wall(inner, lists=None, block_ips=["203.0.113.9"])
        status, headers, body = _asgi_get(app, peer="203.0.113.9")
        self.assertEqual(called["n"], 0)
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("x-wall-decision"), "block")
        self.assertEqual(json.loads(body)["decision"], "block")

    def test_ipv4_mapped_matches_ipv4_block(self):
        app = _wrap(block_ips=["203.0.113.9"])
        asgi = wall(_ok_asgi, lists=None, block_ips=["203.0.113.9"])
        status, headers, _ = _wsgi_get(app, remote="::ffff:203.0.113.9")
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("X-Wall-Decision"), "block")
        decision, _ = app.check(ip="::ffff:203.0.113.9")
        self.assertEqual(decision, Decision.BLOCK)
        status, headers, _ = _asgi_get(asgi, peer="::ffff:203.0.113.9")
        self.assertEqual(status, 403)

    def test_asgi_websocket_blocked_does_not_reach_app(self):
        called = {"n": 0}

        async def inner(scope, receive, send):
            called["n"] += 1
            await send({"type": "websocket.accept"})

        app = wall(inner, lists=None, block_ips=["203.0.113.9"])
        messages = []

        async def receive():
            return {"type": "websocket.connect"}

        async def send(message):
            messages.append(message)

        scope = {
            "type": "websocket",
            "asgi": {"version": "3.0"},
            "path": "/ws",
            "headers": [],
            "client": ("203.0.113.9", 12345),
            "scheme": "ws",
        }
        asyncio.run(app(scope, receive, send))
        self.assertEqual(called["n"], 0)
        self.assertEqual(messages[0]["type"], "websocket.close")
        self.assertEqual(messages[0].get("code"), 403)

    def test_wsgi_streams_without_buffering(self):
        seen = []

        def inner(environ, start_response):
            seen.append("start")
            start_response("200 OK", [("Content-Type", "text/plain")])

            def gen():
                seen.append("a")
                yield b"a"
                seen.append("b")
                yield b"b"

            return gen()

        app = wall(inner, lists=None, allow_ips=["127.0.0.1"])
        captured = {}

        def start_response(status, headers, exc_info=None):
            captured["status"] = status
            captured["headers"] = headers

        environ = {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/",
            "QUERY_STRING": "",
            "CONTENT_LENGTH": "0",
            "SERVER_NAME": "test",
            "SERVER_PORT": "80",
            "wsgi.input": io.BytesIO(b""),
            "wsgi.errors": io.StringIO(),
            "wsgi.version": (1, 0),
            "wsgi.url_scheme": "http",
            "wsgi.multithread": False,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
            "REMOTE_ADDR": "127.0.0.1",
        }
        result = app(environ, start_response)
        self.assertEqual(seen, ["start"])
        self.assertEqual(next(result), b"a")
        self.assertEqual(seen, ["start", "a"])
        self.assertEqual(b"".join(result), b"b")
        self.assertEqual(seen, ["start", "a", "b"])

    def test_non_ascii_org_header_does_not_throw(self):
        app = _wrap()
        asgi = wall(_ok_asgi, lists=None)
        ctx = _ctx(ip="1.1.1.1", org_name="Café 日本")
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=ctx):
            status, headers, body = _wsgi_get(app, remote="1.1.1.1")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")
        self.assertTrue(headers.get("X-Wall-Org"))
        with patch(
            "looking_glass.intel_server.client.lookup_ip_async",
            new=AsyncMock(return_value=ctx),
        ):
            status, headers, body = _asgi_get(asgi, peer="1.1.1.1")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")
        self.assertTrue(headers.get("x-wall-org") or headers.get("X-Wall-Org"))

    def test_empty_peer_is_blocked(self):
        app = _wrap()
        with patch("looking_glass.intel_server.client.lookup_ip") as mocked:
            status, headers, body = _wsgi_get(app, remote="")
        mocked.assert_not_called()
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("X-Wall-Reason"), "no_ip")
        self.assertEqual(json.loads(body)["decision"], "block")

    def test_lookup_none_blocks_when_asn_list_set(self):
        app = _wrap(block_asns=[13335])
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=None):
            status, headers, _ = _wsgi_get(app, remote="1.1.1.1")
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("X-Wall-Decision"), "block")
        self.assertEqual(headers.get("X-Wall-Reason"), "lookup_failed")

    def test_lookup_none_challenges_when_only_challenge_asn(self):
        app = _wrap(challenge_asns=[13335])
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=None):
            status, headers, _ = _wsgi_get(app, remote="1.1.1.1")
        self.assertEqual(status, 403)
        self.assertEqual(headers.get("X-Wall-Decision"), "challenge")
        self.assertEqual(headers.get("X-Wall-Reason"), "lookup_failed")

    def test_asgi_allow_reaches_app(self):
        app = wall(_ok_asgi, lists=None, allow_ips=["1.1.1.1"])
        status, headers, body = _asgi_get(app, peer="1.1.1.1")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"ok")
        self.assertEqual(headers.get("x-wall-decision"), "allow")

    def test_wrong_protocol_is_explicit(self):
        wsgi = _wrap()
        with self.assertRaises(TypeError):
            wsgi(object(), object(), object())
        asgi = wall(_ok_asgi, lists=None)
        with self.assertRaises(TypeError):
            asgi({}, lambda: None)

    def test_asgi_wrapper_is_asgi3(self):
        app = wall(_ok_asgi, lists=None)
        self.assertIsInstance(app, WallASGI)
        self.assertTrue(inspect.iscoroutinefunction(type(app).__call__))
        self.assertIsInstance(_wrap(), WallWSGI)
        self.assertFalse(inspect.iscoroutinefunction(type(_wrap()).__call__))

    def test_asgi_lifespan_completes(self):
        app = wall(_ok_asgi, lists=None)
        inbox = [{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}]
        sent = []

        async def receive():
            return inbox.pop(0)

        async def send(message):
            sent.append(message["type"])

        asyncio.run(app({"type": "lifespan"}, receive, send))
        self.assertEqual(
            sent, ["lifespan.startup.complete", "lifespan.shutdown.complete"]
        )

    def test_mtime_reloads_lists(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wall.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"block_ips": ["198.51.100.1"]}, fh)
            app = wall(_ok_wsgi, lists=path)
            status, _, _ = _wsgi_get(app, remote="198.51.100.1")
            self.assertEqual(status, 403)
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"block_ips": []}, fh)
            st = os.stat(path)
            os.utime(path, (st.st_atime, st.st_mtime + 1))
            status, _, body = _wsgi_get(app, remote="198.51.100.1")
            self.assertEqual(status, 200)
            self.assertEqual(body, b"ok")


class WallCliTests(unittest.TestCase):
    def test_block_list_remove_ip_asn_country(self):
        from click.testing import CliRunner

        from looking_glass.cli.entry import cli

        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.wall.lists.get_data_dir", return_value=tmp), patch(
                "looking_glass.http.weblog.compact_intel", return_value={}
            ):
                ip = runner.invoke(cli, ["--json", "wall", "block", "ip", "2001:db8::/32"])
                asn = runner.invoke(cli, ["--json", "wall", "block", "asn", "AS13335"])
                cc = runner.invoke(cli, ["--json", "wall", "block", "country", "uk"])
                listed = runner.invoke(cli, ["--json", "wall", "list"])
                self.assertEqual(ip.exit_code, 0, ip.output)
                self.assertEqual(asn.exit_code, 0, asn.output)
                self.assertEqual(cc.exit_code, 0, cc.output)
                self.assertEqual(listed.exit_code, 0, listed.output)
                payload = json.loads(listed.stdout)
                self.assertEqual(payload["ip"]["block"], ["2001:db8::/32"])
                self.assertEqual(payload["asn"]["block"], [13335])
                self.assertEqual(payload["country"]["block"], ["GB"])

                host = runner.invoke(cli, ["--json", "wall", "block", "ip", "192.0.2.1/32"])
                self.assertEqual(json.loads(host.stdout)["value"], "192.0.2.1")
                allow = runner.invoke(cli, ["--json", "wall", "allow", "ip", "192.0.2.1"])
                allow_payload = json.loads(allow.stdout)
                self.assertIn("192.0.2.1", allow_payload["allow"])
                self.assertNotIn("192.0.2.1", allow_payload["block"])

                removed = runner.invoke(cli, ["--json", "wall", "remove", "country", "GB"])
                self.assertEqual(removed.exit_code, 0, removed.output)
                countries = json.loads(
                    runner.invoke(cli, ["--json", "wall", "list", "country"]).stdout
                )
                self.assertEqual(countries["block"], [])

    def test_invalid_value_is_json_error(self):
        from click.testing import CliRunner

        from looking_glass.cli.entry import cli

        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.wall.lists.get_data_dir", return_value=tmp):
                result = runner.invoke(cli, ["--json", "wall", "block", "ip", "not-an-ip"])
        self.assertEqual(result.exit_code, 2)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["ok"])
        self.assertIn("error", payload)

    def test_lookup_rbl_does_not_mutate_lists(self):
        from click.testing import CliRunner

        from looking_glass.cli.entry import cli

        runner = CliRunner()
        rbl = {
            "ok": True,
            "listed": True,
            "status": "blocked",
            "flags": ["SBL"],
            "listed_on": ["Spamhaus ZEN"],
            "txt": [],
            "errors": 0,
        }
        fake = {
            "ok": True,
            "ip": "203.0.113.9",
            "result": {
                "ip": "203.0.113.9",
                "prefix": "203.0.113.0/24",
                "country": "US",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.cli.entry._daemon_running", return_value=False),
                patch("looking_glass.cli.entry._lookup_ip", return_value=fake),
                patch("looking_glass.cli.entry.check_rbls", return_value=rbl),
            ):
                result = runner.invoke(cli, ["--json", "lookup", "203.0.113.9", "--rbl"])
                self.assertEqual(result.exit_code, 0, result.output)
                payload = json.loads(result.stdout)
                self.assertNotIn("wall", payload)
                self.assertEqual(payload["rbl"]["status"], "blocked")
                self.assertEqual(wall_lists.read_actions(), [])
                listed = wall_lists.snapshot()
                self.assertEqual(listed["ip"]["block"], [])

    def test_cli_writes_and_reads_actions_log(self):
        from click.testing import CliRunner

        from looking_glass.cli.entry import cli

        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.wall.lists.get_data_dir", return_value=tmp):
                runner.invoke(cli, ["--json", "wall", "block", "ip", "192.0.2.1"])
                runner.invoke(cli, ["--json", "wall", "allow", "ip", "192.0.2.1"])
                runner.invoke(cli, ["--json", "wall", "challenge", "ip", "198.51.100.0/24"])
                runner.invoke(cli, ["--json", "wall", "remove", "ip", "198.51.100.0/24"])
                result = runner.invoke(cli, ["--json", "wall", "log"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        events = [row["event"] for row in payload["actions"]]
        self.assertEqual(events, ["block", "allow", "challenge", "remove"])
        self.assertTrue(all(row["source"] == "cli" for row in payload["actions"]))
        self.assertTrue(all(row["trigger"] == "manual" for row in payload["actions"]))
        self.assertEqual(payload["actions"][2]["value"], "198.51.100.0/24")
        self.assertEqual(payload["actions"][0]["note"], "blocked via cli")
        self.assertEqual(payload["actions"][1]["note"], "allowed via cli")
        self.assertEqual(payload["actions"][2]["note"], "challenged via cli")
        self.assertEqual(payload["actions"][3]["note"], "removed via cli")

    def test_http_demo_commands_exist(self):
        from looking_glass.cli.entry import cli

        self.assertEqual(
            {"block", "allow", "challenge", "list", "log", "reset", "remove", "wsgi", "asgi"},
            set(cli.commands["wall"].commands),
        )

    def test_http_demo_loads_default_lists(self):
        from looking_glass.http import asgi, wsgi
        from looking_glass.wall.lists import default_lists_path

        for app in (wsgi.app, asgi.app):
            self.assertEqual(app.lists_path, default_lists_path())
            self.assertFalse(hasattr(app, "use_reputation"))


class WallResetTests(unittest.TestCase):
    def test_reset_clears_arrays_meta_and_keeps_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wall.json")
            wall_lists.add("block", "ip", "203.0.113.9", path=path, note="scanner")
            wall_lists.add("allow", "ip", "192.0.2.1", path=path)
            wall_lists.add("challenge", "asn", "13335", path=path)
            wall_lists.add("block", "country", "CN", path=path)
            result = wall_lists.reset(path=path, note="wipe")
            self.assertTrue(result["ok"])
            self.assertTrue(result["changed"])
            self.assertEqual(result["action"], "reset")
            self.assertEqual(result["cleared"]["block_ips"], 1)
            self.assertEqual(result["cleared"]["allow_ips"], 1)
            self.assertEqual(result["cleared"]["challenge_asns"], 1)
            self.assertEqual(result["cleared"]["block_countries"], 1)
            snap = wall_lists.snapshot(path=path)
            self.assertEqual(snap["ip"]["block"], [])
            self.assertEqual(snap["ip"]["allow"], [])
            self.assertEqual(snap["ip"]["challenge"], [])
            self.assertEqual(snap["ip"]["meta"], {})
            self.assertEqual(snap["asn"]["challenge"], [])
            self.assertEqual(snap["country"]["block"], [])
            with open(path, encoding="utf-8") as fh:
                stored = json.loads(fh.read())
            for key in wall_lists.DEFAULT_LISTS:
                self.assertEqual(stored.get(key) or [], [])
            self.assertNotIn("meta", stored)
            self.assertNotIn("reasons", stored)
            actions = wall_lists.read_actions(path)
            self.assertGreaterEqual(len(actions), 5)
            self.assertEqual(actions[-1]["event"], "reset")
            self.assertEqual(actions[-1]["note"], "wipe")
            self.assertEqual(actions[-1]["source"], "cli")
            self.assertTrue(any(row["event"] == "block" for row in actions))

    def test_reset_force_skips_prompt(self):
        from click.testing import CliRunner

        from looking_glass.cli.entry import cli

        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.wall.lists.get_data_dir", return_value=tmp), patch(
                "looking_glass.http.weblog.compact_intel", return_value={}
            ):
                runner.invoke(cli, ["--json", "wall", "block", "ip", "192.0.2.1"])
                result = runner.invoke(cli, ["--json", "wall", "reset", "--force"])
                listed = runner.invoke(cli, ["--json", "wall", "list", "ip"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["changed"])
        self.assertEqual(payload["cleared"]["block_ips"], 1)
        self.assertEqual(json.loads(listed.stdout)["block"], [])

    def test_reset_stdin_n_aborts(self):
        from click.testing import CliRunner

        from looking_glass.cli.entry import cli

        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.http.weblog.compact_intel", return_value={}),
                patch("looking_glass.cli.entry._stdin_is_tty", return_value=True),
            ):
                runner.invoke(cli, ["--json", "wall", "block", "ip", "192.0.2.1"])
                result = runner.invoke(cli, ["wall", "reset"], input="n\n")
                listed = runner.invoke(cli, ["--json", "wall", "list", "ip"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertEqual(json.loads(listed.stdout)["block"], ["192.0.2.1"])

    def test_reset_stdin_y_proceeds(self):
        from click.testing import CliRunner

        from looking_glass.cli.entry import cli

        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.http.weblog.compact_intel", return_value={}),
                patch("looking_glass.cli.entry._stdin_is_tty", return_value=True),
            ):
                runner.invoke(cli, ["--json", "wall", "block", "ip", "192.0.2.1"])
                result = runner.invoke(cli, ["wall", "reset"], input="y\n")
                listed = runner.invoke(cli, ["--json", "wall", "list", "ip"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(listed.stdout)["block"], [])

    def test_reset_non_tty_requires_force(self):
        from click.testing import CliRunner

        from looking_glass.cli.entry import cli

        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.wall.lists.get_data_dir", return_value=tmp), patch(
                "looking_glass.http.weblog.compact_intel", return_value={}
            ):
                runner.invoke(cli, ["--json", "wall", "block", "ip", "192.0.2.1"])
                result = runner.invoke(cli, ["--json", "wall", "reset"])
                listed = runner.invoke(cli, ["--json", "wall", "list", "ip"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("--force", result.output)
        self.assertEqual(json.loads(listed.stdout)["block"], ["192.0.2.1"])


class WallMetaTests(unittest.TestCase):
    def test_add_stores_ts_note_and_snapshot_meta(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wall.json")
            result = wall_lists.add("block", "ip", "203.0.113.9", path=path, note="scanner")
            meta = result["meta"]["203.0.113.9"]
            self.assertEqual(meta["note"], "scanner")
            self.assertEqual(meta["event"], "block")
            self.assertEqual(meta["source"], "cli")
            self.assertTrue(str(meta["ts"]).endswith("Z"))
            snap = wall_lists.snapshot(path=path)
            self.assertEqual(snap["ip"]["meta"]["203.0.113.9"]["note"], "scanner")
            with open(path, encoding="utf-8") as fh:
                stored = json.loads(fh.read())
            self.assertEqual(stored["block_ips"], ["203.0.113.9"])
            self.assertEqual(stored["meta"]["block_ips:203.0.113.9"]["note"], "scanner")

    def test_existing_lists_have_empty_meta(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wall.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"block_ips": ["198.51.100.1"]}, fh)
            snap = wall_lists.snapshot(path=path)
            self.assertEqual(snap["ip"]["block"], ["198.51.100.1"])
            self.assertEqual(snap["ip"]["meta"], {})

    def test_move_drops_sibling_meta(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wall.json")
            wall_lists.add("block", "ip", "203.0.113.9", path=path, note="bad")
            wall_lists.add("allow", "ip", "203.0.113.9", path=path, note="false positive")
            snap = wall_lists.snapshot(path=path)
            self.assertEqual(snap["ip"]["allow"], ["203.0.113.9"])
            self.assertEqual(snap["ip"]["block"], [])
            self.assertEqual(snap["ip"]["meta"]["203.0.113.9"]["note"], "false positive")
            self.assertEqual(snap["ip"]["meta"]["203.0.113.9"]["event"], "allow")
            with open(path, encoding="utf-8") as fh:
                stored = json.loads(fh.read())
            self.assertNotIn("block_ips:203.0.113.9", stored.get("meta") or {})

    def test_remove_logs_note_and_drops_meta(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "wall.json")
            wall_lists.add("block", "ip", "203.0.113.9", path=path, note="temp")
            wall_lists.remove("ip", "203.0.113.9", path=path, note="expired")
            actions = wall_lists.read_actions(path)
            self.assertEqual(actions[-1]["event"], "remove")
            self.assertEqual(actions[-1]["note"], "expired")
            snap = wall_lists.snapshot(path=path)
            self.assertEqual(snap["ip"]["meta"], {})
            with open(path, encoding="utf-8") as fh:
                stored = json.loads(fh.read())
            self.assertNotIn("meta", stored)

    def test_cli_default_and_custom_notes(self):
        from click.testing import CliRunner

        from looking_glass.cli.entry import cli

        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.wall.lists.get_data_dir", return_value=tmp), patch(
                "looking_glass.http.weblog.compact_intel", return_value={}
            ):
                runner.invoke(cli, ["--json", "wall", "block", "ip", "192.0.2.1"])
                custom = runner.invoke(
                    cli,
                    ["--json", "wall", "block", "ip", "192.0.2.2", "--note", "honeypot"],
                )
                listed = runner.invoke(cli, ["--json", "wall", "list", "ip"])
        self.assertEqual(custom.exit_code, 0, custom.output)
        self.assertEqual(listed.exit_code, 0, listed.output)
        payload = json.loads(listed.stdout)
        self.assertEqual(payload["meta"]["192.0.2.1"]["note"], "blocked via cli")
        self.assertEqual(payload["meta"]["192.0.2.2"]["note"], "honeypot")
        self.assertEqual(json.loads(custom.stdout)["meta"]["192.0.2.2"]["note"], "honeypot")

    def test_admin_post_note(self):
        from looking_glass.http.site import respond

        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.wall.lists.get_data_dir", return_value=tmp):
                with patch("looking_glass.http.admin.current_user", return_value="alice"):
                    status, _, body, _ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/wall/block",
                        {},
                        method="POST",
                        body=b'{"kind":"ip","value":"203.0.113.9","note":"gui ban"}',
                        cookie="looking_glass_session=x",
                    )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["meta"]["203.0.113.9"]["note"], "gui ban")
        self.assertEqual(payload["meta"]["203.0.113.9"]["source"], "gui")


class ChallengeTrafficTests(unittest.TestCase):
    def setUp(self):
        from looking_glass.wall import traffic as wall_traffic

        wall_traffic.reset()
        self._tmp = tempfile.TemporaryDirectory()
        self._data_patch = patch("looking_glass.wall.lists.get_data_dir", return_value=self._tmp.name)
        self._data_patch.start()

    def tearDown(self):
        self._data_patch.stop()
        self._tmp.cleanup()
        from looking_glass.wall import traffic as wall_traffic

        wall_traffic.reset()

    def test_puzzle_cookie_allows_and_binds_ip(self):
        from looking_glass.wall.challenge import solve_ticket

        app = _wrap(challenge_ips=["198.51.100.0/24"], challenge_bits=8)
        status, _headers, body = _wsgi_get(app, remote="198.51.100.9")
        self.assertEqual(status, 403)
        payload = json.loads(body)
        counter = solve_ticket(payload["ticket"], payload["bits"])
        status2, headers2, body2 = _wsgi_get(
            app,
            remote="198.51.100.9",
            path="/_wall/challenge",
            method="POST",
            body=json.dumps(
                {"ticket": payload["ticket"], "counter": counter, "next": "/"}
            ),
        )
        self.assertEqual(status2, 200)
        self.assertTrue(json.loads(body2)["ok"])
        cookie = headers2.get("Set-Cookie", "")
        self.assertIn("looking_glass_pass=", cookie)
        token = cookie.split(";", 1)[0]
        status3, headers3, body3 = _wsgi_get(app, remote="198.51.100.9", cookie=token)
        self.assertEqual(status3, 200)
        self.assertEqual(body3, b"ok")
        self.assertEqual(headers3.get("X-Wall-Reason"), "pass")
        status4, _, body4 = _wsgi_get(app, remote="198.51.100.10", cookie=token)
        self.assertEqual(status4, 403)
        self.assertEqual(json.loads(body4)["decision"], "challenge")

    def test_challenge_html_for_browser(self):
        app = _wrap(challenge_ips=["198.51.100.9"], challenge_bits=8)
        status, headers, body = _wsgi_get(
            app, remote="198.51.100.9", accept="text/html"
        )
        self.assertEqual(status, 403)
        self.assertIn("text/html", headers.get("Content-Type", ""))
        self.assertIn(b"Checking your browser", body)

    def test_admin_session_still_challenged_on_index(self):
        app = _wrap(challenge_ips=["198.51.100.9"], challenge_bits=8)
        with patch("looking_glass.wall.wrapper._admin_user", return_value="alice"):
            status, headers, body = _wsgi_get(
                app,
                remote="198.51.100.9",
                accept="text/html",
                cookie="looking_glass_session=x",
            )
        self.assertEqual(status, 403)
        self.assertIn(b"Checking your browser", body)
        self.assertEqual(headers.get("X-Wall-Decision"), "challenge")

    def test_admin_session_can_use_wall_api_while_challenged(self):
        def inner(environ, start_response):
            start_response("200 OK", [("Content-Type", "application/json")])
            return [b'{"ok":true}']

        app = wall(
            inner,
            {"lists": None, "challenge_ips": ["198.51.100.9"], "challenge_bits": 8},
        )
        with patch("looking_glass.wall.wrapper._admin_user", return_value="alice"):
            status, headers, body = _wsgi_get(
                app,
                remote="198.51.100.9",
                path="/wall",
                cookie="looking_glass_session=x",
            )
            removed, _, _ = _wsgi_get(
                app,
                remote="198.51.100.9",
                path="/wall/remove",
                method="POST",
                body=b'{"kind":"ip","value":"198.51.100.9"}',
                cookie="looking_glass_session=x",
            )
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"ok":true}')
        self.assertEqual(headers.get("X-Wall-Reason"), "session")
        self.assertEqual(removed, 200)

    def test_correlation_id_minted_ignores_client(self):
        from looking_glass.wall import traffic as wall_traffic

        app = _wrap()
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=None):
            status, headers, _ = _wsgi_get(app, remote="1.1.1.1", correlation="req-1")
        self.assertEqual(status, 200)
        cid = headers.get("X-Correlation-Id")
        self.assertTrue(cid)
        self.assertNotEqual(cid, "req-1")
        self.assertEqual(len(cid), 36)
        rows = wall_traffic.tail()
        self.assertTrue(rows)
        self.assertEqual(rows[-1]["id"], cid)
        status2, headers2, _ = _wsgi_get(app, remote="1.1.1.1")
        self.assertTrue(headers2.get("X-Correlation-Id"))
        self.assertNotEqual(headers2.get("X-Correlation-Id"), cid)

    def test_traffic_ring_includes_denies(self):
        from looking_glass.wall import traffic as wall_traffic

        app = _wrap(block_ips=["203.0.113.9"])
        _wsgi_get(app, remote="203.0.113.9", path="/hello")
        rows = wall_traffic.tail()
        self.assertTrue(rows)
        last = rows[-1]
        self.assertEqual(last["decision"], "block")
        self.assertEqual(last["status"], 403)
        self.assertEqual(last["path"], "/hello")
        self.assertEqual(last["peer"], "203.0.113.9")
        self.assertTrue(last["id"])
        more = wall_traffic.tail(after=last["id"])
        self.assertEqual(more, [])

    def test_traffic_row_includes_prefix(self):
        from looking_glass.wall import traffic as wall_traffic

        wall_traffic.reset()
        app = _wrap()
        ctx = _ctx(ip="1.1.1.1", prefix="1.1.1.0/24")
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=ctx):
            _wsgi_get(app, remote="1.1.1.1", path="/hello")
        rows = wall_traffic.tail()
        self.assertTrue(rows)
        self.assertEqual(rows[-1]["prefix"], "1.1.1.0/24")
        self.assertEqual(rows[-1]["path"], "/hello")

    def test_traffic_skips_heartbeat_gets(self):
        from looking_glass.wall import traffic as wall_traffic

        wall_traffic.reset()
        app = _wrap()
        _wsgi_get(app, remote="1.1.1.1", path="/status")
        _wsgi_get(app, remote="1.1.1.1", path="/wall")
        _wsgi_get(app, remote="1.1.1.1", path="/wall/traffic")
        _wsgi_get(app, remote="1.1.1.1", path="/wall/challenge")
        _wsgi_get(app, remote="1.1.1.1", path="/hello")
        paths = [row["path"] for row in wall_traffic.tail()]
        self.assertNotIn("/status", paths)
        self.assertNotIn("/wall", paths)
        self.assertNotIn("/wall/traffic", paths)
        self.assertNotIn("/wall/challenge", paths)
        self.assertIn("/hello", paths)

    def test_challenge_ring_issued_solved_failed(self):
        from looking_glass.wall import traffic as wall_traffic
        from looking_glass.wall.challenge import solve_ticket

        wall_traffic.reset()
        app = _wrap(challenge_ips=["198.51.100.0/24"], challenge_bits=8)
        status, _, body = _wsgi_get(app, remote="198.51.100.9")
        self.assertEqual(status, 403)
        issued = wall_traffic.tail_challenge()
        self.assertTrue(any(row.get("event") == "issued" for row in issued))
        self.assertTrue(any(row.get("reason") == "challenge_ip" for row in issued))
        payload = json.loads(body)
        fail_status, _, _ = _wsgi_get(
            app,
            remote="198.51.100.9",
            path="/_wall/challenge",
            method="POST",
            body=json.dumps({"ticket": "not-a-ticket", "counter": 0, "next": "/"}),
        )
        self.assertEqual(fail_status, 403)
        failed = wall_traffic.tail_challenge()
        self.assertTrue(any(row.get("event") == "failed" for row in failed))
        self.assertTrue(any(row.get("reason") == "challenge failed" for row in failed))
        counter = solve_ticket(payload["ticket"], payload["bits"])
        ok_status, _, ok_body = _wsgi_get(
            app,
            remote="198.51.100.9",
            path="/_wall/challenge",
            method="POST",
            body=json.dumps(
                {"ticket": payload["ticket"], "counter": counter, "next": "/"}
            ),
        )
        self.assertEqual(ok_status, 200)
        self.assertTrue(json.loads(ok_body)["ok"])
        solved = wall_traffic.tail_challenge()
        self.assertTrue(any(row.get("event") == "solved" for row in solved))
        self.assertTrue(any(row.get("reason") == "pass" for row in solved))
        log_path = os.path.join(self._tmp.name, "wall.log")
        self.assertTrue(os.path.isfile(log_path))
        text = open(log_path, encoding="utf-8").read()
        self.assertIn('"event": "issued"', text)
        self.assertIn('"event": "failed"', text)
        self.assertIn('"event": "solved"', text)

    def test_admin_wall_api_mutates_lists(self):
        from looking_glass.http.site import respond

        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.wall.lists.get_data_dir", return_value=tmp):
                denied, _, denied_body, _ = respond("wsgi", "127.0.0.1", "/wall", {})
                self.assertEqual(denied, 401)
                with patch("looking_glass.http.admin.current_user", return_value="alice"):
                    listed, _, listed_body, _ = respond(
                        "wsgi", "127.0.0.1", "/wall", {}, cookie="looking_glass_session=x"
                    )
                    self.assertEqual(listed, 200)
                    snap = json.loads(listed_body)
                    self.assertTrue(snap["ok"])
                    self.assertTrue(snap.get("country_catalog"))
                    self.assertTrue(any(row.get("code") == "US" for row in snap["country_catalog"]))
                    self.assertEqual(snap.get("ip_prefix"), {})
                    blocked, _, block_body, _ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/wall/block",
                        {},
                        method="POST",
                        body=b'{"kind":"ip","value":"203.0.113.9"}',
                        cookie="looking_glass_session=x",
                    )
                    self.assertEqual(blocked, 200)
                    self.assertIn("203.0.113.9", json.loads(block_body)["block"])
                    with patch(
                        "looking_glass.http.weblog.compact_intel",
                        return_value={"prefix": "203.0.113.0/24"},
                    ):
                        prefixed, _, prefix_body, _ = respond(
                            "wsgi", "127.0.0.1", "/wall", {}, cookie="looking_glass_session=x"
                        )
                    self.assertEqual(prefixed, 200)
                    self.assertEqual(
                        json.loads(prefix_body).get("ip_prefix", {}).get("203.0.113.9"),
                        "203.0.113.0/24",
                    )
                    traffic, _, traffic_body, _ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/wall/traffic",
                        {},
                        cookie="looking_glass_session=x",
                    )
                    self.assertEqual(traffic, 200)
                    self.assertIn("rows", json.loads(traffic_body))
                    puzzles, _, puzzle_body, _ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/wall/challenge",
                        {},
                        cookie="looking_glass_session=x",
                    )
                    self.assertEqual(puzzles, 200)
                    self.assertIn("rows", json.loads(puzzle_body))


class ClassifyQueryTests(unittest.TestCase):
    def test_detects_ip_asn_country(self):
        from looking_glass.intel_server.pipeline import classify_query

        self.assertEqual(classify_query("1.1.1.1"), ("ip", "1.1.1.1"))
        self.assertEqual(classify_query("[2001:db8::1]"), ("ip", "2001:db8::1"))
        self.assertEqual(classify_query("AS13335"), ("asn", "13335"))
        self.assertEqual(classify_query("13335"), ("asn", "13335"))
        self.assertEqual(classify_query("au"), ("country", "AU"))
        self.assertEqual(classify_query("UK"), ("country", "GB"))

    def test_rejects_garbage(self):
        from looking_glass.intel_server.pipeline import classify_query

        with self.assertRaises(ValueError):
            classify_query("not-an-ip")


class HttpDemoTests(unittest.TestCase):
    def _demo_app(self, protocol):
        if protocol == "wsgi":
            from looking_glass.http.wsgi import inner
        else:
            from looking_glass.http.asgi import inner
        return wall(inner, lists=None)

    def test_root_looks_up_visitor(self):
        fake = {"ok": True, "ip": "1.1.1.1", "result": {"ip": "1.1.1.1", "asn": 13335}}
        ctx = _ctx(ip="1.1.1.1", asn=13335, country="AU", flag_url="https://flagcdn.com/au.svg")
        app = self._demo_app("wsgi")
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=ctx),
            patch("looking_glass.http.site.lookup_classified", return_value=fake) as classified,
        ):
            status, _headers, body = _wsgi_get(app, remote="1.1.1.1")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        classified.assert_called_once_with("ip", "1.1.1.1", qtype=None)
        self.assertEqual(payload["protocol"], "wsgi")
        self.assertEqual(payload["visitor"], "1.1.1.1")
        self.assertEqual(payload["query"], "1.1.1.1")
        self.assertEqual(payload["kind"], "ip")
        self.assertEqual(payload["result"]["asn"], 13335)
        keys = list(payload)
        self.assertEqual(keys[keys.index("query") + 1], "result")
        self.assertNotIn("wall", payload)

    def test_path_detects_ip_asn_country(self):
        app = self._demo_app("wsgi")

        def classified(kind, value, qtype=None):
            return {"ok": True, "result": {kind: value}}

        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.lookup_classified", side_effect=classified),
        ):
            status, _, body = _wsgi_get(app, remote="127.0.0.1", path="/1.1.1.1")
            ip_payload = json.loads(body)
            status_asn, _, asn_body = _wsgi_get(app, remote="127.0.0.1", path="/AS13335")
            asn_payload = json.loads(asn_body)
            status_cc, _, cc_body = _wsgi_get(app, remote="127.0.0.1", path="/AU")
            cc_payload = json.loads(cc_body)
            status_v6, _, v6_body = _wsgi_get(
                app, remote="127.0.0.1", path="/2001%3Adb8%3A%3A1"
            )
            v6_payload = json.loads(v6_body)
        self.assertEqual(status, 200)
        self.assertEqual(ip_payload["kind"], "ip")
        self.assertEqual(ip_payload["query"], "1.1.1.1")
        self.assertEqual(ip_payload["visitor"], "127.0.0.1")
        self.assertEqual(status_asn, 200)
        self.assertEqual(asn_payload["kind"], "asn")
        self.assertEqual(asn_payload["query"], "13335")
        self.assertEqual(status_cc, 200)
        self.assertEqual(cc_payload["kind"], "country")
        self.assertEqual(cc_payload["query"], "AU")
        self.assertEqual(status_v6, 200)
        self.assertEqual(v6_payload["kind"], "ip")
        self.assertEqual(v6_payload["query"], "2001:db8::1")
        self.assertNotIn("wall", ip_payload)

    def test_path_query_omits_visitor_iana(self):
        app = self._demo_app("wsgi")
        ctx = _ctx(
            ip="127.0.0.1",
            source="iana",
            iana={"cidr": "127.0.0.0/8", "designation": "Loopback"},
            timings={"iana_lookup_ms": 0.4},
        )
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=ctx),
            patch(
                "looking_glass.http.site.lookup_classified",
                return_value={"ok": True, "ip": "24.154.32.53", "result": {"country": "US"}},
            ),
        ):
            status, _, body = _wsgi_get(
                app, remote="127.0.0.1", path="/24.154.32.53"
            )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertNotIn("wall", payload)

    def test_forwarded_for_does_not_change_visitor_or_lookup(self):
        app = self._demo_app("wsgi")
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch(
                "looking_glass.http.site.lookup_classified",
                return_value={"ok": True, "ip": "127.0.0.1", "result": {}},
            ) as classified,
        ):
            status, _, body = _wsgi_get(
                app, remote="127.0.0.1", forwarded="1.1.1.1"
            )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        classified.assert_called_once_with("ip", "127.0.0.1", qtype=None)
        self.assertEqual(payload["visitor"], "127.0.0.1")
        self.assertEqual(payload["query"], "127.0.0.1")

    def test_unknown_path_is_404(self):
        app = self._demo_app("wsgi")
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")):
            status, _, body = _wsgi_get(app, remote="127.0.0.1", path="/not-an-ip")
        self.assertEqual(status, 404)
        payload = json.loads(body)
        self.assertFalse(payload["ok"])
        self.assertIn("not an IP address", payload["error"])

    def test_unknown_path_html_is_404_not_index(self):
        app = self._demo_app("wsgi")
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")):
            status, _, body = _wsgi_get(
                app, remote="127.0.0.1", path="/favicon.ico", accept="text/html"
            )
        self.assertEqual(status, 404)
        text = _with_static(body)
        self.assertIn("not an IP address", text)
        self.assertNotIn("form-ip", text)
        self.assertNotIn("id=\"form-ip\"", text)

    def test_dns_path_queries_type(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "name": "example.com.",
            "qtype": "AAAA",
            "result": {
                "status": "NOERROR",
                "name": "example.com.",
                "qtype": "AAAA",
                "qtype_value": 28,
                "answers": [
                    {
                        "name": "example.com.",
                        "type": "AAAA",
                        "class": "IN",
                        "ttl": 300,
                        "data": "2606:2800:220:1:248:1893:25c8:1946",
                    }
                ],
                "authority": [],
                "additional": [],
            },
            "error": None,
            "total_ms": 1.2,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.lookup_dns", return_value=fake) as dns,
        ):
            status, _, body = _wsgi_get(
                app, remote="127.0.0.1", path="/dns/example.com/AAAA"
            )
            default_status, _, default_body = _wsgi_get(
                app, remote="127.0.0.1", path="/dns/example.com"
            )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "dns")
        self.assertEqual(payload["query"], "example.com")
        self.assertEqual(payload["qtype"], "AAAA")
        self.assertEqual(payload["result"]["answers"][0]["type"], "AAAA")
        self.assertNotIn("wall", payload)
        dns.assert_any_call("example.com", "AAAA")
        self.assertEqual(default_status, 200)
        self.assertEqual(json.loads(default_body)["query"], "example.com")
        dns.assert_any_call("example.com", "A")

    def test_dns_rejects_meta_and_bare_prefix(self):
        app = self._demo_app("wsgi")
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")):
            any_status, _, any_body = _wsgi_get(
                app, remote="127.0.0.1", path="/dns/example.com/ANY"
            )
            bare_status, _, bare_body = _wsgi_get(app, remote="127.0.0.1", path="/dns")
        self.assertEqual(any_status, 400)
        self.assertIn("not a lookup type", json.loads(any_body)["error"])
        self.assertEqual(bare_status, 400)
        self.assertIn("needs a name", json.loads(bare_body)["error"])

    def test_dns_query_string_sets_nameserver_and_port(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "name": "example.com.",
            "qtype": "DS",
            "result": {
                "status": "NOERROR",
                "qtype": "DS",
                "answers": [
                    {
                        "name": "example.com.",
                        "type": "DS",
                        "ttl": 3600,
                        "data": "370 13 2 aabbccdd",
                    }
                ],
                "authority": [],
                "additional": [],
            },
            "error": None,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.lookup_dns", return_value=fake) as dns,
        ):
            status, _, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/dns/example.com/DS",
                query="server=1.1.1.1&port=5353",
            )
            html_status, html_headers, html_body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/dns/example.com/DS",
                accept="text/html",
            )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "dns")
        self.assertEqual(payload["qtype"], "DS")
        self.assertEqual(payload["result"]["answers"][0]["type"], "DS")
        dns.assert_any_call("example.com", "DS", server="1.1.1.1", port=5353)
        self.assertEqual(html_status, 200)
        self.assertTrue(html_headers["Content-Type"].startswith("text/html"))
        html = html_body.decode("utf-8")
        self.assertIn("DS", html)
        self.assertIn("370 13 2", html)

    def test_asgi_dns_path(self):
        fake = {
            "ok": True,
            "name": "example.com.",
            "qtype": "A",
            "result": {"status": "NOERROR", "qtype": "A", "answers": [], "authority": [], "additional": []},
            "error": None,
        }
        app = self._demo_app("asgi")
        with (
            patch(
                "looking_glass.intel_server.client.lookup_ip_async",
                new=AsyncMock(return_value=_ctx(ip="127.0.0.1")),
            ),
            patch(
                "looking_glass.http.site.lookup_dns_async",
                new=AsyncMock(return_value=fake),
            ) as dns,
        ):
            status, _, body = _asgi_get(
                app, peer="127.0.0.1", path="/dns/example.com"
            )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "dns")
        self.assertEqual(payload["query"], "example.com")
        dns.assert_awaited()

    def test_asgi_demo_path_and_visitor(self):
        fake = {"ok": True, "ip": "1.1.1.1", "result": {"asn": 13335}}
        ctx = _ctx(ip="1.1.1.1", asn=13335, country="AU")
        app = self._demo_app("asgi")
        with (
            patch(
                "looking_glass.intel_server.client.lookup_ip_async",
                new=AsyncMock(return_value=ctx),
            ),
            patch(
                "looking_glass.intel_server.client.lookup_json_async",
                new=AsyncMock(return_value=fake),
            ),
            patch("looking_glass.http.site.lookup_classified", return_value=fake),
        ):
            status, _headers, body = _asgi_get(app, peer="1.1.1.1")
            path_status, _, path_body = _asgi_get(
                app, peer="127.0.0.1", path="/AS13335"
            )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["protocol"], "asgi")
        self.assertEqual(payload["visitor"], "1.1.1.1")
        self.assertEqual(payload["kind"], "ip")
        self.assertNotIn("wall", payload)
        self.assertEqual(path_status, 200)
        self.assertEqual(json.loads(path_body)["kind"], "asn")
        self.assertEqual(json.loads(path_body)["query"], "13335")
        self.assertNotIn("wall", json.loads(path_body))

    def test_asgi_ip_lookup_uses_daemon_without_local_load(self):
        fake = {"ok": True, "ip": "1.1.1.1", "result": {"asn": 13335}}
        app = self._demo_app("asgi")
        with (
            patch(
                "looking_glass.intel_server.client.lookup_ip_async",
                new=AsyncMock(return_value=_ctx(ip="127.0.0.1")),
            ),
            patch(
                "looking_glass.intel_server.client.lookup_json_async",
                new=AsyncMock(return_value=fake),
            ) as daemon,
            patch("looking_glass.intel_server.pipeline.lookup_ip") as local,
        ):
            status, _, body = _asgi_get(app, peer="127.0.0.1", path="/1.1.1.1")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["via"], "intel")
        self.assertEqual(payload["query"], "1.1.1.1")
        self.assertEqual(list(payload)[list(payload).index("query") + 1], "result")
        daemon.assert_awaited()
        local.assert_not_called()

    def test_sync_ip_lookup_skips_asyncio_run_inside_loop(self):
        from looking_glass.http.site import lookup_classified

        async def go():
            with patch("looking_glass.intel_server.client.lookup_json") as daemon:
                out = lookup_classified("ip", "1.1.1.1")
            daemon.assert_not_called()
            self.assertFalse(out["ok"])
            self.assertEqual(out["error"], "intel server unavailable")
            self.assertIsNone(out.get("via"))

        asyncio.run(go())

    def test_asgi_ip_lookup_does_not_load_locally_when_daemon_misses(self):
        app = self._demo_app("asgi")
        with (
            patch(
                "looking_glass.intel_server.client.lookup_ip_async",
                new=AsyncMock(return_value=_ctx(ip="127.0.0.1")),
            ),
            patch(
                "looking_glass.intel_server.client.lookup_json_async",
                new=AsyncMock(return_value=None),
            ),
            patch("looking_glass.intel_server.pipeline.lookup_ip") as local,
        ):
            status, _, body = _asgi_get(app, peer="127.0.0.1", path="/1.1.1.1")
        self.assertEqual(status, 503)
        payload = json.loads(body)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "intel server unavailable")
        local.assert_not_called()

    def test_reputation_domain_path(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "domain": "example.com",
                "status": "allowed",
                "listed": False,
                "listed_on": [],
                "flags": [],
                "txt": [],
                "lists": {},
            },
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.lookup_classified", return_value=fake) as classified,
        ):
            status, _, body = _wsgi_get(
                app, remote="127.0.0.1", path="/reputation/example.com"
            )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "reputation")
        self.assertEqual(payload["query"], "example.com")
        self.assertEqual(payload["result"]["status"], "allowed")
        classified.assert_called_once_with("reputation", "example.com", qtype=None)

    def test_reputation_needs_a_name(self):
        app = self._demo_app("wsgi")
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")):
            status, _, body = _wsgi_get(app, remote="127.0.0.1", path="/reputation")
        self.assertEqual(status, 400)
        self.assertIn("needs a name", json.loads(body)["error"])

    def test_tls_sni_query_reaches_inspect(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {"host": "example.com", "sni": "www.example.com", "verified": True},
            "error": None,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.inspect_tls", return_value=fake) as inspect,
        ):
            status, _, body = _wsgi_get(
                app, remote="127.0.0.1", path="/tls/example.com?sni=www.example.com"
            )
        self.assertEqual(status, 200)
        inspect.assert_called_once_with("example.com", port=443, sni="www.example.com")
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "tls")
        self.assertEqual(payload["query"], "example.com")

    def test_tls_colon_port_reaches_inspect(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {"host": "s1.example.com", "port": 5555, "verified": True},
            "error": None,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.inspect_tls", return_value=fake) as inspect,
        ):
            status, _, body = _wsgi_get(
                app, remote="127.0.0.1", path="/tls/s1.example.com:5555"
            )
        self.assertEqual(status, 200)
        inspect.assert_called_once_with("s1.example.com", port=5555, sni=None)
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "tls")
        self.assertEqual(payload["query"], "s1.example.com")

    def test_apex_path(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "domain": "example.com",
                "parent": "com",
                "summary": {"pass": 1, "warn": 0, "fail": 0, "info": 0, "total": 1},
                "sections": [
                    {
                        "id": "parent",
                        "title": "Parent",
                        "checks": [
                            {
                                "id": "parent_glue",
                                "title": "DNS Parent sent Glue",
                                "status": "pass",
                                "detail": "Good. Glue.",
                                "rfcs": [
                                    {
                                        "rfc": 1912,
                                        "section": "2.3",
                                        "title": "Common DNS Operational and Configuration Errors",
                                        "url": "https://www.rfc-editor.org/rfc/rfc1912",
                                    }
                                ],
                                "data": {},
                            }
                        ],
                    }
                ],
                "standards": [
                    {
                        "rfc": 1912,
                        "title": "Common DNS Operational and Configuration Errors",
                        "why": "Glue",
                        "url": "https://www.rfc-editor.org/rfc/rfc1912",
                        "sections": ["2.3"],
                    }
                ],
            },
            "error": None,
            "total_ms": 12.5,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.check_apex", return_value=fake) as check,
        ):
            status, _, body = _wsgi_get(
                app, remote="127.0.0.1", path="/apex/example.com"
            )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "apex")
        self.assertEqual(payload["query"], "example.com")
        self.assertEqual(payload["result"]["domain"], "example.com")
        self.assertEqual(payload["result"]["sections"][0]["checks"][0]["id"], "parent_glue")
        check.assert_called_once_with("example.com")

    def test_apex_needs_a_domain(self):
        app = self._demo_app("wsgi")
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")):
            bare_status, _, bare_body = _wsgi_get(app, remote="127.0.0.1", path="/apex")
            ip_status, _, ip_body = _wsgi_get(
                app, remote="127.0.0.1", path="/apex/1.1.1.1"
            )
        self.assertEqual(bare_status, 400)
        self.assertIn("needs a domain", json.loads(bare_body)["error"])
        self.assertEqual(ip_status, 400)
        self.assertIn("needs a domain", json.loads(ip_body)["error"])

    def test_ping_path(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "target": "1.1.1.1",
                "ip": "1.1.1.1",
                "family": "IPv4",
                "transmitted": 4,
                "received": 4,
                "loss_percent": 0.0,
                "min_ms": 1.1,
                "avg_ms": 1.2,
                "max_ms": 1.4,
                "probes": [
                    {"seq": 1, "from": "1.1.1.1", "rtt_ms": 1.2, "ok": True, "error": None}
                ],
                "via": "python-icmp",
            },
            "error": None,
            "total_ms": 40.0,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.run_probe", return_value=fake) as run,
        ):
            status, _, body = _wsgi_get(app, remote="127.0.0.1", path="/ping/1.1.1.1")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "ping")
        self.assertEqual(payload["query"], "1.1.1.1")
        self.assertEqual(payload["result"]["via"], "python-icmp")
        run.assert_called_once_with("ping", "1.1.1.1")

    def test_traceroute_and_mtr_paths(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "target": "example.com",
                "ip": "93.184.216.34",
                "family": "IPv4",
                "reached": True,
                "hops": [{"hop": 1, "host": "10.0.0.1", "rtt_ms": 1.0, "status": "ttl"}],
                "via": "python-icmp",
            },
            "error": None,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.run_probe", return_value=fake) as run,
        ):
            tr_status, _, tr_body = _wsgi_get(
                app, remote="127.0.0.1", path="/traceroute/example.com"
            )
            mtr_status, _, mtr_body = _wsgi_get(
                app, remote="127.0.0.1", path="/mtr/example.com"
            )
        self.assertEqual(tr_status, 200)
        self.assertEqual(json.loads(tr_body)["kind"], "traceroute")
        self.assertEqual(mtr_status, 200)
        self.assertEqual(json.loads(mtr_body)["kind"], "mtr")
        self.assertEqual([call.args[0] for call in run.call_args_list], ["traceroute", "mtr"])

    def test_mtr_cycles_query_is_forwarded(self):
        app = self._demo_app("wsgi")
        fake = {"ok": True, "result": {"cycles": 3, "hops": []}, "error": None}
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.run_probe", return_value=fake) as run,
        ):
            status, _, body = _wsgi_get(
                app, remote="127.0.0.1", path="/mtr/1.1.1.1", query="cycles=3"
            )
            omit, _, _ = _wsgi_get(app, remote="127.0.0.1", path="/mtr/1.1.1.1")
            garbage, _, garbage_body = _wsgi_get(
                app, remote="127.0.0.1", path="/mtr/1.1.1.1", query="cycles=foo"
            )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["kind"], "mtr")
        self.assertEqual(run.call_args_list[0].kwargs.get("cycles"), 3)
        self.assertIsNone(run.call_args_list[1].kwargs.get("cycles"))
        self.assertEqual(len(run.call_args_list), 2)
        self.assertEqual(omit, 200)
        self.assertEqual(garbage, 400)
        self.assertFalse(json.loads(garbage_body)["ok"])

    def test_ping_needs_a_host(self):
        app = self._demo_app("wsgi")
        with patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")):
            status, _, body = _wsgi_get(app, remote="127.0.0.1", path="/ping")
        self.assertEqual(status, 400)
        self.assertIn("needs a host", json.loads(body)["error"])

    def test_html_ping_renders_report(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "target": "1.1.1.1",
                "ip": "1.1.1.1",
                "family": "IPv4",
                "transmitted": 1,
                "received": 1,
                "loss_percent": 0.0,
                "min_ms": 1.0,
                "avg_ms": 1.0,
                "max_ms": 1.0,
                "probes": [
                    {
                        "seq": 1,
                        "from": "1.1.1.1",
                        "rtt_ms": 1.0,
                        "ok": True,
                        "error": None,
                        "asn": 13335,
                        "org_name": "CLOUDFLARENET",
                        "country": "AU",
                        "flag_url": "https://flagcdn.com/au.svg",
                    }
                ],
                "via": "python-icmp",
                "asn": 13335,
                "org_name": "CLOUDFLARENET",
                "country": "AU",
                "flag_url": "https://flagcdn.com/au.svg",
            },
            "error": None,
            "total_ms": 5.0,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.run_probe", return_value=fake),
        ):
            status, headers, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/ping/1.1.1.1",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        text = _with_static(body)
        self.assertIn("1.1.1.1", text)
        self.assertIn("New lookup", text)
        self.assertNotIn("UDP traceroute like traceroute(8)", _without_i18n(text))
        self.assertIn("python-icmp", text)
        self.assertIn("13335", text)
        self.assertIn("CLOUDFLARENET", text)
        self.assertIn("flagcdn.com/au.svg", text)
        self.assertIn("http://lg.example.com/ping/1.1.1.1", text)
        self.assertIn("paintInspect", text)
        self.assertIn("report-payload", text)
        self.assertIn('id="status-bar"', text)
        self.assertIn('id="status-ip"', text)
        self.assertIn('id="status-time"', text)
        self.assertIn('id="status-uptime"', text)
        self.assertIn('fetch("/status"', text)
        self.assertIn("data.ipv4", text)
        self.assertIn("data.ipv6", text)

    def test_html_traceroute_labels_udp_not_tcp(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "target": "1.1.1.1",
                "ip": "1.1.1.1",
                "family": "IPv4",
                "reached": True,
                "via": "python-tcp+python-tcp+python-udp",
                "probe": "udp",
                "summary": {
                    "route_text": "United States → Australia",
                    "reached": True,
                    "loss_percent": 0.0,
                    "latency_ms": 2.4,
                    "as_path": [13335],
                },
                "hops": [
                    {
                        "hop": 1,
                        "host": "1.1.1.1",
                        "rtt_ms": 2.4,
                        "status": "reply",
                        "via": "python-tcp",
                    }
                ],
            },
            "error": None,
            "total_ms": 20.0,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.run_probe", return_value=fake),
        ):
            status, _, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/traceroute/1.1.1.1",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        text = _with_static(body)
        self.assertIn("New lookup", text)
        self.assertIn("python-udp", text)
        self.assertIn("Route summary", text)
        self.assertIn("Path (GeoIP)", text)
        self.assertIn("United States", text)
        self.assertIn("Australia", text)
        self.assertIn("window.renderRegistration", text)
        self.assertIn("ASN + RDAP", text)
        self.assertIn('"probe": "udp"', text)
        self.assertIn('kind === "traceroute" || kind === "mtr"', text)
        self.assertNotIn("UDP traceroute like traceroute(8)", _without_i18n(text))

    def test_html_mtr_renders_summary_and_private_scope(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "target": "196.216.2.1",
                "ip": "196.216.2.1",
                "family": "IPv4",
                "cycles": 5,
                "reached": True,
                "via": "python-udp",
                "hops": [
                    {
                        "hop": 1,
                        "host": "10.64.10.169",
                        "loss_percent": 0.0,
                        "sent": 5,
                        "scope": "private",
                        "scope_label": "RFC1918",
                        "scope_detail": "Private/internal network address (RFC 1918)",
                        "lan": False,
                        "hosts": ["10.64.10.169", "63.218.9.241"],
                        "hosts_detail": [
                            {
                                "ip": "10.64.10.169",
                                "scope": "private",
                                "scope_label": "RFC1918",
                            },
                            {
                                "ip": "63.218.9.241",
                                "scope": "public",
                                "scope_label": "Public",
                                "org_name": "PCCW Global",
                            },
                        ],
                    },
                    {
                        "hop": 2,
                        "host": "196.216.2.1",
                        "loss_percent": 0.0,
                        "sent": 5,
                        "avg_ms": 225.5,
                        "asn": 33764,
                        "org_name": "AFRINIC",
                        "country": "MU",
                        "country_name": "Mauritius",
                        "flag_url": "https://flagcdn.com/mu.svg",
                        "scope": "public",
                        "lan": False,
                    },
                ],
                "summary": {
                    "route_text": "Mauritius",
                    "inferred_text": "Los Angeles → Sydney",
                    "reached": True,
                    "loss_percent": 0.0,
                    "latency_ms": 225.5,
                    "as_text": "AS33764",
                    "as_path": [33764],
                    "warnings": [
                        "Intermediate ICMP loss detected; downstream hosts respond normally"
                    ],
                },
            },
            "error": None,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.run_probe", return_value=fake),
        ):
            status, _, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/mtr/196.216.2.1",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        text = _with_static(body)
        self.assertIn("New lookup", text)
        self.assertIn("python-udp", text)
        self.assertIn("Route summary", text)
        self.assertIn("AS33764", text)
        self.assertIn("data-asn", text)
        self.assertIn("data-ip", text)
        self.assertIn("196.216.2.1", text)
        self.assertIn("10.64.10.169", text)
        self.assertIn("inspect-pop-bar", text)
        self.assertIn("RFC1918", text)
        self.assertIn("Private/internal network address", text)
        self.assertNotIn("Private LAN", text)
        self.assertIn("Path (GeoIP)", text)
        self.assertIn("Path (hostname)", text)
        self.assertIn("Los Angeles", text)
        self.assertIn("Sydney", text)
        self.assertIn("63.218.9.241", text)
        self.assertIn("PCCW Global", text)
        self.assertIn("Intermediate ICMP loss", text)
        self.assertIn("Destination reached", text)
        self.assertIn("paintInspect", text)
        self.assertIn("report-payload", text)

    def test_html_dnssec_renders_break(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "name": "example.com.",
                "apex": "example.com.",
                "status": "bogus",
                "broken": True,
                "broken_at": "example.com.",
                "broken_reason": "Parent DS does not match any child DNSKEY digest.",
                "issue": {
                    "code": "ds_mismatch",
                    "severity": "error",
                    "title": "Chain breaks at example.com.",
                    "what": "Parent DS does not match any child DNSKEY digest.",
                    "effect": "Validating resolvers SERVFAIL this name.",
                    "fix": "Replace the DS or restore the matching DNSKEY.",
                    "rfc": "RFC 4035 §5.2",
                },
                "chain": [
                    {
                        "zone": ".",
                        "status": "secure",
                        "detail": "Root is good",
                        "dnskeys": [{"role": "KSK", "key_tag": 20326, "flags": 257, "algorithm_name": "RSASHA256"}],
                        "ds": [],
                    },
                    {
                        "zone": "example.com.",
                        "status": "bogus",
                        "detail": "digest mismatch",
                        "dnskeys": [],
                        "ds": [
                            {
                                "key_tag": 12345,
                                "algorithm_name": "RSASHA256",
                                "digest_name": "SHA-256",
                                "matches_dnskey": False,
                            }
                        ],
                        "issue": {
                            "code": "ds_mismatch",
                            "severity": "error",
                            "title": "Chain breaks at example.com.",
                            "what": "Parent DS does not match any child DNSKEY digest.",
                            "effect": "Validating resolvers SERVFAIL this name.",
                            "fix": "Replace the DS or restore the matching DNSKEY.",
                            "rfc": "RFC 4035 §5.2",
                        },
                        "graph": {
                            "groups": [
                                {
                                    "title": "DS at com.",
                                    "status": "bogus",
                                    "nodes": [
                                        {
                                            "kind": "ds",
                                            "label": "DS 12345",
                                            "sub": "RSASHA256 · SHA-256",
                                            "status": "bogus",
                                        }
                                    ],
                                    "link": {"status": "bogus", "label": "no matching digest"},
                                }
                            ]
                        },
                        "nameservers": [
                            {
                                "host": "ns1.example.com.",
                                "ip": "192.0.2.1",
                                "side": "child",
                                "ok": True,
                                "qtype": "DNSKEY",
                                "rcode": "NOERROR",
                                "aa": True,
                                "tags": [111, 222],
                                "rrsig": True,
                                "count": 2,
                                "ms": 12.0,
                            }
                        ],
                    },
                ],
                "leaf": {
                    "name": "example.com.",
                    "type": "A",
                    "status": "bogus",
                    "detail": "no RRSIG",
                },
                "standards": [{"rfc": 4035, "title": "Protocol", "why": "auth", "url": "https://www.rfc-editor.org/rfc/rfc4035"}],
            },
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.check_dnssec", return_value=fake),
        ):
            status, _, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/dnssec/example.com",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        text = _with_static(body)
        self.assertIn("Chain breaks at", text)
        self.assertIn("example.com.", text)
        self.assertIn("no matching DNSKEY", text)
        self.assertIn("What resolvers do", text)
        self.assertIn("no matching digest", text)
        self.assertIn("ns1.example.com.", text)
        self.assertIn("SERVFAIL", text)
        self.assertIn("paintInspect", text)
        self.assertIn("report-payload", text)
        self.assertIn("dnskey_rrsig", text)
        self.assertIn("RRSIGs over DNSKEY", text)

    def test_html_dnssec_leaf_rrsig_valid_is_not_secure(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "name": "dnssec-failed.org.",
                "apex": "dnssec-failed.org.",
                "status": "bogus",
                "secure": False,
                "broken": True,
                "broken_at": "dnssec-failed.org.",
                "broken_reason": "Parent DS does not match any child DNSKEY digest.",
                "chain": [
                    {
                        "zone": "dnssec-failed.org.",
                        "status": "bogus",
                        "detail": "digest mismatch",
                        "dnskeys": [],
                        "ds": [],
                    },
                ],
                "leaf": {
                    "name": "dnssec-failed.org.",
                    "type": "A",
                    "status": "rrsig_valid",
                    "rrsig": "valid",
                    "authenticated": False,
                    "chain_secure": False,
                    "detail": (
                        "The A RRset signature validates against the zone DNSKEY, but "
                        "the DNSKEY is not authenticated because the parent DS does not match."
                    ),
                },
                "standards": [],
            },
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.check_dnssec", return_value=fake),
        ):
            status, _, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/dnssec/dnssec-failed.org",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        text = _with_static(body)
        self.assertIn("rrsig_valid", text)
        self.assertIn("not authenticated", text)
        self.assertIn('"authenticated": false', text)
        self.assertIn("Authenticated", text)
        self.assertNotRegex(
            text,
            r'<span class="apex-status">secure</span>',
        )

    def test_html_dnssec_renders_unsigned_not_break(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "name": "google.com.",
                "apex": "google.com.",
                "status": "insecure",
                "broken": False,
                "broken_at": None,
                "broken_reason": None,
                "chain": [
                    {
                        "zone": ".",
                        "status": "secure",
                        "detail": "Root is good",
                        "dnskeys": [],
                        "ds": [],
                    },
                    {
                        "zone": "google.com.",
                        "status": "insecure",
                        "detail": "Parent com. has no DS for this zone (NOERROR) — insecure delegation, not a break.",
                        "dnskeys": [],
                        "ds": [],
                    },
                ],
                "leaf": {
                    "name": "google.com.",
                    "type": "A",
                    "status": "insecure",
                    "detail": "Apex is unsigned, so this RRset is not authenticated.",
                },
                "standards": [],
            },
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.check_dnssec", return_value=fake),
        ):
            status, _, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/dnssec/google.com",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        text = _with_static(body)
        self.assertIn("unsigned", text)
        self.assertIn("not a break", text)
        self.assertNotIn("Chain breaks at", text)
        self.assertIn("tab-cli", text)
        self.assertIn("http://lg.example.com/dnssec/google.com", text)
        self.assertIn("panel-cli", text)

    def test_html_rdap_renders_entities(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "query": "1.1.1.1",
                "type": "ip",
                "name": "CLOUDFLARENET",
                "handle": "NET-1",
                "country": "US",
                "status": ["active"],
                "entities": [
                    {"name": "Abuse", "roles": ["abuse"], "email": "abuse@cloudflare.com"}
                ],
                "events": [{"action": "last changed", "date": "2024-01-01"}],
                "cidr": ["1.1.1.0/24"],
            },
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.lookup_rdap", return_value=fake),
        ):
            status, _, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/rdap/1.1.1.1",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        text = _with_static(body)
        self.assertIn("CLOUDFLARENET", text)
        self.assertIn("abuse@cloudflare.com", text)
        self.assertIn("1.1.1.0/24", text)

    def test_json_tcptraceroute_path(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "target": "1.1.1.1",
                "ip": "1.1.1.1",
                "port": 443,
                "probe": "tcp",
                "reached": True,
                "hops": [],
            },
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.run_probe", return_value=fake) as run,
        ):
            status, _, body = _wsgi_get(
                app, remote="127.0.0.1", path="/tcptraceroute/1.1.1.1/443"
            )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "tcptraceroute")
        self.assertEqual(payload["query"], "1.1.1.1")
        run.assert_called_once_with("tcptraceroute", "1.1.1.1", port=443)

    def test_asgi_mtr_path(self):
        fake = {
            "ok": True,
            "result": {
                "target": "1.1.1.1",
                "ip": "1.1.1.1",
                "family": "IPv4",
                "cycles": 5,
                "reached": True,
                "hops": [],
                "via": "python-icmp",
            },
            "error": None,
        }
        app = self._demo_app("asgi")
        with (
            patch(
                "looking_glass.intel_server.client.lookup_ip_async",
                new=AsyncMock(return_value=_ctx(ip="127.0.0.1")),
            ),
            patch(
                "looking_glass.http.site.run_probe_async",
                new=AsyncMock(return_value=fake),
            ) as run,
        ):
            status, _, body = _asgi_get(app, peer="127.0.0.1", path="/mtr/1.1.1.1")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["kind"], "mtr")
        run.assert_awaited()

    def test_html_apex_renders_report(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "domain": "example.com",
                "parent": "com",
                "summary": {"pass": 1, "warn": 0, "fail": 0, "info": 0, "total": 1},
                "sections": [
                    {
                        "id": "parent",
                        "title": "Parent",
                        "checks": [
                            {
                                "id": "parent_glue",
                                "title": "DNS Parent sent Glue",
                                "status": "pass",
                                "detail": "Good. The parent sent glue.",
                                "rfcs": [
                                    {
                                        "rfc": 1912,
                                        "section": "2.3",
                                        "title": "Common DNS Operational and Configuration Errors",
                                        "url": "https://www.rfc-editor.org/rfc/rfc1912",
                                    }
                                ],
                                "data": {},
                            }
                        ],
                    }
                ],
                "standards": [
                    {
                        "rfc": 1912,
                        "title": "Common DNS Operational and Configuration Errors",
                        "why": "Glue",
                        "url": "https://www.rfc-editor.org/rfc/rfc1912",
                        "sections": ["2.3"],
                    }
                ],
            },
            "error": None,
            "total_ms": 9.1,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.check_apex", return_value=fake),
        ):
            status, headers, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/apex/example.com",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        text = _with_static(body)
        self.assertIn("Apex report", text)
        self.assertIn("example.com", text)
        self.assertIn("DNS Parent sent Glue", text)
        self.assertIn("1912", text)
        self.assertIn("RFC ${", text)
        self.assertIn("http://lg.example.com/apex/example.com", text)
        self.assertNotIn("/dns/example.com", text)
        self.assertIn("paintInspect", text)
        self.assertIn("report-payload", text)

    def test_asgi_apex_path(self):
        fake = {
            "ok": True,
            "result": {
                "domain": "example.com",
                "parent": "com",
                "summary": {"pass": 0, "warn": 0, "fail": 0, "info": 0, "total": 0},
                "sections": [],
                "standards": [],
            },
            "error": None,
        }
        app = self._demo_app("asgi")
        with (
            patch(
                "looking_glass.intel_server.client.lookup_ip_async",
                new=AsyncMock(return_value=_ctx(ip="127.0.0.1")),
            ),
            patch(
                "looking_glass.http.site.check_apex_async",
                new=AsyncMock(return_value=fake),
            ) as check,
        ):
            status, _, body = _asgi_get(
                app, peer="127.0.0.1", path="/apex/example.com"
            )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["kind"], "apex")
        self.assertEqual(payload["query"], "example.com")
        check.assert_awaited()

    def test_html_index_is_a_gui(self):
        app = self._demo_app("wsgi")
        with (
            patch(
                "looking_glass.http.site.dns_type_choices",
                return_value=[
                    {"name": "A", "value": 1, "meaning": "a host address", "common": True},
                    {"name": "AAAA", "value": 28, "meaning": "IP6 Address", "common": True},
                    {"name": "TYPE99", "value": 99, "meaning": "private", "common": False},
                ],
            ),
            patch("looking_glass.cache.gui_enabled", return_value=False),
        ):
            status, headers, body = _wsgi_get(
                app,
                remote="1.1.1.1",
                accept="text/html,application/xhtml+xml",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        raw = body.decode("utf-8")
        self.assertIn("/static/gui.css", raw)
        self.assertIn("/static/gui.js", raw)
        self.assertIn("/static/index.js", raw)
        self.assertNotIn("/static/admin.js", raw)
        self.assertNotIn("if (window.lookingGlassWindows) return", raw)
        text = _with_static(body)
        self.assertIn("form-ip", text)
        self.assertIn("form-asn", text)
        self.assertIn("form-dns", text)
        self.assertIn('name="server"', text)
        self.assertIn("resolv.conf", text)
        self.assertIn('name="port"', text)
        self.assertIn("function renderDns", text)
        self.assertIn("img.looking-glass-flag", text)
        self.assertIn("max-height: 1.2em", text)
        self.assertIn("form-bar", text)
        self.assertIn("openLookup", text)
        self.assertIn("paintHowto", text)
        self.assertIn("function howtoPath", text)
        self.assertIn("/http?url=", text)
        self.assertIn('replace(/%2F/gi, "/")', text)
        self.assertNotIn("reset-result", text)
        self.assertNotIn('id="result-box"', text)
        self.assertIn("GET /&lt;ip&gt;", text)
        self.assertIn("GET /AS&lt;number&gt;", text)
        self.assertIn("form-apex", text)
        self.assertIn("form-register", text)
        self.assertIn("form-dnssec", text)
        self.assertIn("form-tls", text)
        self.assertIn('name="sni"', text)
        self.assertIn('if (kind === "tls") return renderTls(payload)', text)
        self.assertNotIn('if (kind === "tls" && result) return renderTls(payload)', text)
        self.assertIn("openTool(meta.kind, meta.target, undefined, meta.extras)", text)
        self.assertIn("function paintHttps", text)
        self.assertIn("status.https.up", text)
        self.assertNotIn("status-serve-btn", text)
        self.assertIn("form-rdap", text)
        self.assertIn('id="rdap-route"', text)
        self.assertIn("syncRdapRoute", text)
        self.assertIn("RDAP (HTTPS JSON)", text)
        self.assertIn("Legacy WHOIS (port 43)", text)
        self.assertIn("function printableError", text)
        self.assertIn("form-ping", text)
        self.assertIn("form-traceroute", text)
        self.assertIn("form-mtr", text)
        self.assertIn('name="cycles"', text)
        self.assertNotIn("erso-wall", text)
        self.assertNotIn("looking-glass serve start", text)
        self.assertIn('id="mtr-route"', text)
        self.assertIn("form-tcptraceroute", text)
        self.assertIn("tcptraceroute", text)
        self.assertIn("form-rep", text)
        self.assertIn("form-bgp", text)
        self.assertIn("form-dnstrace", text)
        self.assertIn("form-ptr", text)
        self.assertIn("form-http", text)
        self.assertIn("form-mail", text)
        self.assertIn("form-tcp", text)
        self.assertIn("form-pmtu", text)
        self.assertNotIn("cancel-result", text)
        self.assertIn("looking-glass", text)
        self.assertIn("tool-nav", text)
        self.assertIn('role="tablist"', text)
        self.assertIn("lg.example.com", text)
        self.assertNotIn("Look up IPs, ASNs, countries", text)
        self.assertIn("howto-", text)
        self.assertIn("term-bar", text)
        self.assertIn("Double-click a command to copy", text)
        self.assertNotIn("This lookup from the command line", text)
        self.assertNotIn("copy-cli", text)
        self.assertNotIn("copyOnDoubleClick", text)
        self.assertNotIn("<i></i><i></i><i></i>", text)
        self.assertIn('addEventListener("dblclick"', text)
        self.assertIn("hist-action", text)
        self.assertIn("gui.history.copy", text)
        self.assertIn("gui.history.open", text)
        self.assertIn("bindHistPermalink", text)
        self.assertIn("openHistInWindow", text)
        self.assertIn("openLookupPayload", text)
        self.assertNotIn('window.open(url, "_blank"', text)
        self.assertIn('dataset.copyBound', text)
        self.assertNotIn('querySelectorAll("p.route code")', text)
        self.assertIn('scheme === "http"', text)
        self.assertNotIn('parts.slice(1).join("/")].filter(Boolean).join(" ")', text)
        self.assertNotIn("if (window.el) return window.el", text)
        self.assertIn("const el = window.el", text)
        self.assertIn("window.el = el", text)
        self.assertIn("2001:db8::1", text)
        self.assertIn("1.1.1.1, 2001:db8::1, or example.com", text)
        self.assertIn("tool-nav", text)
        self.assertIn("tool-group", text)
        self.assertNotIn("tool-menu-btn", text)
        self.assertNotIn("Current tool", text)
        self.assertIn("inspect-pop-bar", text)
        self.assertIn("inspect-tool-list", text)
        self.assertIn('id="status-login"', text)
        self.assertIn("gui.wall.note", text)
        self.assertNotIn('id="status-windows"', text)
        self.assertNotIn("minimizeAll", text)
        self.assertNotIn("restoreAll", text)
        self.assertIn("unwrapPayload", text)
        self.assertIn("lockPopSize(pop, { width: false })", text)
        self.assertIn("max-content", text)
        self.assertIn(".sec-graph", text)
        self.assertNotIn("status.windows.min", text)
        self.assertNotIn('id="status-logs"', text)
        self.assertNotIn('id="status-services"', text)
        self.assertNotIn('id="cache-btn"', text)
        self.assertNotIn('id="status-logout"', text)
        self.assertNotIn('id="history-rail"', text)
        self.assertNotIn('id="status-history"', text)
        self.assertNotIn('id="status-wall"', text)
        self.assertNotIn("rdap-cache-btn", text)
        self.assertIn("trace-hops", text)
        self.assertIn("inspect-pop-bar", text)
        self.assertIn("inspect-tool-list", text)
        self.assertIn("Looking up WHOIS", text)
        self.assertIn("Pinging", text)
        self.assertIn("openInspect", text)
        self.assertIn("toolsFor", text)
        self.assertIn("paintInspect", text)
        self.assertIn("data-ip", text)
        self.assertIn("data-domain", text)
        self.assertIn('"name": "A"', text)
        self.assertIn('"name": "AAAA"', text)
        self.assertNotIn('"name": "ANY"', text)
        self.assertIn('id="status-bar"', text)
        self.assertIn('id="status-ip"', text)
        self.assertIn('id="status-time"', text)
        self.assertIn('id="status-uptime"', text)
        self.assertIn('id="status-docs"', text)
        self.assertIn('id="status-locale"', text)
        self.assertIn('href="/docs"', text)
        self.assertNotIn('id="status-docs" href="/docs" target="_blank"', text)
        self.assertIn('docs-page', text)
        self.assertIn('window.t("status.exit")', text)
        self.assertIn('fetch("/status"', text)
        self.assertIn("data.ipv4", text)
        self.assertIn("data.ipv6", text)
        self.assertNotIn("focuses the current tool", text)
        self.assertIn("not_before", text)
        self.assertIn("dnskey_rrsigs", text)
        self.assertIn("sender_score", text)
        self.assertIn("r.origins", text)
        self.assertIn("decorateReport", text)
        self.assertIn("probe-observed", text)
        self.assertIn("inspect.diff.vs_previous", text)
        self.assertIn("inspect.tcp.status.refused", text)
        self.assertIn("result-history", text)
        self.assertIn("openHistoryCompare", text)
        self.assertIn(".asn-pop.compare-pop", text)
        self.assertIn("96rem", text)
        self.assertIn("paintHistoryBar", text)
        self.assertIn("bindHistPermalink", text)
        self.assertIn("hist-action", text)
        self.assertIn("openHistInWindow", text)
        self.assertIn("openLookupPayload", text)
        self.assertNotIn('window.open(url, "_blank"', text)
        self.assertIn('addEventListener("dblclick"', text)
        self.assertNotIn('link.target = "_blank"', text)

    def test_html_index_shows_cache_gui_when_logged_in(self):
        app = self._demo_app("wsgi")
        with (
            patch(
                "looking_glass.http.site.dns_type_choices",
                return_value=[{"name": "A", "value": 1, "meaning": "a host address", "common": True}],
            ),
            patch("looking_glass.http.admin.current_user", return_value="alice"),
        ):
            status, _, body = _wsgi_get(
                app,
                remote="1.1.1.1",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        raw = body.decode("utf-8")
        self.assertIn("/static/admin.js", raw)
        text = _with_static(body)
        self.assertIn('id="cache-btn"', text)
        self.assertIn('id="status-logs"', text)
        self.assertIn('id="status-services"', text)
        self.assertNotIn('id="status-https"', text)
        self.assertNotIn("status-serve-btn", text)
        self.assertIn('id="status-wins"', text)
        self.assertIn("status-win-stack", text)
        self.assertIn("inspect-pop-min", text)
        self.assertIn("inspect-pop-refresh", text)
        self.assertIn("onRefresh: loadCache", text)
        self.assertIn("onRefresh: loadHistory", text)
        self.assertIn("onRefresh: loadTab", text)
        self.assertIn("onRefresh: loadServices", text)
        self.assertIn('register("services"', text)
        self.assertIn("services-pop", text)
        self.assertIn("function formatDn", text)
        self.assertIn("formatDn(https.subject)", text)
        self.assertIn("gui.services.system", text)
        self.assertIn("gui.services.service", text)
        self.assertRegex(text, r"\.services-host\s*\{[^}]*text-align:\s*center")
        self.assertIn('id="status-services">services', text)
        self.assertIn('register("wall"', text)
        self.assertIn('cache: "no-store"', text)
        self.assertIn("document.body.contains", text)
        self.assertIn("status-win-max", text)
        self.assertIn("status-win-close", text)
        self.assertIn("lookingGlassWindows", text)
        self.assertIn("lookingGlassWindows.place", text)
        self.assertIn("lookingGlassWindows.fit", text)
        self.assertIn("nudge(node)", text)
        self.assertIn("function placePop", text)
        self.assertIn("inspect-pop-bar", text)
        self.assertIn("cache-pop", text)
        self.assertNotIn('id="cache-layer"', text)
        self.assertNotIn('id="history-rail"', text)
        self.assertIn('id="status-history"', text)
        self.assertIn('id="status-history">history', text)
        self.assertIn('id="cache-btn">cache', text)
        self.assertNotIn('id="status-windows"', text)
        self.assertIn("status.history", text)
        self.assertIn("status.cache", text)
        self.assertIn('id="status-wall"', text)
        self.assertIn("/wall/traffic", text)
        self.assertIn("/wall/challenge", text)
        self.assertIn("wall-tree", text)
        self.assertIn("gui.wall.issued", text)
        self.assertIn("gui.wall.note", text)
        self.assertIn("gui.wall.added", text)
        self.assertIn("gui.logs.challenge", text)
        self.assertIn("gui.logs.peak", text)
        self.assertIn("sortHistRows", text)
        self.assertIn("gui.wall.ipv4", text)
        self.assertIn("gui.wall.cidr", text)
        self.assertIn("gui.wall.confirm_block", text)
        self.assertIn("wall-menu", text)
        self.assertIn("openWallMenu", text)
        self.assertIn('toolsFor("ip")', text)
        self.assertIn("window.openTool", text)
        self.assertIn("listedCidr", text)
        self.assertIn("gui.wall.lookup", text)
        self.assertIn("gui.wall.search", text)
        self.assertIn("sortWallRows", text)
        self.assertIn("wallQuery", text)
        self.assertIn("gui.wall.method", text)
        self.assertIn("sortCacheRows", text)
        self.assertIn("gui.cache.query", text)
        self.assertIn('el("table", "log-table")', text)
        self.assertIn("fmtStamp(row.ts)", text)
        self.assertIn("country_catalog", text)
        self.assertIn("history-pop", text)
        self.assertIn("hist-link", text)
        self.assertIn("hist-query", text)
        self.assertIn("hist-who", text)
        self.assertIn("hist-visitor", text)
        self.assertIn("hist-intel", text)
        self.assertIn("gui.history.search", text)
        self.assertIn("copyHistUrl", text)
        self.assertNotIn("hist-info", text)
        self.assertIn("gui.history.guest", text)
        self.assertIn('id="status-logout"', text)
        self.assertNotIn('id="status-login"', text)
        self.assertNotIn("RDAP cache", text)

    def test_html_index_uses_request_host(self):
        app = self._demo_app("wsgi")
        with (
            patch(
                "looking_glass.http.site.dns_type_choices",
                return_value=[
                    {"name": "A", "value": 1, "meaning": "a host address", "common": True},
                ],
            ),
            patch("looking_glass.cache.gui_enabled", return_value=False),
        ):
            status, headers, body = _wsgi_get(
                app,
                remote="1.1.1.1",
                accept="text/html",
                host="lookup.example.net",
            )
        self.assertEqual(status, 200)
        text = _with_static(body)
        self.assertIn("lookup.example.net", text)
        self.assertIn('<h1><a href="/">lookup.example.net</a></h1>', text)

    def test_html_index_does_not_run_lookup(self):
        app = self._demo_app("wsgi")
        with (
            patch("looking_glass.http.site.lookup_classified") as classified,
            patch("looking_glass.cache.gui_enabled", return_value=False),
        ):
            status, headers, _body = _wsgi_get(
                app, remote="1.1.1.1", accept="text/html", host="lg.example.com"
            )
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        classified.assert_not_called()

    def test_dns_type_choices_puts_common_first(self):
        from looking_glass.http.site import dns_type_choices

        rows = [
            {"name": "TYPE99", "value": 99, "meaning": "private"},
            {"name": "A", "value": 1, "meaning": "a host address"},
            {"name": "TXT", "value": 16, "meaning": "text strings"},
        ]
        with patch("looking_glass.dns.resolve.types", return_value=rows):
            out = dns_type_choices()
        self.assertEqual([row["name"] for row in out], ["A", "TXT", "TYPE99"])
        self.assertEqual([row["common"] for row in out], [True, True, False])

    def test_html_result_page_still_renders_query(self):
        app = self._demo_app("wsgi")
        fake = {"ok": True, "ip": "1.1.1.1", "result": {"asn": 13335}}
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.lookup_classified", return_value=fake),
        ):
            status, headers, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/1.1.1.1",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        text = _with_static(body)
        self.assertIn("1.1.1.1", text)
        self.assertIn("New lookup", text)
        self.assertNotIn("IP, ASN, country, DNS, reputation, Apex, ping, traceroute, and MTR.", text)
        self.assertIn("tab-curl", text)
        self.assertIn("tab-cli", text)
        self.assertIn("http://lg.example.com/1.1.1.1", text)
        self.assertNotIn("/dns/example.com", text)
        self.assertIn("white-space: pre-wrap", text)

    def test_html_dnstrace_renders_hops_not_raw_json(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "name": "cpanel.net.",
                "qtype": "A",
                "hops": [
                    {
                        "zone": ".",
                        "server": "198.41.0.4",
                        "rcode": "NOERROR",
                        "error": None,
                        "answers": [],
                        "authority": [{"type": "NS", "data": "a.gtld-servers.net."}],
                    },
                    {
                        "zone": "net.",
                        "server": "192.55.83.30",
                        "rcode": "NOERROR",
                        "error": None,
                        "answers": [],
                        "authority": [{"type": "NS", "data": "c.cpanel.net."}],
                    },
                ],
                "error": None,
            },
            "error": None,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.trace_dns", return_value=fake),
        ):
            status, headers, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/dnstrace/cpanel.net",
                accept="text/html",
                host="lg.example.com",
            )
            json_status, json_headers, json_body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/dnstrace/cpanel.net",
                accept="application/json",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        text = _with_static(body)
        self.assertIn("DNS trace", text)
        self.assertIn("cpanel.net", text)
        self.assertIn("trace-hops", text)
        self.assertIn("a.gtld-servers.net.", text)
        self.assertNotIn('<pre class="result">', text)
        self.assertIn("paintInspect", text)
        self.assertIn("report-payload", text)
        self.assertEqual(json_status, 200)
        self.assertTrue(json_headers["Content-Type"].startswith("application/json"))
        payload = json.loads(json_body)
        self.assertEqual(payload["kind"], "dnstrace")
        self.assertEqual(payload["result"]["name"], "cpanel.net.")

    def test_html_http_inspect_renders_status(self):
        app = self._demo_app("wsgi")
        fake = {
            "ok": True,
            "result": {
                "query": "example.com",
                "final_url": "https://example.com/",
                "status": 200,
                "http_version": "HTTP/1.1",
                "alpn": "http/1.1",
                "ttfb_ms": 12.0,
                "redirects": 0,
                "hsts": None,
                "chain": [
                    {
                        "status": 200,
                        "reason": "OK",
                        "url": "https://example.com/",
                        "ttfb_ms": 12.0,
                        "http_version": "HTTP/1.1",
                        "server": "ECS",
                        "headers": {"content-type": "text/html"},
                    }
                ],
            },
            "error": None,
        }
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.inspect_http", return_value=fake),
        ):
            status, headers, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/http/example.com",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        text = _with_static(body)
        self.assertIn("HTTP", text)
        self.assertIn("example.com", text)
        self.assertNotIn('<pre class="result">', text)
        self.assertIn("paintInspect", text)
        self.assertIn("report-payload", text)
        self.assertIn("term-bar", text)
        self.assertNotIn("copyOnDoubleClick", text)

    def test_html_http_inspect_protocol_error_is_200(self):
        app = self._demo_app("wsgi")
        fake = {"ok": False, "result": None, "error": "http2_handshake_failed"}
        with (
            patch("looking_glass.intel_server.client.lookup_ip", return_value=_ctx(ip="127.0.0.1")),
            patch("looking_glass.http.site.inspect_http", return_value=fake),
        ):
            json_status, json_headers, json_body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/http/example.com",
                accept="application/json",
                host="lg.example.com",
            )
            html_status, _, html_body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/http/example.com",
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(json_status, 200)
        self.assertTrue(json_headers["Content-Type"].startswith("application/json"))
        payload = json.loads(json_body)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "http2_handshake_failed")
        self.assertNotIn("\x00", json_body.decode("utf-8"))
        self.assertEqual(html_status, 200)
        text = _with_static(html_body)
        self.assertIn("http2_handshake_failed", text)
        self.assertIn("printableError", text)

    def test_template_override_in_home_dir(self):
        app = self._demo_app("wsgi")
        with tempfile.TemporaryDirectory() as tmp:
            override = os.path.join(tmp, "templates")
            os.makedirs(override)
            with open(os.path.join(override, "index.html"), "w", encoding="utf-8") as fh:
                fh.write("<html>overridden {{ visitor }}</html>")
            with (
                patch("looking_glass.http.render.get_root", return_value=tmp),
                patch("looking_glass.cache.gui_enabled", return_value=False),
            ):
                status, headers, body = _wsgi_get(
                    app,
                    remote="1.1.1.1",
                    accept="text/html",
                    host="lg.example.com",
                )
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("text/html"))
        self.assertEqual(body.decode("utf-8"), "<html>overridden 1.1.1.1</html>")

    def test_status_json_wsgi(self):
        app = self._demo_app("wsgi")
        with (
            patch("looking_glass.http.site._status_hostname", return_value="box.example"),
            patch(
                "looking_glass.http.site._status_addrs",
                return_value={"ipv4": "192.0.2.10", "ipv6": None},
            ),
            patch("looking_glass.http.site._status_uptime", return_value=93784.0),
            patch("looking_glass.http.site.os.getloadavg", return_value=(0.12, 0.34, 0.56)),
            patch(
                "looking_glass.http.site._status_clock",
                return_value={"time_epoch": 1756067372.0, "utc_offset": -14400, "tz": "EDT"},
            ),
        ):
            status, headers, body = _wsgi_get(
                app,
                remote="127.0.0.1",
                path="/status",
                accept="text/html",
            )
        self.assertEqual(status, 200)
        self.assertTrue(headers["Content-Type"].startswith("application/json"))
        self.assertEqual(headers.get("Cache-Control"), "no-store")
        payload = json.loads(body)
        self.assertEqual(payload["hostname"], "box.example")
        self.assertEqual(payload["ip"], "192.0.2.10")
        self.assertEqual(payload["ipv4"], "192.0.2.10")
        self.assertIsNone(payload["ipv6"])
        self.assertEqual(payload["uptime"], 93784.0)
        self.assertEqual(payload["load"], [0.12, 0.34, 0.56])
        self.assertEqual(payload["mode"], "wsgi")
        self.assertEqual(payload["time_epoch"], 1756067372.0)
        self.assertEqual(payload["utc_offset"], -14400)
        self.assertEqual(payload["tz"], "EDT")
        self.assertIsNone(payload.get("user"))

    def test_status_json_asgi(self):
        app = self._demo_app("asgi")
        with (
            patch("looking_glass.http.site._status_hostname", return_value="box.example"),
            patch(
                "looking_glass.http.site._status_addrs",
                return_value={"ipv4": "192.0.2.10", "ipv6": None},
            ),
            patch("looking_glass.http.site._status_uptime", return_value=93784.0),
            patch("looking_glass.http.site.os.getloadavg", return_value=(0.12, 0.34, 0.56)),
            patch(
                "looking_glass.http.site._status_clock",
                return_value={"time_epoch": 1756067372.0, "utc_offset": -14400, "tz": "EDT"},
            ),
        ):
            status, headers, body = _asgi_get(
                app,
                peer="127.0.0.1",
                path="/status",
            )
        self.assertEqual(status, 200)
        self.assertTrue(headers["content-type"].startswith("application/json"))
        self.assertEqual(headers.get("cache-control"), "no-store")
        payload = json.loads(body)
        self.assertEqual(payload["hostname"], "box.example")
        self.assertEqual(payload["ip"], "192.0.2.10")
        self.assertEqual(payload["ipv4"], "192.0.2.10")
        self.assertIsNone(payload["ipv6"])
        self.assertEqual(payload["uptime"], 93784.0)
        self.assertEqual(payload["load"], [0.12, 0.34, 0.56])
        self.assertEqual(payload["mode"], "asgi")
        self.assertEqual(payload["time_epoch"], 1756067372.0)
        self.assertEqual(payload["utc_offset"], -14400)
        self.assertEqual(payload["tz"], "EDT")
        self.assertIsNone(payload.get("user"))

    def test_status_json_dual_stack(self):
        app = self._demo_app("wsgi")
        with (
            patch("looking_glass.http.site._status_hostname", return_value="box.example"),
            patch(
                "looking_glass.http.site._status_addrs",
                return_value={"ipv4": "192.0.2.10", "ipv6": "2001:db8::1"},
            ),
            patch("looking_glass.http.site._status_uptime", return_value=1.0),
            patch("looking_glass.http.site.os.getloadavg", return_value=(0.0, 0.0, 0.0)),
            patch(
                "looking_glass.http.site._status_clock",
                return_value={"time_epoch": 1.0, "utc_offset": 0, "tz": "UTC"},
            ),
        ):
            status, _, body = _wsgi_get(app, remote="127.0.0.1", path="/status")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["ip"], "192.0.2.10")
        self.assertEqual(payload["ipv4"], "192.0.2.10")
        self.assertEqual(payload["ipv6"], "2001:db8::1")

    def test_status_json_ipv6_only(self):
        app = self._demo_app("wsgi")
        with (
            patch("looking_glass.http.site._status_hostname", return_value="box.example"),
            patch(
                "looking_glass.http.site._status_addrs",
                return_value={"ipv4": None, "ipv6": "2001:db8::9"},
            ),
            patch("looking_glass.http.site._status_uptime", return_value=1.0),
            patch("looking_glass.http.site.os.getloadavg", return_value=(0.0, 0.0, 0.0)),
            patch(
                "looking_glass.http.site._status_clock",
                return_value={"time_epoch": 1.0, "utc_offset": 0, "tz": "UTC"},
            ),
        ):
            status, _, body = _wsgi_get(app, remote="127.0.0.1", path="/status")
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertEqual(payload["ip"], "2001:db8::9")
        self.assertIsNone(payload["ipv4"])
        self.assertEqual(payload["ipv6"], "2001:db8::9")

    def test_status_clock_compact_tz(self):
        from datetime import datetime, timedelta, timezone

        from looking_glass.http import site as http_site

        edt = timezone(timedelta(hours=-4), "EDT")
        now = datetime(2026, 8, 24, 17, 49, 32, tzinfo=edt)
        clock = http_site._status_clock(now)
        self.assertEqual(clock["utc_offset"], -14400)
        self.assertEqual(clock["tz"], "EDT")
        self.assertEqual(clock["time_epoch"], now.timestamp())

    def test_status_hostname_prefers_fqdn(self):
        from looking_glass.http import site as http_site

        with (
            patch("looking_glass.http.site.socket.getfqdn", return_value="al.home.arpa"),
            patch("looking_glass.http.site.socket.gethostname", return_value="al"),
            patch("looking_glass.observe.socket.getfqdn", return_value="al.home.arpa"),
            patch("looking_glass.observe.socket.gethostname", return_value="al"),
        ):
            self.assertEqual(http_site._status_hostname(), "al.home.arpa")

    def test_rdap_cache_http(self):
        app = self._demo_app("wsgi")
        with tempfile.TemporaryDirectory() as tmp:
            directory = os.path.join(tmp, "cache", "rdap")
            os.makedirs(directory)
            path = os.path.join(directory, "autnum_13335.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"_cached_at": 1, "data": {"handle": "AS13335"}}, handle)
            with (
                patch("looking_glass.cache.get_cache_path", side_effect=lambda name: os.path.join(tmp, name)),
                patch("looking_glass.http.admin.current_user", return_value="alice"),
                patch("looking_glass.auth.history.append", return_value=None),
            ):
                status, headers, body = _wsgi_get(
                    app,
                    path="/cache/rdap",
                    accept="application/json",
                )
                self.assertEqual(status, 200)
                payload = json.loads(body)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["count"], 1)
                self.assertEqual(payload["ttl_days"], 7)
                self.assertEqual(payload["files"][0]["query"], "13335")
                status, _, body = _wsgi_get(
                    app,
                    path="/cache/rdap/autnum_13335.json",
                    accept="application/json",
                    method="DELETE",
                )
                self.assertEqual(status, 200)
                payload = json.loads(body)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["count"], 0)
                self.assertFalse(os.path.exists(path))

    def test_cache_http_lists_and_clears_bgp(self):
        app = self._demo_app("wsgi")
        with tempfile.TemporaryDirectory() as tmp:
            directory = os.path.join(tmp, "cache", "bgp")
            os.makedirs(directory)
            path = os.path.join(directory, "1.1.1.1.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"_cached_at": 1, "data": {"query": "1.1.1.1"}}, handle)
            with (
                patch("looking_glass.cache.get_cache_path", side_effect=lambda name: os.path.join(tmp, name)),
                patch("looking_glass.http.admin.current_user", return_value="alice"),
                patch("looking_glass.auth.history.append", return_value=None),
            ):
                status, _, body = _wsgi_get(
                    app,
                    path="/cache",
                    accept="application/json",
                )
                self.assertEqual(status, 200)
                payload = json.loads(body)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["count"], 1)
                self.assertEqual(payload["files"][0]["namespace"], "bgp")
                status, _, body = _wsgi_get(
                    app,
                    path="/cache/bgp",
                    accept="application/json",
                )
                self.assertEqual(status, 200)
                payload = json.loads(body)
                self.assertEqual(payload["count"], 1)
                status, _, body = _wsgi_get(
                    app,
                    path="/cache/bgp/1.1.1.1.json",
                    accept="application/json",
                    method="DELETE",
                )
                self.assertEqual(status, 200)
                payload = json.loads(body)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["count"], 0)
                self.assertFalse(os.path.exists(path))

    def test_cache_http_clear_all(self):
        app = self._demo_app("wsgi")
        with tempfile.TemporaryDirectory() as tmp:
            rdap_dir = os.path.join(tmp, "cache", "rdap")
            bgp_dir = os.path.join(tmp, "cache", "bgp")
            os.makedirs(rdap_dir)
            os.makedirs(bgp_dir)
            rdap_path = os.path.join(rdap_dir, "ip_1.1.1.1.json")
            bgp_path = os.path.join(bgp_dir, "1.1.1.1.json")
            with open(rdap_path, "w", encoding="utf-8") as handle:
                json.dump({"_cached_at": 1, "data": {"handle": "NET"}}, handle)
            with open(bgp_path, "w", encoding="utf-8") as handle:
                json.dump({"_cached_at": 1, "data": {"query": "1.1.1.1"}}, handle)
            with (
                patch("looking_glass.cache.get_cache_path", side_effect=lambda name: os.path.join(tmp, name)),
                patch("looking_glass.http.admin.current_user", return_value="alice"),
                patch("looking_glass.auth.history.append", return_value=None),
            ):
                status, _, body = _wsgi_get(
                    app,
                    path="/cache",
                    accept="application/json",
                    method="DELETE",
                )
                self.assertEqual(status, 200)
                payload = json.loads(body)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["count"], 0)
                self.assertFalse(os.path.exists(rdap_path))
                self.assertFalse(os.path.exists(bgp_path))

    def test_cache_http_requires_login(self):
        app = self._demo_app("wsgi")
        with tempfile.TemporaryDirectory() as tmp:
            directory = os.path.join(tmp, "cache", "rdap")
            os.makedirs(directory)
            path = os.path.join(directory, "ip_1.1.1.1.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"_cached_at": 1, "data": {"handle": "NET"}}, handle)
            with (
                patch("looking_glass.cache.get_cache_path", side_effect=lambda name: os.path.join(tmp, name)),
            ):
                for route, method in (
                    ("/cache", "GET"),
                    ("/cache/rdap", "GET"),
                    ("/cache/rdap/ip_1.1.1.1.json", "DELETE"),
                ):
                    status, _, body = _wsgi_get(
                        app,
                        path=route,
                        accept="application/json",
                        method=method,
                    )
                    self.assertEqual(status, 401)
                    payload = json.loads(body)
                    self.assertFalse(payload["ok"])
                    self.assertNotIn("files", payload)
            self.assertTrue(os.path.exists(path))

