import json
import os
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass.auth import history as action_history
from looking_glass.auth import keys, password, session
from looking_glass.cli.entry import cli
from looking_glass.http.site import respond
from looking_glass.http.wsgi import app as wsgi_app
from tests.test_wall import _wsgi_get, _with_static


def _roots(tmp: str):
    return (
        patch("looking_glass.config.get_root", return_value=tmp),
        patch("looking_glass.utility.get_root", return_value=tmp),
    )


def _cookie(token: str) -> str:
    return f"looking_glass_session={token}"


class AuthCoreTests(unittest.TestCase):
    def test_unset_password_is_not_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                status, _, body, extra = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/login",
                    {},
                    method="POST",
                    body=b'{"password":"secret"}',
                )
                self.assertEqual(status, 401)
                self.assertFalse(json.loads(body)["ok"])
                self.assertFalse(any(name.lower() == "set-cookie" for name, _ in extra))
                denied, _, raw, _ = respond(
                    "wsgi", "127.0.0.1", "/config", {}, accept="application/json"
                )
                self.assertEqual(denied, 401)
                self.assertFalse(json.loads(raw)["ok"])

    def test_password_login_and_wrong_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                password.set_password("secret")
                bad, _, body, extra = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/login",
                    {},
                    method="POST",
                    body=b'{"password":"nope"}',
                )
                self.assertEqual(bad, 401)
                self.assertFalse(any(name.lower() == "set-cookie" for name, _ in extra))
                ok, _, raw, headers = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/login",
                    {},
                    method="POST",
                    body=b'{"password":"secret"}',
                )
                self.assertEqual(ok, 200)
                payload = json.loads(raw)
                self.assertTrue(payload["ok"])
                self.assertTrue(payload["admin"])
                self.assertEqual(payload["user"], "admin")
                cookie = dict(headers).get("Set-Cookie", "")
                self.assertIn("looking_glass_session=", cookie)
                token = cookie.split(";", 1)[0]
                stats, _, cache_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/cache",
                    {},
                    accept="application/json",
                    cookie=token,
                )
                self.assertEqual(stats, 200)
                self.assertTrue(json.loads(cache_body)["ok"])

    def test_bearer_key_and_revoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                created = keys.create("tokyo")
                secret = created["secret"]
                self.assertTrue(secret.startswith("lg_"))
                listed = keys.list_keys()
                self.assertEqual(len(listed), 1)
                self.assertNotIn("secret", listed[0])
                self.assertNotIn("hash", listed[0])
                ok, _, body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/config",
                    {},
                    accept="application/json",
                    authorization=f"Bearer {secret}",
                )
                self.assertEqual(ok, 200)
                self.assertTrue(json.loads(body)["ok"])
                self.assertNotIn("password_hash", json.loads(body))
                denied, _, raw, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/config",
                    {},
                    accept="application/json",
                    authorization="Bearer nope",
                )
                self.assertEqual(denied, 401)
                self.assertTrue(keys.revoke(created["id"]))
                gone, _, _, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/config",
                    {},
                    accept="application/json",
                    authorization=f"Bearer {secret}",
                )
                self.assertEqual(gone, 401)

    def test_cli_password_keys_sessions(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                listed = runner.invoke(cli, ["--json", "auth", "password"])
                self.assertEqual(listed.exit_code, 0, listed.output)
                self.assertFalse(json.loads(listed.output)["set"])
                set_out = runner.invoke(
                    cli, ["--json", "auth", "password", "set"], input="secret\nsecret\n"
                )
                self.assertEqual(set_out.exit_code, 0, set_out.output)
                self.assertTrue(json.loads(set_out.output)["set"])
                created = runner.invoke(cli, ["--json", "auth", "keys", "create", "probe"])
                self.assertEqual(created.exit_code, 0, created.output)
                payload = json.loads(created.output)
                self.assertIn("secret", payload)
                self.assertTrue(payload["secret"].startswith("lg_"))
                keys_out = runner.invoke(cli, ["--json", "auth", "keys"])
                self.assertEqual(json.loads(keys_out.output)["count"], 1)
                self.assertNotIn("secret", json.loads(keys_out.output)["keys"][0])
                revoked = runner.invoke(cli, ["--json", "auth", "keys", "revoke", payload["id"]])
                self.assertEqual(revoked.exit_code, 0, revoked.output)
                session.create()
                cleared = runner.invoke(cli, ["--json", "auth", "sessions", "clear"])
                self.assertEqual(cleared.exit_code, 0, cleared.output)
                self.assertEqual(json.loads(cleared.output)["removed"], 1)

    def test_cli_human_password_and_random(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                unset = runner.invoke(cli, ["auth", "password"])
                self.assertEqual(unset.exit_code, 0, unset.output)
                self.assertIn("password is not set (login disabled)", unset.output)
                self.assertNotIn("user(s)", unset.output)
                set_out = runner.invoke(
                    cli, ["auth", "password", "set"], input="secret\nsecret\n"
                )
                self.assertEqual(set_out.exit_code, 0, set_out.output)
                self.assertIn("password is set", set_out.output)
                self.assertNotIn("user(s)", set_out.output)
                random_json = runner.invoke(
                    cli, ["--json", "auth", "password", "set", "--random"]
                )
                self.assertEqual(random_json.exit_code, 0, random_json.output)
                payload = json.loads(random_json.output)
                self.assertTrue(payload["set"])
                secret = payload["password"]
                self.assertTrue(secret)
                self.assertTrue(password.verify(secret))
                random_human = runner.invoke(cli, ["auth", "password", "set", "--random"])
                self.assertEqual(random_human.exit_code, 0, random_human.output)
                self.assertIn("password is set", random_human.output)
                self.assertNotIn("user(s)", random_human.output)
                generated = [
                    line.strip()
                    for line in random_human.output.splitlines()
                    if line.strip() and line.strip() != "password is set"
                ]
                self.assertEqual(len(generated), 1)
                self.assertTrue(password.verify(generated[0]))
                created = runner.invoke(cli, ["auth", "keys", "create", "probe"])
                self.assertEqual(created.exit_code, 0, created.output)
                self.assertIn("lg_", created.output)
                self.assertNotIn("user(s)", created.output)
                listed = runner.invoke(cli, ["auth", "keys"])
                self.assertEqual(listed.exit_code, 0, listed.output)
                self.assertIn("key(s)", listed.output)
                self.assertNotIn("user(s)", listed.output)
                cleared = runner.invoke(cli, ["auth", "password", "clear"])
                self.assertEqual(cleared.exit_code, 0, cleared.output)
                self.assertIn("password is not set (login disabled)", cleared.output)

    def test_session_token_is_hex(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                token = session.create()
                self.assertRegex(token, r"^[0-9a-f]{64}$")
                self.assertEqual(session.user_from_cookie(_cookie(token)), "admin")
                self.assertEqual(len(token), 64)
                self.assertNotIn(".", token)
                self.assertIsNone(session.user_from_cookie("looking_glass_session=aaa.bbb.ccc"))

    def test_login_html_is_password_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                page, _, html, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/",
                    {},
                    accept="text/html",
                    host="lg.example.com",
                )
                self.assertEqual(page, 200)
                text = html.decode("utf-8")
                self.assertIn('name="password"', text)
                self.assertNotIn('name="user"', text)
                self.assertNotIn('name="username"', text)
                self.assertNotIn('id="status-user"', text)
                password.set_password("secret")
                _, _, _, extra = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/login",
                    {},
                    method="POST",
                    body=b'{"password":"secret"}',
                )
                cookie = dict(extra).get("Set-Cookie", "").split(";", 1)[0]
                authed, _, body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/",
                    {},
                    accept="text/html",
                    host="lg.example.com",
                    cookie=cookie,
                )
                self.assertEqual(authed, 200)
                signed = body.decode("utf-8")
                self.assertIn('id="status-auth-user"', signed)
                self.assertNotIn('id="status-user"', signed)
                self.assertNotIn('id="status-login"', signed)

    def test_http_key_crud(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                password.set_password("secret")
                _, _, _, extra = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/login",
                    {},
                    method="POST",
                    body=b'{"password":"secret"}',
                )
                cookie = dict(extra).get("Set-Cookie", "").split(";", 1)[0]
                created, _, raw, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/auth/keys",
                    {},
                    method="POST",
                    cookie=cookie,
                    body=b'{"name":"gui"}',
                )
                self.assertEqual(created, 200)
                payload = json.loads(raw)
                self.assertIn("secret", payload)
                listed, _, body, _ = respond(
                    "wsgi", "127.0.0.1", "/auth/keys", {}, cookie=cookie
                )
                self.assertEqual(listed, 200)
                data = json.loads(body)
                self.assertTrue(data["password_set"])
                self.assertEqual(data["count"], 1)
                self.assertNotIn("secret", data["keys"][0])
                gone, _, _, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    f"/auth/keys/{payload['id']}",
                    {},
                    method="DELETE",
                    cookie=cookie,
                )
                self.assertEqual(gone, 200)


class AuthHttpTests(unittest.TestCase):
    def test_history_replay(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                token = session.create()
                cookie = _cookie(token)
                ident = action_history.append(
                    "admin",
                    path="/1.1.1.1",
                    kind="ip",
                    query="1.1.1.1",
                    payload={"ok": True, "kind": "ip", "query": "1.1.1.1", "result": {"ip": "1.1.1.1"}},
                )
                listed, _, body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/history",
                    {},
                    cookie=cookie,
                )
                self.assertEqual(listed, 200)
                files = json.loads(body)["files"]
                self.assertEqual(files[0]["id"], ident)
                self.assertGreaterEqual(len(str(ident).split("-")[-1]), 32)
                self.assertIn("visitor", files[0])
                self.assertIn("intel", files[0])
                one, _, raw, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    f"/history/{ident}",
                    {},
                    cookie=cookie,
                )
                self.assertEqual(one, 200)
                payload = json.loads(raw)["payload"]
                self.assertEqual(payload["query"], "1.1.1.1")
                self.assertEqual(payload["result"]["ip"], "1.1.1.1")
                page, ctype, html, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    f"/history/{ident}",
                    {},
                    cookie=cookie,
                    accept="text/html",
                    host="lg.example.com",
                )
                self.assertEqual(page, 200)
                self.assertTrue(ctype.startswith("text/html"))
                text = _with_static(html)
                self.assertIn("report-payload", text)
                self.assertIn("paintInspect", text)
                self.assertIn("hist-link", text)
                self.assertIn("copyHistUrl", text)
                self.assertIn("hist-visitor", text)
                self.assertIn("hist-query", text)
                self.assertIn("gui.history.search", text)
                self.assertIn("permalink", text)
                self.assertIn("gui.history.visitor", text)
                self.assertIn("gui.history.who", text)
                self.assertIn('id="status-history"', text)
                self.assertIn('id="status-wall"', text)
                self.assertNotIn('id="history-rail"', text)
                listed_out, _, _, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/history",
                    {},
                )
                self.assertEqual(listed_out, 401)
                shared, _, shared_raw, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    f"/history/{ident}",
                    {},
                )
                self.assertEqual(shared, 200)
                self.assertEqual(json.loads(shared_raw)["payload"]["query"], "1.1.1.1")
                guest_page, guest_ctype, guest_html, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    f"/history/{ident}",
                    {},
                    accept="text/html",
                    host="lg.example.com",
                )
                self.assertEqual(guest_page, 200)
                self.assertTrue(guest_ctype.startswith("text/html"))
                guest_text = _with_static(guest_html)
                self.assertIn("report-payload", guest_text)
                self.assertIn("paintInspect", guest_text)
                self.assertNotIn('id="history-rail"', guest_text)
                self.assertNotIn('id="status-history"', guest_text)
                self.assertNotIn('id="status-logs"', guest_text)
                self.assertNotIn('id="cache-btn"', guest_text)
                self.assertNotIn('id="status-logout"', guest_text)
                self.assertIn('id="status-login"', guest_text)

    def test_history_is_global(self):
        fake = {"ok": True, "kind": "ip", "query": "8.8.8.8", "result": {"ip": "8.8.8.8"}}
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with patch(
                    "looking_glass.http.site.lookup_classified",
                    return_value=fake,
                ):
                    status, _, body, _ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/8.8.8.8",
                        {},
                        accept="application/json",
                    )
                self.assertEqual(status, 200)
                self.assertTrue(json.loads(body)["ok"])
                bob_id = action_history.append(
                    "bob",
                    path="/1.1.1.1",
                    kind="ip",
                    query="1.1.1.1",
                    payload={"ok": True, "kind": "ip", "query": "1.1.1.1", "result": {"ip": "1.1.1.1"}},
                )
                legacy_id = "0000000000001-abcd"
                legacy_dir = os.path.join(tmp, "data", "history", "carol")
                os.makedirs(legacy_dir, exist_ok=True)
                with open(os.path.join(legacy_dir, f"{legacy_id}.json"), "w", encoding="utf-8") as handle:
                    json.dump(
                        {
                            "id": legacy_id,
                            "ts": 1,
                            "user": "carol",
                            "path": "/9.9.9.9",
                            "kind": "ip",
                            "query": "9.9.9.9",
                            "payload": {"ok": True, "query": "9.9.9.9"},
                        },
                        handle,
                    )
                cookie = _cookie(session.create())
                listed, _, raw, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/history",
                    {},
                    cookie=cookie,
                )
                self.assertEqual(listed, 200)
                files = json.loads(raw)["files"]
                queries = {row["query"] for row in files}
                who = {row["user"] for row in files}
                ids = {row["id"] for row in files}
                self.assertIn("8.8.8.8", queries)
                self.assertIn("1.1.1.1", queries)
                self.assertIn("9.9.9.9", queries)
                guest = next(row for row in files if row["query"] == "8.8.8.8")
                self.assertEqual(guest["user"], "")
                self.assertEqual(guest["visitor"], "127.0.0.1")
                self.assertIn("", who)
                self.assertIn("bob", who)
                self.assertIn("carol", who)
                self.assertIn(bob_id, ids)
                self.assertIn(legacy_id, ids)
                leftover = action_history.get_entry("alice", legacy_id)
                self.assertIsNotNone(leftover)
                self.assertEqual(leftover["user"], "carol")

    def test_history_intel_is_visitor_not_query(self):
        def fake_intel(value):
            text = str(value or "")
            if text == "203.0.113.9":
                return {"asn": 64496, "org_name": "EXAMPLE-VISITOR", "country": "AU"}
            if text == "8.8.8.8":
                return {"asn": 15169, "org_name": "GOOGLE", "country": "US"}
            return None

        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with patch("looking_glass.http.weblog.compact_intel", side_effect=fake_intel):
                    ident = action_history.append(
                        "admin",
                        path="/8.8.8.8",
                        kind="ip",
                        query="8.8.8.8",
                        payload={
                            "ok": True,
                            "kind": "ip",
                            "query": "8.8.8.8",
                            "visitor": "203.0.113.9",
                            "result": {"ip": "8.8.8.8", "asn": 15169, "org_name": "GOOGLE"},
                        },
                        visitor="203.0.113.9",
                    )
                    rows = action_history.list_entries()
                    row = next(item for item in rows if item["id"] == ident)
                    self.assertEqual(row["visitor"], "203.0.113.9")
                    self.assertEqual(row["intel"]["asn"], 64496)
                    self.assertEqual(row["intel"]["org_name"], "EXAMPLE-VISITOR")
                    entry = action_history.get_entry("admin", ident)
                    self.assertEqual(entry["intel"]["asn"], 64496)
                    self.assertEqual(entry["payload"]["result"]["asn"], 15169)

    def test_serve_requires_login(self):
        status, _, body, _ = respond(
            "wsgi",
            "127.0.0.1",
            "/serve/start",
            {},
            method="POST",
        )
        self.assertEqual(status, 401)
        self.assertFalse(json.loads(body)["ok"])

    def test_serve_start_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                cookie = _cookie(session.create())
                with patch(
                    "looking_glass.intel_server.app.start",
                    return_value={"ok": True, "running": True, "state": "started"},
                ) as start:
                    status, _, body, _ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/serve/start",
                        {},
                        method="POST",
                        cookie=cookie,
                    )
                self.assertEqual(status, 200)
                self.assertTrue(json.loads(body)["running"])
                start.assert_called_once_with(wait_ready=False)
                with patch(
                    "looking_glass.intel_server.app.stop",
                    return_value={"ok": True, "running": False, "state": "stopped"},
                ) as stop:
                    status, _, body, _ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/serve/stop",
                        {},
                        method="POST",
                        cookie=cookie,
                    )
                self.assertEqual(status, 200)
                self.assertFalse(json.loads(body)["running"])
                stop.assert_called_once()

    def test_wsgi_login_sets_cookie(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                password.set_password("x")
                status, headers, body = _wsgi_get(
                    wsgi_app,
                    path="/login",
                    method="POST",
                    accept="application/json",
                    body=b'{"password":"x"}',
                )
        self.assertEqual(status, 200)
        self.assertIn("looking_glass_session=", headers.get("Set-Cookie", ""))
        self.assertIn("HttpOnly", headers.get("Set-Cookie", ""))
        self.assertIn("SameSite=Lax", headers.get("Set-Cookie", ""))
        self.assertTrue(json.loads(body)["ok"])

    def test_https_login_keeps_secure_if_forwarded_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                password.set_password("x")
                status, headers, body = _wsgi_get(
                    wsgi_app,
                    path="/login",
                    method="POST",
                    accept="application/json",
                    body=b'{"password":"x"}',
                    scheme="https",
                    forwarded_proto="http",
                )
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie", "")
        self.assertIn("looking_glass_session=", cookie)
        self.assertIn("Secure", cookie)
        self.assertTrue(json.loads(body)["ok"])

    def test_wall_admin_allows_bearer(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                created = keys.create("wall")
                denied, _, raw, _ = respond(
                    "wsgi", "127.0.0.1", "/wall", {}, accept="application/json"
                )
                self.assertEqual(denied, 401)
                ok, _, body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/wall",
                    {},
                    accept="application/json",
                    authorization=f"Bearer {created['secret']}",
                )
                self.assertEqual(ok, 200)
                self.assertTrue(json.loads(body)["ok"])
