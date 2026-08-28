import json
import os
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass.auth import session, users
from looking_glass.cli.entry import cli
from looking_glass.http.site import respond
from tests.test_wall import _wsgi_get, _with_static
from looking_glass.http.wsgi import app as wsgi_app


def _roots(tmp: str):
    return (
        patch("looking_glass.config.get_root", return_value=tmp),
        patch("looking_glass.utility.get_root", return_value=tmp),
    )


class AuthUsersTests(unittest.TestCase):
    def test_rejects_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with self.assertRaises(ValueError):
                    users.add_user("root")
                with self.assertRaises(ValueError):
                    users.add_user("Root")

    def test_cli_add_remove(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                added = runner.invoke(cli, ["--json", "auth", "users", "add", "alice"])
                self.assertEqual(added.exit_code, 0, added.output)
                payload = json.loads(added.output)
                self.assertEqual(payload["users"], ["alice"])
                listed = runner.invoke(cli, ["--json", "auth", "users"])
                self.assertEqual(json.loads(listed.output)["users"], ["alice"])
                removed = runner.invoke(cli, ["--json", "auth", "users", "remove", "alice"])
                self.assertEqual(json.loads(removed.output)["users"], [])
                bad = runner.invoke(cli, ["--json", "auth", "users", "add", "root"])
                self.assertNotEqual(bad.exit_code, 0)

    def test_sessions_clear(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                session.create("alice")
                out = runner.invoke(cli, ["--json", "auth", "sessions", "clear"])
                self.assertEqual(out.exit_code, 0, out.output)
                self.assertEqual(json.loads(out.output)["removed"], 1)

    def test_session_token_is_hex(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                token = session.create("alice")
                self.assertRegex(token, r"^[0-9a-f]{64}$")
                self.assertEqual(session.user_from_cookie(f"looking_glass_session={token}"), "alice")
                self.assertEqual(len(token), 64)
                self.assertNotIn(".", token)
                self.assertIsNone(session.user_from_cookie("looking_glass_session=aaa.bbb.ccc"))


class AuthHttpTests(unittest.TestCase):
    def test_root_forbidden_even_if_pam_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with patch("looking_glass.auth.pam.authenticate", return_value=True):
                    status, _, body, extra = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/login",
                        {},
                        method="POST",
                        body=b'{"username":"root","password":"x"}',
                    )
        self.assertEqual(status, 403)
        self.assertFalse(json.loads(body)["ok"])
        self.assertFalse(any(name.lower() == "set-cookie" for name, _ in extra))

    def test_first_user_bootstraps(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with patch("looking_glass.auth.pam.authenticate", return_value=True):
                    status, _, body, extra = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/login",
                        {},
                        method="POST",
                        body=b'{"username":"alice","password":"secret"}',
                    )
                self.assertEqual(status, 200)
                payload = json.loads(body)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["user"], "alice")
                self.assertEqual(users.list_users(), ["alice"])
                cookie = dict(extra).get("Set-Cookie", "")
                self.assertIn("looking_glass_session=", cookie)
                with patch("looking_glass.auth.pam.authenticate", return_value=True):
                    denied, _, raw, _ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/login",
                        {},
                        method="POST",
                        body=b'{"username":"bob","password":"secret"}',
                    )
                self.assertEqual(denied, 403)
                self.assertFalse(json.loads(raw)["ok"])
                with patch("looking_glass.auth.pam.authenticate", return_value=True):
                    listed, _, listed_body, extra2 = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/login",
                        {},
                        method="POST",
                        body=b'{"username":"alice","password":"secret"}',
                    )
                self.assertEqual(listed, 200)
                token = extra2[0][1].split(";", 1)[0]
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

    def test_bad_password(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with patch("looking_glass.auth.pam.authenticate", return_value=False):
                    status, _, body, extra = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/login",
                        {},
                        method="POST",
                        body=b'{"username":"alice","password":"nope"}',
                    )
        self.assertEqual(status, 401)
        self.assertFalse(any(name.lower() == "set-cookie" for name, _ in extra))

    def test_history_replay(self):
        from looking_glass.auth import history as action_history

        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                users.add_user("alice")
                token = session.create("alice")
                cookie = f"looking_glass_session={token}"
                ident = action_history.append(
                    "alice",
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
        from looking_glass.auth import history as action_history

        fake = {"ok": True, "kind": "ip", "query": "8.8.8.8", "result": {"ip": "8.8.8.8"}}
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                users.add_user("alice")
                users.add_user("bob")
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
                cookie = f"looking_glass_session={session.create('alice')}"
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
        from looking_glass.auth import history as action_history

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
                        "alice",
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
                    entry = action_history.get_entry("alice", ident)
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
                users.add_user("alice")
                token = session.create("alice")
                cookie = f"looking_glass_session={token}"
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
                with patch("looking_glass.auth.pam.authenticate", return_value=True):
                    status, headers, body = _wsgi_get(
                        wsgi_app,
                        path="/login",
                        method="POST",
                        accept="application/json",
                        body=b'{"username":"alice","password":"x"}',
                    )
        self.assertEqual(status, 200)
        self.assertIn("looking_glass_session=", headers.get("Set-Cookie", ""))
        self.assertIn("HttpOnly", headers.get("Set-Cookie", ""))
        self.assertIn("SameSite=Lax", headers.get("Set-Cookie", ""))
        self.assertTrue(json.loads(body)["ok"])

    def test_https_login_keeps_secure_if_forwarded_http(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with patch("looking_glass.auth.pam.authenticate", return_value=True):
                    status, headers, body = _wsgi_get(
                        wsgi_app,
                        path="/login",
                        method="POST",
                        accept="application/json",
                        body=b'{"username":"alice","password":"x"}',
                        scheme="https",
                        forwarded_proto="http",
                    )
        self.assertEqual(status, 200)
        cookie = headers.get("Set-Cookie", "")
        self.assertIn("looking_glass_session=", cookie)
        self.assertIn("Secure", cookie)
        self.assertTrue(json.loads(body)["ok"])
