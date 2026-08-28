import json
import os
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass.auth import session
from looking_glass.cli.entry import cli
from looking_glass.config import set_value
from looking_glass.docs.generate import generate_docs_html, write_docs
from looking_glass.http.site import respond


def _with_static(html: bytes | str) -> str:
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


def _roots(tmp: str):
    return (
        patch("looking_glass.config.get_root", return_value=tmp),
        patch("looking_glass.utility.get_root", return_value=tmp),
    )


class DocsGenerateTests(unittest.TestCase):
    def test_html_covers_http_cli_and_gui(self):
        text = generate_docs_html()
        self.assertIn("looking-glass dns", text)
        self.assertIn("GET /dns/", text)
        self.assertIn("form-ip", text)
        self.assertIn("paintInspect", text)
        self.assertIn('id="cli-dns"', text)
        self.assertIn('id="http-dns"', text)
        self.assertIn("<pre>", text)
        self.assertIn("<code>", text)
        self.assertIn("$ looking-glass dns --help", text)
        self.assertIn('class="docs-page"', text)
        self.assertIn('id="status-bar"', text)
        self.assertIn('id="status-docs"', text)
        self.assertIn('id="status-locale"', text)
        self.assertIn("/i18n/", text)
        self.assertNotIn("window.__i18n =", text)
        self.assertIn('class="nav-exit"', text)
        self.assertIn('href="/"', text)
        self.assertIn(">exit</a>", text)
        self.assertIn('href="/docs">docs</a>', text)
        self.assertIn("POST /docs", text)
        self.assertIn("GET /config", text)
        self.assertIn("<!--looking-glass-status-bar-->", text)
        self.assertNotIn('id="status-docs-regen"', text)
        self.assertIn("paintAuth", text)
        self.assertIn("data.user", text)
        self.assertIn('id="status-wins"', text)
        self.assertIn('id="status-windows"', text)
        self.assertIn("minimizeAll", text)
        self.assertIn("restoreAll", text)
        self.assertIn("status-win-stack", text)
        self.assertIn("inspect-pop-min", text)
        self.assertIn("inspect-pop-refresh", text)
        self.assertIn("status-win-max", text)
        self.assertIn("lookingGlassWindows", text)
        self.assertIn("lookingGlassWindows.place", text)
        self.assertIn("lookingGlassWindows.fit", text)
        self.assertIn("nudge(node)", text)
        self.assertIn("function placePop", text)
        self.assertNotIn("<i></i><i></i><i></i>", text)
        self.assertNotIn('id="status-logs"', text)
        self.assertNotIn('id="status-history"', text)
        self.assertNotIn('id="status-wall"', text)
        self.assertNotIn('id="cache-btn"', text)
        self.assertNotIn('id="status-config"', text)
        self.assertNotIn("sizeLogPopToAccess", text)
        self.assertNotIn('id="status-logout"', text)
        self.assertIn("openInspect", text)
        self.assertIn("data-ip", text)
        self.assertIn("/logs/stats", text)
        self.assertIn("/i18n/en.js", text)
        self.assertNotIn("/static/", text)
        self.assertIn("window.lookingGlassWindows", text)

    def test_catalog_brand_and_gui_tls_port(self):
        text = generate_docs_html()
        self.assertIn("looking-glass HTTPS supervisor", text)
        self.assertIn("/tls/&lt;host&gt;[/&lt;port&gt;]", text)
        self.assertIn("/tcptraceroute/&lt;host&gt;[/&lt;port&gt;]", text)
        self.assertNotIn("looking-glass serve", text)

    def test_click_writes_path(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "out.html")
            result = runner.invoke(cli, ["docs", dest])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertTrue(os.path.isfile(dest))
            text = open(dest, encoding="utf-8").read()
            self.assertIn("looking-glass dns", text)
            self.assertIn(dest, result.output)

    def test_write_docs_default_uses_data_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.docs.generate.get_data_dir", return_value=tmp):
                dest = write_docs()
            self.assertEqual(dest, os.path.join(tmp, "docs.html"))
            self.assertTrue(os.path.isfile(dest))

    def test_ensure_docs_on_serve_rewrites_when_enabled(self):
        from looking_glass.docs.generate import ensure_docs_on_serve

        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with patch("looking_glass.docs.generate.get_data_dir", return_value=tmp):
                    set_value("docs.enabled", True)
                    dest = os.path.join(tmp, "docs.html")
                    with open(dest, "w", encoding="utf-8") as fh:
                        fh.write("stale")
                    out = ensure_docs_on_serve()
                    self.assertEqual(out, dest)
                    text = open(dest, encoding="utf-8").read()
                    self.assertNotEqual(text, "stale")
                    self.assertIn("looking-glass dns", text)

    def test_ensure_docs_on_serve_skips_when_disabled(self):
        from looking_glass.docs.generate import ensure_docs_on_serve

        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with patch("looking_glass.docs.generate.get_data_dir", return_value=tmp):
                    dest = os.path.join(tmp, "docs.html")
                    with open(dest, "w", encoding="utf-8") as fh:
                        fh.write("stale")
                    self.assertIsNone(ensure_docs_on_serve())
                    self.assertEqual(open(dest, encoding="utf-8").read(), "stale")

    def test_wsgi_serve_generates_docs(self):
        from unittest.mock import MagicMock

        from looking_glass.http import wsgi as wsgi_mod

        httpd = MagicMock()
        with (
            patch("looking_glass.http.wsgi.make_server", return_value=httpd),
            patch("looking_glass.docs.generate.ensure_docs_on_serve") as ensure,
        ):
            wsgi_mod.serve("127.0.0.1", 9)
        ensure.assert_called_once()
        httpd.serve_forever.assert_called_once()


class DocsHttpTests(unittest.TestCase):
    def test_disabled_is_404_even_if_file_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                write_docs()
                status, ctype, body, *_ = respond("wsgi", "127.0.0.1", "/docs", {})
        self.assertEqual(status, 404)
        self.assertTrue(ctype.startswith("text/html"))
        self.assertNotIn("looking-glass dns", body.decode("utf-8"))

    def test_missing_file_is_404(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                set_value("docs.enabled", True)
                status, ctype, body, *_ = respond("wsgi", "127.0.0.1", "/docs", {})
        self.assertEqual(status, 404)
        self.assertTrue(ctype.startswith("text/html"))
        self.assertIn("looking-glass docs", body.decode("utf-8"))

    def test_serves_written_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                set_value("docs.enabled", True)
                write_docs()
                status, ctype, body, extra = respond("wsgi", "127.0.0.1", "/docs", {})
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("text/html"))
        self.assertIn(("Cache-Control", "no-store"), extra)
        text = body.decode("utf-8")
        self.assertIn("looking-glass dns", text)
        self.assertIn("GET /dns/", text)
        self.assertIn("form-ip", text)
        self.assertIn('id="status-login"', text)
        self.assertNotIn('id="status-logout"', text)
        self.assertNotIn('id="status-logs"', text)
        self.assertNotIn('id="cache-btn"', text)

    def test_session_chrome_and_post_regen(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                set_value("docs.enabled", True)
                write_docs()
                token = session.create()
                cookie = f"looking_glass_session={token}"
                status, _, body, *_ = respond("wsgi", "127.0.0.1", "/docs", {}, cookie=cookie)
                self.assertEqual(status, 200)
                raw = body.decode("utf-8")
                self.assertIn("/static/admin.js", raw)
                text = _with_static(raw)
                self.assertNotIn('id="status-login"', text)
                self.assertIn('id="status-auth-user"', text)
                self.assertIn('id="status-logout"', text)
                self.assertIn('id="status-logs"', text)
                self.assertIn('id="status-history"', text)
                self.assertIn('id="status-wall"', text)
                self.assertIn('id="cache-btn"', text)
                self.assertIn('id="status-config"', text)
                self.assertIn("log-pop", text)
                self.assertIn("cache-pop", text)
                self.assertIn("asn-pop inspect-pop config-pop", text)
                self.assertIn("cache-clear-all", text)
                self.assertIn(
                    "button, a, input, select, textarea, label, .inspect-pop-actions",
                    text,
                )
                self.assertIn("sortCacheRows", text)
                self.assertIn("sortWallRows", text)
                self.assertIn("dataset.tab", text)
                self.assertIn('id="status-docs-regen"', text)
                denied, _, raw, *_ = respond("wsgi", "127.0.0.1", "/docs", {}, method="POST")
                self.assertEqual(denied, 401)
                self.assertFalse(json.loads(raw)["ok"])
                with patch("looking_glass.docs.generate.write_docs", return_value="/tmp/docs.html") as regen:
                    ok, ctype, payload, *_ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/docs",
                        {},
                        method="POST",
                        cookie=cookie,
                    )
                self.assertEqual(ok, 200)
                self.assertTrue(ctype.startswith("application/json"))
                data = json.loads(payload)
                self.assertTrue(data["ok"])
                self.assertEqual(data["kind"], "docs")
                self.assertEqual(data["query"], "regenerate")
                regen.assert_called_once()

    def test_missing_file_keeps_session_chrome(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                set_value("docs.enabled", True)
                token = session.create()
                status, _, body, *_ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/docs",
                    {},
                    cookie=f"looking_glass_session={token}",
                )
        self.assertEqual(status, 404)
        text = body.decode("utf-8")
        self.assertIn('id="status-auth-user"', text)
        self.assertIn('id="status-logout"', text)
        self.assertIn('id="status-docs-regen"', text)
        self.assertNotIn(" hidden>", text.split('id="status-docs-regen"', 1)[1][:20])

    def test_status_reports_docs_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                set_value("docs.enabled", True)
                token = session.create()
                cookie = f"looking_glass_session={token}"
                status, _, body, *_ = respond("wsgi", "127.0.0.1", "/status", {}, cookie=cookie)
                self.assertEqual(status, 200)
                payload = json.loads(body)
                self.assertTrue(payload["docs"]["enabled"])
                self.assertFalse(payload["docs"]["generated"])
                write_docs()
                status, _, body, *_ = respond("wsgi", "127.0.0.1", "/status", {}, cookie=cookie)
                self.assertTrue(json.loads(body)["docs"]["generated"])
