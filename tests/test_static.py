import asyncio
import unittest

from looking_glass.http import weblog
from looking_glass.http.site import respond, respond_async
from looking_glass.http.static_files import resolve_static, serve, static_url


class StaticFilesTests(unittest.TestCase):
    def test_css_and_js_are_cached(self):
        for path, needle, ctype in (
            ("/static/gui.css", ".asn-pop", "text/css"),
            ("/static/gui.js", "window.lookingGlassWindows", "text/javascript"),
            ("/static/index.js", "const boot", "text/javascript"),
            ("/static/admin.js", "cache-clear-all", "text/javascript"),
        ):
            status, content_type, body, extra = respond("wsgi", "127.0.0.1", path, {})
            self.assertEqual(status, 200, path)
            self.assertTrue(content_type.startswith(ctype), content_type)
            self.assertIn(("Cache-Control", "public, max-age=31536000, immutable"), extra)
            self.assertIn(needle.encode("utf-8"), body)

    def test_mtr_form_passes_cycles_on_path(self):
        _, _, gui, _ = respond("wsgi", "127.0.0.1", "/static/gui.js", {})
        _, _, index, _ = respond("wsgi", "127.0.0.1", "/static/index.js", {})
        gui_text = gui.decode("utf-8")
        index_text = index.decode("utf-8")
        self.assertIn("function mtrCyclesQuery", gui_text)
        self.assertIn("mtrCyclesQuery(extras.cycles)", gui_text)
        self.assertIn("?cycles=", gui_text)
        self.assertIn("window.toolPath(kind, target, extras)", gui_text)
        self.assertIn("looking-glass", gui_text)
        self.assertIn('if (head === "mtr")', gui_text)
        self.assertIn("--cycles", gui_text)
        self.assertNotIn("erso-wall", gui_text)
        self.assertIn("data.serve.ready", gui_text)
        self.assertIn("data.https", gui_text)
        self.assertIn("function paintHttps", gui_text)
        self.assertIn("status.https.up", gui_text)
        self.assertNotIn("status-serve-btn", gui_text)
        self.assertNotIn("/serve/stop", gui_text)
        self.assertIn("intel building", gui_text)
        self.assertNotIn("looking-glass serve start", gui_text)
        self.assertIn("lookingGlassStatus", gui_text)
        self.assertIn('runLookup(window.toolPath("mtr", target, { cycles }))', index_text)
        self.assertIn('[name=cycles]', index_text)
        self.assertNotIn("erso-wall", index_text)

    def test_tls_port_and_failure_card(self):
        _, _, gui, _ = respond("wsgi", "127.0.0.1", "/static/gui.js", {})
        gui_text = gui.decode("utf-8")
        self.assertIn("function splitTlsHostPort", gui_text)
        self.assertIn('if (kind === "tls") return renderTls(payload)', gui_text)
        self.assertNotIn('if (kind === "tls" && result) return renderTls(payload)', gui_text)
        self.assertIn("payload.error || result.error", gui_text)
        self.assertIn("reopen: \"tool\", kind, target, extras", gui_text)
        self.assertIn("openTool(meta.kind, meta.target, undefined, meta.extras)", gui_text)
        self.assertIn("`/tls/${encodeToken(host)}/${encodeToken(port)}`", gui_text)
        from pathlib import Path

        html = (
            Path(__file__).resolve().parents[1]
            / "looking_glass"
            / "http"
            / "templates"
            / "index.html"
        ).read_text(encoding="utf-8")
        self.assertIn('t("gui.tls.port")', html)
        self.assertIn('id="form-tls"', html)

    def test_admin_js_declares_http_config_once(self):
        status, _, body, _ = respond("wsgi", "127.0.0.1", "/static/admin.js", {})
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertEqual(text.count("const http = data.http"), 1)
        self.assertIn("const httpSec", text)
        self.assertIn("const mtrSec", text)
        self.assertIn('WIN_ID = "services"', text)
        self.assertIn("services-pop", text)
        self.assertIn("function formatDn", text)
        self.assertIn("commonName", text)
        self.assertIn("formatDn(https.subject)", text)
        self.assertIn("formatDn(https.issuer)", text)
        self.assertNotIn("String(https.subject)", text)
        self.assertIn("gui.services.system", text)
        self.assertIn("gui.services.service", text)
        self.assertNotIn("/serve/stop", text)
        _, _, css, _ = respond("wsgi", "127.0.0.1", "/static/gui.css", {})
        css_text = css.decode("utf-8")
        self.assertRegex(css_text, r"\.services-host\s*\{[^}]*text-align:\s*center")

    def test_missing_and_escape_are_404(self):
        for path in ("/static/nope.js", "/static/../site.py", "/static/%2e%2e/site.py"):
            status, _, body, _ = respond("wsgi", "127.0.0.1", path, {})
            self.assertEqual(status, 404, path)
            self.assertEqual(body, b"not found")
        self.assertIsNone(resolve_static("../site.py"))
        self.assertIsNone(resolve_static("static/../site.py"))

    def test_post_is_405(self):
        status, _, _, extra = respond("wsgi", "127.0.0.1", "/static/gui.css", {}, method="POST")
        self.assertEqual(status, 405)
        self.assertIn(("Allow", "GET, HEAD"), extra)

    def test_static_url_points_at_mtime(self):
        href = static_url("gui.js")
        self.assertTrue(href.startswith("/static/gui.js?v="))
        self.assertGreater(len(href.split("v=", 1)[1]), 0)

    def test_skip_access_log(self):
        self.assertTrue(weblog.skip_access("/static/gui.css"))
        self.assertEqual(weblog.classify_request("/static/gui.js")[0], "static")

    def test_async_get(self):
        status, ctype, body, extra = asyncio.run(
            respond_async("asgi", "127.0.0.1", "/static/gui.css", {})
        )
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("text/css"))
        self.assertIn(("Cache-Control", "public, max-age=31536000, immutable"), extra)
        self.assertIn(b".asn-pop", body)

    def test_serve_unknown_name(self):
        status, _, body, _ = serve("GET", "static/secret.txt")
        self.assertEqual(status, 404)
        self.assertEqual(body, b"not found")

    def test_raw_text_fields_disable_safari_correct(self):
        import re
        from pathlib import Path

        root = Path(__file__).resolve().parents[1]
        four = 'spellcheck="false" autocorrect="off" autocapitalize="off" autocomplete="off"'
        macro = (root / "looking_glass/http/templates/_raw_input.html").read_text(encoding="utf-8")
        self.assertIn(four, macro)
        html = (root / "looking_glass/http/templates/index.html").read_text(encoding="utf-8")
        self.assertIn('{% from "_raw_input.html" import raw %}', html)
        ping = html[html.index('id="form-ping"'):html.index('id="form-tcp"')]
        self.assertIn("{{ raw() }}", ping)
        tag_re = re.compile(r"<input\b[^>]*>", re.I)
        for tag in tag_re.findall(html):
            if 'type="radio"' in tag or 'inputmode="numeric"' in tag:
                continue
            self.assertIn("{{ raw() }}", tag, tag)
        bar = (root / "looking_glass/http/templates/_status_bar.html").read_text(encoding="utf-8")
        pw = bar.split('type="password"', 1)[1].split(">", 1)[0]
        self.assertIn('spellcheck="false"', pw)
        self.assertIn('autocomplete="current-password"', pw)
        self.assertNotIn("autocorrect", pw)
        gui = (root / "looking_glass/http/static/gui.js").read_text(encoding="utf-8")
        admin = (root / "looking_glass/http/static/admin.js").read_text(encoding="utf-8")
        self.assertIn("function rawTextField", gui)
        self.assertIn("function rawTextField", admin)
        self.assertIn("rawTextField(search)", gui)
        self.assertIn("rawTextField(input)", admin)
        self.assertIn("rawTextField(search)", admin)
        self.assertIn("rawTextField(searchEl)", admin)
        self.assertIn('rawTextField(pw, "password")', admin)
        status, _, body, _ = respond(
            "wsgi",
            "127.0.0.1",
            "/",
            {},
            accept="text/html",
            host="lg.example.com",
            scheme="https",
        )
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        ping_html = text[text.index('id="form-ping"'):text.index('id="form-tcp"')]
        host = ping_html.split("<input", 1)[1].split(">", 1)[0]
        self.assertIn('spellcheck="false"', host)
        self.assertIn('autocorrect="off"', host)
        self.assertIn('autocapitalize="off"', host)
        self.assertIn('autocomplete="off"', host)
