import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass.cli.entry import cli
from looking_glass.http.site import respond
from looking_glass.i18n import available_locales, set_locale, t
from looking_glass.i18n.catalog import ui_messages_map


class FallbackTests(unittest.TestCase):
    def tearDown(self):
        set_locale("en")

    def test_missing_key_falls_back_to_english_then_id(self):
        self.assertEqual(t("gui.result.empty"), "Run a lookup. Reports paint here.")
        self.assertEqual(t("no.such.key.ever"), "no.such.key.ever")
        self.assertIn("HTTP API", t("docs.lede", cmd="looking-glass docs"))


class HtmlLocaleTests(unittest.TestCase):
    def tearDown(self):
        set_locale("en")

    def test_index_has_lang_and_i18n(self):
        status, ctype, body, *_ = respond(
            "wsgi",
            "1.1.1.1",
            "/",
            {},
            accept="text/html",
            host="lg.example.com",
        )
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("text/html"))
        text = body.decode("utf-8")
        self.assertIn('lang="en"', text)
        self.assertIn("/i18n/en.js", text)
        self.assertIn("window.t =", text)
        self.assertNotIn("window.__i18n =", text)
        self.assertIn("form-ip", text)
        self.assertIn("form-bar", text)
        self.assertIn("RDAP (HTTPS JSON)", text)
        self.assertIn("Legacy WHOIS (port 43)", text)
        self.assertIn('id="rdap-route"', text)
        self.assertIn("GET /rdap/&lt;token&gt;", text)
        self.assertNotIn("GET /whois/&lt;token&gt;?legacy=1", text)
        self.assertIn('id="status-locale"', text)

    def test_cookie_wins_over_accept_language(self):
        self.assertIn("de", available_locales())
        status, _, body, *_ = respond(
            "wsgi",
            "1.1.1.1",
            "/",
            {},
            accept="text/html",
            accept_language="en",
            cookie="looking_glass_lang=de",
            host="lg.example.com",
        )
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn('lang="de"', text)
        self.assertIn("/i18n/de.js", text)

    def test_accept_language_skips_unshipped_codes(self):
        self.assertIn("de", available_locales())
        status, _, body, *_ = respond(
            "wsgi",
            "1.1.1.1",
            "/",
            {},
            accept="text/html",
            accept_language="ko,de",
            host="lg.example.com",
        )
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn('lang="de"', text)

    def test_accept_language_sets_html_lang(self):
        self.assertIn("de", available_locales())
        status, _, body, *_ = respond(
            "wsgi",
            "1.1.1.1",
            "/",
            {},
            accept="text/html",
            accept_language="de-DE,de;q=0.9",
            host="lg.example.com",
        )
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn('lang="de"', text)

    def test_status_bar_select_when_multiple_locales(self):
        with patch("looking_glass.i18n.available_locales", return_value=["de", "en"]):
            status, _, body, *_ = respond(
                "wsgi",
                "1.1.1.1",
                "/",
                {},
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn('<select class="status-locale"', text)
        self.assertIn('id="status-locale"', text)
        self.assertIn('option value="de"', text)
        self.assertIn('option value="en"', text)

    def test_status_bar_span_when_one_locale(self):
        with patch("looking_glass.i18n.available_locales", return_value=["en"]):
            status, _, body, *_ = respond(
                "wsgi",
                "1.1.1.1",
                "/",
                {},
                accept="text/html",
                host="lg.example.com",
            )
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertNotIn('<select class="status-locale"', text)
        self.assertRegex(text, r'<span[^>]*id="status-locale"[^>]*>en<')

    def test_i18n_json_is_ui_projection(self):
        self.assertIn("de", available_locales())
        status, ctype, body, extra = respond("wsgi", "1.1.1.1", "/i18n/de.json", {})
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("application/json"))
        self.assertIn(("Cache-Control", "public, max-age=300"), extra)
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual(payload["locale"], "de")
        self.assertIn("gui.ip.tab", payload["messages"])
        self.assertNotIn("cli.build.help", payload["messages"])

    def test_i18n_js_assigns_window_map(self):
        status, ctype, body, extra = respond("wsgi", "1.1.1.1", "/i18n/en.js", {})
        self.assertEqual(status, 200)
        self.assertTrue(ctype.startswith("application/javascript"))
        self.assertIn(("Cache-Control", "public, max-age=300"), extra)
        text = body.decode("utf-8")
        self.assertTrue(text.startswith("window.__i18n = "))
        self.assertIn("gui.ip.tab", text)

    def test_i18n_unknown_lang_is_404(self):
        status, _, body, *_ = respond("wsgi", "1.1.1.1", "/i18n/qaa.json", {})
        self.assertEqual(status, 404)
        payload = json.loads(body.decode("utf-8"))
        self.assertFalse(payload["ok"])

    def test_gui_sets_lang_cookie_on_picker_change(self):
        status, _, body, *_ = respond("wsgi", "1.1.1.1", "/static/gui.js", {})
        self.assertEqual(status, 200)
        text = body.decode("utf-8")
        self.assertIn("looking_glass_lang=", text)
        self.assertIn("location.reload()", text)

    def test_available_locales_skips_sidecar_json(self):
        for code in available_locales():
            self.assertRegex(code, r"^[a-z]+$")

    def test_json_dns_error_stays_english(self):
        status, ctype, body, *_ = respond(
            "wsgi",
            "127.0.0.1",
            "/dns",
            {},
            accept="application/json",
            accept_language="fr",
        )
        self.assertEqual(status, 400)
        self.assertTrue(ctype.startswith("application/json"))
        payload = json.loads(body.decode("utf-8"))
        self.assertIn("needs a name", payload["error"])


class LocaleCliTests(unittest.TestCase):
    def tearDown(self):
        set_locale("en")

    def _root(self, tmp):
        return patch("looking_glass.i18n.catalog.get_root", return_value=tmp)

    def test_list_add_delete(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp, self._root(tmp):
            listed = runner.invoke(cli, ["locale", "list"])
            self.assertEqual(listed.exit_code, 0, listed.output)
            self.assertIn("en", listed.output)
            added = runner.invoke(cli, ["locale", "add", "fr"])
            self.assertEqual(added.exit_code, 0, added.output)
            dest = Path(tmp) / "locales" / "fr.json"
            self.assertTrue(dest.is_file())
            listed2 = runner.invoke(cli, ["locale", "list"])
            self.assertIn("fr", listed2.output)
            deleted = runner.invoke(cli, ["locale", "delete", "fr"])
            self.assertEqual(deleted.exit_code, 0, deleted.output)
            self.assertFalse(dest.is_file())

    def test_delete_en_fails(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp, self._root(tmp):
            result = runner.invoke(cli, ["locale", "delete", "en"])
            self.assertNotEqual(result.exit_code, 0)
            self.assertIn("cannot be deleted", result.output)


class ResultPageGuiKeysTests(unittest.TestCase):
    def test_result_map_includes_dnssec_wait_elapsed(self):
        msgs = ui_messages_map("result")
        for key in (
            "gui.dnssec.tab",
            "gui.wait.mtr",
            "gui.wait.http",
            "gui.elapsed",
            "gui.howto.curl",
            "gui.howto.httpie",
            "gui.howto.cli",
            "gui.ok",
            "gui.cancel",
            "gui.maximize",
        ):
            self.assertIn(key, msgs)
