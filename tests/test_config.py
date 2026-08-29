import json
import os
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass.auth import session
from looking_glass.cli.entry import cli
from looking_glass.config import load, path, set_value
from looking_glass.http.site import respond
from looking_glass.i18n import set_locale


def _root(tmp: str):
    return patch("looking_glass.config.get_root", return_value=tmp)


def _roots(tmp: str):
    return (
        patch("looking_glass.config.get_root", return_value=tmp),
        patch("looking_glass.utility.get_root", return_value=tmp),
    )


class ConfigLoaderTests(unittest.TestCase):
    def test_defaults_write_config_json(self):
        with tempfile.TemporaryDirectory() as tmp, _root(tmp):
            cfg = load()
            self.assertEqual(cfg["locale"], "en")
            self.assertEqual(cfg["cache"]["ttl_days"], 7)
            self.assertFalse(cfg["cache"]["gui"])
            self.assertFalse(cfg["docs"]["enabled"])
            self.assertNotIn("auth", cfg)
            self.assertEqual(cfg["refresh"]["rir"], 1)
            self.assertEqual(cfg["history"]["snapshots"], -1)
            self.assertEqual(cfg["wall"]["challenge_ttl_days"], 5)
            self.assertEqual(cfg["wall"]["challenge_bits"], 16)
            self.assertEqual(cfg["mtr"]["cycles"], 10)
            self.assertEqual(cfg["mtr"]["max_cycles"], 30)
            self.assertFalse(cfg["http"]["enabled"])
            self.assertEqual(cfg["http"]["port"], 5555)
            self.assertEqual(cfg["http"]["acme_port"], 80)
            self.assertEqual(cfg["http"]["workers"], 1)
            self.assertEqual(cfg["http"]["bind"], "*")
            self.assertEqual(cfg["http"]["hostname"], "")
            self.assertEqual(cfg["http"]["controller_origins"], [])
            dest = path()
            self.assertEqual(dest, os.path.join(tmp, "config.json"))
            self.assertTrue(os.path.isfile(dest))
            self.assertFalse(os.path.isfile(os.path.join(tmp, "data", "cache.json")))

    def test_missing_mtr_keys_mean_ten_and_thirty(self):
        with tempfile.TemporaryDirectory() as tmp, _root(tmp):
            dest = path()
            os.makedirs(os.path.dirname(dest) or tmp, exist_ok=True)
            with open(dest, "w", encoding="utf-8") as handle:
                json.dump({"locale": "en", "cache": {"ttl_days": 7, "gui": False}}, handle)
            cfg = load()
            self.assertEqual(cfg["mtr"]["cycles"], 10)
            self.assertEqual(cfg["mtr"]["max_cycles"], 30)

    def test_migrates_legacy_files_once(self):
        with tempfile.TemporaryDirectory() as tmp, _root(tmp):
            data = os.path.join(tmp, "data")
            os.makedirs(data)
            with open(os.path.join(tmp, "locale"), "w", encoding="utf-8") as handle:
                handle.write("fr\n")
            with open(os.path.join(data, "cache.json"), "w", encoding="utf-8") as handle:
                json.dump({"ttl_days": 3, "gui": True}, handle)
            with open(os.path.join(data, "refresh.json"), "w", encoding="utf-8") as handle:
                json.dump({"rir": 9, "iana": 30, "dns_types": 30, "asn_org": 7, "asn": 1}, handle)
            cfg = load()
            self.assertEqual(cfg["locale"], "fr")
            self.assertEqual(cfg["cache"]["ttl_days"], 3)
            self.assertTrue(cfg["cache"]["gui"])
            self.assertEqual(cfg["refresh"]["rir"], 9)
            with open(os.path.join(data, "cache.json"), "w", encoding="utf-8") as handle:
                json.dump({"ttl_days": 99, "gui": False}, handle)
            with open(os.path.join(tmp, "locale"), "w", encoding="utf-8") as handle:
                handle.write("de\n")
            again = load()
            self.assertEqual(again["locale"], "fr")
            self.assertEqual(again["cache"]["ttl_days"], 3)
            self.assertTrue(again["cache"]["gui"])
            self.assertTrue(os.path.isfile(os.path.join(data, "cache.json")))


class ConfigCliTests(unittest.TestCase):
    def test_show_get_set(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp, _root(tmp):
            shown = runner.invoke(cli, ["--json", "config"])
            self.assertEqual(shown.exit_code, 0, shown.output)
            payload = json.loads(shown.output)
            self.assertTrue(payload["ok"])
            self.assertTrue(payload["path"].endswith("config.json"))
            self.assertEqual(payload["locale"], "en")
            got = runner.invoke(cli, ["--json", "config", "get", "locale"])
            self.assertEqual(json.loads(got.output)["value"], "en")
            setted = runner.invoke(cli, ["--json", "config", "set", "cache.gui", "true"])
            self.assertEqual(setted.exit_code, 0, setted.output)
            body = json.loads(setted.output)
            self.assertTrue(body["cache"]["gui"])
            shown2 = runner.invoke(cli, ["--json", "config", "show"])
            self.assertTrue(json.loads(shown2.output)["cache"]["gui"])
            rir = runner.invoke(cli, ["--json", "config", "set", "refresh.rir", "2"])
            self.assertEqual(json.loads(rir.output)["refresh"]["rir"], 2)
            lang = runner.invoke(cli, ["--json", "config", "set", "locale", "fr"])
            self.assertEqual(json.loads(lang.output)["locale"], "fr")
            snaps = runner.invoke(cli, ["--json", "config", "set", "history.snapshots", "-1"])
            self.assertEqual(snaps.exit_code, 0, snaps.output)
            self.assertEqual(json.loads(snaps.output)["history"]["snapshots"], -1)
            ttl = runner.invoke(cli, ["--json", "config", "set", "wall.challenge_ttl_days", "5"])
            self.assertEqual(ttl.exit_code, 0, ttl.output)
            self.assertEqual(json.loads(ttl.output)["wall"]["challenge_ttl_days"], 5)
            mode = runner.invoke(cli, ["--json", "config", "set", "wall.default", "block"])
            self.assertEqual(mode.exit_code, 0, mode.output)
            self.assertEqual(json.loads(mode.output)["wall"]["default"], "block")
            hdr = runner.invoke(cli, ["--json", "config", "set", "wall.headers.asn", "false"])
            self.assertEqual(hdr.exit_code, 0, hdr.output)
            self.assertFalse(json.loads(hdr.output)["wall"]["headers"]["asn"])
            keep = runner.invoke(cli, ["--json", "config", "set", "logs.keep", "-1"])
            self.assertEqual(keep.exit_code, 0, keep.output)
            self.assertEqual(json.loads(keep.output)["logs"]["keep"], -1)
            unknown = runner.invoke(cli, ["--json", "config", "set", "nope", "1"])
            self.assertNotEqual(unknown.exit_code, 0)
            docs = runner.invoke(cli, ["--json", "config", "set", "docs.enabled", "true"])
            self.assertEqual(docs.exit_code, 0, docs.output)
            self.assertTrue(json.loads(docs.output)["docs"]["enabled"])
            workers = runner.invoke(cli, ["--json", "config", "set", "http.workers", "40"])
            self.assertEqual(workers.exit_code, 0, workers.output)
            self.assertEqual(json.loads(workers.output)["http"]["workers"], 32)
            host = runner.invoke(cli, ["--json", "config", "hostname", "S1.Example.COM."])
            self.assertEqual(host.exit_code, 0, host.output)
            self.assertEqual(json.loads(host.output)["http"]["hostname"], "s1.example.com")
            self.assertFalse(json.loads(host.output)["detected"])
            with patch("looking_glass.observe.hostname", return_value="node.example.test"):
                detected = runner.invoke(cli, ["--json", "config", "hostname"])
            self.assertEqual(detected.exit_code, 0, detected.output)
            self.assertEqual(json.loads(detected.output)["http"]["hostname"], "node.example.test")
            self.assertTrue(json.loads(detected.output)["detected"])


class ConfigHtmlTests(unittest.TestCase):
    def tearDown(self):
        set_locale("en")

    def test_accept_language_wins_for_html(self):
        with tempfile.TemporaryDirectory() as tmp, _root(tmp):
            load()
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
        self.assertIn('lang="de"', body.decode("utf-8"))

    def test_json_dns_error_stays_english(self):
        with tempfile.TemporaryDirectory() as tmp, _root(tmp):
            runner = CliRunner()
            runner.invoke(cli, ["--json", "config", "set", "locale", "fr"])
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
        self.assertIn("needs a name", json.loads(body.decode("utf-8"))["error"])


class ConfigHttpTests(unittest.TestCase):
    def test_config_requires_session(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                status, _, body, *_ = respond("wsgi", "127.0.0.1", "/config", {})
        self.assertEqual(status, 401)
        self.assertFalse(json.loads(body)["ok"])

    def test_get_and_post_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                token = session.create()
                cookie = f"looking_glass_session={token}"
                status, _, body, *_ = respond(
                    "wsgi", "127.0.0.1", "/config", {}, cookie=cookie
                )
                self.assertEqual(status, 200)
                payload = json.loads(body)
                self.assertTrue(payload["ok"])
                self.assertFalse(payload["docs"]["enabled"])
                self.assertEqual(payload["wall"]["challenge_bits"], 16)
                self.assertEqual(payload["mtr"]["cycles"], 10)
                self.assertEqual(payload["mtr"]["max_cycles"], 30)
                status, _, body, *_ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/config",
                    {},
                    method="POST",
                    cookie=cookie,
                    body=b'{"docs.enabled":true,"wall.challenge_bits":12,"mtr.max_cycles":999,"mtr.cycles":3}',
                )
                self.assertEqual(status, 200)
                saved = json.loads(body)
                self.assertTrue(saved["docs"]["enabled"])
                self.assertEqual(saved["wall"]["challenge_bits"], 12)
                self.assertEqual(saved["mtr"]["max_cycles"], 50)
                self.assertEqual(saved["mtr"]["cycles"], 3)
                denied, _, raw, *_ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/config",
                    {},
                    method="POST",
                    cookie=cookie,
                    body=b'{"auth.users":["bob"]}',
                )
                self.assertEqual(denied, 400)
                self.assertIn("unknown key", json.loads(raw)["error"])
