import json
import math
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from looking_glass.cli.entry import cli as looking_glass_cli
from looking_glass.i18n.catalog import load_json_file, package_locales_dir
from tools.engine import locale_label, system_prompt
from tools.glossary import DEFAULT_GLOSSARY, is_copy_through, undo_utf8_mojibake, verify_translation
from tools.locale import _display_width, cli as locale_cli
from tools.providers import BAKED_MODELS, CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT, ProviderError, complete_json
from tools.tm import en_sha256, unique_hashes


def _json(result):
    text = result.output
    start = text.find("{")
    if start < 0:
        raise AssertionError(f"no JSON in output: {text!r}")
    payload, _end = json.JSONDecoder().raw_decode(text[start:])
    return payload


class BakedDefaultsTests(unittest.TestCase):
    def test_baked_models(self):
        self.assertEqual(BAKED_MODELS["claude"], "claude-sonnet-5")
        self.assertEqual(BAKED_MODELS["openai"], "gpt-5.6-sol")
        self.assertEqual(BAKED_MODELS["grok"], "grok-4.6")

    def test_glossary_extras(self):
        for term in ("looking-glass", "JSON", "JSONL", "IPv4", "IPv6", "GUI", "Click"):
            self.assertIn(term, DEFAULT_GLOSSARY)


class VerifyTests(unittest.TestCase):
    def test_glossary_and_placeholder(self):
        ok, reason = verify_translation("Look up DNS for {path}", "DNS für {path}", DEFAULT_GLOSSARY)
        self.assertTrue(ok, reason)
        ok, reason = verify_translation("Look up DNS for {path}", "Nachschlagen", DEFAULT_GLOSSARY)
        self.assertFalse(ok)
        self.assertTrue(reason)

    def test_backtick_and_flag(self):
        ok, _ = verify_translation("run `looking-glass` --legacy", "lauf `looking-glass` --legacy", DEFAULT_GLOSSARY)
        self.assertTrue(ok)
        ok, reason = verify_translation("run `looking-glass` --legacy", "lauf looking-glass", DEFAULT_GLOSSARY)
        self.assertFalse(ok)
        self.assertTrue(reason)

    def test_home_path_ignores_sentence_period(self):
        en = "List or edit the admin allowlist in ~/.looking-glass/config.json."
        ok, reason = verify_translation(
            en,
            "Listen oder bearbeiten Sie die Admin-Allowlist in ~/.looking-glass/config.json.",
            DEFAULT_GLOSSARY,
        )
        self.assertTrue(ok, reason)
        en_data = "Download lookup datasets into ~/.looking-glass/data.\n\nNext."
        ok, reason = verify_translation(
            en_data,
            "Lookup-Datensätze nach ~/.looking-glass/data herunterladen.\n\nWeiter.",
            DEFAULT_GLOSSARY,
        )
        self.assertTrue(ok, reason)
        ok, reason = verify_translation(en, "looking-glass Allowlist bearbeiten.", DEFAULT_GLOSSARY)
        self.assertFalse(ok)
        self.assertEqual(reason, "span:~/.looking-glass/config.json")

    def test_glossary_matches_whole_tokens_only(self):
        ok, reason = verify_translation(
            "classify_query: then ASN digits, then country.",
            "classify_query: dann ASN-Ziffern, dann Land.",
            DEFAULT_GLOSSARY,
        )
        self.assertTrue(ok, reason)
        ok, reason = verify_translation("Walk like dig +trace.", "Iterativ vom Root.", DEFAULT_GLOSSARY)
        self.assertFalse(ok)
        self.assertEqual(reason, "glossary:dig")
        ok, reason = verify_translation("Write JSONL logs.", "JSONL-Logs schreiben.", DEFAULT_GLOSSARY)
        self.assertTrue(ok, reason)
        ok, reason = verify_translation("HTTP API, Click CLI, and GUI.", "HTTP API und GUI.", DEFAULT_GLOSSARY)
        self.assertFalse(ok)
        self.assertEqual(reason, "glossary:Click")


class CopyThroughTests(unittest.TestCase):
    def test_nav_tabs_and_whole_string_glossary(self):
        self.assertTrue(is_copy_through("gui.register.tab", "Register", DEFAULT_GLOSSARY))
        self.assertTrue(is_copy_through("gui.mail.tab", "Mail", DEFAULT_GLOSSARY))
        self.assertTrue(is_copy_through("inspect.mail.label", "Mail", DEFAULT_GLOSSARY))
        self.assertTrue(is_copy_through("tech.only", "DNS", DEFAULT_GLOSSARY))
        self.assertFalse(is_copy_through("gui.mail.hint", "Mail diagnostics", DEFAULT_GLOSSARY))
        self.assertFalse(is_copy_through("cli.apex.help", "Hello DNS", DEFAULT_GLOSSARY))


class MojibakeTests(unittest.TestCase):
    def test_undo_utf8_mojibake(self):
        self.assertEqual(undo_utf8_mojibake("prÃ¼fen"), "prüfen")
        self.assertEqual(undo_utf8_mojibake("prüfen"), "prüfen")
        self.assertEqual(undo_utf8_mojibake("ASCII only"), "ASCII only")


class BabelLocaleTests(unittest.TestCase):
    def test_de_and_ja_labels(self):
        de = locale_label("de")
        self.assertIn("de", de)
        self.assertIn("German", de)
        self.assertIn("Deutsch", de)
        ja = locale_label("ja")
        self.assertIn("Japanese", ja)
        prompt = system_prompt("de", DEFAULT_GLOSSARY)
        self.assertIn("German", prompt)
        self.assertIn("Deutsch", prompt)
        self.assertIn("Target locale:", prompt)
        self.assertIn("Sie", prompt)

    def test_pt_prompt_is_brazilian(self):
        prompt = system_prompt("pt", DEFAULT_GLOSSARY)
        self.assertIn("Brazilian", prompt)
        self.assertIn("pt-BR", prompt)
        self.assertIn("você", prompt)

    def test_unknown_code_stays_raw(self):
        self.assertEqual(locale_label("zzq"), "zzq")


class LocaleShipToolTests(unittest.TestCase):
    def _runner(self):
        return CliRunner()

    def test_pip_cli_has_no_translate_or_generate(self):
        runner = self._runner()
        for argv in (
            ["locale", "translate", "--help"],
            ["locale", "generate", "--help"],
            ["locale", "regenerate", "--help"],
            ["locale", "configure", "--help"],
        ):
            result = runner.invoke(looking_glass_cli, argv)
            self.assertNotEqual(result.exit_code, 0, argv)

    def test_harvest_writes_package_en(self):
        runner = self._runner()
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "pkg"
            pkg.mkdir()
            with (
                patch("looking_glass.i18n.catalog.get_root", return_value=str(Path(tmp) / "op")),
                patch("looking_glass.i18n.catalog.PACKAGE_LOCALES", pkg),
            ):
                first = runner.invoke(locale_cli, ["--json", "harvest"])
                self.assertEqual(first.exit_code, 0, first.output)
                harvested = _json(first)
                self.assertEqual(harvested["langs"], [])
                self.assertEqual(harvested["stale"], [])
                path = pkg / "en.json"
                self.assertTrue(path.is_file())
                text1 = path.read_text(encoding="utf-8")
                second = runner.invoke(locale_cli, ["--json", "harvest"])
                self.assertEqual(second.exit_code, 0, second.output)
                self.assertEqual(text1, path.read_text(encoding="utf-8"))
                catalog = json.loads(text1)
                self.assertIn("gui.result.empty", catalog["messages"])
                self.assertIn("cli.locale.help", catalog["messages"])
                self.assertIn("cli.locale.list.help", catalog["messages"])
                self.assertNotIn("cli.locale.translate.help", catalog["messages"])
                self.assertNotIn("cli.locale.generate.help", catalog["messages"])

    def test_glossary_show_default_and_file(self):
        runner = self._runner()
        shown = runner.invoke(locale_cli, ["--json", "glossary", "show"])
        self.assertEqual(shown.exit_code, 0, shown.output)
        payload = _json(shown)
        self.assertTrue(payload["ok"])
        self.assertIn("looking-glass", payload["glossary"])
        self.assertEqual(payload["glossary"][:3], DEFAULT_GLOSSARY[:3])
        with tempfile.TemporaryDirectory() as tmp:
            extra = Path(tmp) / "extra.json"
            extra.write_text(json.dumps(["DNS", "WAF"]), encoding="utf-8")
            merged = runner.invoke(locale_cli, ["--json", "glossary", "show", "--glossary", str(extra)])
        self.assertEqual(merged.exit_code, 0, merged.output)
        terms = _json(merged)["glossary"]
        self.assertIn("WAF", terms)
        self.assertEqual(terms.count("DNS"), 1)
        self.assertLess(terms.index("DNS"), terms.index("WAF"))

    def test_package_glossary_merges_by_default(self):
        runner = self._runner()
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "pkg"
            pkg.mkdir()
            (pkg / "glossary.json").write_text(json.dumps(["Register", "DNS"]), encoding="utf-8")
            with patch("looking_glass.i18n.catalog.PACKAGE_LOCALES", pkg):
                shown = runner.invoke(locale_cli, ["--json", "glossary", "show"])
        self.assertEqual(shown.exit_code, 0, shown.output)
        terms = _json(shown)["glossary"]
        self.assertIn("Register", terms)
        self.assertEqual(terms.count("DNS"), 1)
        self.assertEqual(terms[:3], DEFAULT_GLOSSARY[:3])
        self.assertLess(terms.index("DNS"), terms.index("Register"))

    def test_dry_run_defaults_to_package_locales(self):
        src = package_locales_dir() / "en.json"
        messages = load_json_file(src)
        expected_keys = len(messages)
        expected_unique = unique_hashes(messages)
        runner = self._runner()
        with patch("tools.engine.complete_json") as complete:
            result = runner.invoke(
                locale_cli,
                ["--json", "translate", "de", "--provider", "claude", "--dry-run"],
            )
        complete.assert_not_called()
        self.assertEqual(result.exit_code, 0, result.output)
        payload = _json(result)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["src"], str(src))
        self.assertEqual(payload["dst"], str(package_locales_dir() / "de.json"))
        self.assertEqual(payload["keys"], expected_keys)
        self.assertEqual(payload["unique"], expected_unique)
        self.assertLessEqual(payload["unique"], payload["keys"])
        self.assertGreater(payload["keys"], 500)
        self.assertGreater(payload["unique"], 400)
        self.assertLessEqual(payload["send_unique"], payload["unique"])
        held = payload.get("copy_through") or []
        self.assertIn("gui.register.tab", held)
        self.assertIn("inspect.register.label", held)
        for key in held:
            self.assertNotIn(key, payload["send"])
        self.assertLessEqual(len(payload["send"]), payload["new"] + payload["changed"])
        send_unique = payload["send_unique"]
        self.assertEqual(
            payload["batches"],
            math.ceil(send_unique / 25) if send_unique else 0,
        )
        if send_unique:
            self.assertGreater(payload["est_input"], payload["est_output"])
            self.assertIn("cli.apex.help", payload["send"])

    def test_status_matches_dry_run_shape(self):
        runner = self._runner()
        result = runner.invoke(locale_cli, ["--json", "status", "de"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = _json(result)
        self.assertEqual(
            payload["new"] + payload["changed"] + payload["unchanged"],
            payload["keys"],
        )
        send_unique = payload["send_unique"]
        self.assertEqual(
            payload["batches"],
            math.ceil(send_unique / 25) if send_unique else 0,
        )
        self.assertEqual(payload["est_tokens"], payload["est_input"] + payload["est_output"])
        if send_unique:
            self.assertGreater(payload["est_input"], payload["est_output"])
        dry = runner.invoke(
            locale_cli,
            ["--json", "translate", "de", "--provider", "claude", "--dry-run"],
        )
        self.assertEqual(dry.exit_code, 0, dry.output)
        again = _json(dry)
        self.assertEqual(again["batches"], payload["batches"])
        self.assertEqual(again["est_input"], payload["est_input"])
        self.assertEqual(again["est_output"], payload["est_output"])

    def test_models_mocked_and_configure_rejects_unknown(self):
        runner = self._runner()

        def fake_get(url, headers=None, timeout=None):
            self.assertIn("api.openai.com", url)
            res = MagicMock()
            res.raise_for_status = MagicMock()
            res.json.return_value = {
                "data": [
                    {"id": "gpt-5.6-sol", "owned_by": "openai", "created": 1},
                    {"id": "text-embedding-3-small", "owned_by": "openai", "created": 2},
                    {"id": "gpt-5.6-terra", "owned_by": "openai", "created": 3},
                ]
            }
            return res

        with tempfile.TemporaryDirectory() as tmp:
            env = {"OPENAI_API_KEY": "sk-test"}
            with (
                patch("tools.providers.get_root", return_value=tmp),
                patch.dict(os.environ, env, clear=False),
                patch("tools.providers.requests.get", side_effect=fake_get),
            ):
                listed = runner.invoke(locale_cli, ["--json", "models", "--provider", "openai"])
                self.assertEqual(listed.exit_code, 0, listed.output)
                payload = _json(listed)
                ids = [row["id"] for row in payload["models"]]
                self.assertIn("gpt-5.6-sol", ids)
                self.assertIn("gpt-5.6-terra", ids)
                self.assertNotIn("text-embedding-3-small", ids)
                self.assertEqual(
                    next(row["mark"] for row in payload["models"] if row["id"] == "gpt-5.6-sol"),
                    "*",
                )
                bad = runner.invoke(
                    locale_cli,
                    ["configure", "--provider", "openai", "--model", "nope-model"],
                )
                self.assertEqual(bad.exit_code, 2, bad.output)
                good = runner.invoke(
                    locale_cli,
                    ["--json", "configure", "--provider", "openai", "--model", "gpt-5.6-terra"],
                )
                self.assertEqual(good.exit_code, 0, good.output)
                ack = _json(good)
                self.assertEqual(ack["model"], "gpt-5.6-terra")
                saved = json.loads((Path(tmp) / "locale.json").read_text(encoding="utf-8"))
                self.assertEqual(saved["providers"]["openai"]["model"], "gpt-5.6-terra")

    def test_models_missing_key_is_2(self):
        runner = self._runner()
        with tempfile.TemporaryDirectory() as tmp:
            env = {key: "" for key in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY")}
            with (
                patch("tools.providers.get_root", return_value=tmp),
                patch.dict(os.environ, env, clear=False),
            ):
                result = runner.invoke(locale_cli, ["models", "--provider", "claude"])
        self.assertEqual(result.exit_code, 2, result.output)
        self.assertIn("python tools/locale.py configure", result.output)

    def test_configure_show_does_not_print_secret(self):
        runner = self._runner()
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("tools.providers.get_root", return_value=tmp),
                patch.dict(os.environ, {"XAI_API_KEY": ""}, clear=False),
            ):
                result = runner.invoke(
                    locale_cli,
                    [
                        "configure",
                        "--provider",
                        "grok",
                        "--api-key",
                        "sekrit-value",
                        "--force-model",
                    ],
                )
                shown = runner.invoke(locale_cli, ["--json", "configure", "--provider", "grok"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertNotIn("sekrit-value", result.output)
        payload = _json(shown)
        self.assertEqual(payload["key_source"], "file")
        self.assertNotIn("sekrit-value", shown.output)
        self.assertNotIn("api_key", json.dumps(payload))

    def test_translate_mocked_updates_dst_and_tm_then_skips(self):
        runner = self._runner()
        src_doc = {
            "locale": "en",
            "source": "en",
            "messages": {
                "a.one": {"en": "Hello DNS", "text": "Hello DNS"},
                "a.two": {"en": "Hello DNS", "text": "Hello DNS"},
                "b.one": {"en": "Other {n}", "text": "Other {n}"},
            },
        }

        def fake_complete(provider, model, system, user, **_kwargs):
            messages = user.get("messages") or user
            out = {}
            for key, en in messages.items():
                out[key] = "DE " + en
            return out

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "en.json"
            dst = Path(tmp) / "de.json"
            src.write_text(json.dumps(src_doc), encoding="utf-8")
            env = {"ANTHROPIC_API_KEY": "sk-test"}
            with (
                patch("tools.providers.get_root", return_value=tmp),
                patch.dict(os.environ, env, clear=False),
                patch("tools.engine.complete_json", side_effect=fake_complete) as complete,
            ):
                first = runner.invoke(
                    locale_cli,
                    [
                        "--json",
                        "translate",
                        "de",
                        "--src",
                        str(src),
                        "--dst",
                        str(dst),
                        "--provider",
                        "claude",
                    ],
                )
                self.assertEqual(first.exit_code, 0, first.output)
                payload = _json(first)
                self.assertEqual(payload["send_unique"], 2)
                self.assertEqual(complete.call_count, 1)
                catalog = json.loads(dst.read_text(encoding="utf-8"))
                self.assertEqual(catalog["messages"]["a.one"]["text"], "DE Hello DNS")
                self.assertEqual(catalog["messages"]["a.two"]["text"], "DE Hello DNS")
                self.assertEqual(catalog["messages"]["a.one"]["en"], "Hello DNS")
                self.assertEqual(catalog["messages"]["b.one"]["text"], "DE Other {n}")
                tm = json.loads((Path(str(dst) + ".tm.json")).read_text(encoding="utf-8"))
                self.assertEqual(tm["provider"], "claude")
                self.assertEqual(tm["model"], "claude-sonnet-5")
                second = runner.invoke(
                    locale_cli,
                    [
                        "--json",
                        "translate",
                        "de",
                        "--src",
                        str(src),
                        "--dst",
                        str(dst),
                        "--provider",
                        "claude",
                    ],
                )
            self.assertEqual(second.exit_code, 0, second.output)
            again = _json(second)
            self.assertEqual(again["send"], [])
            self.assertEqual(complete.call_count, 1)

    def test_copy_through_skips_send_and_keeps_english(self):
        runner = self._runner()
        src_doc = {
            "locale": "en",
            "source": "en",
            "messages": {
                "gui.register.tab": {"en": "Register", "text": "Register"},
                "gui.mail.tab": {"en": "Mail", "text": "Mail"},
                "inspect.mail.label": {"en": "Mail", "text": "Mail"},
                "tech.dns": {"en": "DNS", "text": "DNS"},
                "x.help": {"en": "Look up the path", "text": "Look up the path"},
            },
        }

        def fake_complete(provider, model, system, user, **_kwargs):
            messages = user.get("messages") or user
            self.assertEqual(set(messages), {"x.help"})
            return {key: "DE " + en for key, en in messages.items()}

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "en.json"
            dst = Path(tmp) / "de.json"
            src.write_text(json.dumps(src_doc), encoding="utf-8")
            env = {"ANTHROPIC_API_KEY": "sk-test"}
            with (
                patch.dict(os.environ, env, clear=False),
                patch("tools.engine.complete_json", side_effect=fake_complete) as complete,
            ):
                result = runner.invoke(
                    locale_cli,
                    [
                        "--json",
                        "translate",
                        "de",
                        "--src",
                        str(src),
                        "--dst",
                        str(dst),
                        "--provider",
                        "claude",
                        "--all",
                    ],
                )
            self.assertEqual(result.exit_code, 0, result.output)
            payload = _json(result)
            self.assertEqual(payload["send"], ["x.help"])
            for key in (
                "gui.register.tab",
                "gui.mail.tab",
                "inspect.mail.label",
                "tech.dns",
            ):
                self.assertIn(key, payload["copy_through"])
                self.assertNotIn(key, payload["send"])
            self.assertEqual(complete.call_count, 1)
            catalog = json.loads(dst.read_text(encoding="utf-8"))
            self.assertEqual(catalog["messages"]["gui.register.tab"]["text"], "Register")
            self.assertEqual(catalog["messages"]["gui.mail.tab"]["text"], "Mail")
            self.assertEqual(catalog["messages"]["inspect.mail.label"]["text"], "Mail")
            self.assertEqual(catalog["messages"]["tech.dns"]["text"], "DNS")
            self.assertEqual(catalog["messages"]["x.help"]["text"], "DE Look up the path")

    def test_copy_through_rewrites_stale_nav_without_api(self):
        runner = self._runner()
        src_doc = {
            "locale": "en",
            "messages": {
                "gui.register.tab": {"en": "Register", "text": "Register"},
                "x.help": {"en": "Hello", "text": "Hello"},
            },
        }
        dst_doc = {
            "locale": "de",
            "messages": {
                "gui.register.tab": {"en": "Register", "text": "Registrieren"},
                "x.help": {"en": "Hello", "text": "Hallo"},
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "en.json"
            dst = Path(tmp) / "de.json"
            src.write_text(json.dumps(src_doc), encoding="utf-8")
            dst.write_text(json.dumps(dst_doc), encoding="utf-8")
            (Path(str(dst) + ".tm.json")).write_text(
                json.dumps(
                    {
                        "version": 1,
                        "keys": {
                            "gui.register.tab": {
                                "en_sha256": en_sha256("Register"),
                                "text": "Registrieren",
                            },
                            "x.help": {"en_sha256": en_sha256("Hello"), "text": "Hallo"},
                        },
                    }
                ),
                encoding="utf-8",
            )
            with patch("tools.engine.complete_json") as complete:
                result = runner.invoke(
                    locale_cli,
                    [
                        "--json",
                        "translate",
                        "de",
                        "--src",
                        str(src),
                        "--dst",
                        str(dst),
                        "--provider",
                        "claude",
                    ],
                )
            complete.assert_not_called()
            self.assertEqual(result.exit_code, 0, result.output)
            payload = _json(result)
            self.assertEqual(payload["send"], [])
            self.assertIn("gui.register.tab", payload["copy_through_dirty"])
            catalog = json.loads(dst.read_text(encoding="utf-8"))
            self.assertEqual(catalog["messages"]["gui.register.tab"]["text"], "Register")
            self.assertEqual(catalog["messages"]["x.help"]["text"], "Hallo")

    def test_verify_fail_exits_4(self):
        runner = self._runner()
        src_doc = {
            "locale": "en",
            "messages": {"x.help": {"en": "Look up DNS", "text": "Look up DNS"}},
        }

        def fake_complete(*_a, **_k):
            return {"x.help": "Nachschlagen"}

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "en.json"
            dst = Path(tmp) / "de.json"
            src.write_text(json.dumps(src_doc), encoding="utf-8")
            env = {"ANTHROPIC_API_KEY": "sk-test"}
            with (
                patch.dict(os.environ, env, clear=False),
                patch("tools.engine.complete_json", side_effect=fake_complete),
            ):
                result = runner.invoke(
                    locale_cli,
                    [
                        "--json",
                        "translate",
                        "de",
                        "--src",
                        str(src),
                        "--dst",
                        str(dst),
                        "--provider",
                        "claude",
                    ],
                )
        self.assertEqual(result.exit_code, 4, result.output)
        payload = _json(result)
        self.assertEqual(payload["failed"], ["x.help"])

    def test_verify_fail_json_does_not_confirm(self):
        runner = self._runner()
        src_doc = {
            "locale": "en",
            "messages": {"x.help": {"en": "Look up DNS", "text": "Look up DNS"}},
        }
        confirm = MagicMock()
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "en.json"
            dst = Path(tmp) / "de.json"
            src.write_text(json.dumps(src_doc), encoding="utf-8")
            env = {"ANTHROPIC_API_KEY": "sk-test"}
            with (
                patch.dict(os.environ, env, clear=False),
                patch("tools.engine.complete_json", return_value={"x.help": "Nachschlagen"}),
                patch("tools.locale.click.confirm", confirm),
            ):
                result = runner.invoke(
                    locale_cli,
                    [
                        "--json",
                        "translate",
                        "de",
                        "--src",
                        str(src),
                        "--dst",
                        str(dst),
                        "--provider",
                        "claude",
                    ],
                )
        confirm.assert_not_called()
        self.assertEqual(result.exit_code, 4, result.output)
        self.assertEqual(_json(result)["failed"], ["x.help"])

    def test_verify_fail_yes_leaves_tm_unstamped(self):
        runner = self._runner()
        src_doc = {
            "locale": "en",
            "messages": {"x.help": {"en": "Look up DNS", "text": "Look up DNS"}},
        }
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "en.json"
            dst = Path(tmp) / "de.json"
            src.write_text(json.dumps(src_doc), encoding="utf-8")
            env = {"ANTHROPIC_API_KEY": "sk-test"}
            with (
                patch.dict(os.environ, env, clear=False),
                patch("tools.engine.complete_json", return_value={"x.help": "Nachschlagen"}),
                patch("tools.locale._can_prompt", return_value=True),
                patch("tools.locale.click.confirm", return_value=True),
            ):
                result = runner.invoke(
                    locale_cli,
                    ["translate", "de", "--src", str(src), "--dst", str(dst), "--provider", "claude"],
                )
            self.assertEqual(result.exit_code, 4, result.output)
            tm = json.loads((Path(str(dst) + ".tm.json")).read_text(encoding="utf-8"))
            self.assertNotIn("x.help", tm.get("keys") or {})

    def test_verify_fail_no_stamps_tm_and_skips_next(self):
        runner = self._runner()
        src_doc = {
            "locale": "en",
            "messages": {"x.help": {"en": "Look up DNS", "text": "Look up DNS"}},
        }
        complete = MagicMock(return_value={"x.help": "Nachschlagen"})
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "en.json"
            dst = Path(tmp) / "de.json"
            src.write_text(json.dumps(src_doc), encoding="utf-8")
            env = {"ANTHROPIC_API_KEY": "sk-test"}
            with (
                patch.dict(os.environ, env, clear=False),
                patch("tools.engine.complete_json", complete),
                patch("tools.locale._can_prompt", return_value=True),
                patch("tools.locale.click.confirm", return_value=False),
            ):
                first = runner.invoke(
                    locale_cli,
                    ["translate", "de", "--src", str(src), "--dst", str(dst), "--provider", "claude"],
                )
            self.assertEqual(first.exit_code, 0, first.output)
            tm = json.loads((Path(str(dst) + ".tm.json")).read_text(encoding="utf-8"))
            self.assertIn("x.help", tm.get("keys") or {})
            with (
                patch.dict(os.environ, env, clear=False),
                patch("tools.engine.complete_json", complete),
            ):
                second = runner.invoke(
                    locale_cli,
                    [
                        "--json",
                        "translate",
                        "de",
                        "--src",
                        str(src),
                        "--dst",
                        str(dst),
                        "--provider",
                        "claude",
                    ],
                )
        self.assertEqual(second.exit_code, 0, second.output)
        self.assertEqual(_json(second)["send"], [])
        self.assertEqual(complete.call_count, 2)

    def test_env_key_wins_over_file(self):
        captured = []

        def fake_post(url, headers=None, json=None, timeout=None, stream=False):
            captured.append(headers)
            payload = __import__("json").dumps({"k.one": "DE Hello DNS"})
            chunk = __import__("json").dumps({"choices": [{"delta": {"content": payload}}]})
            res = MagicMock()
            res.raise_for_status = MagicMock()
            res.json.return_value = {"choices": [{"message": {"content": payload}}]}
            res.iter_lines.return_value = [f"data: {chunk}", "data: [DONE]"]
            return res

        src_doc = {
            "locale": "en",
            "messages": {"k.one": {"en": "Hello DNS", "text": "Hello DNS"}},
        }
        runner = self._runner()
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "en.json"
            dst = Path(tmp) / "de.json"
            src.write_text(json.dumps(src_doc), encoding="utf-8")
            cfg = {
                "providers": {
                    "openai": {"model": "gpt-5.6-sol", "api_key": "file-secret"},
                    "claude": {"model": "claude-sonnet-5", "api_key": None},
                    "grok": {"model": "grok-4.6", "api_key": None},
                }
            }
            (Path(tmp) / "locale.json").write_text(json.dumps(cfg), encoding="utf-8")
            env = {"OPENAI_API_KEY": "env-secret"}
            with (
                patch("tools.providers.get_root", return_value=tmp),
                patch.dict(os.environ, env, clear=False),
                patch("tools.providers.requests.post", side_effect=fake_post),
            ):
                result = runner.invoke(
                    locale_cli,
                    [
                        "--json",
                        "translate",
                        "de",
                        "--src",
                        str(src),
                        "--dst",
                        str(dst),
                        "--provider",
                        "openai",
                    ],
                )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(captured)
        auth = captured[0].get("Authorization")
        self.assertEqual(auth, "Bearer env-secret")
        self.assertNotIn("file-secret", json.dumps(captured))

    def test_human_status_omits_key_lists(self):
        runner = self._runner()
        result = runner.invoke(locale_cli, ["status", "de"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("🔍", result.output)
        self.assertIn("new", result.output)
        self.assertNotIn("new_keys", result.output)
        self.assertNotIn('"unchanged_keys"', result.output)
        self.assertIn("tokens", result.output)
        self.assertIn("estimate", result.output)
        self.assertIn("📦", result.output)
        self.assertTrue(
            "all caught up" in result.output
            or "python tools/locale.py translate de --provider grok" in result.output,
            result.output,
        )

    def test_human_configure_save_hides_secret(self):
        runner = self._runner()
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("tools.providers.get_root", return_value=tmp),
                patch.dict(os.environ, {"XAI_API_KEY": ""}, clear=False),
            ):
                result = runner.invoke(
                    locale_cli,
                    [
                        "configure",
                        "--provider",
                        "grok",
                        "--api-key",
                        "sekrit-value",
                        "--force-model",
                    ],
                )
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("✅", result.output)
        self.assertIn("grok", result.output)
        self.assertNotIn("sekrit-value", result.output)
        self.assertNotIn("{", result.output)

    def test_human_providers_shows_env_badge(self):
        runner = self._runner()

        def fake_get(url, headers=None, timeout=None):
            res = MagicMock()
            res.raise_for_status = MagicMock()
            res.json.return_value = {"data": [{"id": "grok-4.6"}]}
            return res

        with tempfile.TemporaryDirectory() as tmp:
            env = {
                "XAI_API_KEY": "env-secret",
                "ANTHROPIC_API_KEY": "",
                "OPENAI_API_KEY": "",
            }
            with (
                patch("tools.providers.get_root", return_value=tmp),
                patch.dict(os.environ, env, clear=False),
                patch("tools.providers.requests.get", side_effect=fake_get),
            ):
                result = runner.invoke(locale_cli, ["providers"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("🔌", result.output)
        self.assertIn("🔑", result.output)
        self.assertIn("env", result.output)
        self.assertIn("grok", result.output)
        self.assertNotIn("env-secret", result.output)

    def test_languages_json_is_curated_ship_list(self):
        runner = self._runner()
        result = runner.invoke(locale_cli, ["--json", "languages"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = _json(result)
        rows = payload["languages"]
        codes = [row["code"] for row in rows]
        self.assertEqual(codes, ["de", "fr", "es", "ja", "pt"])
        by_code = {row["code"]: row for row in rows}
        self.assertEqual(by_code["de"]["english"], "German")
        self.assertIn("Deutsch", by_code["de"]["native"])
        self.assertIn("Brazilian", by_code["pt"]["prompt"])
        self.assertIn("pt-BR", by_code["pt"]["style"])
        self.assertNotIn("en", by_code)
        self.assertNotIn("qaa", by_code)
        self.assertNotIn("ko", by_code)
        self.assertEqual(by_code["de"]["shipped"], (package_locales_dir() / "de.json").is_file())
        self.assertNotIn("send", by_code["de"])
        self.assertNotIn("new_keys", by_code["de"])
        for code in ("de", "pt"):
            status = runner.invoke(locale_cli, ["--json", "status", code])
            self.assertEqual(status.exit_code, 0, status.output)
            expected = _json(status)
            row = by_code[code]
            self.assertEqual(row["batches"], expected["batches"])
            self.assertEqual(row["batch_size"], expected["batch_size"])
            self.assertEqual(row["est_input"], expected["est_input"])
            self.assertEqual(row["est_output"], expected["est_output"])
            self.assertEqual(row["est_tokens"], expected["est_tokens"])

    def test_languages_human_columns_align(self):
        self.assertEqual(_display_width("日本語"), 6)
        self.assertEqual(_display_width("português"), 9)
        runner = self._runner()
        result = runner.invoke(locale_cli, ["languages"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("batches", result.output)
        self.assertIn("in /", result.output)
        body = [line for line in result.output.splitlines() if line and not line.startswith("🌐")]
        self.assertEqual(len(body), 5)
        widths = {_display_width(line) for line in body}
        self.assertEqual(len(widths), 1, result.output)

    def test_status_unknown_locale_fails(self):
        runner = self._runner()
        result = runner.invoke(locale_cli, ["status", "ko"])
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("ship_langs.py", result.output)

    def test_translate_unknown_locale_fails(self):
        runner = self._runner()
        result = runner.invoke(
            locale_cli,
            ["translate", "ko", "--provider", "grok", "--dry-run"],
        )
        self.assertNotEqual(result.exit_code, 0)
        self.assertIn("ship_langs.py", result.output)

    def _write_generated(self, pkg: Path, *, en: str, de_text: str, tm_en: str) -> None:
        pkg.mkdir(parents=True, exist_ok=True)
        (pkg / "en.json").write_text(
            json.dumps(
                {
                    "locale": "en",
                    "source": "en",
                    "messages": {"k.one": {"en": en, "text": en}},
                }
            ),
            encoding="utf-8",
        )
        (pkg / "de.json").write_text(
            json.dumps(
                {
                    "locale": "de",
                    "source": "en",
                    "messages": {"k.one": {"en": en, "text": de_text}},
                }
            ),
            encoding="utf-8",
        )
        (pkg / "de.json.tm.json").write_text(
            json.dumps(
                {
                    "version": 1,
                    "keys": {"k.one": {"en_sha256": en_sha256(tm_en), "text": de_text}},
                }
            ),
            encoding="utf-8",
        )

    def test_status_all_lists_generated_and_stale(self):
        runner = self._runner()
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "pkg"
            self._write_generated(pkg, en="Hello", de_text="Hallo", tm_en="Hello")
            with patch("looking_glass.i18n.catalog.PACKAGE_LOCALES", pkg):
                caught = runner.invoke(locale_cli, ["--json", "status"])
                self.assertEqual(caught.exit_code, 0, caught.output)
                payload = _json(caught)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["stale"], [])
                self.assertEqual([row["lang"] for row in payload["langs"]], ["de"])
                self.assertEqual(payload["langs"][0]["new"], 0)
                self.assertEqual(payload["langs"][0]["changed"], 0)
                self._write_generated(pkg, en="Hello now", de_text="Hallo", tm_en="Hello")
                stale = runner.invoke(locale_cli, ["--json", "status"])
                self.assertEqual(stale.exit_code, 1, stale.output)
                again = _json(stale)
                self.assertFalse(again["ok"])
                self.assertEqual(again["stale"], ["de"])
                self.assertEqual(again["langs"][0]["changed"], 1)
                self.assertNotIn("ja", [row["lang"] for row in again["langs"]])

    def test_translate_all_dry_run_skips_api_when_caught_up(self):
        runner = self._runner()
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "pkg"
            self._write_generated(pkg, en="Hello", de_text="Hallo", tm_en="Hello")
            with (
                patch("looking_glass.i18n.catalog.PACKAGE_LOCALES", pkg),
                patch("tools.engine.complete_json") as complete,
            ):
                result = runner.invoke(
                    locale_cli,
                    ["--json", "translate", "--provider", "claude", "--dry-run"],
                )
            complete.assert_not_called()
            self.assertEqual(result.exit_code, 0, result.output)
            payload = _json(result)
            self.assertTrue(payload["ok"])
            self.assertEqual(len(payload["langs"]), 1)
            self.assertEqual(payload["langs"][0]["lang"], "de")
            self.assertEqual(payload["langs"][0]["send"], [])

    def test_reset_deletes_dst_and_tm_never_en(self):
        runner = self._runner()
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "pkg"
            pkg.mkdir()
            (pkg / "en.json").write_text('{"locale":"en","messages":{}}', encoding="utf-8")
            (pkg / "de.json").write_text('{"locale":"de","messages":{}}', encoding="utf-8")
            (pkg / "de.json.tm.json").write_text('{"version":1,"keys":{}}', encoding="utf-8")
            (pkg / "fr.json").write_text('{"locale":"fr","messages":{}}', encoding="utf-8")
            (pkg / "fr.json.tm.json").write_text('{"version":1,"keys":{}}', encoding="utf-8")
            with patch("looking_glass.i18n.catalog.PACKAGE_LOCALES", pkg):
                one = runner.invoke(locale_cli, ["--json", "reset", "de"])
                self.assertEqual(one.exit_code, 0, one.output)
                payload = _json(one)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["langs"], ["de"])
                self.assertFalse((pkg / "de.json").is_file())
                self.assertFalse((pkg / "de.json.tm.json").is_file())
                self.assertTrue((pkg / "en.json").is_file())
                self.assertTrue((pkg / "fr.json").is_file())
                blocked = runner.invoke(locale_cli, ["--json", "reset", "en"])
                self.assertNotEqual(blocked.exit_code, 0, blocked.output)
                self.assertTrue((pkg / "en.json").is_file())
                all_langs = runner.invoke(locale_cli, ["--json", "reset"])
            self.assertEqual(all_langs.exit_code, 0, all_langs.output)
            gone = _json(all_langs)
            self.assertIn("fr", gone["langs"])
            self.assertNotIn("en", gone["langs"])
            self.assertFalse((pkg / "fr.json").is_file())
            self.assertFalse((pkg / "fr.json.tm.json").is_file())
            self.assertTrue((pkg / "en.json").is_file())

    def test_harvest_mentions_stale_generated_langs(self):
        runner = self._runner()
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "pkg"
            self._write_generated(pkg, en="Old hello", de_text="Hallo", tm_en="Old hello")
            with (
                patch("looking_glass.i18n.catalog.get_root", return_value=str(Path(tmp) / "op")),
                patch("looking_glass.i18n.catalog.PACKAGE_LOCALES", pkg),
            ):
                blob = runner.invoke(locale_cli, ["--json", "harvest"])
                self.assertEqual(blob.exit_code, 0, blob.output)
                payload = _json(blob)
                self.assertTrue(payload["ok"])
                self.assertIn("de", payload["stale"])
                human = runner.invoke(locale_cli, ["harvest"])
            self.assertEqual(human.exit_code, 0, human.output)
            self.assertIn("de", human.output)
            self.assertIn("python tools/locale.py translate --provider grok", human.output)


class CompleteJsonTests(unittest.TestCase):
    def test_grok_streams_sse_high_effort_and_timeout_tuple(self):
        captured: dict = {}

        def fake_post(url, headers=None, json=None, timeout=None, stream=False):
            captured["url"] = url
            captured["headers"] = dict(headers or {})
            captured["body"] = json
            captured["timeout"] = timeout
            captured["stream"] = stream
            chunk = __import__("json").dumps({"choices": [{"delta": {"content": '{"a":"x"}'}}]})
            res = MagicMock()
            res.raise_for_status = MagicMock()
            res.iter_lines.return_value = [f"data: {chunk}", "data: [DONE]"]
            return res

        env = {"XAI_API_KEY": "xai-test"}
        with patch.dict(os.environ, env, clear=False), patch("tools.providers.requests.post", side_effect=fake_post):
            out = complete_json("grok", "grok-4.6", "sys", {"messages": {"a": "hi"}}, lang="de")
        self.assertEqual(out, {"a": "x"})
        self.assertTrue(captured["stream"])
        self.assertEqual(captured["timeout"], (CONNECT_TIMEOUT, DEFAULT_READ_TIMEOUT))
        self.assertTrue(captured["body"]["stream"])
        self.assertEqual(captured["body"]["reasoning_effort"], "high")
        self.assertEqual(captured["headers"]["x-grok-conv-id"], "looking-glass-locale-de")
        self.assertIn("api.x.ai", captured["url"])

    def test_grok_reasoning_effort_low_override(self):
        captured: dict = {}

        def fake_post(url, headers=None, json=None, timeout=None, stream=False):
            captured["body"] = json
            res = MagicMock()
            res.raise_for_status = MagicMock()
            chunk = __import__("json").dumps({"choices": [{"delta": {"content": '{"a":"x"}'}}]})
            res.iter_lines.return_value = [f"data: {chunk}", "data: [DONE]"]
            return res

        env = {"XAI_API_KEY": "xai-test"}
        with patch.dict(os.environ, env, clear=False), patch("tools.providers.requests.post", side_effect=fake_post):
            complete_json(
                "grok",
                "grok-4.6",
                "sys",
                {"messages": {"a": "hi"}},
                lang="de",
                reasoning_effort="low",
            )
        self.assertEqual(captured["body"]["reasoning_effort"], "low")

    def test_grok_stream_keeps_utf8_umlauts(self):
        payload = json.dumps({"a": "prüfen"}, ensure_ascii=False)
        chunk = json.dumps({"choices": [{"delta": {"content": payload}}]}, ensure_ascii=False)
        line = f"data: {chunk}".encode("utf-8")

        def fake_post(url, headers=None, json=None, timeout=None, stream=False):
            res = MagicMock()
            res.raise_for_status = MagicMock()
            res.iter_lines.return_value = [line, b"data: [DONE]"]
            return res

        env = {"XAI_API_KEY": "xai-test"}
        with patch.dict(os.environ, env, clear=False), patch("tools.providers.requests.post", side_effect=fake_post):
            out = complete_json("grok", "grok-4.6", "sys", {"messages": {"a": "check"}}, lang="de")
        self.assertEqual(out, {"a": "prüfen"})
        self.assertNotIn("Ã", out["a"])

    def test_claude_does_not_stream(self):
        captured: dict = {}

        def fake_post(url, headers=None, json=None, timeout=None, stream=False):
            captured["body"] = json
            captured["timeout"] = timeout
            captured["stream"] = stream
            res = MagicMock()
            res.raise_for_status = MagicMock()
            res.json.return_value = {
                "content": [{"type": "text", "text": '{"a":"y"}'}],
            }
            return res

        env = {"ANTHROPIC_API_KEY": "sk-test"}
        with patch.dict(os.environ, env, clear=False), patch("tools.providers.requests.post", side_effect=fake_post):
            out = complete_json("claude", "claude-sonnet-5", "sys", {"messages": {"a": "hi"}}, timeout=99)
        self.assertEqual(out, {"a": "y"})
        self.assertFalse(captured["stream"])
        self.assertEqual(captured["timeout"], (CONNECT_TIMEOUT, 99))
        self.assertNotIn("stream", captured["body"])
        self.assertNotIn("reasoning_effort", captured["body"])

    def test_read_timeout_is_explicit(self):
        import requests as req

        def fake_post(*_a, **_k):
            raise req.ReadTimeout("Read timed out. (read timeout=3600.0)")

        env = {"XAI_API_KEY": "xai-test"}
        with patch.dict(os.environ, env, clear=False), patch("tools.providers.requests.post", side_effect=fake_post):
            with self.assertRaises(ProviderError) as ctx:
                complete_json("grok", "grok-4.6", "sys", {"messages": {"a": "hi"}}, lang="de")
        self.assertIn("still thinking", str(ctx.exception))
        self.assertIn("read timeout", str(ctx.exception))
