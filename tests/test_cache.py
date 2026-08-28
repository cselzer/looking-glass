import json
import os
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass import cache
from looking_glass.cli.entry import cli
from looking_glass.intel import bgp


def _env(tmp: str):
    return (
        patch("looking_glass.config.get_root", return_value=tmp),
        patch("looking_glass.cache.get_cache_path", side_effect=lambda name: os.path.join(tmp, "data", name)),
    )


class CacheConfigTests(unittest.TestCase):
    def test_writes_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            patches = _env(tmp)
            with patches[0], patches[1]:
                cfg = cache.load_config()
            self.assertEqual(cfg["ttl_days"], 7)
            self.assertFalse(cfg["gui"])
            path = os.path.join(tmp, "config.json")
            self.assertTrue(os.path.isfile(path))
            self.assertFalse(os.path.isfile(os.path.join(tmp, "data", "cache.json")))
            with open(path, encoding="utf-8") as handle:
                written = json.load(handle)
            self.assertEqual(written["cache"]["ttl_days"], 7)
            self.assertFalse(written["cache"]["gui"])

    def test_ttl_zero_always_misses(self):
        with tempfile.TemporaryDirectory() as tmp:
            patches = _env(tmp)
            with patches[0], patches[1]:
                cache.put("rdap", "ip_1.1.1.1", {"handle": "NET"})
                with open(os.path.join(tmp, "config.json"), "w", encoding="utf-8") as handle:
                    json.dump(
                        {
                            "locale": "en",
                            "cache": {"ttl_days": 0, "gui": False},
                            "refresh": {"iana": 30, "dns_types": 30, "rir": 1, "asn_org": 7, "asn": 1},
                        },
                        handle,
                    )
                self.assertIsNone(cache.get("rdap", "ip_1.1.1.1"))
                self.assertEqual(cache.get_any("rdap", "ip_1.1.1.1")["handle"], "NET")


class CacheStoreTests(unittest.TestCase):
    def test_get_put_stats_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            patches = _env(tmp)
            with patches[0], patches[1]:
                cache.put("rdap", "ip_1.1.1.1", {"handle": "NET"})
                cache.put("bgp", "1.1.1.1", {"query": "1.1.1.1"})
                self.assertEqual(cache.get("rdap", "ip_1.1.1.1")["handle"], "NET")
                self.assertEqual(cache.get("bgp", "1.1.1.1")["query"], "1.1.1.1")
                all_stats = cache.stats()
                self.assertEqual(all_stats["count"], 2)
                self.assertEqual(all_stats["ttl_days"], 7)
                self.assertFalse(all_stats["gui"])
                self.assertTrue(all_stats["config"].endswith("config.json"))
                self.assertEqual(all_stats["directory"], os.path.join(tmp, "data", "cache"))
                self.assertTrue(os.path.isfile(cache.entry_path("rdap", "ip_1.1.1.1")))
                self.assertTrue(os.path.isfile(cache.entry_path("bgp", "1.1.1.1")))
                self.assertFalse(os.path.isdir(os.path.join(tmp, "data", "rdap")))
                self.assertFalse(os.path.isdir(os.path.join(tmp, "data", "bgp")))
                rdap_stats = cache.stats("rdap")
                self.assertEqual(rdap_stats["count"], 1)
                self.assertEqual(rdap_stats["files"][0]["kind"], "ip")
                self.assertEqual(rdap_stats["files"][0]["query"], "1.1.1.1")
                one = cache.clear("bgp", "1.1.1.1.json")
                self.assertTrue(one["ok"])
                self.assertEqual(one["count"], 0)
                gone = cache.clear()
                self.assertTrue(gone["ok"])
                self.assertEqual(gone["count"], 0)

    def test_migrates_legacy_namespace_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            patches = _env(tmp)
            with patches[0], patches[1]:
                legacy = os.path.join(tmp, "data", "rdap")
                os.makedirs(legacy)
                with open(os.path.join(legacy, "ip_1.1.1.1.json"), "w", encoding="utf-8") as handle:
                    json.dump({"_cached_at": 1, "data": {"handle": "NET"}}, handle)
                dest = cache.layout_dir("rdap")
                self.assertEqual(dest, os.path.join(tmp, "data", "cache", "rdap"))
                self.assertTrue(os.path.isfile(os.path.join(dest, "ip_1.1.1.1.json")))
                self.assertFalse(os.path.isdir(legacy))
                self.assertEqual(cache.stats("rdap")["count"], 1)
                self.assertEqual(cache.stats()["directory"], os.path.join(tmp, "data", "cache"))


class BgpCacheTests(unittest.TestCase):
    def test_check_bgp_uses_cache_and_stale_fallback(self):
        overview = {
            "resource": "1.1.1.0/24",
            "announced": True,
            "asns": [{"asn": 13335, "holder": "CLOUDFLARENET"}],
            "holder": "CLOUDFLARENET",
            "block": {"resource": "1.1.1.0/24"},
        }
        rpki = {"status": "valid", "validator": "ripe", "validating_roas": []}

        def fake_get(url, timeout=8.0):
            if "prefix-overview" in url:
                return overview
            return rpki

        with tempfile.TemporaryDirectory() as tmp:
            patches = _env(tmp)
            with patches[0], patches[1]:
                with patch("looking_glass.intel.bgp._get", side_effect=fake_get) as get:
                    first = bgp.check_bgp("1.1.1.1")
                    second = bgp.check_bgp("1.1.1.1")
                self.assertTrue(first["ok"])
                self.assertEqual(first["result"]["origin_asn"], 13335)
                self.assertEqual(second["result"]["prefix"], "1.1.1.0/24")
                self.assertEqual(get.call_count, 2)
                with patch("looking_glass.intel.bgp._get", side_effect=RuntimeError("down")):
                    stale = bgp.check_bgp("1.1.1.1")
                self.assertTrue(stale["ok"])
                self.assertEqual(stale["result"]["origin_asn"], 13335)


class CacheCliTests(unittest.TestCase):
    def test_stats_clear(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            patches = _env(tmp)
            with patches[0], patches[1]:
                cache.put("rdap", "ip_1.1.1.1", {"handle": "NET"})
                stats = runner.invoke(cli, ["--json", "cache", "stats"])
                self.assertEqual(stats.exit_code, 0, stats.output)
                payload = json.loads(stats.output)
                self.assertTrue(payload["ok"])
                self.assertEqual(payload["count"], 1)
                self.assertTrue(payload["config"].endswith("config.json"))
                cleared = runner.invoke(cli, ["--json", "cache", "clear", "rdap"])
                self.assertEqual(cleared.exit_code, 0, cleared.output)
                empty = json.loads(cleared.output)
                self.assertTrue(empty["ok"])
                self.assertEqual(empty["count"], 0)
            missing = runner.invoke(cli, ["--json", "cache", "config"])
            self.assertNotEqual(missing.exit_code, 0)
