import asyncio
import os
import tempfile
import unittest
from unittest.mock import patch

from looking_glass.dns.reputation import (
    classify_a_records,
    default_rbl_map,
    reverse_for_dnsbl,
    check_rbls,
    status_from_flags,
    overall_status,
    explain,
    verdict_action,
)


class ReverseTests(unittest.TestCase):
    def test_ipv4(self):
        self.assertEqual(reverse_for_dnsbl("8.8.4.4"), "4.4.8.8")

    def test_ipv6(self):
        rev = reverse_for_dnsbl("2001:db8::1")
        self.assertTrue(rev.startswith("1.0.0.0."))
        self.assertIn("8.b.d.0.1.0.0.2", rev)
        self.assertEqual(len(rev.split(".")), 32)


class ClassifyTests(unittest.TestCase):
    def test_nxdomain_is_clean(self):
        self.assertEqual(classify_a_records([]), ("clean", [], None))

    def test_listing_codes(self):
        status, addrs, err = classify_a_records(["127.0.0.2", "127.0.0.4"])
        self.assertEqual(status, "listed")
        self.assertEqual(addrs, ["127.0.0.2", "127.0.0.4"])
        self.assertIsNone(err)

    def test_spamhaus_public_resolver_is_error(self):
        status, addrs, err = classify_a_records(["127.255.255.254"])
        self.assertEqual(status, "error")
        self.assertEqual(addrs, [])
        self.assertIn("public resolver", err)

    def test_query_error_outranks_listing_code(self):
        status, addrs, err = classify_a_records(["127.0.0.10", "127.255.255.254"])
        self.assertEqual(status, "error")
        self.assertEqual(addrs, [])
        self.assertIn("public resolver", err)

    def test_interceptor_is_error(self):
        status, addrs, err = classify_a_records(["1.2.3.4"])
        self.assertEqual(status, "error")
        self.assertEqual(addrs, [])
        self.assertIn("127/8", err)


class VerdictTests(unittest.TestCase):
    def test_allowed(self):
        self.assertEqual(status_from_flags([], query_status="clean"), "allowed")

    def test_policy_pbl_only(self):
        self.assertEqual(status_from_flags(["PBL"], query_status="listed"), "policy")

    def test_blocked_sbl(self):
        self.assertEqual(status_from_flags(["SBL"], query_status="listed"), "blocked")

    def test_drop_outranks(self):
        self.assertEqual(
            status_from_flags(["PBL", "DROP", "SBL"], query_status="listed"),
            "drop",
        )

    def test_unknown(self):
        self.assertEqual(status_from_flags([], query_status="error"), "unknown")

    def test_overall_picks_worst(self):
        self.assertEqual(
            overall_status(
                {
                    "a": {"status": "allowed"},
                    "b": {"status": "policy"},
                    "c": {"status": "drop"},
                }
            ),
            "drop",
        )


class ExplainTests(unittest.TestCase):
    def test_lists_flags_and_zone(self):
        text = explain(
            {
                "status": "drop",
                "flags": ["DROP"],
                "listed_on": ["Spamhaus ZEN"],
                "txt": ["https://www.spamhaus.org/drop/"],
            }
        )
        self.assertIn("reputation drop", text)
        self.assertIn("DROP", text)
        self.assertIn("Spamhaus ZEN", text)
        self.assertIn("spamhaus.org", text)

    def test_allowed_is_not_an_action(self):
        self.assertIsNone(
            verdict_action({"ok": True, "listed": False, "status": "allowed"})
        )
        self.assertIsNone(
            verdict_action({"ok": True, "listed": False, "status": "blocked"})
        )
        self.assertEqual(
            verdict_action(
                {"ok": True, "listed": True, "status": "drop", "flags": ["DROP"]}
            ),
            "block",
        )

    def test_open_resolver_txt_is_not_an_action(self):
        self.assertIsNone(
            verdict_action(
                {
                    "ok": True,
                    "listed": True,
                    "status": "policy",
                    "flags": ["PBL"],
                    "listed_on": ["Spamhaus ZEN"],
                    "txt": [
                        "Error: open resolver; https://check.spamhaus.org/returnc/pub/2001:19f0:1000:963e:5400:5ff:fe95:6a60/"
                    ],
                }
            )
        )


class DefaultMapTests(unittest.TestCase):
    def test_ipv4_includes_major_lists(self):
        zones = default_rbl_map(4)
        self.assertIn("Spamhaus ZEN", zones)
        self.assertEqual(zones["Spamhaus ZEN"], "zen.spamhaus.org")
        self.assertIn("Barracuda BRBL", zones)
        self.assertIn("SpamCop", zones)
        self.assertIn("DroneBL", zones)
        self.assertIn("Mailspike", zones)
        self.assertIn("PSBL", zones)
        self.assertIn("SORBS", zones)

    def test_ipv6_skips_ipv4_only(self):
        zones = default_rbl_map(6)
        self.assertIn("Spamhaus ZEN", zones)
        self.assertIn("DroneBL", zones)
        self.assertNotIn("Barracuda BRBL", zones)
        self.assertNotIn("SpamCop", zones)

    def test_dqs_key_rewrites_spamhaus(self):
        with patch.dict(os.environ, {"SPAMHAUS_DQS_KEY": "abc123"}, clear=False):
            zones = default_rbl_map(4)
        self.assertEqual(zones["Spamhaus ZEN"], "abc123.zen.dq.spamhaus.net")


class CheckRblsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        def cache_path(name: str) -> str:
            return os.path.join(self.tmp.name, name)

        self.cache_patch = patch("looking_glass.cache.get_cache_path", side_effect=cache_path)
        self.cache_patch.start()
        self.addCleanup(self.cache_patch.stop)

    def test_invalid_ip(self):
        out = check_rbls("not-an-ip")
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "invalid ip")
        self.assertEqual(out["status"], "unknown")

    def test_listed_and_clean(self):
        async def fake_resolve(name, rdtype, timeout, resolver=None):
            if rdtype == "TXT":
                return ["Listed by SBL, see https://check.spamhaus.org/"], None
            if name.startswith("2.0.0.127."):
                return ["127.0.0.2"], None
            return [], None

        with patch("looking_glass.dns.reputation._resolve_rr", side_effect=fake_resolve):
            out = check_rbls("127.0.0.2", {"Spamhaus ZEN": "zen.spamhaus.org"}, force=True)
        self.assertTrue(out["ok"])
        self.assertEqual(out["status"], "blocked")
        self.assertEqual(out["flags"], ["SBL"])
        self.assertTrue(out["txt"])
        self.assertTrue(out["listed"])
        self.assertEqual(out["listed_on"], ["Spamhaus ZEN"])
        info = out["result"]["Spamhaus ZEN"]
        self.assertTrue(info["listed"])
        self.assertEqual(info["status"], "blocked")
        self.assertEqual(info["query"], "2.0.0.127.zen.spamhaus.org")
        self.assertEqual(info["codes"][0]["reason"], "SBL")
        self.assertTrue(info["txt"])

        with patch("looking_glass.dns.reputation._resolve_rr", side_effect=fake_resolve):
            clean = check_rbls("8.8.4.4", {"Spamhaus ZEN": "zen.spamhaus.org"}, force=True)
        self.assertTrue(clean["ok"])
        self.assertEqual(clean["status"], "allowed")
        self.assertFalse(clean["listed"])
        self.assertEqual(clean["result"]["Spamhaus ZEN"]["status"], "allowed")
        self.assertEqual(clean["result"]["Spamhaus ZEN"]["query"], "4.4.8.8.zen.spamhaus.org")

    def test_open_resolver_txt_is_unknown_not_listed(self):
        txt = [
            "Error: open resolver; https://check.spamhaus.org/returnc/pub/2001:19f0:1000:963e:5400:5ff:fe95:6a60/"
        ]

        async def fake_resolve(name, rdtype, timeout, resolver=None):
            if rdtype == "TXT":
                return txt, None
            return ["127.0.0.10"], None

        with patch("looking_glass.dns.reputation._resolve_rr", side_effect=fake_resolve):
            out = check_rbls(
                "8.8.8.8", {"Spamhaus ZEN": "zen.spamhaus.org"}, force=True
            )
        zen = out["result"]["Spamhaus ZEN"]
        self.assertTrue(out["ok"])
        self.assertEqual(out["status"], "unknown")
        self.assertFalse(out["listed"])
        self.assertEqual(out["listed_on"], [])
        self.assertGreaterEqual(out["errors"], 1)
        self.assertEqual(zen["status"], "unknown")
        self.assertFalse(zen["listed"])
        self.assertIn("open resolver", (zen.get("error") or "").lower() + " ".join(zen.get("txt") or []).lower())
        self.assertIsNone(verdict_action(out))

        with patch("looking_glass.dns.reputation._resolve_rr", side_effect=fake_resolve):
            again = check_rbls("8.8.8.8", {"Spamhaus ZEN": "zen.spamhaus.org"})
        self.assertFalse(again["cached"])

    def test_drop_and_pbl(self):
        async def fake_resolve(name, rdtype, timeout, resolver=None):
            if rdtype == "TXT":
                return ["Listed by PBL, see https://check.spamhaus.org/query/ip/193.32.162.159"], None
            if rdtype == "A":
                return ["127.0.0.11", "127.0.0.9", "127.0.0.2"], None
            return [], None

        with patch("looking_glass.dns.reputation._resolve_rr", side_effect=fake_resolve):
            out = check_rbls("193.32.162.159", {"Spamhaus ZEN": "zen.spamhaus.org"}, force=True)
        self.assertEqual(out["status"], "drop")
        self.assertEqual(out["flags"], ["PBL", "DROP", "SBL"])
        self.assertEqual(out["result"]["Spamhaus ZEN"]["status"], "drop")
        self.assertTrue(out["txt"][0].startswith("Listed by PBL"))

    def test_ipv6_marks_ipv4_only_zones_skipped(self):
        async def fake_resolve(name, rdtype, timeout, resolver=None):
            return [], None

        with patch("looking_glass.dns.reputation._resolve_rr", side_effect=fake_resolve):
            out = check_rbls("2001:db8::1", force=True)
        self.assertTrue(out["ok"])
        self.assertEqual(out["result"]["Barracuda BRBL"]["status"], "skipped")
        self.assertEqual(out["result"]["SpamCop"]["status"], "skipped")
        self.assertEqual(out["result"]["Spamhaus ZEN"]["status"], "allowed")
        rev = reverse_for_dnsbl("2001:db8::1")
        self.assertTrue(out["result"]["Spamhaus ZEN"]["query"].startswith(rev + "."))

    def test_cache_hit_and_force(self):
        calls = {"n": 0}

        async def fake_resolve(name, rdtype, timeout, resolver=None):
            calls["n"] += 1
            return [], None

        with patch("looking_glass.dns.reputation._resolve_rr", side_effect=fake_resolve):
            first = check_rbls("9.9.9.9", {"Spamhaus ZEN": "zen.spamhaus.org"}, force=True)
            cached = check_rbls("9.9.9.9", {"Spamhaus ZEN": "zen.spamhaus.org"})
            forced = check_rbls("9.9.9.9", {"Spamhaus ZEN": "zen.spamhaus.org"}, force=True)
        self.assertFalse(first["cached"])
        self.assertTrue(cached["cached"])
        self.assertEqual(cached["status"], "allowed")
        self.assertFalse(forced["cached"])
        self.assertGreater(calls["n"], 0)
        self.assertGreater(forced["fetched_at"], 0)


class CheckDomainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

        def cache_path(name: str) -> str:
            return os.path.join(self.tmp.name, name)

        self.cache_patch = patch(
            "looking_glass.cache.get_cache_path", side_effect=cache_path
        )
        self.cache_patch.start()
        self.addCleanup(self.cache_patch.stop)

    def test_listed_and_clean(self):
        from looking_glass.dns.reputation import check_domain

        async def fake_resolve(name, rdtype, timeout, resolver=None):
            if rdtype == "TXT":
                return [], None
            if name.startswith("listed.example."):
                return ["127.0.1.2"], None
            return [], None

        with patch("looking_glass.dns.reputation._resolve_rr", side_effect=fake_resolve):
            out = check_domain(
                "listed.example", {"Spamhaus DBL": "dbl.spamhaus.org"}, force=True
            )
        self.assertTrue(out["ok"])
        self.assertEqual(out["domain"], "listed.example")
        self.assertEqual(out["status"], "blocked")
        self.assertEqual(out["flags"], ["spam"])
        self.assertTrue(out["listed"])
        self.assertEqual(out["listed_on"], ["Spamhaus DBL"])

        with patch("looking_glass.dns.reputation._resolve_rr", side_effect=fake_resolve):
            clean = check_domain(
                "example.com", {"Spamhaus DBL": "dbl.spamhaus.org"}, force=True
            )
        self.assertTrue(clean["ok"])
        self.assertEqual(clean["status"], "allowed")
        self.assertFalse(clean["listed"])

    def test_invalid_domain(self):
        from looking_glass.dns.reputation import check_domain

        out = check_domain("not a name")
        self.assertFalse(out["ok"])
        self.assertEqual(out["status"], "unknown")


class SystemResolverTests(unittest.TestCase):
    def test_dns_resolver_uses_system_targets(self):
        from looking_glass.dns import reputation

        class FakeResolver:
            def __init__(self, configure=True):
                self.nameservers = ["8.8.8.8"]
                self.nameserver_ports = {}
                self.lifetime = None
                self.timeout = None

        with patch(
            "looking_glass.dns.reputation.system_resolver_targets",
            return_value=[("127.0.0.1", 53), ("10.0.0.53", 5353)],
        ), patch("dns.asyncresolver.Resolver", FakeResolver):
            resolver = reputation.dns_resolver(1.5)
        self.assertEqual(resolver.nameservers, ["127.0.0.1", "10.0.0.53"])
        self.assertEqual(
            resolver.nameserver_ports,
            {"127.0.0.1": 53, "10.0.0.53": 5353},
        )
        self.assertEqual(resolver.lifetime, 1.5)


class SenderScoreTests(unittest.TestCase):
    def test_parses_127_0_4_score(self):
        from looking_glass.dns.reputation import lookup_sender_score

        async def fake_resolve(name, rdtype, timeout, resolver=None):
            self.assertTrue(name.endswith(".score.senderscore.com"))
            return ["127.0.4.87"], None

        with patch("looking_glass.dns.reputation._resolve_rr", side_effect=fake_resolve):
            out = asyncio.run(lookup_sender_score("8.8.8.8"))
        self.assertTrue(out["ok"])
        self.assertEqual(out["score"], 87)

    def test_255_is_not_a_score(self):
        from looking_glass.dns.reputation import lookup_sender_score

        async def fake_resolve(name, rdtype, timeout, resolver=None):
            return ["127.255.255.255"], None

        with patch("looking_glass.dns.reputation._resolve_rr", side_effect=fake_resolve):
            out = asyncio.run(lookup_sender_score("1.1.1.1"))
        self.assertFalse(out["ok"])
        self.assertIsNone(out["score"])
        self.assertEqual(out["answer"], "127.255.255.255")

    def test_uribl_query_refused_txt(self):
        from looking_glass.dns.reputation import query_error_from_txt

        self.assertEqual(
            query_error_from_txt(["Query Refused"]),
            "query refused",
        )

    def test_127_0_0_1_is_query_error(self):
        status, addrs, err = classify_a_records(["127.0.0.1"])
        self.assertEqual(status, "error")
        self.assertEqual(addrs, [])
        self.assertTrue(err)


if __name__ == "__main__":
    unittest.main()
