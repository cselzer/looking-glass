import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from looking_glass.intel import rdap


class RdapHelpers(unittest.TestCase):
    def test_detect_type(self):
        self.assertEqual(rdap.detect_rdap_type("1.1.1.1"), "ip")
        self.assertEqual(rdap.detect_rdap_type("AS13335"), "autnum")
        self.assertEqual(rdap.detect_rdap_type("13335"), "autnum")
        self.assertEqual(rdap.detect_rdap_type("example.com"), "domain")

    def test_parse_path(self):
        self.assertEqual(rdap.parse_rdap_path("/rdap/AS13335"), "AS13335")
        with self.assertRaises(ValueError):
            rdap.parse_rdap_path("/rdap")

    def test_summarize_entities_and_cidr(self):
        summary = rdap.summarize_rdap(
            {
                "handle": "NET-1-1-1-0-1",
                "name": "CLOUDFLARENET",
                "country": "US",
                "startAddress": "1.1.1.0",
                "endAddress": "1.1.1.255",
                "status": ["active"],
                "cidr0_cidrs": [{"v4prefix": "1.1.1.0", "length": 24}],
                "entities": [
                    {
                        "handle": "ABUSE",
                        "roles": ["abuse"],
                        "vcardArray": [
                            "vcard",
                            [
                                ["fn", {}, "text", "Abuse"],
                                ["email", {}, "text", "abuse@cloudflare.com"],
                            ],
                        ],
                    }
                ],
                "events": [{"eventAction": "last changed", "eventDate": "2024-01-01T00:00:00Z"}],
            },
            kind="ip",
            query="1.1.1.1",
        )
        self.assertEqual(summary["name"], "CLOUDFLARENET")
        self.assertEqual(summary["cidr"], ["1.1.1.0/24"])
        self.assertEqual(summary["entities"][0]["email"], "abuse@cloudflare.com")
        self.assertEqual(summary["entities"][0]["roles"], ["abuse"])
        self.assertEqual(summary["events"][0]["action"], "last changed")

    def test_summarize_domain_dnssec_age_and_nameservers(self):
        now = datetime(2026, 8, 23, tzinfo=timezone.utc)
        summary = rdap.summarize_rdap(
            {
                "ldhName": "EXAMPLE.COM",
                "unicodeName": "example.com",
                "status": ["client transfer prohibited"],
                "secureDNS": {
                    "delegationSigned": True,
                    "dsData": [
                        {
                            "keyTag": 370,
                            "algorithm": 13,
                            "digestType": 2,
                            "digest": "abcdef",
                        }
                    ],
                },
                "nameservers": [
                    {
                        "ldhName": "A.IANA-SERVERS.NET",
                        "ipAddresses": {
                            "v4": ["199.43.135.53"],
                            "v6": ["2001:500:8f::53"],
                        },
                    },
                    {"ldhName": "B.IANA-SERVERS.NET"},
                ],
                "events": [
                    {"eventAction": "registration", "eventDate": "2009-02-17T18:19:12Z"},
                    {"eventAction": "expiration", "eventDate": "2027-02-17T18:19:12Z"},
                ],
                "entities": [
                    {
                        "roles": ["registrar"],
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                        "publicIds": [{"type": "IANA Registrar ID", "identifier": "123"}],
                    }
                ],
            },
            kind="domain",
            query="example.com",
            now=now,
        )
        self.assertEqual(summary["dnssec"]["signed"], True)
        self.assertEqual(summary["dnssec"]["label"], "signed")
        self.assertEqual(summary["dnssec"]["ds"][0]["key_tag"], 370)
        self.assertEqual(summary["dnssec"]["ds"][0]["algorithm_name"], "ECDSAP256SHA256")
        self.assertEqual(summary["nameservers"], ["a.iana-servers.net", "b.iana-servers.net"])
        self.assertEqual(summary["nameserver_details"][0]["v4"], ["199.43.135.53"])
        self.assertEqual(summary["dates"]["registered"], "2009-02-17 18:19 UTC")
        self.assertIn("year", summary["registered_age"])
        self.assertIn("registered", summary["timeline"])
        self.assertEqual(summary["registrar"]["name"], "Example Registrar")
        self.assertEqual(summary["registrar"]["iana_id"], "123")

    def test_summarize_unsigned_domain(self):
        summary = rdap.summarize_rdap(
            {"ldhName": "unsigned.example", "secureDNS": {"delegationSigned": False}},
            kind="domain",
            query="unsigned.example",
        )
        self.assertEqual(summary["dnssec"]["signed"], False)
        self.assertEqual(summary["dnssec"]["label"], "unsigned")

    def test_asn_lookup_attaches_rdap(self):
        from looking_glass.http.site import lookup_classified

        with (
            patch(
                "looking_glass.http.site.asn_org.find_org",
                return_value={"asn": 13335, "name": "CLOUDFLARENET"},
            ),
            patch(
                "looking_glass.intel.rdap.rdap_for_asn",
                return_value={"handle": "AS13335", "name": "CLOUDFLARENET", "type": "autnum"},
            ),
        ):
            out = lookup_classified("asn", "13335")
        self.assertTrue(out["ok"])
        self.assertEqual(out["result"]["name"], "CLOUDFLARENET")
        self.assertEqual(out["result"]["rdap"]["handle"], "AS13335")


class RdapCacheTests(unittest.TestCase):
    def test_stats_and_clear(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.cache.get_cache_path", side_effect=lambda name: os.path.join(tmp, name)):
                directory = os.path.join(tmp, "cache", "rdap")
                os.makedirs(directory)
                path = os.path.join(directory, "ip_1.1.1.1.json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump({"_cached_at": 1, "data": {"handle": "NET"}}, handle)
                stats = rdap.rdap_cache_stats()
                self.assertEqual(stats["count"], 1)
                self.assertEqual(stats["ttl_days"], 7)
                self.assertEqual(stats["files"][0]["kind"], "ip")
                self.assertEqual(stats["files"][0]["query"], "1.1.1.1")
                self.assertGreater(stats["bytes"], 0)
                one = rdap.clear_rdap_cache("ip_1.1.1.1.json")
                self.assertTrue(one["ok"])
                self.assertEqual(one["count"], 0)
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump({"_cached_at": 1, "data": {}}, handle)
                all_out = rdap.clear_rdap_cache()
                self.assertTrue(all_out["ok"])
                self.assertEqual(all_out["count"], 0)
                missing = rdap.clear_rdap_cache("nope.json")
                self.assertFalse(missing["ok"])

    def test_fetch_uses_shared_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.cache.get_cache_path", side_effect=lambda name: os.path.join(tmp, name)):
                with patch("requests.get") as get:
                    resp = MagicMock()
                    resp.status_code = 200
                    resp.json.return_value = {"handle": "NET"}
                    get.return_value = resp
                    first = rdap.fetch_rdap("1.1.1.1", target_type="ip")
                    second = rdap.fetch_rdap("1.1.1.1", target_type="ip")
                self.assertEqual(first["handle"], "NET")
                self.assertEqual(second["handle"], "NET")
        self.assertEqual(get.call_count, 1)

    def test_ipv6_keeps_colons_in_rdap_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.cache.get_cache_path", side_effect=lambda name: os.path.join(tmp, name)):
                with patch("requests.get") as get:
                    resp = MagicMock()
                    resp.status_code = 200
                    resp.json.return_value = {"handle": "NET6"}
                    get.return_value = resp
                    rdap.fetch_rdap("2606:4700:4700::1111", target_type="ip")
                url = get.call_args[0][0]
                self.assertIn("2606:4700:4700::1111", url)
                self.assertNotIn("%3A", url)

    def test_rir_fallback_after_rdap_org_404(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.cache.get_cache_path", side_effect=lambda name: os.path.join(tmp, name)):
                with patch("requests.get") as get:
                    miss = MagicMock()
                    miss.status_code = 404
                    hit = MagicMock()
                    hit.status_code = 200
                    hit.json.return_value = {"handle": "NET6", "name": "Documentation"}
                    get.side_effect = [miss, hit]
                    data = rdap.fetch_rdap("2001:db8::1", target_type="ip")
                self.assertEqual(data["handle"], "NET6")
                first, second = get.call_args_list[0][0][0], get.call_args_list[1][0][0]
                self.assertIn("rdap.org", first)
                self.assertIn("2001:db8::1", first)
                self.assertNotIn("%3A", first)
                self.assertIn("rdap.arin.net", second)
                self.assertIn("2001:db8::1", second)
