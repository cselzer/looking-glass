import json
import os
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from looking_glass.http.site import respond
from looking_glass.intel import rdap


_IANA_FIXTURE = [
    [["jp"], ["https://rdap.jprs.jp/"]],
    [["de"], ["https://rdap.denic.de/"]],
    [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
]
_IANA_COM_ONLY = [
    [["com", "net"], ["https://rdap.verisign.com/com/v1/"]],
]


def _reset_bootstrap() -> None:
    rdap._DNS_BOOTSTRAP = None
    rdap._DNS_BOOTSTRAP_LOADED = 0.0


def _write_iana(tmp: str, services) -> None:
    path = os.path.join(tmp, "rdap-dns.json")
    with open(path, "w", encoding="utf-8") as handle:
        json.dump({"_fetched_at": time.time(), "services": services}, handle)
    _reset_bootstrap()


def _tmp_cache(tmp: str):
    def path_for(name: str) -> str:
        return os.path.join(tmp, name)

    return (
        patch("looking_glass.intel.rdap.get_cache_path", side_effect=path_for),
        patch("looking_glass.cache.get_cache_path", side_effect=path_for),
        patch("looking_glass.intel.rdap.fetch_text", return_value=None),
    )


def _json_resp(payload, status=200, url=""):
    resp = MagicMock()
    resp.status_code = status
    resp.url = url
    resp.headers = {"Content-Type": "application/rdap+json"}
    resp.json.return_value = payload
    resp.text = json.dumps(payload)
    return resp


class RdapHelpers(unittest.TestCase):
    def test_detect_type(self):
        self.assertEqual(rdap.detect_rdap_type("1.1.1.1"), "ip")
        self.assertEqual(rdap.detect_rdap_type("AS13335"), "autnum")
        self.assertEqual(rdap.detect_rdap_type("13335"), "autnum")
        self.assertEqual(rdap.detect_rdap_type("example.com"), "domain")
        with self.assertRaises(ValueError):
            rdap.detect_rdap_type("notanip")
        with self.assertRaises(ValueError):
            rdap.detect_rdap_type("999.999.999.999")
        with self.assertRaises(ValueError):
            rdap.detect_rdap_type("AS99999999999")
        with self.assertRaises(ValueError):
            rdap.detect_rdap_type("4294967296")
        with self.assertRaises(ValueError):
            rdap.detect_rdap_type("fe80::1%eth0")

    def test_parse_path(self):
        self.assertEqual(rdap.parse_rdap_path("/rdap/AS13335"), "AS13335")
        with self.assertRaises(ValueError):
            rdap.parse_rdap_path("/rdap")
        with self.assertRaises(ValueError):
            rdap.parse_rdap_path("/rdap/notanip")
        with self.assertRaises(ValueError):
            rdap.parse_rdap_path("/rdap/999.999.999.999")

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
    def tearDown(self):
        _reset_bootstrap()

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

    def test_junk_does_not_fetch(self):
        with patch("requests.get") as get:
            self.assertIsNone(rdap.fetch_rdap("notanip"))
            payload = rdap.lookup_rdap("notanip")
            self.assertFalse(payload["ok"])
            self.assertIsNone(rdap.fetch_rdap("999.999.999.999"))
            bogus = rdap.lookup_rdap("999.999.999.999")
            self.assertFalse(bogus["ok"])
        get.assert_not_called()

    def test_idn_fetch_uses_punycode(self):
        hit = _json_resp({"handle": "EXAMPLE", "ldhName": "xn--fsq.jp"})
        with tempfile.TemporaryDirectory() as tmp:
            _write_iana(tmp, _IANA_FIXTURE)
            with _tmp_cache(tmp)[0], _tmp_cache(tmp)[1], _tmp_cache(tmp)[2]:
                with patch("requests.get", return_value=hit) as get:
                    data = rdap.fetch_rdap("例.jp")
                    again = rdap.fetch_rdap("xn--fsq.jp")
        self.assertEqual(data["handle"], "EXAMPLE")
        self.assertEqual(again["handle"], "EXAMPLE")
        urls = [call[0][0] for call in get.call_args_list]
        self.assertTrue(any("xn--fsq.jp" in url for url in urls))
        self.assertFalse(any("例" in url for url in urls))
        self.assertFalse(any("rdap.org" in url for url in urls))
        self.assertTrue(all("rdap.jprs.jp" in url or "jpnic" in url for url in urls))

    def test_html_200_is_not_cached(self):
        html = MagicMock()
        html.status_code = 200
        html.url = ""
        html.headers = {"Content-Type": "text/html; charset=utf-8"}
        html.text = "<!DOCTYPE html><html><body>LACNIC RDAP client</body></html>"
        html.json.side_effect = AssertionError("must not parse HTML as JSON")
        with tempfile.TemporaryDirectory() as tmp:
            _write_iana(tmp, _IANA_FIXTURE)
            with _tmp_cache(tmp)[0], _tmp_cache(tmp)[1], _tmp_cache(tmp)[2]:
                with patch("looking_glass.intel.rdap.query_cache.put") as put:
                    with patch("requests.get", return_value=html) as get:
                        data = rdap.fetch_rdap("example.com")
        self.assertIsNone(data)
        get.assert_called()
        put.assert_not_called()
        html.json.assert_not_called()
        self.assertIn("verisign", get.call_args[0][0])
        self.assertNotIn("rdap.org", get.call_args[0][0])

    def test_domain_fetch_skips_rir_html_trap(self):
        miss = _json_resp({"errorCode": 404, "title": "Not Found"}, status=404)
        with tempfile.TemporaryDirectory() as tmp:
            _write_iana(tmp, _IANA_FIXTURE)
            with _tmp_cache(tmp)[0], _tmp_cache(tmp)[1], _tmp_cache(tmp)[2]:
                with patch("requests.get", return_value=miss) as get:
                    data = rdap.fetch_rdap("example.com")
        self.assertIsNone(data)
        self.assertEqual(get.call_count, 1)
        url = get.call_args[0][0]
        self.assertIn("rdap.verisign.com", url)
        self.assertNotIn("rdap.org", url)
        self.assertNotIn("rdap.lacnic.net", url)

    def test_cctld_bootstrap_urls(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_iana(tmp, _IANA_FIXTURE)
            with _tmp_cache(tmp)[0], _tmp_cache(tmp)[1], _tmp_cache(tmp)[2]:
                jp = rdap.domain_rdap_urls("jprs.jp")
                idn = rdap.domain_rdap_urls("xn--fsq.jp")
                de = rdap.domain_rdap_urls("xn--bcher-kva.de")
                com = rdap.domain_rdap_urls("example.com")
        self.assertEqual(jp, ["https://rdap.jprs.jp/domain/jprs.jp"])
        self.assertEqual(idn, ["https://rdap.jprs.jp/domain/xn--fsq.jp"])
        self.assertEqual(de, ["https://rdap.denic.de/domain/xn--bcher-kva.de"])
        self.assertEqual(com, ["https://rdap.verisign.com/com/v1/domain/example.com"])
        self.assertFalse(any("rdap.org" in url for url in jp + idn + de + com))

    def test_bootstrap_reads_disk_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            _write_iana(tmp, [[["jp"], ["https://rdap.jprs.jp/"]]])
            with _tmp_cache(tmp)[0], _tmp_cache(tmp)[1], _tmp_cache(tmp)[2]:
                with patch("requests.get") as get:
                    urls = rdap.domain_rdap_urls("jprs.jp")
            get.assert_not_called()
            self.assertEqual(urls, ["https://rdap.jprs.jp/domain/jprs.jp"])

    def test_jprs_and_denic_fetch(self):
        hit = _json_resp({"handle": "JPRS.JP", "ldhName": "JPRS.JP"})
        with tempfile.TemporaryDirectory() as tmp:
            _write_iana(tmp, _IANA_FIXTURE)
            with _tmp_cache(tmp)[0], _tmp_cache(tmp)[1], _tmp_cache(tmp)[2]:
                with patch("requests.get", return_value=hit) as get:
                    data = rdap.fetch_rdap("jprs.jp")
                    looked = rdap.lookup_rdap("例.jp")
                    de = rdap.fetch_rdap("bücher.de")
        self.assertEqual(data["handle"], "JPRS.JP")
        urls = [call[0][0] for call in get.call_args_list]
        self.assertIn("rdap.jprs.jp/domain/jprs.jp", urls[0])
        self.assertFalse(any("rdap.org" in url for url in urls))
        self.assertFalse(any("verisign" in url for url in urls if "jprs" in url or "xn--fsq" in url or "bcher" in url))
        self.assertTrue(looked["ok"])
        self.assertEqual(looked["result"]["query"], "例.jp")
        self.assertIn("rdap.jprs.jp/domain/xn--fsq.jp", urls[1])
        self.assertIn("rdap.denic.de/domain/xn--bcher-kva.de", urls[2])

    def test_registry_404_is_not_found(self):
        miss = _json_resp({"errorCode": 404, "title": "Not Found"}, status=404)
        with tempfile.TemporaryDirectory() as tmp:
            _write_iana(tmp, _IANA_FIXTURE)
            with _tmp_cache(tmp)[0], _tmp_cache(tmp)[1], _tmp_cache(tmp)[2]:
                with patch("requests.get", return_value=miss) as get:
                    payload = rdap.lookup_rdap("missing.jp")
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status"], 404)
        self.assertEqual(payload["error"], "not found")
        self.assertNotIn("rdap.org", payload["url"])
        self.assertIn("jprs.jp", payload["url"])
        self.assertEqual(payload["http_status"], 404)
        self.assertNotEqual(payload["error"], "rdap lookup failed")
        get.assert_called_once()

    def test_html_timeout_is_502_with_url(self):
        html = MagicMock()
        html.status_code = 200
        html.url = ""
        html.headers = {"Content-Type": "text/html"}
        html.text = "<!DOCTYPE html><html></html>"
        html.json.side_effect = AssertionError("must not parse HTML as JSON")
        with tempfile.TemporaryDirectory() as tmp:
            _write_iana(tmp, _IANA_FIXTURE)
            with _tmp_cache(tmp)[0], _tmp_cache(tmp)[1], _tmp_cache(tmp)[2]:
                with patch("requests.get", return_value=html):
                    html_fail = rdap.lookup_rdap("jprs.jp")
                with patch("requests.get", side_effect=TimeoutError("timed out")) as get:
                    timed = rdap.lookup_rdap("nic.jp")
        self.assertFalse(html_fail["ok"])
        self.assertEqual(html_fail["status"], 502)
        self.assertIn("rdap.jprs.jp", html_fail["error"])
        self.assertNotIn("rdap.org", html_fail["url"])
        self.assertNotEqual(html_fail["error"], "rdap lookup failed")
        self.assertFalse(timed["ok"])
        self.assertEqual(timed["status"], 502)
        self.assertNotIn("rdap.org", timed["error"])
        self.assertIn("nic.jp", get.call_args[0][0])
        timeout = get.call_args[1]["timeout"]
        self.assertEqual(timeout, (3, 8))

    def test_iana_fixture_without_jp_de_uses_supplement(self):
        hit = _json_resp({"ldhName": "xn--bcher-kva.de"})
        with tempfile.TemporaryDirectory() as tmp:
            _write_iana(tmp, _IANA_COM_ONLY)
            with _tmp_cache(tmp)[0], _tmp_cache(tmp)[1], _tmp_cache(tmp)[2]:
                with patch("requests.get", return_value=hit) as get:
                    de = rdap.lookup_rdap("bücher.de")
                    jp = rdap.lookup_rdap("jprs.jp")
        self.assertTrue(de["ok"])
        self.assertEqual(de["result"]["query"], "bücher.de")
        de_url = get.call_args_list[0][0][0]
        jp_url = get.call_args_list[1][0][0]
        self.assertIn("rdap.denic.de/domain/xn--bcher-kva.de", de_url)
        self.assertNotIn("rdap.org", de_url)
        self.assertNotIn("rdap.org", jp_url)
        self.assertTrue("jprs.jp" in jp_url or "jpnic" in jp_url)
        self.assertIn("denic", de.get("url") or de_url)

    def test_missing_bootstrap_is_502_not_rdap_org(self):
        with tempfile.TemporaryDirectory() as tmp:
            _reset_bootstrap()
            with _tmp_cache(tmp)[0], _tmp_cache(tmp)[1], _tmp_cache(tmp)[2]:
                with patch("requests.get") as get:
                    payload = rdap.lookup_rdap("example.com")
        get.assert_not_called()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["status"], 502)
        self.assertIn("dns.json", (payload.get("error") or "") + (payload.get("url") or ""))
        self.assertNotIn("rdap.org/domain", payload.get("url") or "")
        self.assertNotIn("rdap.org/domain", payload.get("error") or "")

    def test_redirect_uses_final_registry_url(self):
        hit = _json_resp(
            {"ldhName": "xn--bcher-kva.de", "handle": "BUECHER"},
            url="https://rdap.denic.de/domain/xn--bcher-kva.de",
        )
        with tempfile.TemporaryDirectory() as tmp:
            _write_iana(tmp, _IANA_FIXTURE)
            with _tmp_cache(tmp)[0], _tmp_cache(tmp)[1], _tmp_cache(tmp)[2]:
                with patch("requests.get", return_value=hit) as get:
                    payload = rdap.lookup_rdap("xn--bcher-kva.de")
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["url"], "https://rdap.denic.de/domain/xn--bcher-kva.de")
        self.assertNotIn("rdap.org", payload["url"])
        self.assertNotIn("rdap.org", get.call_args[0][0])

    def test_build_writes_rdap_dns_json(self):
        blob = json.dumps(
            {
                "services": [
                    [["com"], ["https://rdap.verisign.com/com/v1/"]],
                    [["de"], ["https://rdap.denic.de/"]],
                ]
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            _reset_bootstrap()
            with patch("looking_glass.intel.rdap.get_cache_path", side_effect=lambda name: os.path.join(tmp, name)):
                with patch("looking_glass.intel.rdap.fetch_text", return_value=blob) as fetch:
                    self.assertTrue(rdap.build(force=True))
                    self.assertTrue(rdap.load(force=False))
            fetch.assert_called()
            dest = os.path.join(tmp, "rdap-dns.json")
            with open(dest, encoding="utf-8") as handle:
                saved = json.load(handle)
            self.assertTrue(saved["services"])
            self.assertIn("_fetched_at", saved)
            urls = rdap.domain_rdap_urls("xn--bcher-kva.de")
            self.assertTrue(any("rdap.denic.de" in url for url in urls))
            self.assertFalse(any("rdap.org" in url for url in urls))

    def test_json_http_ok_and_garbage_400(self):
        fake = {
            "ok": True,
            "result": {"type": "ip", "handle": "NET", "query": "1.1.1.1"},
            "error": None,
            "total_ms": 1,
        }
        with patch("looking_glass.http.site.lookup_rdap", return_value=fake) as lookup:
            status, _, body, *_ = respond(
                "wsgi", "127.0.0.1", "/rdap/1.1.1.1", {}, accept="application/json"
            )
        self.assertEqual(status, 200)
        payload = json.loads(body)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["result"]["type"], "ip")
        lookup.assert_called_once()

        with patch("looking_glass.http.site.lookup_rdap") as lookup:
            for path in ("/rdap/notanip", "/rdap/999.999.999.999", "/rdap/AS99999999999"):
                status, _, body, *_ = respond(
                    "wsgi", "127.0.0.1", path, {}, accept="application/json"
                )
                self.assertEqual(status, 400)
                denied = json.loads(body)
                self.assertFalse(denied["ok"])
                self.assertNotIn("result", denied)
                self.assertNotEqual(denied.get("kind"), "domain")
            lookup.assert_not_called()

    def test_json_http_lookup_failure_is_502(self):
        failed = {
            "ok": False,
            "result": None,
            "error": "rdap lookup failed https://rdap.jprs.jp/domain/nic.jp timeout",
            "url": "https://rdap.jprs.jp/domain/nic.jp",
            "http_status": None,
            "status": 502,
            "total_ms": 1,
        }
        with patch("looking_glass.http.site.lookup_rdap", return_value=failed):
            status, _, body, *_ = respond(
                "wsgi", "127.0.0.1", "/rdap/nic.jp", {}, accept="application/json"
            )
        self.assertEqual(status, 502)
        payload = json.loads(body)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["query"], "nic.jp")
        self.assertIn("rdap.jprs.jp", payload["error"])
        self.assertEqual(payload["url"], "https://rdap.jprs.jp/domain/nic.jp")

    def test_json_http_registry_404(self):
        failed = {
            "ok": False,
            "result": None,
            "error": "not found",
            "url": "https://rdap.jprs.jp/domain/missing.jp",
            "http_status": 404,
            "status": 404,
            "total_ms": 1,
        }
        with patch("looking_glass.http.site.lookup_rdap", return_value=failed):
            status, _, body, *_ = respond(
                "wsgi", "127.0.0.1", "/rdap/missing.jp", {}, accept="application/json"
            )
        self.assertEqual(status, 404)
        payload = json.loads(body)
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"], "not found")
        self.assertNotEqual(payload["error"], "rdap lookup failed")
        self.assertEqual(payload["http_status"], 404)
