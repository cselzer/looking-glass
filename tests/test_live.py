"""
Live internet tests. These download real IANA/RIR/ASN datasets and look up
real IPs. No download/lookup mocks.

A throwaway HOME is used so this does not overwrite ~/.looking-glass/data.
Expect roughly 1–2 minutes for the first download.
"""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path

from click.testing import CliRunner

from looking_glass.intel import asn as asn_mod
from looking_glass.intel import asn_org, iana, rir
from looking_glass.intel_server import app as lookup_mod
from looking_glass.intel_server import client as lookup_client
from looking_glass.cli.entry import cli
from looking_glass.intel.asn_prefixes import get_prefixes
from looking_glass.intel.flags import country_to_flag
from looking_glass.intel.rdap import get_rdap_for_ip
from looking_glass.dns.reputation import check_rbls
from looking_glass.utility import get_cache_path, get_data_dir


_HOME: str | None = None
_OLD_HOME: str | None = None


def _sock_path() -> str:
    return str(Path(get_data_dir()) / "lookup.sock")


def _cleanup() -> None:
    try:
        lookup_mod.stop(timeout=10)
    except Exception:
        pass
    if _OLD_HOME is None:
        os.environ.pop("HOME", None)
    else:
        os.environ["HOME"] = _OLD_HOME
    try:
        lookup_mod._data_dir_path.cache_clear()
    except Exception:
        pass
    if _HOME and os.path.isdir(_HOME):
        shutil.rmtree(_HOME, ignore_errors=True)


def setUpModule() -> None:
    global _HOME, _OLD_HOME
    _HOME = tempfile.mkdtemp(prefix="looking-glass-live-")
    _OLD_HOME = os.environ.get("HOME")
    os.environ["HOME"] = _HOME
    try:
        lookup_mod._data_dir_path.cache_clear()
        lookup_client.LOOKUP_SOCKET = _sock_path()
        lookup_client.lookup_ip.cache_clear()

        print(f"\nLive test data dir: {get_data_dir()}", flush=True)
        print("Downloading IANA, RIR, ASN org, and RouteViews ASN data for real…", flush=True)

        steps = (
            ("IANA", iana.build),
            ("RIR", rir.build),
            ("ASN org", asn_org.build),
            ("ASN prefixes", asn_mod.build),
        )
        for label, fn in steps:
            t0 = time.time()
            ok = fn(force=True)
            elapsed = time.time() - t0
            print(f"  {label}: {'ok' if ok else 'FAILED'}  ({elapsed:.1f}s)", flush=True)
            if not ok:
                raise RuntimeError(f"live {label} build failed after {elapsed:.1f}s")

        for mod in (iana, rir, asn_mod, asn_org):
            if not mod.load(force=False):
                raise RuntimeError(f"failed to load {mod.__name__} after live build")

        lookup_mod.start(timeout=30)
        deadline = time.time() + 30
        while time.time() < deadline:
            if os.path.exists(_sock_path()):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError(f"lookup server did not create {_sock_path()}")
        print(f"Lookup server socket: {_sock_path()}", flush=True)
    except Exception:
        _cleanup()
        raise


def tearDownModule() -> None:
    _cleanup()


class LiveBuildTests(unittest.TestCase):
    def test_cache_files_are_real_sizes(self):
        iana_size = os.path.getsize(get_cache_path("iana.json"))
        rir_size = os.path.getsize(get_cache_path("rir.json"))
        org_size = os.path.getsize(get_cache_path("asn2org.json"))
        asn_size = os.path.getsize(get_cache_path("asn_prefix.ipasn.dat"))
        self.assertGreater(iana_size, 8_000, f"iana.json too small: {iana_size} B")
        self.assertGreater(rir_size, 1_000_000, f"rir.json too small: {rir_size} B (empty-cache bug?)")
        self.assertGreater(org_size, 100_000, f"asn2org.json too small: {org_size} B")
        self.assertGreater(asn_size, 1_000_000, f"asn db too small: {asn_size} B")


class LiveIanaTests(unittest.TestCase):
    def test_loopback_v4(self):
        hit = iana.find_for_ip("127.0.0.1")
        self.assertIsNotNone(hit)
        text = json.dumps(hit).lower()
        self.assertTrue("loopback" in text or "127.0.0.0/8" in hit.get("cidr", ""))

    def test_private_v4(self):
        hit = iana.find_for_ip("10.1.2.3")
        self.assertIsNotNone(hit)
        text = json.dumps(hit).lower()
        self.assertTrue("private" in text or hit.get("cidr", "").startswith("10."))

    def test_loopback_v6(self):
        hit = iana.find_for_ip("::1")
        self.assertIsNotNone(hit)

    def test_public_cloudflare_is_not_iana_special(self):
        self.assertIsNone(iana.find_for_ip("1.1.1.1"))

    def test_6to4_anycast_not_shadowed_by_more_specific(self):
        hit = iana.find_for_ip("192.88.99.100")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.get("cidr"), "192.88.99.0/24")

    def test_6a44_relay_keeps_more_specific(self):
        hit = iana.find_for_ip("192.88.99.2")
        self.assertIsNotNone(hit)
        self.assertEqual(hit.get("cidr"), "192.88.99.2/32")


class LiveRirTests(unittest.TestCase):
    def test_cloudflare_anycast(self):
        hit = rir.get_country("1.1.1.1")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["country"], "AU")
        self.assertEqual(hit["flag"], country_to_flag("AU"))
        self.assertEqual(hit["country_name"], "Australia")
        self.assertIn("flagcdn.com/au.svg", hit["flag_url"])
        self.assertIn("<img", hit["flag_html"])

    def test_google_dns(self):
        hit = rir.get_country("8.8.8.8")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["country"], "US")
        self.assertEqual(hit["flag"], country_to_flag("US"))
        self.assertEqual(hit["country_name"], "United States")
        self.assertIn("flagcdn.com/us.svg", hit["flag_url"])

    def test_ipv6_google(self):
        hit = rir.get_country("2001:4860:4860::8888")
        self.assertIsNotNone(hit)
        self.assertEqual(len(hit["country"]), 2)


class LiveAsnTests(unittest.TestCase):
    def test_cloudflare_origin(self):
        hit = asn_mod.find_origin("1.1.1.1")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["asn"], 13335)
        self.assertTrue(str(hit["prefix"]).startswith("1.1.1."))

    def test_google_origin(self):
        hit = asn_mod.find_origin("8.8.8.8")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["asn"], 15169)

    def test_cloudflare_org_name(self):
        hit = asn_org.find_org(13335)
        self.assertIsNotNone(hit)
        self.assertIn("cloudflare", hit["name"].lower())

    def test_google_org_name(self):
        hit = asn_org.find_org("AS15169")
        self.assertIsNotNone(hit)
        self.assertIn("google", hit["name"].lower())

    def test_cloudflare_prefixes_include_1_1_1_0(self):
        hit = get_prefixes(13335)
        self.assertIsNotNone(hit)
        self.assertGreater(hit["count"], 10)
        self.assertIn("1.1.1.0/24", hit["prefixes"])


class LivePipelineTests(unittest.TestCase):
    def test_fastapi_lookup_iana(self):
        resp = lookup_mod.lookup("127.0.0.1")
        self.assertTrue(resp["ok"])
        self.assertEqual(resp["result"]["source"], "iana")

    def test_fastapi_lookup_cloudflare(self):
        resp = lookup_mod.lookup("1.1.1.1")
        self.assertTrue(resp["ok"])
        result = resp["result"]
        self.assertEqual(result["source"], "rir")
        self.assertEqual(result["country"], "AU")
        self.assertEqual(result["asn"], 13335)
        self.assertIn("cloudflare", (result.get("org_name") or "").lower())

    def test_lookup_query_ipv6(self):
        resp = lookup_mod.lookup_query("2001:4860:4860::8888")
        self.assertTrue(resp["ok"], resp)
        self.assertEqual(resp["result"]["source"], "rir")
        self.assertEqual(len(resp["result"]["country"]), 2)

    def test_cli_serve_status_running(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "lookup-server", "status"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertTrue(payload["running"], payload)
        self.assertTrue(payload["socket_exists"], payload)

    def test_cli_lookup_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "lookup", "1.1.1.1"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["via"], "intel")
        self.assertEqual(payload["result"]["asn"], 13335)
        self.assertEqual(payload["result"]["country"], "AU")

    def test_cli_human_google(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "lookup", "8.8.8.8"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["via"], "intel")
        self.assertEqual(payload["result"]["country"], "US")
        self.assertEqual(payload["result"]["asn"], 15169)

    def test_cli_lookup_asn(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "lookup", "AS13335"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["asn"], "13335")
        self.assertTrue(payload.get("result"))

    def test_cli_lookup_dns(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "lookup", "example.com", "--type", "A"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["qtype"], "A")
        self.assertEqual(payload["result"]["status"], "NOERROR")
        self.assertTrue(payload["result"]["answers"])
        self.assertEqual(payload["result"]["answers"][0]["type"], "A")

    def test_cli_dns_common_types_including_ds(self):
        runner = CliRunner()
        cases = [
            ("example.com", "A"),
            ("example.com", "AAAA"),
            ("example.com", "NS"),
            ("example.com", "MX"),
            ("example.com", "TXT"),
            ("example.com", "SOA"),
            ("example.com", "DS"),
            ("example.com", "DNSKEY"),
            ("cloudflare.com", "CAA"),
            ("1.1.1.1", "PTR"),
            ("www.iana.org", "CNAME"),
        ]
        for name, qtype in cases:
            with self.subTest(name=name, qtype=qtype):
                result = runner.invoke(cli, ["--json", "dns", name, qtype])
                self.assertEqual(result.exit_code, 0, result.output)
                payload = json.loads(result.output)
                self.assertEqual(payload["qtype"], qtype)
                self.assertEqual(payload["result"]["status"], "NOERROR", payload)
                self.assertTrue(payload["result"]["answers"], payload)
                self.assertEqual(payload["result"]["answers"][0]["type"], qtype)

    def test_cli_validate_json(self):
        runner = CliRunner()
        result = runner.invoke(cli, ["--json", "validate"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertTrue(payload["ok"], payload)
        ids = {row["id"] for row in payload["checks"]}
        self.assertIn("file.rir", ids)
        self.assertTrue(any(i.startswith("sample.iana.") for i in ids), ids)
        self.assertTrue(any(i.startswith("sample.rir.") for i in ids), ids)
        self.assertTrue(any(i.startswith("sample.asn.") for i in ids), ids)
        failed = [row for row in payload["checks"] if row["status"] == "failed"]
        self.assertEqual(failed, [])
        self.assertIn("elapsed", payload)
        self.assertIn("seed", payload)
        self.assertGreater(payload["elapsed_s"], 0)
        for row in payload["checks"]:
            self.assertIn("started", row)
            self.assertIn("finished", row)
            self.assertRegex(row["elapsed"], r"(µs|ms|s)$")

    def test_socket_client_matches_inprocess(self):
        lookup_client.lookup_ip.cache_clear()
        ctx = lookup_client.lookup_ip("1.1.1.1", socket_path=_sock_path(), timeout=5.0)
        self.assertIsNotNone(ctx)
        self.assertEqual(ctx.asn, 13335)
        self.assertEqual(ctx.country, "AU")
        self.assertEqual(ctx.country_name, "Australia")
        self.assertIn("flagcdn.com/au.svg", ctx.flag_url or "")
        self.assertIn("<img", ctx.flag_html or "")
        self.assertIn("cloudflare", (ctx.org_name or "").lower())


class LiveWallTests(unittest.TestCase):
    def test_flask_injects_real_asn_header(self):
        from flask import Flask

        from looking_glass.wall import wall

        lookup_client.lookup_ip.cache_clear()
        inner = Flask(__name__)

        @inner.get("/")
        def index():
            return "ok"

        app = wall(inner, lists=None)
        from werkzeug.test import Client

        rv = Client(app).get("/", environ_overrides={"REMOTE_ADDR": "1.1.1.1"})
        self.assertEqual(rv.status_code, 200)
        self.assertEqual(rv.headers.get("X-Wall-ASN"), "13335")
        self.assertEqual(rv.headers.get("X-Wall-Country"), "AU")
        self.assertIn("flagcdn.com/au.svg", rv.headers.get("X-Wall-Flag-Url", ""))


class LiveReputationTests(unittest.TestCase):
    def test_rbl_queries_real_dns(self):
        out = check_rbls("8.8.4.4", timeout=5.0)
        self.assertTrue(out["ok"], out)
        self.assertGreaterEqual(len(out["result"]), 1)
        for name, info in out["result"].items():
            self.assertTrue(info["query"].startswith("4.4.8.8."), info)
            self.assertIn(info.get("status"), {"drop", "blocked", "policy", "allowed", "unknown", "skipped"}, info)
            if info.get("listed"):
                for addr in info.get("addresses") or []:
                    self.assertTrue(addr.startswith("127."), addr)
        self.assertIn(out.get("status"), {"drop", "blocked", "policy", "allowed", "unknown"})


class LiveRdapTests(unittest.TestCase):
    def test_cloudflare_rdap(self):
        data = get_rdap_for_ip("1.1.1.1", force=True)
        self.assertIsInstance(data, dict)
        blob = json.dumps(data).lower()
        self.assertIn("cloudflare", blob)


if __name__ == "__main__":
    unittest.main()
