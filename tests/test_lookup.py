import json
import tempfile
import unittest
from unittest.mock import patch

from starlette.routing import Match

from looking_glass.intel_server.client import lookup_url


class LookupUrlTests(unittest.TestCase):
    def test_ipv4_uses_path(self):
        self.assertEqual(lookup_url("11.22.33.44"), "http://localhost/11.22.33.44")

    def test_ipv6_uses_path(self):
        self.assertEqual(lookup_url("2001:db8::1"), "http://localhost/2001:db8::1")
        self.assertEqual(
            lookup_url("2001:4860:4860::8888"),
            "http://localhost/2001:4860:4860::8888",
        )

    def test_country_uses_path(self):
        self.assertEqual(lookup_url("AU"), "http://localhost/AU")
        self.assertEqual(lookup_url("au"), "http://localhost/au")


def _route_name(path: str, query: bytes = b"") -> str | None:
    from looking_glass.intel_server.app import app

    scope = {"type": "http", "method": "GET", "path": path, "query_string": query}
    for route in app.router.routes:
        match, _child = route.matches(scope)
        if match == Match.FULL:
            endpoint = getattr(route, "endpoint", None)
            return getattr(endpoint, "__name__", None)
    return None


class LookupRouteTests(unittest.TestCase):
    def test_lookup_query_is_not_captured_as_an_ip(self):
        self.assertEqual(_route_name("/lookup", b"ip=11.22.33.44"), "lookup_query")
        self.assertEqual(_route_name("/lookup"), "lookup_query")

    def test_ipv4_and_ipv6_path(self):
        self.assertEqual(_route_name("/1.1.1.1"), "lookup_by_path")
        self.assertEqual(_route_name("/11.22.33.44"), "lookup_by_path")
        self.assertEqual(_route_name("/2001:db8::1"), "lookup_by_path")
        self.assertEqual(_route_name("/2001:4860:4860::8888"), "lookup_by_path")

    def test_query_handler_accepts_ip(self):
        from looking_glass.intel_server.app import lookup_query

        fake = {"ok": True, "ip": "11.22.33.44", "result": {"ip": "11.22.33.44"}}
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                from looking_glass.intel_server import app as lookup_mod

                lookup_mod._data_dir_path.cache_clear()
                with patch("looking_glass.intel_server.app.lookup_ip", return_value=fake):
                    out = lookup_query("11.22.33.44")
        self.assertEqual(out["ip"], "11.22.33.44")

    def test_path_handler_accepts_ipv6(self):
        from looking_glass.intel_server.app import lookup

        fake = {
            "ok": True,
            "ip": "2001:db8::1",
            "result": {"ip": "2001:db8::1"},
        }
        with patch("looking_glass.intel_server.app.lookup_ip", return_value=fake):
            out = lookup("2001:db8::1")
        self.assertEqual(out["ip"], "2001:db8::1")

    def test_path_handler_accepts_country(self):
        from looking_glass.intel_server.app import lookup

        fake = {
            "ok": True,
            "country": "AU",
            "result": {"country": "AU", "prefixes": ["1.0.0.0/24"], "count": 1},
        }
        with patch("looking_glass.intel_server.app.lookup_country", return_value=fake):
            out = lookup("AU")
        self.assertEqual(out["country"], "AU")
        self.assertEqual(out["result"]["prefixes"], ["1.0.0.0/24"])


class LookupBenchTests(unittest.TestCase):
    def test_invalid_ip(self):
        from looking_glass.intel_server.bench import bench

        out = bench("not-an-ip", duration=0.01, concurrency=1, show_progress=False)
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "invalid ip")

    def test_requires_daemon(self):
        from looking_glass.intel_server.bench import bench

        daemon = {
            "running": False,
            "socket_exists": False,
            "pid": None,
            "state": "not_running",
        }
        with patch("looking_glass.intel_server.bench.lookup_mod.status", return_value=daemon):
            out = bench("1.1.1.1", duration=0.01, concurrency=1, show_progress=False)
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "intel server is not running")
        self.assertIsNone(out["via"])

    def test_ipv6_uses_path_url(self):
        from looking_glass.intel_server.bench import bench

        fake = {
            "ok": True,
            "count": 2,
            "errors": 0,
            "duration_s": 0.05,
            "latencies": [1.0, 2.0],
        }
        with (
            patch(
                "looking_glass.intel_server.bench.lookup_mod.status",
                return_value={"running": True, "ready": True, "socket_exists": True, "pid": 1},
            ),
            patch("looking_glass.intel_server.bench.run_loop", side_effect=lambda *a, **k: fake),
        ):
            out = bench(
                "2001:db8::1",
                duration=0.01,
                concurrency=1,
                threads=1,
                show_progress=False,
            )
        self.assertTrue(out["ok"])
        self.assertEqual(out["via"], "intel")
        self.assertEqual(out["url"], "http://localhost/2001:db8::1")
        self.assertEqual(out["ip"], "2001:db8::1")
        self.assertEqual(out["requests"], 2)

    def test_error_summary_is_merged(self):
        from looking_glass.intel_server.bench import bench

        fake = {
            "count": 10,
            "errors": 3,
            "duration_s": 0.05,
            "latencies": [1.0],
            "error_summary": {"timeout": 2, "http_500": 1},
        }
        with (
            patch(
                "looking_glass.intel_server.bench.lookup_mod.status",
                return_value={"running": True, "ready": True, "socket_exists": True, "pid": 1},
            ),
            patch("looking_glass.intel_server.bench.run_loop", return_value=fake),
        ):
            out = bench(
                "1.1.1.1",
                duration=0.01,
                concurrency=1,
                threads=1,
                show_progress=False,
            )
        self.assertEqual(out["errors"], 3)
        self.assertEqual(out["error_summary"], {"timeout": 2, "http_500": 1})

    def test_timeout_label(self):
        import asyncio
        from looking_glass.intel_server.bench import _error_label

        self.assertEqual(_error_label(asyncio.TimeoutError()), "timeout")

    def test_connector_limit_matches_concurrency(self):
        import asyncio
        from unittest.mock import AsyncMock, MagicMock
        from looking_glass.intel_server.bench import run_loop

        async def noop(*args, **kwargs):
            return None

        async def go():
            conn = MagicMock()
            session = MagicMock()
            session.close = AsyncMock()
            with (
                patch("looking_glass.intel_server.bench.lookup_client.aiohttp.UnixConnector", return_value=conn) as ctor,
                patch("looking_glass.intel_server.bench.lookup_client.aiohttp.ClientSession", return_value=session),
                patch("looking_glass.intel_server.bench._worker", side_effect=noop),
            ):
                await run_loop(
                    "1.1.1.1",
                    socket_path="/tmp/lookup.sock",
                    concurrency=200,
                    duration=0.01,
                    timeout=0.5,
                    connections=200,
                    show_progress=False,
                )
            kwargs = ctor.call_args.kwargs
            self.assertEqual(kwargs["limit"], 200)
            self.assertEqual(kwargs["limit_per_host"], 0)
            self.assertEqual(kwargs["path"], "/tmp/lookup.sock")

        asyncio.run(go())

    def test_pool_size_caps_to_connections(self):
        from looking_glass.intel_server.bench import pool_size

        self.assertEqual(pool_size(300, connections=64), 64)
        self.assertEqual(pool_size(10, connections=64), 10)

    def test_connect_error_uses_errno_name(self):
        import errno
        from looking_glass.intel_server.bench import _error_label
        from looking_glass.intel_server.client import aiohttp

        class Boom(aiohttp.ClientConnectorError):
            def __init__(self):
                OSError.__init__(self)
                self._os_error = OSError(errno.EMFILE, "Too many open files")

            @property
            def os_error(self):
                return self._os_error

        self.assertEqual(_error_label(Boom()), "connect:EMFILE")

    def test_click_lookup_bench(self):
        from looking_glass.cli.entry import cli
        from click.testing import CliRunner

        runner = CliRunner()
        fake = {
            "ok": True,
            "ip": "1.1.1.1",
            "via": "intel",
            "url": "http://localhost/1.1.1.1",
            "requests": 3,
            "errors": 0,
        }
        with patch("looking_glass.intel_server.bench.bench", return_value=fake):
            result = runner.invoke(cli, ["--json", "lookup", "bench", "1.1.1.1", "-d", "1", "-c", "2"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["via"], "intel")
        self.assertEqual(payload["url"], "http://localhost/1.1.1.1")

    def test_click_lookup_bench_missing_daemon(self):
        from looking_glass.cli.entry import cli
        from click.testing import CliRunner

        runner = CliRunner()
        fake = {
            "ok": False,
            "ip": "1.1.1.1",
            "error": "intel server is not running",
            "via": None,
        }
        with patch("looking_glass.intel_server.bench.bench", return_value=fake):
            result = runner.invoke(cli, ["--json", "lookup", "bench", "1.1.1.1"])
        self.assertEqual(result.exit_code, 2)
        payload = json.loads(result.output)
        self.assertFalse(payload["ok"])


class CountryCidrTests(unittest.TestCase):
    def test_rir_summarizes_allocation_range(self):
        from array import array

        from looking_glass.intel import rir

        with (
            patch.object(rir, "_starts_v4", array("I", [0xC0000200])),
            patch.object(rir, "_ends_v4", array("I", [0xC00002FF])),
            patch.object(rir, "_meta_v4", ["US"]),
            patch.object(rir, "_starts_v6", None),
            patch.object(rir, "_ends_v6", None),
            patch.object(rir, "_meta_v6", None),
            patch.object(rir, "_built", True),
        ):
            out = rir.cidrs_for_country("US")
        self.assertEqual(out["country"], "US")
        self.assertEqual(out["prefixes"], ["192.0.2.0/24"])
        self.assertEqual(out["ipv4"], 1)
        self.assertEqual(out["ipv6"], 0)
        self.assertEqual(out["count"], 1)

    def test_uk_matches_gb_allocations(self):
        from array import array

        from looking_glass.intel import rir

        with (
            patch.object(rir, "_starts_v4", array("I", [0xC0000200])),
            patch.object(rir, "_ends_v4", array("I", [0xC00002FF])),
            patch.object(rir, "_meta_v4", ["GB"]),
            patch.object(rir, "_starts_v6", None),
            patch.object(rir, "_ends_v6", None),
            patch.object(rir, "_meta_v6", None),
            patch.object(rir, "_built", True),
        ):
            out = rir.cidrs_for_country("UK")
        self.assertEqual(out["country"], "GB")
        self.assertEqual(out["prefixes"], ["192.0.2.0/24"])

    def test_nested_range_returns_parent_country(self):
        from array import array

        from looking_glass.intel import rir

        with (
            patch.object(rir, "_starts_v4", array("I", [0xC0000200, 0xC000020A])),
            patch.object(rir, "_ends_v4", array("I", [0xC00002FF, 0xC000020A])),
            patch.object(rir, "_meta_v4", ["US", "GB"]),
            patch.object(rir, "_starts_v6", None),
            patch.object(rir, "_ends_v6", None),
            patch.object(rir, "_meta_v6", None),
            patch.object(rir, "_built", True),
        ):
            hit = rir.get_country("192.0.2.11")
        self.assertIsNotNone(hit)
        self.assertEqual(hit["country"], "US")

    def test_lookup_country_payload(self):
        from looking_glass.intel_server.pipeline import lookup_country

        dump = {
            "country": "AU",
            "prefixes": ["1.0.0.0/24"],
            "count": 1,
            "ipv4": 1,
            "ipv6": 0,
        }
        with patch("looking_glass.intel_server.pipeline.rir.cidrs_for_country", return_value=dump):
            out = lookup_country("AU", load=False)
        self.assertTrue(out["ok"])
        self.assertEqual(out["country"], "AU")
        self.assertEqual(out["result"]["prefixes"], ["1.0.0.0/24"])
        self.assertEqual(out["result"]["count"], 1)
        self.assertEqual(out["result"]["country_name"], "Australia")

    def test_demo_country_uses_daemon_cidrs(self):
        from looking_glass.http.site import lookup_classified

        fake = {
            "ok": True,
            "country": "AU",
            "result": {"country": "AU", "prefixes": ["1.0.0.0/24"], "count": 1},
        }
        with patch("looking_glass.intel_server.client.lookup_json", return_value=fake):
            out = lookup_classified("country", "AU")
        self.assertEqual(out["via"], "intel")
        self.assertEqual(out["result"]["prefixes"], ["1.0.0.0/24"])
