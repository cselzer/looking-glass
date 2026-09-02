import asyncio
import json
import os
import tempfile
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

from looking_glass.intel_server import app as lookup_mod
from looking_glass.http import weblog
from looking_glass.http.site import respond, _https_status_view, _serve_status_view


def _with_static(html: bytes | str) -> str:
    text = html.decode("utf-8") if isinstance(html, (bytes, bytearray)) else html
    for name in ("gui.css", "gui.js", "index.js", "admin.js"):
        if f"/static/{name}" not in text:
            continue
        status, _, body, *_ = respond("wsgi", "127.0.0.1", f"/static/{name}", {})
        if int(status) == 200:
            text += "\n" + body.decode("utf-8")
    pos = 0
    seen = set()
    marker = 'src="/i18n/'
    while True:
        start = text.find(marker, pos)
        if start < 0:
            break
        end = text.find('"', start + 5)
        pos = start + 1
        if end < 0:
            break
        path = text[start + 5 : end]
        if path in seen:
            continue
        seen.add(path)
        status, _, body, *_ = respond("wsgi", "127.0.0.1", path, {})
        if int(status) == 200:
            text += "\n" + body.decode("utf-8")
    return text


def _roots(tmp: str):
    return (
        patch("looking_glass.config.get_root", return_value=tmp),
        patch("looking_glass.utility.get_root", return_value=tmp),
    )


class ServeUptimeTests(unittest.TestCase):
    def tearDown(self):
        lookup_mod._data_dir_path.cache_clear()
        weblog.reset()

    def test_status_omits_uptime_when_down(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()
                info = lookup_mod.status()
        self.assertFalse(info["running"])
        self.assertFalse(info["ready"])
        self.assertNotIn("https", info)
        self.assertNotIn("uptime", info)
        self.assertNotIn("started_at", info)

    def test_https_view_omits_privkey_and_stopped_paths(self):
        running = _https_status_view(
            {
                "running": True,
                "uptime": 12.0,
                "port": 5555,
                "fullchain": "/tmp/fullchain.pem",
                "privkey": "/tmp/privkey.pem",
                "days_left": 80,
            }
        )
        self.assertEqual(running["fullchain"], "/tmp/fullchain.pem")
        self.assertNotIn("privkey", running)
        stopped = _https_status_view(
            {
                "running": False,
                "enabled": True,
                "hostname": "s1.example.com",
                "port": 5555,
                "uptime": 12.0,
                "pid": 9,
                "fullchain": "/tmp/fullchain.pem",
                "privkey": "/tmp/privkey.pem",
                "days_left": 80,
            }
        )
        self.assertFalse(stopped["running"])
        self.assertNotIn("uptime", stopped)
        self.assertNotIn("pid", stopped)
        self.assertNotIn("fullchain", stopped)
        self.assertNotIn("privkey", stopped)
        self.assertEqual(stopped["days_left"], 80)
        self.assertEqual(stopped["hostname"], "s1.example.com")
        down = _serve_status_view({"running": False, "ready": False, "uptime": 9, "pid": 3, "socket": "/tmp/x"})
        self.assertNotIn("uptime", down)
        self.assertNotIn("pid", down)
        self.assertEqual(down["socket"], "/tmp/x")

    def test_status_uptime_when_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()
                Path(tmp, "lookup.pid").write_text(str(os.getpid()), encoding="utf-8")
                Path(tmp, "lookup.started").write_text(str(time.time() - 125), encoding="utf-8")
                with patch("looking_glass.intel_server.app._is_running", return_value=True):
                    info = lookup_mod.status()
        self.assertTrue(info["running"])
        self.assertFalse(info["ready"])
        self.assertGreaterEqual(info["uptime"], 120)
        self.assertIn("started_at", info)


class WebLogTests(unittest.TestCase):
    def setUp(self):
        lookup_mod._data_dir_path.cache_clear()
        weblog.reset()

    def tearDown(self):
        lookup_mod._data_dir_path.cache_clear()
        weblog.reset()

    def test_classify_lookup_kinds(self):
        self.assertEqual(weblog.classify_request("/rdap/example.com")[1], "rdap")
        self.assertEqual(weblog.classify_request("/AS13335")[1], "asn")
        self.assertEqual(weblog.classify_request("/1.1.1.1")[1], "ip")
        self.assertEqual(weblog.classify_request("/")[0], "index")
        self.assertEqual(weblog.classify_request("/favicon.ico"), ("other", "other", "favicon.ico"))

    def test_access_and_login_and_routes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                weblog.reset()
                home, _, home_body, _ = respond("wsgi", "127.0.0.1", "/", {}, accept="text/html")
                self.assertEqual(home, 200)
                home_html = _with_static(home_body)
                self.assertIn('id="status-login"', home_html)
                self.assertIn("gui.wall.note", home_html)
                self.assertNotIn('id="status-logs"', home_html)
                self.assertNotIn('id="status-services"', home_html)
                self.assertNotIn('id="cache-btn"', home_html)
                self.assertNotIn("sizeLogPopToAccess", home_html)
                self.assertIn('id="status-wins"', home_html)
                self.assertNotIn('id="status-windows"', home_html)
                self.assertNotIn("minimizeAll", home_html)
                self.assertNotIn("restoreAll", home_html)
                self.assertIn("status-win-stack", home_html)
                self.assertIn("inspect-pop-min", home_html)
                self.assertIn("inspect-pop-max", home_html)
                self.assertIn("inspect-pop-refresh", home_html)
                self.assertIn("site-head-cluster", home_html)
                self.assertIn('id="status-mem"', home_html)
                self.assertIn("resize: both", home_html)
                respond("wsgi", "127.0.0.1", "/status", {}, accept="application/json")
                from looking_glass.auth import password as admin_password

                admin_password.set_password("secret")
                denied, _, _body, _ = respond(
                    "wsgi",
                    "10.0.0.1",
                    "/login",
                    {},
                    method="POST",
                    body=b'{"password":"nope"}',
                )
                self.assertEqual(denied, 401)
                ok, _, _raw, extra = respond(
                    "wsgi",
                    "10.0.0.1",
                    "/login",
                    {},
                    method="POST",
                    body=b'{"password":"secret"}',
                )
                self.assertEqual(ok, 200)
                cookie = dict(extra).get("Set-Cookie", "").split(";", 1)[0]
                authed, _, authed_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/",
                    {},
                    accept="text/html",
                    cookie=cookie,
                )
                self.assertEqual(authed, 200)
                authed_html = _with_static(authed_body)
                self.assertIn('id="status-logs"', authed_html)
                self.assertIn('id="status-services"', authed_html)
                self.assertIn('id="status-history"', authed_html)
                self.assertIn('id="status-wall"', authed_html)
                self.assertIn("/wall/traffic", authed_html)
                self.assertIn("log-pop", authed_html)
                self.assertIn("sizeLogPopToAccess", authed_html)
                self.assertIn("lookingGlassWindows.fit", authed_html)
                self.assertIn("onRefresh: loadTab", authed_html)
                self.assertIn("inspect-pop-refresh", authed_html)
                self.assertIn("/logs?kind=", authed_html)
                self.assertIn("lockPopSize(pop, { width: false }", authed_html)
                self.assertIn("min(96vw, 110rem", authed_html)
                self.assertIn('{ key: "peer", label: "visitor" }', authed_html)
                self.assertIn("row.peer", authed_html)
                self.assertIn("log-summary", authed_html)
                self.assertIn("sortLogRows", authed_html)
                self.assertIn("log-th-sort", authed_html)
                self.assertIn("gui.logs.challenge", authed_html)
                self.assertIn("gui.logs.acme", authed_html)
                self.assertIn("gui.logs.https_out", authed_html)
                self.assertIn("gui.config.wall.default", authed_html)
                self.assertIn(".asn-pop.config-pop", authed_html)
                self.assertIn("min(96vw, 72rem", authed_html)
                self.assertIn("lockPopSize(pop, { width: false, height: false }", authed_html)
                self.assertIn("geomPx(state.width) < 640", authed_html)
                self.assertIn("gui.logs.peak", authed_html)
                self.assertIn("log-charts", authed_html)
                self.assertIn("log-spark", authed_html)
                self.assertIn("log-chart-tick", authed_html)
                self.assertIn("formatTs", authed_html)
                self.assertIn(" → ", authed_html)
                self.assertIn('kind === "clock"', authed_html)
                self.assertIn('kind === "datehour"', authed_html)
                self.assertIn("gui.wall.note", authed_html)
                self.assertIn("openWallMenu", authed_html)
                self.assertIn("data-ip", authed_html)
                self.assertIn("data-asn", authed_html)
                self.assertIn("data-domain", authed_html)
                self.assertIn("paintServe", authed_html)
                out_log = Path(tmp, "data", "lookup.out.log")
                err_log = Path(tmp, "data", "lookup.err.log")
                out_log.parent.mkdir(parents=True, exist_ok=True)
                out_log.write_text(
                    "plain leftover\n"
                    + json.dumps(
                        {
                            "ts": time.time(),
                            "logger": "lookup",
                            "status": 200,
                            "ms": 1.2,
                            "kind": "ip",
                            "query": "1.1.1.1",
                            "intel": {"asn": 13335, "org_name": "CLOUDFLARENET", "country": "AU"},
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                err_log.write_text(
                    "not json\n"
                    + json.dumps(
                        {
                            "ts": time.time(),
                            "logger": "uvicorn.error",
                            "level": "warning",
                            "message": "daemon warn",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                Path(tmp, "data", "wall.log").write_text(
                    json.dumps({"ts": time.time(), "event": "allow", "kind": "ip", "value": "8.8.8.8"})
                    + "\n"
                    + json.dumps(
                        {
                            "ts": time.time(),
                            "event": "issued",
                            "kind": "puzzle",
                            "value": "8.8.8.8",
                            "peer": "8.8.8.8",
                            "reason": "challenge_ip",
                        }
                    )
                    + "\n"
                    + json.dumps(
                        {
                            "ts": time.time(),
                            "event": "solved",
                            "kind": "puzzle",
                            "value": "8.8.8.8",
                            "peer": "8.8.8.8",
                            "reason": "pass",
                        }
                    )
                    + "\n",
                    encoding="utf-8",
                )
                Path(tmp, "data", "build.raw.log").write_text(
                    json.dumps({"ts": time.time(), "logger": "build", "event": "event", "dataset": "iana", "message": "ok"})
                    + "\n",
                    encoding="utf-8",
                )
                Path(tmp, "data", "acme.log").write_text(
                    "2026-08-28T00:00:00Z issued example.com\n",
                    encoding="utf-8",
                )
                unauth, _, _denied_body, _ = respond("wsgi", "127.0.0.1", "/logs", {})
                self.assertEqual(unauth, 401)
                listed, ctype, payload, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs",
                    {},
                    query_string="kind=access",
                    cookie=cookie,
                )
                self.assertEqual(listed, 200)
                self.assertTrue(ctype.startswith("application/json"))
                access = json.loads(payload)
                self.assertTrue(access["ok"])
                paths = [row["path"] for row in access["rows"]]
                self.assertIn("/", paths)
                self.assertNotIn("/status", paths)
                pages = {row.get("page") for row in access["rows"]}
                self.assertIn("index", pages)
                login_fail, _, login_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs",
                    {},
                    query_string="kind=login&ok=false",
                    cookie=cookie,
                )
                self.assertEqual(login_fail, 200)
                fails = json.loads(login_body)["rows"]
                self.assertTrue(any(row.get("ok") is False for row in fails))
                login_ok, _, login_ok_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs",
                    {},
                    query_string="kind=login&ok=true",
                    cookie=cookie,
                )
                self.assertEqual(login_ok, 200)
                wins = json.loads(login_ok_body)["rows"]
                self.assertTrue(any(row.get("ok") is True for row in wins))
                stats_st, _, stats_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs/stats",
                    {},
                    cookie=cookie,
                )
                self.assertEqual(stats_st, 200)
                stats = json.loads(stats_body)
                self.assertIn("index", stats["totals"])
                out_st, _, out_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs",
                    {},
                    query_string="kind=lookup",
                    cookie=cookie,
                )
                self.assertEqual(out_st, 200)
                lookup_payload = json.loads(out_body)
                self.assertIsNone(lookup_payload.get("text"))
                self.assertTrue(lookup_payload["rows"])
                self.assertEqual(lookup_payload["kind"], "lookup")
                self.assertTrue(any(row.get("query") == "1.1.1.1" for row in lookup_payload["rows"]))
                self.assertFalse(any("plain leftover" in json.dumps(row) for row in lookup_payload["rows"]))
                alias_st, _, alias_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs",
                    {},
                    query_string="kind=serve-out",
                    cookie=cookie,
                )
                self.assertEqual(alias_st, 200)
                self.assertEqual(json.loads(alias_body)["kind"], "lookup")
                err_st, _, err_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs",
                    {},
                    query_string="kind=serve-err",
                    cookie=cookie,
                )
                self.assertEqual(err_st, 200)
                err_payload = json.loads(err_body)
                self.assertTrue(any(row.get("message") == "daemon warn" for row in err_payload["rows"]))
                wall_st, _, wall_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs",
                    {},
                    query_string="kind=wall",
                    cookie=cookie,
                )
                self.assertEqual(wall_st, 200)
                wall_rows = json.loads(wall_body)["rows"]
                self.assertTrue(any(row.get("event") == "allow" for row in wall_rows))
                self.assertFalse(any(row.get("kind") == "puzzle" for row in wall_rows))
                challenge_st, _, challenge_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs",
                    {},
                    query_string="kind=challenge",
                    cookie=cookie,
                )
                self.assertEqual(challenge_st, 200)
                challenge_rows = json.loads(challenge_body)["rows"]
                self.assertTrue(any(row.get("event") == "issued" for row in challenge_rows))
                self.assertTrue(any(row.get("event") == "solved" for row in challenge_rows))
                solved_st, _, solved_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs",
                    {},
                    query_string="kind=challenge&ok=true",
                    cookie=cookie,
                )
                self.assertEqual(solved_st, 200)
                self.assertTrue(all(row.get("event") == "solved" for row in json.loads(solved_body)["rows"]))
                build_st, _, build_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs",
                    {},
                    query_string="kind=build",
                    cookie=cookie,
                )
                self.assertEqual(build_st, 200)
                self.assertTrue(any(row.get("logger") == "build" for row in json.loads(build_body)["rows"]))
                acme_st, _, acme_body, _ = respond(
                    "wsgi",
                    "127.0.0.1",
                    "/logs",
                    {},
                    query_string="kind=acme",
                    cookie=cookie,
                )
                self.assertEqual(acme_st, 200)
                self.assertTrue(
                    any("issued example.com" in str(row.get("message") or "") for row in json.loads(acme_body)["rows"])
                )
                with patch("looking_glass.intel_server.app.status", return_value={
                    "running": True,
                    "ready": True,
                    "uptime": 90.0,
                    "pid": 4242,
                    "socket": "/tmp/intel.sock",
                    "stale": False,
                }), patch(
                    "looking_glass.http.https_serve.status",
                    return_value={
                        "running": True,
                        "uptime": 12.0,
                        "port": 5555,
                        "hostname": "s1.example.com",
                        "days_left": 80,
                        "fullchain": "/tmp/fullchain.pem",
                        "privkey": "/tmp/privkey.pem",
                        "subject": "s1.example.com",
                    },
                ):
                    st, _, status_body, _ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/status",
                        {},
                        cookie=cookie,
                    )
                self.assertEqual(st, 200)
                payload = json.loads(status_body)
                serve = payload["serve"]
                self.assertTrue(serve["running"])
                self.assertTrue(serve["ready"])
                self.assertEqual(serve["uptime"], 90.0)
                https = payload["https"]
                self.assertTrue(https["running"])
                self.assertEqual(https["uptime"], 12.0)
                self.assertEqual(https["port"], 5555)
                self.assertEqual(serve["pid"], 4242)
                self.assertEqual(serve["socket"], "/tmp/intel.sock")
                self.assertEqual(https["hostname"], "s1.example.com")
                self.assertEqual(https["days_left"], 80)
                self.assertEqual(https["fullchain"], "/tmp/fullchain.pem")
                self.assertNotIn("privkey", https)

    def test_access_stamps_intel_for_public_peer(self):
        intel = {"asn": 13335, "org_name": "CLOUDFLARENET", "country": "AU", "flag_url": "https://example/au.svg"}
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                weblog.reset()
                with patch("looking_glass.http.weblog.compact_intel", side_effect=lambda v: intel if v == "1.1.1.1" else None):
                    respond("wsgi", "1.1.1.1", "/", {}, accept="text/html")
                path = Path(tmp, "data", "logs", "access.jsonl")
                rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
                self.assertTrue(rows)
                self.assertEqual(rows[-1]["intel"]["asn"], 13335)
                self.assertEqual(rows[-1]["peer"], "1.1.1.1")


class DaemonJsonLogTests(unittest.TestCase):
    def tearDown(self):
        lookup_mod._data_dir_path.cache_clear()

    def test_lookup_writes_json_access(self):
        fake = {
            "ok": True,
            "ip": "1.1.1.1",
            "result": {
                "ip": "1.1.1.1",
                "asn": 13335,
                "org_name": "CLOUDFLARENET",
                "country": "AU",
                "flag_url": "https://example/au.svg",
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()
                with patch("looking_glass.intel_server.app.lookup_ip", return_value=fake):
                    lookup_mod._logged_lookup("1.1.1.1")
                lines = Path(tmp, "lookup.out.log").read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        row = json.loads(lines[0])
        self.assertEqual(row["logger"], "lookup")
        self.assertEqual(row["kind"], "ip")
        self.assertEqual(row["query"], "1.1.1.1")
        self.assertEqual(row["status"], 200)
        self.assertEqual(row["intel"]["asn"], 13335)
        self.assertEqual(row["intel"]["org_name"], "CLOUDFLARENET")

    def test_json_log_formatter(self):
        import logging

        record = logging.LogRecord("uvicorn.error", logging.INFO, __file__, 1, "hello", (), None)
        row = json.loads(lookup_mod.JsonLogFormatter().format(record))
        self.assertEqual(row["message"], "hello")
        self.assertEqual(row["logger"], "uvicorn.error")
        self.assertEqual(row["level"], "info")
        self.assertIn("ts", row)


class BuildJsonLogTests(unittest.TestCase):
    def test_build_writer_emits_jsonl(self):
        from looking_glass.cli.entry import _BuildRawLog

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "build.raw.log")
            raw = _BuildRawLog(path)
            raw.open()
            raw.banner(force=False, data_dir=tmp, planned=["iana"])
            raw.event("iana", "fetched")
            raw.close_banner(1.25)
            raw.close()
            rows = [json.loads(line) for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertGreaterEqual(len(rows), 3)
        self.assertTrue(all(row.get("logger") == "build" for row in rows))
        self.assertEqual(rows[0]["event"], "banner")
        self.assertEqual(rows[1]["event"], "event")
        self.assertEqual(rows[1]["message"], "fetched")
        self.assertEqual(rows[-1]["event"], "end")


class StatsSnapshotTests(unittest.TestCase):
    def tearDown(self):
        weblog.reset()

    def test_sparse_15_minute_buckets(self):
        now = time.time()
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                weblog.reset()
                weblog._bump("index", 200, 12, 3.5, now=now)
                payload = weblog.stats_payload()
        day = payload["day"]["index"]
        self.assertEqual(payload["step"], 900)
        self.assertEqual(len(day), 1)
        self.assertEqual(day[0]["hits"], 1)
        self.assertEqual(day[0]["t"], int(now) // 900 * 900)
        week = payload["week"]["index"]
        self.assertEqual(len(week), 1)

    def test_migrates_old_5_minute_day_keys(self):
        now = time.time()
        old_key = str(int(now) // 300)
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                weblog.reset()
                path = Path(tmp, "data", "logs")
                path.mkdir(parents=True, exist_ok=True)
                (path / "stats.json").write_text(
                    json.dumps(
                        {
                            "day": {
                                "index": {
                                    old_key: {
                                        "hits": 4,
                                        "errors": 0,
                                        "bytes": 10,
                                        "ms_sum": 8.0,
                                        "ms_n": 4,
                                    }
                                }
                            },
                            "week": {},
                        }
                    ),
                    encoding="utf-8",
                )
                payload = weblog.stats_payload()
        day = payload["day"]["index"]
        self.assertEqual(len(day), 1)
        self.assertEqual(day[0]["hits"], 4)
        self.assertEqual(day[0]["t"] % 900, 0)


class LogsStatsCliTests(unittest.TestCase):
    def tearDown(self):
        weblog.reset()

    def test_logs_stats_prints_iso(self):
        from click.testing import CliRunner

        from looking_glass.cli.entry import cli

        now = time.time()
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                weblog.reset()
                weblog._bump("index", 200, 12, 3.5, now=now)
                result = runner.invoke(cli, ["--json", "logs", "stats"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["ok"])
        row = payload["day"]["index"][0]
        self.assertEqual(row["t"], int(now) // 900 * 900)
        self.assertTrue(row["iso"].endswith("Z"))
        self.assertIn("T", row["iso"])
        self.assertEqual(row["hits"], 1)


class DaemonRebuildTests(unittest.TestCase):
    def tearDown(self):
        lookup_mod._data_dir_path.cache_clear()

    def test_rebuild_due_skips_fresh_files(self):
        from looking_glass.datasets import DATASETS, rebuild_due

        now = time.time()
        fresh = {"exists": True, "mtime": now, "size": 50_000, "path": "x"}
        days = {key: 30 for key, *_ in DATASETS}
        with (
            patch("looking_glass.datasets.file_row", return_value=fresh),
            patch("looking_glass.config.refresh_policy", return_value={"days": days}),
            patch("looking_glass.datasets._tee_build_raw"),
            ExitStack() as stack,
        ):
            builds = [
                stack.enter_context(patch.object(mod, "build"))
                for _key, mod, _fn, _label in DATASETS
            ]
            results = rebuild_due(now=now)
            for mocked in builds:
                mocked.assert_not_called()
        self.assertTrue(all(row["result"] == "up_to_date" for row in results))

    def test_rebuild_due_builds_missing(self):
        from looking_glass.datasets import DATASETS, rebuild_due

        missing = {"exists": False, "mtime": None, "size": None, "path": "x"}
        days = {key: 30 for key, *_ in DATASETS}
        with (
            patch("looking_glass.datasets.file_row", return_value=missing),
            patch("looking_glass.config.refresh_policy", return_value={"days": days}),
            patch("looking_glass.datasets._tee_build_raw"),
            ExitStack() as stack,
        ):
            builds = [
                stack.enter_context(patch.object(mod, "build", return_value=True))
                for _key, mod, _fn, _label in DATASETS
            ]
            for _key, mod, _fn, _label in DATASETS:
                stack.enter_context(patch.object(mod, "load", return_value=True))
            results = rebuild_due(now=time.time())
            for mocked in builds:
                mocked.assert_called()
        self.assertTrue(all(row["result"] == "ok" for row in results))

    def test_rebuild_due_tees_build_raw(self):
        from looking_glass.datasets import DATASETS, rebuild_due

        missing = {"exists": False, "mtime": None, "size": None, "path": "x"}
        days = {key: 30 for key, *_ in DATASETS}
        with tempfile.TemporaryDirectory() as tmp:
            dest = os.path.join(tmp, "build.raw.log")
            with (
                patch("looking_glass.datasets.file_row", return_value=missing),
                patch("looking_glass.config.refresh_policy", return_value={"days": days}),
                patch("looking_glass.datasets.get_cache_path", return_value=dest),
                ExitStack() as stack,
            ):
                for _key, mod, _fn, _label in DATASETS:
                    stack.enter_context(patch.object(mod, "build", return_value=True))
                    stack.enter_context(patch.object(mod, "load", return_value=True))
                rebuild_due(now=time.time())
            text = Path(dest).read_text(encoding="utf-8")
        self.assertIn("rebuild start", text)
        self.assertIn("rebuild end", text)

    def test_lifespan_writes_ready_after_rebuild(self):
        async def idle(_loop):
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                raise

        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()
                with (
                    patch("looking_glass.intel_server.app._rebuild_then_load") as rebuild,
                    patch("looking_glass.intel_server.app._refresh_loop", side_effect=idle),
                ):
                    async def run():
                        async with lookup_mod._lifespan(lookup_mod.app):
                            rebuild.assert_called()
                            self.assertTrue(Path(tmp, "lookup.ready").is_file())
                            self.assertTrue(Path(tmp, "lookup.started").is_file())

                    asyncio.run(run())
        rebuild.assert_called()


class IntelServerStartTests(unittest.TestCase):
    def tearDown(self):
        lookup_mod._data_dir_path.cache_clear()

    def test_status_ready_false_until_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()
                Path(tmp, "lookup.pid").write_text(str(os.getpid()), encoding="utf-8")
                with patch("looking_glass.intel_server.app._is_running", return_value=True):
                    info = lookup_mod.status()
                    self.assertTrue(info["running"])
                    self.assertFalse(info["ready"])
                    Path(tmp, "lookup.ready").write_text("1\n", encoding="utf-8")
                    info = lookup_mod.status()
                    self.assertTrue(info["ready"])

    def test_start_waits_for_ready_file(self):
        import threading

        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()
                ready = Path(tmp) / "lookup.ready"

                class FakeProc:
                    pid = 4242

                    def poll(self):
                        return None

                def popen(*_a, **_k):
                    def write_ready():
                        time.sleep(0.25)
                        ready.write_text("1\n", encoding="utf-8")

                    threading.Thread(target=write_ready, daemon=True).start()
                    return FakeProc()

                with (
                    patch("looking_glass.intel_server.app._due_keys", return_value=[]),
                    patch("looking_glass.intel_server.app.subprocess.Popen", side_effect=popen),
                    patch("looking_glass.intel_server.app._is_running", return_value=True),
                ):
                    report = lookup_mod.start(timeout=5, wait_ready=True)
                self.assertTrue(report["ok"], report)
                self.assertEqual(report["state"], "started")
                self.assertTrue(ready.is_file())

    def test_start_not_started_until_ready_when_build_due(self):
        import io
        from contextlib import redirect_stderr

        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()

                class FakeProc:
                    pid = 7

                    def poll(self):
                        return None

                err = io.StringIO()
                with (
                    patch("looking_glass.intel_server.app._due_keys", return_value=["asn", "rir"]),
                    patch("looking_glass.intel_server.app.subprocess.Popen", return_value=FakeProc()),
                    patch("looking_glass.intel_server.app._is_running", return_value=True),
                    redirect_stderr(err),
                ):
                    report = lookup_mod.start(timeout=1, wait_ready=True)
                self.assertFalse(report["ok"])
                self.assertNotEqual(report.get("state"), "started")
                self.assertIn("building asn, rir", err.getvalue())

    def test_start_tails_rebuild_progress(self):
        import io
        import threading
        from contextlib import redirect_stderr

        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()
                errlog = Path(tmp) / "lookup.err.log"
                errlog.write_text("", encoding="utf-8")
                ready = Path(tmp) / "lookup.ready"

                class FakeProc:
                    pid = 9

                    def poll(self):
                        return None

                def popen(*_a, **_k):
                    def progress():
                        time.sleep(0.15)
                        with errlog.open("a", encoding="utf-8") as fh:
                            fh.write(json.dumps({"message": "rebuild start asn"}) + "\n")
                            fh.write(json.dumps({"message": "rebuild end asn"}) + "\n")
                        time.sleep(0.15)
                        ready.write_text("1\n", encoding="utf-8")

                    threading.Thread(target=progress, daemon=True).start()
                    return FakeProc()

                err = io.StringIO()
                with (
                    patch("looking_glass.intel_server.app._due_keys", return_value=["asn"]),
                    patch("looking_glass.intel_server.app.subprocess.Popen", side_effect=popen),
                    patch("looking_glass.intel_server.app._is_running", return_value=True),
                    redirect_stderr(err),
                ):
                    report = lookup_mod.start(timeout=5, wait_ready=True)
                self.assertTrue(report["ok"], report)
                text = err.getvalue()
                self.assertIn("rebuild start asn", text)
                self.assertIn("rebuild end asn", text)

    def test_start_wait_ready_false_returns_starting(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()

                class FakeProc:
                    pid = 11

                    def poll(self):
                        return None

                with (
                    patch("looking_glass.intel_server.app._due_keys", return_value=["asn"]),
                    patch("looking_glass.intel_server.app.subprocess.Popen", return_value=FakeProc()),
                    patch("looking_glass.intel_server.app._is_running", return_value=True),
                ):
                    report = lookup_mod.start(wait_ready=False)
                self.assertTrue(report["ok"])
                self.assertEqual(report["state"], "starting")
                self.assertFalse(report.get("ready"))
                self.assertEqual(report["building"], ["asn"])
                self.assertFalse((Path(tmp) / "lookup.ready").is_file())

    def test_module_path(self):
        import looking_glass.intel_server as pkg
        import looking_glass.intel_server.__main__ as main_mod

        self.assertEqual(lookup_mod.UVICORN_MODULE, "looking_glass.intel_server.app:app")
        self.assertEqual(pkg.__name__, "looking_glass.intel_server")
        self.assertTrue(hasattr(main_mod, "serve_uvicorn"))


class DueKeysTests(unittest.TestCase):
    def test_due_keys_lists_missing(self):
        from looking_glass.datasets import DATASETS, due_keys

        missing = {"exists": False, "mtime": None, "size": None, "path": "x"}
        days = {key: 30 for key, *_ in DATASETS}
        with (
            patch("looking_glass.datasets.file_row", return_value=missing),
            patch("looking_glass.config.refresh_policy", return_value={"days": days}),
        ):
            keys = due_keys(now=time.time())
        self.assertEqual(keys, [key for key, *_ in DATASETS])
