import errno
import json
import os
import signal
import tempfile
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from looking_glass.cli.entry import cli
from looking_glass.config import load, set_value
from looking_glass.http import acme_issue, https_serve
from looking_glass.intel_server import app as lookup_mod


def _roots(tmp: str):
    return (
        patch("looking_glass.config.get_root", return_value=tmp),
        patch("looking_glass.utility.get_root", return_value=tmp),
    )


class AcmeIssueTests(unittest.TestCase):
    def test_refuse_without_hostname_or_email(self):
        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            with self.assertRaises(ValueError) as ctx:
                acme_issue.ensure_certificate("", "ops@example.com")
            self.assertIn("hostname", str(ctx.exception))
            with self.assertRaises(ValueError) as ctx:
                acme_issue.ensure_certificate("s1.example.com", "")
            self.assertIn("email", str(ctx.exception))

    def test_mocked_issuer_writes_pems(self):
        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            def issuer(host, email, **_kwargs):
                written = acme_issue.write_self_signed(host, days=90)
                return (
                    open(written["fullchain"], encoding="utf-8").read(),
                    open(written["privkey"], encoding="utf-8").read(),
                )

            out = acme_issue.ensure_certificate(
                "s1.example.com",
                "ops@example.com",
                issuer=issuer,
            )
            self.assertTrue(out["issued"])
            self.assertTrue(os.path.isfile(out["fullchain"]))
            self.assertTrue(os.path.isfile(out["privkey"]))
            again = acme_issue.ensure_certificate(
                "s1.example.com",
                "ops@example.com",
                issuer=issuer,
            )
            self.assertFalse(again["issued"])

    def test_bind_80_failure_message(self):
        err = OSError(errno.EACCES, "Permission denied")
        err.errno = errno.EACCES
        with patch("looking_glass.http.acme_issue.HTTPServer", side_effect=err):
            with self.assertRaises(OSError) as ctx:
                with acme_issue.serve_http01(80, "token", "body"):
                    pass
        text = str(ctx.exception)
        self.assertIn("ip_unprivileged_port_start", text)
        self.assertIn("80", text)
        self.assertIn("EACCES", text)


class HttpsSupervisorTests(unittest.TestCase):
    def test_start_requires_email(self):
        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            load()
            set_value("http.enabled", True)
            set_value("http.hostname", "s1.example.com")
            report = https_serve.start()
            self.assertFalse(report["ok"])
            self.assertIn("email", report["error"])

    def test_restart_when_workers_change(self):
        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            load()
            set_value("http.enabled", True)
            set_value("http.hostname", "s1.example.com")
            set_value("http.email", "ops@example.com")
            acme_issue.write_self_signed("s1.example.com", days=90)
            spawned = []

            def spawn(*_a, **_k):
                proc = MagicMock()
                proc.poll.return_value = None
                spawned.append(proc)
                return proc

            step = {"n": 0}

            def should_stop():
                step["n"] += 1
                if step["n"] == 3:
                    set_value("http.workers", "4")
                return step["n"] > 6

            https_serve.supervisor_loop(
                poll=0.01,
                renew_every=10_000,
                spawn=spawn,
                sleep=lambda _s: None,
                should_stop=should_stop,
            )
            self.assertGreaterEqual(len(spawned), 2)
            self.assertEqual(load()["http"]["workers"], 4)

    def test_supervisor_spawns_ipv4_and_ipv6(self):
        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            load()
            set_value("http.enabled", True)
            set_value("http.hostname", "s1.example.com")
            set_value("http.email", "ops@example.com")
            acme_issue.write_self_signed("s1.example.com", days=90)
            hosts = []

            def spawn(*_a, **kwargs):
                proc = MagicMock()
                proc.poll.return_value = None
                hosts.append(kwargs.get("host"))
                return proc

            step = {"n": 0}

            def should_stop():
                step["n"] += 1
                return step["n"] > 2

            https_serve.supervisor_loop(
                poll=0.01,
                renew_every=10_000,
                spawn=spawn,
                sleep=lambda _s: None,
                should_stop=should_stop,
            )
            self.assertEqual(hosts, ["0.0.0.0", "::"])

    def test_status_includes_cert_not_after(self):
        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            load()
            set_value("http.enabled", True)
            set_value("http.hostname", "s1.example.com")
            set_value("http.email", "ops@example.com")
            acme_issue.write_self_signed("s1.example.com", days=90)
            info = https_serve.status()
        self.assertTrue(info["enabled"])
        self.assertEqual(info["hostname"], "s1.example.com")
        self.assertFalse(info["needs_issue"])
        self.assertFalse(info["staging"])
        self.assertEqual(info["acme_port"], 80)
        self.assertTrue(info["fullchain_exists"])
        self.assertTrue(info["privkey_exists"])
        self.assertIn("privkey", info)
        self.assertIn("account_key", info)
        self.assertIn("not_after", info)
        self.assertIn("fullchain", info)
        self.assertGreaterEqual(info["days_left"], 30)
        self.assertEqual((info.get("subject") or {}).get("commonName"), "s1.example.com")
        self.assertIn("s1.example.com", info.get("san") or [])
        self.assertEqual(info["bind"], "*")
        self.assertEqual(info["listen"], ["0.0.0.0", "::"])
        expiry = datetime.fromisoformat(info["not_after"])
        self.assertGreater(expiry, datetime.now(timezone.utc) + timedelta(days=30))

    def test_uvicorn_omits_workers_when_one(self):
        self.assertEqual(https_serve._listen_hosts("*"), ["0.0.0.0", "::"])
        self.assertEqual(https_serve._listen_hosts("0.0.0.0"), ["0.0.0.0"])
        self.assertEqual(https_serve._listen_hosts("::"), ["::"])
        one = https_serve._uvicorn_cmd(
            {"bind": "*", "port": 5555, "workers": 1},
            Path("/tmp/fullchain.pem"),
            Path("/tmp/privkey.pem"),
            host="0.0.0.0",
        )
        self.assertNotIn("--workers", one)
        self.assertIn("0.0.0.0", one)
        two = https_serve._uvicorn_cmd(
            {"bind": "::", "port": 5555, "workers": 2},
            Path("/tmp/fullchain.pem"),
            Path("/tmp/privkey.pem"),
            host="::",
        )
        self.assertIn("--workers", two)
        self.assertEqual(two[two.index("--workers") + 1], "2")
        self.assertIn("::", two)

    def test_start_fails_when_port_in_use(self):
        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            load()
            set_value("http.enabled", True)
            set_value("http.hostname", "s1.example.com")
            set_value("http.email", "ops@example.com")
            with (
                patch(
                    "looking_glass.http.https_serve._busy_hosts",
                    return_value=["0.0.0.0"],
                ),
                patch("looking_glass.http.https_serve.ensure_ready") as ready,
                patch("looking_glass.http.https_serve.subprocess.Popen") as popen,
            ):
                report = https_serve.start()
        self.assertFalse(report["ok"])
        self.assertIn("already in use", report["error"])
        self.assertIn("0.0.0.0:5555", report["error"])
        self.assertEqual(report["bind"], "*")
        self.assertEqual(report["port"], 5555)
        ready.assert_not_called()
        popen.assert_not_called()

    def test_stop_kills_orphan_asgi(self):
        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            load()
            live = {4242: True}
            killed = []

            def is_running(pid):
                return bool(live.get(pid))

            def fake_kill(pid, sig):
                killed.append((pid, sig))
                if sig in (signal.SIGTERM, signal.SIGKILL):
                    live[pid] = False

            with (
                patch("looking_glass.http.https_serve._asgi_pids", return_value=[4242]),
                patch("looking_glass.http.https_serve._is_running", side_effect=is_running),
                patch("looking_glass.http.https_serve.os.kill", side_effect=fake_kill),
            ):
                report = https_serve.stop()
        self.assertTrue(report["ok"])
        self.assertEqual(report["state"], "stopped")
        self.assertTrue(any(pid == 4242 for pid, _sig in killed))

    def test_logs_tail(self):
        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            data = Path(tmp) / "data"
            data.mkdir()
            (data / "https.err.log").write_text("old-err\nnew-err\n", encoding="utf-8")
            (data / "https.out.log").write_text("old-out\nnew-out\n", encoding="utf-8")
            payload = https_serve.logs(lines=1)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["err"], "new-err")
        self.assertEqual(payload["out"], "new-out")
        self.assertIn("https.err.log", payload["err_log"])
        self.assertNotIn("old-err", payload["err"])

    def test_renew_force_reissues(self):
        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            load()
            set_value("http.hostname", "s1.example.com")
            set_value("http.email", "ops@example.com")
            first = acme_issue.write_self_signed("s1.example.com", days=90)
            calls = {"n": 0}

            def issuer(host, email, **_kwargs):
                calls["n"] += 1
                written = acme_issue.write_self_signed(host, days=60)
                return (
                    Path(written["fullchain"]).read_text(encoding="utf-8"),
                    Path(written["privkey"]).read_text(encoding="utf-8"),
                )

            skipped = acme_issue.ensure_certificate(
                "s1.example.com",
                "ops@example.com",
                issuer=issuer,
            )
            self.assertFalse(skipped["issued"])
            self.assertEqual(calls["n"], 0)
            forced = acme_issue.ensure_certificate(
                "s1.example.com",
                "ops@example.com",
                force=True,
                issuer=issuer,
            )
            self.assertTrue(forced["issued"])
            self.assertEqual(calls["n"], 1)
            self.assertEqual(forced["fullchain"], first["fullchain"])

    def test_renew_uses_force_and_skips_enabled(self):
        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            load()
            set_value("http.enabled", False)
            set_value("http.hostname", "s1.example.com")
            set_value("http.email", "ops@example.com")
            with patch(
                "looking_glass.http.acme_issue.ensure_certificate",
                return_value={
                    "fullchain": "/tmp/fullchain.pem",
                    "privkey": "/tmp/privkey.pem",
                    "issued": True,
                },
            ) as issue:
                report = https_serve.renew(force=True)
        self.assertTrue(report["ok"], report)
        self.assertTrue(report["issued"])
        self.assertEqual(report["state"], "issued")
        issue.assert_called_once()
        self.assertTrue(issue.call_args.kwargs.get("force"))

    def test_supervisor_logs_acme_errors(self):
        import io
        from contextlib import redirect_stderr

        with tempfile.TemporaryDirectory() as tmp, _roots(tmp)[0], _roots(tmp)[1]:
            load()
            set_value("http.enabled", True)
            set_value("http.hostname", "s1.example.com")
            set_value("http.email", "ops@example.com")
            step = {"n": 0}

            def should_stop():
                step["n"] += 1
                return step["n"] > 2

            err = io.StringIO()
            with (
                patch("looking_glass.http.https_serve.ensure_ready", side_effect=RuntimeError("bind 80")),
                redirect_stderr(err),
            ):
                https_serve.supervisor_loop(
                    poll=0.01,
                    renew_every=10_000,
                    spawn=lambda *_a, **_k: None,
                    sleep=lambda _s: None,
                    should_stop=should_stop,
                )
            text = err.getvalue()
            self.assertIn("HTTPS ACME", text)
            self.assertIn("bind 80", text)


class HttpsCliTests(unittest.TestCase):
    def test_status_cli(self):
        fake = {
            "enabled": True,
            "running": False,
            "pid": None,
            "hostname": "s1.example.com",
            "port": 5555,
            "workers": 1,
            "not_after": "2026-11-25T00:00:00+00:00",
            "out_log": "/tmp/https.out.log",
            "err_log": "/tmp/https.err.log",
        }
        runner = CliRunner()
        with patch("looking_glass.http.https_serve.status", return_value=dict(fake)):
            result = runner.invoke(cli, ["--json", "https", "status"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["hostname"], "s1.example.com")
        self.assertEqual(payload["not_after"], fake["not_after"])
        self.assertEqual(payload["state"], "not_running")
        self.assertEqual(payload["port"], 5555)

    def test_start_cli(self):
        runner = CliRunner()
        with patch(
            "looking_glass.http.https_serve.start",
            return_value={"ok": True, "state": "started", "enabled": True},
        ) as start:
            result = runner.invoke(cli, ["--json", "https", "start"])
        self.assertEqual(result.exit_code, 0, result.output)
        start.assert_called_once()
        kwargs = start.call_args.kwargs
        self.assertEqual(kwargs.get("timeout"), 8)
        self.assertFalse(kwargs.get("foreground"))
        payload = json.loads(result.output)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["state"], "started")

    def test_logs_cli(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "out_log": "/tmp/https.out.log",
            "err_log": "/tmp/https.err.log",
            "lines": 50,
            "out": "listening",
            "err": "issued",
        }
        with patch("looking_glass.http.https_serve.logs", return_value=dict(fake)):
            result = runner.invoke(cli, ["--json", "https", "logs"])
        self.assertEqual(result.exit_code, 0, result.output)
        payload = json.loads(result.output)
        self.assertEqual(payload["err"], "issued")
        self.assertEqual(payload["out"], "listening")

    def test_renew_cli_force(self):
        runner = CliRunner()
        with patch(
            "looking_glass.http.https_serve.renew",
            return_value={
                "ok": True,
                "state": "issued",
                "issued": True,
                "staging": False,
                "fullchain": "/tmp/fullchain.pem",
                "not_after": "2026-11-25T00:00:00+00:00",
            },
        ) as renew:
            result = runner.invoke(cli, ["--json", "https", "renew", "--force"])
        self.assertEqual(result.exit_code, 0, result.output)
        renew.assert_called_once()
        self.assertTrue(renew.call_args.kwargs.get("force"))
        payload = json.loads(result.output)
        self.assertTrue(payload["issued"])
        self.assertNotIn("BEGIN PRIVATE KEY", result.output)
        self.assertNotIn("BEGIN CERTIFICATE", result.output)

    def test_no_lookup_server_acme_copy(self):
        root = Path(__file__).resolve().parents[1]
        readme = (root / "README.md").read_text(encoding="utf-8")
        self.assertNotIn("lookup-server starts ACME", readme)
        self.assertNotIn("Set `http.enabled` to also run", readme)
        self.assertIn("looking-glass https start", readme)
        runner = CliRunner()
        lookup_help = runner.invoke(cli, ["lookup-server", "--help"])
        self.assertEqual(lookup_help.exit_code, 0, lookup_help.output)
        self.assertNotIn("ACME", lookup_help.output)
        self.assertNotIn("5555", lookup_help.output)


class IntelHttpsDecoupleTests(unittest.TestCase):
    def tearDown(self):
        lookup_mod._data_dir_path.cache_clear()

    def test_lookup_server_status_has_no_https_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()
                info = lookup_mod.status()
        self.assertNotIn("https", info)
        self.assertIn("ready", info)
        self.assertIn("socket_exists", info)

    def test_lookup_server_start_does_not_start_https(self):
        import threading

        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.intel_server.app.get_data_dir", return_value=tmp):
                lookup_mod._data_dir_path.cache_clear()
                ready = Path(tmp) / "lookup.ready"

                class FakeProc:
                    pid = 99

                    def poll(self):
                        return None

                def popen(*_a, **_k):
                    def write_ready():
                        time.sleep(0.05)
                        ready.write_text("1\n", encoding="utf-8")

                    threading.Thread(target=write_ready, daemon=True).start()
                    return FakeProc()

                with (
                    patch("looking_glass.intel_server.app._due_keys", return_value=[]),
                    patch("looking_glass.intel_server.app.subprocess.Popen", side_effect=popen),
                    patch("looking_glass.intel_server.app._is_running", return_value=True),
                    patch("looking_glass.http.https_serve.start") as https_start,
                ):
                    report = lookup_mod.start(timeout=5, wait_ready=True)
                self.assertTrue(report["ok"], report)
                https_start.assert_not_called()
