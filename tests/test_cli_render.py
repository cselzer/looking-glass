import json
import os
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass.cli.entry import cli


def _looks_json_object(text: str) -> bool:
    blob = (text or "").lstrip()
    return blob.startswith("{")


class CliRenderTests(unittest.TestCase):
    def test_default_is_not_json_dump(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "ip": "1.1.1.1",
            "via": "local",
            "result": {"ip": "1.1.1.1", "country": "AU", "asn": 13335},
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.cli.entry._daemon_running", return_value=False),
                patch("looking_glass.cli.entry._lookup_ip", return_value=fake),
            ):
                listed = runner.invoke(cli, ["wall", "list"])
                looked = runner.invoke(cli, ["lookup", "1.1.1.1"])
        self.assertEqual(listed.exit_code, 0, listed.output)
        self.assertEqual(looked.exit_code, 0, looked.output)
        self.assertFalse(_looks_json_object(listed.stdout), listed.stdout)
        self.assertFalse(_looks_json_object(looked.stdout), looked.stdout)
        self.assertNotIn('"country_catalog"', listed.stdout)
        self.assertIn("AU", looked.stdout)

    def test_json_flag_parses(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "ip": "1.1.1.1",
            "via": "local",
            "intel": {"running": False},
            "result": {"ip": "1.1.1.1", "country": "AU", "asn": 13335},
        }
        with tempfile.TemporaryDirectory() as tmp:
            with (
                patch("looking_glass.wall.lists.get_data_dir", return_value=tmp),
                patch("looking_glass.cli.entry._daemon_running", return_value=False),
                patch("looking_glass.cli.entry._lookup_ip", return_value=fake),
            ):
                listed = runner.invoke(cli, ["--json", "wall", "list"])
                looked = runner.invoke(cli, ["--json", "lookup", "1.1.1.1"])
                after = runner.invoke(cli, ["wall", "list", "--json"])
        self.assertEqual(listed.exit_code, 0, listed.output)
        self.assertEqual(looked.exit_code, 0, looked.output)
        self.assertEqual(after.exit_code, 0, after.output)
        wall_payload = json.loads(listed.stdout)
        self.assertTrue(wall_payload["ok"])
        self.assertIn("ip", wall_payload)
        lookup_payload = json.loads(looked.stdout)
        self.assertEqual(lookup_payload["result"]["country"], "AU")
        self.assertEqual(json.loads(after.stdout)["ok"], True)

    def test_looking_glass_json_env(self):
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with patch("looking_glass.wall.lists.get_data_dir", return_value=tmp):
                with patch.dict(os.environ, {"LOOKING_GLASS_JSON": "1"}, clear=False):
                    result = runner.invoke(cli, ["wall", "list"])
                with patch.dict(os.environ, {"LOOKING_GLASS_JSON": "0"}, clear=False):
                    off = runner.invoke(cli, ["wall", "list"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertTrue(json.loads(result.stdout)["ok"])
        self.assertEqual(off.exit_code, 0, off.output)
        self.assertFalse(_looks_json_object(off.stdout), off.stdout)


def _intel_report(**extra):
    payload = {
        "ok": True,
        "running": True,
        "ready": True,
        "state": "started",
        "pid": 9818,
        "uptime": 0.12,
        "socket": "/tmp/lookup.sock",
    }
    payload.update(extra)
    return payload


def _https_report(**extra):
    payload = {
        "ok": True,
        "running": True,
        "state": "started",
        "pid": 9823,
        "port": 5555,
        "uptime": 1.11,
        "days_left": 89,
        "fullchain": "/tmp/fullchain.pem",
    }
    payload.update(extra)
    return payload


class DaemonCliTests(unittest.TestCase):
    def test_status_is_compact_not_json(self):
        runner = CliRunner()
        with (
            patch("looking_glass.cli.boot.units_enabled", return_value=False),
            patch("looking_glass.intel_server.app.status", return_value=_intel_report()),
            patch("looking_glass.http.https_serve.status", return_value=_https_report()),
        ):
            human = runner.invoke(cli, ["status"])
            blob = runner.invoke(cli, ["--json", "status"])
        self.assertEqual(human.exit_code, 0, human.output)
        self.assertFalse(_looks_json_object(human.stdout), human.stdout)
        self.assertIn("intel", human.stdout)
        self.assertIn("https", human.stdout)
        self.assertIn("pid 9818", human.stdout)
        self.assertIn(":5555", human.stdout)
        self.assertIn("up 0s", human.stdout)
        self.assertIn("cert 89d", human.stdout)
        self.assertNotIn("pidfile", human.stdout)
        self.assertEqual(blob.exit_code, 0, blob.output)
        payload = json.loads(blob.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["intel"]["pid"], 9818)
        self.assertEqual(payload["https"]["port"], 5555)

    def test_restart_calls_stop_then_start(self):
        runner = CliRunner()
        order = []

        def rec(name, payload):
            def inner(*_a, **_k):
                order.append(name)
                return dict(payload)

            return inner

        with (
            patch("looking_glass.cli.boot.units_enabled", return_value=False),
            patch("looking_glass.http.https_serve.stop", side_effect=rec("https.stop", {"ok": True, "running": False, "state": "stopped"})),
            patch("looking_glass.intel_server.app.stop", side_effect=rec("intel.stop", {"ok": True, "running": False, "state": "stopped"})),
            patch("looking_glass.intel_server.app.start", side_effect=rec("intel.start", _intel_report())),
            patch("looking_glass.http.https_serve.start", side_effect=rec("https.start", _https_report())),
        ):
            result = runner.invoke(cli, ["restart"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(order, ["https.stop", "intel.stop", "intel.start", "https.start"])
        self.assertFalse(_looks_json_object(result.stdout), result.stdout)
        self.assertIn("intel", result.stdout)
        self.assertIn("https", result.stdout)

    def test_restart_starts_from_stopped(self):
        runner = CliRunner()
        with (
            patch("looking_glass.cli.boot.units_enabled", return_value=False),
            patch("looking_glass.http.https_serve.stop", return_value={"ok": True, "running": False, "state": "stopped"}),
            patch("looking_glass.intel_server.app.stop", return_value={"ok": True, "running": False, "state": "stopped"}),
            patch("looking_glass.intel_server.app.start", return_value=_intel_report()) as intel_start,
            patch("looking_glass.http.https_serve.start", return_value=_https_report()) as https_start,
        ):
            result = runner.invoke(cli, ["restart"])
        self.assertEqual(result.exit_code, 0, result.output)
        intel_start.assert_called_once()
        https_start.assert_called_once()

    def test_restart_exits_1_when_start_fails(self):
        runner = CliRunner()
        with (
            patch("looking_glass.cli.boot.units_enabled", return_value=False),
            patch("looking_glass.http.https_serve.stop", return_value={"ok": True, "state": "stopped"}),
            patch("looking_glass.intel_server.app.stop", return_value={"ok": True, "state": "stopped"}),
            patch("looking_glass.intel_server.app.start", return_value=_intel_report()),
            patch("looking_glass.http.https_serve.start", return_value={"ok": False, "error": "no cert", "running": False}),
        ):
            result = runner.invoke(cli, ["restart"])
        self.assertEqual(result.exit_code, 1, result.output)
        self.assertIn("https", result.stdout)
