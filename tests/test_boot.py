import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass.cli.boot import (
    HTTPS_UNIT,
    INTEL_UNIT,
    TARGET_UNIT,
    canonical_units,
    check,
    enable,
)
from looking_glass.cli.entry import cli


def _linger(on: bool = True, user: str = "cody"):
    return {
        "ok": True,
        "enabled": on,
        "user": user,
        "hint": f"loginctl enable-linger {user}",
        "raw": f"Linger={'yes' if on else 'no'}",
    }


def _systemctl(enabled: bool = True, active: bool = True):
    def run(argv, timeout=15):
        if argv[:1] == ["loginctl"]:
            return 0, "Linger=yes", ""
        if argv[:2] != ["systemctl", "--user"]:
            return 1, "", "unexpected"
        cmd = argv[2]
        if cmd == "daemon-reload":
            return 0, "", ""
        if cmd == "enable":
            return 0, "", ""
        if cmd == "restart":
            return 0, "", ""
        if cmd == "status":
            return 0, "● looking-glass-intel.service\n● looking-glass-https.service", ""
        if cmd == "is-enabled":
            return (0, "enabled", "") if enabled else (1, "disabled", "")
        if cmd == "is-active":
            return (0, "active", "") if active else (3, "inactive", "")
        return 1, "", "unexpected " + cmd

    return run


class BootUnitTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_linger_off_enable_writes_nothing(self):
        with patch("looking_glass.cli.boot.linger_status", return_value=_linger(False)):
            payload = enable(unit_dir=self.tmp, exe="/opt/lg/looking-glass")
        self.assertFalse(payload["ok"])
        self.assertIn("linger is off", payload["error"])
        self.assertIn("loginctl enable-linger", payload["error"])
        self.assertEqual(list(self.tmp.iterdir()), [])

    def test_enable_writes_three_canonical_files(self):
        exe = "/opt/lg/looking-glass"
        with (
            patch("looking_glass.cli.boot.linger_status", return_value=_linger(True)),
            patch("looking_glass.cli.boot._run", side_effect=_systemctl()),
        ):
            payload = enable(unit_dir=self.tmp, exe=exe)
        self.assertTrue(payload["ok"], payload)
        self.assertEqual(payload["action"], "added")
        wanted = canonical_units(exe)
        for name, text in wanted.items():
            self.assertEqual((self.tmp / name).read_text(encoding="utf-8"), text)
        intel = (self.tmp / INTEL_UNIT).read_text(encoding="utf-8")
        https = (self.tmp / HTTPS_UNIT).read_text(encoding="utf-8")
        self.assertIn("Restart=on-failure", intel)
        self.assertIn("lookup-server start --foreground", intel)
        self.assertIn("https start --foreground", https)

    def test_second_enable_does_not_rewrite_when_active(self):
        exe = "/opt/lg/looking-glass"
        with (
            patch("looking_glass.cli.boot.linger_status", return_value=_linger(True)),
            patch("looking_glass.cli.boot._run", side_effect=_systemctl()) as run,
        ):
            first = enable(unit_dir=self.tmp, exe=exe)
            mtimes = {name: (self.tmp / name).stat().st_mtime_ns for name in canonical_units(exe)}
            run.reset_mock()
            second = enable(unit_dir=self.tmp, exe=exe)
        self.assertEqual(first["action"], "added")
        self.assertEqual(second["action"], "unchanged")
        for name, stamp in mtimes.items():
            self.assertEqual((self.tmp / name).stat().st_mtime_ns, stamp)
        wrote = [
            list(c.args[0])
            for c in run.call_args_list
            if c.args and len(c.args[0]) > 2 and c.args[0][2] == "enable"
        ]
        self.assertEqual(wrote, [])

    def test_edited_unit_is_replaced_sibling_left_alone(self):
        exe = "/opt/lg/looking-glass"
        wanted = canonical_units(exe)
        (self.tmp / INTEL_UNIT).write_text(wanted[INTEL_UNIT], encoding="utf-8")
        (self.tmp / HTTPS_UNIT).write_text("[Service]\nExecStart=/bin/false\n", encoding="utf-8")
        (self.tmp / TARGET_UNIT).write_text(wanted[TARGET_UNIT], encoding="utf-8")
        (self.tmp / "other.service").write_text("[Service]\nExecStart=/bin/true\n", encoding="utf-8")
        with (
            patch("looking_glass.cli.boot.linger_status", return_value=_linger(True)),
            patch("looking_glass.cli.boot._run", side_effect=_systemctl()),
        ):
            payload = enable(unit_dir=self.tmp, exe=exe)
        self.assertEqual(payload["action"], "replaced")
        self.assertEqual((self.tmp / HTTPS_UNIT).read_text(encoding="utf-8"), wanted[HTTPS_UNIT])
        self.assertEqual((self.tmp / INTEL_UNIT).read_text(encoding="utf-8"), wanted[INTEL_UNIT])
        self.assertEqual(
            (self.tmp / "other.service").read_text(encoding="utf-8"),
            "[Service]\nExecStart=/bin/true\n",
        )

    def test_linger_status_parses_loginctl(self):
        from looking_glass.cli import boot as boot_mod

        with patch("looking_glass.cli.boot._run", return_value=(0, "Linger=yes", "")):
            on = boot_mod.linger_status("cody")
        with patch("looking_glass.cli.boot._run", return_value=(0, "Linger=no", "")):
            off = boot_mod.linger_status("cody")
        self.assertTrue(on["enabled"])
        self.assertFalse(off["enabled"])

    def test_check_missing_files_is_not_ok(self):
        with (
            patch("looking_glass.cli.boot.linger_status", return_value=_linger(True)),
            patch("looking_glass.cli.boot._run", side_effect=_systemctl(enabled=False, active=False)),
        ):
            payload = check(unit_dir=self.tmp, exe="/opt/lg/looking-glass")
        self.assertFalse(payload["ok"])
        self.assertIn("missing", payload["error"])


class BootCliTests(unittest.TestCase):
    def test_help_and_json_check(self):
        runner = CliRunner()
        help_result = runner.invoke(cli, ["boot", "--help"])
        self.assertEqual(help_result.exit_code, 0, help_result.output)
        self.assertIn("check", help_result.output)
        self.assertIn("enable", help_result.output)
        self.assertNotIn("looking-glass serve", help_result.output)

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        with (
            patch("looking_glass.cli.boot.user_unit_dir", return_value=tmp),
            patch("looking_glass.cli.boot.linger_status", return_value=_linger(False)),
            patch("looking_glass.cli.boot._run", side_effect=_systemctl(enabled=False, active=False)),
        ):
            result = runner.invoke(cli, ["--json", "boot", "check"])
        self.assertEqual(result.exit_code, 1)
        payload = json.loads(result.output)
        self.assertFalse(payload["ok"])
        self.assertFalse(payload["linger"]["enabled"])


class BootDaemonCliTests(unittest.TestCase):
    def test_restart_uses_systemctl_when_units_enabled(self):
        from tests.test_cli_render import _https_report, _intel_report

        calls = []

        def run(argv, timeout=15):
            calls.append(list(argv))
            cmd = argv[2] if len(argv) > 2 else ""
            if cmd == "is-enabled":
                return 0, "enabled", ""
            if cmd == "is-active":
                return 0, "active", ""
            if cmd == "restart":
                return 0, "", ""
            if cmd == "status":
                return 0, "● looking-glass-intel.service", ""
            return 1, "", "unexpected"

        runner = CliRunner()
        with (
            patch("looking_glass.cli.boot._run", side_effect=run),
            patch("looking_glass.intel_server.app.status", return_value=_intel_report()),
            patch("looking_glass.http.https_serve.status", return_value=_https_report()),
            patch("looking_glass.http.https_serve.stop") as https_stop,
            patch("looking_glass.intel_server.app.stop") as intel_stop,
            patch("looking_glass.intel_server.app.start") as intel_start,
            patch("looking_glass.http.https_serve.start") as https_start,
        ):
            result = runner.invoke(cli, ["restart"])
        self.assertEqual(result.exit_code, 0, result.output)
        https_stop.assert_not_called()
        intel_stop.assert_not_called()
        intel_start.assert_not_called()
        https_start.assert_not_called()
        self.assertTrue(
            any(c[:5] == ["systemctl", "--user", "restart", INTEL_UNIT, HTTPS_UNIT] for c in calls)
        )
        self.assertIn("systemctl --user restart", result.output)
        self.assertIn("unit active", result.output)

    def test_status_includes_systemd(self):
        from tests.test_cli_render import _https_report, _intel_report

        runner = CliRunner()
        with (
            patch("looking_glass.cli.boot._run", side_effect=_systemctl()),
            patch("looking_glass.intel_server.app.status", return_value=_intel_report()),
            patch("looking_glass.http.https_serve.status", return_value=_https_report()),
        ):
            human = runner.invoke(cli, ["status"])
            blob = runner.invoke(cli, ["--json", "status"])
        self.assertEqual(human.exit_code, 0, human.output)
        self.assertIn("unit active", human.stdout)
        self.assertIn("pid 9818", human.stdout)
        self.assertIn("systemctl --user status", human.stdout)
        payload = json.loads(blob.stdout)
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["via"], "systemd")
        self.assertTrue(payload["intel"]["systemd"]["active"])
        self.assertTrue(payload["https"]["systemd"]["enabled"])
        self.assertEqual(payload["intel"]["pid"], 9818)

    def test_restart_systemctl_fail_skips_pidfile(self):
        def run(argv, timeout=15):
            cmd = argv[2] if len(argv) > 2 else ""
            if cmd == "is-enabled":
                return 0, "enabled", ""
            if cmd == "is-active":
                return 0, "active", ""
            if cmd == "restart":
                return 1, "", "Job for looking-glass-intel.service failed"
            return 1, "", "unexpected"

        runner = CliRunner()
        with (
            patch("looking_glass.cli.boot._run", side_effect=run),
            patch("looking_glass.http.https_serve.stop") as https_stop,
            patch("looking_glass.intel_server.app.start") as intel_start,
        ):
            result = runner.invoke(cli, ["restart"])
        self.assertEqual(result.exit_code, 1, result.output)
        https_stop.assert_not_called()
        intel_start.assert_not_called()
        self.assertIn("systemctl --user restart", result.output)
