import json
import os
import tempfile
import unittest
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass.auth import history as action_history
from looking_glass.cli.entry import cli
from looking_glass.config import set_value
from looking_glass.http.site import respond
from looking_glass.observe import attach_observation, observed_at
from looking_glass.utility import save_json_cache
from tests.test_wall import _with_static


def _roots(tmp: str):
    return (
        patch("looking_glass.config.get_root", return_value=tmp),
        patch("looking_glass.utility.get_root", return_value=tmp),
    )


def _tcp_payload(host="example.com", port=443, status="ok", ok=True):
    return {
        "ok": ok,
        "kind": "tcp",
        "query": host,
        "result": {
            "host": host,
            "port": port,
            "ok": ok,
            "status": status,
            "peer": f"1.1.1.1:{port}" if ok else None,
            "rtt_ms": 1.5,
            "banner": None,
            "error": None if ok else "Connection refused",
        },
    }


def _tls_payload(sha256: str):
    return {
        "ok": True,
        "kind": "tls",
        "query": "example.com",
        "result": {
            "host": "example.com",
            "port": 443,
            "ip": "1.1.1.1",
            "verified": True,
            "protocol": "TLSv1.3",
            "hostname_matches": True,
            "leaf": {"sha256": sha256},
        },
    }


class ObserveTests(unittest.TestCase):
    def test_attach_observation_sets_probe_and_time(self):
        payload = {"ok": True, "kind": "tcp"}
        with (
            patch("looking_glass.observe.hostname", return_value="probe.host"),
            patch("looking_glass.observe.egress_ip", return_value="203.0.113.8"),
        ):
            attach_observation(payload)
        self.assertEqual(payload["probe"], {"host": "probe.host", "ip": "203.0.113.8"})
        self.assertRegex(payload["observed_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

    def test_attach_does_not_overwrite(self):
        payload = {
            "ok": True,
            "observed_at": "2026-01-01T00:00:00Z",
            "probe": {"host": "kept", "ip": "192.0.2.1"},
        }
        attach_observation(payload)
        self.assertEqual(payload["observed_at"], "2026-01-01T00:00:00Z")
        self.assertEqual(payload["probe"]["host"], "kept")

    def test_observed_at_is_utc_z(self):
        self.assertTrue(observed_at().endswith("Z"))


class ProbeStampTests(unittest.TestCase):
    def test_http_envelope_and_cli(self):
        fake = {
            "ok": True,
            "result": {
                "host": "example.com",
                "port": 443,
                "ok": True,
                "status": "ok",
                "peer": "1.1.1.1:443",
                "rtt_ms": 2.0,
                "banner": None,
                "error": None,
            },
            "error": None,
        }
        runner = CliRunner()
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with (
                    patch("looking_glass.http.site.check_tcp", return_value=fake),
                    patch("looking_glass.cli.tools.lookup_classified", return_value=dict(fake)),
                    patch("looking_glass.observe.hostname", return_value="probe.host"),
                    patch("looking_glass.observe.egress_ip", return_value="203.0.113.8"),
                    patch("looking_glass.http.weblog.compact_intel", return_value=None),
                ):
                    status, _, body, _ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/tcp/example.com/443",
                        {},
                        accept="application/json",
                    )
                    self.assertEqual(status, 200)
                    http_payload = json.loads(body)
                    self.assertEqual(http_payload["probe"]["host"], "probe.host")
                    self.assertEqual(http_payload["probe"]["ip"], "203.0.113.8")
                    self.assertRegex(
                        http_payload["observed_at"],
                        r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$",
                    )
                    self.assertEqual(http_payload["result"]["status"], "ok")
                    self.assertTrue(http_payload.get("id"))
                    self.assertIn("/history/", str(http_payload.get("history") or ""))
                    html_status, _, html, _ = respond(
                        "wsgi",
                        "127.0.0.1",
                        "/tcp/example.com/443",
                        {},
                        accept="text/html",
                        host="lg.example.com",
                    )
                    self.assertEqual(html_status, 200)
                    text = _with_static(html)
                    self.assertIn("decorateReport", text)
                    self.assertIn("probe-observed", text)
                    self.assertIn("/history/", text)
                    cli_out = runner.invoke(cli, ["--json", "tcp", "example.com", "-p", "443"])
        self.assertEqual(cli_out.exit_code, 0, cli_out.output)
        cli_payload = json.loads(cli_out.output)
        self.assertEqual(cli_payload["probe"]["host"], "probe.host")
        self.assertRegex(cli_payload["observed_at"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
        self.assertTrue(cli_payload.get("id"))
        self.assertTrue(str(cli_payload.get("history") or "").startswith("/history/"))


class SnapshotHistoryTests(unittest.TestCase):
    def test_zero_writes_no_target_index(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                set_value("history.snapshots", "0")
                with (
                    patch("looking_glass.observe.hostname", return_value="probe.host"),
                    patch("looking_glass.observe.egress_ip", return_value="203.0.113.8"),
                    patch("looking_glass.http.weblog.compact_intel", return_value=None),
                ):
                    ident = action_history.append(
                        "",
                        path="/tcp/example.com/443",
                        kind="tcp",
                        query="example.com",
                        payload=_tcp_payload(),
                    )
                self.assertIsNotNone(ident)
                self.assertFalse(os.path.isdir(os.path.join(tmp, "data", "history", "targets")))
                entry = action_history.get_entry("", ident)
                self.assertNotIn("diff", entry["payload"])
                self.assertNotIn("prev_id", entry["payload"])
                self.assertEqual(entry["payload"]["id"], ident)
                self.assertTrue(str(entry["payload"].get("history") or "").startswith("/history/"))

    def test_unlimited_skips_global_trim_and_rail_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                root = os.path.join(tmp, "data", "history")
                os.makedirs(root, exist_ok=True)
                for i in range(action_history.CAP + 1):
                    ident = f"{i:013d}-{'a' * 32}"
                    save_json_cache(
                        os.path.join(root, f"{ident}.json"),
                        {
                            "id": ident,
                            "ts": float(i),
                            "kind": "tcp",
                            "query": f"h{i}.example",
                            "payload": _tcp_payload(f"h{i}.example"),
                        },
                    )
                action_history._trim()
                files = [name for name in os.listdir(root) if name.endswith(".json")]
                self.assertEqual(len(files), action_history.CAP + 1)
                rows = action_history.list_entries()
                self.assertEqual(len(rows), action_history.CAP)
                self.assertEqual(rows[0]["query"], f"h{action_history.CAP}.example")

    def test_keep_two_drops_the_third(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                set_value("history.snapshots", "2")
                ids = []
                with (
                    patch("looking_glass.observe.hostname", return_value="probe.host"),
                    patch("looking_glass.observe.egress_ip", return_value="203.0.113.8"),
                    patch("looking_glass.http.weblog.compact_intel", return_value=None),
                ):
                    for _ in range(3):
                        ids.append(
                            action_history.append(
                                "",
                                path="/tcp/example.com/443",
                                kind="tcp",
                                query="example.com",
                                payload=_tcp_payload(),
                            )
                        )
                root = os.path.join(tmp, "data", "history")
                kept = [name for name in os.listdir(root) if name.endswith(".json")]
                self.assertEqual(len(kept), 2)
                self.assertIsNone(action_history.get_entry("", ids[0]))
                self.assertIsNotNone(action_history.get_entry("", ids[1]))
                self.assertIsNotNone(action_history.get_entry("", ids[2]))
                targets = os.path.join(root, "targets", "tcp")
                index_files = os.listdir(targets)
                self.assertEqual(len(index_files), 1)
                index = json.loads(open(os.path.join(targets, index_files[0]), encoding="utf-8").read())
                self.assertEqual(index["ids"], [ids[2], ids[1]])

    def test_cert_changed_diff(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with (
                    patch("looking_glass.observe.hostname", return_value="probe.host"),
                    patch("looking_glass.observe.egress_ip", return_value="203.0.113.8"),
                    patch("looking_glass.http.weblog.compact_intel", return_value=None),
                ):
                    first = action_history.append(
                        "",
                        path="/tls/example.com",
                        kind="tls",
                        query="example.com",
                        payload=_tls_payload("aaa"),
                    )
                    second = action_history.append(
                        "",
                        path="/tls/example.com",
                        kind="tls",
                        query="example.com",
                        payload=_tls_payload("bbb"),
                    )
                entry = action_history.get_entry("", second)
                self.assertEqual(entry["payload"]["prev_id"], first)
                self.assertTrue(entry["payload"]["diff"]["cert_changed"])
                self.assertTrue(entry["payload"]["diff"]["changed"])
                paths = [row["path"] for row in entry["payload"]["diff"]["changes"]]
                self.assertIn("result.leaf.sha256", paths)

    def test_append_sets_id_and_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                payload = _tcp_payload()
                with (
                    patch("looking_glass.observe.hostname", return_value="probe.host"),
                    patch("looking_glass.observe.egress_ip", return_value="203.0.113.8"),
                    patch("looking_glass.http.weblog.compact_intel", return_value=None),
                ):
                    ident = action_history.append(
                        "",
                        path="/tcp/example.com/443",
                        kind="tcp",
                        query="example.com",
                        payload=payload,
                    )
                self.assertEqual(payload["id"], ident)
                self.assertEqual(payload["history"], f"/history/{ident}")

    def test_ip_previous_run_has_field_changes(self):
        def ip_payload(country):
            return {
                "ok": True,
                "kind": "ip",
                "query": "1.1.1.1",
                "result": {"ip": "1.1.1.1", "country": country},
            }

        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with (
                    patch("looking_glass.observe.hostname", return_value="probe.host"),
                    patch("looking_glass.observe.egress_ip", return_value="203.0.113.8"),
                    patch("looking_glass.http.weblog.compact_intel", return_value=None),
                ):
                    first = action_history.append(
                        "",
                        path="/1.1.1.1",
                        kind="ip",
                        query="1.1.1.1",
                        payload=ip_payload("US"),
                    )
                    second = action_history.append(
                        "",
                        path="/1.1.1.1",
                        kind="ip",
                        query="1.1.1.1",
                        payload=ip_payload("AU"),
                    )
                entry = action_history.get_entry("", second)
                self.assertEqual(entry["payload"]["prev_id"], first)
                self.assertTrue(entry["payload"]["diff"]["changed"])
                changes = entry["payload"]["diff"]["changes"]
                match = [row for row in changes if row["path"] == "result.country"]
                self.assertEqual(len(match), 1)
                self.assertEqual(match[0]["op"], "change")
                self.assertEqual(match[0]["previous"], "US")
                self.assertEqual(match[0]["current"], "AU")

    def test_cli_appends_history(self):
        runner = CliRunner()
        fake = {
            "ok": True,
            "result": {
                "host": "example.com",
                "port": 25,
                "ok": True,
                "status": "ok",
                "peer": "1.1.1.1:25",
                "rtt_ms": 1.0,
                "banner": None,
                "error": None,
            },
            "error": None,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with _roots(tmp)[0], _roots(tmp)[1]:
                with (
                    patch("looking_glass.cli.tools.lookup_classified", return_value=fake),
                    patch("looking_glass.observe.hostname", return_value="probe.host"),
                    patch("looking_glass.observe.egress_ip", return_value="203.0.113.8"),
                    patch("looking_glass.http.weblog.compact_intel", return_value=None),
                ):
                    result = runner.invoke(cli, ["--json", "tcp", "example.com", "-p", "25"])
                self.assertEqual(result.exit_code, 0, result.output)
                payload = json.loads(result.output)
                self.assertTrue(payload.get("id"))
                self.assertTrue(str(payload.get("history") or "").startswith("/history/"))
                rows = action_history.list_entries()
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0]["kind"], "tcp")
                self.assertEqual(rows[0]["path"], "/tcp/example.com/25")
