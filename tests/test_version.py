"""Installed package version comes from git tags via setuptools-scm."""

from __future__ import annotations

import unittest
from importlib.metadata import PackageNotFoundError
from unittest.mock import patch

from click.testing import CliRunner

from looking_glass import package_version
from looking_glass.cli.entry import cli
from looking_glass.intel.rdap import _rdap_headers


class PackageVersionTests(unittest.TestCase):
    def test_version_option_uses_installed_metadata(self):
        runner = CliRunner()
        with patch("importlib.metadata.version", return_value="0.1.0.dev3+gdeadbee"):
            result = runner.invoke(cli, ["--version"])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertIn("looking-glass, version 0.1.0.dev3+gdeadbee", result.output)

    def test_package_version_reads_metadata(self):
        with patch("looking_glass._pkg_version", return_value="0.1.0.dev2+gabcdef1"):
            self.assertEqual(package_version(), "0.1.0.dev2+gabcdef1")

    def test_package_version_when_not_installed(self):
        with patch(
            "looking_glass._pkg_version",
            side_effect=PackageNotFoundError("looking-glass"),
        ):
            with patch.dict("sys.modules", {"looking_glass._version": None}):
                value = package_version()
        self.assertTrue(isinstance(value, str) and value)

    def test_rdap_user_agent_tracks_package_version(self):
        with patch("looking_glass.package_version", return_value="0.1.0.dev1+gabc1234"):
            headers = _rdap_headers()
        self.assertEqual(headers["User-Agent"], "looking-glass/0.1.0.dev1+gabc1234")
        self.assertEqual(headers["Accept"], "application/rdap+json")
