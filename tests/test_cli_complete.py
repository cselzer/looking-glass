"""Click shell completion: commands, options, dns types; no rejected hosts."""

from __future__ import annotations

import unittest

import click
from click.shell_completion import ShellComplete
from click.testing import CliRunner

from looking_glass.cli.entry import cli
from looking_glass.dns.resolve import DNS_TYPE_EXAMPLES


def _complete(args, incomplete=""):
    return ShellComplete(cli, {}, "looking-glass", "_LOOKING_GLASS_COMPLETE").get_completions(
        args, incomplete
    )


def _values(args, incomplete=""):
    return [item.value for item in _complete(args, incomplete)]


_JUNK = ("javascript:", "169.254.169.254", "1.2.3", "1.1.1.1/32")


class CompleteCommandTests(unittest.TestCase):
    def test_prints_bash_zsh_fish_scripts(self):
        runner = CliRunner()
        for shell in ("bash", "zsh", "fish"):
            result = runner.invoke(cli, ["complete", shell])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertIn("_LOOKING_GLASS_COMPLETE", result.output)
            self.assertNotIn("same as GET", result.output)

    def test_complete_is_listed_in_help(self):
        listed = CliRunner().invoke(cli, ["--help"]).output
        self.assertIn("complete", listed)
        self.assertIn("bash", CliRunner().invoke(cli, ["complete", "--help"]).output)


class CommandCompletionTests(unittest.TestCase):
    def test_commands_and_help_match_one_liners(self):
        ctx = click.Context(cli)
        listed = CliRunner().invoke(cli, ["--help"]).output
        self.assertNotIn("same as GET", listed)
        names = _values([])
        self.assertIn("ping", names)
        self.assertIn("dns", names)
        self.assertIn("complete", names)
        for item in _complete([]):
            self.assertNotIn("same as GET", item.help or "")
            self.assertIn(item.value, listed)
            cmd = cli.get_command(ctx, item.value)
            if cmd is None:
                continue
            short = (cmd.get_short_help_str(limit=200) or "").strip()
            help_txt = (item.help or "").strip()
            if help_txt.endswith("..."):
                help_txt = help_txt[:-3].rstrip()
            self.assertTrue(
                short.startswith(help_txt),
                f"{item.value}: completer {item.help!r} vs --help {short!r}",
            )

    def test_ping_does_not_offer_rejected_targets(self):
        for incomplete in ("", "1", "169", "javascript", "fe80"):
            values = _values(["ping"], incomplete)
            blob = " ".join(values)
            for junk in _JUNK:
                self.assertNotIn(junk, values, incomplete)
                self.assertNotIn("169.254", blob)
                self.assertNotIn("javascript:", blob)
            self.assertNotIn("1.2.3", values)

    def test_dns_type_option_completes_examples(self):
        values = _values(["dns", "-t"], "")
        self.assertEqual(set(values), set(DNS_TYPE_EXAMPLES))
        prefix = _values(["dns", "-t"], "D")
        self.assertIn("DS", prefix)
        self.assertIn("DNSKEY", prefix)
        self.assertNotIn("A", prefix)
        self.assertNotIn("AAAA", prefix)

    def test_dns_positional_type_after_name(self):
        values = _values(["dns", "example.com"], "")
        self.assertEqual(set(values), set(DNS_TYPE_EXAMPLES))
        prefix = _values(["dns", "example.com"], "MX")
        self.assertEqual(prefix, ["MX"])

    def test_dns_first_arg_is_not_junk_hosts(self):
        values = _values(["dns"], "")
        for junk in _JUNK:
            self.assertNotIn(junk, values)

    def test_dnstrace_type_option(self):
        values = _values(["dnstrace", "-t"], "A")
        self.assertIn("A", values)
        self.assertIn("AAAA", values)
        self.assertNotIn("MX", values)
