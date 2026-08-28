import json
import os
import tempfile
import unittest
from unittest.mock import patch

from looking_glass.intel import iana as iana_mod
from looking_glass.utility import parse_iana_csv_text


_CSV = """Address Block,Name,RFC,Allocation Date
2002::/16 [3],6to4,[RFC3056],2001-02
192.0.0.0/24 [2],IETF Protocol Assignments,[RFC6890],2010-01
"192.0.0.170/32, 192.0.0.171/32",NAT64/DNS64 Discovery,[RFC7050],2013-02
2001:db8::/32,Documentation,[RFC3849],2004-07
"""

_UNQUOTED_NAT64 = """Address Block,Name,RFC,Allocation Date
192.0.0.170/32, 192.0.0.171/32,NAT64/DNS64 Discovery,[RFC7050],2013-02
"""


def _iana_globals():
    return (
        iana_mod._starts_v4,
        iana_mod._ends_v4,
        iana_mod._meta_v4,
        iana_mod._starts_v6,
        iana_mod._ends_v6,
        iana_mod._meta_v6,
        iana_mod._built,
        iana_mod._fetched_at,
    )


def _restore_iana(saved):
    (
        iana_mod._starts_v4,
        iana_mod._ends_v4,
        iana_mod._meta_v4,
        iana_mod._starts_v6,
        iana_mod._ends_v6,
        iana_mod._meta_v6,
        iana_mod._built,
        iana_mod._fetched_at,
    ) = saved


class IanaCsvTests(unittest.TestCase):
    def test_footnotes_and_quoted_lists(self):
        rows = parse_iana_csv_text(_CSV, "iana-ipv6-special")
        by_cidr = {row["cidr"]: row for row in rows}
        self.assertEqual(by_cidr["2002::/16"]["designation"], "6to4")
        self.assertEqual(by_cidr["192.0.0.0/24"]["designation"], "IETF Protocol Assignments")
        self.assertEqual(by_cidr["192.0.0.170/32"]["designation"], "NAT64/DNS64 Discovery")
        self.assertEqual(by_cidr["192.0.0.171/32"]["designation"], "NAT64/DNS64 Discovery")
        self.assertEqual(by_cidr["2001:db8::/32"]["designation"], "Documentation")

    def test_unquoted_two_column_nat64(self):
        rows = parse_iana_csv_text(_UNQUOTED_NAT64, "iana-ipv4-special")
        by_cidr = {row["cidr"]: row for row in rows}
        self.assertEqual(by_cidr["192.0.0.170/32"]["designation"], "NAT64/DNS64 Discovery")
        self.assertEqual(by_cidr["192.0.0.171/32"]["designation"], "NAT64/DNS64 Discovery")

    def test_find_for_ip_after_build_arrays(self):
        rows = parse_iana_csv_text(_CSV, "iana-special")
        saved = _iana_globals()
        try:
            iana_mod._build_arrays_from_entries(rows)
            sixto4 = iana_mod.find_for_ip("2002::1")
            nat64 = iana_mod.find_for_ip("192.0.0.170")
            ietf = iana_mod.find_for_ip("192.0.0.20")
        finally:
            _restore_iana(saved)
        self.assertIsNotNone(sixto4)
        self.assertEqual(sixto4["cidr"], "2002::/16")
        self.assertEqual(sixto4["designation"], "6to4")
        self.assertIsNotNone(nat64)
        self.assertEqual(nat64["cidr"], "192.0.0.170/32")
        self.assertIsNotNone(ietf)
        self.assertEqual(ietf["cidr"], "192.0.0.0/24")


class IanaCacheVersionTests(unittest.TestCase):
    def test_stale_parser_version_rebuilds(self):
        saved = _iana_globals()
        csv = """Address Block,Name,RFC,Allocation Date
2002::/16 [3],6to4,[RFC3056],2001-02
"""
        with tempfile.TemporaryDirectory() as tmp:
            cache = os.path.join(tmp, "iana.json")
            with open(cache, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "parser_version": 1,
                        "_fetched_at": 1,
                        "entries": [{"cidr": "192.0.2.0/24", "designation": "OLD"}],
                    },
                    handle,
                )
            try:
                iana_mod._starts_v4 = None
                iana_mod._ends_v4 = None
                iana_mod._meta_v4 = None
                iana_mod._starts_v6 = None
                iana_mod._ends_v6 = None
                iana_mod._meta_v6 = None
                iana_mod._built = False
                iana_mod._fetched_at = 0
                with (
                    patch.object(iana_mod, "_get_iana_db_path", return_value=cache),
                    patch.object(iana_mod, "fetch_text", return_value=csv) as fetch,
                ):
                    self.assertTrue(iana_mod.load(force=False))
                    hit = iana_mod.find_for_ip("2002::1")
                    miss = iana_mod.find_for_ip("192.0.2.1")
                    self.assertTrue(fetch.called)
                payload = json.loads(open(cache, encoding="utf-8").read())
                self.assertEqual(payload["parser_version"], iana_mod.PARSER_VERSION)
            finally:
                _restore_iana(saved)
        self.assertIsNotNone(hit)
        self.assertEqual(hit["designation"], "6to4")
        self.assertIsNone(miss)
