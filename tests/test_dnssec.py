import asyncio
import unittest
from unittest.mock import patch

from looking_glass.dns import dnssec


class DnssecPathTests(unittest.TestCase):
    def test_parse(self):
        self.assertEqual(dnssec.parse_dnssec_path("/dnssec/example.com"), "example.com")
        with self.assertRaises(ValueError):
            dnssec.parse_dnssec_path("/dnssec")
        with self.assertRaises(ValueError):
            dnssec.parse_dnssec_path("/apex/example.com")


class DnssecChainTests(unittest.TestCase):
    def test_silent_queries_break_at_root(self):
        async def silent(*_args, **_kwargs):
            return None, "timeout"

        out = asyncio.run(dnssec.check_dnssec_async("example.com", query=silent))
        self.assertTrue(out["ok"])
        result = out["result"]
        self.assertEqual(result["status"], "bogus")
        self.assertTrue(result["broken"])
        self.assertEqual(result["broken_at"], ".")
        self.assertGreaterEqual(len(result["chain"]), 2)
        self.assertEqual(result["chain"][0]["zone"], ".")
        self.assertIn("4035", {str(row["rfc"]) for row in result["standards"]})


class DnssecUnsignedTests(unittest.TestCase):
    def _empty_query(self):
        async def empty(_server, qname, rdtype, **_kwargs):
            import dns.message
            import dns.rdatatype

            q = dns.message.make_query(qname, dns.rdatatype.from_text(rdtype))
            return dns.message.make_response(q), None

        return empty

    def _force_root_secure(self):
        return (
            patch.object(dnssec, "resolver_targets", return_value=[("127.0.0.1", 53)]),
            patch.object(
                dnssec,
                "_anchor_ds_rows",
                return_value=[{"matches_dnskey": True}],
            ),
            patch.object(dnssec, "_validate", return_value=("valid", None)),
            patch.object(
                dnssec,
                "_dnskey_rows",
                return_value=[
                    {
                        "key_tag": 20326,
                        "role": "KSK",
                        "flags": 257,
                        "algorithm_name": "RSASHA256",
                    }
                ],
            ),
        )

    def test_unsigned_delegation_is_insecure_not_broken(self):
        patches = self._force_root_secure()
        with patches[0], patches[1], patches[2], patches[3]:
            out = asyncio.run(
                dnssec.check_dnssec_async("example.com", query=self._empty_query())
            )
        self.assertTrue(out["ok"])
        result = out["result"]
        self.assertEqual(result["status"], "insecure")
        self.assertFalse(result["broken"])
        self.assertIsNone(result["broken_at"])
        by_zone = {row["zone"]: row["status"] for row in result["chain"]}
        self.assertEqual(by_zone["."], "secure")
        self.assertEqual(by_zone["com."], "insecure")
        self.assertEqual(by_zone["example.com."], "insecure")
        self.assertIn("not a break", result["chain"][1]["detail"])

    def test_ds_query_failure_is_indeterminate_not_unsigned(self):
        async def fail_ds(_server, qname, rdtype, **_kwargs):
            import dns.message
            import dns.rdatatype

            if rdtype == "DS":
                return None, "timeout"
            q = dns.message.make_query(qname, dns.rdatatype.from_text(rdtype))
            return dns.message.make_response(q), None

        patches = self._force_root_secure()
        with patches[0], patches[1], patches[2], patches[3]:
            out = asyncio.run(
                dnssec.check_dnssec_async("example.com", query=fail_ds)
            )
        result = out["result"]
        by_zone = {row["zone"]: row for row in result["chain"]}
        self.assertEqual(by_zone["." ]["status"], "secure")
        self.assertEqual(by_zone["com."]["status"], "indeterminate")
        self.assertTrue(
            "DS" in by_zone["com."]["detail"] or "timeout" in by_zone["com."]["detail"]
        )
        self.assertNotEqual(result["status"], "bogus")

    def test_nxdomain_qname_is_not_a_secure_apex(self):
        async def nx(_server, qname, rdtype, **_kwargs):
            import dns.message
            import dns.rcode
            import dns.rdatatype

            q = dns.message.make_query(qname, dns.rdatatype.from_text(rdtype))
            r = dns.message.make_response(q)
            r.set_rcode(dns.rcode.NXDOMAIN)
            return r, None

        patches = self._force_root_secure()
        with patches[0], patches[1], patches[2], patches[3]:
            out = asyncio.run(
                dnssec.check_dnssec_async("google.com.json", query=nx)
            )
        result = out["result"]
        self.assertEqual(result["status"], "nxdomain")
        self.assertFalse(result["secure"])
        self.assertEqual(result["leaf"]["status"], "nxdomain")
        self.assertNotEqual((result.get("issue") or {}).get("title"), "Chain of trust holds")
        self.assertIn("NXDOMAIN", result["leaf"]["detail"])
        self.assertFalse(result["broken"])

    def test_ds_nxdomain_is_not_insecure_delegation(self):
        async def ds_nx(_server, qname, rdtype, **_kwargs):
            import dns.message
            import dns.rcode
            import dns.rdatatype

            q = dns.message.make_query(qname, dns.rdatatype.from_text(rdtype))
            r = dns.message.make_response(q)
            if rdtype == "DS":
                r.set_rcode(dns.rcode.NXDOMAIN)
            return r, None

        patches = self._force_root_secure()
        with patches[0], patches[1], patches[2], patches[3]:
            out = asyncio.run(
                dnssec.check_dnssec_async("example.com", query=ds_nx)
            )
        result = out["result"]
        self.assertEqual(result["status"], "nxdomain")
        self.assertNotEqual((result.get("issue") or {}).get("code"), "insecure_delegation")

    def test_invalid_is_nxdomain_not_insecure(self):
        patches = self._force_root_secure()
        with patches[0], patches[1], patches[2], patches[3]:
            out = asyncio.run(
                dnssec.check_dnssec_async("invalid", query=self._empty_query())
            )
        result = out["result"]
        self.assertEqual(result["status"], "nxdomain")
        self.assertEqual(result["apex"], ".")
        self.assertNotEqual((result.get("issue") or {}).get("code"), "insecure_delegation")
        self.assertFalse(result.get("leaf", {}).get("nameservers"))

    def test_ns_targets_skip_localhost(self):
        async def query(_server, qname, rdtype, **_kwargs):
            import dns.message
            import dns.rdatatype

            q = dns.message.make_query(qname, dns.rdatatype.from_text(rdtype))
            r = dns.message.make_response(q)
            if rdtype == "NS":
                import dns.rrset

                rr = dns.rrset.from_text(qname, 300, "IN", "NS", "localhost.")
                r.answer.append(rr)
            if rdtype == "A":
                import dns.rrset

                rr = dns.rrset.from_text(qname, 300, "IN", "A", "127.0.0.1")
                r.answer.append(rr)
            return r, None

        rows = asyncio.run(dnssec._ns_targets("invalid.", 1.0, query))
        self.assertEqual(rows, [])


class DnssecCoversTests(unittest.TestCase):
    def test_covers_property_and_method(self):
        import dns.rdatatype

        class AsProperty:
            covers = dns.rdatatype.DNSKEY

        class AsMethod:
            def covers(self):
                return dns.rdatatype.DNSKEY

        self.assertEqual(dnssec._rrsig_covers(AsProperty()), dns.rdatatype.DNSKEY)
        self.assertEqual(dnssec._rrsig_covers(AsMethod()), dns.rdatatype.DNSKEY)


class DnssecDigestTests(unittest.TestCase):
    def test_digest_hex_from_bytes_matches_iana(self):
        iana = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
        raw = bytes.fromhex(iana)
        self.assertEqual(dnssec._digest_hex(raw), iana)
        self.assertNotEqual(str(raw).replace(" ", "").upper(), iana)

    def test_ds_from_key_uses_hex_not_bytes_repr(self):
        iana = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"
        raw = bytes.fromhex(iana)

        class FakeDS:
            digest = raw

        with patch("dns.dnssec.make_ds", return_value=FakeDS()):
            digest = dnssec._ds_from_key(".", object(), 2)
        self.assertEqual(digest, iana)
        self.assertFalse(digest.startswith("B'"))


class DnssecExplainTests(unittest.TestCase):
    def test_ds_mismatch_explains_the_break(self):
        issue = dnssec._diagnose(
            zone="dnssec-failed.org.",
            parent="org.",
            status="bogus",
            detail="digest mismatch",
            ds_rows=[{"key_tag": 42069, "matches_dnskey": False}],
            dnskeys=[{"role": "KSK", "key_tag": 50719}, {"role": "ZSK", "key_tag": 32784}],
            dnskey_sig="valid",
            dnskey_sig_err=None,
        )
        self.assertEqual(issue["code"], "ds_mismatch")
        self.assertEqual(issue["severity"], "error")
        self.assertIn("42069", issue["what"])
        self.assertIn("50719", issue["what"])
        self.assertIn("SERVFAIL", issue["effect"])

    def test_graph_marks_ds_edge_as_bogus(self):
        graph = dnssec._graph_for_zone(
            zone="dnssec-failed.org.",
            parent="org.",
            status="bogus",
            ds_rows=[
                {
                    "key_tag": 42069,
                    "algorithm_name": "ECDSAP256SHA256",
                    "digest_name": "SHA-256",
                    "digest": "ABCD" * 8,
                    "matches_dnskey": False,
                }
            ],
            dnskeys=[{"role": "KSK", "key_tag": 50719, "algorithm_name": "ECDSAP256SHA256"}],
            dnskey_sig="valid",
        )
        self.assertEqual(graph["groups"][0]["link"]["status"], "bogus")
        self.assertIn("digest", graph["groups"][0]["link"]["label"])
        self.assertEqual(graph["groups"][0]["nodes"][0]["status"], "bogus")

    def test_ns_agreement_detects_split_brain(self):
        agree = dnssec._ns_agreement(
            [
                {"ok": True, "tags": [1, 2]},
                {"ok": True, "tags": [1, 2]},
            ]
        )
        self.assertTrue(agree["ok"])
        split = dnssec._ns_agreement(
            [
                {"ok": True, "tags": [1, 2]},
                {"ok": True, "tags": [3]},
            ]
        )
        self.assertFalse(split["ok"])
        self.assertEqual(split["variants"], 2)

    def test_ns_names_and_first_address(self):
        import dns.rdata
        import dns.rdataclass
        import dns.rdatatype
        import dns.rrset

        ns = dns.rrset.from_text("example.com.", 60, "IN", "NS", "ns1.example.com.")
        msg = type("Msg", (), {"answer": [ns], "authority": []})()
        self.assertEqual(dnssec._ns_names(msg), ["ns1.example.com."])
        a = dns.rrset.from_text("ns1.example.com.", 60, "IN", "A", "192.0.2.1")
        amsg = type("Msg", (), {"answer": [a]})()
        self.assertEqual(dnssec._first_address(amsg), "192.0.2.1")


class DnssecLeafVerdictTests(unittest.TestCase):
    def test_secure_chain_and_valid_rrsig_is_authenticated(self):
        out = dnssec._leaf_verdict(
            rrtype="A",
            apex_status="secure",
            rrsig_status="valid",
        )
        self.assertEqual(out["status"], "secure")
        self.assertEqual(out["rrsig"], "valid")
        self.assertTrue(out["authenticated"])
        self.assertTrue(out["chain_secure"])
        self.assertIn("authenticated", out["detail"])

    def test_broken_ds_with_valid_child_rrsig_is_not_secure(self):
        out = dnssec._leaf_verdict(
            rrtype="A",
            apex_status="bogus",
            rrsig_status="valid",
        )
        self.assertEqual(out["status"], "rrsig_valid")
        self.assertEqual(out["rrsig"], "valid")
        self.assertFalse(out["authenticated"])
        self.assertFalse(out["chain_secure"])
        self.assertNotEqual(out["status"], "secure")
        self.assertIn("not authenticated", out["detail"])
        self.assertIn("DS", out["detail"])

    def test_secure_chain_invalid_leaf_rrsig_is_bogus(self):
        out = dnssec._leaf_verdict(
            rrtype="A",
            apex_status="secure",
            rrsig_status="bogus",
            rrsig_error="signature failed",
        )
        self.assertEqual(out["status"], "bogus")
        self.assertEqual(out["rrsig"], "bogus")
        self.assertFalse(out["authenticated"])
        self.assertTrue(out["chain_secure"])
        self.assertIn("signature failed", out["detail"])

    def test_unsigned_delegation_is_insecure_not_bogus_or_secure(self):
        out = dnssec._leaf_verdict(
            rrtype="A",
            apex_status="insecure",
            rrsig_status="valid",
        )
        self.assertEqual(out["status"], "insecure")
        self.assertFalse(out["authenticated"])
        self.assertFalse(out["chain_secure"])
        self.assertNotEqual(out["status"], "secure")
        self.assertNotEqual(out["status"], "bogus")

    def test_unauthenticated_ancestor_valid_rrsig_is_not_secure(self):
        out = dnssec._leaf_verdict(
            rrtype="A",
            apex_status="indeterminate",
            rrsig_status="valid",
        )
        self.assertEqual(out["status"], "rrsig_valid")
        self.assertFalse(out["authenticated"])
        self.assertFalse(out["chain_secure"])
        self.assertNotEqual(out["status"], "secure")


class DnssecLeafChainTests(unittest.TestCase):
    def _empty_query(self):
        async def empty(_server, qname, rdtype, **_kwargs):
            import dns.message
            import dns.rdatatype

            q = dns.message.make_query(qname, dns.rdatatype.from_text(rdtype))
            return dns.message.make_response(q), None

        return empty

    def _run(
        self,
        name,
        *,
        match_ds,
        validate=("valid", None),
        find_leaf=True,
        anchor_ok=True,
    ):
        dummy = object()

        def find(_msg, _qname, rdtype):
            if rdtype in {"DNSKEY", "DS"} or (find_leaf and rdtype in {"A", "AAAA", "SOA"}):
                return dummy, dummy
            return None, None

        patches = [
            patch.object(dnssec, "resolver_targets", return_value=[("127.0.0.1", 53)]),
            patch.object(
                dnssec,
                "_anchor_ds_rows",
                return_value=[{"matches_dnskey": anchor_ok, "key_tag": 20326}],
            ),
            patch.object(
                dnssec,
                "_dnskey_rows",
                return_value=[
                    {
                        "key_tag": 20326,
                        "role": "KSK",
                        "flags": 257,
                        "algorithm_name": "RSASHA256",
                    }
                ],
            ),
            patch.object(dnssec, "_find_rrset", side_effect=find),
            patch.object(dnssec, "_match_ds", side_effect=match_ds),
        ]
        if callable(validate):
            patches.append(patch.object(dnssec, "_validate", side_effect=validate))
        else:
            patches.append(patch.object(dnssec, "_validate", return_value=validate))
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
        ):
            return asyncio.run(dnssec.check_dnssec_async(name, query=self._empty_query()))

    @staticmethod
    def _ds_ok(_zone, *_args):
        return [{"key_tag": 1, "matches_dnskey": True}]

    @staticmethod
    def _ds_apex_mismatch(zone, *_args):
        if zone in {".", "org.", "com."}:
            return [{"key_tag": 1, "matches_dnskey": True}]
        return [{"key_tag": 42069, "matches_dnskey": False}]

    def test_secure_chain_valid_leaf_rrsig(self):
        out = self._run("example.com", match_ds=self._ds_ok)
        result = out["result"]
        leaf = result["leaf"]
        self.assertEqual(result["status"], "secure")
        self.assertTrue(result["secure"])
        self.assertFalse(result["broken"])
        self.assertEqual(leaf["status"], "secure")
        self.assertEqual(leaf["rrsig"], "valid")
        self.assertTrue(leaf["authenticated"])
        self.assertTrue(leaf["chain_secure"])

    def test_ds_mismatch_valid_leaf_rrsig_is_not_secure(self):
        out = self._run("dnssec-failed.org", match_ds=self._ds_apex_mismatch)
        result = out["result"]
        leaf = result["leaf"]
        self.assertEqual(result["status"], "bogus")
        self.assertTrue(result["broken"])
        self.assertEqual(result["broken_at"], "dnssec-failed.org.")
        self.assertEqual(leaf["status"], "rrsig_valid")
        self.assertNotEqual(leaf["status"], "secure")
        self.assertEqual(leaf["rrsig"], "valid")
        self.assertFalse(leaf["authenticated"])
        self.assertFalse(leaf["chain_secure"])
        self.assertIn("not authenticated", leaf["detail"])

    def test_dnssec_failed_org_leaf_is_not_labeled_secure(self):
        out = self._run("dnssec-failed.org", match_ds=self._ds_apex_mismatch)
        leaf = out["result"]["leaf"]
        self.assertEqual(out["result"]["status"], "bogus")
        self.assertNotEqual(leaf["status"], "secure")
        self.assertFalse(leaf["authenticated"])
        self.assertFalse(leaf["chain_secure"])

    def test_valid_chain_invalid_leaf_rrsig_is_bogus(self):
        n = {"i": 0}

        def validate(*_a, **_k):
            n["i"] += 1
            if n["i"] >= 4:
                return ("bogus", "leaf RRSIG failed")
            return ("valid", None)

        out = self._run("example.com", match_ds=self._ds_ok, validate=validate)
        result = out["result"]
        leaf = result["leaf"]
        self.assertEqual(result["status"], "bogus")
        self.assertEqual(leaf["status"], "bogus")
        self.assertEqual(leaf["rrsig"], "bogus")
        self.assertFalse(leaf["authenticated"])
        self.assertTrue(leaf["chain_secure"])
        self.assertIn("leaf RRSIG failed", leaf["detail"])

    def test_invalid_dnskey_rrsig_is_bogus(self):
        n = {"i": 0}

        def validate(*_a, **_k):
            n["i"] += 1
            if n["i"] == 3:
                return ("bogus", "apex DNSKEY RRSIG failed")
            return ("valid", None)

        out = self._run("example.com", match_ds=self._ds_ok, validate=validate)
        result = out["result"]
        by_zone = {row["zone"]: row["status"] for row in result["chain"]}
        self.assertEqual(result["status"], "bogus")
        self.assertEqual(by_zone["example.com."], "bogus")
        self.assertNotEqual(result["leaf"]["status"], "secure")
        self.assertFalse(result["leaf"]["authenticated"])

    def test_unsigned_delegation_is_insecure(self):
        out = self._run(
            "example.com",
            match_ds=lambda *_a, **_k: [],
            find_leaf=True,
        )
        result = out["result"]
        by_zone = {row["zone"]: row["status"] for row in result["chain"]}
        self.assertEqual(result["status"], "insecure")
        self.assertFalse(result["broken"])
        self.assertEqual(by_zone["com."], "insecure")
        self.assertEqual(by_zone["example.com."], "insecure")
        self.assertEqual(result["leaf"]["status"], "insecure")
        self.assertFalse(result["leaf"]["authenticated"])
        self.assertFalse(result["leaf"]["chain_secure"])
        self.assertNotEqual(result["leaf"]["status"], "secure")
        self.assertNotEqual(result["leaf"]["status"], "bogus")

    def test_root_trust_anchor_failure_nothing_beneath_is_secure(self):
        out = self._run(
            "example.com",
            match_ds=self._ds_ok,
            anchor_ok=False,
        )
        result = out["result"]
        self.assertEqual(result["status"], "bogus")
        self.assertEqual(result["broken_at"], ".")
        for row in result["chain"]:
            self.assertNotEqual(row["status"], "secure")
            if row["zone"] != ".":
                self.assertFalse(
                    row["status"] in {"secure"},
                    f"{row['zone']} marked {row['status']} under a failed trust anchor",
                )
        leaf = result["leaf"]
        self.assertNotEqual(leaf["status"], "secure")
        self.assertFalse(leaf["authenticated"])
        self.assertFalse(leaf["chain_secure"])
