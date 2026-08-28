import unittest

from looking_glass.dns import apex


class ApexHelpers(unittest.TestCase):
    def test_parse_path(self):
        self.assertEqual(apex.parse_apex_path("/apex/example.com"), "example.com")
        self.assertEqual(apex.parse_apex_path("apex/Example.COM"), "Example.COM")
        with self.assertRaises(ValueError):
            apex.parse_apex_path("/apex")
        with self.assertRaises(ValueError):
            apex.parse_apex_path("/apex/example.com/extra")
        with self.assertRaises(ValueError):
            apex.parse_apex_path("/dns/example.com")

    def test_parent_and_bailiwick(self):
        self.assertEqual(apex.parent_zone("example.com."), "com.")
        self.assertEqual(apex.parent_zone("com"), ".")
        self.assertTrue(apex.in_bailiwick("ns1.example.com", "example.com"))
        self.assertFalse(apex.in_bailiwick("ns2.example.net", "example.com"))

    def test_hostname_and_public_ip(self):
        self.assertTrue(apex.hostname_ok("ns1.example.com"))
        self.assertFalse(apex.hostname_ok("ns_1.example.com"))
        self.assertTrue(apex.is_public_ip("1.1.1.1"))
        self.assertFalse(apex.is_public_ip("10.0.0.1"))
        self.assertFalse(apex.is_public_ip("192.168.1.1"))
        self.assertFalse(apex.is_public_ip("192.0.2.1"))
        self.assertTrue(apex.looks_like_ip("192.0.2.1"))
        self.assertFalse(apex.looks_like_ip("mail.example.com"))

    def test_ns_count_and_soa_timers(self):
        self.assertEqual(apex.ns_count_status(1)[0], "fail")
        self.assertEqual(apex.ns_count_status(2)[0], "pass")
        self.assertEqual(apex.ns_count_status(4)[0], "pass")
        self.assertEqual(apex.ns_count_status(8)[0], "warn")
        self.assertEqual(apex.soa_refresh_status(3600)[0], "pass")
        self.assertEqual(apex.soa_retry_status(600, 3600)[0], "pass")
        self.assertEqual(apex.soa_retry_status(7200, 3600)[0], "warn")
        self.assertEqual(apex.soa_expire_status(1_209_600)[0], "pass")
        self.assertEqual(apex.soa_minimum_status(3600)[0], "pass")
        self.assertEqual(apex.soa_minimum_status(86400)[0], "pass")

    def test_standards_cover_intodns_rfcs(self):
        numbers = {row["rfc"] for row in apex.STANDARDS}
        self.assertEqual(
            numbers,
            {
                974,
                1034,
                1035,
                1123,
                1912,
                1918,
                1982,
                2181,
                2182,
                2308,
                3596,
                5321,
                5358,
                7505,
                7766,
            },
        )
        glue = apex.rfc_ref(1912, "2.3")
        self.assertEqual(glue["rfc"], 1912)
        self.assertEqual(glue["section"], "2.3")
        self.assertIn("rfc1912", glue["url"])


def _msg(flags, question, answers=(), authority=(), additional=()):
    import dns.message

    lines = [
        "id 1",
        "opcode QUERY",
        "rcode NOERROR",
        f"flags {flags}",
        ";QUESTION",
        question,
    ]
    if answers:
        lines.append(";ANSWER")
        lines.extend(answers)
    if authority:
        lines.append(";AUTHORITY")
        lines.extend(authority)
    if additional:
        lines.append(";ADDITIONAL")
        lines.extend(additional)
    return dns.message.from_text("\n".join(lines))


def _empty(qname, rdtype):
    return _msg("QR RD RA", f"{qname} IN {rdtype}")


class ApexReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_mocked_zone_hits_every_section_and_rfc(self):
        parent_referral = _msg(
            "QR",
            "example.com. IN NS",
            authority=(
                "example.com. 172800 IN NS ns1.example.com.",
                "example.com. 172800 IN NS ns2.example.net.",
            ),
            additional=("ns1.example.com. 172800 IN A 1.1.1.1",),
        )
        child_ns = _msg(
            "QR AA",
            "example.com. IN NS",
            answers=(
                "example.com. 300 IN NS ns1.example.com.",
                "example.com. 300 IN NS ns2.example.net.",
            ),
            additional=("ns1.example.com. 300 IN A 1.1.1.1",),
        )
        soa = _msg(
            "QR AA",
            "example.com. IN SOA",
            answers=(
                "example.com. 300 IN SOA ns1.example.com. hostmaster.example.com. 2026082201 7200 3600 1209600 3600",
            ),
        )
        mx = _msg(
            "QR AA",
            "example.com. IN MX",
            answers=("example.com. 300 IN MX 10 mail.example.com.",),
        )

        async def query(server, qname, rdtype, timeout=4.0, rd=True, tcp=False, **kwargs):
            qn = str(qname).rstrip(".").lower()
            rdtype = str(rdtype).upper()
            if qn == "dns.google":
                return None, "timeout"
            if server in {"1.1.1.1", "8.8.8.8"} and not rd:
                if rdtype == "NS":
                    return child_ns, None
                if rdtype == "SOA":
                    return soa, None
                if rdtype == "MX":
                    return mx, None
                return None, "timeout"
            if server == "192.5.6.30" and qn == "example.com" and rdtype == "NS":
                return parent_referral, None
            if qn == "com" and rdtype == "NS":
                return _msg(
                    "QR RD RA",
                    "com. IN NS",
                    answers=("com. 86400 IN NS a.gtld-servers.net.",),
                ), None
            if qn == "a.gtld-servers.net" and rdtype == "A":
                return _msg(
                    "QR RD RA",
                    "a.gtld-servers.net. IN A",
                    answers=("a.gtld-servers.net. 86400 IN A 192.5.6.30",),
                ), None
            if qn == "ns1.example.com" and rdtype == "A":
                return _msg(
                    "QR RD RA",
                    "ns1.example.com. IN A",
                    answers=("ns1.example.com. 300 IN A 1.1.1.1",),
                ), None
            if qn == "ns2.example.net" and rdtype == "A":
                return _msg(
                    "QR RD RA",
                    "ns2.example.net. IN A",
                    answers=("ns2.example.net. 300 IN A 8.8.8.8",),
                ), None
            if qn == "mail.example.com" and rdtype == "A":
                return _msg(
                    "QR RD RA",
                    "mail.example.com. IN A",
                    answers=("mail.example.com. 300 IN A 9.9.9.9",),
                ), None
            if qn == "www.example.com" and rdtype == "A":
                return _msg(
                    "QR RD RA",
                    "www.example.com. IN A",
                    answers=(
                        "www.example.com. 300 IN CNAME example.com.",
                        "example.com. 300 IN A 1.0.0.1",
                    ),
                ), None
            if qn == "www.example.com" and rdtype == "CNAME":
                return _msg(
                    "QR RD RA",
                    "www.example.com. IN CNAME",
                    answers=("www.example.com. 300 IN CNAME example.com.",),
                ), None
            if qn == "example.com" and rdtype == "NS" and rd:
                return child_ns, None
            if qn.endswith(".in-addr.arpa") and rdtype == "PTR":
                return _msg(
                    "QR RD RA",
                    f"{qn}. IN PTR",
                    answers=(f"{qn}. 300 IN PTR mail.example.com.",),
                ), None
            if rdtype in {"AAAA", "CNAME"}:
                return _empty(qn + ".", rdtype), None
            return _empty(qn + ".", rdtype), None

        async def smtp(host, ip, timeout=4.0):
            return {
                "host": host,
                "ip": ip,
                "ok": True,
                "banner": "220 mail.example.com ESMTP",
                "error": None,
            }

        async def ping(ip, timeout=1.2):
            return True

        async def asn(ip):
            return 64500 if ip == "1.1.1.1" else 64501

        payload = await apex.check_apex_async(
            "example.com",
            query=query,
            smtp=smtp,
            ping=ping,
            asn=asn,
        )
        self.assertTrue(payload["ok"])
        result = payload["result"]
        ids = {
            check["id"]
            for section in result["sections"]
            for check in section["checks"]
        }
        for needed in (
            "parent_ns",
            "tld_parent",
            "listed_at_parent",
            "parent_glue",
            "parent_ns_a",
            "child_ns",
            "same_glue",
            "multiple_ns",
            "glue_for_ns",
            "ns_public",
            "ns_cname",
            "ns_hostname",
            "subnets",
            "asns",
            "responded",
            "recursive",
            "tcp",
            "same_class",
            "ping",
            "soa_record",
            "soa_serial_same",
            "soa_mname",
            "soa_serial",
            "soa_refresh",
            "soa_retry",
            "soa_expire",
            "soa_minimum",
            "mx_records",
            "mx_count",
            "mx_consistent",
            "mx_cname",
            "mx_not_ip",
            "mx_name",
            "mx_public",
            "mx_duplicate_a",
            "mx_ptr",
            "www_a",
            "www_public",
            "www_cname",
            "smtp",
        ):
            self.assertIn(needed, ids)
        cited = {
            rfc["rfc"]
            for section in result["sections"]
            for check in section["checks"]
            for rfc in check.get("rfcs") or []
        }
        self.assertTrue({974, 1034, 1035, 1912, 2181, 2182, 2308, 5321, 7766} <= cited)
        self.assertEqual(
            {row["rfc"] for row in result["standards"]},
            {row["rfc"] for row in apex.STANDARDS},
        )
        by_id = {
            check["id"]: check
            for section in result["sections"]
            for check in section["checks"]
        }
        self.assertEqual(by_id["parent_glue"]["status"], "pass")
        self.assertEqual(by_id["multiple_ns"]["status"], "pass")
        self.assertEqual(by_id["soa_serial"]["status"], "pass")
        self.assertEqual(by_id["mx_cname"]["status"], "pass")
        self.assertEqual(by_id["www_cname"]["status"], "pass")
        self.assertEqual(by_id["smtp"]["status"], "pass")
        self.assertEqual(result["summary"]["fail"], 0)


class ApexEmptyNsTests(unittest.IsolatedAsyncioTestCase):
    async def test_no_such_tld_ns_quality_is_info(self):
        async def empty(_server, qname, rdtype, **_kwargs):
            return _empty(str(qname).rstrip(".") + ".", rdtype), None

        async def nosmtp(*_a, **_k):
            return {"ok": False, "error": "skipped"}

        out = await apex.check_apex_async(
            "google.com.json",
            query=empty,
            smtp=nosmtp,
            ping=lambda *_a, **_k: None,
            asn=lambda *_a, **_k: None,
        )
        by_id = {
            check["id"]: check
            for section in out["result"]["sections"]
            for check in section["checks"]
        }
        for ident in (
            "recursive",
            "same_glue",
            "ns_public",
            "ns_cname",
            "ns_hostname",
            "glue_for_ns",
            "same_class",
        ):
            self.assertEqual(by_id[ident]["status"], "info", ident)
            self.assertIn("No nameservers", by_id[ident]["detail"])
        for ident in ("parent_ns_a", "mx_consistent", "mx_cname"):
            self.assertEqual(by_id[ident]["status"], "info", ident)
        self.assertEqual(by_id["child_ns"]["status"], "fail")


class ApexNullMxTests(unittest.IsolatedAsyncioTestCase):
    async def test_null_mx_does_not_fail_mx_name(self):
        async def query(_server, qname, rdtype, **kwargs):
            qn = str(qname).rstrip(".").lower()
            if rdtype == "MX" and qn == "example.com":
                return _msg(
                    "QR AA",
                    "example.com. IN MX",
                    answers=("example.com. 300 IN MX 0 .",),
                ), None
            return _empty(qn + ".", rdtype), None

        async def nosmtp(*_a, **_k):
            return {"ok": False, "error": "skipped"}

        out = await apex.check_apex_async(
            "example.com",
            query=query,
            smtp=nosmtp,
            ping=lambda *_a, **_k: None,
            asn=lambda *_a, **_k: None,
        )
        by_id = {
            check["id"]: check
            for section in out["result"]["sections"]
            for check in section["checks"]
        }
        self.assertEqual(by_id["mx_name"]["status"], "info")
        self.assertIn("7505", str(by_id["mx_name"]["rfcs"]))
        self.assertNotEqual(by_id["mx_name"]["status"], "fail")
        self.assertEqual(by_id["smtp"]["status"], "info")
        self.assertIn("Null MX", by_id["smtp"]["detail"])


if __name__ == "__main__":
    unittest.main()
