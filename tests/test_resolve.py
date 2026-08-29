import unittest
from unittest.mock import patch

from looking_glass.dns import resolve

_CSV = """TYPE,Value,Meaning,Reference,Template,Registration Date
A,1,a host address,[RFC1035],,
NS,2,an authoritative name server,[RFC1035],,
PTR,12,a domain name pointer,[RFC1035],,
MX,15,mail exchange,[RFC1035],,
TXT,16,text strings,[RFC1035],,
AAAA,28,IP6 Address,[RFC3596],,
SRV,33,Server Selection,[RFC2782],,
OPT,41,OPT,[RFC6891],,
Unassigned,62-98,,,,
CNAME,5,the canonical name for an alias,[RFC1035],,
SOA,6,marks the start of a zone of authority,[RFC1035],,
DS,43,Delegation Signer,[RFC4034],,
SSHFP,44,SSH Key Fingerprint,[RFC4255],,
RRSIG,46,RRSIG,[RFC4034],,
NSEC,47,NSEC,[RFC4034],,
DNSKEY,48,DNSKEY,[RFC4034],,
NSEC3,50,NSEC3,[RFC5155],,
TLSA,52,TLSA,[RFC6698],,
SVCB,64,Service Binding,[RFC9460],SVCB,2023-07-12
HTTPS,65,HTTPS Binding,[RFC9460],HTTPS,2023-07-12
AXFR,252,transfer of an entire zone,[RFC1035][RFC5936],,
*,255,A request for all records the server/cache has available,[RFC1035][RFC6895][RFC8482],,
CAA,257,Certification Authority Restriction,[RFC8659],CAA,2010-11-18
Private use,65280-65534,,,,
Reserved,65535,,,,
"""


class DnsTypesCsvTests(unittest.TestCase):
    def setUp(self):
        self.entries = resolve.parse_dns_types_csv(_CSV)
        resolve._install(self.entries, 1)

    def tearDown(self):
        resolve._install([], 0)
        resolve._built = False

    def test_skips_unassigned_reserved_private_ranges(self):
        names = {e["name"] for e in self.entries}
        self.assertIn("A", names)
        self.assertIn("HTTPS", names)
        self.assertIn("CAA", names)
        self.assertIn("ANY", names)
        self.assertNotIn("UNASSIGNED", names)
        self.assertNotIn("RESERVED", names)
        self.assertNotIn("PRIVATE USE", names)
        values = {e["value"] for e in self.entries}
        self.assertNotIn(65535, values)

    def test_star_is_any_and_meta(self):
        any_row = next(e for e in self.entries if e["name"] == "ANY")
        self.assertEqual(any_row["value"], 255)
        self.assertTrue(any_row["meta"])
        opt = next(e for e in self.entries if e["name"] == "OPT")
        self.assertTrue(opt["meta"])
        axfr = next(e for e in self.entries if e["name"] == "AXFR")
        self.assertTrue(axfr["meta"])
        self.assertFalse(next(e for e in self.entries if e["name"] == "A")["meta"])

    def test_types_lookup_only_drops_meta(self):
        lookup = {e["name"] for e in resolve.types(lookup_only=True)}
        all_names = {e["name"] for e in resolve.types(lookup_only=False)}
        self.assertIn("A", lookup)
        self.assertIn("HTTPS", lookup)
        self.assertNotIn("ANY", lookup)
        self.assertNotIn("AXFR", lookup)
        self.assertNotIn("OPT", lookup)
        self.assertIn("ANY", all_names)


class QtypeTests(unittest.TestCase):
    def setUp(self):
        resolve._install(resolve.parse_dns_types_csv(_CSV), 1)

    def tearDown(self):
        resolve._install([], 0)
        resolve._built = False

    def test_mnemonic_number_and_type_prefix(self):
        self.assertEqual(resolve.canonicalize_qtype("a"), {"name": "A", "value": 1})
        self.assertEqual(resolve.canonicalize_qtype("28"), {"name": "AAAA", "value": 28})
        self.assertEqual(resolve.canonicalize_qtype("TYPE65"), {"name": "HTTPS", "value": 65})
        self.assertEqual(resolve.canonicalize_qtype(None), {"name": "A", "value": 1})

    def test_rejects_meta_types(self):
        for qtype in ("ANY", "*", "255", "AXFR", "OPT", "TYPE41"):
            with self.subTest(qtype=qtype):
                with self.assertRaises(ValueError) as ctx:
                    resolve.canonicalize_qtype(qtype)
                self.assertIn("not a lookup type", str(ctx.exception))

    def test_private_use_type_number(self):
        out = resolve.canonicalize_qtype("TYPE65280")
        self.assertEqual(out["value"], 65280)
        self.assertEqual(out["name"], "TYPE65280")

    def test_unknown_mnemonic(self):
        with self.assertRaises(ValueError):
            resolve.canonicalize_qtype("NOTATYPE")


class QnameTests(unittest.TestCase):
    def test_absolute_and_idna(self):
        self.assertEqual(resolve.normalize_qname("Example.COM"), "example.com.")
        self.assertTrue(resolve.normalize_qname("münchen.de").endswith(".de."))
        self.assertTrue(resolve.normalize_qname("münchen.de").startswith("xn--"))

    def test_srv_underscore(self):
        self.assertEqual(
            resolve.normalize_qname("_sip._tcp.example.com"),
            "_sip._tcp.example.com.",
        )

    def test_ptr_from_ip(self):
        self.assertEqual(
            resolve.normalize_qname("1.1.1.1", qtype="PTR"),
            "1.1.1.1.in-addr.arpa.",
        )
        v6 = resolve.normalize_qname("2001:db8::1", qtype="PTR")
        self.assertTrue(v6.endswith("ip6.arpa."))
        self.assertIn("8.b.d.0.1.0.0.2", v6)

    def test_ip_requires_ptr(self):
        with self.assertRaises(ValueError) as ctx:
            resolve.normalize_qname("1.1.1.1", qtype="A")
        self.assertIn("PTR", str(ctx.exception))

    def test_rejects_junk(self):
        with self.assertRaises(ValueError):
            resolve.normalize_qname("has space.com")
        with self.assertRaises(ValueError):
            resolve.normalize_qname("")
        with self.assertRaises(ValueError):
            resolve.normalize_qname("*")
        with self.assertRaises(ValueError):
            resolve.normalize_qname("foo\x00bar")
        self.assertEqual(resolve.normalize_qname("*.example.com"), "*.example.com.")


class DnsPathTests(unittest.TestCase):
    def test_name_and_type(self):
        self.assertEqual(resolve.parse_dns_path("/dns/example.com"), ("example.com", "A"))
        self.assertEqual(
            resolve.parse_dns_path("/dns/example.com/AAAA"), ("example.com", "AAAA")
        )
        self.assertEqual(
            resolve.parse_dns_path("/dns/_sip._tcp.example.com/SRV"),
            ("_sip._tcp.example.com", "SRV"),
        )

    def test_ipv6_ptr(self):
        self.assertEqual(
            resolve.parse_dns_path("/dns/2001:db8::1/PTR"),
            ("2001:db8::1", "PTR"),
        )

    def test_invalid_paths(self):
        with self.assertRaises(ValueError):
            resolve.parse_dns_path("/dns")
        with self.assertRaises(ValueError):
            resolve.parse_dns_path("/dns/example.com/A/extra")
        with self.assertRaises(ValueError):
            resolve.parse_dns_path("/AU")


class DnsLookupTests(unittest.TestCase):
    def setUp(self):
        resolve._install(resolve.parse_dns_types_csv(_CSV), 1)

    def tearDown(self):
        resolve._install([], 0)
        resolve._built = False

    def test_payload_from_message(self):
        import dns.message

        msg = dns.message.from_text(
            """id 1
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
example.com. IN A
;ANSWER
example.com. 300 IN A 93.184.216.34
example.com. 300 IN A 93.184.216.35
example.com. 300 IN A 93.184.216.36
example.com. 300 IN A 93.184.216.37
example.com. 300 IN A 93.184.216.38
example.com. 300 IN A 93.184.216.39
"""
        )
        qtype = {"name": "A", "value": 1}
        result = resolve.result_from_response(
            msg, qname="example.com.", qtype=qtype, status="NOERROR"
        )
        self.assertEqual(result["status"], "NOERROR")
        self.assertEqual(len(result["answers"]), 6)
        self.assertEqual(
            [row["data"] for row in result["answers"]],
            [
                "93.184.216.34",
                "93.184.216.35",
                "93.184.216.36",
                "93.184.216.37",
                "93.184.216.38",
                "93.184.216.39",
            ],
        )
        self.assertTrue(all(row["type"] == "A" for row in result["answers"]))

    def test_lookup_uses_query_and_nxdomain(self):
        async def fake_query(qname, rdtype, timeout, server, **kwargs):
            self.assertEqual(qname, "missing.example.")
            return None, "NXDOMAIN", None

        with patch("looking_glass.dns.resolve._query", side_effect=fake_query):
            out = resolve.lookup_dns("missing.example", "A")
        self.assertTrue(out["ok"])
        self.assertEqual(out["result"]["status"], "NXDOMAIN")
        self.assertEqual(out["result"]["answers"], [])

    def test_lookup_servfail_is_not_ok(self):
        async def fake_query(qname, rdtype, timeout, server, **kwargs):
            return None, "SERVFAIL", None

        with patch("looking_glass.dns.resolve._query", side_effect=fake_query):
            out = resolve.lookup_dns("dnssec-failed.org", "A")
        self.assertFalse(out["ok"])
        self.assertEqual(out["result"]["status"], "SERVFAIL")
        self.assertEqual(out["error"], "SERVFAIL")

    def test_lookup_timeout(self):
        async def fake_query(qname, rdtype, timeout, server, **kwargs):
            return None, "ERROR", "timeout"

        with patch("looking_glass.dns.resolve._query", side_effect=fake_query):
            out = resolve.lookup_dns("example.com", "A")
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "timeout")

    def test_default_uses_system_resolver(self):
        with patch.object(
            resolve,
            "system_resolver_targets",
            return_value=[("127.0.0.1", 53), ("10.0.0.1", 5353)],
        ):
            self.assertEqual(
                resolve.resolver_targets(None, None),
                [("127.0.0.1", 53), ("10.0.0.1", 5353)],
            )

    def test_explicit_nameserver_is_used(self):
        self.assertEqual(resolve.resolver_targets("1.1.1.1"), [("1.1.1.1", 53)])
        self.assertEqual(resolve.resolver_targets("127.0.0.1"), [("127.0.0.1", 53)])
        self.assertEqual(
            resolve.resolver_targets("1.1.1.1:5353"), [("1.1.1.1", 5353)]
        )

    def test_system_resolver_reads_dnspython_resolver(self):
        class FakeResolver:
            def __init__(self, configure=True):
                self.nameservers = ["127.0.0.1", "10.0.0.1", "127.0.0.1"]
                self.nameserver_ports = {"10.0.0.1": 5353}

        with patch("dns.resolver.Resolver", FakeResolver):
            self.assertEqual(
                resolve.system_resolver_targets(),
                [("127.0.0.1", 53), ("10.0.0.1", 5353)],
            )
            self.assertEqual(
                resolve.system_resolver_targets(5353),
                [("127.0.0.1", 5353), ("10.0.0.1", 5353)],
            )

    def test_lookup_default_does_not_force_a_public_ns(self):
        seen = {}

        async def fake_query(qname, rdtype, timeout, server, *, port=None):
            seen["server"] = server
            seen["port"] = port
            return None, "NXDOMAIN", None

        with patch("looking_glass.dns.resolve._query", side_effect=fake_query):
            resolve.lookup_dns("example.com", "A")
        self.assertIsNone(seen["server"])
        self.assertIsNone(seen["port"])


class NameserverParseTests(unittest.TestCase):
    def test_ip_and_port_forms(self):
        self.assertEqual(resolve.parse_nameserver(None), (None, 53))
        self.assertEqual(resolve.parse_nameserver("1.1.1.1"), ("1.1.1.1", 53))
        self.assertEqual(resolve.parse_nameserver("1.1.1.1:5353"), ("1.1.1.1", 5353))
        self.assertEqual(resolve.parse_nameserver("1.1.1.1:5353", 53), ("1.1.1.1", 53))
        self.assertEqual(resolve.parse_nameserver("@8.8.8.8"), ("8.8.8.8", 53))
        self.assertEqual(
            resolve.parse_nameserver("[2001:db8::1]:5353"),
            ("2001:db8::1", 5353),
        )
        self.assertEqual(resolve.parse_nameserver(None, 5353), (None, 5353))

    def test_rejects_junk(self):
        with self.assertRaises(ValueError):
            resolve.parse_nameserver("ns1.example.com")
        with self.assertRaises(ValueError):
            resolve.parse_nameserver("1.1.1.1:99999")


class DnsTypeLookupTests(unittest.TestCase):
    """Every lookup type can be queried; common types parse real rdata."""

    _SAMPLES = (
        ("A", "example.com.", "example.com. 300 IN A 93.184.216.34"),
        ("AAAA", "example.com.", "example.com. 300 IN AAAA 2606:2800:220:1:248:1893:25c8:1946"),
        ("NS", "example.com.", "example.com. 86400 IN NS a.iana-servers.net."),
        ("MX", "example.com.", "example.com. 3600 IN MX 10 mail.example.com."),
        ("TXT", "example.com.", 'example.com. 300 IN TXT "v=spf1 -all"'),
        ("SOA", "example.com.", "example.com. 3600 IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 300"),
        ("CNAME", "www.example.com.", "www.example.com. 300 IN CNAME example.com."),
        ("CAA", "example.com.", 'example.com. 3600 IN CAA 0 issue "letsencrypt.org"'),
        ("HTTPS", "example.com.", "example.com. 300 IN HTTPS 1 . alpn=h2"),
        (
            "DS",
            "example.com.",
            "example.com. 3600 IN DS 370 13 2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        (
            "DNSKEY",
            "example.com.",
            "example.com. 3600 IN DNSKEY 257 3 13 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa==",
        ),
        ("SRV", "_sip._tcp.example.com.", "_sip._tcp.example.com. 300 IN SRV 0 5 5060 sip.example.com."),
        ("PTR", "1.1.1.1.in-addr.arpa.", "1.1.1.1.in-addr.arpa. 300 IN PTR one.one.one.one."),
        (
            "TLSA",
            "_443._tcp.www.example.com.",
            "_443._tcp.www.example.com. 3600 IN TLSA 3 1 1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ),
        ("SSHFP", "example.com.", "example.com. 3600 IN SSHFP 4 2 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ("NAPTR", "example.com.", 'example.com. 3600 IN NAPTR 10 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .'),
    )

    def setUp(self):
        resolve._install(resolve.parse_dns_types_csv(_CSV), 1)

    def tearDown(self):
        resolve._install([], 0)
        resolve._built = False

    def test_every_catalog_type_is_a_valid_qtype(self):
        for row in resolve.types(lookup_only=True):
            with self.subTest(qtype=row["name"]):
                info = resolve.canonicalize_qtype(row["name"])
                self.assertEqual(info["name"], row["name"])
                self.assertEqual(info["value"], row["value"])

    def test_lookup_types_return_typed_answers(self):
        import dns.message

        for qtype, qname, rdata in self._SAMPLES:
            with self.subTest(qtype=qtype):
                msg = dns.message.from_text(
                    f"""id 1
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
{qname} IN {qtype}
;ANSWER
{rdata}
"""
                )

                async def fake_query(name, rdtype, timeout, server, **kwargs):
                    return msg, "NOERROR", None

                with patch("looking_glass.dns.resolve._query", side_effect=fake_query):
                    owner = qname.rstrip(".")
                    if qtype == "PTR":
                        owner = "1.1.1.1"
                    out = resolve.lookup_dns(owner, qtype)
                self.assertTrue(out["ok"], out)
                self.assertEqual(out["qtype"], qtype)
                self.assertEqual(out["result"]["status"], "NOERROR")
                self.assertTrue(out["result"]["answers"], out)
                self.assertEqual(out["result"]["answers"][0]["type"], qtype)
                self.assertTrue(out["result"]["answers"][0]["data"])

    def test_empty_nodata_is_ok_for_every_lookup_type(self):
        import dns.message

        msg = dns.message.from_text(
            """id 1
opcode QUERY
rcode NOERROR
flags QR RD RA
;QUESTION
example.com. IN A
"""
        )

        async def fake_query(qname, rdtype, timeout, server, **kwargs):
            return msg, "NOERROR", None

        with patch("looking_glass.dns.resolve._query", side_effect=fake_query):
            for row in resolve.types(lookup_only=True):
                with self.subTest(qtype=row["name"]):
                    out = resolve.lookup_dns("example.com", row["name"])
                    self.assertTrue(out["ok"], out)
                    self.assertEqual(out["result"]["status"], "NOERROR")
                    self.assertEqual(out["result"]["answers"], [])
                    self.assertEqual(out["result"]["qtype"], row["name"])

    def test_nxdomain_keeps_authority(self):
        import dns.message

        msg = dns.message.from_text(
            """id 1
opcode QUERY
rcode NXDOMAIN
flags QR RD RA
;QUESTION
missing.example.com. IN A
;AUTHORITY
example.com. 300 IN SOA ns.example.com. hostmaster.example.com. 1 7200 3600 1209600 300
"""
        )

        async def fake_query(qname, rdtype, timeout, server, **kwargs):
            return msg, "NXDOMAIN", None

        with patch("looking_glass.dns.resolve._query", side_effect=fake_query):
            out = resolve.lookup_dns("missing.example.com", "A")
        self.assertTrue(out["ok"])
        self.assertEqual(out["result"]["status"], "NXDOMAIN")
        self.assertEqual(out["result"]["answers"], [])
        self.assertTrue(out["result"]["authority"])
        self.assertEqual(out["result"]["authority"][0]["type"], "SOA")

    def test_lookup_passes_nameserver_port(self):
        seen = {}

        async def fake_query(qname, rdtype, timeout, server, *, port=53):
            seen["server"] = server
            seen["port"] = port
            return None, "NXDOMAIN", None

        with patch("looking_glass.dns.resolve._query", side_effect=fake_query):
            resolve.lookup_dns("example.com", "DS", server="1.1.1.1:5353")
        self.assertEqual(seen["server"], "1.1.1.1")
        self.assertEqual(seen["port"], 5353)

    def test_ds_is_a_lookup_type(self):
        info = resolve.canonicalize_qtype("DS")
        self.assertEqual(info, {"name": "DS", "value": 43})
        self.assertIn("example.com", resolve.DNS_TYPE_EXAMPLES["DS"])
