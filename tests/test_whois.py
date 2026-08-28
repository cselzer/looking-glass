import unittest
from datetime import datetime, timezone
from unittest import mock

from looking_glass.intel import whois


SAMPLE = """
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Registrar IANA ID: 123
Creation Date: 2009-02-17T18:19:12Z
Registry Expiry Date: 2027-02-17T18:19:12Z
Updated Date: 2024-01-01T00:00:00Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
nserver: a.iana-servers.net 199.43.135.53
DNSSEC: signedDelegation
Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
Registrant Organization: Example Org
Registrant Country: US
"""


class WhoisParseTests(unittest.TestCase):
    def test_parse_signed_domain(self):
        now = datetime(2026, 8, 23, tzinfo=timezone.utc)
        parsed = whois.parse_whois_text(SAMPLE, now=now)
        self.assertEqual(parsed["name"], "EXAMPLE.COM")
        self.assertEqual(parsed["registrar"]["name"], "Example Registrar, Inc.")
        self.assertEqual(parsed["registrar"]["iana_id"], "123")
        self.assertEqual(parsed["dnssec"]["signed"], True)
        self.assertEqual(parsed["dnssec"]["label"], "signed")
        self.assertEqual(parsed["nameservers"], ["a.iana-servers.net", "b.iana-servers.net"])
        self.assertEqual(parsed["nameserver_details"][0]["v4"], ["199.43.135.53"])
        self.assertIn("year", parsed["registered_age"])
        self.assertTrue(parsed["expires_in"].startswith("in "))
        self.assertIn("clientTransferProhibited", parsed["status"])

    def test_parse_unsigned(self):
        parsed = whois.parse_whois_text("Domain Name: NOSEC.EXAMPLE\nDNSSEC: unsigned\n")
        self.assertEqual(parsed["dnssec"]["signed"], False)
        self.assertEqual(parsed["dnssec"]["label"], "unsigned")


IANA_DOMAIN_STUB = """
% IANA WHOIS server
domain:       EXAMPLE.COM
created:      1992-01-01
changed:      2024-08-18
nserver:      A.IANA-SERVERS.NET
"""

IANA_TLD_COM = """
domain:       COM
organisation: VeriSign Global Registry Services
whois:        whois.verisign-grs.com
status:       ACTIVE
created:      1985-01-01
"""

IANA_DOMAIN_REFER = """
domain:       EXAMPLE.COM
refer:        whois.verisign-grs.com
"""

REGISTRY_WITH_IANA_REFERRAL = SAMPLE + "\nRegistrar WHOIS Server: whois.iana.org\n"


class WhoisReferralTests(unittest.TestCase):
    def test_iana_stub_follows_tld_whois_to_registry(self):
        calls = []

        def fake_query(server, question, timeout=8.0):
            calls.append((server, question))
            if server == "whois.iana.org":
                if str(question).strip(".").lower() == "com":
                    return IANA_TLD_COM
                return IANA_DOMAIN_STUB
            if server == "whois.verisign-grs.com":
                self.assertEqual(question, "example.com")
                return SAMPLE
            raise AssertionError(f"unexpected whois query {server!r} {question!r}")

        with unittest.mock.patch("looking_glass.intel.whois._query", side_effect=fake_query):
            payload = whois.lookup_whois_legacy("example.com")
        self.assertTrue(payload["ok"])
        result = payload["result"]
        self.assertEqual(result["name"], "EXAMPLE.COM")
        self.assertEqual(result["nameservers"], ["a.iana-servers.net", "b.iana-servers.net"])
        self.assertIn("2009", result["dates"]["registered"] or "")
        self.assertNotIn("1992", result["dates"]["registered"] or "")
        self.assertEqual(result["server"], "whois.verisign-grs.com")
        self.assertIn(("whois.iana.org", "com"), calls)
        self.assertIn(("whois.verisign-grs.com", "example.com"), calls)

    def test_verisign_referral_back_to_iana_does_not_clobber_registry(self):
        def fake_query(server, question, timeout=8.0):
            if server == "whois.iana.org":
                return IANA_DOMAIN_REFER
            if server == "whois.verisign-grs.com":
                return REGISTRY_WITH_IANA_REFERRAL
            raise AssertionError(f"unexpected extra hop to {server!r}")

        with unittest.mock.patch("looking_glass.intel.whois._query", side_effect=fake_query):
            payload = whois.lookup_whois_legacy("example.com")
        self.assertTrue(payload["ok"])
        result = payload["result"]
        self.assertEqual(result["name"], "EXAMPLE.COM")
        self.assertEqual(result["server"], "whois.verisign-grs.com")
        self.assertIn("EXAMPLE.COM", result["text"])
        self.assertNotIn("refer:", result["text"].lower())
        servers = [hop["server"] for hop in result["chain"]]
        self.assertEqual(servers.count("whois.iana.org"), 1)
