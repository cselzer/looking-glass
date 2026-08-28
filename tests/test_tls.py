import datetime
import socket
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from looking_glass.http.site import _lookup_kwargs, _plan, path_token
from looking_glass.net.tls import _leaf_from_cert, _leaf_from_der, inspect_tls, parse_tls_path


class TlsPathTests(unittest.TestCase):
    def test_parse_host_and_port(self):
        self.assertEqual(parse_tls_path("/tls/example.com"), ("example.com", 443))
        self.assertEqual(parse_tls_path("/tls/example.com/8443"), ("example.com", 8443))
        with self.assertRaises(ValueError):
            parse_tls_path("/tls")
        with self.assertRaises(ValueError):
            parse_tls_path("/tls/example.com/99/extra")
        with self.assertRaises(ValueError):
            parse_tls_path("/tls/example.com/70000")

    def test_colon_host_port(self):
        self.assertEqual(parse_tls_path("/tls/s1.example.com:5555"), ("s1.example.com", 5555))
        self.assertEqual(parse_tls_path("/tls/45.63.74.250:5555"), ("45.63.74.250", 5555))
        self.assertEqual(
            parse_tls_path("/tls/[2606:4700:4700::1111]:5555"),
            ("2606:4700:4700::1111", 5555),
        )
        self.assertEqual(
            parse_tls_path("/tls/example.com:8443/5555"),
            ("example.com", 5555),
        )
        with self.assertRaises(ValueError):
            parse_tls_path("/tls/example.com:70000")
        with self.assertRaises(ValueError):
            parse_tls_path("/tls/example.com:nope")

    def test_ipv6_literals(self):
        self.assertEqual(
            parse_tls_path("/tls/2606:4700:4700::1111"),
            ("2606:4700:4700::1111", 443),
        )
        self.assertEqual(
            parse_tls_path("/tls/[2606:4700:4700::1111]"),
            ("2606:4700:4700::1111", 443),
        )
        self.assertEqual(
            parse_tls_path("/tls/[2606:4700:4700::1111]/443"),
            ("2606:4700:4700::1111", 443),
        )

    def test_collapsed_https_url_uses_hostname(self):
        self.assertEqual(path_token("/tls/https:/example.com"), "tls/https://example.com")
        self.assertEqual(parse_tls_path("/tls/https:/example.com"), ("example.com", 443))
        self.assertEqual(parse_tls_path("/tls/https://example.com"), ("example.com", 443))
        self.assertEqual(parse_tls_path("/tls/https://example.com:8443"), ("example.com", 8443))


class TlsSniPlanTests(unittest.TestCase):
    def test_sni_query_reaches_kwargs(self):
        err, kind, value, base = _plan(
            "wsgi", "1.1.1.1", "/tls/example.com", {}, "sni=www.example.com"
        )
        self.assertIsNone(err)
        self.assertEqual(kind, "tls")
        self.assertEqual(value, "example.com")
        self.assertEqual(base.get("sni"), "www.example.com")
        self.assertEqual(_lookup_kwargs(base).get("sni"), "www.example.com")

    def test_collapsed_https_envelope_is_host(self):
        err, kind, value, base = _plan(
            "wsgi", "1.1.1.1", "/tls/https:/example.com", {}, ""
        )
        self.assertIsNone(err)
        self.assertEqual(kind, "tls")
        self.assertEqual(value, "example.com")
        self.assertEqual(base["query"], "example.com")
        self.assertEqual(base["port"], 443)

    def test_colon_port_reaches_plan(self):
        err, kind, value, base = _plan(
            "wsgi", "1.1.1.1", "/tls/s1.example.com:5555", {}, ""
        )
        self.assertIsNone(err)
        self.assertEqual(kind, "tls")
        self.assertEqual(value, "s1.example.com")
        self.assertEqual(base["port"], 5555)
        err, kind, value, base = _plan(
            "wsgi", "1.1.1.1", "/tls/45.63.74.250:5555", {}, ""
        )
        self.assertIsNone(err)
        self.assertEqual(value, "45.63.74.250")
        self.assertEqual(base["port"], 5555)
        err, _, _, _ = _plan("wsgi", "1.1.1.1", "/tls/s1.example.com:70000", {}, "")
        self.assertIsNotNone(err)
        self.assertEqual(err[0], 400)


class TlsInspectFailTests(unittest.TestCase):
    def test_refused_keeps_result_stub(self):
        err = ConnectionRefusedError("[Errno 111] Connection refused")
        with (
            patch(
                "looking_glass.net.tls._resolve",
                return_value=("1.2.3.4", socket.AF_INET, "example.com"),
            ),
            patch("looking_glass.net.tls._handshake", side_effect=err),
        ):
            payload = inspect_tls("example.com", port=443)
        self.assertFalse(payload["ok"])
        result = payload["result"]
        self.assertIsNotNone(result)
        self.assertEqual(result["host"], "example.com")
        self.assertEqual(result["ip"], "1.2.3.4")
        self.assertEqual(result["port"], 443)
        self.assertEqual(result["family"], "IPv4")
        self.assertFalse(result["verified"])
        self.assertTrue(payload["error"])
        self.assertEqual(result["error"], payload["error"])
        self.assertNotIn("pem", result)
        self.assertNotIn("pem", result.get("leaf") or {})

    def test_resolve_fail_keeps_host_port(self):
        with patch(
            "looking_glass.net.tls._resolve",
            side_effect=socket.gaierror(-2, "Name or service not known"),
        ):
            payload = inspect_tls("no.such.host", port=5555)
        self.assertFalse(payload["ok"])
        result = payload["result"]
        self.assertEqual(result["host"], "no.such.host")
        self.assertEqual(result["port"], 5555)
        self.assertFalse(result["verified"])
        self.assertNotIn("ip", result)
        self.assertTrue(payload["error"])


def _aia_der() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.OCSP,
                        x509.UniformResourceIdentifier("http://ocsp.example"),
                    ),
                    x509.AccessDescription(
                        x509.AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.UniformResourceIdentifier("http://ca.example/ca.cer"),
                    ),
                ]
            ),
            critical=False,
        )
        .add_extension(
            x509.CRLDistributionPoints(
                [
                    x509.DistributionPoint(
                        full_name=[x509.UniformResourceIdentifier("http://crl.example/ca.crl")],
                        relative_name=None,
                        reasons=None,
                        crl_issuer=None,
                    )
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class TlsDerAiaTests(unittest.TestCase):
    def test_leaf_from_der_reads_aia_and_version(self):
        leaf = _leaf_from_der(_aia_der())
        self.assertEqual(leaf["version"], 2)
        self.assertIn("http://ocsp.example", leaf["ocsp"])
        self.assertIn("http://ca.example/ca.cer", leaf["ca_issuers"])
        self.assertIn("http://crl.example/ca.crl", leaf["crl"])

    def test_unverified_peercert_overlays_der_aia(self):
        der = _aia_der()
        leaf = _leaf_from_cert(
            {
                "subject": ((("commonName", "mismatch.example"),),),
                "issuer": ((("commonName", "test.example"),),),
                "version": None,
                "OCSP": [],
                "caIssuers": [],
                "crlDistributionPoints": [],
            },
            der,
        )
        self.assertEqual(leaf["version"], 2)
        self.assertIn("http://ocsp.example", leaf["ocsp"])
        self.assertIn("http://ca.example/ca.cer", leaf["ca_issuers"])
