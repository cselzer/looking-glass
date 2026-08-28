import unittest

from looking_glass.http.cli_text import curl_line, wall_cli
from looking_glass.http.site import _bad_query, _howto_path, _plan


class WallCliTests(unittest.TestCase):
    def test_ip_and_asn(self):
        self.assertEqual(wall_cli("/"), "looking-glass ip")
        self.assertEqual(wall_cli("/1.1.1.1"), "looking-glass ip 1.1.1.1")
        self.assertEqual(wall_cli("/AS13335"), "looking-glass asn 13335")

    def test_dns_dig_style(self):
        self.assertEqual(wall_cli("/dns/example.com"), "looking-glass dns example.com")
        self.assertEqual(wall_cli("/dns/example.com/MX"), "looking-glass dns example.com MX")
        self.assertEqual(
            wall_cli("/dns/example.com/A?server=127.0.0.1&port=5353"),
            "looking-glass dns @127.0.0.1:5353 example.com",
        )

    def test_whois_legacy_and_new_tools(self):
        self.assertEqual(wall_cli("/rdap/1.1.1.1"), "looking-glass rdap 1.1.1.1")
        self.assertEqual(wall_cli("/whois/example.com?legacy=1"), "looking-glass whois example.com --legacy")
        self.assertEqual(wall_cli("/bgp/1.1.1.1"), "looking-glass bgp 1.1.1.1")
        self.assertEqual(wall_cli("/dnstrace/example.com/AAAA"), "looking-glass dnstrace example.com -t AAAA")
        self.assertEqual(wall_cli("/tcp/example.com/25"), "looking-glass tcp example.com -p 25")
        self.assertEqual(wall_cli("/http/example.com/path"), "looking-glass http example.com/path")
        self.assertEqual(
            wall_cli("/http/example.com?scheme=http"),
            "looking-glass http http://example.com",
        )
        self.assertEqual(
            wall_cli("/http/https://example.com/a"),
            "looking-glass http https://example.com/a",
        )
        self.assertEqual(
            wall_cli("/http?url=https://example.com"),
            "looking-glass http https://example.com",
        )
        self.assertEqual(wall_cli("/whois/example.com?legacy=yes"), "looking-glass whois example.com --legacy")
        self.assertEqual(wall_cli("/tls/example.com?sni=www.example.com"), "looking-glass tls example.com --sni www.example.com")
        self.assertEqual(wall_cli("/mtr/1.1.1.1"), "looking-glass mtr 1.1.1.1")
        self.assertEqual(wall_cli("/mtr/1.1.1.1?cycles=3"), "looking-glass mtr 1.1.1.1 --cycles 3")
        self.assertEqual(wall_cli("/AU"), "looking-glass ip AU")
        self.assertNotIn("erso-wall", wall_cli("/1.1.1.1"))


class HowtoPathTests(unittest.TestCase):
    def test_http_howto_uses_query_url(self):
        path = _howto_path(
            "/http/https:/example.com",
            {"kind": "http", "query": "https://example.com"},
        )
        self.assertEqual(path, "/http?url=https%3A%2F%2Fexample.com")
        self.assertNotIn("%2F", path.split("?", 1)[0])
        line = curl_line("https://s1.example", path)
        self.assertIn("/http?url=", line)
        self.assertIn("example.com", line)
        self.assertNotIn("/http/https:", line)

    def test_tls_howto_uses_stripped_host(self):
        path = _howto_path(
            "/tls/https:/example.com",
            {"kind": "tls", "query": "example.com", "result": {"port": 443}},
        )
        self.assertEqual(path, "/tls/example.com")
        self.assertNotIn("https:/", path)
        self.assertEqual(wall_cli(path), "looking-glass tls example.com")
        self.assertEqual(
            _howto_path(
                "/tls/https:/example.com/8443",
                {"kind": "tls", "query": "example.com", "result": {"port": 8443}},
            ),
            "/tls/example.com/8443",
        )

    def test_tcp_howto_uses_stripped_host(self):
        path = _howto_path(
            "/tcp/https:/example.com/443",
            {"kind": "tcp", "query": "example.com", "result": {"port": 443}},
        )
        self.assertEqual(path, "/tcp/example.com/443")
        self.assertNotIn("https:/", path)
        self.assertEqual(wall_cli(path), "looking-glass tcp example.com -p 443")

    def test_bad_query_strips_tool_prefix(self):
        self.assertEqual(_bad_query("dns", "dns/not a domain"), "not a domain")
        err, kind, value, base = _plan("wsgi", "1.1.1.1", "/dns/not a domain", {})
        self.assertIsNotNone(err)
        status, _ctype, body = err
        self.assertEqual(status, 400)
        payload = __import__("json").loads(body)
        self.assertEqual(payload["query"], "not a domain")
        self.assertNotIn("dns/", payload["query"])
