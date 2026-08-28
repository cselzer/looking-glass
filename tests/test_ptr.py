import unittest
from unittest.mock import patch

from looking_glass.dns import ptr


class PtrMappedTests(unittest.IsolatedAsyncioTestCase):
    async def test_ipv4_mapped_fcrdns_uses_a(self):
        async def look(name, qtype, timeout=4.0):
            if qtype == "PTR":
                return {
                    "ok": True,
                    "result": {"answers": [{"data": "one.one.one.one."}]},
                }
            if qtype == "A":
                return {
                    "ok": True,
                    "result": {"answers": [{"data": "1.1.1.1"}]},
                }
            return {"ok": True, "result": {"answers": [{"data": "2606:4700:4700::1111"}]}}

        with patch("looking_glass.dns.resolve.lookup_dns_async", side_effect=look):
            payload = await ptr.check_ptr_async("::ffff:1.1.1.1")
        self.assertTrue(payload["ok"])
        self.assertTrue(payload["result"]["fcrdns"])
        self.assertEqual(payload["result"]["forward"][0]["type"], "A")
        self.assertTrue(payload["result"]["forward"][0]["matches"])
