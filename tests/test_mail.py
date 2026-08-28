import unittest
from unittest.mock import patch

from looking_glass.net.mail import check_mail, is_null_mx


class NullMxTests(unittest.TestCase):
    def test_detects_root_exchange(self):
        self.assertTrue(is_null_mx([{"preference": 0, "host": "."}]))
        self.assertTrue(is_null_mx([{"preference": 0, "exchange": ""}]))
        self.assertFalse(is_null_mx([{"preference": 0, "host": "mail.example.com"}]))
        self.assertFalse(
            is_null_mx(
                [
                    {"preference": 0, "host": "."},
                    {"preference": 10, "host": "mail.example.com"},
                ]
            )
        )

    def test_check_mail_skips_smtp(self):
        async def answers(name, qtype, timeout):
            if qtype == "MX":
                return [{"data": "0 .", "ttl": 300}]
            return []

        with (
            patch("looking_glass.net.mail._answers", side_effect=answers),
            patch("looking_glass.net.mail._smtp_probe") as smtp,
        ):
            payload = check_mail("example.com")
        smtp.assert_not_called()
        self.assertTrue(payload["ok"])
        self.assertIsNone(payload["error"])
        self.assertTrue(payload["result"]["null_mx"])
        self.assertEqual(payload["result"]["mx"][0]["host"], ".")
        self.assertIsNone(payload["result"]["smtp"])
