import inspect
import unittest

from looking_glass.dns import trace


class DnsTraceHelpers(unittest.TestCase):
    def test_v4_first(self):
        self.assertEqual(
            trace._v4_first(["2001:db8::1", "192.0.2.1", "192.0.2.1"]),
            ["192.0.2.1", "2001:db8::1"],
        )

    def test_timeout_default_is_eight_seconds(self):
        self.assertEqual(inspect.signature(trace.trace_dns).parameters["timeout"].default, 8.0)
        self.assertEqual(inspect.signature(trace.trace_dns_async).parameters["timeout"].default, 8.0)

    def test_query_error_shortens_timeout(self):
        self.assertEqual(
            trace._query_error(TimeoutError("The DNS operation timed out after 4.000 seconds"), 8.0),
            "timed out after 8s",
        )
