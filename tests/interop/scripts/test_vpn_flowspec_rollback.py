"""Checker controls for the released-daemon VPN FlowSpec rollback probe."""

import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "rollback", Path(__file__).with_name("qualify-vpn-flowspec-rollback.py")
)
ROLLBACK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ROLLBACK)


class RollbackChecks(unittest.TestCase):
    def test_only_application_refusal_passes(self):
        for code in ("InvalidArgument", "Unimplemented"):
            stderr = f"ERROR:\n  Code: {code}\n  Message: unsupported family\n"
            self.assertEqual(ROLLBACK.refusal_status(1, stderr), ("PASS", code))

    def test_success_fails_even_if_stderr_looks_like_a_status(self):
        self.assertEqual(
            ROLLBACK.refusal_status(
                0, "ERROR:\n  Code: InvalidArgument\n  Message: unsupported family\n"
            )[0],
            "FAIL",
        )

    def test_transport_and_client_errors_are_invalid(self):
        for stderr in (
            "Failed to dial target host: connection refused\n",
            "ERROR:\n  Code: Unavailable\n  Message: transport is closing\n",
            "ERROR:\n  Code: DeadlineExceeded\n  Message: context deadline exceeded\n",
            "Error invoking method: error getting request data: unknown field rd\n",
            "ERROR:\n  Code: PermissionDenied\n  Message: access denied\n",
            "",
        ):
            self.assertEqual(ROLLBACK.refusal_status(1, stderr)[0], "INVALID")

    def test_empty_valid_snapshots(self):
        self.assertEqual(ROLLBACK.read_listing("{}", "leases"), {})
        self.assertEqual(
            ROLLBACK.read_listing('{"receivedView":true}', "routes"), {"receivedView": True}
        )

    def test_failed_or_malformed_reads_are_not_comparable(self):
        for text, kind in (
            ("connection refused", "leases"),
            ("[]", "leases"),
            ('{"leases":{}}', "leases"),
            ('{"leases":[1]}', "leases"),
            ("{}", "routes"),
            ('{"receivedView":false}', "routes"),
            ('{"receivedView":true,"receivedRoutes":"error"}', "routes"),
            (
                '{"receivedView":true,"receivedRoutes":[{"route":{"afiSafi":"ADDRESS_FAMILY_L3VPN_IPV4_FLOWSPEC"}}]}',
                "routes",
            ),
            ('{"receivedView":true,"routes":[{}]}', "routes"),
            ('{"receivedView":true,"receivedRoutes":[{}]}', "routes"),
        ):
            with self.assertRaises(ValueError):
                ROLLBACK.read_listing(text, kind)

    def test_control_requires_more_than_elapsed_lease_time(self):
        before = '{"receivedView":true,"receivedRoutes":[{"route":{"afiSafi":"ADDRESS_FAMILY_IPV4_FLOWSPEC","leaseRemainingMs":100,"actions":[]}}]}'
        elapsed = before.replace(":100", ":99")
        changed = elapsed.replace('"actions":[]', '"actions":[{"trafficRate":{"rate":0}}]')
        self.assertEqual(ROLLBACK.stable_rules(before), ROLLBACK.stable_rules(elapsed))
        self.assertNotEqual(ROLLBACK.stable_rules(before), ROLLBACK.stable_rules(changed))


if __name__ == "__main__":
    unittest.main()
