import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_netns_selector_receipt import BASE, VRF, finalize


class ReceiptTest(unittest.TestCase):
    def run_case(self, selectors, vrf):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            receipt, output, summary = root / "seen", root / "out.json", root / "summary"
            receipt.write_text("".join(f"{item}\n" for item in selectors))
            errors = finalize(receipt, output, summary, vrf)
            return errors, json.loads(output.read_text()), summary.read_text()

    def test_selector_rosters_are_exact(self):
        self.assertEqual(
            BASE,
            (
                "fdb_nhg",
                "fib_runtime",
                "bfd_runtime",
                "dataplane_vlan_fdb",
                "dataplane_remote_mac",
                "vlan_local_mac_attribution",
                "macip_vlan_attribution",
                "svd_fdb_vni",
                "managed_bridge",
                "managed_vxlan",
                "managed_svd_vxlan",
                "managed_vlan_upper",
                "managed_ready",
                "link_carrier",
                "ac_gate",
                "nexthop_raw",
                "foreign_state_l2",
                "foreign_state_nhid",
            ),
        )
        self.assertEqual(
            VRF,
            (
                "l3_multipath",
                "managed_ip_vrf_ready",
                "l3_all_active_writer",
                "foreign_state_l3",
                "l3_route_event",
                "l3_single_path_cycle",
                "l3_foreign_route_cycle",
            ),
        )

    def test_vrf_available_requires_all_25(self):
        errors, payload, summary = self.run_case(BASE + VRF, True)
        self.assertEqual(errors, [])
        self.assertEqual(payload["executed_selectors"], list(BASE + VRF))
        self.assertEqual(payload["omitted_selectors"], [])
        self.assertIn("PASS", summary)

    def test_vrf_unavailable_requires_18_and_publishes_seven_omissions(self):
        errors, payload, _ = self.run_case(BASE, False)
        self.assertEqual(errors, [])
        self.assertEqual(
            payload["omitted_selectors"],
            [{"selector": item, "reason": "vrf_unavailable"} for item in VRF],
        )

    def test_rejects_missing_duplicate_and_unexpected(self):
        errors, payload, summary = self.run_case(BASE[1:] + (BASE[1], "surprise"), False)
        self.assertIn(f"missing selector: {BASE[0]}", errors)
        self.assertIn(f"duplicate selector: {BASE[1]}", errors)
        self.assertIn("unexpected selector: surprise", errors)
        self.assertEqual(errors, sorted(errors))
        self.assertEqual(payload["errors"], errors)
        self.assertIn("FAIL", summary)


if __name__ == "__main__":
    unittest.main()
