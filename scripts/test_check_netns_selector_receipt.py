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

    def test_vrf_available_requires_all_21(self):
        errors, payload, summary = self.run_case(BASE + VRF, True)
        self.assertEqual(errors, [])
        self.assertEqual(payload["executed_selectors"], list(BASE + VRF))
        self.assertEqual(payload["omitted_selectors"], [])
        self.assertIn("PASS", summary)

    def test_vrf_unavailable_requires_16_and_publishes_five_omissions(self):
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
        self.assertEqual(payload["errors"], sorted(errors))
        self.assertIn("FAIL", summary)


if __name__ == "__main__":
    unittest.main()
