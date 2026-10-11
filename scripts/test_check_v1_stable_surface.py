"""Exercise the capability-section rules of the v1 stable-surface checker."""

import contextlib
import copy
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check-v1-stable-surface.py"
SPEC = importlib.util.spec_from_file_location("check_v1_stable_surface", SCRIPT)
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


class CapabilitySectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inventory = checker.load_json(checker.INVENTORY_PATH)
        cls.legs = checker.evidence_index.load_legs(checker.ROOT)

    def rejected(self, inventory, expected):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            checker.check_capabilities(inventory, self.legs)
        self.assertIn(expected, stderr.getvalue())

    def row(self, row_id):
        inventory = copy.deepcopy(self.inventory)
        rows = inventory["capabilities"]["rows"]
        return inventory, next(row for row in rows if row["id"] == row_id)

    def test_live_inventory_passes(self):
        checker.check_capabilities(self.inventory, self.legs)

    def test_row_cannot_write_a_compatibility_label(self):
        inventory, row = self.row("flowspec-controller")
        row["classification"] = "stable"
        self.rejected(inventory, "compatibility is read from the inventory")

    def test_stable_is_not_a_behavior_claim(self):
        inventory, row = self.row("flowspec-controller")
        row["evidence"][0]["claims"].append("stable")
        self.rejected(inventory, "stability is never a claim")

    def test_projection_cannot_exceed_the_leg_declaration(self):
        inventory, row = self.row("bmp-base-export")
        row["evidence"][0]["claims"].append("selected")
        self.rejected(inventory, "projects claim 'selected' that leg m24-bmp-frr does not declare")

    def test_dangling_and_duplicate_references_fail(self):
        cases = [
            (lambda row: row.update(roles=["flowspec"]), "unknown role 'flowspec'"),
            (lambda row: row.update(surfaces=["InjectionService.AddFlowSpecs"]), "not inventoried"),
            (lambda row: row.update(evidence=[{"leg": "m22", "claims": ["stored"]}]),
             "with no driver header"),
            (lambda row: row.update(evidence=row["evidence"] * 2), "repeats evidence leg"),
            (lambda row: row.update(evidence=[]), "needs evidence"),
            (lambda row: row.update(excludes=[]), "must state what it does not cover"),
            (lambda row: row.update(id="FlowSpec"), "must be a lowercase slug"),
            (lambda row: row.update(id="bmp-base-export"), "duplicate capability id"),
        ]
        for mutate, expected in cases:
            with self.subTest(expected=expected):
                inventory, row = self.row("flowspec-controller")
                mutate(row)
                self.rejected(inventory, expected)

    def test_section_shape(self):
        inventory = copy.deepcopy(self.inventory)
        inventory["capabilities"]["stable"] = []
        self.rejected(inventory, "exactly 'purpose' and 'rows'")
        del inventory["capabilities"]
        self.rejected(inventory, "exactly 'purpose' and 'rows'")

    def test_inventory_rejects_duplicate_json_keys(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "inventory.json"
            path.write_text(json.dumps({"a": 1})[:-1] + ', "a": 2}')
            stderr = io.StringIO()
            original = checker.ROOT
            checker.ROOT = Path(temp)
            try:
                with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
                    checker.load_json(path)
            finally:
                checker.ROOT = original
            self.assertIn("duplicate keys ['a']", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
