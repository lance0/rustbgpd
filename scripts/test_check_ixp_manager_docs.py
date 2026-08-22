#!/usr/bin/env python3
"""Mutation proofs for the fail-closed IXP Manager docs contract gate."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_ixp_manager_docs as checker

README = checker.README.read_text(encoding="utf-8")
CONTRACT = json.loads(checker.CONTRACT.read_text(encoding="utf-8"))
INTEROP = checker.INTEROP.read_text(encoding="utf-8")
RECEIPTS = checker.RECEIPTS.read_text(encoding="utf-8")
PROOF = checker.PROOF.read_text(encoding="utf-8")


def row(document: str, prefix: str) -> str:
    (line,) = [line for line in document.splitlines() if line.startswith(prefix)]
    return line + "\n"


def without(document: str, prefix: str) -> str:
    return document.replace(row(document, prefix), "", 1)


class IxpManagerDocsTests(unittest.TestCase):
    def assert_red(self, needle: str, readme=README, interop=INTEROP, receipts=RECEIPTS, proof=PROOF) -> None:
        errors = checker.check(readme, CONTRACT, interop, receipts, proof)
        self.assertTrue(any(needle in error for error in errors), errors)

    def test_tree_is_green(self) -> None:
        self.assertEqual(checker.check(README, CONTRACT, INTEROP, RECEIPTS, PROOF), [])

    def test_dropped_active_reason_row_is_red(self) -> None:
        self.assert_red("active_ids", readme=without(README, "| `.rpol` term `ixp-manager-hygiene:reject-as-path-too-long` |"))

    def test_reason_display_drift_is_red(self) -> None:
        self.assert_red("reason id 3 displays", readme=README.replace("| 3 | BOGON |", "| 3 | BOGUS |", 1))

    def test_missing_fallback_row_is_red(self) -> None:
        self.assert_red("no fallback row", readme=without(README, "| any other or ambiguous cause |"))

    def test_dropped_defined_only_row_is_red(self) -> None:
        self.assert_red("defined_only_ids", readme=without(README, "| 11 | PREFIX NOT IN ORIGIN AS |"))

    def test_defined_only_emission_drift_is_red(self) -> None:
        self.assert_red(
            "defined-only id 12 is emitted as 12",
            readme=README.replace("| 12 | RPKI UNKNOWN | 0 |", "| 12 | RPKI UNKNOWN | 12 |", 1),
        )

    def test_capability_status_flip_is_red(self) -> None:
        self.assert_red(
            "runtime_supported",
            readme=README.replace("| `atomic-full-table-snapshot` | supported |", "| `atomic-full-table-snapshot` | unsupported |", 1),
        )

    def test_dropped_capability_row_is_red(self) -> None:
        self.assert_red("contract unsupported", readme=without(README, "| `full-table-count` |"))

    def test_missing_tables_are_red(self) -> None:
        errors = checker.check("# empty\n", CONTRACT, INTEROP, RECEIPTS, PROOF)
        self.assertTrue(any("reason-id table" in e for e in errors), errors)
        self.assertTrue(any("capability table" in e for e in errors), errors)

    def test_receipt_row_removal_is_red(self) -> None:
        self.assert_red("claims M96 in its IXP Manager sections but RECEIPTS.md", receipts=without(RECEIPTS, "| M96 |"))

    def test_proof_row_removal_is_red(self) -> None:
        self.assert_red("claims M97 in its IXP Manager sections but OPERATIONAL_PROOF.md", proof=without(PROOF, "| M97 |"))

    def test_new_interop_claim_without_receipt_row_is_red(self) -> None:
        unreceipted = next(f"M{n}" for n in range(100, 10000) if f"| {f'M{n}'} " not in RECEIPTS)
        bullet = f"- **IXP Manager future proof** — a new claim: **{unreceipted}**.\n"
        self.assert_red(f"claims {unreceipted}", interop=INTEROP + bullet)

    def test_empty_interop_claims_are_red(self) -> None:
        self.assert_red("walk is broken", interop="# no ixp sections\n")

    def test_recipe_table_does_not_count_as_receipt_row(self) -> None:
        self.assertNotIn("M14", checker.receipt_rows("| Receipts | Recipe |\n|---|---|\n| M14, M76 | x |\n"))
        self.assertIn("M14", checker.receipt_rows("| Receipt | Proves |\n|---|---|\n| M14 | x |\n"))
        self.assertIn("M14", checker.receipt_rows("| Receipts | Coverage |\n|---|---|\n| M14, M76 | x |\n", "Receipts"))


if __name__ == "__main__":
    unittest.main()
