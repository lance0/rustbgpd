import sys
import unittest
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

import compare  # noqa: E402


def cells(aa, abba, confirmation):
    """Every stage with parent at 1.0 s and the candidate slot at the given ratio."""
    result = []
    for stage, ratio in (("aa", aa), ("abba", abba), ("confirmation", confirmation)):
        for _ in range(compare.PAIRS):
            result.append((stage, "parent", {field: 1.0 for field in compare.FIELDS}))
            result.append((stage, "candidate", {field: ratio for field in compare.FIELDS}))
    return result


class Compare(unittest.TestCase):
    def test_schedule_is_aa_then_abba_then_confirmation_with_equal_sides(self):
        stages = [stage for stage, _ in compare.SCHEDULE]
        self.assertEqual(stages, sorted(stages, key=("aa", "abba", "confirmation").index))
        self.assertEqual([side for stage, side in compare.SCHEDULE if stage == "aa"], ["parent"] * 10)
        self.assertEqual([side for stage, side in compare.SCHEDULE if stage == "abba"],
                         ["parent", "candidate", "candidate", "parent", "parent",
                          "candidate", "candidate", "parent", "parent", "candidate"])
        self.assertEqual([side for stage, side in compare.SCHEDULE if stage == "confirmation"],
                         ["parent", "candidate"] * 5)
        for schedule in (compare.SCHEDULE, compare.CORRECTNESS_SCHEDULE):
            slots = compare.slots(schedule)
            for stage in ("aa", "abba", "confirmation"):
                sides = [slot for slot_stage, slot in slots if slot_stage == stage]
                self.assertEqual(sides.count("parent"), sides.count("candidate"), stage)
            # Outside A/A a cell is compared as the binary it ran.
            self.assertEqual([pair for pair in slots if pair[0] != "aa"],
                             [pair for pair in schedule if pair[0] != "aa"])

    def test_a_field_fails_only_when_abba_and_confirmation_both_exceed_the_threshold(self):
        for aa, abba, confirmation, threshold, fail in (
                (1.00, 1.019, 1.50, 1.02, False),   # ABBA inside the floor
                (1.00, 1.50, 1.019, 1.02, False),   # confirmation inside the floor
                (1.00, 1.021, 1.021, 1.02, True),   # both over the floor
                (1.05, 1.059, 1.059, 1.06, False),  # both inside a noisy A/A plus the margin
                (1.05, 1.061, 1.061, 1.06, True),
                (0.90, 1.021, 1.021, 1.02, True)):  # a fast A/A never lowers the floor
            row = compare.ratios(cells(aa, abba, confirmation))
            for field in compare.FIELDS:
                self.assertAlmostEqual(row[field]["threshold"], threshold)
                self.assertEqual(row[field]["fail"], fail, (aa, abba, confirmation))
                self.assertAlmostEqual(row[field]["abba"]["ratio"], abba)

    def test_fields_are_judged_separately(self):
        mixed = cells(1.0, 1.5, 1.5)
        for _, slot, values in mixed:
            if slot == "candidate":
                values["convergence-seconds"] = 1.0
        row = compare.ratios(mixed)
        self.assertTrue(row["churn-applied-seconds"]["fail"])
        self.assertFalse(row["convergence-seconds"]["fail"])

    def test_identical_owned_daemons_are_refused(self):
        same = {"rustbgpd-candidate": "a" * 64}
        with self.assertRaisesRegex(ValueError, "same binary"):
            compare.require_distinct({"parent": same, "candidate": dict(same)})
        compare.require_distinct({"parent": same, "candidate": {"rustbgpd-candidate": "b" * 64}})


if __name__ == "__main__":
    unittest.main()
