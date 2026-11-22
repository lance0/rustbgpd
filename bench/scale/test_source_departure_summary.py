"""Campaign grading. Synthetic receipts only; no Rust process or cgroup needed."""

from pathlib import Path
import shutil
import tempfile
import unittest

from recovery_memory import write_json
import source_departure_summary as summary

MODES = ("grouped-unicast", "private-unicast")
SCHEDULE = [("aa", "parent")] * 2 + [
    ("abba", arm) for arm in ("parent", "candidate", "candidate", "parent")
] + [("confirmation", "parent"), ("confirmation", "candidate")]


def trial(mode, arm, delay=1_000, convergence=10_000, peak=1 << 30, work=None):
    candidate = arm == "candidate"
    return {
        "mode": mode,
        "repetition": 1,
        "verdict": "PASS",
        "reason": "exact receiver inventory and expected Loc-RIB application order",
        "cgroup_peak_bytes": peak,
        "swap_peak_bytes": 0,
        "observation": {
            "mode": mode,
            "receivers": 150,
            "rows": 37_000,
            "exact": True,
            "rib_withdrawal_rows": 150 * 37_000,
            "update_to_applied_ns": delay // 4 if candidate else delay,
            "convergence_ns": convergence,
            "max_withdrawals_per_poll": (256 if candidate else 5_550_000)
            if work is None
            else work,
            "update_applied_before_departure_complete": candidate,
        },
    }


class SummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def campaign(self, edit=None):
        """Write the schedule; `edit(stage, index, arm, receipt)` may mutate a receipt."""
        counts = {}
        for stage, arm in SCHEDULE:
            counts[stage] = counts.get(stage, 0) + 1
            receipt = {
                "arm": arm,
                "shape": "standard",
                "binary_sha256": arm,
                "break_witness": False,
                "trials": [trial(mode, arm) for mode in MODES],
            }
            if edit:
                edit(stage, counts[stage], arm, receipt)
            directory = self.root / f"{stage}-{counts[stage]}"
            directory.mkdir()
            write_json(directory / "receipt.json", receipt)
        return summary.summarize(self.root)

    def reset(self):
        shutil.rmtree(self.root)
        self.root.mkdir()

    def verdicts(self, cells):
        return {name: cell["verdict"] for name, cell in cells.items()}

    def test_scheduled_campaign_passes_each_cell(self):
        cells = self.campaign()
        self.assertEqual(
            self.verdicts(cells),
            {"standard/grouped-unicast": "PASS", "standard/private-unicast": "PASS"},
        )
        ratios = cells["standard/private-unicast"]["ratios"]
        self.assertEqual(ratios["delay"], {"abba": 0.25, "confirmation": 0.25})
        self.assertEqual(ratios["convergence"]["threshold"], 1.02)

    def test_candidate_delay_above_half_of_parent_fails(self):
        def slow(stage, index, arm, receipt):
            if arm == "candidate" and stage == "confirmation":
                receipt["trials"][1] = trial(MODES[1], arm, delay=2_400)
        cells = self.campaign(slow)
        self.assertEqual(cells["standard/private-unicast"]["verdict"], "FAIL")
        self.assertIn("UPDATE delay confirmation 0.600", cells["standard/private-unicast"]["reason"])
        self.assertEqual(cells["standard/grouped-unicast"]["verdict"], "PASS")

    def test_cost_fails_only_when_abba_and_confirmation_both_exceed_threshold(self):
        def slower(stages):
            def edit(stage, index, arm, receipt):
                if arm == "candidate" and stage in stages:
                    receipt["trials"][0] = trial(MODES[0], arm, convergence=10_500)
            return edit

        for stages, verdict in ((("abba",), "PASS"), (("abba", "confirmation"), "FAIL")):
            with self.subTest(stages=stages):
                self.reset()
                cells = self.campaign(slower(stages))
                self.assertEqual(cells["standard/grouped-unicast"]["verdict"], verdict)

    def test_noisy_aa_raises_the_cost_threshold(self):
        def noisy(stage, index, arm, receipt):
            if stage == "aa" and index == 2:
                receipt["trials"][0] = trial(MODES[0], arm, peak=(1 << 30) * 21 // 20)
            if arm == "candidate" and stage != "aa":
                receipt["trials"][0] = trial(MODES[0], arm, peak=(1 << 30) * 21 // 20)
        cells = self.campaign(noisy)
        peak = cells["standard/grouped-unicast"]["ratios"]["cgroup_peak"]
        self.assertAlmostEqual(peak["threshold"], 1.06)
        self.assertEqual(cells["standard/grouped-unicast"]["verdict"], "PASS")

    def test_plausible_broken_candidate_fails_its_hard_checks(self):
        breaks = {
            "work": lambda row, t: row.update(max_withdrawals_per_poll=257),
            "order": lambda row, t: row.update(update_applied_before_departure_complete=False),
            "inexact": lambda row, t: row.update(rib_withdrawal_rows=150 * 37_000 - 1),
            "swap": lambda row, t: t.update(swap_peak_bytes=4096),
            "trial": lambda row, t: t.update(verdict="FAIL", reason="duplicate withdrawal"),
        }
        for name, mutate in breaks.items():
            with self.subTest(name=name):
                self.reset()

                def edit(stage, index, arm, receipt, mutate=mutate):
                    if arm == "candidate" and stage == "abba" and index == 3:
                        broken = receipt["trials"][1]
                        mutate(broken["observation"], broken)

                cells = self.campaign(edit)
                self.assertEqual(cells["standard/private-unicast"]["verdict"], "FAIL")
                self.assertIn("abba-3", cells["standard/private-unicast"]["reason"])
                self.assertEqual(cells["standard/grouped-unicast"]["verdict"], "PASS")

    def test_parent_arm_is_not_held_to_the_work_bar(self):
        cells = self.campaign()
        self.assertTrue(all(cell["verdict"] == "PASS" for cell in cells.values()))

    def test_unqualified_campaigns_are_invalid(self):
        def same_binary(stage, index, arm, receipt):
            receipt["binary_sha256"] = "same"

        def swapped(stage, index, arm, receipt):
            if stage == "abba" and index == 1:
                receipt["arm"] = "candidate"

        def skipped(stage, index, arm, receipt):
            if stage == "confirmation":
                receipt["trials"][1] = dict(receipt["trials"][1], verdict="SKIP", reason="room")

        def missing(stage, index, arm, receipt):
            if stage == "aa" and index == 2:
                receipt["trials"] = receipt["trials"][:1]

        def control(stage, index, arm, receipt):
            receipt["break_witness"] = True

        for edit, cell in (
            (same_binary, "campaign"),
            (swapped, "campaign"),
            (control, "campaign"),
            (skipped, "standard/private-unicast"),
            (missing, "standard/private-unicast"),
        ):
            with self.subTest(edit=edit.__name__):
                self.reset()
                cells = self.campaign(edit)
                self.assertEqual(cells[cell]["verdict"], "INVALID")

    def test_observation_from_another_shape_is_invalid(self):
        def smoke(stage, index, arm, receipt):
            if arm == "candidate" and stage == "abba" and index == 2:
                row = receipt["trials"][1]["observation"]
                row.update(receivers=8, rows=1_024, rib_withdrawal_rows=8 * 1_024)

        cells = self.campaign(smoke)
        self.assertEqual(cells["standard/private-unicast"]["verdict"], "INVALID")
        self.assertIn("not standard/private-unicast", cells["standard/private-unicast"]["reason"])
        self.assertEqual(cells["standard/grouped-unicast"]["verdict"], "PASS")

    def test_missing_or_empty_binary_digest_is_invalid(self):
        for digest in (None, "", "drop"):
            with self.subTest(digest=digest):
                self.reset()

                def edit(stage, index, arm, receipt, digest=digest):
                    if stage == "confirmation" and index == 2:
                        if digest == "drop":
                            del receipt["binary_sha256"]
                        else:
                            receipt["binary_sha256"] = digest

                cells = self.campaign(edit)
                self.assertEqual(cells["campaign"]["verdict"], "INVALID")
                self.assertIn("lacks a binary digest", cells["campaign"]["reason"])

    def test_incomplete_schedule_is_invalid(self):
        self.campaign()
        for child in (self.root / "abba-4").iterdir():
            child.unlink()
        (self.root / "abba-4").rmdir()
        self.assertEqual(summary.summarize(self.root)["campaign"]["verdict"], "INVALID")


if __name__ == "__main__":
    unittest.main()
