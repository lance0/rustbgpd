#!/usr/bin/env python3
"""Reject broken compact evidence and pin both independent timing-bar components."""
import csv
import json
import math
from pathlib import Path
import shutil
import tempfile
import unittest

import recompute


class ArtifactValidation(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("reloads-24.csv", "legs.json", "provenance.json"):
            shutil.copyfile(Path(__file__).parent / name, self.root / name)

    def edit_json(self, name, edit):
        path = self.root / name
        data = json.loads(path.read_text())
        edit(data)
        path.write_text(json.dumps(data))

    def edit_rows(self, edit):
        path = self.root / "reloads-24.csv"
        with path.open() as file:
            reader = csv.DictReader(file)
            fields, rows = reader.fieldnames, list(reader)
        edit(rows)
        with path.open("w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def test_valid_receipt(self):
        result = recompute.main(self.root)
        self.assertEqual(len(result["endpoints"]), 9)
        self.assertTrue(result["timing_bars_pass"])
        self.assertAlmostEqual(result["stall_p50_gain_ms"], 80.877)
        self.assertAlmostEqual(result["three_leg_median_stall_p50_gain_ms"], 79.7875)
        self.assertEqual(result["endpoints"]["completion_max_s"]["B"], 0.891329)
        self.assertAlmostEqual(result["endpoints"]["changed_first_generation_update_p95_ms"]
                               ["three_leg_median_change_percent"], 1.8414131294774538)

    def test_absent_empty_or_incomplete_native_maps(self):
        path = self.root / "legs.json"
        original = path.read_text()
        for field in ("native_checks", "wrapper_exits"):
            for mode in ("absent", "empty", "missing_one"):
                with self.subTest(field=field, mode=mode):
                    data = json.loads(original)
                    if mode == "absent":
                        del data[0][field]
                    elif mode == "empty":
                        data[0][field] = {}
                    else:
                        data[0][field].pop(next(iter(data[0][field])))
                    path.write_text(json.dumps(data))
                    with self.assertRaisesRegex(ValueError, "check keys"):
                        recompute.main(self.root)

    def test_boolean_is_not_successful_exit(self):
        self.edit_json("legs.json", lambda legs: legs[0]["native_checks"].update(harness_exit=False))
        with self.assertRaisesRegex(ValueError, "invalid native/wrapper exit"):
            recompute.main(self.root)

    def test_wrong_workload(self):
        self.edit_json("legs.json", lambda legs: legs[0]["workload"].update(FLAP_ROUNDS="3"))
        with self.assertRaisesRegex(ValueError, "noncanonical workload"):
            recompute.main(self.root)

    def test_wrong_arm_binary_and_harness(self):
        path = self.root / "legs.json"
        original = path.read_text()
        for field in ("daemon", "harness"):
            data = json.loads(original)
            data[1][field]["sha256"] = "0" * 64
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, "arm source/binary/harness mismatch"):
                recompute.main(self.root)

    def test_false_harness_producer(self):
        self.edit_json("provenance.json", lambda data: data["arms"]["B"]["harness"].update(
            producer_commit=data["arms"]["B"]["source"]["commit"]))
        with self.assertRaisesRegex(ValueError, "shared baseline harness identity mismatch"):
            recompute.main(self.root)

    def test_duplicate_reload_hiding_missing_reload(self):
        self.edit_rows(lambda rows: rows.__setitem__(-1, rows[0].copy()))
        with self.assertRaisesRegex(ValueError, "four unique reloads"):
            recompute.main(self.root)

    def test_consistently_relabelled_candidate_is_not_this_receipt(self):
        self.edit_json("provenance.json", lambda data: data["arms"]["B"]["daemon"].update(
            sha256="e" * 64))
        def change(legs):
            for leg in legs:
                if leg["leg"].endswith("B"):
                    leg["daemon"]["sha256"] = "e" * 64
        self.edit_json("legs.json", change)
        with self.assertRaisesRegex(ValueError, "dated campaign producer mismatch"):
            recompute.main(self.root)

    def test_failed_reload_health(self):
        self.edit_rows(lambda rows: rows[0].update(parse_errors="1"))
        with self.assertRaisesRegex(ValueError, "failed reload health"):
            recompute.main(self.root)

    def test_nonfinite_endpoint(self):
        path = self.root / "reloads-24.csv"
        original = path.read_text()
        for bad in ("NaN", "Infinity", "-1"):
            path.write_text(original)
            self.edit_rows(lambda rows, bad=bad: rows[0].update(completion_p50_s=bad))
            with self.assertRaisesRegex(ValueError, "non-finite or negative"):
                recompute.main(self.root)

    def test_quiet_outside_leg(self):
        def change(legs):
            start = math.floor(legs[0]["started_epoch_s"])
            for sample, offset in zip(legs[0]["quiet"], (-120, -90)):
                sample["epoch_s"] = str(start + offset)
        self.edit_json("legs.json", change)
        with self.assertRaisesRegex(ValueError, "quiet sample outside leg"):
            recompute.main(self.root)

    def test_quiet_same_second_as_fractional_start(self):
        def change(legs):
            start = math.floor(legs[0]["started_epoch_s"])
            for sample, offset in zip(legs[0]["quiet"], (0, 30)):
                sample["epoch_s"] = str(start + offset)
        self.edit_json("legs.json", change)
        self.assertTrue(recompute.main(self.root)["timing_bars_pass"])

    def test_short_cooldown(self):
        self.edit_json("legs.json", lambda legs: legs[0].update(cooldown_observed_s=299))
        with self.assertRaisesRegex(ValueError, "shortened cooldown"):
            recompute.main(self.root)

    def test_actual_worst_cannot_be_hidden_by_median(self):
        def change(rows):
            worst_a = max(float(row["completion_max_s"]) for row in rows if row["arm"] == "A")
            next(row for row in rows if row["arm"] == "B")["completion_max_s"] = str(worst_a * 1.021)
        self.edit_rows(change)
        result = recompute.main(self.root)
        metric = result["endpoints"]["completion_max_s"]
        self.assertFalse(metric["within_2_percent"])
        self.assertTrue(metric["three_leg_median_within_2_percent"])
        self.assertFalse(result["timing_bars_pass"])

    def test_both_stall_gain_aggregates_are_required(self):
        path = self.root / "reloads-24.csv"
        original = path.read_text()
        for candidate, pooled_pass, process_pass in (
            ([[50, 50, 250, 250], [50, 50, 250, 250], [50, 50, 50, 50]], True, False),
            ([[50, 100, 100, 250], [50, 100, 100, 250], [250, 250, 250, 250]], False, True),
        ):
            path.write_text(original)
            def change(rows, candidate=candidate):
                for row in rows:
                    value = 200 if row["arm"] == "A" else candidate[
                        ["02-B", "03-B", "06-B"].index(row["leg"])][int(row["reload"]) - 1]
                    row.update(changed_maxgap_p50_ms=str(value), changed_maxgap_p95_ms="500",
                               changed_maxgap_max_ms="500")
            self.edit_rows(change)
            result = recompute.main(self.root)
            self.assertEqual(result["stall_p50_gain_ms"] >= 60, pooled_pass)
            self.assertEqual(result["three_leg_median_stall_p50_gain_ms"] >= 60, process_pass)
            self.assertFalse(result["timing_bars_pass"])


if __name__ == "__main__":
    unittest.main()
