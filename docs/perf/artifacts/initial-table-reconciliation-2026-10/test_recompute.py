#!/usr/bin/env python3
"""Check the receipt reader against plausible invalid or nonqualifying inputs."""
import csv
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import recompute

ROOT = Path(__file__).parent


class ReceiptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ["rounds.csv", "catchup.csv", "survivors.csv", "legs.json", "provenance.json", "common-qualification.patch"]:
            shutil.copyfile(ROOT / name, self.root / name)

    def change_csv(self, name, change):
        rows = recompute.read_csv(self.root, name)
        change(rows)
        with (self.root / name).open("w") as file:
            writer = csv.DictWriter(file, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)

    def test_valid_recomputes_exact_original_comparison(self):
        self.assertEqual(recompute.main(self.root), json.loads((ROOT / "comparison.json").read_text()))

    def test_duplicate_survivor_cannot_replace_missing_identity(self):
        self.change_csv("survivors.csv", lambda rows: rows.__setitem__(1, rows[0].copy()))
        with self.assertRaisesRegex(ValueError, "peer-round coverage"):
            recompute.main(self.root)

    def test_current_table_loss_after_latched_completion_fails(self):
        self.change_csv("catchup.csv", lambda rows: rows[0].update(current_full_us=str(int(rows[0]["complete_us"]) + 1)))
        with self.assertRaisesRegex(ValueError, "EoR/current-full ordering"):
            recompute.main(self.root)

    def test_missing_eor_fails(self):
        self.change_csv("catchup.csv", lambda rows: rows[0].update(eor_us="0"))
        with self.assertRaisesRegex(ValueError, "EoR/current-full ordering"):
            recompute.main(self.root)

    def test_first_arrival_quantile_must_match_observations(self):
        self.change_csv("rounds.csv", lambda rows: rows[0].update(first_reann_s_p50="0.001000"))
        with self.assertRaisesRegex(ValueError, "quantile mismatch"):
            recompute.main(self.root)

    def test_nonfinite_endpoint_fails(self):
        self.change_csv("rounds.csv", lambda rows: rows[0].update(withdraw_s_p50="nan"))
        with self.assertRaisesRegex(ValueError, "invalid endpoint"):
            recompute.main(self.root)

    def test_native_receipt_defects_fail(self):
        original = json.loads((ROOT / "legs.json").read_text())
        mutations = [
            lambda leg: leg["exits"].pop("cleanup"),
            lambda leg: leg["workload"].update(FLAPSTORM="1"),
            lambda leg: leg.update(binary_sha256="0" * 64),
            lambda leg: leg["readiness"][0].update(failures=1),
            lambda leg: leg["stage_ns"].__setitem__(8, leg["stage_ns"][7] + 299_000_000_000),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                legs = json.loads(json.dumps(original))
                mutate(legs[0])
                (self.root / "legs.json").write_text(json.dumps(legs))
                with self.assertRaises(ValueError):
                    recompute.main(self.root)

    def test_frozen_inclusive_bars_and_failed_payoff(self):
        rows = []
        for leg in recompute.LEGS:
            arm = leg.split("-", 1)[1]
            for round_ in range(1, 4):
                values = {"first_reann_s": .18 if arm == "candidate" else .20,
                          "withdraw_s": .103 if arm == "candidate" else .10,
                          "reannounce_s": .103 if arm == "candidate" else .10,
                          "rejoin_complete_s": 1.0}
                rows.append({"leg": leg, "mode": arm, "round": round_,
                             **{m + "_" + q: v for m, v in values.items() for q in ["p50", "p95", "max"]}})
        self.assertEqual(recompute.summarize(rows)["verdict"], "qualifies")
        for row in rows:
            if row["mode"] == "candidate":
                row["first_reann_s_p50"] = .180001
        result = recompute.summarize(rows)
        self.assertEqual(result["verdict"], "hold")
        self.assertFalse(result["acceptance"]["first_20ms"])
        self.assertFalse(result["acceptance"]["first_10pct"])

    def test_each_returning_bar_rejects_a_positive_microsecond(self):
        for quantile, bar in [("p50", "returning_p50_not_slower"), ("max", "returning_max_not_slower")]:
            with self.subTest(bar=bar):
                rows = recompute.read_csv(self.root, "rounds.csv")
                for row in rows:
                    for metric in recompute.METRICS:
                        for q in ["p50", "p95", "max"]:
                            row[metric + "_" + q] = float(row[metric + "_" + q])
                    row["rejoin_complete_s_" + quantile] = 1.000001 if row["mode"] == "candidate" else 1.0
                result = recompute.summarize(rows)
                self.assertEqual(result["verdict"], "hold")
                self.assertFalse(result["acceptance"][bar])


if __name__ == "__main__":
    unittest.main()
