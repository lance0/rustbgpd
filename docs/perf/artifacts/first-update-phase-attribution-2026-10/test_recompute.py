#!/usr/bin/env python3
"""Small invalid-artifact checks for the compact receipt reader."""
import csv
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import recompute


class ArtifactValidation(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        for name in ["rounds.csv", "arrivals.csv", "legs.json", "provenance.json"]:
            shutil.copyfile(Path(__file__).parent / name, self.root / name)

    def edit_csv(self, name, edit):
        path = self.root / name
        with path.open() as file:
            rows = list(csv.DictReader(file))
        fields = list(rows[0])
        edit(rows)
        with path.open("w") as file:
            writer = csv.DictWriter(file, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)

    def test_valid_receipt(self):
        result = recompute.main(self.root)
        self.assertEqual(result["endpoints_ms"]["first_reann_s_p50"]["control"]["median"], 133.376)
        self.assertEqual(result["matching_marker_signed_spans_us"]["rib_admit_to_ingest"]["n"], 6)

    def test_duplicate_observer_hides_missing_observer(self):
        self.edit_csv("arrivals.csv", lambda rows: rows.__setitem__(-1, rows[0].copy()))
        with self.assertRaisesRegex(ValueError, "5850 unique survivor-rounds"):
            recompute.main(self.root)

    def test_duplicate_round_hides_missing_round(self):
        self.edit_csv("rounds.csv", lambda rows: rows.__setitem__(-1, rows[0].copy()))
        with self.assertRaisesRegex(ValueError, "18 unique rounds"):
            recompute.main(self.root)

    def test_marker_outside_writer_bracket(self):
        def change(rows):
            row = next(row for row in rows if row["mode"] == "instrumented")
            row["marker_byte_end"] = str(int(row["writer_byte_end"]) + 1)
        self.edit_csv("rounds.csv", change)
        with self.assertRaisesRegex(ValueError, "marker outside writer byte bracket"):
            recompute.main(self.root)

    def test_nonfinite_endpoint(self):
        self.edit_csv("rounds.csv", lambda rows: rows[0].update(first_reann_s_p50="nan"))
        with self.assertRaisesRegex(ValueError, "invalid endpoint quantiles"):
            recompute.main(self.root)

    def test_shortened_cooldown(self):
        path = self.root / "legs.json"
        legs = json.loads(path.read_text())
        legs[0]["cooldown_observed_s"] = 299
        path.write_text(json.dumps(legs))
        with self.assertRaisesRegex(ValueError, "shortened cooldown"):
            recompute.main(self.root)

    def test_missing_native_check(self):
        path = self.root / "legs.json"
        original = path.read_text()
        for field in ["exits", "http"]:
            with self.subTest(field=field):
                legs = json.loads(original)
                legs[0][field].pop("health-after")
                path.write_text(json.dumps(legs))
                with self.assertRaisesRegex(ValueError, "native check keys"):
                    recompute.main(self.root)

    def test_wrong_workload(self):
        path = self.root / "legs.json"
        legs = json.loads(path.read_text())
        legs[0]["workload"]["FLAPSTORM"] = "49"
        path.write_text(json.dumps(legs))
        with self.assertRaisesRegex(ValueError, "noncanonical workload"):
            recompute.main(self.root)

    def test_wrong_binary_or_harness_hash(self):
        path = self.root / "legs.json"
        original = path.read_text()
        for field in ["binary_sha256", "harness_sha256"]:
            with self.subTest(field=field):
                legs = json.loads(original)
                legs[0][field] = "0" * 64
                path.write_text(json.dumps(legs))
                with self.assertRaisesRegex(ValueError, "hash mismatch"):
                    recompute.main(self.root)


if __name__ == "__main__":
    unittest.main()
