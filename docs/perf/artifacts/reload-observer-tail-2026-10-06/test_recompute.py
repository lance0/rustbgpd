"""Regression cases for malformed compact evidence, using the frozen good receipt."""
import csv
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import recompute


class ReceiptTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for path in recompute.ROOT.iterdir():
            if path.is_file():
                shutil.copyfile(path, self.root / path.name)

    def rehash(self):
        # Semantic negative cases must pass the byte-integrity gate first.
        (self.root / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n"
            for p in sorted(self.root.iterdir()) if p.is_file() and p.name != "SHA256SUMS"))

    def test_complete_receipt(self):
        result = recompute.recompute(self.root)
        self.assertEqual(result["probe"]["top35_union"], 119)
        self.assertEqual(result["probe"]["rounds"][0]["gap_ends_first_generation"], 700)

    def test_bad_hash(self):
        with (self.root / "observers-probe.csv").open("a") as stream:
            stream.write("\n")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            recompute.recompute(self.root)

    def test_missing_native_generation(self):
        path = self.root / "native-control.log"
        lines = path.read_text().splitlines()
        lines.remove(next(x for x in lines if x.startswith("scout_generation,")))
        path.write_text("\n".join(lines)+"\n")
        self.rehash()
        with self.assertRaisesRegex(ValueError, "missing native observer map"):
            recompute.recompute(self.root)

    def test_wrong_native_workload(self):
        path = self.root / "native-probe.log"
        path.write_text(path.read_text().replace(
            "reloadstall_csv,1,700,700,0,400400,", "reloadstall_csv,1,700,700,0,400000,"))
        self.rehash()
        with self.assertRaisesRegex(ValueError, "wrong native workload"):
            recompute.recompute(self.root)

    def test_rehashed_provenance_workload(self):
        path = self.root / "provenance.json"
        value = json.loads(path.read_text())
        value["workload"]["CONTROL_SECS"] = "3"
        path.write_text(json.dumps(value))
        self.rehash()
        with self.assertRaisesRegex(ValueError, "wrong provenance workload"):
            recompute.recompute(self.root)

    def test_rehashed_binary_identity(self):
        path = self.root / "provenance.json"
        value = json.loads(path.read_text())
        value["binaries"]["control"] = value["binaries"]["probe"]
        path.write_text(json.dumps(value))
        self.rehash()
        with self.assertRaisesRegex(ValueError, "wrong source or binary identity"):
            recompute.recompute(self.root)

    def test_rehashed_raw_identity(self):
        path = self.root / "archived-raw-sha256.json"
        value = json.loads(path.read_text())
        value["control/pre-freeze.json"] = "0"*64
        path.write_text(json.dumps(value))
        self.rehash()
        with self.assertRaisesRegex(ValueError, "wrong archived raw hashes"):
            recompute.recompute(self.root)

    def test_rehashed_empty_identity_maps(self):
        for name in ("legs.json", "native-provenance.json", "freezes.json", "builds.json"):
            with self.subTest(name=name):
                path = self.root / name
                original = path.read_text()
                path.write_text("{}")
                self.rehash()
                with self.assertRaisesRegex(ValueError, "missing .*map"):
                    recompute.recompute(self.root)
                path.write_text(original)

    def test_rehashed_arm_freeze_swap(self):
        path = self.root / "freezes.json"
        value = json.loads(path.read_text())
        for phase in ("pre", "post"):
            value["control"][phase]["installed_binary"] = recompute.BINARIES["probe"]
            value["control"][phase]["archived_binary"] = recompute.BINARIES["probe"]
        path.write_text(json.dumps(value))
        self.rehash()
        with self.assertRaisesRegex(ValueError, "wrong arm freeze binary binding"):
            recompute.recompute(self.root)

    def test_rehashed_missing_native_file(self):
        (self.root / "native-provenance.json").unlink()
        self.rehash()
        with self.assertRaises(FileNotFoundError):
            recompute.recompute(self.root)

    def test_missing_consumer_stage(self):
        path = self.root / "coverage-probe.json"
        value = json.loads(path.read_text())
        value[0]["consumer_events"] = 699
        path.write_text(json.dumps(value))
        self.rehash()
        with self.assertRaisesRegex(ValueError, "incomplete or duplicate stage coverage"):
            recompute.recompute(self.root)

    def test_neighbor_writer_interval_does_not_match(self):
        path = self.root / "matched-writers.csv"
        with path.open() as stream:
            rows = list(csv.DictReader(stream))
        # A preceding batch that ends exactly at the first admitted byte is not its writer.
        with (self.root / "observers-probe.csv").open() as stream:
            admitted = int(next(csv.DictReader(stream))["admitted_before"])
        rows[0]["bulk_before"] = str(admitted-int(rows[0]["bytes"]))
        with path.open("w") as stream:
            writer = csv.DictWriter(stream, fieldnames=rows[0].keys())
            writer.writeheader()
            writer.writerows(rows)
        self.rehash()
        with self.assertRaisesRegex(ValueError, "first chunk outside FIFO writer interval"):
            recompute.recompute(self.root)


if __name__ == "__main__":
    unittest.main()
