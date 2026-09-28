#!/usr/bin/env python3
"""Mutation proofs for the benchmark driver inventory check."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("check_bench_inventory.py")
REPO = SCRIPT.parent.parent
SPEC = importlib.util.spec_from_file_location("check_bench_inventory", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)


def run(justfile_text: str) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "justfile"
        path.write_text(justfile_text, encoding="utf-8")
        return subprocess.run([sys.executable, str(SCRIPT), str(path)], check=False,
                              capture_output=True, text=True)


class BenchInventoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.justfile = (REPO / "justfile").read_text(encoding="utf-8")

    def test_current_justfile_passes(self) -> None:
        result = run(self.justfile)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_unlisted_driver_is_rejected(self) -> None:
        text = self.justfile.replace("      bench/scale/reloadstall/failover_cell.sh\n", "", 1)
        self.assertNotEqual(text, self.justfile)
        result = run(text)
        self.assertEqual(result.returncode, 1)
        self.assertIn("driver not in bench-list: bench/scale/reloadstall/failover_cell.sh", result.stdout)

    def test_listed_missing_file_is_rejected(self) -> None:
        text = self.justfile.replace("bench/run-fib-kernel-dump.py", "bench/run-fib-kernel-dumps.py", 1)
        result = run(text)
        self.assertEqual(result.returncode, 1)
        self.assertIn("bench-list names a missing file: bench/run-fib-kernel-dumps.py", result.stdout)
        self.assertIn("driver not in bench-list: bench/run-fib-kernel-dump.py", result.stdout)

    def test_path_outside_bench_list_does_not_count(self) -> None:
        # A path named only in another recipe's comment is not in the listing.
        text = self.justfile.replace("      bench/scale/reloadstall/failover_cell.sh\n", "", 1)
        text += "\n# bench/scale/reloadstall/failover_cell.sh\n"
        self.assertEqual(run(text).returncode, 1)

    def test_driver_patterns(self) -> None:
        for path, is_driver in (("bench/scale/x/run-receipt.sh", True), ("bench/compare-a.sh", True),
                                ("bench/scale/reloadstall/policy_stats_cell.sh", True),
                                ("bench/scale/reloadstall/policy_stats_cell.py", False),
                                ("bench/scale/host-quiet.sh", False), ("bench/verify-x.py", False)):
            with self.subTest(path=path):
                self.assertEqual(bool(checker.DRIVER.search(path)), is_driver)


if __name__ == "__main__":
    unittest.main()
