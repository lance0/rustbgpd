#!/usr/bin/env python3
"""Allocation invariants of the flapstorm failover overlap emitter."""
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location(
    "gen_failover_overlap", Path(__file__).with_name("gen-failover-overlap.py"))
gen = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gen)


class AllocationTests(unittest.TestCase):
    def test_fraction_sources_and_survivor_only_alternates(self):
        rows = gen.allocation(700, 400400, 50, 75, 16)
        per_peer = 572
        self.assertEqual(len(rows), 50 * (per_peer * 75 // 100))
        indices = [index for _, index in rows]
        self.assertEqual(len(indices), len(set(indices)), "one alternate per prefix")
        for flapper in range(50):
            members = {m for m, i in rows if i // per_peer == flapper}
            self.assertEqual(len(members), 16, f"flapper {flapper} has 16 new winners")
            covered = sorted(i for _, i in rows if i // per_peer == flapper)
            self.assertEqual(covered, list(range(flapper * per_peer, flapper * per_peer + 429)))
        for member, index in rows:
            self.assertTrue(50 <= member < 700 - gen.CHURNERS, "alternates are non-churning survivors")
            self.assertNotEqual(member, index // per_peer, "never the member's own slice")

    def test_single_source_and_rejections(self):
        rows = gen.allocation(700, 400400, 50, 25, 1)
        for flapper in range(50):
            self.assertEqual(len({m for m, i in rows if i // 572 == flapper}), 1)
        with self.assertRaises(ValueError):
            gen.allocation(700, 400401, 50, 25, 1)
        with self.assertRaises(ValueError):
            gen.allocation(700, 400400, 50, 25, 700)


if __name__ == "__main__":
    unittest.main()
