"""Seed bad receiver data and lost instruments into otherwise valid restart receipts."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import credit_bars


class LabeledRestart(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / "restart-labeled6.json"
        receiver = {
            "peer": "192.0.2.1", "exact": True, "exact_at_eor": True,
            "missing": 0, "outside": 0, "decode_failures": 0, "resets": 0,
            "routes_after_eor": 0, "eors": 1, "announced": 128, "withdrawals": 1,
            "labeled_announced": 128, "labeled_withdrawn": 1, "routes_before_eor": 128,
            "post_eor_sentinel_changes": 1,
            "eor_ms": 17.5,
        }
        self.run_data = {
            "cell": "restart", "family": "labeled6", "mode": "correctness",
            "shape": {"receivers": 2, "rows_per_receiver": 128, "registered_peers": 6,
                      "trigger": credit_bars.RELEASE_TRIGGER},
            "checks": dict.fromkeys(
                (*credit_bars.RESTART_WIRE_CHECKS, "selection_held", "selection_released",
                 "owed_at_release", "post_release_withdrawal", "physical_poll_observed",
                 "release_update_delivered", "source_restart", "labeled_payload_counted", "memory_fenced"), True
            ),
            "source": {"old_session": 1, "new_session": 2, "old_rows": 128, "retained_rows": 128,
                       "replayed_rows": 128, "retained_sample_stale": True,
                       "peer": "127.254.0.1", "release_helper": "127.254.0.3", "restart_state": True,
                       "old_sample_stale": False, "replayed_sample_stale": False},
            "witness": {"active_before_release": 1, "waiters_before_release": 1, "all_eor_releases": 1,
                        "owing_flip_delta_while_paused": 2},
            "receivers": [receiver, dict(receiver, peer="192.0.2.2", eor_ms=22.25)],
            "actor": {"poll_count": 2, "slice_max_us": {"actor_poll": 1500.0},
                      "from_ms": 0.0, "to_ms": 23.0},
            "unaffected": {
                "peer": "127.254.0.2",
                "release_update_sequence": 1, "release_update_wait_ms": 3.125,
                "release_update_admitted_ms": 2.5, "release_update_winner_ms": 5.625,
                "release_update_received_ms": 6.5, "release_update_wire_ms": 4.0,
            },
            "timing": {"release_sent_ms": 2.0, "resume_issued_ms": 10.0,
                       "last_eor_ms": 22.25, "release_to_last_eor_ms": 20.25},
            "memory": {
                "cgroup": "/sys/fs/cgroup/test.scope", "cgroup_swap_max": "0", "cgroup_oom_kill": "0",
                "cgroup_memory_peak_bytes": 2048000,
            },
        }
        self.original = json.dumps(self.run_data).encode()
        self.path.write_bytes(self.original)

    def grade(self):
        (line,) = credit_bars.check(self.root)
        return line[1:]

    def test_readings_and_receivers(self):
        verdict, detail = self.grade()
        self.assertEqual(verdict, "PASS", detail)
        for expected in ("2 exact receivers", "1.500 ms", "3.125 ms", "20.250 ms", "2048000 bytes"):
            self.assertIn(expected, detail)

    def test_seeded_receipt_defects(self):
        # Keep the emitting check booleans true. The receiver counters and
        # clocks must catch the defect independently, including on a sibling.
        cases = (
            ("receivers.1.outside", 1, "FAIL", "outside"),
            ("receivers.0.eors", 0, "FAIL", "one labeled EoR"),
            ("receivers.0.post_eor_sentinel_changes", 0, "FAIL", "sentinel withdrawal"),
            ("receivers.1.routes_before_eor", 127, "FAIL", "announcement count"),
            ("receivers.0.labeled_announced", 0, "INVALID", "payload counters"),
            ("receivers.1.labeled_withdrawn", 0, "INVALID", "payload counters"),
            ("receivers.1.peer", "192.0.2.1", "INVALID", "duplicate receiver"),
            ("actor.slice_max_us.actor_poll", None, "INVALID", "actor_poll"),
            ("actor.poll_count", 0, "INVALID", "poll_count"),
            ("actor.to_ms", 20.0, "INVALID", "physical poll window"),
            ("unaffected.release_update_sequence", 2, "INVALID", "sequence"),
            ("unaffected.peer", "127.254.0.3", "INVALID", "release participant"),
            ("unaffected.release_update_wait_ms", None, "INVALID", "release_update_wait_ms"),
            ("unaffected.release_update_received_ms", 6, "INVALID", "release-window stamps"),
            ("timing.release_to_last_eor_ms", 12, "INVALID", "release to last EoR"),
            ("timing.last_eor_ms", 17.5, "INVALID", "last receiver"),
            ("memory.cgroup_memory_peak_bytes", 0, "INVALID", "peak"),
            ("memory.cgroup_swap_max", "max", "INVALID", "swap-fenced"),
            ("memory.cgroup_oom_kill", "1", "INVALID", "swap-fenced"),
            ("checks.owed_at_release", False, "INVALID", "owed_at_release"),
            ("witness.owing_flip_delta_while_paused", 1, "INVALID", "paused receiver debt"),
            ("source.retained_rows", 0, "INVALID", "source restart"),
            ("source.restart_state", False, "INVALID", "source restart"),
            ("source.replayed_sample_stale", True, "INVALID", "source restart"),
        )
        for field, value, expected, reason in cases:
            with self.subTest(field=field):
                bad = copy.deepcopy(self.run_data)
                *parents, key = field.split(".")
                obj = bad
                for parent in parents:
                    obj = obj[int(parent)] if isinstance(obj, list) else obj[parent]
                obj[key] = value
                self.path.write_text(json.dumps(bad))
                verdict, detail = self.grade()
                self.assertEqual(verdict, expected, detail)
                self.assertIn(reason, detail)
                self.path.write_bytes(self.original)
                self.assertEqual(self.path.read_bytes(), self.original)
                self.assertEqual(self.grade()[0], "PASS")

    def test_exit_without_receipt_and_unexplained_exit(self):
        (self.root / "restart-labeled6-exit.json").write_text('{"exit": 1}')
        self.assertEqual(self.grade()[0], "INVALID")
        self.path.unlink()
        verdict, detail = self.grade()
        self.assertEqual(verdict, "INVALID")
        self.assertIn("without a result", detail)

    def test_measured_cell_needs_quiet_full_shape(self):
        self.run_data.update(mode="measured", shape={**credit_bars.RELEASE_SHAPE, "registered_peers": 154})
        self.run_data["host"] = {"compiler_watch": {"samples": 100, "observed": 1, "first": "rustc"}}
        self.path.write_text(json.dumps(self.run_data))
        verdict, detail = self.grade()
        self.assertEqual(verdict, "INVALID")
        self.assertIn("compiler observed", detail)

    def test_interrupted_attempt_listed_alongside_success_is_invalid(self):
        (self.root / "provenance.jsonl").write_text(json.dumps({
            "sha256": "binary", "cells": ["restart-labeled4", "restart-labeled6"],
        }))
        lines = credit_bars.check(self.root)
        self.assertEqual([line[1] for line in lines], ["INVALID", "PASS"])
        self.assertIn("attempted, no result", lines[0][2])


if __name__ == "__main__":
    unittest.main()
