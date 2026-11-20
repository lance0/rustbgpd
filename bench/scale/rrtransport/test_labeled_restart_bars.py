"""Seed bad receiver data and lost instruments into otherwise valid restart receipts."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import credit_bars


class LabeledRestart(unittest.TestCase):
    family = "labeled"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path = self.root / f"restart-{self.family}6.json"
        receiver = {
            "peer": "192.0.2.1", "exact": True, "exact_at_eor": True,
            "missing": 0, "outside": 0, "decode_failures": 0, "resets": 0,
            "routes_after_eor": 0, "eors": 1, "announced": 128, "withdrawals": 1,
            f"{self.family}_announced": 128, f"{self.family}_withdrawn": 1, "routes_before_eor": 128,
            "post_eor_sentinel_changes": 1,
            "eor_ms": 17.5, "max_observed_stub_backlog_messages": 90,
        }
        self.run_data = {
            "cell": "restart", "family": f"{self.family}6", "mode": "correctness",
            "shape": {"receivers": 2, "rows_per_receiver": 128, "registered_peers": 6,
                      "trigger": credit_bars.RELEASE_TRIGGER, "chunk_rows": 1024,
                      "stub_backlog_capacity_messages": 65536, "pause_ms": 8},
            "checks": dict.fromkeys(
                (*credit_bars.RESTART_WIRE_CHECKS, "selection_held", "selection_released",
                 "owed_at_release", "post_release_withdrawal", "physical_poll_observed",
                 "release_update_delivered", "source_restart", f"{self.family}_payload_counted", "memory_fenced"), True
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
                       "last_eor_ms": 22.25, "release_to_last_eor_ms": 20.25,
                       "resume_to_last_eor_ms": 12.25},
            "memory": {
                "cgroup": "/sys/fs/cgroup/test.scope", "cgroup_swap_max": "0", "cgroup_oom_kill": "0",
                "cgroup_memory_peak_bytes": 2048000,
            },
        }
        if self.family == "vpn":
            self.run_data["checks"]["no_rtc"] = True
            self.run_data["shape"].update(
                rtc_negotiated=False, route_target="64512:100", export_policy="permit matching RT, default deny"
            )
            for peer in self.run_data["receivers"]:
                peer["withdrawal_rd_sibling_present"] = True
        self.set_steps(self.run_data, "whole", 2)
        self.original = json.dumps(self.run_data).encode()
        self.path.write_bytes(self.original)

    def grade(self):
        (line,) = credit_bars.check(self.root)
        return line[1:]

    @staticmethod
    def set_steps(run, scope, count, paused=None):
        for window, n in (("while_paused", count if paused is None else paused), ("to_last_eor", count)):
            steps = {label: {"observations": 0, "above_ms": None, "at_most_ms": None}
                     for label in credit_bars.STEP_SCOPES}
            steps[scope] = {"observations": n, "above_ms": 1, "at_most_ms": 5}
            run["witness"]["owed_steps_" + window] = steps

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
            ("receivers.0.eors", 0, "FAIL", f"one {self.family} EoR"),
            ("receivers.0.post_eor_sentinel_changes", 0, "FAIL", "sentinel withdrawal"),
            ("receivers.1.routes_before_eor", 127, "FAIL", "announcement count"),
            (f"receivers.0.{self.family}_announced", 0, "INVALID", "payload counters"),
            (f"receivers.1.{self.family}_withdrawn", 0, "INVALID", "payload counters"),
            ("receivers.1.peer", "192.0.2.1", "INVALID", "duplicate receiver"),
            ("actor.slice_max_us.actor_poll", None, "INVALID", "actor_poll"),
            ("actor.poll_count", 0, "INVALID", "poll_count"),
            ("actor.to_ms", 20.0, "INVALID", "physical poll window"),
            ("unaffected.release_update_sequence", 2, "INVALID", "sequence"),
            ("unaffected.peer", "127.254.0.3", "INVALID", "release participant"),
            ("unaffected.release_update_wait_ms", None, "INVALID", "release_update_wait_ms"),
            ("unaffected.release_update_received_ms", 6, "INVALID", "release-window stamps"),
            ("timing.release_to_last_eor_ms", 12, "INVALID", "release to last EoR"),
            ("timing.resume_to_last_eor_ms", 12, "INVALID", "resume to last EoR"),
            ("timing.last_eor_ms", 17.5, "INVALID", "last receiver"),
            ("memory.cgroup_memory_peak_bytes", 0, "INVALID", "peak"),
            ("memory.cgroup_swap_max", "max", "INVALID", "swap-fenced"),
            ("memory.cgroup_oom_kill", "1", "INVALID", "swap-fenced"),
            ("checks.owed_at_release", False, "INVALID", "owed_at_release"),
            ("witness.owing_flip_delta_while_paused", 1, "INVALID", "paused receiver debt"),
            ("source.retained_rows", 0, "INVALID", "source restart"),
            ("source.restart_state", False, "INVALID", "source restart"),
            ("source.replayed_sample_stale", True, "INVALID", "source restart"),
            ("witness.owed_steps_to_last_eor.whole.at_most_ms", -1, "INVALID", "upper bucket"),
            ("receivers.0.max_observed_stub_backlog_messages", 65537, "INVALID", "backlog"),
        )
        if self.family == "vpn":
            cases += (
                ("family", "vpn4", "INVALID", "different cell"),
                ("shape.rtc_negotiated", True, "INVALID", "RTC"),
                ("checks.no_rtc", False, "INVALID", "no_rtc"),
                ("shape.export_policy", "permit all", "INVALID", "export policy"),
                ("shape.route_target", "64512:101", "INVALID", "route target"),
                ("shape.rows_per_receiver", 0, "INVALID", "rows_per_receiver"),
                ("shape.rows_per_receiver", 1, "INVALID", "two RDs"),
                ("receivers.0.withdrawal_rd_sibling_present", False, "FAIL", "other RD"),
                ("receivers.0.peer", self.run_data["source"]["peer"], "INVALID", "receiver also named"),
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
        (self.root / f"restart-{self.family}6-exit.json").write_text('{"exit": 1}')
        self.assertEqual(self.grade()[0], "INVALID")
        self.path.unlink()
        verdict, detail = self.grade()
        self.assertEqual(verdict, "INVALID")
        self.assertIn("without a result", detail)

    def test_measured_cell_needs_quiet_full_shape(self):
        self.run_data.update(mode="measured", shape=credit_bars.MPLS_RELEASE_SHAPE)
        self.run_data["host"] = {"compiler_watch": {"samples": 100, "observed": 1, "first": "rustc"}}
        self.path.write_text(json.dumps(self.run_data))
        verdict, detail = self.grade()
        self.assertEqual(verdict, "INVALID")
        self.assertIn("compiler observed", detail)

    def test_interrupted_attempt_listed_alongside_success_is_invalid(self):
        (self.root / "provenance.jsonl").write_text(json.dumps({
            "sha256": "binary", "cells": credit_bars.RESTART_CELLS[self.family],
        }))
        lines = credit_bars.check(self.root)
        self.assertEqual([line[1] for line in lines], ["INVALID", "PASS"])
        self.assertIn("attempted, no result", lines[0][2])

    def measured_arm(self, name, scope):
        directory = self.root / name
        directory.mkdir()
        (directory / "provenance.jsonl").write_text(json.dumps({
            "sha256": ("a" if name == "parent" else "b") * 64,
            "cells": list(credit_bars.RESTART_CELLS[self.family]), "measured": 1,
        }))
        for cell in credit_bars.RESTART_CELLS[self.family]:
            run = copy.deepcopy(self.run_data)
            run.update(family=cell.split("-")[1], mode="measured")
            run["shape"].update(credit_bars.MPLS_RELEASE_SHAPE)
            run["source"].update(old_rows=150000, replayed_rows=150000, retained_rows=150000)
            run["witness"]["owing_flip_delta_while_paused"] = 150
            peer = run["receivers"][0]
            peer.update(announced=150000, routes_before_eor=150000, eor_ms=90022.25)
            peer[f"{self.family}_announced"] = 150000
            run["receivers"] = [dict(peer, peer=f"192.0.2.{i}") for i in range(1, 151)]
            run["timing"].update(resume_issued_ms=90010.0, last_eor_ms=90022.25, release_to_last_eor_ms=90020.25)
            run["actor"]["to_ms"] += 90000.0
            run["host"] = {"compiler_watch": {"samples": 100, "observed": 0}}
            self.set_steps(run, scope, 150 if scope == "whole" else 22050, 100)
            if scope == "cursor":
                run["actor"]["slice_max_us"]["actor_poll"] *= 0.5
                run["unaffected"]["release_update_wait_ms"] *= 2
                run["unaffected"]["release_update_winner_ms"] = 8.75
                run["memory"]["cgroup_memory_peak_bytes"] *= 3
            (directory / f"{cell}.json").write_text(json.dumps(run))
        return directory

    def test_compare_requires_matched_cells_and_the_expected_binary_and_drain(self):
        parent = self.measured_arm("parent", "whole")
        candidate = self.measured_arm("candidate", "cursor")
        lines = credit_bars.compare_restart_family(parent, candidate, self.family)
        self.assertEqual([v for _, v, _ in lines].count("PASS"), 4, lines)
        ratios = {key: detail for key, verdict, detail in lines if verdict == "REPORT"}
        self.assertEqual(len(ratios), 10)
        for title, ratio in (("longest RIB poll", "0.5000"), ("release-turn UPDATE", "2.0000"),
                             ("whole-process cgroup", "3.0000"), ("resume → last EoR", "1.0000")):
            matches = [row for key, row in ratios.items() if title in key]
            self.assertEqual(len(matches), 2)
            self.assertTrue(all(f"candidate/parent {ratio}" in row for row in matches))
        self.assertTrue(all(v == "INVALID" for _, v, _ in credit_bars.compare_restart_family(candidate, parent, self.family)))
        self.assertEqual(credit_bars.compare_restart_family(parent, parent, self.family)[0][1], "INVALID")
        self.assertTrue(all(row[1] == "INVALID" for row in credit_bars.check_restart_family(candidate, "whole", self.family)))
        self.assertTrue(all(row[1] == "PASS" for row in credit_bars.check_restart_family(candidate, "cursor", self.family)))

        result = candidate / f"restart-{self.family}6.json"
        raw = result.read_bytes()
        for key, scope, value in (
            ("owed_steps_to_last_eor", "whole", {"observations": 1, "above_ms": 1, "at_most_ms": 5}),
            ("owed_steps_to_last_eor", "cursor", {"observations": 22049, "above_ms": 1, "at_most_ms": 5}),
            ("owed_steps_while_paused", "cursor", {"observations": 22051, "above_ms": 1, "at_most_ms": 5}),
            ("owed_steps_while_paused", "whole", None),
        ):
            with self.subTest(key=key, scope=scope, value=value):
                run = json.loads(raw)
                if value is None:
                    del run["witness"][key][scope]
                else:
                    run["witness"][key][scope] = value
                result.write_text(json.dumps(run))
                lines = credit_bars.compare_restart_family(parent, candidate, self.family)
                self.assertTrue(any(v == "INVALID" and f"{self.family}6" in n for n, v, _ in lines))
                self.assertFalse(any(v == "REPORT" and f"{self.family}6" in n for n, v, _ in lines))
        result.write_bytes(raw)
        run = json.loads(raw)
        run["shape"]["pause_ms"] = 30000
        result.write_text(json.dumps(run))
        self.assertTrue(any(v == "INVALID" and "pause_ms" in detail for _, v, detail in
                            credit_bars.compare_restart_family(parent, candidate, self.family)))
        result.unlink()
        self.assertTrue(any(v == "INVALID" and "attempted, no result" in detail for _, v, detail in
                            credit_bars.compare_restart_family(parent, candidate, self.family)))


class VpnRestart(LabeledRestart):
    family = "vpn"


if __name__ == "__main__":
    unittest.main()
