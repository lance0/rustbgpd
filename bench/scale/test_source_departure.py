"""Runner controls. No cgroup privileges, systemd, or Rust process required."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import source_departure as runner


class SourceDepartureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.spec = {"mode": "private-unicast", "rows": 1024, "receivers": 8, "arm": "candidate"}
        self.row = {
            **self.spec,
            "departure_queued_ns": 3,
            "update_queued_ns": 5,
            "detach_started_ns": 8,
            "selection_finished_ns": 12,
            "loc_rib_applied_ns": 16,
            "rib_last_withdrawal_ns": 20,
            "rib_withdrawal_rows": 8192,
            "update_to_applied_ns": 11,
            "max_rib_poll_ns": 6,
            "max_withdrawals_per_poll": 128,
            "convergence_ns": 21,
            "receiver_last_withdrawal_ns": 24,
            "receiver_last_probe_ns": 20,
            "source_detach_selection_ns": 4,
            "exact": True,
            "post_departure_recovery": {
                "commit_refusals": 0,
                "route_drops": 0,
                "dirty_resync_ticks": 0,
                "owing_fallbacks": 0,
                "owing_flips": 0,
                "owed_drain_steps": 0,
                "commit_refusals_by_reason": {},
            },
            "update_applied_before_departure_complete": True,
        }

    def test_parent_and_candidate_must_show_opposite_publication_orders(self):
        self.assertEqual(runner.witness(self.row, self.spec)[0], "PASS")
        late = {
            **self.row,
            "rib_last_withdrawal_ns": 14,
            "update_applied_before_departure_complete": False,
        }
        self.assertEqual(runner.witness(late, dict(self.spec, arm="parent"))[0], "PASS")
        self.assertEqual(runner.witness(late, self.spec)[0], "FAIL")
        self.assertEqual(runner.witness(self.row, dict(self.spec, arm="parent"))[0], "FAIL")

    def test_receiver_can_decode_while_actor_is_preempted_after_its_send(self):
        received_early = dict(self.row, receiver_last_withdrawal_ns=19, receiver_last_probe_ns=24)
        self.assertEqual(runner.witness(received_early, self.spec)[0], "PASS")

    def test_probe_receipt_and_durations_must_match_their_causal_boundaries(self):
        for mutation in (
            {"receiver_last_probe_ns": 15},  # Before the sentinel was selected.
            {"convergence_ns": 20},  # 24 - 3 = 21.
            {"source_detach_selection_ns": 5},  # 12 - 8 = 4.
            {"departure_queued_ns": 6, "convergence_ns": 18},  # UPDATE queued first.
            {"detach_started_ns": 4, "source_detach_selection_ns": 8},
            {"selection_finished_ns": 17, "source_detach_selection_ns": 9},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(runner.InvalidReceipt):
                runner.witness({**self.row, **mutation}, self.spec)

    def test_missing_or_forged_witness_is_invalid_even_if_receiver_completed(self):
        for mutation in (
            {"loc_rib_applied_ns": None},
            {"update_applied_before_departure_complete": False},
            {"rib_last_withdrawal_ns": 16},
            {"update_to_applied_ns": 0},
            {"receivers": 7},
            {"source_detach_selection_ns": 0},
            {"max_withdrawals_per_poll": None},
        ):
            with self.subTest(mutation=mutation), self.assertRaises(runner.InvalidReceipt):
                runner.witness({**self.row, **mutation}, self.spec)

    def test_post_departure_credit_is_report_only_with_exact_convergence(self):
        diag = {
            **self.row["post_departure_recovery"],
            "commit_refusals": 2,
            "owed_drain_steps": 3,
            "commit_refusals_by_reason": {"credit": 2},
        }
        row = {**self.row, "post_departure_recovery": diag}
        self.assertEqual(runner.witness(row, self.spec)[0], "PASS")
        self.assertEqual(runner.witness({**row, "exact": False}, self.spec)[0], "FAIL")
        for malformed in (
            None,
            {**diag, "owed_drain_steps": -1},
            {**diag, "commit_refusals_by_reason": {"credit": "2"}},
        ):
            with self.subTest(malformed=malformed), self.assertRaises(runner.InvalidReceipt):
                runner.witness({**row, "post_departure_recovery": malformed}, self.spec)

    def test_driver_behavioral_failures_and_broken_witness_have_distinct_signals(self):
        wrong = "FAIL: source-departure: receiver inventory mismatch: duplicate withdrawal"
        missing = f"source-departure: {runner.MISSING_WITNESS}\n"
        self.assertEqual(runner.classify_exit(1, wrong, False), ("FAIL", wrong))
        self.assertEqual(
            runner.classify_exit(1, missing, True), ("CONTROL", runner.MISSING_WITNESS)
        )
        self.assertEqual(len(set(runner.EXIT.values())), len(runner.EXIT))
        self.assertNotEqual(runner.EXIT["CONTROL"], runner.EXIT["FAIL"])
        for code, stderr, broken in [
            (1, wrong, True),
            (101, wrong, False),
            (1, missing, False),
            (1, "source-departure: actor timeout", False),
            (1, "panic", True),
        ]:
            self.assertEqual(runner.classify_exit(code, stderr, broken)[0], "INVALID")

    def test_broken_witness_control_runs_every_mode_with_its_own_exit(self):
        binary = self.root / "rrharness"
        binary.write_bytes(b"binary")

        def scope(verdicts):
            def run(command, **_kwargs):
                directory = Path(command[-1])
                spec = runner.read_object(directory / "spec.json")
                verdict = verdicts.pop(0)
                runner.write_json(
                    directory / "trial.json",
                    {"mode": spec["mode"], "repetition": spec["repetition"],
                     "verdict": verdict, "reason": "fixture"},
                )
                return mock.Mock(returncode=0)
            return run

        for name, verdicts, code, trials in (
            ("all", ["CONTROL"] * 6, 4, 6),
            ("late", ["CONTROL"] * 3 + ["FAIL"], 2, 4),
        ):
            with self.subTest(name=name):
                out = self.root / name
                argv = ["source_departure.py", "--binary", str(binary), "--arm", "parent",
                        "--output", str(out), "--break-witness"]
                with (
                    mock.patch.object(runner.sys, "argv", argv),
                    mock.patch.object(runner.subprocess, "run", side_effect=scope(verdicts)),
                ):
                    self.assertEqual(runner.main(), code)
                receipt = runner.read_object(out / "receipt.json")
                self.assertEqual(len(receipt["trials"]), trials)
                self.assertEqual(
                    {trial["mode"] for trial in receipt["trials"]},
                    set(runner.MODES) if trials == 6 else set(runner.MODES[:2]),
                )

    def test_inexact_or_incomplete_publications_fail(self):
        for mutation in ({"exact": False}, {"rib_withdrawal_rows": 8191}):
            self.assertEqual(runner.witness({**self.row, **mutation}, self.spec)[0], "FAIL")

    def test_memory_budget_uses_parent_headroom_and_host_reserve(self):
        scope = self.root / "parent" / "sample.scope"
        scope.mkdir(parents=True)
        for directory, used, high, cap in [
            (scope, "10", "max", "1000"),
            (scope.parent, "975", "985", "990"),
        ]:
            for key, value in [
                ("memory.current", used),
                ("memory.high", high),
                ("memory.max", cap),
            ]:
                (directory / key).write_text(value)
        headroom = runner.available_memory(scope, self.root, "MemAvailable: 8388608 kB\n")
        self.assertEqual(headroom["limiting"]["available_bytes"], 10)
        self.assertEqual(headroom["limiting"]["source"], str(scope.parent / "memory.high"))
        host = runner.available_memory(scope, self.root, "MemAvailable: 1024 kB\n")
        self.assertEqual(host["limiting"]["available_bytes"], 0)

    def test_projection_uses_highest_passing_private_peak_of_same_arm_binary(self):
        path = self.root / "reference.json"
        ref = {
            "arm": "candidate",
            "shape": "standard",
            "binary_sha256": "abc",
            "trials": [
                {"mode": "private-unicast", "verdict": "PASS", "cgroup_peak_bytes": 12_000},
                {"mode": "private-unicast", "verdict": "PASS", "cgroup_peak_bytes": 28_000},
                {"mode": "grouped-unicast", "verdict": "PASS", "cgroup_peak_bytes": 39_000},
            ],
        }
        path.write_text(json.dumps(ref))
        estimate = runner.projected_budget(path, "abc", "candidate")
        self.assertEqual(estimate["standard_peak_bytes"], 28_000)
        self.assertEqual(estimate["bytes"], 1_765_766)
        with self.assertRaises(runner.InvalidReceipt):
            runner.projected_budget(path, "changed", "candidate")
        ref["trials"][0]["verdict"] = "INVALID"
        path.write_text(json.dumps(ref))
        with self.assertRaises(runner.InvalidReceipt):
            runner.projected_budget(path, "abc", "candidate")

    def test_large_budget_skip_is_written_before_starting_a_child(self):
        scope = self.root / "test.scope"
        scope.mkdir()
        (scope / "memory.max").write_text("456")
        directory = self.root / "trial"
        directory.mkdir()
        read = Path.read_text
        for budget in (
            {"bytes": None, "reason": "no large-shape projection"},
            {"bytes": 500, "source": "standard receipt"},
        ):
            spec = {
                **self.spec,
                "shape": "large",
                "repetition": 1,
                "scope_limit_bytes": 456,
                "large_budget": budget,
            }
            runner.write_json(directory / "spec.json", spec)

            def fixture(p, *args, **kwargs):
                if p == Path("/proc/self/cgroup"):
                    return "0::/test.scope\n"
                return read(p, *args, **kwargs)

            with (
                mock.patch.object(runner, "CGROUP_ROOT", self.root),
                mock.patch.object(runner, "snapshot_scope"),
                mock.patch.object(
                    runner,
                    "available_memory",
                    return_value={
                        "limiting": {"available_bytes": 125, "source": "parent/memory.high"}
                    },
                ),
                mock.patch.object(Path, "read_text", fixture),
                mock.patch.object(runner.subprocess, "run") as child,
            ):
                result = runner.scoped_trial(directory)
            child.assert_not_called()
            self.assertEqual(result["verdict"], "SKIP")
            self.assertIn(
                "parent/memory.high" if budget["bytes"] else "no large-shape projection",
                result["reason"],
            )
            self.assertEqual(runner.read_object(directory / "trial.json"), result)
            self.assertEqual(runner.read_object(directory / "preflight.json")["budget"], budget)


if __name__ == "__main__":
    unittest.main()
