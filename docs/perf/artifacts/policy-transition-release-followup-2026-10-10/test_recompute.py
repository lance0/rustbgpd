import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("recompute", ROOT / "recompute.py")
RECOMPUTE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RECOMPUTE)


class RecomputeTest(unittest.TestCase):
    def test_prior_step_values_reproduce(self):
        summary = RECOMPUTE.prior_steps(ROOT)
        self.assertEqual(summary["early-s2"]["base"]["median"], 574)
        self.assertEqual(summary["early-s2"]["main"]["median"], 486)
        self.assertEqual(summary["prefix-snapshot-s2"]["memo-reloads2to4"]["median"], 369.5)
        self.assertEqual(summary["prefix-snapshot-s2"]["snap-reloads2to4"]["median"], 325)

    def test_original_has_every_reload_and_countercase(self):
        summary, _ = RECOMPUTE.compute(ROOT, "j2", 12)
        self.assertEqual(summary["post2952"]["long_post_commit_cases"], 18)
        self.assertEqual(summary["pre2952"]["long_post_commit_cases"], 0)
        self.assertEqual(summary["post2952"]["rib_to_trace_arm_ms"]["n"], 23)

    def test_confirmation_has_every_reload_and_countercase(self):
        summary, _ = RECOMPUTE.compute(ROOT, "confirmation", 8)
        self.assertEqual(summary["post2952"]["long_post_commit_cases"], 13)
        self.assertEqual(summary["pre2952"]["long_post_commit_cases"], 0)
        self.assertEqual(summary["post2952"]["rib_to_trace_arm_ms"]["n"], 16)

    def test_missing_reload_is_invalid(self):
        self.rejected(lambda records: records.pop())

    def test_failed_cell_is_invalid(self):
        self.rejected(lambda records: records[0]["exits"].update({"daemon": 1}))

    def test_wrong_transition_outcome_is_invalid(self):
        self.rejected(lambda records: records[0]["rib_transition"].update({"outcome": "fallback_handoff"}))

    def test_wrong_shape_is_invalid(self):
        self.rejected(lambda records: records[0]["rib_transition"].update({"member_count": 700}))

    def test_phase_differs_from_selected_log_is_invalid(self):
        self.rejected(lambda records: records[0]["phase_timing"].update({"cohort_prestage_session_apply_us": 1}))

    def test_failed_stats_probe_is_invalid(self):
        self.rejected(lambda records: next(call for call in records[0]["calls"]
                                          if call["op"] == "policy_stats").update({"exit": 1}))

    def test_missing_stats_probe_is_invalid(self):
        self.rejected(lambda records: records[0]["calls"].pop(next(i for i, call in enumerate(records[0]["calls"])
                                                                if call["phase"] == "pair" and call["op"] == "policy_stats")))

    def test_over_deadline_probe_is_invalid(self):
        self.rejected(lambda records: records[0]["calls"][0].update({"duration_ms": 2001}))

    def test_insufficient_in_band_pairs_is_invalid(self):
        def mutate(records):
            for record in records:
                if record["run"] == "pre2952-r1":
                    for call in record["calls"]:
                        if call["phase"] == "pair":
                            call["start_minus_rib_commit_ms"] = -221
        self.rejected(mutate)

    def test_selected_commit_outcome_is_bound(self):
        self.rejected_log("RIB export-policy transition completed", "fields", {"outcome": "fallback_handoff"})

    def test_selected_completion_timestamp_is_bound(self):
        self.rejected_log("config reload complete (one runtime generation)", "timestamp", "2000-01-01T00:00:00Z")

    def rejected_log(self, message, key, value):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "j2-reloads.json").write_bytes((ROOT / "j2-reloads.json").read_bytes())
            events = [json.loads(line) for line in (ROOT / "j2-timeline.jsonl").read_text().splitlines()]
            event = next(event for event in events if event["fields"].get("message") == message)
            if key == "fields":
                event[key].update(value)
            else:
                event[key] = value
            (root / "j2-timeline.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
            with self.assertRaises(AssertionError):
                RECOMPUTE.compute(root, "j2", 12)

    def rejected(self, mutate):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            records = json.loads((ROOT / "j2-reloads.json").read_text())
            mutate(records)
            (root / "j2-reloads.json").write_text(json.dumps(records))
            (root / "j2-timeline.jsonl").write_bytes((ROOT / "j2-timeline.jsonl").read_bytes())
            with self.assertRaises(AssertionError):
                RECOMPUTE.compute(root, "j2", 12)


if __name__ == "__main__":
    unittest.main()
