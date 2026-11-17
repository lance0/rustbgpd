"""Seeded defects for the outbound-credit bars: each must turn exactly its
own cell's verdict, for its own reason, and leave every other cell PASS."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import credit_bars

GIB = 1 << 30


def exhaust(family, recovery_ms=20_000.0, p99=5.0, gap=60.0):
    return {
        "cell": "exhaust",
        "family": family,
        "mode": "measured",
        "row_size_of": 104 if family == "unicast" else 144,
        "timing": {"recovery_ms": recovery_ms},
        "checks": {name: True for name in credit_bars.WIRE_CHECKS},
        "witness": {"refused_receivers": 150, "owing_flips_total": 0.0, "receivers": 150},
        "unaffected": {
            "injected": 1_000,
            "delivered": 1_000,
            "max_gap_ms": gap,
            "p99_latency_ms": p99,
        },
    }


def paused(peak, credit_bytes):
    return {
        "cell": "paused",
        "mode": "measured",
        "row_size_of": 144,
        "checks": {"no_session_resets": True},
        "not_established": [],
        "memory": {
            "cgroup_memory_peak_bytes": peak,
            "cgroup_memory_max": str(12 * GIB),
            "cgroup_swap_max": "0",
            "cgroup_oom_kill": "0",
            "vmhwm_kib": peak // 1024,
            "peak_credit_bytes": credit_bytes,
        },
    }


def probes():
    cells = [{"cell": "lag_stall", "shape": "s", "peers": 150, "dirty_episodes": 0}] * 8
    cells.append({"cell": "restart_during_dump", "peers": 150, "dirty_episodes": 0})
    return {"cell": "probes", "mode": "measured", "probes": cells}


def fill(family, estimate):
    return {
        "cell": "fill",
        "family": family,
        "mode": "measured",
        "row_size_of": 104,
        "estimate": {"bytes_per_queued_row": estimate},
    }


def arm(candidate):
    files = {
        "exhaust-unicast.json": exhaust("unicast"),
        "exhaust-evpn.json": exhaust("evpn"),
        "paused-evpn.json": paused(6 * GIB if candidate else 9 * GIB, GIB if candidate else None),
        "probes.json": probes(),
    }
    for family in credit_bars.FILL_FAMILIES:
        files[f"fill-{family}.json"] = fill(family, 240.0)
    return files


class Bars(unittest.TestCase):
    def run_bars(self, mutate=None):
        parent, candidate = arm(False), arm(True)
        if mutate:
            mutate(parent, candidate)
        with tempfile.TemporaryDirectory() as root:
            for name, files in (("parent", parent), ("candidate", candidate)):
                directory = Path(root, name)
                directory.mkdir()
                for file, value in files.items():
                    if value is not None:
                        Path(directory, file).write_text(json.dumps(value))
            return {
                name: (verdict, reason)
                for name, verdict, reason in credit_bars.verdicts(
                    Path(root, "parent"), Path(root, "candidate")
                )
            }

    def assert_only(self, results, cell, verdict, reason):
        self.assertEqual(results[cell][0], verdict, results[cell])
        self.assertIn(reason, results[cell][1])
        others = {name: value for name, value in results.items() if name != cell}
        self.assertTrue(all(v == "PASS" for v, _ in others.values()), others)

    def test_clean_pair_passes_every_cell(self):
        results = self.run_bars()
        self.assertEqual(len(results), 7)
        self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)

    def wire_defect(self, check):
        def mutate(_parent, candidate):
            candidate["exhaust-unicast.json"]["checks"][check] = False

        return self.run_bars(mutate)

    def test_seeded_dropped_route(self):
        results = self.wire_defect("final_state_exact")
        self.assert_only(results, "cell 2 exhaustion unicast", "FAIL", "final_state_exact failed")

    def test_seeded_route_after_eor(self):
        results = self.wire_defect("eor_after_every_route")
        self.assert_only(
            results, "cell 2 exhaustion unicast", "FAIL", "eor_after_every_route failed"
        )

    def test_seeded_session_reset(self):
        results = self.wire_defect("no_session_resets")
        self.assert_only(results, "cell 2 exhaustion unicast", "FAIL", "no_session_resets failed")

    def test_seeded_over_long_recovery(self):
        def mutate(_parent, candidate):
            # Parent 20 s: bar is max(25 s, 22 s) = 25 s.
            candidate["exhaust-evpn.json"]["timing"]["recovery_ms"] = 25_001.0

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 2 exhaustion evpn", "FAIL", "recovery over bar")

    def test_recovery_slack_applies_to_short_parent(self):
        def mutate(parent, candidate):
            parent["exhaust-evpn.json"]["timing"]["recovery_ms"] = 4_000.0
            candidate["exhaust-evpn.json"]["timing"]["recovery_ms"] = 5_999.0

        self.assertEqual(self.run_bars(mutate)["cell 2 exhaustion evpn"][0], "PASS")

    def test_seeded_delivery_gap(self):
        def mutate(_parent, candidate):
            candidate["exhaust-unicast.json"]["unaffected"]["max_gap_ms"] = 1_001.0

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 3 unaffected peer unicast", "FAIL", "delivery gap")

    def test_seeded_p99_regression(self):
        def mutate(_parent, candidate):
            candidate["exhaust-evpn.json"]["unaffected"]["p99_latency_ms"] = 5.6

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 3 unaffected peer evpn", "FAIL", "candidate p99")

    def test_seeded_missing_refusal_witness(self):
        def mutate(parent, _candidate):
            parent["exhaust-unicast.json"]["witness"]["refused_receivers"] = 0

        results = self.run_bars(mutate)
        # The unaffected-peer cell reads the same run but has no witness bar.
        self.assertEqual(results["cell 2 exhaustion unicast"][0], "INVALID")
        self.assertIn("never exhausted credit", results["cell 2 exhaustion unicast"][1])
        others = {k: v for k, v in results.items() if k != "cell 2 exhaustion unicast"}
        self.assertTrue(all(v == "PASS" for v, _ in others.values()), others)

    def test_owe_whole_flips_are_a_witness(self):
        def mutate(parent, _candidate):
            witness = parent["exhaust-unicast.json"]["witness"]
            witness["refused_receivers"] = 0
            witness["owing_flips_total"] = 150.0

        self.assertEqual(self.run_bars(mutate)["cell 2 exhaustion unicast"][0], "PASS")

    def test_too_few_flips_are_not_a_witness(self):
        def mutate(parent, _candidate):
            witness = parent["exhaust-unicast.json"]["witness"]
            witness["refused_receivers"] = 0
            witness["owing_flips_total"] = 149.0

        self.assertEqual(self.run_bars(mutate)["cell 2 exhaustion unicast"][0], "INVALID")

    def test_seeded_dropped_route_without_settlement_is_fail(self):
        # A run that never settles has no recovery time; the wire FAIL must
        # survive instead of becoming INVALID in the timing math.
        def mutate(_parent, candidate):
            run = candidate["exhaust-unicast.json"]
            run["checks"]["final_state_exact"] = False
            run["timing"]["recovery_ms"] = None

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 2 exhaustion unicast", "FAIL", "final_state_exact failed")

    def test_seeded_disconnected_paused_receiver_is_invalid(self):
        def mutate(_parent, candidate):
            run = candidate["paused-evpn.json"]
            run["checks"]["no_session_resets"] = False
            run["not_established"] = ["127.10.1.1: None"]

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 1 paused-reader evpn", "INVALID", "session reset")

    def test_seeded_not_established_paused_receiver_is_invalid(self):
        def mutate(parent, _candidate):
            parent["paused-evpn.json"]["not_established"] = ["127.10.1.1: None"]

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 1 paused-reader evpn", "INVALID", "not Established")

    def test_seeded_correctness_fill_is_invalid(self):
        def mutate(_parent, candidate):
            candidate["fill-vpn.json"]["mode"] = "correctness"

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 6 bytes per queued row", "INVALID", "not measured")

    def test_every_required_field_missing_is_invalid(self):
        # Each loader's required fields: deleting or nulling any one of them
        # gives that cell INVALID, never PASS and never an exception.
        required = {
            "paused-evpn.json": (
                "cell 1 paused-reader evpn",
                [
                    "mode",
                    "checks.no_session_resets",
                    "not_established",
                    "memory.cgroup_swap_max",
                    "memory.cgroup_memory_max",
                    "memory.cgroup_memory_peak_bytes",
                    "memory.vmhwm_kib",
                    "memory.cgroup_oom_kill",
                    "memory.peak_credit_bytes",
                    "row_size_of",
                ],
            ),
            "exhaust-unicast.json": (
                "cell 2 exhaustion unicast",
                [
                    "mode",
                    "witness.refused_receivers",
                    "witness.owing_flips_total",
                    "witness.receivers",
                    "checks.final_state_exact",
                    "checks.eor_after_every_route",
                    "checks.no_session_resets",
                    "timing.recovery_ms",
                ],
            ),
            "exhaust-evpn.json": (
                "cell 3 unaffected peer evpn",
                [
                    "mode",
                    "unaffected.injected",
                    "unaffected.delivered",
                    "unaffected.p99_latency_ms",
                    "unaffected.max_gap_ms",
                ],
            ),
            "probes.json": ("cell 4 lag and restart probes", ["mode", "probes"]),
            "fill-flowspec.json": (
                "cell 6 bytes per queued row",
                ["mode", "estimate.bytes_per_queued_row", "row_size_of"],
            ),
        }
        for file, (cell, fields) in required.items():
            for field in fields:
                for removal in ("delete", "null"):

                    def mutate(_parent, candidate, file=file, field=field, removal=removal):
                        *parents, leaf = field.split(".")
                        node = candidate[file]
                        for key in parents:
                            node = node[key]
                        if removal == "delete":
                            del node[leaf]
                        else:
                            node[leaf] = None

                    with self.subTest(file=file, field=field, removal=removal):
                        results = self.run_bars(mutate)
                        self.assertEqual(results[cell][0], "INVALID", results[cell])

    def test_null_probe_dirty_count_is_invalid(self):
        def mutate(_parent, candidate):
            run = candidate["probes.json"]
            run["probes"] = copy.deepcopy(run["probes"])
            run["probes"][0]["dirty_episodes"] = None

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 4 lag and restart probes", "INVALID", "dirty_episodes")

    def test_witness_is_never_pass_when_absent(self):
        def mutate(_parent, candidate):
            del candidate["exhaust-evpn.json"]["witness"]

        results = self.run_bars(mutate)
        self.assertEqual(results["cell 2 exhaustion evpn"][0], "INVALID")

    def test_seeded_missing_instrument(self):
        def mutate(_parent, candidate):
            candidate["paused-evpn.json"]["memory"]["cgroup_memory_peak_bytes"] = None

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 1 paused-reader evpn", "INVALID", "missing instrument")

    def test_missing_credit_bytes_gauge_is_invalid(self):
        def mutate(_parent, candidate):
            candidate["paused-evpn.json"]["memory"]["peak_credit_bytes"] = None

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 1 paused-reader evpn", "INVALID", "credit_bytes")

    def test_unfenced_swap_is_invalid(self):
        def mutate(parent, _candidate):
            parent["paused-evpn.json"]["memory"]["cgroup_swap_max"] = "max"

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 1 paused-reader evpn", "INVALID", "swap not fenced")

    def test_cell1_margin(self):
        def mutate(_parent, candidate):
            candidate["paused-evpn.json"]["memory"]["cgroup_memory_peak_bytes"] = int(7.6 * GIB)

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 1 paused-reader evpn", "FAIL", "1.5 GiB")

    def test_candidate_oom_fails(self):
        def mutate(_parent, candidate):
            candidate["paused-evpn.json"] = None
            candidate["paused-exit.json"] = {"oom": True, "exit": 137}

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 1 paused-reader evpn", "FAIL", "OOM")

    def test_correctness_run_is_not_a_measurement(self):
        def mutate(_parent, candidate):
            candidate["exhaust-unicast.json"]["mode"] = "correctness"

        results = self.run_bars(mutate)
        self.assertEqual(results["cell 2 exhaustion unicast"][0], "INVALID")
        self.assertEqual(results["cell 3 unaffected peer unicast"][0], "INVALID")

    def test_dirty_episode_fails_cell4(self):
        def mutate(_parent, candidate):
            run = candidate["probes.json"]
            run["probes"] = copy.deepcopy(run["probes"])
            run["probes"][8]["dirty_episodes"] = 1

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 4 lag and restart probes", "FAIL", "restart_during_dump")

    def test_missing_probe_cell_is_invalid(self):
        def mutate(_parent, candidate):
            candidate["probes.json"]["probes"] = candidate["probes.json"]["probes"][:8]

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 4 lag and restart probes", "INVALID", "probe cells")

    def test_estimate_above_charge_is_flagged(self):
        def mutate(_parent, candidate):
            candidate["fill-flowspec.json"]["estimate"]["bytes_per_queued_row"] = 400.0

        results = self.run_bars(mutate)
        self.assertEqual(results["cell 6 bytes per queued row"][0], "PASS")
        self.assertIn("follow-up ticket for flowspec", results["cell 6 bytes per queued row"][1])

    def test_every_cell_reported_when_all_fail(self):
        def mutate(_parent, candidate):
            for name in ("exhaust-unicast.json", "exhaust-evpn.json"):
                candidate[name]["checks"]["final_state_exact"] = False
                candidate[name]["unaffected"]["max_gap_ms"] = 5_000.0
            candidate["paused-evpn.json"]["memory"]["cgroup_memory_peak_bytes"] = 9 * GIB

        results = self.run_bars(mutate)
        self.assertEqual(len(results), 7)
        failed = [name for name, (verdict, _) in results.items() if verdict == "FAIL"]
        self.assertEqual(len(failed), 5, results)

    def test_exit_status(self):
        self.assertEqual(credit_bars.report([("a", "PASS", "")]), 0)
        self.assertEqual(credit_bars.report([("a", "PASS", ""), ("b", "INVALID", "")]), 2)
        self.assertEqual(credit_bars.report([("a", "FAIL", ""), ("b", "INVALID", "")]), 1)


if __name__ == "__main__":
    unittest.main()
