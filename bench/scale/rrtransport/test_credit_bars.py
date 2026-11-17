"""Seeded defects for the outbound-credit bars: each must turn exactly its
own cell's verdict, for its own reason, and leave every other cell PASS."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import credit_bars

GIB = 1 << 30


# The fixed shape's per-peer credit at 153 registered peers.
ROW_CREDIT = 16_777_216 // 153
BYTE_CREDIT = (2 * GIB) // 153


def exhaust(family, recovery_ms=20_000.0, p99=5.0, gap=60.0, candidate=False):
    """An ordinary burst that filled every receiver's credit and then owed
    keys: no refusal and, on the parent, no owe-whole flip."""
    return {
        "cell": "exhaust",
        "family": family,
        "mode": "measured",
        "row_size_of": 104 if family == "unicast" else 144,
        "shape": dict(credit_bars.EXHAUST_SHAPE),
        "timing": {
            "release_sent_ms": 7_000.0,
            "resumed_ms": 10_000.0,
            "recovery_ms": recovery_ms,
            "drain_after_resume_ms": recovery_ms - 10_000.0,
        },
        "checks": {name: True for name in credit_bars.WIRE_CHECKS},
        "witness": {
            "refused_receivers": 0,
            "owing_flips_total": 150.0 if candidate else 0.0,
            "receivers": 150,
            "peak_credit_rows": 150.0 * (56_144 if candidate else ROW_CREDIT),
            "peak_credit_bytes": 150.0 * 56_144 * 250 if candidate else None,
        },
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
        "family": "evpn",
        "mode": "measured",
        "row_size_of": 144,
        "shape": dict(credit_bars.PAUSED_SHAPE),
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
    cells = [
        {
            "cell": "lag_stall",
            "shape": shape,
            "peers": peers,
            "stall_ms": stall,
            "dirty_episodes": 0,
        }
        for shape in ("unicast_private", "evpn_private")
        for peers in (150, 1_000)
        for stall in (500, 2_000)
    ]
    cells.append(
        {"cell": "restart_during_dump", "peers": 150, "table": 100_000, "dirty_episodes": 0}
    )
    return {"cell": "probes", "mode": "measured", "probes": cells}


def fill(family, estimate):
    return {
        "cell": "fill",
        "family": family,
        "mode": "measured",
        "row_size_of": 104,
        "shape": dict(credit_bars.FILL_SHAPE),
        "estimate": {"bytes_per_queued_row": estimate},
    }


def arm(candidate):
    files = {
        "exhaust-unicast.json": exhaust("unicast", candidate=candidate),
        "exhaust-evpn.json": exhaust("evpn", candidate=candidate),
        "paused-evpn.json": paused(6 * GIB if candidate else 9 * GIB, GIB if candidate else None),
        "probes.json": probes(),
    }
    for family in credit_bars.FILL_FAMILIES:
        files[f"fill-{family}.json"] = fill(family, 240.0)
    return files


ALL_CELLS = ["probes", "exhaust-unicast", "exhaust-evpn", "paused"] + [
    f"fill-{family}" for family in credit_bars.FILL_FAMILIES
]


def provenance(sha, cells=None):
    return [{"sha256": sha, "measured": 1, "cells": list(cells or ALL_CELLS)}]


class Bars(unittest.TestCase):
    def run_bars(self, mutate=None):
        parent, candidate = arm(False), arm(True)
        if mutate:
            mutate(parent, candidate)
        with tempfile.TemporaryDirectory() as root:
            for name, files in (("parent", parent), ("candidate", candidate)):
                if files is None:
                    continue
                files.setdefault("provenance.jsonl", provenance(name))
                for file, value in files.items():
                    # Unprefixed files belong to repetition 1.
                    path = Path(root, name, file if "/" in file else f"1/{file}")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if value is None:
                        continue
                    if file.endswith(".jsonl"):
                        path.write_text("".join(json.dumps(line) + "\n" for line in value))
                    else:
                        path.write_text(json.dumps(value))
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

    def test_seeded_misplaced_eor(self):
        results = self.wire_defect("one_eor_before_burst")
        self.assert_only(
            results, "cell 2 exhaustion unicast", "FAIL", "one_eor_before_burst failed"
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

    def witness_defect(self, side, family="unicast", **fields):
        def mutate(parent, candidate):
            arm = parent if side == "parent" else candidate
            arm[f"exhaust-{family}.json"]["witness"].update(fields)

        return self.run_bars(mutate)

    def test_seeded_credit_never_reached(self):
        # One row (parent) or one byte (candidate) short of every receiver's
        # credit. The unaffected-peer cell reads the same run but has no
        # witness bar.
        cases = {
            "parent": {"peak_credit_rows": 150.0 * ROW_CREDIT - 1},
            "candidate": {"peak_credit_bytes": 150.0 * BYTE_CREDIT - 1},
        }
        for side, fields in cases.items():
            with self.subTest(side=side):
                results = self.witness_defect(side, **fields)
                self.assert_only(
                    results, "cell 2 exhaustion unicast", "INVALID", "never exhausted credit"
                )
                self.assertIn(f"{side} run 0", results["cell 2 exhaustion unicast"][1])

    def test_seeded_owe_whole_flips_without_spent_credit_are_not_a_witness(self):
        # What a selection release leaves: one flip per receiver, no credit
        # charged, nothing refused.
        cases = {
            "parent": {"peak_credit_rows": 0.0},
            "candidate": {"peak_credit_rows": 0.0, "peak_credit_bytes": 0.0},
        }
        for side, fields in cases.items():
            with self.subTest(side=side):
                results = self.witness_defect(
                    side, "evpn", owing_flips_total=150.0, refused_receivers=0, **fields
                )
                self.assert_only(
                    results, "cell 2 exhaustion evpn", "INVALID", "flips are not a witness"
                )

    def test_seeded_operation_refusals_are_not_a_witness(self):
        # Every receiver refused only because a whole-table operation was
        # live: the same `outbound_credit` reason, nothing charged.
        for side, gauge in (("parent", "peak_credit_rows"), ("candidate", "peak_credit_bytes")):
            with self.subTest(side=side):
                results = self.witness_defect(side, refused_receivers=150, **{gauge: 0.0})
                self.assert_only(
                    results, "cell 2 exhaustion unicast", "INVALID", "never exhausted credit"
                )
                self.assertIn("refusals on 150/150 receivers, report-only", results[
                    "cell 2 exhaustion unicast"
                ][1])

    def test_refusals_are_reported_beside_a_witness(self):
        results = self.witness_defect("candidate", refused_receivers=3)
        verdict, reason = results["cell 2 exhaustion unicast"]
        self.assertEqual(verdict, "PASS", reason)
        self.assertIn("credit refusals on 3/150 receivers, report-only", reason)

    def test_seeded_overadmission_masks_a_receiver_that_spent_nothing(self):
        # 149 receivers each one 1,024-row envelope over their credit, the
        # 150th at zero: the sum still clears 150 x credit.
        results = self.witness_defect(
            "candidate", peak_credit_bytes=149.0 * (BYTE_CREDIT + 1_024 * 250)
        )
        self.assert_only(
            results, "cell 2 exhaustion unicast", "INVALID", "cannot show each one reached it"
        )

    def test_seeded_credit_above_the_burst_is_invalid(self):
        # A credit larger than the 150,000-row burst: nobody reaches it, yet
        # the sum of whole bursts clears receivers x credit.
        cases = {
            "candidate": {"peak_credit_bytes": 150.0 * 150_000 * 250},
            "parent": {"peak_credit_rows": 150.0 * 150_000},
        }
        for side, fields in cases.items():
            with self.subTest(side=side):
                results = self.witness_defect(side, **fields)
                self.assert_only(
                    results, "cell 2 exhaustion unicast", "INVALID", "more than every receiver"
                )
                self.assertIn(f"{side} run 0", results["cell 2 exhaustion unicast"][1])

    def test_witness_window_edges(self):
        # Upper edge: every receiver one row (unicast 104 + 146 bytes) past
        # its credit, plus one healthy row; one more is INVALID.
        cases = {
            "candidate": ("peak_credit_bytes", 150 * (BYTE_CREDIT + 250) + 250),
            "parent": ("peak_credit_rows", 150 * (ROW_CREDIT + 1) + 1),
        }
        for side, (gauge, high) in cases.items():
            for peak, verdict in ((high, "PASS"), (high + 1, "INVALID")):
                with self.subTest(side=side, peak=peak):
                    results = self.witness_defect(side, **{gauge: float(peak)})
                    self.assertEqual(results["cell 2 exhaustion unicast"][0], verdict, results)

    def test_seeded_burst_sent_after_resume_is_invalid(self):
        for sent in (10_000.0, 15_000.0):

            def mutate(_parent, candidate, sent=sent):
                candidate["exhaust-unicast.json"]["timing"]["release_sent_ms"] = sent

            with self.subTest(sent=sent):
                results = self.run_bars(mutate)
                self.assert_only(
                    results, "cell 2 exhaustion unicast", "INVALID", "not before the readers"
                )

    def test_seeded_witness_receivers_differ_from_shape(self):
        results = self.witness_defect(
            "candidate", receivers=1, peak_credit_bytes=float(BYTE_CREDIT)
        )
        self.assert_only(
            results, "cell 2 exhaustion unicast", "INVALID", "witness.receivers 1 is not"
        )

    def test_seeded_arm_identity(self):
        # Two builds of one tree: a parent with the byte gauge, or a
        # candidate without it.
        cases = {
            "parent": {"peak_credit_bytes": 150.0 * BYTE_CREDIT},
            "candidate": {"peak_credit_bytes": None, "peak_credit_rows": 150.0 * ROW_CREDIT},
        }
        for side, fields in cases.items():
            with self.subTest(side=side):
                results = self.witness_defect(side, **fields)
                for cell in ("cell 2 exhaustion unicast", "cell 3 unaffected peer unicast"):
                    self.assertEqual(results[cell][0], "INVALID", results[cell])
                    self.assertIn(f"{side} exhaust-unicast run 0: byte credit gauge", results[
                        cell
                    ][1])
                others = [v for name, (v, _) in results.items() if "unicast" not in name]
                self.assertTrue(all(v == "PASS" for v in others), results)

    def test_drain_after_resume_is_reported_not_gated(self):
        # The candidate drains 3.1x slower after resume, yet recovery (which
        # includes the 80 s pause) stays under its bar.
        def mutate(parent, candidate):
            parent["exhaust-unicast.json"]["timing"].update(
                recovery_ms=90_501.0, resumed_ms=80_006.0, drain_after_resume_ms=10_495.0
            )
            candidate["exhaust-unicast.json"]["timing"].update(
                recovery_ms=113_000.0, resumed_ms=80_006.0, drain_after_resume_ms=32_994.0
            )

        verdict, reason = self.run_bars(mutate)["cell 2 exhaustion unicast"]
        self.assertEqual(verdict, "PASS", reason)
        self.assertIn(
            "report-only, not a bar: drain after resume candidate 32994 ms vs parent 10495 ms "
            "(ratio 3.14; the recovery rule would allow 13119 ms)",
            reason,
        )

    def test_drain_report_rides_a_recovery_fail(self):
        def mutate(_parent, candidate):
            candidate["exhaust-evpn.json"]["timing"]["recovery_ms"] = 25_001.0
            candidate["exhaust-evpn.json"]["timing"]["drain_after_resume_ms"] = None

        verdict, reason = self.run_bars(mutate)["cell 2 exhaustion evpn"]
        self.assertEqual(verdict, "FAIL", reason)
        self.assertIn("drain after resume: not recorded in every run", reason)

    def test_seeded_later_repetition_without_witness_is_invalid(self):
        def mutate(parent, candidate):
            bad = exhaust("unicast", candidate=True)
            bad["witness"]["peak_credit_bytes"] = 0.0
            self.two_repetitions(
                parent,
                candidate,
                "exhaust-unicast",
                "exhaust-unicast.json",
                exhaust("unicast"),
                bad,
            )

        results = self.run_bars(mutate)
        self.assertEqual(results["cell 2 exhaustion unicast"][0], "INVALID", results)
        self.assertIn("candidate run 1", results["cell 2 exhaustion unicast"][1])

    def check_one(self, run):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "exhaust-unicast.json").write_text(json.dumps(run))
            return credit_bars.check(Path(root))[0]

    def test_seeded_fewer_registered_peers_than_receivers_is_invalid(self):
        run = exhaust("unicast")
        run["shape"]["registered_peers"] = 149
        _, verdict, reason = self.check_one(run)
        self.assertEqual(verdict, "INVALID", reason)
        self.assertIn("150 burst receivers among 149 registered peers", reason)

    def test_per_peer_credit_clamps(self):
        # (registered peers, unit, per-peer credit): the ceiling binds at 7
        # peers (the reduced shape), the floor past 1,024 or 2,048.
        cases = [
            (7, "rows", 1_048_576),
            (7, "bytes", 256 << 20),
            (2_051, "rows", 8_192),
            (2_051, "bytes", 2 << 20),
        ]
        for peers, unit, limit in cases:
            with self.subTest(peers=peers, unit=unit):
                receivers = peers - 3
                run = exhaust("unicast", candidate=unit == "bytes")
                run["shape"].update(receivers=receivers, registered_peers=peers)
                run["witness"]["receivers"] = receivers
                gauge = "peak_credit_bytes" if unit == "bytes" else "peak_credit_rows"
                run["witness"][gauge] = float(receivers * limit)
                _, verdict, reason = self.check_one(run)
                self.assertEqual(verdict, "PASS", reason)
                self.assertIn(f"{receivers * limit} {unit} in [{receivers} x {limit},", reason)

    def test_seeded_refusals_on_too_few_receivers_are_not_a_witness(self):
        results = self.witness_defect("parent", peak_credit_rows=0.0, refused_receivers=149)
        self.assert_only(results, "cell 2 exhaustion unicast", "INVALID", "refusals on 149/150")

    def test_seeded_byte_credit_tree_without_its_gauge_is_invalid(self):
        # Judged in rows, a byte-credit tree's rows never reach the row credit.
        run = exhaust("unicast", candidate=True)
        run["witness"]["peak_credit_bytes"] = None
        _, verdict, reason = self.check_one(run)
        self.assertEqual(verdict, "INVALID", reason)
        self.assertIn("rows <", reason)

    def test_clean_witness_names_what_it_counted(self):
        reason = self.run_bars()["cell 2 exhaustion unicast"][1]
        self.assertIn(
            f"parent credit gauge peak 16448250 rows in [150 x {ROW_CREDIT}, 16448401]", reason
        )
        self.assertIn(
            f"candidate credit gauge peak 2105400000 bytes in [150 x {BYTE_CREDIT}, 2105413750]",
            reason,
        )

    def test_seeded_selection_release_is_not_an_exhaustion_cell(self):
        # A restart burst's result offered as cell 2, with its 150 flips.
        run = exhaust("unicast")
        run["shape"]["trigger"] = "rfc4724_selection_release"
        run["witness"].update(owing_flips_total=150.0, peak_credit_rows=0.0)
        with tempfile.TemporaryDirectory() as root:
            Path(root, "exhaust-unicast.json").write_text(json.dumps(run))
            results = credit_bars.check(Path(root))
        self.assertEqual(results[0][1], "INVALID", results)
        self.assertIn("cannot exhaust ordinary credit", results[0][2])

    def test_check_reads_a_restart_burst_without_a_witness(self):
        run = exhaust("evpn")
        run["cell"] = "restart"
        run["shape"]["trigger"] = "rfc4724_selection_release"
        run["checks"] = {name: True for name in credit_bars.RESTART_WIRE_CHECKS}
        run["witness"].update(owing_flips_total=150.0, peak_credit_rows=0.0)
        for seeded, verdict in ((None, "PASS"), ("eor_after_every_route", "FAIL")):
            with self.subTest(seeded=seeded), tempfile.TemporaryDirectory() as root:
                if seeded:
                    run["checks"][seeded] = False
                Path(root, "restart-evpn.json").write_text(json.dumps(run))
                Path(root, "exhaust-evpn.json").write_text(json.dumps(exhaust("evpn")))
                results = {name: verdict for name, verdict, _ in credit_bars.check(Path(root))}
                self.assertEqual(
                    results, {"exhaustion evpn": "PASS", "restart burst evpn": verdict}
                )

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
                    "shape.trigger",
                    "shape.registered_peers",
                    "witness.refused_receivers",
                    "witness.peak_credit_rows",
                    "witness.receivers",
                    "shape.receivers",
                    "timing.release_sent_ms",
                    "timing.resumed_ms",
                    "row_size_of",
                    "checks.final_state_exact",
                    "checks.one_eor_before_burst",
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

    def second_repetition(self, arm, cells, **files):
        arm["2/provenance.jsonl"] = provenance(arm["provenance.jsonl"][0]["sha256"], cells)
        for file, value in files.items():
            arm[f"2/{file}"] = value

    def test_seeded_failed_repetition_without_result_is_invalid(self):
        # Repetition 2 of the candidate died before writing its result; the
        # good repetition 1 must not stand in for it.
        def mutate(parent, candidate):
            parent.setdefault("provenance.jsonl", provenance("parent"))
            candidate.setdefault("provenance.jsonl", provenance("candidate"))
            self.second_repetition(
                parent, ["exhaust-unicast"], **{"exhaust-unicast.json": exhaust("unicast")}
            )
            self.second_repetition(
                candidate,
                ["exhaust-unicast"],
                **{"exhaust-unicast-exit.json": {"cell": "exhaust-unicast", "exit": 1}},
            )

        results = self.run_bars(mutate)
        for cell in ("cell 2 exhaustion unicast", "cell 3 unaffected peer unicast"):
            self.assertEqual(results[cell][0], "INVALID", results[cell])
            self.assertIn(
                "repetition 2: exhaust-unicast exited 1 without a result", results[cell][1]
            )
        others = [v for name, (v, _) in results.items() if "unicast" not in name]
        self.assertTrue(all(v == "PASS" for v in others), results)

    def test_seeded_attempted_repetition_with_nothing_is_invalid(self):
        def mutate(parent, candidate):
            parent.setdefault("provenance.jsonl", provenance("parent"))
            candidate.setdefault("provenance.jsonl", provenance("candidate"))
            self.second_repetition(parent, ["fill-vpn"], **{"fill-vpn.json": fill("vpn", 240.0)})
            self.second_repetition(candidate, ["fill-vpn"])

        results = self.run_bars(mutate)
        self.assert_only(
            results, "cell 6 bytes per queued row", "INVALID", "fill-vpn attempted, no result"
        )

    def test_explicit_wire_failure_with_exit_marker_stays_fail(self):
        def mutate(_parent, candidate):
            candidate["exhaust-evpn.json"]["checks"]["final_state_exact"] = False
            candidate["exhaust-evpn-exit.json"] = {"cell": "exhaust-evpn", "exit": 1}

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 2 exhaustion evpn", "FAIL", "final_state_exact failed")

    def test_seeded_mismatched_repetition_sets_are_invalid(self):
        def mutate(parent, _candidate):
            parent.setdefault("provenance.jsonl", provenance("parent"))
            self.second_repetition(parent, ["probes"], **{"probes.json": probes()})

        results = self.run_bars(mutate)
        self.assert_only(
            results, "cell 4 lag and restart probes", "INVALID", "differ from candidate"
        )

    def test_seeded_missing_arm_is_invalid(self):
        def mutate(parent, _candidate):
            parent.clear()
            parent["provenance.jsonl"] = None

        results = self.run_bars(mutate)
        self.assertTrue(all(v == "INVALID" for v, _ in results.values()), results)

    def test_seeded_two_binaries_in_one_arm_are_invalid(self):
        def mutate(_parent, candidate):
            candidate["provenance.jsonl"] = provenance("candidate") + provenance("other")

        results = self.run_bars(mutate)
        self.assertTrue(all(v == "INVALID" for v, _ in results.values()), results)
        self.assertIn("more than one harness binary", results["cell 4 lag and restart probes"][1])

    def test_seeded_same_binary_on_both_arms_is_invalid(self):
        def mutate(parent, candidate):
            parent["provenance.jsonl"] = provenance("same")
            candidate["provenance.jsonl"] = provenance("same")

        results = self.run_bars(mutate)
        self.assertTrue(all(v == "INVALID" for v, _ in results.values()), results)

    def test_seeded_mixed_family_is_invalid(self):
        def mutate(_parent, candidate):
            candidate["exhaust-unicast.json"]["family"] = "evpn"

        results = self.run_bars(mutate)
        self.assertEqual(results["cell 2 exhaustion unicast"][0], "INVALID")
        self.assertIn("holds a exhaust/evpn result", results["cell 2 exhaustion unicast"][1])

    def test_seeded_stray_result_is_invalid(self):
        # A result left in a repetition whose runs never listed the cell.
        def mutate(_parent, candidate):
            candidate["provenance.jsonl"] = provenance(
                "candidate", [c for c in ALL_CELLS if c != "fill-evpn"]
            )

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 6 bytes per queued row", "INVALID", "not from a listed run")

    def test_seeded_short_paused_run_is_invalid(self):
        def mutate(_parent, candidate):
            candidate["paused-evpn.json"]["shape"]["seconds"] = 1

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 1 paused-reader evpn", "INVALID", "shape.seconds is 1")

    def test_seeded_non_qualification_shapes_are_invalid(self):
        cases = {
            ("exhaust-unicast.json", "rows_per_receiver"): ("cell 2 exhaustion unicast", 4_096),
            ("exhaust-evpn.json", "receivers"): ("cell 2 exhaustion evpn", 4),
            ("exhaust-evpn.json", "pause_ms"): ("cell 2 exhaustion evpn", 30_000.0),
            ("exhaust-evpn.json", "burst_interval_ms"): ("cell 2 exhaustion evpn", 0.0),
            ("exhaust-unicast.json", "registered_peers"): ("cell 2 exhaustion unicast", 7),
            ("exhaust-unicast.json", "trigger"): (
                "cell 2 exhaustion unicast",
                "rfc4724_selection_release",
            ),
            ("paused-evpn.json", "receivers"): ("cell 1 paused-reader evpn", 4),
            ("paused-evpn.json", "routes"): ("cell 1 paused-reader evpn", 2_000),
            ("fill-unicast.json", "rows_per_receiver"): ("cell 6 bytes per queued row", 8_192),
        }
        for (file, key), (cell, value) in cases.items():
            for side in ("parent", "candidate"):

                def mutate(parent, candidate, file=file, key=key, value=value, side=side):
                    (parent if side == "parent" else candidate)[file]["shape"][key] = value

                with self.subTest(file=file, key=key, side=side):
                    results = self.run_bars(mutate)
                    self.assertEqual(results[cell][0], "INVALID", results[cell])
                    self.assertIn(f"shape.{key}", results[cell][1])

    def test_seeded_wrong_probe_shape_is_invalid(self):
        def mutate(_parent, candidate):
            run = candidate["probes.json"]
            run["probes"] = copy.deepcopy(run["probes"])
            run["probes"][0]["peers"] = 16

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 4 lag and restart probes", "INVALID", "fixed 9-cell set")

    def test_paused_cgroup_limit_mismatch_is_invalid(self):
        def mutate(parent, _candidate):
            parent["paused-evpn.json"]["memory"]["cgroup_memory_max"] = str(64 * GIB)

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 1 paused-reader evpn", "INVALID", "not 12 GiB")

    def test_check_marker_without_result_is_invalid(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "exhaust-unicast-exit.json").write_text('{"exit": 1}')
            results = credit_bars.check(Path(root))
        self.assertEqual(results[0][1], "INVALID")

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

    def test_seeded_oom_after_paused_result_decides_cell1(self):
        # `paused` writes its result before teardown; an OOM kill after
        # that leaves a pre-OOM result beside the OOM marker.
        for side, verdict in (("candidate", "FAIL"), ("parent", "INVALID")):

            def mutate(parent, candidate, side=side):
                arm = parent if side == "parent" else candidate
                arm["paused-exit.json"] = {"cell": "paused", "exit": 137, "oom": True}

            with self.subTest(side=side):
                results = self.run_bars(mutate)
                self.assert_only(results, "cell 1 paused-reader evpn", verdict, "OOM")

    def test_candidate_oom_is_not_weakened_by_a_bad_parent_run(self):
        def mutate(parent, candidate):
            parent["paused-evpn.json"]["not_established"] = ["127.10.1.1: None"]
            candidate["paused-exit.json"] = {"cell": "paused", "exit": 137, "oom": True}

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 1 paused-reader evpn", "FAIL", "candidate OOM")

    def test_candidate_credit_failure_survives_a_parent_oom(self):
        # The credit-bytes bar reads only the candidate.
        def mutate(parent, candidate):
            parent["paused-exit.json"] = {"cell": "paused", "exit": 137, "oom": True}
            candidate["paused-evpn.json"]["memory"]["peak_credit_bytes"] = 4 * GIB

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 1 paused-reader evpn", "FAIL", "credit bytes peak")

    def test_seeded_unexplained_exit_after_result_is_invalid(self):
        # A nonzero exit beside a result that records no failure: the run
        # failed after writing it (teardown), so the result is not evidence.
        cases = {
            "exhaust-unicast": ["cell 2 exhaustion unicast", "cell 3 unaffected peer unicast"],
            "paused": ["cell 1 paused-reader evpn"],
            "probes": ["cell 4 lag and restart probes"],
            "fill-vpn": ["cell 6 bytes per queued row"],
        }
        for cell, names in cases.items():
            for side in ("parent", "candidate"):

                def mutate(parent, candidate, cell=cell, side=side):
                    arm = parent if side == "parent" else candidate
                    arm[f"{cell}-exit.json"] = {"cell": cell, "exit": 1, "oom": False}

                with self.subTest(cell=cell, side=side):
                    results = self.run_bars(mutate)
                    for name in names:
                        self.assertEqual(results[name][0], "INVALID", results[name])
                        self.assertIn("records no failure", results[name][1])
                    others = [v for name, (v, _) in results.items() if name not in names]
                    self.assertTrue(all(v == "PASS" for v in others), results)

    def test_check_unexplained_exit_after_result_is_invalid(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "exhaust-unicast.json").write_text(json.dumps(exhaust("unicast")))
            Path(root, "exhaust-unicast-exit.json").write_text('{"exit": 1}')
            results = credit_bars.check(Path(root))
        self.assertEqual(results[0][1], "INVALID", results)

    def test_check_explicit_failure_with_exit_marker_stays_fail(self):
        with tempfile.TemporaryDirectory() as root:
            run = exhaust("unicast")
            run["checks"]["final_state_exact"] = False
            Path(root, "exhaust-unicast.json").write_text(json.dumps(run))
            Path(root, "exhaust-unicast-exit.json").write_text('{"exit": 1}')
            results = credit_bars.check(Path(root))
        self.assertEqual(results[0][1], "FAIL", results)

    def two_repetitions(self, parent, candidate, cell, file, parent_run, candidate_run):
        for arm, run in ((parent, parent_run), (candidate, candidate_run)):
            arm.setdefault(
                "provenance.jsonl", provenance("parent" if arm is parent else "candidate")
            )
            self.second_repetition(arm, [cell], **{file: run})

    def test_seeded_unavailable_fit_in_an_earlier_repetition_is_invalid(self):
        # Repetition 1 of the candidate has no fit; a good repetition 2
        # must not stand in for it.
        def mutate(parent, candidate):
            candidate["fill-evpn.json"]["estimate"]["bytes_per_queued_row"] = None
            candidate["fill-evpn-exit.json"] = {"cell": "fill-evpn", "exit": 1, "oom": False}
            self.two_repetitions(
                parent,
                candidate,
                "fill-evpn",
                "fill-evpn.json",
                fill("evpn", 240.0),
                fill("evpn", 240.0),
            )

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 6 bytes per queued row", "INVALID", "bytes_per_queued_row")

    def test_seeded_missing_row_size_in_one_repetition_is_invalid(self):
        # Cell 6 read only the last repetition, cell 1 only the first; the
        # defect sits in the one each skipped.
        for file, cell, name, bad_rep in (
            ("fill-unicast.json", "fill-unicast", "cell 6 bytes per queued row", 1),
            ("paused-evpn.json", "paused", "cell 1 paused-reader evpn", 2),
        ):

            def mutate(parent, candidate, file=file, cell=cell, bad_rep=bad_rep):
                if cell == "paused":
                    parent_run, candidate_run = paused(9 * GIB, None), paused(6 * GIB, GIB)
                else:
                    parent_run, candidate_run = fill("unicast", 240.0), fill("unicast", 240.0)
                self.two_repetitions(parent, candidate, cell, file, parent_run, candidate_run)
                del (candidate[file] if bad_rep == 1 else candidate_run)["row_size_of"]

            with self.subTest(cell=cell):
                results = self.run_bars(mutate)
                self.assert_only(results, name, "INVALID", "row_size_of")

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
