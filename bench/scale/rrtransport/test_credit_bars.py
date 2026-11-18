"""Seeded defects for the outbound-credit bars: each must turn exactly its
own cell's verdict, for its own reason, and leave every other cell PASS."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import credit_bars

GIB = 1 << 30


# The RIB's row-credit constants as the harness records them, and the fixed
# shape's per-peer credit at 153 registered peers.
ROW_CREDIT_RECORD = {
    "DAEMON_ROW_CREDIT": 16_777_216,
    "MIN_ROW_CREDIT": 8_192,
    "MAX_ROW_CREDIT": 1_048_576,
    "CHUNK_ROWS": 1_024,
}
ROW_CREDIT = 16_777_216 // 153
BYTE_CREDIT = (2 * GIB) // 153
# Every unicast receiver at its credit, and the healthy receiver's row.
FULL = {"parent": 150 * ROW_CREDIT, "candidate": 150 * 56_144 * 250}
HEALTHY = {"parent": 1, "candidate": 250}


def plateau(level, high=None, samples=100, quiet=None):
    """A plateau at `level` from 54 s to the 80 s resume; its maximum `high`
    (the healthy row's), and churn-free readings at `quiet` (the level)."""
    quiet = level if quiet is None else quiet
    return {
        "sample_interval_ms": 250.0,
        "threshold": quiet,
        "start_ms": 54_000.0,
        "end_ms": 79_900.0,
        "samples": samples,
        "min": min(level, quiet),
        "max": max(level, quiet) if high is None else high,
        "resume_issued_ms": 80_001.0,
        "quiet": {
            "churn_stopped_ms": 79_705.0,
            "churn_delivered_ms": 79_706.0,
            "published_ms": 79_727.0,
            "end_ms": 80_000.0,
            "readings": 27,
            "min": quiet,
            "max": quiet,
        },
    }


def set_level(run, level, **fields):
    run["witness"]["plateau"] = plateau(level, **fields)


def exhaust(family, recovery_ms=20_000.0, p99=5.0, gap=60.0, candidate=False):
    """An ordinary burst that filled every receiver's credit and then owed
    keys: no refusal and, on the parent, no owe-whole flip."""
    return {
        "cell": "exhaust",
        "family": family,
        "mode": "measured",
        "row_size_of": 104 if family == "unicast" else 144,
        "healthy_row_size_of": 104,
        "row_credit": dict(ROW_CREDIT_RECORD),
        "shape": dict(credit_bars.EXHAUST_SHAPE),
        "timing": {
            "release_sent_ms": 73_200.0,
            "resumed_ms": 80_006.0,
            "actual_pause_ms": 80_006.0,
            "recovery_ms": recovery_ms,
            "drain_after_resume_ms": recovery_ms / 2,
        },
        "checks": {name: True for name in credit_bars.WIRE_CHECKS},
        "witness": {
            "refused_receivers": 0,
            "owing_flips_total": 150.0 if candidate else 0.0,
            "receivers": 150,
            "peak_credit_rows": 150.0 * (56_144 if candidate else ROW_CREDIT),
            "peak_credit_bytes": 150.0 * 56_144 * 250 + 250 if candidate else None,
            "plateau": plateau(
                FULL["candidate" if candidate else "parent"],
                high=FULL["candidate"] + 250 if candidate else FULL["parent"] + 1,
            ),
        },
        "unaffected": unaffected(gap, p99),
    }


def unaffected(gap=60.0, p99=5.0):
    """The healthy receiver: its longest gap outside the churn-free window,
    which by itself held no delivery for 300 ms."""
    return {
        "injected": 1_000,
        "delivered": 1_000,
        "max_gap_ms": gap,
        "max_gap_raw_ms": 330.0,
        "quiet_excluded": {"from_ms": 79_700.0, "to_ms": 80_000.0, "span_ms": 300.0},
        "quiet_lead_ms": 300.0,
        "p99_latency_ms": p99,
    }


def histogram(above, at_most, observations=1):
    return {"observations": observations, "above_ms": above, "at_most_ms": at_most}


# Cell 7 bar 6 in rows: the bound, 150 x (credit + one 1,024-row pass).
RELEASE_ROW_BOUND = 150 * (ROW_CREDIT + 1_024)
# The held read of a clean full-shape release, as measured on a cursor-drain
# tree: rows held toward the paused receivers, the charge, and the bytes the
# sessions already encoded (writers plus the receivers' kernel queues) at
# 202 B a row. Held may exceed the charge by those bytes over 202 B.
CLEAN_HELD = 12_029_952
CLEAN_CHARGED = 9_879_552
HELD_QUEUED = 455_788_668
HELD_WRITER = 97_717_500
ROW_BYTES = 202
HELD_SLACK = HELD_QUEUED // ROW_BYTES
# The same tree with every fourth cursor envelope admitted uncharged.
QUARTER_HELD = 11_993_088
QUARTER_CHARGED = 7_382_016
QUARTER_QUEUED = 455_779_196
QUARTER_SLACK = QUARTER_QUEUED // ROW_BYTES


def held(charged=CLEAN_CHARGED, advertised=CLEAN_HELD, queued=HELD_QUEUED):
    """A held read: `advertised` rows handed toward the paused receivers,
    none read, `charged` before and after."""
    return {
        "at_ms": 29_700.0,
        "advertised_rows": advertised,
        "read_rows": 0,
        "charged_before": charged,
        "charged_after": charged,
        "writer_bytes": HELD_WRITER,
        "socket_bytes": queued - HELD_WRITER,
        "socket_ends": 300,
    }


# A byte-credit tree's constants, as a harness that records them would,
# and the release bound at its credit: 150 x (credit + one pass of
# `row_size_of` + 146 bytes a row).
BYTE_CREDIT_RECORD = {
    "DAEMON_CREDIT_BYTES": 2 * GIB,
    "MIN_CREDIT_BYTES": 2 << 20,
    "MAX_CREDIT_BYTES": 256 << 20,
}
RELEASE_BYTE_BOUND = {
    "unicast": 150 * (BYTE_CREDIT + 1_024 * 250),
    "evpn": 150 * (BYTE_CREDIT + 1_024 * 290),
}


def release(family, churn=False):
    """A clean selection release (or the same under churn) on a row-credit
    candidate: the future owed-drain step instrument, its turns, inbox round
    trips, gauges (every paused receiver at its row credit) and churn all
    inside their bars."""
    run = {
        "cell": "restart-churn" if churn else "restart",
        "family": family,
        "mode": "measured",
        "row_size_of": 104 if family == "unicast" else 144,
        "healthy_row_size_of": 104,
        "row_credit": dict(ROW_CREDIT_RECORD),
        "shape": dict(credit_bars.RELEASE_SHAPE),
        "timing": {
            "release_sent_ms": 40.0,
            "resumed_ms": 30_006.0,
            "first_eor_ms": 30_400.0,
            "last_eor_ms": 31_000.0,
        },
        "checks": {name: True for name in credit_bars.RESTART_WIRE_CHECKS},
        "wire": {
            "churn_reflected_before_eor": [0] * 150,
            "duplicates_before_eor": 0,
            "min_row_bytes": ROW_BYTES,
            "max_row_bytes": ROW_BYTES,
            "max_rows_per_update": 1,
        },
        "witness": {
            "peak_credit_rows": 150.0 * ROW_CREDIT,
            "peak_credit_bytes": None,
            "held": held(),
        },
        "actor": {
            "slice_max_us": {"actor_poll": 120_000.0, "other": 9_000.0},
            "turn_longest_ms": {"end_of_rib": histogram(100.0, 200.0)},
            "work_longest_ms": {"distribute_flush": histogram(25.0, 50.0, 400)},
            # As on main: unicast drains by cursor, EVPN whole.
            "owed_drain_step_longest_ms": {
                "cursor" if family == "unicast" else "whole": histogram(25.0, 50.0, 900)
            },
            "inbox_round_trip": {
                "probes": 2_500,
                "longest_ms": 40.0,
                "longest_sent_ms": 90.0,
                "unfinished": False,
                "cap_ms": 30_000.0,
            },
        },
        "drain_gauges": {
            "from_ms": 40.0,
            "to_ms": 33_040.0,
            "read_every_ms": 1.0,
            "reads": 30_000,
            "peak_operations_live": 0,
            "peak_credit_rows": 150 * ROW_CREDIT,
            "peak_credit_bytes": None,
        },
        "unaffected": unaffected(),
    }
    if churn:
        run["churn"] = {
            "withdrawn": 1_500,
            "re_announced": 750,
            "started_ms": 14_850.0,
            "sent_ms": 14_870.0,
        }
        run["wire"]["churn_reflected_before_eor"] = [12] * 150
    return run


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
    for family in credit_bars.FAMILIES:
        files[f"restart-{family}.json"] = release(family)
        files[f"restart-churn-{family}.json"] = release(family, True)
    return files


RELEASE_CELLS = [
    f"{kind}-{family}" for kind, _ in credit_bars.RELEASE_KINDS for family in credit_bars.FAMILIES
]
ALL_CELLS = (
    ["probes", "exhaust-unicast", "exhaust-evpn", "paused"]
    + [f"fill-{family}" for family in credit_bars.FILL_FAMILIES]
    + RELEASE_CELLS
)
CELL_COUNT = 12


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
        self.assertEqual(len(results), CELL_COUNT)
        self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)

    def test_failed_optional_release_is_visible_without_gating_campaign(self):
        def mutate(_parent, candidate):
            candidate["provenance.jsonl"] = provenance("candidate", [*ALL_CELLS, "release-timer"])
            candidate["release-timer.json"] = {
                "cell": "release-timer",
                "mode": "correctness",
                "checks": {
                    **dict.fromkeys(credit_bars.OPTIONAL_RELEASE_CHECKS, True),
                    "wire_exact": False,
                },
                "release_ms": None,
            }
            candidate["release-timer-exit.json"] = {"exit": 1}

        results = self.run_bars(mutate)
        note, detail = results.pop("candidate 1 release-timer")
        self.assertEqual(note, "REPORT")
        self.assertIn("failed checks: wire_exact", detail)
        self.assertIn("last family EoR unavailable", detail)
        self.assertTrue(all(verdict == "PASS" for verdict, _ in results.values()))

    def test_optional_release_without_provenance_is_not_reported_as_measured(self):
        def mutate(_parent, candidate):
            candidate["release-timer.json"] = {"cell": "release-timer", "release_ms": 10}

        verdict, reason = self.run_bars(mutate)["candidate 1 release-timer"]
        self.assertEqual(verdict, "REPORT")
        self.assertIn("not from a listed run", reason)

    def test_incomplete_optional_check_set_cannot_report_a_clean_release(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            path = directory / "release-mixed.json"
            path.write_text(json.dumps({
                "cell": "release-mixed",
                "checks": {"ownership": True},
                "release_ms": 1,
                "mode": "measured",
            }))
            [(_, verdict, reason)] = credit_bars.check(directory)
            self.assertEqual(verdict, "REPORT")
            self.assertIn("incomplete", reason)

    def test_missing_attempted_optional_release_stays_report_only(self):
        def mutate(parent, _candidate):
            parent["provenance.jsonl"] = provenance("parent", [*ALL_CELLS, "release-mixed"])

        verdict, reason = self.run_bars(mutate)["parent 1 release-mixed"]
        self.assertEqual(verdict, "REPORT")
        self.assertIn("attempted, no result", reason)

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

    def test_recovery_over_the_old_rule_is_report_only(self):
        def mutate(_parent, candidate):
            # Parent 20 s: the old rule is max(25 s, 22 s) = 25 s.
            candidate["exhaust-evpn.json"]["timing"]["recovery_ms"] = 25_001.0

        verdict, reason = self.run_bars(mutate)["cell 2 exhaustion evpn"]
        self.assertEqual(verdict, "PASS", reason)
        self.assertIn(
            "report-only, not a bar: recovery candidate 25001 ms vs parent 20000 ms "
            "(ratio 1.25; the old rule would allow 25000 ms)",
            reason,
        )

    def test_recovery_slack_applies_to_short_parent(self):
        def mutate(parent, candidate):
            parent["exhaust-evpn.json"]["timing"]["recovery_ms"] = 4_000.0
            candidate["exhaust-evpn.json"]["timing"]["recovery_ms"] = 5_999.0

        verdict, reason = self.run_bars(mutate)["cell 2 exhaustion evpn"]
        self.assertEqual(verdict, "PASS", reason)
        self.assertIn("the old rule would allow 6000 ms", reason)

    def test_seeded_slow_drain_after_resume(self):
        # Bar 5: absolute, every candidate run; the parent's drain is no bar.
        for drain, verdict in ((60_000.0, "PASS"), (60_001.0, "FAIL")):

            def mutate(parent, candidate, drain=drain):
                parent["exhaust-unicast.json"]["timing"]["drain_after_resume_ms"] = 90_000.0
                candidate["exhaust-unicast.json"]["timing"]["drain_after_resume_ms"] = drain

            with self.subTest(drain=drain):
                results = self.run_bars(mutate)
                if verdict == "FAIL":
                    self.assert_only(
                        results, "cell 2 exhaustion unicast", "FAIL", "drain after resume over bar"
                    )
                else:
                    self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)

    def test_seeded_slow_drain_in_a_later_repetition(self):
        def mutate(parent, candidate):
            slow = exhaust("evpn", candidate=True)
            slow["timing"]["drain_after_resume_ms"] = 61_000.0
            self.two_repetitions(
                parent, candidate, "exhaust-evpn", "exhaust-evpn.json", exhaust("evpn"), slow
            )

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 2 exhaustion evpn", "FAIL", "drain after resume 61000 ms")

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

    def witness_defect(self, side, family="unicast", level=None, **fields):
        def mutate(parent, candidate):
            arm = parent if side == "parent" else candidate
            arm[f"exhaust-{family}.json"]["witness"].update(fields)
            if level is not None:
                set_level(arm[f"exhaust-{family}.json"], level)

        return self.run_bars(mutate)

    def test_seeded_credit_never_reached(self):
        # One row (parent) or one byte (candidate) short of every receiver's
        # credit. The unaffected-peer cell reads the same run but has no
        # witness bar.
        cases = {"parent": 150.0 * ROW_CREDIT - 1, "candidate": 150.0 * BYTE_CREDIT - 1}
        for side, level in cases.items():
            with self.subTest(side=side):
                results = self.witness_defect(side, level=level)
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
                    side, "evpn", 0.0, owing_flips_total=150.0, refused_receivers=0, **fields
                )
                self.assert_only(
                    results, "cell 2 exhaustion evpn", "INVALID", "flips are not a witness"
                )

    def test_seeded_operation_refusals_are_not_a_witness(self):
        # Every receiver refused only because a whole-table operation was
        # live: the same `outbound_credit` reason, nothing charged.
        for side, gauge in (("parent", "peak_credit_rows"), ("candidate", "peak_credit_bytes")):
            with self.subTest(side=side):
                results = self.witness_defect(
                    side, level=0.0, refused_receivers=150, **{gauge: 0.0}
                )
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
        results = self.witness_defect("candidate", level=149.0 * (BYTE_CREDIT + 1_024 * 250))
        self.assert_only(
            results, "cell 2 exhaustion unicast", "INVALID", "cannot show each one reached it"
        )

    def test_seeded_credit_above_the_burst_is_invalid(self):
        # A credit larger than the 150,000-row burst: nobody reaches it, yet
        # the sum of whole bursts clears receivers x credit.
        cases = {"candidate": 150.0 * 150_000 * 250, "parent": 150.0 * 150_000}
        for side, level in cases.items():
            with self.subTest(side=side):
                results = self.witness_defect(side, level=level)
                self.assert_only(
                    results, "cell 2 exhaustion unicast", "INVALID", "more than every receiver"
                )
                self.assertIn(f"{side} run 0", results["cell 2 exhaustion unicast"][1])

    def plateau_defect(self, side, level, **fields):
        def mutate(parent, candidate):
            set_level((parent if side == "parent" else candidate)["exhaust-unicast.json"], level, **fields)

        return self.run_bars(mutate)["cell 2 exhaustion unicast"]

    def test_witness_accepts_only_every_receiver_at_its_credit(self):
        # Every receiver at ceil(credit / row) rows (unicast 56,144 x 250 B;
        # rows 109,655) at the plateau's minimum, churn-free readings
        # included, plus at most one healthy row (a unicast 250 B row) at
        # its maximum.
        for side, base in FULL.items():
            healthy = HEALTHY[side]
            for level, high, verdict in (
                (base, base, "PASS"),
                (base, base + healthy, "PASS"),
                (base - 1, base, "INVALID"),
                (base + 1, base + 1, "INVALID"),
                (base, base + healthy + 1, "INVALID"),
            ):
                with self.subTest(side=side, level=level, high=high):
                    verdict_, reason = self.plateau_defect(side, level, high=high)
                    self.assertEqual(verdict_, verdict, reason)

    def test_seeded_short_receiver_hidden_by_the_healthy_row(self):
        # 149 receivers at full credit and one a row short; the healthy row
        # charged in every sampler sample brings the sum to exactly the
        # expected plateau. Rows: 149 x 109,655 + 109,654 + 1 = 16,448,250;
        # bytes: a 250 B burst row short, a 250 B healthy row over. The
        # churn-free readings show the short sum.
        for side, base in FULL.items():
            short = base - HEALTHY[side]
            with self.subTest(side=side):
                verdict, reason = self.plateau_defect(side, base, quiet=short)
                self.assertEqual(verdict, "INVALID", reason)
                self.assertIn(f"plateau min {short} ", reason)
                self.assertIn("a receiver below its credit", reason)

    def test_seeded_plateau_min_one_row_short(self):
        # The churn-free readings are exact, but one sampler sample on the
        # plateau sits a row below: a receiver's charge fell while paused.
        for side, base in FULL.items():
            short = base - HEALTHY[side]
            with self.subTest(side=side):

                def mutate(parent, candidate, side=side, short=short):
                    run = (parent if side == "parent" else candidate)["exhaust-unicast.json"]
                    run["witness"]["plateau"]["min"] = short

                verdict, reason = self.run_bars(mutate)["cell 2 exhaustion unicast"]
                self.assertEqual(verdict, "INVALID", reason)
                self.assertIn(f"plateau min {short} ", reason)

    def test_seeded_every_reading_one_row_over(self):
        # Every reading, churn-free ones included, a row above every
        # receiver at its credit: a receiver held more than its credit.
        for side, base in FULL.items():
            with self.subTest(side=side):
                verdict, reason = self.plateau_defect(side, base + HEALTHY[side])
                self.assertEqual(verdict, "INVALID", reason)
                self.assertIn("more than every receiver at its credit", reason)

    def test_seeded_churn_free_readings_holding_the_healthy_row(self):
        # The sampler saw the exact level once, but the churn-free readings
        # still carry a healthy row: the hold separated nothing.
        for side, base in FULL.items():
            with self.subTest(side=side):
                verdict, reason = self.plateau_defect(
                    side, base, quiet=base + HEALTHY[side], high=base + HEALTHY[side]
                )
                self.assertEqual(verdict, "INVALID", reason)
                self.assertIn("churn hold did not separate the healthy row", reason)

    def test_seeded_too_few_plateau_samples(self):
        for samples, verdict in ((credit_bars.PLATEAU_MIN_SAMPLES, "PASS"), (39, "INVALID")):
            with self.subTest(samples=samples):
                verdict_, reason = self.plateau_defect(
                    "candidate", FULL["candidate"], samples=samples
                )
                self.assertEqual(verdict_, verdict, reason)
                if verdict == "INVALID":
                    self.assertIn("39 plateau samples (54000-79900 ms), fewer than 40", reason)

    def test_seeded_churn_free_window_outside_the_plateau(self):
        # Readings taken before credit was reached, after the resume was
        # issued, missing, or with the held churn row never delivered.
        cases = {
            "before": ("start_ms", 79_800.0),
            "after": ("resume_issued_ms", 79_900.0),
        }
        for name, (field, value) in cases.items():
            with self.subTest(case=name):

                def mutate(_parent, candidate, field=field, value=value):
                    candidate["exhaust-unicast.json"]["witness"]["plateau"][field] = value

                verdict, reason = self.run_bars(mutate)["cell 2 exhaustion unicast"]
                self.assertEqual(verdict, "INVALID", reason)
                self.assertIn("not inside the plateau", reason)
        for field, value in (("readings", 0), ("churn_delivered_ms", None)):
            with self.subTest(field=field):

                def mutate(_parent, candidate, field=field, value=value):
                    candidate["exhaust-unicast.json"]["witness"]["plateau"]["quiet"][field] = value

                verdict, reason = self.run_bars(mutate)["cell 2 exhaustion unicast"]
                self.assertEqual(verdict, "INVALID", reason)

    def test_seeded_one_short_receiver_masked_by_sub_row_overshoot(self):
        # 149 receivers at 56,144 unicast rows and one at 56,048: the sum is
        # exactly 150 x credit, 2,105,376,000 B.
        level = (149 * 56_144 + 56_048) * 250
        self.assertEqual(level, 150 * BYTE_CREDIT)
        results = self.witness_defect("candidate", level=float(level))
        self.assert_only(results, "cell 2 exhaustion unicast", "INVALID", "a receiver below")

    def test_healthy_row_needs_its_size(self):
        def mutate(_parent, candidate):
            del candidate["exhaust-evpn.json"]["healthy_row_size_of"]

        results = self.run_bars(mutate)
        self.assert_only(results, "cell 2 exhaustion evpn", "INVALID", "healthy_row_size_of")

    def test_seeded_burst_submission_past_the_pause_deadline_is_invalid(self):
        # The burst ended at or after the 80 s deadline; the readers stayed
        # paused until then, so the resume still follows the last send.
        for sent in (80_000.0, 95_000.0):

            def mutate(parent, candidate, sent=sent):
                # Both arms alike, so the arms' pauses agree.
                for arm in (parent, candidate):
                    arm["exhaust-unicast.json"]["timing"].update(
                        release_sent_ms=sent, resumed_ms=sent + 6.0, actual_pause_ms=sent + 6.0
                    )

            with self.subTest(sent=sent):
                results = self.run_bars(mutate)
                self.assertEqual(results["cell 2 exhaustion unicast"][0], "INVALID", results)
                self.assertIn("pause deadline", results["cell 2 exhaustion unicast"][1])

    def test_seeded_actual_pause_off_the_configured_pause_is_invalid(self):
        for actual, verdict in ((80_250.0, "PASS"), (80_251.0, "INVALID"), (79_749.0, "INVALID")):

            def mutate(parent, candidate, actual=actual):
                for arm in (parent, candidate):
                    arm["exhaust-unicast.json"]["timing"]["actual_pause_ms"] = actual

            with self.subTest(actual=actual):
                verdict_, reason = self.run_bars(mutate)["cell 2 exhaustion unicast"]
                self.assertEqual(verdict_, verdict, reason)
                if verdict == "INVALID":
                    self.assertIn("from the configured 80000 ms", reason)

    def test_seeded_arms_with_different_actual_pauses_are_invalid(self):
        # Each arm within 250 ms of 80 s, but 400 ms apart.
        def mutate(parent, candidate):
            parent["exhaust-unicast.json"]["timing"]["actual_pause_ms"] = 79_800.0
            candidate["exhaust-unicast.json"]["timing"]["actual_pause_ms"] = 80_200.0

        results = self.run_bars(mutate)
        for cell in ("cell 2 exhaustion unicast", "cell 3 unaffected peer unicast"):
            self.assertEqual(results[cell][0], "INVALID", results[cell])
            self.assertIn("actual pauses differ by 400 ms", results[cell][1])

    def test_seeded_witness_receivers_differ_from_shape(self):
        results = self.witness_defect(
            "candidate", receivers=1, peak_credit_bytes=float(BYTE_CREDIT)
        )
        self.assert_only(
            results, "cell 2 exhaustion unicast", "INVALID", "witness.receivers 1 is not"
        )

    def test_seeded_arm_identity(self):
        # A parent with the byte gauge is not the row-credit parent.
        results = self.witness_defect("parent", peak_credit_bytes=150.0 * BYTE_CREDIT)
        for cell in ("cell 2 exhaustion unicast", "cell 3 unaffected peer unicast"):
            self.assertEqual(results[cell][0], "INVALID", results[cell])
            self.assertIn("parent exhaust-unicast run 0: byte credit gauge present", results[
                cell
            ][1])
        others = [v for name, (v, _) in results.items() if "unicast" not in name]
        self.assertTrue(all(v == "PASS" for v in others), results)

    def row_candidate(self, parent, candidate):
        for family in credit_bars.FAMILIES:
            candidate[f"exhaust-{family}.json"] = exhaust(family)

    def test_result_from_an_older_harness_is_invalid(self):
        # A parent built without this harness records no row-credit
        # constants; the reason names the workflow, not a stray field.
        def mutate(parent, _candidate):
            del parent["exhaust-unicast.json"]["row_credit"]

        results = self.run_bars(mutate)
        self.assert_only(
            results,
            "cell 2 exhaustion unicast",
            "INVALID",
            "parent run 0: no row_credit record: the result is from an older harness; build "
            "both arms with this harness",
        )

    def test_row_credit_candidate_passes_cells_2_and_3(self):
        # A clean row-credit candidate (no byte gauge on either arm).
        results = self.run_bars(self.row_candidate)
        self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)

    def test_seeded_row_pair_from_one_binary_is_invalid(self):
        def mutate(parent, candidate):
            self.row_candidate(parent, candidate)
            parent["provenance.jsonl"] = provenance("same")
            candidate["provenance.jsonl"] = provenance("same")

        results = self.run_bars(mutate)
        self.assertTrue(all(v == "INVALID" for v, _ in results.values()), results)
        self.assertIn("same harness binary", results["cell 2 exhaustion unicast"][1])

    def test_seeded_swapped_arms_are_not_a_pass(self):
        # Byte candidate in the parent's place: cells 2 and 3 are INVALID.
        def swap(parent, candidate):
            for file in list(parent):
                if file.endswith(".json"):
                    parent[file], candidate[file] = candidate[file], parent[file]

        results = self.run_bars(swap)
        for family in credit_bars.FAMILIES:
            for cell in (f"cell 2 exhaustion {family}", f"cell 3 unaffected peer {family}"):
                self.assertEqual(results[cell][0], "INVALID", results[cell])
                self.assertIn("byte credit gauge present", results[cell][1])

        # A row/row pair swapped: the uncharged parent tree, judged as the
        # candidate, fails cell 7's charge witness where the candidate drains
        # by cursor (unicast); EVPN's witness is report-only.
        def uncharged_parent_swapped(parent, candidate):
            for family in credit_bars.FAMILIES:
                for kind in ("restart", "restart-churn"):
                    run = parent[f"{kind}-{family}.json"]
                    run["drain_gauges"]["peak_credit_rows"] = 0
                    run["witness"]["held"].update(charged_before=0, charged_after=0)
            swap(parent, candidate)

        results = self.run_bars(uncharged_parent_swapped)
        for kind in ("selection release", "release under churn"):
            cell = f"cell 7 {kind} unicast"
            self.assertEqual(results[cell][0], "FAIL", results[cell])
            self.assertIn("owed rows not charged", results[cell][1])
            cell = f"cell 7 {kind} evpn"
            self.assertEqual(results[cell][0], "PASS", results[cell])
            self.assertIn(
                "charge witness report-only: the run recorded only whole owed-drain steps for evpn",
                results[cell][1],
            )
            self.assertIn("would fail", results[cell][1])

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

    def test_parent_without_a_drain_time_keeps_the_report_only(self):
        # A parent built from an older harness may lack the drain; only the
        # candidate's is the bar.
        def mutate(parent, _candidate):
            parent["exhaust-evpn.json"]["timing"]["drain_after_resume_ms"] = None

        verdict, reason = self.run_bars(mutate)["cell 2 exhaustion evpn"]
        self.assertEqual(verdict, "PASS", reason)
        self.assertIn("drain after resume: not recorded in every run", reason)

    def test_seeded_later_repetition_without_witness_is_invalid(self):
        def mutate(parent, candidate):
            bad = exhaust("unicast", candidate=True)
            set_level(bad, 0.0)
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
                row = 250 if unit == "bytes" else 1
                full = -(-limit // row)
                run = exhaust("unicast", candidate=unit == "bytes")
                run["shape"].update(receivers=receivers, registered_peers=peers)
                run["witness"]["receivers"] = receivers
                set_level(run, float(receivers * full * row))
                _, verdict, reason = self.check_one(run)
                self.assertEqual(verdict, "PASS", reason)
                self.assertIn(f"{receivers} receivers x {full} rows at credit {limit}", reason)

    def test_seeded_refusals_on_too_few_receivers_are_not_a_witness(self):
        results = self.witness_defect("parent", level=0.0, refused_receivers=149)
        self.assert_only(results, "cell 2 exhaustion unicast", "INVALID", "refusals on 149/150")

    def test_seeded_byte_credit_tree_without_its_gauge_is_invalid(self):
        # Judged in rows, a byte-credit tree's rows never reach the row credit.
        run = exhaust("unicast", candidate=True)
        run["witness"]["peak_credit_bytes"] = None
        set_level(run, run["witness"]["peak_credit_rows"])
        _, verdict, reason = self.check_one(run)
        self.assertEqual(verdict, "INVALID", reason)
        self.assertIn("rows <", reason)

    def test_clean_witness_names_what_it_counted(self):
        reason = self.run_bars()["cell 2 exhaustion unicast"][1]
        self.assertIn(
            "parent credit gauge plateau 16448250-16448251 rows over 100 samples "
            "(54000-79900 ms), churn-free min 16448250 = 150 receivers x "
            f"{ROW_CREDIT} rows at credit {ROW_CREDIT} rows, max within one healthy row; "
            "peak 16448250",
            reason,
        )
        self.assertIn(
            "candidate credit gauge plateau 2105400000-2105400250 bytes over 100 samples "
            "(54000-79900 ms), churn-free min 2105400000 = 150 receivers x 56144 rows at "
            f"credit {BYTE_CREDIT} bytes, max within one healthy row; peak 2105400250",
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
                    "witness.peak_credit_bytes",
                    "healthy_row_size_of",
                    "witness.plateau.samples",
                    "witness.plateau.start_ms",
                    "witness.plateau.end_ms",
                    "witness.plateau.min",
                    "witness.plateau.max",
                    "witness.plateau.resume_issued_ms",
                    "witness.plateau.quiet.readings",
                    "witness.plateau.quiet.churn_stopped_ms",
                    "witness.plateau.quiet.churn_delivered_ms",
                    "witness.plateau.quiet.end_ms",
                    "witness.plateau.quiet.min",
                    "witness.receivers",
                    "shape.receivers",
                    "timing.release_sent_ms",
                    "timing.actual_pause_ms",
                    "shape.pause_ms",
                    "row_size_of",
                    "checks.final_state_exact",
                    "checks.one_eor_before_burst",
                    "checks.no_session_resets",
                    "timing.recovery_ms",
                    "timing.drain_after_resume_ms",
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
                    "unaffected.max_gap_raw_ms",
                    "unaffected.quiet_excluded.from_ms",
                    "unaffected.quiet_excluded.to_ms",
                    "unaffected.quiet_excluded.span_ms",
                    "unaffected.quiet_lead_ms",
                ],
            ),
            "probes.json": ("cell 4 lag and restart probes", ["mode", "probes"]),
            "fill-flowspec.json": (
                "cell 6 bytes per queued row",
                ["mode", "estimate.bytes_per_queued_row", "row_size_of"],
            ),
            "restart-unicast.json": (
                "cell 7 selection release unicast",
                [
                    "mode",
                    "shape.receivers",
                    "shape.rows_per_receiver",
                    "shape.pause_ms",
                    "shape.trigger",
                    "shape.registered_peers",
                    "checks.final_state_exact",
                    "checks.eor_after_every_route",
                    "checks.no_session_resets",
                    "actor.slice_max_us.actor_poll",
                    "actor.turn_longest_ms",
                    "actor.work_longest_ms",
                    "actor.inbox_round_trip.longest_ms",
                    "actor.inbox_round_trip.probes",
                    "actor.inbox_round_trip.unfinished",
                    "drain_gauges.peak_operations_live",
                    "drain_gauges.peak_credit_rows",
                    "drain_gauges.reads",
                    "drain_gauges.from_ms",
                    "drain_gauges.to_ms",
                    "drain_gauges.read_every_ms",
                    "row_credit.DAEMON_ROW_CREDIT",
                    "row_credit.MIN_ROW_CREDIT",
                    "row_credit.MAX_ROW_CREDIT",
                    "row_credit.CHUNK_ROWS",
                    "witness",
                    "unaffected.max_gap_ms",
                    "unaffected.quiet_excluded.span_ms",
                    "unaffected.quiet_lead_ms",
                ],
            ),
            "restart-churn-evpn.json": (
                "cell 7 release under churn evpn",
                [
                    "churn.withdrawn",
                    "churn.re_announced",
                    "churn.started_ms",
                    "churn.sent_ms",
                    "timing.release_sent_ms",
                    "timing.resumed_ms",
                    "timing.last_eor_ms",
                    "wire.churn_reflected_before_eor",
                    "drain_gauges.peak_operations_live",
                ],
            ),
            "restart-churn-unicast.json": (
                "cell 7 release owed-drain step",
                ["actor.owed_drain_step_longest_ms"],
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
        self.assertEqual(len(results), CELL_COUNT)
        failed = [name for name, (verdict, _) in results.items() if verdict == "FAIL"]
        self.assertEqual(len(failed), 5, results)

    def release_defect(self, file, change):
        def mutate(_parent, candidate):
            change(candidate[file])

        return self.run_bars(mutate)

    def test_harness_without_an_owed_drain_step_instrument_is_invalid(self):
        # What this harness records on a tree without the proposed metric.
        def change(run):
            run["actor"]["owed_drain_step_longest_ms"] = None

        # Bar 6 agrees: without the histogram it cannot tell how the
        # candidate drains the family, so the release line cannot pass.
        for file, line in (
            ("restart-evpn.json", "cell 7 selection release evpn"),
            ("restart-churn-unicast.json", "cell 7 release under churn unicast"),
        ):
            with self.subTest(file=file):
                results = self.release_defect(file, change)
                self.assertEqual(results[line][0], "INVALID", results[line])
                self.assertIn(
                    "no instrument: actor.owed_drain_step_longest_ms is null", results[line][1]
                )
                del results[line]
                self.assert_only(
                    results, "cell 7 release owed-drain step", "INVALID", "no instrument"
                )

    def test_seeded_owed_drain_step_over_50_ms(self):
        cases = (
            (histogram(50.0, 100.0), "FAIL", "step over 50 ms"),
            (histogram(25.0, 100.0), "INVALID", "bucket resolution cannot judge 50 ms"),
            (histogram(25.0, None), "INVALID", "bucket resolution cannot judge 50 ms"),
            ({}, "INVALID", "no owed-drain step observed"),
        )
        for entry, verdict, reason in cases:

            def change(run, entry=entry):
                steps = {"cursor": histogram(25.0, 50.0), "keyed": entry} if entry else {}
                run["actor"]["owed_drain_step_longest_ms"] = steps

            with self.subTest(entry=entry):
                results = self.release_defect("restart-churn-unicast.json", change)
                if entry:
                    self.assert_only(results, "cell 7 release owed-drain step", verdict, reason)
                    continue
                # No step at all: bar 6 cannot tell how the family drained.
                line = "cell 7 release under churn unicast"
                self.assertEqual(results[line][0], "INVALID", results[line])
                self.assertIn("no cursor or whole owed-drain step recorded", results[line][1])
                del results[line]
                self.assert_only(results, "cell 7 release owed-drain step", verdict, reason)

    def test_seeded_long_actor_turn(self):
        line = "cell 7 selection release unicast"
        # A poll at the bar passes every turn inside it.
        results = self.release_defect(
            "restart-unicast.json",
            lambda run: run["actor"]["slice_max_us"].update(actor_poll=250_000.0),
        )
        self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)

        def long_turn(run):
            run["actor"]["slice_max_us"]["actor_poll"] = 1_200_000.0
            run["actor"]["turn_longest_ms"]["end_of_rib"] = histogram(500.0, 1_000.0)

        results = self.release_defect("restart-unicast.json", long_turn)
        self.assert_only(results, line, "FAIL", "end_of_rib over 500 ms > 250 ms")

        def long_work_unit(run):
            run["actor"]["slice_max_us"]["actor_poll"] = 600_000.0
            run["actor"]["work_longest_ms"]["distribute_flush"] = histogram(500.0, 1_000.0)

        results = self.release_defect("restart-unicast.json", long_work_unit)
        self.assert_only(results, line, "FAIL", "distribute_flush over 500 ms")

        # A long poll whose turns all sit at or under 200 ms: no turn
        # instrument can tell, so no verdict.
        results = self.release_defect(
            "restart-unicast.json",
            lambda run: run["actor"]["slice_max_us"].update(actor_poll=250_001.0),
        )
        self.assert_only(results, line, "INVALID", "no turn is provably over it")

    def test_seeded_live_unicast_operation_during_the_drain(self):
        def change(run):
            run["drain_gauges"]["peak_operations_live"] = 1

        results = self.release_defect("restart-churn-unicast.json", change)
        self.assert_only(
            results,
            "cell 7 release under churn unicast",
            "FAIL",
            "1 live whole-table operations during the drain",
        )
        # The gauge is unlabeled and the bar names unicast: EVPN reports it.
        results = self.release_defect("restart-evpn.json", change)
        self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)
        self.assertIn(
            "live whole-table operations peak 1 (report-only",
            results["cell 7 selection release evpn"][1],
        )

    def test_evpn_on_the_cursor_gates_the_charge_witness(self):
        # A candidate that moved EVPN onto the cursor records cursor steps
        # for it, with or without a family label on the histogram: its
        # uncharged owed rows FAIL like unicast's, and its clean read passes.
        step = histogram(10.0, 25.0)
        for steps in ({"cursor": step}, {"cursor/l2vpn_evpn": step}):
            for file, line in (
                ("restart-evpn.json", "cell 7 selection release evpn"),
                ("restart-churn-evpn.json", "cell 7 release under churn evpn"),
            ):
                for record, verdict in (
                    (held(), "PASS"),
                    (held(CLEAN_HELD - HELD_SLACK - 1), "FAIL"),
                    (held(QUARTER_CHARGED, QUARTER_HELD, QUARTER_QUEUED), "FAIL"),
                ):

                    def change(run, steps=steps, record=record):
                        run["actor"]["owed_drain_step_longest_ms"] = steps
                        run["witness"]["held"] = record
                        run["drain_gauges"]["peak_credit_rows"] = record["charged_after"]

                    with self.subTest(steps=steps, file=file, charged=record["charged_after"]):
                        results = self.release_defect(file, change)
                        if verdict == "PASS":
                            self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)
                            self.assertIn(
                                "charge witness (the run recorded cursor owed-drain steps for "
                                "evpn)",
                                results[line][1],
                            )
                        else:
                            self.assert_only(results, line, "FAIL", "owed rows not charged")

        # On the cursor, EVPN keeps no whole-table operation live either.
        def live(run):
            run["actor"]["owed_drain_step_longest_ms"] = {"cursor": step}
            run["drain_gauges"]["peak_operations_live"] = 1

        results = self.release_defect("restart-evpn.json", live)
        self.assert_only(
            results, "cell 7 selection release evpn", "FAIL", "1 live whole-table operations"
        )

    def test_labeled_steps_of_another_family_do_not_decide(self):
        # A labeled histogram: unicast's cursor steps say nothing about an
        # EVPN cell whose own steps are whole.
        def change(run):
            run["actor"]["owed_drain_step_longest_ms"] = {
                "cursor/ipv4_unicast": histogram(10.0, 25.0),
                "whole/l2vpn_evpn": histogram(25.0, 50.0),
            }
            run["witness"]["held"] = held(0)

        results = self.release_defect("restart-evpn.json", change)
        self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)
        self.assertIn(
            "charge witness report-only: the run recorded only whole owed-drain steps for evpn",
            results["cell 7 selection release evpn"][1],
        )

    def test_partial_move_to_the_cursor_is_invalid(self):
        # Cursor and whole steps for the cell's family: the witness can
        # neither gate nor skip it. A FAIL elsewhere in bar 6 still stands.
        cursor, whole = histogram(10.0, 25.0), histogram(25.0, 50.0)
        for file, line, steps in (
            ("restart-evpn.json", "cell 7 selection release evpn", {"cursor": cursor, "whole": whole}),
            (
                "restart-churn-evpn.json",
                "cell 7 release under churn evpn",
                {"cursor/l2vpn_evpn": cursor, "whole/l2vpn_evpn": whole},
            ),
            (
                "restart-unicast.json",
                "cell 7 selection release unicast",
                {"cursor": cursor, "whole": whole},
            ),
        ):

            def mixed(run, steps=steps):
                run["actor"]["owed_drain_step_longest_ms"] = steps

            def over(run, steps=steps):
                mixed(run, steps)
                run["drain_gauges"]["peak_credit_rows"] = RELEASE_ROW_BOUND + 1

            with self.subTest(file=file):
                results = self.release_defect(file, mixed)
                self.assert_only(results, line, "INVALID", "partial move")
                results = self.release_defect(file, over)
                self.assert_only(results, line, "FAIL", f"> {RELEASE_ROW_BOUND}")
                self.assertIn("partial move", results[line][1])

    @staticmethod
    def byte_tree(run, peak=None, record=True):
        """`run` on a byte-credit tree: both byte peaks and, with `record`,
        the RIB's byte-credit constants."""
        bound = RELEASE_BYTE_BOUND[run["family"]]
        run["witness"]["peak_credit_bytes"] = float(bound)
        run["drain_gauges"]["peak_credit_bytes"] = bound if peak is None else peak
        if record:
            run["byte_credit"] = dict(BYTE_CREDIT_RECORD)

    def test_byte_credit_tree_takes_the_row_witness(self):
        # The witness works in rows, whose gauge keeps its meaning on a
        # byte-credit tree: an uncharged cursor row fails and a clean read
        # passes.
        for file, line in (
            ("restart-unicast.json", "cell 7 selection release unicast"),
            ("restart-churn-unicast.json", "cell 7 release under churn unicast"),
        ):
            for record, verdict in (
                (held(), "PASS"),
                (held(CLEAN_HELD - HELD_SLACK - 1), "FAIL"),
                (held(0), "FAIL"),
            ):

                def change(run, record=record):
                    self.byte_tree(run)
                    run["witness"]["held"] = record
                    run["drain_gauges"]["peak_credit_rows"] = record["charged_after"]

                with self.subTest(file=file, charged=record["charged_after"]):
                    results = self.release_defect(file, change)
                    if verdict == "PASS":
                        self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)
                        self.assertIn("charge witness (the run recorded cursor", results[line][1])
                        bound = RELEASE_BYTE_BOUND["unicast"]
                        self.assertIn(
                            f"credit bytes peak {bound} read every 1 ms (bound {bound})",
                            results[line][1],
                        )
                    else:
                        self.assert_only(results, line, "FAIL", "owed rows not charged")

        # Every candidate release cell on a byte tree; the parent arm, a
        # row-credit tree, has no byte gauge and cell 7 never reads it.
        def all_byte(_parent, candidate):
            for cell in RELEASE_CELLS:
                self.byte_tree(candidate[f"{cell}.json"])

        results = self.run_bars(all_byte)
        self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)

    def test_byte_bound_gates_only_with_its_record_and_uniform_rows(self):
        line = "cell 7 release under churn evpn"
        bound = RELEASE_BYTE_BOUND["evpn"]
        for peak in (bound, bound + 1):
            with self.subTest(peak=peak):
                results = self.release_defect(
                    "restart-churn-evpn.json", lambda run, peak=peak: self.byte_tree(run, peak)
                )
                if peak == bound:
                    self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)
                else:
                    self.assert_only(
                        results,
                        line,
                        "FAIL",
                        f"credit bytes peak {peak} > {bound} = 150 x ({BYTE_CREDIT} + 1024 x 290)",
                    )

        # Over the bound, but without the run's byte-credit record, rows of
        # one size or the 1 ms reading: report-only, never undecided.
        def no_record(run):
            self.byte_tree(run, bound + 1, record=False)

        def two_rows(run):
            self.byte_tree(run, bound + 1)
            run["wire"]["max_rows_per_update"] = 2

        def partial_record(run):
            self.byte_tree(run, bound + 1)
            del run["byte_credit"]["MIN_CREDIT_BYTES"]

        def sampler_only(run):
            self.byte_tree(run)
            del run["drain_gauges"]["peak_credit_bytes"]

        for change, reason in (
            (no_record, "byte bound report-only: no byte_credit record in the run"),
            (two_rows, "report-only: row size not uniform"),
            (partial_record, "byte bound report-only: not judged"),
            (sampler_only, "no 1 ms byte reading"),
        ):
            with self.subTest(reason=reason):
                results = self.release_defect("restart-churn-evpn.json", change)
                self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)
                self.assertIn(reason, results[line][1])

        def huge_rows(run):
            self.byte_tree(run)
            run["drain_gauges"]["peak_credit_rows"] = 10**12

        results = self.release_defect("restart-churn-evpn.json", huge_rows)
        self.assert_only(results, line, "FAIL", f"credit rows peak {10**12} > {RELEASE_ROW_BOUND}")

    def test_check_without_a_step_histogram_keeps_the_legacy_families(self):
        # `check` on a tree that predates the histogram: unicast's witness
        # still reports a verdict, EVPN's stays report-only.
        for family, expected in (
            ("unicast", "bar 6 would FAIL: run 0: owed rows not charged"),
            (
                "evpn",
                "charge witness report-only: no step histogram (a tree that predates it), "
                "where evpn drains whole: would fail",
            ),
        ):
            run = release(family)
            run["mode"] = "correctness"
            run["actor"]["owed_drain_step_longest_ms"] = None
            run["witness"]["held"] = held(0)
            with tempfile.TemporaryDirectory() as root:
                Path(root, f"restart-{family}.json").write_text(json.dumps(run))
                ((_, verdict, reason),) = credit_bars.check(Path(root))
            with self.subTest(family=family):
                self.assertEqual(verdict, "PASS", reason)
                self.assertIn(expected, reason)

    def test_release_credit_bound_on_a_row_credit_tree(self):
        # Without the byte gauge the bound is in rows, from the getter peak.
        for peak, verdict in ((RELEASE_ROW_BOUND, "PASS"), (RELEASE_ROW_BOUND + 1, "FAIL")):

            def change(run, peak=peak):
                run["drain_gauges"]["peak_credit_rows"] = peak

            with self.subTest(peak=peak):
                results = self.release_defect("restart-unicast.json", change)
                self.assertEqual(results["cell 7 selection release unicast"][0], verdict, results)

    def test_seeded_uncharged_owed_rows_fail(self):
        # Held toward the paused receivers against charged, whatever the
        # peak: the measured clean read passes; the measured read with
        # every fourth cursor envelope uncharged, or nothing charged, fails.
        cases = (
            (held(), "PASS"),
            (held(QUARTER_CHARGED, QUARTER_HELD, QUARTER_QUEUED), "FAIL"),
            (held(0), "FAIL"),
            # The slack boundary: held may exceed the charge by the slack.
            (held(CLEAN_HELD - HELD_SLACK), "PASS"),
            (held(CLEAN_HELD - HELD_SLACK - 1), "FAIL"),
        )
        for file in ("restart-unicast.json", "restart-churn-unicast.json"):
            line = "cell 7 " + (
                "release under churn unicast" if "churn" in file else "selection release unicast"
            )
            for record, verdict in cases:

                def change(run, record=record):
                    run["witness"]["held"] = record
                    run["drain_gauges"]["peak_credit_rows"] = record["charged_after"]

                with self.subTest(file=file, record=record):
                    results = self.release_defect(file, change)
                    if verdict == "PASS":
                        self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)
                        self.assertIn("report-only: credit not reached", results[line][1])
                    else:
                        self.assert_only(results, line, "FAIL", "owed rows not charged")
        # The arithmetic is in the line: no churn or pass term in the slack.
        results = self.release_defect(
            "restart-churn-unicast.json",
            lambda run: run["witness"].update(
                held=held(QUARTER_CHARGED, QUARTER_HELD, QUARTER_QUEUED)
            ),
        )
        gap = QUARTER_HELD - QUARTER_CHARGED
        self.assertIn(
            f"held exceeds charged by {gap} > slack (held {QUARTER_HELD} = {QUARTER_HELD} "
            f"advertised - 0 read, charged {QUARTER_CHARGED}; slack {QUARTER_SLACK} = "
            f"{QUARTER_QUEUED} queued bytes / 202 B a row)",
            results["cell 7 release under churn unicast"][1],
        )
        margin = HELD_SLACK - (CLEAN_HELD - CLEAN_CHARGED)
        results = self.run_bars()
        self.assertIn(f"margin {margin}", results["cell 7 selection release unicast"][1])

    def test_held_read_without_power_or_uniform_rows_is_invalid(self):
        line = "cell 7 selection release unicast"
        cases = (
            # Nothing staged, or held within the slack: a missing charge
            # cannot show.
            (lambda run: run["witness"].update(held=held(0, 0, 0)), "has no power"),
            (lambda run: run["witness"].update(held=held(0, HELD_SLACK)), "has no power"),
            # Rows sharing an UPDATE, or of different sizes, make the
            # divisor no one row's size.
            (lambda run: run["wire"].update(max_rows_per_update=2), "row size not uniform"),
            (lambda run: run["wire"].update(max_row_bytes=205), "row size not uniform"),
            (lambda run: run["wire"].update(min_row_bytes=70), "row size not uniform"),
            # The read timed out.
            (
                lambda run: run["witness"].update(held={"unavailable": "no reply within 5000 ms"}),
                "held read unavailable: no reply within 5000 ms",
            ),
            # The kernel queues of no connection, or of the wrong ones.
            (lambda run: run["witness"]["held"].update(socket_ends=0), "connection ends"),
            (lambda run: run["witness"]["held"].update(socket_ends=301), "connection ends"),
            (lambda run: run["witness"]["held"].update(socket_bytes=None), "socket_bytes"),
        )
        for change, reason in cases:
            with self.subTest(reason=reason):
                results = self.release_defect("restart-unicast.json", change)
                self.assert_only(results, line, "INVALID", reason)
        # One row over the slack has power (and, uncharged, fails); a 1%
        # spread of row sizes is uniform.
        results = self.release_defect(
            "restart-unicast.json", lambda run: run["witness"].update(held=held(0, HELD_SLACK + 1))
        )
        self.assert_only(results, line, "FAIL", "owed rows not charged")
        results = self.release_defect(
            "restart-unicast.json", lambda run: run["wire"].update(max_row_bytes=204)
        )
        self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)

    def test_evpn_charge_witness_is_report_only(self):
        # EVPN is not drained by cursor: nothing charged, an idle read or a
        # missing read leaves the line as its other bars say.
        for change in (
            lambda run: run["witness"].update(held=held(0)),
            lambda run: run["witness"].update(held=held(0, 0, 0)),
            lambda run: run["witness"].pop("held"),
        ):
            results = self.release_defect("restart-evpn.json", change)
            verdict, reason = results["cell 7 selection release evpn"]
            self.assertEqual(verdict, "PASS", reason)
            self.assertIn(
                "charge witness report-only: the run recorded only whole owed-drain steps for "
                "evpn, whose whole-table operations charge no rows by design",
                reason,
            )

    def test_held_read_must_be_tight_and_inside_the_pause(self):
        line = "cell 7 selection release unicast"
        spread = 150 * 1_024
        for change, reason in (
            (lambda h: h.update(charged_before=h["charged_after"] - spread - 1), "not tight"),
            # A charge that fell across the read: as loose as one that rose.
            (lambda h: h.update(charged_before=h["charged_after"] + spread + 1), "not tight"),
            (lambda h: h.update(at_ms=30_006.0), "not between"),
            (lambda h: h.update(at_ms=39.0), "not between"),
        ):

            def mutate(run, change=change):
                change(run["witness"]["held"])

            with self.subTest(reason=reason):
                results = self.release_defect("restart-unicast.json", mutate)
                self.assert_only(results, line, "INVALID", reason)
        # A spread of exactly one pass a receiver, either way, is tight.
        for sign in (-1, 1):
            results = self.release_defect(
                "restart-unicast.json",
                lambda run, sign=sign: run["witness"]["held"].update(
                    charged_before=run["witness"]["held"]["charged_after"] + sign * spread
                ),
            )
            self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)

    def test_charged_peak_short_of_the_credit_passes_alone(self):
        # The witness on one run: a charged drain short of the credit
        # passes, a peak over the upper bound fails, and a run without each
        # held field is INVALID.
        run = credit_bars.measured([release("unicast", churn=True)], "run")[0]
        for peak, failed in ((CLEAN_CHARGED, False), (RELEASE_ROW_BOUND + 1, True)):
            run["drain_gauges"]["peak_credit_rows"] = peak
            with self.subTest(peak=peak):
                failure, undecided, _ = credit_bars.credit_bar(run, "run", "unicast")
                self.assertIsNone(undecided)
                self.assertEqual(failure is not None, failed, failure)
        fields = [f"witness.held.{key}" for key in held()] + [
            "witness.held",
            "wire.min_row_bytes",
            "wire.max_row_bytes",
            "wire.max_rows_per_update",
        ]
        # A run without the held read still fails the upper bound.
        missing = copy.deepcopy(run)
        missing["drain_gauges"]["peak_credit_rows"] = RELEASE_ROW_BOUND + 1
        del missing["witness"]["held"]
        failure, undecided, _ = credit_bars.credit_bar(missing, "run", "unicast")
        self.assertIn(f"> {RELEASE_ROW_BOUND}", failure)
        self.assertIn("witness.held", undecided)
        run["drain_gauges"]["peak_credit_rows"] = CLEAN_CHARGED
        for field in fields:
            missing = copy.deepcopy(run)
            *parents, leaf = field.split(".")
            node = missing
            for key in parents:
                node = node[key]
            del node[leaf]
            with self.subTest(missing=field):
                failure, undecided, _ = credit_bars.credit_bar(missing, "run", "unicast")
                self.assertIsNone(failure)
                self.assertIn(field, undecided)

    def test_seeded_dead_gauge_watch_is_invalid(self):
        # 33,000 ms watched at 1 ms: at least 16,500 reads.
        line = "cell 7 selection release evpn"
        for reads, verdict in ((0, "INVALID"), (16_499, "INVALID"), (16_500, "PASS")):

            def change(run, reads=reads):
                run["drain_gauges"]["reads"] = reads

            with self.subTest(reads=reads):
                results = self.release_defect("restart-evpn.json", change)
                if verdict == "PASS":
                    self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)
                else:
                    self.assert_only(results, line, "INVALID", "the gauge watch did not run")

    def test_reduced_release_reports_the_charge_witness(self):
        # The reduced shape, judged by `check`: bar 6 is reported, never
        # gated. A whole-table release charges nothing: 8,192 rows held,
        # 827,415 bytes in the kernel queues at 202 B a row (4,096 rows).
        run = release("unicast")
        run["mode"] = "correctness"
        run["shape"].update(receivers=4, rows_per_receiver=4_096, registered_peers=7)
        run["drain_gauges"].update(peak_credit_rows=0, peak_operations_live=0)
        run["witness"]["held"] = {
            "at_ms": 204.0,
            "advertised_rows": 8_192,
            "read_rows": 0,
            "charged_before": 0,
            "charged_after": 0,
            "writer_bytes": 0,
            "socket_bytes": 827_415,
            "socket_ends": 8,
        }
        with tempfile.TemporaryDirectory() as root:
            Path(root, "restart-unicast.json").write_text(json.dumps(run))
            ((_, verdict, reason),) = credit_bars.check(Path(root))
        self.assertEqual(verdict, "PASS", reason)
        self.assertIn(
            "bar 6 would FAIL: run 0: owed rows not charged: held exceeds charged by 8192 > "
            "slack (held 8192 = 8192 advertised - 0 read, charged 0; slack 4096 = 827415 queued "
            "bytes / 202 B a row)",
            reason,
        )

    def test_seeded_release_wire_defect_and_gap(self):
        def wire(run):
            run["checks"]["eor_after_every_route"] = False

        results = self.release_defect("restart-evpn.json", wire)
        self.assert_only(
            results, "cell 7 selection release evpn", "FAIL", "eor_after_every_route failed"
        )

        def gap(run):
            run["unaffected"]["max_gap_ms"] = 1_001.0

        results = self.release_defect("restart-churn-evpn.json", gap)
        self.assert_only(
            results, "cell 7 release under churn evpn", "FAIL", "healthy delivery gap 1001 ms"
        )

    def test_seeded_churn_outside_the_drain_is_invalid(self):
        cases = {
            "before the release": ({"started_ms": 30.0}, "not between the 40 ms release"),
            "after the resume": ({"sent_ms": 30_500.0}, "and the 30006 ms resume"),
            "no withdrawal": ({"withdrawn": 0}, "needs both"),
            "no re-announcement": ({"re_announced": 0}, "needs both"),
        }
        for name, (fields, reason) in cases.items():

            def change(run, fields=fields):
                run["churn"].update(fields)

            with self.subTest(name):
                results = self.release_defect("restart-churn-unicast.json", change)
                self.assert_only(results, "cell 7 release under churn unicast", "INVALID", reason)

    def test_seeded_churn_behind_the_whole_release_is_invalid(self):
        # Every churned row reached one receiver only after its End-of-RIB
        # (the release had sent the table before the churn reached the RIB).
        def change(run):
            run["wire"]["churn_reflected_before_eor"][149] = 0

        results = self.release_defect("restart-churn-evpn.json", change)
        self.assert_only(
            results,
            "cell 7 release under churn evpn",
            "INVALID",
            "churn did not land in the drain: churned routes already in their post-churn state "
            "before the End-of-RIB on 149/150 receivers (fewest 0)",
        )

    def test_churn_witness_is_report_only_off_the_full_shape(self):
        run = release("unicast", churn=True)
        run["mode"] = "correctness"
        run["shape"].update(receivers=4, rows_per_receiver=4_096, registered_peers=7)
        run["wire"]["churn_reflected_before_eor"] = [0, 0, 0, 0]
        with tempfile.TemporaryDirectory() as root:
            Path(root, "restart-churn-unicast.json").write_text(json.dumps(run))
            ((_, verdict, reason),) = credit_bars.check(Path(root))
        self.assertEqual(verdict, "PASS", reason)
        self.assertIn("on 0/4 receivers (fewest 0) (report-only: not the full shape)", reason)
        self.assertIn("duplicate announcements before the End-of-RIB 0 (report-only)", reason)

    def test_correctness_release_run_is_not_a_measurement(self):
        def change(run):
            run["mode"] = "correctness"

        results = self.release_defect("restart-evpn.json", change)
        self.assertEqual(results["cell 7 selection release evpn"][0], "INVALID")
        self.assertEqual(results["cell 7 release owed-drain step"][0], "INVALID")

    def test_check_reads_the_churn_variant(self):
        run = release("unicast", churn=True)
        run["mode"] = "correctness"
        run["actor"]["owed_drain_step_longest_ms"] = None
        with tempfile.TemporaryDirectory() as root:
            Path(root, "restart-churn-unicast.json").write_text(json.dumps(run))
            (name, verdict, reason), = credit_bars.check(Path(root))
            self.assertEqual((name, verdict), ("restart burst under churn unicast", "PASS"))
            self.assertIn(
                "between the release (40 ms) and the resume (30006 ms); churned routes already "
                "in their post-churn state before the End-of-RIB on 150/150 receivers (fewest 12)",
                reason,
            )
            self.assertIn("bar 2 within: longest actor poll 120.0 ms", reason)
            self.assertIn("owed-drain step no instrument", reason)
            run["churn"]["sent_ms"] = 31_000.0
            Path(root, "restart-churn-unicast.json").write_text(json.dumps(run))
            (_, verdict, reason), = credit_bars.check(Path(root))
            self.assertEqual(verdict, "INVALID", reason)

    def test_excluded_churn_free_window_is_reported(self):
        verdict, reason = self.run_bars()["cell 3 unaffected peer unicast"]
        self.assertEqual(verdict, "PASS", reason)
        self.assertIn(
            "max gap 60 ms (330 ms before excluding the 300 ms churn-free window "
            "79700-80000 ms)",
            reason,
        )

    def test_seeded_dead_turn_instruments_are_invalid(self):
        line = "cell 7 selection release unicast"
        cases = {
            "poll never read": (lambda a: a["slice_max_us"].update(actor_poll=0.0), "dead instrument"),
            "probe never ran": (
                lambda a: a["inbox_round_trip"].update(probes=0, longest_ms=0.0),
                "dead instrument",
            ),
            "no end_of_rib turn": (
                lambda a: a.update(turn_longest_ms={}, work_longest_ms={}),
                "no end_of_rib turn observed",
            ),
        }
        for name, (change, reason) in cases.items():
            with self.subTest(name):
                results = self.release_defect(
                    "restart-unicast.json", lambda run, change=change: change(run["actor"])
                )
                self.assert_only(results, line, "INVALID", reason)

    def test_seeded_inbox_round_trip_over_the_turn_bar(self):
        # The poll within 250 ms cannot see a drain that yields between
        # steps without serving the update channel; the probe can.
        line = "cell 7 release under churn unicast"
        for trip, verdict in ((250.0, "PASS"), (250.1, "INVALID")):

            def change(run, trip=trip):
                run["actor"]["inbox_round_trip"]["longest_ms"] = trip

            with self.subTest(trip=trip):
                results = self.release_defect("restart-churn-unicast.json", change)
                if verdict == "PASS":
                    self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)
                else:
                    self.assert_only(results, line, "INVALID", "instruments disagree")

    def test_seeded_unfinished_round_trip_probe(self):
        # A probe the RIB never answered within its 30 s cap: over the turn
        # bar, so bar 2 cannot pass; a turn provably over it still fails.
        # The flag decides even beside a short recorded wait.
        line = "cell 7 selection release evpn"

        def unanswered(run, trip=30_000.0):
            run["actor"]["inbox_round_trip"].update(unfinished=True, longest_ms=trip)

        for trip in (30_000.0, 40.0):
            with self.subTest(trip=trip):
                results = self.release_defect(
                    "restart-evpn.json", lambda run, trip=trip: unanswered(run, trip)
                )
                self.assert_only(results, line, "INVALID", "probe unfinished")

        def unanswered_long_turn(run):
            unanswered(run)
            run["actor"]["turn_longest_ms"]["end_of_rib"] = histogram(500.0, 1_000.0)

        results = self.release_defect("restart-evpn.json", unanswered_long_turn)
        self.assert_only(results, line, "FAIL", "end_of_rib over 500 ms > 250 ms")

    def test_seeded_bar_fail_outranks_an_unusable_repetition(self):
        # Repetition 1 fails bar 4; repetition 2 left no result or a result
        # of the wrong shape. The FAIL stands.
        line = "cell 7 selection release unicast"
        cases = {"missing": None, "wrong shape": release("unicast")}
        cases["wrong shape"]["shape"]["receivers"] = 4
        reasons = {"missing": "restart-unicast attempted, no result", "wrong shape": "shape.receivers"}
        for name, second in cases.items():

            def mutate(_parent, candidate, second=second):
                candidate["restart-unicast.json"]["unaffected"]["max_gap_ms"] = 5_000.0
                candidate.setdefault("provenance.jsonl", provenance("candidate"))
                self.second_repetition(
                    candidate, ["restart-unicast"], **{"restart-unicast.json": second}
                )

            with self.subTest(name):
                results = self.run_bars(mutate)
                verdict, reason = results[line]
                self.assertEqual(verdict, "FAIL", reason)
                self.assertIn("run 0: healthy delivery gap 5000 ms", reason)
                self.assertIn(reasons[name], reason)

    def test_seeded_step_fail_outranks_an_absent_release_cell(self):
        def mutate(_parent, candidate):
            candidate["restart-evpn.json"]["actor"]["owed_drain_step_longest_ms"] = {
                "whole": histogram(50.0, 100.0)
            }
            candidate["restart-unicast.json"] = None

        results = self.run_bars(mutate)
        verdict, reason = results["cell 7 release owed-drain step"]
        self.assertEqual(verdict, "FAIL", reason)
        self.assertIn("candidate restart-evpn run 0: whole step over 50 ms", reason)
        self.assertIn("restart-unicast attempted, no result", reason)
        self.assertEqual(results["cell 7 selection release unicast"][0], "INVALID")

    def test_missing_repetition_never_passes_cell_7(self):
        # Every usable run passes; repetition 2 attempted the cell and left
        # nothing.
        def mutate(_parent, candidate):
            candidate.setdefault("provenance.jsonl", provenance("candidate"))
            self.second_repetition(candidate, ["restart-churn-evpn"])

        results = self.run_bars(mutate)
        for line in ("cell 7 release under churn evpn", "cell 7 release owed-drain step"):
            verdict, reason = results[line]
            self.assertEqual(verdict, "INVALID", reason)
            self.assertIn("repetition 2: restart-churn-evpn attempted, no result", reason)

    def test_seeded_wide_excluded_window_is_invalid(self):
        # 300 ms configured: up to 600 ms excluded.
        for span, verdict in ((600.0, "PASS"), (601.0, "INVALID")):

            def change(run, span=span):
                run["unaffected"]["quiet_excluded"]["span_ms"] = span

            with self.subTest(span=span):
                results = self.release_defect("restart-unicast.json", change)
                cell = "cell 7 selection release unicast"
                if verdict == "PASS":
                    self.assertTrue(all(v == "PASS" for v, _ in results.values()), results)
                else:
                    self.assert_only(results, cell, "INVALID", "it could hide a stall")

    def test_nothing_excluded_when_the_held_churn_row_never_arrived(self):
        cell = "cell 7 selection release evpn"
        for gap, verdict in ((330.0, "PASS"), (60.0, "INVALID")):

            def change(run, gap=gap):
                run["unaffected"].update(quiet_excluded=None, max_gap_ms=gap)

            with self.subTest(gap=gap):
                results = self.release_defect("restart-evpn.json", change)
                self.assertEqual(results[cell][0], verdict, results[cell])

    def test_unavailable_churn_free_window_is_invalid(self):
        # The raw gap would pass with nothing excluded; an unavailable
        # window must not read as that.
        why = "no RIB reply within 5000 ms of the window's end"

        def change(run):
            run["unaffected"].update(
                quiet_excluded={"unavailable": why}, max_gap_ms=330.0, max_gap_raw_ms=330.0
            )

        results = self.release_defect("restart-evpn.json", change)
        cell = "cell 7 selection release evpn"
        self.assert_only(results, cell, "INVALID", f"churn-free window unavailable: {why}")

    def test_seeded_fail_outranks_another_runs_missing_instrument(self):
        def mutate(parent, candidate):
            for arm in (parent, candidate):
                arm["provenance.jsonl"] = provenance(
                    "parent" if arm is parent else "candidate"
                ) + []
            bad_gap = release("unicast")
            bad_gap["unaffected"]["max_gap_ms"] = 5_000.0
            no_poll = release("unicast")
            del no_poll["actor"]["slice_max_us"]["actor_poll"]
            no_poll["actor"]["owed_drain_step_longest_ms"] = None
            candidate["restart-unicast.json"] = bad_gap
            candidate["restart-evpn.json"]["actor"]["owed_drain_step_longest_ms"] = {
                "whole": histogram(50.0, 100.0)
            }
            self.second_repetition(parent, ["restart-unicast"])
            self.second_repetition(candidate, ["restart-unicast"], **{"restart-unicast.json": no_poll})

        results = self.run_bars(mutate)
        verdict, reason = results["cell 7 selection release unicast"]
        self.assertEqual(verdict, "FAIL", reason)
        self.assertIn("run 0: healthy delivery gap 5000 ms", reason)
        self.assertIn("run 1: actor.slice_max_us.actor_poll", reason)
        verdict, reason = results["cell 7 release owed-drain step"]
        self.assertEqual(verdict, "FAIL", reason)
        self.assertIn("no instrument", reason)

    def test_seeded_non_object_witness_is_invalid(self):
        for file, cell in (
            ("restart-unicast.json", "cell 7 selection release unicast"),
            ("exhaust-evpn.json", "cell 2 exhaustion evpn"),
        ):
            for side in ("parent", "candidate"):
                if side == "parent" and file.startswith("restart"):
                    continue

                def mutate(parent, candidate, file=file, side=side):
                    (parent if side == "parent" else candidate)[file]["witness"] = 5

                with self.subTest(file=file, side=side):
                    results = self.run_bars(mutate)
                    self.assertEqual(results[cell][0], "INVALID", results[cell])
                    # Cell 7 names the malformed object; cell 2 its first
                    # missing field under it.
                    self.assertIn("witness", results[cell][1])

    def test_exit_status(self):
        self.assertEqual(credit_bars.report([("a", "PASS", "")]), 0)
        self.assertEqual(credit_bars.report([("a", "PASS", ""), ("b", "INVALID", "")]), 2)
        self.assertEqual(credit_bars.report([("a", "FAIL", ""), ("b", "INVALID", "")]), 1)


if __name__ == "__main__":
    unittest.main()
