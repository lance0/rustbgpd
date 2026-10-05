#!/usr/bin/env python3
"""Tests for the headline campaign driver and its extractor.

The extractor must reproduce the committed headline receipts: every
summary.csv row, and the medians the receipt tables publish. The daemon
reload intervals come from daemon logs, which the bundles do not carry, so
they are checked against a stubbed log. A finished leg
missing a labelled value must fail extraction instead of dropping a row. The
campaign must fail closed: a failed build, a daemon whose hash depends on the
commit, or a failed leg ends with a non-zero exit status.

Run: python3 -m unittest -v bench/scale/headline/test_headline.py
"""

import contextlib
import csv
import io
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE))
import summarize  # noqa: E402

ARTIFACTS = REPO / "docs/perf/artifacts"
V0720 = ARTIFACTS / "headline-refresh-v0720-2026-09"
V0730 = ARTIFACTS / "headline-refresh-v0730-2026-09"
V0740 = ARTIFACTS / "cross-daemon-v0740-2026-10"
# The first lines of a competitor's daemon.log, as run-matrix.sh records it.
BIRD_LOG = "bird: 2026-10-04 01:56:55.742 [0000] <INFO> Started\nbird: 2026-10-04 01:58:41.541 [0000] <INFO> Reconfiguring\n"


def summary_rows(path, names):
    rows = list(csv.reader(path.read_text().splitlines()))[1:]
    return sorted((r[0], names.get(r[1], r[1]), *r[2:]) for r in rows)


def quiet_main(argv):
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return summarize.main(argv)


def medians(source, excludes=()):
    rows, spans, _ = summarize.extract(source, excludes)
    table = summarize.aggregate(rows, spans)
    return {key: {arm: statistics.median(v) for arm, v in cells.items()} for key, cells in table.items()}


class ReceiptReproduction(unittest.TestCase):
    """Published medians, as (phase, metric) -> {arm: (value, decimals)}."""

    def assert_published(self, got, published):
        for key, arms in published.items():
            for arm, (value, decimals) in arms.items():
                with self.subTest(cell=key, arm=arm):
                    self.assertAlmostEqual(got[key][arm], value, delta=0.5 * 10**-decimals + 1e-9)

    def test_v0720_summary_rows(self):
        names = {"ctrl": "v0.72.0", "cand": "main-33f8e7142"}
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(quiet_main([str(V0720), "--out", out]), 0)
            self.assertEqual(summary_rows(Path(out) / "summary.csv", names),
                             summary_rows(V0720 / "summary.csv", {}))

    def test_v0720_published_medians(self):
        self.assert_published(medians(V0720), {
            ("matrix-s1", "cold_convergence"): {"ctrl": (3.6, 1), "cand": (3.9, 1)},
            ("matrix-s2", "reload_completion_p50"): {"ctrl": (1.50, 2), "cand": (1.52, 2)},
            ("matrix-s2", "reload_changed_maxgap_p50"): {"ctrl": (499, 0), "cand": (527, 0)},
            ("matrix-s3", "flap_withdraw_p50"): {"ctrl": (0.37, 2), "cand": (0.39, 2)},
            ("matrix-s3", "flap_reannounce_p50"): {"ctrl": (0.50, 2), "cand": (0.52, 2)},
            ("matrix-s3", "flap_post_round_rss"): {"ctrl": (410, 0), "cand": (408, 0)},
            ("irr-ov0", "completion_p50"): {"ctrl": (1.282, 3), "cand": (1.267, 3)},
            ("irr-ov0", "changed_maxgap_p50"): {"ctrl": (534, 0), "cand": (510, 0)},
            ("rr1000", "staged_ms"): {"ctrl": (298, 0), "cand": (312, 0)},
            ("rr1000", "wire_ms"): {"ctrl": (339, 0), "cand": (346, 0)},
            ("rr1000", "wire_vmrss"): {"ctrl": (394878, 0), "cand": (407208, 0)},
        })

    def test_v0730_summary_rows(self):
        names = {"v0730": "v0.73.0", "v0720": "v0.72.0", "v0680": "v0.68.0",
                 "xh": "v0.68.0-daemon/v0.72.0-harness"}
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(quiet_main([str(V0730), "--out", out]), 0)
            self.assertEqual(summary_rows(Path(out) / "summary.csv", names),
                             summary_rows(V0730 / "summary.csv", {}))

    def test_v0730_published_medians(self):
        # The v0.68.0 column is its main-block runs 1-3.
        self.assert_published(medians(V0730, ["matrix-v0680-r[456]-*"]), {
            ("matrix-s1", "cold_convergence"): {"v0730": (3.0, 1), "v0720": (3.7, 1), "v0680": (3.5, 1)},
            ("matrix-s2", "reload_completion_p50"): {"v0730": (1.47, 2), "v0720": (1.52, 2), "v0680": (1.32, 2)},
            ("matrix-s2", "reload_changed_maxgap_p50"): {"v0730": (587, 0), "v0720": (536, 0), "v0680": (495, 0)},
            ("matrix-s3", "flap_withdraw_p50"): {"v0730": (0.28, 2), "v0720": (0.32, 2), "v0680": (0.36, 2)},
            ("matrix-s3", "flap_reannounce_p50"): {"v0730": (0.38, 2), "v0720": (0.51, 2), "v0680": (0.38, 2)},
            ("matrix-s3", "flap_post_round_rss"): {"v0730": (476, 0), "v0720": (410, 0), "v0680": (404, 0)},
            ("irr-ov0", "completion_p50"): {"v0730": (1.382, 3), "v0720": (1.273, 3), "v0680": (0.897, 3)},
            ("irr-ov0", "changed_maxgap_p50"): {"v0730": (555, 0), "v0720": (515, 0), "v0680": (442, 0)},
            ("rr1000", "injection_ms"): {"v0730": (17, 0), "v0720": (37, 0), "v0680": (35, 0)},
            ("rr1000", "staged_ms"): {"v0730": (298, 0), "v0720": (304, 0), "v0680": (305, 0)},
            ("rr1000", "wire_ms"): {"v0730": (318, 0), "v0720": (341, 0), "v0680": (335, 0)},
            ("rr1000", "wire_vmrss"): {"v0730": (366344, 0), "v0720": (396360, 0), "v0680": (405280, 0)},
        })
        # Cross-harness block: the interleaved v0.68.0 runs 4-6, less the one
        # leg another workload overlapped, against the cross-harness arm.
        self.assert_published(medians(V0730, ["matrix-v0680-r[123]-*", "matrix-v0680-r6-s2"]), {
            ("matrix-s1", "cold_convergence"): {"v0680": (3.4, 1), "xh": (3.4, 1)},
            ("matrix-s2", "reload_completion_p50"): {"v0680": (1.33, 2), "xh": (1.44, 2)},
            ("matrix-s2", "reload_changed_maxgap_p50"): {"v0680": (562, 0), "xh": (666, 0)},
            ("matrix-s3", "flap_reannounce_p50"): {"v0680": (0.37, 2), "xh": (0.37, 2)},
        })


def daemon_log(reloads, complete="config reload complete (one runtime generation)", drop=()):
    """A daemon JSON log with RELOADS SIGHUP reloads: loaded at +100 ms, complete at +1,199 ms.

    DROP holds (reload, part) pairs to leave out: part is "loaded", "validate" or "rib"."""
    def record(stamp, message, **fields):
        return json.dumps({"timestamp": f"2026-09-28T01:{stamp}Z", "fields": {"message": message, **fields}}) + "\n"
    lines = [record("00:00.000000", "session established")]
    for minute in range(1, reloads + 1):
        lines.append(record(f"{minute:02d}:00.000000", "SIGHUP received, reloading configuration"))
        if (minute, "loaded") not in drop:
            validate = {} if (minute, "validate") in drop else {"validate_ms": 84}
            lines.append(record(f"{minute:02d}:00.100000", "config source loaded", **validate))
        if (minute, "rib") not in drop:
            lines.append(record(f"{minute:02d}:00.900000", "reload generation phase timing",
                                cohort_rib_transition_us=581000))
        lines.append(record(f"{minute:02d}:01.199000", complete))
    return "".join(lines)


def matrix_leg(root, name, scenario="s2"):
    """Copy one committed v0.72.0 matrix leg into campaign layout."""
    source = V0720 / "matrix" / f"matrix-ctrl-r1-{scenario}"
    cell = root / name / "rustbgpd"
    shutil.copytree(source, cell)
    return cell


class ExtractorFailsClosed(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def run_main(self):
        return quiet_main([str(self.tmp), "--out", str(self.tmp / "out")])

    def test_campaign_layout_extracts(self):
        matrix_leg(self.tmp, "matrix-a-r1-s2")
        matrix_leg(self.tmp, "matrix-a-r1-s3", "s3")
        self.assertEqual(self.run_main(), 0)
        table = medians(self.tmp)
        self.assertEqual(len(summarize.aggregate(*summarize.extract(self.tmp)[:2])[("matrix-s1", "established")]["a"]), 2)
        self.assertIn(("matrix-s3", "flap_reannounce_p50"), table)

    def test_renamed_label_fails(self):
        cell = matrix_leg(self.tmp, "matrix-a-r1-s2")
        log = cell / "reloadstall.log"
        log.write_text(log.read_text().replace("completion_s:", "completion_secs:"))
        with self.assertRaisesRegex(summarize.ExtractionError, "reload_completion_p50"):
            summarize.extract(self.tmp)
        self.assertEqual(self.run_main(), 1)

    def test_missing_established_line_fails(self):
        cell = matrix_leg(self.tmp, "matrix-a-r1-s2")
        log = cell / "reloadstall.log"
        log.write_text("".join(l for l in log.read_text().splitlines(True) if not l.startswith("established ")))
        (cell / "daemon.log").write_text("")
        with self.assertRaisesRegex(summarize.ExtractionError, "matrix-a-r1-s2: .*'established'"):
            summarize.extract(self.tmp)
        self.assertEqual(self.run_main(), 1)

    def test_unequal_flap_counts_fail(self):
        cell = matrix_leg(self.tmp, "matrix-a-r1-s3", "s3")
        log = cell / "reloadstall.log"
        lines = [line for line in log.read_text().splitlines() if not line.startswith("flap 3 first_reann_s:")]
        log.write_text("\n".join(lines) + "\n")
        with self.assertRaisesRegex(summarize.ExtractionError, "flap metric rounds differ"):
            summarize.extract(self.tmp)

    def heap_leg(self, rounds, fields=None):
        """Insert heap lines numbered ROUNDS, one after each round's RSS line in order.

        FIELDS, when given, replaces every line's key=value text."""
        cell = matrix_leg(self.tmp, "matrix-a-r1-s3", "s3")
        log = cell / "reloadstall.log"
        lines, pending = [], list(rounds)
        for line in log.read_text().splitlines():
            lines.append(line)
            if line.startswith("flap ") and " sessions_up " in line and pending:
                round_ = pending.pop(0)
                lines.append(f"flap {round_} heap " + (fields or f"allocated_mib={300 + round_} active_mib=320 "
                                                                f"resident_mib={350 + round_} mapped_mib=400"))
        assert not pending
        log.write_text("\n".join(lines) + "\n")

    def test_heap_lines_extract_per_round(self):
        self.heap_leg([1, 2, 3])
        rows, _, _ = summarize.extract(self.tmp)
        heap = sorted((r[3], r[4], r[5]) for r in rows if r[3].startswith("flap_heap_"))
        self.assertEqual(heap, [("flap_heap_allocated", i, str(300 + i)) for i in (1, 2, 3)]
                         + [("flap_heap_resident", i, str(350 + i)) for i in (1, 2, 3)])

    def test_heap_line_missing_a_round_fails(self):
        self.heap_leg([1, 3])
        with self.assertRaisesRegex(summarize.ExtractionError, "flap metric rounds differ"):
            summarize.extract(self.tmp)

    def test_heap_line_duplicate_round_fails(self):
        # As many heap lines as rounds, but round 1 twice and round 2 never.
        self.heap_leg([1, 1, 3])
        with self.assertRaisesRegex(summarize.ExtractionError, "duplicate flap round in 'heap'"):
            summarize.extract(self.tmp)

    def heap_rows(self):
        rows, _, _ = summarize.extract(self.tmp)
        return sorted((r[3], r[4], r[5]) for r in rows if r[3].startswith("flap_heap_"))

    def test_absent_heap_lines_still_count_rounds(self):
        absent = "allocated_mib=absent active_mib=absent resident_mib=absent mapped_mib=absent"
        self.heap_leg([1, 2, 3], absent)
        self.assertEqual(self.heap_rows(), [])

    def test_absent_heap_line_missing_a_round_fails(self):
        absent = "allocated_mib=absent active_mib=absent resident_mib=absent mapped_mib=absent"
        self.heap_leg([1, 3], absent)
        with self.assertRaisesRegex(summarize.ExtractionError, "flap metric rounds differ"):
            summarize.extract(self.tmp)

    def test_mixed_heap_line_emits_only_numeric_rows(self):
        self.heap_leg([1, 2, 3], "allocated_mib=300 active_mib=absent resident_mib=absent mapped_mib=absent")
        self.assertEqual(self.heap_rows(), [("flap_heap_allocated", i, "300") for i in (1, 2, 3)])

    def test_malformed_heap_value_fails(self):
        for fields in ("allocated_mib=3x0 resident_mib=350", "allocated_mib=300", "allocated_mib= resident_mib=350"):
            with self.subTest(fields=fields):
                shutil.rmtree(self.tmp)
                self.tmp.mkdir()
                self.heap_leg([1, 2, 3], fields)
                with self.assertRaisesRegex(summarize.ExtractionError, "neither an integer nor 'absent'"):
                    summarize.extract(self.tmp)

    def test_heap_line_for_an_unknown_round_fails(self):
        self.heap_leg([1, 2, 4])
        with self.assertRaisesRegex(summarize.ExtractionError, "flap metric rounds differ"):
            summarize.extract(self.tmp)

    def test_unfinished_legs_are_not_counted(self):
        matrix_leg(self.tmp, "matrix-a-r1-s2")
        (matrix_leg(self.tmp, "matrix-a-r2-s2") / "status").write_text("fail rc=1\n")
        shutil.copytree(V0720 / "irr" / "irr-ov0-ctrl-r1", self.tmp / "irr-ov0-a-r1")
        (self.tmp / "irr-ov0-a-r1" / "COMPLETED").unlink()
        shutil.copytree(V0720 / "rr1000" / "rr1000-ctrl-c1", self.tmp / "rr1000-a-c1")
        (self.tmp / "rr1000-a-c1" / "COMPLETED").write_text("fail\n")
        rows, _, _ = summarize.extract(self.tmp)
        self.assertEqual({row[2] for row in rows}, {"1"})
        self.assertEqual({row[0] for row in rows}, {"matrix-s2"})

    def test_exclude_and_set_aside_legs(self):
        matrix_leg(self.tmp, "matrix-a-r1-s2")
        matrix_leg(self.tmp, "matrix-a-r2-s2")
        shutil.copytree(V0720 / "irr" / "irr-ov0-ctrl-r1", self.tmp / "irr-ov0-a-r1.failed.1")
        rows, _, excluded = summarize.extract(self.tmp, ["matrix-a-r2-*"])
        self.assertEqual({(row[0], row[2]) for row in rows}, {("matrix-s2", "1")})
        self.assertEqual(excluded, ["matrix-a-r2-s2"])

    def test_excluded_file_drops_and_lists_legs(self):
        matrix_leg(self.tmp, "matrix-a-r1-s2")
        matrix_leg(self.tmp, "matrix-a-r2-s2")
        (self.tmp / "EXCLUDED").write_text("# another build overlapped this leg\nmatrix-a-r2-s2\n")
        self.assertEqual(self.run_main(), 0)
        report = (self.tmp / "out" / "report.md").read_text()
        self.assertIn("| matrix-s2 | reload_completion_p50 | 1.45–1.62 (median 1.49, n=4) |", report)
        self.assertIn("- `matrix-a-r2-s2`", report)
        summary = (self.tmp / "out" / "summary.csv").read_text().splitlines()[1:]
        self.assertEqual({row[2] for row in csv.reader(summary)}, {"1"})
        # A mistyped entry must not silently keep the leg it meant to drop.
        (self.tmp / "EXCLUDED").write_text("matrix-a-r9-s2\n")
        with self.assertRaisesRegex(summarize.ExtractionError, "matches no leg"):
            summarize.extract(self.tmp)

    def test_cgroup_memory_rows(self):
        cell = matrix_leg(self.tmp, "matrix-a-r1-s2")
        self.assertFalse({"daemon_cg_peak", "settled_cg_current_last_sample"} & {r[3] for r in summarize.extract(self.tmp)[0]})
        rss = cell / "rss.csv"
        lines = rss.read_text().splitlines()
        rss.write_text("\n".join([lines[0] + ",cg_current_kib"] + [f"{line},{i + 1000}" for i, line in enumerate(lines[1:])] + [lines[-1] + ","]) + "\n")
        (cell / "cgroup-memory").write_text("cg_peak: 812345 kB\ncg_current: 700000 kB\ncg_swap_max: 0\n")
        cg = {r[3]: r[5] for r in summarize.extract(self.tmp)[0] if r[3].startswith(("daemon_cg", "settled_cg"))}
        # The trailing sample lost its cgroup read at teardown; the last real one counts.
        self.assertEqual(cg, {"daemon_cg_peak": "812345", "settled_cg_current_last_sample": 1000 + len(lines) - 2})
        (cell / "cgroup-memory").write_text(
            "cg_peak: 812345 kB\ncg_current: 700000 kB\ncg_swap_max: 0\n"
            "cg_last_sample_anon: 400000 kB\ncg_last_sample_file: 200000 kB\n"
            "cg_last_sample_file_mapped: 100000 kB\ncg_teardown_anon: 390000 kB\n"
            "cg_teardown_file: 190000 kB\ncg_teardown_file_mapped: 90000 kB\n"
        )
        self.assertIn("daemon_cg_peak", {r[3] for r in summarize.extract(self.tmp)[0]})
        (cell / "cgroup-memory").write_text((cell / "cgroup-memory").read_text().replace("cg_teardown_file: 190000 kB\n", ""))
        with self.assertRaisesRegex(summarize.ExtractionError, r"all cg_last_sample_\* and cg_teardown_\* fields"):
            summarize.extract(self.tmp)
        (cell / "cgroup-memory").write_text("cg_scope: unavailable\n")
        self.assertNotIn("daemon_cg_peak", {r[3] for r in summarize.extract(self.tmp)[0]})
        # Only the optional cgroup column may be blank; a blank primary RSS sample fails.
        good = rss.read_text()
        rss.write_text(good + "1790000000,,1,1\n")
        with self.assertRaises(ValueError):
            summarize.extract(self.tmp)
        rss.write_text(good)
        # No cg_peak may publish without the full readout and its swap-fence evidence.
        for bad in ("cg_peak_kib: 812345\n",
                    "cg_peak: 812345 kB\ncg_current: 700000 kB\ncg_swap_max: max\n",
                    "cg_peak: 812345 kB\ncg_swap_max: 0\n",
                    "cg_peak: 812345 kB\ncg_current: 700000 kB\n",
                    "cg_scope: unavailable\ncg_peak: 812345 kB\n"):
            with self.subTest(bad=bad):
                (cell / "cgroup-memory").write_text(bad)
                with self.assertRaisesRegex(summarize.ExtractionError, "cgroup-memory"):
                    summarize.extract(self.tmp)

    def test_container_memory_rows(self):
        cell = matrix_leg(self.tmp, "matrix-bird-r1-s2")
        self.assertNotIn("container_cg_peak", {r[3] for r in summarize.extract(self.tmp)[0]})
        (cell / "container-memory").write_text("container_cg_peak: 1234567 kB\ncontainer_cg_swap_peak: 0 kB\n")
        self.assertIn(["matrix-s2", "bird", "1", "container_cg_peak", "", "1234567", "KiB"], summarize.extract(self.tmp)[0])
        (cell / "container-memory").write_text("container_cg: unavailable\n")
        self.assertNotIn("container_cg_peak", {r[3] for r in summarize.extract(self.tmp)[0]})
        # A peak with pages swapped out is incomplete, and a partial readout is not a peak.
        for bad in ("container_cg_peak: 1234567 kB\ncontainer_cg_swap_peak: 4 kB\n",
                    "container_cg_peak: 1234567 kB\n",
                    "container_cg: unavailable\ncontainer_cg_peak: 1234567 kB\n"):
            with self.subTest(bad=bad):
                (cell / "container-memory").write_text(bad)
                with self.assertRaisesRegex(summarize.ExtractionError, "container-memory"):
                    summarize.extract(self.tmp)

    def test_irr_daemon_vmhwm_row(self):
        root = self.tmp / "irr-ov0-a-r1"
        shutil.copytree(V0720 / "irr" / "irr-ov0-ctrl-r1", root)
        self.assertNotIn("daemon_vmhwm", {r[3] for r in summarize.extract(self.tmp)[0]})
        (root / "rustbgpd-sighup" / "vmhwm").write_text("VmHWM:\t  700001 kB\nVmRSS:\t  500000 kB\n")
        self.assertIn(["irr-ov0", "a", "1", "daemon_vmhwm", "", "700001", "KiB"], summarize.extract(self.tmp)[0])

    def test_irr_cgroup_peaks_and_window(self):
        root = self.tmp / "irr-ov0-a-r1"
        shutil.copytree(V0720 / "irr" / "irr-ov0-ctrl-r1", root)
        native = root / "rustbgpd-sighup"
        native_readout = "cg_peak: 812345 kB\ncg_current: 700000 kB\ncg_swap_max: 0\ncg_swap_peak: 0 kB\n"
        (native / "cgroup-memory").write_text(native_readout)
        (native / "memory-window").write_text(summarize.IRR_MEMORY_WINDOW)
        for name, peak in (("bird", 901234), ("openbgpd", 912345)):
            cell = root / name
            cell.mkdir(exist_ok=True)
            (cell / "container-memory").write_text(f"container_cg_peak: {peak} kB\ncontainer_cg_swap_peak: 0 kB\n")
            (cell / "memory-window").write_text(summarize.IRR_MEMORY_WINDOW)
        (root / "provenance.json").write_text(json.dumps({"schema": 3, "inputs": {"cells": "rustbgpd-sighup,bird,openbgpd"}}))
        rows = summarize.extract(self.tmp)[0]
        self.assertIn(["irr-ov0", "a", "1", "irr_daemon_cg_peak", "", "812345", "KiB"], rows)
        self.assertIn(["irr-ov0", "bird", "1", "irr_container_cg_peak", "", "901234", "KiB"], rows)
        self.assertIn(["irr-ov0", "openbgpd", "1", "irr_container_cg_peak", "", "912345", "KiB"], rows)
        self.assertEqual(self.run_main(), 0)
        report = (self.tmp / "out" / "report.md").read_text()
        self.assertIn("| Phase | Metric | a | bird | openbgpd |", report)
        (self.tmp / "arms.txt").write_text("a=fixture\n")
        self.assertEqual(summarize.arm_order(self.tmp, summarize.aggregate(rows, [])), ["a", "bird", "openbgpd"])
        (self.tmp / "arms.txt").unlink()
        self.assertIn("before transaction lifecycle probes; actual memory.swap.peak is zero", report)
        self.assertIn("before teardown, with zero swap peak", report)
        for bad in (native_readout.replace("cg_swap_peak: 0", "cg_swap_peak: 1"),
                    native_readout.replace("cg_swap_peak: 0 kB\n", "")):
            (native / "cgroup-memory").write_text(bad)
            with self.assertRaisesRegex(summarize.ExtractionError, "zero actual swap peak"):
                summarize.extract(self.tmp)
        (native / "cgroup-memory").write_text(native_readout)
        (native / "memory-window").write_text("after_lifecycle\n")
        with self.assertRaisesRegex(summarize.ExtractionError, "memory-window"):
            summarize.extract(self.tmp)
        (native / "memory-window").write_text(summarize.IRR_MEMORY_WINDOW)
        bird = root / "bird" / "container-memory"
        bird.write_text("container_cg_peak: 901234 kB\ncontainer_cg_swap_peak: 1 kB\n")
        with self.assertRaisesRegex(summarize.ExtractionError, "zero actual swap peak"):
            summarize.extract(self.tmp)
        bird.write_text("container_cg: unavailable\n")
        self.assertNotIn("bird", {row[1] for row in summarize.extract(self.tmp)[0]})
        for name, filename in (("rustbgpd-sighup", "cgroup-memory"), ("bird", "container-memory"), ("openbgpd", "container-memory")):
            cell = root / name
            path, window = cell / filename, cell / "memory-window"
            saved = path.read_text()
            path.unlink(); window.unlink()
            with self.assertRaisesRegex(summarize.ExtractionError, "requires its cgroup memory readout"):
                summarize.extract(self.tmp)
            path.write_text(saved); window.write_text(summarize.IRR_MEMORY_WINDOW)
            target = self.tmp / "readout-target"
            target.write_text(saved)
            path.unlink(); path.symlink_to(target)
            with self.assertRaisesRegex(summarize.ExtractionError, "must be regular files"):
                summarize.extract(self.tmp)
            path.unlink(); path.write_text(saved)
            target.write_text(summarize.IRR_MEMORY_WINDOW)
            window.unlink(); window.symlink_to(target)
            with self.assertRaisesRegex(summarize.ExtractionError, "must be regular files"):
                summarize.extract(self.tmp)
            window.unlink(); window.write_text(summarize.IRR_MEMORY_WINDOW)
        provenance = root / "provenance.json"
        saved_provenance = provenance.read_text()
        saved_native = (native / "cgroup-memory").read_text()
        (native / "cgroup-memory").unlink(); (native / "memory-window").unlink()
        provenance.unlink()
        with self.assertRaisesRegex(summarize.ExtractionError, "IRR provenance must be a regular file"):
            summarize.extract(self.tmp)
        provenance.symlink_to(self.tmp / "missing-provenance")
        with self.assertRaisesRegex(summarize.ExtractionError, "IRR provenance must be a regular file"):
            summarize.extract(self.tmp)
        provenance.unlink(); provenance.write_text(saved_provenance)
        (native / "cgroup-memory").write_text(saved_native)
        (native / "memory-window").write_text(summarize.IRR_MEMORY_WINDOW)

    def test_irr_schema3_rejects_unselected_memory(self):
        root = self.tmp / "irr-ov0-a-r1"
        shutil.copytree(V0720 / "irr" / "irr-ov0-ctrl-r1", root)
        native = root / "rustbgpd-sighup"
        (native / "cgroup-memory").write_text("cg_peak: 812345 kB\ncg_current: 700000 kB\ncg_swap_max: 0\ncg_swap_peak: 0 kB\n")
        (native / "memory-window").write_text(summarize.IRR_MEMORY_WINDOW)
        provenance = root / "provenance.json"
        provenance.write_text(json.dumps({"schema": 3, "inputs": {"cells": "rustbgpd-sighup"}}))
        self.assertIn("irr_daemon_cg_peak", {r[3] for r in summarize.extract(self.tmp)[0]})
        for name in ("bird", "openbgpd"):
            with self.subTest(cell=name):
                cell = root / name
                cell.mkdir(exist_ok=True)
                path, window = cell / "container-memory", cell / "memory-window"
                readout = "container_cg_peak: 901234 kB\ncontainer_cg_swap_peak: 0 kB\n"
                path.write_text(readout); window.write_text(summarize.IRR_MEMORY_WINDOW)
                with self.assertRaisesRegex(summarize.ExtractionError, "outside the selected cell roster"):
                    summarize.extract(self.tmp)
                provenance.write_text(json.dumps({"schema": 3, "inputs": {"cells": f"rustbgpd-sighup,{name}"}}))
                self.assertIn(["irr-ov0", name, "1", "irr_container_cg_peak", "", "901234", "KiB"], summarize.extract(self.tmp)[0])
                provenance.write_text(json.dumps({"schema": 3, "inputs": {"cells": "rustbgpd-sighup"}}))
                path.write_text("container_cg: unavailable\n")
                with self.assertRaisesRegex(summarize.ExtractionError, "outside the selected cell roster"):
                    summarize.extract(self.tmp)
                path.unlink()
                with self.assertRaisesRegex(summarize.ExtractionError, "outside the selected cell roster"):
                    summarize.extract(self.tmp)
                window.unlink()
        self.assertNotIn("irr_container_cg_peak", {r[3] for r in summarize.extract(self.tmp)[0]})

    def test_report_names_memory_sources(self):
        matrix_leg(self.tmp, "matrix-a-r1-s2")
        self.assertEqual(self.run_main(), 0)
        report = (self.tmp / "out" / "report.md").read_text()
        self.assertIn("- `peak_rss_sample`: KiB; the largest 5 s process-tree RSS sample;", report)
        self.assertIn("- `daemon_vmhwm`: KiB; the kernel's VmHWM", report)
        # Only metrics in the table get a source line.
        self.assertNotIn("container_cg_peak", report)

    def test_report_names_rr1000_memory_sources(self):
        shutil.copytree(V0720 / "rr1000" / "rr1000-ctrl-c1", self.tmp / "rr1000-ctrl-c1")
        self.assertEqual(self.run_main(), 0)
        report = (self.tmp / "out" / "report.md").read_text()
        self.assertIn("| rr1000 | wire_vmrss | ", report)
        self.assertIn("- `wire_vmrss`: KiB; the RR1000 target process's own VmRSS (direct PID", report)
        self.assertIn("- `wire_vmhwm`: KiB; the RR1000 target process's own VmHWM (direct PID", report)

    def test_report_memory_values_stay_fixed_point(self):
        # Above seven digits, significant-digit formatting would print 1e+07.
        table = {("matrix-s2", "daemon_cg_peak"): {"a": [10000000.0, 12345678.0]},
                 ("matrix-s2", "flap_post_round_rss"): {"a": [407.0, 410.0]},
                 ("matrix-s2", "reload_completion_p50"): {"a": [12345678.9]}}
        text = summarize.report(table, ["a"], False, [])
        self.assertIn("| matrix-s2 | daemon_cg_peak | 10000000–12345678 (median 11172839, n=2) |", text)
        self.assertIn("| matrix-s2 | flap_post_round_rss | 407–410 (median 408.5, n=2) |", text)
        self.assertIn("| matrix-s2 | reload_completion_p50 | 1.234568e+07–1.234568e+07 (median 1.234568e+07, n=1) |", text)

    def test_daemon_reload_intervals(self):
        cell = matrix_leg(self.tmp, "matrix-a-r1-s2")
        (cell / "daemon.log").write_text(daemon_log(4))
        root = self.tmp / "irr-ov0-a-r1"
        shutil.copytree(V0720 / "irr" / "irr-ov0-ctrl-r1", root)
        (root / "rustbgpd-sighup" / "daemon.log").write_text(daemon_log(4))
        rows, _, _ = summarize.extract(self.tmp)
        daemon = sorted({(r[0], r[3], r[5]) for r in rows if r[3].startswith("daemon_") and r[3] not in ("daemon_vmhwm", "daemon_cg_peak")})
        expected = [(phase, metric, value) for phase in ("irr-ov0", "matrix-s2") for metric, value in (
            ("daemon_rib_transition", 581.0), ("daemon_sighup_to_complete", 1199.0),
            ("daemon_sighup_to_loaded", 100.0), ("daemon_validate", 84))]
        self.assertEqual(daemon, expected)
        self.assertEqual(sum(r[3] == "daemon_sighup_to_complete" for r in rows), 8)

    def test_renamed_reload_message_fails(self):
        cell = matrix_leg(self.tmp, "matrix-a-r1-s2")
        (cell / "daemon.log").write_text(daemon_log(4, complete="configuration reload finished"))
        with self.assertRaisesRegex(summarize.ExtractionError, "line 6: SIGHUP while the one at line 2 is still pending"):
            summarize.extract(self.tmp)
        (cell / "daemon.log").write_text(daemon_log(3))
        with self.assertRaisesRegex(summarize.ExtractionError, "3 completed reloads, harness measured 4"):
            summarize.extract(self.tmp)

    def test_reload_missing_a_field_fails(self):
        cell = matrix_leg(self.tmp, "matrix-a-r1-s2")
        for drop, message in (((2, "rib"), "reload 2 lacks cohort_rib_transition_us"),
                              ((3, "validate"), "reload 3 lacks validate_ms"),
                              ((1, "loaded"), "reload 1 lacks 'config source loaded', validate_ms")):
            with self.subTest(drop=drop):
                (cell / "daemon.log").write_text(daemon_log(4, drop={drop}))
                with self.assertRaisesRegex(summarize.ExtractionError, f"matrix-a-r1-s2: daemon log {message}"):
                    summarize.extract(self.tmp)

    def test_reload_events_must_pair(self):
        cell = matrix_leg(self.tmp, "matrix-a-r1-s2")
        lines = daemon_log(4).splitlines(True)  # line 1 is a session; reload N spans lines 4N-2..4N+1
        cases = (
            (lines[:6] + [lines[5]] + lines[6:], "line 7: SIGHUP while the one at line 6 is still pending"),
            (lines[:5] + lines[6:], "line 8: reload complete with no SIGHUP pending"),
            (lines[:-1], "line 14: SIGHUP never completed"),
        )
        for text, message in cases:
            with self.subTest(message=message):
                (cell / "daemon.log").write_text("".join(text))
                with self.assertRaisesRegex(summarize.ExtractionError, f"^matrix-a-r1-s2: daemon.log {message}"):
                    summarize.extract(self.tmp)

    def test_campaign_must_keep_daemon_logs(self):
        matrix_leg(self.tmp, "matrix-a-r1-s2")
        (self.tmp / "arms.txt").write_text("a=HEAD:HEAD\n")
        with self.assertRaisesRegex(summarize.ExtractionError, "daemon.log is missing"):
            summarize.extract(self.tmp)

    def test_establishment_span_from_daemon_log(self):
        cell = matrix_leg(self.tmp, "matrix-a-r1-s3", "s3")
        log = cell / "reloadstall.log"
        log.write_text(log.read_text().replace("established 700 at", "established 3 at"))
        stamps = ["2026-09-28T01:00:00.100Z", "2026-09-28T01:00:00.400Z", "2026-09-28T01:00:00.900Z"]
        (cell / "daemon.log").write_text("".join(
            json.dumps({"timestamp": t, "fields": {"message": "session established"}}) + "\n" for t in stamps))
        _, spans, _ = summarize.extract(self.tmp)
        self.assertEqual(spans, [["a", "1", "s3", 3, 3, "0.800"]])

    def competitor_leg(self, path, daemon="bird"):
        """A committed v0.74.0 S2 cell of DAEMON at PATH, with its own text daemon.log."""
        shutil.copytree(V0740 / "matrix" / f"matrix-{daemon}-r1-s2", path)
        (path / "daemon.log").write_text(BIRD_LOG)
        return path

    def test_competitor_daemon_log_is_not_parsed(self):
        cell = self.competitor_leg(self.tmp / "matrix-bird-r1-s2")
        rows, spans, _ = summarize.extract(self.tmp)
        self.assertIn(["matrix-s2", "bird", "1", "reload_completion_p50", 1, "101.58", "s"], rows)
        self.assertEqual([r for r in rows if r[3].startswith("daemon_")], [])
        self.assertEqual(spans, [])
        # The cell is named by its provenance, not its arm: a rustbgpd cell
        # still has its log parsed strictly, and an unknown cell fails.
        provenance = json.loads((cell / "provenance.json").read_text())
        (cell / "provenance.json").write_text(json.dumps({**provenance, "cell": "rustbgpd"}))
        with self.assertRaisesRegex(summarize.ExtractionError, "0 completed reloads, harness measured 4"):
            summarize.extract(self.tmp)
        (cell / "provenance.json").write_text(json.dumps({**provenance, "cell": "gobgp"}))
        with self.assertRaisesRegex(summarize.ExtractionError, "provenance.json names cell 'gobgp'"):
            summarize.extract(self.tmp)

    def test_cross_daemon_queue_layout(self):
        legs = self.tmp / "legs"
        for daemon in ("bird", "openbgpd"):
            self.competitor_leg(legs / f"matrix-s2-r1-{daemon}" / daemon, daemon)
        cell = legs / "matrix-s2-r1-rustbgpd" / "rustbgpd"
        shutil.copytree(V0740 / "matrix" / "matrix-rustbgpd-r1-s2", cell)
        irr = legs / "irr-ov10-r1"
        shutil.copytree(V0740 / "irr" / "irr-ov10-rustbgpd-r1", irr)
        # Set-aside retries and runner logs sit beside the legs.
        (legs / "matrix-s2-r1-rustbgpd.log").write_text("runner output\n")
        shutil.copytree(cell, legs / "matrix-s2-r1-rustbgpd.aside.1" / "rustbgpd")
        # A queue directory is a campaign: rustbgpd's daemon logs must be kept.
        with self.assertRaisesRegex(summarize.ExtractionError, "matrix-s2-r1-rustbgpd: daemon.log is missing"):
            summarize.extract(self.tmp)
        (cell / "daemon.log").write_text(daemon_log(4))
        with self.assertRaisesRegex(summarize.ExtractionError, "irr-ov10-r1: daemon.log is missing"):
            summarize.extract(self.tmp)
        (irr / "rustbgpd-sighup" / "daemon.log").write_text(daemon_log(4))
        rows, _, _ = summarize.extract(self.tmp)
        self.assertEqual({(r[0], r[1]) for r in rows},
                         {("matrix-s2", "bird"), ("matrix-s2", "openbgpd"), ("matrix-s2", "rustbgpd"),
                          ("irr-ov10", "rustbgpd")})
        daemon = {(r[0], r[1]) for r in rows if r[3] == "daemon_sighup_to_complete"}
        self.assertEqual(daemon, {("matrix-s2", "rustbgpd"), ("irr-ov10", "rustbgpd")})
        # The committed bundle holds the same cells under its own names; only
        # the stubbed daemon-log rows differ.
        bundle = {tuple(r) for r in csv.reader((V0740 / "summary.csv").read_text().splitlines()[1:])}
        self.assertLessEqual({tuple(map(str, r)) for r in rows if r[3] not in summarize.RELOAD_METRICS}, bundle)
        # The new memory readouts extract from queue-layout cells as well.
        (legs / "matrix-s2-r1-bird" / "bird" / "container-memory").write_text(
            "container_cg_peak: 456789 kB\ncontainer_cg_swap_peak: 0 kB\n")
        (irr / "rustbgpd-sighup" / "vmhwm").write_text("VmHWM:\t  700001 kB\nVmRSS:\t  500000 kB\n")
        rows, _, _ = summarize.extract(self.tmp)
        self.assertIn(["matrix-s2", "bird", "1", "container_cg_peak", "", "456789", "KiB"], rows)
        self.assertIn(["irr-ov10", "rustbgpd", "1", "daemon_vmhwm", "", "700001", "KiB"], rows)

    def test_bundle_needs_out(self):
        self.assertEqual(quiet_main([str(V0720)]), 2)

    def test_empty_source_fails(self):
        self.assertEqual(self.run_main(), 1)


FAKE_CARGO = """#!/usr/bin/env bash
# Stand-in for cargo: a product build writes a daemon whose bytes are the
# tree hash (FAKE_CARGO=tree) or the commit (FAKE_CARGO=commit), or fails.
set -euo pipefail
echo "$*"
[[ ${FAKE_CARGO} != fail ]] || { echo "fake build failure" >&2; exit 101; }
if [[ " $* " == *" --manifest-path "* ]]; then
    profile=release
    [[ " $* " != *" --profile scale "* ]] || profile=scale
    target=target/$profile
    [[ ! -f bench/scale/Cargo.toml ]] || target=bench/scale/target/$profile
    mkdir -p "$target" && echo harness >"$target/reloadstall"
else
    what=tree; [[ ${FAKE_CARGO} != commit ]] || what=commit
    mkdir -p target/release
    git rev-parse "HEAD^{$what}" >target/release/rustbgpd
fi
"""

FAKE_MATRIX = """#!/usr/bin/env bash
# Stand-in for run-matrix.sh: copy a committed leg, or record a failed cell
# and exit 0 as the real runner does.
set -euo pipefail
mkdir -p "$ARTIFACTS_DIR/rustbgpd"
if [[ -n ${FAKE_MATRIX_FAIL:-} ]]; then echo "fail rc=1" >"$ARTIFACTS_DIR/rustbgpd/status"; exit 0; fi
scenario=s2; [[ -z $FLAPSTORM ]] || scenario=s3
cp -r "$FIXTURES/matrix-ctrl-r1-$scenario/." "$ARTIFACTS_DIR/rustbgpd/"
cp "$DAEMON_LOGS/daemon-$scenario.log" "$ARTIFACTS_DIR/rustbgpd/daemon.log"
"""


class CampaignFailsClosed(unittest.TestCase):
    """Run run-campaign.sh inside a scratch repository with stub builds and runners."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        git = lambda *args, cwd=self.tmp: subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)
        git("init", "-q", "--bare", "-b", "main", "origin.git")
        repo = self.tmp / "repo"
        git("clone", "-q", "origin.git", "repo")
        for args in (("config", "user.email", "test@example.invalid"), ("config", "user.name", "test")):
            git(*args, cwd=repo)
        headline = repo / "bench/scale/headline"
        headline.mkdir(parents=True)
        for name in ("run-campaign.sh", "summarize.py"):
            shutil.copy(HERE / name, headline / name)
        matrix = repo / "bench/scale/matrix/run-matrix.sh"
        matrix.parent.mkdir(parents=True)
        matrix.write_text(FAKE_MATRIX)
        (repo / ".gitignore").write_text("target/\n")
        git("add", "-A", cwd=repo)
        git("commit", "-qm", "base", cwd=repo)
        git("push", "-q", "origin", "HEAD:main", cwd=repo)
        git("fetch", "-q", "origin", cwd=repo)
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "cargo").write_text(FAKE_CARGO)
        (bin_dir / "cargo").chmod(0o755)
        self.repo = repo
        self.out = self.tmp / "campaign"
        (self.tmp / "daemon-s2.log").write_text(daemon_log(4))
        (self.tmp / "daemon-s3.log").write_text(daemon_log(0))
        self.env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FIXTURES": str(V0720 / "matrix"),
                    "DAEMON_LOGS": str(self.tmp),
                    "CELLS": "matrix", "RUNS": "1"}

    def campaign(self, *arms, **env):
        return subprocess.run(["bash", str(self.repo / "bench/scale/headline/run-campaign.sh"), str(self.out), *arms],
                              env={**self.env, **env}, capture_output=True, text=True)

    def progress(self):
        return (self.out / "progress.txt").read_text()

    def test_failed_build_exits_nonzero(self):
        result = self.campaign("a=HEAD", "b=HEAD", FAKE_CARGO="fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("campaign done", self.progress())
        self.assertFalse(list(self.out.glob("matrix-*")))

    def test_commit_dependent_daemon_exits_nonzero(self):
        result = self.campaign("a=HEAD", "b=HEAD", FAKE_CARGO="commit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("STOP: a: daemon at HEAD hashes", self.progress())
        self.assertNotIn("campaign done", self.progress())

    def test_failed_leg_exits_nonzero(self):
        result = self.campaign("a=HEAD", "b=HEAD", FAKE_CARGO="tree", FAKE_MATRIX_FAIL="1")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("campaign done rc=1 failed=matrix-a-r1-s2 matrix-a-r1-s3 matrix-b-r1-s2 matrix-b-r1-s3",
                      self.progress())

    def test_used_directory_without_manifest_is_refused(self):
        self.out.mkdir()
        (self.out / "progress.txt").write_text("[earlier] campaign start\n")
        result = self.campaign("a=HEAD", "b=HEAD", FAKE_CARGO="tree")
        self.assertEqual(result.returncode, 2)
        self.assertIn("not empty and has no campaign manifest", result.stderr)
        self.assertEqual(sorted(p.name for p in self.out.iterdir()), ["progress.txt"])

    def test_empty_directory_is_a_fresh_start(self):
        self.out.mkdir()
        result = self.campaign("a=HEAD", "b=HEAD", FAKE_CARGO="tree")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.out / "manifest.txt").exists())

    def test_one_arm_is_refused(self):
        result = self.campaign("a=HEAD", FAKE_CARGO="tree")
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)
        self.assertFalse(self.out.exists())

    def test_two_arms_pass_and_summarize(self):
        result = self.campaign("a=HEAD", "b=HEAD", FAKE_CARGO="tree")
        self.assertEqual(result.returncode, 0, self.progress())
        self.assertIn("--profile scale", (self.out / "build-a.log").read_text())
        self.assertIn("campaign done rc=0 failed=none", self.progress())
        self.assertIn("| matrix-s2 | reload_completion_p50 | ", (self.out / "report.md").read_text())
        self.assertIn("cpus_allowed=", (self.out / "placement.txt").read_text())
        self.assertRegex(self.progress(), r"matrix-a-r1-s2 start load=\S+ \S+ \S+ pswpin=\d+ pswpout=\d+ +cpus=\S+")
        # A rerun resumes: every leg is already done.
        again = self.campaign("a=HEAD", "b=HEAD", FAKE_CARGO="tree")
        self.assertEqual(again.returncode, 0)
        self.assertEqual(self.progress().count("already pass, skip"), 4)
        # Any other shape in the same output directory is refused before a leg runs.
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.repo, check=True,
                              capture_output=True, text=True).stdout.strip()
        self.assertEqual(self.campaign("a=HEAD", f"b={head}", FAKE_CARGO="tree").returncode, 0)
        for arms, env in ((("c=HEAD", "b=HEAD"), {}), (("a=HEAD", "b=HEAD"), {"RUNS": "2"}),
                          (("a=HEAD", "b=HEAD"), {"SMOKE": "1"}), (("a=HEAD", "b=HEAD"), {"MATRIX_SCENARIOS": "s2"}),
                          (("a=HEAD", "b=HEAD"), {"CELLS": "matrix,irr"}), (("a=HEAD", "b=HEAD"), {"MATRIX_PEERS": "20"})):
            with self.subTest(arms=arms, env=env):
                refused = self.campaign(*arms, FAKE_CARGO="tree", **env)
                self.assertEqual(refused.returncode, 2)
                self.assertIn("campaign with another shape", refused.stderr)
        # A moved ref resolves to another commit, which is another shape too.
        subprocess.run(["git", "commit", "-q", "--allow-empty", "-m", "next"], cwd=self.repo, check=True)
        moved = self.campaign("a=HEAD", "b=HEAD", FAKE_CARGO="tree")
        self.assertEqual(moved.returncode, 2)
        self.assertIn(f"< arm a={head}:{head}", moved.stderr)
        self.assertEqual(self.progress().count("campaign start"), 3)

    def test_legacy_scale_workspace_uses_its_release_profile(self):
        manifest = self.repo / "bench/scale/Cargo.toml"
        manifest.write_text('[workspace]\nmembers = ["reloadstall"]\n')
        subprocess.run(["git", "add", str(manifest)], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-qm", "legacy scale workspace"], cwd=self.repo, check=True)
        result = self.campaign("a=HEAD", "b=HEAD", FAKE_CARGO="tree")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--profile release ", (self.out / "build-a.log").read_text())

    def test_dry_run_rotates_arm_order(self):
        result = self.campaign("a=HEAD", "b=HEAD", "c=HEAD", DRY_RUN="1", CELLS="rr", RUNS="3")
        self.assertEqual(result.returncode, 0)
        order = [line.split()[1] for line in result.stdout.splitlines() if line.startswith("rr ")]
        self.assertEqual(order, ["a", "b", "c", "b", "c", "a", "c", "a", "b"])
        legs = self.campaign("a=HEAD", "b=HEAD", DRY_RUN="1", MATRIX_SCENARIOS="s2").stdout
        self.assertEqual([line for line in legs.splitlines() if line.startswith("matrix")],
                         ["matrix a 1 s2", "matrix b 1 s2"])
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
