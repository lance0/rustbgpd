"""Seeded defects for the source-burst cell's analyzer: each must turn the
verdict for its own reason, and the latency reading must follow the stamps."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

import credit_bars
import test_credit_bars

BURST_START, BURST_DONE = 500.0, 37_500.0


def update(sequence, sent, wait, ahead=0):
    """One healthy update admitted 1 ms after it was sent, dispatched `wait`
    ms later and received 1 ms after that."""
    return [sequence, sent, sent + 1, sent + 1 + wait, sent + 2 + wait, ahead, ahead * 3]


def burst(control=False, measured=True):
    run = {
        "schema": "rrtransport-credit/1",
        "cell": "source-burst-control" if control else "source-burst",
        "family": "unicast",
        "mode": "measured" if measured else "correctness",
        "shape": {
            "receivers": 150,
            "routes": 150_000,
            "rows_per_update": 1_000,
            "burst_interval_ms": 0.0,
        },
        "seeded": None,
        "host": {
            "compiler_watch": {"samples": 40, "observed": 0, "first": None, "unavailable": None}
        },
        "burst": {
            "first_sent_ms": BURST_START,
            "first_admitted_ms": BURST_START + 1,
            "paced_sleep_ms": 0.0,
            "rib_done_ms": BURST_DONE,
            "completion_ms": BURST_DONE + 20,
            "ingest_routes_per_s": 4_054.0,
            "admit_routes_per_s": 300_000.0,
        },
        "checks": dict.fromkeys(credit_bars.SOURCE_BURST_CHECKS, True),
        "memory": {"vmhwm_kib": 2_097_152},
    }
    if not control:
        run["healthy"] = {
            "columns": list(credit_bars.SOURCE_BURST_COLUMNS),
            "markers_lost": 0,
            "updates": [
                update(1, 100.0, 0.2),
                update(2, 120.0, 0.3),
                update(3, 520.0, 36_000.0, ahead=146),
                update(4, 540.0, 35_980.0, ahead=146),
                update(5, 560.0, 35_960.0, ahead=145),
                update(6, 37_600.0, 0.2),
            ],
        }
    return run


def verdict(run):
    try:
        return credit_bars.source_burst(run, "run")
    except credit_bars.Invalid as error:
        return "INVALID", str(error)


class SourceBurst(unittest.TestCase):
    def assert_verdict(self, run, expected, reason):
        got = verdict(run)
        self.assertEqual(got[0], expected, got)
        self.assertIn(reason, got[1])

    def test_clean_runs_pass_and_report_their_readings(self):
        self.assert_verdict(burst(), "PASS", "healthy admission to dispatch max 36000.0 ms")
        self.assert_verdict(burst(), "PASS", "at most 146 burst messages queued ahead")
        self.assert_verdict(burst(), "PASS", "at most 0.3 ms before it")
        self.assert_verdict(burst(), "PASS", "burst finished in the RIB 37000 ms")
        self.assert_verdict(burst(control=True), "PASS", "4,054 routes/s")
        self.assertNotIn("healthy", verdict(burst(control=True))[1])

    def test_latency_reading_follows_an_injected_delay(self):
        """The reading is the dispatch stamp less the admission stamp of the
        slowest update: delaying one dispatch by a known time moves it by
        exactly that, and delaying its send does not."""
        run = burst()
        before = credit_bars.source_burst_readings(run, "run")
        run["healthy"]["updates"][2][3] += 250.0
        run["healthy"]["updates"][2][4] += 250.0
        after = credit_bars.source_burst_readings(run, "run")
        self.assertEqual(after["dispatch_max_ms"] - before["dispatch_max_ms"], 250.0)
        self.assertEqual(after["delivery_max_ms"] - before["delivery_max_ms"], 250.0)
        run["healthy"]["updates"][2][1] -= 100.0
        late = credit_bars.source_burst_readings(run, "run")
        self.assertEqual(late["dispatch_max_ms"], after["dispatch_max_ms"])
        self.assertEqual(late["delivery_max_ms"] - after["delivery_max_ms"], 100.0)

    def test_failed_check_fails_before_any_instrument_question(self):
        for check in credit_bars.SOURCE_BURST_CHECKS:
            run = burst()
            run["checks"][check] = False
            run["shape"]["burst_interval_ms"] = 10.0
            self.assert_verdict(run, "FAIL", f"failed checks: {check}")
        run = burst()
        del run["checks"]["per_source_order"]
        self.assert_verdict(run, "INVALID", "incomplete or malformed checks")

    def test_paced_burst_is_invalid(self):
        for control in (False, True):
            run = burst(control)
            run["shape"]["burst_interval_ms"] = 10.0
            self.assert_verdict(run, "INVALID", "the burst was paced (10 ms between UPDATEs")
            run = burst(control)
            run["burst"]["paced_sleep_ms"] = 1_500.0
            self.assert_verdict(run, "INVALID", "1500 ms slept")

    def test_missing_or_disordered_stamps_are_invalid(self):
        for column in (2, 3, 4):
            run = burst()
            run["healthy"]["updates"][3][column] = None
            self.assert_verdict(run, "INVALID", "missing a stamp")
        run = burst()
        run["healthy"]["updates"][3][3] = run["healthy"]["updates"][3][2] - 1
        self.assert_verdict(run, "INVALID", "healthy update 4 has stamps out of order")
        run = burst()
        run["healthy"]["markers_lost"] = 2
        self.assert_verdict(run, "INVALID", "2 dispatch markers were never answered")
        run = burst()
        run["healthy"]["updates"] = []
        self.assert_verdict(run, "INVALID", "no healthy update was sent")
        run = burst()
        del run["burst"]["rib_done_ms"]
        self.assert_verdict(run, "INVALID", "missing instrument run: burst.rib_done_ms")
        run = burst()
        run["healthy"]["columns"].reverse()
        self.assert_verdict(run, "INVALID", "unknown healthy update columns")

    def test_burst_no_healthy_update_was_queued_behind_is_invalid(self):
        run = burst()
        # The burst was over before the third healthy update was admitted.
        run["burst"]["rib_done_ms"] = 545.0
        run["burst"]["completion_ms"] = 546.0
        self.assert_verdict(run, "INVALID", "2 of 6 healthy updates were admitted while")
        run["burst"]["rib_done_ms"] = 565.0
        run["burst"]["completion_ms"] = 566.0
        self.assertEqual(verdict(run)[0], "PASS")

    def test_seeded_stall_is_invalid_and_shows_its_reading(self):
        run = burst(measured=False)
        run["seeded"] = {"stall_ms": 200.0, "sequence": 2}
        run["healthy"]["updates"][1] = update(2, 120.0, 200.4)
        self.assert_verdict(
            run,
            "INVALID",
            "seeded stall of 200 ms at healthy update 2: admission to dispatch read 200.4 ms "
            "there and at most 0.2 ms on the other updates before the burst",
        )
        run["seeded"]["sequence"] = 99
        self.assert_verdict(run, "INVALID", "healthy update 99 was never sent")

    def test_measured_run_needs_the_fixed_shape_and_no_compiler(self):
        for control in (False, True):
            run = burst(control)
            run["host"]["compiler_watch"].update(observed=3, first="rustc")
            self.assert_verdict(run, "INVALID", "compiler observed during the timed cell: rustc")
            run["mode"] = "correctness"
            self.assert_verdict(run, "PASS", "correctness run")
            run = burst(control)
            run["host"]["compiler_watch"]["unavailable"] = "permission denied"
            self.assert_verdict(run, "INVALID", "compiler roster unavailable")
            run = burst(control)
            run["host"]["compiler_watch"]["samples"] = 0
            self.assert_verdict(run, "INVALID", "compiler roster unavailable")
            run = burst(control)
            run["shape"]["receivers"] = 8
            self.assert_verdict(run, "INVALID", "shape.receivers is 8, not the fixed 150")
            run = burst(control)
            run["mode"] = "timed"
            self.assert_verdict(run, "INVALID", "unknown mode 'timed'")


class Directories(unittest.TestCase):
    def test_check_judges_each_result_and_an_unexplained_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paced = burst(control=True, measured=False)
            paced["shape"]["burst_interval_ms"] = 5.0
            (root / "source-burst.json").write_text(json.dumps(burst(measured=False)))
            (root / "source-burst-control.json").write_text(json.dumps(paced))
            lines = credit_bars.check(root)
            self.assertEqual([verdict for _, verdict, _ in lines], ["PASS", "INVALID"])
            self.assertTrue(lines[0][0].endswith(" source-burst"), lines[0])
            self.assertIn("the burst was paced", lines[1][2])
            # A nonzero exit beside a result whose checks all passed.
            (root / "source-burst-exit.json").write_text('{"cell": "source-burst", "exit": 1}')
            self.assertEqual(credit_bars.check(root)[0][1], "INVALID")
            (root / "source-burst.json").unlink()
            self.assertIn("exited without a result", credit_bars.check(root)[0][2])

    def analyze(self, parent, candidate, listed=True):
        with tempfile.TemporaryDirectory() as directory:
            for name, extra in (("parent", parent), ("candidate", candidate)):
                files = test_credit_bars.arm(name == "candidate")
                cells = test_credit_bars.ALL_CELLS + (sorted(extra) if listed else [])
                files["provenance.jsonl"] = test_credit_bars.provenance(name, cells)
                files.update({f"{cell}.json": run for cell, run in extra.items()})
                for file, value in files.items():
                    path = Path(directory, name, "1", file)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    if file.endswith(".jsonl"):
                        path.write_text("".join(json.dumps(line) + "\n" for line in value))
                    else:
                        path.write_text(json.dumps(value))
            results = credit_bars.verdicts(Path(directory, "parent"), Path(directory, "candidate"))
            return {name: (verdict, reason) for name, verdict, reason in results}

    def test_analyze_reports_the_cell_only_where_it_ran(self):
        without = self.analyze({}, {})
        self.assertFalse([name for name in without if "source-burst" in name])
        gated = dict.fromkeys(credit_bars.CELLS, "PASS")
        self.assertEqual({name: without[name][0] for name in credit_bars.CELLS}, gated)

        fixed = copy.deepcopy(burst())
        fixed["healthy"]["updates"] = [update(n, 100.0 + 20 * n, 240.0, ahead=1) for n in range(25)]
        fixed["burst"]["completion_ms"] = BURST_START + (BURST_DONE + 20 - BURST_START) * 1.05
        results = self.analyze(
            {"source-burst": burst(), "source-burst-control": burst(control=True)},
            {"source-burst": fixed, "source-burst-control": burst(control=True)},
        )
        self.assertEqual({name: results[name][0] for name in credit_bars.CELLS}, gated)
        for arm in ("parent", "candidate"):
            for cell in credit_bars.SOURCE_BURST:
                self.assertEqual(results[f"{arm} 1 {cell}"][0], "PASS")
        compared = results["source-burst candidate over parent"]
        self.assertEqual(compared[0], "REPORT")
        self.assertIn("burst completion x1.05", compared[1])
        self.assertIn("max 240.0 ms against 36000.0 ms", compared[1])
        self.assertIn("queued ahead 1 against 146", compared[1])
        self.assertIn("ingest rate x1.00", results["source-burst-control candidate over parent"][1])

    def test_analyze_rejects_a_result_no_run_listed(self):
        results = self.analyze({"source-burst": burst()}, {}, listed=False)
        self.assertEqual(results["parent 1 source-burst"][0], "INVALID")
        self.assertIn("not from a listed run", results["parent 1 source-burst"][1])
        self.assertNotIn("source-burst candidate over parent", results)


if __name__ == "__main__":
    unittest.main()
