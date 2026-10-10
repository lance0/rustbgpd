#!/usr/bin/env python3
"""Tests for converged_rejoin.py: the schedule, the acceptance file, the bars,
and the analyzer's refusal (INVALID) of doctored or incomplete campaigns."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import converged_rejoin  # noqa: E402

PY = HERE / "converged_rejoin.py"
HEADER = ("converged_rejoin_csv_header,round,peers_total,peers_flapped,prefixes,rejoin_p50_s,rejoin_max_s,"
          "survivor_maxgap_ms,readiness_samples,rss_mib,sessions_up,parse_errors")
# Real rows: one arm's 700 x 400,400 converged-rejoin rounds at K=1 and K=50,
# two repetitions of three rounds (round, rejoin_p50_s, rejoin_max_s,
# survivor_maxgap_ms, readiness_samples, rss_mib). Pooled, they give the
# published K=1 rejoin_max median 0.310 s [0.278-0.329] and the K=50 median
# 12.757 s [12.671-13.158].
FIXTURE = {
    (1, 1): [(1, 0.291354, 0.291354, 272.631, 12, 444), (2, 0.301601, 0.301601, 277.292, 12, 424),
             (3, 0.277951, 0.277951, 274.243, 12, 420)],
    (1, 2): [(1, 0.329437, 0.329437, 278.063, 12, 445), (2, 0.318299, 0.318299, 273.575, 12, 429),
             (3, 0.321650, 0.321650, 282.211, 12, 438)],
    (50, 1): [(1, 6.600786, 12.670692, 7851.415, 26, 409), (2, 6.673967, 12.795301, 5076.774, 26, 447),
              (3, 6.669373, 12.721580, 8360.516, 26, 429)],
    (50, 2): [(1, 6.874453, 13.157993, 1295.195, 26, 447), (2, 6.679188, 12.753079, 5567.347, 26, 412),
              (3, 6.646099, 12.759939, 4821.097, 26, 432)],
}
QUIET_HEADER = ("sample\tepoch_s\tload1\tpswpin\tpswpout\tgovernors\tperformance_governors\tgovernor_count"
                "\tcompetitors\tquiet\tfailed_dimensions\toriginal_attempt")
QUIET = "\n".join([QUIET_HEADER,
                   "1\t1000\t0.50\t77\t88\tperformance,performance\t2\t2\tnone\ttrue\tnone\t1",
                   "2\t1030\t0.40\t77\t88\tperformance,performance\t2\t2\tnone\ttrue\tnone\t2"]) + "\n"


def campaign(out: Path, *, scale: dict | None = None, bars: dict | None = None, quiet: bool = True,
             smoke: bool = False) -> Path:
    """Both arms from FIXTURE; scale maps (arm, K) to a factor on the two rejoin clocks."""
    out.mkdir(parents=True, exist_ok=True)
    c = {"peers": 700, "prefixes": 400400, "ks": [1, 50], "repeats": 2, "rounds": 3, "quiet": quiet,
         "smoke": smoke, "bars": {**converged_rejoin.DEFAULT_BARS, **(bars or {})}}
    (out / "campaign.json").write_text(json.dumps(c))
    runs = ["arm\tk\trep\tharness_rc\tdaemon_rc"]
    for arm, k, rep in converged_rejoin.schedule(c):
        name = f"{arm}-k{k}-rep{rep}"
        f = (scale or {}).get((arm, k), 1.0)
        rows = [f"converged_rejoin_csv,{r},700,{k},400400,{p50 * f:.6f},{mx * f:.6f},{gap:.6f},{ready},{rss},700,0"
                for r, p50, mx, gap, ready, rss in FIXTURE[(k, rep)]]
        (out / "raw" / name).mkdir(parents=True)
        (out / "raw" / name / "reloadstall.log").write_text("\n".join(["startup", HEADER, *rows, "done"]) + "\n")
        if quiet:
            (out / "quiet").mkdir(exist_ok=True)
            (out / "quiet" / f"{name}.tsv").write_text(QUIET)
        runs.append(f"{arm}\t{k}\t{rep}\t0\t0")
    (out / "runs.tsv").write_text("\n".join(runs) + "\n")
    (out / "schedule.txt").write_text("".join(f"{a} {k} {r}\n" for a, k, r in converged_rejoin.schedule(c)))
    return out


def analyze(out: Path) -> tuple[int, str, dict]:
    p = subprocess.run([sys.executable, str(PY), "analyze", str(out)], capture_output=True, text=True)
    verdict = json.loads((out / "verdict.json").read_text()) if (out / "verdict.json").exists() else {}
    return p.returncode, p.stdout, verdict


def edit(path: Path, old: str, new: str, count: int = 1) -> None:
    text = path.read_text()
    assert old in text, (path, old)
    path.write_text(text.replace(old, new, count))


class Analyzer(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def test_fixture_reproduces_published_numbers_and_identical_arms_fail(self):
        rc, text, v = analyze(campaign(self.tmp / "c"))
        self.assertEqual(rc, 1, text)
        self.assertEqual(v["verdict"], "FAIL")
        for arm in ("base", "head"):
            self.assertAlmostEqual(v["table"][f"{arm}_k1"]["max_med"], 0.309950, places=6)
            self.assertEqual((v["table"][f"{arm}_k1"]["max_min"], v["table"][f"{arm}_k1"]["max_max"]),
                             (0.277951, 0.329437))
            self.assertAlmostEqual(v["table"][f"{arm}_k50"]["max_med"], 12.756509, places=6)
            self.assertEqual(v["table"][f"{arm}_k50"]["n"], 6)
        self.assertFalse(v["bars"]["B1"]["pass"])  # identical arms are not disjoint
        self.assertTrue(v["bars"]["B2"]["pass"] and v["bars"]["B3"]["pass"])

    def test_disjoint_improvement_passes(self):
        rc, text, v = analyze(campaign(self.tmp / "c", scale={("head", 50): 0.1}))
        self.assertEqual(rc, 0, text)
        self.assertEqual(v["verdict"], "PASS")
        self.assertIn("VERDICT: PASS", text)
        rows = (self.tmp / "c" / "samples.tsv").read_text().splitlines()
        self.assertEqual(len(rows), 1 + 24)

    def test_overlapping_improvement_fails_b1(self):
        # The head median is lower but its slowest round (13.158 s * 0.97) is not below base's fastest.
        rc, _, v = analyze(campaign(self.tmp / "c", scale={("head", 50): 0.97}))
        self.assertEqual((rc, v["bars"]["B1"]["pass"]), (1, False))

    def test_low_k_regression_fails_b2(self):
        rc, _, v = analyze(campaign(self.tmp / "c", scale={("head", 50): 0.1, ("head", 1): 1.25}))
        self.assertEqual((rc, v["bars"]["B1"]["pass"], v["bars"]["B2"]["pass"]), (1, True, False))

    def test_survivor_gap_regression_fails_b3(self):
        out = campaign(self.tmp / "c", scale={("head", 50): 0.1})
        edit(out / "raw" / "head-k1-rep1" / "reloadstall.log", ",272.631000,", ",900.000000,")
        rc, _, v = analyze(out)
        self.assertEqual((rc, v["bars"]["B1"]["pass"], v["bars"]["B3"]["pass"]), (1, True, False))

    def test_not_worse_mode_accepts_identical_arms_and_rejects_regression(self):
        rc, text, _ = analyze(campaign(self.tmp / "a", bars={"high_k": "not_worse"}))
        self.assertEqual(rc, 0, text)
        rc, _, v = analyze(campaign(self.tmp / "b", bars={"high_k": "not_worse"}, scale={("head", 50): 1.2}))
        self.assertEqual((rc, v["bars"]["B1"]["pass"]), (1, False))

    def test_smoke_judges_validity_but_no_bars(self):
        # A regression big enough to fail B1 and B2 is still a valid smoke.
        rc, text, v = analyze(campaign(self.tmp / "c", smoke=True, scale={("head", 1): 3.0}))
        self.assertEqual((rc, v["verdict"], v["bars"]), (0, "SMOKE", {}), text)
        self.assertIn("performance bars not judged", text)

    def test_unquieted_campaign_needs_no_quiet_samples(self):
        rc, text, _ = analyze(campaign(self.tmp / "c", quiet=False, scale={("head", 50): 0.1}))
        self.assertEqual(rc, 0, text)


class Invalid(unittest.TestCase):
    """Each doctored input must fail closed: exit 4, verdict INVALID, never PASS."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.out = campaign(self.tmp / "c", scale={("head", 50): 0.1})  # a PASS before doctoring
        self.log = self.out / "raw" / "head-k50-rep1" / "reloadstall.log"

    def assert_invalid(self, why: str) -> None:
        rc, text, v = analyze(self.out)
        self.assertEqual(rc, 4, text)
        self.assertEqual(v.get("verdict", "INVALID"), "INVALID")
        self.assertIn(why, text)

    def test_harness_rc(self):
        edit(self.out / "runs.tsv", "head\t50\t1\t0\t0", "head\t50\t1\t1\t0")
        self.assert_invalid("head-k50-rep1: harness_rc=1")

    def test_daemon_rc(self):
        edit(self.out / "runs.tsv", "base\t1\t2\t0\t0", "base\t1\t2\t0\t143")
        self.assert_invalid("base-k1-rep2: harness_rc=0 daemon_rc=143")

    def test_cell_not_run(self):
        edit(self.out / "runs.tsv", "base\t50\t2\t0\t0\n", "")
        self.assert_invalid("base-k50-rep2: not run")

    def test_duplicate_run_row(self):
        with (self.out / "runs.tsv").open("a") as f:
            f.write("head\t1\t1\t0\t0\n")
        self.assert_invalid("duplicate runs.tsv row")

    def test_missing_row(self):
        edit(self.log, "converged_rejoin_csv,2,", "dropped,2,")
        self.assert_invalid("2/3 converged_rejoin_csv rows")

    def test_missing_log(self):
        self.log.unlink()
        self.assert_invalid("0/3 converged_rejoin_csv rows")

    def test_readiness_zero(self):
        edit(self.log, ",26,", ",0,")
        self.assert_invalid("readiness")

    def test_wrong_k(self):
        edit(self.log, ",700,50,400400,", ",700,49,400400,")
        self.assert_invalid("head-k50-rep1: round 1 fails")

    def test_wrong_fleet(self):
        edit(self.log, "converged_rejoin_csv,1,700,", "converged_rejoin_csv,1,699,")
        self.assert_invalid("head-k50-rep1: round 1 fails")

    def test_wrong_prefix_count(self):
        edit(self.log, "converged_rejoin_csv,2,700,50,400400,", "converged_rejoin_csv,2,700,50,400399,")
        self.assert_invalid("head-k50-rep1: round 2 fails")

    def test_smoke_cell_still_invalid(self):
        out = campaign(self.tmp / "s", smoke=True)
        (out / "raw" / "base-k1-rep1" / "reloadstall.log").unlink()
        rc, text, v = analyze(out)
        self.assertEqual((rc, v["verdict"]), (4, "INVALID"), text)

    def test_run_outside_schedule(self):
        with (self.out / "runs.tsv").open("a") as f:
            f.write("head\t50\t3\t0\t0\n")
        self.assert_invalid("runs.tsv row ('head', '50', '3') is not in the schedule")

    def test_relabelled_run_row(self):
        # Same row count, but one scheduled cell is replaced by an unscheduled one.
        edit(self.out / "runs.tsv", "base\t1\t2\t0\t0", "base\t2\t2\t0\t0")
        self.assert_invalid("runs.tsv row ('base', '2', '2') is not in the schedule")

    def test_schedule_file_differs(self):
        edit(self.out / "schedule.txt", "head 1 1\nhead 50 1\n", "head 50 1\nhead 1 1\n")
        self.assert_invalid("schedule.txt differs")

    def test_parse_errors_and_sessions(self):
        edit(self.log, ",700,0\n", ",699,0\n")
        self.assert_invalid("head-k50-rep1: round 1 fails")

    def test_p50_above_max_and_nan(self):
        edit(self.log, "converged_rejoin_csv,1,700,50,400400,0.660079,", "converged_rejoin_csv,1,700,50,400400,99.0,")
        self.assert_invalid("head-k50-rep1: round 1 fails")
        edit(self.log, ",99.0,", ",nan,")
        self.assert_invalid("head-k50-rep1: round 1 fails")

    def test_duplicate_round_number(self):
        edit(self.log, "converged_rejoin_csv,3,", "converged_rejoin_csv,2,")
        self.assert_invalid("rounds [1, 2, 2] != 1..3")

    def test_unparseable_row(self):
        edit(self.log, "converged_rejoin_csv,1,700,50,", "converged_rejoin_csv,1,700,fifty,")
        self.assert_invalid("unparseable row")

    def test_no_accepted_quiet_sample(self):
        edit(self.out / "quiet" / "base-k50-rep1.tsv", "\n2\t1030", "\n1\t1030")
        self.assert_invalid("base-k50-rep1: quiet-host gate: samples ['1', '1']")

    def test_quiet_gate_fields(self):
        q = self.out / "quiet" / "base-k50-rep1.tsv"
        for old, new, why in (
                ("\ttrue\tnone\t2", "\tfalse\tload1\t2", "sample 2 is not quiet"),
                ("\t0.40\t", "\t2.40\t", "sample 2 is not quiet"),
                ("\tnone\ttrue\tnone\t2", "\t123:cargo\ttrue\tnone\t2", "sample 2 is not quiet"),
                ("\t2\t2\tnone\ttrue\tnone\t2", "\t1\t2\tnone\ttrue\tnone\t2", "sample 2 is not quiet"),
                ("1030\t0.40\t77\t88", "1030\t0.40\t78\t88", "swap counters moved"),
                ("2\t1030\t", "2\t1029\t", "samples 29 s apart, need 30"),
                ("2\t1030\t", "2\tlater\t", "unparseable")):
            with self.subTest(why=why, new=new):
                q.write_text(QUIET)
                edit(q, old, new)
                self.assert_invalid(f"base-k50-rep1: quiet-host gate: {why}")

    def test_campaign_json_missing_or_tampered(self):
        good = json.loads((self.out / "campaign.json").read_text())
        for field, value in (("bars.extra", 1), ("bars.rejoin_rel", "0.1"), ("bars.gap_max_abs_ms", None),
                             ("bars.gap_median_rel", True), ("bars.high_k", "faster"), ("bars", []),
                             ("quiet", "yes"), ("smoke", 0), ("peers", True), ("prefixes", 400400.0),
                             ("ks", [1, "50"]), ("ks", [1]), ("extra", 1)):
            with self.subTest(field=field, value=value):
                c = json.loads(json.dumps(good))
                if field.startswith("bars."):
                    c["bars"][field[5:]] = value
                else:
                    c[field] = value
                (self.out / "campaign.json").write_text(json.dumps(c))
                self.assert_invalid("campaign.json")
        (self.out / "campaign.json").write_text(json.dumps({**good, "bars": {
            k: v for k, v in good["bars"].items() if k != "gap_max_rel"}}))
        self.assert_invalid("missing bar(s) ['gap_max_rel']")
        (self.out / "campaign.json").write_text("[]")
        self.assert_invalid("campaign.json")
        (self.out / "campaign.json").unlink()
        self.assert_invalid("campaign.json")


class Setup(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)

    def init(self, *extra: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, str(PY), "init", str(self.tmp), "--peers", "700", "--prefixes",
                               "400400", "--repeats", "3", "--rounds", "3", "--quiet", "1", *extra],
                              capture_output=True, text=True)

    def test_schedule_alternates_arms(self):
        self.assertEqual(self.init("--ks", "1,50").returncode, 0)
        p = subprocess.run([sys.executable, str(PY), "schedule", str(self.tmp)], capture_output=True, text=True)
        self.assertEqual(p.stdout.splitlines(), [
            "base 1 1", "head 1 1", "head 50 1", "base 50 1",
            "base 50 2", "head 50 2", "head 1 2", "base 1 2",
            "base 1 3", "head 1 3", "head 50 3", "base 50 3"])

    def test_acceptance_overrides_are_recorded(self):
        acc = self.tmp / "acceptance.json"
        acc.write_text(json.dumps({"high_k": "not_worse", "gap_max_abs_ms": 250}))
        self.assertEqual(self.init("--ks", "1,50", "--acceptance", str(acc)).returncode, 0)
        bars = json.loads((self.tmp / "campaign.json").read_text())["bars"]
        self.assertEqual(bars, {**converged_rejoin.DEFAULT_BARS, "high_k": "not_worse", "gap_max_abs_ms": 250})

    def test_bad_acceptance_and_shape_are_refused(self):
        acc = self.tmp / "acceptance.json"
        for bad in ({"rejoin_rel": "0.1"}, {"unknown": 1}, {"high_k": "faster"}, {"gap_max_abs_ms": -1}, [1]):
            acc.write_text(json.dumps(bad))
            self.assertEqual(self.init("--ks", "1,50", "--acceptance", str(acc)).returncode, 2, bad)
        for ks in ("50,1", "1,1", "0,5", "1", "a,b"):
            self.assertEqual(self.init("--ks", ks).returncode, 2, ks)
        self.assertFalse((self.tmp / "campaign.json").exists())


if __name__ == "__main__":
    unittest.main()
