#!/usr/bin/env python3
"""Tests for the headline campaign driver and its extractor.

The extractor must reproduce the committed headline receipts: every
summary.csv row, and the medians the receipt tables publish. A finished leg
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

    @unittest.skipUnless(V0730.is_dir(), "v0.73.0 headline bundle not in this tree")
    def test_v0730_summary_rows(self):
        names = {"v0730": "v0.73.0", "v0720": "v0.72.0", "v0680": "v0.68.0",
                 "xh": "v0.68.0-daemon/v0.72.0-harness"}
        with tempfile.TemporaryDirectory() as out:
            self.assertEqual(quiet_main([str(V0730), "--out", out]), 0)
            self.assertEqual(summary_rows(Path(out) / "summary.csv", names),
                             summary_rows(V0730 / "summary.csv", {}))

    @unittest.skipUnless(V0730.is_dir(), "v0.73.0 headline bundle not in this tree")
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
        with self.assertRaisesRegex(summarize.ExtractionError, "flap metric line counts"):
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

    def test_establishment_span_from_daemon_log(self):
        cell = matrix_leg(self.tmp, "matrix-a-r1-s2")
        log = cell / "reloadstall.log"
        log.write_text(log.read_text().replace("established 700 at", "established 3 at"))
        stamps = ["2026-09-28T01:00:00.100Z", "2026-09-28T01:00:00.400Z", "2026-09-28T01:00:00.900Z"]
        (cell / "daemon.log").write_text("".join(
            json.dumps({"timestamp": t, "fields": {"message": "session established"}}) + "\n" for t in stamps))
        _, spans, _ = summarize.extract(self.tmp)
        self.assertEqual(spans, [["a", "1", "s2", 3, 3, "0.800"]])

    def test_bundle_needs_out(self):
        self.assertEqual(quiet_main([str(V0720)]), 2)

    def test_empty_source_fails(self):
        self.assertEqual(self.run_main(), 1)


FAKE_CARGO = """#!/usr/bin/env bash
# Stand-in for cargo: a product build writes a daemon whose bytes are the
# tree hash (FAKE_CARGO=tree) or the commit (FAKE_CARGO=commit), or fails.
set -euo pipefail
[[ ${FAKE_CARGO} != fail ]] || { echo "fake build failure" >&2; exit 101; }
if [[ " $* " == *" --manifest-path "* ]]; then
    mkdir -p bench/scale/target/release && echo harness >bench/scale/target/release/reloadstall
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
        self.env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FIXTURES": str(V0720 / "matrix"),
                    "CELLS": "matrix", "RUNS": "1"}

    def campaign(self, *arms, **env):
        return subprocess.run(["bash", str(self.repo / "bench/scale/headline/run-campaign.sh"), str(self.out), *arms],
                              env={**self.env, **env}, capture_output=True, text=True)

    def progress(self):
        return (self.out / "progress.txt").read_text()

    def test_failed_build_exits_nonzero(self):
        result = self.campaign("a=HEAD", FAKE_CARGO="fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("campaign done", self.progress())
        self.assertFalse(list(self.out.glob("matrix-*")))

    def test_commit_dependent_daemon_exits_nonzero(self):
        result = self.campaign("a=HEAD", FAKE_CARGO="commit")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("STOP: a: daemon at HEAD hashes", self.progress())
        self.assertNotIn("campaign done", self.progress())

    def test_failed_leg_exits_nonzero(self):
        result = self.campaign("a=HEAD", FAKE_CARGO="tree", FAKE_MATRIX_FAIL="1")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("campaign done rc=1 failed=matrix-a-r1-s2 matrix-a-r1-s3", self.progress())

    def test_two_arms_pass_and_summarize(self):
        result = self.campaign("a=HEAD", "b=HEAD", FAKE_CARGO="tree")
        self.assertEqual(result.returncode, 0, self.progress())
        self.assertIn("campaign done rc=0 failed=none", self.progress())
        self.assertIn("| matrix-s2 | reload_completion_p50 | ", (self.out / "report.md").read_text())
        self.assertIn("cpus_allowed=", (self.out / "placement.txt").read_text())
        self.assertRegex(self.progress(), r"matrix-a-r1-s2 start load=\S+ \S+ \S+ pswpin=\d+ pswpout=\d+ +cpus=\S+")
        # A rerun resumes: every leg is already done.
        again = self.campaign("a=HEAD", "b=HEAD", FAKE_CARGO="tree")
        self.assertEqual(again.returncode, 0)
        self.assertEqual(self.progress().count("already pass, skip"), 4)
        # Other arms in the same output directory are refused.
        self.assertEqual(self.campaign("c=HEAD", "b=HEAD", FAKE_CARGO="tree").returncode, 2)

    def test_dry_run_rotates_arm_order(self):
        result = self.campaign("a=HEAD", "b=HEAD", "c=HEAD", DRY_RUN="1", CELLS="rr", RUNS="3")
        self.assertEqual(result.returncode, 0)
        order = [line.split()[1] for line in result.stdout.splitlines() if line.startswith("rr ")]
        self.assertEqual(order, ["a", "b", "c", "b", "c", "a", "c", "a", "b"])
        legs = self.campaign("a=HEAD", DRY_RUN="1", MATRIX_SCENARIOS="s2").stdout
        self.assertEqual([line for line in legs.splitlines() if line.startswith("matrix")], ["matrix a 1 s2"])
        self.assertFalse(self.out.exists())


if __name__ == "__main__":
    unittest.main()
