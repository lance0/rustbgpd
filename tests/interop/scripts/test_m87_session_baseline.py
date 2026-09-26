#!/usr/bin/env python3
"""Exercise M87's actual baseline and continuity checks without a live lab."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest


DRIVER = Path(__file__).with_name("test-m87-exact-export-rejection.sh")
SOURCE = DRIVER.read_text()
BASELINE = SOURCE.split("metric_before=$(exact_rejections)", 1)[1].split(
    '\nlog "Phase 2:', 1
)[0]
BASELINE = "metric_before=$(exact_rejections)" + BASELINE


def function(name):
    marker = f"\n{name}() {{"
    if marker not in SOURCE:
        return ""  # The baseline regression also executes on the unfixed driver.
    return name + "() {" + SOURCE.split(marker, 1)[1].split("\n}\n", 1)[0] + "\n}\n"


def state(uptime=0, session="SESSION_STATE_ESTABLISHED", flaps=3):
    return {"state": session, "uptimeSeconds": str(uptime), "flapCount": str(flaps)}


class M87SessionBaselineTests(unittest.TestCase):
    def run_baseline(self, samples, ending=""):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            for index, sample in enumerate(samples):
                (path / f"state-{index}").write_text(json.dumps(sample))
            (path / "count").write_text("0")
            script = r'''
set -euo pipefail
SINK_ADDR=10.87.2.2
neighbor_state() {
    local index
    index=$(cat count)
    echo "$((index + 1))" > count
    if [ "$index" -ge "$LAST" ]; then index=$LAST; fi
    cat "state-$index"
}
exact_rejections() { echo 7; }
sleep() { :; }
ok() { echo "PASS $*"; }
fail() { echo "FAIL $*"; }
bird_protocol() { echo Established; }
'''
            script += f"LAST={len(samples) - 1}\n"
            for name in ("wait_condition", "capture_live_sink_baseline", "assert_session_continuity"):
                script += function(name)
            script += BASELINE + "\n" + ending
            result = subprocess.run(
                ["bash", "-c", script], cwd=path, text=True,
                capture_output=True, timeout=5, check=False,
            )
            return result, int((path / "count").read_text())

    def test_waits_past_zero_and_keeps_one_sample(self):
        result, calls = self.run_baseline([state(0), state(1, flaps=4)])
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(calls, 2)
        self.assertIn("flapCount=4, uptime=1", result.stdout)

    def test_does_not_accept_non_established_positive_uptime(self):
        result, calls = self.run_baseline([state(9, "SESSION_STATE_IDLE"), state(2)])
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(calls, 2)
        self.assertIn("uptime=2", result.stdout)

    def test_invalid_or_zero_sample_exhausts_bounded_wait(self):
        for sample in (state(0), {}, state("invalid"), state(4, "SESSION_STATE_IDLE")):
            with self.subTest(sample=sample):
                result, calls = self.run_baseline([sample])
                self.assertEqual(result.returncode, 1, result.stderr + result.stdout)
                self.assertEqual(calls, 10)
                self.assertIn("FAIL", result.stdout)

    def test_later_flap_and_uptime_reset_still_fail(self):
        for later in (state(5, flaps=4), state(0)):
            with self.subTest(later=later):
                result, _ = self.run_baseline(
                    [state(1), later],
                    'assert_session_continuity "$flaps_before" "$uptime_before" rejection',
                )
                self.assertIn("FAIL rejection: BIRD session continuity failed", result.stdout)


if __name__ == "__main__":
    unittest.main()
