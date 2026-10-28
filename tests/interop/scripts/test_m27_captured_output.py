#!/usr/bin/env python3
"""Exercise M27's actual captured-output assertions without a running lab."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
DRIVER = Path(__file__).with_name("test-m27-aspa-rtr2.sh")
# Keep the real initialization, shared library and assertion functions. Only
# omit the entry point that deploys and queries the live topology.
SOURCE, TRAILING = DRIVER.read_text().rsplit('\nmain "$@"\n', 1)
if TRAILING:
    raise ValueError("unexpected code after the M27 entry point")
LARGE = 2 * 1024 * 1024
STUBS = r'''
docker() {
    case "$1" in
        ps) : ;;
        inspect)
            if [ "$2" = -f ]; then echo captured-fixture; fi
            ;;
        exec)
            shift
            [ "$*" = "clab-m27-aspa-rtr2-rustbgpd cat /tmp/rustbgpd.log" ] || return 91
            echo docker >> "$M27_CALLS"
            cat "$M27_CAPTURE"
            ;;
        *) return 92 ;;
    esac
}
grpcurl() {
    echo grpcurl >> "$M27_CALLS"
    cat "$M27_CAPTURE"
}
'''


def padding(large):
    return "rpki pending\n" * (LARGE // 13 + 1) if large else "rpki pending\n"


class M27CapturedOutputTests(unittest.TestCase):
    def run_assertion(self, function, captured):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            capture = directory / "captured"
            capture.write_text(captured)
            calls = directory / "calls"
            script = STUBS + SOURCE + f'\n{function}\n'
            script += 'printf "RESULT pass=%s fail=%s\\n" "$pass" "$fail"\n[ "$fail" -eq 0 ]\n'
            environment = {
                **os.environ,
                "M27_CAPTURE": str(capture),
                "M27_CALLS": str(calls),
                "CLEANUP": "0",
                "LC_ALL": "C",
            }
            try:
                result = subprocess.run(
                    ["bash", "-c", script, str(DRIVER)], cwd=ROOT,
                    env=environment, capture_output=True, text=True,
                    timeout=5, check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise self.failureException(
                    f"{function} did not finish: stdout={error.stdout!r}; stderr={error.stderr!r}"
                ) from None
            return result, calls.read_text().splitlines()

    def test_v2_near_front_accepts_both_log_formats(self):
        for marker in ('{"fields":{"rtr_version":2}}', "RTR connected rtr_version=2"):
            for large in (False, True):
                with self.subTest(marker=marker, large=large):
                    result, calls = self.run_assertion(
                        "test_rtr_v2_session", marker + "\n" + padding(large)
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn("RESULT pass=2 fail=0", result.stdout)
                    self.assertEqual(calls, ["docker"])
                    self.assertEqual(result.stderr, "")

    def test_absent_v2_is_rejected(self):
        for large in (False, True):
            with self.subTest(large=large):
                result, _ = self.run_assertion("test_rtr_v2_session", padding(large))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("RTR v2 connection not found in logs", result.stdout)
                self.assertIn("RESULT pass=1 fail=1", result.stdout)
                self.assertEqual(result.stderr, "")

    def test_early_fallback_is_rejected_even_with_v2_at_end(self):
        for marker in ('{"fields":{"rtr_version":2}}', "RTR connected rtr_version=2"):
            for large in (False, True):
                with self.subTest(marker=marker, large=large):
                    captured = "falling back to v1\n" + padding(large) + marker + "\n"
                    result, _ = self.run_assertion("test_rtr_v2_session", captured)
                    self.assertIn("RTR v2 connection established", result.stdout)
                    self.assertIn("RTR fell back to v1 (unexpected)", result.stdout)
                    self.assertNotIn("No RTR v1 fallback detected", result.stdout)
                    self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                    self.assertIn("RESULT pass=1 fail=1", result.stdout)
                    self.assertEqual(result.stderr, "")

    def test_aspa_wait_accepts_valid_state_near_front(self):
        for large in (False, True):
            with self.subTest(large=large):
                captured = json.dumps({
                    "routes": [{"aspaState": "valid"}],
                    "padding": "x" * LARGE if large else "",
                }, indent=2)
                result, calls = self.run_assertion("wait_aspa_validation", captured)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("ASPA validation states populated (attempt 1)", result.stdout)
                self.assertEqual(calls, ["grpcurl"])
                self.assertEqual(result.stderr, "")

    def test_explain_accepts_case_insensitive_reason_near_front(self):
        for large in (False, True):
            with self.subTest(large=large):
                result, calls = self.run_assertion(
                    "test_aspa_best_path_explain", "ASPA_PREFERENCE\n" + padding(large)
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("RESULT pass=1 fail=0", result.stdout)
                self.assertEqual(calls, ["grpcurl"])
                self.assertEqual(result.stderr, "")

    def test_missing_explain_reason_is_rejected(self):
        for large in (False, True):
            with self.subTest(large=large):
                result, _ = self.run_assertion("test_aspa_best_path_explain", padding(large))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("ExplainBestPath does not mention aspa_preference", result.stdout)
                self.assertIn("RESULT pass=0 fail=1", result.stdout)
                self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
