#!/usr/bin/env python3
"""Exercise the M69 driver's actual sample oracle and release-child cleanup."""

import ast
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import Mock


DRIVER = Path(__file__).with_name("test-m69-evpn-preference-df-frr.sh")
PYTHON = DRIVER.read_text().split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
FUNCTIONS = {"flood_suppressed", "check_samples", "reap_release"}
DEFINITIONS = [node for node in ast.parse(PYTHON).body
               if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
assert {node.name for node in DEFINITIONS} == FUNCTIONS
NAMESPACE = {"re": re}
exec(compile(ast.Module(body=DEFINITIONS, type_ignores=[]), str(DRIVER), "exec"), NAMESPACE)


def samples():
    return [{"elapsed": index / 10, "duration": 0.04, "errors": [], "df": 0,
             "bridge": "7: es0: <BROADCAST,UP> master br200\n flood off mcast_flood off bcast_flood off\n"}
            for index in range(120)]


class M69DfWaitCheckerTests(unittest.TestCase):
    def check(self, rows, first=0, window_end=12):
        return NAMESPACE["check_samples"](rows, first, 6, window_end)

    def test_complete_sampled_non_df_window_passes(self):
        self.assertEqual(self.check(samples()), [])

    def test_df_sample_fails(self):
        rows = samples()
        rows[20]["df"] = 1
        self.assertTrue(self.check(rows))

    def test_each_open_or_missing_flood_flag_fails(self):
        for flag in ("flood", "mcast_flood", "bcast_flood"):
            for replacement in (f" {flag} on", ""):
                with self.subTest(flag=flag, replacement=replacement):
                    rows = samples()
                    rows[20]["bridge"] = rows[20]["bridge"].replace(f" {flag} off", replacement)
                    self.assertTrue(self.check(rows))

    def test_long_sample_and_observation_gap_fail(self):
        rows = samples()
        rows[20]["duration"] = 0.251
        self.assertTrue(self.check(rows))
        rows = samples()
        del rows[20:23]
        self.assertTrue(self.check(rows))

    def test_missing_metric_bridge_and_failed_collection_fail(self):
        for field in ("df", "bridge"):
            with self.subTest(field=field):
                rows = samples()
                del rows[20][field]
                self.assertTrue(self.check(rows))
        rows = samples()
        rows[20]["errors"] = ["metrics request timed out"]
        self.assertTrue(self.check(rows))
        self.assertTrue(self.check(samples(), first=None))

    def test_truncated_tail_and_delayed_window_end_fail(self):
        # Adjacent 100 ms samples and a complete held phase cannot excuse
        # losing the tail after the peer is released.
        self.assertTrue(self.check(samples()[:62]))
        self.assertTrue(self.check(samples(), window_end=13))
        self.assertTrue(self.check(samples()[:60]))

    def test_pre_first_role_exclusion_does_not_hide_later_missing_samples(self):
        rows = samples()
        rows.insert(0, {"elapsed": -0.1, "duration": 0.04, "errors": ["daemon not started"]})
        self.assertEqual(self.check(rows, first=1), [])
        rows[20].pop("df")
        self.assertTrue(self.check(rows, first=1))

    def test_release_child_is_joined_after_success_timeout_or_error(self):
        for error in (None, subprocess.TimeoutExpired("vtysh", 10), OSError("read failed")):
            with self.subTest(error=error):
                process = Mock()
                process.poll.return_value = None if error else 0
                if error:
                    process.communicate.side_effect = error
                    with self.assertRaises(type(error)):
                        NAMESPACE["reap_release"](process)
                    process.kill.assert_called_once()
                else:
                    NAMESPACE["reap_release"](process)
                    process.kill.assert_not_called()
                process.wait.assert_called_once()


if __name__ == "__main__":
    unittest.main()
