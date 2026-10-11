#!/usr/bin/env python3
"""Exercise the M69 driver's actual sample oracle and release-child cleanup."""

import ast
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import Mock


DRIVER = Path(__file__).with_name("test-m69-evpn-preference-df-frr.sh")
PYTHON = DRIVER.read_text().split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
FUNCTIONS = {"flood_suppressed", "check_samples", "reap_release", "parse_daemon_log", "wait_daemon_exit", "frr_command"}
DEFINITIONS = [node for node in ast.parse(PYTHON).body
               if isinstance(node, ast.FunctionDef) and node.name in FUNCTIONS]
assert {node.name for node in DEFINITIONS} == FUNCTIONS
NAMESPACE = {"re": re, "json": json}
exec(compile(ast.Module(body=DEFINITIONS, type_ignores=[]), str(DRIVER), "exec"), NAMESPACE)


RESTART_BODY = next(node.body for node in ast.parse(PYTHON).body if isinstance(node, ast.Try))
RESTART_PREFIX = RESTART_BODY[:next(
    index + 1 for index, node in enumerate(RESTART_BODY)
    if "start-rustbgpd-m69-vtep.sh" in ast.unparse(node))]


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

    def test_actual_startup_banner_preserves_json_df_events(self):
        starting = {"target": "rustbgpd", "fields": {
            "message": "starting rustbgpd", "version": "0.75.0"}}
        transition = {"fields": {"message": "EVPN segment: DF role updated", "role": "df"}}
        # Exact stderr block retained from an M69 restart; version comes from
        # the preceding structured startup record, not a release-specific skip.
        banner = "\n  rustbgpd 0.75.0 | AS 65000 | router-id 10.0.0.1\n" \
            "  |- 1 peers (1 iBGP)\n" \
            "  |- grpc: tcp://0.0.0.0:50051 (token auth)\n" \
            "  |- grpc: unix:///var/lib/rustbgpd/grpc.sock\n" \
            "  |- metrics: http://0.0.0.0:9179/metrics\n\n"
        text = json.dumps(starting) + "\n" + banner + json.dumps(transition) + "\n"
        parse = NAMESPACE["parse_daemon_log"]
        self.assertEqual(parse(text), [starting, transition])
        for broken in (text.replace("1 peers (1 iBGP)", "2 peers (2 iBGP)"),
                       text.replace("  |- metrics: http://0.0.0.0:9179/metrics\n", ""),
                       text.replace("rustbgpd 0.75.0", "rustbgpd 0.74.0"),
                       banner + json.dumps(transition),
                       text + "unexpected stderr warning\n",
                       text + '{"fields":{"message":"EVPN segment: DF role updated","role":"df"}\n'):
            with self.subTest(broken=broken):
                with self.assertRaises(json.JSONDecodeError):
                    parse(broken)

    def run_restart_prefix(self, ending):
        def stat(state="S", start="123"):
            return "42 (rustbgpd) " + " ".join([state] + ["0"] * 18 + [start])

        clock = 0
        observed_exit = False
        checks = 0
        restarted = False

        def poll_delay(seconds):
            nonlocal clock
            clock += seconds if ending is not None else 5

        def run(args, timeout=10):
            nonlocal checks, observed_exit, restarted
            self.assertGreater(timeout, 0)
            if "bridge" in args:
                return samples()[0]["bridge"]
            if "kill -KILL" in args[-1]:
                return stat()
            if args[-1] == "42":
                checks += 1
                if clock == 0 or ending is None:
                    return stat()
                observed_exit = True
                return "" if ending == "gone" else stat(*ending)
            # Neither the peer hold nor replacement may run until an actual
            # poll observes exit; the controlled clock alone is not enough.
            self.assertTrue(observed_exit)
            self.assertGreaterEqual(checks, 2)
            if "show bgp neighbors 10.0.0.1 json" in args:
                return json.dumps({"10.0.0.1": {"bgpState": "Idle"}})
            if args[-1] == "restart":
                restarted = True
            return ""

        with tempfile.TemporaryDirectory() as directory:
            namespace = {"re": re, "json": json, "pe1": "pe1", "pe2": "pe2",
                         "output": Path(directory), "run": run,
                         "time": Mock(monotonic=lambda: clock, time=lambda: 0,
                                      sleep=poll_delay)}
            exec(compile(ast.Module(body=DEFINITIONS, type_ignores=[]), str(DRIVER), "exec"), namespace)
            prefix = compile(ast.Module(body=RESTART_PREFIX, type_ignores=[]), str(DRIVER), "exec")
            if ending is None:
                with self.assertRaisesRegex(RuntimeError, "did not exit within 10s"):
                    exec(prefix, namespace)
                self.assertFalse(restarted)
            else:
                exec(prefix, namespace)
                self.assertTrue(restarted)

    def test_restart_waits_for_old_lifetime_before_peer_hold_and_replacement(self):
        for ending in ("gone", ("Z", "123"), ("X", "123"), ("S", "456")):
            with self.subTest(ending=ending):
                self.run_restart_prefix(ending)

    def test_restart_timeout_does_not_hold_peer_or_start_replacement(self):
        self.run_restart_prefix(None)

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
