#!/usr/bin/env python3
import copy
from datetime import datetime, timezone
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import qualify as Q
import recovery as R
from test_qualify import witness, metrics_text


def two_groups(generation="a"):
    row = witness("candidate", 4, 10)
    row.update(owned_groups=2, owned_routes=80, elapsed_us=50_000)
    for index, peer in enumerate(row["peers"]):
        peer[1] = 2 if index == 1 or (index >= 2 and generation == "b") else 1
    return row


class RecoveryTests(unittest.TestCase):
    def test_readiness_probe_retains_http_error_code(self):
        sampler = R.Readiness.__new__(R.Readiness)
        sampler.correctness = True
        error = Q.urllib.error.HTTPError("http://readyz", 503, "busy", {}, None)
        with patch.object(Q, "fetch", side_effect=error):
            row = sampler.probe(1.)
        self.assertEqual(row["status"], 503)
        self.assertEqual(row["http_error_code"], 503)
        self.assertEqual(row["scheduled"], 1.)
        self.assertIsNone(row["seconds"])

    def test_private_bar_misses_do_not_abort_later_recovery_cells(self):
        with tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryFile() as lock:
            manifest = {"recovery": Q.RECOVERY_BARS}
            def cell(*args):
                if args[2] == "private":
                    raise Q.AcceptanceFailure("baseline bar miss")
            with patch.object(R.sys, "argv", ["recovery.py", "run", temporary]), \
                 patch.object(Q, "manifest_for", return_value=manifest), \
                 patch.object(Q, "verify_export"), \
                 patch.dict(Q.os.environ, {"RUSTBGPD_HOST_LOCK_FD": str(lock.fileno())}), \
                 patch.object(R, "run_cell", side_effect=cell) as run, \
                 patch.object(R, "analyze") as analyze:
                R.main()
            self.assertEqual([call.args[2] for call in run.call_args_list], list(Q.SCHEDULE))
            self.assertEqual([call.args[3] for call in run.call_args_list], list(range(6)))
            analyze.assert_called_once_with(Path(temporary))

    def test_candidate_bar_and_private_invalid_still_abort_recovery_cells(self):
        for arm, error in (("candidate", Q.AcceptanceFailure("candidate bar miss")),
                           ("private", ValueError("technical failure"))):
            with self.subTest(arm=arm), tempfile.TemporaryDirectory() as temporary, tempfile.TemporaryFile() as lock:
                def cell(*args, arm=arm, error=error):
                    if args[2] == arm:
                        raise error
                with patch.object(R.sys, "argv", ["recovery.py", "run", temporary]), \
                     patch.object(Q, "manifest_for", return_value={"recovery": Q.RECOVERY_BARS}), \
                     patch.object(Q, "verify_export"), \
                     patch.dict(Q.os.environ, {"RUSTBGPD_HOST_LOCK_FD": str(lock.fileno())}), \
                     patch.object(R, "run_cell", side_effect=cell) as run, \
                     patch.object(R, "analyze") as analyze:
                    with self.assertRaises(type(error)):
                        R.main()
                self.assertEqual(run.call_count, 1 if arm == "candidate" else 2)
                analyze.assert_not_called()

    def test_control_bar_failure_summary_is_fail_not_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.analysis_fixture(root)
            path = root / "recovery-01-private/result.json"
            row = json.loads(path.read_text())
            row.update(status="FAIL", error="readiness HTTP 503")
            Q.write_json(path, row)
            with self.assertRaises(Q.AcceptanceFailure):
                R.analyze(root)
            summary = json.loads((root / "recovery-summary.json").read_text())
            self.assertEqual(summary["status"], "FAIL")
            self.assertFalse(summary["terminal_only_qualified"])
            self.assertEqual(summary["failed_cells"][0]["arm"], "private")

    def test_actual_group_membership_not_policy_names(self):
        a, b = two_groups(), two_groups("b")
        self.assertTrue(R.group_members(a, "candidate", 4, "a"))
        self.assertTrue(R.group_members(b, "candidate", 4, "b"))
        self.assertFalse(R.group_members(a, "candidate", 4, "b"))
        a["peers"][1][1] = 1
        with self.assertRaisesRegex(ValueError, "anchor policies coalesced"):
            R.group_members(a, "candidate", 4, "a")

    def test_aggregate_dirty_cannot_fake_actual_roster(self):
        row = two_groups()
        row["dirty"] = 4
        with self.assertRaisesRegex(ValueError, "aggregate observer"):
            R.roster(row, "candidate", 4)
        for peer in row["peers"]:
            peer[2] = True
        R.roster(row, "candidate", 4)

    def test_twenty_percent_headroom_is_required(self):
        for target in ("daemon", "peer"):
            row = two_groups()
            if target == "daemon":
                row["peak"] = int(row["daemon_budget"] * .8) + 1
            else:
                row["peers"][0][4] = int(row["peer_budget"] * .8) + 1
            with self.assertRaisesRegex(Q.AcceptanceFailure, "headroom"):
                R.roster(row, "candidate", 4)

    def test_clean_dirty_bit_does_not_prove_release(self):
        row = two_groups()
        self.assertTrue(R.settled(row))
        for key in ("completion_receipts", "marker_debt", "pending_resets", "retained_recovery",
                    "refresh_pending", "eor_pending", "protocol_obligations"):
            bad = copy.deepcopy(row)
            bad[key] = 1
            self.assertFalse(R.settled(bad))
        row["retained"] = 128
        self.assertTrue(R.settled(row), "fixed charged metadata is not live proof duty")

    def test_common_protocol_obligation_retains_origins_and_counts_each_peer_once(self):
        row = two_groups()
        row["peers"][0][5] = 1
        row["peers"][0][8] = row["peers"][0][9] = True
        row["marker_debt"] = row["refresh_pending"] = row["eor_pending"] = row["protocol_obligations"] = 1
        R.roster(row, "candidate", 4)
        self.assertFalse(R.settled(row))
        for field, value in (("protocol_obligations", 3), ("refresh_pending", 0), ("marker_debt", 0)):
            bad = copy.deepcopy(row)
            bad[field] = value
            with self.assertRaisesRegex(ValueError, "aggregate observer"):
                R.roster(bad, "candidate", 4)
        row["peers"][0][5] = 0
        row["marker_debt"] = 0
        R.roster(row, "candidate", 4)
        self.assertFalse(R.settled(row), "no terminal receipt does not clear pending protocol response")

    def test_missing_wire_phase_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "driver.log").write_text('evpn_control {"command":"connected","clients":3}\n'
                                            'evpn_control {"command":"finish"}\n')
            with self.assertRaisesRegex(ValueError, "missing required wire phase"):
                R.check_wire(root, 3, 10)

    def test_repeated_or_interrupted_dirty_snapshot_is_not_overlap(self):
        first = two_groups()
        first["dirty"] = 4
        second = copy.deepcopy(first)
        self.assertIsNone(R.dirty_pair([first, second], 4))
        second["elapsed_us"] += 50_000
        self.assertEqual(R.dirty_pair([first, second], 4), (first, second))
        middle = copy.deepcopy(first)
        middle["dirty"] = 3
        self.assertIsNone(R.dirty_pair([first, middle, second], 4))

    def test_timings_use_reload_trigger_and_all_resume_ack(self):
        events = [{"event": "reload", "generation": "a", "at": 1},
                  {"event": "complete", "command": "policy a", "at": 3},
                  {"event": "reload", "generation": "b", "at": 4},
                  {"event": "complete", "command": "policy b", "at": 7},
                  {"event": "command", "command": "resume", "at": 10},
                  {"event": "complete", "command": "resume", "at": 11},
                  {"event": "complete", "command": "settle", "at": 15}]
        self.assertEqual(R.timings(events), {"regroup-a-seconds": 2, "regroup-b-seconds": 3,
                                            "recovery-seconds": 4})
        with self.assertRaisesRegex(ValueError, "missing/duplicate"):
            R.timings(events[:-1])

    def test_socket_writes_and_wrapped_final_state_cannot_replace_actor_barrier(self):
        def row(peer):
            return {"peer": Q.COMMON.peer(peer), "session": "fixture-session",
                    "pending_batches": 0, "window_open": False, "window_messages": 0,
                    "window_routes": 0, "pending_withdrawals": 0}
        rows = [row(peer) for peer in range(3)]
        self.assertFalse(R.input_applied(rows[:2], 3, 1))
        self.assertTrue(R.input_applied(rows, 3, 1))
        # The final key bitmap can wrap to its old value, but missing source
        # markers still leave the next input generation unapplied.
        self.assertFalse(R.input_applied(rows, 3, 2))
        rows[2]["pending_batches"] = 1
        with self.assertRaisesRegex(Q.AcceptanceFailure, "before route work"):
            R.input_applied(rows, 3, 1)

    def test_window_edges_are_last_start_bounds(self):
        manifest = {"timing_window": Q.timing_window("2030-01-02T03:30:00Z", "2030-01-02T07:30:00Z")}
        for value in ("2030-01-02T03:29:59+00:00", "2030-01-02T07:30:00+00:00"):
            with self.assertRaisesRegex(ValueError, "outside"):
                Q.require_timing_window(manifest, datetime.fromisoformat(value))
        for value in ("2030-01-02T03:30:00+00:00", "2030-01-02T07:29:59+00:00"):
            Q.require_timing_window(manifest, datetime.fromisoformat(value))
        with self.assertRaisesRegex(ValueError, "explicitly authorized"):
            Q.require_timing_window({})

    def test_quiet_failure_or_preparation_crossing_end_prevents_child_launch(self):
        inside = datetime(2030, 1, 2, 7, 29, tzinfo=timezone.utc)
        outside = datetime(2030, 1, 2, 7, 30, tzinfo=timezone.utc)
        for quiet_status in (0, 1):
            with self.subTest(quiet_status=quiet_status), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                identities = {"rustbgpd-candidate": "candidate", "evpn-rr-soak": "driver"}
                Q.write_json(root / "binaries.json", identities)
                manifest = {"recovery": Q.RECOVERY_BARS, "daemon_cpus": "0", "harness_cpus": "1",
                            "timing_window": Q.timing_window("2030-01-02T03:30:00Z", "2030-01-02T07:30:00Z")}
                with patch.object(Q, "datetime", wraps=datetime) as clock, \
                     patch.object(R, "scenario", side_effect=lambda fixture, *_: (fixture / "config.toml").write_text("fixture")), \
                     patch.object(Q, "digest", side_effect=lambda path, identities=identities: identities[path.name]), \
                     patch.object(R.subprocess, "run", return_value=Mock(returncode=quiet_status)), \
                     patch.object(R.subprocess, "Popen") as launch:
                    clock.now.side_effect = [inside, inside, outside]
                    with self.assertRaisesRegex(ValueError, "outside|quiet-host"):
                        R.run_cell(root, manifest, "candidate", 0, False)
                    launch.assert_not_called()
                result = json.loads((root / "recovery-00-candidate/result.json").read_text())
                self.assertEqual(result["status"], "INVALID")

    def analysis_fixture(self, root):
        (root / "source.tar").write_bytes(b"fixed source fixture")
        Q.write_json(root / "campaign.json", {"schema": "rustbgpd.evpn-memory.v1", "head": "a" * 40,
            "source_sha256": Q.digest(root / "source.tar"), "shapes": Q.SHAPES, "schedule": Q.SCHEDULE,
            "settle_seconds": 45, "daemon_bytes": Q.DAEMON_BYTES,
            "max_slope_bytes_per_delivery": Q.MAX_SLOPE_BYTES, "recovery": Q.RECOVERY_BARS})
        wire_report = {phase: [{"peer": peer, "state": phase, "ordered": phase if phase in R.PHASES[:3] else None}
                               for peer in range(3)] for phase in R.PHASES}
        for index, arm in enumerate(("candidate", "private")):
            leg = root / f"recovery-{index:02}-{arm}"
            leg.mkdir()
            row = {"status": "PASS", "arm": arm, "clients": 3, "routes": 10_000,
                   "correctness_only": True, "wire": wire_report, "driver_exit": 0,
                   "executed_resets": dict.fromkeys(Q.CAUSES, 0)}
            snapshots = []
            names = ("initial_groups", "baseline", "regroup-b", "regroup-a", "mass_dirty_previous", "mass_dirty",
                     "protocol_obligation_before_churn", "protocol_obligation_during_churn", "protocol_obligation_after_churn", "settled")
            for sequence, name in enumerate(names):
                observation = witness(arm, 3, 10_000)
                if arm == "candidate":
                    observation["owned_groups"] = 2
                    observation["owned_routes"] = 60_000
                    for peer, data in enumerate(observation["peers"]):
                        data[1] = 2 if peer == 1 or (peer >= 2 and name == "regroup-b") else 1
                observation.update(elapsed_us=sequence * 100, wall_us=sequence * 100)
                if name.startswith("mass_dirty"):
                    observation["dirty"] = 3
                    for data in observation["peers"]: data[2] = True
                if name.startswith("protocol_obligation"):
                    observation["refresh_pending"] = observation["protocol_obligations"] = 3
                    for data in observation["peers"]: data[8] = True
                row[name] = observation
                snapshots.append(observation)
            row["protocol_obligation_before_churn"]["wall_us"] = 1000
            row["protocol_obligation_during_churn"]["wall_us"] = 3000
            row["protocol_obligation_after_churn"]["wall_us"] = 6000
            barriers = [{"peer": Q.COMMON.peer(peer), "session": "same-session", "wall_us": generation * 100,
                         "pending_batches": 0, "window_open": False, "window_messages": 0,
                         "window_routes": 0, "pending_withdrawals": 0}
                        for generation in range(1, 4) for peer in range(3)]
            (leg / "observer.log").write_text("".join("evpn_qualification " + json.dumps(item) + "\n" for item in snapshots)
                + "".join("evpn_input_barrier " + json.dumps(item) + "\n" for item in barriers))
            (leg / "daemon.log").write_text('evpn_input_barrier {interleaved stdout fragment}\n')
            events = [{"event": "reload", "generation": "a", "at": 1},
                      {"event": "complete", "command": "policy a", "at": 3},
                      {"event": "reload", "generation": "b", "at": 4},
                      {"event": "complete", "command": "policy b", "at": 6},
                      *[{"event": "complete", "command": "churn", "at": 7 + n} for n in range(32)],
                      {"event": "command", "command": "churn-overlap", "at": 40, "wall_us": 2000},
                      {"event": "complete", "command": "churn-overlap", "at": 41, "wall_us": 4000},
                      *[{"event": "input-applied", "generation": n, "receipts": n * 3,
                         "at": n * 15, "wall_us": 5000 if n == 3 else n * 100} for n in range(1, 4)],
                      {"event": "command", "command": "resume", "at": 51},
                      {"event": "complete", "command": "resume", "at": 52},
                      {"event": "complete", "command": "settle", "at": 56}]
            (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
            (leg / "driver.log").write_text('evpn_control ' + json.dumps({"command": "churn-overlap",
                "result": {"write_started_us": 2100, "writers_drained_us": 3900}}) + "\n")
            (leg / "readiness.jsonl").write_text(json.dumps({"status": 200, "at": 1., "scheduled": 1., "seconds": None}) + "\n")
            (leg / "metrics.txt").write_text(metrics_text())
            row.update({key: None for key in R.timings(events)})
            row["cgroup"] = {"memory.current": 1000, "memory.peak": 2000, "memory.max": Q.DAEMON_BYTES,
                             "memory.swap.max": 0, "memory.swap.current": 0, "memory.swap.peak": 0}
            Q.write_json(leg / "cgroup.json", row["cgroup"])
            Q.write_json(leg / "result.json", row)
        return wire_report

    def test_analyze_consumes_raw_receipts_and_rejects_hidden_middle_peak(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self.analysis_fixture(root)
            # Wire grammar has independent byte fixtures. Here the real
            # aggregate consumer must reach and emit its final verdict.
            with patch.object(R, "check_wire", return_value=report):
                R.analyze(root)
                self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], "PASS")
                self.assertIs(json.loads((root / "recovery-summary.json").read_text())["terminal_only_qualified"], False)
                path = root / "recovery-00-candidate/observer.log"
                bad = witness("candidate", 3, 10_000)
                bad["peak"] = Q.DAEMON_BYTES
                path.write_text(path.read_text() + "evpn_qualification " + json.dumps(bad) + "\n")
                with self.assertRaisesRegex(Q.AcceptanceFailure, "headroom"):
                    R.analyze(root)
                self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], "FAIL")

    def test_analyze_rejects_reused_marker_and_wrong_shape(self):
        for defect in ("reused-marker", "shape", "post-writes-sample"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report = self.analysis_fixture(root)
                leg = root / "recovery-00-candidate"
                row = json.loads((leg / "result.json").read_text())
                if defect == "shape":
                    row["routes"] = 1000  # Former smoke shape never filled the real writer queue.
                elif defect == "reused-marker":
                    row["protocol_obligation_after_churn"] = row["protocol_obligation_during_churn"]
                else:
                    # Between actual driver completion and Python's delayed
                    # acknowledgement: not an observation during writes.
                    row["protocol_obligation_during_churn"]["wall_us"] = 3950
                    text = (leg / "observer.log").read_text().replace('"wall_us": 3000', '"wall_us": 3950')
                    (leg / "observer.log").write_text(text)
                Q.write_json(leg / "result.json", row)
                with patch.object(R, "check_wire", return_value=report), self.assertRaises(ValueError):
                    R.analyze(root)

    def wire_fixture(self, root, recovery_eor):
        from test_wire import announce, withdraw, EOR
        captures, counts, controls = [bytearray() for _ in range(3)], [0] * 3, []
        controls.append({"command": "connected", "clients": 3})

        def inventory(peer, community, shifted=False):
            return b"".join(announce(kind, origin, index, community)
                            for origin in range(3) if origin != peer
                            for kind, width in ((2, 8), (5, 2))
                            for index in range(width if shifted else 0, 2 * width if shifted else width))

        def boundary(name, command=None, shifted=False):
            controls.append({"command": command or f"mark {name}", "result": {
                "boundary": name, "offsets": [len(data) for data in captures],
                "shifts": [33 if shifted else 0] * 3, "eors": counts.copy()}})

        for peer in range(3): captures[peer] += inventory(peer, 2000 if peer == 1 else 1000)
        boundary("loaded", "load")
        captures[2] += inventory(2, 2000)
        boundary("regroup-b", "policy b")
        captures[2] += inventory(2, 1000)
        boundary("regroup-a", "policy a")
        boundary("refresh-start")
        controls.append({"command": "refresh", "result": {"eor_baseline": counts.copy()}})
        for peer in range(3):
            captures[peer] += inventory(peer, 2000 if peer == 1 else 1000) + EOR
            counts[peer] += 1
        boundary("refresh", "refresh-settle")
        controls.append({"command": "refresh", "result": {"eor_baseline": counts.copy()}})
        for peer in range(3):
            captures[peer] += inventory(peer, 2000 if peer == 1 else 1000, shifted=True)
            captures[peer] += b"".join(withdraw(kind, origin, index)
                                      for origin in range(3) if origin != peer
                                      for kind, width in ((2, 8), (5, 2)) for index in range(width))
            if recovery_eor:
                captures[peer] += EOR
                counts[peer] += 1
        boundary("recovered", shifted=True)
        boundary("finished", "finish", shifted=True)
        (root / "wire").mkdir()
        for peer, data in enumerate(captures): (root / "wire" / f"peer-{peer}.bgp").write_bytes(data)
        (root / "driver.log").write_text("".join("evpn_control " + json.dumps(row) + "\n" for row in controls))

    def test_exact_recovered_keys_without_received_eor_cannot_pass(self):
        for received in (True, False):
            with self.subTest(received=received), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.wire_fixture(root, received)
                if received:
                    report = R.check_wire(root, 3, 10)
                    self.assertEqual(len(report["recovered"]), 3)
                else:
                    with self.assertRaisesRegex(Q.AcceptanceFailure, "before receiver refresh EoR"):
                        R.check_wire(root, 3, 10)


if __name__ == "__main__":
    unittest.main()
