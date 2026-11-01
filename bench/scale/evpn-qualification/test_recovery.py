#!/usr/bin/env python3
import copy
import io
from datetime import datetime, timezone
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import qualify as Q
import recovery as R
from test_qualify import witness, metrics_text, set_provenance_peak


def two_groups(generation="a"):
    row = witness("candidate", 4, 10)
    row.update(owned_groups=2, owned_routes=80, elapsed_us=50_000, sample_slot=1)
    for index, peer in enumerate(row["peers"]):
        peer[1] = 2 if index == 1 or (index >= 2 and generation == "b") else 1
    return row


def last_reload(started, finished, outcome="complete"):
    return {"record": {"started_unix_millis": started, "finished_unix_millis": finished,
                       "outcome": outcome, "route": "generation", "reason_code": None,
                       "failure_bucket": None, "failure_target": None, "applied_count": 2,
                       "applied": [], "applied_omitted": 0, "unapplied_count": 0,
                       "unapplied": [], "unapplied_omitted": 0}, "convergence": None}


def reload_controls(leg, row, events):
    controls = []
    previous = {"record": None, "convergence": None}
    for generation, start in (("b", 1), ("a", 4)):
        response = last_reload(start * 1000, start * 1000 + 100)
        for step, requested, completed, body in (("before", start - .5, start - .4, previous),
                                                  ("after", start + .01, start + .2, response)):
            controls.append({"generation": generation, "step": step, "pid": row["daemon_owner"]["pid"],
                             "requested_at": requested, "at": completed, "wall_us": int(completed * 1_000_000),
                             "timeout_seconds": 30, "returncode": 0, "stdout": json.dumps(body), "stderr": ""})
        events.extend([{"event": "reload_signal", "generation": generation, "at": start + .001,
                        "pid": row["daemon_owner"]["pid"], "signal_floor_ms": start * 1000},
                       {"event": "reload_settled", "generation": generation, "at": start + .21}])
        row[f"reload-{generation}"] = response
        previous = response
    (leg / "reload-control.jsonl").write_text("".join(json.dumps(item) + "\n" for item in controls))


def write_readiness(leg, times, **fields):
    (leg / "readiness.jsonl").write_text("".join(json.dumps({"status": 200, "http_error_code": None, "at": at,
                                                             "scheduled": at, "seconds": None, **fields}) + "\n"
                                                 for at in times))


class RecoveryTests(unittest.TestCase):
    def test_build_pins_same_source_cli_without_using_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def build(command, **kwargs):
                binary = command[command.index("--bin") + 1]
                target = Path(kwargs["env"]["CARGO_TARGET_DIR"])
                (target / "release").mkdir(parents=True, exist_ok=True)
                (target / "release" / binary).write_text(binary + str(target))
                return Mock(returncode=0)
            with patch.object(Q, "manifest_for"), patch.object(Q, "verify_export"), \
                 patch.object(Q.subprocess, "check_output", return_value="fixture version"), \
                 patch.object(Q.subprocess, "run", side_effect=build) as runs:
                Q.build(Mock(output=str(root)))
            identities = json.loads((root / "binaries.json").read_text())
            self.assertEqual(set(identities), {"rustbgpd-candidate", "rustbgpd-private", "evpn-rr-soak", "rbgp"})
            self.assertEqual(identities["rbgp"], Q.digest(root / "bin/rbgp"))
            cli = runs.call_args_list[-1]
            self.assertIn("rustbgpctl", cli.args[0])
            self.assertEqual(cli.kwargs["cwd"], root / "sources/candidate")
            self.assertEqual(cli.kwargs["env"]["CARGO_TARGET_DIR"], str(root / "target-candidate"))

    def test_reload_record_requires_new_correlated_settlement_not_convergence(self):
        old = last_reload(999, 1000)
        changed_convergence = copy.deepcopy(old)
        changed_convergence["convergence"] = {"state": "converged"}
        self.assertFalse(R.reload_complete(changed_convergence, old["record"], 1000, 1_100_000))
        self.assertFalse(R.reload_complete(last_reload(999, 1001), old["record"], 1000, 1_100_000))
        # Millisecond equality is valid; the signal may arrive later within the same millisecond.
        self.assertTrue(R.reload_complete(last_reload(1000, 1000), old["record"], 1000, 1_100_000))
        for outcome in ("ignored_in_flight", "known_partial", "rejected_no_effect", "task_failed"):
            with self.subTest(outcome=outcome), self.assertRaises(Q.AcceptanceFailure):
                R.reload_complete(last_reload(1000, 1001, outcome), old["record"], 1000, 1_100_000)
        for response in ({}, last_reload(True, 1000), last_reload(1001, 1000), last_reload(1000, 2000)):
            with self.subTest(response=response), self.assertRaises(ValueError) as caught:
                R.reload_complete(response, old["record"], 1000, 1_100_000)
            self.assertNotIsInstance(caught.exception, Q.AcceptanceFailure)

    def test_controller_waits_for_owner_before_next_signal_with_one_deadline(self):
        with tempfile.TemporaryDirectory() as temporary:
            controller = R.Controller.__new__(R.Controller)
            controller.leg = Path(temporary)
            controller.daemon = Mock(pid=123)
            state = {"clock": 1., "record": None, "active": False, "polls": 0}
            signaled_while_active = []
            def kill(pid, sig):
                self.assertEqual((pid, sig), (123, R.signal.SIGHUP))
                signaled_while_active.append(state["active"])
                state.update(active=True, polls=0, started=int(state["clock"] * 1000))
            def poll():
                state["clock"] += .01
                state["polls"] += 1
                if state["active"] and state["polls"] == 2:
                    state["record"] = last_reload(state["started"], int(state["clock"] * 1000))["record"]
                    state["active"] = False
            def rpc(command, **kwargs):
                self.assertEqual(command[:3], ["/frozen/bin/rbgp", "--addr", "unix:///fixture/grpc.sock"])
                self.assertLessEqual(kwargs["timeout"], 30)
                return Mock(returncode=0, stdout=json.dumps({"record": state["record"], "convergence": None}), stderr="")
            controller.poll = Mock(side_effect=poll)
            responses = []
            with patch.object(R.time, "monotonic", side_effect=lambda: state["clock"]), \
                 patch.object(R.time, "time_ns", side_effect=lambda: int(state["clock"] * 1_000_000_000)), \
                 patch.object(R.os, "kill", side_effect=kill), \
                 patch.object(R.subprocess, "run", side_effect=rpc):
                for generation in ("b", "a"):
                    started, deadline, response = controller.reload(generation, Path("/frozen/bin/rbgp"),
                                                                    "unix:///fixture/grpc.sock", 60)
                    self.assertEqual(deadline, started + 60)
                    responses.append(response)
            self.assertEqual(signaled_while_active, [False, False])
            self.assertEqual([response["record"]["outcome"] for response in responses], ["complete", "complete"])
            controls = [json.loads(line) for line in (controller.leg / "reload-control.jsonl").read_text().splitlines()]
            self.assertEqual([item["step"] for item in controls], ["before", "after", "after"] * 2)
            self.assertIsNone(json.loads(controls[1]["stdout"])["record"])

    def test_remaining_deadline_bounds_rpc_group_and_wire_waits(self):
        with tempfile.TemporaryDirectory() as temporary:
            controller = R.Controller.__new__(R.Controller)
            controller.leg, controller.daemon = Path(temporary), Mock(pid=123)
            with patch.object(R.time, "monotonic", return_value=59.75), \
                 patch.object(R.subprocess, "run", return_value=Mock(returncode=0, stdout='{"record":null}', stderr="")) as rpc:
                controller.reload_status("b", "after", Path("/frozen/rbgp"), "unix:///fixture/grpc.sock", 60)
            self.assertEqual(rpc.call_args.kwargs["timeout"], .25)
            with patch.object(R.time, "monotonic", return_value=60), \
                 patch.object(R.subprocess, "run") as rpc, self.assertRaises(Q.AcceptanceFailure):
                controller.reload_status("b", "after", Path("/frozen/rbgp"), "unix:///fixture/grpc.sock", 60)
            rpc.assert_not_called()
            controller.observations, controller.messages = [], []
            controller.poll = Mock()
            with patch.object(R.time, "monotonic", return_value=60):
                with self.assertRaises(R.MissingWitness):
                    controller.witness(lambda row: True, deadline=60)
                with self.assertRaises(Q.AcceptanceFailure):
                    controller.ack("policy b", deadline=60)
            controller.poll.assert_not_called()

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
        second["sample_slot"] += 1
        self.assertEqual(R.dirty_pair([first, second], 4), (first, second))
        middle = copy.deepcopy(first)
        middle["dirty"] = 3
        self.assertIsNone(R.dirty_pair([first, middle, second], 4))

    def test_dirty_pair_requires_adjacent_slots_and_actual_twenty_hz_gap(self):
        first = two_groups()
        first["dirty"] = 4
        for gap in (1_000_000, 50_001):
            with self.subTest(gap=gap):
                second = copy.deepcopy(first)
                second["elapsed_us"] += gap
                second["sample_slot"] = second["elapsed_us"] // 50_000
                self.assertIsNone(R.dirty_pair([first, second], 4))
        second = copy.deepcopy(first)
        second.update(elapsed_us=100_000, sample_slot=2)
        self.assertEqual(R.dirty_pair([first, second], 4), (first, second))
        for elapsed, slot in ((50_001, 1), (150_000, 3), (100_000, 3)):
            with self.subTest(elapsed=elapsed, slot=slot):
                second = copy.deepcopy(first)
                second.update(elapsed_us=elapsed, sample_slot=slot)
                self.assertIsNone(R.dirty_pair([first, second], 4))

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
                identities = {"rustbgpd-candidate": "candidate", "evpn-rr-soak": "driver", "rbgp": "client"}
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
        (root / "bin").mkdir()
        (root / "bin/rbgp").write_text("same-source client fixture")
        client_hash = Q.digest(root / "bin/rbgp")
        Q.write_json(root / "binaries.json", {"rbgp": client_hash})
        wire_report = {phase: [{"peer": peer, "state": phase, "ordered": phase if phase in R.PHASES[:3] else None}
                               for peer in range(3)] for phase in R.PHASES}
        for index, arm in enumerate(("candidate", "private")):
            leg = root / f"recovery-{index:02}-{arm}"
            leg.mkdir()
            row = {"status": "PASS", "arm": arm, "clients": 3, "routes": 10_000,
                   "correctness_only": True, "wire": wire_report, "driver_exit": 0,
                   "executed_resets": dict.fromkeys(Q.CAUSES, 0), "daemon_owner": {"pid": 1000 + index},
                   "reload_client_sha256": client_hash}
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
                observation.update(elapsed_us=sequence * 50_000, sample_slot=sequence, wall_us=sequence * 100)
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
            events = [{"event": "reload", "generation": "b", "at": 1, "wall_us": 1_000_000},
                      {"event": "complete", "command": "policy b", "at": 3},
                      {"event": "reload", "generation": "a", "at": 4, "wall_us": 4_000_000},
                      {"event": "complete", "command": "policy a", "at": 6},
                      *[{"event": "complete", "command": "churn", "at": 7 + n} for n in range(32)],
                      {"event": "command", "command": "churn-overlap", "at": 40, "wall_us": 2000},
                      {"event": "complete", "command": "churn-overlap", "at": 41, "wall_us": 4000},
                      *[{"event": "input-applied", "generation": n, "receipts": n * 3,
                         "at": n * 15, "wall_us": 5000 if n == 3 else n * 100} for n in range(1, 4)],
                      {"event": "command", "command": "resume", "at": 51},
                      {"event": "complete", "command": "resume", "at": 52},
                      {"event": "complete", "command": "settle", "at": 56}]
            reload_controls(leg, row, events)
            events.sort(key=lambda event: event["at"])
            (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
            (leg / "driver.log").write_text('evpn_control ' + json.dumps({"command": "churn-overlap",
                "result": {"write_started_us": 2100, "writers_drained_us": 3900}}) + "\n")
            # One 20 Hz probe series covering the first through last workload event.
            write_readiness(leg, [1 + n * .05 for n in range(round((56 - 1) / .05) + 1)])
            (leg / "metrics.txt").write_text(metrics_text())
            row.update({key: None for key in R.timings(events)})
            row["cgroup"] = {"memory.current": 1000, "memory.peak": 2000, "memory.max": Q.DAEMON_BYTES,
                             "memory.swap.max": 0, "memory.swap.current": 0, "memory.swap.peak": 0}
            Q.write_json(leg / "cgroup.json", row["cgroup"])
            Q.write_json(leg / "result.json", row)
        return wire_report

    def test_analyzer_rechecks_raw_reload_owner_receipts_in_both_arms(self):
        defects = ("stale", "ignored_in_flight", "known_partial", "task_failed", "prepublished",
                   "late", "pid", "copied", "client", "missing", "future-finish", "unapplied")
        for arm in ("candidate", "private"):
            for defect in defects:
                with self.subTest(arm=arm, defect=defect), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    report = self.analysis_fixture(root)
                    leg = next(root.glob(f"recovery-*-{arm}"))
                    row = json.loads((leg / "result.json").read_text())
                    controls = [json.loads(line) for line in (leg / "reload-control.jsonl").read_text().splitlines()]
                    response = json.loads(controls[-1]["stdout"])
                    if defect == "stale":
                        response = json.loads(controls[-2]["stdout"])
                    elif defect in ("ignored_in_flight", "known_partial", "task_failed"):
                        response["record"]["outcome"] = defect
                    elif defect == "future-finish":
                        response["record"]["finished_unix_millis"] = 10_000
                    elif defect == "unapplied":
                        response["record"]["unapplied_count"] = 1
                    elif defect == "prepublished":
                        controls[-1].update(requested_at=3.8, at=3.9)
                    elif defect == "late":
                        controls[-1].update(requested_at=63.9, at=64.01, timeout_seconds=.1)
                    elif defect == "pid":
                        controls[-1]["pid"] += 1
                    elif defect == "client":
                        row["reload_client_sha256"] = "0" * 64
                    controls[-1]["stdout"] = json.dumps(response)
                    row["reload-a"] = response
                    Q.write_json(leg / "result.json", row)
                    path = leg / "reload-control.jsonl"
                    path.write_text("".join(json.dumps(item) + "\n" for item in controls))
                    if defect == "missing":
                        path.unlink()
                    elif defect == "copied":
                        other = next(path for path in root.glob("recovery-*") if path != leg)
                        path.write_bytes((other / "reload-control.jsonl").read_bytes())
                    with patch.object(R, "check_wire", return_value=report), self.assertRaises(Exception) as caught:
                        R.analyze(root)
                    expected = "FAIL" if defect in ("ignored_in_flight", "known_partial", "task_failed") else "INVALID"
                    self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], expected)
                    self.assertEqual(isinstance(caught.exception, Q.AcceptanceFailure), expected == "FAIL")

    def test_analyze_rejects_dirty_cadence_misses_in_either_arm(self):
        for arm in ("candidate", "private"):
            for gap in (1_000_000, 50_001, 100_000, 1):
                with self.subTest(arm=arm, gap=gap), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    report = self.analysis_fixture(root)
                    leg = next(root.glob(f"recovery-*-{arm}"))
                    row = json.loads((leg / "result.json").read_text())
                    snapshots = [json.loads(line.removeprefix("evpn_qualification "))
                                 for line in (leg / "observer.log").read_text().splitlines()
                                 if line.startswith("evpn_qualification ")]
                    start = snapshots.index(row["mass_dirty"])
                    shift = gap - 50_000
                    for snapshot in snapshots[start:]:
                        snapshot["elapsed_us"] += shift
                        snapshot["sample_slot"] = snapshot["elapsed_us"] // 50_000
                    row["mass_dirty"] = snapshots[start]
                    # Other retained receipts refer to these same raw rows.
                    for name in ("protocol_obligation_before_churn", "protocol_obligation_during_churn",
                                 "protocol_obligation_after_churn", "settled"):
                        match = next(snapshot for snapshot in snapshots if snapshot["wall_us"] == row[name]["wall_us"])
                        row[name] = match
                    barriers = [line for line in (leg / "observer.log").read_text().splitlines()
                                if line.startswith("evpn_input_barrier ")]
                    (leg / "observer.log").write_text(
                        "".join("evpn_qualification " + json.dumps(snapshot) + "\n" for snapshot in snapshots)
                        + "".join(line + "\n" for line in barriers))
                    Q.write_json(leg / "result.json", row)
                    with patch.object(R, "check_wire", return_value=report), \
                         self.assertRaises(Q.AcceptanceFailure):
                        R.analyze(root)

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
                # Valid evidence over the 80% bar; a peak above the budget is INVALID instead.
                bad.update(owned_groups=2, peak=int(bad["daemon_budget"] * .9))
                path.write_text(path.read_text() + "evpn_qualification " + json.dumps(bad) + "\n")
                with self.assertRaisesRegex(Q.AcceptanceFailure, "headroom"):
                    R.analyze(root)
                self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], "FAIL")

    def test_roster_validates_types_ranges_and_source_before_bars(self):
        def private_owned(row):
            row["peers"][0][1] = 1
        def candidate_private_routes(row):
            row["private_routes"] = 1
        cases = {"bool-peer-charge": ("candidate", lambda row: row["peers"][0].__setitem__(3, True)),
                 "bool-daemon-charge": ("candidate", lambda row: row.update(retained=True)),
                 "bool-count": ("candidate", lambda row: row.update(completion_receipts=False)),
                 "negative-peer-charge": ("candidate", lambda row: row["peers"][0].__setitem__(3, -1)),
                 "negative-daemon-charge": ("candidate", lambda row: row.update(retained=-1)),
                 "non-numeric-charge": ("candidate", lambda row: row["peers"][0].__setitem__(4, "128")),
                 "wrong-source-private": ("private", private_owned),
                 "wrong-source-candidate": ("candidate", candidate_private_routes)}
        for name, (arm, defect) in cases.items():
            for over_bar in (False, True):
                with self.subTest(defect=name, over_bar=over_bar):
                    row = two_groups() if arm == "candidate" else witness("private", 4, 10)
                    defect(row)
                    if over_bar:
                        # Invalid evidence plus a valid-looking bar miss stays INVALID.
                        row["peak"] = int(row["daemon_budget"] * .9)
                    with self.assertRaises(ValueError) as caught:
                        R.roster(row, arm, 4)
                    self.assertNotIsInstance(caught.exception, Q.AcceptanceFailure)

    def test_partial_roster_rows_are_checked_against_the_bar(self):
        for arm in ("candidate", "private"):
            for target in ("daemon", "peer"):
                for fraction, failed in ((.8, False), (.9, True)):
                    with self.subTest(arm=arm, target=target, fraction=fraction):
                        row = witness(arm, 1, 10)
                        set_provenance_peak(row, target, int(row[f"{target}_budget"] * fraction))
                        if failed:
                            with self.assertRaisesRegex(Q.AcceptanceFailure, "headroom"):
                                R.roster(row, arm, 4)
                        else:
                            R.roster(row, arm, 4)

    def test_online_poll_checks_partial_rows_and_classifies_invalid_first(self):
        for arm in ("candidate", "private"):
            for defect, expected in (("partial-over-bar", Q.AcceptanceFailure), ("partial-under-bar", None),
                                     ("wrong-source-over-bar", ValueError)):
                with self.subTest(arm=arm, defect=defect):
                    row = witness(arm, 1, 10)
                    if defect == "partial-under-bar":
                        set_provenance_peak(row, "peer", int(row["peer_budget"] * .8))
                    else:
                        set_provenance_peak(row, "peer", int(row["peer_budget"] * .9))
                    if defect == "wrong-source-over-bar":
                        row["peers"][0][1] = None if arm == "candidate" else 1
                    controller = R.Controller.__new__(R.Controller)
                    controller.arm, controller.clients, controller.last_sample = arm, 4, 0
                    controller.daemon, controller.driver = Mock(poll=Mock(return_value=None)), Mock(poll=Mock(return_value=None))
                    controller.probes = Mock()
                    controller.selector = Mock(select=Mock(return_value=[]))
                    controller.messages, controller.observations, controller.input_barriers = [], [], []
                    controller.observer_log = io.StringIO("evpn_qualification " + json.dumps(row) + "\n")
                    controller.observer_buffer = ""
                    if expected is None:
                        controller.poll()
                        self.assertEqual(controller.observations, [row])
                        continue
                    with self.assertRaises(expected) as caught:
                        controller.poll()
                    if expected is ValueError:
                        self.assertNotIsInstance(caught.exception, Q.AcceptanceFailure)

    def test_analyze_checks_partial_rows_and_invalid_source_before_bars(self):
        for arm in ("candidate", "private"):
            for defect, expected in (("partial-under-bar", "PASS"), ("partial-over-bar", "FAIL"),
                                     ("wrong-source-over-bar", "INVALID")):
                with self.subTest(arm=arm, defect=defect), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    report = self.analysis_fixture(root)
                    path = next(root.glob(f"recovery-*-{arm}")) / "observer.log"
                    if defect == "wrong-source-over-bar":
                        row = witness(arm, 3, 10_000)
                        row["owned_groups"] = 2 if arm == "candidate" else 0
                        row["peers"][0][1] = None if arm == "candidate" else 1
                    else:
                        # Registration rows precede the full roster.
                        row = witness(arm, 1, 10_000)
                    fraction = .8 if defect == "partial-under-bar" else .9
                    set_provenance_peak(row, "peer", int(row["peer_budget"] * fraction))
                    path.write_text("evpn_qualification " + json.dumps(row) + "\n" + path.read_text())
                    with patch.object(R, "check_wire", return_value=report):
                        if expected == "PASS":
                            R.analyze(root)
                        else:
                            with self.assertRaises(ValueError) as caught:
                                R.analyze(root)
                            self.assertEqual(isinstance(caught.exception, Q.AcceptanceFailure), expected == "FAIL")
                    self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], expected)

    def test_readiness_must_cover_the_recorded_workload(self):
        full = [1 + n * .05 for n in range(1101)]
        cases = {"one-sample": ([1.], "INVALID"),  # The former positive fixture shape.
                 "common-shift-later": ([at + .5 for at in full], "INVALID"),
                 "common-shift-earlier": ([at - .5 for at in full], "INVALID"),
                 "truncated-start": (full[2:], "INVALID"),
                 "truncated-end": (full[:-2], "INVALID"),
                 "truncated-with-503": (full[:-2], "INVALID"),
                 "one-cadence-edges": (full[1:-1], "PASS"),
                 "covered-503": (full, "FAIL")}
        for arm in ("candidate", "private"):
            for name, (times, expected) in cases.items():
                with self.subTest(arm=arm, defect=name), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    report = self.analysis_fixture(root)
                    leg = next(root.glob(f"recovery-*-{arm}"))
                    write_readiness(leg, times, **({"status": 503, "http_error_code": 503} if "503" in name else {}))
                    with patch.object(R, "check_wire", return_value=report):
                        if expected == "PASS":
                            R.analyze(root)
                        else:
                            with self.assertRaises(ValueError) as caught:
                                R.analyze(root)
                            self.assertEqual(isinstance(caught.exception, Q.AcceptanceFailure), expected == "FAIL")
                    self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], expected)

    def test_sampler_issues_the_slot_due_before_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            sampler = R.Readiness.__new__(R.Readiness)
            sampler.path, sampler.correctness = Path(temporary) / "readiness.jsonl", True
            sampler.results, sampler.stop_event = R.queue.Queue(), R.threading.Event()
            sampler.thread = Mock(is_alive=Mock(return_value=False))
            clock = {"now": 0.}
            def sleep(_):
                # The stop request lands between two loop checks, after the next slot was due.
                clock["now"] = round(clock["now"] + .006, 6)
                if clock["now"] == .054:
                    sampler.stop()
            with patch.object(R.time, "monotonic", side_effect=lambda: clock["now"]), \
                 patch.object(R.time, "sleep", side_effect=sleep), \
                 patch.object(Q, "probe_readiness", return_value={"status": 200, "http_error_code": None}):
                sampler.run()
            scheduled = [json.loads(line)["scheduled"] for line in sampler.path.read_text().splitlines()]
            self.assertEqual(sorted(scheduled), [0., .05])
            self.assertGreaterEqual(max(scheduled), sampler.stop_at - .05)

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
