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
from test_qualify import held, witness, metrics_text, set_provenance_peak


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


def actor_text(maximum, buckets):
    """A scrape as the daemon renders it: unrelated stages and work units beside the two read series."""
    lines = ['# TYPE bgp_rib_actor_slice_max_microseconds gauge',
             'bgp_rib_actor_slice_max_microseconds{stage="selection"} 7000000',
             f'bgp_rib_actor_slice_max_microseconds{{stage="actor_poll"}} {maximum}',
             'bgp_rib_actor_work_duration_seconds_bucket{work_unit="distribute_flush",le="0.2"} 999',
             'bgp_rib_actor_work_duration_seconds_bucket{work_unit="distribute_flush",le="+Inf"} 999']
    lines += [f'bgp_rib_actor_work_duration_seconds_bucket{{work_unit="route_chunk",le="{edge}"}} {count}'
              for edge, count in buckets.items()]
    lines += [f'bgp_rib_actor_work_duration_seconds_count{{work_unit="route_chunk"}} {max(buckets.values())}']
    return "\n".join(lines) + "\n"


def transition_text(fallback):
    return "".join(f'bgp_rib_policy_transition_total{{outcome="{outcome}"}} {count}\n' for outcome, count in
                   (("committed", 0), ("fallback_handoff", fallback), ("fallback_cleanup_error", 0)))


def log_stamp(wall_us):
    return datetime.fromtimestamp(wall_us / 1_000_000, timezone.utc).isoformat().replace("+00:00", "Z")


def batch_event(wall_us, fallback_members=148):
    fields = {"message": "authoritative_batch_phase", "classification": "fallback", "input_peers": 148,
              "present_peers": 148, "shared_members": 0, "fallback_members": fallback_members,
              "fallback_regroup_us": 1_300_000, "distribution_us": 7_000_000, "total_us": 8_400_000}
    return json.dumps({"timestamp": log_stamp(wall_us), "level": "INFO", "fields": fields,
                       "target": "authoritative_batch_phase"})


def regroup_evidence(leg, events, controls):
    """Raw regroup-window evidence: the regroup witnesses are at wall 200 (b)
    and 300 (a); each window opens before its signal and closes after them."""
    log = []
    for generation, base in (("b", 100), ("a", 200)):
        signal = next(event for event in events
                      if event["event"] == "reload_signal" and event["generation"] == generation)
        signal["wall_us"] = base + 50
        at = signal["at"]
        # The probe stops after the policy command completes (3 for b, 6 for a).
        converged = 3 if generation == "b" else 6
        events.extend([{"event": "scrape", "name": f"regroup-{generation}-start", "at": at,
                        "requested_at": at, "requested_us": base + 30, "wall_us": base + 40},
                       {"event": "command", "command": f"probe-stop {generation}", "at": converged + .05},
                       {"event": "complete", "command": f"probe-stop {generation}", "at": converged + .08},
                       {"event": "scrape", "name": f"regroup-{generation}-end", "at": converged + .1,
                        "requested_at": converged + .09, "requested_us": base + 110, "wall_us": base + 120}])
        (leg / f"metrics-regroup-{generation}-start.txt").write_text(
            actor_text(5, {"0.2": 1, "+Inf": 1}) + transition_text(0))
        (leg / f"metrics-regroup-{generation}-end.txt").write_text(
            actor_text(8_300_000, {"0.2": 1, "+Inf": 2}) + transition_text(1))
        controls.append({"command": f"probe-stop {generation}", "result": {"samples": [
            {"sent_us": base + 10, "seen_us": base + 20, "withdrawn": True, "every_receiver": None},
            {"sent_us": base + 60, "seen_us": base + 105, "withdrawn": True, "every_receiver": True}]}})
        log.extend([batch_event(base + 70), batch_event(base + 130, 1)])
    with (leg / "daemon.log").open("a") as stream:
        stream.write("".join(line + "\n" for line in log))


class RecoveryTests(unittest.TestCase):
    def test_mass_dirty_actor_reads_the_closing_window_and_the_phase_bucket_delta(self):
        start = actor_text(900_000, {"0.2": 5, "0.5": 6, "+Inf": 6})
        end = actor_text(1_300_000, {"0.2": 40, "0.5": 43, "+Inf": 44})
        # The opening scrape's maximum belongs to earlier phases; other
        # stages and work units never leak into the receipt.
        self.assertEqual(R.mass_dirty_actor(start, end), {
            "actor_poll_max_microseconds": 1_300_000,
            "route_chunk_buckets": {"0.2": 35, "0.5": 37, "+Inf": 38},
            "route_chunk_over_200ms": 3})

    def test_mass_dirty_actor_rejects_missing_duplicate_and_inconsistent_series(self):
        good = actor_text(10, {"0.2": 1, "+Inf": 2})
        maximum = 'bgp_rib_actor_slice_max_microseconds{stage="actor_poll"} 10\n'
        broken = {
            # A scrape of a build without the gauge, with every other stage present.
            "no maximum": good.replace(maximum, ""),
            "duplicate maximum": good + maximum,
            "fractional maximum": good.replace(maximum, maximum.replace(" 10", " 10.5")),
            "no 0.2 edge": actor_text(10, {"0.5": 1, "+Inf": 2}),
            "no +Inf": actor_text(10, {"0.2": 1, "0.5": 2}),
            "not cumulative": actor_text(10, {"0.2": 3, "+Inf": 2}),
            "duplicate bucket": good + 'bgp_rib_actor_work_duration_seconds_bucket{work_unit="route_chunk",le="0.2"} 1\n',
        }
        # Two cumulative scrapes whose difference is not: five chunks left
        # the slow bucket's complement, which no counter can do.
        with self.assertRaises(ValueError) as caught:
            R.mass_dirty_actor(actor_text(10, {"0.2": 5, "+Inf": 6}), actor_text(10, {"0.2": 10, "+Inf": 10}))
        self.assertIn("not cumulative", str(caught.exception))
        for name, text in broken.items():
            with self.subTest(name), self.assertRaises(ValueError):
                R.mass_dirty_actor(good, text)
        with self.assertRaises(ValueError):  # a restarted daemon's counters
            R.mass_dirty_actor(actor_text(10, {"0.2": 5, "+Inf": 5}), good)
        with self.assertRaises(ValueError):
            R.mass_dirty_actor(actor_text(10, {"0.2": 1, "0.5": 1, "+Inf": 2}), good)

    def test_mass_dirty_window_closes_only_after_every_source_applied_the_last_round(self):
        def barrier(peer, at):
            return {"peer": Q.COMMON.peer(peer), "wall_us": at}
        load = [barrier(peer, 100 + peer) for peer in range(3)]
        churn = [barrier(peer, 500 + peer * 10) for peer in range(3)]
        row = lambda at: {"wall_us": at}
        # Two of three sources applied: no snapshot can close the window yet.
        self.assertIsNone(R.churn_applied_at(load + churn[:2], 3))
        self.assertFalse(R.closes_mass_dirty(row(10_000), load + churn[:2], 3))
        # The boundary is the last source's second barrier, not the first
        # source's, not the load barriers, and not a later third one.
        self.assertEqual(R.churn_applied_at(load + churn, 3), 520)
        self.assertEqual(R.churn_applied_at(load + churn + [barrier(0, 900)], 3), 520)
        # Per source, the second barrier in arrival order is the churn one.
        self.assertEqual(R.churn_applied_at([load[0], churn[0], load[1], load[2], churn[2], churn[1]], 3), 520)
        for at, closes in ((499, False), (505, False), (520, False), (521, True), (6999, True)):
            self.assertEqual(R.closes_mass_dirty(row(at), load + churn, 3, 7000), closes, at)
        # A snapshot taken after the receivers resumed is outside the phase.
        self.assertFalse(R.closes_mass_dirty(row(7000), load + churn, 3, 7000))
        with self.assertRaises(ValueError):
            R.churn_applied_at(load + [barrier(9, 1)], 3)

    def test_analyze_rejects_a_mass_dirty_window_closed_before_the_last_round_applied(self):
        for defect in ("early", "after-resume", "not-observed", "missing"):
            with self.subTest(defect), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report = self.analysis_fixture(root)
                leg = root / "recovery-00-candidate"
                row = json.loads((leg / "result.json").read_text())
                if defect == "early":  # the second barriers are at 200
                    row["mass_dirty_close"] = row["regroup-b"]
                elif defect == "after-resume":  # resume is at 7000
                    late = dict(row["settled"], wall_us=7001)
                    row["mass_dirty_close"] = row["settled"] = late
                    with (leg / "observer.log").open("a") as log:
                        log.write("evpn_qualification " + json.dumps(late) + "\n")
                elif defect == "not-observed":
                    row["mass_dirty_close"] = dict(row["mass_dirty_close"], wall_us=951)
                else:
                    del row["mass_dirty_close"]
                Q.write_json(leg / "result.json", row)
                with patch.object(R, "check_wire", return_value=report), self.assertRaises(Exception) as caught:
                    R.analyze(root)
                self.assertNotIsInstance(caught.exception, Q.AcceptanceFailure)
                self.assertIn("mass-dirty scrape window", str(caught.exception))
                self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], "INVALID")

    def test_analyze_rechecks_the_mass_dirty_actor_receipt_against_both_raw_scrapes(self):
        for defect in ("copied-value", "missing-field", "missing-start", "corrupt-end"):
            with self.subTest(defect), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report = self.analysis_fixture(root)
                leg = root / "recovery-00-candidate"
                row = json.loads((leg / "result.json").read_text())
                if defect == "copied-value":
                    row["mass_dirty_actor"] = {"actor_poll_max_microseconds": 1}
                elif defect == "missing-field":
                    del row["mass_dirty_actor"]
                elif defect == "missing-start":
                    (leg / "metrics-mass-dirty-start.txt").unlink()
                else:
                    (leg / "metrics-mass-dirty-end.txt").write_text(metrics_text())
                Q.write_json(leg / "result.json", row)
                with patch.object(R, "check_wire", return_value=report), self.assertRaises(Exception) as caught:
                    R.analyze(root)
                self.assertNotIsInstance(caught.exception, Q.AcceptanceFailure)
                self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], "INVALID")

    def test_regroup_window_reads_actor_transitions_batches_and_probe_from_raw_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.analysis_fixture(root)
            leg = root / "recovery-00-candidate"
            row = json.loads((leg / "result.json").read_text())
            window = row["regroup-b-window"]
            self.assertEqual(window["actor"]["actor_poll_max_microseconds"], 8_300_000)
            self.assertEqual(window["actor"]["route_chunk_over_200ms"], 1)
            self.assertEqual(window["transitions"],
                             {"committed": 0, "fallback_cleanup_error": 0, "fallback_handoff": 1})
            # Only the events inside [signal, closing scrape] belong to this regroup.
            self.assertEqual([batch["wall_us"] for batch in window["batches"]], [170])
            self.assertEqual(window["batches"][0]["fallback_members"], 148)
            self.assertEqual(window["batches"][0]["distribution_us"], 7_000_000)
            self.assertEqual(window["probe"], {"status": "PASS", "reason": None, "samples": 2, "max_latency_us": 45})
            self.assertEqual([batch["wall_us"] for batch in row["regroup-a-window"]["batches"]], [270])

    def test_probe_that_never_arrives_or_misses_the_regroup_is_invalid_not_a_pass(self):
        def sample(sent, seen, withdrawn=True, every=None, quiet=None):
            row = {"sent_us": sent, "seen_us": seen, "withdrawn": withdrawn, "every_receiver": every}
            if quiet is not None:
                row["quiet"] = quiet
            return row
        good = [sample(10, 20), sample(60, 9_000_060), sample(9_000_100, 9_000_110, every=True)]
        self.assertEqual(R.probe_window({"samples": good}, 50, 9_000_000),
                         {"status": "PASS", "reason": None, "samples": 3, "max_latency_us": 9_000_000})
        for name, samples, reason in (
                ("never-arrives", [sample(10, 20), sample(60, None)], "never reached"),
                ("left-behind", [sample(10, 20), sample(60, 9_000_060, False)], "not withdrawn"),
                ("started-late", [sample(60, 9_000_060, every=True)], "does not span"),
                ("stopped-early", [sample(10, 20), sample(30, 40, every=True)], "does not span"),
                ("final-missed-a-receiver", [sample(10, 20), sample(60, 9_000_060, every=False)],
                 "every receiver"),
                ("final-unchecked", [sample(10, 20), sample(60, 9_000_060)], "every receiver"),
                ("never-quiet", [sample(10, 20), sample(9_000_100, None, False, False, quiet=False)],
                 "did not quiesce"),
                ("empty", [], "no probe sample")):
            with self.subTest(name):
                result = R.probe_window({"samples": samples}, 50, 9_000_000)
                self.assertEqual(result["status"], "INVALID")
                self.assertIsNone(result["max_latency_us"])
                self.assertIn(reason, result["reason"])
        for malformed in (None, {}, {"samples": [sample(20, 10)]}, {"samples": [sample(10, 20), sample(10, 30)]},
                          {"samples": [{"sent_us": 1, "seen_us": 2}]},
                          {"samples": [dict(sample(1, 2), every_receiver="yes")]},
                          {"samples": [dict(sample(1, 2), quiet="no")]}):
            with self.subTest(malformed=malformed), self.assertRaises(Exception) as caught:
                R.probe_window(malformed, 50, 100)
            self.assertNotIsInstance(caught.exception, Q.AcceptanceFailure)

    def test_transition_counts_and_batch_phases_reject_malformed_series(self):
        self.assertEqual(R.transition_counts(metrics_text() + transition_text(3))["fallback_handoff"], 3)
        for text in ("", transition_text(1) + transition_text(1),
                     'bgp_rib_policy_transition_total{outcome="committed"} 1.5\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                R.transition_counts(text)
        self.assertEqual(R.batch_phases("plain text\n" + batch_event(100), 50, 150)[0]["wall_us"], 100)
        self.assertEqual(R.batch_phases(batch_event(100), 101, 150), [])
        # A parent daemon logs no deferred_members; a paced one does.
        self.assertIsNone(R.batch_phases(batch_event(100), 50, 150)[0]["deferred_members"])
        paced = json.loads(batch_event(100))
        paced["fields"]["deferred_members"] = 148
        self.assertEqual(R.batch_phases(json.dumps(paced), 50, 150)[0]["deferred_members"], 148)
        self.assertIsNone(R.batch_phases(json.dumps(paced), 50, 150)[0]["applied_members"])
        paced["fields"].update(classification="paced_apply", applied_members=3, fallback_members=0)
        row = R.batch_phases(json.dumps(paced), 50, 150)[0]
        self.assertEqual((row["classification"], row["applied_members"], row["fallback_members"]),
                         ("paced_apply", 3, 0))
        paced["fields"]["deferred_members"] = "148"
        with self.assertRaises(ValueError):
            R.batch_phases(json.dumps(paced), 50, 150)
        broken = json.loads(batch_event(100))
        for field, value in (("timestamp", "yesterday"), ("timestamp", "2026-11-11T00:00:00")):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                R.batch_phases(json.dumps(dict(broken, **{field: value})), 0, 10**18)
        del broken["fields"]["distribution_us"]
        with self.assertRaises(ValueError):
            R.batch_phases(json.dumps(broken), 0, 10**18)

    def test_analyze_rejects_regroup_scrapes_that_miss_the_window_and_copied_receipts(self):
        for defect in ("scrape-before-settled", "scrape-after-signal", "copied-window", "missing-window",
                       "missing-probe", "missing-scrape", "counter-backwards"):
            with self.subTest(defect), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report = self.analysis_fixture(root)
                leg = root / "recovery-00-candidate"
                row = json.loads((leg / "result.json").read_text())
                events = [json.loads(line) for line in (leg / "events.jsonl").read_text().splitlines()]
                end = next(event for event in events if event.get("name") == "regroup-b-end")
                start = next(event for event in events if event.get("name") == "regroup-b-start")
                if defect == "scrape-before-settled":  # the regroup-b witness is at wall 200
                    end["requested_us"] = 199
                elif defect == "scrape-after-signal":  # the regroup-b signal is at wall 150
                    start["wall_us"] = 151
                elif defect == "copied-window":
                    row["regroup-b-window"] = row["regroup-a-window"]
                elif defect == "missing-window":
                    del row["regroup-a-window"]
                elif defect == "missing-probe":
                    lines = (leg / "driver.log").read_text().splitlines()
                    (leg / "driver.log").write_text("".join(line + "\n" for line in lines if "probe-stop b" not in line))
                elif defect == "missing-scrape":
                    events.remove(end)
                else:  # the closing scrape holds fallback_handoff 1
                    (leg / "metrics-regroup-b-start.txt").write_text(
                        actor_text(5, {"0.2": 1, "+Inf": 1}) + transition_text(2))
                (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
                Q.write_json(leg / "result.json", row)
                with patch.object(R, "check_wire", return_value=report), self.assertRaises(Exception) as caught:
                    R.analyze(root)
                self.assertNotIsInstance(caught.exception, Q.AcceptanceFailure)
                self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], "INVALID")
                if defect.startswith("scrape-"):
                    self.assertIn("scrape window does not bracket the regroup", str(caught.exception))

    def test_build_pins_same_source_cli_without_using_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            def build(command, **kwargs):
                binary = command[command.index("--bin") + 1]
                target = Path(kwargs["env"]["CARGO_TARGET_DIR"])
                profile = command[command.index("--profile") + 1] if "--profile" in command else "release"
                (target / profile).mkdir(parents=True, exist_ok=True)
                (target / profile / binary).write_text(binary + str(target))
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
        with tempfile.TemporaryDirectory() as temporary, tempfile.NamedTemporaryFile() as lock:
            manifest = {"recovery": Q.RECOVERY_BARS}
            def cell(*args):
                if args[2] == "private":
                    raise Q.AcceptanceFailure("baseline bar miss")
            with patch.object(R.sys, "argv", ["recovery.py", "run", temporary]), \
                 patch.object(Q, "manifest_for", return_value=manifest), \
                 patch.object(Q, "verify_export"), \
                 patch.dict(Q.os.environ, held(lock)), \
                 patch.object(R, "run_cell", side_effect=cell) as run, \
                 patch.object(R, "analyze") as analyze:
                R.main()
            self.assertEqual([call.args[2] for call in run.call_args_list], list(Q.SCHEDULE))
            self.assertEqual([call.args[3] for call in run.call_args_list], list(range(6)))
            analyze.assert_called_once_with(Path(temporary))

    def test_candidate_bar_and_private_invalid_still_abort_recovery_cells(self):
        for arm, error in (("candidate", Q.AcceptanceFailure("candidate bar miss")),
                           ("private", ValueError("technical failure"))):
            with self.subTest(arm=arm), tempfile.TemporaryDirectory() as temporary, tempfile.NamedTemporaryFile() as lock:
                def cell(*args, arm=arm, error=error):
                    if args[2] == arm:
                        raise error
                with patch.object(R.sys, "argv", ["recovery.py", "run", temporary]), \
                     patch.object(Q, "manifest_for", return_value={"recovery": Q.RECOVERY_BARS}), \
                     patch.object(Q, "verify_export"), \
                     patch.dict(Q.os.environ, held(lock)), \
                     patch.object(R, "run_cell", side_effect=cell) as run, \
                     patch.object(R, "analyze") as analyze:
                    with self.assertRaises(type(error)):
                        R.main()
                self.assertEqual(run.call_count, 1 if arm == "candidate" else 2)
                analyze.assert_not_called()

    def test_control_bar_failure_summary_is_fail_not_invalid(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self.analysis_fixture(root)
            path = root / "recovery-01-private/result.json"
            row = json.loads(path.read_text())
            row.update(status="FAIL", error="readiness HTTP 503")
            Q.write_json(path, row)
            with patch.object(R, "check_wire", return_value=report), self.assertRaises(Q.AcceptanceFailure):
                R.analyze(root)
            summary = json.loads((root / "recovery-summary.json").read_text())
            self.assertEqual(summary["status"], "FAIL")
            self.assertFalse(summary["terminal_only_qualified"])
            self.assertEqual(summary["failed_cells"][0]["arm"], "private")

    def test_corrupt_complete_cell_outranks_a_recorded_control_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self.analysis_fixture(root)
            path = root / "recovery-01-private/result.json"
            row = json.loads(path.read_text())
            row.update(status="FAIL", error="readiness HTTP 503")
            Q.write_json(path, row)
            (root / "recovery-00-candidate/metrics.txt").write_text("")
            with patch.object(R, "check_wire", return_value=report), self.assertRaises(Exception) as caught:
                R.analyze(root)
            self.assertNotIsInstance(caught.exception, Q.AcceptanceFailure)
            self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], "INVALID")

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
        row["dirty"] = row["dirty_high_water"] = row["recovery_pending"] = 4
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
                row["peers"][0][4] = int(Q.PEER_BAR_BUDGET * .8) + 1
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

    def test_bytes_before_the_finish_boundary_must_be_validated_and_teardown_after_it_is_not(self):
        R.require_validated_tail(4096, 4096)
        for cursor, finished in ((4096, 4097), (4096, 4000), (4096, None)):
            with self.assertRaisesRegex(ValueError, "unvalidated trailing receiver bytes"):
                R.require_validated_tail(cursor, finished)

    def test_missing_wire_phase_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "driver.log").write_text('evpn_control {"command":"connected","clients":3}\n'
                                            'evpn_control {"command":"finish"}\n')
            with self.assertRaisesRegex(ValueError, "missing required wire phase"):
                R.check_wire(root, 3, 10)

    def test_recovery_witness_needs_every_member_inside_one_paused_slot(self):
        first, second = two_groups(), two_groups()
        first["wall_us"], second["wall_us"] = 100, 200
        second.update(elapsed_us=100_000, sample_slot=2, dirty=4, dirty_high_water=4, recovery_pending=4)
        for peer in second["peers"]:
            peer[2] = True
        self.assertEqual(R.recovery_pair([first, second], 4, 100, 200, "candidate"), (first, second))
        for paused, resumed in ((101, 200), (100, 199)):
            with self.subTest(paused=paused, resumed=resumed):
                self.assertIsNone(R.recovery_pair([first, second], 4, paused, resumed, "candidate"))
        short = copy.deepcopy(second)
        short["dirty"] = short["dirty_high_water"] = short["recovery_pending"] = 3
        short["peers"][2][2] = False
        self.assertIsNone(R.recovery_pair([first, short], 4, 100, 200, "candidate"), "one member short is not mass-dirty")
        for gap in (1_000_000, 50_001):
            with self.subTest(gap=gap):
                late = copy.deepcopy(second)
                late["elapsed_us"] = first["elapsed_us"] + gap
                late["sample_slot"] = late["elapsed_us"] // 50_000
                self.assertIsNone(R.recovery_pair([first, late], 4, 100, 200, "candidate"))
        for elapsed, slot in ((50_001, 1), (150_000, 3), (100_000, 3)):
            with self.subTest(elapsed=elapsed, slot=slot):
                skewed = copy.deepcopy(second)
                skewed.update(elapsed_us=elapsed, sample_slot=slot)
                self.assertIsNone(R.recovery_pair([first, skewed], 4, 100, 200, "candidate"))

    def test_private_owing_requires_every_peer_in_one_snapshot(self):
        first, second = witness("private", 4, 10), witness("private", 4, 10)
        first.update(wall_us=100, elapsed_us=50_000, sample_slot=1)
        second.update(wall_us=200, elapsed_us=100_000, sample_slot=2, owing=4, recovery_pending=4)
        for peer in second["peers"]:
            peer[10] = True
        R.roster(second, "private", 4)
        self.assertEqual(R.recovery_pair([first, second], 4, 100, 200, "private"), (first, second))
        self.assertIsNone(R.recovery_pair([first, second], 4, 100, 200, "candidate"), "owing is not dirty")
        mixed = copy.deepcopy(second)
        mixed["peers"][0][2] = True
        mixed["dirty"] = mixed["dirty_high_water"] = 1
        self.assertIsNone(R.recovery_pair([first, mixed], 4, 100, 200, "candidate"), "one dirty, the rest owing")
        self.assertEqual(R.recovery_pair([first, mixed], 4, 100, 200, "private"), (first, mixed))
        short = copy.deepcopy(second)
        short["peers"][2][10] = False
        short["owing"] = short["recovery_pending"] = 3
        R.roster(short, "private", 4)
        self.assertIsNone(R.recovery_pair([first, short], 4, 100, 200, "private"))

    def test_high_water_and_cross_row_union_do_not_replace_a_snapshot(self):
        rows = []
        for slot in range(1, 6):
            row = two_groups()
            row.update(elapsed_us=slot * 50_000, sample_slot=slot, wall_us=slot * 100,
                       dirty=3, dirty_high_water=4, recovery_pending=3)
            for index, peer in enumerate(row["peers"]):
                peer[2] = index != slot % 4
            R.roster(row, "candidate", 4)
            rows.append(row)
        self.assertEqual({peer[0] for row in rows for peer in row["peers"] if peer[2]},
                         {Q.COMMON.peer(index) for index in range(4)})
        self.assertIsNone(R.recovery_pair(rows, 4, 0, 1_000, "candidate"))

    def test_timings_use_reload_trigger_and_all_resume_ack(self):
        events = [{"event": "reload", "generation": "a", "at": 1},
                  {"event": "complete", "command": "policy a", "at": 3},
                  {"event": "reload", "generation": "b", "at": 4},
                  {"event": "complete", "command": "policy b", "at": 7},
                  {"event": "command", "command": "resume", "at": 10},
                  {"event": "complete", "command": "resume", "at": 11},
                  {"event": "complete", "command": "settle", "at": 15}]
        # The probe stops after convergence, so nothing is subtracted.
        for generation, converged in (("a", 3), ("b", 7)):
            events += [{"event": "command", "command": f"probe-stop {generation}", "at": converged + .1},
                       {"event": "complete", "command": f"probe-stop {generation}", "at": converged + 5}]
        self.assertEqual(R.timings(events), {"regroup-a-seconds": 2, "regroup-b-seconds": 3,
                                            "recovery-seconds": 4})
        with self.assertRaisesRegex(ValueError, "missing/duplicate"):
            R.timings(events[:6] + events[7:])
        # Convergence that completes while the probe stops: the stop's final
        # cycle waits for every receiver, so it would absorb the drain. The
        # measured regroup still includes it, and the overlap is refused.
        overlapped = copy.deepcopy(events)
        stop = next(event for event in overlapped if event.get("command") == "probe-stop b"
                    and event["event"] == "command")
        stop["at"] = 5
        with self.assertRaisesRegex(ValueError, "probe-stop b overlapped wire convergence"):
            R.timings(overlapped)
        stop["at"] = 7
        self.assertEqual(R.timings(overlapped)["regroup-b-seconds"], 3)

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
            names = ("initial_groups", "baseline", "regroup-b", "regroup-a", "mass_recovery_previous", "mass_recovery",
                     "protocol_obligation_before_churn", "protocol_obligation_during_churn", "protocol_obligation_after_churn", "settled")
            for sequence, name in enumerate(names):
                observation = witness(arm, 3, 10_000)
                if arm == "candidate":
                    observation["owned_groups"] = 2
                    observation["owned_routes"] = 60_000
                    for peer, data in enumerate(observation["peers"]):
                        data[1] = 2 if peer == 1 or (peer >= 2 and name == "regroup-b") else 1
                observation.update(elapsed_us=sequence * 50_000, sample_slot=sequence, wall_us=sequence * 100)
                if name.startswith("mass_recovery") or name.startswith("protocol_obligation"):
                    observation["recovery_pending"] = 3
                    observation["dirty" if arm == "candidate" else "owing"] = 3
                    observation["dirty_high_water"] = observation["dirty"]
                    for data in observation["peers"]: data[2 if arm == "candidate" else 10] = True
                if name.startswith("protocol_obligation"):
                    observation["refresh_pending"] = observation["protocol_obligations"] = 3
                    for data in observation["peers"]: data[8] = True
                row[name] = observation
                snapshots.append(observation)
            # The actor's next snapshot after the second barriers (at 200).
            row["mass_dirty_close"] = dict(copy.deepcopy(row["settled"]), elapsed_us=len(names) * 50_000,
                                           sample_slot=len(names), wall_us=950)
            snapshots.append(row["mass_dirty_close"])
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
                      {"event": "complete", "command": "pause", "at": 6.5, "wall_us": 350},
                      *[{"event": "complete", "command": "churn", "at": 7 + n} for n in range(32)],
                      {"event": "command", "command": "churn-overlap", "at": 40, "wall_us": 2000},
                      {"event": "complete", "command": "churn-overlap", "at": 41, "wall_us": 4000},
                      *[{"event": "input-applied", "generation": n, "receipts": n * 3,
                         "at": n * 15, "wall_us": 5000 if n == 3 else n * 100} for n in range(1, 4)],
                      {"event": "command", "command": "resume", "at": 51, "wall_us": 7000},
                      {"event": "complete", "command": "resume", "at": 52},
                      {"event": "complete", "command": "settle", "at": 56}]
            reload_controls(leg, row, events)
            controls = [{"command": "churn-overlap", "result": {"write_started_us": 2100, "writers_drained_us": 3900}}]
            regroup_evidence(leg, events, controls)
            events.sort(key=lambda event: event["at"])
            (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
            (leg / "driver.log").write_text("".join("evpn_control " + json.dumps(item) + "\n" for item in controls))
            for generation in ("b", "a"):
                row[f"regroup-{generation}-window"] = R.regroup_window(leg, generation, row[f"regroup-{generation}"])
            # One 20 Hz probe series covering the first through last workload event.
            write_readiness(leg, [1 + n * .05 for n in range(round((56 - 1) / .05) + 1)])
            (leg / "metrics.txt").write_text(metrics_text())
            (leg / "metrics-mass-dirty-start.txt").write_text(actor_text(900_000, {"0.2": 5, "0.5": 6, "+Inf": 6}))
            (leg / "metrics-mass-dirty-end.txt").write_text(actor_text(1_300_000, {"0.2": 40, "0.5": 43, "+Inf": 44}))
            row["mass_dirty_actor"] = None
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

    def test_analyze_rejects_recovery_cadence_misses_in_either_arm(self):
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
                    start = snapshots.index(row["mass_recovery"])
                    shift = gap - 50_000
                    for snapshot in snapshots[start:]:
                        snapshot["elapsed_us"] += shift
                        snapshot["sample_slot"] = snapshot["elapsed_us"] // 50_000
                    row["mass_recovery"] = snapshots[start]
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

    def test_analyze_fails_a_short_or_unpaused_recovery_snapshot_in_either_arm(self):
        for arm in ("candidate", "private"):
            for defect in ("short", "before-pause", "after-resume"):
                with self.subTest(arm=arm, defect=defect), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    report = self.analysis_fixture(root)
                    leg = next(root.glob(f"recovery-*-{arm}"))
                    row = json.loads((leg / "result.json").read_text())
                    events = [json.loads(line) for line in (leg / "events.jsonl").read_text().splitlines()]
                    lines = (leg / "observer.log").read_text().splitlines()
                    if defect == "short":
                        target = row["mass_recovery"]
                        row["mass_recovery"] = copy.deepcopy(target)
                        row["mass_recovery"]["recovery_pending"] = 2
                        row["mass_recovery"]["dirty" if arm == "candidate" else "owing"] = 2
                        row["mass_recovery"]["dirty_high_water"] = row["mass_recovery"]["dirty"]
                        row["mass_recovery"]["peers"][2][2 if arm == "candidate" else 10] = False
                        lines = [("evpn_qualification " + json.dumps(row["mass_recovery"]))
                                 if line.startswith("evpn_qualification ")
                                 and json.loads(line.removeprefix("evpn_qualification ")) == target
                                 else line for line in lines]
                    else:
                        # Moves the pause after, or the resume before, the witness window.
                        command, kind = ("pause", "complete") if defect == "before-pause" else ("resume", "command")
                        for event in events:
                            if event.get("command") == command and event["event"] == kind:
                                event["wall_us"] = 450
                    (leg / "observer.log").write_text("".join(line + "\n" for line in lines))
                    (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
                    Q.write_json(leg / "result.json", row)
                    with patch.object(R, "check_wire", return_value=report), \
                         self.assertRaises(Q.AcceptanceFailure):
                        R.analyze(root)

    def test_analyze_checks_one_complete_recovery_snapshot(self):
        for arm in ("candidate", "private"):
            # One dirty and two owing peers: the owned arm needs all three dirty.
            partial = "PASS" if arm == "private" else "FAIL"
            for mode, verdict in (("mixed", partial), ("overlap", partial), ("missing-reason", "FAIL"),
                                  ("missing-peer", "INVALID"), ("missing-row", "INVALID"),
                                  ("cross-row-union", "FAIL"), ("double-count", "INVALID")):
                with self.subTest(arm=arm, mode=mode), tempfile.TemporaryDirectory() as temporary:
                    root = Path(temporary)
                    report = self.analysis_fixture(root)
                    leg = next(root.glob(f"recovery-*-{arm}"))
                    row = json.loads((leg / "result.json").read_text())
                    original = copy.deepcopy(row["mass_recovery"])
                    changed = row["mass_recovery"]
                    for index, peer in enumerate(changed["peers"]):
                        peer[2], peer[10] = index == 0, index != 0
                    if mode == "overlap":
                        changed["peers"][0][10] = True
                    elif mode in ("missing-reason", "cross-row-union", "double-count"):
                        changed["peers"][2][10] = False
                        if mode == "double-count":
                            changed["peers"][0][10] = True
                    elif mode == "missing-peer":
                        changed["peers"].pop()
                        changed["members"] = 2
                        changed["owned_members"] = 2 if arm == "candidate" else 0
                    changed["dirty"] = changed["dirty_high_water"] = sum(peer[2] for peer in changed["peers"])
                    changed["owing"] = sum(peer[10] for peer in changed["peers"])
                    changed["recovery_pending"] = sum(peer[2] or peer[10] for peer in changed["peers"])
                    if mode == "double-count":
                        changed["recovery_pending"] = changed["dirty"] + changed["owing"]
                    lines = (leg / "observer.log").read_text().splitlines()
                    lines = [line if not line.startswith("evpn_qualification ")
                             or json.loads(line.removeprefix("evpn_qualification ")) != original
                             else "evpn_qualification " + json.dumps(changed) for line in lines]
                    if mode == "missing-row":
                        lines.remove("evpn_qualification " + json.dumps(changed))
                    (leg / "observer.log").write_text("".join(line + "\n" for line in lines))
                    Q.write_json(leg / "result.json", row)
                    with patch.object(R, "check_wire", return_value=report) as wire_check:
                        if verdict == "PASS":
                            R.analyze(root)
                            self.assertEqual(wire_check.call_count, 2)
                            summary = json.loads((root / "recovery-summary.json").read_text())
                            result = next(item for item in summary["recovery"] if item["arm"] == arm)
                            self.assertEqual(result["pending"], 3)
                            self.assertEqual(len(result["dirty"]), 1)
                            self.assertEqual(len(result["owing"]), 3 if mode == "overlap" else 2)
                        else:
                            with self.assertRaises(ValueError) as caught:
                                R.analyze(root)
                            self.assertEqual(isinstance(caught.exception, Q.AcceptanceFailure), verdict == "FAIL")
                            # The mutated arm must fail before its wire/parity or median checks.
                            self.assertLessEqual(wire_check.call_count, 1)
                    self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], verdict)

    def test_only_the_candidate_must_hold_a_refresh_obligation_through_the_overlap(self):
        # At 150 peers the private control answers the paused refresh at once:
        # owing peers and no refresh/EoR obligation in any snapshot.
        for arm, mode, verdict in (("candidate", "no-obligation", "FAIL"), ("private", "no-obligation", "PASS"),
                                   ("candidate", "one-row", "FAIL"), ("private", "no-recovery-work", "FAIL")):
            with self.subTest(arm=arm, mode=mode), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                report = self.analysis_fixture(root)
                leg = next(root.glob(f"recovery-*-{arm}"))
                row = json.loads((leg / "result.json").read_text())
                names = ("protocol_obligation_during_churn",) if mode == "one-row" else (
                    "protocol_obligation_before_churn", "protocol_obligation_during_churn",
                    "protocol_obligation_after_churn")
                replaced = {}
                for name in names:
                    original = copy.deepcopy(row[name])
                    row[name]["refresh_pending"] = row[name]["protocol_obligations"] = 0
                    for peer in row[name]["peers"]: peer[8] = False
                    if mode == "no-recovery-work":
                        row[name]["recovery_pending"] = row[name]["owing"] = 0
                        for peer in row[name]["peers"]: peer[10] = False
                    replaced[json.dumps(original, sort_keys=True)] = row[name]
                lines = []
                for line in (leg / "observer.log").read_text().splitlines():
                    if line.startswith("evpn_qualification "):
                        key = json.dumps(json.loads(line.removeprefix("evpn_qualification ")), sort_keys=True)
                        line = "evpn_qualification " + json.dumps(replaced.pop(key)) if key in replaced else line
                    lines.append(line)
                self.assertEqual(replaced, {})
                (leg / "observer.log").write_text("".join(line + "\n" for line in lines))
                Q.write_json(leg / "result.json", row)
                with patch.object(R, "check_wire", return_value=report):
                    if verdict == "PASS":
                        R.analyze(root)
                    else:
                        with self.assertRaises(Q.AcceptanceFailure):
                            R.analyze(root)
                self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], verdict)

    def test_recovery_median_ratio_is_reported_but_only_regroup_gates(self):
        def rows(candidate, private):
            return [{"arm": arm, "regroup-a-seconds": 1., "regroup-b-seconds": 1., "recovery-seconds": value}
                    for arm, value in (("candidate", candidate), ("private", private)) for _ in range(3)]
        with patch("sys.stdout", io.StringIO()) as printed:
            report = R.median_report(rows(1.04, .22))
        self.assertEqual((report["recovery-seconds"]["within_ratio"], report["recovery-seconds"]["gated"]), (False, False))
        self.assertAlmostEqual(report["recovery-seconds"]["ratio"], 1.04 / .22)
        self.assertIn("recovery-seconds: candidate 1.040000 s, private 0.220000 s", printed.getvalue())
        self.assertIn("report-only", printed.getvalue())
        slow = rows(1., 1.)
        for row in slow:
            if row["arm"] == "candidate":
                row["regroup-b-seconds"] = 1.04
        with patch("sys.stdout", io.StringIO()), self.assertRaisesRegex(Q.AcceptanceFailure, "regressed: regroup-b"):
            R.median_report(slow)
        with patch("sys.stdout", io.StringIO()), self.assertRaisesRegex(Q.AcceptanceFailure, "convergence bar"):
            R.median_report(rows(61., 61.))

    def test_analyze_needs_the_pause_and_resume_clocks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self.analysis_fixture(root)
            leg = next(root.glob("recovery-*-candidate"))
            events = [json.loads(line) for line in (leg / "events.jsonl").read_text().splitlines()]
            events = [event for event in events if event.get("command") != "pause"]
            (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
            with patch.object(R, "check_wire", return_value=report), \
                 self.assertRaisesRegex(ValueError, "pause/resume events missing") as caught:
                R.analyze(root)
            self.assertNotIsInstance(caught.exception, Q.AcceptanceFailure)

    def test_roster_requires_a_consistent_high_water(self):
        row = two_groups()
        R.roster(row, "candidate", 4)
        for value in (None, True, -1, 5, "4"):
            with self.subTest(value=value):
                bad = copy.deepcopy(row)
                if value is None:
                    del bad["dirty_high_water"]
                else:
                    bad["dirty_high_water"] = value
                with self.assertRaisesRegex(ValueError, "dirty high-water") as caught:
                    R.roster(bad, "candidate", 4)
                self.assertNotIsInstance(caught.exception, Q.AcceptanceFailure)
        below = copy.deepcopy(row)
        for peer in below["peers"]:
            peer[2] = True
        below["dirty"], below["dirty_high_water"], below["recovery_pending"] = 4, 3, 4
        with self.assertRaisesRegex(ValueError, "dirty high-water"):
            R.roster(below, "candidate", 4)

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

    def test_analyze_ends_the_observer_log_at_a_cut_off_final_line_and_rejects_one_in_the_middle(self):
        # The final line of a real private-arm observer log: the daemon exited
        # partway through writing this teardown sample.
        torn = ('evpn_qualification {"live_provenance_slots":0,"provenance_slot_capacity":0,"elapsed_us":17000231,'
                '"sample_slot":340,"wall_us":1794469460656626,"members":0,"owned_groups":0,"owned_members":0,'
                '"owned_routes":0,"private_routes":0,"dirty":0,"dirty_high_water":0,"retained":192,"peak":192,'
                '"peer_budget":23068672,"daemon_budget":268435456,"pending_resets":0,"completion_receipts":0,'
                '"marker_debt":0,"retained_recovery":0,"refresh_pending":0,"eor_pending":0,'
                '"protocol_obligations":0,"owing":0,"recovery_pending":')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            report = self.analysis_fixture(root)
            path = root / "recovery-00-candidate/observer.log"
            complete = path.read_text()
            with patch.object(R, "check_wire", return_value=report):
                R.analyze(root)
                self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["observer_torn_tails"], [])
                path.write_text(complete + torn)
                R.analyze(root)
                summary = json.loads((root / "recovery-summary.json").read_text())
                self.assertEqual((summary["status"], summary["observer_torn_tails"]), ("PASS", ["recovery-00-candidate"]))
                # The same cut-off line anywhere but the end is malformed evidence.
                lines = complete.splitlines(keepends=True)
                path.write_text("".join(lines[:1]) + torn + "\n" + "".join(lines[1:]))
                with self.assertRaises(json.JSONDecodeError):
                    R.analyze(root)
                self.assertEqual(json.loads((root / "recovery-summary.json").read_text())["status"], "INVALID")
                # A bar miss still reports the cut-off tail in its FAIL summary.
                bad = witness("candidate", 3, 10_000)
                bad.update(owned_groups=2, peak=int(bad["daemon_budget"] * .9))
                path.write_text(complete + "evpn_qualification " + json.dumps(bad) + "\n" + torn)
                with self.assertRaisesRegex(Q.AcceptanceFailure, "headroom"):
                    R.analyze(root)
                summary = json.loads((root / "recovery-summary.json").read_text())
                self.assertEqual((summary["status"], summary.get("observer_torn_tails")), ("FAIL", ["recovery-00-candidate"]))

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
                        budget = Q.PEER_BAR_BUDGET if target == "peer" else row["daemon_budget"]
                        set_provenance_peak(row, target, int(budget * fraction))
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
                        set_provenance_peak(row, "peer", int(Q.PEER_BAR_BUDGET * .8))
                    else:
                        set_provenance_peak(row, "peer", int(Q.PEER_BAR_BUDGET * .9))
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
                    set_provenance_peak(row, "peer", int(Q.PEER_BAR_BUDGET * fraction))
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
                    # Receivers are checked in parallel; the report keeps peer order.
                    self.assertTrue(all([row["peer"] for row in rows] == [0, 1, 2] for rows in report.values()))
                else:
                    with self.assertRaisesRegex(Q.AcceptanceFailure, "before receiver refresh EoR"):
                        R.check_wire(root, 3, 10)


if __name__ == "__main__":
    unittest.main()
