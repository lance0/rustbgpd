#!/usr/bin/env python3
"""Negative controls for the real-daemon qualification instrument."""

import argparse
import copy
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
import tomllib
import time
import unittest
from unittest import mock


SPEC = importlib.util.spec_from_file_location("mass_dirty", Path(__file__).with_name("recovery_mass_dirty.py"))
receipt = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(receipt)


class MassDirtyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rmd-test-")
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_harness_evidence_does_not_wait_for_protocol_consumption(self):
        read_fd, write_fd = os.pipe()
        try:
            capacity = fcntl.fcntl(write_fd, fcntl.F_GETPIPE_SZ)
        finally:
            os.close(read_fd)
            os.close(write_fd)
        line = 'mass_dirty_readiness {"status":200,"phase":null,"request_deadline_ms":1000,"elapsed_seconds":null}\n'
        count = max(1024 * 1024, capacity * 4) // len(line) + 1
        script = (f"import sys; sys.stdout.write({line!r} * {count}); "
                  "sys.stdout.flush(); print('mass_dirty_ready {\"complete\":true}', flush=True)")
        path = self.root / "harness.log"
        with path.open("w") as log, (self.root / "harness.stderr").open("w") as errors:
            child = receipt.start_harness([sys.executable, "-c", script], log, errors)
            try:
                # No stdout consumer exists while the producer fills more than
                # an actual pipe's capacity. This must finish independently.
                self.assertEqual(child.wait(timeout=5), 0)
                with path.open() as records:
                    self.assertEqual(receipt.read_record(child, records, "mass_dirty_ready", time.monotonic() + 5),
                                     {"complete": True})
                self.assertEqual(path.read_text().splitlines(), [line.rstrip()] * count +
                                 ['mass_dirty_ready {"complete":true}'])
            finally:
                receipt.stop_owned(child)
                if child.stdin is not None:
                    child.stdin.close()
                if child.stdout is not None:
                    child.stdout.close()

    def test_harness_tail_waits_for_partial_records_and_fails_on_death_or_deadline(self):
        child = mock.Mock(returncode=None)
        child.poll.return_value = None
        records = mock.Mock()
        records.readline.side_effect = ['mass_dirty_ready {', '', '"complete":true}\n']
        with mock.patch.object(receipt.time, "sleep") as wait:
            self.assertEqual(receipt.read_record(child, records, "mass_dirty_ready", time.monotonic() + 5),
                             {"complete": True})
        wait.assert_called_once()
        child.returncode = 7
        child.poll.return_value = 7
        with self.assertRaisesRegex(ValueError, "harness exited before"):
            receipt.read_record(child, io.StringIO('mass_dirty_ready {'), "mass_dirty_ready", time.monotonic() + 5)
        with self.assertRaisesRegex(TimeoutError, "fixed leg deadline"):
            receipt.read_record(child, io.StringIO(''), "mass_dirty_ready", time.monotonic() - 1)

    def test_fixture_snapshot_skips_socket_and_preserves_initiating_error(self):
        source = self.root / "fixture-source"
        source.mkdir()
        (source / "config.toml").write_text("configuration")
        (source / "data").mkdir()
        (source / "data" / "generation.list").write_text("64500\n")
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(source / "grpc.sock"))
            with self.assertRaisesRegex(RuntimeError, "initiating reload failure"):
                try:
                    raise RuntimeError("initiating reload failure")
                finally:
                    receipt.copy_fixture(source, self.root / "fixture-snapshot")
        self.assertEqual((self.root / "fixture-snapshot/config.toml").read_text(), "configuration")
        self.assertEqual((self.root / "fixture-snapshot/data/generation.list").read_text(), "64500\n")
        self.assertFalse((self.root / "fixture-snapshot/grpc.sock").exists())

    def test_readiness_covers_each_full_operation_with_bracket_probes_and_no_gaps(self):
        def fixture():
            probes = [{"sequence": index + 1, "status": 200, "phase": None, "request_deadline_ms": 1000,
                       "elapsed_seconds": .01, "started_monotonic_seconds": float(100 + index),
                       "finished_monotonic_seconds": 100.01 + index} for index in range(7)]
            records = {"mass_dirty_exit": [{"status": "PASS", "readiness_samples": 7, "readiness_interval_ms": 250,
                                            "readiness_request_deadline_ms": 1000}],
                       "mass_dirty_readiness": probes}
            operations = [{"trigger_monotonic_seconds": start, "drain_monotonic_seconds": start + .1,
                           "resume_monotonic_seconds": start + .2, "fold_monotonic_seconds": start + 2,
                           "trigger_to_drain_seconds": .1, "drain_to_resume_seconds": .1,
                           "resume_to_observed_fold_seconds": 1.8, "trigger_to_fold_seconds": 2}
                          for start in (100.5, 103.5)]
            return records, operations

        records, operations = fixture()
        self.assertEqual(receipt.readiness_coverage(records, operations, False),
                         [{"sample_count": 4, "max_start_gap_seconds": 1.0}] * 2)
        # A slow or failed sample is readiness evidence for the verdict bars, not invalid coverage.
        records, operations = fixture()
        records["mass_dirty_readiness"][1].update(elapsed_seconds=.999, finished_monotonic_seconds=101.999,
                                                  status=None, phase="response_read_to_eof")
        self.assertEqual(receipt.readiness_coverage(records, operations, False),
                         [{"sample_count": 4, "max_start_gap_seconds": 1.0}] * 2)
        for mutation in ("before-b", "after-a", "gap", "sequence", "backward", "nonfinite", "unexplained-status",
                         "request-deadline", "phase", "duration"):
            with self.subTest(mutation=mutation):
                records, operations = fixture()
                probes = records["mass_dirty_readiness"]
                if mutation in ("before-b", "after-a"):
                    probes.pop(0 if mutation == "before-b" else -1)
                    for index, probe in enumerate(probes):
                        probe["sequence"] = index + 1
                    records["mass_dirty_exit"][0]["readiness_samples"] = len(probes)
                elif mutation == "gap":
                    probes[1]["started_monotonic_seconds"] += .3
                    probes[1]["finished_monotonic_seconds"] += .3
                elif mutation == "sequence":
                    probes[1]["sequence"] = 1
                elif mutation == "backward":
                    probes[1]["started_monotonic_seconds"] = 99
                elif mutation == "nonfinite":
                    probes[1]["finished_monotonic_seconds"] = float("nan")
                elif mutation == "unexplained-status":
                    probes[1]["status"] = 503
                elif mutation == "request-deadline":
                    probes[1]["request_deadline_ms"] = 250
                elif mutation == "phase":
                    operations[0]["resume_monotonic_seconds"] = 99
                else:
                    operations[0]["trigger_to_fold_seconds"] = 1
                with self.assertRaises(ValueError):
                    receipt.readiness_coverage(records, operations, False)

    def test_identical_daemons_fail_even_with_matching_binary_roster(self):
        binaries = self.root / "bin"
        binaries.mkdir()
        for name, contents in (("rustbgpd-candidate", "same daemon"), ("rustbgpd-flat", "same daemon"),
                               ("reloadstall", "observer"), ("rbgp", "client")):
            (binaries / name).write_text(contents)
        (self.root / "binaries.sha256").write_text("".join(
            f"{receipt.digest(path)}  {path}\n" for path in sorted(binaries.iterdir())))
        with self.assertRaisesRegex(ValueError, "candidate and flat daemon binaries are identical"):
            receipt.verified_binaries(self.root)

    def manifest(self, correctness=True, cohort="no-refusal", profile="full-vpn"):
        cpus = sorted(os.sched_getaffinity(0))
        if len(cpus) < 2:
            self.skipTest("requires two assigned CPUs")
        root = self.root / "campaign"
        args = argparse.Namespace(output=str(root), head="a" * 40, profile=profile, cohort=cohort,
                                  daemon_cpus=str(cpus[0]), harness_cpus=str(cpus[1]), correctness_only=correctness)
        return root, receipt.init(args)

    def test_fixed_policy_and_raw_family_split(self):
        for profile, pressure in (("full-uc", False), ("full-vpn", False), ("full-uc", True), ("full-vpn", True)):
            scenario = self.root / f"{profile}-{pressure}"
            hashes = receipt.generate(scenario, profile, 12, 17986, 19186, pressure=pressure)
            self.assertEqual(scenario.stat().st_mode & 0o777, 0o700)
            config = tomllib.loads((scenario / "config.toml").read_text())
            self.assertEqual(config["config_epoch"], 2)
            self.assertTrue(config["global"]["ebgp_requires_policy"])
            self.assertEqual(len(config["neighbors"]), 13)
            self.assertFalse(config["neighbors"][0]["route_reflector_client"])
            self.assertTrue(all(row["route_reflector_client"] for row in config["neighbors"][1:]))
            expected = ["l3vpn_ipv4_unicast", "l3vpn_ipv6_unicast"] if profile == "full-vpn" else ["ipv4_unicast", "ipv6_unicast"]
            self.assertEqual(config["neighbors"][0]["families"], expected)
            policy = (scenario / "member.rpol").read_text()
            self.assertIn("route.origin-as in generation_b", policy)
            self.assertNotIn("peer.asn", policy)
            self.assertEqual("route.prefix in denied" in policy, pressure)
            before = receipt.digest(scenario / "member.rpol")
            stimulus = receipt.wire_stimulus()
            origins = [int(value) for value in (scenario / "generation.list").read_text().splitlines()]
            self.assertEqual(origins, [stimulus["origin_base"] + 2 * chunk + 1
                                       for chunk in range(stimulus["origin_cardinality"])])
            self.assertEqual(len(origins), 15375)
            self.assertNotIn(64512, origins)
            self.assertEqual(set(hashes), {"config.toml", "member.rpol", "generation.list"})
            self.assertEqual(receipt.digest(scenario / "member.rpol"), before)
            self.assertEqual(hashes["member.rpol"], before)
            self.assertEqual(receipt.profile_shape(profile), [1_000_000, 230_000])

    def test_source_derivation_changes_only_full_capture_boolean(self):
        source = self.root / "update_groups.rs"
        before = ("    fn capture_group_admitted_keys_inner(\n"
                  "        let captured = ledger.capture_full_old_with_checkpoint(\n"
                  "            peer, hint, &group.table, true, uc, vpn, checkpoint,\n"
                  "        );\n    }\n"
                  "    pub(in crate::manager) fn prepare_empty_group_recovery_admission() {\n"
                  "        let still_shared = true;\n    }\n")
        source.write_text(before)
        metadata = receipt.derive_flat(source, self.root / "derivation.json")
        self.assertEqual(source.read_text(), before.replace("&group.table, true,", "&group.table, false,", 1))
        self.assertFalse(metadata["vpn_full_old_already_flat"])
        self.assertEqual(metadata["expression_before"], "true")
        with self.assertRaisesRegex(ValueError, "guard anchor drift"):
            receipt.derive_flat(source, self.root / "second.json")

    def test_derivation_refuses_old_sorted_candidate_instead_of_relabeling_it(self):
        source = self.root / "old.rs"
        source.write_text("    fn capture_group_admitted_keys_inner(\nlet shared = ledger.with_ordered_capture();\n    pub(in crate::manager) fn prepare_empty_group_recovery_admission")
        with self.assertRaisesRegex(ValueError, "helper anchor drift"):
            receipt.derive_flat(source, self.root / "derivation.json")

    def test_cohorts_resources_and_bars_are_frozen_before_results(self):
        root, manifest = self.manifest(correctness=False, cohort="cap-pressure")
        self.assertEqual(manifest["receivers"], 24)
        self.assertEqual(manifest["limits"]["daemon_bytes"], 10 * 1024 ** 3)
        self.assertEqual(manifest["limits"]["harness_bytes"], 2 * 1024 ** 3)
        self.assertEqual(manifest["limits"]["readiness_request_deadline_ms"], 1000)
        self.assertEqual(manifest["limits"]["readiness_interval_seconds"], .25)
        self.assertEqual(manifest["limits"]["convergence_relative"], 1.10)
        self.assertEqual(manifest["limits"]["convergence_absolute_seconds"], .030)
        self.assertIn("ingress fill, cold capture and dirty witness", manifest["primary_convergence"])
        manifest["receivers"] = 12
        receipt.write_json(root / "campaign.json", manifest)
        with self.assertRaisesRegex(ValueError, "campaign changed"):
            receipt.load_manifest(root)

    def test_cpu_overlap_is_refused(self):
        cpu = str(next(iter(os.sched_getaffinity(0))))
        args = argparse.Namespace(output=str(self.root / "bad"), head="a" * 40, profile="full-uc", cohort="no-refusal",
                                  daemon_cpus=cpu, harness_cpus=cpu, correctness_only=True)
        with self.assertRaisesRegex(ValueError, "overlap"):
            receipt.init(args)

    def test_manifest_cannot_omit_or_reorder_required_operations(self):
        root, original = self.manifest(correctness=False)
        mutations = ({"schedule": []}, {"schedule": ["flat"]},
                     {"schedule": ["flat"] * 6}, {"schedule": original["schedule"][::-1]},
                     {"repetitions": 0}, {"repetitions": True}, {"correctness_only": True},
                     {"correctness_only": "false"}, {"schema": "unqualified"},
                     {"inputs": {}}, {"support_inputs": {}}, {"profile": "unknown"},
                     {"cohort": "unknown"}, {"head": "not-a-source"})
        for change in mutations:
            with self.subTest(change=change):
                receipt.write_json(root / "campaign.json", {**original, **change})
                (root / "campaign.sha256").write_text(receipt.digest(root / "campaign.json") + "\n")
                with self.assertRaises(ValueError):
                    receipt.load_manifest(root)

    def test_dirty_witness_requires_actual_each_peer_and_unchanged_group(self):
        def row(index):
            return {"state": "Established", "slow_peer": False, "outbound_resync_pending": True,
                    "update_group": "group:7", "update_group_recovery_fallback": "", "address": receipt.peer(index)}
        snapshot = mock.Mock(side_effect=[(row(1), 0, 0), (row(2), 0, 0)])
        actual = receipt.neighbor_witness(snapshot, 2, pending=True)
        self.assertEqual(len(actual), 2)
        omitted = row(1)
        omitted.pop("slow_peer")
        receipt.neighbor_witness(mock.Mock(side_effect=[(omitted, 0, 0), (row(2), 0, 0)]), 2, pending=True)
        for invalid in ({**row(1), "slow_peer": True}, {**row(1), "slow_peer": 0},
                        {**row(1), "address": receipt.peer(2)}):
            with self.assertRaises(ValueError):
                receipt.neighbor_witness(mock.Mock(return_value=(invalid, 0, 0)), 2, pending=True)
        bad = row(2)
        bad["outbound_resync_pending"] = False
        with self.assertRaisesRegex(ValueError, "actual dirty"):
            receipt.neighbor_witness(mock.Mock(side_effect=[(row(1), 0, 0), (bad, 0, 0)]), 2, pending=True)
        with self.assertRaisesRegex(ValueError, "group identity"):
            receipt.neighbor_witness(mock.Mock(side_effect=[(row(1), 0, 0), (row(2), 0, 0)]), 2,
                                     expected=[(receipt.peer(1), "group:6"), (receipt.peer(2), "group:6")], pending=True)

    def test_all_fallback_causes_are_required(self):
        text = "\n".join(f'bgp_update_group_recovery_fallback_total{{cause="{cause}"}} 0' for cause in receipt.CAUSES)
        self.assertEqual(receipt.fallback(text), dict.fromkeys(receipt.CAUSES, 0))
        with self.assertRaisesRegex(ValueError, "missing/invalid metric"):
            receipt.fallback(text.replace('cause="missing_proof"', 'cause="other"'))

    def snapshot_row(self, address, pending=False, **fields):
        return {"address": address, "state": "Established", "update_group": "group:7",
                "outbound_resync_pending": pending, "outbound_dirty_seconds": 3, **fields}

    def snapshot_error(self):
        return subprocess.CalledProcessError(1, ["rbgp", "neighbor"], output="",
            stderr="Error: deadline exceeded: RIB snapshot query timed out\n")

    def test_snapshot_retry_restarts_both_held_sweeps_with_success_only_clocks(self):
        failures = self.root / "failures.jsonl"
        failures.write_text("")
        clock, calls = [0.0], []
        def run(args, **kwargs):
            calls.append(args[-1])
            clock[0] += .1
            if len(calls) == 3:
                raise self.snapshot_error()
            row = self.snapshot_row(args[-1], args[-1] != receipt.peer(0),
                                    epoch="discarded" if len(calls) < 3 else "complete")
            return subprocess.CompletedProcess(args, 0, json.dumps(row), "")
        def pause(duration):
            clock[0] += duration
        groups = [(receipt.peer(index), "group:7") for index in (1, 2)]
        with mock.patch.object(receipt.subprocess, "run", side_effect=run), \
             mock.patch.object(receipt.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(receipt.time, "sleep", side_effect=pause):
            witness = receipt.poll_snapshot_witness(lambda query: receipt.held_dirty_witness(query, 2, groups, False),
                "rbgp", "unix:///owned.sock", 10, failures, "held-b")
        self.assertEqual(len(calls), 8)
        self.assertTrue(all(row["raw"]["epoch"] == "complete" for sweep in witness["sweeps"] for row in sweep))
        self.assertAlmostEqual(witness["sweeps"][0][0]["query_begin_monotonic_seconds"], .35)
        receipt.validate_held_witness(witness, groups, False,
            {"trigger_monotonic_seconds": 0, "drain_monotonic_seconds": 0, "resume_monotonic_seconds": 10})
        record = json.loads(failures.read_text())
        self.assertEqual((record["stderr"], record["stdout"], record["phase"], record["peer"]),
                         (self.snapshot_error().stderr, "", "held-b", receipt.peer(1)))
        self.assertEqual(receipt.snapshot_failure_counts(failures, 2),
                         {"total": 1, "by_phase": {"held-b": {receipt.peer(1): 1}}})

    def test_snapshot_retry_covers_initial_source_held_source_and_settled_callers(self):
        groups = [(receipt.peer(index), "group:7") for index in (1, 2)]
        readers = {
            "initial": lambda query: receipt.neighbor_witness(query, 2, pending=False),
            "initial-source": receipt.source_witness,
            "held-b": lambda query: receipt.held_dirty_witness(query, 2, groups, True),
            "settled-b": lambda query: receipt.neighbor_witness(query, 2, expected=groups, pending=False),
            "settled-b-source": receipt.source_witness}
        for phase, read in readers.items():
            with self.subTest(phase=phase):
                failures = self.root / "failures.jsonl"
                failures.write_text("")
                failed = []
                target = receipt.peer(0) if phase.endswith("source") or phase == "held-b" else receipt.peer(1)
                def run(args, target=target, failed=failed, phase=phase, **kwargs):
                    if args[-1] == target and not failed:
                        failed.append(True)
                        raise self.snapshot_error()
                    row = self.snapshot_row(args[-1], phase == "held-b" and args[-1] != receipt.peer(0))
                    return subprocess.CompletedProcess(args, 0, json.dumps(row), "")
                with mock.patch.object(receipt.subprocess, "run", side_effect=run) as cli, \
                     mock.patch.object(receipt.time, "monotonic", return_value=0), \
                     mock.patch.object(receipt.time, "sleep"):
                    receipt.poll_snapshot_witness(read, "rbgp", "unix:///owned.sock", 1800, failures, phase)
                self.assertTrue(all(call.kwargs["timeout"] == 30 for call in cli.call_args_list))
                self.assertEqual(receipt.snapshot_failure_counts(failures, 2),
                                 {"total": 1, "by_phase": {phase: {target: 1}}})

    def test_snapshot_retry_stays_inside_original_leg_deadline(self):
        failures = self.root / "failures.jsonl"
        failures.write_text("")
        clock, budgets = [0.0], []
        def run(args, **kwargs):
            budgets.append(kwargs["timeout"])
            clock[0] += kwargs["timeout"]
            raise self.snapshot_error()
        def pause(duration):
            clock[0] += duration
        with mock.patch.object(receipt.subprocess, "run", side_effect=run), \
             mock.patch.object(receipt.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(receipt.time, "sleep", side_effect=pause):
            with self.assertRaisesRegex(TimeoutError, "fixed leg deadline expired"):
                receipt.poll_snapshot_witness(lambda query: receipt.neighbor_witness(query, 1, pending=True),
                    "rbgp", "unix:///owned.sock", 31, failures, "held-b")
        self.assertEqual(budgets[0], 30)
        self.assertAlmostEqual(budgets[1], .95)
        self.assertAlmostEqual(clock[0], 31)
        self.assertEqual(receipt.snapshot_failure_counts(failures, 1)["total"], 2)

    def test_source_witness_diagnostic_persists_fatal_row_and_query_bracket(self):
        source = Path(receipt.__file__).read_text()
        begin = source.index("    except BaseException as error:\n", source.index("def run_cell("))
        end = source.index("    finally:\n", begin)
        # Exercise the existing run-cell failure writer, including its bare
        # re-raise, without launching a daemon or changing failure persistence.
        handler = "\n".join(line[4:] for line in source[begin:end].splitlines()) + "\n"
        groups = [(receipt.peer(1), "group:7")]
        for phase in ("initial-source", "held-b", "settled-b-source"):
            for field, value in (("state", "Idle"), ("slow_peer", True), ("outbound_resync_pending", True)):
                with self.subTest(phase=phase, field=field):
                    failures = self.root / "failures.jsonl"
                    failures.write_text("")
                    (self.root / "failure.json").unlink(missing_ok=True)
                    row = self.snapshot_row(receipt.peer(0), False, diagnostic_extra={"raw": [1, "kept"]})
                    row[field] = value
                    clock = [12.5]
                    def run(args, row=row, clock=clock, **kwargs):
                        if args[-1] == receipt.peer(0):
                            clock[0] = 34.75
                            actual = row
                        else:
                            actual = self.snapshot_row(args[-1], True)
                        return subprocess.CompletedProcess(args, 0, json.dumps(actual), "")
                    read = receipt.source_witness if phase != "held-b" else \
                        lambda query, groups=groups: receipt.held_dirty_witness(query, 1, groups, False)
                    def invoke(read=read, phase=phase, failures=failures):
                        try:
                            receipt.poll_snapshot_witness(read, "rbgp", "unix:///owned.sock", 1800, failures, phase)
                        except ValueError as error:
                            if phase == "held-b":
                                # Preserve the held loop's existing fatal
                                # classification and chained exception context.
                                receipt.require(str(error) in ("actual dirty overlap/settlement missing",
                                                               "no common current dirty instant"), str(error))
                            raise
                    with mock.patch.object(receipt.subprocess, "run", side_effect=run) as cli, \
                         mock.patch.object(receipt.time, "monotonic", side_effect=lambda clock=clock: clock[0]), \
                         mock.patch.object(receipt.time, "sleep") as pause:
                        with self.assertRaises(ValueError) as caught:
                            exec("try:\n    invoke()\n" + handler,
                                 {"invoke": invoke, "leg": self.root, "write_json": receipt.write_json,
                                  "traceback": receipt.traceback})
                    self.assertIs(type(caught.exception), ValueError)
                    self.assertEqual(caught.exception.args, ("source session/pending state changed",))
                    self.assertEqual(str(caught.exception), "source session/pending state changed")
                    self.assertEqual(cli.call_count, 3 if phase == "held-b" else 1)
                    pause.assert_not_called()
                    self.assertEqual(failures.read_text(), "")
                    persisted = json.loads((self.root / "failure.json").read_text())
                    self.assertEqual((persisted["type"], persisted["error"]),
                                     ("ValueError", "source session/pending state changed"))
                    notes = [line.removeprefix("rejected source witness: ") for line in persisted["traceback"].splitlines()
                             if line.startswith("rejected source witness: ")]
                    self.assertEqual(len(notes), 1)
                    self.assertEqual(json.loads(notes[0]), {"row": row, "query_begin_monotonic_seconds": 12.5,
                                                          "query_end_monotonic_seconds": 34.75})

    def test_source_witness_diagnostic_keeps_success_path_unchanged(self):
        row = self.snapshot_row(receipt.peer(0), False)
        snapshot = mock.Mock(return_value=(row, 12.5, 34.75))
        self.assertIs(receipt.source_witness(snapshot), row)
        snapshot.assert_called_once_with(receipt.peer(0))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_snapshot_nonmatching_errors_and_malformed_json_are_fatal(self):
        errors = [subprocess.CalledProcessError(code, ["rbgp"], output=stdout, stderr=stderr) for code, stdout, stderr in (
            (1, "", "Error: permission denied: unauthorized\n"),
            (1, "", "Error: transport error\n"),
            (1, "", "Error: deadline exceeded: another query timed out\n"),
            (2, "", self.snapshot_error().stderr),
            (1, "unexpected stdout", self.snapshot_error().stderr),
            (1, "", self.snapshot_error().stderr + "another error\n"),
            (1, "", "Error: unavailable: RIB export-policy transition stalled\n"))]
        errors.append(subprocess.TimeoutExpired(["rbgp"], 30, output=b"partial", stderr=b"timeout stderr"))
        errors.append(FileNotFoundError("missing rbgp"))
        for error in [*errors, None]:
            with self.subTest(error=error):
                failures = self.root / "failures.jsonl"
                failures.write_text("")
                clock = [0.0]
                def run(args, clock=clock, error=error, **kwargs):
                    clock[0] += 1
                    if error is not None:
                        raise error
                    return subprocess.CompletedProcess(args, 0, "{", "malformed stderr\n")
                expected = type(error) if error is not None else json.JSONDecodeError
                with mock.patch.object(receipt.subprocess, "run", side_effect=run) as cli, \
                     mock.patch.object(receipt.time, "monotonic", side_effect=lambda clock=clock: clock[0]), \
                     mock.patch.object(receipt.time, "sleep") as pause:
                    with self.assertRaises(expected):
                        receipt.poll_snapshot_witness(lambda query: receipt.neighbor_witness(query, 1, pending=False),
                            "rbgp", "unix:///owned.sock", 3, failures, "initial")
                self.assertEqual(cli.call_count, 1)
                pause.assert_not_called()
                record = json.loads(failures.read_text())
                self.assertEqual(record["error"], expected.__name__)
                stderr = getattr(error, "stderr", None)
                self.assertEqual(record["stderr"], (stderr.decode() if isinstance(stderr, bytes) else stderr)
                                 if error is not None else "malformed stderr\n")

    def test_snapshot_semantic_errors_and_owned_harness_exit_are_fatal(self):
        for mutation in ("identity", "group", "missing-age", "harness-exit"):
            with self.subTest(mutation=mutation):
                failures = self.root / "failures.jsonl"
                failures.write_text("")
                process = mock.Mock()
                process.poll.return_value = None
                def run(args, mutation=mutation, process=process, **kwargs):
                    if mutation == "harness-exit":
                        process.poll.return_value = 1
                        raise self.snapshot_error()
                    row = self.snapshot_row(args[-1], mutation == "missing-age")
                    if mutation == "identity":
                        row["address"] = receipt.peer(2)
                    elif mutation == "group":
                        row["update_group"] = "group:8"
                    else:
                        del row["outbound_dirty_seconds"]
                    return subprocess.CompletedProcess(args, 0, json.dumps(row), "")
                groups = [(receipt.peer(1), "group:7")]
                read = (lambda query, groups=groups: receipt.held_dirty_witness(query, 1, groups, True)) if mutation == "missing-age" else \
                       (lambda query, groups=groups: receipt.neighbor_witness(query, 1, expected=groups, pending=False))
                expected = {"identity": "identity changed", "group": "group identity", "missing-age": "invalid current dirty episode",
                            "harness-exit": "owned process exited"}[mutation]
                with mock.patch.object(receipt.subprocess, "run", side_effect=run), \
                     mock.patch.object(receipt.time, "monotonic", return_value=0), mock.patch.object(receipt.time, "sleep") as pause:
                    with self.assertRaisesRegex(ValueError, expected):
                        receipt.poll_snapshot_witness(read, "rbgp", "unix:///owned.sock", 1800, failures,
                                                      "held-b" if mutation == "missing-age" else "initial", (process,))
                pause.assert_not_called()

    def test_snapshot_invalid_reply_cannot_be_discarded_by_later_timeout(self):
        mutations = {"group": "group identity changed", "group-clean": "group identity changed",
                     "group-type": "receiver is not grouped", "initial-cohort": "receivers do not share one group",
                     "missing-age": "invalid current dirty episode", "negative-age": "invalid current dirty episode",
                     "boolean-age": "invalid current dirty episode", "string-age": "invalid current dirty episode",
                     "reversed-clock": "invalid dirty query clock", "nan-clock": "invalid dirty query clock",
                     "boolean-clock": "invalid dirty query clock"}
        for mutation, expected in mutations.items():
            with self.subTest(mutation=mutation):
                failures = self.root / "failures.jsonl"
                failures.write_text("")
                clock, calls = [0.0], []
                invalid_call = 2 if mutation == "initial-cohort" else 1
                def run(args, mutation=mutation, clock=clock, calls=calls, invalid_call=invalid_call, **kwargs):
                    calls.append(args[-1])
                    clock[0] = 0.0
                    if len(calls) == invalid_call + 1:
                        raise self.snapshot_error()
                    row = self.snapshot_row(args[-1], mutation != "initial-cohort" and args[-1] != receipt.peer(0))
                    if len(calls) == invalid_call:
                        if mutation in ("group", "group-clean", "initial-cohort"):
                            row["update_group"] = "group:8"
                            if mutation == "group-clean":
                                row["outbound_resync_pending"] = False
                                del row["outbound_dirty_seconds"]
                        elif mutation == "group-type":
                            row["update_group"] = 7
                        elif mutation == "missing-age":
                            del row["outbound_dirty_seconds"]
                        elif mutation.endswith("age"):
                            row["outbound_dirty_seconds"] = {"negative-age": -1, "boolean-age": True, "string-age": "3"}[mutation]
                        else:
                            clock[0] = {"reversed-clock": -1.0, "nan-clock": float("nan"), "boolean-clock": False}[mutation]
                    return subprocess.CompletedProcess(args, 0, json.dumps(row), "")
                groups = [(receipt.peer(index), "group:7") for index in (1, 2, 3)]
                read = (lambda query: receipt.neighbor_witness(query, 3, pending=False)) if mutation == "initial-cohort" else \
                       (lambda query, groups=groups: receipt.held_dirty_witness(query, 3, groups, True))
                with mock.patch.object(receipt.subprocess, "run", side_effect=run), \
                     mock.patch.object(receipt.time, "monotonic", side_effect=lambda clock=clock: clock[0]), \
                     mock.patch.object(receipt.time, "sleep") as pause:
                    with self.assertRaisesRegex(ValueError, expected):
                        receipt.poll_snapshot_witness(read, "rbgp", "unix:///owned.sock", 1800, failures,
                                                      "initial" if mutation == "initial-cohort" else "held-b")
                self.assertEqual(len(calls), invalid_call)
                self.assertEqual(failures.read_text(), "")
                pause.assert_not_called()

    def test_snapshot_clean_and_zero_age_keep_original_overlap_transients(self):
        for pending in (False, True):
            with self.subTest(pending=pending):
                failures = self.root / "failures.jsonl"
                failures.write_text("")
                clock = [0.0]
                def run(args, pending=pending, clock=clock, **kwargs):
                    clock[0] += .1
                    row = self.snapshot_row(args[-1], pending, outbound_dirty_seconds=0)
                    if not pending:
                        del row["outbound_dirty_seconds"]
                    return subprocess.CompletedProcess(args, 0, json.dumps(row), "")
                groups = [(receipt.peer(index), "group:7") for index in (1, 2)]
                with mock.patch.object(receipt.subprocess, "run", side_effect=run) as cli, \
                     mock.patch.object(receipt.time, "monotonic", side_effect=lambda clock=clock: clock[0]), \
                     mock.patch.object(receipt.time, "sleep") as pause:
                    expected = "no common current dirty instant" if pending else "actual dirty overlap/settlement missing"
                    with self.assertRaisesRegex(ValueError, expected):
                        receipt.poll_snapshot_witness(lambda query, groups=groups: receipt.held_dirty_witness(query, 2, groups, True),
                                                      "rbgp", "unix:///owned.sock", 1800, failures, "held-b")
                self.assertEqual(cli.call_count, 4 if pending else 1)
                self.assertEqual(failures.read_text(), "")
                pause.assert_not_called()

    def test_snapshot_failure_replay_reclassifies_raw_attempts_and_counts(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        original = [{"sequence": 1, "phase": "held-b", "peer": receipt.peer(1), "attempt": 1,
                     "error": "CalledProcessError", "returncode": 1, "stdout": "", "stderr": self.snapshot_error().stderr},
                    {"sequence": 2, "phase": "settled-b-source", "peer": receipt.peer(0), "attempt": 1,
                     "error": "CalledProcessError", "returncode": 1, "stdout": "", "stderr": self.snapshot_error().stderr}]
        for mutation in (None, "stderr", "stdout", "status", "kind", "phase", "phase-order", "peer", "attempt", "sequence", "omitted", "counts", "raw-digest"):
            with self.subTest(mutation=mutation):
                leg, row = self.small_leg(manifest)
                records = copy.deepcopy(original)
                counts = {"total": 2, "by_phase": {"held-b": {receipt.peer(1): 1}, "settled-b-source": {receipt.peer(0): 1}}}
                if mutation == "stderr":
                    records[0].update(stderr="Error: permission denied\n", retryable=True)
                elif mutation == "stdout":
                    records[0]["stdout"] = "unexpected output"
                elif mutation == "status":
                    records[0]["returncode"] = 2
                elif mutation == "kind":
                    records[0]["error"] = "TimeoutExpired"
                elif mutation == "phase":
                    records[0]["phase"] = "unknown"
                elif mutation == "phase-order":
                    records[1]["phase"] = "initial-source"
                    counts["by_phase"] = {"held-b": {receipt.peer(1): 1}, "initial-source": {receipt.peer(0): 1}}
                elif mutation == "peer":
                    records[0]["peer"] = receipt.peer(3)
                elif mutation in ("attempt", "sequence"):
                    records[0][mutation] = 2
                elif mutation == "omitted":
                    records.pop()
                elif mutation == "counts":
                    counts["total"] = 3
                path = leg / "ordinary-snapshot-failures.jsonl"
                path.write_text("".join(json.dumps(record) + "\n" for record in records))
                row["snapshot_failure_counts"] = counts
                if mutation != "raw-digest":
                    row["raw_sha256"] = self.raw_hashes(leg)
                if mutation is None:
                    receipt.validate_leg(leg, manifest, row)
                else:
                    with self.assertRaises(ValueError):
                        receipt.validate_leg(leg, manifest, row)

    def test_held_episode_receipt_binds_raw_current_state_and_both_sweeps(self):
        identities = [(receipt.peer(i), "group:7") for i in (1, 2)]

        def row(index, begin):
            return {"peer": receipt.peer(index), "group": "group:7", "pending": True, "dirty_seconds": 3,
                    "query_begin_monotonic_seconds": begin, "query_end_monotonic_seconds": begin + .1,
                    "raw": {"address": receipt.peer(index), "state": "Established", "update_group": "group:7",
                            "outbound_resync_pending": True, "outbound_dirty_seconds": 3}}

        sweeps = [[row(1, 10), row(2, 10.2)], [row(1, 10.5), row(2, 10.7)]]
        witness = {"sweeps": sweeps, "overlap": [receipt.dirty_overlap(rows) for rows in sweeps],
                   "stable_overlap": receipt.dirty_overlap([item for rows in sweeps for item in rows]),
                   "source": {"address": receipt.peer(0), "state": "Established", "outbound_resync_pending": False}}
        operation = {"trigger_monotonic_seconds": 8, "drain_monotonic_seconds": 9, "resume_monotonic_seconds": 12}
        # The conservative interval begins before trigger; its intersection
        # with this operation still supplies a valid common dirty instant.
        receipt.validate_held_witness(witness, identities, False, operation)
        for mutation in ("pending", "raw-age", "source", "overlap", "clock", "epoch-reset", "shifted", "reused-b", "sweep-order"):
            altered = copy.deepcopy(witness)
            bounds = operation
            if mutation == "source":
                altered["source"]["outbound_resync_pending"] = True
            elif mutation == "overlap":
                altered["stable_overlap"]["begin_monotonic_seconds"] += .1
            elif mutation == "raw-age":
                altered["sweeps"][0][0]["raw"]["outbound_dirty_seconds"] = 2
            elif mutation == "clock":
                altered["sweeps"][0][0]["query_begin_monotonic_seconds"] = None
            elif mutation == "pending":
                altered["sweeps"][0][0]["pending"] = False
            elif mutation == "shifted":
                for rows in altered["sweeps"]:
                    for item in rows:
                        item["query_begin_monotonic_seconds"] += 20
                        item["query_end_monotonic_seconds"] += 20
                altered["overlap"] = [receipt.dirty_overlap(rows) for rows in altered["sweeps"]]
                altered["stable_overlap"] = receipt.dirty_overlap([item for rows in altered["sweeps"] for item in rows])
            elif mutation == "reused-b":
                bounds = {"trigger_monotonic_seconds": 18, "drain_monotonic_seconds": 19, "resume_monotonic_seconds": 22}
            elif mutation == "sweep-order":
                altered["sweeps"][0][0]["query_begin_monotonic_seconds"] = 10.4
                altered["sweeps"][0][0]["query_end_monotonic_seconds"] = 10.5
                altered["overlap"][0] = receipt.dirty_overlap(altered["sweeps"][0])
                altered["stable_overlap"] = receipt.dirty_overlap([item for rows in altered["sweeps"] for item in rows])
            else:
                altered["sweeps"][1] = [row(1, 20), row(2, 20.2)]
                altered["overlap"][1] = receipt.dirty_overlap(altered["sweeps"][1])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                receipt.validate_held_witness(altered, identities, False, bounds)

    def test_retained_fixture_files_are_verified_independently_of_top_level_raw_hashes(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        for mutation in ("config.toml", "member.rpol", "generation.list", "missing-roster", "extra-roster"):
            with self.subTest(mutation=mutation):
                leg, row = self.small_leg(manifest)
                receipt.validate_leg(leg, manifest, row)
                if mutation in receipt.FIXTURE_INPUTS:
                    path = leg / "fixture" / mutation
                    path.write_text(path.read_text() + "\nchanged retained input\n")
                    expected = "retained fixture input changed"
                else:
                    path = leg / "fixture.sha256.json"
                    hashes = json.loads(path.read_text())
                    if mutation == "missing-roster":
                        hashes.pop("generation.list")
                    else:
                        hashes["unrelated"] = "a" * 64
                    receipt.write_json(path, hashes)
                    expected = "fixture input roster differs"
                row["raw_sha256"] = self.raw_hashes(leg)
                with self.assertRaisesRegex(ValueError, expected):
                    receipt.validate_leg(leg, manifest, row)

    def test_metric_duplicate_and_nonfinite_refused(self):
        for text in ("metric 1\nmetric 1", "metric NaN", "metric -1"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                receipt.metric(text, "metric")

    def test_cleanup_signals_only_verified_held_child_and_waits(self):
        child = mock.Mock(pid=123, qualification_starttime=77)
        child.poll.return_value = None
        child.wait.side_effect = [subprocess.TimeoutExpired("owned", 15), 0]
        with mock.patch.object(receipt, "child_starttime", return_value=77), mock.patch.object(receipt.os, "killpg") as groups:
            receipt.stop_owned(child)
        child.terminate.assert_called_once_with()
        child.kill.assert_called_once_with()
        self.assertEqual(child.wait.call_count, 2)
        groups.assert_not_called()
        child.reset_mock()
        with mock.patch.object(receipt, "child_starttime", return_value=78):
            with self.assertRaisesRegex(ValueError, "identity changed"):
                receipt.stop_owned(child)
        child.terminate.assert_not_called()
        child.kill.assert_not_called()
        child.pid = -123
        with self.assertRaisesRegex(ValueError, "invalid owned child PID"):
            receipt.stop_owned(child)

    def test_recovery_charge_requires_all_integer_gauges_without_capping_attempted_peak(self):
        valid = ("bgp_update_group_recovery_entries 0\n"
                 "bgp_update_group_recovery_bytes 1024\n"
                 "bgp_update_group_recovery_peak_bytes 600000000\n")
        self.assertEqual(receipt.recovery_charge(valid)["peak_bytes"], 600_000_000)
        for broken in (valid.replace("bgp_update_group_recovery_entries 0\n", ""),
                       valid.replace("bytes 1024", "bytes NaN"),
                       valid.replace("entries 0", "entries 0.5"),
                       valid.replace("bytes 1024", "bytes -1")):
            with self.subTest(broken=broken), self.assertRaises(ValueError):
                receipt.recovery_charge(broken)

    def test_missing_or_failed_driver_cannot_finalize_green(self):
        root, _ = self.manifest()
        self.assertEqual(receipt.finalize(root)["status"], "INVALID")
        (root / "driver.exit").write_text("1\n")
        self.assertEqual(receipt.finalize(root)["status"], "INVALID")
        (root / "driver.exit").write_text("0\n")
        self.assertEqual(receipt.finalize(root)["status"], "INVALID")

    def complete_campaign(self, measured_failure=False, profile="full-vpn", candidate_duration=4, mutate=None):
        root, manifest = self.manifest(correctness=not measured_failure, profile=profile)
        (root / "candidate.sha").write_text(manifest["head"] + "\n")
        source = ("    fn capture_group_admitted_keys_inner(\n"
                  "        let captured = ledger.capture_full_old_with_checkpoint(\n"
                  "            peer, hint, &group.table, true, uc, vpn, checkpoint,\n"
                  "        );\n    }\n"
                  "    pub(in crate::manager) fn prepare_empty_group_recovery_admission() {\n")
        (root / "capture-source.rs").write_text(source)
        (root / "flat-control-source.rs").write_text(source)
        receipt.derive_flat(root / "flat-control-source.rs", root / "derivation.json")
        binaries = root / "bin"
        binaries.mkdir()
        for name in ("rustbgpd-candidate", "rustbgpd-flat", "reloadstall", "rbgp"):
            (binaries / name).write_text(name + "\n")
        (root / "binaries.sha256").write_text("".join(
            f"{receipt.digest(path)}  {path}\n" for path in sorted(binaries.iterdir())))
        # Complete immutable build/source fixture. The fixture's byte strings
        # stand for build outputs; no compiler or daemon runs in these controls.
        for role in ("candidate", "flat", "harness", "rbgp"):
            (root / f"build-{role}.log").write_text(f"successful fixture build: {role}\n")
            (root / f"build-{role}.exit").write_text("0\n")
        (root / "rustc-version.txt").write_text("rustc fixture version\n")
        (root / "cargo-version.txt").write_text("cargo fixture version\n")
        (root / "flat-control.patch").write_text("-true\n+false\n")
        receipt.write_json(root / "binary-validation.json", receipt.verified_binaries(root))
        for name in receipt.OWNED_INPUTS:
            path = root / "frozen-instrumentation" / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((receipt.HERE / name).read_bytes())
        for name in receipt.SUPPORT_INPUTS:
            relative = os.path.normpath("bench/scale/reloadstall/" + name)
            path = root / "frozen-support" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((receipt.HERE / name).read_bytes())
        receipt.seal_build(root)
        seal = json.loads((root / "campaign-build-evidence.json").read_text())
        self.assertEqual(set(seal["files"]), set(self.build_evidence_names()))
        for index, arm in enumerate(manifest["schedule"]):
            leg, row = self.small_leg(manifest)
            if measured_failure:
                self.measured_leg(leg, row, arm, index, candidate_duration, mutate)
            row.update({"arm": arm, "index": index, "source": manifest["head"],
                        "status": "PASS" if measured_failure else "CORRECTNESS_ONLY",
                        "capture_source_sha256": receipt.digest(root / "capture-source.rs"),
                        "binary_sha256": receipt.digest(binaries / f"rustbgpd-{arm}"),
                        "harness_sha256": receipt.digest(binaries / "reloadstall"),
                        "rbgp_sha256": receipt.digest(binaries / "rbgp")})
            receipt.write_json(leg / "result.json", row)
            leg.rename(root / f"leg-{index}-{arm}")
        (root / "driver.exit").write_text("0\n")
        (root / "execution.exit").write_text("0\n")
        if not measured_failure:
            self.assertEqual(receipt.finalize(root)["status"], "CORRECTNESS_ONLY")
        elif candidate_duration == 4:
            self.assertEqual(receipt.analyze(root)["status"], "FAIL")
        return root, manifest

    def measured_leg(self, leg, row, arm, index, candidate_duration=4, mutate=None):
        """Synthetic measured records exercise replay; no clocks are sampled."""
        records = receipt.harness_records(leg / "harness.log")
        records["mass_dirty_ready"][0]["correctness_only"] = False
        probes = [{"sequence": index + 1, "status": 200, "phase": None, "request_deadline_ms": 1000,
                   "elapsed_seconds": .01, "started_monotonic_seconds": float(100 + index),
                   "finished_monotonic_seconds": 100.01 + index} for index in range(20)]
        if mutate is not None:
            mutate(arm, index, probes)
        records["mass_dirty_readiness"] = probes
        records["mass_dirty_exit"][0]["readiness_samples"] = len(probes)
        for index, generation in enumerate(("b", "a")):
            start = 100.5 + index * 10
            duration = candidate_duration if arm == "candidate" else 2
            drain, resume, fold = start + .5, start + 1.5, start + duration
            operation = row["operations"][index]
            operation.update({"trigger_monotonic_seconds": start, "drain_monotonic_seconds": drain,
                "resume_monotonic_seconds": resume, "fold_monotonic_seconds": fold,
                "trigger_to_drain_seconds": .5, "drain_to_resume_seconds": 1,
                "resume_to_observed_fold_seconds": duration - 1.5, "trigger_to_fold_seconds": duration})
            for name in ("resume_to_fold_p50_seconds", "resume_to_fold_max_seconds"):
                operation[name] = duration - 1.5
                records["mass_dirty_complete"][index][name] = duration - 1.5
            records["mass_dirty_sent"][index]["drained_monotonic_seconds"] = drain
            path = leg / f"neighbors-paused-{generation}.json"
            witness = json.loads(path.read_text())
            for sweep_index, rows in enumerate(witness["sweeps"]):
                for peer_index, item in enumerate(rows):
                    begin = drain + .01 * (1 + sweep_index * len(rows) + peer_index)
                    item["query_begin_monotonic_seconds"] = begin
                    item["query_end_monotonic_seconds"] = begin + .001
            witness["overlap"] = [receipt.dirty_overlap(rows) for rows in witness["sweeps"]]
            witness["stable_overlap"] = receipt.dirty_overlap([item for rows in witness["sweeps"] for item in rows])
            receipt.write_json(path, witness)
        for operation, coverage in zip(row["operations"], receipt.readiness_coverage(records, row["operations"], False), strict=True):
            operation["readiness_coverage"] = coverage
        (leg / "harness.log").write_text("".join(prefix + " " + json.dumps(record) + "\n"
            for prefix, values in records.items() for record in values))
        (leg / "memory.csv").write_text("monotonic_ns,peak_bytes\n100,2048\n")
        for name, maximum in (("memory_after", receipt.LIMITS["daemon_bytes"]),
                              ("harness_memory_after", receipt.LIMITS["harness_bytes"])):
            row[name] = {"memory.max": maximum, "memory.peak": 2048, "memory.current": 1024,
                         "memory.swap.max": 0, "memory.swap.peak": 0, "memory.swap.current": 0,
                         "boundary_monotonic_ns": 200, "events": {"oom": 0, "oom_kill": 0, "oom_group_kill": 0}}
        row["raw_sha256"] = self.raw_hashes(leg)

    @staticmethod
    def readiness_probes(values, statuses=()):
        statuses = dict(statuses)
        return [{"sequence": index + 1, "status": statuses.get(index, 200),
                 "phase": "response_validation" if index in statuses else None, "request_deadline_ms": 1000,
                 "elapsed_seconds": value, "started_monotonic_seconds": 100 + index * 1.25,
                 "finished_monotonic_seconds": 100 + index * 1.25 + value} for index, value in enumerate(values)]

    def test_readiness_ceiling_judges_consecutive_slow_one_second_and_non_200(self):
        window = [{"drain_monotonic_seconds": 100, "fold_monotonic_seconds": 1000}]
        cases = (
            ([.01] * 5 + [.26, .3, .251] + [.01] * 5, {}, "3 consecutive /readyz samples over 250 ms"),
            ([.01, .3, .3, .01, .3, .01], {}, None),
            ([.01, .2, 1.001, .01], {}, "over 1 s"),
            ([.01, .01, .02], {1: 503}, "1 non-200 or failed /readyz samples"),
            ([.01, .01, .02], {1: None}, "1 non-200 or failed /readyz samples"),
        )
        for values, statuses, failure in cases:
            with self.subTest(values=values, statuses=statuses):
                summary, failures = receipt.readiness_summary(self.readiness_probes(values, statuses), window)
                self.assertEqual(len(failures), 0 if failure is None else 1, failures)
                if failure is not None:
                    self.assertIn(failure, failures[0])
        summary, failures = receipt.readiness_summary(self.readiness_probes([.01, .3, .3, .01, .3, .01]), window)
        self.assertEqual((failures, summary["over_250ms"], summary["longest_run_over_250ms"], summary["non_200_or_failed"]),
                         ([], 3, 2, 0))
        self.assertEqual({key: round(summary[key], 6) for key in ("p50_ms", "p99_ms", "max_ms")},
                         {"p50_ms": 10, "p99_ms": 300, "max_ms": 300})
        self.assertEqual(summary["post_sent"]["samples"], 6)

    def test_readiness_comparison_bounds_candidate_p99_and_max_against_flat(self):
        flat = [.1] * 100
        cases = (([.1] * 98 + [.151] * 2, "p99"), ([.1] * 98 + [.149] * 2, None),
                 ([.1] * 99 + [.201], "max"), ([.1] * 99 + [.199], None))
        for candidate, failed in cases:
            with self.subTest(candidate=candidate[-1], failed=failed):
                detail, failures = receipt.readiness_comparison({"flat": flat, "candidate": candidate})
                self.assertEqual([failure.split()[3] for failure in failures], [] if failed is None else [failed])
        self.assertEqual({name: {key: round(value, 6) for key, value in values.items()} for name, values in detail.items()},
                         {"p99_ms": {"flat": 100, "candidate": 100, "limit": 150},
                          "max_ms": {"flat": 100, "candidate": 199, "limit": 200}})

    def test_readiness_verdict_fails_ceiling_in_either_arm_and_compares_both_profiles(self):
        def slow_candidate(arm, _index, probes):
            for probe in probes:
                if arm == "candidate":
                    probe["elapsed_seconds"] = .2
                    probe["finished_monotonic_seconds"] = probe["started_monotonic_seconds"] + .2

        def three_slow_flat(arm, index, probes):
            if arm == "flat" and index == 0:
                for probe in probes[5:8]:
                    probe["elapsed_seconds"] = .3
                    probe["finished_monotonic_seconds"] = probe["started_monotonic_seconds"] + .3

        def failed_candidate(arm, index, probes):
            if arm == "candidate" and index == 1:
                probes[3].update(status=503, phase="response_validation")

        cases = (("full-vpn", None, "PASS", "all predeclared bars met"),
                 ("full-vpn", slow_candidate, "FAIL", "candidate post-sent /readyz p99 200.0 ms over 37.5 ms bar"),
                 ("full-uc", None, "PASS", "all predeclared bars met"),
                 ("full-uc", slow_candidate, "FAIL", "candidate post-sent /readyz p99 200.0 ms over 37.5 ms bar"),
                 ("full-vpn", three_slow_flat, "FAIL", "leg-0-flat: 3 consecutive /readyz samples over 250 ms"),
                 ("full-vpn", failed_candidate, "FAIL", "leg-1-candidate: 1 non-200 or failed /readyz samples"))
        for profile, mutate, status, reason in cases:
            with self.subTest(profile=profile, mutate=mutate and mutate.__name__), \
                    tempfile.TemporaryDirectory(prefix="rmd-readiness-") as directory, \
                    mock.patch.object(self, "root", Path(directory)):
                root, _ = self.complete_campaign(measured_failure=True, profile=profile, candidate_duration=2, mutate=mutate)
                (root / "driver.exit").write_text("1\n" if status == "FAIL" else "0\n")
                verdict = receipt.finalize(root)
                self.assertEqual(verdict["status"], status, verdict.get("reason"))
                self.assertIn(reason, verdict["reason"])
                self.assertEqual(set(verdict["readiness"]), {path.name for path in root.glob("leg-*")})
                self.assertEqual(set(verdict["readiness_comparison"]), {"p99_ms", "max_ms"})

    def test_actual_analyze_failure_survives_driver_cleanup_and_finalizer(self):
        root, _ = self.complete_campaign(measured_failure=True)
        expected = receipt.analyze(root)
        self.assertEqual(expected["status"], "FAIL")
        source = Path(__file__).with_name("run-recovery-mass-dirty.sh").read_text()
        handler = source[source.index("finish() {"):source.index('mkdir -p "$output/bin"')]
        ending = source[source.rindex("\ndone\n") + len("\ndone\n"):]
        scratch = self.root / "accepted-failure-scratch"
        (scratch / "candidate").mkdir(parents=True)
        (scratch / "flat").mkdir()
        setup = r'''
set -euo pipefail
output=$TEST_OUTPUT scratch=$TEST_SCRATCH repository=$TEST_REPOSITORY checker=$TEST_CHECKER
active_controller='' active_starttime='' acceptance_status=0
git() { command rmdir -- "${!#}"; }
'''
        completed = subprocess.run(["bash", "-c", setup + handler + ending],
            env=os.environ | {"TEST_OUTPUT": str(root), "TEST_SCRATCH": str(scratch),
                "TEST_REPOSITORY": str(self.root), "TEST_CHECKER": str(receipt.HERE / "recovery_mass_dirty.py")},
            text=True, capture_output=True, timeout=5)
        self.assertEqual(completed.returncode, 1, completed.stderr)
        result = receipt.finalize(root)
        self.assertEqual(result, expected)
        self.assertEqual(json.loads((root / "verdict.json").read_text()), expected)
        finalizer = subprocess.run([sys.executable, str(receipt.HERE / "recovery_mass_dirty.py"), "finalize", str(root)],
                                   text=True, capture_output=True, timeout=5)
        self.assertEqual(finalizer.returncode, 1, finalizer.stderr)
        self.assertEqual(json.loads(finalizer.stdout), expected)
        self.assertEqual((root / "driver.exit").read_text(), "1\n")
        self.assertEqual((root / "execution.exit").read_text(), "0\n")
        self.assertFalse(scratch.exists(), "an acceptance failure must still finish normal cleanup")

    def test_actual_analyzer_or_cleanup_errors_still_invalidate_campaigns(self):
        source = Path(__file__).with_name("run-recovery-mass-dirty.sh").read_text()
        handler = source[source.index("finish() {"):source.index('mkdir -p "$output/bin"')]
        ending = source[source.rindex("\ndone\n") + len("\ndone\n"):]
        setup = r'''
set -euo pipefail
output=$TEST_OUTPUT scratch=$TEST_SCRATCH repository=$TEST_REPOSITORY checker=$TEST_CHECKER
active_controller='' active_starttime='' acceptance_status=0
git() {
    [[ $TEST_CLEANUP_EXIT == 0 ]] || return "$TEST_CLEANUP_EXIT"
    command rmdir -- "${!#}"
}
'''
        for failure in ("analyzer", "cleanup"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix="rmd-verdict-") as directory:
                with mock.patch.object(self, "root", Path(directory)):
                    root, _ = self.complete_campaign(measured_failure=True)
                    if failure == "analyzer":
                        (root / "leg-0-flat/result.json").unlink()
                    scratch = self.root / "failed-scratch"
                    (scratch / "candidate").mkdir(parents=True)
                    (scratch / "flat").mkdir()
                    result = subprocess.run(["bash", "-c", setup + handler + ending],
                        env=os.environ | {"TEST_OUTPUT": str(root), "TEST_SCRATCH": str(scratch),
                            "TEST_REPOSITORY": str(self.root), "TEST_CHECKER": str(receipt.HERE / "recovery_mass_dirty.py"),
                            "TEST_CLEANUP_EXIT": "17" if failure == "cleanup" else "0"},
                        text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 17 if failure == "cleanup" else 1, result.stderr)
                    self.assertEqual((root / "execution.exit").read_text(), "17\n" if failure == "cleanup" else "0\n")
                    verdict = receipt.finalize(root)
                    self.assertEqual(verdict["status"], "INVALID")
                    self.assertEqual(verdict["reason"], "driver failed or was interrupted" if failure == "cleanup" else "missing complete leg 0")
                    self.assertEqual(scratch.exists(), failure == "cleanup")

    def test_completed_execution_marker_prevents_build_resealing(self):
        root, manifest = self.complete_campaign()
        seal = root / "campaign-build-evidence.json"
        seal.unlink()
        (root / "driver.exit").unlink()
        for leg in root.glob("leg-*"):
            leg.rename(self.root / leg.name)
        self.assertEqual((root / "execution.exit").read_text(), "0\n")
        with self.assertRaisesRegex(ValueError, "before the first leg"):
            receipt.seal_build(root)
        self.assertFalse(seal.exists())
        (root / "execution.exit").unlink()
        receipt.seal_build(root)
        receipt.verified_build_evidence(root, manifest)

    def test_terminal_exit_markers_require_execution_success_and_exact_replayed_verdict(self):
        for measured, marker, value in ((False, "execution.exit", None), (False, "execution.exit", "1\n"),
                                         (False, "driver.exit", None),
                                         (False, "driver.exit", "1\n"), (True, "driver.exit", "0\n"),
                                         (True, "driver.exit", "130\n")):
            with self.subTest(measured=measured, marker=marker, value=value), tempfile.TemporaryDirectory(prefix="rmd-markers-") as directory:
                with mock.patch.object(self, "root", Path(directory)):
                    root, _ = self.complete_campaign(measured_failure=measured)
                    (root / "driver.exit").write_text("1\n" if measured else "0\n")
                    self.assertEqual(receipt.finalize(root)["status"], "FAIL" if measured else "CORRECTNESS_ONLY")
                    if value is None:
                        (root / marker).unlink()
                    else:
                        (root / marker).write_text(value)
                    self.assertEqual(receipt.finalize(root)["status"], "INVALID")

    def build_evidence_names(self):
        return ("campaign.json", "campaign.sha256", "candidate.sha", "capture-source.rs",
                "flat-control-source.rs", "flat-control.patch", "derivation.json",
                "rustc-version.txt", "cargo-version.txt", "binaries.sha256", "binary-validation.json",
                *(f"build-{role}.{suffix}" for role in ("candidate", "flat", "harness", "rbgp")
                  for suffix in ("log", "exit")),
                *("frozen-instrumentation/" + name for name in receipt.OWNED_INPUTS),
                "frozen-support/bench/scale/reloadstall/sample-daemon-cgroup.py",
                "frozen-support/bench/scale/provenance.sh", "frozen-support/bench/scale/cgroup-memory.sh",
                "frozen-support/tests/soak/host-lock.sh")

    def test_campaign_build_evidence_cannot_be_removed_or_changed(self):
        for name in (*self.build_evidence_names(), "campaign-build-evidence.json"):
            for change in ("remove", "alter"):
                with self.subTest(name=name, change=change), tempfile.TemporaryDirectory(prefix="rmd-build-") as directory:
                    with mock.patch.object(self, "root", Path(directory)):
                        root, _ = self.complete_campaign()
                        path = root / name
                        if change == "remove":
                            path.unlink()
                        else:
                            path.write_bytes(path.read_bytes() + b"changed\n")
                        self.assertEqual(receipt.finalize(root)["status"], "INVALID")

    def test_campaign_resealed_archives_must_match_manifest_inputs(self):
        for name in self.build_evidence_names():
            if not name.startswith("frozen-"):
                continue
            with self.subTest(name=name), tempfile.TemporaryDirectory(prefix="rmd-archive-") as directory:
                with mock.patch.object(self, "root", Path(directory)):
                    root, _ = self.complete_campaign()
                    path = root / name
                    path.write_bytes(path.read_bytes() + b"changed archived source\n")
                    seal = json.loads((root / "campaign-build-evidence.json").read_text())
                    seal["files"][name] = receipt.digest(path)
                    receipt.write_json(root / "campaign-build-evidence.json", seal)
                    result = receipt.finalize(root)
                    self.assertEqual(result["status"], "INVALID")
                    self.assertIn("archived campaign input changed", result["reason"])

    def test_campaign_build_seal_is_exact_one_time_and_precedes_legs(self):
        root, manifest = self.complete_campaign()
        seal_path = root / "campaign-build-evidence.json"
        original = seal_path.read_bytes()
        with self.assertRaisesRegex(ValueError, "already sealed"):
            receipt.seal_build(root)
        self.assertEqual(seal_path.read_bytes(), original)
        seal_path.unlink()
        with self.assertRaisesRegex(ValueError, "before the first leg"):
            receipt.seal_build(root)
        self.assertFalse(seal_path.exists())
        self.assertEqual(receipt.finalize(root)["status"], "INVALID")
        self.assertFalse(seal_path.exists(), "consumers must not recreate a missing seal")
        args = argparse.Namespace(output=str(root), arm="flat", index=0,
            daemon=str(root / "bin/rustbgpd-flat"), harness=str(root / "bin/reloadstall"), rbgp=str(root / "bin/rbgp"))
        with mock.patch.object(receipt, "generate") as generate, mock.patch.object(receipt.subprocess, "Popen") as launch:
            with self.assertRaises(FileNotFoundError):
                receipt.run_cell(args)
        generate.assert_not_called()
        launch.assert_not_called()
        self.assertFalse(seal_path.exists(), "run-cell must verify, never regenerate build evidence")
        receipt.write_json(seal_path, json.loads(original))
        record = json.loads(original)
        for change in ("omitted", "extra", "wrong-hash", "wrong-head", "wrong-schema"):
            with self.subTest(change=change):
                altered = copy.deepcopy(record)
                if change == "omitted":
                    del altered["files"]["build-candidate.log"]
                elif change == "extra":
                    altered["files"]["controller-0.log"] = "0" * 64
                elif change == "wrong-hash":
                    altered["files"]["build-candidate.log"] = "0" * 64
                else:
                    altered[change.removeprefix("wrong-")] = "changed"
                receipt.write_json(seal_path, altered)
                self.assertEqual(receipt.finalize(root)["status"], "INVALID")
        receipt.write_json(seal_path, record)
        self.assertEqual(receipt.verified_build_evidence(root, manifest), receipt.verified_binaries(root))

    def test_campaign_resealed_evidence_cannot_hide_failed_builds_or_live_archives(self):
        for change in ("failed-build", "binary-proof", "extra-archive", "linked-archive"):
            with self.subTest(change=change), tempfile.TemporaryDirectory(prefix="rmd-seal-") as directory:
                with mock.patch.object(self, "root", Path(directory)):
                    root, _ = self.complete_campaign()
                    if change == "failed-build":
                        name = "build-candidate.exit"
                        (root / name).write_text("17\n")
                    elif change == "binary-proof":
                        name = "binary-validation.json"
                        receipt.write_json(root / name, {})
                    elif change == "extra-archive":
                        name = "frozen-instrumentation/unrecorded.rs"
                        (root / name).write_text("unexpected archived input\n")
                    else:
                        name = "frozen-instrumentation/README.md"
                        (root / name).unlink()
                        (root / name).symlink_to(receipt.HERE / "README.md")
                    seal = json.loads((root / "campaign-build-evidence.json").read_text())
                    seal["files"][name] = receipt.digest(root / name)
                    receipt.write_json(root / "campaign-build-evidence.json", seal)
                    self.assertEqual(receipt.finalize(root)["status"], "INVALID")

    def test_campaign_build_exit_markers_are_actual_command_results(self):
        source = Path(__file__).with_name("run-recovery-mass-dirty.sh").read_text()
        begin = source.index("for role in candidate flat; do", source.index("jobs=${CARGO_BUILD_JOBS"))
        end = source.index('sha256sum "$output"/bin/*', begin)
        self.assertLess(source.index('check-binaries "$output"'), source.index('seal-build "$output"'))
        self.assertLess(source.index('seal-build "$output"'), source.index("mapfile -t schedule"))
        setup = r'''
set -euo pipefail
output=$TEST_OUTPUT scratch=$TEST_SCRATCH jobs=2
cargo() {
    local role binary directory=release
    if [[ $* == *"-p reloadstall"* ]]; then role=harness binary=reloadstall directory=scale
    elif [[ $* == *"--bin rbgp"* ]]; then role=rbgp binary=rbgp
    else role=${PWD##*/} binary=rustbgpd; fi
    printf 'fixture cargo completed %s\n' "$role"
    [[ $TEST_FAIL_ROLE != "$role" ]] || return 17
    mkdir -p "$CARGO_TARGET_DIR/$directory"
    printf '%s\n' "$role" >"$CARGO_TARGET_DIR/$directory/$binary"
}
'''
        for failed in ("none", "candidate", "flat", "harness", "rbgp"):
            with self.subTest(failed=failed), tempfile.TemporaryDirectory(prefix="rmd-exit-") as directory:
                root = Path(directory)
                output, scratch = root / "output", root / "scratch"
                (output / "bin").mkdir(parents=True)
                for role in ("candidate", "flat"):
                    (scratch / role).mkdir(parents=True)
                result = subprocess.run(["bash", "-c", setup + source[begin:end]],
                    env=os.environ | {"TEST_OUTPUT": str(output), "TEST_SCRATCH": str(scratch), "TEST_FAIL_ROLE": failed},
                    text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0 if failed == "none" else 17, result.stderr)
                reached_failure = False
                for role in ("candidate", "flat", "harness", "rbgp"):
                    marker = output / f"build-{role}.exit"
                    if reached_failure:
                        self.assertFalse(marker.exists(), "unexecuted commands cannot claim completion")
                    else:
                        self.assertEqual(marker.read_text(), "17\n" if role == failed else "0\n")
                        self.assertIn(f"fixture cargo completed {role}", (output / f"build-{role}.log").read_text())
                    reached_failure |= role == failed

    def test_actual_driver_cleanup_failures_invalidate_a_complete_campaign(self):
        root, _ = self.complete_campaign()

        source = Path(__file__).with_name("run-recovery-mass-dirty.sh").read_text()
        handler = source[source.index("finish() {"):source.index('mkdir -p "$output/bin"')]
        # Execute the actual EXIT trap with deterministic failures, confined to
        # owned temporary directories. No worktrees, builds or daemons run.
        setup = r'''
set -euo pipefail
output=$TEST_OUTPUT scratch=$TEST_SCRATCH repository=$TEST_REPOSITORY
active_controller='' active_starttime='' acceptance_status=0
if [[ $TEST_MISMATCH == 1 ]]; then active_controller=12345 active_starttime=original; fi
controller_starttime() { printf 'changed\n'; }
kill() { printf 'kill %s\n' "$*" >>"$TEST_CALLS"; }
wait() { printf 'wait %s\n' "$*" >>"$TEST_CALLS"; }
git() {
    local role=${!#} status
    role=${role##*/}
    printf 'git %s\n' "$role" >>"$TEST_CALLS"
    if [[ $role == candidate ]]; then status=$TEST_CANDIDATE; else status=$TEST_FLAT; fi
    if [[ $status != 0 ]]; then return "$status"; fi
    command rmdir -- "$scratch/$role"
}
rm() {
    printf 'rm\n' >>"$TEST_CALLS"
    if [[ $TEST_RM != 0 ]]; then return "$TEST_RM"; fi
    command rm "$@"
}
'''
        for initial, candidate, flat, removal, mismatch in ((0, 17, 0, 0, 0), (0, 0, 18, 0, 0),
                                                           (0, 17, 18, 0, 0), (0, 0, 0, 19, 0),
                                                           (23, 17, 18, 19, 0), (130, 0, 0, 0, 0),
                                                           (143, 0, 0, 0, 0), (0, 0, 0, 0, 0),
                                                           (0, 0, 0, 0, 1), (23, 0, 0, 0, 1)):
            with self.subTest(initial=initial, candidate=candidate, flat=flat, removal=removal, mismatch=mismatch):
                scratch = self.root / f"scratch-{initial}-{candidate}-{flat}-{removal}-{mismatch}"
                (scratch / "candidate").mkdir(parents=True)
                (scratch / "flat").mkdir()
                for name in ("cleanup-error.txt", "scratch-retained.txt", "driver.exit", "execution.exit"):
                    (root / name).unlink(missing_ok=True)
                calls = self.root / "cleanup-calls"
                calls.write_text("")
                completed = subprocess.run(["bash", "-c", setup + handler + '\nexit "$TEST_INITIAL"\n'],
                    env=os.environ | {"TEST_OUTPUT": str(root), "TEST_SCRATCH": str(scratch),
                        "TEST_REPOSITORY": str(self.root), "TEST_CALLS": str(calls),
                        "TEST_INITIAL": str(initial), "TEST_CANDIDATE": str(candidate),
                        "TEST_FLAT": str(flat), "TEST_RM": str(removal), "TEST_MISMATCH": str(mismatch)},
                    text=True, capture_output=True, timeout=5)
                expected = initial or mismatch or candidate or flat or removal
                result = receipt.finalize(root)
                self.assertEqual(result["status"], "INVALID" if expected else "CORRECTNESS_ONLY")
                self.assertEqual(completed.returncode, expected, completed.stderr)
                self.assertEqual((root / "driver.exit").read_text(), f"{expected}\n")
                self.assertEqual((root / "execution.exit").read_text(), f"{expected}\n")
                expected_calls = ["wait 12345"] if mismatch else [] if initial else ["git candidate", "git flat"]
                if not (initial or mismatch or candidate or flat):
                    expected_calls.append("rm")
                self.assertEqual(calls.read_text().splitlines(), expected_calls)
                if mismatch:
                    self.assertEqual((root / "cleanup-error.txt").read_text(), "held controller PID identity changed\n")
                if expected:
                    self.assertTrue(scratch.is_dir())
                    self.assertEqual((root / "scratch-retained.txt").read_text(), f"{scratch}\n")
                    if not initial:
                        errors = (root / "cleanup-error.txt").read_text()
                        self.assertEqual(len(errors.splitlines()), bool(candidate) + bool(flat) + bool(removal) + mismatch)
                    self.assertEqual(result["reason"], "driver failed or was interrupted")
                else:
                    self.assertFalse(scratch.exists())
                    self.assertFalse((root / "scratch-retained.txt").exists())

    def test_actual_broken_fold_is_rejected_even_with_pass_status(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        leg, row = self.small_leg(manifest)
        receipt.validate_leg(leg, manifest, row)
        for mutation in ("missing-withdraw", "dirty-cleared", "group-replaced", "no-readiness", "timing-in-correctness", "retained-proof", "retained-charge", "held-proof-empty", "source-dirty", "missing-churn-drain", "dirty-proof-missing"):
            with self.subTest(mutation=mutation):
                # A failed subtest must not leak mutated raw evidence into the
                # next control, including intentional predicate-removal runs.
                leg, row = self.small_leg(manifest)
                altered = copy.deepcopy(row)
                if mutation == "timing-in-correctness":
                    altered["operations"][0]["trigger_to_fold_seconds"] = 1.0
                else:
                    if mutation == "missing-withdraw":
                        records = (leg / "harness.log").read_text().replace('"withdrawals": 16', '"withdrawals": 15')
                        (leg / "harness.log").write_text(records)
                    elif mutation == "dirty-cleared":
                        path = leg / "daemon-window-b.jsonl"
                        values = path.read_text().replace('"dirty": true', '"dirty": false', 1)
                        path.write_text(values)
                    elif mutation == "group-replaced":
                        values = json.loads((leg / "neighbors-settled-a.json").read_text())
                        values[0]["group"] = "group:8"
                        receipt.write_json(leg / "neighbors-settled-a.json", values)
                    elif mutation == "held-proof-empty":
                        path = leg / "metrics-paused-b.prom"
                        path.write_text(path.read_text().replace(f"recovery_entries {altered['operations'][0]['recovery_paused']['entries']}", "recovery_entries 0"))
                        altered["operations"][0]["recovery_paused"] = {
                            **altered["operations"][0]["recovery_paused"], "entries": 0}
                    elif mutation == "source-dirty":
                        path = leg / "source-settled-a.json"
                        values = json.loads(path.read_text())
                        values["outbound_resync_pending"] = True
                        receipt.write_json(path, values)
                    elif mutation == "missing-churn-drain":
                        path = leg / "harness.log"
                        path.write_text(path.read_text().replace('"writer_drained": true', '"writer_drained": false', 1))
                    elif mutation == "dirty-proof-missing":
                        path = leg / "neighbors-paused-b.json"
                        values = json.loads(path.read_text())
                        values["stable_overlap"]["proved"] = False
                        receipt.write_json(path, values)
                    elif mutation in ("retained-proof", "retained-charge"):
                        path = leg / "metrics-settled-a.prom"
                        field, old, new = ("entries", 0, 1) if mutation == "retained-proof" else ("bytes", 1024, 1025)
                        path.write_text(path.read_text().replace(f"recovery_{field} {old}", f"recovery_{field} {new}"))
                        altered["operations"][1]["recovery_settled"] = {
                            **altered["operations"][1]["recovery_settled"], field: new}
                    else:
                        text = (leg / "harness.log").read_text().replace('"readiness_samples": 1', '"readiness_samples": 0')
                        (leg / "harness.log").write_text(text)
                expected_error = "settled recovery charge did not return to empty baseline" if mutation in ("retained-proof", "retained-charge") else ".*"
                altered["raw_sha256"] = self.raw_hashes(leg)
                with self.assertRaisesRegex(ValueError, expected_error):
                    receipt.validate_leg(leg, manifest, altered)

    def test_fallback_deltas_use_each_churn_baseline(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        for cause in receipt.CAUSES:
            with self.subTest(cause=cause):
                leg, row = self.small_leg(manifest)
                self.set_fallback_chain(leg, row, cause, [0, 0, 7, 7, 7, 7, 7])
                receipt.validate_leg(leg, manifest, row)
                self.assertEqual([operation["fallback_deltas"][cause] for operation in row["operations"]], [7, 0])
                row["operations"][1]["fallback_deltas"][cause] = 7
                with self.assertRaisesRegex(ValueError, "fallback derivation differs"):
                    receipt.validate_leg(leg, manifest, row)

    def test_fallback_counters_cannot_decrease_between_consecutive_snapshots(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        for cause in receipt.CAUSES:
            for edge in range(1, 7):
                with self.subTest(cause=cause, edge=edge):
                    leg, row = self.small_leg(manifest)
                    counts = [0] * 7
                    counts[edge - 1] = 3
                    counts[edge:] = [2] * (7 - edge)
                    self.set_fallback_chain(leg, row, cause, counts)
                    with self.assertRaisesRegex(ValueError, "fallback counter regressed"):
                        receipt.validate_leg(leg, manifest, row)

    def test_cap_pressure_requires_cap_only_on_flat_and_no_fallback_on_either_candidate(self):
        for profile in ("full-uc", "full-vpn"):
            with tempfile.TemporaryDirectory(prefix="rmd-pressure-") as directory, \
                    mock.patch.object(self, "root", Path(directory)):
                _, manifest = self.manifest(correctness=False, cohort="cap-pressure", profile=profile)
                # Two receivers keep the synthetic held charge under the daemon cap.
                self.pressure_arms(dict(manifest, receivers=2), profile)

    def pressure_arms(self, manifest, profile):
        for arm, capped, error in (("flat", True, None), ("flat", False, "never reached cap"),
                                   ("candidate", False, None), ("candidate", True, "refused proof")):
            with self.subTest(profile=profile, arm=arm, capped=capped):
                leg, row = self.small_leg(manifest)
                self.measured_leg(leg, row, arm, 0, 2)
                row["arm"] = arm
                if capped:
                    self.set_fallback_chain(leg, row, "daemon_limit", [0, 0, 7, 7, 7, 9, 9])
                if error is None:
                    receipt.validate_leg(leg, manifest, row)
                else:
                    with self.assertRaisesRegex(ValueError, error):
                        receipt.validate_leg(leg, manifest, row)
                for path in leg.rglob("*"):
                    if path.is_file():
                        path.unlink()

    def test_no_refusal_cannot_hide_fallback_before_churn(self):
        _, manifest = self.manifest()
        leg, row = self.small_leg(manifest)
        self.set_fallback_chain(leg, row, "daemon_limit", [0, 7, 7, 7, 7, 7, 7])
        with self.assertRaisesRegex(ValueError, "no-refusal.*fallback"):
            receipt.validate_leg(leg, manifest, row)

    def test_operation_log_evidence_cannot_be_reused_from_another_generation(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        leg, row = self.small_leg(manifest)
        receipt.validate_leg(leg, manifest, row)
        cursors = row["operations"][1]["daemon_log_bytes"]
        full_log = (leg / "daemon.log").read_bytes()
        replacement = b'{"fields":{"message":"no resync in A"}}\n'
        changed = full_log[:cursors["resume"]] + replacement + full_log[cursors["end"]:]
        cursors["end"] = cursors["resume"] + len(replacement)
        (leg / "daemon.log").write_bytes(changed)
        (leg / "daemon-operation-a.jsonl").write_bytes(changed[cursors["start"]:cursors["end"]])
        for prefix in ("daemon-window", "dirty-receipts"):
            suffix = "jsonl" if prefix == "daemon-window" else "json"
            (leg / f"{prefix}-a.{suffix}").write_bytes((leg / f"{prefix}-b.{suffix}").read_bytes())
        row["raw_sha256"] = self.raw_hashes(leg)
        with self.assertRaisesRegex(ValueError, "post-resume log slice differs"):
            receipt.validate_leg(leg, manifest, row)

    def test_operation_log_byte_cursors_are_required_ordered_and_exact(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        for mutation in ("missing", "missing-end", "bool", "float", "negative", "reversed", "out-of-bounds", "overlap", "shifted", "operation-bytes"):
            with self.subTest(mutation=mutation):
                leg, row = self.small_leg(manifest)
                operation = row["operations"][1]
                cursors = operation["daemon_log_bytes"]
                expected = "daemon log byte cursors"
                if mutation == "missing":
                    del operation["daemon_log_bytes"]
                elif mutation == "missing-end":
                    del cursors["end"]
                elif mutation == "bool":
                    cursors["start"] = True
                elif mutation == "float":
                    cursors["resume"] = float(cursors["resume"])
                elif mutation == "negative":
                    cursors["start"] = -1
                elif mutation == "reversed":
                    cursors["resume"] = cursors["start"] - 1
                elif mutation == "out-of-bounds":
                    cursors["end"] = len((leg / "daemon.log").read_bytes()) + 1
                elif mutation == "overlap":
                    cursors["start"] = row["operations"][0]["daemon_log_bytes"]["start"]
                elif mutation == "shifted":
                    cursors["start"] += 1
                else:
                    (leg / "daemon-operation-a.jsonl").write_bytes(b"different operation\n")
                    expected = "operation log slice differs"
                row["raw_sha256"] = self.raw_hashes(leg)
                with self.assertRaisesRegex(ValueError, expected):
                    receipt.validate_leg(leg, manifest, row)

    def test_raw_evidence_hash_roster_cannot_omit_any_file(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        leg, row = self.small_leg(manifest)
        self.assertIn("daemon.log", row["raw_sha256"])
        (leg / "result.json").write_text("{}\n")
        receipt.validate_leg(leg, manifest, row)
        for omitted in (None, *sorted(row["raw_sha256"])):
            with self.subTest(omitted=omitted):
                leg, row = self.small_leg(manifest)
                if omitted is None:
                    row["raw_sha256"].clear()
                else:
                    del row["raw_sha256"][omitted]
                with self.assertRaisesRegex(ValueError, "raw evidence hash roster differs"):
                    receipt.validate_leg(leg, manifest, row)

    def test_omitted_daemon_digest_cannot_hide_unrelated_log_tampering(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        leg, row = self.small_leg(manifest)
        path = leg / "daemon.log"
        original = path.read_bytes()
        changed = original.replace(b'"startup"', b'"changed"', 1)
        self.assertNotEqual(original, changed)
        self.assertEqual(len(original), len(changed))
        path.write_bytes(changed)
        del row["raw_sha256"]["daemon.log"]
        with self.assertRaisesRegex(ValueError, "raw evidence hash roster differs"):
            receipt.validate_leg(leg, manifest, row)

    def test_complete_hash_roster_does_not_make_consumed_files_optional(self):
        _, manifest = self.manifest(cohort="cap-pressure")
        leg, row = self.small_leg(manifest)
        for name in sorted(row["raw_sha256"]):
            with self.subTest(missing=name):
                leg, row = self.small_leg(manifest)
                (leg / name).unlink()
                row["raw_sha256"] = self.raw_hashes(leg)
                expected = ValueError if name == "config-check.log" else FileNotFoundError
                with self.assertRaises(expected):
                    receipt.validate_leg(leg, manifest, row)

    def raw_hashes(self, leg):
        return {path.name: receipt.digest(path) for path in leg.iterdir() if path.is_file() and path.name != "result.json"}

    def set_fallback_chain(self, leg, row, cause, counts):
        self.assertEqual(len(counts), 7)
        phases = ("initial", "before-b", "paused-b", "settled-b", "before-a", "paused-a", "settled-a")
        metric = f'bgp_update_group_recovery_fallback_total{{cause="{cause}"}}'
        for phase, count in zip(phases, counts, strict=True):
            path = leg / f"metrics-{phase}.prom"
            path.write_text("\n".join(f"{metric} {count}" if line.startswith(metric + " ") else line
                                      for line in path.read_text().splitlines()) + "\n")
        row["fallback_initial"][cause] = counts[0]
        for index, before in enumerate((1, 4)):
            row["operations"][index]["fallback_before"][cause] = counts[before]
            row["operations"][index]["fallback_deltas"][cause] = counts[before + 2] - counts[before]
        row["raw_sha256"] = self.raw_hashes(leg)

    def small_leg(self, manifest):
        leg = self.root / "small-leg"
        leg.mkdir(exist_ok=True)
        row = {"daemon_exit": 0, "harness_exit": 0, "config_check_exit": 0, "raw_sha256": {}, "operations": []}
        (leg / "ordinary-snapshot-failures.jsonl").write_text("")
        row["snapshot_failure_counts"] = {"total": 0, "by_phase": {}}
        charge = {"entries": 0, "bytes": 1024, "peak_bytes": 2048}
        held_charge = {"entries": manifest["receivers"] * sum(manifest["family_keys"]),
                       "bytes": manifest["receivers"] * sum(manifest["family_keys"]) * 32 + 1024}
        held_charge["peak_bytes"] = held_charge["bytes"]
        row["recovery_initial"] = charge
        row["fallback_initial"] = dict.fromkeys(receipt.CAUSES, 0)
        fixture = leg / "fixture"
        fixture.mkdir(exist_ok=True)
        for name in receipt.FIXTURE_INPUTS:
            (fixture / name).write_text(f"original {name}\n")
        receipt.write_json(leg / "fixture.sha256.json", {name: receipt.digest(fixture / name) for name in receipt.FIXTURE_INPUTS})
        (leg / "config-check.log").write_text("strict config validation passed\n")
        stimulus = manifest["wire_stimulus"]
        receivers = manifest["receivers"]
        ready = {"family_keys": manifest["family_keys"], "receivers": receivers,
                 "bitmap_bytes": receivers * sum((count + 63) // 64 * 8 * 3 for count in manifest["family_keys"]),
                 "correctness_only": True, **{key: stimulus[key] for key in
                    ("batch_size", "origin_cardinality", "baseline_eor_messages", "receiver_receive_buffer_bytes")}}
        lines = ["mass_dirty_ready " + json.dumps(ready)]
        peers = [{"peer": receipt.peer(i), "group": "group:7", "pending": False} for i in range(1, receivers + 1)]
        source = {"address": receipt.peer(0), "state": "Established", "outbound_resync_pending": False}
        receipt.write_json(leg / "source-initial.json", source)
        receipt.write_json(leg / "neighbors-initial.json", peers)
        def metrics(charge):
            return ("bgp_update_group_regroups_total 0\n" +
                    "\n".join(f'bgp_update_group_recovery_fallback_total{{cause="{cause}"}} 0' for cause in receipt.CAUSES) + "\n" +
                    "\n".join(f"bgp_update_group_recovery_{key} {value}" for key, value in charge.items()))
        (leg / "metrics-initial.prom").write_text(metrics(charge))
        daemon_log = bytearray(b'{"fields":{"message":"startup"}}\n')
        for generation in ("b", "a"):
            lines.append("mass_dirty_paused " + json.dumps({"generation": generation, "receivers": receivers}))
            lines.append("mass_dirty_sent " + json.dumps({"generation": generation, "family_keys": manifest["family_keys"],
                "announcement_messages": stimulus["origin_cardinality"], "eor_messages": stimulus["origin_cardinality"],
                "origin_cardinality": stimulus["origin_cardinality"], "writer_drained": True, "drained_monotonic_seconds": None}))
            wire = {"generation": generation, "receivers": receivers, "withdrawals": manifest["receivers"] * manifest["withdrawals_per_receiver"], "exact_fold": True,
                    "sessions_continuous": True, "resume_to_fold_p50_seconds": None, "resume_to_fold_max_seconds": None}
            lines.append("mass_dirty_complete " + json.dumps(wire))
            operation = {**wire, "fallback_before": dict.fromkeys(receipt.CAUSES, 0),
                         "fallback_deltas": dict.fromkeys(receipt.CAUSES, 0), "trigger_to_fold_seconds": None,
                         "recovery_paused": held_charge, "recovery_settled": {**charge, "peak_bytes": held_charge["peak_bytes"]},
                         "trigger_to_drain_seconds": None, "drain_to_resume_seconds": None, "resume_to_observed_fold_seconds": None,
                         "trigger_monotonic_seconds": None, "drain_monotonic_seconds": None,
                         "resume_monotonic_seconds": None, "fold_monotonic_seconds": None,
                         "readiness_coverage": {"sample_count": None, "max_start_gap_seconds": None}}
            row["operations"].append(operation)
            dirty = [{"message": "outbound routes resynced", "peer": item["peer"], "dirty": True, "force": False,
                      "generation": generation} for item in peers]
            start = len(daemon_log)
            daemon_log.extend(json.dumps({"fields": {"message": "held π", "generation": generation}}, ensure_ascii=False).encode() + b"\n")
            resume = len(daemon_log)
            window = ("\n".join(json.dumps({"fields": item}) for item in dirty) + "\n").encode()
            daemon_log.extend(window)
            end = len(daemon_log)
            operation["daemon_log_bytes"] = {"start": start, "resume": resume, "end": end}
            (leg / f"daemon-operation-{generation}.jsonl").write_bytes(daemon_log[start:end])
            (leg / f"daemon-window-{generation}.jsonl").write_bytes(window)
            daemon_log.extend(json.dumps({"fields": {"message": "settled", "generation": generation}}).encode() + b"\n")
            receipt.write_json(leg / f"dirty-receipts-{generation}.json", dirty)
            intervals = {"begin_monotonic_seconds": None, "end_monotonic_seconds": None, "proved": True}
            sweep = [{**item, "pending": True, "dirty_seconds": 2, "query_begin_monotonic_seconds": None,
                      "query_end_monotonic_seconds": None,
                      "raw": {"address": item["peer"], "state": "Established", "update_group": item["group"],
                              "outbound_resync_pending": True, "outbound_dirty_seconds": 2}} for item in peers]
            receipt.write_json(leg / f"neighbors-paused-{generation}.json",
                               {"sweeps": [sweep, sweep], "overlap": [intervals, intervals], "stable_overlap": intervals, "source": source})
            receipt.write_json(leg / f"neighbors-settled-{generation}.json", peers)
            receipt.write_json(leg / f"source-settled-{generation}.json", source)
            (leg / f"metrics-before-{generation}.prom").write_text(metrics(charge if generation == "b" else operation["recovery_settled"]))
            (leg / f"metrics-paused-{generation}.prom").write_text(metrics(held_charge))
            (leg / f"metrics-settled-{generation}.prom").write_text(metrics(operation["recovery_settled"]))
        lines.append("mass_dirty_exit " + json.dumps({"readiness_samples": 1, "readiness_interval_ms": 250,
                                                     "readiness_request_deadline_ms": 1000, "status": "PASS"}))
        lines.append("mass_dirty_readiness " + json.dumps({"sequence": 1, "status": 200, "phase": None, "request_deadline_ms": 1000, "elapsed_seconds": None,
                                                          "started_monotonic_seconds": None, "finished_monotonic_seconds": None}))
        (leg / "harness.log").write_text("\n".join(lines) + "\n")
        (leg / "daemon.log").write_bytes(daemon_log)
        row["raw_sha256"] = self.raw_hashes(leg)
        return leg, row

    def test_real_dirty_receipt_target_set_cannot_be_fabricated_from_trigger(self):
        fields = [{"message": "outbound routes resynced", "peer": receipt.peer(i), "dirty": True, "force": False} for i in (1, 2)]
        text = lambda values: "\n".join(json.dumps({"fields": value}) for value in values)
        self.assertEqual(len(receipt.dirty_receipts(text(fields), 2)), 2)
        for bad in (fields[:1], fields + [{**fields[0], "peer": receipt.peer(3)}],
                    [{**fields[0], "dirty": False}, fields[1]], [{**fields[0], "force": True}, fields[1]]):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                receipt.dirty_receipts(text(bad), 2)

    def test_dirty_episode_intersection_rejects_sequential_or_recreated_debt(self):
        def row(peer, begin, end, age):
            return {"peer": peer, "pending": True, "dirty_seconds": age,
                    "query_begin_monotonic_seconds": begin, "query_end_monotonic_seconds": end}
        actual = [row("one", 10.0, 10.1, 2), row("two", 10.5, 10.6, 2)]
        self.assertEqual(receipt.dirty_overlap(actual),
                         {"begin_monotonic_seconds": 8.6, "end_monotonic_seconds": 10.0, "proved": True})
        # Exact touching boundary is a real guaranteed common instant.
        self.assertTrue(receipt.dirty_overlap([row("one", 10, 10, 0), row("two", 11, 11, 1)])["proved"])
        for rows in ([row("one", 10, 10.1, 1), row("two", 12, 12.1, 1)],
                     actual + [row("one", 20, 20.1, 1), row("two", 20.5, 20.6, 1)],
                     [{**actual[0], "pending": False}, actual[1]],
                     [{**actual[0], "dirty_seconds": -1}, actual[1]],
                     [{**actual[0], "dirty_seconds": True}, actual[1]],
                     [row("one", 10, 10.1, 0)],
                     [row("one", float("nan"), 10.1, 1)]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                receipt.dirty_overlap(rows)



if __name__ == "__main__":
    unittest.main()
