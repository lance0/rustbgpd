"""Exercise derivation and the final wire consumer with the explicit pinned input."""

import copy
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import shutil
import tarfile
import tempfile
import unittest
from unittest import mock
from types import SimpleNamespace

import patches
import source
import terminal
from test_check import feed as feed_fixture, fixture as debt_fixture


@unittest.skipUnless(os.environ.get("QUALIFICATION_SOURCE"), "supply the explicit pinned QUALIFICATION_SOURCE")
class DependencyChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dependency = Path(os.environ["QUALIFICATION_SOURCE"]).resolve()
        if source.git(cls.dependency, "rev-parse", "HEAD") != source.PINNED or source.git(cls.dependency, "status", "--porcelain"):
            raise ValueError("tests require the clean pinned qualification input")
        cls.q, cls.r, cls.wire = source.helpers(cls.dependency)
        cls.fixture_wire = importlib.import_module("test_wire")
        data = subprocess.check_output(["git", "-C", str(cls.dependency), "archive", source.PINNED])
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            cls.files = {row.name: archive.extractfile(row).read() for row in archive if row.isfile()}

    def derived(self, arm):
        files = dict(self.files)
        paths = ("src/main.rs", "crates/rib/src/manager/mod.rs")
        result = self.q.derived_texts(*(files[name].decode() for name in paths),
                                    files["bench/scale/evpn-qualification/observer.rs"].decode(), arm,
                                    files["bench/scale/evpn-qualification/input_observer.rs"].decode())
        files.update(zip(paths, (text.encode() for text in result), strict=True))
        return patches.instrument(files, source.HERE)

    def test_private_exports_differ_only_by_the_bench_constructor(self):
        candidate, private = self.derived("candidate"), self.derived("private")
        self.assertEqual({name for name in candidate if candidate[name] != private[name]}, {"src/main.rs"})
        self.assertIn(b".with_bench_evpn_group_ownership()", candidate["src/main.rs"])
        self.assertNotIn(b".with_bench_evpn_group_ownership()", private["src/main.rs"])
        changed = {name for name in candidate if candidate[name] != self.files.get(name)}
        self.assertFalse(any("peer_manager" in name or name.startswith("tests/soak/") for name in changed))
        session = "crates/transport/src/session/mod.rs"
        self.assertEqual(candidate[session], self.files[session])
        self.assertIn(b"const OUTBOUND_BUFFER: usize = 4096;", candidate[session])

    def test_anchor_drift_refuses_derivation(self):
        with self.assertRaisesRegex(ValueError, "anchor drift"):
            patches.once("anchor anchor", "anchor", "replacement")

    def test_actual_run_cell_leaves_capture_directory_creation_to_the_driver(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            daemon = SimpleNamespace(pid=42, poll=lambda: None)
            driver = SimpleNamespace(pid=43, poll=lambda: 17)
            seen = []

            def spawn(command, **kwargs):
                if command[0] == "systemd-run":
                    return daemon
                position = command.index("--qualification-control-dir") + 1
                capture = Path(command[position])
                seen.append(capture.exists())
                self.assertEqual(kwargs["env"]["RUSTBGPD_TERMINAL_RAW_DIR"], str(capture))
                # The pinned real driver exclusively creates this directory
                # before connecting. Mirror that boundary, without a socket.
                capture.mkdir()
                return driver

            def scenario(fixture, *_):
                (fixture / "config.toml").touch()

            def cleanup(_record, _leg, fixture, *_):
                shutil.rmtree(fixture)

            def early_exit(*_):
                raise ValueError("simulated early driver exit")

            controller = SimpleNamespace(ack=early_exit)
            manifest = {"head": "a" * 40, "qualification_head": source.PINNED,
                        "daemon_cpus": source.DAEMON_CPUS, "harness_cpus": source.HARNESS_CPUS}
            identities = {"rustbgpd-private": "private", "evpn-rr-soak": "driver"}
            with mock.patch.object(self.q, "cell_gate"), mock.patch.object(self.r, "scenario", side_effect=scenario), \
                 mock.patch.object(source, "verify_build", return_value=identities), \
                 mock.patch.object(self.q, "digest", side_effect=lambda path: identities[path.name]), \
                 mock.patch.object(self.q, "fetch", return_value=(200, "metrics")), \
                 mock.patch.object(self.q.COMMON, "own_child", side_effect=lambda process: process), \
                 mock.patch.object(self.q.COMMON, "daemon_pid", return_value=42), \
                 mock.patch.object(self.q.COMMON, "process_identity", return_value={"pid": 42}), \
                 mock.patch.object(terminal.subprocess, "run"), mock.patch.object(terminal.subprocess, "Popen", side_effect=spawn), \
                 mock.patch.object(terminal, "controller_type", return_value=lambda *_: controller), \
                 mock.patch.object(self.q, "cleanup_cell", side_effect=cleanup):
                record = terminal.run_cell(output, manifest, self.q, self.r, self.wire, "private", 0, True)
            self.assertEqual(seen, [False], "runner precreated the driver's exclusive capture directory")
            self.assertEqual(record["driver_exit_before_cleanup"], 17)

    def test_full_export_verification_rejects_missing_extra_modified_and_symlink_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "file").write_bytes(b"known")
            (root / "link").symlink_to("file")
            expected = {"file": b"known", "link": ("symlink", "file")}
            source.verify_tree(root, expected)
            for mode in ("missing", "extra", "modified", "symlink"):
                with self.subTest(mode=mode):
                    if mode == "missing":
                        (root / "file").unlink()
                    elif mode == "extra":
                        (root / "extra").touch()
                    elif mode == "modified":
                        (root / "file").write_bytes(b"wrong")
                    else:
                        (root / "link").unlink()
                        (root / "link").symlink_to("wrong")
                    with self.assertRaises(ValueError):
                        source.verify_tree(root, expected)
                    (root / "file").write_bytes(b"known")
                    (root / "extra").unlink(missing_ok=True)
                    (root / "link").unlink()
                    (root / "link").symlink_to("file")

    def write_wire_fixture(self, leg, early=False):
        wire = leg / "wire"
        wire.mkdir()
        boundaries = {name: {"boundary": name, "offsets": [], "eors": [], "shifts": shifts}
                      for name, shifts in (("loaded", [0, 0, 0]), ("refresh-start", [0, 0, 0]),
                                            ("settled", [1, 0, 0]), ("finished", [1, 0, 0]))}
        for peer in range(3):
            community = 2000 if peer == 1 else 1000
            inventory = b"".join(self.fixture_wire.announce(kind, origin, index, community)
                                  for origin in range(3) if origin != peer
                                  for kind, width in ((2, 8), (5, 2)) for index in range(width))
            loaded = inventory + self.fixture_wire.EOR
            churn = b"".join(self.fixture_wire.withdraw(kind, 0, 0)
                             + self.fixture_wire.announce(kind, 0, width, community)
                             for kind, width in ((2, 8), (5, 2))) if peer != 0 else b""
            refresh = inventory + (self.fixture_wire.EOR + churn if early else churn + self.fixture_wire.EOR)
            data = loaded + refresh
            (wire / f"peer-{peer}.bgp").write_bytes(data)
            (wire / f"raw-240.1.0.{peer + 1}.bgp").write_bytes(data)
            for name in boundaries:
                initial = name in ("loaded", "refresh-start")
                boundaries[name]["offsets"].append(len(loaded) if initial else len(data))
                boundaries[name]["eors"].append(1 if initial else 2)
        controls = [{"command": "connected", "clients": 3},
                    {"command": "load", "result": boundaries["loaded"]},
                    {"command": "source-barrier", "result": {"input_barrier_generation": 1}},
                    {"command": "terminal-baseline", "result": {**boundaries["loaded"], "boundary": "baseline"}},
                    {"command": "mark refresh-start", "result": boundaries["refresh-start"]},
                    {"command": "pause", "result": {"socket_read_acks": 3}},
                    {"command": "refresh", "result": {"refreshes": 3, "eor_baseline": [1, 1, 1]}},
                    {"command": "terminal-churn", "result": {"source": 0, "messages": 1, "events": 4,
                                                               "write_started_us": 180, "writers_drained_us": 199}},
                    {"command": "source-barrier", "result": {"input_barrier_generation": 2}},
                    {"command": "resume", "result": {"socket_read_acks": 3}},
                    {"command": "settle", "result": boundaries["settled"]},
                    {"command": "finish", "result": boundaries["finished"]}]
        receiver_rows = [{"peer": self.q.COMMON.peer(peer), "cookie": 116 + peer, "receive_buffer": 8192,
                          "local": f"{self.q.COMMON.peer(peer)}:{1234 + peer}", "remote": "127.0.0.1:17986"} for peer in range(3)]
        content = "".join("evpn_terminal_receiver " + json.dumps(row) + "\n" for row in receiver_rows)
        content += "".join("evpn_control " + json.dumps(row) + "\n" for row in controls)
        (leg / "driver.log").write_text(content)

    def test_final_wire_consumer_checks_actual_bytes_coverage_order_and_strict_withdrawals(self):
        with tempfile.TemporaryDirectory() as directory:
            leg = Path(directory)
            self.write_wire_fixture(leg)
            rows = terminal.wire_receipt(leg, 3, 10, self.wire, "candidate")
            self.assertTrue(all(row["terminal_after_churn"] for row in rows))
            original = (leg / "wire/peer-1.bgp").read_bytes()
            for mode in ("raw-mismatch", "early-eor", "unknown-withdraw", "missing-coverage", "missing-initial-eor"):
                with self.subTest(mode=mode), tempfile.TemporaryDirectory() as altered:
                    target = Path(altered)
                    self.write_wire_fixture(target, early=mode == "early-eor")
                    if mode == "early-eor":
                        result = terminal.wire_receipt(target, 3, 10, self.wire, "candidate")
                        self.assertFalse(all(row["terminal_after_churn"] for row in result))
                        continue
                    if mode == "raw-mismatch":
                        (target / "wire/raw-240.1.0.2.bgp").write_bytes(original[:-1])
                    elif mode == "missing-initial-eor":
                        controls = terminal.check.lines(target / "driver.log", "evpn_control ")
                        for peer in range(3):
                            data = (target / "wire" / f"peer-{peer}.bgp").read_bytes().replace(self.fixture_wire.EOR, b"", 1)
                            (target / "wire" / f"peer-{peer}.bgp").write_bytes(data)
                            (target / "wire" / f"raw-240.1.0.{peer + 1}.bgp").write_bytes(data)
                            for row in controls:
                                if "boundary" in row.get("result", {}):
                                    row["result"]["offsets"][peer] -= len(self.fixture_wire.EOR)
                                    row["result"]["eors"][peer] -= 1
                        (target / "driver.log").write_text("".join("evpn_control " + json.dumps(row) + "\n" for row in controls))
                    else:
                        controls = terminal.check.lines(target / "driver.log", "evpn_control ")
                        initial = next(row["result"]["offsets"][1] for row in controls if row["command"] == "load")
                        if mode == "unknown-withdraw":
                            altered = self.fixture_wire.withdraw(2, 0, 9) + original[initial:]
                        else:
                            # Remove a replayed old key that is subsequently
                            # withdrawn by legitimate churn. The final map is
                            # still correct, so only coverage/order catches it.
                            altered = original[initial:].replace(self.fixture_wire.announce(2, 0, 0, 2000), b"", 1)
                        data = original[:initial] + altered
                        (target / "wire/peer-1.bgp").write_bytes(data)
                        (target / "wire/raw-240.1.0.2.bgp").write_bytes(data)
                        for row in controls:
                            if row["command"] in ("settle", "finish"):
                                row["result"]["offsets"][1] = len(data)
                        (target / "driver.log").write_text("".join("evpn_control " + json.dumps(row) + "\n" for row in controls))
                    with self.assertRaises(ValueError):
                        terminal.wire_receipt(target, 3, 10, self.wire, "candidate")

    def test_final_raw_consumer_rejects_settlement_reset_and_hidden_headroom_defects(self):
        # Keep this a real consumer test: actual pinned validators, metrics and
        # wire parser consume the retained files, rather than a mirrored stub.
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(terminal.BARS, routes_per_source=10):
            leg = Path(directory)
            self.write_wire_fixture(leg)
            row = {name: 0 for name in ("dirty", "marker_debt", "pending_resets", "retained_recovery", "completion_receipts",
                                        "refresh_pending", "eor_pending", "protocol_obligations", "retained", "peak", "owned_routes", "private_routes")}
            row.update(members=3, owned_groups=2, owned_members=3, peer_budget=16777216, daemon_budget=268435456,
                       peers=[[self.q.COMMON.peer(peer), 1 if peer == 1 else 0, False, 0, 0, 0, False, False, False, False]
                              for peer in range(3)])
            controls = terminal.check.lines(leg / "driver.log", "evpn_control ")
            applied = {"event": "input-applied", "generation": 2, "wall_us": 400, "at": 4.0}
            events = [{"event": "command", "command": "load", "wall_us": 0, "at": 0.0},
                      {"event": "complete", "command": "load", "wall_us": 1, "at": .01},
                      {"event": "command", "command": "source-barrier", "wall_us": 2, "at": .02},
                      {"event": "complete", "command": "source-barrier", "wall_us": 8, "at": .08},
                      {"event": "input-applied", "generation": 1, "wall_us": 15, "at": .15},
                      {"event": "command", "command": "terminal-baseline", "wall_us": 20, "at": .2},
                      {"event": "complete", "command": "terminal-baseline", "wall_us": 50, "at": .5},
                      {"event": "command", "command": "refresh", "wall_us": 70, "at": .7},
                      {"event": "complete", "command": "refresh", "wall_us": 90, "at": .9},
                      {"event": "command", "command": "terminal-churn", "wall_us": 170, "at": 1.7},
                      {"event": "complete", "command": "terminal-churn", "wall_us": 320, "at": 3.2},
                      {"event": "command", "command": "source-barrier", "wall_us": 330, "at": 3.3},
                      {"event": "complete", "command": "source-barrier", "wall_us": 380, "at": 3.8}, applied,
                      {"event": "complete", "command": "resume", "wall_us": 550, "at": 5.5},
                      {"event": "complete", "command": "settle", "wall_us": 600, "at": 6.0}]
            churn = next(value["result"] for value in controls if value["command"] == "terminal-churn")
            record = {"arm": "candidate", "settled": row, "applied": applied, "churn": churn,
                      "correctness_only": True, "churn-applied-seconds": None, "convergence-seconds": None}
            (leg / "readiness.jsonl").write_text(json.dumps({"scheduled": 1, "at": 1.001, "seconds": .01, "status": 200}) + "\n")
            metrics = "jemalloc_allocated_bytes 12345\n" + "".join(
                f'bgp_evpn_recovery_provenance_exhausted_total{{cause="{cause}"}} 0\n' for cause in self.q.CAUSES)
            (leg / "metrics.txt").write_text(metrics)
            self.q.write_json(leg / "cgroup.json", {"memory.current": 100, "memory.peak": 100, "memory.max": self.q.DAEMON_BYTES,
                                                   "memory.swap.current": 0, "memory.swap.peak": 0, "memory.swap.max": 0,
                                                   "events": {name: "0" for name in ("max", "oom", "oom_kill", "oom_group_kill")}})
            feed, work, sockets, writes, samples, _, _ = debt_fixture()
            # Use valid, exactly re-parsable raw ss instead of trusting a
            # retained summary's claimed kernel-limited durations.
            for entry in feed:
                entry["peer"] = self.q.COMMON.peer(1)
            sockets = [{"peer": self.q.COMMON.peer(peer), "cookie": 16 + peer, "send_buffer": 8192, "notsent_lowat": 4096,
                        "local": "127.0.0.1:17986", "remote": f"{self.q.COMMON.peer(peer)}:{1234 + peer}"} for peer in range(3)]
            work[0]["group"] = 1
            second = copy.deepcopy(work[0])
            second.update(id=2, group=0)
            work.append(second)
            second_root = copy.deepcopy(feed[1])
            second_root.update(root=2, peer=self.q.COMMON.peer(2), target_group=0, channel=2)
            feed.insert(2, second_root)
            current = feed_fixture("sample", 160)
            current["peer"] = self.q.COMMON.peer(1)
            feed.insert(1, current)
            barriers = [{"peer": self.q.COMMON.peer(peer), "session": "same-session", "wall_us": wall,
                         "pending_batches": 0, "window_open": False, "window_messages": 0,
                         "window_routes": 0, "pending_withdrawals": 0}
                        for peer in range(3) for wall in (10, 390)]
            ss = [{"started_us": sample["started_us"], "ended_us": sample["ended_us"],
                   "raw": f'ESTAB 0 4096 local remote sk:11\n cubic rwnd_limited:{sample["rwnd_limited_us"]}us notsent:4096\n',
                   "rows": [sample]} for sample in samples]
            (leg / "ss.jsonl").write_text("".join(json.dumps(sample) + "\n" for sample in ss))
            before = {"event": "pressure-before", "at": 1.65, "wall_us": 165, "peer": self.q.COMMON.peer(1),
                      "write_id": 55, "cookie": 17, "pending": writes[0], "sample": samples[0], "admitted": feed[0], "current": current}
            debt = terminal.check.debt_receipt([value for value in feed if value["peer"] == before["peer"]], work,
                                               sockets, writes, samples, 400, self.q.COMMON.peer(0))
            after = {"event": "pressure-after", "at": 5.2, "wall_us": 520, "peer": before["peer"], "kernel": debt["kernel"], "debt": debt}
            events.insert(9, before)
            events.insert(-2, after)
            events.insert(-2, {"event": "command", "command": "resume", "wall_us": 530, "at": 5.3})
            (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
            record.update(admitted=feed[0], pressure_before=before, pressure_after=after)

            def observer(observed):
                content = "".join("evpn_qualification " + json.dumps(value) + "\n" for value in observed)
                content += "".join("evpn_input_barrier " + json.dumps(value) + "\n" for value in barriers)
                for prefix, values in (("evpn_terminal_feed ", feed), ("evpn_terminal_work ", work),
                                       ("evpn_terminal_socket ", sockets), ("evpn_terminal_write ", writes)):
                    content += "".join(prefix + json.dumps(value) + "\n" for value in values)
                (leg / "observer.log").write_text(content)

            observer([row])
            good = terminal.evidence(leg, record, self.q, self.r, self.wire)
            self.assertEqual(good["debt"]["work"]["inventory_visits"], 32)
            with self.assertRaises(self.q.AcceptanceFailure):
                terminal.accept_report(good, "candidate", self.q)
            for defect in ("dirty", "marker_debt", "pending_resets", "retained_recovery", "completion_receipts", "refresh_pending", "eor_pending", "protocol_obligations",
                           "peer_limit", "daemon_limit", "allocation_failure", "capture_unavailable", "admission_invariant", "hidden-peer-peak", "hidden-daemon-peak"):
                with self.subTest(defect=defect):
                    bad = copy.deepcopy(row)
                    current_record = copy.deepcopy(record)
                    (leg / "metrics.txt").write_text(metrics)
                    if defect in self.q.CAUSES:
                        (leg / "metrics.txt").write_text(metrics.replace(f'cause="{defect}"}} 0', f'cause="{defect}"}} 1'))
                        observer([row])
                    elif defect.startswith("hidden-"):
                        if defect == "hidden-peer-peak":
                            bad["peers"][0][4] = bad["peer_budget"] * 9 // 10
                            bad["peak"] = bad["peers"][0][4]
                        else:
                            bad["peak"] = bad["daemon_budget"] * 9 // 10
                        bad.update(members=2, owned_members=2, peers=bad["peers"][:2])
                        observer([bad, row])
                    else:
                        bad[defect] = 1
                        if defect == "dirty":
                            bad["peers"][0][2] = True
                        elif defect == "pending_resets":
                            bad["peers"][0][6] = True
                        elif defect == "retained_recovery":
                            bad["peers"][0][7] = True
                        elif defect == "marker_debt":
                            bad["peers"][0][5] = 1
                            bad["protocol_obligations"] = 1
                        elif defect in ("refresh_pending", "eor_pending", "protocol_obligations"):
                            bad["peers"][0][9 if defect == "eor_pending" else 8] = True
                            bad["eor_pending" if defect == "eor_pending" else "refresh_pending"] = 1
                            bad["protocol_obligations"] = 1
                        current_record["settled"] = bad
                        observer([bad])
                    with self.assertRaises(self.q.AcceptanceFailure):
                        terminal.evidence(leg, current_record, self.q, self.r, self.wire)

            observer([row])
            (leg / "metrics.txt").write_text(metrics)
            original_events = copy.deepcopy(events)
            original_barriers = copy.deepcopy(barriers)
            for defect in ("old-input-receipts", "wrong-generation", "copied-applied-result", "copied-convergence", "late-convergence"):
                with self.subTest(raw_provenance=defect):
                    broken_record = copy.deepcopy(record)
                    mutated_events = copy.deepcopy(original_events)
                    original_driver = (leg / "driver.log").read_text()
                    if defect == "old-input-receipts":
                        for index, value in enumerate(barriers):
                            if index % 2:
                                value["wall_us"] = 25
                    elif defect == "wrong-generation":
                        changed = original_driver.replace('"input_barrier_generation": 2', '"input_barrier_generation": 1')
                        self.assertNotEqual(changed, original_driver)
                        (leg / "driver.log").write_text(changed)
                    elif defect == "copied-applied-result":
                        broken_record["applied"]["wall_us"] = 450
                    elif defect == "copied-convergence":
                        broken_record.update(correctness_only=False, **{"churn-applied-seconds": 4.0 - 1.7, "convergence-seconds": .001})
                    else:
                        next(value for value in mutated_events if value.get("command") == "settle")["at"] = 66.0
                    observer([row])
                    (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in mutated_events))
                    with self.assertRaises(ValueError) as failure:
                        terminal.evidence(leg, broken_record, self.q, self.r, self.wire)
                    if defect == "late-convergence":
                        self.assertIsInstance(failure.exception, self.q.AcceptanceFailure)
                    else:
                        self.assertNotIsInstance(failure.exception, self.q.AcceptanceFailure)
                    barriers[:] = copy.deepcopy(original_barriers)
                    (leg / "driver.log").write_text(original_driver)

    def test_final_summary_reapplies_raw_work_bar_and_rejects_incomplete_pass_or_cleanup(self):
        manifest = {"head": "a" * 40, "bars": terminal.BARS}
        for defect, expected in (("positive-work", "FAIL"), ("private-partial-fail", "FAIL"),
                                  ("private-partial-pass", "INVALID"), ("private-cleanup", "INVALID")):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                output, rows = Path(directory), []
                for index, arm in enumerate(("private", "candidate")):
                    row = {"status": "PASS", "arm": arm, "correctness_only": True, "head": manifest["head"],
                           "qualification_head": source.PINNED, "scope": terminal.SCOPE, "production_activation": False,
                           "driver_exit": 0, "settled": {}, "evidence": {"debt": {"work": {"inventory_visits": 0}}},
                           "boot_id": "00000000-0000-0000-0000-000000000001",
                           "daemon_owner": {"pid": 100 + index, "starttime": 1000 + index, "binary_sha256": arm},
                           "cell_started_monotonic_ns": (index * 10 + 1) * 1000000000,
                           "cell_finished_monotonic_ns": (index * 10 + 9) * 1000000000}
                    if arm == "candidate" and defect == "positive-work":
                        row["evidence"]["debt"]["work"]["inventory_visits"] = 32
                    if arm == "private" and defect.startswith("private-"):
                        row.pop("settled")
                        row.pop("evidence")
                        if defect != "private-partial-pass":
                            row.update(status="FAIL", error="retained private acceptance miss")
                        if defect == "private-cleanup":
                            row["cleanup_errors"] = ["daemon: owned child remains"]
                    leg = output / f"terminal-{index:02}-{arm}"
                    leg.mkdir()
                    self.q.write_json(leg / "result.json", row)
                    (leg / "events.jsonl").write_text(json.dumps({"at": index * 10 + 2}) + "\n")
                    rows.append(row)
                # The real raw consumer and its positive work witness are tested
                # above. Isolate the final disposition from stored PASS flags.
                with mock.patch.object(terminal, "evidence", side_effect=lambda _leg, row, *_: row["evidence"]), \
                     mock.patch.object(source, "verify_build", return_value={"rustbgpd-private": "private", "rustbgpd-candidate": "candidate"}):
                    self.assertEqual(terminal.summarize(output, manifest, rows, self.q, self.r, self.wire, True), 1)
                summary = json.loads((output / "summary.json").read_text())
                self.assertEqual(summary["status"], expected)
                self.assertFalse(summary["medians"])
                if defect == "private-partial-fail":
                    self.assertEqual(len(summary["partial_failures_unvalidated"]), 1)

    def test_baseline_acceptance_miss_does_not_hide_later_technical_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            output, rows = Path(directory), []
            manifest = {"head": "a" * 40, "bars": terminal.BARS}
            for index, arm in enumerate(("private", "candidate")):
                row = {"status": "FAIL" if arm == "private" else "PASS", "error": "headroom", "arm": arm,
                       "correctness_only": True, "head": manifest["head"], "qualification_head": source.PINNED,
                       "scope": terminal.SCOPE, "production_activation": False, "driver_exit": 0, "settled": {}, "evidence": {},
                       "boot_id": "00000000-0000-0000-0000-000000000001",
                       "daemon_owner": {"pid": index + 100, "starttime": index + 1000, "binary_sha256": arm},
                       "cell_started_monotonic_ns": (index * 10 + 1) * 1000000000,
                       "cell_finished_monotonic_ns": (index * 10 + 9) * 1000000000}
                leg = output / f"terminal-{index:02}-{arm}"
                leg.mkdir()
                self.q.write_json(leg / "result.json", row)
                (leg / "events.jsonl").write_text(json.dumps({"at": index * 10 + 2}) + "\n")
                rows.append(row)
            with mock.patch.object(source, "verify_build", return_value={"rustbgpd-private": "private", "rustbgpd-candidate": "candidate"}), \
                 mock.patch.object(terminal, "evidence", side_effect=[self.q.AcceptanceFailure("private headroom"), ValueError("candidate truncated wire")]) as consumer:
                terminal.summarize(output, manifest, rows, self.q, self.r, self.wire, True)
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(consumer.call_count, 2)
            self.assertEqual(summary["status"], "INVALID")
            self.assertEqual(len(summary["failures"]), 1)
            self.assertIn("truncated wire", summary["invalid_cells"][0]["error"])

    def test_repeated_physical_pair_cannot_supply_three_samples(self):
        for defect in ("copied-process", "copied-interval", "copied-raw-clocks", "wrong-arm-binary"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                output, rows = Path(directory), []
                manifest = {"head": "a" * 40, "bars": terminal.BARS}
                for index, arm in enumerate(terminal.BARS["schedule"]):
                    row = {"status": "PASS", "arm": arm, "correctness_only": False, "head": manifest["head"],
                           "qualification_head": source.PINNED, "scope": terminal.SCOPE, "production_activation": False,
                           "driver_exit": 0, "settled": {}, "evidence": {"debt": {"work": {"inventory_visits": 0}}},
                           "churn-applied-seconds": 1.0, "convergence-seconds": 1.0,
                           "boot_id": "00000000-0000-0000-0000-000000000001",
                           "daemon_owner": {"pid": 100 + index, "starttime": 1000 + index, "binary_sha256": arm},
                           "cell_started_monotonic_ns": (index * 10 + 1) * 1000000000,
                           "cell_finished_monotonic_ns": (index * 10 + 9) * 1000000000}
                    leg = output / f"terminal-{index:02}-{arm}"
                    leg.mkdir()
                    (leg / "events.jsonl").write_text(json.dumps({"at": index * 10 + 2}) + "\n")
                    if index == 2:
                        if defect == "copied-process":
                            row["daemon_owner"] = copy.deepcopy(rows[0]["daemon_owner"])
                        elif defect == "copied-interval":
                            row["cell_started_monotonic_ns"] = rows[0]["cell_started_monotonic_ns"]
                            row["cell_finished_monotonic_ns"] = rows[0]["cell_finished_monotonic_ns"]
                        elif defect == "copied-raw-clocks":
                            (leg / "events.jsonl").write_text(json.dumps({"at": 2}) + "\n")
                        else:
                            row["daemon_owner"]["binary_sha256"] = "candidate"
                    self.q.write_json(leg / "result.json", row)
                    rows.append(row)
                with mock.patch.object(source, "verify_build", return_value={"rustbgpd-private": "private", "rustbgpd-candidate": "candidate"}), \
                     mock.patch.object(terminal, "evidence", side_effect=lambda _leg, row, *_: row["evidence"]):
                    terminal.summarize(output, manifest, rows, self.q, self.r, self.wire, False)
                self.assertEqual(json.loads((output / "summary.json").read_text())["status"], "INVALID")

    def test_build_verifier_rejects_missing_changed_identical_or_unproven_binaries(self):
        for defect in ("none", "missing-receipt", "changed-binary", "identical-arms", "wrong-toolchain", "failed-build", "wrong-source"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                (output / "bin").mkdir()
                for name in ("rustbgpd-private", "rustbgpd-candidate", "evpn-rr-soak"):
                    (output / "bin" / name).write_bytes(name.encode())
                manifest = {"head": "a" * 40, "qualification_head": source.PINNED, "qualification_sha256": "b" * 64,
                            "terminal_sha256": "c" * 64, "build_toolchain": {"rustc": "rustc 1.99.1", "cargo": "cargo 1.99.1"}}
                receipt = {key: manifest[key] for key in ("head", "qualification_head", "qualification_sha256", "terminal_sha256")}
                receipt.update(toolchain=manifest["build_toolchain"], binaries={path.name: self.q.digest(path) for path in (output / "bin").iterdir()})
                self.q.write_json(output / "toolchain.json", manifest["build_toolchain"])
                for label in ("candidate", "private", "driver"):
                    (output / f"build-{label}.log").write_text("completed canonical separate build\n")
                    (output / f"build-{label}.exit").write_text("0\n")
                if defect == "changed-binary":
                    (output / "bin/rustbgpd-private").write_bytes(b"changed")
                elif defect == "identical-arms":
                    (output / "bin/rustbgpd-private").write_bytes((output / "bin/rustbgpd-candidate").read_bytes())
                    receipt["binaries"]["rustbgpd-private"] = receipt["binaries"]["rustbgpd-candidate"]
                elif defect == "wrong-toolchain":
                    self.q.write_json(output / "toolchain.json", {"rustc": "rustc other", "cargo": "cargo other"})
                elif defect == "failed-build":
                    (output / "build-private.exit").write_text("1\n")
                elif defect == "wrong-source":
                    receipt["head"] = "d" * 40
                if defect != "missing-receipt":
                    self.q.write_json(output / "binaries.json", receipt)
                if defect == "none":
                    self.assertEqual(source.verify_build(output, manifest, self.q), receipt["binaries"])
                else:
                    with self.assertRaises((ValueError, OSError)):
                        source.verify_build(output, manifest, self.q)


if __name__ == "__main__":
    unittest.main()
