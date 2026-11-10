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


# Any input commit id: these fixtures never resolve it.
PIN = "c" * 40


@unittest.skipUnless(os.environ.get("QUALIFICATION_SOURCE"), "supply the explicit pinned QUALIFICATION_SOURCE")
class DependencyChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dependency = Path(os.environ["QUALIFICATION_SOURCE"]).resolve()
        if source.git(cls.dependency, "status", "--porcelain"):
            raise ValueError("tests require the clean pinned qualification input")
        cls.q, cls.r, cls.wire = source.helpers(cls.dependency)
        cls.fixture_wire = importlib.import_module("test_wire")
        data = subprocess.check_output(["git", "-C", str(cls.dependency), "archive", "HEAD"])
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
        for text in ("no match", "anchor anchor"):
            with self.assertRaisesRegex(ValueError, "anchor drift"):
                patches.split_once(text, "anchor")
        self.assertEqual(patches.split_once("before anchor after", "anchor"), ["before ", " after"])

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
            manifest = {"head": "a" * 40, "qualification_head": PIN,
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
                record = terminal.run_cell(output, manifest, self.q, self.r, self.wire, "pressure", "private", 0, True)
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

    def write_wire_fixture(self, leg, eor_split=None, forced=False):
        """No-refusal: refresh replay, its EoR, then churn (the fixed build's
        order). eor_split puts the EoR before part of the replay. Forced: fill,
        replay with the fill, EoR from the tick, then the fill's withdrawal."""
        wire = leg / "wire"
        wire.mkdir()
        final = [0, 0, 0] if forced else [1, 0, 0]
        boundaries = {name: {"boundary": name, "offsets": [], "eors": [], "shifts": shifts}
                      for name, shifts in (("loaded", [0, 0, 0]), ("refresh-start", [0, 0, 0]),
                                            ("settled", final), ("finished", final))}
        for peer in range(3):
            community = 2000 if peer == 1 else 1000
            routes = [self.fixture_wire.announce(kind, origin, index, community)
                      for origin in range(3) if origin != peer
                      for kind, width in ((2, 8), (5, 2)) for index in range(width)]
            inventory = b"".join(routes)
            loaded = inventory + self.fixture_wire.EOR
            churn = b"".join(self.fixture_wire.withdraw(kind, 0, 0)
                             + self.fixture_wire.announce(kind, 0, width, community)
                             for kind, width in ((2, 8), (5, 2))) if peer != 0 else b""
            if forced:
                fill = b"".join(self.fixture_wire.announce(2, 0, index, community) for index in (8, 9)) if peer else b""
                unfill = b"".join(self.fixture_wire.withdraw(2, 0, index) for index in (8, 9)) if peer else b""
                refresh = fill + inventory + fill + self.fixture_wire.EOR + unfill
            elif eor_split is not None:
                refresh = b"".join(routes[:eor_split]) + self.fixture_wire.EOR + b"".join(routes[eor_split:]) + churn
            else:
                refresh = inventory + self.fixture_wire.EOR + churn
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
                    {"command": "pause", "result": {"socket_read_acks": 3}}]
        refresh = {"command": "refresh", "result": {"refreshes": 3, "eor_baseline": [1, 1, 1]}}
        barrier = {"command": "source-barrier", "result": {"input_barrier_generation": 2}}
        resume = {"command": "resume", "result": {"socket_read_acks": 3}}
        if forced:
            controls += [{"command": "terminal-fill 2", "result": {"source": 0, "routes": 2, "total": 2,
                                                                   "write_started_us": 61, "writers_drained_us": 62}},
                         refresh, resume,
                         {"command": "terminal-unfill", "result": {"source": 0, "routes": 2, "messages": 1,
                                                                   "write_started_us": 565, "writers_drained_us": 585}},
                         barrier]
        else:
            controls += [refresh, {"command": "terminal-churn", "result": {"source": 0, "messages": 1, "events": 4,
                                                                           "write_started_us": 180, "writers_drained_us": 199}},
                         barrier, resume]
        controls += [{"command": "settle", "result": boundaries["settled"]},
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
            rows = terminal.wire_receipt(leg, 3, 10, self.wire, self.q)
            self.assertEqual([row["eors"] for row in rows], [2, 2, 2])
            with tempfile.TemporaryDirectory() as forced:
                self.write_wire_fixture(Path(forced), forced=True)
                terminal.wire_receipt(Path(forced), 3, 10, self.wire, self.q)
            original = (leg / "wire/peer-1.bgp").read_bytes()
            for mode in ("raw-mismatch", "eor-before-covered-route", "unknown-withdraw", "missing-coverage", "missing-initial-eor"):
                with self.subTest(mode=mode), tempfile.TemporaryDirectory() as altered:
                    target = Path(altered)
                    self.write_wire_fixture(target, eor_split=19 if mode == "eor-before-covered-route" else None)
                    if mode == "eor-before-covered-route":
                        # The EoR precedes the last route its refresh covers: a bar miss.
                        with self.assertRaisesRegex(self.q.AcceptanceFailure, "EoR reached the wire before a route it covers"):
                            terminal.wire_receipt(target, 3, 10, self.wire, self.q)
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
                        terminal.wire_receipt(target, 3, 10, self.wire, self.q)

    def test_final_raw_consumer_rejects_settlement_reset_and_hidden_headroom_defects(self):
        # Keep this a real consumer test: actual pinned validators, metrics and
        # wire parser consume the retained files, rather than a mirrored stub.
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(terminal.BARS, routes_per_source=10):
            leg = Path(directory)
            self.write_wire_fixture(leg)
            row = {name: 0 for name in ("dirty", "dirty_high_water", "marker_debt", "pending_resets", "retained_recovery", "completion_receipts",
                                        "refresh_pending", "eor_pending", "protocol_obligations", "retained", "peak", "owned_routes", "private_routes")}
            row.update(members=3, owned_groups=2, owned_members=3, peer_budget=self.q.REPORTED_PEER_BUDGET, daemon_budget=268435456,
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
            record = {"shape": "pressure", "arm": "candidate", "settled": row, "applied": applied, "churn": churn,
                      "correctness_only": True, "churn-applied-seconds": None, "convergence-seconds": None,
                      "cell_started_monotonic_ns": 0, "cell_finished_monotonic_ns": 7_000_000_000}
            # 20 Hz readiness from load dispatch through finish completion.
            (leg / "readiness.jsonl").write_text("".join(
                json.dumps({"scheduled": index * .05, "at": index * .05 + .001, "seconds": .01, "status": 200}) + "\n"
                for index in range(123)))
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
            # The fixed build's refresh tail sends each debtor's markers at once.
            for peer in (1, 2):
                sent = feed_fixture("refresh_sent", 95, owed=0, peer=self.q.COMMON.peer(peer))
                sent["markers"]["refresh_attempts"] = 1
                feed.insert(1, sent)
            barriers = [{"peer": self.q.COMMON.peer(peer), "session": "same-session", "wall_us": wall,
                         "pending_batches": 0, "window_open": False, "window_messages": 0,
                         "window_routes": 0, "pending_withdrawals": 0}
                        for peer in range(3) for wall in (10, 390)]
            ss = [{"started_us": sample["started_us"], "ended_us": sample["ended_us"],
                   "raw": f'ESTAB 0 4096 local remote sk:11\n cubic rwnd_limited:{sample["rwnd_limited_us"]}us notsent:4096\n',
                   "rows": [sample]} for sample in samples]
            (leg / "ss.jsonl").write_text("".join(json.dumps(sample) + "\n" for sample in ss))
            before = {"event": "pressure-before", "at": 1.65, "wall_us": 165, "peer": self.q.COMMON.peer(1),
                      "write_id": 55, "cookie": 17, "pending": writes[0], "sample": samples[0]}
            kernel = terminal.check.kernel_pressure(sockets, writes, samples, before["peer"], writes[0]["wall_us"], 520, 165, 400)
            after = {"event": "pressure-after", "at": 5.2, "wall_us": 520, "peer": before["peer"], "kernel": kernel}
            events.insert(9, before)
            events.insert(-2, after)
            events.insert(-2, {"event": "command", "command": "resume", "wall_us": 530, "at": 5.3})
            events += [{"event": "command", "command": "finish", "wall_us": 605, "at": 6.05},
                       {"event": "complete", "command": "finish", "wall_us": 610, "at": 6.1}]
            (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
            record.update(pressure_before=before, pressure_after=after)

            def observer(observed):
                content = "".join("evpn_qualification " + json.dumps(value) + "\n" for value in observed)
                content += "".join("evpn_input_barrier " + json.dumps(value) + "\n" for value in barriers)
                for prefix, values in (("evpn_terminal_feed ", feed), ("evpn_terminal_work ", work),
                                       ("evpn_terminal_socket ", sockets), ("evpn_terminal_write ", writes)):
                    content += "".join(prefix + json.dumps(value) + "\n" for value in values)
                (leg / "observer.log").write_text(content)

            observer([row])
            good = terminal.evidence(leg, record, self.q, self.r, self.wire)
            self.assertEqual(good["work"]["inventory_visits"], 32)
            # A refused refresh-site send means this is not a no-refusal cell.
            refused = copy.deepcopy(feed)
            refused[-1]["markers"].update(refresh_attempts=1, refresh_refused=1)
            feed[:], kept = refused, feed[:]
            observer([row])
            with self.assertRaisesRegex(ValueError, "did not send its markers at the refresh"):
                terminal.evidence(leg, record, self.q, self.r, self.wire)
            feed[:] = kept
            observer([row])
            with self.assertRaises(self.q.AcceptanceFailure):
                terminal.accept_report(good, "candidate", self.q)
            # A shifted readiness file keeps its cadence but misses the raw load clock.
            readiness = (leg / "readiness.jsonl").read_text()
            (leg / "readiness.jsonl").write_text("".join(
                json.dumps({**value, "scheduled": value["scheduled"] + .5, "at": value["at"] + .5}) + "\n"
                for value in map(json.loads, readiness.splitlines())))
            with self.assertRaisesRegex(ValueError, "starts after the workload phase") as failure:
                terminal.evidence(leg, record, self.q, self.r, self.wire)
            self.assertNotIsInstance(failure.exception, self.q.AcceptanceFailure)
            (leg / "readiness.jsonl").write_text(readiness)
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
                            bad["dirty_high_water"] = 1
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

            # Pressure cell: missing required pressure evidence is INVALID.
            (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in original_events))
            observer([row])
            kept_ss = (leg / "ss.jsonl").read_text()
            (leg / "ss.jsonl").write_text(kept_ss.splitlines()[0] + "\n")
            with self.assertRaisesRegex(ValueError, "no real kernel backpressure across churn") as failure:
                terminal.evidence(leg, record, self.q, self.r, self.wire)
            self.assertNotIsInstance(failure.exception, self.q.AcceptanceFailure)
            (leg / "ss.jsonl").write_text(kept_ss)

            # Timed overlap cell on the same raw files: no pressure handshake,
            # churn timed on CLOCK_MONOTONIC from dispatch to the last receipt.
            refresh_us = 9_000_000
            dispatch_us = refresh_us + terminal.BARS["churn_phase_us"] + 500
            overlap_events = [dict(event) for event in original_events
                              if event["event"] not in ("pressure-before", "pressure-after")]
            for event in overlap_events:
                if event["event"] == "command" and event.get("command") == "refresh":
                    event["mono_us"] = refresh_us
                if event["event"] == "command" and event.get("command") == "terminal-churn":
                    event["mono_us"] = dispatch_us
            for index, value in enumerate(barriers):
                value["mono_us"] = 8_000_000 if index % 2 == 0 else dispatch_us + 50_000 + index
            replay_rows = (terminal.BARS["clients"] - 1) * terminal.BARS["routes_per_source"]
            replays = [feed_fixture("data_admitted", 80, rows=replay_rows, peer=self.q.COMMON.peer(peer), mono_us=mono)
                       for peer, mono in enumerate((dispatch_us - 1_000, 9_120_000, 9_210_000))]
            feed[:0] = replays
            overlap = {key: value for key, value in copy.deepcopy(record).items()
                       if key not in ("pressure_before", "pressure_after")}
            overlap.update(shape="overlap", correctness_only=False,
                           **{"churn-applied-seconds": (dispatch_us + 50_000 + 5 - dispatch_us) / 1e6,
                              "convergence-seconds": .5})

            def write_overlap(events_now):
                observer([row])
                (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events_now))

            write_overlap(overlap_events)
            good = terminal.evidence(leg, overlap, self.q, self.r, self.wire)
            self.assertEqual(good["phase"], {"phase_us": terminal.BARS["churn_phase_us"] + 500,
                                             "replays_before_dispatch": 1,
                                             "replay_residue_us": 9_210_000 - dispatch_us})
            self.assertEqual(good["churn_applied_seconds"], overlap["churn-applied-seconds"])
            self.assertNotIn("kernel", good)
            for defect, message in (("late-dispatch", "outside the predeclared phase window"),
                                    ("drained", "after the refresh replays drained"),
                                    ("unstamped-receipt", "missing CLOCK_MONOTONIC stamp"),
                                    ("unstamped-dispatch", "missing CLOCK_MONOTONIC stamp"),
                                    ("wall-metric", "churn duration differs")):
                with self.subTest(overlap=defect):
                    events_now, current = copy.deepcopy(overlap_events), copy.deepcopy(overlap)
                    kept_barriers, kept_feed = copy.deepcopy(barriers), copy.deepcopy(feed)
                    churn_event = next(event for event in events_now if event.get("command") == "terminal-churn"
                                       and event["event"] == "command")
                    if defect == "late-dispatch":
                        churn_event["mono_us"] = refresh_us + terminal.BARS["churn_phase_us"] + 2_001
                        for index, value in enumerate(barriers):
                            if index % 2:
                                value["mono_us"] = refresh_us + 200_000 + index
                        current["churn-applied-seconds"] = (200_005 - terminal.BARS["churn_phase_us"] - 2_001) / 1e6
                    elif defect == "drained":
                        for value in feed[:3]:
                            value["mono_us"] = dispatch_us - 1_000
                    elif defect == "unstamped-receipt":
                        barriers[3].pop("mono_us")
                    elif defect == "unstamped-dispatch":
                        churn_event.pop("mono_us")
                    else:
                        # The poll-observed duration is no longer the metric.
                        current["churn-applied-seconds"] = 4.0 - 1.7
                    write_overlap(events_now)
                    with self.assertRaisesRegex(ValueError, message) as failure:
                        terminal.evidence(leg, current, self.q, self.r, self.wire)
                    self.assertNotIsInstance(failure.exception, self.q.AcceptanceFailure)
                    barriers[:], feed[:] = kept_barriers, kept_feed

    def test_pressure_witness_waits_are_invalid_not_acceptance_misses(self):
        controller = object.__new__(terminal.controller_type(self.r))
        controller.sockets, controller.writes, controller.feed = [], [], []
        controller.kernel = SimpleNamespace(rows=[])
        controller.poll = lambda: None
        with mock.patch.dict(terminal.BARS, debt_witness_seconds=.01):
            with self.assertRaisesRegex(ValueError, "did not establish a live Pending/kernel baseline") as failure:
                controller.before_churn(0)
            self.assertNotIsInstance(failure.exception, self.q.AcceptanceFailure)
            before = {"peer": self.q.COMMON.peer(1), "pending": {"wall_us": 1}, "wall_us": 2, "write_id": 9}
            controller.sockets = [{"peer": before["peer"], "cookie": 17, "send_buffer": 8192, "notsent_lowat": 4096}]
            with self.assertRaisesRegex(ValueError, "did not span actually applied churn") as failure:
                controller.after_applied({"wall_us": 3}, before)
            self.assertNotIsInstance(failure.exception, self.q.AcceptanceFailure)

    def test_derived_receipts_and_feed_carry_the_same_monotonic_clock_in_both_arms(self):
        for arm in ("candidate", "private"):
            with self.subTest(arm=arm):
                files = self.derived(arm)
                main = files["src/main.rs"].decode()
                self.assertIn("rustbgpd_rib::BENCH_MONO_CLOCK.set(bench_mono_us)", main)
                self.assertIn("nix::time::ClockId::CLOCK_MONOTONIC", main)
                self.assertIn("pub static BENCH_MONO_CLOCK", files["crates/rib/src/lib.rs"].decode())
                rib = files["crates/rib/src/manager/mod.rs"].decode()
                self.assertIn('\\"wall_us\\":{},\\"mono_us\\":{},\\"pending_batches\\"', rib)
                self.assertIn("crate::BENCH_MONO_CLOCK.get().map_or(0, |clock| clock()),\n"
                              "                            self.pending_route_batches.len(),", rib)
                self.assertIn("super::terminal_debt::mono_us(),", files["crates/rib/src/manager/evpn_recovery.rs"].decode())
                self.assertIn("pub(super) fn mono_us() -> u64", files["crates/rib/src/manager/terminal_debt.rs"].decode())

    def test_forced_refusal_consumer_measures_refusal_drain_and_tick(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(terminal.BARS, routes_per_source=10):
            leg = Path(directory)
            self.write_wire_fixture(leg, forced=True)
            peer = self.q.COMMON.peer(1)
            row = {name: 0 for name in ("dirty", "dirty_high_water", "marker_debt", "pending_resets", "retained_recovery", "completion_receipts",
                                        "refresh_pending", "eor_pending", "protocol_obligations", "retained", "peak", "owned_routes", "private_routes")}
            row.update(members=3, owned_groups=2, owned_members=3, peer_budget=self.q.REPORTED_PEER_BUDGET, daemon_budget=268435456,
                       peers=[[self.q.COMMON.peer(index), 1 if index == 1 else 0, False, 0, 0, 0, False, False, False, False]
                              for index in range(3)])
            (leg / "readiness.jsonl").write_text("".join(
                json.dumps({"scheduled": index * .05, "at": index * .05 + .001, "seconds": .01, "status": 200}) + "\n"
                for index in range(143)))
            (leg / "metrics.txt").write_text("jemalloc_allocated_bytes 12345\n" + "".join(
                f'bgp_evpn_recovery_provenance_exhausted_total{{cause="{cause}"}} 0\n' for cause in self.q.CAUSES))
            self.q.write_json(leg / "cgroup.json", {"memory.current": 100, "memory.peak": 100, "memory.max": self.q.DAEMON_BYTES,
                                                   "memory.swap.current": 0, "memory.swap.peak": 0, "memory.swap.max": 0,
                                                   "events": {name: "0" for name in ("max", "oom", "oom_kill", "oom_group_kill")}})
            (leg / "ss.jsonl").write_text("")

            def debt(event, at, owed=1, capacity=0, rows=0, root=0, **markers):
                value = feed_fixture(event, at, root=root, rows=rows, peer=peer, owed=owed, capacity=capacity)
                value["markers"].update(markers)
                return value
            refused = dict(refresh_attempts=1, refresh_refused=1)
            filled = debt("data_admitted", 63, owed=0, capacity=1, rows=1)
            full = debt("data_admitted", 95, rows=30)
            refusal = debt("refresh_refused", 96, **refused)
            feed = [debt("sample", 60, owed=0, capacity=4096), debt("data_admitted", 62, owed=0, capacity=2, rows=1), filled,
                    full, refusal, debt("retry_refused", 120, retry_attempts=1, retry_refused=1, **refused),
                    debt("sample", 540, capacity=4096, retry_attempts=1, retry_refused=1, **refused),
                    debt("retry_sent", 545, owed=0, capacity=4095, retry_attempts=2, retry_refused=1, **refused),
                    debt("root_before", 570, owed=0, capacity=4096, root=1, retry_attempts=2, retry_refused=1, **refused)]
            work = {name: 0 for name in terminal.check.COUNTERS}
            work.update(id=1, wall_us=575, group=1, keys=2, debtors_before=0, stage_rows=2, delta_rows=2, elapsed_us=3)
            sockets = [{"peer": self.q.COMMON.peer(index), "cookie": 16 + index, "send_buffer": 8192, "notsent_lowat": 4096,
                        "local": "127.0.0.1:17986", "remote": f"{self.q.COMMON.peer(index)}:{1234 + index}"} for index in range(3)]
            pending = {"event": "pending", "id": 9, "cookie": 17, "started_us": 61, "wall_us": 62}
            barriers = [{"peer": self.q.COMMON.peer(index), "session": "same-session", "wall_us": wall,
                         "pending_batches": 0, "window_open": False, "window_messages": 0,
                         "window_routes": 0, "pending_withdrawals": 0} for index in range(3) for wall in (10, 610)]

            def observer(rows):
                content = "evpn_qualification " + json.dumps(row) + "\n"
                content += "".join("evpn_input_barrier " + json.dumps(value) + "\n" for value in barriers)
                for prefix, values in (("evpn_terminal_feed ", rows), ("evpn_terminal_work ", [work]),
                                       ("evpn_terminal_socket ", sockets), ("evpn_terminal_write ", [pending])):
                    content += "".join(prefix + json.dumps(value) + "\n" for value in values)
                (leg / "observer.log").write_text(content)

            fill = {"event": "fill-complete", "at": .64, "wall_us": 64, "peer": peer, "routes": 2,
                    "capacity": {peer: 1, self.q.COMMON.peer(2): 1}, "pending": pending, "admitted": filled}
            refresh_full = {"event": "refresh-full", "at": .97, "wall_us": 97, "peer": peer, "admitted": full, "refusal": refusal}
            applied = {"event": "input-applied", "generation": 2, "wall_us": 630, "at": 6.3}
            events = [{"event": "command", "command": "load", "wall_us": 0, "at": 0.0},
                      {"event": "complete", "command": "load", "wall_us": 1, "at": .01},
                      {"event": "command", "command": "source-barrier", "wall_us": 2, "at": .02},
                      {"event": "complete", "command": "source-barrier", "wall_us": 8, "at": .08},
                      {"event": "input-applied", "generation": 1, "wall_us": 15, "at": .15},
                      {"event": "command", "command": "terminal-baseline", "wall_us": 20, "at": .2},
                      {"event": "complete", "command": "terminal-baseline", "wall_us": 50, "at": .5}, fill,
                      {"event": "command", "command": "refresh", "wall_us": 70, "at": .7},
                      {"event": "complete", "command": "refresh", "wall_us": 90, "at": .9}, refresh_full,
                      {"event": "command", "command": "resume", "wall_us": 530, "at": 5.3},
                      {"event": "complete", "command": "resume", "wall_us": 550, "at": 5.5},
                      {"event": "command", "command": "terminal-unfill", "wall_us": 560, "at": 5.6},
                      {"event": "complete", "command": "terminal-unfill", "wall_us": 590, "at": 5.9},
                      {"event": "command", "command": "source-barrier", "wall_us": 600, "at": 6.0},
                      {"event": "complete", "command": "source-barrier", "wall_us": 620, "at": 6.2}, applied,
                      {"event": "complete", "command": "settle", "wall_us": 700, "at": 7.0},
                      {"event": "command", "command": "finish", "wall_us": 705, "at": 7.05},
                      {"event": "complete", "command": "finish", "wall_us": 710, "at": 7.1}]
            (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
            record = {"shape": "forced-refusal", "arm": "candidate", "settled": row, "applied": applied, "fill": fill,
                      "refresh_full": refresh_full, "correctness_only": False, "churn-applied-seconds": None,
                      "convergence-seconds": None, "cell_started_monotonic_ns": 0, "cell_finished_monotonic_ns": 8_000_000_000}
            observer(feed)
            good = terminal.evidence(leg, record, self.q, self.r, self.wire)
            self.assertEqual(good["fill"], {"peer": peer, "routes": 2, "capacity": fill["capacity"], "refresh_capacity_after": 0})
            self.assertEqual((good["fallback"]["drain_us"], good["fallback"]["tick_us"], good["fallback"]["sent_event"]),
                             (10, 15, "retry_sent"))
            self.assertEqual(good["work"]["inventory_visits"], 0)
            terminal.accept_report(good, "candidate", self.q)
            for mode, failure in (("no-refusal", "no refused refresh-site"), ("no-drain-clock", "missing drain clock"),
                                  ("free-slot", "last outbound slot"), ("late-tick", "resync tick within 1 s")):
                with self.subTest(mode=mode):
                    rows, current, raw = copy.deepcopy(feed), copy.deepcopy(record), copy.deepcopy(events)
                    if mode == "no-refusal":
                        rows.remove(refusal)
                    elif mode == "no-drain-clock":
                        rows[6]["capacity"] = 4095
                    elif mode == "late-tick":
                        # One microsecond past resume + 1 s + the 10 us drain. The
                        # runner withdraws the fill only after that send, so every
                        # later clock moves with it. Last mode: shifts in place.
                        late = 530 + 1_000_000 + 10 + 1
                        delta = late - rows[7]["wall_us"]

                        def shift(value, delta=delta):
                            if isinstance(value, dict):
                                for key, item in value.items():
                                    if key.endswith("_us") and isinstance(item, int) and item > 545:
                                        value[key] = item + delta
                                    else:
                                        shift(item, delta)
                            elif isinstance(value, list):
                                for item in value:
                                    shift(item, delta)
                        for value in (rows, raw, current, work, barriers):
                            shift(value)
                        rows[7]["wall_us"] = late
                        controls = [json.loads(line.split(" ", 1)[1])
                                    for line in (leg / "driver.log").read_text().splitlines()]
                        prefixes = [line.split(" ", 1)[0] for line in (leg / "driver.log").read_text().splitlines()]
                        shift(controls)
                        (leg / "driver.log").write_text("".join(f"{prefix} {json.dumps(value)}\n"
                                                                for prefix, value in zip(prefixes, controls)))
                    else:
                        rows[3]["capacity"] = 1
                        current["refresh_full"]["admitted"]["capacity"] = 1
                        raw[raw.index(refresh_full)] = current["refresh_full"]
                    observer(rows)
                    (leg / "events.jsonl").write_text("".join(json.dumps(event) + "\n" for event in raw))
                    with self.assertRaisesRegex(ValueError, failure) as raised:
                        terminal.accept_report(terminal.evidence(leg, current, self.q, self.r, self.wire), "candidate", self.q)
                    self.assertEqual(isinstance(raised.exception, self.q.AcceptanceFailure), mode == "late-tick")

    def test_final_summary_reapplies_raw_work_bar_and_rejects_incomplete_pass_or_cleanup(self):
        manifest = {"head": "a" * 40, "qualification_head": PIN, "bars": terminal.BARS}
        for defect, expected in (("positive-work", "FAIL"), ("private-partial-fail", "FAIL"),
                                  ("private-partial-pass", "INVALID"), ("private-cleanup", "INVALID")):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                output, rows = Path(directory), []
                for index, (shape, arm) in enumerate(terminal.BARS["correctness_schedule"]):
                    row = {"status": "PASS", "shape": shape, "arm": arm, "correctness_only": True, "head": manifest["head"],
                           "qualification_head": PIN, "scope": terminal.SCOPE, "production_activation": False,
                           "driver_exit": 0, "settled": {}, "evidence": {"work": {"inventory_visits": 0}},
                           "boot_id": "00000000-0000-0000-0000-000000000001",
                           "daemon_owner": {"pid": 100 + index, "starttime": 1000 + index, "binary_sha256": arm},
                           "cell_started_monotonic_ns": (index * 10 + 1) * 1000000000,
                           "cell_finished_monotonic_ns": (index * 10 + 9) * 1000000000}
                    if index == 1 and defect == "positive-work":
                        row["evidence"]["work"]["inventory_visits"] = 32
                    if index == 0 and defect.startswith("private-"):
                        row.pop("settled")
                        row.pop("evidence")
                        if defect != "private-partial-pass":
                            row.update(status="FAIL", error="retained private acceptance miss")
                        if defect == "private-cleanup":
                            row["cleanup_errors"] = ["daemon: owned child remains"]
                    leg = output / f"terminal-{index:02}-{shape}-{arm}"
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
            manifest = {"head": "a" * 40, "qualification_head": PIN, "bars": terminal.BARS}
            for index, (shape, arm) in enumerate(terminal.BARS["correctness_schedule"]):
                row = {"status": "FAIL" if index == 0 else "PASS", "error": "headroom", "shape": shape, "arm": arm,
                       "correctness_only": True, "head": manifest["head"], "qualification_head": PIN,
                       "scope": terminal.SCOPE, "production_activation": False, "driver_exit": 0, "settled": {}, "evidence": {},
                       "boot_id": "00000000-0000-0000-0000-000000000001",
                       "daemon_owner": {"pid": index + 100, "starttime": index + 1000, "binary_sha256": arm},
                       "cell_started_monotonic_ns": (index * 10 + 1) * 1000000000,
                       "cell_finished_monotonic_ns": (index * 10 + 9) * 1000000000}
                leg = output / f"terminal-{index:02}-{shape}-{arm}"
                leg.mkdir()
                self.q.write_json(leg / "result.json", row)
                (leg / "events.jsonl").write_text(json.dumps({"at": index * 10 + 2}) + "\n")
                rows.append(row)
            outcomes = [self.q.AcceptanceFailure("private headroom"), ValueError("candidate truncated wire"), {}, {}, {}, {}]
            with mock.patch.object(source, "verify_build", return_value={"rustbgpd-private": "private", "rustbgpd-candidate": "candidate"}), \
                 mock.patch.object(terminal, "evidence", side_effect=outcomes) as consumer, \
                 mock.patch.object(terminal, "accept_report"):
                terminal.summarize(output, manifest, rows, self.q, self.r, self.wire, True)
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(consumer.call_count, len(terminal.BARS["correctness_schedule"]))
            self.assertEqual(summary["status"], "INVALID")
            self.assertEqual(len(summary["failures"]), 1)
            self.assertIn("truncated wire", summary["invalid_cells"][0]["error"])

    def test_repeated_physical_pair_cannot_supply_three_samples(self):
        for defect in ("copied-process", "copied-interval", "copied-raw-clocks", "wrong-arm-binary"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                output, rows = Path(directory), []
                manifest = {"head": "a" * 40, "qualification_head": PIN, "bars": terminal.BARS}
                for index, (shape, arm) in enumerate(terminal.BARS["schedule"]):
                    row = {"status": "PASS", "shape": shape, "arm": arm, "correctness_only": False, "head": manifest["head"],
                           "qualification_head": PIN, "scope": terminal.SCOPE, "production_activation": False,
                           "driver_exit": 0, "settled": {}, "evidence": {"work": {"inventory_visits": 0}},
                           "churn-applied-seconds": 1.0, "convergence-seconds": 1.0,
                           "boot_id": "00000000-0000-0000-0000-000000000001",
                           "daemon_owner": {"pid": 100 + index, "starttime": 1000 + index, "binary_sha256": arm},
                           "cell_started_monotonic_ns": (index * 10 + 1) * 1000000000,
                           "cell_finished_monotonic_ns": (index * 10 + 9) * 1000000000}
                    leg = output / f"terminal-{index:02}-{shape}-{arm}"
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

    def test_only_timed_overlap_cells_carry_the_medians(self):
        with tempfile.TemporaryDirectory() as directory:
            output, rows = Path(directory), []
            manifest = {"head": "a" * 40, "qualification_head": PIN, "bars": terminal.BARS}
            for index, (shape, arm) in enumerate(terminal.BARS["schedule"]):
                timed = shape == "overlap"
                row = {"status": "PASS", "shape": shape, "arm": arm, "correctness_only": False, "head": manifest["head"],
                       "qualification_head": PIN, "scope": terminal.SCOPE, "production_activation": False,
                       "driver_exit": 0, "settled": {}, "evidence": {"work": {"inventory_visits": 0}},
                       # Pressure and forced timings are diagnostic: never a median input.
                       "churn-applied-seconds": (1.0 if arm == "private" else 1.02) if timed else None,
                       "convergence-seconds": 1.0 if timed else None,
                       "boot_id": "00000000-0000-0000-0000-000000000001",
                       "daemon_owner": {"pid": 100 + index, "starttime": 1000 + index, "binary_sha256": arm},
                       "cell_started_monotonic_ns": (index * 10 + 1) * 1000000000,
                       "cell_finished_monotonic_ns": (index * 10 + 9) * 1000000000}
                leg = output / f"terminal-{index:02}-{shape}-{arm}"
                leg.mkdir()
                (leg / "events.jsonl").write_text(json.dumps({"at": index * 10 + 2}) + "\n")
                self.q.write_json(leg / "result.json", row)
                rows.append(row)
            self.assertEqual(sum(row["shape"] == "overlap" for row in rows), 10)
            with mock.patch.object(source, "verify_build", return_value={"rustbgpd-private": "private", "rustbgpd-candidate": "candidate"}), \
                 mock.patch.object(terminal, "evidence", side_effect=lambda _leg, row, *_: row["evidence"]):
                self.assertEqual(terminal.summarize(output, manifest, rows, self.q, self.r, self.wire, False), 0)
            summary = json.loads((output / "summary.json").read_text())
            self.assertEqual(summary["medians"]["churn-applied-seconds"],
                             {"candidate": 1.02, "private": 1.0, "pass": True})

    def test_build_verifier_rejects_missing_changed_identical_or_unproven_binaries(self):
        for defect in ("none", "missing-receipt", "changed-binary", "identical-arms", "wrong-toolchain", "failed-build", "wrong-source"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                (output / "bin").mkdir()
                for name in ("rustbgpd-private", "rustbgpd-candidate", "evpn-rr-soak"):
                    (output / "bin" / name).write_bytes(name.encode())
                manifest = {"head": "a" * 40, "qualification_head": PIN, "qualification_sha256": "b" * 64,
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
