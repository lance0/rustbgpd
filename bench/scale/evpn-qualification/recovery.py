#!/usr/bin/env python3
"""Controlled non-RTC actual-daemon recovery and two-policy regroup campaign."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import selectors
import queue
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import threading
import time

import qualify as Q
import wire

SCOPE = ("non-RTC Type 2/5, two pre-existing export groups, all but two peers moving; "
         "initial/clean-regroup per-key wire order, quiescent-refresh coverage before EoR, "
         "recovery final bytes, strict withdrawals and common refresh/EoR obligation overlap; "
         "not terminal-only complete-feed marker debt, repeated-producer cost, full-fleet/new-group "
         "activation, RTC, soak or complete section F qualification")
PHASES = ("loaded", "regroup-b", "regroup-a", "refresh", "recovered")


class MissingWitness(Q.AcceptanceFailure):
    """The bounded observation window ended without the requested state."""


class Readiness:
    """Issue probes at 20 Hz even when an earlier request is still pending."""

    def __init__(self, path, correctness):
        self.path, self.correctness = path, correctness
        self.results, self.stop_event = queue.Queue(), threading.Event()
        self.thread = threading.Thread(target=self.run, name="evpn-ready-probes", daemon=True)
        self.thread.start()

    def probe(self, scheduled):
        started = time.monotonic()
        sample = Q.probe_readiness()
        sample.update(at=started, scheduled=scheduled,
                      seconds=None if self.correctness else time.monotonic() - started)
        return sample

    def run(self):
        pending, scheduled = [], time.monotonic()
        with self.path.open("x") as stream, ThreadPoolExecutor(max_workers=8) as executor:
            while not self.stop_event.is_set() or pending:
                now = time.monotonic()
                if not self.stop_event.is_set() and now >= scheduled:
                    pending.append(executor.submit(self.probe, scheduled))
                    scheduled += .05
                for future in list(pending):
                    if future.done():
                        row = future.result()
                        stream.write(json.dumps(row) + "\n")
                        stream.flush()
                        self.results.put(row)
                        pending.remove(future)
                time.sleep(.005)

    def stop(self):
        self.stop_event.set()
        self.thread.join(timeout=5)
        Q.require(not self.thread.is_alive(), "readiness sampler did not stop")


def roster(row, arm, clients):
    Q.require(row["members"] == clients and len(row["peers"]) == clients
              and {p[0] for p in row["peers"]} == {Q.COMMON.peer(i) for i in range(clients)},
              "observer peer roster differs")
    Q.require(row["peer_budget"] == 16 * 1024 ** 2 and row["daemon_budget"] == 256 * 1024 ** 2,
              "observer budgets differ")
    Q.accept(0 <= row["retained"] <= row["peak"] <= row["daemon_budget"] * .8, "daemon provenance headroom breached")
    for p in row["peers"]:
        Q.require(len(p) == 10 and all(type(p[i]) is bool for i in (2, 6, 7, 8, 9)), "invalid peer witness")
        Q.accept(0 <= p[3] <= p[4] <= row["peer_budget"] * .8 and not p[6], "peer headroom or reset failure")
    Q.accept(row["pending_resets"] == 0, "pending provenance reset")
    Q.require(row["dirty"] == sum(p[2] for p in row["peers"])
              and row["marker_debt"] == sum(p[5] != 0 for p in row["peers"])
              and row["retained_recovery"] == sum(p[7] for p in row["peers"])
              and row["refresh_pending"] == sum(p[8] for p in row["peers"])
              and row["eor_pending"] == sum(p[9] for p in row["peers"])
              and row["protocol_obligations"] == sum(p[5] != 0 or p[8] or p[9] for p in row["peers"]),
              "aggregate observer differs from peer witnesses")
    if arm == "candidate":
        Q.require(row["owned_groups"] == 2 and row["owned_members"] == clients
                  and row["private_routes"] == 0 and all(type(p[1]) is int for p in row["peers"]),
                  "candidate does not own two actual EVPN groups")
    else:
        Q.require(row["owned_groups"] == row["owned_members"] == row["owned_routes"] == 0
                  and all(p[1] is None for p in row["peers"]), "private control owns EVPN")
    return {p[0]: p for p in row["peers"]}


def settled(row):
    return all(row[key] == 0 for key in ("dirty", "marker_debt", "pending_resets", "retained_recovery",
                                        "completion_receipts", "refresh_pending", "eor_pending", "protocol_obligations"))


def dirty_pair(observed, clients):
    return next(((left, right) for left, right in zip(observed, observed[1:])
                 if left["dirty"] == right["dirty"] == clients
                 and right["elapsed_us"] > left["elapsed_us"]), None)


def timings(events):
    def at(event, **fields):
        rows = [row for row in events if row["event"] == event
                and all(row.get(key) == value for key, value in fields.items())]
        Q.require(len(rows) == 1, "missing/duplicate timing boundary")
        return rows[0]["at"]
    values = {f"regroup-{generation}-seconds": at("complete", command=f"policy {generation}")
              - at("reload", generation=generation) for generation in ("a", "b")}
    values["recovery-seconds"] = at("complete", command="settle") - at("complete", command="resume")
    Q.require(all(value >= 0 for value in values.values()), "reversed timing boundaries")
    return values


def input_applied(rows, clients, generation):
    peers = {Q.COMMON.peer(index): [] for index in range(clients)}
    for row in rows:
        Q.require(row["peer"] in peers, "input barrier names an unknown source")
        Q.accept(row["pending_batches"] == row["window_messages"] == row["window_routes"]
                 == row["pending_withdrawals"] == 0 and row["window_open"] is False,
                 "input EoR observed before route work was applied")
        peers[row["peer"]].append(row["session"])
    Q.require(all(len(sessions) <= generation and len(set(sessions)) <= 1 for sessions in peers.values()),
              "duplicate input marker or source session changed")
    return all(len(sessions) == generation for sessions in peers.values())


def protocol_overlap(record, events, controls):
    starts = [row for row in events if row["event"] == "command" and row.get("command") == "churn-overlap"]
    ends = [row for row in events if row["event"] == "complete" and row.get("command") == "churn-overlap"]
    applied = [row for row in events if row["event"] == "input-applied" and row["generation"] == 3]
    Q.require(len(starts) == len(ends) == len(applied) == 1
              and sum(row["event"] == "complete" and row.get("command") == "churn" for row in events)
              == Q.RECOVERY_BARS["max_churn_rounds"],
              "missing fixed churn commands or final applied-input barrier")
    writes = [row["result"] for row in controls if row["command"] == "churn-overlap"]
    Q.require(len(writes) == 1, "missing actual writer-completion interval")
    write = writes[0]
    before, during, after = [record[key] for key in
                            ("protocol_obligation_before_churn", "protocol_obligation_during_churn", "protocol_obligation_after_churn")]
    Q.accept(all(row["protocol_obligations"] > 0 for row in (before, during, after)), "refresh/EoR obligation absent")
    Q.require(before["elapsed_us"] < during["elapsed_us"] < after["elapsed_us"]
              and starts[-1]["wall_us"] <= write["write_started_us"] <= write["writers_drained_us"] <= ends[-1]["wall_us"]
              and before["wall_us"] < write["write_started_us"] <= during["wall_us"] <= write["writers_drained_us"]
              < applied[0]["wall_us"] < after["wall_us"],
              "protocol-obligation observations do not bracket paced churn and applied-input completion")


def group_members(row, arm, clients, generation):
    peers = roster(row, arm, clients)
    if arm == "private":
        return True
    a, b = peers[Q.COMMON.peer(0)][1], peers[Q.COMMON.peer(1)][1]
    Q.require(a != b, "anchor policies coalesced into the same group")
    return all(peers[Q.COMMON.peer(i)][1] == (b if i == 1 or (i >= 2 and generation == "b") else a)
               for i in range(clients))


def scenario(output, source, clients):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GEN_")}
    env.update(GEN_EVPN="1", GEN_IBGP_RR_ASN="64512")
    subprocess.run([sys.executable, str(source / "bench/scale/reloadstall/gen-scenario.py"),
                    str(clients), str(output), "17986"], env=env, check=True, stdout=subprocess.DEVNULL)
    text = (output / "config.toml").read_text().replace("127.0.0.1:9179", "127.0.0.1:19186")
    header, *peers = text.split("[[neighbors]]")
    header += '[policy]\nrpol_files = ["groups.rpol"]\n\n'
    (output / "groups.rpol").write_text("""policy cohort-a {
    term tag { add community 65400:1000; accept }
}
policy cohort-b {
    term tag { add community 65400:2000; accept }
}
""")
    for generation in ("a", "b"):
        parts = [header]
        for index, peer in enumerate(peers):
            cohort = "b" if index == 1 or (index >= 2 and generation == "b") else "a"
            parts.append('[[neighbors]]' + peer.rstrip() + f'\nexport_policy_chain = ["cohort-{cohort}"]\n\n')
        (output / f"config-{generation}.toml").write_text("".join(parts))
    shutil.copyfile(output / "config-a.toml", output / "config.toml")


class Controller:
    def __init__(self, daemon, driver, leg, arm, clients, correctness, ready_limit):
        self.daemon, self.driver, self.leg = daemon, driver, leg
        self.arm, self.clients, self.correctness = arm, clients, correctness
        self.ready_limit = ready_limit
        self.buffer, self.messages = b"", []
        self.selector = selectors.DefaultSelector()
        self.selector.register(driver.stdout, selectors.EVENT_READ)
        self.last_sample, self.samples, self.observations = 0, [], []
        self.raw = (leg / "driver.log").open("xb")
        self.observer_log = (leg / "observer.log").open()
        self.observer_buffer = ""
        self.input_barriers = []
        self.probes = Readiness(leg / "readiness.jsonl", correctness)
        self.last_completion = None

    def event(self, event, **fields):
        at = time.monotonic()
        self.last_event = {"event": event, "at": at, "wall_us": time.time_ns() // 1000, **fields}
        with (self.leg / "events.jsonl").open("a") as stream:
            stream.write(json.dumps(self.last_event) + "\n")
        return at

    def check_probes(self):
        while not self.probes.results.empty():
            sample = self.probes.results.get_nowait()
            self.samples.append(sample)
            Q.accept(sample["status"] == 200, "readiness request failed")
            Q.accept(self.correctness or sample["seconds"] < self.ready_limit,
                     "readiness latency exceeded fixed bar")
            Q.require(sample["at"] - sample["scheduled"] < .05,
                      "readiness sampler missed its 20 Hz schedule")

    def poll(self):
        Q.require(self.daemon.poll() is None, "owned daemon exited")
        Q.require(self.probes.thread.is_alive(), "readiness sampler exited")
        for key, _ in self.selector.select(max(0, min(.05, self.last_sample + .05 - time.monotonic()))):
            chunk = os.read(key.fd, 65536)
            self.raw.write(chunk)
            self.raw.flush()
            self.buffer += chunk
            while b"\n" in self.buffer:
                line, self.buffer = self.buffer.split(b"\n", 1)
                if line.startswith(b"evpn_control "):
                    self.messages.append(json.loads(line.removeprefix(b"evpn_control ")))
                Q.accept(not line.startswith((b"FAIL:", b"evpn_session_lost ")), "driver rejected wire/session state")
        Q.require(self.driver.poll() is None or any(row["command"] == "finish" for row in self.messages),
                  "driver exited before finish acknowledgement")
        now = time.monotonic()
        self.check_probes()
        if now - self.last_sample >= .05:
            self.last_sample = now
            self.observer_buffer += self.observer_log.read()
            lines = self.observer_buffer.split("\n")
            self.observer_buffer = lines.pop()
            observed = [json.loads(line.removeprefix("evpn_qualification ")) for line in lines
                        if line.startswith("evpn_qualification ")]
            self.input_barriers.extend(json.loads(line.removeprefix("evpn_input_barrier ")) for line in lines
                                       if line.startswith("evpn_input_barrier "))
            for row in observed:
                # Initial registration may be incomplete; every full-roster sample is checked.
                if row["members"] == self.clients:
                    roster(row, self.arm, self.clients)
            self.observations.extend(observed)

    def command(self, command, timeout=180):
        self.event("command", command=command)
        self.last_command_start = self.last_event.copy()
        self.driver.stdin.write((command + "\n").encode())
        self.driver.stdin.flush()
        result = self.ack(command, timeout)
        self.last_completion = self.event("complete", command=command)
        self.last_command_complete = self.last_event.copy()
        return result

    def ack(self, command, timeout=180):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            for index, row in enumerate(self.messages):
                if row["command"] == command:
                    return self.messages.pop(index).get("result", row)
            self.poll()
        raise Q.AcceptanceFailure(f"command deadline: {command}")

    def witness(self, predicate, timeout=60, after=None):
        start = len(self.observations) if after is None else after
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.poll()
            for row in self.observations[start:]:
                if row["members"] == self.clients and predicate(row):
                    return row
        raise MissingWitness("required actual daemon witness did not occur")

    def source_barrier(self):
        result = self.command("source-barrier")
        generation = result["input_barrier_generation"]
        end = time.monotonic() + 60
        while time.monotonic() < end:
            self.poll()
            if input_applied(self.input_barriers, self.clients, generation):
                self.event("input-applied", generation=generation, receipts=len(self.input_barriers))
                return self.last_event.copy()
        raise MissingWitness("not every source EoR reached the actor after its route burst")

    def close(self):
        self.probes.stop()
        self.selector.close()
        self.raw.close()
        self.observer_log.close()


def check_wire(leg, clients, routes):
    controls = [json.loads(line.removeprefix("evpn_control ")) for line in
                (leg / "driver.log").read_text().splitlines() if line.startswith("evpn_control ")]
    connected = [row for row in controls if row["command"] == "connected"]
    Q.require(len(connected) == 1 and connected[0]["clients"] == clients
              and sum(row["command"] == "finish" for row in controls) == 1,
              "missing connected roster or final driver acknowledgement")
    boundaries = {row["result"]["boundary"]: row["result"] for row in controls
                  if "result" in row and "boundary" in row["result"]}
    Q.require(all(name in boundaries for name in (*PHASES, "refresh-start")), "missing required wire phase")
    Q.require(all(sum(row.get("result", {}).get("boundary") == name for row in controls) == 1
                  for name in (*PHASES, "refresh-start")), "duplicate required wire phase")
    refreshes = [row["result"] for row in controls if row["command"] == "refresh"]
    Q.require(len(refreshes) == 2, "missing quiescent or paused refresh")
    report = {name: [] for name in PHASES}
    for peer in range(clients):
        receiver = wire.Receiver(peer, clients, routes * 4 // 5, routes // 5)
        path = leg / "wire" / f"peer-{peer}.bgp"
        cursor = 0
        with path.open("rb") as stream:
            for name in (*PHASES[:3], "refresh-start", *PHASES[3:]):
                boundary = boundaries[name]
                end = boundary["offsets"][peer]
                Q.require(type(end) is int and cursor <= end <= path.stat().st_size, "invalid capture boundary")
                data = stream.read(end - cursor)
                cursor = end
                communities = {1000, 2000} if name in ("regroup-b", "regroup-a") and peer >= 2 else {
                    2000 if peer == 1 else 1000}
                transition = name in ("regroup-b", "regroup-a") and peer >= 2
                if transition:
                    receiver.begin_policy(*((1000, 2000) if name == "regroup-b" else (2000, 1000)))
                receiver.consume(data, communities)
                Q.require(receiver.eors == boundary["eors"][peer], "driver EoR count differs from raw wire")
                if name == "refresh-start":
                    receiver.begin_replay()
                    receiver.events.clear()
                    continue
                if name == "refresh":
                    receiver.end_replay()
                if name == "recovered":
                    Q.accept(receiver.eors > refreshes[1]["eor_baseline"][peer],
                             "recovery finished before receiver refresh EoR")
                community = 2000 if peer == 1 or (peer >= 2 and name == "regroup-b") else 1000
                state = receiver.boundary(boundary["shifts"], routes * 4 // 5, routes // 5, community)
                if transition:
                    receiver.end_policy()
                ordered = receiver.ordered_digest()
                report[name].append({"peer": peer, "state": state,
                                     "ordered": ordered if name in PHASES[:3] else None,
                                     "eors": receiver.eors})
        Q.require(cursor == path.stat().st_size, "unvalidated trailing receiver bytes")
    return report


def run_cell(output, manifest, arm, index, correctness):
    # The small peer roster still needs enough packed UPDATEs to fill the real
    # 4,096-message writer queue within 32 rounds; 1,000 routes did not.
    clients, routes = (3, 10_000) if correctness else (150, 250)
    bars = manifest["recovery"]
    leg = output / f"recovery-{index:02}-{arm}"
    leg.mkdir()
    fixture = Path(tempfile.mkdtemp(prefix="evpn-r-"))
    daemon = driver = controller = None
    record = {"status": "INVALID", "arm": arm, "clients": clients, "routes": routes,
              "correctness_only": correctness, "scope": SCOPE, "terminal_only_qualified": False}
    try:
        Q.cell_gate(output, manifest, leg, correctness)
        scenario(fixture, output / "sources/candidate", clients)
        identities = json.loads((output / "binaries.json").read_text())
        binary, harness = output / "bin" / f"rustbgpd-{arm}", output / "bin/evpn-rr-soak"
        for path in (binary, harness):
            Q.require(Q.digest(path) == identities[path.name], "binary changed after build")
        with (leg / "daemon.log").open("x") as log, (leg / "observer.log").open("x") as observer:
            subprocess.run(["taskset", "-c", manifest["daemon_cpus"], str(binary), "--check", "--strict",
                            str(fixture / "config.toml")], stdout=log, stderr=subprocess.STDOUT, check=True)
            if not correctness:
                Q.require_timing_window(manifest)
            record["started_at"] = Q.datetime.now(Q.timezone.utc).isoformat()
            daemon = Q.COMMON.own_child(subprocess.Popen([
                "systemd-run", "--user", "--scope", "--quiet", "-p", f"MemoryMax={Q.DAEMON_BYTES}",
                "-p", "MemorySwapMax=0", "--", "taskset", "-c", manifest["daemon_cpus"],
                str(binary), str(fixture / "config.toml")], stdout=log, stderr=observer))
            pid = Q.COMMON.daemon_pid(binary, time.monotonic() + 120)
            Q.require(pid == daemon.pid, "scope launcher changed PID")
            record["daemon_owner"] = Q.COMMON.process_identity(pid, binary)
            end = time.monotonic() + 120
            while True:
                Q.require(daemon.poll() is None and time.monotonic() < end, "daemon startup failed")
                try:
                    Q.metrics(Q.fetch(19186, "/metrics")[1])
                    break
                except OSError:
                    time.sleep(.1)
            driver = Q.COMMON.own_child(subprocess.Popen([
                "taskset", "-c", manifest["harness_cpus"], str(harness), "--daemon", "127.0.0.1:17986",
                "--clients", str(clients), "--type2", str(routes * 4 // 5), "--type5", str(routes // 5),
                "--shift2", str(routes * 4 // 5), "--shift5", str(routes // 5), "--epochs", "0",
                "--epoch-secs", "1", "--churn-secs", "0", "--hold-time", "180",
                "--converge-cap-secs", str(bars["convergence_seconds"]), "--initial-cap-secs", "900",
                "--qualification-control-dir", str(leg / "wire")],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT))
            controller = Controller(daemon, driver, leg, arm, clients, correctness, bars["readiness_seconds"])
            controller.ack("connected")
            initial = controller.witness(lambda row: group_members(row, arm, clients, "a")
                                         and row["owned_routes"] == row["private_routes"] == 0)
            record["initial_groups"] = initial
            controller.command("load", 900)
            controller.source_barrier()
            baseline = controller.witness(settled)
            record["baseline"] = baseline
            for generation in ("b", "a"):
                shutil.copyfile(fixture / f"config-{generation}.toml", fixture / "config.toml")
                # Exact child only; never discover/kill a host daemon by name.
                started = controller.event("reload", generation=generation)
                os.kill(pid, signal.SIGHUP)
                record[f"regroup-{generation}"] = controller.witness(
                    lambda row, generation=generation: group_members(row, arm, clients, generation) and settled(row))
                controller.command(f"policy {generation}", bars["convergence_seconds"])
                elapsed = controller.last_completion - started
                Q.accept(elapsed <= bars["convergence_seconds"], "regroup wire convergence exceeded bar")
                record[f"regroup-{generation}-seconds"] = None if correctness else elapsed
            controller.command("mark refresh-start")
            controller.command("refresh")
            controller.command("refresh-settle", bars["convergence_seconds"])
            controller.witness(settled)
            controller.command("pause")
            dirty = None
            for _ in range(bars["max_churn_rounds"]):
                start = len(controller.observations)
                controller.command("churn")
                if dirty is not None:
                    continue
                # The socket read acknowledgement alone is never the witness.
                try:
                    controller.witness(lambda row: row["dirty"] == clients, timeout=2, after=start)
                    pair = dirty_pair(controller.observations[start:], clients)
                    if pair is None:
                        controller.witness(lambda row: row["dirty"] == clients, timeout=2)
                        pair = dirty_pair(controller.observations[start:], clients)
                    if pair is None:
                        raise MissingWitness("two consecutive actual dirty snapshots missing")
                    dirty = pair
                except MissingWitness:
                    continue
            Q.accept(dirty is not None, "simultaneous all-peer mass-dirty witness missing")
            record["mass_dirty_previous"], record["mass_dirty"] = dirty
            controller.source_barrier()
            controller.command("refresh")
            debt = controller.witness(lambda row: row["protocol_obligations"] > 0 and row["dirty"] > 0)
            start = len(controller.observations)
            writes = controller.command("churn-overlap")
            during = [row for row in controller.observations[start:] if row["protocol_obligations"] > 0
                      and writes["write_started_us"] <= row["wall_us"] <= writes["writers_drained_us"]]
            Q.accept(bool(during), "no actual refresh/EoR obligation during the paced source-update sequence")
            record["protocol_obligation_before_churn"] = debt
            record["protocol_obligation_during_churn"] = during[0]
            applied = controller.source_barrier()
            record["protocol_obligation_after_churn"] = controller.witness(
                lambda row: row["protocol_obligations"] > 0 and row["wall_us"] > applied["wall_us"])
            controller.command("resume")
            started = controller.last_completion
            controller.command("settle", bars["convergence_seconds"])
            elapsed = controller.last_completion - started
            Q.accept(elapsed <= bars["convergence_seconds"], "recovery wire convergence exceeded bar")
            record["recovery-seconds"] = None if correctness else elapsed
            final = controller.witness(settled)
            record["settled"] = final
            controller.command("mark recovered")
            _, metrics = Q.fetch(19186, "/metrics")
            (leg / "metrics.txt").write_text(metrics)
            record["executed_resets"] = Q.metrics(metrics)["executed_resets"]
            record["cgroup"] = Q.COMMON.snapshot_cgroup(pid, Q.DAEMON_BYTES)
            Q.write_json(leg / "cgroup.json", record["cgroup"])
            controller.command("finish")
            controller.probes.stop()
            controller.check_probes()
            record["driver_exit"] = driver.wait(timeout=30)
            Q.require(record["driver_exit"] == 0, "driver finish failed")
            record["wire"] = check_wire(leg, clients, routes)
            record["status"] = "PASS"
    except Exception as error:
        record["status"] = "FAIL" if isinstance(error, Q.AcceptanceFailure) else "INVALID"
        record["error"] = str(error)
        raise
    finally:
        Q.cleanup_cell(record, leg, fixture, driver, daemon, controller)


def analyze(output):
    path = output / "recovery-summary.json"
    Q.write_json(path, {"status": "INVALID", "scope": SCOPE, "terminal_only_qualified": False,
                        "error": "analysis incomplete"})
    try:
        return analyze_results(output)
    except Exception as error:
        summary = json.loads(path.read_text())
        summary.update(status="FAIL" if isinstance(error, Q.AcceptanceFailure) else "INVALID", error=str(error))
        Q.write_json(path, summary)
        raise


def analyze_results(output):
    manifest = Q.manifest_for(output)
    Q.require(manifest.get("recovery") == Q.RECOVERY_BARS, "recovery bars changed")
    paths = sorted(output.glob("recovery-*/result.json"))
    rows = [json.loads(path.read_text()) for path in paths]
    Q.require(rows, "missing recovery cells")
    correctness = rows[0]["correctness_only"]
    schedule = ["candidate", "private"] if correctness else list(Q.SCHEDULE)
    Q.require([row["arm"] for row in rows] == schedule
              and all(row["correctness_only"] == correctness for row in rows), "incomplete/reordered recovery matrix")
    Q.require(all(row["status"] in ("PASS", "FAIL") for row in rows), "invalid recovery cell")
    failures = [{"cell": path.parent.name, "arm": row["arm"], "error": row["error"]}
                for path, row in zip(paths, rows, strict=True) if row["status"] == "FAIL"]
    if failures:
        Q.write_json(output / "recovery-summary.json", {
            "status": "FAIL", "correctness_only": correctness, "scope": SCOPE,
            "production_activation_qualified": False, "terminal_only_qualified": False,
            "cells": len(rows), "medians": {}, "failed_cells": failures})
        Q.accept(False, "recorded cell acceptance failures; see failed_cells")
    for path, row in zip(paths, rows, strict=True):
        leg, clients = path.parent, row["clients"]
        Q.require(row["driver_exit"] == 0, "driver did not finish successfully")
        Q.require((clients, row["routes"]) == ((3, 10_000) if correctness else (150, 250)),
                  "recovery cell shape differs from fixed campaign")
        Q.require(row["wire"] == check_wire(leg, clients, row["routes"]), "wire receipt differs from raw captures")
        Q.require(row["executed_resets"] == Q.metrics((leg / "metrics.txt").read_text())["executed_resets"],
                  "reset receipt differs from raw metrics")
        cgroup = json.loads((leg / "cgroup.json").read_text())
        Q.require(row["cgroup"] == cgroup, "cgroup receipt differs from raw observation")
        Q.check_cgroup(cgroup)
        observed = [json.loads(line.removeprefix("evpn_qualification ")) for line in
                    (leg / "observer.log").read_text().splitlines() if line.startswith("evpn_qualification ")]
        for observation in observed:
            if observation["members"] == clients:
                roster(observation, row["arm"], clients)
        for key in ("initial_groups", "baseline", "regroup-b", "regroup-a", "mass_dirty_previous", "mass_dirty",
                    "protocol_obligation_before_churn", "protocol_obligation_during_churn", "protocol_obligation_after_churn", "settled"):
            Q.require(row[key] in observed, f"{key} absent from raw observer")
            roster(row[key], row["arm"], clients)
        Q.accept(row["mass_dirty"]["dirty"] == row["mass_dirty_previous"]["dirty"] == clients
                 and row["protocol_obligation_before_churn"]["protocol_obligations"] > 0
                 and row["protocol_obligation_during_churn"]["protocol_obligations"] > 0
                 and row["protocol_obligation_after_churn"]["protocol_obligations"] > 0, "missing actual overlap witness")
        first = observed.index(row["mass_dirty_previous"])
        Q.require(first + 1 < len(observed) and observed[first + 1] == row["mass_dirty"]
                  and row["mass_dirty"]["elapsed_us"] > row["mass_dirty_previous"]["elapsed_us"],
                  "mass-dirty snapshots are not consecutive actual observations")
        Q.accept(settled(row["settled"]), "proof duty did not settle")
        samples = [json.loads(line) for line in (leg / "readiness.jsonl").read_text().splitlines()]
        Q.accept(samples and all(s["status"] == 200 and (correctness or 0 <= s["seconds"] < .2)
                                for s in samples), "readiness bar failed")
        Q.require(all(0 <= sample["at"] - sample["scheduled"] < .05 for sample in samples),
                  "readiness sampler missed a scheduled probe")
        ordered_samples = sorted(samples, key=lambda sample: sample["scheduled"])
        Q.require(all(abs(right["scheduled"] - left["scheduled"] - .05) < .000001
                      for left, right in zip(ordered_samples, ordered_samples[1:])), "missing 20 Hz probe")
        events = [json.loads(line) for line in (leg / "events.jsonl").read_text().splitlines()]
        controls = [json.loads(line.removeprefix("evpn_control ")) for line in
                    (leg / "driver.log").read_text().splitlines() if line.startswith("evpn_control ")]
        protocol_overlap(row, events, controls)
        barriers = [json.loads(line.removeprefix("evpn_input_barrier ")) for line in
                    (leg / "observer.log").read_text().splitlines() if line.startswith("evpn_input_barrier ")]
        Q.require(input_applied(barriers, clients, 3), "missing actor-applied input barriers")
        applied = [event for event in events if event["event"] == "input-applied"]
        Q.require([event["generation"] for event in applied] == [1, 2, 3]
                  and [event["receipts"] for event in applied] == [clients, clients * 2, clients * 3],
                  "missing source-barrier acknowledgement")
        resume = [event for event in events if event["event"] == "command" and event.get("command") == "resume"]
        Q.require(len(resume) == 1 and applied[-1]["at"] < resume[0]["at"],
                  "readers resumed before the final actor-applied input barrier")
        for key, seconds in timings(events).items():
            Q.require(row[key] == (None if correctness else seconds), "timing receipt differs from raw events")
    for candidate, private in zip(rows[::2], rows[1::2], strict=True):
        for phase in PHASES:
            for left, right in zip(candidate["wire"][phase], private["wire"][phase], strict=True):
                Q.accept(left["state"] == right["state"] and left["ordered"] == right["ordered"],
                         f"paired wire parity differs: {phase}")
    median_timings = {}
    if not correctness:
        for phase in ("regroup-a-seconds", "regroup-b-seconds", "recovery-seconds"):
            samples = {arm: [row[phase] for row in rows if row["arm"] == arm] for arm in ("candidate", "private")}
            Q.accept(all(0 <= value <= 60 for values in samples.values() for value in values), "convergence bar failed")
            medians = {arm: statistics.median(values) for arm, values in samples.items()}
            Q.accept(medians["candidate"] <= medians["private"] * 1.03, f"candidate median regressed: {phase}")
            median_timings[phase] = medians
    summary = {"status": "PASS", "correctness_only": correctness, "scope": SCOPE,
               "production_activation_qualified": False, "terminal_only_qualified": False,
               "cells": len(rows), "medians": median_timings}
    Q.write_json(output / "recovery-summary.json", summary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "analyze"))
    parser.add_argument("output", type=Path)
    parser.add_argument("--correctness-only", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    manifest = Q.manifest_for(output)
    Q.require(manifest.get("recovery") == Q.RECOVERY_BARS, "recovery bars changed")
    if args.command == "run":
        for arm in ("candidate", "private"):
            Q.verify_export(output, arm)
        lock = os.environ.get("RUSTBGPD_HOST_LOCK_FD")
        Q.require(lock is not None and Path(f"/proc/self/fd/{int(lock)}").exists(), "use run.sh for host lock")
        Q.require(args.correctness_only or manifest.get("source_kind", "committed") == "committed",
                  "measured recovery requires committed source")
        for index, arm in enumerate(["candidate", "private"] if args.correctness_only else Q.SCHEDULE):
            try:
                run_cell(output, manifest, arm, index, args.correctness_only)
            except Q.AcceptanceFailure as error:
                if arm != "private":
                    raise
                print(f"private baseline cell {index} FAIL: {error}", file=sys.stderr)
    analyze(output)


if __name__ == "__main__":
    main()
