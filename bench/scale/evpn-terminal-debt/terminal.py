#!/usr/bin/env python3
"""EVPN terminal-marker debt: immediate refresh send and forced refusal under real backpressure."""

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import uuid

sys.dont_write_bytecode = True

import check  # noqa: E402 - disable bytecode before importing verified local inputs
import source  # noqa: E402 - disable bytecode before importing verified local inputs

BARS = {"clients": 3, "routes_per_source": 10000, "type2_fraction": .8,
        "churn_source": 0, "churn_messages": 1, "churn_keys": 4, "churn_rounds": 1,
        "receive_buffer_requested": 4096, "receive_buffer_readback": 8192,
        "send_buffer_requested": 4096, "send_buffer_readback": 8192,
        "tcp_notsent_lowat": 4096, "rib_queue": 4096, "writer_queue": 4096,
        "peer_provenance_budget": 16777216, "daemon_provenance_budget": 268435456,
        "max_budget_fraction": .8, "daemon_bytes": 12884901888,
        "readiness_hz": 20, "readiness_seconds": .2, "max_schedule_lag_seconds": .05,
        "convergence_seconds": 60, "initial_seconds": 900, "debt_witness_seconds": 2,
        "kernel_sample_hz": 20, "max_repeated_inventory_visits": 0,
        "candidate_median_ratio": 1.03,
        # Timed overlap cells: churn dispatched on the controller's
        # CLOCK_MONOTONIC at refresh dispatch + 20 ms, inside [20, 22] ms: after
        # every replay has started and long before any arm's last replay ends.
        # churn-applied is that dispatch to the last actor-applied receipt, on
        # the same clock.
        "churn_phase_us": 20_000, "churn_phase_window_us": 2_000,
        # Five timed overlap pairs carry the medians. Pressure cells keep the
        # Pending/kernel witness around churn; their timings are diagnostic.
        "schedule": [["overlap", "private"], ["overlap", "candidate"]] * 5
        + [["pressure", "private"], ["pressure", "candidate"]] * 3
        + [["forced-refusal", "private"], ["forced-refusal", "candidate"]] * 3,
        "correctness_schedule": [["overlap", "private"], ["overlap", "candidate"],
                                 ["pressure", "private"], ["pressure", "candidate"],
                                 ["forced-refusal", "private"], ["forced-refusal", "candidate"]],
        # Forced refusal fills the unchanged 4,096-entry outbound channel with
        # single-route announcements from source zero's unused pool indices,
        # stopping when a debtor has one free slot for the refresh's data.
        "fill_target_capacity": 1, "fill_spare_routes": 10000, "fill_seconds": 60,
        "marker_retry_seconds": 1}
SCOPE = ("non-RTC Type 2/5, three real TCP peers, ordinary route refresh; "
         "timed overlap cells: churn-applied during refresh replay overlap (performance, <=1.03x medians); "
         "pressure cells: immediate refresh-tail EVPN marker send and churn correctness under witnessed kernel "
         "backpressure (timings diagnostic; no <=1.03x claim under witnessed pressure); "
         "forced-refusal cells: refresh-site marker refused by a full 4,096-entry outbound channel and "
         "sent by the 1 s resync tick; complete actual-caller producer work and raw receiver UPDATE/EoR order; "
         "not ERR, RTC, full-fleet recovery, soak or production activation")


class KernelSampler:
    def __init__(self, leg):
        self.stop_event, self.rows, self.errors = threading.Event(), [], []
        self.leg = leg
        self.thread = threading.Thread(target=self.run, name="terminal-kernel-samples", daemon=True)
        self.thread.start()

    def run(self):
        try:
            with (self.leg / "ss.jsonl").open("x") as output:
                scheduled = time.monotonic()
                while not self.stop_event.is_set():
                    started = time.time_ns() // 1000
                    result = subprocess.run(["ss", "-tinpe", "( sport = :17986 )"], capture_output=True, text=True, timeout=2)
                    ended = time.time_ns() // 1000
                    check.require(result.returncode == 0, f"ss failed: {result.stderr}")
                    rows = check.ss_rows(result.stdout, started, ended)
                    output.write(json.dumps({"started_us": started, "ended_us": ended, "raw": result.stdout, "rows": rows}) + "\n")
                    output.flush()
                    self.rows.extend(rows)
                    scheduled += .05
                    self.stop_event.wait(max(0, scheduled - time.monotonic()))
        except Exception as error:
            self.errors.append(str(error))

    def close(self):
        self.stop_event.set()
        self.thread.join(timeout=3)
        check.require(not self.thread.is_alive() and not self.errors, f"kernel sampler failed: {self.errors}")


def readiness_type(r):
    """The pinned input's 20 Hz sampler, except that a slot already due when
    the stop request lands is still issued. Its loop sleeps 5 ms between
    checks, so a stop just after finish could otherwise drop the slot that
    reaches the workload's end and leave the series short of it."""
    class Readiness(r.Readiness):
        def run(self):
            pending, scheduled = [], time.monotonic()
            with self.path.open("x") as stream, r.ThreadPoolExecutor(max_workers=8) as executor:
                while True:
                    stopping = self.stop_event.is_set()
                    now = time.monotonic()
                    if now >= scheduled and (not stopping or scheduled <= self.stop_at):
                        pending.append(executor.submit(self.probe, scheduled))
                        scheduled += .05
                    elif stopping and not pending:
                        break
                    for future in list(pending):
                        if future.done():
                            row = future.result()
                            stream.write(json.dumps(row) + "\n")
                            stream.flush()
                            self.results.put(row)
                            pending.remove(future)
                    time.sleep(.005)

        def stop(self):
            if not self.stop_event.is_set():
                self.stop_at = time.monotonic()
                self.stop_event.set()
            self.thread.join(timeout=5)
            check.require(not self.thread.is_alive(), "readiness sampler did not stop")

    return Readiness


def resume_after_fallback(controller, q, arm, debtor):
    """Resume the readers; in a candidate forced cell, withdraw nothing until
    the tick has sent the owed markers, so the drain the fallback bar measures
    lies inside [resume, unfill]. The wait is bounded by the convergence bar."""
    controller.command("resume")
    started = controller.last_completion
    if arm == "candidate":
        resumed = controller.last_command_start["wall_us"]
        sent = controller.fallback_send(resumed, debtor, BARS["convergence_seconds"])
        q.accept(sent is not None, "fallback marker send exceeded the convergence bar")
    return started


def dispatch_overlap_churn(controller):
    """Timed overlap cells: churn leaves at refresh dispatch + the predeclared
    phase on CLOCK_MONOTONIC. No pressure or daemon observation gates it."""
    controller.command("refresh", BARS["convergence_seconds"])
    controller.dispatch_at(controller.last_command_start["mono_us"] + BARS["churn_phase_us"])
    return controller.command("terminal-churn", BARS["convergence_seconds"])


def controller_type(r):
    # The pinned input's Controller builds its sampler from this module name.
    if not getattr(r.Readiness, "issues_slot_due_before_stop", False):
        r.Readiness = readiness_type(r)
        r.Readiness.issues_slot_due_before_stop = True

    class Controller(r.Controller):
        def __init__(self, *args):
            super().__init__(*args)
            self.terminal_log = (self.leg / "observer.log").open()
            self.terminal_buffer = ""
            self.feed, self.work, self.sockets, self.writes = [], [], [], []
            self.kernel = KernelSampler(self.leg)

        def poll(self):
            super().poll()
            self.read_terminal()
            check.require(not self.kernel.errors, f"kernel sampler failed: {self.kernel.errors}")

        def read_terminal(self):
            self.terminal_buffer += self.terminal_log.read()
            lines = self.terminal_buffer.split("\n")
            self.terminal_buffer = lines.pop()
            for prefix, rows in (("evpn_terminal_feed ", self.feed), ("evpn_terminal_work ", self.work),
                                 ("evpn_terminal_socket ", self.sockets), ("evpn_terminal_write ", self.writes)):
                rows.extend(json.loads(line[len(prefix):]) for line in lines if line.startswith(prefix))

        def event(self, event, **fields):
            # The pinned event, plus the same CLOCK_MONOTONIC reading in µs
            # that the derived daemon stamps on its receipts.
            now = time.monotonic_ns()
            self.last_event = {"event": event, "at": now / 1e9, "wall_us": time.time_ns() // 1000,
                               "mono_us": now // 1000, **fields}
            with (self.leg / "events.jsonl").open("a") as stream:
                stream.write(json.dumps(self.last_event) + "\n")
            return self.last_event["at"]

        def dispatch_at(self, mono_us):
            """Return at `mono_us` on CLOCK_MONOTONIC: sleep, then spin the
            last 2 ms. Nothing here waits on, or reads, daemon observation."""
            while (remaining := mono_us - time.monotonic_ns() // 1000) > 2_000:
                time.sleep((remaining - 2_000) / 1e6)
            while time.monotonic_ns() // 1000 < mono_us:
                pass

        def before_churn(self, after):
            end = time.monotonic() + BARS["debt_witness_seconds"]
            while time.monotonic() < end:
                self.poll()
                for socket in self.sockets:
                    if socket["peer"] == r.Q.COMMON.peer(0):
                        continue
                    pending = check.pending_write(self.writes, socket["cookie"], after)
                    if pending is None:
                        continue
                    # The fixed build sends the refresh's markers at once, so a
                    # no-refusal cell carries no debt into the churn; both arms
                    # take the same live Pending/kernel baseline.
                    pre = [row for row in self.kernel.rows if row["cookie"] == socket["cookie"]
                           and max(after, pending["wall_us"]) <= row["started_us"] <= row["ended_us"]
                           <= time.time_ns() // 1000]
                    if pre:
                        self.event("pressure-before", peer=socket["peer"], write_id=pending["id"], cookie=socket["cookie"],
                                   pending=pending, sample=pre[-1])
                        return self.last_event.copy()
            # Missing required pressure evidence makes a pressure cell INVALID.
            raise ValueError("refresh did not establish a live Pending/kernel baseline before churn")

        def after_applied(self, applied, before):
            end = time.monotonic() + BARS["debt_witness_seconds"]
            while time.monotonic() < end:
                self.poll()
                kernel = check.kernel_pressure(self.sockets, self.writes, self.kernel.rows, before["peer"],
                                                before["pending"]["wall_us"], time.time_ns() // 1000,
                                                before["wall_us"], applied["wall_us"])
                if kernel and kernel["pending"]["id"] == before["write_id"]:
                    self.event("pressure-after", peer=before["peer"], kernel=kernel)
                    return self.last_event.copy()
            raise ValueError("same live write/kernel limiting did not span actually applied churn")

        def fill(self):
            """Raise route volume until a debtor's outbound channel has one slot.

            Each step sends at most (lowest observed capacity - 1) single-route
            UPDATEs, after every earlier one is admitted to both debtors, so the
            channel cannot overfill: one UPDATE commits at most one message per
            member and only the writer, blocked by the paused reader, frees room.
            Failing to reach the shape is INVALID, never retried.
            """
            debtors = [r.Q.COMMON.peer(index) for index in range(1, BARS["clients"])]
            started, total = time.time_ns() // 1000, 0
            end = time.monotonic() + BARS["fill_seconds"]
            target = BARS["fill_target_capacity"]
            capacity = {}
            while time.monotonic() < end:
                self.poll()
                rows = {peer: [row for row in self.feed if row["peer"] == peer] for peer in debtors}
                admitted = {peer: sum(row["rows"] for row in rows[peer]
                                      if row["event"] == "data_admitted" and row["wall_us"] >= started)
                            for peer in debtors}
                check.require(all(value <= total for value in admitted.values()), "fill admitted unsent routes")
                if not all(rows.values()) or any(value != total for value in admitted.values()):
                    continue
                capacity = {peer: rows[peer][-1]["capacity"] for peer in debtors}
                low = min(capacity.values())
                check.require(low >= target, f"outbound channel filled before the refresh: {capacity}")
                if low == target:
                    debtor = min(debtors, key=capacity.get)
                    cookie = [row["cookie"] for row in self.sockets if row["peer"] == debtor]
                    check.require(len(cookie) == 1, "missing debtor socket identity")
                    pending = check.pending_write(self.writes, cookie[0], started)
                    if pending is None:
                        continue
                    self.event("fill-complete", peer=debtor, routes=total, capacity=capacity,
                               pending=pending, admitted=rows[debtor][-1])
                    return self.last_event.copy()
                send = min(low - target, BARS["fill_spare_routes"] - total)
                check.require(send > 0, f"route volume exhausted before the channel filled: {total} routes, {capacity}")
                self.command(f"terminal-fill {send}", BARS["fill_seconds"])
                total += send
            raise ValueError(f"outbound channel did not fill by route volume: {total} routes, {capacity}")

        def refusal(self, after, debtor):
            """The refresh's data takes the last slot; the candidate's marker is refused."""
            end = time.monotonic() + BARS["debt_witness_seconds"]
            while time.monotonic() < end:
                self.poll()
                rows = [row for row in self.feed if row["peer"] == debtor and row["wall_us"] >= after]
                full = [row for row in rows if row["event"] == "data_admitted" and row["root"] == 0
                        and row["rows"] > 0 and row["capacity"] == 0]
                refused = any(row["event"] == "refresh_refused" for row in rows)
                if full and (self.arm == "private" or refused):
                    witness = check.refusal_witness(self.feed, debtor, after) if self.arm == "candidate" else None
                    self.event("refresh-full", peer=debtor, admitted=full[0], refusal=witness)
                    return self.last_event.copy()
            raise ValueError("refresh did not take the last outbound slot with a refused marker send")

        def fallback_send(self, after, debtor, seconds):
            """The debtor's owed markers sent by the resync tick after `after`, or
            None when the bounded wait expires."""
            end = time.monotonic() + seconds
            while time.monotonic() < end:
                self.poll()
                if any(row["peer"] == debtor and row["wall_us"] >= after and row["event"] == "retry_sent"
                       for row in self.feed):
                    return True
                time.sleep(.01)
            return None

        def close(self):
            try:
                self.kernel.close()
                self.terminal_log.close()
            finally:
                super().close()
    return Controller


def wire_receipt(leg, clients, routes, wire, q):
    controls = check.lines(leg / "driver.log", "evpn_control ")
    boundaries = {row["result"]["boundary"]: row["result"] for row in controls
                  if "boundary" in row.get("result", {})}
    check.require(all(sum(row.get("result", {}).get("boundary") == name for row in controls) == 1
                      for name in ("loaded", "baseline", "refresh-start", "settled", "finished")), "missing/duplicate wire boundary")
    check.require(sum(row["command"] == "finish" for row in controls) == 1, "missing final finish acknowledgement")
    result = []
    for peer in range(clients):
        path = leg / "wire" / f"peer-{peer}.bgp"
        actual = (leg / "wire" / f"raw-240.1.{peer // 200}.{peer % 200 + 1}.bgp").read_bytes()
        check.require(check.raw_updates(actual) == path.read_bytes(), "raw TCP UPDATE bytes differ from checked capture")
        receiver = wire.Receiver(peer, clients, routes * 4 // 5, routes // 5)
        cursor = 0
        data = path.read_bytes()
        for name in ("loaded", "baseline", "refresh-start", "settled", "finished"):
            boundary = boundaries[name]
            end = boundary["offsets"][peer]
            check.require(type(end) is int and cursor <= end <= len(data), "invalid receiver capture offset")
            if name == "settled":
                # Check every raw frame; a later correct state cannot hide an
                # early terminal marker or an unknown/duplicate withdrawal.
                chunk, offset = data[cursor:end], 0
                while offset < len(chunk):
                    size = int.from_bytes(chunk[offset + 16:offset + 18], "big")
                    check.require(size >= 23 and offset + size <= len(chunk), "malformed captured UPDATE")
                    frame = chunk[offset:offset + size]
                    attrs, _ = next(wire.frames(frame))
                    if set(attrs) == {15} and len(attrs[15][1]) == 3 and receiver.coverage is not None:
                        # The EVPN EoR covers the refreshed table; ERR is not
                        # negotiated, so no EoRR reaches this wire.
                        q.accept(receiver.coverage <= receiver.replay_seen,
                                 f"peer {peer}: EVPN EoR reached the wire before a route it covers")
                    receiver.consume(frame, {2000 if peer == 1 else 1000})
                    offset += size
                receiver.end_replay()
            else:
                receiver.consume(data[cursor:end], {2000 if peer == 1 else 1000})
            cursor = end
            check.require(receiver.eors == boundary["eors"][peer], "raw and driver EoR counts differ")
            if name in ("baseline", "refresh-start"):
                check.require(receiver.eors > 0, "initial receiver EoR was not proved before pause/refresh")
            state = receiver.boundary(boundary["shifts"], 1, 1, 2000 if peer == 1 else 1000)
            if name == "refresh-start":
                receiver.begin_replay()
        check.require(cursor == len(data), "unvalidated trailing receiver bytes")
        result.append({"peer": peer, "state": state, "eors": receiver.eors})
    return result


def evidence(leg, record, q, r, wire):
    clients = BARS["clients"]
    observations = check.lines(leg / "observer.log", "evpn_qualification ")
    check.require(observations, "missing actual daemon observations")
    for row in observations:
        q.validate_provenance(row, clients)
    for row in observations:
        q.accept_provenance_headroom(row)
        if row["members"] == clients:
            r.roster(row, record["arm"], clients)
    check.require(record["settled"] in observations, "settled receipt absent from raw observations")
    q.accept(check.settled(record["settled"]), "completion/proof/dirty/pending duties did not settle")
    samples = [json.loads(line) for line in (leg / "readiness.jsonl").read_text().splitlines()]
    events = [json.loads(line) for line in (leg / "events.jsonl").read_text().splitlines()]
    loads = [row["at"] for row in events if row["event"] == "command" and row.get("command") == "load"]
    finishes = [row["at"] for row in events if row["event"] == "complete" and row.get("command") == "finish"]
    check.require(len(loads) == len(finishes) == 1, "missing raw load/finish controller clocks")
    # Online, the cell is still open: the current monotonic time bounds it.
    cell = (record["cell_started_monotonic_ns"] / 1e9,
            record.get("cell_finished_monotonic_ns", time.monotonic_ns()) / 1e9)
    q.accept(check.readiness(samples, loads[0], finishes[0], cell), "readiness status/latency bar failed")
    resets = q.metrics((leg / "metrics.txt").read_text())["executed_resets"]
    q.accept(check.reset_free(resets), "a provenance reset cause executed")
    cgroup = json.loads((leg / "cgroup.json").read_text())
    q.check_cgroup(cgroup)
    q.accept(all(int(cgroup["events"][name]) == 0 for name in ("max", "oom", "oom_kill", "oom_group_kill")),
             "cgroup max/OOM event breached the bar")
    report = {"readiness_requests": len(samples), "executed_resets": resets,
              "wire": wire_receipt(leg, clients, BARS["routes_per_source"], wire, q)}
    socket_rows = check.lines(leg / "observer.log", "evpn_terminal_socket ")
    report["sockets"] = check.socket_roster(socket_rows, check.lines(leg / "driver.log", "evpn_terminal_receiver "),
                                           {q.COMMON.peer(peer) for peer in range(clients)})
    ss = []
    for line in (leg / "ss.jsonl").read_text().splitlines():
        row = json.loads(line)
        parsed = check.ss_rows(row["raw"], row["started_us"], row["ended_us"])
        check.require(parsed == row["rows"], "retained kernel observations differ from raw ss")
        ss.extend(parsed)
    forced = record["shape"] == "forced-refusal"
    controls = check.lines(leg / "driver.log", "evpn_control ")
    commands = ["terminal-fill" if row["command"].startswith("terminal-fill ") else row["command"] for row in controls]
    fills = commands.count("terminal-fill")
    head = ["connected", "load", "source-barrier", "terminal-baseline", "mark refresh-start", "pause"]
    if forced:
        burst = "terminal-unfill"
        expected = head + ["terminal-fill"] * fills + ["refresh", "resume", burst, "source-barrier", "settle", "finish"]
    else:
        burst = "terminal-churn"
        expected = head + ["refresh", burst, "source-barrier", "resume", "settle", "finish"]
    check.require((fills > 0) == forced and commands == expected, "missing, repeated or reordered fixed workload command")
    bursts = [row["result"] for row in controls if row["command"] == burst]
    applied = [row for row in events if row["event"] == "input-applied" and row["generation"] == 2]
    starts = [row for row in events if row["event"] == "command" and row.get("command") == burst]
    ends = [row for row in events if row["event"] == "complete" and row.get("command") == burst]
    check.require(len(applied) == len(starts) == len(ends) == len(bursts) == 1
                  and record["applied"] == applied[0], "source burst/applied receipt differs from raw controls")
    if forced:
        filled = [row["result"] for row in controls if row["command"].startswith("terminal-fill ")]
        check.require(all(row["source"] == 0 and row["routes"] > 0 for row in filled)
                      and [row["total"] for row in filled] == [sum(row["routes"] for row in filled[:index + 1])
                                                               for index in range(len(filled))]
                      and bursts[0]["source"] == 0 and bursts[0]["routes"] == filled[-1]["total"]
                      and bursts[0]["messages"] > 0, "fill/unfill route volume differs")
    else:
        check.require(record["churn"] == bursts[0] and bursts[0]["source"] == 0 and bursts[0]["messages"] == 1
                      and bursts[0]["events"] == 4, "fixed source UPDATE differs")
    check.require(starts[0]["wall_us"] <= bursts[0]["write_started_us"] <= bursts[0]["writers_drained_us"]
                  <= ends[0]["wall_us"] < applied[0]["wall_us"], "fixed source UPDATE/application ordering differs")
    barriers = check.lines(leg / "observer.log", "evpn_input_barrier ")
    q.accept(r.input_applied(barriers, clients, 2), "source EoR did not prove all route work actually applied")
    generations = [row["result"]["input_barrier_generation"] for row in controls if row["command"] == "source-barrier"]
    barrier_starts = [row for row in events if row["event"] == "command" and row.get("command") == "source-barrier"]
    barrier_ends = [row for row in events if row["event"] == "complete" and row.get("command") == "source-barrier"]
    applied_events = [row for row in events if row["event"] == "input-applied"]
    check.require(generations == [1, 2] and len(barrier_starts) == len(barrier_ends) == 2
                  and [row["generation"] for row in applied_events] == [1, 2], "source barrier generation/command lineage differs")
    check.require(barrier_starts[0]["wall_us"] <= barrier_ends[0]["wall_us"] < barrier_starts[1]["wall_us"]
                  <= barrier_ends[1]["wall_us"] <= applied[0]["wall_us"]
                  and ends[0]["wall_us"] < barrier_starts[1]["wall_us"], "source barriers do not bracket actual source writes")
    for peer in range(clients):
        actual = [row for row in barriers if row["peer"] == q.COMMON.peer(peer)]
        check.require(len(actual) == 2 and actual[0]["wall_us"] < actual[1]["wall_us"], "duplicate/nonmonotone actor input receipt")
        for generation, row in enumerate(actual):
            check.require(barrier_starts[generation]["wall_us"] <= row["wall_us"] <= applied_events[generation]["wall_us"],
                          "actor input receipt does not follow its actual source-barrier dispatch")
        check.require(actual[1]["wall_us"] > bursts[0]["writers_drained_us"], "old input receipt was substituted for applied source work")
    overlap = record["shape"] == "overlap"
    timed = not record["correctness_only"] and overlap
    churn_seconds = applied[0]["at"] - starts[0]["at"]
    q.accept(0 <= churn_seconds <= BARS["convergence_seconds"], "source work application exceeded convergence bar")
    if overlap:
        churn_seconds = check.churn_applied(barriers, [q.COMMON.peer(peer) for peer in range(clients)],
                                            check.mono(starts[0], "the churn dispatch"))
        q.accept(churn_seconds <= BARS["convergence_seconds"], "churn application exceeded convergence bar")
    check.require(record["churn-applied-seconds"] == (churn_seconds if timed else None),
                  "churn duration differs from raw monotonic controller and receipt clocks")
    report["churn_applied_seconds"] = churn_seconds
    phases = [("load", BARS["initial_seconds"]), ("terminal-baseline", BARS["convergence_seconds"]),
              ("refresh", BARS["convergence_seconds"])] + ([(burst, BARS["convergence_seconds"])] if forced else [])
    for command, cap in phases:
        phase_start = [row for row in events if row["event"] == "command" and row.get("command") == command]
        phase_end = [row for row in events if row["event"] == "complete" and row.get("command") == command]
        check.require(len(phase_start) == len(phase_end) == 1, f"missing raw {command} controller clocks")
        q.accept(0 <= phase_end[0]["at"] - phase_start[0]["at"] <= cap, f"{command} exceeded fixed convergence cap")
    resumed = [row for row in events if row["event"] == "complete" and row.get("command") == "resume"]
    converged = [row for row in events if row["event"] == "complete" and row.get("command") == "settle"]
    check.require(len(resumed) == len(converged) == 1, "missing raw resume/convergence clocks")
    convergence = converged[0]["at"] - resumed[0]["at"]
    q.accept(0 <= convergence <= BARS["convergence_seconds"], "resume convergence exceeded bar")
    check.require(record["convergence-seconds"] == (convergence if timed else None),
                  "convergence duration differs from raw monotonic controller clocks")
    resume_start = [row for row in events if row["event"] == "command" and row.get("command") == "resume"]
    refresh_start = [row for row in events if row["event"] == "command" and row.get("command") == "refresh"]
    check.require(len(resume_start) == len(refresh_start) == 1, "missing raw refresh/resume dispatch")
    feed = check.lines(leg / "observer.log", "evpn_terminal_feed ")
    check.validate_feed(feed, {q.COMMON.peer(index) for index in range(clients)})
    work = check.lines(leg / "observer.log", "evpn_terminal_work ")
    debtors = [q.COMMON.peer(index) for index in range(1, clients)]
    report["convergence_seconds"] = convergence
    if overlap:
        # Pressure observation neither delays this dispatch nor decides validity.
        report["phase"] = check.overlap_phase(
            feed, [q.COMMON.peer(index) for index in range(clients)], (clients - 1) * BARS["routes_per_source"],
            check.mono(refresh_start[0], "the refresh dispatch"), check.mono(starts[0], "the churn dispatch"),
            BARS["churn_phase_us"], BARS["churn_phase_window_us"])
    elif not forced:
        before_events = [row for row in events if row["event"] == "pressure-before"]
        after_events = [row for row in events if row["event"] == "pressure-after"]
        check.require(len(before_events) == len(after_events) == 1
                      and record["pressure_before"] == before_events[0] and record["pressure_after"] == after_events[0],
                      "pressure handshake differs from actual controller events")
        before, after = before_events[0], after_events[0]
        check.require(before["wall_us"] <= starts[0]["wall_us"] < applied[0]["wall_us"] < after["wall_us"] <= resume_start[0]["wall_us"]
                      and before["sample"] in ss and before["sample"]["ended_us"] <= before["wall_us"]
                      and before["pending"]["wall_us"] <= before["sample"]["started_us"]
                      and before["cookie"] == before["sample"]["cookie"] == before["pending"]["cookie"]
                      and before["write_id"] == before["pending"]["id"],
                      "actual Pending/kernel handshakes do not bracket source application and resume")
        kernel = check.kernel_pressure(socket_rows, check.lines(leg / "observer.log", "evpn_terminal_write "), ss,
                                       before["peer"], before["pending"]["wall_us"], after["wall_us"],
                                       before["wall_us"], applied[0]["wall_us"])
        check.require(kernel is not None, "no real kernel backpressure across churn")
        check.require(kernel == after["kernel"] and kernel["pending"] == before["pending"],
                      "live-write/kernel handshake differs from raw evidence")
        report["kernel"] = kernel
    if not forced:
        if record["arm"] == "candidate":
            # The no-refusal shape: every debtor's refresh-tail send succeeded.
            for peer in debtors:
                rows = [row for row in feed if row["peer"] == peer]
                check.require(rows and check.marker_counts(rows[-1])["refresh_refused"] == 0
                              and any(row["event"] == "refresh_sent" and row["wall_us"] >= refresh_start[0]["wall_us"]
                                      for row in rows),
                              "no-refusal cell did not send its markers at the refresh")
            # Every root called for this applied source UPDATE, across both groups.
            roots = {row["root"] for row in feed if row["event"] == "root_before"
                     and record["churn"]["write_started_us"] <= row["wall_us"] <= record["applied"]["wall_us"]}
            report["work"] = check.work_receipt(work, sorted(roots))
            groups = {row["group"] for row in work if row["id"] in roots}
            check.require(len(groups) == 2 and all(sum(row["keys"] for row in work if row["id"] in roots and row["group"] == group) == 4
                                                  for group in groups), "producer roots do not cover the four changed keys in both groups")
        return report
    fill = [row for row in events if row["event"] == "fill-complete"]
    full = [row for row in events if row["event"] == "refresh-full"]
    check.require(len(fill) == len(full) == 1 and record["fill"] == fill[0] and record["refresh_full"] == full[0],
                  "fill/refusal handshake differs from actual controller events")
    fill, full = fill[0], full[0]
    peer = fill["peer"]
    check.require(peer in debtors and full["peer"] == peer and fill["capacity"][peer] == BARS["fill_target_capacity"]
                  and fill["routes"] == bursts[0]["routes"] and fill["admitted"] in feed and full["admitted"] in feed
                  and refresh_start[0]["wall_us"] <= full["admitted"]["wall_us"] < resume_start[0]["wall_us"]
                  and full["admitted"]["event"] == "data_admitted" and full["admitted"]["root"] == 0
                  and full["admitted"]["peer"] == peer and full["admitted"]["capacity"] == 0,
                  "refresh did not take the debtor's last outbound slot after the route-volume fill")
    report["fill"] = {"peer": peer, "routes": fill["routes"], "capacity": fill["capacity"],
                      "refresh_capacity_after": full["admitted"]["capacity"]}
    if record["arm"] == "candidate":
        refusal = check.refusal_witness(feed, peer, refresh_start[0]["wall_us"])
        check.require(refusal == full["refusal"], "refusal handshake differs from raw feed")
        unfill = starts[0]["wall_us"]
        report["fallback"] = check.fallback(feed, refusal, resume_start[0]["wall_us"], unfill)
        settle_end = converged[0]["wall_us"]
        roots = {row["root"] for row in feed if row["event"] == "root_before"
                 and refresh_start[0]["wall_us"] <= row["wall_us"] <= settle_end}
        report["work"] = check.work_receipt(work, sorted(roots))
    return report


def accept_report(report, arm, q):
    if arm == "candidate":
        q.accept(report["work"]["inventory_visits"] <= BARS["max_repeated_inventory_visits"],
                 "complete current-feed churn repeated full-inventory producer work")
    if "fallback" in report:
        q.accept(check.fallback_within_bar(report["fallback"]),
                 "markers did not leave the refusal through the resync tick within 1 s plus the measured drain")

def run_cell(output, manifest, q, r, wire, shape, arm, index, correctness):
    leg = output / f"terminal-{index:02}-{shape}-{arm}"
    leg.mkdir()
    fixture = Path(tempfile.mkdtemp(prefix="evpn-terminal-"))
    daemon = driver = controller = None
    record = {"status": "INVALID", "shape": shape, "arm": arm, "correctness_only": correctness,
              "head": manifest["head"], "qualification_head": manifest["qualification_head"],
              "scope": SCOPE, "production_activation": False,
              "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
              "cell_started_monotonic_ns": time.monotonic_ns()}
    try:
        q.cell_gate(output, manifest, leg, correctness)
        r.scenario(fixture, output / "sources/candidate", BARS["clients"])
        identities = source.verify_build(output, manifest, q)
        binary, harness = output / "bin" / f"rustbgpd-{arm}", output / "bin/evpn-rr-soak"
        check.require(all(q.digest(path) == identities[path.name] for path in (binary, harness)), "binary input changed")
        environment = dict(os.environ, RUSTBGPD_BENCH_WRITER_POLLS="1", RUSTBGPD_BENCH_UNSENT_THRESHOLD_BYTES="4096")
        with (leg / "daemon.log").open("x") as log, (leg / "observer.log").open("x") as observer:
            subprocess.run(["taskset", "-c", manifest["daemon_cpus"], str(binary), "--check", "--strict", str(fixture / "config.toml")],
                           stdout=log, stderr=subprocess.STDOUT, env=environment, check=True)
            if not correctness:
                q.require_timing_window(manifest)
            daemon = q.COMMON.own_child(subprocess.Popen([
                "systemd-run", "--user", "--scope", "--quiet", "-p", f"MemoryMax={q.DAEMON_BYTES}", "-p", "MemorySwapMax=0", "--",
                "taskset", "-c", manifest["daemon_cpus"], str(binary), str(fixture / "config.toml")],
                stdout=log, stderr=observer, env=environment))
            pid = q.COMMON.daemon_pid(binary, time.monotonic() + 120)
            check.require(pid == daemon.pid, "scope launcher changed PID")
            record["daemon_owner"] = q.COMMON.process_identity(pid, binary)
            end = time.monotonic() + 120
            while True:
                check.require(daemon.poll() is None and time.monotonic() < end, "daemon startup failed")
                try:
                    q.fetch(19186, "/metrics")
                    break
                except OSError:
                    time.sleep(.1)
            driver = q.COMMON.own_child(subprocess.Popen([
                "taskset", "-c", manifest["harness_cpus"], str(harness), "--daemon", "127.0.0.1:17986", "--clients", "3",
                "--type2", "8000", "--type5", "2000", "--shift2", "1", "--shift5", "1", "--epochs", "0", "--epoch-secs", "1",
                "--churn-secs", "0", "--hold-time", "180", "--converge-cap-secs", "60", "--initial-cap-secs", "900",
                "--qualification-control-dir", str(leg / "wire")], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=dict(os.environ, RUSTBGPD_TERMINAL_RAW_DIR=str(leg / "wire"))))
            # Even correctness cells retain and enforce real readiness latency.
            controller = controller_type(r)(daemon, driver, leg, arm, 3, False, .2)
            controller.ack("connected")
            controller.command("load", BARS["initial_seconds"])
            controller.source_barrier()
            controller.command("terminal-baseline", BARS["convergence_seconds"])
            record["baseline"] = controller.witness(r.settled)
            controller.command("mark refresh-start")
            controller.command("pause")
            timed = not correctness and shape == "overlap"
            if shape == "overlap":
                record["churn"] = dispatch_overlap_churn(controller)
                churn_started = controller.last_command_start.copy()
                record["applied"] = controller.source_barrier()
                churn_seconds = check.churn_applied(controller.input_barriers,
                                                    [r.Q.COMMON.peer(peer) for peer in range(BARS["clients"])],
                                                    churn_started["mono_us"])
                q.accept(churn_seconds <= BARS["convergence_seconds"], "churn application exceeded convergence bar")
                record["churn-applied-seconds"] = churn_seconds if timed else None
                controller.command("resume")
                started = controller.last_completion
            elif shape == "pressure":
                controller.command("refresh", BARS["convergence_seconds"])
                refresh_started = controller.last_command_start["wall_us"]
                record["pressure_before"] = controller.before_churn(refresh_started)
                record["churn"] = controller.command("terminal-churn", BARS["convergence_seconds"])
                churn_started = controller.last_command_start.copy()
                record["applied"] = controller.source_barrier()
                q.accept(record["applied"]["at"] - churn_started["at"] <= BARS["convergence_seconds"],
                         "churn application exceeded convergence bar")
                record["churn-applied-seconds"] = None
                record["pressure_after"] = controller.after_applied(record["applied"], record["pressure_before"])
                controller.command("resume")
                started = controller.last_completion
            else:
                record["fill"] = controller.fill()
                controller.command("refresh", BARS["convergence_seconds"])
                refresh_started = controller.last_command_start["wall_us"]
                record["refresh_full"] = controller.refusal(refresh_started, record["fill"]["peer"])
                started = resume_after_fallback(controller, q, arm, record["fill"]["peer"])
                controller.command("terminal-unfill", BARS["convergence_seconds"])
                unfill_started = controller.last_command_start.copy()
                record["applied"] = controller.source_barrier()
                q.accept(record["applied"]["at"] - unfill_started["at"] <= BARS["convergence_seconds"],
                         "fill withdrawal exceeded convergence bar")
                record["churn-applied-seconds"] = None
            controller.command("settle", BARS["convergence_seconds"])
            elapsed = controller.last_completion - started
            q.accept(elapsed <= BARS["convergence_seconds"], "resume convergence exceeded bar")
            record["convergence-seconds"] = elapsed if timed else None
            record["settled"] = controller.witness(r.settled)
            (leg / "metrics.txt").write_text(q.fetch(19186, "/metrics")[1])
            q.write_json(leg / "cgroup.json", q.COMMON.snapshot_cgroup(pid, q.DAEMON_BYTES))
            controller.command("finish")
            controller.probes.stop()
            controller.check_probes()
            record["driver_exit"] = driver.wait(timeout=30)
            check.require(record["driver_exit"] == 0, "driver finish failed")
            controller.read_terminal()
            controller.kernel.close()
            record["evidence"] = evidence(leg, record, q, r, wire)
            accept_report(record["evidence"], arm, q)
            record["status"] = "PASS"
    except Exception as error:
        record["status"] = "FAIL" if isinstance(error, q.AcceptanceFailure) else "INVALID"
        record["error"] = str(error)
        record["driver_exit_before_cleanup"] = driver.poll() if driver is not None else None
    finally:
        try:
            q.cleanup_cell(record, leg, fixture, driver, daemon, controller)
        finally:
            record["cell_finished_monotonic_ns"] = time.monotonic_ns()
            q.write_json(leg / "result.json", record)
    return record


def run(args):
    output = Path(args.output).resolve()
    manifest, q, r, wire = source.load(output)
    check.require(manifest["bars"] == BARS, "predeclared bars changed")
    lock = os.environ.get("RUSTBGPD_HOST_LOCK_FD")
    check.require(lock is not None and Path(f"/proc/self/fd/{int(lock)}").exists(), "use run.sh to hold the host lock")
    schedule = BARS["correctness_schedule"] if args.correctness_only else BARS["schedule"]
    results = []
    q.write_json(output / "summary.json", {"status": "INVALID", "scope": SCOPE,
                                           "production_activation": False, "error": "campaign incomplete"})
    for index, (shape, arm) in enumerate(schedule):
        record = run_cell(output, manifest, q, r, wire, shape, arm, index, args.correctness_only)
        results.append(record)
        if record["status"] == "INVALID" or (record["status"] == "FAIL" and arm == "candidate"):
            break
    return summarize(output, manifest, results, q, r, wire, args.correctness_only)


def summarize(output, manifest, rows, q, r, wire, correctness):
    summary = {"status": "INVALID", "scope": SCOPE, "head": manifest["head"], "qualification_head": source.PINNED,
               "correctness_only": correctness, "production_activation": False, "cells": len(rows), "medians": {}}
    q.write_json(output / "summary.json", summary)
    try:
        check.require(manifest["bars"] == BARS, "predeclared campaign bars changed")
        identities = source.verify_build(output, manifest, q)
        expected = BARS["correctness_schedule"] if correctness else BARS["schedule"]
        check.require(rows and all(row["status"] in ("PASS", "FAIL") and not row.get("cleanup_errors")
                                  and "retained_fixture" not in row for row in rows),
                      "technical/cleanup cell failure; inspect retained result")
        check.require(all(row["correctness_only"] == correctness and row["head"] == manifest["head"]
                          and row["qualification_head"] == source.PINNED and row["scope"] == SCOPE
                          and row["production_activation"] is False for row in rows), "mixed cell source/scope/mode")
        cells = [[row["shape"], row["arm"]] for row in rows]
        check.require(cells == expected[:len(rows)], "reordered campaign prefix")
        paths = sorted(output.glob("terminal-*/result.json"))
        check.require(len(paths) == len(rows), "missing/extra retained cell records")
        processes, boots, previous_end, previous_raw_end = set(), set(), 0, 0
        for path, row in zip(paths, rows, strict=True):
            owner = row["daemon_owner"]
            check.require(all(type(owner[name]) is int and owner[name] > 0 for name in ("pid", "starttime"))
                          and owner["binary_sha256"] == identities[f'rustbgpd-{row["arm"]}'],
                          "daemon process is not bound to the verified arm binary")
            boot = str(uuid.UUID(row["boot_id"]))
            process = boot, owner["pid"], owner["starttime"]
            check.require(process not in processes, "a physical daemon process was reused as another cell")
            processes.add(process)
            boots.add(boot)
            start, end = row["cell_started_monotonic_ns"], row["cell_finished_monotonic_ns"]
            check.require(type(start) is int and type(end) is int and 0 < start < end and previous_end <= start,
                          "physical cell intervals overlap or repeat")
            previous_end = end
            event_path = path.parent / "events.jsonl"
            events = [json.loads(line) for line in event_path.read_text().splitlines()] if event_path.exists() else []
            if events:
                clocks = [event["at"] for event in events]
                check.require(all(type(clock) in (int, float) and start <= clock * 1e9 <= end for clock in clocks)
                              and clocks == sorted(clocks) and previous_raw_end < clocks[0],
                              "raw global cell clocks repeat/overlap or escape their physical interval")
                previous_raw_end = clocks[-1]
            else:
                check.require(row["status"] == "FAIL" and "settled" not in row, "complete cell lacks raw global interval")
        check.require(len(boots) == 1, "campaign combines different host boots")
        partial, failures, invalids = [], [], []
        for index, (path, row) in enumerate(zip(paths, rows, strict=True)):
            check.require(path.parent.name == f'terminal-{index:02}-{row["shape"]}-{row["arm"]}',
                          "cell path differs from ordered arm")
            try:
                if row["status"] == "PASS":
                    check.require("settled" in row and "evidence" in row and row.get("driver_exit") == 0,
                                  "PASS cell lacks complete raw-evidence/driver receipt")
                if "settled" in row:
                    raw = evidence(path.parent, row, q, r, wire)
                    check.require(raw == row.get("evidence"), "retained evidence differs from raw consumer")
                    accept_report(raw, row["arm"], q)
                    check.require(row["status"] == "PASS", "stored complete failure is unsupported by its raw bars")
                else:
                    check.require(row["status"] == "FAIL" and isinstance(row.get("error"), str) and row["error"],
                                  "unvalidated partial cell is not a recorded acceptance miss")
                    partial.append({"cell": path.parent.name, "error": row["error"]})
                    failures.append({"cell": path.parent.name, "error": row["error"]})
            except q.AcceptanceFailure as error:
                failures.append({"cell": path.parent.name, "error": str(error)})
            except Exception as error:
                invalids.append({"cell": path.parent.name, "error": str(error)})
        if invalids:
            summary.update(status="INVALID", invalid_cells=invalids, failures=failures)
        elif failures:
            summary.update(status="FAIL", failures=failures, partial_failures_unvalidated=partial)
        else:
            check.require(cells == expected, "incomplete/reordered campaign")
            if not correctness:
                # Only timed overlap cells are compared on time. Pressure
                # timings are diagnostic; forced-refusal cells carry debt the
                # private arm cannot.
                summary["medians"] = check.timing_medians([row for row in rows if row["shape"] == "overlap"],
                                                          BARS["candidate_median_ratio"])
                for field, medians in summary["medians"].items():
                    q.accept(medians["pass"], f"{field} exceeded 1.03 bar")
            summary["status"] = "PASS"
    except Exception as error:
        summary.update(status="FAIL" if isinstance(error, q.AcceptanceFailure) else "INVALID", error=str(error))
    q.write_json(output / "summary.json", summary)
    return 0 if summary["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare")
    prepare.add_argument("output")
    prepare.add_argument("--qualification-source", required=True)
    prepare.add_argument("--base", required=True)
    prepare.add_argument("--daemon-cpus", required=True)
    prepare.add_argument("--harness-cpus", required=True)
    prepare.add_argument("--window-start")
    prepare.add_argument("--window-end")
    build = sub.add_parser("build")
    build.add_argument("output")
    run_parser = sub.add_parser("run")
    run_parser.add_argument("output")
    run_parser.add_argument("--correctness-only", action="store_true")
    analyze = sub.add_parser("analyze")
    analyze.add_argument("output")
    verify = sub.add_parser("verify")
    verify.add_argument("output")
    verify.add_argument("--built", action="store_true")
    args = parser.parse_args()
    if args.command == "prepare":
        source.prepare(args, BARS)
        return 0
    if args.command == "build":
        source.build(args)
        return 0
    if args.command == "run":
        return run(args)
    output = Path(args.output).resolve()
    manifest, q, r, wire = source.load(output)
    if args.command == "verify":
        if args.built:
            source.verify_build(output, manifest, q)
        print(json.dumps({"head": manifest["head"], "qualification_head": manifest["qualification_head"], "verified": True}))
        return 0
    rows = [json.loads(path.read_text()) for path in sorted(output.glob("terminal-*/result.json"))]
    return summarize(output, manifest, rows, q, r, wire, rows[0]["correctness_only"] if rows else False)


if __name__ == "__main__":
    sys.exit(main())
