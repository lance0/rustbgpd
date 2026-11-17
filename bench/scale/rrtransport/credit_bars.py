#!/usr/bin/env python3
"""Apply the outbound-credit campaign bars to parent and candidate results.

    credit_bars.py analyze PARENT_DIR CANDIDATE_DIR
    credit_bars.py check RESULT_DIR

Each arm directory holds one or more repetitions: every directory under it
that `run-credit-cells.sh` wrote a ``provenance.jsonl`` into (the arm
directory itself or subdirectories such as ``1/`` and ``2/``). A repetition
attempted the cells its provenance lists; each attempted cell must leave its
result (``exhaust-unicast.json``, ``exhaust-evpn.json``, ``paused-evpn.json``,
``probes.json``, ``fill-<family>.json``) or, for an OOM-killed paused-reader
cell, a ``paused-exit.json`` marker saying so. An attempted cell that left
neither, or only a failure marker, makes its cell INVALID. Both arms must
attempt each cell in the same repetitions, each arm must use one harness
binary, and the two arms must use different ones.

Every cell gets one ``PASS``, ``FAIL`` or ``INVALID`` line; the analyzer
never stops at the first failing cell. Exit status: 1 when any cell FAILs,
else 2 when any is INVALID, else 0.

``check`` applies the single-arm parts (wire checks and exhaustion witness)
to one result set, measured or not, for correctness runs. It also applies
the wire checks to any ``restart-<family>.json`` (the RFC 4724 restart
burst) and ``restart-churn-<family>.json`` (the same with churn during its
drain, whose timing it checks), and reports their instruments; their bars
are cell 7's, which ``analyze`` judges on the candidate alone.
"""

from __future__ import annotations

import json
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path

GIB = 1 << 30
# Cell 1: the candidate's cgroup peak must be at least this far below the parent's.
CELL1_MARGIN = 1.5 * GIB
CELL1_CGROUP_MAX = 12 * GIB
# Cell 1: 2 GiB plus 150 peers x one 1,024-row pass at the candidate's charge.
CREDIT_TARGET = 2 * GIB
PASS_ROWS = 1_024
PEERS = 150
# The candidate charges each announced row its element plus this.
ANNOUNCED_ROW_OVERHEAD = 146
# Cell 2, report-only since the drain bar replaced it: recovery against
# max(parent x 1.25, parent + 2 s).
RECOVERY_RATIO = 1.25
RECOVERY_SLACK_MS = 2_000.0
# Cell 2: every burst receiver exact this soon after the readers resume, in
# every candidate run.
DRAIN_AFTER_RESUME_MAX_MS = 60_000.0
# Cell 7: the RFC 4724 selection release and its owed drain. Absolute bars
# on the candidate: the longest owed-drain step, the longest RIB actor turn,
# and the summed credit gauge against receivers x (per-peer credit + one
# 1,024-row pass); unicast keeps no whole-table operation live.
OWED_STEP_MAX_MS = 50.0
ACTOR_TURN_MAX_MS = 250.0
RELEASE_TRIGGER = "rfc4724_selection_release"
RELEASE_SHAPE = {
    "receivers": 150,
    "rows_per_receiver": 150_000,
    "pause_ms": 30_000,
    "trigger": RELEASE_TRIGGER,
    "registered_peers": 153,
}
# (cell prefix, line label): the plain release and the release under churn.
RELEASE_KINDS = (("restart", "selection release"), ("restart-churn", "release under churn"))
# Cell 2: fewest sampler samples on the exhaustion plateau. The fixed shape
# reaches the row tree's credit at the 108th 500 ms chunk (about 53.5 s) and
# the byte tree's earlier, leaving 26 s or more, about 100 samples at 250 ms,
# before the 80 s resume. 40 samples (10 s) keeps a 2.5x margin and rejects a
# plateau reached only in the burst's last seconds or a stalled sampler.
PLATEAU_MIN_SAMPLES = 40
# Cell 2: the actual pause may differ this much from the configured one, and
# the runs of both arms this much from each other.
PAUSE_TOLERANCE_MS = 250.0
# Cell 3: no delivery gap over 1 s; p99 <= parent x 1.10.
MAX_GAP_MS = 1_000.0
P99_RATIO = 1.10
# Cell 6: a family measured more than 25% above its charge gets a ticket.
ESTIMATE_RATIO = 1.25
FAMILIES = ("unicast", "evpn")
FILL_FAMILIES = ("unicast", "evpn", "vpn", "flowspec")
WIRE_CHECKS = ("final_state_exact", "one_eor_before_burst", "no_session_resets")
RESTART_WIRE_CHECKS = ("final_state_exact", "eor_after_every_route", "no_session_resets")
# Cell 2's trigger. A selection release owes every private receiver its
# family whole and spends no ordinary credit, so it cannot witness exhaustion.
ORDINARY_TRIGGER = "ordinary_announce_burst"
# Cell 2 witness: each tree's per-peer ordinary credit, as (daemon-wide
# credit, per-peer floor, per-peer ceiling), in the unit of the gauge the
# tree exports: bytes where `bgp_rib_outbound_credit_bytes` exists, else rows.
# The clamps bind outside the fixed shape (under 16 or over 1,024 registered
# peers), which `check` can read, such as the reduced shape's 7.
BYTE_CREDIT = (CREDIT_TARGET, 2 << 20, 256 << 20)
ROW_CREDIT = (16_777_216, 8_192, 1_048_576)

# The fixed qualification shapes. A measured result with any other shape is
# not campaign evidence.
EXHAUST_SHAPE = {
    "receivers": 150,
    "rows_per_receiver": 150_000,
    "pause_ms": 80_000,
    "burst_interval_ms": 500,
    "trigger": ORDINARY_TRIGGER,
    "registered_peers": 153,
}
PAUSED_SHAPE = {"receivers": 150, "routes": 37_500, "seconds": 240, "round_ms": 2_000}
FILL_SHAPE = {"receivers": 150, "rows_per_receiver": 150_000}
# Cell 4: (cell, shape, peers, stall_ms) of the 8 lag cells and the restart cell.
PROBE_SET = sorted(
    [
        ("lag_stall", shape, peers, stall)
        for shape in ("unicast_private", "evpn_private")
        for peers in (150, 1_000)
        for stall in (500, 2_000)
    ]
    + [("restart_during_dump", "", 150, 0)]
)


class Invalid(Exception):
    """The evidence cannot support a verdict."""


def read(path: Path) -> dict:
    try:
        value = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
        raise Invalid(f"{path}: unreadable result ({error})") from error
    if not isinstance(value, dict):
        raise Invalid(f"{path}: not a JSON object")
    return value


def need(run: dict, path: str, what: str):
    """The value at dotted `path`; a missing or null field is INVALID."""
    value = run
    for key in path.split("."):
        value = value.get(key) if isinstance(value, dict) else None
        if value is None:
            raise Invalid(f"missing instrument {what}: {path}")
    return value


def number(run: dict, path: str, what: str) -> float:
    value = need(run, path, what)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise Invalid(f"{what}: {path} is not a number ({value!r})")
    return value


def same_number(runs: list[dict], path: str, what: str) -> float:
    """`path` in every run, which must agree: one binary's constant."""
    values = {number(run, path, f"{what} run {index}") for index, run in enumerate(runs)}
    if len(values) != 1:
        raise Invalid(f"{what}: {path} differs between repetitions ({sorted(values)})")
    return values.pop()


def records_failure(run: dict) -> bool:
    """Whether a result records the failure that made its run exit nonzero:
    a failed check, an unavailable fit, or a dirty probe episode."""
    checks = run.get("checks")
    if isinstance(checks, dict) and any(value is not True for value in checks.values()):
        return True
    if (
        run.get("cell") == "fill"
        and (run.get("estimate") or {}).get("bytes_per_queued_row") is None
    ):
        return True
    probes = run.get("probes") if run.get("cell") == "probes" else None
    return isinstance(probes, list) and any(
        not isinstance(probe, dict) or probe.get("dirty_episodes") != 0 for probe in probes
    )


def explained(run: dict, exit_record: dict | None, what: str) -> dict:
    """`run`, unless its cell exited nonzero for a reason the result does
    not record (a teardown error after the result was written)."""
    if exit_record is not None and not records_failure(run):
        raise Invalid(
            f"{what} exited {exit_record.get('exit')} after writing a result that records "
            "no failure"
        )
    return run


def result_file(cell: str) -> str:
    return "paused-evpn.json" if cell == "paused" else f"{cell}.json"


def identity(cell: str) -> tuple[str, str | None]:
    """The `cell` and `family` fields a cell's result must carry."""
    if cell == "paused":
        return "paused", "evpn"
    if cell == "probes":
        return "probes", None
    kind, family = cell.rsplit("-", 1)
    return kind, family


@dataclass
class Arm:
    """One arm: its repetitions, by path relative to the arm directory."""

    name: str
    directory: Path
    repetitions: dict[str, Path] = field(default_factory=dict)
    attempted: dict[str, set[str]] = field(default_factory=dict)
    sha256: str = ""

    @classmethod
    def load(cls, name: str, directory: Path) -> Arm:
        arm = cls(name, directory)
        hashes = set()
        for provenance in sorted(directory.rglob("provenance.jsonl")):
            rep = provenance.parent.relative_to(directory).as_posix()
            lines = [
                json.loads(line) for line in provenance.read_text().splitlines() if line.strip()
            ]
            if not lines or any(not isinstance(line, dict) for line in lines):
                raise Invalid(f"{name} repetition {rep}: empty or malformed provenance")
            shas = {line.get("sha256") for line in lines}
            if None in shas or len(shas) != 1:
                raise Invalid(f"{name} repetition {rep}: more than one harness binary")
            hashes |= shas
            arm.repetitions[rep] = provenance.parent
            arm.attempted[rep] = {cell for line in lines for cell in line.get("cells") or []}
        if not arm.repetitions:
            raise Invalid(f"{name}: no repetition (no provenance.jsonl under {directory})")
        paths = list(arm.repetitions.values())
        if any(a != b and a in b.parents for a in paths for b in paths):
            raise Invalid(f"{name}: a repetition directory contains another")
        if len(hashes) != 1:
            raise Invalid(f"{name}: repetitions used different harness binaries")
        arm.sha256 = hashes.pop()
        return arm

    def runs(self, cell: str) -> dict[str, dict]:
        """Each attempted repetition's result of `cell`; an OOM-killed paused
        cell reads as `{"oom": True}`."""
        file = result_file(cell)
        kind, family = identity(cell)
        runs = {}
        for rep, path in sorted(self.repetitions.items()):
            result, marker = path / file, path / f"{cell}-exit.json"
            if cell not in self.attempted[rep]:
                if result.exists() or marker.exists():
                    raise Invalid(f"{self.name} repetition {rep}: {file} not from a listed run")
                continue
            exit_record = read(marker) if marker.exists() else None
            if cell == "paused" and exit_record is not None and exit_record.get("oom") is True:
                # `paused` writes its result before teardown, so an OOM kill
                # can follow a result; the kill is the verdict either way.
                runs[rep] = {"oom": True}
            elif result.exists():
                run = read(result)
                if run.get("cell") != kind or run.get("family") != family:
                    raise Invalid(
                        f"{self.name} repetition {rep}: {file} holds a "
                        f"{run.get('cell')}/{run.get('family')} result"
                    )
                runs[rep] = explained(run, exit_record, f"{self.name} repetition {rep}: {cell}")
            elif exit_record is not None:
                raise Invalid(
                    f"{self.name} repetition {rep}: {cell} exited "
                    f"{exit_record.get('exit')} without a result"
                )
            else:
                raise Invalid(f"{self.name} repetition {rep}: {cell} attempted, no result")
        if not runs:
            raise Invalid(f"{self.name}: no repetition ran {cell}")
        return runs


def pair(parent: Arm, candidate: Arm, cell: str) -> tuple[list[dict], list[dict]]:
    runs = parent.runs(cell), candidate.runs(cell)
    if set(runs[0]) != set(runs[1]):
        raise Invalid(
            f"{cell}: parent repetitions {sorted(runs[0])} differ from candidate {sorted(runs[1])}"
        )
    return list(runs[0].values()), list(runs[1].values())


def measured(runs: list[dict], what: str, shape: dict | None = None) -> list[dict]:
    for run in runs:
        if run.get("mode") != "measured":
            raise Invalid(f"{what} result is a {run.get('mode')} run, not measured")
        for key, value in (shape or {}).items():
            actual = need(run, f"shape.{key}", what)
            if actual != value:
                raise Invalid(f"{what}: shape.{key} is {actual!r}, not the fixed {value!r}")
    return runs


def credit_unit(run: dict, what: str) -> tuple[str, int, float]:
    """The summed credit gauge's unit (bytes where the tree exports
    `bgp_rib_outbound_credit_bytes`, else rows), the per-peer credit in it
    at the run's registered peers, and one burst row's charge."""
    peers = number(run, "shape.registered_peers", what)
    if peers <= 0:
        raise Invalid(f"{what}: {peers} registered peers")
    if need(run, "witness", what).get("peak_credit_bytes") is not None:
        credit, row = BYTE_CREDIT, number(run, "row_size_of", what) + ANNOUNCED_ROW_OVERHEAD
        unit = "bytes"
    else:
        unit, credit, row = "rows", ROW_CREDIT, 1
    return unit, min(max(credit[0] // int(peers), credit[1]), credit[2]), row


def exhaustion(run: dict, what: str) -> str:
    """What witnessed that every burst receiver spent its ordinary credit in
    `run`; INVALID when nothing did."""
    if need(run, "shape.trigger", what) != ORDINARY_TRIGGER:
        raise Invalid(
            f"{what}: trigger {run['shape']['trigger']!r} is not {ORDINARY_TRIGGER!r}; "
            "it cannot exhaust ordinary credit"
        )
    receivers = number(run, "witness.receivers", what)
    if receivers != number(run, "shape.receivers", what):
        raise Invalid(
            f"{what}: witness.receivers {receivers} is not shape.receivers "
            f"{run['shape']['receivers']}"
        )
    refused = number(run, "witness.refused_receivers", what)
    peers = number(run, "shape.registered_peers", what)
    rows = number(run, "witness.peak_credit_rows", what)
    if receivers <= 0 or peers < receivers:
        raise Invalid(f"{what}: {receivers} burst receivers among {peers} registered peers")
    # The whole burst must be in the RIB before the pause deadline, or the
    # readers stayed paused until it was and the pause ran long.
    pause = number(run, "shape.pause_ms", what)
    sent = number(run, "timing.release_sent_ms", what)
    if sent >= pause:
        raise Invalid(
            f"{what}: burst submission ended at {sent:.0f} ms, not before the {pause:.0f} ms "
            "pause deadline"
        )
    actual = number(run, "timing.actual_pause_ms", what)
    if abs(actual - pause) > PAUSE_TOLERANCE_MS:
        raise Invalid(
            f"{what}: actual pause {actual:.0f} ms is more than {PAUSE_TOLERANCE_MS:.0f} ms "
            f"from the configured {pause:.0f} ms"
        )
    # The gauge sums every peer. Every burst row charges the same `row`
    # (bytes: element plus overhead; rows: 1) and admission stops a peer
    # below its credit plus one row, so a peer holds at most
    # full = ceil(credit / row) rows and holds exactly that once it reached
    # its credit. Paused, the burst receivers' sum stays constant until the
    # readers resume, while the healthy receiver's churn row (a unicast row)
    # comes and goes. So the plateau, the samples from the first at or above
    # the churn-free minimum until the resume was issued, must sit at exactly
    # receivers x full x row at its minimum, churn-free readings included,
    # the churn-free minimum must be that minimum, and no sample may exceed
    # it by more than one healthy row. Anything else is INVALID. Credit
    # refusals are reported but are no witness: the same reason counts a
    # refusal for a live whole-table operation with nothing charged.
    unit, limit, row = credit_unit(run, what)
    peak = number(run, "witness.peak_credit_bytes", what) if unit == "bytes" else rows
    healthy = 1 if unit == "rows" else (
        number(run, "healthy_row_size_of", what) + ANNOUNCED_ROW_OVERHEAD
    )
    full = -(-limit // int(row))
    expected = receivers * full * row
    shape = f"{receivers} receivers x {full} rows at credit {limit} {unit}"
    refusals = f"credit refusals on {refused}/{receivers} receivers, report-only"
    samples = number(run, "witness.plateau.samples", what)
    start = number(run, "witness.plateau.start_ms", what)
    end = number(run, "witness.plateau.end_ms", what)
    if samples < PLATEAU_MIN_SAMPLES:
        raise Invalid(
            f"{what}: {samples:.0f} plateau samples ({start:.0f}-{end:.0f} ms), fewer than "
            f"{PLATEAU_MIN_SAMPLES}: credit was reached too late, or the sampler stalled"
        )
    quiet = number(run, "witness.plateau.quiet.readings", what)
    stopped = number(run, "witness.plateau.quiet.churn_stopped_ms", what)
    quiet_end = number(run, "witness.plateau.quiet.end_ms", what)
    resume = number(run, "witness.plateau.resume_issued_ms", what)
    if quiet < 1 or not start <= stopped < quiet_end <= resume:
        raise Invalid(
            f"{what}: {quiet:.0f} churn-free readings over {stopped:.0f}-{quiet_end:.0f} ms, not "
            f"inside the plateau {start:.0f} ms to the {resume:.0f} ms resume"
        )
    number(run, "witness.plateau.quiet.churn_delivered_ms", what)
    low = number(run, "witness.plateau.min", what)
    high = number(run, "witness.plateau.max", what)
    calm = number(run, "witness.plateau.quiet.min", what)
    if low < expected:
        flips = run["witness"].get("owing_flips_total")
        raise Invalid(
            f"{what}: credit gauge plateau min {low:.0f} {unit} < {expected:.0f} = {shape}: a "
            f"receiver below its credit ({refusals}; {flips} owe-whole flips are not a "
            "witness); the cell never exhausted credit"
        )
    if low != expected:
        raise Invalid(
            f"{what}: credit gauge plateau min {low:.0f} {unit} is not {expected:.0f} = "
            f"{shape}: more than every receiver at its credit, so the sum cannot show each "
            f"one reached it ({refusals})"
        )
    if calm != low:
        raise Invalid(
            f"{what}: churn-free min {calm:.0f} {unit} is not the plateau min {low:.0f}: the "
            "churn hold did not separate the healthy row"
        )
    if high > expected + healthy:
        raise Invalid(
            f"{what}: credit gauge plateau max {high:.0f} {unit} > {expected + healthy:.0f} = "
            f"{shape} + one healthy row: more than every receiver at its credit ({refusals})"
        )
    return (
        f"credit gauge plateau {low:.0f}-{high:.0f} {unit} over {samples:.0f} samples "
        f"({start:.0f}-{end:.0f} ms), churn-free min {calm:.0f} = {shape}, max within one "
        f"healthy row; peak {peak:.0f} ({refusals})"
    )


def wire_failure(runs: list[dict], arm: str, checks: tuple[str, ...]) -> str | None:
    """The first wire FAIL reason, or None when every run passed `checks`;
    INVALID when a run lacks one."""
    for index, run in enumerate(runs):
        for check in checks:
            need(run, f"checks.{check}", f"{arm} run {index}")
    for index, run in enumerate(runs):
        for check in checks:
            if run["checks"][check] is not True:
                return f"{arm} run {index}: {check} failed"
    return None


def single_arm_exhaust(runs: list[dict], arm: str) -> tuple[str | None, str]:
    """Raise INVALID for a missing witness in any run, then return the first
    wire FAIL reason (None when every run passed its wire checks) and the
    weakest run's witness."""
    witnesses = [exhaustion(run, f"{arm} run {index}") for index, run in enumerate(runs)]
    return wire_failure(runs, arm, WIRE_CHECKS), witnesses[0]


def recovery(runs: list[dict], arm: str) -> float:
    values = []
    for index, run in enumerate(runs):
        value = number(run, "timing.recovery_ms", f"{arm} run {index}")
        if value <= 0:
            raise Invalid(f"{arm} run {index}: nonpositive recovery")
        values.append(value)
    return statistics.median(values)


def exhaust_runs(parent: Arm, candidate: Arm, family: str) -> dict[str, list[dict]]:
    cell = f"exhaust-{family}"
    runs = pair(parent, candidate, cell)
    arms = {
        "parent": measured(runs[0], f"parent {cell}", EXHAUST_SHAPE),
        "candidate": measured(runs[1], f"candidate {cell}", EXHAUST_SHAPE),
    }
    # Arm identity: the parent is a row-credit tree and the candidate a
    # byte-credit one, so two builds of one tree cannot pass as the pair.
    for arm, arm_runs in arms.items():
        for index, run in enumerate(arm_runs):
            present = (run.get("witness") or {}).get("peak_credit_bytes") is not None
            if present != (arm == "candidate"):
                raise Invalid(
                    f"{arm} {cell} run {index}: byte credit gauge "
                    f"{'present' if present else 'absent'}; the parent must lack "
                    "bgp_rib_outbound_credit_bytes and the candidate must export it"
                )
    # Arms are comparable only over the same actual pause.
    pauses = [
        number(run, "timing.actual_pause_ms", f"{arm} {cell} run {index}")
        for arm, arm_runs in arms.items()
        for index, run in enumerate(arm_runs)
    ]
    if max(pauses) - min(pauses) > PAUSE_TOLERANCE_MS:
        raise Invalid(
            f"{cell}: actual pauses differ by {max(pauses) - min(pauses):.0f} ms across the "
            f"arms' runs, more than {PAUSE_TOLERANCE_MS:.0f} ms"
        )
    return arms


def cell2(parent: Arm, candidate: Arm, family: str) -> tuple[str, str]:
    arms = exhaust_runs(parent, candidate, family)
    single = {arm: single_arm_exhaust(runs, arm) for arm, runs in arms.items()}
    failures = [reason for reason, _ in single.values() if reason is not None]
    # A run that never settled has no recovery time; its wire FAIL stands
    # without any timing comparison.
    if failures:
        return "FAIL", "; ".join(failures)
    # The bar: every candidate run exact within 60 s of the resume. The
    # parent-relative rules on recovery and on the drain are report-only.
    drain = max(
        number(run, "timing.drain_after_resume_ms", f"candidate run {index}")
        for index, run in enumerate(arms["candidate"])
    )
    times = {arm: recovery(runs, arm) for arm, runs in arms.items()}
    rule = max(times["parent"] * RECOVERY_RATIO, times["parent"] + RECOVERY_SLACK_MS)
    report = (
        f"report-only, not a bar: recovery candidate {times['candidate']:.0f} ms vs parent "
        f"{times['parent']:.0f} ms (ratio {times['candidate'] / times['parent']:.2f}; the old "
        f"rule would allow {rule:.0f} ms); {drain_report(arms)}"
    )
    line = f"drain after resume {drain:.0f} ms (bar {DRAIN_AFTER_RESUME_MAX_MS:.0f} ms)"
    if drain > DRAIN_AFTER_RESUME_MAX_MS:
        return "FAIL", f"drain after resume over bar: {line}; {report}"
    witnessed = "; ".join(f"{arm} {witness}" for arm, (_, witness) in single.items())
    return (
        "PASS",
        f"exhaustion witnessed ({witnessed}); wire exact, ordered, no resets; {line}; {report}",
    )


def drain_report(arms: dict[str, list[dict]]) -> str:
    """The recovery rule applied to `drain_after_resume_ms`, report-only:
    `recovery_ms` includes the fixed pause, which dilutes the bar."""
    drains = {}
    for arm, runs in arms.items():
        values = [(run.get("timing") or {}).get("drain_after_resume_ms") for run in runs]
        if not all(isinstance(v, int | float) and not isinstance(v, bool) for v in values):
            return "report-only drain after resume: not recorded in every run"
        drains[arm] = statistics.median(values)
    parent, candidate = drains["parent"], drains["candidate"]
    bar = max(parent * RECOVERY_RATIO, parent + RECOVERY_SLACK_MS)
    ratio = f"{candidate / parent:.2f}" if parent > 0 else "n/a"
    return (
        f"report-only, not a bar: drain after resume candidate {candidate:.0f} ms vs parent "
        f"{parent:.0f} ms (ratio {ratio}; the recovery rule would allow {bar:.0f} ms)"
    )


def healthy_gap(run: dict, what: str) -> tuple[float, str]:
    """The healthy receiver's longest delivery gap, outside the harness's
    own churn-free window, and a note naming the window it excluded."""
    if not number(run, "unaffected.injected", what) or not number(
        run, "unaffected.delivered", what
    ):
        raise Invalid(f"{what}: the healthy receiver got no churn")
    gap = number(run, "unaffected.max_gap_ms", what)
    raw = number(run, "unaffected.max_gap_raw_ms", what)
    start = number(run, "unaffected.quiet_excluded.from_ms", what)
    end = number(run, "unaffected.quiet_excluded.to_ms", what)
    span = number(run, "unaffected.quiet_excluded.span_ms", what)
    return gap, (
        f"max gap {gap:.0f} ms ({raw:.0f} ms before excluding the {span:.0f} ms churn-free "
        f"window {start:.0f}-{end:.0f} ms)"
    )


def cell3(parent: Arm, candidate: Arm, family: str) -> tuple[str, str]:
    arms = exhaust_runs(parent, candidate, family)
    p99, gaps = {}, []
    for arm, runs in arms.items():
        values = []
        for index, run in enumerate(runs):
            what = f"{arm} run {index}"
            if not number(run, "unaffected.injected", what) or not number(
                run, "unaffected.delivered", what
            ):
                raise Invalid(f"{what}: the healthy receiver got no churn")
            values.append(number(run, "unaffected.p99_latency_ms", what))
            if arm == "candidate":
                gaps.append(healthy_gap(run, what))
            else:
                number(run, "unaffected.max_gap_ms", what)
        p99[arm] = statistics.median(values)
    gap, note = max(gaps)
    failures = []
    if gap > MAX_GAP_MS:
        failures.append(f"candidate delivery gap {gap:.0f} ms > {MAX_GAP_MS:.0f} ms ({note})")
    if p99["candidate"] > p99["parent"] * P99_RATIO:
        failures.append(
            f"candidate p99 {p99['candidate']:.1f} ms > parent {p99['parent']:.1f} ms x {P99_RATIO}"
        )
    line = f"{note}; p99 {p99['candidate']:.1f} ms vs parent {p99['parent']:.1f} ms"
    return ("FAIL", "; ".join(failures)) if failures else ("PASS", line)


def paused_oom(run: dict) -> bool:
    """An OOM-killed paused-reader run: the runner's marker, or a kill the
    cgroup counted before the result was written."""
    return run.get("oom") is True or (run.get("memory") or {}).get("cgroup_oom_kill") not in (
        None,
        "0",
    )


def paused_run(run: dict, arm: str) -> None:
    """Validate one paused-reader result that was not OOM-killed."""
    measured([run], f"{arm} paused-evpn", PAUSED_SHAPE)
    # A receiver that disconnected frees its queued state, so the memory
    # comparison needs proof every session stayed up for the whole run.
    if need(run, "checks.no_session_resets", arm) is not True:
        raise Invalid(f"{arm}: a paused receiver's session reset; its memory is not comparable")
    down = need(run, "not_established", arm)
    if down:
        raise Invalid(f"{arm}: receivers not Established at the end: {down}")
    swap = need(run, "memory.cgroup_swap_max", arm)
    if swap != "0":
        raise Invalid(f"{arm}: swap not fenced (memory.swap.max={swap})")
    limit = need(run, "memory.cgroup_memory_max", arm)
    if limit != str(CELL1_CGROUP_MAX):
        raise Invalid(f"{arm}: cgroup limit {limit}, not 12 GiB")
    number(run, "memory.cgroup_memory_peak_bytes", f"{arm} cgroup memory.peak")
    number(run, "memory.vmhwm_kib", f"{arm} VmHWM")
    need(run, "memory.cgroup_oom_kill", arm)


def cell1(parent: Arm, candidate: Arm) -> tuple[str, str]:
    runs = dict(zip(("parent", "candidate"), pair(parent, candidate, "paused"), strict=True))
    # The candidate-only bars come first, so no parent evidence can weaken them.
    if any(paused_oom(run) for run in runs["candidate"]):
        return "FAIL", "candidate OOM in the 12 GiB cgroup"
    for run in runs["candidate"]:
        paused_run(run, "candidate")
    credit = max(
        number(run, "memory.peak_credit_bytes", "candidate bgp_rib_outbound_credit_bytes")
        for run in runs["candidate"]
    )
    row = same_number(runs["candidate"], "row_size_of", "candidate paused-evpn")
    credit_bar = CREDIT_TARGET + PEERS * PASS_ROWS * (row + ANNOUNCED_ROW_OVERHEAD)
    failures = []
    if credit > credit_bar:
        failures.append(f"credit bytes peak {credit / GIB:.3f} GiB > {credit_bar / GIB:.3f} GiB")
    try:
        if any(paused_oom(run) for run in runs["parent"]):
            raise Invalid("parent OOM: no parent peak to compare against")
        for run in runs["parent"]:
            paused_run(run, "parent")
    except Invalid as error:
        if failures:
            return "FAIL", f"{failures[0]} (parent evidence: {error})"
        raise
    peaks = {
        arm: statistics.median(run["memory"]["cgroup_memory_peak_bytes"] for run in arm_runs)
        for arm, arm_runs in runs.items()
    }
    if peaks["candidate"] > peaks["parent"] - CELL1_MARGIN:
        failures.insert(
            0,
            f"candidate cgroup peak {peaks['candidate'] / GIB:.2f} GiB > parent "
            f"{peaks['parent'] / GIB:.2f} GiB - 1.5 GiB",
        )
    hwm = max(run["memory"]["vmhwm_kib"] for run in runs["candidate"])
    line = (
        f"median cgroup peak {peaks['candidate'] / GIB:.2f} vs parent "
        f"{peaks['parent'] / GIB:.2f} GiB; credit bytes peak {credit / GIB:.3f} GiB "
        f"(bar {credit_bar / GIB:.3f}); VmHWM {hwm / 2**20:.2f} GiB"
    )
    return ("FAIL", "; ".join(failures)) if failures else ("PASS", line)


def probe_key(probe: dict, what: str) -> tuple:
    return (
        need(probe, "cell", what),
        probe.get("shape") or "",
        need(probe, "peers", what),
        probe.get("stall_ms") or 0,
    )


def probe_set(run: dict, what: str) -> list[dict]:
    cells = need(run, "probes", what)
    if not isinstance(cells, list):
        raise Invalid(f"{what}: probes is not a list")
    if sorted(probe_key(probe, what) for probe in cells) != PROBE_SET:
        raise Invalid(f"{what}: probe cells are not the fixed 9-cell set")
    for probe in cells:
        if probe["cell"] == "restart_during_dump" and probe.get("table") != 100_000:
            raise Invalid(f"{what}: restart probe table is not 100,000 routes")
    return cells


def cell4(parent: Arm, candidate: Arm) -> tuple[str, str]:
    parent_runs, candidate_runs = pair(parent, candidate, "probes")
    probes = []
    for arm, runs in (("parent", parent_runs), ("candidate", candidate_runs)):
        for index, run in enumerate(measured(runs, f"{arm} probes")):
            cells = probe_set(run, f"{arm} probes run {index}")
            if arm == "candidate":
                probes += cells
    dirty = [p for p in probes if number(p, "dirty_episodes", "candidate probe") != 0]
    parent_dirty = sum(
        probe.get("dirty_episodes") or 0 for run in parent_runs for probe in run["probes"]
    )
    if dirty:
        cells = ", ".join(f"{p.get('cell')}/{p.get('shape', '')}/{p.get('peers')}" for p in dirty)
        return "FAIL", f"dirty episodes in {cells}"
    return "PASS", f"0 dirty episodes in {len(probes)} probe cells (parent total {parent_dirty})"


def cell6(parent: Arm, candidate: Arm) -> tuple[str, str]:
    notes, flagged = [], []
    for family in FILL_FAMILIES:
        cell = f"fill-{family}"
        parent_runs, candidate_runs = pair(parent, candidate, cell)
        measured(parent_runs, f"parent {cell}", FILL_SHAPE)
        measured(candidate_runs, f"candidate {cell}", FILL_SHAPE)
        # Every candidate repetition needs its fit; the median is reported.
        estimate = statistics.median(
            number(run, "estimate.bytes_per_queued_row", f"candidate {cell} run {index}")
            for index, run in enumerate(candidate_runs)
        )
        charged = same_number(candidate_runs, "row_size_of", f"candidate {cell}")
        charged += ANNOUNCED_ROW_OVERHEAD
        # The parent's fit is context only: a tree without the credit-rows
        # gauge has none.
        parent_fits = [
            value
            for run in parent_runs
            if isinstance(
                value := (run.get("estimate") or {}).get("bytes_per_queued_row"), int | float
            )
        ]
        notes.append(
            f"{family} {estimate:.0f} B/row vs charge {charged:.0f}"
            + (
                f" (parent {statistics.median(parent_fits):.0f}, {len(parent_fits)}/"
                f"{len(parent_runs)} fits)"
                if parent_fits
                else ""
            )
        )
        if estimate > charged * ESTIMATE_RATIO:
            flagged.append(family)
    tail = f"; follow-up ticket for {', '.join(flagged)}" if flagged else ""
    return "PASS", "report-only: " + "; ".join(notes) + tail


def churn_inside_drain(run: dict, what: str) -> str:
    """The churn variant's withdrawals and re-announcements must have been
    sent after the release and before the last receiver's End-of-RIB, or the
    run did not churn during the drain: INVALID."""
    withdrawn = number(run, "churn.withdrawn", what)
    again = number(run, "churn.re_announced", what)
    started = number(run, "churn.started_ms", what)
    sent = number(run, "churn.sent_ms", what)
    release = number(run, "timing.release_sent_ms", what)
    last = number(run, "timing.last_eor_ms", what)
    if withdrawn < 1 or not release <= started <= sent < last:
        raise Invalid(
            f"{what}: {withdrawn:.0f} withdrawals sent {started:.0f}-{sent:.0f} ms, not inside "
            f"the drain from the {release:.0f} ms release to the {last:.0f} ms last End-of-RIB"
        )
    return (
        f"{withdrawn:.0f} withdrawn and {again:.0f} re-announced at {started:.0f}-{sent:.0f} ms, "
        f"inside the drain ({release:.0f}-{last:.0f} ms)"
    )


def longest_bounds(run: dict, path: str, what: str) -> list[tuple[str, float, float | None]]:
    """Per label, the bucket edges around a histogram's longest observation
    in the run: (label, above ms, at most ms or None past the top edge)."""
    entries = need(run, path, what)
    if not isinstance(entries, dict):
        raise Invalid(f"{what}: {path} is not an object")
    bounds = []
    for label, entry in entries.items():
        at_most = entry.get("at_most_ms") if isinstance(entry, dict) else None
        if at_most is not None and (isinstance(at_most, bool) or not isinstance(at_most, int | float)):
            raise Invalid(f"{what}: {path}.{label}.at_most_ms is not a number")
        bounds.append((label, number(entry, "above_ms", f"{what} {path}.{label}"), at_most))
    return bounds


def turn_bar(run: dict, what: str) -> tuple[str | None, str | None, str]:
    """Bar 2 for one run: (FAIL reason, undecided reason, reading). A poll
    holds whole turns, so a longest poll within the bar passes every turn;
    a turn or work unit whose bucket lies above the bar fails; anything
    else is undecided, since a poll can hold many turns and resync ticks
    have no turn instrument."""
    poll = number(run, "actor.slice_max_us.actor_poll", what) / 1e3
    over, top = [], []
    for path in ("actor.turn_longest_ms", "actor.work_longest_ms"):
        for label, above, at_most in longest_bounds(run, path, what):
            if above >= ACTOR_TURN_MAX_MS:
                over.append(f"{label} over {above:.0f} ms")
            top.append((above, at_most, label))
    worst = max(top, default=(0.0, 0.0, "none"))
    reading = (
        f"longest actor poll {poll:.1f} ms; longest turn or work unit {worst[2]} in "
        f"({worst[0]:.0f}, {'inf' if worst[1] is None else f'{worst[1]:.0f}'}] ms"
    )
    if over:
        return f"{what}: {', '.join(over)} > {ACTOR_TURN_MAX_MS:.0f} ms ({reading})", None, reading
    if poll <= ACTOR_TURN_MAX_MS:
        return None, None, reading
    return None, (
        f"{what}: longest actor poll {poll:.1f} ms > {ACTOR_TURN_MAX_MS:.0f} ms but no turn is "
        f"provably over it ({reading}): a poll can hold many turns"
    ), reading


def release_runs(candidate: Arm, cell: str) -> list[dict]:
    return measured(list(candidate.runs(cell).values()), f"candidate {cell}", RELEASE_SHAPE)


def cell7(candidate: Arm, kind: str, family: str) -> tuple[str, str]:
    """Bars 2, 3, 4 and 6 on the candidate's release runs of one kind."""
    cell = f"{kind}-{family}"
    runs = release_runs(candidate, cell)
    failures, undecided, notes = [], [], []
    wire = wire_failure(runs, f"candidate {cell}", RESTART_WIRE_CHECKS)
    if wire is not None:
        failures.append(wire)
    for index, run in enumerate(runs):
        what = f"candidate {cell} run {index}"
        if kind == "restart-churn" and wire is None:
            notes.append(churn_inside_drain(run, what))
        failure, open_question, reading = turn_bar(run, what)
        failures += [failure] if failure else []
        undecided += [open_question] if open_question else []
        gap, note = healthy_gap(run, what)
        if gap > MAX_GAP_MS:
            failures.append(f"{what}: healthy delivery gap {gap:.0f} ms > {MAX_GAP_MS:.0f} ms")
        unit, limit, row = credit_unit(run, what)
        receivers = number(run, "shape.receivers", what)
        bound = receivers * (limit + PASS_ROWS * row)
        if unit == "bytes":
            peak = number(run, "witness.peak_credit_bytes", what)
        else:
            peak = number(run, "drain_gauges.peak_credit_rows", what)
        if peak > bound:
            failures.append(
                f"{what}: credit {unit} peak {peak:.0f} > {bound:.0f} = {receivers:.0f} x "
                f"({limit} + {PASS_ROWS} x {row:.0f})"
            )
        operations = number(run, "drain_gauges.peak_operations_live", what)
        if family == "unicast" and operations != 0:
            failures.append(
                f"{what}: {operations:.0f} live whole-table operations during the drain, not 0"
            )
        notes.append(
            f"{reading}; {note}; credit {unit} peak {peak:.0f} (bound {bound:.0f}); live "
            f"whole-table operations peak {operations:.0f}"
            + ("" if family == "unicast" else " (report-only: the gauge is unlabeled)")
        )
    if failures:
        return "FAIL", "; ".join(failures + undecided)
    if undecided:
        raise Invalid("; ".join(undecided))
    return "PASS", "wire exact, ordered, no resets; " + "; ".join(notes)


def cell7_step(candidate: Arm) -> tuple[str, str]:
    """Bar 1 over every release run: the longest owed-drain step."""
    failures, undecided, longest = [], [], 0.0
    for kind, _ in RELEASE_KINDS:
        for family in FAMILIES:
            cell = f"{kind}-{family}"
            for index, run in enumerate(release_runs(candidate, cell)):
                what = f"candidate {cell} run {index}"
                if (run.get("actor") or {}).get("owed_drain_step_longest_ms") is None:
                    raise Invalid(
                        f"{what}: no instrument: no product metric times one owed-drain step "
                        "(actor.owed_drain_step_longest_ms is null)"
                    )
                bounds = longest_bounds(run, "actor.owed_drain_step_longest_ms", what)
                if not bounds:
                    raise Invalid(f"{what}: no owed-drain step observed")
                for label, above, at_most in bounds:
                    longest = max(longest, above)
                    if above >= OWED_STEP_MAX_MS:
                        failures.append(f"{what}: {label} step over {above:.0f} ms")
                    elif at_most is None or at_most > OWED_STEP_MAX_MS:
                        undecided.append(f"{what}: {label} step in ({above:.0f}, {at_most}] ms")
    if failures:
        return "FAIL", f"owed-drain step over {OWED_STEP_MAX_MS:.0f} ms: " + "; ".join(failures)
    if undecided:
        raise Invalid("bucket resolution cannot judge 50 ms: " + "; ".join(undecided))
    return "PASS", f"every owed-drain step at most {OWED_STEP_MAX_MS:.0f} ms"


CELLS = (
    ["cell 1 paused-reader evpn"]
    + [
        f"cell {n} {kind} {family}"
        for family in FAMILIES
        for n, kind in ((2, "exhaustion"), (3, "unaffected peer"))
    ]
    + ["cell 4 lag and restart probes", "cell 6 bytes per queued row"]
    + ["cell 7 release owed-drain step"]
    + [f"cell 7 {label} {family}" for _, label in RELEASE_KINDS for family in FAMILIES]
)


def verdicts(parent_dir: Path, candidate_dir: Path) -> list[tuple[str, str, str]]:
    try:
        parent = Arm.load("parent", parent_dir)
        candidate = Arm.load("candidate", candidate_dir)
        if parent.sha256 == candidate.sha256:
            raise Invalid("parent and candidate used the same harness binary")
    except (Invalid, json.JSONDecodeError, OSError) as error:
        return [(name, "INVALID", f"arm evidence: {error}") for name in CELLS]
    cells = [("cell 1 paused-reader evpn", lambda: cell1(parent, candidate))]
    for family in FAMILIES:
        cells.append((f"cell 2 exhaustion {family}", lambda f=family: cell2(parent, candidate, f)))
        cells.append(
            (f"cell 3 unaffected peer {family}", lambda f=family: cell3(parent, candidate, f))
        )
    cells.append(("cell 4 lag and restart probes", lambda: cell4(parent, candidate)))
    cells.append(("cell 6 bytes per queued row", lambda: cell6(parent, candidate)))
    cells.append(("cell 7 release owed-drain step", lambda: cell7_step(candidate)))
    for kind, label in RELEASE_KINDS:
        for family in FAMILIES:
            cells.append(
                (f"cell 7 {label} {family}", lambda k=kind, f=family: cell7(candidate, k, f))
            )
    results = []
    for name, evaluate in cells:
        try:
            verdict, reason = evaluate()
        except Invalid as error:
            verdict, reason = "INVALID", str(error)
        except (KeyError, TypeError, ValueError) as error:
            verdict, reason = "INVALID", f"malformed result: {error!r}"
        results.append((name, verdict, reason))
    return results


def release_readings(run: dict) -> str:
    """Report-only: what `check` shows of a release run's instruments; the
    bars on them are cell 7's."""
    actor = run.get("actor") or {}
    gauges = run.get("drain_gauges") or {}
    poll = (actor.get("slice_max_us") or {}).get("actor_poll")
    step = actor.get("owed_drain_step_longest_ms")
    return (
        "report-only: longest actor poll "
        + ("not recorded" if poll is None else f"{poll / 1e3:.1f} ms")
        + f"; owed-drain step {'no instrument' if step is None else step}"
        + f"; live operations peak {gauges.get('peak_operations_live', 'not recorded')}"
        + f"; credit rows peak {gauges.get('peak_credit_rows', 'not recorded')}"
    )


def check(directory: Path) -> list[tuple[str, str, str]]:
    results = []
    kinds = (
        ("exhaust", "exhaustion"),
        ("restart", "restart burst"),
        ("restart-churn", "restart burst under churn"),
    )
    for kind, label in kinds:
        for family in FAMILIES:
            cell = f"{kind}-{family}"
            name = f"{cell}.json"
            try:
                # A failure marker without its result, or beside a result that
                # records no failure, is never a passing run.
                for marker in sorted(directory.rglob(f"{cell}-exit.json")):
                    if not (marker.parent / name).exists():
                        raise Invalid(f"{marker.parent}: {cell} exited without a result")
                runs = []
                for path in sorted(directory.rglob(name)):
                    marker = path.parent / f"{cell}-exit.json"
                    exit_record = read(marker) if marker.exists() else None
                    runs.append(explained(read(path), exit_record, f"{path.parent}: {cell}"))
                if not runs:
                    continue
                if kind == "exhaust":
                    reason, witness = single_arm_exhaust(runs, "arm")
                    passed = f"{witness}; wire exact, ordered, no resets"
                else:
                    # No witness: a selection release spends no ordinary credit.
                    reason = wire_failure(runs, "arm", RESTART_WIRE_CHECKS)
                    notes = [release_readings(run) for run in runs]
                    if kind == "restart-churn" and reason is None:
                        notes = [
                            churn_inside_drain(run, f"run {index}") + "; " + note
                            for index, (run, note) in enumerate(zip(runs, notes, strict=True))
                        ]
                    passed = "wire exact, ordered, no resets (no exhaustion witness); " + (
                        "; ".join(notes)
                    )
                verdict, reason = ("FAIL", reason) if reason else ("PASS", passed)
            except Invalid as error:
                verdict, reason = "INVALID", str(error)
            results.append((f"{label} {family}", verdict, reason))
    return results


def report(results: list[tuple[str, str, str]]) -> int:
    for name, verdict, reason in results:
        print(f"{verdict:<7} {name}: {reason}")
    found = {verdict for _, verdict, _ in results}
    return 1 if "FAIL" in found else 2 if "INVALID" in found or not results else 0


def main(argv: list[str]) -> int:
    if len(argv) == 4 and argv[1] == "analyze":
        return report(verdicts(Path(argv[2]), Path(argv[3])))
    if len(argv) == 3 and argv[1] == "check":
        return report(check(Path(argv[2])))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
