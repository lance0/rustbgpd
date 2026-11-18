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

Each gated cell gets one ``PASS``, ``FAIL`` or ``INVALID`` line; the analyzer
never stops at the first failing cell. Exit status: 1 when any cell FAILs,
else 2 when any is INVALID, else 0. Optional release cells print REPORT
lines with their observations and do not contribute to either verdict.

``check`` applies the single-arm parts (wire checks and exhaustion witness)
to one result set, measured or not, for correctness runs. It also applies
the wire checks to any ``restart-<family>.json`` (the RFC 4724 restart
burst) and ``restart-churn-<family>.json`` (the same with churn during its
drain, whose timing it checks), and reports their instruments; their bars
are cell 7's, which ``analyze`` judges on the candidate alone.
"""

from __future__ import annotations

import json
import math
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path

OPTIONAL_RELEASES = ("release-mixed", "release-timer")
OPTIONAL_RELEASE_CHECKS = {
    "armed_after_staging",
    "release_reason",
    "ownership",
    "wire_exact",
    "eor_order",
    "all_markers_after_trigger",
    "sessions_established",
}

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
# the summed credit-rows gauge at most receivers x (per-peer credit + one
# pass), and every row held toward the paused receivers charged; unicast
# keeps no whole-table operation live.
OWED_STEP_MAX_MS = 50.0
ACTOR_TURN_MAX_MS = 250.0
# Bar 6's charge witness divides queued bytes by one announced row's wire
# size, so a release's UPDATEs must each carry one row, all of one size
# within this fraction of the smallest.
ROW_BYTES_TOLERANCE = 0.01
# Families the candidate drains by row cursor in charged ordinary envelopes.
# An owed family outside them goes out as whole-table operations, which
# charge no rows by design, so the charge witness is report-only there.
CURSOR_FAMILIES = ("unicast",)
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
# peers), which `check` can read, such as the reduced shape's 7. A row-credit
# tree's constants come from the run's `row_credit` record, which the harness
# mirrors from the RIB (a harness test fails when they drift).
BYTE_CREDIT = (CREDIT_TARGET, 2 << 20, 256 << 20)
ROW_CREDIT_KEYS = ("DAEMON_ROW_CREDIT", "MIN_ROW_CREDIT", "MAX_ROW_CREDIT")
# Cell 7: the inbox round-trip probe runs on both arms; bar 2 PASS needs it
# within the turn bar too. The excluded churn-free window may span at most
# this many times its configured length.
EXCLUDED_SPAN_RATIO = 2.0

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
    if cell in ("probes", *OPTIONAL_RELEASES):
        return cell, None
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

    def run(self, rep: str, cell: str) -> dict | None:
        """Repetition `rep`'s result of `cell`, None when it did not attempt
        the cell; an OOM-killed paused cell reads as `{"oom": True}`."""
        file = result_file(cell)
        kind, family = identity(cell)
        path = self.repetitions[rep]
        result, marker = path / file, path / f"{cell}-exit.json"
        if cell not in self.attempted[rep]:
            if result.exists() or marker.exists():
                raise Invalid(f"{self.name} repetition {rep}: {file} not from a listed run")
            return None
        exit_record = read(marker) if marker.exists() else None
        if cell == "paused" and exit_record is not None and exit_record.get("oom") is True:
            # `paused` writes its result before teardown, so an OOM kill
            # can follow a result; the kill is the verdict either way.
            return {"oom": True}
        if result.exists():
            run = read(result)
            if run.get("cell") != kind or run.get("family") != family:
                raise Invalid(
                    f"{self.name} repetition {rep}: {file} holds a "
                    f"{run.get('cell')}/{run.get('family')} result"
                )
            return explained(run, exit_record, f"{self.name} repetition {rep}: {cell}")
        if exit_record is not None:
            raise Invalid(
                f"{self.name} repetition {rep}: {cell} exited "
                f"{exit_record.get('exit')} without a result"
            )
        raise Invalid(f"{self.name} repetition {rep}: {cell} attempted, no result")

    def runs(self, cell: str) -> dict[str, dict]:
        """Each attempted repetition's result of `cell`; INVALID when any
        attempted repetition has none, or none attempted it."""
        runs = {
            rep: run
            for rep in sorted(self.repetitions)
            if (run := self.run(rep, cell)) is not None
        }
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


def witness_of(run: dict, what: str) -> dict:
    witness = need(run, "witness", what)
    if not isinstance(witness, dict):
        raise Invalid(f"{what}: witness is not an object ({witness!r})")
    return witness


def per_peer(run: dict, credit: tuple, what: str) -> int:
    """`credit` (daemon-wide, floor, ceiling) per peer at the run's
    registered peers."""
    peers = number(run, "shape.registered_peers", what)
    if peers <= 0:
        raise Invalid(f"{what}: {peers} registered peers")
    return min(max(int(credit[0]) // int(peers), credit[1]), credit[2])


def row_credit(run: dict, what: str) -> tuple[int, int]:
    """The run's per-peer row credit and rows in one ordinary pass, from the
    RIB constants the harness recorded. Both arms run this harness (README,
    Running), so a result without the record is not campaign evidence."""
    if run.get("row_credit") is None:
        raise Invalid(
            f"{what}: no row_credit record: the result is from an older harness; build both "
            "arms with this harness (README, Running)"
        )
    credit = tuple(int(number(run, f"row_credit.{key}", what)) for key in ROW_CREDIT_KEYS)
    return per_peer(run, credit, what), int(number(run, "row_credit.CHUNK_ROWS", what))


def credit_unit(run: dict, what: str) -> tuple[str, int, float]:
    """The summed credit gauge's unit (bytes where the tree exports
    `bgp_rib_outbound_credit_bytes`, else rows), the per-peer credit in it
    at the run's registered peers, and one burst row's charge."""
    if witness_of(run, what).get("peak_credit_bytes") is not None:
        row = number(run, "row_size_of", what) + ANNOUNCED_ROW_OVERHEAD
        return "bytes", per_peer(run, BYTE_CREDIT, what), row
    return "rows", row_credit(run, what)[0], 1


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
    # Arm identity: the parent is a row-credit tree, so a parent with the
    # byte gauge (a byte-credit candidate in the parent's place) is not the
    # pair. The candidate may charge rows or bytes; two builds of one tree
    # are caught by the binary hashes (`verdicts`).
    for arm, arm_runs in arms.items():
        for index, run in enumerate(arm_runs):
            what = f"{arm} {cell} run {index}"
            if arm == "parent" and witness_of(run, what).get("peak_credit_bytes") is not None:
                raise Invalid(
                    f"{what}: byte credit gauge present; the parent must lack "
                    "bgp_rib_outbound_credit_bytes"
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
    if "quiet_excluded" not in run["unaffected"]:
        raise Invalid(f"missing instrument {what}: unaffected.quiet_excluded")
    excluded = run["unaffected"]["quiet_excluded"]
    if isinstance(excluded, dict) and "unavailable" in excluded:
        # A RIB wait in the window reached its cap: its span is unknown, so
        # the raw gap is no PASS either.
        raise Invalid(f"{what}: churn-free window unavailable: {excluded['unavailable']}")
    if excluded is None:
        # The last churn row before the window never arrived: nothing is
        # excluded, so the gap is the raw one.
        if gap != raw:
            raise Invalid(f"{what}: nothing excluded, yet max gap {gap} ms is not raw {raw} ms")
        return gap, f"max gap {gap:.0f} ms (nothing excluded: the held churn row never arrived)"
    start = number(run, "unaffected.quiet_excluded.from_ms", what)
    end = number(run, "unaffected.quiet_excluded.to_ms", what)
    span = number(run, "unaffected.quiet_excluded.span_ms", what)
    lead = number(run, "unaffected.quiet_lead_ms", what)
    if span > lead * EXCLUDED_SPAN_RATIO:
        raise Invalid(
            f"{what}: excluded churn-free window {span:.0f} ms is over "
            f"{EXCLUDED_SPAN_RATIO:g} x its configured {lead:.0f} ms: it could hide a stall"
        )
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


def full_release_shape(run: dict) -> bool:
    """Whether a release run has the fixed shape's receivers, rows and pause,
    measured or not: where the drain is long enough for its witnesses."""
    shape = run.get("shape") if isinstance(run.get("shape"), dict) else {}
    return all(shape.get(key) == RELEASE_SHAPE[key] for key in ("receivers", "rows_per_receiver"))


def churn_in_drain(run: dict, what: str, gate: bool) -> str:
    """The churn variant: both withdrawals and re-announcements, sent after
    the release and before the readers resumed, and on the wire, per burst
    receiver, churned routes whose state before its End-of-RIB already
    reflected the churn (the RIB had the churn before the release sent
    those rows). With `gate`, a receiver without one is INVALID: the churn
    did not land in the drain; otherwise the count is reported only."""
    withdrawn = number(run, "churn.withdrawn", what)
    again = number(run, "churn.re_announced", what)
    if withdrawn < 1 or again < 1:
        raise Invalid(
            f"{what}: {withdrawn:.0f} withdrawn and {again:.0f} re-announced; the churn "
            "variant needs both"
        )
    started = number(run, "churn.started_ms", what)
    sent = number(run, "churn.sent_ms", what)
    release = number(run, "timing.release_sent_ms", what)
    resumed = number(run, "timing.resumed_ms", what)
    # Necessary, not sufficient: the last End-of-RIB is decoded after the
    # resume, so only the wire witness below shows the churn in the drain.
    last = number(run, "timing.last_eor_ms", what)
    if not release <= started <= sent < min(resumed, last):
        raise Invalid(
            f"{what}: churn sent {started:.0f}-{sent:.0f} ms, not between the {release:.0f} ms "
            f"release and the {resumed:.0f} ms resume and before the {last:.0f} ms last "
            "End-of-RIB"
        )
    receivers = number(run, "shape.receivers", what)
    reflected = need(run, "wire.churn_reflected_before_eor", what)
    if not isinstance(reflected, list) or len(reflected) != receivers:
        raise Invalid(f"{what}: wire.churn_reflected_before_eor is not one count per receiver")
    counts = [
        value if isinstance(value, int) and not isinstance(value, bool) else 0
        for value in reflected
    ]
    short = sum(1 for count in counts if count < 1)
    line = (
        f"churned routes already in their post-churn state before the End-of-RIB on "
        f"{receivers - short:.0f}/{receivers:.0f} receivers (fewest {min(counts, default=0)})"
    )
    if short and gate:
        raise Invalid(
            f"{what}: churn did not land in the drain: {line}; every burst receiver needs one"
        )
    duplicates = (run.get("wire") or {}).get("duplicates_before_eor")
    return (
        f"{withdrawn:.0f} withdrawn and {again:.0f} re-announced at {started:.0f}-{sent:.0f} ms, "
        f"between the release ({release:.0f} ms) and the resume ({resumed:.0f} ms); {line}"
        + ("" if gate else " (report-only: not the full shape)")
        + f"; duplicate announcements before the End-of-RIB {duplicates} (report-only)"
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


# One bar on one run: (FAIL reason, undecided reason, reading).
Bar = tuple[str | None, str | None, str]


def turn_bar(run: dict, what: str) -> Bar:
    """Bar 2 for one run. A turn or work unit whose bucket lies above the
    bar fails. A pass needs both instruments within it: the longest poll
    (which holds whole turns, so it bounds every turn) and the longest
    inbox round trip (which a drain that yields without serving the RIB's
    update channel stretches). A poll within the bar with a longer round
    trip, a longer poll with no turn provably over it, a probe still
    unanswered at its cap, a dead poll instrument and a window without an
    `end_of_rib` turn are undecided."""
    poll = number(run, "actor.slice_max_us.actor_poll", what) / 1e3
    trip = number(run, "actor.inbox_round_trip.longest_ms", what)
    probes = number(run, "actor.inbox_round_trip.probes", what)
    unfinished = need(run, "actor.inbox_round_trip.unfinished", what)
    if not isinstance(unfinished, bool):
        raise Invalid(f"{what}: actor.inbox_round_trip.unfinished is not a boolean")
    over, top, labels = [], [], set()
    for path in ("actor.turn_longest_ms", "actor.work_longest_ms"):
        for label, above, at_most in longest_bounds(run, path, what):
            if above >= ACTOR_TURN_MAX_MS:
                over.append(f"{label} over {above:.0f} ms")
            top.append((above, at_most, label))
            if path == "actor.turn_longest_ms":
                labels.add(label)
    worst = max(top, default=(0.0, 0.0, "none"))
    reading = (
        f"longest actor poll {poll:.1f} ms; longest inbox round trip {trip:.1f} ms over "
        f"{probes:.0f} probes; longest turn or work unit {worst[2]} in "
        f"({worst[0]:.0f}, {'inf' if worst[1] is None else f'{worst[1]:.0f}'}] ms"
    )
    if over:
        return f"{what}: {', '.join(over)} > {ACTOR_TURN_MAX_MS:.0f} ms ({reading})", None, reading
    if unfinished:
        return None, (
            f"{what}: probe unfinished: an inbox round trip got no reply within its "
            f"{trip:.0f} ms cap, over {ACTOR_TURN_MAX_MS:.0f} ms, yet no turn is provably over "
            f"it ({reading})"
        ), reading
    if poll <= 0 or probes < 1:
        return None, f"{what}: dead instrument ({reading})", reading
    if "end_of_rib" not in labels:
        return None, f"{what}: no end_of_rib turn observed in the run window ({reading})", reading
    if poll > ACTOR_TURN_MAX_MS:
        return None, (
            f"{what}: longest actor poll {poll:.1f} ms > {ACTOR_TURN_MAX_MS:.0f} ms but no turn "
            f"is provably over it ({reading}): a poll can hold many turns"
        ), reading
    if trip > ACTOR_TURN_MAX_MS:
        return None, (
            f"{what}: instruments disagree: longest actor poll {poll:.1f} ms is within "
            f"{ACTOR_TURN_MAX_MS:.0f} ms but an inbox round trip took {trip:.1f} ms ({reading})"
        ), reading
    return None, None, reading


def held_witness(run: dict, what: str, pass_rows: int) -> tuple[str | None, str]:
    """Whether every row the RIB handed toward the paused receivers and they
    have not read is charged, from `witness.held`, read with every burst
    reader paused and without the credit gauge: held = the receivers'
    Adj-RIB-Out rows of the burst family less the rows they decoded. Rows
    leave the charge only once their session has encoded them, so held may
    exceed the charge by those bytes (writer gauge plus the receivers'
    kernel queues) over one announced row's wire size, and by nothing else.
    A partly encoded envelope is both charged and queued, and rows admitted
    after the held read are charged and held nowhere: both only loosen the
    check, the second by at most the charge's movement across the read,
    which must stay within one pass a receiver. INVALID when held fits the
    slack, where a missing charge cannot show."""
    held = need(run, "witness.held", what)
    if not isinstance(held, dict):
        raise Invalid(f"{what}: witness.held is not an object ({held!r})")
    if "unavailable" in held:
        raise Invalid(f"{what}: held read unavailable: {held['unavailable']}")
    receivers = number(run, "shape.receivers", what)
    advertised = number(run, "witness.held.advertised_rows", what)
    read = number(run, "witness.held.read_rows", what)
    before = number(run, "witness.held.charged_before", what)
    charged = number(run, "witness.held.charged_after", what)
    queued = number(run, "witness.held.writer_bytes", what) + number(
        run, "witness.held.socket_bytes", what
    )
    ends = number(run, "witness.held.socket_ends", what)
    low = number(run, "wire.min_row_bytes", what)
    high = number(run, "wire.max_row_bytes", what)
    per_update = number(run, "wire.max_rows_per_update", what)
    at = number(run, "witness.held.at_ms", what)
    release = number(run, "timing.release_sent_ms", what)
    resumed = number(run, "timing.resumed_ms", what)
    if not release <= at < resumed:
        raise Invalid(
            f"{what}: held read at {at:.0f} ms, not between the {release:.0f} ms release and "
            f"the {resumed:.0f} ms resume"
        )
    if ends != 2 * receivers:
        raise Invalid(
            f"{what}: {ends:.0f} connection ends matched the receivers' listeners, not "
            f"2 x {receivers:.0f}: the kernel queues are not the receivers'"
        )
    if low < 1 or per_update > 1 or high > low * (1 + ROW_BYTES_TOLERANCE):
        raise Invalid(
            f"{what}: row size not uniform: {low:.0f} to {high:.0f} B a row (tolerance "
            f"{ROW_BYTES_TOLERANCE:.0%}), up to {per_update:.0f} announced rows in one UPDATE"
        )
    if abs(charged - before) > receivers * pass_rows:
        raise Invalid(
            f"{what}: charge moved {before:.0f} -> {charged:.0f} across the held read, over "
            f"{receivers:.0f} x {pass_rows}: the snapshot is not tight"
        )
    rows = advertised - read
    slack = queued // low
    gap = rows - charged
    arithmetic = (
        f"held {rows:.0f} = {advertised:.0f} advertised - {read:.0f} read, charged "
        f"{charged:.0f}; slack {slack:.0f} = {queued:.0f} queued bytes / {low:.0f} B a row"
    )
    if rows <= slack:
        raise Invalid(
            f"{what}: the charge witness has no power: held fits the slack, so a missing charge "
            f"cannot show ({arithmetic})"
        )
    if gap > slack:
        return (
            f"{what}: owed rows not charged: held exceeds charged by {gap:.0f} > slack ({arithmetic})"
        ), arithmetic
    return None, f"{arithmetic}; margin {slack - gap:.0f}"


def credit_bar(run: dict, what: str, family: str) -> Bar:
    """Bar 6 for one run. The 1 ms gauge watch must have run (reads over at
    least half its window). In rows: the peak at most receivers x (per-peer
    credit + one pass), and, for a family drained by cursor, every row held
    toward the paused receivers charged (`held_witness`), or owed rows went
    uncharged; elsewhere the witness is report-only. Backpressure may stop a
    charged drain short of the credit, so whether the peak reached receivers
    x (credit - one pass) is reported only. A byte-credit tree's byte bound
    reads the 250 ms sampler and is report-only: the rows bound can still
    FAIL it, nothing PASSes it. Unicast keeps no whole-table operation
    live."""
    receivers = number(run, "shape.receivers", what)
    start = number(run, "drain_gauges.from_ms", what)
    end = number(run, "drain_gauges.to_ms", what)
    every = number(run, "drain_gauges.read_every_ms", what)
    reads = number(run, "drain_gauges.reads", what)
    if every <= 0 or end <= start or reads < (end - start) / every / 2:
        return None, (
            f"{what}: {reads:.0f} gauge reads over the {end - start:.0f} ms watch, fewer than "
            f"half of one every {every:g} ms: the gauge watch did not run"
        ), ""
    rows = number(run, "drain_gauges.peak_credit_rows", what)
    limit, pass_rows = row_credit(run, what)
    bound, credit_floor = receivers * (limit + pass_rows), receivers * (limit - pass_rows)
    failures = []
    if rows > bound:
        failures.append(
            f"{what}: credit rows peak {rows:.0f} > {bound:.0f} = {receivers:.0f} x "
            f"({limit} + {pass_rows})"
        )
    operations = number(run, "drain_gauges.peak_operations_live", what)
    if family == "unicast" and operations != 0:
        failures.append(
            f"{what}: {operations:.0f} live whole-table operations during the drain, not 0"
        )
    reading = (
        f"credit rows peak {rows:.0f} (bound {bound:.0f}) over {reads:.0f} reads; live "
        f"whole-table operations peak {operations:.0f}"
        + ("" if family == "unicast" else " (report-only: the gauge is unlabeled)")
    )
    unit, byte_limit, row = credit_unit(run, what)
    undecided = None
    if unit == "bytes":
        peak = number(run, "witness.peak_credit_bytes", what)
        byte_bound = receivers * (byte_limit + PASS_ROWS * row)
        reading += (
            f"; report-only: credit bytes peak {peak:.0f} vs {byte_bound:.0f} = "
            f"{receivers:.0f} x ({byte_limit} + {PASS_ROWS} x {row:.0f}), read every 250 ms"
        )
        undecided = (
            f"{what}: byte credit: the bar 6 byte bound is report-only (250 ms sampler) and "
            f"the row witness does not apply, so bar 6 cannot pass ({reading})"
        )
    elif family not in CURSOR_FAMILIES:
        try:
            failure, arithmetic = held_witness(run, what, pass_rows)
        except Invalid as error:
            failure, arithmetic = None, f"not judged ({error})"
        reading += (
            f"; charge witness report-only: {family} is not drained by cursor and its "
            "whole-table operations charge no rows by design: "
            + (f"would fail ({failure})" if failure else arithmetic)
        )
    else:
        # A missing held read leaves the other bar 6 checks standing.
        try:
            failure, arithmetic = held_witness(run, what, pass_rows)
        except Invalid as error:
            failure, undecided, arithmetic = None, str(error), "not judged"
        failures += [failure] if failure else []
        reached = "reached" if rows >= credit_floor else "not reached"
        reading += (
            f"; charge witness: {arithmetic}; report-only: credit {reached}, "
            f"{credit_floor:.0f} = {receivers:.0f} x ({limit} - {pass_rows})"
        )
    return ("; ".join(failures) or None), undecided, reading


def release_run(run: dict, what: str, kind: str, family: str) -> tuple[list, list, list]:
    """Every cell-7 bar on one run, each on its own, so one bar's missing
    instrument never hides another's FAIL: (failures, undecided, readings)."""

    def wire() -> Bar:
        for check in RESTART_WIRE_CHECKS:
            if need(run, f"checks.{check}", what) is not True:
                return f"{what}: {check} failed", None, ""
        return None, None, ""

    def gap() -> Bar:
        value, note = healthy_gap(run, what)
        failure = f"{what}: healthy delivery gap {value:.0f} ms > {MAX_GAP_MS:.0f} ms"
        return (failure if value > MAX_GAP_MS else None), None, note

    bars = [wire, lambda: turn_bar(run, what), gap, lambda: credit_bar(run, what, family)]
    if kind == "restart-churn":
        bars.insert(1, lambda: (None, None, churn_in_drain(run, what, gate=True)))
    failures, undecided, readings = [], [], []
    for bar in bars:
        try:
            failure, open_question, reading = bar()
        except Invalid as error:
            undecided.append(str(error))
            continue
        failures += [failure] if failure else []
        undecided += [open_question] if open_question else []
        readings += [reading] if reading else []
    return failures, undecided, readings


def release_runs(candidate: Arm, cell: str) -> tuple[list[tuple[str, dict]], list[str]]:
    """The candidate's usable measured runs of `cell`, each with its name,
    and why each other repetition that attempted it is not usable. Cell 7
    judges the usable runs first, so one missing or malformed repetition
    leaves another's FAIL standing and only keeps the cell from passing."""
    usable, undecided = [], []
    for index, rep in enumerate(sorted(candidate.repetitions)):
        what = f"candidate {cell} run {index}"
        try:
            run = candidate.run(rep, cell)
            if run is not None:
                usable.append((what, measured([run], what, RELEASE_SHAPE)[0]))
        except Invalid as error:
            undecided.append(str(error))
    if not usable and not undecided:
        undecided.append(f"candidate: no repetition ran {cell}")
    return usable, undecided


def cell7(candidate: Arm, kind: str, family: str) -> tuple[str, str]:
    """Bars 2, 3, 4 and 6 on the candidate's release runs of one kind. A
    FAIL in any bar of any run outranks every undecided one."""
    cell = f"{kind}-{family}"
    runs, undecided = release_runs(candidate, cell)
    failures, notes = [], []
    for what, run in runs:
        run_failures, run_undecided, readings = release_run(run, what, kind, family)
        failures += run_failures
        undecided += run_undecided
        notes.append("; ".join(readings))
    if failures:
        return "FAIL", "; ".join(failures + undecided)
    if undecided:
        raise Invalid("; ".join(undecided))
    return "PASS", "wire exact, ordered, no resets; " + "; ".join(notes)


def cell7_step(candidate: Arm) -> tuple[str, str]:
    """Bar 1 over every release run: the longest owed-drain step."""
    failures, undecided = [], []
    for kind, _ in RELEASE_KINDS:
        for family in FAMILIES:
            runs, unusable = release_runs(candidate, f"{kind}-{family}")
            undecided += unusable
            for what, run in runs:
                try:
                    if (run.get("actor") or {}).get("owed_drain_step_longest_ms") is None:
                        raise Invalid(
                            f"{what}: no instrument: no product metric times one owed-drain "
                            "step (actor.owed_drain_step_longest_ms is null)"
                        )
                    bounds = longest_bounds(run, "actor.owed_drain_step_longest_ms", what)
                    if not bounds:
                        raise Invalid(f"{what}: no owed-drain step observed")
                except Invalid as error:
                    undecided.append(str(error))
                    continue
                for label, above, at_most in bounds:
                    if above >= OWED_STEP_MAX_MS:
                        failures.append(f"{what}: {label} step over {above:.0f} ms")
                    elif at_most is None or at_most > OWED_STEP_MAX_MS:
                        undecided.append(
                            f"{what}: {label} step in ({above:.0f}, {at_most}] ms: bucket "
                            "resolution cannot judge 50 ms"
                        )
    if failures:
        return "FAIL", (
            f"owed-drain step over {OWED_STEP_MAX_MS:.0f} ms: " + "; ".join(failures + undecided)
        )
    if undecided:
        raise Invalid("; ".join(undecided))
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
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            verdict, reason = "INVALID", f"malformed result: {error!r}"
        results.append((name, verdict, reason))
    for arm in (parent, candidate):
        for rep, directory in sorted(arm.repetitions.items()):
            results.extend(optional_release_reports(directory, arm, rep))
            for cell in sorted(arm.attempted[rep]):
                if not cell.startswith(("restart-", "exhaust-")):
                    continue
                try:
                    run = arm.run(rep, cell)
                except (Invalid, AttributeError, TypeError, ValueError):
                    continue  # The campaign cells above report unusable results.
                if run and (note := eviction_reading(run, f"{arm.name} {rep} {cell}")):
                    results.append(note)
    return results


def eviction_reading(run: dict, source: str) -> tuple[str, str, str] | None:
    actor = run.get("actor")
    field = "eviction_recovery_longest_ms"
    if not isinstance(actor, dict) or field not in actor:
        return None  # Older result schema.
    reading = actor[field]
    if reading is None:
        detail = "no instrument"
    elif reading == {}:
        detail = "no eviction recovery build observed"
    else:
        detail = json.dumps(reading, sort_keys=True)
    return f"{source} eviction recovery", "REPORT", f"{run.get('mode')} run, actor.{field}: {detail}"


def optional_release_reports(
    directory: Path, arm: Arm | None = None, rep: str = ""
) -> list[tuple[str, str, str]]:
    """Describe each optional observation without assigning a campaign verdict."""
    readings = []
    for cell in OPTIONAL_RELEASES:
        result = directory / result_file(cell)
        marker = directory / f"{cell}-exit.json"
        if not (result.exists() or marker.exists() or (arm and cell in arm.attempted[rep])):
            continue
        name = f"{arm.name} {rep} {cell}" if arm else f"{directory} {cell}"
        try:
            if arm:
                run = arm.run(rep, cell)
            else:
                run = explained(read(result), read(marker) if marker.exists() else None, cell)
            if not run or run.get("cell") != cell:
                raise Invalid("result belongs to a different cell")
            checks = need(run, "checks", cell)
            if (
                not isinstance(checks, dict)
                or not OPTIONAL_RELEASE_CHECKS.issubset(checks)
                or any(not isinstance(value, bool) for value in checks.values())
            ):
                raise Invalid("incomplete or malformed release checks")
            failed = [key for key, passed in checks.items() if not passed]
            if run.get("release_ms") is None and failed:
                timing = "last family EoR unavailable"
            else:
                ms = number(run, "release_ms", cell)
                if not math.isfinite(ms) or ms < 0:
                    raise Invalid("invalid release_ms")
                timing = f"last family EoR {ms:.2f} ms after ingest"
            summary = (
                f"failed checks: {', '.join(failed)}" if failed else "release checks passed"
            )
            mode = need(run, "mode", cell)
            if mode not in ("correctness", "measured"):
                raise Invalid(f"unknown release mode {mode!r}")
            reason = f"{summary}; {timing}; mode {mode}"
        except Invalid as error:
            reason = f"unavailable: {error}"
        readings.append((name, "REPORT", reason))
    return readings


def release_readings(run: dict, what: str, family: str) -> str:
    """Report-only: what cell 7's bars 2 and 6 would say of a release run;
    `analyze` judges them on the candidate's measured runs."""
    parts = []
    for name, bar in (
        ("bar 2", lambda: turn_bar(run, what)),
        ("bar 6", lambda: credit_bar(run, what, family)),
    ):
        try:
            failure, open_question, reading = bar()
            verdict = "would FAIL" if failure else "undecided" if open_question else "within"
            parts.append(f"{name} {verdict}: {failure or open_question or reading}")
        except Invalid as error:
            parts.append(f"{name} not judged: {error}")
    step = (run.get("actor") or {}).get("owed_drain_step_longest_ms")
    parts.append(f"owed-drain step {'no instrument' if step is None else step}")
    return "report-only: " + "; ".join(parts)


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
                    run = explained(read(path), exit_record, f"{path.parent}: {cell}")
                    runs.append(run)
                    if note := eviction_reading(run, str(path)):
                        results.append(note)
                if not runs:
                    continue
                if kind == "exhaust":
                    reason, witness = single_arm_exhaust(runs, "arm")
                    passed = f"{witness}; wire exact, ordered, no resets"
                else:
                    # No witness: a selection release spends no ordinary credit.
                    reason = wire_failure(runs, "arm", RESTART_WIRE_CHECKS)
                    notes = [
                        release_readings(run, f"run {index}", family)
                        for index, run in enumerate(runs)
                    ]
                    if kind == "restart-churn" and reason is None:
                        notes = [
                            churn_in_drain(run, f"run {index}", full_release_shape(run))
                            + "; "
                            + note
                            for index, (run, note) in enumerate(zip(runs, notes, strict=True))
                        ]
                    passed = "wire exact, ordered, no resets (no exhaustion witness); " + (
                        "; ".join(notes)
                    )
                verdict, reason = ("FAIL", reason) if reason else ("PASS", passed)
            except Invalid as error:
                verdict, reason = "INVALID", str(error)
            results.append((f"{label} {family}", verdict, reason))
    optional_dirs = {
        path.parent
        for cell in OPTIONAL_RELEASES
        for suffix in (".json", "-exit.json")
        for path in directory.rglob(f"{cell}{suffix}")
    }
    for optional_dir in sorted(optional_dirs):
        results.extend(optional_release_reports(optional_dir))
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
