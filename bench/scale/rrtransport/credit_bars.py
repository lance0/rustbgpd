#!/usr/bin/env python3
"""Apply the outbound-credit campaign bars to parent and candidate results.

    credit_bars.py analyze [--require-cursor FAMILY]... PARENT_DIR CANDIDATE_DIR
    credit_bars.py check RESULT_DIR
    credit_bars.py check-labeled whole|cursor RESULT_DIR
    credit_bars.py labeled PARENT_DIR CANDIDATE_DIR
    credit_bars.py check-vpn whole|cursor RESULT_DIR
    credit_bars.py vpn PARENT_DIR CANDIDATE_DIR

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

``--require-cursor FAMILY`` (repeatable; ``unicast`` or ``evpn``) adds a
family the candidate must drain by cursor to the default (unicast): a cell
7 release run that recorded no cursor owed-drain step for it FAILs.

``check-labeled`` and ``check-vpn`` grade one arm's graceful-restart cells
for the drain it must show: ``whole`` (one whole-family step per receiver,
the parent) or ``cursor``. A measured whole-family run is INVALID unless
every receiver's step ran while the readers were paused; a cursor run needs
only one step while paused, because a cursor stops on credit and finishes
after resume. A run where no receiver's decoded queue held a message is
INVALID at any shape, and a measured run where every receiver's queue was
full is INVALID: the cgroup peak includes those queues. ``labeled`` and
``vpn`` pair a whole-family parent with a cursor candidate built from a
different binary and print REPORT ratios of the arms' means. They apply no
bar and cannot grade an A/A, since identical binaries are INVALID. Where a
campaign has no A/A block, it forms the bar itself from three parent runs
per cell: a reading fails when candidate mean / parent mean exceeds
max(1.02, parent max / parent mean + 0.01).

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

Both commands also judge any ``source-burst.json`` and
``source-burst-control.json`` (the unpaced source burst through real
sessions and its control without healthy updates), and their
``source-burst-small`` counterparts (the same burst in UPDATEs of fewer than
1,024 routes): FAIL on a failed correctness check, INVALID when the
instrument could not have seen a healthy update queued behind the burst,
else PASS with its readings, which are report-only. ``analyze`` adds a
REPORT line with the candidate's readings over the parent's when both arms
ran the cell, and refuses to compare runs that used different UPDATE sizes.
"""

from __future__ import annotations

import json
import math
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path

OPTIONAL_RELEASES = (
    "release-mixed", "release-timer", "release-vpn4", "release-vpn6",
    "release-labeled4", "release-labeled6",
)
RESTART_CELLS = {
    "labeled": ("restart-labeled4", "restart-labeled6"),
    "vpn": ("restart-vpn4", "restart-vpn6"),
}
MPLS_RESTARTS = RESTART_CELLS["labeled"] + RESTART_CELLS["vpn"]
OPTIONAL_RELEASE_CHECKS = {
    "armed_after_staging",
    "release_reason",
    "ownership",
    "wire_exact",
    "eor_order",
    "all_markers_after_trigger",
    "sessions_established",
}
# The unpaced source burst through real sessions and its control, with
# 1,024 routes per UPDATE or (the `-small` cells) fewer. Their latency,
# count, completion, rate and memory readings are report-only.
SOURCE_BURST = (
    "source-burst",
    "source-burst-control",
    "source-burst-two",
    "source-burst-small",
    "source-burst-small-control",
)
SOURCE_BURST_CHECKS = ("final_state_exact", "per_source_order", "sessions_established")
SOURCE_BURST_SHAPE = {"receivers": 150, "routes": 150_000}
SOURCE_BURST_ROUTES_PER_UPDATE = 1_024
SOURCE_BURST_COLUMNS = [
    "sequence",
    "sent_ms",
    "admitted_ms",
    "dispatched_ms",
    "received_ms",
    "burst_ahead",
    "queue_depth",
]
# With fewer healthy updates admitted while the burst was unfinished, the
# cell had nothing that could queue behind it.
SOURCE_BURST_MIN_DURING = 3
# The dispatch stamp is taken when the tap's stamper thread wakes, so it can
# trail the healthy receiver's decode; past this the stamper itself stalled.
SOURCE_BURST_DISPATCH_TRAIL_MS = 50.0

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
# How a release cell's family drains, from the run's owed-drain step
# histogram: `cursor` steps are charged ordinary envelopes, so the charge
# witness gates them; `whole` steps are whole-table operations, which charge
# no rows by design, so the witness is report-only there. A tree whose step
# histogram carries a `family` label names each step's family; one without
# it drains only the cell's own family in that cell. The scopes and family
# labels are the product's closed vocabularies (`OWED_DRAIN_STEP_SCOPES` and
# the canonical family labels in `crates/telemetry/src/metrics.rs`); a key
# outside them is INVALID. A label maps to the release cell family it
# drains, or to itself for a family no release cell measures.
STEP_SCOPES = ("cursor", "keyed", "whole")
STEP_FAMILIES = {
    "ipv4_unicast": "unicast",
    "ipv6_unicast": "unicast",
    "l2vpn_evpn": "evpn",
    **{
        label: label
        for label in (
            "ipv4_flowspec",
            "ipv6_flowspec",
            "linkstate",
            "linkstate_vpn",
            "l3vpn_ipv4_unicast",
            "l3vpn_ipv6_unicast",
            "ipv4_labeled_unicast",
            "ipv6_labeled_unicast",
            "rtc",
            "l3vpn_ipv4_flowspec",
            "l3vpn_ipv6_flowspec",
        )
    },
}
# Families the candidate must drain by cursor: a judged release cell of one
# whose run recorded no cursor step for it FAILs. `analyze --require-cursor
# FAMILY` adds one for a campaign that moves that family onto the cursor.
REQUIRED_CURSOR_FAMILIES = ("unicast",)
# A run without the step histogram (a tree that predates it): the families
# such a tree drains by cursor.
LEGACY_CURSOR_FAMILIES = ("unicast",)
# A byte-credit tree's per-peer byte credit, as (daemon-wide, floor,
# ceiling), when the run records it under `byte_credit`.
BYTE_CREDIT_KEYS = ("DAEMON_CREDIT_BYTES", "MIN_CREDIT_BYTES", "MAX_CREDIT_BYTES")
# Bar 6's byte bound gates only on a byte watch that read the gauge at
# least once per this many ms of its window on average. Each read is a
# registry gather, so the watch cannot hold the getters' 1 ms; this keeps
# it 25 times denser than the 250 ms sampler.
BYTE_READ_EVERY_MAX_MS = 10.0
# `drain_gauges.credit_bytes_watch` values under which the byte watch saw
# the whole drain or the tree has no byte gauge. Any other value (the gauge
# appeared only after the watch started, or the watch failed) is INVALID.
BYTE_WATCH_COMPLETE = ("watched", "not exported")
RELEASE_TRIGGER = "rfc4724_selection_release"
RELEASE_SHAPE = {
    "receivers": 150,
    "rows_per_receiver": 150_000,
    "pause_ms": 30_000,
    "trigger": RELEASE_TRIGGER,
    "registered_peers": 153,
}
MPLS_RELEASE_SHAPE = {**RELEASE_SHAPE, "pause_ms": 90_000, "registered_peers": PEERS + 4}
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
    if cell in SOURCE_BURST:
        return cell, "unicast"
    kind, family = cell.rsplit("-", 1)
    return kind, family


@dataclass
class Arm:
    """One arm: its repetitions, by path relative to the arm directory."""

    name: str
    directory: Path
    repetitions: dict[str, Path] = field(default_factory=dict)
    attempted: dict[str, set[str]] = field(default_factory=dict)
    measured_cells: dict[str, dict[str, int | None]] = field(default_factory=dict)
    sha256: str = ""

    @classmethod
    def load(cls, name: str, directory: Path, *, recursive: bool = True) -> Arm:
        arm = cls(name, directory)
        hashes = set()
        pattern = "**/provenance.jsonl" if recursive else "provenance.jsonl"
        for provenance in sorted(directory.glob(pattern)):
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
            arm.measured_cells[rep] = {
                cell: line.get("measured") for line in lines for cell in line.get("cells") or []
            }
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


def drains_by_cursor(
    run: dict, what: str, family: str, judged: bool, required: tuple = ()
) -> tuple[bool, str, str | None]:
    """Whether the run drained `family`'s owed work by row cursor, from its
    owed-drain step histogram, why, and a FAIL reason when `judged` and
    `family` is in `required` but the run recorded no cursor step for it.
    A step key is its `scope`, or `scope/family` on a tree whose histogram
    carries a `family` label; an unlabeled step in a release cell is the
    cell's family's. INVALID for a scope or family label outside the
    product's vocabularies, when the run recorded both `cursor` and `whole`
    steps for the family (a partial move), no step for it, or steps but
    neither scope (unless required: then FAIL). A run without the histogram is a tree that predates it:
    INVALID when `judged` (the candidate's measured runs), else the legacy
    families drain by cursor."""
    steps = (run.get("actor") or {}).get("owed_drain_step_longest_ms")
    if steps is None:
        if judged:
            raise Invalid(
                f"{what}: no instrument: actor.owed_drain_step_longest_ms is null, so how "
                f"{family} drains, and whether the charge witness applies, is unknown"
            )
        cursor = family in LEGACY_CURSOR_FAMILIES
        return cursor, (
            f"no step histogram (a tree that predates it), where {family} "
            + ("drains by cursor" if cursor else "drains whole")
        ), None
    if not isinstance(steps, dict):
        raise Invalid(f"{what}: actor.owed_drain_step_longest_ms is not an object")
    scopes = set()
    for key in steps:
        scope, _, label = key.partition("/")
        if scope not in STEP_SCOPES:
            raise Invalid(f"{what}: owed-drain step key {key!r} has unknown scope {scope!r}")
        if label and label not in STEP_FAMILIES:
            raise Invalid(
                f"{what}: owed-drain step key {key!r} has unknown family label {label!r}"
            )
        if not label or STEP_FAMILIES[label] == family:
            scopes.add(scope)
    if {"cursor", "whole"} <= scopes:
        raise Invalid(
            f"{what}: partial move: the run recorded both cursor and whole owed-drain steps for "
            f"{family}, so the charge witness can neither gate nor skip it"
        )
    if "cursor" in scopes:
        return True, f"the run recorded cursor owed-drain steps for {family}", None
    seen = ", ".join(sorted(scopes))
    if not scopes:
        raise Invalid(f"{what}: no owed-drain step recorded for {family}: how it drains is unknown")
    if judged and family in required:
        return False, f"the run recorded no cursor owed-drain step for {family}", (
            f"{what}: {family} must drain by cursor, but the run recorded no cursor owed-drain "
            f"step for it (scopes seen: {seen})"
        )
    if "whole" in scopes:
        return False, (
            f"the run recorded only whole owed-drain steps for {family}, whose whole-table "
            "operations charge no rows by design"
        ), None
    raise Invalid(
        f"{what}: no cursor or whole owed-drain step recorded for {family} (scopes seen: "
        f"{seen}): how it drains is unknown"
    )


def byte_bound(run: dict, what: str, receivers: float) -> Bar:
    """Bar 6's byte bound on a tree with `bgp_rib_outbound_credit_bytes`
    (empty on a row-credit tree): the byte watch's peak at most receivers x
    (per-peer byte credit + one pass of `row_size_of` + 146 bytes a row),
    from the run's `byte_credit` record. An observed peak over the bound
    FAILs however sparse the watch; otherwise INVALID when the byte credit
    is in use but the bound cannot gate: no watch over the whole drain, no
    `byte_credit` record, rows not of one size, or reads sparser than one
    per `BYTE_READ_EVERY_MAX_MS` on average."""
    witness = run.get("witness") if isinstance(run.get("witness"), dict) else {}
    gauges = run.get("drain_gauges") or {}
    peak, sampled = gauges.get("peak_credit_bytes"), witness.get("peak_credit_bytes")
    state = gauges.get("credit_bytes_watch")
    if state is not None and state not in BYTE_WATCH_COMPLETE:
        raise Invalid(
            f"{what}: byte watch {state!r}: the credit-bytes gauge was not read over the drain"
        )
    if state == "watched" and peak is None:
        # The watch started, so the tree exports the gauge, but it kept no
        # reading: not a row-credit tree.
        raise Invalid(
            f"{what}: byte watch started but kept no credit-bytes reading "
            f"(drain_gauges.peak_credit_bytes null): the byte bound cannot gate"
        )
    if peak is None and sampled is None and run.get("byte_credit") is None:
        return None, None, ""
    if peak is None:
        raise Invalid(
            f"{what}: byte credit in use (sampler peak {sampled}) but no 1 ms byte watch "
            "reading (drain_gauges.peak_credit_bytes): the byte bound cannot gate"
        )
    if state != "watched":
        raise Invalid(
            f"{what}: credit-bytes peak recorded but drain_gauges.credit_bytes_watch is "
            f"{state!r}, not 'watched': the byte watch's coverage is unconfirmed"
        )
    peak = number(run, "drain_gauges.peak_credit_bytes", what)
    reading = f"; credit bytes peak {peak:.0f}"
    coverage_error = None
    try:
        reads = number(run, "drain_gauges.credit_bytes_reads", what)
        window = number(run, "drain_gauges.to_ms", what) - number(run, "drain_gauges.from_ms", what)
        every = window / reads if reads > 0 else math.inf
        reading += f" over {reads:.0f} reads, one every {every:.1f} ms"
        if every > BYTE_READ_EVERY_MAX_MS:
            coverage_error = (
                f"{what}: byte watch too sparse: {reads:.0f} reads over the {window:.0f} ms "
                f"watch, one every {every:.1f} ms, fewer than one every "
                f"{BYTE_READ_EVERY_MAX_MS:g} ms"
            )
    except Invalid as error:
        coverage_error = str(error)
    if run.get("byte_credit") is None:
        raise Invalid(
            f"{what}: byte credit in use but no byte bound recorded (no byte_credit record in "
            f"the run){reading}"
        )
    row = number(run, "row_size_of", what) + ANNOUNCED_ROW_OVERHEAD
    credit = tuple(int(number(run, f"byte_credit.{key}", what)) for key in BYTE_CREDIT_KEYS)
    limit = per_peer(run, credit, what)
    low = number(run, "wire.min_row_bytes", what)
    high = number(run, "wire.max_row_bytes", what)
    per_update = number(run, "wire.max_rows_per_update", what)
    bound = receivers * (limit + PASS_ROWS * row)
    arithmetic = f"{bound:.0f} = {receivers:.0f} x ({limit} + {PASS_ROWS} x {row:.0f})"
    if low < 1 or per_update > 1 or high > low * (1 + ROW_BYTES_TOLERANCE):
        raise Invalid(
            f"{what}: byte bound {arithmetic} cannot gate: row size not uniform ({low:.0f} to "
            f"{high:.0f} B a row, up to {per_update:.0f} announced rows in one UPDATE){reading}"
        )
    reading += f" (bound {bound:.0f})"
    if peak > bound:
        return f"{what}: credit bytes peak {peak:.0f} > {arithmetic}", None, reading
    return None, coverage_error, reading


def credit_bar(
    run: dict, what: str, family: str, judged: bool = False, required: tuple = ()
) -> Bar:
    """Bar 6 for one run. The 1 ms gauge watch must have run (reads over at
    least half its window), and `witness` must be an object. In rows, on
    every tree: the peak at most receivers x (per-peer credit + one pass),
    and, for a family the run drained by cursor (`drains_by_cursor`), every
    row held toward the paused receivers charged (`held_witness`), or owed
    rows went uncharged, and no whole-table operation live; for a family it
    drained whole both are report-only, unless `judged` and the family is
    in `required`: then FAIL. Backpressure may stop a charged drain short
    of the credit, so whether the peak reached receivers x (credit - one
    pass) is reported only. A byte-credit tree adds its byte bound
    (`byte_bound`). Each check is judged on its own, so a FAIL stands
    beside another's missing input."""
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
    failures, undecided = [], []
    if rows > bound:
        failures.append(
            f"{what}: credit rows peak {rows:.0f} > {bound:.0f} = {receivers:.0f} x "
            f"({limit} + {pass_rows})"
        )
    try:
        witness_of(run, what)
    except Invalid as error:
        undecided.append(str(error))
    try:
        cursor, drains, failure = drains_by_cursor(run, what, family, judged, required)
        failures += [failure] if failure else []
    except Invalid as error:
        # How the family drains is unknown: the witness and the live
        # operations are reported, and the bar cannot pass.
        cursor, drains = None, f"not judged ({error})"
        undecided.append(str(error))
    operations = number(run, "drain_gauges.peak_operations_live", what)
    if cursor and operations != 0:
        failures.append(
            f"{what}: {operations:.0f} live whole-table operations during the drain, not 0"
        )
    reading = (
        f"credit rows peak {rows:.0f} (bound {bound:.0f}) over {reads:.0f} reads; live "
        f"whole-table operations peak {operations:.0f}"
        + ("" if cursor else " (report-only: not drained by cursor, and the gauge is unlabeled)")
    )
    if not cursor:
        try:
            failure, arithmetic = held_witness(run, what, pass_rows)
        except Invalid as error:
            failure, arithmetic = None, f"not judged ({error})"
        reading += (
            f"; charge witness report-only: {drains}: "
            + (f"would fail ({failure})" if failure else arithmetic)
        )
    else:
        # A missing held read leaves the other bar 6 checks standing.
        try:
            failure, arithmetic = held_witness(run, what, pass_rows)
        except Invalid as error:
            failure, arithmetic = None, "not judged"
            undecided.append(str(error))
        failures += [failure] if failure else []
        reached = "reached" if rows >= credit_floor else "not reached"
        reading += (
            f"; charge witness ({drains}): {arithmetic}; report-only: credit {reached}, "
            f"{credit_floor:.0f} = {receivers:.0f} x ({limit} - {pass_rows})"
        )
    try:
        failure, open_question, bytes_reading = byte_bound(run, what, receivers)
        failures += [failure] if failure else []
        undecided += [open_question] if open_question else []
        reading += bytes_reading
    except Invalid as error:
        undecided.append(str(error))
    return ("; ".join(failures) or None), ("; ".join(undecided) or None), reading


def release_run(
    run: dict, what: str, kind: str, family: str, required: tuple = REQUIRED_CURSOR_FAMILIES
) -> tuple[list, list, list]:
    """Every cell-7 bar on one run, each on its own, so one bar's missing
    instrument never hides another's FAIL: (failures, undecided, readings).
    `required`: the families that must drain by cursor."""

    def wire() -> Bar:
        for check in RESTART_WIRE_CHECKS:
            if need(run, f"checks.{check}", what) is not True:
                return f"{what}: {check} failed", None, ""
        return None, None, ""

    def gap() -> Bar:
        value, note = healthy_gap(run, what)
        failure = f"{what}: healthy delivery gap {value:.0f} ms > {MAX_GAP_MS:.0f} ms"
        return (failure if value > MAX_GAP_MS else None), None, note

    bars = [
        wire,
        lambda: turn_bar(run, what),
        gap,
        lambda: credit_bar(run, what, family, True, required),
    ]
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


def cell7(
    candidate: Arm, kind: str, family: str, required: tuple = REQUIRED_CURSOR_FAMILIES
) -> tuple[str, str]:
    """Bars 2, 3, 4 and 6 on the candidate's release runs of one kind. A
    FAIL in any bar of any run outranks every undecided one."""
    cell = f"{kind}-{family}"
    runs, undecided = release_runs(candidate, cell)
    failures, notes = [], []
    for what, run in runs:
        run_failures, run_undecided, readings = release_run(run, what, kind, family, required)
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


def verdicts(
    parent_dir: Path, candidate_dir: Path, require_cursor: tuple = ()
) -> list[tuple[str, str, str]]:
    """Every gated cell's verdict. `require_cursor`: families the candidate
    must drain by cursor beyond `REQUIRED_CURSOR_FAMILIES`."""
    required = REQUIRED_CURSOR_FAMILIES + tuple(require_cursor)
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
                (
                    f"cell 7 {label} {family}",
                    lambda k=kind, f=family: cell7(candidate, k, f, required),
                )
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
            expected = "whole" if arm is parent else "cursor"
            results.extend(optional_cell_reports(directory, arm, rep, restart_scope=expected))
            for cell in sorted(arm.attempted[rep]):
                try:
                    run = arm.run(rep, cell)
                except (Invalid, AttributeError, TypeError, ValueError):
                    continue  # The campaign cells above report unusable results.
                if run:
                    source = f"{arm.name} {rep} {cell}"
                    if note := allocator_reading(run, source):
                        results.append(note)
                    if cell.startswith(("restart-", "exhaust-")) and (note := eviction_reading(run, source)):
                        results.append(note)
    for cell in SOURCE_BURST:
        if note := source_burst_compare(parent, candidate, cell):
            results.append(note)
    return results


def allocator_reading(run: dict, source: str) -> tuple[str, str, str] | None:
    memory = run.get("memory")
    if not isinstance(memory, dict) or "peak_jemalloc_allocated_bytes" not in memory:
        return None

    def value(raw):
        # 0 is a gauge the allocator never refreshed: no reading.
        if type(raw) is int or (isinstance(raw, float) and math.isfinite(raw)):
            return raw if raw > 0 else None
        return None

    def reading(raw):
        return "n/a" if (raw := value(raw)) is None else f"{raw:.0f}"

    fields = ["jemalloc_" + name + "_bytes" for name in ("allocated", "active", "resident")]
    at = memory.get("at_peak_sampled_rss")
    at = at if isinstance(at, dict) else {}
    triples = [
        [memory.get("peak_" + field) for field in fields],
        [at.get(field) for field in fields],
    ]
    peaks, paired = ("/".join(map(reading, triple)) for triple in triples)
    rss, hwm = (reading(memory.get(key)) for key in ("peak_sampled_rss_kib", "vmhwm_kib"))
    detail = (
        f"allocated/active/resident bytes: independent peaks {peaks}, "
        f"at sampled RSS peak ({rss} KiB, VmHWM {hwm} KiB) {paired}"
    )
    # jemalloc's own invariant: resident >= active >= allocated.
    for triple in triples:
        known = [value(raw) for raw in triple]
        if None not in known and not known[0] <= known[1] <= known[2]:
            reason = f"out of order, not resident >= active >= allocated: {detail}"
            return f"{source} jemalloc", "INVALID", reason
    return f"{source} jemalloc", "REPORT", detail


def check_allocator_readings(directory: Path):
    cells = [
        "paused", "probes", *OPTIONAL_RELEASES, *SOURCE_BURST,
        *(f"fill-{family}" for family in FILL_FAMILIES),
        *(f"{kind}-{family}" for kind in ("exhaust", "restart", "restart-churn") for family in FAMILIES),
    ]
    files = {result_file(cell): identity(cell) for cell in cells}
    for path in sorted(directory.rglob("*.json")):
        if path.name not in files:
            continue
        try:
            run = read(path)
        except Invalid:
            continue
        if (run.get("cell"), run.get("family")) == files[path.name]:
            if note := allocator_reading(run, str(path)):
                yield note


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
                    # No exhaustion witness: a selection release need not
                    # exhaust ordinary credit. Bar 6's charge witness is only
                    # reported here; `analyze` judges it on measured runs.
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
    graded_dirs = {
        path.parent
        for cell in (*SOURCE_BURST, *MPLS_RESTARTS)
        for suffix in (".json", "-exit.json")
        for path in directory.rglob(f"{cell}{suffix}")
    }
    graded_dirs.update(path.parent for path in directory.rglob("provenance.jsonl"))
    for graded_dir in sorted(graded_dirs):
        if (graded_dir / "provenance.jsonl").exists():
            try:
                arm = Arm.load(str(graded_dir), graded_dir, recursive=False)
            except (Invalid, AttributeError, OSError, TypeError, ValueError) as error:
                results.append((f"{graded_dir} provenance", "INVALID", str(error)))
                continue
            results.extend(optional_cell_reports(graded_dir, arm, "."))
        else:
            results.extend(optional_cell_reports(graded_dir))
    return results


def healthy_readings(run: dict, what: str, start: float, done: float) -> dict:
    """The healthy source's readings from its per-update stamps. `start` and
    `done`: the burst's first admission and the RIB finishing its last
    message."""
    if need(run, "healthy.columns", what) != SOURCE_BURST_COLUMNS:
        raise Invalid(f"{what}: unknown healthy update columns")
    rows = need(run, "healthy.updates", what)
    if not isinstance(rows, list) or not rows:
        raise Invalid(f"{what}: no healthy update was sent")
    if lost := number(run, "healthy.markers_lost", what):
        raise Invalid(f"{what}: {lost:.0f} dispatch markers were never answered")
    for row in rows:
        stamped = isinstance(row, list) and len(row) == len(SOURCE_BURST_COLUMNS)
        if not stamped or any(
            isinstance(value, bool) or not isinstance(value, (int, float)) for value in row
        ):
            raise Invalid(f"{what}: a healthy update is missing a stamp: {row!r}")
        sequence, sent, admitted, dispatched, received = row[:5]
        if not (sent <= admitted <= dispatched and admitted <= received):
            raise Invalid(f"{what}: healthy update {sequence} has stamps out of order")
        if (trail := dispatched - received) > SOURCE_BURST_DISPATCH_TRAIL_MS:
            raise Invalid(
                f"{what}: healthy update {sequence}'s dispatch stamp trails its receipt by "
                f"{trail:.1f} ms (at most {SOURCE_BURST_DISPATCH_TRAIL_MS:g}): the stamper stalled"
            )
    waits = [(row[3] - row[2], row) for row in rows]
    # The run's own baseline: updates the RIB reached before the burst.
    lead = [wait for wait, row in waits if row[3] < start]
    seeded = run.get("seeded")
    if seeded is not None:
        stall = number(run, "seeded.stall_ms", what)
        at = number(run, "seeded.sequence", what)
        held = [wait for wait, row in waits if row[0] == at]
        if not held:
            raise Invalid(f"{what}: seeded stall, but healthy update {at:.0f} was never sent")
        others = [wait for wait, row in waits if row[0] != at and row[3] < start]
        raise Invalid(
            f"{what}: seeded stall of {stall:.0f} ms at healthy update {at:.0f}: admission to "
            f"dispatch read {held[0]:.1f} ms there and at most {max(others, default=0.0):.1f} ms "
            "on the other updates before the burst"
        )
    during = [wait for wait, row in waits if start <= row[2] <= done]
    if len(during) < SOURCE_BURST_MIN_DURING:
        if run.get("cell") == "source-burst-two":
            return {"short_overlap": len(during)}
        raise Invalid(
            f"{what}: {len(during)} of {len(rows)} healthy updates were admitted while the "
            f"burst was unfinished (need {SOURCE_BURST_MIN_DURING}): none could queue behind it"
        )
    return {
        "updates": len(rows),
        "during": len(during),
        "dispatch_max_ms": max(wait for wait, _ in waits),
        "dispatch_median_ms": statistics.median(during),
        "lead_dispatch_max_ms": max(lead, default=None),
        "burst_ahead_max": max(row[5] for row in rows),
        "delivery_max_ms": max(row[4] - row[1] for row in rows),
        # Dispatch to receipt: the update's own distribution pass. Negative
        # where the dispatch stamp trailed the receiver.
        "own_pass_max_ms": max(row[4] - row[3] for row in rows),
        "stamped_late": number(run, "healthy.stamped_late", what),
    }


def source_burst_readings(run: dict, what: str) -> dict:
    """The cell's readings; INVALID when the instrument could not have seen
    a healthy update queued behind the burst, or its timing is unusable."""
    interval = number(run, "shape.burst_interval_ms", what)
    slept = number(run, "burst.paced_sleep_ms", what)
    if interval > 0 or slept > 0:
        raise Invalid(
            f"{what}: the burst was paced ({interval:g} ms between UPDATEs, {slept:.0f} ms "
            "slept), so it is not the unpaced burst"
        )
    cell = need(run, "cell", what)
    per_update = need(run, "shape.rows_per_update", what)
    small = cell.startswith("source-burst-small")
    if small:
        named = (
            isinstance(per_update, int)
            and not isinstance(per_update, bool)
            and 1 <= per_update < SOURCE_BURST_ROUTES_PER_UPDATE
        )
    else:
        named = per_update == SOURCE_BURST_ROUTES_PER_UPDATE
    if not named:
        raise Invalid(f"{what}: shape.rows_per_update {per_update!r} is not {cell}'s shape")
    # Each burst message and each marker behind one takes a slot in the
    # RIB's half of the tap; past its capacity the later admission stamps
    # wait for room and read late. Older results marked every message.
    messages = number(run, "shape.burst_messages", what)
    markers = run["shape"].get("burst_markers", messages)
    capacity = (run["shape"].get("tap_capacity") or [None, None])[1]
    if capacity is not None and messages + markers > capacity:
        raise Invalid(
            f"{what}: the burst's {messages:.0f} messages and {markers:.0f} markers need more "
            f"than the {capacity} slots of the tap's RIB-side channel, so its admission stamps "
            "would read late"
        )
    sent = number(run, "burst.first_sent_ms", what)
    done = number(run, "burst.rib_done_ms", what)
    # Bucket edges bracketing the longest distribution pass in the run.
    flush = (run.get("actor", {}).get("work_longest_ms") or {}).get("distribute_flush") or {}
    readings = {
        "rib_done_ms": done - sent,
        "completion_ms": number(run, "burst.completion_ms", what) - sent,
        "ingest_routes_per_s": number(run, "burst.ingest_routes_per_s", what),
        "admit_routes_per_s": number(run, "burst.admit_routes_per_s", what),
        "vmhwm_kib": number(run, "memory.vmhwm_kib", what),
        "flush_above_ms": flush.get("above_ms"),
        "flush_at_most_ms": flush.get("at_most_ms"),
        "passes": flush.get("observations"),
        "burst_messages": messages,
        "burst_markers": markers,
    }
    if not cell.endswith("-control"):
        start = number(run, "burst.first_admitted_ms", what)
        readings.update(healthy_readings(run, what, start, done))
    if need(run, "mode", what) == "measured":
        for key, value in SOURCE_BURST_SHAPE.items():
            actual = need(run, f"shape.{key}", what)
            if actual != value:
                raise Invalid(f"{what}: shape.{key} is {actual!r}, not the fixed {value!r}")
        check_compiler_watch(run, what)
    return readings


def check_compiler_watch(run: dict, what: str):
    watch = need(run, "host.compiler_watch", what)
    samples = number(run, "host.compiler_watch.samples", what)
    observed = number(run, "host.compiler_watch.observed", what)
    if watch.get("unavailable") is not None or not math.isfinite(samples) or samples < 1:
        raise Invalid(f"{what}: compiler roster unavailable during the timed cell")
    if observed:
        raise Invalid(
            f"{what}: compiler observed during the timed cell: {watch.get('first')} in "
            f"{observed:.0f} of {samples:.0f} samples"
        )


def burst_sources(run: dict, what: str) -> list[str]:
    sources = need(run, "burst.sources", what)
    if (
        need(run, "shape.burst_sources", what) != 2
        or not isinstance(sources, list)
        or len(sources) != 2
    ):
        raise Invalid(f"{what}: expected two burst sources")
    peers = [need(s, "peer", what) for s in sources]
    if peers[0] == peers[1]:
        raise Invalid(f"{what}: duplicate burst peer")
    rows = number(run, "shape.routes", what)
    if run.get("mode") != "correctness" or type(rows) is not int or not 2 <= rows <= 16_000:
        raise Invalid(f"{what}: inconsistent two-source correctness shape")
    if (
        number(run, "shape.receivers", what) != 8
        or number(run, "shape.registered_peers", what) != 12
    ):
        raise Invalid(f"{what}: incorrect two-source session count")
    planned = 0
    final_marker = 0.0
    notes = []
    ranges = []
    start = number(run, "burst.first_sent_ms", what)
    for index, source in enumerate(sources):
        count = number(source, "messages_planned", what)
        planned += count
        # The prefixes the source's plan carried, read back from its UPDATEs.
        routes = number(source, "routes", what)
        span = need(source, "prefix_range", what)
        if not (
            isinstance(span, list)
            and len(span) == 2
            and all(type(edge) is int for edge in span)
            and 0 <= span[0] < span[1] <= rows
            and type(routes) is int
            and 1 <= routes <= span[1] - span[0]
        ):
            raise Invalid(f"{what}: burst peer {peers[index]} has no usable prefix range")
        ranges.append(span)
        if (
            count < 1
            or number(source, "messages_admitted", what) != count
            or source.get("in_order") is not True
        ):
            raise Invalid(f"{what}: inconsistent work for burst peer {peers[index]}")
        written = number(source, "written_ms", what)
        marker = number(source, "rib_done_ms", what)
        done = marker - start
        if not math.isfinite(written) or written < start or not math.isfinite(done) or done < 0:
            raise Invalid(f"{what}: invalid RIB completion for burst peer {peers[index]}")
        final_marker = max(final_marker, marker)
        notes.append(
            f"peer {peers[index]} {routes:g} routes {span[0]}..{span[1]}, {count:g} messages, "
            f"RIB done {done:.1f} ms"
        )
    # The split must divide the single-source work, not repeat it. Each of
    # the plan's three stages (announce, withdraw, announce again) can gain
    # one UPDATE where the split cuts a chunk.
    low, high = sorted(ranges)
    single = number(run, "shape.single_source_messages", what)
    if (
        low[1] > high[0]
        or sum(number(s, "routes", what) for s in sources) != rows
        or planned > single + 3
    ):
        raise Invalid(
            f"{what}: the sources' plans do not split the {rows}-route table "
            f"(ranges {low} and {high}, {planned:g} messages for {single:g} from one source)"
        )
    # Both sockets finished their first write before either writer went on.
    first = [number(s, "first_written_ms", what) for s in sources]
    went_on = [number(s, "continued_ms", what) for s in sources]
    if max(first) > min(went_on):
        raise Invalid(
            f"{what}: a writer continued at {min(went_on):.3f} ms, before the other socket's "
            f"first write at {max(first):.3f} ms"
        )
    if (
        planned != number(run, "shape.burst_messages", what)
        or planned != number(run, "burst.messages_finished", what)
        or final_marker != number(run, "burst.rib_done_ms", what)
    ):
        raise Invalid(f"{what}: per-source completions disagree with the burst")
    if number(run, "wire.exact_receivers", what) != 8 or number(run, "wire.missing_routes", what):
        raise Invalid(f"{what}: incomplete burst receiver tables")
    if (
        need(run, "healthy.last_received", what) != need(run, "healthy.last_sent", what)
        or number(run, "wire.healthy_decode_failures", what) != 0
        or number(run, "wire.healthy_table_errors", what) != 0
    ):
        raise Invalid(f"{what}: healthy wire evidence disagrees with convergence check")
    return notes


def one_source_starved(run: dict) -> bool:
    """One burst source's plan was admitted in full and the other's was not."""
    sources = (run.get("burst") or {}).get("sources")
    if not isinstance(sources, list) or len(sources) != 2:
        return False
    full = []
    for source in sources:
        counts = [source.get(key) if isinstance(source, dict) else None
                  for key in ("messages_planned", "messages_admitted")]
        if not all(type(count) is int for count in counts) or counts[0] < 1:
            return False
        full.append(counts[0] == counts[1])
    return sorted(full) == [False, True]


def source_burst(run: dict, what: str) -> tuple[str, str]:
    """One source-burst result's verdict and its report-only readings. A
    recorded failure outranks every INVALID, except where the tap judged it."""
    checks = run.get("checks")
    required = SOURCE_BURST_CHECKS
    two_sources = run.get("cell") == "source-burst-two"
    if two_sources:
        required += ("sources_complete", "healthy_converged")
    well_formed = (
        isinstance(checks, dict)
        and set(checks) == set(required)
        and all(isinstance(value, bool) for value in checks.values())
    )
    failed = [key for key in required if well_formed and not checks[key]]
    # A flap, reset or session down is a correctness failure even where the
    # result's own check missed it, and whatever else the result holds: the
    # sessions' state does not depend on the tap.
    wire = run.get("wire") if isinstance(run.get("wire"), dict) else {}
    flaps, resets = wire.get("session_flaps_total") or 0, wire.get("stub_resets") or 0
    if (flaps or resets or wire.get("not_established")) and "sessions_established" not in failed:
        failed.append("sessions_established")
    if "sessions_established" in failed:
        return "FAIL", f"failed checks: {', '.join(failed)}"
    if not well_formed:
        raise Invalid(f"{what}: incomplete or malformed checks")
    need(run, "wire", what)
    # One source admitted in full shows the tap recognizes burst messages:
    # the other source's shortfall is the session's, a read gate that never
    # reopened or a writer blocked past the deadline.
    if two_sources and "sources_complete" in failed and one_source_starved(run):
        return "FAIL", f"failed checks: {', '.join(failed)}"
    # A tap that no longer recognizes what the session admits sees no burst
    # and leaves the run to time out: its table and order checks then judge
    # the instrument, not the daemon.
    admitted = number(run, "burst.messages_admitted", what)
    planned = number(run, "shape.burst_messages", what)
    if admitted != planned:
        raise Invalid(
            f"{what}: the tap recognized {admitted:.0f} of the {planned:.0f} burst messages "
            "the source sent"
        )
    if failed:
        return "FAIL", f"failed checks: {', '.join(failed)}"
    mode = need(run, "mode", what)
    if mode not in ("correctness", "measured"):
        raise Invalid(f"{what}: unknown mode {mode!r}")
    r = source_burst_readings(run, what)
    parts = [
        f"tables exact, order kept, sessions Established; report-only, {mode} run, "
        f"{need(run, 'shape.rows_per_update', what)} routes per UPDATE"
    ]
    if two_sources:
        parts.extend(burst_sources(run, what))
        if "short_overlap" in r:
            parts.append(f"{r['short_overlap']} healthy updates admitted during burst; too few for latency readings")
    if "updates" in r:
        lead = r["lead_dispatch_max_ms"]
        before = "no update" if lead is None else f"at most {lead:.1f} ms"
        grouped = (
            f" (counted by marker, {r['burst_markers']:.0f} for {r['burst_messages']:.0f} messages)"
            if r["burst_markers"] < r["burst_messages"]
            else ""
        )
        parts.append(
            f"healthy admission to dispatch max {r['dispatch_max_ms']:.1f} ms (median "
            f"{r['dispatch_median_ms']:.1f} ms over the {r['during']} of {r['updates']} updates "
            f"admitted during the burst; {before} before it), at most "
            f"{r['burst_ahead_max']} burst messages queued ahead{grouped}, send to receive max "
            f"{r['delivery_max_ms']:.1f} ms, dispatch to receive (its own pass) max "
            f"{r['own_pass_max_ms']:.1f} ms, {r['stamped_late']:.0f} admission stamps late"
        )
    parts.append(
        f"burst finished in the RIB {r['rib_done_ms']:.0f} ms and on every receiver "
        f"{r['completion_ms']:.0f} ms after its first write, {r['ingest_routes_per_s']:,.0f} "
        f"routes/s ({r['admit_routes_per_s']:,.0f} routes/s admitted by the session)"
    )
    if r["flush_above_ms"] is None:
        parts.append("no distribution pass recorded")
    else:
        most = r["flush_at_most_ms"]
        bound = "past the top bucket" if most is None else f"at most {most:g} ms"
        parts.append(f"longest distribution pass above {r['flush_above_ms']:g} ms, {bound}")
    if r["passes"] is not None:
        # Without healthy updates, every pass in the run is the burst's.
        share = (
            f", {r['burst_messages'] / r['passes']:.1f} burst messages a pass"
            if need(run, "cell", what).endswith("-control")
            else ""
        )
        parts.append(f"{r['passes']} distribution passes in the run{share}")
    parts.append(f"peak RSS {r['vmhwm_kib'] / 1024:.0f} MiB")
    return "PASS", "; ".join(parts)


def restart_step_window(run: dict, key: str, cell: str) -> dict:
    steps = need(run, f"witness.{key}", cell)
    if not isinstance(steps, dict) or set(steps) != set(STEP_SCOPES):
        raise Invalid(f"{cell}: {key} needs the observed cursor, keyed and whole series")
    for scope, entry in steps.items():
        if not isinstance(entry, dict) or not {"observations", "above_ms", "at_most_ms"} <= entry.keys():
            raise Invalid(f"{key}.{scope}: incomplete histogram")
        count, lo, hi = entry["observations"], entry["above_ms"], entry["at_most_ms"]
        if type(count) is not int or count < 0:
            raise Invalid(f"{key}.{scope}: invalid step count")
        if count == 0:
            if lo is not None or hi is not None:
                raise Invalid(f"{key}.{scope}: duration with no steps")
            continue
        if type(lo) not in (int, float) or not math.isfinite(lo) or lo < 0:
            raise Invalid(f"{key}.{scope}: invalid lower bucket edge")
        if hi is not None and (type(hi) not in (int, float) or not math.isfinite(hi) or hi <= lo):
            raise Invalid(f"{key}.{scope}: invalid upper bucket edge")
    return steps


def restart_drain(run: dict, cell: str, expected: str | None) -> str:
    before = restart_step_window(run, "owed_steps_while_paused", cell)
    total = restart_step_window(run, "owed_steps_to_last_eor", cell)
    for scope in STEP_SCOPES:
        if before[scope]["observations"] > total[scope]["observations"] or (
            before[scope]["observations"] and before[scope]["above_ms"] > total[scope]["above_ms"]
        ):
            raise Invalid(f"{cell}: {scope} paused histogram exceeds the complete window")
    seen = [scope for scope in STEP_SCOPES if total[scope]["observations"]]
    if seen not in (["whole"], ["cursor"]) or (expected and seen != [expected]):
        raise Invalid(f"{cell}: expected {expected or 'whole-only or cursor-only'} drain, observed {seen}")
    scope = seen[0]
    n = run["shape"]["receivers"]
    rows = run["shape"]["rows_per_receiver"]
    chunk = need(run, "shape.chunk_rows", cell)
    if chunk != PASS_ROWS:
        raise Invalid(f"{cell}: unexpected drain unit {chunk!r}")
    count = total[scope]["observations"]
    paused = before[scope]["observations"]
    if scope == "whole" and count != n:
        raise Invalid(f"{cell}: observed {count} whole steps for {n} receivers")
    if scope == "cursor" and count < n * math.ceil(rows / chunk):
        raise Invalid(f"{cell}: too few cursor steps for the advertised inventory")
    if run["mode"] == "measured" and paused == 0:
        raise Invalid(f"{cell}: no {scope} steps observed while paused")
    # A whole-family send is one step per receiver. One still to run when the
    # readers return makes the peak and the recovery readings of the pause.
    # A cursor stops on credit while readers are paused, so its arm finishes
    # after resume by design and keeps the weaker rule above.
    if run["mode"] == "measured" and scope == "whole" and paused != n:
        raise Invalid(
            f"{cell}: production not finished before resume ({paused} of {n} whole steps while paused)"
        )
    lo, hi = total[scope]["above_ms"], total[scope]["at_most_ms"]
    bracket = f">{lo:g} ms" if hi is None else f"({lo:g}, {hi:g}] ms"
    return f"{count} {scope} steps ({paused} while paused), longest {bracket}"


def mpls_restart(run: dict, cell: str, expected_scope: str | None = None) -> tuple[str, str]:
    """Validate the instruments without setting a performance threshold."""
    if (run.get("cell"), run.get("family")) != identity(cell):
        raise Invalid("result belongs to a different cell")

    def positive(path: str):
        value = number(run, path, cell)
        if not math.isfinite(value) or value <= 0:
            raise Invalid(f"invalid {path}: {value}")
        return value

    payload = "vpn" if cell in RESTART_CELLS["vpn"] else "labeled"
    checks = need(run, "checks", cell)
    required = RESTART_WIRE_CHECKS + (
        "selection_held", "selection_released", "owed_at_release",
        "post_release_withdrawal", "physical_poll_observed", "release_update_delivered",
        "source_restart", f"{payload}_payload_counted", "memory_fenced",
    )
    if payload == "vpn":
        required += ("no_rtc",)
    if set(checks) != set(required) or any(type(value) is not bool for value in checks.values()):
        raise Invalid("malformed restart checks")
    for key in (*RESTART_WIRE_CHECKS, "post_release_withdrawal"):
        if not checks[key]:
            return "FAIL", f"failed {key}"
    for key in required:
        if not checks[key]:
            raise Invalid(f"missing {key} witness")
    mode = need(run, "mode", cell)
    if mode not in ("correctness", "measured") or need(run, "shape.trigger", cell) != RELEASE_TRIGGER:
        raise Invalid("unexpected restart shape or mode")
    if mode == "measured":
        measured([run], cell, MPLS_RELEASE_SHAPE)
        check_compiler_watch(run, cell)
    rows = positive("shape.rows_per_receiver")
    n = positive("shape.receivers")
    if payload == "vpn":
        if need(run, "shape.rtc_negotiated", cell) is not False:
            raise Invalid("expected a VPN session without RTC")
        if need(run, "shape.route_target", cell) != "64512:100":
            raise Invalid("unexpected VPN route target")
        if need(run, "shape.export_policy", cell) != "permit matching RT, default deny":
            raise Invalid("unexpected VPN export policy")
        if type(rows) is not int or rows < 2:
            raise Invalid("too few VPN rows to observe two RDs on a shared prefix")
    if positive("shape.registered_peers") != n + 4:
        raise Invalid("incorrect receiver, healthy, or source peer count")
    if (
        need(run, "source.old_session", cell) == need(run, "source.new_session", cell)
        or need(run, "source.peer", cell) == need(run, "source.release_helper", cell)
        or need(run, "source.restart_state", cell) is not True
        or need(run, "source.old_sample_stale", cell) is not False
        or need(run, "source.retained_sample_stale", cell) is not True
        or need(run, "source.replayed_sample_stale", cell) is not False
        or any(
            number(run, f"source.{key}", cell) != rows
            for key in ("old_rows", "retained_rows", "replayed_rows")
        )
    ):
        raise Invalid("source restart did not retain and replay the table")
    if any(number(run, f"witness.{key}", cell) != expected for key, expected in (
        ("active_before_release", 1), ("waiters_before_release", 1), ("all_eor_releases", 1),
        ("owing_flip_delta_while_paused", n),
    )):
        raise Invalid("absent hold, selection release or paused receiver debt")
    peers = need(run, "receivers", cell)
    if not isinstance(peers, list) or len(peers) != n:
        raise Invalid("incomplete receiver records")
    receiver_ids = {need(peer, "peer", cell) for peer in peers}
    if len(receiver_ids) != n:
        raise Invalid("duplicate receiver records")
    source_ids = (run["source"]["peer"], run["source"]["release_helper"], need(run, "unaffected.peer", cell))
    if receiver_ids.intersection(source_ids):
        raise Invalid("receiver also named as a source or release helper")
    capacity = positive("shape.stub_backlog_capacity_messages")
    backlogs = []
    for peer in peers:
        backlog = need(peer, "max_observed_stub_backlog_messages", cell)
        if type(backlog) is not int or not 0 <= backlog <= capacity:
            raise Invalid(f"{peer['peer']} invalid sampled receive backlog")
        backlogs.append(backlog)
        if need(peer, "exact", cell) is not True or need(peer, "exact_at_eor", cell) is not True:
            return "FAIL", f"{peer['peer']} incomplete table or premature EoR"
        for key in ("missing", "outside", "decode_failures", "resets", "routes_after_eor"):
            if number(peer, key, cell) != 0:
                return "FAIL", f"{peer['peer']} {key}"
        if number(peer, "eors", cell) != 1:
            return "FAIL", f"{peer['peer']} expected one {payload} EoR"
        announced = number(peer, "announced", cell)
        withdrawn = number(peer, "withdrawals", cell)
        if (number(peer, f"{payload}_announced", cell), number(peer, f"{payload}_withdrawn", cell)) != (
            announced, withdrawn
        ):
            raise Invalid(f"{peer['peer']} {payload} payload counters disagree with folded wire rows")
        if announced != rows or number(peer, "routes_before_eor", cell) != rows:
            return "FAIL", f"{peer['peer']} announcement count before EoR"
        if withdrawn != 1 or number(peer, "post_eor_sentinel_changes", cell) != 1:
            return "FAIL", f"{peer['peer']} incomplete advertisements or sentinel withdrawal"
        if payload == "vpn" and need(peer, "withdrawal_rd_sibling_present", cell) is not True:
            return "FAIL", f"{peer['peer']} lost the other RD on sentinel withdrawal"
    positive("actor.poll_count")
    poll_us = positive("actor.slice_max_us.actor_poll")
    if number(run, "unaffected.release_update_sequence", cell) != 1:
        raise Invalid("unrelated UPDATE sequence missing or mismatched")
    if need(run, "unaffected.peer", cell) in (run["source"]["peer"], run["source"]["release_helper"]):
        raise Invalid("UPDATE probe used a release participant")
    wait = positive("unaffected.release_update_wait_ms")
    admitted = number(run, "unaffected.release_update_admitted_ms", cell)
    winner = number(run, "unaffected.release_update_winner_ms", cell)
    received = number(run, "unaffected.release_update_received_ms", cell)
    wire_wait = positive("unaffected.release_update_wire_ms")
    recovery = positive("timing.release_to_last_eor_ms")
    last = positive("timing.last_eor_ms")
    start = number(run, "timing.release_sent_ms", cell)
    resume = number(run, "timing.resume_issued_ms", cell)
    markers = [number(peer, "eor_ms", cell) for peer in peers]
    if not start <= resume or any(not math.isfinite(marker) or marker < resume for marker in markers):
        raise Invalid("receiver EoR outside release window")
    if not math.isclose(last, max(markers), abs_tol=1e-6):
        raise Invalid("last EoR does not match the last receiver")
    if start < 0 or not math.isclose(recovery, last - start, abs_tol=1e-6):
        raise Invalid("recovery does not span release to last EoR")
    resumed_recovery = positive("timing.resume_to_last_eor_ms")
    if not math.isclose(resumed_recovery, last - resume, abs_tol=1e-6):
        raise Invalid("recovery does not span resume to last EoR")
    if mode == "measured" and resume - start < MPLS_RELEASE_SHAPE["pause_ms"]:
        raise Invalid("readers resumed before the fixed reader pause elapsed")
    if not number(run, "actor.from_ms", cell) <= start <= last <= number(run, "actor.to_ms", cell):
        raise Invalid("physical poll window does not cover release through last EoR")
    if (
        not start <= admitted <= last
        or not math.isclose(wait, winner - admitted, abs_tol=1e-6)
        or not math.isclose(wire_wait, received - admitted, abs_tol=1e-6)
    ):
        raise Invalid("unrelated UPDATE wait does not match its release-window stamps")
    peak = positive("memory.cgroup_memory_peak_bytes")
    scope = need(run, "memory.cgroup", cell)
    if (
        not isinstance(scope, str)
        or not scope.endswith(".scope")
        or need(run, "memory.cgroup_swap_max", cell) != "0"
        or need(run, "memory.cgroup_oom_kill", cell) != "0"
    ):
        raise Invalid("missing swap-fenced memory scope")
    # The decoded queues are harness memory inside the cgroup peak, recorded
    # in messages only. The depth is sampled after a dequeue, so a full queue
    # reads one below capacity.
    if not any(backlogs):
        raise Invalid("no decoded-queue backlog on any receiver; the pause did not load the daemon")
    if mode == "measured" and all(backlog >= capacity - 1 for backlog in backlogs):
        raise Invalid("harness queue saturated; memory not comparable")
    drain = restart_drain(run, cell, expected_scope)
    return "PASS", (
        f"{mode}, {n:g} exact receivers; longest RIB poll {poll_us / 1000:.3f} ms, "
        f"release-turn UPDATE wait {wait:.3f} ms, release to last EoR {recovery:.3f} ms, "
        f"resume to last EoR {resumed_recovery:.3f} ms; {drain}; "
        f"cgroup peak {peak} bytes (includes harness), largest sampled receiver backlog "
        f"{max(backlogs)} of {capacity:g} messages"
    )


def optional_cell_reports(
    directory: Path, arm: Arm | None = None, rep: str = "", *,
    cells=(*SOURCE_BURST, *MPLS_RESTARTS), restart_scope: str | None = None,
) -> list[tuple[str, str, str]]:
    """A verdict line per optional graded cell this directory ran or attempted."""
    lines = []
    for cell in cells:
        result = directory / result_file(cell)
        marker = directory / f"{cell}-exit.json"
        if not (result.exists() or marker.exists() or (arm and cell in arm.attempted[rep])):
            continue
        try:
            if arm:
                run = arm.run(rep, cell)
            elif not result.exists():
                raise Invalid(f"{cell} exited without a result")
            else:
                run = explained(read(result), read(marker) if marker.exists() else None, cell)
            if not run or run.get("cell") != identity(cell)[0]:
                raise Invalid("result belongs to a different cell")
            if cell in MPLS_RESTARTS:
                verdict, reason = mpls_restart(run, cell, restart_scope)
            else:
                verdict, reason = source_burst(run, cell)
        except Invalid as error:
            verdict, reason = "INVALID", str(error)
        except (AttributeError, KeyError, TypeError, ValueError) as error:
            verdict, reason = "INVALID", f"malformed result: {error!r}"
        name = f"{arm.name} {rep} {cell}" if arm else f"{directory} {cell}"
        lines.append((name, verdict, reason))
    return lines


def mean_readings(readings: list[dict]) -> dict:
    """Each reading's mean over the repetitions; a reading null in any of
    them (no update before the burst, no pass recorded) is left out."""
    keys = [key for key in readings[0] if all(r.get(key) is not None for r in readings)]
    return {key: statistics.fmean(r[key] for r in readings) for key in keys}


def restart_arm(name: str, directory: Path) -> Arm:
    arm = Arm.load(name, directory)
    if not isinstance(arm.sha256, str) or len(arm.sha256) != 64 or any(
        ch not in "0123456789abcdef" for ch in arm.sha256
    ):
        raise Invalid(f"{name}: missing binary SHA-256")
    return arm


def check_restart_family(directory: Path, expected: str, family: str) -> list[tuple[str, str, str]]:
    try:
        arm = restart_arm(str(directory), directory)
        return [
            line for rep, path in sorted(arm.repetitions.items())
            for line in optional_cell_reports(path, arm, rep, cells=RESTART_CELLS[family], restart_scope=expected)
        ] or [(str(directory), "INVALID", f"no {family} restart was attempted")]
    except (Invalid, OSError, TypeError, ValueError) as error:
        return [(str(directory), "INVALID", str(error))]


def compare_restart_family(parent_dir: Path, candidate_dir: Path, family: str) -> list[tuple[str, str, str]]:
    """Ratios of arithmetic means across matched measured runs, by AFI."""
    try:
        parent = restart_arm("parent", parent_dir)
        candidate = restart_arm("candidate", candidate_dir)
        if parent.sha256 == candidate.sha256:
            raise Invalid("A/B requires distinct parent and candidate binaries")
    except (Invalid, OSError, TypeError, ValueError) as error:
        return [(f"{family} A/B", "INVALID", str(error))]
    results = []
    readings = (
        ("longest RIB poll (µs)", "actor.slice_max_us.actor_poll"),
        ("release-turn UPDATE wait (ms)", "unaffected.release_update_wait_ms"),
        ("release → last EoR (ms)", "timing.release_to_last_eor_ms"),
        ("resume → last EoR (ms)", "timing.resume_to_last_eor_ms"),
        ("whole-process cgroup peak (bytes, includes harness)", "memory.cgroup_memory_peak_bytes"),
    )
    for cell in RESTART_CELLS[family]:
        try:
            old, new = pair(parent, candidate, cell)
            passed = True
            for arm, scope, runs in ((parent, "whole", old), (candidate, "cursor", new)):
                repetitions = sorted(rep for rep, cells in arm.attempted.items() if cell in cells)
                for rep, run in zip(repetitions, runs, strict=True):
                    verdict, reason = mpls_restart(run, cell, scope)
                    results.append((f"{arm.name} {rep} {cell}", verdict, reason))
                    passed &= verdict == "PASS"
                    if verdict == "PASS" and arm.measured_cells[rep][cell] != 1:
                        raise Invalid(f"{arm.name}/{rep}: {cell} was not measured by the runner")
            if not passed:
                continue
            measured(old + new, cell, MPLS_RELEASE_SHAPE)
            for title, field in readings:
                p, c = (statistics.fmean(number(run, field, cell) for run in runs) for runs in (old, new))
                results.append((
                    f"{cell} {title}", "REPORT",
                    f"parent {p:.3f}, candidate {c:.3f}, candidate/parent {c / p:.4f} ({len(old)} matched pairs)",
                ))
        except (Invalid, OSError, AttributeError, KeyError, TypeError, ValueError) as error:
            results.append((cell, "INVALID", str(error)))
    return results


def source_burst_compare(parent: Arm, candidate: Arm, cell: str) -> tuple[str, str, str] | None:
    """Report-only: the candidate's readings beside the parent's, each the
    mean of its passing repetitions; None unless both arms have one. Runs
    with different routes per UPDATE are different shapes: neither averaged
    nor compared."""
    if cell == "source-burst-two":
        return None  # Fixed correctness fixture.
    means, sizes = [], set()
    for arm in (parent, candidate):
        readings = []
        for rep in sorted(arm.repetitions):
            if cell not in arm.attempted[rep]:
                continue
            try:
                run = arm.run(rep, cell)
                if run and source_burst(run, cell)[0] == "PASS":
                    readings.append(source_burst_readings(run, cell))
                    sizes.add(run["shape"]["rows_per_update"])
            except (Invalid, AttributeError, KeyError, TypeError, ValueError):
                continue  # The repetition's own line says why.
        if not readings:
            return None
        means.append(mean_readings(readings))
    name = f"{cell} candidate over parent"
    if len(sizes) > 1:
        return (
            name,
            "INVALID",
            f"runs used {', '.join(map(str, sorted(sizes)))} routes per UPDATE: different "
            "shapes, not compared",
        )
    old, new = means
    parts = [
        f"burst completion x{new['completion_ms'] / old['completion_ms']:.2f}",
        f"ingest rate x{new['ingest_routes_per_s'] / old['ingest_routes_per_s']:.2f}",
        f"peak RSS x{new['vmhwm_kib'] / old['vmhwm_kib']:.2f}",
    ]
    if "dispatch_max_ms" in old and "dispatch_max_ms" in new:
        parts.append(
            f"healthy admission to dispatch max {new['dispatch_max_ms']:.1f} ms against "
            f"{old['dispatch_max_ms']:.1f} ms, burst messages queued ahead "
            f"{new['burst_ahead_max']:.0f} against {old['burst_ahead_max']:.0f}"
        )
    return name, "REPORT", "; ".join(parts)


def report(results: list[tuple[str, str, str]], readings=()) -> int:
    readings = list(readings)
    for name, verdict, reason in [*results, *readings]:
        print(f"{verdict:<7} {name}: {reason}")
    # A report-only reading counts only when its instrument is unusable.
    found = {verdict for _, verdict, _ in [*results, *readings] if verdict != "REPORT"}
    return 1 if "FAIL" in found else 2 if "INVALID" in found or not results else 0


def main(argv: list[str]) -> int:
    args, require = [], []
    rest = iter(argv[1:])
    for arg in rest:
        if arg == "--require-cursor":
            require.append(next(rest, None))
        else:
            args.append(arg)
    known = all(family in FAMILIES for family in require)
    if len(args) == 3 and args[0] == "analyze" and known:
        return report(verdicts(Path(args[1]), Path(args[2]), tuple(require)))
    if len(args) == 2 and args[0] == "check" and not require:
        directory = Path(args[1])
        return report(check(directory), check_allocator_readings(directory))
    if len(args) == 3 and not require:
        family = args[0].removeprefix("check-")
        if args[0].startswith("check-") and family in RESTART_CELLS and args[1] in ("whole", "cursor"):
            return report(check_restart_family(Path(args[2]), args[1], family))
        if args[0] in RESTART_CELLS:
            return report(compare_restart_family(Path(args[1]), Path(args[2]), args[0]))
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
