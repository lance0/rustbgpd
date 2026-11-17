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
burst), which no campaign bar reads.
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
# Cell 2: recovery <= max(parent x 1.25, parent + 2 s).
RECOVERY_RATIO = 1.25
RECOVERY_SLACK_MS = 2_000.0
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
    kind, family = cell.split("-", 1)
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


def exhaustion(run: dict, what: str) -> str:
    """What witnessed that every burst receiver spent its ordinary credit in
    `run`; INVALID when nothing did."""
    if need(run, "shape.trigger", what) != ORDINARY_TRIGGER:
        raise Invalid(
            f"{what}: trigger {run['shape']['trigger']!r} is not {ORDINARY_TRIGGER!r}; "
            "it cannot exhaust ordinary credit"
        )
    receivers = number(run, "witness.receivers", what)
    refused = number(run, "witness.refused_receivers", what)
    peers = number(run, "shape.registered_peers", what)
    rows = number(run, "witness.peak_credit_rows", what)
    if receivers <= 0 or peers < receivers:
        raise Invalid(f"{what}: {receivers} burst receivers among {peers} registered peers")
    # The gauge sums every peer. Admission stops at a peer's credit (within
    # one row), so a sum at receivers x credit means every one reached it.
    if run["witness"].get("peak_credit_bytes") is not None:
        unit, peak, credit = "bytes", number(run, "witness.peak_credit_bytes", what), BYTE_CREDIT
    else:
        unit, peak, credit = "rows", rows, ROW_CREDIT
    limit = min(max(credit[0] // int(peers), credit[1]), credit[2])
    if peak >= receivers * limit:
        return f"credit gauge peak {peak:.0f} {unit} >= {receivers} x {limit}"
    if refused >= receivers:
        return f"credit refusals on {refused}/{receivers} receivers"
    flips = run["witness"].get("owing_flips_total")
    raise Invalid(
        f"{what}: credit gauge peak {peak:.0f} {unit} < {receivers} x {limit} and credit "
        f"refusals on {refused}/{receivers} receivers ({flips} owe-whole flips are not a "
        "witness); the cell never exhausted credit"
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
    return {
        "parent": measured(runs[0], f"parent {cell}", EXHAUST_SHAPE),
        "candidate": measured(runs[1], f"candidate {cell}", EXHAUST_SHAPE),
    }


def cell2(parent: Arm, candidate: Arm, family: str) -> tuple[str, str]:
    arms = exhaust_runs(parent, candidate, family)
    single = {arm: single_arm_exhaust(runs, arm) for arm, runs in arms.items()}
    failures = [reason for reason, _ in single.values() if reason is not None]
    # A run that never settled has no recovery time; its wire FAIL stands
    # without any timing comparison.
    if failures:
        return "FAIL", "; ".join(failures)
    times = {arm: recovery(runs, arm) for arm, runs in arms.items()}
    bar = max(times["parent"] * RECOVERY_RATIO, times["parent"] + RECOVERY_SLACK_MS)
    line = (
        f"recovery candidate {times['candidate']:.0f} ms vs bar {bar:.0f} ms "
        f"(parent {times['parent']:.0f} ms)"
    )
    if times["candidate"] > bar:
        return "FAIL", f"recovery over bar: {line}"
    witnessed = "; ".join(f"{arm} {witness}" for arm, (_, witness) in single.items())
    return "PASS", f"exhaustion witnessed ({witnessed}); wire exact, ordered, no resets; {line}"


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
            gap = number(run, "unaffected.max_gap_ms", what)
            if arm == "candidate":
                gaps.append(gap)
        p99[arm] = statistics.median(values)
    failures = []
    if max(gaps) > MAX_GAP_MS:
        failures.append(f"candidate delivery gap {max(gaps):.0f} ms > {MAX_GAP_MS:.0f} ms")
    if p99["candidate"] > p99["parent"] * P99_RATIO:
        failures.append(
            f"candidate p99 {p99['candidate']:.1f} ms > parent {p99['parent']:.1f} ms x {P99_RATIO}"
        )
    line = (
        f"max gap {max(gaps):.0f} ms; p99 {p99['candidate']:.1f} ms vs parent "
        f"{p99['parent']:.1f} ms"
    )
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


CELLS = (
    ["cell 1 paused-reader evpn"]
    + [
        f"cell {n} {kind} {family}"
        for family in FAMILIES
        for n, kind in ((2, "exhaustion"), (3, "unaffected peer"))
    ]
    + ["cell 4 lag and restart probes", "cell 6 bytes per queued row"]
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


def check(directory: Path) -> list[tuple[str, str, str]]:
    results = []
    for kind, label in (("exhaust", "exhaustion"), ("restart", "restart burst")):
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
                    passed = "wire exact, ordered, no resets (no exhaustion witness)"
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
