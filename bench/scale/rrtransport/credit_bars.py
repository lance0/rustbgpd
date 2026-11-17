#!/usr/bin/env python3
"""Apply the outbound-credit campaign bars to parent and candidate results.

    credit_bars.py analyze PARENT_DIR CANDIDATE_DIR
    credit_bars.py check RESULT_DIR

Each directory holds the result files of one arm (searched recursively, so
repetitions may sit in subdirectories): ``exhaust-unicast.json``,
``exhaust-evpn.json``, ``paused-evpn.json`` (or ``paused-exit.json`` when
the run died), ``probes.json`` and ``fill-<family>.json``. Every cell gets
one ``PASS``, ``FAIL`` or ``INVALID`` line; the analyzer never stops at the
first failing cell. Exit status: 1 when any cell FAILs, else 2 when any is
INVALID, else 0.

``check`` applies the single-arm parts (wire checks and refusal witness) to
one result set, measured or not, for correctness runs.
"""

from __future__ import annotations

import json
import statistics
import sys
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
# Cell 4: 8 lag cells and one restart cell.
PROBE_CELLS = 9
# Cell 6: a family measured more than 25% above its charge gets a ticket.
ESTIMATE_RATIO = 1.25
FAMILIES = ("unicast", "evpn")
FILL_FAMILIES = ("unicast", "evpn", "vpn", "flowspec")
WIRE_CHECKS = ("final_state_exact", "eor_after_every_route", "no_session_resets")


class Invalid(Exception):
    """The evidence cannot support a verdict."""


def load(directory: Path, name: str) -> list[dict]:
    runs = []
    for path in sorted(directory.rglob(name)):
        try:
            runs.append(json.loads(path.read_text()))
        except (OSError, json.JSONDecodeError) as error:
            raise Invalid(f"{path}: unreadable result ({error})") from error
    return runs


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


def measured(runs: list[dict], what: str) -> list[dict]:
    if not runs:
        raise Invalid(f"no {what} result")
    for run in runs:
        if run.get("mode") != "measured":
            raise Invalid(f"{what} result is a {run.get('mode')} run, not measured")
    return runs


def single_arm_exhaust(runs: list[dict], arm: str, family: str) -> str | None:
    """Raise INVALID for a missing witness in any run, then return the first
    wire FAIL reason, or None when every run passed its wire checks."""
    for index, run in enumerate(runs):
        what = f"{arm} run {index}"
        refused = number(run, "witness.refused_receivers", what)
        flips = number(run, "witness.owing_flips_total", what)
        receivers = number(run, "witness.receivers", what)
        # Past its credit a private family either refuses the send or owes
        # its keys; this shape's owed sets outgrow their cap, so each burst
        # receiver flips to owing the family whole. Either signal on every
        # receiver is the witness.
        if receivers <= 0 or (refused < receivers and flips < receivers):
            raise Invalid(
                f"{what}: credit exhaustion witnessed on {refused}/{receivers} "
                f"receivers by refusal and {flips:.0f} owe-whole flips; the cell never "
                "exhausted credit"
            )
        for check in WIRE_CHECKS:
            need(run, f"checks.{check}", what)
    for index, run in enumerate(runs):
        for check in WIRE_CHECKS:
            if run["checks"][check] is not True:
                return f"{arm} run {index}: {check} failed"
    return None


def recovery(runs: list[dict], arm: str) -> float:
    values = []
    for index, run in enumerate(runs):
        value = number(run, "timing.recovery_ms", f"{arm} run {index}")
        if value <= 0:
            raise Invalid(f"{arm} run {index}: nonpositive recovery")
        values.append(value)
    return statistics.median(values)


def cell2(parent: Path, candidate: Path, family: str) -> tuple[str, str]:
    name = f"exhaust-{family}.json"
    arms = {
        "parent": measured(load(parent, name), f"parent {name}"),
        "candidate": measured(load(candidate, name), f"candidate {name}"),
    }
    failures = [
        reason
        for arm, runs in arms.items()
        if (reason := single_arm_exhaust(runs, arm, family)) is not None
    ]
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
    return "PASS", f"refusal witnessed on both arms; wire exact, ordered, no resets; {line}"


def cell3(parent: Path, candidate: Path, family: str) -> tuple[str, str]:
    name = f"exhaust-{family}.json"
    arms = {
        "parent": measured(load(parent, name), f"parent {name}"),
        "candidate": measured(load(candidate, name), f"candidate {name}"),
    }
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


def paused(directory: Path, arm: str) -> dict:
    exits = load(directory, "paused-exit.json")
    if any(run.get("oom") for run in exits):
        return {"oom": True}
    runs = measured(load(directory, "paused-evpn.json"), f"{arm} paused-evpn.json")
    if len(runs) != 1:
        raise Invalid(f"{arm}: expected one paused-reader run, found {len(runs)}")
    run = runs[0]
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
    if need(run, "memory.cgroup_oom_kill", arm) != "0":
        return {"oom": True}
    return {"oom": False, "run": run}


def cell1(parent: Path, candidate: Path) -> tuple[str, str]:
    arms = {"parent": paused(parent, "parent"), "candidate": paused(candidate, "candidate")}
    if arms["candidate"]["oom"]:
        return "FAIL", "candidate OOM in the 12 GiB cgroup"
    if arms["parent"]["oom"]:
        raise Invalid("parent OOM: no parent peak to compare against")
    peaks = {arm: data["run"]["memory"]["cgroup_memory_peak_bytes"] for arm, data in arms.items()}
    run = arms["candidate"]["run"]
    credit = number(run, "memory.peak_credit_bytes", "candidate bgp_rib_outbound_credit_bytes")
    row = number(run, "row_size_of", "candidate")
    credit_bar = CREDIT_TARGET + PEERS * PASS_ROWS * (row + ANNOUNCED_ROW_OVERHEAD)
    failures = []
    if peaks["candidate"] > peaks["parent"] - CELL1_MARGIN:
        failures.append(
            f"candidate cgroup peak {peaks['candidate'] / GIB:.2f} GiB > parent "
            f"{peaks['parent'] / GIB:.2f} GiB - 1.5 GiB"
        )
    if credit > credit_bar:
        failures.append(f"credit bytes peak {credit / GIB:.3f} GiB > {credit_bar / GIB:.3f} GiB")
    line = (
        f"cgroup peak {peaks['candidate'] / GIB:.2f} vs parent {peaks['parent'] / GIB:.2f} GiB; "
        f"credit bytes peak {credit / GIB:.3f} GiB (bar {credit_bar / GIB:.3f}); "
        f"VmHWM {run['memory']['vmhwm_kib'] / 2**20:.2f} GiB"
    )
    return ("FAIL", "; ".join(failures)) if failures else ("PASS", line)


def cell4(parent: Path, candidate: Path) -> tuple[str, str]:
    runs = measured(load(candidate, "probes.json"), "candidate probes.json")
    probes = []
    for index, run in enumerate(runs):
        cells = need(run, "probes", f"candidate probes run {index}")
        if not isinstance(cells, list) or len(cells) != PROBE_CELLS:
            raise Invalid(f"candidate probes run {index}: expected {PROBE_CELLS} probe cells")
        probes += cells
    dirty = [p for p in probes if number(p, "dirty_episodes", "candidate probe") != 0]
    parent_dirty = sum(
        probe.get("dirty_episodes") or 0
        for run in load(parent, "probes.json")
        for probe in run.get("probes") or []
    )
    if dirty:
        cells = ", ".join(f"{p.get('cell')}/{p.get('shape', '')}/{p.get('peers')}" for p in dirty)
        return "FAIL", f"dirty episodes in {cells}"
    return "PASS", f"0 dirty episodes in {len(probes)} probe cells (parent total {parent_dirty})"


def cell6(parent: Path, candidate: Path) -> tuple[str, str]:
    notes, flagged = [], []
    for family in FILL_FAMILIES:
        name = f"fill-{family}.json"
        run = measured(load(candidate, name), f"candidate {name}")[-1]
        estimate = number(run, "estimate.bytes_per_queued_row", f"candidate {name}")
        charged = number(run, "row_size_of", f"candidate {name}") + ANNOUNCED_ROW_OVERHEAD
        parent_runs = [r for r in load(parent, name) if r.get("mode") == "measured"]
        parent_estimate = (
            (parent_runs[-1].get("estimate") or {}).get("bytes_per_queued_row")
            if parent_runs
            else None
        )
        notes.append(
            f"{family} {estimate:.0f} B/row vs charge {charged}"
            + (f" (parent {parent_estimate:.0f})" if parent_estimate is not None else "")
        )
        if estimate > charged * ESTIMATE_RATIO:
            flagged.append(family)
    tail = f"; follow-up ticket for {', '.join(flagged)}" if flagged else ""
    return "PASS", "report-only: " + "; ".join(notes) + tail


def verdicts(parent: Path, candidate: Path) -> list[tuple[str, str, str]]:
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
    for family in FAMILIES:
        name = f"exhaust-{family}.json"
        runs = load(directory, name)
        if not runs:
            continue
        try:
            reason = single_arm_exhaust(runs, "arm", family)
            verdict = "FAIL" if reason else "PASS"
            reason = reason or "refusal witnessed; wire exact, ordered, no resets"
        except Invalid as error:
            verdict, reason = "INVALID", str(error)
        results.append((f"exhaustion {family}", verdict, reason))
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
