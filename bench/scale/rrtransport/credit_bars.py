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


def require(value, what: str):
    if value is None:
        raise Invalid(f"missing instrument {what}")
    return value


def measured(runs: list[dict], what: str) -> list[dict]:
    if not runs:
        raise Invalid(f"no {what} result")
    for run in runs:
        if run.get("mode") != "measured":
            raise Invalid(f"{what} result is a {run.get('mode')} run, not measured")
    return runs


def single_arm_exhaust(runs: list[dict], arm: str, family: str) -> str | None:
    """Raise INVALID for a missing witness; return a FAIL reason or None."""
    for index, run in enumerate(runs):
        witness = run.get("witness") or {}
        refused = witness.get("refused_receivers")
        flips = witness.get("owing_flips_total")
        receivers = witness.get("receivers")
        if refused is None or flips is None or receivers is None:
            raise Invalid(f"{arm} run {index}: missing refusal witness")
        # Past its credit a private family either refuses the send or owes
        # its keys; this shape's owed sets outgrow their cap, so each burst
        # receiver flips to owing the family whole. Either signal on every
        # receiver is the witness.
        if refused < receivers and flips < receivers:
            raise Invalid(
                f"{arm} run {index}: credit exhaustion witnessed on {refused}/{receivers} "
                f"receivers by refusal and {flips:.0f} owe-whole flips; the cell never "
                "exhausted credit"
            )
        checks = run.get("checks") or {}
        for check in WIRE_CHECKS:
            if checks.get(check) is not True:
                return f"{arm} run {index}: {check} failed"
        if require(run.get("timing", {}).get("recovery_ms"), f"{family} recovery_ms") <= 0:
            raise Invalid(f"{arm} run {index}: nonpositive recovery")
    return None


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
    recovery = {
        arm: statistics.median(run["timing"]["recovery_ms"] for run in runs)
        for arm, runs in arms.items()
    }
    bar = max(recovery["parent"] * RECOVERY_RATIO, recovery["parent"] + RECOVERY_SLACK_MS)
    line = (
        f"recovery candidate {recovery['candidate']:.0f} ms vs bar {bar:.0f} ms "
        f"(parent {recovery['parent']:.0f} ms)"
    )
    if recovery["candidate"] > bar:
        failures.append(f"recovery over bar: {line}")
    if failures:
        return "FAIL", "; ".join(failures)
    return "PASS", f"refusal witnessed on both arms; wire exact, ordered, no resets; {line}"


def cell3(parent: Path, candidate: Path, family: str) -> tuple[str, str]:
    name = f"exhaust-{family}.json"
    arms = {
        "parent": measured(load(parent, name), f"parent {name}"),
        "candidate": measured(load(candidate, name), f"candidate {name}"),
    }
    p99 = {}
    for arm, runs in arms.items():
        values = []
        for run in runs:
            unaffected = require(run.get("unaffected"), f"{arm} unaffected-peer record")
            if not unaffected.get("injected") or not unaffected.get("delivered"):
                raise Invalid(f"{arm}: the healthy receiver got no churn")
            values.append(require(unaffected.get("p99_latency_ms"), f"{arm} p99_latency_ms"))
        p99[arm] = statistics.median(values)
    gaps = [
        require(run["unaffected"].get("max_gap_ms"), "candidate max_gap_ms")
        for run in arms["candidate"]
    ]
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
    memory = runs[0].get("memory") or {}
    if memory.get("cgroup_swap_max") != "0":
        raise Invalid(f"{arm}: swap not fenced (memory.swap.max={memory.get('cgroup_swap_max')})")
    if memory.get("cgroup_memory_max") != str(CELL1_CGROUP_MAX):
        raise Invalid(f"{arm}: cgroup limit {memory.get('cgroup_memory_max')}, not 12 GiB")
    require(memory.get("cgroup_memory_peak_bytes"), f"{arm} cgroup memory.peak")
    require(memory.get("vmhwm_kib"), f"{arm} VmHWM")
    if memory.get("cgroup_oom_kill") not in (None, "0"):
        return {"oom": True}
    return {"oom": False, "memory": memory, "row_size_of": runs[0].get("row_size_of")}


def cell1(parent: Path, candidate: Path) -> tuple[str, str]:
    arms = {"parent": paused(parent, "parent"), "candidate": paused(candidate, "candidate")}
    if arms["candidate"]["oom"]:
        return "FAIL", "candidate OOM in the 12 GiB cgroup"
    if arms["parent"]["oom"]:
        raise Invalid("parent OOM: no parent peak to compare against")
    peaks = {arm: data["memory"]["cgroup_memory_peak_bytes"] for arm, data in arms.items()}
    credit = require(
        arms["candidate"]["memory"].get("peak_credit_bytes"),
        "candidate bgp_rib_outbound_credit_bytes",
    )
    row = require(arms["candidate"]["row_size_of"], "candidate row_size_of")
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
        f"VmHWM {arms['candidate']['memory']['vmhwm_kib'] / 2**20:.2f} GiB"
    )
    return ("FAIL", "; ".join(failures)) if failures else ("PASS", line)


def cell4(parent: Path, candidate: Path) -> tuple[str, str]:
    runs = measured(load(candidate, "probes.json"), "candidate probes.json")
    parent_runs = load(parent, "probes.json")
    probes = [probe for run in runs for probe in run.get("probes", [])]
    if len(probes) < PROBE_CELLS * len(runs):
        raise Invalid(f"{len(probes)} probe cells, expected {PROBE_CELLS} per run")
    dirty = [p for p in probes if require(p.get("dirty_episodes"), "dirty_episodes") != 0]
    parent_dirty = sum(
        probe.get("dirty_episodes") or 0 for run in parent_runs for probe in run.get("probes", [])
    )
    if dirty:
        cells = ", ".join(f"{p['cell']}/{p.get('shape', '')}/{p['peers']}" for p in dirty)
        return "FAIL", f"dirty episodes in {cells}"
    return "PASS", f"0 dirty episodes in {len(probes)} probe cells (parent total {parent_dirty})"


def cell6(parent: Path, candidate: Path) -> tuple[str, str]:
    notes, flagged = [], []
    for family in FILL_FAMILIES:
        runs = load(candidate, f"fill-{family}.json")
        if not runs:
            raise Invalid(f"no candidate fill-{family}.json")
        estimate = require(runs[-1].get("estimate", {}).get("bytes_per_queued_row"), family)
        charged = require(runs[-1].get("row_size_of"), f"{family} row_size_of") + (
            ANNOUNCED_ROW_OVERHEAD
        )
        parent_runs = load(parent, f"fill-{family}.json")
        parent_estimate = (
            parent_runs[-1].get("estimate", {}).get("bytes_per_queued_row") if parent_runs else None
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
