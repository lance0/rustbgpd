#!/usr/bin/env python3
"""Parent-versus-candidate cost comparison on the timed overlap cell.

Two ordinary terminal-debt campaigns are frozen side by side, one per product
tree, each on its own input commit: `<output>/parent` and `<output>/candidate`.
Both run their owned arm (`rustbgpd-candidate`, the daemon with EVPN group
ownership enabled); the private arm is built, as every campaign builds it, but
never run here. The schedule is three stages of timed overlap cells:

- A/A: the parent binary against itself, in pairs. Its ratio is the noise floor.
- ABBA: parent, candidate, candidate, parent, repeated.
- confirmation: one more alternated block, parent first.

A field (churn-applied, convergence) fails only when its ABBA ratio and its
confirmation ratio both exceed max(1.02, its A/A ratio + 0.01). Ratios are
candidate median over parent median within one stage. A failed field is a cost
to report; this comparison does not decide whether a change may merge.

No report-only cell is defined: the harness has three shapes (overlap,
pressure, forced refusal) and none isolates a clean-delta owned pass or a
refused-member pass.
"""

import argparse
import json
import os
from pathlib import Path
import statistics
import sys
from types import SimpleNamespace

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import check  # noqa: E402
import source  # noqa: E402

SIDES = ("parent", "candidate")
FIELDS = ("churn-applied-seconds", "convergence-seconds")
PAIRS = 5
FLOOR, MARGIN = 1.02, .01
# (stage, side) per timed overlap cell, in run order.
SCHEDULE = ([("aa", "parent")] * (2 * PAIRS)
            + [("abba", side) for side in ("parent", "candidate", "candidate", "parent") * PAIRS][:2 * PAIRS]
            + [("confirmation", side) for side in ("parent", "candidate") * PAIRS])
CORRECTNESS_SCHEDULE = [("aa", "parent"), ("aa", "parent"), ("abba", "parent"), ("abba", "candidate"),
                        ("confirmation", "parent"), ("confirmation", "candidate")]


def slots(schedule):
    """The comparison slot of every cell: in A/A the second cell of each pair
    stands in for the candidate, so the stage has a ratio of its own."""
    seen, result = 0, []
    for stage, side in schedule:
        if stage == "aa":
            result.append((stage, "candidate" if seen % 2 else "parent"))
            seen += 1
        else:
            result.append((stage, side))
    return result


def ratios(cells):
    """`cells`: (stage, slot, {field: seconds}) for every completed cell."""
    result = {}
    for field in FIELDS:
        row = {}
        for stage in ("aa", "abba", "confirmation"):
            medians = {slot: statistics.median(values[field] for cell_stage, cell_slot, values in cells
                                               if cell_stage == stage and cell_slot == slot)
                       for slot in SIDES}
            row[stage] = {"parent": medians["parent"], "candidate": medians["candidate"],
                          "ratio": medians["candidate"] / medians["parent"]}
        threshold = max(FLOOR, row["aa"]["ratio"] + MARGIN)
        row["threshold"] = threshold
        row["fail"] = row["abba"]["ratio"] > threshold and row["confirmation"]["ratio"] > threshold
        result[field] = row
    return result


def require_distinct(identities):
    """`identities`: {side: {binary name: sha256}} from each side's build receipt."""
    check.require(identities["parent"]["rustbgpd-candidate"] != identities["candidate"]["rustbgpd-candidate"],
                  "parent and candidate owned daemons are the same binary")


def load(output):
    """Verify both frozen campaigns with one set of qualification modules."""
    parent, q, r, wire = source.load(output / "parent")
    candidate = source.manifest(output / "candidate")
    files = source.archive_files(output / "candidate/qualification.tar")
    source.verify_tree(output / "candidate/input", files)
    for name in sorted((output / "parent/input/bench/scale/evpn-qualification").glob("*.py")):
        other = output / "candidate/input/bench/scale/evpn-qualification" / name.name
        check.require(other.read_bytes() == name.read_bytes(), "the two inputs carry different qualification harnesses")
    for arm in ("candidate", "private"):
        source.verify_tree(output / "candidate/sources" / arm, source.expected(output / "candidate", arm, q))
    check.require(parent["head"] == candidate["head"] and parent["bars"] == candidate["bars"]
                  and parent["timing_window"] == candidate["timing_window"]
                  and parent["qualification_head"] != candidate["qualification_head"],
                  "the two campaigns must share harness head, bars and window, and differ in input")
    return {"parent": parent, "candidate": candidate}, q, r, wire


def prepare(args, bars):
    output = Path(args.output).resolve()
    check.require(not output.exists(), "comparison directory must be new")
    output.mkdir(parents=True)
    for side, tree in (("parent", args.parent_input), ("candidate", args.candidate_input)):
        pin = source.git(Path(tree).resolve(), "rev-parse", "HEAD")
        source.prepare(SimpleNamespace(output=str(output / side), qualification_source=tree, base=pin,
                                       daemon_cpus=source.DAEMON_CPUS, harness_cpus=source.HARNESS_CPUS,
                                       window_start=args.window_start, window_end=args.window_end), bars)
    return 0


def build(args):
    output = Path(args.output).resolve()
    for side in SIDES:
        source.build(SimpleNamespace(output=str(output / side)))
    return verify(output, built=True)


def verify(output, built):
    manifests, q, _, _ = load(output)
    report = {side: {"head": manifests[side]["head"], "input": manifests[side]["qualification_head"]} for side in SIDES}
    if built:
        identities = {side: source.verify_build(output / side, manifests[side], q) for side in SIDES}
        require_distinct(identities)
        for side in SIDES:
            report[side]["binaries"] = identities[side]
    report["timing_window"] = manifests["parent"]["timing_window"]
    print(json.dumps(report, indent=1, sort_keys=True))
    return 0


def plan(correctness):
    schedule = CORRECTNESS_SCHEDULE if correctness else SCHEDULE
    for index, ((stage, side), (_, slot)) in enumerate(zip(schedule, slots(schedule), strict=True)):
        print(f"cell {index:02}  stage {stage:<12}  binary {side:<9}  compared as {slot:<9}  overlap, owned arm, "
              f"{'correctness only' if correctness else 'timed: UTC window, quiet gate, window recheck'}")
    print(f"gated fields: {', '.join(FIELDS)}; a field fails when ABBA and confirmation ratios both exceed "
          f"max({FLOOR}, A/A ratio + {MARGIN}); report-only cells: none")
    return 0


def run(args):
    import terminal
    output = Path(args.output).resolve()
    manifests, q, r, wire = load(output)
    lock = os.environ.get("RUSTBGPD_HOST_LOCK_FD")
    check.require(lock is not None and Path(f"/proc/self/fd/{int(lock)}").exists(), "the launcher must hold the host lock")
    identities = {side: source.verify_build(output / side, manifests[side], q) for side in SIDES}
    require_distinct(identities)
    check.require(not list(output.glob("*/terminal-*")) and not (output / "comparison.json").exists(),
                  "comparison already ran; no retry")
    schedule = CORRECTNESS_SCHEDULE if args.correctness_only else SCHEDULE
    q.write_json(output / "comparison.json", {"status": "INVALID", "error": "comparison incomplete"})
    rows = []
    for index, ((stage, side), (_, slot)) in enumerate(zip(schedule, slots(schedule), strict=True)):
        record = terminal.run_cell(output / side, manifests[side], q, r, wire, "overlap", "candidate", index,
                                   args.correctness_only)
        rows.append({"index": index, "stage": stage, "side": side, "slot": slot, "status": record["status"],
                     "error": record.get("error"), "cell": f"{side}/terminal-{index:02}-overlap-candidate"})
        q.write_json(output / "cells.json", rows)
        if record["status"] != "PASS":
            break
    return summarize(output, rows, schedule, args.correctness_only, identities, q)


def summarize(output, rows, schedule, correctness, identities, q):
    summary = {"status": "INVALID", "correctness_only": correctness, "cells": len(rows), "binaries": identities,
               "rule": f"fail when ABBA and confirmation both exceed max({FLOOR}, A/A + {MARGIN})"}
    bad = next((row for row in rows if row["status"] != "PASS"), None)
    if bad:
        summary.update(status="INVALID" if bad["status"] == "INVALID" else "FAIL",
                       error=f'{bad["cell"]}: {bad["status"]}: {bad["error"]}')
    elif len(rows) != len(schedule):
        summary["error"] = f"{len(rows)} of {len(schedule)} cells recorded"
    elif correctness:
        summary["status"] = "PASS"
    else:
        cells = []
        for row in rows:
            record = json.loads((output / row["cell"] / "result.json").read_text())
            check.require(record["daemon_owner"]["binary_sha256"] == identities[row["side"]]["rustbgpd-candidate"],
                          "a cell ran a binary other than its side's verified owned daemon")
            cells.append((row["stage"], row["slot"], {field: record[field] for field in FIELDS}))
        summary["fields"] = ratios(cells)
        failed = [field for field, row in summary["fields"].items() if row["fail"]]
        summary.update(status="FAIL" if failed else "PASS", failed_fields=failed)
    q.write_json(output / "comparison.json", summary)
    for field, row in summary.get("fields", {}).items():
        print(f'{field}: A/A {row["aa"]["ratio"]:.3f}  ABBA {row["abba"]["ratio"]:.3f}  confirmation '
              f'{row["confirmation"]["ratio"]:.3f}  threshold {row["threshold"]:.3f}  {"FAIL" if row["fail"] else "ok"}')
    print(f'{summary["status"]}: {summary.get("error") or summary.get("failed_fields") or "comparison complete"}')
    return {"PASS": 0, "FAIL": 1}.get(summary["status"], 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("output")
    prepare_parser.add_argument("--parent-input", required=True)
    prepare_parser.add_argument("--candidate-input", required=True)
    prepare_parser.add_argument("--window-start")
    prepare_parser.add_argument("--window-end")
    for name in ("build", "verify", "run", "plan"):
        command = sub.add_parser(name)
        command.add_argument("output")
        if name in ("run", "plan"):
            command.add_argument("--correctness-only", action="store_true")
        if name == "verify":
            command.add_argument("--built", action="store_true")
    args = parser.parse_args()
    if args.command == "prepare":
        import terminal
        return prepare(args, terminal.BARS)
    if args.command == "build":
        return build(args)
    if args.command == "verify":
        return verify(Path(args.output).resolve(), args.built)
    if args.command == "plan":
        return plan(args.correctness_only)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
