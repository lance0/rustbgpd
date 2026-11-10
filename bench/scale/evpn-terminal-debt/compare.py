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
from pathlib import Path
import statistics
import subprocess
import sys

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


def product(files):
    """The product sources of one input: everything under `src/` and `crates/`."""
    return {name: data for name, data in files.items() if name.startswith(("src/", "crates/"))}


def require_distinct(parent, candidate):
    """Each argument: {path: content} of one input. Binary digests cannot tell
    the sides apart, because each daemon embeds its own build directory; the
    two product trees must differ."""
    check.require(product(parent) != product(candidate), "parent and candidate inputs carry the same product tree")


def load(output):
    """Verify both frozen campaigns with one set of qualification modules."""
    parent, q, r, wire = source.load(output / "parent")
    candidate = source.manifest(output / "candidate")
    files = source.archive_files(output / "candidate/qualification.tar")
    source.verify_tree(output / "candidate/input", files)
    require_distinct(source.archive_files(output / "parent/qualification.tar"), files)
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


def one_campaign(*arguments):
    """Each side is an ordinary campaign, frozen and built by the ordinary
    runner in its own process: one process may load one qualification input."""
    subprocess.run([sys.executable, "-B", str(HERE / "terminal.py"), *arguments], check=True)


def prepare(args):
    output = Path(args.output).resolve()
    check.require(not output.exists(), "comparison directory must be new")
    trees = [source.git(Path(tree).resolve(), "rev-parse", "HEAD:src", "HEAD:crates")
             for tree in (args.parent_input, args.candidate_input)]
    check.require(trees[0] != trees[1], "parent and candidate inputs carry the same product tree")
    output.mkdir(parents=True)
    for side, tree in (("parent", args.parent_input), ("candidate", args.candidate_input)):
        window = ["--window-start", args.window_start, "--window-end", args.window_end] if args.window_start else []
        one_campaign("prepare", str(output / side), "--qualification-source", tree,
                     "--base", source.git(Path(tree).resolve(), "rev-parse", "HEAD"),
                     "--daemon-cpus", source.DAEMON_CPUS, "--harness-cpus", source.HARNESS_CPUS, *window)
    return 0


def build(args):
    output = Path(args.output).resolve()
    for side in SIDES:
        one_campaign("build", str(output / side))
    return verify(output, built=True)


def verify(output, built):
    manifests, q, _, _ = load(output)
    report = {side: {"head": manifests[side]["head"], "input": manifests[side]["qualification_head"]} for side in SIDES}
    if built:
        identities = {side: source.verify_build(output / side, manifests[side], q) for side in SIDES}
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
    q.require_host_lock()
    identities = {side: source.verify_build(output / side, manifests[side], q) for side in SIDES}
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
        return prepare(args)
    if args.command == "build":
        return build(args)
    if args.command == "verify":
        return verify(Path(args.output).resolve(), args.built)
    if args.command == "plan":
        return plan(args.correctness_only)
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
