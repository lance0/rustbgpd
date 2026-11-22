#!/usr/bin/env python3
"""Grade a source-departure campaign against its frozen qualification bars.

The campaign root holds one `source_departure.py` output directory per run,
named by stage and run order:

- `aa-1`, `aa-2`, ...: the parent binary, `--arm parent`, in pairs. The second
  run of each pair stands in for the candidate, so A/A has a ratio of its own.
- `abba-1` ... `abba-4n`: parent, candidate, candidate, parent, repeated.
- `confirmation-1` ... `confirmation-2n`: parent, candidate, repeated.

Each cell (one mode at the campaign's shape) is PASS, FAIL or INVALID:

- FAIL on any failed trial; on swap use; on a candidate trial that published
  more than 256 measured withdrawal rows in one poll (the work bar's observable
  lower bound); on an UPDATE applied in the wrong order relative to the final
  withdrawal publication; or on an inexact receiver inventory.
- INVALID when a trial is INVALID or SKIP, a stage lacks the mode, the arms or
  binaries are not as scheduled, or the two arms ran identical binaries.
- FAIL when the candidate mean UPDATE-to-Loc-RIB delay exceeds 0.50 of the
  parent mean in ABBA or in confirmation.
- FAIL when end-to-end convergence or cgroup peak exceeds max(1.02, A/A + 0.01)
  in both ABBA and confirmation. Ratios are candidate mean over parent mean
  within one stage, over every run and repetition.

Exit status: 0 every cell PASS, 1 any FAIL, 2 otherwise.
"""

import argparse
from pathlib import Path
import re
import statistics
import sys

from recovery_memory import InvalidReceipt, read_object, require, uint, write_json

STAGES = ("aa", "abba", "confirmation")
ORDER = {
    "aa": ("parent", "parent"),
    "abba": ("parent", "candidate", "candidate", "parent"),
    "confirmation": ("parent", "candidate"),
}
DELAY_BAR = 0.50
WORK_BAR = 256
FLOOR, MARGIN = 1.02, 0.01
COSTS = {
    "convergence": lambda trial: uint(trial["observation"]["convergence_ns"], "convergence"),
    "cgroup_peak": lambda trial: uint(trial["cgroup_peak_bytes"], "cgroup peak"),
}


def load(root):
    """Every scheduled run as (stage, slot, receipt), after the identity checks."""
    runs = {stage: [] for stage in STAGES}
    for entry in sorted(root.iterdir()):
        match = re.fullmatch(r"(aa|abba|confirmation)-([1-9][0-9]*)", entry.name)
        if match:
            runs[match[1]].append((int(match[2]), read_object(entry / "receipt.json")))
    loaded, shapes, binaries = [], set(), {"parent": set(), "candidate": set()}
    for stage, entries in runs.items():
        entries.sort(key=lambda item: item[0])
        order = ORDER[stage]
        require(
            entries and len(entries) % len(order) == 0,
            f"{stage} needs whole {'/'.join(order)} blocks",
        )
        require(
            [index for index, _ in entries] == list(range(1, len(entries) + 1)),
            f"{stage} runs are not numbered contiguously from 1",
        )
        for index, receipt in entries:
            arm = order[(index - 1) % len(order)]
            require(receipt.get("arm") == arm, f"{stage}-{index} must be the {arm} arm")
            require(receipt.get("break_witness") is False, f"{stage}-{index} is a control run")
            shapes.add(receipt.get("shape"))
            binaries[arm].add(receipt.get("binary_sha256"))
            slot = ("candidate" if index % 2 == 0 else "parent") if stage == "aa" else arm
            loaded.append((stage, index, slot, receipt))
    require(len(shapes) == 1, "runs mix shapes")
    require(
        all(len(digests) == 1 for digests in binaries.values()),
        "each arm must use one binary throughout",
    )
    require(binaries["parent"] != binaries["candidate"], "identical binaries cannot be compared")
    return shapes.pop(), loaded


def hard_failure(stage, index, slot, receipt, trial):
    """A correctness or fixed-ceiling breach in one completed trial, else None."""
    where = f"{stage}-{index} rep {trial.get('repetition')}"
    if trial["verdict"] == "FAIL":
        return f"{where}: {trial.get('reason')}"
    if trial["verdict"] != "PASS":
        return None
    row = trial["observation"]
    if uint(trial.get("swap_peak_bytes"), "swap peak") != 0:
        return f"{where}: swap used"
    if row.get("exact") is not True or uint(row["rib_withdrawal_rows"], "rows") != uint(
        row["receivers"], "receivers"
    ) * uint(row["rows"], "rows"):
        return f"{where}: inexact receiver inventory"
    candidate = receipt["arm"] == "candidate"
    if row.get("update_applied_before_departure_complete") is not candidate:
        return f"{where}: Loc-RIB application order does not match the {receipt['arm']} arm"
    work = uint(row["max_withdrawals_per_poll"], "withdrawals per poll")
    if candidate and work > WORK_BAR:
        return f"{where}: {work} withdrawals in one poll exceeds {WORK_BAR}"
    return None


def ratio(samples, stage, measure):
    means = {}
    for slot in ("parent", "candidate"):
        values = [measure(trial) for trial in samples[(stage, slot)]]
        means[slot] = statistics.mean(values)
    require(means["parent"] > 0, f"{stage} parent mean is zero")
    return means["candidate"] / means["parent"]


def grade(mode, loaded):
    """(verdict, one-line reason, ratios) for one mode."""
    samples = {(stage, slot): [] for stage in STAGES for slot in ("parent", "candidate")}
    unqualified = []
    for stage, index, slot, receipt in loaded:
        trials = [trial for trial in receipt.get("trials", []) if trial.get("mode") == mode]
        if not trials:
            unqualified.append(f"{stage}-{index} has no {mode} trial")
        for trial in trials:
            failure = hard_failure(stage, index, slot, receipt, trial)
            if failure:
                return "FAIL", failure, {}
            if trial["verdict"] == "PASS":
                samples[(stage, slot)].append(trial)
            else:
                unqualified.append(f"{stage}-{index}: {trial['verdict']} {trial.get('reason')}")
    if unqualified:
        return "INVALID", unqualified[0], {}
    ratios = {
        "delay": {
            stage: ratio(
                samples,
                stage,
                lambda trial: uint(trial["observation"]["update_to_applied_ns"], "delay"),
            )
            for stage in ("abba", "confirmation")
        }
    }
    failures = [
        f"UPDATE delay {stage} {value:.3f} > {DELAY_BAR}"
        for stage, value in ratios["delay"].items()
        if value > DELAY_BAR
    ]
    for name, measure in COSTS.items():
        row = {stage: ratio(samples, stage, measure) for stage in STAGES}
        row["threshold"] = max(FLOOR, row["aa"] + MARGIN)
        ratios[name] = row
        if row["abba"] > row["threshold"] and row["confirmation"] > row["threshold"]:
            failures.append(
                f"{name} ABBA {row['abba']:.3f} and confirmation {row['confirmation']:.3f}"
                f" > {row['threshold']:.3f}"
            )
    if failures:
        return "FAIL", "; ".join(failures), ratios
    delay = ratios["delay"]
    return (
        "PASS",
        f"UPDATE delay ABBA {delay['abba']:.3f} / confirmation {delay['confirmation']:.3f};"
        " convergence and cgroup peak within threshold",
        ratios,
    )


def summarize(root):
    try:
        shape, loaded = load(root)
    except (InvalidReceipt, OSError, KeyError, ValueError) as err:
        return {"campaign": {"verdict": "INVALID", "reason": str(err)}}
    modes = sorted(
        {trial.get("mode") for *_, receipt in loaded for trial in receipt.get("trials", [])}
    )
    cells = {}
    for mode in modes:
        try:
            verdict, reason, ratios = grade(mode, loaded)
        except (InvalidReceipt, KeyError, TypeError, ValueError) as err:
            verdict, reason, ratios = "INVALID", f"malformed trial: {err}", {}
        cells[f"{shape}/{mode}"] = {"verdict": verdict, "reason": reason, "ratios": ratios}
    return cells or {"campaign": {"verdict": "INVALID", "reason": "no trials"}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    cells = summarize(args.root.resolve())
    write_json(args.root / "summary.json", cells)
    for name, cell in cells.items():
        print(f"{name}: {cell['verdict']} — {cell['reason']}")
    verdicts = {cell["verdict"] for cell in cells.values()}
    return 0 if verdicts == {"PASS"} else 1 if "FAIL" in verdicts else 2


if __name__ == "__main__":
    sys.exit(main())
