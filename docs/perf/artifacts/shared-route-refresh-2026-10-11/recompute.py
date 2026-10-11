#!/usr/bin/env python3
"""Recompute archived numeric evidence with the unchanged as-run raw validators."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("validator", ROOT / "validate-control.py")
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
exits = json.loads((ROOT / "native-exits.json").read_text())
v.require(all(exits[key] == 0 for key in (
    "owner_native_exit", "wrapper_native_exit", "campaign_native_exit", "validation_native_exit"
)), "native campaign and acceptance validation succeeded")
v.require(exits["owner_fully_reaped"], "recorded owner reap")
expected = {f"{arm}/k{k}" for arm in ("a1", "b1", "b2", "a2") for k in (1, 50)}
v.require(set(exits["cells"]) == expected, "exact eight native cells")
cells = {}
for arm in ("a1", "b1", "b2", "a2"):
    cells[arm] = {}
    for k in (1, 50):
        path = ROOT / "raw" / arm / f"k{k}"
        native = exits["cells"][f"{arm}/k{k}"]
        v.require(set(native["exits"]) == {"cell", "harness", "daemon", "metrics", "wrapper"}
                  and all(value == 0 for value in native["exits"].values()), "native cell exits")
        v.require(native["forced_kill"] == 0 and native["proc_absent"], "recorded cell cleanup")
        cells[arm][str(k)] = v.raw((path / "reloadstall.log").read_text().splitlines(), k) | {
            "quiet": v.quiet(path / "quiet.tsv"),
            "cleanup": "native exits zero; no forced kills; owned PIDs and scenario absent",
        }
comparisons = {}
for k in ("1", "50"):
    values = {arm: [r["completion_max_us"] for r in cells[arm][k]["rounds"]] for arm in cells}
    pairs = {pair: [b / a for a, b in zip(values["a" + pair], values["b" + pair], strict=True)]
             for pair in ("1", "2")}
    a, b = values["a1"] + values["a2"], values["b1"] + values["b2"]
    comparisons[k] = {"all_round_max_completion_us": values,
                      "matched_candidate_over_baseline_round_ratios": pairs,
                      "candidate_over_baseline_range_extremes": [min(b) / max(a), max(b) / min(a)]}
result = {"validated": True,
          "order": ["a1/k1", "b1/k1", "b1/k50", "a1/k50", "a2/k50", "b2/k50", "b2/k1", "a2/k1"],
          "cells": cells, "comparisons": comparisons,
          "scope": "Two fresh processes per arm and K, three correlated rounds per process; all clocks, readiness, RSS, and churn gaps retained. Descriptive paired comparison without pooled significance."}
v.require(result == json.loads((ROOT / "summary.json").read_text()), "published summary exactly reproduced")
print(json.dumps(result, indent=2))
