#!/usr/bin/env python3
"""Recompute this receipt from its compact published extracts (stdlib only)."""
import csv
import json
import math
from pathlib import Path
from statistics import median

def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value):
    result = float(value)
    require(math.isfinite(result), "non-finite measurement")
    return result


ROOT = Path(__file__).resolve().parent
legs = json.loads((ROOT / "legs.json").read_text())
with (ROOT / "cpu-brackets.csv").open() as stream:
    cpu = list(csv.DictReader(stream))
require(len(legs) == 6 and len(cpu) == 24, "expected six legs and 24 CPU rows")
rows = {}
for leg in legs:
    lines = (ROOT / leg["reload_csv"]).read_text().splitlines()
    require(bool(lines) and lines[0].startswith("reloadstall_csv_header,"), "missing CSV header")
    require(all(line.startswith("reloadstall_csv,") for line in lines[1:]), "unexpected CSV row marker")
    values = list(csv.DictReader(line.split(",", 1)[1] for line in lines))
    require([int(row["reload"]) for row in values] == [1, 2, 3, 4], "expected four ordered reloads")
    for row in values:
        require(all(int(row[key]) == expected for key, expected in {
            "peers_total": 700, "peers_changed": 700, "peers_stable": 0,
            "prefixes": 400400, "sessions_up": 700, "parse_errors": 0,
        }.items()), "unexpected workload or session result")
    rows[leg["leg"]] = values
require([(leg["leg"], leg["arm"]) for leg in legs] == [
    (1, "unset"), (2, "65536"), (3, "65536"),
    (4, "unset"), (5, "unset"), (6, "65536"),
], "unexpected leg order")
require({(int(row["leg"]), int(row["reload"]), row["arm"]) for row in cpu} == {
    (leg["leg"], reload, leg["arm"]) for leg in legs for reload in range(1, 5)
}, "CPU windows do not cover every reload")

def change(before, after):
    return (after / before - 1) * 100

arms = {}
for arm in ("unset", "65536"):
    selected = [leg for leg in legs if leg["arm"] == arm]
    reloads = [row for leg in selected for row in rows[leg["leg"]]]
    completion = [number(row["completion_p50_s"]) for row in reloads]
    stall = [number(row["changed_maxgap_p50_ms"]) for row in reloads]
    peaks = [number(leg["kernel_scope_peak_observed_bytes"]) / 2**20 for leg in selected]
    bursts = [number(row["cpu_seconds_outer_bracket"]) for row in cpu if row["arm"] == arm]
    controls = [number(row["control_cpu_seconds_outer_bracket"]) for row in cpu if row["arm"] == arm]
    arms[arm] = {
        "independent_legs": len(selected), "correlated_reload_rows": len(reloads),
        "completion_p50_median_s": median(completion),
        "completion_p50_range_s": [min(completion), max(completion)],
        "stall_p50_median_ms": median(stall),
        "stall_p50_range_ms": [min(stall), max(stall)],
        "worst_completion_s": max(number(row["completion_max_s"]) for row in reloads),
        "worst_stall_ms": max(number(row["changed_maxgap_max_ms"]) for row in reloads),
        "observed_kernel_peak_median_mib": median(peaks),
        "observed_kernel_peak_range_mib": [min(peaks), max(peaks)],
        "burst_cpu_outer_bracket_median_s": median(bursts),
        "control_cpu_outer_bracket_median_s": median(controls),
        "trace_cpu_median_s": median(number(leg["cpu_seconds_across_observed_trace"]) for leg in selected),
    }
before, after = arms["unset"], arms["65536"]
changes = {key: change(before[key], after[key]) for key in (
    "completion_p50_median_s", "stall_p50_median_ms",
    "burst_cpu_outer_bracket_median_s", "trace_cpu_median_s",
)}
reduction = before["observed_kernel_peak_median_mib"] - after["observed_kernel_peak_median_mib"]
pairs = []
for baseline, candidate in ((1, 2), (4, 3), (5, 6)):
    pairs.append({
        "unset_leg": baseline, "candidate_leg": candidate,
        "completion_p50_median_change_percent": change(
            median(number(row["completion_p50_s"]) for row in rows[baseline]),
            median(number(row["completion_p50_s"]) for row in rows[candidate])),
        "observed_kernel_peak_reduction_mib": (
            number(legs[baseline - 1]["kernel_scope_peak_observed_bytes"])
            - number(legs[candidate - 1]["kernel_scope_peak_observed_bytes"])) / 2**20,
    })
print(json.dumps({
    "arms": arms, "change_percent": changes,
    "observed_kernel_peak_median_reduction_mib": reduction,
    "matched_pairs": pairs,
    "screen_components": {
        "completion_at_most_plus_2_percent": changes["completion_p50_median_s"] <= 2,
        "memory_reduction_at_least_100_mib": reduction >= 100,
        "writer_wakeup_gate": "unresolved",
        "frozen_65536_byte_candidate": "NO-GO" if changes["completion_p50_median_s"] > 2 else "incomplete",
    },
}, indent=2, allow_nan=False))
