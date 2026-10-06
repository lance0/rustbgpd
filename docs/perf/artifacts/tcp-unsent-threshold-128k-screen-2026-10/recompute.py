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
    require([number(row["reload"]) for row in values] == [1, 2, 3, 4], "expected four ordered reloads")
    for row in values:
        for value in row.values():
            number(value)
        require(all(number(row[key]) == expected for key, expected in {
            "peers_total": 700, "peers_changed": 700, "peers_stable": 0,
            "prefixes": 400400, "sessions_up": 700, "parse_errors": 0,
        }.items()), "unexpected workload or session result")
    rows[leg["leg"]] = values
require([(leg["leg"], leg["arm"]) for leg in legs] == [
    (1, "unset"), (2, "131072"), (3, "131072"),
    (4, "unset"), (5, "unset"), (6, "131072"),
], "unexpected leg order")
require({(number(row["leg"]), number(row["reload"]), row["arm"]) for row in cpu} == {
    (leg["leg"], reload, leg["arm"]) for leg in legs for reload in range(1, 5)
}, "CPU windows do not cover every reload")


def change(before, after):
    return (after / before - 1) * 100

arms = {}
for arm in ("unset", "131072"):
    selected = [leg for leg in legs if leg["arm"] == arm]
    reloads = [row for leg in selected for row in rows[leg["leg"]]]
    completion = [number(row["completion_p50_s"]) for row in reloads]
    stall = [number(row["changed_maxgap_p50_ms"]) for row in reloads]
    peaks = [number(leg["kernel_scope_peak_observed_bytes"]) / 2**20 for leg in selected]
    bursts = [number(row["cpu_seconds_outer_bracket"]) for row in cpu if row["arm"] == arm]
    controls = [number(row["control_cpu_seconds_outer_bracket"]) for row in cpu if row["arm"] == arm]
    windows = [row for row in cpu if row["arm"] == arm]
    durations = [number(row["wall_seconds_requested"]) for row in windows]
    widths = [number(row["wall_seconds_requested"]) + number(row["bracket_extra_ms"]) / 1000 for row in windows]
    control_widths = [number(row["control_wall_seconds_requested"]) + number(row["control_bracket_extra_ms"]) / 1000 for row in windows]
    require(all(width > 0 for width in widths + control_widths), "CPU bracket widths must be positive")
    leg_completion = [median(number(row["completion_p50_s"]) for row in rows[leg["leg"]]) for leg in selected]
    leg_stall = [median(number(row["changed_maxgap_p50_ms"]) for row in rows[leg["leg"]]) for leg in selected]
    arms[arm] = {
        "independent_legs": len(selected), "correlated_reload_rows": len(reloads),
        "completion_p50_median_s": median(completion),
        "completion_p50_range_s": [min(completion), max(completion)],
        "independent_leg_completion_medians_s": leg_completion,
        "independent_leg_completion_median_s": median(leg_completion),
        "independent_leg_stall_medians_ms": leg_stall,
        "independent_leg_stall_median_ms": median(leg_stall),
        "stall_p50_median_ms": median(stall),
        "stall_p50_range_ms": [min(stall), max(stall)],
        "worst_completion_s": max(number(row["completion_max_s"]) for row in reloads),
        "worst_stall_ms": max(number(row["changed_maxgap_max_ms"]) for row in reloads),
        "observed_kernel_peak_median_mib": median(peaks),
        "observed_kernel_peak_range_mib": [min(peaks), max(peaks)],
        "burst_cpu_outer_bracket_median_s": median(bursts),
        "burst_requested_duration_median_s": median(durations),
        "burst_outer_bracket_width_median_s": median(widths),
        "burst_cpu_rate_outer_bracket_median": median(value / width for value, width in zip(bursts, widths, strict=True)),
        "control_cpu_outer_bracket_median_s": median(controls),
        "control_outer_bracket_width_median_s": median(control_widths),
        "control_cpu_rate_outer_bracket_median": median(value / width for value, width in zip(controls, control_widths, strict=True)),
        "trace_cpu_seconds": [number(leg["cpu_seconds_across_observed_trace"]) for leg in selected],
        "trace_cpu_median_s": median(number(leg["cpu_seconds_across_observed_trace"]) for leg in selected),
    }
before, after = arms["unset"], arms["131072"]
changes = {key: change(before[key], after[key]) for key in (
    "completion_p50_median_s", "stall_p50_median_ms",
    "independent_leg_completion_median_s", "independent_leg_stall_median_ms",
    "burst_cpu_outer_bracket_median_s", "trace_cpu_median_s",
)}
reduction = before["observed_kernel_peak_median_mib"] - after["observed_kernel_peak_median_mib"]
numeric_screen_passes = (
    changes["completion_p50_median_s"] <= 2
    and changes["stall_p50_median_ms"] <= 2
    and reduction >= 100
)
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
        "stall_at_most_plus_2_percent": changes["stall_p50_median_ms"] <= 2,
        "memory_reduction_at_least_100_mib": reduction >= 100,
        "writer_wakeup_gate": "unresolved",
        "frozen_131072_byte_candidate": "incomplete" if numeric_screen_passes else "NO-GO",
    },
}, indent=2, allow_nan=False))
