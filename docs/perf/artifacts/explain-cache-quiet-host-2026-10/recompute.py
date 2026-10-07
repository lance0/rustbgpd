#!/usr/bin/env python3
"""Recompute the receipt's arm means and differences from cells.csv."""

import csv
import json
from pathlib import Path
from statistics import mean

MIB = 1024 * 1024
HERE = Path(__file__).resolve().parent
rows = list(csv.DictReader((HERE / "cells.csv").open()))
assert len(rows) == 10 and all(r["runner_status"] == "success" for r in rows)
assert all(
    r["daemon_cgroup_swap_peak_bytes"] == "0" and r["daemon_cgroup_oom_kill"] == "0" for r in rows
)

METRICS = {
    "daemon_cgroup_peak_mib": ("daemon_cgroup_peak_bytes", MIB),
    "vmhwm_mib": ("vmhwm_kib", 1024),
    "settled_vmrss_mib": ("settled_vmrss_kib", 1024),
    "jemalloc_allocated_mib": ("jemalloc_allocated_bytes", MIB),
}


def arm(peers, size):
    cells = [r for r in rows if r["peers"] == peers and r["cache_size"] == size]
    assert cells, (peers, size)
    out = {"cells": [r["cell"] for r in cells]}
    for name, (column, scale) in METRICS.items():
        values = [int(r[column]) / scale for r in cells]
        out[name] = {
            "mean": round(mean(values), 1),
            "min": round(min(values), 1),
            "max": round(max(values), 1),
        }
    return out


def deltas(arms, base):
    return {
        key: {m: round(a[m]["mean"] - arms[base][m]["mean"], 1) for m in METRICS}
        for key, a in arms.items()
        if key != base
    }


two = {
    label: arm("2", size)
    for label, size in (("off", ""), ("4096", "4096"), ("262144", "262144"), ("1048576", "1048576"))
}
fleet = {label: arm("1000", label) for label in ("4096", "1048576")}
result = {
    "two_peer_2m_routes": {"arms": two, "minus_off": deltas(two, "off")},
    "fleet_1000x400": {"arms": fleet, "minus_4096": deltas(fleet, "4096")},
}
print(json.dumps(result, indent=2))
