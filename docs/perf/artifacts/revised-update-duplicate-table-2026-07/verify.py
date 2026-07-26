#!/usr/bin/env python3
"""Recompute the revised UPDATE duplicate-table receipt from retained data."""

from __future__ import annotations

import gzip
import json
import statistics
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ATTEMPTS = 6


def median_estimate(kind: str, attempt: int, side: str) -> tuple[float, float, float]:
    path = ROOT / "estimates" / kind / f"attempt-{attempt}-{side}.json"
    median = json.loads(path.read_text(encoding="utf-8"))["median"]
    confidence = median["confidence_interval"]
    return (
        float(median["point_estimate"]),
        float(confidence["lower_bound"]),
        float(confidence["upper_bound"]),
    )


def timing_summary(kind: str) -> dict[str, float]:
    base_medians: list[float] = []
    head_medians: list[float] = []
    deltas: list[float] = []
    last_base: tuple[float, float, float] | None = None
    last_head: tuple[float, float, float] | None = None
    for attempt in range(1, ATTEMPTS + 1):
        base = median_estimate(kind, attempt, "base")
        head = median_estimate(kind, attempt, "head")
        base_medians.append(base[0])
        head_medians.append(head[0])
        deltas.append((head[0] - base[0]) / base[0] * 100.0)
        last_base = base
        last_head = head

    assert last_base is not None and last_head is not None
    last_ci_low = (last_head[1] - last_base[2]) / last_base[2] * 100.0
    last_ci_high = (last_head[2] - last_base[1]) / last_base[1] * 100.0
    return {
        "base_median_mean_ns": statistics.mean(base_medians),
        "head_median_mean_ns": statistics.mean(head_medians),
        "mean_delta_percent": statistics.mean(deltas),
        "delta_stddev_percent": statistics.stdev(deltas),
        "delta_min_percent": min(deltas),
        "delta_max_percent": max(deltas),
        "last_ci_low_percent": last_ci_low,
        "last_ci_high_percent": last_ci_high,
    }


def assert_rounded(actual: dict[str, float], expected: dict[str, float]) -> None:
    for key, expected_value in expected.items():
        digits = 1 if key.endswith("_ns") else 2
        assert round(actual[key], digits) == expected_value, (
            key,
            actual[key],
            expected_value,
        )


def load_diagnostic(path: Path) -> dict[str, dict[str, object]]:
    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(rows) == 3
    assert all(row["schema_version"] == 1 for row in rows)
    assert all(row["operations"] == 10_000 for row in rows)
    return {str(row["benchmark"]): row for row in rows}


def allocation_tuple(row: dict[str, object]) -> tuple[int, int, int, int, int]:
    return (
        int(row["alloc_calls"]),
        int(row["alloc_zeroed_calls"]),
        int(row["realloc_calls"]),
        int(row["allocation_calls"]),
        int(row["requested_bytes"]),
    )


def main() -> None:
    manifest = json.loads((ROOT / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["schema_version"] == 1

    summaries = {
        kind: timing_summary(kind)
        for kind in ("control", "target")
    }
    for kind, actual in summaries.items():
        assert_rounded(actual, manifest["timing"][kind]["expected_rounded"])

    gap = (
        summaries["control"]["delta_min_percent"]
        - summaries["target"]["delta_max_percent"]
    )
    assert round(gap, 2) == manifest["timing"]["minimum_band_gap_percentage_points"]

    log_paths = sorted((ROOT / "logs").glob("*/*.log.gz"))
    assert len(log_paths) == 24
    for path in log_paths:
        with gzip.open(path, "rt", encoding="utf-8") as stream:
            text = stream.read()
        assert "Benchmarking update_parse_revised/1" in text
        assert "time:" in text

    diagnostic_paths = sorted((ROOT / "allocations").glob("*.jsonl"))
    assert len(diagnostic_paths) == 6
    diagnostics = [load_diagnostic(path) for path in diagnostic_paths]
    baseline = diagnostics[0]
    for repeat in diagnostics[1:2]:
        assert repeat == baseline
    candidates = diagnostics[2:]
    for candidate in candidates:
        assert candidate == diagnostics[2]

    hot_path = "attr_decode_revised/typical/6"
    assert allocation_tuple(baseline[hot_path]) == (50_000, 0, 10_000, 60_000, 26_920_000)
    assert allocation_tuple(candidates[0][hot_path]) == (
        40_000,
        0,
        10_000,
        50_000,
        26_440_000,
    )
    assert baseline[hot_path]["fixture_len_bytes"] == 53
    assert baseline[hot_path]["fixture_attributes"] == 6
    assert baseline[hot_path]["fixture_digest"] == candidates[0][hot_path]["fixture_digest"]

    for negative_control in ("attr_encode/rich/11", "validate_update"):
        assert baseline[negative_control] == candidates[0][negative_control]

    assert (
        baseline[hot_path]["allocation_calls"]
        - candidates[0][hot_path]["allocation_calls"]
    ) // 10_000 == manifest["allocation"]["requests_removed_per_call"]
    assert (
        baseline[hot_path]["requested_bytes"]
        - candidates[0][hot_path]["requested_bytes"]
    ) // 10_000 == manifest["allocation"]["requested_bytes_removed_per_call"]

    red = (ROOT / "restored-hashset-red.txt").read_text(encoding="utf-8")
    assert "left: (50000, 0, 10000, 60000, 26920000)" in red
    assert "right: (40000, 0, 10000, 50000, 26440000)" in red
    print(json.dumps({"timing": summaries, "minimum_band_gap_pp": gap}, indent=2))
    print("receipt verification: PASS")


if __name__ == "__main__":
    main()
