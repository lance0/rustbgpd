#!/usr/bin/env python3
"""Validate and gate the exact event-history producer Criterion result matrix."""

from __future__ import annotations

import argparse
import csv
import json
import math
from dataclasses import dataclass
from pathlib import Path


SHAPES = ("route_added", "route_policy_filtered", "evpn_best_changed")
MANAGER_GROUP = "event_history_manager_self_time"
SQLITE_GROUP = "event_history_sqlite_end_to_end"
EXPECTED_IDS = {
    *(f"{MANAGER_GROUP}/{shape}/{mode}" for shape in SHAPES for mode in ("noop", "ehm")),
    *(f"{SQLITE_GROUP}/{shape}/full" for shape in SHAPES),
}


def fail(message: str) -> None:
    raise SystemExit(message)


def regular_file(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        fail(f"{label} is not a regular file: {path}")


def read_json(path: Path, label: str) -> dict[str, object]:
    regular_file(path, label)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot read {label}: {error}")
    if not isinstance(value, dict):
        fail(f"{label} must contain a JSON object")
    return value


def finite_positive(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        fail(f"{label} is not numeric: {value!r}")
    result = float(value)
    if not math.isfinite(result) or result <= 0:
        fail(f"{label} is not finite and positive: {value!r}")
    return result


@dataclass(frozen=True)
class Estimate:
    point: float
    lower: float
    upper: float


def estimate(path: Path, label: str) -> Estimate:
    root = read_json(path, label)
    mean = root.get("mean")
    if not isinstance(mean, dict):
        fail(f"{label} has no mean estimate")
    interval = mean.get("confidence_interval")
    if not isinstance(interval, dict):
        fail(f"{label} has no mean confidence interval")
    confidence = finite_positive(interval.get("confidence_level"), f"{label} confidence")
    if not math.isclose(confidence, 0.95, rel_tol=0, abs_tol=1e-12):
        fail(f"{label} confidence is not 0.95: {confidence}")
    result = Estimate(
        point=finite_positive(mean.get("point_estimate"), f"{label} point"),
        lower=finite_positive(interval.get("lower_bound"), f"{label} lower bound"),
        upper=finite_positive(interval.get("upper_bound"), f"{label} upper bound"),
    )
    if not result.lower <= result.point <= result.upper:
        fail(f"{label} point is outside its confidence interval")
    return result


def inventory(root: Path, run_name: str) -> dict[str, Estimate]:
    if root.is_symlink() or not root.is_dir():
        fail(f"Criterion directory is not a regular directory: {root}")
    found: dict[str, Estimate] = {}
    for benchmark_path in root.glob(f"**/{run_name}/benchmark.json"):
        benchmark = read_json(benchmark_path, "Criterion benchmark identity")
        full_id = benchmark.get("full_id")
        if not isinstance(full_id, str) or not full_id:
            fail(f"Criterion benchmark has no full_id: {benchmark_path}")
        if full_id in found:
            fail(f"duplicate Criterion benchmark identity: {full_id}")
        found[full_id] = estimate(
            benchmark_path.with_name("estimates.json"),
            f"Criterion estimate {full_id}/{run_name}",
        )
    if set(found) != EXPECTED_IDS:
        missing = sorted(EXPECTED_IDS - set(found))
        extra = sorted(set(found) - EXPECTED_IDS)
        fail(f"Criterion matrix mismatch: missing={missing!r} extra={extra!r}")
    return found


def intervals_overlap(left: Estimate, right: Estimate) -> bool:
    return left.lower <= right.upper and right.lower <= left.upper


def pct_delta(base: Estimate, head: Estimate) -> float:
    return ((head.point / base.point) - 1.0) * 100.0


def gate_baseline(base: dict[str, Estimate]) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    passing = 0
    for shape in SHAPES:
        noop = base[f"{MANAGER_GROUP}/{shape}/noop"]
        ehm = base[f"{MANAGER_GROUP}/{shape}/ehm"]
        overhead = pct_delta(noop, ehm)
        ci_separated = ehm.lower > noop.upper
        passed = overhead >= 25.0 and ci_separated
        passing += int(passed)
        rows.append(
            {
                "shape": shape,
                "ehm_overhead_pct": overhead,
                "confidence_intervals_separated": ci_separated,
                "pass": passed,
            }
        )
    return {
        "phase": "baseline",
        "manager_proceed_pass": passing >= 2,
        "manager_shapes_passing": passing,
        "required_manager_shapes": 2,
        "full_daemon_attribution_required_pct": 5.0,
        "full_daemon_attribution_status": "separate_required_receipt",
        "rows": rows,
    }


def gate_candidate(
    base: dict[str, Estimate], head: dict[str, Estimate]
) -> dict[str, object]:
    rows: list[dict[str, object]] = []
    all_pass = True
    for shape in SHAPES:
        base_ehm = base[f"{MANAGER_GROUP}/{shape}/ehm"]
        head_ehm = head[f"{MANAGER_GROUP}/{shape}/ehm"]
        reduction = -pct_delta(base_ehm, head_ehm)
        ehm_pass = reduction >= 50.0 and head_ehm.upper < base_ehm.lower
        rows.append(
            {
                "gate": "manager_ehm",
                "shape": shape,
                "reduction_pct": reduction,
                "confidence_intervals_separated": head_ehm.upper < base_ehm.lower,
                "pass": ehm_pass,
            }
        )
        all_pass &= ehm_pass

        base_noop = base[f"{MANAGER_GROUP}/{shape}/noop"]
        head_noop = head[f"{MANAGER_GROUP}/{shape}/noop"]
        noop_delta = pct_delta(base_noop, head_noop)
        noop_pass = noop_delta < 3.0 and intervals_overlap(base_noop, head_noop)
        rows.append(
            {
                "gate": "manager_noop",
                "shape": shape,
                "delta_pct": noop_delta,
                "confidence_intervals_overlap": intervals_overlap(base_noop, head_noop),
                "pass": noop_pass,
            }
        )
        all_pass &= noop_pass

        base_full = base[f"{SQLITE_GROUP}/{shape}/full"]
        head_full = head[f"{SQLITE_GROUP}/{shape}/full"]
        sqlite_delta = pct_delta(base_full, head_full)
        sqlite_overlap = intervals_overlap(base_full, head_full)
        sqlite_pass = sqlite_delta < 5.0 and (sqlite_delta <= 0.0 or sqlite_overlap)
        rows.append(
            {
                "gate": "sqlite_end_to_end",
                "shape": shape,
                "delta_pct": sqlite_delta,
                "confidence_intervals_overlap": sqlite_overlap,
                "pass": sqlite_pass,
            }
        )
        all_pass &= sqlite_pass
    return {
        "phase": "candidate",
        "candidate_acceptance_pass": all_pass,
        "rows": rows,
    }


def write_csv(
    path: Path,
    base: dict[str, Estimate],
    head: dict[str, Estimate] | None,
) -> None:
    with path.open("w", encoding="utf-8", newline="") as output:
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(("variant", "benchmark", "mean_ns", "ci95_lower_ns", "ci95_upper_ns"))
        for variant, values in (("baseline", base), ("candidate", head)):
            if values is None:
                continue
            for full_id in sorted(values):
                value = values[full_id]
                writer.writerow((variant, full_id, value.point, value.lower, value.upper))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--criterion-dir", type=Path, required=True)
    parser.add_argument("--baseline-name", required=True)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--verdict", type=Path, required=True)
    args = parser.parse_args()

    base = inventory(args.criterion_dir, args.baseline_name)
    head = inventory(args.criterion_dir, "new") if args.phase == "candidate" else None
    verdict = gate_baseline(base) if head is None else gate_candidate(base, head)
    write_csv(args.results, base, head)
    args.verdict.write_text(
        json.dumps(verdict, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"phase={args.phase}")
    print(f"criterion_cases={len(base)}")
    print(f"verdict={args.verdict.name}")


if __name__ == "__main__":
    main()
