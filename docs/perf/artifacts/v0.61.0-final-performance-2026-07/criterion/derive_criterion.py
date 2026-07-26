#!/usr/bin/env python3
"""Derive this receipt's compact Criterion table from a saved-baseline tree."""

from __future__ import annotations

import csv
import json
import math
import sys
from collections import Counter
from pathlib import Path


BASELINE = "v0.61.0-final-99ee74ba"
EXPECTED_SUITES = {"rib_ops": 18, "codec": 28, "policy_eval": 25}
REQUIRED_ROWS = {
    "adj_rib_in_insert/10000",
    "rib_pipeline/1000",
    "update_build/1",
    "update_build/ipv6_mp_add_path",
    "update_parse_revised/1",
    "update_parse_revised/ipv6_mp_add_path",
    "policy_chain_eval/1",
    "policy_chain_eval_early_deny",
    "export_policy_eval/lazy_as_path_string",
}
HEADER = (
    "suite",
    "benchmark",
    "median_lower_ns",
    "median_ns",
    "median_upper_ns",
    "sample_count",
    "sampling_mode",
)


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def suite_for(benchmark: str) -> str:
    if benchmark.startswith(("nlri_", "update_", "attr_")) or benchmark == "validate_update":
        return "codec"
    if benchmark.startswith(
        (
            "policy_",
            "loop_eval/",
            "set_heavy/",
            "value_expr/",
            "fn_eval/",
            "dataset_parity/",
        )
    ):
        return "policy_eval"
    return "rib_ops"


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: derive_criterion.py SAVED_CRITERION_ROOT")
    root = Path(sys.argv[1])
    if not root.is_dir():
        fail("saved Criterion root is not a directory")

    rows: list[tuple[str, ...]] = []
    for estimates_path in sorted(root.glob(f"**/{BASELINE}/estimates.json")):
        benchmark = estimates_path.parent.parent.relative_to(root).as_posix()
        sample_path = estimates_path.with_name("sample.json")
        if not sample_path.is_file():
            fail(f"{benchmark}: missing sample.json")
        estimates = json.loads(estimates_path.read_text(encoding="utf-8"))
        sample = json.loads(sample_path.read_text(encoding="utf-8"))
        try:
            median = estimates["median"]
            lower = float(median["confidence_interval"]["lower_bound"])
            point = float(median["point_estimate"])
            upper = float(median["confidence_interval"]["upper_bound"])
            sample_count = len(sample["iters"])
            sampling_mode = sample["sampling_mode"]
        except (KeyError, TypeError, ValueError) as error:
            fail(f"{benchmark}: malformed saved estimate: {error}")
        if not all(math.isfinite(value) and value > 0 for value in (lower, point, upper)):
            fail(f"{benchmark}: invalid median estimate")
        if not lower <= point <= upper:
            fail(f"{benchmark}: invalid median confidence interval")
        if sample_count not in (10, 100) or sampling_mode != "Linear":
            fail(f"{benchmark}: unexpected sampling contract")
        rows.append(
            (
                suite_for(benchmark),
                benchmark,
                str(lower),
                str(point),
                str(upper),
                str(sample_count),
                sampling_mode,
            )
        )

    if len(rows) != 71:
        fail(f"expected 71 rows, got {len(rows)}")
    identities = {row[1] for row in rows}
    if len(identities) != 71:
        fail("benchmark identities are not unique")
    missing = REQUIRED_ROWS - identities
    if missing:
        fail(f"missing required rows: {sorted(missing)}")
    suites = Counter(row[0] for row in rows)
    if dict(suites) != EXPECTED_SUITES:
        fail(f"suite counts mismatch: {dict(suites)}")

    writer = csv.writer(sys.stdout, delimiter="\t", lineterminator="\n")
    writer.writerow(HEADER)
    writer.writerows(rows)


if __name__ == "__main__":
    try:
        main()
    except (OSError, json.JSONDecodeError) as error:
        fail(str(error))
