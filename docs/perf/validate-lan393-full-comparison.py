#!/usr/bin/env python3
"""Combine LAN-393 enabled/disabled daemon receipts into the final gate."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
from pathlib import Path


RESULT_HEADER = [
    "name",
    "target",
    "version",
    "peers",
    "prefixes per peer",
    "required",
    "received",
    "monitor (s)",
    "elapsed (s)",
    "prefix received (s)",
    "testers (s)",
    "total time",
    "max cpu %",
    "max mem (GB)",
    "min idle%",
    "min free mem (GB)",
    "flags",
    "date",
    "cores",
    "Mem (GB)",
    "tester errors",
    "tester timeouts",
    "failed",
    "MSG",
    "filters",
]


def fail(message: str) -> None:
    raise SystemExit(message)


def read_json(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        fail(f"missing regular JSON receipt: {path.name}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        fail(f"cannot parse {path.name}: {error}")
    if not isinstance(value, dict):
        fail(f"JSON receipt is not an object: {path.name}")
    return value


def resource_row(path: Path) -> dict[str, float]:
    if path.is_symlink() or not path.is_file():
        fail(f"missing regular bgperf result: {path.name}")
    rows = list(csv.reader(path.read_text(encoding="utf-8").splitlines()))
    if len(rows) != 2 or rows[0] != RESULT_HEADER or len(rows[1]) != len(RESULT_HEADER):
        fail(f"invalid normalized bgperf matrix: {path.name}")
    values: dict[str, float] = {}
    for name, index in (("max_cpu_pct", 12), ("max_mem_gb", 13)):
        try:
            value = float(rows[1][index])
        except ValueError:
            fail(f"invalid {name} in {path.name}")
        if not math.isfinite(value) or value <= 0:
            fail(f"non-finite/non-positive {name} in {path.name}")
        values[name] = value
    return values


def completion(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        fail(f"missing profile completion: {path.name}")
    text = path.read_text(encoding="utf-8")
    if "phase_complete=1" not in text.splitlines():
        fail(f"profile is incomplete: {path.name}")


def verify_manifest(root: Path, name: str) -> None:
    manifest = root / name
    if manifest.is_symlink() or not manifest.is_file():
        fail(f"missing regular checksum manifest: {name}")
    seen: set[Path] = set()
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if len(line) < 67 or line[64:66] != "  ":
            fail(f"malformed checksum line in {name}")
        expected = line[:64]
        relative = Path(line[66:])
        if any(part == ".." for part in relative.parts) or relative.is_absolute():
            fail(f"unsafe checksum path in {name}: {relative}")
        path = root / relative
        if path in seen:
            fail(f"duplicate checksum path in {name}: {relative}")
        seen.add(path)
        if path.is_symlink() or not path.is_file():
            fail(f"checksum target is not regular in {name}: {relative}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != expected:
            fail(f"checksum mismatch in {name}: {relative}")
    if not seen:
        fail(f"empty checksum manifest: {name}")


def percent_delta(base: float, head: float) -> float:
    return ((head / base) - 1.0) * 100.0


def zero_producer_samples(receipt: dict[str, object], label: str) -> bool:
    value = receipt.get("ehm_producer_samples")
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        fail(f"invalid EHM producer sample count in {label}")
    return value == 0


def baseline(root: Path) -> dict[str, object]:
    verify_manifest(root, "microbench-baseline-SHA256SUMS")
    verify_manifest(root, "full-daemon-baseline-enabled-SHA256SUMS")
    manager = read_json(root / "microbench-baseline-verdict.json")
    enabled = read_json(root / "full-daemon-baseline-enabled-perf-attribution.json")
    disabled = read_json(root / "full-daemon-baseline-disabled-perf-attribution.json")
    for mode in ("enabled", "disabled"):
        completion(root / f"full-daemon-baseline-{mode}-completion.txt")
    manager_pass = manager.get("manager_proceed_pass") is True
    attribution_pass = enabled.get("baseline_proceed_pass") is True
    disabled_clean = zero_producer_samples(disabled, "baseline-disabled attribution")
    return {
        "phase": "baseline",
        "manager_proceed_pass": manager_pass,
        "full_daemon_attribution_pass": attribution_pass,
        "disabled_default_producer_clean": disabled_clean,
        "overall_proceed_pass": manager_pass and attribution_pass and disabled_clean,
        "enabled_resources": resource_row(
            root / "full-daemon-baseline-enabled-bgperf-result.csv"
        ),
        "disabled_resources": resource_row(
            root / "full-daemon-baseline-disabled-bgperf-result.csv"
        ),
    }


def candidate(root: Path) -> dict[str, object]:
    for manifest in (
        "microbench-baseline-SHA256SUMS",
        "microbench-candidate-SHA256SUMS",
        "full-daemon-baseline-enabled-SHA256SUMS",
        "full-daemon-baseline-disabled-SHA256SUMS",
        "full-daemon-candidate-enabled-SHA256SUMS",
    ):
        verify_manifest(root, manifest)
    microbench = read_json(root / "microbench-candidate-verdict.json")
    for phase in ("baseline", "candidate"):
        for mode in ("enabled", "disabled"):
            completion(root / f"full-daemon-{phase}-{mode}-completion.txt")
    base_disabled = resource_row(root / "full-daemon-baseline-disabled-bgperf-result.csv")
    head_disabled = resource_row(root / "full-daemon-candidate-disabled-bgperf-result.csv")
    cpu_delta = percent_delta(base_disabled["max_cpu_pct"], head_disabled["max_cpu_pct"])
    memory_delta = percent_delta(base_disabled["max_mem_gb"], head_disabled["max_mem_gb"])
    disabled_resource_pass = cpu_delta < 5.0 and memory_delta < 5.0
    disabled_attr = read_json(root / "full-daemon-candidate-disabled-perf-attribution.json")
    disabled_clean = zero_producer_samples(disabled_attr, "candidate-disabled attribution")
    criterion_pass = microbench.get("candidate_acceptance_pass") is True
    return {
        "phase": "candidate",
        "criterion_acceptance_pass": criterion_pass,
        "disabled_default_cpu_delta_pct": cpu_delta,
        "disabled_default_memory_delta_pct": memory_delta,
        "disabled_default_resource_pass": disabled_resource_pass,
        "disabled_default_producer_clean": disabled_clean,
        "candidate_acceptance_pass": criterion_pass
        and disabled_resource_pass
        and disabled_clean,
        "baseline_enabled_resources": resource_row(
            root / "full-daemon-baseline-enabled-bgperf-result.csv"
        ),
        "candidate_enabled_resources": resource_row(
            root / "full-daemon-candidate-enabled-bgperf-result.csv"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=("baseline", "candidate"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = baseline(args.artifact_dir) if args.phase == "baseline" else candidate(args.artifact_dir)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"phase={args.phase}")
    print(f"verdict={args.output.name}")


if __name__ == "__main__":
    main()
