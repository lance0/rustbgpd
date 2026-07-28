#!/usr/bin/env python3
import csv
import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONTROL = "e49d1c87d64cd1e9ca5e8c9d4f2be021be8ecf14"
BASE = "9a7b64615fd0a81572fc75e938dd2084890fecbe"
ROWS = {
    "policy_chain_eval/1",
    "policy_chain_eval/8",
    "policy_chain_eval/32",
    "policy_chain_eval/early_deny",
}


def fail(message):
    print(f"policy attribution receipt error: {message}", file=sys.stderr)
    raise SystemExit(1)


manifest = json.loads((ROOT / "manifest.json").read_text())
if manifest.get("control_sha") != CONTROL:
    fail("wrong control source SHA")
if manifest.get("isolated_base_sha") != BASE:
    fail("wrong isolated parent SHA")
if manifest.get("isolated_head_sha") != CONTROL:
    fail("wrong isolated source SHA")
if manifest.get("attempts") != 6:
    fail("attempt count must be exactly six")
expected_order = [
    "base-first",
    "head-first",
    "base-first",
    "head-first",
    "base-first",
    "head-first",
]
if manifest.get("order") != expected_order:
    fail("attempt order is not alternating")
if set(manifest.get("rows", {})) != ROWS:
    fail("manifest must contain exactly the four graded rows")

metadata = {}
for line in (ROOT / "metadata.txt").read_text().splitlines():
    if "=" in line:
        key, value = line.split("=", 1)
        metadata[key] = value
if metadata.get("governor") != "performance":
    fail("governor metadata drift")
if metadata.get("use_taskset") != "1" or metadata.get("core") != "8":
    fail("taskset/core metadata drift")
if metadata.get("attempts") != "6":
    fail("metadata attempt count drift")
if metadata.get("host_lock") != "acquired":
    fail("host lock was not acquired")
try:
    preflight_load = float(metadata.get("preflight_load_1m", ""))
except ValueError:
    fail("preflight load is not numeric")
if preflight_load >= 2:
    fail("preflight load was not below 2")
if metadata.get("no_competing_workloads") != "true":
    fail("competing-workload preflight failed")
if metadata.get("control_base_sha") != CONTROL or metadata.get("control_head_sha") != CONTROL:
    fail("metadata control SHA drift")
if metadata.get("isolated_base_sha") != BASE or metadata.get("isolated_head_sha") != CONTROL:
    fail("metadata isolated SHA drift")

observed = {}
with (ROOT / "attempt-estimates.tsv").open(newline="") as handle:
    for row in csv.DictReader(handle, delimiter="\t"):
        key = (row["run"], row["row"], int(row["attempt"]))
        if key in observed:
            fail(f"duplicate estimate row: {key}")
        if row["run"] not in {"control", "isolated"} or row["row"] not in ROWS:
            fail(f"unexpected estimate row: {key}")
        attempt = key[2]
        if attempt not in range(1, 7):
            fail(f"attempt outside 1..6: {key}")
        if row["order"] != expected_order[attempt - 1]:
            fail(f"non-alternating estimate order: {key}")
        base = float(row["base_median_ns"])
        head = float(row["head_median_ns"])
        delta = float(row["delta_pct"])
        calculated = (head - base) / base * 100.0
        if abs(calculated - delta) > 1e-6:
            fail(f"corrupted estimate delta: {key}")
        observed[key] = delta

expected_keys = {
    (run, row, attempt)
    for run in ("control", "isolated")
    for row in ROWS
    for attempt in range(1, 7)
}
if set(observed) != expected_keys:
    fail("missing or extra attempt/row data")

for row, verdict in manifest["rows"].items():
    control = [observed[("control", row, attempt)] for attempt in range(1, 7)]
    isolated = [observed[("isolated", row, attempt)] for attempt in range(1, 7)]
    supported = (
        max(isolated) < min(control)
        and statistics.stdev(isolated) < statistics.stdev(control)
    )
    expected = "supported" if supported else "inconclusive"
    if verdict != expected:
        fail(f"claim/verdict mismatch for {row}: expected {expected}, got {verdict}")

print("policy attribution receipt: OK (0 supported, 4 inconclusive)")
