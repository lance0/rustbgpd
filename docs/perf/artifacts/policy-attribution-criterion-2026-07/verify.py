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

derived_verdicts = {}
for row, verdict in manifest["rows"].items():
    control = [observed[("control", row, attempt)] for attempt in range(1, 7)]
    isolated = [observed[("isolated", row, attempt)] for attempt in range(1, 7)]
    supported = (
        max(isolated) < min(control)
        and statistics.stdev(isolated) < statistics.stdev(control)
    )
    expected = "supported" if supported else "inconclusive"
    derived_verdicts[row] = expected
    if verdict != expected:
        fail(f"claim/verdict mismatch for {row}: expected {expected}, got {verdict}")

supported_count = sum(verdict == "supported" for verdict in derived_verdicts.values())
inconclusive_count = len(derived_verdicts) - supported_count
if (supported_count, inconclusive_count) != (0, 4):
    fail("measured public contract is not 0 supported / 4 inconclusive")

repo = ROOT.parents[3]
receipt = (repo / "docs/perf/policy-attribution-criterion-2026-07.md").read_text()
for row in ROWS:
    matching = [line for line in receipt.splitlines() if line.startswith(f"| `{row}` |")]
    if len(matching) != 1 or not matching[0].endswith("| inconclusive; no claim |"):
        fail(f"public receipt verdict drift for {row}")
receipt_conclusion = (
    "This controlled run therefore does not substantiate attribution of a measured\n"
    "CPU gain at these four shapes. It makes no claim about convergence, reload\n"
    "latency, throughput, or end-to-end daemon performance."
)
if receipt.count(receipt_conclusion) != 1:
    fail("public receipt conclusion drift")

receipts_row = (
    "| Policy-attribution Criterion control | Six-attempt same-SHA and isolated "
    "`Arc<str>` attribution measurements grade all four exact rows inconclusive: "
    f"{supported_count} supported, {inconclusive_count} inconclusive. This controlled "
    "negative evidence makes no CPU or end-to-end claim | "
    "[`perf/policy-attribution-criterion-2026-07.md`]"
    "(perf/policy-attribution-criterion-2026-07.md), "
    "[`artifacts`](perf/artifacts/policy-attribution-criterion-2026-07/README.md) |"
)
receipts = (repo / "docs/RECEIPTS.md").read_text()
if receipts.splitlines().count(receipts_row) != 1:
    fail("RECEIPTS policy-attribution row drift")

operational_row = (
    "| Policy-attribution Criterion control | Pinned same-SHA plus isolated "
    "six-attempt receipt | Four exact `policy_chain_eval` rows were graded against "
    f"fresh controls: {supported_count} supported, {inconclusive_count} inconclusive. "
    "This controlled negative evidence makes no CPU or end-to-end claim. See "
    "[`perf/policy-attribution-criterion-2026-07.md`]"
    "(perf/policy-attribution-criterion-2026-07.md) and its "
    "[checksummed artifacts]"
    "(perf/artifacts/policy-attribution-criterion-2026-07/README.md). |"
)
operational = (repo / "docs/OPERATIONAL_PROOF.md").read_text()
if operational.splitlines().count(operational_row) != 1:
    fail("OPERATIONAL_PROOF policy-attribution row drift")

print(
    "policy attribution receipt: OK "
    f"({supported_count} supported, {inconclusive_count} inconclusive)"
)
