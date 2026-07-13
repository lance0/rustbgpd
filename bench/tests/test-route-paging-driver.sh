#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
driver="$repo_root/bench/compare-route-paging.sh"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/route-paging-driver-test.XXXXXX")
dirty_marker="$repo_root/.route-paging-driver-dirty-test.$$"
cleanup() {
  rm -f "$dirty_marker"
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

help_output=$(bash "$driver" --help)
for expected in \
  --allow-dirty-mechanics \
  --preflight-wait-seconds \
  --max-ingest-regression-pct \
  --max-churn-regression-pct \
  --max-complete-regression-pct \
  --max-page-p99-regression-pct \
  --min-grouped-400k-speedup \
  --max-resident-growth-pct \
  --max-resident-growth-bytes \
  'one-minute load below' \
  'exclusive host lock' \
  'valid positive traversal, ingest' \
  'read-side speedup/latency'; do
  grep -Fq -- "$expected" <<<"$help_output" \
    || fail "help omits $expected"
done

set +e
invalid_override_output=$(
  bash "$driver" \
    --base missing-baseline --head missing-candidate \
    --allow-dirty-mechanics 2>&1
)
invalid_override_status=$?
set -e
[[ $invalid_override_status -eq 2 ]] \
  || fail "dirty override without --no-taskset returned $invalid_override_status"
grep -Fq -- '--allow-dirty-mechanics requires --no-taskset' \
  <<<"$invalid_override_output" \
  || fail 'dirty override did not explain the mechanics-only requirement'

# Make the invoking checkout observably dirty and prove the default guard wins
# before ref resolution, lock acquisition, builds, or cells.
: >"$dirty_marker"
set +e
dirty_output=$(
  RUSTBGPD_HOST_LOCK="$tmp_dir/uncontended.lock" \
    bash "$driver" --base missing-baseline --head missing-candidate \
      --no-taskset 2>&1
)
dirty_status=$?
set -e
rm -f "$dirty_marker"
[[ $dirty_status -eq 1 ]] || fail "dirty checkout returned $dirty_status"
grep -Fq 'invoking checkout is dirty' <<<"$dirty_output" \
  || fail 'dirty checkout was not rejected by the invoking-source guard'

# Hold a private lock and prove contention returns EX_TEMPFAIL before the
# intentionally invalid refs can be resolved.
lock_path="$tmp_dir/held.lock"
exec {lock_fd}>"$lock_path"
flock -n "$lock_fd"
set +e
lock_output=$(
  RUSTBGPD_HOST_LOCK="$lock_path" \
    bash "$driver" --base missing-baseline --head missing-candidate \
      --no-taskset --allow-dirty-mechanics 2>&1
)
lock_status=$?
set -e
[[ $lock_status -eq 75 ]] || fail "held host lock returned $lock_status"
grep -Fq 'the driver did not build or run' <<<"$lock_output" \
  || fail 'lock contention did not report the no-build/no-run guarantee'
if grep -Fq 'does not resolve to a commit' <<<"$lock_output"; then
  fail 'driver resolved refs before acquiring the host lock'
fi

python3 - "$driver" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")

def require(fragment: str) -> int:
    offset = source.find(fragment)
    if offset < 0:
        raise SystemExit(f"FAIL: driver omits required fragment: {fragment}")
    return offset

lock = require('if ! flock -n "$host_lock_fd"; then')
prebuild = require('prebuild_variant baseline "$base_tree" "$base_target_dir"')
matrix = require('for route_count in "${routes[@]}"; do')
if not lock < prebuild < matrix:
    raise SystemExit("FAIL: host lock / prebuild / timed-matrix ordering regressed")

run_cell = source[source.index("run_cell() {"):matrix]
preflight = run_cell.find('preflight_cell "$cell_id"')
execute = run_cell.find('"${command[@]}"', preflight)
if not 0 <= preflight < execute:
    raise SystemExit("FAIL: per-cell preflight no longer immediately precedes execution")

for metadata_key in (
    "invoking_head=",
    "invoking_dirty=",
    "host_lock_source=",
    "host_lock_path_sha256=",
    "load_one_max=",
    "required_governor=",
    "driver_source_sha256=",
    "measurement_source_manifest_sha256=",
    "cell_preflight_tsv=",
    "gate_summary_csv=gate-summary.csv",
    "cell_launch=direct_prebuilt_executable",
    "write_side_memory_gates=passed",
    "read_write_memory_gates=passed",
    "matrix_complete=1",
):
    require(metadata_key)

expected_production_sources = {
    "crates/rib/src/adj_rib_in.rs",
    "crates/rib/src/adj_rib_out.rs",
    "crates/rib/src/lib.rs",
    "crates/rib/src/loc_rib.rs",
    "crates/rib/src/manager/distribution/mod.rs",
    "crates/rib/src/manager/graceful_restart.rs",
    "crates/rib/src/manager/mod.rs",
    "crates/rib/src/manager/route_refresh.rs",
    "crates/rib/src/manager/selection_deferral.rs",
    "crates/rib/src/manager/update_groups.rs",
    "crates/rib/src/prefix_map.rs",
    "crates/rib/src/update.rs",
}
array_start = source.index("readonly -a production_sources=(")
array_end = source.index("\n)", array_start)
production_sources = {
    line.strip()
    for line in source[array_start:array_end].splitlines()[1:]
    if line.strip()
}
if production_sources != expected_production_sources:
    raise SystemExit(
        f"FAIL: production source inventory differs: {production_sources}"
    )
require('"$source_dir/baseline-production/$production_source"')
require('"$source_dir/optimized-production/$production_source"')
if '${production_source##*/}' in source:
    raise SystemExit("FAIL: production receipt paths are flattened by basename")

for gate_fragment in (
    "rows_per_second,ingest_ns,churn_routes,churn_ns,resident_bytes",
    'integer_fields = (',
    'math.isfinite(rows_per_second)',
    'page timing order must satisfy p50 <= p99 <= max <= complete',
    'complete_speedup >= min_grouped_400k_speedup',
    'p99_change <= max_page_p99_pct',
    '("ingest_ns", max_ingest_pct)',
    '("churn_ns", max_churn_pct)',
    'rss_change_bytes <= max_resident_bytes',
):
    require(gate_fragment)
PY

# Exercise the driver's embedded result validator without building either ref.
# This keeps zero/invalid RSS, fixture parity, and explicit regression gates
# executable mechanics rather than source-vocabulary assertions only.
validator="$tmp_dir/validate-route-paging.py"
python3 - "$driver" "$validator" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
start = source.index("<<'PY'\n") + len("<<'PY'\n")
end = source.index("\nPY\n", start)
Path(sys.argv[2]).write_text(source[start:end] + "\n", encoding="utf-8")
PY

valid_csv="$tmp_dir/valid.csv"
python3 - "$valid_csv" <<'PY'
import csv
import sys

fields = [
    "variant", "commit", "harness_sha256", "scope", "routes", "page_size",
    "repetition", "pair_order", "run_position", "pages", "rows",
    "ordered_key_checksum", "complete_ns", "page_p50_ns", "page_p99_ns",
    "page_max_ns", "rows_per_second", "ingest_ns", "churn_routes",
    "churn_ns", "resident_bytes",
]
rows = []
for scope, count, checksum in (
    ("best", 100, "aaaaaaaaaaaaaaaa"),
    ("grouped_advertised", 93, "bbbbbbbbbbbbbbbb"),
):
    for repetition, order in ((1, "baseline-first"), (2, "optimized-first")):
        positions = {
            "baseline-first": {"baseline": "first", "optimized": "second"},
            "optimized-first": {"baseline": "second", "optimized": "first"},
        }[order]
        for variant in ("baseline", "optimized"):
            optimized = variant == "optimized"
            rows.append({
                "variant": variant,
                "commit": variant,
                "harness_sha256": "harness",
                "scope": scope,
                "routes": 100,
                "page_size": 10,
                "repetition": repetition,
                "pair_order": order,
                "run_position": positions[variant],
                "pages": 10,
                "rows": count,
                "ordered_key_checksum": checksum,
                "complete_ns": 100,
                "page_p50_ns": 10,
                "page_p99_ns": 20,
                "page_max_ns": 30,
                "rows_per_second": 1,
                "ingest_ns": 105 if optimized else 100,
                "churn_routes": 100,
                "churn_ns": 105 if optimized else 100,
                "resident_bytes": 1100 if optimized else 1000,
            })
with open(sys.argv[1], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY

python3 "$validator" \
  "$valid_csv" harness baseline optimized 3 0 10 10 10 25 134217728 \
  "$tmp_dir/valid-gates.csv" \
  >/dev/null || fail 'valid result matrix failed embedded validation'

assert_validator_fails() {
  local csv_path=$1 expected=$2
  set +e
  local output
  output=$(python3 "$validator" \
    "$csv_path" harness baseline optimized 3 0 10 10 10 25 134217728 \
    "$tmp_dir/failing-gates.csv" 2>&1)
  local status=$?
  set -e
  [[ $status -ne 0 ]] || fail "invalid matrix unexpectedly passed: $expected"
  grep -Fq -- "$expected" <<<"$output" \
    || fail "invalid matrix did not report $expected: $output"
}

python3 - "$valid_csv" "$tmp_dir/zero-rss.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))
    fields = handle.seek(0) or next(csv.reader(handle))
rows[0]["resident_bytes"] = "0"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/zero-rss.csv" 'resident_bytes must be positive'

python3 - "$valid_csv" "$tmp_dir/invalid-rss.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    fields = reader.fieldnames
    rows = list(reader)
rows[0]["resident_bytes"] = "invalid"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/invalid-rss.csv" 'invalid resident_bytes'

python3 - "$valid_csv" "$tmp_dir/churn-mismatch.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    fields = reader.fieldnames
    rows = list(reader)
next(row for row in rows if row["variant"] == "optimized")["churn_routes"] = "99"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/churn-mismatch.csv" 'churn_routes must equal 100'

python3 - "$valid_csv" "$tmp_dir/ingest-regression.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    fields = reader.fieldnames
    rows = list(reader)
for row in rows:
    if row["variant"] == "optimized":
        row["ingest_ns"] = "200"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/ingest-regression.csv" 'ingest_ns'

python3 - "$valid_csv" "$tmp_dir/zero-complete.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    fields = reader.fieldnames
    rows = list(reader)
rows[0]["complete_ns"] = "0"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/zero-complete.csv" 'complete_ns must be positive'

python3 - "$valid_csv" "$tmp_dir/nonfinite-throughput.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    fields = reader.fieldnames
    rows = list(reader)
rows[0]["rows_per_second"] = "nan"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/nonfinite-throughput.csv" \
  'rows_per_second must be finite and positive'

python3 - "$valid_csv" "$tmp_dir/timing-order.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    fields = reader.fieldnames
    rows = list(reader)
rows[0]["page_p50_ns"] = "21"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/timing-order.csv" 'p50 <= p99 <= max <= complete'

python3 - "$valid_csv" "$tmp_dir/page-count.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    fields = reader.fieldnames
    rows = list(reader)
rows[0]["pages"] = "9"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/page-count.csv" \
  'pages must equal ceil(rows/min(page_size,1000))'

python3 - "$valid_csv" "$tmp_dir/p99-regression.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    fields = reader.fieldnames
    rows = list(reader)
for row in rows:
    if row["variant"] == "optimized":
        row["page_p99_ns"] = "25"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/p99-regression.csv" 'page_p99_ns'

python3 - "$valid_csv" "$tmp_dir/complete-regression.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    fields = reader.fieldnames
    rows = list(reader)
for row in rows:
    if row["variant"] == "optimized":
        row["complete_ns"] = "200"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/complete-regression.csv" 'complete_ns'

python3 - "$valid_csv" "$tmp_dir/target-speedup.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    fields = reader.fieldnames
    rows = list(reader)
for row in rows:
    row["routes"] = "400000"
    row["churn_routes"] = "1000"
    row["complete_ns"] = "200" if row["variant"] == "optimized" else "1000"
    if row["scope"] == "best":
        row["rows"] = "400000"
        row["pages"] = "40000"
    else:
        row["rows"] = "375000"
        row["pages"] = "37500"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/target-speedup.csv" 'speedup 5.000x'

python3 - "$valid_csv" "$tmp_dir/commit-mismatch.csv" <<'PY'
import csv
import sys
with open(sys.argv[1], newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    fields = reader.fieldnames
    rows = list(reader)
rows[0]["commit"] = "wrong"
with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
    writer = csv.DictWriter(handle, fieldnames=fields)
    writer.writeheader()
    writer.writerows(rows)
PY
assert_validator_fails "$tmp_dir/commit-mismatch.csv" 'result commit mismatch'

printf 'route-paging driver mechanics: PASS\n'
