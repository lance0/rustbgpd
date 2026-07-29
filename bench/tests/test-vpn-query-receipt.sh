#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

timing_receipt="$tmp_dir/timing.json"
allocation_receipt="$tmp_dir/allocation.json"
bench_source="$repo_root/crates/api/benches/vpn_query.rs"

check_allocator_seam() {
  python3 - "$1" <<'PY'
import pathlib
import sys

lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
needle = "static ALLOCATOR: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;"
matches = [index for index, line in enumerate(lines) if line.strip() == needle]
assert len(matches) == 1
index = matches[0]
assert index > 0
assert lines[index - 1].strip() == "#[global_allocator]"
PY
}

check_allocator_seam "$bench_source"
python3 - "$bench_source" <<'PY'
import pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text()
for contract in (
    "compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)",
    "locked.store(false, Ordering::Release)",
):
    assert contract in source, contract
assert source.count("let _guard = self.guard();") == 6
PY
sed '/^#\[global_allocator\]$/d' "$bench_source" >"$tmp_dir/no-global-allocator.rs"
if check_allocator_seam "$tmp_dir/no-global-allocator.rs" >/dev/null 2>&1; then
  echo "bench source without global allocator unexpectedly passed" >&2
  exit 1
fi

cargo bench --manifest-path "$repo_root/Cargo.toml" -p rustbgpd-api \
  --bench vpn_query_timing --features bench-internals -- smoke U "$timing_receipt"
cargo bench --manifest-path "$repo_root/Cargo.toml" -p rustbgpd-api \
  --bench vpn_query_allocation --features bench-internals,vpn-query-allocation -- \
  smoke F "$allocation_receipt"

verify() {
  python3 - "$1" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["schema"] == 1
assert doc["allocator"] == "tikv-jemallocator"
assert doc["routes"] == 256
assert doc["peers"] == 16
query = doc["query"]
assert query["actor_rows"] == 256
assert query["actor_capacity"] >= 256
assert query["dispatch"] == 1
assert query["returned_rows"] == (256 if doc["case"] == "U" else 16)
assert query["checksum"] == (
    5102335214269610730 if doc["case"] == "U" else 7341237881033179096
)
assert query["actor_handler_ns"] > 0
assert query["service_method_ns"] >= query["actor_handler_ns"]
assert query["post_actor_ns"] == query["service_method_ns"] - query["actor_handler_ns"]
PY
}

verify "$timing_receipt"
verify "$allocation_receipt"
python3 - "$timing_receipt" "$allocation_receipt" <<'PY'
import json, sys
timing = json.load(open(sys.argv[1]))
allocation = json.load(open(sys.argv[2]))
assert timing["mode"] == "timing" and timing["case"] == "U"
assert timing["query"]["returned_rows"] == 256
assert timing["peak_live_requested_bytes"] is None
assert allocation["mode"] == "allocation" and allocation["case"] == "F"
assert allocation["query"]["returned_rows"] == 16
assert allocation["peak_live_requested_bytes"] > 0
PY

set +e
mapfile -t timing_bins < <(find "$repo_root/target/release/deps" -maxdepth 1 \
  -type f -perm -0100 -name 'vpn_query_timing-*')
[[ ${#timing_bins[@]} -eq 1 ]]
RUSTBGPD_VPN_QUERY_FORCE_CENSOR=1 "${timing_bins[0]}" \
  smoke U "$tmp_dir/censor.json" >/dev/null 2>&1
censor_status=$?
set -e
[[ $censor_status -eq 75 ]]
python3 - "$tmp_dir/censor.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert doc == {
    "schema": 1, "mode": "timing", "routes": 256, "case": "U",
    "outcome": "capacity_censored", "censor_phase": "forced_fixture",
}
PY

python3 - "$timing_receipt" "$tmp_dir/bad-rows.json" "$tmp_dir/bad-checksum.json" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
bad_rows = json.loads(json.dumps(doc))
bad_rows["query"]["returned_rows"] = 15
json.dump(bad_rows, open(sys.argv[2], "w", encoding="utf-8"))
bad_checksum = json.loads(json.dumps(doc))
bad_checksum["query"]["checksum"] += 1
json.dump(bad_checksum, open(sys.argv[3], "w", encoding="utf-8"))
PY

if verify "$tmp_dir/bad-rows.json" >/dev/null 2>&1; then
  echo "row-corrupted receipt unexpectedly passed" >&2
  exit 1
fi
if verify "$tmp_dir/bad-checksum.json" >/dev/null 2>&1; then
  echo "checksum-corrupted receipt unexpectedly passed" >&2
  exit 1
fi
