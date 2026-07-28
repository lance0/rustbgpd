#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

receipt="$tmp_dir/receipt.json"
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
sed '/^#\[global_allocator\]$/d' "$bench_source" >"$tmp_dir/no-global-allocator.rs"
if check_allocator_seam "$tmp_dir/no-global-allocator.rs" >/dev/null 2>&1; then
  echo "bench source without global allocator unexpectedly passed" >&2
  exit 1
fi

cargo bench --manifest-path "$repo_root/Cargo.toml" -p rustbgpd-api \
  --bench vpn_query --features bench-internals -- smoke "$receipt"

verify() {
  python3 - "$1" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc["schema"] == 1
assert doc["allocator"] == "tikv-jemallocator"
assert doc["mode"] == "timing"
assert doc["routes"] == 256
assert doc["peers"] == 16
all_rows = doc["queries"]["all"]
peer_rows = doc["queries"]["peer_10_0_0_1"]
assert all_rows["actor_rows"] == 256
assert all_rows["actor_capacity"] >= 256
assert all_rows["returned_rows"] == 256
assert peer_rows["actor_rows"] == 256
assert peer_rows["returned_rows"] == 16
assert all_rows["dispatch"] == 1
assert peer_rows["dispatch"] == 2
assert all_rows["checksum"] == 5102335214269610730
assert peer_rows["checksum"] == 7341237881033179096
for query in (all_rows, peer_rows):
    assert query["actor_handler_ns"] > 0
    assert query["service_method_ns"] > 0
    assert query["post_actor_ns"] > 0
PY
}

verify "$receipt"

python3 - "$receipt" "$tmp_dir/bad-rows.json" "$tmp_dir/bad-checksum.json" <<'PY'
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
bad_rows = json.loads(json.dumps(doc))
bad_rows["queries"]["peer_10_0_0_1"]["returned_rows"] = 15
json.dump(bad_rows, open(sys.argv[2], "w", encoding="utf-8"))
bad_checksum = json.loads(json.dumps(doc))
bad_checksum["queries"]["all"]["checksum"] = 5102335214269610731
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
