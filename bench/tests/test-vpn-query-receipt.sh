#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

receipt="$tmp_dir/receipt.json"
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
assert all_rows["checksum"] != 0
assert peer_rows["checksum"] != 0
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
bad_checksum["queries"]["all"]["checksum"] = 0
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
