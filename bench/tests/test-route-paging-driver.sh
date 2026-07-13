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
  'one-minute load below' \
  'exclusive host lock'; do
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
    "cell_launch=direct_prebuilt_executable",
    "matrix_complete=1",
):
    require(metadata_key)
PY

printf 'route-paging driver mechanics: PASS\n'
