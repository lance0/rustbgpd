#!/usr/bin/env bash
set -euo pipefail

source_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
driver="${source_root}/bench/compare-criterion.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
repo="${tmp}/repo"
fake_bin="${tmp}/bin"
harness_path="crates/rib/benches/rib_ops.rs"
dash_harness_path="-crates/rib/benches/rib_ops.rs"
real_git="$(command -v git)"

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

assert_metadata() {
  local file="$1"
  local key="$2"
  local expected="$3"
  grep -Fxq "${key}=${expected}" "$file" \
    || fail "${file}: expected ${key}=${expected}"
}

expect_failure() {
  local expected="$1"
  local expected_rc="$2"
  shift 2
  local output
  local rc
  set +e
  output="$(cd "$repo" && "$driver" \
    --base "$base_sha" --head "$head_sha" --no-taskset --attempts 1 \
    --allow-dirty --out-dir "${tmp}/rejected-$RANDOM" "$@" 2>&1)"
  rc=$?
  set -e
  [[ $rc -eq $expected_rc ]] \
    || fail "expected rc ${expected_rc} for '${expected}', got ${rc}: ${output}"
  grep -Fq -- "$expected" <<<"$output" \
    || fail "missing rejection '${expected}' in: ${output}"
}

mkdir -p "$repo/$(dirname -- "$harness_path")" "$fake_bin"
git -C "$repo" init -q
git -C "$repo" config user.email test@example.invalid
git -C "$repo" config user.name "Harness Test"
printf '%s\n' 'duplicate-prefix fixture' >"${repo}/${harness_path}"
git -C "$repo" add -- "$harness_path"
git -C "$repo" commit -qm base
base_sha="$(git -C "$repo" rev-parse HEAD)"
base_blob="$(git -C "$repo" rev-parse "HEAD:${harness_path}")"
base_sha256="$(git -C "$repo" cat-file blob "$base_blob" | sha256sum | awk '{print $1}')"

printf '%s\n' 'unique-prefix fixture' >"${repo}/${harness_path}"
git -C "$repo" commit -qam head
head_sha="$(git -C "$repo" rev-parse HEAD)"
head_blob="$(git -C "$repo" rev-parse "HEAD:${harness_path}")"
head_sha256="$(git -C "$repo" cat-file blob "$head_blob" | sha256sum | awk '{print $1}')"

printf '%s\n' 'fixed comparison fixture' >"${repo}/${harness_path}"
mkdir -p "$repo/$(dirname -- "$dash_harness_path")"
printf '%s\n' 'fixed comparison fixture' >"${repo}/${dash_harness_path}"
git -C "$repo" add -- "$dash_harness_path"
git -C "$repo" commit -qam harness
harness_sha="$(git -C "$repo" rev-parse HEAD)"
harness_blob="$(git -C "$repo" rev-parse "HEAD:${harness_path}")"
harness_sha256="$(git -C "$repo" cat-file blob "$harness_blob" | sha256sum | awk '{print $1}')"
ln -s rib_ops.rs "${repo}/crates/rib/benches/link.rs"
git -C "$repo" add crates/rib/benches/link.rs
git -C "$repo" commit -qm symlink
symlink_sha="$(git -C "$repo" rev-parse HEAD)"
mkdir "${repo}/crates/rib/benches/tree.rs"
printf '%s\n' member >"${repo}/crates/rib/benches/tree.rs/member"
git -C "$repo" add crates/rib/benches/tree.rs
git -C "$repo" commit -qm tree
tree_sha="$(git -C "$repo" rev-parse HEAD)"

rm -rf "${repo}/crates/rib/benches/tree.rs"
rm "${repo}/${harness_path}"
printf '%s\n' 'outside sentinel' >"${tmp}/escaped.rs"
ln -s "${tmp}/escaped.rs" "${repo}/${harness_path}"
git -C "$repo" add -A crates/rib/benches
git -C "$repo" commit -qm side-symlink
side_symlink_sha="$(git -C "$repo" rev-parse HEAD)"

expected_harness="${tmp}/expected-rib-ops.rs"
git -C "$repo" cat-file blob "$harness_blob" >"$expected_harness"
rm "${repo}/${harness_path}"
printf '%s\n' 'dirty working-tree decoy' >"${repo}/${harness_path}"

cat >"${fake_bin}/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${1:-} == -V ]]; then
  echo 'cargo 1.95.0 (fixture)'
  exit 0
fi
[[ -n ${FAKE_HARNESS_PATH:-} && -n ${FAKE_CARGO_LOG:-} ]]
git hash-object -- "$FAKE_HARNESS_PATH" >>"$FAKE_CARGO_LOG"
baseline=''
while (( $# )); do
  if [[ $1 == --save-baseline ]]; then
    baseline="${2:?missing fake baseline}"
    shift 2
  else
    shift
  fi
done
[[ -n $baseline && -n ${CRITERION_HOME:-} ]]
result="${CRITERION_HOME}/adj_rib_in_insert/500000/${baseline}/estimates.json"
mkdir -p "$(dirname "$result")"
printf '%s\n' '{"median":{"point_estimate":1000,"confidence_interval":{"lower_bound":990,"upper_bound":1010}}}' >"$result"
EOF
chmod +x "${fake_bin}/cargo"
cat >"${fake_bin}/git" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ ${FAIL_GIT_STATUS:-0} == 1 && " $* " == *" status --porcelain=v1 "* ]]; then
  exit 1
fi
exec "$REAL_GIT" "$@"
EOF
chmod +x "${fake_bin}/git"
export REAL_GIT="$real_git"
export PATH="${fake_bin}:${PATH}"
export RUSTBGPD_HOST_LOCK="${tmp}/host.lock"
export FAKE_HARNESS_PATH="$harness_path"
export FAKE_CARGO_LOG="${tmp}/cargo-harness.log"
: >"$FAKE_CARGO_LOG"

out="${tmp}/different"
(cd "$repo" && "$driver" \
  --base "$base_sha" --head "$head_sha" --no-taskset --attempts 1 \
  --harness-ref "$harness_sha" --harness-path "$harness_path" \
  --allow-dirty --out-dir "$out" --keep-worktrees >/dev/null)
metadata="$(find "$out" -name metadata.txt -print -quit)"
[[ -n $metadata ]] || fail 'comparison did not write metadata'
python3 - "$metadata" <<'PY'
import sys

lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
expected = "run_id base_ref base_sha head_ref head_sha package bench filter features core attempts fail_on_regression regression_threshold_pct regression_max_stddev_pct verdict_min_attempts governor use_taskset base_target_dir head_target_dir criterion_dir".split()
assert [line.split("=", 1)[0] for line in lines[:len(expected)]] == expected
assert lines[len(expected)] == ""
PY
run_dir="$(dirname "$metadata")"
cmp "${run_dir}/base/${harness_path}" "$expected_harness"
cmp "${run_dir}/head/${harness_path}" "$expected_harness"
assert_metadata "$metadata" harness_sha "$harness_sha"
assert_metadata "$metadata" harness_enabled 1
assert_metadata "$metadata" harness_mode 100644
assert_metadata "$metadata" harness_path "$harness_path"
assert_metadata "$metadata" harness_blob "$harness_blob"
assert_metadata "$metadata" harness_sha256 "$harness_sha256"
assert_metadata "$metadata" base_original_harness_blob "$base_blob"
assert_metadata "$metadata" base_original_harness_sha256 "$base_sha256"
assert_metadata "$metadata" head_original_harness_blob "$head_blob"
assert_metadata "$metadata" head_original_harness_sha256 "$head_sha256"
assert_metadata "$metadata" base_installed_harness_blob "$harness_blob"
assert_metadata "$metadata" base_installed_harness_sha256 "$harness_sha256"
assert_metadata "$metadata" head_installed_harness_blob "$harness_blob"
assert_metadata "$metadata" head_installed_harness_sha256 "$harness_sha256"
assert_metadata "$metadata" base_harness_overlay overlaid
assert_metadata "$metadata" head_harness_overlay overlaid
mapfile -t measured_blobs <"$FAKE_CARGO_LOG"
[[ ${#measured_blobs[@]} -eq 2 ]] || fail 'expected two measured harness blobs'
[[ ${measured_blobs[0]} == "$harness_blob" && ${measured_blobs[1]} == "$harness_blob" ]] \
  || fail 'cargo did not measure the selected harness blob on both sides'

symlink_out="${tmp}/side-symlink"
(cd "$repo" && "$driver" \
  --base "$side_symlink_sha" --head "$harness_sha" --no-taskset --attempts 1 \
  --harness-ref "$harness_sha" --harness-path "$harness_path" \
  --allow-dirty --out-dir "$symlink_out" --keep-worktrees >/dev/null)
symlink_metadata="$(find "$symlink_out" -name metadata.txt -print -quit)"
cmp "$(dirname "$symlink_metadata")/base/${harness_path}" "$expected_harness"
grep -Fxq 'outside sentinel' "${tmp}/escaped.rs" \
  || fail 'fixed-harness install followed a side-worktree symlink'

same_out="${tmp}/same"
: >"$FAKE_CARGO_LOG"
FAKE_HARNESS_PATH="$dash_harness_path"
(cd "$repo" && "$driver" \
  --base "$harness_sha" --head "$harness_sha" --no-taskset --attempts 1 \
  --harness-ref "$harness_sha" --harness-path "$dash_harness_path" \
  --allow-dirty --out-dir "$same_out" --keep-worktrees >/dev/null)
same_metadata="$(find "$same_out" -name metadata.txt -print -quit)"
assert_metadata "$same_metadata" harness_path "$dash_harness_path"
assert_metadata "$same_metadata" base_harness_overlay clean
assert_metadata "$same_metadata" head_harness_overlay clean
mapfile -t measured_blobs <"$FAKE_CARGO_LOG"
[[ ${#measured_blobs[@]} -eq 2 && ${measured_blobs[0]} == "$harness_blob" \
  && ${measured_blobs[1]} == "$harness_blob" ]] || fail 'leading-dash harness was not measured'
FAKE_HARNESS_PATH="$harness_path"
[[ -z $(git -C "$(dirname "$same_metadata")/base" status --porcelain) ]]
[[ -z $(git -C "$(dirname "$same_metadata")/head" status --porcelain) ]]

plain_out="${tmp}/plain"
(cd "$repo" && "$driver" \
  --base "$base_sha" --head "$head_sha" --no-taskset --attempts 1 \
  --allow-dirty --package example --bench other --out-dir "$plain_out" >/dev/null)
plain_metadata="$(find "$plain_out" -name metadata.txt -print -quit)"
assert_metadata "$plain_metadata" harness_enabled 0
assert_metadata "$plain_metadata" harness_ref ''

expect_failure 'must be provided together' 2 --harness-ref "$harness_sha"
expect_failure 'must be provided together' 2 --harness-path "$harness_path"
expect_failure 'must be a safe repository-relative' 2 \
  --harness-ref "$harness_sha" --harness-path '/tmp/rib_ops.rs'
expect_failure 'must be a safe repository-relative' 2 \
  --harness-ref "$harness_sha" --harness-path '../benches/rib_ops.rs'
expect_failure 'must be a safe repository-relative' 2 \
  --harness-ref "$harness_sha" --harness-path 'crates/rib/src/rib_ops.rs'
expect_failure 'fixed harness is not a blob' 2 \
  --harness-ref "$harness_sha" --harness-path 'crates/rib/benches/missing.rs'
expect_failure 'fixed harness is not a blob' 2 \
  --harness-ref "$tree_sha" --harness-path 'crates/rib/benches/tree.rs'
expect_failure 'fixed harness must be a regular git file' 2 \
  --harness-ref "$symlink_sha" --harness-path 'crates/rib/benches/link.rs'

: >"$FAKE_CARGO_LOG"
export FAIL_GIT_STATUS=1
expect_failure 'cannot inspect base fixed-harness overlay' 1 \
  --harness-ref "$harness_sha" --harness-path "$harness_path"
unset FAIL_GIT_STATUS
[[ ! -s $FAKE_CARGO_LOG ]] || fail 'cargo ran after fixed-harness status failure'

cat >"${repo}/.git/hooks/post-checkout" <<'EOF'
#!/bin/sh
: >unexpected.txt
EOF
chmod +x "${repo}/.git/hooks/post-checkout"
expect_failure 'overlay dirtied unexpected paths' 1 \
  --harness-ref "$harness_sha" --harness-path "$harness_path"
rm "${repo}/.git/hooks/post-checkout"

grep -Fq "install_fixed_harness \"\$base_dir\" \"\$base_sha\" base" "$driver"
grep -Fq "install_fixed_harness \"\$head_dir\" \"\$head_sha\" head" "$driver"
ci="${source_root}/.github/workflows/ci.yml"
grep -Fq 'bash -n bench/compare-criterion.sh bench/tests/test-compare-criterion-harness.sh' "$ci"
grep -Fq 'shellcheck bench/compare-criterion.sh bench/tests/test-compare-criterion-harness.sh' "$ci"
grep -Fq 'bash bench/tests/test-compare-criterion-harness.sh' "$ci"
grep -Fq "&& \$harness_enabled == 0" "$driver"

echo 'fixed comparison harness tests passed'
