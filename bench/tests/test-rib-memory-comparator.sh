#!/usr/bin/env bash
set -euo pipefail

repo_root=$(git rev-parse --show-toplevel)
comparator="${repo_root}/bench/compare-rib-memory.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

fixture_repo="${tmp}/fixture-repo"
fake_bin="${tmp}/fake-bin"
fake_cargo_log="${tmp}/fake-cargo.log"
mkdir -p "$fixture_repo" "$fake_bin"

cat >"${fake_bin}/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s|%s\n' "$PWD" "$*" >>"${FAKE_CARGO_LOG:?}"
case "${1:-}" in
  -V|--version)
    echo "cargo 1.0.0 (fixture)"
    ;;
  test)
    cat fixture.jsonl
    ;;
  *)
    echo "unexpected fake cargo invocation: $*" >&2
    exit 97
    ;;
esac
EOF
chmod +x "${fake_bin}/cargo"

git -C "$fixture_repo" init -q
git -C "$fixture_repo" config user.email fixture@example.invalid
git -C "$fixture_repo" config user.name "RIB memory comparator fixture"

write_rows() {
  local pct_live=$1
  local abs_live=$2
  local include_abs=${3:-1}
  local zero_base_live=${4:-1}

  cat >"${fixture_repo}/fixture.jsonl" <<EOF
{"kind":"rib_memory","shape":"pct_only","prefixes":100000,"live_bytes":${pct_live},"peak_bytes":${pct_live},"bytes_per_prefix":1048,"adj_in_capacity":10,"loc_capacity":20,"adj_out_capacity":30,"adj_in_prefix_index_entries":40,"adj_out_prefix_index_entries":50}
EOF
  if [[ "$include_abs" -eq 1 ]]; then
    cat >>"${fixture_repo}/fixture.jsonl" <<EOF
{"kind":"rib_memory","shape":"abs_only","prefixes":100000,"live_bytes":${abs_live},"peak_bytes":${abs_live},"bytes_per_prefix":10737,"adj_in_capacity":11,"loc_capacity":21,"adj_out_capacity":31,"adj_in_prefix_index_entries":41,"adj_out_prefix_index_entries":51}
EOF
  fi
  cat >>"${fixture_repo}/fixture.jsonl" <<EOF
{"kind":"rib_memory","shape":"zero_base","prefixes":100000,"live_bytes":${zero_base_live},"peak_bytes":${zero_base_live},"bytes_per_prefix":0,"adj_in_capacity":0,"loc_capacity":0,"adj_out_capacity":0,"adj_in_prefix_index_entries":0,"adj_out_prefix_index_entries":0}
EOF
}

# Base: 100 MiB and 1 GiB. The review fixture grows the first row by exactly
# 5% but only 5 MiB, and the second by exactly 32 MiB but less than 5%.
write_rows 104857600 1073741824 1 0
git -C "$fixture_repo" add fixture.jsonl
git -C "$fixture_repo" commit -qm base
git -C "$fixture_repo" tag base

write_rows 105906176 1074790400
git -C "$fixture_repo" commit -qam clean
git -C "$fixture_repo" tag clean

write_rows 110100480 1107296256
git -C "$fixture_repo" commit -qam review
git -C "$fixture_repo" tag review

write_rows 104857600 0 0
git -C "$fixture_repo" commit -qam missing
git -C "$fixture_repo" tag missing

run_compare() {
  local name=$1
  local head=$2
  local expected_status=$3
  shift 3
  local out="${tmp}/${name}"
  local log="${tmp}/${name}.log"
  local status

  set +e
  (
    cd "$fixture_repo"
    PATH="${fake_bin}:$PATH" \
      FAKE_CARGO_LOG="$fake_cargo_log" \
      RUSTBGPD_HOST_LOCK="${tmp}/host.lock" \
      bash "$comparator" \
        --base base \
        --head "$head" \
        --profile quick \
        --out-dir "$out" \
        "$@"
  ) >"$log" 2>&1
  status=$?
  set -e

  if [[ "$status" -ne "$expected_status" ]]; then
    cat "$log" >&2
    echo "${name}: expected exit ${expected_status}, got ${status}" >&2
    exit 1
  fi

  find "$out" -mindepth 1 -maxdepth 1 -type d -print -quit
}

assert_metadata() {
  local metadata=$1
  shift
  local expected
  for expected in "$@"; do
    grep -Fxq "$expected" "$metadata" || {
      echo "missing metadata row '${expected}' in ${metadata}" >&2
      exit 1
    }
  done
}

advisory_dir=$(run_compare advisory review 0)
python3 - "$advisory_dir/results.csv" <<'PY'
import csv
import sys

with open(sys.argv[1], newline="") as fh:
    rows = {row["shape"]: row for row in csv.DictReader(fh)}

pct = rows["pct_only"]
absolute = rows["abs_only"]
zero_base = rows["zero_base"]
assert pct["review"] == "review"
assert float(pct["delta_pct"]) >= 5
assert float(pct["delta_mib"]) < 32
assert absolute["review"] == "review"
assert float(absolute["delta_pct"]) < 5
assert float(absolute["delta_mib"]) >= 32
assert zero_base["delta_pct"] == ""
assert zero_base["review"] == "ok"
PY
assert_metadata "$advisory_dir/metadata.txt" \
  "fail_on_regression=0" \
  "review_threshold_percent=5" \
  "review_threshold_bytes=33554432" \
  "review_rule=percentage_or_absolute" \
  "gate_result=advisory" \
  "review_count=2" \
  "missing_row_count=0"
grep -Fq -- "- Mode: \`advisory\`" "$advisory_dir/summary.md"
grep -Fq -- "- Gate result: \`advisory\`" "$advisory_dir/summary.md"
grep -Fq '+5% **or** +32 MiB' "$advisory_dir/summary.md"
grep -Fq '1 B (n/a)' "$advisory_dir/summary.md"

clean_dir=$(run_compare gated-clean clean 0 --fail-on-regression)
python3 - "$clean_dir/results.csv" <<'PY'
import csv
import sys

with open(sys.argv[1], newline="") as fh:
    assert all(row["review"] == "ok" for row in csv.DictReader(fh))
PY
assert_metadata "$clean_dir/metadata.txt" \
  "fail_on_regression=1" \
  "gate_result=pass" \
  "review_count=0" \
  "missing_row_count=0"
grep -Fq -- "- Mode: \`gated\`" "$clean_dir/summary.md"
grep -Fq -- "- Gate result: \`pass\`" "$clean_dir/summary.md"

review_dir=$(run_compare gated-review review 1 --fail-on-regression)
test -s "$review_dir/results.csv"
test -s "$review_dir/summary.md"
test -s "$review_dir/metadata.txt"
assert_metadata "$review_dir/metadata.txt" \
  "fail_on_regression=1" \
  "gate_result=fail" \
  "review_count=2" \
  "missing_row_count=0"
grep -Fq 'review rows: abs_only/100000, pct_only/100000' \
  "${tmp}/gated-review.log"

missing_advisory_dir=$(run_compare missing-advisory missing 0)
assert_metadata "$missing_advisory_dir/metadata.txt" \
  "fail_on_regression=0" \
  "gate_result=advisory" \
  "review_count=0" \
  "missing_row_count=1"
grep -Fq ',missing-row' "$missing_advisory_dir/results.csv"

missing_gated_dir=$(run_compare missing-gated missing 1 --fail-on-regression)
test -s "$missing_gated_dir/results.csv"
test -s "$missing_gated_dir/summary.md"
test -s "$missing_gated_dir/metadata.txt"
assert_metadata "$missing_gated_dir/metadata.txt" \
  "fail_on_regression=1" \
  "gate_result=fail" \
  "review_count=0" \
  "missing_row_count=1"
grep -Fq 'missing rows: abs_only/100000' "${tmp}/missing-gated.log"

# Every Cargo invocation was intercepted, and every worktree stayed beneath
# this test's temporary directory and was removed by the comparator trap.
awk -F'|' -v root="${tmp}/" 'index($1, root) != 1 { exit 1 }' "$fake_cargo_log"
if [[ $(git -C "$fixture_repo" worktree list --porcelain | grep -c '^worktree ') -ne 1 ]]; then
  git -C "$fixture_repo" worktree list >&2
  echo "temporary comparator worktree leaked" >&2
  exit 1
fi

echo "RIB memory comparator gate self-test passed"
