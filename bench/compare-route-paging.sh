#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Compare RIB route paging at two pinned refs with one fresh process per cell.

Usage: bench/compare-route-paging.sh [options]

  --base REF          Baseline ref (required; must predate the optimization)
  --head REF          Optimized ref (required; must contain the optimization)
  --routes LIST       Comma-separated route counts (default: 100000,400000)
  --page-sizes LIST   Comma-separated page sizes (default: 100,1000)
  --repetitions N     Paired repetitions per cell (default: 2)
  --core N            CPU core for taskset (default: 5)
  --output-dir DIR    Retained logs/raw/combined CSV directory (must be empty)
  --no-taskset        Do not pin execution (mechanics only)
  -h, --help          Show this help

The invoking checkout's route_paging.rs and benchmark-support module are copied
byte-for-byte into both detached worktrees. The script refuses to run if those
measurement sources differ. REF values must resolve to distinct committed
trees in one ancestry chain. Production differences outside the two route-paging
implementation files are rejected; benchmark, test, and documentation overlays
remain auditable. Uncommitted production changes are intentionally never measured.
EOF
}

base_ref=
head_ref=
routes_csv=100000,400000
page_sizes_csv=100,1000
repetitions=2
core=5
output_dir=
use_taskset=1

while (($#)); do
  case "$1" in
    --base) base_ref=${2:?--base requires a ref}; shift 2 ;;
    --head) head_ref=${2:?--head requires a ref}; shift 2 ;;
    --routes) routes_csv=${2:?--routes requires a list}; shift 2 ;;
    --page-sizes) page_sizes_csv=${2:?--page-sizes requires a list}; shift 2 ;;
    --repetitions) repetitions=${2:?--repetitions requires a value}; shift 2 ;;
    --core) core=${2:?--core requires a value}; shift 2 ;;
    --output-dir) output_dir=${2:?--output-dir requires a path}; shift 2 ;;
    --no-taskset) use_taskset=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n $base_ref ]] || {
  printf '%s is required and must name the committed baseline\n' --base >&2
  exit 2
}
[[ -n $head_ref ]] || {
  printf '%s is required and must name the committed optimized tree\n' --head >&2
  exit 2
}

positive_integer() {
  [[ $1 =~ ^[1-9][0-9]*$ ]] || {
    printf '%s must be a positive integer, got %s\n' "$2" "$1" >&2
    exit 2
  }
}

positive_integer "$repetitions" --repetitions
((repetitions >= 2)) || {
  printf '%s must be at least 2 for counterbalanced pairs\n' --repetitions >&2
  exit 2
}
[[ $core =~ ^[0-9]+$ ]] || {
  printf '%s must be a non-negative integer, got %s\n' --core "$core" >&2
  exit 2
}
IFS=, read -r -a routes <<<"$routes_csv"
IFS=, read -r -a page_sizes <<<"$page_sizes_csv"
((${#routes[@]} > 0 && ${#page_sizes[@]} > 0)) || {
  printf 'route and page-size matrices must be nonempty\n' >&2
  exit 2
}
for value in "${routes[@]}"; do positive_integer "$value" --routes; done
for value in "${page_sizes[@]}"; do positive_integer "$value" --page-sizes; done

repo_root=$(git rev-parse --show-toplevel)
canonical_harness="$repo_root/crates/rib/benches/route_paging.rs"
canonical_bench_support="$repo_root/crates/rib/src/manager/bench_support.rs"
driver_path=$0
[[ $driver_path == */* ]] || driver_path=$(command -v -- "$driver_path")
canonical_driver=$(realpath "$driver_path")
base_commit=$(git rev-parse --verify "${base_ref}^{commit}") || {
  printf 'baseline ref does not resolve to a commit: %s\n' "$base_ref" >&2
  exit 2
}
head_commit=$(git rev-parse --verify "${head_ref}^{commit}") || {
  printf 'optimized ref does not resolve to a commit: %s\n' "$head_ref" >&2
  exit 2
}
[[ $base_commit != "$head_commit" ]] || {
  printf 'baseline and optimized refs resolve to the same commit: %s\n' "$base_commit" >&2
  exit 2
}
git merge-base --is-ancestor "$base_commit" "$head_commit" || {
  printf 'baseline must be an ancestor of optimized commit: %s !<= %s\n' \
    "$base_commit" "$head_commit" >&2
  exit 2
}

mapfile -t changed_files < <(
  git -C "$repo_root" diff --name-only "$base_commit..$head_commit"
)
for changed_file in "${changed_files[@]}"; do
  case "$changed_file" in
    crates/rib/src/manager/mod.rs|crates/rib/src/manager/update_groups.rs)
      ;;
    crates/rib/src/manager/tests/paged_query.rs|\
    crates/rib/src/manager/bench_support.rs|\
    crates/rib/benches/route_paging.rs|\
    crates/rib/Cargo.toml|\
    bench/README.md|bench/compare-route-paging.sh|\
    docs/perf/rib-route-paging-2026-07.md)
      ;;
    *)
      printf 'base..head contains an unexpected change: %s\n' "$changed_file" >&2
      exit 2
      ;;
  esac
done
baseline_call='^[[:space:]]*match self\.grouped_advertised_routes\(peer\) \{$'
optimized_call='^[[:space:]]*match self\.grouped_advertised_routes_iter\(peer\) \{$'
iterator_definition='^[[:space:]]*pub\(in crate::manager\) fn grouped_advertised_routes_iter\($'
borrowed_iterator_body='^[[:space:]]*Some\(group\.table\.iter\(\)\.filter\(move \|route\| \{$'
if ! git -C "$repo_root" grep -Eq "$baseline_call" "$base_commit" -- \
  crates/rib/src/manager/mod.rs \
  || git -C "$repo_root" grep -Eq "$optimized_call" "$base_commit" -- \
    crates/rib/src/manager/mod.rs \
  || git -C "$repo_root" grep -Eq "$iterator_definition" "$base_commit" -- \
    crates/rib/src/manager/update_groups.rs; then
  printf 'baseline does not contain only the materialized paging call: %s\n' \
    "$base_commit" >&2
  exit 2
fi
if ! git -C "$repo_root" grep -Eq "$optimized_call" "$head_commit" -- \
  crates/rib/src/manager/mod.rs \
  || git -C "$repo_root" grep -Eq "$baseline_call" "$head_commit" -- \
    crates/rib/src/manager/mod.rs \
  || ! git -C "$repo_root" grep -Eq "$iterator_definition" "$head_commit" -- \
    crates/rib/src/manager/update_groups.rs \
  || ! git -C "$repo_root" grep -Eq "$borrowed_iterator_body" "$head_commit" -- \
    crates/rib/src/manager/update_groups.rs; then
  printf 'optimized commit lacks the executable borrowed-iterator paging path: %s\n' \
    "$head_commit" >&2
  exit 2
fi
harness_source_sha256=$(sha256sum "$canonical_harness" | awk '{print $1}')
bench_support_source_sha256=$(sha256sum "$canonical_bench_support" | awk '{print $1}')
driver_source_sha256=$(sha256sum "$canonical_driver" | awk '{print $1}')
harness_sha256=$(
  printf '%s\n%s\n' "$harness_source_sha256" "$bench_support_source_sha256" \
    | sha256sum | awk '{print $1}'
)

if [[ -z $output_dir ]]; then
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  output_dir="$repo_root/target/route-paging-compare/$stamp"
fi
if [[ -e $output_dir ]]; then
  [[ -d $output_dir ]] || {
    printf 'output path exists and is not a directory: %s\n' "$output_dir" >&2
    exit 2
  }
  shopt -s nullglob dotglob
  output_entries=("$output_dir"/*)
  shopt -u nullglob dotglob
  ((${#output_entries[@]} == 0)) || {
    printf 'output directory must be empty: %s\n' "$output_dir" >&2
    exit 2
  }
else
  mkdir -p "$output_dir"
fi
output_dir=$(cd "$output_dir" && pwd)
raw_dir="$output_dir/raw"
mkdir "$raw_dir"
source_dir="$output_dir/measurement-sources"
mkdir "$source_dir"
cp "$canonical_harness" "$source_dir/route_paging.rs"
cp "$canonical_bench_support" "$source_dir/bench_support.rs"
cp "$canonical_driver" "$source_dir/compare-route-paging.sh"
cmp --silent "$canonical_harness" "$source_dir/route_paging.rs"
cmp --silent "$canonical_bench_support" "$source_dir/bench_support.rs"
cmp --silent "$canonical_driver" "$source_dir/compare-route-paging.sh"
mkdir "$source_dir/baseline-production" "$source_dir/optimized-production"
for production_source in \
  crates/rib/src/manager/mod.rs \
  crates/rib/src/manager/update_groups.rs; do
  source_name=${production_source##*/}
  git -C "$repo_root" show "$base_commit:$production_source" \
    >"$source_dir/baseline-production/$source_name"
  git -C "$repo_root" show "$head_commit:$production_source" \
    >"$source_dir/optimized-production/$source_name"
done
(
  cd "$source_dir"
  sha256sum \
    route_paging.rs \
    bench_support.rs \
    compare-route-paging.sh \
    baseline-production/mod.rs \
    baseline-production/update_groups.rs \
    optimized-production/mod.rs \
    optimized-production/update_groups.rs \
    >SHA256SUMS
  sha256sum --check SHA256SUMS >/dev/null
)
measurement_source_manifest_sha256=$(sha256sum "$source_dir/SHA256SUMS" | awk '{print $1}')

scratch=$(mktemp -d "${TMPDIR:-/tmp}/rustbgpd-route-paging.XXXXXX")
base_tree="$scratch/base"
head_tree="$scratch/head"
cleanup() {
  git -C "$repo_root" worktree remove --force "$base_tree" >/dev/null 2>&1 || true
  git -C "$repo_root" worktree remove --force "$head_tree" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT INT TERM

git -C "$repo_root" worktree add --detach "$base_tree" "$base_commit" >/dev/null
git -C "$repo_root" worktree add --detach "$head_tree" "$head_commit" >/dev/null
cp "$canonical_harness" "$base_tree/crates/rib/benches/route_paging.rs"
cp "$canonical_harness" "$head_tree/crates/rib/benches/route_paging.rs"
cp "$canonical_bench_support" "$base_tree/crates/rib/src/manager/bench_support.rs"
cp "$canonical_bench_support" "$head_tree/crates/rib/src/manager/bench_support.rs"
cmp --silent \
  "$base_tree/crates/rib/benches/route_paging.rs" \
  "$head_tree/crates/rib/benches/route_paging.rs" || {
  printf 'baseline and optimized harness sources differ\n' >&2
  exit 1
}
cmp --silent \
  "$base_tree/crates/rib/src/manager/bench_support.rs" \
  "$head_tree/crates/rib/src/manager/bench_support.rs" || {
  printf 'baseline and optimized benchmark-support sources differ\n' >&2
  exit 1
}

cat >"$output_dir/metadata.txt" <<EOF
base_ref=$base_ref
base_commit=$base_commit
head_ref=$head_ref
head_commit=$head_commit
harness_sha256=$harness_sha256
harness_source_sha256=$harness_source_sha256
bench_support_source_sha256=$bench_support_source_sha256
driver_source_sha256=$driver_source_sha256
measurement_source_manifest_sha256=$measurement_source_manifest_sha256
routes=$routes_csv
page_sizes=$page_sizes_csv
repetitions=$repetitions
core=$core
taskset=$use_taskset
uname=$(uname -srvmo)
rustc=$(rustc --version)
EOF

results="$output_dir/route-paging.csv"
printf '%s\n' \
  'variant,commit,harness_sha256,scope,routes,page_size,repetition,pair_order,run_position,pages,rows,ordered_key_checksum,complete_ns,page_p50_ns,page_p99_ns,page_max_ns,rows_per_second' \
  >"$results"
execution_log="$output_dir/execution.log"
: >"$execution_log"

run_cell() {
  local variant=$1 tree=$2 commit=$3 scope=$4 route_count=$5 page_size=$6
  local repetition=$7 pair_order=$8 run_position=$9
  local cell_output="$raw_dir/${variant}-${scope}-${route_count}-${page_size}-rep${repetition}-${pair_order}-${run_position}.csv"
  local -a command=(
    cargo bench -p rustbgpd-rib --features bench-internals
    --bench route_paging --
    --routes "$route_count"
    --page-size "$page_size"
    --scope "$scope"
    --repetition "$repetition"
    --output "$cell_output"
  )
  if ((use_taskset)); then
    command=(taskset -c "$core" "${command[@]}")
  fi
  printf 'run variant=%s scope=%s routes=%s page=%s repetition=%s order=%s position=%s\n' \
    "$variant" "$scope" "$route_count" "$page_size" "$repetition" \
    "$pair_order" "$run_position" >>"$execution_log"
  (
    cd "$tree"
    RUSTBGPD_ROUTE_PAGING_VARIANT=$variant \
    RUSTBGPD_ROUTE_PAGING_COMMIT=$commit \
    RUSTBGPD_ROUTE_PAGING_HARNESS_SHA256=$harness_sha256 \
    RUSTBGPD_ROUTE_PAGING_PAIR_ORDER=$pair_order \
    RUSTBGPD_ROUTE_PAGING_RUN_POSITION=$run_position \
      "${command[@]}"
  ) >>"$execution_log" 2>&1
  [[ $(wc -l <"$cell_output") -eq 2 ]] || {
    printf 'cell did not emit exactly one CSV row: %s\n' "$cell_output" >&2
    exit 1
  }
  tail -n 1 "$cell_output" >>"$results"
}

cell_index=0
for route_count in "${routes[@]}"; do
  for page_size in "${page_sizes[@]}"; do
    for scope in best grouped-advertised; do
      ((cell_index += 1))
      for ((repetition = 1; repetition <= repetitions; repetition++)); do
        if (((cell_index + repetition) % 2 == 0)); then
          pair_order=baseline-first
          run_cell baseline "$base_tree" "$base_commit" "$scope" "$route_count" \
            "$page_size" "$repetition" "$pair_order" first
          run_cell optimized "$head_tree" "$head_commit" "$scope" "$route_count" \
            "$page_size" "$repetition" "$pair_order" second
        else
          pair_order=optimized-first
          run_cell optimized "$head_tree" "$head_commit" "$scope" "$route_count" \
            "$page_size" "$repetition" "$pair_order" first
          run_cell baseline "$base_tree" "$base_commit" "$scope" "$route_count" \
            "$page_size" "$repetition" "$pair_order" second
        fi
      done
    done
  done
done

python3 - "$results" "$harness_sha256" <<'PY'
import csv
import sys
from collections import defaultdict

path, expected_harness = sys.argv[1:]
with open(path, newline="", encoding="utf-8") as handle:
    rows = list(csv.DictReader(handle))

pairs = defaultdict(dict)
fixtures = defaultdict(dict)
for row in rows:
    if row["harness_sha256"] != expected_harness:
        raise SystemExit("result harness hash differs from the canonical source")
    key = (row["scope"], row["routes"], row["page_size"], row["repetition"])
    if row["variant"] in pairs[key]:
        raise SystemExit(f"duplicate variant for cell {key}")
    pairs[key][row["variant"]] = row
    fixture_key = (row["variant"], row["routes"], row["page_size"], row["repetition"])
    fixtures[fixture_key][row["scope"]] = row

for key, variants in pairs.items():
    if set(variants) != {"baseline", "optimized"}:
        raise SystemExit(f"unpaired cell {key}")
    baseline = variants["baseline"]
    optimized = variants["optimized"]
    if baseline["pair_order"] != optimized["pair_order"]:
        raise SystemExit(f"pair-order mismatch for {key}")
    expected_positions = {
        "baseline-first": ("first", "second"),
        "optimized-first": ("second", "first"),
    }
    expected = expected_positions.get(baseline["pair_order"])
    if expected is None or (baseline["run_position"], optimized["run_position"]) != expected:
        raise SystemExit(f"invalid counterbalanced positions for {key}")
    for field in ("pages", "rows", "ordered_key_checksum"):
        if baseline[field] != optimized[field]:
            raise SystemExit(f"baseline/optimized {field} mismatch for {key}")

for key, scopes in fixtures.items():
    if set(scopes) != {"best", "grouped_advertised"}:
        raise SystemExit(f"missing fixture control for {key}")
    best = scopes["best"]
    grouped = scopes["grouped_advertised"]
    if int(best["rows"]) != int(best["routes"]):
        raise SystemExit(f"best fixture row mismatch for {key}")
    if int(grouped["rows"]) >= int(best["rows"]):
        raise SystemExit(f"grouped fixture is not distinct for {key}")
    if grouped["ordered_key_checksum"] == best["ordered_key_checksum"]:
        raise SystemExit(f"grouped fixture checksum is not distinct for {key}")

orders = defaultdict(set)
for key, variants in pairs.items():
    scope, routes, page_size, _repetition = key
    orders[(scope, routes, page_size)].add(variants["baseline"]["pair_order"])
for key, seen in orders.items():
    if seen != {"baseline-first", "optimized-first"}:
        raise SystemExit(f"cell did not counterbalance pair order: {key}")

print(f"validated {len(pairs)} paired cells with identical route/page checksums")
PY

printf 'route paging comparison written to %s\n' "$output_dir"
