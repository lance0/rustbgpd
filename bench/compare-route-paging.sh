#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Compare RIB route paging at two pinned refs with one fresh process per cell.

Usage: bench/compare-route-paging.sh [options]

  --base REF          Baseline ref (required; must resolve to the pinned baseline)
  --head REF          Optimized ref (required; must resolve to the pinned candidate)
  --routes LIST       Comma-separated route counts (default: 100000,400000)
  --page-sizes LIST   Comma-separated page sizes (default: 100,1000)
  --repetitions N     Paired repetitions per cell (default: 2)
  --core N            CPU core for taskset (default: 5)
  --output-dir DIR    Retained logs/raw/combined CSV directory (must be empty)
  --no-taskset        Do not pin execution (mechanics only)
  --allow-dirty-mechanics
                      Allow a dirty invoking checkout only with --no-taskset;
                      the output is marked mechanics-only
  --preflight-wait-seconds N
                      Maximum idle-preflight polling time per cell (default: 30)
  --max-ingest-regression-pct PCT
                      Maximum median seed-ingest regression (default: 10)
  --max-churn-regression-pct PCT
                      Maximum median remove/reannounce regression (default: 10)
  --max-complete-regression-pct PCT
                      Maximum median complete-traversal regression outside the
                      400k grouped target shapes (default: 3)
  --max-page-p99-regression-pct PCT
                      Maximum median handler-boundary p99 regression (default: 0)
  --min-grouped-400k-speedup FACTOR
                      Minimum complete-traversal speedup for every requested
                      400k grouped-advertised shape (default: 10)
  --max-resident-growth-pct PCT
                      Maximum median resident-set growth (default: 25)
  --max-resident-growth-bytes N
                      Maximum median resident-set growth in bytes (default: 134217728)
  -h, --help          Show this help

The invoking checkout's route_paging.rs and benchmark-support module are copied
byte-for-byte into both detached worktrees. The script refuses to run if those
measurement sources differ. REF values must resolve to the exact reviewed
baseline/candidate commits. The normalized production patch, including every
ordered-index source, and all Cargo/build inputs must match the pinned hashes;
benchmark, test, and documentation overlays remain auditable. Retained
comparisons require a clean invoking checkout,
exclusive host lock, selected-core performance governor, one-minute load below
2.0, and no competing cargo/rustc/rrharness/route_paging process immediately
before every cell. Every row must report valid positive traversal, ingest,
churn, and resident measurements. Paired medians must satisfy the explicit
read-side speedup/latency, write-side, and memory gates. Uncommitted production
changes are intentionally never measured.
EOF
}

readonly expected_base_commit=63159c20617ac6ebdecb3c3dd76eef5b01d452dd
readonly expected_head_commit=fbb3789881eb1549354ebb5ecf6869b3ed49573d
readonly expected_production_diff_sha256=fb439f795d2b6869d1a34f3f1d7c30d70736d0a9b6104ab24f524d97df815432
readonly -a production_sources=(
  crates/rib/src/adj_rib_in.rs
  crates/rib/src/adj_rib_out.rs
  crates/rib/src/lib.rs
  crates/rib/src/loc_rib.rs
  crates/rib/src/manager/distribution/mod.rs
  crates/rib/src/manager/graceful_restart.rs
  crates/rib/src/manager/mod.rs
  crates/rib/src/manager/route_refresh.rs
  crates/rib/src/manager/selection_deferral.rs
  crates/rib/src/manager/update_groups.rs
  crates/rib/src/prefix_map.rs
  crates/rib/src/update.rs
)

base_ref=
head_ref=
routes_csv=100000,400000
page_sizes_csv=100,1000
repetitions=2
core=5
output_dir=
use_taskset=1
allow_dirty_mechanics=0
preflight_wait_seconds=30
max_ingest_regression_pct=10
max_churn_regression_pct=10
max_complete_regression_pct=3
max_page_p99_regression_pct=0
min_grouped_400k_speedup=10
max_resident_growth_pct=25
max_resident_growth_bytes=134217728
readonly load_one_max=2.0
readonly required_governor=performance

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
    --allow-dirty-mechanics) allow_dirty_mechanics=1; shift ;;
    --preflight-wait-seconds)
      preflight_wait_seconds=${2:?--preflight-wait-seconds requires a value}
      shift 2
      ;;
    --max-ingest-regression-pct)
      max_ingest_regression_pct=${2:?--max-ingest-regression-pct requires a value}
      shift 2
      ;;
    --max-churn-regression-pct)
      max_churn_regression_pct=${2:?--max-churn-regression-pct requires a value}
      shift 2
      ;;
    --max-complete-regression-pct)
      max_complete_regression_pct=${2:?--max-complete-regression-pct requires a value}
      shift 2
      ;;
    --max-page-p99-regression-pct)
      max_page_p99_regression_pct=${2:?--max-page-p99-regression-pct requires a value}
      shift 2
      ;;
    --min-grouped-400k-speedup)
      min_grouped_400k_speedup=${2:?--min-grouped-400k-speedup requires a value}
      shift 2
      ;;
    --max-resident-growth-pct)
      max_resident_growth_pct=${2:?--max-resident-growth-pct requires a value}
      shift 2
      ;;
    --max-resident-growth-bytes)
      max_resident_growth_bytes=${2:?--max-resident-growth-bytes requires a value}
      shift 2
      ;;
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
positive_integer "$preflight_wait_seconds" --preflight-wait-seconds
nonnegative_decimal() {
  [[ $1 =~ ^([0-9]+([.][0-9]*)?|[.][0-9]+)$ ]] || {
    printf '%s must be a non-negative decimal, got %s\n' "$2" "$1" >&2
    exit 2
  }
}
nonnegative_decimal "$max_ingest_regression_pct" --max-ingest-regression-pct
nonnegative_decimal "$max_churn_regression_pct" --max-churn-regression-pct
nonnegative_decimal "$max_complete_regression_pct" --max-complete-regression-pct
nonnegative_decimal "$max_page_p99_regression_pct" --max-page-p99-regression-pct
nonnegative_decimal "$min_grouped_400k_speedup" --min-grouped-400k-speedup
awk -v value="$min_grouped_400k_speedup" 'BEGIN { exit !(value + 0 > 0) }' || {
  printf '%s must be greater than zero, got %s\n' \
    --min-grouped-400k-speedup "$min_grouped_400k_speedup" >&2
  exit 2
}
nonnegative_decimal "$max_resident_growth_pct" --max-resident-growth-pct
positive_integer "$max_resident_growth_bytes" --max-resident-growth-bytes
if ((allow_dirty_mechanics && use_taskset)); then
  printf '%s requires %s; dirty output cannot be retained as evidence\n' \
    --allow-dirty-mechanics --no-taskset >&2
  exit 2
fi
IFS=, read -r -a routes <<<"$routes_csv"
IFS=, read -r -a page_sizes <<<"$page_sizes_csv"
((${#routes[@]} > 0 && ${#page_sizes[@]} > 0)) || {
  printf 'route and page-size matrices must be nonempty\n' >&2
  exit 2
}
for value in "${routes[@]}"; do positive_integer "$value" --routes; done
for value in "${page_sizes[@]}"; do positive_integer "$value" --page-sizes; done
if ((use_taskset)); then
  [[ ",${routes_csv}," == *,400000,* ]] || {
    printf 'retained evidence must include the 400000-route target shape\n' >&2
    exit 2
  }
  for target_page_size in 100 1000; do
    [[ ",${page_sizes_csv}," == *",${target_page_size},"* ]] || {
      printf 'retained evidence must include page size %s\n' "$target_page_size" >&2
      exit 2
    }
  done
fi

repo_root=$(git rev-parse --show-toplevel)
invoking_head=$(git -C "$repo_root" rev-parse --verify HEAD)
invoking_status=$(git -C "$repo_root" status --porcelain --untracked-files=normal)
if [[ -n $invoking_status ]]; then
  invoking_dirty=1
else
  invoking_dirty=0
fi
if ((invoking_dirty && !allow_dirty_mechanics)); then
  printf 'invoking checkout is dirty; commit/stash changes or use %s with %s\n' \
    --allow-dirty-mechanics --no-taskset >&2
  exit 1
fi
if ((use_taskset)); then
  evidence_class=retained
else
  evidence_class=mechanics-only
fi

for required_command in \
  awk cargo cmp find flock git ps python3 realpath rustc sha256sum sort tail tr wc xargs; do
  command -v "$required_command" >/dev/null 2>&1 || {
    printf 'required command not found: %s\n' "$required_command" >&2
    exit 1
  }
done
if ((use_taskset)); then
  command -v taskset >/dev/null 2>&1 || {
    printf 'taskset not found; install util-linux or use %s for mechanics only\n' \
      --no-taskset >&2
    exit 1
  }
  taskset -c "$core" true >/dev/null 2>&1 || {
    printf 'selected CPU cannot be used by taskset: %s\n' "$core" >&2
    exit 1
  }
fi

# Exclude cooperating soak and performance workloads before creating worktrees,
# compiling, or executing a benchmark. Exit 75 (EX_TEMPFAIL) lets unattended
# callers retry a busy host without treating contention as a benchmark failure.
if [[ -n ${RUSTBGPD_HOST_LOCK+x} ]]; then
  host_lock=$RUSTBGPD_HOST_LOCK
  host_lock_source=environment-override
else
  host_lock="${HOME}/.local/state/rustbgpd-host.lock"
  host_lock_source=default-user-state
fi
host_lock_sha256=$(printf '%s' "$host_lock" | sha256sum | awk '{print $1}')
mkdir -p "$(dirname "$host_lock")"
touch "$host_lock"
# shellcheck disable=SC1083 # bash dynamic file descriptor syntax is intentional.
exec {host_lock_fd}>"$host_lock"
if ! flock -n "$host_lock_fd"; then
  printf 'error: %s is held by another process (soak or bench)\n' "$host_lock" >&2
  printf '       wait for it to finish; the driver did not build or run\n' >&2
  exit 75
fi
printf 'acquired host lock: %s\n' "$host_lock"

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
[[ $base_commit == "$expected_base_commit" ]] || {
  printf 'baseline must resolve to the pinned commit: expected %s, got %s\n' \
    "$expected_base_commit" "$base_commit" >&2
  exit 2
}
[[ $head_commit == "$expected_head_commit" ]] || {
  printf 'optimized ref must resolve to the pinned commit: expected %s, got %s\n' \
    "$expected_head_commit" "$head_commit" >&2
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
is_production_source() {
  local candidate=$1 production_source
  for production_source in "${production_sources[@]}"; do
    [[ $candidate == "$production_source" ]] && return 0
  done
  return 1
}
for changed_file in "${changed_files[@]}"; do
  if is_production_source "$changed_file"; then
    continue
  fi
  case "$changed_file" in
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
production_diff_sha256=$(
  LC_ALL=C git -C "$repo_root" -c diff.algorithm=myers --no-pager diff \
    --no-ext-diff --no-textconv --no-color --abbrev=8 \
    --src-prefix=a/ --dst-prefix=b/ --indent-heuristic \
    "$base_commit..$head_commit" -- "${production_sources[@]}" \
    | sha256sum | awk '{print $1}'
)
[[ $production_diff_sha256 == "$expected_production_diff_sha256" ]] || {
  printf 'normalized production diff hash mismatch: expected %s, got %s\n' \
    "$expected_production_diff_sha256" "$production_diff_sha256" >&2
  exit 2
}
ordered_page_definition='^[[:space:]]*fn page_ordered_routes'
ordered_resume_definition='^[[:space:]]*pub fn iter_ordered_from\(&self,'
prefix_resume_definition='^[[:space:]]*pub\(crate\) fn iter_from\(&self,'
loc_index_field='^[[:space:]]*ordered_prefixes: FamilyPrefixMap<\(\)>,'
if git -C "$repo_root" grep -Eq "$ordered_page_definition" "$base_commit" -- \
  crates/rib/src/manager/mod.rs \
  || git -C "$repo_root" grep -Eq "$prefix_resume_definition" "$base_commit" -- \
    crates/rib/src/prefix_map.rs \
  || git -C "$repo_root" grep -Eq "$loc_index_field" "$base_commit" -- \
    crates/rib/src/loc_rib.rs; then
  printf 'baseline unexpectedly contains the ordered continuation path: %s\n' \
    "$base_commit" >&2
  exit 2
fi
if ! git -C "$repo_root" grep -Eq "$ordered_page_definition" "$head_commit" -- \
  crates/rib/src/manager/mod.rs \
  || ! git -C "$repo_root" grep -Eq "$ordered_resume_definition" "$head_commit" -- \
    crates/rib/src/adj_rib_in.rs crates/rib/src/adj_rib_out.rs crates/rib/src/loc_rib.rs \
  || ! git -C "$repo_root" grep -Eq "$prefix_resume_definition" "$head_commit" -- \
    crates/rib/src/prefix_map.rs \
  || ! git -C "$repo_root" grep -Eq "$loc_index_field" "$head_commit" -- \
    crates/rib/src/loc_rib.rs; then
  printf 'optimized commit lacks the executable ordered continuation path: %s\n' \
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
build_log_dir="$output_dir/build-logs"
mkdir "$build_log_dir"
source_dir="$output_dir/measurement-sources"
mkdir "$source_dir"
cp "$canonical_harness" "$source_dir/route_paging.rs"
cp "$canonical_bench_support" "$source_dir/bench_support.rs"
cp "$canonical_driver" "$source_dir/compare-route-paging.sh"
cmp --silent "$canonical_harness" "$source_dir/route_paging.rs"
cmp --silent "$canonical_bench_support" "$source_dir/bench_support.rs"
cmp --silent "$canonical_driver" "$source_dir/compare-route-paging.sh"
printf '%s' "$invoking_status" >"$source_dir/invoking-status.txt"
invoking_status_sha256=$(sha256sum "$source_dir/invoking-status.txt" | awk '{print $1}')
mkdir "$source_dir/baseline-production" "$source_dir/optimized-production"
for production_source in "${production_sources[@]}"; do
  mkdir -p \
    "$source_dir/baseline-production/$(dirname "$production_source")" \
    "$source_dir/optimized-production/$(dirname "$production_source")"
  git -C "$repo_root" show "$base_commit:$production_source" \
    >"$source_dir/baseline-production/$production_source"
  git -C "$repo_root" show "$head_commit:$production_source" \
    >"$source_dir/optimized-production/$production_source"
done
scratch=$(mktemp -d "${TMPDIR:-/tmp}/rustbgpd-route-paging.XXXXXX")
base_tree="$scratch/base"
head_tree="$scratch/head"
base_target_dir="$scratch/target-base"
head_target_dir="$scratch/target-head"
cleanup() {
  git -C "$repo_root" worktree remove --force "$base_tree" >/dev/null 2>&1 || true
  git -C "$repo_root" worktree remove --force "$head_tree" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT INT TERM

git -C "$repo_root" worktree add --detach "$base_tree" "$base_commit" >/dev/null
git -C "$repo_root" worktree add --detach "$head_tree" "$head_commit" >/dev/null
mkdir "$base_target_dir" "$head_target_dir"
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

# The canonical benchmark/support overlays are identical, but Cargo can still
# compile them differently if dependency resolution, profiles, build scripts,
# toolchain selection, or Cargo configuration differs. Require and retain one
# byte-identical copy of every tracked input in those categories.
compile_input_path() {
  case "$1" in
    Cargo.lock|*/Cargo.lock|Cargo.toml|*/Cargo.toml|\
    build.rs|*/build.rs|\
    .cargo/config|*/.cargo/config|.cargo/config.toml|*/.cargo/config.toml|\
    rust-toolchain|*/rust-toolchain|rust-toolchain.toml|*/rust-toolchain.toml)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}
mapfile -t base_compile_inputs < <(
  git -C "$base_tree" ls-files | while IFS= read -r path; do
    compile_input_path "$path" && printf '%s\n' "$path"
  done
)
mapfile -t head_compile_inputs < <(
  git -C "$head_tree" ls-files | while IFS= read -r path; do
    compile_input_path "$path" && printf '%s\n' "$path"
  done
)
[[ ${#base_compile_inputs[@]} -gt 0 ]] || {
  printf 'no Cargo/build inputs found in baseline worktree\n' >&2
  exit 1
}
[[ ${#base_compile_inputs[@]} -eq ${#head_compile_inputs[@]} ]] || {
  printf 'baseline and optimized Cargo/build input sets differ\n' >&2
  exit 1
}
compile_input_dir="$source_dir/compile-inputs"
mkdir "$compile_input_dir"
compile_input_manifest="$source_dir/compile-inputs.sha256"
: >"$compile_input_manifest"
for index in "${!base_compile_inputs[@]}"; do
  path=${base_compile_inputs[$index]}
  [[ $path == "${head_compile_inputs[$index]}" ]] || {
    printf 'baseline and optimized Cargo/build input sets differ: %s != %s\n' \
      "$path" "${head_compile_inputs[$index]}" >&2
    exit 1
  }
  cmp --silent "$base_tree/$path" "$head_tree/$path" || {
    printf 'baseline and optimized Cargo/build input differs: %s\n' "$path" >&2
    exit 1
  }
  destination="$compile_input_dir/$path"
  mkdir -p "$(dirname "$destination")"
  cp "$base_tree/$path" "$destination"
  printf '%s  %s\n' "$(sha256sum "$base_tree/$path" | awk '{print $1}')" "$path" \
    >>"$compile_input_manifest"
done
(
  cd "$compile_input_dir"
  sha256sum --check ../compile-inputs.sha256 >/dev/null
)
compile_input_manifest_sha256=$(sha256sum "$compile_input_manifest" | awk '{print $1}')
compile_input_count=${#base_compile_inputs[@]}

source_manifest_tmp="$scratch/measurement-source-SHA256SUMS"
(
  cd "$source_dir"
  find . -type f ! -path ./SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum >"$source_manifest_tmp"
  mv "$source_manifest_tmp" SHA256SUMS
  sha256sum --check SHA256SUMS >/dev/null
)
measurement_source_manifest_sha256=$(sha256sum "$source_dir/SHA256SUMS" | awk '{print $1}')

cat >"$output_dir/metadata.txt" <<EOF
run_utc_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)
evidence_class=$evidence_class
invoking_head=$invoking_head
invoking_dirty=$invoking_dirty
allow_dirty_mechanics=$allow_dirty_mechanics
invoking_status_sha256=$invoking_status_sha256
base_ref=$base_ref
base_commit=$base_commit
expected_base_commit=$expected_base_commit
head_ref=$head_ref
head_commit=$head_commit
expected_head_commit=$expected_head_commit
production_diff_sha256=$production_diff_sha256
expected_production_diff_sha256=$expected_production_diff_sha256
production_source_count=${#production_sources[@]}
harness_sha256=$harness_sha256
harness_source_sha256=$harness_source_sha256
bench_support_source_sha256=$bench_support_source_sha256
driver_source_sha256=$driver_source_sha256
measurement_source_manifest_sha256=$measurement_source_manifest_sha256
compile_input_manifest_sha256=$compile_input_manifest_sha256
compile_input_count=$compile_input_count
routes=$routes_csv
page_sizes=$page_sizes_csv
repetitions=$repetitions
max_ingest_regression_pct=$max_ingest_regression_pct
max_churn_regression_pct=$max_churn_regression_pct
max_complete_regression_pct=$max_complete_regression_pct
max_page_p99_regression_pct=$max_page_p99_regression_pct
min_grouped_400k_speedup=$min_grouped_400k_speedup
max_resident_growth_pct=$max_resident_growth_pct
max_resident_growth_bytes=$max_resident_growth_bytes
core=$core
taskset=$use_taskset
host_lock_source=$host_lock_source
host_lock_path_sha256=$host_lock_sha256
host_lock_acquired=1
load_one_max=$load_one_max
preflight_wait_seconds=$preflight_wait_seconds
preflight_poll_seconds=1
required_governor=$required_governor
governor_path=/sys/devices/system/cpu/cpu${core}/cpufreq/scaling_governor
load_source=/proc/loadavg
competing_process_names=cargo,rustc,rrharness,route_paging
build_mode=cargo_bench_no_run_locked_jobs_1_separate_target_dirs
build_log_baseline=build-logs/baseline.log
build_log_optimized=build-logs/optimized.log
cell_preflight_tsv=cell-preflight.tsv
gate_summary_csv=gate-summary.csv
uname=$(uname -srvmo)
rustc=$(rustc --version)
cargo=$(cargo --version)
EOF

prebuild_variant() {
  local variant=$1 tree=$2 target_dir=$3
  local build_log="$build_log_dir/${variant}.log"
  {
    printf 'utc_start=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'variant=%s\n' "$variant"
    printf 'tree_commit=%s\n' "$(git -C "$tree" rev-parse HEAD)"
    printf 'command=CARGO_TARGET_DIR=%s cargo bench -p rustbgpd-rib --features bench-internals --bench route_paging --locked --no-run --jobs 1\n' \
      "$target_dir"
  } >"$build_log"
  (
    cd "$tree"
    CARGO_TARGET_DIR="$target_dir" \
      cargo bench -p rustbgpd-rib --features bench-internals \
        --bench route_paging --locked --no-run --jobs 1
  ) >>"$build_log" 2>&1
  printf 'utc_finish=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$build_log"
}

# Compile both pinned trees before the first timed cell. Separate target
# directories prevent Cargo from reusing a same-named artifact across refs.
prebuild_variant baseline "$base_tree" "$base_target_dir"
prebuild_variant optimized "$head_tree" "$head_target_dir"

locate_benchmark_binary() {
  local target_dir=$1
  local -a candidates
  mapfile -t candidates < <(
    find "$target_dir/release/deps" -maxdepth 1 -type f -perm -u+x \
      -name 'route_paging-*' -print | sort
  )
  [[ ${#candidates[@]} -eq 1 ]] || {
    printf 'expected one prebuilt route_paging executable under %s, found %s\n' \
      "$target_dir/release/deps" "${#candidates[@]}" >&2
    return 1
  }
  printf '%s\n' "${candidates[0]}"
}

base_benchmark_binary=$(locate_benchmark_binary "$base_target_dir")
head_benchmark_binary=$(locate_benchmark_binary "$head_target_dir")
base_benchmark_binary_sha256=$(sha256sum "$base_benchmark_binary" | awk '{print $1}')
head_benchmark_binary_sha256=$(sha256sum "$head_benchmark_binary" | awk '{print $1}')
{
  printf 'baseline_benchmark_binary_sha256=%s\n' "$base_benchmark_binary_sha256"
  printf 'optimized_benchmark_binary_sha256=%s\n' "$head_benchmark_binary_sha256"
  printf 'cell_launch=direct_prebuilt_executable\n'
} >>"$output_dir/metadata.txt"

results="$output_dir/route-paging.csv"
printf '%s\n' \
  'variant,commit,harness_sha256,scope,routes,page_size,repetition,pair_order,run_position,pages,rows,ordered_key_checksum,complete_ns,page_p50_ns,page_p99_ns,page_max_ns,rows_per_second,ingest_ns,churn_routes,churn_ns,resident_bytes' \
  >"$results"
execution_log="$output_dir/execution.log"
: >"$execution_log"
preflight_log="$output_dir/cell-preflight.tsv"
printf 'cell_id\tattempt\tutc\tload_1m\tload_1m_max\tgovernor\trequired_governor\tcompeting_process_count\tcompeting_processes\tstatus\n' \
  >"$preflight_log"

read_selected_governor() {
  if ((!use_taskset)); then
    printf 'not-required-mechanics-only\n'
    return
  fi
  local governor_path="/sys/devices/system/cpu/cpu${core}/cpufreq/scaling_governor"
  if [[ ! -r $governor_path ]]; then
    printf 'unavailable\n'
    return
  fi
  tr -d '\n' <"$governor_path"
  printf '\n'
}

competing_process_snapshot() {
  # Linux comm names are sufficient for cargo/rustc and include the stable
  # prefix of hashed benchmark executable names. The current shell is `bash`,
  # so no special self exemption is needed beyond the defensive PID check.
  ps -eo pid=,comm=,args= --no-headers \
    | awk -v self="$$" '
        $1 != self &&
        ($2 == "cargo" || $2 == "rustc" ||
         $2 ~ /^rrharness($|-)/ || $2 ~ /^route_paging($|-)/) {
          print
        }
      '
}

preflight_cell() {
  local cell_id=$1 attempt=0
  local deadline=$((SECONDS + preflight_wait_seconds))
  local utc load_one governor process_lines process_count process_summary status timed_out
  while true; do
    ((attempt += 1))
    utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    load_one=$(awk '{print $1}' /proc/loadavg)
    governor=$(read_selected_governor)
    process_lines=$(competing_process_snapshot)
    if [[ -n $process_lines ]]; then
      process_count=$(wc -l <<<"$process_lines")
      process_summary=$(printf '%s' "$process_lines" | tr '\t\n' '  ' | tr -s ' ')
    else
      process_count=0
      process_summary=none
    fi

    status=pass
    if ! awk -v observed="$load_one" -v maximum="$load_one_max" \
      'BEGIN { exit !(observed + 0 < maximum + 0) }'; then
      status=wait-load
    elif ((use_taskset)) && [[ $governor != "$required_governor" ]]; then
      status=wait-governor
    elif ((process_count != 0)); then
      status=wait-processes
    fi

    timed_out=0
    if [[ $status != pass ]] && ((SECONDS >= deadline)); then
      status=${status/wait-/timeout-}
      timed_out=1
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$cell_id" "$attempt" "$utc" "$load_one" "$load_one_max" \
      "$governor" "$required_governor" "$process_count" "$process_summary" \
      "$status" >>"$preflight_log"
    if [[ $status == pass ]]; then
      return
    fi
    if ((timed_out)); then
      printf 'cell preflight timed out after %ss: %s (load=%s governor=%s processes=%s)\n' \
        "$preflight_wait_seconds" "$cell_id" "$load_one" "$governor" \
        "$process_summary" >&2
      return 75
    fi
    sleep 1
  done
}

run_cell() {
  local variant=$1 tree=$2 commit=$3 scope=$4 route_count=$5 page_size=$6
  local repetition=$7 pair_order=$8 run_position=$9
  local cell_output="$raw_dir/${variant}-${scope}-${route_count}-${page_size}-rep${repetition}-${pair_order}-${run_position}.csv"
  local cell_id="${variant}-${scope}-${route_count}-${page_size}-rep${repetition}-${pair_order}-${run_position}"
  local benchmark_binary
  case "$variant" in
    baseline) benchmark_binary=$base_benchmark_binary ;;
    optimized) benchmark_binary=$head_benchmark_binary ;;
    *) printf 'unknown benchmark variant: %s\n' "$variant" >&2; exit 2 ;;
  esac
  local -a command=(
    "$benchmark_binary"
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
  preflight_cell "$cell_id"
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

gate_summary="$output_dir/gate-summary.csv"
python3 - \
  "$results" \
  "$harness_sha256" \
  "$base_commit" \
  "$head_commit" \
  "$max_complete_regression_pct" \
  "$max_page_p99_regression_pct" \
  "$min_grouped_400k_speedup" \
  "$max_ingest_regression_pct" \
  "$max_churn_regression_pct" \
  "$max_resident_growth_pct" \
  "$max_resident_growth_bytes" \
  "$gate_summary" <<'PY'
import csv
import math
import sys
from collections import defaultdict
from statistics import median

(
    path,
    expected_harness,
    expected_base_commit,
    expected_head_commit,
    max_complete_pct,
    max_page_p99_pct,
    min_grouped_400k_speedup,
    max_ingest_pct,
    max_churn_pct,
    max_resident_pct,
    max_resident_bytes,
    gate_summary,
) = sys.argv[1:]
max_complete_pct = float(max_complete_pct)
max_page_p99_pct = float(max_page_p99_pct)
min_grouped_400k_speedup = float(min_grouped_400k_speedup)
max_ingest_pct = float(max_ingest_pct)
max_churn_pct = float(max_churn_pct)
max_resident_pct = float(max_resident_pct)
max_resident_bytes = int(max_resident_bytes)
required_fields = [
    "variant", "commit", "harness_sha256", "scope", "routes", "page_size",
    "repetition", "pair_order", "run_position", "pages", "rows",
    "ordered_key_checksum", "complete_ns", "page_p50_ns", "page_p99_ns",
    "page_max_ns", "rows_per_second", "ingest_ns", "churn_routes",
    "churn_ns", "resident_bytes",
]
with open(path, newline="", encoding="utf-8") as handle:
    reader = csv.DictReader(handle)
    if reader.fieldnames != required_fields:
        raise SystemExit(
            f"result columns differ: expected {required_fields}, got {reader.fieldnames}"
        )
    rows = list(reader)
if not rows:
    raise SystemExit("route-paging matrix emitted no rows")

pairs = defaultdict(dict)
fixtures = defaultdict(dict)
integer_fields = (
    "routes", "page_size", "repetition", "pages", "rows", "complete_ns",
    "page_p50_ns", "page_p99_ns", "page_max_ns", "ingest_ns",
    "churn_routes", "churn_ns", "resident_bytes",
)
expected_commits = {
    "baseline": expected_base_commit,
    "optimized": expected_head_commit,
}
for row in rows:
    variant = row["variant"]
    if variant not in expected_commits:
        raise SystemExit(f"invalid result variant: {variant!r}")
    if row["commit"] != expected_commits[variant]:
        raise SystemExit(
            f"{variant} result commit mismatch: expected {expected_commits[variant]}, "
            f"got {row['commit']}"
        )
    if row["harness_sha256"] != expected_harness:
        raise SystemExit("result harness hash differs from the canonical source")
    if row["scope"] not in {"best", "grouped_advertised"}:
        raise SystemExit(f"invalid result scope: {row['scope']!r}")
    for field in integer_fields:
        raw = row[field]
        if not raw or not raw.isascii() or not raw.isdigit():
            raise SystemExit(f"invalid {field} for result row: {raw!r}")
        value = int(raw)
        if value <= 0:
            raise SystemExit(f"{field} must be positive, got {value}")
        row[field] = value
    try:
        rows_per_second = float(row["rows_per_second"])
    except (TypeError, ValueError) as error:
        raise SystemExit(
            f"invalid rows_per_second for result row: {row['rows_per_second']!r}"
        ) from error
    if not math.isfinite(rows_per_second) or rows_per_second <= 0:
        raise SystemExit(
            f"rows_per_second must be finite and positive, got {row['rows_per_second']!r}"
        )
    row["rows_per_second"] = rows_per_second
    checksum = row["ordered_key_checksum"]
    if len(checksum) != 16 or any(char not in "0123456789abcdef" for char in checksum):
        raise SystemExit(f"invalid ordered_key_checksum: {checksum!r}")
    if not (
        row["page_p50_ns"] <= row["page_p99_ns"] <= row["page_max_ns"]
        <= row["complete_ns"]
    ):
        raise SystemExit("page timing order must satisfy p50 <= p99 <= max <= complete")
    page_cap = min(row["page_size"], 1_000)
    expected_pages = (row["rows"] + page_cap - 1) // page_cap
    if row["pages"] != expected_pages:
        raise SystemExit(
            f"pages must equal ceil(rows/min(page_size,1000)): expected "
            f"{expected_pages}, got {row['pages']}"
        )
    expected_churn_routes = min(row["routes"], 1_000)
    if row["churn_routes"] != expected_churn_routes:
        raise SystemExit(
            f"churn_routes must equal {expected_churn_routes}, got "
            f"{row['churn_routes']}"
        )
    key = (row["scope"], row["routes"], row["page_size"], row["repetition"])
    if variant in pairs[key]:
        raise SystemExit(f"duplicate variant for cell {key}")
    pairs[key][variant] = row
    fixture_key = (variant, row["routes"], row["page_size"], row["repetition"])
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
    for field in ("pages", "rows", "ordered_key_checksum", "churn_routes"):
        if baseline[field] != optimized[field]:
            raise SystemExit(f"baseline/optimized {field} mismatch for {key}")

for key, scopes in fixtures.items():
    if set(scopes) != {"best", "grouped_advertised"}:
        raise SystemExit(f"missing fixture control for {key}")
    best = scopes["best"]
    grouped = scopes["grouped_advertised"]
    if best["rows"] != best["routes"]:
        raise SystemExit(f"best fixture row mismatch for {key}")
    expected_grouped_rows = best["routes"] - ((best["routes"] + 15) // 16)
    if grouped["rows"] != expected_grouped_rows:
        raise SystemExit(
            f"grouped fixture row mismatch for {key}: expected "
            f"{expected_grouped_rows}, got {grouped['rows']}"
        )
    if grouped["ordered_key_checksum"] == best["ordered_key_checksum"]:
        raise SystemExit(f"grouped fixture checksum is not distinct for {key}")
    if grouped["churn_routes"] != best["churn_routes"]:
        raise SystemExit(f"scope churn fixture mismatch for {key}")

orders = defaultdict(set)
for key, variants in pairs.items():
    scope, routes, page_size, _repetition = key
    orders[(scope, routes, page_size)].add(variants["baseline"]["pair_order"])
for key, seen in orders.items():
    if seen != {"baseline-first", "optimized-first"}:
        raise SystemExit(f"cell did not counterbalance pair order: {key}")

def delta_pct(baseline, optimized):
    return ((optimized / baseline) - 1.0) * 100.0

gate_rows = []
gate_failures = []
shapes = defaultdict(lambda: {"baseline": [], "optimized": []})
for (scope, routes, page_size, _repetition), variants in pairs.items():
    shape = (scope, routes, page_size)
    for variant in ("baseline", "optimized"):
        shapes[shape][variant].append(variants[variant])

for shape, variants in sorted(shapes.items()):
    scope, routes, page_size = shape
    baseline_complete = median(row["complete_ns"] for row in variants["baseline"])
    optimized_complete = median(row["complete_ns"] for row in variants["optimized"])
    complete_change = delta_pct(baseline_complete, optimized_complete)
    complete_speedup = baseline_complete / optimized_complete
    target_shape = scope == "grouped_advertised" and routes == 400_000
    complete_verdict = (
        "pass"
        if (
            complete_speedup >= min_grouped_400k_speedup
            if target_shape
            else complete_change <= max_complete_pct
        )
        else "fail"
    )
    gate_rows.append([
        "complete_ns", scope, routes, page_size, baseline_complete,
        optimized_complete, complete_change, complete_speedup,
        min_grouped_400k_speedup if target_shape else "",
        "" if target_shape else max_complete_pct, "", complete_verdict,
    ])
    if complete_verdict == "fail":
        if target_shape:
            gate_failures.append(
                f"complete_ns {shape} speedup {complete_speedup:.3f}x "
                f"(minimum {min_grouped_400k_speedup:.3f}x)"
            )
        else:
            gate_failures.append(
                f"complete_ns {shape} regressed {complete_change:.3f}% "
                f"(limit {max_complete_pct:.3f}%)"
            )

    baseline_p99 = median(row["page_p99_ns"] for row in variants["baseline"])
    optimized_p99 = median(row["page_p99_ns"] for row in variants["optimized"])
    p99_change = delta_pct(baseline_p99, optimized_p99)
    p99_speedup = baseline_p99 / optimized_p99
    p99_verdict = "pass" if p99_change <= max_page_p99_pct else "fail"
    gate_rows.append([
        "page_p99_ns", scope, routes, page_size, baseline_p99, optimized_p99,
        p99_change, p99_speedup, "", max_page_p99_pct, "", p99_verdict,
    ])
    if p99_verdict == "fail":
        gate_failures.append(
            f"page_p99_ns {shape} regressed {p99_change:.3f}% "
            f"(limit {max_page_p99_pct:.3f}%)"
        )

    for metric, limit in (
        ("ingest_ns", max_ingest_pct),
        ("churn_ns", max_churn_pct),
    ):
        baseline_value = median(row[metric] for row in variants["baseline"])
        optimized_value = median(row[metric] for row in variants["optimized"])
        change = delta_pct(baseline_value, optimized_value)
        speedup = baseline_value / optimized_value
        verdict = "pass" if change <= limit else "fail"
        gate_rows.append(
            [metric, scope, routes, page_size, baseline_value, optimized_value,
             change, speedup, "", limit, "", verdict]
        )
        if verdict == "fail":
            gate_failures.append(
                f"{metric} {shape} regressed {change:.3f}% (limit {limit:.3f}%)"
            )

    baseline_rss = median(row["resident_bytes"] for row in variants["baseline"])
    optimized_rss = median(row["resident_bytes"] for row in variants["optimized"])
    rss_change_pct = delta_pct(baseline_rss, optimized_rss)
    rss_change_bytes = optimized_rss - baseline_rss
    verdict = (
        "pass"
        if rss_change_pct <= max_resident_pct and rss_change_bytes <= max_resident_bytes
        else "fail"
    )
    gate_rows.append(
        ["resident_bytes", scope, routes, page_size, baseline_rss, optimized_rss,
         rss_change_pct, "", "", max_resident_pct, max_resident_bytes, verdict]
    )
    if verdict == "fail":
        gate_failures.append(
            f"resident_bytes {shape} grew {rss_change_pct:.3f}% / "
            f"{rss_change_bytes} bytes (limits {max_resident_pct:.3f}% / "
            f"{max_resident_bytes} bytes)"
        )

with open(gate_summary, "w", newline="", encoding="utf-8") as handle:
    writer = csv.writer(handle)
    writer.writerow([
        "metric", "scope", "routes", "page_size", "baseline_median",
        "optimized_median", "delta_pct", "speedup", "min_speedup",
        "max_delta_pct", "max_delta_bytes", "verdict",
    ])
    writer.writerows(gate_rows)

if gate_failures:
    raise SystemExit("; ".join(gate_failures))

print(
    f"validated {len(pairs)} paired cells with identical route/page/churn "
    f"fixtures and {len(gate_rows)} passing read/write/memory gates"
)
PY

{
  printf 'run_utc_finish=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf 'write_side_memory_gates=passed\n'
  printf 'read_write_memory_gates=passed\n'
  printf 'matrix_complete=1\n'
} >>"$output_dir/metadata.txt"

artifact_manifest_tmp="$scratch/artifact-SHA256SUMS"
(
  cd "$output_dir"
  find . -type f ! -path ./SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum
) >"$artifact_manifest_tmp"
mv "$artifact_manifest_tmp" "$output_dir/SHA256SUMS"
(
  cd "$output_dir"
  sha256sum --check SHA256SUMS >/dev/null
)

printf 'route paging comparison written to %s\n' "$output_dir"
