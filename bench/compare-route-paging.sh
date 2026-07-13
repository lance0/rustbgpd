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
  -h, --help          Show this help

The invoking checkout's route_paging.rs and benchmark-support module are copied
byte-for-byte into both detached worktrees. The script refuses to run if those
measurement sources differ. REF values must resolve to the exact reviewed
baseline/candidate commits. The normalized production patch and all Cargo/build
inputs must match the pinned hashes; benchmark, test, and documentation overlays
remain auditable. Retained comparisons require a clean invoking checkout,
exclusive host lock, selected-core performance governor, one-minute load below
2.0, and no competing cargo/rustc/rrharness/route_paging process immediately
before every cell. Uncommitted production changes are intentionally never
measured.
EOF
}

readonly expected_base_commit=50399dac696507a827480be4a9dcfef49e1682b3
readonly expected_head_commit=d12cbaae37a9779ccc58617189253450b57c8fa4
readonly expected_production_diff_sha256=558cf2ebc9101ca722b3d733a4dc2f4a91859a08e16ab6c7258844e99930ec87

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
production_diff_sha256=$(
  LC_ALL=C git -C "$repo_root" -c diff.algorithm=myers --no-pager diff \
    --no-ext-diff --no-textconv --no-color --abbrev=8 \
    --src-prefix=a/ --dst-prefix=b/ --indent-heuristic \
    "$base_commit..$head_commit" -- \
    crates/rib/src/manager/mod.rs \
    crates/rib/src/manager/update_groups.rs \
    | sha256sum | awk '{print $1}'
)
[[ $production_diff_sha256 == "$expected_production_diff_sha256" ]] || {
  printf 'normalized production diff hash mismatch: expected %s, got %s\n' \
    "$expected_production_diff_sha256" "$production_diff_sha256" >&2
  exit 2
}
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
for production_source in \
  crates/rib/src/manager/mod.rs \
  crates/rib/src/manager/update_groups.rs; do
  source_name=${production_source##*/}
  git -C "$repo_root" show "$base_commit:$production_source" \
    >"$source_dir/baseline-production/$source_name"
  git -C "$repo_root" show "$head_commit:$production_source" \
    >"$source_dir/optimized-production/$source_name"
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
  'variant,commit,harness_sha256,scope,routes,page_size,repetition,pair_order,run_position,pages,rows,ordered_key_checksum,complete_ns,page_p50_ns,page_p99_ns,page_max_ns,rows_per_second' \
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

{
  printf 'run_utc_finish=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
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
