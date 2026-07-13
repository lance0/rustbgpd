#!/usr/bin/env bash
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

usage() {
  cat <<'EOF'
Run the pinned LAN-395 rrharness A/B matrix with fail-closed receipt gates.

Usage: bench/scale/compare-rrharness.sh [options]

  --base REF              Baseline ref (required; must resolve to pinned base)
  --head REF              Candidate ref (required; must resolve to pinned head)
  --core N                CPU pinned with taskset (default: 5)
  --output-dir DIR        New, empty receipt directory
  --preflight-wait N      Per-cell idle wait in seconds (default: 120)
  --timeout N             Per-cell outer timeout in seconds (default: 600)
  --validate-only         Verify pinned refs/tooling and exit before host access
  -h, --help              Show this help

The matrix is fixed: flood 256/1000 x 100k and churn 256x256/1000x1000 x
3000, each for 20 seconds, with two counterbalanced repetitions. The driver
requires a clean invoking checkout, exact reviewed refs and production diff,
the shared host lock, a performance-governor pinned CPU, load below 2.0, and
no competing build/performance process before every fresh-process cell.

The receipt is marked complete only if all 16 cells parse, every folded
profile reclassifies exactly, every LAN-395 throughput gate passes, privacy
checks pass, and the final checksum manifest verifies.
EOF
}

readonly expected_base_commit=b2ec55f21364978f26662b1ec35fd47ddcfce9a6
readonly expected_head_commit=ea579bea4ad6602dc719a1664441f04330c5ef64
readonly expected_production_diff_sha256=363ca576015ced26223b72b109acede0b88c1859db4cffb5c702d3d95ba236c4
readonly load_one_max=2.0
readonly required_governor=performance

base_ref=
head_ref=
core=5
output_dir=
preflight_wait_seconds=120
cell_timeout_seconds=600
validate_only=0

while (($#)); do
  case "$1" in
    --base) base_ref=${2:?--base requires a ref}; shift 2 ;;
    --head) head_ref=${2:?--head requires a ref}; shift 2 ;;
    --core) core=${2:?--core requires a value}; shift 2 ;;
    --output-dir) output_dir=${2:?--output-dir requires a path}; shift 2 ;;
    --preflight-wait)
      preflight_wait_seconds=${2:?--preflight-wait requires a value}
      shift 2
      ;;
    --timeout) cell_timeout_seconds=${2:?--timeout requires a value}; shift 2 ;;
    --validate-only) validate_only=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ -n $base_ref ]] || { printf '%s is required\n' --base >&2; exit 2; }
[[ -n $head_ref ]] || { printf '%s is required\n' --head >&2; exit 2; }
[[ $core =~ ^[0-9]+$ ]] || { printf '%s must be a nonnegative integer\n' --core >&2; exit 2; }
for value_name in preflight_wait_seconds cell_timeout_seconds; do
  value=${!value_name}
  [[ $value =~ ^[1-9][0-9]*$ ]] || {
    printf '%s must be a positive integer\n' "$value_name" >&2
    exit 2
  }
done

for command_name in \
  awk cargo cmp cp date diff dirname find flock git gzip mkdir mktemp ps python3 \
  hostname realpath rg rm rustc sed sha256sum sort tail tar taskset timeout \
  touch tr uname wc xargs; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'required command not found: %s\n' "$command_name" >&2
    exit 1
  }
done

repo_root=$(git rev-parse --show-toplevel)
invoking_head=$(git -C "$repo_root" rev-parse --verify HEAD)
[[ -z $(git -C "$repo_root" status --porcelain --untracked-files=normal) ]] || {
  printf 'invoking checkout must be clean; uncommitted inputs are not measurable\n' >&2
  exit 1
}

canonical_driver="$repo_root/bench/scale/compare-rrharness.sh"
canonical_criterion_driver="$repo_root/bench/compare-criterion.sh"
canonical_parser="$repo_root/bench/scale/rebaseline/parse_rrharness.py"
canonical_classifier="$repo_root/bench/scale/rebaseline/classify_cpu.py"
canonical_criterion_validator="$repo_root/bench/scale/rebaseline/validate_lan395_criterion.py"
pin_path="$repo_root/bench/scale/rebaseline/lan395-run-pin.env"
driver_path=$0
[[ $driver_path == */* ]] || driver_path=$(command -v -- "$driver_path")
actual_driver=$(realpath "$driver_path")
[[ $actual_driver == "$(realpath "$canonical_driver")" ]] || {
  printf 'driver must run from the canonical repository path: %s\n' "$canonical_driver" >&2
  exit 2
}
for source in \
  "$canonical_driver" "$canonical_criterion_driver" "$canonical_parser" \
  "$canonical_classifier" "$canonical_criterion_validator" "$pin_path"; do
  [[ -f $source && ! -L $source ]] || {
    printf 'pinned measurement source missing or not regular: %s\n' "$source" >&2
    exit 2
  }
done

mapfile -t invoking_parents < <(
  git -C "$repo_root" rev-list --parents -n 1 "$invoking_head"
)
read -r -a invoking_parent_fields <<<"${invoking_parents[0]}"
[[ ${#invoking_parent_fields[@]} -eq 2 ]] || {
  printf 'measurement pin commit must have exactly one parent\n' >&2
  exit 2
}
tooling_commit=${invoking_parent_fields[1]}
tooling_parent_line=$(git -C "$repo_root" rev-list --parents -n 1 "$tooling_commit")
read -r -a tooling_parent_fields <<<"$tooling_parent_line"
[[ ${#tooling_parent_fields[@]} -eq 2 ]] || {
  printf 'reviewed tooling commit must have exactly one parent\n' >&2
  exit 2
}
[[ ${tooling_parent_fields[1]} == "$expected_head_commit" ]] || {
  printf 'reviewed tooling must be a direct child of pinned production head\n' >&2
  exit 2
}
mapfile -t pin_changed_files < <(
  git -C "$repo_root" diff --name-only "$tooling_commit..$invoking_head"
)
[[ ${#pin_changed_files[@]} -eq 1 \
  && ${pin_changed_files[0]} == bench/scale/rebaseline/lan395-run-pin.env ]] || {
  printf 'invoking commit must add only the LAN-395 run pin over reviewed tooling\n' >&2
  exit 2
}
git -C "$repo_root" diff --quiet "$tooling_commit..$invoking_head" -- \
  bench/scale/compare-rrharness.sh \
  bench/compare-criterion.sh \
  bench/scale/rebaseline/parse_rrharness.py \
  bench/scale/rebaseline/classify_cpu.py \
  bench/scale/rebaseline/validate_lan395_criterion.py || {
  printf 'measurement tooling differs from the reviewed tooling parent\n' >&2
  exit 2
}

pin_value() {
  local key=$1
  awk -F= -v key="$key" '$1 == key { count += 1; value = substr($0, length(key) + 2) }
    END { if (count != 1 || value == "") exit 1; print value }' "$pin_path"
}
[[ $(wc -l <"$pin_path") -eq 5 ]] || {
  printf 'LAN-395 run pin must contain exactly five canonical rows\n' >&2
  exit 2
}
[[ $(pin_value schema) == rustbgpd.lan395-run-pin.v1 \
  && $(pin_value base_commit) == "$expected_base_commit" \
  && $(pin_value head_commit) == "$expected_head_commit" \
  && $(pin_value production_diff_sha256) == "$expected_production_diff_sha256" \
  && $(pin_value tooling_commit) == "$tooling_commit" ]] || {
  printf 'LAN-395 run pin does not bind the exact reviewed refs and tooling\n' >&2
  exit 2
}

base_commit=$(git -C "$repo_root" rev-parse --verify "${base_ref}^{commit}") || {
  printf 'baseline ref does not resolve: %s\n' "$base_ref" >&2
  exit 2
}
head_commit=$(git -C "$repo_root" rev-parse --verify "${head_ref}^{commit}") || {
  printf 'candidate ref does not resolve: %s\n' "$head_ref" >&2
  exit 2
}
[[ $base_commit == "$expected_base_commit" ]] || {
  printf 'baseline drift: expected %s, got %s\n' "$expected_base_commit" "$base_commit" >&2
  exit 2
}
[[ $head_commit == "$expected_head_commit" ]] || {
  printf 'candidate drift: expected %s, got %s\n' "$expected_head_commit" "$head_commit" >&2
  exit 2
}
git -C "$repo_root" merge-base --is-ancestor "$base_commit" "$head_commit" || {
  printf 'baseline is not an ancestor of candidate\n' >&2
  exit 2
}

mapfile -t changed_files < <(git -C "$repo_root" diff --name-only "$base_commit..$head_commit")
for changed_file in "${changed_files[@]}"; do
  case "$changed_file" in
    crates/rib/src/manager/distribution/mod.rs|\
    crates/rib/src/manager/tests/exportability.rs|\
    bench/scale/rebaseline/README.md|\
    bench/scale/rebaseline/classify_cpu.py|\
    bench/scale/rebaseline/fixtures/cpu.expected.tsv|\
    bench/scale/rebaseline/fixtures/cpu.folded)
      ;;
    *)
      printf 'base..head contains an unexpected change: %s\n' "$changed_file" >&2
      exit 2
      ;;
  esac
done
[[ ${#changed_files[@]} -eq 6 ]] || {
  printf 'base..head change set is incomplete: expected 6 paths, got %s\n' "${#changed_files[@]}" >&2
  exit 2
}

production_diff_sha256=$(
  LC_ALL=C git -C "$repo_root" -c diff.algorithm=myers --no-pager diff \
    --no-ext-diff --no-textconv --no-color --abbrev=8 \
    --src-prefix=a/ --dst-prefix=b/ --indent-heuristic \
    "$base_commit..$head_commit" -- crates/rib/src/manager/distribution/mod.rs \
    | sha256sum | awk '{print $1}'
)
[[ $production_diff_sha256 == "$expected_production_diff_sha256" ]] || {
  printf 'production diff drift: expected %s, got %s\n' \
    "$expected_production_diff_sha256" "$production_diff_sha256" >&2
  exit 2
}

git -C "$repo_root" diff --quiet "$base_commit..$head_commit" -- \
  bench/scale/rrharness || {
  printf 'rrharness source, manifest, or lock differs between base and candidate\n' >&2
  exit 2
}

if ((validate_only)); then
  printf 'validated LAN-395 refs and tooling: pin=%s tooling=%s base=%s head=%s\n' \
    "$invoking_head" "$tooling_commit" "$base_commit" "$head_commit"
  exit 0
fi
git -C "$repo_root" diff --quiet "$base_commit..$head_commit" -- \
  Cargo.toml Cargo.lock .cargo rust-toolchain rust-toolchain.toml \
  ':(glob)**/Cargo.toml' ':(glob)**/Cargo.lock' ':(glob)**/build.rs' \
  ':(glob)**/.cargo/config' ':(glob)**/.cargo/config.toml' || {
  printf 'Cargo, toolchain, build-script, or configuration input drifted\n' >&2
  exit 2
}

taskset -c "$core" true >/dev/null 2>&1 || {
  printf 'selected CPU cannot be used by taskset: %s\n' "$core" >&2
  exit 1
}
governor_path="/sys/devices/system/cpu/cpu${core}/cpufreq/scaling_governor"
[[ -r $governor_path ]] || {
  printf 'selected CPU governor is unavailable: %s\n' "$governor_path" >&2
  exit 1
}
[[ $(tr -d '\n' <"$governor_path") == "$required_governor" ]] || {
  printf 'cpu%s must use the %s governor\n' "$core" "$required_governor" >&2
  exit 75
}

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
# shellcheck disable=SC1083 # Bash dynamic file descriptor syntax is intentional.
exec {host_lock_fd}>"$host_lock"
if ! flock -n "$host_lock_fd"; then
  printf 'shared performance host is busy; no build or cell was started\n' >&2
  exit 75
fi

if [[ -z $output_dir ]]; then
  output_dir="$repo_root/target/rrharness-compare/$(date -u +%Y%m%dT%H%M%SZ)"
fi
if [[ -e $output_dir ]]; then
  [[ -d $output_dir ]] || { printf 'output path is not a directory\n' >&2; exit 2; }
  [[ -z $(find "$output_dir" -mindepth 1 -maxdepth 1 -print -quit) ]] || {
    printf 'output directory must be empty: %s\n' "$output_dir" >&2
    exit 2
  }
else
  mkdir -p "$output_dir"
fi
output_dir=$(realpath "$output_dir")
raw_dir="$output_dir/raw"
build_log_dir="$output_dir/build-logs"
source_dir="$output_dir/measurement-sources"
rows_dir="$output_dir/rows"
mkdir "$raw_dir" "$build_log_dir" "$source_dir" "$rows_dir"

cp "$canonical_driver" "$source_dir/compare-rrharness.sh"
cp "$canonical_criterion_driver" "$source_dir/compare-criterion.sh"
cp "$canonical_parser" "$source_dir/parse_rrharness.py"
cp "$canonical_classifier" "$source_dir/classify_cpu.py"
cp "$canonical_criterion_validator" "$source_dir/validate_lan395_criterion.py"
cp "$pin_path" "$source_dir/lan395-run-pin.env"
LC_ALL=C git -C "$repo_root" -c diff.algorithm=myers --no-pager diff \
  --no-ext-diff --no-textconv --no-color --abbrev=8 \
  --src-prefix=a/ --dst-prefix=b/ --indent-heuristic \
  "$base_commit..$head_commit" -- crates/rib/src/manager/distribution/mod.rs \
  >"$source_dir/production.patch"
printf '%s  %s\n' "$production_diff_sha256" production.patch \
  >"$source_dir/production-diff.sha256"
(
  cd "$source_dir"
  sha256sum --check production-diff.sha256 >/dev/null
)

default_tmp='/'"tmp"
scratch_root=${TMPDIR:-$default_tmp}
scratch=$(mktemp -d "$scratch_root/rustbgpd-rrharness.XXXXXX")
base_tree="$scratch/base"
head_tree="$scratch/head"
base_target="$scratch/target-base"
head_target="$scratch/target-head"
cleanup() {
  git -C "$repo_root" worktree remove --force "$base_tree" >/dev/null 2>&1 || true
  git -C "$repo_root" worktree remove --force "$head_tree" >/dev/null 2>&1 || true
  rm -rf "$scratch"
}
trap cleanup EXIT INT TERM

git -C "$repo_root" worktree add --detach "$base_tree" "$base_commit" >/dev/null
git -C "$repo_root" worktree add --detach "$head_tree" "$head_commit" >/dev/null
mkdir "$base_target" "$head_target"

compile_input_manifest="$source_dir/compile-inputs.sha256"
: >"$compile_input_manifest"
for tracked_path in \
  Cargo.toml Cargo.lock \
  bench/scale/rrharness/Cargo.toml bench/scale/rrharness/Cargo.lock \
  bench/scale/rrharness/src/main.rs; do
  cmp --silent "$base_tree/$tracked_path" "$head_tree/$tracked_path" || {
    printf 'base/candidate compile input mismatch: %s\n' "$tracked_path" >&2
    exit 2
  }
  printf '%s  %s\n' "$(sha256sum "$base_tree/$tracked_path" | awk '{print $1}')" \
    "$tracked_path" >>"$compile_input_manifest"
done

run_utc_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)

build_variant() {
  local variant=$1 tree=$2 target=$3
  local log="$build_log_dir/${variant}.log"
  {
    printf 'utc_start=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf 'variant=%s\n' "$variant"
    printf 'commit=%s\n' "$(git -C "$tree" rev-parse HEAD)"
    printf 'command=cargo build --release --locked --jobs 1 --manifest-path bench/scale/rrharness/Cargo.toml\n'
  } >"$log"
  (
    cd "$tree"
    CARGO_TARGET_DIR="$target" cargo build --release --locked --jobs 1 \
      --manifest-path bench/scale/rrharness/Cargo.toml
  ) >>"$log" 2>&1
  printf 'utc_finish=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$log"
}

build_variant base "$base_tree" "$base_target"
build_variant head "$head_tree" "$head_target"
base_binary="$base_target/release/rrharness"
head_binary="$head_target/release/rrharness"
[[ -x $base_binary && -x $head_binary ]] || {
  printf 'expected one direct rrharness executable per target directory\n' >&2
  exit 1
}
base_binary_sha256=$(sha256sum "$base_binary" | awk '{print $1}')
head_binary_sha256=$(sha256sum "$head_binary" | awk '{print $1}')

# Cargo may print absolute package paths. Retain the logs only after replacing
# every private or ephemeral prefix with a stable logical marker.
for log in "$build_log_dir"/*.log; do
  sed -i \
    -e "s#${base_tree}#<base-tree>#g" \
    -e "s#${head_tree}#<head-tree>#g" \
    -e "s#${scratch}#<scratch>#g" \
    -e "s#${repo_root}#<invoking-tree>#g" \
    -e "s#${HOME}#<home>#g" \
    "$log"
done

results="$output_dir/results.csv"
comparison="$output_dir/comparison.csv"
preflight="$output_dir/preflight.tsv"
execution="$output_dir/execution.tsv"
printf '%s\n' \
  'variant,commit,mode,clients,candidates,prefixes,seconds,repetition,pair_order,run_position,rate_name,rate,rss_established_mib,rss_converged_mib,rss_end_mib,setup_s,window_s,work_units,mgr_cpu_s,mgr_busy_frac,folded_sha256,classified_sha256,total_samples' \
  >"$results"
printf 'cell\tattempt\tutc\tload_1m\tload_max\tgovernor\tcompeting_count\tcompeting_names\tstatus\n' \
  >"$preflight"
printf 'cell\tvariant\tcommit\trepetition\tpair_order\trun_position\targv\n' >"$execution"

competing_process_names() {
  ps -eo comm=,args= --no-headers | awk '
    $1 == "cargo" || $1 == "rustc" || $1 == "rustdoc" ||
    $1 ~ /^rrharness($|-)/ || $1 ~ /^route_paging($|-)/ ||
    $1 == "perf" || $1 ~ /^bgperf2($|-)/ ||
    $0 ~ /compare-route-paging[.]sh/ || $0 ~ /reloadstall\/run-receipt[.]sh/ {
      print $1
    }
  ' | LC_ALL=C sort -u
}

preflight_cell() {
  local cell=$1 attempt=0 deadline=$((SECONDS + preflight_wait_seconds))
  local utc load governor names count status
  while true; do
    ((attempt += 1))
    utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    load=$(awk '{print $1}' /proc/loadavg)
    governor=$(tr -d '\n' <"$governor_path")
    names=$(competing_process_names)
    if [[ -n $names ]]; then
      count=$(wc -l <<<"$names")
      names=$(tr '\n' ',' <<<"$names" | sed 's/,$//')
    else
      count=0
      names=none
    fi
    status=pass
    if ! awk -v value="$load" -v maximum="$load_one_max" \
      'BEGIN { exit !(value + 0 < maximum + 0) }'; then
      status=wait-load
    elif [[ $governor != "$required_governor" ]]; then
      status=wait-governor
    elif ((count != 0)); then
      status=wait-processes
    fi
    if [[ $status != pass && $SECONDS -ge $deadline ]]; then
      status=${status/wait-/timeout-}
    fi
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
      "$cell" "$attempt" "$utc" "$load" "$load_one_max" "$governor" \
      "$count" "$names" "$status" >>"$preflight"
    [[ $status == pass ]] && return 0
    [[ $status == timeout-* ]] && {
      printf 'preflight timed out for %s: %s\n' "$cell" "$status" >&2
      return 75
    }
    sleep 1
  done
}

run_cell() {
  local variant=$1 mode=$2 clients=$3 candidates=$4 prefixes=$5 seconds=$6
  local repetition=$7 pair_order=$8 run_position=$9
  local commit binary
  case "$variant" in
    base) commit=$base_commit; binary=$base_binary ;;
    head) commit=$head_commit; binary=$head_binary ;;
    *) printf 'unknown variant: %s\n' "$variant" >&2; exit 2 ;;
  esac
  local cell="${mode}-${clients}-${candidates}-${prefixes}-rep${repetition}-${variant}"
  local out_prefix="$raw_dir/$cell"
  local log="$out_prefix.log" stderr="$out_prefix.stderr"
  local folded="$out_prefix.folded" classified="$out_prefix.cpu.tsv"
  local row="$rows_dir/$cell.csv"
  local -a rr_args
  if [[ $mode == flood ]]; then
    rr_args=(flood "$clients" "$prefixes" "$seconds" "$out_prefix")
    logical_argv="rrharness flood $clients $prefixes $seconds raw/$cell"
  else
    rr_args=(churn "$clients" "$candidates" "$prefixes" "$seconds" "$out_prefix")
    logical_argv="rrharness churn $clients $candidates $prefixes $seconds raw/$cell"
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$cell" "$variant" "$commit" "$repetition" "$pair_order" "$run_position" \
    "$logical_argv" >>"$execution"
  preflight_cell "$cell"
  timeout --signal=TERM --kill-after=30s "${cell_timeout_seconds}s" \
    taskset -c "$core" "$binary" "${rr_args[@]}" >"$log" 2>"$stderr"
  [[ ! -s $stderr ]] || {
    printf 'rrharness emitted stderr for %s\n' "$cell" >&2
    exit 1
  }
  [[ -s $folded ]] || { printf 'rrharness omitted folded profile for %s\n' "$cell" >&2; exit 1; }
  python3 "$source_dir/classify_cpu.py" "$folded" --output "$classified"
  python3 "$source_dir/classify_cpu.py" "$folded" --check "$classified"
  python3 "$source_dir/parse_rrharness.py" parse \
    --mode "$mode" --variant "$variant" --commit "$commit" \
    --repetition "$repetition" --pair-order "$pair_order" \
    --run-position "$run_position" --log "$log" --folded "$folded" \
    --classified "$classified" --output "$row"
  [[ $(wc -l <"$row") -eq 2 ]] || {
    printf 'cell parser did not emit exactly one row: %s\n' "$cell" >&2
    exit 1
  }
  tail -n 1 "$row" >>"$results"
}

run_pair() {
  local mode=$1 clients=$2 candidates=$3 prefixes=$4 seconds=$5 repetition=$6
  if ((repetition == 1)); then
    run_cell base "$mode" "$clients" "$candidates" "$prefixes" "$seconds" \
      "$repetition" base-first first
    run_cell head "$mode" "$clients" "$candidates" "$prefixes" "$seconds" \
      "$repetition" base-first second
  else
    run_cell head "$mode" "$clients" "$candidates" "$prefixes" "$seconds" \
      "$repetition" head-first first
    run_cell base "$mode" "$clients" "$candidates" "$prefixes" "$seconds" \
      "$repetition" head-first second
  fi
}

for repetition in 1 2; do
  run_pair flood 256 0 100000 20 "$repetition"
done
for repetition in 1 2; do
  run_pair flood 1000 0 100000 20 "$repetition"
done
for repetition in 1 2; do
  run_pair churn 256 256 3000 20 "$repetition"
done
for repetition in 1 2; do
  run_pair churn 1000 1000 3000 20 "$repetition"
done

python3 "$source_dir/parse_rrharness.py" compare \
  --input "$results" --raw-dir "$raw_dir" --output "$comparison"

(
  cd "$output_dir"
  find raw -type f -name '*.folded' -print0 | LC_ALL=C sort -z | xargs -0 sha256sum \
    >folded-SHA256SUMS
  sha256sum --check folded-SHA256SUMS >/dev/null
  while IFS= read -r member; do
    [[ $member != /* && $member != *'..'* ]] || {
      printf 'unsafe folded archive member: %s\n' "$member" >&2
      exit 1
    }
    [[ -f $member && ! -L $member ]] || {
      printf 'folded archive member is not a regular file: %s\n' "$member" >&2
      exit 1
    }
  done < <(awk '{print $2}' folded-SHA256SUMS)
  awk '{print $2}' folded-SHA256SUMS \
    | tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 \
      --numeric-owner -T - -cf - \
    | gzip -n >folded-profiles.tar.gz
  tar -tzf folded-profiles.tar.gz | LC_ALL=C sort >folded-archive-members.txt
  diff -u <(awk '{print $2}' folded-SHA256SUMS | LC_ALL=C sort) folded-archive-members.txt
)

run_utc_finish=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cpu_model=$(awk -F: '/^model name/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' /proc/cpuinfo)
python3 - "$output_dir/manifest.json" <<PY
import json
from pathlib import Path

manifest = {
    "schema": "rustbgpd.rrharness-comparison.v1",
    "status": "all-throughput-gates-passed",
    "run_utc_start": "$run_utc_start",
    "run_utc_finish": "$run_utc_finish",
    "invoking_commit": "$invoking_head",
    "pin_commit": "$invoking_head",
    "tooling_commit": "$tooling_commit",
    "base_commit": "$base_commit",
    "head_commit": "$head_commit",
    "base_tree": "$(git -C "$repo_root" rev-parse "${base_commit}^{tree}")",
    "head_tree": "$(git -C "$repo_root" rev-parse "${head_commit}^{tree}")",
    "production_diff_sha256": "$production_diff_sha256",
    "base_binary_sha256": "$base_binary_sha256",
    "head_binary_sha256": "$head_binary_sha256",
    "driver_sha256": "$(sha256sum "$source_dir/compare-rrharness.sh" | awk '{print $1}')",
    "criterion_driver_sha256": "$(sha256sum "$source_dir/compare-criterion.sh" | awk '{print $1}')",
    "parser_sha256": "$(sha256sum "$source_dir/parse_rrharness.py" | awk '{print $1}')",
    "classifier_sha256": "$(sha256sum "$source_dir/classify_cpu.py" | awk '{print $1}')",
    "criterion_validator_sha256": "$(sha256sum "$source_dir/validate_lan395_criterion.py" | awk '{print $1}')",
    "run_pin_sha256": "$(sha256sum "$source_dir/lan395-run-pin.env" | awk '{print $1}')",
    "compile_inputs_sha256": "$(sha256sum "$compile_input_manifest" | awk '{print $1}')",
    "host_lock_source": "$host_lock_source",
    "host_lock_path_sha256": "$host_lock_sha256",
    "cpu_core": $core,
    "cpu_governor": "$required_governor",
    "cpu_model": "$cpu_model",
    "load_one_max": $load_one_max,
    "cell_timeout_seconds": $cell_timeout_seconds,
    "cell_count": 16,
    "repetitions": 2,
    "counterbalance": ["repetition-1-base-first", "repetition-2-head-first"],
    "build": "cargo build --release --locked --jobs 1 --manifest-path bench/scale/rrharness/Cargo.toml",
    "launch": "direct-prebuilt-binary-with-taskset",
    "rustc": "$(rustc --version)",
    "cargo": "$(cargo --version)",
    "kernel": "$(uname -sr)",
}
Path("$output_dir/manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

rm -rf "$rows_dir"

# Reconcile the row-level folded/classified hashes once more immediately
# before the immutable checksum envelope. This closes the post-parse window:
# later raw-file drift cannot be blessed by a new top-level checksum while
# results.csv still names the earlier bytes.
final_comparison="$scratch/final-comparison.csv"
python3 "$source_dir/parse_rrharness.py" compare \
  --input "$results" --raw-dir "$raw_dir" --output "$final_comparison"
cmp --silent "$comparison" "$final_comparison" || {
  printf 'final comparison differs from the gated matrix\n' >&2
  exit 1
}

# Retained Python tooling is executed with bytecode writes disabled. Require
# the complete reviewed source inventory here, after the last parser process,
# so ignored caches, sidecars, symlinks, or other generated files cannot enter
# the checksum envelope after review.
expected_measurement_sources=(
  classify_cpu.py
  compare-criterion.sh
  compare-rrharness.sh
  compile-inputs.sha256
  lan395-run-pin.env
  parse_rrharness.py
  production-diff.sha256
  production.patch
  validate_lan395_criterion.py
)
mapfile -d '' -t actual_measurement_sources < <(
  find "$source_dir" -mindepth 1 -maxdepth 1 -printf '%f\0' | LC_ALL=C sort -z
)
[[ ${#actual_measurement_sources[@]} -eq ${#expected_measurement_sources[@]} ]] || {
  printf 'measurement-source inventory differs from the reviewed exact set\n' >&2
  exit 1
}
for source_index in "${!expected_measurement_sources[@]}"; do
  [[ ${actual_measurement_sources[$source_index]} == "${expected_measurement_sources[$source_index]}" ]] || {
    printf 'measurement-source inventory differs from the reviewed exact set\n' >&2
    exit 1
  }
done
for source in "$source_dir"/*; do
  [[ -f $source && ! -L $source ]] || {
    printf 'measurement source is not a regular non-symlink file: %s\n' "$source" >&2
    exit 1
  }
done

# Scan every retained file, including ignored and binary measurement sources,
# for the actual private/ephemeral roots and hostname used by this run. A
# second structural scan covers credentials and PID/argv-shaped derivatives;
# checked-in sources are excluded only from that generic vocabulary scan, not
# from actual private values. No retained-file producer runs after this point.
privacy_require_no_match() {
  local label=$1
  local scan_rc=0
  shift
  rg "$@" >/dev/null || scan_rc=$?
  case $scan_rc in
    0)
      printf 'privacy scan rejected %s\n' "$label" >&2
      return 1
      ;;
    1)
      return 0
      ;;
    *)
      printf 'privacy scan failed while inspecting %s (rg exit %s)\n' \
        "$label" "$scan_rc" >&2
      return 1
      ;;
  esac
}

for private_value in "$HOME/" "$repo_root/" "$scratch/" "$(hostname)"; do
  [[ -n $private_value ]] || continue
  privacy_require_no_match 'retained private value' \
    -a --no-ignore -F -n --hidden -- "$private_value" "$output_dir"
done
privacy_require_no_match 'retained credentials or process identity' \
  -a --no-ignore -n --hidden \
  'https?://[^/@:]+:[^/@]+@|(^|[^[:alpha:]])pid([^[:alpha:]]|$)|user(name)?=' \
  -g '!**/measurement-sources/**' "$output_dir"

final_manifest_tmp="$scratch/final-SHA256SUMS"
(
  cd "$output_dir"
  find . -type f ! -name SHA256SUMS ! -name COMPLETED -print0 \
    | LC_ALL=C sort -z | xargs -0 sha256sum >"$final_manifest_tmp"
  mv "$final_manifest_tmp" SHA256SUMS
  sha256sum --check SHA256SUMS >/dev/null
  printf 'schema=rustbgpd.rrharness-comparison.v1\n' >COMPLETED
  printf 'sha256sums_sha256=%s\n' "$(sha256sum SHA256SUMS | awk '{print $1}')" >>COMPLETED
  printf 'matrix_complete=1\nthroughput_gates_passed=1\n' >>COMPLETED
)

printf 'complete LAN-395 rrharness receipt: %s\n' "$output_dir"
