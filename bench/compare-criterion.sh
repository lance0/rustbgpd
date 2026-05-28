#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Compare Criterion benchmarks between two git refs using a pinned CPU core.

Usage:
  bench/compare-criterion.sh [options]

Options:
  --base REF              Baseline ref to benchmark first (default: origin/main)
  --head REF              Head ref to compare against baseline (default: HEAD)
  --package NAME          Cargo package to benchmark (default: rustbgpd-rib)
  --bench NAME            Criterion bench target (default: rib_ops)
  --filter TEXT           Criterion benchmark filter, for example adj_rib_in_insert
  --core CPU              CPU core passed to taskset -c (default: 0)
  --out-dir PATH          Output directory (default: target/bench-compare)
  --allow-dirty           Allow a dirty worktree; refs still resolve to commits
  --no-taskset            Run without taskset pinning
  --require-performance   Fail if the selected CPU is not using performance governor
  --keep-worktrees        Leave temporary git worktrees in the output directory
  -h, --help              Show this help

Examples:
  bench/compare-criterion.sh \
    --base v0.24.0 \
    --head HEAD \
    --core 8 \
    --package rustbgpd-rib \
    --bench rib_ops \
    --filter adj_rib_in_insert

  bench/compare-criterion.sh \
    --base origin/main \
    --head perf/my-branch \
    --core 8 \
    --package rustbgpd-wire \
    --bench codec
EOF
}

base_ref="origin/main"
head_ref="HEAD"
package="rustbgpd-rib"
bench_name="rib_ops"
filter=""
core="0"
out_root="target/bench-compare"
allow_dirty=0
use_taskset=1
require_performance=0
keep_worktrees=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base)
      base_ref="${2:?missing value for --base}"
      shift 2
      ;;
    --head)
      head_ref="${2:?missing value for --head}"
      shift 2
      ;;
    --package)
      package="${2:?missing value for --package}"
      shift 2
      ;;
    --bench)
      bench_name="${2:?missing value for --bench}"
      shift 2
      ;;
    --filter)
      filter="${2:?missing value for --filter}"
      shift 2
      ;;
    --core)
      core="${2:?missing value for --core}"
      shift 2
      ;;
    --out-dir)
      out_root="${2:?missing value for --out-dir}"
      shift 2
      ;;
    --allow-dirty)
      allow_dirty=1
      shift
      ;;
    --no-taskset)
      use_taskset=0
      shift
      ;;
    --require-performance)
      require_performance=1
      shift
      ;;
    --keep-worktrees)
      keep_worktrees=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

repo="$(git rev-parse --show-toplevel)"
cd "$repo"

if [[ "$allow_dirty" -eq 0 ]]; then
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    echo "error: worktree is dirty; commit/stash changes or pass --allow-dirty" >&2
    exit 1
  fi
fi

base_sha="$(git rev-parse --verify "${base_ref}^{commit}")"
head_sha="$(git rev-parse --verify "${head_ref}^{commit}")"
base_short="$(git rev-parse --short=12 "$base_sha")"
head_short="$(git rev-parse --short=12 "$head_sha")"

if [[ "$use_taskset" -eq 1 ]] && ! command -v taskset >/dev/null 2>&1; then
  echo "error: taskset not found; install util-linux or pass --no-taskset" >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 not found; required for Criterion JSON summary" >&2
  exit 1
fi

gov_file="/sys/devices/system/cpu/cpu${core}/cpufreq/scaling_governor"
governor="unknown"
if [[ -r "$gov_file" ]]; then
  governor="$(<"$gov_file")"
fi
if [[ "$require_performance" -eq 1 && "$governor" != "performance" ]]; then
  echo "error: cpu${core} governor is '${governor}', expected 'performance'" >&2
  exit 1
fi
if [[ "$governor" != "performance" ]]; then
  echo "warning: cpu${core} governor is '${governor}', not 'performance'" >&2
fi

run_id="$(date -u +%Y%m%dT%H%M%SZ)-${base_short}-vs-${head_short}-${package}-${bench_name}"
case "$out_root" in
  /*) out_parent="$out_root" ;;
  *) out_parent="${repo}/${out_root}" ;;
esac
run_dir="${out_parent}/${run_id}"
base_dir="${run_dir}/base"
head_dir="${run_dir}/head"
target_dir="${run_dir}/target"
log_dir="${run_dir}/logs"
summary_file="${run_dir}/summary.md"
metadata_file="${run_dir}/metadata.txt"

mkdir -p "$log_dir" "$target_dir"

cleanup() {
  if [[ "$keep_worktrees" -eq 0 ]]; then
    git worktree remove --force "$base_dir" >/dev/null 2>&1 || true
    git worktree remove --force "$head_dir" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Creating detached worktrees under ${run_dir}"
git worktree add --detach "$base_dir" "$base_sha" >/dev/null
git worktree add --detach "$head_dir" "$head_sha" >/dev/null

baseline_name="base-${base_short}"

write_metadata() {
  {
    echo "run_id=${run_id}"
    echo "base_ref=${base_ref}"
    echo "base_sha=${base_sha}"
    echo "head_ref=${head_ref}"
    echo "head_sha=${head_sha}"
    echo "package=${package}"
    echo "bench=${bench_name}"
    echo "filter=${filter}"
    echo "core=${core}"
    echo "governor=${governor}"
    echo "use_taskset=${use_taskset}"
    echo "target_dir=${target_dir}"
    echo "criterion_dir=${target_dir}/criterion"
    echo
    uname -a
    echo
    rustc -Vv
    echo
    cargo -V
    echo
    if [[ -r /proc/cpuinfo ]]; then
      grep -m1 -E 'model name|Hardware' /proc/cpuinfo || true
    fi
    if command -v sysctl >/dev/null 2>&1; then
      sysctl kernel.perf_event_paranoid 2>/dev/null || true
    fi
  } >"$metadata_file"
}

run_bench() {
  local worktree="$1"
  local log_file="$2"
  shift 2

  (
    cd "$worktree"
    export CARGO_TARGET_DIR="$target_dir"
    echo "+ CARGO_TARGET_DIR=$target_dir $*"
    if [[ "$use_taskset" -eq 1 ]]; then
      taskset -c "$core" "$@"
    else
      "$@"
    fi
  ) 2>&1 | tee "$log_file"
}

criterion_base=(--save-baseline "$baseline_name")
criterion_head=(--baseline "$baseline_name")
if [[ -n "$filter" ]]; then
  criterion_base+=("$filter")
  criterion_head+=("$filter")
fi

write_metadata

echo "Running baseline ${base_ref} (${base_short})"
run_bench "$base_dir" "$log_dir/base.log" \
  cargo bench -p "$package" --bench "$bench_name" -- "${criterion_base[@]}"

echo "Running head ${head_ref} (${head_short})"
run_bench "$head_dir" "$log_dir/head.log" \
  cargo bench -p "$package" --bench "$bench_name" -- "${criterion_head[@]}"

CRITERION_DIR="${target_dir}/criterion" \
SUMMARY_FILE="$summary_file" \
BASE_SHA="$base_sha" \
HEAD_SHA="$head_sha" \
BASE_SHORT="$base_short" \
HEAD_SHORT="$head_short" \
BASELINE_NAME="$baseline_name" \
RUN_ID="$run_id" \
METADATA_FILE="$metadata_file" \
python3 - <<'PY'
import json
import os
from pathlib import Path

criterion_dir = Path(os.environ["CRITERION_DIR"])
summary_file = Path(os.environ["SUMMARY_FILE"])
baseline_name = os.environ["BASELINE_NAME"]

def fmt_ns(ns: float) -> str:
    if ns < 1_000:
        return f"{ns:.1f} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.2f} us"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000:.2f} ms"
    return f"{ns / 1_000_000_000:.2f} s"

rows = []
for new_estimates in sorted(criterion_dir.glob("**/new/estimates.json")):
    bench_dir = new_estimates.parent.parent
    try:
        bench_id = bench_dir.relative_to(criterion_dir).as_posix()
        new_data = json.loads(new_estimates.read_text())
        head_median = float(new_data["median"]["point_estimate"])
    except (OSError, KeyError, ValueError, json.JSONDecodeError):
        continue

    change_file = bench_dir / "change" / "estimates.json"
    base_median = None
    delta_pct = None
    ci = None
    baseline_estimates = bench_dir / baseline_name / "estimates.json"
    if baseline_estimates.exists():
        try:
            base_data = json.loads(baseline_estimates.read_text())
            base_median = float(base_data["median"]["point_estimate"])
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            pass

    if change_file.exists():
        try:
            change_data = json.loads(change_file.read_text())
            mean = change_data["mean"]
            delta = float(mean["point_estimate"])
            delta_pct = delta * 100.0
            interval = mean["confidence_interval"]
            ci = (
                float(interval["lower_bound"]) * 100.0,
                float(interval["upper_bound"]) * 100.0,
            )
        except (OSError, KeyError, ValueError, json.JSONDecodeError):
            pass

    rows.append((bench_id, base_median, head_median, delta_pct, ci))

lines = [
    "# Criterion Compare Summary",
    "",
    f"- Run: `{os.environ['RUN_ID']}`",
    f"- Base: `{os.environ['BASE_SHORT']}` (`{os.environ['BASE_SHA']}`)",
    f"- Head: `{os.environ['HEAD_SHORT']}` (`{os.environ['HEAD_SHA']}`)",
    f"- Metadata: `{os.environ['METADATA_FILE']}`",
    f"- Criterion artifacts: `{criterion_dir}`",
    "",
    "| Benchmark | Base median | Head median | Mean delta | 95% CI |",
    "|---|---:|---:|---:|---:|",
]

for bench_id, base_median, head_median, delta_pct, ci in rows:
    base_cell = fmt_ns(base_median) if base_median is not None else "n/a"
    head_cell = fmt_ns(head_median)
    delta_cell = f"{delta_pct:+.2f}%" if delta_pct is not None else "n/a"
    ci_cell = f"{ci[0]:+.2f}%..{ci[1]:+.2f}%" if ci is not None else "n/a"
    lines.append(f"| `{bench_id}` | {base_cell} | {head_cell} | {delta_cell} | {ci_cell} |")

if not rows:
    lines.append("| n/a | n/a | n/a | n/a | n/a |")

summary_file.write_text("\n".join(lines) + "\n")
print(summary_file.read_text())
PY

echo "Summary written to ${summary_file}"
echo "Logs written to ${log_dir}"
