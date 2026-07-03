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
  --attempts N            Number of A/B attempts with alternating order to
                          dampen base/head cache-warming bias (default: 1).
                          Odd attempts run base first, even attempts run head
                          first. Even N fully cancels first-vs-second bias.
  --out-dir PATH          Output directory (default: target/bench-compare)
  --allow-dirty           Allow a dirty worktree; refs still resolve to commits
  --no-taskset            Run without taskset pinning
  --require-performance   Fail if the selected CPU is not using performance governor
  --fail-on-regression    Exit non-zero when any row is a confident regression:
                          completed attempts >= --verdict-min-attempts,
                          min..max entirely above zero, the last-run 95% CI
                          entirely above zero, stddev below
                          --regression-max-stddev-pct, and mean delta >=
                          --regression-threshold-pct. Rows that clear the delta
                          but whose 95% CI straddles zero stay advisory
                          (`ci-straddles-zero`).
  --regression-threshold-pct PCT
                          Mean head-vs-base delta needed for a confident
                          regression verdict (default: 3).
  --regression-max-stddev-pct PCT
                          Maximum across-attempt delta stddev for a confident
                          verdict; noisier rows stay inconclusive (default: 10).
  --verdict-min-attempts N
                          Minimum completed A/B attempts before verdicts can
                          fail the run; must be at least 2 because verdicts use
                          across-attempt stddev/min..max (default: 3).
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
attempts=1
out_root="target/bench-compare"
allow_dirty=0
use_taskset=1
require_performance=0
keep_worktrees=0
fail_on_regression=0
regression_threshold_pct="3"
regression_max_stddev_pct="10"
verdict_min_attempts=3

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
    --attempts)
      attempts="${2:?missing value for --attempts}"
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
    --fail-on-regression)
      fail_on_regression=1
      shift
      ;;
    --regression-threshold-pct)
      regression_threshold_pct="${2:?missing value for --regression-threshold-pct}"
      shift 2
      ;;
    --regression-max-stddev-pct)
      regression_max_stddev_pct="${2:?missing value for --regression-max-stddev-pct}"
      shift 2
      ;;
    --verdict-min-attempts)
      verdict_min_attempts="${2:?missing value for --verdict-min-attempts}"
      shift 2
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

if ! [[ "$attempts" =~ ^[0-9]+$ ]] || [[ "$attempts" -lt 1 ]]; then
  echo "error: --attempts must be a positive integer (got '${attempts}')" >&2
  exit 1
fi
if ! [[ "$verdict_min_attempts" =~ ^[0-9]+$ ]] || [[ "$verdict_min_attempts" -lt 2 ]]; then
  echo "error: --verdict-min-attempts must be an integer >= 2 (got '${verdict_min_attempts}')" >&2
  exit 1
fi
if ! python3 - "$regression_threshold_pct" <<'PY'
import sys
try:
    threshold = float(sys.argv[1])
except ValueError:
    sys.exit(1)
sys.exit(0 if threshold > 0 else 1)
PY
then
  echo "error: --regression-threshold-pct must be a positive number (got '${regression_threshold_pct}')" >&2
  exit 1
fi
if ! python3 - "$regression_max_stddev_pct" <<'PY'
import sys
try:
    threshold = float(sys.argv[1])
except ValueError:
    sys.exit(1)
sys.exit(0 if threshold > 0 else 1)
PY
then
  echo "error: --regression-max-stddev-pct must be a positive number (got '${regression_max_stddev_pct}')" >&2
  exit 1
fi

# Host-level mutex with any concurrent soak / other perf workload.
# The bench host is shared between this workflow and the soak runner;
# letting both run at once would corrupt every reading from both. The
# soak harnesses under `tests/soak/` acquire the same lock via
# `tests/soak/host-lock.sh`; the path and acquisition here must stay in
# sync with that helper. Always lock (creating the lock dir if needed):
# an earlier "skip when ${HOME}/.local/state is absent" gate silently
# disabled the mutex on the shared box, where that dir did not exist, so
# a soak and the nightly bench ran unprotected. The soak runner and this
# bench runner run as the same user, so the per-user default path
# resolves to one shared file. Exit 75 (EX_TEMPFAIL — host busy) on
# contention so an unattended caller can skip rather than fail red.
host_lock="${RUSTBGPD_HOST_LOCK:-${HOME}/.local/state/rustbgpd-host.lock}"
mkdir -p "$(dirname "$host_lock")"
touch "$host_lock"
exec {host_lock_fd}>"$host_lock"
if ! flock -n "$host_lock_fd"; then
  echo "error: ${host_lock} is held by another process (soak or bench)" >&2
  echo "       wait for it to finish or remove the lock if stale" >&2
  exit 75
fi
echo "acquired host lock: ${host_lock}"

run_id="$(date -u +%Y%m%dT%H%M%SZ)-${base_short}-vs-${head_short}-${package}-${bench_name}"
case "$out_root" in
  /*) out_parent="$out_root" ;;
  *) out_parent="${repo}/${out_root}" ;;
esac
run_dir="${out_parent}/${run_id}"
base_dir="${run_dir}/base"
head_dir="${run_dir}/head"
# Per-side target dirs — never share one CARGO_TARGET_DIR between the
# two worktrees. Cargo names a path crate's artifacts with a metadata
# hash whose package-id component is stable-hashed RELATIVE to the
# workspace root, so base/ and head/ produce IDENTICAL artifact
# filenames for any crate whose name/version/features/dep-graph are
# unchanged between the refs. Both worktrees are checked out before
# either side builds, so whichever side builds second passes cargo's
# mtime freshness check against the first side's rlib (sources older
# than the artifact) and silently links it: a mixed-tree build. That
# either fails the compile (new source against a stale rlib) or —
# worse — quietly benches the first side's code on both sides.
# Separate target dirs make the collision structurally impossible;
# Criterion data still lands in one shared tree via CRITERION_HOME
# (the attempt-N-base/-head baseline names keep the sides apart) so
# the summariser reads a single directory.
base_target_dir="${run_dir}/target-base"
head_target_dir="${run_dir}/target-head"
criterion_home="${run_dir}/criterion"
log_dir="${run_dir}/logs"
summary_file="${run_dir}/summary.md"
metadata_file="${run_dir}/metadata.txt"

mkdir -p "$log_dir" "$base_target_dir" "$head_target_dir" "$criterion_home"

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
    echo "attempts=${attempts}"
    echo "fail_on_regression=${fail_on_regression}"
    echo "regression_threshold_pct=${regression_threshold_pct}"
    echo "regression_max_stddev_pct=${regression_max_stddev_pct}"
    echo "verdict_min_attempts=${verdict_min_attempts}"
    echo "governor=${governor}"
    echo "use_taskset=${use_taskset}"
    echo "base_target_dir=${base_target_dir}"
    echo "head_target_dir=${head_target_dir}"
    echo "criterion_dir=${criterion_home}"
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
  local target_dir="$2"
  local log_file="$3"
  shift 3

  (
    cd "$worktree"
    export CARGO_TARGET_DIR="$target_dir"
    export CRITERION_HOME="$criterion_home"
    echo "+ CARGO_TARGET_DIR=$target_dir CRITERION_HOME=$criterion_home $*"
    if [[ "$use_taskset" -eq 1 ]]; then
      taskset -c "$core" "$@"
    else
      "$@"
    fi
  ) 2>&1 | tee "$log_file"
}

write_metadata

# Attempt loop. Odd attempts run base first then head; even attempts
# run head first then base. Cache and codegen state warm during the
# first bench; alternating ordering lets the across-attempt mean
# cancel that bias. Each ref's run uses `--save-baseline` only — not
# `--baseline` — because criterion rejects the two flags combined
# ("an argument cannot be used with one or more of the other
# specified arguments"). Deltas are computed from the saved-baseline
# medians in the summariser, so the sign convention stays head-vs-base
# regardless of which ref ran first.
build_args() {
  local baseline_name="$1"
  printf '%s\n%s\n' "--save-baseline" "$baseline_name"
  if [[ -n "$filter" ]]; then
    printf '%s\n' "$filter"
  fi
}

for attempt in $(seq 1 "$attempts"); do
  if (( attempt % 2 == 1 )); then
    order="base-first"
  else
    order="head-first"
  fi

  base_baseline="attempt-${attempt}-base"
  head_baseline="attempt-${attempt}-head"

  mapfile -t base_args < <(build_args "$base_baseline")
  mapfile -t head_args < <(build_args "$head_baseline")

  echo "===== attempt ${attempt} / ${attempts} (order: ${order}) ====="

  if [[ "$order" == "base-first" ]]; then
    echo "[attempt ${attempt}] Running base ${base_ref} (${base_short})"
    run_bench "$base_dir" "$base_target_dir" "${log_dir}/attempt-${attempt}-base.log" \
      cargo bench -p "$package" --bench "$bench_name" -- "${base_args[@]}"
    echo "[attempt ${attempt}] Running head ${head_ref} (${head_short})"
    run_bench "$head_dir" "$head_target_dir" "${log_dir}/attempt-${attempt}-head.log" \
      cargo bench -p "$package" --bench "$bench_name" -- "${head_args[@]}"
  else
    echo "[attempt ${attempt}] Running head ${head_ref} (${head_short})"
    run_bench "$head_dir" "$head_target_dir" "${log_dir}/attempt-${attempt}-head.log" \
      cargo bench -p "$package" --bench "$bench_name" -- "${head_args[@]}"
    echo "[attempt ${attempt}] Running base ${base_ref} (${base_short})"
    run_bench "$base_dir" "$base_target_dir" "${log_dir}/attempt-${attempt}-base.log" \
      cargo bench -p "$package" --bench "$bench_name" -- "${base_args[@]}"
  fi
done

CRITERION_DIR="$criterion_home" \
SUMMARY_FILE="$summary_file" \
ATTEMPTS="$attempts" \
BASE_SHA="$base_sha" \
HEAD_SHA="$head_sha" \
BASE_SHORT="$base_short" \
HEAD_SHORT="$head_short" \
RUN_ID="$run_id" \
METADATA_FILE="$metadata_file" \
FAIL_ON_REGRESSION="$fail_on_regression" \
REGRESSION_THRESHOLD_PCT="$regression_threshold_pct" \
REGRESSION_MAX_STDDEV_PCT="$regression_max_stddev_pct" \
VERDICT_MIN_ATTEMPTS="$verdict_min_attempts" \
python3 - <<'PY'
import json
import os
import statistics
import sys
from pathlib import Path

criterion_dir = Path(os.environ["CRITERION_DIR"])
summary_file = Path(os.environ["SUMMARY_FILE"])
attempts = int(os.environ["ATTEMPTS"])
fail_on_regression = os.environ["FAIL_ON_REGRESSION"] == "1"
regression_threshold_pct = float(os.environ["REGRESSION_THRESHOLD_PCT"])
regression_max_stddev_pct = float(os.environ["REGRESSION_MAX_STDDEV_PCT"])
verdict_min_attempts = int(os.environ["VERDICT_MIN_ATTEMPTS"])


def fmt_ns(ns: float) -> str:
    if ns < 1_000:
        return f"{ns:.1f} ns"
    if ns < 1_000_000:
        return f"{ns / 1_000:.2f} us"
    if ns < 1_000_000_000:
        return f"{ns / 1_000_000:.2f} ms"
    return f"{ns / 1_000_000_000:.2f} s"


def load_estimates(path: Path):
    """Return (point_estimate, ci_lower, ci_upper) for the median, or None."""
    try:
        data = json.loads(path.read_text())["median"]
        return (
            float(data["point_estimate"]),
            float(data["confidence_interval"]["lower_bound"]),
            float(data["confidence_interval"]["upper_bound"]),
        )
    except (OSError, KeyError, ValueError, json.JSONDecodeError):
        return None


def propagated_ci_pct(base_est, head_est):
    """Conservative bracket on (head-vs-base) ratio from saved median CIs.

    head ∈ [head_lo, head_hi], base ∈ [base_lo, base_hi]; the delta
    (head-base)/base is maximised by (head_hi - base_lo)/base_lo and
    minimised by (head_lo - base_hi)/base_hi. Wider than Criterion's
    `change/estimates.json` mean CI, but it does not require running a
    `--baseline` comparison (which conflicts with `--save-baseline`).
    """
    _, base_lo, base_hi = base_est
    _, head_lo, head_hi = head_est
    if base_lo <= 0 or base_hi <= 0:
        return None
    lo = (head_lo - base_hi) / base_hi * 100.0
    hi = (head_hi - base_lo) / base_lo * 100.0
    return (lo, hi)


def verdict(attempts_completed, mean_delta, stddev, minmax, last_ci):
    if attempts_completed < verdict_min_attempts or stddev is None or minmax is None:
        return "insufficient-attempts"
    if minmax[0] <= 0 <= minmax[1]:
        return "noise"
    if minmax[1] < 0:
        return "improvement"
    if stddev >= regression_max_stddev_pct:
        return "inconclusive-noisy"
    if minmax[0] > 0 and mean_delta >= regression_threshold_pct:
        # A confident regression also requires the last run's own propagated
        # 95% CI to sit entirely above zero. The across-attempt deltas can all
        # land positive (min..max > 0) from a small systematic skew even when a
        # single run is not statistically separable from no-change; when that
        # CI straddles zero (or is unavailable) the row stays advisory instead
        # of failing the run. This is what keeps a docs-only / no-op change
        # from tripping `--fail-on-regression` on benchmark noise.
        if last_ci is not None and last_ci[0] > 0:
            return "regression"
        return "ci-straddles-zero"
    if minmax[0] > 0:
        return "positive-under-threshold"
    return "noise"


# Discover bench_ids via attempt-1-base saved baselines.
bench_ids = sorted({
    p.parent.parent.relative_to(criterion_dir).as_posix()
    for p in criterion_dir.glob("**/attempt-1-base/estimates.json")
})

rows = []
regression_rows = []
for bench_id in bench_ids:
    deltas_pct = []
    base_medians = []
    head_medians = []
    last_ci = None
    attempts_completed = 0
    for attempt in range(1, attempts + 1):
        base_est = load_estimates(
            criterion_dir / bench_id / f"attempt-{attempt}-base" / "estimates.json"
        )
        head_est = load_estimates(
            criterion_dir / bench_id / f"attempt-{attempt}-head" / "estimates.json"
        )
        if base_est is None or head_est is None or base_est[0] == 0:
            continue
        base_med = base_est[0]
        head_med = head_est[0]
        # head-vs-base from saved medians; sign-independent of order.
        deltas_pct.append((head_med - base_med) / base_med * 100.0)
        base_medians.append(base_med)
        head_medians.append(head_med)
        attempts_completed += 1
        last_ci = propagated_ci_pct(base_est, head_est)

    if attempts_completed == 0:
        rows.append((bench_id, 0, None, None, None, None, None, None, "missing"))
        continue

    mean_delta = statistics.mean(deltas_pct)
    stddev = statistics.stdev(deltas_pct) if attempts_completed >= 2 else None
    minmax = (min(deltas_pct), max(deltas_pct)) if attempts_completed >= 2 else None
    row_verdict = verdict(attempts_completed, mean_delta, stddev, minmax, last_ci)
    if row_verdict == "regression":
        regression_rows.append(bench_id)

    rows.append(
        (
            bench_id,
            attempts_completed,
            statistics.mean(base_medians),
            statistics.mean(head_medians),
            mean_delta,
            stddev,
            minmax,
            last_ci,
            row_verdict,
        )
    )

lines = [
    "# Criterion Compare Summary",
    "",
    f"- Run: `{os.environ['RUN_ID']}`",
    f"- Base: `{os.environ['BASE_SHORT']}` (`{os.environ['BASE_SHA']}`)",
    f"- Head: `{os.environ['HEAD_SHORT']}` (`{os.environ['HEAD_SHA']}`)",
    f"- Attempts: {attempts}"
    + (" (alternating order: odd = base-first, even = head-first)" if attempts >= 2 else ""),
    f"- Verdict mode: {'fail on confident regression' if fail_on_regression else 'summary only'}",
    f"- Regression threshold: mean delta >= {regression_threshold_pct:g}% "
    f"with min..max and the last-run 95% CI both entirely above zero, "
    f"stddev < {regression_max_stddev_pct:g}%, "
    f"with >= {verdict_min_attempts} completed attempts "
    f"(delta-only rows whose 95% CI straddles zero stay advisory)",
    f"- Metadata: `{os.environ['METADATA_FILE']}`",
    f"- Criterion artifacts: `{criterion_dir}`",
    "",
]

if attempts >= 2:
    lines.extend([
        "| Benchmark | attempts | base median (mean) | head median (mean) | mean delta | stddev | min..max | last-run 95% CI | verdict |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ])
    for (
        bench_id,
        n,
        base_med,
        head_med,
        mean_delta,
        stddev,
        minmax,
        last_ci,
        row_verdict,
    ) in rows:
        if base_med is None:
            lines.append(
                f"| `{bench_id}` | 0/{attempts} | n/a | n/a | n/a | n/a | n/a | n/a | {row_verdict} |"
            )
            continue
        attempts_cell = f"{n}/{attempts}"
        base_cell = fmt_ns(base_med)
        head_cell = fmt_ns(head_med)
        delta_cell = f"{mean_delta:+.2f}%"
        stddev_cell = f"{stddev:.2f}%" if stddev is not None else "n/a"
        minmax_cell = (
            f"{minmax[0]:+.2f}%..{minmax[1]:+.2f}%" if minmax is not None else "n/a"
        )
        ci_cell = (
            f"{last_ci[0]:+.2f}%..{last_ci[1]:+.2f}%" if last_ci is not None else "n/a"
        )
        lines.append(
            f"| `{bench_id}` | {attempts_cell} | {base_cell} | {head_cell} | "
            f"{delta_cell} | {stddev_cell} | {minmax_cell} | {ci_cell} | {row_verdict} |"
        )
else:
    lines.extend([
        "| Benchmark | base median | head median | delta | 95% CI | verdict |",
        "|---|---:|---:|---:|---:|---|",
    ])
    for (
        bench_id,
        _n,
        base_med,
        head_med,
        mean_delta,
        _stddev,
        _minmax,
        last_ci,
        row_verdict,
    ) in rows:
        if base_med is None:
            lines.append(f"| `{bench_id}` | n/a | n/a | n/a | n/a | {row_verdict} |")
            continue
        base_cell = fmt_ns(base_med)
        head_cell = fmt_ns(head_med)
        delta_cell = f"{mean_delta:+.2f}%"
        ci_cell = (
            f"{last_ci[0]:+.2f}%..{last_ci[1]:+.2f}%" if last_ci is not None else "n/a"
        )
        lines.append(
            f"| `{bench_id}` | {base_cell} | {head_cell} | {delta_cell} | {ci_cell} | {row_verdict} |"
        )

if not rows:
    # Column width must match whichever table header was emitted above.
    if attempts >= 2:
        lines.append("| n/a | n/a | n/a | n/a | n/a | n/a | n/a | n/a | missing |")
    else:
        lines.append("| n/a | n/a | n/a | n/a | n/a | missing |")

lines.extend(["", "## Verdict", ""])
if regression_rows:
    lines.append(
        "Confident regression rows: "
        + ", ".join(f"`{bench_id}`" for bench_id in regression_rows)
    )
elif rows:
    lines.append("No confident regressions by the configured verdict rule.")
else:
    lines.append("No benchmark rows were discovered.")

summary_file.write_text("\n".join(lines) + "\n")
print(summary_file.read_text())
if fail_on_regression and regression_rows:
    sys.exit(1)
PY

echo "Summary written to ${summary_file}"
echo "Logs written to ${log_dir}"
