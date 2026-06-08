#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Compare RIB structural memory profiles between two git refs.

Usage:
  bench/compare-rib-memory.sh [options]

Options:
  --base REF          Baseline ref to profile first (default: origin/main)
  --head REF          Head ref to compare against baseline (default: HEAD)
  --profile NAME      Profile size set: quick or full (default: quick)
  --out-dir PATH      Output directory (default: target/rib-memory-compare)
  --allow-dirty       Allow a dirty worktree; refs still resolve to commits
  --keep-worktrees    Leave temporary git worktrees in the output directory
  -h, --help          Show this help

Examples:
  bench/compare-rib-memory.sh \
    --base origin/main \
    --head HEAD \
    --profile quick

  bench/compare-rib-memory.sh \
    --base origin/main \
    --head perf/rib-storage \
    --profile full
EOF
}

base_ref="origin/main"
head_ref="HEAD"
profile="quick"
out_root="target/rib-memory-compare"
allow_dirty=0
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
    --profile)
      profile="${2:?missing value for --profile}"
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

case "$profile" in
  quick|full) ;;
  *)
    echo "error: --profile must be quick or full (got '${profile}')" >&2
    exit 2
    ;;
esac

repo="$(git rev-parse --show-toplevel)"
cd "$repo"

if [[ "$allow_dirty" -eq 0 ]]; then
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    echo "error: worktree is dirty; commit/stash changes or pass --allow-dirty" >&2
    exit 1
  fi
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "error: python3 not found; required for JSONL summary" >&2
  exit 1
fi

base_sha="$(git rev-parse --verify "${base_ref}^{commit}")"
head_sha="$(git rev-parse --verify "${head_ref}^{commit}")"
base_short="$(git rev-parse --short=12 "$base_sha")"
head_short="$(git rev-parse --short=12 "$head_sha")"

# Host-level mutex with any concurrent soak / other perf workload. Keep this
# path and contention behaviour in sync with bench/compare-criterion.sh and
# tests/soak/host-lock.sh.
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

run_id="$(date -u +%Y%m%dT%H%M%SZ)-${base_short}-vs-${head_short}-rib-memory-${profile}"
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
results_file="${run_dir}/results.csv"
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

write_metadata() {
  {
    echo "run_id=${run_id}"
    echo "base_ref=${base_ref}"
    echo "base_sha=${base_sha}"
    echo "head_ref=${head_ref}"
    echo "head_sha=${head_sha}"
    echo "profile=${profile}"
    echo "target_dir=${target_dir}"
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
  } >"$metadata_file"
}

run_profile() {
  local worktree="$1"
  local log_file="$2"
  (
    cd "$worktree"
    export CARGO_TARGET_DIR="$target_dir"
    export RUSTBGPD_RIB_MEMORY_PROFILE="$profile"
    echo "+ RUSTBGPD_RIB_MEMORY_PROFILE=$profile CARGO_TARGET_DIR=$target_dir cargo test -p rustbgpd-rib --features bench-internals --test memory_profile memory_profile_high_n -- --ignored --nocapture"
    cargo test -p rustbgpd-rib --features bench-internals \
      --test memory_profile memory_profile_high_n -- --ignored --nocapture
  ) 2>&1 | tee "$log_file"
}

write_metadata

echo "Running base ${base_ref} (${base_short})"
run_profile "$base_dir" "${log_dir}/base.log"
echo "Running head ${head_ref} (${head_short})"
run_profile "$head_dir" "${log_dir}/head.log"

BASE_LOG="${log_dir}/base.log" \
HEAD_LOG="${log_dir}/head.log" \
SUMMARY_FILE="$summary_file" \
RESULTS_FILE="$results_file" \
RUN_ID="$run_id" \
BASE_SHA="$base_sha" \
HEAD_SHA="$head_sha" \
BASE_SHORT="$base_short" \
HEAD_SHORT="$head_short" \
PROFILE="$profile" \
METADATA_FILE="$metadata_file" \
python3 - <<'PY'
import csv
import json
import os
from pathlib import Path

BASE_LOG = Path(os.environ["BASE_LOG"])
HEAD_LOG = Path(os.environ["HEAD_LOG"])
SUMMARY_FILE = Path(os.environ["SUMMARY_FILE"])
RESULTS_FILE = Path(os.environ["RESULTS_FILE"])


def load_rows(path: Path):
    rows = {}
    for line in path.read_text().splitlines():
        if not line.startswith('{"kind":"rib_memory"'):
            continue
        row = json.loads(line)
        rows[(row["shape"], int(row["prefixes"]))] = row
    if not rows:
        raise SystemExit(
            f"no rib_memory JSONL rows found in {path}; "
            "does the ref include the structured memory_profile_high_n harness?"
        )
    return rows


def fmt_bytes(value: int) -> str:
    sign = "-" if value < 0 else ""
    value = abs(value)
    if value >= 1024 * 1024 * 1024:
        return f"{sign}{value / (1024 * 1024 * 1024):.2f} GiB"
    if value >= 1024 * 1024:
        return f"{sign}{value / (1024 * 1024):.1f} MiB"
    if value >= 1024:
        return f"{sign}{value / 1024:.1f} KiB"
    return f"{sign}{value} B"


def delta_pct(base: int, head: int):
    if base == 0:
        return None
    return (head - base) / base * 100.0


base_rows = load_rows(BASE_LOG)
head_rows = load_rows(HEAD_LOG)
keys = sorted(set(base_rows) | set(head_rows), key=lambda key: (key[0], key[1]))

csv_rows = []
for key in keys:
    base = base_rows.get(key)
    head = head_rows.get(key)
    shape, prefixes = key
    if base is None or head is None:
        csv_rows.append({
            "shape": shape,
            "prefixes": prefixes,
            "base_live_bytes": "" if base is None else base["live_bytes"],
            "head_live_bytes": "" if head is None else head["live_bytes"],
            "delta_pct": "",
            "delta_mib": "",
            "review": "missing-row",
        })
        continue

    delta_bytes = int(head["live_bytes"]) - int(base["live_bytes"])
    pct = delta_pct(int(base["live_bytes"]), int(head["live_bytes"]))
    review = (
        "review"
        if pct is not None
        and pct >= 5.0
        and delta_bytes >= 32 * 1024 * 1024
        else "ok"
    )
    csv_rows.append({
        "shape": shape,
        "prefixes": prefixes,
        "base_live_bytes": base["live_bytes"],
        "head_live_bytes": head["live_bytes"],
        "delta_pct": "" if pct is None else f"{pct:.3f}",
        "delta_mib": f"{delta_bytes / (1024 * 1024):.3f}",
        "base_peak_bytes": base["peak_bytes"],
        "head_peak_bytes": head["peak_bytes"],
        "base_bytes_per_prefix": base["bytes_per_prefix"],
        "head_bytes_per_prefix": head["bytes_per_prefix"],
        "base_route_capacity": (
            base["adj_in_capacity"] + base["loc_capacity"] + base["adj_out_capacity"]
        ),
        "head_route_capacity": (
            head["adj_in_capacity"] + head["loc_capacity"] + head["adj_out_capacity"]
        ),
        "base_prefix_index_entries": (
            base["adj_in_prefix_index_entries"]
            + base["adj_out_prefix_index_entries"]
        ),
        "head_prefix_index_entries": (
            head["adj_in_prefix_index_entries"]
            + head["adj_out_prefix_index_entries"]
        ),
        "review": review,
    })

fieldnames = [
    "shape",
    "prefixes",
    "base_live_bytes",
    "head_live_bytes",
    "delta_pct",
    "delta_mib",
    "base_peak_bytes",
    "head_peak_bytes",
    "base_bytes_per_prefix",
    "head_bytes_per_prefix",
    "base_route_capacity",
    "head_route_capacity",
    "base_prefix_index_entries",
    "head_prefix_index_entries",
    "review",
]
with RESULTS_FILE.open("w", newline="") as fh:
    writer = csv.DictWriter(fh, fieldnames=fieldnames)
    writer.writeheader()
    writer.writerows(csv_rows)

lines = [
    "# RIB Memory Compare Summary",
    "",
    f"- Run: `{os.environ['RUN_ID']}`",
    f"- Profile: `{os.environ['PROFILE']}`",
    f"- Base: `{os.environ['BASE_SHORT']}` (`{os.environ['BASE_SHA']}`)",
    f"- Head: `{os.environ['HEAD_SHORT']}` (`{os.environ['HEAD_SHA']}`)",
    f"- Metadata: `{os.environ['METADATA_FILE']}`",
    f"- Results CSV: `{RESULTS_FILE}`",
    "",
    "| Shape | Prefixes | Base live | Head live | Delta | Base b/pfx | Head b/pfx | Route capacity | Review |",
    "|---|---:|---:|---:|---:|---:|---:|---:|---|",
]

for row in csv_rows:
    base = base_rows.get((row["shape"], row["prefixes"]))
    head = head_rows.get((row["shape"], row["prefixes"]))
    if base is None or head is None:
        lines.append(
            f"| `{row['shape']}` | {row['prefixes']} | "
            f"{row['base_live_bytes'] or 'n/a'} | {row['head_live_bytes'] or 'n/a'} | "
            "n/a | n/a | n/a | n/a | missing-row |"
        )
        continue
    delta = int(head["live_bytes"]) - int(base["live_bytes"])
    pct = delta_pct(int(base["live_bytes"]), int(head["live_bytes"]))
    route_capacity = (
        f"{row['base_route_capacity']} -> {row['head_route_capacity']}"
    )
    lines.append(
        f"| `{row['shape']}` | {row['prefixes']} | "
        f"{fmt_bytes(int(base['live_bytes']))} | {fmt_bytes(int(head['live_bytes']))} | "
        f"{fmt_bytes(delta)} ({pct:+.2f}%) | "
        f"{base['bytes_per_prefix']} | {head['bytes_per_prefix']} | "
        f"{route_capacity} | {row['review']} |"
    )

lines.extend([
    "",
    "Review rule: `review` means head grew by at least +5% and +32 MiB for the same shape/size. Smaller movement is reported but treated as allocator/map-capacity noise unless the PR is explicitly memory-targeted.",
])

SUMMARY_FILE.write_text("\n".join(lines) + "\n")
print(SUMMARY_FILE.read_text())
PY

echo "Summary written to ${summary_file}"
echo "CSV written to ${results_file}"
echo "Logs written to ${log_dir}"
