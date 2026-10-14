#!/usr/bin/env bash
# Hosted-only memory receipt: fixed c862 baseline, exact candidate, A/B/B/A
# in fresh swap-fenced cgroup v2 scopes. No RSS fallback or timing verdict.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "$script_dir/cgroup-memory.sh"
# shellcheck source=/dev/null
source "$script_dir/provenance.sh"
checker=$script_dir/recovery_memory.py
driver=$script_dir/compare-recovery-memory.sh
baseline=c862af9338aa828b7462f3cf85781f63b0e79fe8

fail() { echo "recovery-memory: $*" >&2; exit 1; }

# These are scoped child commands, never a fallback to the caller's cgroup.
if [[ ${1:-} == --scope-worker || ${1:-} == --scope-probe ]]; then
    mode=$1
    shift
    cgroup=$(daemon_scope_cgroup "$$") || fail 'scope membership or swap fence unavailable'
    if [[ $mode == --scope-probe ]]; then
        [[ $# == 1 ]] || fail 'invalid scope probe arguments'
        python3 "$checker" scope-snapshot "$cgroup" "$1/raw"
        record_scope_peak "$cgroup" "$1/compatibility-peak.txt"
    else
        [[ $# == 4 ]] || fail 'invalid scope worker arguments'
        status=0
        python3 "$checker" run-scope "$1" "$2" "$3" "$cgroup" "$4" || status=$?
        record_scope_peak "$cgroup" "$2/compatibility-peak.txt" || status=1
        exit "$status"
    fi
    exit 0
fi

[[ $# == 4 && $1 == --head && $3 == --output-dir ]] ||
    fail 'usage: compare-recovery-memory.sh --head FULL_SHA --output-dir NEW_DIR'
head=$2
output=$4
[[ $head =~ ^[0-9a-f]{40}$ ]] || fail 'head must be an exact source SHA'
[[ ${GITHUB_ACTIONS:-} == true && ${RECOVERY_MEMORY_RUNNER_ENVIRONMENT:-${RUNNER_ENVIRONMENT:-}} == github-hosted && ${RUNNER_OS:-} == Linux ]] ||
    fail 'this receipt requires a fresh GitHub-hosted Linux VM; do not measure on the dev or soak host'
[[ -n ${RUNNER_TEMP:-} && -d $RUNNER_TEMP ]] || fail 'RUNNER_TEMP unavailable'
[[ ! -e $output ]] || fail 'output directory must be new'
mkdir -p -- "$output"
output=$(cd -- "$output" && pwd)
repository=$(git -C "$script_dir" rev-parse --show-toplevel)
[[ $(git -C "$repository" rev-parse HEAD) == "$head" ]] || fail 'checked-out source does not match head'
[[ -z $(git -C "$repository" status --porcelain --untracked-files=normal) ]] ||
    fail 'receipt instrumentation and candidate must be committed and clean'
git -C "$repository" cat-file -e "$baseline^{commit}"
work_root=$(mktemp -d "$RUNNER_TEMP/recovery-memory-work.XXXXXXXX")
finish() {
    local status=$?
    trap - EXIT
    printf '%s\n' "$status" > "$output/driver.exit"
    awk '$1 == "oom_kill" { print $2 }' /proc/vmstat > "$output/host-oom.after" || true
    for role in baseline candidate; do
        if [[ -d $work_root/$role ]]; then
            git -C "$repository" worktree remove --force "$work_root/$role" || true
        fi
    done
    # Only this invocation's fresh worktrees and separate build targets.
    rm -rf -- "$work_root"
    exit "$status"
}
trap finish EXIT
printf '%s\n' "$baseline" > "$output/baseline.sha"
printf '%s\n' "$head" > "$output/candidate.sha"
uname -a > "$output/kernel.txt"
rustc -Vv > "$output/rustc.txt"
cargo -V > "$output/cargo.txt"
cat /etc/os-release > "$output/os-release.txt"
lscpu > "$output/lscpu.txt"
free -b > "$output/host-memory.txt"
awk '$1 == "oom_kill" { print $2 }' /proc/vmstat > "$output/host-oom.before"
[[ $(cat "$output/host-oom.before") =~ ^[0-9]+$ ]] || fail 'host OOM observer unavailable'
record_command() { printf '%q ' "$@" >> "$output/commands.txt"; printf '\n' >> "$output/commands.txt"; }
launch_scope() {
    local unit=$1
    shift
    record_command sudo systemd-run --scope --quiet --unit="$unit" -p MemorySwapMax=0 -- "$@"
    sudo systemd-run --scope --quiet --unit="$unit" -p MemorySwapMax=0 -- "$@"
}
# Probe actual scope capabilities before paying for either build.
mkdir "$output/probe"
status=0
launch_scope "recovery-memory-probe-$$.scope" bash "$driver" --scope-probe "$output/probe" > "$output/probe/launcher.log" 2>&1 || status=$?
printf '%s\n' "$status" > "$output/probe/launcher.exit"
[[ $status == 0 ]] || fail 'required cgroup capability probe failed; retain its raw files and log'

inputs=(bench/scale/rrharness/src/main.rs bench/scale/rrharness/src/recovery_memory.rs
    bench/scale/rrharness/Cargo.toml bench/scale/compare-recovery-memory.sh
    bench/scale/recovery_memory.py bench/scale/cgroup-memory.sh bench/scale/provenance.sh)
mkdir "$output/frozen-instrumentation"
for path in "${inputs[@]}"; do
    mkdir -p -- "$output/frozen-instrumentation/$(dirname -- "$path")"
    cp -- "$repository/$path" "$output/frozen-instrumentation/$path"
    printf '%s  %s\n' "$(provenance_sha256_file "$repository/$path")" "$path" >> "$output/instrumentation.sha256"
done
instrumentation=$(provenance_sha256_file "$output/instrumentation.sha256")
python3 - "$output/manifest.json" "$baseline" "$head" "$instrumentation" <<'PY'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps({
    "schema": "rustbgpd.recovery-memory.campaign.v1",
    "baseline": sys.argv[2], "candidate": sys.argv[3],
    "instrumentation_manifest_sha256": sys.argv[4],
    "clients": 256, "prefixes": 100000, "build_jobs": 4,
    "cells": ["dataset-reevaluate", "peer-down"],
    "order_per_cell": ["baseline", "candidate", "candidate", "baseline"],
    "scope": "manager-direct RIB and production exact-export preflight; no TCP/session output",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
for role in baseline candidate; do
    revision=$head
    [[ $role != baseline ]] || revision=$baseline
    tree=$work_root/$role
    record_command git worktree add --detach "$tree" "$revision"
    git -C "$repository" worktree add --detach "$tree" "$revision" > "$output/$role-worktree.log" 2>&1
    # Preserve each source's manifests, dependency pins and lockfile. The
    # harness manifest must already agree before freezing only its source.
    cmp "$repository/bench/scale/rrharness/Cargo.toml" "$tree/bench/scale/rrharness/Cargo.toml" ||
        fail 'harness manifest drift would confound the frozen instrumentation'
    for path in bench/scale/rrharness/src/main.rs bench/scale/rrharness/src/recovery_memory.rs; do
        cp -- "$output/frozen-instrumentation/$path" "$tree/$path"
        provenance_require_sha256 "$tree/$path" "$(provenance_sha256_file "$repository/$path")"
    done
    record_command python3 "$checker" instrument-observer "$tree"
    python3 "$checker" instrument-observer "$tree"
    git -C "$tree" diff --binary > "$output/$role-instrumentation.patch"
    git -C "$tree" diff --binary -- crates/rib/src/update.rs crates/rib/src/manager/mod.rs > "$output/$role-observer.patch"
    for path in Cargo.toml Cargo.lock bench/scale/rrharness/Cargo.toml; do
        printf '%s  %s\n' "$(provenance_sha256_file "$tree/$path")" "$path" >> "$output/$role-build-inputs.sha256"
    done
    record_command env CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$work_root/target-$role" RRHARNESS_RECOVERY_SOURCE_SHA="$revision" RRHARNESS_RECOVERY_INSTRUMENTATION_SHA256="$instrumentation" cargo build --profile scale --locked -p rrharness --features rustbgpd-rib/bench-internals -j 4
    status=0
    (cd -- "$tree" && CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$work_root/target-$role" \
        RRHARNESS_RECOVERY_SOURCE_SHA="$revision" RRHARNESS_RECOVERY_INSTRUMENTATION_SHA256="$instrumentation" \
        cargo build --profile scale --locked -p rrharness --features rustbgpd-rib/bench-internals -j 4) \
        > "$output/$role-build.log" 2>&1 || status=$?
    printf '%s\n' "$status" > "$output/$role-build.exit"
    [[ $status == 0 ]] || fail "$role build failed; retain its log"
    provenance_sha256_file "$work_root/target-$role/scale/rrharness" > "$output/$role-binary.sha256"
done
for cell in dataset-reevaluate peer-down; do
    leg=0
    for role in baseline candidate candidate baseline; do
        leg=$((leg + 1))
        directory=$output/$cell-$leg-$role
        mkdir "$directory"
        status=0
        launch_scope "recovery-memory-$$-$cell-$leg.scope" bash "$driver" --scope-worker \
            "$work_root/target-$role/scale/rrharness" "$directory" "$cell" "$(cat "$output/$role-binary.sha256")" \
            > "$directory/launcher.log" 2>&1 || status=$?
        printf '%s\n' "$status" > "$directory/launcher.exit"
        [[ $status == 0 ]] || fail "$cell leg $leg failed; retain all artifacts"
    done
done
awk '$1 == "oom_kill" { print $2 }' /proc/vmstat > "$output/host-oom.after"
[[ $(cat "$output/host-oom.before") == "$(cat "$output/host-oom.after")" ]] || fail 'host OOM invalidates the campaign'
python3 "$checker" summarize "$output"
