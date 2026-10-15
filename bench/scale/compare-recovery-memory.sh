#!/usr/bin/env bash
# Hosted memory receipt, or explicitly selected same-runtime component scans.
# Memory uses fixed c862/bdb controls and has no RSS fallback/timing verdict;
# component timing never qualifies daemon memory, delivery or activation.
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=/dev/null
source "$script_dir/cgroup-memory.sh"
# shellcheck source=/dev/null
source "$script_dir/provenance.sh"
checker=$script_dir/recovery_memory.py
driver=$script_dir/compare-recovery-memory.sh
baseline=c862af9338aa828b7462f3cf85781f63b0e79fe8
intermediate=bdb7bc34dfe0e6a66fc8c0f1d56d3e57184dea00

fail() { echo "recovery-memory: $*" >&2; exit 1; }

# These are scoped child commands, never a fallback to the caller's cgroup.
if [[ ${1:-} == --scope-worker || ${1:-} == --scope-probe || ${1:-} == --scope-scan || ${1:-} == --scope-retirement ]]; then
    mode=$1
    shift
    cgroup=$(daemon_scope_cgroup "$$") || fail 'scope membership or swap fence unavailable'
    if [[ $mode == --scope-probe ]]; then
        [[ $# == 1 ]] || fail 'invalid scope probe arguments'
        python3 "$checker" scope-snapshot "$cgroup" "$1/raw"
        record_scope_peak "$cgroup" "$1/compatibility-peak.txt"
    else
        [[ $# == 6 || ( $mode == --scope-scan && $# == 7 && ${7:-} == --shuffled-old ) ]] || fail 'invalid scope worker arguments'
        status=0
        scan_option=()
        [[ $mode != --scope-scan ]] || scan_option=(--scan)
        [[ $mode != --scope-retirement ]] || scan_option=(--retirement)
        [[ $# != 7 ]] || scan_option+=(--shuffled-old)
        python3 "$checker" run-scope "$1" "$2" "$3" "$cgroup" "$4" "$5" "$6" "${scan_option[@]}" || status=$?
        record_scope_peak "$cgroup" "$2/compatibility-peak.txt" || status=1
        exit "$status"
    fi
    exit 0
fi

[[ $# -ge 4 && $1 == --head && $3 == --output-dir ]] ||
    fail 'usage: compare-recovery-memory.sh --head FULL_SHA --output-dir NEW_DIR [--mode memory|scan] [--shuffled-old] [--phase pilot|qualified] [--profile PROFILE] [--cell all|dataset-reevaluate|peer-down|widen|unsynchronized-dirty]'
head=$2
output=$4
shift 4
phase=pilot
receipt_mode=memory
profile=all
selected_cell=all
old_order=sorted
scan_options=()
while [[ $# -gt 0 ]]; do
    if [[ $1 == --shuffled-old ]]; then
        old_order=shuffled
        scan_options=(--shuffled-old)
        shift
        continue
    fi
    [[ $# -ge 2 ]] || fail 'missing selector value'
    case $1 in --mode) receipt_mode=$2 ;; --phase) phase=$2 ;; --profile) profile=$2 ;; --cell) selected_cell=$2 ;; *) fail 'unknown selector' ;; esac
    shift 2
done
[[ $phase == pilot || $phase == qualified ]] || fail 'invalid campaign phase'
[[ $receipt_mode == memory || $receipt_mode == scan || $receipt_mode == retirement ]] || fail 'invalid receipt mode'
if [[ $receipt_mode == retirement ]]; then
    [[ $phase == qualified && ( $profile == full-uc || $profile == full-vpn ) && $selected_cell == retirement && $old_order == sorted ]] || fail 'invalid retirement selection'
elif [[ $receipt_mode == scan ]]; then
    [[ $phase == qualified && ( $profile == full-uc || $profile == full-vpn || $profile == evpn-soak ) && $selected_cell == capture-scan ]] || fail 'invalid component scan selection'
else
    [[ $old_order == sorted ]] || fail 'shuffled OLD is only valid for component scans'
    [[ $profile == all || $profile == ipv4-100k || $profile == full-uc || $profile == full-vpn || $profile == mixed-widen ]] || fail 'invalid campaign profile'
    [[ $selected_cell == all || $selected_cell == dataset-reevaluate || $selected_cell == peer-down || $selected_cell == widen || $selected_cell == unsynchronized-dirty ]] || fail 'invalid campaign cell'
fi
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
git -C "$repository" cat-file -e "$intermediate^{commit}"
work_root=$(mktemp -d "$RUNNER_TEMP/recovery-memory-work.XXXXXXXX")
finish() {
    local status=$?
    trap - EXIT
    printf '%s\n' "$status" > "$output/driver.exit"
    awk '$1 == "oom_kill" { print $2 }' /proc/vmstat > "$output/host-oom.after" || true
    for role in baseline intermediate candidate; do
        if [[ -d $work_root/$role ]]; then
            git -C "$repository" worktree remove --force "$work_root/$role" || true
        fi
    done
    # Only this invocation's fresh worktrees and separate build targets.
    rm -rf -- "$work_root"
    exit "$status"
}
finish_retirement() {
    local status=$? candidate_status=0 old_status=0 remove_status=0
    trap - EXIT
    awk '$1 == "oom_kill" { print $2 }' /proc/vmstat > "$output/host-oom.after" || { [[ $status != 0 ]] || status=1; }
    if [[ $status == 0 ]]; then
        git -C "$repository" worktree remove --force "$work_root/candidate" || candidate_status=$?
        git -C "$repository" worktree remove --force "$work_root/old-drop" || old_status=$?
        if [[ $candidate_status == 0 && $old_status == 0 ]]; then
            rm -rf -- "$work_root" || remove_status=$?
        fi
        printf '{"candidate_worktree_exit":%s,"old_drop_worktree_exit":%s,"scratch_remove_exit":%s}\n' \
            "$candidate_status" "$old_status" "$remove_status" > "$output/cleanup-proof.json"
        if [[ $candidate_status != 0 || $old_status != 0 || $remove_status != 0 ]]; then status=1; fi
    fi
    [[ $status == 0 ]] || printf '%s\n' "$work_root" > "$output/scratch-retained.txt"
    printf '%s\n' "$status" > "$output/driver.exit"
    if [[ $status == 0 ]]; then
        python3 "$checker" summarize-retirement "$output" || status=$?
        printf '%s\n' "$status" > "$output/driver.exit"
    fi
    exit "$status"
}
trap finish EXIT
printf '%s\n' "$baseline" > "$output/baseline.sha"
printf '%s\n' "$intermediate" > "$output/intermediate.sha"
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
    local limits=(-p MemorySwapMax=0)
    [[ $receipt_mode != retirement ]] || limits+=(-p MemoryMax=12884901888)
    record_command sudo systemd-run --scope --quiet --unit="$unit" "${limits[@]}" -- "$@"
    sudo systemd-run --scope --quiet --unit="$unit" "${limits[@]}" -- "$@"
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
[[ $receipt_mode != scan ]] || inputs+=(bench/scale/rrharness/src/recovery_scan.rs)
[[ $receipt_mode != retirement ]] || inputs+=(
    bench/scale/rrharness/src/recovery_retirement.rs
    crates/rib/src/manager/bench_support.rs crates/rib/src/manager/distribution/vpn.rs
    crates/rib/src/manager/peer_lifecycle.rs)
mkdir "$output/frozen-instrumentation"
for path in "${inputs[@]}"; do
    mkdir -p -- "$output/frozen-instrumentation/$(dirname -- "$path")"
    cp -- "$repository/$path" "$output/frozen-instrumentation/$path"
    if [[ $receipt_mode == memory && $path == bench/scale/rrharness/src/main.rs ]]; then
        # Historical controls lack the component-only RIB API. Freeze the
        # identical memory entrypoint for every role, without porting runtime.
        python3 "$checker" normalize-memory-entrypoint "$output/frozen-instrumentation/$path" "$output/memory-entrypoint-derivation.json"
    fi
    printf '%s  %s\n' "$(provenance_sha256_file "$output/frozen-instrumentation/$path")" "$path" >> "$output/instrumentation.sha256"
done
instrumentation=$(provenance_sha256_file "$output/instrumentation.sha256")
if [[ $receipt_mode == retirement ]]; then
    # Timing uses the same current runtime in both arms, never historical controls.
    trap finish_retirement EXIT
    python3 - <<'PYCODE' > "$output/retirement-preflight.json"
import json
from pathlib import Path
available = int(next(line.split()[1] for line in Path("/proc/meminfo").read_text().splitlines()
                     if line.startswith("MemAvailable:"))) * 1024
required = 12 * 1024**3
print(json.dumps({"available_bytes": available, "minimum_bytes": required,
                  "memory_max": required, "swap_max": 0}))
if available < required:
    raise SystemExit("retirement shape requires at least 12 GiB available; refusing to resize")
PYCODE
    python3 "$checker" snapshot-build-inputs "$repository" "$output/committed-inputs.json"
    python3 - "$output/manifest.json" "$head" "$instrumentation" "$profile" <<'PYCODE'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps({
    "schema": "rustbgpd.retirement-timing.campaign.v1", "candidate": sys.argv[2],
    "instrumentation_manifest_sha256": sys.argv[3], "profile": sys.argv[4],
    "cells": ["retirement-empty", "retirement-full"],
    "order": ["old-drop", "candidate", "candidate", "old-drop"],
    "memory_max": 12 * 1024**3, "build_jobs": 4,
    "scope": "component attribution only; no daemon/fleet/readiness qualification or timing pass bar",
}, indent=2, sort_keys=True) + "\n")
PYCODE
    mkdir "$output/bin"
    for role in candidate old-drop; do
        tree=$work_root/$role
        git -C "$repository" worktree add --detach "$tree" "$head" > "$output/$role-worktree.log" 2>&1
        if [[ $role == old-drop ]]; then
            python3 "$checker" derive-retirement-control "$tree/crates/rib/src/manager/distribution/vpn.rs"
            cp -- "$tree/crates/rib/src/manager/distribution/vpn.rs" "$output/old-drop-source.rs"
        fi
        git -C "$tree" diff --binary > "$output/$role-source.patch"
        python3 "$checker" snapshot-build-inputs "$tree" "$output/$role-inputs.json"
        record_command env CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$work_root/target-$role" \
            RRHARNESS_RECOVERY_SOURCE_SHA="$head" RRHARNESS_RECOVERY_INSTRUMENTATION_SHA256="$instrumentation" \
            cargo build --profile scale --locked -p rrharness --features rustbgpd-rib/bench-internals -j 4
        status=0
        (cd -- "$tree" && CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$work_root/target-$role" \
            RRHARNESS_RECOVERY_SOURCE_SHA="$head" RRHARNESS_RECOVERY_INSTRUMENTATION_SHA256="$instrumentation" \
            cargo build --profile scale --locked -p rrharness --features rustbgpd-rib/bench-internals -j 4) \
            > "$output/$role-build.log" 2>&1 || status=$?
        printf '%s\n' "$status" > "$output/$role-build.exit"
        [[ $status == 0 ]] || fail "$role retirement build failed"
        python3 "$checker" snapshot-build-inputs "$tree" "$output/$role-inputs-after.json"
        cmp "$output/$role-inputs.json" "$output/$role-inputs-after.json" || fail 'retirement build inputs changed'
        cp -- "$work_root/target-$role/scale/rrharness" "$output/bin/$role"
        provenance_sha256_file "$output/bin/$role" > "$output/$role-binary.sha256"
    done
    ordinal=0
    for cell in retirement-empty retirement-full; do
        leg=0
        for role in old-drop candidate candidate old-drop; do
            directory=$output/$cell-$leg-$role
            mkdir "$directory"
            status=0
            launch_scope "recovery-retirement-$$-$ordinal.scope" env GITHUB_ACTIONS="$GITHUB_ACTIONS" \
                RECOVERY_MEMORY_RUNNER_ENVIRONMENT="${RECOVERY_MEMORY_RUNNER_ENVIRONMENT:-${RUNNER_ENVIRONMENT:-}}" \
                bash "$driver" --scope-retirement "$output/bin/$role" "$directory" "$cell" \
                "$(cat "$output/$role-binary.sha256")" "$profile" 1 \
                > "$directory/launcher.log" 2>&1 || status=$?
            printf '%s\n' "$status" > "$directory/launcher.exit"
            python3 "$checker" seal-retirement-raw "$directory"
            [[ $status == 0 ]] || fail 'retirement actor cell failed'
            leg=$((leg + 1))
            ordinal=$((ordinal + 1))
        done
    done
    exit 0
fi
if [[ $receipt_mode == scan ]]; then
    python3 - "$output/manifest.json" "$head" "$instrumentation" "$profile" "$old_order" <<'PYCODE'
import json
from pathlib import Path
import sys
Path(sys.argv[1]).write_text(json.dumps({
    "schema": "rustbgpd.recovery-scan.campaign.v3", "candidate": sys.argv[2],
    "instrumentation_manifest_sha256": sys.argv[3], "profile": sys.argv[4],
    "old_order": sys.argv[5],
    "build_jobs": 4, "order_per_cell": ["flat", "candidate", "candidate", "flat"],
    "scope": "component capture only; same runtime, no activation or daemon claim",
}, indent=2, sort_keys=True) + "\n")
PYCODE
    tree=$work_root/candidate
    git -C "$repository" worktree add --detach "$tree" "$head" > "$output/candidate-worktree.log" 2>&1
    for path in Cargo.toml Cargo.lock bench/scale/rrharness/Cargo.toml; do
        printf '%s  %s\n' "$(provenance_sha256_file "$tree/$path")" "$path" >> "$output/candidate-build-inputs.sha256"
    done
    record_command env CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$work_root/target-candidate" RRHARNESS_RECOVERY_SOURCE_SHA="$head" RRHARNESS_RECOVERY_INSTRUMENTATION_SHA256="$instrumentation" cargo build --profile scale --locked -p rrharness --features rustbgpd-rib/bench-internals -j 4
    status=0
    (cd -- "$tree" && CARGO_BUILD_JOBS=4 CARGO_TARGET_DIR="$work_root/target-candidate" \
        RRHARNESS_RECOVERY_SOURCE_SHA="$head" RRHARNESS_RECOVERY_INSTRUMENTATION_SHA256="$instrumentation" \
        cargo build --profile scale --locked -p rrharness --features rustbgpd-rib/bench-internals -j 4) \
        > "$output/candidate-build.log" 2>&1 || status=$?
    printf '%s\n' "$status" > "$output/candidate-build.exit"
    [[ $status == 0 ]] || fail 'component scan build failed'
    provenance_sha256_file "$work_root/target-candidate/scale/rrharness" > "$output/candidate-binary.sha256"
    mkdir "$output/scan"
    status=0
    launch_scope "recovery-scan-$$.scope" env GITHUB_ACTIONS="$GITHUB_ACTIONS" \
        RECOVERY_MEMORY_RUNNER_ENVIRONMENT="${RECOVERY_MEMORY_RUNNER_ENVIRONMENT:-${RUNNER_ENVIRONMENT:-}}" \
        bash "$driver" --scope-scan \
        "$work_root/target-candidate/scale/rrharness" "$output/scan" capture-scan \
        "$(cat "$output/candidate-binary.sha256")" "$profile" 1 "${scan_options[@]}" \
        > "$output/scan/launcher.log" 2>&1 || status=$?
    printf '%s\n' "$status" > "$output/scan/launcher.exit"
    awk '$1 == "oom_kill" { print $2 }' /proc/vmstat > "$output/host-oom.after"
    python3 "$checker" summarize-scan "$output"
    exit 0
fi
python3 - "$output/manifest.json" "$baseline" "$intermediate" "$head" "$instrumentation" "$phase" "$profile" "$checker" "$selected_cell" <<'PYCODE'
import importlib.util
import json
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location("receipt", sys.argv[8])
receipt = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receipt)
profiles = None if sys.argv[7] == "all" else [sys.argv[7]]
cases = receipt.campaign_cases(sys.argv[6], profiles, sys.argv[9])
derivation = Path(sys.argv[1]).parent / "memory-entrypoint-derivation.json"
profiles = list(dict.fromkeys(case["profile"] for case in cases))
Path(sys.argv[1]).write_text(json.dumps({
    "schema": "rustbgpd.recovery-memory.campaign.v2",
    "memory_entrypoint_derivation_sha256": receipt.hashlib.sha256(derivation.read_bytes()).hexdigest(),
    "baseline": sys.argv[2], "intermediate": sys.argv[3], "candidate": sys.argv[4],
    "instrumentation_manifest_sha256": sys.argv[5], "phase": sys.argv[6],
    "profiles": profiles, "selected_cell": sys.argv[9], "cases": cases, "build_jobs": 4,
    "comparators": ["baseline", "intermediate"],
    "order_per_cell": ["control", "candidate", "candidate", "control"],
    "scope": "manager-direct RIB and production exact-export preflight; no final wire/TCP",
}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PYCODE
for role in baseline intermediate candidate; do
    revision=$head
    [[ $role != baseline ]] || revision=$baseline
    [[ $role != intermediate ]] || revision=$intermediate
    tree=$work_root/$role
    record_command git worktree add --detach "$tree" "$revision"
    git -C "$repository" worktree add --detach "$tree" "$revision" > "$output/$role-worktree.log" 2>&1
    # Preserve each source's manifests, dependency pins and lockfile. The
    # harness manifest must already agree before freezing only its source.
    cmp "$repository/bench/scale/rrharness/Cargo.toml" "$tree/bench/scale/rrharness/Cargo.toml" ||
        fail 'harness manifest drift would confound the frozen instrumentation'
    for path in bench/scale/rrharness/src/main.rs bench/scale/rrharness/src/recovery_memory.rs; do
        cp -- "$output/frozen-instrumentation/$path" "$tree/$path"
        provenance_require_sha256 "$tree/$path" "$(provenance_sha256_file "$output/frozen-instrumentation/$path")"
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
free -b > "$output/host-memory.post-build.txt"
python3 - "$output/manifest.json" > "$output/cases.tsv" <<'PYCODE'
import json
import sys
for case in json.load(open(sys.argv[1]))["cases"]:
    print(case["profile"], case["cell"], case["clients"], sep="\t")
PYCODE
ordinal=0
while IFS=$'\t' read -r selected cell clients; do
    for comparator in baseline intermediate; do
        leg=0
        for role in "$comparator" candidate candidate "$comparator"; do
            leg=$((leg + 1))
            ordinal=$((ordinal + 1))
            directory=$output/$selected-$cell-$comparator-$leg-$role
            mkdir "$directory"
            free -b > "$directory/host-memory.before.txt"
            status=0
            launch_scope "recovery-memory-$$-$ordinal.scope" bash "$driver" --scope-worker \
                "$work_root/target-$role/scale/rrharness" "$directory" "$cell" "$(cat "$output/$role-binary.sha256")" "$selected" "$clients" \
                > "$directory/launcher.log" 2>&1 || status=$?
            printf '%s\n' "$status" > "$directory/launcher.exit"
            # Continue every matched leg, including historical contract failures.
            # The final checker fails any invalid candidate while retaining all raw evidence.
        done
    done
done < "$output/cases.tsv"
awk '$1 == "oom_kill" { print $2 }' /proc/vmstat > "$output/host-oom.after"
[[ $(cat "$output/host-oom.before") == "$(cat "$output/host-oom.after")" ]] || fail 'host OOM invalidates the campaign'
python3 "$checker" summarize "$output"
