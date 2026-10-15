#!/usr/bin/env bash
# Fresh-hosted, exact-source actual-daemon shared/flat recovery qualification.
set -euo pipefail
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS
here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository=$(git -C "$here" rev-parse --show-toplevel)
checker=$here/recovery_mass_dirty.py
head='' output='' profile='' cohort='' daemon_cpus='' harness_cpus=''
correctness=()
while [[ $# -gt 0 ]]; do
    if [[ $1 == --correctness-only ]]; then
        correctness=(--correctness-only)
        shift
        continue
    fi
    [[ $# -ge 2 ]] || { echo 'missing flag value' >&2; exit 1; }
    case $1 in
        --head) head=$2 ;; --output-dir) output=$2 ;; --profile) profile=$2 ;;
        --cohort) cohort=$2 ;; --daemon-cpus) daemon_cpus=$2 ;; --harness-cpus) harness_cpus=$2 ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
    shift 2
done
[[ $head =~ ^[0-9a-f]{40}$ && -n $output && ( $profile == full-uc || $profile == full-vpn ) && ( $cohort == no-refusal || $cohort == cap-pressure ) ]] || {
    echo 'usage: run-recovery-mass-dirty.sh --head SHA --output-dir NEW_DIR --profile full-uc|full-vpn --cohort no-refusal|cap-pressure [--daemon-cpus LIST --harness-cpus LIST] [--correctness-only]' >&2
    exit 1
}
if [[ ${#correctness[@]} == 0 ]]; then
    [[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted && ${RUNNER_OS:-} == Linux ]] || {
        echo 'measurements require a fresh GitHub-hosted Linux runner' >&2; exit 1;
    }
fi
[[ $(git -C "$repository" rev-parse HEAD) == "$head" ]] || { echo 'source SHA mismatch' >&2; exit 1; }
[[ -z $(git -C "$repository" status --porcelain --untracked-files=normal) ]] || { echo 'source/instrument must be committed and clean' >&2; exit 1; }
[[ ! -e $output ]] || { echo 'output must be new' >&2; exit 1; }
if [[ -z $daemon_cpus && -z $harness_cpus ]]; then
    read -r daemon_cpus harness_cpus < <(python3 - <<'PY'
import os
cpus = sorted(os.sched_getaffinity(0))
assert len(cpus) >= 3, 'at least three CPUs required'
split = max(1, len(cpus) // 2)
print(','.join(map(str, cpus[:split])), ','.join(map(str, cpus[split:])))
PY
)
fi
# shellcheck source=tests/soak/host-lock.sh
source "$repository/tests/soak/host-lock.sh"
acquire_rustbgpd_host_lock
# shellcheck source=bench/scale/provenance.sh
source "$repository/bench/scale/provenance.sh"
python3 "$checker" init "$output" --head "$head" --profile "$profile" --cohort "$cohort" \
    --daemon-cpus "$daemon_cpus" --harness-cpus "$harness_cpus" "${correctness[@]}"
output=$(realpath -- "$output")
scratch=$(mktemp -d "${RUNNER_TEMP:-/tmp}/recovery-mass-dirty-build.XXXXXXXX")
active_controller='' active_starttime=''
controller_starttime() {
    python3 - "$1" <<'PY'
from pathlib import Path
import sys
print(Path(f'/proc/{int(sys.argv[1])}/stat').read_text().rsplit(')', 1)[1].split()[19])
PY
}
finish() {
    local status=$? cleanup_status
    trap - EXIT INT TERM
    if [[ -n $active_controller ]]; then
        local current
        current=$(controller_starttime "$active_controller" 2>/dev/null || true)
        if [[ $current == "$active_starttime" && $active_controller =~ ^[1-9][0-9]*$ ]]; then
            kill -TERM "$active_controller" 2>/dev/null || true
        elif [[ -n $current ]]; then
            printf 'held controller PID identity changed\n' >"$output/cleanup-error.txt"
            [[ $status != 0 ]] || status=1
        fi
        wait "$active_controller" || true
    fi
    if [[ $status == 0 ]]; then
        for role in candidate flat; do
            if [[ -d $scratch/$role ]]; then
                if git -C "$repository" worktree remove --force "$scratch/$role"; then
                    :
                else
                    cleanup_status=$?
                    [[ $status != 0 ]] || status=$cleanup_status
                    printf 'failed to remove %s worktree (exit %s)\n' "$role" "$cleanup_status" >>"$output/cleanup-error.txt"
                fi
            fi
        done
        if [[ $status == 0 ]]; then
            if rm -rf -- "$scratch"; then
                :
            else
                status=$?
                printf 'failed to remove scratch directory (exit %s)\n' "$status" >>"$output/cleanup-error.txt"
            fi
        fi
    fi
    if [[ $status != 0 ]]; then
        # A failed/aborted build or cleanup may still own work. Preserve its
        # exact scratch paths for inspection rather than removing live inputs.
        printf '%s\n' "$scratch" >"$output/scratch-retained.txt"
    fi
    printf '%s\n' "$status" >"$output/driver.exit"
    exit "$status"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
mkdir -p "$output/bin" "$output/frozen-instrumentation"
printf '%s\n' "$head" >"$output/candidate.sha"
for path in src/main.rs src/recovery_mass_dirty.rs recovery_mass_dirty.py test_recovery_mass_dirty.py run-recovery-mass-dirty.sh README.md; do
    mkdir -p "$output/frozen-instrumentation/$(dirname "$path")"
    cp -- "$here/$path" "$output/frozen-instrumentation/$path"
done
for path in bench/scale/reloadstall/sample-daemon-cgroup.py bench/scale/provenance.sh bench/scale/cgroup-memory.sh tests/soak/host-lock.sh; do
    mkdir -p "$output/frozen-support/$(dirname "$path")"
    cp -- "$repository/$path" "$output/frozen-support/$path"
done
for role in candidate flat; do
    git -C "$repository" worktree add --detach "$scratch/$role" "$head"
done
cp -- "$scratch/candidate/crates/rib/src/manager/update_groups.rs" "$output/capture-source.rs"
python3 "$checker" derive-flat "$scratch/flat/crates/rib/src/manager/update_groups.rs" "$output/derivation.json"
cp -- "$scratch/flat/crates/rib/src/manager/update_groups.rs" "$output/flat-control-source.rs"
git -C "$scratch/flat" diff --binary >"$output/flat-control.patch"
rustc -Vv >"$output/rustc-version.txt"
cargo --version >"$output/cargo-version.txt"
jobs=${CARGO_BUILD_JOBS:-2}
[[ $jobs =~ ^[1-4]$ ]] || { echo 'build jobs must be 1..=4' >&2; exit 1; }
for role in candidate flat; do
    # Source worktrees must not reuse a role's cached RIB fingerprint. The
    # off-source mutation predates both builds, so one shared target is unsafe.
    target=$scratch/target-$role
    if (
        cd "$scratch/$role" || exit
        printf 'CARGO_BUILD_JOBS=%s CARGO_TARGET_DIR=%q cargo build --release --locked --bin rustbgpd\n' "$jobs" "$target"
        CARGO_BUILD_JOBS=$jobs CARGO_TARGET_DIR=$target cargo build --release --locked --bin rustbgpd
    ) >"$output/build-$role.log" 2>&1; then build_exit=0; else build_exit=$?; fi
    printf '%s\n' "$build_exit" >"$output/build-$role.exit"
    [[ $build_exit == 0 ]] || exit "$build_exit"
    cp -- "$target/release/rustbgpd" "$output/bin/rustbgpd-$role"
done
target=$scratch/target-candidate
if (cd "$scratch/candidate" && CARGO_BUILD_JOBS=$jobs CARGO_TARGET_DIR=$target cargo build --profile scale --locked -p reloadstall) >"$output/build-harness.log" 2>&1; then build_exit=0; else build_exit=$?; fi
printf '%s\n' "$build_exit" >"$output/build-harness.exit"
[[ $build_exit == 0 ]] || exit "$build_exit"
cp -- "$target/scale/reloadstall" "$output/bin/reloadstall"
if (cd "$scratch/candidate" && CARGO_BUILD_JOBS=$jobs CARGO_TARGET_DIR=$target cargo build --release --locked --bin rbgp) >"$output/build-rbgp.log" 2>&1; then build_exit=0; else build_exit=$?; fi
printf '%s\n' "$build_exit" >"$output/build-rbgp.exit"
[[ $build_exit == 0 ]] || exit "$build_exit"
cp -- "$target/release/rbgp" "$output/bin/rbgp"
sha256sum "$output"/bin/* >"$output/binaries.sha256"
python3 "$checker" check-binaries "$output" >"$output/binary-validation.json"
python3 "$checker" seal-build "$output"
mapfile -t schedule < <(python3 - "$output/campaign.json" <<'PY'
import json, sys
for arm in json.load(open(sys.argv[1]))['schedule']:
    print(arm)
PY
)
for index in "${!schedule[@]}"; do
    arm=${schedule[$index]}
    while read -r expected binary; do
        provenance_require_sha256 "$binary" "$expected"
    done <"$output/binaries.sha256"
    timeout --foreground --signal=TERM --kill-after=150s 1900s python3 "$checker" run-cell "$output" --arm "$arm" --index "$index" \
        --daemon "$output/bin/rustbgpd-$arm" --harness "$output/bin/reloadstall" --rbgp "$output/bin/rbgp" \
        >"$output/controller-$index.log" 2>&1 &
    active_controller=$!
    active_starttime=$(controller_starttime "$active_controller")
    if wait "$active_controller"; then
        active_controller=''
    else
        status=$?
        active_controller=''
        exit "$status"
    fi
done
python3 "$checker" analyze "$output"
