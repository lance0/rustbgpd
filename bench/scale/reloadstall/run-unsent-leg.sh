#!/usr/bin/env bash
# One measured matrix leg. Build the dedicated worktree first (see README).
set -euo pipefail

out=${1:?usage: run-unsent-leg.sh OUT_DIR unset|BYTES [RTT_MS=0] [--container]}
threshold=${2:?usage: run-unsent-leg.sh OUT_DIR unset|BYTES [RTT_MS=0] [--container]}
rtt=${3:-0}
mode=${4:-}
case $mode in "" | --inside-netns | --container) ;; *) exit 2 ;; esac
cleanup_seconds=${UNSENT_CLEANUP_TIMEOUT_SECS:-30}
repo=$(cd "$(dirname "$0")/../../.." && pwd)
case $threshold in
    unset) unset RUSTBGPD_BENCH_UNSENT_THRESHOLD_BYTES ;;
    *[!0-9]* | '') echo 'threshold must be unset or a positive u32' >&2; exit 2 ;;
    *)
        [ "$threshold" -gt 0 ] && [ "$threshold" -le 4294967295 ] || exit 2
        export RUSTBGPD_BENCH_UNSENT_THRESHOLD_BYTES=$threshold
        ;;
esac
case $rtt in *[!0-9]* | '') echo 'RTT_MS must be a non-negative integer' >&2; exit 2 ;; esac
[ "$rtt" -le 1000 ] || exit 2
case $cleanup_seconds in *[!0-9]* | '') exit 2 ;; esac
[ "$cleanup_seconds" -gt 0 ] && [ "$cleanup_seconds" -le 30 ] || exit 2
[ "$threshold" = unset ] || [ "$threshold" -le 4294967295 ] || exit 2

if [ "$mode" = --container ]; then
    [ "$rtt" -gt 0 ] || { echo 'container mode needs a positive RTT' >&2; exit 2; }
    image=${UNSENT_CONTAINER_IMAGE:?set UNSENT_CONTAINER_IMAGE to the prepared runtime image}
    export RELOADSTALL_CONTAINER_IMAGE_ID
    RELOADSTALL_CONTAINER_IMAGE_ID=$(docker image inspect --format '{{.Id}}' "$image")
    [[ $RELOADSTALL_CONTAINER_IMAGE_ID =~ ^sha256:[0-9a-f]{64}$ ]] || exit 2
    export RELOADSTALL_CONTAINER_MEMORY_BYTES=${UNSENT_CONTAINER_MEMORY_BYTES:-107374182400}
    [[ $RELOADSTALL_CONTAINER_MEMORY_BYTES =~ ^[1-9][0-9]*$ ]] || exit 2
    export RELOADSTALL_MEMORY_KIND=container-daemon-only
    export RELOADSTALL_HOST_NETNS
    RELOADSTALL_HOST_NETNS=$(readlink /proc/self/ns/net)
elif [ "$rtt" -gt 0 ] && [ "$mode" != --inside-netns ]; then
    export RELOADSTALL_HOST_NETNS
    RELOADSTALL_HOST_NETNS=$(readlink /proc/self/ns/net)
    exec unshare --user --map-root-user --net -- bash "$0" "$out" "$threshold" "$rtt" --inside-netns
fi
if [ "$mode" != --container ]; then
    unset RELOADSTALL_CONTAINER_IMAGE_ID RELOADSTALL_CONTAINER_MEMORY_BYTES RELOADSTALL_MEMORY_KIND
fi

out=$(realpath -m -- "$out")
[ ! -e "$out" ] || { echo 'OUT_DIR must be fresh' >&2; exit 2; }
# Provenance applies to HEAD: staged, unstaged and untracked (non-ignored)
# changes go through a scratch index, captured before OUT_DIR exists.
prov=$(mktemp -d)
cp "$(git -C "$repo" rev-parse --path-format=absolute --git-path index)" "$prov/index" 2>/dev/null || true
GIT_INDEX_FILE=$prov/index git -C "$repo" add -A
GIT_INDEX_FILE=$prov/index git -C "$repo" diff --binary --cached HEAD >"$prov/experiment.diff"
git -C "$repo" rev-parse HEAD >"$prov/experiment.head"
mkdir -p "$out"
mv "$prov/experiment.diff" "$prov/experiment.head" "$out/"
rm -rf "$prov"
if [ ! -x "$repo/target/release/rustbgpd" ] || [ ! -x "$repo/target/scale/reloadstall" ]; then
    echo 'missing dedicated daemon/harness binaries; see reloadstall README' >&2; exit 2
fi

export RELOADSTALL_UNSENT_THRESHOLD_BYTES=$threshold
export RELOADSTALL_UNSENT_RTT_MS=$rtt
export RUSTBGPD_BENCH_WRITER_POLLS=${RUSTBGPD_BENCH_WRITER_POLLS:-0}
export RELOADSTALL_UNSENT_WRITER_POLLS=$RUSTBGPD_BENCH_WRITER_POLLS
export ARTIFACTS_DIR=$out/matrix
cat /proc/sys/net/ipv4/tcp_notsent_lowat >"$out/sysctl-before"
sha256sum "$repo/target/release/rustbgpd" "$repo/target/scale/reloadstall" >"$out/binaries.sha256"
if [ "$rtt" -gt 0 ]; then
    sha256sum "$repo/bench/scale/reloadstall/receiver-netem.py" \
        "$repo/bench/scale/reloadstall/sample-daemon-cgroup.py" \
        "$repo/bench/scale/reloadstall/run-unsent-leg.sh" >"$out/tools.sha256"
fi
if [ "$mode" = --container ]; then
    docker image inspect "$RELOADSTALL_CONTAINER_IMAGE_ID" >"$out/runtime-image.json"
fi

sampler=''
runner=''
cleanup() {
    if [ -n "$runner" ]; then
        # The matrix owns every daemon, harness and sampler in this group.
        # Signal the entire group, retain the real child status, and bound exit.
        kill -TERM -- "-$runner" 2>/dev/null || true
        deadline=$((SECONDS + cleanup_seconds))
        # Per container: lookup + ID inspect + stop + kill + logs + final
        # inspect + rm <= cleanup_seconds + 70s; add waiter/sampler grace.
        [ "$mode" != --container ] || deadline=$((SECONDS + 2 * (cleanup_seconds + 70) + 20))
        while kill -0 -- "-$runner" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do sleep 1; done
        kill -KILL -- "-$runner" 2>/dev/null || true
        runner_rc=0
        wait "$runner" || runner_rc=$?
        printf '%s\n' "$runner_rc" >"$out/runner.exit"
    fi
    if [ -n "$sampler" ]; then
        kill "$sampler" 2>/dev/null || true
        deadline=$((SECONDS + cleanup_seconds))
        while jobs -pr | grep -qx "$sampler" && [ "$SECONDS" -lt "$deadline" ]; do sleep 0.1; done
        if jobs -pr | grep -qx "$sampler"; then kill -KILL "$sampler" 2>/dev/null || true; fi
        sampler_rc=0
        wait "$sampler" 2>/dev/null || sampler_rc=$?
        printf '%s\n' "$sampler_rc" >"$out/sampler.exit"
        sampler=''
    fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
matrix=(bash "$repo/bench/scale/matrix/run-matrix.sh" rustbgpd)
if [ "$rtt" -gt 0 ] && [ "$mode" != --container ]; then
    # The same receiver-ingress path serves user namespaces and containers.
    matrix=(python3 "$repo/bench/scale/reloadstall/receiver-netem.py"
        --rtt "$rtt" --host-netns "${RELOADSTALL_HOST_NETNS:-$(readlink /proc/1/ns/net)}"
        --out "$out/netem" -- "${matrix[@]}")
fi
setsid "${matrix[@]}" >"$out/runner.log" 2>&1 &
runner=$!
printf '%s\n' "$runner" >"$out/runner.pid"
if [ "$mode" != --container ]; then
    python3 "$repo/bench/scale/reloadstall/sample-daemon-cgroup.py" \
    --exe "$repo/target/release/rustbgpd" --out "$out/cgroup-fast.csv" \
    --expected-pgid "$runner" >"$out/sampler.log" 2>&1 &
    sampler=$!
fi
# Retain the matrix's canonical cooldown and actual exit status.
runner_rc=0
wait "$runner" || runner_rc=$?
# On failure, the helper may have exited while native descendants still own
# the process group. Keep ownership until EXIT kills and reaps that group.
[ "$runner_rc" -eq 0 ] || exit "$runner_rc"
runner=''
printf '%s\n' "$runner_rc" >"$out/runner.exit"
sampler_rc=0
if [ "$mode" = --container ]; then
    sampler_rc=$(cat "$out/sampler.exit" 2>/dev/null || echo 1)
else
    if [ ! -s "$out/cgroup-fast.csv" ]; then
        kill "$sampler" 2>/dev/null || true
    fi
    wait "$sampler" || sampler_rc=$?
    sampler=''
fi
printf '%s\n' "$sampler_rc" >"$out/sampler.exit"
cat /proc/sys/net/ipv4/tcp_notsent_lowat >"$out/sysctl-after"
cmp "$out/sysctl-before" "$out/sysctl-after"
if [ "$rtt" -gt 0 ]; then sha256sum -c "$out/tools.sha256" >"$out/tools-check.log"; fi
# The daemon must prove the arm on every established session; a build without
# the benchmark hook logs no readback and fails here.
readback_rc=0
python3 "$repo/bench/scale/reloadstall/check-unsent-readback.py" \
    "$out/matrix/rustbgpd/daemon.log" "$threshold" >"$out/readback-check.log" 2>&1 || readback_rc=$?
printf '%s\n' "$readback_rc" >"$out/readback.exit"
[ "$runner_rc" -eq 0 ] && [ "$sampler_rc" -eq 0 ] && [ "$readback_rc" -eq 0 ] &&
    [ -s "$out/cgroup-fast.csv" ] &&
    awk 'NR > 1 {found = 1; exit} END {exit !found}' "$out/cgroup-fast.csv" &&
    [ "$(cat "$out/matrix/rustbgpd/status")" = pass ]
