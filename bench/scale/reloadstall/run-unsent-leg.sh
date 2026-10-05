#!/usr/bin/env bash
# One measured matrix leg. Build the dedicated worktree first (see README).
set -euo pipefail

out=${1:?usage: run-unsent-leg.sh OUT_DIR unset|BYTES [RTT_MS=0]}
threshold=${2:?usage: run-unsent-leg.sh OUT_DIR unset|BYTES [RTT_MS=0]}
rtt=${3:-0}
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

if [ "$rtt" -gt 0 ] && [ "${4:-}" != --inside-netns ]; then
    # Both endpoints stay on loopback in an owned, short-lived network namespace.
    exec unshare --user --map-root-user --net -- bash "$0" "$out" "$threshold" "$rtt" --inside-netns
fi
if [ "$rtt" -gt 0 ]; then
    ip link set lo up
    delay=$(awk -v rtt="$rtt" 'BEGIN {printf "%.3fms", rtt / 2}')
    tc qdisc add dev lo root netem delay "$delay"
fi

out=$(realpath -m -- "$out")
[ ! -e "$out" ] || { echo 'OUT_DIR must be fresh' >&2; exit 2; }
mkdir -p "$out"
if [ ! -x "$repo/target/release/rustbgpd" ] || [ ! -x "$repo/target/scale/reloadstall" ]; then
    echo 'missing dedicated daemon/harness binaries; see reloadstall README' >&2; exit 2
fi

export RELOADSTALL_UNSENT_THRESHOLD_BYTES=$threshold
export RELOADSTALL_UNSENT_RTT_MS=$rtt
export RUSTBGPD_BENCH_WRITER_POLLS=${RUSTBGPD_BENCH_WRITER_POLLS:-0}
export RELOADSTALL_UNSENT_WRITER_POLLS=$RUSTBGPD_BENCH_WRITER_POLLS
export ARTIFACTS_DIR=$out/matrix
cat /proc/sys/net/ipv4/tcp_notsent_lowat >"$out/sysctl-before"
git -C "$repo" diff --binary >"$out/experiment.diff"
sha256sum "$repo/target/release/rustbgpd" "$repo/target/scale/reloadstall" >"$out/binaries.sha256"
if [ "$rtt" -gt 0 ]; then tc -s qdisc show dev lo >"$out/netem-before"; fi

sampler=''
runner=''
cleanup() {
    if [ -n "$runner" ]; then
        # The matrix owns every daemon, harness and sampler in this group.
        # Signal the entire group, retain the real child status, and bound exit.
        kill -TERM -- "-$runner" 2>/dev/null || true
        deadline=$((SECONDS + cleanup_seconds))
        while kill -0 -- "-$runner" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do sleep 1; done
        kill -KILL -- "-$runner" 2>/dev/null || true
        runner_rc=0
        wait "$runner" || runner_rc=$?
        printf '%s\n' "$runner_rc" >"$out/runner.exit"
    fi
    kill "$sampler" 2>/dev/null || true
    wait "$sampler" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
setsid bash "$repo/bench/scale/matrix/run-matrix.sh" rustbgpd >"$out/runner.log" 2>&1 &
runner=$!
printf '%s\n' "$runner" >"$out/runner.pid"
python3 "$repo/bench/scale/reloadstall/sample-daemon-cgroup.py" \
    --exe "$repo/target/release/rustbgpd" --out "$out/cgroup-fast.csv" \
    --expected-pgid "$runner" >"$out/sampler.log" 2>&1 &
sampler=$!
# Retain the matrix's canonical cooldown and actual exit status.
runner_rc=0
wait "$runner" || runner_rc=$?
runner=''
printf '%s\n' "$runner_rc" >"$out/runner.exit"
sampler_rc=0
if [ -s "$out/cgroup-fast.csv" ]; then
    wait "$sampler" || sampler_rc=$?
else
    kill "$sampler" 2>/dev/null || true
    wait "$sampler" || sampler_rc=$?
fi
printf '%s\n' "$sampler_rc" >"$out/sampler.exit"
cat /proc/sys/net/ipv4/tcp_notsent_lowat >"$out/sysctl-after"
if [ "$rtt" -gt 0 ]; then tc -s qdisc show dev lo >"$out/netem-after"; fi
cmp "$out/sysctl-before" "$out/sysctl-after"
[ "$runner_rc" -eq 0 ] && [ "$sampler_rc" -eq 0 ] && [ -s "$out/cgroup-fast.csv" ] &&
    [ "$(cat "$out/matrix/rustbgpd/status")" = pass ]
