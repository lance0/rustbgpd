#!/usr/bin/env bash
# PREPARED ONLY: scale RR control cell adapted from the qualified smoke wrapper.
# Usage: under one continuous canonical host lock, supply frozen env and run:
# bash prebuilt-cell.sh CELL_NAME DAEMON HARNESS RUNNER_TREE OUT_ROOT
# Required env: DAEMON_SHA256 HARNESS_SHA256 RUNNER_SHA RUSTBGPD_HOST_LOCK_FD.
# Both arms use one frozen HARNESS
# and clean RUNNER_TREE with matched-package daemon build provenance archived.
set -euo pipefail
[[ $# -eq 5 ]] || { echo "expected CELL_NAME DAEMON HARNESS RUNNER_TREE OUT_ROOT" >&2; exit 2; }
NAME=$1 DAEMON=$(realpath "$2") HARNESS=$(realpath "$3") WT=$(realpath "$4") OUT=$(realpath -m "$5")
[[ $NAME =~ ^[a-z0-9][a-z0-9-]*$ ]] || exit 2
: "${DAEMON_SHA256:?frozen daemon hash required}" "${HARNESS_SHA256:?frozen common instrument hash required}"
: "${RUNNER_SHA:?exact frozen runner commit required}" "${RUSTBGPD_HOST_LOCK_FD:?inherited canonical lock fd required}"
[[ $RUNNER_SHA =~ ^[0-9a-f]{40}$ && $RUSTBGPD_HOST_LOCK_FD =~ ^[0-9]+$ ]] || exit 2
[[ $(git -C "$WT" rev-parse HEAD) == "$RUNNER_SHA" && -z $(git -C "$WT" status --porcelain) ]] || exit 2
RUSTBGPD_HOST_LOCK=${RUSTBGPD_HOST_LOCK:-$HOME/.local/state/rustbgpd-host.lock}
export RUSTBGPD_HOST_LOCK
[[ $RUSTBGPD_HOST_LOCK == "$HOME/.local/state/rustbgpd-host.lock" ]] || exit 2
[[ $(readlink "/proc/$$/fd/$RUSTBGPD_HOST_LOCK_FD") == "$RUSTBGPD_HOST_LOCK" ]] || exit 2
flock -n "$RUSTBGPD_HOST_LOCK_FD" || exit 75
if flock -n "$RUSTBGPD_HOST_LOCK" true; then
    echo "canonical host lock must already be held by the outer campaign" >&2
    exit 2
fi
CELL=$OUT/$NAME
[[ ! -e $CELL ]] || { echo "new cell path required" >&2; exit 2; }
mkdir -p "$CELL"
log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*" >>"$CELL/cell.log"; }
verify_binaries() {
    printf '%s  %s\n%s  %s\n' "$DAEMON_SHA256" "$DAEMON" "$HARNESS_SHA256" "$HARNESS" |
        sha256sum -c - >>"$CELL/binary-integrity.log" 2>&1
}
DPID='' HPID='' SCEN='' FORCED_KILL=0
# Ambient workload knobs must not change this fixed shape.
while IFS= read -r var; do
    case $var in GEN_*|RELOADSTALL_*) unset "$var" ;; esac
done < <(compgen -e)

stop_group() {
    local pid=$1 secs=$2 i rc
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    for ((i=0; i<secs*10; i++)); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
        FORCED_KILL=1
        log "cleanup forced kill pid=$pid"
        kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
    fi
    if wait "$pid"; then rc=0; else rc=$?; fi
    return "$rc"
}
cleanup() {
    local original=$? rc
    trap - EXIT
    if [[ -n $HPID ]]; then
        if stop_group "$HPID" 15; then rc=0; else rc=$?; fi
        printf '%s\n' "$rc" >"$CELL/harness-cleanup.exit"
        ((rc==0)) || original=1
    fi
    if [[ -n $DPID ]]; then
        if stop_group "$DPID" 60; then rc=0; else rc=$?; fi
        printf '%s\n' "$rc" >"$CELL/daemon-cleanup.exit"
        ((rc==0)) || original=1
    fi
    [[ -z $SCEN ]] || rm -rf -- "$SCEN"
    printf '%s\n' "$FORCED_KILL" >"$CELL/forced-kill.txt"
    if ((original==0 && FORCED_KILL)); then original=1; fi
    printf '%s\n' "$original" >"$CELL/cell.exit"
    exit "$original"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
verify_binaries
# shellcheck source=/dev/null
source "$WT/tests/soak/fd-headroom.sh"
require_fd_headroom
# shellcheck source=/dev/null
source "$WT/bench/scale/host-quiet.sh"
export RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=1800
export RUSTBGPD_HOST_QUIET_SAMPLE_INTERVAL_SECS=30 RUSTBGPD_HOST_QUIET_MIN_SPACING_SECS=30
unset RUSTBGPD_HOST_QUIET_PROC_ROOT RUSTBGPD_HOST_QUIET_CPU_ROOT
wait_for_rustbgpd_quiet_host "$CELL/quiet.tsv"
PEERS=200 PREFIXES=400000 K=${RR_CONTROL_K:?set K=1 or 50} ROUNDS=3 CONTROL_SECS=30
[[ $K == 1 || $K == 50 ]] || exit 2
PORT=17988 MPORT=19188 DAEMON_CPUS=12-32,34-39 ENGINE_CPUS=40-63
SCEN=$(mktemp -d "${TMPDIR:-/tmp}/rr-control-cell.XXXXXX")
chmod 700 "$SCEN"
sha256sum "$WT/bench/scale/reloadstall/gen-scenario.py" >"$CELL/generator.sha256"
GEN_IBGP_RR_ASN=65000 python3 "$WT/bench/scale/reloadstall/gen-scenario.py" "$PEERS" "$SCEN" "$PORT" >"$CELL/generator.log" 2>&1
sed -i "s#prometheus_addr = \"127.0.0.1:9179\"#prometheus_addr = \"127.0.0.1:$MPORT\"#" "$SCEN/config.toml"
rg -q "127.0.0.1:$MPORT" "$SCEN/config.toml"
cp -- "$SCEN/config.toml" "$SCEN/member.rpol" "$SCEN/gen-a.rpol" "$SCEN/gen-b.rpol" "$CELL/"
(cd "$CELL" && sha256sum config.toml member.rpol gen-a.rpol gen-b.rpol >generated-inputs.sha256)
"$DAEMON" --check "$SCEN/config.toml" >"$CELL/config-check.log" 2>&1
log "cell start peers=$PEERS prefixes=$PREFIXES k=$K rounds=$ROUNDS"
(cd "$SCEN" && exec setsid taskset -c "$DAEMON_CPUS" "$DAEMON" "$SCEN/config.toml") >"$CELL/daemon.log" 2>&1 &
DPID=$!
printf '%s\n' "$DPID" >"$CELL/daemon.pid"
t0=$SECONDS
until curl -fsS --max-time 1 "http://127.0.0.1:$MPORT/readyz" >/dev/null 2>&1; do
    kill -0 "$DPID" 2>/dev/null || { log "daemon died at start"; exit 1; }
    ((SECONDS-t0 < 60)) || { log "daemon not ready in 60s"; exit 1; }
    sleep 0.2
done
(cd "$SCEN" && RELOADSTALL_IBGP_RR_ASN=65000 RELOADSTALL_IBGP_RR_HOLD_SECS=3 \
    RELOADSTALL_RR_REFRESHERS=$K RELOADSTALL_RR_REFRESH_ROUNDS=$ROUNDS \
    RELOADSTALL_REJOIN_METRICS_ADDR=127.0.0.1:$MPORT exec setsid taskset -c "$ENGINE_CPUS" \
    "$HARNESS" "$PEERS" "$PREFIXES" "$PORT" "$DPID" "$SCEN/member.rpol" "$SCEN/gen-a.rpol" \
    "$SCEN/gen-b.rpol" 0 "$CONTROL_SECS") \
    >"$CELL/reloadstall.log" 2>&1 &
HPID=$!
printf '%s\n' "$HPID" >"$CELL/harness.pid"
t0=$SECONDS timed_out=0
while kill -0 "$HPID" 2>/dev/null; do
    if ! kill -0 "$DPID" 2>/dev/null; then log "daemon died during harness"; timed_out=1; break; fi
    if ((SECONDS-t0 >= 1200)); then log "cell timeout"; timed_out=1; break; fi
    sleep 1
done
if ((timed_out)); then
    if stop_group "$HPID" 15; then hrc=0; else hrc=$?; fi
else
    if wait "$HPID"; then hrc=0; else hrc=$?; fi
fi
HPID=''
printf '%s\n' "$hrc" >"$CELL/harness.exit"
if curl -fsS --max-time 5 "http://127.0.0.1:$MPORT/metrics" >"$CELL/metrics-final.prom" 2>"$CELL/metrics-final.stderr"; then mrc=0; else mrc=$?; fi
printf '%s\n' "$mrc" >"$CELL/metrics.exit"
if stop_group "$DPID" 60; then drc=0; else drc=$?; fi
DPID=''
printf '%s\n' "$drc" >"$CELL/daemon.exit"
verify_binaries
sha256sum -c "$CELL/generator.sha256" >>"$CELL/input-integrity.log" 2>&1
(cd "$SCEN" && sha256sum -c "$CELL/generated-inputs.sha256") >>"$CELL/input-integrity.log" 2>&1
log "cell done harness_rc=$hrc daemon_rc=$drc metrics_rc=$mrc timeout=$timed_out forced_kill=$FORCED_KILL"
((hrc==0 && drc==0 && mrc==0 && timed_out==0 && FORCED_KILL==0)) || exit 1
log "cell pass"
