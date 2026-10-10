#!/usr/bin/env bash
# One converged-rejoin K=1 cell; DAEMON is the fix build unless $2 names the base build.
# Usage: flock ~/.local/state/rustbgpd-host.lock bash cell.sh NAME
set -u
B=<bench-dir>  # bin/harness-main/reloadstall, and trees/ctl: a worktree at the base commit
WT=$B/trees/ctl
S=<cell-dir>
DAEMON=$S/${2:-rustbgpd-fix}
HARNESS=$B/bin/harness-main/reloadstall
PEERS=700 PREFIXES=400400 K=1 ROUNDS=3 CONTROL_SECS=30
PORT=17986 MPORT=19186
DAEMON_CPUS=12-32,34-39 ENGINE_CPUS=40-63
cell=$S/cells/$1
mkdir -p "$cell"
log() { echo "$(date -u +%FT%TZ) $*" | tee -a "$cell/cell.log"; }
if flock -n "${RUSTBGPD_HOST_LOCK}" true; then log "host lock not held"; exit 2; fi
# shellcheck source=/dev/null
source "$WT/tests/soak/fd-headroom.sh"; require_fd_headroom || { log "fd headroom"; exit 2; }
# shellcheck source=/dev/null
source "$WT/bench/scale/host-quiet.sh"
export RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=1800
wait_for_rustbgpd_quiet_host "$cell/quiet.tsv" || { log "quiet gate timed out"; exit 75; }
DPID='' HPID=''
SCEN=$(mktemp -d "${TMPDIR:-/tmp}/cell.XXXXXX"); chmod 700 "$SCEN"
stop_group() {
    local pid=$1 secs=${2:-60} i
    [ -n "$pid" ] || return 0
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
    for ((i = 0; i < secs * 10; i++)); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$pid" 2>/dev/null; then kill -KILL -- "-$pid" 2>/dev/null; fi
    wait "$pid" 2>/dev/null
}
cleanup() { stop_group "$HPID" 15; stop_group "$DPID" 60; rm -rf "$SCEN"; }
trap cleanup EXIT
GEN_CONVERGED_REJOIN=1 python3 "$WT/bench/scale/reloadstall/gen-scenario.py" "$PEERS" "$SCEN" "$PORT" >"$cell/generator.log" 2>&1 || exit 1
sed -i "s#prometheus_addr = \"127.0.0.1:9179\"#prometheus_addr = \"127.0.0.1:$MPORT\"#" "$SCEN/config.toml"
grep -q "127.0.0.1:$MPORT" "$SCEN/config.toml" || exit 1
"$DAEMON" --check "$SCEN/config.toml" >"$cell/config-check.log" 2>&1 || exit 1
log "cell start"
(cd "$SCEN" && exec setsid taskset -c "$DAEMON_CPUS" "$DAEMON" "$SCEN/config.toml") >"$cell/daemon.log" 2>&1 &
DPID=$!
t0=$SECONDS
until curl -fsS --max-time 1 "http://127.0.0.1:$MPORT/readyz" >/dev/null 2>&1; do
    kill -0 "$DPID" 2>/dev/null || { log "daemon died at start"; exit 1; }
    [ $((SECONDS - t0)) -lt 60 ] || { log "daemon not ready in 60s"; exit 1; }
    sleep 0.2
done
(cd "$SCEN" && RELOADSTALL_REJOIN_METRICS_ADDR=127.0.0.1:$MPORT exec setsid taskset -c "$ENGINE_CPUS" \
    "$HARNESS" "$PEERS" "$PREFIXES" "$PORT" "$DPID" "$SCEN/member.rpol" "$SCEN/gen-a.rpol" \
    "$SCEN/gen-b.rpol" 0 "$CONTROL_SECS" --flapstorm "$K" --flap-rounds "$ROUNDS" --converged-rejoin) \
    >"$cell/reloadstall.log" 2>&1 &
HPID=$!
t0=$SECONDS
while kill -0 "$HPID" 2>/dev/null; do
    kill -0 "$DPID" 2>/dev/null || { log "daemon died during harness"; break; }
    [ $((SECONDS - t0)) -lt 3600 ] || { log "cell timeout"; break; }
    sleep 1
done
if kill -0 "$HPID" 2>/dev/null; then stop_group "$HPID" 15; hrc=124; else wait "$HPID"; hrc=$?; fi
HPID=''
curl -fsS --max-time 5 "http://127.0.0.1:$MPORT/metrics" >"$cell/metrics-final.prom" 2>/dev/null
stop_group "$DPID" 60; drc=$?
DPID=''
log "cell done harness_rc=$hrc daemon_rc=$drc"
