#!/usr/bin/env bash
# GetPolicyStats reload cell: the isolated-generator operator-read shape with
# one pair per reload near the RIB commit plus one quiescent stats probe.
#
# usage: policy_stats_cell.sh BIN_DIR RELOADSTALL_BIN RUN_DIR
#   BIN_DIR holds release `rustbgpd` and `rbgp` built from the source under
#   test; RUN_DIR must not exist. Knobs (defaults are the qualification shape):
#   PEERS=1000 PREFIXES=400000 RELOADS=12 CONTROL_SECS=15 QUIESCE_SECS=40
#   DAEMON_CPUS=2-3 ENGINE_CPUS=4-5 PROBE_CPUS=8-15 PAIR_OFFSET=0.50
#   QUIESCENT_OFFSET=20
# Exit: 0 all checks pass, 1 a check failed (verdict retained), 2 setup/runtime.
set -euo pipefail
BIN=$(realpath "$1"); ENGINE=$(realpath "$2"); RUN_DIR=$(realpath -m "$3")
HERE=$(cd "$(dirname "$0")" && pwd); REPO=$(cd "$HERE/../../.." && pwd)
PEERS=${PEERS:-1000}; PREFIXES=${PREFIXES:-400000}; RELOADS=${RELOADS:-12}
CONTROL_SECS=${CONTROL_SECS:-15}; QUIESCE_SECS=${QUIESCE_SECS:-40}
DAEMON_CPUS=${DAEMON_CPUS:-2-3}; ENGINE_CPUS=${ENGINE_CPUS:-4-5}; PROBE_CPUS=${PROBE_CPUS:-8-15}
PAIR_OFFSET=${PAIR_OFFSET:-0.50}; QUIESCENT_OFFSET=${QUIESCENT_OFFSET:-20}
PORT=1793; MPORT=9183
[[ ! -e $RUN_DIR ]] || { echo 'run directory exists; keep earlier runs' >&2; exit 2; }
# shellcheck source=/dev/null
source "$REPO/tests/soak/fd-headroom.sh"
require_fd_headroom
mkdir -p "$(dirname "$RUN_DIR")"
mkdir -m 700 "$RUN_DIR"
export RUST_LOG=info,grpc_authz=debug,policy_stats=debug

python3 - "$RUN_DIR/environment.json" "$REPO" "$BIN" "$ENGINE" <<PY
import hashlib, json, os, platform, subprocess, sys
out, repo, bins, engine = sys.argv[1:]
def sha(p): return hashlib.sha256(open(p, 'rb').read()).hexdigest()
def run(*c): return subprocess.run(c, capture_output=True, text=True).stdout.strip()
def comm(p):
    try: return open(f'/proc/{p}/comm').read().strip()
    except OSError: return ''
compilers = [p for p in os.listdir('/proc') if p.isdigit() and comm(p) in ('cargo', 'rustc', 'rustdoc', 'clippy-driver')]
json.dump({
    'source_head': run('git', '-C', repo, 'rev-parse', 'HEAD'),
    'source_dirty': run('git', '-C', repo, 'status', '--porcelain', '--untracked-files=no'),
    'binaries': {n: sha(p) for n, p in (('rustbgpd', f'{bins}/rustbgpd'), ('rbgp', f'{bins}/rbgp'), ('reloadstall', engine))},
    'versions': {n: run(f'{bins}/{n}', '--version') for n in ('rustbgpd', 'rbgp')},
    'shape': {'peers': $PEERS, 'prefixes': $PREFIXES, 'reloads': $RELOADS, 'control_secs': $CONTROL_SECS,
              'quiesce_secs': $QUIESCE_SECS, 'pair_offset_s': $PAIR_OFFSET, 'quiescent_offset_s': $QUIESCENT_OFFSET},
    'placement': {'daemon_cpus': '$DAEMON_CPUS', 'engine_cpus': '$ENGINE_CPUS', 'probe_cpus': '$PROBE_CPUS'},
    'kernel': platform.release(), 'nproc': os.cpu_count(), 'loadavg_start': open('/proc/loadavg').read().split()[:3],
    'cpu_model': next((l.split(':', 1)[1].strip() for l in open('/proc/cpuinfo') if l.startswith('model name')), None),
    'cpu_topology': run('lscpu', '-e=CPU,CORE,SOCKET,NODE'),
    'compiler_processes_at_start': len(compilers),
}, open(out, 'w'), indent=2)
PY

SCEN=$(mktemp -d /tmp/psc.XXXXXX)
DPID=''; HPID=''; PPID_=''; SPID=''
# shellcheck disable=SC2317  # invoked by the EXIT trap
cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    for child in "$PPID_" "$SPID" "$HPID" "$DPID"; do
        [[ -z $child ]] || kill -TERM -- "-$child" 2>/dev/null || true
    done
    for child in "$PPID_" "$SPID" "$HPID" "$DPID"; do
        [[ -n $child ]] || continue
        for _ in $(seq 1 100); do kill -0 "$child" 2>/dev/null || break; sleep .1; done
        kill -KILL -- "-$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
    done
    mkdir -p "$RUN_DIR/scenario"
    cp "$SCEN/config.toml" "$SCEN"/*.rpol "$RUN_DIR/scenario/" 2>/dev/null || true
    rm -rf "$SCEN"
    printf '%s\n' "$rc" >"$RUN_DIR/cell.exit"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
fail() { echo "$1" >&2; exit 2; }

python3 "$HERE/gen-scenario.py" "$PEERS" "$SCEN" "$PORT" "$PEERS" >"$RUN_DIR/generator.log"
sed -i "s#prometheus_addr = \"127.0.0.1:9179\"#prometheus_addr = \"127.0.0.1:$MPORT\"#" "$SCEN/config.toml"
setsid taskset -c "$DAEMON_CPUS" "$BIN/rustbgpd" "$SCEN/config.toml" >"$RUN_DIR/rustbgpd.log" 2>&1 & DPID=$!
for _ in $(seq 1 1200); do
    curl -fsS --max-time .25 "http://127.0.0.1:$MPORT/readyz" >/dev/null 2>&1 && break
    kill -0 "$DPID" 2>/dev/null || fail 'daemon exited during startup'
    sleep .1
done
curl -fsS --max-time 1 "http://127.0.0.1:$MPORT/readyz" >/dev/null || fail 'daemon not ready'
RELOADSTALL_CYCLE_QUIESCE_SECS=$QUIESCE_SECS RELOADSTALL_RELOAD_METRICS_ADDR="127.0.0.1:$MPORT" \
RELOADSTALL_EVIDENCE_DIR="$RUN_DIR/final-evidence" \
    setsid taskset -c "$ENGINE_CPUS" "$ENGINE" "$PEERS" "$PREFIXES" "$PORT" "$DPID" \
    "$SCEN/member.rpol" "$SCEN/gen-a.rpol" "$SCEN/gen-b.rpol" "$RELOADS" "$CONTROL_SECS" "$PEERS" \
    >"$RUN_DIR/reloadstall.log" 2>&1 & HPID=$!
setsid taskset -c "$PROBE_CPUS" python3 "$HERE/policy_stats_cell.py" sample --pid "$DPID" --engine-pid "$HPID" \
    --output "$RUN_DIR/cpu.jsonl" & SPID=$!
deadline=$(($(date +%s) + 900))
until grep -q '^converged (' "$RUN_DIR/reloadstall.log"; do
    kill -0 "$HPID" 2>/dev/null || fail 'engine exited before convergence'
    (($(date +%s) < deadline)) || fail 'convergence cap exceeded'
    sleep 1
done
setsid taskset -c "$PROBE_CPUS" python3 "$HERE/policy_stats_cell.py" probe --log "$RUN_DIR/rustbgpd.log" \
    --rbgp "$BIN/rbgp" --socket "unix://$SCEN/grpc.sock" --output "$RUN_DIR/probes.jsonl" \
    --cpus "$PROBE_CPUS" --peers "$PEERS" --reloads "$RELOADS" --pair-offset "$PAIR_OFFSET" \
    --quiescent-offset "$QUIESCENT_OFFSET" >"$RUN_DIR/probe.log" 2>&1 & PPID_=$!
curl -fsS --max-time 5 "http://127.0.0.1:$MPORT/metrics" >"$RUN_DIR/metrics-before.prom"
# The engine holds its final evidence boundary after the last reload; wait
# for every probe (including the last quiescent one) before acknowledging.
deadline=$(($(date +%s) + 120 * RELOADS + 300))
until [[ -f $RUN_DIR/final-evidence/ready ]]; do
    kill -0 "$HPID" 2>/dev/null || fail 'engine exited before final evidence'
    (($(date +%s) < deadline)) || fail 'reload cap exceeded'
    sleep .1
done
set +e
wait "$PPID_"; prc=$?; PPID_=''
set -e
printf '%s\n' "$prc" >"$RUN_DIR/probe.exit"
((prc == 0)) || fail 'probe driver failed'
curl -fsS --max-time 5 "http://127.0.0.1:$MPORT/metrics" >"$RUN_DIR/metrics-after.prom"
python3 -c 'import json,sys,time; json.dump({"wall": time.time()}, open(sys.argv[1], "w"))' \
    "$RUN_DIR/final-evidence-completed.json"
touch "$RUN_DIR/final-evidence/ack"
set +e
wait "$HPID"; hrc=$?; HPID=''
kill -TERM -- "-$SPID"; wait "$SPID"; SPID=''
kill -TERM -- "-$DPID"
for _ in $(seq 1 300); do kill -0 "$DPID" 2>/dev/null || break; sleep .1; done
wait "$DPID"; drc=$?; DPID=''
set -e
printf '%s\n' "$hrc" >"$RUN_DIR/engine.exit"; printf '%s\n' "$drc" >"$RUN_DIR/daemon.exit"
((hrc == 0 && drc == 0)) || fail 'engine or daemon exited nonzero'
set +e
python3 "$HERE/policy_stats_cell.py" analyze "$RUN_DIR" >"$RUN_DIR/summary.txt"
arc=$?
set -e
cat "$RUN_DIR/summary.txt"
exit "$arc"
