#!/usr/bin/env bash
# Quiet-host unchanged-main VRP-delta replay baseline (prepared 2026-10-02 for the 10-03 overnight queue).
#   Source   = origin/main 481e0187d (repinned to tip; contains #2855 refresh accounting, #2857 GEN_RPKI_CACHE,
#              #2858 dual-stack VRP fixtures, #2859 --no-churn), detached clean worktree
#              <worktree>. No refresh-targeting change: this is the baseline receipt.
#   Shape    = 700 x 400,400 dual-stack route server (200,200 IPv4 + 200,200 IPv6), reject-invalid on
#              every member (GEN_DUALSTACK=1 GEN_RPKI_CACHE), 500,000 VRPs (rpki_cell.py vrps), served by
#              digest-pinned StayRTR 0.6.4 from a directory mount; a delta of N equal-cardinality maxLength
#              replacements (rpki_cell.py maxlen-delta, N in 10/100/1000 = N withdrawals + N announcements,
#              validity unchanged) is injected by atomic rename while reloadstall --no-churn holds sessions.
#   Cells    = one fresh StayRTR + daemon + harness per (N, repeat); N order alternates per repeat;
#              quiet-host gate before every cell; a failed gate stops measuring (defer, rc 75).
#   Proof    = per cell (fail closed => invalid, rc 5): same RTR session, serial +1, VRP counts unchanged;
#              exactly one non-empty "RTR incremental update received" with announced=withdrawn=N and no
#              full table after injection; one RIB "re-validation complete" with mode=delta and
#              changed_routes=0; one Rpki "processed validation-cache import-policy refresh" with
#              eligible=refreshed=PEERS and no skips/failures; all sessions up, no flaps, zero decode
#              errors; every peer/family received >=1 ROUTE-REFRESH; replay observed to go quiet.
#   Signals  = bgp_validation_import_refreshes_total{dependency="rpki"} deltas; member burden
#              (route_refresh_accounting: ROUTE-REFRESH PDUs, latch suppressions, completed, sent NLRI);
#              settle = max(RIB re-validation log, refresh-pass log, last observed increase of the daemon's
#              summed UPDATE-received counter, polled every POLL_SECS) minus the daemon's "RTR incremental
#              update received" log time (StayRTR file-poll lag is reported separately, not counted);
#              daemon CPU-seconds (/proc utime+stime) from the last poll before that receipt to the first
#              poll at/after settle, raw and net of the
#              idle rate measured over IDLE_SECS just before injection with the same pollers running;
#              /readyz sampled every POLL_SECS; samples between delta receipt and settle reported (no ticket threshold).
#   Verdict  = predeclared kill: decline-eligible only if a full-fleet replay costs < 1 CPU-second (net) AND
#              < 1 s settle for every delta size (medians); the member-side "acceptable" leg is a
#              maintainer judgement and is reported, not decided. Otherwise the targeted-variant gate
#              (<=20% of baseline peers refreshed at N=100, byte-identical views) applies.
#   Pinning  = daemon 12-32,34-39 (CPU 33 hosts an unrelated busy process), harness 40-63, StayRTR 8-11.
# Runtime estimate (full shape): build <=2 min warm (~15 min cold); fixtures ~1 min;
#   6 cells x (quiet gate >=1 min + StayRTR/VRP load ~1 min + dual-stack convergence ~1-3 min +
#   HOLD_SECS 240 + teardown) ~= 50-70 min.
# Locks: queue bench.lock (fd 8, waits 2 h), canonical host lock (tests/soak/host-lock.sh,
#   retried up to 1 h) and /tmp/rustbgpd-bench.lock (fd 7) for the measuring phase.
#   Do NOT wrap this script in another flock on bench.lock (it would self-deadlock).
# Exit: 0 ok, 2 setup, 3 build, 5 any invalid run (or summary failure), 75 deferred.
# Env knobs (smoke only): PEERS (700) PREFIXES (400400) V4 (200200) VRPS (500000) DELTAS ("10 100 1000")
#   REPEATS (2) HOLD_SECS (240) QUIET (1) OUT DAEMON_CPUS ENGINE_CPUS RTR_CPUS.  Smallest shape: PEERS=8 PREFIXES=32 V4=16 VRPS=48.
set -u
Q='<queue-dir>'
QLOCK='<queue-lock>'
PRIMARY='<repo>'
PIN=481e0187d873dd8e7715033224be0fe90cb7d4e2
WT='<worktree>'
TOOLCHAIN=1.99.0
IMAGE=rpki/stayrtr@sha256:cdb93c0b661d97179a5525e00caf7d9e693a04da3b9002f7e24bebb194d9a77b
OUT=${OUT:-'<out-dir>'}
PEERS=${PEERS:-700}
PREFIXES=${PREFIXES:-400400}
V4=${V4:-200200}
VRPS=${VRPS:-500000}
DELTAS=${DELTAS:-10 100 1000}
REPEATS=${REPEATS:-2}
HOLD_SECS=${HOLD_SECS:-240}
QUIET=${QUIET:-1}
IDLE_SECS=10
POLL_SECS=0.25
TAIL_SECS=10
CONVERGE_TIMEOUT_SECS=900
DAEMON_CPUS=${DAEMON_CPUS:-12-32,34-39}
ENGINE_CPUS=${ENGINE_CPUS:-40-63}
RTR_CPUS=${RTR_CPUS:-8-11}
PORT=17983
MPORT=19183
RTR_PORT=13383
RTR_MPORT=19883
RTR_NAME=rpki-refresh-$$

mkdir -p "$OUT"/{raw,bin,quiet,fixtures}
exec 3>&1 >>"$OUT/job.log" 2>&1
log() { echo "$(date -u +%FT%TZ) $*"; }

DPID='' HPID='' PPID_POLL='' SCEN='' CACHE='' RTR_UP=''
stop_group() { # TERM the owned process group, KILL after $2 s (default 60); returns the exit status
    local pid=$1 secs=${2:-60} i
    [ -n "$pid" ] || return 0
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
    for ((i = 0; i < secs * 10; i++)); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$pid" 2>/dev/null; then log "pid $pid survived ${secs}s TERM; KILL"; kill -KILL -- "-$pid" 2>/dev/null; fi
    wait "$pid" 2>/dev/null
}
stop_rtr() { # stop_rtr [CELL_DIR]: save logs, remove the owned container
    [ -n "$RTR_UP" ] || return 0
    [ -n "${1:-}" ] && docker logs "$RTR_NAME" >"$1/stayrtr.log" 2>&1
    docker rm -f "$RTR_NAME" >/dev/null 2>&1
    RTR_UP=''
}
cleanup() {
    [ -n "$PPID_POLL" ] && { [ -n "$SCEN" ] && touch "$SCEN/poll-stop"; stop_group "$PPID_POLL" 5; PPID_POLL=''; }
    stop_group "$HPID" 30; HPID=''
    stop_group "$DPID" 60; DPID=''
    stop_rtr
    [ -n "$SCEN" ] && [ -d "$SCEN" ] && rm -rf "$SCEN"
    [ -n "$CACHE" ] && [ -d "$CACHE" ] && rm -rf "$CACHE"
    SCEN='' CACHE=''
}
fail() { cleanup; log "FAIL rc=$1 $2"; echo "$1" >"$OUT/exit_code"; echo "job FAILED rc=$1: $2 (see $OUT/job.log)" | tee "$OUT/summary.txt" >&3; exit "$1"; }
trap 'cleanup' EXIT
trap 'fail 5 "interrupted by signal"' INT TERM

exec 8>"$QLOCK"
flock -w 7200 8 || fail 75 "queue bench.lock busy for 2h"
log "START baseline peers=$PEERS prefixes=$PREFIXES v4=$V4 vrps=$VRPS deltas='$DELTAS' repeats=$REPEATS hold=$HOLD_SECS quiet=$QUIET load=$(cut -d' ' -f1-3 /proc/loadavg)"
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker pull "$IMAGE" >/dev/null || fail 2 "StayRTR image unavailable"

# Pinned clean worktree.
if [ ! -e "$WT" ]; then
    git -C "$PRIMARY" fetch -q origin || fail 2 "git fetch"
    git -C "$PRIMARY" worktree add -q --detach "$WT" "$PIN" || fail 2 "worktree add $WT"
fi
[ "$(git -C "$WT" rev-parse HEAD)" = "$PIN" ] || fail 2 "$WT not at $PIN"
[ -z "$(git -C "$WT" status --porcelain)" ] || fail 2 "$WT dirty"
CELLPY=$WT/bench/scale/rpki-cell/rpki_cell.py
python3 "$CELLPY" check "$PEERS" "$PREFIXES" "$VRPS" "$V4" || fail 2 "fixture shape rejected"

# Build once (outside the host lock and quiet checks), copy binaries out.
log "build @ $PIN"
(cd "$WT" && taskset -c 40-63 env CARGO_BUILD_JOBS=8 cargo +$TOOLCHAIN build --release --locked --bin rustbgpd --bin rbgp &&
    taskset -c 40-63 env CARGO_BUILD_JOBS=8 cargo +$TOOLCHAIN build --profile scale --locked -p reloadstall) \
    >"$OUT/build.log" 2>&1 || fail 3 "build (see build.log)"
[ -z "$(git -C "$WT" status --porcelain)" ] || fail 3 "$WT dirty after build"
cp "$WT/target/release/rustbgpd" "$WT/target/release/rbgp" "$WT/target/scale/reloadstall" "$OUT/bin/" || fail 3 "copy binaries"
BIN=$OUT/bin

# Fixtures: one canonical dual-stack base and one replacement table per delta size.
F=$OUT/fixtures
python3 "$CELLPY" vrps "$PEERS" "$PREFIXES" "$VRPS" "$F/base.json" "$V4" || fail 2 "base VRP fixture"
for n in $DELTAS; do
    python3 "$CELLPY" maxlen-delta "$PEERS" "$PREFIXES" "$VRPS" "$V4" "$n" "$F/base.json" "$F/delta-$n.json" \
        >"$F/delta-$n.counts" || fail 2 "delta fixture N=$n"
    grep -q "withdrawals=$n announcements=$n " "$F/delta-$n.counts" || fail 2 "delta fixture N=$n counts: $(cat "$F/delta-$n.counts")"
done

# Poller: daemon CPU ticks + summed UPDATE-received counter, and /readyz, each every POLL_SECS.
cat >"$BIN/poll.py" <<'PY'
import os, sys, threading, time, urllib.request
murl, rurl, pid, stop, pout, rout, interval = sys.argv[1:8]
interval = float(interval)
def ticks():
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])
def ready():
    with open(rout, "w", buffering=1) as o:
        o.write("epoch\tstatus\tlatency_ms\n")
        while not os.path.exists(stop):
            t = time.time(); status = "error"
            try:
                with urllib.request.urlopen(rurl, timeout=2) as r:
                    r.read(); status = str(r.status)
            except urllib.error.HTTPError as e:
                status = str(e.code)
            except Exception:
                pass
            o.write(f"{t:.3f}\t{status}\t{(time.time() - t) * 1000:.1f}\n")
            time.sleep(max(0, interval - (time.time() - t)))
threading.Thread(target=ready, daemon=True).start()
with open(pout, "w", buffering=1) as o:
    o.write("epoch\tticks\tupdates_received\tscrape_ms\n")
    while not os.path.exists(stop):
        t = time.time(); total = -1
        try:
            with urllib.request.urlopen(murl, timeout=5) as r:
                total = 0
                for line in r.read().decode().splitlines():
                    if line.startswith("bgp_messages_received_total{") and 'type="update"' in line:
                        total += int(float(line.rsplit(" ", 1)[1]))
        except Exception:
            total = -1
        try:
            tk = ticks()
        except OSError:
            break
        o.write(f"{t:.3f}\t{tk}\t{total}\t{(time.time() - t) * 1000:.1f}\n")
        time.sleep(max(0, interval - (time.time() - t)))
PY

HARNESS_SRC=(bench/scale/reloadstall/gen-scenario.py bench/scale/reloadstall/src/main.rs
    bench/scale/rpki-cell/rpki_cell.py bench/scale/host-quiet.sh tests/soak/host-lock.sh tests/soak/fd-headroom.sh)
{
    echo "pin $PIN tree $(git -C "$WT" rev-parse 'HEAD^{tree}')"
    rustc +$TOOLCHAIN --version; cargo +$TOOLCHAIN --version
    (cd "$BIN" && sha256sum rustbgpd rbgp reloadstall poll.py)
    (cd "$WT" && sha256sum "${HARNESS_SRC[@]}")
    sha256sum "$(readlink -f "$0")"
    (cd "$F" && sha256sum ./*.json)
    echo "stayrtr $IMAGE id $(docker image inspect "$IMAGE" --format '{{.Id}}')"
    echo "daemon_cpus $DAEMON_CPUS engine_cpus $ENGINE_CPUS rtr_cpus $RTR_CPUS kernel $(uname -r) clk_tck $(getconf CLK_TCK)"
    echo "shape peers=$PEERS prefixes=$PREFIXES v4=$V4 vrps=$VRPS deltas='$DELTAS' repeats=$REPEATS hold=$HOLD_SECS idle=$IDLE_SECS poll=$POLL_SECS tail=$TAIL_SECS quiet=$QUIET"
} >"$OUT/identity.txt"

# Measurement locks: canonical host lock (retry the repo helper) + legacy bench lock.
# shellcheck source=/dev/null
source "$WT/tests/soak/host-lock.sh"
deadline=$((SECONDS + 3600))
until acquire_rustbgpd_host_lock; do
    [ "$SECONDS" -lt "$deadline" ] || fail 75 "host lock busy for 1h"
    sleep 30
done
exec 7>/tmp/rustbgpd-bench.lock
flock -w 3600 7 || fail 75 "/tmp/rustbgpd-bench.lock busy for 1h"
# shellcheck source=/dev/null
source "$WT/tests/soak/fd-headroom.sh"
require_fd_headroom || fail 2 "fd headroom"
# shellcheck source=/dev/null
source "$WT/bench/scale/host-quiet.sh"
export RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=${RUSTBGPD_HOST_QUIET_TIMEOUT_SECS:-900}

ports_free() {
    python3 - "$@" <<'PY'
import socket, sys
held = []
for port in map(int, sys.argv[1:]):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); held.append(s)
PY
}
rbgp() { "$BIN/rbgp" --addr "unix://$SCEN/grpc.sock" --json "$@"; }
wait_file() { # wait_file FILE SECS
    local end=$((SECONDS + $2))
    until [ -f "$1" ]; do
        kill -0 "$DPID" 2>/dev/null || { log "daemon exited"; return 1; }
        kill -0 "$HPID" 2>/dev/null || { log "harness exited"; return 1; }
        [ "$SECONDS" -lt "$end" ] || { log "timeout waiting for $1"; return 1; }
        sleep 0.1
    done
}
ticks() { awk '{ print $14 + $15 }' "/proc/$DPID/stat"; }

run_cell() { # run_cell N REP -> 0 ok, 1 invalid, 75 deferred
    local n=$1 rep=$2 cell=$OUT/raw/n$1-rep$2 hrc=setup drc=setup t0 idle_epoch idle_ticks inj_epoch inj_ticks pre_lines
    mkdir -p "$cell"
    if [ "$QUIET" = 1 ] && ! wait_for_rustbgpd_quiet_host "$OUT/quiet/n$n-rep$rep.tsv"; then
        return 75
    fi
    ports_free "$PORT" "$MPORT" "$RTR_PORT" "$RTR_MPORT" || { log "owned ports busy"; return 1; }
    SCEN=$(mktemp -d /tmp/rpki-refresh.XXXXXX) && chmod 700 "$SCEN" || return 1
    CACHE=$(mktemp -d /tmp/rpki-refresh-rtr.XXXXXX) && chmod 755 "$CACHE" || return 1
    mkdir "$SCEN/pre" "$SCEN/final"
    GEN_DUALSTACK=1 GEN_RPKI_CACHE=127.0.0.1:$RTR_PORT python3 "$WT/bench/scale/reloadstall/gen-scenario.py" \
        "$PEERS" "$SCEN" "$PORT" >"$cell/generator.log" 2>&1 || return 1
    sed -i "s#prometheus_addr = \"127.0.0.1:9179\"#prometheus_addr = \"127.0.0.1:$MPORT\"#" "$SCEN/config.toml"
    grep -q "127.0.0.1:$MPORT" "$SCEN/config.toml" || return 1
    "$BIN/rustbgpd" --check --strict "$SCEN/config.toml" >"$cell/config-check.log" 2>&1 || return 1
    cp "$F/base.json" "$CACHE/vrps.json" && chmod 644 "$CACHE/vrps.json" || return 1
    log "cell n=$n rep=$rep start load=$(cut -d' ' -f1 /proc/loadavg)"
    docker run -d --name "$RTR_NAME" --network host --cpuset-cpus "$RTR_CPUS" -v "$CACHE:/data:ro" "$IMAGE" \
        -cache /data/vrps.json -bind "127.0.0.1:$RTR_PORT" -metrics.addr "127.0.0.1:$RTR_MPORT" \
        -protocol 1 -checktime=false -refresh 2 -rtr.refresh 30 -rtr.retry 5 -rtr.expire 600 \
        -loglevel debug -log.verbose=false >"$cell/container-id.txt" || return 1
    RTR_UP=1
    t0=$SECONDS
    until (exec 4<>"/dev/tcp/127.0.0.1/$RTR_PORT") 2>/dev/null; do
        [ "$(docker inspect -f '{{.State.Running}}' "$RTR_NAME" 2>/dev/null)" = true ] || { log "StayRTR exited"; return 1; }
        [ $((SECONDS - t0)) -lt 180 ] || { log "StayRTR not listening in 180s"; return 1; }
        sleep 0.5
    done
    (cd "$SCEN" && RUST_LOG=info exec setsid taskset -c "$DAEMON_CPUS" "$BIN/rustbgpd" "$SCEN/config.toml") \
        >"$cell/daemon.log" 2>&1 &
    DPID=$!
    python3 "$CELLPY" wait-vrps "http://127.0.0.1:$MPORT/metrics" "$VRPS" 300 "$DPID" >"$cell/vrp-gate.log" 2>&1 || return 1
    (cd "$SCEN" && RELOADSTALL_DUALSTACK=1 RELOADSTALL_IPV4_PREFIXES=$V4 \
        RELOADSTALL_PRE_CHURN_EVIDENCE_DIR="$SCEN/pre" RELOADSTALL_EVIDENCE_DIR="$SCEN/final" \
        exec setsid taskset -c "$ENGINE_CPUS" "$BIN/reloadstall" "$PEERS" "$PREFIXES" "$PORT" "$DPID" \
        "$SCEN/member.rpol" "$SCEN/gen-a.rpol" "$SCEN/gen-b.rpol" 0 "$HOLD_SECS" --no-churn) \
        >"$cell/reloadstall.log" 2>&1 &
    HPID=$!
    wait_file "$SCEN/pre/ready" "$CONVERGE_TIMEOUT_SECS" || return 1
    # Inside the harness's 60 s pre-evidence window: initial cache/session state.
    rbgp rpki caches >"$cell/caches-before.json" && rbgp neighbor >"$cell/neighbors-before.json" &&
        curl -fsS --max-time 10 "http://127.0.0.1:$MPORT/metrics" >"$cell/metrics-before.prom" || return 1
    python3 - "$cell" "$PEERS" "$VRPS" <<'PY' || return 1
import json, sys
from pathlib import Path
p, peers, vrps = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
c = json.loads((p / "caches-before.json").read_text())
assert c["complete"] and c["omitted"] == 0 and len(c["caches"]) == 1, "cache list"
c = c["caches"][0]; a = c["accepted"]
assert c["connected"] and a["session_id"] is not None and a["serial"] is not None, "cache not accepted"
assert a["vrp_v4_count"] + a["vrp_v6_count"] == vrps, f"vrp counts {a}"
n = json.loads((p / "neighbors-before.json").read_text())
assert len(n) == peers and all(x["state"] == "Established" for x in n), "neighbors not all Established"
PY
    touch "$SCEN/pre/ack"
    (exec setsid python3 "$BIN/poll.py" "http://127.0.0.1:$MPORT/metrics" "http://127.0.0.1:$MPORT/readyz" "$DPID" \
        "$SCEN/poll-stop" "$cell/poll.tsv" "$cell/readyz.tsv" "$POLL_SECS") >"$cell/poll.err" 2>&1 &
    PPID_POLL=$!
    idle_epoch=$(date +%s.%N); idle_ticks=$(ticks)
    sleep "$IDLE_SECS"
    pre_lines=$(wc -l <"$cell/daemon.log")
    # Directory bind follows this atomic rename; replacing a bind-mounted file would not.
    cp "$F/delta-$n.json" "$CACHE/next.json" && chmod 644 "$CACHE/next.json"
    inj_epoch=$(date +%s.%N); inj_ticks=$(ticks)
    mv "$CACHE/next.json" "$CACHE/vrps.json"
    log "cell n=$n rep=$rep injected"
    wait_file "$SCEN/final/ready" $((HOLD_SECS + 120)) || return 1
    touch "$SCEN/poll-stop"; stop_group "$PPID_POLL" 5; PPID_POLL=''
    rbgp rpki caches >"$cell/caches-after.json"; rbgp neighbor >"$cell/neighbors-after.json"
    curl -fsS --max-time 10 "http://127.0.0.1:$MPORT/metrics" >"$cell/metrics-after.prom"
    touch "$SCEN/final/ack"
    t0=$SECONDS
    while kill -0 "$HPID" 2>/dev/null && [ $((SECONDS - t0)) -lt 60 ]; do sleep 0.2; done
    if kill -0 "$HPID" 2>/dev/null; then stop_group "$HPID" 15; hrc=124; else wait "$HPID"; hrc=$?; fi
    HPID=''
    grep -E '^(VmHWM|VmRSS):' "/proc/$DPID/status" >"$cell/vmhwm" 2>/dev/null
    stop_group "$DPID" 60; drc=$?
    DPID=''
    stop_rtr "$cell"
    find "$SCEN" -maxdepth 1 -type f -size -1M -exec cp {} "$cell/" \; 2>/dev/null
    rm -rf "$SCEN" "$CACHE"; SCEN='' CACHE=''
    cat >"$cell/cell.env" <<EOF
n=$n
rep=$rep
peers=$PEERS
idle_epoch=$idle_epoch
idle_ticks=$idle_ticks
inject_epoch=$inj_epoch
inject_ticks=$inj_ticks
pre_inject_log_lines=$pre_lines
clk_tck=$(getconf CLK_TCK)
harness_rc=$hrc
daemon_rc=$drc
EOF
    log "cell n=$n rep=$rep harness_rc=$hrc daemon_rc=$drc"
    [ "$hrc" = 0 ] && [ "$drc" = 0 ]
}

deferred=""
invalid=0
for rep in $(seq 1 "$REPEATS"); do
    order=$DELTAS
    [ $((rep % 2)) = 0 ] && order=$(printf '%s\n' $DELTAS | tac | paste -sd' ')
    for n in $order; do
        run_cell "$n" "$rep"
        rc=$?
        cleanup
        if [ "$rc" = 75 ]; then deferred="quiet gate failed before n=$n rep=$rep"; log "DEFER $deferred"; break 2; fi
        [ "$rc" = 0 ] || { invalid=$((invalid + 1)); log "cell n=$n rep=$rep INVALID (setup/run rc=$rc)"; }
    done
done
exec 7>&- 8>&-

python3 - "$OUT" "$DELTAS" "$TAIL_SECS" "$deferred" >"$OUT/summary.txt" <<'PY'
import datetime, json, os, re, statistics, sys
from pathlib import Path
out, deltas, tail, deferred = Path(sys.argv[1]), [int(x) for x in sys.argv[2].split()], float(sys.argv[3]), sys.argv[4]
def ts(s): return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
def metric_sum(text, prefix):
    return sum(float(l.rsplit(" ", 1)[1]) for l in text.splitlines() if l.startswith(prefix))
def tsv(path):
    lines = path.read_text().splitlines()
    head = lines[0].split("\t")
    return [dict(zip(head, l.split("\t"))) for l in lines[1:] if l]
results, bad = [], []
for cell in sorted((out / "raw").glob("n*-rep*")):
    try:
        env = dict(l.split("=", 1) for l in (cell / "cell.env").read_text().split())
        n, peers = int(env["n"]), int(env["peers"])
        assert env["harness_rc"] == "0" and env["daemon_rc"] == "0", f"harness_rc={env['harness_rc']} daemon_rc={env['daemon_rc']}"
        read = lambda name: json.loads((cell / name).read_text())
        b = read("caches-before.json")["caches"][0]; a = read("caches-after.json")
        assert a["complete"] and len(a["caches"]) == 1, "cache list after"
        a = a["caches"][0]; ba, aa = b["accepted"], a["accepted"]
        assert a["connected"] and (aa["protocol_version"], aa["session_id"]) == (ba["protocol_version"], ba["session_id"]), "RTR session changed"
        assert aa["serial"] == (ba["serial"] + 1) & 0xffffffff, f"serial {ba['serial']} -> {aa['serial']}"
        assert (aa["vrp_v4_count"], aa["vrp_v6_count"]) == (ba["vrp_v4_count"], ba["vrp_v6_count"]), "VRP counts changed"
        nb, na = read("neighbors-before.json"), read("neighbors-after.json")
        assert len(na) == peers and all(x["state"] == "Established" for x in na), "sessions not all Established after"
        assert {x["address"]: x["flap_count"] for x in nb} == {x["address"]: x["flap_count"] for x in na}, "flap counts changed"
        lines = (cell / "daemon.log").read_text(errors="replace").splitlines()[int(env["pre_inject_log_lines"]):]
        ev = []
        for l in lines:
            if l.startswith("{"):
                try:
                    j = json.loads(l); ev.append((ts(j["timestamp"]), j.get("fields", {})))
                except (ValueError, KeyError):
                    pass
        upd = [(t, f) for t, f in ev if f.get("message") == "RTR incremental update received" and (f.get("vrps_announced", 0) or f.get("vrps_withdrawn", 0))]
        assert len(upd) == 1 and upd[0][1]["vrps_announced"] == upd[0][1]["vrps_withdrawn"] == n, f"incremental updates {upd}"
        t0 = upd[0][0]  # the daemon accepted the delta: settle/CPU/readiness windows start here
        assert not any(f.get("message") == "RTR full table received" for _, f in ev), "full table after injection"
        rib = [(t, f) for t, f in ev if f.get("message") == "RPKI cache update re-validation complete"]
        assert len(rib) == 1 and rib[0][1]["mode"] == "delta" and rib[0][1]["changed_routes"] == 0, f"RIB revalidation {rib}"
        ref = [(t, f) for t, f in ev if f.get("message") == "processed validation-cache import-policy refresh" and f.get("dependency") == "Rpki"]
        assert len(ref) == 1, f"{len(ref)} Rpki refresh passes"
        rf = ref[0][1]
        assert rf["eligible"] == rf["refreshed"] == peers and rf["skipped_not_established"] == rf["skipped_state_unknown"] == rf["failures"] == 0, f"refresh pass {rf}"
        h = (cell / "reloadstall.log").read_text(errors="replace")
        assert f"final sessions_up {peers}/{peers} parse_errors=0" in h and "FAIL:" not in h, "harness final sessions/parse"
        acc = [tuple(map(int, x)) for x in re.findall(r"route_refresh_accounting,peer=(\d+),family=ipv[46],received=(\d+),suppressed=(\d+),completed=(\d+),sent_nlri=(\d+)", h)]
        assert len(acc) == 2 * peers and all(x[1] >= 1 for x in acc), f"refresh accounting rows {len(acc)}"
        mb, ma = (cell / "metrics-before.prom").read_text(), (cell / "metrics-after.prom").read_text()
        rdelta = {o: metric_sum(ma, f'bgp_validation_import_refreshes_total{{dependency="rpki",outcome="{o}"}}')
                  - metric_sum(mb, f'bgp_validation_import_refreshes_total{{dependency="rpki",outcome="{o}"}}')
                  for o in ("eligible", "refreshed", "skipped_not_established", "skipped_state_unknown", "failed")}
        assert rdelta["refreshed"] == peers, f"refresh counter delta {rdelta}"
        polls = [p for p in tsv(cell / "poll.tsv") if int(p["updates_received"]) >= 0]
        inj, inj_ticks, clk = float(env["inject_epoch"]), int(env["inject_ticks"]), int(env["clk_tck"])
        after = [p for p in polls if float(p["epoch"]) >= inj]
        base_upd = max((int(p["updates_received"]) for p in polls if float(p["epoch"]) < inj), default=None)
        assert base_upd is not None and after, "no polls around injection"
        last_inc = None; prev = base_upd
        for p in after:
            u = int(p["updates_received"])
            if u > prev: last_inc = float(p["epoch"])
            prev = u
        assert last_inc is not None, "no replayed UPDATE observed"
        assert float(after[-1]["epoch"]) - last_inc >= tail, "replay not quiet before the hold ended"
        settle_end = max(rib[0][0], ref[0][0], last_inc)
        start = [p for p in polls if float(p["epoch"]) <= t0][-1]
        row = next(p for p in after if float(p["epoch"]) >= settle_end)
        cpu_raw = (int(row["ticks"]) - int(start["ticks"])) / clk
        idle_rate = (inj_ticks - int(env["idle_ticks"])) / clk / (inj - float(env["idle_epoch"]))
        cpu_net = cpu_raw - idle_rate * (float(row["epoch"]) - float(start["epoch"]))
        rdy = [r for r in tsv(cell / "readyz.tsv") if t0 <= float(r["epoch"]) <= settle_end]
        lat = [float(r["latency_ms"]) for r in rdy]
        results.append(dict(n=n, rep=env["rep"], rtr_lag=t0 - inj, settle=settle_end - t0, reval=rib[0][0] - t0, refresh_pass=ref[0][0] - t0,
            last_update=last_inc - t0, cpu_raw=cpu_raw, cpu_net=cpu_net, idle_rate=idle_rate,
            rr_pdus=sum(x[1] for x in acc), rr_suppressed=sum(x[2] for x in acc), rr_completed=sum(x[3] for x in acc),
            sent_nlri=sum(x[4] for x in acc), peers_refreshed=len({x[0] for x in acc if x[1] > 0}),
            updates=prev - base_upd, refresh_counter=rdelta, revalidated=rib[0][1].get("routes_revalidated"),
            rib_elapsed_ms=rib[0][1].get("elapsed_ms"), ready_n=len(rdy), ready_non200=sum(r["status"] != "200" for r in rdy),
            ready_max_ms=max(lat, default=0.0), ready_over_250=sum(x > 250 for x in lat)))
    except Exception as e:
        bad.append(f"{cell.name}: {e!r}")
with open(out / "cells.json", "w") as f:
    json.dump(results, f, indent=1)
med = lambda xs: statistics.median(xs) if xs else float("nan")
parts, decline = [], True
for n in deltas:
    rs = [r for r in results if r["n"] == n]
    if not rs:
        decline = False; parts.append(f"N={n}: no valid cell"); continue
    s, c, cr = med([r["settle"] for r in rs]), med([r["cpu_net"] for r in rs]), med([r["cpu_raw"] for r in rs])
    decline &= c < 1 and s < 1
    parts.append(f"N={n} (n={len(rs)}): settle {s:.2f}s [reval {med([r['reval'] for r in rs]):.2f} refresh-pass "
                 f"{med([r['refresh_pass'] for r in rs]):.2f} last-UPDATE {med([r['last_update'] for r in rs]):.2f}], "
                 f"cpu net {c:.2f}s raw {cr:.2f}s, rtr lag {med([r['rtr_lag'] for r in rs]):.2f}s, refreshed peers {med([r['peers_refreshed'] for r in rs]):.0f}, "
                 f"ROUTE-REFRESH {med([r['rr_pdus'] for r in rs]):.0f} (suppressed {med([r['rr_suppressed'] for r in rs]):.0f}), "
                 f"replayed NLRI {med([r['sent_nlri'] for r in rs]):.0f}, daemon UPDATEs {med([r['updates'] for r in rs]):.0f}, "
                 f"readyz {sum(r['ready_n'] for r in rs)} samples non200={sum(r['ready_non200'] for r in rs)} "
                 f"max {max(r['ready_max_ms'] for r in rs):.0f}ms >250ms={sum(r['ready_over_250'] for r in rs)}")
raw_decline = all(med([r["cpu_raw"] for r in results if r["n"] == n]) < 1 and med([r["settle"] for r in results if r["n"] == n]) < 1
                  for n in deltas if any(r["n"] == n for r in results))
if decline:
    verdict = "KILL CPU/SETTLE LEGS MET (<1 CPU-s and <1 s at every N): decline-eligible if member-side replay is judged acceptable (maintainer call)"
else:
    verdict = "KILL NOT MET (>=1 CPU-s or >=1 s settle at some N, or a size lacks a valid cell): targeted-variant gate applies (<=20% of baseline peers at N=100, byte-identical member views)"
if raw_decline != decline:
    verdict += " | NOTE: verdict differs on raw CPU (scrape/idle correction is decisive)"
line = "VRP-delta full-fleet replay baseline | " + " | ".join(parts) + " | " + verdict
if bad:
    line += f" | {len(bad)} invalid cells: " + "; ".join(bad)
if deferred:
    line += f" | DEFERRED: {deferred}"
print(line)
sys.exit(0)
PY
prc=$?
code=0
[ "$prc" = 0 ] || code=5
[ "$invalid" -gt 0 ] && code=5
grep -q 'invalid cells' "$OUT/summary.txt" && code=5
[ -n "$deferred" ] && code=75
echo "$code" >"$OUT/exit_code"
log "END baseline rc=$code"
cat "$OUT/summary.txt" >&3
exit "$code"
