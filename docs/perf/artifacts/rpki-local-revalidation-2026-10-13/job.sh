#!/usr/bin/env bash
# Quiet-host A/B: RFC 9324 local re-evaluation (PR #3080 head 7dc289613) off vs on.
# Derived from the r1 job (<r1-queue-dir>/prep/job.sh, copy kept as
# prep/job-r1.orig.sh), itself derived from the validation-refresh baseline job (prep/job-baseline.orig.sh).
# Unchanged from r1 unless listed: shape, StayRTR pin, CPU pinning, injection, quiet gate, schedule
# (2 arms x N x REPEATS, arm order alternating), cgroup scope, member views and validity proof.
# r2 changes (diagnosis of the first run, 2026-10-12):
#   1. per-delta cgroup peak: the poller handles SIGTERM, writes cg-delta-peak.txt when the job
#      touches $SCEN/peak-read (BEFORE the view capture; the job waits for the file and invalidates
#      the cell without it), and writes cg-hold-peak.txt (through the views) on exit; after
#      poll-stop the job waits for the poller to exit on its own before any TERM;
#   2. summarizer: the rediag's B refresh-accounting rule (B valid with zero rows), every other rule
#      identical, cg-delta-peak.txt required again;
#   3. settle on the daemon log clock; the CPU-busy window ends at the next RTR update after the
#      injected one (the periodic, no-VRP-change serial query) and is reported only;
#   4. VRP fixtures with the Invalid share measured from a pinned real snapshot (fixtures/real,
#      prep/real-fixture.py); reloadstall carries a queue-local patch so convergence excludes
#      import-rejected base indexes (prep/reloadstall-import-rejected.patch, binaries/harness);
#   5. reject-retention size in the summary (retained, retained_rejects, B-A steady memory).
# Env (smoke only): JOB_DELTAS, JOB_REPEATS, JOB_QUIET override the receipt's "10 100 1000", 2, 1.
# Exit: 0 PASS, 1 FAIL, 2 setup, 4 INVALID (any invalid/missing cell), 75 deferred.
set -u
RES=<prep-dir>
QLOCK=<queue-lock>
WT=$RES/trees/pr3080
PIN=7dc289613dc680d4328806870da2701c59779c0e
BIN=$RES/binaries/pr3080
HBIN=$RES/binaries/harness
F=$RES/fixtures/real
IMAGE=rpki/stayrtr@sha256:cdb93c0b661d97179a5525e00caf7d9e693a04da3b9002f7e24bebb194d9a77b
OUT=${1:?usage: job.sh OUT_DIR}
PEERS=700 PREFIXES=400400 V4=200200 VRPS=500000
DELTAS=${JOB_DELTAS:-"10 100 1000"} REPEATS=${JOB_REPEATS:-2} HOLD_SECS=240 QUIET=${JOB_QUIET:-1}
IDLE_SECS=10 POLL_SECS=0.25 TAIL_SECS=10 VIEW_AT_SECS=60 BUSY_WINDOW_SECS=50
CONVERGE_TIMEOUT_SECS=900
DAEMON_CPUS=12-32,34-39 ENGINE_CPUS=40-63 RTR_CPUS=8-11
PORT=17983 MPORT=19183 RTR_PORT=13383 RTR_MPORT=19883
RTR_NAME=rlv-$$
[ ! -e "$OUT" ] || { echo "OUT exists: $OUT" >&2; exit 2; }
mkdir -p "$OUT"/{raw,quiet,bin}
exec 3>&1 >>"$OUT/job.log" 2>&1
log() { echo "$(date -u +%FT%TZ) $*"; }

DPID='' HPID='' PPID_POLL='' SCEN='' CACHE='' RTR_UP=''
stop_group() {
    local pid=$1 secs=${2:-60} i
    [ -n "$pid" ] || return 0
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null
    for ((i = 0; i < secs * 10; i++)); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    if kill -0 "$pid" 2>/dev/null; then log "pid $pid survived ${secs}s TERM; KILL"; kill -KILL -- "-$pid" 2>/dev/null; fi
    wait "$pid" 2>/dev/null
}
stop_rtr() {
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
fail() { cleanup; log "FAIL rc=$1 $2"; echo "$1" >"$OUT/exit_code"; echo "job FAILED rc=$1: $2" | tee "$OUT/summary.txt" >&3; exit "$1"; }
trap 'cleanup' EXIT
trap 'fail 4 "interrupted by signal"' INT TERM

exec 8>"$QLOCK"
flock -w 7200 8 || fail 75 "queue bench.lock busy for 2h"
log "START local-reval-r2 pin=$PIN peers=$PEERS prefixes=$PREFIXES deltas='$DELTAS' repeats=$REPEATS load=$(cut -d' ' -f1-3 /proc/loadavg)"
docker image inspect "$IMAGE" >/dev/null 2>&1 || fail 2 "StayRTR image not present locally"
[ "$(git -C "$WT" rev-parse HEAD)" = "$PIN" ] || fail 2 "$WT not at $PIN"
[ -z "$(git -C "$WT" status --porcelain)" ] || fail 2 "$WT dirty"
(cd "$BIN" && sha256sum -c --quiet SHA256SUMS) || fail 2 "prebuilt binaries changed"
(cd "$HBIN" && sha256sum -c --quiet SHA256SUMS) || fail 2 "patched harness changed"
(cd "$F" && sha256sum -c --quiet SHA256SUMS) || fail 2 "fixtures changed"
[ -s "$F/import-rejected.txt" ] || fail 2 "no import-rejected index list"
CELLPY=$WT/bench/scale/rpki-cell/rpki_cell.py
python3 "$CELLPY" check "$PEERS" "$PREFIXES" "$VRPS" "$V4" || fail 2 "fixture shape rejected"
for n in $DELTAS; do grep -q "withdrawals=$n announcements=$n " "$F/delta-$n.counts" || fail 2 "delta-$n counts"; done
cp "$BIN"/{rustbgpd,rbgp} "$HBIN/reloadstall" "$OUT/bin/"

# Poller: baseline columns + the scope's memory.current; resets its own memory.peak fd at start.
cat >"$OUT/bin/poll.py" <<'PY'
import os, sys, threading, time, urllib.request
import signal
murl, rurl, pid, stop, pout, rout, interval, cg, peak_out, peak_req, hold_out = sys.argv[1:12]
interval = float(interval)
term = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: term.set())
peak_fd = os.open(f"{cg}/memory.peak", os.O_RDWR)
os.write(peak_fd, b"reset")
def read_peak(path):
    os.lseek(peak_fd, 0, 0)
    value = os.read(peak_fd, 64).decode().strip()
    open(path + ".tmp", "w").write(value + "\n")
    os.rename(path + ".tmp", path)
def ticks():
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])
def ready():
    with open(rout, "w", buffering=1) as o:
        o.write("epoch\tstatus\tlatency_ms\n")
        while not os.path.exists(stop) and not term.is_set():
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
    o.write("epoch\tticks\tupdates_received\tscrape_ms\tcg_current\n")
    while not os.path.exists(stop) and not term.is_set():
        t = time.time(); total = -1
        if not os.path.exists(peak_out) and os.path.exists(peak_req):
            read_peak(peak_out)
        try:
            with urllib.request.urlopen(murl, timeout=5) as r:
                total = 0
                for line in r.read().decode().splitlines():
                    if line.startswith("bgp_messages_received_total{") and 'type="update"' in line:
                        total += int(float(line.rsplit(" ", 1)[1]))
        except Exception:
            total = -1
        try:
            tk = ticks(); cur = int(open(f"{cg}/memory.current").read())
        except OSError:
            break
        o.write(f"{t:.3f}\t{tk}\t{total}\t{(time.time() - t) * 1000:.1f}\t{cur}\n")
        term.wait(max(0, interval - (time.time() - t)))
read_peak(hold_out)
PY
# Canonical digest of one `rbgp --json rib advertised` output (JSON or JSON lines).
cat >"$OUT/bin/viewdigest.py" <<'PY'
import hashlib, json, sys
text = sys.stdin.read()
try:
    docs = [json.loads(text)]
except ValueError:
    docs = [json.loads(l) for l in text.splitlines() if l.strip()]
VOL = ("age", "time", "epoch", "uptime", "stamp")
def clean(x):
    if isinstance(x, dict):
        return {k: clean(v) for k, v in x.items() if not any(s in k.lower() for s in VOL)}
    if isinstance(x, list):
        return [clean(v) for v in x]
    return x
routes = []
for d in docs:
    if isinstance(d, dict) and d.get("type") == "route":
        routes.append(d["route"])
    elif isinstance(d, dict) and isinstance(d.get("routes"), list):
        routes += d["routes"]
    elif isinstance(d, list):
        routes += d
rows = sorted(json.dumps(clean(r), sort_keys=True) for r in routes)
print(hashlib.sha256("\n".join(rows).encode()).hexdigest(), len(rows))
PY

HARNESS_SRC=(bench/scale/reloadstall/gen-scenario.py bench/scale/reloadstall/src/main.rs
    bench/scale/rpki-cell/rpki_cell.py bench/scale/host-quiet.sh bench/scale/cgroup-memory.sh tests/soak/host-lock.sh tests/soak/fd-headroom.sh)
{
    echo "pin $PIN tree $(git -C "$WT" rev-parse 'HEAD^{tree}') (PR #3080 head)"
    cat "$BIN/toolchain.txt"
    (cd "$OUT/bin" && sha256sum rustbgpd rbgp reloadstall poll.py viewdigest.py)
    (cd "$WT" && sha256sum "${HARNESS_SRC[@]}")
    sha256sum "$(readlink -f "$0")" "$RES/prep/job-baseline.orig.sh" "$RES/prep/job-r1.orig.sh" \
        "$RES/prep/summarize.py" "$RES/prep/real-fixture.py" "$RES/prep/reloadstall-import-rejected.patch"
    cat "$HBIN/source-identity.txt"
    (cd "$F" && sha256sum ./*.json ./*.txt)
    python3 -c 'import json,sys; s=json.load(open(sys.argv[1])); print("vrp_snapshot", json.dumps(s["vrp_snapshot"])); print("invalid_share ipv4", s["ipv4"]["invalid_share"], "ipv6", s["ipv6"]["invalid_share"]); print("scenario", json.dumps(s["scenario"]))' "$F/share.json"
    echo "stayrtr $IMAGE id $(docker image inspect "$IMAGE" --format '{{.Id}}')"
    echo "daemon_cpus $DAEMON_CPUS engine_cpus $ENGINE_CPUS rtr_cpus $RTR_CPUS kernel $(uname -r) clk_tck $(getconf CLK_TCK)"
    echo "shape peers=$PEERS prefixes=$PREFIXES v4=$V4 vrps=$VRPS deltas='$DELTAS' repeats=$REPEATS hold=$HOLD_SECS idle=$IDLE_SECS poll=$POLL_SECS tail=$TAIL_SECS view_at=$VIEW_AT_SECS busy_window=$BUSY_WINDOW_SECS"
} >"$OUT/identity.txt"

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
# shellcheck source=/dev/null
source "$WT/bench/scale/cgroup-memory.sh"
export RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=900

ports_free() {
    python3 - "$@" <<'PY'
import socket, sys
held = []
for port in map(int, sys.argv[1:]):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); held.append(s)
PY
}
rbgp() { "$OUT/bin/rbgp" --addr "unix://$SCEN/grpc.sock" --json "$@"; }
wait_file() {
    local end=$((SECONDS + $2))
    until [ -f "$1" ]; do
        kill -0 "$DPID" 2>/dev/null || { log "daemon exited"; return 1; }
        kill -0 "$HPID" 2>/dev/null || { log "harness exited"; return 1; }
        [ "$SECONDS" -lt "$end" ] || { log "timeout waiting for $1"; return 1; }
        sleep 0.1
    done
}
ticks() { awk '{ print $14 + $15 }' "/proc/$DPID/stat"; }

run_cell() { # run_cell ARM N REP -> 0 ok, 1 invalid, 75 deferred
    local arm=$1 n=$2 rep=$3 cell=$OUT/raw/$1-n$2-rep$3 hrc=setup drc=setup t0 idle_epoch idle_ticks inj_epoch inj_ticks pre_lines cg peer fam
    local lr=false
    [ "$arm" = B ] && lr=true
    mkdir -p "$cell"
    if [ "$QUIET" = 1 ] && ! wait_for_rustbgpd_quiet_host "$OUT/quiet/$arm-n$n-rep$rep.tsv"; then
        return 75
    fi
    ports_free "$PORT" "$MPORT" "$RTR_PORT" "$RTR_MPORT" || { log "owned ports busy"; return 1; }
    SCEN=$(mktemp -d /tmp/rlv.XXXXXX) && chmod 700 "$SCEN" || return 1
    CACHE=$(mktemp -d /tmp/rlv-rtr.XXXXXX) && chmod 755 "$CACHE" || return 1
    mkdir "$SCEN/pre" "$SCEN/final"
    GEN_DUALSTACK=1 GEN_RPKI_CACHE=127.0.0.1:$RTR_PORT python3 "$WT/bench/scale/reloadstall/gen-scenario.py" \
        "$PEERS" "$SCEN" "$PORT" >"$cell/generator.log" 2>&1 || return 1
    sed -i "s#prometheus_addr = \"127.0.0.1:9179\"#prometheus_addr = \"127.0.0.1:$MPORT\"#" "$SCEN/config.toml"
    grep -q "127.0.0.1:$MPORT" "$SCEN/config.toml" || return 1
    [ "$(grep -cx '\[rpki\]' "$SCEN/config.toml")" = 1 ] || { log "expected one [rpki] table"; return 1; }
    sed -i "s#^\[rpki\]\$#[rpki]\nlocal_revalidation = $lr#" "$SCEN/config.toml"
    [ "$(grep -cx "local_revalidation = $lr" "$SCEN/config.toml")" = 1 ] || return 1
    "$OUT/bin/rustbgpd" --check --strict "$SCEN/config.toml" >"$cell/config-check.log" 2>&1 || return 1
    cp "$SCEN/config.toml" "$cell/config.toml"
    cp "$F/base.json" "$CACHE/vrps.json" && chmod 644 "$CACHE/vrps.json" || return 1
    memory_scope_launcher "$cell/cgroup-memory"
    [ "${#MEMORY_SCOPE[@]}" -gt 0 ] || { log "no systemd user scope"; return 1; }
    log "cell $arm n=$n rep=$rep start load=$(cut -d' ' -f1 /proc/loadavg)"
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
    (cd "$SCEN" && RUST_LOG=info exec setsid "${MEMORY_SCOPE[@]}" taskset -c "$DAEMON_CPUS" "$OUT/bin/rustbgpd" "$SCEN/config.toml") \
        >"$cell/daemon.log" 2>&1 &
    DPID=$!
    python3 "$CELLPY" wait-vrps "http://127.0.0.1:$MPORT/metrics" "$VRPS" 300 "$DPID" >"$cell/vrp-gate.log" 2>&1 || return 1
    (cd "$SCEN" && RELOADSTALL_DUALSTACK=1 RELOADSTALL_IPV4_PREFIXES=$V4 RELOADSTALL_IMPORT_REJECTED="$F/import-rejected.txt" \
        RELOADSTALL_PRE_CHURN_EVIDENCE_DIR="$SCEN/pre" RELOADSTALL_EVIDENCE_DIR="$SCEN/final" \
        exec setsid taskset -c "$ENGINE_CPUS" "$OUT/bin/reloadstall" "$PEERS" "$PREFIXES" "$PORT" "$DPID" \
        "$SCEN/member.rpol" "$SCEN/gen-a.rpol" "$SCEN/gen-b.rpol" 0 "$HOLD_SECS" --no-churn) \
        >"$cell/reloadstall.log" 2>&1 &
    HPID=$!
    wait_file "$SCEN/pre/ready" "$CONVERGE_TIMEOUT_SECS" || return 1
    cg=$(daemon_scope_cgroup "$DPID") || { log "daemon not in a fenced scope"; return 1; }
    printf 'cgroup=%s\nsteady_current=%s\nlifetime_peak_preinject=%s\nswap_max=%s\n' "$cg" \
        "$(cat "$cg/memory.current")" "$(cat "$cg/memory.peak")" "$(cat "$cg/memory.swap.max")" >"$cell/cgroup-pre.txt"
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
    (exec setsid python3 "$OUT/bin/poll.py" "http://127.0.0.1:$MPORT/metrics" "http://127.0.0.1:$MPORT/readyz" "$DPID" \
        "$SCEN/poll-stop" "$cell/poll.tsv" "$cell/readyz.tsv" "$POLL_SECS" "$cg" "$cell/cg-delta-peak.txt" "$SCEN/peak-read" \
        "$cell/cg-hold-peak.txt") >"$cell/poll.err" 2>&1 &
    PPID_POLL=$!
    idle_epoch=$(date +%s.%N); idle_ticks=$(ticks)
    sleep "$IDLE_SECS"
    pre_lines=$(wc -l <"$cell/daemon.log")
    cp "$F/delta-$n.json" "$CACHE/next.json" && chmod 644 "$CACHE/next.json"
    inj_epoch=$(date +%s.%N); inj_ticks=$(ticks)
    mv "$CACHE/next.json" "$CACHE/vrps.json"
    log "cell $arm n=$n rep=$rep injected"
    # Member views after settle, inside the hold (outside every timing window).
    sleep "$VIEW_AT_SECS"
    # Per-delta peak (idle window start .. now), read by the poller's own reset fd BEFORE the views.
    touch "$SCEN/peak-read"
    t0=$SECONDS
    until [ -s "$cell/cg-delta-peak.txt" ]; do
        kill -0 "$PPID_POLL" 2>/dev/null || { log "poller exited before the per-delta peak"; return 1; }
        [ $((SECONDS - t0)) -lt 15 ] || { log "no per-delta peak in 15s"; return 1; }
        sleep 0.1
    done
    python3 - "$cell/neighbors-before.json" >"$cell/view-peers.txt" <<'PY'
import json, sys
n = sorted(json.load(open(sys.argv[1])), key=lambda x: tuple(int(o) for o in x["address"].split(".")))
print(n[0]["address"]); print(n[len(n) // 2]["address"])
PY
    : >"$cell/views.tsv"
    while read -r peer; do
        for fam in ipv4_unicast ipv6_unicast; do
            printf '%s\t%s\t%s\n' "$peer" "$fam" "$(rbgp rib advertised "$peer" -a "$fam" | python3 "$OUT/bin/viewdigest.py")" >>"$cell/views.tsv"
        done
    done <"$cell/view-peers.txt"
    wait_file "$SCEN/final/ready" $((HOLD_SECS + 120)) || return 1
    touch "$SCEN/poll-stop"
    t0=$SECONDS
    while kill -0 "$PPID_POLL" 2>/dev/null && [ $((SECONDS - t0)) -lt 20 ]; do sleep 0.1; done
    if kill -0 "$PPID_POLL" 2>/dev/null; then log "poller still running 20s after poll-stop; TERM"; fi
    stop_group "$PPID_POLL" 10; PPID_POLL=''
    [ -s "$cell/cg-delta-peak.txt" ] && [ -s "$cell/cg-hold-peak.txt" ] || { log "cgroup peak files missing"; return 1; }
    rbgp rpki caches >"$cell/caches-after.json"; rbgp neighbor >"$cell/neighbors-after.json"
    curl -fsS --max-time 10 "http://127.0.0.1:$MPORT/metrics" >"$cell/metrics-after.prom"
    printf 'post_current=%s\nlifetime_peak=%s\nswap_peak=%s\n' "$(cat "$cg/memory.current")" "$(cat "$cg/memory.peak")" \
        "$(cat "$cg/memory.swap.peak" 2>/dev/null)" >"$cell/cgroup-post.txt"
    touch "$SCEN/final/ack"
    t0=$SECONDS
    while kill -0 "$HPID" 2>/dev/null && [ $((SECONDS - t0)) -lt 60 ]; do sleep 0.2; done
    if kill -0 "$HPID" 2>/dev/null; then stop_group "$HPID" 15; hrc=124; else wait "$HPID"; hrc=$?; fi
    HPID=''
    grep -E '^(VmHWM|VmRSS):' "/proc/$DPID/status" >"$cell/vmhwm" 2>/dev/null
    stop_group "$DPID" 60; drc=$?
    DPID=''
    stop_rtr "$cell"
    rm -rf "$SCEN" "$CACHE"; SCEN='' CACHE=''
    cat >"$cell/cell.env" <<EOF
arm=$arm
local_revalidation=$lr
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
    log "cell $arm n=$n rep=$rep harness_rc=$hrc daemon_rc=$drc"
    [ "$hrc" = 0 ] && [ "$drc" = 0 ]
}

# Schedule: rep 1 N ascending, pairs A,B / B,A / A,B; rep 2 N descending, pairs B,A / A,B / B,A.
SCHEDULE=()
k=0
for rep in $(seq 1 "$REPEATS"); do
    order=$DELTAS
    [ $((rep % 2)) = 0 ] && order=$(printf '%s\n' $DELTAS | tac | paste -sd' ')
    for n in $order; do
        if [ $((k % 2)) = 0 ]; then SCHEDULE+=("A:$n:$rep" "B:$n:$rep"); else SCHEDULE+=("B:$n:$rep" "A:$n:$rep"); fi
        k=$((k + 1))
    done
done
printf '%s\n' "${SCHEDULE[@]}" >"$OUT/schedule.txt"
deferred=""
invalid=0
for c in "${SCHEDULE[@]}"; do
    IFS=: read -r arm n rep <<<"$c"
    run_cell "$arm" "$n" "$rep"
    rc=$?
    cleanup
    if [ "$rc" = 75 ]; then deferred="quiet gate failed before $arm n=$n rep=$rep"; log "DEFER $deferred"; break; fi
    [ "$rc" = 0 ] || { invalid=$((invalid + 1)); log "cell $arm n=$n rep=$rep INVALID (setup/run rc=$rc)"; }
done
exec 7>&- 8>&-

python3 "$RES/prep/summarize.py" "$OUT" "$DELTAS" "$TAIL_SECS" "$BUSY_WINDOW_SECS" "$deferred" >"$OUT/summary.txt" 2>"$OUT/summary.err"
prc=$?
code=$prc
[ "$invalid" -gt 0 ] && code=4
[ -n "$deferred" ] && code=75
echo "$code" >"$OUT/exit_code"
log "END local-reval-r2 rc=$code (summary rc=$prc)"
cat "$OUT/summary.txt" >&3
exit "$code"
