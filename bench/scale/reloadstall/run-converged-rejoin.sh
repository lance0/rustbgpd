#!/usr/bin/env bash
# Converged-rejoin A/B campaign: the reloadstall GR-helper flapstorm
# (`--flapstorm K --converged-rejoin`) on the disjoint IPv4 route-server
# shape, BASE against HEAD, at a low and a high K, alternating arms.
#
# Usage: run-converged-rejoin.sh OUT_DIR BASE HEAD
#
# OUT_DIR must not exist. BASE and HEAD are refs to two different commits.
# Each arm's daemon is built at its ref in a detached worktree, into one
# shared target directory, with `cargo build --release --locked -p rustbgpd
# --bin rustbgpd`; the reloadstall harness and the scenario generator come
# from this checkout, so both arms face the same instrument. The worktrees
# and the shared target are removed on exit; the daemons stay in OUT_DIR/bin
# and their hashes in OUT_DIR/manifest.txt, and each daemon is re-hashed
# before every cell.
#
# Before the first cell, converged_rejoin.py writes OUT_DIR/campaign.json:
# the shape, the schedule's inputs and the bars. ACCEPTANCE names a JSON file
# that overrides the default bars (see converged_rejoin.py); write it before
# the run, because the verdict reads only campaign.json. Every cell runs a
# fresh daemon. Repetition 1, 3, ... runs base-Klo head-Klo head-Khi
# base-Khi; even repetitions run the reverse. Each cell keeps
# raw/ARM-kK-repN/{reloadstall.log,daemon.log,metrics-final.prom,...}; the
# campaign ends with `converged_rejoin.py analyze`, which writes samples.tsv,
# verdict.json and verdict.txt and fails closed on any missing or invalid
# cell.
#
# Knobs (env):
#   DAEMON_CPUS ENGINE_CPUS  disjoint CPU lists for the daemon and the
#                            harness (required)
#   BUILD_CPUS               CPU list for the builds (default: inherited)
#   PEERS=700 PREFIXES=400400 KS="1 50" REPEATS=3 ROUNDS=3 CONTROL_SECS=30
#   ACCEPTANCE               bar overrides, a JSON file (default: none)
#   QUIET=1                  canonical quiet-host gate before every cell
#                            (bench/scale/host-quiet.sh); SMOKE defaults it to 0
#   RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=3600  quiet-gate wait per cell
#   CELL_TIMEOUT_SECS=3600   harness wall-clock limit per cell
#   PORT=17986 MPORT=19186   BGP listener and metrics/readiness port
#   SMOKE=1                  pipeline check, not a measurement: 16 peers x
#                            1,600 prefixes, KS="1 2", one repetition of one
#                            round, unless overridden
#   DRY_RUN=1                print the arms, the shape and every command,
#                            then exit without locking, building or writing
#
# The shared host lock (tests/soak/host-lock.sh) is held from before the
# first build to exit; a busy host exits 75. Exit: 0 PASS (or a valid SMOKE
# run, which judges no bars), 1 FAIL, 2 usage, setup or build failure,
# 4 INVALID, 75 host busy or a quiet gate timed out.
set -euo pipefail

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2
    exit 2
}

[[ $# -eq 3 ]] || usage
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
OUT=$(realpath -m "$1")
BASE_REF=$2
HEAD_REF=$3
PY=$HERE/converged_rejoin.py

SMOKE=${SMOKE:-}
if [[ -n $SMOKE ]]; then
    PEERS=${PEERS:-16} PREFIXES=${PREFIXES:-1600} KS=${KS:-1 2} REPEATS=${REPEATS:-1}
    ROUNDS=${ROUNDS:-1} CONTROL_SECS=${CONTROL_SECS:-1} QUIET=${QUIET:-0}
else
    PEERS=${PEERS:-700} PREFIXES=${PREFIXES:-400400} KS=${KS:-1 50} REPEATS=${REPEATS:-3}
    ROUNDS=${ROUNDS:-3} CONTROL_SECS=${CONTROL_SECS:-30} QUIET=${QUIET:-1}
fi
CELL_TIMEOUT_SECS=${CELL_TIMEOUT_SECS:-3600}
PORT=${PORT:-17986}
MPORT=${MPORT:-19186}
DAEMON_CPUS=${DAEMON_CPUS:-}
ENGINE_CPUS=${ENGINE_CPUS:-}
BUILD_CPUS=${BUILD_CPUS:-}
ACCEPTANCE=${ACCEPTANCE:-}
DRY_RUN=${DRY_RUN:-}
export RUSTBGPD_HOST_QUIET_TIMEOUT_SECS=${RUSTBGPD_HOST_QUIET_TIMEOUT_SECS:-3600}
unset CARGO_TARGET_DIR RUSTFLAGS

for knob in PEERS PREFIXES REPEATS ROUNDS CONTROL_SECS CELL_TIMEOUT_SECS PORT MPORT; do
    [[ ${!knob} =~ ^[0-9]+$ ]] || { echo "$knob must be a non-negative integer" >&2; exit 2; }
done
[[ $QUIET == 0 || $QUIET == 1 ]] || { echo "QUIET must be 0 or 1" >&2; exit 2; }
read -r KLO KHI EXTRA <<<"$KS"
[[ $KLO =~ ^[0-9]+$ && $KHI =~ ^[0-9]+$ && -z ${EXTRA:-} ]] || { echo "KS must be two integers: '$KS'" >&2; exit 2; }
# reloadstall reserves its last 8 stubs as churners: K is 1..PEERS-8.
((1 <= KLO && KLO < KHI && KHI <= PEERS - 8)) || { echo "KS needs 1 <= KLO < KHI <= PEERS-8: '$KS'" >&2; exit 2; }
[[ -z $ACCEPTANCE || -f $ACCEPTANCE ]] || { echo "ACCEPTANCE is not a file: $ACCEPTANCE" >&2; exit 2; }
[[ -n $DAEMON_CPUS && -n $ENGINE_CPUS ]] || {
    echo "set DAEMON_CPUS and ENGINE_CPUS (disjoint CPU lists, e.g. DAEMON_CPUS=8-31 ENGINE_CPUS=32-47)" >&2
    exit 2
}
expand_cpus() { # 2-4,7 -> one CPU per line
    local part
    [[ $1 =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || { echo "bad CPU list: $1" >&2; return 1; }
    IFS=, read -r -a parts <<<"$1"
    for part in "${parts[@]}"; do seq "${part%-*}" "${part#*-}"; done
}
for list in "$DAEMON_CPUS" "$ENGINE_CPUS" ${BUILD_CPUS:+"$BUILD_CPUS"}; do
    expand_cpus "$list" >/dev/null || exit 2
    taskset -c "$list" true 2>/dev/null || { echo "CPU list not usable here: $list" >&2; exit 2; }
done
shared=$(comm -12 <(expand_cpus "$DAEMON_CPUS" | sort -u) <(expand_cpus "$ENGINE_CPUS" | sort -u) | paste -sd,)
[[ -z $shared ]] || { echo "DAEMON_CPUS and ENGINE_CPUS overlap: $shared" >&2; exit 2; }

for tool in cargo comm curl flock git python3 setsid sha256sum taskset; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
resolve() {
    git -C "$REPO" rev-parse --verify -q "$1^{commit}" || { echo "unknown ref: $1" >&2; exit 2; }
}
BASE_SHA=$(resolve "$BASE_REF")
HEAD_SHA=$(resolve "$HEAD_REF")
[[ $BASE_SHA != "$HEAD_SHA" ]] || { echo "BASE and HEAD are the same commit" >&2; exit 2; }
[[ ! -e $OUT ]] || { echo "OUT_DIR exists; use a new directory: $OUT" >&2; exit 2; }

init_args=(--peers "$PEERS" --prefixes "$PREFIXES" --ks "$KLO,$KHI" --repeats "$REPEATS" --rounds "$ROUNDS"
    --quiet "$QUIET")
[[ -z $SMOKE ]] || init_args+=(--smoke)
[[ -z $ACCEPTANCE ]] || init_args+=(--acceptance "$(realpath "$ACCEPTANCE")")
cell_cmds() { # cell_cmds ARM K SCEN DAEMON: the generator, daemon and harness command lines
    printf '%s\n' \
        "GEN_CONVERGED_REJOIN=1 python3 $REPO/bench/scale/reloadstall/gen-scenario.py $PEERS $3 $PORT" \
        "setsid taskset -c $DAEMON_CPUS $4 $3/config.toml" \
        "RELOADSTALL_REJOIN_METRICS_ADDR=127.0.0.1:$MPORT setsid taskset -c $ENGINE_CPUS reloadstall $PEERS $PREFIXES $PORT DAEMON_PID $3/member.rpol $3/gen-a.rpol $3/gen-b.rpol 0 $CONTROL_SECS --flapstorm $2 --flap-rounds $ROUNDS --converged-rejoin"
}

if [[ -n $DRY_RUN ]]; then
    dry=$(mktemp -d "${TMPDIR:-/tmp}/converged-rejoin-dry.XXXXXX")
    trap 'rm -rf "$dry"' EXIT
    python3 "$PY" init "$dry" "${init_args[@]}" || exit 2
    echo "# dry run: nothing is locked, built or written"
    echo "base=$BASE_REF $BASE_SHA"
    echo "head=$HEAD_REF $HEAD_SHA"
    echo "out=$OUT smoke=${SMOKE:+1} quiet=$QUIET daemon_cpus=$DAEMON_CPUS engine_cpus=$ENGINE_CPUS"
    echo "# campaign.json:"
    cat "$dry/campaign.json"
    echo "acquire_rustbgpd_host_lock"
    echo "cargo build --profile scale --locked -p reloadstall   # this checkout"
    for arm in base head; do
        sha_var=${arm^^}_SHA
        echo "git worktree add --detach $OUT/trees/$arm ${!sha_var}"
        echo "CARGO_TARGET_DIR=$OUT/target cargo build --release --locked -p rustbgpd --bin rustbgpd   # $arm"
    done
    python3 "$PY" schedule "$dry" | while read -r arm k rep; do
        echo "# cell $arm-k$k-rep$rep"
        [[ $QUIET == 0 ]] || echo "wait_for_rustbgpd_quiet_host $OUT/quiet/$arm-k$k-rep$rep.tsv"
        cell_cmds "$arm" "$k" SCEN "$OUT/bin/$arm/rustbgpd"
    done
    echo "python3 $PY analyze $OUT"
    exit 0
fi

# shellcheck source=tests/soak/host-lock.sh
source "$REPO/tests/soak/host-lock.sh"
acquire_rustbgpd_host_lock || exit $?
# shellcheck source=tests/soak/fd-headroom.sh
source "$REPO/tests/soak/fd-headroom.sh"
require_fd_headroom || exit 2
# shellcheck source=bench/scale/host-quiet.sh
source "$REPO/bench/scale/host-quiet.sh"
# shellcheck source=bench/scale/provenance.sh
source "$REPO/bench/scale/provenance.sh"

# Sample the invoking checkout before OUT_DIR exists, so an OUT_DIR inside
# the repository cannot make a clean checkout look dirty.
DRIVER_STATE="$(git -C "$REPO" rev-parse HEAD) dirty=$(git -C "$REPO" status --porcelain | wc -l)"
mkdir -p "$(dirname "$OUT")"
mkdir "$OUT"
mkdir "$OUT/raw" "$OUT/quiet" "$OUT/bin" "$OUT/trees"
[[ -z $SMOKE ]] || echo "pipeline check at a reduced shape; not a measurement" >"$OUT/SMOKE"
python3 "$PY" init "$OUT" "${init_args[@]}" || exit 2
SCEN='' DPID='' HPID=''

log() { echo "$(date -u +%FT%TZ) $*" | tee -a "$OUT/progress.txt"; }
stop_group() { # stop_group PID SECS: TERM the process group, KILL after SECS; returns the exit status
    local pid=$1 secs=$2 i rc=0
    [[ -n $pid ]] || return 0
    kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
    for ((i = 0; i < secs * 10; i++)); do kill -0 "$pid" 2>/dev/null || break; sleep .1; done
    if kill -0 "$pid" 2>/dev/null; then
        log "pid $pid survived ${secs}s TERM; KILL"
        kill -KILL -- "-$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || rc=$?
    return "$rc"
}
# shellcheck disable=SC2317 # invoked by the EXIT trap
cleanup() {
    local rc=$? arm
    trap - EXIT INT TERM
    stop_group "$HPID" 15 || true
    stop_group "$DPID" 60 || true
    [[ -z $SCEN ]] || rm -rf "$SCEN"
    rm -rf "$OUT/target"
    for arm in base head; do
        [[ ! -d $OUT/trees/$arm ]] || git -C "$REPO" worktree remove --force "$OUT/trees/$arm" || true
    done
    rmdir "$OUT/trees" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

PIN_BUILD=()
[[ -z $BUILD_CPUS ]] || PIN_BUILD=(taskset -c "$BUILD_CPUS")
build_failed() { log "STOP: $1 build failed (see $OUT/build.log)"; exit 2; }
log "build reloadstall from this checkout"
(cd "$REPO" && "${PIN_BUILD[@]}" cargo build --profile scale --locked -p reloadstall) >>"$OUT/build.log" 2>&1 \
    || build_failed reloadstall
cp "$REPO/target/scale/reloadstall" "$OUT/bin/reloadstall"
HARNESS=$OUT/bin/reloadstall
declare -A BIN=() DAEMON_SHA=()
for arm in base head; do
    sha_var=${arm^^}_SHA
    log "build $arm daemon at ${!sha_var}"
    git -C "$REPO" worktree add -q --detach "$OUT/trees/$arm" "${!sha_var}"
    (cd "$OUT/trees/$arm" && CARGO_TARGET_DIR="$OUT/target" "${PIN_BUILD[@]}" \
        cargo build --release --locked -p rustbgpd --bin rustbgpd) >>"$OUT/build.log" 2>&1 || build_failed "$arm"
    [[ -z $(git -C "$OUT/trees/$arm" status --porcelain) ]] || { log "STOP: $arm tree dirty after build"; exit 2; }
    mkdir "$OUT/bin/$arm"
    cp "$OUT/target/release/rustbgpd" "$OUT/bin/$arm/rustbgpd"
    BIN[$arm]=$OUT/bin/$arm/rustbgpd
    DAEMON_SHA[$arm]=$(provenance_sha256_file "${BIN[$arm]}")
done
rm -rf "$OUT/target"
for arm in base head; do git -C "$REPO" worktree remove --force "$OUT/trees/$arm"; done
rmdir "$OUT/trees"
{
    echo "base=$BASE_REF $BASE_SHA tree=$(git -C "$REPO" rev-parse "$BASE_SHA^{tree}") daemon_sha256=${DAEMON_SHA[base]}"
    echo "head=$HEAD_REF $HEAD_SHA tree=$(git -C "$REPO" rev-parse "$HEAD_SHA^{tree}") daemon_sha256=${DAEMON_SHA[head]}"
    echo "diffstat=$(git -C "$REPO" diff --shortstat "$BASE_SHA" "$HEAD_SHA")"
    echo "driver=$DRIVER_STATE"
    echo "reloadstall_sha256=$(provenance_sha256_file "$HARNESS")"
    echo "gen_scenario_sha256=$(provenance_sha256_file "$REPO/bench/scale/reloadstall/gen-scenario.py")"
    echo "analyzer_sha256=$(provenance_sha256_file "$PY")"
    echo "rustc=$(rustc --version)"
    echo "kernel=$(uname -r)"
    echo "peers=$PEERS prefixes=$PREFIXES ks=$KLO,$KHI repeats=$REPEATS rounds=$ROUNDS control_secs=$CONTROL_SECS quiet=$QUIET smoke=${SMOKE:+1}"
    echo "daemon_cpus=$DAEMON_CPUS engine_cpus=$ENGINE_CPUS"
    echo "loadavg_start=$(cut -d' ' -f1-3 /proc/loadavg)"
} >"$OUT/manifest.txt"

ports_free() {
    python3 - "$@" <<'PY'
import socket, sys
held = []
for port in map(int, sys.argv[1:]):
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); held.append(s)
PY
}

run_cell() { # run_cell ARM K REP -> 0 valid exits, 1 failed, 75 quiet gate timed out
    local arm=$1 k=$2 rep=$3 name=$1-k$2-rep$3 cell hrc drc t0
    cell=$OUT/raw/$name
    mkdir "$cell"
    if [[ $QUIET == 1 ]] && ! wait_for_rustbgpd_quiet_host "$OUT/quiet/$name.tsv"; then
        return 75
    fi
    provenance_require_sha256 "${BIN[$arm]}" "${DAEMON_SHA[$arm]}" || { log "$name: $arm daemon hash changed"; return 1; }
    ports_free "$PORT" "$MPORT" 2>"$cell/ports.log" || { log "$name: port $PORT or $MPORT busy"; return 1; }
    SCEN=$(mktemp -d "${TMPDIR:-/tmp}/converged-rejoin.XXXXXX")
    GEN_CONVERGED_REJOIN=1 python3 "$REPO/bench/scale/reloadstall/gen-scenario.py" "$PEERS" "$SCEN" "$PORT" \
        >"$cell/generator.log" 2>&1 || return 1
    sed -i "s#prometheus_addr = \"127.0.0.1:9179\"#prometheus_addr = \"127.0.0.1:$MPORT\"#" "$SCEN/config.toml"
    grep -q "127.0.0.1:$MPORT" "$SCEN/config.toml" || { log "$name: metrics address not rewritten"; return 1; }
    "${BIN[$arm]}" --check "$SCEN/config.toml" >"$cell/config-check.log" 2>&1 || return 1
    log "$name start load=$(cut -d' ' -f1-3 /proc/loadavg)"
    (cd "$SCEN" && exec setsid taskset -c "$DAEMON_CPUS" "${BIN[$arm]}" "$SCEN/config.toml") >"$cell/daemon.log" 2>&1 &
    DPID=$!
    t0=$SECONDS
    until curl -fsS --max-time 1 "http://127.0.0.1:$MPORT/readyz" >/dev/null 2>&1; do
        kill -0 "$DPID" 2>/dev/null || { log "$name: daemon exited at start"; return 1; }
        ((SECONDS - t0 < 60)) || { log "$name: daemon not ready in 60 s"; return 1; }
        sleep .2
    done
    (cd "$SCEN" && RELOADSTALL_REJOIN_METRICS_ADDR=127.0.0.1:$MPORT exec setsid taskset -c "$ENGINE_CPUS" \
        "$HARNESS" "$PEERS" "$PREFIXES" "$PORT" "$DPID" "$SCEN/member.rpol" "$SCEN/gen-a.rpol" \
        "$SCEN/gen-b.rpol" 0 "$CONTROL_SECS" --flapstorm "$k" --flap-rounds "$ROUNDS" --converged-rejoin) \
        >"$cell/reloadstall.log" 2>&1 &
    HPID=$!
    t0=$SECONDS
    while kill -0 "$HPID" 2>/dev/null; do
        kill -0 "$DPID" 2>/dev/null || { log "$name: daemon exited during the harness"; break; }
        ((SECONDS - t0 < CELL_TIMEOUT_SECS)) || { log "$name: cell timeout ${CELL_TIMEOUT_SECS}s"; break; }
        sleep 1
    done
    if kill -0 "$HPID" 2>/dev/null; then
        stop_group "$HPID" 15 || true
        hrc=124
    else
        hrc=0
        wait "$HPID" || hrc=$?
    fi
    HPID=''
    curl -fsS --max-time 5 "http://127.0.0.1:$MPORT/metrics" >"$cell/metrics-final.prom" 2>/dev/null || true
    grep -E '^(VmHWM|VmRSS):' "/proc/$DPID/status" >"$cell/vmhwm" 2>/dev/null || true
    drc=0
    stop_group "$DPID" 60 || drc=$?
    DPID=''
    cp "$SCEN/config.toml" "$cell/config.toml"
    rm -rf "$SCEN"
    SCEN=''
    printf '%s\t%s\t%s\t%s\t%s\n' "$arm" "$k" "$rep" "$hrc" "$drc" >>"$OUT/runs.tsv"
    log "$name harness_rc=$hrc daemon_rc=$drc"
    [[ $hrc == 0 && $drc == 0 ]]
}

printf 'arm\tk\trep\tharness_rc\tdaemon_rc\n' >"$OUT/runs.tsv"
python3 "$PY" schedule "$OUT" >"$OUT/schedule.txt"
deferred=''
while read -r arm k rep; do
    rc=0
    run_cell "$arm" "$k" "$rep" </dev/null || rc=$?
    stop_group "$HPID" 15 || true
    stop_group "$DPID" 60 || true
    HPID='' DPID=''
    [[ -z $SCEN ]] || rm -rf "$SCEN"
    SCEN=''
    if ((rc == 75)); then
        deferred="quiet gate timed out before $arm-k$k-rep$rep"
        log "STOP: $deferred"
        break
    fi
    if ((rc != 0)) && ! grep -q "^$arm	$k	$rep	" "$OUT/runs.tsv"; then
        printf '%s\t%s\t%s\tsetup\tsetup\n' "$arm" "$k" "$rep" >>"$OUT/runs.tsv"
    fi
done <"$OUT/schedule.txt"

arc=0
python3 "$PY" analyze "$OUT" >"$OUT/verdict.txt" 2>&1 || arc=$?
cat "$OUT/verdict.txt"
log "analyzer rc=$arc${deferred:+ ($deferred)}"
[[ -z $deferred ]] || exit 75
exit "$arc"
