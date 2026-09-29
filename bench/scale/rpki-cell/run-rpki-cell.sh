#!/usr/bin/env bash
# RPKI convergence A/B cell: the reloadstall route-server initial convergence
# with a large static VRP table loaded from a real RTR cache, BASE against
# HEAD, alternating arms.
#
# Usage: run-rpki-cell.sh OUT_DIR BASE HEAD
#
# OUT_DIR must not exist. BASE and HEAD are refs to two different commits.
# Each arm's daemon is built from a detached worktree at its ref into one
# shared target directory; the reloadstall harness, the scenario generator
# and the VRP fixture come from this checkout, so both arms face the same
# instrument. The worktrees and the shared target are removed on exit; the
# daemon hashes stay in OUT_DIR/manifest.txt.
#
# The fixture (rpki_cell.py vrps) makes every announced /24 Valid for its
# owning stub and pads the table to VRPS entries with prefixes no stub
# announces. It is served by a digest-pinned StayRTR container on RTR_CPUS.
# Before each daemon starts, the driver waits for the RTR port to listen; the
# cell config sets `retry_interval = 5`, because a first connect that races
# the cache start otherwise waits the 600 s default before retrying. The
# daemon must report bgp_rpki_vrp_count >= VRPS within VRP_TIMEOUT_SECS before
# the harness sends any route, or the campaign stops with exit 1.
#
# Each run is one cell per arm, base first on odd runs and head first on even
# runs. A cell records the rib_actor_work{route_chunk} sum and count, the
# daemon's CPU time (utime + stime) and the wall time from harness start to
# its convergence evidence boundary. The campaign ends by writing cells.csv
# and summary.txt (per-arm median, range and head-vs-base delta) with
# rpki_cell.py summarize, which rejects any incomplete cell.
#
# Knobs (env):
#   DAEMON_CPUS            CPU list for the daemon (required)
#   RTR_CPUS               CPU list for StayRTR, disjoint from the daemon and
#                          harness lists (required)
#   ENGINE_CPUS            CPU list for the reloadstall harness (default:
#                          DAEMON_CPUS, as in the original measurement)
#   BUILD_CPUS             CPU list for the builds (default: inherited)
#   N_PEERS=700 TOTAL_PREFIXES=400400 VRPS=500000 RUNS=3
#   VRP_TIMEOUT_SECS=300   wait for the full VRP table, per cell
#   CELL_TIMEOUT_SECS=900  wait for convergence, per cell
#   SMOKE=1                pipeline check, not a measurement: 10 peers x
#                          2,000 prefixes with 5,000 VRPs unless overridden
#   RPKI_CELL_LOCKS        space-separated extra lock files held, nonblocking,
#                          for the whole run (for example a timing-core lock);
#                          contention exits 75
#
# The shared host lock (tests/soak/host-lock.sh) is held from before the
# first build to exit; a busy host exits 75. Exit: 0 all cells complete,
# 1 a build, cell or extraction failed, 2 usage or setup.
set -euo pipefail

usage() {
    sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//' >&2
    exit 2
}
die() {
    echo "run-rpki-cell: $*" >&2
    exit 1
}

[[ $# -eq 3 ]] || usage
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
OUT=$(realpath -m "$1")
BASE_REF=$2
HEAD_REF=$3

STAYRTR_IMAGE=rpki/stayrtr@sha256:cdb93c0b661d97179a5525e00caf7d9e693a04da3b9002f7e24bebb194d9a77b
PORT=1794
MPORT=9184
RTR_PORT=3324
RTR_NAME=rustbgpd-rpki-cell-$$

SMOKE=${SMOKE:-}
if [[ -n $SMOKE ]]; then
    N_PEERS=${N_PEERS:-10} TOTAL_PREFIXES=${TOTAL_PREFIXES:-2000} VRPS=${VRPS:-5000}
else
    N_PEERS=${N_PEERS:-700} TOTAL_PREFIXES=${TOTAL_PREFIXES:-400400} VRPS=${VRPS:-500000}
fi
RUNS=${RUNS:-3}
VRP_TIMEOUT_SECS=${VRP_TIMEOUT_SECS:-300}
CELL_TIMEOUT_SECS=${CELL_TIMEOUT_SECS:-900}
DAEMON_CPUS=${DAEMON_CPUS:-}
RTR_CPUS=${RTR_CPUS:-}
ENGINE_CPUS=${ENGINE_CPUS:-$DAEMON_CPUS}
BUILD_CPUS=${BUILD_CPUS:-}
unset CARGO_TARGET_DIR RUSTFLAGS

for knob in N_PEERS TOTAL_PREFIXES VRPS RUNS VRP_TIMEOUT_SECS CELL_TIMEOUT_SECS; do
    [[ ${!knob} =~ ^[1-9][0-9]*$ ]] || { echo "$knob must be a positive integer" >&2; exit 2; }
done
[[ -n $DAEMON_CPUS && -n $RTR_CPUS ]] || {
    echo "set DAEMON_CPUS and RTR_CPUS (disjoint CPU lists, e.g. DAEMON_CPUS=2-9 RTR_CPUS=10-11)" >&2
    exit 2
}
expand_cpus() { # 2-4,7 -> one CPU per line
    local part
    [[ $1 =~ ^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$ ]] || { echo "bad CPU list: $1" >&2; return 1; }
    IFS=, read -r -a parts <<<"$1"
    for part in "${parts[@]}"; do seq "${part%-*}" "${part#*-}"; done
}
for list in "$DAEMON_CPUS" "$ENGINE_CPUS" "$RTR_CPUS" ${BUILD_CPUS:+"$BUILD_CPUS"}; do
    expand_cpus "$list" >/dev/null || exit 2
    taskset -c "$list" true 2>/dev/null || { echo "CPU list not usable here: $list" >&2; exit 2; }
done
shared=$(comm -12 <(expand_cpus "$RTR_CPUS" | sort -u) \
    <({ expand_cpus "$DAEMON_CPUS"; expand_cpus "$ENGINE_CPUS"; } | sort -u) | paste -sd,)
[[ -z $shared ]] || { echo "RTR_CPUS overlaps the daemon or harness CPUs: $shared" >&2; exit 2; }

for tool in cargo comm curl docker flock git python3 setsid sha256sum taskset; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done
resolve() {
    git -C "$REPO" rev-parse --verify -q "$1^{commit}" || { echo "unknown ref: $1" >&2; exit 2; }
}
BASE_SHA=$(resolve "$BASE_REF")
HEAD_SHA=$(resolve "$HEAD_REF")
[[ $BASE_SHA != "$HEAD_SHA" ]] || { echo "BASE and HEAD are the same commit" >&2; exit 2; }
[[ ! -e $OUT ]] || { echo "OUT_DIR exists; use a new directory: $OUT" >&2; exit 2; }
python3 "$HERE/rpki_cell.py" vrps "$N_PEERS" "$TOTAL_PREFIXES" "$VRPS" /dev/null || exit 2

for lock in ${RPKI_CELL_LOCKS:-}; do
    exec {fd}>>"$lock"
    flock -n "$fd" || { echo "lock busy: $lock" >&2; exit 75; }
done
# shellcheck source=tests/soak/host-lock.sh
source "$REPO/tests/soak/host-lock.sh"
acquire_rustbgpd_host_lock || exit $?
# shellcheck source=tests/soak/fd-headroom.sh
source "$REPO/tests/soak/fd-headroom.sh"
require_fd_headroom

mkdir -p "$(dirname "$OUT")"
mkdir "$OUT"
mkdir "$OUT/cells" "$OUT/bin" "$OUT/trees"
[[ -z $SMOKE ]] || echo "pipeline check at a reduced shape; not a measurement" >"$OUT/SMOKE"
SCEN=$(mktemp -d "${TMPDIR:-/tmp}/rpki-cell.XXXXXX")
DPID='' HPID=''

stop_group() { # stop_group PID: TERM the process group, KILL after 30 s
    [[ -n $1 ]] || return 0
    kill -TERM -- "-$1" 2>/dev/null || true
    for _ in $(seq 1 300); do kill -0 "$1" 2>/dev/null || break; sleep .1; done
    kill -KILL -- "-$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}
# shellcheck disable=SC2317 # invoked by the EXIT trap
cleanup() {
    local rc=$? arm
    trap - EXIT INT TERM
    stop_group "$HPID"
    stop_group "$DPID"
    docker rm -f "$RTR_NAME" >/dev/null 2>&1 || true
    rm -rf "$SCEN" "$OUT/target"
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
cargo_build() { # cargo_build DIR ARGS...: release build into the shared target
    local dir=$1
    shift
    (cd "$dir" && CARGO_TARGET_DIR="$OUT/target" "${PIN_BUILD[@]}" \
        cargo build --release --locked "$@") >>"$OUT/build.log" 2>&1
}
sha() { sha256sum "$1" | cut -c1-64; }

echo "build reloadstall from this checkout"
(cd "$REPO" && "${PIN_BUILD[@]}" cargo build --release --locked \
    --manifest-path bench/scale/reloadstall/Cargo.toml) >>"$OUT/build.log" 2>&1 \
    || die "reloadstall build failed (see $OUT/build.log)"
cp "$REPO/bench/scale/target/release/reloadstall" "$OUT/bin/reloadstall"
HARNESS=$OUT/bin/reloadstall
declare -A BIN=()
for arm in base head; do
    sha_var=${arm^^}_SHA
    echo "build $arm daemon at ${!sha_var}"
    git -C "$REPO" worktree add -q --detach "$OUT/trees/$arm" "${!sha_var}"
    cargo_build "$OUT/trees/$arm" -p rustbgpd || die "$arm build failed (see $OUT/build.log)"
    [[ -z $(git -C "$OUT/trees/$arm" status --porcelain) ]] || die "$arm tree dirty after build"
    mkdir "$OUT/bin/$arm"
    cp "$OUT/target/release/rustbgpd" "$OUT/bin/$arm/rustbgpd"
    BIN[$arm]=$OUT/bin/$arm/rustbgpd
done

python3 "$HERE/rpki_cell.py" vrps "$N_PEERS" "$TOTAL_PREFIXES" "$VRPS" "$OUT/vrps.json"
{
    echo "base=$BASE_REF $BASE_SHA daemon_sha256=$(sha "${BIN[base]}")"
    echo "head=$HEAD_REF $HEAD_SHA daemon_sha256=$(sha "${BIN[head]}")"
    echo "driver=$(git -C "$REPO" rev-parse HEAD) dirty=$(git -C "$REPO" status --porcelain | wc -l)"
    echo "reloadstall_sha256=$(sha "$HARNESS")"
    echo "vrps_sha256=$(sha "$OUT/vrps.json")"
    echo "stayrtr=$STAYRTR_IMAGE"
    echo "n_peers=$N_PEERS total_prefixes=$TOTAL_PREFIXES vrps=$VRPS runs=$RUNS smoke=${SMOKE:+1}"
    echo "daemon_cpus=$DAEMON_CPUS engine_cpus=$ENGINE_CPUS rtr_cpus=$RTR_CPUS"
    echo "loadavg_start=$(cut -d' ' -f1-3 /proc/loadavg)"
} >"$OUT/manifest.txt"

docker run -d --name "$RTR_NAME" --network host --cpuset-cpus "$RTR_CPUS" \
    -v "$OUT/vrps.json:/data/vrps.json:ro" "$STAYRTR_IMAGE" \
    -cache /data/vrps.json -bind "127.0.0.1:$RTR_PORT" -checktime=false \
    -refresh 3600 -rtr.refresh 3600 >/dev/null || die "StayRTR container did not start"

rtr_listening() { (exec 3<>"/dev/tcp/127.0.0.1/$RTR_PORT") 2>/dev/null; }
wait_rtr() {
    local _
    for _ in $(seq 1 240); do
        rtr_listening && return 0
        [[ $(docker inspect -f '{{.State.Running}}' "$RTR_NAME" 2>/dev/null) == true ]] \
            || die "StayRTR container exited: $(docker logs --tail 5 "$RTR_NAME" 2>&1)"
        sleep .5
    done
    die "StayRTR is not listening on 127.0.0.1:$RTR_PORT after 120 s"
}
scrape() { curl -fsS --max-time 5 "http://127.0.0.1:$MPORT/metrics"; }
ticks() { awk '{ print $14 + $15 }' "/proc/$1/stat"; }

run_cell() { # run_cell ARM RUN POSITION
    local arm=$1 run=$2 pos=$3 cell=$OUT/cells/$1-r$2 t_start t_ready start_ticks end_ticks hrc
    mkdir "$cell"
    rm -rf "${SCEN:?}"/*
    mkdir "$SCEN/evidence"
    python3 "$REPO/bench/scale/reloadstall/gen-scenario.py" "$N_PEERS" "$SCEN" "$PORT" >/dev/null
    sed -i "s#prometheus_addr = \"127.0.0.1:9179\"#prometheus_addr = \"127.0.0.1:$MPORT\"#" "$SCEN/config.toml"
    grep -q "127.0.0.1:$MPORT" "$SCEN/config.toml" || die "scenario metrics address not rewritten"
    printf '\n[rpki]\n[[rpki.cache_servers]]\naddress = "127.0.0.1:%s"\nretry_interval = 5\n' \
        "$RTR_PORT" >>"$SCEN/config.toml"
    cp "$SCEN/config.toml" "$cell/config.toml"

    wait_rtr
    setsid taskset -c "$DAEMON_CPUS" "${BIN[$arm]}" "$SCEN/config.toml" >"$cell/daemon.log" 2>&1 &
    DPID=$!
    # The whole VRP table must be loaded before any route arrives.
    python3 "$HERE/rpki_cell.py" wait-vrps "http://127.0.0.1:$MPORT/metrics" "$VRPS" \
        "$VRP_TIMEOUT_SECS" "$DPID" || die "$arm-r$run: VRP table not loaded; cell failed"
    scrape >"$cell/metrics-before.prom" || die "$arm-r$run: metrics scrape failed"
    start_ticks=$(ticks "$DPID")
    t_start=$(date +%s.%N)
    RELOADSTALL_EVIDENCE_DIR="$SCEN/evidence" setsid taskset -c "$ENGINE_CPUS" "$HARNESS" \
        "$N_PEERS" "$TOTAL_PREFIXES" "$PORT" "$DPID" "$SCEN/member.rpol" \
        "$SCEN/gen-a.rpol" "$SCEN/gen-b.rpol" 0 0 --convergence-only \
        >"$cell/reloadstall.log" 2>&1 &
    HPID=$!
    local deadline=$((SECONDS + CELL_TIMEOUT_SECS))
    until [[ -f $SCEN/evidence/ready ]]; do
        kill -0 "$HPID" 2>/dev/null || die "$arm-r$run: harness exited before convergence (see $cell/reloadstall.log)"
        kill -0 "$DPID" 2>/dev/null || die "$arm-r$run: daemon exited during convergence"
        ((SECONDS < deadline)) || die "$arm-r$run: no convergence within $CELL_TIMEOUT_SECS s"
        sleep .1
    done
    t_ready=$(date +%s.%N)
    end_ticks=$(ticks "$DPID")
    scrape >"$cell/metrics-after.prom" || die "$arm-r$run: metrics scrape failed"
    touch "$SCEN/evidence/ack"
    hrc=0
    wait "$HPID" || hrc=$?
    HPID=''
    stop_group "$DPID"
    DPID=''
    cat >"$cell/cell.env" <<EOF
arm=$arm
run=$run
position=$pos
vrps_expected=$VRPS
cpu_ticks_start=$start_ticks
cpu_ticks_end=$end_ticks
clk_tck=$(getconf CLK_TCK)
t_start=$t_start
t_ready=$t_ready
harness_rc=$hrc
EOF
    ((hrc == 0)) || die "$arm-r$run: harness exited $hrc (see $cell/reloadstall.log)"
    echo "$arm-r$run done: $(grep -c . "$cell/metrics-after.prom") metric lines"
}

for ((run = 1; run <= RUNS; run++)); do
    if ((run % 2)); then order=(base head); else order=(head base); fi
    run_cell "${order[0]}" "$run" 1
    run_cell "${order[1]}" "$run" 2
done
python3 "$HERE/rpki_cell.py" summarize "$OUT" || die "summary rejected the campaign (see $OUT/summary.txt)"
