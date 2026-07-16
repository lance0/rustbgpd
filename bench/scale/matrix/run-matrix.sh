#!/usr/bin/env bash
# LAN-334 IXP receipt matrix: sequential reload-stall cells across daemons.
#
# Cells:
#   rustbgpd  bare release binary, SIGHUP reloads (the frozen receipt recipe)
#   bird      BIRD 3.3.1 in docker --network=host, `birdc configure` reloads
#             (image: docker build -t bird:3.3.1 -f tests/interop/Dockerfile.bird3 tests/interop)
#   openbgpd  OpenBGPD 9.1 in docker --network=host, `bgpctl reload` reloads
#             (image: docker pull openbgpd/openbgpd:9.1)
#
# One cell at a time: 1-min loadavg gate (< 2.0) before each cell, 5-minute
# cool-down after. Per-cell status files under the artifacts dir make the
# campaign resumable — a rerun skips cells whose status is `pass` (delete the
# status file to redo one). A cell aborts (campaign continues) on harness
# acceptance failure or daemon-tree RSS > 100 GiB.
#
# Usage: run-matrix.sh [cell ...]         (default: rustbgpd bird openbgpd)
# Knobs (env): N_PEERS=700 TOTAL_PREFIXES=400400 PORT=1790 RELOADS=4
#              CONTROL_SECS=30 BIRD_THREADS=8 FLAPSTORM= (K, optional)
#              ARTIFACTS_DIR=bench/scale/matrix/artifacts
set -u

REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
RSTALL="$REPO/bench/scale/reloadstall"
HARNESS="$RSTALL/target/release/reloadstall"
SAMPLER="$REPO/bench/scale/matrix/rss-sampler.sh"

N_PEERS="${N_PEERS:-700}"
TOTAL="${TOTAL_PREFIXES:-400400}"
PORT="${PORT:-1790}"
RELOADS="${RELOADS:-4}"
CONTROL_SECS="${CONTROL_SECS:-30}"
BIRD_THREADS="${BIRD_THREADS:-8}"
FLAPSTORM="${FLAPSTORM:-}"
ART="${ARTIFACTS_DIR:-$REPO/bench/scale/matrix/artifacts}"
RSS_LIMIT_KIB=$((100 * 1024 * 1024)) # abort a cell past 100 GiB

CELLS=("$@")
[ ${#CELLS[@]} -eq 0 ] && CELLS=(rustbgpd bird openbgpd)

[ -x "$HARNESS" ] || {
    echo "missing $HARNESS - build with: cd $RSTALL && cargo build --release" >&2
    exit 1
}
mkdir -p "$ART"

load_gate() {
    local load
    while :; do
        load=$(cut -d' ' -f1 /proc/loadavg)
        if awk -v l="$load" 'BEGIN { exit !(l < 2.0) }'; then return 0; fi
        echo "load_gate: 1-min loadavg $load >= 2.0, waiting 30s"
        sleep 30
    done
}

# run_cell <cell>: everything for one matrix cell. Nonzero return = cell
# failed; the campaign moves on.
run_cell() {
    local cell=$1
    local cdir="$ART/$cell"
    # Short run dir: gen-scenario.py's gRPC UDS path must fit SUN_LEN.
    local run="/tmp/ixp-$cell"
    rm -rf "$run"
    mkdir -p "$cdir" "$run"

    local daemon_pid="" container="" reload_cmd="" pid_arg=""
    local live a b
    case $cell in
    rustbgpd)
        [ -x "$REPO/target/release/rustbgpd" ] || {
            echo "missing $REPO/target/release/rustbgpd (cargo build --release)" >&2
            return 1
        }
        python3 "$RSTALL/gen-scenario.py" "$N_PEERS" "$run" "$PORT" || return 1
        "$REPO/target/release/rustbgpd" "$run/config.toml" \
            >"$cdir/daemon.log" 2>&1 &
        daemon_pid=$!
        live="$run/member.rpol" a="$run/gen-a.rpol" b="$run/gen-b.rpol"
        pid_arg=$daemon_pid # frozen recipe: real PID, SIGHUP reloads
        ;;
    bird)
        python3 "$RSTALL/gen-bird-scenario.py" "$N_PEERS" "$run" "$PORT" \
            "$BIRD_THREADS" || return 1
        container="ixp-bird"
        docker rm -f "$container" >/dev/null 2>&1
        docker run -d --name "$container" --network=host -v "$run":/etc/bird \
            bird:3.3.1 bird -f -c /etc/bird/bird.conf >/dev/null || return 1
        reload_cmd="docker exec $container birdc configure"
        live="$run/gen.conf" a="$run/gen-a.conf" b="$run/gen-b.conf"
        pid_arg=0 # the outer sampler owns RSS
        ;;
    openbgpd)
        python3 "$RSTALL/gen-obgpd-scenario.py" "$N_PEERS" "$run" "$PORT" || return 1
        container="ixp-obgpd"
        docker rm -f "$container" >/dev/null 2>&1
        docker run -d --name "$container" --network=host -v "$run":/etc/bgpd \
            openbgpd/openbgpd:9.1 >/dev/null || return 1
        reload_cmd="docker exec $container bgpctl reload"
        live="$run/gen.conf" a="$run/gen-a.conf" b="$run/gen-b.conf"
        pid_arg=0
        ;;
    *)
        echo "unknown cell: $cell (want rustbgpd|bird|openbgpd)" >&2
        return 1
        ;;
    esac

    sleep 3
    if [ -n "$container" ]; then
        daemon_pid=$(docker inspect -f '{{.State.Pid}}' "$container") || daemon_pid=0
        if [ "$daemon_pid" -le 0 ]; then
            echo "cell $cell: container died at start" >&2
            docker logs "$container" >"$cdir/daemon.log" 2>&1
            docker rm -f "$container" >/dev/null 2>&1
            return 1
        fi
    elif [ ! -d "/proc/$daemon_pid" ]; then
        echo "cell $cell: daemon died at start (see $cdir/daemon.log)" >&2
        return 1
    fi

    "$SAMPLER" "$daemon_pid" "$cdir/rss.csv" 5 &
    local sampler_pid=$!

    local hargs=("$N_PEERS" "$TOTAL" "$PORT" "$pid_arg" "$live" "$a" "$b"
        "$RELOADS" "$CONTROL_SECS")
    [ -n "$reload_cmd" ] && hargs+=("$N_PEERS" "$reload_cmd")
    [ -n "$FLAPSTORM" ] && hargs+=(--flapstorm "$FLAPSTORM")

    # Harness in the background so the RSS guard can abort the cell.
    "$HARNESS" "${hargs[@]}" >"$cdir/reloadstall.log" 2>&1 &
    local hpid=$!
    local rc=""
    while kill -0 "$hpid" 2>/dev/null; do
        local last_kib
        last_kib=$(tail -n1 "$cdir/rss.csv" 2>/dev/null | cut -d, -f2)
        case ${last_kib:-} in
        '' | *[!0-9]*) ;;
        *)
            if [ "$last_kib" -gt "$RSS_LIMIT_KIB" ]; then
                echo "cell $cell: daemon RSS ${last_kib} KiB > 100 GiB, aborting cell" >&2
                kill "$hpid" 2>/dev/null
                rc=99
            fi
            ;;
        esac
        sleep 5
    done
    local hrc
    wait "$hpid"
    hrc=$?
    [ -z "$rc" ] && rc=$hrc

    # Collect artifacts, then teardown.
    kill "$sampler_pid" 2>/dev/null
    if [ -n "$container" ]; then
        docker logs "$container" >"$cdir/daemon.log" 2>&1
        docker rm -f "$container" >/dev/null 2>&1
    else
        kill "$daemon_pid" 2>/dev/null
    fi
    cp -r "$run" "$cdir/scenario"
    echo "cell $cell: harness rc=$rc (artifacts: $cdir)"
    return "$rc"
}

for cell in "${CELLS[@]}"; do
    status_file="$ART/$cell/status"
    if [ -f "$status_file" ] && grep -qx pass "$status_file"; then
        echo "cell $cell: already pass, skipping (rm $status_file to rerun)"
        continue
    fi
    load_gate
    echo "=== cell $cell start $(date -Is) ==="
    if run_cell "$cell"; then
        echo pass >"$status_file"
        echo "=== cell $cell PASS $(date -Is) ==="
    else
        echo "fail rc=$? $(date -Is)" >"$status_file"
        echo "=== cell $cell FAIL (campaign continues) ==="
    fi
    echo "cool-down 300s"
    sleep 300
done
echo "matrix done; per-cell status under $ART/*/status"
