#!/usr/bin/env bash
# Gate 8b 24-hour soak — sustained shared-ESI candidate-set churn
# on the 2-PE shared-ESI topology at `tests/soak/gate8b-soak.clab.yml`.
#
# Drives election by toggling PE2 (docker stop / docker start) on a
# configurable cadence; PE1's segment orchestrator re-runs election
# on every Type 4 event. With the default modulo election and PE1's
# lower originator IP, PE1 remains DF in both the one-candidate and
# two-candidate states; this soak stresses recompute/reconcile
# memory behavior rather than a DF↔Non-DF flag transition.
#
# Output: tests/soak/runs/gate8b-<UTC-timestamp>/
#   - samples.csv     one-row-per-minute timeseries (mem, df_role,
#                     df_role_changes, applied_bum_ops, failed_bum_ops,
#                     ce-port flag state)
#   - soak.log        stdout + stderr from this script
#   - pe1.log         daemon log streamed from `docker logs pe1`
#   - pe2.log         daemon log streamed from `docker logs pe2`
#   - flips.log       per-flip event log (timestamp, action, target)
#   - run.json        run metadata (image SHA, git rev, env at start)
#
# Prerequisites:
#   docker build -t rustbgpd:dev .
#   sudo containerlab deploy -t tests/soak/gate8b-soak.clab.yml
#
# Usage:
#   bash tests/soak/run-gate8b-soak.sh                  # 24h default
#   SOAK_HOURS=1 bash tests/soak/run-gate8b-soak.sh     # 1h smoke
#   FLIP_INTERVAL_SEC=300 SOAK_HOURS=24 \
#       bash tests/soak/run-gate8b-soak.sh              # 5-min flips
#
# Tail the per-PE logs while the soak runs:
#   tail -F tests/soak/runs/gate8b-<UTC>/pe1.log
#   tail -F tests/soak/runs/gate8b-<UTC>/samples.csv

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"
TOPOLOGY="$SOAK_SCRIPT_DIR/gate8b-soak.clab.yml"

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

SOAK_HOURS="${SOAK_HOURS:-24}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-60}"          # seconds between CSV rows
FLIP_INTERVAL_SEC="${FLIP_INTERVAL_SEC:-600}"     # 10-minute DF flips by default
WARMUP_SEC="${WARMUP_SEC:-120}"                   # discard first 2 min of samples for slope
PE1_NAME="${PE1_NAME:-clab-gate8b-soak-pe1}"
PE2_NAME="${PE2_NAME:-clab-gate8b-soak-pe2}"
CLEANUP="${CLEANUP:-0}"                           # 1 = destroy topology on EXIT

START_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/gate8b-$START_TS}"
mkdir -p "$RUN_DIR"

SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
PE1_LOG="$RUN_DIR/pe1.log"
PE2_LOG="$RUN_DIR/pe2.log"
FLIPS_LOG="$RUN_DIR/flips.log"
RUN_JSON="$RUN_DIR/run.json"

# Re-route stdout/stderr to soak.log AND original tty so the user
# can `tail -F soak.log` from another terminal and still see live
# progress in the foreground tmux pane.
exec > >(tee -a "$SOAK_LOG") 2>&1

# Host mutex shared with bench/compare-criterion.sh. See
# tests/soak/host-lock.sh for sudo/HOME caveats; the gist is "do not
# invoke this harness under sudo, or export RUSTBGPD_HOST_LOCK
# explicitly so it points at the bench user's lock file."
# shellcheck source=./host-lock.sh
source "$SOAK_SCRIPT_DIR/host-lock.sh"
acquire_rustbgpd_host_lock

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

flip_log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$FLIPS_LOG"
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "ERROR: required tool '$1' not in PATH"
        exit 2
    fi
}

# Scrape Prometheus from the host using the container's clab IP.
#
# The rustbgpd image is built on debian:bookworm-slim with neither
# wget nor curl installed (deliberately — the daemon doesn't need
# either at runtime). Scraping from the host instead avoids the
# image bloat, and on a containerlab management network the host
# can reach the per-container IP directly. Falls back through
# `docker inspect`'s NetworkSettings.Networks map (clab labels the
# bridge `clab-<topology>` so we can't hardcode a single key).
prom_scrape() {
    local container="$1"
    local ip
    ip=$(docker inspect --format \
        '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' \
        "$container" 2>/dev/null | awk '{print $1}')
    [ -z "$ip" ] && return 0
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null || true
}

prom_extract() {
    # $1 = scraped text, $2 = metric name, $3 = optional label match
    local text="$1" metric="$2" label="${3:-}"
    if [ -n "$label" ]; then
        printf '%s' "$text" | awk -v m="$metric" -v l="$label" '
            $0 ~ "^"m"\\{" && index($0, l) { print $NF; exit }
        '
    else
        printf '%s' "$text" | awk -v m="$metric" '
            $0 ~ "^"m"( |\\{)" { print $NF; exit }
        '
    fi
}

container_rss_mb() {
    # /proc/<pid>/status VmRSS for the rustbgpd PID inside the
    # container. Falls back to docker stats memory if VmRSS isn't
    # readable (e.g. permission edge cases or a stopped container).
    local container="$1"
    local rss
    rss=$(docker exec "$container" sh -c '
        pid=$(pidof rustbgpd 2>/dev/null || echo "")
        if [ -n "$pid" ] && [ -r /proc/$pid/status ]; then
            awk "/^VmRSS:/ {print \$2/1024}" /proc/$pid/status
        fi
    ' 2>/dev/null || echo "")
    if [ -n "$rss" ]; then
        echo "$rss"
        return 0
    fi

    docker stats --no-stream --format '{{.MemUsage}}' "$container" 2>/dev/null | awk '
        NR == 1 {
            value = $1
            unit = value
            sub(/^[0-9.]+/, "", unit)
            sub(/[A-Za-z]+$/, "", value)
            n = value + 0
            if (unit == "KiB" || unit == "kB" || unit == "KB") {
                print n / 1024
            } else if (unit == "MiB" || unit == "MB") {
                print n
            } else if (unit == "GiB" || unit == "GB") {
                print n * 1024
            }
        }
    '
}

bridge_flag_state() {
    # Returns "df" if all three flood flags are ON for the CE-facing
    # bridge port, "nondf" if all three are OFF, "unreachable" if
    # the container/interface cannot be read, and "mixed" otherwise.
    local container="$1"
    local out
    if ! out=$(docker exec "$container" bridge -d link show dev ce100a 2>/dev/null); then
        echo "unreachable"
        return 0
    fi
    if [ -z "$out" ]; then
        echo "unreachable"
        return 0
    fi
    local f m b
    f=$(printf '%s' "$out" | grep -oE 'flood (on|off)' | head -1 | awk '{print $2}')
    m=$(printf '%s' "$out" | grep -oE 'mcast_flood (on|off)' | head -1 | awk '{print $2}')
    b=$(printf '%s' "$out" | grep -oE 'bcast_flood (on|off)' | head -1 | awk '{print $2}')
    if [ "$f" = "on" ] && [ "$m" = "on" ] && [ "$b" = "on" ]; then
        echo "df"
    elif [ "$f" = "off" ] && [ "$m" = "off" ] && [ "$b" = "off" ]; then
        echo "nondf"
    else
        echo "mixed"
    fi
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------

require_tool docker
require_tool containerlab
require_tool curl

container_is_running() {
    [ "$(docker inspect --format='{{.State.Running}}' "$1" 2>/dev/null || echo false)" = "true" ]
}

if ! container_is_running "$PE1_NAME"; then
    log "ERROR: container $PE1_NAME not running. Deploy the topology first:"
    log "  sudo containerlab deploy -t $TOPOLOGY"
    exit 2
fi
if ! container_is_running "$PE2_NAME"; then
    log "ERROR: container $PE2_NAME not running"
    exit 2
fi

# Capture run metadata before the loop starts.
GIT_REV="$(cd "$REPO_ROOT" && git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_DIRTY="$(cd "$REPO_ROOT" && [ -n "$(git status --porcelain 2>/dev/null)" ] && echo true || echo false)"
IMAGE_ID="$(docker inspect --format='{{.Image}}' "$PE1_NAME" 2>/dev/null || echo unknown)"
KERNEL="$(uname -r)"

cat >"$RUN_JSON" <<EOF
{
  "started_at": "$START_TS",
  "git_rev": "$GIT_REV",
  "git_dirty": $GIT_DIRTY,
  "image_id": "$IMAGE_ID",
  "kernel": "$KERNEL",
  "soak_hours": $SOAK_HOURS,
  "sample_interval_sec": $SAMPLE_INTERVAL,
  "flip_interval_sec": $FLIP_INTERVAL_SEC,
  "warmup_sec": $WARMUP_SEC,
  "topology": "$TOPOLOGY",
  "run_dir": "$RUN_DIR"
}
EOF

# Tail each PE's container log into the run directory in the
# background; on EXIT we kill them so they don't outlive the soak.
docker logs -f "$PE1_NAME" >>"$PE1_LOG" 2>&1 &
PE1_TAIL_PID=$!
docker logs -f "$PE2_NAME" >>"$PE2_LOG" 2>&1 &
PE2_TAIL_PID=$!

cleanup() {
    set +e
    log "soak loop exiting; cleaning up background tasks"
    kill "$PE1_TAIL_PID" "$PE2_TAIL_PID" 2>/dev/null || true
    wait "$PE1_TAIL_PID" "$PE2_TAIL_PID" 2>/dev/null || true
    if [ "$CLEANUP" = "1" ]; then
        log "CLEANUP=1: destroying topology"
        sudo containerlab destroy -t "$TOPOLOGY" --cleanup || true
    fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------------------
# CSV header
# ---------------------------------------------------------------------------

cat >"$SAMPLES_CSV" <<'EOF'
ts_unix,elapsed_sec,pe1_rss_mb,pe2_rss_mb,pe1_df_role,pe2_df_role,pe1_df_changes,pe2_df_changes,pe1_bum_flags,pe2_bum_flags,pe2_running
EOF

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

START_UNIX="$(date +%s)"
END_UNIX="$((START_UNIX + SOAK_HOURS * 3600))"
NEXT_FLIP_UNIX="$((START_UNIX + FLIP_INTERVAL_SEC))"
PE2_RUNNING=1

log "Gate 8b soak starting — duration=${SOAK_HOURS}h sample=${SAMPLE_INTERVAL}s flip=${FLIP_INTERVAL_SEC}s"
log "run_dir=$RUN_DIR"
log "git_rev=$GIT_REV dirty=$GIT_DIRTY kernel=$KERNEL"

# Settle for the warmup window before sampling so the daemon's
# initial dataplane discovery doesn't pollute the slope regression.
log "warmup: waiting ${WARMUP_SEC}s for initial dataplane discovery"
sleep "$WARMUP_SEC"

while [ "$(date +%s)" -lt "$END_UNIX" ]; do
    NOW="$(date +%s)"
    ELAPSED="$((NOW - START_UNIX))"

    # Sample.
    PE1_PROM="$(prom_scrape "$PE1_NAME")"
    PE2_PROM="$(prom_scrape "$PE2_NAME")"
    PE1_RSS="$(container_rss_mb "$PE1_NAME" || echo "")"
    PE2_RSS="$(container_rss_mb "$PE2_NAME" || echo "")"

    PE1_DF="$(prom_extract "$PE1_PROM" evpn_df_role 'role="df"')"
    PE2_DF="$(prom_extract "$PE2_PROM" evpn_df_role 'role="df"')"
    PE1_DF_CHANGES="$(prom_extract "$PE1_PROM" evpn_df_role_changes_total)"
    PE2_DF_CHANGES="$(prom_extract "$PE2_PROM" evpn_df_role_changes_total)"

    PE1_FLAGS="$(bridge_flag_state "$PE1_NAME")"
    PE2_FLAGS="$(bridge_flag_state "$PE2_NAME" 2>/dev/null || echo unreachable)"

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$NOW" "$ELAPSED" \
        "${PE1_RSS:-NaN}" "${PE2_RSS:-NaN}" \
        "${PE1_DF:-NaN}" "${PE2_DF:-NaN}" \
        "${PE1_DF_CHANGES:-NaN}" "${PE2_DF_CHANGES:-NaN}" \
        "${PE1_FLAGS:-unknown}" "${PE2_FLAGS:-unknown}" \
        "$PE2_RUNNING" >>"$SAMPLES_CSV"

    # Flip PE2 if it's time.
    if [ "$NOW" -ge "$NEXT_FLIP_UNIX" ]; then
        if [ "$PE2_RUNNING" = "1" ]; then
            flip_log "stopping PE2"
            log "flip: stopping PE2"
            docker stop -t 5 "$PE2_NAME" >/dev/null
            PE2_RUNNING=0
        else
            flip_log "starting PE2"
            log "flip: starting PE2"
            docker start "$PE2_NAME" >/dev/null
            # Re-exec the start script after `docker start` since
            # exec entries from the topology only fire on initial
            # deploy. Without this PE2 wouldn't bring up its bridge
            # / VXLAN on the second start.
            docker exec "$PE2_NAME" /usr/local/bin/start-rustbgpd-soak-gate8b.sh \
                10.0.0.2 10.0.0.1 100 || true
            # Re-attach the docker-logs tail since `docker start`
            # invalidated the prior tail's underlying stream.
            kill "$PE2_TAIL_PID" 2>/dev/null || true
            docker logs -f "$PE2_NAME" >>"$PE2_LOG" 2>&1 &
            PE2_TAIL_PID=$!
            PE2_RUNNING=1
        fi
        NEXT_FLIP_UNIX="$((NOW + FLIP_INTERVAL_SEC))"
    fi

    sleep "$SAMPLE_INTERVAL"
done

log "soak loop completed; final samples in $SAMPLES_CSV"
