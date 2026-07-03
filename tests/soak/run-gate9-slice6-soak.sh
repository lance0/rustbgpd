#!/usr/bin/env bash
# Gate 9 slice 6 24-hour soak — sustained tenant-prefix churn on
# the symmetric Interface-less IRB topology at
# `tests/soak/gate9-slice6-soak.clab.yml`.
#
# Drives the slice 6a route-event subscription + slice 6b Type 5
# origination by cycling PE1's tenant `192.0.2.1/24` on `lo-vrf1`
# every CHURN_INTERVAL_SEC. PE2 keeps its tenant
# `198.51.100.0/24` up the whole soak so slice 6c's import side
# stays installed under steady state. Each churn cycle exercises:
#
#   1. `ip addr add` → kernel emits RTM_NEWROUTE for the connected
#      /24 → slice 6a's RTNLGRP_IPV4_ROUTE wake → reconcile dump →
#      observation watch update → slice 6b emits Type 5 inject
#      → FRR (PE2) sees the announcement.
#   2. `ip addr del` → RTM_DELROUTE → wake → reconcile → empty
#      observation → slice 6b emits Type 5 withdraw → FRR drops it.
#
# Output: tests/soak/runs/gate9-slice6-<UTC-timestamp>/
#   - samples.csv     one-row-per-minute timeseries (PE1/PE2 RSS,
#                     originated/installed/observed route gauges,
#                     BGP session state, tenant-up flag,
#                     cumulative churn cycles)
#   - soak.log        stdout + stderr from this script
#   - pe1.log         daemon log streamed from `docker logs pe1`
#   - pe2.log         daemon log streamed from `docker logs pe2`
#   - churn.log       per-cycle event log (timestamp, action)
#   - run.json        run metadata (image SHA, git rev, env at start)
#
# Prerequisites:
#   docker build --target dev -t rustbgpd:dev .
#   sudo containerlab deploy -t tests/soak/gate9-slice6-soak.clab.yml
#
# Usage:
#   bash tests/soak/run-gate9-slice6-soak.sh                   # 24h default
#   SOAK_HOURS=1 bash tests/soak/run-gate9-slice6-soak.sh      # 1h smoke
#   CHURN_INTERVAL_SEC=15 bash tests/soak/run-gate9-slice6-soak.sh  # tight churn
#
# Tail the per-PE logs while the soak runs:
#   tail -F tests/soak/runs/gate9-slice6-<UTC>/pe1.log
#   tail -F tests/soak/runs/gate9-slice6-<UTC>/samples.csv

set -euo pipefail

SOAK_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SOAK_SCRIPT_DIR/../.." && pwd)"
TOPOLOGY="$SOAK_SCRIPT_DIR/gate9-slice6-soak.clab.yml"

# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

SOAK_HOURS="${SOAK_HOURS:-24}"
# `SOAK_SECONDS` (optional) overrides `SOAK_HOURS * 3600` — used by
# sub-hour smoke runs that want a precise duration (e.g., a 5-min
# local validation before launching the 24 h cloudbox run).
SOAK_SECONDS="${SOAK_SECONDS:-}"
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-60}"          # seconds between CSV rows
CHURN_INTERVAL_SEC="${CHURN_INTERVAL_SEC:-30}"    # seconds between add ↔ del transitions
WARMUP_SEC="${WARMUP_SEC:-120}"                   # discard first 2 min for slope analysis
PE1_NAME="${PE1_NAME:-clab-gate9-slice6-soak-pe1}"
PE2_NAME="${PE2_NAME:-clab-gate9-slice6-soak-pe2}"
TENANT_CIDR="${TENANT_CIDR:-192.0.2.1/24}"
TENANT_DEV="${TENANT_DEV:-lo-vrf1}"
VRF_NAME="${VRF_NAME:-vrf1}"
L3VNI="${L3VNI:-100}"
ROUTER_MAC="${ROUTER_MAC:-02:00:00:00:01:01}"
CLEANUP="${CLEANUP:-0}"                           # 1 = destroy topology on EXIT

START_TS="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_DIR="${RUN_DIR_OVERRIDE:-$SOAK_SCRIPT_DIR/runs/gate9-slice6-$START_TS}"
mkdir -p "$RUN_DIR"

SAMPLES_CSV="$RUN_DIR/samples.csv"
SOAK_LOG="$RUN_DIR/soak.log"
PE1_LOG="$RUN_DIR/pe1.log"
PE2_LOG="$RUN_DIR/pe2.log"
CHURN_LOG="$RUN_DIR/churn.log"
RUN_JSON="$RUN_DIR/run.json"

exec > >(tee -a "$SOAK_LOG") 2>&1

# Host mutex shared with bench/compare-criterion.sh. See
# tests/soak/host-lock.sh for sudo/HOME caveats.
# shellcheck source=./host-lock.sh
source "$SOAK_SCRIPT_DIR/host-lock.sh"
acquire_rustbgpd_host_lock

# ---------------------------------------------------------------------------
# Helpers (mirror Gate 8b's pattern so the analyzer / triage habits port over)
# ---------------------------------------------------------------------------

log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"
}

churn_log() {
    printf '[%s] %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >>"$CHURN_LOG"
}

require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        log "ERROR: required tool '$1' not in PATH"
        exit 2
    fi
}

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
    # Fall back to docker stats for FRR (no rustbgpd PID).
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

# Is the BGP session established? We poll FRR's vtysh because PE2
# is FRR; PE1's rustbgpd surfaces session state via gRPC but the
# Prometheus scrape already covers PE1's perspective. A simple
# binary "is the peer up from PE2's view" reads cleanly in the CSV.
bgp_session_up() {
    if docker exec "$PE2_NAME" vtysh -c 'show bgp neighbors 10.0.0.1 json' 2>/dev/null \
        | grep -q '"bgpState":"Established"'; then
        echo 1
    else
        echo 0
    fi
}

# Is PE1's tenant address currently UP? Mirrors the churn state
# the loop drives so the CSV's RSS column can be correlated with
# the actual add/del cycle phase.
tenant_present() {
    if docker exec "$PE1_NAME" ip addr show "$TENANT_DEV" 2>/dev/null \
        | grep -q "inet ${TENANT_CIDR%/*}"; then
        echo 1
    else
        echo 0
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

# Provision PE1's kernel topology (VRF + L3VXLAN + tenant dummy
# with the initial /24 address) and start the daemon. The
# tenant address is the first thing the churn loop will toggle.
log "provisioning PE1 kernel topology"
docker exec "$PE1_NAME" /usr/local/bin/start-rustbgpd-m39-pe1.sh \
    10.0.0.1 "$L3VNI" "$VRF_NAME" "$TENANT_CIDR" "$ROUTER_MAC" >/dev/null
log "starting PE1 daemon"
docker exec -d "$PE1_NAME" sh -c '/usr/local/bin/start-rustbgpd.sh >/tmp/rustbgpd.log 2>&1'

# Capture run metadata.
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
  "churn_interval_sec": $CHURN_INTERVAL_SEC,
  "warmup_sec": $WARMUP_SEC,
  "tenant_cidr": "$TENANT_CIDR",
  "tenant_dev": "$TENANT_DEV",
  "vrf_name": "$VRF_NAME",
  "l3vni": $L3VNI,
  "topology": "$TOPOLOGY",
  "run_dir": "$RUN_DIR"
}
EOF

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
ts_unix,elapsed_sec,pe1_rss_mb,pe2_rss_mb,pe1_installed_routes,pe1_observed_routes,bgp_established,tenant_present,churn_cycles
EOF
# Note: `evpn_ip_vrf_originated_routes` is gRPC-only today
# (`IpVrfState.originated_routes_count`), not a Prometheus gauge.
# `pe1_observed_routes` is a sufficient proxy — slice 6a's observed
# set is exactly the input slice 6b originates from, so it tracks
# the churn cadence one reconcile-pass behind the kernel.

# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

START_UNIX="$(date +%s)"
if [ -n "$SOAK_SECONDS" ]; then
    END_UNIX="$((START_UNIX + SOAK_SECONDS))"
else
    END_UNIX="$((START_UNIX + SOAK_HOURS * 3600))"
fi
NEXT_CHURN_UNIX="$((START_UNIX + CHURN_INTERVAL_SEC))"
# Start the loop with the address present (provisioned above) so
# the first churn transition is `del`.
TENANT_UP=1
CHURN_CYCLES=0

if [ -n "$SOAK_SECONDS" ]; then
    DURATION_LABEL="${SOAK_SECONDS}s"
else
    DURATION_LABEL="${SOAK_HOURS}h"
fi
log "Gate 9 slice 6 soak starting — duration=${DURATION_LABEL} sample=${SAMPLE_INTERVAL}s churn=${CHURN_INTERVAL_SEC}s"
log "run_dir=$RUN_DIR"
log "git_rev=$GIT_REV dirty=$GIT_DIRTY kernel=$KERNEL"
log "tenant=$TENANT_CIDR dev=$TENANT_DEV vrf=$VRF_NAME l3vni=$L3VNI"

log "warmup: waiting ${WARMUP_SEC}s for initial BGP + IP-VRF discovery"
sleep "$WARMUP_SEC"

while [ "$(date +%s)" -lt "$END_UNIX" ]; do
    NOW="$(date +%s)"
    ELAPSED="$((NOW - START_UNIX))"

    # Sample.
    PE1_PROM="$(prom_scrape "$PE1_NAME")"
    PE1_RSS="$(container_rss_mb "$PE1_NAME" || echo "")"
    PE2_RSS="$(container_rss_mb "$PE2_NAME" || echo "")"
    PE1_INSTALLED="$(prom_extract "$PE1_PROM" evpn_ip_vrf_installed_routes "vrf=\"$VRF_NAME\"")"
    PE1_OBSERVED="$(prom_extract "$PE1_PROM" evpn_ip_vrf_observed_routes "vrf=\"$VRF_NAME\"")"
    BGP_UP="$(bgp_session_up)"
    TENANT="$(tenant_present)"

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$NOW" "$ELAPSED" \
        "${PE1_RSS:-NaN}" "${PE2_RSS:-NaN}" \
        "${PE1_INSTALLED:-NaN}" "${PE1_OBSERVED:-NaN}" \
        "$BGP_UP" "$TENANT" "$CHURN_CYCLES" >>"$SAMPLES_CSV"

    # Churn the tenant prefix if it's time.
    if [ "$NOW" -ge "$NEXT_CHURN_UNIX" ]; then
        if [ "$TENANT_UP" = "1" ]; then
            churn_log "ip addr del $TENANT_CIDR on $TENANT_DEV"
            log "churn: removing tenant $TENANT_CIDR"
            docker exec "$PE1_NAME" ip addr del "$TENANT_CIDR" dev "$TENANT_DEV" 2>/dev/null || true
            TENANT_UP=0
        else
            churn_log "ip addr add $TENANT_CIDR on $TENANT_DEV"
            log "churn: re-adding tenant $TENANT_CIDR"
            docker exec "$PE1_NAME" ip addr add "$TENANT_CIDR" dev "$TENANT_DEV" 2>/dev/null || true
            TENANT_UP=1
            CHURN_CYCLES=$((CHURN_CYCLES + 1))
        fi
        NEXT_CHURN_UNIX="$((NOW + CHURN_INTERVAL_SEC))"
    fi

    sleep "$SAMPLE_INTERVAL"
done

log "soak loop completed; final samples in $SAMPLES_CSV"
log "total churn cycles: $CHURN_CYCLES"
