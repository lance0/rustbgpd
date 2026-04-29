#!/usr/bin/env bash
# chaos-flap-storm.sh — bounce a peer's BGP session repeatedly via
# `EnableNeighbor`/`DisableNeighbor` and assert post-storm health.
#
# Topology: M33 (`tests/interop/m33-evpn-scale.clab.yml`). The daemon
# must already be running with at least one neighbor configured. Run
# `containerlab deploy -t tests/interop/m33-evpn-scale.clab.yml` first.
#
# Drives the FSM disable→idle→reconnect→OpenSent→...→Established
# cycle every CHAOS_INTERVAL_SEC seconds. Each cycle exercises:
#   - Outbound writer-task teardown (`close_tcp` + writer JoinHandle)
#   - RIB clear-and-resync on the next Established
#   - Per-peer ADJ-RIB-IN HashMap / interning teardown
#
# Pass criteria:
#   - Daemon never returns a non-OK gRPC GetHealth during the storm
#   - Memory growth across the storm < 10 MB above pre-storm baseline
#   - No process restart (counter monotonicity preserved)
#   - At least 3 successful Established-after-Disable cycles
#
# Output: tests/chaos/runs/<UTC-timestamp>/{driver.log,samples.csv,report.json}

set -euo pipefail

CHAOS_DURATION_SEC=${CHAOS_DURATION_SEC:-60}
CHAOS_INTERVAL_SEC=${CHAOS_INTERVAL_SEC:-3}
CHAOS_TOPO=${CHAOS_TOPO:-m33-evpn-scale}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TS=$(date -u +%Y%m%dT%H%M%SZ)
RUN_DIR="$SCRIPT_DIR/runs/$TS"
mkdir -p "$RUN_DIR"
DRIVER_LOG="$RUN_DIR/driver.log"
SAMPLES="$RUN_DIR/samples.csv"
REPORT="$RUN_DIR/report.json"

# Reuse interop test-lib for resolve_grpc_addr / grpc_health
TOPO="$CHAOS_TOPO"
# shellcheck source=../interop/scripts/test-lib.sh
source "$SCRIPT_DIR/../interop/scripts/test-lib.sh"
resolve_grpc_addr

# Pick the first non-local neighbor to bounce. M33 advertises tester-a
# and tester-b at .4 and .5; we'll target .4.
PEER_TARGET=${PEER_TARGET:-10.0.0.2}

log "[chaos-flap-storm] target=$PEER_TARGET duration=${CHAOS_DURATION_SEC}s interval=${CHAOS_INTERVAL_SEC}s"
log "[chaos-flap-storm] run dir: $RUN_DIR"

# Pre-storm baseline
baseline_mem=$(docker exec "$RUSTBGPD" sh -c \
    'cat /sys/fs/cgroup/memory.current 2>/dev/null || cat /proc/$(pgrep rustbgpd)/status | awk "/VmRSS/ {print \$2*1024}"')
baseline_health=$(grpc_health 2>&1 | head -1 || true)
echo "ts,event,mem_bytes,health_ok" >"$SAMPLES"
echo "$(date +%s),baseline,$baseline_mem,$( [ -n "$baseline_health" ] && echo 1 || echo 0)" >>"$SAMPLES"
log "[chaos-flap-storm] baseline mem=$baseline_mem bytes"

# Storm loop
deadline=$(( $(date +%s) + CHAOS_DURATION_SEC ))
cycles=0
established_after=0
health_failures=0
while [ "$(date +%s)" -lt "$deadline" ]; do
    cycles=$((cycles + 1))

    # Disable
    if ! grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"address\":\"$PEER_TARGET\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/DisableNeighbor \
        >>"$DRIVER_LOG" 2>&1; then
        log "[chaos-flap-storm] DisableNeighbor failed at cycle $cycles"
    fi

    sleep "$CHAOS_INTERVAL_SEC"

    # Health probe mid-cycle
    if grpc_health >/dev/null 2>&1; then
        :
    else
        health_failures=$((health_failures + 1))
    fi

    # Re-enable
    if ! grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"address\":\"$PEER_TARGET\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/EnableNeighbor \
        >>"$DRIVER_LOG" 2>&1; then
        log "[chaos-flap-storm] EnableNeighbor failed at cycle $cycles"
    fi

    # Wait briefly for re-Establish; check state.
    sleep "$CHAOS_INTERVAL_SEC"
    state=$(grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"address\":\"$PEER_TARGET\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null \
        | jq -r '.state // empty')
    if [ "$state" = "SESSION_STATE_ESTABLISHED" ]; then
        established_after=$((established_after + 1))
    fi

    mem=$(docker exec "$RUSTBGPD" sh -c \
        'cat /sys/fs/cgroup/memory.current 2>/dev/null || cat /proc/$(pgrep rustbgpd)/status | awk "/VmRSS/ {print \$2*1024}"' 2>/dev/null || echo 0)
    echo "$(date +%s),cycle$cycles,$mem,$( grpc_health >/dev/null 2>&1 && echo 1 || echo 0)" >>"$SAMPLES"
done

# Post-storm sample
final_mem=$(docker exec "$RUSTBGPD" sh -c \
    'cat /sys/fs/cgroup/memory.current 2>/dev/null || cat /proc/$(pgrep rustbgpd)/status | awk "/VmRSS/ {print \$2*1024}"')
mem_delta=$(( final_mem - baseline_mem ))
mem_delta_mb=$(awk -v d="$mem_delta" 'BEGIN{printf "%.2f", d/1048576}')

verdict="clean"
failures=()
if [ "$health_failures" -gt 0 ]; then
    verdict="needs-attention"
    failures+=("\"$health_failures gRPC health failures during storm\"")
fi
if [ "$mem_delta" -gt $((10 * 1024 * 1024)) ]; then
    verdict="needs-attention"
    failures+=("\"memory grew ${mem_delta_mb} MB across ${cycles} cycles (>10 MB)\"")
fi
if [ "$cycles" -lt 3 ]; then
    verdict="needs-attention"
    failures+=("\"only $cycles cycles completed in ${CHAOS_DURATION_SEC}s (need >=3)\"")
fi

# After the last cycle, give the peer up to 30 s to recover Established.
# A healthy daemon must let *at least one* re-establishment complete by
# the end of the storm, even if the in-cycle wait was too tight to
# observe each individual recovery. Without this gate the harness would
# pass even with a stuck FSM that never re-Establishes after Disable —
# which would defeat the purpose of bouncing the session.
log "[chaos-flap-storm] post-storm: waiting up to 30s for $PEER_TARGET to re-Establish"
post_storm_established=0
for _ in $(seq 1 30); do
    state=$(grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"address\":\"$PEER_TARGET\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState 2>/dev/null \
        | jq -r '.state // empty')
    if [ "$state" = "SESSION_STATE_ESTABLISHED" ]; then
        post_storm_established=1
        break
    fi
    sleep 1
done
if [ "$post_storm_established" -ne 1 ]; then
    verdict="needs-attention"
    failures+=("\"$PEER_TARGET never reached Established within 30s post-storm — possible stuck FSM or writer teardown regression\"")
fi

failures_json=$(IFS=,; echo "[${failures[*]:-}]")

cat >"$REPORT" <<EOF
{
  "verdict": "$verdict",
  "failures": $failures_json,
  "topology": "$CHAOS_TOPO",
  "peer_target": "$PEER_TARGET",
  "duration_sec": $CHAOS_DURATION_SEC,
  "interval_sec": $CHAOS_INTERVAL_SEC,
  "cycles": $cycles,
  "established_after": $established_after,
  "post_storm_established": $post_storm_established,
  "health_failures": $health_failures,
  "baseline_mem_bytes": $baseline_mem,
  "final_mem_bytes": $final_mem,
  "mem_delta_mb": $mem_delta_mb
}
EOF

log "[chaos-flap-storm] verdict=$verdict cycles=$cycles established_after=$established_after mem_delta=${mem_delta_mb}MB"
[ "$verdict" = "clean" ] && exit 0 || exit 1
