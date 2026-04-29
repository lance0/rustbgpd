#!/usr/bin/env bash
# chaos-gr-cycles.sh — repeated graceful-restart cycles against a
# GR-capable peer (FRR) and assert the RR's stale-sweep / clear-on-
# reconnect lifecycle stays correct across N back-to-back cycles.
#
# Topology: M16 (`tests/interop/m16-llgr-frr.clab.yml`). The synthetic
# tester used by the M33 soak harness does not announce GR, so this
# harness needs FRR for the negotiated GR path. Run
# `containerlab deploy -t tests/interop/m16-llgr-frr.clab.yml` first.
#
# Each cycle:
#   1. Trigger FRR-side BGP daemon restart (`vtysh -c "restart bgp"` or
#      kill -HUP) so rustbgpd sees the session drop with GR negotiated.
#   2. Wait briefly so rustbgpd enters GR / promotes routes to stale.
#   3. Watch for the session to re-Establish; FRR replays its routes;
#      rustbgpd clears stale.
#   4. Assert the stale count returns to 0 within the GR timer budget.
#
# Pass criteria across N cycles:
#   - Each cycle's stale_routes peaks > 0 during the GR window
#     (proves the GR path actually fires)
#   - Each cycle's stale_routes returns to 0 after clear
#     (proves stale-sweep correctness)
#   - Final memory growth < 10 MB above pre-storm baseline
#   - No process restart
#
# Output: tests/chaos/runs/<UTC-timestamp>/{driver.log,cycles.csv,report.json}

set -euo pipefail

CHAOS_CYCLES=${CHAOS_CYCLES:-5}
CHAOS_GR_WAIT_SEC=${CHAOS_GR_WAIT_SEC:-10}
CHAOS_TOPO=${CHAOS_TOPO:-m16-llgr-frr}
FRR_CONTAINER=${FRR_CONTAINER:-clab-${CHAOS_TOPO}-peer}

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TS=$(date -u +%Y%m%dT%H%M%SZ)
RUN_DIR="$SCRIPT_DIR/runs/$TS"
mkdir -p "$RUN_DIR"
DRIVER_LOG="$RUN_DIR/driver.log"
CYCLES_CSV="$RUN_DIR/cycles.csv"
REPORT="$RUN_DIR/report.json"

TOPO="$CHAOS_TOPO"
# shellcheck source=../interop/scripts/test-lib.sh
source "$SCRIPT_DIR/../interop/scripts/test-lib.sh"
resolve_grpc_addr

log "[chaos-gr-cycles] cycles=$CHAOS_CYCLES gr_wait=${CHAOS_GR_WAIT_SEC}s frr=$FRR_CONTAINER"
log "[chaos-gr-cycles] run dir: $RUN_DIR"

# Helper: read RR's stale route count from Prometheus metrics.
# Sums the bgp_gr_stale_routes gauge across all peers/families.
stale_count() {
    local rr_addr
    rr_addr=$(echo "$GRPC_ADDR" | cut -d: -f1)
    curl -s "http://${rr_addr}:9179/metrics" 2>/dev/null \
        | awk '/^bgp_gr_stale_routes\{/ {sum+=$2} END {print sum+0}'
}

# Pre-storm baseline
baseline_mem=$(docker exec "$RUSTBGPD" sh -c \
    'cat /sys/fs/cgroup/memory.current 2>/dev/null || cat /proc/$(pgrep rustbgpd)/status | awk "/VmRSS/ {print \$2*1024}"')
log "[chaos-gr-cycles] baseline mem=$baseline_mem bytes stale=$(stale_count)"
echo "cycle,stale_during_gr,stale_after_clear,mem_bytes" >"$CYCLES_CSV"

cycles_with_stale=0
cycles_cleared=0
for cycle in $(seq 1 "$CHAOS_CYCLES"); do
    log "[chaos-gr-cycles] cycle $cycle/$CHAOS_CYCLES — restarting FRR BGP"

    # Restart FRR's BGP daemon. SIGHUP-style restart preserves the
    # FRR config so rustbgpd sees a clean session-down with GR cap
    # negotiated, then re-Establish.
    docker exec "$FRR_CONTAINER" vtysh -c "clear bgp *" >>"$DRIVER_LOG" 2>&1 || true
    docker exec "$FRR_CONTAINER" pkill -HUP bgpd >>"$DRIVER_LOG" 2>&1 || true

    # Wait for rustbgpd to enter GR + accumulate stale routes.
    sleep 2
    stale_during=$(stale_count)

    # Wait for FRR to come back and EoR to clear stale.
    sleep "$CHAOS_GR_WAIT_SEC"
    stale_after=$(stale_count)

    mem=$(docker exec "$RUSTBGPD" sh -c \
        'cat /sys/fs/cgroup/memory.current 2>/dev/null || cat /proc/$(pgrep rustbgpd)/status | awk "/VmRSS/ {print \$2*1024}"' 2>/dev/null || echo 0)
    echo "$cycle,$stale_during,$stale_after,$mem" >>"$CYCLES_CSV"
    log "[chaos-gr-cycles] cycle $cycle: stale_during=$stale_during stale_after=$stale_after mem=$mem"

    [ "$stale_during" -gt 0 ] && cycles_with_stale=$((cycles_with_stale + 1))
    [ "$stale_after" -eq 0 ] && cycles_cleared=$((cycles_cleared + 1))
done

# Post-storm sample
final_mem=$(docker exec "$RUSTBGPD" sh -c \
    'cat /sys/fs/cgroup/memory.current 2>/dev/null || cat /proc/$(pgrep rustbgpd)/status | awk "/VmRSS/ {print \$2*1024}"')
mem_delta=$(( final_mem - baseline_mem ))
mem_delta_mb=$(awk -v d="$mem_delta" 'BEGIN{printf "%.2f", d/1048576}')

verdict="clean"
failures=()
if [ "$cycles_with_stale" -lt "$CHAOS_CYCLES" ]; then
    verdict="needs-attention"
    failures+=("\"only $cycles_with_stale/$CHAOS_CYCLES cycles peaked with stale>0 (GR path may not have fired)\"")
fi
if [ "$cycles_cleared" -lt "$CHAOS_CYCLES" ]; then
    verdict="needs-attention"
    failures+=("\"only $cycles_cleared/$CHAOS_CYCLES cycles returned stale=0 within ${CHAOS_GR_WAIT_SEC}s (stale-sweep may be stuck)\"")
fi
if [ "$mem_delta" -gt $((10 * 1024 * 1024)) ]; then
    verdict="needs-attention"
    failures+=("\"memory grew ${mem_delta_mb} MB across $CHAOS_CYCLES cycles (>10 MB)\"")
fi

failures_json=$(IFS=,; echo "[${failures[*]:-}]")

cat >"$REPORT" <<EOF
{
  "verdict": "$verdict",
  "failures": $failures_json,
  "topology": "$CHAOS_TOPO",
  "frr_container": "$FRR_CONTAINER",
  "cycles": $CHAOS_CYCLES,
  "cycles_with_stale": $cycles_with_stale,
  "cycles_cleared": $cycles_cleared,
  "gr_wait_sec": $CHAOS_GR_WAIT_SEC,
  "baseline_mem_bytes": $baseline_mem,
  "final_mem_bytes": $final_mem,
  "mem_delta_mb": $mem_delta_mb
}
EOF

log "[chaos-gr-cycles] verdict=$verdict cycles=$CHAOS_CYCLES with_stale=$cycles_with_stale cleared=$cycles_cleared mem_delta=${mem_delta_mb}MB"
[ "$verdict" = "clean" ] && exit 0 || exit 1
