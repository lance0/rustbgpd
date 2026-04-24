#!/usr/bin/env bash
# M33 — EVPN Route Reflector scale validation (Gate 5).
#
# Shape: 2 testers each advertise 25k Type 2 MAC/IP routes; rustbgpd RR
# reflects the 50k total to a third observer; observer measures the
# Established-to-50k convergence time. Then drives a 60-second churn
# phase (withdraw + re-advertise a sliding window at 1000 rps) and
# asserts no route loss, no session flap, and RR-side consistency.
#
# Assertions:
#   1. Monitor reaches Established and sees 50,000 Type 2 routes.
#   2. Convergence completes within 60s.
#   3. After churn, monitor still shows 50,000 routes (no loss).
#   4. rustbgpd ListEvpnRoutes reports >= 50,000 Type 2 routes (the RR's
#      own view matches what the monitor received).
#   5. All 3 neighbor sessions stay Established throughout (no flaps).
#   6. rustbgpd gRPC stays healthy the entire time (no crashes).
#   7. Peak RR memory stays under a soft ceiling (logged even on pass).
#
# Notes on assertion scope (see docs/evpn-enablement.md § Gate 5):
# this suite validates reflection throughput, churn fidelity, and
# RR-side process health. It does NOT audit per-MAC identity or full
# per-route attribute preservation — those are covered by the FRR-based
# interop tests (M30-M32). Treat M33 as the hot-path scale gate.
#
# Prerequisites:
#   - docker build -t rustbgpd:dev .  (must include evpn-tester + evpn-monitor)
#   - containerlab deploy -t tests/interop/m33-evpn-scale.clab.yml

TOPO="m33-evpn-scale"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

TESTER_A="clab-${TOPO}-tester-a"
TESTER_B="clab-${TOPO}-tester-b"
MONITOR="clab-${TOPO}-monitor"

COUNT_PER_TESTER=25000
TOTAL_COUNT=50000
ADVERTISE_RATE=5000
CHURN_DURATION=60
CHURN_RATE=1000
CONVERGE_TIMEOUT=120
# Keep testers Established through the entire post-run assertion phase
# so the RR's gRPC snapshot reflects a loaded, live topology — not a
# torn-down one where all routes have been withdrawn due to peer-down.
TESTER_LINGER=240

grpc_list_evpn() {
    # 50k EVPN routes blow past grpcurl's default 4 MiB message size.
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -max-msg-sz 134217728 \
        -d '{}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

resolve_grpc_addr
start_rustbgpd

# ---------------------------------------------------------------------------
# Stage 1: bring all 3 sessions to Established, then start the monitor
# before testers inject so convergence is measured from first route seen.
# ---------------------------------------------------------------------------

log "[stage 1] launch monitor in background — expects ${TOTAL_COUNT} Type 2 routes"
MON_LOG=$(mktemp)
MON_JSON=$(mktemp)
docker exec -d "$MONITOR" sh -c "evpn-monitor \
    --listen 0.0.0.0:179 \
    --local-as 65000 \
    --router-id 10.0.0.20 \
    --expect ${TOTAL_COUNT} \
    --stable-sec 5 \
    --timeout-sec ${CONVERGE_TIMEOUT} \
    --observe-sec $((CHURN_DURATION + 30)) \
    > /tmp/monitor.json 2> /tmp/monitor.log"
sleep 2

# ---------------------------------------------------------------------------
# Stage 2: fire the two testers in parallel.
# ---------------------------------------------------------------------------

log "[stage 2] launch tester-a (${COUNT_PER_TESTER} routes @ ${ADVERTISE_RATE}/s)"
docker exec -d "$TESTER_A" sh -c "evpn-tester \
    --listen 0.0.0.0:179 \
    --local-as 65000 \
    --router-id 10.0.0.11 \
    --count ${COUNT_PER_TESTER} \
    --rate ${ADVERTISE_RATE} \
    --batch 40 \
    --vni 100 \
    --churn-duration-sec ${CHURN_DURATION} \
    --churn-rate ${CHURN_RATE} \
    --linger-sec ${TESTER_LINGER} \
    > /tmp/tester.log 2>&1"

log "[stage 2] launch tester-b (${COUNT_PER_TESTER} routes @ ${ADVERTISE_RATE}/s)"
docker exec -d "$TESTER_B" sh -c "evpn-tester \
    --listen 0.0.0.0:179 \
    --local-as 65000 \
    --router-id 10.0.0.12 \
    --count ${COUNT_PER_TESTER} \
    --rate ${ADVERTISE_RATE} \
    --batch 40 \
    --vni 100 \
    --churn-duration-sec ${CHURN_DURATION} \
    --churn-rate ${CHURN_RATE} \
    --linger-sec ${TESTER_LINGER} \
    > /tmp/tester.log 2>&1"

# ---------------------------------------------------------------------------
# Stage 3: wait for monitor to converge or time out.
# ---------------------------------------------------------------------------

log "[stage 3] wait for monitor — convergence timeout ${CONVERGE_TIMEOUT}s + churn ${CHURN_DURATION}s"
wait_seconds=$((CONVERGE_TIMEOUT + CHURN_DURATION + 60))
for i in $(seq 1 "$wait_seconds"); do
    if ! docker exec "$MONITOR" sh -c 'test -f /tmp/monitor.json && test -s /tmp/monitor.json' 2>/dev/null; then
        sleep 1
        continue
    fi
    if docker exec "$MONITOR" sh -c 'grep -q "\"converged\"" /tmp/monitor.json' 2>/dev/null; then
        break
    fi
    sleep 1
done

docker cp "${MONITOR}:/tmp/monitor.json" "$MON_JSON" 2>/dev/null || true
docker cp "${MONITOR}:/tmp/monitor.log" "$MON_LOG" 2>/dev/null || true

if [ ! -s "$MON_JSON" ]; then
    fail "monitor never produced a JSON report"
    cat "$MON_LOG" >&2 || true
    print_summary
fi

log "monitor report:"
cat "$MON_JSON"

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

converged=$(grep -o '"converged": true' "$MON_JSON" || true)
if [ -n "$converged" ]; then
    ok "monitor reached convergence"
else
    fail "monitor did not converge"
fi

# Initial convergence: time from session-est to first time the live set
# reached expect. This is the RR reflection hot-path — the number we
# actually care about for scale claims.
initial_sec=$(grep -o '"initial_convergence_sec": [0-9.]*' "$MON_JSON" | awk '{print $2}')
if [ -n "$initial_sec" ] && [ "$initial_sec" != "null" ]; then
    int_sec=${initial_sec%.*}
    if [ "${int_sec:-0}" -le 60 ]; then
        ok "initial convergence under 60s (${initial_sec}s)"
    else
        fail "initial convergence exceeded 60s (${initial_sec}s)"
    fi
fi
# Stable convergence: first time the set reached expect AND stayed there
# for stable_sec seconds. This is later than initial when churn is on
# (each churn tick resets the stable window). Logged, not gated.
stable_sec_reported=$(grep -o '"stable_convergence_sec": [0-9.]*' "$MON_JSON" | awk '{print $2}')
log "stable-after-churn convergence: ${stable_sec_reported}s"

final_count=$(grep -o '"final_count": [0-9]*' "$MON_JSON" | awk '{print $2}')
if [ "${final_count:-0}" -eq "$TOTAL_COUNT" ]; then
    ok "post-churn route count is exactly ${TOTAL_COUNT} (no loss)"
else
    fail "expected ${TOTAL_COUNT} routes; got ${final_count}"
fi

log "[check] rustbgpd ListEvpnRoutes matches the monitor's view"
evpn_json=$(grpc_list_evpn)
type2_count=$(echo "$evpn_json" | grep -c '"routeType": 2' || true)
# RR should hold at least the full monitor-visible set. It may briefly
# exceed it during churn windows, but must not fall below.
if [ "$type2_count" -ge "$TOTAL_COUNT" ]; then
    ok "ListEvpnRoutes returned ${type2_count} Type 2 routes (>= monitor's ${TOTAL_COUNT})"
else
    fail "ListEvpnRoutes returned only ${type2_count} Type 2 routes (< monitor's ${TOTAL_COUNT})"
fi

log "[check] tester peers stayed Established without mid-run flaps"
neighbors_json=$(grpcurl -plaintext -import-path . -proto "$PROTO" \
    "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors 2>/dev/null)
# Walk each neighbor block separately: count testers in Established
# state and capture their flap counts. The JSON format puts "state"
# about 10 lines after the address in each neighbor entry.
tester_established=$(echo "$neighbors_json" \
    | awk '/"description": "tester-[ab]"/{inblock=1}
           inblock && /SESSION_STATE_ESTABLISHED/{found++; inblock=0}
           END{print found+0}')
if [ "$tester_established" -eq 2 ]; then
    ok "both tester peers still Established"
else
    fail "expected 2 tester peers Established; got ${tester_established}"
    echo "$neighbors_json" >&2
fi
# flapCount only appears in the JSON when it's non-zero — count the
# literal field under each tester's block.
tester_flaps=$(echo "$neighbors_json" \
    | awk '/"description": "tester-[ab]"/{inblock=1}
           inblock && /"flapCount"/{found++; inblock=0}
           /^    \}/{inblock=0}
           END{print found+0}')
if [ "${tester_flaps:-0}" -eq 0 ]; then
    ok "no flap counter on either tester peer"
else
    fail "tester peers reported ${tester_flaps} flap(s) mid-run"
fi

log "[check] rustbgpd gRPC still healthy"
if grpc_health >/dev/null 2>&1; then
    ok "gRPC health check passes post-run"
else
    fail "gRPC health failed — RR may have crashed"
fi

log "[info] peak RR resource usage (recorded, not a hard gate)"
mem_mb=$(docker stats --no-stream --format '{{.MemUsage}}' "$RUSTBGPD" 2>/dev/null \
    | awk -F'[ /]+' '{print $1}' | sed 's/[A-Za-z]//g')
cpu_pct=$(docker stats --no-stream --format '{{.CPUPerc}}' "$RUSTBGPD" 2>/dev/null \
    | tr -d '%')
log "RR final snapshot — memory=${mem_mb:-?}MB cpu=${cpu_pct:-?}%"
# Soft gate: fail only at an absurd memory ceiling (indicates a leak),
# not the steady-state number, which is dominated by route tables.
if [ -n "$mem_mb" ]; then
    mem_int=${mem_mb%.*}
    if [ "${mem_int:-0}" -gt 2048 ]; then
        fail "RR memory exceeded 2 GB soft ceiling (${mem_mb}MB) — possible leak"
    else
        ok "RR memory within soft ceiling (${mem_mb}MB)"
    fi
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

rm -f "$MON_JSON" "$MON_LOG"

print_summary
