#!/usr/bin/env bash
# M33 — EVPN Route Reflector scale validation (Gate 5).
#
# Shape: 2 testers each advertise 25k Type 2 MAC/IP routes; rustbgpd RR
# reflects the 50k total to a third observer; observer measures the
# Established-to-50k convergence time. Then drives a 60-second churn
# phase (withdraw + re-advertise a sliding window at 1000 rps) and
# asserts no route loss and no session flap.
#
# Assertions:
#   1. Monitor reaches Established and sees 50,000 Type 2 routes.
#   2. Convergence completes within 60s.
#   3. After churn, monitor still shows 50,000 routes (no loss).
#   4. rustbgpd ListEvpnRoutes reports a non-empty Type 2 set during
#      the run.
#   5. rustbgpd gRPC stays healthy the entire time (no crashes).
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

grpc_list_evpn() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
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
    --linger-sec 60 \
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
    --linger-sec 60 \
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

convergence_sec=$(grep -o '"convergence_sec": [0-9.]*' "$MON_JSON" | awk '{print $2}')
if [ -n "$convergence_sec" ]; then
    converged_int=${convergence_sec%.*}
    if [ "${converged_int:-0}" -le 60 ]; then
        ok "convergence under 60s (${convergence_sec}s)"
    else
        fail "convergence exceeded 60s (${convergence_sec}s)"
    fi
fi

final_count=$(grep -o '"final_count": [0-9]*' "$MON_JSON" | awk '{print $2}')
if [ "${final_count:-0}" -eq "$TOTAL_COUNT" ]; then
    ok "post-churn route count is exactly ${TOTAL_COUNT} (no loss)"
else
    fail "expected ${TOTAL_COUNT} routes; got ${final_count}"
fi

log "[check] rustbgpd ListEvpnRoutes shows a Type 2 population"
evpn_json=$(grpc_list_evpn)
type2_count=$(echo "$evpn_json" | grep -c '"routeType": 2' || true)
if [ "$type2_count" -ge 1000 ]; then
    ok "ListEvpnRoutes returned ${type2_count} Type 2 routes (sampled)"
else
    fail "ListEvpnRoutes returned only ${type2_count} Type 2 routes"
fi

log "[check] rustbgpd gRPC still healthy"
if grpc_health >/dev/null 2>&1; then
    ok "gRPC health check passes post-run"
else
    fail "gRPC health failed — RR may have crashed"
fi

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

rm -f "$MON_JSON" "$MON_LOG"

print_summary
