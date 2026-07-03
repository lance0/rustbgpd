#!/usr/bin/env bash
# M32b — EVPN Type 1 EAD-per-EVI reflection (synthetic).
#
# Closes the Phase 1 coverage gap that M32-against-FRR can't hit:
# FRR only originates EAD-per-EVI when the local ES is bound to a
# specific EVI via VLAN-aware bridge + SVI sub-interface, which is
# Phase 3 setup. M32b uses the in-tree `evpn-tester` with
# `--route-type ead-per-evi` to originate Type 1 EAD-per-EVI directly,
# so the RR's reflection of that route type is exercised end-to-end
# without depending on FRR.
#
# Shape: tester originates N EAD-per-EVI routes; RR reflects them
# through to the monitor; monitor counts Type 1 EAD-per-EVI keys.
#
# Assertions:
#   1. tester + monitor reach Established on L2VPN/EVPN.
#   2. Monitor reaches `expect` Type 1 EAD-per-EVI keys within timeout.
#   3. rustbgpd ListEvpnRoutes reports `expect` Type 1 routes.
#   4. RR gRPC stays healthy throughout.
#
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - containerlab deploy -t tests/interop/m32b-evpn-ead-synthetic.clab.yml

TOPO="m32b-evpn-ead-synthetic"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

TESTER="clab-${TOPO}-tester-ead"
MONITOR="clab-${TOPO}-monitor"

EAD_COUNT=500
ADVERTISE_RATE=2000
CONVERGE_TIMEOUT=60
TESTER_LINGER=120

grpc_list_evpn() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -max-msg-sz 16777216 \
        -d '{}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

resolve_grpc_addr
start_rustbgpd

log "[stage 1] launch monitor — expects ${EAD_COUNT} Type 1 EAD-per-EVI routes"
docker exec -d "$MONITOR" sh -c "evpn-monitor \
    --listen 0.0.0.0:179 \
    --local-as 65000 \
    --router-id 10.0.0.20 \
    --route-type ead-per-evi \
    --expect ${EAD_COUNT} \
    --stable-sec 5 \
    --timeout-sec ${CONVERGE_TIMEOUT} \
    --observe-sec 10 \
    > /tmp/monitor.json 2> /tmp/monitor.log"
sleep 2

log "[stage 2] launch tester (${EAD_COUNT} EAD-per-EVI routes @ ${ADVERTISE_RATE}/s)"
docker exec -d "$TESTER" sh -c "evpn-tester \
    --listen 0.0.0.0:179 \
    --local-as 65000 \
    --router-id 10.0.0.11 \
    --route-type ead-per-evi \
    --count ${EAD_COUNT} \
    --rate ${ADVERTISE_RATE} \
    --batch 40 \
    --vni 100 \
    --linger-sec ${TESTER_LINGER} \
    > /tmp/tester.log 2>&1"

log "[stage 3] wait for monitor — convergence timeout ${CONVERGE_TIMEOUT}s"
wait_seconds=$((CONVERGE_TIMEOUT + 30))
for _ in $(seq 1 "$wait_seconds"); do
    if docker exec "$MONITOR" sh -c 'test -f /tmp/monitor.json && test -s /tmp/monitor.json' 2>/dev/null \
        && docker exec "$MONITOR" sh -c 'grep -q "\"converged\"" /tmp/monitor.json' 2>/dev/null; then
        break
    fi
    sleep 1
done

MON_JSON=$(mktemp)
docker cp "${MONITOR}:/tmp/monitor.json" "$MON_JSON" 2>/dev/null || true

if [ ! -s "$MON_JSON" ]; then
    fail "monitor never produced a JSON report"
    docker cp "${MONITOR}:/tmp/monitor.log" /tmp/m32b-monitor.log 2>/dev/null || true
    cat /tmp/m32b-monitor.log >&2 || true
    print_summary
fi

log "monitor report:"
cat "$MON_JSON"

converged=$(grep -o '"converged": true' "$MON_JSON" || true)
if [ -n "$converged" ]; then
    ok "monitor reached convergence on Type 1 EAD-per-EVI"
else
    fail "monitor did not converge on Type 1 EAD-per-EVI"
fi

initial_sec=$(jq -r '.initial_convergence_sec // "null"' "$MON_JSON")
if [ -n "$initial_sec" ] && [ "$initial_sec" != "null" ]; then
    int_sec=${initial_sec%.*}
    if [ "${int_sec:-0}" -le 30 ]; then
        ok "initial convergence under 30s (${initial_sec}s)"
    else
        fail "initial convergence exceeded 30s (${initial_sec}s)"
    fi
fi

final_count=$(grep -o '"final_count": [0-9]*' "$MON_JSON" | awk '{print $2}')
if [ "${final_count:-0}" -eq "$EAD_COUNT" ]; then
    ok "monitor saw exactly ${EAD_COUNT} Type 1 EAD-per-EVI keys"
else
    fail "expected ${EAD_COUNT} Type 1 EAD-per-EVI keys; got ${final_count}"
fi

log "[check] rustbgpd ListEvpnRoutes shows the EAD-per-EVI routes"
evpn_json=$(grpc_list_evpn)
type1_count=$(echo "$evpn_json" | grep -c '"routeType": 1' || true)
if [ "$type1_count" -ge "$EAD_COUNT" ]; then
    ok "ListEvpnRoutes returned ${type1_count} Type 1 routes (>= monitor's ${EAD_COUNT})"
else
    fail "ListEvpnRoutes returned only ${type1_count} Type 1 routes (< ${EAD_COUNT})"
fi

log "[check] tester peer stayed Established"
neighbors_json=$(grpcurl -plaintext -import-path . -proto "$PROTO" \
    "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors 2>/dev/null)
if ! command -v jq >/dev/null 2>&1; then
    fail "jq is required for neighbor-state parsing (install with apt-get install jq)"
    print_summary
fi
tester_established=$(echo "$neighbors_json" | jq -r '
    [.neighbors[]?
        | select(.config.description // "" == "tester-ead")
        | select(.state == "SESSION_STATE_ESTABLISHED")]
    | length')
if [ "$tester_established" -eq 1 ]; then
    ok "tester peer still Established"
else
    fail "tester peer not Established"
fi

log "[check] rustbgpd gRPC still healthy"
if grpc_health >/dev/null 2>&1; then
    ok "gRPC health check passes post-run"
else
    fail "gRPC health failed"
fi

print_summary
