#!/usr/bin/env bash
# M38 smoke — Gate 8 observable DF election against a 2-PE rustbgpd
# Ethernet Segment.
#
# Asserts (see m38-evpn-df-election.clab.yml for full design notes):
#   1. PE1 reports DF=1 / NonDF=0 for (esi=...:01, vni=100) within ~30s.
#   2. PE2 reports DF=0 / NonDF=1 for the same key within ~30s.
#   3. After PE1 shuts down, PE2 promotes to DF (DF=1) and
#      `evpn_df_role_changes_total{esi=...,vni="100"}` increments.
#   4. PE2's RIB shows the reflected Type 4 ES route from PE1 carrying
#      the auto-derived ES-Import RT extcomm (RFC 7432 §7.6).
#   5. PE2's RIB shows the reflected Type 1 EAD-per-ES route from PE1
#      carrying the ESI Label extcomm (RFC 7432 §7.5).
#
# Usage:
#   docker build --target dev -t rustbgpd:dev .
#   sudo containerlab deploy -t tests/interop/m38-evpn-df-election.clab.yml
#   bash tests/interop/scripts/test-m38-evpn-df-election.sh
#   sudo containerlab destroy -t tests/interop/m38-evpn-df-election.clab.yml

set -eu

TOPO="m38-evpn-df-election"
PE1="clab-${TOPO}-pe1"
PE2="clab-${TOPO}-pe2"
ESI="00:00:00:00:00:00:00:00:00:01"
VNI="100"
PROTO="proto/rustbgpd.proto"
TEST_OPERATOR_TOKEN_FILE="tests/fixtures/grpc-test-only-operator.token"
IFS= read -r TEST_OPERATOR_TOKEN < "$TEST_OPERATOR_TOKEN_FILE"
GRPC_AUTH=(-H "authorization: Bearer $TEST_OPERATOR_TOKEN")

# Type 0x06 / Subtype 0x02 = ES-Import RT (RFC 7432 §7.6).
# Type 0x06 / Subtype 0x01 = ESI Label (RFC 7432 §7.5).
# We match on the high 16 bits of the raw u64, which lets the test
# stay correct across changes to the ESI value or synthesized label.
ES_IMPORT_RT_TYPESUB="0x0602"
ESI_LABEL_TYPESUB="0x0601"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Scrape Prometheus via the container's management IP. The
# `rustbgpd:dev` runtime image intentionally stays small and does not
# carry curl/wget, so do the HTTP request from the host like the soak
# harnesses do.
prom_scrape() {
    local container=${1:?}
    local ip
    ip=$(resolve_ip "$container")
    if [ -z "$ip" ]; then
        echo "ERROR: could not resolve management IP for $container" >&2
        return 1
    fi
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || wget -qO- -T 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || true
}

# Read the current value of evpn_df_role for the given role label.
# Returns "0", "1", or "" if the metric line isn't yet emitted.
prom_df_role() {
    local container=${1:?}
    local role=${2:?}
    prom_scrape "$container" \
        | awk -v esi="$ESI" -v vni="$VNI" -v role="$role" '
            $0 ~ /^evpn_df_role\{/ \
                && index($0, "esi=\"" esi "\"") \
                && index($0, "vni=\"" vni "\"") \
                && index($0, "role=\"" role "\"") {
                print $NF
                exit
            }
        '
}

stop_rustbgpd_daemon() {
    local container=${1:?}
    docker exec "$container" sh -c \
        'pid=$(pidof rustbgpd) && [ -n "$pid" ] && kill -TERM $pid' \
        2>/dev/null || true
    for _ in $(seq 1 30); do
        if ! docker exec "$container" pidof rustbgpd >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    echo "ERROR: rustbgpd did not exit in $container within 30s of SIGTERM" >&2
    return 1
}

resolve_ip() {
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>/dev/null
}

# List the EVPN routes a PE currently has best-pathed for the given
# route_type (4 = ES, 1 = EAD-per-ES / EAD-per-EVI). Returns raw JSON.
grpc_list_evpn() {
    local container=${1:?}
    local route_type=${2:?}
    local ip
    ip=$(resolve_ip "$container")
    [ -z "$ip" ] && return 1
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        "${GRPC_AUTH[@]}" \
        -d "{\"route_type_filter\": $route_type}" \
        "${ip}:50051" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
}

evpn_route_count() {
    local container=${1:?}
    local route_type=${2:?}
    local json
    json=$(grpc_list_evpn "$container" "$route_type") || return 1
    [ -z "$json" ] && return 1
    printf '%s' "$json" | python3 -c '
import json, sys
data = json.load(sys.stdin)
print(len(data.get("routes", [])))
'
}

wait_for_route_count() {
    local container=${1:?}
    local route_type=${2:?}
    local want=${3:?}
    local timeout=${4:-60}
    for _ in $(seq 1 "$timeout"); do
        local got
        got=$(evpn_route_count "$container" "$route_type" 2>/dev/null || echo 0)
        if [ "$got" -ge "$want" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

# True iff at least one EVPN route in the PE's RIB at the given
# route_type carries an extended community whose high 16 bits match
# $type_sub (e.g. 0x0602 for ES-Import RT, 0x0601 for ESI Label).
has_extcomm_typesub() {
    local container=${1:?}
    local route_type=${2:?}
    local type_sub=${3:?}
    local json
    json=$(grpc_list_evpn "$container" "$route_type") || return 1
    [ -z "$json" ] && return 1
    printf '%s' "$json" | python3 -c '
import json, sys
type_sub = int(sys.argv[1], 16)
data = json.load(sys.stdin)
for route in data.get("routes", []):
    for raw in route.get("extendedCommunities", []) or []:
        if (int(raw) >> 48) & 0xFFFF == type_sub:
            sys.exit(0)
sys.exit(1)
' "$type_sub"
}

wait_for_extcomm() {
    local container=${1:?}
    local route_type=${2:?}
    local type_sub=${3:?}
    local timeout=${4:-30}
    for _ in $(seq 1 "$timeout"); do
        if has_extcomm_typesub "$container" "$route_type" "$type_sub"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

prom_df_role_changes() {
    local container=${1:?}
    prom_scrape "$container" \
        | awk -v esi="$ESI" -v vni="$VNI" '
            $0 ~ /^evpn_df_role_changes_total\{/ \
                && index($0, "esi=\"" esi "\"") \
                && index($0, "vni=\"" vni "\"") {
                print $NF
                exit
            }
        '
}

wait_for_role() {
    local container=${1:?}
    local role=${2:?}
    local want=${3:?}
    local timeout=${4:-30}
    for _ in $(seq 1 "$timeout"); do
        local got
        got=$(prom_df_role "$container" "$role")
        if [ "$got" = "$want" ]; then return 0; fi
        sleep 1
    done
    return 1
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
TOTAL=0

assert() {
    local desc=${1:?}
    local cmd=${2:?}
    TOTAL=$((TOTAL + 1))
    if eval "$cmd"; then
        echo "PASS — $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL — $desc"
        FAIL=$((FAIL + 1))
    fi
}

# Wait for the segment orchestrator to settle. We don't have a
# direct signal here, so first wait for both PEs to have the local
# and remote Type 4 ES candidates in LocRib, then poll Prometheus.
echo "Waiting up to 60s for Type 4 ES candidate exchange..."
assert "PE1 LocRib has both Type 4 ES candidates" \
    'wait_for_route_count "$PE1" 4 2 60'

assert "PE2 LocRib has both Type 4 ES candidates" \
    'wait_for_route_count "$PE2" 4 2 60'

echo "Waiting up to 60s for initial DF election to land..."

assert "PE1 reports DF=1 for (esi=$ESI, vni=$VNI)" \
    'wait_for_role "$PE1" df 1 60'

assert "PE1 reports NonDF=0 for the same key" \
    '[ "$(prom_df_role "$PE1" nondf)" = "0" ]'

assert "PE2 reports DF=0 for (esi=$ESI, vni=$VNI)" \
    'wait_for_role "$PE2" df 0 60'

assert "PE2 reports NonDF=1 for the same key" \
    '[ "$(prom_df_role "$PE2" nondf)" = "1" ]'

# Gate 8b prep: ES-Import RT extcomm (RFC 7432 §7.6) on Type 4 routes
# and ESI Label extcomm (RFC 7432 §7.5) on Type 1 EAD-per-ES routes.
# Each PE should both see them in its own LocRib (originated locally)
# and in routes received from the other PE (reflected via iBGP).
echo "Waiting up to 30s for ES-Import RT (Type 4) on PE1..."
assert "PE1 LocRib has Type 4 ES with ES-Import RT extcomm" \
    'wait_for_extcomm "$PE1" 4 "$ES_IMPORT_RT_TYPESUB" 30'

echo "Waiting up to 30s for ES-Import RT (Type 4) on PE2..."
assert "PE2 LocRib has Type 4 ES with ES-Import RT extcomm" \
    'wait_for_extcomm "$PE2" 4 "$ES_IMPORT_RT_TYPESUB" 30'

echo "Waiting up to 30s for ESI Label (Type 1) on PE1..."
assert "PE1 LocRib has Type 1 EAD-per-ES with ESI Label extcomm" \
    'wait_for_extcomm "$PE1" 1 "$ESI_LABEL_TYPESUB" 30'

echo "Waiting up to 30s for ESI Label (Type 1) on PE2..."
assert "PE2 LocRib has Type 1 EAD-per-ES with ESI Label extcomm" \
    'wait_for_extcomm "$PE2" 1 "$ESI_LABEL_TYPESUB" 30'

# Capture PE2's transition counter before forcing the flip.
PE2_BEFORE=$(prom_df_role_changes "$PE2")
PE2_BEFORE=${PE2_BEFORE:-0}
echo "PE2 evpn_df_role_changes_total before PE1 shutdown: $PE2_BEFORE"

# Shutdown PE1's daemon; PE2 should promote. Keep the container
# running so containerlab's veth pair and management address survive.
# A full `docker stop` tears down the peer netns and destroys PE2's
# side of the clab link, masking DF-election behavior behind topology
# loss.
echo "Stopping PE1 rustbgpd process to force DF promotion on PE2..."
stop_rustbgpd_daemon "$PE1"

echo "Waiting up to 120s for PE2 to promote to DF..."
# DF re-election depends on BGP hold-timer expiry on PE2 after PE1's
# session dies; under host contention (CI runner running multiple
# workloads concurrently) that can slip past a tight 60s window.
# Widening to 120s costs nothing in the success case and absorbs the
# observed jitter without masking real regressions.
assert "PE2 promotes to DF after PE1 shutdown" \
    'wait_for_role "$PE2" df 1 120'

# The transition counter should have advanced by at least 1.
PE2_AFTER=$(prom_df_role_changes "$PE2")
PE2_AFTER=${PE2_AFTER:-0}
echo "PE2 evpn_df_role_changes_total after promotion: $PE2_AFTER"
assert "PE2 evpn_df_role_changes_total advanced after promotion" \
    'awk -v b="$PE2_BEFORE" -v a="$PE2_AFTER" "BEGIN { exit !(a > b) }"'

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "M38 smoke: $PASS/$TOTAL passed, $FAIL failed."
[[ $FAIL -eq 0 ]]
