#!/usr/bin/env bash
# M49 smoke — RFC 9785 Highest-Preference DF election against a 2-PE
# rustbgpd Ethernet Segment.
#
# Both PEs run `df_algorithm = "highest-preference"`. PE1 has
# df_preference 100; PE2 has df_preference 200 and df_dont_preempt=true.
# For (ESI 00:..:01, VNI 200) Highest-Preference elects PE2 (preference
# 200 > 100). Default service carving would elect PE1 (200 mod 2 = slot
# 0 -> lower IP), so PE2 winning is only possible if the RFC 9785
# preference algorithm — negotiated over the DF Election Extended
# Community — actually drives the election. That makes assertion (2) a
# positive proof that preference-DF is in effect, not modulo (i.e. it
# guards against a silent fall-back to default carving). The byte-exact
# DF Election extcomm, including the Don't-Preempt bit, is pinned by the
# `preference_df_election_extcomm_*` unit test.
#
# NOT cross-vendor: both PEs are rustbgpd. M69 covers FRR
# preference-DF interop separately.
#
# Asserts:
#   1. Both PEs exchange both Type 4 ES candidates.
#   2. PE2 reports DF=1 / NonDF=0 for (esi, vni=200) — preference winner.
#   3. PE1 reports DF=0 / NonDF=1 — loser under preference (modulo winner).
#   4. After PE2 (the DF) shuts down, PE1 promotes to DF and
#      `evpn_df_role_changes_total{...,vni="200"}` increments.
#
# Usage:
#   docker build -t rustbgpd:dev .
#   sudo containerlab deploy -t tests/interop/m49-evpn-preference-df.clab.yml
#   bash tests/interop/scripts/test-m49-evpn-preference-df.sh
#   sudo containerlab destroy -t tests/interop/m49-evpn-preference-df.clab.yml

set -eu

TOPO="m49-evpn-preference-df"
PE1="clab-${TOPO}-pe1"
PE2="clab-${TOPO}-pe2"
ESI="00:00:00:00:00:00:00:00:00:01"
VNI="200"
PROTO="proto/rustbgpd.proto"

resolve_ip() {
    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>/dev/null
}

# Scrape Prometheus from the host — the slim runtime image carries no
# curl/wget inside the container.
prom_scrape() {
    local container=${1:?}
    local ip
    ip=$(resolve_ip "$container")
    [ -z "$ip" ] && {
        echo "ERROR: could not resolve management IP for $container" >&2
        return 1
    }
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || wget -qO- -T 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || true
}

prom_df_role() {
    local container=${1:?} role=${2:?}
    prom_scrape "$container" \
        | awk -v esi="$ESI" -v vni="$VNI" -v role="$role" '
            $0 ~ /^evpn_df_role\{/ \
                && index($0, "esi=\"" esi "\"") \
                && index($0, "vni=\"" vni "\"") \
                && index($0, "role=\"" role "\"") { print $NF; exit }'
}

prom_df_role_changes() {
    local container=${1:?}
    prom_scrape "$container" \
        | awk -v esi="$ESI" -v vni="$VNI" '
            $0 ~ /^evpn_df_role_changes_total\{/ \
                && index($0, "esi=\"" esi "\"") \
                && index($0, "vni=\"" vni "\"") { print $NF; exit }'
}

wait_for_role() {
    local container=${1:?} role=${2:?} want=${3:?} timeout=${4:-60}
    for _ in $(seq 1 "$timeout"); do
        [ "$(prom_df_role "$container" "$role")" = "$want" ] && return 0
        sleep 1
    done
    return 1
}

grpc_list_evpn() {
    local container=${1:?} route_type=${2:?} ip
    ip=$(resolve_ip "$container")
    [ -z "$ip" ] && return 1
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d "{\"route_type_filter\": $route_type}" \
        "${ip}:50051" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
}

evpn_route_count() {
    local container=${1:?} route_type=${2:?} json
    json=$(grpc_list_evpn "$container" "$route_type") || return 1
    [ -z "$json" ] && return 1
    printf '%s' "$json" | python3 -c 'import json,sys; print(len(json.load(sys.stdin).get("routes", [])))'
}

wait_for_route_count() {
    local container=${1:?} route_type=${2:?} want=${3:?} timeout=${4:-60}
    for _ in $(seq 1 "$timeout"); do
        local got
        got=$(evpn_route_count "$container" "$route_type" 2>/dev/null || echo 0)
        [ "$got" -ge "$want" ] && return 0
        sleep 1
    done
    return 1
}

stop_rustbgpd_daemon() {
    local container=${1:?}
    docker exec "$container" sh -c \
        'pid=$(pidof rustbgpd) && [ -n "$pid" ] && kill -TERM $pid' 2>/dev/null || true
    for _ in $(seq 1 30); do
        docker exec "$container" pidof rustbgpd >/dev/null 2>&1 || return 0
        sleep 1
    done
    echo "ERROR: rustbgpd did not exit in $container within 30s of SIGTERM" >&2
    return 1
}

PASS=0
FAIL=0
TOTAL=0
assert() {
    local desc=${1:?} cmd=${2:?}
    TOTAL=$((TOTAL + 1))
    if eval "$cmd"; then
        echo "PASS — $desc"
        PASS=$((PASS + 1))
    else
        echo "FAIL — $desc"
        FAIL=$((FAIL + 1))
    fi
}

echo "Waiting up to 60s for Type 4 ES candidate exchange..."
assert "PE1 LocRib has both Type 4 ES candidates" 'wait_for_route_count "$PE1" 4 2 60'
assert "PE2 LocRib has both Type 4 ES candidates" 'wait_for_route_count "$PE2" 4 2 60'

echo "Waiting up to 60s for preference-DF election to land (PE2 wins on preference)..."
# Positive proof of preference-DF: PE2 (higher preference, lower-priority
# under modulo) is DF. Default modulo carving for VNI 200 would have
# elected PE1, so this can only hold under RFC 9785 Highest-Preference.
assert "PE2 reports DF=1 for (esi=$ESI, vni=$VNI) — the preference winner" \
    'wait_for_role "$PE2" df 1 60'
assert "PE2 reports NonDF=0 for the same key" \
    '[ "$(prom_df_role "$PE2" nondf)" = "0" ]'
assert "PE1 reports DF=0 (preference loser; modulo would have made it DF)" \
    'wait_for_role "$PE1" df 0 60'
assert "PE1 reports NonDF=1 for the same key" \
    '[ "$(prom_df_role "$PE1" nondf)" = "1" ]'

PE1_BEFORE=$(prom_df_role_changes "$PE1")
PE1_BEFORE=${PE1_BEFORE:-0}
echo "PE1 evpn_df_role_changes_total before PE2 shutdown: $PE1_BEFORE"

echo "Stopping PE2 (the preference DF) to force DF promotion on PE1..."
stop_rustbgpd_daemon "$PE2"

echo "Waiting up to 120s for PE1 to promote to DF..."
assert "PE1 promotes to DF after PE2 shutdown" 'wait_for_role "$PE1" df 1 120'

PE1_AFTER=$(prom_df_role_changes "$PE1")
PE1_AFTER=${PE1_AFTER:-0}
echo "PE1 evpn_df_role_changes_total after promotion: $PE1_AFTER"
assert "PE1 evpn_df_role_changes_total advanced after promotion" \
    'awk -v b="$PE1_BEFORE" -v a="$PE1_AFTER" "BEGIN { exit !(a > b) }"'

echo ""
echo "M49 smoke: $PASS/$TOTAL passed, $FAIL failed."
[[ $FAIL -eq 0 ]]
