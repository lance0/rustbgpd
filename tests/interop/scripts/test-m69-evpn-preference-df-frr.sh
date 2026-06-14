#!/usr/bin/env bash
# M69 smoke — RFC 9785 Highest-Preference DF election across rustbgpd
# and FRR.
#
# rustbgpd advertises preference 100, FRR advertises preference 200 via
# `evpn mh es-df-pref 200`. Default service carving would elect
# rustbgpd for VNI 200, so asserting rustbgpd NonDF + FRR DF proves the
# preference-DF signal is understood cross-vendor.

set -euo pipefail

TOPO="m69-evpn-preference-df-frr"
RUSTBGPD="clab-${TOPO}-pe1"
PE1="$RUSTBGPD"
PE2="clab-${TOPO}-pe2"
PE1_IP="10.0.0.1"
PE2_IP="10.0.0.2"
ESI="03:aa:bb:cc:dd:ee:ff:00:00:01"
VNI="200"
# ExtendedCommunity::df_election(HighestPreference=2, capabilities=0,
# preference=200), rendered as protobuf JSON's uint64 string.
FRR_DF_EXTCOMM="434036613111087304"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

wait_grpc_ready() {
    log "Waiting for rustbgpd gRPC..."
    for i in $(seq 1 30); do
        if grpc_health >/dev/null 2>&1; then
            ok "rustbgpd gRPC endpoint ready (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "rustbgpd gRPC endpoint not reachable within 60s"
    return 1
}

grpc_list_type4() {
    grpcurl -plaintext -import-path . -proto "$PROTO" \
        -d '{"route_type_filter": 4}' \
        "$GRPC_ADDR" rustbgpd.v1.RibService/ListEvpnRoutes 2>/dev/null
}

type4_route_count() {
    grpc_list_type4 \
        | jq '[.routes[]? | select(.routeType == 4)] | length'
}

wait_for_type4_count() {
    local want=${1:?} timeout=${2:-60}
    for _ in $(seq 1 "$timeout"); do
        local got
        got=$(type4_route_count 2>/dev/null || echo 0)
        if [ "$got" -ge "$want" ]; then
            return 0
        fi
        sleep 1
    done
    return 1
}

rust_decoded_frr_preference_df() {
    grpc_list_type4 \
        | jq -e --arg peer "$PE2_IP" --arg esi "$ESI" --arg ec "$FRR_DF_EXTCOMM" '
            any(.routes[]?;
                .routeType == 4
                and .peerAddress == $peer
                and .esi == $esi
                and ((.extendedCommunities // []) | map(tostring) | index($ec) != null)
            )' >/dev/null
}

wait_rust_decoded_frr_preference_df() {
    for _ in $(seq 1 60); do
        rust_decoded_frr_preference_df && return 0
        sleep 1
    done
    return 1
}

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

wait_for_role() {
    local container=${1:?} role=${2:?} want=${3:?} timeout=${4:-60}
    for _ in $(seq 1 "$timeout"); do
        [ "$(prom_df_role "$container" "$role")" = "$want" ] && return 0
        sleep 1
    done
    return 1
}

frr_sees_both_type4() {
    local out
    out=$(docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type es" 2>/dev/null || true)
    echo "$out" | grep -q "$PE1_IP" && echo "$out" | grep -q "$PE2_IP"
}

wait_frr_sees_both_type4() {
    for _ in $(seq 1 60); do
        frr_sees_both_type4 && return 0
        sleep 1
    done
    return 1
}

frr_reports_preference_df_win() {
    local out
    out=$(docker exec "$PE2" vtysh -c "show evpn es detail" 2>/dev/null || true)
    echo "$out" | grep -qiE 'DF status:[[:space:]]*df' \
        && echo "$out" | grep -qiE 'DF preference:[[:space:]]*200' \
        && echo "$out" | grep -qiE 'df_alg:[[:space:]]*preference' \
        && echo "$out" | grep -qiE 'df_pref:[[:space:]]*100'
}

wait_frr_reports_preference_df_win() {
    for _ in $(seq 1 60); do
        frr_reports_preference_df_win && return 0
        sleep 1
    done
    return 1
}

dump_debug() {
    echo "--- rustbgpd Type 4 routes ---" >&2
    grpc_list_type4 >&2 || true
    echo "--- rustbgpd evpn_df_role metrics ---" >&2
    prom_scrape "$PE1" | grep '^evpn_df_role' >&2 || true
    echo "--- FRR Type 4 routes ---" >&2
    docker exec "$PE2" vtysh -c "show bgp l2vpn evpn route type es" >&2 || true
    echo "--- FRR ES detail ---" >&2
    docker exec "$PE2" vtysh -c "show evpn es detail" >&2 || true
}

resolve_grpc_addr
wait_grpc_ready

log "[baseline] FRR session Established"
wait_frr_established "$PE2" "$PE1_IP" "FRR EVPN" \
    || fail "FRR did not establish to rustbgpd"

log "[test] Both peers exchange Type 4 ES routes"
if wait_for_type4_count 2 90; then
    ok "rustbgpd Loc-RIB has both Type 4 ES candidates"
else
    fail "rustbgpd Loc-RIB did not receive both Type 4 ES candidates"
    dump_debug
fi
if wait_frr_sees_both_type4; then
    ok "FRR sees both Type 4 ES candidates"
else
    fail "FRR did not see both Type 4 ES candidates"
    dump_debug
fi

log "[test] FRR Type 4 carries RFC 9785 preference-DF signal"
if wait_rust_decoded_frr_preference_df; then
    ok "rustbgpd decoded FRR DF Election extcomm as Highest-Preference / preference 200"
else
    fail "rustbgpd did not expose FRR's expected DF Election extcomm"
    dump_debug
fi

log "[test] preference-DF elects FRR, not the modulo winner"
if wait_for_role "$PE1" nondf 1 90; then
    ok "rustbgpd reports NonDF=1 for (esi=$ESI, vni=$VNI)"
else
    fail "rustbgpd did not settle as NonDF"
    dump_debug
fi
if [ "$(prom_df_role "$PE1" df)" = "0" ]; then
    ok "rustbgpd reports DF=0 for the same key"
else
    fail "rustbgpd DF gauge is not 0"
    dump_debug
fi
if wait_frr_reports_preference_df_win; then
    ok "FRR reports local DF with preference 200 and remote preference 100"
else
    fail "FRR did not report the expected preference-DF winner state"
    dump_debug
fi

print_summary
