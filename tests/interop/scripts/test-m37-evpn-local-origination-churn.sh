#!/usr/bin/env bash
# M37 churn driver — local-only EVPN Type 2 origination soak helper.
#
# Deploy the M37 topology first, then run this script to repeatedly add
# and delete static bridge FDB entries on rustbgpd's non-VXLAN bridge
# port. It is intentionally not wired into CI; it needs the privileged
# containerlab topology and is meant for local soak runs.
#
# Usage:
#   docker build -t rustbgpd:dev .
#   sudo containerlab deploy -t tests/interop/m37-evpn-local-origination.clab.yml
#   M37_CHURN_MACS=1000 M37_CHURN_ROUNDS=60 \
#     bash tests/interop/scripts/test-m37-evpn-local-origination-churn.sh

set -euo pipefail

TOPO="m37-evpn-local-origination"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

RUSTBGPD="clab-${TOPO}-rustbgpd"
CONSUMER="clab-${TOPO}-consumer"
RUSTBGPD_IP="10.0.0.1"
VNI="${M37_CHURN_VNI:-100}"
VETH_PORT="veth${VNI}a"
MACS="${M37_CHURN_MACS:-250}"
ROUNDS="${M37_CHURN_ROUNDS:-10}"
SETTLE_SECONDS="${M37_CHURN_SETTLE_SECONDS:-3}"
VERIFY_SAMPLES="${M37_CHURN_VERIFY_SAMPLES:-1}"

format_mac() {
    local n=${1:?}
    printf '02:37:%02x:%02x:%02x:%02x' \
        $(((n >> 24) & 255)) \
        $(((n >> 16) & 255)) \
        $(((n >> 8) & 255)) \
        $((n & 255))
}

frr_has_type2() {
    local mac=${1:?}
    docker exec "$CONSUMER" vtysh -c "show bgp l2vpn evpn route type macip" 2>/dev/null \
        | grep -A1 -iF "$mac" \
        | grep -qF "$RUSTBGPD_IP"
}

rb_fdb_replace() {
    local mac=${1:?}
    docker exec "$RUSTBGPD" bridge fdb replace "$mac" dev "$VETH_PORT" master static
}

rb_fdb_del() {
    local mac=${1:?}
    docker exec "$RUSTBGPD" bridge fdb del "$mac" dev "$VETH_PORT" master 2>/dev/null || true
}

sample_check_present() {
    local sample
    sample=$(format_mac 1)
    for _ in $(seq 1 15); do
        if frr_has_type2 "$sample"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

sample_check_absent() {
    local sample
    sample=$(format_mac 1)
    for _ in $(seq 1 15); do
        if ! frr_has_type2 "$sample"; then
            return 0
        fi
        sleep 1
    done
    return 1
}

emit_metrics_snapshot() {
    local ip
    ip=$(resolve_ip "$RUSTBGPD")
    if command -v curl >/dev/null 2>&1 && [ -n "$ip" ]; then
        curl -fsS "http://${ip}:9179/metrics" 2>/dev/null \
            | grep -E 'evpn_(local_originations|local_origination_errors|local_observations_dropped|duplicate_mac_moves)' \
            || true
    fi
}

log "Waiting for M37 L2VPN/EVPN session before churn..."
wait_frr_established "$CONSUMER" "$RUSTBGPD_IP" "L2VPN/EVPN" || true

log "Starting M37 churn: VNI=$VNI port=$VETH_PORT macs=$MACS rounds=$ROUNDS settle=${SETTLE_SECONDS}s"

for round in $(seq 1 "$ROUNDS"); do
    log "Round $round/$ROUNDS: add $MACS local MACs"
    for i in $(seq 1 "$MACS"); do
        rb_fdb_replace "$(format_mac "$i")"
    done

    sleep "$SETTLE_SECONDS"
    if [ "$VERIFY_SAMPLES" = "1" ]; then
        if sample_check_present; then
            ok "sample Type 2 present after add round $round"
        else
            fail "sample Type 2 missing after add round $round"
        fi
    fi

    log "Round $round/$ROUNDS: delete $MACS local MACs"
    for i in $(seq 1 "$MACS"); do
        rb_fdb_del "$(format_mac "$i")"
    done

    sleep "$SETTLE_SECONDS"
    if [ "$VERIFY_SAMPLES" = "1" ]; then
        if sample_check_absent; then
            ok "sample Type 2 withdrawn after delete round $round"
        else
            fail "sample Type 2 still present after delete round $round"
        fi
    fi
done

log "EVPN metric snapshot after churn:"
emit_metrics_snapshot

print_summary
