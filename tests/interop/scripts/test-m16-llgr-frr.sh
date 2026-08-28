#!/usr/bin/env bash
# M16 interop test — dual-stack Long-Lived Graceful Restart (RFC 9494)
#
# Proves one IPv4-session restart carries an exact two-prefix IPv4 inventory
# and one-prefix IPv6 inventory through fresh -> GR-stale -> LLGR-stale ->
# fresh. Capability and timer assertions use the structured rustbgpd and FRR
# views; FRR's known-incomplete per-peer LLGR family field is not an oracle.
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m16-llgr-frr.clab.yml
#   - grpcurl, jq, and either curl or wget installed on the host
#
# Usage:
#   bash tests/interop/scripts/test-m16-llgr-frr.sh

TOPO="m16-llgr-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH

if ! command -v curl >/dev/null 2>&1 && ! command -v wget >/dev/null 2>&1; then
    echo "ERROR: curl or wget not found in PATH" >&2
    exit 1
fi

source "$SCRIPT_DIR/test-lib.sh"

FRR="clab-${TOPO}-frr"
RUST_PEER="10.0.0.2"
FRR_PEER="10.0.0.1"
RUST_TOKEN_FILE="/run/rustbgpd/grpc-test-only-operator.token"
V4_PREFIX_A="192.168.1.0/24"
V4_PREFIX_B="192.168.2.0/24"
V6_PREFIX="2001:db8:16::/48"
WATCHFRR_PAUSED=0

rbgp() {
    docker exec -e RUSTBGPD_TOKEN_FILE="$RUST_TOKEN_FILE" "$RUSTBGPD" \
        rbgp -s http://127.0.0.1:50051 "$@"
}

rust_neighbor_json() {
    rbgp neighbor "$RUST_PEER" -j 2>/dev/null
}

rust_routes_json() {
    rbgp rib received "$RUST_PEER" -j 2>/dev/null
}

frr_neighbor_json() {
    docker exec "$FRR" vtysh -c "show bgp neighbors $FRR_PEER json" 2>/dev/null
}

strict_prom_scrape() {
    local ip
    ip=$(resolve_ip "$RUSTBGPD") || return 1
    [ -n "$ip" ] || return 1
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || wget -qO- -T 5 "http://${ip}:9179/metrics" 2>/dev/null
}

gr_active_total() {
    local scrape
    scrape=$(strict_prom_scrape) || return 1
    awk '/^bgp_gr_active_peers\{/ {s+=$2} END {print s+0}' <<<"$scrape"
}

gr_timer_expired_count() {
    local scrape
    scrape=$(strict_prom_scrape) || return 1
    awk '/^bgp_gr_timer_expired_total\{/ {s+=$2} END {print s+0}' <<<"$scrape"
}

session_flap_count() {
    local scrape
    scrape=$(strict_prom_scrape) || return 1
    awk '/^bgp_session_flaps_total\{/ {s+=$2} END {print s+0}' <<<"$scrape"
}

route_shape_matches() {
    local shape=${1:?} routes
    routes=$(rust_routes_json) || return 1
    jq -e \
        --arg shape "$shape" \
        --arg v4a "$V4_PREFIX_A" \
        --arg v4b "$V4_PREFIX_B" \
        --arg v6 "$V6_PREFIX" '
        ([.[].prefix] | sort) == ([$v4a, $v4b, $v6] | sort)
        and (length == 3)
        and all(.[];
          if $shape == "fresh" then
            ((.stale // false) | not) and ((.llgr_stale // false) | not)
          elif $shape == "gr" then
            (.stale // false) and ((.llgr_stale // false) | not)
          elif $shape == "llgr" then
            ((.stale // false) | not) and (.llgr_stale // false)
          else
            false
          end)
    ' <<<"$routes" >/dev/null
}

wait_route_shape() {
    local shape=${1:?} label=${2:?} last="unavailable" routes
    log "Waiting for exact dual-stack route inventory in $label state..."
    for i in $(seq 1 45); do
        if route_shape_matches "$shape"; then
            ok "Exact IPv4 2 + IPv6 1 inventory is $label (attempt $i)"
            return 0
        fi
        if routes=$(rust_routes_json); then
            last=$(jq -c '[.[] | {prefix, stale:(.stale // false), llgr_stale:(.llgr_stale // false)}]' <<<"$routes")
        fi
        sleep 1
    done
    fail "Exact dual-stack inventory never reached $label; last=$last"
    return 1
}

wait_frr_established_exact() {
    local state="unavailable" neighbor
    log "Waiting for the FRR session to reach Established..."
    for i in $(seq 1 45); do
        if neighbor=$(frr_neighbor_json); then
            state=$(jq -r --arg peer "$FRR_PEER" '.[$peer].bgpState // "unavailable"' <<<"$neighbor")
            if [ "$state" = "Established" ]; then
                ok "FRR session Established (attempt $i)"
                return 0
            fi
        fi
        sleep 2
    done
    fail "FRR session did not reach Established; last=$state"
    return 1
}

wait_gr_active_exact() {
    local want=${1:?} label=${2:?} current="unavailable"
    log "Waiting for bgp_gr_active_peers == $want ($label)..."
    for i in $(seq 1 30); do
        if current=$(gr_active_total) && [ "$current" -eq "$want" ]; then
            ok "bgp_gr_active_peers == $want ($label, attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "bgp_gr_active_peers never reached $want ($label); last=$current"
    return 1
}

wait_timer_increment_exact() {
    local before=${1:?} current="unavailable" want
    want=$((before + 1))
    log "Waiting for bgp_gr_timer_expired_total to advance exactly once..."
    for i in $(seq 1 30); do
        if current=$(gr_timer_expired_count); then
            if [ "$current" -eq "$want" ]; then
                ok "bgp_gr_timer_expired_total advanced exactly $before -> $current (attempt $i)"
                return 0
            fi
            if [ "$current" -gt "$want" ]; then
                fail "bgp_gr_timer_expired_total over-advanced: expected $want, got $current"
                return 1
            fi
        fi
        sleep 1
    done
    fail "bgp_gr_timer_expired_total did not reach $want; last=$current"
    return 1
}

assert_rust_negotiation() {
    local neighbor
    if ! neighbor=$(rust_neighbor_json); then
        fail "rustbgpd neighbor state is unavailable for the negotiation check"
        return 1
    fi
    if jq -e '
        .state == "Established"
        and ((.families | sort) == ["ipv4_unicast", "ipv6_unicast"])
        and ((.negotiated_session.families | sort)
             == ["ipv4_unicast", "ipv6_unicast"])
        and ((.negotiated_session.graceful_restart.peer_families | sort)
             == ["ipv4_unicast", "ipv6_unicast"])
        and (.negotiated_session.graceful_restart.peer_restart_time_seconds == 15)
        and (.negotiated_session.graceful_restart.effective_retention_time_seconds == 15)
    ' <<<"$neighbor" >/dev/null; then
        ok "rustbgpd negotiated exact IPv4/IPv6 MP and GR family sets with a 15s retention timer"
    else
        fail "rustbgpd MP/GR negotiation does not match the dual-stack contract"
        return 1
    fi
}

assert_frr_negotiation_and_eor() {
    local neighbor
    if ! neighbor=$(frr_neighbor_json); then
        fail "FRR neighbor state is unavailable for the negotiation and EoR check"
        return 1
    fi
    if jq -e --arg peer "$FRR_PEER" '
        .[$peer] as $n
        | $n.bgpState == "Established"
        and ($n.neighborCapabilities.multiprotocolExtensions.ipv4Unicast.advertisedAndReceived == true)
        and ($n.neighborCapabilities.multiprotocolExtensions.ipv6Unicast.advertisedAndReceived == true)
        and ($n.neighborCapabilities.gracefulRestart == "advertisedAndReceived")
        and ($n.neighborCapabilities.gracefulRestartRemoteTimerMsecs == 15000)
        and ($n.neighborCapabilities.longLivedGracefulRestart == "advertisedAndReceived")
        and (($n.neighborCapabilities.addressFamiliesByPeer | keys | sort)
             == (["ipv4Unicast", "ipv6Unicast"] | sort))
        and ($n.gracefulRestartInfo.timers.configuredRestartTimer == 15)
        and ($n.gracefulRestartInfo.timers.receivedRestartTimer == 15)
        and ($n.gracefulRestartInfo.ipv4Unicast.timers.llgrStaleTime == 30)
        and ($n.gracefulRestartInfo.ipv6Unicast.timers.llgrStaleTime == 30)
        and ($n.gracefulRestartInfo.endOfRibSend.ipv4Unicast == true)
        and ($n.gracefulRestartInfo.endOfRibSend.ipv6Unicast == true)
        and ($n.addressFamilyInfo.ipv4Unicast.sentPrefixCounter == 2)
        and ($n.addressFamilyInfo.ipv6Unicast.sentPrefixCounter == 1)
    ' <<<"$neighbor" >/dev/null; then
        ok "FRR proves IPv4/IPv6 MP, GR, LLGR timers, exact 2/1 export, and both-family EoR"
    else
        fail "FRR dual-stack MP/GR/LLGR timer or EoR contract does not match"
        return 1
    fi
}

assert_flap_count() {
    local want=${1:?} label=${2:?} current
    if ! current=$(session_flap_count); then
        fail "bgp_session_flaps_total is unavailable ($label)"
        return 1
    fi
    if [ "$current" -eq "$want" ]; then
        ok "bgp_session_flaps_total == $want ($label)"
    else
        fail "bgp_session_flaps_total expected $want ($label), got $current"
        return 1
    fi
}

restore_watchfrr() {
    if [ "$WATCHFRR_PAUSED" -eq 1 ]; then
        docker exec "$FRR" killall -CONT watchfrr >/dev/null 2>&1 || true
        WATCHFRR_PAUSED=0
    fi
}

m16_cleanup_on_exit() {
    local rc=$?
    trap - EXIT INT TERM HUP
    set +e
    restore_watchfrr
    if [ "${CLEANUP:-0}" = "1" ]; then
        containerlab destroy -t "$(_clab_topology_file)" --cleanup >/dev/null 2>&1
    fi
    exit "$rc"
}

trap m16_cleanup_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

main() {
    local flap_before flap_after timer_before timer_after bgpd_before bgpd_after

    log "M16 interop test: dual-stack LLGR (RFC 9494)"
    resolve_grpc_addr
    start_rustbgpd
    wait_frr_established_exact
    wait_route_shape fresh "fresh"
    assert_rust_negotiation
    assert_frr_negotiation_and_eor

    if ! flap_before=$(session_flap_count); then
        fail "bgp_session_flaps_total is unavailable before the controlled restart"
        return 1
    fi
    if ! timer_before=$(gr_timer_expired_count); then
        fail "bgp_gr_timer_expired_total is unavailable before the controlled restart"
        return 1
    fi
    bgpd_before=$(docker exec "$FRR" pidof bgpd 2>/dev/null || true)
    [ -n "$bgpd_before" ] || { fail "FRR bgpd PID unavailable before restart"; return 1; }

    log "Pausing watchfrr and terminating bgpd for one controlled restart..."
    if ! docker exec "$FRR" killall -STOP watchfrr; then
        fail "Could not pause watchfrr before the controlled restart"
        return 1
    fi
    WATCHFRR_PAUSED=1
    if ! docker exec "$FRR" killall -9 bgpd; then
        fail "Could not terminate FRR bgpd for the controlled restart"
        return 1
    fi

    wait_route_shape gr "GR-stale"
    wait_gr_active_exact 1 "GR-stale"
    assert_flap_count "$((flap_before + 1))" "GR-stale"

    wait_route_shape llgr "LLGR-stale"
    wait_timer_increment_exact "$timer_before"
    wait_gr_active_exact 1 "LLGR-stale"
    assert_flap_count "$((flap_before + 1))" "LLGR-stale"

    log "Resuming watchfrr so it performs the single bgpd restart..."
    if ! docker exec "$FRR" killall -CONT watchfrr; then
        fail "Could not resume watchfrr for the controlled restart"
        return 1
    fi
    WATCHFRR_PAUSED=0
    wait_frr_established_exact
    wait_route_shape fresh "fresh after both-family EoR"
    assert_rust_negotiation
    assert_frr_negotiation_and_eor
    wait_gr_active_exact 0 "reconciled"

    bgpd_after=$(docker exec "$FRR" pidof bgpd 2>/dev/null || true)
    [ -n "$bgpd_after" ] || { fail "FRR bgpd PID unavailable after restart"; return 1; }
    if [ "$bgpd_after" != "$bgpd_before" ]; then
        ok "watchfrr relaunched bgpd with a new PID ($bgpd_before -> $bgpd_after)"
    else
        fail "FRR bgpd PID did not change across the restart"
        return 1
    fi

    if ! flap_after=$(session_flap_count); then
        fail "bgp_session_flaps_total is unavailable after the controlled restart"
        return 1
    fi
    if ! timer_after=$(gr_timer_expired_count); then
        fail "bgp_gr_timer_expired_total is unavailable after the controlled restart"
        return 1
    fi
    if [ "$flap_after" -eq "$((flap_before + 1))" ]; then
        ok "Exactly one session flap observed ($flap_before -> $flap_after)"
    else
        fail "Expected exactly one session flap: $flap_before -> $flap_after"
        return 1
    fi
    if [ "$timer_after" -eq "$((timer_before + 1))" ]; then
        ok "Timer-expiry counter remained at the exact +1 terminal value"
    else
        fail "Timer-expiry counter expected $((timer_before + 1)), got $timer_after"
        return 1
    fi

    print_summary
}

main "$@"
