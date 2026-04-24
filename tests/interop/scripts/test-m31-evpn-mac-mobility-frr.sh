#!/usr/bin/env bash
# M31 interop test — EVPN MAC mobility (RFC 7432 §15.1) through rustbgpd RR
#
# Validates the following end-to-end, against real FRR 10.3.1 VTEPs:
#
# Baseline:
#   1. All three VTEPs reach Established with L2VPN/EVPN negotiated.
#   2. VTEP-B sees Type 3 IMET from both VTEP-A and VTEP-C (control plane
#      flows through the RR in both directions).
#
# Plain MAC reflection:
#   3. MAC M1 injected on VTEP-A appears on VTEP-B with remote VTEP =
#      VTEP-A's tunnel IP.
#
# MAC mobility (VM move):
#   4. M1 moved to VTEP-C (bridge fdb add on C + del on A). VTEP-B's MAC
#      table updates to show VTEP-C as the remote VTEP.
#   5. The reflected Type 2 from VTEP-C carries a MAC Mobility extcomm
#      with a strictly-larger sequence number than VTEP-A's advertisement.
#
# Sticky MAC:
#   6. Sticky MAC M2 injected on VTEP-A (bridge fdb add ... sticky static).
#      Non-sticky attempt on VTEP-C does not displace it — VTEP-B's best
#      path for M2 stays pointed at VTEP-A.
#
# Prerequisites:
#   - containerlab deployed: containerlab deploy -t tests/interop/m31-evpn-mac-mobility-frr.clab.yml
#   - grpcurl installed on the host

TOPO="m31-evpn-mac-mobility-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

VTEP_A="clab-${TOPO}-vtep-a"
VTEP_B="clab-${TOPO}-vtep-b"
VTEP_C="clab-${TOPO}-vtep-c"
VTEP_A_IP="10.0.0.2"
VTEP_B_IP="10.0.1.2"
VTEP_C_IP="10.0.2.2"
VNI="100"
M1="aa:bb:cc:10:00:01"   # mobile MAC — moves from VTEP-A to VTEP-C
M2="aa:bb:cc:20:00:02"   # sticky MAC — must stay on VTEP-A

# ---------------------------------------------------------------------------
# Helpers (reuse-friendly with M30; kept local to keep scripts self-
# contained; promote to test-lib.sh if Gates 4+ reuse them.)
# ---------------------------------------------------------------------------

wait_frr_evpn_mac_learned() {
    local container=${1:?}
    local vni=${2:?}
    local mac=${3:?}
    local timeout=${4:-30}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        if docker exec "$container" vtysh -c "show evpn mac vni $vni json" 2>/dev/null \
            | grep -iq "\"$mac\""; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# Wait until VTEP-B's MAC table lists <mac> with remote VTEP == <expected_ip>.
wait_frr_evpn_mac_remote() {
    local container=${1:?}
    local vni=${2:?}
    local mac=${3:?}
    local expected_ip=${4:?}
    local timeout=${5:-30}
    local attempts=$((timeout / 2))
    for _ in $(seq 1 "$attempts"); do
        # Use text output — it's more stable than JSON across FRR versions.
        local txt
        txt=$(docker exec "$container" vtysh -c "show evpn mac vni $vni mac $mac" 2>/dev/null || true)
        # FRR renders remote VTEP as "Remote VTEP: <ip>" in the detail view.
        if echo "$txt" | grep -i "remote vtep" | grep -q "$expected_ip"; then
            return 0
        fi
        sleep 2
    done
    return 1
}

# Extract MAC Mobility sequence number (if any) for <mac> from VTEP-B's
# reflected route table. Echoes the number or "-" if absent. Uses FRR's
# detail view; the `Sequence Number:` text field has been stable across
# recent FRR releases.
frr_mac_mobility_seq() {
    local container=${1:?}
    local mac=${2:?}
    docker exec "$container" vtysh -c "show bgp l2vpn evpn route mac $mac" 2>/dev/null \
        | awk '/[Ss]equence [Nn]umber/ {print $NF; exit}' \
        | tr -d '\r'
}

inject_mac() {
    local container=${1:?}
    local mac=${2:?}
    local flags=${3:-static}
    # flags: "static" for plain; "sticky static" for sticky-MAC test.
    docker exec "$container" bridge fdb add "$mac" dev "vxlan${VNI}" self master $flags >/dev/null
}

withdraw_mac() {
    local container=${1:?}
    local mac=${2:?}
    # Try both forms — depending on how it was added, one of these works.
    docker exec "$container" bridge fdb del "$mac" dev "vxlan${VNI}" self master 2>/dev/null \
        || docker exec "$container" bridge fdb del "$mac" dev "vxlan${VNI}" self 2>/dev/null \
        || true
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

resolve_grpc_addr
start_rustbgpd

# Tests 1-3: all three VTEPs Established
log "[baseline] Waiting for all 3 VTEP sessions to reach Established"
wait_frr_established "$VTEP_A" "10.0.0.1" "VTEP-A EVPN" \
    && ok "VTEP-A Established" || fail "VTEP-A not Established"
wait_frr_established "$VTEP_B" "10.0.0.1" "VTEP-B EVPN" \
    && ok "VTEP-B Established" || fail "VTEP-B not Established"
wait_frr_established "$VTEP_C" "10.0.0.1" "VTEP-C EVPN" \
    && ok "VTEP-C Established" || fail "VTEP-C not Established"

# Test 4: VTEP-B sees IMET from both A and C
log "[baseline] VTEP-B sees Type 3 IMET from both A and C"
both_imets=0
for _ in $(seq 1 20); do
    multicast=$(docker exec "$VTEP_B" vtysh -c "show bgp l2vpn evpn route type multicast" 2>/dev/null)
    if echo "$multicast" | grep -q "$VTEP_A_IP" && echo "$multicast" | grep -q "$VTEP_C_IP"; then
        both_imets=1
        break
    fi
    sleep 2
done
if [ "$both_imets" -eq 1 ]; then
    ok "VTEP-B sees IMET from both VTEP-A and VTEP-C"
else
    fail "VTEP-B did not receive both reflected IMETs"
    docker exec "$VTEP_B" vtysh -c "show bgp l2vpn evpn route type multicast" >&2 || true
fi

# ---------------------------------------------------------------------------
# Phase 1 — plain MAC reflection (baseline for the move)
# ---------------------------------------------------------------------------
log "[phase 1] Injecting mobile MAC $M1 on VTEP-A"
inject_mac "$VTEP_A" "$M1"
if wait_frr_evpn_mac_learned "$VTEP_B" "$VNI" "$M1" 30; then
    ok "VTEP-B learned $M1"
else
    fail "VTEP-B did not learn $M1 within 30s"
fi
if wait_frr_evpn_mac_remote "$VTEP_B" "$VNI" "$M1" "$VTEP_A_IP" 15; then
    ok "VTEP-B sees $M1 with remote VTEP = VTEP-A"
else
    fail "VTEP-B sees $M1 but remote VTEP != VTEP-A"
    docker exec "$VTEP_B" vtysh -c "show evpn mac vni $VNI mac $M1" >&2 || true
fi

# Record the sequence number before the move (may be "-" if FRR omits
# the Mobility community at initial advertise).
seq_before=$(frr_mac_mobility_seq "$VTEP_B" "$M1")
log "MAC Mobility sequence before move: ${seq_before:-absent}"

# ---------------------------------------------------------------------------
# Phase 2 — move to VTEP-C; sequence must increment
# ---------------------------------------------------------------------------
log "[phase 2] Moving $M1 from VTEP-A to VTEP-C"
inject_mac "$VTEP_C" "$M1"
withdraw_mac "$VTEP_A" "$M1"

if wait_frr_evpn_mac_remote "$VTEP_B" "$VNI" "$M1" "$VTEP_C_IP" 30; then
    ok "VTEP-B's best path for $M1 moved to VTEP-C"
else
    fail "VTEP-B still shows VTEP-A as remote after move"
    docker exec "$VTEP_B" vtysh -c "show evpn mac vni $VNI mac $M1" >&2 || true
fi

seq_after=$(frr_mac_mobility_seq "$VTEP_B" "$M1")
log "MAC Mobility sequence after move: ${seq_after:-absent}"
if [ -n "$seq_after" ] && [ "$seq_after" != "-" ]; then
    # seq_before might be empty; treat as 0 for comparison
    before_val=${seq_before:-0}
    [ "$before_val" = "-" ] && before_val=0
    if [ "$seq_after" -gt "$before_val" ] 2>/dev/null; then
        ok "MAC Mobility sequence incremented ($before_val -> $seq_after)"
    else
        fail "MAC Mobility sequence did not increment ($before_val -> $seq_after)"
    fi
else
    fail "No MAC Mobility sequence number visible after move"
    docker exec "$VTEP_B" vtysh -c "show bgp l2vpn evpn route mac $M1" >&2 || true
fi

# Clean up M1 so it doesn't pollute Phase 3
withdraw_mac "$VTEP_C" "$M1"

# ---------------------------------------------------------------------------
# Phase 3 — sticky MAC preservation
# ---------------------------------------------------------------------------
log "[phase 3] Injecting sticky MAC $M2 on VTEP-A"
inject_mac "$VTEP_A" "$M2" "sticky static"
if wait_frr_evpn_mac_remote "$VTEP_B" "$VNI" "$M2" "$VTEP_A_IP" 30; then
    ok "VTEP-B sees sticky $M2 from VTEP-A"
else
    fail "VTEP-B did not learn sticky $M2 from VTEP-A"
fi

log "[phase 3] Attempting non-sticky takeover on VTEP-C"
inject_mac "$VTEP_C" "$M2"

# Give FRR a few seconds to propagate the attempted move, then assert
# that VTEP-B's best path for M2 is STILL pointed at VTEP-A.
sleep 6
if wait_frr_evpn_mac_remote "$VTEP_B" "$VNI" "$M2" "$VTEP_A_IP" 5; then
    ok "Sticky $M2 preserved on VTEP-A against non-sticky VTEP-C advertisement"
else
    fail "Sticky $M2 was displaced by VTEP-C"
    docker exec "$VTEP_B" vtysh -c "show evpn mac vni $VNI mac $M2" >&2 || true
fi

# Cleanup
withdraw_mac "$VTEP_A" "$M2"
withdraw_mac "$VTEP_C" "$M2"

print_summary
