#!/usr/bin/env bash
# M40 interop — ADR-0059 slice 4: aliasing dataplane ECMP against
# real FRR EVPN-MH. The slice 3b coordinator + Pass 1b diff path
# both land here for the first time against an upstream peer.
#
# Topology (see `m40-evpn-aliasing-ecmp-frr.clab.yml`):
#   pe-rb (rustbgpd) ─ pe-a (FRR, ES1)
#         └────────── pe-c (FRR, ES1)
#
# Test shape:
#   1. Both FRR peers Established to rustbgpd on L2VPN/EVPN.
#   2. Each FRR node has a local ES1 in `show evpn es`.
#   3. Inject a test MAC on pe-a's ES bond → FRR originates
#      Type 2 with ESI=ES1.
#   4. rustbgpd installs an FDB row on br100/vxlan100 referencing
#      an FDB nexthop group (`bridge fdb show` shows `nhid N`).
#   5. `ip nexthop show` on rustbgpd has:
#        - one group `id N group X/Y ... fdb` (NHG-tagged ID)
#        - two member NHs (one each via pe-a's IP, pe-c's IP)
#   6. Stop pe-c → pe-c's EAD-per-EVI withdraws → alias set
#      shrinks to {pe-a}. Per the projection invariant
#      (`empty alias_vtep_ips ⇔ alias_group_key.is_none()`) the
#      entry transitions to single-dst: group + alias-pe-c member
#      tear down, FDB row falls back to `dst pe-a` (no `nhid`).
#   7. Withdraw the MAC from pe-a's bond → FDB row + member NH
#      for pe-a's VTEP disappear.
#
# iproute2 prints `nhid` in decimal; group form is
# `id <gid> group <mid>/<mid> ... fdb`. Sources:
#   - iproute2 bridge/fdb.c (NHID print path)
#   - iproute2 ip/ipnexthop.c (group print path)
#
# Manual/local only — containerlab needs privileges CI doesn't
# carry. M39's privileged-runner gate (ROADMAP follow-up) covers
# this slot when it lands.

TOPO="m40-evpn-aliasing-ecmp-frr"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# M40 names the rustbgpd node `pe-rb` (matches the FRR `pe-a` /
# `pe-c` shape) rather than the shared lib's default
# `clab-${TOPO}-rustbgpd`. Override `RUSTBGPD` before sourcing so
# `preflight` (which runs at source time) inspects the right
# container.
PE_RB="clab-${TOPO}-pe-rb"
PE_A="clab-${TOPO}-pe-a"
PE_C="clab-${TOPO}-pe-c"
RUSTBGPD="$PE_RB"
export RUSTBGPD

# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

PE_A_IP="10.0.0.2"
PE_C_IP="10.0.1.2"
TEST_MAC="02:aa:bb:cc:dd:40"
ES_DUMMY="esdummy"
VNI=100
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"

# Helper: print rustbgpd's bridge FDB rows for the test MAC.
fdb_show_test_mac() {
    docker exec "$PE_RB" bridge fdb show dev "$VXLAN" 2>/dev/null \
        | grep -i "$TEST_MAC" || true
}

# Helper: print rustbgpd's nexthop table.
nexthop_show() {
    docker exec "$PE_RB" ip nexthop show 2>/dev/null || true
}

# Helper: wait for predicate (single shell expression) to return 0
# inside the rustbgpd container. Caller passes a description for
# logging and a max attempt count (each attempt waits 2 s).
wait_for_rb() {
    local desc="$1"
    local cmd="$2"
    local attempts="${3:-30}"
    for i in $(seq 1 "$attempts"); do
        if docker exec "$PE_RB" sh -c "$cmd" >/dev/null 2>&1; then
            ok "$desc (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$desc not reached within $((attempts * 2))s"
    return 1
}

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

# rustbgpd is already running — the clab `exec` block runs
# `start-rustbgpd-vtep.sh` which launches the daemon in the
# background. Calling `start_rustbgpd` here would race a second
# instance against the first. Just resolve the gRPC address and
# wait for the endpoint to become reachable (same pattern as
# M36).
resolve_grpc_addr
log "Waiting for rustbgpd gRPC endpoint..."
grpc_ready=0
for i in $(seq 1 15); do
    if grpc_health >/dev/null 2>&1; then
        ok "gRPC endpoint ready (attempt $i)"
        grpc_ready=1
        break
    fi
    sleep 2
done
if [ "$grpc_ready" -ne 1 ]; then
    fail "gRPC endpoint not reachable within 30s"
    # Hard prereq — every subsequent assertion depends on the daemon
    # being responsive. Abort rather than emit cascade failures.
    print_summary
fi

log "[baseline] both FRR peers Established to rustbgpd"
wait_frr_established "$PE_A" "10.0.0.1" "pe-a EVPN" \
    && ok "pe-a Established" || fail "pe-a not Established"
wait_frr_established "$PE_C" "10.0.1.1" "pe-c EVPN" \
    && ok "pe-c Established" || fail "pe-c not Established"

log "[baseline] both FRR nodes have local ES1"
for node in "$PE_A" "$PE_C"; do
    es_out=""
    for _ in $(seq 1 30); do
        es_out=$(docker exec "$node" vtysh -c "show evpn es" 2>/dev/null || true)
        if echo "$es_out" | grep -qE '^03:aa:bb:cc:dd:ee:ff:00:00:01\b'; then
            break
        fi
        sleep 2
    done
    if echo "$es_out" | grep -qE '^03:aa:bb:cc:dd:ee:ff:00:00:01\b'; then
        ok "$node has local ES1"
    else
        fail "$node missing local ES1"
        echo "--- $node show evpn es ---" >&2
        echo "$es_out" | head -20 >&2
    fi
done

log "[setup] inject test MAC on pe-a's ES bond"
docker exec "$PE_A" bridge fdb add "$TEST_MAC" \
    dev "$ES_DUMMY" master static 2>&1 \
    && ok "MAC injected on pe-a:$ES_DUMMY" \
    || fail "bridge fdb add on pe-a failed"

# ---------------------------------------------------------------------------
# Phase 1: both pe-a and pe-c are reachable; expect FDB-NHG install
# ---------------------------------------------------------------------------

log "[phase 1] rustbgpd installs FDB row with nhid"
# `nhid N` (decimal). The FDB row landing implies Type 2 from pe-a
# was observed AND pe-c's EAD-per-EVI was observed AND the alias
# set resolved AND apply_nhg_op succeeded. Hard prereq — Phase 2
# and Phase 3 both inspect the row this assertion establishes;
# bail out on failure rather than emit cascading false negatives.
wait_for_rb \
    "FDB row for $TEST_MAC has nhid" \
    "bridge fdb show dev $VXLAN | grep -i '$TEST_MAC' | grep -E ' nhid [0-9]+'" \
    45 \
    || { print_summary; }

# Capture the row + nhid for the next assertions.
fdb_row=$(fdb_show_test_mac)
nhid=$(echo "$fdb_row" | grep -oE ' nhid [0-9]+' | awk '{print $2}' | head -1)
if [ -z "$nhid" ]; then
    fail "could not parse nhid from FDB row: $fdb_row"
else
    log "captured nhid=$nhid for $TEST_MAC"
fi

log "[phase 1] ip nexthop show has the matching group with two members"
# Group line shape: `id <gid> group <mid>/<mid> ... fdb`. Members
# print as `id <mid> via <ip> fdb`. We assert:
#   - the group exists with our nhid
#   - exactly two members via pe-a's IP and pe-c's IP
nh_dump=$(nexthop_show)
group_line=$(echo "$nh_dump" | grep -E "^id $nhid group [0-9/]+ .*fdb" || true)
if [ -n "$group_line" ]; then
    ok "group line present: $group_line"
else
    fail "no group line for nhid=$nhid in ip nexthop show"
    echo "--- nh_dump ---" >&2
    echo "$nh_dump" | head -30 >&2
fi

# Extract member IDs from the group line: `group 12/13 ...` → 12 and 13.
member_ids=$(echo "$group_line" \
    | grep -oE 'group [0-9/]+' \
    | awk '{print $2}' \
    | tr '/' ' ')
if [ -n "$member_ids" ]; then
    ok "parsed group member IDs: $member_ids"
else
    fail "could not parse group member IDs from: $group_line"
fi

# Each member ID should resolve to a `via <ip> fdb` line; collect
# their gateway IPs.
member_ips=""
for mid in $member_ids; do
    mline=$(echo "$nh_dump" | grep -E "^id $mid via [0-9.]+ .*fdb" || true)
    mip=$(echo "$mline" | grep -oE 'via [0-9.]+' | awk '{print $2}')
    if [ -n "$mip" ]; then
        member_ips="$member_ips $mip"
    fi
done
member_ips=$(echo "$member_ips" | tr ' ' '\n' | sort -u | grep -v '^$' | tr '\n' ' ')
if echo "$member_ips" | grep -qw "$PE_A_IP" && echo "$member_ips" | grep -qw "$PE_C_IP"; then
    ok "group members cover both pe-a ($PE_A_IP) and pe-c ($PE_C_IP)"
else
    fail "group members do not cover both VTEPs (got: $member_ips)"
fi

# ---------------------------------------------------------------------------
# Phase 2: stop pe-c → drain alias → entry transitions to single-dst
# ---------------------------------------------------------------------------
#
# Per the projection invariant (`empty alias_vtep_ips ⇔
# alias_group_key.is_none()`), withdrawing pe-c's EAD-per-EVI
# shrinks aliases to [], which makes the entry single-dst pointing
# at pe-a. Expect:
#   - FDB row falls back to `dst $PE_A_IP` (no `nhid`)
#   - group + pe-c member are torn down
#   - pe-a member may stay tracked (could be re-claimed if alias
#     re-appears), but the test doesn't assert on that.

log "[phase 2] stop pe-c — withdrawal of EAD-per-EVI must drain the group"
# `docker stop` brings down watchfrr + bgpd together. Killing only
# bgpd inside the container would race a watchfrr restart and
# re-originate EAD-per-EVI mid-drain (M1's test relies on that
# auto-restart behavior; M40 needs the opposite).
docker stop --time 5 "$PE_C" >/dev/null 2>&1 \
    && ok "pe-c container stopped" \
    || fail "could not stop pe-c container"

wait_for_rb \
    "FDB row falls back to single-dst (no nhid)" \
    "bridge fdb show dev $VXLAN | grep -i '$TEST_MAC' | grep -vE ' nhid [0-9]+' | grep -E ' dst $PE_A_IP'" \
    45 \
    || { print_summary; }

log "[phase 2] group nhid=$nhid removed from ip nexthop show"
post_drain=$(nexthop_show)
if echo "$post_drain" | grep -qE "^id $nhid group "; then
    fail "group nhid=$nhid still present after drain"
    echo "$post_drain" | head -30 >&2
else
    ok "group nhid=$nhid torn down"
fi

# ---------------------------------------------------------------------------
# Phase 3: withdraw MAC from pe-a → FDB row + remaining member gone
# ---------------------------------------------------------------------------

log "[phase 3] withdraw test MAC from pe-a's ES bond"
docker exec "$PE_A" bridge fdb del "$TEST_MAC" \
    dev "$ES_DUMMY" master 2>&1 \
    && ok "MAC withdrawn from pe-a:$ES_DUMMY" \
    || fail "bridge fdb del on pe-a failed"

wait_for_rb \
    "FDB row for $TEST_MAC removed from rustbgpd's bridge FDB" \
    "! bridge fdb show dev $VXLAN | grep -qi '$TEST_MAC'" \
    45 \
    || { print_summary; }

# Any remaining FDB-NHG-tagged nexthop should be cleaned up by the
# reconcile coordinator. Plain single-dst members + remaining
# rustbgpd-tagged adopted IDs would also show up here, but for
# this clean teardown the table should not list our specific
# pe-a / pe-c gateways under an FDB nexthop entry.
final_nh=$(nexthop_show)
if echo "$final_nh" | grep -E ' fdb$' | grep -qE "via $PE_A_IP\b|via $PE_C_IP\b"; then
    fail "stale FDB nexthops still reference test VTEPs after teardown"
    echo "--- final ip nexthop show ---" >&2
    echo "$final_nh" >&2
else
    ok "no stale FDB nexthops for $PE_A_IP / $PE_C_IP"
fi

print_summary
