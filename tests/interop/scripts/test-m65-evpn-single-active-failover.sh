#!/usr/bin/env bash
# M65 — ADR-0083 single-active failover blackout measurement.
#
# Validates the ADR-0083 backup-path arc (slices 1-3) end-to-end on a
# live kernel and captures the failover-time receipt: rustbgpd is the
# remote VTEP (receive side, the device under test); two GoBGP-driven
# PEs share single-active ES 00:00:00:00:00:00:00:00:00:01 for VNI
# 100. pe1 (10.0.1.2) is active and originates the CE MAC's Type 2;
# pe2 (10.0.2.2) is the backup. A host (hr) behind the DUT pings the
# CE through the fabric at a 100 ms grain across the failover.
#
# Why GoBGP PEs and not rustbgpd ones: the swap trigger is the
# RFC 7432 §8.2 mass-withdraw wire shape — the EAD-per-ES withdrawn
# while the segment's MAC routes stay advertised. rustbgpd can
# originate the Single-Active flag (`redundancy_mode =
# "single-active"`), but an Ethernet Segment has no AC/interface
# binding, so the only live EAD-per-ES withdrawal trigger is a config
# reload — and the SIGHUP ES-removal path drains and synchronously
# re-keys the VNI's Type 2 routes (zero ESI) in the same apply,
# destroying the swap window. FRR is all-active only. GoBGP's
# `global rib add/del` emits exactly the standards-shaped stimulus.
#
# Scope note (node failure): a hard PE kill is NOT a swap test by
# construction — the dead PE's session carries its MAC routes down
# with its EAD-per-ES, so the receive side flushes (no swap window
# exists). That path is hold-timer/detection-bounded (ADR-0083
# decision 4) and its flush semantics are covered by M36/M60. This
# job measures the AC-failure mass-withdraw repair — the path slice 3
# ships — plus the last-PE ordered teardown.
#
# Asserts (hard on mechanism, informational on timing — the M63
# precedent):
#
# 1. Steady state (slice 2 pre-install): the CE MAC lands as an
#    `NDA_NH_ID` FDB row behind a one-member FDB nexthop group
#    (member = pe1's per-VTEP NH), with pe2's per-VTEP NH pre-created
#    as standby — present in `ip nexthop show` but NOT a group member.
#    Baseline pings flow; swap/teardown counters 0, gauge 0.
# 2. AC failure (pe1's CE leg down + EAD-per-ES withdrawn): the DUT
#    retargets the SAME group to pe2's pre-created NH in one
#    membership replace — group id unchanged, new member id == the
#    pre-install standby id ("the swap allocates nothing"), the MAC
#    row present with the same nhid throughout (never flushed),
#    pe1's NH garbage-collected, `evpn_single_active_backup_swaps_total
#    == 1`, gauge == 1, pings flow again.
# 3. Blackout window: measured from the 100 ms ping stream (max
#    consecutive missed-probe run) and logged prominently —
#    informational. One hard bound: < 3 s, which pins the supervisor's
#    debounced RIB-event recompute (200 ms debounce + one netlink
#    replace) against a regression back to the 5 s poll backstop
#    (no Type 3 routes are injected, so the DUT has no flood entries:
#    the swap is the ONLY restoration path — connectivity back ⇔ swap
#    landed; a relearn wave cannot mask a broken swap).
# 4. Ordered teardown (the LAST eligible PE withdraws): pe2's
#    EAD-per-ES deleted while pe1's MAC route is still advertised →
#    eligible set empty → MAC rows flushed, group + NHs gone,
#    `evpn_single_active_teardowns_total == 1`, gauge back to 0,
#    pings hard-dead (no flood path).
# 5. Foreign state untouched: the start-script's pre-loaded foreign
#    FDB row, a driver-planted foreign static FDB row, and a
#    driver-planted untagged fdb nexthop survive the whole cycle.
#
# Usage:
#   docker build -t rustbgpd:dev .
#   docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
#   containerlab deploy -t tests/interop/m65-evpn-single-active-failover.clab.yml
#   bash tests/interop/scripts/test-m65-evpn-single-active-failover.sh
#   containerlab destroy -t tests/interop/m65-evpn-single-active-failover.clab.yml

set -eu

TOPO="m65-evpn-single-active-failover"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUSTBGPD="clab-${TOPO}-vtep"
export RUSTBGPD
# shellcheck source=test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

VTEP="clab-${TOPO}-vtep"
PE1="clab-${TOPO}-pe1"
PE2="clab-${TOPO}-pe2"
HR="clab-${TOPO}-hr"

PE1_IP="10.0.1.2"
PE2_IP="10.0.2.2"
VNI="100"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"
# 10-byte wire ESI 00:00:00:00:00:00:00:00:00:01 (type 0 + 9 value
# bytes in the gobgp CLI form).
ESI_GOBGP="esi 0 00:00:00:00:00:00:00:00:01"
RD_PE1="65000:101"
RD_PE2="65000:102"
RT="65000:100"
CE_MAC="02:ce:ce:ce:ce:01"
CE_HOST_IP="192.168.65.10"
# Driver-planted foreign row (the start script pre-loads
# 02:99:99:99:99:99 before rustbgpd starts).
FOREIGN_MAC="02:99:99:99:99:98"
PRELOADED_FOREIGN_MAC="02:99:99:99:99:99"
# Untagged (non-0x3000_0000/0x4000_0000) fdb nexthop — foreign to the
# ADR-0059 id allocator, must never be touched.
FOREIGN_NH_ID="4242"
PROBE_INTERVAL_MS="100"
# Hard sanity bound on the measured blackout: generous vs. the
# expected sub-second repair (200 ms event debounce + EAD-withdrawal
# propagation + one netlink replace + the driver's ~100-200 ms
# injection serialization gap), but strictly below the supervisor's
# 5 s poll backstop, so a regression back to poll-driven recompute
# fails the job.
BLACKOUT_BOUND_MS="3000"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

rb_fdb() {
    docker exec "$VTEP" bridge fdb show dev "$VXLAN" 2>/dev/null || true
}

rb_nh() {
    docker exec "$VTEP" ip nexthop show 2>/dev/null || true
}

# One round-trip snapshot of nexthops + FDB so the tight swap-wait
# loop observes both from the same instant.
rb_snapshot() {
    docker exec "$VTEP" sh -c "ip nexthop show; echo '---FDB---'; bridge fdb show dev $VXLAN" 2>/dev/null || true
}

ce_mac_row() {
    rb_fdb | grep -i "$CE_MAC" || true
}

# Per-VTEP fdb nexthop id for a gateway IP (`id <nid> via <ip> fdb`).
nh_id_for_via() {
    local ip=${1:?}
    rb_nh | grep -E "^id [0-9]+ via ${ip} " | grep -E ' fdb' \
        | awk '{print $2}' | head -1 || true
}

# Member ids of a group line (`id <gid> group <mid>[/<mid>...] ... fdb`).
group_members_of() {
    local gid=${1:?}
    rb_nh | grep -E "^id ${gid} group " \
        | grep -oE 'group [0-9/]+' | awk '{print $2}' | tr '/' ' ' || true
}

# Scrape Prometheus via the container's management IP (M38 pattern —
# the rustbgpd:dev runtime image intentionally stays small and does
# not carry curl/wget, so the HTTP request runs from the host).
prom_scrape() {
    local ip
    ip=$(resolve_ip "$VTEP")
    if [ -z "$ip" ]; then
        echo "ERROR: could not resolve management IP for $VTEP" >&2
        return 1
    fi
    curl -sfm 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || wget -qO- -T 5 "http://${ip}:9179/metrics" 2>/dev/null \
        || true
}

# Read an unlabelled counter/gauge value; empty if the line isn't emitted.
prom_value() {
    local name=${1:?}
    prom_scrape | awk -v n="$name" '$1 == n { print $2; exit }'
}

# Poll until the named metric reports the wanted value (counters fold
# in via DataplaneReport, so allow a short settle).
wait_prom_value() {
    local name=${1:?}
    local want=${2:?}
    local label=${3:?}
    local got=""
    for _ in $(seq 1 15); do
        got=$(prom_value "$name")
        if [ "${got:-_}" = "$want" ]; then
            ok "$label ($name=$got)"
            return 0
        fi
        sleep 1
    done
    fail "$label ($name='$got', want $want)"
    prom_scrape | grep -E '^evpn_single_active' >&2 || true
    return 1
}

wait_gobgp_established() {
    local pe=${1:?}
    local peer=${2:?}
    local label=${3:-BGP}
    log "Waiting for $label session to reach Established..."
    for i in $(seq 1 45); do
        local state
        state=$(docker exec "$pe" gobgp neighbor "$peer" 2>/dev/null | grep -i 'BGP state' || true)
        if echo "$state" | grep -qi "establ"; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    return 1
}

# Ping from hr to the CE: require >= 9 of 10 replies (veth fabric;
# anything lower is a real forwarding problem, one straggler is CI
# scheduler noise).
ping_burst_ok() {
    local label=${1:?}
    local out received
    out=$(docker exec "$HR" ping -c 10 -i 0.2 -W 1 "$CE_HOST_IP" 2>/dev/null || true)
    received=$(echo "$out" | grep -oE '[0-9]+ received' | awk '{print $1}' || true)
    if [ "${received:-0}" -ge 9 ] 2>/dev/null; then
        ok "$label (${received:-0}/10 replies)"
        return 0
    fi
    fail "$label (${received:-0}/10 replies)"
    echo "$out" | tail -5 >&2
    return 1
}

# Bounded wait for the first successful ping (convergence gate before
# the strict burst).
wait_ping() {
    local label=${1:?}
    local attempts=${2:-30}
    for i in $(seq 1 "$attempts"); do
        if docker exec "$HR" ping -c 1 -W 1 "$CE_HOST_IP" >/dev/null 2>&1; then
            ok "$label (attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "$label not reached within ${attempts}s"
    return 1
}

pe1_rib() { docker exec "$PE1" gobgp global rib "$@"; }
pe2_rib() { docker exec "$PE2" gobgp global rib "$@"; }

# ---------------------------------------------------------------------------
# Phase 1 — sessions + segment route injection
# ---------------------------------------------------------------------------

resolve_grpc_addr
log "vtep (DUT): $VTEP — pe1 (active): $PE1 — pe2 (backup): $PE2"

log "Verifying VTEP topology inside the DUT container..."
docker exec "$VTEP" ip -d link show "$BRIDGE" >/dev/null \
    || { fail "bridge $BRIDGE missing in DUT netns"; exit 1; }
docker exec "$VTEP" ip -d link show "$VXLAN" >/dev/null \
    || { fail "VXLAN port $VXLAN missing"; exit 1; }

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
    print_summary
fi

wait_gobgp_established "$PE1" "10.0.1.1" "pe1 EVPN" || print_summary
wait_gobgp_established "$PE2" "10.0.2.1" "pe2 EVPN" || print_summary

log "Injecting the single-active segment (EAD-per-ES + EAD-per-EVI from both PEs, CE MAC Type 2 from pe1)..."
# EAD-per-ES: etag MAX_ET (4294967295), label 0, Single-Active flag in
# the ESI Label extended community (RFC 7432 §7.5).
pe1_rib add -a evpn a-d $ESI_GOBGP etag 4294967295 label 0 \
    rd "$RD_PE1" rt "$RT" encap vxlan esi-label 0 single-active nexthop "$PE1_IP" \
    && ok "pe1 EAD-per-ES (single-active) injected" \
    || fail "pe1 EAD-per-ES injection failed"
pe1_rib add -a evpn a-d $ESI_GOBGP etag 0 label "$VNI" \
    rd "$RD_PE1" rt "$RT" encap vxlan nexthop "$PE1_IP" \
    && ok "pe1 EAD-per-EVI injected" \
    || fail "pe1 EAD-per-EVI injection failed"
pe1_rib add -a evpn macadv "$CE_MAC" 0.0.0.0 $ESI_GOBGP etag 0 label "$VNI" \
    rd "$RD_PE1" rt "$RT" encap vxlan nexthop "$PE1_IP" \
    && ok "pe1 Type 2 for $CE_MAC (ESI-attached) injected" \
    || fail "pe1 Type 2 injection failed"
pe2_rib add -a evpn a-d $ESI_GOBGP etag 4294967295 label 0 \
    rd "$RD_PE2" rt "$RT" encap vxlan esi-label 0 single-active nexthop "$PE2_IP" \
    && ok "pe2 EAD-per-ES (single-active) injected" \
    || fail "pe2 EAD-per-ES injection failed"
pe2_rib add -a evpn a-d $ESI_GOBGP etag 0 label "$VNI" \
    rd "$RD_PE2" rt "$RT" encap vxlan nexthop "$PE2_IP" \
    && ok "pe2 EAD-per-EVI injected" \
    || fail "pe2 EAD-per-EVI injection failed"

# ---------------------------------------------------------------------------
# Phase 2 — steady state: slice-2 pre-install shape + baseline traffic
# ---------------------------------------------------------------------------

log "[phase 2] CE MAC must land as an NDA_NH_ID row behind a one-member group"
group_id=""
for _ in $(seq 1 60); do
    row=$(ce_mac_row)
    group_id=$(echo "$row" | grep -oE ' nhid [0-9]+' | awk '{print $2}' | head -1 || true)
    [ -n "$group_id" ] && break
    sleep 1
done
if [ -n "$group_id" ]; then
    ok "FDB row for $CE_MAC carries nhid $group_id"
else
    fail "FDB row for $CE_MAC never gained an nhid"
    rb_fdb >&2
    docker exec "$VTEP" tail -80 /var/log/rustbgpd.log >&2 || true
    print_summary
fi

member_id=$(nh_id_for_via "$PE1_IP")
standby_id=$(nh_id_for_via "$PE2_IP")
members=$(group_members_of "$group_id")
member_count=$(echo "$members" | tr ' ' '\n' | grep -c . || true)
if [ "$member_count" -eq 1 ] && [ "$members" = "$member_id" ] && [ -n "$member_id" ]; then
    ok "group $group_id has exactly one member: $member_id (via $PE1_IP — the active PE)"
else
    fail "group $group_id members '$members' (want exactly the via-$PE1_IP NH '$member_id')"
    rb_nh >&2
fi
if [ -n "$standby_id" ] && [ "$standby_id" != "$member_id" ]; then
    ok "backup per-VTEP NH pre-created: $standby_id (via $PE2_IP)"
else
    fail "no pre-created backup NH via $PE2_IP (got '$standby_id')"
    rb_nh >&2
fi
if echo "$members" | grep -qw "$standby_id"; then
    fail "standby NH $standby_id must NOT be a group member (kernel hashes over all members)"
else
    ok "standby NH $standby_id is not a group member (single egress forwards)"
fi

log "[phase 2] baseline counters"
wait_prom_value "evpn_single_active_backup_swaps_total" "0" "no swaps before the failure"
wait_prom_value "evpn_single_active_teardowns_total" "0" "no teardowns before the failure"
wait_prom_value "evpn_single_active_backup_active" "0" "no open failover window"

log "[phase 2] planting foreign state (must survive the whole cycle)"
docker exec "$VTEP" bridge fdb add "$FOREIGN_MAC" dev "$VXLAN" master static \
    && ok "foreign static FDB row $FOREIGN_MAC planted" \
    || fail "could not plant foreign static FDB row"
docker exec "$VTEP" ip nexthop add id "$FOREIGN_NH_ID" via 10.0.2.99 fdb \
    && ok "foreign untagged fdb nexthop id $FOREIGN_NH_ID planted" \
    || fail "could not plant foreign fdb nexthop"

log "[phase 2] baseline traffic hr -> CE through the active PE"
wait_ping "first hr -> CE ping reply" || print_summary
ping_burst_ok "baseline ping burst hr -> CE"

# ---------------------------------------------------------------------------
# Phase 3 — AC failure: one-message membership swap to the backup PE
# ---------------------------------------------------------------------------

log "[phase 3] starting the 100ms blackout prober on hr..."
docker exec "$HR" sh -c "rm -f /tmp/m65-prober.log" || true
# Record the prober's PID so teardown kills exactly this ping and
# never an interactive diagnostic one.
docker exec -d "$HR" sh -c "ping -i 0.1 -O $CE_HOST_IP >/tmp/m65-prober.log 2>&1 & echo \$! >/tmp/m65-prober.pid"
sleep 2

log "[phase 3] injecting the AC failure: pe1 CE leg down + EAD-per-ES withdrawal"
# The two steps emulate what an AC-binding PE does on attachment
# failure: forwarding to the CE dies, and the mass-withdraw signal
# (the EAD-per-ES alone — MAC routes stay advertised) goes out. The
# serialization gap between the two docker execs (~100-200 ms) is
# part of the measured window; noted in the receipt.
docker exec "$PE1" ip link set eth2 down \
    && ok "pe1 CE-facing bridge port down (blackout begins)" \
    || fail "could not down pe1's CE leg"
pe1_rib del -a evpn a-d $ESI_GOBGP etag 4294967295 label 0 rd "$RD_PE1" \
    && ok "pe1 EAD-per-ES withdrawn (mass-withdraw signal sent)" \
    || fail "pe1 EAD-per-ES withdrawal failed"

log "[phase 3] waiting for the membership swap (group $group_id -> $standby_id)..."
swap_seen=0
row_held=1
swap_wait_iters=150
for i in $(seq 1 "$swap_wait_iters"); do
    snap=$(rb_snapshot)
    fdb_part=$(echo "$snap" | sed -n '/^---FDB---$/,$p')
    if ! echo "$fdb_part" | grep -i "$CE_MAC" | grep -qE " nhid ${group_id}( |\$)"; then
        row_held=0
        fail "CE MAC row lost or re-pointed during the failover window (iteration $i)"
        echo "$fdb_part" >&2
        break
    fi
    gline=$(echo "$snap" | grep -E "^id ${group_id} group " || true)
    gmembers=$(echo "$gline" | grep -oE 'group [0-9/]+' | awk '{print $2}' || true)
    if [ "$gmembers" = "$standby_id" ]; then
        swap_seen=1
        break
    fi
    sleep 0.2
done
if [ "$swap_seen" -eq 1 ]; then
    ok "group $group_id retargeted to the pre-created backup NH $standby_id (same group id, nothing allocated)"
else
    [ "$row_held" -eq 1 ] && fail "membership swap not observed within ~30s"
    rb_nh >&2
    docker exec "$VTEP" tail -80 /var/log/rustbgpd.log >&2 || true
fi
if [ "$row_held" -eq 1 ]; then
    ok "CE MAC row kept nhid $group_id continuously across the failover (never flushed)"
fi

log "[phase 3] post-swap kernel + counter state"
row=$(ce_mac_row)
if echo "$row" | grep -qE " nhid ${group_id}( |\$)"; then
    ok "CE MAC row still behind group $group_id after the swap"
else
    fail "CE MAC row no longer behind group $group_id: $row"
fi
# The withdrawn PE's per-VTEP NH must be garbage-collected (it is
# neither a member nor a standby anywhere now).
old_member_gone=0
for _ in $(seq 1 30); do
    if ! rb_nh | grep -qE "^id ${member_id} via "; then
        old_member_gone=1
        break
    fi
    sleep 1
done
if [ "$old_member_gone" -eq 1 ]; then
    ok "withdrawn PE's NH $member_id garbage-collected"
else
    fail "withdrawn PE's NH $member_id still present after the swap"
    rb_nh >&2
fi
wait_prom_value "evpn_single_active_backup_swaps_total" "1" "exactly one membership swap"
wait_prom_value "evpn_single_active_teardowns_total" "0" "no teardown during the swap"
wait_prom_value "evpn_single_active_backup_active" "1" "failover window open (gauge)"

# Let the prober record a recovery segment, then stop it and measure.
sleep 3
docker exec "$HR" sh -c 'kill -TERM "$(cat /tmp/m65-prober.pid)" 2>/dev/null' || true
sleep 1

log "[phase 3] traffic restored through the backup PE"
wait_ping "hr -> CE ping reply via pe2" || true
ping_burst_ok "post-swap ping burst hr -> CE (via $PE2_IP)"

# ---------------------------------------------------------------------------
# Phase 4 — blackout window receipt
# ---------------------------------------------------------------------------

# Max consecutive missed-probe run from the reply sequence numbers.
# INFORMATIONAL measurement; the only hard gate is the <3s sanity
# bound (see header). At a 100 ms grain the floor of the measurable
# window is one probe.
prober_log=$(docker exec "$HR" cat /tmp/m65-prober.log 2>/dev/null || true)
max_gap=$(echo "$prober_log" | grep 'bytes from' \
    | grep -oE 'icmp_seq=[0-9]+' | cut -d= -f2 \
    | awk 'NR>1 && $1>prev+1 { g=$1-prev-1; if (g>max) max=g } { prev=$1 } END { print max+0 }' || true)
missed_lines=$(echo "$prober_log" | grep -c 'no answer yet' || true)
blackout_ms=$((${max_gap:-0} * PROBE_INTERVAL_MS))
log "=================================================================="
log " MEASURED BLACKOUT WINDOW: ${blackout_ms} ms"
log "   (${max_gap:-0} consecutive ${PROBE_INTERVAL_MS}ms probes lost; ${missed_lines} 'no answer yet' lines)"
log "   AC-failure case: CE-leg down + EAD-per-ES withdrawal, including"
log "   the driver's ~100-200ms injection serialization gap."
log "=================================================================="
if [ "$blackout_ms" -lt "$BLACKOUT_BOUND_MS" ]; then
    ok "blackout ${blackout_ms}ms < ${BLACKOUT_BOUND_MS}ms sanity bound (event-driven swap, not the periodic backstop)"
else
    fail "blackout ${blackout_ms}ms >= ${BLACKOUT_BOUND_MS}ms — repair did not ride the event path"
fi

# ---------------------------------------------------------------------------
# Phase 5 — ordered teardown: the LAST eligible PE withdraws
# ---------------------------------------------------------------------------

log "[phase 5] withdrawing pe2's EAD-per-ES (eligible set -> empty; pe1's MAC route still advertised)"
pe2_rib del -a evpn a-d $ESI_GOBGP etag 4294967295 label 0 rd "$RD_PE2" \
    && ok "pe2 EAD-per-ES withdrawn" \
    || fail "pe2 EAD-per-ES withdrawal failed"

teardown_done=0
for _ in $(seq 1 30); do
    if ! rb_fdb | grep -qi "$CE_MAC" \
        && ! rb_nh | grep -qE "^id ${group_id} " \
        && ! rb_nh | grep -qE "^id ${standby_id} "; then
        teardown_done=1
        break
    fi
    sleep 1
done
if [ "$teardown_done" -eq 1 ]; then
    ok "ordered teardown: CE MAC row flushed, group $group_id and NH $standby_id gone"
else
    fail "teardown incomplete: row/group/NH still present after 30s"
    rb_fdb >&2
    rb_nh >&2
fi
wait_prom_value "evpn_single_active_teardowns_total" "1" "exactly one ordered teardown"
wait_prom_value "evpn_single_active_backup_swaps_total" "1" "swap counter unchanged by the teardown"
wait_prom_value "evpn_single_active_backup_active" "0" "failover window closed (gauge)"

# No flood entries exist (no Type 3 was ever injected), so with the
# MAC row flushed the fabric has no path: pings must be hard-dead.
if docker exec "$HR" ping -c 3 -W 1 "$CE_HOST_IP" >/dev/null 2>&1; then
    fail "pings still flow after the teardown — a stale path survived"
else
    ok "pings hard-dead after the teardown (no eligible PE, no flood path)"
fi

# ---------------------------------------------------------------------------
# Phase 6 — foreign state survived the whole cycle
# ---------------------------------------------------------------------------

if rb_fdb | grep -qi "$FOREIGN_MAC"; then
    ok "driver-planted foreign FDB row $FOREIGN_MAC untouched"
else
    fail "driver-planted foreign FDB row $FOREIGN_MAC was deleted"
    rb_fdb >&2
fi
if rb_fdb | grep -qi "$PRELOADED_FOREIGN_MAC"; then
    ok "pre-loaded foreign FDB row $PRELOADED_FOREIGN_MAC untouched"
else
    fail "pre-loaded foreign FDB row $PRELOADED_FOREIGN_MAC was deleted"
fi
if rb_nh | grep -qE "^id ${FOREIGN_NH_ID} via "; then
    ok "foreign untagged fdb nexthop id $FOREIGN_NH_ID untouched"
else
    fail "foreign fdb nexthop id $FOREIGN_NH_ID was deleted"
    rb_nh >&2
fi

print_summary
