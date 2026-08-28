#!/usr/bin/env bash
# M81 interop test — the BMP trio receipt: RFC 8671 Adj-RIB-Out +
# RFC 9069 Loc-RIB + BMPv4 TLV framing (draft-ietf-grow-bmp-tlv-21), validated
# against three collectors at once.
#
# ── Oracle-support matrix (validated against pinned images) ─────────
#
#   oracle                  | v3 semantics             | v4 draft-21
#   ------------------------+--------------------------+---------------------------
#   pmacct pmbmpd pinned    | full semantic decode     | accepts version 4; raw
#                           | across all three views   | oracle remains decisive
#   gobmp pinned            | full semantic decode     | rejects version != 3
#   tshark 4.4.7 pinned     | full dissection          | version, peer headers,
#                           |                          | generic TLV header fields
#   raw sink                | byte reference           | normative wire oracle
#
# pmacct and gobmp remain independent semantic v3 oracles. The raw sink
# pins draft-21 Route Monitoring code points and exact embedded PDU bytes;
# tshark is used only for fields the pinned release dissects generically.
# Path Marking is not emitted: its active draft's type 5 conflicts with
# draft-21 Sequence Number. No assertion claims otherwise.
#
# Assertions (numbered in output):
#    1  pmacct: Initiation sysName/sysDescr
#    2  gobmp: RFC 9069 loc-rib per-AFI/SAFI stats (type 10) decoded
#       with the expected per-family route counts (gobmp validates but
#       discards Initiation content, so sysName is pmacct-only)
#    3  pmacct: PeerUp for both GoBGP peers
#    4  gobmp: PeerUp for both GoBGP peers
#    5  pmacct: Loc-RIB instance PeerUp (peer type 3, is_loc,
#       VRF table name "global", local ASN + router-id)
#    6  gobmp: Loc-RIB instance PeerUp (IsLocRIB)
#    7  pmacct: rib-in-pre RM for the pe1 unicast route
#    8  gobmp: rib-in RM for the pe1 unicast route
#    9  pmacct: rib-out-post RM toward pe2 (O+L set) for the reflected route
#   10  gobmp: rib-out-post RM (IsAdjRIBOut + IsAdjRIBOutPost)
#   11  pmacct: loc-rib RM for the best path
#   12  gobmp: loc-rib RM for the best path
#   13  IPv6 unicast route visible on the loc-rib stream
#   14  VPNv4 route (RD 65001:100) visible on rib-in + loc-rib streams
#   15  loc-rib best-path flip: pe1's LP=200 path replaces pe2's LP=100
#   16  loc-rib withdraw propagates on the v3 stream after route removal
#   17  gobmp: reconnect triggers a full loc-rib dump (PeerUp + table
#       re-delivery) — RFC 9069 collector-connect sync
#   18  raw v4: reconnect dump = loc-rib PeerUp + unmarked dump
#       announces + exactly 4 End-of-RIBs
#   19  pmacct: PeerDown for pe2 with a reason code
#   20  gobmp: peer down message for pe2
#   21  loc-rib withdraw of pe2's route after session down
#   22  pmacct: Termination on daemon shutdown
#   23  raw: both sink streams close with a Termination message
#   24  raw: loc-rib instance PeerDown reason 6 on shutdown (v3 + v4)
#   25  raw: every message on the v4 slot is version 4 (v3 slot: 3)
#   26  raw v4 RM framing: exact TLV walk; single BGP Message TLV
#       type 4, index 0; TLV length == PDU length (excludes index)
#   27  raw: rib-in/rib-out/loc-rib RM PDU sets byte-equal across the
#       v3 stream and the v4 BGP Message TLVs (mixed-fleet equality)
#   28  raw: v4 Initiation byte-identical to v3 except the version byte
#   29  raw: v4 PeerUp byte-identical to v3 except the version byte
#   30  raw: v4 Stats Report wraps Stats Count + data in Stats TLV
#       code 1; unwrapped value byte-matches a v3 stats body
#   31  raw: stats carry loc-rib type 8 + 10 counters (instance peer)
#       and type 7 (Adj-RIB-In) on a regular peer
#   32  raw v4: every RM carries only BGP Message TLV type 4; no
#       ambiguous type-5 Path Marking is emitted
#   33  tshark: all v4-port messages dissect with bmp.version == 4
#   34  tshark: v4 RM TLV header fields dissect generically as
#       type 4 / index 0 (value naming per released Wireshark tracks
#       older tlv drafts — documented skew, see matrix)
#   35  tshark: per-peer headers dissect on both ports — loc-rib
#       instance peer (type 3) and Adj-RIB-Out + post-policy flags
#   36  tshark: the dissected v3 loc-rib UPDATE for the contested
#       prefix carries LOCAL_PREF 200 (the LP winner is in the
#       Loc-RIB stream)
#   37  tshark: v3-port RM messages dissect as plain BGP UPDATEs
#       (bmp.version == 3, no v4 TLV fields)
#   38  raw: PE1 Stats Reports carry exactly one IPv4-unicast and one
#       IPv6-unicast RFC 9972 policy-rejection row (type 22), both 1,
#       with byte-equal v3 body / v4 Stats TLV value
#   39  raw: PE1 Stats Reports carry exact RFC 9972 RPKI post-policy
#       Adj-RIB-In rows (types 35/36/37) for IPv4/IPv6 unicast: one
#       Invalid, one Valid, and one NotFound path in each family, with
#       byte-equal v3 body / v4 Stats TLV value
#
# Deferred (documented, not asserted): Path Marking is unavailable
# until its draft receives a non-colliding assignment; draft-21 uses
# type 5 for Sequence Number. pmacct-side stats decoding is not asserted (pmbmpd msglog
# does not emit per-counter stats entries); stats are pinned at byte
# level (30/31) instead.
#
# Self-test: bash tests/interop/scripts/test-m81-bmp-trio-gobgp.sh
#   --self-test-startup-diagnostics
# Prerequisites:
#   - docker build --target dev -t rustbgpd:dev .
#   - docker build -t gobgp:interop -f tests/interop/Dockerfile.gobgp tests/interop
#   - docker build -t bmpsink:m81 -f tests/interop/Dockerfile.bmpsink tests/interop
#   - containerlab deployed:
#       containerlab deploy -t tests/interop/m81-bmp-trio-gobgp.clab.yml

TOPO="m81-bmp-trio-gobgp"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
if [ "${1:-}" = "--self-test-startup-diagnostics" ]; then
    set -euo pipefail
    log() { printf 'TEST %s\n' "$*"; }
    ok() { printf 'PASS %s\n' "$*"; }
    fail() { printf 'FAIL %s\n' "$*" >&2; }
    RUSTBGPD="fixture-rustbgpd"
    GRPC_ADDR="fixture-grpc"
else
    # shellcheck source=tests/interop/scripts/test-lib.sh
    source "$SCRIPT_DIR/test-lib.sh"
fi

PE1="clab-${TOPO}-gobgp-pe1"
PE2="clab-${TOPO}-gobgp-pe2"
PMACCT="clab-${TOPO}-pmacct"
GOBMP="clab-${TOPO}-gobmp"
SINK="clab-${TOPO}-bmpsink"
STAYRTR="clab-${TOPO}-stayrtr"

PE1_ADDR="10.0.0.2"
PE2_ADDR="10.0.1.2"

UNI_PREFIX="10.10.1.0/24"        # pe1 unicast, later withdrawn (16)
PE2_PREFIX="10.20.2.0/24"        # pe2 unique, withdrawn by peer down (21)
CONTEST_PREFIX="10.99.0.0/24"    # pe2 LP=100 first, pe1 LP=200 wins (15/33)
V6_PREFIX="2001:db8:10::/48"
REJECT_V4_PREFIX="198.18.81.0/24"
REJECT_V6_PREFIX="2001:db8:81::/48"
RPKI_VALID_V4_PREFIX="203.0.113.0/24"
RPKI_INVALID_V4_PREFIX="203.0.114.0/24"
RPKI_VALID_V6_PREFIX="2001:db8:82::/48"
RPKI_INVALID_V6_PREFIX="2001:db8:83::/48"
VPN_PREFIX="10.100.1.0/24"
VPN_RD="65001:100"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# BusyBox/slim images lack pkill; walk /proc by comm name (M79 pattern).
kill_by_comm() {
    local container=${1:?} comm=${2:?} sig=${3:-TERM}
    docker exec "$container" sh -c '
        for p in /proc/[0-9]*; do
            [ "$(cat "$p/comm" 2>/dev/null)" = "'"$comm"'" ] && kill -'"$sig"' "${p#/proc/}"
        done' || true
}

start_gobgpd() {
    local container=${1:?}
    log "Starting gobgpd in $container..."
    docker exec -d "$container" sh -c \
        'nohup gobgpd -f /config/gobgp.toml >/tmp/gobgpd.log 2>&1'
}

gobgp() {
    local container=${1:?}
    shift
    docker exec "$container" gobgp "$@" 2>/dev/null
}

dump_m81_startup_diagnostics() {
    local container=${1:?} rr_peer=${2:?} rustbgpd_peer=${3:?}

    printf '%s\n' \
        '--- M81 startup diagnostics: gobgpd log (/tmp/gobgpd.log; tail 120) ---' >&2
    timeout 5 docker exec "$container" sh -c \
        'tail -n 120 /tmp/gobgpd.log' 2>&1 | head -n 120 >&2 || true

    printf '%s\n' '--- M81 startup diagnostics: gobgpd process ---' >&2
    # shellcheck disable=SC2016
    timeout 5 docker exec "$container" sh -c '
        for p in /proc/[0-9]*; do
            [ "$(cat "$p/comm" 2>/dev/null)" = "gobgpd" ] || continue
            printf "pid=%s cmd=" "${p#/proc/}"
            tr "\0" " " <"$p/cmdline" 2>/dev/null || true
            printf "\n"
        done
    ' 2>&1 | head -n 40 >&2 || true

    printf '%s\n' \
        '--- M81 startup diagnostics: gobgp neighbor (stderr unsuppressed) ---' >&2
    timeout 5 docker exec "$container" gobgp neighbor 2>&1 | head -n 120 >&2 || true

    printf '%s\n' '--- M81 startup diagnostics: peer eth1 address ---' >&2
    timeout 5 docker exec "$container" ip -brief address show dev eth1 \
        2>&1 | head -n 40 >&2 || true

    printf '%s\n' '--- M81 startup diagnostics: peer eth1 link ---' >&2
    timeout 5 docker exec "$container" ip -details link show dev eth1 \
        2>&1 | head -n 80 >&2 || true

    printf '%s\n' \
        '--- M81 startup diagnostics: peer route to RR + table ---' >&2
    # shellcheck disable=SC2016
    timeout 5 docker exec "$container" sh -c \
        'ip route get "$1"; ip route show' sh "$rr_peer" \
        2>&1 | head -n 120 >&2 || true

    printf '%s\n' '--- M81 startup diagnostics: rustbgpd log (tail 120) ---' >&2
    timeout 5 docker logs --tail 120 "$RUSTBGPD" \
        2>&1 | head -n 120 >&2 || true

    printf '%s\n' \
        '--- M81 startup diagnostics: rustbgpd neighbor snapshot ---' >&2
    grpcurl_call -max-time 5 -d "{\"address\":\"$rustbgpd_peer\"}" \
        "$GRPC_ADDR" rustbgpd.v1.NeighborService/GetNeighborState \
        2>&1 | head -n 160 >&2 || true
}

wait_gobgp_established() {
    local container=${1:?} peer=${2:?} label=${3:?} rustbgpd_peer=${4:?}
    log "Waiting for $label session to $peer..."
    for i in $(seq 1 45); do
        if gobgp "$container" neighbor 2>/dev/null | grep -F -- "$peer" \
            | grep -i "establ" >/dev/null; then
            ok "$label session established (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "$label session did not reach Established within 90s"
    dump_m81_startup_diagnostics "$container" "$peer" "$rustbgpd_peer"
    return 1
}

# pmacct msglog is JSONL in the pmacct container.
pmacct_json() {
    docker exec "$PMACCT" cat /tmp/bmp-msglog.json 2>/dev/null || true
}

# Count pmacct msglog entries matching a jq select expression.
pmacct_count() {
    local expr=${1:?}
    pmacct_json | jq -s "[.[] | select($expr)] | length" 2>/dev/null || echo 0
}

wait_pmacct() {
    local expr=${1:?} label=${2:?} attempts=${3:-30}
    for i in $(seq 1 "$attempts"); do
        if [ "$(pmacct_count "$expr")" -ge 1 ]; then
            ok "pmacct: $label (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "pmacct: $label"
    pmacct_json | tail -20 >&2 || true
    return 1
}

# gobmp dumps one JSON object per message line to stdout (docker logs),
# interleaved with glog lines — keep only JSON lines.
gobmp_json() {
    docker logs "$GOBMP" 2>&1 | grep '^{' || true
}

gobmp_count() {
    local expr=${1:?}
    gobmp_json | jq -s "[.[] | select($expr)] | length" 2>/dev/null || echo 0
}

wait_gobmp() {
    local expr=${1:?} label=${2:?} attempts=${3:-30}
    for i in $(seq 1 "$attempts"); do
        if [ "$(gobmp_count "$expr")" -ge 1 ]; then
            ok "gobmp: $label (attempt $i)"
            return 0
        fi
        sleep 2
    done
    fail "gobmp: $label"
    gobmp_json | tail -20 >&2 || true
    return 1
}

# Numbered raw-byte assertion via m81-bmp-assert.py inside the sink.
raw_assert() {
    local label=${1:?}
    shift
    local out
    if out=$(docker exec "$SINK" python3 /usr/local/bin/m81-bmp-assert.py "$@" 2>&1); then
        ok "raw: $label — ${out#OK: }"
    else
        fail "raw: $label — $out"
    fi
}

# tshark over the sink-side pcap, BMP forced onto the v4 port.
sink_tshark() {
    # Wireshark's default BMP port is neither sink port: force BMP
    # decode on both.
    docker exec "$SINK" tshark -r /tmp/m81.pcap \
        -d tcp.port==11019,bmp -d tcp.port==11020,bmp "$@" 2>/dev/null
}

tshark_count() {
    sink_tshark -Y "${1:?}" -T fields -e frame.number | wc -l
}

assert_tshark() {
    local label=${1:?} filter=${2:?} want_nonzero=${3:-1}
    local n
    n=$(tshark_count "$filter")
    if { [ "$want_nonzero" = "1" ] && [ "$n" -ge 1 ]; } \
        || { [ "$want_nonzero" = "0" ] && [ "$n" -eq 0 ]; }; then
        ok "tshark: $label ($n frames)"
    else
        fail "tshark: $label (matched $n frames)"
    fi
}

patch_runtime_addrs() {
    local pmacct_ip gobmp_ip sink_ip stayrtr_ip
    pmacct_ip=$(resolve_ip "$PMACCT")
    gobmp_ip=$(resolve_ip "$GOBMP")
    sink_ip=$(resolve_ip "$SINK")
    stayrtr_ip=$(resolve_ip "$STAYRTR")
    if [ -z "$pmacct_ip" ] || [ -z "$gobmp_ip" ] || [ -z "$sink_ip" ] \
        || [ -z "$stayrtr_ip" ]; then
        echo "ERROR: cannot resolve collector or StayRTR management IPs" >&2
        exit 1
    fi
    log "Runtime endpoints: pmacct=$pmacct_ip gobmp=$gobmp_ip sink=$sink_ip stayrtr=$stayrtr_ip"
    docker exec "$RUSTBGPD" sh -c \
        "sed -e 's/PMACCT_ADDR/${pmacct_ip}/' -e 's/GOBMP_ADDR/${gobmp_ip}/' \
             -e 's/SINK_ADDR/${sink_ip}/' -e 's/STAYRTR_ADDR/${stayrtr_ip}/' \
             /etc/rustbgpd/config.toml > /tmp/config.toml"
}

wait_rpki_vrps() {
    local v4 v6
    for i in $(seq 1 45); do
        v4=$(prom_value "$RUSTBGPD" 'bgp_rpki_vrp_count{af="ipv4"}')
        v6=$(prom_value "$RUSTBGPD" 'bgp_rpki_vrp_count{af="ipv6"}')
        if [ "${v4:-}" = 2 ] && [ "${v6:-}" = 2 ]; then
            ok "StayRTR VRP table loaded exactly (IPv4=2, IPv6=2; attempt $i)"
            return 0
        fi
        sleep 1
    done
    fail "StayRTR VRP table not loaded exactly (IPv4=${v4:-missing}, IPv6=${v6:-missing})"
    return 1
}

start_sink() {
    log "Starting raw BMP sink + tshark capture in $SINK..."
    docker exec -d "$SINK" python3 /usr/local/bin/bmp-raw-sink.py
    docker exec -d "$SINK" sh -c \
        'tshark -i eth0 -w /tmp/m81.pcap "port 11019 or port 11020" >/tmp/tshark.log 2>&1'
    sleep 2
}

# ---------------------------------------------------------------------------
# Test phases
# ---------------------------------------------------------------------------

test_initiation_and_peerups() {
    log "Assertions 1-6: Initiation + PeerUps on both semantic oracles"

    # 1
    wait_pmacct '.bmp_msg_type == "init"
                 and .bmp_init_info_sysname == "rustbgpd-m81"
                 and (.bmp_init_info_sysdescr | length > 0)' \
        "(1) Initiation with sysName rustbgpd-m81 + sysDescr"
    # 3
    if [ "$(pmacct_count ".bmp_msg_type == \"peer_up\" and .peer_ip == \"$PE1_ADDR\"")" -ge 1 ] \
        && [ "$(pmacct_count ".bmp_msg_type == \"peer_up\" and .peer_ip == \"$PE2_ADDR\"")" -ge 1 ]; then
        ok "pmacct: (3) PeerUp for pe1 + pe2"
    else
        fail "pmacct: (3) PeerUp for pe1 + pe2"
        pmacct_json | tail -10 >&2 || true
    fi
    # 4
    if [ "$(gobmp_count ".msg_data.remote_ip? == \"$PE1_ADDR\" and .msg_data.action? == \"add\"")" -ge 1 ] \
        && [ "$(gobmp_count ".msg_data.remote_ip? == \"$PE2_ADDR\" and .msg_data.action? == \"add\"")" -ge 1 ]; then
        ok "gobmp: (4) PeerUp for pe1 + pe2"
    else
        fail "gobmp: (4) PeerUp for pe1 + pe2"
        gobmp_json | tail -10 >&2 || true
    fi
    # 5
    wait_pmacct '.bmp_msg_type == "peer_up" and .peer_type == 3
                 and .is_loc == 1 and .peer_asn == 65001
                 and .bgp_id == "10.255.0.1"
                 and .bmp_peer_up_info_vrf_table_name == "global"' \
        "(5) Loc-RIB instance PeerUp (type 3, ASN 65001, table \"global\")" 5
    # 6
    wait_gobmp '.msg_data.is_loc_rib? == true and .msg_data.action? == "add"
                and .msg_data.remote_bgp_id? == "10.255.0.1"' \
        "(6) Loc-RIB instance PeerUp (IsLocRIB, local router-id)" 5
}

test_route_streams() {
    log "Assertions 7-15: the three RM streams on both v3 oracles"

    # Contested prefix: pe2's LP=100 path FIRST, so the later pe1 LP=200
    # winner is a decision against a live runner-up (reason code, #33).
    gobgp "$PE2" global rib add "$CONTEST_PREFIX" nexthop "$PE2_ADDR" local-pref 100
    gobgp "$PE2" global rib add "$PE2_PREFIX" nexthop "$PE2_ADDR"
    # 11 (first half): pe2's path reaches the loc-rib stream before pe1 competes
    wait_pmacct ".bmp_msg_type == \"route_monitor\" and .is_loc == 1
                 and .ip_prefix == \"$CONTEST_PREFIX\"" \
        "(11a) loc-rib RM for the initial $CONTEST_PREFIX best path"

    gobgp "$PE1" global rib add "$CONTEST_PREFIX" nexthop "$PE1_ADDR" local-pref 200
    gobgp "$PE1" global rib add "$UNI_PREFIX" nexthop "$PE1_ADDR"
    gobgp "$PE1" global rib add -a ipv6 "$V6_PREFIX" nexthop "2001:db8::1"
    gobgp "$PE1" global rib add "$REJECT_V4_PREFIX" nexthop "$PE1_ADDR"
    gobgp "$PE1" global rib add -a ipv6 "$REJECT_V6_PREFIX" nexthop "2001:db8::1"
    gobgp "$PE1" global rib add "$RPKI_VALID_V4_PREFIX" nexthop "$PE1_ADDR" aspath 65100
    gobgp "$PE1" global rib add "$RPKI_INVALID_V4_PREFIX" nexthop "$PE1_ADDR" aspath 65100
    gobgp "$PE1" global rib add -a ipv6 "$RPKI_VALID_V6_PREFIX" nexthop "2001:db8::1" aspath 65100
    gobgp "$PE1" global rib add -a ipv6 "$RPKI_INVALID_V6_PREFIX" nexthop "2001:db8::1" aspath 65100
    gobgp "$PE1" vrf add blue rd "$VPN_RD" rt both "$VPN_RD"
    gobgp "$PE1" vrf blue rib add "$VPN_PREFIX" nexthop "$PE1_ADDR"

    # 7
    wait_pmacct ".bmp_msg_type == \"route_monitor\" and .is_in == 1
                 and .is_post == 0 and .peer_ip == \"$PE1_ADDR\"
                 and .ip_prefix == \"$UNI_PREFIX\"" \
        "(7) rib-in-pre RM for $UNI_PREFIX from pe1"
    # 8
    wait_gobmp ".msg_data.prefix? == \"10.10.1.0\" and .msg_data.prefix_len? == 24
                and .msg_data.peer_ip? == \"$PE1_ADDR\"
                and .msg_data.is_adj_rib_out? != true
                and .msg_data.is_loc_rib? != true" \
        "(8) rib-in RM for $UNI_PREFIX from pe1"
    # 9
    wait_pmacct ".bmp_msg_type == \"route_monitor\" and .is_out == 1
                 and .is_post == 1 and .peer_ip == \"$PE2_ADDR\"
                 and .ip_prefix == \"$UNI_PREFIX\"" \
        "(9) rib-out-post RM toward pe2 for reflected $UNI_PREFIX (O+L)"
    # 10
    wait_gobmp ".msg_data.prefix? == \"10.10.1.0\"
                and .msg_data.is_adj_rib_out? == true
                and .msg_data.is_adj_rib_out_post_policy? == true
                and .msg_data.peer_ip? == \"$PE2_ADDR\"" \
        "(10) rib-out-post RM toward pe2 (IsAdjRIBOut + post-policy)"
    # 11
    wait_pmacct ".bmp_msg_type == \"route_monitor\" and .is_loc == 1
                 and .ip_prefix == \"$UNI_PREFIX\"" \
        "(11) loc-rib RM for best path $UNI_PREFIX"
    # 12
    wait_gobmp ".msg_data.prefix? == \"10.10.1.0\"
                and .msg_data.is_loc_rib? == true" \
        "(12) loc-rib RM for best path $UNI_PREFIX"
    # 13
    wait_pmacct ".bmp_msg_type == \"route_monitor\" and .is_loc == 1
                 and .ip_prefix == \"$V6_PREFIX\"" \
        "(13) loc-rib RM for IPv6 $V6_PREFIX"
    # 14
    if [ "$(pmacct_count ".bmp_msg_type == \"route_monitor\" and .is_in == 1
                and .ip_prefix == \"$VPN_PREFIX\"")" -ge 1 ]; then
        wait_pmacct ".bmp_msg_type == \"route_monitor\" and .is_loc == 1
                     and .ip_prefix == \"$VPN_PREFIX\"" \
            "(14) VPNv4 $VPN_PREFIX on rib-in + loc-rib streams"
    else
        fail "pmacct: (14) VPNv4 $VPN_PREFIX on the rib-in stream"
        pmacct_json | grep -F "$VPN_PREFIX" | tail -5 >&2 || true
    fi
    # 15
    wait_pmacct ".bmp_msg_type == \"route_monitor\" and .is_loc == 1
                 and .ip_prefix == \"$CONTEST_PREFIX\"
                 and .bgp_nexthop == \"$PE1_ADDR\"" \
        "(15) loc-rib best for $CONTEST_PREFIX flips to pe1's LP=200 path"
}

test_withdraw() {
    log "Assertion 16: loc-rib withdraw on the v3 stream"
    gobgp "$PE1" global rib del "$UNI_PREFIX"
    # 16
    wait_pmacct ".bmp_msg_type == \"route_monitor\" and .is_loc == 1
                 and .ip_prefix == \"$UNI_PREFIX\" and .log_type == \"withdraw\"" \
        "(16) loc-rib withdraw RM for $UNI_PREFIX"
}

test_reconnect_dump() {
    log "Assertions 17-18: collector-connect loc-rib table sync (RFC 9069)"

    # 17 — gobmp restart: rustbgpd reconnects and must re-dump the table.
    local marker
    marker=$(date +%s)
    docker restart "$GOBMP" >/dev/null
    for i in $(seq 1 30); do
        if docker logs --since "$marker" "$GOBMP" 2>&1 | grep '^{' \
            | jq -s "[.[] | select(.msg_data.prefix? == \"10.99.0.0\" and .msg_data.is_loc_rib? == true)] | length" 2>/dev/null \
            | grep -qv '^0$'; then
            ok "gobmp: (17) reconnect re-delivered the loc-rib table (dump)"
            break
        fi
        if [ "$i" -eq 30 ]; then
            fail "gobmp: (17) no loc-rib dump after reconnect"
            docker logs --since "$marker" "$GOBMP" 2>&1 | tail -15 >&2 || true
        fi
        sleep 2
    done

    # 18 — raw v4 dump shape: restart the sink process with a fresh
    # conn-id base; rustbgpd reconnects within reconnect_interval (5 s).
    docker exec "$SINK" pkill -f bmp-raw-sink.py || true  # alpine has pkill
    sleep 1
    docker exec -d "$SINK" python3 /usr/local/bin/bmp-raw-sink.py 100
    log "Waiting for the v4 reconnect dump to complete (4 EoRs)..."
    for i in $(seq 1 30); do
        if docker exec "$SINK" python3 /usr/local/bin/m81-bmp-assert.py dump 100 >/dev/null 2>&1; then
            break
        fi
        sleep 2
    done
    raw_assert "(18) v4 reconnect dump: PeerUp + unmarked announces + 4 EoRs" \
        dump 100
}

test_stats() {
    log "Assertion 2 (+ raw 30/31 precondition): a periodic stats round (60 s cadence)"
    for i in $(seq 1 40); do
        if docker exec "$SINK" python3 /usr/local/bin/m81-bmp-assert.py \
            stats_locrib_counts >/dev/null 2>&1; then
            log "stats observed on the raw v3 stream (attempt $i)"
            break
        fi
        sleep 3
    done
    # 2 — gobmp decodes the RFC 9069 type-10 per-AFI/SAFI loc-rib
    # gauges; after the feed the ipv4-unicast and vpnv4 counts are >= 1.
    wait_gobmp '.msg_data.per_afi_loc_rib? != null
                and ([.msg_data.per_afi_loc_rib[]
                      | select(.afi == 1 and .safi == 1 and .count >= 1)] | length) > 0
                and ([.msg_data.per_afi_loc_rib[]
                      | select(.afi == 1 and .safi == 128 and .count >= 1)] | length) > 0' \
        "(2) loc-rib per-AFI stats: ipv4-unicast + vpnv4 counts >= 1 (RFC 9069 type 10)" 40
    raw_assert "(38) PE1 policy rejects: exact v4/v6 type-22 rows, v3/v4-equal body" \
        stats_policy_reject_counts "$PE1_ADDR"
    raw_assert "(39) PE1 RPKI states: exact v4/v6 type-35/36/37 rows, v3/v4-equal body" \
        stats_rpki_counts "$PE1_ADDR"
}

test_peer_down() {
    log "Assertions 19-21: PeerDown + loc-rib withdraw on session teardown"
    kill_by_comm "$PE2" gobgpd TERM
    # 19
    wait_pmacct ".bmp_msg_type == \"peer_down\" and .peer_ip == \"$PE2_ADDR\"
                 and (.reason_type != null or .reason != null)" \
        "(19) PeerDown for pe2 with a reason"
    # 20
    wait_gobmp ".msg_data.remote_ip? == \"$PE2_ADDR\" and .msg_data.action? == \"down\"
                and .msg_data.bmp_reason? != null" \
        "(20) peer down message for pe2 (with BMP reason)"
    # 21
    wait_pmacct ".bmp_msg_type == \"route_monitor\" and .is_loc == 1
                 and .ip_prefix == \"$PE2_PREFIX\" and .log_type == \"withdraw\"" \
        "(21) loc-rib withdraw of pe2's $PE2_PREFIX"
}

test_shutdown() {
    log "Assertions 22-24: coordinated shutdown — Termination + loc-rib PeerDown 6"
    kill_by_comm "$RUSTBGPD" rustbgpd TERM
    sleep 4
    # 22
    wait_pmacct '.bmp_msg_type == "term"' "(22) Termination on shutdown" 5
    # 23
    raw_assert "(23a) v3 stream closes with Termination" term 11019
    raw_assert "(23b) v4 stream closes with Termination" term 11020
    # 24
    raw_assert "(24a) v3 loc-rib PeerDown reason 6" locrib_peerdown_reason6 11019
    raw_assert "(24b) v4 loc-rib PeerDown reason 6" locrib_peerdown_reason6 11020
}

test_raw_byte_matrix() {
    log "Assertions 25-32: byte-level BMPv4 draft-21 framing"
    raw_assert "(25a) v4 slot all version 4" versions 11020 4
    raw_assert "(25b) v3 slot all version 3" versions 11019 3
    raw_assert "(26) v4 RM: single BGP Message TLV 4, index 0, len excludes index" rm_bgp_tlv
    raw_assert "(27) mixed fleet: RM PDU byte-equality across v3/v4 streams" rm_pdu_equality
    raw_assert "(28) v4 Initiation == v3 except version byte" init_equal
    raw_assert "(29) v4 PeerUp == v3 except version byte (pe1)" peerup_equal "$PE1_ADDR"
    raw_assert "(30) v4 Stats wrapped in Stats TLV 1, value == v3 body" stats_v4_wrap
    raw_assert "(31) stats: loc-rib types 8+10, peer type 7" stats_locrib_counts
    raw_assert "(32) no ambiguous type-5 Path Marking on any v4 RM" no_path_marking
}

test_tshark_matrix() {
    log "Assertions 33-37: tshark 4.4 dissection of the capture (scoped per the oracle matrix)"
    docker exec "$SINK" pkill tshark || true
    sleep 2

    # 33 — nothing on the v4 port dissects as any other BMP version.
    assert_tshark "(33a) v4 port carries bmp.version 4 frames" \
        'tcp.port == 11020 && bmp.version == 4' 1
    assert_tshark "(33b) no non-4 BMP version on the v4 port" \
        'tcp.port == 11020 && bmp.version && bmp.version != 4' 0
    # 34 — the RM TLV header (type/length/index) dissects generically
    # before any per-type value parsing: an independent read of "first
    # TLV type is 4, index 0" under draft-21.
    assert_tshark "(34) v4 RM TLV header fields: type 4, index 0" \
        'bmp.tlv.type == 4 && bmp.tlv.index == 0' 1
    # 35 — per-peer header dissection is draft-revision-independent.
    assert_tshark "(35a) loc-rib instance peer (type 3) frames on the v4 port" \
        'tcp.port == 11020 && bmp.peer.type == 3' 1
    assert_tshark "(35b) loc-rib instance peer (type 3) frames on the v3 port" \
        'tcp.port == 11019 && bmp.peer.type == 3' 1
    assert_tshark "(35c) Adj-RIB-Out + post-policy peer flags (RFC 8671 O+L)" \
        'bmp.peer.flags.adj_rib_out == 1 && bmp.peer.flags.post_policy == 1' 1
    # 36 — semantic loc-rib check through full v3 dissection: the
    # contested prefix's Loc-RIB copy carries the winning LOCAL_PREF.
    assert_tshark "(36) v3 loc-rib UPDATE for the contested prefix has LOCAL_PREF 200" \
        'tcp.port == 11019 && bmp.peer.type == 3 && bgp.update.path_attribute.local_pref == 200 && bgp.nlri_prefix == 10.99.0.0' 1
    # 37 — v3 side: classic RM, BGP PDU dissected inline, no v4 TLVs.
    assert_tshark "(37a) v3 port RM dissects as plain BGP UPDATE" \
        'tcp.port == 11019 && bmp.version == 3 && bgp.type == 2' 1
    assert_tshark "(37b) no v4 TLV fields on the v3 port" \
        'tcp.port == 11019 && bmp.tlv.type' 0
}

main() {
    log "M81 interop test: BMP trio receipt (RFC 8671 + RFC 9069 + BMPv4 draft-21 TLV)"
    log "Topology: $TOPO"

    preflight
    resolve_grpc_addr
    patch_runtime_addrs
    start_sink
    start_rustbgpd "/usr/local/bin/rustbgpd /tmp/config.toml"
    wait_rpki_vrps || exit 1
    start_gobgpd "$PE1"
    start_gobgpd "$PE2"

    wait_gobgp_established "$PE1" "10.0.0.1" "pe1" "$PE1_ADDR" || exit 1
    wait_gobgp_established "$PE2" "10.0.1.1" "pe2" "$PE2_ADDR" || exit 1

    test_initiation_and_peerups
    test_route_streams
    test_withdraw
    test_reconnect_dump
    test_stats
    test_peer_down
    test_shutdown
    test_raw_byte_matrix
    test_tshark_matrix

    print_summary
}

self_test_startup_diagnostics() {
    local output status needle
    local -a expected=(
        "FAIL pe-test session did not reach Established within 90s"
        "--- M81 startup diagnostics: gobgpd log (/tmp/gobgpd.log; tail 120) ---"
        "--- M81 startup diagnostics: gobgpd process ---"
        "--- M81 startup diagnostics: gobgp neighbor (stderr unsuppressed) ---"
        "--- M81 startup diagnostics: peer eth1 address ---"
        "--- M81 startup diagnostics: peer eth1 link ---"
        "--- M81 startup diagnostics: peer route to RR + table ---"
        "--- M81 startup diagnostics: rustbgpd log (tail 120) ---"
        "--- M81 startup diagnostics: rustbgpd neighbor snapshot ---"
        "fixture gobgpd log" "fixture gobgpd process"
        "fixture gobgp neighbor" "fixture peer address"
        "fixture peer link" "fixture peer routes"
        "fixture rustbgpd log" "fixture rustbgpd neighbor"
    )

    seq() { printf '1\n'; }
    sleep() { :; }
    gobgp() { return 1; }
    timeout() { shift; "$@"; }
    docker() {
        case "$*" in
            *"/tmp/gobgpd.log"*) printf 'fixture gobgpd log\n' ;;
            *"/proc/"*) printf 'fixture gobgpd process\n' ;;
            *"gobgp neighbor"*) printf 'fixture gobgp neighbor\n' ;;
            *"ip -brief"*) printf 'fixture peer address\n' ;;
            *"ip -details link"*) printf 'fixture peer link\n' ;;
            *"ip route get"*) printf 'fixture peer routes\n' ;;
            *"logs --tail 120"*) printf 'fixture rustbgpd log\n' ;;
            *) return 1 ;;
        esac
    }
    grpcurl_call() { printf 'fixture rustbgpd neighbor\n'; }

    set +e
    output=$(wait_gobgp_established fixture-pe 10.0.0.1 pe-test 10.0.0.2 2>&1)
    status=$?
    set -e
    [ "$status" -eq 1 ] || {
        printf 'self-test expected status 1, got %s\n' "$status" >&2
        return 1
    }
    for needle in "${expected[@]}"; do
        [[ "$output" == *"$needle"* ]] || {
            printf 'self-test missing %q in:\n%s\n' "$needle" "$output" >&2
            return 1
        }
    done

    docker() { return 127; }
    grpcurl_call() { return 127; }
    set +e
    output=$(wait_gobgp_established fixture-pe 10.0.0.1 pe-test 10.0.0.2 2>&1)
    status=$?
    set -e
    if [ "$status" -ne 1 ] \
        || [[ "$output" != *"${expected[0]}"* ]] \
        || [[ "$output" != *"${expected[8]}"* ]]; then
        printf 'unavailable-tools self-test masked the primary failure:\n%s\n' \
            "$output" >&2
        return 1
    fi

    printf 'M81 startup diagnostic self-test passed\n'
}

if [ "${1:-}" = "--self-test-startup-diagnostics" ]; then
    self_test_startup_diagnostics
else
    main "$@"
fi
