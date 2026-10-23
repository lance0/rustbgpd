#!/usr/bin/env bash
# M53b: RA-discovered interface-only peers and scoped RFC 8950 forwarding.
set -euo pipefail

TOPO=m53b-interface-only-frr
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_TEST_OPERATOR_AUTH=1
export INTEROP_TEST_OPERATOR_AUTH
# shellcheck source=tests/interop/scripts/test-lib.sh
source "$SCRIPT_DIR/test-lib.sh"

FRR1="clab-${TOPO}-frr1"
FRR2="clab-${TOPO}-frr2"
FRR3="clab-${TOPO}-frr3"
SWITCH="clab-${TOPO}-switch"
ROGUE="clab-${TOPO}-rogue"
PREFIX=198.51.100.53/32
PREFIX3=198.51.100.54/32
INJECTED_PREFIX=192.0.2.53/32
TABLE_ID=1000
METRIC=200
WORK=$(mktemp -d /tmp/m53b-lifecycle.XXXXXX)
PACKET_HELPER=$WORK/packet.py
CAPTURE="clab-${TOPO}-capture"

cleanup_m53b() {
    local rc=$?
    docker rm -f "$CAPTURE" >/dev/null 2>&1 || true
    cp "$WORK/capture.jsonl" /tmp/m53b-lifecycle-last-capture.jsonl 2>/dev/null || true
    docker exec "$RUSTBGPD" cat /tmp/m53b-rustbgpd.log \
        >/tmp/m53b-lifecycle-last-daemon.log 2>/dev/null || true
    rm -rf "$WORK"
    _cleanup_on_exit
    return "$rc"
}
trap cleanup_m53b EXIT

configure_bridge() {
    docker exec "$SWITCH" sh -ec '
        ip link add br-m53b type bridge
        ip link set br-m53b up
        for dev in eth1 eth2 eth3; do
            ip link set "$dev" master br-m53b
            ip link set "$dev" up
        done'
}

write_packet_helper() {
    cat >"$PACKET_HELPER" <<'PY'
import ipaddress
import json
import os
import socket
import struct
import sys
import time


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def capture(dev, output, ready, stop):
    # ETH_P_ALL is required on a Linux bridge slave: an ETH_P_IPV6 socket
    # misses frames forwarded through the bridge on this lab kernel.
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    sock.bind((dev, 0))
    sock.settimeout(0.1)
    with open(output, "w", buffering=1) as stream:
        open(ready, "w").close()  # socket is already bound before the signal
        while not os.path.exists(stop):
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                continue
            if len(frame) < 62 or frame[12:14] != b"\x86\xdd" or frame[20] != 58:
                continue
            kind = frame[54]
            if kind not in (133, 134) or (kind == 134 and len(frame) < 70):
                continue
            stream.write(json.dumps({
                "ns": time.monotonic_ns(),
                "type": "RS" if kind == 133 else "RA",
                "src": str(ipaddress.IPv6Address(frame[22:38])),
                "dst": str(ipaddress.IPv6Address(frame[38:54])),
                "lifetime": int.from_bytes(frame[60:62], "big") if kind == 134 else None,
            }) + "\n")


def send_ra(dev, source, lifetime):
    src = ipaddress.IPv6Address(source).packed
    dst = ipaddress.IPv6Address("ff02::1").packed
    mac = bytes.fromhex(open("/sys/class/net/%s/address" % dev).read().strip().replace(":", ""))
    icmp = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0, lifetime, 0, 0)
    pseudo = src + dst + struct.pack("!I3xB", len(icmp), 58)
    icmp = icmp[:2] + struct.pack("!H", checksum(pseudo + icmp)) + icmp[4:]
    ip6 = struct.pack("!IHBB", 6 << 28, len(icmp), 58, 255) + src + dst
    frame = bytes.fromhex("333300000001") + mac + b"\x86\xdd" + ip6 + icmp
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86dd))
    sock.bind((dev, 0))
    sock.send(frame)


if sys.argv[1] == "capture":
    capture(*sys.argv[2:])
elif sys.argv[1] == "send-ra":
    send_ra(sys.argv[2], sys.argv[3], int(sys.argv[4]))
else:
    raise SystemExit("unknown command")
PY
}

capture_start() {
    rm -f "$WORK/capture.jsonl" "$WORK/capture.ready" "$WORK/capture.stop"
    docker run -d --rm --name "$CAPTURE" --network "container:$SWITCH" \
        --cap-add NET_RAW -v "$WORK:/work" --entrypoint python3 \
        quay.io/frrouting/frr:10.7.1 /work/packet.py capture eth2 \
        /work/capture.jsonl /work/capture.ready /work/capture.stop >/dev/null
    local deadline=$((SECONDS + 10))
    until [ -f "$WORK/capture.ready" ]; do
        if ((SECONDS >= deadline)) || ! docker inspect "$CAPTURE" >/dev/null 2>&1; then
            docker logs "$CAPTURE" >&2 || true
            fail "packet capture did not arm"; return 1
        fi
        sleep 0.1
    done
}

send_ra() {
    local node=$1 source=$2 lifetime=$3
    docker run --rm --network "container:$node" --cap-add NET_RAW \
        -v "$WORK:/work:ro" --entrypoint python3 quay.io/frrouting/frr:10.7.1 \
        /work/packet.py send-ra eth1 "$source" "$lifetime"
}

capture_ra_count() {
    jq -s --arg src "$LL2" '[.[] | select(.type == "RA" and .src == $src)] | length' "$WORK/capture.jsonl"
}

ra_count() {
    local source=$1 lifetime=$2
    jq -s --arg src "$source" --argjson lifetime "$lifetime" '
        [.[] | select(.type == "RA" and .src == $src and .lifetime == $lifetime)] | length' \
        "$WORK/capture.jsonl"
}

wait_ra_count() {
    local source=$1 lifetime=$2 before=$3
    for _ in $(seq 1 30); do
        if [ "$(ra_count "$source" "$lifetime")" -gt "$before" ]; then return 0; fi
        sleep 0.1
    done
    return 1
}

assert_solicited_recovery() {
    local recovery_ns=$1 quiet_count=$2
    for _ in $(seq 1 100); do
        if jq -s -e --arg mode packets --argjson recovery "$recovery_ns" --arg ll "$LL2" \
            --arg own "$LOCAL_LL2" --argjson before "$quiet_count" \
            -f "$SCRIPT_DIR/m53b-next-hop.jq" "$WORK/capture.jsonl" >/dev/null 2>&1; then
            ok "restored link sent RS; FRR replied before its unsolicited RA interval"
            return 0
        fi
        sleep 0.1
    done
    fail "no captured recovery RS followed by FRR RA before unsolicited interval"
    cat "$WORK/capture.jsonl" >&2
    return 1
}

resolve_grpc_addr

neighbors() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.NeighborService/ListNeighbors; }
received() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.RibService/ListReceivedRoutes; }
fib() { grpcurl_call "$GRPC_ADDR" rustbgpd.v1.RibService/ListFibRoutes; }
route() { docker exec "$RUSTBGPD" ip route show table "$TABLE_ID" exact "$PREFIX"; }
daemon_events() { docker exec "$RUSTBGPD" cat /tmp/m53b-rustbgpd.log | sed -n '/^{/p'; }

event_count() {
    local message=$1 interface=$2
    daemon_events | jq -s --arg message "$message" --arg interface "$interface" '
        [.[] | select(.fields.message? == $message and .fields.interface? == $interface)] | length'
}

event_count_address() {
    local message=$1 interface=$2 address=$3
    daemon_events | jq -s --arg message "$message" --arg interface "$interface" --arg address "$address" '
        [.[] | select(.fields.message? == $message and .fields.interface? == $interface
            and .fields.address? == $address)] | length'
}

own_drop_count() {
    daemon_events | jq -s --arg source "$LOCAL_LL2" '
        [.[] | select(.fields.message? == "router discovery packet dropped"
            and .fields.reason? == "own_address" and .fields.source? == $source)] | length'
}

flap_count() {
    neighbors | jq -r --arg ll "$LL2" '
        [.neighbors[]? | select(.config.interface == "eth2" and .config.address == $ll
            and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6) and .stale != true)]
        | if length == 1 then (.[0].flapCount // 0 | tonumber) else error("bound eth2 peer not Established") end'
}

wait_event() {
    local message=$1 interface=$2 address=$3 after=$4
    for _ in $(seq 1 100); do
        if daemon_events | jq -s -e --arg message "$message" --arg interface "$interface" \
            --arg address "$address" --argjson after "$after" '
            [.[] | select(.fields.message? == $message and .fields.interface? == $interface)]
            | .[$after:][] | select(.fields.address? == $address
                or .fields.source? == $address or .fields.other? == $address)' >/dev/null; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

assert_stable_two_paths() {
    neighbors | jq -e --arg one "$LL1" --arg two "$LL2" '
        [.neighbors[]? | select((.config.interface == "eth1" and .config.address == $one
            or .config.interface == "eth2" and .config.address == $two)
            and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6)
            and (.stale != true))] | length == 2' >/dev/null || return 1
    received | jq -e '[.routes[]? | select(.prefix == "198.51.100.53" and .prefixLength == 32)] | length == 2' >/dev/null || return 1
    fib | jq -e '[.routes[]? | select(.prefix == "198.51.100.53" and .prefixLength == 32)]
        | length == 1 and (.[0].nextHops | length) == 2' >/dev/null || return 1
    local text
    text=$(route) || return 1
    grep -Fq "nexthop via inet6 $LL1 dev eth1" <<<"$text" || return 1
    grep -Fq "nexthop via inet6 $LL2 dev eth2" <<<"$text" || return 1
}

dump_state() {
    neighbors >&2 || true
    received >&2 || true
    fib >&2 || true
    route >&2 || true
    for frr in "$FRR1" "$FRR2" "$FRR3"; do
        docker exec "$frr" ip -6 addr show dev eth1 >&2 || true
        docker exec "$frr" vtysh -c 'show bgp summary' >&2 || true
    done
}

link_local() {
    local node=$1 dev=$2
    docker exec "$node" ip -j -6 addr show dev "$dev" | jq -r '
        [.[] .addr_info[]? | select(.scope == "link" and (.local | startswith("fe80:"))) | .local]
        | if length == 1 then .[0] else error("expected one kernel link-local address") end'
}

assert_fabric_addresses() {
    for pair in "$RUSTBGPD eth1" "$RUSTBGPD eth2" "$RUSTBGPD eth3" "$FRR1 eth1" "$FRR2 eth1" "$FRR3 eth1"; do
        local node=${pair% *} dev=${pair#* }
        if docker exec "$node" ip -4 addr show dev "$dev" | grep -q ' inet '; then
            fail "$node $dev has an IPv4 fabric address"; return 1
        fi
        if ! docker exec "$node" ip -d link show dev "$dev" | grep -q 'addrgenmode eui64'; then
            fail "$node $dev is not generating EUI-64 link-local addresses"; return 1
        fi
        if ! docker exec "$node" ip -j -6 addr show dev "$dev" | jq -e '
            [.[].addr_info[]?] | length == 1 and .[0].scope == "link"' >/dev/null; then
            fail "$node $dev has other IPv6 fabric addresses"; return 1
        fi
        link_local "$node" "$dev" >/dev/null
    done
    LL1=$(link_local "$FRR1" eth1)
    LL2=$(link_local "$FRR2" eth1)
    LOCAL_LL=$(link_local "$RUSTBGPD" eth1)
    LOCAL_LL2=$(link_local "$RUSTBGPD" eth2)
    LL3=$(link_local "$FRR3" eth1)
    LOCAL_LL3=$(link_local "$RUSTBGPD" eth3)
    if [ "$(printf '%s\n' "$LL1" "$LL2" "$LL3" | sort -u | wc -l)" != 3 ] \
        || [ "$(printf '%s\n' "$LOCAL_LL" "$LOCAL_LL2" "$LOCAL_LL3" | sort -u | wc -l)" != 3 ]; then
        fail "parallel fabric links generated duplicate link-local addresses"; return 1
    fi
    ok "fabric uses distinct kernel EUI-64 link-local addresses and no IPv4"
}

wait_established() {
    local expected=$1
    for _ in $(seq 1 45); do
        local frr_ok=0 rust_ok=0
        if docker exec "$FRR1" vtysh -c 'show bgp summary json' \
            | jq -e '.. | objects | select(.state? == "Established" or .bgpState? == "Established")' >/dev/null 2>&1 \
            && docker exec "$FRR2" vtysh -c 'show bgp summary json' \
            | jq -e '.. | objects | select(.state? == "Established" or .bgpState? == "Established")' >/dev/null 2>&1; then
            frr_ok=1
        fi
        if neighbors | jq -e --argjson count "$expected" --arg one "$LL1" --arg two "$LL2" '
            [.neighbors[]? | select((.config.interface == "eth1" and .config.address == $one
                or .config.interface == "eth2" and .config.address == $two)
                and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6)
                and (.stale != true))] | length == $count' >/dev/null 2>&1; then
            rust_ok=1
        fi
        if [ "$frr_ok" = 1 ] && [ "$rust_ok" = 1 ]; then
            ok "FRR and rustbgpd established $expected interface-only peers"
            return 0
        fi
        sleep 2
    done
    fail "interface-only peers did not establish on both sides"
    dump_state
    return 1
}

wait_paths() {
    local expected=$1
    for _ in $(seq 1 30); do
        if received | jq -e --argjson count "$expected" '
            [.routes[]? | select(.prefix == "198.51.100.53" and .prefixLength == 32)]
            | length == $count' >/dev/null 2>&1 \
            && fib | jq -e --argjson count "$expected" '
                [.routes[]? | select(.prefix == "198.51.100.53" and .prefixLength == 32)]
                | length == 1 and (.[0].nextHops | length) == $count' >/dev/null 2>&1; then
            ok "$expected IPv4 paths received and selected in FIB"
            return 0
        fi
        sleep 1
    done
    fail "IPv4 path count did not reach $expected"
    dump_state
    return 1
}

wait_kernel_route() {
    local expected=$1 text
    for _ in $(seq 1 30); do
        text=$(route)
        if [ "$expected" = 2 ]; then
            if grep -Fq "nexthop via inet6 $LL1 dev eth1" <<<"$text" \
                && grep -Fq "nexthop via inet6 $LL2 dev eth2" <<<"$text" \
                && grep -Fq 'proto bgp' <<<"$text" \
                && grep -Fq "metric $METRIC" <<<"$text"; then
                ok "$PREFIX installed through both scoped link-local next hops"
                return 0
            fi
        elif grep -Fq "via inet6 $LL1 dev eth1" <<<"$text" \
            && ! grep -Fq 'dev eth2' <<<"$text" \
            && grep -Fq 'proto bgp' <<<"$text"; then
            ok "$PREFIX removed failed eth2 next hop"
            return 0
        fi
        sleep 1
    done
    fail "$PREFIX kernel route did not converge to $expected next hops"
    dump_state
    return 1
}

assert_outbound() {
    grpcurl_call -d "{\"prefix\":\"192.0.2.53\",\"prefix_length\":32,\"next_hop\":\"$LOCAL_LL\",\"origin\":0}" \
        "$GRPC_ADDR" rustbgpd.v1.InjectionService/AddPath >/dev/null
    for entry in "$FRR1 $LOCAL_LL" "$FRR2 $LOCAL_LL2"; do
        local frr=${entry% *} next_hop=${entry#* } found=0
        for _ in $(seq 1 30); do
            if docker exec "$frr" vtysh -c "show bgp ipv4 unicast $INJECTED_PREFIX json" \
                | jq -e --arg prefix "$INJECTED_PREFIX" --arg nh "$next_hop" \
                    -f "$SCRIPT_DIR/m53b-next-hop.jq" >/dev/null 2>&1; then
                found=1; break
            fi
            sleep 1
        done
        if [ "$found" != 1 ]; then
            fail "$frr did not receive IPv4 with next hop $next_hop"
            dump_state
            return 1
        fi
    done
    ok "both FRR peers received IPv4 with RFC 8950 link-local next hops"
}

# FRR3 sends no RAs and dials rustbgpd through a static link-local neighbor,
# so the eth3 interface-only neighbor can only be learned from that inbound
# connection (ADR-0142 secondary discovery).
eth3_established() {
    neighbors | jq -e --arg ll "$LL3" '
        [.neighbors[]? | select(.config.interface == "eth3" and .config.address == $ll
            and (.state == "SESSION_STATE_ESTABLISHED" or .state == 6) and .stale != true)]
        | length == 1' >/dev/null 2>&1
}

assert_inbound_learning() {
    local config
    config=$(docker exec "$FRR3" vtysh -c 'show running-config')
    # `ipv6 nd suppress-ra` is FRR's default and is not rendered; the absence
    # of any RA candidate on eth3 below proves FRR3 advertised nothing.
    if [[ $config != *'no bgp ipv6-auto-ra'* ]]; then
        fail "FRR3 lacks no bgp ipv6-auto-ra"; return 1
    fi
    if neighbors | jq -e '[.neighbors[]? | select(.config.interface == "eth3")] | length != 0' >/dev/null; then
        fail "eth3 neighbor was bound before FRR3 dialed"; dump_state; return 1
    fi
    docker exec "$FRR3" vtysh -c 'configure terminal' -c 'router bgp 65003' \
        -c "neighbor $LOCAL_LL3 remote-as 65001" \
        -c "neighbor $LOCAL_LL3 interface eth1" \
        -c "neighbor $LOCAL_LL3 capability extended-nexthop" \
        -c "neighbor $LOCAL_LL3 timers connect 5" \
        -c 'address-family ipv6 unicast' -c "neighbor $LOCAL_LL3 activate" >/dev/null
    local established=0
    for _ in $(seq 1 45); do
        if eth3_established \
            && docker exec "$FRR3" vtysh -c 'show bgp summary json' \
                | jq -e '.. | objects | select(.state? == "Established")' >/dev/null 2>&1 \
            && received | jq -e '[.routes[]? | select(.prefix == "198.51.100.54" and .prefixLength == 32)] | length == 1' >/dev/null 2>&1; then
            established=1; break
        fi
        sleep 2
    done
    if [ "$established" != 1 ]; then
        fail "FRR3 static link-local neighbor did not establish through inbound learning"
        dump_state; return 1
    fi
    if [ "$(event_count_address "unnumbered: peer address learned from an inbound connection" eth3 "$LL3")" -lt 1 ] \
        || [ "$(event_count "unnumbered: peer address learned" eth3)" != 0 ] \
        || [ "$(event_count "unnumbered: binding changed" eth3)" != 0 ]; then
        fail "eth3 endpoint was not learned from the inbound connection alone"
        daemon_events | jq -c 'select(.fields.interface? == "eth3")' >&2 || true
        return 1
    fi
    local text
    for _ in $(seq 1 30); do
        text=$(docker exec "$RUSTBGPD" ip route show table "$TABLE_ID" exact "$PREFIX3")
        if grep -Fq "via inet6 $LL3 dev eth3" <<<"$text"; then
            ok "FRR3 with no RAs established through inbound learning; $PREFIX3 via $LL3 dev eth3"
            return 0
        fi
        sleep 1
    done
    fail "$PREFIX3 was not installed via the inbound-learned endpoint"
    dump_state; return 1
}

configure_bridge
for pair in "$RUSTBGPD eth2" "$FRR2 eth1" "$SWITCH br-m53b" "$SWITCH eth1" "$SWITCH eth2" "$SWITCH eth3" "$ROGUE eth1"; do
    node=${pair% *}
    dev=${pair#* }
    docker exec "$node" sh -c "echo 0 > /proc/sys/net/ipv6/conf/$dev/router_solicitations"
done
write_packet_helper
capture_start
frr_ra_config=$(docker exec "$FRR2" vtysh -c 'show running-config')
if [[ $frr_ra_config != *'ipv6 nd ra-interval 900'* \
    || $frr_ra_config != *'no ipv6 nd ra-fast-retrans'* \
    || $frr_ra_config != *'ipv6 nd ra-lifetime 1800'* ]]; then
    fail "FRR2 lacks the pinned long RA cadence needed for solicited-response proof"; exit 1
fi
assert_fabric_addresses
ROGUE_LL=$(link_local "$ROGUE" eth1)
start_rustbgpd '/usr/local/bin/start-rustbgpd.sh >/tmp/m53b-rustbgpd.log 2>&1'
wait_established 2
wait_paths 2
wait_kernel_route 2
assert_outbound
assert_inbound_learning || exit 1

carrier_start=$(python3 -c 'import time; print(time.monotonic_ns())')
docker exec "$SWITCH" ip link set eth1 down
if ! docker exec "$RUSTBGPD" ip -j link show dev eth2 | jq -e '.[0].operstate == "DOWN"' >/dev/null; then
    fail "Rust eth2 did not lose carrier when its switch endpoint went down"; exit 1
fi
down=0
for _ in $(seq 1 20); do
    if neighbors | jq -e --arg mode down -f "$SCRIPT_DIR/m53b-next-hop.jq" >/dev/null 2>&1; then
        down=1
        break
    fi
    sleep 0.05
done
if [ "$down" != 1 ]; then
    fail "eth2 session did not leave Established after carrier loss"; dump_state; exit 1
fi
carrier_ns=$(( $(python3 -c 'import time; print(time.monotonic_ns())') - carrier_start ))
carrier_ms=$(( carrier_ns / 1000000 ))
if ((carrier_ns > 1000000000)); then
    fail "carrier loss did not end eth2 session within 1s (${carrier_ms}ms)"
    dump_state; exit 1
fi
ok "carrier loss ended eth2 session in ${carrier_ms}ms"
wait_paths 1
wait_kernel_route 1
if ! docker exec "$FRR2" ip -j link show dev eth1 | jq -e '.[0].operstate == "UP"' >/dev/null; then
    fail "FRR2 carrier changed during rustbgpd eth2 flap"; exit 1
fi

ra_before_quiet=$(capture_ra_count)
sleep 2
ra_before_recovery=$(capture_ra_count)
if [ "$ra_before_quiet" != "$ra_before_recovery" ]; then
    fail "FRR sent an unsolicited RA during the pre-recovery quiet window"; exit 1
fi
recovery_ns=$(python3 -c 'import time; print(time.monotonic_ns())')
learned_recovery_before=$(event_count "unnumbered: peer address learned" eth2)
docker exec "$SWITCH" ip link set eth1 up
assert_solicited_recovery "$recovery_ns" "$ra_before_recovery"
if ! wait_event "unnumbered: peer address learned" eth2 "$LL2" "$learned_recovery_before"; then
    fail "recovery RA did not yield a new learned eth2 candidate"; exit 1
fi
ok "restored-link RA relearned the FRR endpoint"
wait_established 2
wait_paths 2
wait_kernel_route 2
baseline_flaps=$(flap_count)
added_before=$(event_count "unnumbered: bound peer added" eth2)
ending_before=$(event_count "unnumbered: ending the bound session" eth2)
binding_before=$(event_count "unnumbered: binding changed" eth2)
learned_before=$(event_count "unnumbered: peer address learned" eth2)
conflicts_before=$(event_count "unnumbered: a second router advertises on an interface-only link" eth2)
own_before=$(own_drop_count)
own_ra_before=$(ra_count "$LOCAL_LL2" 60)
send_ra "$ROGUE" "$LOCAL_LL2" 60
if ! wait_ra_count "$LOCAL_LL2" 60 "$own_ra_before"; then
    fail "spoofed own-source RA was not seen on eth2 segment"; exit 1
fi
for _ in $(seq 1 30); do
    if [ "$(own_drop_count)" -gt "$own_before" ]; then break; fi
    sleep 0.1
done
if ! daemon_events | jq -s -e --arg mode own --arg source "$LOCAL_LL2" \
    --argjson drop_before "$own_before" --argjson learned_before "$learned_before" \
    --argjson conflict_before "$conflicts_before" -f "$SCRIPT_DIR/m53b-next-hop.jq" >/dev/null; then
    fail "own-source RA caused learning/conflict or lacked own_address drop"; exit 1
fi
assert_stable_two_paths || { fail "own-source RA changed BGP/FIB paths"; exit 1; }
ok "received own-source RA was dropped without candidate or conflict"

conflict_before=$(event_count "unnumbered: a second router advertises on an interface-only link" eth2)
exact_conflict_before=$(daemon_events | jq -s --arg bound "$LL2" --arg other "$ROGUE_LL" '
    [.[] | select(.fields.message? == "unnumbered: a second router advertises on an interface-only link"
        and .fields.interface? == "eth2" and .fields.bound? == $bound and .fields.other? == $other)] | length')
rogue_learned_before=$(event_count_address "unnumbered: peer address learned" eth2 "$ROGUE_LL")
rogue_expired_before=$(event_count_address "unnumbered: peer address expired" eth2 "$ROGUE_LL")
rogue_ra_before=$(ra_count "$ROGUE_LL" 60)
send_ra "$ROGUE" "$ROGUE_LL" 60
if ! wait_ra_count "$ROGUE_LL" 60 "$rogue_ra_before" \
    || ! wait_event "unnumbered: peer address learned" eth2 "$ROGUE_LL" "$learned_before" \
    || ! wait_event "unnumbered: a second router advertises on an interface-only link" eth2 "$ROGUE_LL" "$conflict_before"; then
    fail "third-source RA did not produce a conflict on bound eth2"; exit 1
fi
rogue_ra_ns=$(jq -s --arg source "$ROGUE_LL" '
    [.[] | select(.type == "RA" and .src == $source and .lifetime == 60)] | last | .ns' \
    "$WORK/capture.jsonl")
if [ "$(event_count_address "unnumbered: peer address learned" eth2 "$ROGUE_LL")" -le "$rogue_learned_before" ]; then
    fail "third RA source was not learned as a candidate"; exit 1
fi
if ! daemon_events | jq -s -e --arg mode conflict --arg bound "$LL2" --arg other "$ROGUE_LL" \
    --argjson learned_before "$rogue_learned_before" --argjson conflict_before "$exact_conflict_before" \
    -f "$SCRIPT_DIR/m53b-next-hop.jq" >/dev/null; then
    fail "conflict log did not identify bound and third RA sources"; exit 1
fi
assert_stable_two_paths || { fail "third-source conflict changed BGP/FIB paths"; exit 1; }
[ "$(flap_count)" = "$baseline_flaps" ] || { fail "third-source conflict flapped eth2"; exit 1; }
ok "third RA source reported conflict without peer flap or path change"

# A regular FRR RA after the lifetime-2 packet would refresh this candidate;
# the capture count invalidates that case.
regular_before=$(ra_count "$LL2" 1800)
expired_before=$(event_count_address "unnumbered: peer address expired" eth2 "$LL2")
expired_total_before=$(event_count "unnumbered: peer address expired" eth2)
short_before=$(ra_count "$LL2" 2)
send_ra "$FRR2" "$LL2" 2
if ! wait_ra_count "$LL2" 2 "$short_before" \
    || ! wait_event "unnumbered: peer address expired" eth2 "$LL2" "$expired_total_before"; then
    fail "bound candidate did not expire after a captured lifetime-2 RA"; exit 1
fi
if [ "$(ra_count "$LL2" 1800)" != "$regular_before" ] \
    || (( $(python3 -c 'import time; print(time.monotonic_ns())') - rogue_ra_ns >= 60000000000 )) \
    || ! daemon_events | jq -s -e --arg mode expiry --arg bound "$LL2" --arg other "$ROGUE_LL" \
        --argjson expired_before "$expired_before" --argjson other_expired_before "$rogue_expired_before" \
        --argjson binding_before "$binding_before" --argjson added_before "$added_before" \
        --argjson ending_before "$ending_before" -f "$SCRIPT_DIR/m53b-next-hop.jq" >/dev/null; then
    fail "unsolicited RA or expired third candidate invalidated bound expiry"; exit 1
fi
assert_stable_two_paths || { fail "candidate expiry changed established BGP/FIB paths"; exit 1; }
if [ "$(flap_count)" != "$baseline_flaps" ] \
    || [ "$(event_count "unnumbered: bound peer added" eth2)" != "$added_before" ] \
    || [ "$(event_count "unnumbered: ending the bound session" eth2)" != "$ending_before" ] \
    || [ "$(event_count "unnumbered: binding changed" eth2)" != "$binding_before" ]; then
    fail "third source or candidate expiry replaced or flapped the bound session"; exit 1
fi
ok "bound RA candidate expired while Established binding and FIB stayed healthy"
print_summary
