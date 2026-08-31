#!/usr/bin/env bash
# Disposable proof for the remaining RFC 8365 local-bias softswitch seam.
#
# A tiny TC direct-action eBPF classifier runs on the local VTEP's underlay
# ingress, before VXLAN decapsulation. It recognizes only this lab's fixed
# IPv4/UDP/4789/VNI-100 packet shape, marks ES-peer BUM plus one fixed
# unknown-unicast destination, and leaves all other traffic unchanged. A
# post-decap fw counter proves mark survival; a CE-egress fw action drops the
# same mark. This is a finding harness, not production packet parsing.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPILER_IMAGE="docker.io/silkeh/clang:20-bookworm@sha256:203abb1df1563b3bd19cd596d67112e0c0ad380a428810dc9a61c85e555b1323"
TEST_IMAGE="${TEST_IMAGE:-rustbgpd-netns-tests:latest}"

outer_cleanup() {
    local rc=$?
    trap - EXIT INT TERM
    if [ -n "${COMPILER_CONTAINER:-}" ]; then
        docker rm -f "$COMPILER_CONTAINER" >/dev/null 2>&1 || true
    fi
    if [ -n "${TEST_CONTAINER:-}" ]; then
        docker rm -f "$TEST_CONTAINER" >/dev/null 2>&1 || true
    fi
    if [ -n "${BUILD_DIR:-}" ]; then
        rm -rf "$BUILD_DIR"
    fi
    exit "$rc"
}

run_outer() {
    command -v docker >/dev/null 2>&1 || {
        echo "SETUP-ERROR: docker is required" >&2
        return 2
    }
    docker image inspect "$TEST_IMAGE" >/dev/null 2>&1 || {
        echo "SETUP-ERROR: missing existing test image $TEST_IMAGE" >&2
        return 2
    }

    BUILD_DIR="$(mktemp -d /tmp/rustbgpd-localbias-mark.XXXXXX)"
    COMPILER_CONTAINER="rustbgpd-localbias-compile-$$"
    TEST_CONTAINER="rustbgpd-localbias-test-$$"
    trap outer_cleanup EXIT INT TERM

    echo "source_sha=$(git -C "$SCRIPT_DIR/../../../.." rev-parse HEAD)"
    echo "host_kernel=$(uname -r)"
    echo "compiler_image=$COMPILER_IMAGE"
    TEST_IMAGE_ID="$(docker image inspect "$TEST_IMAGE" --format '{{.Id}}')"
    echo "test_image=$TEST_IMAGE"
    echo "test_image_id=$TEST_IMAGE_ID"

    docker run --rm --name "$COMPILER_CONTAINER" \
        -v "$SCRIPT_DIR:/source:ro" \
        -v "$BUILD_DIR:/output" \
        -w /source \
        "$COMPILER_IMAGE" \
        sh -ceu '
            printf "compiler_version="
            clang --version | sed -n "1p"
            clang -O2 -g -target bpf -Wall -Werror \
                -c netns-localbias-underlay-mark-spike.bpf.c \
                -o /output/localbias-underlay-mark.bpf.o
        '
    COMPILER_CONTAINER=""

    echo "compiler_image_id=$(docker image inspect "$COMPILER_IMAGE" --format '{{.Id}}')"
    echo "object_sha256=$(sha256sum "$BUILD_DIR/localbias-underlay-mark.bpf.o" | awk '{print $1}')"

    local test_rc=0
    docker run --rm --name "$TEST_CONTAINER" \
        --cap-add=NET_ADMIN \
        --cap-add=SYS_ADMIN \
        --security-opt apparmor=unconfined \
        -v "$SCRIPT_DIR:/lab:ro" \
        -v "$BUILD_DIR:/object:ro" \
        "$TEST_IMAGE_ID" \
        bash /lab/netns-localbias-underlay-mark-spike.sh \
            --inside /object/localbias-underlay-mark.bpf.o || test_rc=$?
    TEST_CONTAINER=""

    for name in "rustbgpd-localbias-compile-$$" "rustbgpd-localbias-test-$$"; do
        if docker ps -a --format '{{.Names}}' | grep -Fxq "$name"; then
            echo "CLEANUP-ERROR: container remains: $name" >&2
            return 2
        fi
    done
    echo "cleanup_containers=absent"

    trap - EXIT INT TERM
    rm -rf "$BUILD_DIR"
    BUILD_DIR=""
    return "$test_rc"
}

if [ "${1:-}" != "--inside" ]; then
    run_outer
    exit $?
fi

BPF_OBJECT="${2:-}"
[ -r "$BPF_OBJECT" ] || {
    echo "SETUP-ERROR: unreadable BPF object: $BPF_OBJECT" >&2
    exit 2
}

SFX=$$
ULNS="lbmark-ul-$SFX"
LOC="lbmark-loc-$SFX"
ESP="lbmark-esp-$SFX"
NES="lbmark-nes-$SFX"
VNI=100
DPORT=4789
MARK=0x40000000
MARK_MASK=0x40000000
PARSER_MARK=0x20000000
PARSER_MARK_MASK=0x20000000
LOC_UL=10.255.0.1
ESP_UL=10.255.0.2
NES_UL=10.255.0.3
OV=10.200.0
PINGS=5
KNOWN_MAC=02:00:00:00:00:aa
UNKNOWN_MAC=02:00:00:00:00:50
MCAST_GRP=239.1.1.1
PASS=0
FAIL=0

ulx() { ip netns exec "$ULNS" "$@"; }
locx() { ip netns exec "$LOC" "$@"; }
espx() { ip netns exec "$ESP" "$@"; }
nesx() { ip netns exec "$NES" "$@"; }

cleanup_namespaces() {
    local namespace
    for namespace in "$ULNS" "$LOC" "$ESP" "$NES"; do
        ip netns delete "$namespace" >/dev/null 2>&1 || true
    done
}

finish() {
    local rc=$?
    local leftovers
    trap - EXIT INT TERM
    cleanup_namespaces
    leftovers="$(ip netns list | awk '{print $1}' | grep '^lbmark-' || true)"
    if [ -n "$leftovers" ]; then
        echo "CLEANUP-ERROR: matching namespaces remain: $leftovers" >&2
        rc=2
    else
        echo "cleanup_namespaces=absent"
    fi
    exit "$rc"
}
trap finish EXIT INT TERM

die() {
    echo "SETUP-ERROR: $*" >&2
    exit 2
}
pass() {
    echo "PASS [$1]: ${2:-}"
    PASS=$((PASS + 1))
}
fail() {
    echo "FAIL [$1]: ${2:-}"
    FAIL=$((FAIL + 1))
}

[ "$(id -u)" -eq 0 ] || die "requires container root"
for tool in ip bridge tc ping sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || die "missing tool '$tool'"
done

echo "test_kernel=$(uname -r)"
echo "test_iproute2=$(ip -Version 2>&1)"
echo "bpf_object_sha256=$(sha256sum "$BPF_OBJECT" | awk '{print $1}')"

rx() {
    locx cat /sys/class/net/ce-tap/statistics/rx_packets
}

packet_counter() {
    local namespace=$1
    local device=$2
    local direction=$3
    local preference=$4
    ip netns exec "$namespace" tc -s filter show dev "$device" "$direction" pref "$preference" 2>/dev/null |
        awk '/Sent [0-9]+ bytes [0-9]+ pkt/ { for (i = 1; i <= NF; i++) if ($i == "pkt") value = $(i - 1) } END { print value + 0 }'
}

assert_forwarded() {
    local label=$1
    local delta=$2
    if [ "$delta" -gt 0 ]; then
        pass "$label" "CE rx delta=$delta"
    else
        fail "$label" "expected forwarding, CE rx delta=0"
    fi
}

assert_dropped() {
    local label=$1
    local baseline=$2
    local delta=$3
    if [ "$((delta * 5))" -lt "$baseline" ]; then
        pass "$label" "CE rx delta=$delta (baseline=$baseline)"
    else
        fail "$label" "expected drop, CE rx delta=$delta (baseline=$baseline)"
    fi
}

assert_zero() {
    local label=$1
    local delta=$2
    if [ "$delta" -eq 0 ]; then
        pass "$label" "counter delta=0"
    else
        fail "$label" "expected counter delta=0, got $delta"
    fi
}

add_leg() {
    local child_namespace=$1
    local leg=$2
    local address=$3
    ip -n "$ULNS" link add "ul-$leg" type veth peer name "$leg"
    ip -n "$ULNS" link set "$leg" netns "$child_namespace"
    ip -n "$ULNS" link set "ul-$leg" master ulbr
    ip -n "$ULNS" link set "ul-$leg" up
    ip -n "$child_namespace" link set "$leg" up
    ip -n "$child_namespace" address add "$address/24" dev "$leg"
}

make_remote() {
    local namespace=$1
    local local_ip=$2
    local overlay_ip=$3
    local leg=$4
    ip netns exec "$namespace" ip link add brm type bridge
    ip netns exec "$namespace" ip link add vx type vxlan id "$VNI" \
        dstport "$DPORT" local "$local_ip" dev "$leg" nolearning
    ip netns exec "$namespace" ip link add inj type veth peer name injt
    ip netns exec "$namespace" ip link set vx master brm
    ip netns exec "$namespace" ip link set inj master brm
    local device
    for device in brm vx inj injt; do
        ip netns exec "$namespace" ip link set "$device" up
    done
    ip netns exec "$namespace" ip address add "$overlay_ip/24" dev injt
    ip netns exec "$namespace" bridge fdb append 00:00:00:00:00:00 \
        dev vx dst "$LOC_UL"
}

gen_broadcast() {
    ip netns exec "$1" ping -b -W1 -c"$PINGS" -I injt "$OV.255" \
        >/dev/null 2>&1 || true
}

gen_multicast() {
    ip netns exec "$1" ping -W1 -c"$PINGS" -I injt "$MCAST_GRP" \
        >/dev/null 2>&1 || true
}

gen_unicast() {
    local namespace=$1
    local destination_mac=$2
    local destination_ip=$3
    ip netns exec "$namespace" ip neigh replace "$destination_ip" \
        lladdr "$destination_mac" dev injt
    ip netns exec "$namespace" bridge fdb append "$destination_mac" \
        dev vx dst "$LOC_UL" >/dev/null 2>&1 || true
    ip netns exec "$namespace" ping -W1 -c"$PINGS" -I injt "$destination_ip" \
        >/dev/null 2>&1 || true
}

measure_rx() {
    local generator=$1
    shift
    local before after
    before="$(rx)"
    "$generator" "$@"
    sleep 0.3
    after="$(rx)"
    echo $((after - before))
}

run_candidate_probe() {
    local label=$1
    local expectation=$2
    local baseline=$3
    local generator=$4
    shift 4
    local parser_before mark_before drop_before ce_before
    local parser_after mark_after drop_after ce_after
    local parser_delta mark_delta drop_delta ce_delta

    parser_before="$(packet_counter "$LOC" loc-leg ingress 2)"
    mark_before="$(packet_counter "$LOC" vxlan100 ingress 1)"
    drop_before="$(packet_counter "$LOC" ce-br egress 1)"
    ce_before="$(rx)"
    "$generator" "$@"
    sleep 0.3
    parser_after="$(packet_counter "$LOC" loc-leg ingress 2)"
    mark_after="$(packet_counter "$LOC" vxlan100 ingress 1)"
    drop_after="$(packet_counter "$LOC" ce-br egress 1)"
    ce_after="$(rx)"

    parser_delta=$((parser_after - parser_before))
    mark_delta=$((mark_after - mark_before))
    drop_delta=$((drop_after - drop_before))
    ce_delta=$((ce_after - ce_before))
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$label" "$parser_delta" "$mark_delta" "$drop_delta" "$ce_delta"

    if [ "$parser_delta" -gt 0 ]; then
        pass "$label parser" "$parser_delta packet(s) traversed loc-leg ingress"
    else
        fail "$label parser" "classifier execution counter did not advance"
    fi

    if [ "$expectation" = drop ]; then
        if [ "$mark_delta" -gt 0 ]; then
            pass "$label mark" "$mark_delta packet(s) carried the reserved bit after decap"
        else
            fail "$label mark" "post-decap reserved-bit counter did not advance"
        fi
        if [ "$drop_delta" -gt 0 ]; then
            pass "$label drop" "$drop_delta packet(s) reached the CE-egress drop"
        else
            fail "$label drop" "CE-egress drop counter did not advance"
        fi
        assert_dropped "$label delivery" "$baseline" "$ce_delta"
    else
        assert_zero "$label mark" "$mark_delta"
        assert_zero "$label drop" "$drop_delta"
        assert_forwarded "$label delivery" "$ce_delta"
    fi
}

run_underlay_control() {
    local parser_before mark_before drop_before
    local parser_after mark_after drop_after
    local parser_delta mark_delta drop_delta
    parser_before="$(packet_counter "$LOC" loc-leg ingress 2)"
    mark_before="$(packet_counter "$LOC" vxlan100 ingress 1)"
    drop_before="$(packet_counter "$LOC" ce-br egress 1)"
    if ! espx ping -q -W1 -c1 "$LOC_UL" >/dev/null 2>&1; then
        fail "non-VXLAN underlay delivery" "ordinary underlay ping failed"
    else
        pass "non-VXLAN underlay delivery" "ES peer reached the local underlay address"
    fi
    sleep 0.1
    parser_after="$(packet_counter "$LOC" loc-leg ingress 2)"
    mark_after="$(packet_counter "$LOC" vxlan100 ingress 1)"
    drop_after="$(packet_counter "$LOC" ce-br egress 1)"
    parser_delta=$((parser_after - parser_before))
    mark_delta=$((mark_after - mark_before))
    drop_delta=$((drop_after - drop_before))
    printf '%s\t%s\t%s\t%s\t%s\n' \
        non_vxlan_underlay "$parser_delta" "$mark_delta" "$drop_delta" n/a
    if [ "$parser_delta" -gt 0 ]; then
        pass "non-VXLAN underlay parser" "$parser_delta packet(s) traversed loc-leg ingress"
    else
        fail "non-VXLAN underlay parser" "classifier execution counter did not advance"
    fi
    assert_zero "non-VXLAN underlay mark" "$mark_delta"
    assert_zero "non-VXLAN underlay drop" "$drop_delta"
}

# Reuse the existing three-VTEP topology.
for namespace in "$ULNS" "$LOC" "$ESP" "$NES"; do
    ip netns add "$namespace"
    ip netns exec "$namespace" ip link set lo up
done
ulx ip link add ulbr type bridge
ulx ip link set ulbr up
add_leg "$LOC" loc-leg "$LOC_UL"
add_leg "$ESP" esp-leg "$ESP_UL"
add_leg "$NES" nes-leg "$NES_UL"

for namespace in "$LOC" "$ESP" "$NES"; do
    ip netns exec "$namespace" sysctl -wq net.ipv4.icmp_echo_ignore_broadcasts=0 \
        2>/dev/null || true
    ip netns exec "$namespace" sysctl -wq net.ipv4.ping_group_range='0 65535' \
        2>/dev/null || true
done

locx ip link add br100 type bridge
locx ip link add vxlan100 type vxlan id "$VNI" dstport "$DPORT" \
    local "$LOC_UL" dev loc-leg nolearning || die "kernel rejected VXLAN creation"
if locx ip -d link show dev vxlan100 | grep -qw gbp; then
    die "fixture unexpectedly enabled VXLAN GBP, which can overwrite skb marks"
fi
echo "vxlan_gbp=off"
locx ip link add ce-br type veth peer name ce-tap
locx ip link set vxlan100 master br100
locx ip link set ce-br master br100
for device in br100 vxlan100 ce-br ce-tap; do
    locx ip link set "$device" up
done
locx ip address add "$OV.1/24" dev ce-tap

make_remote "$ESP" "$ESP_UL" "$OV.2" esp-leg
make_remote "$NES" "$NES_UL" "$OV.3" nes-leg
locx bridge fdb replace "$KNOWN_MAC" dev ce-br master static
sleep 0.4

# Baseline: both source classes and both unicast classes reach the CE.
BASE_ES_BROADCAST="$(measure_rx gen_broadcast "$ESP")"
assert_forwarded "baseline ES-peer broadcast" "$BASE_ES_BROADCAST"
BASE_ES_MULTICAST="$(measure_rx gen_multicast "$ESP")"
assert_forwarded "baseline ES-peer multicast" "$BASE_ES_MULTICAST"
BASE_NON_ES_BROADCAST="$(measure_rx gen_broadcast "$NES")"
assert_forwarded "baseline non-ES broadcast" "$BASE_NON_ES_BROADCAST"
BASE_ES_UNKNOWN="$(measure_rx gen_unicast "$ESP" "$UNKNOWN_MAC" "$OV.50")"
assert_forwarded "baseline ES-peer fixed unknown unicast" "$BASE_ES_UNKNOWN"
BASE_ES_KNOWN="$(measure_rx gen_unicast "$ESP" "$KNOWN_MAC" "$OV.60")"
assert_forwarded "baseline ES-peer fixed known unicast" "$BASE_ES_KNOWN"
# Candidate: classify before decap, observe the mark after decap, then drop it.
locx tc qdisc add dev loc-leg clsact
locx tc filter add dev loc-leg ingress pref 1 bpf da obj "$BPF_OBJECT" sec classifier \
    || {
        echo "FINDING=NEGATIVE_BOUNDED_LOADER"
        echo "MECHANISM-ERROR: TC BPF classifier did not load with the bounded capability set" >&2
        exit 1
    }
locx tc filter add dev loc-leg ingress pref 2 protocol all \
    handle "$PARSER_MARK/$PARSER_MARK_MASK" fw \
    action skbedit mark "0/$PARSER_MARK_MASK" pipe \
    action pass \
    || die "parser diagnostic observer did not install"
locx tc qdisc add dev vxlan100 clsact
locx tc filter add dev vxlan100 ingress pref 1 protocol all \
    handle "$MARK/$MARK_MASK" fw \
    action pass || die "post-decap mark observer did not install"
locx tc qdisc add dev ce-br clsact
locx tc filter add dev ce-br egress pref 1 protocol all \
    handle "$MARK/$MARK_MASK" fw \
    action drop || die "CE-egress mark drop did not install"

echo $'probe\tparser_delta\tpost_decap_mark_delta\tce_drop_delta\tce_rx_delta'
run_candidate_probe es_peer_broadcast drop "$BASE_ES_BROADCAST" gen_broadcast "$ESP"
run_candidate_probe es_peer_multicast drop "$BASE_ES_MULTICAST" gen_multicast "$ESP"
run_candidate_probe es_peer_fixed_unknown drop "$BASE_ES_UNKNOWN" \
    gen_unicast "$ESP" "$UNKNOWN_MAC" "$OV.51"
run_candidate_probe es_peer_fixed_known pass "$BASE_ES_KNOWN" \
    gen_unicast "$ESP" "$KNOWN_MAC" "$OV.60"
run_candidate_probe non_es_broadcast pass "$BASE_NON_ES_BROADCAST" \
    gen_broadcast "$NES"
run_candidate_probe non_es_fixed_unknown pass "$BASE_ES_UNKNOWN" \
    gen_unicast "$NES" "$UNKNOWN_MAC" "$OV.52"
run_underlay_control

echo "--- underlay classifier stats ---"
locx tc -s filter show dev loc-leg ingress pref 1
echo "--- parser diagnostic stats ---"
locx tc -s filter show dev loc-leg ingress pref 2
echo "--- post-decap mark stats ---"
locx tc -s filter show dev vxlan100 ingress pref 1
echo "--- CE-egress drop stats ---"
locx tc -s filter show dev ce-br egress pref 1

# Removal is part of the finding: no filter state may be required for recovery.
locx tc filter del dev loc-leg ingress pref 1
locx tc filter del dev loc-leg ingress pref 2
locx tc filter del dev vxlan100 ingress pref 1
locx tc filter del dev ce-br egress pref 1
RESTORED_ES="$(measure_rx gen_broadcast "$ESP")"
assert_forwarded "classifier removal restores ES-peer baseline" "$RESTORED_ES"
RESTORED_NON_ES="$(measure_rx gen_broadcast "$NES")"
assert_forwarded "classifier removal restores non-ES baseline" "$RESTORED_NON_ES"

echo
echo "=== underlay-mark local-bias spike: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -ne 0 ]; then
    echo "FINDING=NEGATIVE"
    exit 1
fi
echo "FINDING=POSITIVE_CURRENT_KERNEL_ONLY"
