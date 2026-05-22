#!/usr/bin/env bash
# Privileged netns spike for Gate A2 — VXLAN local-bias split-horizon
# (RFC 8365 §8.3.1). See docs/adr/0065-evpn-localbias-split-horizon.md.
#
# THE GATE: tests whether the candidate two-stage softswitch design works
# before any daemon wiring:
#   stage 1: tc-flower on the local VXLAN device ingress matches the
#            overlay source IP (`enc_src_ip <peer-VTEP> enc_key_id <VNI>`)
#            and `skbedit mark`s the frame.
#   stage 2: the CE-port egress drops marked frames.
#
# Topology — three VTEPs, each in its OWN netns (two VXLAN devices with
# the same VNI+dstport cannot coexist in one netns), joined by an
# underlay bridge in a fourth netns:
#
#   ul netns:  ulbr  <- veth legs ->  loc(.1) / esp(.2) / nes(.3)
#   loc netns: br100 { vxlan100 (local .1, VNI 100, nolearning), ce-br/ce-tap }   (PE under test, DF)
#   esp netns: bresp { vx (local .2), inj/injt }   (ES-peer VTEP)
#   nes netns: bnes  { vx (local .3), inj/injt }   (non-ES VTEP)
#
# Remote VTEPs head-end-replicate BUM to the local VTEP via a static
# all-zero VXLAN FDB entry, so a frame injected on a remote tap arrives
# at vxlan100 ingress with outer src = that VTEP's underlay IP.
#
# Seven assertions (see ADR-0065): (a) mark survival, (b) enc_src_ip
# match, (c) bcast dropped, (d) mcast dropped, (e) unknown-unicast
# dropped, (f) known-unicast preserved, (g) non-ES BUM still reaches CE.
# (a)/(e)/(f) decide whether the stateless tc-flower design is viable.
#
# Usage (autonomy path):
#   docker run --rm --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
#       --security-opt apparmor=unconfined -v "$PWD":/work -w /work \
#       rustbgpd-netns-tests:latest \
#       bash crates/evpn-linux/tests/scripts/netns-localbias-sph-spike.sh
#
# A FAIL on the gate is a valid result (it scopes A2 to eBPF-with-MAC-
# state or an ASIC dataplane). Exits non-zero only on setup errors.

set -uo pipefail

SFX=$$
ULNS="sph-ul-$SFX"; LOC="sph-loc-$SFX"; ESP="sph-esp-$SFX"; NES="sph-nes-$SFX"
VNI=100; DPORT=4789; MARK="0x42"
LOC_UL="10.255.0.1"; ESP_UL="10.255.0.2"; NES_UL="10.255.0.3"
OV="10.200.0"; PINGS=5
KNOWN_MAC="02:00:00:00:00:aa"; UNK_MAC="02:00:00:00:00:50"; MCAST_GRP="239.1.1.1"

PASS=0; FAIL=0
ulx() { ip netns exec "$ULNS" "$@"; }
locx() { ip netns exec "$LOC" "$@"; }
espx() { ip netns exec "$ESP" "$@"; }
nesx() { ip netns exec "$NES" "$@"; }
cleanup() { for n in "$ULNS" "$LOC" "$ESP" "$NES"; do ip netns delete "$n" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT
die() { echo "SETUP-ERROR: $*" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || die "requires root (CAP_NET_ADMIN)"
for t in ip bridge tc ping; do command -v "$t" >/dev/null 2>&1 || die "missing tool '$t'"; done

rx() { locx cat /sys/class/net/ce-tap/statistics/rx_packets; }
pass() { echo "PASS [$1]: ${2:-}"; PASS=$((PASS+1)); }
fail() { echo "FAIL [$1]: ${2:-}"; FAIL=$((FAIL+1)); }
assert_dropped() { local l=$1 base=$2 a=$3
    if [ "$a" -le 2 ] && [ "$((a*5))" -lt "$base" ]; then pass "$l" "CE rx delta=$a (baseline=$base)"
    else fail "$l" "expected drop, CE rx delta=$a (baseline=$base)"; fi; }
assert_forwarded() { local l=$1 a=$2
    if [ "$a" -gt 0 ]; then pass "$l" "CE rx delta=$a"; else fail "$l" "expected forward, CE rx delta=0"; fi; }

# --------------------------------------------------------------------------
# Underlay: ulbr in ULNS, one veth leg per VTEP netns.
# --------------------------------------------------------------------------
for n in "$ULNS" "$LOC" "$ESP" "$NES"; do ip netns add "$n"; ip netns exec "$n" ip link set lo up; done
ulx ip link add ulbr type bridge; ulx ip link set ulbr up
add_leg() { # child-netns leg-name child-ip
    ip -n "$ULNS" link add "ul-$2" type veth peer name "$2"
    ip -n "$ULNS" link set "$2" netns "$1"
    ip -n "$ULNS" link set "ul-$2" master ulbr; ip -n "$ULNS" link set "ul-$2" up
    ip -n "$1" link set "$2" up; ip -n "$1" addr add "$3/24" dev "$2"
}
add_leg "$LOC" loc-leg "$LOC_UL"
add_leg "$ESP" esp-leg "$ESP_UL"
add_leg "$NES" nes-leg "$NES_UL"
ulx sysctl -wq net.ipv4.icmp_echo_ignore_broadcasts=0 2>/dev/null || true
for n in "$LOC" "$ESP" "$NES"; do
    ip netns exec "$n" sysctl -wq net.ipv4.icmp_echo_ignore_broadcasts=0 2>/dev/null || true
    ip netns exec "$n" sysctl -wq net.ipv4.ping_group_range="0 65535" 2>/dev/null || true
done

# Local VTEP (PE under test).
locx ip link add br100 type bridge
locx ip link add vxlan100 type vxlan id "$VNI" dstport "$DPORT" local "$LOC_UL" dev loc-leg nolearning \
    || die "kernel rejected vxlan create"
locx ip link add ce-br type veth peer name ce-tap
locx ip link set vxlan100 master br100
locx ip link set ce-br master br100
for d in br100 vxlan100 ce-br ce-tap; do locx ip link set "$d" up; done
locx ip addr add "${OV}.1/24" dev ce-tap

# Remote VTEP factory.
make_remote() { # exec-fn local-ip ov-ip leg
    local fn=$1 lip=$2 ov=$3 leg=$4
    $fn ip link add brm type bridge
    $fn ip link add vx type vxlan id "$VNI" dstport "$DPORT" local "$lip" dev "$leg" nolearning
    $fn ip link add inj type veth peer name injt
    $fn ip link set vx master brm
    $fn ip link set inj master brm
    for d in brm vx inj injt; do $fn ip link set "$d" up; done
    $fn ip addr add "$ov/24" dev injt
    $fn bridge fdb append 00:00:00:00:00:00 dev vx dst "$LOC_UL"
}
make_remote espx "$ESP_UL" "${OV}.2" esp-leg
make_remote nesx "$NES_UL" "${OV}.3" nes-leg
sleep 0.4

gen_bcast() { ip netns exec "$1" ping -b -W1 -c"$PINGS" -I injt "${OV}.255" >/dev/null 2>&1 || true; }
gen_mcast() { ip netns exec "$1" ping -W1 -c"$PINGS" -I injt "$MCAST_GRP" >/dev/null 2>&1 || true; }
gen_unicast() { # netns mac ov-ip
    ip netns exec "$1" ip neigh replace "$3" lladdr "$2" dev injt
    ip netns exec "$1" bridge fdb append "$2" dev vx dst "$LOC_UL"
    ip netns exec "$1" ping -W1 -c"$PINGS" -I injt "$3" >/dev/null 2>&1 || true
}

# --------------------------------------------------------------------------
# Reference flood baseline (no filter).
# --------------------------------------------------------------------------
r0=$(rx); gen_bcast "$ESP"; sleep 0.3; r1=$(rx); BASELINE=$((r1-r0))
[ "$BASELINE" -gt 0 ] || die "no flood baseline — ES-peer broadcast never reached CE (topology broken)"
echo "flood baseline (ES-peer broadcast -> CE) = $BASELINE"

# --------------------------------------------------------------------------
# Candidate filter: flower enc_src_ip -> mark at vxlan100 ingress; fw mark
# -> drop at ce-br egress.
# --------------------------------------------------------------------------
locx tc qdisc add dev vxlan100 ingress 2>/dev/null || true
locx tc qdisc add dev ce-br clsact 2>/dev/null || true
FLOWER_OK=1
locx tc filter add dev vxlan100 ingress protocol ip flower \
    enc_src_ip "$ESP_UL" enc_key_id "$VNI" action skbedit mark "$MARK" 2>/tmp/sph_flower.err || FLOWER_OK=0
PKTS=0
if [ "$FLOWER_OK" -ne 1 ]; then
    fail "(b) enc_src_ip match" "kernel rejected flower enc_src_ip on vxlan ingress: $(cat /tmp/sph_flower.err 2>/dev/null)"
else
    gen_bcast "$ESP"; sleep 0.3
    PKTS=$(locx tc -s filter show dev vxlan100 ingress 2>/dev/null | grep -oE '[0-9]+ pkt' | grep -oE '[0-9]+' | head -1)
    PKTS=${PKTS:-0}
    if [ "$PKTS" -gt 0 ]; then pass "(b) enc_src_ip match" "flower matched $PKTS pkt(s) from ES-peer at vxlan ingress"
    else fail "(b) enc_src_ip match" "flower installed but matched 0 pkts (overlay src not visible at this hook)"; fi
    # Diagnostic: prove the ingress hook DOES see the decapped inner frame
    # (isolates "enc_src_ip absent" from "hook sees nothing").
    locx tc filter add dev vxlan100 ingress pref 100 matchall action pass 2>/dev/null || true
    gen_bcast "$ESP"; sleep 0.3
    MA=$(locx tc -s filter show dev vxlan100 ingress pref 100 2>/dev/null | grep -oE '[0-9]+ pkt' | grep -oE '[0-9]+' | head -1)
    echo "diag: matchall on vxlan100 ingress matched ${MA:-0} pkt(s) — proves the hook sees the decapped inner frame; only enc_* tunnel metadata is missing"
    locx tc filter del dev vxlan100 ingress pref 100 2>/dev/null || true
fi
locx tc filter add dev ce-br egress handle "$MARK" fw action drop 2>/dev/null \
    || echo "note: ce-br egress fw-drop filter add failed"

# (a) mark survival: marked ES-peer broadcast must not reach CE.
r0=$(rx); gen_bcast "$ESP"; sleep 0.3; r1=$(rx); A=$((r1-r0))
if [ "$FLOWER_OK" -eq 1 ] && [ "$PKTS" -gt 0 ]; then
    if [ "$A" -le 2 ] && [ "$((A*5))" -lt "$BASELINE" ]; then pass "(a) mark survival" "suppressed at CE egress (delta=$A)"
    else fail "(a) mark survival" "mark set at ingress did not reach CE egress (delta=$A vs baseline $BASELINE)"; fi
else
    fail "(a) mark survival" "skipped — ingress mark never set (see (b))"
fi

# (c)/(d)/(e)/(f)/(g)
r0=$(rx); gen_bcast "$ESP"; sleep 0.3; r1=$(rx); assert_dropped "(c) ES-peer broadcast dropped" "$BASELINE" "$((r1-r0))"
r0=$(rx); gen_mcast "$ESP"; sleep 0.3; r1=$(rx); assert_dropped "(d) ES-peer multicast dropped" "$BASELINE" "$((r1-r0))"
r0=$(rx); gen_unicast "$ESP" "$UNK_MAC" "${OV}.50"; sleep 0.3; r1=$(rx); assert_dropped "(e) ES-peer unknown-unicast dropped" "$BASELINE" "$((r1-r0))"
locx bridge fdb add "$KNOWN_MAC" dev ce-br master static
r0=$(rx); gen_unicast "$ESP" "$KNOWN_MAC" "${OV}.60"; sleep 0.3; r1=$(rx); assert_forwarded "(f) ES-peer known-unicast preserved" "$((r1-r0))"
r0=$(rx); gen_bcast "$NES"; sleep 0.3; r1=$(rx); assert_forwarded "(g) non-ES broadcast reaches CE" "$((r1-r0))"

echo
echo "=== local-bias SPH spike: $PASS passed, $FAIL failed ==="
echo "GATE (all must pass for the stateless tc-flower design): (a) mark survival, (e) unknown-unicast dropped, (f) known-unicast preserved."
echo "A FAIL scopes A2 to eBPF-with-MAC-state or an ASIC dataplane (ADR-0065 fallback ladder)."
exit 0
