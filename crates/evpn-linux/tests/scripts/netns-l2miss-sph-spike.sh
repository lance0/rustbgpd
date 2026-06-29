#!/usr/bin/env bash
# Privileged netns spike for ADR-0094 — EVPN VXLAN all-active BUM filtering via
# the kernel `l2_miss` primitive (mainline 6.5). Revisits ADR-0065, whose
# `enc_src_ip` spike failed because a standard bridged VXLAN strips the outer
# tunnel metadata before the device ingress qdisc.
#
# THE NEW MECHANISM (single-stage, on the CE/ES-bond EGRESS, decapped inner frame):
#   tc filter add dev ce-br egress flower \
#       indev vxlan100 dst_mac 01:00:00:00:00:00/01:00:00:00:00:00 action drop   # B/M
#   tc filter add dev ce-br egress flower \
#       indev vxlan100 l2_miss 1 action drop                                     # unknown-unicast
#   (known unicast: FDB hit -> l2_miss 0 -> unmatched -> forwarded)
#
# Topology is reused verbatim from netns-localbias-sph-spike.sh (3 VTEPs each in
# its own netns + an underlay bridge; remote VTEPs head-end-replicate BUM to the
# local PE). The CE is ce-tap; frames delivered to the CE are counted there.
#
# Assertion matrix (ADR-0094):
#   (a) `l2_miss 1` installs on the egress hook AND matches unknown-unicast
#   (b) ES-peer broadcast dropped       (dst_mac multicast-bit, indev vxlan100)
#   (c) ES-peer multicast dropped
#   (e) ES-peer unknown-unicast dropped (l2_miss 1 — the case enc_src_ip could not reach)
#   (f) ES-peer KNOWN-unicast preserved (l2_miss 0 — the case ADR-0065 feared)
#   (g) source-blindness: non-ES broadcast ALSO dropped with the filter on
#       -> EXPECTED (the filter is non-DF/frame-class, not source-conditioned);
#          correctness must compose with DF election (filter on non-DF only).
#   (h) DF role (filter removed): non-ES broadcast reaches the CE again
#       -> proves the DF delivers external BUM; the composition gives one copy.
#
# (a)/(e)/(f) decide whether the mechanism works at all on a standard bridged
# VXLAN (overturning ADR-0065's ASIC deferral). (g)/(h) characterize the
# DF/non-DF composition for the production design.
#
# Requires kernel >= 6.5 (`l2_miss`) and an iproute2 with the `l2_miss` flower
# key. Usage:
#   docker run --rm --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
#       --security-opt apparmor=unconfined -v "$PWD":/work -w /work \
#       rustbgpd-netns-tests:latest \
#       bash crates/evpn-linux/tests/scripts/netns-l2miss-sph-spike.sh
#   (or: sudo bash crates/evpn-linux/tests/scripts/netns-l2miss-sph-spike.sh)
#
# A FAIL on (a) leaves ADR-0065's ASIC deferral standing. Exits non-zero only on
# setup errors.

set -uo pipefail

SFX=$$
ULNS="l2m-ul-$SFX"; LOC="l2m-loc-$SFX"; ESP="l2m-esp-$SFX"; NES="l2m-nes-$SFX"
VNI=100; DPORT=4789
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
echo "kernel: $(uname -r)  ($(uname -r | awk -F. '{ if ($1>6 || ($1==6 && $2>=5)) print "l2_miss-capable (>=6.5)"; else print "TOO OLD for l2_miss (<6.5)" }'))"

rx() { locx cat /sys/class/net/ce-tap/statistics/rx_packets; }
pass() { echo "PASS [$1]: ${2:-}"; PASS=$((PASS+1)); }
fail() { echo "FAIL [$1]: ${2:-}"; FAIL=$((FAIL+1)); }
note() { echo "NOTE [$1]: ${2:-}"; }
assert_dropped() { local l=$1 base=$2 a=$3
    if [ "$a" -le 2 ] && [ "$((a*5))" -lt "$base" ]; then pass "$l" "CE rx delta=$a (baseline=$base)"
    else fail "$l" "expected drop, CE rx delta=$a (baseline=$base)"; fi; }
assert_forwarded() { local l=$1 a=$2
    if [ "$a" -gt 0 ]; then pass "$l" "CE rx delta=$a"; else fail "$l" "expected forward, CE rx delta=0"; fi; }

# --------------------------------------------------------------------------
# Underlay + 3 VTEPs (reused from netns-localbias-sph-spike.sh).
# --------------------------------------------------------------------------
for n in "$ULNS" "$LOC" "$ESP" "$NES"; do ip netns add "$n"; ip netns exec "$n" ip link set lo up; done
ulx ip link add ulbr type bridge; ulx ip link set ulbr up
add_leg() { ip -n "$ULNS" link add "ul-$2" type veth peer name "$2"
    ip -n "$ULNS" link set "$2" netns "$1"
    ip -n "$ULNS" link set "ul-$2" master ulbr; ip -n "$ULNS" link set "ul-$2" up
    ip -n "$1" link set "$2" up; ip -n "$1" addr add "$3/24" dev "$2"; }
add_leg "$LOC" loc-leg "$LOC_UL"
add_leg "$ESP" esp-leg "$ESP_UL"
add_leg "$NES" nes-leg "$NES_UL"
for n in "$LOC" "$ESP" "$NES"; do
    ip netns exec "$n" sysctl -wq net.ipv4.icmp_echo_ignore_broadcasts=0 2>/dev/null || true
    ip netns exec "$n" sysctl -wq net.ipv4.ping_group_range="0 65535" 2>/dev/null || true
done

# Local VTEP (PE under test). Bridge does the FDB lookup that sets l2_miss.
locx ip link add br100 type bridge
locx ip link add vxlan100 type vxlan id "$VNI" dstport "$DPORT" local "$LOC_UL" dev loc-leg nolearning \
    || die "kernel rejected vxlan create"
locx ip link add ce-br type veth peer name ce-tap
locx ip link set vxlan100 master br100
locx ip link set ce-br master br100
for d in br100 vxlan100 ce-br ce-tap; do locx ip link set "$d" up; done
locx ip addr add "${OV}.1/24" dev ce-tap

make_remote() { local fn=$1 lip=$2 ov=$3 leg=$4
    $fn ip link add brm type bridge
    $fn ip link add vx type vxlan id "$VNI" dstport "$DPORT" local "$lip" dev "$leg" nolearning
    $fn ip link add inj type veth peer name injt
    $fn ip link set vx master brm; $fn ip link set inj master brm
    for d in brm vx inj injt; do $fn ip link set "$d" up; done
    $fn ip addr add "$ov/24" dev injt
    $fn bridge fdb append 00:00:00:00:00:00 dev vx dst "$LOC_UL"; }
make_remote espx "$ESP_UL" "${OV}.2" esp-leg
make_remote nesx "$NES_UL" "${OV}.3" nes-leg
sleep 0.4

gen_bcast() { ip netns exec "$1" ping -b -W1 -c"$PINGS" -I injt "${OV}.255" >/dev/null 2>&1 || true; }
gen_mcast() { ip netns exec "$1" ping -W1 -c"$PINGS" -I injt "$MCAST_GRP" >/dev/null 2>&1 || true; }
gen_unicast() { ip netns exec "$1" ip neigh replace "$3" lladdr "$2" dev injt
    ip netns exec "$1" bridge fdb append "$2" dev vx dst "$LOC_UL"
    ip netns exec "$1" ping -W1 -c"$PINGS" -I injt "$3" >/dev/null 2>&1 || true; }

# Reference flood baseline (no filter).
r0=$(rx); gen_bcast "$ESP"; sleep 0.3; r1=$(rx); BASELINE=$((r1-r0))
[ "$BASELINE" -gt 0 ] || die "no flood baseline — ES-peer broadcast never reached CE (topology broken)"
echo "flood baseline (ES-peer broadcast -> CE) = $BASELINE"

# Diagnostic: does the egress hook see decapped frames at all (sanity vs ADR-0065)?
locx tc qdisc add dev ce-br clsact 2>/dev/null || true
locx tc filter add dev ce-br egress pref 100 matchall action pass 2>/dev/null || true
gen_bcast "$ESP"; sleep 0.3
MA=$(locx tc -s filter show dev ce-br egress pref 100 2>/dev/null | grep -oE '[0-9]+ pkt' | grep -oE '[0-9]+' | head -1)
echo "diag: matchall on ce-br egress matched ${MA:-0} pkt(s) (the hook sees decapped frames)"
locx tc filter del dev ce-br egress pref 100 2>/dev/null || true

# --------------------------------------------------------------------------
# Candidate l2_miss filter on the CE-bond egress.
# --------------------------------------------------------------------------
BM_OK=1; L2M_OK=1
locx tc filter add dev ce-br egress pref 1 protocol all flower \
    indev vxlan100 dst_mac 01:00:00:00:00:00/01:00:00:00:00:00 action drop 2>/tmp/l2m_bm.err || BM_OK=0
locx tc filter add dev ce-br egress pref 2 protocol all flower \
    indev vxlan100 l2_miss 1 action drop 2>/tmp/l2m_l2m.err || L2M_OK=0

if [ "$L2M_OK" -ne 1 ]; then
    fail "(a) l2_miss installs" "kernel/iproute2 rejected 'flower l2_miss 1': $(cat /tmp/l2m_l2m.err 2>/dev/null)"
else
    # match unknown-unicast and read the per-filter packet counter
    gen_unicast "$ESP" "$UNK_MAC" "${OV}.50"; sleep 0.3
    L2M_PKTS=$(locx tc -s filter show dev ce-br egress pref 2 2>/dev/null | grep -oE '[0-9]+ pkt' | grep -oE '[0-9]+' | head -1)
    L2M_PKTS=${L2M_PKTS:-0}
    if [ "$L2M_PKTS" -gt 0 ]; then pass "(a) l2_miss installs+matches" "flower l2_miss 1 matched $L2M_PKTS unknown-unicast pkt(s) at ce-br egress"
    else fail "(a) l2_miss installs+matches" "filter installed but matched 0 pkts"; fi
fi
[ "$BM_OK" -eq 1 ] || note "(b/c) B/M filter" "kernel rejected dst_mac flower: $(cat /tmp/l2m_bm.err 2>/dev/null)"

# (b)/(c)/(e)/(f) — ES-peer, with the filter installed (PE acting as non-DF).
r0=$(rx); gen_bcast "$ESP"; sleep 0.3; r1=$(rx); assert_dropped "(b) ES-peer broadcast dropped" "$BASELINE" "$((r1-r0))"
r0=$(rx); gen_mcast "$ESP"; sleep 0.3; r1=$(rx); assert_dropped "(c) ES-peer multicast dropped" "$BASELINE" "$((r1-r0))"
r0=$(rx); gen_unicast "$ESP" "$UNK_MAC" "${OV}.51"; sleep 0.3; r1=$(rx); assert_dropped "(e) ES-peer unknown-unicast dropped" "$BASELINE" "$((r1-r0))"
locx bridge fdb add "$KNOWN_MAC" dev ce-br master static
r0=$(rx); gen_unicast "$ESP" "$KNOWN_MAC" "${OV}.60"; sleep 0.3; r1=$(rx); assert_forwarded "(f) ES-peer known-unicast preserved" "$((r1-r0))"

# (g) source-blindness: with the filter on, non-ES BUM is ALSO dropped (expected).
r0=$(rx); gen_bcast "$NES"; sleep 0.3; r1=$(rx); G=$((r1-r0))
if [ "$G" -le 2 ] && [ "$((G*5))" -lt "$BASELINE" ]; then
    note "(g) source-blind" "non-ES broadcast ALSO dropped (delta=$G) — EXPECTED: filter is frame-class, not source-conditioned. Production applies it on NON-DF PEs only; the DF delivers external BUM."
else
    note "(g) source-blind" "non-ES broadcast reached CE (delta=$G) — filter is somehow source-aware; investigate."
fi

# (h) DF role: remove the filter, confirm external (non-ES) BUM reaches the CE.
locx tc filter del dev ce-br egress pref 1 2>/dev/null || true
locx tc filter del dev ce-br egress pref 2 2>/dev/null || true
r0=$(rx); gen_bcast "$NES"; sleep 0.3; r1=$(rx); assert_forwarded "(h) DF (no filter): non-ES broadcast reaches CE" "$((r1-r0))"

echo
echo "=== ADR-0094 l2_miss SPH spike: $PASS passed, $FAIL failed ==="
echo "GATE (must pass to overturn ADR-0065's ASIC deferral): (a) l2_miss matches, (e) unknown-unicast dropped, (f) known-unicast preserved, (b) B/M dropped."
echo "(g)/(h) characterize the DF/non-DF composition: the filter is source-blind, so the production design installs it on NON-DF PEs and relies on DF election for external delivery + the residual ES-peer-on-DF dedup (ADR-0094 assertion (i))."
exit 0
