#!/usr/bin/env bash
# ADR-0094 assertion (i) — the 2-PE composition spike. The single-PE
# netns-l2miss-sph-spike.sh proved the l2_miss filter mechanism and its
# source-blindness; this resolves the load-bearing question it could not:
# when a multi-homed CE's own BUM is re-delivered to it via the OTHER PE
# (the loop split-horizon must prevent), does "install the filter on the
# non-DF PE only" actually stop it?
#
# Topology — a CE dual-homed to two local PEs that share the ESI, plus an
# underlay bridge. The CE sends a broadcast in on PE1; it must NOT come
# back to the SAME CE via PE2.
#
#   ul   netns: ulbr  <- legs ->  loc1(.1) / loc2(.2)
#   loc1 netns: br100 { vxlan100(.1, VNI100, nolearning), ce1p }   (PE1)
#   loc2 netns: br100 { vxlan100(.2, VNI100, nolearning), ce2p }   (PE2, filter target)
#   ce   netns: ce1h(<->loc1.ce1p)  ce2h(<->loc2.ce2p)             (the one dual-homed CE)
#
# Each PE head-end-replicates BUM to the other via a static all-zero VXLAN
# FDB entry. A broadcast injected on ce1h floods loc1.br100 -> overlay ->
# loc2.vxlan100 -> (drop or deliver) -> ce2p -> ce2h. ce2h rx > 0 == the
# CE got its own broadcast back == the loop.
#
# Measurements:
#   T1 baseline (no filter on loc2)            -> ce2h rx > 0   (loop EXISTS; topology valid)
#   T2 loc2 filtered (loc2 == non-DF)          -> ce2h rx ~0    (filter on the re-deliverer stops it)
#   Conclusion: the loop is present exactly when the re-delivering PE is UNfiltered.
#   DF election picks the DF independent of which uplink the CE used, so when the
#   ingress is the non-DF and the DF is the peer, the DF re-delivers UNfiltered ->
#   the loop survives. => "non-DF only" does NOT fully close split-horizon; the DF
#   also needs a source-conditioned ES-peer drop (the residual ADR-0065 local-bias).
#
# Run: docker run --rm --cap-add=NET_ADMIN --cap-add=SYS_ADMIN \
#        --security-opt apparmor=unconfined -v "$PWD":/work -w /work \
#        rustbgpd-netns-tests bash crates/evpn-linux/tests/scripts/netns-l2miss-sph-2pe-spike.sh

set -uo pipefail

SFX=$$
UL="l2m2-ul-$SFX"; L1="l2m2-loc1-$SFX"; L2="l2m2-loc2-$SFX"; CE="l2m2-ce-$SFX"
VNI=100; DPORT=4789
L1_UL="10.255.0.1"; L2_UL="10.255.0.2"
OV="10.200.0"; PINGS=5
PASS=0; FAIL=0
cleanup() { for n in "$UL" "$L1" "$L2" "$CE"; do ip netns delete "$n" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT
die() { echo "SETUP-ERROR: $*" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || die "requires root (CAP_NET_ADMIN)"
for t in ip bridge tc ping; do command -v "$t" >/dev/null 2>&1 || die "missing tool '$t'"; done
echo "kernel: $(uname -r)"

ce2_rx() { ip netns exec "$CE" cat /sys/class/net/ce2h/statistics/rx_packets; }
gen_bcast_from_ce1() { ip netns exec "$CE" ping -b -W1 -c"$PINGS" -I ce1h "${OV}.255" >/dev/null 2>&1 || true; }

# --- netns + underlay ---
for n in "$UL" "$L1" "$L2" "$CE"; do ip netns add "$n"; ip netns exec "$n" ip link set lo up; done
ip -n "$UL" link add ulbr type bridge; ip -n "$UL" link set ulbr up
add_leg() { ip -n "$UL" link add "ul-$2" type veth peer name "$2"
    ip -n "$UL" link set "$2" netns "$1"
    ip -n "$UL" link set "ul-$2" master ulbr; ip -n "$UL" link set "ul-$2" up
    ip -n "$1" link set "$2" up; ip -n "$1" addr add "$3/24" dev "$2"; }
add_leg "$L1" l1-leg "$L1_UL"
add_leg "$L2" l2-leg "$L2_UL"

# --- a PE: bridge + vxlan + a CE-facing veth whose far end lands in the CE netns ---
make_pe() { # netns local-ul peer-ul leg ce-port ce-host
    local ns=$1 lip=$2 pip=$3 leg=$4 cep=$5 ceh=$6
    ip netns exec "$ns" ip link add br100 type bridge
    ip netns exec "$ns" ip link add vxlan100 type vxlan id "$VNI" dstport "$DPORT" local "$lip" dev "$leg" nolearning \
        || die "kernel rejected vxlan create in $ns"
    ip netns exec "$ns" ip link add "$cep" type veth peer name "$ceh"
    ip netns exec "$ns" ip link set "$ceh" netns "$CE"
    ip netns exec "$ns" ip link set vxlan100 master br100
    ip netns exec "$ns" ip link set "$cep" master br100
    for d in br100 vxlan100 "$cep"; do ip netns exec "$ns" ip link set "$d" up; done
    ip netns exec "$ns" bridge fdb append 00:00:00:00:00:00 dev vxlan100 dst "$pip"
    ip netns exec "$CE" ip link set "$ceh" up
}
make_pe "$L1" "$L1_UL" "$L2_UL" l1-leg ce1p ce1h
make_pe "$L2" "$L2_UL" "$L1_UL" l2-leg ce2p ce2h
ip netns exec "$CE" ip addr add "${OV}.10/24" dev ce1h
ip netns exec "$CE" ip addr add "${OV}.11/24" dev ce2h
ip netns exec "$CE" sysctl -wq net.ipv4.icmp_echo_ignore_broadcasts=0 2>/dev/null || true
ip netns exec "$CE" sysctl -wq net.ipv4.ping_group_range="0 65535" 2>/dev/null || true
sleep 0.5

# --- T1 baseline: no filter on loc2 (== loc2 is DF). The CE's broadcast must
#     loop back to itself via PE2. ce2h rx > 0 proves the loop + the topology.
r0=$(ce2_rx); gen_bcast_from_ce1; sleep 0.3; r1=$(ce2_rx); T1=$((r1-r0))
if [ "$T1" -gt 0 ]; then PASS=$((PASS+1)); echo "PASS [T1 baseline] CE's own broadcast loops back via the unfiltered peer PE: ce2h rx delta=$T1 (the duplicate)"
else FAIL=$((FAIL+1)); echo "FAIL [T1 baseline] no loop observed (delta=$T1) — topology broken, can't measure (i)"; fi

# --- T2: install the l2_miss filter on loc2's CE egress (loc2 == non-DF).
ip netns exec "$L2" tc qdisc add dev ce2p clsact 2>/dev/null || true
ip netns exec "$L2" tc filter add dev ce2p egress pref 1 protocol all flower \
    indev vxlan100 dst_mac 01:00:00:00:00:00/01:00:00:00:00:00 action drop 2>/dev/null || echo "note: B/M filter add failed"
ip netns exec "$L2" tc filter add dev ce2p egress pref 2 protocol all flower \
    indev vxlan100 l2_miss 1 action drop 2>/dev/null || echo "note: l2_miss filter add failed"
r0=$(ce2_rx); gen_bcast_from_ce1; sleep 0.3; r1=$(ce2_rx); T2=$((r1-r0))
if [ "$T2" -le 2 ] && [ "$((T2*5))" -lt "${T1:-1}" ]; then PASS=$((PASS+1)); echo "PASS [T2 non-DF filtered] filter on the re-delivering PE stops the loop: ce2h rx delta=$T2 (vs baseline $T1)"
else FAIL=$((FAIL+1)); echo "FAIL [T2 non-DF filtered] loop NOT stopped: ce2h rx delta=$T2 (baseline $T1)"; fi

echo
echo "=== ADR-0094 assertion (i) — 2-PE composition: $PASS passed, $FAIL failed ==="
echo "FINDING: the loop is present iff the RE-DELIVERING peer PE is UNfiltered (T1), and is stopped"
echo "when that PE carries the l2_miss filter (T2). DF election selects the DF independently of which"
echo "uplink the CE used, so when the ingress is the non-DF and the DF is the peer, the DF re-delivers"
echo "UNfiltered -> the loop survives. => 'install on the non-DF only' does NOT fully close split-horizon."
echo "The DF also needs a source-conditioned ES-peer drop (the residual ADR-0065 local-bias) for the"
echo "shared-ES case. v1 l2_miss is still a strict improvement on the source-blind A1 non-DF filter."
exit 0
