#!/bin/sh
# M65 single-active segment PE (GoBGP control plane over a plain
# kernel bridge/VXLAN dataplane) — ADR-0083 slice 4.
#
# The PE's dataplane is deliberately daemon-free: a learning VXLAN
# port (the PE learns the remote host's MAC from the DUT's
# encapsulated frames) bridged with the CE-facing attachment circuit
# (eth2). EVPN route state is injected/withdrawn by the test driver
# through the gobgp CLI — GoBGP only speaks BGP here; the kernel
# forwards.
#
# Deliberately NO all-zero flood entry toward the DUT: the ping path
# never needs it (CE only replies, and by then the PE has learned the
# remote host's MAC from the request's VXLAN ingress), and with one
# the CE's spontaneous chatter (IPv6 RS etc.) floods into the DUT and
# gets kernel-learned on its bridge BEFORE the EVPN route arrives —
# an unmarked pre-existing row the DUT's foreign-FDB preservation
# (ADR-0054 §5/§7) correctly refuses to claim, blocking the install
# under test. No flood entries anywhere also makes the measurement
# strict: known-unicast via the NHG row is the only fabric path.
#
# Args:
#   $1 = local VTEP IP (the PE's eth1 address; EVPN next-hop)
#   $2 = VNI (24-bit)
#   $3 = optional extra route CIDR (underlay reach to the DUT VTEP IP)
#   $4 = gateway for $3

set -eu

if [ $# -lt 2 ]; then
    echo "usage: start-gobgp-sa-pe.sh <local-vtep-ip> <vni> [<route-cidr> <gw>]" >&2
    exit 1
fi

LOCAL_IP="$1"
VNI="$2"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"

# Bridge for the VNI with the CE-facing attachment circuit enslaved.
ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${BRIDGE}" up
ip link set dev eth2 master "${BRIDGE}"
ip link set dev eth2 up

# Learning VXLAN port: unlike the rustbgpd VTEP shape (nolearning,
# EVPN owns the FDB), this PE has no EVPN dataplane agent — kernel
# learning from the DUT's encapsulated traffic provides the return
# path (remote-host MAC -> DUT VTEP).
ip link add "${VXLAN}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" 2>/dev/null || true
ip link set dev "${VXLAN}" master "${BRIDGE}"
ip link set dev "${VXLAN}" up

# Optional underlay route (PE2 reaches the DUT's VTEP IP through the
# DUT's other link subnet).
if [ $# -ge 4 ]; then
    ip route add "$3" via "$4" 2>/dev/null || true
fi

# Start gobgpd. nohup + & so the exec returns immediately and
# `sleep infinity` (the container's PID 1) keeps the netns alive.
nohup gobgpd -f /config/gobgp.toml \
    >/var/log/gobgpd.log 2>&1 &

# Tiny pause so the first `docker exec gobgp ...` finds gobgpd up.
sleep 1
