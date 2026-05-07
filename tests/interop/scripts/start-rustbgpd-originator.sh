#!/bin/sh
# rustbgpd VTEP-originator setup — M37.
#
# Pre-creates:
#   - br${VNI} bridge
#   - vxlan${VNI} VXLAN port enslaved to the bridge (so the link
#     cache populates the vxlan_ifindex_to_vni map and our notify
#     classifier drops VXLAN-port echoes correctly)
#   - veth${VNI}a / veth${VNI}b veth pair, with veth${VNI}a enslaved
#     to the bridge as a *non-VXLAN* port. RTNLGRP_NEIGH events on
#     this port are what we want the originator to react to —
#     `bridge fdb add` against this ifindex will trigger the
#     LocalMacObservation flow.
#
# Then starts rustbgpd. The test driver injects MACs and asserts
# Type 2 / Type 3 visibility via FRR's vtysh.
#
# Args:
#   $1 = VTEP loopback IP (must match config local_vtep_ip)
#   $2 = VNI (24-bit; must match config evpn_instances.vni)

set -eu

if [ $# -lt 2 ]; then
    echo "usage: start-rustbgpd-originator.sh <loopback-ip> <vni>" >&2
    exit 1
fi

LOCAL_IP="$1"
VNI="$2"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"
VETH_A="veth${VNI}a"
VETH_B="veth${VNI}b"

ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${BRIDGE}" up

ip link add "${VXLAN}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${VXLAN}" master "${BRIDGE}"
ip link set dev "${VXLAN}" up

# veth pair so a non-VXLAN bridge port exists. The originator reacts
# to MACs added on this port (via `bridge fdb add ... master static`)
# by emitting Type 2 routes — that's the loop M37 exercises.
ip link add "${VETH_A}" type veth peer name "${VETH_B}" 2>/dev/null || true
ip link set dev "${VETH_A}" master "${BRIDGE}"
ip link set dev "${VETH_A}" up
ip link set dev "${VETH_B}" up

# Start rustbgpd. nohup + & so the exec returns immediately.
nohup /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml \
    >/var/log/rustbgpd.log 2>&1 &

sleep 1
