#!/bin/sh
# rustbgpd VTEP-originator setup for the M37+IP MAC-with-IP variant.
#
# Same topology as start-rustbgpd-originator.sh, plus:
#   - `bridge link set ... neigh_suppress on` on the VXLAN port so
#     the kernel snoops ARP/ND traffic into the bridge's neighbour
#     table. AF_INET / AF_INET6 RTM_NEWNEIGH messages on the
#     bridge ifindex are what slice 1's classifier acts on.
#
# Args:
#   $1 = VTEP loopback IP (must match config local_vtep_ip)
#   $2 = VNI (24-bit; must match config evpn_instances.vni)

set -eu

if [ $# -lt 2 ]; then
    echo "usage: start-rustbgpd-originator-mac-ip.sh <loopback-ip> <vni>" >&2
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

# Veth pair so a non-VXLAN bridge port exists (same as M37).
ip link add "${VETH_A}" type veth peer name "${VETH_B}" 2>/dev/null || true
ip link set dev "${VETH_A}" master "${BRIDGE}"
ip link set dev "${VETH_A}" up
ip link set dev "${VETH_B}" up

# Gate 7b+2 prerequisite: enable per-VXLAN-port neighbour suppression
# so the kernel snoops ARP/ND into the bridge's neighbour table and
# emits AF_INET / AF_INET6 RTM_NEWNEIGH messages on the bridge
# ifindex. Without this, the daemon never sees IpAdded / IpRemoved
# events.
bridge link set dev "${VXLAN}" neigh_suppress on

# Start rustbgpd. nohup + & so the exec returns immediately.
nohup /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml \
    >/var/log/rustbgpd.log 2>&1 &

sleep 1
