#!/bin/sh
# M72 VTEP (rustbgpd) kernel topology setup — L3 receive datapath for
# all-active ESI overlay-index Type 5.
#
# Args:
#   $1 = VTEP local IP used by the VXLAN devices (10.0.1.1)
#   $2 = L3VNI (100)
#   $3 = VRF name (vrf1)
#   $4 = router MAC (must match `router_mac` in rustbgpd-m72-vtep.toml)
#   $5 = L2VNI (10)

set -eu

if [ $# -lt 5 ]; then
    echo "usage: start-rustbgpd-m72-vtep.sh <loopback-ip> <l3vni> <vrf-name> <router-mac> <l2vni>" >&2
    exit 1
fi

LOCAL_IP="$1"
L3VNI="$2"
VRF="$3"
ROUTER_MAC="$4"
L2VNI="$5"

L3VXLAN="l3vxlan${L3VNI}"
BRIDGE="br${L2VNI}"
L2VXLAN="vxlan${L2VNI}"

ip link add "${VRF}" type vrf table "${L3VNI}" 2>/dev/null || true
ip link set dev "${VRF}" up

ip link add "${L3VXLAN}" type vxlan \
    id "${L3VNI}" \
    local "${LOCAL_IP}" \
    dstport 4789 \
    nolearning 2>/dev/null || true
ip link set dev "${L3VXLAN}" address "${ROUTER_MAC}"
ip link set dev "${L3VXLAN}" master "${VRF}"
ip link set dev "${L3VXLAN}" up

ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${BRIDGE}" master "${VRF}"
ip link set dev "${BRIDGE}" addrgenmode none
ip link set dev "${BRIDGE}" up

ip link add "${L2VXLAN}" type vxlan \
    id "${L2VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${L2VXLAN}" master "${BRIDGE}"
ip link set dev "${L2VXLAN}" up
bridge link set dev "${L2VXLAN}" neigh_suppress on 2>/dev/null || true

echo "M72 VTEP kernel topology ready:"
echo "  VRF        : ${VRF} (table ${L3VNI})"
echo "  L3 VXLAN   : ${L3VXLAN} (vni=${L3VNI}, local=${LOCAL_IP}, mac=${ROUTER_MAC})"
echo "  L2 bridge  : ${BRIDGE} (vni=${L2VNI}, linked to ${VRF})"
