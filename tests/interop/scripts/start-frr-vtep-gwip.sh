#!/bin/sh
# FRR VTEP setup for M68: L3VNI 100 plus linked L2VNI 10. The L2
# bridge address makes the Gateway Address subnet L3-reachable; the
# Type 2 route received over EVPN supplies the overlay-index MAC/VTEP
# resolution.
#
# Args:
#   $1 = VTEP loopback IP
#   $2 = L3VNI
#   $3 = VRF name
#   $4 = L2VNI
#   $5 = connected gateway subnet CIDR on the L2 bridge

set -eu

if [ $# -lt 5 ]; then
    echo "usage: start-frr-vtep-gwip.sh <loopback-ip> <l3vni> <vrf-name> <l2vni> <gateway-subnet-cidr>" >&2
    exit 1
fi

LOCAL_IP="$1"
L3VNI="$2"
VRF="$3"
L2VNI="$4"
GATEWAY_CIDR="$5"

L3_BRIDGE="br${L3VNI}"
L3VXLAN="vxlan${L3VNI}"
SVI="vlan${L3VNI}"
L2_BRIDGE="br${L2VNI}"
L2VXLAN="vxlan${L2VNI}"

ip link add "${VRF}" type vrf table "${L3VNI}" 2>/dev/null || true
ip link set dev "${VRF}" up

# L3VNI shape used by FRR/zebra for the tenant VRF.
ip link add name "${L3_BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${L3_BRIDGE}" master "${VRF}"
ip link set dev "${L3_BRIDGE}" addrgenmode none
ip link set dev "${L3_BRIDGE}" up

if ! ip link add link "${L3_BRIDGE}" name "${SVI}" type macvlan mode bridge 2>/dev/null; then
    ip link add "${SVI}" type dummy 2>/dev/null || true
    ip link set dev "${SVI}" master "${L3_BRIDGE}"
fi
ip link set dev "${SVI}" master "${VRF}"
ip link set dev "${SVI}" up

ip link add "${L3VXLAN}" type vxlan \
    id "${L3VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${L3VXLAN}" master "${L3_BRIDGE}"
ip link set dev "${L3VXLAN}" up

# Linked L2VNI used for overlay-index resolution.
ip link add name "${L2_BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${L2_BRIDGE}" master "${VRF}"
ip link set dev "${L2_BRIDGE}" addrgenmode none
ip link set dev "${L2_BRIDGE}" up
ip addr add "${GATEWAY_CIDR}" dev "${L2_BRIDGE}" 2>/dev/null || true

ip link add "${L2VXLAN}" type vxlan \
    id "${L2VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${L2VXLAN}" master "${L2_BRIDGE}"
ip link set dev "${L2VXLAN}" up

sleep 1
