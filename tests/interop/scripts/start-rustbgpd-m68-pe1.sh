#!/bin/sh
# M68 PE1 kernel topology setup: one IP-VRF/L3VNI plus a linked
# L2VNI bridge that can originate the Gateway Address Type 2.
#
# Args:
#   $1 = VTEP loopback IP (10.0.0.1)
#   $2 = L3VNI (100)
#   $3 = VRF name (vrf1)
#   $4 = router MAC for the L3VXLAN device
#   $5 = L2VNI (10)
#   $6 = connected gateway subnet CIDR on the L2 bridge (10.1.1.1/24)

set -eu

if [ $# -lt 6 ]; then
    echo "usage: start-rustbgpd-m68-pe1.sh <loopback-ip> <l3vni> <vrf-name> <router-mac> <l2vni> <gateway-subnet-cidr>" >&2
    exit 1
fi

LOCAL_IP="$1"
L3VNI="$2"
VRF="$3"
ROUTER_MAC="$4"
L2VNI="$5"
GATEWAY_CIDR="$6"

L3VXLAN="l3vxlan${L3VNI}"
BRIDGE="br${L2VNI}"
L2VXLAN="vxlan${L2VNI}"
VETH_A="veth${L2VNI}a"
VETH_B="veth${L2VNI}b"

# IP-VRF and L3VXLAN readiness path.
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

# Linked L2VNI. The bridge is also the connected subnet interface in
# vrf1, so a static route via 10.1.1.5 passes the GW-IP on-subnet gate.
ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${BRIDGE}" master "${VRF}"
ip link set dev "${BRIDGE}" addrgenmode none
ip link set dev "${BRIDGE}" up
ip addr add "${GATEWAY_CIDR}" dev "${BRIDGE}" 2>/dev/null || true

ip link add "${L2VXLAN}" type vxlan \
    id "${L2VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${L2VXLAN}" master "${BRIDGE}"
ip link set dev "${L2VXLAN}" up
bridge link set dev "${L2VXLAN}" neigh_suppress on 2>/dev/null || true

ip link add "${VETH_A}" type veth peer name "${VETH_B}" 2>/dev/null || true
ip link set dev "${VETH_A}" master "${BRIDGE}"
ip link set dev "${VETH_A}" up
ip link set dev "${VETH_B}" up

echo "M68 PE1 kernel topology ready:"
echo "  VRF        : ${VRF} (table ${L3VNI})"
echo "  L3 VXLAN   : ${L3VXLAN} (vni=${L3VNI}, local=${LOCAL_IP}, mac=${ROUTER_MAC})"
echo "  L2 bridge  : ${BRIDGE} (vni=${L2VNI}, connected=${GATEWAY_CIDR})"
