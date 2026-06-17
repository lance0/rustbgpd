#!/bin/sh
# M71 VTEP (rustbgpd) kernel topology setup — the L3 receive datapath
# for an imported ESI overlay-index Type 5.
#
# Mirrors the M39 / M68 receive-side L3 shape so an imported Type 5
# installs a kernel route in the IP-VRF's table:
#   1. IP-VRF master with table_id == L3VNI.
#   2. L3VXLAN device (vni == L3VNI) carrying the operator-configured
#      Router MAC, enslaved directly to the VRF (interface-less
#      symmetric IRB, ADR-0058 §3).
#   3. Linked L2VNI bridge + VXLAN (vni == L2VNI), enslaved to the VRF,
#      so the EAD-per-EVI rows that scope by this L2VNI resolve the
#      overlay-index recursion. nolearning on both VXLANs (EVPN owns
#      the FDB).
#
# No tenant address / dummy is needed: this is the RECEIVE side. The
# imported prefix comes off the wire from the GoBGP PE, not from a
# local origination.
#
# Args:
#   $1 = VTEP loopback IP (10.0.0.1)
#   $2 = L3VNI (100)
#   $3 = VRF name (vrf1)
#   $4 = router MAC (must match `router_mac` in rustbgpd-m71-vtep.toml)
#   $5 = L2VNI (10)

set -eu

if [ $# -lt 5 ]; then
    echo "usage: start-rustbgpd-m71-vtep.sh <loopback-ip> <l3vni> <vrf-name> <router-mac> <l2vni>" >&2
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

# 1. IP-VRF master with table_id == L3VNI (the rustbgpd config sets
#    table_id = 100 to match).
ip link add "${VRF}" type vrf table "${L3VNI}" 2>/dev/null || true
ip link set dev "${VRF}" up

# 2. L3 VXLAN with the operator-configured Router MAC, enslaved
#    directly to the VRF (interface-less symmetric IRB). nolearning:
#    EVPN owns the FDB.
ip link add "${L3VXLAN}" type vxlan \
    id "${L3VNI}" \
    local "${LOCAL_IP}" \
    dstport 4789 \
    nolearning 2>/dev/null || true
ip link set dev "${L3VXLAN}" address "${ROUTER_MAC}"
ip link set dev "${L3VXLAN}" master "${VRF}"
ip link set dev "${L3VXLAN}" up

# 3. Linked L2VNI bridge + VXLAN, enslaved to the VRF. Its presence
#    lets the receive path scope EAD-per-EVI rows (label == vni 10) and
#    tie the matched IP-VRF to this L2VNI for protected recursion.
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

echo "M71 VTEP kernel topology ready:"
echo "  VRF        : ${VRF} (table ${L3VNI})"
echo "  L3 VXLAN   : ${L3VXLAN} (vni=${L3VNI}, local=${LOCAL_IP}, mac=${ROUTER_MAC})"
echo "  L2 bridge  : ${BRIDGE} (vni=${L2VNI}, linked to ${VRF})"
