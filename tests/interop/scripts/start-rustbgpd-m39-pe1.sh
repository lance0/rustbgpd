#!/bin/sh
# M39 PE1 (rustbgpd) kernel topology setup. Mirrors what
# start-frr-vtep-l3.sh does for the FRR side but writes the
# router_mac value the rustbgpd config expects so the slice-5
# readiness probe lands `Ready`.
#
# Order matters (same rationale as start-frr-vtep-l3.sh):
#   1. VRF master with the right table_id.
#   2. L3VXLAN with the operator-configured Router MAC.
#   3. L3VXLAN enslaved to the VRF (`master vrf1`).
#   4. Both up.
#   5. Tenant dummy in the VRF carrying the prefix we want
#      rustbgpd to originate as Type 5.
#
# Args:
#   $1 = VTEP loopback IP (10.0.0.1 for PE1)
#   $2 = L3VNI (100)
#   $3 = VRF name (vrf1)
#   $4 = tenant prefix (192.0.2.1/32)
#   $5 = router MAC (02:00:00:00:01:01 — must match the
#         `router_mac` value in rustbgpd-m39-pe1.toml)

set -eu

if [ $# -lt 5 ]; then
    echo "usage: start-rustbgpd-m39-pe1.sh <loopback-ip> <l3vni> <vrf-name> <tenant-prefix-cidr> <router-mac>" >&2
    exit 1
fi

LOCAL_IP="$1"
VNI="$2"
VRF="$3"
TENANT_CIDR="$4"
ROUTER_MAC="$5"
L3VXLAN="l3vxlan${VNI}"
LOTEN="lo-${VRF}"

# 1. VRF master with table_id == VNI (the rustbgpd config also
#    sets table_id=100 to match this convention).
ip link add "${VRF}" type vrf table "${VNI}" 2>/dev/null || true
ip link set dev "${VRF}" up

# 2. L3 VXLAN with the operator-configured Router MAC. nolearning
#    because EVPN owns the FDB.
ip link add "${L3VXLAN}" type vxlan \
    id "${VNI}" \
    local "${LOCAL_IP}" \
    dstport 4789 \
    nolearning 2>/dev/null || true
ip link set dev "${L3VXLAN}" address "${ROUTER_MAC}"

# 3. Enslave L3VXLAN to the VRF (no bridge between them — this
#    is the L3VXLAN-direct shape ADR-0058 §3 requires for
#    Interface-less symmetric IRB).
ip link set dev "${L3VXLAN}" master "${VRF}"
ip link set dev "${L3VXLAN}" up

# 4. Tenant dummy in the VRF carrying the prefix slice 6a will
#    observe and slice 6b will originate as Type 5.
ip link add "${LOTEN}" type dummy 2>/dev/null || true
ip link set dev "${LOTEN}" master "${VRF}"
ip link set dev "${LOTEN}" up
ip addr add "${TENANT_CIDR}" dev "${LOTEN}" 2>/dev/null || true

echo "M39 PE1 kernel topology ready:"
echo "  VRF        : ${VRF} (table ${VNI})"
echo "  L3 VXLAN   : ${L3VXLAN} (vni=${VNI}, local=${LOCAL_IP}, mac=${ROUTER_MAC})"
echo "  tenant dev : ${LOTEN} (${TENANT_CIDR})"
