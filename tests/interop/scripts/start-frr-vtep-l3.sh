#!/bin/sh
# FRR VTEP kernel setup for L3VNI / symmetric IRB origination — creates
# a VRF, bridge with SVI, VXLAN interface, and a tenant loopback so
# FRR's zebra binds the L3VNI to vrf1 and originates a Type 5 (IP
# Prefix) route for the tenant prefix.
#
# Args:
#   $1 = VTEP loopback IP (becomes VXLAN tunnel source + router-id)
#   $2 = L3VNI (24-bit)
#   $3 = VRF name (e.g. vrf1)
#   $4 = tenant prefix in CIDR form to install on lo-${VRF}
#
# Layout built (for VNI=100, VRF=vrf1):
#   vrf1        : Linux VRF, table 100
#   br100       : bridge in the L3VNI broadcast domain, master vrf1
#   vlan100     : SVI on the bridge (the L3VNI's L3 anchor — FRR
#                 zebra binds the L3VNI's Router-MAC here per RFC
#                 9135 §3). macvlan(bridge) preferred; dummy fallback.
#   vxlan100    : VXLAN, id=100, dstport=4789, local=<loopback>,
#                 nolearning, master br100
#   lo-vrf1     : tenant dummy in VRF carrying the prefix that
#                 `redistribute connected` will export as Type 5.
#
# Order matters: VRF first, then bridge in the VRF, then SVI on the
# bridge, then VXLAN attached. This is what FRR EVPN docs and the
# fedepaol L3EVPN guide both prescribe — zebra reads the bridge's VRF
# membership when it sees the VXLAN device come up, so the bridge has
# to be VRF-attached before VXLAN comes up.

set -eu

if [ $# -lt 4 ]; then
    echo "usage: start-frr-vtep-l3.sh <loopback-ip> <l3vni> <vrf-name> <tenant-prefix-cidr>" >&2
    exit 1
fi

LOCAL_IP="$1"
VNI="$2"
VRF="$3"
TENANT_CIDR="$4"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"
SVI="vlan${VNI}"
LOTEN="lo-${VRF}"

# 1. VRF — the L3 forwarding table behind the L3VNI.
ip link add "${VRF}" type vrf table "${VNI}" 2>/dev/null || true
ip link set dev "${VRF}" up

# 2. Bridge in the L3VNI broadcast domain, attached to the VRF.
ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${BRIDGE}" master "${VRF}"
ip link set dev "${BRIDGE}" addrgenmode none
ip link set dev "${BRIDGE}" up

# 3. SVI on the bridge — L3 anchor for the L3VNI broadcast domain.
# Try macvlan(bridge) first (the canonical setup in FRR's EVPN guide);
# fall back to a dummy with `master ${BRIDGE}` for kernels where
# macvlan(bridge) is restricted.
if ! ip link add link "${BRIDGE}" name "${SVI}" type macvlan mode bridge 2>/dev/null; then
    ip link add "${SVI}" type dummy 2>/dev/null || true
    ip link set dev "${SVI}" master "${BRIDGE}"
fi
ip link set dev "${SVI}" master "${VRF}"
ip link set dev "${SVI}" up

# 4. VXLAN attached to the bridge. nolearning — EVPN owns the FDB.
ip link add "${VXLAN}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${VXLAN}" master "${BRIDGE}"
ip link set dev "${VXLAN}" up

# 5. Tenant loopback in the VRF carrying the prefix to redistribute.
ip link add "${LOTEN}" type dummy 2>/dev/null || true
ip link set dev "${LOTEN}" master "${VRF}"
ip link set dev "${LOTEN}" up
ip addr add "${TENANT_CIDR}" dev "${LOTEN}" 2>/dev/null || true

# Let zebra notice the new interfaces before BGP comes up.
sleep 1
