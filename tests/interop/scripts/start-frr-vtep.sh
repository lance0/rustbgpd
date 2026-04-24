#!/bin/sh
# FRR VTEP kernel setup — creates bridge + VXLAN interface so FRR's zebra
# daemon auto-detects VNI and begins originating EVPN Type 3 IMET + any
# Type 2 routes from local MAC learning.
#
# Args:
#   $1 = VTEP loopback IP (becomes VXLAN tunnel source + router-id)
#   $2 = VNI (24-bit)
#
# Layout built:
#   lo          : loopback carries the VTEP tunnel-source IP
#   br100       : bridge domain for VNI 100
#   vxlan100    : VXLAN interface, id=100, dstport=4789, local=<loopback>,
#                 attached to br100
#
# Learning is disabled on vxlan100 — EVPN controls the FDB instead of the
# kernel. This is standard FRR EVPN VTEP configuration.
#
# Note on `remote`: omitted from the vxlan link to use the default
# head-end replication group from EVPN signalling. Real data plane does
# not need to work for the M30 interop; only the control plane is tested.

set -eu

if [ $# -lt 2 ]; then
    echo "usage: start-frr-vtep.sh <loopback-ip> <vni>" >&2
    exit 1
fi

LOCAL_IP="$1"
VNI="$2"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"

# 1. Linux bridge for VNI ${VNI}.
ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${BRIDGE}" up

# 2. VXLAN interface. `nolearning` hands MAC learning to EVPN —
# the kernel FDB is populated from reflected EVPN routes, not from
# ingress traffic. `local <ip>` sets the tunnel source IP that appears
# as next-hop on Type 2 / Type 3 routes FRR originates.
ip link add "${VXLAN}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${VXLAN}" master "${BRIDGE}"
ip link set dev "${VXLAN}" up

# 3. Make sure the bridge is up as well (some distros leave it down).
ip link set dev "${BRIDGE}" up

# Let zebra see the interfaces before FRR's BGP daemon starts. Small sleep
# is pragmatic — the exact value isn't critical.
sleep 1
