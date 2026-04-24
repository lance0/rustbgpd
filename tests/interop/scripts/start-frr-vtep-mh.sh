#!/bin/sh
# FRR VTEP setup WITH EVPN multi-homing — extends start-frr-vtep.sh with
# a dummy access interface that carries the Ethernet Segment config.
#
# Args:
#   $1 = VTEP tunnel source IP (eth1 address)
#   $2 = VNI (24-bit)
#   $3 = ES-ID (1..16M)
#   $4 = ES-SYS-MAC (48-bit, colon-separated)
#
# Layout built (on top of the plain VTEP layout):
#   es-dummy  : dummy access interface attached to the bridge. FRR treats
#               this as the "trunk to the dual-homed CE" and originates
#               Type 4 ES + Type 1 EAD routes for the configured ESI.
#
# Two VTEPs launched with the same (es-id, es-sys-mac) form a shared
# Ethernet Segment; both advertise ES routes with the same 10-byte ESI
# derived from es-sys-mac + es-id per RFC 7432 §5 (ESI Type 3).

set -eu

if [ $# -lt 4 ]; then
    echo "usage: start-frr-vtep-mh.sh <loopback-ip> <vni> <es-id> <es-sys-mac>" >&2
    exit 1
fi

LOCAL_IP="$1"
VNI="$2"
ES_ID="$3"
ES_SYS_MAC="$4"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"
ES_DUMMY="esdummy"

# --- Standard VTEP: bridge + VXLAN interface with nolearning ---
ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${BRIDGE}" up

ip link add "${VXLAN}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${VXLAN}" master "${BRIDGE}"
ip link set dev "${VXLAN}" up

# --- Multi-homing extension: dummy access interface attached to bridge ---
ip link add "${ES_DUMMY}" type dummy 2>/dev/null || true
ip link set dev "${ES_DUMMY}" master "${BRIDGE}"
ip link set dev "${ES_DUMMY}" up

ip link set dev "${BRIDGE}" up

# ES-ID and ES-SYS-MAC come through as FRR config on this interface
# (see frr-bgpd-m32-vtep-*.conf). Surface them here for log-visibility
# when the shim runs as a container exec hook.
echo "start-frr-vtep-mh: local=${LOCAL_IP} vni=${VNI} es-id=${ES_ID} es-sys-mac=${ES_SYS_MAC}" >&2

sleep 1
