#!/bin/sh
# M70 FRR traditional VTEP setup: one bridge and VXLAN device per VNI.
#
# Args:
#   $1 = VTEP loopback / tunnel-source IP

set -eu

if [ $# -lt 1 ]; then
    echo "usage: start-frr-m70-vtep.sh <loopback-ip>" >&2
    exit 1
fi

LOCAL_IP="$1"

for VNI in 100 200; do
    BRIDGE="br${VNI}"
    VXLAN="vxlan${VNI}"
    DUMMY="dummy${VNI}"

    ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
    ip link set dev "${BRIDGE}" up

    ip link add "${VXLAN}" type vxlan \
        id "${VNI}" \
        dstport 4789 \
        local "${LOCAL_IP}" \
        nolearning 2>/dev/null || true
    ip link set dev "${VXLAN}" master "${BRIDGE}"
    ip link set dev "${VXLAN}" up

    ip link add "${DUMMY}" type dummy 2>/dev/null || true
    ip link set dev "${DUMMY}" master "${BRIDGE}"
    ip link set dev "${DUMMY}" up
done

sleep 1
