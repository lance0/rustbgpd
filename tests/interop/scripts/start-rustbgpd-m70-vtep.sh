#!/bin/sh
# M70 rustbgpd VTEP setup: ADR-0089 VLAN-aware bridge with two
# VNI-per-broadcast-domain EVPN instances.
#
# Args:
#   $1 = VTEP loopback / tunnel-source IP

set -eu

if [ $# -lt 1 ]; then
    echo "usage: start-rustbgpd-m70-vtep.sh <loopback-ip>" >&2
    exit 1
fi

LOCAL_IP="$1"
BRIDGE="brvlan"

ip link add name "${BRIDGE}" type bridge vlan_filtering 1 vlan_default_pvid 0 2>/dev/null || true
ip link set dev "${BRIDGE}" up

for pair in "100 10" "200 20"; do
    VNI="${pair% *}"
    VLAN="${pair#* }"
    VXLAN="vxlan${VNI}"

    ip link add "${VXLAN}" type vxlan \
        id "${VNI}" \
        dstport 4789 \
        local "${LOCAL_IP}" \
        nolearning 2>/dev/null || true
    ip link set dev "${VXLAN}" master "${BRIDGE}"
    ip link set dev "${VXLAN}" up

    bridge vlan add dev "${BRIDGE}" vid "${VLAN}" self 2>/dev/null || true
    bridge vlan add dev "${VXLAN}" vid "${VLAN}" 2>/dev/null || true
done

nohup /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml \
    >/var/log/rustbgpd.log 2>&1 &

sleep 1
