#!/bin/sh
# Gate 8b 24-hour soak — per-PE startup script.
#
# Builds a complete L2VNI VTEP topology so the dataplane reaches
# `Ready` and the Gate 8b BUM-suppression filter has a real
# CE-facing bridge port to flip flags on:
#
#   br100 ─┬─ vxlan100 (VXLAN port, dst 10.0.0.<peer>)
#          └─ ce100a   (veth, peer ce100b — the "CE-facing" side
#                       the soak harness inspects flags on)
#
# Args:
#   $1 = local VTEP IP (must match config local_vtep_ip)
#   $2 = remote VTEP IP (the other PE)
#   $3 = VNI

set -eu

if [ $# -lt 3 ]; then
    echo "usage: start-rustbgpd-soak-gate8b.sh <local-ip> <remote-ip> <vni>" >&2
    exit 1
fi

LOCAL_IP="$1"
REMOTE_IP="$2"
VNI="$3"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"
CE_BR="ce${VNI}a"
CE_TAP="ce${VNI}b"

ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${BRIDGE}" up

ip link add "${VXLAN}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    remote "${REMOTE_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${VXLAN}" master "${BRIDGE}"
ip link set dev "${VXLAN}" up

# CE veth pair. ce<vni>a is enslaved to the bridge; ce<vni>b is the
# "CE side" that the harness can inspect or generate traffic on.
ip link add "${CE_BR}" type veth peer name "${CE_TAP}" 2>/dev/null || true
ip link set dev "${CE_BR}" master "${BRIDGE}"
ip link set dev "${CE_BR}" up
ip link set dev "${CE_TAP}" up

# The Gate 8b dataplane orchestrator needs to find a non-VXLAN
# bridge port to apply BUM-suppression flags to. ce<vni>a fits that
# role; the orchestrator's KernelLinkInfo.ce_port_ifindexes will
# include it on the next dump pass.

nohup /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml \
    >/var/log/rustbgpd.log 2>&1 &

# Give the daemon a moment to come up before exec returns. Without
# this, fast follow-up `docker exec ip route` calls can race the
# rtnetlink probe.
sleep 1
