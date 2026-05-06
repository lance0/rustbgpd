#!/bin/sh
# rustbgpd VTEP setup — pre-creates the bridge + VXLAN port that
# the [[evpn_instances]] config references, pre-loads a foreign
# static FDB entry to validate ADR-0054 §5/§7 preservation, then
# starts rustbgpd in the background.
#
# Args:
#   $1 = VTEP loopback IP (must match config local_vtep_ip)
#   $2 = VNI (24-bit; must match config evpn_instances.vni)
#
# Exits 0 once rustbgpd is launched (sleep infinity entrypoint
# keeps the container alive; the test driver waits on the gRPC
# port itself).

set -eu

if [ $# -lt 2 ]; then
    echo "usage: start-rustbgpd-vtep.sh <loopback-ip> <vni>" >&2
    exit 1
fi

LOCAL_IP="$1"
VNI="$2"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"

# Bridge for the VNI. Not VLAN-aware — Gate 7b probe rejects
# vlan_filtering=1 explicitly.
ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${BRIDGE}" up

# VXLAN port: nolearning hands FDB ownership to EVPN. local_ip
# must match the [[evpn_instances]] local_vtep_ip in the config so
# the probe's IP-match check passes.
ip link add "${VXLAN}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${VXLAN}" master "${BRIDGE}"
ip link set dev "${VXLAN}" up

# Pre-load a foreign static FDB entry with a distinguishable MAC
# (02:99:99:99:99:99). The `master` flag lands it in the
# bridge-owned FDB (the same path rustbgpd's diff loop iterates
# against), so this is a valid test of ADR-0054 §5/§7 foreign-
# entry preservation against a real kernel — not a `self` /
# device-local entry that would be invisible to the bridge FDB.
bridge fdb add 02:99:99:99:99:99 dev "${VXLAN}" \
    dst 10.0.0.99 vni "${VNI}" master static 2>/dev/null || true

# Start rustbgpd. nohup + & so the exec returns immediately and
# `sleep infinity` (the container's PID 1) keeps the netns alive.
nohup /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml \
    >/var/log/rustbgpd.log 2>&1 &

# Tiny pause so the first containerlab `docker exec` finds rustbgpd
# already up.
sleep 1
