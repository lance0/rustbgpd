#!/bin/sh
# rustbgpd single-active segment PE setup — M66.
#
# Pre-creates the kernel L2 topology a full rustbgpd VTEP-with-AC
# needs: br${VNI} bridging the EVPN VXLAN port (nolearning + bridge
# port learning off — EVPN owns the remote-MAC rows, ADR-0054 §5/§7)
# and the CE-facing attachment circuit eth2 (kernel learning ON: a
# CE MAC learned here is what the local Type 2 originator
# advertises, and what the ADR-0084 drain must withdraw).
#
# The config is bind-mounted as a read-only TEMPLATE at
# /etc/rustbgpd/config.template.toml and copied to the live path so
# the test driver can stage a config edit + SIGHUP (M58 pattern).
# The daemon PID is written to /var/run/rustbgpd.pid so the driver
# signals exactly this process (never a name-based kill).
#
# Args:
#   $1 = local VTEP IP (must match config local_vtep_ip)
#   $2 = VNI (24-bit; must match config evpn_instances.vni)
#   $3 = optional extra route CIDR (underlay reach to the far PE subnet)
#   $4 = gateway for $3

set -eu

if [ $# -lt 2 ]; then
    echo "usage: start-rustbgpd-sa-pe.sh <local-vtep-ip> <vni> [<route-cidr> <gw>]" >&2
    exit 1
fi

LOCAL_IP="$1"
VNI="$2"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"

# Bridge for the VNI. Not VLAN-aware — Gate 7b probe rejects
# vlan_filtering=1 explicitly. Multicast snooping + interface
# multicast OFF: the kernel's IGMP machinery otherwise emits
# bring-up frames (port/bridge-MAC sourced) that flood through the
# dual-homed CE onto the OTHER PE's attachment circuit, where they
# kernel-learn junk rows the local Type 2 originator would advertise
# — breaking the "CE MAC from the DF only" steady state M66 pins.
ip link add name "${BRIDGE}" type bridge mcast_snooping 0 2>/dev/null || true
ip link set dev "${BRIDGE}" multicast off
ip link set dev "${BRIDGE}" up

# EVPN-owned VXLAN port: nolearning + bridge-port learning off so
# fabric frames never kernel-learn unmarked rows the daemon would
# refuse to claim.
ip link add "${VXLAN}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${VXLAN}" master "${BRIDGE}"
ip link set dev "${VXLAN}" up
bridge link set dev "${VXLAN}" learning off

# CE-facing attachment circuit, kernel learning on (default),
# interface multicast off (see the bridge comment above).
ip link set dev eth2 multicast off
ip link set dev eth2 master "${BRIDGE}"
ip link set dev eth2 up

# Optional underlay route (each PE reaches the far PE's subnet
# through the vtep hub).
if [ $# -ge 4 ]; then
    ip route add "$3" via "$4" 2>/dev/null || true
fi

# Live config from the read-only template (idempotent on re-exec).
mkdir -p /var/lib/rustbgpd
if [ -f /etc/rustbgpd/config.template.toml ]; then
    cp /etc/rustbgpd/config.template.toml /etc/rustbgpd/config.toml
fi

# Start rustbgpd. nohup + & so the exec returns immediately and
# `sleep infinity` (the container's PID 1) keeps the netns alive.
nohup /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml \
    >/var/log/rustbgpd.log 2>&1 &
echo $! >/var/run/rustbgpd.pid

# Tiny pause so the first containerlab `docker exec` finds rustbgpd
# already up.
sleep 1
