#!/bin/sh
# rustbgpd ESI-segment PE setup — M38.
#
# Pre-creates a minimal br${VNI} bridge (no VXLAN port — the M38
# smoke is control-plane focused on DF election visibility, not
# VXLAN data-plane forwarding) so the EVPN instance reaches Ready
# and the segment orchestrator can run election.
#
# Then starts rustbgpd. The driver scrapes Prometheus on each PE
# and asserts the elected DF role flips when the lower-IP PE
# departs.
#
# Args:
#   $1 = VNI (24-bit; must match config evpn_instances.vni)

set -eu

if [ $# -lt 1 ]; then
    echo "usage: start-rustbgpd-segment.sh <vni>" >&2
    exit 1
fi

VNI="$1"
BRIDGE="br${VNI}"

ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${BRIDGE}" up

nohup /usr/local/bin/rustbgpd /etc/rustbgpd/config.toml \
    >/var/log/rustbgpd.log 2>&1 &

sleep 1
