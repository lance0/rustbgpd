#!/bin/sh
# FRR VTEP setup WITH EVPN multi-homing — extends start-frr-vtep.sh with
# a dummy access interface that carries the Ethernet Segment config.
#
# Args:
#   $1 = VTEP tunnel source IP (eth1 address)
#   $2 = VNI (24-bit)
#   $3 = ES-ID (1..16M)
#   $4 = ES-SYS-MAC (48-bit, colon-separated)
#   $5 = optional FRR EVPN MH DF preference (1..16777215)
#
# Layout built (on top of the plain VTEP layout):
#   esdummy        : LACP bond device attached to the bridge — the FRR-
#                    supported shape for an EVPN-MH ES. `evpn mh es-id`
#                    + `evpn mh es-sys-mac` configured on this device
#                    register the ES as local. A plain dummy attached
#                    to the bridge does not reliably register (FRR's
#                    behavior on non-bond ES interfaces is undocumented
#                    and racy across runs).
#   esdummy-slave  : single dummy enslaved to the bond so it has at
#                    least one member. Real EVPN-MH expects a hardware
#                    bond with an LACP partner; a no-partner bond with
#                    a dummy slave is enough for FRR to emit the local
#                    ES and originate Type 1 EAD-per-EVI + Type 4 ES.
#
# Two VTEPs launched with the same (es-id, es-sys-mac) form a shared
# Ethernet Segment; both advertise ES routes with the same 10-byte ESI
# derived from es-sys-mac + es-id per RFC 7432 §5 (ESI Type 3).

set -eu

if [ $# -lt 4 ]; then
    echo "usage: start-frr-vtep-mh.sh <loopback-ip> <vni> <es-id> <es-sys-mac> [df-pref]" >&2
    exit 1
fi

LOCAL_IP="$1"
VNI="$2"
ES_ID="$3"
ES_SYS_MAC="$4"
DF_PREF="${5:-}"
BRIDGE="br${VNI}"
VXLAN="vxlan${VNI}"
ES_DUMMY="esdummy"

# --- Standard VTEP: bridge + VXLAN interface with nolearning ---
# Non-VLAN-aware bridge — VNI is implicit (one VNI per bridge). A
# VLAN-aware bridge would let FRR auto-bind the ES to a specific EVI
# and origination Type 1 EAD-per-EVI routes, but that requires SVI
# sub-interfaces and a richer FRR config that's out of scope for the
# Phase 1 multi-homing reflection test.
ip link add name "${BRIDGE}" type bridge 2>/dev/null || true
ip link set dev "${BRIDGE}" up

ip link add "${VXLAN}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning 2>/dev/null || true
ip link set dev "${VXLAN}" master "${BRIDGE}"
ip link set dev "${VXLAN}" up

# --- Multi-homing extension: bond access interface attached to bridge ---
# FRR EVPN-MH expects the ES interface to be a bond — `show evpn es`
# only registers the local ES when the configured `evpn mh es-id`
# interface is a bond device. A plain dummy attached to the bridge
# is sometimes recognized and sometimes not (FRR's behavior on
# non-bond ES interfaces is undocumented and racy). Use a bond with a
# single dummy slave so the linux interface model matches what FRR
# expects without requiring a real LACP partner.
ip link add "${ES_DUMMY}-slave" type dummy 2>/dev/null || true
ip link add "${ES_DUMMY}" type bond mode 802.3ad 2>/dev/null || true
ip link set dev "${ES_DUMMY}-slave" down
ip link set dev "${ES_DUMMY}-slave" master "${ES_DUMMY}"
ip link set dev "${ES_DUMMY}-slave" up
ip link set dev "${ES_DUMMY}" master "${BRIDGE}"
ip link set dev "${ES_DUMMY}" up

ip link set dev "${BRIDGE}" up

# Apply the EVPN MH config dynamically via vtysh — putting it in
# frr.conf races with the interface creation here, and on FRR 10.3.1
# one of the two VTEPs sometimes fails to pick up the per-interface
# config when esdummy appears later. Issuing the config after the
# interface exists is reliable.
echo "start-frr-vtep-mh: local=${LOCAL_IP} vni=${VNI} es-id=${ES_ID} es-sys-mac=${ES_SYS_MAC} df-pref=${DF_PREF:-default}" >&2

# Wait briefly for FRR daemons to be reachable via vtysh.
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if vtysh -c "show version" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

apply_evpn_mh_config() {
    # `evpn mh startup-delay` lives at top-level config in FRR 10.3.1,
    # NOT under `router bgp`. Putting it under `router bgp` produces
    # "Unknown command" and silently fails — the default 180 s timer
    # then holds the ES in protodown for the entire test run.
    vtysh -c "configure terminal" \
          -c "evpn mh startup-delay 5" \
          -c "end" >/dev/null 2>&1 || true
    vtysh -c "configure terminal" \
          -c "interface ${ES_DUMMY}" \
          -c "no evpn mh es-id ${ES_ID}" \
          -c "no evpn mh es-sys-mac ${ES_SYS_MAC}" \
          -c "no evpn mh es-df-pref" \
          -c "end" >/dev/null 2>&1 || true
    if [ -n "$DF_PREF" ]; then
        vtysh -c "configure terminal" \
              -c "interface ${ES_DUMMY}" \
              -c "evpn mh es-id ${ES_ID}" \
              -c "evpn mh es-sys-mac ${ES_SYS_MAC}" \
              -c "evpn mh es-df-pref ${DF_PREF}" \
              -c "end" >/dev/null 2>&1 || true
    else
        vtysh -c "configure terminal" \
              -c "interface ${ES_DUMMY}" \
              -c "evpn mh es-id ${ES_ID}" \
              -c "evpn mh es-sys-mac ${ES_SYS_MAC}" \
              -c "end" >/dev/null 2>&1 || true
    fi
}

# FRR's per-interface EVPN-MH config has a startup race with esdummy
# creation: occasionally one of two co-deployed VTEPs ends up without
# a local ES even though the running config shows it. Reapply with
# a no/yes dance until `show evpn es` confirms a local ES, or give up
# after ~30 s. Also clamp `bgp evpn mh startup-delay` (default 180 s)
# down to 5 s so the ES exits protodown promptly — there is no LACP
# in this lab so the production safety window is unneeded.
for attempt in 1 2 3 4 5 6 7 8 9 10; do
    apply_evpn_mh_config
    sleep 3
    # The local-ES line in `show evpn es` looks like:
    #   03:aa:bb:cc:dd:ee:ff:00:00:01  L    esdummy
    # i.e. starts with the ESI hex and contains "esdummy" + an "L" type
    # marker. Match either the ESI prefix at line start OR a row that
    # references our specific ES interface — alternation grouped so it
    # doesn't read as "starts with prefix OR contains esdummy anywhere".
    if vtysh -c "show evpn es" 2>/dev/null \
        | grep -qE "^(${ES_SYS_MAC%%:*}|[0-9a-f:]+).*\b${ES_DUMMY}\b"; then
        echo "start-frr-vtep-mh: ES local on ${ES_DUMMY} after attempt ${attempt}" >&2
        break
    fi
    echo "start-frr-vtep-mh: ES not yet local on attempt ${attempt}, retrying" >&2
done

sleep 1
