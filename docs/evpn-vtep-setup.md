# EVPN VTEP kernel setup (operator guide)

> **Status: stub.** Core L2VNI recipe is grounded in the interop
> harness; the IP-VRF / multi-homing sections are skeletons and need
> validation + worked examples before this is operator-complete.

rustbgpd is **observe-only** for kernel netdev topology. It programs and
reconciles FDB / L3 FIB state on top of interfaces you provide, but it
does **not** create or delete the bridge, VXLAN, VRF, or Ethernet
Segment netdevs (ADR-0063 non-goals; ADR-0054 §4). You provision those
with your host's network layer (`ip link`, ifupdown2, systemd-networkd,
NetworkManager, SONiC, a CNI, ansible, …); rustbgpd reports
`NotReady{reasons}` until they match the configured model.

This guide maps each readiness predicate to the command that satisfies
it. The authoritative recipe lives in
`tests/interop/scripts/start-rustbgpd-vtep.sh` (L2VNI) and the
ADR-0058 §3 predicate list; keep this doc in sync with both.

## Prerequisites

- Linux kernel with VXLAN + bridge + VRF support.
- `CAP_NET_ADMIN` for the `ip link` commands.
- A routed underlay reachable on the VTEP's `local_vtep_ip`.
- VXLAN UDP dest port `4789` (IANA) open in the underlay.

## L2VNI VTEP (Type 2 / MAC-VRF)

For each `[[evpn_instances]]` entry (`vni`, `local_vtep_ip`, optional
`bridge`):

```bash
VNI=100
LOCAL_IP=10.0.0.1          # must equal [[evpn_instances]].local_vtep_ip

# Bridge for the VNI. NOT vlan-aware — the Gate 7b probe rejects
# vlan_filtering=1.
ip link add name "br${VNI}" type bridge
ip link set dev "br${VNI}" up

# VXLAN port. `nolearning` hands FDB ownership to EVPN (rustbgpd owns
# the bridge FDB; the kernel must not also learn).
ip link add "vxlan${VNI}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning
ip link set dev "vxlan${VNI}" master "br${VNI}"
ip link set dev "vxlan${VNI}" up
```

<!-- TODO: MAC+IP (Type 2 with IP) origination needs ARP/ND suppression:
     `bridge link set dev vxlanNNN neigh_suppress on`. Document the
     access-port / SVI side and the neighbor-table prerequisites. -->

## IP-VRF / L3VNI VTEP (Type 5 / symmetric IRB)

> **TODO: stub — validate against a real L3 setup before relying on it.**

For each `[[evpn_ip_vrfs]]` entry the seven ADR-0058 §3 predicates must
all hold. Skeleton:

```bash
VRF=vrf-blue
TABLE=5000                 # [[evpn_ip_vrfs]].table_id
L3VNI=5000                 # [[evpn_ip_vrfs]].vni
LOCAL_IP=10.0.0.100        # [[evpn_ip_vrfs]].local_vtep_ip
RMAC=02:00:00:00:00:01     # [[evpn_ip_vrfs]].router_mac
L3VXLAN=vni${L3VNI}

# VRF device bound to the route table.
ip link add "${VRF}" type vrf table "${TABLE}"
ip link set dev "${VRF}" up

# L3 VXLAN device, enslaved to the VRF, with the configured Router MAC.
ip link add "${L3VXLAN}" type vxlan id "${L3VNI}" dstport 4789 \
    local "${LOCAL_IP}" nolearning
ip link set dev "${L3VXLAN}" address "${RMAC}"
ip link set dev "${L3VXLAN}" master "${VRF}"
ip link set dev "${L3VXLAN}" up
```

### Readiness predicate → command map

| # | Predicate (ADR-0058 §3) | Satisfied by |
|---|-------------------------|--------------|
| 1 | `vrf_device` exists + UP | `ip link add … type vrf` + `set up` |
| 2 | `vrf_device` `IFLA_VRF_TABLE` == `table_id` | `type vrf table ${TABLE}` |
| 3 | `l3vxlan_device` exists + UP | `ip link add … type vxlan` + `set up` |
| 4 | `IFLA_VXLAN_ID` == L3VNI | `id ${L3VNI}` |
| 5 | `IFLA_VXLAN_LOCAL` == `local_vtep_ip` | `local ${LOCAL_IP}` |
| 6 | `IFLA_MASTER` == `vrf_device` | `set master ${VRF}` |
| 7 | link-layer addr == `router_mac` | `set address ${RMAC}` |

## Multi-homing (Ethernet Segment)

<!-- TODO: bond/LAG + ES interface setup, ESI derivation, and how it
     maps to [[ethernet_segments]]. Reference start-frr-vtep-mh.sh. -->

## Verifying

```bash
rustbgpctl evpn vrfs <name>     # readiness_state + not_ready_reasons
rustbgpctl evpn instances       # L2VNI view
```

If a VRF stays `NotReady`, the `not_ready_reasons` list names exactly
which predicate failed — see `docs/evpn-vtep-troubleshooting.md`.

## See also

- `docs/CONFIGURATION.md` — `[[evpn_instances]]` / `[[evpn_ip_vrfs]]`
  fields and the full predicate definitions.
- `docs/evpn-vtep-troubleshooting.md` — diagnosing `NotReady` and
  receive-path drops.
- `tests/interop/scripts/start-rustbgpd-vtep.sh` — the working L2VNI
  recipe this guide is derived from.
