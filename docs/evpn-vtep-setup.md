# EVPN VTEP kernel setup (operator guide)

rustbgpd is **observe-only by default** for kernel netdev topology. It
programs and reconciles FDB / L3 FIB state on top of interfaces you
provide. ADR-0091 adds an explicit opt-in exception for Linux bridge,
fixed-VNI VXLAN, VLAN upper, VRF, and L3VXLAN create/adopt/reap through
`[managed_netdevs]`. SVD / collect-metadata VXLAN lifecycle creation remains
operator-provisioned.
You normally provision topology
with your host's network layer (`ip link`, ifupdown2, systemd-networkd,
NetworkManager, SONiC, a CNI, ansible, …); rustbgpd probes it each
reconcile pass and reports its state until it matches the configured
model.

Two independent readiness surfaces govern this:

| Surface | Covers | Spec | Status via |
|---------|--------|------|-----------|
| L2VNI bridge/VXLAN probe | `[[evpn_instances]]` | ADR-0054 §4 | `rbgp evpn instances` |
| IP-VRF / L3VNI predicates | `[[evpn_ip_vrfs]]` | ADR-0058 §3 | `rbgp evpn vrfs [NAME]` |

Ethernet Segments (`[[ethernet_segments]]`) are **control-plane only**
(Type 1/4 origination) and do **not** probe a kernel netdev — see
[Multi-homing](#multi-homing-ethernet-segments).

The authoritative recipes this guide is derived from live in
`tests/interop/scripts/start-rustbgpd-vtep.sh` (L2VNI) and
`start-frr-vtep-mh.sh` (the multi-homed bond). Keep this doc in sync
with those and with the probe code in `crates/evpn-linux/src/linux/probe.rs`.

## Prerequisites

- Linux kernel with VXLAN + bridge + VRF support.
- `CAP_NET_ADMIN` for the `ip link` commands.
- A routed underlay reachable on each VTEP's `local_vtep_ip`.
- VXLAN UDP destination port **4789** (IANA / EVPN) open in the underlay.
  The Linux default is `8472`; you must set `dstport 4789` to interop
  with FRR and most EVPN peers.

## L2VNI VTEP (Type 2 / MAC-VRF)

For each `[[evpn_instances]]` entry that should bind to the Linux
dataplane. The bridge name is **operator-chosen** and must equal the
`bridge` field in that instance — it does **not** have to be `br<vni>`;
the convention below just keeps names readable.

```bash
VNI=100
LOCAL_IP=10.0.0.1          # must equal [[evpn_instances]].local_vtep_ip
BRIDGE=br100               # must equal [[evpn_instances]].bridge
VXLAN=vxlan100

# Default legacy bridge for one VNI. Omit bridge_vlan in the rustbgpd
# config for this shape. Set vlan_filtering explicitly rather than relying
# on the kernel default.
ip link add name "${BRIDGE}" type bridge vlan_filtering 0
ip link set dev "${BRIDGE}" up

# VXLAN port. `nolearning` hands FDB ownership to EVPN — rustbgpd owns
# the bridge FDB and the kernel must not also learn. `local` must match
# local_vtep_ip; `dstport 4789` is required for EVPN interop.
ip link add "${VXLAN}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning
ip link set dev "${VXLAN}" master "${BRIDGE}"
ip link set dev "${VXLAN}" up
```

For ADR-0089's VLAN-aware VNI-per-broadcast-domain shape, set
`bridge_vlan = <VID>` on the instance, create the bridge with
`vlan_filtering=1`, and make the configured VLAN present on both the
bridge and the matching VXLAN member:

```bash
VID=100

ip link add name "${BRIDGE}" type bridge vlan_filtering 1
ip link set dev "${BRIDGE}" up
ip link add "${VXLAN}" type vxlan \
    id "${VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning
ip link set dev "${VXLAN}" master "${BRIDGE}"
bridge vlan add dev "${BRIDGE}" vid "${VID}" self
bridge vlan add dev "${VXLAN}" vid "${VID}"
ip link set dev "${VXLAN}" up
```

If you **omit** `bridge` from the instance config, that L2VNI is
control-plane only (RR-style): the probe reports `Unbound` and rustbgpd
programs no kernel FDB for it. Don't create the bridge in that case.

### L2VNI readiness predicates (ADR-0054 §4)

`probe_one` in `crates/evpn-linux/src/linux/probe.rs` reports the
instance `Ready` only when all hold (otherwise `NotReady{reason}`):

| # | Predicate | Satisfied by |
|---|-----------|--------------|
| 1 | `bridge` exists in the kernel | `ip link add … type bridge` |
| 2a | without `bridge_vlan`: bridge is **not** VLAN-aware (`vlan_filtering=0`) and has exactly one VXLAN port | `type bridge vlan_filtering 0`; one `set master ${BRIDGE}` |
| 2b | with `bridge_vlan`: bridge is VLAN-aware (`vlan_filtering=1`), exactly one VXLAN member has the instance VNI, and the configured VLAN is present on both bridge and VXLAN member | `type bridge vlan_filtering 1`; `bridge vlan add dev ${BRIDGE} vid ${VID} self`; `bridge vlan add dev ${VXLAN} vid ${VID}` |
| 3 | VXLAN `IFLA_VXLAN_ID` == instance `vni` | `id ${VNI}` |
| 4 | VXLAN local IP == instance `local_vtep_ip` | `local ${LOCAL_IP}` |
| 5 | VXLAN `nolearning` (learning disabled) | `nolearning` |

(No `bridge` configured ⇒ `Unbound`, not `NotReady`.)

`bridge_vlan` is not the EVPN Ethernet Tag; Type 2 / Type 3 /
EAD-per-EVI routes remain Ethernet Tag ID `0`. It is the local Linux VLAN
selector used for readiness and for `NDA_VLAN` on remote-MAC FDB writes.

### MAC+IP origination (ARP/ND suppression)

To originate Type 2 routes carrying the host IP (MAC+IP), enable
neighbour suppression on the VXLAN port so the kernel surfaces snooped
`(IP, MAC)` bindings instead of flooding ARP/ND:

```bash
bridge link set dev "${VXLAN}" neigh_suppress on
```

rustbgpd then correlates `RTNLGRP_NEIGH` updates into MAC+IP Type 2
origination under the FRR-style replace model (one Type 2 per MAC;
`IpAdded` upgrades MAC-only → MAC+IP). Without `neigh_suppress on`,
only MAC-only Type 2 routes are originated.

### SVI MAC

Set `advertise_svi_mac = true` on the instance to originate a Type 2 for
the bridge's own MAC (RFC 9135 §6.1). This requires `bridge` to be set;
rustbgpd reads the bridge MAC from the probe — no extra netdev step.

## IP-VRF / L3VNI VTEP (Type 5 / symmetric IRB)

For each `[[evpn_ip_vrfs]]` entry. All seven ADR-0058 §3 predicates must
hold for the IP-VRF to be `Ready`.

```bash
VRF=vrf-blue               # [[evpn_ip_vrfs]].vrf_device
TABLE=5000                 # [[evpn_ip_vrfs]].table_id
L3VNI=5000                 # [[evpn_ip_vrfs]].vni
LOCAL_IP=10.0.0.100        # [[evpn_ip_vrfs]].local_vtep_ip
RMAC=02:00:00:00:00:01     # [[evpn_ip_vrfs]].router_mac
L3VXLAN=vni5000            # [[evpn_ip_vrfs]].l3vxlan_device

# VRF device bound to the route table.
ip link add "${VRF}" type vrf table "${TABLE}"
ip link set dev "${VRF}" up

# L3 VXLAN device: configured Router MAC, enslaved to the VRF.
ip link add "${L3VXLAN}" type vxlan \
    id "${L3VNI}" \
    dstport 4789 \
    local "${LOCAL_IP}" \
    nolearning
ip link set dev "${L3VXLAN}" address "${RMAC}"
ip link set dev "${L3VXLAN}" master "${VRF}"
ip link set dev "${L3VXLAN}" up
```

Symmetric IRB also needs the L3 VXLAN's MAC-VRF bridge plumbing (a
bridge for the L3VNI on hosts that bridge the L3VXLAN); the exact L2
attachment is environment-specific. Validate against your topology — the
predicate table below is the contract rustbgpd checks.

### IP-VRF readiness predicates (ADR-0058 §3)

| # | Predicate | Satisfied by |
|---|-----------|--------------|
| 1 | `vrf_device` exists + UP | `ip link add … type vrf` + `set up` |
| 2 | `vrf_device` `IFLA_VRF_TABLE` == `table_id` | `type vrf table ${TABLE}` |
| 3 | `l3vxlan_device` exists + UP | `ip link add … type vxlan` + `set up` |
| 4 | `l3vxlan_device` `IFLA_VXLAN_ID` == L3VNI | `id ${L3VNI}` |
| 5 | `IFLA_VXLAN_LOCAL`(`6`) == `local_vtep_ip` | `local ${LOCAL_IP}` |
| 6 | `IFLA_MASTER` == `vrf_device` | `set master ${VRF}` |
| 7 | link-layer addr == `router_mac` | `set address ${RMAC}` |

## Multi-homing (Ethernet Segments)

rustbgpd's `[[ethernet_segments]]` is **control-plane only**: when the
EVPN reconcile actor is running it originates Type 4 (ES route), Type 1
EAD-per-ES, and Type 1 EAD-per-EVI for the configured ESI over its
`member_vnis`, and runs DF election. It does **not** probe or require a
kernel bond/ES netdev — there is no ES readiness gate. Optionally, an
`interface = "<linkname>"` binding (ADR-0085) makes the ES's drain
state follow that link's carrier — an AC failure then withdraws the
ES routes automatically (see the drain section in
`docs/evpn-vtep-troubleshooting.md`); this watches the named link's
carrier but still gates nothing at startup beyond the drain itself.

What you still provide:

- Each `member_vnis` entry must be a configured `[[evpn_instances]]`
  with its L2VNI bridge/VXLAN set up per the [L2VNI](#l2vni-vtep-type-2--mac-vrf)
  recipe.
- The actual multi-homed **access link** (the LAG/bond that attaches the
  dual-homed host or switch to this VTEP and its peer) is ordinary host
  L2 configuration, outside the readiness model. For a worked LACP-bond
  example, see `tests/interop/scripts/start-frr-vtep-mh.sh`.
- Both VTEPs sharing the segment must advertise the **same 10-byte ESI**
  (`esi` in config).

## Verifying

```bash
rbgp evpn instances        # L2VNI view (Ready / NotReady / Unbound / Unknown)
rbgp evpn vrfs <name>      # IP-VRF readiness_state + not_ready_reasons
rbgp evpn vrfs <name>      #   also: remote_prefix_drop_counts
```

`NotReady` L2VNI rows include the single failing probe reason on
`rbgp evpn instances`; `Unknown` means a bound instance has no dataplane
verdict yet; `NotReady` IP-VRF rows enumerate predicate failures on
`rbgp evpn vrfs`. The reconcile actor logs the `Ready` ↔ `NotReady`
transition once per state change (not every pass).

## Common pitfalls

| Symptom | Cause | Fix |
|---------|-------|-----|
| L2VNI `NotReady` "VLAN-aware" | bridge created with `vlan_filtering=1` but instance has no `bridge_vlan` | set `bridge_vlan` and add the VLAN membership, or recreate with `vlan_filtering 0` |
| L2VNI `NotReady` "learning enabled" | VXLAN missing `nolearning` | recreate the VXLAN with `nolearning` |
| L2VNI `NotReady` "local IP …" | `local` ≠ `local_vtep_ip` | match the config |
| L2VNI `NotReady` ">1 VXLAN port" | legacy instance has multiple VXLANs on one bridge, or `bridge_vlan` instance has multiple VXLANs for the same VNI | legacy: one VXLAN per bridge; VLAN-aware: one VXLAN member per VNI |
| L2VNI `Unbound` unexpectedly | `bridge` omitted from config | set `bridge` if you want dataplane binding |
| IP-VRF predicate 6/7 fails | L3VXLAN not enslaved to VRF, or wrong MAC | `set master ${VRF}` / `set address ${RMAC}` |
| IP-VRF predicate 2 fails | VRF table id ≠ `table_id` | `type vrf table ${TABLE}` |

## See also

- `docs/CONFIGURATION.md` — `[[evpn_instances]]` / `[[evpn_ip_vrfs]]` /
  `[[ethernet_segments]]` fields and full predicate definitions.
- `docs/evpn-vtep-troubleshooting.md` — diagnosing `NotReady` and
  receive-path drops.
- `tests/interop/scripts/start-rustbgpd-vtep.sh` — the working L2VNI
  recipe this guide is derived from.
- `tests/interop/scripts/start-frr-vtep-mh.sh` — multi-homed bond example.
