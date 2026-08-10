# EVPN VTEP leaf (Phase-2 alpha)

Leaf-mode rustbgpd config: an iBGP peering to one or more spine route
reflectors, plus three local **EVPN instances** declared in TOML. This
is the operator-facing surface of the Gate 7a / 7b / 7b+1 bidirectional
VTEP alpha path: the daemon consumes the resolved `[[evpn_instances]]`
table to program remote Type 2 routes into the Linux bridge FDB,
originate Type 2 routes from kernel-learned local MACs, and emit one
Type 3 IMET per configured L2VNI.

For the route-reflector counterpart — same fabric, no local EVIs —
see [`../rr-evpn-fabric/`](../rr-evpn-fabric/).

## What this example demonstrates

- **iBGP session to a spine RR** with `families = ["l2vpn_evpn"]`. No
  local EVI state on the RR; the leaf owns its own.
- **Three `[[evpn_instances]]` blocks** showing the full operator
  surface:
  - **VNI 10100** — the core shape: `vni`, `rd`, `route_targets`,
    `local_vtep_ip`, with `bridge` set to `br100` for the Linux
    dataplane reconciler. Also demonstrates `sticky_macs` (two pinned
    anycast-gateway MACs) and `duplicate_mac_detection` (detect-only,
    RFC 7432 defaults).
  - **VNI 10200** — adds `advertise_svi_mac = true` (RFC 9135 §6.1).
    The Linux dataplane captures the bridge link-layer address,
    surfaces it on `InstanceDataplaneStatus.bridge_mac`, and the
    daemon's SVI task originates a Type 2 for the bridge MAC on
    instance-Ready; withdraws on `Ready → NotReady` or bridge MAC drift.
  - **VNI 10300** — uses a 4-octet AS in the RD (`4200000000:300` →
    RFC 4364 Type 2 RD); two route targets to demonstrate the
    bidirectional list (deduplicated and canonicalized on
    resolution).

## Verifying the config

```bash
# Validate the schema, RD/RT parsing, VTEP-IP unicast check, and
# uniqueness invariants without starting the daemon.
rustbgpd --check --strict examples/evpn-vtep-leaf/config.toml

# Preview against another config.
rustbgpd --diff examples/rr-evpn-fabric/config.toml \
                examples/evpn-vtep-leaf/config.toml
```

The starter config is expected to pass strict validation without warnings.

Most `[[evpn_instances]]` edits now **hot-apply** at runtime via the
ADR-0063 EVPN runtime coordinator — through both SIGHUP file-driven reload
and the gRPC `EvpnService.ApplyEvpnRuntime`. `--diff` classifies each edit
as **reload-applied** or **restart-required**. What stays restart-required is
IP-VRF L3VNI/device/table identity redefines (kernel VRF identity lifecycle),
plus the shapes the plan decomposer's fixed phase order cannot express: a
relink away from an IP-VRF deleted in the same candidate, a relink onto an
IP-VRF added in the same candidate, and an Ethernet Segment left memberless
mid-sequence. Every other mixed ES / IP-VRF edit hot-applies through the
decomposer, one committed runtime generation per step. See ADR-0063,
`docs/reload-matrix.md`, and `KNOWN_ISSUES.md`.

## Pre-create the Linux bridge/VXLAN devices

rustbgpd does not create bridge or VXLAN netdevs by default — this example
pre-creates them out of band. To have the daemon own their lifecycle instead,
opt into the ADR-0091 `[[managed_netdevs.bridges]]` / `[[managed_netdevs.vxlans]]`
rows (status via `rbgp evpn managed-netdevs`); that table is restart-required.

For a legacy instance (`bridge_vlan` unset, the shape this example uses) the
readiness probe requires:

- bridge exists;
- bridge VLAN filtering is disabled;
- exactly one VXLAN port is enslaved to the bridge;
- VXLAN VNI matches the `[[evpn_instances]].vni`;
- VXLAN local IP matches `local_vtep_ip`;
- VXLAN learning is disabled.

On a `vlan_filtering=1` bridge, set `[[evpn_instances]].bridge_vlan` instead —
the ADR-0089 VLAN-aware path then selects either a fixed-VNI VXLAN member or a
collect-metadata / SVD member via the bridge VLAN tunnel mapping.

Example for the first instance (`vni = 10100`, `bridge = "br100"`,
`local_vtep_ip = "10.0.0.10"`):

```bash
sudo ip link add br100 type bridge vlan_filtering 0
sudo ip link set br100 up

sudo ip link add vxlan10100 type vxlan \
  id 10100 local 10.0.0.10 dstport 4789 nolearning
sudo ip link set vxlan10100 master br100
sudo ip link set vxlan10100 up

# Optional local access port for testing kernel-learned local MAC
# origination. Production hosts usually enslave a real NIC, bond, or
# tap interface instead.
sudo ip link add veth10100a type veth peer name veth10100b
sudo ip link set veth10100a master br100
sudo ip link set veth10100a up
sudo ip link set veth10100b up
```

Repeat the same pattern for `br200` / VNI `10200` and any other
configured instance, changing the bridge, VXLAN device name, VNI, and
local VTEP IP as needed.

## Inspecting at runtime

```bash
# Human format
rbgp evpn instances

# JSON for scripting
rbgp evpn instances --json
```

Expected output (human format):

```
vni=10100 rd=10.0.0.10:10100 vtep=10.0.0.10 rts=[65000:10100] readiness=ready bridge=br100 originated-local-macs=0
vni=10200 rd=10.0.0.10:10200 vtep=10.0.0.10 rts=[65000:10200] readiness=ready bridge=br200 advertise-svi-mac originated-local-macs=0
vni=10300 rd=4200000000:300 vtep=10.0.0.10 rts=[65000:10300,65000:55000] readiness=unbound originated-local-macs=0
```

VNI 10300 has no `bridge` binding in this config, so it reports
`readiness=unbound` — the probe does not apply to it. Add a `bridge` key (and
the matching netdevs) to move it to `ready`.

The same state plus route/metric presence can be summarized with:

```bash
rbgp evpn diagnose
```

## What this example does NOT do (yet)

- Create Linux bridge or VXLAN netdevs for you: it declares no
  `[managed_netdevs]` rows, so the ADR-0091 lifecycle is off here.
- Enforce RFC 7432 §15 duplicate-MAC quarantine beyond what ships today:
  detect-only quarantine (detection metrics exposed) plus the optional
  `action = "suppress_local"` enforcement both ship. The M/N detector
  withdraws and suppresses local Type 2 originations for the duplicate MAC
  until recovery, clearable via `rbgp evpn clear-duplicate-mac`.
- Configure an IP-VRF / L3VNI tenant. Gate 9 Type 5 origination and
  symmetric Interface-less IRB dataplane programming ship in the main daemon
  (`[[evpn_ip_vrfs]]`, `rbgp evpn vrfs`, M39), but this example is kept
  as a single-homed L2VNI leaf and intentionally omits the L3VNI/VRF pieces.

## Related

- [`../rr-evpn-fabric/`](../rr-evpn-fabric/) — RR-side counterpart
- [`../../docs/adr/0052-evpn-vtep-foundation.md`](../../docs/adr/0052-evpn-vtep-foundation.md) — boundaries between this slice and the future dataplane crate
- [`../../docs/evpn-enablement.md`](../../docs/evpn-enablement.md) — Gate 7a / 7b roadmap
- [`../../KNOWN_ISSUES.md`](../../KNOWN_ISSUES.md) — `[[evpn_instances]]` SIGHUP semantics
