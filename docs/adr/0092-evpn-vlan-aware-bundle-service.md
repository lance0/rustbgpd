# ADR-0092: EVPN VLAN-Aware Bundle service (non-zero Ethernet Tag)

**Status:** Accepted
**Date:** 2026-06-19

## Context

ADR-0089 shipped Linux `vlan_filtering=1` bridge support for rustbgpd's
existing VNI-per-broadcast-domain EVPN model. That model realizes the RFC 7432
VLAN-Based Service Interface on a Linux VLAN-aware bridge topology: each
`[[evpn_instances]]` row is one EVI / VNI / broadcast domain, and EVPN
Ethernet Tag ID stays `0` for Type 2 MAC/IP, Type 3 IMET, and EAD-per-EVI
routes.

That is not the RFC VLAN-Aware Bundle Service Interface. In VLAN-Aware Bundle,
one MAC-VRF / EVI contains multiple bridge tables, and Ethernet Tag ID
identifies the bridge table / VLAN within the bundle. RFC 7432 sets the
service-interface semantics, and RFC 8365 carries them into VXLAN: for the
VLAN-Aware Bundle Service, Ethernet Tag in MAC Advertisement, EAD-per-EVI,
and IMET routes identifies a bridge table within a MAC-VRF and must be
configured consistently on all participating PEs.

This distinction matters operationally. Linux VLAN-aware bridges, traditional
multi-VXLAN layouts, and SVD/collect-metadata VXLAN are dataplane topology
shapes. They do not by themselves imply non-zero EVPN Ethernet Tag semantics.
FRRouting documents its MAC-VRF behavior as the RFC 7432 VLAN-Based Service
Interface. NVIDIA/Cumulus VLAN-to-VNI and SVD documentation is useful Linux
topology evidence, but it is not proof that the true non-zero-tag bundle
service is implemented.

rustbgpd already preserves Ethernet Tag on the wire/RIB key for Type 1/2/3/5
EVPN NLRIs. The missing work is making that field load-bearing in the domain
and dataplane model. Today the L2 desired-state table intentionally collapses
remote MACs to `(VNI, MAC)` because ADR-0089 keeps Ethernet Tag `0`.

## Decision

### 1. Bundle service is an explicit opt-in service-interface mode

The default remains ADR-0089 VLAN-Based Service over Linux VLAN-aware bridge
topologies. True VLAN-Aware Bundle is selected explicitly, for example:

```toml
[[evpn_bundle_instances]]
name = "bundle-blue"
rd = "65000:100"
import_route_targets = ["65000:100"]
export_route_targets = ["65000:100"]
service_interface = "vlan_aware_bundle"

[[evpn_bundle_instances.members]]
ethernet_tag = 10
bridge = "br_default"
bridge_vlan = 10
vni = 10010

[[evpn_bundle_instances.members]]
ethernet_tag = 20
bridge = "br_default"
bridge_vlan = 20
vni = 10020
```

The final schema can differ, but the model is fixed:

```text
(EVI / RD / RT set, Ethernet Tag) -> (bridge, bridge_vlan, VNI)
```

`bridge_vlan` remains a local Linux selector. It is not reinterpreted as an
EVPN Ethernet Tag field.

### 2. Ethernet Tag becomes route identity in bundle mode

In bundle mode, Ethernet Tag is load-bearing for at least:

- Type 2 MAC/IP Advertisement routes;
- Type 3 IMET routes;
- Type 1 EAD-per-EVI routes.

Import/export selection, route projection, event history, API/status surfaces,
and dataplane desired state must preserve isolation by `(EVI, Ethernet Tag)`.
Two members of the same bundle may carry the same MAC address in different
tags without collapsing into one `(VNI, MAC)` entry.

The existing wire key already contains Ethernet Tag. The domain collapse points
that must be lifted include the remote-MAC desired table and projection paths
that currently stage by `(VNI, MAC)`.

### 3. Type 5 with non-zero Ethernet Tag is deferred from the MVP

RFC 9136 Type 5 routes carry Ethernet Tag in the route key, so bundle-mode
L3 behavior cannot be ignored forever. It is nevertheless out of the MVP for
this ADR's first implementation tranche.

The first bundle slice must either:

- reject Type 5 routes with non-zero Ethernet Tag in bundle mode with an
  observable fail-closed reason, or
- land a separate L3 follow-on ADR that defines the Type 5 semantics before
  enabling them.

No Type 5 bundle behavior is authorized implicitly by Type 2/3 support.

### 4. Multi-homing is tag-scoped but deferred from the MVP

The service principle is clear: EAD-per-EVI, aliasing, DF election,
single-active backup, mass-withdraw, and all-active Type 5 overlay-index
behavior become scoped by `(ESI, EVI, Ethernet Tag)`.

The initial bundle implementation must fail closed for multi-homing shapes it
cannot prove. Full tag-scoped multi-homing requires a follow-on ADR or a later
accepted extension to this one.

### 5. Coexistence and migration are explicit

Tag-0 ADR-0089 instances and bundle instances may coexist across different
EVIs/RDs. They must not both claim the same local `(bridge, bridge_vlan)` or
same `(EVI, Ethernet Tag)` identity.

Migration from Tag-0 VNI-per-BD to bundle mode is not an in-place semantic
reinterpretation. Operators configure a new bundle EVI/member map, validate
readiness/import behavior, and then move traffic deliberately.

## Consequences

### Positive

- Gives the true RFC VLAN-Aware Bundle service a precise boundary instead of
  conflating it with Linux VLAN-aware bridge topology.
- Preserves the shipped ADR-0089 behavior and interop receipts.
- Makes the necessary blast radius explicit before code starts: route identity,
  projection, API/status, event history, dataplane desired state, and
  multi-homing all need tag-aware handling.

### Negative

- This is a large, multi-sprint feature if implemented.
- FRR/Cumulus-style Linux topology docs do not provide the non-zero-tag
  interop proof; a different peer/proof target is needed.
- Multi-homing and Type 5 cannot be safely bundled into the first slice
  without expanding the design substantially.

## Dependencies and relationships

- **Builds on:** ADR-0089 (Linux VLAN-aware bridge and VLAN-scoped FDB
  substrate), existing Ethernet Tag wire/RIB keying, and the EVPN API/status
  surfaces.
- **Independent of:** ADR-0091 (managed netdev creation) and ADR-0093
  (raw bridge MAC+IP correlation).
- **Feeds into:** future tag-scoped multi-homing and Type 5 bundle decisions.

## Rejected Alternatives

### Treat Linux VLAN-aware bridge support as VLAN-Aware Bundle

Rejected. A Linux `vlan_filtering=1` bridge is a topology shape, not an EVPN
service-interface model. ADR-0089 deliberately keeps Ethernet Tag `0`.

### Use `bridge_vlan` as Ethernet Tag

Rejected. `bridge_vlan` is local Linux attribution. Turning it into wire
identity would change import/export, interop, and route-key semantics for
existing ADR-0089 deployments.

### Silently widen only the dataplane key

Rejected. Bundle mode is not just FDB programming. Import/export, route
projection, API/status, event history, and Add-Path safety all need the same
identity model.

### Include multi-homing in the MVP by default

Rejected for the first implementation tranche. Multi-homing is tag-scoped in
principle, but the DF/aliasing/mass-withdraw consequences deserve their own
proofs.

## Implementation Plan

1. Add the bundle config/domain model and validation:
   `service_interface = "vlan_aware_bundle"` plus explicit member maps.
2. Add route projection/import/export isolation by `(EVI, Ethernet Tag)`.
3. Add Type 2 / Type 3 / EAD-per-EVI origination and receive behavior for
   non-zero Ethernet Tag.
4. Reuse ADR-0089 Linux FDB machinery through an explicit
   `(EVI, Ethernet Tag) -> (bridge_vlan, VNI)` resolution layer.
5. Extend API/status/event-history output so operators can see service mode
   and Ethernet Tag.
6. Add a cross-vendor non-zero-tag bundle interop receipt.
7. Decide Type 5 and multi-homing follow-ons.

## Test Obligations

- Wire round-trip tests proving non-zero Ethernet Tag remains preserved for
  Type 1/2/3/5.
- Projection tests where two tags in one EVI carry the same MAC without
  collapsing.
- Import/export tests proving `(EVI, Tag)` isolation.
- Linux dataplane tests proving the member map resolves to the right
  VLAN-scoped FDB rows.
- Fail-closed tests for unsupported Type 5 and multi-homing bundle shapes.
- Cross-vendor receipt with a peer that advertises and accepts non-zero
  Ethernet Tag bundle routes.

## References

- RFC 7432 §6.1-§6.3, EVPN service-interface models.
  <https://www.rfc-editor.org/rfc/rfc7432.html#section-6>
- RFC 8365 §5.1.3, VXLAN/NVO3 service-interface mapping.
  <https://www.rfc-editor.org/rfc/rfc8365.html#section-5.1.3>
- RFC 9136, Type 5 IP Prefix route behavior.
  <https://www.rfc-editor.org/rfc/rfc9136.html>
- FRRouting EVPN documentation, documenting MAC-VRFs as VLAN-Based Service.
  <https://docs.frrouting.org/en/latest/evpn.html>
- Nokia SR Linux VLAN-aware bundle documentation, including non-zero
  `vlan-aware-bundle-eth-tag` behavior.
  <https://documentation.nokia.com/srlinux/24-10/books/vpn-services/evpn-interoperability-with-vlan-aware-bundle-services.html>
