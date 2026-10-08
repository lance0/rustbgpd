# ADR-0092: EVPN VLAN-Aware Bundle service (non-zero Ethernet Tag)

**Status:** Accepted — Decision 6 proof-ladder slice 1 executed (M82, 2026-07-03); amended 2026-10-08: VTEP origination MVP shape decided (see "Amendment (2026-10-08)" below)
**Date:** 2026-06-19

> **Proof-ladder status (2026-07-03):** the Decision 6 receive/reflect
> ground truth exists on both rungs. The GoBGP-synthetic slice is
> CI-gated (M82 synthetic leg, 26/26: tag-as-route-identity on the RR,
> same MAC under two tags uncollapsed, tag-verbatim reflection,
> tag-scoped withdraw), and the non-FRR vendor receipt is in hand —
> Nokia SR Linux 25.10.1 in VLAN-aware-bundle interoperability mode
> (`vlan-aware-bundle-eth-tag`, 20/20, local lab; rustbgpd's first
> vendor-NOS interop row). Feasibility note from the vendor lab:
> SR Linux enforces one EVI per mac-vrf, so its bundle mode carries the
> bundle identity as shared RT + non-zero eth-tag over per-BD RDs — a
> remote PE modelling one-RD-per-bundle must not assume RD equality
> across tags. The RR path needed no code changes (the wire/RIB key
> already carries the tag); origination, import selection, and
> dataplane bundle mode remain the unimplemented tranches of this ADR.

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

> **Superseded in part by the [2026-10-08 amendment](#amendment-2026-10-08-vtep-origination-and-import-mvp-shape) (A, B, B2).**
> The opt-in and the model below still hold. The nested
> `[[evpn_bundle_instances]]` member-map sketch does not: each member is a flat
> `[[evpn_instances]]` row with `service_interface = "vlan_aware_bundle"` and an
> explicit `ethernet_tag`. The bundle is identified by its shared RT set, and
> each member has its own RD.

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

> **Superseded in part by the [2026-10-08 amendment](#amendment-2026-10-08-vtep-origination-and-import-mvp-shape) (C, E, F).**
> Tag isolation still holds. The remote-MAC desired table is **not** widened:
> member VNIs are globally unique, so `(VNI, MAC)` already isolates
> `(EVI, Ethernet Tag)`. In the MVP, Type 1 EAD-per-EVI is reject-only, with no
> origination and received routes dropped with a counted reason. Type 3 is
> origination-only until flood-list programming from received IMET routes
> lands.

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

> **Superseded in part by the [2026-10-08 amendment](#amendment-2026-10-08-vtep-origination-and-import-mvp-shape) (D).**
> The deferral and the rule against a NOTIFICATION still hold. Unsupported
> routes are **not** removed from Adj-RIB-In, because a daemon that is also a
> route reflector must keep reflecting them. The VTEP projection skips them
> instead and records a counted drop reason. For Type 5 that reason goes in the
> existing IP-VRF remote-prefix-drop counters.

RFC 9136 Type 5 routes carry Ethernet Tag in the route key, so bundle-mode
L3 behavior cannot be ignored forever. It is nevertheless out of the MVP for
this ADR's first implementation tranche.

The first bundle slice must either:

- reject such Type 5 routes at **import (Adj-RIB-In)** with a structured,
  per-route drop reason surfaced through the existing remote-prefix-drop /
  policy-reason counters — the same shape as the OTC-block and overlay-index
  drop reasons — and **never** via a session-level NOTIFICATION (tearing down an
  otherwise healthy session on an unsupported route is interop-hostile and
  debugging-hostile), or
- land a separate L3 follow-on ADR that defines the Type 5 semantics before
  enabling them.

No Type 5 bundle behavior is authorized implicitly by Type 2/3 support. The same
"fail closed = structured import-level drop, not NOTIFICATION" rule applies to
every unsupported bundle shape (see Decision 4).

### 4. Multi-homing is tag-scoped but deferred from the MVP

> **Refined by the [2026-10-08 amendment](#amendment-2026-10-08-vtep-origination-and-import-mvp-shape) (D, E).** The amendment lists
> the concrete fail-closed shapes. Bundle members cannot join an Ethernet
> Segment. For a bundle member, a remote Type 2 with a non-zero ESI and a remote
> EAD-per-EVI route are dropped at VTEP projection with the counted reason
> `multihoming_unsupported`. They are never handled as single-path.

The service principle is clear: EAD-per-EVI, aliasing, DF election,
single-active backup, mass-withdraw, and all-active Type 5 overlay-index
behavior become scoped by `(ESI, EVI, Ethernet Tag)`.

The initial bundle implementation must fail closed for multi-homing shapes it
cannot prove. Full tag-scoped multi-homing requires a follow-on ADR or a later
accepted extension to this one.

### 5. Coexistence and migration are explicit

> **Superseded in part by the [2026-10-08 amendment](#amendment-2026-10-08-vtep-origination-and-import-mvp-shape) (A, C, E).**
> There is no member map. VNI uniqueness is the existing daemon-wide check. The
> duplicate `(bridge, bridge_vlan)` check applies when a bundle row is
> involved, whether that pair is shared with another bundle member or with a
> VLAN-Based row. The amendment adds the RT and Ethernet Tag uniqueness rules.
> The migration and cutover-window text still holds.

Tag-0 ADR-0089 instances and bundle instances may coexist across different
EVIs/RDs. They must not both claim the same local `(bridge, bridge_vlan)` or
same `(EVI, Ethernet Tag)` identity.

Within a single bundle, the member map must also be internally unique: config
validation **rejects** two members that share the same `(bridge, bridge_vlan)`
(differing only in Ethernet Tag) or the same VNI. A duplicate `(bridge,
bridge_vlan)` is a local forwarding conflict, not a valid bundle, and must fail
validation rather than program ambiguous state.

Migration from Tag-0 VNI-per-BD to bundle mode is not an in-place semantic
reinterpretation. Operators configure a new bundle EVI/member map, validate
readiness/import behavior, and then move traffic deliberately. This leaves a
**transition window**: while the old Tag-0 EVI drains and the bundle EVI takes
over, the VTEP does not originate for the affected MACs under the new EVI until
they re-learn there. A coordinated cutover (drain the old EVI, then re-learn /
originate under the bundle EVI) is therefore expected; this ADR does **not**
promise a hitless in-place flip, and a Graceful-Restart-assisted or otherwise
hitless migration is future work.

### 6. Interop ground truth: GoBGP-synthetic first, then a non-FRR vendor

> **Refined by the [2026-10-08 amendment](#amendment-2026-10-08-vtep-origination-and-import-mvp-shape) (E, F, G).** In the MVP, GoBGP
> Type 1 routes prove the counted drop, not import or programming. Type 3
> receive is proven only once flood-list programming lands. SR Linux
> bundle-interoperability mode is the named vendor receipt for origination, and
> it lands after flood-list programming, as slice 4 of the order in G.

Non-zero-Ethernet-Tag bundle behavior varies across vendors, so this ADR names
its proof targets before implementation rather than leaving "cross-vendor
receipt" abstract:

- **FRR is not a bundle target.** FRR — and FRR-based NOSes (Cumulus, SONiC,
  Dell OS10) — implement EVPN as the **VLAN-Based** service (one VNI per
  L2VNI), not VLAN-Aware Bundle. An FRR peer, including FRR running on a lab
  switch, is a valuable general EVPN / VLAN-Based interop rig and (with ASIC
  offload) the right vehicle for local-bias (ADR-0065) — but it cannot
  originate or validate non-zero-Tag bundle routes.
- **GoBGP is the synthetic CI proof** (the M71/M72 pattern): it can originate
  controllable non-zero-Ethernet-Tag Type 1/2/3 routes, giving a CI-gated
  receive-side proof that rustbgpd imports and programs the bundle correctly.
  This is the first slice's required proof.
- **A real cross-vendor receipt needs a non-FRR NOS** that implements
  VLAN-Aware Bundle (e.g. Nokia SR Linux / SR OS, Cisco NX-OS, Juniper, Arista).
  That is the eventual ground truth and is demand-/hardware-shaped; the bundle
  service stays alpha until one is in hand.

## Amendment (2026-10-08): VTEP origination and import MVP shape

**Status:** Accepted (2026-10-08). The points below are decided, not
proposed.

A survey of the VTEP code before origination work refines Decisions 1-4.
The model `(EVI / RT set, Ethernet Tag) -> (bridge, bridge_vlan, VNI)` is
unchanged. This amendment decides how the MVP maps that model onto the
existing per-VNI machinery, where the fail-closed checks run, and the order
in which the proofs land.

**A. Bundle members are `[[evpn_instances]]` rows.** A member is an ordinary
instance row with `service_interface = "vlan_aware_bundle"` and a non-zero
`ethernet_tag`; there is no separate bundle table. Every per-VNI surface
already operates on a row: readiness, runtime add/delete/redefine, Linux
local-MAC attribution, duplicate-MAC detection and SVI origination. A nested
member table would need a parallel version of each one. The bundle is
identified by its shared route-target set. This follows RFC 8365 §5.1.2 Option 2, where
the control plane identifies a bridge table by `<RT, Ethernet Tag>`.

**B. Each member keeps its own RD in the MVP.** Receivers select a bridge
table by RT and Ethernet Tag, so a shared RD is not load-bearing on the wire.
Nokia SR Linux uses this shape for its bundle interoperability mode.
A shared bundle RD remains a later option: it can be added by relaxing the
duplicate-RD check, without breaking existing configurations.

**B2. `ethernet_tag` is explicit only.** Each member's Ethernet Tag must be
configured and must be in `1..=16777215`. Zero means VLAN-Based service, and
`0xFFFFFFFF` is reserved for per-ES routes. There is no automatic default: in
particular, the tag is not derived from the VNI, even though RFC 8365 §5.1.3
says the tag SHOULD equal the VNI when VNIs are global. The tag set must match
on every PE in the EVI, so an implicit value would be easy to get wrong.

**C. `(VNI, MAC)` keys stay.** VNIs are unique across all instances, so a
member VNI already identifies one `(EVI, Ethernet Tag)` pair. The same MAC
under two tags lands on two different VNIs and does not collapse. This
supersedes Decision 2's statement that the remote-MAC desired table must be
widened; that becomes necessary only if one VNI can serve two tags. VNIs
stay globally unique, and the MVP supports global VNIs only. A received Type 2
route is consumed by a member only when its VNI field equals the member VNI,
its Ethernet Tag equals the member tag, and it carries a member RT. A route
whose `<RT, tag>` selects a member but whose VNI field differs (locally
assigned VNIs) is dropped with a reason. Type 1 is covered in E, and Type 3
in F.

**D. Fail-closed drops happen at local consumption, not by removing routes
from Adj-RIB-In.** One daemon can be a VTEP and a route reflector at once,
and the reflection path already handles non-zero tags correctly (M82).
Removing an unsupported route from Adj-RIB-In would stop a valid route from
being reflected. Decisions 3 and 4 are therefore read as follows: the VTEP
projection skips an unsupported route and records a per-instance,
per-reason drop counter visible through the API and metrics. Type 5 drops
use the existing IP-VRF remote-prefix-drop reasons. The rule against a
session NOTIFICATION is unchanged.

**E. MVP rejections.** Configuration rejects the following for bundle
members:

- membership in `[[ethernet_segments]]` (multi-homing);
- `ip_vrf` (IRB);
- `auto_derive_route_target`, because the RFC 8365 auto-derived RT is per
  VNI and would split the shared bundle RT;
- two members that share both an RT and an Ethernet Tag;
- an RT shared between a bundle member and a VLAN-Based row.

The duplicate `(bridge, bridge_vlan)` check applies only when a bundle row is
involved: a pair claimed by a bundle member and any other row is rejected.
Configurations made only of VLAN-Based rows keep their current behavior.

For a bundle member, the VTEP drops a remote Type 2 route with a non-zero ESI
and records the `multihoming_unsupported` reason. It never falls back to
handling that route as single-homed with aliasing ignored, because that would
lose redundancy without anyone noticing. Remote EAD-per-EVI routes for a
bundle member are dropped with the same reason. DF election, aliasing and
BUM enforcement state are keyed
per VNI. Because member VNIs are unique, a later tag-scoped multi-homing
extension can map `(ESI, EVI, Ethernet Tag)` onto those keys.

**F. Type 3 scope.** The MVP originates one IMET per member, carrying the
member tag and member VNI. Today the VTEP does not program ingress-replication
flood lists from received IMET routes, for any service interface. That gap
is tracked separately. When flood-list programming lands, it resolves
received IMET routes to members through the same rule as Type 2.
Flood-list programming must land before the SR Linux datapath receipt in G,
so that receipt uses BUM-driven address resolution rather than static
neighbor entries.

**G. Origination proof target.** SR Linux in bundle interoperability mode
accepts a route into a mac-vrf only when its Ethernet Tag matches that
mac-vrf's configured `vlan-aware-bundle-eth-tag`. It therefore checks
rustbgpd's per-member tag stamping directly, and it is the Decision 6 vendor
receipt for origination. FRR 10.7.1 matches received EVPN routes to VNIs by
route target alone and does not check the tag, so it remains unsuitable.

The proofs land in this order:

1. inert configuration and validation;
2. live Type 2 and Type 3 origination plus per-tag import;
3. the GoBGP-synthetic CI leg;
4. after flood-list programming (F), the SR Linux origination and datapath
   receipt with a pinned image.

**H. Current test obligations.** These replace the older Test Obligations
list.

- Wire round-trip tests keep non-zero Ethernet Tag intact for Type 1/2/3/5.
- Row-level config validation, with each error message pinned:
  - `ethernet_tag` without `service_interface = "vlan_aware_bundle"` is
    rejected, as is the reverse;
  - a tag of `0`, a tag above `16777215`, and the reserved `0xFFFFFFFF` are
    rejected;
  - `ip_vrf`, `auto_derive_route_target`, and Ethernet Segment
    `member_vnis` that name a bundle row are rejected.
- Table-level config validation:
  - two bundle rows that share an RT and an Ethernet Tag are rejected;
  - an RT shared between a bundle row and a VLAN-Based row is rejected;
  - a `(bridge, bridge_vlan)` pair claimed twice is rejected when a bundle row
    is involved, and is still accepted between VLAN-Based rows only;
  - duplicate VNIs are still rejected daemon-wide;
  - the same rules hold for runtime apply and SIGHUP candidates before commit.
- Per-tag origination:
  - Type 2 (MAC-only, MAC+IP, SVI) and Type 3 carry the member's tag, RD and
    VNI;
  - a redefine from tag 0 to a non-zero tag withdraws the old keys and
    originates the new ones.
- Per-tag import and projection:
  - the same remote MAC under two member tags gives two `(VNI, MAC)` entries
    and two VLAN-scoped FDB rows;
  - a tag mismatch, a VNI mismatch, a non-zero ESI and an EAD-per-EVI route
    each give no FDB row and increment their counted reason.
- Type 5 with a non-zero tag increments the IP-VRF drop reason.
- Fail-closed paths never send a NOTIFICATION. A route dropped at VTEP
  projection stays in Adj-RIB-In and is still reflected when the daemon is
  also a route reflector.
- Linux netns: two member rows on one `vlan_filtering=1` bridge program
  per-member VLAN-scoped FDB rows, and local-MAC attribution maps each VLAN to
  its member.
- GoBGP-synthetic CI leg:
  - rustbgpd's per-tag Type 2/3 match field for field on the peer;
  - received per-tag Type 2 routes program the right FDB rows;
  - the negative cases move only the drop counters.
- Received-IMET flood-list resolution per member is tested with the
  flood-list work. SR Linux follows it, as slice 4.

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
- FRR and FRR-based NOSes are VLAN-Based-only, so they cannot prove
  non-zero-Tag bundle behavior; the proof is GoBGP-synthetic in CI plus an
  eventual non-FRR vendor receipt (Decision 6).
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

> **Superseded by the [2026-10-08 amendment](#amendment-2026-10-08-vtep-origination-and-import-mvp-shape).** The amendment's slice
> order (G) replaces this list. In particular, item 1 ("explicit member maps")
> becomes flat member rows. Item 3's EAD-per-EVI origination is out of the MVP.
> Item 4's resolution layer is the member row itself.

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

> **Superseded by the [2026-10-08 amendment](#amendment-2026-10-08-vtep-origination-and-import-mvp-shape) (H).** H is the current
> obligation list. The member-map and Adj-RIB-In drop wording below is
> historical.

- Wire round-trip tests proving non-zero Ethernet Tag remains preserved for
  Type 1/2/3/5.
- Projection tests where two tags in one EVI carry the same MAC without
  collapsing.
- Import/export tests proving `(EVI, Tag)` isolation.
- Linux dataplane tests proving the member map resolves to the right
  VLAN-scoped FDB rows.
- Config validation rejects a bundle whose member map repeats a
  `(bridge, bridge_vlan)` or a VNI (Decision 5).
- Fail-closed tests for unsupported Type 5 and multi-homing bundle shapes,
  asserting a **structured Adj-RIB-In drop reason / counter** — never a session
  NOTIFICATION (Decisions 3-4).
- GoBGP-synthetic receive-side proof: a peer originating non-zero-Ethernet-Tag
  Type 1/2/3 routes is imported and programmed to the right VLAN-scoped FDB
  rows (CI-gated, M71/M72 pattern). A non-FRR vendor receipt is the eventual
  cross-vendor ground truth (Decision 6).

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
