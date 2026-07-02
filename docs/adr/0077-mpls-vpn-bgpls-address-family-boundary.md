# ADR-0077: MPLS, VPN, and BGP-LS address-family boundary

**Status:** Accepted
**Date:** 2026-06-08

## Context

rustbgpd is an API-first BGP daemon with strong route-server,
route-reflector, validation, policy, telemetry, and bounded Linux dataplane
surfaces. It already supports:

- IPv4 / IPv6 unicast through the shared `Prefix` enum and unicast RIB path.
- FlowSpec through separate NLRI, RIB, injection, and policy surfaces.
- EVPN through `EvpnRoute` / `EvpnRouteKey`, EVPN-specific RIB and API
  surfaces, and a deliberately bounded Linux VXLAN / IP-VRF dataplane.

The remaining visible AFI/SAFI breadth gap versus full routing suites is in
service-provider and traffic-engineering families: BGP labeled unicast,
VPNv4/v6, Route Target Constraints, and BGP-LS. These are all carried by BGP,
but they are not all "IP prefix routes" and they are not evidence that
rustbgpd should become a full MPLS router.

The standards reinforce that distinction:

- RFC 4760 identifies the semantics of MP-BGP NLRI by `(AFI, SAFI)`, not by a
  single universal prefix shape.
- RFC 8277 binds MPLS labels to prefixes and says a speaker that changes the
  next-hop for SAFI-4 / SAFI-128 routes must program its dataplane
  appropriately.
- RFC 4364 / RFC 4659 VPN routes key on an RD plus an IP prefix and use Route
  Target extended communities to control VPN distribution.
- RFC 4684 Route Target Constraints are control-plane distribution state for
  VPN scale, not forwarding state.
- RFC 9552, which obsoletes RFC 7752 and RFC 9029, defines BGP-LS as a way to
  distribute link-state and traffic-engineering information to consumers such
  as PCE or ALTO systems. It uses AFI 16388 / SAFI 71, and BGP-LS VPN uses AFI
  16388 / SAFI 72.
- RFC 3031 / RFC 3032 describe an MPLS forwarding plane with label stack
  operations and local label significance. That is a different problem from
  reflecting or exporting BGP-carried labeled NLRI.

The codebase has the same boundary today:

- `crates/wire/src/nlri.rs` defines `Prefix` as IPv4 or IPv6 only.
- `crates/rib` stores unicast, FlowSpec, and EVPN as separate route families.
- The public gRPC route surfaces are either prefix-centric unicast, FlowSpec, or
  EVPN-specific; there is no generic "arbitrary MP-NLRI" route API.
- ADR-0061 explicitly excludes FlowSpec, EVPN, VPNv4/v6, and labeled-unicast
  from ordinary unicast FIB installation.
- ADR-0075's Address-Prefix ORF codec parses only IPv4 / IPv6 unicast entries;
  non-IP or future SAFIs remain raw so rustbgpd does not accidentally apply
  unicast prefix-list semantics to VPN, MPLS, or BGP-LS families.

The architectural question is therefore not "should we add MPLS?" It is:

1. Which BGP-carried address families fit rustbgpd's identity?
2. What route-key and API model should exist before any implementation lands?
3. Which dataplane behaviors are explicitly out of scope?

## Decision

### 1. Treat this as AFI/SAFI breadth, not an MPLS-router pivot

MPLS, VPN, and BGP-LS work in rustbgpd is control-plane address-family breadth.
It does not imply support for LDP, RSVP-TE, SR-MPLS policy signaling, MPLS
kernel programming, PE VRF dataplane import, label allocation for local
forwarding, or packet forwarding by label push / swap / pop.

The first viable product shapes are:

- **BGP-LS propagator / exporter**: receive, store, reflect, and expose BGP-LS
  NLRI and attributes to controllers. Producer mode from a local IGP LSDB/TED is
  out of scope because rustbgpd does not run OSPF or IS-IS.
- **VPNv4/v6 route-reflector only**: negotiate and reflect VPN routes while
  preserving RD, labels, next-hop, Route Targets, ORIGINATOR_ID, CLUSTER_LIST,
  Add-Path where applicable, and normal policy behavior. No local VRF import or
  MPLS FIB install.
- **IPv4/IPv6 labeled-unicast route-reflector only**: negotiate and reflect
  labeled routes. Next-hop-self, label rewrite, and local label allocation are
  disabled unless a later dataplane-backed ADR owns the required forwarding
  behavior.
- **Route Target Constraints (RTC)**: if VPN RR support ships, RTC is the
  scalability companion. It is routing/distribution state, not dataplane state.

These are demand-shaped. They should not displace the current fabric,
route-server, validation, API, and operational-proof priorities unless there is
operator demand or a clear controller-integration goal.

### 2. Do not extend `Prefix` to mean every route key

`Prefix` remains the IPv4 / IPv6 unicast prefix type. Future families get
family-specific keys, following the FlowSpec and EVPN precedent.

The conceptual route-key model is:

```rust
pub enum RouteFamilyKey {
    Unicast(Prefix),
    FlowSpec(FlowSpecRule),
    Evpn(EvpnRouteKey),
    LabeledUnicast(LabeledPrefixKey),
    Vpn(VpnRouteKey),
    RouteTargetMembership(RouteTargetMembershipKey),
    BgpLs(BgpLsKey),
}
```

This enum is a design boundary, not a required immediate Rust API. The point is
that every family must expose a key that matches its standard identity:

- `LabeledPrefixKey`: AFI, prefix, and Add-Path path-id in the RIB layer; label
  stack belongs to route data, not the prefix key, because RFC 8277 route
  comparability is by AFI/SAFI/prefix with label propagation rules layered on
  top.
- `VpnRouteKey`: AFI, RD, prefix, and Add-Path path-id in the RIB layer. Route
  Targets are attributes/policy input, not identity; one VPN route can carry
  multiple RTs.
- `RouteTargetMembershipKey`: origin AS plus Route Target prefix state from RFC
  4684, including the default RT membership route.
- `BgpLsKey`: protocol-id, identifier, NLRI type, and the typed or opaque
  descriptor bytes needed to identify one BGP-LS NLRI. BGP-LS TLVs and unknown
  descriptors must round-trip; the key must not depend on display text.

This avoids the main landmine: shoehorning VPNv4, labeled-unicast, or BGP-LS
into unicast prefix maps and then discovering that policy, event history,
import-explain, API filters, ORF, or FIB code treats those routes as ordinary
IPv4/IPv6 prefixes.

### 3. Add families as typed vertical slices

New address families must land as complete typed slices, not by only adding
AFI/SAFI constants.

Each implemented family needs:

- `crates/wire` codec for capability values, MP_REACH_NLRI, MP_UNREACH_NLRI,
  and route-key encode/decode, with RFC 7606-compatible error handling.
- RIB storage for Adj-RIB-In, Loc-RIB, Adj-RIB-Out, stale/LLGR handling,
  route refresh, dirty resync, and event history.
- Export/distribution integration, including ORIGINATOR_ID / CLUSTER_LIST
  reflection and Add-Path handling where applicable.
- Policy context fields that describe the family honestly. Do not use a dummy
  `0.0.0.0/0` prefix for BGP-LS or VPN routes merely to reuse unicast policy
  code.
- gRPC and CLI surfaces that expose family-specific identity and attributes.
  Existing unicast `ListRoutes` / `AddPath` surfaces stay IPv4/IPv6 unicast.
- Metrics, max-prefix or max-object bounds, and memory DoS guardrails. BGP-LS
  TLV cardinality and VPN route-key growth are peer-fed and need explicit caps.
- Interop tests against at least one implementation that already supports the
  family.

Adding an `(Afi, Safi)` enum value without the matching decoder and RIB slice is
not safe: peers can negotiate the family and then send UPDATEs that rustbgpd
cannot parse or store.

### 3a. Substrate-only work must stay unreachable

It is acceptable to prepare internal route-family substrate before a full
family ships, but that substrate must be deliberately unreachable from peers and
operators until a complete vertical slice exists.

A substrate-only PR may add private or crate-local types such as
`RouteFamilyKey`, family-specific key structs, parser test fixtures, or
conversion helpers. It must not:

- advertise a new AFI/SAFI in OPEN;
- accept new config or gNMI family names;
- add CLI/API commands that imply operational support;
- route non-unicast families through unicast `Prefix`, unicast policy context,
  unicast route-refresh state, or unicast FIB/EVPN dataplane paths;
- make unknown MP_REACH/MP_UNREACH payloads look successfully supported.

The review test is simple: if a real peer can negotiate the family, the PR is no
longer substrate-only and must satisfy the full typed-slice checklist above. If
an operator can configure the family, the CLI/API/docs must make the same
support boundary explicit and the implementation must reject unsupported
runtime effects predictably.

The first implementation guard for this boundary is the wire codec's MP-NLRI
family classifier. `MP_REACH_NLRI` / `MP_UNREACH_NLRI` may only dispatch to
the current complete verticals: IPv4/IPv6 unicast, IPv4/IPv6 FlowSpec, L2VPN
EVPN, and BGP-LS / BGP-LS VPN. Other recognized AFI/SAFI combinations reject
before NLRI parsing, so adding a future SAFI cannot accidentally reinterpret
VPN, RTC, or labeled payloads as ordinary unicast `Prefix` data.

The first BGP-LS implementation steps follow this rule deliberately. The wire
crate first exposed a standalone RFC 9552 NLRI/TLV codec for raw fixtures while
the daemon still rejected BGP-LS at MP-BGP dispatch. The receive/API tranche
then made BGP-LS reachable only as a typed vertical slice: explicit
`linkstate` / `linkstate_vpn` family negotiation, dedicated Adj-RIB-In /
Loc-RIB storage keyed by BGP-LS identity, opaque API/CLI export, and outbound
reflection/export through the same Adj-RIB-Out, route-refresh, dirty-resync,
and RFC 4456 route-reflector pipeline used by the existing families. It still
rejects BGP-LS Add-Path until that route-identity lifecycle is pinned, and it
omits BGP-LS from GR/LLGR stale-preservation capabilities until that lifecycle
is implemented for the typed RIB; until then, GR entry conservatively withdraws
BGP-LS routes and Enhanced Route Refresh sweeps omitted BGP-LS objects at
EoRR/timeout so stale controller-feed data is not reported as live.

The VPNv4/VPNv6 wire substrate follows the same rule. The callable codec for
RFC 8277 label stacks plus RFC 4364 / RFC 4659 RD-prefixed VPN prefixes is
kept unreachable from peer UPDATE dispatch. It records VPN route identity as
Route Distinguisher plus family-specific prefix and leaves MPLS labels as route
data, not route-key identity. Until a full typed family slice lands, rustbgpd
still does not negotiate, accept, store, reflect, expose, rewrite, allocate, or
program VPNv4/VPNv6 routes.

### 4. Preserve opaque data where the standard requires extensibility

Unknown path attributes are already preserved in rustbgpd. The same principle
must apply to families whose standards are TLV-heavy or extension-heavy.

- BGP-LS must preserve unknown NLRI types and unknown TLVs as opaque bytes so a
  propagator can reflect information it does not understand.
- VPN and labeled-unicast codecs must preserve label values and label stacks
  within negotiated capability limits. They must not silently rewrite labels.
- RTC must preserve Route Target encodings even when policy does not use them.

The implementation can still expose typed helpers for known values. Opaque
preservation is the forward-compatibility baseline.

### 5. Keep ORF Address-Prefix unicast-only until a family-specific ORF exists

ADR-0075's current ORF decision stands. Address-Prefix ORF parsing and
application is valid only for IPv4 / IPv6 unicast today.

Future VPN/MPLS support may extend ORF deliberately, but that work must answer
family-specific questions first:

- Does the ORF prefix include RD or labels, or only the customer IP prefix?
- Does the filter match VPNv4/v6 route identity, post-import VRF membership, or
  Route Target membership?
- Does it interact with RTC, and if so which filter wins?
- What does implicit deny mean for BGP-LS, where NLRI are not IP prefixes?

Until those answers exist, non-unicast ORF groups remain raw/ignored rather than
malformed or applied.

### 6. Default to no next-hop-self / label rewrite for labeled families

For SAFI-4 and SAFI-128 routes, a route reflector that preserves the next-hop
can preserve the received labels. A speaker that changes the next-hop must also
own the label(s) bound at the new next-hop and program the dataplane
appropriately.

Therefore:

- `next_hop_self` and any future label rewrite knob are rejected or ignored for
  labeled-unicast and VPN families until a dataplane-backed ADR defines label
  ownership.
- A route-reflector-only implementation must preserve next-hop and label stack
  unless policy withdraws the route.
- If a future implementation allows next-hop rewrite, it must be paired with
  explicit label allocation, FIB/MPLS programming, and rollback semantics.

### 7. BGP-LS is a controller-feed feature, not a local topology engine

BGP-LS support starts as receive / reflect / API-export:

- rustbgpd can be a BGP-LS **propagator** or controller-facing exporter.
- It is not initially a BGP-LS **producer** from OSPF, IS-IS, RSVP-TE, Segment
  Routing, or local netlink topology because rustbgpd does not own those LSDBs
  or TEDs.
- It does not compute TE paths, run PCEP, or make forwarding decisions from
  BGP-LS data.

This is the address-family expansion closest to rustbgpd's API-first identity:
receive control-plane data, preserve it accurately, apply policy, and expose it
cleanly to automation.

### 8. Align names with OpenConfig without promising full OpenConfig coverage

Family names should align with OpenConfig identity names where practical:

- `ipv4_labeled_unicast`
- `ipv6_labeled_unicast`
- `l3vpn_ipv4_unicast`
- `l3vpn_ipv6_unicast`
- `rtc`
- `linkstate`
- `linkstate_vpn`

This helps the future gNMI Set / OpenConfig bridge map family enablement
without inventing a parallel vocabulary. It does not mean the first
implementation must cover full OpenConfig MPLS, network-instance, VRF leaking,
or BGP-LS configuration models.

OpenConfig naming is therefore a translation boundary, not a shortcut. The
native candidate config, transaction planner, and route APIs still need typed
rustbgpd semantics before the gNMI bridge can expose a family. A future gNMI Set
path must not be the first place where a non-unicast family becomes
operationally reachable.

### 9. Interop is a release gate for every family

Each family needs at least one real-peer interop before it leaves alpha:

- FRR for labeled-unicast, L3VPN, and BGP-LS.
- GoBGP for API/control-plane parity and BGP-LS route objects. The first
  BGP-LS reflection receipt is M73: GoBGP 4.6.0 source -> rustbgpd RR ->
  GoBGP 4.6.0 sink for SAFI 71 Node NLRI reflection and withdrawal.
- BIRD 3.x for MPLS/VPN route-reflector behavior where applicable.
- OpenBGPD for VPN interoperability if the supported shape matches the feature.
- OpenDaylight BGPCEP or another controller for BGP-LS export if BGP-LS is the
  selected first family.

The interop should prove more than OPEN negotiation: it must assert that
received routes are stored, reflected/exported with identity intact, withdrawn
correctly, and not installed into an unintended dataplane.

## Non-goals

These are out of scope for this ADR and for any first implementation slice:

- MPLS dataplane programming: no kernel MPLS FIB, no ILM / FTN / NHLFE model,
  no label push / swap / pop, no TTL / TC forwarding behavior.
- LDP, RSVP-TE, PCEP, IS-IS, OSPF, or Segment Routing protocol support.
- Local PE behavior: no VRF import/export into Linux tables, no per-VRF FIB
  ownership, no local VPN service route origination from connected/static routes.
- Label allocation for routes whose next-hop is rewritten to rustbgpd.
- BGP-LS production from a local LSDB/TED.
- VPLS, MVPN, multicast VPN, SR Policy, SRv6 service programming, or full
  service-provider suite parity.
- Retrofitting the unicast FIB or EVPN VXLAN dataplane to handle MPLS labels.

## Consequences

- The roadmap can discuss VPN/MPLS/BGP-LS without implying a pivot away from
  rustbgpd's current route-server / fabric / API-first niche.
- Future code should prepare a family-specific route-key substrate before
  adding new AFI/SAFI config strings.
- Reviewers have a hard boundary for future work: either substrate remains
  unreachable, or the PR implements a complete typed family slice with codec,
  RIB, policy, API, refresh/GR, metrics, caps, docs, and interop.
- `Prefix` stays a unicast type. The compiler remains useful: new families
  should require explicit match arms rather than silently entering unicast code.
- The ORF raw-preservation behavior from ADR-0075 remains intentional and
  future-safe.
- BGP-LS is the most identity-aligned first slice if controller integration
  becomes a goal. VPNv4/v6 and labeled-unicast are route-reflector/control-plane
  features unless a later ADR deliberately expands rustbgpd into PE dataplane
  ownership.
- This ADR adds no new runtime feature by itself. Implementation remains
  deferred and demand-shaped.

## References

- RFC 3031 - Multiprotocol Label Switching Architecture:
  <https://www.rfc-editor.org/info/rfc3031>
- RFC 3032 - MPLS Label Stack Encoding:
  <https://www.rfc-editor.org/info/rfc3032>
- RFC 4364 - BGP/MPLS IP Virtual Private Networks:
  <https://www.rfc-editor.org/info/rfc4364>
- RFC 4659 - BGP-MPLS IP VPN Extension for IPv6 VPN:
  <https://www.rfc-editor.org/info/rfc4659>
- RFC 4684 - Constrained Route Distribution for BGP/MPLS IP VPNs:
  <https://www.rfc-editor.org/info/rfc4684>
- RFC 4760 - Multiprotocol Extensions for BGP-4:
  <https://www.rfc-editor.org/info/rfc4760>
- RFC 7606 - Revised Error Handling for BGP UPDATE Messages:
  <https://www.rfc-editor.org/info/rfc7606>
- RFC 8277 - Using BGP to Bind MPLS Labels to Address Prefixes:
  <https://www.rfc-editor.org/info/rfc8277>
- RFC 8654 - Extended Message Support for BGP:
  <https://www.rfc-editor.org/info/rfc8654>
- RFC 8950 - Advertising IPv4 NLRI with an IPv6 Next Hop:
  <https://www.rfc-editor.org/info/rfc8950>
- RFC 9552 - Distribution of Link-State and Traffic Engineering Information
  Using BGP:
  <https://www.rfc-editor.org/info/rfc9552>
- FRR BGP and BGP-LS documentation:
  <https://docs.frrouting.org/en/latest/bgp.html>,
  <https://docs.frrouting.org/en/latest/bgp-linkstate.html>
- GoBGP configuration and BGP-LS documentation:
  <https://github.com/osrg/gobgp/blob/master/docs/sources/configuration.md>,
  <https://github.com/osrg/gobgp/blob/master/docs/sources/bgp-ls.md>
- BIRD 3.3.0 User's Guide:
  <https://bird.nic.cz/doc/bird-3.3.0.html>
- OpenConfig BGP model documentation:
  <https://openconfig.net/projects/models/schemadocs/yangdoc/openconfig-bgp.html>

See also ADR-0023 (Prefix enum and AFI-agnostic RIB), ADR-0054 (EVPN Linux
dataplane boundary), ADR-0061 (unicast Linux FIB integration), ADR-0070
(gNMI / OpenConfig telemetry and Set adapter), and ADR-0075 (receive-side
Address-Prefix ORF).

## Amendment (2026-07-01): RT-Constrain shipped — recorded decisions

RTC (AFI 1 / SAFI 132) shipped as the VPN RR scalability companion scoped
above. Four implementation decisions are recorded here because they are not
derivable from RFC 4684 alone:

1. **Strict empty-membership semantics.** A peer that negotiated SAFI 132
   but has advertised no RT membership receives **no** VPN routes (including
   the initial table dump — the RR never floods-then-prunes). A peer that did
   not negotiate SAFI 132 is unfiltered. The membership for each peer derives
   from that peer's own Adj-RIB-In SAFI-132 routes (all paths, honoring
   §3.2's all-paths clause), never from Loc-RIB best.
2. **RFC-faithful prefix matching, with a documented GoBGP divergence.**
   Matching builds a 96-bit candidate — the RT's global-administrator field
   as the origin AS, concatenated with the full 8-byte RT extended
   community — and prefix-compares against the membership NLRI. GoBGP
   instead matches the 8-byte RT exactly and ignores the origin-AS bits;
   the two agree whenever an RT's administrator equals the advertising AS
   (the conventional case, and what GoBGP-originated /96 NLRI carry). When
   an RT's administrator differs from the advertiser's AS, rustbgpd
   under-advertises relative to GoBGP. This is RFC-defensible; if it bites
   in practice, the recorded upgrade path is to additionally accept a match
   when bits 32..len match the RT alone. Do not silently switch to exact
   matching — that breaks legitimate sub-96-bit prefix filters.
3. **Self-originated default membership.** rustbgpd has no VRFs, so its own
   RT interest is always "everything": it lazily originates the zero-length
   default RTC NLRI (LOCAL_PEER, no config knob) once any peer negotiates
   SAFI 132. Without this, RFC 4684-compliant PEs filter their VPN routes
   toward the RR and the reflector starves.
4. **Deferral register** (each with its un-defer trigger): §3.2(ii)
   non-client attribute-swap (multi-RR non-client meshes); §6 60-second VPN
   delay until RTC EoR (strict-empty already prevents flood-then-prune;
   revisit only if gradual-interest churn is observed); eBGP RTC
   distribution subtleties (§3.1 — the shipped arc is iBGP RR; GoBGP's own
   eBGP RTC filtering is broken upstream); RTC × ORF cross-validation
   (filters compose independently today); Add-Path for SAFI 132 (rejected
   at negotiation, matching the VPN/BGP-LS posture).

M75 is the interop receipt: GoBGP source/sink, strict filtering, RTC
reflection, widen/narrow membership without session resets, an unfiltered
non-RTC peer, and no dataplane installs.
