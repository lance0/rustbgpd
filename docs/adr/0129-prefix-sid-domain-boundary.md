# ADR-0129: BGP Prefix-SID administrative-domain boundary

**Status:** Proposed (no runtime behavior is shipped by this ADR)
**Date:** 2026-08-29

## Context

RFC 8669 defines the BGP Prefix-SID path attribute, type code 40, as an
optional transitive attribute. Its scope is an SR administrative domain, not
an Autonomous System boundary. One SR domain may contain one AS or multiple
ASes under consolidated SID administration, so an eBGP session is not by
itself proof that its neighbor is outside the SR domain.

The RFC nevertheless requires an explicit boundary posture:

- a Prefix-SID received from an eBGP neighbor outside the SR domain is
  discarded unless that neighbor is configured for acceptance;
- filtering should remove the attribute when advertising across the
  administrative boundary; and
- inter-AS propagation must be explicitly configured, including the valid
  multi-AS, single-domain deployment model.

rustbgpd does not implement Prefix-SID semantics. It does not interpret a
label index, construct or consume an SRGB, program MPLS labels, or originate a
Prefix-SID. Current support is deliberately narrower:

- the wire crate recognizes type 40's registered Optional/Transitive class;
- it walks the outer TLV framing and checks the lengths of the Label-Index and
  Originator SRGB TLVs;
- a framing-valid value remains opaque as
  `PathAttribute::Unknown(RawAttribute)` and is eligible for propagation;
- complete reserved or unknown TLVs remain opaque rather than becoming a
  semantic support claim; and
- malformed framing is attribute-discard under RFC 8669 and RFC 7606, so the
  route and session survive without type 40.

The existing `discard_path_attributes` control does not express the complete
RFC boundary. It is available only to route-server clients, acts only on
accepted inbound attributes, and is an inverse numeric list. It cannot stop a
framing-valid Prefix-SID learned from an internal peer from being advertised
to a different peer outside the SR domain.

This ADR reserves an operator contract before configuration, API, metric, or
runtime code is added. Until the ADR is accepted and implemented, current
opaque propagation remains unchanged.

## Decision

### 1. Name the action, not unsupported semantics

The stable configuration concept is `prefix_sid_passthrough`. It is a
per-neighbor and peer-group boolean describing whether opaque type-40 carriage
is authorized across that session. It must not be named `accept_prefix_sid`,
because rustbgpd does not semantically accept or use a Prefix-SID.

The effective value is symmetric:

- `true` permits the existing opaque attribute to cross the session in both
  directions; and
- `false` removes an otherwise framing-valid type-40 attribute at both the
  inbound and outbound boundary while preserving the associated route.

The control applies to type 40 independent of the UPDATE's AFI/SAFI. RFC 8669
defines semantic use for IPv4/IPv6 labeled unicast, but administrative-domain
leak prevention must not depend on rustbgpd understanding or trusting the
attribute's semantic attachment.

This value does not enable Prefix-SID origination, label-index validation,
SRGB conflict detection, MPLS programming, or any other SR behavior.

### 2. Default to authorization, not an inferred domain fact

The effective default is derived from session type:

| Session | Omitted effective value | Rationale |
|---------|-------------------------|-----------|
| iBGP | `true` | Preserve current intra-AS carriage. An operator with multiple SR domains inside one AS can set `false`. |
| eBGP | `false` | Do not authorize inter-AS carriage until the operator declares that the peer is in the same SR domain. A same-domain multi-AS peer can set `true`. |

This does not assert that every eBGP peer is outside the SR domain. It treats
same-domain inter-AS carriage as an authorization that cannot be inferred
from the OPEN exchange. Likewise, iBGP is only the compatibility-preserving
default, not proof that two speakers share an SR domain.

A neighbor value overrides its peer-group value. A group value applies to
static and dynamically accepted inheritors. With neither value present, the
session-type default above is used. The resolved effective value, its source
(neighbor, group, or session-type default), and the configured value must be
preserved by the same config inspection and persistence surfaces as other
inherited neighbor controls.

### 3. Enforce the boundary after safety validation in both directions

Inbound processing retains the existing order:

1. decode and perform class/framing safety validation;
2. apply RFC 7606 disposition to a malformed attribute;
3. if the effective passthrough value is `false`, remove a surviving type 40
   before import policy and the RIB; and
4. process the route normally without that attribute.

The pre-policy BMP raw-update tap remains byte-exact and may therefore show
the received type 40. Post-policy Adj-RIB-In, policy explanation, RIB state,
and later exports must not contain the boundary-discarded attribute.

Outbound processing performs a final target-specific type-40 removal after
export policy and before encoding whenever the target's effective value is
`false`. No policy result, cached attribute bundle, replay, or exact-export
snapshot may bypass that final fence. This covers a route learned from iBGP
and sent toward an outside-domain eBGP peer, which an ingress-only control
would miss.

When passthrough is `true`, current payload behavior remains exact:
framing-valid opaque value and TLV octets, including complete reserved and
unknown TLVs, survive unchanged. Whole-attribute encoding retains the existing
conservative Partial-bit behavior. The new control may not weaken class or
framing validation.

### 4. Do not add a route-server exception

Route-server clients use the same session-type default and explicit override.
A normal eBGP route-server client therefore defaults to `false`; an operator
may set `true` only when that session is intentionally inside the same SR
domain.

`discard_path_attributes = [40]` remains valid for route-server clients. It
is an additional discard request and wins over
`prefix_sid_passthrough = true`; the passthrough control cannot override a
configured numeric discard. The numeric control remains inbound-only and is
not documented as a substitute for the symmetric domain boundary.

### 5. Treat an effective change as a session replacement

Changing the effective passthrough value changes both accepted Adj-RIB-In and
target-specific export bytes. A reload must purge-reset and rebuild every
affected static session and collision candidate so previously accepted or
advertised type-40 state cannot survive the new boundary. Dynamic inheritors
take the new group value through the same replacement/re-acceptance rules as
other session-affecting group changes.

The effective value is part of immutable session export posture and
update-group equivalence. Peers with different values cannot share prepared
wire output that contains type 40. Replay, route refresh, Add-Path candidates,
and exact-export snapshots must all apply the same target fence.

Omitted and explicit values are compared by effective behavior. A textual
change that leaves the effective value unchanged must not reset a session.

### 6. Keep malformed and extension behavior independent

Malformed handling precedes the administrative boundary and never depends on
the passthrough value:

- a truncated TLV header or value remains attribute-discard;
- a Label-Index TLV of the wrong length remains attribute-discard;
- an invalid Originator SRGB TLV length remains attribute-discard; and
- the route and session continue without the malformed attribute.

When passthrough is `true`, a complete reserved or unknown TLV remains opaque
and propagatable. Context-free wire validation must not reject one merely
because the implementation has no typed model for it. When passthrough is
`false`, the whole valid attribute is removed at the session boundary rather
than selectively rewriting its TLVs.

### 7. Add bounded, separate observability

The existing `bgp_path_attribute_discarded_total` contract counts the
route-server-only configured numeric filter. Its meaning must not silently
expand.

An implementation should add
`bgp_prefix_sid_boundary_discards_total{peer,direction}`, where `direction`
is the closed set `inbound|outbound`. It increments once for each logical
type-40 attribute instance removed at that peer boundary, independent of the
number of NLRI sharing the attribute set.

Each peer and direction gets one default-visible record per session epoch;
subsequent removals in that epoch are DEBUG. The record names the peer,
direction, effective-value source, and type code, but never emits opaque
attribute bytes. This bounds log volume while satisfying RFC 8669's request
for operator-visible discard analysis.

### 8. Ship the default change only in a minor release

Today an omitted eBGP configuration can propagate framing-valid type 40.
Making omitted eBGP effective `false` therefore changes observable routing
behavior: after upgrade and session rebuild, the route remains but the
attribute disappears.

The implementation must ship in a new minor release, not a patch. Its
CHANGELOG and upgrade note must state:

- the old omitted behavior;
- the new eBGP/iBGP defaults;
- that `prefix_sid_passthrough = true` restores opaque carriage for a
  declared same-domain eBGP peer;
- that setting `false` on iBGP represents an intra-AS administrative
  boundary; and
- that the setting is session-reset/relearn, not live route mutation.

The new optional config/API field is additive, but the eBGP effective-default
change still requires the project's explicit stable-surface compatibility
review. Acceptance of this ADR is the owner decision to take that next-minor
behavior change. If that decision is rejected, implementation remains
blocked until a replacement ADR defines a config-epoch or legacy-default
cell; a Worker must not silently change this ADR's default.

## Required implementation gates

The implementation is incomplete unless mutation-bearing tests prove every
boundary below:

1. Removing or flipping either session-type default fails direct effective
   config tests.
2. eBGP omission discards in both directions; explicit `true` preserves the
   opaque value and TLV octets for a declared same-domain peer while retaining
   the existing Partial-bit behavior on whole-attribute encoding.
3. iBGP omission preserves in both directions; explicit `false` discards at
   an intra-AS boundary.
4. Route-server eBGP uses the same default and explicit override, while an
   inherited/direct `discard_path_attributes = [40]` still wins.
5. Neighbor override, group inheritance, explicit false, omission, static
   peers, and dynamic inheritors resolve to the exact expected source and
   value.
6. Deleting the inbound filter exposes type 40 to policy/RIB; deleting the
   outbound filter leaks an internally learned attribute. Each mutation must
   fail independently.
7. Complete reserved and unknown TLV type/length/value octets round-trip
   byte-for-byte under `true`; changing their bytes or rejecting them fails the
   fixture.
8. Truncated and known-wrong-length TLVs are attribute-discard under both
   passthrough values, with unchanged route/session survival.
9. A reload flip purge-resets and relearns without stale inbound or outbound
   state; an effective-equivalent edit does not reset.
10. Peers with unequal effective values cannot share an update group or
    cached/exact-export encoding that contains type 40.
11. File config, runtime API, persistence, semantic diff, support output, and
    the consecutive stable fixture parse the additive field without losing
    presence or inheritance.
12. Counter direction, increment units, bounded logging, and label inventory
    are exact; existing configured-discard metric semantics stay unchanged.

## Consequences

- Operators get one explicit control that matches the real administrative
  boundary in both directions without claiming Prefix-SID semantic support.
- Same-domain eBGP remains supported, but only by explicit authorization.
- The conservative eBGP default prevents an omitted setting from leaking the
  attribute across an AS boundary.
- Existing eBGP deployments that intentionally carry type 40 must opt in
  during the documented minor-version upgrade.
- Update-group and reload work is part of correctness, not optional
  optimization, because the value changes target wire bytes and retained
  inbound state.
- The route-server numeric discard remains useful but does not become a
  misleading standards-compliance shortcut.

This ADR changes no shipped behavior while Proposed.

## Exclusions

This decision does not add:

- a typed Prefix-SID path-attribute model;
- label-index or SRGB semantic validation;
- MPLS label allocation or dataplane programming;
- Prefix-SID origination or policy mutation;
- SR Policy, BGP-LS, or topology support;
- a route-server-specific hidden default; or
- a context-free rejection rule for complete reserved or unknown TLVs.

## References

- [RFC 8669 — Segment Routing Prefix Segment Identifier Extensions for BGP](https://www.rfc-editor.org/rfc/rfc8669.html)
- [RFC 8402 — Segment Routing Architecture](https://www.rfc-editor.org/rfc/rfc8402.html)
- [RFC 7606 — Revised Error Handling for BGP UPDATE Messages](https://www.rfc-editor.org/rfc/rfc7606.html)
- [Path-attribute registry contract](../path-attribute-registry.md)
- [RFC implementation notes](../RFC_NOTES.md)
