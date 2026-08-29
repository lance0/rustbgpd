# ADR-0128: Route-server next-hop translation

**Status:** Accepted (architecture GO if activated; implementation NO-GO,
demand-gated)
**Date:** 2026-08-29

## Context

RFC 8950 lets IPv4 NLRI use an IPv6 next hop. That can remove IPv4 addressing
from an IXP peering LAN, but only when every member can consume the extended
next-hop form. `draft-marenamat-grow-route-server-nh-translation-02` proposes a
transition mechanism for a mixed fleet. An IXP maintains a Specific Local
Address Table (SLAT) containing each member's IPv6 link-local and global
addresses plus an IPv4 address in every client-specific local prefix (CSLP).
The route server then:

- maps an IPv4 next hop received from any member to that member's IPv6 SLAT
  identity;
- maps that IPv6 identity to the source member's address in a Legacy
  receiver's CSLP; and
- preserves the IPv6 next hop toward Supporting and Unnumbered receivers.

The draft also requires the route server to suppress a route whose next hop
does not belong to a SLAT row. The IXP owns the corresponding ARP/ND proxy and
address-management system; those are not route-server functions.

Revision 02 was published on 2026-07-21. It remains an active individual
Internet-Draft, not an adopted working-group document. Its operational model
and configuration vocabulary can still change.

rustbgpd has useful substrate but does not implement this proposal:

- RFC 8950 negotiation, receive, reflection, and encoding are shipped and
  covered by M18 and M53.
- A stored unicast route retains its advertising `peer`, accepted next hop,
  optional link-local companion, and scope. An import-policy rewrite replaces
  the decoded wire next hop; the original is not retained separately.
- Transparent route-server export preserves the accepted next hop.
- `next_hop_ownership = "strict_peer"` is an opt-in pre-policy ingress check.
  It accepts only the advertising session's own complete wire identity.
- The immutable session export profile and exact-export encoder keep current
  target-dependent wire inputs generation-consistent.

That ownership knob is not a translation mode. On an IPv6 session, an IPv4
SLAT address intentionally differs from the session's IPv6 peer address, so
`strict_peer` would reject an input the translation proposal needs to accept.
Translation also depends on both the source member and the receiving member,
whereas `strict_peer` validates one inbound session.

## Decision

Record a bounded architectural **GO** for a future translation slice and an
implementation **NO-GO** now.

Implementation may start only when both conditions hold:

1. either the draft is adopted by an IETF working group or a named IXP asks
   rustbgpd to implement the model; and
2. that work has a real SLAT producer and retained fixtures for the exact
   generated table plus Legacy, Supporting, and Unnumbered UPDATE forms.

General RFC parity, an individual draft revision, or codec capability alone
does not activate the feature.

### 1. Keep translation separate from ownership enforcement

A future operator surface may use a conceptual `next_hop_translation` mode,
but this ADR does not reserve a stable key or API field. It must remain
separate from `next_hop_ownership`:

- the default remains transparent route-server export;
- `strict_peer` keeps its current wire-identity and pre-policy behavior;
- translation is opt-in and cannot silently enable, weaken, or reinterpret
  `strict_peer`; and
- configuring both must fail closed until a later decision defines and tests
  their composition.

The distinction is structural. Ownership answers whether an inbound identity
is authorized. Translation chooses a canonical source identity and then a
receiver-specific wire representation.

### 2. Classify clients explicitly

The future configuration must represent the draft's three client classes:

- **Legacy:** cannot receive IPv4 NLRI with an IPv6 next hop;
- **Supporting:** can use the RFC 8950 form and can still use an IPv4 next hop;
  and
- **Unnumbered:** uses the RFC 8950 form and has no IPv4 next-hop capability.

Negotiation can show whether Extended Next Hop is present. It cannot prove
that a capable peer is Supporting rather than Unnumbered, nor that an operator
wants a particular transition role. Effective classification therefore needs
an explicit operator value plus a negotiated-capability consistency check.
Do not infer it from address text, family configuration, or reachability.

### 3. Publish one bounded SLAT generation

The minimum authoritative input is an immutable, generation-stamped table
that resolves:

- an advertising session to one source row;
- every accepted IPv4 or IPv6 wire next hop to that same row;
- the row's scoped link-local and global IPv6 identities; and
- for each Legacy receiver, the source row's IPv4 address in that receiver's
  selected CSLP column.

Publication must validate uniqueness, required columns, address families,
link-local scope, row-to-session bindings, and configured size limits before
one atomic generation becomes visible. Missing, duplicate, stale, or
generation-mismatched rows fail closed. A route must never be encoded from a
mixture of table generations.

The route server does not discover this inventory from ARP, ND, the FIB, or
OPEN capabilities. The IXP address-management system is authoritative. Any
future renderer integration must consume and publish that source atomically;
hand-edited parallel tables are not an acceptable contract.

### 4. Preserve source provenance through policy and export

Translation requires three distinguishable values: the received wire next
hop, the canonical IPv6 source identity, and the final receiver-specific wire
value. A future implementation must retain enough provenance to expose and
audit all three; overwriting the existing route next hop in place is
insufficient.

The ordering is:

1. validate the immutable received wire identity against the source SLAT row
   before import policy;
2. keep existing import-policy matching and explanation grounded in the
   received value, then retain the accepted route with its source peer and
   translation provenance; and
3. after export policy, choose the final representation from the same SLAT
   generation: receiver-CSLP IPv4 for Legacy, canonical IPv6 for Supporting
   and Unnumbered.

A policy next-hop rewrite cannot authorize an unrelated row or escape the
table. If its result cannot be mapped unambiguously to the source row, export
fails closed for that route. Looking-glass or API projection is future
consumer-shaped work; this ADR creates no public field.

### 5. Preserve exact replacement and withdrawal behavior

An unauthorized or untranslatable announcement follows the existing
pre-policy rejection rule: a rejected replacement withdraws only its prior
`(prefix, path_id)` identity, while a first-seen rejection emits no synthetic
withdrawal.

Withdrawals and replay use the same source identity and export-profile/SLAT
generation as announcements. A table reload must either re-evaluate and
resynchronize every affected route atomically or rebuild the affected
sessions before the generation is active. It must not leave an announcement
encoded under one mapping and its withdrawal encoded under another.

### 6. Make sharing and caches translation-aware

Today the prepared-attribute cache key includes the source-derived
`peer_router_id`, but not `route.peer`. Translation makes the advertising peer
itself a wire input.

A future slice must include client class, selected CSLP identity, and SLAT
generation in export-profile equivalence. Any cache that derives a next hop
must key on the source peer or on an equally specific resolved-row identity.
Targets may share an update group only when those translation inputs produce
identical bytes. A table publication must dirty or rebuild every affected
group and exact-export snapshot.

### 7. Keep renderer and reload work behind activation

`rs-config-render` currently reads an upstream `rfc8950` value but refuses the
effective enabled value on IPv6 sessions. It does not ingest a SLAT or client
translation class. The future integration must correct that boundary as one
atomic generated-tree change, with offline validation, semantic diff, reload
settlement, and rollback defined for the complete table generation.

This ADR does not add configuration, gRPC, CLI, renderer, or reload behavior.
Exact field names, inheritance, and stable-surface placement remain decisions
for the activated implementation and its named consumer.

## Consequences

- Current transparent export and `strict_peer` behavior remain unchanged.
- The project has a maintainable seam for the proposal without conflating
  ingress authorization with receiver-specific rewriting.
- The real implementation cost is authoritative inventory and generation
  consistency, not RFC 8950 wire encoding.
- Source-dependent translation cannot accidentally reuse a target-only cache
  entry or update group.
- Draft churn costs only an ADR update until demand and real fixtures exist.

The following remain out of scope: feature code, ARP/ND proxying or snooping,
proxy forwarding, FIB programming, address allocation, a new stable API, and a
claim that rustbgpd supports the draft.

## Verification

This is a documentation-only decision. No production behavior or regression
gate changes. An activated implementation must add mutation-bearing unit,
session, reload, exact-export, renderer, and cross-client interop proofs for
the boundaries above.

## References

- [Route Server Next Hop Translation, revision 02](https://datatracker.ietf.org/doc/draft-marenamat-grow-route-server-nh-translation/02/)
- [RFC 8950](https://www.rfc-editor.org/rfc/rfc8950.html)
- [RFC 7947](https://www.rfc-editor.org/rfc/rfc7947.html)
- [ADR-0107](0107-route-server-next-hop-ownership.md)
- [Route-server limitations](../LIMITATIONS.md)
