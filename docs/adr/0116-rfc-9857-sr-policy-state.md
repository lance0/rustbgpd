# ADR-0116: RFC 9857 SR Policy state in BGP-LS

**Status:** Accepted (feature implementation demand-gated)
**Date:** 2026-07-22

## Context

RFC 9857 defines a BGP-LS object for reporting the operational state of an
instantiated Segment Routing Policy candidate path to a controller.  This is a
controller-feed use case, so receiving, reflecting, and exporting it could fit
rustbgpd's route-reflector niche.  It does not justify turning rustbgpd into an
SR Policy producer, PCE, or forwarding-plane implementation.

The existing ADR-0077 BGP-LS slice already provides an important but limited
substrate:

- `BgpLsNlriType::Unknown(5)` preserves the complete type-5 NLRI payload as
  opaque route identity.  It passes through Adj-RIB-In, Loc-RIB, Adj-RIB-Out,
  reflection, withdrawal, route-refresh replay, dirty resync, and GR/LLGR stale
  handling without projecting it into a unicast prefix.
- BGP-LS Attribute 29 is retained as `PathAttribute::Unknown(RawAttribute)`
  and reflected as opaque bytes.  `ListBgpLsRoutes` exposes both the raw NLRI
  payload and raw Attribute 29 value.
- Unknown BGP-LS TLVs and unknown NLRI types are therefore byte-preserved, as
  RFC 9552 requires of a propagator.

That byte passage is not typed RFC 9857 support.  In particular, treating type
5 as wholly unknown bypasses its internal TLV framing and canonical-order
validation, while treating Attribute 29 as a generic raw path attribute does
not implement RFC 9552's BGP-LS-specific whole-attribute discard boundary.
Promoting the existing opaque bytes directly into a public typed API would
freeze an unproven controller contract and could turn malformed state into an
apparently valid object.

### The RFC 9857 wire contract

RFC 9857 allocates BGP-LS NLRI type 5, `SR Policy Candidate Path NLRI`, with
Protocol-ID 9 (`Segment Routing`).  For this ADR, the standards-backed family
is AFI 16388 / SAFI 71.  RFC 9857 does not define the type for BGP-LS VPN SAFI
72 or specify a Route Distinguisher form; opaque passage on rustbgpd's generic
SAFI-72 path is not a typed RFC 9857 compliance claim.

The type-5 NLRI contains, in order:

1. Protocol-ID 9 and the RFC 9552 64-bit Identifier.
2. Local Node Descriptors TLV 256, identifying the policy headend.  It must
   contain at least one of the IPv4 or IPv6 local Router-ID descriptors (TLV
   1028 or 1029).  When the headend itself is the producer, BGP Router-ID TLV
   516 and Autonomous System TLV 512 are also mandatory; a PCE producing on
   the headend's behalf must not substitute its own identity in the NLRI.
3. Mandatory SR Policy Candidate Path Descriptor TLV 554.  It identifies the
   candidate path by protocol origin, IPv4/IPv6 endpoint, policy color,
   originator AS, IPv4/IPv6 originator address, and discriminator.  Its valid
   value lengths are 24, 36, or 48 octets according to the address flags.

The associated optional non-transitive BGP-LS Attribute 29 carries the state
TLVs allocated by RFC 9857:

| Code | State carried |
|------|---------------|
| 1201 | SR Binding SID |
| 1202 | SR Candidate Path State, including priority, flags, and preference |
| 1203 / 1213 | Candidate Path Name / SR Policy Name |
| 1204 | Candidate Path Constraints |
| 1205 | One segment list and its ordered sub-TLVs |
| 1206 | One segment, its SID/status, descriptor, and optional sub-sub-TLVs |
| 1207 / 1216 / 1217 | Segment-list metric, bandwidth, and identifier |
| 1208-1211 / 1214 / 1215 | Affinity, SRLG, bandwidth, disjoint, bidirectional-group, and metric constraints |
| 1212 | SRv6 Binding SID and optional SRv6 behavior/structure sub-TLVs |

TLVs 1201-1205, 1212, and 1213 are top-level Attribute 29 state.  Constraint
TLVs 1208-1211, 1214, and 1215 are sub-TLVs of TLV 1204.  Segment TLVs 1206,
1207, 1216, and 1217 are sub-TLVs of TLV 1205; SRv6 Endpoint Behavior TLV 1250
and SID Structure TLV 1252 may be nested under 1206 or 1212.

The procedures include TLV 1202 to report candidate-path state, include a BSID
TLV when one is specified or allocated, and include one TLV 1205 for each
associated SID list.  Each non-empty list contains ordered TLV 1206 segment
sub-TLVs.  The initial segment descriptor registry is:

| Type | Descriptor |
|------|------------|
| 1 / A | SR-MPLS label |
| 2 / B | SRv6 SID |
| 3 / C | IPv4 prefix with optional SR algorithm |
| 4 / D | IPv6 global prefix with optional SR-MPLS algorithm |
| 5 / E | IPv4 prefix and local interface ID |
| 6 / F | IPv4 local/remote link endpoint addresses |
| 7 / G | IPv6 local/remote prefixes and interface IDs for SR-MPLS |
| 8 / H | IPv6 local/remote link endpoint addresses for SR-MPLS |
| 9 / I | IPv6 global prefix with optional SRv6 algorithm |
| 10 / J | IPv6 local/remote prefixes and interface IDs for SRv6 |
| 11 / K | IPv6 local/remote link endpoint addresses for SRv6 |

A typed implementation must preserve unknown future descriptor types and
nested TLVs rather than discarding them.

The RFC Editor has verified erratum 8709.  The last paragraph of RFC 9857
Section 5.1 says `SR Binding SID sub-TLV` three times, but the defined object
is TLV 1201, `SR Binding SID TLV`.  Any future type names and documentation
must use the corrected term.

### Fault boundary

RFC 9857 inherits RFC 9552 fault handling, which refines the RFC 7606 recovery
model for BGP-LS:

- Outer UPDATE, MP_REACH/MP_UNREACH, NLRI, TLV, and sub-TLV containment,
  length sums, and the permitted lengths of recognized TLVs and sub-TLVs are
  syntax.  Recoverably malformed NLRIs are discarded individually.  A framing
  failure that prevents locating the next NLRI uses AFI/SAFI disable where
  available, otherwise session reset.
- A syntactically malformed TLV inside Attribute 29 discards the complete
  BGP-LS Attribute, not just that TLV.  The NLRI remains propagatable without
  Attribute 29 so consumers can distinguish lost attributes from a withdrawn
  object.
- Missing mandatory TLVs, unexpected TLVs, field values, flag combinations,
  and whether a TLV is meaningful for a particular NLRI are semantic checks.
  A propagator must not reject an object for those reasons.  That judgment
  belongs to the consuming application.
- Unknown NLRI/TLV/segment extensions remain opaque and round-trip.  RFC 4271
  path-attribute framing and flag rules still apply outside the more specific
  BGP-LS recovery behavior.

This separation is load-bearing for a route reflector.  Being stricter than a
consumer can suppress forward-compatible state; being looser on framing can
reflect an object whose identity or attribute boundary is ambiguous.

## Decision

Record a bounded **GO** for a future RFC 9857 receive / reflect / controller-
export vertical slice, and a **NO-GO** for feature code now.

Implementation may start only when all of these activation gates are met:

1. **Named demand:** a named controller integration or operator deployment
   needs candidate-path state from rustbgpd.  General standards parity is not
   sufficient.
2. **Real evidence:** the work has a real producer, real consumer, and captured
   UPDATE fixture.  The fixture must exercise withdrawal and at least one
   Attribute 29 state change, not only a hand-built happy-path NLRI.
3. **Generic framing first:** the BGP-LS codec implements and tests Attribute
   29 TLV framing plus RFC 9552 whole-attribute discard behavior independent
   of RFC 9857.  Type-5 parsing must also enforce recoverable NLRI discard
   versus unlocatable framing failure without adding semantic rejection.
4. **Consumer-shaped API:** the named consumer determines which fields need
   typed filters or messages.  Raw `payload` and `bgp_ls_attribute` bytes stay
   available for forward compatibility; no speculative public schema is added.

If activated, the smallest acceptable implementation is one SAFI-71 vertical
slice:

1. Add a typed type-5 identity view over the preserved bytes, including the
   mandatory descriptor structure, while retaining unknown TLVs verbatim.
2. Add typed accessors for the state/constraint/segment hierarchy actually
   consumed by the integration.  Unknown TLVs, segment types, and nested
   sub-TLVs must remain available as raw bytes.
3. Apply the fault boundary above before RIB insertion.  Prove by mutation that
   removing each NLRI-discard or whole-Attribute-29-discard decision makes its
   regression test fail.
4. Carry the typed identity through the existing BGP-LS RIB, reflection,
   refresh, and GR paths without adding Add-Path behavior or changing opaque
   route identity.
5. Add only the consumer-required additive gRPC/CLI view, resource bounds, and
   a real producer -> rustbgpd RR -> consumer interop receipt.

The following are explicitly excluded:

- local SR Policy or BGP-LS origination;
- SRPM, PCEP, path computation, topology/TE computation, or controller logic;
- MPLS/SRv6 label allocation, tunnel programming, or any dataplane behavior;
- new policy-language predicates for candidate-path state;
- BGP-LS Add-Path changes;
- a typed RFC 9857 claim for SAFI 72.

## Consequences

- Operators retain today's useful opaque type-5 and Attribute 29 passage; this
  ADR does not claim that opaque passage validates or interprets RFC 9857.
- A future controller integration can reuse the existing RIB and lifecycle
  path instead of building a new address-family subsystem.
- Generic Attribute 29 correctness is separated from SR Policy semantics and
  can improve all BGP-LS consumers without prematurely committing to RFC 9857
  API types.
- The project does not spend a feature tranche on an unproven controller feed
  or drift into SR traffic engineering and forwarding-plane scope.
- Typed SAFI-72, policy predicates, and Add-Path remain separate decisions with
  their own evidence requirements.

## Verification

This is a documentation-only decision.  The load-bearing regression rule is
**N/A**: no production behavior, test, or gate changes in this ADR.

## References

- [RFC 9857 - Advertisement of Segment Routing Policies Using BGP - Link
  State](https://www.rfc-editor.org/rfc/rfc9857.html)
- [RFC 9857 verified erratum 8709](https://www.rfc-editor.org/errata/eid8709)
- [RFC 9552 - Distribution of Link-State and Traffic Engineering Information
  Using BGP](https://www.rfc-editor.org/rfc/rfc9552.html)
- [RFC 7606 - Revised Error Handling for BGP UPDATE
  Messages](https://www.rfc-editor.org/rfc/rfc7606.html)
- [RFC 4271 - A Border Gateway Protocol 4
  (BGP-4)](https://www.rfc-editor.org/rfc/rfc4271.html)
- [IANA BGP-LS Parameters](https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml)
