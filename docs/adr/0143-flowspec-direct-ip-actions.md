# ADR-0143: Direct target-IP FlowSpec actions

**Status:** Accepted (2026-11-01); the action and observation implementation has landed.
**Date:** 2026-10-27

> **Acceptance note (2026-11-01).** This record was accepted after the typed
> `redirect_ip` action, the attribute 25 model and the raw IPv6 observation
> fields shipped as proposed below. Acceptance covers that scope only. It does
> not qualify router forwarding: installation on a specific router and
> packet-level traffic diversion remain separate work, as described under
> [Compatibility and remaining work](#compatibility-and-remaining-work).

## Context

A controller diverting traffic to a scrubber needs a target IP address.
The existing `FlowSpecRedirect.route_target` selects a VRF by route target;
its IPv4-specific form is not an address to which traffic is redirected.

The current mechanism in
[draft-ietf-idr-flowspec-redirect-ip-16](https://datatracker.ietf.org/doc/html/draft-ietf-idr-flowspec-redirect-ip-16)
uses `0x010c` for IPv4 targets and `0x000c` in a 20-octet IPv6 Address
Specific Extended Community for IPv6 targets. The latter needs path
attribute 25. The draft distinguishes this from legacy next-hop-based
`0x0800` and the RFC 8955/RFC 7674 VRF actions. It remains an Internet-Draft.

[GoBGP's redirect-to-IP examples](https://github.com/osrg/gobgp/blob/v4.10.0/docs/sources/flowspec.md#example---redirect-to-ip)
expose both target families and the copy bit. Vendor support must still be
qualified for the exact router and software: for example,
[Juniper's feature description](https://apps.juniper.net/feature-explorer/feature/5203)
distinguishes target-IP and legacy next-hop support by address family.

## Proposal

- Add `FlowSpecAction.redirect_ip = 6`, containing a literal address and an
  explicit copy bit. Preserve the existing VRF field and field numbers.
  Originate canonical reserved bits; ignore received reserved bits when
  interpreting actions and retain their exact raw value.
- Model attribute 25 with lossless 20-octet values and a received Partial
  variant. Preserve unknown communities and duplicates, validate nonempty
  multiples of 20 on decode, and do not set Partial on originated values.
- Add `AddFlowSpecRequest.ipv6_extended_communities = 6` and
  `FlowSpecRouteEntry.ipv6_extended_communities = 11`, each a repeated bytes
  field whose entries are exactly 20 octets. Keep the existing 8-octet raw
  list. Return both raw lists alongside the interpreted actions in the
  selected, local-intent, received and committed-advertised projections.
- Apply the same construction to leased and unleased adds. Reject malformed
  targets and typed/raw target-IP ambiguity before enqueueing a mutation.
  Raw-only values retain the existing expert-level passthrough semantics.
- Amend the pinned v1 message graphs for `InjectionService` and `RibService`
  alongside the implementation. Existing RPC signatures and fields stay
  compatible; the new action and raw observation join the API shape contract.
  This does not promote CLI output or remote forwarding into that contract.

## Compatibility and remaining work

An old protobuf server can ignore new fields. Controllers must pin to an
implementing release and must not treat a successful mutation as capability
negotiation. New clients continue to render existing actions and omit an
empty IPv6 raw list from CLI JSON.

This slice does not add bounded authorization or per-admission revisions to
the lease protocol. Existing timeout semantics remain: an admitted operation
can commit after its caller times out. A safety-sensitive diversion controller
also needs server-checked commit deadlines, revision-fenced add/read/delete,
independent scrubber owners, readiness/withdrawal and rearm behavior, export
isolation, quotas and packet-level router/scrubber qualification. Those are
separate work; typed actions and local RIB observations do not enable or
qualify a scrubber product.

Golden vectors cover both encodings, both copy bits and reserved bits.
Attribute tests cover unknown values, Partial and length handling. API tests
cover rejection before mutation and retained leased/unleased intent; CLI
tests cover typed rendering and raw observation. These tests do not prove
remote installation or traffic forwarding.
