# ADR-0037: Extended Next Hop Encoding (RFC 8950)

**Status:** Accepted
**Date:** 2026-03-04

## Context

rustbgpd already supported dual-stack unicast via RFC 4760 and stored route
next-hops as `IpAddr`, but IPv4 unicast advertisements still used the legacy
body NLRI + classic `NEXT_HOP` attribute. That meant IPv4 routes could not use
an IPv6 next hop, even though modern dual-stack deployments commonly rely on
RFC 8950 for that behavior.

The transport and wire layers already had the pieces needed to carry IPv4 NLRI
in `MP_REACH_NLRI` / `MP_UNREACH_NLRI`. The remaining design question was how
to expose RFC 8950 cleanly without adding another per-neighbor configuration
knob or bifurcating the route model.

## Decision

rustbgpd implements RFC 8950 for **IPv4 unicast NLRI over IPv6 next hop** with
the following rules:

- Advertise capability code `5` automatically when a neighbor is configured for
  both `ipv4_unicast` and `ipv6_unicast`.
- Negotiate support only when both peers advertise the exact Extended Next Hop
  tuple `(IPv4 unicast -> IPv6 next-hop AFI)`.
- When RFC 8950 is negotiated for IPv4 unicast, outbound IPv4 unicast updates
  use `MP_REACH_NLRI` / `MP_UNREACH_NLRI` instead of body NLRI.
- Existing peers that do not negotiate RFC 8950 keep the legacy IPv4 body NLRI
  + `NEXT_HOP` path unchanged.
- The route model remains unchanged: `Route.next_hop` stays `IpAddr`.
- No new config knob is added. The existing `local_ipv6_nexthop` setting is
  reused for eBGP self next-hop when advertising IPv4 routes with an IPv6 next
  hop.

## Consequences

### Positive

- Full bidirectional RFC 8950 support for the most important deployment case:
  IPv4 unicast over IPv6 next hop.
- No route-model or gRPC schema redesign was required.
- Backward compatibility is preserved for non-negotiated peers.
- Add-Path for IPv4 unicast continues to work in both legacy and MP-encoded
  forms.

### Negative

- Outbound IPv4 unicast now has two wire encodings depending on negotiated
  capability, which makes the transport send path more complex.
- Dual-stack capability advertisement is automatic; operators do not get a
  separate enable/disable flag for RFC 8950 alone.

### Neutral

- This ADR only covers the IPv4-unicast-over-IPv6-next-hop case. Other SAFIs
  or AFI combinations remain future work if needed.
