# ADR-0035: FlowSpec (RFC 8955 / RFC 8956)

**Status:** Accepted
**Date:** 2026-03-03

## Context

FlowSpec distributes traffic filtering rules via BGP, enabling programmatic
DDoS mitigation and traffic engineering without out-of-band signaling.
GoBGP supports FlowSpec (IPv4 + IPv6 unicast), and operators integrating
with prefixd or RTBH systems need it. rustbgpd had no FlowSpec support.
The feature touches wire, RIB, transport, config, policy, and API but
reuses the existing iBGP/RR/policy infrastructure.

## Decision

### Parallel types: FlowSpecRule / FlowSpecRoute

FlowSpec rules are variable-length TLV structures that cannot implement
`Copy`. To preserve `Prefix`'s `Copy` trait (used pervasively in the RIB),
FlowSpec uses separate types:

- `FlowSpecRule` — ordered set of `FlowSpecComponent` values (the match key)
- `FlowSpecRoute` — parallel to `Route`, keyed by `FlowSpecRule` instead of `Prefix`
- `FlowSpecPrefix` — `V4(Ipv4Prefix)` or `V6 { prefix, offset }` for IPv6 bit-offset encoding

The RIB stores FlowSpec routes in separate `HashMap<FlowSpecRule, FlowSpecRoute>`
collections within `AdjRibIn`, `LocRib`, and `AdjRibOut`, rather than mixing
them with unicast routes.

### SAFI 133, IPv4 + IPv6

FlowSpec uses SAFI 133 with AFI 1 (IPv4) and AFI 2 (IPv6). Config families
`"ipv4_flowspec"` and `"ipv6_flowspec"` are negotiated via MP-BGP
capabilities, independent of unicast families.

### FlowSpec components (RFC 8955 type codes 1-13)

The wire codec supports all 13 component types:

```rust
pub enum FlowSpecComponent {
    DestinationPrefix(FlowSpecPrefix),  // type 1
    SourcePrefix(FlowSpecPrefix),       // type 2
    IpProtocol(Vec<NumericMatch>),      // type 3
    Port(Vec<NumericMatch>),            // type 4
    DestinationPort(Vec<NumericMatch>), // type 5
    SourcePort(Vec<NumericMatch>),      // type 6
    IcmpType(Vec<NumericMatch>),        // type 7
    IcmpCode(Vec<NumericMatch>),        // type 8
    TcpFlags(Vec<BitmaskMatch>),        // type 9
    PacketLength(Vec<NumericMatch>),    // type 10
    Dscp(Vec<NumericMatch>),            // type 11
    Fragment(Vec<BitmaskMatch>),        // type 12
    FlowLabel(Vec<NumericMatch>),       // type 13 (IPv6 only)
}
```

Numeric operators encode `lt`/`gt`/`eq` comparisons with AND/OR chaining.
Bitmask operators encode `not`/`match` bit tests. Both use RFC 8955's
operator byte encoding with end-of-list termination.

### No next-hop (NH length = 0)

FlowSpec rules are filter specifications, not forwarding entries. The
`MP_REACH_NLRI` attribute carries `next_hop_length = 0` per RFC 8955.
The wire codec enforces this on decode (non-zero NH length is rejected)
and encode (always writes 0).

### No feasibility check (RFC 8955 section 6)

RFC 8955 section 6 defines a feasibility check: a FlowSpec destination
prefix should have a corresponding unicast route with the same next-hop
for the rule to be considered valid. This cross-RIB validation is
deferred to a future version. All received FlowSpec rules are accepted
and installed in the RIB regardless of unicast routing state.

### No VPN FlowSpec (SAFI 134)

Only unicast FlowSpec (SAFI 133) is supported. VPN FlowSpec (SAFI 134)
requires VRF infrastructure that rustbgpd does not have. This matches
the scope of unicast-only operation.

### Component ordering validation

`FlowSpecRule::validate()` checks that components are in ascending
type-code order per RFC 8955. Rules with out-of-order components are
rejected on decode and on gRPC injection.

### FlowSpec actions via extended communities

FlowSpec traffic actions (rate-limit, redirect, mark DSCP) are encoded
as extended communities per RFC 8955 section 7. The gRPC API accepts
structured `FlowSpecAction` messages and converts them to the
appropriate extended community encoding. Existing extended community
wire codec and RIB storage handle these transparently.

### Reuse of existing infrastructure

FlowSpec routes flow through the same infrastructure as unicast:

- **Transport:** MP_REACH/MP_UNREACH decode/encode with SAFI 133 branching
- **RIB:** Parallel FlowSpec collections in AdjRibIn, LocRib, AdjRibOut
- **Best-path:** Same selection logic (LOCAL_PREF, AS_PATH, etc.)
- **Policy:** Import/export policy evaluated per FlowSpec route
- **iBGP split-horizon:** Applies to FlowSpec routes
- **Route Reflector:** FlowSpec routes reflected like unicast
- **Outbound distribution:** `OutboundRouteUpdate` carries `flowspec_announce` / `flowspec_withdraw` alongside unicast

### gRPC API

Three new RPCs on the existing services:

- `InjectionService/AddFlowSpec` — inject a FlowSpec rule with components, attributes, and actions
- `InjectionService/DeleteFlowSpec` — withdraw a FlowSpec rule by its components
- `RibService/ListFlowSpecRoutes` — query FlowSpec Loc-RIB, filterable by AFI

### RibUpdate variants

Three new `RibUpdate` enum variants:

- `InjectFlowSpec { route, reply }` — local FlowSpec injection
- `WithdrawFlowSpec { rule, reply }` — local FlowSpec withdrawal
- `QueryFlowSpecRoutes { reply }` — Loc-RIB FlowSpec query

## Consequences

- FlowSpec rules use `Clone` + `Hash` + `Eq` for RIB keying, not `Copy`
- Separate FlowSpec storage adds collections to AdjRibIn/LocRib/AdjRibOut
  but avoids polluting the unicast fast path
- Without the feasibility check, operators must use policy to filter
  unwanted FlowSpec rules — acceptable for initial deployment
- The `families` config field now accepts four values: `ipv4_unicast`,
  `ipv6_unicast`, `ipv4_flowspec`, `ipv6_flowspec`
- FlowSpec EoR uses the same empty MP_UNREACH_NLRI mechanism as IPv6 unicast
- Prometheus metric `bgp_loc_rib_prefixes{family="flowspec"}` tracks
  FlowSpec Loc-RIB size
