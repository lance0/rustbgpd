# ADR-0023: Prefix enum and AFI-agnostic RIB for MP-BGP

**Status:** Accepted
**Date:** 2026-02-28

## Context

rustbgpd v0.1.0 was IPv4-only. Adding MP-BGP (RFC 4760) for IPv6 unicast
requires the RIB, policy, transport, and API to handle multiple address
families. The core question is how to generalize the data model without
over-engineering for families we don't yet support (VPNv4, FlowSpec, etc.).

Key constraints:

1. `Ipv4Prefix` is used as a HashMap key throughout the RIB, policy, and
   transport layers. Any generalization must preserve `Hash + Eq`.
2. `Route.next_hop` is `Ipv4Addr`. IPv6 next-hops are 16 bytes (or 32 with
   link-local), carried inside `MP_REACH_NLRI`, not in the body NEXT_HOP
   attribute.
3. The RIB is a single task (ADR-0013). Per-AFI sharding is the documented
   future seam, but premature for two families.
4. Best-path comparison is AFI-agnostic — all decision criteria (LOCAL_PREF,
   AS_PATH length, ORIGIN, MED, eBGP preference, peer address) work
   identically for IPv4 and IPv6.

## Alternatives Considered

### A. Per-AFI RIB tasks

Separate `RibManager` instances per (AFI, SAFI). Clean separation but doubles
the channel and task infrastructure for a second family. Premature — the
DESIGN.md already documents this as a future optimization triggered by
latency metrics.

### B. Generic `Route<P: Prefix>` with trait

Parameterize `Route`, `AdjRibIn`, `LocRib`, etc. over a `Prefix` trait.
Adds complexity to every generic bound and makes the API surface harder to
use. Over-engineered for two concrete types.

### C. `Prefix` enum (chosen)

A simple enum wrapping `Ipv4Prefix` and `Ipv6Prefix`. Derives `Hash + Eq`
naturally. IPv4 and IPv6 routes coexist in the same `HashMap<Prefix, Route>`.
No generics, no traits, minimal code churn.

## Decision

### Prefix enum

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Prefix {
    V4(Ipv4Prefix),
    V6(Ipv6Prefix),
}
```

All RIB data structures (`AdjRibIn`, `LocRib`, `AdjRibOut`) use
`HashMap<Prefix, Route>`. IPv4 and IPv6 routes are stored together.
Best-path comparison is unchanged — it operates on `Route` fields that
are AFI-agnostic.

### Next-hop generalization

`Route.next_hop` changed from `Ipv4Addr` to `IpAddr`. IPv4 routes carry
`IpAddr::V4`, IPv6 routes carry `IpAddr::V6`. The body NEXT_HOP attribute
(type 3) is IPv4-only; IPv6 next-hops live inside `MpReachNlri`.

### MP_REACH_NLRI / MP_UNREACH_NLRI

New `PathAttribute` variants:

```rust
PathAttribute::MpReachNlri(MpReachNlri),
PathAttribute::MpUnreachNlri(MpUnreachNlri),
```

These are decoded/encoded per RFC 4760 §3. The transport layer extracts
them from parsed UPDATE attributes to build `Route` objects — they are not
stored on `Route.attributes` (they are per-UPDATE framing, not per-route
state). `prepare_outbound_attributes()` strips them before cloning.

### Outbound UPDATE splitting

IPv4 routes use the existing body NLRI path (`UpdateMessage::build()` with
announced/withdrawn prefixes in the message body). IPv6 routes use empty
body NLRI with `MpReachNlri` / `MpUnreachNlri` in the attributes. A single
UPDATE message carries one AFI — mixed-AFI UPDATEs are not generated.

### Family negotiation

`intersect_families()` computes the intersection of locally configured
families and peer MP-BGP capabilities. The result is stored in
`NegotiatedSession.negotiated_families`. Only negotiated families are
processed in inbound UPDATEs and included in outbound advertisements.

### Config

Per-neighbor `families` field (list of strings):

```toml
families = ["ipv4_unicast", "ipv6_unicast"]
```

Defaults: `["ipv4_unicast"]` for IPv4 neighbors, `["ipv4_unicast",
"ipv6_unicast"]` for IPv6 neighbors.

## Consequences

### Positive

- Minimal code churn — enum dispatch instead of generics.
- IPv4 and IPv6 routes share the same best-path, distribution, and policy
  logic with no duplication.
- Easy to extend: adding a third family (e.g., VPNv4) means adding a
  `Prefix::Vpn4(...)` variant, not redesigning the RIB.
- No new locks, no new tasks — single RibManager pattern preserved.

### Negative

- IPv4 and IPv6 routes share a single HashMap. At scale (millions of routes
  per AFI), per-AFI sharding would reduce contention and improve cache
  locality. This is the documented future optimization path (ADR-0013).
- `match` exhaustiveness: every consumer of `Prefix` must handle both
  variants. This is enforced by the compiler, which is a feature.

### Neutral

- `Ipv4Prefix` remains a concrete type (not deprecated). Code that only
  handles IPv4 (e.g., body NLRI decode) still uses it directly.
- Policy prefix lists now handle both families via the same `Prefix` enum.
  The `le` default adjusts automatically (32 for V4, 128 for V6).
