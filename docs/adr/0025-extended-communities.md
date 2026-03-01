# ADR-0025: Extended Communities (RFC 4360)

**Status:** Accepted
**Date:** 2026-03-01

## Context

Extended communities (RFC 4360) are 8-byte community values that carry
route targets, route origins, and other operational metadata. They are
critical for IX, transit, and VPN use cases — any deployment that tags
routes with traffic engineering or policy signals uses them.

Regular communities (RFC 1997, type code 8) are already implemented as
`PathAttribute::Communities(Vec<u32>)` — each community stored as a raw
`u32`. Extended communities follow the same model but with 8-byte values.

Key constraints:

1. **Wire codec consistency.** The existing Communities pattern (raw
   numeric storage, validated length, roundtrip-safe) is proven and
   should be mirrored.
2. **Type safety without over-engineering.** A raw `u64` prevents
   accidental confusion with other integers, but a full typed enum for
   every EC subtype is premature — policy matching on EC values is a
   separate roadmap item.
3. **Helper methods for common subtypes.** Route targets and route
   origins are by far the most common extended communities. Helpers
   should exist for extracting these without requiring callers to do
   bit manipulation.

## Decision

### Representation: `ExtendedCommunity(u64)` newtype

A zero-cost newtype wrapping the raw 8-byte wire value. Each EC is
8 bytes: type (1) + sub-type (1) + value (6).

Helper methods:
- `type_byte()`, `subtype()` — extract type/sub-type bytes
- `is_transitive()` — bit 6 of type byte (0 = transitive)
- `value_bytes()` — bytes 2-7
- `route_target()`, `route_origin()` — decode common sub-types
  (2-octet AS, 4-octet AS, IPv4 address specific)
- `Display` — `RT:asn:value` / `RO:asn:value` for recognized types,
  hex fallback for others

### PathAttribute variant

`PathAttribute::ExtendedCommunities(Vec<ExtendedCommunity>)` — stored
on `Route.attributes` like all other attributes. Not stripped during
UPDATE processing (unlike MP_REACH/MP_UNREACH which are per-UPDATE
framing).

### Wire codec

- Attribute type code 16, flags Optional | Transitive (0xC0)
- Decode: validate length is multiple of 8, `chunks_exact(8)` to `u64`
- Encode: iterate, `to_be_bytes()` each value

### gRPC

`repeated uint64` in proto — the newtype is a Rust-side concern only.
Proto consumers can reconstruct `ExtendedCommunity::new(value)` from
the raw u64.

### What this does NOT include

- **Policy matching on EC values** — separate roadmap item
- **Typed enum variants** (RouteTarget, RouteOrigin, etc.) — can be
  added later as the newtype's helpers cover common cases
- **Large communities** (RFC 8092, 12-byte) — separate feature

## Consequences

- Extended communities are decoded, stored, advertised, and queryable
  via gRPC, matching the full lifecycle of regular communities.
- The newtype prevents accidental mixing of raw u64 values with EC
  values and provides a natural home for helper methods.
- Existing fuzz harnesses automatically cover the new decode path.
- Policy matching on EC values will build on the `route_target()` and
  `route_origin()` helpers when implemented.
