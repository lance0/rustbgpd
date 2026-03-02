# ADR-0031: Large Communities (RFC 8092)

**Status:** Accepted
**Date:** 2026-03-02

## Context

Large Communities (RFC 8092) extend the community concept to 4-byte
ASN operators. Each value is a 12-byte triple (global_admin, local_data1,
local_data2) — unlike standard communities (4 bytes) and extended
communities (8 bytes). This is table stakes for any operator using
32-bit ASNs.

## Decision

### Wire codec

`LargeCommunity` struct with three `u32` fields. Derives
`Debug, Clone, Copy, PartialEq, Eq, Hash`. Display format:
`"65001:100:200"`.

`PathAttribute::LargeCommunities(Vec<LargeCommunity>)` variant with
type code 32, flags `OPTIONAL | TRANSITIVE`. Decode validates length
is a multiple of 12 and parses `chunks_exact(12)` into three `u32`s.
Encode outputs three `u32::to_be_bytes()` per community.

### RIB

`Route::large_communities()` accessor follows the same pattern as
`communities()` and `extended_communities()`.

### gRPC API

`Route` message: `repeated string large_communities` field in
`"global:local1:local2"` format. `AddPathRequest`: same field for
injection. Parse and format use `LargeCommunity::to_string()` and
a `parse_large_community()` helper.

### Policy matching

`CommunityMatch::LargeCommunity { global_admin, local_data1, local_data2 }`
variant. Config format: `"LC:65001:100:200"` in `match_community`.
Uses OR semantics with standard and extended community matches within
a single policy statement.

### Policy set/delete

Large communities in `set_community_add` and `set_community_remove`
use the same `"LC:65001:100:200"` format. Applied by
`apply_modifications()` alongside standard and extended communities.

## Consequences

- 4-byte ASN operators can use community-based policy with rustbgpd
- Wire codec adds one new attribute type (well-tested pattern)
- Consistent with existing community handling at all layers
