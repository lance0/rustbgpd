# ADR-0026: Extended Community Policy Matching

**Status:** Accepted
**Date:** 2026-03-01

## Context

Extended communities (RFC 4360) are decoded, stored, and exposed via gRPC
(ADR-0025). Operators need to filter routes based on route target (RT) or
route origin (RO) values — the core use case for IX, transit, and VPN
deployments.

The existing policy system is prefix-only (`PrefixList` with `PrefixListEntry`
matching on prefix + ge/le). This ADR extends it to optionally match on
extended community values.

## Decision

### Config format

```toml
[[neighbors.import_policy]]
action = "deny"
match_community = ["RT:65001:100"]

[[neighbors.import_policy]]
prefix = "10.0.0.0/8"
action = "deny"
match_community = ["RT:65001:100", "RO:65002:200"]
```

- `match_community` is a list of `TYPE:GLOBAL:LOCAL` strings
- TYPE is `RT` (route target) or `RO` (route origin)
- GLOBAL is a decimal ASN (u32) or IPv4 address (converted to u32)
- LOCAL is a decimal u32

### Match semantics

- **`prefix` is now optional** — entries can match community-only, prefix-only,
  or both
- **Both present → AND** — prefix and community conditions must both match
- **Multiple communities in one entry → OR** — route has ANY of the listed
  values
- **No match_community → prefix-only** — backwards compatible with existing
  configs

### Encoding-agnostic matching

Matching uses `route_target()` / `route_origin()` which return decoded
`(u32, u32)` pairs. This means 2-octet AS, IPv4-specific, and 4-octet AS
encodings all compare equal when they represent the same global:local pair.
This is the correct operational behavior — operators care about the semantic
value, not the wire encoding.

### Applied at both import and export

Extended communities are extracted from UPDATE attributes (import) or from
stored Route attributes (export) and passed to `check_prefix_list()` as a
third parameter.

## Consequences

- Existing prefix-only configs work unchanged (backwards compatible)
- Entries must have at least one of `prefix` or `match_community`
- `ge`/`le` cannot be set without `prefix`
- No wildcard matching in this version — exact `(global, local)` match only
- `PrefixListEntry.prefix` changed from `Prefix` to `Option<Prefix>`
- `check_prefix_list()` signature gained `ecs: &[ExtendedCommunity]` parameter
