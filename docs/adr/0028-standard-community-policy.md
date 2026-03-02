# ADR-0028: Standard Community Policy Matching (RFC 1997)

**Status:** Accepted
**Date:** 2026-03-02

## Context

Standard BGP communities (RFC 1997) are the most widely used tagging
mechanism in operational BGP. rustbgpd already decodes, stores, and
exposes them via gRPC, but they were not actionable in import/export
policy. Extended community matching (ADR-0026) established the pattern;
standard communities extend it.

## Decision

### Config format

The existing `match_community` list in prefix list entries accepts three
formats:

| Format | Example | Meaning |
|--------|---------|---------|
| `TYPE:GLOBAL:LOCAL` | `RT:65001:100` | Extended community (unchanged) |
| `ASN:VALUE` | `65001:100` | Standard community (u16:u16) |
| Well-known name | `NO_EXPORT` | Standard community by name |

The format is unambiguous: 2 colons = extended, 1 colon = standard,
no colons = well-known name.

### Well-known communities

Three well-known communities are recognized by name:

- `NO_EXPORT` (0xFFFFFF01)
- `NO_ADVERTISE` (0xFFFFFF02)
- `NO_EXPORT_SUBCONFED` (0xFFFFFF03)

### `CommunityMatch` enum

A `Standard { value: u32 }` variant is added alongside the existing
`RouteTarget` and `RouteOrigin` variants. Each variant's match method
only matches its own community type — standard criteria never match
extended communities and vice versa.

### OR semantics across types

Within a `match_community` list, criteria are OR'd. A route matches if
ANY criterion matches against ANY of the route's standard OR extended
communities. This allows mixed filters like:

```toml
match_community = ["65001:100", "RT:65002:200"]
```

### Signature change

`check_prefix_list()` and `PrefixList::evaluate()` gain a
`communities: &[u32]` parameter for standard communities. All call
sites in transport (import) and RIB manager (export) pass both
community types.

## Consequences

- Operators can filter on standard communities in import/export policy.
- Existing configs with only extended community or prefix-only entries
  continue to work unchanged (the new parameter is `&[]`).
- The `match_community` field name is shared between standard and
  extended communities — no new config field.
