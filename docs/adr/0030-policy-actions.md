# ADR-0030: Policy Actions and AS_PATH Regex

**Status:** Accepted
**Date:** 2026-03-02

## Context

The policy engine could only accept or reject routes — no attribute
manipulation. Operators couldn't set LOCAL_PREF on import, prepend
AS_PATH on export, or filter by AS_PATH regex. Without route
modification, rustbgpd was observation-only in production.

The policy crate also used naming inherited from the initial prefix-list
implementation (`PrefixList`, `PrefixListEntry`, `check_prefix_list`),
which no longer reflected the engine's scope (community matching, regex,
modifications).

## Decision

### Policy engine rename

Clean rename across the codebase (private repo, no external consumers):

- `PrefixList` -> `Policy`
- `PrefixListEntry` -> `PolicyStatement`
- `check_prefix_list()` -> `evaluate_policy()`
- File: `crates/policy/src/prefix_list.rs` -> `crates/policy/src/engine.rs`

### Return type redesign

`evaluate_policy()` returns `PolicyResult` instead of `PolicyAction`:

```rust
pub struct PolicyResult {
    pub action: PolicyAction,
    pub modifications: RouteModifications,
}

#[derive(Default)]
pub struct RouteModifications {
    pub set_local_pref: Option<u32>,
    pub set_med: Option<u32>,
    pub set_next_hop: Option<NextHopAction>,
    pub communities_add: Vec<u32>,
    pub communities_remove: Vec<u32>,
    pub extended_communities_add: Vec<ExtendedCommunity>,
    pub extended_communities_remove: Vec<ExtendedCommunity>,
    pub large_communities_add: Vec<LargeCommunity>,
    pub large_communities_remove: Vec<LargeCommunity>,
    pub as_path_prepend: Option<(u32, u8)>, // (ASN, count)
}

pub enum NextHopAction { Self_, Specific(IpAddr) }
```

### Modification engine

`apply_modifications(attrs, mods) -> Option<NextHopAction>` applies
changes in fixed order: LOCAL_PREF, MED, standard communities,
extended communities, large communities, AS_PATH prepend. Returns
the next-hop action for the caller to resolve (needs local address).

### Application sites

**Import (transport):** After `evaluate_policy()` returns Permit,
clone attributes, apply modifications, resolve next-hop. Modified
attributes are stored on the Route in Adj-RIB-In and Loc-RIB
(standard BGP behavior — import modifies the stored route).

**Export (RIB manager):** After `evaluate_policy()` returns Permit,
clone the Loc-RIB route, apply modifications. Loc-RIB is never
mutated. The `next_hop_self` flag is passed to transport via a
parallel `Vec<bool>` on `OutboundRouteUpdate`, resolved during
`prepare_outbound_attributes()`.

### AS_PATH regex matching

`AsPathRegex` wraps a compiled `regex::Regex` with Cisco/Quagga
`_` boundary convention (`_` expands to `(?:^| |$)`). Stored as
`match_as_path: Option<AsPathRegex>` on `PolicyStatement`, ANDed
with existing prefix and community conditions.

`AsPath::to_aspath_string()` converts AS_PATH to a matchable string:
AS_SEQUENCE segments as space-separated ASNs, AS_SET as `{ASN1 ASN2}`.

### Config format

```toml
[[policy.import]]
action = "permit"
prefix = "10.0.0.0/8"
set_local_pref = 200
set_community_add = ["65001:100"]

[[policy.import]]
action = "permit"
match_as_path = "^65100_"

[[policy.export]]
action = "permit"
set_as_path_prepend = { asn = 65001, count = 3 }
set_med = 100
set_next_hop = "self"
```

Validation: set fields on `action = "deny"` rejected at config load.
Prepend count 1-10. Invalid regex rejected at load time (fail-fast).
Entry requires at least one of `prefix`, `match_community`, or
`match_as_path`.

## Consequences

- Policy engine is production-capable: match, modify, and filter
- ~30 call sites updated for rename (one-time, mechanical)
- `regex` dependency added to policy crate
- All existing configs work identically (modifications default to empty)
- 595 tests pass after implementation
