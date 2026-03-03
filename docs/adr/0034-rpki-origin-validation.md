# ADR-0034: RPKI Origin Validation (RFC 6811 + RFC 8210)

**Status:** Accepted
**Date:** 2026-03-03

## Context

RPKI origin validation is a growing regulatory requirement (MANRS, RIPE).
Operators expect it, and GoBGP has full RPKI/RTR support. rustbgpd had
none. The feature touches wire, RIB, policy, config, and API without
requiring massive structural changes.

## Decision

### New crate: `rustbgpd-rpki`

A dedicated crate contains the RTR protocol codec, per-cache-server
client, and multi-cache VRP aggregation. This keeps the RPKI subsystem
self-contained and testable independently.

### RpkiValidation enum in wire crate

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RpkiValidation {
    Valid,
    Invalid,
    #[default]
    NotFound,
}
```

Defined in `rustbgpd-wire` (the shared types crate) so Route, policy,
API, and the rpki crate can all reference it without circular deps.

### VrpTable: sorted Vec with binary search

`VrpTable` stores VRP entries in a sorted `Vec<VrpEntry>`, deduplicated
at construction time. Validation uses binary search to find covering
prefixes, then linear scan within the range for containment and origin
ASN matching.

This is simpler than a trie and sufficient for typical VRP table sizes
(~400K entries). The immutable design allows `Arc<VrpTable>` sharing.

### Arc<VrpTable> snapshot pattern

VRP tables are shared between the VrpManager and RibManager via
`Arc<VrpTable>`. This is an intentional exception to the project's
general avoidance of `Arc` — the table is immutable after construction
and needs to be accessed by both tasks without copying.

### RTR protocol version 1 only

The RTR codec supports RFC 8210 (version 1) only. RFC 6810 (version 0)
is rejected. Version 1 adds the Router Key PDU and End of Data timers.

### Multi-cache merge strategy

The VrpManager maintains per-server VRP tables and merges them via
set union with deduplication. If a cache goes down, its entries are
removed and the merged table is recomputed. Only changed tables are
sent to the RibManager to avoid unnecessary re-validation.

### Best-path step 0.5: RPKI preference

RPKI validation integrates into best-path selection between stale
route demotion (step 0) and LOCAL_PREF (step 1):

- Valid (2) > NotFound (1) > Invalid (0)

Invalid routes are deprioritized but not dropped — operators who want
hard rejection use policy: `match_rpki_validation = "invalid"` +
`action = "deny"`.

### RIB re-validation on cache update

When a new VRP table arrives, the RibManager re-validates ALL routes
in ALL Adj-RIB-Ins. Routes whose validation state changes are added
to the recompute set and best-path re-runs for affected prefixes.

### Policy `match_rpki_validation`

Policy statements gain an optional `match_rpki_validation` field that
matches routes by their RPKI validation state. This enables:
- Rejecting invalid routes
- Tagging valid routes with communities
- Setting LOCAL_PREF based on validation state

## Consequences

- Routes carry a `validation_state: RpkiValidation` field (default NotFound)
- VRP table updates trigger full re-validation which may be expensive with
  large RIBs — acceptable since cache updates are infrequent (~hourly)
- Without RPKI configured, all routes remain NotFound and best-path step 0.5
  is a no-op tie
- The RTR client handles reconnection with configurable retry/refresh/expire
  intervals per RFC 8210
- TCP-AO is not supported for RTR connections (same as BGP sessions)
- gRPC Route messages include `validation_state` field
- Prometheus metrics track VRP counts, cache status, and validation totals
