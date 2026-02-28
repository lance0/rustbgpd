# ADR-0014: Best-path comparison as standalone function with deterministic MED

**Status:** Accepted
**Date:** 2026-02-27

## Context

M2 adds Loc-RIB best-path selection per RFC 4271 §9.1.2. Two design
questions arose:

1. **How to express the comparison.** Rust's `Ord` trait on `Route` is
   the obvious approach, but best-path ordering is domain-specific and
   may need multiple orderings in the future (e.g., different MED
   comparison modes, different tiebreakers for route server mode).

2. **MED comparison scope.** RFC 4271 §9.1.2.2(c) says MED should only
   be compared between paths from the same neighboring AS. This creates
   ordering sensitivity — the result depends on the order paths are
   compared. Many implementations offer a "deterministic MED" mode that
   always compares MED regardless of neighboring AS.

## Decision

### Standalone comparison function

```rust
pub fn best_path_cmp(a: &Route, b: &Route) -> Ordering
```

Not `Ord` on `Route`. The function lives in `crates/rib/src/best_path.rs`
and is the single place where decision logic is encoded.

### Deterministic MED (always-compare)

MED is always compared between any two candidate paths, regardless of
neighboring AS. This matches GoBGP's default behavior and eliminates
ordering sensitivity.

### Decision steps

1. Highest LOCAL_PREF (default 100 if absent)
2. Shortest AS_PATH length (AS_SET counts as 1)
3. Lowest ORIGIN (IGP < EGP < INCOMPLETE)
4. Lowest MED (default 0 if absent; always-compare)
5. eBGP over iBGP (`Route.is_ebgp: bool`, added in M7)
6. Lowest peer address (final tiebreaker)

Router-id tiebreaker is deferred to post-v1.

## Consequences

**Positive:**
- No `Ord` pollution on `Route` — the comparison is explicit and its
  semantics are clear from the call site.
- Deterministic MED eliminates a class of subtle ordering bugs.
- Property tests (antisymmetry, transitivity, totality) verify the
  comparison is a valid total order.
- Adding alternative comparison modes later (e.g., same-AS MED, route
  server tiebreakers) only requires a new function, not changing trait
  impls.

**Negative:**
- Cannot use `Route` directly in `BTreeSet` or similar sorted collections
  without a wrapper. Not needed for the current design (HashMap-backed
  Loc-RIB with explicit `min_by`).
- Deterministic MED does not match the strict RFC 4271 letter. This is
  a deliberate operational simplicity choice, consistent with GoBGP and
  configurable in the future if needed.

**Neutral:**
- `Route` gains a `peer: IpAddr` field to support the peer address
  tiebreaker. This field also simplifies gRPC response construction
  (previously required passing the peer address separately).
