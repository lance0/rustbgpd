# ADR-0048: RIB Memory Optimizations

## Status

Accepted

## Context

With a full Internet routing table (~900k IPv4 prefixes), memory consumption is
a key differentiator for BGP daemons.  GoBGP uses 8-16+ GB due to Go's GC
overhead and per-route object model.  BIRD achieves ~325 MB for 30 peers by
sharing path attribute storage across routes.  rustbgpd needed to close the gap
with BIRD-class efficiency while maintaining its simple single-owner RIB design.

Three independent optimizations were applied in sequence, each building on the
previous:

1. **Arc-shared attributes** (v0.4.2) — `Route.attributes` changed from
   `Vec<PathAttribute>` to `Arc<Vec<PathAttribute>>`.
2. **AdjRibIn prefix index** — secondary `HashMap<Prefix, HashSet<u32>>` for
   O(1) `iter_prefix()` lookups.
3. **Path attribute interning** — `HashSet<Arc<Vec<PathAttribute>>>` intern
   table in `AdjRibIn` deduplicates identical attribute sets.

## Decision

### Arc-shared attributes

`Route.attributes` is `Arc<Vec<PathAttribute>>` instead of `Vec<PathAttribute>`.
When a route is cloned from Adj-RIB-In to Loc-RIB to Adj-RIB-Out, all three
copies share the same heap allocation.  Only `Arc::make_mut()` (used for LLGR
community injection and policy modifications) triggers a copy.

This required adding `Hash` to `PathAttribute` and all its constituent types
(`AsPath`, `AsPathSegment`, `MpReachNlri`, `MpUnreachNlri`, `RawAttribute`)
to enable the interning optimization.

Route stack size: 88 bytes (down from 104 with `Vec`).

### AdjRibIn prefix index

A secondary index `HashMap<Prefix, HashSet<u32>>` maps each prefix to its set
of path IDs.  `iter_prefix()` uses this for O(candidates) lookup instead of
scanning the entire RIB.

Trade-off: insert is ~1.8x slower (must maintain both maps), but `iter_prefix()`
goes from O(N) to O(1).  The full pipeline benchmark (50k prefixes) improved
from 7.1s to 82ms (86x).

### Path attribute interning

`AdjRibIn` maintains a `HashSet<Arc<Vec<PathAttribute>>>` intern table.  On
`insert()`, the route's attributes are looked up in the set.  If an identical
attribute set already exists, the existing `Arc` is reused instead of keeping
a separate allocation.

This is effective because BGP peers typically advertise many prefixes with
identical attributes (same ORIGIN, AS_PATH, NEXT_HOP, LOCAL_PREF, MED, and
communities).  A peer's full table might have 900k prefixes but only 50-200
unique attribute sets.

- **Lookup**: `HashSet::get()` returns `&Arc`, which is cloned (cheap ref bump).
- **Miss**: the route's `Arc` is inserted into the set.
- **GC**: `gc_intern_table()` retains entries with `strong_count > 1` (still
  referenced by at least one route).  Called explicitly — no automatic
  background cleanup.
- **Mutation**: `Arc::make_mut()` detaches the route from the shared allocation.
  The old intern entry becomes orphaned and is cleaned up at next GC.
- **Clear**: `AdjRibIn::clear()` also clears the intern table.

## Memory Impact

| Version | Full RIB (900k x 2 peers) | Per-prefix | vs GoBGP |
|---------|--------------------------|------------|----------|
| Pre-Arc (`Vec<PathAttribute>`) | 1.80 GB | 2.1 KB | 4-9x less |
| Arc sharing | 1.41 GB | 1.6 KB | 6-11x less |
| Arc + interning | 547 MB | 637 B | 15-29x less |

Single-peer AdjRibIn: 217 MB for 900k routes (252 B/route), down from 667 MB
(776 B/route) before interning.

## Consequences

- `PathAttribute` and all inner types now implement `Hash`, enabling use as
  HashMap/HashSet keys throughout the codebase.
- `AdjRibIn` is 264 bytes (up from 216) due to the intern `HashSet`.
- Routes that undergo mutation (LLGR community injection, policy modifications)
  break out of the intern table via `Arc::make_mut()`.  This is correct —
  mutated attributes are unique and should not be shared.
- The intern table is per-peer, not global.  Cross-peer dedup would require a
  shared concurrent data structure, violating the single-owner principle.
  Per-peer interning captures the dominant case (same peer, same attributes).
- `gc_intern_table()` must be called explicitly after bulk withdrawals to
  reclaim orphaned entries.  The cost of stale intern entries is small (one
  `Arc` per unique attribute set), so aggressive GC is not required.
