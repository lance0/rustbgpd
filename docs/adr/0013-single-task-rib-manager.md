# ADR-0013: Single-task RIB manager with channel-based ownership

**Status:** Accepted
**Date:** 2026-02-27

## Context

The Adj-RIB-In stores routes received from all peers. Multiple peer session
tasks produce route updates concurrently; the gRPC API layer queries routes.
Two patterns were considered:

1. **Shared state** — `Arc<RwLock<HashMap<...>>>` shared across tasks.
   Simple to implement but introduces lock contention, potential priority
   inversion, and makes it harder to reason about consistency.

2. **Owned state** — A single tokio task owns all RIB data. Peer sessions
   send updates via a bounded mpsc channel. Queries use an embedded oneshot
   for the response.

## Decision

Single-task ownership via `RibManager`:

```rust
pub struct RibManager {
    ribs: HashMap<IpAddr, AdjRibIn>,
    rx: mpsc::Receiver<RibUpdate>,
}

pub enum RibUpdate {
    RoutesReceived { peer, announced, withdrawn },
    PeerDown { peer },
    QueryReceivedRoutes { peer: Option<IpAddr>, reply: oneshot::Sender<Vec<Route>> },
}
```

- Bounded mpsc channel with capacity 4096 for updates.
- Queries embed a `oneshot::Sender` for the response.
- No `Arc<RwLock>` anywhere in the RIB path.

## Consequences

**Positive:**
- No lock contention. All state mutations are sequential within one task.
- Clear ownership model — the `RibManager` task is the single authority
  for routing state. Matches the design document's control plane ownership
  principle.
- Natural backpressure: if the RIB task falls behind, senders block on
  the bounded channel. This is observable via metrics.
- The sharding seam is at the channel boundary — adding per-AFI/SAFI
  RIB tasks later requires no changes to session code.

**Negative:**
- Query latency includes channel round-trip (send + oneshot receive).
  Negligible for gRPC API queries but worth monitoring if query volume
  grows significantly.
- All updates are serialized through one task. At very high UPDATE rates
  (100K+ routes/sec sustained), this could become a bottleneck. The
  `rib_update_latency_p99` metric from the design document monitors this.

**Neutral:**
- The `PeerDown` variant clears all routes for a peer atomically, which
  is simpler than distributed cleanup across shared state.
- The pattern is identical to the design document's specified data flow:
  `Session RX → wire::decode → fsm → RibUpdate → RIB task`.

## Update (M2)

The `RibManager` now also owns a `LocRib` (Loc-RIB best-path table).
This is a natural extension of the single-task ownership pattern — the
Loc-RIB is recomputed incrementally on every announce, withdraw, and
peer-down event within the same task. No new locks or synchronization
were needed. A `QueryBestRoutes` variant was added to `RibUpdate`.
