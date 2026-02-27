# ADR-0018: Broadcast channel for WatchRoutes streaming

**Status:** Accepted
**Date:** 2026-02-27

## Context

The `WatchRoutes` gRPC endpoint needs to stream real-time route change events
to multiple concurrent subscribers. Each subscriber should see the same events
independently, at their own pace.

Options considered:
1. **One mpsc per subscriber** — RibManager tracks a `Vec<mpsc::Sender>` and
   fans out manually. Works, but requires managing subscriber lifecycle and
   cleanup of closed channels.
2. **`tokio::sync::broadcast`** — built-in fan-out with independent receivers.
   Subscribers that fall behind get `RecvError::Lagged` instead of blocking
   the sender.
3. **External pub-sub** (e.g., Redis) — far too heavy for an in-process event bus.

## Decision

Use `tokio::sync::broadcast` with a capacity of 4096:

- `RibManager` owns a `broadcast::Sender<RouteEvent>` created at construction.
- After `recompute_best()`, if a prefix changed, emit a `RouteEvent` with the
  appropriate type: `Added` (new best), `Withdrawn` (best removed), or
  `BestChanged` (best replaced).
- Subscribers request a receiver via `RibUpdate::SubscribeRouteEvents`.
- The gRPC `watch_routes()` implementation wraps the broadcast receiver in a
  `BroadcastStream`, filters by peer address if specified, and maps to proto
  `RouteEvent` messages.
- `RecvError::Lagged` is logged and skipped — the subscriber misses some events
  but stays connected.

## Consequences

**Positive:**
- Zero overhead when no subscribers exist (`broadcast::send` is a no-op with
  zero receivers — the send returns `Err` which is ignored via `let _ =`).
- Multiple subscribers are independent — one slow subscriber doesn't block others.
- No subscriber lifecycle management in RibManager.
- Lagged subscribers get a clear error instead of unbounded memory growth.

**Negative:**
- Lagged subscribers lose events. For the monitoring use case this is acceptable
  (operators see "current state" not "perfect history"). A replay mechanism
  could be added later if needed.
- Fixed capacity (4096) is a trade-off — too small wastes events under burst,
  too large wastes memory. Matches the mpsc channel capacity used elsewhere.
