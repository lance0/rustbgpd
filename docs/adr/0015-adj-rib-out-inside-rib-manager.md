# ADR-0015: Adj-RIB-Out inside RibManager with per-peer outbound channels

**Status:** Accepted
**Date:** 2026-02-27

## Context

M3 requires outbound route advertisement. When the Loc-RIB best path changes,
affected peers must receive UPDATE messages with announcements or withdrawals.

Two ownership models were considered:
1. **Adj-RIB-Out inside each PeerSession** — each session tracks its own outbound state.
2. **Adj-RIB-Out inside RibManager** — the central RIB task owns all outbound state.

## Decision

Adj-RIB-Out tables live inside `RibManager`, one per registered peer. When a
peer reaches Established, the transport sends a `PeerUp { peer, outbound_tx }`
message to the RIB manager. The RIB manager:

1. Registers the peer's outbound channel (`mpsc::Sender<OutboundRouteUpdate>`).
2. Creates an `AdjRibOut` for delta tracking.
3. Sends an initial table dump (full Loc-RIB minus split-horizon, filtered by
   export policy).
4. On subsequent best-path changes, computes deltas against the Adj-RIB-Out and
   sends only changes.

The `PeerSession` receives `OutboundRouteUpdate` messages in its `tokio::select!`
loop and converts them to wire UPDATE messages. Outbound UPDATEs bypass the pure
FSM — consistent with how inbound UPDATEs bypass it (the FSM only receives
payloadless events).

## Consequences

**Positive:**
- Single-task ownership of all RIB state — no new locks or shared mutable state.
- Split-horizon and export policy are enforced in one place.
- Delta computation is centralized, avoiding per-session duplication.

**Negative:**
- The RIB manager task does more work per update (iterates all peers).
- A slow peer's outbound channel can back up, but `try_send` prevents blocking
  the RIB task. On channel-full, staged deltas are rolled back (AdjRibOut
  preserved) and the peer is marked dirty. A persistent 1-second resync timer
  diffs the full Loc-RIB against AdjRibOut to recover (M7).

**Neutral:**
- Injected routes (via gRPC `AddPath`) use sentinel peer `0.0.0.0` and
  participate in normal Adj-RIB-In / Loc-RIB / distribution flow.
