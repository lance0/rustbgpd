# ADR-0051: Per-peer outbound writer task

**Status:** Proposed
**Date:** 2026-04-27

## Context

The 2026-04-27 M33 1h soak (`tests/soak/runs/20260427T133455Z/`) reproduced
a deterministic gRPC `GetHealth` wedge after ~46 min of 1k rps EVPN route
churn against 3 RR-client peers. The diagnosis (commit `0735dd9`,
investigation summary in this PR description) traced the wedge through
two layers:

1. **Surface symptom (closed by `0735dd9`)**: `list_peers` iterated peers
   sequentially with one `query_state().await` per peer; if any peer's
   session task was parked, the entire `ListPeers` reply hung, and so did
   `GetHealth`. Fixed by parallel fan-out + bounded `query_state_timeout`.
2. **Root cause (open — this ADR)**: the peer session task's
   `tokio::select!` outbound arm calls
   `send_route_update().await → send_message().await → stream.write_all().await`
   (`crates/transport/src/session/mod.rs:418`,
   `crates/transport/src/session/io.rs:11`). When TCP back-pressures (the
   peer's receive socket buffer fills), `write_all` parks. While parked,
   the entire `select!` is parked — including the `commands.recv()` arm.
   `0735dd9` makes that parking observable as `stale = true` instead of
   wedging gRPC, but the session task is still operationally broken: it
   no longer services `QueryState`, `Stop`, `SendRouteRefresh`, policy
   updates, or anything else.

Two consequences are still visible during a wedge under the v0.9.0+1
build:

- **Memory growth**: each affected peer in `dirty_peers` causes
  `distribute_changes` to rebuild full Loc-RIB HashSets per chunk
  (`crates/rib/src/manager/distribution.rs:1362`); the un-sendable Vecs
  get computed and dropped, but the chunk-processing loop slows down,
  letting `pending_route_batches` accumulate.
- **Outbound drops accumulate**: `try_reserve()` fails on the per-peer
  outbound mpsc (`distribution.rs:213-218`), the drop counter increments,
  the peer stays dirty, and routes destined for that peer are never
  delivered as long as TCP stays back-pressured.

The architectural problem is that the session task owns *both* the BGP
protocol state machine (which must stay responsive to commands and
keepalives) and the TCP write half (which under back-pressure can park
arbitrarily long). Decoupling them removes the coupling that lets one
slow peer turn the session into an unresponsive black box.

## Decision

### Split the per-peer task into two cooperating tasks

**Session task** (existing, retained):
- FSM state and transitions (`drive_fsm`, `negotiated`)
- `commands.recv()` — admin RPCs, query state, policy updates, shutdown
- TCP **read** half — `read_tcp` + `process_read_buffer`
- Timers — keepalive, hold, connect-retry
- Translation: `OutboundRouteUpdate` → encoded `Message`s
- Owns: state, attribute intern table, FSM
- Channel **out** to writer: `mpsc::Sender<EncodedMessage>`

**Writer task** (new):
- Owns the TCP **write** half (`OwnedWriteHalf` from `TcpStream::into_split()`)
- Reads from a bounded `mpsc::Receiver<EncodedMessage>`
- Calls `stream.write_all(&bytes).await` and `flush().await`
- Exits cleanly when its receiver closes (session task drops the sender on
  shutdown) or when a write fails

This mirrors the well-known reader/writer split pattern (e.g. h2's
`framed_write`, redis-rs, async-postgres). UPDATE ordering is preserved
because exactly one task owns writes and the inbound channel is FIFO.

### Bounded writer queue with disconnect-on-saturation

The writer's inbound channel is bounded at the same size as today's
session-side outbound buffer (`OUTBOUND_BUFFER = 4096`). When the session
task tries to enqueue an encoded `Message` and the channel is full:

- **Reject the send and trigger session shutdown via `Cease/9`** (Out of
  Resources, RFC 4486 §4). The peer's TCP receive socket has not drained
  4096 BGP messages from us — that is "out of resources" semantics. Other
  Cease subcodes (e.g. `/4` Other Configuration Change) are wrong:
  nothing in the local configuration has changed.

Trigger at full saturation, not at 90% or any partial threshold. A
fractional threshold would imply a retry window and coalescing logic
that we've explicitly ruled out as non-goals — and a peer that recovers
between 90% and 100% would have recovered at 100% too.

Rationale: a peer that hasn't read 4096 BGP messages from us is
operationally broken. BGP's recovery model is session restart — the peer
re-establishes, we re-advertise from scratch (post-GR if negotiated),
and the queue is empty again. Silent drops are *worse*: the RIB believes
those routes are advertised, the peer never receives them, blackholing
follows. A clean disconnect lets BGP do what BGP does — surface the
break, restart, reconverge.

This is preferable to the alternatives:

- **Silent drops + dirty resync**: today's behavior. Operationally
  invisible, blackholes for as long as TCP stays back-pressured.
- **Coalesce / drop-old**: requires understanding semantics across
  message boundaries (an UPDATE batch can announce + withdraw the same
  prefix); would need a non-FIFO writer, breaks ordering guarantees.
- **Unbounded writer queue**: defers the question, lets memory grow
  unboundedly — the same root pathology this ADR is meant to fix, just
  measured in MB instead of session liveness.

### Non-goals

- Multi-task RIB. RibManager stays single-task (ADR-0013); writer split
  is per-peer transport, not per-peer RIB.
- Coalescing or batching beyond what the session task already does. The
  writer is a dumb pipe.
- Multi-writer per peer. One task, one TCP write half, FIFO.

## Consequences

### Positive

- Session task stays responsive to commands under arbitrary write
  back-pressure. `query_state`, `Stop`, policy updates work even when
  the peer's read socket is silent.
- Drops become an explicit, observable event (a `Cease/9` notification
  + session restart) instead of an accumulating counter.
- Memory growth from dirty-resync HashSet rebuilds is bounded by the
  fact that the peer either drains or disconnects within
  `OUTBOUND_BUFFER` messages — no more "stuck dirty for minutes"
  cascading into pending-batch backlog.
- Symmetry: today the read half is already split conceptually
  (`read_tcp` lives in the session's `select!`); making the write half
  symmetric is a structural cleanup.

### Negative

- One additional task per peer. At v0.9.0 deployment scales (hundreds of
  peers), this is a few hundred extra tasks — within tokio's comfort
  zone (default scheduler handles tens of thousands).
- Disconnect-on-saturation is a behavior change. A peer that today
  silently misses routes during a slow read window will now flap. This
  is the *correct* behavior — the prior behavior is an outage in
  disguise — but operators monitoring flap counters will see them tick
  on degraded peer links that previously appeared fine.
- The session task's current synchronous `send_message().await` becomes
  an async `enqueue` operation. NOTIFICATION sends in `drive_fsm`
  (`crates/transport/src/session/fsm.rs:71`) must reach the wire even
  when the bounded queue is full — including the `Cease/9` we send when
  the queue saturates. Solution: give the writer task two inbound
  channels and a biased `select!`:

  ```rust
  loop {
      tokio::select! {
          biased;
          msg = priority_rx.recv() => write(msg).await,
          msg = bounded_rx.recv()  => write(msg).await,
      }
  }
  ```

  `priority_tx` is an `UnboundedSender<EncodedMessage>` carrying
  NOTIFICATIONs and the initial OPEN. KEEPALIVEs can ride either
  channel — they're tiny, infrequent, and bounded by hold-time, so the
  bounded path is fine. Using an unbounded channel for priority is safe
  because NOTIFICATIONs are bounded by session lifetime (one per
  shutdown), not by route volume. The existing
  `session_notify_tx: Option<mpsc::UnboundedSender<...>>`
  (`crates/transport/src/session/mod.rs:89`) is precedent for this
  pattern in the codebase.
- Test surface grows: the per-peer integration tests need updating to
  account for the writer task lifecycle.

### Neutral

- No proto changes. `bgp_outbound_route_drops_total` semantics shift
  from "channel full, peer marked dirty" to "channel full, session is
  about to disconnect" — the counter still fires on the same physical
  event, just with different downstream behavior. CHANGELOG note.
- BGP RFC compliance unchanged. RFC 4271 says nothing about per-peer
  task topology; this is an internal restructure.

## Validation

Before merging the writer-split PR:

1. **Repro test**: connected test peer accepts TCP but stops reading;
   enqueue outbound updates until the writer queue saturates; assert
   that (a) `query_state_timeout` returns `Some(state)` (not `None`)
   throughout — proving the session stayed responsive — and (b) the
   session disconnects with `Cease/9` within `OUTBOUND_BUFFER` messages.
   Mirrors the test sketched in `crates/transport/src/handle.rs::tests`
   for the `0735dd9` containment, but covers the writer-side actor
   instead of the command-side wedge.

2. **M33 1h soak rerun**: same harness, expect (a) `grpc_health_failures
   == 0`, (b) `outbound_drop_delta == 0` *or* explicit session flaps
   accounting for the disconnects, (c) `slope_mb_per_hour < 0.5`. If a
   peer disconnects under the new behavior, the soak's flap gate will
   fire — that's a feature; it surfaces a problem the harness was
   silently masking before.

3. **M30/M31/M32 interop runs unchanged**. FRR / GoBGP / BIRD peer in
   normal conditions; the writer split is internal and shouldn't change
   any wire-level behavior in non-stalled paths.

## What this does NOT fix

- The dirty-resync HashSet rebuild cost in `distribution.rs:1362-1373`.
  Disconnecting a saturated peer drops its `dirty_peers` membership, so
  the symptom abates, but a healthy peer at the edge of capacity could
  still drive distribution-side allocation pressure. Address separately
  if the post-split soak still shows steady-state allocation pressure.
- The `pending_route_batches` accumulation. Same answer: disconnect
  removes the pressure, but if a real-world deployment has many peers
  near capacity, the chunk loop still does redundant work.

These are follow-up work, not v1.0 blockers. The writer split closes
the actor-starvation root cause; allocation tuning is a polish pass on
the new normal.
