# ADR-0008: Single tokio task per peer for M0

**Status:** Accepted
**Date:** 2026-02-27

## Context

The transport layer needs to manage TCP connections, BGP message framing,
timers, and FSM events for each peer. Common patterns include:

1. **Single task per peer** — one `tokio::spawn` owns the stream, FSM,
   timers, and read buffer. Uses `tokio::select!` to multiplex.
2. **Split reader/writer** — separate tasks for reading and writing,
   communicating via channels. Better write throughput under load.
3. **Actor model** — each peer is an actor with a mailbox. More
   structured but adds channel overhead and complexity.

For M0, the only messages are OPEN, KEEPALIVE, and NOTIFICATION — all
small and infrequent. UPDATE processing is M1 scope.

## Decision

Use a single `tokio::spawn`'d task per peer that owns everything. The
`PeerSession` struct holds the FSM, `Option<TcpStream>`, `Timers`,
`ReadBuffer`, and `BgpMetrics`. A `tokio::select!` loop multiplexes
TCP reads, timer expirations, and external commands.

To avoid `&mut self` borrow conflicts in `select!`, timers use a
freestanding `poll_timer` function and the TCP read is extracted as a
freestanding `read_tcp` function.

## Consequences

- **Positive:** Simplest correct design. No channels between reader/
  writer, no synchronization, no message ordering concerns.
- **Positive:** Easy to reason about — one task, one event loop, one
  FSM instance.
- **Positive:** Low overhead — no channel allocations per message.
- **Negative:** Write throughput is limited by the single-task model.
  If a large UPDATE encode blocks the task, timer processing stalls.
  Acceptable for M0 (no UPDATEs). M1 can split if needed.
- **Neutral:** External control via `PeerHandle` with an `mpsc` channel
  of `PeerCommand` values. This pattern works regardless of whether the
  internal architecture is single-task or split.
