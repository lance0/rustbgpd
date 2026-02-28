# ADR-0019: Inbound TCP listener

**Status:** Accepted
**Date:** 2026-02-27

## Context

Real BGP speakers accept inbound TCP connections on port 179. Prior to M5,
rustbgpd only initiated outbound connections — `listen_port` was parsed from
config but unused. This limits deployment to scenarios where rustbgpd always
dials the peer, which doesn't work when the peer is also configured for
passive-only operation.

Options considered:
1. **Listener in main.rs** — bind a `TcpListener` directly in the daemon
   entrypoint and forward accepted connections to PeerManager. Simple but
   couples I/O to the binary.
2. **Listener in transport crate** — `BgpListener` struct in a dedicated
   module, spawned as a task. Clean separation: the transport crate owns all
   TCP I/O. PeerManager receives `AcceptInbound` commands via its existing
   channel.
3. **Listener per peer** — each `PeerSession` binds its own listener. Too
   many sockets, no way to share port 179 across peers.

## Decision

Use option 2: `BgpListener` in the transport crate.

- `BgpListener` binds to `0.0.0.0:{listen_port}` and runs an accept loop.
- Accepted connections are forwarded to PeerManager via `AcceptInbound`
  command containing the `TcpStream` and peer IP.
- `PeerManager` looks up the peer by address:
  - **Known + idle** → shut down old (idle) session, spawn inbound session
    via `PeerHandle::spawn_inbound()`, send `ManualStart`.
  - **Known + connected** → log and drop (collision detection deferred).
  - **Unknown** → log and drop.
- `PeerSession::new_inbound()` sets `stream = Some(tcp_stream)` at construction.
  When the FSM emits `InitiateTcpConnection`, `attempt_connect()` detects the
  existing stream and returns `TcpConnectionConfirmed` without dialing.

### Collision detection

RFC 4271 §6.8 defines TCP connection collision detection (compare router IDs,
close the connection from the higher ID). This is deferred to post-M5. For now,
if a peer is already connected (non-idle), inbound connections are dropped.
This is safe: the existing session continues unaffected.

## Consequences

**Positive:**
- Passive peering works — peers that only listen can now connect to rustbgpd.
- `listen_port` config field is no longer dead code.
- No new locking or shared state — PeerManager's single-task channel model
  handles inbound connections the same way it handles gRPC commands.
- Inbound session reuses 100% of existing `PeerSession` code.

**Negative:**
- No collision detection yet — simultaneous inbound+outbound from the same
  peer will result in the inbound being dropped. Acceptable for M5.
- Single listener socket — no per-peer bind address support. Sufficient for
  the common case (all peers on the same port).
