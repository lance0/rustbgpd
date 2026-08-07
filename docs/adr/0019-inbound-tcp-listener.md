# ADR-0019: Inbound TCP listener

**Status:** Accepted
**Date:** 2026-02-27
**Update (2026-08, LAN-907):** the original single socket bound only
`0.0.0.0:{listen_port}`, so inbound IPv6 sessions could never establish and
IPv6 peers' listener-side MD5/GTSM/TCP-AO entries were silently skipped.
`BgpListener` now always binds both families — `0.0.0.0` and `[::]` (with
`IPV6_V6ONLY` set, so v4-mapped connections cannot race the IPv4 socket) —
behind one accept loop, one accept channel, and one rotation/auth state
machine, with each kernel auth key installed on the socket matching its peer
family. There is no listen-address knob. A family that cannot be bound
(IPv6 disabled on the host) logs a warning and the other keeps serving;
startup fails only when neither family binds.

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

- `BgpListener` binds `0.0.0.0:{listen_port}` and `[::]:{listen_port}` (see
  the 2026-08 update above; originally IPv4 only) and runs one accept loop.
- Accepted connections are forwarded to PeerManager via `AcceptInbound`
  command containing the `TcpStream` and peer IP.
- `PeerManager` looks up the peer by address:
  - **Known + idle** → shut down old (idle) session, spawn inbound session
    via `PeerHandle::spawn_inbound()`, send `ManualStart`.
  - **Known + connected** → hand off to ADR-0021 collision resolution when
    the connection is a simultaneous-open candidate; otherwise drop the
    extra inbound.
  - **Unknown** → log and drop.
- `PeerSession::new_inbound()` sets `stream = Some(tcp_stream)` at construction.
  When the FSM emits `InitiateTcpConnection`, `attempt_connect()` detects the
  existing stream and returns `TcpConnectionConfirmed` without dialing.

### Collision detection

RFC 4271 §6.8 defines TCP connection collision detection (compare router IDs,
close the connection from the higher ID). This was deferred in the original
M5 listener slice and is now implemented by ADR-0021. PeerManager runs a live
pending inbound candidate alongside the current session, compares BGP
Identifiers once a candidate reaches OpenConfirm, sends Cease/7
(`CONNECTION_COLLISION_RESOLUTION`) to the loser, and uses session ids to
ignore stale notifications from drained candidates.

## Consequences

**Positive:**
- Passive peering works — peers that only listen can now connect to rustbgpd.
- `listen_port` config field is no longer dead code.
- No new locking or shared state — PeerManager's single-task channel model
  handles inbound connections the same way it handles gRPC commands.
- Inbound session reuses 100% of existing `PeerSession` code.

**Negative:**
- One wildcard listener socket per address family — no per-peer bind address
  support. Sufficient for the common case (all peers on the same port).
