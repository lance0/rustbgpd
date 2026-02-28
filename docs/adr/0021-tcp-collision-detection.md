# ADR-0021: TCP collision detection via PeerManager coordination

**Status:** Accepted
**Date:** 2026-02-28

## Context

RFC 4271 §6.8 requires that when both sides of a BGP session initiate TCP
connections simultaneously, the collision must be resolved by comparing BGP
Identifiers (router-ids). The side with the higher identifier keeps its
initiated connection; the other side closes its connection with a Cease/7
(Connection Collision Resolution) NOTIFICATION.

The existing code dropped all inbound connections when the outbound was
active, without comparing router-ids and without sending Cease/7. This
violated RFC 4271 §6.8 and could prevent session establishment in
simultaneous-open scenarios.

Options considered:

1. **Resolve in transport session** — each session tracks both connections
   and resolves internally. Rejected: a single session task only sees one
   connection, and the collision involves coordination between the existing
   outbound session and the new inbound connection.

2. **Resolve in PeerManager** — the PeerManager already owns the peer
   lifecycle and receives inbound connections. It can hold a pending inbound,
   wait for the existing session to reach OpenConfirm (where the remote
   router-id is known), then compare identifiers and decide which to keep.

3. **Resolve in FSM** — add collision-aware events to the pure FSM. Rejected:
   the FSM is pure `(State, Event) → (State, Actions)` with no I/O concerns.
   Collision detection requires access to both TCP connections, which is a
   transport/coordination concern.

## Decision

Implement TCP collision detection in PeerManager (option 2) with session
notifications from transport.

### Wire

Cease subcode 7 (`CONNECTION_COLLISION_RESOLUTION`) added to
`cease_subcode` module and `description()`.

### Transport

`SessionNotification` enum sent from peer sessions to PeerManager:
- `OpenReceived { peer_addr, remote_router_id }` — session entered
  OpenConfirm, remote router-id now available.
- `BackToIdle { peer_addr }` — session fell back to Idle (connection
  failed or was torn down).

`CollisionDump` command added to `PeerCommand` — sends Cease/7
NOTIFICATION, cleans up RIB if Established, closes TCP.

`remote_router_id: Option<Ipv4Addr>` added to `PeerSessionState` for
queries during OpenConfirm state.

Both `PeerHandle::spawn()` and `PeerHandle::spawn_inbound()` accept an
optional `mpsc::Sender<SessionNotification>` parameter.

### PeerManager

`pending_inbound: Option<TcpStream>` added to `ManagedPeer`.

`session_notify_tx/rx` channel (capacity 64) created in `PeerManager::new()`.

`run()` uses `tokio::select!` on both the command channel and the
notification channel.

Inbound connection handling by existing session state:
- **Idle** → accept immediately (no collision).
- **Established** → drop inbound (no collision possible).
- **Connect/Active/OpenSent** → store as `pending_inbound`, wait for
  `OpenReceived` notification.
- **OpenConfirm** → resolve immediately (router-id available from
  `query_state()`).

`resolve_collision()` compares `u32::from(local_router_id)` vs
`u32::from(remote_router_id)`:
- Local > remote → drop inbound (keep existing).
- Local < remote → send `CollisionDump` to existing, replace with inbound.
- Equal → drop inbound (degenerate case).

`BackToIdle` notification with pending inbound → accept the pending
connection (existing session failed).

### FSM

No changes. Collision detection is a transport/PeerManager concern.

## Consequences

**Positive:**
- RFC 4271 §6.8 compliance — simultaneous-open scenarios resolve correctly.
- Cease/7 NOTIFICATION sent per spec — remote peer knows why connection
  was closed.
- FSM stays pure — no collision-aware logic added.
- Session notification channel is generic — reusable for future coordination
  needs (e.g., graceful restart).

**Negative:**
- PeerManager `run()` now has two select branches — slightly more complex.
- `pending_inbound` stream held in memory until resolution — bounded by
  the number of configured peers.
- Notification channel adds a small per-session overhead (one try_send per
  state change to OpenConfirm or Idle).
