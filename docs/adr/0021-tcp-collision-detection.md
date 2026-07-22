# ADR-0021: TCP collision detection via PeerManager coordination

**Status:** Accepted
**Date:** 2026-02-28

## Context

RFC 4271 §6.8 requires that when both sides of a BGP session initiate TCP
connections simultaneously, the collision must be resolved by comparing BGP
Identifiers (router-ids). The side with the higher identifier keeps its
initiated connection; the other side closes its connection with a Cease/7
(Connection Collision Resolution) NOTIFICATION. RFC 6286 §2.3 adds the eBGP
tie-break for equal identifiers: preserve the connection initiated by the
speaker with the larger AS number.

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
   lifecycle and receives inbound connections. It can run an inbound
   collision candidate alongside the current session, wait until either
   side reaches OpenConfirm (where the remote router-id is known), then
   compare identifiers and decide which session to keep.

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
- `OpenReceived { peer_addr, session_id, role, remote_router_id, peer_asn }` —
  session entered OpenConfirm with the lossless negotiated router-id and peer
  ASN available, including a four-octet ASN learned from the capability.
- `BackToIdle { peer_addr, session_id, role }` — session fell back to
  Idle (connection failed or was torn down).

`CollisionDump` command added to `PeerCommand` — sends Cease/7
NOTIFICATION, cleans up RIB if Established, closes TCP.

`remote_router_id: Option<Ipv4Addr>` and `peer_asn: Option<u32>` in
`PeerSessionState` carry the negotiated identity for queries during
OpenConfirm state.

Both `PeerHandle::spawn()` and `PeerHandle::spawn_inbound()` accept an
optional `mpsc::UnboundedSender<SessionNotification>` parameter plus a
monotonically allocated session id and role (`Primary` or
`InboundCandidate`).

### PeerManager

`pending_inbound: Option<PendingInbound>` added to `ManagedPeer`.
`PendingInbound` holds a live inbound `PeerHandle` plus its session id.
This supersedes the original parked-`TcpStream` sketch: holding an
unstarted stream can deadlock simultaneous active-open because the
candidate never progresses far enough to reveal the remote BGP Identifier.

`session_notify_tx/rx` is created with `mpsc::unbounded_channel()` in
`PeerManager::new()`. This collision-coordination lane is intentionally
unbounded so its lossless notifications neither drop under backpressure nor
block a session task and deadlock with `QueryState`; its event rate is bounded
by session state transitions, not route volume.

`run()` uses `tokio::select!` on both the command channel and the
notification channel.

Inbound connection handling by existing session state:
- **Idle** → accept immediately (no collision).
- **Established** → drop inbound (no collision possible).
- **Connect/Active/OpenSent** → spawn a live `pending_inbound`
  candidate session, wait for an `OpenReceived` notification from either
  the current primary or the candidate.
- **OpenConfirm** → resolve immediately (negotiated router-id and peer ASN
  available from the current primary's state, or once the candidate reports
  its OpenConfirm).

`resolve_collision()` compares `u32::from(local_router_id)` vs
`u32::from(remote_router_id)`:
- Local > remote → send `CollisionDump` to the inbound candidate (keep
  the current primary).
- Local < remote → send `CollisionDump` to the current primary, promote
  the inbound candidate atomically.
- Equal identifiers on eBGP → compare the local and negotiated peer ASNs;
  preserve the connection initiated by the larger-AS speaker per RFC 6286
  §2.3.
- Equal identifiers and ASNs → drop inbound defensively. Equal identifiers
  on iBGP are rejected during OPEN negotiation before collision resolution.

`BackToIdle` notification from the current primary with a pending inbound
candidate → promote the pending candidate. `BackToIdle` or `OpenReceived`
from stale session ids is ignored. The session-id discriminator is
load-bearing: after a collision dump, the losing session may still emit a
late notification, and it must not mutate the peer that already promoted
or survived.

### FSM

No changes. Collision detection is a transport/PeerManager concern.

## Consequences

**Positive:**
- RFC 4271 §6.8 and RFC 6286 §2.3 compliance — simultaneous-open scenarios,
  including equal-identifier eBGP peers, resolve correctly.
- Cease/7 NOTIFICATION sent per spec — remote peer knows why connection
  was closed.
- FSM stays pure — no collision-aware logic added.
- Session notification channel is generic — reusable for future coordination
  needs (e.g., graceful restart).
- Simultaneous active-open no longer depends on a held TCP stream making
  progress out of band; both candidate sessions can process OPENs until
  PeerManager chooses the survivor.

**Negative:**
- PeerManager `run()` now has two select branches — slightly more complex.
- `pending_inbound` live session held until resolution — bounded by the
  number of configured peers and drained on peer disable / shutdown.
- The unbounded notification lane adds a small per-session overhead and relies
  on the session-transition-bounded event rate described above.
