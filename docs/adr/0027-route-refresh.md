# ADR-0027: Route Refresh (RFC 2918)

**Status:** Accepted
**Date:** 2026-03-02

## Context

Operators need to re-evaluate routes after policy changes without tearing
down sessions. RFC 2918 defines ROUTE-REFRESH (type 5), a simple message
that asks a peer to re-advertise its Adj-RIB-Out for a given AFI/SAFI.
This is the standard mechanism for "soft reset inbound".

## Decision

### Wire format

ROUTE-REFRESH is message type 5 with a 4-byte body: AFI (u16) + Reserved
(u8, must be 0) + SAFI (u8). Total wire length: 23 bytes.

### Capability

Route Refresh capability code 2 with zero-length value. Advertised
unconditionally in every OPEN. Inbound ROUTE-REFRESH from peers that did
not advertise the capability is logged and ignored.

### Inbound path (peer sends ROUTE-REFRESH to us)

1. Transport decodes `Message::RouteRefresh`, records metric, checks peer
   advertised the capability.
2. Sends `RibUpdate::RouteRefreshRequest { peer, afi, safi }` to the RIB
   manager.
3. FSM receives `RouteRefreshReceived` event (restarts hold timer, no
   state change).
4. RIB manager iterates Loc-RIB filtered by the requested family, applies
   split horizon + export policy + sendable-family check, sends the routes
   via the outbound channel, then sends End-of-RIB for that family.

### Outbound path (operator triggers soft reset via gRPC)

1. `SoftResetIn` gRPC RPC on `NeighborService` sends
   `PeerManagerCommand::SoftResetIn` with address and optional family
   filter (empty = all negotiated families).
2. PeerManager looks up the peer handle and calls
   `handle.send_route_refresh(afi, safi)` for each target family.
3. Transport sends the ROUTE-REFRESH message on the wire.

### FSM

`RouteRefreshReceived { afi, safi }` is a new event variant. In
Established state it restarts the hold timer (same arm as
`KeepaliveReceived` and `UpdateReceived`). In any other state it triggers
the default FSM error path.

### NegotiatedSession

`peer_route_refresh: bool` is set during OPEN validation based on whether
the peer's capabilities include `Capability::RouteRefresh`.

## Consequences

- Operators can apply policy changes without session disruption.
- The capability is unconditionally advertised; peers that support it can
  request route refresh from us at any time.
- The RIB manager's `send_route_refresh_response` reuses the same
  filtering logic as `send_initial_table` (split horizon, export policy,
  sendable families).
