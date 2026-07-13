# ADR-0038: Enhanced Route Refresh (RFC 7313)

**Status:** Accepted
**Date:** 2026-03-04

## Context

RFC 2918 route refresh lets a peer request re-advertisement for an AFI/SAFI,
but it does not explicitly delimit the replacement window. That means an
inbound soft reset can re-learn updated routes without a clear boundary for
removing unreplaced stale entries. RFC 7313 addresses that by extending the
existing ROUTE-REFRESH message with Beginning-of-RIB-Refresh (`BoRR`) and
End-of-RIB-Refresh (`EoRR`) markers.

rustbgpd already had RFC 2918 support (ADR-0027). The missing piece was
family-scoped replacement semantics for `SoftResetIn`.

## Decision

### Capability

Advertise and negotiate the RFC 7313 Enhanced Route Refresh capability
(code 70) unconditionally, alongside RFC 2918 Route Refresh.

`NegotiatedSession.peer_enhanced_route_refresh` records whether the peer
advertised the capability.

### Wire format

Reuse the existing ROUTE-REFRESH message type (5). The third octet in the
4-byte body is now modeled explicitly as a subtype:

- `0` = normal route refresh request
- `1` = `BoRR`
- `2` = `EoRR`

Unknown subtypes are preserved on decode and ignored at runtime.

### Inbound behavior (peer refreshing us)

When a peer sends:

- `Normal`: existing RFC 2918 path, re-advertise requested family
- `BoRR`: begin an inbound refresh window for `(peer, afi, safi)`
- `EoRR`: end that window and sweep unreplaced routes for that family

`BoRR`/`EoRR` are ignored unless the peer negotiated Enhanced Route Refresh.

### Inbound replacement semantics (our `SoftResetIn`)

When we trigger `SoftResetIn` and the peer supports RFC 7313:

1. Inbound `BoRR` marks current routes from that peer/family as
   refresh-stale in external RIB manager state and snapshots the transport's
   matching typed route identities for max-prefix accounting
2. Refreshed announcements/withdrawals clear the exact stale entries they
   replace in both views, after their ordered RIB update is accepted
3. Inbound `EoRR` sweeps any remaining unreplaced routes for that family from
   both the RIB and the transport's live max-prefix count

The transport mirror covers every family that contributes to the neighbor's
max-prefix limit: IPv4/IPv6 unicast (including exact Add-Path identity),
`FlowSpec`, EVPN, BGP-LS, VPN, labeled-unicast, and RT-Constrain. Stale routes
remain counted during the refresh window. This intentionally provides no
transient headroom: a peer already at its configured limit can still exceed it
by announcing a new prefix before `EoRR` reconciles an omitted old prefix.

Marker mutation is ordered behind acceptance by the peer's RIB sender. A full
RIB channel applies backpressure without opening or closing the local window;
a closed channel preserves the existing accounting state rather than sweeping
only one side.

For a peer that advertised Graceful Restart, rustbgpd ignores a `BoRR` for a
family until that exact family has completed its initial End-of-RIB. This keeps
RFC 7313 replacement state from overlapping the initial RFC 4724 replay.

Graceful Restart stale state remains separate; ERR uses its own tracking and
does not overload GR `is_stale`.

### Timeout behavior

Each active inbound ERR window has a fixed 5-minute timeout.

If a peer sends `BoRR` but never sends `EoRR`, rustbgpd treats the timeout as
an implicit end-of-refresh sweep for that `(peer, afi, safi)`:

1. transport enqueues an ordinary `EndRouteRefresh` on the same ordered peer
   sender used by inbound UPDATEs
2. after that enqueue succeeds, remaining unreplaced refresh-stale entries are
   withdrawn from the RIB and transport max-prefix mirror
3. the refresh window is closed and a warning is logged

The transport checks expiry before every buffered PDU decode and also owns an
independent timer for quiet peers. If the RIB channel is full, expiry waits so
the implicit end marker cannot be overtaken by the next UPDATE. If the channel
is closed, the session preserves the window and live count and stops processing
the buffered batch; it does not perform an unpaired local sweep. Families with
different refresh deadlines expire independently.

This bounds resource use and prevents stale refresh state from persisting
indefinitely due to buggy peers or dropped inbound markers.

### Outbound response behavior

When a peer asks us for route refresh:

- The RIB always stages a single outbound response unit containing:
  - `BoRR`
  - refreshed routes for the requested family
  - `EoRR`
  - legacy `EndOfRib` family metadata

Transport decides what to emit:

- ERR peers receive `BoRR -> routes -> EoRR`
- non-ERR peers ignore the refresh markers and receive the existing
  `routes -> EndOfRib` behavior

This keeps the RIB response path unified and backward compatible.

### Retry behavior

If a route-refresh response cannot be enqueued, the family is recorded in
`pending_refresh` and the peer is marked dirty. After a successful dirty-peer
resync (or a no-op dirty tick), the RIB retries the full route-refresh
response for each deferred family.

Legacy `pending_eor` remains in place for normal `EndOfRib` retries.

## Consequences

- `SoftResetIn` now has explicit replacement semantics for ERR-capable peers
- Unreplaced inbound routes are removed deterministically at `EoRR`
- Unreplaced inbound routes are also removed if the refresh window times out
- Existing RFC 2918-only peers keep the previous behavior unchanged
- Route-refresh response retries are now retried as whole refresh windows,
  not just as trailing `EndOfRib` markers
- ADR-0027 remains the base RFC 2918 decision, but its refresh-window
  limitation is superseded by this ADR for ERR-capable peers
