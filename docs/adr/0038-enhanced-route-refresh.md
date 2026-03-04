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
   refresh-stale in external RIB manager state
2. Refreshed announcements/withdrawals clear the exact stale entries they
   replace
3. Inbound `EoRR` sweeps any remaining unreplaced routes for that family

This applies to both unicast families and `FlowSpec`.

Graceful Restart stale state remains separate; ERR uses its own tracking and
does not overload GR `is_stale`.

### Timeout behavior

Each active inbound ERR window has a fixed 5-minute timeout.

If a peer sends `BoRR` but never sends `EoRR`, rustbgpd treats the timeout as
an implicit end-of-refresh sweep for that `(peer, afi, safi)`:

1. remaining unreplaced refresh-stale entries are withdrawn
2. the refresh window is closed
3. a warning is logged

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
