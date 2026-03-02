# ADR-0029: Route Reflector (RFC 4456)

**Status:** Accepted
**Date:** 2026-03-02

## Context

iBGP requires a full mesh between all speakers in an AS. This doesn't
scale beyond a handful of peers. Route Reflector (RFC 4456) relaxes
the full-mesh requirement by designating certain speakers as reflectors
that re-advertise iBGP-learned routes based on client/non-client roles.

rustbgpd already has iBGP split-horizon with `RouteOrigin` and
`peer_is_ebgp` tracking. Route Reflector replaces the blanket
suppression with RFC 4456 reflection rules when `cluster_id` is set.

## Decision

### Config

- `cluster_id` (global) — explicit IPv4 address, or defaults to
  `router_id` when any neighbor has `route_reflector_client = true`.
  `None` when no RR clients are configured (standard split-horizon).
- `route_reflector_client` (per-neighbor, default `false`) — only
  valid on iBGP peers (remote_asn == global.asn).

### Reflection rules (RIB manager)

When `cluster_id` is `Some` (RR mode), iBGP split-horizon is replaced:

| Route source | Advertise to |
|---|---|
| eBGP peer | All iBGP peers (unchanged) |
| RR client | All iBGP peers (clients + non-clients) |
| Non-client | Clients only |
| Local | All iBGP peers (unchanged) |

Source peer never receives its own route back (existing `best.peer == peer`
guard). When `cluster_id` is `None`, standard split-horizon applies.

### ORIGINATOR_ID and CLUSTER_LIST attributes

- **ORIGINATOR_ID** (type 9, Optional non-transitive): 4-byte IPv4
  address of the originating speaker's router-id. Set on first
  reflection if not already present.
- **CLUSTER_LIST** (type 10, Optional non-transitive): list of 4-byte
  cluster IDs traversed. Our cluster_id is prepended on each reflection.

Both are stripped on eBGP outbound (must not leave the AS).

### Inbound loop detection (transport)

After AS_PATH loop detection, before RIB insertion:
- **ORIGINATOR_ID == local router-id** → loop (route we originated)
- **Our cluster_id in CLUSTER_LIST** → loop (route already reflected by us)

On loop: log, record `bgp_rr_loop_detected_total` metric, process
withdrawals only, discard announcements. Same pattern as AS_PATH loop.

### Best-path tiebreakers (RFC 4456 §9)

Inserted between step 5 (eBGP over iBGP) and step 6 (lowest peer):
- **5.5** Shortest CLUSTER_LIST length
- **5.6** Lowest ORIGINATOR_ID (only when both routes carry the attribute)

### Borrow checker pattern

`should_suppress_ibgp_inner()` is a free function (not a method) because
`distribute_changes()` holds a mutable borrow on `self.adj_ribs_out`
while needing immutable access to `self.peer_is_rr_client` and
`self.cluster_id`. Pre-extracting these values before the mutable borrow
avoids the E0502 conflict.

## Consequences

- Operators can deploy rustbgpd as a route reflector by setting
  `route_reflector_client = true` on client peers.
- Non-RR configs (no `cluster_id`, no RR clients) preserve exact
  existing behavior.
- The reflection logic is concentrated in `should_suppress_ibgp_inner()`
  with a clear decision table, replacing three inline split-horizon checks.
- ORIGINATOR_ID and CLUSTER_LIST participate in best-path selection,
  preferring shorter reflection paths.
