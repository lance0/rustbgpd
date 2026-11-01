### Added

- `[[dynamic_neighbors]]` ranges take a `bfd = { profile = "..." }` block:
  every session accepted through the range runs single-hop, non-strict BFD
  (RFC 5880/5881) to its source address, for IPv4 and IPv6 global sessions.
  The session registers its BFD session when it is accepted and removes it
  when the session ends, and a genuine BFD Down tears the session down with
  Cease/10 as it does for a static neighbor. A SIGHUP that adds, edits or
  removes a range's `bfd` applies to the running sessions through the reload
  generation without resetting BGP; changing it together with another range
  change is rejected. A connection whose BFD session cannot be registered is
  counted as `bgp_inbound_connections_dropped_total{reason="bfd_unavailable"}`.
  Strict and multihop range BFD are rejected, a range still never
  inherits `bfd` from its peer group, and runtime range CRUD and config
  transactions cannot change it. The setting is outside the v1 inventory.
  See [Dynamic-range BFD](../docs/reference/configuration.md#dynamic-range-bfd).
