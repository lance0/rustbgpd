### Fixed

- `rbgp neighbor` no longer presents an update-group member's advertised count
  as delivered while the member awaits outbound resync. During that window
  `prefixes_sent` is still the group's desired count, which
  `rbgp rib advertised <addr>` and export explain do not back up. The new
  `NeighborState.prefixes_sent_pending` flags it, the detail view prints
  `(pending outbound resync)` after the count, the neighbor table prefixes it
  with `~`, and the JSON adds `prefixes_sent_pending`.
