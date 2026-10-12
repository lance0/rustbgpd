### Added

- `rbgp neighbor PEER` and `NeighborService.GetNeighborState` show a
  per-family stale-route retention row while the RIB retains GR or LLGR stale
  routes for a peer, including while its session is down: the phase
  (`gr_restart`, `gr_awaiting_eor`, or `llgr`), the time until the RIB's next
  sweep or LLGR promotion for that family, and, for a single neighbor, the
  stale-route count. The new `gr_retention` rows and the presence-aware
  `gr_retention_available` flag are additive; `rbgp doctor` warns, naming the
  time left, for each family in the LLGR phase. See
  [Graceful Restart](../docs/reference/operations.md#graceful-restart).
