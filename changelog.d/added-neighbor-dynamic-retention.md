### Added

- A dynamic neighbor whose session went idle stays visible while the RIB
  retains its GR or LLGR stale routes: `rbgp neighbor`, `ListNeighbors` and
  `GetNeighborState` return a row for it with its retention phase and time
  left, marked by the new presence-aware `retention_only` field
  (`"retention_only": true` in JSON, source
  `retention only (no session or configuration)`). The row disappears when
  retention ends. `rbgp doctor` runs only the retention check for such a
  row, and `rbgp diff advertised` refuses it as not configured. The
  `rbgp neighbor --json` list now also carries the optional `gr_retention`
  rows, with stale-route counts, and `gr_retention_available`. See
  [Graceful Restart](../docs/reference/operations.md#graceful-restart).
