### Added

- `NeighborState` reports outbound resync and update-group recovery fallback
  per peer: `outbound_resync_pending`, `outbound_dirty_seconds` and
  `update_group_recovery_fallback` (the `cause` label of
  `bgp_update_group_recovery_fallback_total`). `rbgp neighbor <addr>` shows
  them as `Outbound Resync` and `Recovery Fallback`, and its JSON adds the
  same keys. `rbgp doctor` adds `peer.<addr>.outbound_resync`, yellow while a
  fallback cause is set or a resync has been pending for 60 seconds, and
  `rib.update_group_recovery`, yellow once a `peer_limit`, `daemon_limit` or
  `allocation_failure` fallback has occurred since daemon start. See
  [Update-group recovery fallback](../docs/reference/operations.md#update-group-recovery-fallback).
  The additive fields change the v1 `NeighborService` message-graph digest.
