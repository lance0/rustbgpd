### Added

- `bgp_update_group_recovery_limit_bytes{scope}` exports the fixed unicast/VPN
  update-group recovery caps (`peer` and `daemon`), and
  `bgp_rib_outbound_dirty_peers` reports how many peers are currently dirty
  and awaiting outbound resync, sampled from RIB state.
  **Operator-visible:** two new warning alerts ship in the alert pack.
  `BgpUpdateGroupRecoveryLimited` fires when a `peer_limit`, `daemon_limit` or
  `allocation_failure` recovery fallback was recorded in the last 15 minutes.
  `BgpOutboundResyncStalled` fires when the dirty-peer gauge stays above zero
  for 15 minutes without a recorded full drain. The `rbgp doctor`
  `rib.update_group_recovery` check also warns when the recovery charge is
  above 75% of the daemon cap. The Grafana overview adds "Update-group
  recovery" and "Outbound dirty peers" panels, and the "Ungrouped (fallback)
  peers" description now lists every fallback reason. See
  [update-group recovery fallback](../docs/reference/operations.md#update-group-recovery-fallback).
