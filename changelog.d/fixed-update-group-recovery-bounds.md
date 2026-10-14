### Fixed

- Bound transient unicast/VPN update-group admitted-key recovery capacity
  and preserve owed withdrawals when a send fails without a full channel or
  complete admitted proof is unavailable. Restore shared encoding for plain
  groups and restrict full prior-slot snapshots to per-client-best groups.
  Add `bgp_update_group_recovery_entries`,
  `bgp_update_group_recovery_bytes`, `bgp_update_group_recovery_peak_bytes`,
  and `bgp_update_group_recovery_fallback_total` to expose capacity charge
  and conservative fallback causes. See
  [update-group operation](../docs/reference/configuration.md) for the
  internal bounds and accounting scope.
