### Added

- `EvpnService.ListEthernetSegments` and `rbgp evpn es list` report the DF
  preference and Don't-Preempt bit the local Type 4 route carries
  (`advertised_df_preference`, `advertised_df_dont_preempt`) beside the
  configured values, and whether RFC 9785 recovery is still waiting for
  remote Type 4 routes (`df_recovery_pending`,
  `df_recovery_remaining_ms`). The advertised values differ from the
  configured ones while a recovering PE inherits another PE's preference.
