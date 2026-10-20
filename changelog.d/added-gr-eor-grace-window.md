### Added

- Opt-in planned-restart End-of-RIB grace window: `gr_eor_grace_time` on a
  neighbor or peer group (default off) holds End-of-RIB toward a Graceful
  Restart helper after a marker-backed restart until one deadline fixed at
  daemon start, so injection controllers can replay routes before the helper
  removes its stale copies. Routes and withdrawals keep flowing; every
  End-of-RIB path respects the hold. Release is timer-driven and logged, and
  `bgp_gr_eor_grace_expired_total{peer}` counts it. The window closes the
  observed gap only when replay completes before release; see
  [the configuration reference](../docs/reference/configuration.md#planned-restart-end-of-rib-grace-window).
