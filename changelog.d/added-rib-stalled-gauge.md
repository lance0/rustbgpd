### Added

- New gauge `bgp_rib_stalled` is 1 while the RIB actor answers "stalled" (one
  export-policy transition, selection-deferral release or peer teardown has
  run for 30 seconds or more) and 0 otherwise. The daemon samples it every
  5 seconds on the telemetry thread, so a stalled RIB is visible to an install
  that only scrapes `/metrics`; a scrape adds no work to the RIB.
  **Operator-visible:** the `BgpReadinessRibStalled` alert now reads this
  gauge instead of `bgp_readiness_probe_failures_total{reason="rib_stalled"}`
  and no longer needs a recurring `/readyz` probe. It fires when the gauge
  reads 1 on every evaluation for ten minutes; an evaluation that reads 0
  resets it. The gauge is sampled only when the telemetry listener is
  configured. The `/readyz` counter is unchanged.
