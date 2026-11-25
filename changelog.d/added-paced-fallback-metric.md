### Added

- `bgp_rib_paced_fallback_total{job,cause}` counts each time a paced RIB job
  hands its work to a one-turn path: a dirty resync of the member's table, a
  one-turn initial table, or a synchronous group build. `job` names the paced
  work (`first_group_build`, `per_client_best_build`, `reload_build`,
  `initial_replay`, `source_departure`, `release_fanout`) and `cause` the
  condition, such as `scan_repair_limit` or `ineligible_shape`. Each fallback
  also logs a debug event with the peer, job and cause. Initial tables below
  the 10,000-route pacing threshold are not counted. See
  [Paced-job fallbacks](../docs/reference/operations.md#paced-job-fallbacks).
