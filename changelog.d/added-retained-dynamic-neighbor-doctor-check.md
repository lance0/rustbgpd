### Added

- `rbgp doctor` lists the idle dynamic neighbors that keep a
  `dynamic_neighbor_limit` slot for graceful restart retention, as the
  `dynamic_neighbors.retained` check: each neighbor's address, range, reason
  (`its_routes`, `our_routes` or `both`) and deadlines. It is informational,
  and yellow while the limit is full and inbound dynamic connections have been
  refused at it. The daemon publishes the same facts as the new
  `bgp_dynamic_neighbor_retained_until_timestamp_seconds{peer,range,retention}`
  gauge. See
  [Support bundles with `rbgp doctor`](../docs/reference/operations.md#support-bundles-and-triage-checks-rbgp-doctor).
