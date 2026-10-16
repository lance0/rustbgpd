### Fixed

- Service dedicated RIB readiness queries while source-peer teardown collects
  affected keys, recomputes selected routes and distributes withdrawals. Counts
  reflect completed unicast prefix changes, while ordinary reads and mutations
  remain fenced. Teardown exceeding the existing healthy-age bound reports
  `RIB peer teardown stalled` under the new `peer_teardown` value of
  `bgp_rib_readiness_query_wait_seconds{seam}`; existing limits are unchanged.
