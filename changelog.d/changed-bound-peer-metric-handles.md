### Changed

- The RIB resolves each outbound peer's `peer` label and its per-commit
  metric series (`bgp_rib_adj_out_prefixes`, `bgp_outbound_prefix_usage`,
  `bgp_outbound_prefix_blocking`, export `bgp_policy_routes_total` and
  `bgp_peer_update_group`) once per registration instead of on every
  Adj-RIB-Out commit, which took a few percent of RIB actor CPU when one
  peer's announcements fan out to hundreds of members. Metric names, labels
  and values are unchanged, including after a peer's series are removed and
  published again.
