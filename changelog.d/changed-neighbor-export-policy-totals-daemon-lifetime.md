### Changed

- A neighbor's `export_policy_routes_permitted` / `export_policy_routes_denied`
  (API `NeighborState` and the `rbgp neighbor` Policy Stats block) no longer
  reset when the session goes down. They now count for the daemon's lifetime
  per neighbor, like the import-policy totals: a reconfigure keeps them, and
  only a daemon restart or deleting the neighbor clears them. The totals
  belong to the neighbor (its address, plus the interface for a scoped
  address) rather than to a bare address. With this, every `NeighborState`
  counter is daemon-lifetime per neighbor. The `bgp_policy_routes_total`
  labels are unchanged.
