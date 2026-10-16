### Fixed

- Reuse immutable slab-slot indexes for full unicast recovery captures, with
  exact-key checks and bounded flat fallback under heavy slot churn. Groups
  that negotiate VPN share the same pool, with an exact hashed VPN position
  index in place of slab slots, so full-table VPN members dirtied together no
  longer exhaust the recovery memory limit and fall back to conservative
  withdrawal. Existing memory budgets and the fallback remain in force.
  Incremental and empty-proof sharing is unchanged.
