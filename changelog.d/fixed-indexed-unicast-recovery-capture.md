### Fixed

- Reuse immutable slab-slot indexes for full unicast recovery captures, with
  exact-key checks and bounded flat fallback under heavy slot churn. Peers that
  negotiate VPN use exact flat storage for their full common recovery proof,
  including unicast rows; existing memory budgets and conservative withdrawal
  fallback remain in force. Incremental and empty-proof sharing is unchanged.
