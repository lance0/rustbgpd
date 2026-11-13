### Fixed

- A config transaction whose only change is `[global] dynamic_neighbor_limit`
  no longer plans as "no changes". The field is applied by SIGHUP reload and
  has no transaction executor, so the plan now lists
  `[global].dynamic_neighbor_limit (apply via SIGHUP reload)` under
  unsupported sections and the transaction is rejected.
