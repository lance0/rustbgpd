### Fixed

- EVPN runtime failures with fully acknowledged compensation retain the committed
  coordinator without degrading it. SIGHUP reports an EVPN rejection as
  `rejected_no_effect` when no other reload step changes runtime state, or
  `known_partial` alongside independently accepted changes. Unacknowledged effects,
  failed rollback, and previously committed decomposed steps still fence the reload.
- LACP partner netlink errors retain their underlying I/O error in the standard
  error chain.
