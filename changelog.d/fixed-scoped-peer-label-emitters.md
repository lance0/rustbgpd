### Fixed

- Every emitter of `peer`-labeled series (RIB, session, policy and BFD) now
  passes the neighbor's own value, scoped as `fe80::1%eth0` for an IPv6
  link-local neighbor. Previously a shared map turned a bare link-local
  address into the scoped value of whichever neighbor registered it last.
  When a reload moved a link-local neighbor to another interface, RIB gauge
  and counter writes queued for the old neighbor could land on the
  replacement's series, and counters stayed misattributed until restart.
  `peer` values in steady state are unchanged.
