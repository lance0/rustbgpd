### Fixed

- A foreign kernel route at another metric for the same prefix no longer
  strands a daemon-owned RFC 7999 BLACKHOLE discard route. The reconciler
  used to drop ownership of its row as soon as a foreign row appeared, so the
  discard outlived the withdrawal and every restart until it was deleted by
  hand. The row now stays owned, an adopted row beside a foreign route is
  still reaped, and withdrawal removes only the daemon's row. IPv6 removal now
  names the discard route's metric, because the kernel's IPv6 delete ignores
  the route type and could otherwise remove a co-resident daemon's
  `proto bgp` unicast route for the same prefix.
  **Operator-visible:** `rbgp rib blackholes` keeps reporting such a prefix as
  `installed/owned` instead of `failed/foreign_route_exists`.
