### Fixed

- A failed BLACKHOLE ownership receipt write no longer strands the kernel
  discard route. Previously one write error (for example a full disk) after a
  successful install disabled every later kernel mutation: the route stayed in
  the main table after withdrawal, shutdown and restart, and a re-announcement
  reported `foreign_route_exists`. The receipt is now written before a route is
  installed and after it is deleted, so it always names every daemon route, and
  a write failure no longer stops withdrawal or shutdown from removing owned
  routes. **Operator-visible:** while the receipt cannot be written, new
  installs report `failed/receipt_write_failed` and are retried on the next
  pass. A receipt that is unreadable or changed outside the daemon still
  fail-stops as `ownership_state_unavailable`. See
  [the BLACKHOLE discard reference](../docs/reference/configuration.md).
