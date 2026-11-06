### Fixed

- A failed BLACKHOLE ownership receipt write no longer strands the kernel
  discard route. Previously one write error (for example a full disk) after a
  successful install disabled every later kernel mutation: the route stayed in
  the main table after withdrawal, shutdown and restart, and a re-announcement
  reported `foreign_route_exists`. The daemon now keeps the route owned in
  memory, retries the receipt on every pass, and still removes owned routes on
  withdrawal and shutdown. **Operator-visible:** while the receipt cannot be
  written, routes it does not name report `installed/receipt_write_failed` and
  new installs report `failed/receipt_write_failed`; the first successful write
  restores installs. A receipt that is unreadable or changed outside the daemon
  still fail-stops as `ownership_state_unavailable`. See
  [the BLACKHOLE discard reference](../docs/reference/configuration.md).
