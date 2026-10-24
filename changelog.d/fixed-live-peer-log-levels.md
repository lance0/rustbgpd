### Fixed

- A per-neighbor or peer-group `log_level` edit applied by SIGHUP now
  reaches sessions that are already running. Before, the reload swapped in
  a new log filter that matched only sessions started after it, and every
  reload dropped the override from running sessions until they restarted.
  A neighbor written with a non-canonical IPv6 address, such as
  `2001:DB8::0002`, now also gets its level.
  **Operator-visible:** the `RUST_LOG` base level and per-peer span
  directives written in `RUST_LOG` behave as before, and are no longer
  reset for running sessions by a reload; JSON and text output are
  unchanged.
