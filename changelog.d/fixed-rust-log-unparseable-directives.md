### Fixed

- An unparseable directive in `RUST_LOG` no longer discards the whole
  variable. The daemon previously fell back to `info` without saying so when
  any directive failed to parse; it now keeps the valid directives and drops
  only the bad ones.
  **Operator-visible:** each dropped directive is reported with its parse
  error, as one `warning:` line on stderr at startup and as a `warn` event
  when a SIGHUP reload rebuilds the per-peer log filter. A `RUST_LOG` with no
  valid directive still falls back to `info`. Neither case fails startup or
  `--check`.
