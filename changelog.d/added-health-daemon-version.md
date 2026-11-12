### Added

- `rbgp health` prints the running daemon's version (`Version:`, and
  `daemon_version` in JSON, `null` when an older daemon reports none). After
  a package upgrade without a restart it differs from
  `rustbgpd --version`, which reads the binary on disk; the upgrade
  runbook now verifies with it. See
  [Package upgrade and rollback](../docs/how-to/deployment.md#upgrade).
