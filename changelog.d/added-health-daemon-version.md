### Added

- `rbgp health` prints the running daemon's version (`Version:`, and
  `daemon_version` in JSON, `null` when an older daemon reports none). After
  a package upgrade without a restart it differs from
  `rustbgpd --version`, which reads the binary on disk; the upgrade
  runbook now verifies with it. The opt-in `rbgp-json` envelope advances
  to version 1.2 for this additive field; `rbgp-rib` stays at 1.1. See
  [Package upgrade and rollback](../docs/how-to/deployment.md#upgrade).
