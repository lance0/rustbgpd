### Fixed

- A daemon shutting down after a component failure no longer writes a second,
  spurious panic report when a config-persistence write was still queued. The
  runtime cancels that queued write at shutdown, and the persister treated the
  cancellation as a panic. The cancelled write is still not reported as
  published. **Operator-visible:** `<runtime_state_dir>/crash/` and
  `rbgp doctor` bundles hold one report for the failure that caused the
  shutdown, not an extra report reading "`JoinError` reason is not a panic".
