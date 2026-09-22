### Changed

- `rbgp doctor --pre-upgrade` now quotes the daemon's status text in the
  `upgrade.transaction` detail for a confirmed transaction that is pending
  with a deadline, as it already did for applying, rollback-failed, and
  ambiguous transactions. An overdue automatic rollback now reports there,
  not only in `rbgp config status`, that it is waiting for the runtime-config
  coordinator.
  **Operator-visible:** the human and `--json` `detail` for a pending
  transaction gains that sentence (for an ordinary pending transaction,
  "Confirmed config transaction is awaiting confirmation."), and the
  following instruction now starts "Confirm it"; the check's status and
  exit code are unchanged. See the
  [pre-upgrade checks](../docs/reference/operations.md).
