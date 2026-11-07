### Fixed

- A persisted runtime mutation (`rbgp config apply`, neighbor, policy,
  peer-group or FIB-table changes) could overwrite an operator's edit to the
  config file. The edit was lost if it was saved while the mutation applied,
  or at any point after the daemon's last read or write and before a SIGHUP.
  The daemon now checks the file's bytes before it publishes. A pending edit
  refuses the mutation with `FAILED_PRECONDITION` before anything changes.
  An edit that lands while a config transaction applies makes the
  transaction compensate and fail. The other mutations cannot undo their
  runtime change, so they fence the daemon (exit 70), and it restarts from
  the edited file. In every case the edit stays on disk; SIGHUP adopts it.
  The check is active from boot, also after a commit-confirm boot revert,
  and through a symlinked config path it reads the file the write replaces.
  A save in the brief interval between the last check and the rename can
  still be replaced.
  See [runtime changes rewrite the config file](../docs/reference/operations.md#runtime-changes-rewrite-the-config-file).
