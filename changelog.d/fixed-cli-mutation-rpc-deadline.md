### Fixed

- `rbgp` mutation commands no longer wait forever on a daemon that accepts
  the connection but never answers. Runtime controls such as neighbor
  `reset`, `gshut` and route injection stop after 11 minutes. Persisted
  configuration changes and `mrt-dump` stop after 31 minutes. Both budgets
  sit just past the daemon's own bounds. On expiry the command exits 1 with
  an outcome-unknown error that names a command to verify with, and it never
  retries: the daemon may still apply the change. Each `rbgp config` diff,
  plan, apply, confirm, abort and rollback RPC stops after 31 minutes, just
  past the daemon's 30-minute operation bound. An expired apply, confirm,
  abort or rollback reports that the transaction may still commit or roll
  back and points at `rbgp config history` or `rbgp config status`. Live
  streams are unchanged.
