### Fixed

- `rbgp` mutation commands no longer wait forever on a daemon that accepts
  the connection but never answers. Runtime controls such as neighbor
  `reset`, `gshut` and route injection stop after 11 minutes. Persisted
  configuration changes and `mrt-dump` stop after 31 minutes. Both budgets
  sit just past the daemon's own bounds. On expiry the command exits 1 with
  an outcome-unknown error that names a command to verify with, and it never
  retries: the daemon may still apply the change. Config transactions and
  live streams are unchanged.
