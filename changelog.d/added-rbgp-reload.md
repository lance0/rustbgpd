### Added

- `rbgp reload` sends SIGHUP to the daemon behind the local Unix socket,
  through a pidfd so a reused PID is never signalled, waits for the
  reload that read the config after its signal (a coalesced follow-up
  counts), prints the receipt `rbgp config last-reload` shows, and exits
  0 for `complete`, 2 for `known_partial`, 3 for `rejected_no_effect` or
  `task_failed`, and 1 on error, a daemon restart, or after `--timeout`,
  which bounds the whole command. `GetLastSighupReload` records gain
  `started_monotonic_micros`, the reload's start on the daemon host's
  `CLOCK_MONOTONIC`, which `rbgp reload` uses to match its reload. The
  example systemd unit points automation that needs the outcome at
  `rbgp reload`. See
  [Configuration reload](../docs/reference/operations.md#configuration-reload-sighup).
