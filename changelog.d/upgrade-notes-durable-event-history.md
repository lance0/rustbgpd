### Upgrade notes

- A configuration that still contains an `[event_history]` section now fails
  to load, at startup and on reload. Delete the section, and delete any
  `events.db` (plus its `-wal` and `-shm` files) left under
  `runtime_state_dir` or the configured `[event_history].path`; the daemon
  no longer reads them. Before upgrading, settle any pending commit-confirm
  transaction with the previous release (`rbgp config confirm <id>` or
  `rbgp config abort <id>`), and never edit its retained prior, whose length,
  file identity and SHA-256 boot recovery checks. If the daemon is upgraded
  while a pending prior still contains `[event_history]`, startup exits 1
  with "v3 commit-confirm boot authority is invalid or unavailable" and
  leaves the locator, pending files and config untouched; reinstall the
  previous release and start it so its boot recovery restores the prior and
  ends the transaction, remove the section, then upgrade again. A
  config-history entry that contains the section cannot be rolled back to.
  Automation that resumed from `SubscribeFromEvent` cursors should, on
  reconnect, open and buffer `WatchEvents` before re-reading state (separate
  RPCs give no atomic handoff), or use a gNMI `Subscribe`, which subscribes
  before its snapshot. Collectors that need a durable record keep using BMP,
  Prometheus and the daemon logs.
