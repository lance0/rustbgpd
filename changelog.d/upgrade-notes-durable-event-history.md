### Upgrade notes

- A configuration that still contains an `[event_history]` section now fails
  to load, at startup and on reload. Delete the section, and delete any
  `events.db` (plus its `-wal` and `-shm` files) left under
  `runtime_state_dir` or the configured `[event_history].path`; the daemon
  no longer reads them. Confirm or cancel a pending commit-confirm
  transaction before upgrading: a pending prior configuration that contains
  `[event_history]` stops startup until the section is removed, and a
  config-history entry that contains it cannot be rolled back to.
  Automation that resumed from `SubscribeFromEvent` cursors should re-read
  current state on reconnect, for example with a gNMI `Subscribe`, which
  sends a full snapshot before changes. Collectors that need a durable
  record keep using BMP, Prometheus and the daemon logs.
