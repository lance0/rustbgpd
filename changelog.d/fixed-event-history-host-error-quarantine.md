### Fixed

- A durable event history store that the host will not let the daemon open
  or write at startup (a full filesystem, a read-only mount, files owned by
  another user, I/O errors or locks) is no longer quarantined as corrupt and
  replaced by an empty store. The files stay in place, and startup follows
  `[event_history].required` as it does for a newer schema: exit 1, or
  continue in live-only mode. Only content errors (corrupt or non-SQLite
  files, malformed metadata) still quarantine. Startup now also stages one
  write and rolls it back, so a store the daemon can read but not write fails
  at startup instead of at the first event.
  **Operator-visible:** a `required = true` daemon whose `events.db` is not
  writable by its user now refuses to start instead of starting degraded;
  see [Recovery and degraded health](../docs/reference/configuration.md#recovery-and-degraded-health).
