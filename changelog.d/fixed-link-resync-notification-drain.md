### Fixed

- Apply link notifications queued during a netlink resync before publishing
  the snapshot. An already queued recovery no longer appears as a transient
  link failure, and another overrun keeps the monitor state unknown until a
  successful resync.
