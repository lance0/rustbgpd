### Fixed

- Disabling a peer (`rbgp neighbor disable`, gRPC `DisableNeighbor`, a config
  `admin_down`) or deleting it (gRPC `DeleteNeighbor`, `rbgp neighbor delete`,
  removal by a config reload) no longer leaves routes retained when the peer
  negotiated RFC 8538 Notification Graceful Restart. The plain Cease /
  Administrative Shutdown made both sides keep each other's routes as stale
  for the restart time, then any LLGR stale time, although the session was
  not coming back. The NOTIFICATION is now a Cease / Hard Reset wrapping the
  Administrative Shutdown and any RFC 9003 shutdown communication (RFC 8538
  §5.1, §5.2), as is a Cease / Out of Resources raised while the teardown
  drains queued output. A disable that finds the session Idle or reconnecting
  purges routes still retained from an earlier session loss. A dynamic peer
  removed because a config rollback left no range that admits it, and an
  interface-only (unnumbered) neighbor removed from the configuration, are
  handled like a deleted peer. The session-crash and maximum-prefix latches
  stop the peer the same way; a maximum-prefix breach already sent its own
  Cease as a Hard Reset.
  **Operator-visible:** such peers see subcode 9 instead of 2, and the
  NOTIFICATION event and `bgp_notifications_sent_total` report subcode 9.
  Daemon shutdown, a neighbor rebuilt by a reload and a dynamic peer bounced
  onto new peer-group configuration still send a plain Cease /
  Administrative Shutdown and keep their retention. With the N bit, a
  reload or config transaction that fails after removing peers has already
  hard-reset them, so restoring them on rollback is a full session flap
  rather than a graceful-restart resume.
  See [Enable / disable a peer](../docs/reference/operations.md#enable--disable-a-peer).
