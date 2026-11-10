### Fixed

- A session that replaces one the daemon has already retired is no longer
  treated as one side of a connection collision. When an inbound
  connection replaced an idle session, or a session was respawned after an
  abort, and the old session's final `PeerDown` was still queued behind a
  busy RIB, the RIB kept the old session as a possible collision survivor.
  If the replacement then went down under graceful restart before that
  `PeerDown` was handled, the peer's registration failed over to the dead
  session and the replacement's routes were withdrawn instead of retained.
  The replacement now names the session it supersedes when it registers.
  The RIB drops that session at once and ignores what it still delivers,
  so the replacement's routes are retained as stale. A real collision,
  where either session may survive, is handled as before.
