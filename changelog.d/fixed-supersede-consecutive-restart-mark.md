### Fixed

- A session that replaces a graceful-restart reconnect before the
  reconnect's own end reaches the RIB now applies the consecutive-restart
  rule (RFC 4724 section 4.2) at its `PeerUp`. A peer that restarted,
  reconnected, sent fresh routes and was replaced again could have the
  replaced session's end queued behind the replacement's `PeerUp`; that
  end is discarded as superseded, so the replaced session's fresh routes
  were never marked stale and stayed installed and advertised after the
  replacement's End-of-RIB. The superseding `PeerUp` now deletes routes
  still stale from the earlier restart, marks the replaced session's
  routes stale, and keeps long-lived-stale routes (RFC 9494 section 4.2);
  the replacement's End-of-RIB or the stale-routes timer removes what it
  does not re-announce. Families the replaced session had already
  completed with End-of-RIB, or that the first graceful-restart capability
  did not list, are withdrawn at that point rather than held stale, until
  the replacement re-announces them. An in-order end, a replacement
  without graceful restart, and an unnamed connection collision are
  handled as before.
  **Operator-visible:** routes from a replaced session during
  graceful-restart recovery no longer stay advertised after the new
  session's End-of-RIB.
