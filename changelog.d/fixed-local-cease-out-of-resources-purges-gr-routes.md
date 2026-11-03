### Fixed

- A session that rustbgpd closes with Cease / Out of Resources (subcode 8)
  now purges the peer's routes when the peer supports graceful restart but
  did not negotiate Notification GR (the RFC 8538 N bit). Before, these
  closes kept the routes as graceful-restart stale for the restart time. The
  closes covered are writer-queue saturation, an expired writer admission
  deadline, an outbound route that cannot be encoded, an export-snapshot
  invariant breach, and a Cease/8 raised while draining before a shutdown or
  reset. With the N bit negotiated, the routes are still retained, as RFC
  8538 specifies for Cease/8.
