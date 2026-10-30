### Fixed

- Reject superseded-session route updates and completion markers while an
  established peer's outbound registration is still deferred. The current
  session's received routes remain authoritative before its initial table is
  sent. An older session's teardown preserves that current state without a
  reset or replay request. Unregistered legacy emitters retain their existing
  behavior.
