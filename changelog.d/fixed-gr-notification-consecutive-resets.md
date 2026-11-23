### Fixed

- Retain previously GR-stale routes when the RIB receives a second
  graceful restart from a session that exchanged the Notification bit.
  The peer's original End-of-RIB deadline still bounds the GR wait.
