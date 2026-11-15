### Added

- `ListSessionEvents` reports `evicted_total` and `oldest_retained_unix_ms`,
  `bgp_session_event_history_evicted_total` counts evictions, and
  `NeighborState.last_error_unix_ms` records when `last_error` was set.
  **Operator-visible:** when the shared 4096-event session history is full, a
  peer's repeated pre-Established `state_change` retries are evicted before any
  `established` or `lost` event, so a flapping peer no longer pushes out other
  peers' transitions; a nonzero `evicted_total` means rows were dropped, and
  other event types newer than `oldest_retained_unix_ms` are retained.
  `rbgp events sessions` prints a stderr note after an eviction, and `rbgp neighbor` shows when the last error occurred, in
  JSON as `last_error_unix_ms`. The proto fields are additive.
