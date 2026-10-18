### Fixed

- gNMI `Subscribe` STREAM/`ON_CHANGE` on the neighbor `session-state` leaf
  now works with the default configuration. It reads the live session-event
  stream instead of requiring the opt-in durable event history, so it no
  longer returns `FAILED_PRECONDITION`, and gNMI dial-out
  `mode = "on_change"` no longer requires `[event_history]` to load. A
  subscriber that falls behind the live stream still gets `DATA_LOSS` and
  resynchronizes from a full snapshot on reconnect.
