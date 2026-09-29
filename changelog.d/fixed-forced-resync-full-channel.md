### Fixed

- Forced outbound refreshes defer full-table rebuilding while a peer's
  outbound channel is full, then replay once capacity returns. Deferred
  passes no longer produce repeated route-drop counts or warnings.
