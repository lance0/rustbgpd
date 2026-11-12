### Fixed

- A peer whose import or export policy update timed out, or otherwise went
  unacknowledged, no longer keeps a chain the daemon does not record. The
  session could install the new chain after the deadline while the daemon
  still recorded the prior one, so a later reload back to that prior chain,
  such as reverting `honor_graceful_shutdown` or `honor_blackhole`, sent no
  policy update and reported `complete` while the peer kept the new chain.
  The daemon now treats that peer's installed chain as unknown and resends
  it, with a Route Refresh for import, on the next apply that reaches the
  peer, even when it matches the recorded chain. See
  [Honor-knob partial apply](../docs/reference/reload-matrix.md#honor-knob-partial-apply).
