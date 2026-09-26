### Fixed

- Pace large outbound route envelopes through the bounded writer queue so a
  healthy peer can receive more than 4,096 distinct UPDATE frames without a
  resource teardown. Shared update-group output and replay terminal markers
  retain their ordering while session input, timers, and snapshots stay live.
  A stalled admission still ends in Cease/8 after the configured send-hold
  interval, or its finite default when the RFC send-hold timer is disabled;
  the independent RFC 9687 writer timeout remains local error 8/0.
