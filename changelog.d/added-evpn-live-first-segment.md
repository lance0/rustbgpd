### Added

- A daemon started with no `[[ethernet_segments]]` now takes its first
  Ethernet Segment live. SIGHUP or `ApplyEvpnRuntime` can add an explicit-ESI
  segment or an `esi = "auto-lacp"` segment without a restart, where both
  were rejected with `FAILED_PRECONDITION` before. The segment orchestrator
  starts with the first committed segment; the `auto-lacp` readiness probe
  starts the first time the committed config names an `auto-lacp` bond. A
  refused or failed apply starts neither. Coordinated shutdown drains a
  live-started orchestrator the same way as one started at boot. See
  [Auto-derived ESI](../docs/reference/configuration.md#auto-derived-esi-lacp-type-1).
  **Operator-visible:** on a daemon with no Ethernet Segment,
  `SetEthernetSegmentDrain` for an unconfigured ESI now returns `NOT_FOUND`
  instead of `UNAVAILABLE`.
