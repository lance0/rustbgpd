### Fixed

- A peer marked dirty for resync no longer has its full outbound table rebuilt
  on every distribution pass and resync tick while its outbound channel is
  still full. Each such rebuild failed to send and was discarded, so a few
  slow-reading route-server members could hold the RIB actor at hundreds of
  milliseconds per pass and keep the ingest channel full. The resync now runs
  once the channel has room; forced resyncs (outbound refresh) still attempt
  every time.
  **Operator-visible:** while a dirty peer's channel stays full, the repeated
  `outbound channel full or closed — marking dirty for resync` warning and the
  matching `bgp_outbound_route_drops_total` increment no longer occur on every
  pass; a debug-level `outbound channel still full — deferring dirty resync`
  event is logged instead.
