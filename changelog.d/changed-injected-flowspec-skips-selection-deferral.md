### Changed

- FlowSpec rules injected through `AddFlowSpec` or `AddLeasedFlowSpec` are
  now selected and sent to Established peers at once after a planned
  restart, instead of waiting out RFC 4724 selection deferral (up to the
  maximum effective `gr_restart_time`, 120 seconds by default, when a static
  Graceful Restart neighbor never comes up). Received FlowSpec rules and the
  FlowSpec End-of-RIB still wait for the deferral to release; when it
  releases, the ordinary best-path order decides between a local and a
  received rule with the same key. Injected unicast routes, RTBH host routes
  included, stay deferred. See the
  [ADR-0141 amendment](../docs/adr/0141-injection-owner-lease.md#amendment-injected-flowspec-skips-selection-deferral-2026-10-26).
  **Operator-visible:** during the deferral window `ListFlowSpecRoutes` reads
  a re-injected rule as `selected: true`, and
  `ListFlowSpecExportDispositions` reports it `COMMITTED` rather than
  `PENDING`/`selection_deferred`. The v1 contract and the End-of-RIB grace
  window documentation now describe the unicast deferral window and state
  that `MarkReplayComplete` does not shorten it.
