### Added

- `bgp_readiness_probe_failures_total{reason}` counts each failed `/readyz`
  probe once, by the failing component: `deadline`,
  `peer_manager_unavailable`, `peer_manager_timeout`, `rib_unavailable`,
  `rib_timeout`, `rib_stalled` or `daemon_unavailable`. Readiness status,
  response bodies and deadlines are unchanged.
  `bgp_inbound_connections_dropped_total{reason}` now exports every reason at 0
  from startup, so a first drop is visible to `increase()`.
  **Operator-visible:** the alert pack adds `BgpPolicyTransitionFallback`
  (warning, a `fallback_handoff` or `fallback_cleanup_error` export-policy
  transition in the last 15 minutes), `BgpInboundNotificationBackoffDrops`
  (warning, inbound connections closed during a neighbor's NOTIFICATION
  reconnect wait), `EvpnCoreIsolationHold` (warning) and
  `EvpnCoreIsolationFault` (critical), which mirror the `rbgp doctor`
  core-isolation verdicts. The Grafana overview adds "Readiness probe
  failures" and "Inbound connection drops by reason" panels, and the EVPN
  dashboard adds a "Core isolation" row. The `rbgp` TUI marks a neighbor's
  transmitted prefix count as pending (`~` in the table, `(pending outbound
  resync)` in the detail view) while its outbound resync is pending, as
  `rbgp neighbor` does. See
  [HTTP probes](../docs/reference/operations.md#http-probes).
