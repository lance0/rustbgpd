# Grafana Dashboard

A ready-to-import overview dashboard lives at
[`grafana/rustbgpd-overview.json`](grafana/rustbgpd-overview.json)
(uid `rustbgpd-overview`). It covers session health (including graceful
restart), RIB scale (including the per-peer attribute-intern gauge),
churn/distribution (including the ADR-0098 update-group gauges and index
internals), policy decisions and engine errors, BMP/event-outbox health,
RPKI/ASPA state, and an operations row (config transactions, event-stream
subscribers, jemalloc memory). Every panel references metrics the daemon
actually exports from `crates/telemetry/src/metrics.rs` — no speculative
series.

## Enable the metrics endpoint

Metrics are served by the daemon's built-in Prometheus listener,
configured in [`CONFIGURATION.md`](CONFIGURATION.md#globaltelemetry):

```toml
[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"
```

The same listener serves `/metrics`, `/livez`, and `/readyz`. Omit
`prometheus_addr` to disable it.

## Prometheus scrape config

```yaml
scrape_configs:
  - job_name: rustbgpd
    scrape_interval: 15s
    static_configs:
      - targets: ["127.0.0.1:9179"]
```

## Import the dashboard

1. Grafana → **Dashboards → New → Import**.
2. Upload `docs/grafana/rustbgpd-overview.json` (or paste its contents).
3. Pick your Prometheus data source when prompted (the dashboard uses a
   `datasource` template variable, so it binds at import time).

Template variables:

- **Instance** — Prometheus `instance` label, populated from
  `bgp_rib_outbound_registered_peers` (always exported, even at zero).
- **Peer** — the daemon's `peer` label (neighbor address), multi-select
  with an All option. Per-peer series are reaped when a peer is deleted,
  so stale neighbors age out of the picker on the next scrape.

## Alert rules

A ready-to-load Prometheus alert-rule pack (session down/flapping,
empty Adj-RIB-In, max-prefix breach, empty RPKI VRP table, event-outbox
degradation, update-group residue growth, stalled policy transition, daemon
down) ships at
[`examples/prometheus/rustbgpd-alerts.yml`](../examples/prometheus/rustbgpd-alerts.yml),
with per-rule unit tests in
[`rustbgpd-alerts_test.yml`](../examples/prometheus/rustbgpd-alerts_test.yml)
(`promtool test rules`). It assumes the scrape config above
(`job_name: rustbgpd`).

## Reading notes

- Counters are plotted with `rate(...[$__rate_interval])`; gauges are
  plotted raw. Single-stats use last-not-null.
- "Peers registered for distribution" is
  `bgp_rib_outbound_registered_peers` — the closest exported gauge to
  "currently Established peers". The daemon does not export a per-peer
  session-state gauge; state history is available via
  `bgp_session_state_transitions_total`.
- Panels for optional subsystems (BFD, BMP, RPKI/ASPA, update groups,
  event outbox, graceful restart) stay empty until the corresponding
  feature is configured; vector metrics only emit series once a label
  combination is touched.
- The "Memory (jemalloc)" panel shows data only for builds with the
  `jemalloc` feature (the release container image); other builds do not
  export the `jemalloc_*` gauges.
- EVPN metrics (the `evpn_*` families) are intentionally not on this
  overview dashboard; they are VTEP-alpha surface with per-VNI/MAC/ESI
  cardinality better served by a dedicated dashboard.
