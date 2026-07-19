# Grafana Dashboard

A ready-to-import overview dashboard lives at
[`grafana/rustbgpd-overview.json`](grafana/rustbgpd-overview.json)
(uid `rustbgpd-overview`). It covers session health (including graceful
restart and slow-peer queues), RIB scale, update-group membership,
policy-transition actor occupancy, accepted-policy age, policy decisions and
engine errors, BMP/event-outbox health, RPKI/ASPA state, and core operations.
Every panel references metrics the daemon actually exports from
`crates/telemetry/src/metrics.rs` — no speculative series.

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
- **Peer endpoint** (`$peer`) — transport/session metrics identify a peer as
  `addr:port`: `192.0.2.1:179` for IPv4 and `[2001:db8::1]:179` for IPv6.
  This selector supports multiple values and All.
- **Neighbor address** (`$neighbor`) — RIB update-group metrics identify the
  same peer by its bare configured address: `192.0.2.1` or `2001:db8::1`.
  It is independently populated from the always-seeded and reaped
  `bgp_peer_update_group` gauge and also supports multiple values and All.

The dashboard intentionally preserves these native, distinct metric identities
instead of hiding a label rewrite inside its selectors. To correlate a row
manually, strip the IPv4 port or the IPv6 brackets and port as shown above.
Per-peer series are reaped when a peer is deleted, so stale values age out after
the next scrape.

## Alert rules

A ready-to-load Prometheus alert-rule pack (session down/flapping,
empty Adj-RIB-In, max-prefix breach, empty RPKI VRP table, event-outbox
degradation, update-group residue growth, stalled policy transition, a slow
peer endpoint, actor polls above 200ms, and daemon down) ships at
[`examples/prometheus/rustbgpd-alerts.yml`](../examples/prometheus/rustbgpd-alerts.yml),
with per-rule unit tests in
[`rustbgpd-alerts_test.yml`](../examples/prometheus/rustbgpd-alerts_test.yml)
(`promtool test rules`). It assumes the scrape config above
(`job_name: rustbgpd`).

## Reading notes

- Counters are plotted with `rate(...[$__rate_interval])`; gauges are
  plotted raw. Single-stats use last-not-null.
- Outbound queue depth is an absolute gauge of coalesced UPDATE frames, sampled
  at enqueue-batch and writer-drain boundaries. A short convergence spike is
  not itself a slow peer; `bgp_peer_slow` is the daemon's persistent 0/1 state.
- The update-group table is discrete. Group IDs 0 and above are stable group
  identities; `-1` legitimately means the neighbor is on the per-peer fallback
  path.
- Policy-transition **in progress** is current state. **Last completed policy
  transition** is a retained terminal duration and does not count upward while
  another transition runs. Actor p99 uses a fixed 15-minute window and stays
  partitioned by `instance`, `job`, and `poll_kind`. Because polls exist only
  during transitions, p99 is sparse and legitimately shows no data/NaN outside
  those windows. The >200ms view is an `increase` estimate above the exact
  `le="0.2"` histogram boundary.
- Accepted-policy age is informational and clamped at zero to tolerate clock
  correction. A static-policy deployment legitimately lets this age grow from
  boot; rejected reloads also leave the last accepted timestamp unchanged.
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

## Validation and load-bearing proofs

Run the same checks as CI with:

```bash
python3 scripts/check-grafana-dashboard.py
promtool check rules examples/prometheus/rustbgpd-alerts.yml
(cd examples/prometheus && promtool test rules rustbgpd-alerts_test.yml)
```

The dashboard checker parses JSON, rejects duplicate panel IDs, validates the
multi/All selector definitions, compares the required PromQL targets after
whitespace normalization, and checks both workflow path filters plus the real
checker step. Its mutation proof makes each of these changes red: malformed
JSON, a non-integer or duplicate ID, deletion of any required target, removal
of the `instance` selector, swapping endpoint/bare-address selectors, removing
`$neighbor`, or replacing the executable workflow step with only a comment.

The slow-peer fixture is red if its `== 1` predicate or five-minute hold is
changed. The actor fixture is red if `ignoring(le)` is removed, `le="0.2"` is
moved to `0.5`, `> 0` becomes `>= 0`, raw counters replace `increase`, or
`job`/`poll_kind` are aggregated away. Its firing observation is in
`(0.2, 0.5]`; exact-boundary and historical-flat controls remain healthy.
