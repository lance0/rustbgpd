# Grafana Dashboard

A ready-to-import overview dashboard lives at
[`grafana/rustbgpd-overview.json`](grafana/rustbgpd-overview.json)
(uid `rustbgpd-overview`). It covers session health (including graceful
restart and slow-peer queues), RIB scale, update-group membership,
policy-transition actor occupancy, accepted-policy age, policy decisions and
engine errors, route-safety rejections and selection-deferral state,
BMP/event-outbox health, RPKI/ASPA state, and core operations. Every panel
references metrics the daemon actually exports from
`crates/telemetry/src/metrics.rs` — no speculative series.

An explicitly **Alpha** EVPN operations dashboard lives at
[`grafana/rustbgpd-evpn.json`](grafana/rustbgpd-evpn.json)
(uid `rustbgpd-evpn-alpha`). It covers the currently exported Type-2 local
origination signals, aggregate Type-3-inclusive Loc-RIB state, Type-5/IP-VRF
state, DF and attachment-circuit state, duplicate-MAC quarantine, dataplane
repair/adoption/reap activity, ownership conflicts, and decomposed-runtime
fail-stops. Alpha means its panels and variable contract may change with the
VTEP surface.

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

On Linux, each private registry also registers the standard process collector.
Readable, usable `/proc` process data is required: inaccessible data can omit
`process_start_time_seconds`, while unusable boot or stat data can leave its
value zero, preventing the alert from establishing a restart. The shipped
`RustbgpdRestarted` rule reports a sampled start-time change for the stable
`job="rustbgpd"` target over ten minutes. It is a generic restart signal:
planned, manual, and package-driven restarts fire too. Missing pre- or
post-restart samples or changing target labels can miss a restart, and the
signal expires after ten minutes. It cannot attribute exit 70, a crash, or any
other reason; logs and the service manager remain authoritative.

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
2. Upload `docs/grafana/rustbgpd-overview.json` or the Alpha
   `docs/grafana/rustbgpd-evpn.json` (or paste its contents).
3. Pick your Prometheus data source when prompted (the dashboard uses a
   `datasource` template variable, so it binds at import time).

Template variables:

- **Instance** — Prometheus `instance` label, populated from
  `bgp_rib_outbound_registered_peers` (always exported, even at zero).
- **Peer** (`$peer`) — the `peer` label, populated from
  `bgp_peer_admin_enabled`, so configured peers appear even before their first
  FSM transition. Every exported metric family
  identifies a peer the same way, by its bare neighbor address
  (`192.0.2.1`, `2001:db8::1`), so one selector drives every per-peer panel
  and `by (peer)` joins across families match. Supports multiple values
  and All.

Per-peer series are reaped when a peer is deleted, so stale values age out after
the next scrape.

The EVPN dashboard intentionally offers only **Instance** and configured
**VRF** selectors. Both support multiple values and All through simple regex
matching. It does not expose MAC, ESI, netdevice name, peer, or IP selectors;
panels aggregate those dimensions away from rendered output and navigation.
The underlying per-MAC move, first-move timestamp, and quarantine series persist
for the daemon lifetime, however, so their Prometheus storage cardinality and
the query scan can grow even though the displayed result is aggregated.

## Alert rules

A ready-to-load Prometheus alert-rule pack (session down/flapping,
empty Adj-RIB-In, max-prefix near-limit and breach, empty RPKI VRP table, event-outbox
degradation, update-group residue growth, stalled policy transition, a slow
peer, RFC 8212 missing import/export policy, sustained outbound-prefix blocking,
dynamic-neighbor admission near-limit and rejection,
actor polls above 200ms, exact-export rejection, malformed UPDATE disposition,
selection-deferral timeout and ledger overflow, outbound route loss, RFC 9687
send-hold teardown, session lifecycle source loss, live event-stream
lag/desynchronization, BMP feed loss,
stale MRT dumps, and daemon down)
ships at
[`examples/prometheus/rustbgpd-alerts.yml`](../examples/prometheus/rustbgpd-alerts.yml),
with per-rule unit tests in
[`rustbgpd-alerts_test.yml`](../examples/prometheus/rustbgpd-alerts_test.yml)
(`promtool test rules`). It assumes the scrape config above
(`job_name: rustbgpd`).

The loss alerts use a 10-minute counter-increase window and clear after
the last increment ages out:

- `BgpOutboundRouteDrops` is critical because the full outbound distribution
  channel has already discarded outbound BGP work. Inspect the peer writer,
  daemon log, and last error to identify the failed path and correct the
  bottleneck. Then refresh outbound for a missed advertised view, or soft reset
  inbound for a missed inbound ROUTE-REFRESH request.
- `BgpSendHoldExpired` is critical because RFC 9687 expiry has already torn
  down the session without a NOTIFICATION after the remote endpoint stopped
  draining TCP. Inspect the writer and peer before allowing the session to
  recover; repeated increments indicate the receiver or path is still wedged.
- `BgpEventStreamLagged` is warning severity because the daemon and routing
  sessions remain live, but the named `service`/`source` consumer missed
  incremental events. Treat that consumer's local view as desynchronized:
  take a fresh authoritative snapshot for the named service and source, then
  restart the live watch. Use a durable cursor only when that API supports one.
- `BgpSessionLifecycleSourceDrops` is warning severity because a session state
  change was lost before process-local, live, and durable event history. The
  `reason` label distinguishes a full source channel from a closed receiver.
  Treat all incremental session history as potentially incomplete and
  resnapshot current neighbor state. The alert clears after the last source
  drop ages out of its 10-minute window; a flat historical counter stays quiet.
- `BmpSourceDrops`, `BmpLocRibSourceDrops`, and `BmpCollectorDrops` are
  warning severity because routing is unaffected, but the BMP mirror is now
  lossy: a dropped per-peer event forces a synthetic PeerDown/PeerUp so
  collectors rebuild that peer, a dropped Loc-RIB event leaves Loc-RIB
  collectors stale until their next reconnect, and a collector-side drop
  leaves that collector incomplete until it reconnects. Find the slow
  consumer via `bmp_collector_drops_total` and the
  `bmp_loc_rib_dump_live_buffer_*` gauges.

The rules intentionally alert on the exported loss counters, not adjacent
queue-depth, subscriber-count, or slow-peer gauges. A flat non-zero counter is
historical evidence and does not keep an alert firing; only a new increment
inside the bounded window does.

## Reading notes

- Counters are plotted with `rate(...[$__rate_interval])`; gauges are
  plotted raw. Single-stats use last-not-null.
- **Peer administrative / session truth** plots
  `bgp_peer_admin_enabled{peer,interface}` and
  `bgp_peer_session_established{peer,interface}` as 0/1 steps. Its interface
  legends distinguish scoped link-local siblings; unscoped peers carry an
  empty `interface`. The shipped session-down alert joins these exact labels,
  so enabled peers that never Established are visible while disabled peers do
  not page.
- **Exact session state** uses the one-hot vector directly; preserving
  `interface` keeps scoped siblings distinct and summing the six rows provides
  a built-in integrity check:
  `sum by (instance,peer,interface) (bgp_peer_session_state) == 1`.
  Recent Established losses can be grouped without log parsing via
  `sum by (instance,peer,interface,reason)
  (increase(bgp_session_down_total[$__rate_interval]))`. The fixed `reason`
  vocabulary separates locally initiated and remotely received NOTIFICATION
  teardown, local/remote close without NOTIFICATION, transport failure, and
  defensive `unknown`. Local initiation remains the cause when best-effort
  NOTIFICATION delivery fails; neither query adds an alert or overview-dashboard
  panel.
- Exact-export rejection and malformed-UPDATE disposition rates share the
  `$peer` selector, like every other per-peer panel.
  Outbound route-drop and RFC 9687 send-hold alerts preserve that same `peer`
  identity. The live event-stream lag alert instead preserves the metric's
  native `service` and `source` labels so operators can resnapshot and restart
  the affected watch.
  The selection-deferral state panel renders
  the raw `active` and `waiters` gauges as steps because their discrete changes
  are normal convergence activity. Only timeout and bounded-ledger-overflow
  counter increases alert; ordinary release reasons do not. Event-rate panels
  filter out zero-valued seeded series so the legend remains actionable on
  large peer fleets.
- rustbgpd materializes the bounded route-safety counter label sets when a
  session or selection-deferral family is created, before its producer actor
  runs. Prometheus still has to scrape that zero value to establish a sampled
  baseline, as with any pull-based counter.
- Max-prefix capacity panels use the bounded `aggregate`, `ipv4_unicast`,
  and `ipv6_unicast` scopes. Limit/headroom series
  are intentionally absent for unlimited scopes, and every capacity series is
  absent while the session is down; no-data is therefore distinct from zero
  headroom.
- **RFC 8212 missing policy** plots both raw directional gauges as 0/1 steps.
  Both zero-valued series exist for every configured peer even when enforcement
  is off, and are reaped only when the peer is removed.
- **Outbound prefix capacity** keeps raw peer/family usage, finite limit,
  headroom, and blocking state together. Only query D (`blocking`) uses the
  stepped 0..1 right axis; the cumulative `blocked_total` event counter is
  intentionally excluded.
- **Dynamic-neighbor admission capacity** plots raw used, limit, and saturating
  headroom gauges for each selected scrape instance. These daemon metrics are
  process-global and label-free; they cannot provide a listener- or range-level
  breakdown.
- **Dynamic-neighbor admission rejections** plots the non-zero admission
  rejection rate for each selected scrape instance.
- Outbound queue depth is an absolute gauge of coalesced UPDATE frames, sampled
  at enqueue-batch and writer-drain boundaries. A short convergence spike is
  not itself a slow peer; `bgp_peer_slow` is the daemon's persistent 0/1 state.
- The update-group table is discrete. Group IDs 0 and above are stable group
  identities; `-1` legitimately means the peer is on the per-peer fallback
  path.
- Policy-transition **in progress** is current state. **Last completed policy
  transition** is a retained terminal duration and does not count upward while
  another transition runs. Actor p99 uses a fixed 15-minute window and stays
  partitioned by `instance`, `job`, and `poll_kind`. Because polls exist only
  during transitions, p99 is sparse and legitimately shows no data/NaN outside
  those windows. The >200ms view is an `increase` estimate above the exact
  `le="0.2"` histogram boundary.
- **Policy transition outcomes** shows terminal committed, authoritative
  fallback-handoff, and cleanup-error rates by instance. It excludes work that
  never acquired transition ownership and non-terminal actor polls.
- **Config lifecycle outcomes** combines config-transaction activity with the
  bounded SIGHUP signal/task outcome rate. A recovery-fenced reload remains
  owned rather than terminal; use the `bgp_runtime_config_settlement_*` series
  for that state.
- Accepted-policy age is informational and clamped at zero to tolerate clock
  correction. A static-policy deployment legitimately lets this age grow from
  boot; rejected reloads also leave the last accepted timestamp unchanged.
- "Peers registered for distribution" is
  `bgp_rib_outbound_registered_peers` — the closest exported gauge to
  the distribution-plane count. Current configured-peer health is the
  administrative/session truth panel above; state history remains available
  via `bgp_session_state_transitions_total`.
- Panels for optional subsystems (BFD, BMP, RPKI/ASPA, update groups,
  event outbox, graceful restart) stay empty until the corresponding
  feature is configured; vector metrics only emit series once a label
  combination is touched.
- The "Memory (jemalloc)" panel shows data only for builds with the
  `jemalloc` feature (the release container image); other builds do not
  export the `jemalloc_*` gauges.
- EVPN metrics (the `evpn_*` families) remain off the overview dashboard; the
  dedicated Alpha dashboard aggregates MAC, ESI, and netdevice-name dimensions.
  There is no dedicated Type-3, VTEP-reachability, generic FDB/NHG installed
  total, or generic reconcile-report metric today. Type-3 is therefore visible
  only inside the aggregate EVPN Loc-RIB count; the dashboard does not infer
  unsupported per-route-type or installed-object totals.
- **Time since first recorded move for active quarantines** joins current
  quarantine state to a process-lifetime first-move timestamp. Clearing or
  re-quarantining the same key does not reset that timestamp, so the panel is
  not the age of the current quarantine interval.

## Validation and load-bearing proofs

Run the same checks as CI with:

```bash
python3 -m unittest -v scripts/test_check_grafana_dashboard.py
python3 scripts/check-grafana-dashboard.py
promtool check rules examples/prometheus/rustbgpd-alerts.yml
(cd examples/prometheus && promtool test rules rustbgpd-alerts_test.yml)
```

The dashboard checker validates both dashboards independently, parses JSON,
rejects non-integer and duplicate panel IDs, and links every target and
query-variable metric to a registered constructor in
`crates/telemetry/src/metrics.rs`. Histogram `_bucket`, `_count`, and `_sum`
series resolve only from registered histograms; aliases, empty discovery,
unregistered constructors, comments, free strings, and test literals fail
closed. It retains the canonical multi/All peer selector, load-bearing PromQL
and legends, panel types, discrete state rendering, RFC 8212 mappings,
outbound-blocking axis and exclusion, and dynamic-neighbor capacity/rejection
semantics. Descriptions, layout, row collapsed state, and particular unique IDs
are intentionally presentation choices rather than validation contracts.

For the EVPN Alpha dashboard, the checker additionally freezes all 38 current
`evpn_*` family names, metric kinds, and constructor labels. Counter panels must
use `rate` or `increase` before aggregation; gauges must remain raw. It rejects
unknown selector labels, unsafe retention of MAC/ESI/name-style dimensions,
non-regex use of multi-value variables, metric typos, missing Alpha or operator
rows, and loss of any required source-backed signal.

The slow-peer fixture is red if its `== 1` predicate or five-minute hold is
changed. The RFC 8212 matrix covers import-only, export-only, and healthy peers;
the outbound-prefix matrix covers sustained, zero, and transient blocking.
The dynamic-neighbor admission fixture pins the exact 80% ratio and ten-minute
hold against a 79% control, a zero-limit control, and the pre-hold boundary.
Its rejection fixture separates an increasing counter from a flat non-zero
counter, then observes the event after it ages out to pin the ten-minute
`increase` window and single-event boundary.
The RFC 8212 import/export and outbound-prefix-blocking warnings are pending at
4m30s and firing at 5m30s, pinning their predicates and five-minute holds. The
actor fixture is red if `ignoring(le)` is removed, `le="0.2"` is moved to
`0.5`, `> 0` becomes `>= 0`, raw counters
replace `increase`, or `job`/`poll_kind` are aggregated away. Its firing
observation is in `(0.2, 0.5]`; exact-boundary and historical-flat controls
remain healthy.
Each route-safety counter fixture is red if its alert is deleted, its window is
shortened from 15 to 5 minutes, `increase` becomes a raw counter, or `> 0`
becomes `> 1`. Malformed UPDATE fixtures cover all three bounded RFC 7606
dispositions and go red when the rule is restricted to one; exact-export fires
all four canonical rejection reasons, and spans
unicast plus EVPN, so the demonstrated `reason="message_too_long"` and
`family="ipv4_unicast"` restrictions fail. Timeout and overflow fixtures each
fire across multiple supported AFI/SAFI values, so their demonstrated
single-family restrictions and timeout/overflow swaps fail independently.
Selection-deferral fixtures also inject normal active/waiter transitions and
an `all_eor` release so substituting any of those normal signals false-alerts
and fails.
