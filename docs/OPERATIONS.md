# Operations Guide

Practical reference for running rustbgpd in production. For config syntax,
see [CONFIGURATION.md](CONFIGURATION.md). For security posture, see
[SECURITY.md](SECURITY.md). For the end-to-end install + lifecycle
walkthrough (systemd setup, Docker, containerlab quick-start, sample
profiles), see [deployment.md](deployment.md).

---

## Starting the daemon

```bash
rustbgpd /etc/rustbgpd/config.toml
```

Or via systemd (see `examples/systemd/rustbgpd.service`):

```bash
sudo systemctl start rustbgpd
```

The daemon validates the config file at startup. Validation errors display
rustc-style diagnostics showing the offending TOML line with column markers:

```
error: invalid hold_time 2: must be 0 or >= 3
  --> /etc/rustbgpd/config.toml:12:13
   |
12 | hold_time = 2
   |             ^ must be 0 or >= 3
```

The daemon exits with code 1 — it never starts with an invalid config.

On success, structured JSON logs go to stdout. If `prometheus_addr` is
configured, use `GET /readyz` on that listener as the orchestrator readiness
signal; it returns ready once the PeerManager and RIB actors answer their
bounded probes. The `starting rustbgpd` log line means process startup reached
runtime wiring, not that every actor has answered a readiness probe yet.

### Per-peer log filtering

Set `log_level` on any neighbor or peer group to override the global log level:

```toml
[[neighbors]]
address = "10.0.0.1"
remote_asn = 65001
log_level = "debug"
```

Or filter via `RUST_LOG` using the per-peer tracing span:

```bash
RUST_LOG=info,peer{peer_addr=10.0.0.1}=debug rustbgpd /etc/rustbgpd/config.toml
```

---

## Config validation

Validate a config file without starting the daemon:

```bash
rustbgpd --check /etc/rustbgpd/config.toml
```

Prints rustc-style diagnostics on error, or `config OK` on success.

## Config diff (dry-run reload)

Preview what a SIGHUP reload would change before sending it:

```bash
# Compare proposed config against current config
rustbgpd --diff /tmp/new-config.toml /etc/rustbgpd/config.toml

# JSON output for scripting
rustbgpd --diff /tmp/new-config.toml /etc/rustbgpd/config.toml --json
```

When the daemon is already running, compare a candidate file against the live
runtime snapshot instead of the on-disk file, then plan/apply a supported
transaction with an optimistic runtime snapshot token:

`rbgp` is the supported CLI spelling.

```bash
rbgp config diff --from-file /tmp/new-config.toml
rbgp --json config diff --from-file /tmp/new-config.toml

rbgp config plan --from-file /tmp/new-config.toml
rbgp --json config plan --from-file /tmp/new-config.toml

rbgp config apply --from-file /tmp/new-config.toml \
  --expected-runtime-snapshot-token kv1:...
```

For a safe deploy that should roll back unless explicitly confirmed, provide a
confirm handle and timeout on the same apply. The daemon applies the candidate
immediately, starts the timer, and rolls back when the timer expires unless the
same handle is confirmed:

```bash
rbgp config apply --from-file /tmp/new-config.toml \
  --expected-runtime-snapshot-token kv1:... \
  --confirm-id deploy-20260605-1 \
  --confirm-timeout 120

rbgp config status
rbgp config confirm deploy-20260605-1
# or, to roll back immediately:
rbgp config abort deploy-20260605-1
```

Confirm handles must be non-empty, at most 128 characters, and free of control
characters. `--confirm-timeout` requires `--confirm-id`; the daemon default is
600 seconds and the maximum accepted timeout is 86400 seconds.

While a confirmed transaction is applying or awaiting confirmation, SIGHUP
reload is ignored and every persisted runtime config mutator (FIB-table and
dynamic-neighbor CRUD, neighbor lifecycle, a further `config apply`) is rejected
with `FAILED_PRECONDITION`, so a pending timeout rollback cannot be overwritten
by a later ad hoc change. The fence clears once the transaction is confirmed,
aborted, or auto-reverted.

`rbgp config status` reports the lifecycle outcome: `pending` (timer running),
`confirmed`, `aborted`, `auto_reverted` (timer expired and the pre-commit
snapshot was re-applied), or one of the two rollback-failure terminal states,
`auto_revert_failed` / `abort_failed` — these mean the daemon could not re-apply
the pre-commit snapshot, the fence has been cleared, and the running config
needs manual correction.

Commit-confirmed also survives a daemon restart or crash inside the confirm
window. Before the candidate commits, the daemon journals the pre-commit config
snapshot to `<runtime_state_dir>/commit-confirm-journal.json` (atomic
write-tmp+rename+fsync); confirm, abort, and timeout auto-revert consume the
journal. If the daemon starts and finds an unconfirmed journal, it reverts at
boot — before adopting the on-disk config, and regardless of how much confirm
time was left, because the operator's confirming session died with the old
process (the NETCONF RFC 6241 §8.4 rule: session loss cancels a confirmed
commit). The unconfirmed candidate config file is saved aside as
`<config>.unconfirmed` and the boot banner + an ERROR log name the transaction
and that file; re-plan and re-apply to retry it. A torn or unreadable journal,
or one whose embedded config no longer parses, refuses boot with a message
naming both the journal and the config file — delete the journal manually only
if you are sure the on-disk config is the one you want.

The boot-revert save-aside moves the unconfirmed candidate to
`<config>.unconfirmed` with an atomic hard-link + unlink, so it never clobbers
an existing `.unconfirmed`. That needs the config file and its directory to be
on a filesystem that supports hard links — every local filesystem does. On a
filesystem without hard-link support (some FUSE mounts, certain NFS setups),
the save-aside fails and the daemon **refuses to boot** with the journal left
intact, rather than risk an unsafe revert. Keep the config and
`runtime_state_dir` on a local filesystem (the default); this mainly matters
for containerized deployments that bind-mount the config from an exotic
backend.

For a static-neighbor edit, change the neighbor in the candidate file (for
example `hold_time`, `max_prefixes`, policy-chain refs, or ORF receive), run
`config plan`, then apply with the returned token. The transaction reconfigures
that peer using the same delete/re-add semantics as SIGHUP and rolls back if
apply or persistence fails.

The live API returns redacted text / JSON diff buckets and never exports the
daemon's full config snapshot. Transaction apply is intentionally narrower than
SIGHUP: v1 commits one pure runtime family at a time (`[[fib_tables]]`,
`[[dynamic_neighbors]]`, static `[[neighbors]]` add/delete/modify, or
catalog-only policy/neighbor-set/peer-group/global-chain edits). It can also
commit policy/neighbor-set/peer-group/global-chain edits that only move existing
static neighbors' or accepted dynamic peers' resolved import/export policy
chains; the executor re-applies those chains to live sessions and rolls them
back if apply or persistence fails.
Because import-chain changes are re-evaluated with Route Refresh, every impacted
Established peer must have negotiated Route Refresh or the transaction is
rejected without committing the candidate.
Peer-group/session reshape transactions can also rebuild affected sessions
(for example, a peer-group `hold_time` edit inherited by existing members):
static neighbors are reconfigured in place with captured prior peer configs and
rollback, and live dynamic sessions accepted by an affected
`[[dynamic_neighbors]]` range are gracefully reset after persist so they
re-accept under the committed config on reconnect (ADR-0086). Mixed-family
candidates, dynamic-range peer-group reassignments, mixed policy/session
effective impact, and unsupported sections are rejected without mutation.

Output is grouped into two actionable sections plus a per-neighbor
effective-impact view:

- **Reload-applied changes** — `[[neighbors]]` deltas, neighbor sets,
  named policies, peer groups, global / per-neighbor policy chains, and
  the hot-applied `[global]` flags `honor_graceful_shutdown` and
  control-plane-only `honor_blackhole`. SIGHUP reconciles all of these.
- **Restart-required changes** — `[global]` ASN/router-id/families,
  `[global.telemetry.grpc_*]` listener config (including TLS / mTLS),
  `[rpki]`, `[bmp]`, `[mrt]`, unsupported EVPN shapes,
  `apply_bum_enforcement`, and inline `policy.import` / `policy.export`
  legacy statements. Supported EVPN edits are shape-aware and appear under
  Reload-applied. Surfaced with a one-line migration hint where applicable.
- **Effectively impacted neighbors (via inheritance)** — every
  neighbor whose resolved import / export chain would move at reload,
  with the upstream change(s) responsible (peer-group / policy /
  neighbor-set / global chain). The JSON form carries `kind` as
  `"policy_chain"` for pure live-policy impact or `"session_reshape"`
  when inherited peer-group/session state changes.
  Catches transitive references: a
  policy definition edit picked up via the global `import_chain`
  (chain list itself unchanged) or via a peer-group's chain
  (peer-group record unchanged) still flags every affected member.

Exit codes: 0 = no actionable changes, 1 = actionable changes found,
2 = error (bad config, missing file).

## Configuration reload (SIGHUP)

```bash
sudo systemctl reload rustbgpd
# or: kill -HUP $(pidof rustbgpd)
```

What happens (in dependency order):

1. The daemon re-reads the TOML config file from disk and diffs it
   against the running snapshot, bucket by bucket.
2. **Definitions land first** — neighbor sets, named policies, peer
   groups, and global import / export chains. Each bucket fires a
   single-shot command at the peer manager that goes through the same
   `apply_policy_change` / `apply_peer_group_change` paths the gRPC API
   uses; effect matches a sequence of `SetPolicy` / `SetPeerGroup` /
   `SetGlobalImportChain` mutations. Hot-applied policy chains land at
   every affected peer's session task without tearing the BGP session.
3. **`[[neighbors]]` reconcile** — `diff_neighbors()` computes per-peer
   add/remove/change deltas; `ReconcilePeers` applies them.
4. **Deletes of obsolete definitions** in reverse-dependency order so
   transient `still referenced` rejections don't fire.
5. **Automatic Route Refresh on import-policy hot-apply** — when a
   peer's effective import chain changes (whether triggered by a
   SIGHUP reload or a gRPC mutation), the peer manager issues
   `soft_reset_in` (gated on Established) so routes already in
   `AdjRibIn` get re-evaluated against the new policy. Operators no
   longer need to run `softreset` manually after a chain swap.

Reload halts at the first step failure and returns a partial-state
snapshot, so the daemon's in-memory config tracks what actually
landed at the peer manager. Operator fixes the failing TOML and
reloads again to converge against the half-applied state. Per-step
errors are logged with structured `bucket` / `target` / `error`
fields.

**Restart-required surfaces** (logged at reload, surfaced under
"Restart-required" in `--diff`): `[global]` ASN/router-id/families,
`[global.telemetry.grpc_tcp]` and `[global.telemetry.grpc_uds]`
listener config (including any TLS / mTLS field), `[rpki]`, `[bmp]`,
`[mrt]`, inline `policy.import` / `policy.export` legacy global-fallback
statements, and `apply_bum_enforcement`. EVPN table edits are
coordinator-gated rather than blanket restart-required: SIGHUP uses the
same daemon actor converger as `EvpnService.ApplyEvpnRuntime` for supported
L2VNI/IP-VRF/ES shapes, additive build-up, atomic tenant teardown,
`ip_vrf` relink, and L2VNI-only mixed compositions. Static
`rustbgpd --diff` is shape-aware: supported EVPN edits appear under
Reload-applied, while unsupported mixed edits or L3VNI/device/table IP-VRF
identity changes remain restart-required or rejected. Missing EVPN actors
or actor convergence failure are runtime outcomes; those pin back to the
committed runtime model and are logged. `apply_bum_enforcement` remains
restart-required because it is a Gate 8b dataplane actor startup flag.

`[[fib_tables]]` is the exception to those restart-required tables: when the
ADR-0061 FIB reconciler is running (at least one table present at startup),
table add / remove / edit **hot-applies** on SIGHUP, with the in-memory
snapshot advancing only after the reconciler acks the new desired set. Only
*starting* the FIB subsystem from an empty config (0→N) still requires a
restart — surfaced under "Restart-required" in `--diff` as `[[fib_tables]]
(start FIB from an empty config)`.

Use `rustbgpd --diff` to preview changes before reloading; the diff
buckets the changes by Reload-applied / Restart-required and surfaces
a per-neighbor "effective impact" view for transitive references
(policy edit picked up via global `import_chain`, peer-group's
chain, etc.).

---

## What state persists

| State | Where | When |
|-------|-------|------|
| Neighbor add/delete/modify via gRPC | Config file (atomic write) | Serialized with SIGHUP reload; the RPC waits for persistence acknowledgement and rolls runtime back if the write is rejected |
| Dynamic-neighbor add/delete via gRPC | Config file (atomic write) | Serialized with SIGHUP reload; the RPC waits for persistence acknowledgement and rolls the matcher back if the write is rejected |
| GR restart marker | `<runtime_state_dir>/gr-restart.toml` | On coordinated shutdown |
| General FIB owned-state | `<runtime_state_dir>/fib-owned.json` | After successful ADR-0061 FIB apply/drain |
| MRT dump files | `[mrt] output_dir` | On periodic timer or `TriggerMrtDump` |
| gRPC UDS socket | `<runtime_state_dir>/grpc.sock` | Daemon lifetime |

**Not persisted:** routing state (Adj-RIB-In, Loc-RIB, Adj-RIB-Out), policy
evaluation state, RPKI VRP tables, BMP client state. The ADR-0061 FIB file is
only an ownership receipt for rows rustbgpd already installed; all route
selection state is still rebuilt from peers after restart.

---

## Upgrading

1. Build the new version: `cargo build --release`
2. Stop the daemon: `systemctl stop rustbgpd` (or `rbgp shutdown`)
3. Replace the binary at `/usr/local/bin/rustbgpd`
4. Start: `systemctl start rustbgpd`

When Graceful Restart is enabled (the default), the coordinated shutdown in
step 2 writes a GR restart marker. On step 4, the daemon advertises `R=1` to
static peers, asking them to retain our routes while we reconnect. The restart
window is the largest `gr_restart_time` among all GR-enabled peers.
rustbgpd still advertises `forwarding_preserved = false`; use a drained
route-server pair or another traffic-shift procedure when forwarding
continuity matters.

For zero-downtime upgrades in a route-server pair, drain traffic to the
standby, upgrade, then swap.

---

## Failure modes

### gRPC server dies unexpectedly

The daemon treats an unexpected gRPC server exit as fatal and initiates a
coordinated shutdown (NOTIFICATION to all peers, GR marker write). This is
deliberate: losing the control plane means losing the ability to shut down
cleanly later. See [ADR-0022](adr/0022-grpc-server-supervision.md).

### RPKI cache unreachable

Each RTR client reconnects independently after a fixed `retry_interval`
(default 600s). If no fresh `EndOfData` arrives before
`expire_interval` (default 7200s), cached VRPs for that server are discarded.
Routes are re-validated against the remaining VRP table.

When all caches are down, the VRP table is empty and all routes have
validation state `NotFound`. If your policy denies `NotFound` routes, this
will cause route drops. The recommended policy is to deny `Invalid` and
prefer `Valid`, leaving `NotFound` as a neutral fallback.

### BMP collector unreachable

Each BMP client reconnects independently with backoff (default
`reconnect_interval` = 30s). During disconnection, BMP events for that
collector are dropped. No routing state is affected — BMP is purely
observational. On reconnect, the client sends a fresh Initiation message;
the collector rebuilds state from subsequent Peer Up and Route Monitoring
messages.

### MRT dump failure

If the output directory is not writable, the MRT manager logs an error and
skips that dump cycle. Periodic dumps continue on the next interval. The
daemon does not crash on MRT failures.

### Peer max-prefix exceeded

When a peer sends more prefixes than `max_prefixes`, the daemon sends a
NOTIFICATION (Cease / Maximum Number of Prefixes Reached) and tears down the
session. The peer is not automatically re-enabled — use
`rbgp neighbor <addr> enable` or the gRPC `EnableNeighbor` RPC to
restart it.

---

## Key metrics to watch

Metrics and HTTP probes are exposed on the Prometheus endpoint if
`prometheus_addr` is configured. If omitted, metrics are still collected
internally and available via gRPC `GetMetrics` and `GetHealth` RPCs, but the
HTTP `/livez` and `/readyz` probes are disabled.

### HTTP probes

The telemetry HTTP listener exposes three read-only paths:

| Path | Success | Failure |
|------|---------|---------|
| `/metrics` | `200` Prometheus text exposition | `500` if metrics encoding fails |
| `/livez` | `200 ok` once the listener accepts connections | No actor checks |
| `/readyz` | `200 ready` when PeerManager and RIB respond within 200 ms total | `503 not ready: <reason>` |

Readiness is actor responsiveness, not routing policy. A daemon with zero
configured peers, zero Established peers, or zero routes can still be ready.
Event-history, EVPN, FIB, and peer-count health are surfaced through their own
metrics and status commands rather than as v1 readiness gates.

### Per-peer series lifecycle

All `peer`-labeled series are removed when the peer is **deleted** — a static
neighbor delete (CLI/gRPC/config reload) or a dynamic peer's auto-removal
when its session ends. Prometheus marks the removed series stale at the next
scrape, so deleted peers stop appearing in instant queries instead of
freezing at their last value. A session flap or admin disable does *not*
remove anything: a flapping peer keeps its counters and history. If a deleted
peer is later re-added, its per-peer counters restart from zero — PromQL
`rate()` / `increase()` treat that as an ordinary counter reset, so
dashboards see no negative-rate artifacts. Process-global counters and
families keyed by other identities (AFI/SAFI, VRF, VNI, BMP collector) are
never removed.

### Health

| Metric | What it tells you |
|--------|-------------------|
| `bgp_session_established_total` | Cumulative sessions that reached Established (per-process counter; resets on restart) |
| `bgp_session_flaps_total` | Cumulative session flaps |
| `bgp_session_state_transitions_total` | FSM state transitions |

The current count of Established peers and daemon uptime are read via
`ControlService.GetHealth` / `rbgp health` (and `GetMetrics`), not a
Prometheus gauge. `GetHealth` uses the same 200 ms core-actor deadline as
`/readyz`, but returns peer and route counts and therefore remains an
authenticated sensitive-read surface.

### Routing

| Metric | What it tells you |
|--------|-------------------|
| `bgp_rib_loc_prefixes{afi_safi}` | Loc-RIB size (best paths) per AFI/SAFI |
| `bgp_rib_prefixes{peer,afi_safi}` | Adj-RIB-In size per peer + AFI/SAFI (received) |
| `bgp_rib_adj_out_prefixes{peer,afi_safi}` | Adj-RIB-Out size per peer + AFI/SAFI (advertised) |
| `bgp_rib_attr_intern_size{peer}` | Unique interned attribute sets in a peer's Adj-RIB-In (attribute-memory dedup). Sum across peers for the daemon-wide total; tracks `gc_intern_table` reclamation and growth under churn |
| `bgp_messages_received_total` | Inbound BGP messages by type |
| `bgp_messages_sent_total` | Outbound BGP messages by type |
| `bgp_route_refresh_in_progress{peer,afi_safi}` | Active inbound Enhanced Route Refresh window for a peer/family (1 = active, 0 = inactive) |
| `bgp_route_refresh_stale_entries{peer,afi_safi}` | Routes still awaiting replacement before EoRR or timeout during an inbound Enhanced Route Refresh window |
| `bgp_rib_outbound_registered_peers` | Peers currently registered for outbound route distribution. An Established session whose peer is missing here has a wedged advertisement path: keepalives still flow but no UPDATE can reach the peer until a new session re-registers |
| `bgp_rib_outbound_registration_replaced_total{peer}` | `PeerUp` re-registrations that replaced a still-registered outbound sender for the same address — two sessions overlapped (collision window); the replacement resets the prior session's RIB state and keeps the superseded session live for failover; its `PeerDown` is matched by session identity |
| `bgp_rib_stale_peer_down_ignored_total{peer}` | `PeerDown`/`PeerGracefulRestart` events discarded because their session id didn't match the registered session — a stale teardown from a superseded collision-loser session; the surviving session's state is untouched |
| `bgp_rib_stale_session_message_ignored_total{peer,kind}` | Session-scoped RIB messages discarded by the same session-identity rule — a superseded session's queued message processed after the replacement's `PeerUp`. `kind` is `routes` (`RoutesReceived`), `eor` (End-of-RIB), `refresh` (route-refresh request / RFC 7313 BoRR/EoRR), `orf` (RFC 5291 ORF push), or `policy_context` (peer-group policy identity). The registered session's state is untouched |
| `bgp_rib_outbound_registration_failover_total{peer}` | Outbound registrations handed to another live session for the same address after the active session's `PeerDown`/GR-down (the symmetric collision interleaving: the loser's `PeerUp` replaced the winner's registration before the loser went down). The survivor is re-registered, re-sent the initial table, and asked for an inbound ROUTE-REFRESH |
| `bgp_rib_dirty_resync_total{outcome}` | Dirty-peer resync timer fires, by `cleared` / `still_dirty` |
| `bgp_rib_ingest_channel_depth` | RIB manager ingest queue depth, sampled once per manager loop iteration; pegged at capacity means producers are parked on backpressure |

### Ingress rejection / route-leak detection

Mechanisms that block routes for protocol-correctness reasons: most
reject at the session boundary before the route reaches the RIB; the
one egress case is `egress_to_upstream_via_otc`, which suppresses an
outbound advertisement after best-path selection. Where a metric
carries a `reason` label, its values are the canonical contract
pinned in `crates/telemetry/src/reason_labels.rs` — stable across
releases and shared verbatim by the metric label, the log-line
`reason` token, and (for OTC) the structured `OTC_ROUTE_BLOCKED`
event payload, so alert expressions can key on them safely. Metrics
without a `reason` label encode the mechanism in the metric name.

| Metric | What it tells you |
|--------|-------------------|
| `bgp_otc_routes_blocked_total{peer,reason}` | RFC 9234 Only-to-Customer route-leak blocks (ADR-0071). `reason` is `ingress_from_customer_rsclient` (OTC-tagged route arrived while we act as Provider / Route Server), `ingress_peer_mismatch` (lateral Peer session, OTC value is not the peer's ASN), `malformed_length` (OTC attribute undecodable; announcements dropped treat-as-withdraw style per RFC 7606), or `egress_to_upstream_via_otc` (outbound advertisement of an OTC-tagged route toward a Provider / Peer / Route Server suppressed) |
| `bgp_as_path_loop_detected_total{peer}` | Prefixes rejected because our own ASN appears in the received `AS_PATH` (RFC 4271 §9.1.2). No `reason` label — the mechanism is the metric name; withdrawals in the same UPDATE are still processed |
| `bgp_rr_loop_detected_total{peer}` | UPDATEs rejected by route-reflection loop detection (RFC 4456 §8). No `reason` label; the debug log line emitted with each increment carries `reason=originator_id` (received `ORIGINATOR_ID` equals our router-id) or `reason=cluster_list` (our cluster-id already in `CLUSTER_LIST`) |
| `bgp_bgpls_nlri_discarded_total{peer}` | Known BGP-LS NLRIs dropped for out-of-order descriptor TLVs (RFC 9552 fault management). The affected NLRI is isolated and the session is preserved; each increment carries a `family=bgp_ls` debug log line. Fatal BGP-LS framing/length errors are not counted here — they still reset the session |
| `bgp_max_prefix_exceeded_total{peer}` | `max_prefixes` ceiling breaches; each increment is followed by a Cease / Maximum Number of Prefixes Reached NOTIFICATION and session teardown (see "Peer max-prefix exceeded" above) |

### Event Streams

| Metric | What it tells you |
|--------|-------------------|
| `bgp_event_stream_lagged_total{service,source}` | Events skipped because a live stream subscriber fell behind the bounded broadcast channel. `service` is `watch_events`, `watch_route_events`, or `watch_routes`; `source` is `route`, `session`, `evpn`, `dataplane`, or `dataplane_route` where applicable |
| `bgp_event_stream_subscribers{service,source}` | Current live stream subscriber count by service/source |
| `bgp_route_event_history_depth` | Current number of unicast route events retained for `ListRouteEvents` / `rbgp events` history queries |
| `bgp_route_event_history_capacity` | Fixed capacity of the bounded unicast route-event history ring |

`WatchEvents`, `WatchRouteEvents`, and `WatchRoutes` are live tails, not
durable queues. Non-zero `bgp_event_stream_lagged_total` means at least one
client missed events and should combine a fresh snapshot or `ListRouteEvents`
query with a new live watch.

### Durable Event Cursor (ADR-0072)

The durable outbox (`SubscribeFromEvent` RPC, CLI
`rbgp events watch --from-event-id <N>`, and the
`examples/event-bridge/` reference binary) survives daemon restart and
exposes a monotonic `event_id` cursor. The legacy live surfaces above
(`WatchEvents` / `WatchRoutes` / `List*Events`) keep their existing
ring-backed behavior and are unaffected by this section.

**Opt-in — default off as of v0.32.0.** The outbox is disabled by default
(v0.32.0 benchmarking measured ~62 MB RSS plus roughly double the peak CPU at
2p/100k — too much to impose on operators who never consume the cursor). Enable
it explicitly and restart:

```toml
[event_history]
enabled = true
max_bytes = 256_000_000   # size retention to your collector's reconnect SLA
```

**Two deployment profiles:**

- **Lean / high-scale (the default):** `[event_history].enabled = false`.
  Routing fast and lean; `SubscribeFromEvent` and gNMI `Subscribe ON_CHANGE`
  return `FAILED_PRECONDITION`, but the live `WatchEvents` / `WatchRoutes` /
  `List*Events` surfaces still provide real-time observability.
  **Security-signal caveat:** the structured `OTC_ROUTE_BLOCKED` event (RFC 9234
  route-leak prevention — per-decision prefixes, AS_PATH, roles) is emitted
  *only* through the durable outbox, so with the lean default it is **not**
  available via `SubscribeFromEvent`. Blocks are still observable via the
  always-on `bgp_otc_routes_blocked_total{peer,reason}` counter, the
  `otc_routes_blocked` per-neighbor scalar, and the daemon log — but if you need
  the rich per-decision event for incident reconstruction or a SIEM feed, enable
  event-history (the observability/replay profile below).
- **Observability / replay:** `[event_history].enabled = true` with
  `max_events` / `max_bytes` sized for your collector's worst-case reconnect
  window. Gives restart-safe `event_id` cursor replay; budget the ~62 MB RSS +
  CPU shown in `docs/BENCHMARKS.md`.

Producer set: `route`, `evpn`, `session` (lifecycle + notification),
`policy` (config-mutation `POLICY_CHANGED` events **plus**
transport-layer `OTC_ROUTE_BLOCKED` route-leak decisions — both
ride on `EVENT_CATEGORY_POLICY`, discriminated by `BgpEventType`),
`bfd`, and `dataplane` (FIB + blackhole summaries and per-route
install / withdraw / failure events). All six categories are
produced through the durable outbox when
`[event_history].enabled = true`. The dataplane poller is
startup-spawned so durable summaries flow regardless of whether
any `WatchEvents` subscriber is alive.

| Metric | What it tells you |
|--------|-------------------|
| `bgp_event_outbox_committed_total{category}` | Events durably committed to the local outbox, per category. Increments inside EHM after the SQLite transaction commits — not on producer enqueue. |
| `bgp_event_outbox_dropped_total{category, reason}` | Events dropped before reaching durable storage, or skipped during cursor decode. `reason` is `queue_full`, `closed`, `db_error`, `decode_failure`, `opaque_codec`, or `source_lagged`. `source_lagged` fires when an upstream broadcast receiver (FIB or BFD bridge) reports `Lagged(missed)` — those missed events never reached the bridge body and therefore never reached EHM; the counter increments by `missed`. `queue_full`, `db_error`, decode/codec failures, and `source_lagged` flip `bgp_event_outbox_degraded` to `1`; shutdown-time `closed` drops do not. |
| `bgp_event_outbox_queue_depth{category}` | Pending events in the EHM producer queue by category. Climbs before drops start — early-warning signal. |
| `bgp_event_outbox_db_size_bytes` | Combined size of `events.db` + WAL on disk, refreshed after commits and retention passes. `[event_history].max_bytes` is the soft retention trigger. |
| `bgp_event_outbox_retention_evicted_total{reason}` | Events evicted by the retention pass. `reason` is `count_cap` or `byte_cap`. |
| `bgp_event_outbox_latest_event_id` | The latest committed `event_id`. Forward progress indicator. |
| `bgp_event_outbox_open_failures_total` | DB-open failures across the process lifetime. Typically 0 or 1; non-zero means EHM went into recovery or pass-through at startup. |
| `bgp_event_outbox_degraded` | `1` once the outbox has seen a durability-impacting drop, decode/codec failure, or open failure since start. Does not auto-clear in v1; the operator restarts to clear. |
| `bgp_event_outbox_cursor_gap_total` | `SubscribeFromEvent` requests whose leading frame was a `StreamLagEvent` (the requested cursor was older than the retention floor). Operator signal that `[event_history].max_events` / `max_bytes` is undersized for the collector reconnect SLA. |

**`FAILED_PRECONDITION` on `SubscribeFromEvent`** means one of:

1. `[event_history].enabled = false` in the daemon config — by design;
   the legacy live surfaces still work, but the durable cursor is
   intentionally off. Flip to `true` and restart.
2. `[event_history].required = false` and EHM failed to open
   `events.db` at startup (permission denied, disk full, corruption).
   `bgp_event_outbox_open_failures_total` will be ≥ 1 and
   `bgp_event_outbox_degraded` is `1`. Check the daemon log for the
   reason; fix permissions / free disk / restore from backup, then
   restart. Pre-1.0, `required = true` is the strictest posture — the
   daemon refuses to start when the outbox cannot be opened.
3. EHM dropped into pass-through mode at runtime because the
   allocator anchor became unrecoverable (e.g. a moved
   `.stale-<ts>` quarantine file with no sidecar fallback). Same
   recovery: check log, fix the underlying I/O issue, restart.

**Sizing retention** — `max_events` and `max_bytes` are *both* hard
caps; whichever fires first wins. Default `100_000` events /
`256_000_000` bytes covers a few minutes of even a busy daemon's
event stream. Operators with longer collector-reconnect tolerance
should raise both proportionally; collectors should alert on
`bgp_event_outbox_cursor_gap_total > 0` to know when retention is
too small for their SLA. Note that `bgp_event_outbox_db_size_bytes`
can briefly exceed `max_bytes` between retention passes — `max_bytes`
is the trigger, not a strict cap. SQLite may also hold onto freed
pages rather than immediately shrink the main DB.

**External-bus integration** — see `examples/event-bridge/` for the
reference skeleton. The pattern is:
1. Connect with the last `event_id` your downstream sink confirmed
   durable.
2. Forward `BgpEvent` records to your sink.
3. Advance the persisted `last_seen_event_id` **only after** the
   sink confirms durable receipt.
4. Treat a leading `StreamLagEvent` as a gap signal, not a stream
   end — your collector lost events older than the retention floor.
5. Use `BgpEvent.timestamp`, not `event_id`, for causal joins
   across event categories. The durable `event_id` is
   order-of-arrival at the EHM actor, not order-of-occurrence at
   each producer.

## gRPC authorization audit and resource guardrails

ADR-0064 v1 uses the daemon's structured JSON log path plus Prometheus metrics
as the operational audit surface. rustbgpd does not run a separate in-daemon
audit file writer or remote audit sink in this release. That keeps audit
emission on the existing non-blocking logging path instead of adding a second
I/O path that could wedge routing-control tasks if a disk, syslog daemon, or
collector stalls.

For production, collect stdout/stderr with journald, syslog, or your log agent
of choice and apply retention outside the daemon:

- Retain `grpc_authz` records for at least the same window as management-plane
  change approvals and incident timelines. Thirty to ninety days is a practical
  minimum for most environments; regulated deployments should use their own
  audit policy.
- Store gRPC authorization logs where only network operators, security
  responders, and the log-collection service account can read them. The records
  mask known credential-bearing fields, but they still expose management-plane
  method names, principals, listener posture, peer names, and topology context.
- Rotate locally before the filesystem can pressure the daemon host. With
  journald, bound `SystemMaxUse` / `RuntimeMaxUse`; with syslog or a file-based
  collector, use normal logrotate or collector retention controls.
- Export logs to remote storage when `operator_only` actions, role denials, or
  authentication failures need tamper-resistant evidence.

Useful local queries:

```bash
# All gRPC authorization records from a systemd unit.
journalctl -u rustbgpd -o cat --since -24h \
  | jq 'select(.target == "grpc_authz")'

# Operator-only calls, including forwarded and denied attempts.
journalctl -u rustbgpd -o cat --since -24h \
  | jq 'select(.target == "grpc_authz" and .tier == "operator_only")'

# Tier or role denials that should be investigated before enabling tier mode.
journalctl -u rustbgpd -o cat --since -24h \
  | jq 'select(.target == "grpc_authz"
      and (.result == "listener_tier_denied"
        or .result == "principal_unmapped"
        or .result == "role_tier_denied"
        or .result == "authn_failed"))'

# Mutating/operator activity grouped by principal when jq has group_by.
journalctl -u rustbgpd -o cat --since -24h \
  | jq -s '[.[] | select(.target == "grpc_authz"
      and (.tier == "mutating" or .tier == "operator_only"))]
      | group_by(.principal)
      | map({principal: .[0].principal, count: length})'
```

Prometheus should watch both authorization volume and stream pressure:

```promql
# Any denied management-plane call in the last five minutes.
sum by (tier, result, authn, access_mode) (
  increase(bgp_grpc_authz_decisions_total{
    result=~"listener_tier_denied|principal_unmapped|role_tier_denied|authn_failed"
  }[5m])
)

# Operator-only calls, successful or denied.
sum by (result, authn, access_mode) (
  increase(bgp_grpc_authz_decisions_total{tier="operator_only"}[5m])
)

# Slow live-stream consumers missing events.
sum by (service, source) (
  increase(bgp_event_stream_lagged_total[5m])
)

# Current live stream fan-out.
sum by (service, source) (bgp_event_stream_subscribers)
```

Resource-abuse posture for v1 is intentionally operational rather than a new
daemon-side rate limiter. The existing controls are listener `max_tier`, opt-in
per-principal tier enforcement, pagination on large route-list RPCs, bounded
event-history rings, bounded stream broadcasts, subscriber gauges, and lag
counters. Keep accepted clients on a management network and use separate
listeners when monitoring, automation, and operators need different ceilings.

The RPCs that deserve the most attention are:

| Class | Examples | Guardrail |
|-------|----------|-----------|
| Large sensitive reads | `ListReceivedRoutes`, `ListBestRoutes`, `ListAdvertisedRoutes`, `ListEvpnRoutes`, `ListFlowSpecRoutes`, `GetMetrics` | Prefer pagination or narrow filters, set client deadlines, and alert on sustained `sensitive_read` volume |
| Live streams | `WatchRoutes`, `WatchRouteEvents`, `EventService.WatchEvents` | Keep clients draining, reconnect after `stream_lagged`, and alert on subscriber count or lag spikes |
| History queries | `ListRouteEvents`, `ListSessionEvents`, `ListPolicyEvents` | Histories are bounded and process-local; use explicit limits for dashboards |
| Mutating calls | Neighbor, policy, peer-group, injection RPCs | Use listener `max_tier`, role enforcement, and audit alerts on `mutating` volume |
| Operator-only calls | `Shutdown`, `TriggerMrtDump`, `SetGracefulShutdown`, selected policy/global changes | Restrict to operator principals/listeners and page on unexpected `operator_only` activity |

Clients should set realistic deadlines on unary inventory queries and avoid
opening idle streams that do not continuously read responses. For long-lived
streams, use keepalive settings conservatively; aggressive keepalives can
create avoidable load and disconnected streams fail like any other RPC. After a
lag warning, treat the stream as a live tail after a gap and refresh state with
a snapshot or bounded history query.

### General Unicast FIB

These metrics are present when the daemon is built with the ADR-0061 general
FIB runtime. The actor is still default-off; configure at least one
`[[fib_tables]]` block to start it.

| Metric | What it tells you |
|--------|-------------------|
| `bgp_fib_routes_installed_total` | Configured-table routes successfully installed or replaced in the Linux kernel |
| `bgp_fib_routes_withdrawn_total` | Daemon-owned configured-table routes successfully removed from the kernel |
| `bgp_fib_routes_rejected_total{reason="foreign_route_exists"}` | Desired route suppressed because a kernel row already exists at the same table / metric / prefix and is not daemon-owned |
| `bgp_fib_routes_rejected_total{reason="owned_route_drifted"}` | A row rustbgpd previously owned was externally changed; rustbgpd released ownership and preserved the live kernel row |
| `bgp_fib_routes_rejected_total{reason="next_hop_family_unsupported"}` | Desired route suppressed because the table family and BGP next-hop family do not match |
| `bgp_fib_routes_rejected_total{reason="link_local_next_hop_scope_missing"}` | Desired route suppressed because an IPv6 link-local next-hop was selected without the egress interface needed to resolve it in the Linux FIB |
| `bgp_fib_routes_rejected_total{reason="peer_not_allowed"}` | Desired route suppressed by a `[[fib_tables]]` peer / peer-group allow-list |
| `bgp_fib_routes_rejected_total{reason="route_limit_exceeded"}` | Desired route suppressed because the table exceeded its `max_routes` hard cap; existing owned rows are frozen in place |
| `bgp_fib_kernel_failures_total{action="setup"}` | Runtime could not open the Linux FIB programming surface at startup |
| `bgp_fib_kernel_failures_total{action="dump"}` | Runtime could not dump configured route tables during a reconcile pass |
| `bgp_fib_kernel_failures_total{action="install"}` | Kernel rejected an add operation |
| `bgp_fib_kernel_failures_total{action="replace"}` | Kernel rejected a replace operation |
| `bgp_fib_kernel_failures_total{action="remove"}` | Kernel rejected a remove operation |
| `bgp_fib_kernel_failures_total{action="unsupported_platform"}` | Config requested FIB programming on a non-Linux build |
| `bgp_kernel_route_notify_dropped_total{actor,reason="channel_full"}` | Kernel route-event wake feed dropped an event before the FIB or BLACKHOLE reconciler could consume it; periodic reconcile remains the repair backstop |
| `bgp_kernel_route_notify_subscription_failures_total{actor,group}` | The FIB or BLACKHOLE reconciler failed to subscribe to an IPv4/IPv6 route multicast group and is running with periodic-only kernel-drift repair |

Use `rbgp rib fib --json` as the per-route companion to these counters.
The most important states to investigate are `foreign_route_exists` and
`owned_route_drifted`. `foreign_route_exists` means rustbgpd never proved
ownership of the live row; `owned_route_drifted` means rustbgpd previously
owned the key but another writer changed the live kernel row. In both cases,
rustbgpd preserves the row instead of overwriting or deleting it. After an
ungraceful restart, rustbgpd only recovers rows that also appear in
`<runtime_state_dir>/fib-owned.json`, match the unchanged `[[fib_tables]]`
declaration, and still have the exact kernel next-hop value the previous
instance owned. If the persisted file has an unsupported version or stale table
signature, rustbgpd renames it to `fib-owned.json.stale` and starts with empty
owned-state.

### Graceful Restart

| Metric | What it tells you |
|--------|-------------------|
| `bgp_gr_active_peers` | Peers currently in GR stale-route state |
| `bgp_gr_stale_routes` | Routes currently marked stale |
| `bgp_gr_timer_expired_total` | GR timers that expired (routes swept) |

### BFD

| Metric | What it tells you |
|--------|-------------------|
| `bfd_session_up{peer}` | Per-peer BFD session state (1 = Up, 0 = not Up) |
| `bfd_session_flaps_total{peer}` | BFD session flaps (transitions out of Up) per peer |

### Config transactions

| Metric | What it tells you |
|--------|-------------------|
| `bgp_config_transaction_lifecycle_total{operation, outcome}` | Confirmed config transaction lifecycle transitions. `operation` is `confirm`, `abort`, or `auto_revert`; `outcome` is `success` or `failure`. |

Alert on `outcome="failure"`: it means an operator abort or timer-driven
auto-revert attempted rollback but could not complete, and
`GetConfigTransactionStatus` / `rbgp config status` will hold the redacted last
failed lifecycle record for triage. The counter intentionally omits
`confirm_id`, candidate content, peer labels, and free-form error text; those
details stay in the structured daemon log and RPC status.

### RPKI / ASPA validation

| Metric | What it tells you |
|--------|-------------------|
| `bgp_rpki_vrp_count{af="ipv4"}` | IPv4 VRP entries loaded |
| `bgp_rpki_vrp_count{af="ipv6"}` | IPv6 VRP entries loaded |
| `bgp_aspa_records_total` | ASPA customer records loaded in the merged table |
| `bgp_validation_import_refreshes_total{dependency, outcome}` | Inbound Route Refresh work triggered by VRP / ASPA cache updates for peers whose import policy matches validation state. `dependency` is `rpki` or `aspa`; `outcome` is `eligible`, `refreshed`, `skipped_not_established`, or `failed`. |

A sudden drop in VRP count likely means a cache connection was lost or the
cache itself has stale data. A non-zero `failed` outcome on
`bgp_validation_import_refreshes_total` means the cache update arrived, but one
or more validation-dependent peers could not be refreshed immediately; check the
daemon log for the peer-specific reason.

### EVPN VTEP alpha

| Metric | What it tells you |
|--------|-------------------|
| `evpn_local_originations_total{action="inject"}` | Locally learned MACs that the originator successfully handed to the RIB as Type 2 advertisements |
| `evpn_local_originations_total{action="withdraw"}` | Locally aged / deleted MACs that the originator successfully handed to the RIB as Type 2 withdraws |
| `evpn_local_origination_errors_total{action="inject"}` | Failed local Type 2 inject attempts: RIB channel closed, RIB rejected the inject, or the reply was dropped |
| `evpn_local_origination_errors_total{action="withdraw"}` | Failed local Type 2 withdraw attempts: RIB channel closed, RIB rejected the withdraw, or the reply was dropped |
| `evpn_local_observations_dropped_total{reason="channel_full"}` | Kernel local-MAC observations classified by the netlink notify loop but dropped because the originator channel was full |
| `evpn_local_observations_dropped_total{reason="channel_closed"}` | Kernel local-MAC observations classified by the netlink notify loop after the originator receiver was gone |
| `evpn_duplicate_mac_moves_total{vni,mac}` | Cross-VTEP MAC mobility contention events detected by the local originator |
| `evpn_duplicate_mac_first_move_timestamp_seconds{vni,mac}` | Unix timestamp of the first observed duplicate-MAC / mobility contention event for that key |
| `evpn_duplicate_mac_threshold_exceeded_total{vni,mac,action}` | RFC 7432 §15.1 M/N threshold crossings. `action` is `detect` or `suppress_local` from the per-instance config |
| `evpn_duplicate_mac_quarantine_active{vni,mac}` | `1` while `action = "suppress_local"` is actively suppressing local Type 2 originations for that key; returns to `0` after timed recovery |
| `evpn_ip_vrf_remote_prefix_drops{vrf,reason}` | Current remote Type 5 projection drops by bounded IP-VRF/reason labels. Overlay-index reasons include `overlay_index_no_linked_l2vni`, `unresolved_overlay_index_gateway`, and `ambiguous_overlay_index_gateway`; `vrf="_unscoped"` means the drop happened before a configured IP-VRF could be selected. |

During M37 or a synthetic MAC-churn soak, the inject and withdraw counters
should follow the `bridge fdb add` / `bridge fdb del` cadence. Any non-zero
observation-drop counter means the kernel event reached the notify loop but
not the originator; any non-zero origination-error counter means the
observation reached the originator but did not complete at the RIB boundary.
`evpn_duplicate_mac_moves_total` and
`evpn_duplicate_mac_first_move_timestamp_seconds` are intentionally per
`(VNI, MAC)`; alert on threshold crossings rather than on one-off
mobility during planned host moves. Default `duplicate_mac_detection`
behavior is detect-only. When an instance opts into
`action = "suppress_local"`, active quarantine withdraws/suppresses only
locally-originated Type 2 routes for that MAC and automatically retries
after `recovery_seconds`; remote EVPN route visibility stays intact, while
dataplane receive-side intent for the quarantined key is filtered out of
the local FDB reconciler. After confirming the loop condition is gone, an
operator can clear one active quarantine immediately:

```bash
rbgp evpn clear-duplicate-mac --vni 100 --mac aa:bb:cc:dd:ee:ff
```

The clear path returns success with `cleared=false` if no active quarantine
exists. When it clears an active key, the originator resets the active gauge
to `0`, republishes the quarantine set, and replays still-live local MAC or
MAC+IP state through the normal recovery path.
`rbgp evpn instances` also reports each L2VNI's
`readiness=ready|not-ready|unbound|unknown` and
`originated-local-macs=N`; `rbgp evpn instances --json` exposes the
same values as `readiness`, `not_ready_reason`, and
`originated_local_macs_count`.

---

## Key log messages

rustbgpd uses structured JSON logging. Key messages to watch for:

| Message | Level | Meaning |
|---------|-------|---------|
| `starting rustbgpd` | INFO | Daemon started successfully |
| `peer session established` | INFO | BGP session reached Established |
| `peer session down` | INFO | BGP session left Established |
| `received shutdown signal` | INFO | SIGTERM/SIGINT received |
| `shutdown initiated via gRPC` | INFO | `Shutdown` RPC called |
| `gRPC server exited unexpectedly` | ERROR | Fatal — coordinated shutdown follows |
| `config reloaded` | INFO | SIGHUP reload succeeded |
| `config reload failed` | ERROR | SIGHUP reload failed — previous config kept |
| `GR restart marker` | INFO | Restart marker written or read |
| `max-prefix limit exceeded` | WARN | Peer exceeded prefix limit |
| `gRPC TCP listener bound to a non-loopback address` | WARN | Security posture warning |

---

## Debugging a session that won't establish

1. **Check peer state:**
   ```bash
   rbgp neighbor
   ```
   Look at the FSM state. `Active` means we're trying to connect but TCP
   isn't establishing. `OpenSent`/`OpenConfirm` means OPEN exchange is
   failing.

2. **Check logs for the peer:**
   ```bash
   journalctl -u rustbgpd | grep "10.0.0.2"
   ```
   Look for NOTIFICATION codes, capability mismatches, or hold timer expiry.

3. **Common causes:**
   - **TCP not reaching:** Firewall, wrong address, peer not listening on 179
   - **ASN mismatch:** Remote peer has a different `remote-as` configured for us
   - **Router ID collision:** Two speakers with the same router ID
   - **Hold timer zero vs non-zero:** One side sends hold_time=0, the other expects keepalives
   - **Capability mismatch:** Check address family negotiation in OPEN logs
   - **MD5 mismatch:** TCP RST with no BGP-level error; check both sides' passwords
   - **TTL security:** GTSM requires TTL=255; multi-hop peers will fail

4. **Verify from the remote side:**
   Check FRR/BIRD/peer logs for their view of the session attempt.

---

## Common operational tasks

### Add a peer at runtime

```bash
rbgp neighbor 10.0.0.5 add --asn 65005 --description "new-peer"
rbgp neighbor 203.0.113.2 add --asn 65002 --role provider --strict-role
```

The peer is persisted to the config file automatically. `--role` enables RFC
9234 BGP Roles / OTC route-leak protection for static eBGP peers; the optional
`--strict-role` flag rejects peers that do not advertise a compatible Role.

### Remove a peer

```bash
rbgp neighbor 10.0.0.5 delete
```

Sends NOTIFICATION, tears down the session, removes from config.

### Manage dynamic-neighbor ranges at runtime

```bash
rbgp dynamic-neighbor list
rbgp dynamic-neighbor add 10.0.0.0/24 --peer-group ix-members
rbgp dynamic-neighbor delete 10.0.0.0/24
```

Adds or removes `[[dynamic_neighbors]]` accept-prefix ranges without a
restart (`AddDynamicNeighbor` / `DeleteDynamicNeighbor`, tier `mutating`).
`add` validates exactly like config load: the peer group must exist and must
not enable BFD, the prefix must be valid, and the effective prefix must not
duplicate an existing range. `delete` stops *future* accepts only —
already-established dynamic peers keep running and drain when they next
return to Idle. Omitting `--asn` uses the accept-any sentinel (`remote_asn = 0`);
once a peer is accepted, operational state surfaces the ASN learned from the
peer's OPEN. When the daemon was started with `--config`, changes persist to the
TOML file (atomic write) before the RPC returns and survive a restart.
The live mutation path is serialized with SIGHUP reload, so a reload cannot
drop an accepted-but-not-yet-persisted range.

### Soft reset (re-evaluate import policy)

```bash
rbgp neighbor 10.0.0.2 softreset
```

Re-applies import policy to all routes from this peer without tearing down
the session.

> Note: as of v0.12.0, `update_runtime_policies` automatically issues a
> Route Refresh whenever a peer's effective import chain materially
> changes (via SIGHUP reload, gRPC `SetPolicy`, `SetPeerGroup`, or
> chain mutations). Operators only need this command after manual
> ad-hoc edits or to recover from a session-mid-restart at the time
> of the original reload. The `pending_refresh` retry semantics on
> `ManagedPeer` cover most of those edge cases automatically.

### Explain an import decision (ADR-0073)

Answer "why didn't this prefix come in?" — or "what did the chain do to
it when it did?" — from the per-session import-decision cache:

```bash
rbgp policy explain --neighbor 10.0.0.2 --prefix 198.51.100.0/24
rbgp policy explain --neighbor 10.0.0.2 --prefix 2001:db8::/32 --json
# Add-Path peer: omit --path-id to see every path, or pin one:
rbgp policy explain --neighbor 10.0.0.2 --prefix 192.0.2.0/24 --path-id 3
```

The address family is inferred from the prefix (IPv4 / IPv6 unicast).
Each result reports an outcome:

| Outcome | Meaning |
|---|---|
| `permit` / `deny` | The chain admitted / rejected the prefix; a `deny` is explainable even though it never reached the RIB. |
| `withdrawn` | Was permitted, then withdrawn by the peer (tombstone; policy context dropped). |
| `evicted` | Was cached but pushed out by the per-peer cap — raise `cache_size`. |
| `stale` | A decision exists but the peer's import policy has changed since; the historical decision is shown with its original generation. |
| `not_seen` | The peer hasn't advertised this prefix on the current session (cache resets on flap / restart), or explain is disabled. |

A `permit` / `deny` result additionally carries a **statement trace** —
which statement inside the matched chain decided, per policy evaluated:

```
  permit
    policy:  edge-import
    ...
    statements:
      [0] policy edge-import statement 1 permit  match: prefix 192.0.2.0/24  set: local_pref 100 -> 200
```

One row per policy the chain consulted (a deny ends the trace at the
denying policy — later policies were never evaluated). `default-action`
rows mean no statement in that policy matched and its default decided.
Matched conditions lead with stable labels (`prefix`, `community`,
`as_path`, `neighbor_set`, `rpki`, `local_pref`, …; `any` for an
unconditional statement) and attribute edits render as
`before -> after` against the route's pre-policy values. The trace is
re-derived on demand from the cached compact pre-policy context, so it
attaches only to current-generation `permit` / `deny` results — a
`stale` decision's chain no longer exists and a `withdrawn` tombstone
has dropped the context the re-derivation needs. `--json` carries
the same trace as a `statements` array per match.

This is a side-effect-free read: it does not touch the RIB or move any
policy counter. The cache is **diagnostic session state**, not durable
history — it resets on peer flap and daemon restart.

Tuning (`[policy.explain]` in the config, diagnostic retention only —
never affects which routes are accepted):

- `enabled` (default `true`) — set `false` on hot full-table peers to
  skip the write-path cost entirely (the daemon then answers
  `not_seen`).
- `cache_size` (default `4096`) — a fabric / partial-table size. For
  reliable full-table explain, raise it toward the peer's
  expected retained-prefix count and budget the memory.

### Enable / disable a peer

```bash
rbgp neighbor 10.0.0.2 enable
rbgp neighbor 10.0.0.2 disable --reason "maintenance"
```

### Trigger an MRT dump

```bash
rbgp mrt-dump
```

### Live dashboard

```bash
rbgp top          # default 2s poll
rbgp top -i 5     # 5s poll interval
```

Shows sessions, prefix counts, message rates, RPKI VRP counts, and
streaming route events in a terminal UI. Press `h` for keybindings.

### Watch live events

```bash
rbgp events watch
rbgp events watch --backfill 50
rbgp events watch --prefix 203.0.113.0/24 --type added,best_changed
rbgp events watch --category session --type established,lost
rbgp events watch --category session --type notification_sent,notification_received
rbgp events watch --category policy --type policy_changed
# OTC route-leak decisions are published only through the durable
# outbox; the CLI automatically routes this filter through
# SubscribeFromEvent in live-only mode. Add `--from-event-id 0` to
# also replay any retained history.
rbgp events watch --category policy --type otc_route_blocked
rbgp events watch --category dataplane --type dataplane_status_changed
rbgp events watch --category dataplane --type dataplane_route_failed --prefix 203.0.113.0/24
rbgp events watch --prefix 203.0.113.0/24 --type policy_filtered
rbgp events watch --category evpn --type evpn_added,evpn_withdrawn,evpn_best_changed
rbgp events watch --category bfd --type bfd_up,bfd_down,bfd_state_changed
rbgp events sessions --address 10.0.0.2 --type established,lost --limit 20
rbgp events policy --address 10.0.0.2 --type policy_changed --limit 20
rbgp events evpn --route-type 2 --rd 65000:100 --limit 20
```

`events watch` tails the unified `EventService.WatchEvents` stream. The
live stream carries route add / withdraw / best-change /
export-policy-filtered events plus structured session lifecycle events
(`state_changed`, `established`, `lost`,
`peer_enabled`, `peer_disabled`), metadata-only BGP NOTIFICATION
sent/received events (`notification_sent`, `notification_received`), opt-in
policy mutation summaries (`policy_changed`), EVPN route best-path events
(`evpn_added`, `evpn_withdrawn`, `evpn_best_changed`), and dataplane status-row
summary changes for the FIB / BLACKHOLE discard reconcilers
(`dataplane_status_changed`) plus live per-route ADR-0061 FIB outcomes
(`dataplane_route_installed`, `dataplane_route_withdrawn`,
`dataplane_route_failed`), and BFD session events (`bfd_up`, `bfd_down`,
`bfd_state_changed`). Prefix and family filters match route events and
per-route FIB dataplane events; use `--category session` with peer and type
filters when watching session events, `--category policy` to watch policy /
neighbor-set / peer-group / chain mutations accepted by the runtime, or
`--category evpn` when watching EVPN route changes. Use `--category bfd` for
BFD up/down/state-change events. Dataplane summary events are peerless and do
not match `--address`, `--family`, or `--prefix`. FIB rejected counts reflect
surfaced status rows; sampled `route_limit_exceeded` rows are not a global
suppressed-route total. Policy-filtered route events are target-peer
scoped: `peer_address` remains the source route peer, `target_peer_address` is
the outbound peer whose export policy denied the route, and `--address` matches
either side for route history and live route filtering. Policy events describe
runtime apply success;
config-file persistence is separate. Session state-change events use a bounded
observability channel separate from the lossless TCP collision-coordination
path, so a saturated watch stream can miss lifecycle events without blocking
BGP collision handling. If the client falls behind a bounded route, session,
policy, EVPN, dataplane, or BFD source stream, `events watch` prints a
`stream_lagged` warning with the missed count; treat subsequent output as a
live tail after a gap. Use `--backfill N`
to print recent matching route history before the live tail starts. Backfill
is route-history only; session, policy, EVPN, dataplane, and BFD events are not
backfilled through the live stream command. Per-route FIB dataplane events are
live-only; use `rbgp rib fib` for the current route ownership snapshot
after a reconnect.
Backfilled route events use the same output shape as live route events, but
the command still prints a history block followed by the live tail rather than
merging the two by wall-clock timestamp.
For recent route history without a live tail, use
`rbgp events --prefix <PREFIX>`. For recent session lifecycle history,
use `rbgp events sessions`; it reads the peer manager's bounded
process-local history and resets on daemon restart. The CLI returns 100
history entries by default. The session-history API uses `limit = 0` as a
daemon-default sentinel, so `rbgp events sessions --limit 0` requests
the full bounded in-memory window rather than zero rows.
For recent runtime policy / neighbor-set / peer-group / chain mutation history,
use `rbgp events policy`; it reads a separate bounded 4096-event
process-local history from the peer manager. `--address` matches only
peer-scoped policy events, so global policy and peer-group changes disappear
from an address-filtered query. `rbgp events policy --limit 0` requests
the full bounded in-memory window.
For recent EVPN route history, use `rbgp events evpn`; it reads the RIB's
bounded 4096-event process-local EVPN route-event history. `--address` matches
both the current and previous best-path peer, `--route-type` accepts route types
1 through 5, and `--rd` uses the same Route Distinguisher display format as
`rbgp evpn`.

### Pick the right observability surface

Use the narrowest surface for the question you are asking:

| Question | Command / RPC | Notes |
|----------|---------------|-------|
| "What is changing right now?" | `rbgp events watch` / `EventService.WatchEvents` | Default live route + session stream. Policy, EVPN, dataplane, and BFD streams are opt-in with `--category` or matching `--type`. No replay after reconnect. |
| "What just changed for this prefix?" | `rbgp events --prefix 203.0.113.0/24` / `ListRouteEvents` | Exact-prefix route history from the bounded in-memory RIB ring. |
| "Why did this prefix not reach a peer?" | `rbgp events watch --address 10.0.0.2 --type policy_filtered --prefix 203.0.113.0/24` / `ListRouteEvents` | Export-policy denials where the peer is the denied outbound target. |
| "Did FIB apply fail for this prefix?" | `rbgp events watch --category dataplane --type dataplane_route_failed --prefix 203.0.113.0/24` / `EventService.WatchEvents` | Live ADR-0061 route apply outcome; replayable through `SubscribeFromEvent` when `[event_history].enabled = true`. |
| "What policy changed recently?" | `rbgp events policy` / `ListPolicyEvents` | Recent policy / neighbor-set / peer-group / chain mutation summaries from the bounded peer-manager ring. |
| "What EVPN route changed recently?" | `rbgp events evpn --route-type 2 --rd 65000:100` / `ListEvpnEvents` | Recent EVPN route add / withdraw / best-change history from the bounded RIB ring. |
| "Are BFD sessions up?" | `rbgp bfd`, `rbgp bfd show 10.0.0.2` / `BfdService.GetBfdSessions` | Snapshot of configured single-hop BFD sessions, strict flag, state, and diagnostic. |
| "Did BFD flap right now?" | `rbgp events watch --category bfd --type bfd_up,bfd_down,bfd_state_changed` / `EventService.WatchEvents` | Live BFD session events. No bounded BFD history API. |
| "What routes does the general FIB runtime own or reject?" | `rbgp rib fib` / `ListFibRoutes` | Snapshot of ADR-0061 configured-table route ownership. |
| "What BLACKHOLE discards are installed or rejected?" | `rbgp rib blackholes` / `ListBlackholeDiscards` | Snapshot of RFC 7999 discard programming. |
| "Are EVPN L2/L3 dataplane pieces ready?" | `rbgp evpn runtime`, `rbgp evpn instances`, `rbgp evpn nexthops`, `rbgp evpn vrfs` | Snapshot of the committed EVPN runtime generation, resolved EVPN config, and latest dataplane reports. |
| "Do I need alerting over time?" | Prometheus `/metrics` | Use counters/gauges for alerting; pair with CLI/RPC snapshots for row-level detail. |

Streams answer "what happened while I was connected." Snapshot RPCs answer
"what does the daemon currently believe or own." Bounded route, session,
policy, and EVPN history rings answer recent after-the-fact timeline questions.
Per-route/per-MAC dataplane histories remain roadmap items.

### Check health

```bash
rbgp health
```

### Check TCP-AO readiness

```bash
rbgp global
```

The `TCP-AO` row reports the local kernel capability probe for RFC 5925
TCP-AO support. `supported` means the daemon's internal socket primitive can
install keys on this host. `unsupported` / `probe_failed` means any configured
static-neighbor `tcp_ao` key will fail closed instead of falling back to
unauthenticated sessions: listener failures abort startup, while active-open
failures reject that connect attempt and retry later. TCP-AO key additions,
removals, and rotations are restart-required because Linux requires the keys to
exist when active-open or passive-listener sockets are created.

### View received routes from a peer

```bash
rbgp rib received 10.0.0.2
```

### View best routes (Loc-RIB)

```bash
rbgp rib
```

### View general FIB route status

```bash
rbgp rib fib
rbgp -j rib fib
rbgp rib fib --table edge --state rejected --reason route_limit_exceeded
rbgp rib fib --prefix 203.0.113.0/24 --peer 198.51.100.2
rbgp rib fib --page-size 100
```

This reports only the ADR-0061 configured-table runtime, not the ordinary
Loc-RIB. Rows are `installed`, `rejected`, or `failed`. The filters compose
with AND semantics. The `--prefix` filter is exact prefix+length matching, not
longest-prefix or containment matching. Use `--page-size` and the returned
next-page token to page through large surfaced status snapshots. Pagination is
over rows visible to `ListFibRoutes`; it does not add suppressed-route counts
for sampled `route_limit_exceeded` rows.

- `installed` / `owned`: rustbgpd owns the row and the kernel table matches
  the current best route.
- `rejected` / `foreign_route_exists`: a kernel row already exists at the
  same table / metric / prefix but is not owned by this daemon instance.
  This includes pre-existing `RTPROT_BGP` rows that are absent from
  `<runtime_state_dir>/fib-owned.json`, have a mismatched `[[fib_tables]]`
  declaration, or otherwise cannot be tied to persisted owned-state; rustbgpd
  preserves them rather than taking ownership by protocol alone.
- `rejected` / `owned_route_drifted`: rustbgpd had owned state for the row,
  but a live reconcile found that the kernel row no longer matched the recorded
  next-hop or `RTPROT_BGP` protocol. rustbgpd releases ownership and leaves the
  row in place; a later BGP withdraw will not delete the replacement.
- `rejected` / `next_hop_family_unsupported`: the configured table family and
  BGP next-hop family do not match.
- `rejected` / `peer_not_allowed`: the route's source peer did not match the
  table's `allowed_neighbors` or `allowed_peer_groups` guardrail.
- `rejected` / `route_limit_exceeded`: the table's eligible route count
  exceeded `max_routes`. The table freezes for that pass: existing owned
  rows stay installed, and growth or replacement is suppressed until the
  eligible count falls back under the cap. For very large over-cap tables,
  rejected rows are sampled so status output stays bounded.
- `failed` / `dump_failed:*`, `install_failed:*`, `replace_failed:*`, or
  `remove_failed:*`: the runtime hit a RIB or kernel boundary error. Check
  `bgp_fib_kernel_failures_total` and daemon logs for the matching action.

For direct kernel inspection, use the configured table and metric:

```bash
ip route show table 1000
ip -6 route show table 1000
```

On coordinated shutdown, the daemon drains only rows still matching its
owned next-hop. If a row drifted underneath the daemon, it is preserved and
ownership is dropped.

**Quick smoke check** — one-shot verification that the runtime is live and
programming the kernel (substitute the configured `table_id`):

```bash
rbgp rib fib                                  # per-route owned / rejected / failed state
ip route show table 1000                            # the configured table, straight from the kernel
curl -s localhost:9179/metrics | grep '^bgp_fib_'   # install / withdraw / reject / kernel-failure counters
```

### Manage FIB export tables at runtime (ADR-0061)

```bash
rbgp fib-table list
rbgp fib-table set edge --table-id 1000 --metric 200 \
    --families ipv4_unicast,ipv6_unicast --max-routes 50000
rbgp fib-table delete edge
```

`set` is create-or-replace by name and carries the full table definition (not
a patch); optional ECMP caps are `--maximum-paths`, `--maximum-paths-ebgp`,
and `--maximum-paths-ibgp`. Edits hot-apply through the running ADR-0061
reconciler and persist to the TOML config (atomic write) when the daemon was
started with `--config`. Changing `--table-id` / `--metric` for an existing
name is a table-key move: the old kernel rows withdraw and the new table
back-fills. The mutating verbs require the reconciler to be running (at least
one `[[fib_tables]]` entry at startup, on Linux); otherwise they fail
`FAILED_PRECONDITION` — add the first table to the config and restart. See
[CONFIGURATION.md](CONFIGURATION.md) for the full `[[fib_tables]]` lifecycle.

### Explain a best-path decision

```bash
# Global Loc-RIB view: best route + every losing candidate annotated with
# the decisive comparison reason and the compared values behind it
# (e.g. "local_pref 100 < 200"). The winner carries the step that beat
# the runner-up ("only_path" for a single-path prefix), and each loser
# is classified against the equal-cost multipath cut
# (eligible / relax_only / none). A prefix with no paths is NOT_FOUND.
rbgp rib --prefix 203.0.113.0/24 --explain

# Peer-scoped view: same shape, but every candidate the named peer would
# actually receive gets a non-zero `advertised_path_id` (rank within the
# peer's effective Add-Path send_max). Filtered candidates (export policy
# reject, family mismatch, split-horizon, iBGP / RFC 4456 RR suppression,
# beyond send_max) stay at 0 so the operator can see *why* each isn't
# advertised.
rbgp rib --prefix 203.0.113.0/24 --explain --explain-peer 10.0.0.2
```

### Explain an export decision ("why did/didn't route X go to peer Y?")

```bash
# The full export gate ladder for one prefix toward one peer, in the
# exact order the live export path evaluates it. Each rung reports
# pass / STOP / n/a with detail; a STOP names the gate that held the
# route back.
rbgp rib --prefix 203.0.113.0/24 advertised 10.0.0.2 --explain

# VPNv4/VPNv6 (SAFI 128): explain the (RD, prefix) identity instead --
# the ladder additionally includes the RFC 4684 RT-Constrain
# membership gate.
rbgp rib --prefix 10.1.0.0/24 advertised 10.0.0.2 --explain --rd 65000:1

# JSON for scripting
rbgp --json rib --prefix 203.0.113.0/24 advertised 10.0.0.2 --explain
```

The gate ladder, in live evaluation order (unicast single-best):
`best_route` (Loc-RIB best exists) -> `split_horizon` (not sent back to
its source) -> `rr_reflection` (iBGP split horizon / RFC 4456
client/cluster rules) -> `family` (peer negotiated the AFI/SAFI) ->
`llgr` (RFC 9494 stale-export restriction) -> `orf` (peer-pushed
RFC 5291 filter) -> `export_policy` (per-chain verdict, labeled
`policy:term` for `.rpol` members) -> `adj_rib_out` (diff against the
advertised state: `staged_announce` = would send, `already_advertised`
= identical route already advertised, peer in sync). The VPN ladder
follows the live VPN staging order and adds `rt_membership`
(RFC 4684). A family still held by the initial-ORF gate (RFC 5291
section 6) stops at `orf_gate` before any per-prefix work.

Truthfulness: the explanation is produced by a read-only dry run of
the *same staging body* live distribution executes -- including for
update-grouped peers, which are explained against their group table
with split horizon applied per member exactly like the emit-time
source-flip matrix. The response carries `update_group_id` when the
peer's export is group-staged. Explain queries never count toward
`bgp_policy_routes_total` or per-term policy hit counters.

An RFC 9107 ORR peer's explain ranks the per-vantage candidate set the
ORR export uses (with per-candidate cost output); an Add-Path-send
peer's explain covers the best path -- per-rank advertisement detail
lives in `rbgp rib --prefix X --explain --explain-peer`.

### Manage policies, peer groups, and neighbor sets

```bash
# Read
rbgp policy list
rbgp policy get import-from-transit
rbgp neighbor-set list
rbgp peer-group list

# Write — JSON file matches the proto message shape
rbgp policy set import-from-transit --from-file policy.json
rbgp neighbor-set set transit-peers --from-file ns.json
rbgp peer-group set transit --from-file pg.json

# Apply chains globally or per-neighbor
rbgp policy chain set-import import-from-transit
rbgp policy chain set-import import-from-transit --neighbor 10.0.0.2
rbgp policy chain show --neighbor 10.0.0.2

# Bind / unbind neighbors to a peer-group
rbgp peer-group attach 10.0.0.5 --group transit
rbgp peer-group detach 10.0.0.5
```

`--from-file` accepts JSON whose shape mirrors the proto message
(`PolicyDefinition` / `NeighborSetDefinition` / `PeerGroupDefinition`);
unknown fields are rejected at parse time. Empty
`chain set-{import,export}` is rejected — use the matching `clear-*`
subcommand to drop a chain.

### Graceful shutdown (daemon exit)

```bash
rbgp shutdown
```

Sends NOTIFICATION to all peers, writes GR marker, exits cleanly.

### RFC 8326 graceful-shutdown community (planned maintenance)

Distinct from the daemon-shutdown RPC above. RFC 8326 lets you drain
traffic ahead of a planned EBGP session shutdown by tagging outbound
paths with the well-known `GRACEFUL_SHUTDOWN` community
(`65535:0` / `0xFFFF_0000`); receivers that honor the community
demote `LOCAL_PREF` to `0` so any non-shutting alternate becomes
preferred. By the time you actually close the session, traffic has
already moved.

**Initiator (the side going down for maintenance):**

```bash
# Start the drain on one peer
rbgp gshut --peer 10.0.0.2

# Or drain every currently-managed peer at once
rbgp gshut

# Wait for traffic to shift (operator-defined, typically 30s-5min
# depending on convergence in the upstream AS), then proceed with
# the actual maintenance — restart, config edit, etc.

# Clear the community when maintenance ends
rbgp gshut --peer 10.0.0.2 --clear
rbgp gshut --clear
```

The toggle is **operator-runtime state**, not config — it lives on
the `ManagedPeer` desired-state record, mirrors to the live session,
and survives session flaps mid-maintenance. The toggle does NOT
persist across daemon restart by design (RFC 8326 is a maintenance-
window action, not a steady state).

When the toggle flips, rustbgpd issues a `RibUpdate::RefreshPeerOutbound`
which forces re-emission of all routes already in `AdjRibOut` to the
target peer. The community appears on the wire immediately (no need
to wait for an unrelated RIB event).

**Receiver (the side honoring others' GShut):**

Set in `[global]`:

```toml
[global]
honor_graceful_shutdown = true
```

When enabled, an implicit chain-tail rule fires on every EBGP peer's
import chain — see `docs/CONFIGURATION.md` for the exact semantics.
iBGP peers are exempt because `LOCAL_PREF` is preserved within an AS.

**Verifying the drain is working:**

The community is attached on the wire by the per-peer transport layer
**after** the RIB-side advertised view is computed, so
`rbgp rib advertised` does NOT show the GShut community on the
initiator side — the RIB doesn't know about the toggle. The
authoritative checks are:

```bash
# Receiver-side: routes from a draining peer that honor the community
# show explicit local_pref_attr = 0 in the RIB (proves the implicit
# chain-tail rule fired). EBGP-received routes have no LOCAL_PREF on
# the wire, so look at local_pref_attr (explicit) rather than
# local_pref (proto3 default).
rbgp rib --neighbor <draining-peer> \
    | jq '.routes[] | {prefix, localPrefAttr, communities}'

# Initiator-side: confirm the toggle is set on the live session via
# the daemon log (look for "RFC 8326 graceful-shutdown advertise
# toggled" in journalctl / Docker logs).
journalctl -u rustbgpd | grep "graceful-shutdown advertise toggled"

# Or verify on the *receiving* peer's BGP table — the canonical
# observation. On FRR:
vtysh -c 'show ip bgp <prefix> json' \
    | jq '.paths[].community'

# (In a maintenance scenario you usually have control of both ends, so
# the receiver-side check is what matters for correctness.)
```

Interop is validated in M35 (`tests/interop/m35-graceful-shutdown-frr.clab.yml`)
against FRR 10.3.1 — both legs (FRR → rustbgpd inbound honor +
rustbgpd → FRR outbound advertise + clear) end-to-end.

### Explain best-path selection

```bash
rbgp rib --prefix 10.0.0.0/24 --explain
```

Shows all candidates for a prefix with the decisive comparison reason
for each non-winner (e.g., `higher_local_pref`, `shorter_as_path`)
plus the compared values behind it (e.g., `local_pref 100 < 200`),
the step that selected the winner over the runner-up, and whether each
loser would survive the equal-cost multipath cut.

### Looking glass (birdwatcher-compatible REST API)

Optional HTTP server for external looking glass frontends (Alice-LG, etc.).
Configure in TOML:

```toml
[global.telemetry.looking_glass]
addr = "0.0.0.0:8080"
```

Endpoints: `/status`, `/protocols/bgp`, `/routes/protocol/{id}`,
`/routes/peer/{peer}`. Omit the section entirely to disable.

### EVPN Route Reflector + Bidirectional VTEP

rustbgpd has two operational EVPN modes that share the same `l2vpn_evpn`
session machinery:

- **RR mode (Phase 1):** empty `[[evpn_instances]]`. The daemon
  reflects RFC 7432 routes between iBGP-speaking VTEPs, owns no
  kernel state, and runs no DF election. External VTEPs (FRR on
  SONiC, commercial NOS) handle local origination + forwarding.
- **Bidirectional VTEP mode (Phase 2 — Gates 7a / 7b / 7b+1):**
  populated `[[evpn_instances]]`. The daemon **programs the kernel
  bridge FDB** from received Type 2 routes (downward, ADR-0054) AND
  **originates Type 2 from kernel-learned local MACs plus one Type 3
  IMET per configured L2VNI** (upward, ADR-0055). Linux-only. Gate
  7b+1 ships in v0.15.0.

> **Phase-2 status:** Gates 7a/7b/7b+1/7b+2/7c have shipped the
> bidirectional L2VNI VTEP loop: declarative instances, downward FDB
> reconciliation, local MAC and MAC+IP origination, Type 3 IMET,
> SVI MAC origination, sticky MAC config, and sub-second mobility
> wakeups. Gate 8/8b adds alpha multi-homing execution: DF election,
> Type 1/4 origination, production-default BUM suppression with opt-out
> config, ESI-aware Type 2 origination, aliasing projection, and
> receive-side mass-withdraw filtering. **Gate 9** ships symmetric Interface-less IRB
> end-to-end in v0.18.0 (RFC 9136 §4.4.2 / ADR-0058):
> `[[evpn_ip_vrfs]]` config schema + `[[evpn_instances]].ip_vrf`
> binding, `IpVrfStatus` readiness probe, Linux VRF / L3VXLAN
> netlink dumps, per-IP-VRF kernel-route observation with
> conservative classifier, Type 5 origination via
> `RibUpdate::InjectEvpn` gated on readiness, remote import + L3
> FIB programming through a transactional `L3OwnedState` model,
> `RTNLGRP_IPV4/IPV6_ROUTE` multicast for sub-second withdraw,
> `ListIpVrfs`/`GetIpVrf` gRPC + `rbgp evpn vrfs` CLI,
> M39 hosted kernel-dataplane CI. **ADR-0059** (v0.19.0)
> adds receive-path aliasing-ECMP via FDB nexthop groups
> (slices 1-4, M40 FRR-validated); **slice 3.5 hardening**
> (PRs #91 / #92 / #93) added the `apply_aliasing_ecmp`
> per-instance off-switch, periodic `RTM_GETNEXTHOP` drift
> recovery, and homogeneous IPv6 alias members. Production-default
> multi-homing enforcement, auto-derived RTs, partial ADR-0063 live
> EVPN runtime mutation, receive-side RFC 9135 overlay-index recursion,
> native GW-IP + ESI overlay-index Type 5 origination, single-active
> and all-active ESI overlay-index Type 5 receive, and controller Gateway
> Address Type 5 injection have since shipped.
> Still ahead: remaining ADR-0063 shapes, Linux softswitch local-bias
> split-horizon, true shared-VNI / non-zero Ethernet Tag service, managed
> netdev ergonomics, service-provider EVPN breadth, and deeper cross-vendor/scale
> validation. See
> [`evpn-enablement.md`](evpn-enablement.md) for the gate ladder,
> [`evpn-alpha-soak.md`](evpn-alpha-soak.md) for the residual
> alpha-confidence checklist, and
> [`evpn-vtep-troubleshooting.md`](evpn-vtep-troubleshooting.md) for
> the operator runbook.

#### Per-neighbor knob

```toml
[[neighbors]]
address = "10.0.1.1"
remote_asn = 65000
families = ["l2vpn_evpn"]
route_reflector_client = true
```

Set `route_reflector_client = true` on every VTEP peer; the daemon's
own `cluster_id` (under `[global]`) drives the RFC 4456 ORIGINATOR_ID
+ CLUSTER_LIST stamping.

#### Inspect the EVPN RIB

```bash
rbgp evpn                             # all EVPN routes
rbgp evpn --route-type 2              # MAC/IP only
rbgp evpn --rd 65000:100              # filter by RD
rbgp evpn --peer 10.0.1.1             # filter by source peer
rbgp evpn diagnose                    # alpha VTEP summary
rbgp evpn runtime                     # committed EVPN generation / mutation state
rbgp evpn clear-duplicate-mac --vni 100 --mac aa:bb:cc:dd:ee:ff
```

`tunnel_type=8` in the output indicates the RFC 8365 VXLAN
encapsulation extended community is present.

#### Inspect the dataplane (ADR-0059 FDB nexthop groups)

```bash
rbgp evpn nexthops                    # owned FDB-NHG groups / members / MAC refs
rbgp evpn nexthops --json             # JSON for scripting
```

This is the rustbgpd-owned view of ADR-0059 aliasing-ECMP state —
distinct from the RIB above. Compare its `group-id`, member
`nh_id`s, and `mac-refs` against `ip nexthop show` / `bridge fdb
show` when debugging multi-homed Type 2 forwarding. The top-line
header reports `orphan-nexthops`, `pending-deletes`, and
`drift-recovery-disabled` so the periodic drift-recovery latch and
allocator GC backlog are visible without log scraping.

#### Inject a route from a controller

```bash
rbgp evpn add-mac-ip --rd 65000:100 \
  --mac 02:00:00:aa:bb:cc --ip 10.0.0.5 \
  --label 100 --next-hop 10.0.0.2 \
  --rt 65000:100

rbgp evpn delete-mac-ip --rd 65000:100 \
  --mac 02:00:00:aa:bb:cc --ip 10.0.0.5

rbgp evpn add-ip-prefix --rd 65000:5000 \
  --prefix 10.50.0.0/24 --label 5000 \
  --next-hop 192.0.2.10 --router-mac 02:00:00:00:50:00 \
  --rt 65000:5000

rbgp evpn delete-ip-prefix --rd 65000:5000 \
  --prefix 10.50.0.0/24
```

Two complementary origination paths exist:

1. **gRPC injection (Phase 1, Gate 6):** `InjectionService.AddEvpnRoute` /
   `DeleteEvpnRoute` (the `rbgp evpn add-mac-ip / add-imet /
   add-ip-prefix / delete-*` commands above). The controller decides
   what to originate; rustbgpd reflects + distributes. Type 2
   (MAC/IP), Type 3 (IMET), and Type 5 (IP Prefix) are exposed.
   Type 5 injection uses ESI=0 and Ethernet Tag ID=0. Omitting
   `--gateway` keeps the Interface-less Gateway IP=0 form; supplying
   `--gateway` injects a non-zero overlay-index Gateway Address.
   `--router-mac` is required for the default VXLAN encapsulation path
   and should be omitted when `--no-vxlan-encap` is set. Non-zero ESI
   overlay-index injection and Type 1/4 multi-homing route injection
   are not exposed. Native Type 1/4 origination is driven by
   `[[ethernet_segments]]`.
2. **Kernel-driven origination (Phase 2, Gate 7b+1):** with
   `[[evpn_instances]]` populated, the daemon subscribes to
   `RTNLGRP_NEIGH` (enum group id 3) and emits Type 2 routes for
   MACs the kernel learns on non-VXLAN bridge ports, plus one
   Type 3 IMET per L2VNI at startup. RFC 7432 §15.1 mobility
   sequencing is automatic. Withdraws fire on FDB age-out / `bridge
   fdb del` and on coordinated shutdown.

#### Common operational signals

- **EVPN routes counted toward `max_prefixes`.** A peer flooding EVPN
  Type 2 routes will trip the same Cease/MAX_PREFIXES that a peer
  flooding unicast prefixes would. The cap is the union of unicast
  unique prefixes + FlowSpec rules + EVPN keys.
- **GR / LLGR works for EVPN.** When a VTEP restarts, its reflected
  EVPN routes are marked stale and ranked below fresh alternatives
  (RFC 4724 §4.2 / RFC 9494 §4.7) — no fabric-wide flap.
- **Late-joining peer.** A VTEP that connects to a converged RR
  receives the existing EVPN routes in its initial dump before the
  EoR marker. (This was not always the case — see commit history for
  the regression test.)
- **MAC mobility correctness.** A MAC that moves between VTEPs
  produces a strictly-increasing MAC Mobility sequence number; the
  RR forwards the highest-sequence advertisement and downstream
  VTEPs flip their best path accordingly. Sticky MACs (RFC 7432
  §7.7) are not displaced by non-sticky ones.

For the full enablement story, gate ladder, and known limitations,
see [docs/evpn-enablement.md](evpn-enablement.md). For a step-by-step
operator checklist, see
[docs/evpn-vtep-troubleshooting.md](evpn-vtep-troubleshooting.md).

#### Troubleshooting kernel-driven origination (Gate 7b+1)

- **Local MAC learned in kernel, but Type 2 not on the wire.** Check
  in order: (a) `[[evpn_instances]]` is populated and the bridge
  named there exists with a single VXLAN port (probe reports
  `Ready` only when ADR-0054 §4's five-point check passes); (b) the
  MAC was learned on a **non-VXLAN** bridge port — the classifier
  intentionally drops VXLAN-port ifindexes (those are remote-MAC
  echoes); (c) `RUST_LOG=rustbgpd_evpn_linux=debug` shows the
  classifier hit (cache miss → `bridge_port_to_vni` doesn't yet
  contain the slave ifindex; the supervisor's periodic dump should
  populate it within 5 s); (d) the BGP session reached Established
  before the originator emitted the Inject — pre-Established
  Injects do reach the AdjRibOut and ride the initial dump after the
  session reaches Established.
- **Type 3 IMET not visible on a peer.** IMET is emitted at startup
  for every configured `EvpnInstance` regardless of dataplane
  Ready/NotReady. If FRR's `show bgp l2vpn evpn route type
  multicast` doesn't show it, check that the peer reached
  Established and that the L2VPN/EVPN family was negotiated
  (`families = ["l2vpn_evpn"]`).
- **Type 2 / Type 3 not withdrawn cleanly on shutdown.** The
  shutdown order is: (1) drain originator's outstanding Withdraws;
  (2) withdraw IMET keys; (3) `PeerManagerCommand::Shutdown`. If
  peers see stale routes after a clean exit, check the structured
  log for the `draining EVPN originator` / `withdrawing EVPN Type 3
  IMET routes` lines firing **before** any peer-session-shutdown
  log lines.
- **`could not subscribe to RTNLGRP_NEIGH; local-MAC observations
  will be silent`** in the startup log. The daemon lacks
  `CAP_NET_ADMIN`. Downward FDB programming also needs the
  capability; if the dataplane reconciler is working but the
  originator is silent, the cap is partially granted (rare). Check
  `getcap` on the binary.
