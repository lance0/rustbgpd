# Operations Guide

Practical reference for running rustbgpd in production. For config syntax,
see [CONFIGURATION.md](CONFIGURATION.md). For security posture, see
[SECURITY.md](SECURITY.md). For the end-to-end install + lifecycle
walkthrough (systemd setup, Docker, containerlab quick-start, sample
profiles), see [deployment.md](deployment.md).

Man pages for both binaries ship in the release tarball under
`share/man/` and can be regenerated any time with `rbgp man` and
`rustbgpd --man` (roff on stdout; view with `rbgp man | man -l -`).

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
# What is the daemon actually running? Dump the effective config with
# defaults materialized (hold_time, send_hold_time, GR timers, families)
# and secrets redacted:
rbgp config effective
rbgp -j config effective

rbgp config diff /tmp/new-config.toml
rbgp --json config diff /tmp/new-config.toml

rbgp config plan /tmp/new-config.toml
rbgp --json config plan /tmp/new-config.toml

rbgp config apply /tmp/new-config.toml \
  --expected-runtime-snapshot-token kv1:...
```

For a safe deploy that should roll back unless explicitly confirmed, provide a
confirm handle and timeout on the same apply. The daemon applies the candidate
immediately, starts the timer, and rolls back when the timer expires unless the
same handle is confirmed:

```bash
rbgp config apply /tmp/new-config.toml \
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
snapshot was re-applied), or one of the two rollback-failure states,
`auto_revert_failed` / `abort_failed` — these mean the daemon could not
re-apply the pre-commit snapshot. The transaction then stays pending and the
mutation fence stays closed (the revert journal is retained, so a mutation
accepted on top of the inconsistency would be clobbered by a boot revert);
resolve it by retrying the abort, confirming the candidate, or restarting the
daemon to boot-revert. A confirmed apply that itself fails without proof of a
terminal outcome (lost persistence acknowledgement, post-persist finalization
failure, or compound rollback failure) likewise retains the journal and blocks
all config mutations until a restart boot-reverts.

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

### The transactional quartet: check, compare, commit confirmed, rollback

For operators coming from Junos, the four verbs map directly:

| Junos | rustbgpd |
|-------|----------|
| `commit check` | `rbgp config plan` (or `rustbgpd --check` offline) |
| `show \| compare` | `rbgp config diff` (with reload-impact annotations) |
| `commit confirmed` | `rbgp config apply --confirm-id ... --confirm-timeout ...` |
| `rollback N` | `rbgp config rollback N` |

The daemon retains a bounded on-disk history of applied configs (the last 20
distinct documents, content-hash-deduplicated, timestamped) under
`<runtime_state_dir>/config-history/`. Transaction applies, gRPC
neighbor/FIB/policy CRUD, successful SIGHUP reloads, and the config running at
daemon startup all record an entry, so the history survives restarts and "put
back what was running yesterday" is one command:

```bash
# What has been applied? Newest first; index 0 is the running config.
rbgp config history
rbgp -j config history

# Restore the previous applied config (Junos `rollback 1`)
rbgp config rollback 1

# A cautious rollback: auto-reverts the rollback itself unless confirmed
rbgp config rollback 1 --confirm-id undo-1 --confirm-timeout 120
rbgp config confirm undo-1
```

`config history` lists index, timestamp, content hash, and a one-line summary
per entry — never config document contents. `config rollback N` resolves
entry N server-side, verifies that its bytes match the SHA-256 in its file
name, and routes it through the **same transaction path as
`config apply`**: the same plan classification, the same reload-impact and
update-group annotations, the same receipts, and the same
`--confirm-id`/`--confirm-timeout` confirmed-commit window (journal, timeout
auto-revert, and boot revert included). There is no second apply engine —
a rollback whose entry contains sections the transaction executor cannot
commit live (for example restart-required `[global]` fields) is rejected
without mutation, exactly like an apply of that file would be. Rolling back
past the retained history fails cleanly, naming how many entries exist.

History and rollback require the daemon to have been started with `--config`
(no persisted config means nothing to retain). SIGHUP reloads adopt the
operator's edited file without recording it — the history tracks what the
daemon itself persisted; your config file under version control remains the
authority for hand-edited changes.

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
  `[rpki]`, `[bmp]`, `[mrt]`, unsupported EVPN shapes, and
  `apply_bum_enforcement`. Supported EVPN edits are shape-aware and appear
  under Reload-applied.
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
`[mrt]`, and `apply_bum_enforcement`. EVPN table edits are
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
| Optional shutdown warm checkpoint | `<runtime_state_dir>/warm-bundle-v1/` | On coordinated shutdown when `warm_cache_checkpoint_on_shutdown = true`; owner-private post-import-policy Adj-RIB-In snapshot and manifest, never restored on boot |
| General FIB owned-state | `<runtime_state_dir>/fib-owned.json` | After successful ADR-0061 FIB apply/drain |
| MRT dump files | `[mrt] output_dir` | On periodic timer or `TriggerMrtDump` |
| gRPC UDS socket | `<runtime_state_dir>/grpc.sock` | Daemon lifetime |

The GR marker format is versioned. V1 is generationless and wall-clock-only;
v2 adds a required checkpoint generation; v3 adds a complete Linux boot and
time-namespace identity plus an absolute `CLOCK_BOOTTIME` deadline, with an
optional checkpoint generation. Full v3 protection requires Linux 5.6+ built
with `CONFIG_TIME_NS`, a readable valid
`/proc/sys/kernel/random/boot_id`, inspectable `/proc/self/ns/time`
device/inode, readable valid `/proc/self/timens_offsets`, and a sampleable
`CLOCK_BOOTTIME` value, with the overall marker identity and deadline fitting
their serialized representations. A missing or access-restricted procfs input
cannot establish clock-domain continuity; it selects the fallback rather than
proving that no time namespace exists.

Startup trusts the v3 boottime deadline only when the live boot ID, current
time-namespace device/inode, and both boottime-offset components match exactly.
Only that exact-domain path protects the shutdown-to-startup interval from
discontinuous `CLOCK_REALTIME` steps. Otherwise the daemon uses the marker's
wall deadline, bounded by the current maximum configured restart time. A
forward wall-clock step can therefore shorten or expire that wall fallback,
including the v1/v2 publication fallback. Publication logs a warning when
clock-domain sampling, checked arithmetic, or TOML's signed integer range
forces a complete v1/v2 fallback; partial v3 markers are never published.

Each concurrently running daemon requires its own `runtime_state_dir`.
Sharing the directory across live daemon processes is unsupported: its restart
marker, optional warm bundle, FIB ownership receipt, and Unix socket all assume
one writer. At startup, an enabled warm checkpoint runs a bounded cleanup of
canonical orphan snapshots and interrupted-write temporary files. A valid
byte-stable manifest protects its selected snapshot; an absent manifest allows
orphan cleanup; and an invalid or changed manifest deletes nothing. Cleanup
errors are warnings and do not disable the next coordinated-shutdown
publication attempt.

**Not restored:** routing state, policy evaluation state, RPKI VRP tables, and
BMP client state. The optional warm checkpoint persists only eligible
post-import-policy Adj-RIB-In views as a future-use artifact; the daemon does
not load, select, install, or advertise any route from it. Loc-RIB and
Adj-RIB-Out are never checkpointed. The ADR-0061 FIB file is only an ownership
receipt for rows rustbgpd already installed; all route selection state is
rebuilt from peers after restart.

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

In a matching domain, marker v3 makes the shutdown-to-startup deadline
resistant to discontinuous `CLOCK_REALTIME` steps and includes suspend time
before the new process resolves it. The daemon then uses its normal
process-local monotonic timer for the remaining live window; it does not claim
suspend-inclusive timing after startup.

Rolling back to a binary that predates marker v3 is a cold-start compatibility
event: that binary rejects the v3 marker and starts without restarting-speaker
mode. This does not guarantee a traffic blackhole; impact depends on peer and
topology behavior. Operators requiring continuity should still use the drained
route-server-pair procedure below.

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
`rbgp doctor` probes every configured cache
(`rpki.cache.<addr>.reachable`) and goes red on an unreachable one.

### BMP collector unreachable

Each BMP client reconnects independently with backoff (default
`reconnect_interval` = 30s). During disconnection, BMP events for that
collector are dropped. No routing state is affected — BMP is purely
observational. On reconnect, the client sends a fresh Initiation message;
the collector rebuilds state from subsequent Peer Up and Route Monitoring
messages.

### gNMI dial-out collector unreachable

Each `[gnmi_dialout]` target dials its collector independently and
reconnects with capped exponential backoff (`backoff_initial`, doubling to
`backoff_max`). A collector that is down — at startup or later — never
affects BGP operation; telemetry for that target is simply not delivered
while disconnected. The daemon logs one `warn` when a target becomes
unreachable and one `info` when it (re)connects; repeated retries log at
`debug` only. Watch `gnmi_dialout_connected{target}` (0/1) for the live
connection state. Every (re)connection restarts the subscription, so the
collector resyncs from a fresh initial snapshot + `sync_response` — the
disconnect window is not replayed (same contract as a dial-in Subscribe
reconnect; use the durable event cursor for gap-free history).

### MRT dump failure

If the output directory is not writable, the MRT manager logs an error and
skips that dump cycle. Periodic dumps continue on the next interval. The
daemon does not crash on MRT failures.

### Peer max-prefix exceeded

When a peer sends more prefixes than `max_prefixes`, the daemon sends a
NOTIFICATION and tears down the session. Without negotiated Notification GR
this is Cease/1 (Maximum Number of Prefixes Reached). With the RFC 8538 N-bit,
the daemon sends outer Cease/9 (Hard Reset) whose data encapsulates the same
Cease/1 reason and RFC 4486 data, preventing the over-limit routes from being
retained as stale. The peer is not automatically re-enabled — use
`rbgp neighbor <addr> enable` or the gRPC `EnableNeighbor` RPC to
restart it.

---

## Key metrics to watch

Metrics and HTTP probes are exposed on the Prometheus endpoint if
`prometheus_addr` is configured. If omitted, metrics are still collected
internally and available via gRPC `GetMetrics` and `GetHealth` RPCs, but the
HTTP `/livez` and `/readyz` probes are disabled.

Metric names are split by prefix on purpose: `bgp_*` covers the BGP core
(sessions, RIB, policy, RPKI/ASPA, GR, event stream/outbox, FIB) and
`evpn_*` covers the EVPN/VTEP dataplane surface — the two subsystems have
different cardinality profiles and are typically dashboarded and alerted
separately. `bfd_*` names the BFD liveness metrics. A ready-to-load
Prometheus alert-rule pack covering the high-signal `bgp_*` metrics ships
at [`examples/prometheus/rustbgpd-alerts.yml`](../examples/prometheus/rustbgpd-alerts.yml).

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
| `bgp_rib_attr_intern_global_size` | Unique attribute sets in the daemon-wide cross-peer intern table (attribute-memory dedup across ALL peers). Tracks reclaim sweeps and growth under churn; a monotonic slope under steady-state churn indicates an intern leak. Replaces the per-peer `bgp_rib_attr_intern_size{peer}` gauge |
| `bgp_messages_received_total` | Inbound BGP messages by type |
| `bgp_messages_sent_total` | Outbound BGP messages by type |
| `bgp_peer_outbound_queue_depth{peer}` | Coalesced update frames buffered for a peer's outbound writer — the "which clients are behind" signal during convergence. Sampled at batch granularity (once per enqueue batch and once per writer drain pass, never per message). A value pinned near the writer's bulk-buffer capacity marks a slow or stuck client that is not draining our output; a healthy peer's depth returns to 0 after each burst. At large route-reflector fanout, sort peers by this gauge to find the laggard holding up convergence. Series reaped on session teardown |
| `bgp_peer_update_group{peer}` | Which update group a peer currently belongs to — the "which group is this client in" lookup that `bgp_update_group_members{group}` (member counts) cannot answer. The value is the stable numeric group id (matches the `group` label of `bgp_update_group_members`); the sentinel `-1` marks a peer on the per-peer/ungrouped fallback path (a v1 disqualifier — peer-context policy, Add-Path send, ORR vantage, negotiated ORF, or slow-peer isolation). Refreshed on every membership change; series reaped on session teardown |
| `bgp_peer_slow{peer}` | 1 while the peer is flagged slow: Established and alive (keepalives flowing, so the RFC 9687 send-hold teardown never fires) but persistently not draining its outbound queue — backlog at or above `slow_peer_threshold_pct` of the writer buffer for `slow_peer_duration` seconds. See "Slow peers" below for interpretation and actions. Refreshed on both transitions and on session teardown; series reaped on peer delete |
| `bgp_route_refresh_in_progress{peer,afi_safi}` | Active inbound Enhanced Route Refresh window for a peer/family (1 = active, 0 = inactive) |
| `bgp_route_refresh_stale_entries{peer,afi_safi}` | Routes still awaiting replacement before EoRR or timeout during an inbound Enhanced Route Refresh window |
| `bgp_rib_outbound_registered_peers` | Peers currently registered for outbound route distribution. An Established session whose peer is missing here has a wedged advertisement path: keepalives still flow but no UPDATE can reach the peer until a new session re-registers |
| `bgp_rib_outbound_registration_replaced_total{peer}` | `PeerUp` re-registrations that replaced a still-registered outbound sender for the same address — two sessions overlapped (collision window); the replacement resets the prior session's RIB state and keeps the superseded session live for failover; its `PeerDown` is matched by session identity |
| `bgp_rib_stale_peer_down_ignored_total{peer}` | `PeerDown`/`PeerGracefulRestart` events discarded because their session id didn't match the registered session — a stale teardown from a superseded collision-loser session; the surviving session's state is untouched |
| `bgp_rib_stale_session_message_ignored_total{peer,kind}` | Session-scoped RIB messages discarded by the same session-identity rule — a superseded session's queued message processed after the replacement's `PeerUp`. `kind` is `routes` (`RoutesReceived`), `eor` (End-of-RIB), `refresh` (route-refresh request / RFC 7313 BoRR/EoRR), `orf` (RFC 5291 ORF push), or `policy_context` (peer-group policy identity). The registered session's state is untouched |
| `bgp_rib_outbound_registration_failover_total{peer}` | Outbound registrations handed to another live session for the same address after the active session's `PeerDown`/GR-down (the symmetric collision interleaving: the loser's `PeerUp` replaced the winner's registration before the loser went down). The exact nonzero, unambiguous survivor enters `awaiting_refresh`, is re-registered, receives the staged initial table without EoR, and is asked for an inbound ROUTE-REFRESH; matching post-failback BoRR/EoRR completes convergence |
| `bgp_rib_dirty_resync_total{outcome}` | Dirty-peer resync timer fires, by `cleared` / `still_dirty` |
| `bgp_rib_ingest_channel_depth` | RIB manager ingest queue depth, sampled once per manager loop iteration; pegged at capacity means producers are parked on backpressure |
| `bgp_rib_policy_transition_in_progress` | Whether the RIB actor owns an atomic export-policy transition (`1` = in progress). General RIB queries and mutations remain fenced while the dedicated core-readiness lane remains responsive |
| `bgp_rib_policy_transition_last_duration_milliseconds` | Monotonic elapsed duration of the most recently completed atomic export-policy transition; retained across idle periods for post-event diagnosis |
| `bgp_rib_policy_transition_actor_poll_duration_seconds{poll_kind}` | Duration of each real RIB actor transition poll. Bounded `poll_kind` values are `bounded` (chunked phase work), `prefix_snapshot` (the two complete O(table) snapshot polls), `finalize` (atomic membership/emission commit plus the global dirty/forced retry opportunity), and `commit` (bounded `CommitMembers` batches — at most eight members flushed per poll) |
| `bgp_orr_input_objects{classification}` | Inputs considered by the ORR default-topology builder before NLRI deduplication. Exactly five classifications exist: `included_default`, `excluded_nondefault`, `malformed_topology`, `malformed_attribute_29`, and `default_with_ignored_flex_algo`. The Flex series is a subset of included default objects: its base object and classic metric remain usable. All series reset to zero when no vantage is configured |

The shipped alert pack raises `BgpPolicyTransitionStalled` when
`bgp_rib_policy_transition_in_progress == 1` for one minute. Independently,
readiness remains healthy during bounded progress below 30 seconds, then fails
closed with `RIB export-policy transition stalled` until commit or a cleaned-up
fallback restores it. Use the poll-duration histogram to distinguish many
bounded polls from one long O(table) snapshot or finalization poll; the
retained terminal duration still describes the previous completed transition
while one is active.
A readiness request that arrives after general queries have queued can overtake
them on its dedicated lane. It cannot preempt an O(table) general query that
was already executing when the request arrived; that actor call must return
before either the transition or readiness probe can advance.

### Policy artifact freshness

For deployments whose policy is rendered by an external pipeline
(IRR toolchain, config generator, cron + SIGHUP), these metrics answer
"when did the daemon last *accept* new policy artifacts" — which is the
staleness signal that matters. File mtimes only say when something was
written to disk; a render that produces a config the daemon rejects
leaves the old generation live, and these timestamps deliberately do
not advance on a rejected load.

| Metric | What it tells you |
|--------|-------------------|
| `bgp_policy_generation_loaded_timestamp_seconds` | Unix time of the last successful full policy apply — initial load, SIGHUP reload (stamped even when the reloaded content is unchanged: the daemon re-accepted it), or config transaction. Frozen across rejected reloads |
| `bgp_policy_dataset_loaded_timestamp_seconds{dataset}` | Unix time the named `[policy.datasets.<name>]` external dataset last swapped in a loaded generation (initial load, or a refresh whose content changed). A failed refresh keeps the prior snapshot serving and does not advance this. Series reaped when the dataset is removed from config |
| `bgp_policy_dataset_refresh_errors_total{dataset}` | Failed dataset refresh attempts; the prior snapshot keeps serving. Series reaped when the dataset is removed from config |

**Alerting on pipeline staleness.** Export ages, not the raw
timestamps, and let Prometheus do the arithmetic. If your pipeline
refreshes every 6 hours, page when nothing has been accepted for a few
missed cycles:

```promql
# Full policy apply older than 3 refresh intervals (here: 3 × 6h).
time() - bgp_policy_generation_loaded_timestamp_seconds > 3 * 21600

# A dataset whose last accepted swap is stale, or whose refreshes are
# actively failing.
time() - bgp_policy_dataset_loaded_timestamp_seconds > 3 * 21600
increase(bgp_policy_dataset_refresh_errors_total[6h]) > 0
```

The dataset timestamp advances only when a refresh swaps in *changed*
content, so pair the dataset-age expression with the refresh-error
counter: age alone can also mean "the data legitimately hasn't
changed", while age plus rising errors means the pipeline output is
being rejected. The full-apply timestamp has no such caveat — it is
stamped on every successful SIGHUP — so it is the primary "pipeline
stuck or daemon rejecting everything" pager.

### Ingress rejection / route-leak detection

Mechanisms that block routes for protocol-correctness reasons: most
reject at the session boundary before the route reaches the RIB. Egress OTC
and exact-export checks instead reject an outbound advertisement after policy
but before Adj-RIB-Out commit. If a previously advertised route becomes
blocked, the RIB withdraws it and removes the logical advertised entry. Where a metric
carries a `reason` label, its values are the canonical contract
pinned in `crates/telemetry/src/reason_labels.rs` — stable across
releases and shared verbatim by the metric label, the log-line
`reason` token, and (for OTC) the structured `OTC_ROUTE_BLOCKED`
event payload, so alert expressions can key on them safely. Metrics
without a `reason` label encode the mechanism in the metric name.

| Metric | What it tells you |
|--------|-------------------|
| `bgp_otc_routes_blocked_total{peer,reason}` | RFC 9234 Only-to-Customer route-leak blocks (ADR-0071). `reason` is `ingress_from_customer_rsclient` (OTC-tagged route arrived while we act as Provider / Route Server), `ingress_peer_mismatch` (lateral Peer session, OTC value is not the peer's ASN), `malformed_length` (OTC attribute undecodable; announcements dropped treat-as-withdraw style per RFC 7606), or `egress_to_upstream_via_otc` (post-policy route rejected before grouped/private Adj-RIB-Out commit toward a Provider / Peer / Route Server). Ingress remains per rejected UPDATE decision; egress increments once per transition of a peer/route identity into the blocked disposition, and permit, withdrawal, or session reset re-arms it. Export explain remains current decision truth; transport retains a defense-only check. |
| `bgp_as_path_loop_detected_total{peer}` | Prefixes rejected because our own ASN appears in the received `AS_PATH` (RFC 4271 §9.1.2). No `reason` label — the mechanism is the metric name; withdrawals in the same UPDATE are still processed |
| `bgp_rr_loop_detected_total{peer}` | UPDATEs rejected by route-reflection loop detection (RFC 4456 §8). No `reason` label; the debug log line emitted with each increment carries `reason=originator_id` (received `ORIGINATOR_ID` equals our router-id) or `reason=cluster_list` (our cluster-id already in `CLUSTER_LIST`) |
| `bgp_bgpls_nlri_discarded_total{peer}` | Known BGP-LS NLRIs dropped for out-of-order descriptor TLVs (RFC 9552 fault management). The affected NLRI is isolated and the session is preserved; each increment carries a `family=bgp_ls` debug log line. Fatal BGP-LS framing/length errors are not counted here — they still reset the session |
| `bgp_update_malformed_total{peer,disposition}` | Malformed UPDATE messages by the RFC 7606 disposition applied: `attribute_discard` (offending attribute dropped, UPDATE proceeds), `treat_as_withdraw` (every route in the UPDATE handled as withdrawn, session stays Established), or `session_reset` (NOTIFICATION + teardown, retained where the NLRI cannot be trusted — including the §5.2 escalation when a treat-as-withdraw-class error arrives with no reachable NLRI). One increment per malformed UPDATE, labeled with the strongest-action disposition that governed it (§3 (h)). Each increment is accompanied by a warn log line per malformed attribute and, at DEBUG, the §6 full-message hex capture |
| `bgp_exact_export_rejections_total{peer,family,reason}` | Post-policy announcements rejected before Adj-RIB-Out commit because the session's exact one-route encoder could not produce a legal wire message. `family` is a bounded OpenConfig AFI/SAFI label; `reason` is `encoding`, `missing_ipv6_next_hop`, `ipv4_requires_extended_next_hop`, or `message_too_long`. Alert on a sustained increase, then correlate the peer/family with the warning log's bounded route identity and detail. Series are reaped only when the configured peer is deleted. |
| `bgp_max_prefix_exceeded_total{peer}` | `max_prefixes` ceiling breaches; each increment is followed by max-prefix teardown: bare Cease/1 without Notification GR, or RFC 8538 Hard Reset encapsulating Cease/1 when the N-bit was negotiated (see "Peer max-prefix exceeded" above) |

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

### gNMI dial-out

| Metric | What it tells you |
|--------|-------------------|
| `gnmi_dialout_connected{target}` | 1 while the dial-out Publish stream to this `[gnmi_dialout]` target is established, 0 while disconnected/retrying. Refreshed on both transitions; the series exists (at 0) from startup even when the collector is down, and is reaped when the target is removed from config (SIGHUP) |

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

## Slow peers (detection and isolation)

A **slow peer** is a client that is Established and alive — keepalives
flow in both directions, so neither the hold timer nor the RFC 9687
send-hold timer fires — but persistently fails to keep up with the
update stream we send it. On a route reflector or route server with
shared update-groups, one such client can drag the shared staging pass
for its whole group. Typical causes: an undersized control plane on the
client, a congested or lossy path (small effective TCP window), or a
client busy with its own convergence.

Detection is on by default and purely observational: once a peer's
outbound backlog stays at or above `slow_peer_threshold_pct` (default
50%) of the writer buffer for `slow_peer_duration` seconds (default
30), the daemon

- raises the `slow_peer` flag in `rbgp neighbor <ip>` (and the
  `GetNeighborState`/`ListNeighbors` gRPC surface),
- sets `bgp_peer_slow{peer}` to 1, and
- logs a warn (`peer flagged slow: session alive but outbound queue
  persistently backlogged`).

All three clear as soon as the backlog drains below the threshold —
the flag can never latch — and on session teardown. Set
`slow_peer_duration = 0` on a neighbor or peer group to disable
detection.

What to do when it fires:

1. Confirm with `bgp_peer_outbound_queue_depth{peer}` — a persistent
   plateau (rather than sawtooth bursts) matches the flag.
2. Check whether the whole group is slow (many peers flagged →
   suspect the local box or an upstream burst) or one client lags its
   group-mates (→ suspect that client / its path).
3. For a chronically slow client on a shared update-group, enable
   `slow_peer_isolation = true` for it (or its peer group): the daemon
   moves the flagged peer onto its own per-peer update path
   (`bgp_peer_update_group` shows the ungrouped sentinel `-1`, reason
   `slow_peer`) so the rest of the group converges at full speed, and
   regroups it automatically when it recovers. Isolation trades the
   shared-encode saving for that one peer against group convergence —
   it is off by default.
4. A peer that stops draining *entirely* is handled by the existing
   guards, not this feature: the RFC 9687 send-hold timer tears down a
   wedged socket, and outbound-buffer saturation tears the session
   down with `Cease/Out of Resources`.

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
| `bgp_selection_deferral_active{afi_safi}` | Planned-restart family convergence/release gate (1 = active); it remains active while collision failback waits for EoRR even after route selection is staged |
| `bgp_selection_deferral_waiters{afi_safi}` | Frozen-roster peers still blocking family convergence/release, including an `awaiting_refresh` survivor after route selection is staged |
| `bgp_selection_deferral_releases_total{afi_safi,reason}` | Family gates released after `all_eor`, `collision_refresh`, `all_excluded`, or `timer` |
| `bgp_selection_deferral_timeouts_total{afi_safi}` | Family gates released by the selection-deferral timer |
| `bgp_selection_deferral_ledger_overflows_total{afi_safi}` | Gated families whose next identity would exceed the process-wide one-million-identity or 64 MiB logical retained-key-data ledger and therefore use a complete release sweep |

For active gates, `rbgp neighbor <address>` and
`NeighborService.GetNeighborState` also show the peer's waiter state, stamped
session, blocking-waiter count, and remaining time. A released row retains its
reason for the daemon lifetime. A ledger-overflow warning is emitted once per
family; release then enumerates the complete Adj-RIB-In and Loc-RIB family so
withdrawals that already left Adj-RIB-In are still removed before EoR. The
64 MiB bound is deterministic accounting for retained key data (including
nested FlowSpec terms and BGP-LS payload bytes), not a promise about process
RSS, allocator capacity, or hash-table overhead. An identity that lands exactly
on either cap is retained; the family of the next identity that would exceed a
cap enters overflow fallback.

An ordinary same-address replacement remains an EoR waiter, and stale EoR from
its predecessor is rejected. If collision resolution fails registration back
to the exact nonzero, unambiguous survivor, only that survivor enters
`awaiting_refresh`; other waiters remain blocking. The current Loc-RIB is staged
as soon as ordinary waiters finish, but downstream EoR and route-refresh
responses stay held until a post-failback BoRR is followed by the matching peer
EoRR. Ordinary EoR, stray EoRR, and the local refresh timeout do not satisfy the
waiter. Full or closed survivor outbound channels can lose the request, so the
original selection-deferral deadline remains the bounded fallback.

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
| `bgp_aspa_records` | ASPA customer records loaded in the merged table. Renamed from `bgp_aspa_records_total` (a gauge must not carry the counter `_total` suffix) |
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
| `published GR restart marker with wall-clock fallback because boottime protection was unavailable` | WARN | Clock-domain sampling or representation failed; a complete bounded v1/v2 marker was selected. Check `publication_durability` on the final publication log for directory-sync status. |
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

## Support bundles and triage checks (`rbgp doctor`)

`rbgp doctor` runs red/green triage checks live (daemon reachable and
healthy, peers stuck outside Established with time-in-state, flap loops,
TCP-AO configuration against the daemon's kernel capability probe, daemon
`nofile` rlimits, recent panic reports) plus first-deploy environment
probes, and writes one redacted `rustbgpd-doctor-<ts>.tar.gz`:

First-deploy probes (each bounded to a 2s timeout, read-only):

| Check | What it probes | Red/yellow advice |
|-------|----------------|-------------------|
| `bgp.listener` | Daemon up: TCP connect to the BGP listen port. Daemon down: test-bind the port and release it | `CAP_NET_BIND_SERVICE` for ports below 1024; port-in-use is yellow (an unreachable daemon may hold it) |
| `rpki.cache.<addr>.reachable` | TCP connect to each `[rpki] cache_servers` entry | origin validation stays degraded until the cache connects |
| `bmp.collector.<addr>.reachable` | TCP connect to each `[bmp] collectors` entry | monitoring export is down; the daemon retries on its reconnect interval |
| `gnmi_dialout.<name>.reachable` | TCP connect to each `[gnmi_dialout] targets` entry | dial-out telemetry backs off and retries |
| `state_dir.writable` / `state_dir.disk` | `runtime_state_dir` writability and free space (yellow < 1 GiB, red < 100 MiB) | journal, MRT dumps, crash reports, and the event-history DB write there |
| `host.run_context` | systemd / container / unknown from pid-1 facts | tailors remediation lines (e.g. `LimitNOFILE=` vs container ulimits) |
| `daemon.config_freshness.<pid>` | config file mtime vs. local daemon start time | yellow when on-disk edits are pending; validate with `rustbgpd --check` then reload with SIGHUP |

Probe targets come from the daemon's effective config when it is up; when
it is down, from the local config file (the path a local daemon process
was started with, else `/etc/rustbgpd/config.toml`) — parsed for
addresses only, never copied into the bundle.

```
rustbgpd-doctor-<ts>/
├── manifest.json            # versions, redaction note, per-section collected/unavailable, check results
├── config/effective.toml    # the daemon's GetEffectiveConfig dump (defaults materialized, secrets <redacted>)
├── peers/neighbors.json     # per-peer state, counters, flap counts
├── peers/events.json        # recent session + policy events (free text scrubbed)
├── logs/tail-1000.jsonl     # only with --log-file; see below
├── crashes/panic-*.toml     # panic reports swept from <runtime_state_dir>/crash/
└── system/                  # environment.json, health.json, global.json, metrics.prom, daemon rlimits
```

Exit codes: `0` all checks green, `1` error, `2` bundle written but one or
more checks are red. A doctor run against a down daemon still produces a
bundle (system facts + crash reports) and the manifest records which
sections are missing.

For live inspection, `rbgp neighbor <address>` reports the effective protected
transport and an explicit TCP-AO health state. Direct dynamic-prefix sessions
derive TCP-AO identity from their validated accepted socket rather than a
per-neighbor key configuration. `unavailable` means TCP-AO protection is
expected but no socket inspection snapshot is available (the peer may be
disconnected, connecting, or socket inspection may have failed).
Persistent disagreement between `TCP_AO_INFO` and `TCP_AO_GET_KEYS` is also
`unavailable`: rustbgpd clears the whole snapshot instead of publishing an
inconsistent degraded value. `healthy` means the published live snapshot has
valid current/RNext keys mapped to a nonempty, internally consistent live MKT
inventory, neither active key is deprecated, and there are no authentication
error counters; `degraded` means a key-validity flag is missing, an active key
is deprecated, or at least one cumulative socket-lifetime error counter is
non-zero. When socket inspection succeeds, connected sessions
also show current/RNext KeyIDs,
packet verification counters, and redacted per-key peer/prefix, directional
IDs, algorithm, selection flags, rollover metadata, and counters. Key bytes,
lengths, hashes, and fingerprints are never returned. `TCP_AO_GET_KEYS` does
copy raw key bytes into a private temporary buffer; rustbgpd compares accepted
sockets against the complete configured keyring without logging the bytes and
zeroizes every temporary on success, error, retry, and unwind.
Longer-lived TCP-AO keys and TCP-MD5 passwords owned by the internal API,
peer-manager, and transport runtime are also redacted and each clone zeroizes
its allocation when replaced or dropped. The temporary Linux `tcp_md5sig`
record scrubs its key buffer and length after `setsockopt`. Parsed TOML,
configuration snapshots, protobuf messages, compiler-created copies, and
kernel-owned keys retain their own lifetimes and are not covered by that
guarantee.

The same neighbor view reports TCP-AO rotation `desired`, `applied`, and
`phase` values. `idle` means the peer has acknowledged the desired immutable
inventory; `add_only` is an in-progress successor install; and
`add_only_failed` includes a secret-free actionable error. A failed add-only
generation does not select or delete keys and is safe to retry with SIGHUP.
If listener mutation may have started, affected protected passive accepts can
reject until the same generation is retried or the daemon restarts; established
sessions keep their prior selectable keys. A child queued before a successful
listener flip is repaired only when it exactly matches the immediately previous
inventory. Partial inventories and older queued generations remain rejected.

The optional per-key `vrf_ifindex` is Linux's VRF L3-master key selector, not
an IPv6 link-local interface scope. rustbgpd currently installs VRF-unbound
TCP-AO MKTs (`TCP_AO_KEYF_IFINDEX` clear), so Linux may match them in any L3
master. Scoped link-local routing remains attached to the TCP socket,
and configuration validation forbids reusing the same link-local neighbor
address across interfaces.

Counters and the key inventory are refreshed from the socket for each query;
inspect `last_error` for setup or connect failures.

What is never collected: the raw daemon config file (the config section is
the daemon's own secret-redacted effective dump — the same document as
`rbgp config effective`) and bearer-token material. Metrics, event free
text, peer descriptions, crash reports, and log lines are additionally
scrubbed for password/secret/token/bearer lines client-side.

Logs: the daemon logs JSON to stdout (journald under systemd), so no log
file is collected by default — the manifest records that instead. If stdout
is redirected to a file, pass it explicitly:

```bash
rbgp doctor --log-file /var/log/rustbgpd.jsonl   # tails the last 1000 lines
```

Crash reports: a daemon panic writes a small TOML report (panic message,
source location, thread, version — never environment variables or argv)
to `<runtime_state_dir>/crash/panic-<ts>.toml`, keeping the 10 most
recent. `rbgp doctor` sweeps them into `crashes/`; a report in a bug
ticket usually pinpoints the crash without a core dump.

Attach the tarball to bug reports — the GitHub bug-report template asks
for it.

---

## Common operational tasks

### Check session status

```bash
rbgp neighbor          # summary table (alias: rbgp summary)
rbgp neighbor --wide   # adds MsgRcvd, MsgSent, Flaps, RRC, State/PfxRcd
```

`--wide` appends the classic vendor summary columns: total messages
received/sent (all types, daemon-lifetime — an Established session whose
counters stop moving is wedged), flap count, an RR-client marker, and the
overloaded `State/PfxRcd` column (a number means Established and shows the
prefixes received). Display-only: `-j` output always carries every field.

### Add a peer at runtime

```bash
rbgp neighbor 10.0.0.5 add --remote-asn 65005 --description "new-peer"
rbgp neighbor 203.0.113.2 add --remote-asn 65002 --role provider --strict-role
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
return to Idle. Omitting `--remote-asn` uses the accept-any sentinel (`remote_asn = 0`);
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

The task-oriented catalog of every explain surface — which question
maps to which command, plus the member-support workflow — is
[explain.md](explain.md); the sections here carry the full semantics.

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
| `not_seen` | The peer hasn't advertised this prefix on the current session (cache resets on flap / restart). This is an evaluated answer: the session is live and the cache is enabled. |
| `cache_disabled` | The session records no decisions (`[policy.explain] enabled = false`). The CLI renders this as an error with a config hint and exits nonzero — it is never folded into `not_seen`. |
| `no_session` | No live session with the requested neighbor, so there is no session-local cache to consult. The CLI renders this as an error and exits nonzero. |

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
  `cache_disabled`, and the CLI errors with a hint).
- `cache_size` (default `4096`) — a fabric / partial-table size. For
  reliable full-table explain, raise it toward the peer's
  expected retained-prefix count and budget the memory.

### Answer a member's "why is my route filtered?" (LAN-472)

The enumeration complement to `policy explain`: when a route-server
member calls asking why their prefix isn't in the RS — and neither of
you knows exactly which announcement is at fault — list everything of
theirs the import path rejected, tagged with the reason:

```bash
rbgp rib received 10.0.0.2 --rejected
rbgp rib received 10.0.0.2 --rejected --json   # Alice-LG-style tooling feed
```

Each row carries the rejected prefix (with Add-Path `path_id`), the
canonical reason token, a detail field, the wire next-hop, the AS path,
and RPKI/ASPA validation states at rejection time:

| Reason | Meaning / detail field |
|---|---|
| `policy_reject` | The import chain denied it (detail: the matched policy name; the row's RPKI/ASPA columns show whether a validation state drove the deny). Follow up with `rbgp policy explain` on the prefix for the statement-level trace. |
| `otc_route_leak` | RFC 9234 Only-to-Customer ingress drop (detail: the canonical OTC sub-reason, e.g. `ingress_from_customer_rsclient`). |
| `next_hop_ownership` | Strict-peer next-hop ownership gate, RFC 7948 §4.8 / ADR-0107 (detail: e.g. `foreign_next_hop`; the next-hop column shows the violating value). |
| `as_path_loop` | Our ASN in the received AS_PATH (RFC 4271 §9.1.2). |
| `rr_loop` | Reflection loop, RFC 4456 §8 (detail: `originator_id` or `cluster_list`). |
| `treat_as_withdraw` | RFC 7606: a malformed attribute forced the whole UPDATE's routes to be handled as withdrawn. |

Retention is per-session and self-maintaining: an identity that is
later **accepted** or **explicitly withdrawn** drops out (the listing
never claims a live route is filtered), and the store resets on session
flap. It is bounded per peer (`[policy.reject_retention] capacity`,
default 1024, LRU on rejection recency) — when the listing reports the
store at capacity, it shows the most recent rejections and the CLI says
so. Max-prefix violations don't appear here: exceeding the limit tears
the session down (Cease/1), which is its own, louder signal.

`bgp_rejected_routes_retained{peer}` gauges the store per peer — a
sustained high value on a member session is the "their filters are
rejecting a lot" signal worth proactive outreach before the support
call. `[policy.reject_retention] enabled = false` disables retention
entirely (the CLI then reports the disabled state, never an empty
answer); both knobs are restart-required per peer.

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
static-neighbor or direct dynamic-prefix `tcp_ao` keyring will fail closed
instead of falling back to unauthenticated sessions: listener failures abort
startup, while active-open failures reject that connect attempt and retry
later. SIGHUP can append non-preferred successor keys to unchanged static and
dynamic owner keyrings without changing Current/RNext. Selection,
deprecation, deletion, editing/reordering existing keys, and protected-owner
CRUD remain restart-required.

`rbgp neighbor <address>` reads TCP-AO KeyIDs and verification counters from
the live connected socket on every query. Inspection failure is reported as
`unavailable` without falling back to an older snapshot or disturbing the BGP
session. Linux counters are cumulative for the socket lifetime, so `degraded`
means either the current/RNext key-validity flag is missing or at least one
verification, missing-key, unsigned-required, or dropped-ICMP error has occurred
since that TCP connection was created.

The same neighbor view reports the RIB's effective live distribution mode,
rather than inferring it from configuration or update-group fallback labels.
Down peers show `unknown`. Paths-Limit rows are numeric AFI/SAFI ordered, and
their effective send value is explicitly `inactive`, `unlimited`, or finite.

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
rbgp rib fib --prefix 203.0.113.0/24 --neighbor 198.51.100.2
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

# Labeled unicast (SAFI 4, RFC 8277): explain the labeled export ladder
# for the prefix instead of the plain unicast one.
rbgp rib --prefix 10.1.0.0/24 advertised 10.0.0.2 --explain --labeled

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
(RFC 4684); the labeled-unicast ladder follows the live labeled staging
order (`family` first, no `rt_membership`/`orf`). A family still held by
the initial-ORF gate (RFC 5291 section 6) stops at `orf_gate` before any
per-prefix work.

Truthfulness: the explanation is produced by a read-only dry run of
the *same staging body* live distribution executes -- including for
update-grouped peers, which are explained against their group table
with split horizon applied per member exactly like the emit-time
source-flip matrix. The response carries `update_group_id` when the
peer's export is group-staged. Explain queries never count toward
`bgp_policy_routes_total` or per-term policy hit counters.

The live commit path then applies one final exact-wire gate through an
immutable snapshot of the session encoder and its negotiated 4096/65535-byte
ceiling. A failed announcement never enters Adj-RIB-Out. If it had been
advertised before an attribute, next-hop, capability, or ceiling change made
it unexportable, that transition sends a withdrawal. For update groups the
shared staged table is unchanged; a sparse per-member overlay removes the
rejected identity from that peer's advertised query and BMP count, allowing a
classic-message peer and an Extended Message peer to remain grouped safely.
Later recompute or dirty resync retries the route, while a source withdrawal
clears the rejection without sending a duplicate withdrawal for a route that
was never advertised. Watch
`bgp_exact_export_rejections_total{peer,family,reason}` and the corresponding
warning log. Cease/8 still tears down the session if transport encounters an
impossible single-route message or a missing/mismatched encoder snapshot; that
is defense in depth, not the normal rejection path.

An RFC 9107 ORR peer's explain ranks the per-vantage candidate set the
ORR export uses (with per-candidate cost output). When filtered or ignored
topology inputs are present, the stable
`orr_topology_input_diagnostics` reason is explicitly aggregate and
non-decisive; it does not replace the winner's decisive interior-cost reason.
`rbgp orr` always prints a `Topology inputs:` aggregate line; JSON and
`ListOrrStatus` expose the same five counters. An Add-Path-send
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
rbgp gshut --neighbor 10.0.0.2

# Or drain every currently-managed peer at once
rbgp gshut

# Wait for traffic to shift (operator-defined, typically 30s-5min
# depending on convergence in the upstream AS), then proceed with
# the actual maintenance — restart, config edit, etc.

# Clear the community when maintenance ends
rbgp gshut --neighbor 10.0.0.2 --clear
rbgp gshut --clear
```

The toggle is **operator-runtime state**, not config — it lives on
the `ManagedPeer` desired-state record, mirrors to the live session,
and survives session flaps mid-maintenance. The toggle does NOT
persist across daemon restart by design (RFC 8326 is a maintenance-
window action, not a steady state).

When the toggle flips, rustbgpd issues a `RibUpdate::RefreshPeerOutbound`
which queues re-emission of all routes already in `AdjRibOut` to the
target peer without waiting for an unrelated RIB event. Receiver-side
verification is still required to prove delivery.

`rbgp neighbor <peer>` always reports the local desired state as
`GShut Advertise Intent: enabled|disabled|unknown`; `unknown` means the CLI is
connected to an older daemon that does not expose this field. This is only the
local send intent — it does not prove that a route was re-advertised, received,
or converged downstream.

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

# Initiator-side: confirm the local desired advertisement state.
rbgp neighbor <receiving-peer> | grep 'GShut Advertise Intent: enabled'

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

### Looking glass (Birdwatcher-shaped REST subset)

For status, peer, accepted-route, filtered-route, and noexport views in
external looking glass frontends, run the external
`examples/birdwatcher-adapter` binary. It serves the Birdwatcher-shaped
endpoints (`/status`, `/protocols/bgp` with real per-neighbor filtered
counts, `/routes/protocol/{id}`, `/routes/peer/{peer}`,
`/routes/filtered/{id}`, `/routes/noexport/{id}`) from the daemon's gRPC
API. The filtered view surfaces the `PolicyService.ListRejectedRoutes`
reject-retention store with a synthesized reject-reason large community
per route; the noexport view diffs Loc-RIB best against the peer's
Adj-RIB-Out and names each suppression's export gate via
`RibService.ExplainAdvertisedRoute`, with its own synthesized
noexport-reason community (mapping tables and Alice-LG config in the
adapter's README). The in-daemon `[global.telemetry.looking_glass]`
server has been removed.

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
rbgp evpn --neighbor 10.0.1.1         # filter by source peer
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
