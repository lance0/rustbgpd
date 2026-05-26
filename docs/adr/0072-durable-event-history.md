# ADR-0072: Durable Event History (Local Outbox)

**Status:** Accepted
**Date:** 2026-05-26

## Context

rustbgpd has accumulated four independent in-memory event rings — route
events on the RIB side (`crates/rib/src/manager/mod.rs:113-147`), EVPN
route events (same file), session lifecycle and policy events on the
PeerManager side (`src/peer_manager/mod.rs:168-171`,
`src/peer_manager/events.rs:44-294`). Each ring is bounded at 4096
entries, fed by an "insert into ring, then broadcast" sequence. They
reset to empty on daemon restart.

Only the route ring carries an `event_id` (`u64`, process-local
monotonic, assigned at
`crates/rib/src/manager/mod.rs:1033-1038`). The CLI's
`rustbgpctl watch --backfill` flag (`crates/cli/src/commands/watch.rs:829-868`)
uses that ID to deduplicate when it fetches history via
`ListRouteEvents` and then subscribes to live events. **The dedup
silently breaks across a daemon restart**: the new process resets
`next_route_event_id` to 1, so the CLI's "skip events with id <=
last_backfilled" filter matches IDs from a different sequence
entirely. EVPN, session, and policy events have no `event_id` at all
— their backfill story is "no story."

Two recently-accepted ADRs explicitly punted to "future durable event
history" work:

- **ADR-0071 (Roles + OTC)** deferred the `OtcRouteBlocked` event
  payload because a backfillable event needs stable cursors that the
  current 4096-entry process-local ring cannot provide
  (`docs/adr/0071-bgp-roles-otc.md:241-245`).
- **ADR-0070 (gNMI / OpenConfig telemetry)** deferred
  `Subscribe ON_CHANGE` for the same reason: gNMI ON_CHANGE
  subscribers need restart-survivable change history with
  monotonic generation IDs.

The Operator Confidence sprint added policy event *counters* (PR2a /
PR2b, merged in #283 / #285), which answer "how many," but not "what
happened, in what order, and can a downstream collector replay it
after a daemon crash?"

### Framing — daemon-local outbox, not event bus

The operator boundary chosen explicitly:

> rustbgpd keeps a bounded durable event outbox for operational
> recovery and restart-survival. Operators who need long retention,
> fanout, joins, SIEM ingestion, or fleet-level analytics consume
> the stream over gRPC and persist it externally on their bus
> (Kafka, NATS, Vector, journald, custom).

The daemon is **not** the system of record for event history. It is
the daemon-local outbox that external collectors drain. This boundary
shapes every subsequent decision in this ADR — what storage we pick,
how aggressively we cap retention, how we behave under load, what
contract we promise consumers.

### What rustbgpd already gives us

- **Actor pattern**: every subsystem (RibManager, PeerManager,
  ConfigPersister) is one tokio task driven by an mpsc receive loop
  (e.g. `src/main.rs:847-849`, `src/main.rs:1027-1066`). A new
  `EventHistoryManager` slots into the existing supervisor pattern.
- **Atomic on-disk state pattern**: `fib-owned.json` uses temp-write +
  rename (`src/fib_runtime.rs:1144-1163`), with `.json.stale`
  quarantine on corrupt-on-load
  (`stale_owned_state_path` at `src/fib_runtime.rs:1140-1142`).
  `gr-restart.toml` is a simpler case — small versioned marker written
  in-place (`src/main.rs:316-334`) — and is the reference for the
  versioned schema-marker pattern below, not the atomic-write one.
  The new SQLite store inherits the `.stale` quarantine convention;
  the WAL handles the atomic-write story internally.
- **Versioned on-disk markers**: `GR_RESTART_MARKER_VERSION` at
  `src/main.rs:67-73` is the existing schema-downgrade-fence pattern;
  the SQLite `metadata.schema_version` row mirrors it.
- **`runtime_state_dir` accessor** at `src/config/mod.rs:181-196`
  with default `/var/lib/rustbgpd` — the events DB lives next to
  `gr-restart.toml` and `fib-owned.json`.
- **Bounded broadcast subscriber + lag detection**:
  `crates/api/src/event_service.rs:176-482` already handles
  `BroadcastStreamRecvError::Lagged` and emits a `StreamLagEvent` so
  clients see "you fell behind." That contract carries forward when
  the broadcast moves into the EventHistoryManager.
- **Authz tiering**: `SensitiveRead` is the existing tier for every
  event-streaming RPC (`crates/api/src/authz.rs:445-468`). New
  cursor RPCs join the same tier.

### What's broken today

| Concern | Today | With durable outbox |
|---|---|---|
| Backfill across restart | Silently broken (event_id collision) | Monotonic event_id continues; replay is gap-free for the committed stream |
| EVPN / session / policy `event_id` | Absent | Carried at `BgpEvent` envelope level for all categories |
| Notification audit history | Broadcast-only, never persisted | Persisted alongside lifecycle events |
| Cursor for external collector | None — collector loses state on restart | `SubscribeFromEvent(from_event_id)` is the durable replay surface |
| Ring eviction visibility | Silent | Drop counter + `event_outbox_degraded` health flag |
| Behavior under disk slowness | Producers proceed unaffected (no durability) | Producers proceed unaffected (drops + degraded flag); no control-plane wedge |

## Decision

Add a single new actor — **`EventHistoryManager`** (EHM) — that owns
the broadcast channels currently scattered across producers, persists
every event to a SQLite WAL store, assigns durable monotonic
`event_id`s via an explicit allocator, and serves a unified
`SubscribeFromEvent(from_event_id)` cursor RPC that external
collectors use to bridge to their bus.

### Categories

`route`, `evpn`, `session`, `policy`, `bfd`, `dataplane`. These match
the existing broadcast streams in
`crates/api/src/event_service.rs:176-482` and the `BgpEvent` oneof
in `proto/rustbgpd.proto:1289`.

### Event ID

`event_id` is a `u64` allocated by EHM, **monotonic across daemon
restarts**, never reused. It is **not** the SQLite ROWID — ROWIDs can
be reused under vacuum-and-reload scenarios and the
"`MAX(event_id)` of an empty table is NULL" boundary case is
unambiguous only when an explicit allocator row exists.

The allocator lives at `metadata.last_event_id` in the events DB.
Every batch insert is one SQL transaction: read the allocator,
assign IDs in memory to every event in the batch, bulk insert with
explicit `event_id` column, update the allocator, commit. All-or-
nothing.

`event_id` is carried at the **`BgpEvent` envelope level only**,
not duplicated onto every nested event type
(`RouteEvent`, `SessionEvent`, etc.). The existing
`RouteEvent.event_id` field stays for wire backwards-compatibility,
reframed as "convenience copy of the envelope ID." Inside the
daemon, `BgpEvent.event_id` is the source of truth; a mismatch
between envelope and nested copy is a panic-in-debug, warn-in-
release bug.

A separate `daemon_boot_id` UUIDv4 is stamped at startup, written to
`metadata.last_boot_id`, and copied onto every event. Clients use
`daemon_boot_id` to detect restarts independently of the monotonic
`event_id` (useful for "is this gap a daemon restart or a queue
drop?").

### Storage — SQLite WAL

One SQLite database at `<runtime_state_dir>/events.db`. Crate:
**`rusqlite`** with the `bundled` feature so the daemon doesn't
inherit per-distro libsqlite packaging variance. Connections set the
following PRAGMAs once on open:

- `journal_mode = WAL`
- `synchronous = FULL` — fsync per commit; the outbox is best-
  effort under overload, but under steady state we don't want silent
  loss on crash. Operators who want NORMAL for raw throughput can
  opt in via config.
- `busy_timeout = 5000` ms — absorbs transient lock contention
  during checkpoints.
- `foreign_keys = OFF` — single-table outbox, no FK relations.
- `wal_autocheckpoint = 1000` pages.

**Architectural boundary**: `spawn_blocking` is confined to a
`storage` submodule in the new crate. The EHM actor itself stays
async — it sends `StoreOp::Append { events, reply: oneshot }`
messages to the storage thread, which owns the `Connection` and
processes batches in one `spawn_blocking` per batch (not per event).
The rest of EHM (batching, retention scheduling, broadcast fanout)
is plain async code with no blocking-context awareness. Only
`storage.rs` and `migrations.rs` see `rusqlite::Connection`.

#### Schema

```sql
CREATE TABLE events (
    event_id           INTEGER NOT NULL PRIMARY KEY,
    timestamp_ns       INTEGER NOT NULL,
    category           TEXT NOT NULL,
    event_type         TEXT NOT NULL,
    peer               TEXT,
    previous_peer      TEXT,
    target_peer        TEXT,
    afi_safi           TEXT,
    prefix             TEXT,
    rd                 TEXT,
    evpn_route_type    INTEGER,
    severity           TEXT NOT NULL,
    schema_version     INTEGER NOT NULL,
    daemon_boot_id     TEXT NOT NULL,
    payload_codec      TEXT NOT NULL DEFAULT 'proto',
    payload            BLOB NOT NULL
);

CREATE INDEX idx_events_category_id ON events(category, event_id);
CREATE INDEX idx_events_peer_id     ON events(peer, event_id)
    WHERE peer IS NOT NULL;
CREATE INDEX idx_events_prefix_id   ON events(prefix, event_id)
    WHERE prefix IS NOT NULL;
CREATE INDEX idx_events_rd_id       ON events(rd, event_id)
    WHERE rd IS NOT NULL;
CREATE INDEX idx_events_timestamp   ON events(timestamp_ns);

CREATE TABLE metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Required keys: schema_version, db_format_version, last_boot_id,
--                last_event_id, created_at_unix
```

`payload` is the prost-encoded `BgpEvent` envelope — identical wire
format to what `WatchEvents` already delivers over gRPC. No separate
codec.

### Hot path — try_send + batched commit

Producers reach EHM through a bounded `mpsc::channel(4096)` per
producer. EHM drains both queues, batches with a size threshold
(1024 events) and a time threshold (50 ms) — whichever fires first.
Each batch is one SQLite transaction (one fsync; **not** one fsync
per event).

Expected steady-state cost: 10-100 µs per event on the producer
side (`try_send` only); ~50 ms commit latency on the durable side.
At 10k events/s with batch=1024 → 10 commits/s, each ~150 KB to
WAL. Well within disk budget for the operationally-recovery use
case.

### "Committed = broadcast" — when enabled and healthy

EHM commits the batch to SQLite **before** broadcasting. If EHM
crashes mid-batch, uncommitted events are lost on both the durable
side and the broadcast side — clients reconnecting do
`SubscribeFromEvent(from_event_id)` and replay every committed event
from where they left off.

The contract is conditional: **when the durable outbox is enabled
and healthy, no live event is broadcast without first being durably
committed.** If `[event_history].enabled = false` or the DB-open
failed into pass-through mode (see Failure Modes below), broadcasts
revert to live-only with no durable backing — clients that need
durability must check `bgp_event_outbox_degraded` and treat live-
only data accordingly.

### Backpressure — uniform best-effort drop

The contract, made painfully explicit in the operator-facing docs:

> The durable event outbox is **best-effort under overload** and
> **not a compliance-grade audit log.** A slow disk or wedged
> SQLite checkpoint degrades observability, not routing behavior.

Producers `try_send`. On full queue:

- Drop the event.
- Increment `bgp_event_outbox_dropped_total{category, reason="queue_full"}`.
- Track `bgp_event_outbox_oldest_queued_age_seconds` — climbs
  before drops start, gives operators an early-warning signal.
- Emit one deduplicated `warn!` log per second with the per-
  category drop count.
- On the first non-zero drop in a process lifetime, flip the
  daemon-wide health flag `event_outbox_degraded = true`. The flag
  is surfaced on the existing `/healthz` and `rustbgpctl status`
  paths. **In v1 it never auto-clears** — operator restarts to
  clear. A future `rustbgpctl event-history reset-health` command
  is a P1 nice-to-have.

**Uniform drop across categories, deliberately.** We do not
bifurcate (route=drop, session=block). Bifurcation is attractive
on paper but creates surprising behavior: route updates keep
flowing while session lifecycle and policy paths stall on disk,
which puts disk slowness one step away from control-plane wedging.
Session lifecycle and notification events are too close to FSM
behavior to risk blocking casually. If audit-grade semantics
become a real operator ask later, the config grows
`overflow = "block"` (P1) or per-category overrides (P2 maybe).
v1 keeps it simple and safe: drop observability before you ever
block control-plane work.

### Global ordering

The durable `event_id` sequence is **order-of-arrival-at-EHM**,
not order-of-causal-occurrence at the producer. RibManager and
PeerManager each feed an independent bounded queue; events from
the two can interleave at EHM in an order that does not reflect
wall-clock or causal precedence at the producer.

This is acceptable for the outbox-replay contract — `event_id` is
strictly monotonic for cursor purposes — but external collectors
joining route + session events for causal analysis must not assume
"session lost N happened before route withdraw M" purely from
`event_id` ordering. They must use the per-event `timestamp_ns`
(stamped at the producer **before** enqueue) when causal ordering
matters. The contract documents this as a hard limit.

### Cursor API — `SubscribeFromEvent` with actor-ordered handoff

A naive "query history, then attach broadcast" implementation has
a race: an event committed *after* the query snapshot but *before*
the subscriber attaches will be lost on both paths. Wrapping it in
a single `tokio::select!` does not close the race.

The cursor RPC `SubscribeFromEvent(from_event_id) returns (stream BgpEvent)`
uses a three-step actor-ordered handoff inside EHM, which is the
single actor that owns both the SQLite write side and the live
broadcast sender:

1. **Inside the actor's serialized loop**, register the live
   broadcast receiver first. Because EHM is single-threaded, no
   commit can happen between steps 1 and 3.
2. **Capture the high-watermark** — the last committed `event_id`
   at this instant. Exact, no race.
3. **Spawn a replay task** that drains SQLite for
   `from_id < event_id <= high_watermark`, then drains the live
   broadcast receiver for `event_id > high_watermark`. The
   boundary applies a defensive `event_id` dedup as belt-and-
   suspenders. Clients dedup defensively anyway — it's free.

The new `SubscribeFromEvent` RPC sits next to (does not replace)
the existing `WatchEvents`, `WatchRoutes`, `WatchRouteEvents`. The
existing watch RPCs become `SubscribeFromEvent(from_event_id=0)`
under the hood — live-only.

### Retention — small, hard-capped, two dimensions

Defaults are **deliberately small** so default-on cannot surprise
an operator with hundreds of MB of unexpected disk growth:

- `max_events = 100_000` — hard count cap.
- `max_bytes = 256_000_000` (~256 MB) — hard byte cap measured
  against `events.db` + WAL combined.

Whichever cap fires first wins. No time-based retention dimension
in v1 — operators wanting >hours of history push to their bus,
not grow the local file. Retention runs every 60 s on EHM:
batched `DELETE LIMIT 5000` per pass against each cap, then
`PRAGMA wal_checkpoint(PASSIVE)`. Sharded DB files are deferred to
a future ADR if disk size becomes a real problem.

### Config (`src/config/schema.rs`)

```toml
[event_history]
enabled = true                  # default-on; opt-out for minimal deployments
required = false                # if true, daemon fails to start when DB unavailable
path = ""                       # relative to runtime_state_dir; "" = events.db
max_events = 100_000            # count retention bound
max_bytes = 256_000_000         # byte retention bound (~256 MB)
synchronous = "full"            # full|normal — "full" = fsync per commit
overflow = "drop"               # "drop" only in v1; "block" reserved for future
queue_capacity_per_producer = 4096
batch_size = 1024
batch_interval_ms = 50
```

All `[event_history]` fields are **restart-required**. Hot reload of
the outbox is deferred to a future ADR.

### Failure modes

**DB-open failure** at startup (permission denied, disk full,
corrupted file, schema downgrade fence) splits by `required`:

- `enabled = true, required = false` (default): log a prominent
  `error!`, increment `bgp_event_outbox_open_failures_total`, set
  the `event_outbox_degraded` health flag, **continue** in pass-
  through mode (broadcasts work, no persistence, cursor RPCs
  return an "outbox disabled" error detail).
- `enabled = true, required = true`: daemon fails to start with
  a structured error. For operators who would rather see refusal-
  to-start than lose audit visibility.
- `enabled = false`: outbox path never opened; EHM still spawned,
  but in pass-through mode (broadcasts only). Minimal-deployment
  escape hatch.

**Corrupted DB on load**: same quarantine pattern as
`fib-owned.json` (`stale_owned_state_path` at
`src/fib_runtime.rs:1140-1142`). Rename to `events.db.stale` —
no timestamp suffix, matching the existing convention so operators
inherit one quarantine idiom across the daemon. Before quarantining,
EHM best-effort reads `last_event_id` from the quarantined file's
`metadata` table to seed the fresh DB's allocator (preserving
cursor monotonicity across the recovery), then continues. The
quarantine file is **not** auto-deleted, and a subsequent
corruption would overwrite the prior quarantine — operators who
need to preserve multiple bad files for forensics rename manually
before the next start. The single-file convention beats a
multi-file timestamped convention here because (a) it matches what
operators already know from `fib-owned.json`, and (b) corruption
during a quarantined-file-still-present state is a rare-enough
event that the manual-rename cost is acceptable.

**Schema downgrade fence**: a future daemon version bumps
`schema_version`. Downgrading the daemon binary while pointing at
the new-schema events.db refuses to start with a clear error
message naming both versions. Operator either quarantines manually
(`mv events.db events.db.stale-downgrade`) or upgrades the binary
forward again.

**Slow disk / wedged SQLite**: the bounded `try_send` queue acts
as the buffer; once full, the producer drops the event and the
degraded flag flips. Route installs / FSM transitions are
unaffected — there is no shared lock or blocking call between the
producer hot path and the SQLite writer.

### Observability

Prometheus counters and gauges added by this work:

- `bgp_event_outbox_committed_total{category}` — events durably
  committed.
- `bgp_event_outbox_dropped_total{category, reason}` — drops by
  category and reason (`queue_full`, `db_error`).
- `bgp_event_outbox_queue_depth{category}` — pending in-memory
  queue per category (gauge).
- `bgp_event_outbox_oldest_queued_age_seconds` — gauge; oldest
  event waiting in any producer queue. Operator early-warning.
- `bgp_event_outbox_batch_commit_seconds` — histogram of commit
  durations.
- `bgp_event_outbox_db_size_bytes` — current
  `events.db` + WAL combined.
- `bgp_event_outbox_retention_evicted_total{reason}` — events
  evicted by retention (`count_cap`, `byte_cap`).
- `bgp_event_outbox_wal_checkpoints_total{result}` — checkpoint
  outcomes (`success`, `failure`).
- `bgp_event_outbox_latest_event_id` — gauge of current allocator
  value. "Is the daemon making progress?"
- `bgp_event_outbox_open_failures_total` — DB-open failure counter.
- `bgp_event_outbox_degraded` — 0 or 1; flipped to 1 on first drop
  or open failure, never auto-clears in v1.

The existing
`bgp_event_stream_lagged_total{service, source}` counter
(`crates/telemetry/src/metrics.rs:46`) keeps its current semantics
— broadcast subscribers falling behind. EHM owning the broadcast
doesn't change that contract.

### External-bus integration contract

Documented for operators in `docs/deployment.md` (PR5 of the
implementation sprint adds the section) and demonstrated by a
reference bridge at `examples/event-bridge/`:

1. Operator's collector persists `last_seen_event_id` externally
   (in their bus, a small KV store, a file — operator's choice).
2. On startup or reconnect, the collector calls
   `SubscribeFromEvent(from_event_id=last_seen_event_id)`.
3. Server replays committed events `> last_seen_event_id`, then
   atomically joins the live broadcast (the 3-step handoff above).
4. Collector consumes the stream, writes each event to its bus,
   updates `last_seen_event_id` on commit-to-bus success.
5. On daemon restart, the cursor stays valid — `event_id` is
   monotonic across restarts.
6. On `bgp_event_outbox_degraded == 1`, the collector knows it
   may have missed events; it surfaces the degraded state to its
   bus consumers as appropriate (alert, gap marker, etc.).

### What v1 does not cover

- **No fanout / no event bus inside the daemon.** Operators consume
  over gRPC and bridge to their own bus. The daemon does not push
  to Kafka / NATS / etc.
- **No long retention or analytics queries.** The outbox is for
  operational recovery and short-window debugging. Long retention
  is the operator's bus's job.
- **No sharded DB files.** Single `events.db`. P1 if disk size
  becomes a real problem.
- **No multi-process / no replication.** One writer (this daemon),
  many readers (gRPC clients). HA and cluster replication are out
  of scope.
- **No event-content schema versioning beyond DB schema.** The
  prost-encoded `BgpEvent` blob evolves under the existing proto-
  evolution discipline (proto3 default semantics on missing
  fields).
- **No producer backpressure.** Drop on full + counter +
  degraded flag. `overflow = "block"` is reserved for a future
  ADR; per-category overflow control is further deferred.
- **No hot config reload.** Toggling `[event_history]` requires a
  daemon restart; the reload matrix tags every field as
  restart-required.
- **No auto-clear for `event_outbox_degraded`.** The flag stays
  set until restart in v1. A future
  `rustbgpctl event-history reset-health` command is a P1 nice-to-
  have.

### Alternatives considered

- **In-process pub/sub library (async-channel fanout).** Does not
  survive restart. The whole reason for this ADR is restart-
  survival.
- **Embedded LMDB / sled / redb.** SQLite WAL is more operationally
  boring, has indexed query support out of the box, and is
  debuggable with the `sqlite3` CLI. We do not need LMDB's write
  throughput — 10k events/s is well below SQLite's limit.
- **Kafka / NATS as a daemon dependency.** Operators do not want
  rustbgpd shipping its own event bus. The product boundary is
  "users throw it on their own bus."
- **Per-producer SQLite stores.** Multi-writer SQLite is painful
  (locking, no shared sequence). Single-writer via EHM gives free
  monotonic global IDs, single retention thread, single WAL.
- **Per-daemon-boot cursor (boot_id + process-local event_id),
  no durable storage.** Operators still hit the "boot mid-window"
  gap — collector reconnecting after a daemon crash sees only
  events since reconnection. Durable storage closes the gap.
- **SQLite ROWID instead of an explicit allocator.** ROWIDs can
  be reused after vacuum and have unhelpful empty-table semantics
  (`MAX(rowid)` of an empty table is NULL). An explicit allocator
  row in the metadata table is unambiguous, retention-
  independent, and supports the stale-DB quarantine case where
  the fresh DB inherits `last_event_id` from the quarantined
  file's metadata.
- **`event_id` duplicated onto every nested event type.** Creates
  consistency bugs when the wrapper and nested copy disagree.
  Carrying `event_id` only on the `BgpEvent` envelope avoids the
  bug class entirely. The existing `RouteEvent.event_id` field
  stays for wire backwards-compatibility, reframed as a
  convenience copy.
- **Synchronous broadcast before commit, async commit after.**
  Violates the "committed = broadcast" contract — a client could
  see a live event the daemon then fails to durably commit. The
  daemon-local outbox would no longer be a faithful record of
  what consumers saw. We pay the commit-before-broadcast latency
  (~50 ms p99) to preserve the invariant.

## Consequences

### Positive

- External collectors gain a stable monotonic cursor that survives
  daemon restarts. The "boot mid-window gap" disappears.
- ADR-0070 (gNMI ON_CHANGE) and ADR-0071 (`OtcRouteBlocked`
  structured payload) unblock — both can now ship event payloads
  with backfill semantics.
- The four asymmetric in-memory rings collapse into one durable
  store with a uniform contract. Session notifications — which
  were broadcast-only and never persisted — become durable
  alongside lifecycle events, closing an audit gap surfaced during
  ADR-0071 review.
- Operators get a clear, finite mental model for failure modes
  via the `event_outbox_degraded` flag and a small, well-named
  set of Prometheus counters.

### Negative

- New on-disk file (`events.db` + WAL) under `runtime_state_dir`.
  Default-on means existing deployments will see disk usage they
  did not see before — capped at ~256 MB, but non-zero. Documented
  prominently; `enabled = false` is the escape hatch.
- New crate (`rustbgpd-event-history`) and a small dependency
  footprint addition: `rusqlite` (bundled libsqlite) plus `uuid`.
  rusqlite-bundled adds ~5 MB to the release binary.
- The "committed = broadcast" contract adds ~50 ms p99 commit
  latency to live event delivery in steady state. Acceptable for
  the use cases — these are operational events, not data-plane.
- The producer-side surgery (PR4 — RibManager, PR5 — PeerManager)
  is invasive. The ring-buffer fields and `next_route_event_id`
  allocator come out; broadcast ownership moves; the
  `publish_*_event` functions collapse to `try_send`. Risk is
  mitigated by PR3 — a separate PR that proves the
  `SubscribeFromEvent` cursor contract end-to-end against
  synthetic producers before any RIB / PeerManager change.

### Neutral

- The existing `WatchEvents`, `WatchRoutes`, `WatchRouteEvents`
  RPCs keep their wire signatures and continue to work — they
  re-route through EHM under the hood. `RouteEvent.event_id`
  keeps its wire format; its semantics are reframed but
  backward-compatible.
- The existing per-category `ListRouteEvents`, `ListEvpnEvents`,
  `ListSessionEvents`, `ListPolicyEvents` RPCs keep working; their
  server impls re-route through EHM's cursor API.
- `rustbgpctl watch --backfill` is deprecated in favor of
  `--from-event-id`. The `--backfill` flag remains for one
  release as an alias with a deprecation warning, then is
  removed.
