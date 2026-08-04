# ADR-0072: Durable Event History (Local Outbox)

**Status:** Accepted — implementation shipped v0.24.0+; **default posture
changed in v0.32.0** (see note below).
**Date:** 2026-05-26

> **v0.32.0 update — default flipped to off (opt-in).** The outbox shipped
> *default-on*. v0.32.0 bgperf2 benchmarking then showed the always-on cost was
> material — ~62 MB RSS and roughly double the peak CPU at 2p/100k — i.e. every
> operator paid a visible memory/CPU tax before asking for replay semantics. For
> a routing daemon the safer default is routing fast and lean by default, with
> durable replay enabled explicitly. So `[event_history].enabled` now defaults
> to `false`; operators who want restart-safe event replay set it `true`. **This
> is a default-posture change, not a design reversal** — the design and
> implementation below are unchanged, and it weakens the "operational recovery
> for free" framing only in that recovery is now an explicit opt-in rather than
> on by default. It is the right response to the measured cost. See
> `docs/BENCHMARKS.md` for the numbers and `docs/OPERATIONS.md` for the two
> deployment profiles (lean default vs. observability/replay).

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
`rbgp watch --backfill` flag (`crates/cli/src/commands/watch.rs:829-868`)
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
| Ring eviction visibility | Silent | Drop counter + `bgp_event_outbox_degraded` health flag |
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
restarts**, never reused **as long as the durable allocator is
recoverable**.

SQLite's `INTEGER PRIMARY KEY` column is technically a ROWID
alias on disk — what we change is **how the value is assigned**.
EHM never relies on ROWID auto-assignment (`INSERT … VALUES (NULL,
…)` style); every insert names an explicit `event_id` taken from
the `metadata.last_event_id` allocator. That matters because
ROWID auto-assignment could be reused after vacuum-and-reload,
and `MAX(rowid)` on an empty table is unhelpful (`NULL`) — an
explicit allocator row in the metadata table is unambiguous and
retention-independent. So the disk layout is ROWID-aliased; the
semantic contract is "EHM assigns, never SQLite."

The "never reused" promise has one explicit failure mode:
**catastrophic loss of the allocator anchor** (DB corrupted *and*
the quarantined `metadata` table unreadable). In that case EHM
refuses to issue new `event_id`s
rather than restart allocation from 1 and silently collide with
prior IDs. Behavior split by `[event_history].required`:

- `required = true` — daemon fails to start with a structured
  error directing the operator to inspect the quarantine and
  decide explicitly.
- `required = false` (default) — EHM continues in pass-through
  mode (broadcasts but does not persist or assign IDs), the
  `bgp_event_outbox_degraded` flag flips, and the durable surface
  reports "outbox disabled" on cursor RPCs. An operator who
  wants to resume durable mode runs an explicit
  `rbgp event-history reset-allocator --starting-id N`
  (P1 follow-up) that records the operator's chosen safe-jump
  value and the rationale in the new DB's metadata. The reset
  command's contract is "I have communicated the cursor break
  to all downstream consumers" — the operator owns the
  consequences.

Pass-through-on-unrecoverable preserves the never-reused promise
for the common case (cursor monotonic forever) and degrades
visibly rather than silently when recovery fails.

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
    peer               TEXT,        -- current peer; denormalized from event_peers
    previous_peer      TEXT,        -- denormalized; query via event_peers
    target_peer        TEXT,        -- denormalized; query via event_peers
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

-- Three-role peer index: lets "find events involving peer X in any role"
-- queries hit a single index lookup instead of an OR over three columns.
-- Populated inside the same transaction as the events insert.
CREATE TABLE event_peers (
    event_id INTEGER NOT NULL,
    role     TEXT    NOT NULL,    -- 'peer' | 'previous_peer' | 'target_peer'
    peer     TEXT    NOT NULL,
    PRIMARY KEY (event_id, role)
);

CREATE INDEX idx_events_category_id   ON events(category, event_id);
CREATE INDEX idx_events_prefix_id     ON events(prefix, event_id)
    WHERE prefix IS NOT NULL;
CREATE INDEX idx_events_rd_id         ON events(rd, event_id)
    WHERE rd IS NOT NULL;
CREATE INDEX idx_events_timestamp     ON events(timestamp_ns);
CREATE INDEX idx_event_peers_peer_id  ON event_peers(peer, event_id);

CREATE TABLE metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
-- Required keys: schema_version, db_format_version, last_boot_id,
--                last_event_id, created_at_unix
```

**Why `event_peers` is a join table, not three indexes on `events`.**
The existing route-history query
(`handle_query_route_event_history` at
`crates/rib/src/manager/mod.rs:1098-1139`) matches the queried peer
against current peer **and** previous peer roles. An OR across
three indexed columns on `events` is planner-hostile (it usually
falls back to a table scan). A join-table with
`(peer, event_id)` indexing turns the lookup into a single seek +
sequential scan, and keeps future peer-role filters (e.g. "only
events where this peer was the `target_peer`") clean.

The `peer` / `previous_peer` / `target_peer` columns are kept on
`events` as **denormalized convenience fields** — once a row has
been fetched, callers read the peer triple without a second
query. The indexed-and-queryable surface is the join table; the
columns are decoded scratch space. Foreign keys stay OFF for
ingest throughput; retention `DELETE` against `events`
explicitly deletes from `event_peers` in the same transaction.

`payload` is **producer-encoded opaque bytes** from EHM's
perspective. The producer is responsible for encoding its own
event shape (eventually the prost-encoded `BgpEvent` envelope;
PR2 accepts any opaque `Vec<u8>` so test fixtures don't need the
proto type). EHM does not decode the payload; it never has to.

**Architectural rationale for opaque payload (PR2 refinement).**
The original draft of this ADR had EHM mutate the in-memory
`BgpEvent`, stamp the `event_id`, and re-encode inside the
storage transaction. That sequence forced a build-time dependency
from `rustbgpd-event-history` onto `rustbgpd-api` (the proto-
source crate), which would create a circular dep when producers
in `rustbgpd-rib` and the PeerManager (in the top-level
`rustbgpd` binary crate) eventually wire up — both already depend
on `rustbgpd-api`. PR2 broke the cycle by making EHM payload-
agnostic: the producer encodes its own event with whatever shape
it wants, hands EHM opaque bytes plus the indexable scalar
fields, and EHM persists + broadcasts those exact bytes. The
`event_id` is delivered to subscribers via the `CommittedEvent`
wrapper struct (which carries the durable id + the unchanged
producer envelope), **not** by mutating the payload bytes. PR4
and PR5 producers can still stamp `event_id` into a structured
field of their own envelope post-commit if they want a self-
describing payload — but that's an upstream-of-EHM concern that
doesn't touch the storage contract.

**Byte-equality invariant.** The bytes the producer hands EHM in
`EventEnvelope.payload` are byte-identical to:

- the `payload` BLOB in the SQLite `events` row, and
- the `payload` field on the `CommittedEvent` delivered to live
  broadcast subscribers.

So a live subscriber and a `SubscribeFromEvent` replay subscriber
observing the same `event_id` see byte-identical payloads. Pinned
by `payload_bytes_identical_persisted_and_broadcast` in
`crates/event-history/tests/byte_equality.rs`. PR3 (the cursor
gRPC surface) and PR4/PR5 (producer wiring) build on this
property — breaking it would silently re-introduce the "history
says one thing, live stream said another" bug class the outbox
exists to prevent.

The bytes persisted to SQLite and the bytes (or struct) handed to
broadcast subscribers are byte-identical, so a live subscriber and
a `SubscribeFromEvent` replay subscriber observing the same
`event_id` see the same envelope. PR2 must pin this with a test
that decodes a persisted payload, re-encodes it, and asserts the
broadcast-side encoded bytes match exactly.

### Hot path — try_send + batched commit

Each producer (`RibManager`, `PeerManager`, and any future producer
such as a dedicated `BfdManager`) reaches EHM through its own
bounded `mpsc::channel(4096)`. EHM's event loop selects across all
producer queues with `tokio::select!`, draining whichever has
ready events, and batches with a size threshold (1024 events) and
a time threshold (50 ms) — whichever fires first. Each batch is
one SQLite transaction (one fsync; **not** one fsync per event).

Expected steady-state cost: 10-100 µs per event on the producer
side (`try_send` only); ~50 ms commit latency on the durable side.
At 10k events/s with batch=1024 → 10 commits/s, each ~150 KB to
WAL. Well within disk budget for the operational-recovery use
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
- Track `bgp_event_outbox_queue_depth{category}` — climbs before
  drops start, gives operators an early-warning signal.
- Emit a `warn!` log for the dropped event with category and event
  type.
- On the first non-zero drop in a process lifetime, flip the
  Prometheus gauge `bgp_event_outbox_degraded = 1`. **In v1 it never
  auto-clears** — operator restarts to
  clear. A future `rbgp event-history reset-health` command
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

The cursor RPC `SubscribeFromEvent(SubscribeFromEventRequest) returns (stream BgpEvent)`
uses a three-step actor-ordered handoff inside EHM, which is the
single actor that owns both the SQLite write side and the live
broadcast sender:

1. **Inside the actor's serialized loop**, register the live
   broadcast receiver first. Because EHM is single-threaded, no
   commit can happen between steps 1 and 3.
2. **Capture the high-watermark** — the last committed `event_id`
   at this instant. Exact, no race.
3. **Spawn a replay task** that drains SQLite for
   `from_event_id < event_id <= high_watermark`, then drains the
   live broadcast receiver for `event_id > high_watermark`. The
   boundary applies a defensive `event_id` dedup as belt-and-
   suspenders. Clients dedup defensively anyway — it's free.

`SubscribeFromEventRequest.from_event_id` is **`optional uint64`**
(proto3 explicit-presence) so that "absent cursor" and "cursor = 0"
are distinguishable on the wire:

- **`from_event_id` absent (presence bit clear)** — live-only
  subscription, no replay. This is the implicit behavior of the
  existing `WatchEvents`, `WatchRoutes`, and `WatchRouteEvents` RPCs
  which never carried a cursor field; their server impls become a
  thin wrapper that calls `SubscribeFromEvent` with the cursor
  absent.
- **`from_event_id = 0` (presence bit set, value 0)** — replay
  every retained event in the outbox from the earliest `event_id`
  onward, then transition to live. This is what a fresh external
  collector calls on first connect when it has no
  `last_seen_event_id` to anchor against.
- **`from_event_id = N` for `N > 0`** — replay
  `event_id > N` then transition to live. The normal collector-
  reconnect case.

Without the explicit-presence disambiguation, `from_event_id = 0`
would conflict with the "live-only existing watch RPC" path — both
serialize to the same wire bytes under proto3 default semantics.
The `optional` keyword (supported in proto3 since 3.15) is the
minimal-cost fix.

The new `SubscribeFromEvent` RPC sits next to (does not replace)
the existing `WatchEvents`, `WatchRoutes`, `WatchRouteEvents`. The
existing watch RPCs route through EHM internally with the cursor
absent.

The RPC baselines EHM's loss generation before delivery; later loss wins replay
or blocked-delivery races and terminates with `DATA_LOSS`. Unlike a retention
gap, pre-commit loss requires authoritative reconciliation before resuming.

### Retention — small, hard-capped, two dimensions

Defaults are **deliberately small** so that when an operator enables
the outbox it keeps local retention pressure bounded (the outbox is
opt-in / default-off as of v0.32.0 — see *Status*):

- `max_events = 100_000` — hard count cap.
- `max_bytes = 256_000_000` (~256 MB) — byte retention trigger
  measured against `events.db` + WAL combined. SQLite DELETE frees
  pages for reuse and does not guarantee the main DB file immediately
  shrinks without a compaction/vacuum step, so this is a soft
  filesystem-size target in v1.

Both retention triggers run. No time-based retention dimension in v1
— operators wanting >hours of history push to their bus, not grow the
local file. Retention runs every 60 s on EHM and
**always evicts in `event_id` ascending order** (oldest first).
SQLite's `DELETE … LIMIT` without an explicit `ORDER BY` is
implementation-defined, so each pass uses the explicit shape:

```sql
DELETE FROM event_peers
  WHERE event_id IN (
    SELECT event_id FROM events ORDER BY event_id ASC LIMIT 5000
  );
DELETE FROM events
  WHERE event_id IN (
    SELECT event_id FROM events ORDER BY event_id ASC LIMIT 5000
  );
PRAGMA wal_checkpoint(PASSIVE);
```

Both `DELETE`s happen inside one transaction so the join table
never lags the main table (foreign keys are off; the cleanup is
explicit by design). Sharded DB files are deferred to a future
ADR if disk size becomes a real problem.

### Config (`src/config/schema.rs`)

```toml
[event_history]
enabled = false                 # default-off (opt-in since v0.32.0); set true for durable replay
required = false                # if true, daemon fails to start when DB unavailable
path = ""                       # relative to runtime_state_dir; "" = events.db
max_events = 100_000            # count retention bound
max_bytes = 256_000_000         # byte retention target (~256 MB)
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

- `enabled = true, required = false`: log a prominent
  `error!`, increment `bgp_event_outbox_open_failures_total`, set
  the `bgp_event_outbox_degraded` health flag, **continue** in pass-
  through mode (broadcasts work, no persistence, cursor RPCs
  return an "outbox disabled" error detail).
- `enabled = true, required = true`: daemon fails to start with
  a structured error. For operators who would rather see refusal-
  to-start than lose audit visibility.
- `enabled = false` (**default since v0.32.0**): outbox path never
  opened; EHM still spawned, but in pass-through mode (broadcasts
  only). The lean default — durable replay is opt-in.

**Corrupted DB on load**: same quarantine pattern as
`fib-owned.json` (`stale_owned_state_path` at
`src/fib_runtime.rs:1140-1142`). Rename to `events.db.stale` —
no timestamp suffix, matching the existing convention so operators
inherit one quarantine idiom across the daemon. The quarantine
file is **not** auto-deleted, and a subsequent corruption would
overwrite the prior quarantine — operators who need to preserve
multiple bad files for forensics rename manually before the next
start. The single-file convention beats a multi-file timestamped
convention here because (a) it matches what operators already
know from `fib-owned.json`, and (b) corruption during a
quarantined-file-still-present state is a rare-enough event that
the manual-rename cost is acceptable.

**Allocator recovery ladder.** Because losing the allocator anchor
silently and restarting at 1 would violate the never-reused
contract, recovery is explicit and uses only authoritative metadata:

1. **Primary**: the open DB's `metadata.last_event_id`. Used
   verbatim when the DB opens cleanly.
2. **Quarantine fallback**: when the DB fails to open and is
   quarantined to `events.db.stale`, EHM best-effort opens the
   quarantined file read-only and reads its
   `metadata.last_event_id`. If recoverable, the fresh DB's
   allocator seeds from that value.
3. **Diagnostic sidecar**: EHM also maintains
   `<runtime_state_dir>/events.last_id` — a tiny file
   (just the allocator value as ASCII, written via the
   `tempfile + rename` atomic pattern at `src/fib_runtime.rs:1159-1161`)
   updated periodically. Because this file can lag committed and
   broadcast events, it is **not** authoritative for allocator
   recovery in v1. It is kept as an operator diagnostic and a future
   reset-tool hint only.

If both authoritative sources are absent and there is no diagnostic
sidecar (no DB, no quarantine, no sidecar — the "truly fresh install"
case), the allocator starts at 1. This is the only path where
event_id=1 is correct, because no prior IDs exist to collide with.

If the primary DB is unreadable AND the quarantine fallback fails
but `<runtime_state_dir>/events.db` did exist at some prior point
(detected by the existence of `events.db.stale` or `events.last_id`
regardless of readability), EHM enters the pass-through + degraded
path described in the Event ID section: refuse to issue new IDs, leave
the operator to resolve explicitly. Restarting at 1 in this state is
**never** automatic.

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

**Orderly shutdown**: one absolute five-second deadline closes producer admission,
aborts retention, and drains the finite accepted queue to `recv() == None` in
`batch_size` chunks. Live sender clones receive `Closed`; they cannot extend the
drain. A submitted append keeps the same future rather than being resubmitted. The
deadline also bounds final sidecar flush, storage shutdown, and the wait for thread
join; non-waiting runtime teardown bounds process exit if that thread stays wedged.

Producer acceptance is one lock-free per-category ledger transition after an mpsc
slot has been reserved. Closing the ledger prevents new acceptance without racing a
sender that already owns a slot. Actor receive transfers ownership out of that
ledger; after the actor terminates, only the manager consumes any accepted handoffs
that never reached the actor and records them as definite `shutdown_timeout` loss.
The producer publishes its proposed queue depth before the admission CAS. Admission
uses acquire-release on success and acquire on failure; manager close uses an
acquire-release RMW. If close wins, the producer publishes a corrective zero and
returns `Closed`; if admission wins, its reserved permit is sent. That order keeps a
late producer from restoring a stale positive gauge after terminal finalization.

Actor-observed queued expiry is also definite `shutdown_timeout` loss. A submitted
append outcome is unknown and latches degradation without being counted as a
definite per-category drop; post-confirmation timeout is finalization only.

### Observability

Prometheus counters and gauges added by this work:

- `bgp_event_outbox_committed_total{category}` — events durably
  committed.
- `bgp_event_outbox_dropped_total{category, reason}` — drops by
  category and reason (`queue_full`, `closed`, `db_error`,
  `shutdown_timeout`, `decode_failure`, `opaque_codec`).
- `bgp_event_outbox_queue_depth{category}` — pending in-memory
  queue per category (gauge).
- `bgp_event_outbox_db_size_bytes` — current
  `events.db` + WAL combined.
- `bgp_event_outbox_retention_evicted_total{reason}` — events
  evicted by retention (`count_cap`, `byte_cap`).
- `bgp_event_outbox_latest_event_id` — gauge of current allocator
  value. "Is the daemon making progress?"
- `bgp_event_outbox_open_failures_total` — DB-open failure counter.
- `bgp_event_outbox_degraded` — 0 or 1; flipped to 1 on
  durability-impacting drops, decode/codec failures, or open
  failures, never auto-clears in v1.
- `bgp_event_outbox_cursor_gap_total` — requests whose cursor was
  older than the retained floor and therefore received a leading
  `StreamLagEvent`.

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
- **No auto-clear for `bgp_event_outbox_degraded`.** The flag stays
  set until restart in v1. A future
  `rbgp event-history reset-health` command is a P1 nice-to-
  have.
- **Dataplane events deferred from the v1 PR5 producer set.**
  *Historical rationale.* PR5 wired five categories through EHM:
  `route`, `evpn`, `session`, `policy`, `bfd`. The `dataplane`
  / `dataplane_route` categories were left on their existing
  `dataplane_events` / `dataplane_route_events` broadcasts
  (consumed by `WatchEvents` and the EVPN service) and were NOT
  enqueued into the durable outbox. `SubscribeFromEvent` with
  an empty `categories` filter therefore returned events from
  the five EHM-fed categories only — operators that wanted full
  durable coverage had to combine the cursor stream with the
  legacy live surfaces. Wiring dataplane through EHM was
  scoped for a follow-up after the v1 producer set had soaked.

  *Resolved by PR #291 (2026-05-27).* Both the
  `spawn_dataplane_poller` summary producer and the
  `spawn_fib_dataplane_event_bridge` per-route producer now
  enqueue into EHM alongside their existing `WatchEvents`
  broadcasts. Both event flavors live under
  `EVENT_CATEGORY_DATAPLANE`, discriminated by `BgpEventType`
  (`DATAPLANE_STATUS_CHANGED` for summaries,
  `DATAPLANE_ROUTE_INSTALLED` / `_WITHDRAWN` / `_FAILED` for
  the per-route stream). The poller is startup-spawned when
  `[event_history].enabled` so durable summaries flow even
  when no `WatchEvents` subscriber is alive. Broadcast lag at
  the FIB and BFD bridges surfaces as
  `bgp_event_outbox_dropped_total{reason="source_lagged"}` +
  `bgp_event_outbox_degraded = 1` so a cursor gap from
  upstream backpressure is observable.
- **Transport-layer policy events (OTC route-leak) deferred from v1.**
  *Historical rationale.* The ADR-0071 (BGP Roles + OTC) deferral
  block already pointed at this work as the home for a structured
  `OtcRouteBlocked` event payload. PR5 wired five categories
  through EHM; the OTC route-leak decision sites in
  `crates/transport/src/session/{inbound,outbound}.rs` still only
  emitted the bounded Prometheus counter and the per-`NeighborState`
  scalar. Operators wanting per-decision incident context
  (`peer`, `direction`, `reason`, `prefixes`, role pair, OTC value,
  AS_PATH) had to correlate the counter with NOTIFICATION and
  UPDATE logs by hand.

  *Resolved by PR #292 (2026-05-27).* A new
  `TransportEventSink` trait (mirroring `RibEventSink`) lets the
  binary plug an EHM-backed sink into `PeerSession`. The four OTC
  decision sites (3 ingress in `inbound.rs`, 1 egress in
  `outbound.rs`) publish a structured `OtcRouteBlockedEvent`
  payload **after** the counter + scalar update, so a sink that
  drops on full queue cannot leave the legacy surfaces
  inconsistent. The new payload rides on
  `EVENT_CATEGORY_POLICY` with the next-free
  `BGP_EVENT_TYPE_OTC_ROUTE_BLOCKED` enum value. AS_PATH is the
  string form (`{…}` notation for AS_SET / confed segments) —
  lossless and matches existing operator-facing renderings — not
  a lossy `repeated uint32`.
- **gNMI `Subscribe ON_CHANGE` deferred from v1.**
  *Historical rationale.* PR5 wired the durable cursor
  (`SubscribeFromEvent`) end-to-end, which gave the daemon a
  path-diffed change source for the first time. The gNMI surface
  (ADR-0070) only supported `STREAM SAMPLE` because the legacy
  broadcasts were lossy and not path-diffed — `ON_CHANGE` needs an
  initial-snapshot + per-leaf delta model that PR5 unblocked.

  *Resolved by PR #293 (2026-05-27).* `GnmiService` accepts
  `Subscribe` with `mode = STREAM` + `subscription.mode = ON_CHANGE`
  for the
  `…/neighbor[neighbor-address=*]/state/session-state` leaf. It
  consumes live FSM transitions via
  `EventHistoryManager::subscribe_live()` (filtered to
  `Category::Session`), decodes each `CommittedEvent`'s
  prost-encoded `BgpEvent` payload, and emits one OpenConfig leaf
  Update per transition. `FailedPrecondition` when EHM is disabled.
  Reconnect = fresh initial snapshot (no replay). A process-local watched loss
  generation advances on every irreversible producer loss, including repeated
  loss after the degraded latch is set. gNMI subscribes before its baseline and
  closes with `DataLoss` on later producer loss or broadcast `Lagged`; recovery
  reconnects without `updates_only` and consumes a full initial snapshot.
  Normal shutdown `Closed` paths do not advance the generation. It is
  service-wide, coalescing, and intentionally not an exact missed-event count.
  The gNMI Subscribe surface stays at the `SensitiveRead` authz tier
  regardless of internal EHM backing — the external contract is
  still gNMI Subscribe. See [ADR-0070](0070-gnmi-openconfig-telemetry.md)
  for the v1 scope contract.
- **`List*Events` RPCs stay on the in-memory rings in v1.**
  `ListRouteEvents` / `ListSessionEvents` / `ListPolicyEvents` /
  `ListEvpnEvents` keep their existing bounded-ring backing
  (resets on daemon restart, process-local `RouteEvent.event_id`
  for routes). Migrating them to EHM-backed queries is a
  follow-up; the v1 split is "legacy live + ring stays legacy;
  durable cursor is `SubscribeFromEvent` only."

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
  via the `bgp_event_outbox_degraded` flag and a small, well-named
  set of Prometheus counters.

### Negative

- New on-disk file (`events.db` + WAL) under `runtime_state_dir`,
  **only when an operator opts in** (`enabled = true`). As of v0.32.0
  the outbox is default-off, so the common deployment has zero on-disk
  footprint. v1 has a hard event-count cap and a byte retention target,
  but SQLite may reuse freed pages rather than shrink the main DB file
  immediately.
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
- `rbgp watch --backfill` is deprecated in favor of
  `--from-event-id`. The `--backfill` flag remains for one
  release as an alias with a deprecation warning, then is
  removed.
