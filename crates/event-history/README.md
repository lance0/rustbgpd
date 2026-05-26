# rustbgpd-event-history

Durable event-history outbox for rustbgpd.

Implements the contract in
[ADR-0072](../../docs/adr/0072-durable-event-history.md): a SQLite
WAL-backed local outbox that survives daemon restart with a monotonic
`event_id` cursor. External collectors (Kafka, NATS, Vector, journald,
custom) bridge to their own bus via the daemon's gRPC stream; this
crate is the daemon-local persistence layer, not an event bus.

Single-writer model. The `EventHistoryManager` actor owns the
broadcast channels currently scattered across producers, batches
inserts into one SQLite transaction, and serves cursor-based replay
through the `SubscribeFromEvent` gRPC RPC.

## Module layout

- `lib.rs` — `EventHistoryManager`, `EventEnvelope`, `OutboxConfig`,
  public actor handle. Async wiring only.
- `storage.rs` — the `spawn_blocking` boundary. Owns the rusqlite
  `Connection` on a dedicated thread; processes batches via an
  internal channel. Only place in the crate that touches
  `rusqlite::Connection`.
- `sequence.rs` — explicit `metadata.last_event_id` allocator and the
  3-step recovery ladder (primary → quarantine → sidecar).
- `migrations.rs` — schema bootstrap + version-fence downgrade refusal
  (mirrors the `GR_RESTART_MARKER_VERSION` pattern in `src/main.rs`).
- `batch.rs` — async-side batching state machine (size + time
  thresholds).
- `retention.rs` — periodic count-cap + byte-cap eviction with
  explicit `ORDER BY event_id ASC` (SQLite `DELETE … LIMIT` is
  otherwise implementation-defined).
- `quarantine.rs` — corrupted-DB detection + `.stale` rename, matching
  the `fib-owned.json` pattern in `src/fib_runtime.rs`.

## Invariants

- **`event_id` is allocated by EHM, never auto-assigned by SQLite.**
  Disk uses `INTEGER PRIMARY KEY` (ROWID-aliased); the semantic
  contract is "EHM picks the value, then INSERTs it explicitly."
- **Encoding order is strict:** assign `event_id` → mutate envelope →
  encode once → insert exact bytes → commit → broadcast same bytes.
  Pinned by the `payload_bytes_identical_persisted_and_broadcast`
  test.
- **No live event without durability**, when enabled and healthy. Pass-
  through degrades visibly via `bgp_event_outbox_degraded`.
- **Allocator recovery ladder**: primary DB → quarantine fallback →
  sidecar. If all three fail and a prior `events.db.stale` exists,
  EHM goes pass-through, never restarts the allocator at 1 silently.
