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
through the `SubscribeFromEvent` gRPC RPC (wired in PR3).

## Module layout

- `lib.rs` — public API. `EventHistoryManager`, `EventHistoryConfig`,
  `EventEnvelope`, `CommittedEvent`, `EventHistorySender`,
  `Category`, `Severity`, `PayloadCodec`, `EnvelopePeers`, plus the
  shared `EhmState` and the async actor loop (`run_actor`). PR3 also
  re-exports `EventSubscription` / `SubscribeFilter` /
  `SubscribeRequest` / `SubscribeStats` from `cursor.rs`.
- `storage.rs` — the `spawn_blocking` boundary. Owns the rusqlite
  `Connection` on a dedicated thread; processes batches via an
  internal channel. Only place in the crate that touches
  `rusqlite::Connection`. Contains the batching + retention SQL paths
  (no separate `batch.rs` / `retention.rs` modules; both are method
  groups on the storage thread for atomic coupling with the
  connection).
- `sequence.rs` — explicit `metadata.last_event_id` allocator and the
  txn-scoped `Allocator::load → next → finalize` lifecycle.
- `migrations.rs` — schema bootstrap + version-fence downgrade
  refusal (mirrors the `GR_RESTART_MARKER_VERSION` pattern in
  `src/main.rs`).
- `quarantine.rs` — corrupted-DB detection + `.stale` rename for
  `events.db`, `events.db-wal`, and `events.db-shm`, plus diagnostic
  sidecar (`events.last_id`) atomic write, matching the
  `fib-owned.json` pattern in `src/fib_runtime.rs`.
- `error.rs` — `EventHistoryError`. Single type covering SQL,
  schema, allocator, I/O, and `PassThrough`.

## Invariants

- **`event_id` is allocated by EHM, never auto-assigned by SQLite.**
  The disk uses `INTEGER PRIMARY KEY` (ROWID-aliased) for storage
  efficiency, but the SEMANTIC contract is that EHM picks the value
  via the explicit `metadata.last_event_id` allocator and then
  INSERTs it. ROWID auto-assignment is never used.
- **Producer-encoded opaque payload.** EHM treats
  `EventEnvelope.payload` as opaque bytes. The producer is
  responsible for whatever encoding it wants (eventually the
  prost-encoded `BgpEvent`; PR2 accepts any `Vec<u8>`). The assigned
  `event_id` is delivered to subscribers via the `CommittedEvent`
  wrapper — never by mutating the payload bytes.
- **Byte-equality across persist + broadcast.** The bytes the
  producer hands EHM equal the SQLite `payload` BLOB AND the
  `CommittedEvent.envelope.payload` field on the broadcast.
  Pinned by `payload_bytes_identical_persisted_and_broadcast` in
  `tests/byte_equality.rs`.
- **No live event without durability (when enabled and healthy).**
  EHM commits a batch BEFORE broadcasting; live subscribers and
  cursor-replay subscribers observing the same `event_id` see the
  same envelope.
- **Allocator recovery ladder.** Primary DB → quarantine fallback.
  `events.last_id` is a diagnostic hint only in v1 because it can lag
  committed events. If both authoritative sources fail AND prior
  allocation evidence exists (`events.db.stale` or `events.last_id`),
  EHM refuses to issue new IDs
  (PassThrough), never restarts the allocator at 1 silently. The
  stale-only-state check happens
  BEFORE any create-capable `Connection::open` to prevent a fresh
  empty DB from masking a quarantined state.
