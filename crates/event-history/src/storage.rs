//! The `spawn_blocking` boundary (ADR-0072).
//!
//! Async EHM never touches a [`rusqlite::Connection`] directly. Instead,
//! the storage layer owns a dedicated OS thread that holds the
//! `Connection` and processes [`StoreOp`] messages from an mpsc
//! channel, replying via oneshot. One thread, one connection, one
//! writer — no SQLite multi-writer locking, no async-context blocking.
//!
//! The async side gets a [`StoreHandle`] — a thin wrapper that pushes
//! ops into the channel and `await`s the reply. The actor loop in
//! [`crate::lib`] holds the only [`StoreHandle`]; broadcast subscribers
//! never call into storage.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

// Re-export for cursor.rs / lib.rs — they hand Arc<EventEnvelope> to
// append so payload bytes aren't cloned a second time on the
// broadcast side.

use rusqlite::{Connection, params, types::Type};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::error::EventHistoryError;
use crate::migrations::{CURRENT_SCHEMA_VERSION, META_LAST_BOOT_ID, META_LAST_EVENT_ID, bootstrap};
use crate::quarantine::{
    quarantine_db, read_quarantine_allocator, read_sidecar, sidecar_path, stale_path, write_sidecar,
};
use crate::sequence::Allocator;
use crate::{Category, EventEnvelope, Severity, SynchronousMode};

/// Operations the async side can send to the blocking storage thread.
pub(crate) enum StoreOp {
    /// Persist a batch of envelopes inside one SQLite transaction.
    ///
    /// Envelopes are passed as `Arc`s so the actor can hand the SAME
    /// underlying payload bytes to both the storage path (here) and
    /// the broadcast path (after commit) without cloning the payload
    /// vec a second time. The earlier design cloned the full
    /// `Vec<EventEnvelope>` (including payload bytes) twice, doubling
    /// allocation per batch.
    ///
    /// Reply carries:
    /// - the assigned `(event_id, ...)` tuples in order (same order as
    ///   the input `envelopes`)
    /// - the new high-water mark (`metadata.last_event_id` post-commit)
    /// - the daemon boot ID stamped on each row
    Append {
        envelopes: Vec<Arc<EventEnvelope>>,
        reply: oneshot::Sender<Result<AppendOutcome, EventHistoryError>>,
    },

    /// Read events with `from_event_id < event_id <= to_event_id`,
    /// limited to `limit` rows, optionally filtered by category /
    /// peer / prefix / rd. Returns persisted rows in `event_id` ascending
    /// order. `SubscribeFromEvent` uses this for replay; tests call it
    /// directly.
    Query {
        from_event_id: u64,
        to_event_id: u64,
        limit: usize,
        filter: QueryFilter,
        reply: oneshot::Sender<Result<Vec<PersistedEvent>, EventHistoryError>>,
    },

    /// Same as `Query` but additionally returns the live `MIN(event_id)`
    /// over the events table, evaluated under the SAME storage-thread
    /// iteration that runs the row read. The cursor handler uses this
    /// op for the FIRST replay chunk of a `SubscribeFromEvent` request
    /// to compute the retention-gap signal race-free against retention
    /// — submitting `OldestEventId` then `Query` as two ops lets
    /// retention be processed in between, which is the race ADR-0072
    /// PR5 review flagged.
    QueryWithFloor {
        from_event_id: u64,
        to_event_id: u64,
        limit: usize,
        filter: QueryFilter,
        reply: oneshot::Sender<Result<QueryWithFloorOutcome, EventHistoryError>>,
    },

    /// Run one pass of retention. Caller cadence is the EHM loop's
    /// interval timer.
    Retain {
        max_events: u64,
        max_bytes: u64,
        reply: oneshot::Sender<Result<RetentionOutcome, EventHistoryError>>,
    },

    /// Flush the sidecar to the current allocator value.
    FlushSidecar {
        reply: oneshot::Sender<Result<u64, EventHistoryError>>,
    },

    /// Return `MIN(event_id)` over the live `events` table, or `None`
    /// when the table is empty. Used by the cursor handler to
    /// detect "client cursor older than retention floor" before
    /// kicking off the actor-ordered handoff. Resolved live against
    /// the connection thread so retention races don't surface as
    /// stale gap counts.
    OldestEventId {
        reply: oneshot::Sender<Result<Option<u64>, EventHistoryError>>,
    },

    /// Graceful shutdown — drain anything pending, checkpoint WAL, close.
    Shutdown { reply: oneshot::Sender<()> },
}

/// What `StoreOp::Append` returns to the caller.
#[derive(Debug)]
pub(crate) struct AppendOutcome {
    /// Assigned event IDs, in the same order as the input envelopes.
    pub assigned_ids: Vec<u64>,
    /// `metadata.last_event_id` after the commit.
    pub new_high_water: u64,
    /// Daemon boot ID stamped on every row in this batch.
    pub daemon_boot_id: Arc<str>,
    /// Combined size of events.db + WAL immediately after the commit.
    pub db_size_bytes: u64,
}

/// What `StoreOp::QueryWithFloor` returns. The floor reflects the
/// live `MIN(event_id)` as of the same storage-thread iteration that
/// ran the row read, so the cursor handler can compute the gap to a
/// client-supplied `from_event_id` without a separate
/// `OldestEventId` round-trip that retention could slip between.
#[derive(Debug)]
pub(crate) struct QueryWithFloorOutcome {
    pub rows: Vec<PersistedEvent>,
    pub floor: Option<u64>,
}

/// What `StoreOp::Retain` returns.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RetentionOutcome {
    pub evicted_count_cap: usize,
    pub evicted_byte_cap: usize,
    pub db_size_bytes: u64,
}

/// Filter for persisted-event queries. Each field is optional; `None`
/// means "any." Public so the cursor API and tests can construct one;
/// the storage-thread internals are still private.
#[derive(Debug, Default, Clone)]
pub struct QueryFilter {
    pub category: Option<Category>,
    pub peer: Option<String>,
    pub prefix: Option<String>,
    pub rd: Option<String>,
}

/// One row read back from `events`. Mirrors `EventEnvelope` shape plus
/// the assigned `event_id`. The payload is byte-identical to what the
/// producer originally provided (byte-equality invariant). The
/// `payload_codec` round-trips the producer's encoding declaration so
/// replay consumers know how to interpret `payload` (e.g., `"opaque"`
/// vs `"proto"` for prost-encoded `BgpEvent` envelopes).
#[derive(Debug, Clone)]
pub struct PersistedEvent {
    pub event_id: u64,
    pub timestamp_ns: i64,
    pub category: Category,
    pub event_type: String,
    pub peer: Option<String>,
    pub previous_peer: Option<String>,
    pub target_peer: Option<String>,
    pub afi_safi: Option<String>,
    pub prefix: Option<String>,
    pub rd: Option<String>,
    pub evpn_route_type: Option<i32>,
    pub severity: Severity,
    pub daemon_boot_id: String,
    /// String form of `PayloadCodec` as stored in SQLite — `"opaque"`
    /// or `"proto"`. Use [`crate::PayloadCodec::parse`] to map back.
    pub payload_codec: String,
    pub payload: Vec<u8>,
}

/// Async-side handle for talking to the blocking storage thread.
///
/// `Clone`-able so multiple parts of EHM can hold the handle, but in
/// practice only the EHM actor loop sends `StoreOp` messages.
#[derive(Debug, Clone)]
pub(crate) struct StoreHandle {
    tx: mpsc::Sender<StoreOp>,
}

impl StoreHandle {
    pub(crate) async fn append(
        &self,
        envelopes: Vec<Arc<EventEnvelope>>,
    ) -> Result<AppendOutcome, EventHistoryError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(StoreOp::Append { envelopes, reply })
            .await
            .map_err(|_| EventHistoryError::PassThrough)?;
        rx.await.map_err(|_| EventHistoryError::PassThrough)?
    }

    pub(crate) async fn query(
        &self,
        from_event_id: u64,
        to_event_id: u64,
        limit: usize,
        filter: QueryFilter,
    ) -> Result<Vec<PersistedEvent>, EventHistoryError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(StoreOp::Query {
                from_event_id,
                to_event_id,
                limit,
                filter,
                reply,
            })
            .await
            .map_err(|_| EventHistoryError::PassThrough)?;
        rx.await.map_err(|_| EventHistoryError::PassThrough)?
    }

    /// `Query` plus the live `MIN(event_id)` evaluated under the same
    /// storage-thread iteration. The cursor handler uses this for the
    /// first replay chunk so the retention-gap signal it emits is
    /// race-free against a retention pass that fires between separate
    /// `OldestEventId` and `Query` calls.
    pub(crate) async fn query_with_floor(
        &self,
        from_event_id: u64,
        to_event_id: u64,
        limit: usize,
        filter: QueryFilter,
    ) -> Result<QueryWithFloorOutcome, EventHistoryError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(StoreOp::QueryWithFloor {
                from_event_id,
                to_event_id,
                limit,
                filter,
                reply,
            })
            .await
            .map_err(|_| EventHistoryError::PassThrough)?;
        rx.await.map_err(|_| EventHistoryError::PassThrough)?
    }

    pub(crate) async fn retain(
        &self,
        max_events: u64,
        max_bytes: u64,
    ) -> Result<RetentionOutcome, EventHistoryError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(StoreOp::Retain {
                max_events,
                max_bytes,
                reply,
            })
            .await
            .map_err(|_| EventHistoryError::PassThrough)?;
        rx.await.map_err(|_| EventHistoryError::PassThrough)?
    }

    pub(crate) async fn flush_sidecar(&self) -> Result<u64, EventHistoryError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(StoreOp::FlushSidecar { reply })
            .await
            .map_err(|_| EventHistoryError::PassThrough)?;
        rx.await.map_err(|_| EventHistoryError::PassThrough)?
    }

    /// `MIN(event_id)` over the live table, or `None` when the table
    /// is empty. Resolves a live query rather than reading a cached
    /// atomic so retention races don't surface as stale gap counts.
    pub(crate) async fn oldest_event_id(&self) -> Result<Option<u64>, EventHistoryError> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(StoreOp::OldestEventId { reply })
            .await
            .map_err(|_| EventHistoryError::PassThrough)?;
        rx.await.map_err(|_| EventHistoryError::PassThrough)?
    }

    pub(crate) async fn shutdown(&self) {
        let (reply, rx) = oneshot::channel();
        if self.tx.send(StoreOp::Shutdown { reply }).await.is_ok() {
            let _ = rx.await;
        }
    }
}

/// Spawn the blocking storage thread on the current tokio runtime.
///
/// `path` is the events DB. If opening fails (corruption, permission
/// denied, schema downgrade), quarantines and reopens fresh — caller
/// learns which path was taken via [`StorageInit::had_quarantine`].
///
/// The returned `JoinHandle` resolves when the storage thread exits
/// (after a `StoreOp::Shutdown` or unrecoverable error).
pub(crate) fn spawn_store(
    path: PathBuf,
    daemon_boot_id: Arc<str>,
    synchronous: SynchronousMode,
    capacity: usize,
) -> Result<(StoreHandle, JoinHandle<()>, StorageInit), EventHistoryError> {
    let init = open_with_recovery(&path, synchronous)?;
    let (tx, rx) = mpsc::channel(capacity);
    let path_clone = path.clone();
    let boot_id_clone = daemon_boot_id.clone();
    let initial_allocator = init.initial_allocator;
    let join = tokio::task::spawn_blocking(move || {
        run_storage_thread(
            path_clone,
            boot_id_clone,
            initial_allocator,
            synchronous,
            rx,
        );
    });
    Ok((StoreHandle { tx }, join, init))
}

/// Snapshot of how `open_with_recovery` resolved the DB state. Used by
/// the EHM actor to decide whether to flip the degraded flag.
#[derive(Debug)]
pub(crate) struct StorageInit {
    /// True if the existing DB was unopenable and got renamed to
    /// `.stale`. The replacement DB is fresh.
    pub had_quarantine: bool,
    /// The allocator value loaded from the live DB (after any
    /// quarantine + recovery). For a brand-new DB this is 0.
    pub initial_allocator: u64,
    /// True if the allocator was seeded from the quarantine fallback
    /// rather than the primary DB.
    pub recovered_via_fallback: bool,
}

/// Open the events DB at `path`, applying the recovery ladder (primary
/// → quarantine). On success, returns the in-memory snapshot of how
/// recovery resolved. On failure, returns an error.
///
/// Implementation notes:
/// - We open the DB twice in the success path (first to probe, second
///   inside the blocking thread). The probe is cheap; doing it on the
///   async side keeps the error path off the blocking thread.
/// - If the primary fails to open, we attempt quarantine metadata before
///   creating a fresh DB. The sidecar is a diagnostic hint only because
///   it can lag committed events.
fn open_with_recovery(
    path: &Path,
    synchronous: SynchronousMode,
) -> Result<StorageInit, EventHistoryError> {
    // Ensure parent dir exists. Matches the create_dir_all pattern in
    // src/fib_runtime.rs:1157.
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|source| EventHistoryError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }

    let sidecar = sidecar_path(path);
    let stale = stale_path(path);

    // STALE/SIDECAR-ONLY GUARD: when a previous start
    // quarantined `events.db` and the daemon exited before producing a
    // replacement, the next start would see no primary file. The plain
    // `Connection::open(path)` below WOULD CREATE a fresh empty DB and
    // `bootstrap` would seed `last_event_id = 0` — silently violating
    // the never-reused contract because prior IDs were already issued
    // (proven by the stale file's existence). A sidecar without a DB is
    // also evidence of prior allocation; because the sidecar is only a
    // diagnostic hint, we refuse instead of using it as authority.
    //
    // Detect this state up front and run the recovery ladder BEFORE
    // any create-capable open. If the ladder can't recover an anchor,
    // surface `PassThrough` instead of restarting at 1.
    if !path.exists() && (stale.exists() || sidecar.exists()) {
        warn!(
            events_db = %path.display(),
            stale = %stale.display(),
            sidecar = %sidecar.display(),
            "primary DB missing but prior allocator evidence exists; entering recovery ladder before create"
        );
        return recover_after_quarantine(path, &stale, &sidecar, synchronous);
    }

    // Try the primary path.
    match probe_open(path, synchronous) {
        Ok(allocator) => Ok(StorageInit {
            had_quarantine: false,
            initial_allocator: allocator,
            recovered_via_fallback: false,
        }),
        Err(primary_err) => {
            warn!(
                events_db = %path.display(),
                error = %primary_err,
                "primary DB open failed; entering recovery ladder"
            );
            // Quarantine the broken file, then enter the recovery
            // ladder. `quarantine_db` no-ops if path doesn't exist
            // (covers the case where probe_open failed without
            // creating a file).
            quarantine_db(path)?;
            recover_after_quarantine(path, &stale, &sidecar, synchronous)
        }
    }
}

/// Allocator-recovery ladder, applied AFTER a quarantine (whether the
/// quarantine just happened or was left over from a prior process).
/// Reads from the quarantine; if it fails AND a stale file or sidecar
/// exists, returns [`EventHistoryError::PassThrough`] rather than
/// seeding a fresh DB with `last_event_id = 0`. The sidecar is ignored
/// for allocator authority because it can lag committed events.
///
/// Only creates the new primary DB when there IS a recoverable anchor
/// (or when no stale file is present, i.e. truly fresh install).
fn recover_after_quarantine(
    path: &Path,
    stale: &Path,
    sidecar: &Path,
    synchronous: SynchronousMode,
) -> Result<StorageInit, EventHistoryError> {
    let quarantine_anchor = read_quarantine_allocator(stale);
    let sidecar_hint = read_sidecar(sidecar);

    let fresh_anchor = match quarantine_anchor {
        Some(v) => v,
        None => {
            // No authoritative anchor recoverable. If a stale file or
            // sidecar exists, we KNOW prior IDs may have been issued —
            // refusing here protects the never-reused promise. Caller
            // decides what to do (required=true ⇒ fail-start,
            // required=false ⇒ pass-through with degraded flag — see
            // EventHistoryManager).
            if stale.exists() || sidecar.exists() {
                if let Some(sidecar_value) = sidecar_hint {
                    warn!(
                        sidecar_value,
                        "ignoring sidecar allocator hint because it may lag committed events"
                    );
                }
                return Err(EventHistoryError::PassThrough);
            }
            // Truly fresh install — no stale, no sidecar, no DB.
            // Allocator starts at 0.
            0
        }
    };

    // Open (or create) the primary DB and seed its allocator to the
    // recovered anchor.
    let mut conn = Connection::open(path).map_err(EventHistoryError::Sqlite)?;
    bootstrap(&mut conn, synchronous)?;
    conn.execute(
        "UPDATE metadata SET value = ?1 WHERE key = ?2",
        params![fresh_anchor.to_string(), META_LAST_EVENT_ID],
    )?;

    Ok(StorageInit {
        had_quarantine: true,
        initial_allocator: fresh_anchor,
        recovered_via_fallback: quarantine_anchor.is_some(),
    })
}

/// Open + bootstrap + read allocator. Used by [`open_with_recovery`] to
/// probe whether the DB is usable.
///
/// **Note**: this WILL create the file if it doesn't exist (SQLite
/// default `Connection::open`). [`open_with_recovery`] is responsible
/// for the stale-only-state guard that prevents an unexpected create
/// from masking a quarantined state. Callers outside `open_with_recovery`
/// must enforce that guard themselves.
fn probe_open(path: &Path, synchronous: SynchronousMode) -> Result<u64, EventHistoryError> {
    let mut conn = Connection::open(path).map_err(EventHistoryError::Sqlite)?;
    bootstrap(&mut conn, synchronous)?;
    crate::sequence::read_allocator(&conn)?
        .ok_or_else(|| EventHistoryError::AllocatorCorrupt("missing post-bootstrap".to_string()))
}

/// The dedicated storage thread loop. Runs on a `spawn_blocking` task.
fn run_storage_thread(
    path: PathBuf,
    daemon_boot_id: Arc<str>,
    initial_allocator: u64,
    synchronous: SynchronousMode,
    mut rx: mpsc::Receiver<StoreOp>,
) {
    let mut conn = match Connection::open(&path) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "storage thread failed to open DB; exiting");
            return;
        }
    };
    if let Err(e) = bootstrap(&mut conn, synchronous) {
        error!(error = %e, "storage thread bootstrap failed; exiting");
        return;
    }

    // Stamp daemon_boot_id (best-effort — failure shouldn't kill the
    // thread, but log it).
    if let Err(e) = conn.execute(
        "INSERT INTO metadata (key, value) VALUES (?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![META_LAST_BOOT_ID, daemon_boot_id.as_ref()],
    ) {
        warn!(error = %e, "failed to stamp daemon_boot_id; continuing");
    }

    info!(
        events_db = %path.display(),
        daemon_boot_id = %daemon_boot_id.as_ref(),
        initial_allocator,
        schema_version = CURRENT_SCHEMA_VERSION,
        "event history storage thread started"
    );

    let sidecar = sidecar_path(&path);

    while let Some(op) = rx.blocking_recv() {
        match op {
            StoreOp::Append { envelopes, reply } => {
                let outcome = append_batch_blocking(&mut conn, &path, envelopes, &daemon_boot_id);
                let _ = reply.send(outcome);
            }
            StoreOp::Query {
                from_event_id,
                to_event_id,
                limit,
                filter,
                reply,
            } => {
                let outcome = query_blocking(&conn, from_event_id, to_event_id, limit, &filter);
                let _ = reply.send(outcome);
            }
            StoreOp::QueryWithFloor {
                from_event_id,
                to_event_id,
                limit,
                filter,
                reply,
            } => {
                // Read MIN(event_id) and the row chunk in one storage-
                // thread iteration. The single-threaded run loop
                // serializes us against StoreOp::Retain, which is the
                // only op that can move the floor. Submitting these
                // two SELECTs as separate StoreOps would let a Retain
                // message interleave between them; that's the race
                // ADR-0072 PR5 review flagged.
                let outcome = oldest_event_id_blocking(&conn).and_then(|floor| {
                    query_blocking(&conn, from_event_id, to_event_id, limit, &filter)
                        .map(|rows| QueryWithFloorOutcome { rows, floor })
                });
                let _ = reply.send(outcome);
            }
            StoreOp::Retain {
                max_events,
                max_bytes,
                reply,
            } => {
                let outcome = retain_blocking(&mut conn, &path, max_events, max_bytes);
                let _ = reply.send(outcome);
            }
            StoreOp::FlushSidecar { reply } => {
                let outcome = flush_sidecar_blocking(&conn, &sidecar);
                let _ = reply.send(outcome);
            }
            StoreOp::OldestEventId { reply } => {
                let outcome = oldest_event_id_blocking(&conn);
                let _ = reply.send(outcome);
            }
            StoreOp::Shutdown { reply } => {
                // Best-effort final checkpoint, then exit.
                if let Err(e) = conn.pragma_update(None, "wal_checkpoint", "TRUNCATE".to_string()) {
                    warn!(error = %e, "shutdown WAL checkpoint failed");
                }
                if let Err(e) = flush_sidecar_blocking(&conn, &sidecar) {
                    warn!(error = %e, "shutdown sidecar flush failed");
                }
                let _ = reply.send(());
                break;
            }
        }
    }

    info!("event history storage thread exited");
}

fn append_batch_blocking(
    conn: &mut Connection,
    db_path: &Path,
    envelopes: Vec<Arc<EventEnvelope>>,
    daemon_boot_id: &Arc<str>,
) -> Result<AppendOutcome, EventHistoryError> {
    if envelopes.is_empty() {
        return Ok(AppendOutcome {
            assigned_ids: Vec::new(),
            new_high_water: crate::sequence::read_allocator(conn)?.unwrap_or(0),
            daemon_boot_id: daemon_boot_id.clone(),
            db_size_bytes: file_size(db_path),
        });
    }

    let txn = conn.transaction()?;
    let mut allocator = Allocator::load(&txn)?;
    let mut assigned_ids = Vec::with_capacity(envelopes.len());

    {
        let mut insert_event = txn.prepare(
            "INSERT INTO events (
                event_id, timestamp_ns, category, event_type,
                peer, previous_peer, target_peer,
                afi_safi, prefix, rd, evpn_route_type,
                severity, schema_version, daemon_boot_id,
                payload_codec, payload
             ) VALUES (
                ?1, ?2, ?3, ?4,
                ?5, ?6, ?7,
                ?8, ?9, ?10, ?11,
                ?12, ?13, ?14,
                ?15, ?16
             )",
        )?;
        let mut insert_peer =
            txn.prepare("INSERT INTO event_peers (event_id, role, peer) VALUES (?1, ?2, ?3)")?;

        for env in &envelopes {
            let id = allocator.next()?;
            assigned_ids.push(id);
            // SQLite INTEGER is signed 64-bit; bind the event_id as i64 because
            // rusqlite 0.40 dropped the `u64` `ToSql` impl. `clamp_event_id` is a
            // no-op for any real allocated id — it only caps the u64::MAX query
            // sentinel — and is the same conversion the read/query paths use.
            let id_sql = clamp_event_id(id);

            insert_event.execute(params![
                id_sql,
                env.timestamp_ns,
                env.category.as_str(),
                &env.event_type,
                env.peers.peer.as_ref().map(ToString::to_string),
                env.peers.previous_peer.as_ref().map(ToString::to_string),
                env.peers.target_peer.as_ref().map(ToString::to_string),
                &env.afi_safi,
                &env.prefix,
                &env.rd,
                env.evpn_route_type,
                env.severity.as_str(),
                CURRENT_SCHEMA_VERSION,
                daemon_boot_id.as_ref(),
                env.payload_codec.as_str(),
                &env.payload,
            ])?;

            if let Some(p) = &env.peers.peer {
                insert_peer.execute(params![id_sql, "peer", p.to_string()])?;
            }
            if let Some(p) = &env.peers.previous_peer {
                insert_peer.execute(params![id_sql, "previous_peer", p.to_string()])?;
            }
            if let Some(p) = &env.peers.target_peer {
                insert_peer.execute(params![id_sql, "target_peer", p.to_string()])?;
            }
        }
    }

    let new_high_water = allocator.finalize(&txn)?;
    txn.commit()?;

    Ok(AppendOutcome {
        assigned_ids,
        new_high_water,
        daemon_boot_id: daemon_boot_id.clone(),
        db_size_bytes: file_size(db_path),
    })
}

fn query_blocking(
    conn: &Connection,
    from_event_id: u64,
    to_event_id: u64,
    limit: usize,
    filter: &QueryFilter,
) -> Result<Vec<PersistedEvent>, EventHistoryError> {
    // Peer filter is special — uses the event_peers join table for
    // "any-role" matching.
    if let Some(peer) = &filter.peer {
        return query_by_peer(conn, from_event_id, to_event_id, limit, peer, filter);
    }
    query_no_peer(conn, from_event_id, to_event_id, limit, filter)
}

fn query_by_peer(
    conn: &Connection,
    from_event_id: u64,
    to_event_id: u64,
    limit: usize,
    peer: &str,
    filter: &QueryFilter,
) -> Result<Vec<PersistedEvent>, EventHistoryError> {
    let mut sql = String::from(
        "SELECT e.event_id, e.timestamp_ns, e.category, e.event_type,
                e.peer, e.previous_peer, e.target_peer,
                e.afi_safi, e.prefix, e.rd, e.evpn_route_type,
                e.severity, e.daemon_boot_id, e.payload_codec, e.payload
         FROM events e
         WHERE EXISTS (
               SELECT 1 FROM event_peers ep
               WHERE ep.event_id = e.event_id AND ep.peer = ?1
         )
           AND e.event_id > ?2
           AND e.event_id <= ?3",
    );
    let category_str = filter.category.map(|c| c.as_str().to_string());
    if category_str.is_some() {
        sql.push_str(" AND e.category = ?4");
    }
    if filter.prefix.is_some() {
        let p = if category_str.is_some() { "?5" } else { "?4" };
        sql.push_str(&format!(" AND e.prefix = {p}"));
    }
    if filter.rd.is_some() {
        let extras = usize::from(category_str.is_some()) + usize::from(filter.prefix.is_some());
        let p = format!("?{}", 4 + extras);
        sql.push_str(&format!(" AND e.rd = {p}"));
    }
    sql.push_str(" ORDER BY e.event_id ASC LIMIT ");
    sql.push_str(&limit.to_string());

    let mut stmt = conn.prepare(&sql)?;
    // SQLite's INTEGER column is signed 64-bit; bind event_ids as i64.
    // event_id > i64::MAX is unreachable in practice (10k events/s ≈
    // 29 million years to wrap), but cap explicitly so the bind doesn't
    // ToSql-fail on u64::MAX sentinel from query callers.
    let to_event_id_i64 = clamp_event_id(to_event_id);
    let from_event_id_i64 = clamp_event_id(from_event_id);
    let mut bind: Vec<Box<dyn rusqlite::ToSql>> = vec![
        Box::new(peer.to_string()),
        Box::new(from_event_id_i64),
        Box::new(to_event_id_i64),
    ];
    if let Some(c) = category_str {
        bind.push(Box::new(c));
    }
    if let Some(p) = &filter.prefix {
        bind.push(Box::new(p.clone()));
    }
    if let Some(r) = &filter.rd {
        bind.push(Box::new(r.clone()));
    }
    let bind_refs: Vec<&dyn rusqlite::ToSql> = bind.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(rusqlite::params_from_iter(bind_refs), persisted_row_mapper)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

fn query_no_peer(
    conn: &Connection,
    from_event_id: u64,
    to_event_id: u64,
    limit: usize,
    filter: &QueryFilter,
) -> Result<Vec<PersistedEvent>, EventHistoryError> {
    let mut sql = String::from(
        "SELECT event_id, timestamp_ns, category, event_type,
                peer, previous_peer, target_peer,
                afi_safi, prefix, rd, evpn_route_type,
                severity, daemon_boot_id, payload_codec, payload
         FROM events
         WHERE event_id > ?1 AND event_id <= ?2",
    );
    if filter.category.is_some() {
        sql.push_str(" AND category = ?3");
    }
    if filter.prefix.is_some() {
        let p = if filter.category.is_some() {
            "?4"
        } else {
            "?3"
        };
        sql.push_str(&format!(" AND prefix = {p}"));
    }
    if filter.rd.is_some() {
        let extras = usize::from(filter.category.is_some()) + usize::from(filter.prefix.is_some());
        let p = format!("?{}", 3 + extras);
        sql.push_str(&format!(" AND rd = {p}"));
    }
    sql.push_str(" ORDER BY event_id ASC LIMIT ");
    sql.push_str(&limit.to_string());

    let mut stmt = conn.prepare(&sql)?;
    let from_event_id_i64 = clamp_event_id(from_event_id);
    let to_event_id_i64 = clamp_event_id(to_event_id);
    let mut bind: Vec<Box<dyn rusqlite::ToSql>> =
        vec![Box::new(from_event_id_i64), Box::new(to_event_id_i64)];
    if let Some(c) = filter.category {
        bind.push(Box::new(c.as_str().to_string()));
    }
    if let Some(p) = &filter.prefix {
        bind.push(Box::new(p.clone()));
    }
    if let Some(r) = &filter.rd {
        bind.push(Box::new(r.clone()));
    }
    let bind_refs: Vec<&dyn rusqlite::ToSql> = bind.iter().map(|b| b.as_ref()).collect();
    let rows = stmt.query_map(rusqlite::params_from_iter(bind_refs), persisted_row_mapper)?;
    rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
}

/// SQLite's INTEGER column is signed 64-bit; we clamp at i64::MAX so
/// a `u64::MAX` sentinel from query callers (e.g. "from_event_id=0,
/// to_event_id=u64::MAX" for "all events") doesn't trip a ToSql
/// conversion failure.
fn clamp_event_id(value: u64) -> i64 {
    if value > i64::MAX as u64 {
        i64::MAX
    } else {
        value as i64
    }
}

fn persisted_row_mapper(row: &rusqlite::Row<'_>) -> rusqlite::Result<PersistedEvent> {
    let category_raw: String = row.get(2)?;
    let severity_raw: String = row.get(11)?;
    let category = Category::parse(&category_raw)
        .ok_or_else(|| invalid_enum_error(2, "category", &category_raw))?;
    let severity = Severity::parse(&severity_raw)
        .ok_or_else(|| invalid_enum_error(11, "severity", &severity_raw))?;
    Ok(PersistedEvent {
        event_id: row.get::<_, i64>(0)? as u64,
        timestamp_ns: row.get(1)?,
        category,
        event_type: row.get(3)?,
        peer: row.get(4)?,
        previous_peer: row.get(5)?,
        target_peer: row.get(6)?,
        afi_safi: row.get(7)?,
        prefix: row.get(8)?,
        rd: row.get(9)?,
        evpn_route_type: row.get(10)?,
        severity,
        daemon_boot_id: row.get(12)?,
        payload_codec: row.get(13)?,
        payload: row.get(14)?,
    })
}

fn invalid_enum_error(column: usize, name: &'static str, value: &str) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(
        column,
        Type::Text,
        Box::new(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid event-history {name}: {value:?}"),
        )),
    )
}

fn retain_blocking(
    conn: &mut Connection,
    db_path: &Path,
    max_events: u64,
    max_bytes: u64,
) -> Result<RetentionOutcome, EventHistoryError> {
    let mut outcome = RetentionOutcome::default();

    // 1. Count cap.
    let total: u64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| {
            row.get::<_, i64>(0)
        })?
        .max(0) as u64;
    if total > max_events {
        let to_evict = (total - max_events).min(5000);
        outcome.evicted_count_cap = evict_oldest(conn, to_evict as usize)?;
    }

    // 2. Byte retention target. DELETE frees pages for SQLite reuse but
    //    does not guarantee the main DB file immediately shrinks. Loop
    //    because one DELETE LIMIT pass may not reduce row pressure enough
    //    on a heavily-overweight DB; cap at 10 passes per retention call
    //    to bound worst-case work.
    for _ in 0..10 {
        let size = file_size(db_path);
        outcome.db_size_bytes = size;
        if size <= max_bytes {
            break;
        }
        let evicted = evict_oldest(conn, 5000)?;
        outcome.evicted_byte_cap += evicted;
        if evicted == 0 {
            // Nothing more to delete; stop the loop even if file is
            // still oversized (WAL growth dominates the size on small
            // DBs and gets reclaimed by the checkpoint below).
            break;
        }
    }

    // Checkpoint WAL pages back to the main file. Without this, the
    // file size may not shrink visibly after DELETE.
    conn.pragma_update(None, "wal_checkpoint", "PASSIVE".to_string())?;

    outcome.db_size_bytes = file_size(db_path);
    Ok(outcome)
}

fn evict_oldest(conn: &mut Connection, limit: usize) -> Result<usize, EventHistoryError> {
    if limit == 0 {
        return Ok(0);
    }
    let txn = conn.transaction()?;
    // Delete from event_peers first (foreign keys are off; we own the
    // referential integrity).
    txn.execute(
        "DELETE FROM event_peers
         WHERE event_id IN (
             SELECT event_id FROM events ORDER BY event_id ASC LIMIT ?1
         )",
        params![limit as i64],
    )?;
    let deleted = txn.execute(
        "DELETE FROM events
         WHERE event_id IN (
             SELECT event_id FROM events ORDER BY event_id ASC LIMIT ?1
         )",
        params![limit as i64],
    )?;
    txn.commit()?;
    Ok(deleted)
}

/// SQLite WAL filenames are formed by appending `"-wal"` to the
/// **full** DB filename, NOT by replacing the extension. So
/// `events.db` → `events.db-wal` (not `events.db.db-wal` or
/// `events.db-wal-wal`) and `events` (no extension) → `events-wal`.
/// `path.with_extension(...)` REPLACES the extension, which gets it
/// wrong in the no-extension case. Concatenate to the OsString
/// directly instead.
fn file_size(path: &Path) -> u64 {
    let main = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    let mut wal_os = path.as_os_str().to_os_string();
    wal_os.push("-wal");
    let wal = std::path::PathBuf::from(wal_os);
    let wal_size = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    main + wal_size
}

fn flush_sidecar_blocking(conn: &Connection, sidecar: &Path) -> Result<u64, EventHistoryError> {
    let last_id = crate::sequence::read_allocator(conn)?
        .ok_or_else(|| EventHistoryError::AllocatorCorrupt("missing".to_string()))?;
    write_sidecar(sidecar, last_id)?;
    Ok(last_id)
}

/// `MIN(event_id)` over `events`. Returns `Ok(None)` for an empty
/// table; the caller maps that to "nothing retained yet, no gap
/// possible." Indexed primary-key scan; cheap.
fn oldest_event_id_blocking(conn: &Connection) -> Result<Option<u64>, EventHistoryError> {
    // SELECT MIN(...) returns one row with a single SQL NULL when the
    // table is empty. `rusqlite::Row::get` over `Option<i64>` maps
    // that NULL to `Ok(None)`, which is what we want — avoid the
    // `QueryReturnedNoRows` round-trip.
    let row: Option<i64> = conn
        .query_row("SELECT MIN(event_id) FROM events", [], |r| r.get(0))
        .map_err(EventHistoryError::Sqlite)?;
    // `event_id` is stored as INTEGER NOT NULL on insert; values must
    // be positive (the allocator skips 0). Cast through i64 only because
    // SQLite's INTEGER column type is i64; the runtime invariant gives
    // us a safe `as u64` cast.
    Ok(row.map(|v| v as u64))
}
