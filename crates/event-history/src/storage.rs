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

use std::path::{Path, PathBuf};
use std::sync::Arc;

// Re-export for cursor.rs / lib.rs — they hand Arc<EventEnvelope> to
// append so payload bytes aren't cloned a second time on the
// broadcast side.

use rusqlite::{Connection, params};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::error::EventHistoryError;
use crate::migrations::{CURRENT_SCHEMA_VERSION, META_LAST_BOOT_ID, META_LAST_EVENT_ID, bootstrap};
use crate::quarantine::{
    quarantine_db, read_quarantine_allocator, read_sidecar, sidecar_path, stale_path, write_sidecar,
};
use crate::sequence::Allocator;
use crate::{Category, EventEnvelope, Severity};

/// Operations the async side can send to the blocking storage thread.
pub(crate) enum StoreOp {
    /// Persist a batch of envelopes inside one SQLite transaction.
    ///
    /// Envelopes are passed as `Arc`s so the actor can hand the SAME
    /// underlying payload bytes to both the storage path (here) and
    /// the broadcast path (after commit) without cloning the payload
    /// vec a second time. Per Copilot review on PR2: the original
    /// design cloned the full `Vec<EventEnvelope>` (including payload
    /// bytes) twice, doubling allocation per batch.
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
    /// order. PR3 uses this for `SubscribeFromEvent` replay; PR2 only
    /// exposes it for tests.
    Query {
        from_event_id: u64,
        to_event_id: u64,
        limit: usize,
        filter: QueryFilter,
        reply: oneshot::Sender<Result<Vec<PersistedEvent>, EventHistoryError>>,
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
}

/// What `StoreOp::Retain` returns.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct RetentionOutcome {
    pub evicted_count_cap: usize,
    pub evicted_byte_cap: usize,
    pub db_size_bytes: u64,
}

/// Filter for [`StoreOp::Query`]. Each field is optional; `None` means
/// "any." Public so PR3's cursor API and PR2's tests can construct one;
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
    capacity: usize,
) -> Result<(StoreHandle, JoinHandle<()>, StorageInit), EventHistoryError> {
    let init = open_with_recovery(&path)?;
    let (tx, rx) = mpsc::channel(capacity);
    let path_clone = path.clone();
    let boot_id_clone = daemon_boot_id.clone();
    let initial_allocator = init.initial_allocator;
    let join = tokio::task::spawn_blocking(move || {
        run_storage_thread(path_clone, boot_id_clone, initial_allocator, rx);
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
    /// True if the allocator was seeded from the quarantine or sidecar
    /// fallback rather than the primary DB.
    pub recovered_via_fallback: bool,
}

/// Open the events DB at `path`, applying the recovery ladder (primary
/// → quarantine → sidecar). On success, returns the in-memory snapshot
/// of how recovery resolved. On failure, returns an error.
///
/// Implementation notes:
/// - We open the DB twice in the success path (first to probe, second
///   inside the blocking thread). The probe is cheap; doing it on the
///   async side keeps the error path off the blocking thread.
/// - If the primary fails to open, we attempt the quarantine + sidecar
///   reads before creating a fresh DB.
fn open_with_recovery(path: &Path) -> Result<StorageInit, EventHistoryError> {
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

    // STALE-ONLY GUARD (Codex review finding): when a previous start
    // quarantined `events.db` and the daemon exited before producing a
    // replacement, the next start would see no primary file. The plain
    // `Connection::open(path)` below WOULD CREATE a fresh empty DB and
    // `bootstrap` would seed `last_event_id = 0` — silently violating
    // the never-reused contract because prior IDs were already issued
    // (proven by the stale file's existence).
    //
    // Detect this state up front and run the recovery ladder BEFORE
    // any create-capable open. If the ladder can't recover an anchor,
    // surface `PassThrough` instead of restarting at 1.
    if !path.exists() && stale.exists() {
        warn!(
            events_db = %path.display(),
            stale = %stale.display(),
            "primary DB missing but stale quarantine exists; entering recovery ladder before create"
        );
        return recover_after_quarantine(path, &stale, &sidecar);
    }

    // Try the primary path.
    match probe_open(path) {
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
            recover_after_quarantine(path, &stale, &sidecar)
        }
    }
}

/// Allocator-recovery ladder, applied AFTER a quarantine (whether the
/// quarantine just happened or was left over from a prior process).
/// Reads from the quarantine first, then the sidecar; if both fail
/// AND a stale file exists, returns [`EventHistoryError::PassThrough`]
/// rather than seeding a fresh DB with `last_event_id = 0`.
///
/// Only creates the new primary DB when there IS a recoverable anchor
/// (or when no stale file is present, i.e. truly fresh install).
fn recover_after_quarantine(
    path: &Path,
    stale: &Path,
    sidecar: &Path,
) -> Result<StorageInit, EventHistoryError> {
    let fallback = read_quarantine_allocator(stale).or_else(|| read_sidecar(sidecar));

    let fresh_anchor = match fallback {
        Some(v) => v,
        None => {
            // No anchor recoverable. If a stale file exists, we KNOW
            // prior IDs were issued — refusing here protects the
            // never-reused promise. Caller decides what to do
            // (required=true ⇒ fail-start, required=false ⇒ pass-
            // through with degraded flag — see EventHistoryManager).
            if stale.exists() {
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
    bootstrap(&mut conn)?;
    conn.execute(
        "UPDATE metadata SET value = ?1 WHERE key = ?2",
        params![fresh_anchor.to_string(), META_LAST_EVENT_ID],
    )?;

    Ok(StorageInit {
        had_quarantine: true,
        initial_allocator: fresh_anchor,
        recovered_via_fallback: fallback.is_some(),
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
fn probe_open(path: &Path) -> Result<u64, EventHistoryError> {
    let mut conn = Connection::open(path).map_err(EventHistoryError::Sqlite)?;
    bootstrap(&mut conn)?;
    crate::sequence::read_allocator(&conn)?
        .ok_or_else(|| EventHistoryError::AllocatorCorrupt("missing post-bootstrap".to_string()))
}

/// The dedicated storage thread loop. Runs on a `spawn_blocking` task.
fn run_storage_thread(
    path: PathBuf,
    daemon_boot_id: Arc<str>,
    initial_allocator: u64,
    mut rx: mpsc::Receiver<StoreOp>,
) {
    let mut conn = match Connection::open(&path) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "storage thread failed to open DB; exiting");
            return;
        }
    };
    if let Err(e) = bootstrap(&mut conn) {
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
                let outcome = append_batch_blocking(&mut conn, envelopes, &daemon_boot_id);
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
    envelopes: Vec<Arc<EventEnvelope>>,
    daemon_boot_id: &Arc<str>,
) -> Result<AppendOutcome, EventHistoryError> {
    if envelopes.is_empty() {
        return Ok(AppendOutcome {
            assigned_ids: Vec::new(),
            new_high_water: crate::sequence::read_allocator(conn)?.unwrap_or(0),
            daemon_boot_id: daemon_boot_id.clone(),
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

            insert_event.execute(params![
                id,
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
                insert_peer.execute(params![id, "peer", p.to_string()])?;
            }
            if let Some(p) = &env.peers.previous_peer {
                insert_peer.execute(params![id, "previous_peer", p.to_string()])?;
            }
            if let Some(p) = &env.peers.target_peer {
                insert_peer.execute(params![id, "target_peer", p.to_string()])?;
            }
        }
    }

    let new_high_water = allocator.finalize(&txn)?;
    txn.commit()?;

    Ok(AppendOutcome {
        assigned_ids,
        new_high_water,
        daemon_boot_id: daemon_boot_id.clone(),
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
         JOIN event_peers ep ON ep.event_id = e.event_id
         WHERE ep.peer = ?1
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
    Ok(PersistedEvent {
        event_id: row.get::<_, i64>(0)? as u64,
        timestamp_ns: row.get(1)?,
        category: Category::parse(&category_raw).unwrap_or(Category::Route),
        event_type: row.get(3)?,
        peer: row.get(4)?,
        previous_peer: row.get(5)?,
        target_peer: row.get(6)?,
        afi_safi: row.get(7)?,
        prefix: row.get(8)?,
        rd: row.get(9)?,
        evpn_route_type: row.get(10)?,
        severity: Severity::parse(&severity_raw).unwrap_or(Severity::Info),
        daemon_boot_id: row.get(12)?,
        payload_codec: row.get(13)?,
        payload: row.get(14)?,
    })
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

    // 2. Byte cap. Loop because one DELETE LIMIT pass may not get us
    //    under the bound on a heavily-overweight DB; cap at 10
    //    passes per retention call to bound worst-case work.
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
