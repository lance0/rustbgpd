//! Durable event history (local outbox) — ADR-0072.
//!
//! See `docs/adr/0072-durable-event-history.md` for the full contract.
//!
//! This crate is the persistence + cursor surface only. Producers
//! convert their existing event types to [`EventEnvelope`] and send
//! via the [`EventHistorySender`] mpsc handle. EHM batches inserts
//! into one SQLite transaction, stamps a durable `event_id`,
//! broadcasts the now-stamped envelope, and serves cursor-based
//! replay via the storage layer (PR3 wires the gRPC surface).
//!
//! ## Quick-start (for tests)
//!
//! ```ignore
//! use rustbgpd_event_history::{
//!     Category, EnvelopePeers, EventEnvelope, EventHistoryConfig,
//!     EventHistoryManager, PayloadCodec, Severity,
//! };
//! use std::path::PathBuf;
//!
//! # tokio_test::block_on(async {
//! let config = EventHistoryConfig {
//!     path: PathBuf::from("/tmp/events.db"),
//!     ..EventHistoryConfig::default()
//! };
//! let manager = EventHistoryManager::start(config).await.unwrap();
//! let env = EventEnvelope {
//!     timestamp_ns: 0,
//!     category: Category::Route,
//!     event_type: "added".into(),
//!     peers: EnvelopePeers::default(),
//!     afi_safi: Some("ipv4-unicast".into()),
//!     prefix: Some("10.0.0.0/24".into()),
//!     rd: None,
//!     evpn_route_type: None,
//!     severity: Severity::Info,
//!     payload_codec: PayloadCodec::Opaque,
//!     payload: vec![1, 2, 3, 4],
//! };
//! manager.sender().try_send(env).unwrap();
//! # })
//! ```

#![warn(clippy::all)]
#![allow(clippy::module_name_repetitions)]

mod error;
mod migrations;
mod quarantine;
mod sequence;
mod storage;

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

pub use error::EventHistoryError;
pub use storage::{PersistedEvent, QueryFilter};

/// Default capacity for each producer's mpsc channel into EHM.
pub const DEFAULT_QUEUE_CAPACITY: usize = 4096;

/// Default batch size — the larger of (this, batch_interval) wins per
/// commit. See ADR-0072 hot-path section.
pub const DEFAULT_BATCH_SIZE: usize = 1024;

/// Default batch interval — the larger of (batch_size, this) wins per
/// commit.
pub const DEFAULT_BATCH_INTERVAL: Duration = Duration::from_millis(50);

/// Default broadcast capacity for committed-event subscribers. Per-
/// subscriber buffer; subscribers falling behind see `Lagged`.
pub const DEFAULT_BROADCAST_CAPACITY: usize = 4096;

/// Default retention bounds. Small by design — see ADR-0072.
pub const DEFAULT_MAX_EVENTS: u64 = 100_000;
pub const DEFAULT_MAX_BYTES: u64 = 256_000_000;

/// Default retention interval — how often EHM runs the count/byte-cap
/// eviction pass.
pub const DEFAULT_RETENTION_INTERVAL: Duration = Duration::from_secs(60);

/// Default sidecar flush cadence — write `events.last_id` every N
/// completed batches.
pub const DEFAULT_SIDECAR_FLUSH_INTERVAL_BATCHES: u64 = 100;

/// Configuration for the EHM actor.
#[derive(Debug, Clone)]
pub struct EventHistoryConfig {
    /// Path to `events.db`. Sidecar lives alongside as
    /// `events.last_id`; quarantine is `events.db.stale`.
    pub path: PathBuf,
    /// Refuse to start if the DB cannot be opened (or recovered).
    /// Default `false` — degrade to pass-through with the degraded
    /// flag.
    pub required: bool,
    /// Per-producer mpsc capacity.
    pub queue_capacity: usize,
    /// Batch-commit size threshold.
    pub batch_size: usize,
    /// Batch-commit time threshold.
    pub batch_interval: Duration,
    /// Per-subscriber broadcast capacity.
    pub broadcast_capacity: usize,
    /// Count-cap retention.
    pub max_events: u64,
    /// Byte-cap retention (combined events.db + WAL).
    pub max_bytes: u64,
    /// Retention pass cadence.
    pub retention_interval: Duration,
    /// Sidecar flush cadence (batches between writes).
    pub sidecar_flush_interval_batches: u64,
}

impl Default for EventHistoryConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("events.db"),
            required: false,
            queue_capacity: DEFAULT_QUEUE_CAPACITY,
            batch_size: DEFAULT_BATCH_SIZE,
            batch_interval: DEFAULT_BATCH_INTERVAL,
            broadcast_capacity: DEFAULT_BROADCAST_CAPACITY,
            max_events: DEFAULT_MAX_EVENTS,
            max_bytes: DEFAULT_MAX_BYTES,
            retention_interval: DEFAULT_RETENTION_INTERVAL,
            sidecar_flush_interval_batches: DEFAULT_SIDECAR_FLUSH_INTERVAL_BATCHES,
        }
    }
}

/// Indexable event categories — see ADR-0072.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Route,
    Evpn,
    Session,
    Policy,
    Bfd,
    Dataplane,
}

impl Category {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Route => "route",
            Self::Evpn => "evpn",
            Self::Session => "session",
            Self::Policy => "policy",
            Self::Bfd => "bfd",
            Self::Dataplane => "dataplane",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "route" => Some(Self::Route),
            "evpn" => Some(Self::Evpn),
            "session" => Some(Self::Session),
            "policy" => Some(Self::Policy),
            "bfd" => Some(Self::Bfd),
            "dataplane" => Some(Self::Dataplane),
            _ => None,
        }
    }
}

/// Operator-facing severity. Matches the existing event surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }

    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "info" => Some(Self::Info),
            "warn" => Some(Self::Warn),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

/// Names the encoding of [`EventEnvelope::payload`].
///
/// Producer-driven — EHM treats payload bytes opaquely. The literal
/// string `"opaque"` is the PR2 default; PR3+ producers will set
/// `"proto"` once a single canonical proto envelope type is wired in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadCodec {
    /// Bytes are opaque to EHM. Used by PR2 tests + early producers
    /// that haven't been wired to a proto envelope yet.
    Opaque,
    /// Bytes are a prost-encoded `BgpEvent` envelope. PR3+.
    Proto,
}

impl PayloadCodec {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Opaque => "opaque",
            Self::Proto => "proto",
        }
    }
}

/// The peers carried on an event, in their three possible roles.
///
/// Pinned by ADR-0072: EHM indexes peers via the `event_peers` join
/// table so "any-role" queries hit a single index lookup. The
/// `event_peers` rows are derived from this struct at insert time.
#[derive(Debug, Default, Clone)]
pub struct EnvelopePeers {
    /// The peer associated with the event in its primary role
    /// (e.g., the peer advertising a route, the peer whose session
    /// changed state).
    pub peer: Option<IpAddr>,
    /// For "best-changed" / "withdrawn" events — the peer that
    /// previously held best.
    pub previous_peer: Option<IpAddr>,
    /// For "policy-filtered" route events — the outbound peer the
    /// route was filtered against.
    pub target_peer: Option<IpAddr>,
}

/// An event handed to EHM by a producer.
///
/// The `payload` field is producer-encoded bytes that EHM persists
/// and broadcasts byte-identically (the byte-equality invariant from
/// ADR-0072). EHM does NOT decode the payload; it does not need to.
/// The `event_id` is stamped by EHM at commit time and delivered to
/// subscribers via [`CommittedEvent`] (not by mutating the payload).
#[derive(Debug, Clone)]
pub struct EventEnvelope {
    /// Producer wall-clock at enqueue. Used for causal-ordering signals
    /// to external consumers; not the cursor (event_id is).
    pub timestamp_ns: i64,
    pub category: Category,
    pub event_type: String,
    pub peers: EnvelopePeers,
    pub afi_safi: Option<String>,
    pub prefix: Option<String>,
    pub rd: Option<String>,
    pub evpn_route_type: Option<i32>,
    pub severity: Severity,
    pub payload_codec: PayloadCodec,
    /// Producer-encoded bytes. Opaque to EHM. Byte-equality invariant:
    /// what the producer hands EHM is what EHM persists and broadcasts.
    pub payload: Vec<u8>,
}

/// A committed event delivered on the EHM broadcast channel.
///
/// Carries the assigned `event_id` alongside the byte-identical
/// `payload` from [`EventEnvelope::payload`]. PR3's gRPC layer
/// converts these to `BgpEvent` envelopes for the wire.
#[derive(Debug, Clone)]
pub struct CommittedEvent {
    pub event_id: u64,
    pub daemon_boot_id: Arc<str>,
    pub envelope: EventEnvelope,
}

/// Reusable sender handle. Producers hold one of these and use
/// [`Self::try_send`] (NEVER `.send().await`) to enqueue events.
#[derive(Debug, Clone)]
pub struct EventHistorySender {
    tx: mpsc::Sender<EventEnvelope>,
}

impl EventHistorySender {
    /// Non-blocking enqueue. On full queue, returns
    /// [`mpsc::error::TrySendError::Full`] — the producer drops the
    /// event, increments its drop counter, and flips the degraded
    /// flag. Never blocks the producer.
    // mpsc::error::TrySendError carries the envelope on the Full /
    // Closed variants — useful for telemetry but ~200B per Err.
    // Boxing keeps the Result small on the success path.
    #[allow(clippy::result_large_err)]
    pub fn try_send(
        &self,
        env: EventEnvelope,
    ) -> Result<(), mpsc::error::TrySendError<EventEnvelope>> {
        self.tx.try_send(env)
    }

    /// Currently-available slots in the underlying mpsc — the
    /// inverse of "in-flight." Subtract from `max_capacity` to get
    /// the queue depth (the value the `bgp_event_outbox_queue_depth`
    /// gauge wants).
    #[must_use]
    pub fn available(&self) -> usize {
        self.tx.capacity()
    }

    /// Total capacity of the underlying mpsc. Paired with
    /// [`Self::available`] to compute queue depth.
    #[must_use]
    pub fn max_capacity(&self) -> usize {
        self.tx.max_capacity()
    }
}

/// Broadcast subscription for committed events. Subscribers falling
/// behind see `RecvError::Lagged` — the gRPC layer (PR3) emits a
/// `StreamLagEvent` in that case.
pub type CommittedSubscriber = broadcast::Receiver<CommittedEvent>;

/// The async EHM actor handle returned by [`EventHistoryManager::start`].
///
/// Owns the storage thread + the actor task. `Drop` does NOT
/// gracefully shutdown — callers should explicitly call
/// [`Self::shutdown`] to flush the sidecar and checkpoint WAL.
pub struct EventHistoryManager {
    sender: EventHistorySender,
    broadcast_tx: broadcast::Sender<CommittedEvent>,
    storage: storage::StoreHandle,
    actor: Option<JoinHandle<()>>,
    storage_join: Option<JoinHandle<()>>,
    daemon_boot_id: Arc<str>,
    state: Arc<EhmState>,
    /// Shared shutdown signal — `shutdown()` notifies it; the actor
    /// loop checks it on every iteration. Using `Notify` (instead of
    /// dropping the sender) lets producers keep `EventHistorySender`
    /// clones alive across shutdown without deadlocking the actor on
    /// `rx.recv()`.
    shutdown_notify: Arc<Notify>,
}

impl std::fmt::Debug for EventHistoryManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // JoinHandle doesn't impl Debug; only print the visible
        // operator-facing state.
        f.debug_struct("EventHistoryManager")
            .field("daemon_boot_id", &self.daemon_boot_id)
            .field("latest_event_id", &self.state.latest_event_id())
            .field("degraded", &self.state.degraded())
            .field("pass_through", &self.state.pass_through())
            .finish()
    }
}

/// Shared atomic state surfaced by EHM. The gRPC layer (PR3) reads
/// these for `/healthz` + the `bgp_event_outbox_degraded` gauge.
#[derive(Debug, Default)]
pub struct EhmState {
    /// Latest committed `event_id`. Updated atomically after each
    /// batch commit so [`Self::latest_event_id`] is lock-free.
    latest_event_id: AtomicU64,
    /// Flipped to true on the first drop, the first open failure, or
    /// when EHM enters pass-through. Never auto-clears in v1 — the
    /// operator restarts to clear.
    degraded: AtomicBool,
    /// True when EHM is in pass-through (no persistence, broadcasts
    /// only). Set when the allocator anchor is unrecoverable AND a
    /// prior stale file exists.
    pass_through: AtomicBool,
}

impl EhmState {
    #[must_use]
    pub fn latest_event_id(&self) -> u64 {
        self.latest_event_id.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn degraded(&self) -> bool {
        self.degraded.load(Ordering::Acquire)
    }

    #[must_use]
    pub fn pass_through(&self) -> bool {
        self.pass_through.load(Ordering::Acquire)
    }

    fn flip_degraded(&self) {
        self.degraded.store(true, Ordering::Release);
    }
}

impl EventHistoryManager {
    /// Start the actor + storage thread. Returns once the storage
    /// thread is initialized (the DB is open + bootstrapped).
    pub async fn start(config: EventHistoryConfig) -> Result<Self, EventHistoryError> {
        let daemon_boot_id: Arc<str> = uuid::Uuid::new_v4().to_string().into();
        let state = Arc::new(EhmState::default());

        let init_result = storage::spawn_store(
            config.path.clone(),
            daemon_boot_id.clone(),
            // Storage channel capacity: matches batch_size so the EHM
            // loop can submit one in-flight commit while building the
            // next batch.
            (config.batch_size * 2).max(64),
        );

        let (store_handle, storage_join, init) = match init_result {
            Ok(triple) => triple,
            Err(EventHistoryError::PassThrough) => {
                if config.required {
                    return Err(EventHistoryError::PassThrough);
                }
                error!(
                    path = %config.path.display(),
                    "event outbox cannot recover allocator anchor; entering pass-through mode"
                );
                state.pass_through.store(true, Ordering::Release);
                state.flip_degraded();
                // We still create a sender so producers can send (the
                // events get dropped at the actor — and the dropped
                // counter increments, surfacing the pass-through
                // condition).
                return Err(EventHistoryError::PassThrough);
            }
            Err(e) => return Err(e),
        };

        if init.had_quarantine {
            state.flip_degraded();
            warn!(
                path = %config.path.display(),
                recovered_via_fallback = init.recovered_via_fallback,
                initial_allocator = init.initial_allocator,
                "event outbox started after quarantine; degraded flag set"
            );
        }
        state
            .latest_event_id
            .store(init.initial_allocator, Ordering::Release);

        let (producer_tx, producer_rx) = mpsc::channel(config.queue_capacity);
        let (broadcast_tx, _) = broadcast::channel(config.broadcast_capacity);
        let shutdown_notify = Arc::new(Notify::new());

        let actor_state = state.clone();
        let actor_store = store_handle.clone();
        let actor_broadcast = broadcast_tx.clone();
        let actor_boot_id = daemon_boot_id.clone();
        let actor_config = config.clone();
        let actor_shutdown = shutdown_notify.clone();

        let actor = tokio::spawn(async move {
            run_actor(
                actor_config,
                actor_state,
                actor_store,
                actor_broadcast,
                actor_boot_id,
                producer_rx,
                actor_shutdown,
            )
            .await;
        });

        info!(
            path = %config.path.display(),
            daemon_boot_id = %daemon_boot_id.as_ref(),
            initial_allocator = init.initial_allocator,
            "event history manager started"
        );

        Ok(Self {
            sender: EventHistorySender { tx: producer_tx },
            broadcast_tx,
            storage: store_handle,
            actor: Some(actor),
            storage_join: Some(storage_join),
            daemon_boot_id,
            state,
            shutdown_notify,
        })
    }

    /// Handle producers use to enqueue events. Clone freely.
    #[must_use]
    pub fn sender(&self) -> EventHistorySender {
        self.sender.clone()
    }

    /// Subscribe to committed events. New subscribers see events
    /// committed AFTER subscription only — cursor-based replay lives
    /// in PR3.
    #[must_use]
    pub fn subscribe(&self) -> CommittedSubscriber {
        self.broadcast_tx.subscribe()
    }

    /// Shared state for the gRPC + metrics layers.
    #[must_use]
    pub fn state(&self) -> Arc<EhmState> {
        self.state.clone()
    }

    /// Daemon boot ID stamped on every committed event in this
    /// process.
    #[must_use]
    pub fn daemon_boot_id(&self) -> Arc<str> {
        self.daemon_boot_id.clone()
    }

    /// Force a query against the durable store. PR2 exposes this for
    /// tests; PR3 wraps it in the `SubscribeFromEvent` cursor RPC.
    pub async fn query_persisted(
        &self,
        from_event_id: u64,
        to_event_id: u64,
        limit: usize,
        filter: storage::QueryFilter,
    ) -> Result<Vec<PersistedEvent>, EventHistoryError> {
        self.storage
            .query(from_event_id, to_event_id, limit, filter)
            .await
    }

    /// Graceful shutdown: signals the actor, drains pending events
    /// into one final commit, flushes the sidecar, checkpoints WAL,
    /// and exits.
    ///
    /// Safe to call while producer-held [`EventHistorySender`] clones
    /// are still alive — the shutdown is `Notify`-driven, not channel-
    /// drop-driven. Producers calling `try_send` after shutdown will
    /// see `TrySendError::Closed` once the storage thread exits.
    pub async fn shutdown(mut self) {
        // Signal the actor; it will run one final commit if there are
        // pending events, flush the sidecar, and return.
        self.shutdown_notify.notify_one();
        if let Some(actor) = self.actor.take() {
            let _ = actor.await;
        }
        self.storage.shutdown().await;
        if let Some(j) = self.storage_join.take() {
            let _ = j.await;
        }
    }
}

async fn run_actor(
    config: EventHistoryConfig,
    state: Arc<EhmState>,
    store: storage::StoreHandle,
    broadcast_tx: broadcast::Sender<CommittedEvent>,
    daemon_boot_id: Arc<str>,
    mut rx: mpsc::Receiver<EventEnvelope>,
    shutdown_notify: Arc<Notify>,
) {
    let mut buffer: Vec<EventEnvelope> = Vec::with_capacity(config.batch_size);
    let mut batches_since_sidecar_flush: u64 = 0;
    let mut retention_interval = tokio::time::interval(config.retention_interval);
    retention_interval.tick().await; // skip the immediate tick

    loop {
        let deadline = tokio::time::sleep(config.batch_interval);
        tokio::pin!(deadline);

        // Phase 1: gather a batch.
        let mut shutdown_requested = false;
        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    match maybe {
                        Some(env) => {
                            buffer.push(env);
                            if buffer.len() >= config.batch_size {
                                break;
                            }
                        }
                        // All senders dropped — also a valid shutdown
                        // signal, but the primary signal is the
                        // explicit Notify (which works while clones
                        // remain).
                        None => { shutdown_requested = true; break; }
                    }
                }
                () = &mut deadline => {
                    break;
                }
                () = shutdown_notify.notified() => {
                    shutdown_requested = true;
                    break;
                }
                _ = retention_interval.tick() => {
                    // Retention is async — kick it off but don't
                    // block the batch loop.
                    let store = store.clone();
                    let max_events = config.max_events;
                    let max_bytes = config.max_bytes;
                    tokio::spawn(async move {
                        if let Err(e) = store.retain(max_events, max_bytes).await {
                            warn!(error = %e, "retention pass failed");
                        }
                    });
                }
            }
        }

        // If shutdown was signaled mid-gather, drain any events the
        // producer queue still has buffered before committing the
        // final batch. Bounded by `batch_size * 2` so a wedged
        // producer can't keep us in this loop forever.
        if shutdown_requested {
            let drain_cap = config.batch_size.saturating_mul(2);
            while buffer.len() < drain_cap {
                match rx.try_recv() {
                    Ok(env) => buffer.push(env),
                    Err(_) => break,
                }
            }
        }

        // Phase 2: commit, broadcast, update state.
        if !buffer.is_empty() {
            let envelopes = std::mem::take(&mut buffer);
            let envelopes_for_broadcast = envelopes.clone();
            match store.append(envelopes).await {
                Ok(outcome) => {
                    state
                        .latest_event_id
                        .store(outcome.new_high_water, Ordering::Release);
                    // Broadcast every committed envelope with its assigned ID.
                    for (env, id) in envelopes_for_broadcast
                        .into_iter()
                        .zip(outcome.assigned_ids)
                    {
                        let committed = CommittedEvent {
                            event_id: id,
                            daemon_boot_id: outcome.daemon_boot_id.clone(),
                            envelope: env,
                        };
                        // broadcast::Sender::send returns Err only if
                        // there are no subscribers; that's fine.
                        let _ = broadcast_tx.send(committed);
                    }
                    batches_since_sidecar_flush += 1;
                    if batches_since_sidecar_flush >= config.sidecar_flush_interval_batches {
                        batches_since_sidecar_flush = 0;
                        if let Err(e) = store.flush_sidecar().await {
                            warn!(error = %e, "sidecar flush failed; will retry next batch");
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "batch commit failed; events dropped");
                    state.flip_degraded();
                }
            }
        }

        if shutdown_requested {
            // Final sidecar flush so the recovery ladder has the most
            // up-to-date anchor in case the next start opens against a
            // corrupted DB.
            if let Err(e) = store.flush_sidecar().await {
                warn!(error = %e, "final sidecar flush failed");
            }
            info!(
                daemon_boot_id = %daemon_boot_id.as_ref(),
                final_event_id = state.latest_event_id(),
                broadcast_subscribers = broadcast_tx.receiver_count(),
                "event history actor shutting down"
            );
            break;
        }
    }
}
