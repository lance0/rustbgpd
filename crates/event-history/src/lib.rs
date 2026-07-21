//! Durable event history (local outbox) — ADR-0072.
//!
//! See `docs/adr/0072-durable-event-history.md` for the full contract.
//!
//! This crate is the persistence + cursor surface only. Producers
//! convert their existing event types to [`EventEnvelope`] and send
//! via the [`EventHistorySender`] mpsc handle. EHM batches inserts
//! into one SQLite transaction, assigns a durable `event_id`, and
//! broadcasts a [`CommittedEvent`] carrying that `event_id` alongside
//! the **unchanged** producer payload bytes (the byte-equality
//! invariant — see `tests/byte_equality.rs`). The daemon's gRPC layer
//! exposes this through `SubscribeFromEvent`.
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

#![deny(unsafe_code)]
#![warn(clippy::all)]
#![allow(
    clippy::module_name_repetitions,
    reason = "public cross-crate types keep the event-history domain explicit"
)]

mod cursor;
mod error;
mod migrations;
mod quarantine;
mod sequence;
mod storage;

pub use cursor::{
    EventSubscription, EventSubscriptionItem, SubscribeFilter, SubscribeRequest, SubscribeStats,
    SubscribeStatsSnapshot,
};

use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use rustbgpd_telemetry::BgpMetrics;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

pub use error::EventHistoryError;
pub use storage::{PersistedEvent, QueryFilter, RetentionOutcome};

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
/// completed batches. The sidecar is diagnostic only in v1; it is not
/// authoritative for allocator recovery because it may lag the committed DB.
pub const DEFAULT_SIDECAR_FLUSH_INTERVAL_BATCHES: u64 = 100;

/// SQLite `PRAGMA synchronous` mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynchronousMode {
    /// `FULL`: sync on every commit. Default durability posture.
    Full,
    /// `NORMAL`: lower sync frequency; higher crash-loss window.
    Normal,
}

impl SynchronousMode {
    #[must_use]
    pub const fn as_pragma(self) -> &'static str {
        match self {
            Self::Full => "FULL",
            Self::Normal => "NORMAL",
        }
    }
}

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
    ///
    /// This is a retention trigger/target, not a strict filesystem cap:
    /// SQLite DELETE frees pages for reuse but does not guarantee the
    /// main DB file shrinks without vacuum/compaction.
    pub max_bytes: u64,
    /// SQLite synchronous mode.
    pub synchronous: SynchronousMode,
    /// Retention pass cadence.
    pub retention_interval: Duration,
    /// Sidecar flush cadence (batches between writes).
    pub sidecar_flush_interval_batches: u64,
    /// Optional Prometheus metrics handle. Tests and non-daemon callers
    /// can leave this unset; the daemon passes its workspace metrics so
    /// EHM can update commit, queue-depth, DB-size, retention, and latest
    /// cursor gauges from inside the actor.
    pub metrics: Option<BgpMetrics>,
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
            synchronous: SynchronousMode::Full,
            retention_interval: DEFAULT_RETENTION_INTERVAL,
            sidecar_flush_interval_batches: DEFAULT_SIDECAR_FLUSH_INTERVAL_BATCHES,
            metrics: None,
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
    pub const ALL: [Self; 6] = [
        Self::Route,
        Self::Evpn,
        Self::Session,
        Self::Policy,
        Self::Bfd,
        Self::Dataplane,
    ];

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
/// string `"opaque"` is available for tests and non-proto callers;
/// production producers set `"proto"` for prost-encoded `BgpEvent`
/// envelopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadCodec {
    /// Bytes are opaque to EHM. Used by tests and non-proto callers.
    Opaque,
    /// Bytes are a prost-encoded `BgpEvent` envelope.
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

    /// Parse the string form stored in
    /// [`crate::PersistedEvent::payload_codec`]. Returns `None` on
    /// unknown values (forward-compat: a future writer might use a
    /// codec name a reader from an older version doesn't recognize;
    /// the reader treats it as opaque rather than panicking).
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "opaque" => Some(Self::Opaque),
            "proto" => Some(Self::Proto),
            _ => None,
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
/// `payload` from [`EventEnvelope::payload`]. The gRPC layer
/// converts these to `BgpEvent` envelopes for the wire.
#[derive(Debug, Clone)]
pub struct CommittedEvent {
    pub event_id: u64,
    pub daemon_boot_id: Arc<str>,
    pub envelope: Arc<EventEnvelope>,
}

/// Reusable sender handle. Producers hold one of these and use
/// [`Self::try_send`] (NEVER `.send().await`) to enqueue events.
#[derive(Debug, Clone)]
pub struct EventHistorySender {
    tx: mpsc::Sender<EventEnvelope>,
    queue_depths: Arc<QueueDepths>,
    metrics: Option<BgpMetrics>,
}

impl EventHistorySender {
    /// Non-blocking enqueue. On full queue, returns
    /// [`mpsc::error::TrySendError::Full`] — the producer drops the
    /// event, increments its drop counter, and flips the degraded
    /// flag. Never blocks the producer.
    // mpsc::error::TrySendError carries the envelope on the Full /
    // Closed variants — useful for delivery accounting despite the ~200B Err.
    #[allow(
        clippy::result_large_err,
        reason = "TrySendError returns the original event when delivery fails"
    )]
    pub fn try_send(
        &self,
        env: EventEnvelope,
    ) -> Result<(), mpsc::error::TrySendError<EventEnvelope>> {
        let category = env.category;
        let depth = self.queue_depths.increment(category);
        set_queue_depth_metric(self.metrics.as_ref(), category, depth);
        match self.tx.try_send(env) {
            Ok(()) => Ok(()),
            Err(e) => {
                let depth = self.queue_depths.decrement(category);
                set_queue_depth_metric(self.metrics.as_ref(), category, depth);
                Err(e)
            }
        }
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

#[derive(Debug, Default)]
struct QueueDepths {
    route: AtomicU64,
    evpn: AtomicU64,
    session: AtomicU64,
    policy: AtomicU64,
    bfd: AtomicU64,
    dataplane: AtomicU64,
}

impl QueueDepths {
    fn counter(&self, category: Category) -> &AtomicU64 {
        match category {
            Category::Route => &self.route,
            Category::Evpn => &self.evpn,
            Category::Session => &self.session,
            Category::Policy => &self.policy,
            Category::Bfd => &self.bfd,
            Category::Dataplane => &self.dataplane,
        }
    }

    fn increment(&self, category: Category) -> u64 {
        self.counter(category).fetch_add(1, Ordering::AcqRel) + 1
    }

    fn decrement(&self, category: Category) -> u64 {
        self.counter(category)
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                Some(value.saturating_sub(1))
            })
            .map_or(0, |previous| previous.saturating_sub(1))
    }
}

fn set_queue_depth_metric(metrics: Option<&BgpMetrics>, category: Category, depth: u64) {
    if let Some(metrics) = metrics {
        metrics.set_event_outbox_queue_depth(
            category.as_str(),
            i64::try_from(depth).unwrap_or(i64::MAX),
        );
    }
}

fn initialize_queue_depth_metrics(metrics: Option<&BgpMetrics>) {
    if let Some(metrics) = metrics {
        for category in Category::ALL {
            metrics.set_event_outbox_queue_depth(category.as_str(), 0);
        }
    }
}

fn record_append_metrics(
    metrics: Option<&BgpMetrics>,
    envelopes: &[Arc<EventEnvelope>],
    outcome: &storage::AppendOutcome,
) {
    if let Some(metrics) = metrics {
        for env in envelopes {
            metrics.record_event_outbox_committed(env.category.as_str());
        }
        metrics.set_event_outbox_latest_event_id(
            i64::try_from(outcome.new_high_water).unwrap_or(i64::MAX),
        );
        metrics.set_event_outbox_db_size_bytes(
            i64::try_from(outcome.db_size_bytes).unwrap_or(i64::MAX),
        );
    }
}

fn record_commit_failure_metrics(metrics: Option<&BgpMetrics>, envelopes: &[Arc<EventEnvelope>]) {
    if let Some(metrics) = metrics {
        for env in envelopes {
            metrics.record_event_outbox_drop(env.category.as_str(), "db_error");
        }
        metrics.mark_event_outbox_degraded();
    }
}

fn record_retention_metrics(metrics: Option<&BgpMetrics>, outcome: storage::RetentionOutcome) {
    if let Some(metrics) = metrics {
        if outcome.evicted_count_cap > 0 {
            metrics.record_event_outbox_retention_evicted(
                "count_cap",
                outcome.evicted_count_cap as u64,
            );
        }
        if outcome.evicted_byte_cap > 0 {
            metrics
                .record_event_outbox_retention_evicted("byte_cap", outcome.evicted_byte_cap as u64);
        }
        metrics.set_event_outbox_db_size_bytes(
            i64::try_from(outcome.db_size_bytes).unwrap_or(i64::MAX),
        );
    }
}

/// Broadcast subscription for committed events. Subscribers falling
/// behind see `RecvError::Lagged` — the gRPC layer emits a
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
    /// Configured retention caps, kept so
    /// [`Self::run_retention_pass`] submits the same pass the actor's
    /// interval timer would.
    max_events: u64,
    max_bytes: u64,
    /// Shared shutdown signal. `shutdown()` flips the watch value to
    /// `true`; every storage await + producer-receive in the actor
    /// loop is wrapped in a `tokio::select!` that races
    /// `shutdown_rx.changed()`, so a wedged storage op can NOT hold
    /// the actor past shutdown. Producers can keep
    /// [`EventHistorySender`] clones alive across shutdown without
    /// deadlocking the actor on `rx.recv()`.
    shutdown_tx: watch::Sender<bool>,
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

/// Cloneable read/write projection of [`EventHistoryManager`].
///
/// Returned by [`EventHistoryManager::handle`]. Holds:
/// - the producer-facing [`EventHistorySender`] (clone-safe),
/// - the live committed-event broadcast,
/// - the shared [`EhmState`] (degraded / pass-through / latest id),
/// - the daemon boot id, stamped on every committed event,
/// - the (crate-internal) storage handle, so the cursor RPC can
///   resolve `MIN(event_id)` live for cursor-gap detection.
///
/// Crucially, the handle does **not** keep the actor or storage
/// thread alive — those are owned by the parent
/// [`EventHistoryManager`], whose [`EventHistoryManager::shutdown`]
/// is a consuming method. Producers and gRPC handlers may hold any
/// number of `EventHistoryHandle` clones without affecting shutdown.
#[derive(Clone)]
pub struct EventHistoryHandle {
    sender: EventHistorySender,
    broadcast_tx: broadcast::Sender<CommittedEvent>,
    state: Arc<EhmState>,
    daemon_boot_id: Arc<str>,
    storage: storage::StoreHandle,
}

impl std::fmt::Debug for EventHistoryHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventHistoryHandle")
            .field("daemon_boot_id", &self.daemon_boot_id)
            .field("latest_event_id", &self.state.latest_event_id())
            .field("degraded", &self.state.degraded())
            .field("pass_through", &self.state.pass_through())
            .finish()
    }
}

impl EventHistoryHandle {
    /// Producer-facing sender. Clone freely; producers should hold
    /// their own [`EventHistorySender`] from [`Self::sender`] (not the
    /// handle) so producer call sites don't carry the full handle.
    #[must_use]
    pub fn sender(&self) -> EventHistorySender {
        self.sender.clone()
    }

    /// Shared atomic state — degraded flag, pass-through flag, latest
    /// committed `event_id`. Lock-free reads.
    #[must_use]
    pub fn state(&self) -> &Arc<EhmState> {
        &self.state
    }

    /// Daemon boot id for the running process. Useful for collectors
    /// that want to detect "the daemon I was talking to restarted"
    /// without parsing event payloads.
    #[must_use]
    pub fn daemon_boot_id(&self) -> &Arc<str> {
        &self.daemon_boot_id
    }

    /// Subscribe to the durable committed-event stream with optional
    /// cursor replay. Delegates to the shared free-function form so
    /// the actor-ordered handoff has exactly one implementation. See
    /// [`SubscribeRequest`] for the cursor semantics.
    ///
    /// # Errors
    ///
    /// Returns [`EventHistoryError::PassThrough`] when EHM is in
    /// pass-through mode (no durable backing).
    pub fn subscribe_from_event(
        &self,
        req: SubscribeRequest,
    ) -> Result<EventSubscription, EventHistoryError> {
        // Step (1) of the 3-step handoff: attach the live receiver
        // here, BEFORE the inner function reads the high-watermark.
        // Doing the subscribe inline (no `await` between subscribe
        // and watermark capture) preserves the race-free shape.
        let live_rx = self.broadcast_tx.subscribe();
        cursor::subscribe_from_event_inner(req, self.state.as_ref(), live_rx, self.storage.clone())
    }

    /// Subscribe to the live broadcast directly (no cursor replay).
    /// Equivalent to `subscribe_from_event(None, …)` but returns the
    /// raw broadcast receiver — useful in tests and for live-only
    /// consumers that want the broadcast's `Lagged` signal.
    #[must_use]
    pub fn subscribe_live(&self) -> broadcast::Receiver<CommittedEvent> {
        self.broadcast_tx.subscribe()
    }

    /// `MIN(event_id)` over the live `events` table, or `None` when
    /// the table is empty. Resolves a live SQLite query rather than
    /// reading a cached atomic so retention races don't surface as
    /// stale gap counts. The gRPC `SubscribeFromEvent` handler calls
    /// this once at subscribe time to decide whether to emit a
    /// leading `StreamLagEvent`.
    ///
    /// # Errors
    ///
    /// Returns [`EventHistoryError::PassThrough`] when the storage
    /// thread has exited or EHM is in pass-through mode.
    pub async fn oldest_retained_event_id(&self) -> Result<Option<u64>, EventHistoryError> {
        if self.state.pass_through() {
            return Err(EventHistoryError::PassThrough);
        }
        self.storage.oldest_event_id().await
    }
}

/// Shared atomic state surfaced by EHM. The gRPC layer and metrics
/// plumbing read these for cursor availability and degraded state.
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

    /// Flip the degraded flag to `true`. Public so out-of-crate
    /// producers (the EHM-backed RIB sink, the BFD bridge, etc.) can
    /// signal that they had to drop an event before it reached the
    /// outbox. Idempotent: re-flipping a true flag is a no-op. Never
    /// auto-clears in v1; operator restarts to clear.
    pub fn flip_degraded(&self) {
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
            config.synchronous,
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
                // The crate-level API returns PassThrough here; the daemon
                // wiring decides whether to create a live-only manager for
                // required=false.
                return Err(EventHistoryError::PassThrough);
            }
            Err(e) => return Err(e),
        };

        if init.had_quarantine {
            state.flip_degraded();
            if let Some(metrics) = &config.metrics {
                metrics.mark_event_outbox_degraded();
            }
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
        if let Some(metrics) = &config.metrics {
            metrics.set_event_outbox_latest_event_id(
                i64::try_from(init.initial_allocator).unwrap_or(i64::MAX),
            );
        }

        let (producer_tx, producer_rx) = mpsc::channel(config.queue_capacity);
        let (broadcast_tx, _) = broadcast::channel(config.broadcast_capacity);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let queue_depths = Arc::new(QueueDepths::default());
        initialize_queue_depth_metrics(config.metrics.as_ref());

        let actor_state = state.clone();
        let actor_store = store_handle.clone();
        let actor_broadcast = broadcast_tx.clone();
        let actor_boot_id = daemon_boot_id.clone();
        let actor_config = config.clone();
        let actor_queue_depths = queue_depths.clone();

        let actor = tokio::spawn(async move {
            run_actor(
                ActorContext {
                    config: actor_config,
                    state: actor_state,
                    store: actor_store,
                    broadcast_tx: actor_broadcast,
                    daemon_boot_id: actor_boot_id,
                    queue_depths: actor_queue_depths,
                },
                producer_rx,
                shutdown_rx,
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
            sender: EventHistorySender {
                tx: producer_tx,
                queue_depths,
                metrics: config.metrics.clone(),
            },
            broadcast_tx,
            storage: store_handle,
            actor: Some(actor),
            storage_join: Some(storage_join),
            daemon_boot_id,
            state,
            max_events: config.max_events,
            max_bytes: config.max_bytes,
            shutdown_tx,
        })
    }

    /// Handle producers use to enqueue events. Clone freely.
    #[must_use]
    pub fn sender(&self) -> EventHistorySender {
        self.sender.clone()
    }

    /// Subscribe to committed events. New subscribers see events
    /// committed AFTER subscription only — cursor-based replay lives
    /// in [`EventHistoryManager::subscribe_from_event`] and
    /// [`EventHistoryHandle::subscribe_from_event`].
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

    /// Force a query against the durable store. Tests use this directly;
    /// the daemon wraps it in the `SubscribeFromEvent` cursor RPC.
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

    /// Run one retention pass immediately with the configured caps —
    /// the same `StoreOp::Retain` the actor's interval timer submits,
    /// processed in FIFO order behind any already-submitted appends.
    /// Tests drive the count/byte-cap check through this instead of
    /// sleeping on `retention_interval` (the timer cadence is
    /// timing-sensitive on a loaded host); production wiring never
    /// needs to call it.
    ///
    /// # Errors
    ///
    /// Returns [`EventHistoryError::PassThrough`] when the storage
    /// thread has exited.
    pub async fn run_retention_pass(&self) -> Result<RetentionOutcome, EventHistoryError> {
        self.storage.retain(self.max_events, self.max_bytes).await
    }

    /// Crate-internal: hand a live broadcast receiver to the cursor
    /// drain task. Mirrors [`Self::subscribe`] but kept on a separate
    /// method so the cursor module's reach into private state is
    /// explicit (and easier to audit).
    pub(crate) fn broadcast_tx_for_cursor(
        &self,
    ) -> tokio::sync::broadcast::Receiver<CommittedEvent> {
        self.broadcast_tx.subscribe()
    }

    /// Crate-internal: clone of the storage handle, for the cursor
    /// drain task's replay-phase queries.
    pub(crate) fn storage_handle_for_cursor(&self) -> storage::StoreHandle {
        self.storage.clone()
    }

    /// Return a cloneable read/write projection of this manager.
    ///
    /// The handle exposes the producer-facing sender, the cursor RPC
    /// (`subscribe_from_event`), the live broadcast, and the shared
    /// state. Lifecycle (`shutdown`) stays on the manager, which is
    /// **not** `Clone` — the binary holds the manager and threads
    /// handle clones into `EventService`, the RIB sink adapter,
    /// `PeerManager`, and the BFD bridge.
    #[must_use]
    pub fn handle(&self) -> EventHistoryHandle {
        EventHistoryHandle {
            sender: self.sender.clone(),
            broadcast_tx: self.broadcast_tx.clone(),
            state: self.state.clone(),
            daemon_boot_id: self.daemon_boot_id.clone(),
            storage: self.storage.clone(),
        }
    }

    /// Graceful shutdown: signals the actor, drains pending events
    /// into one final commit, flushes the sidecar, checkpoints WAL,
    /// and exits.
    ///
    /// Safe to call while producer-held [`EventHistorySender`] clones
    /// are still alive — shutdown is `watch::channel`-driven, not
    /// channel-drop-driven. Producers calling `try_send` after
    /// shutdown will see `TrySendError::Closed` once the storage
    /// thread exits.
    ///
    /// **Bounded by `shutdown_timeout`**: the actor wraps its storage
    /// awaits in a `tokio::select!` with `shutdown_rx.changed()`, so
    /// a wedged SQLite/disk operation can NOT hold us past the
    /// shutdown signal. After the actor exits, we send
    /// `StoreOp::Shutdown` to the storage thread and await its join
    /// handle with a hard timeout so a wedged blocking thread can't
    /// stall the daemon binary exit (we log and abandon the blocking
    /// thread if it doesn't return — the OS reclaims it on process
    /// exit).
    pub async fn shutdown(mut self) {
        // Signal the actor first. `watch::Sender::send` ignores the
        // closed-receiver error because the actor may already have
        // exited (e.g., DB-open failure during start).
        let _ = self.shutdown_tx.send(true);
        if let Some(actor) = self.actor.take() {
            let _ = actor.await;
        }
        // Now drain the storage thread. Best-effort with a bounded
        // timeout so a wedged spawn_blocking task doesn't hold the
        // caller forever.
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(5), self.storage.shutdown()).await;
        if let Some(j) = self.storage_join.take() {
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), j).await;
        }
    }
}

struct ActorContext {
    config: EventHistoryConfig,
    state: Arc<EhmState>,
    store: storage::StoreHandle,
    broadcast_tx: broadcast::Sender<CommittedEvent>,
    daemon_boot_id: Arc<str>,
    queue_depths: Arc<QueueDepths>,
}

async fn run_actor(
    ctx: ActorContext,
    mut rx: mpsc::Receiver<EventEnvelope>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let ActorContext {
        config,
        state,
        store,
        broadcast_tx,
        daemon_boot_id,
        queue_depths,
    } = ctx;

    let mut buffer: Vec<EventEnvelope> = Vec::with_capacity(config.batch_size);
    let mut batches_since_sidecar_flush: u64 = 0;
    let mut retention_interval = tokio::time::interval(config.retention_interval);
    let mut retention_task: Option<
        JoinHandle<Result<storage::RetentionOutcome, EventHistoryError>>,
    > = None;
    retention_interval.tick().await; // skip the immediate tick

    loop {
        // Fast-path bail: shutdown_rx already saw the flip.
        if *shutdown_rx.borrow() {
            break;
        }

        let deadline = tokio::time::sleep(config.batch_interval);
        tokio::pin!(deadline);

        // Phase 1: gather a batch.
        let mut shutdown_requested = false;
        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    match maybe {
                        Some(env) => {
                            let depth = queue_depths.decrement(env.category);
                            set_queue_depth_metric(config.metrics.as_ref(), env.category, depth);
                            buffer.push(env);
                            if buffer.len() >= config.batch_size {
                                break;
                            }
                        }
                        // All senders dropped — also a valid shutdown
                        // signal, distinct from the explicit watch
                        // (which works while clones remain alive).
                        None => { shutdown_requested = true; break; }
                    }
                }
                () = &mut deadline => {
                    break;
                }
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        shutdown_requested = true;
                        break;
                    }
                }
                _ = retention_interval.tick() => {
                    if retention_task.as_ref().is_some_and(|task| !task.is_finished()) {
                        continue;
                    }
                    if let Some(task) = retention_task.take()
                    {
                        match task.await {
                            Ok(Ok(outcome)) => {
                                record_retention_metrics(config.metrics.as_ref(), outcome);
                            }
                            Ok(Err(e)) => warn!(error = %e, "retention pass failed"),
                            Err(e) => warn!(error = %e, "retention task join failed"),
                        }
                    }
                    let store = store.clone();
                    let max_events = config.max_events;
                    let max_bytes = config.max_bytes;
                    retention_task = Some(tokio::spawn(async move {
                        store.retain(max_events, max_bytes).await
                    }));
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
                    Ok(env) => {
                        let depth = queue_depths.decrement(env.category);
                        set_queue_depth_metric(config.metrics.as_ref(), env.category, depth);
                        buffer.push(env);
                    }
                    Err(_) => break,
                }
            }
        }

        // Phase 2: commit, broadcast, update state.
        //
        // `store.append()` is a spawn_blocking-backed operation that
        // can wedge behind a slow/locked SQLite or a stalled disk. We
        // race it against
        // `shutdown_rx.changed()` so a stalled append can't hold the
        // actor past shutdown. The committed-side guarantee still
        // holds — if shutdown cancels the await before append
        // returns, the events are NEITHER persisted NOR broadcast,
        // matching the "no live event without durability" contract.
        if !buffer.is_empty() {
            // Project the gathered envelopes into Arcs ONCE. The same
            // Arcs are handed to the storage thread (for the INSERT
            // bind) and re-used to build CommittedEvent wrappers on
            // the broadcast side — no payload-bytes clone on the
            // broadcast path.
            let shared: Vec<Arc<EventEnvelope>> = std::mem::take(&mut buffer)
                .into_iter()
                .map(Arc::new)
                .collect();
            let len = shared.len();
            let append_input = shared.clone(); // Vec<Arc<...>> clone: pointer-bump only

            let append_result = tokio::select! {
                res = store.append(append_input) => res,
                changed = shutdown_rx.changed() => {
                    if changed.is_err() || *shutdown_rx.borrow() {
                        warn!(
                            pending = len,
                            "shutdown requested mid-batch; pending events lost (not persisted, not broadcast)"
                        );
                        state.flip_degraded();
                        break;
                    } else {
                        // Spurious wake (shouldn't happen for a
                        // boolean watch we never write again).
                        // Re-stash the envelopes back into buffer
                        // and continue around the outer loop.
                        buffer = shared
                            .iter()
                            .map(|e| (**e).clone())
                            .collect();
                        continue;
                    }
                }
            };

            match append_result {
                Ok(outcome) => {
                    state
                        .latest_event_id
                        .store(outcome.new_high_water, Ordering::Release);
                    record_append_metrics(config.metrics.as_ref(), &shared, &outcome);
                    // Broadcast every committed envelope with its assigned ID.
                    // CommittedEvent carries the same Arc handed to storage, so
                    // broadcast fanout clones a pointer, not payload bytes.
                    for (env_arc, id) in shared.into_iter().zip(outcome.assigned_ids) {
                        let committed = CommittedEvent {
                            event_id: id,
                            daemon_boot_id: outcome.daemon_boot_id.clone(),
                            envelope: env_arc,
                        };
                        // broadcast::Sender::send returns Err only if
                        // there are no subscribers; that's fine.
                        let _ = broadcast_tx.send(committed);
                    }
                    batches_since_sidecar_flush += 1;
                    if batches_since_sidecar_flush >= config.sidecar_flush_interval_batches {
                        batches_since_sidecar_flush = 0;
                        let flush_result = tokio::select! {
                            res = store.flush_sidecar() => res,
                            _ = shutdown_rx.changed() => Ok(0),  // shutdown will flush again below
                        };
                        if let Err(e) = flush_result {
                            warn!(error = %e, "sidecar flush failed; will retry next batch");
                        }
                    }
                }
                Err(e) => {
                    error!(error = %e, "batch commit failed; events dropped");
                    record_commit_failure_metrics(config.metrics.as_ref(), &shared);
                    state.flip_degraded();
                }
            }
        }

        if shutdown_requested || *shutdown_rx.borrow() {
            // Final sidecar flush so the recovery ladder has the most
            // up-to-date anchor in case the next start opens against a
            // corrupted DB. Bounded by a short timeout so a wedged
            // sidecar write can't hold the actor here.
            let flush_result =
                tokio::time::timeout(std::time::Duration::from_secs(2), store.flush_sidecar())
                    .await;
            match flush_result {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => warn!(error = %e, "final sidecar flush failed"),
                Err(_) => warn!("final sidecar flush timed out"),
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
