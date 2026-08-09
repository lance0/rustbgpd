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

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
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
    shutdown_progress: Arc<ShutdownProgress>,
    /// Configured retention caps, kept so
    /// [`Self::run_retention_pass`] submits the same pass the actor's
    /// interval timer would.
    max_events: u64,
    max_bytes: u64,
    shutdown_tx: watch::Sender<Option<tokio::time::Instant>>,
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
    /// Process-local wake boundary for irreversible event loss. Unlike
    /// `degraded`, every detected loss advances this generation.
    loss_generation: watch::Sender<u64>,
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

    /// Record an irreversible event loss. Public so out-of-crate producers
    /// (the EHM-backed RIB sink, the BFD bridge, etc.) can signal loss before
    /// it reaches the outbox. The degraded latch never auto-clears, while the
    /// process-local generation advances on every call to wake live consumers.
    pub fn record_loss(&self) {
        self.degraded.store(true, Ordering::Release);
        self.loss_generation
            .send_modify(|generation| *generation = generation.wrapping_add(1));
    }

    /// Subscribe to losses detected after this call. Earlier generations are
    /// considered seen, allowing a fresh snapshot to establish a new baseline.
    #[must_use]
    pub fn subscribe_loss_generation(&self) -> watch::Receiver<u64> {
        self.loss_generation.subscribe()
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
                state.record_loss();
                // The crate-level API returns PassThrough here; the daemon
                // wiring decides whether to create a live-only manager for
                // required=false.
                return Err(EventHistoryError::PassThrough);
            }
            Err(e) => return Err(e),
        };

        if init.had_quarantine {
            state.record_loss();
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
        let (shutdown_tx, shutdown_rx) = watch::channel(None);
        let queue_depths = Arc::new(QueueDepths::default());
        initialize_queue_depth_metrics(config.metrics.as_ref());

        let actor_state = state.clone();
        let actor_store = store_handle.clone();
        let actor_broadcast = broadcast_tx.clone();
        let actor_boot_id = daemon_boot_id.clone();
        let actor_config = config.clone();
        let actor_queue_depths = queue_depths.clone();
        let shutdown_progress = Arc::new(ShutdownProgress::default());
        let actor_shutdown_progress = Arc::clone(&shutdown_progress);

        let actor = tokio::spawn(async move {
            run_actor(
                ActorContext {
                    config: actor_config,
                    state: actor_state,
                    store: actor_store,
                    broadcast_tx: actor_broadcast,
                    daemon_boot_id: actor_boot_id,
                    queue_depths: actor_queue_depths,
                    shutdown_progress: actor_shutdown_progress,
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
            shutdown_progress,
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
    /// shutdown will see `TrySendError::Closed` once the actor closes
    /// producer admission.
    ///
    /// One five-second deadline bounds drain and storage finalization.
    pub async fn shutdown(mut self) {
        let deadline = tokio::time::Instant::now() + SHUTDOWN_TIMEOUT;
        let _ = self.shutdown_tx.send(Some(deadline));
        if let Some(mut actor) = self.actor.take() {
            let result = match tokio::time::timeout_at(deadline, &mut actor).await {
                Ok(result) => result,
                Err(_) => {
                    #[cfg(test)]
                    self.shutdown_progress
                        .deadline_expiries
                        .fetch_add(1, Ordering::AcqRel);
                    actor.abort();
                    actor.await
                }
            };
            if let Err(error) = result {
                warn!(%error, "event-history actor did not complete cleanly during shutdown");
                reconcile_abandoned_queue(&self.sender.queue_depths, self.sender.metrics.as_ref());
                if !self
                    .shutdown_progress
                    .accepted_complete
                    .load(Ordering::Acquire)
                {
                    record_shutdown_loss(
                        &self.state,
                        &self.shutdown_progress,
                        self.sender.metrics.as_ref(),
                    );
                }
            }
        }
        let _ = tokio::time::timeout_at(deadline, self.storage.shutdown()).await;
        if let Some(j) = self.storage_join.take() {
            let _ = tokio::time::timeout_at(deadline, j).await;
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
    shutdown_progress: Arc<ShutdownProgress>,
}

#[derive(Debug, Default)]
struct ShutdownProgress {
    loss_recorded: AtomicBool,
    accepted_complete: AtomicBool,
    #[cfg(test)]
    loss_latches: AtomicU64,
    /// Times shutdown fell back to the shared deadline instead of
    /// finishing on its own. Counts both arms of that race: the actor's
    /// drain loop timing out on `rx.recv`, and the manager timing out on
    /// the actor and aborting it. Lets tests assert a finite queue drains
    /// on channel closure without timing the drain with a stopwatch.
    #[cfg(test)]
    deadline_expiries: AtomicU64,
}

fn record_shutdown_loss(
    state: &EhmState,
    progress: &ShutdownProgress,
    metrics: Option<&BgpMetrics>,
) {
    if !progress.loss_recorded.swap(true, Ordering::AcqRel) {
        #[cfg(test)]
        progress.loss_latches.fetch_add(1, Ordering::AcqRel);
        state.record_loss();
        if let Some(metrics) = metrics {
            metrics.mark_event_outbox_degraded();
        }
    }
}

fn mark_accepted_complete(progress: &ShutdownProgress) {
    progress.accepted_complete.store(true, Ordering::Release);
}

fn shutdown_deadline_from(
    changed: Result<(), watch::error::RecvError>,
    rx: &watch::Receiver<Option<tokio::time::Instant>>,
) -> tokio::time::Instant {
    changed
        .ok()
        .and_then(|()| *rx.borrow())
        .unwrap_or_else(|| tokio::time::Instant::now() + SHUTDOWN_TIMEOUT)
}

fn receive_event(
    env: EventEnvelope,
    buffer: &mut Vec<EventEnvelope>,
    queue_depths: &QueueDepths,
    metrics: Option<&BgpMetrics>,
) {
    let depth = queue_depths.decrement(env.category);
    set_queue_depth_metric(metrics, env.category, depth);
    buffer.push(env);
}

fn begin_actor_shutdown(
    deadline: tokio::time::Instant,
    current: &mut Option<tokio::time::Instant>,
    rx: &mut mpsc::Receiver<EventEnvelope>,
    retention_task: &mut Option<JoinHandle<Result<RetentionOutcome, EventHistoryError>>>,
) {
    if current.is_none() {
        *current = Some(deadline);
        rx.close();
        if let Some(task) = retention_task.take() {
            task.abort();
        }
    }
}

fn discard_accepted_queue(
    rx: &mut mpsc::Receiver<EventEnvelope>,
    queue_depths: &QueueDepths,
    metrics: Option<&BgpMetrics>,
) -> usize {
    let mut dropped = 0;
    while let Ok(env) = rx.try_recv() {
        let depth = queue_depths.decrement(env.category);
        set_queue_depth_metric(metrics, env.category, depth);
        if let Some(metrics) = metrics {
            metrics.record_event_outbox_drop(env.category.as_str(), "shutdown_timeout");
        }
        dropped += 1;
    }
    dropped
}

fn reconcile_abandoned_queue(queue_depths: &QueueDepths, metrics: Option<&BgpMetrics>) {
    for category in Category::ALL {
        queue_depths.counter(category).store(0, Ordering::Release);
        set_queue_depth_metric(metrics, category, 0);
    }
}

async fn run_actor(
    ctx: ActorContext,
    mut rx: mpsc::Receiver<EventEnvelope>,
    mut shutdown_rx: watch::Receiver<Option<tokio::time::Instant>>,
) {
    let ActorContext {
        config,
        state,
        store,
        broadcast_tx,
        daemon_boot_id,
        queue_depths,
        shutdown_progress,
    } = ctx;

    let mut buffer: Vec<EventEnvelope> = Vec::with_capacity(config.batch_size);
    let mut batches_since_sidecar_flush: u64 = 0;
    let mut retention_interval = tokio::time::interval(config.retention_interval);
    let mut retention_task: Option<
        JoinHandle<Result<storage::RetentionOutcome, EventHistoryError>>,
    > = None;
    let mut shutdown_deadline = None;
    let mut accepted_drained = false;
    retention_interval.tick().await; // skip the immediate tick

    'actor: loop {
        if let Some(deadline) = shutdown_deadline {
            while buffer.len() < config.batch_size && !accepted_drained {
                match tokio::time::timeout_at(deadline, rx.recv()).await {
                    Ok(Some(env)) => {
                        receive_event(env, &mut buffer, &queue_depths, config.metrics.as_ref())
                    }
                    Ok(None) => accepted_drained = true,
                    Err(_) => {
                        #[cfg(test)]
                        shutdown_progress
                            .deadline_expiries
                            .fetch_add(1, Ordering::AcqRel);
                        break;
                    }
                }
            }
        } else {
            let batch_deadline = tokio::time::sleep(config.batch_interval);
            tokio::pin!(batch_deadline);
            while buffer.len() < config.batch_size {
                tokio::select! {
                    maybe = rx.recv() => match maybe {
                        Some(env) => receive_event(
                            env,
                            &mut buffer,
                            &queue_depths,
                            config.metrics.as_ref(),
                        ),
                        None => {
                            let deadline = tokio::time::Instant::now() + SHUTDOWN_TIMEOUT;
                            begin_actor_shutdown(
                                deadline,
                                &mut shutdown_deadline,
                                &mut rx,
                                &mut retention_task,
                            );
                            accepted_drained = true;
                            break;
                        }
                    },
                    () = &mut batch_deadline => break,
                    changed = shutdown_rx.changed() => {
                        let deadline = shutdown_deadline_from(changed, &shutdown_rx);
                        begin_actor_shutdown(
                            deadline,
                            &mut shutdown_deadline,
                            &mut rx,
                            &mut retention_task,
                        );
                        break;
                    }
                    _ = retention_interval.tick() => {
                        if retention_task.as_ref().is_some_and(|task| !task.is_finished()) {
                            continue;
                        }
                        if let Some(task) = retention_task.take() {
                            match task.await {
                                Ok(Ok(outcome)) => record_retention_metrics(
                                    config.metrics.as_ref(),
                                    outcome,
                                ),
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
        }

        if buffer.is_empty() && accepted_drained {
            mark_accepted_complete(&shutdown_progress);
            break;
        }

        if buffer.is_empty()
            && shutdown_deadline.is_some_and(|deadline| deadline <= tokio::time::Instant::now())
        {
            let dropped = discard_accepted_queue(&mut rx, &queue_depths, config.metrics.as_ref());
            if dropped > 0 {
                record_shutdown_loss(&state, &shutdown_progress, config.metrics.as_ref());
                warn!(
                    dropped,
                    "event-history shutdown deadline expired; accepted events lost"
                );
            } else {
                mark_accepted_complete(&shutdown_progress);
            }
            break;
        }

        // Phase 2: commit, broadcast, update state.
        //
        // Shutdown keeps polling the same submitted append future until the
        // shared deadline; timeout makes persistence unknown.
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
            let append_input = shared.clone(); // Vec<Arc<...>> clone: pointer-bump only
            let mut append = Box::pin(store.append(append_input));
            let append_result = if let Some(deadline) = shutdown_deadline {
                tokio::time::timeout_at(deadline, &mut append).await
            } else {
                tokio::select! {
                    biased;
                    changed = shutdown_rx.changed() => {
                        let deadline = shutdown_deadline_from(changed, &shutdown_rx);
                        begin_actor_shutdown(
                            deadline,
                            &mut shutdown_deadline,
                            &mut rx,
                            &mut retention_task,
                        );
                        tokio::time::timeout_at(deadline, &mut append).await
                    }
                    res = &mut append => Ok(res),
                }
            };

            match append_result {
                Ok(Ok(outcome)) => {
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
                    if batches_since_sidecar_flush >= config.sidecar_flush_interval_batches
                        && shutdown_deadline.is_none()
                    {
                        batches_since_sidecar_flush = 0;
                        let mut flush = Box::pin(store.flush_sidecar());
                        let flush_result = tokio::select! {
                            biased;
                            changed = shutdown_rx.changed() => {
                                let deadline = shutdown_deadline_from(changed, &shutdown_rx);
                                begin_actor_shutdown(
                                    deadline,
                                    &mut shutdown_deadline,
                                    &mut rx,
                                    &mut retention_task,
                                );
                                if rx.is_empty() {
                                    accepted_drained = true;
                                    mark_accepted_complete(&shutdown_progress);
                                }
                                tokio::time::timeout_at(deadline, &mut flush).await.ok()
                            }
                            result = &mut flush => Some(result),
                        };
                        if let Some(Err(e)) = flush_result {
                            warn!(error = %e, "sidecar flush failed; will retry next batch");
                        } else if flush_result.is_none() {
                            let dropped = discard_accepted_queue(
                                &mut rx,
                                &queue_depths,
                                config.metrics.as_ref(),
                            );
                            if dropped > 0 {
                                record_shutdown_loss(
                                    &state,
                                    &shutdown_progress,
                                    config.metrics.as_ref(),
                                );
                            } else {
                                mark_accepted_complete(&shutdown_progress);
                            }
                            warn!(
                                dropped,
                                "event-history shutdown deadline expired during sidecar flush"
                            );
                            break 'actor;
                        }
                    }
                }
                Ok(Err(e)) => {
                    error!(error = %e, "batch commit failed; events dropped");
                    record_commit_failure_metrics(config.metrics.as_ref(), &shared);
                    state.record_loss();
                }
                Err(_) => {
                    let queued =
                        discard_accepted_queue(&mut rx, &queue_depths, config.metrics.as_ref());
                    record_shutdown_loss(&state, &shutdown_progress, config.metrics.as_ref());
                    warn!(
                        pending = shared.len(),
                        queued,
                        "event-history shutdown deadline expired with an append outcome unknown"
                    );
                    break;
                }
            }
        }
    }

    if let Some(deadline) = shutdown_deadline {
        match tokio::time::timeout_at(deadline, store.flush_sidecar()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => warn!(error = %e, "final sidecar flush failed"),
            Err(_) => warn!("final sidecar flush timed out"),
        }
    }
    info!(
        daemon_boot_id = %daemon_boot_id.as_ref(),
        final_event_id = state.latest_event_id(),
        broadcast_subscribers = broadcast_tx.receiver_count(),
        "event history actor shutting down"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use storage::TestStoreOp::{Append, Flush, Shutdown};

    /// Hang preventer, not a timing property. Every assertion below is on
    /// observed state, never on how long something took, so this only has
    /// to be large enough that a loaded box never reaches it.
    const TEST_BACKSTOP: Duration = Duration::from_secs(60);

    fn test_config(path: PathBuf, batch_size: usize) -> EventHistoryConfig {
        EventHistoryConfig {
            path,
            batch_size,
            batch_interval: Duration::from_secs(60),
            ..EventHistoryConfig::default()
        }
    }

    fn event(category: Category, value: u8) -> EventEnvelope {
        EventEnvelope {
            timestamp_ns: i64::from(value),
            category,
            event_type: "test".into(),
            peers: EnvelopePeers::default(),
            afi_safi: None,
            prefix: None,
            rd: None,
            evpn_route_type: None,
            severity: Severity::Info,
            payload_codec: PayloadCodec::Opaque,
            payload: vec![value],
        }
    }

    async fn wait_for_store(store: &storage::StoreHandle, op: storage::TestStoreOp) {
        tokio::time::timeout(TEST_BACKSTOP, store.test_wait_for_send(op))
            .await
            .expect("storage request backstop elapsed");
    }

    #[tokio::test]
    async fn append_error_advances_loss_generation() {
        // Load-bearing break: replacing `record_loss` in the actor's append-error
        // branch with only the degraded latch exceeds the generation backstop.
        let dir = tempfile::tempdir().unwrap();
        let manager = EventHistoryManager::start(test_config(dir.path().join("events.db"), 1))
            .await
            .unwrap();
        let state = manager.state();
        let mut losses = state.subscribe_loss_generation();

        manager.storage.shutdown().await;
        manager
            .sender()
            .try_send(event(Category::Route, 1))
            .unwrap();
        tokio::time::timeout(TEST_BACKSTOP, losses.changed())
            .await
            .expect("append-error loss generation backstop elapsed")
            .unwrap();
        assert_eq!(*losses.borrow_and_update(), 1);
        assert!(state.degraded());
        assert_eq!(state.latest_event_id(), 0);

        manager.shutdown().await;
    }

    #[tokio::test]
    async fn shutdown_drains_every_accepted_event_with_live_sender() {
        // Load-bearing breaks: the old batch_size*2 cap loses five events;
        // omitting the receiver close leaves the drain with nothing to end
        // it but the shared deadline, which the expiry count catches on
        // either arm of that race — without timing the drain, so a slow
        // box cannot fail a correct drain.
        let dir = tempfile::tempdir().unwrap();
        let manager = EventHistoryManager::start(test_config(dir.path().join("events.db"), 4))
            .await
            .unwrap();
        let sender = manager.sender();
        let state = manager.state();
        let progress = Arc::clone(&manager.shutdown_progress);
        let queue_depths = Arc::clone(&manager.sender.queue_depths);
        let mut committed = manager.subscribe();
        let categories = Category::ALL;
        for value in 0..13 {
            sender
                .try_send(event(
                    categories[usize::from(value) % categories.len()],
                    value,
                ))
                .unwrap();
        }

        tokio::time::timeout(TEST_BACKSTOP, manager.shutdown())
            .await
            .expect("shutdown never returned");
        assert_eq!(
            progress.deadline_expiries.load(Ordering::Acquire),
            0,
            "a finite accepted queue must drain on channel closure, not on the shutdown deadline"
        );
        assert_eq!(state.latest_event_id(), 13);
        for expected in 0..13 {
            let observed = committed.try_recv().unwrap();
            assert_eq!(observed.envelope.payload, vec![expected]);
        }
        for category in Category::ALL {
            assert_eq!(
                queue_depths.counter(category).load(Ordering::Acquire),
                0,
                "{category:?} queue depth did not drain"
            );
        }
        assert!(matches!(
            sender.try_send(event(Category::Route, 99)),
            Err(mpsc::error::TrySendError::Closed(_))
        ));
        drop(sender);
    }

    #[tokio::test]
    async fn shutdown_continues_the_same_append_after_store_send() {
        // Load-bearing breaks: canceling the in-flight append at shutdown loses
        // the broadcast/state update; recreating it increments append_calls.
        let dir = tempfile::tempdir().unwrap();
        let manager = EventHistoryManager::start(test_config(dir.path().join("events.db"), 1))
            .await
            .unwrap();
        let store = manager.storage.clone();
        let state = manager.state();
        let mut committed = manager.subscribe();
        store.test_pause_after_send(Append);
        manager
            .sender()
            .try_send(event(Category::Session, 7))
            .unwrap();
        wait_for_store(&store, Append).await;

        let shutdown = tokio::spawn(manager.shutdown());
        tokio::task::yield_now().await;
        store.test_release(Append);
        tokio::time::timeout(TEST_BACKSTOP, shutdown)
            .await
            .expect("shutdown never returned")
            .unwrap();

        assert_eq!(store.test_append_calls(), 1);
        assert_eq!(state.latest_event_id(), 1);
        assert_eq!(committed.try_recv().unwrap().envelope.payload, vec![7]);
        assert!(!state.degraded());
    }

    #[tokio::test(start_paused = true)]
    async fn actor_uses_shared_deadline_and_latches_unknown_append_once() {
        // Load-bearing breaks: a reset deadline stays pending; missing the
        // latch/gauge or counting an unknown DB outcome makes assertions red.
        let dir = tempfile::tempdir().unwrap();
        let metrics = BgpMetrics::new();
        let mut config = test_config(dir.path().join("events.db"), 1);
        config.metrics = Some(metrics.clone());
        let mut manager = EventHistoryManager::start(config).await.unwrap();
        let store = manager.storage.clone();
        let state = manager.state();
        let mut losses = state.subscribe_loss_generation();
        let progress = Arc::clone(&manager.shutdown_progress);
        store.test_pause_after_send(Append);
        manager
            .sender()
            .try_send(event(Category::Policy, 9))
            .unwrap();
        wait_for_store(&store, Append).await;
        manager
            .sender()
            .try_send(event(Category::Route, 10))
            .unwrap();

        let deadline = tokio::time::Instant::now() + SHUTDOWN_TIMEOUT;
        tokio::time::advance(Duration::from_secs(2)).await;
        manager.shutdown_tx.send(Some(deadline)).unwrap();
        let actor = manager.actor.take().unwrap();
        tokio::time::advance(Duration::from_secs(3)).await;
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        let finished = actor.is_finished();
        store.test_release(Append);
        actor.await.unwrap();
        assert!(finished, "actor reset the shared deadline");
        assert!(state.degraded());
        assert!(metrics.event_outbox_degraded());
        let families = metrics.registry().gather();
        let dropped = families
            .iter()
            .find(|family| family.name() == "bgp_event_outbox_dropped_total")
            .expect("queued expiry must report one definite drop");
        assert_eq!(dropped.get_metric().len(), 1);
        let dropped = &dropped.get_metric()[0];
        let labels = dropped.get_label();
        let has_label = |name, value| {
            labels
                .iter()
                .any(|label| label.name() == name && label.value() == value)
        };
        assert!(has_label("category", "route"));
        assert!(has_label("reason", "shutdown_timeout"));
        assert_eq!(dropped.get_counter().value(), 1.0);
        assert_eq!(progress.loss_latches.load(Ordering::Acquire), 1);
        assert!(losses.has_changed().unwrap());
        assert_eq!(*losses.borrow_and_update(), 1);
        record_shutdown_loss(&state, &progress, Some(&metrics));
        assert_eq!(progress.loss_latches.load(Ordering::Acquire), 1);
        assert!(!losses.has_changed().unwrap());
        assert_eq!(store.test_append_calls(), 1);
        manager.shutdown().await;
    }

    #[tokio::test(start_paused = true)]
    async fn finalization_timeouts_share_deadline_without_recording_event_loss() {
        // Load-bearing breaks: a reset storage deadline stays pending; treating
        // periodic Flush or storage finalization as loss flips the latch.
        for op in [Flush, Shutdown] {
            let dir = tempfile::tempdir().unwrap();
            let mut config = test_config(dir.path().join("events.db"), 1);
            config.sidecar_flush_interval_batches = if matches!(op, Flush) { 1 } else { u64::MAX };
            let manager = EventHistoryManager::start(config).await.unwrap();
            let store = manager.storage.clone();
            let state = manager.state();
            let progress = Arc::clone(&manager.shutdown_progress);
            let mut committed = manager.subscribe();
            store.test_pause_after_send(op);
            if matches!(op, Shutdown) {
                store.test_pause_after_send(Flush);
            }
            manager.sender().try_send(event(Category::Bfd, 3)).unwrap();
            tokio::time::timeout(TEST_BACKSTOP, committed.recv())
                .await
                .expect("committed event backstop elapsed")
                .unwrap();

            let shutdown = tokio::spawn(manager.shutdown());
            tokio::task::yield_now().await;
            if matches!(op, Shutdown) {
                wait_for_store(&store, Flush).await;
                tokio::time::advance(Duration::from_secs(2)).await;
                store.test_release(Flush);
            }
            wait_for_store(&store, op).await;
            tokio::time::advance(if matches!(op, Shutdown) {
                Duration::from_secs(3)
            } else {
                SHUTDOWN_TIMEOUT
            })
            .await;
            tokio::task::yield_now().await;
            let finished = shutdown.is_finished();
            store.test_release(op);
            shutdown.await.unwrap();
            assert!(finished, "{op:?} reset the shared deadline");
            assert_eq!(state.latest_event_id(), 1);
            assert!(!state.degraded());
            assert_eq!(progress.loss_latches.load(Ordering::Acquire), 0);
        }
    }
}
