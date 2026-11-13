//! Async RTR client — one tokio task per configured RPKI cache server.
//!
//! Connects via TCP, prefers RTR protocol version 2 for ASPA support, falls
//! back to version 1 on explicit server rejection, and sends VRP updates to
//! the [`VrpManager`](super::vrp_manager::VrpManager).
//!
//! Cache state is modeled as one per-cache epoch — the
//! `(protocol version, session ID, serial)` triple — advanced only as a
//! unit at a validated End of Data. Any identity mismatch mid-stream
//! triggers a full resynchronization (Reset Query), never a splice.
//! Validated data is retained through reconnects and Cache Reset until a
//! full replacement completes or the expire interval passes — except on
//! fatal evidence the cache epoch is invalid (a session-ID mismatch or a
//! received fatal Error Report such as Cache Shutdown), which flushes
//! this cache's data from the merged tables immediately (see
//! `SessionEndDisposition`). Where 8210bis calls for it, an Error
//! Report is sent best-effort before the session is dropped — never in
//! response to a received Error Report. Each transaction is bounded by a
//! deadline and record/byte budgets. See the crate-level docs for the
//! supported RFC 8210 / 8210bis subset.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant as TokioInstant;
use tracing::{debug, error, info, warn};

use crate::aspa::AspaRecord;
use crate::rtr_codec::{RtrDecodeError, RtrEncodeError, RtrPdu};
use crate::vrp::VrpEntry;
use crate::vrp_manager::{CacheUpdateHandle, EnhancedVrpUpdate};

/// Maximum read buffer size (256 KiB).
const MAX_READ_BUF: usize = 256 * 1024;

/// Protocol ceiling for one PDU — 8210bis §5: the Length field "MUST
/// NOT exceed 65,535 octets". The read buffer above is a transport
/// buffer and stays larger; this is the per-frame acceptance limit. An
/// over-limit length field is corrupt framing (Error Code 0).
const MAX_PDU_LEN: usize = 65_535;

// 8210bis §6 legal bounds for the End of Data timing parameters. The
// refresh/retry minimums are 1 s, which every non-zero value already
// satisfies; an End of Data zero is handled as "not provided" (see
// `apply_eod_timers`), and a configured zero is raised to the minimum
// and a configured retry or expire is capped at its maximum (see
// `configured_interval` and `configured_expire`).
const REFRESH_RETRY_MIN_SECS: u64 = 1;
const REFRESH_MAX_SECS: u64 = 86_400;
const RETRY_MAX_SECS: u64 = 7_200;
const EXPIRE_MIN_SECS: u64 = 600;
/// §6 maximum Expire Interval (two days): the longest a router may
/// retain a cache's data without a fresh End of Data. Also the upper
/// bound for an operator `max_expire_interval`.
pub const EXPIRE_MAX_SECS: u64 = 172_800;

/// Wall-clock budget for one RTR transaction (query → End of Data).
/// A full production table transfers in seconds; a cache that cannot
/// complete within this window is broken or hostile.
const TRANSACTION_DEADLINE: Duration = Duration::from_mins(5);

/// Record budget for one RTR transaction (VRPs + ASPAs, announce +
/// withdraw). The global VRP set is well under 1M; 4M leaves years of
/// headroom while bounding worst-case collection memory.
const MAX_TRANSACTION_RECORDS: usize = 4_000_000;

/// Wire-byte budget for one RTR transaction.
const MAX_TRANSACTION_BYTES: usize = 256 * 1024 * 1024;

/// Default cap on the RPKI records one cache may hold: VRPs plus ASPA
/// provider ASNs. The global RPKI publishes about 1.03M VRPs in 2026, so
/// this is roughly four times one complete set.
pub const DEFAULT_MAX_CACHE_RECORDS: usize = 4_000_000;

/// Default cap on the RPKI records held across every cache of a daemon,
/// counted as for [`DEFAULT_MAX_CACHE_RECORDS`]. Three complete caches use
/// about a third of it.
pub const DEFAULT_MAX_TOTAL_RECORDS: usize = 10_000_000;

/// Shared cap on the RPKI records held by every [`RtrClient`] attached to
/// it, counted as VRPs plus ASPA provider ASNs.
///
/// Each client charges records while it decodes a transaction, so a cache
/// is refused before its data is allocated past the cap. Accepted data
/// stays charged for as long as it exists: queued for the
/// [`VrpManager`](crate::VrpManager) or held there, until it is replaced,
/// flushed or expires. A full
/// resynchronization charges the new set while the old one is still held.
#[derive(Debug)]
pub struct RecordBudget {
    limit: usize,
    used: AtomicUsize,
}

impl RecordBudget {
    /// A budget of `limit` records shared by the clients given it.
    #[must_use]
    pub fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            used: AtomicUsize::new(0),
        })
    }

    /// The configured record limit.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Records currently charged by attached clients.
    #[must_use]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    fn reserve(&self, records: usize) -> bool {
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(records)
                    .filter(|total| *total <= self.limit)
            })
            .is_ok()
    }

    fn release(&self, records: usize) {
        self.used.fetch_sub(records, Ordering::AcqRel);
    }
}

/// Records charged to a [`RecordBudget`]. A transaction charges one while
/// it decodes. At End of Data the charge moves with the update to the
/// manager, which keeps it with that cache's data until the data is
/// replaced or removed. Dropping it releases the charge.
#[derive(Debug)]
pub(crate) struct Reservation {
    budget: Arc<RecordBudget>,
    /// All charged records, withdrawals included.
    records: usize,
    /// The withdrawals among `records`. They are charged only while their
    /// update is staged or queued, and released once it is applied.
    withdrawn: usize,
}

impl Reservation {
    pub(crate) fn new(budget: Arc<RecordBudget>) -> Self {
        Self {
            budget,
            records: 0,
            withdrawn: 0,
        }
    }

    fn clear(&mut self) {
        self.withdrawn = 0;
        self.budget.release(std::mem::take(&mut self.records));
    }

    /// Charged announcements, the part that becomes held data.
    fn announced(&self) -> usize {
        self.records - self.withdrawn
    }

    /// Release the withdrawals' share once nothing holds them any more.
    pub(crate) fn release_withdrawn(&mut self) {
        let withdrawn = std::mem::take(&mut self.withdrawn);
        self.records -= withdrawn;
        self.budget.release(withdrawn);
    }

    /// A charge of `records` already reserved on `budget`.
    #[cfg(test)]
    pub(crate) fn charged(budget: &Arc<RecordBudget>, records: usize, withdrawn: usize) -> Self {
        assert!(budget.reserve(records + withdrawn));
        Self {
            budget: Arc::clone(budget),
            records: records + withdrawn,
            withdrawn,
        }
    }

    /// Take over `other`'s charge, which must come from the same budget.
    pub(crate) fn absorb(&mut self, mut other: Self) {
        debug_assert!(Arc::ptr_eq(&self.budget, &other.budget));
        self.records += std::mem::take(&mut other.records);
        self.withdrawn += std::mem::take(&mut other.withdrawn);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.clear();
    }
}

/// After falling back to RTR v1, how long a healthy v1 session runs before
/// the client reconnects to probe v2 again. 8210bis §7: a router "MUST
/// attempt to open" each session at the highest version it implements,
/// and a version can only change on a new transport connection, so a
/// fallback that a transient failure caused is retried on a later
/// connection instead of pinning v1 for the life of the process.
const V2_REPROBE_INTERVAL: Duration = Duration::from_hours(1);

/// Maximum in-transaction restarts (identity mismatch, Cache Reset)
/// before the connection is dropped and retries are paced by
/// `retry_interval`.
const MAX_TRANSACTION_RESTARTS: u8 = 2;

/// Cap on the erroneous-PDU copy embedded in an outgoing Error Report
/// (8210bis §5.11 permits truncation; at least the first four octets
/// must be kept).
const ERROR_PDU_TRUNCATE: usize = 512;

/// Write budget for a teardown Error Report. Emission is best-effort:
/// a cache that has stopped reading must not delay the session drop.
const ERROR_REPORT_WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// RFC 1982 serial-number order: `new` is the same as or after `old`.
fn serial_not_before(old: u32, new: u32) -> bool {
    new.wrapping_sub(old) < (1 << 31)
}

/// One cache epoch: the `(protocol version, session ID, serial)` triple
/// identifying a coherent cache state.
///
/// The three values advance together and are only ever set as a unit, at a
/// validated End of Data. Incremental (Serial Query) data may only be
/// spliced onto a table whose epoch matches the response identity; any
/// mismatch forces a full resynchronization via Reset Query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CacheEpoch {
    version: u8,
    session_id: u16,
    serial: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueryKind {
    Reset,
    Serial,
}

/// Disposition of the cache's held data when a session ends
/// (8210bis §12).
///
/// Every session-ending event classifies as exactly one of these. The
/// epoch and the data are decided separately, because a cache can
/// invalidate its serial epoch without invalidating the data that epoch
/// produced:
///
/// * `RetainAndRetry` — the held data and its epoch both survive:
///   ordinary transport loss, Cache Restart (Error Report code 12,
///   §8.5), and the unsupported-version fallback (code 4, §12: "data
///   previously learned need not be flushed"). The next query may still
///   be incremental. Data is kept until the expire interval passes
///   without a fresh End of Data.
/// * `ResyncAndRetain` — the epoch is void but the data is not. The
///   cache's serial numbers are no longer commensurate with the held
///   ones, so the next query must be a full Reset Query (§8.1); the
///   validated set it replaces stays live meanwhile (§10: "it SHOULD
///   retain the data from the previous cache until it has a full set of
///   data"). Cache Reset (§5.9) is the protocol's own name for this
///   event; a session-ID mismatch (§5.1) is the same event reported as
///   an error rather than as a Cache Reset.
/// * `FlushAndDrop` — the held data itself is gone: the expire interval
///   elapsed (§6) or the cache sent a fatal Error Report, Cache
///   Shutdown (code 13, §8.6 — the operator wants clients to flush) in
///   particular. This cache's VRPs/ASPAs are removed from the merged
///   tables immediately.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionEndDisposition {
    /// Keep validated data and its epoch; reconnect and resume.
    RetainAndRetry,
    /// Keep validated data, drop the epoch; reconnect and resynchronize
    /// with a Reset Query.
    ResyncAndRetain,
    /// Flush this cache's data now and drop the session.
    FlushAndDrop,
}

/// Update messages sent from an RTR client to the VRP manager.
#[derive(Debug, PartialEq, Eq)]
pub enum VrpUpdate {
    /// Full table replacement from a Reset Query response.
    FullTable {
        /// The cache server that sent this table.
        server: SocketAddr,
        /// All VRP entries from the full reset.
        entries: Vec<VrpEntry>,
        /// All ASPA records from the full reset (RTR v2 only).
        aspa_records: Vec<AspaRecord>,
    },
    /// Incremental delta from a Serial Query response.
    IncrementalUpdate {
        /// The cache server that sent this delta.
        server: SocketAddr,
        /// Newly announced VRP entries.
        announced: Vec<VrpEntry>,
        /// Withdrawn VRP entries.
        withdrawn: Vec<VrpEntry>,
        /// Newly announced ASPA records (RTR v2 only).
        aspa_announced: Vec<AspaRecord>,
        /// Withdrawn ASPA records (RTR v2 only).
        aspa_withdrawn: Vec<AspaRecord>,
    },
    /// Server connection lost — its entries should be expired.
    ServerDown {
        /// The cache server that went down.
        server: SocketAddr,
    },
}

/// Configuration for a single RTR cache server connection.
#[derive(Debug, Clone)]
pub struct RtrClientConfig {
    /// TCP address of the RTR cache server.
    pub server_addr: SocketAddr,
    /// Seconds between Serial Query polls. Values below the RFC 8210 §6
    /// minimum of 1 second are raised to 1 second with a warning.
    pub refresh_interval: u64,
    /// Seconds before retrying after a failed connection. Bounded to the
    /// RFC 8210 §6 range of 1 to 7200 seconds with a warning: zero is
    /// raised to 1 second and a value above 7200 seconds is clamped down
    /// to it.
    pub retry_interval: u64,
    /// Seconds after which cached VRPs are considered stale, until the
    /// cache's End of Data supplies its own expire. Zero is raised to the
    /// RFC 8210 §6 minimum of 600 seconds and a value above the §6
    /// two-day maximum (172800 seconds) is clamped down to it, each with
    /// a warning; a non-zero value below the minimum is kept, since
    /// expiring early is safe. A value not above `refresh_interval` or
    /// `retry_interval` is kept as configured: no data is held before the
    /// first End of Data, and from then on the refresh and retry are
    /// lowered below the effective expire (§6).
    pub expire_interval: u64,
    /// Operator ceiling on the effective expire interval in seconds.
    /// The cache-advertised End of Data expire (and `expire_interval`)
    /// is clamped down to it, so data older than this is discarded
    /// regardless of what the cache says. `None`: only the §6 two-day
    /// maximum applies. `Some` is bounded like `expire_interval`: zero
    /// is raised to 600 seconds and a value above 172800 seconds is
    /// clamped down to it, with a warning; a ceiling not above
    /// `refresh_interval` or `retry_interval` lowers them below it at
    /// End of Data.
    pub max_expire_interval: Option<u64>,
}

/// Per-cache-server RTR client.
///
/// Runs as a single tokio task: connects, exchanges RTR PDUs, sends VRP
/// updates to the manager, and reconnects on failure.
pub struct RtrClient {
    config: RtrClientConfig,
    /// The cache epoch backing the currently held data, if any.
    epoch: Option<CacheEpoch>,
    vrp_tx: mpsc::Sender<VrpUpdate>,
    enhanced_tx: Option<CacheUpdateHandle>,
    refresh_interval: Duration,
    retry_interval: Duration,
    expire_interval: Duration,
    last_end_of_data_at: Option<TokioInstant>,
    data_expires_at: Option<TokioInstant>,
    /// Protocol version used for the current connection attempt
    /// (2 = ASPA capable, 1 = VRP only).
    negotiated_version: u8,
    /// Whether §7 version negotiation has completed for the current
    /// transport session: flips when the cache's first response PDU at
    /// the attempted version is accepted (normally the Cache Response
    /// that "opens" the session), and resets on every new connection.
    /// Until then, Serial Notify PDUs are ignored regardless of their
    /// version field (§5.2/§7).
    negotiation_complete: bool,
    /// When a v1 session, entered by falling back from v2, next reconnects
    /// to probe v2 again. See [`V2_REPROBE_INTERVAL`].
    v2_reprobe_at: Option<TokioInstant>,
    /// Per-transaction budgets (consts in production; shrunk in tests).
    transaction_deadline: Duration,
    max_transaction_records: usize,
    max_transaction_bytes: usize,
    /// Records this cache may hold; see [`Self::with_record_limits`].
    max_records: usize,
    /// Cap shared with the daemon's other clients.
    record_budget: Arc<RecordBudget>,
    /// Records counted against `max_records` for the held data. An upper
    /// bound on this cache's contribution: a full table sets it to the
    /// transfer's size, and a serial delta adds its announcements without
    /// subtracting withdrawals, so withdrawing records never held cannot
    /// lower it.
    held_records: usize,
    /// The held data's charge on `record_budget`, kept here only without
    /// the cache inventory. With it, the charge travels with each update
    /// and the manager holds it beside the data.
    held_charge: Option<Reservation>,
    /// Told the effective expire interval (seconds) at start and after
    /// every End of Data; see [`Self::with_expire_observer`].
    expire_observer: Option<Box<dyn Fn(u64) + Send + Sync>>,
    /// Told each time the client restarts after a panic; see
    /// [`Self::with_restart_observer`].
    restart_observer: Option<Box<dyn Fn() + Send + Sync>>,
    /// Opens every transport connection to the cache; see
    /// [`Self::with_dialer`]. `None` is a plain `TcpStream::connect`.
    dialer: Option<RtrDialer>,
}

/// Drive `future` to completion, or to `None` if it panics. The panic hook
/// has already reported the panic; the future is dropped without another
/// poll.
async fn catch_panic<F: Future>(future: F) -> Option<F::Output> {
    let mut future = std::pin::pin!(future);
    std::future::poll_fn(|cx| {
        // Unwind safety: the panicked future is never polled again, and its
        // locals (the stream, the staged transaction and its record charge)
        // were dropped by the unwind. What outlives it is the `RtrClient`
        // the future borrowed, used only by `restart_after_panic`. Its
        // fields may hold values from an End of Data whose update was not
        // delivered:
        // - `epoch`: cleared by the restart, so the next query is a Reset
        //   Query.
        // - `held_records` and `held_charge`: an over-count at worst; the
        //   full table that answers the Reset Query replaces both.
        // - `refresh_interval`, `retry_interval`, `expire_interval`: the
        //   cache's own advertised timers, each already bounded; the retry
        //   sleep is capped at the expiry instant whatever their relation.
        // - `last_end_of_data_at` and `data_expires_at`: see
        //   `restart_after_panic`.
        // - `negotiated_version`, `negotiation_complete`, `v2_reprobe_at`:
        //   connection state that every new connection attempt re-derives.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| future.as_mut().poll(cx)))
            .map_or(Poll::Ready(None), |poll| poll.map(Some))
    })
    .await
}

/// Bound a configured refresh/retry interval to the §6 minimum and the
/// given maximum, warning with both values. Zero would poll or reconnect
/// with no delay. A retry above its maximum would, before any End of Data
/// has lowered it, park the reconnect sleep at tokio's far-future deadline
/// so the client never retried.
fn configured_interval(server: SocketAddr, timer: &'static str, value: u64, max: u64) -> Duration {
    let bounded = value.clamp(REFRESH_RETRY_MIN_SECS, max);
    if bounded != value {
        warn!(
            server = %server,
            timer,
            value,
            bounded,
            "RTR configured timer outside the §6 range, bounded"
        );
    }
    Duration::from_secs(bounded)
}

/// Bound a configured expire interval or ceiling to the §6 range,
/// warning with both values. Zero is raised to the 600 s minimum: it
/// would otherwise arm expiry at the End of Data instant whenever the
/// cache omits its expire, flushing the table just fetched. A value above
/// the two-day maximum is clamped down to it — the longest retention a
/// cache can legally indicate, and a deadline the timer can represent. A
/// non-zero value below the minimum is kept, as at End of Data: expiring
/// early is safe.
fn configured_expire(server: SocketAddr, timer: &'static str, value: u64) -> u64 {
    let bounded = if value == 0 {
        EXPIRE_MIN_SECS
    } else {
        value.min(EXPIRE_MAX_SECS)
    };
    if bounded != value {
        warn!(
            server = %server,
            timer,
            value,
            bounded,
            "RTR configured expire outside the §6 range, bounded"
        );
    }
    bounded
}

/// Boxed connection opener installed by [`RtrClient::with_dialer`].
type RtrDialer = Box<
    dyn Fn(SocketAddr) -> Pin<Box<dyn Future<Output = std::io::Result<TcpStream>> + Send>>
        + Send
        + Sync,
>;

impl RtrClient {
    /// Create a new RTR client.
    #[must_use]
    pub fn new(mut config: RtrClientConfig, vrp_tx: mpsc::Sender<VrpUpdate>) -> Self {
        let server = config.server_addr;
        config.max_expire_interval = config
            .max_expire_interval
            .map(|max| configured_expire(server, "max_expire", max));
        let expire = configured_expire(server, "expire", config.expire_interval);
        Self {
            // No refresh ceiling: refresh is first used after an End of
            // Data, which keeps it below the bounded expire.
            refresh_interval: configured_interval(
                server,
                "refresh",
                config.refresh_interval,
                u64::MAX,
            ),
            retry_interval: configured_interval(
                server,
                "retry",
                config.retry_interval,
                RETRY_MAX_SECS,
            ),
            expire_interval: Duration::from_secs(
                config
                    .max_expire_interval
                    .map_or(expire, |max| expire.min(max)),
            ),
            last_end_of_data_at: None,
            data_expires_at: None,
            vrp_tx,
            enhanced_tx: None,
            config,
            epoch: None,
            negotiated_version: crate::rtr_codec::RTR_VERSION_2,
            negotiation_complete: false,
            v2_reprobe_at: None,
            transaction_deadline: TRANSACTION_DEADLINE,
            max_transaction_records: MAX_TRANSACTION_RECORDS,
            max_transaction_bytes: MAX_TRANSACTION_BYTES,
            max_records: DEFAULT_MAX_CACHE_RECORDS,
            record_budget: RecordBudget::new(DEFAULT_MAX_TOTAL_RECORDS),
            held_records: 0,
            held_charge: None,
            expire_observer: None,
            restart_observer: None,
            dialer: None,
        }
    }

    /// Cap the RPKI records this cache may hold at `max_records` and charge
    /// them to `budget`, which the daemon shares across all of its clients.
    /// Records are VRPs plus ASPA provider ASNs.
    ///
    /// A transaction that would exceed either cap is refused while it is
    /// decoded, before its records are published or applied. With
    /// [`Self::with_cache_inventory`], each accepted update carries its
    /// charge to the [`VrpManager`](crate::VrpManager), which releases it
    /// when that data is replaced or removed, so updates still queued for
    /// the manager stay charged. Without it, the client keeps the charge
    /// for its last accepted data and releases it on the next full table,
    /// on flush or expiry, or when the client is dropped. The session
    /// ends with [`RtrError::RecordLimit`], the cache's previously accepted
    /// data is kept, and the next connection asks for a full table with a
    /// Reset Query. If no full table fits, the kept data is dropped when it
    /// expires. Without this call a client uses
    /// [`DEFAULT_MAX_CACHE_RECORDS`] and its own [`DEFAULT_MAX_TOTAL_RECORDS`]
    /// budget.
    #[must_use]
    pub fn with_record_limits(mut self, max_records: usize, budget: Arc<RecordBudget>) -> Self {
        self.max_records = max_records;
        self.record_budget = budget;
        self
    }

    /// Charge `records` announced by the transaction in progress against
    /// this cache's cap and the shared budget.
    fn charge(
        &self,
        reservation: &mut Reservation,
        is_reset: bool,
        records: usize,
    ) -> Result<(), RtrError> {
        // A full table replaces the held data; a delta adds to it.
        let base = if is_reset { 0 } else { self.held_records };
        if base
            .saturating_add(reservation.announced())
            .saturating_add(records)
            > self.max_records
        {
            return Err(RtrError::RecordLimit(if is_reset {
                "full table exceeds the per-cache record limit"
            } else {
                "serial update would exceed the per-cache record limit"
            }));
        }
        if !self.record_budget.reserve(records) {
            return Err(RtrError::RecordLimit("total RPKI record limit reached"));
        }
        reservation.records += records;
        Ok(())
    }

    /// Charge one staged withdrawal against the shared budget only: it adds
    /// nothing to the cache's held data, but its update takes memory until
    /// it is applied.
    fn charge_withdrawal(&self, reservation: &mut Reservation) -> Result<(), RtrError> {
        if !self.record_budget.reserve(1) {
            return Err(RtrError::RecordLimit("total RPKI record limit reached"));
        }
        reservation.records += 1;
        reservation.withdrawn += 1;
        Ok(())
    }

    /// Forget the held data's count when the data is flushed. With the
    /// cache inventory, the manager releases the charge when it removes
    /// the data.
    fn release_held_records(&mut self) {
        self.held_records = 0;
        self.held_charge = None;
    }

    /// Route validated cache epochs and connection lifecycle through the
    /// manager's atomic cache-inventory attachment.
    #[must_use]
    pub fn with_cache_inventory(mut self, handle: CacheUpdateHandle) -> Self {
        self.enhanced_tx = Some(handle);
        self
    }

    async fn send_enhanced(&self, update: EnhancedVrpUpdate) {
        if let Some(handle) = &self.enhanced_tx {
            let _ = handle.0.send(update).await;
        }
    }

    /// Report the effective expire interval (seconds) to `observer` at
    /// start and after every End of Data — the hook behind the
    /// `bgp_rpki_cache_effective_expire_seconds` gauge.
    #[must_use]
    pub fn with_expire_observer(mut self, observer: impl Fn(u64) + Send + Sync + 'static) -> Self {
        self.expire_observer = Some(Box::new(observer));
        self
    }

    /// Call `observer` each time [`Self::run`] recovers from a panic by
    /// restarting the cache's session — the hook behind the
    /// `bgp_rpki_rtr_client_restarts_total` counter.
    #[must_use]
    pub fn with_restart_observer(mut self, observer: impl Fn() + Send + Sync + 'static) -> Self {
        self.restart_observer = Some(Box::new(observer));
        self
    }

    fn observe_expire(&self) {
        if let Some(observer) = &self.expire_observer {
            observer(self.expire_interval.as_secs());
        }
    }

    /// Open every transport connection through `dial` instead of a plain
    /// `TcpStream::connect`. The embedding daemon uses this to install
    /// socket options such as TCP MD5 or TCP-AO before connect; a dial
    /// error is a failed connection attempt that is retried after the
    /// retry interval, never a plaintext fallback.
    #[must_use]
    pub fn with_dialer<F, Fut>(mut self, dial: F) -> Self
    where
        F: Fn(SocketAddr) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = std::io::Result<TcpStream>> + Send + 'static,
    {
        self.dialer = Some(Box::new(move |addr| Box::pin(dial(addr))));
        self
    }

    async fn dial(&self) -> std::io::Result<TcpStream> {
        let connect = async {
            match &self.dialer {
                Some(dial) => dial(self.config.server_addr).await,
                None => TcpStream::connect(self.config.server_addr).await,
            }
        };
        // §6: held data MUST NOT be kept past its expire interval. A
        // connection attempt that hangs past that instant ends there, and
        // the failed-attempt path flushes the expired data.
        let Some(expires_at) = self.data_expires_at else {
            return connect.await;
        };
        tokio::time::timeout_at(expires_at, connect)
            .await
            .unwrap_or_else(|_| {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "held RTR data expired while connecting",
                ))
            })
    }

    /// Main event loop — connects, keeps the RTR session open, and reconnects
    /// on failure.
    ///
    /// A panic while connecting or running a session is handled as a lost
    /// session: the cache's validated data is retained until its expire
    /// interval, and the client reconnects after the retry interval and
    /// resynchronizes with a Reset Query.
    pub async fn run(mut self) {
        self.observe_expire();
        loop {
            self.prepare_fresh_connection_attempt();
            match catch_panic(self.connect_and_run()).await {
                Some(Ok(())) => {}
                Some(Err(e)) => {
                    warn!(
                        server = %self.config.server_addr,
                        error = %e,
                        "RTR connection failed"
                    );
                    self.handle_disconnected_session(false).await;
                }
                None => self.restart_after_panic().await,
            }
        }
    }

    /// Recover from a panic in a connection attempt or session, whose
    /// stream the unwind already closed. The held data and its expiry
    /// instant are kept, exactly as for a dropped connection. The epoch is
    /// not: the panic may have struck after the epoch advanced but before
    /// its update reached the manager, so only a full table is known to
    /// match what the manager holds.
    ///
    /// End of Data sets the expiry instant before it sends the update, so
    /// data that reached the manager always has a deadline. The cost is one
    /// window: a panic after the instant is set and before the send leaves
    /// the previous data held under the new End of Data's deadline, up to
    /// one expire interval past its own. The other order would be worse: a
    /// panic after the send would leave delivered data with the older
    /// deadline, or with none after a first End of Data, and data with no
    /// deadline is never flushed.
    async fn restart_after_panic(&mut self) {
        error!(
            server = %self.config.server_addr,
            "RTR client panicked; restarting its session with the held data retained"
        );
        if let Some(observer) = &self.restart_observer {
            observer();
        }
        self.send_enhanced(EnhancedVrpUpdate::Disconnected {
            server: self.config.server_addr,
            flush: false,
        })
        .await;
        self.epoch = None;
        self.handle_disconnected_session(false).await;
    }

    fn prepare_fresh_connection_attempt(&mut self) {
        // Reconnect at the version the held data was validated under.
        // Re-probing v2 while holding a v1 epoch wedges against v1-only
        // caches (StayRTR, GoRTR): they answer the v2 query with a
        // version-0 Error Report, which fails the version check as a
        // decode-level mismatch, and with data held no fallback signal
        // fires — the client would loop until the data expired and
        // validation flapped. A downgraded cache that merely restarted
        // must instead re-land its v1 session within one retry, with
        // full retention.
        //
        // v2 upgrade policy: the preferred version is deliberately
        // re-probed only at the epoch-less points — initial start and
        // after data expiry (see `handle_disconnected_session`) — so a
        // cache that later gains v2 support is still discovered without
        // risking held data. With no epoch, keep the current (possibly
        // downgraded) version so the v1 fallback sticks across retries.
        if let Some(epoch) = self.epoch {
            self.negotiated_version = epoch.version;
        }
        if self.v2_reprobe_due() {
            // The held v1 data stays live: the probe is a v2 Reset Query,
            // and a refusal falls straight back to v1 with that epoch.
            self.negotiated_version = crate::rtr_codec::RTR_VERSION_2;
        }
    }

    /// A fallback to v1 is old enough to try v2 again.
    fn v2_reprobe_due(&self) -> bool {
        self.negotiated_version != crate::rtr_codec::RTR_VERSION_2
            && self
                .v2_reprobe_at
                .is_some_and(|at| TokioInstant::now() >= at)
    }

    async fn connect_and_run(&mut self) -> Result<(), std::io::Error> {
        let mut stream = self.dial().await?;
        let mut disconnect_sent = false;
        self.send_enhanced(EnhancedVrpUpdate::Connected {
            server: self.config.server_addr,
        })
        .await;
        info!(
            server = %self.config.server_addr,
            rtr_version = self.negotiated_version,
            "RTR connected"
        );

        if let Err(error) = self.run_session(&mut stream).await {
            // Close before flushing/retrying so the cache sees the drop
            // (the teardown Error Report, if any, was already sent).
            drop(stream);
            if self.should_fallback_to_v1(&error) {
                self.send_enhanced(EnhancedVrpUpdate::Disconnected {
                    server: self.config.server_addr,
                    flush: false,
                })
                .await;
                self.run_v1_fallback_session().await;
                return Ok(());
            }

            warn!(
                server = %self.config.server_addr,
                error = %error,
                "RTR session ended"
            );
            disconnect_sent = true;
            if error.disposition() != SessionEndDisposition::FlushAndDrop {
                self.send_enhanced(EnhancedVrpUpdate::Disconnected {
                    server: self.config.server_addr,
                    flush: false,
                })
                .await;
            }
            self.end_session(&error).await;
        }

        if !disconnect_sent {
            self.send_enhanced(EnhancedVrpUpdate::Disconnected {
                server: self.config.server_addr,
                flush: false,
            })
            .await;
        }

        Ok(())
    }

    /// Apply the error's [`SessionEndDisposition`] and pace the retry.
    async fn end_session(&mut self, error: &RtrError) {
        let disposition = error.disposition();
        if disposition == SessionEndDisposition::ResyncAndRetain {
            // Serial numbers are no longer commensurate with the held
            // ones, so the epoch cannot carry an incremental query.
            // Dropping it alone makes the next query a Reset Query
            // (`current_query_kind`) while the data it will replace
            // stays live — the same retain-and-resynchronize shape the
            // in-transaction serial-regression path already takes.
            self.epoch = None;
        }
        self.handle_disconnected_session(disposition == SessionEndDisposition::FlushAndDrop)
            .await;
    }

    fn should_fallback_to_v1(&self, error: &RtrError) -> bool {
        if self.negotiated_version != crate::rtr_codec::RTR_VERSION_2 {
            return false;
        }
        // Explicit "Unsupported Protocol Version" error (code 4).
        if matches!(error, RtrError::ServerError { code: 4, .. }) {
            return true;
        }
        // Server closed the connection, or answered with a lower version
        // byte, before this attempt's version was accepted: no epoch is
        // held, or the held epoch is from v1 and this attempt probes v2.
        // Real-world caches like GoRTR and StayRTR disconnect on
        // unsupported versions instead of sending error code 4. A PDU that
        // carries the probed version but fails to decode is not a refusal:
        // the cache speaks that version, and the error takes its own
        // handling (a corrupt Prefix PDU flushes, §12), whether or not a
        // Cache Response came first. Once the cache has answered at v2,
        // negotiation is over and no failure is a refusal.
        !self.negotiation_complete
            && self
                .epoch
                .is_none_or(|epoch| epoch.version < self.negotiated_version)
            && matches!(
                error,
                RtrError::Io(_) | RtrError::ConnectionClosed | RtrError::VersionMismatch { .. }
            )
    }

    async fn run_v1_fallback_session(&mut self) {
        info!(
            server = %self.config.server_addr,
            "RTR server does not support v2, falling back to v1 (no ASPA)"
        );
        self.negotiated_version = crate::rtr_codec::RTR_VERSION;
        self.v2_reprobe_at = Some(TokioInstant::now() + V2_REPROBE_INTERVAL);
        // A v2 epoch is not valid at v1, so the next query is a full Reset
        // Query; held data and its expiry are retained until the v1 full
        // table replaces them or the expire interval passes. A v1 epoch
        // (a failed v2 re-probe) stays, and the v1 session resumes with a
        // Serial Query.
        if self
            .epoch
            .is_some_and(|epoch| epoch.version != crate::rtr_codec::RTR_VERSION)
        {
            self.epoch = None;
        }

        match self.dial().await {
            Ok(mut stream) => {
                let mut disconnect_sent = false;
                self.send_enhanced(EnhancedVrpUpdate::Connected {
                    server: self.config.server_addr,
                })
                .await;
                info!(
                    server = %self.config.server_addr,
                    rtr_version = self.negotiated_version,
                    "RTR reconnected with fallback version"
                );
                if let Err(error) = self.run_session(&mut stream).await {
                    drop(stream);
                    warn!(
                        server = %self.config.server_addr,
                        error = %error,
                        "RTR session ended after v1 fallback"
                    );
                    disconnect_sent = true;
                    if error.disposition() != SessionEndDisposition::FlushAndDrop {
                        self.send_enhanced(EnhancedVrpUpdate::Disconnected {
                            server: self.config.server_addr,
                            flush: false,
                        })
                        .await;
                    }
                    self.end_session(&error).await;
                }
                if !disconnect_sent {
                    self.send_enhanced(EnhancedVrpUpdate::Disconnected {
                        server: self.config.server_addr,
                        flush: false,
                    })
                    .await;
                }
            }
            Err(error) => {
                warn!(
                    server = %self.config.server_addr,
                    error = %error,
                    "RTR reconnection for v1 fallback failed"
                );
                self.handle_disconnected_session(false).await;
            }
        }
    }

    /// Handle a lost or failed session.
    ///
    /// Validated data is RETAINED through reconnect: `ServerDown` (which
    /// drops the cache's entries from the merged tables) is only sent once
    /// the expire interval passes without a fresh End of Data — detected
    /// here while retrying — or when the session ended with a
    /// [`SessionEndDisposition::FlushAndDrop`] event (`flush_now`): data
    /// expiry (§6) or a received fatal Error Report (8210bis §12). A mere
    /// disconnect must not flap route validation, and neither must a
    /// cache rotating its session ID.
    ///
    /// The eager flush is this same expiry path invoked immediately:
    /// `ServerDown` makes the VRP manager remove exactly this cache's
    /// VRPs and ASPAs from the merged tables and redistribute, so route
    /// validation re-runs just as it does at expiry.
    async fn handle_disconnected_session(&mut self, flush_now: bool) {
        let now = TokioInstant::now();
        let expired = flush_now || self.data_expires_at.is_some_and(|at| now >= at);
        if expired {
            if let Some(handle) = &self.enhanced_tx {
                let update = if flush_now {
                    EnhancedVrpUpdate::Disconnected {
                        server: self.config.server_addr,
                        flush: true,
                    }
                } else {
                    EnhancedVrpUpdate::Expired {
                        server: self.config.server_addr,
                    }
                };
                let _ = handle.0.send(update).await;
            } else {
                let _ = self
                    .vrp_tx
                    .send(VrpUpdate::ServerDown {
                        server: self.config.server_addr,
                    })
                    .await;
            }
            self.epoch = None;
            self.last_end_of_data_at = None;
            self.data_expires_at = None;
            self.release_held_records();
            // Data expiry is the deliberate v2 re-probe point: with
            // nothing held there is no retention to protect, so try the
            // preferred version again in case the cache gained v2
            // support. A still-v1-only cache answers the probe with a
            // rejection, and the epoch-less fallback path re-lands v1.
            self.negotiated_version = crate::rtr_codec::RTR_VERSION_2;
        }
        // Wake at expiry if it lands inside the retry window, so retained
        // data cannot outlive its expire interval across failed retries.
        let sleep_for = self.data_expires_at.map_or(self.retry_interval, |at| {
            self.retry_interval.min(at.saturating_duration_since(now))
        });
        tokio::time::sleep(sleep_for).await;
    }

    fn current_query_kind(&self) -> QueryKind {
        // An epoch is only usable for incremental queries at the version
        // it was established under; after a version change the next query
        // must be a full Reset Query.
        match self.epoch {
            Some(epoch) if epoch.version == self.negotiated_version => QueryKind::Serial,
            _ => QueryKind::Reset,
        }
    }

    fn build_query_pdu(&self, query: QueryKind) -> RtrPdu {
        match (query, self.epoch) {
            (QueryKind::Serial, Some(epoch)) => RtrPdu::SerialQuery {
                session_id: epoch.session_id,
                serial: epoch.serial,
            },
            _ => RtrPdu::ResetQuery,
        }
    }

    /// Pop the next complete PDU off `parse_buf`, enforcing that its
    /// version byte matches the negotiated connection version so records
    /// from different protocol versions can never mix in one session.
    ///
    /// The version guard only applies once §7 negotiation has completed:
    /// until then, Serial Notify frames are discarded before it runs.
    fn next_pdu(&mut self, parse_buf: &mut Vec<u8>) -> Result<Option<RtrPdu>, RtrError> {
        loop {
            if parse_buf.len() < 8 {
                return Ok(None);
            }
            let Some(pdu_len) = RtrPdu::peek_length(parse_buf) else {
                return Ok(None);
            };
            let pdu_len = pdu_len as usize;
            // §5: the Length field "MUST NOT exceed 65,535 octets". An
            // over-limit length is corrupt framing — fail now instead
            // of buffering toward a frame that can never be legal.
            if pdu_len > MAX_PDU_LEN {
                return Err(RtrError::Decode(RtrDecodeError::InvalidLength));
            }
            if parse_buf.len() < pdu_len {
                return Ok(None);
            }
            // 8210bis §5.2/§7: a cache MAY send a Serial Notify at any
            // time, including between the router's first query and the
            // response that completes version negotiation, and during
            // that window the router "MUST ignore any Serial Notify
            // PDUs ... regardless of the Protocol Version field" (§7).
            // It must neither fail the session nor influence
            // negotiation: acting on it would only re-issue the query
            // already outstanding, so even a correct-version notify is
            // a no-op here. In particular, on a v1-pinned reconnect
            // (held-epoch version pinning), a v0/v2 Serial Notify in
            // this window is NOT an upgrade/downgrade hint — the pinned
            // version stands until the cache's actual response.
            // The `pdu_len >= 8` guard keeps a frame with a corrupt
            // length field on the normal error path below.
            if !self.negotiation_complete
                && pdu_len >= 8
                && parse_buf[1] == crate::rtr_codec::PDU_SERIAL_NOTIFY
            {
                debug!(
                    server = %self.config.server_addr,
                    version = parse_buf[0],
                    "RTR Serial Notify before negotiation completed (ignored)"
                );
                parse_buf.drain(..pdu_len);
                continue;
            }
            let got = parse_buf[0];
            if got != self.negotiated_version {
                return Err(RtrError::VersionMismatch {
                    expected: self.negotiated_version,
                    got,
                });
            }
            let (pdu, consumed) = RtrPdu::decode(parse_buf).map_err(RtrError::Decode)?;
            parse_buf.drain(..consumed);
            // §7: the cache's first (non-Notify) PDU at the attempted
            // version — normally the Cache Response that opens the
            // session — completes negotiation.
            self.negotiation_complete = true;
            return Ok(Some(pdu));
        }
    }

    /// Adopt the End of Data timing parameters, bounded by §6.
    ///
    /// * Zero means "not provided" and leaves the current value alone
    ///   (every §6 minimum is at least 1 s, so zero is never a legal
    ///   value a cache could mean literally).
    /// * A value above its §6 maximum (refresh 86400 s, retry 7200 s,
    ///   expire 172800 s) is clamped down to that maximum — for expire
    ///   in particular, the router "MUST NOT retain the data past the
    ///   time indicated", and two days is the largest interval a cache
    ///   can legally indicate.
    /// * An expire below the §6 minimum of 600 s is used as-is with a
    ///   warning: expiring early is always safe, while raising it would
    ///   retain data longer than the cache said.
    /// * An operator `max_expire_interval` is a stricter ceiling applied
    ///   the same way: the expire is clamped down to it, never raised,
    ///   and the data takes the ordinary expiry path at that point.
    /// * §6: "Caches MUST set Expire Interval to a value larger than
    ///   both the Refresh Interval and the Retry Interval." On
    ///   violation the effective refresh/retry are lowered below the
    ///   expire so a successful re-query can land before the data dies
    ///   — never the other way around, which would extend retention.
    fn apply_eod_timers(&mut self, refresh: u32, retry: u32, expire: u32) {
        if refresh > 0 {
            self.refresh_interval = Duration::from_secs(self.bounded_timer(
                "refresh",
                u64::from(refresh),
                REFRESH_MAX_SECS,
            ));
        }
        if retry > 0 {
            self.retry_interval =
                Duration::from_secs(self.bounded_timer("retry", u64::from(retry), RETRY_MAX_SECS));
        }
        if expire > 0 {
            let mut expire = self.bounded_timer("expire", u64::from(expire), EXPIRE_MAX_SECS);
            if expire < EXPIRE_MIN_SECS {
                warn!(
                    server = %self.config.server_addr,
                    expire,
                    minimum = EXPIRE_MIN_SECS,
                    "RTR End of Data expire interval below the §6 minimum (using as-is: expiring early is safe)"
                );
            }
            if let Some(max) = self.config.max_expire_interval
                && expire > max
            {
                warn!(
                    server = %self.config.server_addr,
                    expire,
                    max_expire_interval = max,
                    "RTR End of Data expire interval above the configured max_expire_interval, clamped"
                );
                expire = max;
            }
            self.expire_interval = Duration::from_secs(expire);
        }
        let expire_interval = self.expire_interval;
        let floor = expire_interval
            .saturating_sub(Duration::from_secs(1))
            .max(Duration::from_secs(1));
        if self.refresh_interval >= expire_interval {
            warn!(
                server = %self.config.server_addr,
                refresh_secs = self.refresh_interval.as_secs(),
                expire_secs = expire_interval.as_secs(),
                "RTR refresh interval not below expire interval (§6), lowering refresh"
            );
            self.refresh_interval = floor;
        }
        if self.retry_interval >= expire_interval {
            warn!(
                server = %self.config.server_addr,
                retry_secs = self.retry_interval.as_secs(),
                expire_secs = expire_interval.as_secs(),
                "RTR retry interval not below expire interval (§6), lowering retry"
            );
            self.retry_interval = floor;
        }
        self.observe_expire();
    }

    /// Clamp one End of Data timer to its §6 maximum, warning with both
    /// the received and effective values.
    fn bounded_timer(&self, timer: &'static str, value: u64, max: u64) -> u64 {
        if value > max {
            warn!(
                server = %self.config.server_addr,
                timer,
                value,
                clamped = max,
                "RTR End of Data timer above the §6 maximum, clamped"
            );
        }
        value.min(max)
    }

    async fn send_query(&self, stream: &mut TcpStream, query: QueryKind) -> Result<bool, RtrError> {
        let query_pdu = self.build_query_pdu(query);
        let is_reset = matches!(query_pdu, RtrPdu::ResetQuery);
        let mut send_buf = Vec::new();
        query_pdu.encode_with_version(&mut send_buf, self.negotiated_version)?;
        stream.write_all(&send_buf).await.map_err(RtrError::Io)?;
        Ok(is_reset)
    }

    async fn run_session(&mut self, stream: &mut TcpStream) -> Result<(), RtrError> {
        // Every transport connection restarts §7 version negotiation.
        self.negotiation_complete = false;
        let mut read_buf = vec![0u8; 8192];
        let mut parse_buf = Vec::new();
        let mut next_query = self.current_query_kind();

        let result = loop {
            if let Err(error) = self
                .fetch_until_end_of_data(stream, &mut read_buf, &mut parse_buf, next_query)
                .await
            {
                break error;
            }
            match self
                .wait_for_next_query(stream, &mut read_buf, &mut parse_buf)
                .await
            {
                // Instead of the next query on this v1 session, reconnect
                // to probe v2 (§7: the version changes only on a new
                // connection).
                Ok(_) if self.v2_reprobe_due() => {
                    info!(
                        server = %self.config.server_addr,
                        "RTR reconnecting to probe protocol v2 after a v1 fallback"
                    );
                    return Ok(());
                }
                Ok(query) => next_query = query,
                Err(error) => break error,
            }
        };

        // An Error Report, where the draft calls for one, is sent
        // BEFORE the session is dropped (8210bis §5.11, §12) — and
        // never in response to a received Error Report.
        if let Some((code, pdu, text)) =
            teardown_report(&result, &parse_buf, self.negotiation_complete)
        {
            self.send_error_report(stream, code, &pdu, text).await;
        }
        Err(result)
    }

    /// Best-effort transmission of an Error Report just before the
    /// session is dropped. A cache that has stopped reading must not
    /// block the drop: the write is bounded by a short timeout and any
    /// failure is ignored.
    async fn send_error_report(
        &self,
        stream: &mut TcpStream,
        code: u16,
        erroneous_pdu: &[u8],
        text: &str,
    ) {
        // §5.11: a too-large erroneous PDU MUST be truncated (keeping
        // at least the first four octets).
        let pdu = erroneous_pdu[..erroneous_pdu.len().min(ERROR_PDU_TRUNCATE)].to_vec();
        let report = RtrPdu::ErrorReport {
            code,
            pdu,
            text: text.to_string(),
        };
        let mut buf = Vec::new();
        if report
            .encode_with_version(&mut buf, self.negotiated_version)
            .is_err()
        {
            return;
        }
        debug!(
            server = %self.config.server_addr,
            code,
            text,
            "sending RTR error report before dropping session"
        );
        let _ = tokio::time::timeout(ERROR_REPORT_WRITE_TIMEOUT, stream.write_all(&buf)).await;
    }

    fn handle_idle_pdus(&mut self, parse_buf: &mut Vec<u8>) -> Result<Option<QueryKind>, RtrError> {
        let mut next_query = None;

        while let Some(pdu) = self.next_pdu(parse_buf)? {
            match pdu {
                RtrPdu::SerialNotify { session_id, serial } => {
                    debug!(
                        server = %self.config.server_addr,
                        session_id,
                        serial,
                        "RTR Serial Notify received"
                    );
                    let query = if self.epoch.map(|e| e.session_id) == Some(session_id) {
                        self.current_query_kind()
                    } else {
                        QueryKind::Reset
                    };
                    if !matches!(next_query, Some(QueryKind::Reset)) {
                        next_query = Some(query);
                    }
                }
                RtrPdu::CacheReset => {
                    // The epoch is gone but the data is still the most
                    // recent validated state — retain it (and its expiry)
                    // until the Reset Query's full table replaces it.
                    info!(
                        server = %self.config.server_addr,
                        "RTR cache reset received while idle, resynchronizing with Reset Query"
                    );
                    self.epoch = None;
                    next_query = Some(QueryKind::Reset);
                }
                RtrPdu::ErrorReport { code, text, .. } => {
                    warn!(
                        server = %self.config.server_addr,
                        code,
                        text = %text,
                        "RTR error report received"
                    );
                    return Err(RtrError::ServerError { code, text });
                }
                _ => {
                    debug!(
                        server = %self.config.server_addr,
                        ?pdu,
                        "unexpected RTR PDU while idle (ignored)"
                    );
                }
            }
        }

        Ok(next_query)
    }

    async fn wait_for_next_query(
        &mut self,
        stream: &mut TcpStream,
        read_buf: &mut [u8],
        parse_buf: &mut Vec<u8>,
    ) -> Result<QueryKind, RtrError> {
        let refresh_deadline = TokioInstant::now() + self.refresh_interval;
        let mut refresh_sleep = Box::pin(tokio::time::sleep_until(refresh_deadline));
        let has_expiry = self.data_expires_at.is_some();
        let fallback_expiry = refresh_deadline + Duration::from_hours(24 * 365);
        let mut expire_sleep = Box::pin(tokio::time::sleep_until(
            self.data_expires_at.unwrap_or(fallback_expiry),
        ));

        loop {
            if let Some(query) = self.handle_idle_pdus(parse_buf)? {
                return Ok(query);
            }

            tokio::select! {
                read = stream.read(read_buf) => {
                    let n = read.map_err(RtrError::Io)?;
                    if n == 0 {
                        return Err(RtrError::ConnectionClosed);
                    }
                    parse_buf.extend_from_slice(&read_buf[..n]);
                    if parse_buf.len() > MAX_READ_BUF {
                        return Err(RtrError::BufferOverflow);
                    }
                }
                () = refresh_sleep.as_mut() => {
                    debug!(
                        server = %self.config.server_addr,
                        interval = ?self.refresh_interval,
                        "RTR refresh timer fired, requesting update"
                    );
                    return Ok(self.current_query_kind());
                }
                () = expire_sleep.as_mut(), if has_expiry => {
                    return Err(RtrError::Expired);
                }
            }
        }
    }

    /// Fetch VRPs until `EndOfData`, then publish the resulting update.
    ///
    /// One call is one bounded RTR transaction: it is limited by a
    /// wall-clock deadline and record/byte budgets, and every response's
    /// identity (session ID, serial progression) is validated against the
    /// held [`CacheEpoch`] before its records may replace or extend the
    /// table. On any identity mismatch the response is discarded and the
    /// client resynchronizes with a full Reset Query — it never splices.
    #[expect(
        clippy::too_many_lines,
        reason = "RTR transaction keeps identity checks, collection, budgets, and publish ordering together"
    )]
    async fn fetch_until_end_of_data(
        &mut self,
        stream: &mut TcpStream,
        read_buf: &mut [u8],
        parse_buf: &mut Vec<u8>,
        mut query: QueryKind,
    ) -> Result<(), RtrError> {
        let deadline = TokioInstant::now() + self.transaction_deadline;
        // §6: the held data expires on time even while a query is in
        // flight; a transaction still running then ends and the data is
        // flushed. The bound covers every read and every query write: a
        // cache that stops reading can fill the socket buffers and stall a
        // write as long as one that stops sending stalls a read.
        let expires_at = self.data_expires_at;
        let io_deadline = expires_at.map_or(deadline, |at| at.min(deadline));
        let expired = || expires_at.is_some_and(|at| TokioInstant::now() >= at);
        let timed_out = || {
            if expired() {
                RtrError::Expired
            } else {
                RtrError::TransactionTimeout
            }
        };
        let mut bytes: usize = 0;
        let mut restarts: u8 = 0;

        // Bump the restart counter, failing the transaction once a broken
        // cache keeps forcing resynchronization.
        macro_rules! restart {
            () => {{
                restarts += 1;
                if restarts > MAX_TRANSACTION_RESTARTS {
                    return Err(RtrError::ProtocolViolation(
                        "too many restarts in one transaction",
                    ));
                }
            }};
        }

        'transaction: loop {
            // Session identity expected for an incremental response, and
            // the serial it must not regress behind.
            let expected_session = match query {
                QueryKind::Serial => self.epoch.map(|e| e.session_id),
                QueryKind::Reset => None,
            };
            let prior_serial = self.epoch.map(|e| e.serial);
            // Session ID from this transaction's Cache Response; records
            // are only collected once it is set.
            let mut pending_session: Option<u16> = None;
            let mut records: usize = 0;
            // PDUs are split by flag bit; wire order within the transaction
            // is discarded. Safe against a correct cache, which sends net
            // deltas per serial (RFC 8210) — the VRP manager applies all
            // withdrawals before all announcements, so an "announce X then
            // withdraw X" pair in one serial would resolve to X present.
            let mut announced = Vec::new();
            let mut withdrawn = Vec::new();
            let mut aspa_announced: Vec<AspaRecord> = Vec::new();
            let mut aspa_withdrawn: Vec<AspaRecord> = Vec::new();
            // Announcements charged to the record caps as they decode.
            let mut reservation = Reservation::new(Arc::clone(&self.record_budget));
            let is_reset = tokio::time::timeout_at(io_deadline, self.send_query(stream, query))
                .await
                .map_err(|_| timed_out())??;

            loop {
                while let Some(pdu) = self.next_pdu(parse_buf)? {
                    // A ready read can carry PDUs past the captured data expiry.
                    if expired() {
                        return Err(RtrError::Expired);
                    }
                    match pdu {
                        RtrPdu::CacheResponse { session_id } => {
                            // One Cache Response opens one response. A second
                            // one is a protocol violation, not a restart:
                            // the transaction ends and nothing it staged is
                            // kept.
                            if pending_session.is_some() {
                                return Err(RtrError::ProtocolViolation(
                                    "duplicate Cache Response in one response",
                                ));
                            }
                            if expected_session.is_some_and(|expected| expected != session_id) {
                                // The cache is answering from a different
                                // session than the one our data belongs
                                // to — §5.1: terminate with Error Code 0
                                // ("Corrupt Data"). Its serials are no
                                // longer commensurate with ours, so the
                                // epoch is void and the next query is a
                                // Reset Query; the data that epoch
                                // produced is still the most recent
                                // validated set and is retained.
                                warn!(
                                    server = %self.config.server_addr,
                                    expected = expected_session,
                                    got = session_id,
                                    "RTR Cache Response session mismatch — resynchronizing"
                                );
                                let mut offending = Vec::new();
                                let _ = RtrPdu::CacheResponse { session_id }
                                    .encode_with_version(&mut offending, self.negotiated_version);
                                return Err(RtrError::SessionIdMismatch {
                                    expected: expected_session,
                                    got: session_id,
                                    pdu: offending,
                                });
                            }
                            pending_session = Some(session_id);
                        }
                        RtrPdu::Ipv4Prefix {
                            flags,
                            prefix_len,
                            max_len,
                            prefix,
                            asn,
                        } if pending_session.is_some() => {
                            let entry = VrpEntry {
                                prefix: std::net::IpAddr::V4(prefix),
                                prefix_len,
                                max_len,
                                origin_asn: asn,
                            };
                            if flags & 1 == 1 {
                                self.charge(&mut reservation, is_reset, 1)?;
                                announced.push(entry);
                            } else {
                                self.charge_withdrawal(&mut reservation)?;
                                withdrawn.push(entry);
                            }
                            records += 1;
                            if records > self.max_transaction_records {
                                return Err(RtrError::TransactionLimit("record budget exceeded"));
                            }
                        }
                        RtrPdu::Ipv6Prefix {
                            flags,
                            prefix_len,
                            max_len,
                            prefix,
                            asn,
                        } if pending_session.is_some() => {
                            let entry = VrpEntry {
                                prefix: std::net::IpAddr::V6(prefix),
                                prefix_len,
                                max_len,
                                origin_asn: asn,
                            };
                            if flags & 1 == 1 {
                                self.charge(&mut reservation, is_reset, 1)?;
                                announced.push(entry);
                            } else {
                                self.charge_withdrawal(&mut reservation)?;
                                withdrawn.push(entry);
                            }
                            records += 1;
                            if records > self.max_transaction_records {
                                return Err(RtrError::TransactionLimit("record budget exceeded"));
                            }
                        }
                        RtrPdu::Aspa {
                            flags,
                            customer_asn,
                            provider_asns,
                        } if pending_session.is_some() => {
                            // 8210bis §5.12 shape rules. An announcement
                            // "MUST contain at least one Provider
                            // Autonomous System Number"; one carrying
                            // multiple providers "MUST NOT contain AS 0"
                            // (an empty announcement would fabricate an
                            // all-invalidating attestation); and the
                            // providers come "in increasing numeric order"
                            // with each one unique — i.e. strictly
                            // increasing. A withdrawal (flag=0) carries the
                            // customer AS only: "there MUST be no Provider
                            // list, and the PDU Length MUST be 12" (the
                            // codec derives the provider count from the
                            // length, so a non-empty list here is exactly a
                            // length other than 12). Any violation is an
                            // "ASPA Provider List Error" (Error Code 9).
                            let malformed = if flags & 1 == 1 {
                                provider_asns.is_empty()
                                    || (provider_asns.len() > 1 && provider_asns.contains(&0))
                                    || !provider_asns.is_sorted_by(|a, b| a < b)
                            } else {
                                !provider_asns.is_empty()
                            };
                            if malformed {
                                warn!(
                                    server = %self.config.server_addr,
                                    customer_asn,
                                    announce = flags & 1 == 1,
                                    providers = provider_asns.len(),
                                    "RTR ASPA PDU with invalid provider list"
                                );
                                // §5.12: "an Error PDU with Error Code 9
                                // ... is returned by the router".
                                let mut offending = Vec::new();
                                let _ = RtrPdu::Aspa {
                                    flags,
                                    customer_asn,
                                    provider_asns,
                                }
                                .encode_with_version(&mut offending, self.negotiated_version);
                                return Err(RtrError::AspaProviderList { pdu: offending });
                            }
                            let record = AspaRecord {
                                customer_asn,
                                provider_asns,
                            };
                            if flags & 1 == 1 {
                                self.charge(
                                    &mut reservation,
                                    is_reset,
                                    record.provider_asns.len().max(1),
                                )?;
                                aspa_announced.push(record);
                            } else {
                                self.charge_withdrawal(&mut reservation)?;
                                aspa_withdrawn.push(record);
                            }
                            records += 1;
                            if records > self.max_transaction_records {
                                return Err(RtrError::TransactionLimit("record budget exceeded"));
                            }
                        }
                        RtrPdu::EndOfData {
                            session_id,
                            serial,
                            refresh,
                            retry,
                            expire,
                        } => {
                            if pending_session != Some(session_id) {
                                // End of Data carries a session ID that
                                // does not match the Cache Response (or
                                // was never preceded by one): the cache
                                // used two session IDs in one response —
                                // §5.1: terminate with Error Code 0
                                // ("Corrupt Data"). The transaction's
                                // records are discarded unapplied and
                                // the epoch is void, but the last
                                // validated set is untouched by the
                                // cache's confusion and is retained.
                                warn!(
                                    server = %self.config.server_addr,
                                    expected = pending_session,
                                    got = session_id,
                                    serial,
                                    "RTR End of Data session mismatch — resynchronizing"
                                );
                                let mut offending = Vec::new();
                                let _ = RtrPdu::EndOfData {
                                    session_id,
                                    serial,
                                    refresh,
                                    retry,
                                    expire,
                                }
                                .encode_with_version(&mut offending, self.negotiated_version);
                                return Err(RtrError::SessionIdMismatch {
                                    expected: pending_session,
                                    got: session_id,
                                    pdu: offending,
                                });
                            }
                            let serial_sane = is_reset
                                || prior_serial.is_none_or(|old| serial_not_before(old, serial));
                            if !serial_sane {
                                // The serial went backwards (RFC 1982):
                                // the response cannot extend the held
                                // table. Resynchronize from scratch.
                                warn!(
                                    server = %self.config.server_addr,
                                    session_id,
                                    serial,
                                    "RTR End of Data serial regression — resynchronizing"
                                );
                                restart!();
                                self.epoch = None;
                                query = QueryKind::Reset;
                                continue 'transaction;
                            }
                            // A full table replaces the held count, a delta
                            // adds to it. The charge leaves the transaction
                            // with the update below.
                            self.held_records = if is_reset {
                                reservation.announced()
                            } else {
                                self.held_records + reservation.announced()
                            };
                            let mut charge = std::mem::replace(
                                &mut reservation,
                                Reservation::new(Arc::clone(&self.record_budget)),
                            );
                            // A full table carries no withdrawals onward.
                            // Free them before their charge, so the budget
                            // never undercounts what is allocated while the
                            // update waits for the manager below.
                            if is_reset {
                                drop(std::mem::take(&mut withdrawn));
                                drop(std::mem::take(&mut aspa_withdrawn));
                                charge.release_withdrawn();
                            }
                            self.apply_eod_timers(refresh, retry, expire);
                            let now = TokioInstant::now();
                            self.last_end_of_data_at = Some(now);
                            self.data_expires_at = Some(now + self.expire_interval);
                            // The transaction is complete and validated:
                            // advance the epoch as one unit.
                            self.epoch = Some(CacheEpoch {
                                version: self.negotiated_version,
                                session_id,
                                serial,
                            });

                            let aspa_count = aspa_announced.len() + aspa_withdrawn.len();
                            let update = if is_reset {
                                info!(
                                    server = %self.config.server_addr,
                                    serial,
                                    vrps = announced.len(),
                                    aspa_records = aspa_announced.len(),
                                    "RTR full table received"
                                );
                                VrpUpdate::FullTable {
                                    server: self.config.server_addr,
                                    entries: std::mem::take(&mut announced),
                                    aspa_records: std::mem::take(&mut aspa_announced),
                                }
                            } else {
                                info!(
                                    server = %self.config.server_addr,
                                    serial,
                                    vrps_announced = announced.len(),
                                    vrps_withdrawn = withdrawn.len(),
                                    aspa_announced = aspa_announced.len(),
                                    aspa_withdrawn = aspa_withdrawn.len(),
                                    "RTR incremental update received"
                                );
                                VrpUpdate::IncrementalUpdate {
                                    server: self.config.server_addr,
                                    announced: std::mem::take(&mut announced),
                                    withdrawn: std::mem::take(&mut withdrawn),
                                    aspa_announced: std::mem::take(&mut aspa_announced),
                                    aspa_withdrawn: std::mem::take(&mut aspa_withdrawn),
                                }
                            };
                            if aspa_count > 0 {
                                debug!(
                                    server = %self.config.server_addr,
                                    "RTR v2 ASPA records received"
                                );
                            }

                            if let Some(handle) = &self.enhanced_tx {
                                let update = match update {
                                    VrpUpdate::FullTable {
                                        server,
                                        entries,
                                        aspa_records,
                                    } => EnhancedVrpUpdate::Full {
                                        server,
                                        entries,
                                        aspa_records,
                                        charge,
                                        version: self.negotiated_version,
                                        session_id,
                                        serial,
                                        accepted_at: Instant::now(),
                                    },
                                    VrpUpdate::IncrementalUpdate {
                                        server,
                                        announced,
                                        withdrawn,
                                        aspa_announced,
                                        aspa_withdrawn,
                                    } => EnhancedVrpUpdate::Incremental {
                                        server,
                                        announced,
                                        withdrawn,
                                        aspa_announced,
                                        aspa_withdrawn,
                                        charge,
                                        version: self.negotiated_version,
                                        session_id,
                                        serial,
                                        accepted_at: Instant::now(),
                                    },
                                    VrpUpdate::ServerDown { .. } => {
                                        unreachable!("End of Data never emits ServerDown")
                                    }
                                };
                                let _ = handle.0.send(update).await;
                            } else {
                                // The legacy channel cannot carry the
                                // charge, so the client keeps it, and its
                                // withdrawals are released here.
                                charge.release_withdrawn();
                                match &mut self.held_charge {
                                    Some(held) if !is_reset => held.absorb(charge),
                                    held => *held = Some(charge),
                                }
                                let _ = self.vrp_tx.send(update).await;
                            }
                            return Ok(());
                        }
                        RtrPdu::CacheReset => {
                            // Retain held data (and its expiry) until the
                            // Reset Query's full table replaces it.
                            info!(
                                server = %self.config.server_addr,
                                "RTR cache reset received, resynchronizing with Reset Query"
                            );
                            restart!();
                            self.epoch = None;
                            query = QueryKind::Reset;
                            continue 'transaction;
                        }
                        RtrPdu::SerialNotify { .. } => {
                            debug!(
                                server = %self.config.server_addr,
                                "RTR Serial Notify received during fetch (ignored)"
                            );
                        }
                        RtrPdu::ErrorReport { code, text, .. } => {
                            warn!(
                                server = %self.config.server_addr,
                                code,
                                text = %text,
                                "RTR error report received"
                            );
                            // An Error Report is fatal to the session, and
                            // one answering our Serial Query means the
                            // incremental path is dead too: a restarted
                            // cache that no longer knows our session may
                            // reject the query outright (StayRTR sends
                            // "Session ID mismatch" error code 0 instead of
                            // a Cache Reset). Drop the epoch — retaining
                            // the data and its expiry — so the reconnect
                            // resynchronizes with a full Reset Query
                            // instead of retrying the same rejected query
                            // until the data expires.
                            if matches!(query, QueryKind::Serial) {
                                self.epoch = None;
                            }
                            return Err(RtrError::ServerError { code, text });
                        }
                        // A BGPsec router key (RFC 8210 §5.10). The codec has
                        // checked its framing; this router does not validate
                        // BGPsec paths, so it carries nothing to apply.
                        RtrPdu::RouterKey { asn, .. } => {
                            debug!(
                                server = %self.config.server_addr,
                                asn,
                                "RTR Router Key PDU received (ignored: no BGPsec validation)"
                            );
                        }
                        _ => {
                            debug!(
                                server = %self.config.server_addr,
                                ?pdu,
                                "unexpected RTR PDU during fetch (ignored)"
                            );
                        }
                    }
                }

                if expired() {
                    return Err(RtrError::Expired);
                }
                let n = tokio::time::timeout_at(io_deadline, stream.read(read_buf))
                    .await
                    .map_err(|_| timed_out())?
                    .map_err(RtrError::Io)?;
                if n == 0 {
                    return Err(RtrError::ConnectionClosed);
                }
                bytes += n;
                if bytes > self.max_transaction_bytes {
                    return Err(RtrError::TransactionLimit("byte budget exceeded"));
                }
                parse_buf.extend_from_slice(&read_buf[..n]);
                if parse_buf.len() > MAX_READ_BUF {
                    return Err(RtrError::BufferOverflow);
                }
            }
        }
    }
}

/// Map a session-ending error to the Error Report the draft requires
/// or permits the router to send before dropping, if any:
/// `(error code, erroneous PDU copy, diagnostic text)`.
///
/// `parse_buf` still holds the offending wire frame at its front for
/// decode-level errors ([`RtrClient::next_pdu`] only drains on success);
/// semantic errors carry a re-encoded copy of the offending PDU in the
/// error itself.
///
/// Returns `None` for received Error Reports — §5.11: "An Error Report
/// PDU MUST NOT be sent as a response to an Error Report PDU" — and for
/// events with no draft-assigned code (transport loss, local budgets).
fn teardown_report(
    error: &RtrError,
    parse_buf: &[u8],
    negotiated: bool,
) -> Option<(u16, Vec<u8>, &'static str)> {
    // §5.11/§7: never answer an Error Report — even one that is itself
    // erroneous (bad version byte, undecodable) — with an Error Report.
    let offending_is_error_report =
        parse_buf.len() >= 2 && parse_buf[1] == crate::rtr_codec::PDU_ERROR_REPORT;
    match error {
        // §5.1: session-ID mismatch → Error Code 0 ("Corrupt Data").
        RtrError::SessionIdMismatch { pdu, .. } => Some((0, pdu.clone(), "session ID mismatch")),
        // §5.12: invalid ASPA provider list → Error Code 9.
        RtrError::AspaProviderList { pdu } => Some((9, pdu.clone(), "ASPA provider list error")),
        // §12 code 10: transport-layer stall.
        RtrError::TransactionTimeout => Some((10, Vec::new(), "transaction stalled")),
        // §7: a PDU with a Protocol Version different from the
        // negotiated one → code 8 ("Unexpected Protocol Version") for a
        // known-but-wrong version, code 4 ("Unsupported Protocol
        // Version") for a version this implementation does not know.
        RtrError::VersionMismatch { expected, got } => {
            if offending_is_error_report {
                return None;
            }
            // §7: a response at a lower version than the router's query is
            // the cache downgrading, and the router "MUST either downgrade
            // ... or terminate the connection". Terminating needs no
            // report: code 8 is for a version that "differs from the
            // protocol version negotiated", and none has been negotiated
            // yet. The fallback then reconnects at the lower version.
            if !negotiated && got < expected {
                return None;
            }
            let (code, text) = if matches!(got, 0..=2) {
                (8, "unexpected protocol version")
            } else {
                (4, "unsupported protocol version")
            };
            Some((code, offending_pdu_bytes(parse_buf), text))
        }
        RtrError::Decode(decode_error) => {
            if offending_is_error_report {
                return None;
            }
            match decode_error {
                // §12 code 5: PDU Type not known by the receiver.
                RtrDecodeError::InvalidType(_) => {
                    Some((5, offending_pdu_bytes(parse_buf), "unsupported PDU type"))
                }
                // §12 code 4: Protocol Version not known by the receiver.
                RtrDecodeError::InvalidVersion(_) => Some((
                    4,
                    offending_pdu_bytes(parse_buf),
                    "unsupported protocol version",
                )),
                RtrDecodeError::Incomplete => None,
                // §12 code 0: corrupt in a manner not specified by
                // another error code.
                _ => Some((0, offending_pdu_bytes(parse_buf), "corrupt PDU")),
            }
        }
        _ => None,
    }
}

/// The offending wire frame at the front of `parse_buf`, capped for
/// embedding in an Error Report (§5.11 truncation rule).
fn offending_pdu_bytes(parse_buf: &[u8]) -> Vec<u8> {
    let frame_len = RtrPdu::peek_length(parse_buf).map_or(8, |len| len as usize);
    let take = frame_len.min(parse_buf.len()).min(ERROR_PDU_TRUNCATE);
    parse_buf[..take].to_vec()
}

/// Errors from the RTR client.
///
/// # Exhaustiveness
///
/// Additional client failure diagnostics may be added.
/// Since 0.3.0, downstream matches must include a wildcard arm. Existing
/// variants remain directly constructible; their fields are unchanged.
///
/// Matching every currently known variant without a fallback is rejected:
///
/// ```compile_fail,E0004
/// use rustbgpd_rpki::rtr_client::RtrError;
///
/// fn handle(value: RtrError) {
///     match value {
///         RtrError::Io(_)
///         | RtrError::Decode(_)
///         | RtrError::Encode(_)
///         | RtrError::ConnectionClosed
///         | RtrError::BufferOverflow
///         | RtrError::VersionMismatch { .. }
///         | RtrError::TransactionTimeout
///         | RtrError::TransactionLimit(_)
///         | RtrError::RecordLimit(_)
///         | RtrError::ProtocolViolation(_)
///         | RtrError::Expired
///         | RtrError::SessionIdMismatch { .. }
///         | RtrError::AspaProviderList { .. }
///         | RtrError::ServerError { .. } => {}
///     }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RtrError {
    /// TCP or socket I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// RTR PDU decoding failure.
    #[error("RTR decode error: {0}")]
    Decode(#[from] RtrDecodeError),
    /// RTR PDU encoding failure.
    #[error("RTR encode error: {0}")]
    Encode(#[from] RtrEncodeError),
    /// The remote end closed the connection.
    #[error("connection closed")]
    ConnectionClosed,
    /// Inbound data exceeded the read buffer limit.
    #[error("read buffer overflow")]
    BufferOverflow,
    /// A PDU arrived with a version byte different from the negotiated
    /// session version.
    #[error("RTR version mismatch: negotiated {expected}, received {got}")]
    VersionMismatch {
        /// Version negotiated for this session.
        expected: u8,
        /// Version byte carried by the offending PDU.
        got: u8,
    },
    /// An RTR transaction exceeded its wall-clock deadline.
    #[error("RTR transaction deadline exceeded")]
    TransactionTimeout,
    /// An RTR transaction exceeded a record or byte budget.
    #[error("RTR transaction limit: {0}")]
    TransactionLimit(&'static str),
    /// Accepting the transaction would exceed the per-cache or total RPKI
    /// record cap (see [`RtrClient::with_record_limits`]). The epoch is
    /// void and the previously accepted data is kept until a full table
    /// that fits replaces it or the data expires.
    #[error("RPKI record limit: {0}")]
    RecordLimit(&'static str),
    /// The cache repeatedly violated session identity within one
    /// transaction.
    #[error("RTR protocol violation: {0}")]
    ProtocolViolation(&'static str),
    /// Cache data expired without a fresh `EndOfData`.
    #[error("cache data expired")]
    Expired,
    /// The cache used a session ID different from the one this session
    /// is bound to (8210bis §5.1) — reported with Error Code 0
    /// ("Corrupt Data"); the epoch is void and the client
    /// resynchronizes, retaining the held data meanwhile.
    #[error("RTR session ID mismatch: expected {expected:?}, got {got}")]
    SessionIdMismatch {
        /// Session ID the response was required to carry, if any.
        expected: Option<u16>,
        /// Session ID the cache actually used.
        got: u16,
        /// Encoded copy of the offending PDU, for the Error Report.
        pdu: Vec<u8>,
    },
    /// An ASPA announcement carried an invalid provider list
    /// (8210bis §5.12) — reported with Error Code 9.
    #[error("RTR ASPA provider list error")]
    AspaProviderList {
        /// Encoded copy of the offending ASPA PDU, for the Error Report.
        pdu: Vec<u8>,
    },
    /// Cache server sent an Error Report PDU.
    #[error("server error (code {code}): {text}")]
    ServerError {
        /// Error code from the cache server.
        code: u16,
        /// Human-readable error text.
        text: String,
    },
}

impl RtrError {
    /// Classify what happens to the cache's held data when this error
    /// ends the session. See [`SessionEndDisposition`].
    fn disposition(&self) -> SessionEndDisposition {
        match self {
            // §6 expiry and §12 fatal corrupt Prefix PDUs (reported as
            // code 0) both flush the cache's data and clear the epoch
            // before the next Reset Query.
            RtrError::Expired | RtrError::Decode(RtrDecodeError::InvalidPrefix) => {
                SessionEndDisposition::FlushAndDrop
            }
            // A session-identity failure voids the epoch, not the data.
            // §5.3 names the cache's signal for a Serial Query bearing
            // "a session ID [that] designates a session that is no
            // longer available to the cache": a Cache Reset PDU, which
            // §8.1 answers with a Reset Query and no flush. A restarted
            // cache that instead spells that event as Error Code 0 —
            // §5.1's code for a mismatch against a session ID
            // "previously established in the session" — is still
            // reporting a stale epoch, not corrupt held data, so it is
            // handled as the Cache Reset it should have been. The held
            // set stays live until the Reset Query's full table
            // replaces it, or §6 expiry drops it.
            RtrError::SessionIdMismatch { .. } | RtrError::ServerError { code: 0, .. } => {
                SessionEndDisposition::ResyncAndRetain
            }
            // A record cap is a local resource limit, not evidence that the
            // held data is wrong (§10: retain the previous data until a
            // full set arrives). Only a full table has an exact size, so
            // the next query is a Reset Query; one that still does not fit
            // fails the same way until the held data expires (§6).
            RtrError::RecordLimit(_) => SessionEndDisposition::ResyncAndRetain,
            // Remaining Error Reports follow the §12 code table: codes
            // 2 (No Data Available), 4 (Unsupported Protocol Version —
            // "data previously learned need not be flushed"), and 12
            // (Cache Restart, §8.5 — retain, retry, and flush only if
            // the Expire Interval passes) are non-fatal; every other
            // code — including 13 (Cache Shutdown, §8.6: the operator
            // wants clients to flush) and codes unknown to this
            // implementation (§12: an invalid Error Report drops the
            // session and flushes) — is fatal.
            RtrError::ServerError { code, .. } => match code {
                2 | 4 | 12 => SessionEndDisposition::RetainAndRetry,
                _ => SessionEndDisposition::FlushAndDrop,
            },
            // Other local decode/transport guards retain the most recent
            // validated cache state under their existing dispositions.
            RtrError::Io(_)
            | RtrError::Decode(_)
            | RtrError::Encode(_)
            | RtrError::ConnectionClosed
            | RtrError::BufferOverflow
            | RtrError::VersionMismatch { .. }
            | RtrError::TransactionTimeout
            | RtrError::TransactionLimit(_)
            | RtrError::ProtocolViolation(_)
            | RtrError::AspaProviderList { .. } => SessionEndDisposition::RetainAndRetry,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use tokio::net::TcpListener;
    use tokio::time::{advance, timeout};

    use super::*;
    use crate::vrp_manager::CacheInventoryAttachment;

    fn test_config(
        server_addr: SocketAddr,
        refresh: u64,
        retry: u64,
        expire: u64,
    ) -> RtrClientConfig {
        RtrClientConfig {
            server_addr,
            refresh_interval: refresh,
            retry_interval: retry,
            expire_interval: expire,
            max_expire_interval: None,
        }
    }

    /// A client that reconnects with no delay, for tests that drive
    /// reconnects in real time. `RtrClient::new` raises a configured zero
    /// retry to the §6 minimum, so this sets the private field directly.
    fn zero_retry_client(addr: SocketAddr, vrp_tx: mpsc::Sender<VrpUpdate>) -> RtrClient {
        let mut client = RtrClient::new(test_config(addr, 60, 1, 3600), vrp_tx);
        client.retry_interval = Duration::ZERO;
        client
    }

    fn entry(addr: Ipv4Addr, prefix_len: u8, max_len: u8, asn: u32) -> VrpEntry {
        VrpEntry {
            prefix: std::net::IpAddr::V4(addr),
            prefix_len,
            max_len,
            origin_asn: asn,
        }
    }

    async fn read_pdu(stream: &mut TcpStream) -> RtrPdu {
        read_pdu_with_version(stream).await.1
    }

    async fn read_pdu_with_version(stream: &mut TcpStream) -> (u8, RtrPdu) {
        let mut header = [0u8; 8];
        stream.read_exact(&mut header).await.unwrap();
        let len = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        let mut buf = header.to_vec();
        if len > header.len() {
            let mut body = vec![0u8; len - header.len()];
            stream.read_exact(&mut body).await.unwrap();
            buf.extend_from_slice(&body);
        }
        let (pdu, consumed) = RtrPdu::decode(&buf).unwrap();
        assert_eq!(consumed, len);
        (header[0], pdu)
    }

    async fn write_pdu_version(stream: &mut TcpStream, pdu: RtrPdu, version: u8) {
        let mut buf = Vec::new();
        pdu.encode_with_version(&mut buf, version).unwrap();
        stream.write_all(&buf).await.unwrap();
    }

    /// Write a PDU at v2 — the version the client negotiates by default
    /// and now enforces on every received PDU.
    async fn write_pdu(stream: &mut TcpStream, pdu: RtrPdu) {
        write_pdu_version(stream, pdu, crate::rtr_codec::RTR_VERSION_2).await;
    }

    /// Write a whole response as ONE write. Required in `start_paused`
    /// tests: if the client parks between two writes while its
    /// transaction-deadline timer is pending, tokio's paused clock
    /// auto-advances to that timer and the transaction times out.
    async fn write_pdus(stream: &mut TcpStream, pdus: &[RtrPdu]) {
        write_pdus_version(stream, pdus, crate::rtr_codec::RTR_VERSION_2).await;
    }

    async fn write_pdus_version(stream: &mut TcpStream, pdus: &[RtrPdu], version: u8) {
        let mut buf = Vec::new();
        for pdu in pdus {
            pdu.encode_with_version(&mut buf, version).unwrap();
        }
        stream.write_all(&buf).await.unwrap();
    }

    #[tokio::test]
    async fn with_dialer_opens_every_connection_through_the_dialer() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // The configured address is deliberately not the listener: only the
        // dialer knows where the cache is, so an accepted connection proves
        // the client never fell back to a plain connect.
        let configured: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let dials = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&dials);
        let (vrp_tx, _vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(configured, 60, 5, 120), vrp_tx).with_dialer(
            move |requested| {
                assert_eq!(requested, configured);
                counter.fetch_add(1, Ordering::SeqCst);
                TcpStream::connect(addr)
            },
        );
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        assert_eq!(dials.load(Ordering::SeqCst), 1);
        client_handle.abort();
    }

    #[tokio::test]
    async fn serial_notify_triggers_incremental_refresh_without_reconnect() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(203, 0, 113, 0), 24, 24, 65001)],
                aspa_records: vec![],
            }
        );

        write_pdu(
            &mut stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial: 101,
            },
        )
        .await;
        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 114, 0),
                asn: 65002,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 101,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::IncrementalUpdate {
                server: addr,
                announced: vec![entry(Ipv4Addr::new(203, 0, 114, 0), 24, 24, 65002)],
                withdrawn: vec![],
                aspa_announced: vec![],
                aspa_withdrawn: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn periodic_refresh_uses_serial_query_on_existing_session() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 10, 5, 30), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 10,
                    retry: 5,
                    expire: 30,
                },
            ],
        )
        .await;

        let _ = vrp_rx.recv().await.unwrap();

        advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;

        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );

        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 101,
                    refresh: 10,
                    retry: 5,
                    expire: 30,
                },
            ],
        )
        .await;

        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(
            update,
            VrpUpdate::IncrementalUpdate {
                server: addr,
                announced: vec![],
                withdrawn: vec![],
                aspa_announced: vec![],
                aspa_withdrawn: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn expire_interval_clears_server_entries_and_reconnects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 2, 10), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream1, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream1).await, RtrPdu::ResetQuery);

        write_pdus(
            &mut stream1,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 2,
                    expire: 10,
                },
            ],
        )
        .await;

        let _ = vrp_rx.recv().await.unwrap();

        advance(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;

        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(update, VrpUpdate::ServerDown { server: addr });

        advance(Duration::from_secs(2)).await;
        tokio::task::yield_now().await;

        drop(stream1);
        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// Retention across a session rejection is bounded by the expire
    /// interval (§6: "The router MUST NOT retain the data past the time
    /// indicated by this parameter"). A cache that answers every resumed
    /// session with Error Report code 0 absorbs several retries with the
    /// held VRPs intact, and then loses them to expiry — the error code
    /// never keeps data alive past its deadline.
    #[tokio::test(start_paused = true)]
    async fn repeated_code_0_rejection_still_flushes_at_the_expire_interval() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        // Expiry sits far past the rejection loop below, so the two
        // phases cannot overlap: paused-clock auto-advance pads the gaps
        // between explicit advances, and a short expire interval would
        // let it reach the deadline mid-loop.
        let client = RtrClient::new(test_config(addr, 60, 2, 3600), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream1, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream1).await, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream1,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 2,
                    expire: 3600,
                },
            ],
        )
        .await;
        let _ = vrp_rx.recv().await.unwrap();
        drop(stream1);

        // Absorb three rejections, one retry interval apart, the way a
        // restarted StayRTR answers a resumed session. Each reconnect
        // proves the previous rejection was already applied, so the
        // check that no `ServerDown` was published is a real one.
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert!(
                vrp_rx.try_recv().is_err(),
                "held data was flushed by a code-0 rejection"
            );
            let _ = read_pdu_with_version(&mut stream).await;
            write_pdus_version(
                &mut stream,
                &[RtrPdu::ErrorReport {
                    code: 0,
                    pdu: vec![],
                    text: "Session ID mismatch: client is desynchronized".to_string(),
                }],
                crate::rtr_codec::RTR_VERSION_2,
            )
            .await;
            drop(stream);
            advance(Duration::from_secs(2)).await;
            tokio::task::yield_now().await;
        }

        // Past the expire interval the held set goes — bounded by §6,
        // never kept alive by the disposition of the error code.
        advance(Duration::from_hours(1)).await;
        tokio::task::yield_now().await;
        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(update, VrpUpdate::ServerDown { server: addr });

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test]
    async fn cache_reset_retains_entries_until_replacement_full_table() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        let _ = vrp_rx.recv().await.unwrap();

        write_pdu(&mut stream, RtrPdu::CacheReset).await;

        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        // No update between Cache Reset and the replacement full table:
        // the previous data stays valid until it is replaced.
        assert!(vrp_rx.try_recv().is_err());

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 8 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 114, 0),
                asn: 65002,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 8,
                serial: 200,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(203, 0, 114, 0), 24, 24, 65002)],
                aspa_records: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test]
    async fn unsupported_v2_falls_back_to_v1_immediately() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream_v2, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream_v2).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION_2);
        assert_eq!(pdu, RtrPdu::ResetQuery);

        write_pdu(
            &mut stream_v2,
            RtrPdu::ErrorReport {
                code: 4,
                pdu: vec![],
                text: "Unsupported Protocol Version".to_string(),
            },
        )
        .await;
        drop(stream_v2);

        let (mut stream_v1, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream_v1).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION);
        assert_eq!(pdu, RtrPdu::ResetQuery);

        write_pdu_version(
            &mut stream_v1,
            RtrPdu::CacheResponse { session_id: 7 },
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        write_pdu_version(
            &mut stream_v1,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        write_pdu_version(
            &mut stream_v1,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
            crate::rtr_codec::RTR_VERSION,
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(203, 0, 113, 0), 24, 24, 65001)],
                aspa_records: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test]
    async fn unexpected_serial_notify_during_fetch_is_ignored() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial: 101,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
        )
        .await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        let _ = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            timeout(Duration::from_millis(100), read_pdu(&mut stream))
                .await
                .is_err()
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// 8210bis §5.2/§7: a Serial Notify arriving between the router's
    /// first query and the negotiation-completing Cache Response MUST
    /// be ignored "regardless of the Protocol Version field" — it must
    /// not fail the session or influence negotiation. Here v0 and v1
    /// notifies precede the v2 response and negotiation completes
    /// normally with data loaded.
    #[tokio::test]
    async fn wrong_version_serial_notify_during_negotiation_is_ignored() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION_2);
        assert_eq!(pdu, RtrPdu::ResetQuery);

        // One buffer, mixed versions: v0 and v1 Serial Notifies ahead
        // of the v2 response that completes negotiation.
        let mut buf = Vec::new();
        RtrPdu::SerialNotify {
            session_id: 3,
            serial: 9,
        }
        .encode_with_version(&mut buf, 0)
        .unwrap();
        RtrPdu::SerialNotify {
            session_id: 3,
            serial: 9,
        }
        .encode_with_version(&mut buf, crate::rtr_codec::RTR_VERSION)
        .unwrap();
        for pdu in [
            RtrPdu::CacheResponse { session_id: 7 },
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        ] {
            pdu.encode_with_version(&mut buf, crate::rtr_codec::RTR_VERSION_2)
                .unwrap();
        }
        stream.write_all(&buf).await.unwrap();

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(203, 0, 113, 0), 24, 24, 65001)],
                aspa_records: vec![],
            }
        );
        // No Error Report, no reconnect: the session stays up idle.
        assert!(
            timeout(Duration::from_millis(100), read_pdu(&mut stream))
                .await
                .is_err()
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// §7: even a CORRECT-version Serial Notify received before
    /// negotiation completes is ignored — "the only effect that
    /// processing the notification would have would be to trigger
    /// exactly the same Reset Query or Serial Query that the router has
    /// already sent", so it is a no-op, never a second query.
    #[tokio::test]
    async fn correct_version_serial_notify_during_negotiation_is_not_acted_on() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        write_pdus(
            &mut stream,
            &[
                RtrPdu::SerialNotify {
                    session_id: 7,
                    serial: 101,
                },
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(update, VrpUpdate::FullTable { .. }));
        // The pre-negotiation notify triggers no follow-up query: the
        // client sits idle until its refresh interval.
        assert!(
            timeout(Duration::from_millis(100), read_pdu(&mut stream))
                .await
                .is_err()
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// Establish an epoch (session 7, serial 100) on `stream` with one
    /// IPv4 prefix and consume the resulting `FullTable` update.
    async fn establish_epoch(stream: &mut TcpStream, vrp_rx: &mut mpsc::Receiver<VrpUpdate>) {
        establish_epoch_with_timers(stream, vrp_rx, 5, 120).await;
    }

    /// [`establish_epoch`] with explicit End of Data retry/expire timers.
    /// The client adopts cache-provided timers over its configured ones,
    /// so real-time tests that need an instant reconnect pass `retry: 0`
    /// (zero means "not provided" and leaves the configured value alone).
    async fn establish_epoch_with_timers(
        stream: &mut TcpStream,
        vrp_rx: &mut mpsc::Receiver<VrpUpdate>,
        retry: u32,
        expire: u32,
    ) {
        assert_eq!(read_pdu(stream).await, RtrPdu::ResetQuery);
        write_pdus(
            stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry,
                    expire,
                },
            ],
        )
        .await;
        let _ = vrp_rx.recv().await.unwrap();
    }

    /// 8210bis v2 requires Prefix PDUs to carry the canonical network
    /// address. A host bit is fatal corrupt data: code 0 embeds the exact
    /// frame, the session closes, held data is flushed, and the incomplete
    /// transaction is never published.
    #[tokio::test]
    async fn v2_noncanonical_prefix_sends_error_report_flushes_and_is_not_published() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 0, 3600).await;
        write_pdu(
            &mut stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial: 101,
            },
        )
        .await;
        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );
        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;

        let malformed = RtrPdu::Ipv4Prefix {
            flags: 1,
            prefix_len: 24,
            max_len: 24,
            prefix: Ipv4Addr::new(203, 0, 113, 1),
            asn: 65001,
        };
        let mut offending = Vec::new();
        malformed
            .encode_with_version(&mut offending, crate::rtr_codec::RTR_VERSION_2)
            .unwrap();
        stream.write_all(&offending).await.unwrap();

        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::ErrorReport {
                code: 0,
                pdu: offending,
                text: "corrupt PDU".to_string(),
            }
        );
        let mut buf = [0u8; 1];
        assert_eq!(
            timeout(Duration::from_secs(2), stream.read(&mut buf))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert_eq!(
            timeout(Duration::from_secs(2), vrp_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            VrpUpdate::ServerDown { server: addr },
            "fatal corrupt data must flush the cache's previously learned data"
        );
        assert!(
            vrp_rx.try_recv().is_err(),
            "incomplete malformed transaction was published"
        );
        assert_eq!(
            RtrError::Decode(RtrDecodeError::InvalidPrefix).disposition(),
            SessionEndDisposition::FlushAndDrop
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// 8210bis §5.1: a Serial Query answered from a DIFFERENT session is
    /// a session-ID mismatch. Pinned order: the client sends Error
    /// Report code 0 ("Corrupt Data") with a binary copy of the
    /// offending PDU, THEN drops the session, THEN resynchronizes with a
    /// full Reset Query — it never splices the mismatched response.
    ///
    /// The held data is RETAINED across that resynchronization (§10),
    /// because the mismatch invalidates the epoch, not the validated set
    /// the epoch produced. Only §6 expiry drops that set.
    #[tokio::test]
    async fn cache_response_session_mismatch_sends_error_report_0_then_drops_then_retains() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        // Long expire interval: the flush below must be eager, not the
        // expiry path. Zero retry: reconnect immediately.
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 0, 3600).await;

        write_pdu(
            &mut stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial: 101,
            },
        )
        .await;
        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );

        // The cache answers the Serial Query from a DIFFERENT session:
        // the epoch our data belongs to is invalid.
        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 9 }).await;

        // 1. Error Report code 0 with the offending PDU embedded.
        let mut offending = Vec::new();
        RtrPdu::CacheResponse { session_id: 9 }
            .encode_with_version(&mut offending, crate::rtr_codec::RTR_VERSION_2)
            .unwrap();
        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::ErrorReport {
                code: 0,
                pdu: offending,
                text: "session ID mismatch".to_string(),
            }
        );

        // 2. The session is dropped.
        let mut buf = [0u8; 16];
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "expected the client to close after the report");

        // 3. The held data is NOT dropped: no `ServerDown` reaches the
        //    VRP manager, so route validation never flaps to not_found
        //    while the client resynchronizes.
        assert!(
            vrp_rx.try_recv().is_err(),
            "held data was flushed on a session-ID mismatch"
        );

        // Resynchronization starts from scratch with a full Reset Query.
        let (mut stream2, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);

        write_pdus(
            &mut stream2,
            &[
                RtrPdu::CacheResponse { session_id: 9 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 114, 0),
                    asn: 65002,
                },
                RtrPdu::EndOfData {
                    session_id: 9,
                    serial: 200,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        // Full replacement, never an incremental splice.
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(203, 0, 114, 0), 24, 24, 65002)],
                aspa_records: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// 8210bis §5.1: an End of Data carrying a session ID different from
    /// the Cache Response means the cache used two session IDs in one
    /// response. The client sends Error Report code 0, drops the
    /// session, discards the incoherent transaction unapplied, and
    /// resynchronizes from scratch on reconnect (previously it silently
    /// requeried in-session).
    #[tokio::test]
    async fn end_of_data_session_mismatch_reports_corrupt_data_and_resyncs() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        // End of Data carries a session ID that does not match the Cache
        // Response: the response is not one coherent cache state.
        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
        )
        .await;
        let bad_end_of_data = RtrPdu::EndOfData {
            session_id: 8,
            serial: 100,
            refresh: 60,
            retry: 5,
            expire: 120,
        };
        write_pdu(&mut stream, bad_end_of_data.clone()).await;

        // Error Report code 0 with the offending End of Data embedded,
        // then the drop.
        let mut offending = Vec::new();
        bad_end_of_data
            .encode_with_version(&mut offending, crate::rtr_codec::RTR_VERSION_2)
            .unwrap();
        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::ErrorReport {
                code: 0,
                pdu: offending,
                text: "session ID mismatch".to_string(),
            }
        );
        let mut buf = [0u8; 16];
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "expected the client to close after the report");

        // Nothing is published: the incoherent transaction's records are
        // discarded unapplied, and no flush is sent either — there was
        // no validated set here to keep, and a cache contradicting
        // itself is not grounds to drop one.
        assert!(vrp_rx.try_recv().is_err());

        // Fresh full resynchronization on the next connection.
        let (mut stream2, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);

        write_pdus(
            &mut stream2,
            &[
                RtrPdu::CacheResponse { session_id: 8 },
                RtrPdu::EndOfData {
                    session_id: 8,
                    serial: 100,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![],
                aspa_records: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test]
    async fn serial_regression_triggers_full_requery() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch(&mut stream, &mut vrp_rx).await;

        write_pdu(
            &mut stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial: 101,
            },
        )
        .await;
        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );

        // Incremental response whose serial went backwards (RFC 1982).
        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;
        write_pdu(
            &mut stream,
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 50,
                refresh: 60,
                retry: 5,
                expire: 120,
            },
        )
        .await;

        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_retains_data_and_resumes_with_serial_query() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch(&mut stream, &mut vrp_rx).await;

        // Connection drops. The retained data must NOT be flushed: no
        // ServerDown, and the client resumes the same epoch with a Serial
        // Query on reconnect.
        drop(stream);
        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(
            read_pdu(&mut stream2).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn version_mismatch_mid_session_reconnects_and_retains_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch(&mut stream, &mut vrp_rx).await;

        // A PDU with a different version byte mid-session: records from
        // different protocol versions must never mix in one epoch.
        write_pdu_version(
            &mut stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial: 101,
            },
            crate::rtr_codec::RTR_VERSION,
        )
        .await;

        // The client drops the session but retains data and epoch.
        let (mut stream2, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream2).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION_2);
        assert_eq!(
            pdu,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// Drive the client through the code-4 v2 rejection into a v1
    /// session and establish a v1 epoch (session 7, serial 100) with one
    /// prefix, serving the given expire interval. Consumes the resulting
    /// `FullTable` update and returns the live v1 stream.
    async fn establish_v1_epoch(
        listener: &TcpListener,
        vrp_rx: &mut mpsc::Receiver<VrpUpdate>,
        expire: u32,
    ) -> TcpStream {
        let (mut stream_v2, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream_v2).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION_2);
        assert_eq!(pdu, RtrPdu::ResetQuery);
        write_pdu(
            &mut stream_v2,
            RtrPdu::ErrorReport {
                code: 4,
                pdu: vec![],
                text: "Unsupported Protocol Version".to_string(),
            },
        )
        .await;
        drop(stream_v2);

        let (mut stream_v1, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream_v1).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION);
        assert_eq!(pdu, RtrPdu::ResetQuery);
        write_pdus_version(
            &mut stream_v1,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 5,
                    expire,
                },
            ],
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        let update = vrp_rx.recv().await.unwrap();
        assert!(matches!(update, VrpUpdate::FullTable { .. }));
        stream_v1
    }

    /// A v1-only cache (`StayRTR`) restarting while data is held must not
    /// wedge the client. The client must reconnect at v1 — never
    /// re-probing v2 with held v1 data, since the cache can only answer
    /// that with a version-0 Error Report the version check rejects
    /// before any fallback signal fires — and re-land the v1 session
    /// within one retry interval with full retention, including across
    /// the cache's code-0 rejection of the resumed session.
    #[tokio::test(start_paused = true)]
    #[expect(
        clippy::too_many_lines,
        reason = "one scripted cache lifecycle: restart, session rejection, v1 re-land"
    )]
    async fn v1_cache_restart_relands_v1_within_one_retry_with_retention() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        // Large expire interval: the paused clock auto-advances past idle
        // timers, and expiry must stay out of reach so the only way this
        // test passes is an immediate v1 re-land — never the
        // expiry-then-recover blackout this fix removes.
        let client = RtrClient::new(test_config(addr, 60, 5, 3600), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let stream_v1 = establish_v1_epoch(&listener, &mut vrp_rx, 3600).await;

        // The cache restarts: connection drops.
        drop(stream_v1);

        // StayRTR-like restarted cache: any v2 query is answered with a
        // version-0 Error Report and a close. The fixed client never
        // sends one — it reconnects straight at v1.
        let mut relanded = None;
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (version, pdu) = read_pdu_with_version(&mut stream).await;
            if version == crate::rtr_codec::RTR_VERSION_2 {
                write_pdu_version(
                    &mut stream,
                    RtrPdu::ErrorReport {
                        code: 8,
                        pdu: vec![],
                        text: "Bad protocol version".to_string(),
                    },
                    0,
                )
                .await;
                drop(stream);
                continue;
            }
            relanded = Some((stream, pdu));
            break;
        }
        let (mut stream, pdu) = relanded.expect(
            "client wedged: kept re-probing v2 while holding v1 data instead of re-landing v1",
        );
        // Same epoch resumed at its own version — an incremental query.
        assert_eq!(
            pdu,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );
        // Retention held throughout: no ServerDown, no validation flap.
        assert!(vrp_rx.try_recv().is_err());

        // The restarted cache no longer knows the session: StayRTR
        // answers the old-session Serial Query with a "Session ID
        // mismatch" Error Report (code 0) and closes — NOT the Cache
        // Reset that 8210bis §5.3 specifies for a Serial Query naming
        // "a session that is no longer available to the cache". The
        // client treats it as the Cache Reset it should have been: it
        // drops the epoch and never re-sends the rejected Serial Query,
        // but KEEPS the held data (§10) so validation does not blackhole
        // for a retry interval. It also must NOT answer the Error
        // Report with one of its own (§5.11).
        write_pdus_version(
            &mut stream,
            &[RtrPdu::ErrorReport {
                code: 0,
                pdu: vec![],
                text: "Session ID mismatch: client is desynchronized".to_string(),
            }],
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 0, "client answered an Error Report with a PDU");
        drop(stream);

        // No flush: the code-0 rejection reported a stale session, not
        // corrupt held data, so nothing reaches the VRP manager and the
        // validated set stays live.
        assert!(
            vrp_rx.try_recv().is_err(),
            "held data was flushed on the cache's code-0 session rejection"
        );

        // Data is still held, so the version stays pinned at v1: the
        // client must NOT re-probe v2 here. (The flush this replaces
        // reset the probe to v2, re-opening the very wedge this test
        // exists to pin.) It reconnects at v1 with a Reset Query,
        // because the epoch — not the data — was dropped.
        let (mut stream, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream).await;
        assert_eq!(
            version,
            crate::rtr_codec::RTR_VERSION,
            "client re-probed v2 while still holding v1 data"
        );
        assert_eq!(
            pdu,
            RtrPdu::ResetQuery,
            "client kept retrying the rejected Serial Query instead of resynchronizing"
        );
        assert!(vrp_rx.try_recv().is_err());
        write_pdus_version(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 9 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 114, 0),
                    asn: 65002,
                },
                RtrPdu::EndOfData {
                    session_id: 9,
                    serial: 1,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
            crate::rtr_codec::RTR_VERSION,
        )
        .await;

        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(203, 0, 114, 0), 24, 24, 65002)],
                aspa_records: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// A v1-pinned reconnect (held-epoch version pinning) whose cache
    /// emits a v2 Serial Notify before answering the query: the notify
    /// is ignored per §5.2/§7 — NOT treated as an upgrade hint — and
    /// the v1 session re-lands on the same epoch with an incremental
    /// update.
    #[tokio::test(start_paused = true)]
    async fn v1_pinned_reconnect_ignores_v2_serial_notify_during_negotiation() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 3600), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let stream_v1 = establish_v1_epoch(&listener, &mut vrp_rx, 3600).await;
        drop(stream_v1);

        // The client reconnects pinned at the held epoch's version.
        let (mut stream, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION);
        assert_eq!(
            pdu,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );

        // One buffer: a v2 Serial Notify ahead of the v1 response.
        let mut buf = Vec::new();
        RtrPdu::SerialNotify {
            session_id: 7,
            serial: 101,
        }
        .encode_with_version(&mut buf, crate::rtr_codec::RTR_VERSION_2)
        .unwrap();
        for pdu in [
            RtrPdu::CacheResponse { session_id: 7 },
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 114, 0),
                asn: 65002,
            },
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 101,
                refresh: 60,
                retry: 5,
                expire: 3600,
            },
        ] {
            pdu.encode_with_version(&mut buf, crate::rtr_codec::RTR_VERSION)
                .unwrap();
        }
        stream.write_all(&buf).await.unwrap();

        // The v1 session re-lands on the same epoch: an incremental
        // update, no flush, no version flap.
        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(
            update,
            VrpUpdate::IncrementalUpdate {
                server: addr,
                announced: vec![entry(Ipv4Addr::new(203, 0, 114, 0), 24, 24, 65002)],
                withdrawn: vec![],
                aspa_announced: vec![],
                aspa_withdrawn: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// The deliberate v2 re-probe point: once held v1 data expires
    /// (nothing left to protect), the client probes the preferred
    /// version again and can upgrade to a cache that gained v2 support.
    #[tokio::test(start_paused = true)]
    async fn data_expiry_reprobes_v2_for_upgrade() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        // v1 epoch whose data expires before the next refresh.
        let _stream_v1 = establish_v1_epoch(&listener, &mut vrp_rx, 30).await;

        // The cache never speaks again; the expire interval passes and
        // the held entries are dropped.
        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(update, VrpUpdate::ServerDown { server: addr });

        // Epoch-less again: the client re-probes v2 and upgrades.
        let (mut stream, _) = listener.accept().await.unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION_2);
        assert_eq!(pdu, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 11 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 115, 0),
                    asn: 65003,
                },
                RtrPdu::EndOfData {
                    session_id: 11,
                    serial: 1,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
        )
        .await;

        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(203, 0, 115, 0), 24, 24, 65003)],
                aspa_records: vec![],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// A cache that serves `BGPsec` router keys interleaves Router Key PDUs
    /// with prefixes and ASPAs. The client applies everything else, ignores
    /// the keys, and keeps the session: the next Serial Notify draws a
    /// Serial Query on the same connection.
    #[tokio::test]
    async fn router_key_pdus_are_ignored_and_the_session_stays_up() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        let v2 = crate::rtr_codec::RTR_VERSION_2;
        // A Router Key frame: header, 20-octet SKI, AS number, DER SPKI.
        let router_key = {
            let spki = [0x30, 0x03, 0x02, 0x01, 0x00];
            let mut frame = vec![v2, 9, 1, 0];
            frame.extend_from_slice(&u32::try_from(32 + spki.len()).unwrap().to_be_bytes());
            frame.extend_from_slice(&[0xab; 20]);
            frame.extend_from_slice(&65_003u32.to_be_bytes());
            frame.extend_from_slice(&spki);
            frame
        };
        let prefix = RtrPdu::Ipv4Prefix {
            flags: 1,
            prefix_len: 24,
            max_len: 24,
            prefix: Ipv4Addr::new(198, 51, 100, 0),
            asn: 65003,
        };
        let aspa = AspaRecord {
            customer_asn: 65_003,
            provider_asns: vec![65_001],
        };
        let mut buf = Vec::new();
        for (pdu, key_after) in [
            (RtrPdu::CacheResponse { session_id: 7 }, false),
            (prefix, true),
            (
                RtrPdu::Aspa {
                    flags: 1,
                    customer_asn: aspa.customer_asn,
                    provider_asns: aspa.provider_asns.clone(),
                },
                true,
            ),
            (
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 1,
                    refresh: 60,
                    retry: 0,
                    expire: 3600,
                },
                false,
            ),
        ] {
            pdu.encode_with_version(&mut buf, v2).unwrap();
            if key_after {
                buf.extend_from_slice(&router_key);
            }
        }
        stream.write_all(&buf).await.unwrap();

        assert_eq!(
            timeout(Duration::from_secs(5), vrp_rx.recv())
                .await
                .expect("the response carrying Router Keys was not applied")
                .unwrap(),
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(198, 51, 100, 0), 24, 24, 65003)],
                aspa_records: vec![aspa],
            }
        );
        write_pdu(
            &mut stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial: 2,
            },
        )
        .await;
        assert_eq!(
            timeout(Duration::from_secs(5), read_pdu(&mut stream))
                .await
                .expect("the session did not stay up"),
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 1,
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// A transient failure before the first End of Data falls back to v1,
    /// and the v1 session takes the fallback's held data. The client does
    /// not stay at v1 for good: after the re-probe interval it reconnects at
    /// v2, and a v2-capable cache brings back v2 and ASPA without a restart.
    #[tokio::test(start_paused = true)]
    async fn v1_fallback_reprobes_v2_after_the_interval_and_regains_aspa() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        // A connection reset before End of Data.
        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);

        let (mut v1, _) = listener.accept().await.unwrap();
        assert_eq!(
            read_pdu_with_version(&mut v1).await,
            (crate::rtr_codec::RTR_VERSION, RtrPdu::ResetQuery)
        );
        write_pdus_version(
            &mut v1,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 1,
                    refresh: 3600,
                    retry: 0,
                    expire: 7200,
                },
            ],
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        assert!(matches!(
            vrp_rx.recv().await.unwrap(),
            VrpUpdate::FullTable { .. }
        ));

        // The healthy v1 session stays open; at the first refresh past
        // the re-probe interval the client reconnects at v2.
        let (mut v2, _) = timeout(Duration::from_secs(4000), listener.accept())
            .await
            .expect("no reconnect after the re-probe interval")
            .unwrap();
        assert_eq!(
            read_pdu_with_version(&mut v2).await,
            (crate::rtr_codec::RTR_VERSION_2, RtrPdu::ResetQuery),
            "the reconnect did not probe v2"
        );
        let aspa = AspaRecord {
            customer_asn: 64_500,
            provider_asns: vec![64_501],
        };
        write_pdus(
            &mut v2,
            &[
                RtrPdu::CacheResponse { session_id: 9 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::Aspa {
                    flags: 1,
                    customer_asn: aspa.customer_asn,
                    provider_asns: aspa.provider_asns.clone(),
                },
                RtrPdu::EndOfData {
                    session_id: 9,
                    serial: 1,
                    refresh: 3600,
                    retry: 0,
                    expire: 7200,
                },
            ],
        )
        .await;
        assert_eq!(
            vrp_rx.recv().await.unwrap(),
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![entry(Ipv4Addr::new(203, 0, 113, 0), 24, 24, 65001)],
                aspa_records: vec![aspa],
            }
        );
        drop(v1);

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// A v2 re-probe that a v1-only cache refuses falls straight back to
    /// v1, keeping the held v1 epoch: the next query is a v1 Serial Query,
    /// nothing is flushed, and there is no retry-paced probe loop.
    #[tokio::test(start_paused = true)]
    async fn refused_v2_reprobe_resumes_v1_with_the_held_epoch() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);
        let (mut v1, _) = listener.accept().await.unwrap();
        let _ = read_pdu_with_version(&mut v1).await;
        write_pdus_version(
            &mut v1,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 1,
                    refresh: 3600,
                    retry: 0,
                    expire: 7200,
                },
            ],
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        let _ = vrp_rx.recv().await.unwrap();

        let (mut probe, _) = timeout(Duration::from_secs(4000), listener.accept())
            .await
            .expect("no reconnect after the re-probe interval")
            .unwrap();
        assert_eq!(
            read_pdu_with_version(&mut probe).await.0,
            crate::rtr_codec::RTR_VERSION_2
        );
        // A v1-only cache: Unsupported Protocol Version at v1.
        write_pdu_version(
            &mut probe,
            RtrPdu::ErrorReport {
                code: 4,
                pdu: Vec::new(),
                text: "unsupported protocol version".to_string(),
            },
            crate::rtr_codec::RTR_VERSION,
        )
        .await;

        let (mut resumed, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("the refused probe did not fall back to v1 at once")
            .unwrap();
        assert_eq!(
            read_pdu_with_version(&mut resumed).await,
            (
                crate::rtr_codec::RTR_VERSION,
                RtrPdu::SerialQuery {
                    session_id: 7,
                    serial: 1,
                }
            ),
            "the v1 epoch was not kept through the refused probe"
        );
        assert!(vrp_rx.try_recv().is_err(), "held data was flushed");
        drop(v1);

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// A v2 re-probe that the cache accepts has completed negotiation, so a
    /// corrupt Prefix PDU in its first transaction is the §12 fatal error it
    /// is anywhere else: the held v1 data is flushed. Before End of Data the
    /// held epoch is still v1, which must not turn the error into a v1
    /// fallback that keeps the data.
    #[tokio::test(start_paused = true)]
    async fn corrupt_prefix_after_accepted_v2_reprobe_flushes_held_data() {
        corrupt_prefix_during_v2_reprobe_flushes_held_data(true).await;
    }

    /// A corrupt Prefix PDU at the probed version, even ahead of any Cache
    /// Response, shows the cache speaks v2: it is the same §12 fatal error,
    /// not a version refusal, so the held v1 data is flushed.
    #[tokio::test(start_paused = true)]
    async fn corrupt_prefix_before_the_v2_reprobe_response_flushes_held_data() {
        corrupt_prefix_during_v2_reprobe_flushes_held_data(false).await;
    }

    async fn corrupt_prefix_during_v2_reprobe_flushes_held_data(cache_response_first: bool) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);
        let (mut v1, _) = listener.accept().await.unwrap();
        let _ = read_pdu_with_version(&mut v1).await;
        write_pdus_version(
            &mut v1,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 1,
                    refresh: 3600,
                    retry: 0,
                    expire: 7200,
                },
            ],
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        let _ = vrp_rx.recv().await.unwrap();

        let (mut probe, _) = timeout(Duration::from_secs(4000), listener.accept())
            .await
            .expect("no reconnect after the re-probe interval")
            .unwrap();
        assert_eq!(
            read_pdu_with_version(&mut probe).await,
            (crate::rtr_codec::RTR_VERSION_2, RtrPdu::ResetQuery)
        );
        if cache_response_first {
            write_pdus(&mut probe, &[RtrPdu::CacheResponse { session_id: 9 }]).await;
        }
        // Host bits set: a corrupt Prefix PDU (§12, code 0).
        write_pdus(
            &mut probe,
            &[RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 1),
                asn: 65001,
            }],
        )
        .await;

        assert_eq!(
            timeout(Duration::from_secs(5), vrp_rx.recv())
                .await
                .expect("the corrupt Prefix PDU did not flush the held data")
                .unwrap(),
            VrpUpdate::ServerDown { server: addr }
        );
        drop(v1);

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn buffered_end_of_data_cannot_renew_expired_data() {
        for query in [QueryKind::Serial, QueryKind::Reset] {
            for elapsed in [Duration::from_secs(1), Duration::from_secs(2)] {
                buffered_end_of_data_at_expiry(query, elapsed).await;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn buffered_end_of_data_before_expiry_renews_data() {
        for query in [QueryKind::Serial, QueryKind::Reset] {
            buffered_end_of_data_at_expiry(query, Duration::ZERO).await;
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "drive buffered responses through the client and verify both published tables and renewal state at expiry"
    )]
    async fn buffered_end_of_data_at_expiry(query: QueryKind, elapsed: Duration) {
        use crate::vrp_manager::VrpManager;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (connected, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let mut stream = connected.unwrap();
        let (mut cache, _) = accepted.unwrap();
        let (vrp_tx, vrp_rx) = mpsc::channel(8);
        let (rib_tx, mut rib_rx) = mpsc::channel(8);
        let (aspa_tx, mut aspa_rx) = mpsc::channel(8);
        let manager = tokio::spawn(VrpManager::new(vrp_rx, rib_tx).with_aspa_tx(aspa_tx).run());
        let mut client = zero_retry_client(addr, vrp_tx);
        let mut read_buf = [0u8; 8192];
        let mut parse_buf = Vec::new();
        let response = [
            RtrPdu::CacheResponse { session_id: 7 },
            RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                prefix: Ipv4Addr::new(203, 0, 113, 0),
                asn: 65001,
            },
            RtrPdu::Aspa {
                flags: 1,
                customer_asn: 65001,
                provider_asns: vec![65010],
            },
            RtrPdu::EndOfData {
                session_id: 7,
                serial: 100,
                refresh: 60,
                retry: 1,
                expire: 120,
            },
        ];
        write_pdus(&mut cache, &response).await;
        client
            .fetch_until_end_of_data(&mut stream, &mut read_buf, &mut parse_buf, QueryKind::Reset)
            .await
            .unwrap();
        assert_eq!(read_pdu(&mut cache).await, RtrPdu::ResetQuery);
        assert_eq!(rib_rx.recv().await.unwrap().table.len(), 1);
        assert_eq!(aspa_rx.recv().await.unwrap().table.len(), 1);
        let accepted_at = client.last_end_of_data_at;
        let epoch = client.epoch;
        let timers = (
            client.refresh_interval,
            client.retry_interval,
            client.expire_interval,
        );
        let expiry = client.data_expires_at.unwrap();

        // Buffer before expiry; advance explicitly before processing. No
        // sleeper races a socket read or another task.
        tokio::time::advance(
            (expiry - TokioInstant::now())
                .checked_sub(Duration::from_secs(1))
                .unwrap(),
        )
        .await;
        let eod = RtrPdu::EndOfData {
            session_id: 7,
            serial: 101,
            refresh: 90,
            retry: 2,
            expire: 240,
        };
        let pdus = if matches!(query, QueryKind::Reset) {
            vec![
                response[0].clone(),
                response[1].clone(),
                response[2].clone(),
                eod,
            ]
        } else {
            vec![response[0].clone(), eod]
        };
        let mut encoded = Vec::new();
        for pdu in pdus {
            pdu.encode_with_version(&mut encoded, crate::rtr_codec::RTR_VERSION_2)
                .unwrap();
        }
        cache.write_all(&encoded).await.unwrap();
        parse_buf.resize(encoded.len(), 0);
        stream.read_exact(&mut parse_buf).await.unwrap();
        assert!(TokioInstant::now() < expiry);
        tokio::time::advance(elapsed).await;
        let expired = TokioInstant::now() >= expiry;
        let result = client
            .fetch_until_end_of_data(&mut stream, &mut read_buf, &mut parse_buf, query)
            .await;
        if expired {
            assert!(
                matches!(result, Err(RtrError::Expired)),
                "buffered response renewed expired data: {result:?}"
            );
            assert_eq!(client.data_expires_at, Some(expiry));
            assert_eq!(client.last_end_of_data_at, accepted_at);
            assert_eq!(client.epoch, epoch);
            assert_eq!(
                (
                    client.refresh_interval,
                    client.retry_interval,
                    client.expire_interval
                ),
                timers
            );
            client.end_session(&result.unwrap_err()).await;
            assert!(client.data_expires_at.is_none());
            assert!(client.last_end_of_data_at.is_none());
            assert!(client.epoch.is_none());
            assert_eq!(client.held_records, 0);
            assert!(rib_rx.recv().await.unwrap().table.is_empty());
            assert!(aspa_rx.recv().await.unwrap().table.is_empty());
        } else {
            result.unwrap();
            assert!(client.data_expires_at.unwrap() > expiry);
            assert!(client.epoch.is_some());
        }
        manager.abort();
        let _ = manager.await;
    }

    /// §6: held data expires on time while a refresh query is in flight. A
    /// cache that accepts the query and never answers must not keep the
    /// data published until the transaction deadline.
    #[tokio::test(start_paused = true)]
    async fn held_data_expires_during_a_stalled_query() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        // Refresh 60 s, expire 120 s: the refresh query is still
        // unanswered when the data expires.
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 0, 120).await;
        let accepted = TokioInstant::now();
        assert!(matches!(
            read_pdu(&mut stream).await,
            RtrPdu::SerialQuery { .. }
        ));

        let update = timeout(Duration::from_secs(1000), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(update, VrpUpdate::ServerDown { server: addr });
        assert!(
            accepted.elapsed() <= Duration::from_secs(120),
            "flushed {:?} after End of Data, past the 120 s expire",
            accepted.elapsed()
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// §6: held data expires on time while a query write is blocked. A cache
    /// that never reads lets the socket buffers fill, and the next query
    /// write must not wait past the expire interval.
    #[tokio::test(start_paused = true)]
    async fn held_data_expires_during_a_blocked_query_write() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let dials = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&dials);
        // The first connection is ordinary. Every later one arrives with its
        // send path already full, as after a cache stopped reading.
        let client = zero_retry_client(addr, vrp_tx).with_dialer(move |_| {
            let first = counter.fetch_add(1, Ordering::SeqCst) == 0;
            async move {
                let stream = TcpStream::connect(addr).await?;
                if !first {
                    let filler = vec![0u8; 65_536];
                    loop {
                        match stream.try_write(&filler) {
                            Ok(_) => {}
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(error) => return Err(error),
                        }
                    }
                }
                Ok(stream)
            }
        });
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 0, 120).await;
        let accepted = TokioInstant::now();
        drop(stream);
        // Held open and never read.
        let (_silent, _) = listener.accept().await.unwrap();

        let update = timeout(Duration::from_secs(1000), vrp_rx.recv())
            .await
            .expect("held data outlived its expire interval behind a blocked query write")
            .unwrap();
        assert_eq!(update, VrpUpdate::ServerDown { server: addr });
        assert!(accepted.elapsed() <= Duration::from_secs(120));
        assert!(dials.load(Ordering::SeqCst) >= 2);

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// §6: held data expires on time while a reconnect hangs in connect.
    #[tokio::test(start_paused = true)]
    async fn held_data_expires_during_a_hung_connect() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let dials = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&dials);
        // The first connection succeeds; every later one never completes.
        let client = zero_retry_client(addr, vrp_tx).with_dialer(move |_| {
            let first = counter.fetch_add(1, Ordering::SeqCst) == 0;
            async move {
                if first {
                    TcpStream::connect(addr).await
                } else {
                    std::future::pending().await
                }
            }
        });
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 0, 120).await;
        let accepted = TokioInstant::now();
        drop(stream);

        let update = timeout(Duration::from_secs(1000), vrp_rx.recv())
            .await
            .expect("held data outlived its expire interval during a hung connect")
            .unwrap();
        assert_eq!(update, VrpUpdate::ServerDown { server: addr });
        assert!(accepted.elapsed() <= Duration::from_secs(120));
        assert!(dials.load(Ordering::SeqCst) >= 2);

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// §7: a cache that answers the v2 query with a v1 Cache Response is
    /// downgrading. The router terminates without an Error Report (code 8
    /// applies only once a version is negotiated) and reconnects at v1.
    #[tokio::test]
    async fn downgrade_reply_during_negotiation_falls_back_without_error_report() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, _vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(
            read_pdu_with_version(&mut stream).await,
            (crate::rtr_codec::RTR_VERSION_2, RtrPdu::ResetQuery)
        );
        write_pdu_version(
            &mut stream,
            RtrPdu::CacheResponse { session_id: 7 },
            crate::rtr_codec::RTR_VERSION,
        )
        .await;
        let mut rest = Vec::new();
        timeout(Duration::from_secs(5), stream.read_to_end(&mut rest))
            .await
            .expect("the client did not close the downgraded connection")
            .unwrap();
        assert!(
            rest.is_empty(),
            "the client answered the downgrade with {:?}",
            RtrPdu::decode(&rest).map(|(pdu, _)| pdu)
        );

        let (mut v1, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            read_pdu_with_version(&mut v1).await,
            (crate::rtr_codec::RTR_VERSION, RtrPdu::ResetQuery)
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn record_budget_exceeded_drops_connection_without_publishing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let mut client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        client.max_transaction_records = 2;
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);

        let mut pdus = vec![RtrPdu::CacheResponse { session_id: 7 }];
        for i in 0..3u8 {
            pdus.push(RtrPdu::Ipv4Prefix {
                flags: 1,
                prefix_len: 24,
                max_len: 24,
                // Distinct /24s with no host bits: the budget, not a
                // corrupt Prefix PDU, must end the transaction.
                prefix: Ipv4Addr::new(203, 0, 113 + i, 0),
                asn: 65001,
            });
        }
        // A complete transaction, so an unenforced budget would publish it.
        pdus.push(RtrPdu::EndOfData {
            session_id: 7,
            serial: 1,
            refresh: 60,
            retry: 5,
            expire: 120,
        });
        write_pdus(&mut stream, &pdus).await;

        // Budget exceeded: the client drops the connection (bounded
        // error, no wedge/OOM) and publishes nothing.
        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(
            read_pdu_with_version(&mut stream2).await,
            (crate::rtr_codec::RTR_VERSION_2, RtrPdu::ResetQuery),
            "a record-budget failure is not a version refusal"
        );
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    fn host_prefix(flags: u8, last: u8) -> RtrPdu {
        RtrPdu::Ipv4Prefix {
            flags,
            prefix_len: 24,
            max_len: 24,
            prefix: Ipv4Addr::new(198, 51, last, 0),
            asn: 65001,
        }
    }

    fn host_entry(last: u8) -> VrpEntry {
        entry(Ipv4Addr::new(198, 51, last, 0), 24, 24, 65001)
    }

    /// Send a Serial Notify for session 7 and expect the client's Serial
    /// Query from `prior`.
    async fn notify_and_expect_serial_query(stream: &mut TcpStream, serial: u32, prior: u32) {
        write_pdu(
            stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial,
            },
        )
        .await;
        assert_eq!(
            read_pdu(stream).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: prior,
            }
        );
    }

    /// A serial delta that would take a cache past its record cap is
    /// refused while it is still being decoded: nothing is published, the
    /// held data and its charge stay, and the client resynchronizes with a
    /// Reset Query. An in-cap delta is applied unchanged, and withdrawing a
    /// record the cache never sent does not lower the charge.
    #[tokio::test]
    async fn serial_update_over_the_cache_record_cap_is_refused_while_decoding() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let budget = RecordBudget::new(100);
        let client = zero_retry_client(addr, vrp_tx).with_record_limits(3, Arc::clone(&budget));
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 0, 3600).await;
        assert_eq!(budget.used(), 1);

        notify_and_expect_serial_query(&mut stream, 101, 100).await;
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                host_prefix(1, 1),
                host_prefix(0, 9),
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 101,
                    refresh: 60,
                    retry: 0,
                    expire: 3600,
                },
            ],
        )
        .await;
        assert_eq!(
            vrp_rx.recv().await.unwrap(),
            VrpUpdate::IncrementalUpdate {
                server: addr,
                announced: vec![host_entry(1)],
                withdrawn: vec![host_entry(9)],
                aspa_announced: vec![],
                aspa_withdrawn: vec![],
            }
        );
        assert_eq!(budget.used(), 2);

        // Two held plus two announced is over the cap of three. The cache
        // never sends End of Data: the refusal happens mid-transfer.
        notify_and_expect_serial_query(&mut stream, 102, 101).await;
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                host_prefix(1, 2),
                host_prefix(1, 3),
            ],
        )
        .await;
        let (mut stream2, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("the over-cap delta was not refused while decoding")
            .unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        let published = vrp_rx.try_recv();
        assert!(
            published.is_err(),
            "an over-cap delta must not be published, and held data is not flushed: {published:?}"
        );
        assert_eq!(budget.used(), 2);

        // A full table at exactly the cap is accepted and replaces the charge.
        write_pdus(
            &mut stream2,
            &[
                RtrPdu::CacheResponse { session_id: 8 },
                host_prefix(1, 1),
                host_prefix(1, 2),
                host_prefix(1, 3),
                RtrPdu::EndOfData {
                    session_id: 8,
                    serial: 1,
                    refresh: 60,
                    retry: 0,
                    expire: 3600,
                },
            ],
        )
        .await;
        assert_eq!(
            vrp_rx.recv().await.unwrap(),
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![host_entry(1), host_entry(2), host_entry(3)],
                aspa_records: vec![],
            }
        );
        assert_eq!(budget.used(), 3);

        client_handle.abort();
        let _ = client_handle.await;
        assert_eq!(budget.used(), 0, "a stopped client releases its charge");
    }

    /// The total budget is shared: once one cache holds most of it, another
    /// cache's full table is refused while decoding and publishes nothing.
    #[tokio::test]
    async fn total_record_budget_is_shared_across_caches() {
        let budget = RecordBudget::new(3);
        let mut clients = Vec::new();
        let mut receivers = Vec::new();
        let mut listeners = Vec::new();
        for _ in 0..2 {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (vrp_tx, vrp_rx) = mpsc::channel(8);
            let client = zero_retry_client(listener.local_addr().unwrap(), vrp_tx)
                .with_record_limits(10, Arc::clone(&budget));
            clients.push(Some(client));
            receivers.push(vrp_rx);
            listeners.push(listener);
        }

        let first = tokio::spawn(clients[0].take().unwrap().run());
        let (mut stream, _) = listeners[0].accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 1 },
                host_prefix(1, 1),
                host_prefix(1, 2),
                RtrPdu::EndOfData {
                    session_id: 1,
                    serial: 1,
                    refresh: 60,
                    retry: 0,
                    expire: 3600,
                },
            ],
        )
        .await;
        assert!(matches!(
            receivers[0].recv().await.unwrap(),
            VrpUpdate::FullTable { .. }
        ));
        assert_eq!(budget.used(), 2);

        let second = tokio::spawn(clients[1].take().unwrap().run());
        let (mut stream, _) = listeners[1].accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 2 },
                host_prefix(1, 3),
                host_prefix(1, 4),
            ],
        )
        .await;
        let (mut stream, _) = timeout(Duration::from_secs(5), listeners[1].accept())
            .await
            .expect("the full table over the total budget was not refused while decoding")
            .unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        assert!(receivers[1].try_recv().is_err());
        assert_eq!(budget.used(), 2);

        for handle in [first, second] {
            handle.abort();
            let _ = handle.await;
        }
        assert_eq!(budget.used(), 0);
    }

    /// With the cache inventory attached, a record charge travels with the
    /// update into the manager's queue and is released only when that data
    /// is dropped. Full tables queued behind a blocked manager stay
    /// charged, so repeated resets cannot pile up uncharged snapshots.
    #[tokio::test]
    async fn queued_full_tables_stay_charged_until_the_manager_drops_them() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // The manager never runs: its update queue only fills.
        let (attachment, handle, _queries) = CacheInventoryAttachment::new([addr]);
        let (vrp_tx, _vrp_rx) = mpsc::channel(8);
        let budget = RecordBudget::new(2);
        let client = zero_retry_client(addr, vrp_tx)
            .with_record_limits(10, Arc::clone(&budget))
            .with_cache_inventory(handle);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        let full_table = |serial: u32, last: u8| {
            [
                RtrPdu::CacheResponse { session_id: 7 },
                host_prefix(1, last),
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial,
                    refresh: 60,
                    retry: 0,
                    expire: 3600,
                },
            ]
        };
        write_pdus(&mut stream, &full_table(1, 1)).await;
        // The client only queries again once it has queued the table.
        notify_and_expect_serial_query(&mut stream, 2, 1).await;
        assert_eq!(budget.used(), 1);

        // The cache answers with Cache Reset and a second full table.
        write_pdu(&mut stream, RtrPdu::CacheReset).await;
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdus(&mut stream, &full_table(2, 2)).await;
        notify_and_expect_serial_query(&mut stream, 3, 2).await;
        assert_eq!(budget.used(), 2, "both queued tables stay charged");

        // A third queued table would exceed the total: refused.
        write_pdu(&mut stream, RtrPdu::CacheReset).await;
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdus(&mut stream, &full_table(3, 3)).await;
        let (mut stream2, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("a third queued full table was not refused")
            .unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert_eq!(budget.used(), 2);

        client_handle.abort();
        let _ = client_handle.await;
        drop(attachment);
        assert_eq!(
            budget.used(),
            0,
            "dropping the queued data releases its charge"
        );
    }

    /// A second Cache Response inside one response ends the transaction:
    /// the client drops the connection and publishes nothing it staged.
    #[tokio::test]
    async fn duplicate_cache_response_ends_the_transaction() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                host_prefix(1, 1),
                RtrPdu::CacheResponse { session_id: 7 },
                host_prefix(1, 2),
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 1,
                    refresh: 60,
                    retry: 0,
                    expire: 3600,
                },
            ],
        )
        .await;
        let (mut again, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("a duplicate Cache Response did not end the transaction")
            .unwrap();
        assert_eq!(read_pdu(&mut again).await, RtrPdu::ResetQuery);
        let published = vrp_rx.try_recv();
        assert!(published.is_err(), "published {published:?}");

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// Withdrawals in a queued delta take memory until the manager applies
    /// them, so they are charged against the total budget until then. With
    /// the manager blocked, queued withdrawals cannot grow past the cap.
    #[tokio::test]
    async fn queued_withdrawals_stay_charged_until_the_manager_applies_them() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (attachment, handle, _queries) = CacheInventoryAttachment::new([addr]);
        let (vrp_tx, _vrp_rx) = mpsc::channel(8);
        let budget = RecordBudget::new(3);
        let client = zero_retry_client(addr, vrp_tx)
            .with_record_limits(10, Arc::clone(&budget))
            .with_cache_inventory(handle);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        let end = |serial| RtrPdu::EndOfData {
            session_id: 7,
            serial,
            refresh: 60,
            retry: 0,
            expire: 3600,
        };
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                host_prefix(1, 1),
                end(1),
            ],
        )
        .await;
        notify_and_expect_serial_query(&mut stream, 2, 1).await;
        // Two withdrawals of records the cache never sent.
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                host_prefix(0, 8),
                host_prefix(0, 9),
                end(2),
            ],
        )
        .await;
        notify_and_expect_serial_query(&mut stream, 3, 2).await;
        assert_eq!(budget.used(), 3, "queued withdrawals are not charged");

        // One more queued withdrawal would exceed the total: refused.
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                host_prefix(0, 7),
                end(3),
            ],
        )
        .await;
        let (mut again, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("a queued withdrawal past the total was not refused")
            .unwrap();
        assert_eq!(read_pdu(&mut again).await, RtrPdu::ResetQuery);
        assert_eq!(budget.used(), 3);

        client_handle.abort();
        let _ = client_handle.await;
        drop(attachment);
        assert_eq!(budget.used(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn byte_budget_exceeded_drops_connection_without_publishing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let mut client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        client.max_transaction_bytes = 4;
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;

        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn transaction_deadline_drops_stalled_transfer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let mut client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        client.transaction_deadline = Duration::from_secs(30);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        // Cache Response and then… nothing. The transaction must not
        // wedge: the deadline fires (paused clock auto-advances) and the
        // client reconnects.
        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 7 }).await;

        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// Drive one transaction whose payload contains `aspa`, and assert the
    /// client rejects the response (8210bis §5.12 "ASPA Provider List
    /// Error"): an Error Report with code 9 carrying the offending PDU is
    /// returned, the connection is dropped without publishing, and the
    /// reconnect starts over with a Reset Query.
    async fn assert_aspa_pdu_rejected(aspa: RtrPdu) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                aspa.clone(),
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
        )
        .await;

        // §5.12: "an Error PDU with Error Code 9 ... is returned by the
        // router", with the offending ASPA PDU embedded.
        let mut offending = Vec::new();
        aspa.encode_with_version(&mut offending, crate::rtr_codec::RTR_VERSION_2)
            .unwrap();
        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::ErrorReport {
                code: 9,
                pdu: offending,
                text: "ASPA provider list error".to_string(),
            }
        );

        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn aspa_announcement_without_providers_is_rejected() {
        // 8210bis §5.12: an announcement MUST contain at least one
        // Provider ASN (an empty set is only valid on a withdrawal).
        assert_aspa_pdu_rejected(RtrPdu::Aspa {
            flags: 1,
            customer_asn: 65001,
            provider_asns: vec![],
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn aspa_announcement_with_as0_among_multiple_providers_is_rejected() {
        // 8210bis §5.12: a multi-provider announcement MUST NOT contain
        // AS 0. (A single-provider AS 0 announcement is the legal
        // "no providers" attestation and stays accepted.)
        assert_aspa_pdu_rejected(RtrPdu::Aspa {
            flags: 1,
            customer_asn: 65001,
            provider_asns: vec![0, 65002],
        })
        .await;
    }

    #[tokio::test]
    async fn aspa_as0_only_announcement_is_accepted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Aspa {
                    flags: 1,
                    customer_asn: 65001,
                    provider_asns: vec![0],
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![],
                aspa_records: vec![AspaRecord {
                    customer_asn: 65001,
                    provider_asns: vec![0],
                }],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[tokio::test(start_paused = true)]
    async fn aspa_unsorted_providers_rejected() {
        // 8210bis §5.12: providers come "in increasing numeric order".
        assert_aspa_pdu_rejected(RtrPdu::Aspa {
            flags: 1,
            customer_asn: 65001,
            provider_asns: vec![65003, 65002],
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn aspa_duplicate_providers_rejected() {
        // 8210bis §5.12: "Each Provider Autonomous System Number in a
        // given ASPA PDU MUST be unique."
        assert_aspa_pdu_rejected(RtrPdu::Aspa {
            flags: 1,
            customer_asn: 65001,
            provider_asns: vec![65002, 65002],
        })
        .await;
    }

    #[tokio::test(start_paused = true)]
    async fn aspa_withdrawal_with_providers_rejected() {
        // 8210bis §5.12: on a withdrawal "there MUST be no Provider
        // list, and the PDU Length MUST be 12". One provider encodes as
        // length 16 — both violations on one wire frame.
        assert_aspa_pdu_rejected(RtrPdu::Aspa {
            flags: 0,
            customer_asn: 65001,
            provider_asns: vec![65002],
        })
        .await;
    }

    #[tokio::test]
    async fn aspa_sorted_announcement_accepted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Aspa {
                    flags: 1,
                    customer_asn: 65001,
                    provider_asns: vec![65002, 65003, 65010],
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 5,
                    expire: 120,
                },
            ],
        )
        .await;

        let update = timeout(Duration::from_secs(1), vrp_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            update,
            VrpUpdate::FullTable {
                server: addr,
                entries: vec![],
                aspa_records: vec![AspaRecord {
                    customer_asn: 65001,
                    provider_asns: vec![65002, 65003, 65010],
                }],
            }
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// §5: a PDU whose Length field exceeds 65,535 octets violates a
    /// MUST NOT — corrupt framing. The client sends Error Report code 0
    /// ("Corrupt Data") with the offending frame head embedded, drops
    /// the session without publishing, and resynchronizes on reconnect.
    #[tokio::test(start_paused = true)]
    async fn pdu_length_over_65535_is_corrupt_framing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        // IPv4 Prefix header claiming a 65,536-octet PDU.
        let frame: [u8; 8] = [
            crate::rtr_codec::RTR_VERSION_2,
            4,
            0,
            0,
            0x00,
            0x01,
            0x00,
            0x00,
        ];
        stream.write_all(&frame).await.unwrap();

        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::ErrorReport {
                code: 0,
                pdu: frame.to_vec(),
                text: "corrupt PDU".to_string(),
            }
        );

        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// §5 boundary: a PDU of exactly 65,535 octets is legal and must be
    /// parsed, not treated as corrupt framing. A maximum-size Error
    /// Report code 2 ("No Data Available", non-fatal) proves it: the
    /// client processes it as a server error — closing without sending
    /// any Error Report of its own (§5.11) and retaining data — instead
    /// of reporting Corrupt Data.
    #[tokio::test(start_paused = true)]
    async fn pdu_length_exactly_65535_is_accepted() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        let report = RtrPdu::ErrorReport {
            code: 2,
            pdu: vec![],
            text: "x".repeat(65_519), // 16-octet fixed part + text = 65,535
        };
        let mut buf = Vec::new();
        report
            .encode_with_version(&mut buf, crate::rtr_codec::RTR_VERSION_2)
            .unwrap();
        assert_eq!(buf.len(), 65_535);
        stream.write_all(&buf).await.unwrap();

        // The client drops the session without answering the Error
        // Report (§5.11: never reply to one).
        let mut probe = [0u8; 16];
        let n = timeout(Duration::from_secs(2), stream.read(&mut probe))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "expected a silent close, got bytes back");

        // Non-fatal code 2: nothing flushed, resync on reconnect.
        let (mut stream2, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// §6: the router MUST NOT retain data past the Expire Interval,
    /// whose maximum legal value is 172,800 s (2 days). A cache
    /// supplying a larger expire is clamped: the data dies at the
    /// two-day mark, not at the cache-supplied time.
    #[tokio::test(start_paused = true)]
    async fn eod_expire_above_two_day_maximum_expires_at_the_maximum() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = RtrClient::new(test_config(addr, 60, 5, 120), vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        // EoD supplies retry 7200 (the legal maximum) and expire
        // 200,000 (over the two-day maximum).
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 7_200, 200_000).await;
        let eod_at = TokioInstant::now();

        // The cache goes away for good: every reconnect is accepted and
        // immediately closed.
        drop(stream);
        tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                drop(conn);
            }
        });

        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(update, VrpUpdate::ServerDown { server: addr });
        let elapsed = TokioInstant::now().duration_since(eod_at).as_secs();
        // The paused clock auto-advances past pending timers while the
        // client is in real socket I/O, so the flush lands shortly
        // after — not exactly at — the two-day mark. The claim under
        // test is the clamp: expiry at ~172,800 s, far below the
        // cache-supplied 200,000 s.
        assert!(
            (172_800..175_000).contains(&elapsed),
            "expected expiry at the 172,800 s §6 maximum, got {elapsed} s"
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// An operator `max_expire_interval` is a stricter expire and takes
    /// the same expiry path as the §6 maximum: with the cache advertising
    /// 7,200 s and a 1,800 s ceiling, the data dies at the 1,800 s mark —
    /// `ServerDown`, exactly as at any other expiry. The observer sees
    /// the effective value at start (configured expire, under the
    /// ceiling) and after End of Data (the ceiling).
    #[tokio::test(start_paused = true)]
    async fn operator_max_expire_interval_expires_before_the_cache_advertised_expire() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let mut config = test_config(addr, 60, 5, 120);
        config.max_expire_interval = Some(1_800);
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = std::sync::Arc::clone(&seen);
        let client = RtrClient::new(config, vrp_tx)
            .with_expire_observer(move |secs| sink.lock().unwrap().push(secs));
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 5, 7_200).await;
        let eod_at = TokioInstant::now();
        assert_eq!(*seen.lock().unwrap(), vec![120, 1_800]);

        drop(stream);
        tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                drop(conn);
            }
        });

        let update = vrp_rx.recv().await.unwrap();
        assert_eq!(update, VrpUpdate::ServerDown { server: addr });
        let elapsed = TokioInstant::now().duration_since(eod_at).as_secs();
        // As in the two-day test above: the paused clock auto-advances
        // past pending timers (here up to one transaction deadline)
        // while the client is in real socket I/O, so the flush lands
        // shortly after — not exactly at — the ceiling. The claim under
        // test is the cap: expiry at ~1,800 s, far below the
        // cache-supplied 7,200 s.
        assert!(
            (1_800..2_400).contains(&elapsed),
            "expected expiry at the 1,800 s operator ceiling, got {elapsed} s"
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// The crate README keeps the operator freshness contract in its
    /// one bounded RTR-client feature bullet, with the numeric ceiling
    /// derived from the production protocol constant.
    #[test]
    fn rpki_readme_pins_operator_expire_ceiling() {
        const README: &str = include_str!("../README.md");
        const START: &str = "- **RTR client**";
        const END: &str = "- **ASPA path verification**";

        assert_eq!(README.matches(START).count(), 1, "unique section start");
        assert_eq!(README.matches(END).count(), 1, "unique section end");
        let start = README.find(START).expect("RTR client bullet");
        let relative_end = README[start..]
            .find(END)
            .expect("ASPA path-verification bullet follows RTR client");
        let section = README[start..start + relative_end]
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        for clause in [
            "`RtrClientConfig::max_expire_interval` adds an optional operator freshness ceiling",
            "it clamps both the configured `expire_interval` and a cache-advertised End of Data expire down",
            "never raises a lower value",
            "when unset adds no ceiling of its own: the configured interval is limited only by the §6 bounds below, and cache-advertised values only by the protocol ceiling",
        ] {
            assert!(section.contains(clause), "missing README clause: {clause}");
        }
        let ceiling = format!(
            "The crate exports the RFC 8210 two-day ceiling as `RTR_EXPIRE_MAX_SECS` (`{EXPIRE_MAX_SECS}` seconds)."
        );
        assert!(
            section.contains(&ceiling),
            "missing README clause: {ceiling}"
        );
    }

    /// `max_expire_interval` caps the configured expire at construction
    /// and the cache-advertised expire at End of Data, never raises a
    /// lower one, and — being an expire like any other — drags
    /// refresh/retry below it through the existing §6 relationship
    /// rule. Unset leaves the §6 bounds as the only limit.
    #[test]
    fn operator_max_expire_interval_caps_the_effective_expire() {
        let addr: SocketAddr = "127.0.0.1:323".parse().unwrap();
        let with_max = |max| {
            let mut config = test_config(addr, 3600, 600, 7200);
            config.max_expire_interval = max;
            RtrClient::new(config, mpsc::channel(1).0)
        };
        let secs = |client: &RtrClient| {
            (
                client.refresh_interval.as_secs(),
                client.retry_interval.as_secs(),
                client.expire_interval.as_secs(),
            )
        };

        // The configured expire is capped at construction.
        assert_eq!(secs(&with_max(Some(1_800))), (3600, 600, 1_800));

        // The advertised expire is capped; refresh drops below the cap.
        let mut client = with_max(Some(1_800));
        client.apply_eod_timers(3600, 600, 7200);
        assert_eq!(secs(&client), (1_799, 600, 1_800));

        // An advertised expire under the cap is honoured as-is.
        let mut client = with_max(Some(1_800));
        client.apply_eod_timers(0, 0, 900);
        assert_eq!(secs(&client), (899, 600, 900));

        // Unset: the advertised expire lands verbatim.
        let mut client = with_max(None);
        client.apply_eod_timers(3600, 600, 7200);
        assert_eq!(secs(&client), (3600, 600, 7200));
    }

    /// §6 minimum Refresh and Retry Interval is 1 s: a configured zero is
    /// raised to it instead of polling or reconnecting with no delay, and
    /// the minimum itself is kept.
    #[test]
    fn configured_zero_refresh_and_retry_raise_to_the_section_6_minimum() {
        let addr: SocketAddr = "127.0.0.1:323".parse().unwrap();
        let intervals = |refresh, retry| {
            let client =
                RtrClient::new(test_config(addr, refresh, retry, 3600), mpsc::channel(1).0);
            (client.refresh_interval, client.retry_interval)
        };
        let one = Duration::from_secs(1);
        assert_eq!(intervals(0, 0), (one, one));
        assert_eq!(intervals(1, 1), (one, one));
        assert_eq!(
            intervals(60, 5),
            (Duration::from_secs(60), Duration::from_secs(5))
        );
    }

    /// §6 maximum Retry Interval is 7200 s. Retry is consumed before any
    /// End of Data can lower it, so a larger configured value would park
    /// the reconnect sleep at tokio's far-future deadline and the client
    /// would never retry. It is clamped down with a warning naming both
    /// values; the maximum itself is kept silently.
    #[test]
    fn configured_retry_is_capped_at_the_section_6_maximum() {
        use std::sync::{Arc, Mutex};
        use tracing::field::{Field, Visit};
        use tracing::span::{Attributes, Id, Record};
        use tracing::{Event, Metadata, Subscriber};

        #[derive(Default)]
        struct Fields(Vec<(String, String)>);
        impl Visit for Fields {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                self.0.push((field.name().to_owned(), format!("{value:?}")));
            }
        }
        struct Capture(Arc<Mutex<Vec<Fields>>>);
        impl Subscriber for Capture {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &Attributes<'_>) -> Id {
                Id::from_u64(1)
            }
            fn record(&self, _: &Id, _: &Record<'_>) {}
            fn record_follows_from(&self, _: &Id, _: &Id) {}
            fn event(&self, event: &Event<'_>) {
                let mut fields = Fields::default();
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields);
            }
            fn enter(&self, _: &Id) {}
            fn exit(&self, _: &Id) {}
        }

        let addr: SocketAddr = "127.0.0.1:323".parse().unwrap();
        let retry = |secs| {
            RtrClient::new(test_config(addr, 60, secs, 3600), mpsc::channel(1).0).retry_interval
        };
        let captured = Arc::new(Mutex::new(Vec::new()));
        let capped = tracing::subscriber::with_default(Capture(Arc::clone(&captured)), || {
            // Sibling tests reach the same warn! callsite on threads with no
            // subscriber, which can cache it as disabled process-wide. Warm
            // it here and rebuild its interest against this subscriber.
            retry(0);
            tracing::callsite::rebuild_interest_cache();
            captured.lock().unwrap().clear();
            retry(10_000_000_000)
        });
        assert_eq!(capped, Duration::from_secs(7_200));
        let events = captured.lock().unwrap();
        assert_eq!(events.len(), 1);
        let has =
            |name: &str, value: &str| events[0].0.iter().any(|(n, v)| n == name && v == value);
        assert!(has("timer", "\"retry\""));
        assert!(has("value", "10000000000"));
        assert!(has("bounded", "7200"));

        assert_eq!(retry(7_200), Duration::from_secs(7_200));
        assert_eq!(retry(7_201), Duration::from_secs(7_200));
        assert_eq!(retry(u64::MAX), Duration::from_secs(7_200));
    }

    /// Guard, not a regression test: refresh has no configured ceiling
    /// because it is first used after an End of Data, and End of Data
    /// lowers it below the bounded expire even when the cache omits every
    /// timer. That ordering is what keeps the refresh deadline addition
    /// from overflowing; set the field directly so the guard holds even if
    /// construction ever bounds refresh too.
    #[test]
    fn unbounded_refresh_is_lowered_below_expire_at_end_of_data() {
        let addr: SocketAddr = "127.0.0.1:323".parse().unwrap();
        let mut client = RtrClient::new(test_config(addr, u64::MAX, 600, 3600), mpsc::channel(1).0);
        client.refresh_interval = Duration::from_secs(u64::MAX);
        client.apply_eod_timers(0, 0, 0);
        assert!(client.refresh_interval < client.expire_interval);
        assert_eq!(client.refresh_interval, Duration::from_secs(3_599));
        let _ = TokioInstant::now() + client.refresh_interval;
    }

    /// A configured expire of zero is raised to the §6 minimum of 600 s:
    /// left alone it would arm expiry at the End of Data instant itself
    /// whenever the cache omits its expire, flushing the table just
    /// fetched and reconnecting once a second. A value above the §6
    /// two-day maximum is clamped down to it (the retention the cache
    /// could legally ask for, and an `Instant` the timer can hold). A
    /// non-zero value below the minimum is kept, as at End of Data:
    /// expiring early is safe.
    #[test]
    fn configured_expire_is_bounded_to_the_section_6_range() {
        let addr: SocketAddr = "127.0.0.1:323".parse().unwrap();
        let expire = |secs| {
            RtrClient::new(test_config(addr, 60, 5, secs), mpsc::channel(1).0)
                .expire_interval
                .as_secs()
        };
        assert_eq!(expire(0), 600);
        assert_eq!(expire(1), 1);
        assert_eq!(expire(300), 300);
        assert_eq!(expire(7_200), 7_200);
        assert_eq!(expire(172_800), 172_800);
        assert_eq!(expire(172_801), 172_800);
        assert_eq!(expire(u64::MAX), 172_800);
    }

    /// `max_expire_interval` is bounded the same way, and the bounded
    /// ceiling is what End of Data clamps to: `Some(0)` no longer forces
    /// an immediate expiry after every transaction, and a ceiling above
    /// two days is the two-day maximum.
    #[test]
    fn configured_max_expire_is_bounded_to_the_section_6_range() {
        let addr: SocketAddr = "127.0.0.1:323".parse().unwrap();
        let with_max = |max| {
            let mut config = test_config(addr, 60, 5, 7_200);
            config.max_expire_interval = Some(max);
            RtrClient::new(config, mpsc::channel(1).0)
        };

        let mut client = with_max(0);
        assert_eq!(client.expire_interval.as_secs(), 600);
        client.apply_eod_timers(0, 0, 7_200);
        assert_eq!(client.expire_interval.as_secs(), 600);

        let mut client = with_max(u64::MAX);
        assert_eq!(client.expire_interval.as_secs(), 7_200);
        client.apply_eod_timers(0, 0, 200_000);
        assert_eq!(client.expire_interval.as_secs(), 172_800);

        // A ceiling inside the range is applied verbatim.
        let mut client = with_max(900);
        assert_eq!(client.expire_interval.as_secs(), 900);
        client.apply_eod_timers(0, 0, 7_200);
        assert_eq!(client.expire_interval.as_secs(), 900);
    }

    /// A configured expire (or ceiling) not above the refresh or retry is
    /// left as configured at construction — no data is held, so no
    /// expiry is armed — and the existing End of Data rule lowers
    /// refresh/retry below it at the first point data exists. This
    /// guards that decision; it is not a regression test.
    #[test]
    fn configured_expire_ordering_is_enforced_at_end_of_data() {
        let addr: SocketAddr = "127.0.0.1:323".parse().unwrap();
        let secs = |client: &RtrClient| {
            (
                client.refresh_interval.as_secs(),
                client.retry_interval.as_secs(),
                client.expire_interval.as_secs(),
            )
        };

        let mut client = RtrClient::new(test_config(addr, 3_600, 600, 60), mpsc::channel(1).0);
        assert_eq!(secs(&client), (3_600, 600, 60));
        assert!(client.data_expires_at.is_none());
        client.apply_eod_timers(0, 0, 0);
        assert_eq!(secs(&client), (59, 59, 60));

        let mut config = test_config(addr, 3_600, 600, 7_200);
        config.max_expire_interval = Some(120);
        let mut client = RtrClient::new(config, mpsc::channel(1).0);
        assert_eq!(secs(&client), (3_600, 600, 120));
        assert!(client.data_expires_at.is_none());
        client.apply_eod_timers(0, 0, 0);
        assert_eq!(secs(&client), (119, 119, 120));
    }

    /// §6 timer acceptance rules, asserted on the effective intervals:
    /// zero fields stay "not provided" (configured values untouched),
    /// values above the §6 maxima clamp down, an expire below the §6
    /// minimum is honored as-is (expiring early is safe), and a
    /// refresh/retry not below the expire is lowered (§6: "Caches MUST
    /// set Expire Interval to a value larger than both").
    #[test]
    fn eod_timer_bounds_and_relationships() {
        let addr: SocketAddr = "127.0.0.1:323".parse().unwrap();
        let new_client = || RtrClient::new(test_config(addr, 3600, 600, 7200), mpsc::channel(1).0);
        let secs = |client: &RtrClient| {
            (
                client.refresh_interval.as_secs(),
                client.retry_interval.as_secs(),
                client.expire_interval.as_secs(),
            )
        };

        // Zeros mean "not provided": configured values stay (#740).
        let mut client = new_client();
        client.apply_eod_timers(0, 0, 0);
        assert_eq!(secs(&client), (3600, 600, 7200));

        // Values above the §6 maxima clamp down to them.
        let mut client = new_client();
        client.apply_eod_timers(100_000, 10_000, 200_000);
        assert_eq!(secs(&client), (86_400, 7_200, 172_800));

        // The maxima themselves are legal and adopted verbatim.
        let mut client = new_client();
        client.apply_eod_timers(86_400, 7_200, 172_800);
        assert_eq!(secs(&client), (86_400, 7_200, 172_800));

        // Expire below the §6 minimum of 600 is used as-is — never
        // raised — and drags the (configured) refresh/retry below it.
        let mut client = new_client();
        client.apply_eod_timers(0, 0, 300);
        assert_eq!(secs(&client), (299, 299, 300));

        // Refresh/retry at or above a legal expire are lowered below it.
        let mut client = new_client();
        client.apply_eod_timers(7_200, 6_000, 3_600);
        assert_eq!(secs(&client), (3_599, 3_599, 3_600));
    }

    /// 8210bis §12 code table: codes 2, 4, and 12 are non-fatal (retain);
    /// every other assigned code — and any unassigned code, per the §12
    /// invalid-Error-Report rule — is fatal (flush). Code 0 is the one
    /// code whose two consequences differ: §5.3 makes it a report of a
    /// stale session, so the epoch goes but the data stays. Data expiry
    /// flushes; transport loss and other local guards retain.
    #[test]
    fn error_code_disposition_table() {
        use SessionEndDisposition::{FlushAndDrop, ResyncAndRetain, RetainAndRetry};

        for code in 0..=13u16 {
            let expected = match code {
                0 => ResyncAndRetain,
                2 | 4 | 12 => RetainAndRetry,
                _ => FlushAndDrop,
            };
            let error = RtrError::ServerError {
                code,
                text: String::new(),
            };
            assert_eq!(error.disposition(), expected, "error code {code}");
        }
        // Unassigned code: invalid Error Report → drop + flush (§12).
        assert_eq!(
            RtrError::ServerError {
                code: 255,
                text: String::new(),
            }
            .disposition(),
            FlushAndDrop
        );
        // §5.1 mismatch: the epoch is void, the validated data is not.
        assert_eq!(
            RtrError::SessionIdMismatch {
                expected: Some(7),
                got: 9,
                pdu: vec![],
            }
            .disposition(),
            ResyncAndRetain
        );
        // Expiry (§6) is the only clock that drops validated data.
        assert_eq!(RtrError::Expired.disposition(), FlushAndDrop);
        // Cache Shutdown (§8.6) still flushes: the operator asked for it.
        assert_eq!(
            RtrError::ServerError {
                code: 13,
                text: String::new(),
            }
            .disposition(),
            FlushAndDrop
        );
        // Transport loss and local guards retain until expiry.
        assert_eq!(RtrError::ConnectionClosed.disposition(), RetainAndRetry);
        assert_eq!(
            RtrError::Decode(RtrDecodeError::InvalidPrefix).disposition(),
            FlushAndDrop
        );
        assert_eq!(RtrError::TransactionTimeout.disposition(), RetainAndRetry);
        assert_eq!(
            RtrError::TransactionLimit("record budget exceeded").disposition(),
            RetainAndRetry
        );
        assert_eq!(
            RtrError::VersionMismatch {
                expected: 2,
                got: 1
            }
            .disposition(),
            RetainAndRetry
        );
        assert_eq!(
            RtrError::AspaProviderList { pdu: vec![] }.disposition(),
            RetainAndRetry
        );
    }

    /// Establish an epoch with held data, deliver an Error Report with
    /// `code` while the session is idle, and assert the 8210bis §12
    /// disposition end to end: fatal codes flush (`ServerDown`)
    /// immediately, non-fatal codes retain; in both cases the client
    /// answers a received Error Report with NOTHING (§5.11) and then
    /// retries — resuming the held epoch for codes 2/12, falling back to
    /// v1 for code 4, and resynchronizing from scratch for fatal codes.
    ///
    /// Code 0 retains its data but not its epoch (§5.3): it reports a
    /// stale session, so the client resynchronizes like a fatal code but
    /// keeps the held set live like a non-fatal one.
    async fn drive_received_error_code(code: u16) {
        let flush = !matches!(code, 0 | 2 | 4 | 12);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        // Long expire interval: any flush observed is eager, never the
        // expiry path. Zero retry: reconnect immediately.
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 0, 3600).await;

        write_pdu(
            &mut stream,
            RtrPdu::ErrorReport {
                code,
                pdu: vec![],
                text: format!("error code {code}"),
            },
        )
        .await;

        // §5.11: an Error Report MUST NOT be answered with an Error
        // Report — the client closes without writing anything.
        let mut buf = [0u8; 64];
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "code {code}: client replied to an Error Report");

        if flush {
            let update = timeout(Duration::from_secs(2), vrp_rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                update,
                VrpUpdate::ServerDown { server: addr },
                "code {code}: expected an eager flush"
            );
        }

        let (mut stream2, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream2).await;
        match code {
            // Non-fatal, session state intact: resume the held epoch.
            2 | 12 => {
                assert_eq!(version, crate::rtr_codec::RTR_VERSION_2, "code {code}");
                assert_eq!(
                    pdu,
                    RtrPdu::SerialQuery {
                        session_id: 7,
                        serial: 100,
                    },
                    "code {code}: expected the held epoch to resume"
                );
            }
            // Non-fatal, but the version was rejected: v1 fallback.
            4 => {
                assert_eq!(version, crate::rtr_codec::RTR_VERSION);
                assert_eq!(pdu, RtrPdu::ResetQuery);
            }
            // Fatal (and code 0, which retains its data): epoch-less —
            // full resynchronization.
            _ => {
                assert_eq!(version, crate::rtr_codec::RTR_VERSION_2, "code {code}");
                assert_eq!(pdu, RtrPdu::ResetQuery, "code {code}");
            }
        }
        assert!(
            vrp_rx.try_recv().is_err(),
            "code {code}: unexpected extra update"
        );

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// Full received-error-code disposition matrix, codes 0 through 13,
    /// driven through the in-process server.
    #[tokio::test]
    async fn received_error_report_disposition_matrix() {
        for code in 0..=13 {
            drive_received_error_code(code).await;
        }
    }

    /// Pinned: Cache Restart (code 12, 8210bis §8.5) RETAINS the cache's
    /// data and resyncs — the cache intends to come back before expiry.
    #[tokio::test]
    async fn cache_restart_code_12_retains_and_resyncs() {
        drive_received_error_code(12).await;
    }

    /// Pinned: Cache Shutdown (code 13, 8210bis §8.6) FLUSHES the
    /// cache's data immediately — the operator wants clients to flush.
    #[tokio::test]
    async fn cache_shutdown_code_13_flushes_immediately() {
        drive_received_error_code(13).await;
    }

    /// Server-scoped flush through a real [`VrpManager`]: two caches
    /// loaded, cache A sends Cache Shutdown (13) → A's VRPs and ASPAs
    /// are gone immediately (validation flips for A-only routes), B's
    /// data is intact, no expire wait.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "two full cache lifecycles driven against one real VrpManager"
    )]
    async fn cache_shutdown_flushes_only_that_caches_data() {
        use rustbgpd_wire::{Ipv4Prefix, Prefix, RpkiValidation};

        use crate::vrp_manager::VrpManager;

        let listener_a = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listener_b = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let addr_b = listener_b.local_addr().unwrap();

        let (vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (aspa_tx, mut aspa_rx) = mpsc::channel(16);
        let manager_handle =
            tokio::spawn(VrpManager::new(vrp_rx, rib_tx).with_aspa_tx(aspa_tx).run());

        // expire 3600: the flush below must be eager, not expiry.
        let client_a = zero_retry_client(addr_a, vrp_tx.clone());
        let client_b = zero_retry_client(addr_b, vrp_tx);
        let handle_a = tokio::spawn(client_a.run());
        let handle_b = tokio::spawn(client_b.run());

        // Cache A: one VRP and one ASPA record.
        let (mut stream_a, _) = listener_a.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream_a).await, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream_a,
            &[
                RtrPdu::CacheResponse { session_id: 7 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 113, 0),
                    asn: 65001,
                },
                RtrPdu::Aspa {
                    flags: 1,
                    customer_asn: 65001,
                    provider_asns: vec![65010],
                },
                RtrPdu::EndOfData {
                    session_id: 7,
                    serial: 100,
                    refresh: 60,
                    retry: 0,
                    expire: 3600,
                },
            ],
        )
        .await;
        let table = timeout(Duration::from_secs(2), rib_rx.recv())
            .await
            .unwrap()
            .unwrap()
            .table;
        assert_eq!(table.len(), 1);
        let aspa_table = timeout(Duration::from_secs(2), aspa_rx.recv())
            .await
            .unwrap()
            .unwrap()
            .table;
        assert_eq!(aspa_table.len(), 1);

        // Cache B: a different VRP.
        let (mut stream_b, _) = listener_b.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream_b).await, RtrPdu::ResetQuery);
        write_pdus(
            &mut stream_b,
            &[
                RtrPdu::CacheResponse { session_id: 21 },
                RtrPdu::Ipv4Prefix {
                    flags: 1,
                    prefix_len: 24,
                    max_len: 24,
                    prefix: Ipv4Addr::new(203, 0, 114, 0),
                    asn: 65002,
                },
                RtrPdu::EndOfData {
                    session_id: 21,
                    serial: 50,
                    refresh: 60,
                    retry: 0,
                    expire: 3600,
                },
            ],
        )
        .await;
        let table = timeout(Duration::from_secs(2), rib_rx.recv())
            .await
            .unwrap()
            .unwrap()
            .table;
        assert_eq!(table.len(), 2);

        let route_a = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
        let route_b = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 114, 0), 24));
        assert_eq!(table.validate(&route_a, 65001), RpkiValidation::Valid);
        assert_eq!(table.validate(&route_b, 65002), RpkiValidation::Valid);

        // Cache A shuts down deliberately (§8.6).
        write_pdu(
            &mut stream_a,
            RtrPdu::ErrorReport {
                code: 13,
                pdu: vec![],
                text: "Cache Shutdown".to_string(),
            },
        )
        .await;

        // A's data — and only A's — is flushed immediately: validation
        // flips to NotFound for the A-only route, B's stays Valid.
        let table = timeout(Duration::from_secs(2), rib_rx.recv())
            .await
            .unwrap()
            .unwrap()
            .table;
        assert_eq!(table.len(), 1);
        assert_eq!(table.validate(&route_a, 65001), RpkiValidation::NotFound);
        assert_eq!(table.validate(&route_b, 65002), RpkiValidation::Valid);
        let aspa_table = timeout(Duration::from_secs(2), aspa_rx.recv())
            .await
            .unwrap()
            .unwrap()
            .table;
        assert!(aspa_table.is_empty());

        handle_a.abort();
        handle_b.abort();
        manager_handle.abort();
        let _ = handle_a.await;
        let _ = handle_b.await;
        let _ = manager_handle.await;
    }

    /// 8210bis §7: a PDU whose Protocol Version differs from the
    /// negotiated one after negotiation completes → the client drops the
    /// session, SHOULD-sending Error Report code 8 ("Unexpected Protocol
    /// Version") first. Held data is retained (the epoch itself is not
    /// invalidated) and resumes on reconnect.
    #[tokio::test]
    async fn unexpected_version_pdu_triggers_error_report_8() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 0, 3600).await;

        // v1 PDU inside a negotiated-v2 session.
        let offending_pdu = RtrPdu::SerialNotify {
            session_id: 7,
            serial: 101,
        };
        write_pdu_version(
            &mut stream,
            offending_pdu.clone(),
            crate::rtr_codec::RTR_VERSION,
        )
        .await;

        let mut offending = Vec::new();
        offending_pdu
            .encode_with_version(&mut offending, crate::rtr_codec::RTR_VERSION)
            .unwrap();
        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::ErrorReport {
                code: 8,
                pdu: offending,
                text: "unexpected protocol version".to_string(),
            }
        );

        // Retention: no flush, and the held epoch resumes.
        let (mut stream2, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            read_pdu(&mut stream2).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// 8210bis §12 code 5: a PDU type not known by the receiver → the
    /// client sends Error Report code 5 ("Unsupported PDU Type") with
    /// the offending frame embedded, then drops the session. Held data
    /// is retained.
    #[tokio::test]
    async fn unsupported_pdu_type_triggers_error_report_5() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 0, 3600).await;

        // A v2 frame with an unassigned PDU type (99).
        let bogus_frame = [crate::rtr_codec::RTR_VERSION_2, 99, 0, 0, 0, 0, 0, 8];
        stream.write_all(&bogus_frame).await.unwrap();

        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::ErrorReport {
                code: 5,
                pdu: bogus_frame.to_vec(),
                text: "unsupported PDU type".to_string(),
            }
        );

        // Retention: no flush, and the held epoch resumes.
        let (mut stream2, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            read_pdu(&mut stream2).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// 8210bis §5.11/§7: even an Error Report that is itself erroneous
    /// (here: a version byte the session did not negotiate) MUST NOT be
    /// answered with an Error Report — the session is simply dropped.
    #[tokio::test]
    async fn version_mismatched_error_report_gets_no_reply() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 0, 3600).await;

        // StayRTR-style: an Error Report stamped with version 0 inside a
        // negotiated-v2 session.
        write_pdu_version(
            &mut stream,
            RtrPdu::ErrorReport {
                code: 8,
                pdu: vec![],
                text: "Bad protocol version".to_string(),
            },
            0,
        )
        .await;

        // No reply of any kind; the client just closes.
        let mut buf = [0u8; 64];
        let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0, "client answered an Error Report with a PDU");

        // Version mismatch retains: the held epoch resumes at its own
        // version.
        let (mut stream2, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        let (version, pdu) = read_pdu_with_version(&mut stream2).await;
        assert_eq!(version, crate::rtr_codec::RTR_VERSION_2);
        assert_eq!(
            pdu,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    /// Error Report emission is best-effort: a cache that triggers a
    /// session-ending error and then never reads again must not block
    /// the drop — the client still tears down and retries promptly.
    #[tokio::test]
    async fn error_report_emission_is_best_effort_when_server_stops_reading() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let client = zero_retry_client(addr, vrp_tx);
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 0, 3600).await;

        write_pdu(
            &mut stream,
            RtrPdu::SerialNotify {
                session_id: 7,
                serial: 101,
            },
        )
        .await;
        assert_eq!(
            read_pdu(&mut stream).await,
            RtrPdu::SerialQuery {
                session_id: 7,
                serial: 100,
            }
        );

        // Session-ID mismatch — and from here on the server never reads
        // another byte.
        write_pdu(&mut stream, RtrPdu::CacheResponse { session_id: 9 }).await;

        // The drop still completes promptly. The mismatch retains the
        // held data, so the reconnect — not a `ServerDown` — is the
        // observable that the teardown was not blocked.
        let (mut stream2, _) = timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("session drop was blocked by error-report emission")
            .unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert!(vrp_rx.try_recv().is_err());

        client_handle.abort();
        let _ = client_handle.await;
    }

    #[test]
    fn serial_not_before_rfc1982_boundaries() {
        // Same serial: not a regression.
        assert!(serial_not_before(100, 100));
        // Forward step, including across the u32 wrap.
        assert!(serial_not_before(100, 101));
        assert!(serial_not_before(u32::MAX, 0));
        assert!(serial_not_before(u32::MAX, (1 << 31) - 2));
        // Backward step, including across the wrap, is a regression.
        assert!(!serial_not_before(101, 100));
        assert!(!serial_not_before(0, u32::MAX));
        // Exactly half the number space away is undefined in RFC 1982;
        // treated as a regression (the conservative reading).
        assert!(!serial_not_before(0, 1 << 31));
    }

    fn host_prefixes_and_end_of_data(serial: u32, last_octets: &[u8]) -> Vec<RtrPdu> {
        let mut pdus = vec![RtrPdu::CacheResponse { session_id: 7 }];
        pdus.extend(last_octets.iter().map(|&last| RtrPdu::Ipv4Prefix {
            flags: 1,
            prefix_len: 32,
            max_len: 32,
            prefix: Ipv4Addr::new(203, 0, 113, last),
            asn: 65001,
        }));
        pdus.push(RtrPdu::EndOfData {
            session_id: 7,
            serial,
            refresh: 60,
            retry: 0,
            expire: 3600,
        });
        pdus
    }

    /// A panic inside a session is a lost session, not a dead client. The
    /// manager sees an ordinary disconnect and keeps the cache's data, with
    /// nothing published in the gap; the client comes back and
    /// resynchronizes with a Reset Query, because the held serial may be
    /// ahead of what the manager received.
    #[tokio::test]
    async fn panic_in_a_session_retains_data_and_resynchronizes_with_a_reset_query() {
        use std::sync::Mutex;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (attachment, handle, _queries) = CacheInventoryAttachment::new([addr]);
        let (vrp_tx, vrp_rx) = mpsc::channel(8);
        let (table_tx, mut table_rx) = mpsc::channel(8);
        let transitions = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&transitions);
        let manager = tokio::spawn(
            crate::VrpManager::new(vrp_rx, table_tx)
                .with_cache_inventory(attachment)
                .with_connectivity_observer(move |_, connected| {
                    seen.lock().unwrap().push(connected);
                })
                .run(),
        );

        // The expire observer runs at start and inside each End of Data
        // commit: the third call panics in the second transaction, before
        // its update is delivered.
        let expire_calls = AtomicUsize::new(0);
        let restarts = Arc::new(AtomicUsize::new(0));
        let restart_counter = Arc::clone(&restarts);
        let client = zero_retry_client(addr, vrp_tx)
            .with_cache_inventory(handle)
            .with_expire_observer(move |_| {
                assert!(
                    expire_calls.fetch_add(1, Ordering::SeqCst) != 2,
                    "injected RTR client panic"
                );
            })
            .with_restart_observer(move || {
                restart_counter.fetch_add(1, Ordering::SeqCst);
            });
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(read_pdu(&mut stream).await, RtrPdu::ResetQuery);
        write_pdus(&mut stream, &host_prefixes_and_end_of_data(100, &[1])).await;
        assert_eq!(table_rx.recv().await.unwrap().table.len(), 1);

        notify_and_expect_serial_query(&mut stream, 101, 100).await;
        write_pdus(&mut stream, &host_prefixes_and_end_of_data(101, &[2])).await;

        let (mut stream2, _) = timeout(Duration::from_secs(5), listener.accept())
            .await
            .expect("the client did not reconnect after its panic")
            .unwrap();
        assert_eq!(read_pdu(&mut stream2).await, RtrPdu::ResetQuery);
        assert_eq!(restarts.load(Ordering::SeqCst), 1);
        // The panic closed the old connection.
        assert_eq!(stream.read(&mut [0u8; 1]).await.unwrap(), 0);

        // The next table the manager publishes is the resynchronized one:
        // the retained data was neither flushed nor changed in between.
        write_pdus(&mut stream2, &host_prefixes_and_end_of_data(101, &[3, 4])).await;
        let table = table_rx.recv().await.unwrap().table;
        let state = |last| {
            let host = rustbgpd_wire::Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, last), 32);
            table.validate(&rustbgpd_wire::Prefix::V4(host), 65001)
        };
        assert_eq!(table.len(), 2);
        for last in [3, 4] {
            assert_eq!(state(last), rustbgpd_wire::RpkiValidation::Valid);
        }
        // Neither the replaced entry nor the undelivered delta is present.
        for last in [1, 2] {
            assert_eq!(state(last), rustbgpd_wire::RpkiValidation::NotFound);
        }
        assert_eq!(*transitions.lock().unwrap(), [true, false, true]);

        client_handle.abort();
        let _ = client_handle.await;
        manager.abort();
    }

    /// Data held when the client panics keeps its original expiry: with
    /// the cache unreachable afterwards (every later dial panics too), the
    /// client flushes the cache's data exactly at the expire interval of
    /// the last End of Data, as it does across failed reconnects.
    #[tokio::test(start_paused = true)]
    async fn data_held_across_a_panic_is_flushed_at_its_original_expiry() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (vrp_tx, mut vrp_rx) = mpsc::channel(8);
        let dials = AtomicUsize::new(0);
        let restarts = Arc::new(AtomicUsize::new(0));
        let restart_counter = Arc::clone(&restarts);
        let client = RtrClient::new(test_config(addr, 60, 5, 3600), vrp_tx)
            .with_dialer(move |remote| {
                let first = dials.fetch_add(1, Ordering::SeqCst) == 0;
                async move {
                    assert!(first, "injected RTR client panic");
                    TcpStream::connect(remote).await
                }
            })
            .with_restart_observer(move || {
                restart_counter.fetch_add(1, Ordering::SeqCst);
            });
        let client_handle = tokio::spawn(client.run());

        let (mut stream, _) = listener.accept().await.unwrap();
        establish_epoch_with_timers(&mut stream, &mut vrp_rx, 5, 120).await;
        let accepted_at = TokioInstant::now();
        drop(stream);

        assert_eq!(
            vrp_rx.recv().await,
            Some(VrpUpdate::ServerDown { server: addr })
        );
        assert_eq!(
            accepted_at.elapsed(),
            Duration::from_secs(120),
            "flushed at the End of Data expire, neither earlier nor later"
        );
        assert!(restarts.load(Ordering::SeqCst) > 0);

        client_handle.abort();
        let _ = client_handle.await;
    }
}
