//! VRP + ASPA manager — merges tables from multiple RTR cache servers.
//!
//! Runs as a single tokio task. Receives [`VrpUpdate`] messages from RTR
//! clients and maintains merged, deduplicated [`VrpTable`] and [`AspaTable`]
//! snapshots. When either table changes, sends the updated snapshot to the
//! RIB manager.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;

use rustc_hash::FxHashSet;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::time::Instant as TokioInstant;
use tracing::{debug, error, info, warn};

use crate::aspa::{AspaRecord, AspaTable};
use crate::rtr_client::{Reservation, VrpUpdate, catch_panic};
use crate::vrp::{VrpEntry, VrpTable};

const CACHE_QUERY_CAPACITY: usize = 16;
/// Maximum number of configured cache rows returned by one inventory query.
pub const MAX_CACHE_ROWS: usize = 256;

/// Most recent accepted contribution from one configured cache.
///
/// This state can remain present after a disconnect until it is flushed or
/// expires. Counts describe this cache's retained data, not the merged table.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedCacheState {
    /// RTR protocol version at the last accepted End of Data, when known.
    pub protocol_version: Option<u8>,
    /// RTR session ID at the last accepted End of Data, when known.
    pub session_id: Option<u16>,
    /// RTR serial at the last accepted End of Data, when known.
    pub serial: Option<u32>,
    /// Distinct IPv4 VRPs retained from this cache.
    pub vrp_v4_count: usize,
    /// Distinct IPv6 VRPs retained from this cache.
    pub vrp_v6_count: usize,
    /// Customer ASNs with retained ASPA records from this cache.
    pub aspa_count: usize,
    /// Whole seconds elapsed since the last accepted update's monotonic instant.
    pub age_seconds: u64,
}

/// Connection and accepted-data state for one configured cache server.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheState {
    /// Configured cache address.
    pub server: SocketAddr,
    /// Whether the RTR session is currently connected.
    pub connected: bool,
    /// Retained accepted data, independent of current connectivity.
    /// `None` means no update has been accepted, or data was flushed or expired.
    pub accepted: Option<AcceptedCacheState>,
}

/// Bounded snapshot of configured cache servers, ordered by socket address.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheList {
    /// First [`MAX_CACHE_ROWS`] configured servers in address order.
    pub rows: Vec<CacheState>,
    /// Configured servers excluded by the row limit.
    pub omitted: u64,
}

/// Inventory request delivered to the manager actor.
pub struct CacheQuery {
    reply: oneshot::Sender<CacheList>,
}

/// Cloneable sender for cache inventory requests to a running [`VrpManager`].
#[derive(Clone)]
pub struct CacheQueryHandle(mpsc::Sender<CacheQuery>);

impl CacheQueryHandle {
    /// Request the current bounded cache inventory.
    ///
    /// Awaits channel capacity and then the actor's reply without an internal
    /// timeout. Callers needing a deadline must bound the whole operation.
    ///
    /// # Errors
    ///
    /// Returns [`CacheQueryError`] when the manager actor has stopped before
    /// accepting or answering the request.
    pub async fn list(&self) -> Result<CacheList, CacheQueryError> {
        let (reply, rx) = oneshot::channel();
        self.0
            .send(CacheQuery { reply })
            .await
            .map_err(|_| CacheQueryError)?;
        rx.await.map_err(|_| CacheQueryError)
    }
}

/// The manager actor stopped before accepting or answering an inventory query.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("RPKI cache inventory actor is unavailable")]
pub struct CacheQueryError;

#[derive(Debug, Default)]
struct ServerVrpTable {
    entries: HashSet<VrpEntry>,
    v4_count: usize,
    v6_count: usize,
    /// Record-budget charge for this cache's VRP and ASPA data, released
    /// when the table is replaced or removed.
    charge: Option<Reservation>,
    /// When the owning client's expire interval ends for this data, as its
    /// last applied update reported it. `None` on the legacy update channel.
    expires_at: Option<TokioInstant>,
}

impl ServerVrpTable {
    fn from_entries(entries: impl IntoIterator<Item = VrpEntry>) -> Self {
        let mut table = Self::default();
        for entry in entries {
            table.insert(entry);
        }
        table
    }

    fn insert(&mut self, entry: VrpEntry) -> bool {
        let is_v4 = entry.prefix.is_ipv4();
        if !self.entries.insert(entry) {
            return false;
        }
        if is_v4 {
            self.v4_count += 1;
        } else {
            self.v6_count += 1;
        }
        true
    }

    fn remove(&mut self, entry: &VrpEntry) -> bool {
        if !self.entries.remove(entry) {
            return false;
        }
        match entry.prefix {
            std::net::IpAddr::V4(_) => self.v4_count -= 1,
            std::net::IpAddr::V6(_) => self.v6_count -= 1,
        }
        true
    }

    fn iter(&self) -> impl Iterator<Item = &VrpEntry> {
        self.entries.iter()
    }

    const fn counts(&self) -> (usize, usize) {
        (self.v4_count, self.v6_count)
    }
}

#[derive(Debug)]
pub(crate) enum EnhancedVrpUpdate {
    Connected {
        server: SocketAddr,
    },
    Disconnected {
        server: SocketAddr,
        flush: bool,
    },
    Expired {
        server: SocketAddr,
    },
    Full {
        server: SocketAddr,
        entries: Vec<VrpEntry>,
        aspa_records: Vec<AspaRecord>,
        charge: Reservation,
        version: u8,
        session_id: u16,
        serial: u32,
        accepted_at: Instant,
        expires_at: TokioInstant,
    },
    Incremental {
        server: SocketAddr,
        announced: Vec<VrpEntry>,
        withdrawn: Vec<VrpEntry>,
        aspa_announced: Vec<AspaRecord>,
        aspa_withdrawn: Vec<AspaRecord>,
        charge: Reservation,
        version: u8,
        session_id: u16,
        serial: u32,
        accepted_at: Instant,
        expires_at: TokioInstant,
    },
}

impl EnhancedVrpUpdate {
    /// Set a data update's expiry instant; a plain assignment, so the client
    /// can call it between committing its End of Data and sending.
    pub(crate) fn set_expires_at(&mut self, at: TokioInstant) {
        if let Self::Full { expires_at, .. } | Self::Incremental { expires_at, .. } = self {
            *expires_at = at;
        }
    }
}

/// How many times the manager has asked each cache's client for a full
/// table. A client answers a count above the one it last saw.
pub(crate) type ResyncRequests = HashMap<SocketAddr, u64>;

/// Cloneable sender used by RTR clients to report cache updates to the manager.
#[derive(Clone)]
pub struct CacheUpdateHandle(
    pub(crate) mpsc::Sender<EnhancedVrpUpdate>,
    pub(crate) watch::Receiver<ResyncRequests>,
);

// The handle and the attachment were unwind safe before they carried the
// resync watch, and still are: they hold only channel endpoints and plain
// collections, and a panic while one is borrowed leaves nothing half
// written (the watch value is replaced under its own lock, which does not
// poison).
impl std::panic::UnwindSafe for CacheUpdateHandle {}
impl std::panic::RefUnwindSafe for CacheUpdateHandle {}
impl std::panic::UnwindSafe for CacheInventoryAttachment {}
impl std::panic::RefUnwindSafe for CacheInventoryAttachment {}

/// Inventory state and receivers owned by one [`VrpManager`].
///
/// Attach this to the manager before running it. Retain update senders for
/// active clients; closing all update senders and the legacy update channel
/// ends the actor. Query senders alone do not keep it running.
pub struct CacheInventoryAttachment {
    update_rx: mpsc::Receiver<EnhancedVrpUpdate>,
    query_rx: mpsc::Receiver<CacheQuery>,
    query_open: bool,
    states: BTreeMap<SocketAddr, InternalCacheState>,
    resync_tx: watch::Sender<ResyncRequests>,
    /// Caches whose next applied data update must be a full table: the
    /// manager lost an update from them, so it no longer knows what a serial
    /// delta applies to. What it holds from them stays in use until then.
    resync_pending: HashSet<SocketAddr>,
}

#[derive(Clone, Debug)]
struct InternalCacheState {
    connected: bool,
    accepted: Option<AcceptedMetadata>,
}

#[derive(Clone, Debug)]
struct AcceptedMetadata {
    version: Option<u8>,
    session_id: Option<u16>,
    serial: Option<u32>,
    accepted_at: Instant,
}

impl CacheInventoryAttachment {
    /// Initialize rows for configured servers and return the attachment,
    /// update sender, and query sender. Rows start disconnected with no
    /// accepted data. Pass the attachment to
    /// [`VrpManager::with_cache_inventory`] and run that manager to serve queries.
    #[must_use]
    pub fn new(
        servers: impl IntoIterator<Item = SocketAddr>,
    ) -> (Self, CacheUpdateHandle, CacheQueryHandle) {
        let (update_tx, update_rx) = mpsc::channel(256);
        let (query_tx, query_rx) = mpsc::channel(CACHE_QUERY_CAPACITY);
        let (resync_tx, resync_rx) = watch::channel(ResyncRequests::new());
        let states = servers
            .into_iter()
            .map(|server| {
                (
                    server,
                    InternalCacheState {
                        connected: false,
                        accepted: None,
                    },
                )
            })
            .collect();
        (
            Self {
                update_rx,
                query_rx,
                query_open: true,
                states,
                resync_tx,
                resync_pending: HashSet::new(),
            },
            CacheUpdateHandle(update_tx, resync_rx),
            CacheQueryHandle(query_tx),
        )
    }
}

/// Message sent from VRP manager to RIB manager when the VRP table changes.
#[derive(Debug, Clone)]
pub struct RpkiTableUpdate {
    /// The new merged VRP table snapshot.
    pub table: Arc<VrpTable>,
    /// A superset of the VRP entries that differ between the previously
    /// distributed snapshot and this one, whatever produced the update. The
    /// merged table is a union of per-server sets, so a route's validation
    /// outcome can only change if its prefix is covered by one of these
    /// entries, which lets the RIB manager revalidate just the covered
    /// routes.
    ///
    /// For a full table that replaces a server's previous one, and for the
    /// removal of a server's data (flush or expiry), the list is exactly the
    /// entries that joined or left the merged table: an entry another server
    /// still holds is not in it. For an RTR incremental (serial) sync it is
    /// every entry the server announced or withdrawn.
    ///
    /// `None` means there is no baseline to compare with (a server's first
    /// table, also after its data was flushed or expired) and consumers
    /// must revalidate everything.
    pub delta: Option<Vec<VrpEntry>>,
}

/// Message sent from VRP manager to RIB manager when the ASPA table changes.
#[derive(Debug, Clone)]
pub struct AspaTableUpdate {
    /// The new merged ASPA table snapshot.
    pub table: Arc<AspaTable>,
    /// A superset of the customer ASNs whose merged provider set differs
    /// from the previously distributed snapshot: the customers one server
    /// announced or withdrew in an incremental update, those whose record
    /// differs between a server's replacing full table and its previous
    /// one, or those a removed server held. Another server's record for the
    /// same customer is not taken into account.
    ///
    /// `None` requires a full revalidation (a server's first table).
    pub changed_customer_asns: Option<FxHashSet<u32>>,
}

type EndOfDataObserver = Box<dyn Fn(SocketAddr, Option<Instant>) + Send + Sync>;

/// What the inventory channel adds to a data update: applied in the same
/// commit as the data it describes.
struct Accepted {
    charge: Reservation,
    expires_at: TokioInstant,
    metadata: AcceptedMetadata,
}

/// One update, built and not yet installed; see [`VrpManager::stage`].
struct Staged {
    server: SocketAddr,
    incremental: bool,
    /// The cache's next sets; `None` removes them.
    vrps: Option<ServerVrpTable>,
    aspas: Option<HashMap<u32, Vec<u32>>>,
    /// The merged tables to distribute, when they change.
    vrp_update: Option<RpkiTableUpdate>,
    aspa_update: Option<AspaTableUpdate>,
    accepted: Option<Accepted>,
}

/// The inventory messages by what a panic in their handling can cost.
#[derive(Clone, Copy)]
enum UpdateClass {
    /// Connectivity only: no validation data involved.
    Session,
    /// A full table or a serial delta, lost if its handling panics.
    Data,
    /// A flush or an expiry, which must still take effect.
    Removal,
}

/// Merges VRP and ASPA data from multiple RTR cache servers.
pub struct VrpManager {
    /// Per-server VRP tables. Each table owns a set for bounded incremental
    /// updates and cached family counts for bounded inventory queries.
    server_tables: HashMap<SocketAddr, ServerVrpTable>,
    /// Per-server ASPA state, keyed by customer ASN.
    ///
    /// Keyed (not a record list) because 8210bis ASPA PDUs carry the
    /// complete provider set per customer ASN: an announce REPLACES the
    /// customer's previous provider set, and a withdraw removes the
    /// customer ASN entirely.
    server_aspa_tables: HashMap<SocketAddr, HashMap<u32, Vec<u32>>>,
    /// Current distributed VRP table; absent until the first accepted update.
    current_table: Option<Arc<VrpTable>>,
    /// Current distributed ASPA table; absent until the first accepted update.
    current_aspa_table: Option<Arc<AspaTable>>,
    /// Receiver for updates from RTR clients.
    update_rx: mpsc::Receiver<VrpUpdate>,
    /// Sender for VRP table snapshots to the RIB manager.
    rib_tx: mpsc::Sender<RpkiTableUpdate>,
    /// Sender for ASPA table snapshots to the RIB manager.
    aspa_rib_tx: Option<mpsc::Sender<AspaTableUpdate>>,
    readiness_observer: Option<Box<dyn Fn(SocketAddr, bool) + Send + Sync>>,
    connectivity_observer: Option<Box<dyn Fn(SocketAddr, bool) + Send + Sync>>,
    end_of_data_observer: Option<EndOfDataObserver>,
    fault_observer: Option<Box<dyn Fn() + Send + Sync>>,
    resync_observer: Option<Box<dyn Fn(SocketAddr, bool) + Send + Sync>>,
    cache_inventory: Option<CacheInventoryAttachment>,
    test_precommit_panic_on: Option<std::sync::atomic::AtomicUsize>,
    /// Upcoming [`Self::injected_fault`] calls that panic.
    #[cfg(test)]
    pub(crate) injected_faults: Arc<std::sync::atomic::AtomicUsize>,
}

impl VrpManager {
    /// Create a new VRP manager (without ASPA support).
    #[must_use]
    pub fn new(
        update_rx: mpsc::Receiver<VrpUpdate>,
        rib_tx: mpsc::Sender<RpkiTableUpdate>,
    ) -> Self {
        Self {
            server_tables: HashMap::new(),
            server_aspa_tables: HashMap::new(),
            current_table: None,
            current_aspa_table: None,
            update_rx,
            rib_tx,
            aspa_rib_tx: None,
            readiness_observer: None,
            connectivity_observer: None,
            end_of_data_observer: None,
            fault_observer: None,
            resync_observer: None,
            cache_inventory: None,
            test_precommit_panic_on: None,
            #[cfg(test)]
            injected_faults: Arc::default(),
        }
    }

    /// Attach cache inventory receivers and state before [`Self::run`].
    /// Pass the update handle from [`CacheInventoryAttachment::new`] to RTR
    /// clients and retain its query handle for inventory readers. Without
    /// this attachment, inventory updates and queries have no receiver in
    /// the manager.
    #[must_use]
    pub fn with_cache_inventory(mut self, attachment: CacheInventoryAttachment) -> Self {
        self.cache_inventory = Some(attachment);
        self
    }

    /// Set the ASPA table update sender.
    #[must_use]
    pub fn with_aspa_tx(mut self, tx: mpsc::Sender<AspaTableUpdate>) -> Self {
        self.aspa_rib_tx = Some(tx);
        self
    }

    /// Observe per-cache readiness after its retained contribution and both
    /// merged validation tables have been updated.
    #[must_use]
    pub fn with_readiness_observer(
        mut self,
        observer: impl Fn(SocketAddr, bool) + Send + Sync + 'static,
    ) -> Self {
        self.readiness_observer = Some(Box::new(observer));
        self
    }

    /// Observe a configured cache's RTR session going up (`true`) or down
    /// (`false`), from the same transitions that set
    /// [`CacheState::connected`]. Independent of readiness: an ordinary
    /// disconnect retains the contribution until expiry, while a flush drops
    /// it at once. Fires only for
    /// caches registered through [`CacheInventoryAttachment`].
    #[must_use]
    pub fn with_connectivity_observer(
        mut self,
        observer: impl Fn(SocketAddr, bool) + Send + Sync + 'static,
    ) -> Self {
        self.connectivity_observer = Some(Box::new(observer));
        self
    }

    /// Observe a configured cache's last accepted End of Data: `Some` with
    /// the monotonic instant [`AcceptedCacheState::age_seconds`] counts from,
    /// after each accepted full or incremental transaction, and `None` when
    /// a flush or expiry drops the retained contribution. An ordinary
    /// disconnect does not fire it, because the contribution is retained.
    /// Fires only for caches registered through [`CacheInventoryAttachment`],
    /// from the updates their clients send on its [`CacheUpdateHandle`].
    #[must_use]
    pub fn with_end_of_data_observer(
        mut self,
        observer: impl Fn(SocketAddr, Option<Instant>) + Send + Sync + 'static,
    ) -> Self {
        self.end_of_data_observer = Some(Box::new(observer));
        self
    }

    /// Observe each panic the manager recovers from; see [`Self::run`].
    #[must_use]
    pub fn with_fault_observer(mut self, observer: impl Fn() + Send + Sync + 'static) -> Self {
        self.fault_observer = Some(Box::new(observer));
        self
    }

    /// Observe a configured cache becoming resync pending (`true`) and its
    /// next full table being applied (`false`). While pending, the manager
    /// keeps using what it last accepted from that cache, until that data's
    /// expiry; see [`Self::run`].
    #[must_use]
    pub fn with_resync_observer(
        mut self,
        observer: impl Fn(SocketAddr, bool) + Send + Sync + 'static,
    ) -> Self {
        self.resync_observer = Some(Box::new(observer));
        self
    }

    /// Inject one panic before the numbered metadata-bearing data update is
    /// staged. Zero disables the injection. For daemon integration tests only;
    /// never enable this in a running service.
    #[doc(hidden)]
    #[must_use]
    pub fn with_test_precommit_panic_on(mut self, update_number: usize) -> Self {
        self.test_precommit_panic_on = Some(std::sync::atomic::AtomicUsize::new(update_number));
        self
    }

    /// Where a test makes the manager panic: before any state changes.
    #[cfg_attr(
        not(test),
        expect(clippy::unused_self, reason = "test-only fault hook")
    )]
    fn injected_fault(&self) {
        #[cfg(test)]
        {
            use std::sync::atomic::Ordering;
            let faults = &self.injected_faults;
            if faults
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                panic!("injected VRP manager fault");
            }
        }
    }

    /// Report the cache's current accepted instant to the End-of-Data
    /// observer, from the same state [`Self::cache_list`] serves.
    fn notify_end_of_data(&self, server: SocketAddr) {
        let Some(state) = self
            .cache_inventory
            .as_ref()
            .and_then(|i| i.states.get(&server))
        else {
            return;
        };
        let accepted_at = state.accepted.as_ref().map(|m| m.accepted_at);
        if let Some(observer) = &self.end_of_data_observer {
            self.observe(|| observer(server, accepted_at));
        }
    }

    /// Call an embedder's observer. A panic in it is counted and logged as a
    /// fault and costs only that notification: every observer runs after the
    /// state it reports was installed, so the panic says nothing about the
    /// update and must not be handled as a lost one.
    fn observe(&self, notify: impl FnOnce()) {
        // Unwind safety: the manager's state does not depend on observers.
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(notify)).is_err() {
            self.record_fault("observer", None);
        }
    }

    fn set_connected(&mut self, server: SocketAddr, connected: bool) {
        let Some(state) = self
            .cache_inventory
            .as_mut()
            .and_then(|i| i.states.get_mut(&server))
        else {
            return;
        };
        state.connected = connected;
        if let Some(observer) = &self.connectivity_observer {
            self.observe(|| observer(server, connected));
        }
    }

    /// Main event loop.
    ///
    /// With a [`CacheInventoryAttachment`], a panic while handling one of
    /// its messages does not end the manager. Every update is built before
    /// any of it is installed, so the per-cache sets and the published
    /// tables are as they were before the message:
    ///
    /// - A lost full table or serial delta leaves the cache's previous data
    ///   in use and marks the cache resync pending. Its client is asked for
    ///   a full table and sends a Reset Query after its retry interval;
    ///   until that table is applied, the cache's serial deltas are dropped,
    ///   and the manager drops the data it holds at the expiry instant that
    ///   came with it, because the client's own clock now belongs to the
    ///   update that was lost (RFC 8210 section 6: data is not retained past
    ///   the expire interval).
    /// - A lost flush or expiry is carried out again; the cache's data
    ///   leaves the tables. A second panic there ends the manager.
    /// - A panic in an observer is counted as a fault and costs only that
    ///   notification; the update it reported is already installed.
    /// - A lost connectivity change or inventory query costs only itself.
    ///
    /// Updates on the legacy channel are not covered: legacy senders have no
    /// resync channel, even when other senders use an inventory attachment.
    /// A panic outside these per-message and read-only query boundaries ends
    /// the manager; there is no proved state checkpoint for a general restart.
    pub async fn run(mut self) {
        let mut legacy_updates_open = true;
        let mut enhanced_updates_open = self.cache_inventory.is_some();
        loop {
            if self.cache_inventory.is_none() {
                let Some(update) = self.update_rx.recv().await else {
                    break;
                };
                self.handle_update(update).await;
                continue;
            }
            if !legacy_updates_open && !enhanced_updates_open {
                break;
            }
            let held_expiry = self.pending_expiry();
            let Some(inventory) = self.cache_inventory.as_mut() else {
                continue;
            };
            tokio::select! {
                biased;
                // First, so held data leaves at its instant whatever else
                // is queued.
                server = async {
                    match held_expiry {
                        Some((at, server)) => {
                            tokio::time::sleep_until(at).await;
                            server
                        }
                        None => std::future::pending().await,
                    }
                } => {
                    warn!(
                        %server,
                        "data held for a cache awaiting resynchronization reached its expiry"
                    );
                    self.receive(EnhancedVrpUpdate::Expired { server }).await;
                }
                update = self.update_rx.recv(), if legacy_updates_open => match update {
                    Some(update) => self.handle_update(update).await,
                    None => legacy_updates_open = false,
                },
                update = inventory.update_rx.recv(), if enhanced_updates_open => match update {
                    Some(update) => self.receive(update).await,
                    None => enhanced_updates_open = false,
                },
                query = inventory.query_rx.recv(), if inventory.query_open => match query {
                    Some(query) => {
                        // Unwind safety: `cache_list` only reads.
                        let list = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            self.cache_list()
                        }));
                        match list {
                            Ok(list) => { let _ = query.reply.send(list); }
                            Err(_) => self.record_fault("cache inventory query", None),
                        }
                    }
                    None => inventory.query_open = false,
                },
            }
        }
        info!("VRP manager shutting down");
    }

    /// The earliest expiry among the data held for resync-pending caches.
    fn pending_expiry(&self) -> Option<(TokioInstant, SocketAddr)> {
        self.cache_inventory
            .as_ref()?
            .resync_pending
            .iter()
            .filter_map(|server| Some((self.server_tables.get(server)?.expires_at?, *server)))
            .min()
    }

    /// Handle one inventory message, recovering from a panic in it as
    /// [`Self::run`] describes.
    async fn receive(&mut self, update: EnhancedVrpUpdate) {
        let (server, class, what) = match &update {
            EnhancedVrpUpdate::Connected { server }
            | EnhancedVrpUpdate::Disconnected {
                server,
                flush: false,
            } => (*server, UpdateClass::Session, "connectivity change"),
            EnhancedVrpUpdate::Disconnected {
                server,
                flush: true,
            } => (*server, UpdateClass::Removal, "flush"),
            EnhancedVrpUpdate::Expired { server } => (*server, UpdateClass::Removal, "expiry"),
            EnhancedVrpUpdate::Full { server, .. } => (*server, UpdateClass::Data, "full table"),
            EnhancedVrpUpdate::Incremental { server, .. } => {
                (*server, UpdateClass::Data, "serial delta")
            }
        };
        // Unwind safety: the panicked future is never polled again. A data
        // update or a removal mutates only in `commit`, after everything
        // that can panic has run, so the per-cache sets, their charges and
        // deadlines, the inventory rows and the published tables are those
        // of before the message or, for a panic in an observer afterwards,
        // of the fully applied message. A dropped update releases its own
        // record charge.
        if catch_panic(self.handle_enhanced_update(update))
            .await
            .is_some()
        {
            return;
        }
        self.record_fault(what, Some(server));
        match class {
            UpdateClass::Session => {}
            UpdateClass::Data => self.request_resync(server),
            UpdateClass::Removal => {
                // Not caught: if the tables cannot be rebuilt without this
                // cache, nothing can make its data leave on time, and the
                // manager ends instead of holding it.
                self.remove_cache(server).await;
                self.observe_removed(server);
                // No resync request: a client that sends a flush or an
                // expiry has already dropped its epoch, so its next query
                // is a Reset Query, and the manager expires data only for
                // a cache that is already pending.
            }
        }
    }

    fn record_fault(&self, what: &'static str, server: Option<SocketAddr>) {
        error!(
            what,
            server = server.map(tracing::field::display),
            "VRP manager panicked handling a message; continuing with its state as before it"
        );
        // Unwind safety: the observer is the embedder's, and the manager's
        // state does not depend on it.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if let Some(observer) = &self.fault_observer {
                observer();
            }
        }));
    }

    /// Ask `server`'s client for a full table and hold what the cache last
    /// delivered until it arrives.
    fn request_resync(&mut self, server: SocketAddr) {
        let Some(inventory) = self.cache_inventory.as_mut() else {
            return;
        };
        inventory.resync_pending.insert(server);
        inventory
            .resync_tx
            .send_modify(|requests| *requests.entry(server).or_default() += 1);
        if let Some(observer) = &self.resync_observer {
            self.observe(|| observer(server, true));
        }
    }

    /// Drop `server`'s accepted state and data and redistribute.
    async fn remove_cache(&mut self, server: SocketAddr) {
        // Staged first: a panic there leaves the inventory row untouched.
        let staged = self.stage(VrpUpdate::ServerDown { server }, None);
        if let Some(state) = self
            .cache_inventory
            .as_mut()
            .and_then(|i| i.states.get_mut(&server))
        {
            state.accepted = None;
        }
        self.distribute(staged).await;
    }

    fn observe_removed(&self, server: SocketAddr) {
        if let Some(observer) = &self.readiness_observer {
            self.observe(|| observer(server, false));
        }
        self.notify_end_of_data(server);
    }

    fn cache_list(&self) -> CacheList {
        self.injected_fault();
        let Some(inventory) = &self.cache_inventory else {
            return CacheList {
                rows: Vec::new(),
                omitted: 0,
            };
        };
        let total = inventory.states.len();
        let rows = inventory
            .states
            .iter()
            .take(MAX_CACHE_ROWS)
            .map(|(&server, state)| {
                let accepted = state.accepted.as_ref().map(|metadata| {
                    let (vrp_v4_count, vrp_v6_count) = self
                        .server_tables
                        .get(&server)
                        .map_or((0, 0), ServerVrpTable::counts);
                    AcceptedCacheState {
                        protocol_version: metadata.version,
                        session_id: metadata.session_id,
                        serial: metadata.serial,
                        vrp_v4_count,
                        vrp_v6_count,
                        aspa_count: self.server_aspa_tables.get(&server).map_or(0, HashMap::len),
                        age_seconds: metadata.accepted_at.elapsed().as_secs(),
                    }
                });
                CacheState {
                    server,
                    connected: state.connected,
                    accepted,
                }
            })
            .collect();
        CacheList {
            rows,
            omitted: u64::try_from(total.saturating_sub(MAX_CACHE_ROWS)).unwrap_or(u64::MAX),
        }
    }

    async fn handle_enhanced_update(&mut self, update: EnhancedVrpUpdate) {
        match update {
            EnhancedVrpUpdate::Connected { server } => self.set_connected(server, true),
            EnhancedVrpUpdate::Disconnected { server, flush } => {
                self.set_connected(server, false);
                if flush {
                    self.remove_cache(server).await;
                    self.observe_removed(server);
                }
            }
            EnhancedVrpUpdate::Expired { server } => {
                self.remove_cache(server).await;
                self.observe_removed(server);
            }
            EnhancedVrpUpdate::Full {
                server,
                entries,
                aspa_records,
                charge,
                version,
                session_id,
                serial,
                accepted_at,
                expires_at,
            } => {
                // The replaced table releases its charge when it is dropped;
                // this one holds the new data's.
                self.handle_accepted_update(
                    VrpUpdate::FullTable {
                        server,
                        entries,
                        aspa_records,
                    },
                    Some(Accepted {
                        charge,
                        expires_at,
                        metadata: AcceptedMetadata {
                            version: Some(version),
                            session_id: Some(session_id),
                            serial: Some(serial),
                            accepted_at,
                        },
                    }),
                )
                .await;
                self.notify_end_of_data(server);
            }
            EnhancedVrpUpdate::Incremental {
                server,
                announced,
                withdrawn,
                aspa_announced,
                aspa_withdrawn,
                charge,
                version,
                session_id,
                serial,
                accepted_at,
                expires_at,
            } => {
                if self
                    .cache_inventory
                    .as_ref()
                    .is_some_and(|i| i.resync_pending.contains(&server))
                {
                    // An earlier update from this cache was lost, so this
                    // delta's base is not the set held here. Dropping it
                    // releases its charge; the full table that is on its
                    // way replaces the set.
                    warn!(%server, serial, "serial delta dropped: cache is awaiting resynchronization");
                    return;
                }
                self.handle_accepted_update(
                    VrpUpdate::IncrementalUpdate {
                        server,
                        announced,
                        withdrawn,
                        aspa_announced,
                        aspa_withdrawn,
                    },
                    Some(Accepted {
                        charge,
                        expires_at,
                        metadata: AcceptedMetadata {
                            version: Some(version),
                            session_id: Some(session_id),
                            serial: Some(serial),
                            accepted_at,
                        },
                    }),
                )
                .await;
                self.notify_end_of_data(server);
            }
        }
    }

    /// Apply one update in two steps: [`Self::stage`] builds everything that
    /// can fail, then [`Self::commit`] installs it with plain inserts. A
    /// panic while staging leaves every per-cache set and both published
    /// tables exactly as they were before the update.
    async fn handle_update(&mut self, update: VrpUpdate) {
        self.handle_accepted_update(update, None).await;
    }

    async fn handle_accepted_update(&mut self, update: VrpUpdate, accepted: Option<Accepted>) {
        let staged = self.stage(canonical_update(update), accepted);
        let server = staged.server;
        let ready = staged.vrps.is_some();
        self.distribute(staged).await;
        if let Some(observer) = &self.readiness_observer {
            self.observe(|| observer(server, ready));
        }
    }

    /// Commit a staged update and send the tables it changed.
    async fn distribute(&mut self, staged: Staged) {
        let (vrp_update, aspa_update, resynchronized) = self.commit(staged);
        if let Some(update) = vrp_update {
            info!(
                v4 = update.table.v4_count(),
                v6 = update.table.v6_count(),
                total = update.table.len(),
                "VRP table updated"
            );
            let _ = self.rib_tx.send(update).await;
        }
        if let (Some(update), Some(aspa_tx)) = (aspa_update, &self.aspa_rib_tx) {
            info!(records = update.table.len(), "ASPA table updated");
            let _ = aspa_tx.send(update).await;
        }
        if let (Some(server), Some(observer)) = (resynchronized, &self.resync_observer) {
            self.observe(|| observer(server, false));
        }
    }

    /// Build the cache's next contribution and the merged tables it leads
    /// to, without changing any state.
    #[expect(
        clippy::too_many_lines,
        reason = "one update's sets, tables and deltas are built together, before any is installed"
    )]
    fn stage(&self, update: VrpUpdate, accepted: Option<Accepted>) -> Staged {
        self.injected_fault();
        if accepted.is_some()
            && let Some(countdown) = &self.test_precommit_panic_on
        {
            use std::sync::atomic::Ordering;
            assert!(
                countdown.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                    != Ok(1),
                "injected VRP manager pre-commit panic"
            );
        }
        let old_vrps = |server| self.server_tables.get(server);
        let old_aspas = |server| self.server_aspa_tables.get(server);
        // Whether a cache other than `server` holds `entry`: such an entry
        // stays in the merged table whatever `server` does with it.
        let held_elsewhere = |server: SocketAddr, entry: &VrpEntry| {
            self.server_tables
                .iter()
                .any(|(other, table)| *other != server && table.entries.contains(entry))
        };
        let (server, incremental, vrps, aspas, vrp_delta, changed_customer_asns) = match update {
            VrpUpdate::FullTable {
                server,
                entries,
                aspa_records,
            } => {
                info!(
                    %server,
                    vrps = entries.len(),
                    aspa = aspa_records.len(),
                    "full table from cache"
                );
                let vrps = ServerVrpTable::from_entries(entries);
                // Later PDUs for the same customer ASN replace earlier
                // ones within a full table (8210bis replacement semantics).
                let aspas: HashMap<u32, Vec<u32>> = aspa_records
                    .into_iter()
                    .map(|r| (r.customer_asn, r.provider_asns))
                    .collect();
                // A table that replaces this cache's previous one changes
                // the merged table by exactly the entries the two differ in
                // that no other cache holds (only this cache's set changes,
                // and the merged table is the union), so those are the
                // delta. A cache's first table has no previous set to
                // compare with, and downstream rescans.
                // The ASPA set below is not narrowed the same way: the RIB
                // scans every route for an ASPA update and uses the set only
                // to skip detailed validation, so its size costs nothing.
                let vrp_delta = old_vrps(&server).map(|old| {
                    old.entries
                        .symmetric_difference(&vrps.entries)
                        .filter(|entry| !held_elsewhere(server, entry))
                        .cloned()
                        .collect()
                });
                let changed = old_aspas(&server).map(|old| {
                    old.keys()
                        .chain(aspas.keys())
                        .filter(|customer| old.get(customer) != aspas.get(customer))
                        .copied()
                        .collect()
                });
                (server, false, Some(vrps), Some(aspas), vrp_delta, changed)
            }
            VrpUpdate::IncrementalUpdate {
                server,
                announced,
                withdrawn,
                aspa_announced,
                aspa_withdrawn,
            } => {
                debug!(
                    %server,
                    vrps_announced = announced.len(),
                    vrps_withdrawn = withdrawn.len(),
                    aspa_announced = aspa_announced.len(),
                    aspa_withdrawn = aspa_withdrawn.len(),
                    "incremental update from cache"
                );
                // VRP incremental. Withdrawals apply before announcements —
                // wire order within the serial was already discarded by the
                // RTR client's flag-bit split. This assumes the cache sends
                // net deltas per serial (RFC 8210 semantics); a pathological
                // "announce X then withdraw X" in one serial would leave X
                // present. Robustness-only: correct caches never send both
                // sides for one record in one serial.
                // ponytail: the delta is applied to a copy of the cache's
                // set, the same order of work as the merged rebuild below;
                // apply in place with an undo list if deltas ever get hot.
                let mut table =
                    old_vrps(&server).map_or_else(ServerVrpTable::default, |old| ServerVrpTable {
                        entries: old.entries.clone(),
                        v4_count: old.v4_count,
                        v6_count: old.v6_count,
                        charge: None,
                        expires_at: None,
                    });
                for w in &withdrawn {
                    table.remove(w);
                }
                // Every merged-table entry that can differ from the previous
                // snapshot is in one of these two lists (only this server's
                // set is mutated, and only by exactly these entries).
                let mut delta = withdrawn.clone();
                delta.extend(announced.iter().cloned());
                for entry in announced {
                    table.insert(entry);
                }

                // ASPA incremental (8210bis semantics): a withdraw (which
                // carries an empty provider set on the wire) removes the
                // customer ASN; an announce replaces the customer's entire
                // provider set.
                let mut aspa_table = old_aspas(&server).cloned().unwrap_or_default();
                let changed_customer_asns = aspa_announced
                    .iter()
                    .chain(&aspa_withdrawn)
                    .map(|record| record.customer_asn)
                    .collect();
                for w in &aspa_withdrawn {
                    aspa_table.remove(&w.customer_asn);
                }
                for a in aspa_announced {
                    aspa_table.insert(a.customer_asn, a.provider_asns);
                }
                (
                    server,
                    true,
                    Some(table),
                    Some(aspa_table),
                    Some(delta),
                    Some(changed_customer_asns),
                )
            }
            VrpUpdate::ServerDown { server } => {
                info!(%server, "cache server down — removing entries");
                // Only this cache's set leaves, so the delta is what it
                // alone held: with two caches serving the same data, one
                // of them expiring changes almost nothing. A cache that
                // held nothing changes nothing.
                let vrp_delta = Some(
                    old_vrps(&server)
                        .map(|old| {
                            old.entries
                                .iter()
                                .filter(|entry| !held_elsewhere(server, entry))
                                .cloned()
                                .collect()
                        })
                        .unwrap_or_default(),
                );
                let changed = Some(
                    old_aspas(&server)
                        .map(|old| old.keys().copied().collect())
                        .unwrap_or_default(),
                );
                (server, false, None, None, vrp_delta, changed)
            }
        };
        let vrp_update = self.stage_vrp_table(server, vrps.as_ref(), vrp_delta);
        let aspa_update = self.stage_aspa_table(server, aspas.as_ref(), changed_customer_asns);
        Staged {
            server,
            incremental,
            vrps,
            aspas,
            vrp_update,
            aspa_update,
            accepted,
        }
    }

    /// Install a staged update. Only map inserts and removals: nothing here
    /// can panic part-way, so the per-cache sets and the published tables
    /// always describe one accepted state.
    ///
    /// Returns the tables to distribute and, when a full table just ended
    /// the cache's wait for resynchronization, the cache.
    fn commit(
        &mut self,
        staged: Staged,
    ) -> (
        Option<RpkiTableUpdate>,
        Option<AspaTableUpdate>,
        Option<SocketAddr>,
    ) {
        let Staged {
            server,
            incremental,
            vrps,
            aspas,
            vrp_update,
            aspa_update,
            accepted,
        } = staged;
        let mut resynchronized = None;
        match vrps {
            Some(mut table) => {
                if incremental && let Some(old) = self.server_tables.get_mut(&server) {
                    // A delta extends the data it applies to: the charge
                    // and the deadline stay with it.
                    table.charge = old.charge.take();
                    table.expires_at = old.expires_at;
                }
                let metadata = match accepted {
                    Some(Accepted {
                        mut charge,
                        expires_at,
                        metadata,
                    }) => {
                        // The delta's withdrawals are applied; only its
                        // announcements stay charged with the table.
                        charge.release_withdrawn();
                        match &mut table.charge {
                            Some(held) => held.absorb(charge),
                            held => *held = Some(charge),
                        }
                        table.expires_at = Some(expires_at);
                        metadata
                    }
                    None => AcceptedMetadata {
                        version: None,
                        session_id: None,
                        serial: None,
                        accepted_at: Instant::now(),
                    },
                };
                self.server_tables.insert(server, table);
                if let Some(inventory) = self.cache_inventory.as_mut() {
                    if let Some(state) = inventory.states.get_mut(&server) {
                        state.accepted = Some(metadata);
                    }
                    if !incremental && inventory.resync_pending.remove(&server) {
                        resynchronized = Some(server);
                    }
                }
            }
            None => {
                self.server_tables.remove(&server);
            }
        }
        match aspas {
            Some(table) => {
                self.server_aspa_tables.insert(server, table);
            }
            None => {
                self.server_aspa_tables.remove(&server);
            }
        }
        if let Some(update) = &vrp_update {
            self.current_table = Some(Arc::clone(&update.table));
        }
        if let Some(update) = &aspa_update {
            self.current_aspa_table = Some(Arc::clone(&update.table));
        }
        (vrp_update, aspa_update, resynchronized)
    }

    // Full rebuild (clone + sort of every entry) on every update, even a
    // one-entry incremental. Fine at real-world shapes: RTR serial-notify
    // deltas are tiny next to the ~600k-VRP global table, and rebuilds are
    // O(total log total) on a single manager task off the hot path.
    // ponytail: revisit with per-family incremental table maintenance only if
    // caches ever stream high-rate deltas.
    /// The merged VRP table once `server`'s set is `next` (`None`: removed),
    /// or `None` when there is nothing new to distribute.
    fn stage_vrp_table(
        &self,
        server: SocketAddr,
        next: Option<&ServerVrpTable>,
        delta: Option<Vec<VrpEntry>>,
    ) -> Option<RpkiTableUpdate> {
        let mut tables = self
            .server_tables
            .iter()
            .filter(|(other, _)| **other != server)
            .map(|(_, table)| table)
            .chain(next)
            .peekable();
        // A pre-accept disconnect must not initialize an authoritative table.
        if self.current_table.is_none() && tables.peek().is_none() {
            return None;
        }
        let merged: Vec<VrpEntry> = tables.flat_map(|v| v.iter().cloned()).collect();
        let table = Arc::new(VrpTable::new(merged));

        // Dropping a suppressed update's delta is sound: suppression proves
        // the merged table did not change, so the last *distributed* snapshot
        // still equals the table any later delta is computed against.
        if self.current_table.as_ref() == Some(&table) {
            debug!("VRP table unchanged — skipping distribution");
            return None;
        }
        Some(RpkiTableUpdate { table, delta })
    }

    /// The merged ASPA table once `server`'s records are `next`, as for
    /// [`Self::stage_vrp_table`].
    fn stage_aspa_table(
        &self,
        server: SocketAddr,
        next: Option<&HashMap<u32, Vec<u32>>>,
        changed_customer_asns: Option<FxHashSet<u32>>,
    ) -> Option<AspaTableUpdate> {
        self.aspa_rib_tx.as_ref()?;
        let mut tables = self
            .server_aspa_tables
            .iter()
            .filter(|(other, _)| **other != server)
            .map(|(_, table)| table)
            .chain(next)
            .peekable();
        if self.current_aspa_table.is_none() && tables.peek().is_none() {
            return None;
        }
        let merged: Vec<AspaRecord> = tables
            .flat_map(|per_customer| {
                per_customer.iter().map(|(customer, providers)| AspaRecord {
                    customer_asn: *customer,
                    provider_asns: providers.clone(),
                })
            })
            .collect();
        let table = Arc::new(AspaTable::new(merged));
        if self.current_aspa_table.as_ref() == Some(&table) {
            debug!("ASPA table unchanged — skipping distribution");
            return None;
        }
        Some(AspaTableUpdate {
            table,
            changed_customer_asns,
        })
    }

    /// Number of connected cache servers with data.
    #[must_use]
    pub fn connected_servers(&self) -> usize {
        self.server_tables.len()
    }
}

/// The update with every VRP keyed by its canonical prefix (host bits
/// cleared). Validation already masks prefixes, so the per-cache set and the
/// distributed delta must use the same identity.
fn canonical_update(update: VrpUpdate) -> VrpUpdate {
    let canonical = |entries: Vec<VrpEntry>| entries.into_iter().map(VrpEntry::canonical).collect();
    match update {
        VrpUpdate::FullTable {
            server,
            entries,
            aspa_records,
        } => VrpUpdate::FullTable {
            server,
            entries: canonical(entries),
            aspa_records,
        },
        VrpUpdate::IncrementalUpdate {
            server,
            announced,
            withdrawn,
            aspa_announced,
            aspa_withdrawn,
        } => VrpUpdate::IncrementalUpdate {
            server,
            announced: canonical(announced),
            withdrawn: canonical(withdrawn),
            aspa_announced,
            aspa_withdrawn,
        },
        other @ VrpUpdate::ServerDown { .. } => other,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;

    /// An expiry no test reaches unless it means to.
    fn far_expiry() -> TokioInstant {
        TokioInstant::now() + Duration::from_secs(7200)
    }

    fn entry(addr: Ipv4Addr, prefix_len: u8, max_len: u8, asn: u32) -> VrpEntry {
        VrpEntry {
            prefix: IpAddr::V4(addr),
            prefix_len,
            max_len,
            origin_asn: asn,
        }
    }

    fn entry_v6(addr: Ipv6Addr, prefix_len: u8, max_len: u8, asn: u32) -> VrpEntry {
        VrpEntry {
            prefix: IpAddr::V6(addr),
            prefix_len,
            max_len,
            origin_asn: asn,
        }
    }

    /// A zero charge on one unlimited budget shared by these tests, so a
    /// table's charges can be merged.
    fn test_charge() -> Reservation {
        static BUDGET: std::sync::OnceLock<Arc<crate::rtr_client::RecordBudget>> =
            std::sync::OnceLock::new();
        Reservation::new(Arc::clone(
            BUDGET.get_or_init(|| crate::rtr_client::RecordBudget::new(usize::MAX)),
        ))
    }

    fn server1() -> SocketAddr {
        "10.0.0.1:3323".parse().unwrap()
    }

    fn server2() -> SocketAddr {
        "10.0.0.2:3323".parse().unwrap()
    }

    #[test]
    fn cache_query_error_has_stable_error_contract() {
        fn assert_error(error: &dyn std::error::Error) -> String {
            error.to_string()
        }

        assert_eq!(
            assert_error(&CacheQueryError),
            "RPKI cache inventory actor is unavailable"
        );
    }

    #[tokio::test]
    async fn readiness_follows_completed_retained_contribution_lifecycle() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let (aspa_tx, mut aspa_rx) = mpsc::channel(16);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let sink = Arc::clone(&observed);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx)
            .with_aspa_tx(aspa_tx)
            .with_readiness_observer(move |server, ready| {
                sink.lock().unwrap().push((server, ready));
            });

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![],
            aspa_records: vec![],
        })
        .await;
        assert_eq!(*observed.lock().unwrap(), [(server1(), true)]);

        mgr.handle_update(VrpUpdate::IncrementalUpdate {
            server: server1(),
            announced: vec![entry(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001)],
            withdrawn: vec![],
            aspa_announced: vec![],
            aspa_withdrawn: vec![],
        })
        .await;
        let _ = rib_rx.try_recv();
        let _ = aspa_rx.try_recv();
        assert_eq!(observed.lock().unwrap().last(), Some(&(server1(), true)));

        mgr.handle_update(VrpUpdate::ServerDown { server: server1() })
            .await;
        assert!(!mgr.server_tables.contains_key(&server1()));
        assert!(!mgr.server_aspa_tables.contains_key(&server1()));
        assert_eq!(observed.lock().unwrap().last(), Some(&(server1(), false)));
    }

    #[tokio::test]
    async fn full_table_from_single_server() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx);

        let entries = vec![
            entry(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001),
            entry(Ipv4Addr::new(192, 168, 0, 0), 16, 24, 65002),
        ];

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries,
            aspa_records: vec![],
        })
        .await;

        let update = rib_rx.try_recv().unwrap();
        assert_eq!(update.table.len(), 2);
        assert!(
            update.delta.is_none(),
            "full snapshot must not carry a delta"
        );
    }

    #[tokio::test]
    async fn merge_from_two_servers_deduplicates() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx);

        let shared = entry(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![shared.clone()],
            aspa_records: vec![],
        })
        .await;
        let _ = rib_rx.try_recv(); // consume first update

        mgr.handle_update(VrpUpdate::FullTable {
            server: server2(),
            entries: vec![
                shared, // duplicate
                entry(Ipv4Addr::new(10, 1, 0, 0), 24, 24, 65002),
            ],
            aspa_records: vec![],
        })
        .await;

        let update = rib_rx.try_recv().unwrap();
        assert_eq!(update.table.len(), 2);
    }

    /// RTR v1 accepts Prefix PDUs with host bits set, and validation masks
    /// them. A cache that announces a VRP with host bits and then withdraws
    /// the canonical form must leave nothing behind, and the same VRP sent
    /// both ways counts once.
    #[tokio::test]
    async fn host_bit_prefixes_share_the_canonical_identity() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx);
        let host_bits = entry(Ipv4Addr::new(10, 0, 0, 1), 8, 8, 65001);
        let canonical = entry(Ipv4Addr::new(10, 0, 0, 0), 8, 8, 65001);
        let other = entry(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 65002);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![host_bits.clone(), canonical.clone(), other.clone()],
            aspa_records: vec![],
        })
        .await;
        let update = rib_rx.try_recv().unwrap();
        assert_eq!(update.table.len(), 2, "one VRP sent two ways counted twice");

        mgr.handle_update(VrpUpdate::IncrementalUpdate {
            server: server1(),
            announced: vec![],
            withdrawn: vec![canonical],
            aspa_announced: vec![],
            aspa_withdrawn: vec![],
        })
        .await;
        let update = rib_rx.try_recv().unwrap();
        assert_eq!(
            update.table.len(),
            1,
            "the withdrawn VRP still authorizes its prefix through the host-bit copy"
        );
        assert_eq!(mgr.server_tables[&server1()].counts(), (1, 0));
    }

    #[tokio::test]
    async fn incremental_update_adds_and_removes() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx);

        let e1 = entry(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001);
        let e2 = entry(Ipv4Addr::new(10, 1, 0, 0), 24, 24, 65002);
        let e3 = entry(Ipv4Addr::new(10, 2, 0, 0), 24, 24, 65003);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![e1.clone(), e2.clone()],
            aspa_records: vec![],
        })
        .await;
        let _ = rib_rx.try_recv();

        mgr.handle_update(VrpUpdate::IncrementalUpdate {
            server: server1(),
            announced: vec![e3.clone()],
            withdrawn: vec![e1.clone()],
            aspa_announced: vec![],
            aspa_withdrawn: vec![],
        })
        .await;

        let update = rib_rx.try_recv().unwrap();
        assert_eq!(update.table.len(), 2); // e2 + e3
        // Incremental sync carries exactly the withdrawn + announced entries.
        let delta = update.delta.expect("incremental sync must carry a delta");
        assert_eq!(delta.len(), 2);
        assert!(delta.contains(&e1) && delta.contains(&e3));
    }

    #[tokio::test]
    async fn server_down_removes_entries() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![entry(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001)],
            aspa_records: vec![],
        })
        .await;
        let _ = rib_rx.try_recv();

        mgr.handle_update(VrpUpdate::FullTable {
            server: server2(),
            entries: vec![entry(Ipv4Addr::new(10, 1, 0, 0), 24, 24, 65002)],
            aspa_records: vec![],
        })
        .await;
        let _ = rib_rx.try_recv();

        mgr.handle_update(VrpUpdate::ServerDown { server: server1() })
            .await;

        let update = rib_rx.try_recv().unwrap();
        assert_eq!(update.table.len(), 1);
        assert_eq!(
            update.delta,
            Some(vec![entry(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001)]),
            "server loss changes exactly what that server held"
        );
    }

    #[tokio::test]
    async fn empty_table_after_all_servers_down() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![entry(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001)],
            aspa_records: vec![],
        })
        .await;
        let _ = rib_rx.try_recv();

        mgr.handle_update(VrpUpdate::ServerDown { server: server1() })
            .await;

        let update = rib_rx.try_recv().unwrap();
        assert!(update.table.is_empty());
    }

    #[tokio::test]
    async fn unchanged_table_does_not_redistribute() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx);

        let entries = vec![entry(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001)];

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: entries.clone(),
            aspa_records: vec![],
        })
        .await;
        let _ = rib_rx.try_recv().unwrap();

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries,
            aspa_records: vec![],
        })
        .await;

        assert!(rib_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn first_empty_validation_tables_published_once() {
        for first_update in [
            VrpUpdate::FullTable {
                server: server1(),
                entries: vec![],
                aspa_records: vec![],
            },
            VrpUpdate::IncrementalUpdate {
                server: server1(),
                announced: vec![],
                withdrawn: vec![],
                aspa_announced: vec![],
                aspa_withdrawn: vec![],
            },
        ] {
            let (_vrp_tx, vrp_rx) = mpsc::channel(16);
            let (rib_tx, mut rib_rx) = mpsc::channel(16);
            let (aspa_tx, mut aspa_rx) = mpsc::channel(16);
            let mut mgr = VrpManager::new(vrp_rx, rib_tx).with_aspa_tx(aspa_tx);

            // A disconnected cache that never supplied data is still unavailable.
            mgr.handle_update(VrpUpdate::ServerDown { server: server1() })
                .await;
            assert_eq!(
                aspa_rx.try_recv().unwrap_err(),
                mpsc::error::TryRecvError::Empty
            );

            assert_eq!(
                rib_rx.try_recv().unwrap_err(),
                mpsc::error::TryRecvError::Empty
            );

            mgr.handle_update(first_update).await;
            let update = rib_rx.try_recv().expect("first accepted empty VRP table");
            assert!(update.table.is_empty());
            let update = aspa_rx.try_recv().expect("first accepted empty ASPA table");
            assert!(update.table.is_empty());

            // Identical full/incremental replays and removal/reconnection of an
            // empty contribution do not republish the initialized merged table.
            for update in [
                VrpUpdate::FullTable {
                    server: server1(),
                    entries: vec![],
                    aspa_records: vec![],
                },
                VrpUpdate::IncrementalUpdate {
                    server: server1(),
                    announced: vec![],
                    withdrawn: vec![],
                    aspa_announced: vec![],
                    aspa_withdrawn: vec![],
                },
                VrpUpdate::ServerDown { server: server1() },
                VrpUpdate::FullTable {
                    server: server1(),
                    entries: vec![],
                    aspa_records: vec![],
                },
            ] {
                mgr.handle_update(update).await;
                assert_eq!(
                    rib_rx.try_recv().unwrap_err(),
                    mpsc::error::TryRecvError::Empty
                );
                assert_eq!(
                    aspa_rx.try_recv().unwrap_err(),
                    mpsc::error::TryRecvError::Empty
                );
            }
        }
    }

    #[tokio::test]
    async fn aspa_full_table_distributed() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (aspa_tx, mut aspa_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx).with_aspa_tx(aspa_tx);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![],
            aspa_records: vec![AspaRecord {
                customer_asn: 65001,
                provider_asns: vec![65002, 65003],
            }],
        })
        .await;

        let update = aspa_rx.try_recv().unwrap();
        assert_eq!(update.table.len(), 1);
    }

    #[tokio::test]
    async fn aspa_update_change_scope_follows_update_kind() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (aspa_tx, mut aspa_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx).with_aspa_tx(aspa_tx);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![],
            aspa_records: vec![
                AspaRecord {
                    customer_asn: 65001,
                    provider_asns: vec![65101],
                },
                AspaRecord {
                    customer_asn: 65002,
                    provider_asns: vec![65102],
                },
            ],
        })
        .await;
        assert!(aspa_rx.try_recv().unwrap().changed_customer_asns.is_none());

        mgr.handle_update(VrpUpdate::IncrementalUpdate {
            server: server1(),
            announced: vec![],
            withdrawn: vec![],
            aspa_announced: vec![AspaRecord {
                customer_asn: 65001,
                provider_asns: vec![65111],
            }],
            aspa_withdrawn: vec![AspaRecord {
                customer_asn: 65002,
                provider_asns: vec![],
            }],
        })
        .await;
        assert_eq!(
            aspa_rx.try_recv().unwrap().changed_customer_asns.unwrap(),
            FxHashSet::from_iter([65001, 65002])
        );

        mgr.handle_update(VrpUpdate::ServerDown { server: server1() })
            .await;
        assert_eq!(
            aspa_rx.try_recv().unwrap().changed_customer_asns.unwrap(),
            FxHashSet::from_iter([65001]),
            "server loss changes exactly the customers that server held"
        );
    }

    #[tokio::test]
    async fn aspa_server_down_clears() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (aspa_tx, mut aspa_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx).with_aspa_tx(aspa_tx);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![],
            aspa_records: vec![AspaRecord {
                customer_asn: 65001,
                provider_asns: vec![65002],
            }],
        })
        .await;
        let _ = aspa_rx.try_recv();

        mgr.handle_update(VrpUpdate::ServerDown { server: server1() })
            .await;

        let update = aspa_rx.try_recv().unwrap();
        assert!(update.table.is_empty());
    }

    #[tokio::test]
    async fn aspa_reannounce_replaces_provider_set() {
        use crate::aspa::ProviderAuth;

        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (aspa_tx, mut aspa_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx).with_aspa_tx(aspa_tx);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![],
            aspa_records: vec![AspaRecord {
                customer_asn: 65001,
                provider_asns: vec![65002, 65003],
            }],
        })
        .await;
        let _ = aspa_rx.try_recv().unwrap();

        // Re-announce with a different provider set: the new set REPLACES
        // the old one (8210bis), it does not merge.
        mgr.handle_update(VrpUpdate::IncrementalUpdate {
            server: server1(),
            announced: vec![],
            withdrawn: vec![],
            aspa_announced: vec![AspaRecord {
                customer_asn: 65001,
                provider_asns: vec![65004],
            }],
            aspa_withdrawn: vec![],
        })
        .await;
        let update = aspa_rx.try_recv().unwrap();
        assert_eq!(
            update.table.authorized(65001, 65004),
            ProviderAuth::ProviderPlus
        );
        assert_eq!(
            update.table.authorized(65001, 65002),
            ProviderAuth::NotProviderPlus
        );
        assert_eq!(
            update.table.authorized(65001, 65003),
            ProviderAuth::NotProviderPlus
        );
    }

    #[tokio::test]
    async fn aspa_empty_provider_withdraw_removes_customer() {
        use crate::aspa::ProviderAuth;

        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (aspa_tx, mut aspa_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx).with_aspa_tx(aspa_tx);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![],
            aspa_records: vec![AspaRecord {
                customer_asn: 65001,
                provider_asns: vec![65002],
            }],
        })
        .await;
        let _ = aspa_rx.try_recv().unwrap();

        // 8210bis withdraw carries an empty provider set and withdraws the
        // whole customer ASN.
        mgr.handle_update(VrpUpdate::IncrementalUpdate {
            server: server1(),
            announced: vec![],
            withdrawn: vec![],
            aspa_announced: vec![],
            aspa_withdrawn: vec![AspaRecord {
                customer_asn: 65001,
                provider_asns: vec![],
            }],
        })
        .await;
        let update = aspa_rx.try_recv().unwrap();
        assert!(update.table.is_empty());
        assert_eq!(
            update.table.authorized(65001, 65002),
            ProviderAuth::NoAttestation
        );
    }

    #[tokio::test]
    async fn aspa_full_table_last_record_per_customer_wins() {
        use crate::aspa::ProviderAuth;

        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (aspa_tx, mut aspa_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx).with_aspa_tx(aspa_tx);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![],
            aspa_records: vec![
                AspaRecord {
                    customer_asn: 65001,
                    provider_asns: vec![65002],
                },
                AspaRecord {
                    customer_asn: 65001,
                    provider_asns: vec![65003],
                },
            ],
        })
        .await;
        let update = aspa_rx.try_recv().unwrap();
        assert_eq!(
            update.table.authorized(65001, 65003),
            ProviderAuth::ProviderPlus
        );
        assert_eq!(
            update.table.authorized(65001, 65002),
            ProviderAuth::NotProviderPlus
        );
    }

    #[tokio::test]
    async fn cache_inventory_tracks_atomic_epochs_retention_and_flush() {
        let (_legacy_tx, legacy_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (attachment, _updates, _queries) = CacheInventoryAttachment::new([server1()]);
        let mut mgr = VrpManager::new(legacy_rx, rib_tx).with_cache_inventory(attachment);

        mgr.handle_enhanced_update(EnhancedVrpUpdate::Connected { server: server1() })
            .await;
        mgr.handle_enhanced_update(EnhancedVrpUpdate::Full {
            charge: test_charge(),
            expires_at: far_expiry(),
            server: server1(),
            entries: vec![
                entry(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 64_496),
                entry_v6("2001:db8::".parse().unwrap(), 32, 48, 64_496),
            ],
            aspa_records: vec![AspaRecord {
                customer_asn: 64_496,
                provider_asns: vec![64_497],
            }],
            version: 2,
            session_id: 7,
            serial: 11,
            accepted_at: Instant::now()
                .checked_sub(std::time::Duration::from_secs(3))
                .unwrap_or_else(Instant::now),
        })
        .await;
        let row = mgr.cache_list().rows.pop().unwrap();
        assert!(row.connected);
        let accepted = row.accepted.unwrap();
        assert_eq!(
            (
                accepted.protocol_version,
                accepted.session_id,
                accepted.serial
            ),
            (Some(2), Some(7), Some(11))
        );
        assert_eq!(
            (
                accepted.vrp_v4_count,
                accepted.vrp_v6_count,
                accepted.aspa_count
            ),
            (1, 1, 1)
        );
        assert!(accepted.age_seconds >= 3);

        mgr.handle_enhanced_update(EnhancedVrpUpdate::Disconnected {
            server: server1(),
            flush: false,
        })
        .await;
        let retained = mgr.cache_list().rows.pop().unwrap();
        assert!(!retained.connected);
        assert!(retained.accepted.is_some());

        mgr.handle_enhanced_update(EnhancedVrpUpdate::Connected { server: server1() })
            .await;
        mgr.handle_enhanced_update(EnhancedVrpUpdate::Incremental {
            charge: test_charge(),
            server: server1(),
            announced: vec![
                // Duplicate announcement must not inflate the v6 count.
                entry_v6("2001:db8::".parse().unwrap(), 32, 48, 64_496),
                entry(Ipv4Addr::new(198, 51, 100, 0), 24, 24, 64_497),
            ],
            withdrawn: vec![
                entry(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 64_496),
                // Absent withdrawal must not deflate the v4 count.
                entry(Ipv4Addr::new(203, 0, 113, 0), 24, 24, 64_498),
            ],
            aspa_announced: vec![],
            aspa_withdrawn: vec![],
            version: 2,
            session_id: 7,
            serial: 12,
            accepted_at: Instant::now(),
            expires_at: far_expiry(),
        })
        .await;
        assert_eq!(
            mgr.cache_list().rows[0].accepted.as_ref().unwrap().serial,
            Some(12)
        );
        let accepted = mgr.cache_list().rows[0].accepted.clone().unwrap();
        assert_eq!((accepted.vrp_v4_count, accepted.vrp_v6_count), (1, 1));

        mgr.handle_enhanced_update(EnhancedVrpUpdate::Disconnected {
            server: server1(),
            flush: true,
        })
        .await;
        let flushed = mgr.cache_list().rows.pop().unwrap();
        assert!(!flushed.connected);
        assert!(flushed.accepted.is_none());
        assert_eq!(mgr.connected_servers(), 0);
    }

    /// Connectivity and readiness are separate per-cache signals: an
    /// ordinary disconnect drops connectivity while the retained
    /// contribution stays ready, and neither expiry nor a flush reconnects.
    /// Driving connectivity from the readiness transitions makes the
    /// disconnected-but-ready assertion red.
    #[tokio::test]
    async fn connectivity_observer_is_independent_of_readiness() {
        let (_legacy_tx, legacy_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (attachment, _updates, _queries) = CacheInventoryAttachment::new([server1()]);
        let gauges = Arc::new(Mutex::new(HashMap::<(&str, SocketAddr), bool>::new()));
        let (ready_sink, connected_sink) = (Arc::clone(&gauges), Arc::clone(&gauges));
        let mut mgr = VrpManager::new(legacy_rx, rib_tx)
            .with_cache_inventory(attachment)
            .with_readiness_observer(move |server, ready| {
                ready_sink.lock().unwrap().insert(("ready", server), ready);
            })
            .with_connectivity_observer(move |server, connected| {
                connected_sink
                    .lock()
                    .unwrap()
                    .insert(("connected", server), connected);
            });
        let full = || EnhancedVrpUpdate::Full {
            charge: test_charge(),
            server: server1(),
            entries: vec![entry(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 64_496)],
            aspa_records: vec![],
            version: 2,
            session_id: 7,
            serial: 11,
            accepted_at: Instant::now(),
            expires_at: far_expiry(),
        };
        let state = |gauges: &Mutex<HashMap<(&str, SocketAddr), bool>>| {
            let gauges = gauges.lock().unwrap();
            (
                gauges.get(&("connected", server1())).copied(),
                gauges.get(&("ready", server1())).copied(),
            )
        };

        mgr.handle_enhanced_update(EnhancedVrpUpdate::Connected { server: server1() })
            .await;
        assert_eq!(state(&gauges), (Some(true), None));
        mgr.handle_enhanced_update(full()).await;
        assert_eq!(state(&gauges), (Some(true), Some(true)));

        mgr.handle_enhanced_update(EnhancedVrpUpdate::Disconnected {
            server: server1(),
            flush: false,
        })
        .await;
        assert_eq!(state(&gauges), (Some(false), Some(true)));
        mgr.handle_enhanced_update(EnhancedVrpUpdate::Expired { server: server1() })
            .await;
        assert_eq!(state(&gauges), (Some(false), Some(false)));

        mgr.handle_enhanced_update(EnhancedVrpUpdate::Connected { server: server1() })
            .await;
        mgr.handle_enhanced_update(full()).await;
        assert_eq!(state(&gauges), (Some(true), Some(true)));
        mgr.handle_enhanced_update(EnhancedVrpUpdate::Disconnected {
            server: server1(),
            flush: true,
        })
        .await;
        assert_eq!(state(&gauges), (Some(false), Some(false)));

        // Only configured caches have a connectivity series.
        mgr.handle_enhanced_update(EnhancedVrpUpdate::Connected { server: server2() })
            .await;
        assert!(
            !gauges
                .lock()
                .unwrap()
                .contains_key(&("connected", server2()))
        );
    }

    /// The End-of-Data observer carries the exact instant `ListCaches` ages
    /// from, survives an ordinary disconnect, and is cleared by both a flush
    /// and an expiry. Dropping the notify on either clearing path, or
    /// reporting a fresh `Instant::now()` instead of the accepted instant,
    /// turns this red.
    /// A cache's record charge lives with its data in the manager: a full
    /// table releases the charge of the table it replaces, a delta adds to
    /// it, and a flush releases it.
    #[tokio::test]
    async fn table_charge_is_released_when_the_data_is_replaced_or_removed() {
        let budget = crate::rtr_client::RecordBudget::new(10);
        let (_legacy_tx, legacy_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (attachment, _updates, _queries) = CacheInventoryAttachment::new([server1()]);
        let mut mgr = VrpManager::new(legacy_rx, rib_tx).with_cache_inventory(attachment);
        let full = |records| EnhancedVrpUpdate::Full {
            charge: Reservation::charged(&budget, records, 0),
            server: server1(),
            entries: vec![entry(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 64_496)],
            aspa_records: vec![],
            version: 2,
            session_id: 7,
            serial: 11,
            accepted_at: Instant::now(),
            expires_at: far_expiry(),
        };

        mgr.handle_enhanced_update(full(3)).await;
        assert_eq!(budget.used(), 3);
        let replacement = full(2);
        assert_eq!(
            budget.used(),
            5,
            "a queued table is charged beside the held one"
        );
        mgr.handle_enhanced_update(replacement).await;
        assert_eq!(budget.used(), 2, "the replaced table released its charge");

        // A delta with one announcement and two withdrawals: the withdrawals
        // are charged while it waits, and released once it is applied.
        let delta = EnhancedVrpUpdate::Incremental {
            charge: Reservation::charged(&budget, 1, 2),
            server: server1(),
            announced: vec![entry(Ipv4Addr::new(192, 0, 2, 128), 25, 25, 64_496)],
            withdrawn: vec![
                entry(Ipv4Addr::new(198, 51, 100, 0), 24, 24, 64_496),
                entry(Ipv4Addr::new(203, 0, 113, 0), 24, 24, 64_496),
            ],
            aspa_announced: vec![],
            aspa_withdrawn: vec![],
            version: 2,
            session_id: 7,
            serial: 12,
            accepted_at: Instant::now(),
            expires_at: far_expiry(),
        };
        assert_eq!(budget.used(), 5);
        mgr.handle_enhanced_update(delta).await;
        assert_eq!(budget.used(), 3, "applied withdrawals stayed charged");

        mgr.handle_enhanced_update(EnhancedVrpUpdate::Disconnected {
            server: server1(),
            flush: true,
        })
        .await;
        assert_eq!(budget.used(), 0, "a flush released the cache's charge");
    }

    #[tokio::test]
    async fn end_of_data_observer_tracks_accepted_instant_until_flush_or_expiry() {
        let (_legacy_tx, legacy_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (attachment, _updates, _queries) = CacheInventoryAttachment::new([server1()]);
        let events = Arc::new(Mutex::new(Vec::<(SocketAddr, Option<Instant>)>::new()));
        let sink = Arc::clone(&events);
        let mut mgr = VrpManager::new(legacy_rx, rib_tx)
            .with_cache_inventory(attachment)
            .with_end_of_data_observer(move |server, accepted_at| {
                sink.lock().unwrap().push((server, accepted_at));
            });
        let earlier = |secs| {
            Instant::now()
                .checked_sub(Duration::from_secs(secs))
                .unwrap()
        };
        let full = |server, accepted_at| EnhancedVrpUpdate::Full {
            charge: test_charge(),
            server,
            entries: vec![entry(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 64_496)],
            aspa_records: vec![],
            version: 2,
            session_id: 7,
            serial: 11,
            accepted_at,
            expires_at: far_expiry(),
        };
        let last = || *events.lock().unwrap().last().unwrap();

        let first = earlier(30);
        mgr.handle_enhanced_update(full(server1(), first)).await;
        assert_eq!(last(), (server1(), Some(first)));
        let listed = mgr.cache_list().rows[0].accepted.clone().unwrap();
        assert!(
            listed.age_seconds >= 30,
            "ListCaches ages from the same instant"
        );

        // An ordinary disconnect retains the contribution: no event.
        let count = events.lock().unwrap().len();
        mgr.handle_enhanced_update(EnhancedVrpUpdate::Disconnected {
            server: server1(),
            flush: false,
        })
        .await;
        assert_eq!(events.lock().unwrap().len(), count);

        let second = earlier(10);
        mgr.handle_enhanced_update(EnhancedVrpUpdate::Incremental {
            charge: test_charge(),
            server: server1(),
            announced: vec![],
            withdrawn: vec![],
            aspa_announced: vec![],
            aspa_withdrawn: vec![],
            version: 2,
            session_id: 7,
            serial: 12,
            accepted_at: second,
            expires_at: far_expiry(),
        })
        .await;
        assert_eq!(last(), (server1(), Some(second)));

        mgr.handle_enhanced_update(EnhancedVrpUpdate::Expired { server: server1() })
            .await;
        assert_eq!(last(), (server1(), None), "expiry clears the instant");

        let third = earlier(5);
        mgr.handle_enhanced_update(full(server1(), third)).await;
        assert_eq!(last(), (server1(), Some(third)));
        mgr.handle_enhanced_update(EnhancedVrpUpdate::Disconnected {
            server: server1(),
            flush: true,
        })
        .await;
        assert_eq!(last(), (server1(), None), "a flush clears the instant");

        // Unconfigured caches never reach the observer.
        let count = events.lock().unwrap().len();
        mgr.handle_enhanced_update(full(server2(), earlier(1)))
            .await;
        assert_eq!(events.lock().unwrap().len(), count);
    }

    #[tokio::test]
    async fn accepted_empty_legacy_metadata_expiry_and_cap_are_exact() {
        let (_legacy_tx, legacy_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let servers: Vec<SocketAddr> = (0..257)
            .map(|index| format!("[2001:db8::{:x}]:3323", index + 1).parse().unwrap())
            .collect();
        let first = servers[0];
        let (attachment, _updates, _queries) = CacheInventoryAttachment::new(servers);
        let mut mgr = VrpManager::new(legacy_rx, rib_tx).with_cache_inventory(attachment);
        mgr.handle_update(VrpUpdate::FullTable {
            server: first,
            entries: vec![],
            aspa_records: vec![],
        })
        .await;
        let list = mgr.cache_list();
        assert_eq!(list.rows.len(), 256);
        assert_eq!(list.omitted, 1);
        let accepted = list
            .rows
            .iter()
            .find(|row| row.server == first)
            .unwrap()
            .accepted
            .as_ref()
            .unwrap();
        assert_eq!(
            (
                accepted.protocol_version,
                accepted.session_id,
                accepted.serial
            ),
            (None, None, None)
        );
        assert_eq!(
            (
                accepted.vrp_v4_count,
                accepted.vrp_v6_count,
                accepted.aspa_count
            ),
            (0, 0, 0)
        );
        mgr.handle_enhanced_update(EnhancedVrpUpdate::Expired { server: first })
            .await;
        assert!(
            mgr.cache_list()
                .rows
                .iter()
                .find(|row| row.server == first)
                .unwrap()
                .accepted
                .is_none()
        );
    }

    #[tokio::test]
    async fn query_senders_do_not_keep_manager_alive_after_update_lanes_close() {
        let (legacy_tx, legacy_rx) = mpsc::channel(1);
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let (attachment, updates, queries) = CacheInventoryAttachment::new([server1()]);
        let task = tokio::spawn(
            VrpManager::new(legacy_rx, rib_tx)
                .with_cache_inventory(attachment)
                .run(),
        );
        drop(legacy_tx);
        drop(updates);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(queries.list().await.is_err());
    }

    #[tokio::test]
    async fn closed_query_lane_does_not_stop_or_spin_the_update_actor() {
        let (legacy_tx, legacy_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(1);
        let (attachment, updates, queries) = CacheInventoryAttachment::new([server1()]);
        let task = tokio::spawn(
            VrpManager::new(legacy_rx, rib_tx)
                .with_cache_inventory(attachment)
                .run(),
        );
        drop(queries);
        legacy_tx
            .send(VrpUpdate::FullTable {
                server: server1(),
                entries: vec![entry(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 64_496)],
                aspa_records: vec![],
            })
            .await
            .unwrap();
        let update = tokio::time::timeout(std::time::Duration::from_secs(1), rib_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(update.table.len(), 1);
        drop(legacy_tx);
        drop(updates);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn either_update_lane_can_close_while_the_other_updates_and_answers_queries() {
        let (legacy_tx, legacy_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(2);
        let (attachment, updates, queries) = CacheInventoryAttachment::new([server1()]);
        let task = tokio::spawn(
            VrpManager::new(legacy_rx, rib_tx)
                .with_cache_inventory(attachment)
                .run(),
        );
        drop(legacy_tx);
        updates
            .0
            .send(EnhancedVrpUpdate::Full {
                charge: test_charge(),
                server: server1(),
                entries: vec![entry(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 64_496)],
                aspa_records: vec![],
                version: 2,
                session_id: 7,
                serial: 11,
                accepted_at: Instant::now(),
                expires_at: far_expiry(),
            })
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), rib_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let list = tokio::time::timeout(std::time::Duration::from_secs(1), queries.list())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(list.rows[0].accepted.as_ref().unwrap().serial, Some(11));
        drop(updates);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();

        let (legacy_tx, legacy_rx) = mpsc::channel(1);
        let (rib_tx, mut rib_rx) = mpsc::channel(2);
        let (attachment, updates, queries) = CacheInventoryAttachment::new([server1()]);
        let task = tokio::spawn(
            VrpManager::new(legacy_rx, rib_tx)
                .with_cache_inventory(attachment)
                .run(),
        );
        drop(updates);
        legacy_tx
            .send(VrpUpdate::FullTable {
                server: server1(),
                entries: vec![entry(Ipv4Addr::new(198, 51, 100, 0), 24, 24, 64_497)],
                aspa_records: vec![],
            })
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), rib_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let list = tokio::time::timeout(std::time::Duration::from_secs(1), queries.list())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(list.rows[0].accepted.as_ref().unwrap().vrp_v4_count, 1);
        drop(legacy_tx);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }

    // ── Recovery from a panic in one message ─────────────────────────

    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use crate::rtr_client::RecordBudget;

    struct Recovering {
        mgr: VrpManager,
        rib_rx: mpsc::Receiver<RpkiTableUpdate>,
        aspa_rx: mpsc::Receiver<AspaTableUpdate>,
        updates: CacheUpdateHandle,
        queries: CacheQueryHandle,
        budget: Arc<RecordBudget>,
        faults: Arc<AtomicUsize>,
        resyncs: Arc<Mutex<Vec<(SocketAddr, bool)>>>,
        observer_panics: Arc<AtomicBool>,
    }

    /// A manager with two configured caches, each holding one table that
    /// expires 120 s from now, and every observer attached.
    async fn recovering() -> Recovering {
        let (_legacy_tx, legacy_rx) = mpsc::channel(16);
        let (rib_tx, rib_rx) = mpsc::channel(16);
        let (aspa_tx, aspa_rx) = mpsc::channel(16);
        let (attachment, updates, queries) = CacheInventoryAttachment::new([server1(), server2()]);
        let faults = Arc::new(AtomicUsize::new(0));
        let resyncs = Arc::new(Mutex::new(Vec::new()));
        let observer_panics = Arc::new(AtomicBool::new(false));
        let (fault_count, resync_log, panics) = (
            Arc::clone(&faults),
            Arc::clone(&resyncs),
            Arc::clone(&observer_panics),
        );
        let resync_panics = Arc::clone(&observer_panics);
        let mgr = VrpManager::new(legacy_rx, rib_tx)
            .with_cache_inventory(attachment)
            .with_aspa_tx(aspa_tx)
            .with_fault_observer(move || {
                fault_count.fetch_add(1, Ordering::SeqCst);
            })
            .with_resync_observer(move |server, pending| {
                resync_log.lock().unwrap().push((server, pending));
                assert!(
                    pending || !resync_panics.load(Ordering::SeqCst),
                    "injected observer panic"
                );
            })
            .with_connectivity_observer(move |_, _| {
                assert!(!panics.load(Ordering::SeqCst), "injected observer panic");
            });
        let mut fixture = Recovering {
            mgr,
            rib_rx,
            aspa_rx,
            updates,
            queries,
            budget: RecordBudget::new(1000),
            faults,
            resyncs,
            observer_panics,
        };
        for (server, last) in [(server1(), 1), (server2(), 2)] {
            let update = fixture.full(server, &[last, 9], 120);
            fixture.mgr.receive(update).await;
        }
        fixture.drain();
        fixture
    }

    fn host(last: u8) -> VrpEntry {
        entry(Ipv4Addr::new(203, 0, 113, last), 32, 32, 65001)
    }

    impl Recovering {
        fn full(&self, server: SocketAddr, hosts: &[u8], expires_in: u64) -> EnhancedVrpUpdate {
            EnhancedVrpUpdate::Full {
                server,
                entries: hosts.iter().copied().map(host).collect(),
                aspa_records: vec![AspaRecord {
                    customer_asn: u32::from(hosts[0]),
                    provider_asns: vec![64_500],
                }],
                charge: Reservation::charged(&self.budget, hosts.len(), 0),
                version: 2,
                session_id: 7,
                serial: 100,
                accepted_at: Instant::now(),
                expires_at: TokioInstant::now() + Duration::from_secs(expires_in),
            }
        }

        fn delta(&self, server: SocketAddr, announce: u8, withdraw: u8) -> EnhancedVrpUpdate {
            EnhancedVrpUpdate::Incremental {
                server,
                announced: vec![host(announce)],
                withdrawn: vec![host(withdraw)],
                aspa_announced: vec![],
                aspa_withdrawn: vec![],
                charge: Reservation::charged(&self.budget, 1, 1),
                version: 2,
                session_id: 7,
                serial: 101,
                accepted_at: Instant::now(),
                expires_at: TokioInstant::now() + Duration::from_secs(1000),
            }
        }

        fn drain(&mut self) {
            while self.rib_rx.try_recv().is_ok() {}
            while self.aspa_rx.try_recv().is_ok() {}
        }

        fn inject(&self, faults: usize) {
            self.mgr.injected_faults.store(faults, Ordering::SeqCst);
        }

        fn pending(&self) -> Vec<SocketAddr> {
            let inventory = self.mgr.cache_inventory.as_ref().unwrap();
            let mut pending: Vec<_> = inventory.resync_pending.iter().copied().collect();
            pending.sort();
            pending
        }

        /// Everything a lost message must leave alone: each cache's sets,
        /// deadline and charge, both published tables, the inventory rows
        /// and the record budget.
        fn state(&self) -> impl PartialEq + std::fmt::Debug + use<> {
            let per_cache: BTreeMap<_, _> = self
                .mgr
                .server_tables
                .iter()
                .map(|(server, table)| {
                    let mut entries: Vec<_> = table.entries.iter().cloned().collect();
                    entries.sort();
                    let mut aspas: Vec<_> = self.mgr.server_aspa_tables[server]
                        .iter()
                        .map(|(customer, providers)| (*customer, providers.clone()))
                        .collect();
                    aspas.sort();
                    let charge = table.charge.as_ref().map(|charge| format!("{charge:?}"));
                    (*server, (entries, aspas, table.expires_at, charge))
                })
                .collect();
            let published = self
                .mgr
                .current_table
                .as_ref()
                .map(|table| [1, 2, 3, 4, 9].map(|last| covers(table, last)));
            let published_aspa = self
                .mgr
                .current_aspa_table
                .as_ref()
                .map(|table| table.len());
            (
                per_cache,
                published,
                published_aspa,
                self.mgr.cache_list(),
                self.budget.used(),
            )
        }
    }

    fn covers(table: &VrpTable, last: u8) -> bool {
        let prefix = rustbgpd_wire::Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, last), 32);
        table.validate(&rustbgpd_wire::Prefix::V4(prefix), 65001)
            == rustbgpd_wire::RpkiValidation::Valid
    }

    #[tokio::test(start_paused = true)]
    async fn precommit_test_fault_is_one_shot_and_zero_disables_it() {
        let mut f = recovering().await;
        f.mgr = f.mgr.with_test_precommit_panic_on(1);
        let before = f.state();
        let update = f.full(server1(), &[3, 4], 500);
        f.mgr.receive(update).await;
        assert_eq!(f.state(), before);
        assert_eq!(f.pending(), [server1()]);
        let update = f.full(server1(), &[3, 4], 500);
        f.mgr.receive(update).await;
        assert!(f.pending().is_empty());
        assert!(covers(f.mgr.current_table.as_ref().unwrap(), 3));
        assert_eq!(f.faults.load(Ordering::SeqCst), 1);

        f.mgr = f.mgr.with_test_precommit_panic_on(0);
        let update = f.full(server1(), &[1, 9], 500);
        f.mgr.receive(update).await;
        assert!(covers(f.mgr.current_table.as_ref().unwrap(), 1));
        assert_eq!(f.faults.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_legacy_update_panic_ends_the_manager_with_or_without_inventory() {
        for with_inventory in [false, true] {
            let (updates, update_rx) = mpsc::channel(1);
            let (rib_tx, _rib_rx) = mpsc::channel(1);
            let mut manager = VrpManager::new(update_rx, rib_tx);
            if with_inventory {
                let (inventory, _updates, _queries) = CacheInventoryAttachment::new([server1()]);
                manager = manager.with_cache_inventory(inventory);
            }
            manager.injected_faults.store(1, Ordering::SeqCst);
            let task = tokio::spawn(manager.run());
            updates
                .send(VrpUpdate::ServerDown { server: server1() })
                .await
                .unwrap();
            assert!(task.await.unwrap_err().is_panic());
        }
    }

    /// A panic while a full table or a serial delta is being applied loses
    /// that update and nothing else: no set, deadline, charge, inventory row
    /// or published table changes, nothing is distributed, and the cache is
    /// asked to resynchronize.
    #[tokio::test(start_paused = true)]
    async fn panic_in_a_data_update_leaves_state_as_before_and_requests_a_resync() {
        let mut f = recovering().await;
        let before = f.state();
        let table = Arc::clone(f.mgr.current_table.as_ref().unwrap());

        f.inject(1);
        let update = f.full(server1(), &[3, 4], 500);
        f.mgr.receive(update).await;
        assert_eq!(f.state(), before);
        assert!(Arc::ptr_eq(f.mgr.current_table.as_ref().unwrap(), &table));
        assert_eq!(f.pending(), [server1()]);

        f.inject(1);
        let update = f.delta(server2(), 5, 2);
        f.mgr.receive(update).await;
        assert_eq!(f.state(), before);
        assert_eq!(f.pending(), [server1(), server2()]);

        assert!(f.rib_rx.try_recv().is_err() && f.aspa_rx.try_recv().is_err());
        assert_eq!(f.faults.load(Ordering::SeqCst), 2);
        assert_eq!(
            *f.resyncs.lock().unwrap(),
            [(server1(), true), (server2(), true)]
        );
        let requests = f.updates.1.borrow().clone();
        assert_eq!(requests[&server1()], 1);
        assert_eq!(requests[&server2()], 1);
    }

    /// A panic in a connectivity change, here in the embedder's observer,
    /// costs only that notification: no data moves and no resync is asked.
    #[tokio::test(start_paused = true)]
    async fn panic_in_a_connectivity_change_touches_no_data() {
        let mut f = recovering().await;
        let before = f.state();
        f.observer_panics.store(true, Ordering::SeqCst);
        f.mgr
            .receive(EnhancedVrpUpdate::Disconnected {
                server: server1(),
                flush: false,
            })
            .await;
        f.observer_panics.store(false, Ordering::SeqCst);
        assert_eq!(f.state(), before);
        assert_eq!(f.faults.load(Ordering::SeqCst), 1);
        assert_eq!(f.pending(), Vec::<SocketAddr>::new());
        assert!(f.rib_rx.try_recv().is_err());
    }

    /// An observer that panics when told a cache has resynchronized does
    /// not undo the resynchronization: the full table is installed and
    /// published, the cache is no longer pending, and no further full table
    /// is asked of it.
    #[tokio::test(start_paused = true)]
    async fn panic_in_the_resynchronized_notification_leaves_the_cache_resynchronized() {
        let mut f = recovering().await;
        f.inject(1);
        let lost = f.delta(server1(), 3, 1);
        f.mgr.receive(lost).await;
        assert_eq!(f.pending(), [server1()]);

        f.observer_panics.store(true, Ordering::SeqCst);
        let resync = f.full(server1(), &[3, 4], 500);
        f.mgr.receive(resync).await;
        f.observer_panics.store(false, Ordering::SeqCst);

        assert_eq!(f.pending(), Vec::<SocketAddr>::new());
        assert_eq!(f.updates.1.borrow()[&server1()], 1, "no second request");
        assert!(covers(&f.rib_rx.try_recv().expect("published").table, 3));
        assert_eq!(
            f.faults.load(Ordering::SeqCst),
            2,
            "the loss and the observer"
        );
        // Serial deltas are applied again.
        let applied = f.delta(server1(), 5, 3);
        f.mgr.receive(applied).await;
        assert!(covers(&f.rib_rx.try_recv().unwrap().table, 5));
    }

    /// The two types an embedder holds across its own unwinding code keep
    /// the auto traits they were published with.
    #[test]
    fn inventory_handles_stay_unwind_safe() {
        fn assert_unwind_safe<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
        assert_unwind_safe::<CacheUpdateHandle>();
        assert_unwind_safe::<CacheInventoryAttachment>();
    }

    /// A panic in an inventory query loses that query: the caller gets an
    /// error, the manager keeps running and answers the next one.
    #[tokio::test(start_paused = true)]
    async fn panic_in_an_inventory_query_fails_only_that_query() {
        let f = recovering().await;
        f.inject(1);
        let (faults, queries) = (Arc::clone(&f.faults), f.queries.clone());
        let _updates = f.updates.clone();
        let manager = tokio::spawn(f.mgr.run());
        assert_eq!(queries.list().await, Err(CacheQueryError));
        let list = queries.list().await.expect("the manager is still running");
        assert_eq!(list.rows.len(), 2);
        assert_eq!(faults.load(Ordering::SeqCst), 1);
        assert!(!manager.is_finished());
    }

    /// A panic while a cache's data is being removed must not keep the
    /// data: the removal is carried out again, the remaining caches' table
    /// is published with what left as its delta, and the cache owes a full
    /// table.
    #[tokio::test(start_paused = true)]
    async fn panic_in_an_expiry_still_removes_the_data() {
        for flush in [false, true] {
            let mut f = recovering().await;
            f.inject(1);
            let removal = if flush {
                EnhancedVrpUpdate::Disconnected {
                    server: server1(),
                    flush: true,
                }
            } else {
                EnhancedVrpUpdate::Expired { server: server1() }
            };
            f.mgr.receive(removal).await;

            let update = f.rib_rx.try_recv().expect("the removal is published");
            assert!(f.rib_rx.try_recv().is_err(), "published once");
            assert!(!covers(&update.table, 1) && covers(&update.table, 2));
            assert!(covers(&update.table, 9), "the other cache still holds it");
            // Exactly what left the merged table: the other cache still
            // holds host 9.
            assert_eq!(update.delta, Some(vec![host(1)]));
            assert!(!f.mgr.server_tables.contains_key(&server1()));
            assert!(!f.mgr.server_aspa_tables.contains_key(&server1()));
            assert!(f.mgr.cache_list().rows[0].accepted.is_none());
            assert_eq!(f.budget.used(), 2, "the removed table's charge is released");
            assert_eq!(f.faults.load(Ordering::SeqCst), 1);
            // The client that sent the removal has no epoch left, so no
            // resync is asked of it.
            assert_eq!(f.pending(), Vec::<SocketAddr>::new());
        }
    }

    /// If the tables cannot be rebuilt without the cache either, the
    /// manager ends instead of holding data it can no longer expire.
    #[tokio::test(start_paused = true)]
    async fn a_removal_that_panics_twice_ends_the_manager() {
        let mut f = recovering().await;
        f.inject(2);
        let ended = tokio::spawn(async move {
            f.mgr
                .receive(EnhancedVrpUpdate::Expired { server: server1() })
                .await;
        })
        .await;
        assert!(ended.unwrap_err().is_panic());
    }

    /// While a cache is resync pending its serial deltas are dropped (their
    /// base is the lost update, not the set held here) and release their
    /// charge. Only that cache's full table ends the wait, and it is
    /// published once with exactly the entries the two tables differ in.
    #[tokio::test(start_paused = true)]
    async fn pending_cache_drops_serial_deltas_until_its_full_table() {
        let mut f = recovering().await;
        f.inject(1);
        let lost = f.delta(server1(), 3, 1);
        f.mgr.receive(lost).await;
        let before = f.state();

        // The delta after the lost one, and another cache's full table,
        // leave the cache pending.
        let next = f.delta(server1(), 4, 9);
        f.mgr.receive(next).await;
        assert_eq!(f.state(), before);
        let other = f.full(server2(), &[2, 9], 120);
        f.mgr.receive(other).await;
        assert_eq!(f.pending(), [server1()]);
        assert!(
            f.rib_rx.try_recv().is_err(),
            "nothing changed, nothing published"
        );

        let resync = f.full(server1(), &[3, 4], 500);
        f.mgr.receive(resync).await;
        assert_eq!(f.pending(), Vec::<SocketAddr>::new());
        assert_eq!(
            *f.resyncs.lock().unwrap(),
            [(server1(), true), (server1(), false)]
        );
        let update = f.rib_rx.try_recv().expect("one publication");
        assert!(f.rib_rx.try_recv().is_err());
        let mut delta = update
            .delta
            .expect("a replacing table carries its difference");
        delta.sort();
        // Host 9 left this cache's set too, but the other cache still has
        // it, so it did not leave the merged table.
        assert_eq!(delta, [host(1), host(3), host(4)]);
        assert_eq!(
            [1, 2, 3, 4, 9].map(|last| covers(&update.table, last)),
            [false, true, true, true, true]
        );
        // A delta is applied again once the cache is no longer pending.
        let applied = f.delta(server1(), 5, 3);
        f.mgr.receive(applied).await;
        assert!(covers(&f.rib_rx.try_recv().unwrap().table, 5));
    }

    /// A full table equal to the one it replaces changes nothing and is not
    /// distributed, so a resynchronization with unchanged data costs the
    /// RIB no work.
    #[tokio::test(start_paused = true)]
    async fn identical_replacing_table_is_not_distributed() {
        let mut f = recovering().await;
        let same = f.full(server1(), &[1, 9], 120);
        f.mgr.receive(same).await;
        assert!(f.rib_rx.try_recv().is_err() && f.aspa_rx.try_recv().is_err());
    }

    /// The manager drops a pending cache's held data at the expiry instant
    /// that came with it. The client cannot: it renewed its own clock for
    /// the update that was lost.
    #[tokio::test(start_paused = true)]
    async fn held_data_of_a_pending_cache_leaves_at_its_original_expiry() {
        let mut f = recovering().await;
        let start = TokioInstant::now();
        f.inject(1);
        // The lost update would have renewed the deadline to 1000 s.
        let lost = f.delta(server1(), 3, 1);
        f.mgr.receive(lost).await;
        // The other cache is not pending: its own client expires it.
        let updates = f.updates.clone();
        let mut rib_rx = f.rib_rx;
        let manager = tokio::spawn(f.mgr.run());

        // Bounded, so a manager that never drops the data fails the test.
        let update = tokio::time::timeout(Duration::from_secs(1000), rib_rx.recv())
            .await
            .expect("the held data was never dropped")
            .unwrap();
        assert_eq!(start.elapsed(), Duration::from_secs(120));
        assert!(!covers(&update.table, 1) && covers(&update.table, 2));
        // Nothing else leaves on the manager's clock.
        tokio::time::sleep(Duration::from_secs(5000)).await;
        assert!(rib_rx.try_recv().is_err());
        drop(updates);
        manager.abort();
    }
}
