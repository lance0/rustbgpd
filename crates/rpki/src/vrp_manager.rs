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
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info};

use crate::aspa::{AspaRecord, AspaTable};
use crate::rtr_client::VrpUpdate;
use crate::vrp::{VrpEntry, VrpTable};

const CACHE_QUERY_CAPACITY: usize = 16;
pub const MAX_CACHE_ROWS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptedCacheState {
    pub protocol_version: Option<u8>,
    pub session_id: Option<u16>,
    pub serial: Option<u32>,
    pub vrp_v4_count: usize,
    pub vrp_v6_count: usize,
    pub aspa_count: usize,
    pub age_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheState {
    pub server: SocketAddr,
    pub connected: bool,
    pub accepted: Option<AcceptedCacheState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CacheList {
    pub rows: Vec<CacheState>,
    pub omitted: u64,
}

pub struct CacheQuery {
    reply: oneshot::Sender<CacheList>,
}

#[derive(Clone)]
pub struct CacheQueryHandle(mpsc::Sender<CacheQuery>);

impl CacheQueryHandle {
    /// Request the current bounded cache inventory.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheQueryError;

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
        version: u8,
        session_id: u16,
        serial: u32,
        accepted_at: Instant,
    },
    Incremental {
        server: SocketAddr,
        announced: Vec<VrpEntry>,
        withdrawn: Vec<VrpEntry>,
        aspa_announced: Vec<AspaRecord>,
        aspa_withdrawn: Vec<AspaRecord>,
        version: u8,
        session_id: u16,
        serial: u32,
        accepted_at: Instant,
    },
}

#[derive(Clone)]
pub struct CacheUpdateHandle(pub(crate) mpsc::Sender<EnhancedVrpUpdate>);

pub struct CacheInventoryAttachment {
    update_rx: mpsc::Receiver<EnhancedVrpUpdate>,
    query_rx: mpsc::Receiver<CacheQuery>,
    query_open: bool,
    states: BTreeMap<SocketAddr, InternalCacheState>,
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
    #[must_use]
    pub fn new(
        servers: impl IntoIterator<Item = SocketAddr>,
    ) -> (Self, CacheUpdateHandle, CacheQueryHandle) {
        let (update_tx, update_rx) = mpsc::channel(256);
        let (query_tx, query_rx) = mpsc::channel(CACHE_QUERY_CAPACITY);
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
            },
            CacheUpdateHandle(update_tx),
            CacheQueryHandle(query_tx),
        )
    }
}

/// Message sent from VRP manager to RIB manager when the VRP table changes.
#[derive(Debug, Clone)]
pub struct RpkiTableUpdate {
    /// The new merged VRP table snapshot.
    pub table: Arc<VrpTable>,
    /// The VRP entries announced or withdrawn since the previously
    /// distributed snapshot, when this update came from an RTR incremental
    /// (serial) sync. The merged table is a union of per-server sets, so any
    /// entry that differs between consecutive distributed snapshots is
    /// guaranteed to appear in this list — a route's validation outcome can
    /// only change if its prefix is covered by one of these entries, which
    /// lets the RIB manager revalidate just the covered routes.
    ///
    /// `None` means no delta is known (full cache snapshot, cache reset,
    /// resync, server loss) and consumers must revalidate everything.
    pub delta: Option<Vec<VrpEntry>>,
}

/// Message sent from VRP manager to RIB manager when the ASPA table changes.
#[derive(Debug, Clone)]
pub struct AspaTableUpdate {
    /// The new merged ASPA table snapshot.
    pub table: Arc<AspaTable>,
    /// Customer ASNs announced or withdrawn by an RTR incremental update.
    /// `None` requires a full revalidation (full snapshot or server loss).
    pub changed_customer_asns: Option<FxHashSet<u32>>,
}

/// Merges VRP and ASPA data from multiple RTR cache servers.
pub struct VrpManager {
    /// Per-server VRP entry sets. A set (not a list) so an incremental
    /// withdraw is O(withdrawn) instead of O(withdrawn × table size).
    server_tables: HashMap<SocketAddr, HashSet<VrpEntry>>,
    /// Per-server ASPA state, keyed by customer ASN.
    ///
    /// Keyed (not a record list) because 8210bis ASPA PDUs carry the
    /// complete provider set per customer ASN: an announce REPLACES the
    /// customer's previous provider set, and a withdraw removes the
    /// customer ASN entirely.
    server_aspa_tables: HashMap<SocketAddr, HashMap<u32, Vec<u32>>>,
    /// Current merged VRP table.
    current_table: Arc<VrpTable>,
    /// Current merged ASPA table.
    current_aspa_table: Arc<AspaTable>,
    /// Receiver for updates from RTR clients.
    update_rx: mpsc::Receiver<VrpUpdate>,
    /// Sender for VRP table snapshots to the RIB manager.
    rib_tx: mpsc::Sender<RpkiTableUpdate>,
    /// Sender for ASPA table snapshots to the RIB manager.
    aspa_rib_tx: Option<mpsc::Sender<AspaTableUpdate>>,
    readiness_observer: Option<Box<dyn Fn(SocketAddr, bool) + Send + Sync>>,
    cache_inventory: Option<CacheInventoryAttachment>,
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
            current_table: Arc::new(VrpTable::new(vec![])),
            current_aspa_table: Arc::new(AspaTable::new(vec![])),
            update_rx,
            rib_tx,
            aspa_rib_tx: None,
            readiness_observer: None,
            cache_inventory: None,
        }
    }

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

    /// Main event loop.
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
            let Some(inventory) = self.cache_inventory.as_mut() else {
                continue;
            };
            tokio::select! {
                biased;
                update = self.update_rx.recv(), if legacy_updates_open => match update {
                    Some(update) => self.handle_update(update).await,
                    None => legacy_updates_open = false,
                },
                update = inventory.update_rx.recv(), if enhanced_updates_open => match update {
                    Some(update) => self.handle_enhanced_update(update).await,
                    None => enhanced_updates_open = false,
                },
                query = inventory.query_rx.recv(), if inventory.query_open => match query {
                    Some(query) => { let _ = query.reply.send(self.cache_list()); }
                    None => inventory.query_open = false,
                },
            }
        }
        info!("VRP manager shutting down");
    }

    fn cache_list(&self) -> CacheList {
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
                    let table = self.server_tables.get(&server);
                    let (vrp_v4_count, vrp_v6_count) = table.map_or((0, 0), |entries| {
                        entries
                            .iter()
                            .fold((0, 0), |(v4, v6), entry| match entry.prefix {
                                std::net::IpAddr::V4(_) => (v4 + 1, v6),
                                std::net::IpAddr::V6(_) => (v4, v6 + 1),
                            })
                    });
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
            EnhancedVrpUpdate::Connected { server } => {
                if let Some(state) = self
                    .cache_inventory
                    .as_mut()
                    .and_then(|i| i.states.get_mut(&server))
                {
                    state.connected = true;
                }
            }
            EnhancedVrpUpdate::Disconnected { server, flush } => {
                if let Some(state) = self
                    .cache_inventory
                    .as_mut()
                    .and_then(|i| i.states.get_mut(&server))
                {
                    state.connected = false;
                    if flush {
                        state.accepted = None;
                    }
                }
                if flush {
                    self.handle_update(VrpUpdate::ServerDown { server }).await;
                }
            }
            EnhancedVrpUpdate::Expired { server } => {
                if let Some(state) = self
                    .cache_inventory
                    .as_mut()
                    .and_then(|i| i.states.get_mut(&server))
                {
                    state.accepted = None;
                }
                self.handle_update(VrpUpdate::ServerDown { server }).await;
            }
            EnhancedVrpUpdate::Full {
                server,
                entries,
                aspa_records,
                version,
                session_id,
                serial,
                accepted_at,
            } => {
                self.handle_update(VrpUpdate::FullTable {
                    server,
                    entries,
                    aspa_records,
                })
                .await;
                self.set_accepted(
                    server,
                    Some(version),
                    Some(session_id),
                    Some(serial),
                    accepted_at,
                );
            }
            EnhancedVrpUpdate::Incremental {
                server,
                announced,
                withdrawn,
                aspa_announced,
                aspa_withdrawn,
                version,
                session_id,
                serial,
                accepted_at,
            } => {
                self.handle_update(VrpUpdate::IncrementalUpdate {
                    server,
                    announced,
                    withdrawn,
                    aspa_announced,
                    aspa_withdrawn,
                })
                .await;
                self.set_accepted(
                    server,
                    Some(version),
                    Some(session_id),
                    Some(serial),
                    accepted_at,
                );
            }
        }
    }

    fn set_accepted(
        &mut self,
        server: SocketAddr,
        version: Option<u8>,
        session_id: Option<u16>,
        serial: Option<u32>,
        accepted_at: Instant,
    ) {
        if let Some(state) = self
            .cache_inventory
            .as_mut()
            .and_then(|i| i.states.get_mut(&server))
        {
            state.accepted = Some(AcceptedMetadata {
                version,
                session_id,
                serial,
                accepted_at,
            });
        }
    }

    async fn handle_update(&mut self, update: VrpUpdate) {
        let (server, ready, vrp_delta, changed_customer_asns) = match update {
            VrpUpdate::FullTable {
                server,
                entries,
                aspa_records,
            } => {
                self.set_accepted(server, None, None, None, Instant::now());
                info!(
                    %server,
                    vrps = entries.len(),
                    aspa = aspa_records.len(),
                    "full table from cache"
                );
                self.server_tables
                    .insert(server, entries.into_iter().collect());
                // Later PDUs for the same customer ASN replace earlier
                // ones within a full table (8210bis replacement semantics).
                self.server_aspa_tables.insert(
                    server,
                    aspa_records
                        .into_iter()
                        .map(|r| (r.customer_asn, r.provider_asns))
                        .collect(),
                );
                // A full snapshot replaces the server's whole set — there is
                // no bounded changed-entry list, so downstream must rescan.
                (server, true, None, None)
            }
            VrpUpdate::IncrementalUpdate {
                server,
                announced,
                withdrawn,
                aspa_announced,
                aspa_withdrawn,
            } => {
                self.set_accepted(server, None, None, None, Instant::now());
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
                let table = self.server_tables.entry(server).or_default();
                for w in &withdrawn {
                    table.remove(w);
                }
                // Every merged-table entry that can differ from the previous
                // snapshot is in one of these two lists (only this server's
                // set is mutated, and only by exactly these entries).
                let mut delta = withdrawn.clone();
                delta.extend(announced.iter().cloned());
                table.extend(announced);

                // ASPA incremental (8210bis semantics): a withdraw (which
                // carries an empty provider set on the wire) removes the
                // customer ASN; an announce replaces the customer's entire
                // provider set.
                let aspa_table = self.server_aspa_tables.entry(server).or_default();
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
                (server, true, Some(delta), Some(changed_customer_asns))
            }
            VrpUpdate::ServerDown { server } => {
                info!(%server, "cache server down — removing entries");
                self.server_tables.remove(&server);
                self.server_aspa_tables.remove(&server);
                // ponytail: the removed set IS the exact delta, but server
                // loss is rare and multi-cache overlap makes it usually a
                // no-op distribution; wire it through if it ever shows up.
                (server, false, None, None)
            }
        };

        self.rebuild_and_distribute_vrp(vrp_delta).await;
        self.rebuild_and_distribute_aspa(changed_customer_asns)
            .await;
        if let Some(observer) = &self.readiness_observer {
            observer(server, ready);
        }
    }

    // Full rebuild (clone + sort of every entry) on every update, even a
    // one-entry incremental. Fine at real-world shapes: RTR serial-notify
    // deltas are tiny next to the ~600k-VRP global table, and rebuilds are
    // O(total log total) on a single manager task off the hot path.
    // ponytail: revisit with per-family incremental table maintenance only if
    // caches ever stream high-rate deltas.
    async fn rebuild_and_distribute_vrp(&mut self, delta: Option<Vec<VrpEntry>>) {
        let merged: Vec<VrpEntry> = self
            .server_tables
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect();

        let new_table = Arc::new(VrpTable::new(merged));

        // Dropping a suppressed update's delta is sound: suppression proves
        // the merged table did not change, so the last *distributed* snapshot
        // still equals the table any later delta is computed against.
        if *new_table == *self.current_table {
            debug!("VRP table unchanged — skipping distribution");
            return;
        }

        info!(
            v4 = new_table.v4_count(),
            v6 = new_table.v6_count(),
            total = new_table.len(),
            "VRP table updated"
        );
        self.current_table = Arc::clone(&new_table);
        let _ = self
            .rib_tx
            .send(RpkiTableUpdate {
                table: new_table,
                delta,
            })
            .await;
    }

    async fn rebuild_and_distribute_aspa(&mut self, changed_customer_asns: Option<FxHashSet<u32>>) {
        let Some(ref aspa_tx) = self.aspa_rib_tx else {
            return;
        };

        let merged: Vec<AspaRecord> = self
            .server_aspa_tables
            .values()
            .flat_map(|per_customer| {
                per_customer.iter().map(|(customer, providers)| AspaRecord {
                    customer_asn: *customer,
                    provider_asns: providers.clone(),
                })
            })
            .collect();

        let new_table = Arc::new(AspaTable::new(merged));

        if *new_table == *self.current_aspa_table {
            debug!("ASPA table unchanged — skipping distribution");
            return;
        }

        info!(records = new_table.len(), "ASPA table updated");
        self.current_aspa_table = Arc::clone(&new_table);
        let _ = aspa_tx
            .send(AspaTableUpdate {
                table: new_table,
                changed_customer_asns,
            })
            .await;
    }

    /// Number of connected cache servers with data.
    #[must_use]
    pub fn connected_servers(&self) -> usize {
        self.server_tables.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::{Arc, Mutex};

    use super::*;

    fn entry(addr: Ipv4Addr, prefix_len: u8, max_len: u8, asn: u32) -> VrpEntry {
        VrpEntry {
            prefix: IpAddr::V4(addr),
            prefix_len,
            max_len,
            origin_asn: asn,
        }
    }

    fn server1() -> SocketAddr {
        "10.0.0.1:3323".parse().unwrap()
    }

    fn server2() -> SocketAddr {
        "10.0.0.2:3323".parse().unwrap()
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
        assert!(update.delta.is_none(), "server loss must not carry a delta");
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
        assert!(aspa_rx.try_recv().unwrap().changed_customer_asns.is_none());
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
            server: server1(),
            entries: vec![entry(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 64_496)],
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
            (1, 0, 1)
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
            server: server1(),
            announced: vec![],
            withdrawn: vec![],
            aspa_announced: vec![],
            aspa_withdrawn: vec![],
            version: 2,
            session_id: 7,
            serial: 12,
            accepted_at: Instant::now(),
        })
        .await;
        assert_eq!(
            mgr.cache_list().rows[0].accepted.as_ref().unwrap().serial,
            Some(12)
        );

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
                server: server1(),
                entries: vec![entry(Ipv4Addr::new(192, 0, 2, 0), 24, 24, 64_496)],
                aspa_records: vec![],
                version: 2,
                session_id: 7,
                serial: 11,
                accepted_at: Instant::now(),
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
}
