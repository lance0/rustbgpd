//! VRP + ASPA manager — merges tables from multiple RTR cache servers.
//!
//! Runs as a single tokio task. Receives [`VrpUpdate`] messages from RTR
//! clients and maintains merged, deduplicated [`VrpTable`] and [`AspaTable`]
//! snapshots. When either table changes, sends the updated snapshot to the
//! RIB manager.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;

use rustc_hash::FxHashSet;
use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::aspa::{AspaRecord, AspaTable};
use crate::rtr_client::VrpUpdate;
use crate::vrp::{VrpEntry, VrpTable};

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
        }
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
        while let Some(update) = self.update_rx.recv().await {
            self.handle_update(update).await;
        }
        info!("VRP manager shutting down");
    }

    async fn handle_update(&mut self, update: VrpUpdate) {
        let (server, ready, vrp_delta, changed_customer_asns) = match update {
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
}
