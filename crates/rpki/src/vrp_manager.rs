//! VRP + ASPA manager — merges tables from multiple RTR cache servers.
//!
//! Runs as a single tokio task. Receives [`VrpUpdate`] messages from RTR
//! clients and maintains merged, deduplicated [`VrpTable`] and [`AspaTable`]
//! snapshots. When either table changes, sends the updated snapshot to the
//! RIB manager.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

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
}

/// Message sent from VRP manager to RIB manager when the ASPA table changes.
#[derive(Debug, Clone)]
pub struct AspaTableUpdate {
    /// The new merged ASPA table snapshot.
    pub table: Arc<AspaTable>,
}

/// Merges VRP and ASPA data from multiple RTR cache servers.
pub struct VrpManager {
    /// Per-server VRP entry sets.
    server_tables: HashMap<SocketAddr, Vec<VrpEntry>>,
    /// Per-server ASPA record sets.
    server_aspa_tables: HashMap<SocketAddr, Vec<AspaRecord>>,
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
        }
    }

    /// Set the ASPA table update sender.
    #[must_use]
    pub fn with_aspa_tx(mut self, tx: mpsc::Sender<AspaTableUpdate>) -> Self {
        self.aspa_rib_tx = Some(tx);
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
        match update {
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
                self.server_tables.insert(server, entries);
                self.server_aspa_tables.insert(server, aspa_records);
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
                // VRP incremental
                let table = self.server_tables.entry(server).or_default();
                for w in &withdrawn {
                    table.retain(|e| e != w);
                }
                table.extend(announced);

                // ASPA incremental
                let aspa_table = self.server_aspa_tables.entry(server).or_default();
                for w in &aspa_withdrawn {
                    aspa_table.retain(|r| r != w);
                }
                aspa_table.extend(aspa_announced);
            }
            VrpUpdate::ServerDown { server } => {
                info!(%server, "cache server down — removing entries");
                self.server_tables.remove(&server);
                self.server_aspa_tables.remove(&server);
            }
        }

        self.rebuild_and_distribute_vrp().await;
        self.rebuild_and_distribute_aspa().await;
    }

    async fn rebuild_and_distribute_vrp(&mut self) {
        let merged: Vec<VrpEntry> = self
            .server_tables
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect();

        let new_table = Arc::new(VrpTable::new(merged));

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
        let _ = self.rib_tx.send(RpkiTableUpdate { table: new_table }).await;
    }

    async fn rebuild_and_distribute_aspa(&mut self) {
        let Some(ref aspa_tx) = self.aspa_rib_tx else {
            return;
        };

        let merged: Vec<AspaRecord> = self
            .server_aspa_tables
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect();

        let new_table = Arc::new(AspaTable::new(merged));

        if *new_table == *self.current_aspa_table {
            debug!("ASPA table unchanged — skipping distribution");
            return;
        }

        info!(records = new_table.len(), "ASPA table updated");
        self.current_aspa_table = Arc::clone(&new_table);
        let _ = aspa_tx.send(AspaTableUpdate { table: new_table }).await;
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
            withdrawn: vec![e1],
            aspa_announced: vec![],
            aspa_withdrawn: vec![],
        })
        .await;

        let update = rib_rx.try_recv().unwrap();
        assert_eq!(update.table.len(), 2); // e2 + e3
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
    async fn aspa_incremental_withdraw_is_record_level() {
        use crate::aspa::ProviderAuth;

        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, _rib_rx) = mpsc::channel(16);
        let (aspa_tx, mut aspa_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx).with_aspa_tx(aspa_tx);

        // Two ASPA records for the same customer from different CAs
        let record_a = AspaRecord {
            customer_asn: 65001,
            provider_asns: vec![65002],
        };
        let record_b = AspaRecord {
            customer_asn: 65001,
            provider_asns: vec![65003],
        };

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![],
            aspa_records: vec![record_a.clone(), record_b.clone()],
        })
        .await;
        let update = aspa_rx.try_recv().unwrap();
        // Both records merged: 65001 has providers {65002, 65003}
        assert_eq!(
            update.table.authorized(65001, 65002),
            ProviderAuth::ProviderPlus
        );
        assert_eq!(
            update.table.authorized(65001, 65003),
            ProviderAuth::ProviderPlus
        );

        // Withdraw only record_a — record_b should survive
        mgr.handle_update(VrpUpdate::IncrementalUpdate {
            server: server1(),
            announced: vec![],
            withdrawn: vec![],
            aspa_announced: vec![],
            aspa_withdrawn: vec![record_a],
        })
        .await;
        let update = aspa_rx.try_recv().unwrap();
        // 65003 should still be authorized (from record_b)
        assert_eq!(
            update.table.authorized(65001, 65003),
            ProviderAuth::ProviderPlus
        );
        // 65002 should no longer be authorized (record_a withdrawn)
        assert_eq!(
            update.table.authorized(65001, 65002),
            ProviderAuth::NotProviderPlus
        );
    }
}
