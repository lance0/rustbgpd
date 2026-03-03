//! VRP manager — merges VRP tables from multiple RTR cache servers.
//!
//! Runs as a single tokio task. Receives [`VrpUpdate`] messages from RTR
//! clients and maintains a merged, deduplicated [`VrpTable`]. When the table
//! changes, sends an `Arc<VrpTable>` snapshot to the RIB manager.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info};

use crate::rtr_client::VrpUpdate;
use crate::vrp::{VrpEntry, VrpTable};

/// Message sent from VRP manager to RIB manager when the VRP table changes.
#[derive(Debug, Clone)]
pub struct RpkiTableUpdate {
    pub table: Arc<VrpTable>,
}

/// Merges VRP data from multiple RTR cache servers into a single table.
pub struct VrpManager {
    /// Per-server VRP entry sets.
    server_tables: HashMap<SocketAddr, Vec<VrpEntry>>,
    /// Current merged table.
    current_table: Arc<VrpTable>,
    /// Receiver for updates from RTR clients.
    update_rx: mpsc::Receiver<VrpUpdate>,
    /// Sender for table snapshots to the RIB manager.
    rib_tx: mpsc::Sender<RpkiTableUpdate>,
}

impl VrpManager {
    /// Create a new VRP manager.
    #[must_use]
    pub fn new(
        update_rx: mpsc::Receiver<VrpUpdate>,
        rib_tx: mpsc::Sender<RpkiTableUpdate>,
    ) -> Self {
        Self {
            server_tables: HashMap::new(),
            current_table: Arc::new(VrpTable::new(vec![])),
            update_rx,
            rib_tx,
        }
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
            VrpUpdate::FullTable { server, entries } => {
                info!(
                    %server,
                    entries = entries.len(),
                    "VRP full table from cache"
                );
                self.server_tables.insert(server, entries);
            }
            VrpUpdate::IncrementalUpdate {
                server,
                announced,
                withdrawn,
            } => {
                debug!(
                    %server,
                    announced = announced.len(),
                    withdrawn = withdrawn.len(),
                    "VRP incremental update from cache"
                );
                let table = self.server_tables.entry(server).or_default();
                // Remove withdrawn entries
                for w in &withdrawn {
                    table.retain(|e| e != w);
                }
                // Add announced entries (dedup handled by VrpTable::new)
                table.extend(announced);
            }
            VrpUpdate::ServerDown { server } => {
                info!(%server, "VRP cache server down — removing entries");
                self.server_tables.remove(&server);
            }
        }

        self.rebuild_and_distribute().await;
    }

    async fn rebuild_and_distribute(&mut self) {
        // Merge all server tables
        let merged: Vec<VrpEntry> = self
            .server_tables
            .values()
            .flat_map(|v| v.iter().cloned())
            .collect();

        let new_table = Arc::new(VrpTable::new(merged));

        // Avoid spurious RIB revalidation when the merged table is unchanged.
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
        })
        .await;
        let _ = rib_rx.try_recv(); // consume first update

        mgr.handle_update(VrpUpdate::FullTable {
            server: server2(),
            entries: vec![
                shared, // duplicate
                entry(Ipv4Addr::new(10, 1, 0, 0), 24, 24, 65002),
            ],
        })
        .await;

        let update = rib_rx.try_recv().unwrap();
        // Deduplicated: shared entry counted once + the unique one = 2
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

        // Start with e1 and e2
        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![e1.clone(), e2.clone()],
        })
        .await;
        let _ = rib_rx.try_recv();

        // Incremental: withdraw e1, announce e3
        mgr.handle_update(VrpUpdate::IncrementalUpdate {
            server: server1(),
            announced: vec![e3.clone()],
            withdrawn: vec![e1],
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
        })
        .await;
        let _ = rib_rx.try_recv();

        mgr.handle_update(VrpUpdate::FullTable {
            server: server2(),
            entries: vec![entry(Ipv4Addr::new(10, 1, 0, 0), 24, 24, 65002)],
        })
        .await;
        let _ = rib_rx.try_recv();

        // Server 1 goes down
        mgr.handle_update(VrpUpdate::ServerDown { server: server1() })
            .await;

        let update = rib_rx.try_recv().unwrap();
        assert_eq!(update.table.len(), 1); // only server2's entry
    }

    #[tokio::test]
    async fn empty_table_after_all_servers_down() {
        let (_vrp_tx, vrp_rx) = mpsc::channel(16);
        let (rib_tx, mut rib_rx) = mpsc::channel(16);
        let mut mgr = VrpManager::new(vrp_rx, rib_tx);

        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries: vec![entry(Ipv4Addr::new(10, 0, 0, 0), 24, 24, 65001)],
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
        })
        .await;
        let _ = rib_rx.try_recv().unwrap();

        // Same effective merged table should not emit another update.
        mgr.handle_update(VrpUpdate::FullTable {
            server: server1(),
            entries,
        })
        .await;

        assert!(rib_rx.try_recv().is_err());
    }
}
