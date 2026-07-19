//! Persists config mutations to disk.
//!
//! Runs as a single tokio task, receiving mutations via an mpsc channel.
//! Each mutation is applied to the in-memory config, serialized to TOML,
//! and atomically written (temp file + rename) to the config path.

#![deny(unsafe_code)]

use std::net::IpAddr;
use std::path::PathBuf;

use tokio::sync::{mpsc, oneshot};
use tracing::{error, info, warn};

use crate::config::{Config, Neighbor};

/// A mutation to apply to the persisted config.
#[allow(dead_code)]
pub enum ConfigMutation {
    AddNeighbor(Box<Neighbor>),
    DeleteNeighbor(IpAddr),
    /// Replace the entire config snapshot and persist it to disk.
    ReplaceConfig(Box<Config>),
    /// Replace the entire config snapshot, persist it to disk, then acknowledge
    /// the result to a caller that must not proceed until the write has settled.
    ReplaceConfigAck(Box<Config>, oneshot::Sender<Result<(), String>>),
    /// Refresh the persister's base snapshot without writing to disk.
    ///
    /// SIGHUP reload uses this for operator-authored TOML that
    /// contains restart-required fields. Runtime keeps a pinned live
    /// snapshot, but future gRPC mutations must still apply on top of
    /// the operator's desired file rather than writing the pinned
    /// runtime snapshot back to disk.
    RefreshSnapshotNoPersist(Box<Config>),
}

/// Listens for config mutations and persists them atomically.
pub struct ConfigPersister {
    rx: mpsc::Receiver<ConfigMutation>,
    config_path: PathBuf,
    current: Config,
    /// Applied-config history directory (`config_history` module). `None`
    /// disables recording (unit tests, embedders without a state dir).
    history_dir: Option<PathBuf>,
}

impl ConfigPersister {
    pub fn new(
        rx: mpsc::Receiver<ConfigMutation>,
        config_path: PathBuf,
        current: Config,
        history_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            rx,
            config_path,
            current,
            history_dir,
        }
    }

    pub async fn run(mut self) {
        // Record the boot-time config as the newest history entry so the
        // first-ever rollback can restore what was running before the first
        // apply. Content-hash dedup keeps restarts from growing history.
        // Serialize the already-validated runtime snapshot. Re-reading the
        // source here would create a validation-to-read race if an operator
        // edits the file between startup validation and this task starting.
        self.record_current_history();
        while let Some(mutation) = self.rx.recv().await {
            if let ConfigMutation::ReplaceConfigAck(new_config, ack) = mutation {
                let previous = self.current.clone();
                info!("replacing persister config snapshot and persisting it");
                self.current = *new_config;
                let result = self.persist().map_err(|e| e.to_string());
                if let Err(e) = &result {
                    self.current = previous;
                    error!(
                        path = %self.config_path.display(),
                        error = %e,
                        "failed to persist config — persister snapshot rolled back to previous state"
                    );
                }
                let _ = ack.send(result);
                continue;
            }

            let should_persist = self.apply(mutation);
            if should_persist && let Err(e) = self.persist() {
                error!(
                    path = %self.config_path.display(),
                    error = %e,
                    "failed to persist config — in-memory state diverges from disk"
                );
            }
        }
    }

    fn apply(&mut self, mutation: ConfigMutation) -> bool {
        match mutation {
            ConfigMutation::AddNeighbor(neighbor) => {
                if self
                    .current
                    .neighbors
                    .iter()
                    .any(|n| n.address == neighbor.address)
                {
                    warn!(
                        address = %neighbor.address,
                        "neighbor already exists in persisted config, skipping"
                    );
                } else {
                    info!(address = %neighbor.address, "persisting added neighbor");
                    self.current.neighbors.push(*neighbor);
                }
                true
            }
            ConfigMutation::DeleteNeighbor(address) => {
                let addr_str = address.to_string();
                let before = self.current.neighbors.len();
                self.current.neighbors.retain(|n| n.address != addr_str);
                if self.current.neighbors.len() < before {
                    info!(%address, "persisting deleted neighbor");
                }
                true
            }
            ConfigMutation::ReplaceConfig(new_config) => {
                info!("replacing persister config snapshot and persisting it");
                self.current = *new_config;
                true
            }
            ConfigMutation::ReplaceConfigAck(new_config, _) => {
                info!("replacing persister config snapshot and persisting it");
                self.current = *new_config;
                true
            }
            ConfigMutation::RefreshSnapshotNoPersist(new_config) => {
                info!("refreshing persister config snapshot without writing to disk");
                self.current = *new_config;
                // The operator already persisted and successfully reloaded
                // this desired config. Record the validated snapshot without
                // writing it back: otherwise history index 0 still names the
                // pre-SIGHUP config and `rollback 1` cannot restore it.
                self.record_current_history();
                false
            }
        }
    }

    fn persist(&self) -> std::io::Result<()> {
        let toml_str = toml::to_string_pretty(&self.current).map_err(std::io::Error::other)?;

        // Durable atomic write: temp file → fsync → rename → fsync parent dir.
        // Reuses the commit-confirm journal's proven primitive so a crash in the
        // settle window can never leave a torn/zero-length config (LAN-206).
        crate::confirm_journal::write_atomic(&self.config_path, toml_str.as_bytes())?;
        // Every durable config write funnels through this method, so recording
        // here gives the applied-config history exactly one choke point:
        // transaction commits, gRPC CRUD mutations, and boot all land in it.
        self.record_history(&toml_str);
        Ok(())
    }

    /// Best-effort applied-config history recording. A history failure must
    /// never fail the persist that already succeeded — the config on disk is
    /// authoritative; history is the rollback convenience layer.
    fn record_history(&self, toml_str: &str) {
        if let Some(dir) = &self.history_dir
            && let Err(error) = crate::config_history::record(dir, toml_str)
        {
            warn!(
                dir = %dir.display(),
                error = %error,
                "failed to record applied config in the config history"
            );
        }
    }

    fn record_current_history(&self) {
        match toml::to_string_pretty(&self.current) {
            Ok(toml_str) => self.record_history(&toml_str),
            Err(error) => warn!(
                error = %error,
                "failed to serialize the applied config for config history"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> Config {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
        toml::from_str(toml_str).unwrap()
    }

    fn test_neighbor(address: &str, asn: u32) -> Neighbor {
        Neighbor {
            address: address.to_string(),
            interface: None,
            remote_asn: asn,
            description: None,
            peer_group: None,
            hold_time: None,
            send_hold_time: None,
            slow_peer_threshold_pct: None,
            slow_peer_duration: None,
            slow_peer_isolation: None,
            max_prefixes: None,
            max_prefixes_ipv4: None,
            max_prefixes_ipv6: None,
            md5_password: None,
            tcp_ao: None,
            bfd: None,
            ttl_security: Some(false),
            families: Vec::new(),
            graceful_restart: None,
            gr_restart_time: None,
            gr_stale_routes_time: None,
            llgr_stale_time: None,
            local_ipv6_nexthop: None,
            route_reflector_client: Some(false),
            orr_vantage: None,
            route_server_client: Some(false),
            per_client_best: Some(false),
            next_hop_ownership: None,
            interpret_rfc1997: None,
            rs_control_communities: None,
            role: None,
            strict_role: None,
            prefix_orf_receive: None,
            disable_ipv4_unicast: None,
            remove_private_as: None,
            add_path: None,
            import_policy: Vec::new(),
            export_policy: Vec::new(),
            import_policy_chain: Vec::new(),
            export_policy_chain: Vec::new(),
            log_level: None,
        }
    }

    #[tokio::test]
    async fn add_neighbor_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = minimal_config();
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (tx, rx) = mpsc::channel(16);
        let persister = ConfigPersister::new(rx, path.clone(), config, None);
        let handle = tokio::spawn(persister.run());

        tx.send(ConfigMutation::AddNeighbor(Box::new(test_neighbor(
            "10.0.0.2", 65002,
        ))))
        .await
        .unwrap();
        drop(tx);
        handle.await.unwrap();

        let reloaded: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(reloaded.neighbors.len(), 1);
        assert_eq!(reloaded.neighbors[0].address, "10.0.0.2");
        assert_eq!(reloaded.neighbors[0].remote_asn, 65002);
    }

    #[tokio::test]
    async fn delete_neighbor_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let mut config = minimal_config();
        config.neighbors.push(test_neighbor("10.0.0.2", 65002));
        config.neighbors.push(test_neighbor("10.0.0.3", 65003));
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (tx, rx) = mpsc::channel(16);
        let persister = ConfigPersister::new(rx, path.clone(), config, None);
        let handle = tokio::spawn(persister.run());

        tx.send(ConfigMutation::DeleteNeighbor("10.0.0.2".parse().unwrap()))
            .await
            .unwrap();
        drop(tx);
        handle.await.unwrap();

        let reloaded: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(reloaded.neighbors.len(), 1);
        assert_eq!(reloaded.neighbors[0].address, "10.0.0.3");
    }

    #[tokio::test]
    async fn add_then_delete_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = minimal_config();
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (tx, rx) = mpsc::channel(16);
        let persister = ConfigPersister::new(rx, path.clone(), config, None);
        let handle = tokio::spawn(persister.run());

        tx.send(ConfigMutation::AddNeighbor(Box::new(test_neighbor(
            "10.0.0.2", 65002,
        ))))
        .await
        .unwrap();
        tx.send(ConfigMutation::DeleteNeighbor("10.0.0.2".parse().unwrap()))
            .await
            .unwrap();
        drop(tx);
        handle.await.unwrap();

        let reloaded: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(reloaded.neighbors.is_empty());
    }

    #[tokio::test]
    async fn persist_is_durable_atomic_write_no_temp_left() {
        // LAN-206: persist() must go through the fsync'd atomic-write primitive
        // and never leave a temp file lingering.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = minimal_config();
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (tx, rx) = mpsc::channel(16);
        let persister = ConfigPersister::new(rx, path.clone(), config, None);
        let handle = tokio::spawn(persister.run());
        tx.send(ConfigMutation::AddNeighbor(Box::new(test_neighbor(
            "10.0.0.2", 65002,
        ))))
        .await
        .unwrap();
        drop(tx);
        handle.await.unwrap();

        // write_atomic renames `<config>.tmp` into place — it must not survive.
        let mut temp = path.clone().into_os_string();
        temp.push(".tmp");
        assert!(
            !std::path::Path::new(&temp).exists(),
            "atomic write must not leave a temp file behind"
        );
        let reloaded: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(reloaded.neighbors.len(), 1);
        assert_eq!(reloaded.neighbors[0].address, "10.0.0.2");
    }

    #[tokio::test]
    async fn persister_records_history_at_boot_and_on_every_persist() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let history = dir.path().join("config-history");
        let config = minimal_config();
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (tx, rx) = mpsc::channel(16);
        let persister =
            ConfigPersister::new(rx, path.clone(), config.clone(), Some(history.clone()));
        let handle = tokio::spawn(persister.run());
        tx.send(ConfigMutation::AddNeighbor(Box::new(test_neighbor(
            "10.0.0.2", 65002,
        ))))
        .await
        .unwrap();
        drop(tx);
        handle.await.unwrap();

        // Boot config + mutated config = two entries, newest first, and the
        // newest entry is byte-for-byte the config the persister wrote.
        let entries = crate::config_history::list(&history).unwrap();
        assert_eq!(entries.len(), 2);
        let (_, newest) = crate::config_history::read_entry(&history, 0).unwrap();
        assert_eq!(newest, std::fs::read_to_string(&path).unwrap());
        let (_, previous) = crate::config_history::read_entry(&history, 1).unwrap();
        assert_eq!(previous, toml::to_string_pretty(&config).unwrap());

        // "Restart": a fresh persister over the same state boot-records the
        // unchanged config — dedup keeps history from growing.
        let restarted: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let (tx, rx) = mpsc::channel(16);
        let persister = ConfigPersister::new(rx, path.clone(), restarted, Some(history.clone()));
        let handle = tokio::spawn(persister.run());
        drop(tx);
        handle.await.unwrap();
        assert_eq!(crate::config_history::list(&history).unwrap().len(), 2);
    }

    /// Load-bearing SIGHUP-history proof: refreshing the validated desired
    /// snapshot without a daemon write must still make that snapshot the
    /// newest rollback entry. Removing the history record from
    /// `RefreshSnapshotNoPersist` leaves this list at one entry.
    #[test]
    fn refresh_snapshot_no_persist_records_validated_config_history() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let history = dir.path().join("config-history");
        let config = minimal_config();
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (_tx, rx) = mpsc::channel(1);
        let mut persister = ConfigPersister::new(rx, path, config, Some(history.clone()));
        persister.record_current_history();

        let mut refreshed = minimal_config();
        refreshed.neighbors.push(test_neighbor("10.0.0.2", 65002));
        assert!(
            !persister.apply(ConfigMutation::RefreshSnapshotNoPersist(Box::new(
                refreshed.clone()
            ),))
        );

        let entries = crate::config_history::list(&history).unwrap();
        assert_eq!(entries.len(), 2);
        let newest = crate::config_history::read(&entries[0]).unwrap();
        assert_eq!(newest, toml::to_string_pretty(&refreshed).unwrap());
    }

    #[tokio::test]
    async fn refresh_snapshot_no_persist_updates_base_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = minimal_config();
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let mut refreshed = config.clone();
        refreshed.neighbors.push(test_neighbor("10.0.0.2", 65002));

        let (tx, rx) = mpsc::channel(16);
        let persister = ConfigPersister::new(rx, path.clone(), config, None);
        let handle = tokio::spawn(persister.run());

        tx.send(ConfigMutation::RefreshSnapshotNoPersist(Box::new(
            refreshed,
        )))
        .await
        .unwrap();
        tx.send(ConfigMutation::AddNeighbor(Box::new(test_neighbor(
            "10.0.0.3", 65003,
        ))))
        .await
        .unwrap();
        drop(tx);
        handle.await.unwrap();

        let reloaded: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            reloaded.neighbors.len(),
            2,
            "later persisted mutation must build on the refreshed desired snapshot"
        );
        assert_eq!(reloaded.neighbors[0].address, "10.0.0.2");
        assert_eq!(reloaded.neighbors[1].address, "10.0.0.3");
    }
}
