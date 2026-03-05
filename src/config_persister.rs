//! Persists config mutations to disk.
//!
//! Runs as a single tokio task, receiving mutations via an mpsc channel.
//! Each mutation is applied to the in-memory config, serialized to TOML,
//! and atomically written (temp file + rename) to the config path.

#![deny(unsafe_code)]

use std::net::IpAddr;
use std::path::PathBuf;

use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::{Config, Neighbor};

/// A mutation to apply to the persisted config.
pub enum ConfigMutation {
    AddNeighbor(Box<Neighbor>),
    DeleteNeighbor(IpAddr),
    /// Replace the entire config snapshot (e.g. after SIGHUP reload).
    ReplaceConfig(Box<Config>),
}

/// Listens for config mutations and persists them atomically.
pub struct ConfigPersister {
    rx: mpsc::Receiver<ConfigMutation>,
    config_path: PathBuf,
    current: Config,
}

impl ConfigPersister {
    pub fn new(rx: mpsc::Receiver<ConfigMutation>, config_path: PathBuf, current: Config) -> Self {
        Self {
            rx,
            config_path,
            current,
        }
    }

    pub async fn run(mut self) {
        while let Some(mutation) = self.rx.recv().await {
            self.apply(mutation);
            if let Err(e) = self.persist() {
                error!(
                    path = %self.config_path.display(),
                    error = %e,
                    "failed to persist config — in-memory state diverges from disk"
                );
            }
        }
    }

    fn apply(&mut self, mutation: ConfigMutation) {
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
            }
            ConfigMutation::DeleteNeighbor(address) => {
                let addr_str = address.to_string();
                let before = self.current.neighbors.len();
                self.current.neighbors.retain(|n| n.address != addr_str);
                if self.current.neighbors.len() < before {
                    info!(%address, "persisting deleted neighbor");
                }
            }
            ConfigMutation::ReplaceConfig(new_config) => {
                info!("replacing persister config snapshot (e.g. after SIGHUP reload)");
                self.current = *new_config;
            }
        }
    }

    fn persist(&self) -> std::io::Result<()> {
        let toml_str = toml::to_string_pretty(&self.current).map_err(std::io::Error::other)?;

        // Atomic write: write to temp file, then rename
        let temp_path = self.config_path.with_extension("toml.tmp");
        std::fs::write(&temp_path, &toml_str)?;
        std::fs::rename(&temp_path, &self.config_path)?;

        Ok(())
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
            remote_asn: asn,
            description: None,
            hold_time: None,
            max_prefixes: None,
            md5_password: None,
            ttl_security: false,
            families: Vec::new(),
            graceful_restart: None,
            gr_restart_time: None,
            gr_stale_routes_time: None,
            llgr_stale_time: None,
            local_ipv6_nexthop: None,
            route_reflector_client: false,
            route_server_client: false,
            remove_private_as: None,
            add_path: None,
            import_policy: Vec::new(),
            export_policy: Vec::new(),
            import_policy_chain: Vec::new(),
            export_policy_chain: Vec::new(),
        }
    }

    #[tokio::test]
    async fn add_neighbor_persists_to_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = minimal_config();
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (tx, rx) = mpsc::channel(16);
        let persister = ConfigPersister::new(rx, path.clone(), config);
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
        let persister = ConfigPersister::new(rx, path.clone(), config);
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
        let persister = ConfigPersister::new(rx, path.clone(), config);
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
}
