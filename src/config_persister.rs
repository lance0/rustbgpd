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

use crate::config::{Config, Neighbor, persisted_config_document};

/// File under `runtime_state_dir` recording the config file's mtime as of the
/// daemon's last read or write of it.
///
/// `rbgp doctor`'s config-freshness check reads it to tell the daemon's own
/// canonical rewrite from an operator's editor; without it the check compares
/// against process start and warns forever after the first runtime mutation.
/// The reader is `crates/cli/src/commands/doctor.rs` — keep the name in step.
pub const LAST_PERSIST_FILE: &str = "config-last-persist";

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
    /// Durably stage a replacement snapshot without publishing it, then
    /// acknowledge whether the write can land. Every persistence failure an
    /// operator actually hits (unwritable directory, read-only mount, full
    /// filesystem) surfaces here, before the caller mutates any runtime state.
    ///
    /// Exactly one stage may be outstanding; a second replaces the first.
    StageConfigAck(Box<Config>, oneshot::Sender<Result<(), String>>),
    /// Publish the staged snapshot: rename it into place and adopt it.
    CommitStagedConfig(oneshot::Sender<Result<(), String>>),
    /// Drop the staged snapshot. The caller's runtime change did not land, so
    /// neither may the write.
    DiscardStagedConfig,
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
    /// `runtime_state_dir`, the home of the applied-config history
    /// (`config_history`) and the last-persist marker. `None` disables both
    /// (unit tests, embedders without a state dir).
    state_dir: Option<PathBuf>,
    /// Durably written but unpublished snapshot, awaiting commit or discard.
    staged: Option<(crate::confirm_journal::StagedWrite, Config, String)>,
}

impl ConfigPersister {
    pub fn new(
        rx: mpsc::Receiver<ConfigMutation>,
        config_path: PathBuf,
        current: Config,
        state_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            rx,
            config_path,
            current,
            state_dir,
            staged: None,
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
            match mutation {
                ConfigMutation::ReplaceConfigAck(new_config, ack) => {
                    self.discard_staged();
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
                ConfigMutation::StageConfigAck(new_config, ack) => {
                    let _ = ack.send(self.stage(*new_config).map_err(|e| e.to_string()));
                    continue;
                }
                ConfigMutation::CommitStagedConfig(ack) => {
                    let _ = ack.send(self.commit_staged());
                    continue;
                }
                ConfigMutation::DiscardStagedConfig => {
                    self.discard_staged();
                    continue;
                }
                _ => {}
            }

            // Any other durable write reuses the same temp path, so a stage
            // that is still outstanding here can no longer be published.
            self.discard_staged();
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

    /// Durably write a candidate next to the config file without publishing
    /// it. A failure here is the whole point of the two-phase handshake: the
    /// caller learns the write cannot land while its runtime state is still
    /// untouched.
    fn stage(&mut self, new_config: Config) -> std::io::Result<()> {
        // A superseded stage is discarded, never published: its caller either
        // failed its apply or is gone.
        self.discard_staged();
        let toml_str = persisted_config_document(&new_config).map_err(std::io::Error::other)?;
        let staged = crate::confirm_journal::stage_atomic(&self.config_path, toml_str.as_bytes())?;
        info!(
            path = %self.config_path.display(),
            "staged config write, awaiting commit"
        );
        self.staged = Some((staged, new_config, toml_str));
        Ok(())
    }

    /// Publish the staged candidate and adopt it as the persister snapshot.
    fn commit_staged(&mut self) -> Result<(), String> {
        let Some((staged, config, toml_str)) = self.staged.take() else {
            return Err("no staged config write to commit".to_string());
        };
        if let Err(error) = staged.commit() {
            error!(
                path = %self.config_path.display(),
                error = %error,
                "failed to publish the staged config write"
            );
            return Err(error.to_string());
        }
        self.current = config;
        self.record_history(&toml_str);
        Ok(())
    }

    fn discard_staged(&mut self) {
        if let Some((staged, ..)) = self.staged.take() {
            info!(
                path = %self.config_path.display(),
                "discarding the staged config write"
            );
            staged.discard();
        }
    }

    fn apply(&mut self, mutation: ConfigMutation) -> bool {
        match mutation {
            // Handled directly in `run`; a staging mutation never reaches the
            // single-phase applier.
            ConfigMutation::StageConfigAck(..)
            | ConfigMutation::CommitStagedConfig(_)
            | ConfigMutation::DiscardStagedConfig => false,
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
        let toml_str = persisted_config_document(&self.current).map_err(std::io::Error::other)?;

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

    /// Best-effort recording of an applied config: the rollback history entry
    /// and the last-persist marker.
    ///
    /// Both are best-effort by design. A failure here must never fail the
    /// persist that already succeeded — the config on disk is authoritative;
    /// history is the rollback convenience layer and the marker is a hint for
    /// `rbgp doctor`.
    ///
    /// Every point at which the daemon's view of the config file becomes
    /// current — boot, every durable write, and a SIGHUP snapshot refresh —
    /// already funnels here, which is why the marker is recorded here too
    /// rather than at each call site.
    fn record_history(&self, toml_str: &str) {
        self.record_last_persist();
        if let Some(dir) = self.history_dir()
            && let Err(error) = crate::config_history::record(&dir, toml_str)
        {
            warn!(
                dir = %dir.display(),
                error = %error,
                "failed to record applied config in the config history"
            );
        }
    }

    fn history_dir(&self) -> Option<PathBuf> {
        self.state_dir
            .as_deref()
            .map(crate::config_history::history_dir)
    }

    /// Record the config file's mtime as the daemon's own last-persist stamp.
    ///
    /// The value is the file's mtime rather than wall-clock now, so it
    /// compares byte-for-byte against the mtime `rbgp doctor` reads from the
    /// same file — no clock skew or rounding in between. A later external edit
    /// necessarily carries a higher mtime and still warns.
    fn record_last_persist(&self) {
        let Some(dir) = &self.state_dir else {
            return;
        };
        let Some(mtime) = std::fs::metadata(&self.config_path)
            .and_then(|meta| meta.modified())
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|since| since.as_secs())
        else {
            return;
        };
        let path = dir.join(LAST_PERSIST_FILE);
        // A plain write is enough: a torn or missing marker only degrades the
        // freshness check to comparing against process start, which is what it
        // did before the marker existed.
        if let Err(error) =
            std::fs::create_dir_all(dir).and_then(|()| std::fs::write(&path, format!("{mtime}\n")))
        {
            warn!(
                path = %path.display(),
                error = %error,
                "failed to record the config last-persist marker — `rbgp doctor` may report the daemon's own config write as an external edit"
            );
        }
    }

    fn record_current_history(&self) {
        match persisted_config_document(&self.current) {
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
            min_hold_time: None,
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
            max_prefixes_out_ipv4: None,
            max_prefixes_out_ipv6: None,
            max_prefix_restart_seconds: None,
            md5_password: None,
            tcp_ao: None,
            bfd: None,
            ttl_security: Some(false),
            families: Vec::new(),
            required_families: Vec::new(),
            graceful_restart: None,
            gr_restart_time: None,
            gr_peer_restart_time_max: None,
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
        let state_dir = dir.path().to_path_buf();
        let history = crate::config_history::history_dir(&state_dir);
        let config = minimal_config();
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (tx, rx) = mpsc::channel(16);
        let persister =
            ConfigPersister::new(rx, path.clone(), config.clone(), Some(state_dir.clone()));
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
        assert_eq!(previous, persisted_config_document(&config).unwrap());

        // "Restart": a fresh persister over the same state boot-records the
        // unchanged config — dedup keeps history from growing.
        let restarted: Config = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let (tx, rx) = mpsc::channel(16);
        let persister = ConfigPersister::new(rx, path.clone(), restarted, Some(state_dir.clone()));
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
        let state_dir = dir.path().to_path_buf();
        let history = crate::config_history::history_dir(&state_dir);
        let config = minimal_config();
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (_tx, rx) = mpsc::channel(1);
        let mut persister = ConfigPersister::new(rx, path, config, Some(state_dir));
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
        assert_eq!(newest, persisted_config_document(&refreshed).unwrap());
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

    /// The first runtime mutation rewrites the operator's file canonically:
    /// their comments, their key order, and any posture banner they wrote are
    /// gone. The file has to say so itself — and say it exactly once, however
    /// many times it is rewritten.
    #[tokio::test]
    async fn persisted_config_carries_exactly_one_maintenance_header() {
        use crate::config::PERSISTED_CONFIG_HEADER;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let config = minimal_config();
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (tx, rx) = mpsc::channel(16);
        let persister = ConfigPersister::new(rx, path.clone(), config, None);
        let handle = tokio::spawn(persister.run());
        // Two durable writes, so a second header would have somewhere to land.
        tx.send(ConfigMutation::AddNeighbor(Box::new(test_neighbor(
            "10.0.0.2", 65002,
        ))))
        .await
        .unwrap();
        tx.send(ConfigMutation::AddNeighbor(Box::new(test_neighbor(
            "10.0.0.3", 65003,
        ))))
        .await
        .unwrap();
        drop(tx);
        handle.await.unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(
            written.starts_with(PERSISTED_CONFIG_HEADER),
            "the header must be the first lines of the file, got:\n{written}"
        );
        assert_eq!(
            written.matches(PERSISTED_CONFIG_HEADER).count(),
            1,
            "persisting twice must leave exactly one header, got:\n{written}"
        );
    }

    /// A persisted file is a file the daemon must be able to boot from: it
    /// loads through the same gate `rustbgpd --check` uses, and persisting it
    /// again is byte-identical — the header does not accumulate and the body
    /// does not drift.
    #[tokio::test]
    async fn persisted_config_round_trips_through_load_and_persist() {
        use crate::config::PERSISTED_CONFIG_HEADER;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // A config the daemon would really boot from: full validation, not
        // bare deserialization, so the reload below exercises the same gate
        // `rustbgpd --check` runs.
        std::fs::write(
            &path,
            crate::test_support::tier_authorized_uds_test_config(
                r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#,
            ),
        )
        .unwrap();
        let config = Config::load_with_diagnostics(path.to_str().unwrap()).unwrap();

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
        let first = std::fs::read_to_string(&path).unwrap();

        // `--check` and daemon boot both start here; a header that broke
        // parsing would fail this line.
        let reloaded = Config::load_with_diagnostics(path.to_str().unwrap())
            .expect("a persisted config must load through the daemon's own gate");

        // Restart over the persisted file and persist it again unchanged.
        let (tx, rx) = mpsc::channel(16);
        let persister = ConfigPersister::new(rx, path.clone(), reloaded.clone(), None);
        let handle = tokio::spawn(persister.run());
        tx.send(ConfigMutation::ReplaceConfig(Box::new(reloaded)))
            .await
            .unwrap();
        drop(tx);
        handle.await.unwrap();
        let second = std::fs::read_to_string(&path).unwrap();

        assert_eq!(
            first, second,
            "load → persist must not drift the persisted document"
        );
        assert_eq!(second.matches(PERSISTED_CONFIG_HEADER).count(), 1);
    }

    /// `rbgp doctor` needs to tell the daemon's own canonical rewrite from an
    /// operator's editor. The marker is that evidence: after a daemon write it
    /// holds the config file's own mtime, so the freshness check reads equal
    /// (clean) rather than greater (a pending external edit).
    #[tokio::test]
    async fn last_persist_marker_records_the_config_file_mtime() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let state_dir = dir.path().join("state");
        let config = minimal_config();
        std::fs::write(&path, toml::to_string_pretty(&config).unwrap()).unwrap();

        let (tx, rx) = mpsc::channel(16);
        let persister = ConfigPersister::new(rx, path.clone(), config, Some(state_dir.clone()));
        let handle = tokio::spawn(persister.run());
        tx.send(ConfigMutation::AddNeighbor(Box::new(test_neighbor(
            "10.0.0.2", 65002,
        ))))
        .await
        .unwrap();
        drop(tx);
        handle.await.unwrap();

        let recorded: u64 = std::fs::read_to_string(state_dir.join(LAST_PERSIST_FILE))
            .expect("a durable write must record the last-persist marker")
            .trim()
            .parse()
            .expect("the marker holds unix seconds");
        let mtime = std::fs::metadata(&path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert_eq!(
            recorded, mtime,
            "the marker must hold the mtime of the file the daemon just wrote, \
             or doctor reads the daemon's own write as an external edit"
        );
    }
}
