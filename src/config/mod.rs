pub mod diagnostic;
mod parse;
pub mod profiles;
mod schema;
mod validation;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::path::PathBuf;
use std::sync::Arc;

use rustbgpd_evpn::{
    BridgeVlan, DfAlgorithm, DuplicateMacAction, DuplicateMacConfig, EthernetSegment, EvpnInstance,
    EvpnInstanceId, EvpnInstanceTable, EvpnRuntimeCandidate, EvpnRuntimeModel, EvpnRuntimePlan,
    IpVrf, IpVrfId, IpVrfTable, OverlayIndexMode, RedundancyMode, RouteTarget,
};
use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::{
    CommunityMatch, NamedPolicy, NextHopAction, Policy, PolicyAction, PolicyChain, PolicyStatement,
    RouteModifications, parse_community_match,
};
// ADR-0112 reserved chain names live in the policy crate so the daemon, the
// RIB's export explain, and the CLI all test the same identity.
pub use rustbgpd_policy::{RFC8212_MISSING_EXPORT_POLICY, RFC8212_MISSING_IMPORT_POLICY};
use rustbgpd_transport::{
    RemovePrivateAs, TcpAoAlgorithm, TcpAoConfig as TransportTcpAoConfig, TcpAoKeyring,
    TransportConfig,
};
use rustbgpd_wire::{
    Afi, EthernetSegmentIdentifier, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, LargeCommunity,
    MacAddress, Prefix, RouteDistinguisher, Safi,
};

pub use schema::*;
pub(crate) use validation::{effective_prefix, effective_prefix_str};

use self::parse::{ChainDirection, parse_families, parse_policy, resolve_chain};
use self::schema::{
    BGP_PORT, DEFAULT_CONNECT_RETRY_SECS, DEFAULT_DYNAMIC_NEIGHBOR_LIMIT, DEFAULT_HOLD_TIME,
};

#[cfg(test)]
use self::parse::parse_named_policy;

#[derive(Clone, Copy)]
enum DatasetBindMode {
    Apply,
    Stage,
}

pub(crate) struct StagedDatasetCommit {
    updates: Vec<StagedDatasetUpdate>,
}

enum StagedDatasetUpdate {
    Refresh {
        handle: Arc<rustbgpd_policy::datasets::DatasetHandle>,
        data: rustbgpd_policy::datasets::DatasetData,
    },
    Failure {
        handle: Arc<rustbgpd_policy::datasets::DatasetHandle>,
        reason: String,
    },
}

impl StagedDatasetCommit {
    pub(crate) fn is_empty(&self) -> bool {
        self.updates.is_empty()
    }

    pub(crate) fn commit(self) {
        for update in self.updates {
            match update {
                StagedDatasetUpdate::Refresh { handle, data } => {
                    if let Some(generation) = handle.refresh(data) {
                        tracing::info!(
                            dataset = %handle.name(),
                            %generation,
                            "dataset content swapped; scoped peer refresh follows"
                        );
                    }
                }
                StagedDatasetUpdate::Failure { handle, reason } => {
                    tracing::warn!(
                        dataset = %handle.name(),
                        error = %reason,
                        "dataset refresh failed; retaining prior snapshot"
                    );
                    handle.record_error(reason);
                }
            }
        }
    }
}

impl Config {
    fn interface_index(interface: &str) -> Result<u32, String> {
        nix::net::if_::if_nametoindex(interface)
            .map_err(|err| format!("interface {interface:?} does not exist or is invalid: {err}"))
    }

    fn load_from_toml_source(
        content: &str,
        source_name: &str,
        base_dir: Option<&std::path::Path>,
    ) -> Result<Self, String> {
        Self::load_from_toml_source_with_datasets(
            content,
            source_name,
            base_dir,
            None,
            DatasetBindMode::Apply,
        )
    }

    fn load_from_toml_source_with_datasets(
        content: &str,
        source_name: &str,
        base_dir: Option<&std::path::Path>,
        prior_datasets: Option<&rustbgpd_policy::datasets::DatasetBindings>,
        dataset_bind_mode: DatasetBindMode,
    ) -> Result<Self, String> {
        let mut config: Config = match toml::from_str(content) {
            Ok(c) => c,
            Err(e) => {
                // Retired keys reject as unknown fields; replace the bare
                // serde diagnostic with a migration pointer when one is
                // responsible for the failure.
                if let Some(migration) = retired_key_error(content) {
                    return Err(migration);
                }
                let error = ConfigError::Parse(e);
                return Err(diagnostic::render_diagnostic(content, source_name, &error)
                    .unwrap_or_else(|| format!("error: {error}")));
            }
        };
        // Compile referenced .rpol files before validation: chain
        // references resolve against the combined TOML + rpol policy
        // namespace, and rpol compile diagnostics (already
        // ariadne-rendered against the .rpol source) are config load
        // errors in their own right.
        if let Err(error) = config.load_rpol_files(base_dir) {
            return Err(match &error {
                ConfigError::InvalidRpolFile { .. } => format!("error: {error}"),
                other => diagnostic::render_diagnostic(content, source_name, other)
                    .unwrap_or_else(|| format!("error: {other}")),
            });
        }
        // Bind dataset declarations to their snapshot files (LAN-305)
        // before validation: chain references probe datasets, so the
        // resolver needs the handles. With `prior_datasets` (the
        // SIGHUP reload path) existing handles are reused — content
        // swaps happen inside them and a failed refresh keeps the
        // prior snapshot instead of failing the load.
        if let Err(error) = config.bind_datasets(base_dir, prior_datasets, dataset_bind_mode) {
            return Err(format!("error: {error}"));
        }
        if let Err(error) = config.validate() {
            return Err(diagnostic::render_diagnostic(content, source_name, &error)
                .unwrap_or_else(|| format!("error: {error}")));
        }
        Ok(config)
    }

    /// Read, parse, and typecheck every `[policy] rpol_files` entry
    /// (ADR-0096), populating the compiled registry and rewriting
    /// relative paths to absolute against `base_dir` (the config
    /// file's directory when known, the process working directory
    /// otherwise). Name collisions — with `[policy.definitions]` or
    /// across `.rpol` files — are load errors naming both sources.
    ///
    /// Path resolution is deliberately **not** confined to `base_dir`.
    /// `rpol_files` is an operator-authored include directive — the same
    /// trust model as an nginx `include` or a systemd drop-in: whoever
    /// writes the on-disk config is the trusted host operator, and
    /// absolute paths (`/etc/rbgp/policies/common.rpol`) and
    /// parent-relative references into a shared policy library are
    /// legitimate and expected. There is therefore no `..`/symlink
    /// *confinement*: a `base.join(entry)` that escapes `base_dir` is
    /// intended behavior, not a traversal to reject. Each entry is,
    /// however, `canonicalize()`d immediately before it is read
    /// (LAN-218), closing the symlink TOCTOU window between path
    /// resolution and open — canonicalization resolves the target, it
    /// does not confine it. (Untrusted candidate configs arrive via
    /// `load_toml_with_diagnostics` with `base_dir = None`, so relative
    /// entries resolve against the process CWD and never against a
    /// caller-influenced base.)
    ///
    /// In-language `import` declarations (LAN-300) are the opposite:
    /// they are transitive rather than operator-listed, so they ARE
    /// confined — every import must resolve inside the importing
    /// entry's directory or a configured `[policy] rpol_roots` entry
    /// (enforced by `RpolFile::load`).
    fn load_rpol_files(&mut self, base_dir: Option<&std::path::Path>) -> Result<(), ConfigError> {
        use rustbgpd_policy::rpol::{LoadError, RpolFile, RpolPolicyEntry};

        // Policy roots for `import` resolution (LAN-300): absolutize
        // against the config directory and rewrite, like `rpol_files`.
        for root in &mut self.policy.rpol_roots {
            let mut path = PathBuf::from(&*root);
            if path.is_relative()
                && let Some(base) = base_dir
            {
                path = base.join(path);
            }
            *root = path.display().to_string();
        }
        let roots: Vec<PathBuf> = self.policy.rpol_roots.iter().map(PathBuf::from).collect();

        let mut owner_by_name: HashMap<String, String> = HashMap::new();
        for entry in &mut self.policy.rpol_files {
            let mut path = PathBuf::from(&*entry);
            if path.is_relative()
                && let Some(base) = base_dir
            {
                path = base.join(path);
            }
            let display = path.display().to_string();
            // `RpolFile::load` canonicalizes before reading (LAN-218):
            // symlinks and `..` resolve once, then that resolved path
            // is read (closes the symlink TOCTOU window). It also
            // resolves the file's `import` graph against `roots`
            // (LAN-300) as one compilation unit — a missing or broken
            // import anywhere rejects the whole load.
            let file = match RpolFile::load(&path, &roots) {
                Ok(file) => Arc::new(file),
                Err(LoadError::Io { path, reason }) => {
                    return Err(ConfigError::InvalidRpolFile { path, reason });
                }
                Err(error @ LoadError::Compile { .. }) => {
                    return Err(ConfigError::InvalidRpolFile {
                        path: display.clone(),
                        reason: format!("compile failed\n{}", error.render(false)),
                    });
                }
            };
            for (name, params) in file.policies() {
                if self.policy.definitions.contains_key(name) {
                    return Err(ConfigError::InvalidRpolFile {
                        path: display.clone(),
                        reason: format!(
                            "policy {name:?} is already defined in [policy.definitions.{name}]; \
                             rpol and TOML policies share one namespace"
                        ),
                    });
                }
                if let Some(previous) = owner_by_name.get(name) {
                    return Err(ConfigError::InvalidRpolFile {
                        path: display.clone(),
                        reason: format!("policy {name:?} is already defined in {previous:?}"),
                    });
                }
                owner_by_name.insert(name.to_string(), display.clone());
                self.policy.rpol.policies.insert(
                    name.to_string(),
                    RpolPolicyEntry {
                        file: Arc::clone(&file),
                        params,
                        path: display.clone(),
                    },
                );
            }
            *entry = display;
        }
        Ok(())
    }

    /// Bind every `dataset` declared across the loaded `.rpol` units
    /// to its `[policy.datasets]` snapshot file (LAN-305), populating
    /// `policy.dataset_bindings` and `policy.dataset_events`.
    ///
    /// Validation (all load errors): kind agreement when two units
    /// declare the same name, a `[policy.datasets]` entry for every
    /// declaration, and a declaration for every entry. Loading:
    /// declared datasets with a kind-matching handle in `prior` reuse
    /// it — fresh content swaps atomically inside the handle
    /// (generation bump, recorded in `dataset_events.swapped`),
    /// content-equal files are no-ops, and a load/parse failure keeps
    /// the prior snapshot with the error recorded on the handle and in
    /// `dataset_events.failed` (never empty data — ADR-0103 Decision
    /// 8.5). Datasets with no prior handle (initial load, new
    /// declarations, kind changes) must load cleanly or the whole load
    /// fails — introducing a dataset is a config transaction.
    #[expect(
        clippy::too_many_lines,
        reason = "declaration collection, two-way coverage checks, and the load/refresh state machine in one linear pass"
    )]
    fn bind_datasets(
        &mut self,
        base_dir: Option<&std::path::Path>,
        prior: Option<&rustbgpd_policy::datasets::DatasetBindings>,
        mode: DatasetBindMode,
    ) -> Result<(), ConfigError> {
        use rustbgpd_policy::datasets::{DatasetHandle, DatasetKind, load_dataset_file};

        // Declarations across every loaded unit: name → (kind, owner
        // path), kind conflicts rejected. Iterate registry entries
        // deduped by owning file (entries share `Arc<RpolFile>`).
        let mut declared: HashMap<String, (DatasetKind, String)> = HashMap::new();
        let mut seen_files: Vec<*const rustbgpd_policy::rpol::RpolFile> = Vec::new();
        for entry in self.policy.rpol.policies.values() {
            let ptr = Arc::as_ptr(&entry.file);
            if seen_files.contains(&ptr) {
                continue;
            }
            seen_files.push(ptr);
            for (name, kind) in entry.file.dataset_decls() {
                match declared.get(name) {
                    Some((existing, owner)) if *existing != kind => {
                        return Err(ConfigError::InvalidPolicyEntry {
                            reason: format!(
                                "dataset {name:?} is declared as {existing} in {owner:?} but as                                  {kind} in {:?}; dataset kinds are daemon-global",
                                entry.path
                            ),
                        });
                    }
                    Some(_) => {}
                    None => {
                        declared.insert(name.to_string(), (kind, entry.path.clone()));
                    }
                }
            }
        }

        // Both directions of declaration ↔ binding coverage.
        for (name, (_, owner)) in &declared {
            if !self.policy.datasets.contains_key(name) {
                return Err(ConfigError::InvalidPolicyEntry {
                    reason: format!(
                        "dataset {name:?} (declared in {owner:?}) has no [policy.datasets.{name}] entry naming its snapshot file"
                    ),
                });
            }
        }
        for name in self.policy.datasets.keys() {
            if !declared.contains_key(name) {
                return Err(ConfigError::InvalidPolicyEntry {
                    reason: format!(
                        "[policy.datasets.{name}] does not match any `dataset` declaration in the loaded rpol files — remove the entry or declare the dataset"
                    ),
                });
            }
        }

        // Absolutize + rewrite paths like `rpol_files`.
        for entry in self.policy.datasets.values_mut() {
            let mut path = PathBuf::from(&entry.path);
            if path.is_relative()
                && let Some(base) = base_dir
            {
                path = base.join(path);
            }
            entry.path = path.display().to_string();
        }

        // Load / refresh, deterministically ordered for stable logs.
        let mut names: Vec<&String> = declared.keys().collect();
        names.sort();
        for name in names {
            let (kind, _) = declared[name.as_str()];
            let path = PathBuf::from(&self.policy.datasets[name.as_str()].path);
            let existing = prior
                .and_then(|bindings| bindings.get(name))
                .filter(|handle| handle.kind() == kind);
            match (existing, load_dataset_file(&path, kind), mode) {
                (Some(handle), Ok(data), DatasetBindMode::Stage) => {
                    if handle.pin().data != data {
                        self.policy.dataset_events.swapped.push(name.clone());
                    }
                    // Validate the candidate against its proposed snapshot,
                    // but do not mutate the live handle until the complete
                    // reload preflight has passed.
                    self.policy
                        .dataset_bindings
                        .insert(Arc::new(DatasetHandle::new(name, kind, data)));
                }
                (Some(handle), Err(reason), DatasetBindMode::Stage) => {
                    // A failed reload read retains the prior snapshot. Defer
                    // recording the operational error on the live handle too:
                    // an otherwise rejected config must have no side effects.
                    self.policy
                        .dataset_events
                        .failed
                        .push((name.clone(), reason));
                    self.policy.dataset_bindings.insert(Arc::clone(handle));
                }
                (Some(handle), Ok(data), DatasetBindMode::Apply) => {
                    if let Some(generation) = handle.refresh(data) {
                        tracing::info!(
                            dataset = %name,
                            %generation,
                            "dataset content swapped; scoped peer refresh follows"
                        );
                        self.policy.dataset_events.swapped.push(name.clone());
                    }
                    self.policy.dataset_bindings.insert(Arc::clone(handle));
                }
                (Some(handle), Err(reason), DatasetBindMode::Apply) => {
                    // Keep the prior snapshot serving probes; surface
                    // the failure (WARN here, counter + `rbgp policy
                    // stats` via the recorded error).
                    tracing::warn!(
                        dataset = %name,
                        error = %reason,
                        "dataset refresh failed; retaining prior snapshot"
                    );
                    handle.record_error(reason.clone());
                    self.policy
                        .dataset_events
                        .failed
                        .push((name.clone(), reason));
                    self.policy.dataset_bindings.insert(Arc::clone(handle));
                }
                (None, Ok(data), _) => {
                    self.policy
                        .dataset_bindings
                        .insert(Arc::new(DatasetHandle::new(name, kind, data)));
                }
                (None, Err(reason), _) => {
                    return Err(ConfigError::InvalidPolicyEntry {
                        reason: format!(
                            "dataset {name:?}: cannot load {}: {reason}",
                            path.display()
                        ),
                    });
                }
            }
        }
        Ok(())
    }

    /// Load config from TOML text and render diagnostics against `source_name`.
    ///
    /// Used by read-only API surfaces that receive candidate config
    /// content instead of a filesystem path. The returned config does
    /// not expose a `file_path`.
    pub fn load_toml_with_diagnostics(content: &str, source_name: &str) -> Result<Self, String> {
        // No config-file directory here: relative `rpol_files` paths
        // resolve against the process working directory. Initial load
        // rewrites them absolute, so snapshots / candidates derived
        // from a running config are unaffected.
        Self::load_from_toml_source(content, source_name, None)
    }

    /// Load config and, on failure, render a diagnostic with source context.
    ///
    /// Returns the rendered diagnostic string on error (suitable for direct
    /// printing to stderr). Falls back to plain `Display` if no source span
    /// can be determined.
    pub fn load_with_diagnostics(path: &str) -> Result<Self, String> {
        Self::load_with_diagnostics_and_datasets(path, None)
    }

    /// [`Self::load_with_diagnostics`] carrying the running config's
    /// dataset bindings (LAN-305) — the SIGHUP reload entry point.
    /// Declared datasets reuse the running handles: unchanged content
    /// is a no-op, changed content swaps in place (generation bump,
    /// recorded in `policy.dataset_events.swapped`), and a file that
    /// fails to load/parse keeps the prior snapshot with the error
    /// recorded instead of rejecting the reload.
    pub fn load_with_diagnostics_and_datasets(
        path: &str,
        prior_datasets: Option<&rustbgpd_policy::datasets::DatasetBindings>,
    ) -> Result<Self, String> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => return Err(format!("error: failed to read {path}: {e}")),
        };
        let base_dir = std::path::Path::new(path).parent().map(PathBuf::from);
        let mut config = Self::load_from_toml_source_with_datasets(
            &content,
            path,
            base_dir.as_deref(),
            prior_datasets,
            DatasetBindMode::Apply,
        )?;
        config.file_path = Some(PathBuf::from(path));
        Ok(config)
    }

    /// Load a reload candidate against the running dataset snapshots without
    /// mutating their shared handles. Call [`Self::prepare_staged_datasets`]
    /// after every no-side-effect reload preflight has passed, then commit the
    /// returned plan at the ordered dataset reconciliation step.
    pub(crate) fn load_with_diagnostics_and_staged_datasets(
        path: &str,
        prior_datasets: &rustbgpd_policy::datasets::DatasetBindings,
    ) -> Result<Self, String> {
        let content = std::fs::read_to_string(path)
            .map_err(|error| format!("error: failed to read {path}: {error}"))?;
        let base_dir = std::path::Path::new(path).parent().map(PathBuf::from);
        let mut config = Self::load_from_toml_source_with_datasets(
            &content,
            path,
            base_dir.as_deref(),
            Some(prior_datasets),
            DatasetBindMode::Stage,
        )?;
        config.file_path = Some(PathBuf::from(path));
        Ok(config)
    }

    /// Rewrite staged bindings to stable running-handle identities and return
    /// the still-unapplied content/error changes. The caller commits the plan
    /// only after earlier fallible reload reconciliation has succeeded.
    pub(crate) fn prepare_staged_datasets(
        &mut self,
        prior: &rustbgpd_policy::datasets::DatasetBindings,
    ) -> StagedDatasetCommit {
        use rustbgpd_policy::datasets::DatasetBindings;

        let failed: HashMap<&str, &str> = self
            .policy
            .dataset_events
            .failed
            .iter()
            .map(|(name, reason)| (name.as_str(), reason.as_str()))
            .collect();
        let mut committed = DatasetBindings::new();
        let mut staged_handles: Vec<_> = self.policy.dataset_bindings.handles().cloned().collect();
        staged_handles.sort_by(|left, right| left.name().cmp(right.name()));
        let mut updates = Vec::new();
        for staged in staged_handles {
            let Some(live) = prior
                .get(staged.name())
                .filter(|live| live.kind() == staged.kind())
            else {
                committed.insert(staged);
                continue;
            };
            if let Some(reason) = failed.get(staged.name().as_ref()) {
                updates.push(StagedDatasetUpdate::Failure {
                    handle: Arc::clone(live),
                    reason: (*reason).to_string(),
                });
            } else {
                let data = staged.pin().data.clone();
                let content_changed = live.pin().data != data;
                let clears_error = live.status().last_error.is_some();
                if content_changed || clears_error {
                    updates.push(StagedDatasetUpdate::Refresh {
                        handle: Arc::clone(live),
                        data,
                    });
                }
            }
            committed.insert(Arc::clone(live));
        }
        self.policy.dataset_bindings = committed;
        StagedDatasetCommit { updates }
    }

    pub fn prometheus_addr(&self) -> Option<SocketAddr> {
        self.global
            .telemetry
            .prometheus_addr
            .as_ref()
            .map(|s| s.parse().expect("validated in Config::load"))
    }

    pub fn listen_addr(&self) -> SocketAddr {
        SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            self.global.listen_port,
        )
    }

    /// Resolve the configured gRPC listeners.
    ///
    /// If neither TCP nor UDS is configured explicitly, a secure local-only UDS
    /// listener is enabled at `<runtime_state_dir>/grpc.sock`.
    pub fn grpc_listeners(&self) -> Vec<GrpcListener> {
        let telemetry = &self.global.telemetry;
        let tcp = telemetry.grpc_tcp.as_ref().filter(|cfg| cfg.enabled);
        let uds = telemetry.grpc_uds.as_ref().filter(|cfg| cfg.enabled);

        if tcp.is_none() && uds.is_none() {
            return vec![GrpcListener::Uds {
                path: self.default_grpc_uds_path(),
                mode: 0o600,
                access_mode: GrpcAccessMode::ReadWrite,
                max_tier: GrpcMaxTier::OperatorOnly,
                token_file: None,
                principal: None,
            }];
        }

        let mut listeners = Vec::new();
        if let Some(cfg) = tcp {
            let addr = cfg
                .address
                .as_ref()
                .expect("validated in Config::load")
                .parse()
                .expect("validated in Config::load");
            let tls = match (
                cfg.tls_cert_file.as_ref(),
                cfg.tls_key_file.as_ref(),
                cfg.tls_client_ca_file.as_ref(),
            ) {
                (Some(cert), Some(key), Some(ca)) => Some(GrpcTlsPaths {
                    cert_file: PathBuf::from(cert),
                    key_file: PathBuf::from(key),
                    client_ca_file: PathBuf::from(ca),
                }),
                // Partial TLS config rejected at Config::load via
                // validate_grpc_tls_config(); the all-None and
                // any-partial cases both resolve to no-TLS here.
                _ => None,
            };
            let access_mode = cfg
                .access_mode
                .map_or(GrpcAccessMode::ReadWrite, Into::into);
            listeners.push(GrpcListener::Tcp {
                addr,
                access_mode,
                max_tier: effective_grpc_max_tier(access_mode, cfg.max_tier),
                token_file: cfg.token_file.as_ref().map(PathBuf::from),
                principal: cfg.principal.clone(),
                tls,
            });
        }
        if let Some(cfg) = uds {
            let path = cfg
                .path
                .as_ref()
                .map_or_else(|| self.default_grpc_uds_path(), PathBuf::from);
            let access_mode = cfg
                .access_mode
                .map_or(GrpcAccessMode::ReadWrite, Into::into);
            listeners.push(GrpcListener::Uds {
                path,
                mode: cfg.mode,
                access_mode,
                max_tier: effective_grpc_max_tier(access_mode, cfg.max_tier),
                token_file: cfg.token_file.as_ref().map(PathBuf::from),
                principal: cfg.principal.clone(),
            });
        }
        listeners
    }

    /// Directory for daemon-owned runtime state files.
    #[must_use]
    pub fn runtime_state_dir(&self) -> PathBuf {
        PathBuf::from(&self.global.runtime_state_dir)
    }

    /// Marker file used for restarting-speaker Graceful Restart.
    #[must_use]
    pub fn gr_restart_marker_path(&self) -> PathBuf {
        self.runtime_state_dir().join("gr-restart.toml")
    }

    /// Fixed daemon-private directory for shutdown warm-checkpoint bundles.
    ///
    /// Checkpoint publication deliberately has no configurable path: one path
    /// rooted in `runtime_state_dir` keeps ownership, deployment, and marker
    /// binding unambiguous. No boot-side restore exists yet.
    #[must_use]
    #[allow(
        dead_code,
        reason = "wired by the shutdown warm-checkpoint coordinator"
    )]
    pub fn warm_bundle_dir(&self) -> PathBuf {
        self.runtime_state_dir().join("warm-bundle-v1")
    }

    #[must_use]
    pub fn default_grpc_uds_path(&self) -> PathBuf {
        self.runtime_state_dir().join("grpc.sock")
    }

    /// Resolved path for the durable event-history outbox (ADR-0072).
    /// Honors `[event_history].path` when set; defaults to
    /// `<runtime_state_dir>/events.db`. Consumed by the daemon when
    /// it starts the `EventHistoryManager` actor.
    #[must_use]
    pub fn event_history_db_path(&self) -> PathBuf {
        let configured = &self.event_history.path;
        if configured.is_empty() {
            self.runtime_state_dir().join("events.db")
        } else {
            let p = PathBuf::from(configured);
            if p.is_absolute() {
                p
            } else {
                self.runtime_state_dir().join(p)
            }
        }
    }

    /// Resolve the effective cluster ID.
    ///
    /// Returns `Some` if explicitly configured, or if any neighbor is an RR client
    /// (defaults to `router_id`). Returns `None` when not acting as a route reflector.
    pub fn cluster_id(&self) -> Option<Ipv4Addr> {
        if let Some(ref cid) = self.global.cluster_id {
            return Some(cid.parse().expect("validated in Config::load"));
        }
        if self.neighbors.iter().any(|n| {
            n.route_reflector_client.unwrap_or_else(|| {
                n.peer_group
                    .as_deref()
                    .and_then(|name| self.peer_groups.get(name))
                    .and_then(|group| group.route_reflector_client)
                    .unwrap_or(false)
            })
        }) {
            let router_id: Ipv4Addr = self
                .global
                .router_id
                .parse()
                .expect("validated in Config::load");
            return Some(router_id);
        }
        None
    }

    /// Resolve the process-wide cap for accepted dynamic neighbors.
    #[must_use]
    pub(crate) fn effective_dynamic_neighbor_limit(&self) -> u32 {
        self.global
            .dynamic_neighbor_limit
            .unwrap_or(DEFAULT_DYNAMIC_NEIGHBOR_LIMIT)
    }

    /// ADR-0112 RFC 8212 external classification for a configured remote ASN.
    ///
    /// `0` is the accept-any dynamic sentinel, not AS 0 and never an iBGP
    /// match, so it always classifies external. This is deliberately separate
    /// from the RFC 8326 / RFC 7999 implicit-tail `is_ebgp` gate, which keeps
    /// its plain `remote_asn != global.asn` comparison.
    #[must_use]
    pub fn rfc8212_external_asn(&self, remote_asn: u32) -> bool {
        remote_asn == 0 || remote_asn != self.global.asn
    }

    /// Emit the startup notice for `[global] ebgp_requires_policy = true`
    /// while the last ADR-0112 step lands.
    ///
    /// Enforcement and the directional operator surface both ship: an external
    /// session with no explicit operator policy in a direction runs the
    /// reserved internal deny there, and neighbor detail, JSON,
    /// metrics/explain attribution and `rbgp doctor` all report it per
    /// direction. What remains is ADR-0112 step 4 — the Route Refresh
    /// qualification and rollback contract for live policy-presence edits.
    /// Removed when that ships.
    pub fn warn_if_ebgp_requires_policy_partial(&self) {
        if self.global.ebgp_requires_policy {
            tracing::warn!(
                "[global] ebgp_requires_policy = true is enforced on resolved policy and \
                 reported per direction in neighbor detail, JSON, metrics/explain \
                 attribution and rbgp doctor. Not yet available: the Route Refresh \
                 qualification and rollback contract for live policy-presence edits — a \
                 live edit that removes or adds the last explicit import policy is \
                 applied through the ordinary policy path, which does not reject an \
                 Established peer that never negotiated Route Refresh. See \
                 docs/adr/0112-rfc-8212-ebgp-requires-policy.md."
            );
        }
    }

    /// Emit the startup warning for the pre-ADR-0064 legacy gRPC
    /// authorization mode, if active. Tier enforcement becomes
    /// mandatory in a future release.
    pub fn warn_if_legacy_grpc_enforcement(&self) {
        if matches!(
            self.security.grpc.enforcement,
            schema::GrpcEnforcementConfig::Legacy
        ) {
            tracing::warn!(
                "security.grpc.enforcement = \"legacy\" is active: per-method tier \
                 authorization is NOT enforced on read_write listeners. Tier \
                 enforcement becomes mandatory in a future release — migrate to \
                 enforcement = \"tier\" with [security.grpc.roles]; see \
                 docs/adr/0064-grpc-authorization.md."
            );
        }
    }

    /// Resolve the global import policy chain (named policies referenced
    /// by `[policy] import_chain`). `None` when no chain is configured.
    pub fn import_chain(&self) -> Result<Option<PolicyChain>, ConfigError> {
        if self.policy.import_chain.is_empty() {
            return Ok(None);
        }
        resolve_chain(
            &self.policy.import_chain,
            &self.policy.definitions,
            &self.policy.rpol,
            &self.policy.dataset_bindings,
            &self.policy.neighbor_sets,
            &self.peer_groups,
            ChainDirection::Import,
            self.global.asn,
        )
    }

    /// Resolve the global export policy chain.
    pub fn export_chain(&self) -> Result<Option<PolicyChain>, ConfigError> {
        if self.policy.export_chain.is_empty() {
            return Ok(None);
        }
        resolve_chain(
            &self.policy.export_chain,
            &self.policy.definitions,
            &self.policy.rpol,
            &self.policy.dataset_bindings,
            &self.policy.neighbor_sets,
            &self.peer_groups,
            ChainDirection::Export,
            self.global.asn,
        )
    }

    /// Build the implicit RFC 8326 chain-tail import rule:
    /// `match community = GRACEFUL_SHUTDOWN → permit, set local_pref = 0`.
    ///
    /// **Runs LAST in the resolved chain**, not first. `PolicyChain::evaluate`
    /// short-circuits on `Deny` but accumulates modifications across `Permit`
    /// matches with last-writer-wins semantics on scalar fields like
    /// `set_local_pref`. If the implicit rule ran at index 0 and a later
    /// operator policy explicitly set `local_pref = 200` on the same route,
    /// the operator's value would overwrite the `GShut` demotion — silently
    /// breaking the RFC 8326 §4 receiver guarantee. Running at the chain
    /// tail flips the precedence: operator policy still gets to deny
    /// (short-circuits), but any route that survives the chain as `Permit`
    /// has the canonical `local_pref = 0` in the accumulated modifications.
    fn build_implicit_gshut_policy() -> Policy {
        Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Permit,
                match_community: vec![CommunityMatch::Standard {
                    value: rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN,
                }],
                match_as_path: None,
                match_neighbor_set: None,
                match_route_type: None,
                match_evpn_route_type: None,
                match_rpki_validation: None,
                match_aspa_validation: None,
                match_as_path_length_ge: None,
                match_as_path_length_le: None,
                match_local_pref_ge: None,
                match_local_pref_le: None,
                match_med_ge: None,
                match_med_le: None,
                match_next_hop: None,
                modifications: RouteModifications {
                    set_local_pref: Some(0),
                    ..Default::default()
                },
            }],
            default_action: PolicyAction::Permit,
        }
    }

    /// Build the implicit RFC 7999 chain-tail import rule:
    /// `match community = BLACKHOLE → permit, add BLACKHOLE + NO_ADVERTISE`.
    ///
    /// RFC 7999 leaves honoring semantics to explicit operator policy. This
    /// built-in receiver rule does the safe control-plane half only: it keeps
    /// the `BLACKHOLE` marker present even if an earlier policy tried to
    /// remove it, and adds `NO_ADVERTISE` so the request stays local. RFC 1997
    /// egress enforcement runs before export policy, so a policy cannot make
    /// the scoped route exportable by removing `NO_ADVERTISE`. Kernel discard
    /// route installation is a separate `install_blackhole_discard` opt-in.
    fn build_implicit_blackhole_policy() -> Policy {
        Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Permit,
                match_community: vec![CommunityMatch::Standard {
                    value: rustbgpd_wire::COMMUNITY_BLACKHOLE,
                }],
                match_as_path: None,
                match_neighbor_set: None,
                match_route_type: None,
                match_evpn_route_type: None,
                match_rpki_validation: None,
                match_aspa_validation: None,
                match_as_path_length_ge: None,
                match_as_path_length_le: None,
                match_local_pref_ge: None,
                match_local_pref_le: None,
                match_med_ge: None,
                match_med_le: None,
                match_next_hop: None,
                modifications: RouteModifications {
                    communities_add: vec![
                        rustbgpd_wire::COMMUNITY_BLACKHOLE,
                        rustbgpd_wire::COMMUNITY_NO_ADVERTISE,
                    ],
                    ..Default::default()
                },
            }],
            default_action: PolicyAction::Permit,
        }
    }

    /// Resolve the effective import/export policy chains for one neighbor,
    /// discarding the ADR-0112 provenance metadata.
    ///
    /// Test-only: every production resolution site either needs the RFC 8212
    /// verdict or resolves a peer whose external classification is pinned
    /// rather than derived from the record's `remote_asn`, so they all call
    /// [`Self::effective_policy_for_neighbor`] directly.
    ///
    /// # Errors
    /// Propagates any [`ConfigError`] from
    /// [`Self::effective_policy_for_neighbor`].
    #[cfg(test)]
    pub fn effective_policy_chains_for_neighbor(
        &self,
        neighbor: &Neighbor,
    ) -> Result<(Option<PolicyChain>, Option<PolicyChain>), ConfigError> {
        let resolved = self.effective_policy_for_neighbor(neighbor, false)?;
        Ok((resolved.import, resolved.export))
    }

    /// Resolve the effective import/export policy chains for one neighbor,
    /// together with the ADR-0112 directional explicit-policy provenance.
    ///
    /// Per-neighbor named chain overrides per-neighbor inline policy, which
    /// overrides the corresponding peer-group source, which overrides the
    /// corresponding global named chain.
    ///
    /// When `[global] honor_graceful_shutdown = true` and/or
    /// `[global] honor_blackhole = true` AND the neighbor is EBGP, the
    /// resolved import chain is appended with the corresponding implicit
    /// receiver rule. iBGP is intentionally exempt — these are EBGP-edge
    /// receiver behaviors, and re-applying them per iBGP hop would overwrite
    /// values or scoping set legitimately upstream at the EBGP edge.
    ///
    /// `external_pinned` forces the RFC 8212 external classification on. It
    /// exists for one case: a child accepted by an accept-any (`remote_asn =
    /// 0`) dynamic range. The peer manager replaces that sentinel with the ASN
    /// learned from OPEN, so a later re-resolution would otherwise be able to
    /// reclassify a live session as iBGP and drop its enforcement. The flag
    /// deliberately does **not** feed the RFC 8326 / RFC 7999 implicit-tail
    /// gate, which keeps reading the record's `remote_asn`.
    ///
    /// # Errors
    /// Returns [`ConfigError`] when the neighbor references an undefined peer
    /// group, or when any referenced policy/chain fails to resolve or parse.
    #[expect(
        clippy::too_many_lines,
        reason = "one linear inheritance resolution (global, group, neighbor, implicit tails); splitting would hide the precedence order"
    )]
    pub fn effective_policy_for_neighbor(
        &self,
        neighbor: &Neighbor,
        external_pinned: bool,
    ) -> Result<EffectivePolicyChains, ConfigError> {
        let group = self.peer_group_for_neighbor(neighbor)?;
        let global_import = self.import_chain()?;
        let global_export = self.export_chain()?;
        let group_import = if let Some(group) = group {
            if group.import_policy_chain.is_empty() {
                let policy = parse_policy(
                    &group.import_policy,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?;

                policy.map(|p| PolicyChain::new(vec![p]))
            } else {
                resolve_chain(
                    &group.import_policy_chain,
                    &self.policy.definitions,
                    &self.policy.rpol,
                    &self.policy.dataset_bindings,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                    ChainDirection::Import,
                    self.global.asn,
                )?
            }
        } else {
            None
        };
        let group_export = if let Some(group) = group {
            if group.export_policy_chain.is_empty() {
                parse_policy(
                    &group.export_policy,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?
                .map(|p| PolicyChain::new(vec![p]))
            } else {
                resolve_chain(
                    &group.export_policy_chain,
                    &self.policy.definitions,
                    &self.policy.rpol,
                    &self.policy.dataset_bindings,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                    ChainDirection::Export,
                    self.global.asn,
                )?
            }
        } else {
            None
        };

        let import = if neighbor.import_policy_chain.is_empty() {
            if neighbor.import_policy.is_empty() {
                group_import
            } else {
                let policy = parse_policy(
                    &neighbor.import_policy,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?;
                policy.map(|p| PolicyChain::new(vec![p]))
            }
        } else {
            resolve_chain(
                &neighbor.import_policy_chain,
                &self.policy.definitions,
                &self.policy.rpol,
                &self.policy.dataset_bindings,
                &self.policy.neighbor_sets,
                &self.peer_groups,
                ChainDirection::Import,
                self.global.asn,
            )?
        }
        .or_else(|| global_import.clone());
        let export = if neighbor.export_policy_chain.is_empty() {
            if neighbor.export_policy.is_empty() {
                group_export
            } else {
                parse_policy(
                    &neighbor.export_policy,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?
                .map(|p| PolicyChain::new(vec![p]))
            }
        } else {
            resolve_chain(
                &neighbor.export_policy_chain,
                &self.policy.definitions,
                &self.policy.rpol,
                &self.policy.dataset_bindings,
                &self.policy.neighbor_sets,
                &self.peer_groups,
                ChainDirection::Export,
                self.global.asn,
            )?
        }
        .or_else(|| global_export.clone());

        // ADR-0112 explicit-policy provenance, decided HERE — before the
        // implicit tails below can manufacture a chain. Every source that
        // counts as operator provenance (neighbor named, neighbor inline,
        // group named, group inline, global named) is the only thing that can
        // have produced a `Some` at this point: `parse_policy` returns `None`
        // for an empty inline policy and `resolve_chain` returns `None` for an
        // empty name list, so an empty field that fell through to the next
        // level never counts. A permit-all chain still counts — RFC 8212 wants
        // a deliberate policy, not a particular filtering strategy.
        let import_explicit = import.is_some();
        let export_explicit = export.is_some();

        // RFC 8326 §4 / RFC 7999 receiver behavior: append implicit rules to
        // the end of the EBGP import chain when the corresponding honor knob
        // is on. Running LAST guarantees the implicit modification wins over
        // earlier operator policy modifications. Operator denies still
        // short-circuit.
        //
        // FUTURE: when confederation support lands, the EBGP gate
        // should key off an explicit `is_external_neighbor()` helper
        // that knows about confederation sub-AS topology rather than
        // the simple `remote_asn != global.asn` shortcut. Tracked in
        // ROADMAP under "RFC 8326 confederation gating".
        let is_ebgp = neighbor.remote_asn != self.global.asn;
        let import =
            if (self.global.honor_graceful_shutdown || self.global.honor_blackhole) && is_ebgp {
                let mut chain = import.unwrap_or_default();
                if self.global.honor_graceful_shutdown {
                    chain
                        .policies
                        .push(Self::build_implicit_gshut_policy().into());
                }
                if self.global.honor_blackhole {
                    chain
                        .policies
                        .push(Self::build_implicit_blackhole_policy().into());
                }
                Some(chain)
            } else {
                import
            };

        // ADR-0112 RFC 8212 external classification. `remote_asn = 0` is the
        // accept-any dynamic sentinel, never AS 0 and never a real iBGP match,
        // so it is always external; `external_pinned` keeps a session that was
        // accepted through such a range external after OPEN overwrote the
        // sentinel with a learned ASN.
        let external = external_pinned || self.rfc8212_external_asn(neighbor.remote_asn);
        let enforced = self.global.ebgp_requires_policy && external;
        // Substituting the whole direction (rather than prepending) keeps the
        // reserved deny unambiguous: nothing an operator can name or configure
        // is left in a denied direction, and the implicit GSHUT/BLACKHOLE
        // import tails cannot make a missing import policy look satisfied.
        let import = if enforced && !import_explicit {
            Some(reserved_rfc8212_deny_chain(RFC8212_MISSING_IMPORT_POLICY))
        } else {
            import
        };
        let export = if enforced && !export_explicit {
            Some(reserved_rfc8212_deny_chain(RFC8212_MISSING_EXPORT_POLICY))
        } else {
            export
        };

        Ok(EffectivePolicyChains {
            import,
            export,
            import_explicit,
            export_explicit,
            external,
        })
    }

    fn peer_group_for_neighbor(
        &self,
        neighbor: &Neighbor,
    ) -> Result<Option<&PeerGroupConfig>, ConfigError> {
        neighbor
            .peer_group
            .as_deref()
            .map(|name| {
                self.peer_groups
                    .get(name)
                    .ok_or_else(|| ConfigError::UndefinedPeerGroup {
                        name: name.to_string(),
                    })
            })
            .transpose()
    }

    fn resolved_families(
        neighbor: &Neighbor,
        group: Option<&PeerGroupConfig>,
        peer_addr: IpAddr,
    ) -> Result<Vec<(Afi, Safi)>, ConfigError> {
        if !neighbor.families.is_empty() {
            return parse_families(&neighbor.families);
        }
        if let Some(group) = group
            && !group.families.is_empty()
        {
            return parse_families(&group.families);
        }

        let mut f = vec![(Afi::Ipv4, Safi::Unicast)];
        if peer_addr.is_ipv6() {
            f.push((Afi::Ipv6, Safi::Unicast));
        }
        Ok(f)
    }

    fn resolved_required_families(
        neighbor: &Neighbor,
        group: Option<&PeerGroupConfig>,
    ) -> Result<Vec<(Afi, Safi)>, ConfigError> {
        if !neighbor.required_families.is_empty() {
            return parse_families(&neighbor.required_families);
        }
        group
            .filter(|group| !group.required_families.is_empty())
            .map_or_else(
                || Ok(Vec::new()),
                |group| parse_families(&group.required_families),
            )
    }

    fn resolved_remove_private_as(
        neighbor: &Neighbor,
        group: Option<&PeerGroupConfig>,
    ) -> RemovePrivateAs {
        match neighbor
            .remove_private_as
            .as_deref()
            .or_else(|| group.and_then(|g| g.remove_private_as.as_deref()))
        {
            Some("remove") => RemovePrivateAs::Remove,
            Some("all") => RemovePrivateAs::All,
            Some("replace") => RemovePrivateAs::Replace,
            _ => RemovePrivateAs::Disabled,
        }
    }

    fn resolved_add_path(
        neighbor: &Neighbor,
        group: Option<&PeerGroupConfig>,
    ) -> Option<AddPathConfig> {
        neighbor
            .add_path
            .clone()
            .or_else(|| group.and_then(|g| g.add_path.clone()))
    }

    fn resolved_role(
        neighbor: &Neighbor,
        group: Option<&PeerGroupConfig>,
    ) -> Option<rustbgpd_wire::BgpRole> {
        neighbor
            .role
            .or_else(|| group.and_then(|g| g.role))
            .map(BgpRoleConfig::to_wire)
    }

    pub(crate) fn resolve_neighbor(
        &self,
        neighbor: &Neighbor,
    ) -> Result<ResolvedNeighbor, ConfigError> {
        self.resolve_neighbor_pinned(neighbor, false)
    }

    /// [`Self::resolve_neighbor`] with the ADR-0112 external classification
    /// pinned on — see [`Self::effective_policy_for_neighbor`] for when that
    /// is required.
    #[expect(
        clippy::too_many_lines,
        reason = "neighbor resolution centralizes inheritance, validation, and transport projection"
    )]
    pub(crate) fn resolve_neighbor_pinned(
        &self,
        neighbor: &Neighbor,
        external_pinned: bool,
    ) -> Result<ResolvedNeighbor, ConfigError> {
        let router_id: Ipv4Addr = self
            .global
            .router_id
            .parse()
            .expect("validated in Config::load");
        let peer_addr: IpAddr = neighbor.address.parse().expect("validated in Config::load");
        let group = self.peer_group_for_neighbor(neighbor)?;
        let families = Self::resolved_families(neighbor, group, peer_addr)?;
        let add_path = Self::resolved_add_path(neighbor, group);

        let mut peer = PeerConfig::new(self.global.asn, neighbor.remote_asn, router_id);
        peer.hold_time = neighbor
            .hold_time
            .or_else(|| group.and_then(|g| g.hold_time))
            .unwrap_or(DEFAULT_HOLD_TIME);
        peer.min_hold_time = neighbor
            .min_hold_time
            .or_else(|| group.and_then(|g| g.min_hold_time));
        // RFC 9687 §6 default: greater of 8 minutes or 2× hold time.
        peer.send_hold_time = neighbor
            .send_hold_time
            .or_else(|| group.and_then(|g| g.send_hold_time))
            .unwrap_or_else(|| rustbgpd_fsm::default_send_hold_time(peer.hold_time));
        peer.connect_retry_secs = DEFAULT_CONNECT_RETRY_SECS;
        peer.families = families;
        peer.required_families = Self::resolved_required_families(neighbor, group)?;
        peer.graceful_restart = neighbor
            .graceful_restart
            .or_else(|| group.and_then(|g| g.graceful_restart))
            .unwrap_or(true);
        peer.gr_restart_time = neighbor
            .gr_restart_time
            .or_else(|| group.and_then(|g| g.gr_restart_time))
            .unwrap_or(120);
        peer.llgr_stale_time = neighbor
            .llgr_stale_time
            .or_else(|| group.and_then(|g| g.llgr_stale_time))
            .unwrap_or(0);
        peer.add_path_receive = add_path.as_ref().is_some_and(|c| c.receive);
        peer.add_path_send = add_path.as_ref().is_some_and(|c| c.send);
        peer.add_path_send_max = add_path.as_ref().and_then(|c| c.send_max).unwrap_or(0);
        peer.paths_limit_receive_max = add_path.as_ref().and_then(|c| c.receive_max).unwrap_or(0);
        peer.local_role = Self::resolved_role(neighbor, group);
        peer.strict_role = neighbor
            .strict_role
            .or_else(|| group.and_then(|g| g.strict_role))
            .unwrap_or(false);
        peer.prefix_orf_receive = neighbor
            .prefix_orf_receive
            .or_else(|| group.and_then(|g| g.prefix_orf_receive))
            .unwrap_or(false);
        peer.disable_ipv4_unicast = neighbor
            .disable_ipv4_unicast
            .or_else(|| group.and_then(|g| g.disable_ipv4_unicast))
            .unwrap_or(false);

        let (remote_addr, peer_interface, peer_scope_id) =
            if let (IpAddr::V6(v6), Some(interface)) = (peer_addr, neighbor.interface.as_ref()) {
                let scope_id = Self::interface_index(interface).map_err(|err| {
                    ConfigError::InvalidNeighborConfig {
                        address: neighbor.address.clone(),
                        field: "interface".to_string(),
                        reason: err,
                    }
                })?;
                (
                    SocketAddr::V6(SocketAddrV6::new(v6, BGP_PORT, 0, scope_id)),
                    Some(interface.clone()),
                    Some(scope_id),
                )
            } else {
                (SocketAddr::new(peer_addr, BGP_PORT), None, None)
            };
        let mut transport = TransportConfig::new(peer, remote_addr);
        transport.peer_interface = peer_interface;
        transport.peer_scope_id = peer_scope_id;
        transport.max_prefixes = neighbor
            .max_prefixes
            .or_else(|| group.and_then(|g| g.max_prefixes));
        transport.max_prefixes_ipv4 = neighbor
            .max_prefixes_ipv4
            .or_else(|| group.and_then(|g| g.max_prefixes_ipv4));
        transport.max_prefixes_ipv6 = neighbor
            .max_prefixes_ipv6
            .or_else(|| group.and_then(|g| g.max_prefixes_ipv6));
        transport.peer_group.clone_from(&neighbor.peer_group);
        transport.md5_password = neighbor
            .md5_password
            .clone()
            .or_else(|| group.and_then(|g| g.md5_password.clone()))
            .map(Into::into);
        transport.tcp_ao = neighbor.tcp_ao.as_ref().map(|tcp_ao| {
            TcpAoKeyring(
                tcp_ao
                    .iter()
                    .map(|key| TransportTcpAoConfig {
                        key: key.key.clone().into(),
                        send_id: key.send_id,
                        recv_id: key.recv_id,
                        algorithm: TcpAoAlgorithm::from_linux_name(&key.algorithm)
                            .expect("validated in Config::load"),
                        preferred: key.preferred,
                        deprecated: key.deprecated,
                    })
                    .collect(),
            )
        });
        transport.ttl_security = neighbor
            .ttl_security
            .or_else(|| group.and_then(|g| g.ttl_security))
            .unwrap_or(false);
        transport.local_ipv6_nexthop = neighbor
            .local_ipv6_nexthop
            .as_ref()
            .or_else(|| group.and_then(|g| g.local_ipv6_nexthop.as_ref()))
            .map(|s| s.parse::<Ipv6Addr>().expect("validated in Config::load"));
        transport.gr_stale_routes_time = neighbor
            .gr_stale_routes_time
            .or_else(|| group.and_then(|g| g.gr_stale_routes_time))
            .unwrap_or(360);
        transport.gr_peer_restart_time_max = neighbor
            .gr_peer_restart_time_max
            .or_else(|| group.and_then(|g| g.gr_peer_restart_time_max))
            .unwrap_or(4095);
        transport.llgr_stale_time = neighbor
            .llgr_stale_time
            .or_else(|| group.and_then(|g| g.llgr_stale_time))
            .unwrap_or(0);
        transport.route_server_client = neighbor
            .route_server_client
            .or_else(|| group.and_then(|g| g.route_server_client))
            .unwrap_or(false);
        transport.per_client_best = neighbor
            .per_client_best
            .or_else(|| group.and_then(|g| g.per_client_best))
            .unwrap_or(false);
        // ADR-0107: strict-peer NEXT_HOP ownership for route-server
        // clients; the single shipped mode resolves to a bool here.
        transport.next_hop_ownership_strict_peer = matches!(
            neighbor
                .next_hop_ownership
                .or_else(|| group.and_then(|g| g.next_hop_ownership)),
            Some(NextHopOwnershipConfig::StrictPeer)
        );
        transport.slow_peer_threshold_pct = neighbor
            .slow_peer_threshold_pct
            .or_else(|| group.and_then(|g| g.slow_peer_threshold_pct))
            .unwrap_or(rustbgpd_transport::DEFAULT_SLOW_PEER_THRESHOLD_PCT);
        transport.slow_peer_duration = neighbor
            .slow_peer_duration
            .or_else(|| group.and_then(|g| g.slow_peer_duration))
            .unwrap_or(rustbgpd_transport::DEFAULT_SLOW_PEER_DURATION_SECS);
        transport.slow_peer_isolation = neighbor
            .slow_peer_isolation
            .or_else(|| group.and_then(|g| g.slow_peer_isolation))
            .unwrap_or(false);
        // RFC 1997 egress enforcement defaults to on, except for
        // route-server clients (transparent pass-through unless the
        // operator opts in explicitly).
        transport.interpret_rfc1997 = neighbor
            .interpret_rfc1997
            .or_else(|| group.and_then(|g| g.interpret_rfc1997))
            .unwrap_or(!transport.route_server_client);
        // RFC 7947 §2.3.2 control communities default on for
        // route-server clients (the standard IXP posture) and off for
        // everyone else; set explicitly to override either default.
        // Safe to default on since the route-granular emit-time filter
        // (ADR-0101 Decision 3): enabled sessions stay in shared
        // update-groups, and only routes actually carrying a
        // control-form community pay per-target divergence at emit.
        transport.rs_control_communities = neighbor
            .rs_control_communities
            .or_else(|| group.and_then(|g| g.rs_control_communities))
            .unwrap_or(transport.route_server_client);
        transport.route_reflector_client = neighbor
            .route_reflector_client
            .or_else(|| group.and_then(|g| g.route_reflector_client))
            .unwrap_or(false);
        transport.orr_vantage = neighbor
            .orr_vantage
            .or_else(|| group.and_then(|g| g.orr_vantage));
        transport.remove_private_as = Self::resolved_remove_private_as(neighbor, group);
        // RFC 4456: thread the local cluster-id just like
        // `PeerManager::build_transport_config`. Without it a runtime-added
        // iBGP client (this path backs the snapshot-sync gRPC peer adds)
        // reflects routes with no CLUSTER_LIST prepend and skips inbound
        // cluster-loop detection until the daemon restarts.
        transport.cluster_id = self.cluster_id();
        // ADR-0073: this is the second transport-construction path (the
        // resolved-neighbor one used by snapshot-sync gRPC peer adds);
        // it must thread the explain knobs just like
        // PeerManager::build_transport_config, or a gRPC-added peer
        // silently gets the `TransportConfig::new` defaults regardless
        // of `[policy.explain]`.
        transport.explain_enabled = self.policy.explain.enabled;
        transport.explain_cache_size = self.policy.explain.cache_size;
        // LAN-472: same threading hazard for the rejected-route
        // retention knobs — both construction paths must see them.
        transport.reject_retention_enabled = self.policy.reject_retention.enabled;
        transport.reject_retention_capacity = self.policy.reject_retention.capacity;

        let policy = self.effective_policy_for_neighbor(neighbor, external_pinned)?;

        Ok(ResolvedNeighbor {
            transport_config: transport,
            max_prefix_restart_seconds: neighbor
                .max_prefix_restart_seconds
                .or_else(|| group.and_then(|group| group.max_prefix_restart_seconds))
                .map(std::num::NonZeroU32::get),
            label: neighbor
                .description
                .clone()
                .unwrap_or_else(|| neighbor.address.clone()),
            import_policy: policy.import,
            export_policy: policy.export,
            peer_group: neighbor.peer_group.clone(),
            rfc8212_external: policy.external,
        })
    }

    /// Resolve a dynamic neighbor config from a peer group.
    /// Builds a synthetic `Neighbor` inheriting all settings from the group.
    ///
    /// `remote_asn` is the accepting range's configured value at accept time —
    /// including the `0` accept-any sentinel, which classifies the child as
    /// external per ADR-0112. A caller that instead passes the ASN learned from
    /// OPEN must set `external_pinned` from the session's pinned
    /// classification, or a wildcard-accepted child could be re-resolved as
    /// iBGP mid-session.
    pub(crate) fn resolve_dynamic_neighbor(
        &self,
        addr: IpAddr,
        remote_asn: u32,
        description: &str,
        _group: &PeerGroupConfig,
        peer_group_name: &str,
        external_pinned: bool,
    ) -> Result<ResolvedNeighbor, ConfigError> {
        // Build a synthetic Neighbor that references the peer group.
        // All fields come from the group via the normal resolution path.
        let neighbor = Neighbor {
            min_hold_time: None,
            address: addr.to_string(),
            interface: None,
            remote_asn,
            description: Some(description.to_string()),
            peer_group: Some(peer_group_name.to_string()),
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
            ttl_security: None,
            families: Vec::new(),
            required_families: Vec::new(),
            graceful_restart: None,
            gr_restart_time: None,
            gr_peer_restart_time_max: None,
            gr_stale_routes_time: None,
            llgr_stale_time: None,
            local_ipv6_nexthop: None,
            route_reflector_client: None,
            orr_vantage: None,
            route_server_client: None,
            per_client_best: None,
            next_hop_ownership: None,
            interpret_rfc1997: None,
            rs_control_communities: None,
            role: None,
            strict_role: None,
            prefix_orf_receive: None,
            disable_ipv4_unicast: None,
            remove_private_as: None,
            add_path: None,
            log_level: None,
            import_policy: Vec::new(),
            export_policy: Vec::new(),
            import_policy_chain: Vec::new(),
            export_policy_chain: Vec::new(),
        };
        self.resolve_neighbor_pinned(&neighbor, external_pinned)
    }

    pub fn resolved_neighbors(&self) -> Result<Vec<ResolvedNeighbor>, ConfigError> {
        self.neighbors
            .iter()
            .map(|neighbor| self.resolve_neighbor(neighbor))
            .collect()
    }

    /// Resolve `[[evpn_instances]]` entries into a runtime
    /// [`EvpnInstanceTable`].
    ///
    /// Mirrors the per-entry validation done at `Config::load` time —
    /// VNI range, RD/RT parsing, unicast VTEP IP — and additionally
    /// enforces table-level uniqueness on VNI and RD. The validation
    /// pass already runs the same checks; this method exists to give
    /// the daemon and the gRPC layer a typed, indexed view that they
    /// can hand to downstream consumers (CLI list output today, kernel
    /// reconciliation tomorrow).
    ///
    /// # Errors
    /// Surfaces every malformed entry as a [`ConfigError::InvalidEvpnInstance`]
    /// with the offending VNI or duplicate marker in the message — the
    /// entries are processed in declaration order so the first error
    /// reflects the first bad block.
    pub fn resolve_evpn_instances(&self) -> Result<EvpnInstanceTable, ConfigError> {
        let mut table = EvpnInstanceTable::new();
        for cfg in &self.evpn_instances {
            let inst = parse_evpn_instance(cfg, self.global.asn)?;
            table
                .insert(inst)
                .map_err(|e| ConfigError::InvalidEvpnInstance {
                    reason: e.to_string(),
                })?;
        }
        Ok(table)
    }

    /// Resolve `[[ethernet_segments]]` entries into runtime
    /// [`EthernetSegment`] domain objects.
    ///
    /// Validates that every member VNI is also declared in
    /// `[[evpn_instances]]` — orphan members are rejected at config
    /// load time so the daemon never spawns a Type 1 EAD-per-EVI
    /// originator for a VNI it has no instance for.
    ///
    /// # Errors
    /// Surfaces every malformed entry as a
    /// [`ConfigError::InvalidEthernetSegment`] with the offending
    /// ESI string in the message.
    pub fn resolve_ethernet_segments(&self) -> Result<Vec<EthernetSegment>, ConfigError> {
        let mut known_vnis: BTreeSet<EvpnInstanceId> = BTreeSet::new();
        for cfg in &self.evpn_instances {
            if let Ok(id) = EvpnInstanceId::new(cfg.vni) {
                known_vnis.insert(id);
            }
        }
        let mut seen_esis: BTreeSet<EthernetSegmentIdentifier> = BTreeSet::new();
        // ESI-aware MAC origination resolves a Type 2 NLRI's ESI by
        // looking up the MAC's VNI in `vni_to_esi` (built in
        // `src/main.rs` from the resolved segments). That model
        // requires each member VNI to belong to **at most one**
        // segment on this PE — otherwise the daemon would have to
        // know the learned MAC's CE-side ifindex to disambiguate,
        // which Gate 8b doesn't yet plumb. Reject the ambiguous
        // shape at config load so silent wrong-ESI origination is
        // structurally impossible.
        let mut vni_owner: BTreeMap<EvpnInstanceId, EthernetSegmentIdentifier> = BTreeMap::new();
        let mut out = Vec::with_capacity(self.ethernet_segments.len());
        for cfg in &self.ethernet_segments {
            let seg = parse_ethernet_segment(cfg, &known_vnis)?;
            if !seen_esis.insert(seg.esi) {
                return Err(ConfigError::InvalidEthernetSegment {
                    reason: format!(
                        "duplicate ESI {:?} (every [[ethernet_segments]] entry must have a unique ESI)",
                        cfg.esi
                    ),
                });
            }
            for &vni in &seg.member_vnis {
                if let Some(prior_esi) = vni_owner.insert(vni, seg.esi) {
                    return Err(ConfigError::InvalidEthernetSegment {
                        reason: format!(
                            "VNI {} is listed under multiple ethernet_segments \
                             (current segment esi {:?}, prior segment esi {:02x?}); \
                             one local Ethernet Segment per VNI is required for \
                             ESI-aware MAC origination — disambiguation by \
                             learned-port ifindex is not yet plumbed",
                            vni.as_u32(),
                            cfg.esi,
                            prior_esi.octets(),
                        ),
                    });
                }
            }
            out.push(seg);
        }
        Ok(out)
    }

    /// Resolve the ADR-0085 attachment-circuit bindings declared on
    /// `[[ethernet_segments]]` entries (`interface` +
    /// `recovery_delay_secs`) into the daemon-side map keyed by ESI.
    ///
    /// Deliberately separate from [`Self::resolve_ethernet_segments`]:
    /// the binding is coordinator-side trigger state, not part of the
    /// [`EthernetSegment`] domain type the segment actor diffs — a
    /// binding-only edit must not register as a "redefined" segment
    /// and re-originate its routes. Binding-field validation lives in
    /// `parse_ethernet_segment` so every config path rejects malformed
    /// bindings.
    ///
    /// # Errors
    /// Surfaces a malformed ESI as
    /// [`ConfigError::InvalidEthernetSegment`] (already rejected by
    /// full validation; kept as an error so this resolver is safe to
    /// call on any `Config`).
    pub fn resolve_es_link_bindings(
        &self,
    ) -> Result<BTreeMap<EthernetSegmentIdentifier, EsLinkBinding>, ConfigError> {
        let mut out = BTreeMap::new();
        for cfg in &self.ethernet_segments {
            let Some(interface) = cfg.interface.clone() else {
                continue;
            };
            let esi = parse_esi(&cfg.esi).map_err(|e| ConfigError::InvalidEthernetSegment {
                reason: format!("esi {:?}: {e}", cfg.esi),
            })?;
            out.insert(
                esi,
                EsLinkBinding {
                    interface,
                    recovery_delay: std::time::Duration::from_secs(
                        cfg.recovery_delay_secs
                            .unwrap_or(DEFAULT_ES_RECOVERY_DELAY_SECS),
                    ),
                },
            );
        }
        Ok(out)
    }

    /// Resolve `[[evpn_ip_vrfs]]` entries into runtime [`IpVrfTable`].
    ///
    /// Validates:
    ///
    /// - Each IP-VRF entry's own field constraints (delegates to
    ///   `parse_evpn_ip_vrf`).
    /// - Uniqueness of `name` and `vni` across the table (delegated to
    ///   [`IpVrfTable::insert`]).
    /// - No L3VNI collides with any L2VNI in `[[evpn_instances]]` —
    ///   the wire VNI space is shared, so reusing a number across L2
    ///   and L3 would create wire ambiguity.
    /// - Every `[[evpn_instances]].ip_vrf` reference resolves to a
    ///   declared IP-VRF. Marks each referenced IP-VRF in the table
    ///   so downstream layers can spot "declared but unused" entries.
    ///
    /// # Errors
    /// Surfaces every malformed or conflicting entry as a
    /// [`ConfigError::InvalidEvpnIpVrf`] with the offending name in
    /// the message.
    pub fn resolve_evpn_ip_vrfs(&self) -> Result<IpVrfTable, ConfigError> {
        let mut table = IpVrfTable::new();
        // Pre-compute the L2VNI set so we can reject any L3VNI that
        // collides with one.
        let l2_vnis: BTreeSet<u32> = self.evpn_instances.iter().map(|c| c.vni).collect();
        for cfg in &self.evpn_ip_vrfs {
            let vrf = parse_evpn_ip_vrf(cfg, self.global.asn)?;
            if l2_vnis.contains(&vrf.id.as_u32()) {
                return Err(ConfigError::InvalidEvpnIpVrf {
                    reason: format!(
                        "evpn_ip_vrfs[{}]: L3VNI {} collides with an [[evpn_instances]] entry of the same VNI; \
                         L2VNIs and L3VNIs share the wire VNI space and must not overlap",
                        cfg.name,
                        vrf.id.as_u32()
                    ),
                });
            }
            table
                .insert(vrf)
                .map_err(|e| ConfigError::InvalidEvpnIpVrf {
                    reason: e.to_string(),
                })?;
        }
        // Validate L2→L3 bindings + record references.
        for inst in &self.evpn_instances {
            if let Some(ref name) = inst.ip_vrf {
                if table.get(name).is_none() {
                    return Err(ConfigError::InvalidEvpnIpVrf {
                        reason: format!(
                            "evpn_instances[vni={}]: ip_vrf {:?} does not match any declared [[evpn_ip_vrfs]] entry",
                            inst.vni, name
                        ),
                    });
                }
                let vni = rustbgpd_evpn::EvpnInstanceId::new(inst.vni).map_err(|e| {
                    ConfigError::InvalidEvpnIpVrf {
                        reason: format!(
                            "evpn_instances[vni={}]: cannot record ip_vrf {:?} reference: {e}",
                            inst.vni, name
                        ),
                    }
                })?;
                table.mark_referenced_by_l2vni(name.clone(), vni);
            }
        }
        // ADR-0087: GW-IP overlay-index origination requires a linked
        // L2VNI — the receive side scopes the recursive Type 2 lookup
        // to the tenant's MAC-VRFs through that link, so a gateway_ip
        // VRF with no L2VNI could never produce a resolvable route.
        // ESI overlay-index mode needs the same IP-VRF<->MAC-VRF link
        // plus a configured Ethernet Segment member to make EAD-based
        // recursive resolution possible.
        // Reject at load rather than silently originate unresolvable
        // Type 5s. Checked after references are recorded so the
        // L2VNI->IP-VRF bindings are complete.
        let es_members_by_esi = if table
            .iter()
            .any(|vrf| vrf.overlay_index_mode == OverlayIndexMode::Esi)
        {
            Some(self.overlay_index_esi_member_map()?)
        } else {
            None
        };
        for vrf in table.iter() {
            if vrf.overlay_index_mode == OverlayIndexMode::GatewayIp
                && table
                    .referenced_l2vnis(&vrf.name)
                    .is_none_or(std::collections::BTreeSet::is_empty)
            {
                return Err(ConfigError::InvalidEvpnIpVrf {
                    reason: format!(
                        "evpn_ip_vrfs[{}]: overlay_index_mode = \"gateway_ip\" requires at least one \
                         [[evpn_instances]] with ip_vrf = {:?} (the GW-IP receive side scopes its \
                         recursive Type 2 lookup to the linked L2VNIs); link an L2VNI or use \
                         \"interface_less\"",
                        vrf.name, vrf.name
                    ),
                });
            }
            if vrf.overlay_index_mode == OverlayIndexMode::Esi {
                validate_esi_overlay_index_vrf(
                    vrf,
                    &table,
                    es_members_by_esi
                        .as_ref()
                        .expect("ES member map exists when any VRF uses ESI mode"),
                )?;
            }
        }
        Ok(table)
    }

    /// Resolve `[managed_netdevs]` into ADR-0091 desired state.
    ///
    /// The config validation pass already enforces owner-token, bridge-name,
    /// duplicate-name, and derived-altname bounds. This method exists so
    /// daemon wiring can hand a typed, ordered table to the EVPN dataplane
    /// without duplicating the ownership-stamp format.
    ///
    /// # Errors
    /// Returns [`ConfigError::InvalidManagedNetdev`] if a caller bypassed
    /// validation and left bridge rows without an owner token.
    pub fn resolve_managed_netdevs(
        &self,
    ) -> Result<rustbgpd_evpn::ManagedNetdevTable, ConfigError> {
        let owner_token = self.managed_netdevs.owner_token.as_str();
        if self.managed_netdevs_empty_without_owner(owner_token) {
            return Ok(rustbgpd_evpn::ManagedNetdevTable::new());
        }
        if owner_token.is_empty() {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: "managed_netdevs.owner_token is required when managed netdev rows are configured"
                    .to_string(),
            });
        }
        let bridges = self
            .managed_netdevs
            .bridges
            .iter()
            .map(|bridge| (bridge.name.clone(), bridge.vlan_filtering))
            .collect();
        let vxlans = self
            .managed_netdevs
            .vxlans
            .iter()
            .map(|vxlan| {
                (
                    vxlan.name.clone(),
                    rustbgpd_evpn::ManagedVxlanNetdevSpec {
                        vni: vxlan.vni,
                        local_ip: vxlan.local,
                        dstport: vxlan.dstport,
                        bridge: vxlan.bridge.clone(),
                    },
                )
            })
            .collect();
        let svd_vxlans = self.resolve_managed_svd_vxlans()?;
        let vrfs = self
            .managed_netdevs
            .vrfs
            .iter()
            .map(|vrf| {
                (
                    vrf.name.clone(),
                    rustbgpd_evpn::ManagedVrfNetdevSpec {
                        table_id: vrf.table_id,
                    },
                )
            })
            .collect();
        let l3vxlans = self
            .managed_netdevs
            .l3vxlans
            .iter()
            .map(|l3vxlan| {
                let router_mac = parse_mac_address(&l3vxlan.router_mac).map_err(|e| {
                    ConfigError::InvalidManagedNetdev {
                        reason: format!(
                            "managed L3VXLAN {:?}: invalid router_mac {:?}: {e}",
                            l3vxlan.name, l3vxlan.router_mac
                        ),
                    }
                })?;
                Ok((
                    l3vxlan.name.clone(),
                    rustbgpd_evpn::ManagedL3VxlanNetdevSpec {
                        vni: l3vxlan.vni,
                        local_ip: l3vxlan.local,
                        dstport: l3vxlan.dstport,
                        vrf: l3vxlan.vrf.clone(),
                        router_mac,
                    },
                ))
            })
            .collect::<Result<_, ConfigError>>()?;
        let vlan_uppers = self
            .managed_netdevs
            .vlan_uppers
            .iter()
            .map(|vlan_upper| {
                (
                    vlan_upper.name.clone(),
                    rustbgpd_evpn::ManagedVlanUpperNetdevSpec {
                        bridge: vlan_upper.bridge.clone(),
                        vlan: vlan_upper.vlan,
                    },
                )
            })
            .collect();
        Ok(rustbgpd_evpn::ManagedNetdevTable::from_all_maps_with_svd(
            owner_token.to_string(),
            bridges,
            vxlans,
            svd_vxlans,
            vrfs,
            l3vxlans,
            vlan_uppers,
        ))
    }

    fn managed_netdevs_empty_without_owner(&self, owner_token: &str) -> bool {
        self.managed_netdevs.bridges.is_empty()
            && self.managed_netdevs.vxlans.is_empty()
            && self.managed_netdevs.svd_vxlans.is_empty()
            && self.managed_netdevs.vrfs.is_empty()
            && self.managed_netdevs.l3vxlans.is_empty()
            && self.managed_netdevs.vlan_uppers.is_empty()
            && owner_token.is_empty()
    }

    fn resolve_managed_svd_vxlans(
        &self,
    ) -> Result<BTreeMap<String, rustbgpd_evpn::ManagedSvdVxlanNetdevSpec>, ConfigError> {
        self.managed_netdevs
            .svd_vxlans
            .iter()
            .map(|svd| {
                let mut bindings = BTreeMap::new();
                for inst in self.evpn_instances.iter().filter(|inst| {
                    inst.bridge.as_deref() == Some(svd.bridge.as_str())
                        && inst.bridge_vlan.is_some()
                }) {
                    let vlan = inst.bridge_vlan.expect("filtered Some");
                    let bridge_vlan =
                        u16::try_from(vlan).map_err(|_| ConfigError::InvalidManagedNetdev {
                            reason: format!(
                                "managed SVD VXLAN {:?}: bridge {:?} instance VNI {} has invalid bridge_vlan {}",
                                svd.name, svd.bridge, inst.vni, vlan
                            ),
                        })?;
                    if let Some(&existing) = bindings.get(&bridge_vlan)
                        && existing != inst.vni
                    {
                        return Err(ConfigError::InvalidManagedNetdev {
                            reason: format!(
                                "managed SVD VXLAN {:?}: bridge {:?} bridge_vlan {} maps to conflicting VNIs {} and {}; each VLAN must map to exactly one VNI",
                                svd.name, svd.bridge, bridge_vlan, existing, inst.vni
                            ),
                        });
                    }
                    bindings.insert(bridge_vlan, inst.vni);
                }
                Ok((
                    svd.name.clone(),
                    rustbgpd_evpn::ManagedSvdVxlanNetdevSpec {
                        local_ip: svd.local,
                        dstport: svd.dstport,
                        bridge: svd.bridge.clone(),
                        bindings: bindings
                            .into_iter()
                            .map(|(bridge_vlan, vni)| rustbgpd_evpn::ManagedSvdVxlanBinding {
                                bridge_vlan,
                                vni,
                            })
                            .collect(),
                    },
                ))
            })
            .collect()
    }

    fn overlay_index_esi_member_map(
        &self,
    ) -> Result<BTreeMap<EthernetSegmentIdentifier, BTreeSet<EvpnInstanceId>>, ConfigError> {
        let mut out = BTreeMap::new();
        for cfg in &self.ethernet_segments {
            let esi = parse_esi(&cfg.esi).map_err(|e| ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "ethernet_segments[esi={:?}]: invalid ESI needed for ESI overlay-index validation: {e}",
                    cfg.esi
                ),
            })?;
            let mut members = BTreeSet::new();
            for &raw_vni in &cfg.member_vnis {
                let vni =
                    EvpnInstanceId::new(raw_vni).map_err(|e| ConfigError::InvalidEvpnIpVrf {
                        reason: format!(
                            "ethernet_segments[esi={:?}]: invalid member VNI {raw_vni} needed for \
                             ESI overlay-index validation: {e}",
                            cfg.esi
                        ),
                    })?;
                members.insert(vni);
            }
            out.insert(esi, members);
        }
        Ok(out)
    }

    /// Returns `(TransportConfig, label, import_chain, export_chain)` per neighbor.
    ///
    /// Per-neighbor policy overrides global; if neighbor has no policy entries,
    /// the corresponding value is `None` (caller falls back to global).
    #[expect(clippy::type_complexity)]
    #[cfg(test)]
    pub fn to_peer_configs(
        &self,
    ) -> Result<
        Vec<(
            TransportConfig,
            String,
            Option<PolicyChain>,
            Option<PolicyChain>,
        )>,
        ConfigError,
    > {
        self.resolved_neighbors().map(|neighbors| {
            neighbors
                .into_iter()
                .map(|neighbor| {
                    (
                        neighbor.transport_config,
                        neighbor.label,
                        neighbor.import_policy,
                        neighbor.export_policy,
                    )
                })
                .collect()
        })
    }
    /// Build `tracing` filter directives for per-peer log level overrides.
    ///
    /// Returns directives like `[peer{peer_addr=10.0.0.1}]=debug` that can
    /// be appended to an `EnvFilter`. The span directive MUST be wrapped in
    /// square brackets — `peer{...}=level` (no brackets) is rejected by the
    /// `EnvFilter` directive parser (`error parsing level filter`), which
    /// would make `init_logging` fail and abort daemon boot the moment any
    /// neighbor set a `log_level`.
    pub fn per_peer_log_directives(&self) -> Vec<String> {
        let mut directives = Vec::new();
        for neighbor in &self.neighbors {
            let level = neighbor.log_level.as_deref().or_else(|| {
                neighbor
                    .peer_group
                    .as_deref()
                    .and_then(|name| self.peer_groups.get(name))
                    .and_then(|g| g.log_level.as_deref())
            });
            if let Some(level) = level {
                directives.push(format!(
                    "[peer{{peer_addr={addr}}}]={level}",
                    addr = neighbor.address
                ));
            }
        }
        directives
    }

    /// Resolver tables for the ADR-0113 outbound unicast prefix maxima.
    ///
    /// The RIB manager owns the inheritance walk so an accepted dynamic
    /// child — which has no `[[neighbors]]` row — resolves the same
    /// effective values as a static member of the same group. These tables
    /// carry the configuration as written; absence at both levels is
    /// unlimited.
    #[must_use]
    pub fn outbound_prefix_limits(&self) -> rustbgpd_rib::OutboundPrefixLimitConfig {
        use rustbgpd_rib::{OutboundPrefixLimitConfig, OutboundPrefixLimitPair};

        let pair = |ipv4, ipv6| OutboundPrefixLimitPair { ipv4, ipv6 };
        OutboundPrefixLimitConfig {
            neighbors: self
                .neighbors
                .iter()
                .filter(|neighbor| {
                    neighbor.max_prefixes_out_ipv4.is_some()
                        || neighbor.max_prefixes_out_ipv6.is_some()
                })
                .filter_map(|neighbor| {
                    Some((
                        neighbor.address.parse().ok()?,
                        pair(
                            neighbor.max_prefixes_out_ipv4,
                            neighbor.max_prefixes_out_ipv6,
                        ),
                    ))
                })
                .collect(),
            groups: self
                .peer_groups
                .iter()
                .filter(|(_, group)| {
                    group.max_prefixes_out_ipv4.is_some() || group.max_prefixes_out_ipv6.is_some()
                })
                .map(|(name, group)| {
                    (
                        name.clone(),
                        pair(group.max_prefixes_out_ipv4, group.max_prefixes_out_ipv6),
                    )
                })
                .collect(),
        }
    }
}

/// Whether reverting from `candidate` to `rollback` would have to LOWER an
/// outbound prefix maximum (ADR-0113).
///
/// A commit-confirmed transaction may tighten a maximum at or above current
/// usage, because its automatic undo only ever loosens. It must reject a
/// raise or removal, whose undo could become an invalid lowering once the
/// new capacity has admitted routes; an operator makes that change through
/// an ordinary committed transaction instead.
#[must_use]
pub fn outbound_prefix_limits_loosen(rollback: &Config, candidate: &Config) -> bool {
    fn looser(from: Option<std::num::NonZeroU32>, to: Option<std::num::NonZeroU32>) -> bool {
        match (from, to) {
            (Some(_), None) => true,
            (Some(from), Some(to)) => to > from,
            (None, _) => false,
        }
    }
    fn effective(
        config: &Config,
        neighbor: &Neighbor,
    ) -> (Option<std::num::NonZeroU32>, Option<std::num::NonZeroU32>) {
        let group = neighbor
            .peer_group
            .as_deref()
            .and_then(|name| config.peer_groups.get(name));
        (
            neighbor
                .max_prefixes_out_ipv4
                .or_else(|| group.and_then(|group| group.max_prefixes_out_ipv4)),
            neighbor
                .max_prefixes_out_ipv6
                .or_else(|| group.and_then(|group| group.max_prefixes_out_ipv6)),
        )
    }

    // Dynamic children have no `[[neighbors]]` row, so group defaults are
    // compared directly as well as through each static member.
    let groups_loosen = candidate.peer_groups.iter().any(|(name, group)| {
        let prior = rollback.peer_groups.get(name);
        looser(
            prior.and_then(|prior| prior.max_prefixes_out_ipv4),
            group.max_prefixes_out_ipv4,
        ) || looser(
            prior.and_then(|prior| prior.max_prefixes_out_ipv6),
            group.max_prefixes_out_ipv6,
        )
    });
    groups_loosen
        || candidate.neighbors.iter().any(|neighbor| {
            let Some(prior) = rollback
                .neighbors
                .iter()
                .find(|prior| prior.address == neighbor.address)
            else {
                return false;
            };
            let (prior_v4, prior_v6) = effective(rollback, prior);
            let (v4, v6) = effective(candidate, neighbor);
            looser(prior_v4, v4) || looser(prior_v6, v6)
        })
}

#[derive(Clone)]
pub struct ResolvedNeighbor {
    pub transport_config: TransportConfig,
    pub max_prefix_restart_seconds: Option<u32>,
    pub label: String,
    pub import_policy: Option<PolicyChain>,
    pub export_policy: Option<PolicyChain>,
    pub peer_group: Option<String>,
    /// ADR-0112 RFC 8212 external classification, decided from the neighbor
    /// record that produced this resolution (accept-any dynamic ranges
    /// included). The peer manager pins it for the session's lifetime because
    /// the record's `remote_asn` is overwritten with the ASN learned from OPEN.
    pub rfc8212_external: bool,
}

/// Build the ADR-0112 reserved internal deny-all chain for one direction.
///
/// Constructed directly rather than looked up in `[policy] definitions`, so no
/// configured name can reference or replace it. It denies by `default_action`
/// with no statements: `evaluate_chain(Some(..))` still runs, which is what
/// keeps `evaluate_chain(None, ..)` permit-all semantics untouched for every
/// session RFC 8212 enforcement does not govern.
pub(crate) fn reserved_rfc8212_deny_chain(name: &str) -> PolicyChain {
    PolicyChain::from_named(vec![NamedPolicy {
        name: Some(name.to_string()),
        policy: Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Deny,
        },
        rpol: None,
    }])
}

/// True when `chain` is exactly the reserved RFC 8212 deny for `name`
/// (ADR-0112).
///
/// This is the whole directional status derivation: the operator surface asks
/// the *installed* chain what is installed instead of storing a second verdict
/// beside it. That is deliberate. A stored `present` bool has to be threaded
/// through every resolution, live-apply, and rollback path in lockstep with
/// the chain it describes, and the moment one path advances without it the
/// surface reports `present` while the deny is live — which is worse than no
/// surface at all in a fail-closed feature. Reading the chain cannot drift
/// from the chain.
///
/// This does not reconstruct the *provenance* verdict ADR-0112 forbids
/// rebuilding from compiled content, and it could not: the reserved deny
/// replaces the whole direction, so there is no operator policy or implicit
/// tail left to tell apart. It is an identity test against the one chain
/// [`reserved_rfc8212_deny_chain`] builds, and [`Config::validate`] refuses
/// both reserved names to operator policies, so nothing configurable compares
/// equal to it.
#[must_use]
pub fn is_reserved_rfc8212_deny(chain: Option<&PolicyChain>, name: &str) -> bool {
    chain.is_some_and(|chain| *chain == reserved_rfc8212_deny_chain(name))
}

/// Resolved policy chains for one neighbor plus the ADR-0112 directional
/// explicit-policy provenance they were resolved with.
///
/// The provenance verdict is attached to the direction at resolution time. It
/// is never reconstructed by inspecting a compiled [`PolicyChain`]: compiled
/// content cannot tell an operator policy apart from a daemon-owned implicit
/// tail or from the reserved deny.
#[derive(Clone, Debug, PartialEq)]
pub struct EffectivePolicyChains {
    /// Effective import chain, including any implicit RFC 8326 / RFC 7999
    /// tails and any RFC 8212 reserved deny substitution.
    pub import: Option<PolicyChain>,
    /// Effective export chain, including any RFC 8212 reserved deny
    /// substitution.
    pub export: Option<PolicyChain>,
    /// Explicit operator import policy resolved, decided before the implicit
    /// tails were appended and before any reserved deny substitution.
    pub import_explicit: bool,
    /// Explicit operator export policy resolved.
    pub export_explicit: bool,
    /// RFC 8212 external (eBGP) classification for this resolution.
    pub external: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GrpcListener {
    Tcp {
        addr: SocketAddr,
        access_mode: GrpcAccessMode,
        max_tier: GrpcMaxTier,
        token_file: Option<PathBuf>,
        principal: Option<String>,
        tls: Option<GrpcTlsPaths>,
    },
    Uds {
        path: PathBuf,
        mode: u32,
        access_mode: GrpcAccessMode,
        max_tier: GrpcMaxTier,
        token_file: Option<PathBuf>,
        principal: Option<String>,
    },
}

/// PEM file paths for native gRPC mTLS on a TCP listener. All three
/// fields are required together — there is no "TLS-without-mTLS"
/// half-mode.
#[derive(Debug, Clone, PartialEq)]
#[expect(
    clippy::struct_field_names,
    reason = "field-name-postfix repetition mirrors the TOML schema (tls_cert_file / tls_key_file / tls_client_ca_file); operators read TOML, so dropping the suffix here would diverge from the user-facing config keys"
)]
pub struct GrpcTlsPaths {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub client_ca_file: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcAccessMode {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GrpcMaxTier {
    Read,
    SensitiveRead,
    Mutating,
    OperatorOnly,
}

const fn access_mode_compatibility_max_tier(access_mode: GrpcAccessMode) -> GrpcMaxTier {
    match access_mode {
        GrpcAccessMode::ReadOnly => GrpcMaxTier::SensitiveRead,
        GrpcAccessMode::ReadWrite => GrpcMaxTier::OperatorOnly,
    }
}

const TRANSACTION_FIB_SECTION: &str = "[[fib_tables]]";
const TRANSACTION_DYNAMIC_SECTION: &str = "[[dynamic_neighbors]]";
const TRANSACTION_NEIGHBOR_ADD_SECTION: &str = "[[neighbors]] add";
const TRANSACTION_NEIGHBOR_DELETE_SECTION: &str = "[[neighbors]] delete";
const TRANSACTION_NEIGHBOR_MODIFY_SECTION: &str = "[[neighbors]] modify";
const TRANSACTION_PEER_GROUP_CATALOG_SECTION: &str = "[peer_groups] catalog";
const TRANSACTION_POLICY_DEFINITIONS_SECTION: &str = "[policy] definitions";
const TRANSACTION_POLICY_NEIGHBOR_SETS_SECTION: &str = "[policy] neighbor_sets";
const TRANSACTION_POLICY_GLOBAL_CHAINS_SECTION: &str = "[policy] global chains";
const TRANSACTION_POLICY_LIVE_IMPACT_SECTION: &str = "[policy] live impact";
const TRANSACTION_SESSION_RESHAPE_SECTION: &str = "effective neighbor session reshape";

/// Detect removed config keys in a TOML document that failed typed
/// deserialization and return a migration error naming the
/// replacement. Returns `None` when the failure has some other cause
/// (including TOML that is not even syntactically valid — the normal
/// parse diagnostic covers that).
fn retired_key_error(content: &str) -> Option<String> {
    let table: toml::Table = content.parse().ok()?;
    let nested = |path: &[&str]| -> bool {
        let (last, parents) = path.split_last().expect("retired-key path is non-empty");
        let mut current = &table;
        for key in parents {
            match current.get(*key) {
                Some(toml::Value::Table(t)) => current = t,
                _ => return false,
            }
        }
        current.contains_key(*last)
    };
    if nested(&["global", "telemetry", "looking_glass"]) {
        return Some(
            "error: [global.telemetry.looking_glass] has been removed: the in-daemon \
             birdwatcher looking glass HTTP server is gone. Run the external adapter \
             instead — examples/birdwatcher-adapter serves the same birdwatcher REST \
             endpoints from the daemon's gRPC API. Remove the \
             [global.telemetry.looking_glass] section from this config."
                .to_string(),
        );
    }
    if nested(&["policy", "import"]) || nested(&["policy", "export"]) {
        return Some(
            "error: the global inline policy fallback ([[policy.import]] / \
             [[policy.export]]) has been removed. Migrate the statements to named \
             policies ([policy.definitions.<name>] or .rpol files via [policy] \
             rpol_files) referenced from [policy] import_chain / export_chain — see \
             docs/CONFIGURATION.md \"Named policy definitions\". Per-neighbor and per-group \
             inline policy (import_policy / export_policy) is unchanged."
                .to_string(),
        );
    }
    None
}

fn effective_grpc_max_tier(
    access_mode: GrpcAccessMode,
    configured: Option<GrpcMaxTierConfig>,
) -> GrpcMaxTier {
    access_mode_compatibility_max_tier(access_mode)
        .min(configured.map_or(GrpcMaxTier::OperatorOnly, GrpcMaxTier::from))
}

/// Differences between two neighbor lists, keyed by address.
pub struct NeighborDiff {
    pub added: Vec<Neighbor>,
    pub removed: Vec<rustbgpd_api::peer_types::PeerKey>,
    pub changed: Vec<Neighbor>,
}

/// Live-impact class for a single `[[neighbors]]` / `[peer_groups]` field
/// edit, surfaced from the reload matrix (`docs/reload-matrix.md`, the
/// per-field classification pinned by the reload-matrix structural tests)
/// so diff renderings can annotate each changed field with what applying
/// it does to the affected peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigFieldImpact {
    /// Reload-matrix class `live`: the value applies to the running peer
    /// without renegotiating the session.
    HotApplied,
    /// Reload-matrix class `live (effective next session)`: the value is
    /// OPEN-negotiated, socket-scoped, or registered at session
    /// establishment, so applying it takes a session reset.
    SessionReset,
    /// Reload-matrix class `restart-required`: a daemon restart is needed.
    RestartRequired,
}

/// Reload-matrix impact class + human annotation for one neighbor /
/// peer-group field named by [`describe_neighbor_changes`] /
/// [`describe_peer_group_changes`].
///
/// Adjudicated live against a lab peer for LAN-341, so the classes below
/// are the shipped reload behavior, not aspiration:
/// - Hot-applied fields are applied in place by the reload partition
///   (`neighbor_change_hot_applicable` → `HotUpdatePeer`) without
///   touching the session task.
/// - `remote_asn`: `diff_neighbors` keys on `(address, interface)`, so
///   an ASN edit flows through reconcile as an immediate session rebuild
///   under the new ASN — identity delete+add semantics without a daemon
///   restart.
/// - `peer_group`: a reassignment changes the peer's effective inherited
///   config, so both SIGHUP reconcile and the transaction session-reshape
///   executor rebuild the session.
/// - `tcp_ao`: the field-only transaction/diff classifier remains
///   `RestartRequired`. Only the SIGHUP coordinator can prove that a complete
///   candidate is a supported ordered generation shape and apply it
///   across the listener plus every affected managed session.
fn config_field_impact(field: &str) -> Option<(ConfigFieldImpact, &'static str)> {
    Some(match field {
        "description"
        | "max_prefixes"
        | "max_prefixes_ipv4"
        | "max_prefixes_ipv6"
        | "max_prefixes_out_ipv4"
        | "max_prefixes_out_ipv6"
        | "max_prefix_restart_seconds"
        | "gr_peer_restart_time_max"
        | "gr_stale_routes_time"
        | "local_ipv6_nexthop"
        | "remove_private_as"
        | "log_level"
        | "import_policy"
        | "export_policy"
        | "import_policy_chain"
        | "export_policy_chain" => (ConfigFieldImpact::HotApplied, "hot-applied"),
        "remote_asn" => (
            ConfigFieldImpact::SessionReset,
            "session reset: peer re-established with new ASN",
        ),
        "peer_group" => (
            ConfigFieldImpact::SessionReset,
            "session reset: reassignment rebuilds the session",
        ),
        "hold_time"
        | "min_hold_time"
        | "families"
        | "required_families"
        | "graceful_restart"
        | "gr_restart_time"
        | "llgr_stale_time"
        | "role"
        | "strict_role"
        | "prefix_orf_receive"
        | "disable_ipv4_unicast"
        | "add_path" => (
            ConfigFieldImpact::SessionReset,
            "session reset: OPEN renegotiation",
        ),
        "md5_password" | "ttl_security" | "send_hold_time" => (
            ConfigFieldImpact::SessionReset,
            "session reset: TCP re-establish",
        ),
        "route_reflector_client"
        | "orr_vantage"
        | "route_server_client"
        | "per_client_best"
        | "next_hop_ownership"
        | "interpret_rfc1997"
        | "rs_control_communities" => (
            ConfigFieldImpact::SessionReset,
            "session reset: session re-establish",
        ),
        "tcp_ao" | "bfd" => (ConfigFieldImpact::RestartRequired, "restart required"),
        _ => return None,
    })
}

/// One changed field on a neighbor or peer group.
///
/// Serializes with the stable key set `{field, old, new, impact}`:
/// `old`/`new` are the JSON forms of the config values with honest `null`
/// for an absent optional (rendered `(unset)` in human output), and
/// `impact` is the reload-matrix class or `null` when unknown.
/// Secret-bearing and inline-policy fields carry `null` on both value
/// sides and render `<changed>` — the values are never exposed.
#[derive(Clone, Debug, serde::Serialize)]
pub struct FieldChange {
    pub field: &'static str,
    pub old: serde_json::Value,
    pub new: serde_json::Value,
    pub impact: Option<ConfigFieldImpact>,
    #[serde(skip)]
    annotation: Option<&'static str>,
    #[serde(skip)]
    values_summarized: bool,
}

impl FieldChange {
    fn new<T: serde::Serialize>(field: &'static str, old: &T, new: &T) -> Self {
        let (impact, annotation) = match config_field_impact(field) {
            Some((impact, annotation)) => (Some(impact), Some(annotation)),
            None => (None, None),
        };
        Self {
            field,
            old: json_config_value(old),
            new: json_config_value(new),
            impact,
            annotation,
            values_summarized: false,
        }
    }

    /// A change whose values are deliberately withheld (secrets such as
    /// `md5_password` / `tcp_ao`, or inline policy bodies too large to
    /// inline): both value sides are `null` and the human rendering says
    /// `<changed>`.
    fn summarized(field: &'static str) -> Self {
        let (impact, annotation) = match config_field_impact(field) {
            Some((impact, annotation)) => (Some(impact), Some(annotation)),
            None => (None, None),
        };
        Self {
            field,
            old: serde_json::Value::Null,
            new: serde_json::Value::Null,
            impact,
            annotation,
            values_summarized: true,
        }
    }

    /// Human line for this change: `hold_time: 90 → 30  [session reset:
    /// OPEN renegotiation]`. Absent values render `(unset)`; withheld
    /// values render `<changed>`.
    pub fn render(&self) -> String {
        let values = if self.values_summarized {
            "<changed>".to_string()
        } else {
            format!(
                "{} → {}",
                render_json_config_value(&self.old),
                render_json_config_value(&self.new)
            )
        };
        match self.annotation {
            Some(annotation) => format!("{}: {values}  [{annotation}]", self.field),
            None => format!("{}: {values}", self.field),
        }
    }

    /// True when applying this field edit resets the affected session.
    pub fn resets_session(&self) -> bool {
        self.impact == Some(ConfigFieldImpact::SessionReset)
    }
}

fn json_config_value<T: serde::Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

/// Render one JSON config value for human output: `null` → `(unset)`,
/// strings bare, everything else (numbers, bools, arrays, objects) as
/// compact JSON — never Rust `Debug` syntax.
fn render_json_config_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Null => "(unset)".to_string(),
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Describe which fields changed between two `Neighbor` configurations.
pub fn describe_neighbor_changes(old: &Neighbor, new: &Neighbor) -> Vec<FieldChange> {
    let mut changes = Vec::new();

    macro_rules! cmp_field {
        ($field:ident) => {
            if old.$field != new.$field {
                changes.push(FieldChange::new(
                    stringify!($field),
                    &old.$field,
                    &new.$field,
                ));
            }
        };
    }

    cmp_field!(remote_asn);
    cmp_field!(description);
    cmp_field!(peer_group);
    cmp_field!(hold_time);
    cmp_field!(min_hold_time);
    cmp_field!(send_hold_time);
    cmp_field!(max_prefixes);
    cmp_field!(max_prefixes_ipv4);
    cmp_field!(max_prefixes_ipv6);
    cmp_field!(max_prefixes_out_ipv4);
    cmp_field!(max_prefixes_out_ipv6);
    cmp_field!(max_prefix_restart_seconds);
    cmp_field!(ttl_security);
    cmp_field!(families);
    cmp_field!(required_families);
    cmp_field!(graceful_restart);
    cmp_field!(gr_restart_time);
    cmp_field!(gr_peer_restart_time_max);
    cmp_field!(gr_stale_routes_time);
    cmp_field!(llgr_stale_time);
    cmp_field!(local_ipv6_nexthop);
    cmp_field!(route_reflector_client);
    cmp_field!(orr_vantage);
    cmp_field!(route_server_client);
    cmp_field!(per_client_best);
    cmp_field!(next_hop_ownership);
    cmp_field!(interpret_rfc1997);
    cmp_field!(rs_control_communities);
    cmp_field!(role);
    cmp_field!(strict_role);
    cmp_field!(prefix_orf_receive);
    cmp_field!(disable_ipv4_unicast);
    cmp_field!(remove_private_as);
    cmp_field!(add_path);
    cmp_field!(log_level);

    // Secret-bearing fields: report the change without revealing values.
    if old.md5_password != new.md5_password {
        changes.push(FieldChange::summarized("md5_password"));
    }
    if old.tcp_ao != new.tcp_ao {
        changes.push(FieldChange::summarized("tcp_ao"));
    }
    if old.bfd != new.bfd {
        changes.push(FieldChange::summarized("bfd"));
    }

    // Inline policy bodies: summarize rather than dump full config.
    if old.import_policy != new.import_policy {
        changes.push(FieldChange::summarized("import_policy"));
    }
    if old.export_policy != new.export_policy {
        changes.push(FieldChange::summarized("export_policy"));
    }
    cmp_field!(import_policy_chain);
    cmp_field!(export_policy_chain);

    changes
}

/// True when every field that differs between `old` and `new` is
/// reload-matrix `live` (hot-applied), so a SIGHUP reload can apply the
/// change to the running peer in place instead of delete/re-adding the
/// session task (LAN-341).
///
/// Conservative on both edges: an empty change list (a runtime-relevant
/// field `describe_neighbor_changes` doesn't cover) and any field with an
/// unknown impact class both return `false`, keeping the rebuild path as
/// the fallback.
pub fn neighbor_change_hot_applicable(old: &Neighbor, new: &Neighbor) -> bool {
    let changes = describe_neighbor_changes(old, new);
    !changes.is_empty()
        && changes
            .iter()
            .all(|change| change.impact == Some(ConfigFieldImpact::HotApplied))
}

/// Compare two neighbor lists and return the differences.
///
/// Two neighbors with the same address but different runtime-affecting
/// configuration are reported in `changed`. TCP-AO edits are deliberately
/// excluded here because they require listener/session-wide coordination:
/// `diff_config` reports them through `neighbor_tcp_ao_changed`, while the
/// reload coordinator either commits a supported ordered generation or
/// pins the unsupported edit rather than rebuilding one peer against stale
/// listener MKTs.
pub fn diff_neighbors(old: &[Neighbor], new: &[Neighbor]) -> NeighborDiff {
    let key = |n: &Neighbor| (n.address.clone(), n.interface.clone());
    let old_map: std::collections::HashMap<(String, Option<String>), &Neighbor> =
        old.iter().map(|n| (key(n), n)).collect();
    let new_map: std::collections::HashMap<(String, Option<String>), &Neighbor> =
        new.iter().map(|n| (key(n), n)).collect();

    let mut added = Vec::new();
    let mut changed = Vec::new();
    for (addr, new_n) in &new_map {
        match old_map.get(addr) {
            None => added.push((*new_n).clone()),
            Some(old_n) => {
                if !neighbor_runtime_equal(old_n, new_n) {
                    changed.push((*new_n).clone());
                }
            }
        }
    }

    let removed: Vec<rustbgpd_api::peer_types::PeerKey> = old_map
        .iter()
        .filter(|(key, _)| !new_map.contains_key(key))
        .filter_map(|((_addr, _interface), neighbor)| {
            neighbor.address.parse::<IpAddr>().ok().map(|address| {
                rustbgpd_api::peer_types::PeerKey::new(address, neighbor.interface.clone())
            })
        })
        .collect();

    NeighborDiff {
        added,
        removed,
        changed,
    }
}

fn neighbor_runtime_equal(old: &Neighbor, new: &Neighbor) -> bool {
    old.address == new.address
        && old.interface == new.interface
        && old.remote_asn == new.remote_asn
        && old.description == new.description
        && old.peer_group == new.peer_group
        && old.hold_time == new.hold_time
        && old.min_hold_time == new.min_hold_time
        && old.send_hold_time == new.send_hold_time
        && old.max_prefixes == new.max_prefixes
        && old.max_prefixes_ipv4 == new.max_prefixes_ipv4
        && old.max_prefixes_ipv6 == new.max_prefixes_ipv6
        && old.max_prefixes_out_ipv4 == new.max_prefixes_out_ipv4
        && old.max_prefixes_out_ipv6 == new.max_prefixes_out_ipv6
        && old.max_prefix_restart_seconds == new.max_prefix_restart_seconds
        && old.md5_password == new.md5_password
        && old.ttl_security == new.ttl_security
        && old.families == new.families
        && old.required_families == new.required_families
        && old.graceful_restart == new.graceful_restart
        && old.gr_restart_time == new.gr_restart_time
        && old.gr_peer_restart_time_max == new.gr_peer_restart_time_max
        && old.gr_stale_routes_time == new.gr_stale_routes_time
        && old.llgr_stale_time == new.llgr_stale_time
        && old.local_ipv6_nexthop == new.local_ipv6_nexthop
        && old.route_reflector_client == new.route_reflector_client
        && old.orr_vantage == new.orr_vantage
        && old.route_server_client == new.route_server_client
        && old.per_client_best == new.per_client_best
        && old.next_hop_ownership == new.next_hop_ownership
        && old.interpret_rfc1997 == new.interpret_rfc1997
        && old.rs_control_communities == new.rs_control_communities
        && old.role == new.role
        && old.strict_role == new.strict_role
        && old.prefix_orf_receive == new.prefix_orf_receive
        && old.disable_ipv4_unicast == new.disable_ipv4_unicast
        && old.remove_private_as == new.remove_private_as
        && old.add_path == new.add_path
        && old.log_level == new.log_level
        && old.import_policy == new.import_policy
        && old.export_policy == new.export_policy
        && old.import_policy_chain == new.import_policy_chain
        && old.export_policy_chain == new.export_policy_chain
}

/// Differences between two peer group maps, keyed by name.
#[derive(Debug, serde::Serialize)]
pub struct PeerGroupDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

/// Differences between two policy configurations.
#[derive(Debug, serde::Serialize)]
pub struct PolicyDiff {
    pub definitions_added: Vec<String>,
    pub definitions_removed: Vec<String>,
    pub definitions_changed: Vec<String>,
    pub neighbor_sets_added: Vec<String>,
    pub neighbor_sets_removed: Vec<String>,
    pub neighbor_sets_changed: Vec<String>,
    pub import_chain_changed: bool,
    pub export_chain_changed: bool,
    /// The `[policy] rpol_files` list or any referenced `.rpol` file's
    /// compiled content changed (ADR-0096). Reload-applied: chains
    /// referencing rpol policies re-resolve and hot-swap through the
    /// same live-policy path as `[policy.definitions]` edits.
    pub rpol_changed: bool,
}

impl PolicyDiff {
    pub fn has_changes(&self) -> bool {
        !self.definitions_added.is_empty()
            || !self.definitions_removed.is_empty()
            || !self.definitions_changed.is_empty()
            || !self.neighbor_sets_added.is_empty()
            || !self.neighbor_sets_removed.is_empty()
            || !self.neighbor_sets_changed.is_empty()
            || self.import_chain_changed
            || self.export_chain_changed
            || self.rpol_changed
    }
}

/// Full config diff result.
#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, serde::Serialize)]
pub struct ConfigDiff {
    pub neighbors: NeighborDiffSummary,
    /// Neighbors whose effective config — after peer-group inheritance
    /// and policy-chain resolution — differs between old and new
    /// configs, even though their direct neighbor record may be
    /// unchanged. Surfaces inheritance-driven impact: a peer-group or
    /// policy edit that flows down to existing members shows up here,
    /// not just in the raw `peer_groups` / `policy` diffs.
    pub effective_neighbor_impact: Vec<EffectiveNeighborImpact>,
    pub peer_groups: PeerGroupDiff,
    pub peer_group_details: Vec<(String, Vec<FieldChange>)>,
    pub policy: PolicyDiff,
    /// `[global] honor_graceful_shutdown` changed. This is
    /// reload-applied through the peer manager, not restart-required.
    pub honor_graceful_shutdown_changed: bool,
    /// `[global] honor_blackhole` changed in the control-plane-only
    /// case. When BLACKHOLE FIB discard is enabled or requested, the
    /// same raw edit is represented by `blackhole_fib_discard_changed`
    /// instead because it affects the startup-only reconciler spawn
    /// gate.
    pub honor_blackhole_changed: bool,
    pub global_changed: bool,
    /// `[global] ebgp_requires_policy` changed. Already covered by the coarse
    /// `global_changed` restart bucket; tracked separately so receipts can name
    /// the field instead of only the section. ADR-0112 requires the RFC 8212
    /// enforcement mode to be named explicitly, because the running mode stays
    /// at its startup value while the on-disk candidate reads differently.
    pub ebgp_requires_policy_changed: bool,
    pub rpki_changed: bool,
    pub bmp_changed: bool,
    /// `[gnmi_dialout]` changed. Reload-applied: the dial-out manager
    /// diffs the target set on SIGHUP — removed targets stop (their
    /// `gnmi_dialout_connected` series is reaped), added targets start,
    /// changed targets redial, unchanged targets keep their connection.
    pub gnmi_dialout_changed: bool,
    pub mrt_changed: bool,
    /// `[[evpn_instances]]` blocks added/removed/modified between old and
    /// new. Surfaced as restart-required today — the Phase-2 foundation
    /// slice has no SIGHUP reconcile path; mutation lands with kernel
    /// reconciliation. Flagging here ensures `--diff` operators don't
    /// silently miss schema edits.
    pub evpn_instances_changed: bool,
    /// `[[evpn_ip_vrfs]]` blocks added/removed/modified between old
    /// and new. Gate 9's foundation slice validates this schema at
    /// startup but has no runtime swap/reconcile surface, so edits are
    /// restart-required and must remain visible across SIGHUPs.
    pub evpn_ip_vrfs_changed: bool,
    /// `[[ethernet_segments]]` blocks added/removed/modified between
    /// old and new. The segment orchestrator resolves this table once
    /// at startup, so edits are restart-required until a runtime swap
    /// surface exists.
    pub ethernet_segments_changed: bool,
    /// `[managed_netdevs]` changed. ADR-0091 v1 reads this table at
    /// startup and reports status from the Linux dataplane actor; live
    /// lifecycle changes are restart-required until the managed-netdev
    /// executor lands.
    pub managed_netdevs_changed: bool,
    /// `[security.grpc]` (enforcement mode / principal roles) changed.
    /// The authorization context is built once per listener at startup,
    /// so edits are restart-required and must remain visible in `--diff`.
    pub security_grpc_changed: bool,
    /// `[event_history]` changed. The ADR-0072 durable outbox is
    /// configured once at startup (all fields are restart-required per
    /// the reload matrix), so edits must remain visible in `--diff`.
    pub event_history_changed: bool,
    /// `[[fib_tables]]` blocks added/removed/modified between old and new.
    /// Reload-applied in the common case: the ADR-0061 general-FIB actor
    /// accepts a runtime table-set swap on SIGHUP
    /// (`FibRuntimeCommand::ReplaceTables`), so edits hot-apply when the
    /// reconciler is running. The one exception the static diff *can* know is
    /// the startup-from-empty case — see [`Self::fib_tables_requires_restart`].
    pub fib_tables_changed: bool,
    /// The `[[fib_tables]]` change is the startup-from-empty (0→N) case: old
    /// had no tables, new has at least one. The reconciler is spawned only
    /// when ≥1 table is present at startup, so SIGHUP rejects this as
    /// restart-required (`src/reload.rs` logs it; the runtime cannot hot-start
    /// the actor). The static diff cannot predict a netlink spawn *failure*,
    /// but it can know the empty-startup case, so it classifies 0→N as
    /// restart-required to match the runtime. All other edits (N→M, N→0) stay
    /// reload-applied.
    pub fib_tables_requires_restart: bool,
    /// `[[dynamic_neighbors]]` blocks added/removed/modified between old and
    /// new. Reload-applied by replacing the peer-manager config snapshot and
    /// rebuilding the live longest-prefix matcher.
    pub dynamic_neighbors_changed: bool,
    /// The portion of a dynamic-neighbor edit that remains after startup-only
    /// TCP-AO ranges are pinned back to the live listener snapshot.
    pub dynamic_neighbors_reload_applied_changed: bool,
    /// The startup-pinned dynamic TCP-AO protected range set changed. Any
    /// add/remove/move, protected-row edit, or key-material rotation requires
    /// a daemon restart before the listener and matcher can advance together.
    pub dynamic_neighbor_tcp_ao_changed: bool,
    /// Top-level Gate 8b kernel-enforcement opt-in changed. The
    /// dataplane actor reads this once at startup, so SIGHUP must not
    /// silently advance the in-memory snapshot.
    pub apply_bum_enforcement_changed: bool,
    /// `[global] install_blackhole_discard`,
    /// `[global] allow_blackhole_broad_prefixes`, or the
    /// `honor_blackhole` component of an enabled/requested FIB
    /// discard spawn gate changed. The BLACKHOLE FIB actor is spawned
    /// once at startup, so edits are restart-required and must remain
    /// visible in `--diff`.
    pub blackhole_fib_discard_changed: bool,
    /// Static-neighbor TCP-AO startup keys changed. The active and
    /// passive sockets install MKTs only at peer/listener creation, so
    /// edits require a daemon restart until runtime listener key
    /// rotation exists.
    pub neighbor_tcp_ao_changed: bool,
    /// Effective BFD session set changed — `[[bfd_profiles]]` referenced by a
    /// live session, or a neighbor/peer-group `bfd` block. The ADR-0067 BFD
    /// actor resolves its session set once at startup, so edits are
    /// restart-required until actor reconfiguration is implemented and must
    /// remain visible in `--diff`.
    pub bfd_changed: bool,
    /// `[policy.explain]` (`enabled` / `cache_size`, ADR-0073) changed.
    /// These are read by `build_transport_config` / `resolve_neighbor`
    /// when a session is constructed, so they do not hot-apply to live
    /// sessions — surfaced as restart-required (the new value reaches a
    /// peer only on its next session establishment). Diagnostic
    /// retention only; never affects which routes are accepted.
    pub policy_explain_changed: bool,
    /// `[policy.reject_retention]` (`enabled` / `capacity`, LAN-472)
    /// changed. Same restart-required-per-peer contract as
    /// `[policy.explain]`: read at session construction, diagnostic
    /// retention only.
    pub policy_reject_retention_changed: bool,
    /// Shape-aware ADR-0063 / ADR-0085 classification for EVPN runtime
    /// table changes. The raw `evpn_*_changed` booleans above still say
    /// which TOML tables moved; this field says whether SIGHUP can route
    /// that specific shape through the EVPN runtime coordinator or must
    /// leave it restart-required.
    pub evpn_runtime_change_class: EvpnRuntimeChangeClass,
}

/// Static SIGHUP classification for EVPN runtime table edits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvpnRuntimeChangeClass {
    /// No `[[evpn_instances]]`, `[[evpn_ip_vrfs]]`, or
    /// `[[ethernet_segments]]` TOML changed.
    Unchanged,
    /// The edit is in an ADR-0063/0085 shape the runtime coordinator
    /// can hot-apply on SIGHUP, subject to the live actor being
    /// present and accepting the candidate.
    ReloadApplied,
    /// The edit is a mixed shape the #268 plan decomposer splits into
    /// `steps` ordered primitive plans, each committed by SIGHUP as its
    /// own runtime generation (operators see `steps` generations for
    /// one reload).
    ReloadAppliedDecomposed { steps: usize },
    /// The edit is a generic/mixed/identity shape the current
    /// runtime coordinator rejects, or the diff could not resolve a
    /// typed EVPN model defensively. A restart is required.
    RestartRequired,
}

impl EvpnRuntimeChangeClass {
    const fn is_reload_applied(self) -> bool {
        matches!(
            self,
            Self::ReloadApplied | Self::ReloadAppliedDecomposed { .. }
        )
    }

    /// Number of decomposed primitive steps when the edit hot-applies
    /// via the #268 plan decomposer.
    const fn decomposed_steps(self) -> Option<usize> {
        match self {
            Self::ReloadAppliedDecomposed { steps } => Some(steps),
            _ => None,
        }
    }

    const fn is_restart_required(self) -> bool {
        matches!(self, Self::RestartRequired)
    }
}

/// Per-neighbor impact derived from inheritance / chain resolution.
///
/// `reasons` is a short list of upstream changes that flow down to
/// this neighbor. Possible entries (subset, not exhaustive):
///
/// - `"import policy resolved differently"` — the resolved import
///   chain (peer-group inherited + neighbor inline + global) moved.
/// - `"export policy resolved differently"` — same, for export.
/// - `"peer_group \"X\" changed"` — the named peer-group this
///   neighbor belongs to had a field edit that flows down (no
///   reassignment, just the group's record moved).
/// - `"peer_group resolved as <new> (was <old>)"` — the neighbor was
///   reassigned to a different peer-group.
/// - `"policy \"foo\" changed"` — a named policy referenced via the
///   neighbor's chain or peer-group's chain moved.
/// - `"global import/export chain changed"` — the top-level chain
///   reference list was edited.
/// - `"referenced neighbor_set changed"` — a `neighbor_set` edit
///   may reshape match results for any policy that uses it
///   (coarse: not resolved per neighbor).
///
/// The neighbor address may already appear in the raw `neighbors`
/// diff (added/removed/changed); the effective view is additive — it
/// catches the case where the raw record didn't move but the
/// resolved chain did.
///
/// Restart-required `[global]` / `[rpki]` / `[bmp]` / `[mrt]` edits
/// are deliberately excluded: those flow through different fields
/// (`local_asn`, `local_router_id` on `PeerConfig`) and reload
/// can't apply them, so surfacing them under `effective_neighbor_impact`
/// (which lands under "Reload-applied" in `--diff`) would mislead
/// operators into expecting a reload to absorb a restart-only edit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveNeighborImpactKind {
    /// The resolved import/export policy chain moved and can be handled by the
    /// live-policy transaction executor.
    PolicyChain,
    /// Resolved transport/session state or peer-group membership moved. These
    /// impacts route to the session reshape executor: static members get a
    /// rollback-capable in-place reconfigure; live dynamic sessions get a
    /// post-persist graceful reset and re-accept under the committed config.
    SessionReshape,
}

impl EffectiveNeighborImpactKind {
    /// True when this impact is a pure resolved import/export `PolicyChain`
    /// move that can be applied without rebuilding the session.
    pub const fn is_policy_chain(self) -> bool {
        matches!(self, Self::PolicyChain)
    }

    /// Stable `snake_case` label (matches the serde rename) for human-readable
    /// rendering and the `--diff` JSON.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PolicyChain => "policy_chain",
            Self::SessionReshape => "session_reshape",
        }
    }
}

#[derive(Debug, serde::Serialize)]
pub struct EffectiveNeighborImpact {
    pub address: String,
    pub reasons: Vec<String>,
    /// Operator-visible impact kind. `policy_chain` commits through the
    /// live-policy executor; `session_reshape` commits through the session
    /// reshape executor (static members are reconfigured in place, live
    /// dynamic sessions are gracefully reset to re-accept under the committed
    /// config) unless mixed with `policy_chain` impacts.
    pub kind: EffectiveNeighborImpactKind,
    /// True when `address` identifies a `[[dynamic_neighbors]]` range rather
    /// than a static neighbor. Skipped from `--diff`; used to route the
    /// impact to the matching executor arm (dynamic ranges expand to live
    /// sessions inside the peer manager rather than resolving to a static
    /// neighbor record).
    #[serde(skip)]
    pub is_dynamic_range: bool,
}

/// Serializable neighbor diff summary (`NeighborDiff` uses `IpAddr` which is fine,
/// but we want address strings + field-level details).
#[derive(Debug, serde::Serialize)]
pub struct NeighborDiffSummary {
    pub added: Vec<NeighborAddSummary>,
    pub removed: Vec<String>,
    pub changed: Vec<NeighborChangeSummary>,
}

#[derive(Debug, serde::Serialize)]
pub struct NeighborAddSummary {
    pub address: String,
    pub remote_asn: u32,
}

#[derive(Debug, serde::Serialize)]
pub struct NeighborChangeSummary {
    pub address: String,
    pub changes: Vec<FieldChange>,
}

impl ConfigDiff {
    /// Changes that SIGHUP will actually reconcile: neighbor
    /// add/remove/modify, plus policy / peer-group / neighbor-set /
    /// global-chain edits that flow down through inheritance.
    pub fn has_reload_applied_changes(&self) -> bool {
        !self.neighbors.added.is_empty()
            || !self.neighbors.removed.is_empty()
            || !self.neighbors.changed.is_empty()
            || !self.peer_groups.added.is_empty()
            || !self.peer_groups.removed.is_empty()
            || !self.peer_groups.changed.is_empty()
            || !self.policy.definitions_added.is_empty()
            || !self.policy.definitions_removed.is_empty()
            || !self.policy.definitions_changed.is_empty()
            || !self.policy.neighbor_sets_added.is_empty()
            || !self.policy.neighbor_sets_removed.is_empty()
            || !self.policy.neighbor_sets_changed.is_empty()
            || self.policy.import_chain_changed
            || self.policy.export_chain_changed
            || self.policy.rpol_changed
            || self.honor_graceful_shutdown_changed
            || self.honor_blackhole_changed
            || self.dynamic_neighbors_reload_applied_changed
            || self.gnmi_dialout_changed
            || (self.fib_tables_changed && !self.fib_tables_requires_restart)
            || self.evpn_runtime_change_class.is_reload_applied()
    }

    /// Changes that require a full daemon restart.
    pub fn has_restart_required_changes(&self) -> bool {
        self.global_changed
            || self.rpki_changed
            || self.bmp_changed
            || self.mrt_changed
            || self.evpn_runtime_change_class.is_restart_required()
            || self.apply_bum_enforcement_changed
            || self.blackhole_fib_discard_changed
            || self.neighbor_tcp_ao_changed
            || self.dynamic_neighbor_tcp_ao_changed
            || self.bfd_changed
            || self.policy_explain_changed
            || self.policy_reject_retention_changed
            || self.fib_tables_requires_restart
            || self.managed_netdevs_changed
            || self.security_grpc_changed
            || self.event_history_changed
    }

    /// Changes detected but not applied by current SIGHUP. Empty
    /// post the policy / peer-group / chain reload work — kept on
    /// the public surface as a stable predicate so external diff
    /// consumers don't break, and as a hook for future "detected but
    /// not yet applied" buckets (e.g., when a future TOML field
    /// lands ahead of its reload wiring).
    #[expect(
        clippy::unused_self,
        reason = "method preserved on the public surface for external --diff consumers; will gain logic when a future field lands ahead of its reload wiring"
    )]
    pub const fn has_informational_changes(&self) -> bool {
        false
    }

    /// Whether SIGHUP would take any action (reload-applied or restart-required).
    pub fn has_actionable_changes(&self) -> bool {
        self.has_reload_applied_changes() || self.has_restart_required_changes()
    }

    /// Whether any difference exists at all.
    pub fn has_any_changes(&self) -> bool {
        self.has_actionable_changes() || self.has_informational_changes()
    }

    /// Distinct config entries (static neighbors or dynamic ranges) whose
    /// live session(s) the classifiers say will reset when this diff is
    /// applied: changed neighbors with at least one session-reset-class
    /// field edit, plus inheritance-driven session-reshape impacts. Counts
    /// config entries, not live TCP sessions (a dynamic range counts once
    /// however many sessions it currently holds).
    pub fn session_reset_entries(&self) -> usize {
        let mut addresses: std::collections::BTreeSet<&str> = self
            .neighbors
            .changed
            .iter()
            .filter(|change| change.changes.iter().any(FieldChange::resets_session))
            .map(|change| change.address.as_str())
            .collect();
        addresses.extend(
            self.effective_neighbor_impact
                .iter()
                .filter(|impact| !impact.kind.is_policy_chain())
                .map(|impact| impact.address.as_str()),
        );
        addresses.len()
    }
}

/// Terraform-style rollup line for the human diff: neighbor
/// add/change/remove counts, the session-reset count from
/// [`ConfigDiff::session_reset_entries`], and whether a daemon restart is
/// required for part of the change.
fn plan_summary_line(diff: &ConfigDiff) -> String {
    use std::fmt::Write as _;

    let mut counts = Vec::new();
    let added = diff.neighbors.added.len();
    let changed = diff.neighbors.changed.len();
    let removed = diff.neighbors.removed.len();
    if added > 0 {
        counts.push(format!("{added} to add"));
    }
    if changed > 0 {
        counts.push(format!("{changed} to change"));
    }
    if removed > 0 {
        counts.push(format!("{removed} to remove"));
    }
    if counts.is_empty() {
        counts.push("no neighbor changes".to_string());
    }
    let mut line = format!("Plan: {}", counts.join(", "));
    let resets = diff.session_reset_entries();
    match resets {
        // A restart-required change resets every session anyway, so a
        // "no session resets" claim would mislead.
        0 if !diff.has_restart_required_changes() => {
            line.push_str(" · no session resets expected");
        }
        0 => {}
        1 => line.push_str(" · 1 session will reset"),
        n => {
            let _ = write!(line, " · {n} sessions will reset");
        }
    }
    if diff.has_restart_required_changes() {
        line.push_str(" · daemon restart required for some changes");
    }
    line
}

/// Section-level v1 transaction support classification.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[expect(
    clippy::struct_field_names,
    reason = "field names mirror ConfigTransactionPlanResponse proto repeated fields"
)]
pub struct ConfigTransactionSectionClassification {
    /// Sections the v1 transaction model can commit atomically.
    pub supported_sections: Vec<String>,
    /// Hot-reloadable sections that are intentionally outside v1's commit
    /// executor set.
    pub unsupported_sections: Vec<String>,
    /// Sections that still require a daemon restart.
    pub restart_required_sections: Vec<String>,
}

impl ConfigTransactionSectionClassification {
    /// The candidate contains no differences.
    pub fn is_noop(&self) -> bool {
        self.supported_sections.is_empty()
            && self.unsupported_sections.is_empty()
            && self.restart_required_sections.is_empty()
    }

    /// The candidate is wholly inside v1's supported commit surface.
    pub fn is_committable(&self) -> bool {
        !self.supported_sections.is_empty()
            && self.unsupported_sections.is_empty()
            && self.restart_required_sections.is_empty()
    }
}

/// Per-process key for the optimistic config-transaction snapshot token.
///
/// The snapshot token is a change detector handed to `sensitive_read` plan
/// callers — not a credential or a config document. But hashing the canonical
/// config *unkeyed* would turn it into an offline oracle: the serialization
/// includes secret-bearing fields (`md5_password`, `tcp_ao.key`), so a caller
/// who already knows the rest of the config could brute-force a weak secret by
/// hashing guesses and matching the returned token. A per-process random key
/// closes that — without the key a caller cannot recompute the digest for a
/// guessed secret. The full config (secrets included) is still hashed, so a
/// secret rotation invalidates a stale plan.
///
/// The key is seeded once when the peer manager is constructed and never leaves
/// the process, so tokens are **process-local**: a token does not survive a
/// daemon restart, and a client holding a pre-restart token must re-plan (apply
/// returns `FAILED_PRECONDITION` on mismatch). Plan and apply both run in this
/// process against the same peer-manager key, so they compare correctly within
/// a daemon lifetime.
#[derive(Clone)]
pub struct RuntimeSnapshotKey(std::collections::hash_map::RandomState);

impl std::fmt::Debug for RuntimeSnapshotKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the key material.
        f.write_str("RuntimeSnapshotKey(<redacted>)")
    }
}

impl RuntimeSnapshotKey {
    /// Seed a fresh per-process key from the OS RNG (via `RandomState`).
    #[must_use]
    pub fn random() -> Self {
        Self(std::collections::hash_map::RandomState::new())
    }

    /// Compact, process-local identity for a canonical hashable context.
    ///
    /// Uses the same secret per-process key material as runtime snapshot
    /// tokens, so config-controlled context fields cannot cheaply construct a
    /// collision in an unkeyed pre-hash. The fixed-width result avoids
    /// materializing large debug or serialization strings.
    pub(crate) fn digest_context<T: std::hash::Hash>(&self, context: &T) -> [u8; 8] {
        use std::hash::BuildHasher;
        self.0.hash_one(context).to_be_bytes()
    }

    /// Keyed change-detector token for `config`. Hashes the canonical TOML
    /// serialization under this key, so the token changes when any config byte
    /// relevant to a candidate changes (secrets included) but cannot be
    /// reproduced by a caller who does not hold the key.
    #[cfg(test)]
    pub fn token(&self, config: &Config) -> Result<String, String> {
        self.token_with_context(config, &[])
    }

    /// Keyed token additionally bound to a canonical live-runtime context.
    pub fn token_with_context(&self, config: &Config, context: &[u8]) -> Result<String, String> {
        use std::hash::{BuildHasher, Hasher};
        // Canonical because `toml::Value::Table` is `BTreeMap`-backed (keys
        // sorted) unless toml's `preserve_order` feature is enabled, which it is
        // not here. That makes the token independent of `HashMap` insertion
        // order for map-valued config (peer_groups, roles, policy definitions,
        // neighbor_sets). If `preserve_order` is ever turned on, this token
        // would silently become order-dependent — re-establish canonicalization
        // (e.g. sort) before doing so.
        let canonical = toml::Value::try_from(config)
            .map_err(|error| format!("failed to canonicalize runtime config snapshot: {error}"))?;
        let normalized = toml::to_string_pretty(&canonical)
            .map_err(|error| format!("failed to serialize runtime config snapshot: {error}"))?;
        let mut hasher = self.0.build_hasher();
        hasher.write(normalized.as_bytes());
        hasher.write_usize(context.len());
        hasher.write(context);
        let digest = hasher.finish();
        // The token deliberately carries no length of the normalized
        // rendering: that length varies with secret bytes (md5_password,
        // tcp_ao keys), so encoding it would leak secret length to any
        // token holder. Tokens are only equality-compared against tokens
        // minted by this same in-process key, so the keyed digest alone is
        // the change detector.
        if context.is_empty() {
            Ok(format!("kv1:{digest:016x}"))
        } else {
            Ok(format!("kv2:{digest:016x}:{}", context.len()))
        }
    }
}

/// Placeholder emitted in place of secret material by the effective-config
/// dump (`rbgp config effective`). `Config::validate` rejects it loudly so a
/// dumped config with secrets cannot silently boot with the placeholder as a
/// live credential.
pub const REDACTED_SECRET: &str = "<redacted>";

impl Config {
    /// The running post-defaults config for `rbgp config effective`:
    /// a clone of this config with per-neighbor session defaults
    /// materialized (peer-group inheritance and computed defaults such
    /// as `hold_time`, `min_hold_time`, and RFC 9687 `send_hold_time` resolved to the
    /// values the daemon is using) and secret material replaced with
    /// [`REDACTED_SECRET`].
    ///
    /// Peer-group and dynamic-neighbor rows are shown as written —
    /// their values resolve per-session; static `[[neighbors]]` rows
    /// carry the resolved values. Fields whose absence *is* the
    /// effective value (`max_prefixes` unset = unlimited,
    /// `remove_private_as` unset = disabled) stay absent.
    ///
    /// The default constants below are pinned to `resolve_neighbor` by
    /// the `effective_redacted_matches_resolve_neighbor` config test,
    /// so they cannot drift silently.
    #[must_use]
    #[expect(
        clippy::too_many_lines,
        reason = "one inheritance/default chain per materialized neighbor field; splitting would scatter the pins"
    )]
    pub fn effective_redacted(&self) -> Config {
        let mut effective = self.clone();

        for neighbor in &mut effective.neighbors {
            // Runtime configs are validated, so referenced groups exist;
            // a dangling reference just skips inheritance here.
            let group = self.peer_group_for_neighbor(neighbor).unwrap_or(None);
            let hold_time = neighbor
                .hold_time
                .or_else(|| group.and_then(|g| g.hold_time))
                .unwrap_or(DEFAULT_HOLD_TIME);
            neighbor.hold_time = Some(hold_time);
            neighbor.min_hold_time = neighbor
                .min_hold_time
                .or_else(|| group.and_then(|g| g.min_hold_time));
            neighbor.send_hold_time = Some(
                neighbor
                    .send_hold_time
                    .or_else(|| group.and_then(|g| g.send_hold_time))
                    .unwrap_or_else(|| rustbgpd_fsm::default_send_hold_time(hold_time)),
            );
            neighbor.graceful_restart = Some(
                neighbor
                    .graceful_restart
                    .or_else(|| group.and_then(|g| g.graceful_restart))
                    .unwrap_or(true),
            );
            neighbor.gr_restart_time = Some(
                neighbor
                    .gr_restart_time
                    .or_else(|| group.and_then(|g| g.gr_restart_time))
                    .unwrap_or(120),
            );
            neighbor.gr_peer_restart_time_max = Some(
                neighbor
                    .gr_peer_restart_time_max
                    .or_else(|| group.and_then(|g| g.gr_peer_restart_time_max))
                    .unwrap_or(4095),
            );
            neighbor.gr_stale_routes_time = Some(
                neighbor
                    .gr_stale_routes_time
                    .or_else(|| group.and_then(|g| g.gr_stale_routes_time))
                    .unwrap_or(360),
            );
            neighbor.llgr_stale_time = Some(
                neighbor
                    .llgr_stale_time
                    .or_else(|| group.and_then(|g| g.llgr_stale_time))
                    .unwrap_or(0),
            );
            neighbor.ttl_security = Some(
                neighbor
                    .ttl_security
                    .or_else(|| group.and_then(|g| g.ttl_security))
                    .unwrap_or(false),
            );
            neighbor.max_prefixes = neighbor
                .max_prefixes
                .or_else(|| group.and_then(|g| g.max_prefixes));
            neighbor.max_prefixes_ipv4 = neighbor
                .max_prefixes_ipv4
                .or_else(|| group.and_then(|g| g.max_prefixes_ipv4));
            neighbor.max_prefixes_ipv6 = neighbor
                .max_prefixes_ipv6
                .or_else(|| group.and_then(|g| g.max_prefixes_ipv6));
            neighbor.max_prefixes_out_ipv4 = neighbor
                .max_prefixes_out_ipv4
                .or_else(|| group.and_then(|g| g.max_prefixes_out_ipv4));
            neighbor.max_prefixes_out_ipv6 = neighbor
                .max_prefixes_out_ipv6
                .or_else(|| group.and_then(|g| g.max_prefixes_out_ipv6));
            neighbor.max_prefix_restart_seconds = neighbor
                .max_prefix_restart_seconds
                .or_else(|| group.and_then(|g| g.max_prefix_restart_seconds));
            neighbor.route_reflector_client = Some(
                neighbor
                    .route_reflector_client
                    .or_else(|| group.and_then(|g| g.route_reflector_client))
                    .unwrap_or(false),
            );
            neighbor.route_server_client = Some(
                neighbor
                    .route_server_client
                    .or_else(|| group.and_then(|g| g.route_server_client))
                    .unwrap_or(false),
            );
            neighbor.per_client_best = Some(
                neighbor
                    .per_client_best
                    .or_else(|| group.and_then(|g| g.per_client_best))
                    .unwrap_or(false),
            );
            // ADR-0107: unset means no ownership enforcement, so the
            // effective value stays an honest Option (no Some-wrapping
            // of a default).
            neighbor.next_hop_ownership = neighbor
                .next_hop_ownership
                .or_else(|| group.and_then(|g| g.next_hop_ownership));
            // After route_server_client above so the derived default
            // reads the resolved value.
            neighbor.interpret_rfc1997 = Some(
                neighbor
                    .interpret_rfc1997
                    .or_else(|| group.and_then(|g| g.interpret_rfc1997))
                    .unwrap_or_else(|| neighbor.route_server_client != Some(true)),
            );
            neighbor.rs_control_communities = Some(
                neighbor
                    .rs_control_communities
                    .or_else(|| group.and_then(|g| g.rs_control_communities))
                    .unwrap_or_else(|| neighbor.route_server_client == Some(true)),
            );
            neighbor.strict_role = Some(
                neighbor
                    .strict_role
                    .or_else(|| group.and_then(|g| g.strict_role))
                    .unwrap_or(false),
            );
            neighbor.prefix_orf_receive = Some(
                neighbor
                    .prefix_orf_receive
                    .or_else(|| group.and_then(|g| g.prefix_orf_receive))
                    .unwrap_or(false),
            );
            neighbor.disable_ipv4_unicast = Some(
                neighbor
                    .disable_ipv4_unicast
                    .or_else(|| group.and_then(|g| g.disable_ipv4_unicast))
                    .unwrap_or(false),
            );
            if neighbor.required_families.is_empty()
                && let Some(group_required) = group
                    .map(|g| &g.required_families)
                    .filter(|families| !families.is_empty())
            {
                neighbor.required_families.clone_from(group_required);
            }
            if neighbor.families.is_empty() {
                if let Some(group_families) = group.map(|g| &g.families).filter(|f| !f.is_empty()) {
                    neighbor.families.clone_from(group_families);
                } else {
                    neighbor.families.push("ipv4_unicast".to_string());
                    if neighbor
                        .address
                        .parse::<IpAddr>()
                        .is_ok_and(|addr| addr.is_ipv6())
                    {
                        neighbor.families.push("ipv6_unicast".to_string());
                    }
                }
            }
        }

        // Redact secret material everywhere it appears in the schema:
        // neighbor/dynamic-range tcp_ao.key, neighbor md5_password, and
        // peer-group md5_password.
        for neighbor in &mut effective.neighbors {
            if neighbor.md5_password.is_some() {
                neighbor.md5_password = Some(REDACTED_SECRET.to_string());
            }
            if let Some(tcp_ao) = &mut neighbor.tcp_ao {
                for key in &mut tcp_ao.0 {
                    key.key = REDACTED_SECRET.to_string();
                }
            }
        }
        for group in effective.peer_groups.values_mut() {
            if group.md5_password.is_some() {
                group.md5_password = Some(REDACTED_SECRET.to_string());
            }
        }
        for range in &mut effective.dynamic_neighbors {
            if let Some(tcp_ao) = &mut range.tcp_ao {
                for key in &mut tcp_ao.0 {
                    key.key = REDACTED_SECRET.to_string();
                }
            }
        }

        effective
    }

    /// Deterministic TOML rendering of [`Config::effective_redacted`].
    /// Canonicalized through `toml::Value` (BTreeMap-backed, keys
    /// sorted) exactly like the runtime snapshot token, so the output
    /// is stable across `HashMap` iteration orders.
    pub fn effective_redacted_toml(&self) -> Result<String, String> {
        let canonical = toml::Value::try_from(self.effective_redacted())
            .map_err(|error| format!("failed to canonicalize effective config: {error}"))?;
        toml::to_string_pretty(&canonical)
            .map_err(|error| format!("failed to serialize effective config: {error}"))
    }
}

/// Classify a validated config diff for the v1 config transaction model.
///
/// This deliberately does not mirror all SIGHUP reload-applied sections. The
/// transaction model needs an atomic executor for each section it claims; PR1
/// only exposes the validate-only planner and the safe surface that later PRs
/// will execute.
#[expect(
    clippy::too_many_lines,
    reason = "section classifier intentionally lists every diff bucket explicitly"
)]
pub fn classify_config_transaction_v1(diff: &ConfigDiff) -> ConfigTransactionSectionClassification {
    let mut class = ConfigTransactionSectionClassification::default();

    if !diff.neighbors.added.is_empty() {
        class
            .supported_sections
            .push(TRANSACTION_NEIGHBOR_ADD_SECTION.to_string());
    }
    if !diff.neighbors.removed.is_empty() {
        class
            .supported_sections
            .push(TRANSACTION_NEIGHBOR_DELETE_SECTION.to_string());
    }
    if !diff.neighbors.changed.is_empty() {
        class
            .supported_sections
            .push(TRANSACTION_NEIGHBOR_MODIFY_SECTION.to_string());
    }
    if diff.dynamic_neighbors_changed && !diff.dynamic_neighbor_tcp_ao_changed {
        class
            .supported_sections
            .push(TRANSACTION_DYNAMIC_SECTION.to_string());
    }
    if diff.fib_tables_changed && !diff.fib_tables_requires_restart {
        class
            .supported_sections
            .push(TRANSACTION_FIB_SECTION.to_string());
    }
    if !diff.policy.definitions_added.is_empty()
        || !diff.policy.definitions_removed.is_empty()
        || !diff.policy.definitions_changed.is_empty()
    {
        class
            .supported_sections
            .push(TRANSACTION_POLICY_DEFINITIONS_SECTION.to_string());
    }
    if !diff.policy.neighbor_sets_added.is_empty()
        || !diff.policy.neighbor_sets_removed.is_empty()
        || !diff.policy.neighbor_sets_changed.is_empty()
    {
        class
            .supported_sections
            .push(TRANSACTION_POLICY_NEIGHBOR_SETS_SECTION.to_string());
    }
    if diff.policy.import_chain_changed || diff.policy.export_chain_changed {
        class
            .supported_sections
            .push(TRANSACTION_POLICY_GLOBAL_CHAINS_SECTION.to_string());
    }
    if !diff.peer_groups.added.is_empty()
        || !diff.peer_groups.removed.is_empty()
        || !diff.peer_groups.changed.is_empty()
    {
        class
            .supported_sections
            .push(TRANSACTION_PEER_GROUP_CATALOG_SECTION.to_string());
    }
    if !diff.effective_neighbor_impact.is_empty() {
        // A live-impact transaction is committable only when every impacted
        // entry belongs to one executor family. Pure resolved-policy-chain
        // moves use the live-policy executor. Session reshapes use the peer
        // reconfigure executor: static members are reconfigured in place with
        // captured priors, and live dynamic sessions are gracefully reset
        // after persist so they re-accept under the committed config. Mixed
        // policy/session impacts remain rejected until they have a combined
        // rollback story.
        let all_policy_chain = diff
            .effective_neighbor_impact
            .iter()
            .all(|impact| impact.kind.is_policy_chain());
        if all_policy_chain {
            class
                .supported_sections
                .push(TRANSACTION_POLICY_LIVE_IMPACT_SECTION.to_string());
        } else if session_reshape_transaction(diff) {
            class
                .supported_sections
                .push(TRANSACTION_SESSION_RESHAPE_SECTION.to_string());
        } else if diff
            .effective_neighbor_impact
            .iter()
            .any(|impact| !impact.kind.is_policy_chain())
        {
            class
                .unsupported_sections
                .push("effective neighbor inheritance impact".to_string());
        }
    }
    if !transaction_sections_are_one_family(&class.supported_sections) {
        class
            .unsupported_sections
            .push("mixed transaction families".to_string());
    }
    if diff.policy.rpol_changed {
        // No v1 transaction executor owns the .rpol file catalog — the
        // files live outside the candidate TOML, so a transaction
        // cannot atomically stage their content. Apply .rpol changes
        // via SIGHUP reload (which re-reads and hot-swaps them).
        class
            .unsupported_sections
            .push("[policy] rpol_files (apply .rpol changes via SIGHUP reload)".to_string());
    }
    if diff.honor_graceful_shutdown_changed {
        class
            .unsupported_sections
            .push("[global].honor_graceful_shutdown".to_string());
    }
    if diff.honor_blackhole_changed {
        class
            .unsupported_sections
            .push("[global].honor_blackhole".to_string());
    }
    if diff.evpn_runtime_change_class.is_reload_applied() {
        class
            .unsupported_sections
            .push("EVPN runtime coordinator".to_string());
    }
    if diff.gnmi_dialout_changed {
        class
            .unsupported_sections
            .push("[gnmi_dialout] (apply via SIGHUP reload)".to_string());
    }

    if diff.global_changed {
        class.restart_required_sections.push("[global]".to_string());
    }
    if diff.ebgp_requires_policy_changed {
        // ADR-0112: name the RFC 8212 enforcement mode, not just `[global]`.
        // The candidate is rejected outright rather than partly adopted, so the
        // running enforcement mode stays at its startup value.
        class
            .restart_required_sections
            .push("[global].ebgp_requires_policy".to_string());
    }
    if diff.rpki_changed {
        class.restart_required_sections.push("[rpki]".to_string());
    }
    if diff.bmp_changed {
        class.restart_required_sections.push("[bmp]".to_string());
    }
    if diff.mrt_changed {
        class.restart_required_sections.push("[mrt]".to_string());
    }
    if diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_instances_changed {
        class
            .restart_required_sections
            .push("[[evpn_instances]]".to_string());
    }
    if diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_ip_vrfs_changed {
        class
            .restart_required_sections
            .push("[[evpn_ip_vrfs]]".to_string());
    }
    if diff.evpn_runtime_change_class.is_restart_required() && diff.ethernet_segments_changed {
        class
            .restart_required_sections
            .push("[[ethernet_segments]]".to_string());
    }
    if diff.fib_tables_requires_restart {
        class
            .restart_required_sections
            .push("[[fib_tables]] startup-from-empty".to_string());
    }
    if diff.managed_netdevs_changed {
        class
            .restart_required_sections
            .push("[managed_netdevs]".to_string());
    }
    if diff.security_grpc_changed {
        class
            .restart_required_sections
            .push("[security.grpc]".to_string());
    }
    if diff.event_history_changed {
        class
            .restart_required_sections
            .push("[event_history]".to_string());
    }
    if diff.apply_bum_enforcement_changed {
        class
            .restart_required_sections
            .push("apply_bum_enforcement".to_string());
    }
    if diff.blackhole_fib_discard_changed {
        class
            .restart_required_sections
            .push("BLACKHOLE FIB discard".to_string());
    }
    if diff.neighbor_tcp_ao_changed {
        class
            .restart_required_sections
            .push("[[neighbors]].tcp_ao".to_string());
    }
    if diff.dynamic_neighbor_tcp_ao_changed {
        class
            .restart_required_sections
            .push("[[dynamic_neighbors]].tcp_ao".to_string());
    }
    if diff.bfd_changed {
        class
            .restart_required_sections
            .push("[[bfd_profiles]] / neighbor BFD".to_string());
    }
    if diff.policy_explain_changed {
        class
            .restart_required_sections
            .push("[policy.explain]".to_string());
    }
    if diff.policy_reject_retention_changed {
        class
            .restart_required_sections
            .push("[policy.reject_retention]".to_string());
    }
    class
}

fn session_reshape_transaction(diff: &ConfigDiff) -> bool {
    if !diff.neighbors.added.is_empty() || !diff.neighbors.removed.is_empty() {
        return false;
    }
    // A `[[dynamic_neighbors]]` record edit (range add/remove, peer-group
    // reassignment) belongs to the dynamic-neighbor executor family, and a
    // reassigned range cannot be applied to sessions accepted under the old
    // group anyway — so any record-level dynamic change keeps the impact out
    // of the reshape family. With records unchanged, a dynamic-range
    // `SessionReshape` impact is a pure peer-group field reshape, which the
    // executor commits by gracefully resetting the affected live dynamic
    // sessions (they re-accept under the committed config on reconnect).
    if diff.dynamic_neighbors_changed {
        return false;
    }
    if !diff
        .effective_neighbor_impact
        .iter()
        .all(|impact| impact.kind == EffectiveNeighborImpactKind::SessionReshape)
    {
        return false;
    }
    if diff.neighbors.changed.is_empty() {
        return true;
    }
    let impacted: HashSet<&str> = diff
        .effective_neighbor_impact
        .iter()
        .map(|impact| impact.address.as_str())
        .collect();
    diff.neighbors
        .changed
        .iter()
        .all(|neighbor| impacted.contains(neighbor.address.as_str()))
}

fn transaction_sections_are_one_family(sections: &[String]) -> bool {
    let mut has_fib = false;
    let mut has_dynamic = false;
    let mut has_static_neighbor = false;
    let mut has_catalog = false;
    for section in sections {
        match section.as_str() {
            TRANSACTION_FIB_SECTION => has_fib = true,
            TRANSACTION_DYNAMIC_SECTION => has_dynamic = true,
            TRANSACTION_NEIGHBOR_ADD_SECTION
            | TRANSACTION_NEIGHBOR_DELETE_SECTION
            | TRANSACTION_NEIGHBOR_MODIFY_SECTION => {
                has_static_neighbor = true;
            }
            TRANSACTION_PEER_GROUP_CATALOG_SECTION
            | TRANSACTION_POLICY_DEFINITIONS_SECTION
            | TRANSACTION_POLICY_NEIGHBOR_SETS_SECTION
            | TRANSACTION_POLICY_GLOBAL_CHAINS_SECTION
            // The live-impact section co-occurs with the catalog record sections
            // it stems from (a policy/peer-group/chain edit), so it counts as
            // the same family rather than tripping the mixed-family guard.
            | TRANSACTION_POLICY_LIVE_IMPACT_SECTION => {
                has_catalog = true;
            }
            _ => {
                // `TRANSACTION_SESSION_RESHAPE_SECTION` is a family-neutral
                // modifier: it can stem from catalog inheritance (peer-group
                // field edit) or from a direct static neighbor peer-group
                // reassignment, so the underlying changed section decides the
                // family. Unknown sections are ignored here and rejected later
                // by the apply-family dispatcher if they ever reach apply.
            }
        }
    }
    u8::from(has_fib)
        + u8::from(has_dynamic)
        + u8::from(has_static_neighbor)
        + u8::from(has_catalog)
        <= 1
}

/// JSON schema shared by `rustbgpd --diff --json` and the live runtime
/// config-diff API. The schema mirrors the human diff buckets:
/// reload-applied, restart-required, and informational.
pub fn config_diff_json_value(diff: &ConfigDiff) -> serde_json::Value {
    serde_json::json!({
        "has_actionable_changes": diff.has_actionable_changes(),
        "has_informational_changes": diff.has_informational_changes(),
        "has_any_changes": diff.has_any_changes(),
        "evpn_runtime_change_class": diff.evpn_runtime_change_class,
        "summary": {
            "neighbors_added": diff.neighbors.added.len(),
            "neighbors_changed": diff.neighbors.changed.len(),
            "neighbors_removed": diff.neighbors.removed.len(),
            "sessions_will_reset": diff.session_reset_entries(),
            "restart_required": diff.has_restart_required_changes(),
        },
        "reload_applied": {
            "neighbors": &diff.neighbors,
            "peer_groups": &diff.peer_groups,
            "peer_group_details": &diff.peer_group_details,
            "policy_definitions_added": &diff.policy.definitions_added,
            "policy_definitions_removed": &diff.policy.definitions_removed,
            "policy_definitions_changed": &diff.policy.definitions_changed,
            "neighbor_sets_added": &diff.policy.neighbor_sets_added,
            "neighbor_sets_removed": &diff.policy.neighbor_sets_removed,
            "neighbor_sets_changed": &diff.policy.neighbor_sets_changed,
            "import_chain_changed": diff.policy.import_chain_changed,
            "export_chain_changed": diff.policy.export_chain_changed,
            "rpol_changed": diff.policy.rpol_changed,
            "honor_graceful_shutdown_changed": diff.honor_graceful_shutdown_changed,
            "honor_blackhole_changed": diff.honor_blackhole_changed,
            "dynamic_neighbors_changed": diff.dynamic_neighbors_reload_applied_changed,
            "gnmi_dialout_changed": diff.gnmi_dialout_changed,
            "fib_tables_changed": diff.fib_tables_changed && !diff.fib_tables_requires_restart,
            "evpn_runtime_changed": diff.evpn_runtime_change_class.is_reload_applied(),
            "evpn_instances_changed": diff.evpn_runtime_change_class.is_reload_applied() && diff.evpn_instances_changed,
            "evpn_ip_vrfs_changed": diff.evpn_runtime_change_class.is_reload_applied() && diff.evpn_ip_vrfs_changed,
            "ethernet_segments_changed": diff.evpn_runtime_change_class.is_reload_applied() && diff.ethernet_segments_changed,
            "effective_neighbor_impact": &diff.effective_neighbor_impact,
        },
        "restart_required": {
            "global_changed": diff.global_changed,
            "ebgp_requires_policy_changed": diff.ebgp_requires_policy_changed,
            "rpki_changed": diff.rpki_changed,
            "bmp_changed": diff.bmp_changed,
            "mrt_changed": diff.mrt_changed,
            "evpn_instances_changed": diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_instances_changed,
            "evpn_ip_vrfs_changed": diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_ip_vrfs_changed,
            "ethernet_segments_changed": diff.evpn_runtime_change_class.is_restart_required() && diff.ethernet_segments_changed,
            "managed_netdevs_changed": diff.managed_netdevs_changed,
            "security_grpc_changed": diff.security_grpc_changed,
            "event_history_changed": diff.event_history_changed,
            "fib_tables_requires_restart": diff.fib_tables_requires_restart,
            "apply_bum_enforcement_changed": diff.apply_bum_enforcement_changed,
            "blackhole_fib_discard_changed": diff.blackhole_fib_discard_changed,
            "neighbor_tcp_ao_changed": diff.neighbor_tcp_ao_changed,
            "dynamic_neighbor_tcp_ao_changed": diff.dynamic_neighbor_tcp_ao_changed,
            "bfd_changed": diff.bfd_changed,
            "policy_explain_changed": diff.policy_explain_changed,
            "policy_reject_retention_changed": diff.policy_reject_retention_changed,
        },
        "informational": serde_json::Value::Object(serde_json::Map::new()),
    })
}

/// Text styling hooks for config-diff renderers.
///
/// The default style is intentionally plain so API and `rbgp`
/// clients never receive terminal escape codes. The daemon CLI can pass
/// colored markers without duplicating the section logic.
pub struct ConfigDiffTextStyle<'a> {
    pub reload_header: std::borrow::Cow<'a, str>,
    pub restart_header: std::borrow::Cow<'a, str>,
    pub add_marker: std::borrow::Cow<'a, str>,
    pub remove_marker: std::borrow::Cow<'a, str>,
    pub change_marker: std::borrow::Cow<'a, str>,
    pub restart_marker: std::borrow::Cow<'a, str>,
    pub no_changes: std::borrow::Cow<'a, str>,
}

impl Default for ConfigDiffTextStyle<'_> {
    fn default() -> Self {
        Self {
            reload_header: "Reload-applied changes:".into(),
            restart_header: "Restart-required changes:".into(),
            add_marker: "+".into(),
            remove_marker: "-".into(),
            change_marker: "~".into(),
            restart_marker: "!".into(),
            no_changes: "No changes.".into(),
        }
    }
}

/// Plain-text config diff for API/CLI clients that should not receive
/// terminal color escapes. Secret-bearing values remain redacted by
/// the underlying `ConfigDiff` change descriptions.
pub fn format_config_diff(diff: &ConfigDiff) -> String {
    format_config_diff_with_style(diff, &ConfigDiffTextStyle::default())
}

/// Shared config-diff text renderer used by `rustbgpd --diff` and the
/// live runtime config-diff API. Only markers/headings are styleable;
/// section ordering and field coverage live in one place to avoid drift.
#[expect(
    clippy::too_many_lines,
    reason = "plain renderer intentionally mirrors the human config-diff sections"
)]
pub fn format_config_diff_with_style(diff: &ConfigDiff, style: &ConfigDiffTextStyle<'_>) -> String {
    use std::fmt::Write as _;

    let mut out = String::new();
    let has_pg_changes = !diff.peer_groups.added.is_empty()
        || !diff.peer_groups.removed.is_empty()
        || !diff.peer_groups.changed.is_empty();
    let p = &diff.policy;
    let has_named_policy_changes = !p.definitions_added.is_empty()
        || !p.definitions_removed.is_empty()
        || !p.definitions_changed.is_empty()
        || !p.neighbor_sets_added.is_empty()
        || !p.neighbor_sets_removed.is_empty()
        || !p.neighbor_sets_changed.is_empty()
        || p.import_chain_changed
        || p.export_chain_changed
        || p.rpol_changed;

    if diff.has_reload_applied_changes() {
        let _ = writeln!(out, "{}\n", style.reload_header);
        let raw_neighbor_changes = !diff.neighbors.added.is_empty()
            || !diff.neighbors.removed.is_empty()
            || !diff.neighbors.changed.is_empty();
        if raw_neighbor_changes {
            out.push_str("  Neighbors:\n");
            for n in &diff.neighbors.added {
                let _ = writeln!(
                    out,
                    "    {} {} (AS {})",
                    style.add_marker, n.address, n.remote_asn
                );
            }
            for addr in &diff.neighbors.removed {
                let _ = writeln!(out, "    {} {addr}", style.remove_marker);
            }
            for n in &diff.neighbors.changed {
                let _ = writeln!(out, "    {} {}:", style.change_marker, n.address);
                for change in &n.changes {
                    let _ = writeln!(out, "        {}", change.render());
                }
            }
            out.push('\n');
        }

        if has_pg_changes {
            out.push_str("  Peer groups:\n");
            for name in &diff.peer_groups.added {
                let _ = writeln!(out, "    {} {name}", style.add_marker);
            }
            for name in &diff.peer_groups.removed {
                let _ = writeln!(out, "    {} {name}", style.remove_marker);
            }
            for (name, details) in &diff.peer_group_details {
                let _ = writeln!(out, "    {} {name}:", style.change_marker);
                for change in details {
                    let _ = writeln!(out, "        {}", change.render());
                }
            }
            out.push('\n');
        }

        if has_named_policy_changes {
            out.push_str("  Policy:\n");
            for name in &p.definitions_added {
                let _ = writeln!(out, "    {} definition \"{name}\"", style.add_marker);
            }
            for name in &p.definitions_removed {
                let _ = writeln!(out, "    {} definition \"{name}\"", style.remove_marker);
            }
            for name in &p.definitions_changed {
                let _ = writeln!(out, "    {} definition \"{name}\"", style.change_marker);
            }
            for name in &p.neighbor_sets_added {
                let _ = writeln!(out, "    {} neighbor_set \"{name}\"", style.add_marker);
            }
            for name in &p.neighbor_sets_removed {
                let _ = writeln!(out, "    {} neighbor_set \"{name}\"", style.remove_marker);
            }
            for name in &p.neighbor_sets_changed {
                let _ = writeln!(out, "    {} neighbor_set \"{name}\"", style.change_marker);
            }
            if p.import_chain_changed {
                let _ = writeln!(out, "    {} import_chain", style.change_marker);
            }
            if p.export_chain_changed {
                let _ = writeln!(out, "    {} export_chain", style.change_marker);
            }
            if p.rpol_changed {
                let _ = writeln!(
                    out,
                    "    {} rpol_files / .rpol content",
                    style.change_marker
                );
            }
            out.push('\n');
        }

        if !diff.effective_neighbor_impact.is_empty() {
            out.push_str("  Effectively impacted neighbors (via inheritance):\n");
            for impact in &diff.effective_neighbor_impact {
                let _ = writeln!(
                    out,
                    "    {} {} [{}]:",
                    style.change_marker,
                    impact.address,
                    impact.kind.as_str()
                );
                for reason in &impact.reasons {
                    let _ = writeln!(out, "        {reason}");
                }
            }
            out.push('\n');
        }

        let mut hot_applied_global_flags = Vec::new();
        if diff.honor_graceful_shutdown_changed {
            hot_applied_global_flags.push("honor_graceful_shutdown");
        }
        if diff.honor_blackhole_changed {
            hot_applied_global_flags.push("honor_blackhole");
        }
        if !hot_applied_global_flags.is_empty() {
            out.push_str("  Global hot-applied flags:\n");
            for flag in hot_applied_global_flags {
                let _ = writeln!(out, "    {} {flag}", style.change_marker);
            }
            out.push('\n');
        }
        if diff.fib_tables_changed && !diff.fib_tables_requires_restart {
            let _ = writeln!(
                out,
                "  {} [[fib_tables]] hot-applied to the running FIB reconciler",
                style.change_marker
            );
        }
        if diff.dynamic_neighbors_reload_applied_changed {
            let _ = writeln!(
                out,
                "  {} [[dynamic_neighbors]] matcher rebuilt",
                style.change_marker
            );
        }
        if diff.gnmi_dialout_changed {
            let _ = writeln!(
                out,
                "  {} [gnmi_dialout] targets reconciled (removed stop, added start, \
                 changed redial)",
                style.change_marker
            );
        }
        if let Some(steps) = diff.evpn_runtime_change_class.decomposed_steps() {
            let _ = writeln!(
                out,
                "  {} EVPN runtime model hot-applied through the ADR-0063 coordinator \
                 (decomposed: {steps} steps, one runtime generation each)",
                style.change_marker
            );
        } else if diff.evpn_runtime_change_class.is_reload_applied() {
            let _ = writeln!(
                out,
                "  {} EVPN runtime model hot-applied through the ADR-0063 coordinator",
                style.change_marker
            );
        }
    }

    let mut restart_sections = Vec::new();
    if diff.global_changed {
        restart_sections.push("[global]");
    }
    if diff.ebgp_requires_policy_changed {
        restart_sections
            .push("[global].ebgp_requires_policy (RFC 8212 enforcement mode; running value stays at the startup value)");
    }
    if diff.rpki_changed {
        restart_sections.push("[rpki]");
    }
    if diff.bmp_changed {
        restart_sections.push("[bmp]");
    }
    if diff.mrt_changed {
        restart_sections.push("[mrt]");
    }
    if diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_instances_changed {
        restart_sections.push("[[evpn_instances]]");
    }
    if diff.evpn_runtime_change_class.is_restart_required() && diff.evpn_ip_vrfs_changed {
        restart_sections.push("[[evpn_ip_vrfs]]");
    }
    if diff.evpn_runtime_change_class.is_restart_required() && diff.ethernet_segments_changed {
        restart_sections.push("[[ethernet_segments]]");
    }
    if diff.managed_netdevs_changed {
        restart_sections.push("[managed_netdevs]");
    }
    if diff.security_grpc_changed {
        restart_sections.push("[security.grpc]");
    }
    if diff.event_history_changed {
        restart_sections.push("[event_history]");
    }
    if diff.fib_tables_requires_restart {
        restart_sections.push("[[fib_tables]] (start FIB from an empty config)");
    }
    if diff.apply_bum_enforcement_changed {
        restart_sections.push("apply_bum_enforcement");
    }
    if diff.blackhole_fib_discard_changed {
        restart_sections.push("BLACKHOLE FIB discard");
    }
    if diff.neighbor_tcp_ao_changed {
        restart_sections.push("[[neighbors]].tcp_ao");
    }
    if diff.dynamic_neighbor_tcp_ao_changed {
        restart_sections.push("[[dynamic_neighbors]].tcp_ao");
    }
    if diff.bfd_changed {
        restart_sections.push("[[bfd_profiles]] / [neighbors.bfd] / [peer_groups.*.bfd]");
    }
    if diff.policy_explain_changed {
        restart_sections.push("[policy.explain] (per-peer; applies on next session)");
    }
    if diff.policy_reject_retention_changed {
        restart_sections.push("[policy.reject_retention] (per-peer; applies on next session)");
    }
    if !restart_sections.is_empty() {
        let _ = writeln!(out, "{}", style.restart_header);
        for section in &restart_sections {
            let _ = writeln!(out, "  {} {section} changed", style.restart_marker);
        }
        out.push('\n');
    }

    if diff.has_any_changes() {
        let _ = writeln!(out, "{}", plan_summary_line(diff));
    } else {
        let _ = writeln!(out, "{}", style.no_changes);
    }
    out
}

/// Compare two full configurations and return a structured diff.
#[expect(
    clippy::too_many_lines,
    reason = "one flag computation per config section, kept together with the struct literal"
)]
pub fn diff_config(old: &Config, new: &Config) -> ConfigDiff {
    let neighbor_tcp_ao_changed = neighbor_tcp_ao_restart_required_changed(old, new);
    let dynamic_neighbor_tcp_ao_changed =
        dynamic_neighbor_tcp_ao_restart_required_changed(old, new);
    let mut dynamic_reload_new = new.clone();
    pin_dynamic_tcp_ao_startup_only(&mut dynamic_reload_new, old);
    let dynamic_neighbors_reload_applied_changed =
        old.dynamic_neighbors != dynamic_reload_new.dynamic_neighbors;
    let bfd_changed = bfd_restart_required_changed(old, new);
    let mut reload_new = new.clone();
    pin_tcp_ao_startup_only_runtime(&mut reload_new, old);
    // Pin BFD too so the hot-reload neighbor/peer-group diff does not report
    // startup-only BFD edits as if they apply live; the restart-required
    // surface is carried by `bfd_changed` above.
    pin_bfd_startup_only_runtime(&mut reload_new, old);
    let neighbor_diff = diff_neighbors(&old.neighbors, &reload_new.neighbors);

    let old_map: HashMap<&str, &Neighbor> = old
        .neighbors
        .iter()
        .map(|n| (n.address.as_str(), n))
        .collect();

    let neighbors = NeighborDiffSummary {
        added: neighbor_diff
            .added
            .iter()
            .map(|n| NeighborAddSummary {
                address: n.address.clone(),
                remote_asn: n.remote_asn,
            })
            .collect(),
        removed: neighbor_diff
            .removed
            .iter()
            .map(ToString::to_string)
            .collect(),
        changed: neighbor_diff
            .changed
            .iter()
            .filter_map(|n| {
                old_map
                    .get(n.address.as_str())
                    .map(|old_n| NeighborChangeSummary {
                        address: n.address.clone(),
                        changes: describe_neighbor_changes(old_n, n),
                    })
            })
            .collect(),
    };

    let peer_groups = diff_peer_groups(&old.peer_groups, &reload_new.peer_groups);
    let peer_group_details = peer_groups
        .changed
        .iter()
        .filter_map(|name| {
            let old_pg = old.peer_groups.get(name)?;
            let new_pg = reload_new.peer_groups.get(name)?;
            let changes = describe_peer_group_changes(old_pg, new_pg);
            if changes.is_empty() {
                None
            } else {
                Some((name.clone(), changes))
            }
        })
        .collect();

    let policy = diff_policy(&old.policy, &reload_new.policy);
    let effective_neighbor_impact =
        compute_effective_neighbor_impact(old, &reload_new, &peer_groups, &policy);
    let blackhole_fib_discard_changed = old.global.install_blackhole_discard
        != new.global.install_blackhole_discard
        || old.global.allow_blackhole_broad_prefixes != new.global.allow_blackhole_broad_prefixes
        || ((old.global.install_blackhole_discard || new.global.install_blackhole_discard)
            && old.global.honor_blackhole != new.global.honor_blackhole);
    let evpn_runtime_change_class = classify_evpn_runtime_change(old, new);

    ConfigDiff {
        neighbors,
        effective_neighbor_impact,
        peer_groups,
        peer_group_details,
        policy,
        honor_graceful_shutdown_changed: old.global.honor_graceful_shutdown
            != new.global.honor_graceful_shutdown,
        honor_blackhole_changed: old.global.honor_blackhole != new.global.honor_blackhole
            && !blackhole_fib_discard_changed,
        global_changed: global_restart_required_changed(old, new),
        ebgp_requires_policy_changed: old.global.ebgp_requires_policy
            != new.global.ebgp_requires_policy,
        rpki_changed: old.rpki != new.rpki,
        bmp_changed: old.bmp != new.bmp,
        gnmi_dialout_changed: old.gnmi_dialout != new.gnmi_dialout,
        mrt_changed: old.mrt != new.mrt,
        evpn_instances_changed: old.evpn_instances != new.evpn_instances,
        evpn_ip_vrfs_changed: old.evpn_ip_vrfs != new.evpn_ip_vrfs,
        ethernet_segments_changed: old.ethernet_segments != new.ethernet_segments,
        managed_netdevs_changed: old.managed_netdevs != new.managed_netdevs,
        security_grpc_changed: old.security != new.security,
        event_history_changed: old.event_history != new.event_history,
        fib_tables_changed: old.fib_tables != new.fib_tables,
        fib_tables_requires_restart: old.fib_tables.is_empty() && !new.fib_tables.is_empty(),
        dynamic_neighbors_changed: old.dynamic_neighbors != new.dynamic_neighbors,
        dynamic_neighbors_reload_applied_changed,
        dynamic_neighbor_tcp_ao_changed,
        apply_bum_enforcement_changed: old.apply_bum_enforcement != new.apply_bum_enforcement,
        blackhole_fib_discard_changed,
        neighbor_tcp_ao_changed,
        bfd_changed,
        policy_explain_changed: old.policy.explain != new.policy.explain,
        policy_reject_retention_changed: old.policy.reject_retention != new.policy.reject_retention,
        evpn_runtime_change_class,
    }
}

fn evpn_runtime_config_changed(old: &Config, new: &Config) -> bool {
    old.evpn_instances != new.evpn_instances
        || old.evpn_ip_vrfs != new.evpn_ip_vrfs
        || old.ethernet_segments != new.ethernet_segments
}

fn classify_evpn_runtime_change(old: &Config, new: &Config) -> EvpnRuntimeChangeClass {
    if !evpn_runtime_config_changed(old, new) {
        return EvpnRuntimeChangeClass::Unchanged;
    }
    let Ok(current) = evpn_runtime_model_from_config(old) else {
        return EvpnRuntimeChangeClass::RestartRequired;
    };
    let Ok(candidate) = evpn_runtime_candidate_from_config(new) else {
        return EvpnRuntimeChangeClass::RestartRequired;
    };
    let plan = current.plan_candidate(&candidate);
    if evpn_runtime_plan_is_reload_applied(&current, &candidate, &plan) {
        EvpnRuntimeChangeClass::ReloadApplied
    } else if let Ok(steps) =
        crate::evpn_plan_decomposer::decompose_evpn_runtime_candidate(&current, &candidate, &plan)
    {
        // #268: a mixed shape the coordinator dispatch rejects may still
        // converge on SIGHUP as an ordered sequence of primitive steps,
        // each committing its own runtime generation.
        EvpnRuntimeChangeClass::ReloadAppliedDecomposed { steps: steps.len() }
    } else {
        EvpnRuntimeChangeClass::RestartRequired
    }
}

fn evpn_runtime_model_from_config(config: &Config) -> Result<EvpnRuntimeModel, ConfigError> {
    let instances = config.resolve_evpn_instances()?;
    let ip_vrfs = config.resolve_evpn_ip_vrfs()?;
    let ethernet_segments = config.resolve_ethernet_segments()?;
    Ok(EvpnRuntimeModel::startup(
        instances,
        ip_vrfs,
        ethernet_segments,
    ))
}

fn evpn_runtime_candidate_from_config(
    config: &Config,
) -> Result<EvpnRuntimeCandidate, ConfigError> {
    Ok(EvpnRuntimeCandidate::new(
        config.resolve_evpn_instances()?,
        config.resolve_evpn_ip_vrfs()?,
        config.resolve_ethernet_segments()?,
    ))
}

fn evpn_runtime_plan_is_reload_applied(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if plan.is_noop() {
        // ADR-0085 binding-only edits change the TOML
        // `[[ethernet_segments]]` row but not the EVPN domain model.
        // SIGHUP still commits them so the binding watcher republishes.
        return true;
    }
    if evpn_runtime_is_tenant_teardown_plan(plan, current) {
        return evpn_runtime_validate_tenant_teardown_shape(current, candidate, plan);
    }
    if evpn_runtime_is_ip_vrf_relink_plan(plan) {
        return true;
    }
    if evpn_runtime_is_additive_build_up_plan(plan) {
        return evpn_runtime_validate_additive_build_up_shape(current, candidate, plan);
    }
    if evpn_runtime_is_l2vni_mixed_plan(plan) {
        return evpn_runtime_validate_l2vni_mixed_shape(current, candidate, plan);
    }
    if !evpn_runtime_no_unexpected_relink(current, candidate, plan) {
        return false;
    }

    if plan.evpn_instances.has_changes() {
        return evpn_runtime_l2vni_shape_is_reload_applied(current, candidate, plan);
    }
    if plan.ip_vrfs.has_changes() {
        return evpn_runtime_ip_vrf_shape_is_reload_applied(current, candidate, plan);
    }
    if plan.ethernet_segments.has_changes() {
        return evpn_runtime_es_shape_is_reload_applied(current, candidate, plan);
    }
    false
}

fn evpn_runtime_is_ip_vrf_relink_plan(plan: &EvpnRuntimePlan) -> bool {
    plan.ip_vrf_references_changed
        && !plan.evpn_instances.has_changes()
        && !plan.ip_vrfs.has_changes()
        && !plan.ethernet_segments.has_changes()
}

fn evpn_runtime_is_additive_build_up_plan(plan: &EvpnRuntimePlan) -> bool {
    let no_deletes_or_non_es_redefines = plan.evpn_instances.deleted.is_empty()
        && plan.evpn_instances.redefined.is_empty()
        && plan.ip_vrfs.deleted.is_empty()
        && plan.ip_vrfs.redefined.is_empty()
        && plan.ethernet_segments.deleted.is_empty();
    let has_add = !plan.evpn_instances.added.is_empty()
        || !plan.ip_vrfs.added.is_empty()
        || !plan.ethernet_segments.added.is_empty();
    if !(no_deletes_or_non_es_redefines && has_add) {
        return false;
    }
    let resource_types_added = [
        !plan.evpn_instances.added.is_empty(),
        !plan.ip_vrfs.added.is_empty(),
        !plan.ethernet_segments.added.is_empty(),
    ]
    .into_iter()
    .filter(|changed| *changed)
    .count();
    resource_types_added > 1
        || plan.evpn_instances.added.len() > 1
        || plan.ip_vrfs.added.len() > 1
        || plan.ethernet_segments.added.len() > 1
        || !plan.ethernet_segments.redefined.is_empty()
}

fn evpn_runtime_validate_additive_build_up_shape(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if !evpn_runtime_no_unexpected_relink(current, candidate, plan) {
        return false;
    }
    let Some(added_l2vnis) = evpn_runtime_added_l2vnis(plan) else {
        return false;
    };
    plan.evpn_instances.added.iter().all(|&raw_vni| {
        EvpnInstanceId::new(raw_vni).is_ok_and(|vni| {
            current.instances().get(vni).is_none() && candidate.instances().get(vni).is_some()
        })
    }) && plan.ip_vrfs.added.iter().all(|name| {
        current.ip_vrfs().get(name).is_none() && candidate.ip_vrfs().get(name).is_some()
    }) && plan.ethernet_segments.added.iter().all(|esi| {
        current
            .ethernet_segments()
            .iter()
            .all(|segment| segment.esi != *esi)
            && candidate
                .ethernet_segments()
                .iter()
                .find(|segment| segment.esi == *esi)
                .is_some_and(|segment| {
                    !segment.member_vnis.is_empty()
                        && segment
                            .member_vnis
                            .iter()
                            .all(|&vni| candidate.instances().get(vni).is_some())
                })
    }) && plan.ethernet_segments.redefined.iter().all(|esi| {
        evpn_runtime_es_member_expansion_is_additive(current, candidate, *esi, &added_l2vnis)
    })
}

fn evpn_runtime_added_l2vnis(plan: &EvpnRuntimePlan) -> Option<BTreeSet<EvpnInstanceId>> {
    plan.evpn_instances
        .added
        .iter()
        .map(|raw| EvpnInstanceId::new(*raw))
        .collect::<Result<BTreeSet<_>, _>>()
        .ok()
}

fn evpn_runtime_es_member_expansion_is_additive(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    esi: EthernetSegmentIdentifier,
    added_l2vnis: &BTreeSet<EvpnInstanceId>,
) -> bool {
    let Some(current_segment) = current
        .ethernet_segments()
        .iter()
        .find(|segment| segment.esi == esi)
    else {
        return false;
    };
    let Some(candidate_segment) = candidate
        .ethernet_segments()
        .iter()
        .find(|segment| segment.esi == esi)
    else {
        return false;
    };

    if candidate_segment.member_vnis.len() <= current_segment.member_vnis.len()
        || !candidate_segment
            .member_vnis
            .is_superset(&current_segment.member_vnis)
    {
        return false;
    }
    let added_members: BTreeSet<_> = candidate_segment
        .member_vnis
        .difference(&current_segment.member_vnis)
        .copied()
        .collect();
    if added_members.is_empty()
        || !added_members.iter().all(|vni| added_l2vnis.contains(vni))
        || !candidate_segment
            .member_vnis
            .iter()
            .all(|&vni| candidate.instances().get(vni).is_some())
    {
        return false;
    }

    let mut probe = current_segment.clone();
    probe.member_vnis.clone_from(&candidate_segment.member_vnis);
    &probe == candidate_segment
}

fn evpn_runtime_is_l2vni_mixed_plan(plan: &EvpnRuntimePlan) -> bool {
    let l2_change_classes = [
        !plan.evpn_instances.added.is_empty(),
        !plan.evpn_instances.deleted.is_empty(),
        !plan.evpn_instances.redefined.is_empty(),
    ]
    .into_iter()
    .filter(|changed| *changed)
    .count();
    let batch_redefine_only = plan.evpn_instances.added.is_empty()
        && plan.evpn_instances.deleted.is_empty()
        && plan.evpn_instances.redefined.len() > 1;
    (l2_change_classes >= 2 || batch_redefine_only)
        && !plan.ip_vrfs.has_changes()
        && !plan.ethernet_segments.has_changes()
}

fn evpn_runtime_validate_l2vni_mixed_shape(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if !evpn_runtime_no_unexpected_relink(current, candidate, plan) {
        return false;
    }
    plan.evpn_instances.added.iter().all(|&raw_vni| {
        EvpnInstanceId::new(raw_vni).is_ok_and(|vni| {
            current.instances().get(vni).is_none() && candidate.instances().get(vni).is_some()
        })
    }) && plan.evpn_instances.deleted.iter().all(|&raw_vni| {
        EvpnInstanceId::new(raw_vni).is_ok_and(|vni| {
            current.instances().get(vni).is_some()
                && candidate.instances().get(vni).is_none()
                && current
                    .ethernet_segments()
                    .iter()
                    .all(|segment| !segment.member_vnis.contains(&vni))
        })
    }) && plan.evpn_instances.redefined.iter().all(|&raw_vni| {
        EvpnInstanceId::new(raw_vni).is_ok_and(|vni| {
            current.instances().get(vni).is_some() && candidate.instances().get(vni).is_some()
        })
    })
}

fn evpn_runtime_is_tenant_teardown_plan(
    plan: &EvpnRuntimePlan,
    current: &EvpnRuntimeModel,
) -> bool {
    let no_adds = plan.evpn_instances.added.is_empty()
        && plan.ip_vrfs.added.is_empty()
        && plan.ethernet_segments.added.is_empty();
    let no_l2_ipvrf_redefine =
        plan.evpn_instances.redefined.is_empty() && plan.ip_vrfs.redefined.is_empty();
    let has_deletion = !plan.evpn_instances.deleted.is_empty()
        || !plan.ip_vrfs.deleted.is_empty()
        || !plan.ethernet_segments.deleted.is_empty();
    if !(no_adds && no_l2_ipvrf_redefine && has_deletion) {
        return false;
    }
    let resource_types_changed = [
        plan.evpn_instances.has_changes(),
        plan.ip_vrfs.has_changes(),
        plan.ethernet_segments.has_changes(),
    ]
    .into_iter()
    .filter(|changed| *changed)
    .count();
    let multi_resource = resource_types_changed > 1;
    let multi_element = plan.evpn_instances.deleted.len() > 1
        || plan.ip_vrfs.deleted.len() > 1
        || plan.ethernet_segments.deleted.len() > 1;
    let es_member_l2vni_deleted = plan.evpn_instances.deleted.iter().any(|&raw| {
        EvpnInstanceId::new(raw).is_ok_and(|vni| {
            current
                .ethernet_segments()
                .iter()
                .any(|segment| segment.member_vnis.contains(&vni))
        })
    });
    let referenced_ip_vrf_deleted = plan
        .ip_vrfs
        .deleted
        .iter()
        .any(|name| current.ip_vrfs().is_referenced(name));

    multi_resource || multi_element || es_member_l2vni_deleted || referenced_ip_vrf_deleted
}

fn evpn_runtime_validate_tenant_teardown_shape(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if !plan.evpn_instances.added.is_empty()
        || !plan.ip_vrfs.added.is_empty()
        || !plan.ethernet_segments.added.is_empty()
        || !plan.evpn_instances.redefined.is_empty()
        || !plan.ip_vrfs.redefined.is_empty()
    {
        return false;
    }
    if plan.evpn_instances.deleted.is_empty()
        && plan.ip_vrfs.deleted.is_empty()
        && plan.ethernet_segments.deleted.is_empty()
    {
        return false;
    }

    let mut deleted_vnis = BTreeSet::new();
    for &raw_vni in &plan.evpn_instances.deleted {
        let Ok(vni) = EvpnInstanceId::new(raw_vni) else {
            return false;
        };
        if current.instances().get(vni).is_none() || candidate.instances().get(vni).is_some() {
            return false;
        }
        deleted_vnis.insert(vni);
    }

    for name in &plan.ip_vrfs.deleted {
        if current.ip_vrfs().get(name).is_none() || candidate.ip_vrfs().get(name).is_some() {
            return false;
        }
        let refs = current
            .ip_vrfs()
            .referenced_l2vnis(name)
            .cloned()
            .unwrap_or_default();
        if refs.iter().any(|vni| !deleted_vnis.contains(vni)) {
            return false;
        }
    }

    for esi in &plan.ethernet_segments.deleted {
        if !current
            .ethernet_segments()
            .iter()
            .any(|segment| segment.esi == *esi)
            || candidate
                .ethernet_segments()
                .iter()
                .any(|segment| segment.esi == *esi)
        {
            return false;
        }
    }

    for esi in &plan.ethernet_segments.redefined {
        let Some(cur) = current
            .ethernet_segments()
            .iter()
            .find(|segment| segment.esi == *esi)
        else {
            return false;
        };
        let Some(cand) = candidate
            .ethernet_segments()
            .iter()
            .find(|segment| segment.esi == *esi)
        else {
            return false;
        };
        let member_shrink_only = cand.member_vnis.len() < cur.member_vnis.len()
            && cand
                .member_vnis
                .iter()
                .all(|vni| cur.member_vnis.contains(vni))
            && {
                let mut probe = cur.clone();
                probe.member_vnis.clone_from(&cand.member_vnis);
                &probe == cand
            };
        if !member_shrink_only {
            return false;
        }
    }

    candidate.ethernet_segments().iter().all(|segment| {
        segment
            .member_vnis
            .iter()
            .all(|vni| !deleted_vnis.contains(vni))
    })
}

fn evpn_runtime_no_unexpected_relink(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if !plan.ip_vrf_references_changed {
        return true;
    }
    let touched: BTreeSet<EvpnInstanceId> = plan
        .evpn_instances
        .added
        .iter()
        .chain(plan.evpn_instances.deleted.iter())
        .filter_map(|raw| EvpnInstanceId::new(*raw).ok())
        .collect();
    let current_links = current.ip_vrfs().l2vni_link_map();
    let candidate_links = candidate.ip_vrfs().l2vni_link_map();
    let mut vnis: BTreeSet<EvpnInstanceId> = current_links.keys().copied().collect();
    vnis.extend(candidate_links.keys().copied());
    vnis.into_iter()
        .all(|vni| current_links.get(&vni) == candidate_links.get(&vni) || touched.contains(&vni))
}

fn evpn_runtime_l2vni_shape_is_reload_applied(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if plan.ip_vrfs.has_changes() || plan.ethernet_segments.has_changes() {
        return false;
    }
    if !plan.evpn_instances.added.is_empty() {
        return plan.evpn_instances.added.len() == 1
            && plan.evpn_instances.deleted.is_empty()
            && plan.evpn_instances.redefined.is_empty()
            && EvpnInstanceId::new(plan.evpn_instances.added[0]).is_ok_and(|vni| {
                current.instances().get(vni).is_none() && candidate.instances().get(vni).is_some()
            });
    }
    if !plan.evpn_instances.deleted.is_empty() {
        return plan.evpn_instances.deleted.len() == 1
            && plan.evpn_instances.redefined.is_empty()
            && EvpnInstanceId::new(plan.evpn_instances.deleted[0]).is_ok_and(|vni| {
                current.instances().get(vni).is_some()
                    && candidate.instances().get(vni).is_none()
                    && !current
                        .ethernet_segments()
                        .iter()
                        .any(|segment| segment.member_vnis.contains(&vni))
            });
    }
    plan.evpn_instances.redefined.len() == 1
        && plan.evpn_instances.added.is_empty()
        && plan.evpn_instances.deleted.is_empty()
        && EvpnInstanceId::new(plan.evpn_instances.redefined[0]).is_ok_and(|vni| {
            current.instances().get(vni).is_some()
                && candidate.instances().get(vni).is_some()
                && current.ip_vrfs() == candidate.ip_vrfs()
        })
}

fn evpn_runtime_ip_vrf_shape_is_reload_applied(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if plan.evpn_instances.has_changes() || plan.ethernet_segments.has_changes() {
        return false;
    }
    if !plan.ip_vrfs.added.is_empty() {
        return plan.ip_vrfs.added.len() == 1
            && plan.ip_vrfs.deleted.is_empty()
            && plan.ip_vrfs.redefined.is_empty()
            && current.ip_vrfs().get(&plan.ip_vrfs.added[0]).is_none()
            && candidate.ip_vrfs().get(&plan.ip_vrfs.added[0]).is_some();
    }
    if !plan.ip_vrfs.deleted.is_empty() {
        let name = &plan.ip_vrfs.deleted[0];
        return plan.ip_vrfs.deleted.len() == 1
            && plan.ip_vrfs.redefined.is_empty()
            && current.ip_vrfs().get(name).is_some()
            && candidate.ip_vrfs().get(name).is_none()
            && !current.ip_vrfs().is_referenced(name);
    }
    if plan.ip_vrfs.redefined.len() != 1
        || !plan.ip_vrfs.added.is_empty()
        || !plan.ip_vrfs.deleted.is_empty()
    {
        return false;
    }
    let name = &plan.ip_vrfs.redefined[0];
    let Some(old) = current.ip_vrfs().get(name) else {
        return false;
    };
    let Some(new) = candidate.ip_vrfs().get(name) else {
        return false;
    };
    let current_refs = current
        .ip_vrfs()
        .referenced_l2vnis(name)
        .cloned()
        .unwrap_or_default();
    let candidate_refs = candidate
        .ip_vrfs()
        .referenced_l2vnis(name)
        .cloned()
        .unwrap_or_default();
    old.id == new.id
        && old.vrf_device == new.vrf_device
        && old.l3vxlan_device == new.l3vxlan_device
        && old.table_id == new.table_id
        && current_refs == candidate_refs
        && current.ip_vrfs().is_referenced(name) == candidate.ip_vrfs().is_referenced(name)
}

fn evpn_runtime_es_shape_is_reload_applied(
    current: &EvpnRuntimeModel,
    candidate: &EvpnRuntimeCandidate,
    plan: &EvpnRuntimePlan,
) -> bool {
    if plan.evpn_instances.has_changes() || plan.ip_vrfs.has_changes() {
        return false;
    }
    if !plan.ethernet_segments.added.is_empty() {
        let esi = plan.ethernet_segments.added[0];
        return plan.ethernet_segments.added.len() == 1
            && plan.ethernet_segments.deleted.is_empty()
            && plan.ethernet_segments.redefined.is_empty()
            && current
                .ethernet_segments()
                .iter()
                .all(|segment| segment.esi != esi)
            && candidate
                .ethernet_segments()
                .iter()
                .find(|segment| segment.esi == esi)
                .is_some_and(|segment| {
                    !segment.member_vnis.is_empty()
                        && segment
                            .member_vnis
                            .iter()
                            .all(|&vni| candidate.instances().get(vni).is_some())
                });
    }
    if !plan.ethernet_segments.deleted.is_empty() {
        let esi = plan.ethernet_segments.deleted[0];
        return plan.ethernet_segments.deleted.len() == 1
            && plan.ethernet_segments.redefined.is_empty()
            && current
                .ethernet_segments()
                .iter()
                .any(|segment| segment.esi == esi)
            && candidate
                .ethernet_segments()
                .iter()
                .all(|segment| segment.esi != esi);
    }
    let Some(&esi) = plan.ethernet_segments.redefined.first() else {
        return false;
    };
    plan.ethernet_segments.redefined.len() == 1
        && plan.ethernet_segments.added.is_empty()
        && plan.ethernet_segments.deleted.is_empty()
        && current
            .ethernet_segments()
            .iter()
            .any(|segment| segment.esi == esi)
        && candidate
            .ethernet_segments()
            .iter()
            .find(|segment| segment.esi == esi)
            .is_some_and(|segment| {
                !segment.member_vnis.is_empty()
                    && segment
                        .member_vnis
                        .iter()
                        .all(|&vni| candidate.instances().get(vni).is_some())
            })
}

/// Effective BFD config for a neighbor: its own `bfd`, else its peer-group's.
fn neighbor_effective_bfd<'a>(neighbor: &'a Neighbor, config: &'a Config) -> Option<&'a BfdConfig> {
    let resolved = if neighbor.bfd.is_some() {
        neighbor.bfd.as_ref()
    } else {
        config
            .peer_groups
            .get(neighbor.peer_group.as_deref()?)?
            .bfd
            .as_ref()
    };
    // A disabled block (`enabled = false`) runs no session, so it is not part of
    // the effective set — this is how a neighbor overrides an inherited
    // peer-group block to turn BFD off.
    resolved.filter(|bfd| bfd.enabled)
}

/// The effective BFD session set: one tuple per neighbor whose own or inherited
/// `bfd` references a defined profile, resolved to the timers the actor would
/// run. Sorted so it is order-insensitive. This is exactly the actor's startup
/// input, so comparing it across configs detects restart-required BFD drift.
fn effective_bfd_sessions(config: &Config) -> Vec<(String, u32, u32, u32, bool)> {
    let mut out: Vec<(String, u32, u32, u32, bool)> = config
        .neighbors
        .iter()
        .filter_map(|n| {
            let bfd = neighbor_effective_bfd(n, config)?;
            let profile = config.bfd_profiles.iter().find(|p| p.name == bfd.profile)?;
            Some((
                n.address.clone(),
                profile.min_tx_interval,
                profile.min_rx_interval,
                profile.multiplier,
                bfd.strict,
            ))
        })
        .collect();
    out.sort();
    out
}

/// Whether the effective BFD session set differs — restart-required because the
/// ADR-0067 actor resolves its sessions once at startup.
fn bfd_restart_required_changed(old: &Config, new: &Config) -> bool {
    effective_bfd_sessions(old) != effective_bfd_sessions(new)
}

/// Resolved (effective) BFD per neighbor address — its own `bfd`, else its
/// peer-group's. Used to pin/compare the *effective* session set, which
/// peer-group inheritance makes irreducible to raw field comparison.
fn effective_bfd_by_addr(config: &Config) -> HashMap<String, Option<BfdConfig>> {
    config
        .neighbors
        .iter()
        .map(|n| {
            (
                n.address.clone(),
                neighbor_effective_bfd(n, config).cloned(),
            )
        })
        .collect()
}

/// Pin BFD startup-only runtime state to the live snapshot. When the effective
/// session set differs, restore `bfd_profiles` and every peer-group `bfd`
/// field, and — for each neighbor whose *effective* BFD attachment changed —
/// pin its `bfd` and `peer_group` membership back to the live values, so a
/// SIGHUP reload cannot advance the persisted snapshot past what the running
/// actor is using. Pinning membership (not just the raw `bfd` field) is
/// required because BFD can be inherited from a peer group: a reload that moves
/// a neighbor between peer groups, or in/out of a BFD-bearing one, changes the
/// effective session without touching `neighbor.bfd`. This mirrors the
/// whole-neighbor `tcp_ao` pin — a neighbor with a changed startup-only
/// attachment is restart-required this reload. Returns whether anything was
/// pinned.
///
/// Residual: a neighbor *added* in the same reload that *inherits* BFD has no
/// live session to preserve; its inline `bfd` is dropped, but inherited BFD
/// will only start on the next restart (surfaced by `bfd_changed`). A neighbor
/// *removed* while it had BFD likewise leaves a session running until restart.
pub(crate) fn pin_bfd_startup_only_runtime(new_config: &mut Config, current: &Config) -> bool {
    if !bfd_restart_required_changed(current, new_config) {
        return false;
    }
    // Snapshot effective BFD per address for both configs before mutating.
    let live_effective = effective_bfd_by_addr(current);
    let new_effective = effective_bfd_by_addr(new_config);

    new_config.bfd_profiles.clone_from(&current.bfd_profiles);
    for (name, group) in &mut new_config.peer_groups {
        group.bfd = current.peer_groups.get(name).and_then(|g| g.bfd.clone());
    }

    let current_by_addr: HashMap<&str, &Neighbor> = current
        .neighbors
        .iter()
        .map(|n| (n.address.as_str(), n))
        .collect();
    for neighbor in &mut new_config.neighbors {
        let addr = neighbor.address.as_str();
        if live_effective.get(addr) == new_effective.get(addr) {
            continue;
        }
        if let Some(live) = current_by_addr.get(addr) {
            neighbor.bfd.clone_from(&live.bfd);
            neighbor.peer_group.clone_from(&live.peer_group);
        } else {
            // Newly added neighbor — no live session exists. If it carries its
            // own inline bfd, dropping it removes the effective session. If it
            // has no inline bfd but would *inherit* an enabled block, materialize
            // a disabled inline override so the pinned runtime's effective set
            // matches the actor (no session) — the `BfdConfig.enabled` tri-state
            // makes this expressible without editing peer-group membership.
            let pinned_bfd = if neighbor.bfd.is_some() {
                None
            } else {
                match new_effective.get(addr) {
                    Some(Some(inherited)) => Some(BfdConfig {
                        profile: inherited.profile.clone(),
                        enabled: false,
                        strict: inherited.strict,
                    }),
                    _ => None,
                }
            };
            neighbor.bfd = pinned_bfd;
        }
    }
    true
}

/// Pin `[global] ebgp_requires_policy` to the live snapshot. ADR-0112 makes the
/// RFC 8212 enforcement mode restart-required: policy resolution consults it
/// every time a peer's effective import/export chains are recomputed, so an
/// unpinned SIGHUP would flip both directions on every EBGP session at once. A
/// reload still *reports* the on-disk candidate through `ConfigDiff`; the
/// running snapshot keeps the startup value until the daemon restarts. Returns
/// whether anything was pinned.
pub(crate) fn pin_ebgp_requires_policy_startup_only(
    new_config: &mut Config,
    current: &Config,
) -> bool {
    if new_config.global.ebgp_requires_policy == current.global.ebgp_requires_policy {
        return false;
    }
    new_config.global.ebgp_requires_policy = current.global.ebgp_requires_policy;
    true
}

fn neighbor_tcp_ao_restart_required_changed(old: &Config, new: &Config) -> bool {
    let old_by_addr: HashMap<&str, &Neighbor> = old
        .neighbors
        .iter()
        .map(|neighbor| (neighbor.address.as_str(), neighbor))
        .collect();
    let new_by_addr: HashMap<&str, &Neighbor> = new
        .neighbors
        .iter()
        .map(|neighbor| (neighbor.address.as_str(), neighbor))
        .collect();

    for new_neighbor in &new.neighbors {
        match old_by_addr.get(new_neighbor.address.as_str()) {
            Some(old_neighbor) if old_neighbor.tcp_ao != new_neighbor.tcp_ao => return true,
            None if new_neighbor.tcp_ao.is_some() => return true,
            _ => {}
        }
    }

    old.neighbors.iter().any(|old_neighbor| {
        old_neighbor.tcp_ao.is_some() && !new_by_addr.contains_key(old_neighbor.address.as_str())
    })
}

fn dynamic_neighbor_tcp_ao_restart_required_changed(old: &Config, new: &Config) -> bool {
    !protected_dynamic_ranges_equal(old, new)
}

fn protected_dynamic_ranges_equal(old: &Config, new: &Config) -> bool {
    let mut old_protected: Vec<_> = old
        .dynamic_neighbors
        .iter()
        .filter(|range| range.tcp_ao.is_some())
        .collect();
    let mut new_protected: Vec<_> = new
        .dynamic_neighbors
        .iter()
        .filter(|range| range.tcp_ao.is_some())
        .collect();
    old_protected.sort_unstable_by(|left, right| protected_dynamic_range_cmp(left, right));
    new_protected.sort_unstable_by(|left, right| protected_dynamic_range_cmp(left, right));
    old_protected.len() == new_protected.len()
        && old_protected
            .iter()
            .zip(new_protected)
            .all(|(old, new)| protected_dynamic_range_cmp(old, new).is_eq())
}

fn protected_dynamic_range_cmp(
    left: &DynamicNeighborConfig,
    right: &DynamicNeighborConfig,
) -> std::cmp::Ordering {
    let left_ao = left.tcp_ao.as_ref().expect("protected range");
    let right_ao = right.tcp_ao.as_ref().expect("protected range");
    effective_prefix_str(&left.prefix)
        .cmp(&effective_prefix_str(&right.prefix))
        .then_with(|| left.peer_group.cmp(&right.peer_group))
        .then_with(|| left.remote_asn.cmp(&right.remote_asn))
        .then_with(|| left.description.cmp(&right.description))
        .then_with(|| left_ao.cmp(right_ao))
}

/// Pin dynamic TCP-AO listener state to the startup snapshot while preserving
/// disjoint unprotected range edits that the live matcher can safely apply.
pub(crate) fn pin_dynamic_tcp_ao_startup_only(new_config: &mut Config, current: &Config) -> usize {
    let current_protected: Vec<_> = current
        .dynamic_neighbors
        .iter()
        .filter(|range| range.tcp_ao.is_some())
        .cloned()
        .collect();
    let new_protected: Vec<_> = new_config
        .dynamic_neighbors
        .iter()
        .filter(|range| range.tcp_ao.is_some())
        .cloned()
        .collect();
    if protected_dynamic_ranges_equal(current, new_config) {
        return 0;
    }

    let mut current_by_prefix = BTreeMap::new();
    for range in &current_protected {
        if let Some(prefix) = effective_prefix_str(&range.prefix) {
            current_by_prefix.insert(prefix, range);
        }
    }
    let mut new_by_prefix = BTreeMap::new();
    for range in &new_protected {
        if let Some(prefix) = effective_prefix_str(&range.prefix) {
            new_by_prefix.insert(prefix, range);
        }
    }
    let affected_ranges = current_by_prefix
        .keys()
        .chain(new_by_prefix.keys())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .filter(|prefix| current_by_prefix.get(prefix) != new_by_prefix.get(prefix))
        .count();

    let current_prefixes: Vec<_> = current_protected
        .iter()
        .filter_map(|range| effective_prefix_str(&range.prefix))
        .collect();
    let mut restored = vec![false; current_protected.len()];
    new_config.dynamic_neighbors.retain_mut(|range| {
        let Some(prefix) = effective_prefix_str(&range.prefix) else {
            return true;
        };
        if range.tcp_ao.is_some() {
            if let Some((index, startup_range)) =
                current_protected
                    .iter()
                    .enumerate()
                    .find(|(index, startup_range)| {
                        !restored[*index]
                            && effective_prefix_str(&startup_range.prefix) == Some(prefix)
                    })
            {
                *range = startup_range.clone();
                restored[index] = true;
                return true;
            }
            return false;
        }

        !current_prefixes
            .iter()
            .any(|protected| dynamic_prefixes_intersect(prefix, *protected))
    });
    for (index, startup_range) in current_protected.into_iter().enumerate() {
        if !restored[index] {
            let startup_index = current
                .dynamic_neighbors
                .iter()
                .position(|range| range == &startup_range)
                .unwrap_or(new_config.dynamic_neighbors.len());
            new_config.dynamic_neighbors.insert(
                startup_index.min(new_config.dynamic_neighbors.len()),
                startup_range,
            );
        }
    }
    affected_ranges
}

/// Return whether two validated effective IP prefixes cover any common address.
///
/// Shared by config validation, reload pinning, and runtime dynamic-range CRUD
/// so TCP-AO authentication boundaries use one intersection definition.
pub(crate) fn dynamic_prefixes_intersect(left: (IpAddr, u8), right: (IpAddr, u8)) -> bool {
    let min_len = left.1.min(right.1);
    effective_prefix(left.0, min_len).0 == effective_prefix(right.0, min_len).0
}

/// Pin TCP-AO runtime state to the live startup snapshot.
///
/// A reload that keeps a live TCP-AO neighbor but hot-applies its inherited
/// dependencies can synthesize an invalid runtime shape, for example old
/// TCP-AO plus newly-inherited TCP MD5, or an old route-reflector client under
/// a newly edited local ASN. When any TCP-AO neighbor is pinned, pin the
/// restart-required global fields and the peer-group/policy dependency graph
/// with it.
pub(crate) fn pin_tcp_ao_startup_only_runtime(new_config: &mut Config, current: &Config) -> usize {
    let result = pin_tcp_ao_startup_only_neighbors(&mut new_config.neighbors, &current.neighbors);
    if result.pinned > 0 {
        pin_tcp_ao_restart_required_globals(new_config, current);
        pin_tcp_ao_dependency_graph(
            new_config,
            current,
            result.pinned_current_neighbors.iter().map(String::as_str),
        );
    }
    result.pinned
}

fn pin_tcp_ao_restart_required_globals(new_config: &mut Config, current: &Config) {
    let honor_graceful_shutdown = new_config.global.honor_graceful_shutdown;
    let honor_blackhole = new_config.global.honor_blackhole;
    let install_blackhole_discard = new_config.global.install_blackhole_discard;
    let allow_blackhole_broad_prefixes = new_config.global.allow_blackhole_broad_prefixes;

    new_config.global.clone_from(&current.global);

    // These knobs have explicit reload paths or are pinned before TCP-AO
    // pinning when their startup-gated actor is live. Preserve the already
    // shaped value so TCP-AO dependency pinning does not hide unrelated
    // hot-apply intent.
    new_config.global.honor_graceful_shutdown = honor_graceful_shutdown;
    new_config.global.honor_blackhole = honor_blackhole;
    new_config.global.install_blackhole_discard = install_blackhole_discard;
    new_config.global.allow_blackhole_broad_prefixes = allow_blackhole_broad_prefixes;
}

struct TcpAoPinResult {
    pinned: usize,
    pinned_current_neighbors: Vec<String>,
}

fn pin_tcp_ao_startup_only_neighbors(
    new_neighbors: &mut Vec<Neighbor>,
    current_neighbors: &[Neighbor],
) -> TcpAoPinResult {
    let current_by_addr: HashMap<&str, &Neighbor> = current_neighbors
        .iter()
        .map(|neighbor| (neighbor.address.as_str(), neighbor))
        .collect();

    let mut pinned = 0usize;
    let mut pinned_current_neighbors = Vec::new();
    for neighbor in new_neighbors.iter_mut() {
        match current_by_addr.get(neighbor.address.as_str()) {
            Some(current_neighbor) if current_neighbor.tcp_ao != neighbor.tcp_ao => {
                *neighbor = (*current_neighbor).clone();
                pinned += 1;
                pinned_current_neighbors.push(current_neighbor.address.clone());
            }
            _ => {}
        }
    }

    let before_len = new_neighbors.len();
    new_neighbors.retain(|neighbor| {
        current_by_addr.contains_key(neighbor.address.as_str()) || neighbor.tcp_ao.is_none()
    });
    pinned += before_len - new_neighbors.len();

    let new_addrs: HashSet<String> = new_neighbors
        .iter()
        .map(|neighbor| neighbor.address.clone())
        .collect();
    for current_neighbor in current_neighbors {
        if current_neighbor.tcp_ao.is_some() && !new_addrs.contains(&current_neighbor.address) {
            new_neighbors.push(current_neighbor.clone());
            pinned += 1;
            pinned_current_neighbors.push(current_neighbor.address.clone());
        }
    }

    TcpAoPinResult {
        pinned,
        pinned_current_neighbors,
    }
}

fn pin_tcp_ao_dependency_graph<'a>(
    new_config: &mut Config,
    current: &Config,
    pinned_current_neighbors: impl Iterator<Item = &'a str>,
) {
    let current_by_addr: HashMap<&str, &Neighbor> = current
        .neighbors
        .iter()
        .map(|neighbor| (neighbor.address.as_str(), neighbor))
        .collect();

    let mut policy_names = HashSet::new();
    let mut neighbor_set_names = HashSet::new();
    let mut peer_group_names = HashSet::new();
    let mut pin_global_import_chain = false;
    let mut pin_global_export_chain = false;

    for address in pinned_current_neighbors {
        let Some(neighbor) = current_by_addr.get(address) else {
            continue;
        };
        let pinned_global = collect_tcp_ao_neighbor_dependency_refs(
            neighbor,
            current,
            &mut policy_names,
            &mut neighbor_set_names,
            &mut peer_group_names,
        );
        pin_global_import_chain |= pinned_global.import;
        pin_global_export_chain |= pinned_global.export;
    }

    if pin_global_import_chain {
        new_config
            .policy
            .import_chain
            .clone_from(&current.policy.import_chain);
    }
    if pin_global_export_chain {
        new_config
            .policy
            .export_chain
            .clone_from(&current.policy.export_chain);
    }

    let mut processed_peer_groups = HashSet::new();
    let mut processed_policies = HashSet::new();
    let mut processed_neighbor_sets = HashSet::new();
    loop {
        let mut progressed = false;

        for name in peer_group_names
            .difference(&processed_peer_groups)
            .cloned()
            .collect::<Vec<_>>()
        {
            processed_peer_groups.insert(name.clone());
            progressed = true;
            if let Some(group) = current.peer_groups.get(&name) {
                new_config.peer_groups.insert(name, group.clone());
                collect_policy_refs_from_peer_group(
                    group,
                    &mut policy_names,
                    &mut neighbor_set_names,
                );
            }
        }

        for name in policy_names
            .difference(&processed_policies)
            .cloned()
            .collect::<Vec<_>>()
        {
            processed_policies.insert(name.clone());
            progressed = true;
            if let Some(policy) = current.policy.definitions.get(&name) {
                collect_neighbor_set_refs_from_policy(policy, &mut neighbor_set_names);
                new_config.policy.definitions.insert(name, policy.clone());
            }
        }

        for name in neighbor_set_names
            .difference(&processed_neighbor_sets)
            .cloned()
            .collect::<Vec<_>>()
        {
            processed_neighbor_sets.insert(name.clone());
            progressed = true;
            if let Some(set) = current.policy.neighbor_sets.get(&name) {
                peer_group_names.extend(set.peer_groups.iter().cloned());
                new_config.policy.neighbor_sets.insert(name, set.clone());
            }
        }

        if !progressed {
            break;
        }
    }
}

struct PinnedGlobalPolicyChains {
    import: bool,
    export: bool,
}

fn collect_tcp_ao_neighbor_dependency_refs(
    neighbor: &Neighbor,
    current: &Config,
    policy_names: &mut HashSet<String>,
    neighbor_set_names: &mut HashSet<String>,
    peer_group_names: &mut HashSet<String>,
) -> PinnedGlobalPolicyChains {
    collect_policy_refs_from_neighbor(neighbor, policy_names, neighbor_set_names);

    let group = neighbor
        .peer_group
        .as_deref()
        .and_then(|group_name| current.peer_groups.get(group_name));

    if let Some(group_name) = neighbor.peer_group.as_deref() {
        peer_group_names.insert(group_name.to_string());
    }

    let import = neighbor.import_policy_chain.is_empty()
        && neighbor.import_policy.is_empty()
        && group.is_none_or(|group| {
            group.import_policy_chain.is_empty() && group.import_policy.is_empty()
        })
        && !current.policy.import_chain.is_empty();
    if import {
        policy_names.extend(current.policy.import_chain.iter().cloned());
    }

    let export = neighbor.export_policy_chain.is_empty()
        && neighbor.export_policy.is_empty()
        && group.is_none_or(|group| {
            group.export_policy_chain.is_empty() && group.export_policy.is_empty()
        })
        && !current.policy.export_chain.is_empty();
    if export {
        policy_names.extend(current.policy.export_chain.iter().cloned());
    }

    PinnedGlobalPolicyChains { import, export }
}

fn collect_policy_refs_from_neighbor(
    neighbor: &Neighbor,
    policy_names: &mut HashSet<String>,
    neighbor_set_names: &mut HashSet<String>,
) {
    policy_names.extend(neighbor.import_policy_chain.iter().cloned());
    policy_names.extend(neighbor.export_policy_chain.iter().cloned());
    collect_neighbor_set_refs_from_statements(&neighbor.import_policy, neighbor_set_names);
    collect_neighbor_set_refs_from_statements(&neighbor.export_policy, neighbor_set_names);
}

fn collect_policy_refs_from_peer_group(
    group: &PeerGroupConfig,
    policy_names: &mut HashSet<String>,
    neighbor_set_names: &mut HashSet<String>,
) {
    policy_names.extend(group.import_policy_chain.iter().cloned());
    policy_names.extend(group.export_policy_chain.iter().cloned());
    collect_neighbor_set_refs_from_statements(&group.import_policy, neighbor_set_names);
    collect_neighbor_set_refs_from_statements(&group.export_policy, neighbor_set_names);
}

fn collect_neighbor_set_refs_from_policy(
    policy: &NamedPolicyConfig,
    neighbor_set_names: &mut HashSet<String>,
) {
    collect_neighbor_set_refs_from_statements(&policy.statements, neighbor_set_names);
}

fn collect_neighbor_set_refs_from_statements(
    statements: &[PolicyStatementConfig],
    neighbor_set_names: &mut HashSet<String>,
) {
    neighbor_set_names.extend(
        statements
            .iter()
            .filter_map(|statement| statement.match_neighbor_set.clone()),
    );
}

fn global_restart_required_changed(old: &Config, new: &Config) -> bool {
    let old_global = old.global.clone();
    let mut new_global = new.global.clone();

    // These knobs have explicit reload behavior and must not make the
    // coarse `[global] changed` restart bucket fire by themselves.
    // `honor_blackhole` becomes restart-required only as part of the
    // BLACKHOLE FIB actor's startup gate, reported separately through
    // `blackhole_fib_discard_changed`.
    new_global.honor_graceful_shutdown = old_global.honor_graceful_shutdown;
    new_global.honor_blackhole = old_global.honor_blackhole;
    new_global.install_blackhole_discard = old_global.install_blackhole_discard;
    new_global.allow_blackhole_broad_prefixes = old_global.allow_blackhole_broad_prefixes;

    old_global != new_global
}

/// Network address of a `[[dynamic_neighbors]]` prefix, used only to resolve a
/// representative neighbor for effective-policy comparison. The address selects
/// the address family but does not affect import/export chain resolution, so
/// the network address of the range is a faithful stand-in.
fn dynamic_range_representative_addr(prefix: &str) -> Option<IpAddr> {
    prefix.split_once('/')?.0.parse::<IpAddr>().ok()
}

/// Attribute a neighbor's moved resolved chain to the specific changed policy
/// definition / neighbor-set / global chain responsible, appending dedup'd
/// reason strings. Called only when the resolved import/export chain actually
/// moved, so a coarse neighbor-set/global-chain edit doesn't tag every neighbor.
fn attribute_chain_move_reasons(
    reasons: &mut Vec<String>,
    old_neighbor: &Neighbor,
    new_neighbor: &Neighbor,
    new_peer_group: Option<&str>,
    new: &Config,
    policy: &PolicyDiff,
) {
    let policy_changed: HashSet<&str> = policy
        .definitions_changed
        .iter()
        .map(String::as_str)
        .chain(policy.definitions_added.iter().map(String::as_str))
        .chain(policy.definitions_removed.iter().map(String::as_str))
        .collect();
    let mut chain_refs: Vec<&str> = Vec::new();
    chain_refs.extend(new_neighbor.import_policy_chain.iter().map(String::as_str));
    chain_refs.extend(new_neighbor.export_policy_chain.iter().map(String::as_str));
    chain_refs.extend(old_neighbor.import_policy_chain.iter().map(String::as_str));
    chain_refs.extend(old_neighbor.export_policy_chain.iter().map(String::as_str));
    if let Some(pg_name) = new_peer_group
        && let Some(pg) = new.peer_groups.get(pg_name)
    {
        chain_refs.extend(pg.import_policy_chain.iter().map(String::as_str));
        chain_refs.extend(pg.export_policy_chain.iter().map(String::as_str));
    }
    for name in chain_refs {
        if policy_changed.contains(name) {
            let entry = format!("policy {name:?} changed");
            if !reasons.contains(&entry) {
                reasons.push(entry);
            }
        }
    }
    if policy.import_chain_changed || policy.export_chain_changed {
        let entry = "global import/export chain changed".to_string();
        if !reasons.contains(&entry) {
            reasons.push(entry);
        }
    }
    if !policy.neighbor_sets_added.is_empty()
        || !policy.neighbor_sets_removed.is_empty()
        || !policy.neighbor_sets_changed.is_empty()
    {
        let entry = "referenced neighbor_set changed".to_string();
        if !reasons.contains(&entry) {
            reasons.push(entry);
        }
    }
    if policy.rpol_changed {
        let entry = "rpol policy file changed".to_string();
        if !reasons.contains(&entry) {
            reasons.push(entry);
        }
    }
}

/// Walk neighbors that exist in both configs and surface those whose
/// resolved effective config differs between old and new through a
/// reload-applied path — peer-group inheritance, named policy chain
/// edits, neighbor-set membership shifts, peer-group reassignment.
///
/// Deliberately scoped to *reload-applied* signals only: comparing
/// the full resolved `transport_config` would also flag
/// global-derived fields like `local_asn` / `local_router_id` (from
/// `[global]`), which are restart-required and shouldn't surface
/// under `--diff`'s "Reload-applied" bucket. Operators looking at
/// `effective_neighbor_impact` should be able to act on every entry
/// without restarting the daemon.
///
/// What's compared (each contributes a distinct reason string):
///
/// - **Resolved import / export policy chain.** Catches the
///   transitive cases the prior heuristic missed: a
///   `policy.definitions.foo` edit when `foo` is referenced via
///   the unchanged global `import_chain`, or via a peer-group's
///   chain whose record itself is unchanged.
/// - **Peer-group reassignment.** The neighbor moved between
///   peer-groups (its raw record changed, but the cascade is
///   surfaced here too for visibility).
/// - **Peer-group field edits.** The neighbor's peer-group is in
///   `peer_groups.changed`/`added`/`removed`; field edits like
///   `hold_time` flow down via `apply_peer_group_change`'s
///   delete-and-readd path.
/// - **Named policy / neighbor-set / global-chain edits.**
///   Attributed to the specific name where the change was the
///   chain-reference itself; otherwise tagged as a coarse
///   `neighbor_set` or global-chain reason.
///
/// Resolved chain equality is structural and order-sensitive: both sides come
/// from the same `effective_policy_chains_for_neighbor` resolver and
/// `PolicyChain.policies` is a `Vec` whose order is policy semantics.
///
/// Resolution failure (invalid chain reference) is treated as
/// "skip" — the load path already validates the new config, so
/// failures here indicate a transient inconsistency we don't want
/// to surface as effective impact.
fn compute_effective_neighbor_impact(
    old: &Config,
    new: &Config,
    peer_groups: &PeerGroupDiff,
    policy: &PolicyDiff,
) -> Vec<EffectiveNeighborImpact> {
    let pg_changed: HashSet<&str> = peer_groups
        .changed
        .iter()
        .map(String::as_str)
        .chain(peer_groups.added.iter().map(String::as_str))
        .chain(peer_groups.removed.iter().map(String::as_str))
        .collect();
    let new_by_addr: HashMap<&str, &Neighbor> = new
        .neighbors
        .iter()
        .map(|n| (n.address.as_str(), n))
        .collect();

    let mut out: Vec<EffectiveNeighborImpact> = Vec::new();
    for old_neighbor in &old.neighbors {
        let Some(new_neighbor) = new_by_addr.get(old_neighbor.address.as_str()) else {
            continue;
        };
        let Ok(old_resolved) = old.resolve_neighbor(old_neighbor) else {
            continue;
        };
        let Ok(new_resolved) = new.resolve_neighbor(new_neighbor) else {
            continue;
        };

        let import_moved = old_resolved.import_policy != new_resolved.import_policy;
        let export_moved = old_resolved.export_policy != new_resolved.export_policy;
        // A non-policy resolved change (hold_time, families, md5, tcp_ao, role,
        // add_path, ...) lives in transport_config; a group reassignment changes
        // the neighbor's raw record. Either means the impact is not a pure
        // policy-chain move the live-impact executor can re-apply in place; it
        // must route through a session reconfigure instead.
        let transport_changed = old_resolved.transport_config != new_resolved.transport_config;
        let peer_group_reassigned = old_resolved.peer_group != new_resolved.peer_group;

        let mut reasons: Vec<String> = Vec::new();
        if import_moved {
            reasons.push("import policy resolved differently".to_string());
        }
        if export_moved {
            reasons.push("export policy resolved differently".to_string());
        }

        if old_resolved.peer_group != new_resolved.peer_group {
            reasons.push(format!(
                "peer_group resolved as {} (was {})",
                new_resolved.peer_group.as_deref().unwrap_or("(unset)"),
                old_resolved.peer_group.as_deref().unwrap_or("(unset)")
            ));
        } else if let Some(name) = new_resolved.peer_group.as_deref()
            && pg_changed.contains(name)
        {
            reasons.push(format!("peer_group {name:?} changed"));
        }

        // Attribute moved chains to specific changed policies / sets / global
        // chain, but only when something *did* move at the resolved-chain level
        // — otherwise we'd surface every neighbor for any neighbor_set edit.
        if import_moved || export_moved {
            attribute_chain_move_reasons(
                &mut reasons,
                old_neighbor,
                new_neighbor,
                new_resolved.peer_group.as_deref(),
                new,
                policy,
            );
        }

        if !reasons.is_empty() {
            let kind =
                if (import_moved || export_moved) && !transport_changed && !peer_group_reassigned {
                    EffectiveNeighborImpactKind::PolicyChain
                } else {
                    EffectiveNeighborImpactKind::SessionReshape
                };
            out.push(EffectiveNeighborImpact {
                address: old_neighbor.address.clone(),
                reasons,
                kind,
                is_dynamic_range: false,
            });
        }
    }

    out.extend(dynamic_range_effective_impact(old, new, &pg_changed));

    out.sort_by(|a, b| a.address.cmp(&b.address));
    out
}

/// Surface `[[dynamic_neighbors]]` ranges whose resolved effective policy moves
/// between `old` and `new`.
///
/// An established session accepted into a range inherits its peer group's
/// resolved policy, and SIGHUP live-reconciles those dynamic peers on a policy /
/// peer-group / chain edit. A catalog-only transaction stages such an edit
/// without that live reconcile, so a range whose resolved import/export policy
/// moves is not actually "catalog-only" and must surface as effective impact.
///
/// Ranges are paired by prefix (the stable key); a prefix that was added or
/// removed is a `[[dynamic_neighbors]]` family edit handled by the
/// dynamic-neighbor executor, not here. For a range whose prefix is unchanged,
/// only a pure policy-chain move is `EffectiveNeighborImpactKind::PolicyChain`: a peer-group
/// reassignment or a transport/session change is reported as non-committable so
/// it routes to a reconfigure rather than a live policy refresh. (The executor
/// expands a range to its live peers by the peer's *accepted* peer group, so a
/// reassignment cannot be live-applied to already-established sessions.)
///
/// The prefix's network address is a faithful stand-in for resolution (it only
/// picks the address family, which does not affect policy chains).
fn dynamic_range_effective_impact(
    old: &Config,
    new: &Config,
    pg_changed: &HashSet<&str>,
) -> Vec<EffectiveNeighborImpact> {
    let new_ranges: HashMap<&str, &DynamicNeighborConfig> = new
        .dynamic_neighbors
        .iter()
        .map(|dn| (dn.prefix.as_str(), dn))
        .collect();
    let mut out = Vec::new();
    for old_range in &old.dynamic_neighbors {
        let Some(new_range) = new_ranges.get(old_range.prefix.as_str()) else {
            continue;
        };
        let Some(addr) = dynamic_range_representative_addr(&old_range.prefix) else {
            continue;
        };
        let Some(old_group) = old.peer_groups.get(&old_range.peer_group) else {
            continue;
        };
        let Some(new_group) = new.peer_groups.get(&new_range.peer_group) else {
            continue;
        };
        // Both sides pass the range's own configured `remote_asn`, so the
        // accept-any sentinel already classifies the range as external and
        // nothing needs pinning here.
        let Ok(old_resolved) = old.resolve_dynamic_neighbor(
            addr,
            old_range.remote_asn,
            old_range.description.as_deref().unwrap_or_default(),
            old_group,
            &old_range.peer_group,
            false,
        ) else {
            continue;
        };
        let Ok(new_resolved) = new.resolve_dynamic_neighbor(
            addr,
            new_range.remote_asn,
            new_range.description.as_deref().unwrap_or_default(),
            new_group,
            &new_range.peer_group,
            false,
        ) else {
            continue;
        };

        let import_moved = old_resolved.import_policy != new_resolved.import_policy;
        let export_moved = old_resolved.export_policy != new_resolved.export_policy;
        let peer_group_reassigned = old_range.peer_group != new_range.peer_group;
        // A non-policy resolved change (hold_time, families, md5, tcp_ao, role,
        // ...) lives in transport_config and cannot be live-applied by a policy
        // refresh; it needs a session reconfigure. Mirror the static-neighbor
        // classifier so a combined transport + policy edit is not mistaken for a
        // pure policy-chain move and silently committed without the reconfigure.
        let transport_changed = old_resolved.transport_config != new_resolved.transport_config;

        let mut reasons: Vec<String> = Vec::new();
        if import_moved {
            reasons.push("dynamic-range import policy resolved differently".to_string());
        }
        if export_moved {
            reasons.push("dynamic-range export policy resolved differently".to_string());
        }
        if peer_group_reassigned {
            reasons.push(format!(
                "dynamic-range peer_group resolved as {:?} (was {:?})",
                new_range.peer_group, old_range.peer_group
            ));
        }
        if transport_changed {
            reasons
                .push("dynamic-range transport/session settings resolved differently".to_string());
        }
        if pg_changed.contains(old_range.peer_group.as_str()) {
            reasons.push(format!("peer_group {:?} changed", old_range.peer_group));
        }
        if !reasons.is_empty() {
            let kind =
                if (import_moved || export_moved) && !transport_changed && !peer_group_reassigned {
                    EffectiveNeighborImpactKind::PolicyChain
                } else {
                    EffectiveNeighborImpactKind::SessionReshape
                };
            out.push(EffectiveNeighborImpact {
                address: old_range.prefix.clone(),
                reasons,
                kind,
                is_dynamic_range: true,
            });
        }
    }
    out
}

/// Compare two peer group maps and return names of added/removed/changed groups.
pub fn diff_peer_groups(
    old: &HashMap<String, PeerGroupConfig>,
    new: &HashMap<String, PeerGroupConfig>,
) -> PeerGroupDiff {
    let mut added = Vec::new();
    let mut changed = Vec::new();
    for (name, new_pg) in new {
        match old.get(name) {
            None => added.push(name.clone()),
            Some(old_pg) => {
                if old_pg != new_pg {
                    changed.push(name.clone());
                }
            }
        }
    }
    added.sort();
    changed.sort();

    let mut removed: Vec<String> = old
        .keys()
        .filter(|name| !new.contains_key(*name))
        .cloned()
        .collect();
    removed.sort();

    PeerGroupDiff {
        added,
        removed,
        changed,
    }
}

/// Describe which fields changed between two `PeerGroupConfig` values.
pub fn describe_peer_group_changes(
    old: &PeerGroupConfig,
    new: &PeerGroupConfig,
) -> Vec<FieldChange> {
    let mut changes = Vec::new();

    macro_rules! cmp_field {
        ($field:ident) => {
            if old.$field != new.$field {
                changes.push(FieldChange::new(
                    stringify!($field),
                    &old.$field,
                    &new.$field,
                ));
            }
        };
    }

    cmp_field!(hold_time);
    cmp_field!(min_hold_time);
    cmp_field!(send_hold_time);
    cmp_field!(max_prefixes);
    cmp_field!(max_prefixes_ipv4);
    cmp_field!(max_prefixes_ipv6);
    cmp_field!(max_prefixes_out_ipv4);
    cmp_field!(max_prefixes_out_ipv6);
    cmp_field!(max_prefix_restart_seconds);
    cmp_field!(ttl_security);
    cmp_field!(families);
    cmp_field!(required_families);
    cmp_field!(graceful_restart);
    cmp_field!(gr_restart_time);
    cmp_field!(gr_peer_restart_time_max);
    cmp_field!(gr_stale_routes_time);
    cmp_field!(llgr_stale_time);
    cmp_field!(local_ipv6_nexthop);
    cmp_field!(route_reflector_client);
    cmp_field!(orr_vantage);
    cmp_field!(route_server_client);
    cmp_field!(per_client_best);
    cmp_field!(next_hop_ownership);
    cmp_field!(interpret_rfc1997);
    cmp_field!(rs_control_communities);
    cmp_field!(role);
    cmp_field!(strict_role);
    cmp_field!(prefix_orf_receive);
    cmp_field!(disable_ipv4_unicast);
    cmp_field!(remove_private_as);
    cmp_field!(add_path);
    cmp_field!(log_level);

    if old.md5_password != new.md5_password {
        changes.push(FieldChange::summarized("md5_password"));
    }
    if old.import_policy != new.import_policy {
        changes.push(FieldChange::summarized("import_policy"));
    }
    if old.export_policy != new.export_policy {
        changes.push(FieldChange::summarized("export_policy"));
    }
    cmp_field!(import_policy_chain);
    cmp_field!(export_policy_chain);

    changes
}

/// True when every field that differs between two versions of one peer
/// group is reload-matrix `live` (hot-applied), so the group edit can be
/// applied in place to every inheriting member instead of reshaping
/// (delete + re-add) their sessions.
///
/// The peer-group sibling of [`neighbor_change_hot_applicable`], and
/// conservative on exactly the same edges: an empty change list (a
/// runtime-relevant field `describe_peer_group_changes` doesn't cover,
/// e.g. the `slow_peer_*` trio) and any field whose impact class is
/// unknown or non-`HotApplied` both return `false`, keeping the reshape
/// path as the fallback.
pub fn peer_group_change_hot_applicable(old: &PeerGroupConfig, new: &PeerGroupConfig) -> bool {
    let changes = describe_peer_group_changes(old, new);
    !changes.is_empty()
        && changes
            .iter()
            .all(|change| change.impact == Some(ConfigFieldImpact::HotApplied))
}

/// Compare two policy configurations.
pub fn diff_policy(old: &PolicyConfig, new: &PolicyConfig) -> PolicyDiff {
    let definitions_added: Vec<String> = new
        .definitions
        .keys()
        .filter(|k| !old.definitions.contains_key(*k))
        .cloned()
        .collect();
    let definitions_removed: Vec<String> = old
        .definitions
        .keys()
        .filter(|k| !new.definitions.contains_key(*k))
        .cloned()
        .collect();
    let definitions_changed: Vec<String> = new
        .definitions
        .iter()
        .filter(|(k, v)| old.definitions.get(*k).is_some_and(|old_v| old_v != *v))
        .map(|(k, _)| k.clone())
        .collect();

    let neighbor_sets_added: Vec<String> = new
        .neighbor_sets
        .keys()
        .filter(|k| !old.neighbor_sets.contains_key(*k))
        .cloned()
        .collect();
    let neighbor_sets_removed: Vec<String> = old
        .neighbor_sets
        .keys()
        .filter(|k| !new.neighbor_sets.contains_key(*k))
        .cloned()
        .collect();
    let neighbor_sets_changed: Vec<String> = new
        .neighbor_sets
        .iter()
        .filter(|(k, v)| old.neighbor_sets.get(*k).is_some_and(|old_v| old_v != *v))
        .map(|(k, _)| k.clone())
        .collect();

    PolicyDiff {
        definitions_added,
        definitions_removed,
        definitions_changed,
        neighbor_sets_added,
        neighbor_sets_removed,
        neighbor_sets_changed,
        import_chain_changed: old.import_chain != new.import_chain,
        export_chain_changed: old.export_chain != new.export_chain,
        rpol_changed: old.rpol_files != new.rpol_files || old.rpol != new.rpol,
    }
}

impl From<GrpcAccessModeConfig> for GrpcAccessMode {
    fn from(value: GrpcAccessModeConfig) -> Self {
        match value {
            GrpcAccessModeConfig::ReadOnly => Self::ReadOnly,
            GrpcAccessModeConfig::ReadWrite => Self::ReadWrite,
        }
    }
}

impl From<GrpcMaxTierConfig> for GrpcMaxTier {
    fn from(value: GrpcMaxTierConfig) -> Self {
        match value {
            GrpcMaxTierConfig::Read => Self::Read,
            GrpcMaxTierConfig::SensitiveRead => Self::SensitiveRead,
            GrpcMaxTierConfig::Mutating => Self::Mutating,
            GrpcMaxTierConfig::OperatorOnly => Self::OperatorOnly,
        }
    }
}

/// Parse one [`EvpnInstanceConfig`] entry into the runtime
/// [`EvpnInstance`] domain type.
///
/// All operator-input fields are revalidated here even though
/// `Config::validate` already touched them — `resolve_evpn_instances`
/// is called from non-load paths (gRPC `ListEvpnInstances`, future
/// SIGHUP reconcile) where the config has already passed `validate`,
/// so the second pass is cheap and protects against misuse if a caller
/// ever skips validation.
fn parse_evpn_instance(
    cfg: &EvpnInstanceConfig,
    local_asn: u32,
) -> Result<EvpnInstance, ConfigError> {
    let id = EvpnInstanceId::new(cfg.vni).map_err(|e| ConfigError::InvalidEvpnInstance {
        reason: format!("vni {}: {e}", cfg.vni),
    })?;

    let rd =
        cfg.rd
            .parse::<RouteDistinguisher>()
            .map_err(|e| ConfigError::InvalidEvpnInstance {
                reason: format!("vni {}: invalid rd {:?}: {e}", cfg.vni, cfg.rd),
            })?;

    let mut rts: Vec<RouteTarget> =
        Vec::with_capacity(cfg.route_targets.len() + usize::from(cfg.auto_derive_route_target));
    for raw in &cfg.route_targets {
        let rt = raw
            .parse::<RouteTarget>()
            .map_err(|e| ConfigError::InvalidEvpnInstance {
                reason: format!("vni {}: invalid route_target {:?}: {e}", cfg.vni, raw),
            })?;
        rts.push(rt);
    }
    if cfg.auto_derive_route_target {
        // L2VNI / MAC-VRF: RFC 8365 §5.1.2.1 opaque VXLAN RT.
        let rt = RouteTarget::auto_derived_vxlan_l2_rfc8365(local_asn, cfg.vni).map_err(|e| {
            ConfigError::InvalidEvpnInstance {
                reason: format!(
                    "vni {}: cannot auto_derive_route_target: {e}; disable auto_derive_route_target or configure route_targets manually",
                    cfg.vni
                ),
            }
        })?;
        rts.push(rt);
    }
    if rts.is_empty() {
        return Err(ConfigError::InvalidEvpnInstance {
            reason: format!("vni {}: route_targets must not be empty", cfg.vni),
        });
    }

    let local_vtep_ip =
        cfg.local_vtep_ip
            .parse::<IpAddr>()
            .map_err(|e| ConfigError::InvalidEvpnInstance {
                reason: format!(
                    "vni {}: invalid local_vtep_ip {:?}: {e}",
                    cfg.vni, cfg.local_vtep_ip
                ),
            })?;

    if let Some(bridge) = cfg.bridge.as_deref()
        && bridge.trim().is_empty()
    {
        return Err(ConfigError::InvalidEvpnInstance {
            reason: format!("vni {}: bridge name must not be empty", cfg.vni),
        });
    }
    let bridge_vlan = cfg
        .bridge_vlan
        .map(BridgeVlan::new)
        .transpose()
        .map_err(|e| ConfigError::InvalidEvpnInstance {
            reason: format!("vni {}: {e}", cfg.vni),
        })?;
    if bridge_vlan.is_some() && cfg.bridge.is_none() {
        return Err(ConfigError::InvalidEvpnInstance {
            reason: format!("vni {}: bridge_vlan requires bridge", cfg.vni),
        });
    }

    let mut sticky_macs: BTreeSet<MacAddress> = BTreeSet::new();
    for raw in &cfg.sticky_macs {
        let mac = parse_mac_address(raw).map_err(|e| ConfigError::InvalidEvpnInstance {
            reason: format!("vni {}: invalid sticky_mac {raw:?}: {e}", cfg.vni),
        })?;
        if !sticky_macs.insert(mac) {
            return Err(ConfigError::InvalidEvpnInstance {
                reason: format!(
                    "vni {}: duplicate sticky_mac {raw:?} (sticky_macs entries must be unique within an instance)",
                    cfg.vni
                ),
            });
        }
    }

    let inst = EvpnInstance::new(
        id,
        rd,
        rts,
        local_vtep_ip,
        cfg.bridge.clone(),
        cfg.advertise_svi_mac,
    )
    .map_err(|e| ConfigError::InvalidEvpnInstance {
        reason: format!("vni {}: {e}", cfg.vni),
    })?;
    let duplicate_mac_detection =
        parse_duplicate_mac_detection(cfg.vni, &cfg.duplicate_mac_detection)?;
    Ok(inst
        .with_bridge_vlan(bridge_vlan)
        .with_sticky_macs(sticky_macs)
        .with_apply_aliasing_ecmp(cfg.apply_aliasing_ecmp)
        .with_duplicate_mac_detection(duplicate_mac_detection))
}

fn parse_duplicate_mac_detection(
    vni: u32,
    cfg: &EvpnDuplicateMacDetectionConfig,
) -> Result<DuplicateMacConfig, ConfigError> {
    let action = match cfg.action {
        EvpnDuplicateMacActionConfig::Detect => DuplicateMacAction::DetectOnly,
        EvpnDuplicateMacActionConfig::SuppressLocal => DuplicateMacAction::SuppressLocal,
    };
    DuplicateMacConfig::new(
        action,
        std::time::Duration::from_secs(cfg.window_seconds),
        cfg.threshold,
        std::time::Duration::from_secs(cfg.recovery_seconds),
    )
    .map_err(|e| ConfigError::InvalidEvpnInstance {
        reason: format!("vni {vni}: {e}"),
    })
}

/// Parse a `aa:bb:cc:dd:ee:ff` MAC string into a [`MacAddress`]. The
/// wire crate intentionally does not implement `FromStr` on
/// `MacAddress` (RFC 7432 NLRI uses raw bytes, not the operator
/// notation), so the daemon owns this parse.
fn parse_mac_address(raw: &str) -> Result<MacAddress, &'static str> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 6 {
        return Err("expected 6 colon-separated octets");
    }
    let mut bytes = [0u8; 6];
    for (i, octet) in parts.iter().enumerate() {
        if octet.len() != 2 {
            return Err("each octet must be exactly 2 hex digits");
        }
        bytes[i] = u8::from_str_radix(octet, 16).map_err(|_| "invalid hex octet")?;
    }
    Ok(MacAddress::new(bytes))
}

/// Default ADR-0085 decision 3 recovery hold-off: how long a bound
/// ES's link drain is held after carrier returns. Mirrors the RFC
/// 8584 §3 DF-wait rationale (don't attract traffic before the
/// segment re-converges); FRR ships the same concept as its EVPN-MH
/// startup/recovery delay.
pub const DEFAULT_ES_RECOVERY_DELAY_SECS: u64 = 30;

/// Upper bound for `recovery_delay_secs` (one hour). Beyond this an
/// operator wants a manual ADR-0084 drain, not a timer.
pub const MAX_ES_RECOVERY_DELAY_SECS: u64 = 3600;

/// Resolved ADR-0085 attachment-circuit binding for one Ethernet
/// Segment: the link whose carrier drives the ES's `Link` drain
/// reason, plus the decision-3 recovery hold-off.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsLinkBinding {
    /// Kernel link name (the operator contract — resolution is by
    /// name on every transition; ifindex can be reused).
    pub interface: String,
    /// Hold-off between carrier return and link-drain release.
    pub recovery_delay: std::time::Duration,
}

/// Parse one [`EthernetSegmentConfig`] entry into the runtime
/// [`EthernetSegment`] domain type. Validates the ESI text form,
/// rejects Type 0 (single-homed sentinel), confirms every member
/// VNI exists in the resolved EVPN instance set, and validates the
/// ADR-0085 `interface` / `recovery_delay_secs` binding fields.
#[expect(
    clippy::too_many_lines,
    reason = "linear ESI/member-VNI/DF-algorithm/preference/redundancy-mode/binding validation reads clearest as one sequence"
)]
fn parse_ethernet_segment(
    cfg: &EthernetSegmentConfig,
    known_vnis: &BTreeSet<EvpnInstanceId>,
) -> Result<EthernetSegment, ConfigError> {
    // IFNAMSIZ-1 — the longest interface name the kernel can hold.
    const IFNAMSIZ_MAX: usize = 15;
    let esi = parse_esi(&cfg.esi).map_err(|e| ConfigError::InvalidEthernetSegment {
        reason: format!("esi {:?}: {e}", cfg.esi),
    })?;
    if esi.esi_type() == 0 && esi.octets().iter().all(|&b| b == 0) {
        return Err(ConfigError::InvalidEthernetSegment {
            reason: format!(
                "esi {:?}: Type 0 (all-zero) ESI is the single-homed sentinel; \
                 [[ethernet_segments]] entries must use a non-zero ESI",
                cfg.esi
            ),
        });
    }

    if cfg.member_vnis.is_empty() {
        return Err(ConfigError::InvalidEthernetSegment {
            reason: format!(
                "esi {:?}: member_vnis must contain at least one configured EVPN instance",
                cfg.esi
            ),
        });
    }

    let mut member_vnis: BTreeSet<EvpnInstanceId> = BTreeSet::new();
    for raw in &cfg.member_vnis {
        let id = EvpnInstanceId::new(*raw).map_err(|e| ConfigError::InvalidEthernetSegment {
            reason: format!("member_vni {raw}: {e}"),
        })?;
        if !known_vnis.contains(&id) {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "member_vni {raw} not declared in [[evpn_instances]] — every \
                     ES member VNI must have a matching EVPN instance"
                ),
            });
        }
        if !member_vnis.insert(id) {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!("duplicate member_vni {raw} within ESI {:?}", cfg.esi),
            });
        }
    }

    let df_algorithm = match cfg.df_algorithm.as_str() {
        "default-modulo" => DfAlgorithm::DefaultModulo,
        "highest-random-weight" => DfAlgorithm::HighestRandomWeight,
        "highest-preference" => DfAlgorithm::HighestPreference,
        "lowest-preference" => DfAlgorithm::LowestPreference,
        "preference-based" => {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: "df_algorithm \"preference-based\": ambiguous RFC 9785 alias; use \
                         \"highest-preference\" or \"lowest-preference\""
                    .to_string(),
            });
        }
        other => {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "df_algorithm {other:?}: must be \"default-modulo\", \
                     \"highest-random-weight\", \"highest-preference\", or \
                     \"lowest-preference\""
                ),
            });
        }
    };
    let default_preference = 32_768;
    if !matches!(
        df_algorithm,
        DfAlgorithm::HighestPreference | DfAlgorithm::LowestPreference
    ) && cfg.df_preference != default_preference
    {
        return Err(ConfigError::InvalidEthernetSegment {
            reason: format!(
                "df_preference {}: only RFC 9785 highest-/lowest-preference DF election \
                 uses preference; default-modulo and highest-random-weight require \
                 the default {default_preference}",
                cfg.df_preference
            ),
        });
    }
    if cfg.df_preference > u32::from(u16::MAX) {
        return Err(ConfigError::InvalidEthernetSegment {
            reason: format!(
                "df_preference {}: must be in the RFC 9785 range 0..=65535",
                cfg.df_preference
            ),
        });
    }
    if cfg.df_dont_preempt
        && !matches!(
            df_algorithm,
            DfAlgorithm::HighestPreference | DfAlgorithm::LowestPreference
        )
    {
        return Err(ConfigError::InvalidEthernetSegment {
            reason: "df_dont_preempt: RFC 9785 Don't-Preempt only applies to the \
                     highest-/lowest-preference DF algorithms; remove it or set \
                     df_algorithm to a preference algorithm"
                .to_string(),
        });
    }

    let redundancy_mode = match cfg.redundancy_mode.as_str() {
        "all-active" => RedundancyMode::AllActive,
        "single-active" => RedundancyMode::SingleActive,
        other => {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "redundancy_mode {other:?}: must be \"all-active\" or \"single-active\""
                ),
            });
        }
    };

    let originator_ip =
        cfg.originator_ip
            .parse::<IpAddr>()
            .map_err(|e| ConfigError::InvalidEthernetSegment {
                reason: format!("originator_ip {:?}: {e}", cfg.originator_ip),
            })?;

    // ADR-0085 decision 1: the attachment-circuit binding. Validated
    // here so EVERY config path (startup, SIGHUP, runtime apply)
    // rejects a malformed binding; the resolved daemon-side map is
    // built separately by `Config::resolve_es_link_bindings` so the
    // domain type the segment actor diffs stays binding-free.
    if let Some(interface) = cfg.interface.as_deref() {
        if interface.is_empty() {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!("esi {:?}: interface must not be empty", cfg.esi),
            });
        }
        // IFNAMSIZ-1: a longer name can never exist in the kernel, so
        // the binding would silently fail closed into a permanent
        // drain — reject the typo at config load instead.
        if interface.len() > IFNAMSIZ_MAX {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "esi {:?}: interface {interface:?} exceeds the Linux IFNAMSIZ limit \
                     of {IFNAMSIZ_MAX} characters; no kernel link can ever match it",
                    cfg.esi
                ),
            });
        }
    }
    if let Some(delay) = cfg.recovery_delay_secs {
        if cfg.interface.is_none() {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "esi {:?}: recovery_delay_secs is only meaningful with an \
                     `interface` binding (ADR-0085); remove it or bind the \
                     attachment-circuit link",
                    cfg.esi
                ),
            });
        }
        if delay > MAX_ES_RECOVERY_DELAY_SECS {
            return Err(ConfigError::InvalidEthernetSegment {
                reason: format!(
                    "esi {:?}: recovery_delay_secs {delay} outside the supported \
                     range 0..={MAX_ES_RECOVERY_DELAY_SECS}",
                    cfg.esi
                ),
            });
        }
    }

    Ok(EthernetSegment {
        esi,
        member_vnis,
        df_preference: cfg.df_preference,
        df_algorithm,
        df_dont_preempt: cfg.df_dont_preempt,
        redundancy_mode,
        originator_ip,
    })
}

/// Parse one [`EvpnIpVrfConfig`] entry into the runtime [`IpVrf`]
/// domain type. Validates the VNI range, RD / RT / Router MAC /
/// device-name shape, and table id; uniqueness across
/// `[[evpn_ip_vrfs]]` and L3↔L2 VNI overlap are checked at the
/// table-build level in `resolve_evpn_ip_vrfs`.
fn parse_evpn_ip_vrf(cfg: &EvpnIpVrfConfig, local_asn: u32) -> Result<IpVrf, ConfigError> {
    if cfg.name.trim().is_empty() {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!("evpn_ip_vrfs[vni={}]: name must not be empty", cfg.vni),
        });
    }
    // Restrict the name to a safe identifier shape — operators may
    // pass these to gRPC / logging / config diffs, and an
    // unrestricted-character name complicates every downstream tool.
    if !cfg
        .name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic())
        || !cfg
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!("name {:?}: must match ^[a-zA-Z][a-zA-Z0-9_-]*$", cfg.name),
        });
    }

    let id = IpVrfId::new(cfg.vni).map_err(|e| ConfigError::InvalidEvpnIpVrf {
        reason: format!("name {:?}: {e}", cfg.name),
    })?;

    let rd = cfg
        .rd
        .parse::<RouteDistinguisher>()
        .map_err(|e| ConfigError::InvalidEvpnIpVrf {
            reason: format!("name {:?}: invalid rd {:?}: {e}", cfg.name, cfg.rd),
        })?;

    let mut rts: Vec<RouteTarget> =
        Vec::with_capacity(cfg.route_targets.len() + usize::from(cfg.auto_derive_route_target));
    for raw in &cfg.route_targets {
        let rt = raw
            .parse::<RouteTarget>()
            .map_err(|e| ConfigError::InvalidEvpnIpVrf {
                reason: format!("name {:?}: invalid route_target {:?}: {e}", cfg.name, raw),
            })?;
        rts.push(rt);
    }
    if cfg.auto_derive_route_target {
        // L3VNI / IP-VRF: plain AS:VNI to match FRR's default tenant-VRF
        // auto-RT (the RFC 8365 opaque form is MAC-VRF-only and FRR does
        // not use it for L3VNIs, so it would not import cross-vendor).
        let rt = RouteTarget::auto_derived_ip_vrf_as_vni(local_asn, cfg.vni).map_err(|e| {
            ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "name {:?}: cannot auto_derive_route_target: {e}; disable auto_derive_route_target or configure route_targets manually",
                    cfg.name
                ),
            }
        })?;
        rts.push(rt);
    }
    if rts.is_empty() {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!("name {:?}: route_targets must not be empty", cfg.name),
        });
    }

    let local_vtep_ip =
        cfg.local_vtep_ip
            .parse::<IpAddr>()
            .map_err(|e| ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "name {:?}: invalid local_vtep_ip {:?}: {e}",
                    cfg.name, cfg.local_vtep_ip
                ),
            })?;

    let router_mac =
        parse_mac_address(&cfg.router_mac).map_err(|e| ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "name {:?}: invalid router_mac {:?}: {e}",
                cfg.name, cfg.router_mac
            ),
        })?;

    let (overlay_index_mode, esi_overlay_index) = parse_evpn_ip_vrf_overlay_index(cfg)?;
    let vrf = IpVrf::new(
        cfg.name.clone(),
        id,
        rd,
        rts,
        local_vtep_ip,
        router_mac,
        cfg.vrf_device.clone(),
        cfg.l3vxlan_device.clone(),
        cfg.table_id,
    )
    .map_err(|e| ConfigError::InvalidEvpnIpVrf {
        reason: e.to_string(),
    })?;

    if let Some(index) = esi_overlay_index {
        Ok(vrf.with_esi_overlay_index(index.esi, index.mac, index.l2vni))
    } else {
        Ok(vrf.with_overlay_index_mode(overlay_index_mode))
    }
}

#[derive(Debug, Clone, Copy)]
struct ParsedEsiOverlayIndex {
    esi: EthernetSegmentIdentifier,
    mac: MacAddress,
    l2vni: Option<EvpnInstanceId>,
}

fn parse_evpn_ip_vrf_overlay_index(
    cfg: &EvpnIpVrfConfig,
) -> Result<(OverlayIndexMode, Option<ParsedEsiOverlayIndex>), ConfigError> {
    let mode = match cfg.overlay_index_mode {
        OverlayIndexModeConfig::InterfaceLess => OverlayIndexMode::InterfaceLess,
        OverlayIndexModeConfig::GatewayIp => OverlayIndexMode::GatewayIp,
        OverlayIndexModeConfig::Esi => OverlayIndexMode::Esi,
    };
    let l2vni = cfg
        .overlay_index_l2vni
        .map(EvpnInstanceId::new)
        .transpose()
        .map_err(|e| ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "name {:?}: invalid overlay_index_l2vni {:?}: {e}",
                cfg.name, cfg.overlay_index_l2vni
            ),
        })?;
    let esi = cfg
        .overlay_index_esi
        .as_deref()
        .map(parse_esi)
        .transpose()
        .map_err(|e| ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "name {:?}: invalid overlay_index_esi {:?}: {e}",
                cfg.name, cfg.overlay_index_esi
            ),
        })?;
    let mac = cfg
        .overlay_index_mac
        .as_deref()
        .map(parse_mac_address)
        .transpose()
        .map_err(|e| ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "name {:?}: invalid overlay_index_mac {:?}: {e}",
                cfg.name, cfg.overlay_index_mac
            ),
        })?;

    if mode != OverlayIndexMode::Esi {
        if esi.is_some() || mac.is_some() || l2vni.is_some() {
            return Err(ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "evpn_ip_vrfs[{}]: overlay_index_esi, overlay_index_mac, and \
                     overlay_index_l2vni are only valid when overlay_index_mode = \"esi\"",
                    cfg.name
                ),
            });
        }
        return Ok((mode, None));
    }

    let Some(esi) = esi else {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" requires overlay_index_esi",
                cfg.name
            ),
        });
    };
    if esi == EthernetSegmentIdentifier::ZERO {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_esi must be non-zero for ESI overlay-index Type 5",
                cfg.name
            ),
        });
    }
    let Some(mac) = mac else {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" requires overlay_index_mac",
                cfg.name
            ),
        });
    };
    if !is_unicast_nonzero_mac(mac) {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mac must be a unicast non-zero MAC",
                cfg.name
            ),
        });
    }
    Ok((mode, Some(ParsedEsiOverlayIndex { esi, mac, l2vni })))
}

fn validate_esi_overlay_index_vrf(
    vrf: &IpVrf,
    table: &IpVrfTable,
    es_members_by_esi: &BTreeMap<EthernetSegmentIdentifier, BTreeSet<EvpnInstanceId>>,
) -> Result<(), ConfigError> {
    let esi = vrf
        .overlay_index_esi
        .ok_or_else(|| ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" requires overlay_index_esi",
                vrf.name
            ),
        })?;
    let Some(segment_members) = es_members_by_esi.get(&esi) else {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_esi {:02x?} does not match any configured \
                 [[ethernet_segments]].esi",
                vrf.name,
                esi.octets()
            ),
        });
    };
    let linked =
        table
            .referenced_l2vnis(&vrf.name)
            .ok_or_else(|| ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" requires at least one \
                 [[evpn_instances]] with ip_vrf = {:?}",
                    vrf.name, vrf.name
                ),
            })?;
    if linked.is_empty() {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" requires at least one \
                 [[evpn_instances]] with ip_vrf = {:?}",
                vrf.name, vrf.name
            ),
        });
    }
    let selected = if let Some(vni) = vrf.overlay_index_l2vni {
        if !linked.contains(&vni) {
            return Err(ConfigError::InvalidEvpnIpVrf {
                reason: format!(
                    "evpn_ip_vrfs[{}]: overlay_index_l2vni {} is not linked to this IP-VRF",
                    vrf.name,
                    vni.as_u32()
                ),
            });
        }
        vni
    } else if linked.len() == 1 {
        *linked.iter().next().expect("len checked")
    } else {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_mode = \"esi\" with multiple linked L2VNIs \
                 requires overlay_index_l2vni",
                vrf.name
            ),
        });
    };
    if !segment_members.contains(&selected) {
        return Err(ConfigError::InvalidEvpnIpVrf {
            reason: format!(
                "evpn_ip_vrfs[{}]: overlay_index_l2vni {} is not a member of overlay_index_esi {:02x?}",
                vrf.name,
                selected.as_u32(),
                esi.octets()
            ),
        });
    }
    Ok(())
}

fn is_unicast_nonzero_mac(mac: MacAddress) -> bool {
    let octets = mac.octets();
    octets != [0; 6] && (octets[0] & 1) == 0
}

/// Parse a 10-byte ESI from operator text form
/// (`XX:XX:XX:XX:XX:XX:XX:XX:XX:XX`). Each octet must be exactly
/// two hex digits. The wire crate intentionally doesn't implement
/// `FromStr` on `EthernetSegmentIdentifier` (the on-the-wire form
/// is raw bytes, not the operator notation), so the daemon owns
/// this parse.
fn parse_esi(raw: &str) -> Result<EthernetSegmentIdentifier, &'static str> {
    let parts: Vec<&str> = raw.split(':').collect();
    if parts.len() != 10 {
        return Err("expected 10 colon-separated hex octets");
    }
    let mut bytes = [0u8; 10];
    for (i, octet) in parts.iter().enumerate() {
        if octet.len() != 2 {
            return Err("each octet must be exactly 2 hex digits");
        }
        bytes[i] = u8::from_str_radix(octet, 16).map_err(|_| "invalid hex octet")?;
    }
    Ok(EthernetSegmentIdentifier::new(bytes))
}

/// Resolve the `[gnmi_dialout]` section into runtime dial-out target
/// specs. Single source of truth for the section's semantic validation:
/// `Config::validate` calls this at load (startup AND SIGHUP reload
/// preflight) so a config that loads always translates, and the daemon /
/// reload wiring reuses the same resolution to (re)apply targets.
///
/// Subscription paths and modes are validated through the api crate's
/// `build_subscription_list`, which runs the exact checks a dial-in
/// `Subscribe` request would — a path the Subscribe server would reject
/// is rejected here, at config load.
pub(crate) fn gnmi_dialout_targets(
    config: &Config,
) -> Result<Vec<rustbgpd_api::gnmi_dialout::DialoutTarget>, String> {
    use rustbgpd_api::gnmi_dialout as dialout;

    let Some(section) = config.gnmi_dialout.as_ref() else {
        return Ok(Vec::new());
    };
    let mut seen_names = HashSet::new();
    let mut targets = Vec::with_capacity(section.targets.len());
    for (i, target) in section.targets.iter().enumerate() {
        let fail = |reason: String| format!("targets[{i}]: {reason}");
        if target.name.is_empty() {
            return Err(fail("name must not be empty".to_string()));
        }
        if !seen_names.insert(target.name.as_str()) {
            return Err(fail(format!("duplicate name {:?}", target.name)));
        }
        // host:port shape (DNS names allowed, IPv6 literals bracketed).
        let addr_ok = target
            .address
            .rsplit_once(':')
            .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
        if !addr_ok {
            return Err(fail(format!(
                "address {:?} must be host:port",
                target.address
            )));
        }
        match (&target.tls_cert_file, &target.tls_key_file) {
            (Some(_), None) | (None, Some(_)) => {
                return Err(fail(
                    "tls_cert_file and tls_key_file must be set together".to_string(),
                ));
            }
            (Some(_), Some(_)) if target.tls_ca_file.is_none() => {
                return Err(fail(
                    "tls_cert_file/tls_key_file require tls_ca_file".to_string(),
                ));
            }
            _ => {}
        }
        if target.tls_server_name.is_some() && target.tls_ca_file.is_none() {
            return Err(fail("tls_server_name requires tls_ca_file".to_string()));
        }
        if target.sample_interval == 0 {
            return Err(fail("sample_interval must be > 0".to_string()));
        }
        if target.backoff_initial == 0 {
            return Err(fail("backoff_initial must be > 0".to_string()));
        }
        if target.backoff_max < target.backoff_initial {
            return Err(fail("backoff_max must be >= backoff_initial".to_string()));
        }
        let mode = match target.mode {
            GnmiDialoutModeConfig::Sample => dialout::DialoutMode::Sample,
            GnmiDialoutModeConfig::OnChange => dialout::DialoutMode::OnChange,
        };
        if mode == dialout::DialoutMode::OnChange && !config.event_history.enabled {
            return Err(fail(
                "mode = \"on_change\" requires [event_history].enabled = true \
                 (the durable event outbox sources the transitions)"
                    .to_string(),
            ));
        }
        let subscriptions = dialout::build_subscription_list(
            &target.paths,
            mode,
            std::time::Duration::from_secs(target.sample_interval),
        )
        .map_err(fail)?;
        let tls = target.tls_ca_file.as_ref().map(|ca| dialout::DialoutTls {
            ca_file: PathBuf::from(ca),
            cert_file: target.tls_cert_file.as_ref().map(PathBuf::from),
            key_file: target.tls_key_file.as_ref().map(PathBuf::from),
            server_name: target.tls_server_name.clone(),
        });
        targets.push(dialout::DialoutTarget {
            name: target.name.clone(),
            endpoint: dialout::endpoint_uri(&target.address, tls.is_some()),
            tls,
            subscriptions,
            backoff_initial: std::time::Duration::from_secs(target.backoff_initial),
            backoff_max: std::time::Duration::from_secs(target.backoff_max),
        });
    }
    Ok(targets)
}

#[cfg(test)]
mod tests;
