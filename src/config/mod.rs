pub mod diagnostic;
mod parse;
mod schema;
mod validation;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::{
    CommunityMatch, NextHopAction, Policy, PolicyAction, PolicyChain, PolicyStatement,
    RouteModifications, parse_community_match,
};
use rustbgpd_transport::{RemovePrivateAs, TransportConfig};
use rustbgpd_wire::{Afi, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, LargeCommunity, Prefix, Safi};

pub use schema::*;

use self::parse::{parse_families, parse_policy, resolve_chain};
use self::schema::{BGP_PORT, DEFAULT_CONNECT_RETRY_SECS, DEFAULT_HOLD_TIME};

#[cfg(test)]
use self::parse::parse_named_policy;

impl Config {
    /// Load config and, on failure, render a diagnostic with source context.
    ///
    /// Returns the rendered diagnostic string on error (suitable for direct
    /// printing to stderr). Falls back to plain `Display` if no source span
    /// can be determined.
    pub fn load_with_diagnostics(path: &str) -> Result<Self, String> {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => return Err(format!("error: failed to read {path}: {e}")),
        };
        let mut config: Config = match toml::from_str(&content) {
            Ok(c) => c,
            Err(e) => {
                let error = ConfigError::Parse(e);
                return Err(diagnostic::render_diagnostic(&content, path, &error)
                    .unwrap_or_else(|| format!("error: {error}")));
            }
        };
        config.file_path = Some(PathBuf::from(path));
        if let Err(error) = config.validate() {
            return Err(diagnostic::render_diagnostic(&content, path, &error)
                .unwrap_or_else(|| format!("error: {error}")));
        }
        Ok(config)
    }

    pub fn prometheus_addr(&self) -> Option<SocketAddr> {
        self.global
            .telemetry
            .prometheus_addr
            .as_ref()
            .map(|s| s.parse().expect("validated in Config::load"))
    }

    pub fn looking_glass_addr(&self) -> Option<SocketAddr> {
        self.global
            .telemetry
            .looking_glass
            .as_ref()
            .map(|lg| lg.addr.parse().expect("validated in Config::load"))
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
                token_file: None,
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
            listeners.push(GrpcListener::Tcp {
                addr,
                access_mode: cfg
                    .access_mode
                    .map_or(GrpcAccessMode::ReadWrite, Into::into),
                token_file: cfg.token_file.as_ref().map(PathBuf::from),
            });
        }
        if let Some(cfg) = uds {
            let path = cfg
                .path
                .as_ref()
                .map_or_else(|| self.default_grpc_uds_path(), PathBuf::from);
            listeners.push(GrpcListener::Uds {
                path,
                mode: cfg.mode,
                access_mode: cfg
                    .access_mode
                    .map_or(GrpcAccessMode::ReadWrite, Into::into),
                token_file: cfg.token_file.as_ref().map(PathBuf::from),
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

    #[must_use]
    pub fn default_grpc_uds_path(&self) -> PathBuf {
        self.runtime_state_dir().join("grpc.sock")
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

    /// Resolve the global import policy chain.
    ///
    /// If `import_chain` is set, resolves named policies. Otherwise wraps
    /// the inline `import` entries as a single-policy chain.
    pub fn import_chain(&self) -> Result<Option<PolicyChain>, ConfigError> {
        if self.policy.import_chain.is_empty() {
            let policy = parse_policy(
                &self.policy.import,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?;

            Ok(policy.map(|p| PolicyChain::new(vec![p])))
        } else {
            let chain = resolve_chain(
                &self.policy.import_chain,
                &self.policy.definitions,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?;

            Ok(chain)
        }
    }

    /// Resolve the global export policy chain.
    pub fn export_chain(&self) -> Result<Option<PolicyChain>, ConfigError> {
        if self.policy.export_chain.is_empty() {
            Ok(parse_policy(
                &self.policy.export,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?
            .map(|p| PolicyChain::new(vec![p])))
        } else {
            resolve_chain(
                &self.policy.export_chain,
                &self.policy.definitions,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )
        }
    }

    /// Resolve the effective import/export policy chains for one neighbor.
    ///
    /// Per-neighbor named chain overrides per-neighbor inline policy, which
    /// overrides the corresponding global named chain or global inline policy.
    pub fn effective_policy_chains_for_neighbor(
        &self,
        neighbor: &Neighbor,
    ) -> Result<(Option<PolicyChain>, Option<PolicyChain>), ConfigError> {
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
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
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
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
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
                &self.policy.neighbor_sets,
                &self.peer_groups,
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
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?
        }
        .or_else(|| global_export.clone());

        Ok((import, export))
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

    pub(crate) fn resolve_neighbor(
        &self,
        neighbor: &Neighbor,
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

        let peer = PeerConfig {
            local_asn: self.global.asn,
            remote_asn: neighbor.remote_asn,
            local_router_id: router_id,
            hold_time: neighbor
                .hold_time
                .or_else(|| group.and_then(|g| g.hold_time))
                .unwrap_or(DEFAULT_HOLD_TIME),
            connect_retry_secs: DEFAULT_CONNECT_RETRY_SECS,
            families,
            graceful_restart: neighbor
                .graceful_restart
                .or_else(|| group.and_then(|g| g.graceful_restart))
                .unwrap_or(true),
            gr_restart_time: neighbor
                .gr_restart_time
                .or_else(|| group.and_then(|g| g.gr_restart_time))
                .unwrap_or(120),
            llgr_stale_time: neighbor
                .llgr_stale_time
                .or_else(|| group.and_then(|g| g.llgr_stale_time))
                .unwrap_or(0),
            add_path_receive: add_path.as_ref().is_some_and(|c| c.receive),
            add_path_send: add_path.as_ref().is_some_and(|c| c.send),
            add_path_send_max: add_path.as_ref().and_then(|c| c.send_max).unwrap_or(0),
        };

        let remote_addr = SocketAddr::new(peer_addr, BGP_PORT);
        let mut transport = TransportConfig::new(peer, remote_addr);
        transport.max_prefixes = neighbor
            .max_prefixes
            .or_else(|| group.and_then(|g| g.max_prefixes));
        transport.peer_group.clone_from(&neighbor.peer_group);
        transport.md5_password = neighbor
            .md5_password
            .clone()
            .or_else(|| group.and_then(|g| g.md5_password.clone()));
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
        transport.llgr_stale_time = neighbor
            .llgr_stale_time
            .or_else(|| group.and_then(|g| g.llgr_stale_time))
            .unwrap_or(0);
        transport.route_server_client = neighbor
            .route_server_client
            .or_else(|| group.and_then(|g| g.route_server_client))
            .unwrap_or(false);
        transport.route_reflector_client = neighbor
            .route_reflector_client
            .or_else(|| group.and_then(|g| g.route_reflector_client))
            .unwrap_or(false);
        transport.remove_private_as = Self::resolved_remove_private_as(neighbor, group);

        let (import_policy, export_policy) = self.effective_policy_chains_for_neighbor(neighbor)?;

        Ok(ResolvedNeighbor {
            transport_config: transport,
            label: neighbor
                .description
                .clone()
                .unwrap_or_else(|| neighbor.address.clone()),
            import_policy,
            export_policy,
            peer_group: neighbor.peer_group.clone(),
        })
    }

    pub fn resolved_neighbors(&self) -> Result<Vec<ResolvedNeighbor>, ConfigError> {
        self.neighbors
            .iter()
            .map(|neighbor| self.resolve_neighbor(neighbor))
            .collect()
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
    /// Returns directives like `peer{peer_addr=10.0.0.1}=debug` that can be
    /// appended to an `EnvFilter`.
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
                    "peer{{peer_addr={addr}}}={level}",
                    addr = neighbor.address
                ));
            }
        }
        directives
    }
}

#[derive(Clone)]
pub struct ResolvedNeighbor {
    pub transport_config: TransportConfig,
    pub label: String,
    pub import_policy: Option<PolicyChain>,
    pub export_policy: Option<PolicyChain>,
    pub peer_group: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum GrpcListener {
    Tcp {
        addr: SocketAddr,
        access_mode: GrpcAccessMode,
        token_file: Option<PathBuf>,
    },
    Uds {
        path: PathBuf,
        mode: u32,
        access_mode: GrpcAccessMode,
        token_file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrpcAccessMode {
    ReadOnly,
    ReadWrite,
}

/// Differences between two neighbor lists, keyed by address.
pub struct NeighborDiff {
    pub added: Vec<Neighbor>,
    pub removed: Vec<IpAddr>,
    pub changed: Vec<Neighbor>,
}

/// Describe which fields changed between two `Neighbor` configurations.
///
/// Returns a list of human-readable change descriptions (e.g. "`hold_time`: 90 → 45").
pub fn describe_neighbor_changes(old: &Neighbor, new: &Neighbor) -> Vec<String> {
    let mut changes = Vec::new();

    macro_rules! cmp_field {
        ($field:ident) => {
            if old.$field != new.$field {
                changes.push(format!(
                    "{}: {:?} → {:?}",
                    stringify!($field),
                    old.$field,
                    new.$field
                ));
            }
        };
    }

    cmp_field!(remote_asn);
    cmp_field!(description);
    cmp_field!(peer_group);
    cmp_field!(hold_time);
    cmp_field!(max_prefixes);
    cmp_field!(ttl_security);
    cmp_field!(families);
    cmp_field!(graceful_restart);
    cmp_field!(gr_restart_time);
    cmp_field!(gr_stale_routes_time);
    cmp_field!(llgr_stale_time);
    cmp_field!(local_ipv6_nexthop);
    cmp_field!(route_reflector_client);
    cmp_field!(route_server_client);
    cmp_field!(remove_private_as);
    cmp_field!(add_path);
    cmp_field!(log_level);

    // md5_password: log change without revealing values
    if old.md5_password != new.md5_password {
        changes.push("md5_password: <changed>".to_string());
    }

    // Policy changes: summarize rather than dump full config
    if old.import_policy != new.import_policy {
        changes.push("import_policy: <changed>".to_string());
    }
    if old.export_policy != new.export_policy {
        changes.push("export_policy: <changed>".to_string());
    }
    if old.import_policy_chain != new.import_policy_chain {
        changes.push(format!(
            "import_policy_chain: {:?} → {:?}",
            old.import_policy_chain, new.import_policy_chain
        ));
    }
    if old.export_policy_chain != new.export_policy_chain {
        changes.push(format!(
            "export_policy_chain: {:?} → {:?}",
            old.export_policy_chain, new.export_policy_chain
        ));
    }

    changes
}

/// Compare two neighbor lists and return the differences.
///
/// Two neighbors with the same address but different configuration
/// (any field difference) are reported in `changed`.
pub fn diff_neighbors(old: &[Neighbor], new: &[Neighbor]) -> NeighborDiff {
    let old_map: std::collections::HashMap<&str, &Neighbor> =
        old.iter().map(|n| (n.address.as_str(), n)).collect();
    let new_map: std::collections::HashMap<&str, &Neighbor> =
        new.iter().map(|n| (n.address.as_str(), n)).collect();

    let mut added = Vec::new();
    let mut changed = Vec::new();
    for (addr, new_n) in &new_map {
        match old_map.get(addr) {
            None => added.push((*new_n).clone()),
            Some(old_n) => {
                if *old_n != *new_n {
                    changed.push((*new_n).clone());
                }
            }
        }
    }

    let removed: Vec<IpAddr> = old_map
        .keys()
        .filter(|addr| !new_map.contains_key(*addr))
        .filter_map(|addr| addr.parse::<IpAddr>().ok())
        .collect();

    NeighborDiff {
        added,
        removed,
        changed,
    }
}

/// Differences between two peer group maps, keyed by name.
#[derive(Debug, serde::Serialize)]
pub struct PeerGroupDiff {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
}

/// Differences between two policy configurations.
#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, serde::Serialize)]
pub struct PolicyDiff {
    pub definitions_added: Vec<String>,
    pub definitions_removed: Vec<String>,
    pub definitions_changed: Vec<String>,
    pub neighbor_sets_added: Vec<String>,
    pub neighbor_sets_removed: Vec<String>,
    pub neighbor_sets_changed: Vec<String>,
    pub import_changed: bool,
    pub export_changed: bool,
    pub import_chain_changed: bool,
    pub export_chain_changed: bool,
}

impl PolicyDiff {
    pub fn has_changes(&self) -> bool {
        !self.definitions_added.is_empty()
            || !self.definitions_removed.is_empty()
            || !self.definitions_changed.is_empty()
            || !self.neighbor_sets_added.is_empty()
            || !self.neighbor_sets_removed.is_empty()
            || !self.neighbor_sets_changed.is_empty()
            || self.import_changed
            || self.export_changed
            || self.import_chain_changed
            || self.export_chain_changed
    }
}

/// Full config diff result.
#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, serde::Serialize)]
pub struct ConfigDiff {
    pub neighbors: NeighborDiffSummary,
    pub peer_groups: PeerGroupDiff,
    pub peer_group_details: Vec<(String, Vec<String>)>,
    pub policy: PolicyDiff,
    pub global_changed: bool,
    pub rpki_changed: bool,
    pub bmp_changed: bool,
    pub mrt_changed: bool,
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
    pub changes: Vec<String>,
}

impl ConfigDiff {
    /// Changes that SIGHUP will actually reconcile (neighbor add/remove/modify).
    pub fn has_reload_applied_changes(&self) -> bool {
        !self.neighbors.added.is_empty()
            || !self.neighbors.removed.is_empty()
            || !self.neighbors.changed.is_empty()
    }

    /// Changes that require a full daemon restart.
    pub fn has_restart_required_changes(&self) -> bool {
        self.global_changed || self.rpki_changed || self.bmp_changed || self.mrt_changed
    }

    /// Changes detected but not applied by current SIGHUP (peer groups, policy).
    pub fn has_informational_changes(&self) -> bool {
        !self.peer_groups.added.is_empty()
            || !self.peer_groups.removed.is_empty()
            || !self.peer_groups.changed.is_empty()
            || self.policy.has_changes()
    }

    /// Whether SIGHUP would take any action (reload-applied or restart-required).
    pub fn has_actionable_changes(&self) -> bool {
        self.has_reload_applied_changes() || self.has_restart_required_changes()
    }

    /// Whether any difference exists at all.
    pub fn has_any_changes(&self) -> bool {
        self.has_actionable_changes() || self.has_informational_changes()
    }
}

/// Compare two full configurations and return a structured diff.
pub fn diff_config(old: &Config, new: &Config) -> ConfigDiff {
    let neighbor_diff = diff_neighbors(&old.neighbors, &new.neighbors);

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
            .map(IpAddr::to_string)
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

    let peer_groups = diff_peer_groups(&old.peer_groups, &new.peer_groups);
    let peer_group_details = peer_groups
        .changed
        .iter()
        .filter_map(|name| {
            let old_pg = old.peer_groups.get(name)?;
            let new_pg = new.peer_groups.get(name)?;
            let changes = describe_peer_group_changes(old_pg, new_pg);
            if changes.is_empty() {
                None
            } else {
                Some((name.clone(), changes))
            }
        })
        .collect();

    let policy = diff_policy(&old.policy, &new.policy);

    ConfigDiff {
        neighbors,
        peer_groups,
        peer_group_details,
        policy,
        global_changed: old.global != new.global,
        rpki_changed: old.rpki != new.rpki,
        bmp_changed: old.bmp != new.bmp,
        mrt_changed: old.mrt != new.mrt,
    }
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
pub fn describe_peer_group_changes(old: &PeerGroupConfig, new: &PeerGroupConfig) -> Vec<String> {
    let mut changes = Vec::new();

    macro_rules! cmp_field {
        ($field:ident) => {
            if old.$field != new.$field {
                changes.push(format!(
                    "{}: {:?} → {:?}",
                    stringify!($field),
                    old.$field,
                    new.$field
                ));
            }
        };
    }

    cmp_field!(hold_time);
    cmp_field!(max_prefixes);
    cmp_field!(ttl_security);
    cmp_field!(families);
    cmp_field!(graceful_restart);
    cmp_field!(gr_restart_time);
    cmp_field!(gr_stale_routes_time);
    cmp_field!(llgr_stale_time);
    cmp_field!(local_ipv6_nexthop);
    cmp_field!(route_reflector_client);
    cmp_field!(route_server_client);
    cmp_field!(remove_private_as);
    cmp_field!(add_path);
    cmp_field!(log_level);

    if old.md5_password != new.md5_password {
        changes.push("md5_password: <changed>".to_string());
    }
    if old.import_policy != new.import_policy {
        changes.push("import_policy: <changed>".to_string());
    }
    if old.export_policy != new.export_policy {
        changes.push("export_policy: <changed>".to_string());
    }
    if old.import_policy_chain != new.import_policy_chain {
        changes.push(format!(
            "import_policy_chain: {:?} → {:?}",
            old.import_policy_chain, new.import_policy_chain
        ));
    }
    if old.export_policy_chain != new.export_policy_chain {
        changes.push(format!(
            "export_policy_chain: {:?} → {:?}",
            old.export_policy_chain, new.export_policy_chain
        ));
    }

    changes
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
        import_changed: old.import != new.import,
        export_changed: old.export != new.export,
        import_chain_changed: old.import_chain != new.import_chain,
        export_chain_changed: old.export_chain != new.export_chain,
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

#[cfg(test)]
mod tests;
