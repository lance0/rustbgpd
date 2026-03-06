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
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let mut config: Config = toml::from_str(&content)?;
        config.file_path = Some(PathBuf::from(path));
        config.validate()?;
        Ok(config)
    }

    pub fn prometheus_addr(&self) -> SocketAddr {
        self.global
            .telemetry
            .prometheus_addr
            .parse()
            .expect("validated in Config::load")
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
            Ok(parse_policy(
                &self.policy.import,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?
            .map(|p| PolicyChain::new(vec![p])))
        } else {
            resolve_chain(
                &self.policy.import_chain,
                &self.policy.definitions,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )
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
                parse_policy(
                    &group.import_policy,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?
                .map(|p| PolicyChain::new(vec![p]))
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
                parse_policy(
                    &neighbor.import_policy,
                    &self.policy.neighbor_sets,
                    &self.peer_groups,
                )?
                .map(|p| PolicyChain::new(vec![p]))
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
        token_file: Option<PathBuf>,
    },
    Uds {
        path: PathBuf,
        mode: u32,
        token_file: Option<PathBuf>,
    },
}

/// Differences between two neighbor lists, keyed by address.
pub struct NeighborDiff {
    pub added: Vec<Neighbor>,
    pub removed: Vec<IpAddr>,
    pub changed: Vec<Neighbor>,
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

#[cfg(test)]
mod tests;
