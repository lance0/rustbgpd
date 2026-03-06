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
        if self.neighbors.iter().any(|n| n.route_reflector_client) {
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
            Ok(parse_policy(&self.policy.import)?.map(|p| PolicyChain::new(vec![p])))
        } else {
            resolve_chain(&self.policy.import_chain, &self.policy.definitions)
        }
    }

    /// Resolve the global export policy chain.
    pub fn export_chain(&self) -> Result<Option<PolicyChain>, ConfigError> {
        if self.policy.export_chain.is_empty() {
            Ok(parse_policy(&self.policy.export)?.map(|p| PolicyChain::new(vec![p])))
        } else {
            resolve_chain(&self.policy.export_chain, &self.policy.definitions)
        }
    }

    /// Returns `(TransportConfig, label, import_chain, export_chain)` per neighbor.
    ///
    /// Per-neighbor policy overrides global; if neighbor has no policy entries,
    /// the corresponding value is `None` (caller falls back to global).
    #[expect(clippy::type_complexity)]
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
        let router_id: Ipv4Addr = self
            .global
            .router_id
            .parse()
            .expect("validated in Config::load");

        let global_import = self.import_chain()?;
        let global_export = self.export_chain()?;

        let mut configs = Vec::with_capacity(self.neighbors.len());
        for neighbor in &self.neighbors {
            let peer_addr: IpAddr = neighbor.address.parse().expect("validated in Config::load");

            let families = if neighbor.families.is_empty() {
                // Default: IPv4 unicast always. If neighbor is IPv6, also add IPv6 unicast.
                let mut f = vec![(Afi::Ipv4, Safi::Unicast)];
                if peer_addr.is_ipv6() {
                    f.push((Afi::Ipv6, Safi::Unicast));
                }
                f
            } else {
                parse_families(&neighbor.families)?
            };

            let peer = PeerConfig {
                local_asn: self.global.asn,
                remote_asn: neighbor.remote_asn,
                local_router_id: router_id,
                hold_time: neighbor.hold_time.unwrap_or(DEFAULT_HOLD_TIME),
                connect_retry_secs: DEFAULT_CONNECT_RETRY_SECS,
                families,
                graceful_restart: neighbor.graceful_restart.unwrap_or(true),
                gr_restart_time: neighbor.gr_restart_time.unwrap_or(120),
                llgr_stale_time: neighbor.llgr_stale_time.unwrap_or(0),
                add_path_receive: neighbor.add_path.as_ref().is_some_and(|c| c.receive),
                add_path_send: neighbor.add_path.as_ref().is_some_and(|c| c.send),
                add_path_send_max: neighbor
                    .add_path
                    .as_ref()
                    .and_then(|c| c.send_max)
                    .unwrap_or(0),
            };

            let remote_addr = SocketAddr::new(peer_addr, BGP_PORT);
            let mut transport = TransportConfig::new(peer, remote_addr);
            transport.max_prefixes = neighbor.max_prefixes;
            transport.md5_password.clone_from(&neighbor.md5_password);
            transport.ttl_security = neighbor.ttl_security;
            transport.local_ipv6_nexthop = neighbor
                .local_ipv6_nexthop
                .as_ref()
                .map(|s| s.parse::<Ipv6Addr>().expect("validated in Config::load"));
            transport.gr_stale_routes_time = neighbor.gr_stale_routes_time.unwrap_or(360);
            transport.llgr_stale_time = neighbor.llgr_stale_time.unwrap_or(0);
            transport.route_server_client = neighbor.route_server_client;
            transport.remove_private_as = match neighbor.remove_private_as.as_deref() {
                Some("remove") => RemovePrivateAs::Remove,
                Some("all") => RemovePrivateAs::All,
                Some("replace") => RemovePrivateAs::Replace,
                _ => RemovePrivateAs::Disabled,
            };

            let label = neighbor
                .description
                .clone()
                .unwrap_or_else(|| neighbor.address.clone());

            // Per-neighbor policy: chain > inline > global fallback
            let import = if neighbor.import_policy_chain.is_empty() {
                parse_policy(&neighbor.import_policy)?.map(|p| PolicyChain::new(vec![p]))
            } else {
                resolve_chain(&neighbor.import_policy_chain, &self.policy.definitions)?
            }
            .or_else(|| global_import.clone());
            let export = if neighbor.export_policy_chain.is_empty() {
                parse_policy(&neighbor.export_policy)?.map(|p| PolicyChain::new(vec![p]))
            } else {
                resolve_chain(&neighbor.export_policy_chain, &self.policy.definitions)?
            }
            .or_else(|| global_export.clone());

            configs.push((transport, label, import, export));
        }
        Ok(configs)
    }
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
