//! Helpers for policy CRUD config mutations and conversions.

use std::net::IpAddr;

use rustbgpd_api::peer_types::{
    AddPathDefinition, ConfigEvent, FibTableSnapshot, NamedNeighborSetSnapshot,
    NamedPeerGroupSnapshot, NamedPolicyDefinition, NamedPolicySnapshot, NeighborSetDefinition,
    PeerGroupDefinition, PolicyAsPathPrependConfig, PolicyChainAssignment,
    PolicyStatementDefinition,
};

use crate::config::{
    AddPathConfig, AsPathPrependConfig, BgpRoleConfig, Config, ConfigError, FibTableConfig,
    NamedPolicyConfig, Neighbor, NeighborSetConfig, NextHopOwnershipConfig, PeerGroupConfig,
    PolicyStatementConfig, TcpAoConfig, TcpAoKeyringConfig,
};

/// `None` for a registry role this build has no config form for
/// (`BgpRole` is non-exhaustive): the snapshot omits the role rather
/// than fabricating one.
const fn wire_role_to_config(role: rustbgpd_wire::BgpRole) -> Option<BgpRoleConfig> {
    match role {
        rustbgpd_wire::BgpRole::Provider => Some(BgpRoleConfig::Provider),
        rustbgpd_wire::BgpRole::RouteServer => Some(BgpRoleConfig::RouteServer),
        rustbgpd_wire::BgpRole::RouteServerClient => Some(BgpRoleConfig::RouteServerClient),
        rustbgpd_wire::BgpRole::Customer => Some(BgpRoleConfig::Customer),
        rustbgpd_wire::BgpRole::Peer => Some(BgpRoleConfig::Peer),
        _ => None,
    }
}

fn api_prepend_to_config(
    prepend: Option<PolicyAsPathPrependConfig>,
) -> Option<AsPathPrependConfig> {
    prepend.map(|prepend| AsPathPrependConfig {
        asn: prepend.asn,
        count: prepend.count,
    })
}

fn config_prepend_to_api(
    prepend: Option<&AsPathPrependConfig>,
) -> Option<PolicyAsPathPrependConfig> {
    prepend.map(|prepend| PolicyAsPathPrependConfig {
        asn: prepend.asn,
        count: prepend.count,
    })
}

fn api_add_path_to_config(add_path: Option<AddPathDefinition>) -> Option<AddPathConfig> {
    add_path.map(|add_path| AddPathConfig {
        receive: add_path.receive,
        send: add_path.send,
        send_max: add_path.send_max,
        receive_max: add_path.receive_max,
    })
}

fn transport_tcp_ao_to_config(tcp_ao: &rustbgpd_transport::TcpAoKeyring) -> TcpAoKeyringConfig {
    TcpAoKeyringConfig(
        tcp_ao
            .iter()
            .map(|key| TcpAoConfig {
                key: key.key.as_ref().to_owned(),
                send_id: key.send_id,
                recv_id: key.recv_id,
                algorithm: key.algorithm.linux_name().to_string(),
                preferred: key.preferred,
                deprecated: key.deprecated,
            })
            .collect(),
    )
}

fn config_add_path_to_api(add_path: Option<&AddPathConfig>) -> Option<AddPathDefinition> {
    add_path.map(|add_path| AddPathDefinition {
        receive: add_path.receive,
        send: add_path.send,
        send_max: add_path.send_max,
        receive_max: add_path.receive_max,
    })
}

fn api_statement_to_config(statement: PolicyStatementDefinition) -> PolicyStatementConfig {
    PolicyStatementConfig {
        action: statement.action,
        prefix: statement.prefix,
        ge: statement.ge,
        le: statement.le,
        match_community: statement.match_community,
        match_as_path: statement.match_as_path,
        match_neighbor_set: statement.match_neighbor_set,
        match_route_type: statement.match_route_type,
        match_evpn_route_type: statement.match_evpn_route_type,
        match_as_path_length_ge: statement.match_as_path_length_ge,
        match_as_path_length_le: statement.match_as_path_length_le,
        match_local_pref_ge: statement.match_local_pref_ge,
        match_local_pref_le: statement.match_local_pref_le,
        match_med_ge: statement.match_med_ge,
        match_med_le: statement.match_med_le,
        match_next_hop: statement.match_next_hop,
        match_rpki_validation: statement.match_rpki_validation,
        match_aspa_validation: statement.match_aspa_validation,
        set_local_pref: statement.set_local_pref,
        set_med: statement.set_med,
        set_next_hop: statement.set_next_hop,
        set_community_add: statement.set_community_add,
        set_community_remove: statement.set_community_remove,
        set_as_path_prepend: api_prepend_to_config(statement.set_as_path_prepend),
    }
}

fn config_statement_to_api(statement: &PolicyStatementConfig) -> PolicyStatementDefinition {
    PolicyStatementDefinition {
        action: statement.action.clone(),
        prefix: statement.prefix.clone(),
        ge: statement.ge,
        le: statement.le,
        match_community: statement.match_community.clone(),
        match_as_path: statement.match_as_path.clone(),
        match_neighbor_set: statement.match_neighbor_set.clone(),
        match_route_type: statement.match_route_type.clone(),
        match_evpn_route_type: statement.match_evpn_route_type,
        match_as_path_length_ge: statement.match_as_path_length_ge,
        match_as_path_length_le: statement.match_as_path_length_le,
        match_local_pref_ge: statement.match_local_pref_ge,
        match_local_pref_le: statement.match_local_pref_le,
        match_med_ge: statement.match_med_ge,
        match_med_le: statement.match_med_le,
        match_next_hop: statement.match_next_hop.clone(),
        match_rpki_validation: statement.match_rpki_validation.clone(),
        match_aspa_validation: statement.match_aspa_validation.clone(),
        set_local_pref: statement.set_local_pref,
        set_med: statement.set_med,
        set_next_hop: statement.set_next_hop.clone(),
        set_community_add: statement.set_community_add.clone(),
        set_community_remove: statement.set_community_remove.clone(),
        set_as_path_prepend: config_prepend_to_api(statement.set_as_path_prepend.as_ref()),
    }
}

fn api_definition_to_config(definition: NamedPolicyDefinition) -> NamedPolicyConfig {
    NamedPolicyConfig {
        default_action: definition.default_action,
        statements: definition
            .statements
            .into_iter()
            .map(api_statement_to_config)
            .collect(),
    }
}

fn config_definition_to_api(definition: &NamedPolicyConfig) -> NamedPolicyDefinition {
    NamedPolicyDefinition {
        default_action: definition.default_action.clone(),
        statements: definition
            .statements
            .iter()
            .map(config_statement_to_api)
            .collect(),
    }
}

fn api_neighbor_set_to_config(definition: NeighborSetDefinition) -> NeighborSetConfig {
    NeighborSetConfig {
        addresses: definition.addresses,
        remote_asns: definition.remote_asns,
        peer_groups: definition.peer_groups,
    }
}

fn config_neighbor_set_to_api(definition: &NeighborSetConfig) -> NeighborSetDefinition {
    NeighborSetDefinition {
        addresses: definition.addresses.clone(),
        remote_asns: definition.remote_asns.clone(),
        peer_groups: definition.peer_groups.clone(),
    }
}

pub(crate) fn api_peer_group_to_config(definition: PeerGroupDefinition) -> PeerGroupConfig {
    PeerGroupConfig {
        hold_time: definition.hold_time,
        send_hold_time: definition.send_hold_time,
        // Slow-peer knobs are config-file knobs (LAN-470); the gRPC
        // peer-group surface does not carry them.
        slow_peer_threshold_pct: None,
        slow_peer_duration: None,
        slow_peer_isolation: None,
        max_prefixes: definition.max_prefixes,
        // Per-family limits are config-file knobs (ADR-0108); the gRPC
        // peer-group surface does not carry them.
        max_prefixes_ipv4: None,
        max_prefixes_ipv6: None,
        max_prefix_restart_seconds: definition
            .max_prefix_restart_seconds
            .and_then(std::num::NonZeroU32::new),
        md5_password: definition
            .md5_password
            .as_ref()
            .map(|secret| secret.as_ref().to_owned()),
        ttl_security: definition.ttl_security,
        bfd: None,
        families: definition.families,
        required_families: definition.required_families,
        graceful_restart: definition.graceful_restart,
        gr_restart_time: definition.gr_restart_time,
        gr_peer_restart_time_max: definition.gr_peer_restart_time_max,
        gr_stale_routes_time: definition.gr_stale_routes_time,
        llgr_stale_time: definition.llgr_stale_time,
        local_ipv6_nexthop: definition.local_ipv6_nexthop,
        route_reflector_client: definition.route_reflector_client,
        orr_vantage: definition.orr_vantage,
        route_server_client: definition.route_server_client,
        per_client_best: definition.per_client_best,
        // Not exposed on the peer-group gRPC definition: absent means
        // no ADR-0107 ownership enforcement; configure via TOML.
        next_hop_ownership: None,
        // Not exposed on the peer-group gRPC definition: absent means the
        // config-derived default (!route_server_client) applies at resolve.
        interpret_rfc1997: None,
        rs_control_communities: None,
        role: None,
        strict_role: None,
        prefix_orf_receive: None,
        disable_ipv4_unicast: None,
        remove_private_as: definition.remove_private_as,
        add_path: api_add_path_to_config(definition.add_path),
        import_policy: definition
            .import_policy
            .into_iter()
            .map(api_statement_to_config)
            .collect(),
        export_policy: definition
            .export_policy
            .into_iter()
            .map(api_statement_to_config)
            .collect(),
        import_policy_chain: definition.import_policy_chain,
        export_policy_chain: definition.export_policy_chain,
        log_level: None,
    }
}

pub(crate) fn config_peer_group_to_api(definition: &PeerGroupConfig) -> PeerGroupDefinition {
    PeerGroupDefinition {
        hold_time: definition.hold_time,
        send_hold_time: definition.send_hold_time,
        max_prefixes: definition.max_prefixes,
        max_prefix_restart_seconds: definition
            .max_prefix_restart_seconds
            .map(std::num::NonZeroU32::get),
        md5_password: definition.md5_password.as_deref().map(Into::into),
        ttl_security: definition.ttl_security,
        families: definition.families.clone(),
        required_families: definition.required_families.clone(),
        graceful_restart: definition.graceful_restart,
        gr_restart_time: definition.gr_restart_time,
        gr_peer_restart_time_max: definition.gr_peer_restart_time_max,
        gr_stale_routes_time: definition.gr_stale_routes_time,
        llgr_stale_time: definition.llgr_stale_time,
        local_ipv6_nexthop: definition.local_ipv6_nexthop.clone(),
        route_reflector_client: definition.route_reflector_client,
        orr_vantage: definition.orr_vantage,
        route_server_client: definition.route_server_client,
        per_client_best: definition.per_client_best,
        remove_private_as: definition.remove_private_as.clone(),
        add_path: config_add_path_to_api(definition.add_path.as_ref()),
        import_policy: definition
            .import_policy
            .iter()
            .map(config_statement_to_api)
            .collect(),
        export_policy: definition
            .export_policy
            .iter()
            .map(config_statement_to_api)
            .collect(),
        import_policy_chain: definition.import_policy_chain.clone(),
        export_policy_chain: definition.export_policy_chain.clone(),
    }
}

pub(crate) const NEIGHBOR_NOT_FOUND_REASON: &str = "neighbor not found";

fn neighbor_mut(config: &mut Config, address: IpAddr) -> Result<&mut Neighbor, ConfigError> {
    let addr = address.to_string();
    config
        .neighbors
        .iter_mut()
        .find(|neighbor| neighbor.address == addr)
        .ok_or_else(|| ConfigError::InvalidNeighborAddress {
            value: addr,
            reason: NEIGHBOR_NOT_FOUND_REASON.to_string(),
        })
}

/// Return all global/per-neighbor chain references to the named policy.
#[must_use]
pub fn policy_references(config: &Config, name: &str) -> Vec<String> {
    let mut refs = Vec::new();
    if config.policy.import_chain.iter().any(|entry| entry == name) {
        refs.push("global import_chain".to_string());
    }
    if config.policy.export_chain.iter().any(|entry| entry == name) {
        refs.push("global export_chain".to_string());
    }
    for neighbor in &config.neighbors {
        if neighbor
            .import_policy_chain
            .iter()
            .any(|entry| entry == name)
        {
            refs.push(format!("neighbor {} import_policy_chain", neighbor.address));
        }
        if neighbor
            .export_policy_chain
            .iter()
            .any(|entry| entry == name)
        {
            refs.push(format!("neighbor {} export_policy_chain", neighbor.address));
        }
    }
    refs
}

/// Return all policy statements that reference the named neighbor set.
#[must_use]
pub fn neighbor_set_references(config: &Config, name: &str) -> Vec<String> {
    let mut refs = Vec::new();

    for (policy_name, definition) in &config.policy.definitions {
        if definition
            .statements
            .iter()
            .any(|statement| statement.match_neighbor_set.as_deref() == Some(name))
        {
            refs.push(format!("policy definition {policy_name}"));
        }
    }

    for neighbor in &config.neighbors {
        if neighbor
            .import_policy
            .iter()
            .any(|statement| statement.match_neighbor_set.as_deref() == Some(name))
        {
            refs.push(format!("neighbor {} import_policy", neighbor.address));
        }
        if neighbor
            .export_policy
            .iter()
            .any(|statement| statement.match_neighbor_set.as_deref() == Some(name))
        {
            refs.push(format!("neighbor {} export_policy", neighbor.address));
        }
    }

    for (group_name, group) in &config.peer_groups {
        if group
            .import_policy
            .iter()
            .any(|statement| statement.match_neighbor_set.as_deref() == Some(name))
        {
            refs.push(format!("peer_group {group_name} import_policy"));
        }
        if group
            .export_policy
            .iter()
            .any(|statement| statement.match_neighbor_set.as_deref() == Some(name))
        {
            refs.push(format!("peer_group {group_name} export_policy"));
        }
    }

    refs
}

/// Return all references to the named peer group.
#[must_use]
pub fn peer_group_references(config: &Config, name: &str) -> Vec<String> {
    let mut refs = Vec::new();
    for neighbor in &config.neighbors {
        if neighbor.peer_group.as_deref() == Some(name) {
            refs.push(format!("neighbor {}", neighbor.address));
        }
    }
    for (set_name, set) in &config.policy.neighbor_sets {
        if set.peer_groups.iter().any(|group| group == name) {
            refs.push(format!("neighbor_set {set_name}"));
        }
    }
    for table in &config.fib_tables {
        if table.allowed_peer_groups.iter().any(|group| group == name) {
            refs.push(format!("fib_table {}", table.name));
        }
    }
    refs
}

pub(crate) fn fib_table_snapshot_to_config(snapshot: &FibTableSnapshot) -> FibTableConfig {
    FibTableConfig {
        name: snapshot.name.clone(),
        table_id: snapshot.table_id,
        metric: snapshot.metric,
        families: snapshot.families.clone(),
        allowed_peer_groups: snapshot.allowed_peer_groups.clone(),
        allowed_neighbors: snapshot.allowed_neighbors.clone(),
        max_routes: snapshot.max_routes,
        maximum_paths: snapshot.maximum_paths,
        maximum_paths_ebgp: snapshot.maximum_paths_ebgp,
        maximum_paths_ibgp: snapshot.maximum_paths_ibgp,
    }
}

/// Apply a config event to a config snapshot and validate the result.
#[expect(
    clippy::too_many_lines,
    reason = "config mutation application keeps all persisted policy/admin event mappings in one place"
)]
pub fn apply_config_event(config: &mut Config, event: &ConfigEvent) -> Result<(), ConfigError> {
    match event {
        ConfigEvent::NeighborAdded { config: cfg, .. } => {
            if !config.neighbors.iter().any(|neighbor| {
                neighbor.address == cfg.address.to_string() && neighbor.interface == cfg.interface
            }) {
                config.neighbors.push(Neighbor {
                    address: cfg.address.to_string(),
                    interface: cfg.interface.clone(),
                    remote_asn: cfg.remote_asn,
                    description: Some(cfg.description.clone()),
                    peer_group: cfg.peer_group.clone(),
                    hold_time: cfg.hold_time,
                    send_hold_time: cfg.send_hold_time,
                    // Not carried on the runtime neighbor-add surface:
                    // persist as unset so resolution re-applies the
                    // compiled-in detection defaults (LAN-470).
                    slow_peer_threshold_pct: None,
                    slow_peer_duration: None,
                    slow_peer_isolation: None,
                    max_prefixes: cfg.max_prefixes,
                    max_prefixes_ipv4: cfg.max_prefixes_ipv4,
                    max_prefixes_ipv6: cfg.max_prefixes_ipv6,
                    max_prefix_restart_seconds: cfg
                        .max_prefix_restart_seconds
                        .and_then(std::num::NonZeroU32::new),
                    md5_password: cfg
                        .md5_password
                        .as_ref()
                        .map(|secret| secret.as_ref().to_owned()),
                    tcp_ao: cfg.tcp_ao.as_ref().map(transport_tcp_ao_to_config),
                    bfd: None,
                    ttl_security: Some(cfg.ttl_security),
                    families: cfg
                        .families
                        .iter()
                        .map(|(afi, safi)| match (afi, safi) {
                            (rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::Unicast) => {
                                "ipv4_unicast".to_string()
                            }
                            (rustbgpd_wire::Afi::Ipv6, rustbgpd_wire::Safi::Unicast) => {
                                "ipv6_unicast".to_string()
                            }
                            (rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::FlowSpec) => {
                                "ipv4_flowspec".to_string()
                            }
                            (rustbgpd_wire::Afi::Ipv6, rustbgpd_wire::Safi::FlowSpec) => {
                                "ipv6_flowspec".to_string()
                            }
                            _ => format!("{afi:?}_{safi:?}"),
                        })
                        .collect(),
                    required_families: cfg
                        .required_families
                        .iter()
                        .map(|(afi, safi)| match (afi, safi) {
                            (rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::Unicast) => {
                                "ipv4_unicast".to_string()
                            }
                            (rustbgpd_wire::Afi::Ipv6, rustbgpd_wire::Safi::Unicast) => {
                                "ipv6_unicast".to_string()
                            }
                            _ => format!("{afi:?}_{safi:?}"),
                        })
                        .collect(),
                    graceful_restart: Some(cfg.graceful_restart),
                    gr_restart_time: Some(cfg.gr_restart_time),
                    gr_peer_restart_time_max: Some(cfg.gr_peer_restart_time_max),
                    gr_stale_routes_time: Some(cfg.gr_stale_routes_time),
                    llgr_stale_time: if cfg.llgr_stale_time > 0 {
                        Some(cfg.llgr_stale_time)
                    } else {
                        None
                    },
                    local_ipv6_nexthop: cfg.local_ipv6_nexthop.map(|addr| addr.to_string()),
                    route_reflector_client: Some(cfg.route_reflector_client),
                    orr_vantage: cfg.orr_vantage,
                    route_server_client: Some(cfg.route_server_client),
                    per_client_best: Some(cfg.per_client_best),
                    next_hop_ownership: cfg
                        .next_hop_ownership_strict_peer
                        .then_some(NextHopOwnershipConfig::StrictPeer),
                    interpret_rfc1997: None,
                    rs_control_communities: None,
                    role: cfg.local_role.and_then(wire_role_to_config),
                    strict_role: Some(cfg.strict_role),
                    prefix_orf_receive: Some(cfg.prefix_orf_receive),
                    disable_ipv4_unicast: Some(cfg.disable_ipv4_unicast),
                    remove_private_as: match cfg.remove_private_as {
                        rustbgpd_transport::RemovePrivateAs::Disabled => None,
                        rustbgpd_transport::RemovePrivateAs::Remove => Some("remove".to_string()),
                        rustbgpd_transport::RemovePrivateAs::All => Some("all".to_string()),
                        rustbgpd_transport::RemovePrivateAs::Replace => Some("replace".to_string()),
                    },
                    add_path: if cfg.add_path_receive || cfg.add_path_send {
                        Some(crate::config::AddPathConfig {
                            receive: cfg.add_path_receive,
                            send: cfg.add_path_send,
                            send_max: if cfg.add_path_send_max > 0 {
                                Some(cfg.add_path_send_max)
                            } else {
                                None
                            },
                            receive_max: if cfg.paths_limit_receive_max > 0 {
                                Some(cfg.paths_limit_receive_max)
                            } else {
                                None
                            },
                        })
                    } else {
                        None
                    },
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                    log_level: None,
                });
            }
        }
        ConfigEvent::NeighborDeleted { peer, .. } => {
            let addr = peer.address.to_string();
            config.neighbors.retain(|neighbor| {
                !(neighbor.address == addr && neighbor.interface == peer.interface)
            });
        }
        ConfigEvent::DynamicNeighborAdded {
            prefix,
            peer_group,
            remote_asn,
            description,
            ..
        } => {
            // Fail fast on an unparseable prefix rather than mutating the
            // snapshot and tripping `validate()` later — the config-event loop
            // does not roll back a partially-applied event. (The runtime add
            // path validates before emitting this, so this is defensive.)
            let Some(key) = crate::config::effective_prefix_str(prefix) else {
                return Err(ConfigError::InvalidDynamicNeighbor {
                    reason: format!("invalid dynamic neighbor prefix {prefix:?}"),
                });
            };
            let exists = config
                .dynamic_neighbors
                .iter()
                .any(|dn| crate::config::effective_prefix_str(&dn.prefix) == Some(key));
            if !exists {
                config
                    .dynamic_neighbors
                    .push(crate::config::DynamicNeighborConfig {
                        prefix: prefix.clone(),
                        peer_group: peer_group.clone(),
                        remote_asn: *remote_asn,
                        description: description.clone(),
                        tcp_ao: None,
                    });
            }
        }
        ConfigEvent::DynamicNeighborDeleted { prefix, .. } => {
            let Some(key) = crate::config::effective_prefix_str(prefix) else {
                return Err(ConfigError::InvalidDynamicNeighbor {
                    reason: format!("invalid dynamic neighbor prefix {prefix:?}"),
                });
            };
            config
                .dynamic_neighbors
                .retain(|dn| crate::config::effective_prefix_str(&dn.prefix) != Some(key));
        }
        ConfigEvent::SetPolicy {
            name, definition, ..
        } => {
            config
                .policy
                .definitions
                .insert(name.clone(), api_definition_to_config(definition.clone()));
        }
        ConfigEvent::DeletePolicy { name, .. } => {
            config.policy.definitions.remove(name);
        }
        ConfigEvent::SetNeighborSet {
            name, definition, ..
        } => {
            config
                .policy
                .neighbor_sets
                .insert(name.clone(), api_neighbor_set_to_config(definition.clone()));
        }
        ConfigEvent::DeleteNeighborSet { name, .. } => {
            config.policy.neighbor_sets.remove(name);
        }
        ConfigEvent::SetGlobalImportChain { policy_names, .. } => {
            config.policy.import_chain.clone_from(policy_names);
        }
        ConfigEvent::SetGlobalExportChain { policy_names, .. } => {
            config.policy.export_chain.clone_from(policy_names);
        }
        ConfigEvent::ClearGlobalImportChain { .. } => {
            config.policy.import_chain.clear();
        }
        ConfigEvent::ClearGlobalExportChain { .. } => {
            config.policy.export_chain.clear();
        }
        ConfigEvent::SetNeighborImportChain {
            address,
            policy_names,
            ..
        } => {
            let neighbor = neighbor_mut(config, *address)?;
            neighbor.import_policy_chain.clone_from(policy_names);
            neighbor.import_policy.clear();
        }
        ConfigEvent::SetNeighborExportChain {
            address,
            policy_names,
            ..
        } => {
            let neighbor = neighbor_mut(config, *address)?;
            neighbor.export_policy_chain.clone_from(policy_names);
            neighbor.export_policy.clear();
        }
        ConfigEvent::ClearNeighborImportChain { address, .. } => {
            neighbor_mut(config, *address)?.import_policy_chain.clear();
        }
        ConfigEvent::ClearNeighborExportChain { address, .. } => {
            neighbor_mut(config, *address)?.export_policy_chain.clear();
        }
        ConfigEvent::SetPeerGroup {
            name, definition, ..
        } => {
            config
                .peer_groups
                .insert(name.clone(), api_peer_group_to_config(definition.clone()));
        }
        ConfigEvent::DeletePeerGroup { name, .. } => {
            config.peer_groups.remove(name);
        }
        ConfigEvent::SetNeighborPeerGroup {
            address,
            peer_group,
            ..
        } => {
            neighbor_mut(config, *address)?.peer_group = Some(peer_group.clone());
        }
        ConfigEvent::ClearNeighborPeerGroup { address, .. } => {
            neighbor_mut(config, *address)?.peer_group = None;
        }
        ConfigEvent::FibTablesReplaced {
            tables: snapshots, ..
        } => {
            // The full accepted set the FIB reconciler acknowledged. The
            // trailing `config.validate()` re-checks it (`validate_fib_tables`)
            // before the caller commits the snapshot, so a malformed event
            // cannot poison the persisted config.
            config.fib_tables = snapshots.iter().map(fib_table_snapshot_to_config).collect();
        }
        ConfigEvent::ConfigTransactionCommitted { candidate_toml, .. } => {
            *config =
                Config::load_toml_with_diagnostics(candidate_toml, "committed config transaction")
                    .map_err(|reason| ConfigError::InvalidGrpcConfig { reason })?;
        }
    }
    config.validate()
}

/// Convert all named policy definitions from config schema to API payloads.
#[must_use]
pub fn named_policies_from_config(config: &Config) -> Vec<NamedPolicySnapshot> {
    let mut policies: Vec<_> = config
        .policy
        .definitions
        .iter()
        .map(|(name, definition)| NamedPolicySnapshot {
            name: name.clone(),
            definition: config_definition_to_api(definition),
        })
        .collect();
    policies.sort_by(|a, b| a.name.cmp(&b.name));
    policies
}

/// Convert a config named policy definition to the API payload.
pub fn named_policy_from_config(config: &Config, name: &str) -> Option<NamedPolicyDefinition> {
    config
        .policy
        .definitions
        .get(name)
        .map(config_definition_to_api)
}

/// Convert all named neighbor-set definitions from config schema to API payloads.
#[must_use]
pub fn named_neighbor_sets_from_config(config: &Config) -> Vec<NamedNeighborSetSnapshot> {
    let mut neighbor_sets: Vec<_> = config
        .policy
        .neighbor_sets
        .iter()
        .map(|(name, definition)| NamedNeighborSetSnapshot {
            name: name.clone(),
            definition: config_neighbor_set_to_api(definition),
        })
        .collect();
    neighbor_sets.sort_by(|a, b| a.name.cmp(&b.name));
    neighbor_sets
}

/// Convert one named neighbor set from config schema to API payload.
pub fn named_neighbor_set_from_config(
    config: &Config,
    name: &str,
) -> Option<NeighborSetDefinition> {
    config
        .policy
        .neighbor_sets
        .get(name)
        .map(config_neighbor_set_to_api)
}

/// Convert all peer-group definitions from config schema to API payloads.
#[must_use]
pub fn named_peer_groups_from_config(config: &Config) -> Vec<NamedPeerGroupSnapshot> {
    let mut peer_groups: Vec<_> = config
        .peer_groups
        .iter()
        .map(|(name, definition)| NamedPeerGroupSnapshot {
            name: name.clone(),
            definition: config_peer_group_to_api(definition),
        })
        .collect();
    peer_groups.sort_by(|a, b| a.name.cmp(&b.name));
    peer_groups
}

/// Convert one peer-group definition from config schema to API payload.
pub fn named_peer_group_from_config(config: &Config, name: &str) -> Option<PeerGroupDefinition> {
    config.peer_groups.get(name).map(config_peer_group_to_api)
}

/// Return the configured global named policy chains.
#[must_use]
pub fn global_policy_chains_from_config(config: &Config) -> PolicyChainAssignment {
    PolicyChainAssignment {
        import_policy_names: config.policy.import_chain.clone(),
        export_policy_names: config.policy.export_chain.clone(),
    }
}

/// Return a neighbor's configured peer-group membership. Outer `None` =
/// neighbor not configured; inner `None` = no membership.
#[must_use]
#[allow(clippy::option_option)] // the two None levels are distinct contract states
pub fn neighbor_peer_group_from_config(config: &Config, address: IpAddr) -> Option<Option<String>> {
    config
        .neighbors
        .iter()
        .find(|neighbor| neighbor.address == address.to_string())
        .map(|neighbor| neighbor.peer_group.clone())
}

/// Return the configured per-neighbor named policy chains.
pub fn neighbor_policy_chains_from_config(
    config: &Config,
    address: IpAddr,
) -> Option<PolicyChainAssignment> {
    let neighbor = config
        .neighbors
        .iter()
        .find(|neighbor| neighbor.address == address.to_string())?;
    Some(PolicyChainAssignment {
        import_policy_names: neighbor.import_policy_chain.clone(),
        export_policy_names: neighbor.export_policy_chain.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> Config {
        // Bypasses `Config::load_*_with_diagnostics` so the
        // test-only legacy-grpc auto-inject doesn't fire; declare
        // the legacy posture explicitly so post-mutation
        // validation in `apply_config_event` accepts the config.
        let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

[security.grpc]
enforcement = "legacy"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn set_policy_event_round_trips_named_definition() {
        let mut config = minimal_config();
        apply_config_event(
            &mut config,
            &ConfigEvent::SetPolicy {
                name: "tag-internal".to_string(),
                definition: NamedPolicyDefinition {
                    default_action: "permit".to_string(),
                    statements: vec![PolicyStatementDefinition {
                        action: "permit".to_string(),
                        prefix: Some("10.0.0.0/8".to_string()),
                        ge: None,
                        le: Some(16),
                        match_community: Vec::new(),
                        match_as_path: None,
                        match_neighbor_set: None,
                        match_route_type: None,
                        match_evpn_route_type: None,
                        match_as_path_length_ge: None,
                        match_as_path_length_le: None,
                        match_local_pref_ge: None,
                        match_local_pref_le: None,
                        match_med_ge: None,
                        match_med_le: None,
                        match_next_hop: None,
                        match_rpki_validation: None,
                        match_aspa_validation: None,
                        set_local_pref: Some(200),
                        set_med: None,
                        set_next_hop: None,
                        set_community_add: vec!["65001:100".to_string()],
                        set_community_remove: Vec::new(),
                        set_as_path_prepend: None,
                    }],
                },
                ack: None,
            },
        )
        .unwrap();

        let snapshot = named_policy_from_config(&config, "tag-internal").unwrap();
        assert_eq!(snapshot.default_action, "permit");
        assert_eq!(snapshot.statements.len(), 1);
        assert_eq!(snapshot.statements[0].set_community_add, vec!["65001:100"]);
    }

    #[test]
    fn policy_references_find_global_and_neighbor_chains() {
        let mut config = minimal_config();
        config.policy.import_chain = vec!["shared".to_string()];
        config.neighbors[0].export_policy_chain = vec!["shared".to_string()];

        let refs = policy_references(&config, "shared");
        assert!(refs.contains(&"global import_chain".to_string()));
        assert!(refs.contains(&"neighbor 10.0.0.2 export_policy_chain".to_string()));
    }

    #[test]
    fn peer_group_references_include_fib_table_allow_lists() {
        let mut config = minimal_config();
        config.fib_tables.push(FibTableConfig {
            name: "edge".to_string(),
            table_id: 1000,
            metric: 200,
            families: vec!["ipv4_unicast".to_string(), "ipv6_unicast".to_string()],
            allowed_peer_groups: vec!["fabric".to_string()],
            allowed_neighbors: Vec::new(),
            max_routes: None,
            maximum_paths: None,
            maximum_paths_ebgp: None,
            maximum_paths_ibgp: None,
        });

        let refs = peer_group_references(&config, "fabric");
        assert_eq!(refs, vec!["fib_table edge"]);
    }

    #[test]
    fn neighbor_added_event_preserves_tcp_ao_key_material() {
        let mut config = minimal_config();

        apply_config_event(
            &mut config,
            &ConfigEvent::NeighborAdded {
                config: rustbgpd_api::peer_types::PeerManagerNeighborConfig {
                    address: "10.0.0.3".parse().unwrap(),
                    interface: None,
                    scope_id: None,
                    remote_asn: 65003,
                    description: "protected".to_string(),
                    peer_group: None,
                    hold_time: None,
                    send_hold_time: None,
                    max_prefixes: None,
                    max_prefixes_ipv4: None,
                    max_prefixes_ipv6: None,
                    max_prefix_restart_seconds: None,
                    md5_password: None,
                    tcp_ao: Some(
                        rustbgpd_transport::TcpAoConfig {
                            key: "ao-secret".into(),
                            send_id: 7,
                            recv_id: 9,
                            algorithm: rustbgpd_transport::TcpAoAlgorithm::HmacSha256,
                            preferred: true,
                            deprecated: false,
                        }
                        .into(),
                    ),
                    ttl_security: false,
                    families: vec![(rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::Unicast)],
                    required_families: Vec::new(),
                    graceful_restart: true,
                    gr_restart_time: 120,
                    gr_peer_restart_time_max: 4095,
                    gr_stale_routes_time: 360,
                    llgr_stale_time: 0,
                    gr_restart_eligible: false,
                    local_ipv6_nexthop: None,
                    route_reflector_client: false,
                    orr_vantage: None,
                    route_server_client: false,
                    per_client_best: false,
                    next_hop_ownership_strict_peer: false,
                    slow_peer_threshold_pct: rustbgpd_transport::DEFAULT_SLOW_PEER_THRESHOLD_PCT,
                    slow_peer_duration: rustbgpd_transport::DEFAULT_SLOW_PEER_DURATION_SECS,
                    slow_peer_isolation: false,
                    interpret_rfc1997: true,
                    rs_control_communities: false,
                    remove_private_as: rustbgpd_transport::RemovePrivateAs::Disabled,
                    add_path_receive: false,
                    add_path_send: false,
                    add_path_send_max: 0,
                    paths_limit_receive_max: 0,
                    local_role: None,
                    strict_role: false,
                    prefix_orf_receive: false,
                    disable_ipv4_unicast: false,
                    import_policy: None,
                    export_policy: None,
                },
                ack: None,
            },
        )
        .unwrap();

        let neighbor = config
            .neighbors
            .iter()
            .find(|neighbor| neighbor.address == "10.0.0.3")
            .unwrap();
        let tcp_ao = neighbor.tcp_ao.as_ref().expect("tcp_ao preserved");
        let tcp_ao = &tcp_ao.0[0];
        assert_eq!(tcp_ao.key, "ao-secret");
        assert_eq!(tcp_ao.send_id, 7);
        assert_eq!(tcp_ao.recv_id, 9);
        assert_eq!(tcp_ao.algorithm, "hmac(sha256)");
        assert!(tcp_ao.preferred);
        assert!(!tcp_ao.deprecated);
    }
}
