//! Helpers for policy CRUD config mutations and conversions.

use std::net::IpAddr;

use rustbgpd_api::peer_types::{
    ConfigEvent, NamedPolicyDefinition, NamedPolicySnapshot, PolicyAsPathPrependConfig,
    PolicyChainAssignment, PolicyStatementDefinition,
};

use crate::config::{
    AsPathPrependConfig, Config, ConfigError, NamedPolicyConfig, Neighbor, PolicyStatementConfig,
};

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

fn api_statement_to_config(statement: PolicyStatementDefinition) -> PolicyStatementConfig {
    PolicyStatementConfig {
        action: statement.action,
        prefix: statement.prefix,
        ge: statement.ge,
        le: statement.le,
        match_community: statement.match_community,
        match_as_path: statement.match_as_path,
        match_as_path_length_ge: statement.match_as_path_length_ge,
        match_as_path_length_le: statement.match_as_path_length_le,
        match_rpki_validation: statement.match_rpki_validation,
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
        match_as_path_length_ge: statement.match_as_path_length_ge,
        match_as_path_length_le: statement.match_as_path_length_le,
        match_rpki_validation: statement.match_rpki_validation.clone(),
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

fn neighbor_mut(config: &mut Config, address: IpAddr) -> Result<&mut Neighbor, ConfigError> {
    let addr = address.to_string();
    config
        .neighbors
        .iter_mut()
        .find(|neighbor| neighbor.address == addr)
        .ok_or_else(|| ConfigError::InvalidNeighborAddress {
            value: addr,
            reason: "neighbor not found".to_string(),
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

/// Apply a config event to a config snapshot and validate the result.
#[expect(
    clippy::too_many_lines,
    reason = "config mutation application keeps all persisted policy/admin event mappings in one place"
)]
pub fn apply_config_event(config: &mut Config, event: &ConfigEvent) -> Result<(), ConfigError> {
    match event {
        ConfigEvent::NeighborAdded(cfg) => {
            if !config
                .neighbors
                .iter()
                .any(|neighbor| neighbor.address == cfg.address.to_string())
            {
                config.neighbors.push(Neighbor {
                    address: cfg.address.to_string(),
                    remote_asn: cfg.remote_asn,
                    description: Some(cfg.description.clone()),
                    hold_time: cfg.hold_time,
                    max_prefixes: cfg.max_prefixes,
                    md5_password: None,
                    ttl_security: false,
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
                    graceful_restart: Some(cfg.graceful_restart),
                    gr_restart_time: Some(cfg.gr_restart_time),
                    gr_stale_routes_time: Some(cfg.gr_stale_routes_time),
                    llgr_stale_time: if cfg.llgr_stale_time > 0 {
                        Some(cfg.llgr_stale_time)
                    } else {
                        None
                    },
                    local_ipv6_nexthop: cfg.local_ipv6_nexthop.map(|addr| addr.to_string()),
                    route_reflector_client: cfg.route_reflector_client,
                    route_server_client: cfg.route_server_client,
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
                        })
                    } else {
                        None
                    },
                    import_policy: Vec::new(),
                    export_policy: Vec::new(),
                    import_policy_chain: Vec::new(),
                    export_policy_chain: Vec::new(),
                });
            }
        }
        ConfigEvent::NeighborDeleted(address) => {
            let addr = address.to_string();
            config.neighbors.retain(|neighbor| neighbor.address != addr);
        }
        ConfigEvent::SetPolicy { name, definition } => {
            config
                .policy
                .definitions
                .insert(name.clone(), api_definition_to_config(definition.clone()));
        }
        ConfigEvent::DeletePolicy { name } => {
            config.policy.definitions.remove(name);
        }
        ConfigEvent::SetGlobalImportChain { policy_names } => {
            config.policy.import_chain.clone_from(policy_names);
            config.policy.import.clear();
        }
        ConfigEvent::SetGlobalExportChain { policy_names } => {
            config.policy.export_chain.clone_from(policy_names);
            config.policy.export.clear();
        }
        ConfigEvent::ClearGlobalImportChain => {
            config.policy.import_chain.clear();
        }
        ConfigEvent::ClearGlobalExportChain => {
            config.policy.export_chain.clear();
        }
        ConfigEvent::SetNeighborImportChain {
            address,
            policy_names,
        } => {
            let neighbor = neighbor_mut(config, *address)?;
            neighbor.import_policy_chain.clone_from(policy_names);
            neighbor.import_policy.clear();
        }
        ConfigEvent::SetNeighborExportChain {
            address,
            policy_names,
        } => {
            let neighbor = neighbor_mut(config, *address)?;
            neighbor.export_policy_chain.clone_from(policy_names);
            neighbor.export_policy.clear();
        }
        ConfigEvent::ClearNeighborImportChain { address } => {
            neighbor_mut(config, *address)?.import_policy_chain.clear();
        }
        ConfigEvent::ClearNeighborExportChain { address } => {
            neighbor_mut(config, *address)?.export_policy_chain.clear();
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

/// Return the configured global named policy chains.
#[must_use]
pub fn global_policy_chains_from_config(config: &Config) -> PolicyChainAssignment {
    PolicyChainAssignment {
        import_policy_names: config.policy.import_chain.clone(),
        export_policy_names: config.policy.export_chain.clone(),
    }
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
        let toml = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "json"

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
                        match_as_path_length_ge: None,
                        match_as_path_length_le: None,
                        match_rpki_validation: None,
                        set_local_pref: Some(200),
                        set_med: None,
                        set_next_hop: None,
                        set_community_add: vec!["65001:100".to_string()],
                        set_community_remove: Vec::new(),
                        set_as_path_prepend: None,
                    }],
                },
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
}
