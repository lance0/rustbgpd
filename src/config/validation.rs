use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use super::parse::{
    parse_families, parse_named_policy, parse_neighbor_set, parse_policy,
    reject_validation_state_matches_in_import_chain,
    reject_validation_state_matches_in_import_policy, resolve_chain,
};
use super::{Config, ConfigError, DEFAULT_HOLD_TIME, PeerGroupConfig};

impl Config {
    #[expect(clippy::too_many_lines)]
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        // Validate router_id is a valid IPv4
        self.global
            .router_id
            .parse::<Ipv4Addr>()
            .map_err(|e| ConfigError::InvalidRouterId {
                value: self.global.router_id.clone(),
                reason: e.to_string(),
            })?;

        // Validate cluster_id if present
        if let Some(ref cid) = self.global.cluster_id {
            cid.parse::<Ipv4Addr>()
                .map_err(|e| ConfigError::InvalidRrConfig {
                    reason: format!("invalid cluster_id {cid:?}: {e}"),
                })?;
        }

        if self.global.runtime_state_dir.trim().is_empty() {
            return Err(ConfigError::InvalidRuntimeStateDir {
                value: self.global.runtime_state_dir.clone(),
                reason: "must not be empty".to_string(),
            });
        }

        // Validate prometheus_addr is a valid SocketAddr (if configured)
        if let Some(ref addr) = self.global.telemetry.prometheus_addr {
            addr.parse::<SocketAddr>()
                .map_err(|e| ConfigError::InvalidPrometheusAddr {
                    value: addr.clone(),
                    reason: e.to_string(),
                })?;
        }

        let telemetry = &self.global.telemetry;
        let tcp = telemetry.grpc_tcp.as_ref().filter(|cfg| cfg.enabled);
        let uds = telemetry.grpc_uds.as_ref().filter(|cfg| cfg.enabled);

        if let Some(cfg) = tcp {
            let addr = cfg
                .address
                .as_ref()
                .ok_or_else(|| ConfigError::InvalidGrpcConfig {
                    reason: "grpc_tcp.address is required when grpc_tcp is enabled".to_string(),
                })?;
            addr.parse::<SocketAddr>()
                .map_err(|e| ConfigError::InvalidGrpcConfig {
                    reason: format!("invalid grpc_tcp.address {addr:?}: {e}"),
                })?;
            validate_grpc_token_file(cfg.token_file.as_deref(), "grpc_tcp.token_file")?;
        }

        if let Some(cfg) = uds {
            if let Some(path) = cfg.path.as_deref().map(Path::new)
                && !path.is_absolute()
            {
                return Err(ConfigError::InvalidGrpcConfig {
                    reason: format!("grpc_uds.path {:?} must be absolute", path.display()),
                });
            }
            if cfg.mode > 0o777 {
                return Err(ConfigError::InvalidGrpcConfig {
                    reason: format!("grpc_uds.mode {:o} exceeds 0o777", cfg.mode),
                });
            }
            validate_grpc_token_file(cfg.token_file.as_deref(), "grpc_uds.token_file")?;
        }

        if (telemetry.grpc_tcp.is_some() || telemetry.grpc_uds.is_some())
            && tcp.is_none()
            && uds.is_none()
        {
            return Err(ConfigError::InvalidGrpcConfig {
                reason: "at least one gRPC listener must be enabled".to_string(),
            });
        }

        // Validate MRT config if present
        if let Some(ref mrt) = self.mrt {
            if mrt.output_dir.trim().is_empty() {
                return Err(ConfigError::InvalidMrtConfig {
                    reason: "output_dir must not be empty".to_string(),
                });
            }
            if mrt.dump_interval == 0 {
                return Err(ConfigError::InvalidMrtConfig {
                    reason: "dump_interval must be > 0".to_string(),
                });
            }
        }

        // Eagerly validate all policies at load time
        let global_import = parse_policy(
            &self.policy.import,
            &self.policy.neighbor_sets,
            &self.peer_groups,
        )?;
        reject_validation_state_matches_in_import_policy(
            global_import.as_ref(),
            "global import policy",
        )?;
        parse_policy(
            &self.policy.export,
            &self.policy.neighbor_sets,
            &self.peer_groups,
        )?;

        for (name, set) in &self.policy.neighbor_sets {
            parse_neighbor_set(name, set, &self.peer_groups)?;
        }

        for (name, group) in &self.peer_groups {
            validate_peer_group(
                name,
                group,
                &self.policy.definitions,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?;
        }

        // Validate named policy definitions
        for (name, cfg) in &self.policy.definitions {
            parse_named_policy(name, cfg, &self.policy.neighbor_sets, &self.peer_groups)?;
        }

        // Validate global chains
        let global_import_chain = resolve_chain(
            &self.policy.import_chain,
            &self.policy.definitions,
            &self.policy.neighbor_sets,
            &self.peer_groups,
        )?;
        reject_validation_state_matches_in_import_chain(
            global_import_chain.as_ref(),
            "global import_policy_chain",
        )?;
        resolve_chain(
            &self.policy.export_chain,
            &self.policy.definitions,
            &self.policy.neighbor_sets,
            &self.peer_groups,
        )?;

        // Validate neighbor address uniqueness
        {
            let mut seen = std::collections::HashSet::new();
            for neighbor in &self.neighbors {
                let addr = neighbor.address.parse::<IpAddr>().map_err(|e| {
                    ConfigError::InvalidNeighborAddress {
                        value: neighbor.address.clone(),
                        reason: e.to_string(),
                    }
                })?;
                if !seen.insert(addr) {
                    return Err(ConfigError::InvalidNeighborAddress {
                        value: neighbor.address.clone(),
                        reason: "duplicate neighbor address".to_string(),
                    });
                }
            }
        }

        for neighbor in &self.neighbors {
            let group = neighbor
                .peer_group
                .as_deref()
                .map(|name| {
                    self.peer_groups
                        .get(name)
                        .ok_or_else(|| ConfigError::UndefinedPeerGroup {
                            name: name.to_string(),
                        })
                })
                .transpose()?;

            let hold_time = neighbor
                .hold_time
                .or_else(|| group.and_then(|g| g.hold_time))
                .unwrap_or(DEFAULT_HOLD_TIME);
            if hold_time != 0 && hold_time < 3 {
                return Err(ConfigError::InvalidHoldTime { value: hold_time });
            }

            // Validate route_reflector_client: must be iBGP
            let route_reflector_client = neighbor
                .route_reflector_client
                .or_else(|| group.and_then(|g| g.route_reflector_client))
                .unwrap_or(false);
            if route_reflector_client && neighbor.remote_asn != self.global.asn {
                return Err(ConfigError::InvalidRrConfig {
                    reason: format!(
                        "route_reflector_client requires iBGP (remote_asn {} != local asn {})",
                        neighbor.remote_asn, self.global.asn
                    ),
                });
            }

            let route_server_client = neighbor
                .route_server_client
                .or_else(|| group.and_then(|g| g.route_server_client))
                .unwrap_or(false);
            if route_server_client && neighbor.remote_asn == self.global.asn {
                return Err(ConfigError::InvalidRouteServerConfig {
                    reason: format!(
                        "route_server_client requires eBGP (remote_asn {} == local asn {})",
                        neighbor.remote_asn, self.global.asn
                    ),
                });
            }

            if let Some(mode) = neighbor
                .remove_private_as
                .as_deref()
                .or_else(|| group.and_then(|g| g.remove_private_as.as_deref()))
            {
                match mode {
                    "remove" | "all" | "replace" => {}
                    other => {
                        return Err(ConfigError::InvalidRemovePrivateAs {
                            reason: format!(
                                "unknown mode {other:?}, expected \"remove\", \"all\", or \"replace\""
                            ),
                        });
                    }
                }
                if neighbor.remote_asn == self.global.asn {
                    return Err(ConfigError::InvalidRemovePrivateAs {
                        reason: format!(
                            "remove_private_as requires eBGP (remote_asn {} == local asn {})",
                            neighbor.remote_asn, self.global.asn
                        ),
                    });
                }
            }

            // Validate families if explicitly configured
            if !neighbor.families.is_empty() {
                parse_families(&neighbor.families)?;
            } else if let Some(group) = group
                && !group.families.is_empty()
            {
                parse_families(&group.families)?;
            }

            // Validate log_level
            validate_log_level(
                neighbor
                    .log_level
                    .as_deref()
                    .or_else(|| group.and_then(|g| g.log_level.as_deref())),
            )?;

            // Validate GR config
            let gr_enabled = neighbor
                .graceful_restart
                .or_else(|| group.and_then(|g| g.graceful_restart))
                .unwrap_or(true);
            if let Some(t) = neighbor
                .gr_restart_time
                .or_else(|| group.and_then(|g| g.gr_restart_time))
                && t > 4095
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: format!("gr_restart_time {t} exceeds 4095 (12-bit max)"),
                });
            }
            if let Some(0) = neighbor
                .gr_restart_time
                .or_else(|| group.and_then(|g| g.gr_restart_time))
                && gr_enabled
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: "gr_restart_time must be > 0 when graceful_restart is enabled"
                        .to_string(),
                });
            }
            if let Some(t) = neighbor
                .gr_stale_routes_time
                .or_else(|| group.and_then(|g| g.gr_stale_routes_time))
                && t == 0
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: "gr_stale_routes_time must be > 0".to_string(),
                });
            }
            if let Some(t) = neighbor
                .gr_stale_routes_time
                .or_else(|| group.and_then(|g| g.gr_stale_routes_time))
                && t > 3600
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: format!("gr_stale_routes_time {t} exceeds 3600 (1 hour max)"),
                });
            }
            if let Some(t) = neighbor
                .llgr_stale_time
                .or_else(|| group.and_then(|g| g.llgr_stale_time))
                && t > 16_777_215
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: format!("llgr_stale_time {t} exceeds 16777215 (24-bit max)"),
                });
            }

            // Validate local_ipv6_nexthop if configured
            if let Some(nh) = neighbor
                .local_ipv6_nexthop
                .as_ref()
                .or_else(|| group.and_then(|g| g.local_ipv6_nexthop.as_ref()))
            {
                let addr =
                    nh.parse::<Ipv6Addr>()
                        .map_err(|e| ConfigError::InvalidLocalIpv6Nexthop {
                            value: nh.clone(),
                            reason: e.to_string(),
                        })?;
                if !rustbgpd_wire::is_valid_ipv6_nexthop(&addr) {
                    return Err(ConfigError::InvalidLocalIpv6Nexthop {
                        value: nh.clone(),
                        reason: "address is not a valid IPv6 next-hop (loopback, link-local, multicast, or unspecified)".to_string(),
                    });
                }
            }

            let neighbor_import = parse_policy(
                &neighbor.import_policy,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?;
            reject_validation_state_matches_in_import_policy(
                neighbor_import.as_ref(),
                &format!("neighbor {} import_policy", neighbor.address),
            )?;
            parse_policy(
                &neighbor.export_policy,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?;

            // Inline and chain are mutually exclusive
            if !neighbor.import_policy.is_empty() && !neighbor.import_policy_chain.is_empty() {
                return Err(ConfigError::InvalidPolicyEntry {
                    reason: format!(
                        "neighbor {}: import_policy and import_policy_chain are mutually exclusive",
                        neighbor.address
                    ),
                });
            }
            if !neighbor.export_policy.is_empty() && !neighbor.export_policy_chain.is_empty() {
                return Err(ConfigError::InvalidPolicyEntry {
                    reason: format!(
                        "neighbor {}: export_policy and export_policy_chain are mutually exclusive",
                        neighbor.address
                    ),
                });
            }
            let neighbor_import_chain = resolve_chain(
                &neighbor.import_policy_chain,
                &self.policy.definitions,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?;
            reject_validation_state_matches_in_import_chain(
                neighbor_import_chain.as_ref(),
                &format!("neighbor {} import_policy_chain", neighbor.address),
            )?;
            resolve_chain(
                &neighbor.export_policy_chain,
                &self.policy.definitions,
                &self.policy.neighbor_sets,
                &self.peer_groups,
            )?;
        }

        // Validate RPKI cache server config
        if let Some(ref rpki) = self.rpki {
            for (i, server) in rpki.cache_servers.iter().enumerate() {
                if server.refresh_interval == 0 {
                    return Err(ConfigError::InvalidRpkiConfig {
                        reason: format!("cache_server[{i}]: refresh_interval must be > 0"),
                    });
                }
                if server.retry_interval == 0 {
                    return Err(ConfigError::InvalidRpkiConfig {
                        reason: format!("cache_server[{i}]: retry_interval must be > 0"),
                    });
                }
                if server.expire_interval == 0 {
                    return Err(ConfigError::InvalidRpkiConfig {
                        reason: format!("cache_server[{i}]: expire_interval must be > 0"),
                    });
                }
                if server.expire_interval < server.refresh_interval {
                    return Err(ConfigError::InvalidRpkiConfig {
                        reason: format!(
                            "cache_server[{i}]: expire_interval ({}) must be >= refresh_interval ({})",
                            server.expire_interval, server.refresh_interval
                        ),
                    });
                }
            }
        }

        // Validate BMP collector addresses
        if let Some(ref bmp) = self.bmp {
            for (i, collector) in bmp.collectors.iter().enumerate() {
                collector.address.parse::<SocketAddr>().map_err(|e| {
                    ConfigError::InvalidBmpCollector {
                        reason: format!(
                            "collectors[{i}]: invalid address {:?}: {e}",
                            collector.address
                        ),
                    }
                })?;
                if collector.reconnect_interval == 0 {
                    return Err(ConfigError::InvalidBmpCollector {
                        reason: format!("collectors[{i}]: reconnect_interval must be > 0"),
                    });
                }
            }
        }

        Ok(())
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "peer-group validation mirrors the full inheritable neighbor surface"
)]
fn validate_peer_group(
    name: &str,
    group: &PeerGroupConfig,
    definitions: &std::collections::HashMap<String, super::NamedPolicyConfig>,
    neighbor_sets: &std::collections::HashMap<String, super::NeighborSetConfig>,
    peer_groups: &std::collections::HashMap<String, PeerGroupConfig>,
) -> Result<(), ConfigError> {
    let hold_time = group.hold_time.unwrap_or(DEFAULT_HOLD_TIME);
    if hold_time != 0 && hold_time < 3 {
        return Err(ConfigError::InvalidHoldTime { value: hold_time });
    }

    if !group.families.is_empty() {
        parse_families(&group.families)?;
    }

    if let Some(mode) = group.remove_private_as.as_deref() {
        match mode {
            "remove" | "all" | "replace" => {}
            other => {
                return Err(ConfigError::InvalidRemovePrivateAs {
                    reason: format!(
                        "peer_group {name:?}: unknown mode {other:?}, expected \"remove\", \"all\", or \"replace\""
                    ),
                });
            }
        }
    }

    validate_log_level(group.log_level.as_deref())?;

    let gr_enabled = group.graceful_restart.unwrap_or(true);
    if let Some(t) = group.gr_restart_time
        && t > 4095
    {
        return Err(ConfigError::InvalidGrConfig {
            reason: format!("peer_group {name:?}: gr_restart_time {t} exceeds 4095 (12-bit max)"),
        });
    }
    if let Some(0) = group.gr_restart_time
        && gr_enabled
    {
        return Err(ConfigError::InvalidGrConfig {
            reason: format!(
                "peer_group {name:?}: gr_restart_time must be > 0 when graceful_restart is enabled"
            ),
        });
    }
    if let Some(t) = group.gr_stale_routes_time
        && t == 0
    {
        return Err(ConfigError::InvalidGrConfig {
            reason: format!("peer_group {name:?}: gr_stale_routes_time must be > 0"),
        });
    }
    if let Some(t) = group.gr_stale_routes_time
        && t > 3600
    {
        return Err(ConfigError::InvalidGrConfig {
            reason: format!(
                "peer_group {name:?}: gr_stale_routes_time {t} exceeds 3600 (1 hour max)"
            ),
        });
    }
    if let Some(t) = group.llgr_stale_time
        && t > 16_777_215
    {
        return Err(ConfigError::InvalidGrConfig {
            reason: format!(
                "peer_group {name:?}: llgr_stale_time {t} exceeds 16777215 (24-bit max)"
            ),
        });
    }

    if let Some(nh) = group.local_ipv6_nexthop.as_deref() {
        let addr = nh
            .parse::<Ipv6Addr>()
            .map_err(|e| ConfigError::InvalidLocalIpv6Nexthop {
                value: nh.to_string(),
                reason: e.to_string(),
            })?;
        if !rustbgpd_wire::is_valid_ipv6_nexthop(&addr) {
            return Err(ConfigError::InvalidLocalIpv6Nexthop {
                value: nh.to_string(),
                reason:
                    "address is not a valid IPv6 next-hop (loopback, link-local, multicast, or unspecified)"
                        .to_string(),
            });
        }
    }

    let group_import = parse_policy(&group.import_policy, neighbor_sets, peer_groups)?;
    reject_validation_state_matches_in_import_policy(
        group_import.as_ref(),
        &format!("peer_group {name:?} import_policy"),
    )?;
    parse_policy(&group.export_policy, neighbor_sets, peer_groups)?;

    if !group.import_policy.is_empty() && !group.import_policy_chain.is_empty() {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: format!(
                "peer_group {name:?}: import_policy and import_policy_chain are mutually exclusive"
            ),
        });
    }
    if !group.export_policy.is_empty() && !group.export_policy_chain.is_empty() {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: format!(
                "peer_group {name:?}: export_policy and export_policy_chain are mutually exclusive"
            ),
        });
    }
    let group_import_chain = resolve_chain(
        &group.import_policy_chain,
        definitions,
        neighbor_sets,
        peer_groups,
    )?;
    reject_validation_state_matches_in_import_chain(
        group_import_chain.as_ref(),
        &format!("peer_group {name:?} import_policy_chain"),
    )?;
    resolve_chain(
        &group.export_policy_chain,
        definitions,
        neighbor_sets,
        peer_groups,
    )?;

    Ok(())
}

fn validate_log_level(level: Option<&str>) -> Result<(), ConfigError> {
    if let Some(level) = level {
        match level {
            "error" | "warn" | "info" | "debug" | "trace" => {}
            _ => {
                return Err(ConfigError::InvalidLogLevel {
                    value: level.to_string(),
                });
            }
        }
    }
    Ok(())
}

fn validate_grpc_token_file(path: Option<&str>, field_name: &str) -> Result<(), ConfigError> {
    let Some(path) = path else {
        return Ok(());
    };
    if path.trim().is_empty() {
        return Err(ConfigError::InvalidGrpcConfig {
            reason: format!("{field_name} must not be empty"),
        });
    }
    let token = std::fs::read_to_string(path).map_err(|e| ConfigError::InvalidGrpcConfig {
        reason: format!("failed to read {field_name} {path:?}: {e}"),
    })?;
    if token.trim_end().is_empty() {
        return Err(ConfigError::InvalidGrpcConfig {
            reason: format!("{field_name} {path:?} must contain a non-empty token"),
        });
    }
    Ok(())
}
