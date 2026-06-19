use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use super::parse::{
    parse_families, parse_named_policy, parse_neighbor_set, parse_policy, resolve_chain,
};
use super::schema::{
    ManagedBridgeNetdevConfig, ManagedL3VxlanNetdevConfig, ManagedNetdevsConfig,
    ManagedVrfNetdevConfig, ManagedVxlanNetdevConfig,
};
use super::{
    Config, ConfigError, DEFAULT_HOLD_TIME, EventHistoryConfig, GrpcEnforcementConfig,
    PeerGroupConfig, SecurityConfig, TcpAoConfig, is_unicast_nonzero_mac, parse_mac_address,
};

/// Canonical key for a dynamic-neighbor prefix: the network address with all
/// host bits masked off, paired with the prefix length. Two ranges with the
/// same key cover the identical address set (e.g. `10.0.0.5/24` and
/// `10.0.0.9/24` both normalize to `10.0.0.0/24`). Shared by config-load
/// validation and the runtime `AddDynamicNeighbor` path so both reject the
/// same duplicates and match deletes consistently. Callers must pass a
/// length already bounds-checked (`<= 32` for v4, `<= 128` for v6).
pub(crate) fn effective_prefix(addr: IpAddr, prefix_len: u8) -> (IpAddr, u8) {
    let masked = match addr {
        IpAddr::V4(v4) => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & mask))
        }
        IpAddr::V6(v6) => {
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
        }
    };
    (masked, prefix_len)
}

/// Parse an `addr/len` prefix and return its effective key (masked network +
/// length), or `None` if it doesn't parse or is out of bounds. Convenience
/// over [`effective_prefix`] for callers that hold the textual form (config
/// persistence apply, runtime delete matching).
pub(crate) fn effective_prefix_str(prefix: &str) -> Option<(IpAddr, u8)> {
    let (addr_s, len_s) = prefix.split_once('/')?;
    let addr: IpAddr = addr_s.parse().ok()?;
    let len: u8 = len_s.parse().ok()?;
    match addr {
        IpAddr::V4(_) if len > 32 => return None,
        IpAddr::V6(_) if len > 128 => return None,
        _ => {}
    }
    Some(effective_prefix(addr, len))
}

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

        validate_event_history(&self.event_history)?;
        validate_grpc_security(&self.security)?;

        // Validate prometheus_addr is a valid SocketAddr (if configured)
        if let Some(ref addr) = self.global.telemetry.prometheus_addr {
            addr.parse::<SocketAddr>()
                .map_err(|e| ConfigError::InvalidPrometheusAddr {
                    value: addr.clone(),
                    reason: e.to_string(),
                })?;
        }

        // Validate looking_glass addr if configured
        if let Some(ref lg) = self.global.telemetry.looking_glass {
            lg.addr
                .parse::<SocketAddr>()
                .map_err(|e| ConfigError::InvalidGrpcConfig {
                    reason: format!("invalid looking_glass.addr {:?}: {e}", lg.addr),
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
            // mTLS: all three of cert / key / client_ca must be set
            // together, or none. Partial config rejected.
            let tls_set = [
                cfg.tls_cert_file.as_deref().is_some(),
                cfg.tls_key_file.as_deref().is_some(),
                cfg.tls_client_ca_file.as_deref().is_some(),
            ];
            let tls_count = tls_set.iter().filter(|b| **b).count();
            if tls_count != 0 && tls_count != 3 {
                return Err(ConfigError::InvalidGrpcConfig {
                    reason: "grpc_tcp.tls_cert_file, .tls_key_file, and \
                             .tls_client_ca_file must all be set together \
                             (rustbgpd does not support TLS without mTLS)"
                        .to_string(),
                });
            }
            if tls_count == 3 {
                // SAFETY: all three are Some — checked above.
                let cert = cfg.tls_cert_file.as_deref().unwrap();
                let key = cfg.tls_key_file.as_deref().unwrap();
                let ca = cfg.tls_client_ca_file.as_deref().unwrap();
                validate_grpc_pem_file(cert, "grpc_tcp.tls_cert_file", PemKind::Certificate)?;
                validate_grpc_pem_file(key, "grpc_tcp.tls_key_file", PemKind::PrivateKey)?;
                validate_grpc_pem_file(ca, "grpc_tcp.tls_client_ca_file", PemKind::Certificate)?;
            }
            validate_grpc_principal(cfg.principal.as_deref(), "grpc_tcp.principal")?;
            if cfg.principal.is_some() && tls_count == 3 {
                return Err(ConfigError::InvalidGrpcConfig {
                    reason: "grpc_tcp.principal is for non-mTLS bearer-token listeners; \
                             mTLS audit principals are derived from the client certificate"
                        .to_string(),
                });
            }
            if cfg.principal.is_some() && cfg.token_file.is_none() {
                return Err(ConfigError::InvalidGrpcConfig {
                    reason: "grpc_tcp.principal requires grpc_tcp.token_file; unauthenticated \
                             TCP listeners must not claim an authenticated principal"
                        .to_string(),
                });
            }
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
            validate_grpc_principal(cfg.principal.as_deref(), "grpc_uds.principal")?;
        }

        if (telemetry.grpc_tcp.is_some() || telemetry.grpc_uds.is_some())
            && tcp.is_none()
            && uds.is_none()
        {
            return Err(ConfigError::InvalidGrpcConfig {
                reason: "at least one gRPC listener must be enabled".to_string(),
            });
        }
        validate_grpc_tier_enforcement(self)?;

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
        let _global_import = parse_policy(
            &self.policy.import,
            &self.policy.neighbor_sets,
            &self.peer_groups,
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
        let _global_import_chain = resolve_chain(
            &self.policy.import_chain,
            &self.policy.definitions,
            &self.policy.neighbor_sets,
            &self.peer_groups,
        )?;
        resolve_chain(
            &self.policy.export_chain,
            &self.policy.definitions,
            &self.policy.neighbor_sets,
            &self.peer_groups,
        )?;

        // Validate neighbor address/interface identity. Numbered peers remain
        // keyed by bare address; link-local peers are scoped by interface.
        {
            let mut seen = std::collections::HashSet::new();
            let mut seen_link_local_addrs = std::collections::HashSet::new();
            for neighbor in &self.neighbors {
                let addr = neighbor.address.parse::<IpAddr>().map_err(|e| {
                    ConfigError::InvalidNeighborAddress {
                        value: neighbor.address.clone(),
                        reason: e.to_string(),
                    }
                })?;
                let is_link_local = matches!(addr, IpAddr::V6(v6) if is_ipv6_link_local_addr(&v6));
                match (&neighbor.interface, is_link_local) {
                    (Some(interface), true) if interface.trim().is_empty() => {
                        return Err(ConfigError::InvalidNeighborConfig {
                            address: neighbor.address.clone(),
                            field: "interface".to_string(),
                            reason: "interface must not be empty".to_string(),
                        });
                    }
                    (Some(_), false) => {
                        return Err(ConfigError::InvalidNeighborConfig {
                            address: neighbor.address.clone(),
                            field: "interface".to_string(),
                            reason: "interface is only valid for IPv6 link-local neighbors"
                                .to_string(),
                        });
                    }
                    (None, true) => {
                        return Err(ConfigError::InvalidNeighborConfig {
                            address: neighbor.address.clone(),
                            field: "interface".to_string(),
                            reason: "IPv6 link-local neighbors require an interface".to_string(),
                        });
                    }
                    _ => {}
                }
                let key = (
                    addr,
                    if is_link_local {
                        neighbor.interface.as_deref()
                    } else {
                        None
                    },
                );
                if !seen.insert(key) {
                    return Err(ConfigError::InvalidNeighborAddress {
                        value: neighbor.address.clone(),
                        reason: "duplicate neighbor address/interface".to_string(),
                    });
                }
                // v1 limitation: the RIB still keys peers by bare address, so the
                // same link-local address bound to two interfaces would alias into
                // one Adj-RIB-In/Out entry (a PeerDown on one would wipe the
                // other's routes). Require each link-local address to be unique
                // across neighbors until the RIB carries scoped peer identity.
                // See ADR-0069 "Deferred".
                if is_link_local && !seen_link_local_addrs.insert(addr) {
                    return Err(ConfigError::InvalidNeighborConfig {
                        address: neighbor.address.clone(),
                        field: "interface".to_string(),
                        reason: "the same IPv6 link-local address on multiple \
                                 interfaces is not supported in this release; use a \
                                 distinct link-local address per interface"
                            .to_string(),
                    });
                }
            }
        }

        for neighbor in &self.neighbors {
            if neighbor.remote_asn == 0 {
                return Err(ConfigError::InvalidNeighborConfig {
                    address: neighbor.address.clone(),
                    field: "remote_asn".to_string(),
                    reason: "must be > 0 for static neighbors".to_string(),
                });
            }

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

            if let Some(tcp_ao) = &neighbor.tcp_ao {
                if neighbor.md5_password.is_some() {
                    return Err(ConfigError::InvalidNeighborConfig {
                        address: neighbor.address.clone(),
                        field: "tcp_ao".to_string(),
                        reason: "tcp_ao is mutually exclusive with md5_password".to_string(),
                    });
                }
                if group.and_then(|g| g.md5_password.as_ref()).is_some() {
                    return Err(ConfigError::InvalidNeighborConfig {
                        address: neighbor.address.clone(),
                        field: "tcp_ao".to_string(),
                        reason:
                            "tcp_ao is mutually exclusive with inherited peer-group md5_password"
                                .to_string(),
                    });
                }
                validate_tcp_ao_config(&neighbor.address, tcp_ao)?;
            }

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

            let role = neighbor.role.or_else(|| group.and_then(|g| g.role));
            let strict_role = neighbor
                .strict_role
                .or_else(|| group.and_then(|g| g.strict_role))
                .unwrap_or(false);
            if strict_role && role.is_none() {
                return Err(ConfigError::InvalidNeighborConfig {
                    address: neighbor.address.clone(),
                    field: "strict_role".to_string(),
                    reason: "strict_role requires role to be configured".to_string(),
                });
            }
            if role.is_some() && neighbor.remote_asn == self.global.asn {
                return Err(ConfigError::InvalidNeighborConfig {
                    address: neighbor.address.clone(),
                    field: "role".to_string(),
                    reason: format!(
                        "BGP Roles require eBGP (remote_asn {} == local asn {})",
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

            // disable_ipv4_unicast contradicts an effective family set of
            // IPv4 unicast only: the session could never negotiate anything.
            let disable_ipv4_unicast = neighbor
                .disable_ipv4_unicast
                .or_else(|| group.and_then(|g| g.disable_ipv4_unicast))
                .unwrap_or(false);
            if disable_ipv4_unicast {
                // Address parse was validated earlier in this function.
                let peer_addr: IpAddr =
                    neighbor
                        .address
                        .parse()
                        .map_err(|e| ConfigError::InvalidNeighborAddress {
                            value: neighbor.address.clone(),
                            reason: format!("{e}"),
                        })?;
                let families = Self::resolved_families(neighbor, group, peer_addr)?;
                if families
                    .iter()
                    .all(|f| *f == (rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::Unicast))
                {
                    return Err(ConfigError::InvalidNeighborConfig {
                        address: neighbor.address.clone(),
                        field: "disable_ipv4_unicast".to_string(),
                        reason: "disable_ipv4_unicast = true requires at least one \
                                 non-ipv4_unicast family (effective families resolve \
                                 to ipv4_unicast only)"
                            .to_string(),
                    });
                }
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

            let _neighbor_import = parse_policy(
                &neighbor.import_policy,
                &self.policy.neighbor_sets,
                &self.peer_groups,
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
            let _neighbor_import_chain = resolve_chain(
                &neighbor.import_policy_chain,
                &self.policy.definitions,
                &self.policy.neighbor_sets,
                &self.peer_groups,
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

            // Reject duplicate collector addresses (canonicalize through SocketAddr)
            let mut seen_addrs = std::collections::HashSet::new();
            for (i, collector) in bmp.collectors.iter().enumerate() {
                let canonical: SocketAddr = collector.address.parse().expect("validated above");
                if !seen_addrs.insert(canonical) {
                    return Err(ConfigError::InvalidBmpCollector {
                        reason: format!(
                            "collectors[{i}]: duplicate address {:?}",
                            collector.address
                        ),
                    });
                }
            }
        }

        // Validate dynamic neighbor ranges
        let mut seen_prefixes = std::collections::HashSet::new();
        for (i, dn) in self.dynamic_neighbors.iter().enumerate() {
            // Prefix must parse as addr/len
            let parts: Vec<&str> = dn.prefix.split('/').collect();
            if parts.len() != 2 {
                return Err(ConfigError::InvalidDynamicNeighbor {
                    reason: format!(
                        "dynamic_neighbors[{i}]: invalid prefix {:?}: expected addr/len",
                        dn.prefix
                    ),
                });
            }
            let addr: IpAddr =
                parts[0]
                    .parse()
                    .map_err(|e| ConfigError::InvalidDynamicNeighbor {
                        reason: format!(
                            "dynamic_neighbors[{i}]: invalid prefix {:?}: {e}",
                            dn.prefix
                        ),
                    })?;
            let len: u8 = parts[1]
                .parse()
                .map_err(|e| ConfigError::InvalidDynamicNeighbor {
                    reason: format!(
                        "dynamic_neighbors[{i}]: invalid prefix {:?}: {e}",
                        dn.prefix
                    ),
                })?;
            match addr {
                IpAddr::V4(_) if len > 32 => {
                    return Err(ConfigError::InvalidDynamicNeighbor {
                        reason: format!(
                            "dynamic_neighbors[{i}]: invalid prefix {:?}: IPv4 prefix length must be 0..=32",
                            dn.prefix
                        ),
                    });
                }
                IpAddr::V6(_) if len > 128 => {
                    return Err(ConfigError::InvalidDynamicNeighbor {
                        reason: format!(
                            "dynamic_neighbors[{i}]: invalid prefix {:?}: IPv6 prefix length must be 0..=128",
                            dn.prefix
                        ),
                    });
                }
                _ => {}
            }

            // Reject exact-duplicate effective prefixes. Overlapping ranges of
            // DIFFERENT lengths are allowed (longest-prefix-match resolves
            // them); two ranges covering the IDENTICAL prefix are ambiguous, so
            // fail at config time rather than letting the runtime matcher pick
            // one by declaration order.
            let key = effective_prefix(addr, len);
            if !seen_prefixes.insert(key) {
                return Err(ConfigError::InvalidDynamicNeighbor {
                    reason: format!(
                        "dynamic_neighbors[{i}]: duplicate effective prefix {}/{} \
                         (another range already covers it)",
                        key.0, key.1
                    ),
                });
            }

            // Peer group must exist
            let Some(group) = self.peer_groups.get(&dn.peer_group) else {
                return Err(ConfigError::InvalidDynamicNeighbor {
                    reason: format!(
                        "dynamic_neighbors[{i}]: peer_group {:?} not defined",
                        dn.peer_group
                    ),
                });
            };

            // v1 BFD is static-neighbors only (ADR-0067). A dynamic range whose
            // peer group enables BFD would silently get no BFD session — reject
            // it at config time rather than mislead the operator into thinking
            // dynamic peers are BFD-protected.
            if group.bfd.as_ref().is_some_and(|b| b.enabled) {
                return Err(ConfigError::InvalidDynamicNeighbor {
                    reason: format!(
                        "dynamic_neighbors[{i}]: peer_group {:?} enables BFD, but BFD is not \
                         supported for dynamic neighbors (static neighbors only in v1; \
                         set `bfd = {{ enabled = false }}` on the group or use static \
                         neighbors — see ADR-0067)",
                        dn.peer_group
                    ),
                });
            }
        }

        // Validate dynamic_neighbor_limit range
        if let Some(limit) = self.global.dynamic_neighbor_limit
            && (limit == 0 || limit > 5000)
        {
            return Err(ConfigError::InvalidDynamicNeighbor {
                reason: format!("dynamic_neighbor_limit must be 1..=5000, got {limit}"),
            });
        }

        // Validate EVPN instances by resolving them — this runs the
        // full per-entry parse plus the table-level uniqueness checks
        // (duplicate VNI, duplicate RD) in one pass. The resolved
        // table is discarded; gRPC and future kernel reconciliation
        // call `resolve_evpn_instances` on demand.
        let _ = self.resolve_evpn_instances()?;
        // Validate Ethernet Segment config at load time as well. The
        // daemon relies on this invariant before spawning the Gate 8
        // orchestrator; invalid ES config must not silently degrade to
        // "orchestrator not spawned".
        let _ = self.resolve_ethernet_segments()?;
        // Validate EVPN IP-VRF config at load time so an operator who
        // declares a malformed [[evpn_ip_vrfs]] block, a duplicate
        // L3VNI, or an L3VNI that collides with an L2VNI sees the
        // error at startup rather than getting silently degraded
        // behavior once Gate 9 wiring lands. Discards the resolved
        // table; the daemon-side supervisor calls
        // `resolve_evpn_ip_vrfs` on demand.
        let _ = self.resolve_evpn_ip_vrfs()?;
        validate_managed_netdevs(self)?;
        validate_fib_tables(self)?;
        validate_bfd(self)?;

        Ok(())
    }
}

fn validate_managed_netdevs(config: &Config) -> Result<(), ConfigError> {
    let managed = &config.managed_netdevs;
    let owner_token = managed.owner_token.as_str();
    if !owner_token.is_empty() {
        validate_managed_token(owner_token, "managed_netdevs.owner_token")?;
    }
    if managed_netdevs_has_rows(managed) && owner_token.is_empty() {
        return Err(ConfigError::InvalidManagedNetdev {
            reason:
                "managed_netdevs.owner_token is required when managed netdev rows are configured"
                    .to_string(),
        });
    }

    let mut names = HashSet::new();
    validate_managed_bridges(&managed.bridges, owner_token, &mut names)?;
    validate_managed_vxlans(&managed.vxlans, owner_token, &mut names)?;
    validate_managed_vrfs(&managed.vrfs, owner_token, &mut names)?;
    validate_managed_l3vxlans(&managed.l3vxlans, owner_token, &mut names)?;
    Ok(())
}

fn managed_netdevs_has_rows(managed: &ManagedNetdevsConfig) -> bool {
    !managed.bridges.is_empty()
        || !managed.vxlans.is_empty()
        || !managed.vrfs.is_empty()
        || !managed.l3vxlans.is_empty()
}

fn validate_managed_bridges(
    bridges: &[ManagedBridgeNetdevConfig],
    owner_token: &str,
    names: &mut HashSet<String>,
) -> Result<(), ConfigError> {
    for bridge in bridges {
        validate_managed_link_name(&bridge.name)?;
        if !names.insert(bridge.name.clone()) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!("duplicate managed bridge name {:?}", bridge.name),
            });
        }
        validate_managed_stamp_len(
            "managed bridge",
            &bridge.name,
            &rustbgpd_evpn::bridge_ownership_stamp(owner_token, &bridge.name),
        )?;
    }
    Ok(())
}

fn validate_managed_vxlans(
    vxlans: &[ManagedVxlanNetdevConfig],
    owner_token: &str,
    names: &mut HashSet<String>,
) -> Result<(), ConfigError> {
    let mut seen_vnis = HashSet::new();
    for vxlan in vxlans {
        validate_managed_link_name(&vxlan.name)?;
        validate_managed_link_name(&vxlan.bridge)?;
        if !names.insert(vxlan.name.clone()) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!("duplicate managed netdev name {:?}", vxlan.name),
            });
        }
        rustbgpd_evpn::EvpnInstanceId::new(vxlan.vni).map_err(|e| {
            ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed VXLAN {:?}: invalid vni {}: {e}",
                    vxlan.name, vxlan.vni
                ),
            }
        })?;
        if !seen_vnis.insert(vxlan.vni) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed VXLAN {:?}: duplicate vni {}",
                    vxlan.name, vxlan.vni
                ),
            });
        }
        if vxlan.dstport == 0 {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed VXLAN {:?}: dstport must be in 1..=65535",
                    vxlan.name
                ),
            });
        }
        if vxlan.learning {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed VXLAN {:?}: learning=true is unsupported; use learning=false (`nolearning`)",
                    vxlan.name
                ),
            });
        }
        validate_managed_stamp_len(
            "managed VXLAN",
            &vxlan.name,
            &rustbgpd_evpn::vxlan_ownership_stamp(owner_token, &vxlan.name),
        )?;
    }
    Ok(())
}

fn validate_managed_vrfs(
    vrfs: &[ManagedVrfNetdevConfig],
    owner_token: &str,
    names: &mut HashSet<String>,
) -> Result<(), ConfigError> {
    let mut seen_table_ids = HashSet::new();
    for vrf in vrfs {
        validate_managed_link_name(&vrf.name)?;
        if !names.insert(vrf.name.clone()) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!("duplicate managed netdev name {:?}", vrf.name),
            });
        }
        if vrf.table_id == 0 {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!("managed VRF {:?}: table_id must be > 0", vrf.name),
            });
        }
        if !seen_table_ids.insert(vrf.table_id) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed VRF {:?}: duplicate table_id {}",
                    vrf.name, vrf.table_id
                ),
            });
        }
        validate_managed_stamp_len(
            "managed VRF",
            &vrf.name,
            &rustbgpd_evpn::vrf_ownership_stamp(owner_token, &vrf.name),
        )?;
    }
    Ok(())
}

fn validate_managed_l3vxlans(
    l3vxlans: &[ManagedL3VxlanNetdevConfig],
    owner_token: &str,
    names: &mut HashSet<String>,
) -> Result<(), ConfigError> {
    let mut seen_vnis = HashSet::new();
    for l3vxlan in l3vxlans {
        validate_managed_link_name(&l3vxlan.name)?;
        validate_managed_link_name(&l3vxlan.vrf)?;
        if !names.insert(l3vxlan.name.clone()) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!("duplicate managed netdev name {:?}", l3vxlan.name),
            });
        }
        rustbgpd_evpn::EvpnInstanceId::new(l3vxlan.vni).map_err(|e| {
            ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed L3VXLAN {:?}: invalid vni {}: {e}",
                    l3vxlan.name, l3vxlan.vni
                ),
            }
        })?;
        if !seen_vnis.insert(l3vxlan.vni) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed L3VXLAN {:?}: duplicate vni {}",
                    l3vxlan.name, l3vxlan.vni
                ),
            });
        }
        if l3vxlan.dstport == 0 {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed L3VXLAN {:?}: dstport must be in 1..=65535",
                    l3vxlan.name
                ),
            });
        }
        if l3vxlan.learning {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed L3VXLAN {:?}: learning=true is unsupported; use learning=false (`nolearning`)",
                    l3vxlan.name
                ),
            });
        }
        let router_mac = parse_mac_address(&l3vxlan.router_mac).map_err(|e| {
            ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed L3VXLAN {:?}: invalid router_mac {:?}: {e}",
                    l3vxlan.name, l3vxlan.router_mac
                ),
            }
        })?;
        if !is_unicast_nonzero_mac(router_mac) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed L3VXLAN {:?}: router_mac {:?} must be a non-zero unicast MAC",
                    l3vxlan.name, l3vxlan.router_mac
                ),
            });
        }
        validate_managed_stamp_len(
            "managed L3VXLAN",
            &l3vxlan.name,
            &rustbgpd_evpn::l3vxlan_ownership_stamp(owner_token, &l3vxlan.name),
        )?;
    }
    Ok(())
}

fn validate_managed_stamp_len(label: &str, name: &str, stamp: &str) -> Result<(), ConfigError> {
    if stamp.len() > rustbgpd_evpn::MAX_ALT_IFNAME_LEN {
        return Err(ConfigError::InvalidManagedNetdev {
            reason: format!(
                "{label} {name:?}: derived ownership altname {stamp:?} is {} bytes; maximum is {}",
                stamp.len(),
                rustbgpd_evpn::MAX_ALT_IFNAME_LEN
            ),
        });
    }
    Ok(())
}

fn validate_managed_token(value: &str, field: &str) -> Result<(), ConfigError> {
    if value.len() > rustbgpd_evpn::MAX_OWNER_TOKEN_LEN {
        return Err(ConfigError::InvalidManagedNetdev {
            reason: format!(
                "{field} is {} bytes; maximum is {}",
                value.len(),
                rustbgpd_evpn::MAX_OWNER_TOKEN_LEN
            ),
        });
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(ConfigError::InvalidManagedNetdev {
            reason: format!("{field} must contain only ASCII letters, digits, '_', '-', or '.'"),
        });
    }
    Ok(())
}

fn validate_managed_link_name(name: &str) -> Result<(), ConfigError> {
    if name.is_empty() {
        return Err(ConfigError::InvalidManagedNetdev {
            reason: "managed netdev name must not be empty".to_string(),
        });
    }
    if name == "." || name == ".." {
        return Err(ConfigError::InvalidManagedNetdev {
            reason: format!("managed netdev name {name:?} is reserved"),
        });
    }
    if name.len() > rustbgpd_evpn::MAX_IFNAME_LEN {
        return Err(ConfigError::InvalidManagedNetdev {
            reason: format!(
                "managed netdev name {:?} is {} bytes; Linux ifname maximum is {}",
                name,
                name.len(),
                rustbgpd_evpn::MAX_IFNAME_LEN
            ),
        });
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(ConfigError::InvalidManagedNetdev {
            reason: format!(
                "managed netdev name {name:?} must contain only ASCII letters, digits, '_', '-', or '.'"
            ),
        });
    }
    Ok(())
}

fn validate_fib_tables(config: &Config) -> Result<(), ConfigError> {
    let mut names = std::collections::HashSet::new();
    let mut table_ids = std::collections::HashSet::new();

    for table in &config.fib_tables {
        if table.name.trim().is_empty() {
            return Err(ConfigError::InvalidFibTable {
                reason: "name must not be empty".to_string(),
            });
        }
        if !table
            .name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
            || !table
                .name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(ConfigError::InvalidFibTable {
                reason: format!("name {:?}: must match ^[a-zA-Z][a-zA-Z0-9_-]*$", table.name),
            });
        }
        if !names.insert(table.name.clone()) {
            return Err(ConfigError::InvalidFibTable {
                reason: format!("duplicate name {:?}", table.name),
            });
        }
        if !table_ids.insert(table.table_id) {
            return Err(ConfigError::InvalidFibTable {
                reason: format!("duplicate table_id {}", table.table_id),
            });
        }
        match table.table_id {
            0 | 252 | 253 | 254 | 255 => {
                return Err(ConfigError::InvalidFibTable {
                    reason: format!(
                        "table_id {} is reserved; choose an explicit non-reserved table",
                        table.table_id
                    ),
                });
            }
            _ => {}
        }
        if table.families.is_empty() {
            return Err(ConfigError::InvalidFibTable {
                reason: format!("name {:?}: families must not be empty", table.name),
            });
        }
        let mut seen_families = std::collections::HashSet::new();
        for family in &table.families {
            match family.as_str() {
                "ipv4_unicast" | "ipv6_unicast" => {}
                other => {
                    return Err(ConfigError::InvalidFibTable {
                        reason: format!(
                            "name {:?}: unsupported family {other:?}; expected \
                             \"ipv4_unicast\" or \"ipv6_unicast\"",
                            table.name
                        ),
                    });
                }
            }
            if !seen_families.insert(family) {
                return Err(ConfigError::InvalidFibTable {
                    reason: format!("name {:?}: duplicate family {family:?}", table.name),
                });
            }
        }
        validate_fib_table_guardrails(config, table)?;
    }

    Ok(())
}

/// Upper bound on `[[fib_tables]].maximum_paths`. Kernel `RTA_MULTIPATH`
/// supports more, but 256 is a generous practical ceiling that keeps a
/// misconfiguration from generating pathologically wide route messages.
const FIB_MAX_MAXIMUM_PATHS: u32 = 256;

fn validate_fib_table_guardrails(
    config: &Config,
    table: &super::FibTableConfig,
) -> Result<(), ConfigError> {
    if let Some(0) = table.max_routes {
        return Err(ConfigError::InvalidFibTable {
            reason: format!(
                "name {:?}: max_routes must be greater than zero",
                table.name
            ),
        });
    }
    // Same `>= 1` / `<= cap` guardrail for the overall and per-class ECMP caps.
    let check_max_paths = |field: &str, value: Option<u32>| -> Result<(), ConfigError> {
        let Some(v) = value else { return Ok(()) };
        if v == 0 {
            return Err(ConfigError::InvalidFibTable {
                reason: format!("name {:?}: {field} must be greater than zero", table.name),
            });
        }
        if v > FIB_MAX_MAXIMUM_PATHS {
            return Err(ConfigError::InvalidFibTable {
                reason: format!(
                    "name {:?}: {field} {v} exceeds the supported cap of {FIB_MAX_MAXIMUM_PATHS}",
                    table.name
                ),
            });
        }
        Ok(())
    };
    check_max_paths("maximum_paths", table.maximum_paths)?;
    check_max_paths("maximum_paths_ebgp", table.maximum_paths_ebgp)?;
    check_max_paths("maximum_paths_ibgp", table.maximum_paths_ibgp)?;
    let mut seen_groups = std::collections::HashSet::new();
    for group in &table.allowed_peer_groups {
        if !config.peer_groups.contains_key(group) {
            return Err(ConfigError::InvalidFibTable {
                reason: format!(
                    "name {:?}: allowed_peer_groups references undefined peer_group {:?}",
                    table.name, group
                ),
            });
        }
        if !seen_groups.insert(group) {
            return Err(ConfigError::InvalidFibTable {
                reason: format!(
                    "name {:?}: duplicate allowed_peer_groups entry {:?}",
                    table.name, group
                ),
            });
        }
    }
    let mut seen_neighbors = std::collections::HashSet::new();
    for neighbor in &table.allowed_neighbors {
        let parsed = neighbor
            .parse::<IpAddr>()
            .map_err(|e| ConfigError::InvalidFibTable {
                reason: format!(
                    "name {:?}: invalid allowed_neighbors entry {:?}: {e}",
                    table.name, neighbor
                ),
            })?;
        if !seen_neighbors.insert(parsed) {
            return Err(ConfigError::InvalidFibTable {
                reason: format!(
                    "name {:?}: duplicate allowed_neighbors entry {parsed}",
                    table.name
                ),
            });
        }
    }
    Ok(())
}

fn validate_tcp_ao_config(address: &str, tcp_ao: &TcpAoConfig) -> Result<(), ConfigError> {
    let key_len = tcp_ao.key.len();
    if key_len == 0 {
        return Err(ConfigError::InvalidNeighborConfig {
            address: address.to_string(),
            field: "tcp_ao.key".to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    if key_len > 80 {
        return Err(ConfigError::InvalidNeighborConfig {
            address: address.to_string(),
            field: "tcp_ao.key".to_string(),
            reason: "must be 80 bytes or fewer".to_string(),
        });
    }

    match tcp_ao.algorithm.as_str() {
        "hmac(sha1)" | "hmac(sha256)" | "cmac(aes128)" => {}
        other => {
            return Err(ConfigError::InvalidNeighborConfig {
                address: address.to_string(),
                field: "tcp_ao.algorithm".to_string(),
                reason: format!(
                    "unknown algorithm {other:?}, expected \"hmac(sha1)\", \"hmac(sha256)\", or \"cmac(aes128)\""
                ),
            });
        }
    }

    if tcp_ao.preferred && tcp_ao.deprecated {
        return Err(ConfigError::InvalidNeighborConfig {
            address: address.to_string(),
            field: "tcp_ao".to_string(),
            reason: "preferred and deprecated cannot both be true".to_string(),
        });
    }

    Ok(())
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

    let _group_import = parse_policy(&group.import_policy, neighbor_sets, peer_groups)?;
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
    let _group_import_chain = resolve_chain(
        &group.import_policy_chain,
        definitions,
        neighbor_sets,
        peer_groups,
    )?;
    resolve_chain(
        &group.export_policy_chain,
        definitions,
        neighbor_sets,
        peer_groups,
    )?;

    Ok(())
}

fn validate_event_history(cfg: &EventHistoryConfig) -> Result<(), ConfigError> {
    if !cfg.enabled {
        return Ok(());
    }

    if !matches!(cfg.synchronous.as_str(), "full" | "normal") {
        return Err(ConfigError::InvalidEventHistoryConfig {
            reason: format!(
                "synchronous = {:?} not supported; expected \"full\" or \"normal\"",
                cfg.synchronous
            ),
        });
    }
    if cfg.overflow != "drop" {
        return Err(ConfigError::InvalidEventHistoryConfig {
            reason: format!(
                "overflow = {:?} not supported in v1; only \"drop\" is implemented (ADR-0072 reserves \"block\" for a future release)",
                cfg.overflow
            ),
        });
    }
    if cfg.queue_capacity == 0 {
        return Err(ConfigError::InvalidEventHistoryConfig {
            reason: "queue_capacity must be > 0".to_string(),
        });
    }
    if cfg.batch_size == 0 {
        return Err(ConfigError::InvalidEventHistoryConfig {
            reason: "batch_size must be > 0".to_string(),
        });
    }
    if cfg.batch_interval_ms == 0 {
        return Err(ConfigError::InvalidEventHistoryConfig {
            reason: "batch_interval_ms must be > 0".to_string(),
        });
    }
    if cfg.max_events == 0 {
        return Err(ConfigError::InvalidEventHistoryConfig {
            reason: "max_events must be > 0".to_string(),
        });
    }
    if cfg.max_bytes == 0 {
        return Err(ConfigError::InvalidEventHistoryConfig {
            reason: "max_bytes must be > 0".to_string(),
        });
    }
    Ok(())
}

fn validate_grpc_security(security: &SecurityConfig) -> Result<(), ConfigError> {
    for principal in security.grpc.roles.keys() {
        if principal.trim().is_empty() {
            return Err(ConfigError::InvalidGrpcConfig {
                reason: "security.grpc.roles principal keys must not be empty".to_string(),
            });
        }
        if principal == "mtls-unresolved" {
            return Err(ConfigError::InvalidGrpcConfig {
                reason: "security.grpc.roles must not map reserved principal \
                         \"mtls-unresolved\""
                    .to_string(),
            });
        }
    }
    Ok(())
}

fn validate_grpc_tier_enforcement(config: &Config) -> Result<(), ConfigError> {
    if config.security.grpc.enforcement != GrpcEnforcementConfig::Tier {
        return Ok(());
    }
    if config.security.grpc.roles.is_empty() {
        return Err(ConfigError::InvalidGrpcConfig {
            reason: "security.grpc.enforcement = \"tier\" (the v0.24.0 \
                     default) requires at least one [security.grpc.roles] \
                     entry — see docs/CONFIGURATION.md for the migration \
                     checklist, or opt back into legacy with \
                     `security.grpc.enforcement = \"legacy\"`"
                .to_string(),
        });
    }

    let telemetry = &config.global.telemetry;
    let tcp = telemetry.grpc_tcp.as_ref().filter(|cfg| cfg.enabled);
    let uds = telemetry.grpc_uds.as_ref().filter(|cfg| cfg.enabled);
    if tcp.is_none() && uds.is_none() {
        return Err(ConfigError::InvalidGrpcConfig {
            reason: "security.grpc.enforcement = \"tier\" (the v0.24.0 \
                     default) requires an explicit gRPC listener with mTLS \
                     or a configured principal; the implicit UDS listener \
                     has no role identity. Configure \
                     [global.telemetry.grpc_uds] with `principal`, or opt \
                     back into legacy with \
                     `security.grpc.enforcement = \"legacy\"`"
                .to_string(),
        });
    }

    if let Some(cfg) = tcp {
        let mtls_enabled = cfg.tls_cert_file.is_some()
            && cfg.tls_key_file.is_some()
            && cfg.tls_client_ca_file.is_some();
        if !mtls_enabled && cfg.principal.is_none() {
            if cfg.token_file.is_some() {
                return Err(ConfigError::InvalidGrpcConfig {
                    reason: "security.grpc.enforcement = \"tier\" requires \
                             grpc_tcp.principal for bearer-token TCP listeners"
                        .to_string(),
                });
            }
            return Err(ConfigError::InvalidGrpcConfig {
                reason: "security.grpc.enforcement = \"tier\" rejects \
                         unauthenticated TCP listeners; configure native mTLS \
                         or grpc_tcp.token_file plus grpc_tcp.principal"
                    .to_string(),
            });
        }
        if let Some(principal) = cfg.principal.as_deref() {
            validate_grpc_role_principal(config, principal, "grpc_tcp.principal")?;
        }
    }

    if let Some(cfg) = uds {
        let Some(principal) = cfg.principal.as_deref() else {
            return Err(ConfigError::InvalidGrpcConfig {
                reason: "security.grpc.enforcement = \"tier\" requires \
                         grpc_uds.principal for UDS listeners"
                    .to_string(),
            });
        };
        validate_grpc_role_principal(config, principal, "grpc_uds.principal")?;
    }
    Ok(())
}

fn validate_grpc_role_principal(
    config: &Config,
    principal: &str,
    field_name: &str,
) -> Result<(), ConfigError> {
    if config.security.grpc.roles.contains_key(principal) {
        return Ok(());
    }
    Err(ConfigError::InvalidGrpcConfig {
        reason: format!(
            "security.grpc.enforcement = \"tier\" requires {field_name} \
             principal {principal:?} to be present in [security.grpc.roles]"
        ),
    })
}

fn validate_grpc_principal(principal: Option<&str>, field_name: &str) -> Result<(), ConfigError> {
    if let Some(principal) = principal
        && principal.trim().is_empty()
    {
        return Err(ConfigError::InvalidGrpcConfig {
            reason: format!("{field_name} must not be empty"),
        });
    }
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

/// What a PEM file is expected to contain. Used by
/// [`validate_grpc_pem_file`] to surface a clear error when the operator
/// swapped a cert path with a key path (or vice versa).
#[derive(Debug, Clone, Copy)]
enum PemKind {
    /// A `CERTIFICATE` block (server identity or trust anchor).
    Certificate,
    /// A `PRIVATE KEY`, `RSA PRIVATE KEY`, or `EC PRIVATE KEY` block.
    PrivateKey,
}

/// Validate a PEM-encoded TLS file at config-load / `--check` time.
///
/// Catches the surprises that would otherwise only surface at daemon
/// startup: missing path, unreadable file, empty file, file with no
/// PEM markers, file with PEM blocks of the wrong kind (e.g., cert
/// path pointed at a private key). Tonic's `Identity::from_pem` and
/// `Certificate::from_pem` only hold the bytes; the actual parser
/// runs deep inside `ServerTlsConfig::tls_config` at server build
/// time, well past `--check`. This is a structural pre-flight, not a
/// full key/cert match — a mismatched cert+key pair will still fail
/// at server build, but missing-file / wrong-kind errors are caught
/// before the daemon ever starts.
fn validate_grpc_pem_file(path: &str, field_name: &str, kind: PemKind) -> Result<(), ConfigError> {
    if path.trim().is_empty() {
        return Err(ConfigError::InvalidGrpcConfig {
            reason: format!("{field_name} must not be empty"),
        });
    }
    let bytes = std::fs::read(path).map_err(|e| ConfigError::InvalidGrpcConfig {
        reason: format!("failed to read {field_name} {path:?}: {e}"),
    })?;
    if bytes.is_empty() {
        return Err(ConfigError::InvalidGrpcConfig {
            reason: format!("{field_name} {path:?} is empty"),
        });
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| ConfigError::InvalidGrpcConfig {
        reason: format!("{field_name} {path:?} is not valid UTF-8 (PEM is ASCII)"),
    })?;

    let begin_lines: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("-----BEGIN ") && l.trim_end().ends_with("-----"))
        .collect();
    let end_lines: Vec<&str> = text
        .lines()
        .filter(|l| l.starts_with("-----END ") && l.trim_end().ends_with("-----"))
        .collect();
    if begin_lines.is_empty() || end_lines.is_empty() {
        return Err(ConfigError::InvalidGrpcConfig {
            reason: format!(
                "{field_name} {path:?} has no PEM blocks (missing -----BEGIN/END----- markers)"
            ),
        });
    }
    if begin_lines.len() != end_lines.len() {
        return Err(ConfigError::InvalidGrpcConfig {
            reason: format!(
                "{field_name} {path:?} has unbalanced PEM markers ({} BEGIN, {} END)",
                begin_lines.len(),
                end_lines.len()
            ),
        });
    }

    let acceptable: &[&str] = match kind {
        PemKind::Certificate => &["CERTIFICATE"],
        PemKind::PrivateKey => &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"],
    };
    let any_match = begin_lines.iter().any(|line| {
        let trimmed = line.trim_end();
        acceptable
            .iter()
            .any(|kind| trimmed == format!("-----BEGIN {kind}-----"))
    });
    if !any_match {
        let kinds = acceptable.join(" / ");
        return Err(ConfigError::InvalidGrpcConfig {
            reason: format!(
                "{field_name} {path:?} contains no PEM block of expected kind ({kinds}) — \
                 found: {}",
                begin_lines.first().copied().unwrap_or("<none>")
            ),
        });
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

/// Minimum BFD interval (ms). Conservative for v1 — aggressive sub-100 ms
/// timers risk false flaps that are worse than slightly slower detection.
const BFD_MIN_INTERVAL_MS: u32 = 100;
/// Maximum BFD interval (ms). The actor converts ms → microseconds (`* 1000`)
/// into the `u32` wire field, so anything above this would overflow / be
/// silently clamped. Reject it instead.
const BFD_MAX_INTERVAL_MS: u32 = u32::MAX / 1000;
/// Minimum BFD detection multiplier.
const BFD_MIN_MULTIPLIER: u32 = 2;
/// Maximum BFD detection multiplier — the RFC 5880 §4.1 Detect Mult field is a
/// single octet, so values above 255 cannot be represented on the wire.
const BFD_MAX_MULTIPLIER: u32 = 255;

/// Validate `[[bfd_profiles]]` and that every `bfd.profile` reference resolves.
fn validate_bfd(config: &Config) -> Result<(), ConfigError> {
    let mut names = std::collections::HashSet::new();
    for profile in &config.bfd_profiles {
        if profile.name.trim().is_empty() {
            return Err(ConfigError::InvalidBfd {
                reason: "bfd_profile name must not be empty".to_string(),
            });
        }
        if !names.insert(profile.name.clone()) {
            return Err(ConfigError::InvalidBfd {
                reason: format!("duplicate bfd_profile name {:?}", profile.name),
            });
        }
        if profile.min_tx_interval < BFD_MIN_INTERVAL_MS
            || profile.min_rx_interval < BFD_MIN_INTERVAL_MS
        {
            return Err(ConfigError::InvalidBfd {
                reason: format!(
                    "bfd_profile {:?}: min_tx_interval and min_rx_interval must be >= {BFD_MIN_INTERVAL_MS} ms",
                    profile.name
                ),
            });
        }
        if profile.min_tx_interval > BFD_MAX_INTERVAL_MS
            || profile.min_rx_interval > BFD_MAX_INTERVAL_MS
        {
            return Err(ConfigError::InvalidBfd {
                reason: format!(
                    "bfd_profile {:?}: min_tx_interval and min_rx_interval must be <= {BFD_MAX_INTERVAL_MS} ms",
                    profile.name
                ),
            });
        }
        if profile.multiplier < BFD_MIN_MULTIPLIER {
            return Err(ConfigError::InvalidBfd {
                reason: format!(
                    "bfd_profile {:?}: multiplier must be >= {BFD_MIN_MULTIPLIER}",
                    profile.name
                ),
            });
        }
        if profile.multiplier > BFD_MAX_MULTIPLIER {
            return Err(ConfigError::InvalidBfd {
                reason: format!(
                    "bfd_profile {:?}: multiplier must be <= {BFD_MAX_MULTIPLIER}",
                    profile.name
                ),
            });
        }
    }

    let profile_defined = |profile: &str| names.contains(profile);
    for neighbor in &config.neighbors {
        if let Some(bfd) = &neighbor.bfd
            && !profile_defined(&bfd.profile)
        {
            return Err(ConfigError::InvalidBfd {
                reason: format!(
                    "neighbor {:?}: bfd.profile {:?} is not defined in [[bfd_profiles]]",
                    neighbor.address, bfd.profile
                ),
            });
        }
    }
    for (group_name, group) in &config.peer_groups {
        if let Some(bfd) = &group.bfd
            && !profile_defined(&bfd.profile)
        {
            return Err(ConfigError::InvalidBfd {
                reason: format!(
                    "peer_group {group_name:?}: bfd.profile {:?} is not defined in [[bfd_profiles]]",
                    bfd.profile
                ),
            });
        }
    }

    // v1 ships IPv4 + IPv6 global only. BGP link-local peers carry interface
    // scope, but the BFD actor still keys and sends sessions by bare address.
    // Reject it up front with an actionable error rather than silently failing
    // to converge (ADR-0067 defers link-local BFD to v1.1).
    for neighbor in &config.neighbors {
        // Effective BFD = own block, else inherited from the peer group; a
        // disabled (`enabled = false`) block runs no session, so it does not
        // count.
        let effective_bfd = if neighbor.bfd.is_some() {
            neighbor.bfd.as_ref()
        } else {
            neighbor
                .peer_group
                .as_ref()
                .and_then(|g| config.peer_groups.get(g))
                .and_then(|pg| pg.bfd.as_ref())
        };
        let has_effective_bfd = effective_bfd.is_some_and(|b| b.enabled);
        if has_effective_bfd && is_ipv6_link_local(&neighbor.address) {
            return Err(ConfigError::InvalidBfd {
                reason: format!(
                    "neighbor {:?}: BFD on IPv6 link-local addresses is not supported in v1 \
                     (BFD link-local session scoping is deferred to v1.1)",
                    neighbor.address
                ),
            });
        }
    }
    Ok(())
}

/// Whether `addr` parses to an IPv6 link-local address (`fe80::/10`).
fn is_ipv6_link_local(addr: &str) -> bool {
    addr.parse::<std::net::Ipv6Addr>()
        .is_ok_and(|a| is_ipv6_link_local_addr(&a))
}

fn is_ipv6_link_local_addr(addr: &std::net::Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80
}
