use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use rustbgpd_transport::TCP_AO_MAX_INSPECT_KEYS;

use super::parse::{
    ChainDirection, parse_families, parse_named_policy, parse_neighbor_set, parse_policy,
    resolve_chain,
};
use super::schema::{
    ManagedBridgeNetdevConfig, ManagedL3VxlanNetdevConfig, ManagedNetdevsConfig,
    ManagedSvdVxlanNetdevConfig, ManagedVlanUpperNetdevConfig, ManagedVrfNetdevConfig,
    ManagedVxlanNetdevConfig,
};
use super::{
    Config, ConfigError, DEFAULT_HOLD_TIME, EventHistoryConfig, GrpcEnforcementConfig,
    PeerGroupConfig, SecurityConfig, TcpAoConfig, TcpAoKeyringConfig, dynamic_prefixes_intersect,
    is_unicast_nonzero_mac, parse_mac_address,
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

/// A legal configuration with a consequence its operator should see.
///
/// Not an error — `Config::load` accepts the config — but reported by
/// `rustbgpd --check`, counted for `--check --strict`, and logged once at
/// daemon startup. Each one states the condition (`headline`) and then the
/// consequence and the action that clears it (`detail`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ConfigAdvisory {
    /// The condition, as a single sentence.
    pub(crate) headline: &'static str,
    /// Consequence, then the action. Hard-wrapped for the framed `--check`
    /// block; use [`ConfigAdvisory::one_line`] for a log record.
    pub(crate) detail: &'static str,
}

impl ConfigAdvisory {
    /// Headline and detail collapsed onto one line, for `tracing`, where a
    /// record spanning several lines is a parsing hazard.
    pub(crate) fn one_line(&self) -> String {
        let mut out = String::with_capacity(self.headline.len() + self.detail.len() + 1);
        for word in self
            .headline
            .split_whitespace()
            .chain(self.detail.split_whitespace())
        {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(word);
        }
        out
    }
}

impl Config {
    #[expect(
        clippy::too_many_lines,
        reason = "validation keeps related operator diagnostics in one ordered pass"
    )]
    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if self.global.asn == 0 {
            return Err(ConfigError::InvalidLocalAsn {
                value: self.global.asn,
            });
        }

        // RFC 6286 section 2.1: the router ID is any non-zero u32.
        let router_id = self.global.router_id.parse::<Ipv4Addr>().map_err(|e| {
            ConfigError::InvalidRouterId {
                value: self.global.router_id.clone(),
                reason: e.to_string(),
            }
        })?;
        if router_id.is_unspecified() {
            return Err(ConfigError::InvalidRouterId {
                value: self.global.router_id.clone(),
                reason: "must be non-zero (RFC 6286 section 2.1)".to_string(),
            });
        }

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

        validate_reserved_policy_names(self)?;
        validate_event_history(&self.event_history)?;
        validate_grpc_security(&self.security)?;
        self.validate_no_redacted_secrets()?;

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
                let cert = cfg
                    .tls_cert_file
                    .as_deref()
                    .expect("tls_count == 3 means all three TLS paths are Some");
                let key = cfg
                    .tls_key_file
                    .as_deref()
                    .expect("tls_count == 3 means all three TLS paths are Some");
                let ca = cfg
                    .tls_client_ca_file
                    .as_deref()
                    .expect("tls_count == 3 means all three TLS paths are Some");
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
        for (name, set) in &self.policy.neighbor_sets {
            parse_neighbor_set(name, set, &self.peer_groups)?;
        }

        for (name, group) in &self.peer_groups {
            validate_peer_group(
                name,
                group,
                &self.policy.definitions,
                &self.policy.rpol,
                &self.policy.dataset_bindings,
                &self.policy.neighbor_sets,
                &self.peer_groups,
                self.global.asn,
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
            &self.policy.rpol,
            &self.policy.dataset_bindings,
            &self.policy.neighbor_sets,
            &self.peer_groups,
            ChainDirection::Import,
            self.global.asn,
        )?;
        resolve_chain(
            &self.policy.export_chain,
            &self.policy.definitions,
            &self.policy.rpol,
            &self.policy.dataset_bindings,
            &self.policy.neighbor_sets,
            &self.peer_groups,
            ChainDirection::Export,
            self.global.asn,
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
            let min_hold_time = neighbor
                .min_hold_time
                .or_else(|| group.and_then(|g| g.min_hold_time));
            if let Some(minimum) = min_hold_time {
                if minimum < 3 {
                    return Err(ConfigError::InvalidMinHoldTime { value: minimum });
                }
                if hold_time == 0 || minimum > hold_time {
                    return Err(ConfigError::InvalidMinHoldTimeForHoldTime { minimum, hold_time });
                }
            }

            // RFC 9687 §4.4: a non-zero SendHoldTime MUST be greater
            // than the hold time. Checked on the effective (inherited)
            // values; the derived default always satisfies this.
            let send_hold_time = neighbor
                .send_hold_time
                .or_else(|| group.and_then(|g| g.send_hold_time));
            if let Some(value) = send_hold_time
                && value != 0
                && value <= u32::from(hold_time)
            {
                return Err(ConfigError::InvalidSendHoldTime { value, hold_time });
            }

            // Slow-peer backlog threshold is a fraction of the outbound
            // writer buffer: 0 would flag an empty queue and >100 could
            // never fire. Checked on the effective (inherited) value.
            let slow_peer_threshold_pct = neighbor
                .slow_peer_threshold_pct
                .or_else(|| group.and_then(|g| g.slow_peer_threshold_pct));
            if let Some(value) = slow_peer_threshold_pct
                && !(1..=100).contains(&value)
            {
                return Err(ConfigError::InvalidSlowPeerThreshold { value });
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

            // Validate orr_vantage (RFC 9107): ORR is a route-reflector
            // feature, so the vantage only makes sense on an iBGP
            // route-reflector-client.
            let orr_vantage = neighbor
                .orr_vantage
                .or_else(|| group.and_then(|g| g.orr_vantage));
            if let Some(vantage) = orr_vantage {
                if neighbor.remote_asn != self.global.asn {
                    return Err(ConfigError::InvalidRrConfig {
                        reason: format!(
                            "orr_vantage requires iBGP (remote_asn {} != local asn {})",
                            neighbor.remote_asn, self.global.asn
                        ),
                    });
                }
                if !route_reflector_client {
                    return Err(ConfigError::InvalidRrConfig {
                        reason: format!(
                            "orr_vantage on neighbor {} requires route_reflector_client = true",
                            neighbor.address
                        ),
                    });
                }
                // RFC 9107: the vantage must identify a *distinct* BGP-LS
                // topology node. Equal to the client's own peering address
                // or the reflector's router_id it degenerates to the
                // reflector's own viewpoint (plain non-ORR reflection) — a
                // copy-paste misconfiguration. Fail closed at config load.
                if let Ok(peer_addr) = neighbor.address.parse::<IpAddr>()
                    && vantage == peer_addr
                {
                    return Err(ConfigError::InvalidRrConfig {
                        reason: format!(
                            "orr_vantage {vantage} on neighbor {} must not equal the \
                             neighbor's own address",
                            neighbor.address
                        ),
                    });
                }
                if let Ok(local_addr) = self.global.router_id.parse::<IpAddr>()
                    && vantage == local_addr
                {
                    return Err(ConfigError::InvalidRrConfig {
                        reason: format!(
                            "orr_vantage {vantage} on neighbor {} must not equal the \
                             reflector's local router_id {}",
                            neighbor.address, self.global.router_id
                        ),
                    });
                }
                // A wildcard (0.0.0.0 / ::) or loopback vantage names no real
                // BGP-LS topology node, so ORR silently degenerates to plain
                // reflection. Reject it at load rather than run inert.
                if vantage.is_unspecified() || vantage.is_loopback() {
                    return Err(ConfigError::InvalidRrConfig {
                        reason: format!(
                            "orr_vantage {vantage} on neighbor {} must be a real topology \
                             address, not an unspecified or loopback address",
                            neighbor.address
                        ),
                    });
                }
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

            // RFC 7947 §2.3.2 per-client best-path is a route-server
            // feature (eBGP-only follows transitively; ORR exclusion
            // too — the vantage requires an iBGP RR client).
            let per_client_best = neighbor
                .per_client_best
                .or_else(|| group.and_then(|g| g.per_client_best))
                .unwrap_or(false);
            if per_client_best && !route_server_client {
                return Err(ConfigError::InvalidRouteServerConfig {
                    reason: format!(
                        "per_client_best on neighbor {} requires route_server_client = true",
                        neighbor.address
                    ),
                });
            }

            // ADR-0107 NEXT_HOP ownership is a route-server ingress
            // guard: it authorizes a member's announced next hop against
            // the advertising session, which only makes sense on a
            // transparent route-server client session.
            let next_hop_ownership = neighbor
                .next_hop_ownership
                .or_else(|| group.and_then(|g| g.next_hop_ownership));
            if next_hop_ownership.is_some() && !route_server_client {
                return Err(ConfigError::InvalidRouteServerConfig {
                    reason: format!(
                        "next_hop_ownership on neighbor {} requires route_server_client = true",
                        neighbor.address
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

            let required_families = if !neighbor.required_families.is_empty() {
                parse_families(&neighbor.required_families)?
            } else if let Some(group) = group.filter(|g| !g.required_families.is_empty()) {
                parse_families(&group.required_families)?
            } else {
                Vec::new()
            };
            if !required_families.is_empty() {
                let peer_addr: IpAddr = neighbor.address.parse().expect("validated above");
                let mut effective = Self::resolved_families(neighbor, group, peer_addr)?;
                if disable_ipv4_unicast {
                    effective.retain(|family| {
                        *family != (rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::Unicast)
                    });
                }
                if let Some(missing) = required_families
                    .iter()
                    .find(|family| !effective.contains(family))
                {
                    return Err(ConfigError::InvalidNeighborConfig {
                        address: neighbor.address.clone(),
                        field: "required_families".to_string(),
                        reason: format!(
                            "required family {:?}/{:?} is not in the effective configured family set",
                            missing.0, missing.1
                        ),
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
                .gr_peer_restart_time_max
                .or_else(|| group.and_then(|g| g.gr_peer_restart_time_max))
                && t == 0
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: "gr_peer_restart_time_max must be > 0".to_string(),
                });
            }
            if let Some(t) = neighbor
                .gr_peer_restart_time_max
                .or_else(|| group.and_then(|g| g.gr_peer_restart_time_max))
                && t > 4095
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: format!("gr_peer_restart_time_max {t} exceeds 4095 (12-bit max)"),
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
                &self.policy.rpol,
                &self.policy.dataset_bindings,
                &self.policy.neighbor_sets,
                &self.peer_groups,
                ChainDirection::Import,
                self.global.asn,
            )?;
            resolve_chain(
                &neighbor.export_policy_chain,
                &self.policy.definitions,
                &self.policy.rpol,
                &self.policy.dataset_bindings,
                &self.policy.neighbor_sets,
                &self.peer_groups,
                ChainDirection::Export,
                self.global.asn,
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
                if collector.monitor.is_empty() {
                    return Err(ConfigError::InvalidBmpCollector {
                        reason: format!(
                            "collectors[{i}]: monitor must not be empty \
                             (use [\"rib_in_pre\"] and/or [\"rib_out_post\"])"
                        ),
                    });
                }
                if !matches!(collector.version, 3 | 4) {
                    return Err(ConfigError::InvalidBmpCollector {
                        reason: format!(
                            "collectors[{i}]: version must be 3 or 4 (got {})",
                            collector.version
                        ),
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

        // Validate the gNMI dial-out section. The semantic checks live in
        // the shared translation the daemon wiring uses, so a config that
        // loads always resolves into runnable dial-out targets — including
        // running each subscription path through the exact validation a
        // dial-in Subscribe request would get.
        super::gnmi_dialout_targets(self)
            .map_err(|reason| ConfigError::InvalidGnmiDialout { reason })?;

        // Validate dynamic neighbor ranges
        let mut seen_prefixes = std::collections::HashSet::new();
        let mut parsed_dynamic_prefixes = Vec::with_capacity(self.dynamic_neighbors.len());
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
            parsed_dynamic_prefixes.push((key.0, key.1));

            // Peer group must exist
            let Some(group) = self.peer_groups.get(&dn.peer_group) else {
                return Err(ConfigError::InvalidDynamicNeighbor {
                    reason: format!(
                        "dynamic_neighbors[{i}]: peer_group {:?} not defined",
                        dn.peer_group
                    ),
                });
            };

            if !group.required_families.is_empty() {
                let required = parse_families(&group.required_families).map_err(|err| {
                    ConfigError::InvalidDynamicNeighbor {
                        reason: format!(
                            "dynamic_neighbors[{i}]: peer_group {:?} has invalid required_families: {err}",
                            dn.peer_group
                        ),
                    }
                })?;
                let mut effective = if group.families.is_empty() {
                    let mut defaults =
                        vec![(rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::Unicast)];
                    if addr.is_ipv6() {
                        defaults.push((rustbgpd_wire::Afi::Ipv6, rustbgpd_wire::Safi::Unicast));
                    }
                    defaults
                } else {
                    parse_families(&group.families).map_err(|err| {
                        ConfigError::InvalidDynamicNeighbor {
                            reason: format!(
                                "dynamic_neighbors[{i}]: peer_group {:?} has invalid families: {err}",
                                dn.peer_group
                            ),
                        }
                    })?
                };
                if group.disable_ipv4_unicast.unwrap_or(false) {
                    effective.retain(|family| {
                        *family != (rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::Unicast)
                    });
                }
                if let Some(missing) = required.iter().find(|family| !effective.contains(family)) {
                    return Err(ConfigError::InvalidDynamicNeighbor {
                        reason: format!(
                            "dynamic_neighbors[{i}]: required family {:?}/{:?} from peer_group {:?} is not in the effective configured family set",
                            missing.0, missing.1, dn.peer_group
                        ),
                    });
                }
            }

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

            if let Some(tcp_ao) = &dn.tcp_ao {
                if group.md5_password.is_some() {
                    return Err(ConfigError::InvalidDynamicNeighbor {
                        reason: format!(
                            "dynamic_neighbors[{i}]: tcp_ao is mutually exclusive with \
                             md5_password on peer group {:?}; dynamic authentication is direct \
                             and never inherited",
                            dn.peer_group
                        ),
                    });
                }
                validate_tcp_ao_config(&dn.prefix, tcp_ao).map_err(|err| {
                    ConfigError::InvalidDynamicNeighbor {
                        reason: format!("dynamic_neighbors[{i}]: {err}"),
                    }
                })?;
            }
        }

        // Linux may inherit every covering MKT onto an accepted child. Permit
        // overlapping TCP-AO owners only when their directional ID namespaces
        // are disjoint; the listener then reconciles the complete owned union
        // while static-exact/dynamic-LPM selects Current and RNext ownership.
        // Any AO/plaintext or AO/MD5 overlap remains fail-closed.
        for (i, left) in self.dynamic_neighbors.iter().enumerate() {
            for (j, right) in self.dynamic_neighbors.iter().enumerate().skip(i + 1) {
                if !dynamic_prefixes_intersect(
                    parsed_dynamic_prefixes[i],
                    parsed_dynamic_prefixes[j],
                ) || (left.tcp_ao.is_none() && right.tcp_ao.is_none())
                {
                    continue;
                }
                let (Some(left_ao), Some(right_ao)) = (&left.tcp_ao, &right.tcp_ao) else {
                    return Err(ConfigError::InvalidDynamicNeighbor {
                        reason: format!(
                            "dynamic_neighbors[{i}] {:?} and dynamic_neighbors[{j}] {:?} \
                             overlap across a TCP-AO and non-TCP-AO authentication boundary",
                            left.prefix, right.prefix
                        ),
                    });
                };
                if let Some(direction) = tcp_ao_overlap_id_collision(left_ao, right_ao) {
                    return Err(ConfigError::InvalidDynamicNeighbor {
                        reason: format!(
                            "dynamic_neighbors[{i}] {:?} and dynamic_neighbors[{j}] {:?} \
                             overlap with a TCP-AO {direction} collision; overlapping owners \
                             require disjoint SendID and RecvID sets",
                            left.prefix, right.prefix
                        ),
                    });
                }
            }

            for neighbor in &self.neighbors {
                let Ok(address) = neighbor.address.parse::<IpAddr>() else {
                    continue;
                };
                let host_prefix = (address, if address.is_ipv4() { 32 } else { 128 });
                if !dynamic_prefixes_intersect(parsed_dynamic_prefixes[i], host_prefix)
                    || (left.tcp_ao.is_none() && neighbor.tcp_ao.is_none())
                {
                    continue;
                }
                let (Some(dynamic_ao), Some(static_ao)) = (&left.tcp_ao, &neighbor.tcp_ao) else {
                    return Err(ConfigError::InvalidDynamicNeighbor {
                        reason: format!(
                            "dynamic_neighbors[{i}] TCP-AO boundary {:?} overlaps static \
                             neighbor {:?} across a TCP-AO and non-TCP-AO authentication boundary",
                            left.prefix, neighbor.address
                        ),
                    });
                };
                if let Some(direction) = tcp_ao_overlap_id_collision(dynamic_ao, static_ao) {
                    return Err(ConfigError::InvalidDynamicNeighbor {
                        reason: format!(
                            "dynamic_neighbors[{i}] {:?} and static neighbor {:?} overlap \
                             with a TCP-AO {direction} collision; overlapping owners require \
                             disjoint SendID and RecvID sets",
                            left.prefix, neighbor.address
                        ),
                    });
                }
            }
        }

        validate_tcp_ao_listener_capacity(self, &parsed_dynamic_prefixes)?;

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

    /// True when any neighbor (directly or via its peer group) has an
    /// effective `orr_vantage` but NO neighbor's effective `families`
    /// include `"linkstate"` — i.e. the BGP-LS topology feed the ORR SPF
    /// needs would be empty. Pure so the warning condition is testable.
    pub(crate) fn orr_vantage_without_linkstate(&self) -> bool {
        let group_of = |neighbor: &super::Neighbor| {
            neighbor
                .peer_group
                .as_deref()
                .and_then(|name| self.peer_groups.get(name))
        };
        let any_vantage = self.neighbors.iter().any(|n| {
            n.orr_vantage
                .or_else(|| group_of(n).and_then(|g| g.orr_vantage))
                .is_some()
        });
        if !any_vantage {
            return false;
        }
        !self.neighbors.iter().any(|n| {
            let own = &n.families;
            let effective: &[String] = if own.is_empty() {
                group_of(n).map_or(&[], |g| g.families.as_slice())
            } else {
                own.as_slice()
            };
            effective.iter().any(|f| f == "linkstate")
        })
    }

    /// Every advisory this configuration raises, in a stable order.
    ///
    /// Returning them — rather than logging them where they are detected —
    /// is what makes them reach an operator at all. `validate()` runs
    /// inside `Config::load`, which both `--check` and daemon startup call
    /// *before* `init_logging`: a `tracing::warn!` there has no subscriber
    /// installed and is discarded, so a validation-time diagnostic was
    /// invisible on every path except a SIGHUP reload. A returned list is
    /// countable (the `--check --strict` exit code is that count),
    /// printable wherever the caller does have an output channel, and
    /// testable without standing up a subscriber.
    pub(crate) fn advisories(&self) -> Vec<ConfigAdvisory> {
        let mut advisories = Vec::new();

        // RFC 9107 ORR: a vantage without a BGP-LS feed can never resolve.
        // Legal — linkstate peers may be added later — so it warns rather
        // than rejects.
        if self.orr_vantage_without_linkstate() {
            advisories.push(ConfigAdvisory {
                headline: "orr_vantage is configured but no neighbor negotiates the \
                           \"linkstate\" family.",
                detail: "The optimal-route-reflection SPF runs on the BGP-LS topology feed, and\n\
                         nothing feeds it: the topology stays permanently empty, every vantage\n\
                         stays unresolved, and best-path selection falls back to the standard\n\
                         IGP-metric comparison for every client — the orr_vantage settings in\n\
                         this config have no effect. Add \"linkstate\" to the families of the\n\
                         neighbor carrying the BGP-LS feed, or remove orr_vantage from the\n\
                         neighbors and peer groups that set it. See\n\
                         docs/adr/0095-optimal-route-reflection.md.",
            });
        }

        // Pre-ADR-0064 gRPC authorization. Tier enforcement has been the
        // default since v0.24.0 and becomes mandatory, so an operator still
        // pinned to `legacy` is carrying both an open management surface and
        // a config that a future release will reject.
        if matches!(
            self.security.grpc.enforcement,
            GrpcEnforcementConfig::Legacy
        ) {
            advisories.push(ConfigAdvisory {
                headline: "security.grpc.enforcement = \"legacy\" disables per-method tier \
                           authorization.",
                detail: "Every authenticated client of a read_write listener may call every\n\
                         method up to that listener's max_tier cap, including the\n\
                         operator_only methods that reconfigure the daemon; the\n\
                         [security.grpc.roles] entries are recorded as audit context and deny\n\
                         nothing. Tier enforcement is the default since v0.24.0 and becomes\n\
                         mandatory in a future release, which will reject this config.\n\
                         \n\
                         To migrate: give every listener a role identity — mTLS listeners\n\
                         derive it from the client certificate, bearer-token TCP and UDS\n\
                         listeners need an explicit `principal` — map each principal in\n\
                         [security.grpc.roles] to observer, automation, or operator, then set\n\
                         security.grpc.enforcement = \"tier\". See\n\
                         docs/adr/0064-grpc-authorization.md and docs/SECURITY.md.",
            });
        }

        advisories
    }
}

impl Config {
    /// Reject the literal `<redacted>` placeholder that `rbgp config
    /// effective` emits in place of secret material. A dumped config that
    /// still carries the placeholder must fail loudly at load instead of
    /// silently booting with `<redacted>` as a live credential.
    fn validate_no_redacted_secrets(&self) -> Result<(), ConfigError> {
        let placeholder_error = |address: &str, field: &str| ConfigError::InvalidNeighborConfig {
            address: address.to_string(),
            field: field.to_string(),
            reason: format!(
                "is the literal {:?} placeholder emitted by `rbgp config effective`; \
                 restore the real secret before loading this config",
                super::REDACTED_SECRET
            ),
        };
        for neighbor in &self.neighbors {
            if neighbor.md5_password.as_deref() == Some(super::REDACTED_SECRET) {
                return Err(placeholder_error(&neighbor.address, "md5_password"));
            }
            if neighbor
                .tcp_ao
                .as_ref()
                .is_some_and(|tcp_ao| tcp_ao.iter().any(|key| key.key == super::REDACTED_SECRET))
            {
                return Err(placeholder_error(&neighbor.address, "tcp_ao.key"));
            }
        }
        for range in &self.dynamic_neighbors {
            if range
                .tcp_ao
                .as_ref()
                .is_some_and(|tcp_ao| tcp_ao.iter().any(|key| key.key == super::REDACTED_SECRET))
            {
                return Err(placeholder_error(
                    &format!("dynamic_neighbors.{}", range.prefix),
                    "tcp_ao.key",
                ));
            }
        }
        for (name, group) in &self.peer_groups {
            if group.md5_password.as_deref() == Some(super::REDACTED_SECRET) {
                return Err(placeholder_error(
                    &format!("peer_groups.{name}"),
                    "md5_password",
                ));
            }
        }
        Ok(())
    }
}

/// Refuse the two ADR-0112 reserved chain names to operator policies.
///
/// The reserved deny is built directly rather than resolved from the catalog,
/// so enforcement never depended on this. The *reporting* surfaces do: neighbor
/// status identifies a denied direction by comparing the installed chain
/// against the reserved deny, and import/export explain attribute a rejection
/// by the deciding chain member's name. Both are only unambiguous while no
/// operator policy can carry either name — which is what ADR-0112 means by a
/// chain that "cannot be referenced or shadowed by a configured name".
///
/// `.rpol` policies share one namespace with `[policy.definitions]`, so the
/// compiled registry is checked too.
fn validate_reserved_policy_names(config: &Config) -> Result<(), ConfigError> {
    let toml_names = config.policy.definitions.keys();
    let rpol_names = config.policy.rpol.policies.keys();
    for name in toml_names.chain(rpol_names) {
        if rustbgpd_policy::is_rfc8212_reserved_policy_name(name) {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!(
                    "policy name {name:?} is reserved for the RFC 8212 internal deny chain \
                     (ADR-0112) and cannot be defined by an operator policy; rename it"
                ),
            });
        }
    }
    Ok(())
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
    validate_managed_svd_vxlans(config, &managed.svd_vxlans, owner_token, &mut names)?;
    validate_managed_vrfs(&managed.vrfs, owner_token, &mut names)?;
    validate_managed_l3vxlans(&managed.l3vxlans, owner_token, &mut names)?;
    validate_managed_vlan_uppers(config, &managed.vlan_uppers, owner_token, &mut names)?;

    // Cross-section checks need both `config` and `managed`, so they live here
    // rather than in the per-section validators.

    // A managed VRF must not claim a `[[fib_tables]]` table_id: both would
    // install routes into the same kernel table under conflicting ownership.
    let fib_table_ids: HashSet<u32> = config.fib_tables.iter().map(|t| t.table_id).collect();
    for vrf in &managed.vrfs {
        if fib_table_ids.contains(&vrf.table_id) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed VRF {:?}: table_id {} collides with a [[fib_tables]] table_id",
                    vrf.name, vrf.table_id
                ),
            });
        }
    }

    // Fixed-VNI and SVD VXLAN lifecycle rows both own L2VNI dataplane
    // topology, so one VNI must not be managed by both paths. L3VXLAN `vni`
    // (the L3VNI) must also stay distinct from every L2VNI.
    let fixed_vxlan_vnis: HashSet<u32> = managed.vxlans.iter().map(|v| v.vni).collect();
    let mut vxlan_vnis = fixed_vxlan_vnis.clone();
    for svd in &managed.svd_vxlans {
        for inst in config.evpn_instances.iter().filter(|inst| {
            inst.bridge.as_deref() == Some(svd.bridge.as_str()) && inst.bridge_vlan.is_some()
        }) {
            if fixed_vxlan_vnis.contains(&inst.vni) {
                return Err(ConfigError::InvalidManagedNetdev {
                    reason: format!(
                        "managed SVD VXLAN {:?}: derived VNI {} collides with a \
                         [[managed_netdevs.vxlans]] vni; fixed-VNI and SVD lifecycle \
                         rows must not manage the same L2VNI",
                        svd.name, inst.vni
                    ),
                });
            }
            vxlan_vnis.insert(inst.vni);
        }
    }
    for l3vxlan in &managed.l3vxlans {
        if vxlan_vnis.contains(&l3vxlan.vni) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed L3VXLAN {:?}: vni {} (L3VNI) collides with a \
                     [[managed_netdevs.vxlans]] vni (L2VNI); they must be distinct",
                    l3vxlan.name, l3vxlan.vni
                ),
            });
        }
    }
    validate_managed_l3vxlan_vrf_references(managed)?;
    validate_managed_ip_vrf_bindings(config)?;

    Ok(())
}

fn validate_managed_l3vxlan_vrf_references(
    managed: &ManagedNetdevsConfig,
) -> Result<(), ConfigError> {
    let managed_vrfs: HashSet<&str> = managed.vrfs.iter().map(|vrf| vrf.name.as_str()).collect();
    for l3vxlan in &managed.l3vxlans {
        if !managed_vrfs.contains(l3vxlan.vrf.as_str()) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed L3VXLAN {:?}: vrf {:?} must reference a configured [[managed_netdevs.vrfs]] row",
                    l3vxlan.name, l3vxlan.vrf
                ),
            });
        }
    }
    Ok(())
}

fn validate_managed_ip_vrf_bindings(config: &Config) -> Result<(), ConfigError> {
    let managed_vrfs: HashMap<&str, &ManagedVrfNetdevConfig> = config
        .managed_netdevs
        .vrfs
        .iter()
        .map(|vrf| (vrf.name.as_str(), vrf))
        .collect();
    let managed_l3vxlans: HashMap<&str, &ManagedL3VxlanNetdevConfig> = config
        .managed_netdevs
        .l3vxlans
        .iter()
        .map(|l3vxlan| (l3vxlan.name.as_str(), l3vxlan))
        .collect();

    for ip_vrf in &config.evpn_ip_vrfs {
        if let Some(vrf) = managed_vrfs.get(ip_vrf.vrf_device.as_str())
            && vrf.table_id != ip_vrf.table_id
        {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "evpn_ip_vrfs[{}]: managed VRF {:?} table_id {} does not match IP-VRF table_id {}",
                    ip_vrf.name, vrf.name, vrf.table_id, ip_vrf.table_id
                ),
            });
        }

        let Some(l3vxlan) = managed_l3vxlans.get(ip_vrf.l3vxlan_device.as_str()) else {
            continue;
        };
        if l3vxlan.vrf != ip_vrf.vrf_device {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "evpn_ip_vrfs[{}]: managed L3VXLAN {:?} vrf {:?} does not match IP-VRF vrf_device {:?}",
                    ip_vrf.name, l3vxlan.name, l3vxlan.vrf, ip_vrf.vrf_device
                ),
            });
        }
        if l3vxlan.vni != ip_vrf.vni {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "evpn_ip_vrfs[{}]: managed L3VXLAN {:?} vni {} does not match IP-VRF vni {}",
                    ip_vrf.name, l3vxlan.name, l3vxlan.vni, ip_vrf.vni
                ),
            });
        }
        let local_vtep_ip = ip_vrf
            .local_vtep_ip
            .parse::<std::net::IpAddr>()
            .map_err(|e| ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "evpn_ip_vrfs[{}]: invalid local_vtep_ip {:?}: {e}",
                    ip_vrf.name, ip_vrf.local_vtep_ip
                ),
            })?;
        if l3vxlan.local != local_vtep_ip {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "evpn_ip_vrfs[{}]: managed L3VXLAN {:?} local {} does not match IP-VRF local_vtep_ip {}",
                    ip_vrf.name, l3vxlan.name, l3vxlan.local, ip_vrf.local_vtep_ip
                ),
            });
        }
        let ip_vrf_router_mac = parse_mac_address(&ip_vrf.router_mac).map_err(|e| {
            ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "evpn_ip_vrfs[{}]: invalid router_mac {:?}: {e}",
                    ip_vrf.name, ip_vrf.router_mac
                ),
            }
        })?;
        let managed_router_mac = parse_mac_address(&l3vxlan.router_mac).map_err(|e| {
            ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed L3VXLAN {:?}: invalid router_mac {:?}: {e}",
                    l3vxlan.name, l3vxlan.router_mac
                ),
            }
        })?;
        if managed_router_mac != ip_vrf_router_mac {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "evpn_ip_vrfs[{}]: managed L3VXLAN {:?} router_mac {:?} does not match IP-VRF router_mac {:?}",
                    ip_vrf.name, l3vxlan.name, l3vxlan.router_mac, ip_vrf.router_mac
                ),
            });
        }
    }
    Ok(())
}

fn managed_netdevs_has_rows(managed: &ManagedNetdevsConfig) -> bool {
    !managed.bridges.is_empty()
        || !managed.vxlans.is_empty()
        || !managed.svd_vxlans.is_empty()
        || !managed.vrfs.is_empty()
        || !managed.l3vxlans.is_empty()
        || !managed.vlan_uppers.is_empty()
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

fn validate_managed_svd_vxlans(
    config: &Config,
    svd_vxlans: &[ManagedSvdVxlanNetdevConfig],
    owner_token: &str,
    names: &mut HashSet<String>,
) -> Result<(), ConfigError> {
    let mut seen_bridges = HashSet::new();
    for svd in svd_vxlans {
        validate_managed_link_name(&svd.name)?;
        validate_managed_link_name(&svd.bridge)?;
        if !names.insert(svd.name.clone()) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!("duplicate managed netdev name {:?}", svd.name),
            });
        }
        if !seen_bridges.insert(svd.bridge.clone()) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed SVD VXLAN {:?}: duplicate bridge {:?}",
                    svd.name, svd.bridge
                ),
            });
        }
        if svd.dstport == 0 {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed SVD VXLAN {:?}: dstport must be in 1..=65535",
                    svd.name
                ),
            });
        }
        if svd.learning {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed SVD VXLAN {:?}: learning=true is unsupported; use learning=false (`nolearning`)",
                    svd.name
                ),
            });
        }
        let mut bindings: HashMap<u16, u32> = HashMap::new();
        for inst in config
            .evpn_instances
            .iter()
            .filter(|inst| inst.bridge.as_deref() == Some(svd.bridge.as_str()))
        {
            let Some(vlan) = inst.bridge_vlan else {
                continue;
            };
            let vlan = u16::try_from(vlan).map_err(|_| ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed SVD VXLAN {:?}: bridge {:?} instance VNI {} has invalid bridge_vlan {}",
                    svd.name, svd.bridge, inst.vni, vlan
                ),
            })?;
            if let Some(&existing) = bindings.get(&vlan) {
                if existing != inst.vni {
                    return Err(ConfigError::InvalidManagedNetdev {
                        reason: format!(
                            "managed SVD VXLAN {:?}: bridge {:?} bridge_vlan {} maps to conflicting VNIs {} and {}; each VLAN must map to exactly one VNI",
                            svd.name, svd.bridge, vlan, existing, inst.vni
                        ),
                    });
                }
            } else {
                bindings.insert(vlan, inst.vni);
            }
        }
        if bindings.is_empty() {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed SVD VXLAN {:?}: bridge {:?} must match at least one [[evpn_instances]] row with bridge_vlan",
                    svd.name, svd.bridge
                ),
            });
        }
        validate_managed_stamp_len(
            "managed SVD VXLAN",
            &svd.name,
            &rustbgpd_evpn::svd_vxlan_ownership_stamp(owner_token, &svd.name),
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
        if matches!(vrf.table_id, 252..=255) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed VRF {:?}: table_id {} is reserved (252-255: compat/default/main/local)",
                    vrf.name, vrf.table_id
                ),
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

fn validate_managed_vlan_uppers(
    config: &Config,
    vlan_uppers: &[ManagedVlanUpperNetdevConfig],
    owner_token: &str,
    names: &mut HashSet<String>,
) -> Result<(), ConfigError> {
    let evpn_bridge_vlans: HashSet<(&str, u16)> = config
        .evpn_instances
        .iter()
        .filter_map(|instance| {
            let bridge = instance.bridge.as_deref()?;
            let vlan = u16::try_from(instance.bridge_vlan?).ok()?;
            Some((bridge, vlan))
        })
        .collect();
    let mut seen_bindings = HashSet::new();
    for vlan_upper in vlan_uppers {
        validate_managed_link_name(&vlan_upper.name)?;
        validate_managed_link_name(&vlan_upper.bridge)?;
        if !names.insert(vlan_upper.name.clone()) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!("duplicate managed netdev name {:?}", vlan_upper.name),
            });
        }
        if !(1..=4094).contains(&vlan_upper.vlan) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed VLAN upper {:?}: vlan {} must be in 1..=4094",
                    vlan_upper.name, vlan_upper.vlan
                ),
            });
        }
        if !seen_bindings.insert((vlan_upper.bridge.clone(), vlan_upper.vlan)) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed VLAN upper {:?}: duplicate bridge/vlan binding {}:{}",
                    vlan_upper.name, vlan_upper.bridge, vlan_upper.vlan
                ),
            });
        }
        if !evpn_bridge_vlans.contains(&(vlan_upper.bridge.as_str(), vlan_upper.vlan)) {
            return Err(ConfigError::InvalidManagedNetdev {
                reason: format!(
                    "managed VLAN upper {:?}: bridge {:?} vlan {} must match a configured [[evpn_instances]] bridge + bridge_vlan binding",
                    vlan_upper.name, vlan_upper.bridge, vlan_upper.vlan
                ),
            });
        }
        validate_managed_stamp_len(
            "managed VLAN upper",
            &vlan_upper.name,
            &rustbgpd_evpn::vlan_upper_ownership_stamp(owner_token, &vlan_upper.name),
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

fn validate_tcp_ao_config(address: &str, tcp_ao: &TcpAoKeyringConfig) -> Result<(), ConfigError> {
    if tcp_ao.is_empty() || tcp_ao.len() > 256 {
        return Err(ConfigError::InvalidNeighborConfig {
            address: address.to_string(),
            field: "tcp_ao".to_string(),
            reason: "must contain 1..=256 keys".to_string(),
        });
    }
    let mut send_ids = HashSet::new();
    let mut recv_ids = HashSet::new();
    let mut preferred = 0usize;
    let mut nondeprecated = 0usize;
    for key in tcp_ao {
        validate_tcp_ao_key(address, key)?;
        if !send_ids.insert(key.send_id) {
            return Err(ConfigError::InvalidNeighborConfig {
                address: address.to_string(),
                field: "tcp_ao.send_id".to_string(),
                reason: format!("duplicate SendID {}", key.send_id),
            });
        }
        if !recv_ids.insert(key.recv_id) {
            return Err(ConfigError::InvalidNeighborConfig {
                address: address.to_string(),
                field: "tcp_ao.recv_id".to_string(),
                reason: format!("duplicate RecvID {}", key.recv_id),
            });
        }
        preferred += usize::from(key.preferred);
        nondeprecated += usize::from(!key.deprecated);
    }
    if preferred > 1 {
        return Err(ConfigError::InvalidNeighborConfig {
            address: address.to_string(),
            field: "tcp_ao.preferred".to_string(),
            reason: "at most one key may be preferred".to_string(),
        });
    }
    if nondeprecated == 0 {
        return Err(ConfigError::InvalidNeighborConfig {
            address: address.to_string(),
            field: "tcp_ao.deprecated".to_string(),
            reason: "at least one key must not be deprecated".to_string(),
        });
    }
    Ok(())
}

fn validate_tcp_ao_listener_capacity(
    config: &Config,
    parsed_dynamic_prefixes: &[(IpAddr, u8)],
) -> Result<(), ConfigError> {
    let mut ipv4_keys = 0usize;
    let mut ipv6_keys = 0usize;
    for neighbor in &config.neighbors {
        let Some(tcp_ao) = &neighbor.tcp_ao else {
            continue;
        };
        let address = neighbor
            .address
            .parse::<IpAddr>()
            .expect("neighbor addresses were validated before TCP-AO capacity");
        let count = if address.is_ipv4() {
            &mut ipv4_keys
        } else {
            &mut ipv6_keys
        };
        *count =
            count
                .checked_add(tcp_ao.len())
                .ok_or_else(|| ConfigError::InvalidNeighborConfig {
                    address: "BGP listener".to_string(),
                    field: "tcp_ao".to_string(),
                    reason: "aggregate TCP-AO listener key count overflow".to_string(),
                })?;
    }
    for (range, (address, _prefix_len)) in
        config.dynamic_neighbors.iter().zip(parsed_dynamic_prefixes)
    {
        let Some(tcp_ao) = &range.tcp_ao else {
            continue;
        };
        let count = if address.is_ipv4() {
            &mut ipv4_keys
        } else {
            &mut ipv6_keys
        };
        *count =
            count
                .checked_add(tcp_ao.len())
                .ok_or_else(|| ConfigError::InvalidNeighborConfig {
                    address: "BGP listener".to_string(),
                    field: "tcp_ao".to_string(),
                    reason: "aggregate TCP-AO listener key count overflow".to_string(),
                })?;
    }

    for (family, key_count) in [("IPv4", ipv4_keys), ("IPv6", ipv6_keys)] {
        if key_count > TCP_AO_MAX_INSPECT_KEYS {
            return Err(ConfigError::InvalidNeighborConfig {
                address: format!("{family} BGP listener"),
                field: "tcp_ao".to_string(),
                reason: format!(
                    "aggregate key count {key_count} exceeds accepted-socket inspection limit \
                     {TCP_AO_MAX_INSPECT_KEYS}"
                ),
            });
        }
    }
    Ok(())
}

fn tcp_ao_overlap_id_collision(
    left: &TcpAoKeyringConfig,
    right: &TcpAoKeyringConfig,
) -> Option<&'static str> {
    let right_send = right.iter().map(|key| key.send_id).collect::<HashSet<_>>();
    if left.iter().any(|key| right_send.contains(&key.send_id)) {
        return Some("SendID");
    }
    let right_recv = right.iter().map(|key| key.recv_id).collect::<HashSet<_>>();
    if left.iter().any(|key| right_recv.contains(&key.recv_id)) {
        return Some("RecvID");
    }
    None
}

fn validate_tcp_ao_key(address: &str, tcp_ao: &TcpAoConfig) -> Result<(), ConfigError> {
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
#[expect(
    clippy::too_many_arguments,
    reason = "mirrors resolve_chain's namespace threading"
)]
fn validate_peer_group(
    name: &str,
    group: &PeerGroupConfig,
    definitions: &std::collections::HashMap<String, super::NamedPolicyConfig>,
    rpol: &rustbgpd_policy::rpol::RpolPolicySet,
    datasets: &rustbgpd_policy::datasets::DatasetBindings,
    neighbor_sets: &std::collections::HashMap<String, super::NeighborSetConfig>,
    peer_groups: &std::collections::HashMap<String, PeerGroupConfig>,
    local_asn: u32,
) -> Result<(), ConfigError> {
    let hold_time = group.hold_time.unwrap_or(DEFAULT_HOLD_TIME);
    if hold_time != 0 && hold_time < 3 {
        return Err(ConfigError::InvalidHoldTime { value: hold_time });
    }
    if let Some(minimum) = group.min_hold_time {
        if minimum < 3 {
            return Err(ConfigError::InvalidMinHoldTime { value: minimum });
        }
        if hold_time == 0 || minimum > hold_time {
            return Err(ConfigError::InvalidMinHoldTimeForHoldTime { minimum, hold_time });
        }
    }

    // RFC 9687 §4.4 on the group's own values; neighbor-effective
    // combinations are re-checked per neighbor.
    if let Some(value) = group.send_hold_time
        && value != 0
        && value <= u32::from(hold_time)
    {
        return Err(ConfigError::InvalidSendHoldTime { value, hold_time });
    }

    if !group.families.is_empty() {
        parse_families(&group.families)?;
    }
    if !group.required_families.is_empty() {
        let required = parse_families(&group.required_families)?;
        // A group with no configured families has no address-dependent
        // default until it is consumed; validate those effective consumers
        // above instead of rejecting an otherwise reusable definition.
        if !group.families.is_empty() {
            let mut effective = parse_families(&group.families)?;
            if group.disable_ipv4_unicast.unwrap_or(false) {
                effective.retain(|family| {
                    *family != (rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::Unicast)
                });
            }
            if let Some(missing) = required.iter().find(|family| !effective.contains(family)) {
                return Err(ConfigError::InvalidNeighborConfig {
                    address: format!("peer_group.{name}"),
                    field: "required_families".to_string(),
                    reason: format!(
                        "required family {:?}/{:?} is not in the configured family set",
                        missing.0, missing.1
                    ),
                });
            }
        }
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
    if let Some(t) = group.gr_peer_restart_time_max
        && t == 0
    {
        return Err(ConfigError::InvalidGrConfig {
            reason: format!("peer_group {name:?}: gr_peer_restart_time_max must be > 0"),
        });
    }
    if let Some(t) = group.gr_peer_restart_time_max
        && t > 4095
    {
        return Err(ConfigError::InvalidGrConfig {
            reason: format!(
                "peer_group {name:?}: gr_peer_restart_time_max {t} exceeds 4095 (12-bit max)"
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
        rpol,
        datasets,
        neighbor_sets,
        peer_groups,
        ChainDirection::Import,
        local_asn,
    )?;
    resolve_chain(
        &group.export_policy_chain,
        definitions,
        rpol,
        datasets,
        neighbor_sets,
        peer_groups,
        ChainDirection::Export,
        local_asn,
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
