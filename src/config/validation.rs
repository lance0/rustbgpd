use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::parse::{parse_families, parse_named_policy, parse_policy, resolve_chain};
use super::{Config, ConfigError, DEFAULT_HOLD_TIME};

impl Config {
    #[expect(clippy::too_many_lines)]
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
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

        // Validate prometheus_addr is a valid SocketAddr
        self.global
            .telemetry
            .prometheus_addr
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::InvalidPrometheusAddr {
                value: self.global.telemetry.prometheus_addr.clone(),
                reason: e.to_string(),
            })?;

        // Validate grpc_addr is a valid SocketAddr
        self.global
            .telemetry
            .grpc_addr
            .parse::<SocketAddr>()
            .map_err(|e| ConfigError::InvalidGrpcAddr {
                value: self.global.telemetry.grpc_addr.clone(),
                reason: e.to_string(),
            })?;

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
        parse_policy(&self.policy.import)?;
        parse_policy(&self.policy.export)?;

        // Validate named policy definitions
        for (name, cfg) in &self.policy.definitions {
            parse_named_policy(name, cfg)?;
        }

        // Validate global chains
        resolve_chain(&self.policy.import_chain, &self.policy.definitions)?;
        resolve_chain(&self.policy.export_chain, &self.policy.definitions)?;

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
            let hold_time = neighbor.hold_time.unwrap_or(DEFAULT_HOLD_TIME);
            if hold_time != 0 && hold_time < 3 {
                return Err(ConfigError::InvalidHoldTime { value: hold_time });
            }

            // Validate route_reflector_client: must be iBGP
            if neighbor.route_reflector_client && neighbor.remote_asn != self.global.asn {
                return Err(ConfigError::InvalidRrConfig {
                    reason: format!(
                        "route_reflector_client requires iBGP (remote_asn {} != local asn {})",
                        neighbor.remote_asn, self.global.asn
                    ),
                });
            }

            if neighbor.route_server_client && neighbor.remote_asn == self.global.asn {
                return Err(ConfigError::InvalidRouteServerConfig {
                    reason: format!(
                        "route_server_client requires eBGP (remote_asn {} == local asn {})",
                        neighbor.remote_asn, self.global.asn
                    ),
                });
            }

            if let Some(ref mode) = neighbor.remove_private_as {
                match mode.as_str() {
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
            }

            // Validate GR config
            let gr_enabled = neighbor.graceful_restart.unwrap_or(true);
            if let Some(t) = neighbor.gr_restart_time
                && t > 4095
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: format!("gr_restart_time {t} exceeds 4095 (12-bit max)"),
                });
            }
            if let Some(0) = neighbor.gr_restart_time
                && gr_enabled
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: "gr_restart_time must be > 0 when graceful_restart is enabled"
                        .to_string(),
                });
            }
            if let Some(t) = neighbor.gr_stale_routes_time
                && t == 0
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: "gr_stale_routes_time must be > 0".to_string(),
                });
            }
            if let Some(t) = neighbor.gr_stale_routes_time
                && t > 3600
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: format!("gr_stale_routes_time {t} exceeds 3600 (1 hour max)"),
                });
            }
            if let Some(t) = neighbor.llgr_stale_time
                && t > 16_777_215
            {
                return Err(ConfigError::InvalidGrConfig {
                    reason: format!("llgr_stale_time {t} exceeds 16777215 (24-bit max)"),
                });
            }

            // Validate local_ipv6_nexthop if configured
            if let Some(ref nh) = neighbor.local_ipv6_nexthop {
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

            parse_policy(&neighbor.import_policy)?;
            parse_policy(&neighbor.export_policy)?;

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
            resolve_chain(&neighbor.import_policy_chain, &self.policy.definitions)?;
            resolve_chain(&neighbor.export_policy_chain, &self.policy.definitions)?;
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
