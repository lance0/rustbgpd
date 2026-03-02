use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::{PolicyAction, PrefixList, PrefixListEntry, parse_community_match};
use rustbgpd_transport::TransportConfig;
use rustbgpd_wire::{Afi, Ipv4Prefix, Ipv6Prefix, Prefix, Safi};
use serde::Deserialize;

const DEFAULT_HOLD_TIME: u16 = 90;
const DEFAULT_CONNECT_RETRY_SECS: u32 = 30;
const BGP_PORT: u16 = 179;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub global: Global,
    #[serde(default)]
    pub neighbors: Vec<Neighbor>,
    #[serde(default)]
    pub policy: PolicyConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Global {
    pub asn: u32,
    pub router_id: String,
    pub listen_port: u16,
    pub telemetry: TelemetryConfig,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    pub prometheus_addr: String,
    #[expect(dead_code)] // parsed from config, only "json" in M0
    pub log_format: String,
    #[serde(default = "default_grpc_addr")]
    pub grpc_addr: String,
}

fn default_grpc_addr() -> String {
    "127.0.0.1:50051".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Neighbor {
    pub address: String,
    pub remote_asn: u32,
    pub description: Option<String>,
    pub hold_time: Option<u16>,
    pub max_prefixes: Option<u32>,
    pub md5_password: Option<String>,
    #[serde(default)]
    pub ttl_security: bool,
    /// Address families to negotiate (e.g., `["ipv4_unicast", "ipv6_unicast"]`).
    /// Default: `["ipv4_unicast"]`. If the neighbor address is IPv6, `"ipv6_unicast"`
    /// is also included by default.
    #[serde(default)]
    pub families: Vec<String>,
    /// Enable Graceful Restart (RFC 4724). Default: true.
    pub graceful_restart: Option<bool>,
    /// Restart time advertised in GR capability (seconds, max 4095). Default: 120.
    pub gr_restart_time: Option<u16>,
    /// Time to retain stale routes after peer restart (seconds). Default: 360.
    pub gr_stale_routes_time: Option<u64>,
    /// Explicit IPv6 next-hop for eBGP advertisements when the TCP session
    /// is IPv4. If not set, the local IPv6 socket address is used (if
    /// available); otherwise IPv6 routes are suppressed for this peer.
    pub local_ipv6_nexthop: Option<String>,
    #[serde(default)]
    pub import_policy: Vec<PrefixListEntryConfig>,
    #[serde(default)]
    pub export_policy: Vec<PrefixListEntryConfig>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub import: Vec<PrefixListEntryConfig>,
    #[serde(default)]
    pub export: Vec<PrefixListEntryConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixListEntryConfig {
    pub action: String,
    /// CIDR prefix to match. Optional when `match_community` is set.
    pub prefix: Option<String>,
    pub ge: Option<u8>,
    pub le: Option<u8>,
    /// Community match criteria, e.g. `["65001:100"]`, `["RT:65001:100"]`,
    /// or `["NO_EXPORT"]`.
    #[serde(default)]
    pub match_community: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("invalid router_id {value:?}: {reason}")]
    InvalidRouterId { value: String, reason: String },
    #[error("invalid neighbor address {value:?}: {reason}")]
    InvalidNeighborAddress { value: String, reason: String },
    #[error("invalid prometheus_addr {value:?}: {reason}")]
    InvalidPrometheusAddr { value: String, reason: String },
    #[error("invalid grpc_addr {value:?}: {reason}")]
    InvalidGrpcAddr { value: String, reason: String },
    #[error("invalid hold_time {value}: must be 0 or >= 3")]
    InvalidHoldTime { value: u16 },
    #[error("invalid policy entry: {reason}")]
    InvalidPolicyEntry { reason: String },
    #[error("invalid local_ipv6_nexthop {value:?}: {reason}")]
    InvalidLocalIpv6Nexthop { value: String, reason: String },
    #[error("invalid graceful restart config: {reason}")]
    InvalidGrConfig { reason: String },
}

/// Parse and validate a single CIDR prefix string with optional ge/le bounds.
fn parse_prefix_entry(
    prefix_str: &str,
    ge: Option<u8>,
    le: Option<u8>,
) -> Result<Prefix, ConfigError> {
    let parts: Vec<&str> = prefix_str.split('/').collect();
    if parts.len() != 2 {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: format!(
                "invalid prefix {prefix_str:?}, expected CIDR notation (e.g. 10.0.0.0/8 or 2001:db8::/32)"
            ),
        });
    }
    let len: u8 = parts[1]
        .parse()
        .map_err(|_| ConfigError::InvalidPolicyEntry {
            reason: format!("invalid prefix length in {prefix_str:?}"),
        })?;

    let (prefix, max_len) = if let Ok(v4) = parts[0].parse::<Ipv4Addr>() {
        if len > 32 {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("prefix length {len} exceeds 32 in {prefix_str:?}"),
            });
        }
        (Prefix::V4(Ipv4Prefix::new(v4, len)), 32u8)
    } else if let Ok(v6) = parts[0].parse::<Ipv6Addr>() {
        if len > 128 {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("prefix length {len} exceeds 128 in {prefix_str:?}"),
            });
        }
        (Prefix::V6(Ipv6Prefix::new(v6, len)), 128u8)
    } else {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: format!("invalid address in prefix {prefix_str:?}"),
        });
    };

    if let Some(ge) = ge {
        if ge > max_len {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("ge value {ge} exceeds {max_len} in {prefix_str:?}"),
            });
        }
        if ge < len {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("ge value {ge} is less than prefix length {len} in {prefix_str:?}"),
            });
        }
    }
    if let Some(le) = le
        && le > max_len
    {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: format!("le value {le} exceeds {max_len} in {prefix_str:?}"),
        });
    }
    if let (Some(ge), Some(le)) = (ge, le)
        && ge > le
    {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: format!("ge value {ge} exceeds le value {le} in {prefix_str:?}"),
        });
    }
    Ok(prefix)
}

fn parse_prefix_list(entries: &[PrefixListEntryConfig]) -> Result<Option<PrefixList>, ConfigError> {
    if entries.is_empty() {
        return Ok(None);
    }
    let mut parsed = Vec::with_capacity(entries.len());
    for e in entries {
        let action = match e.action.as_str() {
            "permit" => PolicyAction::Permit,
            "deny" => PolicyAction::Deny,
            other => {
                return Err(ConfigError::InvalidPolicyEntry {
                    reason: format!("unknown action {other:?}, expected \"permit\" or \"deny\""),
                });
            }
        };

        let match_community: Vec<_> = e
            .match_community
            .iter()
            .map(|s| {
                parse_community_match(s)
                    .map_err(|reason| ConfigError::InvalidPolicyEntry { reason })
            })
            .collect::<Result<_, _>>()?;

        let prefix = if let Some(ref prefix_str) = e.prefix {
            Some(parse_prefix_entry(prefix_str, e.ge, e.le)?)
        } else {
            if e.ge.is_some() || e.le.is_some() {
                return Err(ConfigError::InvalidPolicyEntry {
                    reason: "ge/le cannot be set without a prefix".to_string(),
                });
            }
            None
        };

        if prefix.is_none() && match_community.is_empty() {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: "entry must have at least one of 'prefix' or 'match_community'".to_string(),
            });
        }

        parsed.push(PrefixListEntry {
            prefix,
            ge: e.ge,
            le: e.le,
            action,
            match_community,
        });
    }

    Ok(Some(PrefixList {
        entries: parsed,
        default_action: PolicyAction::Permit,
    }))
}

/// Parse a list of address family strings into `(Afi, Safi)` pairs.
fn parse_families(families: &[String]) -> Result<Vec<(Afi, Safi)>, ConfigError> {
    let mut result = Vec::with_capacity(families.len());
    for f in families {
        let family = match f.as_str() {
            "ipv4_unicast" => (Afi::Ipv4, Safi::Unicast),
            "ipv6_unicast" => (Afi::Ipv6, Safi::Unicast),
            other => {
                return Err(ConfigError::InvalidPolicyEntry {
                    reason: format!(
                        "unknown address family {other:?}, expected \"ipv4_unicast\" or \"ipv6_unicast\""
                    ),
                });
            }
        };
        if !result.contains(&family) {
            result.push(family);
        }
    }
    Ok(result)
}

impl Config {
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        // Validate router_id is a valid IPv4
        self.global
            .router_id
            .parse::<Ipv4Addr>()
            .map_err(|e| ConfigError::InvalidRouterId {
                value: self.global.router_id.clone(),
                reason: e.to_string(),
            })?;

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

        // Eagerly validate all policies at load time
        parse_prefix_list(&self.policy.import)?;
        parse_prefix_list(&self.policy.export)?;

        for neighbor in &self.neighbors {
            neighbor.address.parse::<IpAddr>().map_err(|e| {
                ConfigError::InvalidNeighborAddress {
                    value: neighbor.address.clone(),
                    reason: e.to_string(),
                }
            })?;

            let hold_time = neighbor.hold_time.unwrap_or(DEFAULT_HOLD_TIME);
            if hold_time != 0 && hold_time < 3 {
                return Err(ConfigError::InvalidHoldTime { value: hold_time });
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

            parse_prefix_list(&neighbor.import_policy)?;
            parse_prefix_list(&neighbor.export_policy)?;
        }

        Ok(())
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

    pub fn grpc_addr(&self) -> SocketAddr {
        self.global
            .telemetry
            .grpc_addr
            .parse()
            .expect("validated in Config::load")
    }

    pub fn import_policy(&self) -> Result<Option<PrefixList>, ConfigError> {
        parse_prefix_list(&self.policy.import)
    }

    pub fn export_policy(&self) -> Result<Option<PrefixList>, ConfigError> {
        parse_prefix_list(&self.policy.export)
    }

    /// Returns `(TransportConfig, label, import_policy, export_policy)` per neighbor.
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
            Option<PrefixList>,
            Option<PrefixList>,
        )>,
        ConfigError,
    > {
        let router_id: Ipv4Addr = self
            .global
            .router_id
            .parse()
            .expect("validated in Config::load");

        let global_import = self.import_policy()?;
        let global_export = self.export_policy()?;

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

            let label = neighbor
                .description
                .clone()
                .unwrap_or_else(|| neighbor.address.clone());

            // Per-neighbor policy overrides global
            let import = parse_prefix_list(&neighbor.import_policy)?.or(global_import.clone());
            let export = parse_prefix_list(&neighbor.export_policy)?.or(global_export.clone());

            configs.push((transport, label, import, export));
        }
        Ok(configs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_toml() -> &'static str {
        r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-1"
hold_time = 90
"#
    }

    fn parse(toml_str: &str) -> Result<Config, ConfigError> {
        let config: Config = toml::from_str(toml_str).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    #[test]
    fn valid_config_parses() {
        let config = parse(valid_toml()).unwrap();
        assert_eq!(config.global.asn, 65001);
        assert_eq!(config.neighbors.len(), 1);
        assert_eq!(config.neighbors[0].remote_asn, 65002);
    }

    #[test]
    fn invalid_router_id_rejected() {
        let toml_str = valid_toml().replace("10.0.0.1", "not-an-ip");
        let err = parse(&toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRouterId { .. }));
    }

    #[test]
    fn invalid_neighbor_address_rejected() {
        let toml_str = valid_toml().replace("10.0.0.2", "bad-addr");
        let err = parse(&toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidNeighborAddress { .. }));
    }

    #[test]
    fn no_neighbors_accepted() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
        let config = parse(toml_str).unwrap();
        assert!(config.neighbors.is_empty());
    }

    #[test]
    fn hold_time_one_rejected() {
        let toml_str = valid_toml().replace("hold_time = 90", "hold_time = 1");
        let err = parse(&toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidHoldTime { value: 1 }));
    }

    #[test]
    fn hold_time_zero_accepted() {
        let toml_str = valid_toml().replace("hold_time = 90", "hold_time = 0");
        let config = parse(&toml_str).unwrap();
        assert_eq!(config.neighbors[0].hold_time, Some(0));
    }

    #[test]
    fn default_hold_time_applied() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
        let config = parse(toml_str).unwrap();
        assert_eq!(config.neighbors[0].hold_time, None);

        let peers = config.to_peer_configs().unwrap();
        assert_eq!(peers[0].0.peer.hold_time, 90);
    }

    #[test]
    fn to_peer_configs_maps_correctly() {
        let config = parse(valid_toml()).unwrap();
        let peers = config.to_peer_configs().unwrap();
        assert_eq!(peers.len(), 1);

        let (transport, label, _, _) = &peers[0];
        assert_eq!(transport.peer.local_asn, 65001);
        assert_eq!(transport.peer.remote_asn, 65002);
        assert_eq!(
            transport.remote_addr,
            "10.0.0.2:179".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(label, "peer-1");
    }

    #[test]
    fn prometheus_addr_parsed() {
        let config = parse(valid_toml()).unwrap();
        assert_eq!(
            config.prometheus_addr(),
            "0.0.0.0:9179".parse::<SocketAddr>().unwrap()
        );
    }

    #[test]
    fn neighbor_max_prefixes() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
max_prefixes = 1000
"#;
        let config = parse(toml_str).unwrap();
        assert_eq!(config.neighbors[0].max_prefixes, Some(1000));

        let peers = config.to_peer_configs().unwrap();
        assert_eq!(peers[0].0.max_prefixes, Some(1000));
    }

    #[test]
    fn neighbor_md5_and_ttl_security() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
md5_password = "secret"
ttl_security = true
"#;
        let config = parse(toml_str).unwrap();
        assert_eq!(config.neighbors[0].md5_password.as_deref(), Some("secret"));
        assert!(config.neighbors[0].ttl_security);

        let peers = config.to_peer_configs().unwrap();
        assert_eq!(peers[0].0.md5_password.as_deref(), Some("secret"));
        assert!(peers[0].0.ttl_security);
    }

    #[test]
    fn policy_config_parsed() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[policy.import]]
action = "deny"
prefix = "10.0.0.0/8"
ge = 24
le = 32

[[policy.export]]
action = "permit"
prefix = "192.168.0.0/16"
"#;
        let config = parse(toml_str).unwrap();
        let import = config.import_policy().unwrap().unwrap();
        assert_eq!(import.entries.len(), 1);
        let export = config.export_policy().unwrap().unwrap();
        assert_eq!(export.entries.len(), 1);
    }

    #[test]
    fn empty_policy_returns_none() {
        let config = parse(valid_toml()).unwrap();
        assert!(config.import_policy().unwrap().is_none());
        assert!(config.export_policy().unwrap().is_none());
    }

    #[test]
    fn multiple_neighbors() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
description = "peer-a"
hold_time = 90

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
hold_time = 180
"#;
        let config = parse(toml_str).unwrap();
        let peers = config.to_peer_configs().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0].1, "peer-a");
        assert_eq!(peers[1].1, "10.0.0.3"); // no description → address used
    }

    #[test]
    fn per_neighbor_policy_parsed() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[neighbors.import_policy]]
action = "deny"
prefix = "10.0.0.0/8"

[[neighbors.export_policy]]
action = "permit"
prefix = "192.168.0.0/16"
"#;
        let config = parse(toml_str).unwrap();
        assert_eq!(config.neighbors[0].import_policy.len(), 1);
        assert_eq!(config.neighbors[0].export_policy.len(), 1);

        let peers = config.to_peer_configs().unwrap();
        assert!(peers[0].2.is_some()); // import policy
        assert!(peers[0].3.is_some()); // export policy
    }

    #[test]
    fn per_neighbor_without_policy_falls_back_to_global() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.export]]
action = "deny"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#;
        let config = parse(toml_str).unwrap();
        assert!(config.neighbors[0].import_policy.is_empty());
        assert!(config.neighbors[0].export_policy.is_empty());

        let peers = config.to_peer_configs().unwrap();
        // Should inherit global export policy
        assert!(peers[0].2.is_none()); // no import (neither neighbor nor global)
        assert!(peers[0].3.is_some()); // export from global
    }

    #[test]
    fn ipv6_neighbor_address_accepted() {
        let toml_str = valid_toml().replace("10.0.0.2", "2001:db8::1");
        let config = parse(&toml_str).unwrap();
        assert_eq!(config.neighbors[0].address, "2001:db8::1");
    }

    #[test]
    fn ipv6_neighbor_default_families() {
        let toml_str = valid_toml().replace("10.0.0.2", "2001:db8::1");
        let config = parse(&toml_str).unwrap();
        let peers = config.to_peer_configs().unwrap();
        // IPv6 neighbor gets both IPv4 and IPv6 unicast by default
        assert_eq!(peers[0].0.peer.families.len(), 2);
        assert_eq!(peers[0].0.peer.families[0], (Afi::Ipv4, Safi::Unicast));
        assert_eq!(peers[0].0.peer.families[1], (Afi::Ipv6, Safi::Unicast));
    }

    #[test]
    fn unknown_field_in_global_rejected() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
unknown_field = true

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn unknown_field_in_neighbor_rejected() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
hold_tme = 90
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::Parse(_)));
    }

    #[test]
    fn per_neighbor_policy_overrides_global() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.export]]
action = "deny"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[neighbors.export_policy]]
action = "permit"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#;
        let config = parse(toml_str).unwrap();
        let peers = config.to_peer_configs().unwrap();

        // First neighbor: has per-neighbor export → uses that
        let export1 = peers[0].3.as_ref().unwrap();
        assert_eq!(export1.entries[0].action, PolicyAction::Permit);

        // Second neighbor: no per-neighbor → falls back to global deny
        let export2 = peers[1].3.as_ref().unwrap();
        assert_eq!(export2.entries[0].action, PolicyAction::Deny);
    }

    #[test]
    fn invalid_policy_action_rejected() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[policy.import]]
action = "allow"
prefix = "10.0.0.0/8"
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
    }

    #[test]
    fn invalid_policy_prefix_rejected() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002

[[policy.export]]
action = "deny"
prefix = "not-a-prefix"
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
    }

    #[test]
    fn policy_prefix_length_over_32_rejected() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.import]]
action = "deny"
prefix = "10.0.0.0/33"
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
    }

    #[test]
    fn policy_ge_over_32_rejected() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.import]]
action = "deny"
prefix = "10.0.0.0/8"
ge = 33
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
    }

    #[test]
    fn policy_ge_less_than_prefix_len_rejected() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.import]]
action = "deny"
prefix = "10.0.0.0/16"
ge = 8
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
    }

    #[test]
    fn policy_ge_exceeds_le_rejected() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[policy.import]]
action = "deny"
prefix = "10.0.0.0/8"
ge = 24
le = 16
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
    }

    fn neighbor_with_nexthop(nexthop: &str) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
local_ipv6_nexthop = "{nexthop}"
"#
        )
    }

    #[test]
    fn local_ipv6_nexthop_loopback_rejected() {
        let err = parse(&neighbor_with_nexthop("::1")).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidLocalIpv6Nexthop { .. }));
    }

    #[test]
    fn local_ipv6_nexthop_link_local_rejected() {
        let err = parse(&neighbor_with_nexthop("fe80::1")).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidLocalIpv6Nexthop { .. }));
    }

    #[test]
    fn local_ipv6_nexthop_multicast_rejected() {
        let err = parse(&neighbor_with_nexthop("ff02::1")).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidLocalIpv6Nexthop { .. }));
    }

    #[test]
    fn local_ipv6_nexthop_global_accepted() {
        let config = parse(&neighbor_with_nexthop("2001:db8::1")).unwrap();
        assert_eq!(
            config.neighbors[0].local_ipv6_nexthop.as_deref(),
            Some("2001:db8::1")
        );
    }

    fn gr_toml(gr_fields: &str) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
{gr_fields}
"#
        )
    }

    #[test]
    fn gr_restart_time_zero_with_gr_enabled_rejected() {
        let err = parse(&gr_toml("gr_restart_time = 0")).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidGrConfig { .. }));
    }

    #[test]
    fn gr_restart_time_zero_with_gr_disabled_accepted() {
        let toml = gr_toml("graceful_restart = false\ngr_restart_time = 0");
        assert!(parse(&toml).is_ok());
    }

    #[test]
    fn gr_stale_routes_time_exceeds_max_rejected() {
        let err = parse(&gr_toml("gr_stale_routes_time = 7200")).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidGrConfig { .. }));
    }

    #[test]
    fn gr_stale_routes_time_at_max_accepted() {
        assert!(parse(&gr_toml("gr_stale_routes_time = 3600")).is_ok());
    }

    #[test]
    fn duplicate_families_deduplicated() {
        let toml = gr_toml(
            r#"families = ["ipv4_unicast", "ipv4_unicast", "ipv6_unicast", "ipv6_unicast"]"#,
        );
        let config = parse(&toml).unwrap();
        let peers = config.to_peer_configs().unwrap();
        assert_eq!(peers[0].0.peer.families.len(), 2);
    }

    // --- Community match config tests ---

    fn community_toml(policy_entries: &str) -> String {
        format!(
            r#"
[global]
asn = 65000
router_id = "1.2.3.4"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.1"
remote_asn = 65001

[[neighbors.import_policy]]
{policy_entries}
"#
        )
    }

    #[test]
    fn community_only_entry_parses() {
        let toml = community_toml(
            r#"action = "deny"
            match_community = ["RT:65001:100"]"#,
        );
        let config = parse(&toml).unwrap();
        let peers = config.to_peer_configs().unwrap();
        let import = peers[0].2.as_ref().unwrap();
        assert_eq!(import.entries.len(), 1);
        assert!(import.entries[0].prefix.is_none());
        assert_eq!(import.entries[0].match_community.len(), 1);
    }

    #[test]
    fn prefix_and_community_parses() {
        let toml = community_toml(
            r#"prefix = "10.0.0.0/8"
            action = "deny"
            match_community = ["RT:65001:100", "RO:65002:200"]"#,
        );
        let config = parse(&toml).unwrap();
        let peers = config.to_peer_configs().unwrap();
        let import = peers[0].2.as_ref().unwrap();
        assert!(import.entries[0].prefix.is_some());
        assert_eq!(import.entries[0].match_community.len(), 2);
    }

    #[test]
    fn ge_without_prefix_rejected() {
        let toml = community_toml(
            r#"action = "deny"
ge = 16
match_community = ["RT:65001:100"]"#,
        );
        assert!(parse(&toml).is_err());
    }

    #[test]
    fn neither_prefix_nor_community_rejected() {
        let toml = community_toml(r#"action = "deny""#);
        assert!(parse(&toml).is_err());
    }

    #[test]
    fn invalid_community_string_rejected() {
        let toml = community_toml(
            r#"action = "deny"
match_community = ["INVALID"]"#,
        );
        assert!(parse(&toml).is_err());
    }

    #[test]
    fn ipv4_community_parses() {
        let toml = community_toml(
            r#"action = "deny"
            match_community = ["RT:192.0.2.1:100"]"#,
        );
        let config = parse(&toml).unwrap();
        let peers = config.to_peer_configs().unwrap();
        let import = peers[0].2.as_ref().unwrap();
        assert_eq!(import.entries[0].match_community.len(), 1);
    }
}
