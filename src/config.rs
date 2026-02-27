use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use rustbgpd_fsm::PeerConfig;
use rustbgpd_policy::{PolicyAction, PrefixList, PrefixListEntry};
use rustbgpd_transport::TransportConfig;
use rustbgpd_wire::{Afi, Ipv4Prefix, Safi};
use serde::Deserialize;

const DEFAULT_HOLD_TIME: u16 = 90;
const DEFAULT_CONNECT_RETRY_SECS: u32 = 30;
const BGP_PORT: u16 = 179;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub global: Global,
    #[serde(default)]
    pub neighbors: Vec<Neighbor>,
    #[serde(default)]
    pub policy: PolicyConfig,
}

#[derive(Debug, Deserialize)]
pub struct Global {
    pub asn: u32,
    pub router_id: String,
    #[expect(dead_code)] // parsed from config, unused in M0 (outbound only)
    pub listen_port: u16,
    pub telemetry: TelemetryConfig,
}

#[derive(Debug, Deserialize)]
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
pub struct Neighbor {
    pub address: String,
    pub remote_asn: u32,
    pub description: Option<String>,
    pub hold_time: Option<u16>,
    pub max_prefixes: Option<u32>,
    pub md5_password: Option<String>,
    #[serde(default)]
    pub ttl_security: bool,
    #[serde(default)]
    pub import_policy: Vec<PrefixListEntryConfig>,
    #[serde(default)]
    pub export_policy: Vec<PrefixListEntryConfig>,
}

#[derive(Debug, Default, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub import: Vec<PrefixListEntryConfig>,
    #[serde(default)]
    pub export: Vec<PrefixListEntryConfig>,
}

#[derive(Debug, Deserialize)]
pub struct PrefixListEntryConfig {
    pub action: String,
    pub prefix: String,
    pub ge: Option<u8>,
    pub le: Option<u8>,
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
}

fn parse_prefix_list(entries: &[PrefixListEntryConfig]) -> Option<PrefixList> {
    if entries.is_empty() {
        return None;
    }
    let parsed: Vec<PrefixListEntry> = entries
        .iter()
        .filter_map(|e| {
            let action = match e.action.as_str() {
                "permit" => PolicyAction::Permit,
                "deny" => PolicyAction::Deny,
                _ => return None,
            };
            let parts: Vec<&str> = e.prefix.split('/').collect();
            if parts.len() != 2 {
                return None;
            }
            let addr: Ipv4Addr = parts[0].parse().ok()?;
            let len: u8 = parts[1].parse().ok()?;
            Some(PrefixListEntry {
                prefix: Ipv4Prefix::new(addr, len),
                ge: e.ge,
                le: e.le,
                action,
            })
        })
        .collect();

    if parsed.is_empty() {
        return None;
    }

    Some(PrefixList {
        entries: parsed,
        default_action: PolicyAction::Permit,
    })
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

    pub fn grpc_addr(&self) -> SocketAddr {
        self.global
            .telemetry
            .grpc_addr
            .parse()
            .expect("validated in Config::load")
    }

    pub fn import_policy(&self) -> Option<PrefixList> {
        parse_prefix_list(&self.policy.import)
    }

    pub fn export_policy(&self) -> Option<PrefixList> {
        parse_prefix_list(&self.policy.export)
    }

    /// Returns `(TransportConfig, label, import_policy, export_policy)` per neighbor.
    ///
    /// Per-neighbor policy overrides global; if neighbor has no policy entries,
    /// the corresponding value is `None` (caller falls back to global).
    pub fn to_peer_configs(
        &self,
    ) -> Vec<(
        TransportConfig,
        String,
        Option<PrefixList>,
        Option<PrefixList>,
    )> {
        let router_id: Ipv4Addr = self
            .global
            .router_id
            .parse()
            .expect("validated in Config::load");

        let global_import = self.import_policy();
        let global_export = self.export_policy();

        self.neighbors
            .iter()
            .map(|neighbor| {
                let peer_addr: IpAddr =
                    neighbor.address.parse().expect("validated in Config::load");

                let peer = PeerConfig {
                    local_asn: self.global.asn,
                    remote_asn: neighbor.remote_asn,
                    local_router_id: router_id,
                    hold_time: neighbor.hold_time.unwrap_or(DEFAULT_HOLD_TIME),
                    connect_retry_secs: DEFAULT_CONNECT_RETRY_SECS,
                    families: vec![(Afi::Ipv4, Safi::Unicast)],
                };

                let remote_addr = SocketAddr::new(peer_addr, BGP_PORT);
                let mut transport = TransportConfig::new(peer, remote_addr);
                transport.max_prefixes = neighbor.max_prefixes;
                transport.md5_password.clone_from(&neighbor.md5_password);
                transport.ttl_security = neighbor.ttl_security;

                let label = neighbor
                    .description
                    .clone()
                    .unwrap_or_else(|| neighbor.address.clone());

                // Per-neighbor policy overrides global
                let import = parse_prefix_list(&neighbor.import_policy).or(global_import.clone());
                let export = parse_prefix_list(&neighbor.export_policy).or(global_export.clone());

                (transport, label, import, export)
            })
            .collect()
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

        let peers = config.to_peer_configs();
        assert_eq!(peers[0].0.peer.hold_time, 90);
    }

    #[test]
    fn to_peer_configs_maps_correctly() {
        let config = parse(valid_toml()).unwrap();
        let peers = config.to_peer_configs();
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

        let peers = config.to_peer_configs();
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

        let peers = config.to_peer_configs();
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
        let import = config.import_policy().unwrap();
        assert_eq!(import.entries.len(), 1);
        let export = config.export_policy().unwrap();
        assert_eq!(export.entries.len(), 1);
    }

    #[test]
    fn empty_policy_returns_none() {
        let config = parse(valid_toml()).unwrap();
        assert!(config.import_policy().is_none());
        assert!(config.export_policy().is_none());
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
        let peers = config.to_peer_configs();
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

        let peers = config.to_peer_configs();
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

        let peers = config.to_peer_configs();
        // Should inherit global export policy
        assert!(peers[0].2.is_none()); // no import (neither neighbor nor global)
        assert!(peers[0].3.is_some()); // export from global
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
        let peers = config.to_peer_configs();

        // First neighbor: has per-neighbor export → uses that
        let export1 = peers[0].3.as_ref().unwrap();
        assert_eq!(export1.entries[0].action, PolicyAction::Permit);

        // Second neighbor: no per-neighbor → falls back to global deny
        let export2 = peers[1].3.as_ref().unwrap();
        assert_eq!(export2.entries[0].action, PolicyAction::Deny);
    }
}
