use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use rustbgpd_fsm::PeerConfig;
use rustbgpd_transport::TransportConfig;
use rustbgpd_wire::{Afi, Safi};
use serde::Deserialize;

const DEFAULT_HOLD_TIME: u16 = 90;
const DEFAULT_CONNECT_RETRY_SECS: u32 = 30;
const BGP_PORT: u16 = 179;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub global: Global,
    #[serde(default)]
    pub neighbors: Vec<Neighbor>,
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
}

#[derive(Debug, Deserialize)]
pub struct Neighbor {
    pub address: String,
    pub remote_asn: u32,
    pub description: Option<String>,
    pub hold_time: Option<u16>,
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
    #[error("no neighbors configured")]
    NoNeighbors,
    #[error("invalid hold_time {value}: must be 0 or >= 3")]
    InvalidHoldTime { value: u16 },
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

        if self.neighbors.is_empty() {
            return Err(ConfigError::NoNeighbors);
        }

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

    pub fn to_peer_configs(&self) -> Vec<(TransportConfig, String)> {
        let router_id: Ipv4Addr = self
            .global
            .router_id
            .parse()
            .expect("validated in Config::load");

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
                let transport = TransportConfig::new(peer, remote_addr);

                let label = neighbor
                    .description
                    .clone()
                    .unwrap_or_else(|| neighbor.address.clone());

                (transport, label)
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
    fn no_neighbors_rejected() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::NoNeighbors));
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

        let (transport, label) = &peers[0];
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
}
