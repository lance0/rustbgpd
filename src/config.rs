use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use rustbgpd_fsm::PeerConfig;
use std::collections::HashMap;

use rustbgpd_policy::{
    CommunityMatch, NextHopAction, Policy, PolicyAction, PolicyChain, PolicyStatement,
    RouteModifications, parse_community_match,
};
use rustbgpd_transport::TransportConfig;
use rustbgpd_wire::{Afi, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, LargeCommunity, Prefix, Safi};
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
    #[serde(default)]
    pub rpki: Option<RpkiConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpkiConfig {
    #[serde(default)]
    pub cache_servers: Vec<CacheServer>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheServer {
    pub address: String,
    #[serde(default = "default_rpki_refresh")]
    pub refresh_interval: u64,
    #[serde(default = "default_rpki_retry")]
    pub retry_interval: u64,
    #[serde(default = "default_rpki_expire")]
    pub expire_interval: u64,
}

fn default_rpki_refresh() -> u64 {
    3600
}
fn default_rpki_retry() -> u64 {
    600
}
fn default_rpki_expire() -> u64 {
    7200
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Global {
    pub asn: u32,
    pub router_id: String,
    pub listen_port: u16,
    /// Cluster ID for route reflection (RFC 4456). Defaults to `router_id`
    /// when any neighbor is configured as a route reflector client.
    pub cluster_id: Option<String>,
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
    /// Mark this neighbor as a route reflector client (RFC 4456).
    /// Only valid for iBGP neighbors (`remote_asn` == `global.asn`).
    #[serde(default)]
    pub route_reflector_client: bool,
    /// Mark this eBGP neighbor as a transparent route-server client.
    ///
    /// When enabled, outbound unicast advertisements preserve the original
    /// next hop and suppress automatic local-AS prepend. Explicit export
    /// policy next-hop rewrites still apply.
    #[serde(default)]
    pub route_server_client: bool,
    /// Add-Path (RFC 7911) configuration for this neighbor.
    pub add_path: Option<AddPathConfig>,
    #[serde(default)]
    pub import_policy: Vec<PolicyStatementConfig>,
    #[serde(default)]
    pub export_policy: Vec<PolicyStatementConfig>,
    /// Named policy chain for import (mutually exclusive with `import_policy`).
    #[serde(default)]
    pub import_policy_chain: Vec<String>,
    /// Named policy chain for export (mutually exclusive with `export_policy`).
    #[serde(default)]
    pub export_policy_chain: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddPathConfig {
    /// Accept multiple paths per prefix from this peer (RFC 7911).
    #[serde(default)]
    pub receive: bool,
    /// Advertise multiple paths per prefix to this peer (RFC 7911).
    #[serde(default)]
    pub send: bool,
    /// Maximum number of paths to advertise per prefix (0 or absent = unlimited).
    pub send_max: Option<u32>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    #[serde(default)]
    pub import: Vec<PolicyStatementConfig>,
    #[serde(default)]
    pub export: Vec<PolicyStatementConfig>,
    /// Named policy definitions, reusable across neighbors and directions.
    #[serde(default)]
    pub definitions: HashMap<String, NamedPolicyConfig>,
    /// Global import policy chain (references named definitions).
    #[serde(default)]
    pub import_chain: Vec<String>,
    /// Global export policy chain (references named definitions).
    #[serde(default)]
    pub export_chain: Vec<String>,
}

/// A named policy definition with configurable default action.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedPolicyConfig {
    /// Default action when no statement matches: `"permit"` (default) or `"deny"`.
    #[serde(default = "default_policy_action_str")]
    pub default_action: String,
    #[serde(default)]
    pub statements: Vec<PolicyStatementConfig>,
}

fn default_policy_action_str() -> String {
    "permit".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyStatementConfig {
    pub action: String,
    /// CIDR prefix to match. Optional when `match_community` or `match_as_path` is set.
    pub prefix: Option<String>,
    pub ge: Option<u8>,
    pub le: Option<u8>,
    /// Community match criteria, e.g. `["65001:100"]`, `["RT:65001:100"]`,
    /// or `["NO_EXPORT"]`.
    #[serde(default)]
    pub match_community: Vec<String>,
    /// `AS_PATH` regex pattern (Cisco/Quagga style: `_` = boundary anchor).
    pub match_as_path: Option<String>,
    /// RPKI validation state to match: `"valid"`, `"invalid"`, or `"not_found"`.
    pub match_rpki_validation: Option<String>,
    /// Set `LOCAL_PREF` on matching routes.
    pub set_local_pref: Option<u32>,
    /// Set MED on matching routes.
    pub set_med: Option<u32>,
    /// Rewrite next-hop: `"self"` or an IP address.
    pub set_next_hop: Option<String>,
    /// Add communities to matching routes.
    #[serde(default)]
    pub set_community_add: Vec<String>,
    /// Remove communities from matching routes.
    #[serde(default)]
    pub set_community_remove: Vec<String>,
    /// Prepend `AS_PATH` on matching routes.
    pub set_as_path_prepend: Option<AsPathPrependConfig>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AsPathPrependConfig {
    pub asn: u32,
    pub count: u8,
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
    #[error("invalid route reflector config: {reason}")]
    InvalidRrConfig { reason: String },
    #[error("invalid route server config: {reason}")]
    InvalidRouteServerConfig { reason: String },
    #[error("invalid RPKI config: {reason}")]
    InvalidRpkiConfig { reason: String },
    #[error("undefined policy {name:?} referenced in chain")]
    UndefinedPolicy { name: String },
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

/// Parse a list of statement configs into `PolicyStatement`s.
fn parse_policy_statements(
    entries: &[PolicyStatementConfig],
) -> Result<Vec<PolicyStatement>, ConfigError> {
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

        let match_as_path = if let Some(ref pat) = e.match_as_path {
            Some(
                rustbgpd_policy::AsPathRegex::new(pat)
                    .map_err(|reason| ConfigError::InvalidPolicyEntry { reason })?,
            )
        } else {
            None
        };

        let match_rpki_validation = if let Some(ref s) = e.match_rpki_validation {
            Some(s.parse::<rustbgpd_wire::RpkiValidation>().map_err(|_| {
                ConfigError::InvalidPolicyEntry {
                    reason: format!(
                        "invalid match_rpki_validation {s:?}: expected \"valid\", \"invalid\", or \"not_found\""
                    ),
                }
            })?)
        } else {
            None
        };

        if prefix.is_none()
            && match_community.is_empty()
            && match_as_path.is_none()
            && match_rpki_validation.is_none()
        {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: "entry must have at least one of 'prefix', 'match_community', 'match_as_path', or 'match_rpki_validation'".to_string(),
            });
        }

        // Build route modifications from set_* fields
        let modifications = parse_modifications(e, action)?;

        parsed.push(PolicyStatement {
            prefix,
            ge: e.ge,
            le: e.le,
            action,
            match_community,
            match_as_path,
            match_rpki_validation,
            modifications,
        });
    }
    Ok(parsed)
}

/// Parse inline policy entries into a single `Policy` with `default_action=Permit`.
fn parse_policy(entries: &[PolicyStatementConfig]) -> Result<Option<Policy>, ConfigError> {
    if entries.is_empty() {
        return Ok(None);
    }
    let parsed = parse_policy_statements(entries)?;
    Ok(Some(Policy {
        entries: parsed,
        default_action: PolicyAction::Permit,
    }))
}

/// Parse a named policy definition with configurable default action.
fn parse_named_policy(name: &str, cfg: &NamedPolicyConfig) -> Result<Policy, ConfigError> {
    let default_action = match cfg.default_action.as_str() {
        "permit" => PolicyAction::Permit,
        "deny" => PolicyAction::Deny,
        other => {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!(
                    "policy {name:?}: unknown default_action {other:?}, expected \"permit\" or \"deny\""
                ),
            });
        }
    };
    let entries = parse_policy_statements(&cfg.statements)?;
    Ok(Policy {
        entries,
        default_action,
    })
}

/// Resolve a list of policy names to a `PolicyChain`.
fn resolve_chain(
    names: &[String],
    definitions: &HashMap<String, NamedPolicyConfig>,
) -> Result<Option<PolicyChain>, ConfigError> {
    if names.is_empty() {
        return Ok(None);
    }
    let policies = names
        .iter()
        .map(|name| {
            definitions
                .get(name.as_str())
                .ok_or_else(|| ConfigError::UndefinedPolicy { name: name.clone() })
                .and_then(|cfg| parse_named_policy(name, cfg))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(PolicyChain::new(policies)))
}

/// Parse the `set_*` fields into `RouteModifications`, with validation.
fn parse_modifications(
    e: &PolicyStatementConfig,
    action: PolicyAction,
) -> Result<RouteModifications, ConfigError> {
    let has_set_fields = e.set_local_pref.is_some()
        || e.set_med.is_some()
        || e.set_next_hop.is_some()
        || !e.set_community_add.is_empty()
        || !e.set_community_remove.is_empty()
        || e.set_as_path_prepend.is_some();

    if has_set_fields && action == PolicyAction::Deny {
        return Err(ConfigError::InvalidPolicyEntry {
            reason: "set_* fields cannot be used with action = \"deny\"".to_string(),
        });
    }

    if !has_set_fields {
        return Ok(RouteModifications::default());
    }

    // Parse next-hop action
    let set_next_hop = if let Some(ref nh) = e.set_next_hop {
        match nh.as_str() {
            "self" => Some(NextHopAction::Self_),
            other => {
                let addr: IpAddr = other.parse().map_err(|_| ConfigError::InvalidPolicyEntry {
                    reason: format!(
                        "invalid set_next_hop {other:?}: expected \"self\" or an IP address"
                    ),
                })?;
                Some(NextHopAction::Specific(addr))
            }
        }
    } else {
        None
    };

    // Parse AS_PATH prepend
    let as_path_prepend = if let Some(ref pp) = e.set_as_path_prepend {
        if pp.count == 0 || pp.count > 10 {
            return Err(ConfigError::InvalidPolicyEntry {
                reason: format!("set_as_path_prepend count must be 1-10, got {}", pp.count),
            });
        }
        Some((pp.asn, pp.count))
    } else {
        None
    };

    // Parse community add/remove values
    let add = parse_community_values(&e.set_community_add)?;
    let remove = parse_community_values(&e.set_community_remove)?;

    Ok(RouteModifications {
        set_local_pref: e.set_local_pref,
        set_med: e.set_med,
        set_next_hop,
        communities_add: add.standard,
        communities_remove: remove.standard,
        extended_communities_add: add.extended,
        extended_communities_remove: remove.extended,
        large_communities_add: add.large,
        large_communities_remove: remove.large,
        as_path_prepend,
    })
}

/// Classified community values parsed from config strings.
struct CommunityValues {
    standard: Vec<u32>,
    extended: Vec<ExtendedCommunity>,
    large: Vec<LargeCommunity>,
}

/// Parse community strings and classify into standard, extended, and large buckets.
fn parse_community_values(strings: &[String]) -> Result<CommunityValues, ConfigError> {
    let mut standard = Vec::new();
    let mut extended = Vec::new();
    let mut large = Vec::new();
    for s in strings {
        let cm = parse_community_match(s)
            .map_err(|reason| ConfigError::InvalidPolicyEntry { reason })?;
        match cm {
            CommunityMatch::Standard { value } => standard.push(value),
            CommunityMatch::RouteTarget { global, local } => {
                extended.push(build_rt_ec(global, local)?);
            }
            CommunityMatch::RouteOrigin { global, local } => {
                extended.push(build_ro_ec(global, local)?);
            }
            CommunityMatch::LargeCommunity {
                global_admin,
                local_data1,
                local_data2,
            } => {
                large.push(LargeCommunity::new(global_admin, local_data1, local_data2));
            }
        }
    }
    Ok(CommunityValues {
        standard,
        extended,
        large,
    })
}

/// Build a 2-octet AS Route Target extended community.
///
/// Rejects `global` > 65535 since the 2-octet AS-Specific sub-type only
/// carries a `u16` AS number.
fn build_rt_ec(global: u32, local: u32) -> Result<ExtendedCommunity, ConfigError> {
    let asn: u16 = global
        .try_into()
        .map_err(|_| ConfigError::InvalidPolicyEntry {
            reason: format!(
                "RT extended community ASN {global} exceeds 65535 (2-octet AS sub-type)"
            ),
        })?;
    let mut b = [0u8; 8];
    b[0] = 0x00; // Transitive Two-Octet AS-Specific
    b[1] = 0x02; // Route Target
    b[2..4].copy_from_slice(&asn.to_be_bytes());
    b[4..8].copy_from_slice(&local.to_be_bytes());
    Ok(ExtendedCommunity::new(u64::from_be_bytes(b)))
}

/// Build a 2-octet AS Route Origin extended community.
///
/// Rejects `global` > 65535 since the 2-octet AS-Specific sub-type only
/// carries a `u16` AS number.
fn build_ro_ec(global: u32, local: u32) -> Result<ExtendedCommunity, ConfigError> {
    let asn: u16 = global
        .try_into()
        .map_err(|_| ConfigError::InvalidPolicyEntry {
            reason: format!(
                "RO extended community ASN {global} exceeds 65535 (2-octet AS sub-type)"
            ),
        })?;
    let mut b = [0u8; 8];
    b[0] = 0x00; // Transitive Two-Octet AS-Specific
    b[1] = 0x03; // Route Origin
    b[2..4].copy_from_slice(&asn.to_be_bytes());
    b[4..8].copy_from_slice(&local.to_be_bytes());
    Ok(ExtendedCommunity::new(u64::from_be_bytes(b)))
}

/// Parse a list of address family strings into `(Afi, Safi)` pairs.
fn parse_families(families: &[String]) -> Result<Vec<(Afi, Safi)>, ConfigError> {
    let mut result = Vec::with_capacity(families.len());
    for f in families {
        let family = match f.as_str() {
            "ipv4_unicast" => (Afi::Ipv4, Safi::Unicast),
            "ipv6_unicast" => (Afi::Ipv6, Safi::Unicast),
            "ipv4_flowspec" => (Afi::Ipv4, Safi::FlowSpec),
            "ipv6_flowspec" => (Afi::Ipv6, Safi::FlowSpec),
            other => {
                return Err(ConfigError::InvalidPolicyEntry {
                    reason: format!(
                        "unknown address family {other:?}, expected one of: \
                         \"ipv4_unicast\", \"ipv6_unicast\", \"ipv4_flowspec\", \"ipv6_flowspec\""
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

    #[expect(clippy::too_many_lines)]
    fn validate(&self) -> Result<(), ConfigError> {
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
        parse_policy(&self.policy.import)?;
        parse_policy(&self.policy.export)?;

        // Validate named policy definitions
        for (name, cfg) in &self.policy.definitions {
            parse_named_policy(name, cfg)?;
        }

        // Validate global chains
        resolve_chain(&self.policy.import_chain, &self.policy.definitions)?;
        resolve_chain(&self.policy.export_chain, &self.policy.definitions)?;

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
            transport.route_server_client = neighbor.route_server_client;

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
        let import = config.import_chain().unwrap().unwrap();
        assert_eq!(import.policies[0].entries.len(), 1);
        let export = config.export_chain().unwrap().unwrap();
        assert_eq!(export.policies[0].entries.len(), 1);
    }

    #[test]
    fn empty_policy_returns_none() {
        let config = parse(valid_toml()).unwrap();
        assert!(config.import_chain().unwrap().is_none());
        assert!(config.export_chain().unwrap().is_none());
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
        assert_eq!(export1.policies[0].entries[0].action, PolicyAction::Permit);

        // Second neighbor: no per-neighbor → falls back to global deny
        let export2 = peers[1].3.as_ref().unwrap();
        assert_eq!(export2.policies[0].entries[0].action, PolicyAction::Deny);
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
        assert_eq!(import.policies[0].entries.len(), 1);
        assert!(import.policies[0].entries[0].prefix.is_none());
        assert_eq!(import.policies[0].entries[0].match_community.len(), 1);
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
        assert!(import.policies[0].entries[0].prefix.is_some());
        assert_eq!(import.policies[0].entries[0].match_community.len(), 2);
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
        assert_eq!(import.policies[0].entries[0].match_community.len(), 1);
    }

    // --- Route Reflector config tests ---

    #[test]
    fn rr_client_on_ebgp_rejected() {
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
route_reflector_client = true
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRrConfig { .. }));
    }

    #[test]
    fn rr_client_on_ibgp_accepted() {
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
remote_asn = 65001
route_reflector_client = true
"#;
        let config = parse(toml_str).unwrap();
        assert!(config.neighbors[0].route_reflector_client);
    }

    #[test]
    fn route_server_client_on_ebgp_accepted() {
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
route_server_client = true
"#;
        let config = parse(toml_str).unwrap();
        assert!(config.neighbors[0].route_server_client);
    }

    #[test]
    fn route_server_client_on_ibgp_rejected() {
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
remote_asn = 65001
route_server_client = true
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRouteServerConfig { .. }));
    }

    #[test]
    fn route_server_client_defaults_to_false() {
        let config = parse(valid_toml()).unwrap();
        assert!(!config.neighbors[0].route_server_client);
    }

    #[test]
    fn cluster_id_invalid_rejected() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
cluster_id = "not-an-ip"

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"
"#;
        let err = parse(toml_str).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRrConfig { .. }));
    }

    #[test]
    fn cluster_id_defaults_to_router_id() {
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
remote_asn = 65001
route_reflector_client = true
"#;
        let config = parse(toml_str).unwrap();
        assert_eq!(config.cluster_id(), Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn explicit_cluster_id_used() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179
cluster_id = "10.0.0.99"

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65001
route_reflector_client = true
"#;
        let config = parse(toml_str).unwrap();
        assert_eq!(config.cluster_id(), Some(Ipv4Addr::new(10, 0, 0, 99)));
    }

    #[test]
    fn no_rr_client_means_no_cluster_id() {
        let config = parse(valid_toml()).unwrap();
        assert_eq!(config.cluster_id(), None);
    }

    // --- AS_PATH regex config tests ---

    #[test]
    fn match_as_path_only_parses() {
        let toml = community_toml(
            r#"action = "permit"
            match_as_path = "^65100_""#,
        );
        let config = parse(&toml).unwrap();
        let peers = config.to_peer_configs().unwrap();
        let import = peers[0].2.as_ref().unwrap();
        assert_eq!(import.policies[0].entries.len(), 1);
        assert!(import.policies[0].entries[0].prefix.is_none());
        assert!(import.policies[0].entries[0].match_as_path.is_some());
    }

    #[test]
    fn match_as_path_with_prefix_parses() {
        let toml = community_toml(
            r#"action = "deny"
            prefix = "10.0.0.0/8"
            match_as_path = "_65200_""#,
        );
        let config = parse(&toml).unwrap();
        let peers = config.to_peer_configs().unwrap();
        let import = peers[0].2.as_ref().unwrap();
        assert!(import.policies[0].entries[0].prefix.is_some());
        assert!(import.policies[0].entries[0].match_as_path.is_some());
    }

    #[test]
    fn match_as_path_invalid_regex_rejected() {
        let toml = community_toml(
            r#"action = "deny"
            match_as_path = "[invalid""#,
        );
        assert!(parse(&toml).is_err());
    }

    #[test]
    fn neither_prefix_nor_community_nor_aspath_rejected() {
        let toml = community_toml(r#"action = "deny""#);
        assert!(parse(&toml).is_err());
    }

    #[test]
    fn set_community_rt_4byte_asn_rejected() {
        // build_rt_ec only supports 2-octet AS — 4-byte ASN should fail at config time.
        let toml = community_toml(
            r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_add = ["RT:100000:100"]"#,
        );
        let err = parse(&toml).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
    }

    #[test]
    fn set_community_ro_4byte_asn_rejected() {
        let toml = community_toml(
            r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_remove = ["RO:100000:200"]"#,
        );
        let err = parse(&toml).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidPolicyEntry { .. }));
    }

    #[test]
    fn set_community_rt_2byte_asn_accepted() {
        let toml = community_toml(
            r#"action = "permit"
            prefix = "10.0.0.0/8"
            set_community_add = ["RT:65535:100"]"#,
        );
        assert!(parse(&toml).is_ok());
    }

    #[test]
    fn add_path_config_receive_enabled() {
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

[neighbors.add_path]
receive = true
"#;
        let config = parse(toml_str).unwrap();
        let peers = config.to_peer_configs().unwrap();
        assert!(peers[0].0.peer.add_path_receive);
    }

    #[test]
    fn add_path_config_defaults_to_disabled() {
        let config = parse(valid_toml()).unwrap();
        let peers = config.to_peer_configs().unwrap();
        assert!(!peers[0].0.peer.add_path_receive);
    }

    #[test]
    fn add_path_config_send_enabled() {
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

[neighbors.add_path]
send = true
send_max = 4
"#;
        let config = parse(toml_str).unwrap();
        let peers = config.to_peer_configs().unwrap();
        assert!(peers[0].0.peer.add_path_send);
        assert_eq!(peers[0].0.peer.add_path_send_max, 4);
    }

    #[test]
    fn add_path_config_send_and_receive() {
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

[neighbors.add_path]
receive = true
send = true
"#;
        let config = parse(toml_str).unwrap();
        let peers = config.to_peer_configs().unwrap();
        assert!(peers[0].0.peer.add_path_receive);
        assert!(peers[0].0.peer.add_path_send);
        // No send_max → defaults to 0 (unlimited at transport layer)
        assert_eq!(peers[0].0.peer.add_path_send_max, 0);
    }

    #[test]
    fn add_path_config_send_defaults_to_disabled() {
        let config = parse(valid_toml()).unwrap();
        let peers = config.to_peer_configs().unwrap();
        assert!(!peers[0].0.peer.add_path_send);
        assert_eq!(peers[0].0.peer.add_path_send_max, 0);
    }

    #[test]
    fn to_peer_configs_maps_route_server_client() {
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
route_server_client = true
"#;
        let config = parse(toml_str).unwrap();
        let peers = config.to_peer_configs().unwrap();
        assert!(peers[0].0.route_server_client);
    }

    // --- RPKI config tests ---

    #[test]
    fn rpki_single_cache_server_parses() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"
"#;
        let config = parse(toml_str).unwrap();
        let rpki = config.rpki.as_ref().unwrap();
        assert_eq!(rpki.cache_servers.len(), 1);
        assert_eq!(rpki.cache_servers[0].address, "127.0.0.1:3323");
        // Check defaults
        assert_eq!(rpki.cache_servers[0].refresh_interval, 3600);
        assert_eq!(rpki.cache_servers[0].retry_interval, 600);
        assert_eq!(rpki.cache_servers[0].expire_interval, 7200);
    }

    #[test]
    fn rpki_multiple_cache_servers_parses() {
        let toml_str = r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[rpki]
[[rpki.cache_servers]]
address = "10.0.0.10:3323"
refresh_interval = 1800
retry_interval = 300
expire_interval = 3600

[[rpki.cache_servers]]
address = "10.0.0.11:8282"
"#;
        let config = parse(toml_str).unwrap();
        let rpki = config.rpki.as_ref().unwrap();
        assert_eq!(rpki.cache_servers.len(), 2);
        assert_eq!(rpki.cache_servers[0].refresh_interval, 1800);
        assert_eq!(rpki.cache_servers[0].retry_interval, 300);
        assert_eq!(rpki.cache_servers[0].expire_interval, 3600);
        // Second server uses defaults
        assert_eq!(rpki.cache_servers[1].refresh_interval, 3600);
    }

    #[test]
    fn rpki_absent_means_none() {
        let config = parse(valid_toml()).unwrap();
        assert!(config.rpki.is_none());
    }

    #[test]
    fn rpki_policy_match_rpki_validation_parses() {
        let toml = community_toml(
            r#"action = "deny"
            match_rpki_validation = "invalid""#,
        );
        let config = parse(&toml).unwrap();
        let peers = config.to_peer_configs().unwrap();
        let import = peers[0].2.as_ref().unwrap();
        assert_eq!(import.policies[0].entries.len(), 1);
        assert_eq!(
            import.policies[0].entries[0].match_rpki_validation,
            Some(rustbgpd_wire::RpkiValidation::Invalid)
        );
    }

    #[test]
    fn rpki_policy_match_rpki_validation_valid() {
        let toml = community_toml(
            r#"action = "permit"
            match_rpki_validation = "valid""#,
        );
        let config = parse(&toml).unwrap();
        let peers = config.to_peer_configs().unwrap();
        let import = peers[0].2.as_ref().unwrap();
        assert_eq!(
            import.policies[0].entries[0].match_rpki_validation,
            Some(rustbgpd_wire::RpkiValidation::Valid)
        );
    }

    #[test]
    fn rpki_policy_match_rpki_validation_not_found() {
        let toml = community_toml(
            r#"action = "permit"
            match_rpki_validation = "not_found""#,
        );
        let config = parse(&toml).unwrap();
        let peers = config.to_peer_configs().unwrap();
        let import = peers[0].2.as_ref().unwrap();
        assert_eq!(
            import.policies[0].entries[0].match_rpki_validation,
            Some(rustbgpd_wire::RpkiValidation::NotFound)
        );
    }

    #[test]
    fn rpki_policy_match_rpki_validation_bad_value_rejected() {
        let toml = community_toml(
            r#"action = "deny"
            match_rpki_validation = "unknown_state""#,
        );
        assert!(parse(&toml).is_err());
    }

    #[test]
    fn rpki_policy_match_rpki_validation_standalone() {
        // match_rpki_validation alone (without prefix/community/aspath) should be valid
        let toml = community_toml(
            r#"action = "deny"
            match_rpki_validation = "invalid""#,
        );
        assert!(parse(&toml).is_ok());
    }

    fn rpki_toml(cache_fields: &str) -> String {
        format!(
            r#"
[global]
asn = 65001
router_id = "10.0.0.1"
listen_port = 179

[global.telemetry]
prometheus_addr = "0.0.0.0:9179"
log_format = "json"

[rpki]
[[rpki.cache_servers]]
address = "127.0.0.1:3323"
{cache_fields}
"#
        )
    }

    #[test]
    fn rpki_zero_refresh_interval_rejected() {
        let err = parse(&rpki_toml("refresh_interval = 0")).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRpkiConfig { .. }));
    }

    #[test]
    fn rpki_zero_retry_interval_rejected() {
        let err = parse(&rpki_toml("retry_interval = 0")).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRpkiConfig { .. }));
    }

    #[test]
    fn rpki_zero_expire_interval_rejected() {
        let err = parse(&rpki_toml("expire_interval = 0")).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRpkiConfig { .. }));
    }

    #[test]
    fn rpki_expire_less_than_refresh_rejected() {
        let err = parse(&rpki_toml(
            "refresh_interval = 3600\nexpire_interval = 1800",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRpkiConfig { .. }));
    }

    #[test]
    fn rpki_expire_equals_refresh_accepted() {
        assert!(
            parse(&rpki_toml(
                "refresh_interval = 3600\nexpire_interval = 3600",
            ))
            .is_ok()
        );
    }

    #[test]
    fn rpki_valid_custom_timers_accepted() {
        let config = parse(&rpki_toml(
            "refresh_interval = 1800\nretry_interval = 300\nexpire_interval = 3600",
        ))
        .unwrap();
        let rpki = config.rpki.as_ref().unwrap();
        assert_eq!(rpki.cache_servers[0].refresh_interval, 1800);
        assert_eq!(rpki.cache_servers[0].retry_interval, 300);
        assert_eq!(rpki.cache_servers[0].expire_interval, 3600);
    }

    // -----------------------------------------------------------------------
    // Named policies + policy chaining
    // -----------------------------------------------------------------------

    fn named_policy_toml() -> String {
        format!(
            r#"
{GLOBAL_HEADER}

[policy.definitions.reject-bogons]
default_action = "deny"
[[policy.definitions.reject-bogons.statements]]
action = "permit"
prefix = "0.0.0.0/0"
ge = 8
le = 24

[policy.definitions.set-lp]
[[policy.definitions.set-lp.statements]]
action = "permit"
prefix = "10.0.0.0/8"
set_local_pref = 200

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#,
            GLOBAL_HEADER = valid_toml()
        )
    }

    #[test]
    fn named_policy_parses() {
        let config = parse(&named_policy_toml()).unwrap();
        assert_eq!(config.policy.definitions.len(), 2);
        assert!(config.policy.definitions.contains_key("reject-bogons"));
        assert!(config.policy.definitions.contains_key("set-lp"));
    }

    #[test]
    fn named_policy_default_deny() {
        let config = parse(&named_policy_toml()).unwrap();
        let def = &config.policy.definitions["reject-bogons"];
        assert_eq!(def.default_action, "deny");
        let policy = parse_named_policy("reject-bogons", def).unwrap();
        assert_eq!(policy.default_action, PolicyAction::Deny);
    }

    #[test]
    fn empty_statements_deny_is_valid() {
        let toml_str = format!(
            r#"
{GLOBAL_HEADER}

[policy.definitions.deny-all]
default_action = "deny"

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#,
            GLOBAL_HEADER = valid_toml()
        );
        let config = parse(&toml_str).unwrap();
        let def = &config.policy.definitions["deny-all"];
        let policy = parse_named_policy("deny-all", def).unwrap();
        assert_eq!(policy.entries.len(), 0);
        assert_eq!(policy.default_action, PolicyAction::Deny);
    }

    #[test]
    fn undefined_policy_in_chain_is_error() {
        let toml_str = format!(
            r#"
{GLOBAL_HEADER}

[policy]
import_chain = ["nonexistent"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#,
            GLOBAL_HEADER = valid_toml()
        );
        let err = parse(&toml_str).unwrap_err();
        assert!(err.to_string().contains("nonexistent"));
    }

    #[test]
    fn global_import_chain_works() {
        let toml_str = format!(
            r#"
{GLOBAL_HEADER}

[policy.definitions.set-lp]
[[policy.definitions.set-lp.statements]]
action = "permit"
prefix = "10.0.0.0/8"
set_local_pref = 200

[policy]
import_chain = ["set-lp"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
"#,
            GLOBAL_HEADER = valid_toml()
        );
        let config = parse(&toml_str).unwrap();
        let chain = config.import_chain().unwrap().unwrap();
        assert_eq!(chain.policies.len(), 1);
        assert_eq!(chain.policies[0].entries.len(), 1);
    }

    #[test]
    fn neighbor_import_chain_overrides_global() {
        let toml_str = format!(
            r#"
{GLOBAL_HEADER}

[policy.definitions.global-pol]
[[policy.definitions.global-pol.statements]]
action = "deny"
prefix = "10.0.0.0/8"

[policy.definitions.peer-pol]
[[policy.definitions.peer-pol.statements]]
action = "permit"
prefix = "192.168.0.0/16"
set_local_pref = 300

[policy]
import_chain = ["global-pol"]

[[neighbors]]
address = "10.0.0.2"
remote_asn = 65002
import_policy_chain = ["peer-pol"]
"#,
            GLOBAL_HEADER = valid_toml()
        );
        let config = parse(&toml_str).unwrap();
        let peers = config.to_peer_configs().unwrap();
        let (_, _, import, _) = &peers[1]; // skip the first neighbor from valid_toml
        let chain = import.as_ref().unwrap();
        // Peer chain should have peer-pol, not global-pol
        assert_eq!(
            chain.policies[0].entries[0].modifications.set_local_pref,
            Some(300)
        );
    }

    #[test]
    fn inline_and_chain_mutually_exclusive() {
        let toml_str = format!(
            r#"
{GLOBAL_HEADER}

[policy.definitions.some-pol]
[[policy.definitions.some-pol.statements]]
action = "permit"
prefix = "10.0.0.0/8"

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
import_policy_chain = ["some-pol"]

[[neighbors.import_policy]]
action = "deny"
prefix = "192.168.0.0/16"
"#,
            GLOBAL_HEADER = valid_toml()
        );
        let err = parse(&toml_str).unwrap_err();
        assert!(err.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn inline_policy_still_works() {
        let toml_str = format!(
            r#"
{GLOBAL_HEADER}

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003

[[neighbors.import_policy]]
action = "deny"
prefix = "192.168.0.0/16"
"#,
            GLOBAL_HEADER = valid_toml()
        );
        let config = parse(&toml_str).unwrap();
        let peers = config.to_peer_configs().unwrap();
        let (_, _, import, _) = &peers[1];
        let chain = import.as_ref().unwrap();
        assert_eq!(chain.policies.len(), 1);
        assert_eq!(chain.policies[0].entries[0].action, PolicyAction::Deny);
    }

    #[test]
    fn no_policy_falls_back_to_global_chain() {
        let toml_str = format!(
            r#"
{GLOBAL_HEADER}

[policy.definitions.global-pol]
[[policy.definitions.global-pol.statements]]
action = "permit"
prefix = "10.0.0.0/8"
set_local_pref = 150

[policy]
import_chain = ["global-pol"]

[[neighbors]]
address = "10.0.0.3"
remote_asn = 65003
"#,
            GLOBAL_HEADER = valid_toml()
        );
        let config = parse(&toml_str).unwrap();
        let peers = config.to_peer_configs().unwrap();
        // Second neighbor (first is from valid_toml) has no per-peer policy
        let (_, _, import, _) = &peers[1];
        let chain = import.as_ref().unwrap();
        assert_eq!(
            chain.policies[0].entries[0].modifications.set_local_pref,
            Some(150)
        );
    }
}
