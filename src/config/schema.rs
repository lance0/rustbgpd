use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(super) const DEFAULT_HOLD_TIME: u16 = 90;
pub(super) const DEFAULT_CONNECT_RETRY_SECS: u32 = 30;
pub(super) const BGP_PORT: u16 = 179;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub global: Global,
    #[serde(default)]
    pub neighbors: Vec<Neighbor>,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub rpki: Option<RpkiConfig>,
    #[serde(default)]
    pub bmp: Option<BmpConfig>,
    #[serde(default)]
    pub mrt: Option<MrtConfig>,
    /// Path of the config file (populated by `Config::load`, not serialized).
    #[serde(skip)]
    pub file_path: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RpkiConfig {
    #[serde(default)]
    pub cache_servers: Vec<CacheServer>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BmpConfig {
    #[serde(default = "default_bmp_sys_name")]
    pub sys_name: String,
    #[serde(default)]
    pub sys_descr: String,
    #[serde(default)]
    pub collectors: Vec<BmpCollector>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BmpCollector {
    pub address: String,
    #[serde(default = "default_bmp_reconnect")]
    pub reconnect_interval: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MrtConfig {
    pub output_dir: String,
    #[serde(default = "default_mrt_dump_interval")]
    pub dump_interval: u64,
    #[serde(default)]
    pub compress: bool,
    #[serde(default = "default_mrt_file_prefix")]
    pub file_prefix: String,
}

fn default_mrt_dump_interval() -> u64 {
    7200
}

fn default_mrt_file_prefix() -> String {
    "rib".to_string()
}

fn default_bmp_sys_name() -> String {
    "rustbgpd".to_string()
}

fn default_bmp_reconnect() -> u64 {
    30
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Global {
    pub asn: u32,
    pub router_id: String,
    pub listen_port: u16,
    /// Cluster ID for route reflection (RFC 4456). Defaults to `router_id`
    /// when any neighbor is configured as a route reflector client.
    pub cluster_id: Option<String>,
    /// Directory for daemon-owned runtime state files.
    #[serde(default = "default_runtime_state_dir")]
    pub runtime_state_dir: String,
    pub telemetry: TelemetryConfig,
}

fn default_runtime_state_dir() -> String {
    "/var/lib/rustbgpd".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    pub prometheus_addr: String,
    pub log_format: String,
    #[serde(default)]
    pub grpc_tcp: Option<GrpcTcpListenerConfig>,
    #[serde(default)]
    pub grpc_uds: Option<GrpcUdsListenerConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcTcpListenerConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub address: Option<String>,
    pub token_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcUdsListenerConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub path: Option<String>,
    #[serde(default = "default_grpc_uds_mode")]
    pub mode: u32,
    pub token_file: Option<String>,
}

fn default_enabled() -> bool {
    true
}

fn default_grpc_uds_mode() -> u32 {
    0o600
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Long-lived stale routes time (RFC 9494, seconds). Default: 0 (disabled).
    /// When > 0, LLGR capability is advertised and routes enter a long-lived
    /// stale phase instead of being purged when the GR timer expires.
    /// Max: `16_777_215` (24-bit, ≈ 194 days).
    pub llgr_stale_time: Option<u32>,
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
    /// Remove private ASNs from `AS_PATH` before eBGP advertisement.
    ///
    /// - `"remove"` — only if the entire path consists of private ASNs
    /// - `"all"` — unconditionally remove all private ASNs
    /// - `"replace"` — replace each private ASN with the local ASN
    ///
    /// Only valid for eBGP neighbors.
    pub remove_private_as: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Minimum `AS_PATH` length (inclusive) to match.
    pub match_as_path_length_ge: Option<u32>,
    /// Maximum `AS_PATH` length (inclusive) to match.
    pub match_as_path_length_le: Option<u32>,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    #[error("invalid gRPC config: {reason}")]
    InvalidGrpcConfig { reason: String },
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
    #[error("invalid runtime_state_dir {value:?}: {reason}")]
    InvalidRuntimeStateDir { value: String, reason: String },
    #[error("invalid RPKI config: {reason}")]
    InvalidRpkiConfig { reason: String },
    #[error("undefined policy {name:?} referenced in chain")]
    UndefinedPolicy { name: String },
    #[error("invalid BMP collector config: {reason}")]
    InvalidBmpCollector { reason: String },
    #[error("invalid MRT config: {reason}")]
    InvalidMrtConfig { reason: String },
    #[error("invalid remove_private_as config: {reason}")]
    InvalidRemovePrivateAs { reason: String },
}
