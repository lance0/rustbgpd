use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub(super) const DEFAULT_HOLD_TIME: u16 = 90;
pub(super) const DEFAULT_CONNECT_RETRY_SECS: u32 = 5;
pub(super) const BGP_PORT: u16 = 179;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub global: Global,
    #[serde(default)]
    pub neighbors: Vec<Neighbor>,
    #[serde(default)]
    pub peer_groups: HashMap<String, PeerGroupConfig>,
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub dynamic_neighbors: Vec<DynamicNeighborConfig>,
    #[serde(default)]
    pub rpki: Option<RpkiConfig>,
    #[serde(default)]
    pub bmp: Option<BmpConfig>,
    #[serde(default)]
    pub mrt: Option<MrtConfig>,
    /// Local EVPN instances on this VTEP. Empty by default — only set
    /// when this daemon is acting as a leaf VTEP (Phase 2). Route
    /// reflector deployments leave this list empty; reflection has no
    /// dependency on local EVI state.
    #[serde(default)]
    pub evpn_instances: Vec<EvpnInstanceConfig>,
    /// Local Ethernet Segments this PE participates in (Gate 8
    /// multihoming foundation). Empty by default — single-homed
    /// VTEPs and route reflectors leave it empty. See ADR-0057 for
    /// the observable-without-enforcement scope decision.
    #[serde(default)]
    pub ethernet_segments: Vec<EthernetSegmentConfig>,
    /// Local IP-VRFs / L3VNIs this VTEP serves (Gate 9 symmetric
    /// Interface-less IRB, RFC 9136 §4.4.2). Empty by default —
    /// L2-only VTEPs and route reflectors leave it empty. See
    /// ADR-0058 for the IP-VRF lifecycle + Router MAC + observe-only
    /// device contract.
    #[serde(default)]
    pub evpn_ip_vrfs: Vec<EvpnIpVrfConfig>,
    /// General-purpose Linux unicast FIB export tables (ADR-0061).
    /// Empty by default — route-server / route-reflector deployments
    /// leave this empty and never spawn the ordinary unicast kernel
    /// FIB actor. Each entry is an explicit operator opt-in for one
    /// Linux route table; when at least one table is present the
    /// default-off FIB reconciler starts and programs unicast best
    /// routes into the configured non-reserved tables. Restart-required.
    #[serde(default)]
    pub fib_tables: Vec<FibTableConfig>,
    /// Apply Gate 8b BUM-suppression filters to the kernel
    /// (per-port `IFLA_BRPORT_*_FLOOD` triplet on CE-facing bridge
    /// ports). Default `false` — observe-only behavior preserved.
    /// Operators flip this to `true` once a privileged-runner soak
    /// validates kernel enforcement on their environment. The
    /// resolved enforcement plan is always reported via
    /// `DataplaneReport.bum_enforcement` regardless of this flag, so
    /// observability does not depend on the flip.
    #[serde(default)]
    pub apply_bum_enforcement: bool,
    /// Path of the config file (populated by `Config::load`, not serialized).
    #[serde(skip)]
    pub file_path: Option<PathBuf>,
}

/// Prefix-based dynamic neighbor range. Inbound connections from IPs
/// within `prefix` are automatically accepted and inherit configuration
/// from the referenced `peer_group`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DynamicNeighborConfig {
    /// IP prefix range (e.g., `10.0.0.0/24` or `2001:db8::/32`).
    pub prefix: String,
    /// Peer group whose config the dynamic peer inherits.
    pub peer_group: String,
    /// Expected remote ASN. 0 = accept any ASN from OPEN message.
    #[serde(default)]
    pub remote_asn: u32,
    /// Description applied to dynamic peers from this range.
    #[serde(default)]
    pub description: Option<String>,
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
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct Global {
    pub asn: u32,
    pub router_id: String,
    pub listen_port: u16,
    /// Cluster ID for route reflection (RFC 4456). Defaults to `router_id`
    /// when any neighbor is configured as a route reflector client.
    pub cluster_id: Option<String>,
    /// Maximum number of dynamic (prefix-based) neighbors. Default 100.
    #[serde(default)]
    pub dynamic_neighbor_limit: Option<u32>,
    /// Honor RFC 8326 `GRACEFUL_SHUTDOWN` community on inbound EBGP routes
    /// by appending an implicit chain-tail rule that sets `local_pref = 0`
    /// on tagged routes. Off by default. Per RFC 8326 §4 receivers
    /// SHOULD apply this on EBGP sessions; iBGP is unaffected because
    /// `LOCAL_PREF` is preserved within an AS and re-clobbering it here
    /// would overwrite values set legitimately upstream.
    ///
    /// SIGHUP hot-applies through the peer manager, recomputing EBGP
    /// runtime policies for already-managed peers.
    #[serde(default)]
    pub honor_graceful_shutdown: bool,
    /// Honor RFC 7999 `BLACKHOLE` community on inbound EBGP routes by
    /// appending an implicit chain-tail rule that preserves the `BLACKHOLE`
    /// marker and adds `NO_ADVERTISE` to keep the request local. Off by
    /// default; RFC 7999 §4 says receivers should not discard traffic without
    /// an explicit operator directive. This knob scopes the control-plane
    /// route; kernel discard/null-route installation requires the separate
    /// `install_blackhole_discard` opt-in.
    ///
    /// SIGHUP hot-applies through the peer manager, matching
    /// `honor_graceful_shutdown`.
    #[serde(default)]
    pub honor_blackhole: bool,
    /// Install local kernel blackhole routes for accepted EBGP best
    /// routes carrying RFC 7999 `BLACKHOLE`. Off by default and only
    /// effective when `honor_blackhole = true`. The first FIB slice is
    /// intentionally conservative: host routes only unless
    /// `allow_blackhole_broad_prefixes = true`, no overwrite of existing
    /// kernel routes, and daemon-owned cleanup on withdraw / shutdown.
    #[serde(default)]
    pub install_blackhole_discard: bool,
    /// Permit non-host BLACKHOLE routes to install kernel discard rows.
    /// Defaults to false so IPv4 `/32` and IPv6 `/128` are the only
    /// installable prefixes. This knob has no effect unless
    /// `install_blackhole_discard = true`.
    #[serde(default)]
    pub allow_blackhole_broad_prefixes: bool,
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
    /// Prometheus metrics HTTP listener address (e.g., "0.0.0.0:9179").
    /// If absent, no metrics HTTP server is started. Metrics are still
    /// collected for gRPC health and internal counters.
    #[serde(default)]
    pub prometheus_addr: Option<String>,
    pub log_format: String,
    #[serde(default)]
    pub grpc_tcp: Option<GrpcTcpListenerConfig>,
    #[serde(default)]
    pub grpc_uds: Option<GrpcUdsListenerConfig>,
    /// Optional birdwatcher-compatible looking glass HTTP server.
    #[serde(default)]
    pub looking_glass: Option<LookingGlassConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LookingGlassConfig {
    /// Listen address for the looking glass HTTP server (e.g., "0.0.0.0:8080").
    pub addr: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcTcpListenerConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub address: Option<String>,
    pub access_mode: Option<GrpcAccessModeConfig>,
    pub token_file: Option<String>,
    /// Server certificate (PEM file path). Required to enable mTLS.
    pub tls_cert_file: Option<String>,
    /// Server private key (PEM file path). Required when `tls_cert_file`
    /// is set.
    pub tls_key_file: Option<String>,
    /// CA certificate(s) (PEM file path) used to verify client
    /// certificates. Required when `tls_cert_file` is set — rustbgpd
    /// always enforces client-cert auth when TLS is on (no
    /// "TLS-without-mTLS" half-mode).
    pub tls_client_ca_file: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcUdsListenerConfig {
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub path: Option<String>,
    #[serde(default = "default_grpc_uds_mode")]
    pub mode: u32,
    pub access_mode: Option<GrpcAccessModeConfig>,
    pub token_file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrpcAccessModeConfig {
    ReadOnly,
    ReadWrite,
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
    /// Optional peer-group reference for inherited transport/policy defaults.
    pub peer_group: Option<String>,
    pub hold_time: Option<u16>,
    pub max_prefixes: Option<u32>,
    pub md5_password: Option<String>,
    pub ttl_security: Option<bool>,
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
    pub route_reflector_client: Option<bool>,
    /// Mark this eBGP neighbor as a transparent route-server client.
    ///
    /// When enabled, outbound unicast advertisements preserve the original
    /// next hop and suppress automatic local-AS prepend. Explicit export
    /// policy next-hop rewrites still apply.
    pub route_server_client: Option<bool>,
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
    /// Override log level for this peer: `"error"`, `"warn"`, `"info"`,
    /// `"debug"`, or `"trace"`.
    pub log_level: Option<String>,
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

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerGroupConfig {
    pub hold_time: Option<u16>,
    pub max_prefixes: Option<u32>,
    pub md5_password: Option<String>,
    pub ttl_security: Option<bool>,
    /// Address families to negotiate (e.g., `["ipv4_unicast", "ipv6_unicast"]`).
    #[serde(default)]
    pub families: Vec<String>,
    pub graceful_restart: Option<bool>,
    pub gr_restart_time: Option<u16>,
    pub gr_stale_routes_time: Option<u64>,
    pub llgr_stale_time: Option<u32>,
    pub local_ipv6_nexthop: Option<String>,
    pub route_reflector_client: Option<bool>,
    pub route_server_client: Option<bool>,
    pub remove_private_as: Option<String>,
    pub add_path: Option<AddPathConfig>,
    /// Override log level for peers in this group.
    pub log_level: Option<String>,
    #[serde(default)]
    pub import_policy: Vec<PolicyStatementConfig>,
    #[serde(default)]
    pub export_policy: Vec<PolicyStatementConfig>,
    #[serde(default)]
    pub import_policy_chain: Vec<String>,
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
    /// Named neighbor-set definitions for policy matching.
    #[serde(default)]
    pub neighbor_sets: HashMap<String, NeighborSetConfig>,
    /// Global import policy chain (references named definitions).
    #[serde(default)]
    pub import_chain: Vec<String>,
    /// Global export policy chain (references named definitions).
    #[serde(default)]
    pub export_chain: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NeighborSetConfig {
    #[serde(default)]
    pub addresses: Vec<String>,
    #[serde(default)]
    pub remote_asns: Vec<u32>,
    #[serde(default)]
    pub peer_groups: Vec<String>,
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
    /// CIDR prefix to match. Optional when any other match criterion is set.
    pub prefix: Option<String>,
    pub ge: Option<u8>,
    pub le: Option<u8>,
    /// Community match criteria, e.g. `["65001:100"]`, `["RT:65001:100"]`,
    /// or `["NO_EXPORT"]`.
    #[serde(default)]
    pub match_community: Vec<String>,
    /// `AS_PATH` regex pattern (Cisco/Quagga style: `_` = boundary anchor).
    pub match_as_path: Option<String>,
    /// Named neighbor-set to match against the evaluation peer.
    pub match_neighbor_set: Option<String>,
    /// Route source type to match: `"local"`, `"internal"`, or `"external"`.
    pub match_route_type: Option<String>,
    /// EVPN route type to match (RFC 7432 §7 / RFC 9136). Numeric: 1
    /// (EAD per-ES/per-EVI), 2 (MAC/IP), 3 (IMET), 4 (Ethernet Segment),
    /// 5 (IP Prefix). `None` means no constraint; non-EVPN routes never
    /// match a set value.
    pub match_evpn_route_type: Option<u8>,
    /// Minimum `AS_PATH` length (inclusive) to match.
    pub match_as_path_length_ge: Option<u32>,
    /// Maximum `AS_PATH` length (inclusive) to match.
    pub match_as_path_length_le: Option<u32>,
    /// Minimum `LOCAL_PREF` (inclusive) to match.
    pub match_local_pref_ge: Option<u32>,
    /// Maximum `LOCAL_PREF` (inclusive) to match.
    pub match_local_pref_le: Option<u32>,
    /// Minimum MED (inclusive) to match.
    pub match_med_ge: Option<u32>,
    /// Maximum MED (inclusive) to match.
    pub match_med_le: Option<u32>,
    /// Exact next-hop address to match.
    pub match_next_hop: Option<String>,
    /// RPKI validation state to match: `"valid"`, `"invalid"`, or `"not_found"`.
    pub match_rpki_validation: Option<String>,
    /// ASPA validation state to match: `"valid"`, `"invalid"`, or `"unknown"`.
    pub match_aspa_validation: Option<String>,
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

/// One local EVPN instance entry in TOML.
///
/// This is the *operator-facing* shape; resolution into the runtime
/// [`rustbgpd_evpn::EvpnInstance`] domain type happens in
/// [`Config::resolve_evpn_instances`]. Phase-2 fields (e.g. inbound
/// MAC-mobility knobs, IRB router-mac) will be added here without
/// reshaping the existing surface.
///
/// Field semantics:
///
/// - `vni` — 24-bit VXLAN VNI (RFC 8365 §5). Required, must be 1..=`16_777_215`.
/// - `rd` — Route Distinguisher (RFC 4364 §4.2). Required, parsed via
///   the wire crate's [`rustbgpd_wire::RouteDistinguisher`] textual
///   forms (`asn:val`, `ipv4:val`, 4-octet AS).
/// - `route_targets` — bidirectional Route Target list (RFC 4360 / RFC 5668).
///   Required, non-empty; each entry parses through
///   [`rustbgpd_evpn::RouteTarget`].
/// - `local_vtep_ip` — VXLAN tunnel source IP for this EVI. Required,
///   must be a unicast address (rejects unspecified / multicast /
///   loopback).
/// - `bridge` — optional Linux bridge name this EVI is bound to.
///   Reserved for the kernel-reconciliation slice; a bridge name is
///   accepted today and surfaces in `ListEvpnInstances` output, but
///   no kernel state is consumed yet.
/// - `advertise_svi_mac` — toggle for Type 2 origination of the SVI's
///   own MAC address (RFC 9135 §6.1). Off by default. Wired through to
///   origination once Type 2 origination lands.
/// - `sticky_macs` — list of MAC addresses (`aa:bb:cc:dd:ee:ff` form)
///   that, when learned by the local kernel, are originated with the
///   RFC 7432 §15.4 "sticky" bit set in the MAC Mobility extended
///   community. **Not** a static FDB: rustbgpd does not synthesize
///   Type 2s for these MACs; the flag only marks them on origination.
///   Empty by default. See ADR-0056.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvpnInstanceConfig {
    /// Local VNI for this instance (`1..=16_777_215`).
    pub vni: u32,
    /// Route Distinguisher (RFC 4364 §4.2). Textual form: `asn:val` or `ipv4:val`.
    pub rd: String,
    /// Bidirectional Route Targets — each entry applies to both import and export.
    pub route_targets: Vec<String>,
    /// VXLAN tunnel source IP for this EVI.
    pub local_vtep_ip: String,
    /// Optional Linux bridge name this EVI is bound to. Reserved for
    /// kernel reconciliation; carried on the schema today so the field
    /// doesn't churn between phases.
    #[serde(default)]
    pub bridge: Option<String>,
    /// Originate Type 2 routes for the SVI's own MAC address (RFC 9135 §6.1).
    /// Off by default.
    #[serde(default)]
    pub advertise_svi_mac: bool,
    /// MACs to be originated with the RFC 7432 §15.4 sticky bit when
    /// the local kernel learns them. Textual form: `aa:bb:cc:dd:ee:ff`
    /// (lowercase hex, six octets). Empty by default. See ADR-0056.
    #[serde(default)]
    pub sticky_macs: Vec<String>,
    /// Optional name of an `[[evpn_ip_vrfs]]` entry that binds this
    /// L2VNI into Gate 9 symmetric Interface-less IRB. When set, the
    /// daemon validates the referenced IP-VRF, originates local Type 5
    /// routes from that VRF's kernel table, and imports remote Type 5
    /// routes into the corresponding L3 FIB. Empty / unset means this
    /// L2VNI remains bridging-only. See ADR-0058.
    #[serde(default)]
    pub ip_vrf: Option<String>,
    /// Program ADR-0059 FDB nexthop groups for multi-homed Type 2 routes
    /// (aliasing-ECMP via `NDA_NH_ID` + `NHA_FDB`). Default `true`.
    /// Operators flip to `false` to roll a single L2VNI back to the
    /// single-dst FDB path (primary VTEP only, no kernel-side ECMP).
    /// Single-homed entries are unaffected — they always take the
    /// single-dst path regardless of this flag.
    ///
    /// **Restart-required.** `[[evpn_instances]]` is pinned at startup
    /// today (config reload reverts edits to the instance table), so
    /// changing this knob requires a daemon restart. Across a
    /// restart with stale tagged FDB rows from a prior run, the
    /// orphaned rows stay in place until the next periodic drift
    /// cycle (≤ 60 s, slice 3.5 PR 2). The diff layer is written so
    /// that a future runtime instance-mutation surface (RPC etc.)
    /// would converge cleanly via the standard `FdbNhg → SingleDst`
    /// transition, but operators cannot drive that path today.
    #[serde(default = "default_enabled")]
    pub apply_aliasing_ecmp: bool,
}

/// One IP-VRF / L3VNI tenant served by this VTEP (Gate 9 symmetric
/// Interface-less IRB, RFC 9136 §4.4.2).
///
/// Each entry binds:
///
/// - A configured **L3VNI** for the VXLAN encapsulation.
/// - A Linux **VRF device** (`vrf_device`) whose route table the
///   daemon watches for local-route → Type 5 origination.
/// - A Linux **L3 VXLAN device** (`l3vxlan_device`) the daemon
///   programs FIB entries through.
/// - A **Router MAC** advertised on every outbound Type 5 via the
///   RFC 9135 §4.2 / RFC 9136 Router MAC extended community. The
///   value is operator-supplied (not auto-derived) — see ADR-0058
///   §4 for why.
///
/// **Operator prerequisite for the follow-on dataplane slices**: the
/// VRF device and the L3 VXLAN device must be pre-created (the daemon
/// will not own their lifecycle — observe-only, same as L2 bridges and
/// L2 VXLAN devices today). The planned reconciler will run the
/// readiness predicates in ADR-0058 §3 before originating or installing
/// anything; Gate 9's foundation slice only parses and validates the
/// schema.
///
/// ## Fields
///
/// - `name` — operator-facing handle, used by
///   `[[evpn_instances]].ip_vrf` to bind L2VNIs to this IP-VRF.
///   `^[a-zA-Z][a-zA-Z0-9_-]*$`, unique across `[[evpn_ip_vrfs]]`.
/// - `vni` — L3VNI in `1..=16_777_215`. Unique across both
///   `[[evpn_instances]]` and `[[evpn_ip_vrfs]]` — an L2VNI and an
///   L3VNI cannot share a number.
/// - `rd` — Route Distinguisher (`asn:value` or `ipv4:value`).
/// - `route_targets` — bidirectional RTs applied to both import
///   and export. Tenant identity on the wire.
/// - `local_vtep_ip` — VXLAN source IP for outbound Type 5
///   `NEXT_HOP`. Typically equals the per-`[[evpn_instances]]`
///   `local_vtep_ip`; explicitly carried so an operator with split
///   VTEP IPs per VRF can express that.
/// - `router_mac` — Router MAC value advertised on every outbound
///   Type 5 and asserted against the kernel-side L3 VXLAN device's
///   MAC. `aa:bb:cc:dd:ee:ff` form.
/// - `vrf_device` — Linux VRF device name. Observe-only.
/// - `l3vxlan_device` — Linux L3 VXLAN device name. Observe-only.
/// - `table_id` — VRF route table id. The follow-on Linux readiness
///   probe will cross-check it against `vrf_device`'s
///   `IFLA_VRF_TABLE`. Observe-only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvpnIpVrfConfig {
    /// Operator-facing tenant handle.
    pub name: String,
    /// L3VNI (`1..=16_777_215`).
    pub vni: u32,
    /// Route Distinguisher (`asn:value` or `ipv4:value`).
    pub rd: String,
    /// Bidirectional Route Targets — applied to both import and export.
    pub route_targets: Vec<String>,
    /// VXLAN tunnel source IP for outbound Type 5 `NEXT_HOP`.
    pub local_vtep_ip: String,
    /// Router MAC value (RFC 9135 §4.2 / RFC 9136 Router MAC ext-community).
    /// `aa:bb:cc:dd:ee:ff` form, hex (case-insensitive).
    pub router_mac: String,
    /// Linux VRF device name (operator-managed, observe-only).
    pub vrf_device: String,
    /// Linux L3 VXLAN device name (operator-managed, observe-only).
    pub l3vxlan_device: String,
    /// VRF route table id, cross-checked against `vrf_device`'s
    /// `IFLA_VRF_TABLE`.
    pub table_id: u32,
}

/// Explicit opt-in for ordinary unicast kernel FIB export.
///
/// ADR-0061 keeps the general FIB path separate from EVPN L3VNI and
/// RFC 7999 BLACKHOLE discard. The operator must name every Linux
/// route table rustbgpd may eventually write to; the daemon never
/// silently takes over `main`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FibTableConfig {
    /// Operator-facing handle for future status output and CLI/API
    /// filters. Unique across `[[fib_tables]]`.
    pub name: String,
    /// Linux route table id. Reserved tables are rejected at config
    /// validation time; use an explicit non-reserved table for the
    /// first general-FIB tranche.
    pub table_id: u32,
    /// Kernel route metric / priority to use for daemon-owned rows.
    /// Required so coexistence with static routes and other routing
    /// daemons is a conscious operator choice rather than an implicit
    /// default.
    pub metric: u32,
    /// Address families eligible for future install. Defaults to both
    /// IPv4 and IPv6 unicast when the `[[fib_tables]]` block itself is
    /// present.
    #[serde(default = "default_fib_families")]
    pub families: Vec<String>,
}

fn default_fib_families() -> Vec<String> {
    vec!["ipv4_unicast".to_string(), "ipv6_unicast".to_string()]
}

/// One Ethernet Segment this PE participates in (Gate 8).
///
/// Each entry produces:
///
/// - One Type 4 ES route announcing this PE as a candidate for the
///   ESI's per-`(ESI, VNI)` DF election.
/// - One Type 1 EAD-per-ES route signalling ES liveness.
/// - One Type 1 EAD-per-EVI route per `member_vni` carrying the
///   role-aware ESI Label flag.
///
/// **Operator prerequisite**: every member VNI must already be
/// declared in `[[evpn_instances]]`. Members referencing unknown
/// VNIs are rejected at config-load time.
///
/// ## Fields
///
/// - `esi` — 10-byte Ethernet Segment Identifier in canonical
///   `XX:XX:XX:XX:XX:XX:XX:XX:XX:XX` form. Must be exactly 10
///   colon-separated hex bytes. Type 0 (all zero) is rejected
///   because Type 0 means "single-homed" and thus shouldn't appear
///   in a multihoming config.
/// - `member_vnis` — non-empty set of VNIs that participate in
///   this ES. Each member contributes a slot to the per-(ESI, VNI)
///   DF election.
/// - `df_preference` — Designated Forwarder preference value
///   reserved for the future preference-based DF Election algorithm
///   (RFC 8584 §3.1). Gate 8 accepts only the default 32768 because
///   default-modulo ignores preference.
/// - `df_algorithm` — DF election algorithm string. Gate 8 accepts
///   only `"default-modulo"` (RFC 7432 §8.5). The domain model keeps
///   `"highest-random-weight"` and `"preference-based"` variants for
///   wire/forward compatibility, but config rejects them until the
///   runtime implements those algorithms. Default `"default-modulo"`.
/// - `originator_ip` — IP this PE uses as the Type 4 ES route's
///   originator address. Typically equals `evpn_instances[].local_vtep_ip`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthernetSegmentConfig {
    /// 10-byte ESI in colon-separated hex (`XX:XX:XX:XX:XX:XX:XX:XX:XX:XX`).
    pub esi: String,
    /// VNIs participating in this ES. Each must already be declared
    /// in `[[evpn_instances]]`.
    pub member_vnis: Vec<u32>,
    /// DF preference (RFC 8584 §3.1). Default 32768.
    #[serde(default = "default_df_preference")]
    pub df_preference: u32,
    /// DF algorithm string. Default `"default-modulo"`.
    #[serde(default = "default_df_algorithm")]
    pub df_algorithm: String,
    /// Originator IP carried on the Type 4 ES route.
    pub originator_ip: String,
}

fn default_df_preference() -> u32 {
    32_768
}

fn default_df_algorithm() -> String {
    "default-modulo".to_string()
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
    #[error("invalid neighbor config for {address}: {field}: {reason}")]
    InvalidNeighborConfig {
        address: String,
        field: String,
        reason: String,
    },
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
    #[error("undefined peer_group {name:?}")]
    UndefinedPeerGroup { name: String },
    #[error("invalid neighbor set: {reason}")]
    InvalidNeighborSet { reason: String },
    #[error("invalid BMP collector config: {reason}")]
    InvalidBmpCollector { reason: String },
    #[error("invalid MRT config: {reason}")]
    InvalidMrtConfig { reason: String },
    #[error("invalid remove_private_as config: {reason}")]
    InvalidRemovePrivateAs { reason: String },
    #[error("invalid log_level {value:?}: expected error, warn, info, debug, or trace")]
    InvalidLogLevel { value: String },
    #[error("invalid dynamic neighbor config: {reason}")]
    InvalidDynamicNeighbor { reason: String },
    #[error("invalid EVPN instance config: {reason}")]
    InvalidEvpnInstance { reason: String },
    #[error("invalid Ethernet Segment config: {reason}")]
    InvalidEthernetSegment { reason: String },
    #[error("invalid EVPN IP-VRF config: {reason}")]
    InvalidEvpnIpVrf { reason: String },
    #[error("invalid FIB table config: {reason}")]
    InvalidFibTable { reason: String },
}
