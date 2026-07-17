use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::PathBuf;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use rustbgpd_wire::BgpRole;

/// Sourced from the fsm crate so the daemon hold-time default lives in
/// exactly one place (completes the LAN-211 dedup; `PeerConfig::default()`
/// and the gRPC send-hold-time validation use the same constant).
pub(super) const DEFAULT_HOLD_TIME: u16 = rustbgpd_fsm::DEFAULT_HOLD_TIME;
/// Runtime cap used when `global.dynamic_neighbor_limit` is omitted.
pub(super) const DEFAULT_DYNAMIC_NEIGHBOR_LIMIT: u32 = 100;
pub(super) const DEFAULT_CONNECT_RETRY_SECS: u32 = 5;
pub(super) const BGP_PORT: u16 = 179;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Daemon-wide BGP settings (ASN, router ID, listeners, telemetry).
    pub global: Global,
    /// Security policy and authorization configuration. Empty by
    /// default so existing deployments keep legacy listener-level
    /// authorization until operators opt into later ADR-0064 slices.
    #[serde(default)]
    pub security: SecurityConfig,
    /// Statically configured BGP neighbors.
    #[serde(default)]
    pub neighbors: Vec<Neighbor>,
    /// Named peer groups providing inherited defaults for neighbors.
    #[serde(default)]
    pub peer_groups: HashMap<String, PeerGroupConfig>,
    /// Routing policy: inline statements, named definitions, chains,
    /// and `.rpol` files.
    #[serde(default)]
    pub policy: PolicyConfig,
    /// Prefix-based dynamic neighbor ranges.
    #[serde(default)]
    pub dynamic_neighbors: Vec<DynamicNeighborConfig>,
    /// RPKI route-origin validation via RTR cache servers.
    #[serde(default)]
    pub rpki: Option<RpkiConfig>,
    /// BGP Monitoring Protocol (RFC 7854) export.
    #[serde(default)]
    pub bmp: Option<BmpConfig>,
    /// Periodic MRT RIB dumps.
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
    /// Optional rustbgpd-managed EVPN Linux netdev lifecycle
    /// (ADR-0091). Empty by default — existing deployments keep the
    /// operator-provisioned / observe-only contract. Configured rows opt
    /// into class-scoped bridge, fixed-VNI VXLAN, SVD VXLAN, VLAN upper,
    /// VRF, and L3VXLAN create/adopt/reap.
    #[serde(default)]
    pub managed_netdevs: ManagedNetdevsConfig,
    /// Named BFD timing profiles (RFC 5880/5881, ADR-0067) referenced by
    /// `[neighbors.bfd]` / `[peer_groups.<name>.bfd]`.
    #[serde(default)]
    pub bfd_profiles: Vec<BfdProfileConfig>,
    /// Apply Gate 8b BUM-suppression filters to the kernel
    /// (per-port `IFLA_BRPORT_*_FLOOD` triplet on CE-facing bridge
    /// ports). **Default `true` since v0.23.0** — kernel enforcement
    /// is the production posture after the Gate 8b MAC-churn 24h soak
    /// (2026-05-16, postmortem `docs/soaks/soak-gate8b-mac-churn-24h.md`)
    /// and the M37 local-origination 24h soak (2026-05-19,
    /// postmortem `docs/soaks/soak-m37-local-origination-churn-24h.md`)
    /// both passed clean. Operators who need the prior observe-only
    /// behavior can still opt out explicitly with
    /// `apply_bum_enforcement = false`; the deserializer honors
    /// explicit values unchanged. The resolved enforcement plan is
    /// always reported via `DataplaneReport.bum_enforcement`
    /// regardless of this flag, so observability does not depend on
    /// the flip.
    #[serde(default = "default_enabled")]
    pub apply_bum_enforcement: bool,
    /// Durable event-history outbox (ADR-0072). **Opt-in (default off)
    /// as of v0.32.0**; set `[event_history].enabled = true` for
    /// restart-safe event replay. All fields are restart-required.
    #[serde(default)]
    pub event_history: EventHistoryConfig,
    /// Path of the config file (populated by `Config::load`, not serialized).
    #[serde(skip)]
    pub file_path: Option<PathBuf>,
}

/// Durable event-history outbox configuration (ADR-0072).
///
/// All fields are restart-required — toggling the outbox or its
/// bounds requires a daemon restart. The reload matrix documents the
/// classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EventHistoryConfig {
    /// Enable the durable outbox. **Default `false` (opt-in as of
    /// v0.32.0).** When `false`, EHM runs in pass-through mode (live
    /// broadcasts only, no persistence) and `SubscribeFromEvent`
    /// returns `FAILED_PRECONDITION`. Set `true` for restart-safe event
    /// replay — it costs memory / CPU / disk (see `docs/BENCHMARKS.md`).
    #[serde(default = "default_event_history_enabled")]
    pub enabled: bool,
    /// Fail to start if the events DB cannot be opened or recovered.
    /// Default `false` — degrade to pass-through with the
    /// `bgp_event_outbox_degraded` flag set.
    #[serde(default)]
    pub required: bool,
    /// Path of `events.db` relative to `runtime_state_dir`.
    /// Empty string ⇒ `<runtime_state_dir>/events.db`.
    #[serde(default = "default_event_history_path")]
    pub path: String,
    /// Hard count cap on retained events.
    #[serde(default = "default_event_history_max_events")]
    pub max_events: u64,
    /// Byte retention trigger on `events.db` + WAL combined. `SQLite`
    /// may reuse freed pages rather than shrink the main DB immediately.
    #[serde(default = "default_event_history_max_bytes")]
    pub max_bytes: u64,
    /// `SQLite` `PRAGMA synchronous` mode. `full` (default) fsyncs
    /// per commit; `normal` checkpoints periodically and trades a
    /// small crash window for throughput.
    #[serde(default = "default_event_history_synchronous")]
    pub synchronous: String,
    /// Behavior on full producer queue. v1 only supports `drop`;
    /// `block` is reserved for a future ADR. ADR-0072 documents the
    /// rationale for uniform best-effort drop.
    #[serde(default = "default_event_history_overflow")]
    pub overflow: String,
    /// Per-producer mpsc capacity.
    #[serde(default = "default_event_history_queue_capacity")]
    pub queue_capacity: usize,
    /// Batch-commit size threshold.
    #[serde(default = "default_event_history_batch_size")]
    pub batch_size: usize,
    /// Batch-commit time threshold (milliseconds).
    #[serde(default = "default_event_history_batch_interval_ms")]
    pub batch_interval_ms: u64,
}

impl Default for EventHistoryConfig {
    fn default() -> Self {
        Self {
            enabled: default_event_history_enabled(),
            required: false,
            path: default_event_history_path(),
            max_events: default_event_history_max_events(),
            max_bytes: default_event_history_max_bytes(),
            synchronous: default_event_history_synchronous(),
            overflow: default_event_history_overflow(),
            queue_capacity: default_event_history_queue_capacity(),
            batch_size: default_event_history_batch_size(),
            batch_interval_ms: default_event_history_batch_interval_ms(),
        }
    }
}

// Default-OFF as of v0.32.0: the durable outbox is opt-in. v0.32.0 bgperf2
// benchmarking showed the always-on cost was material — ~62 MB RSS and roughly
// double the peak CPU at 2p/100k — a tax every operator paid before asking for
// replay semantics. A routing daemon should be fast and lean by default;
// operators who want restart-safe event replay set `[event_history].enabled =
// true`. The ADR-0072 implementation is unchanged — only the default posture.
fn default_event_history_enabled() -> bool {
    false
}
fn default_event_history_path() -> String {
    String::new()
}
fn default_event_history_max_events() -> u64 {
    100_000
}
fn default_event_history_max_bytes() -> u64 {
    256_000_000
}
fn default_event_history_synchronous() -> String {
    "full".to_string()
}
fn default_event_history_overflow() -> String {
    "drop".to_string()
}
fn default_event_history_queue_capacity() -> usize {
    4096
}
fn default_event_history_batch_size() -> usize {
    1024
}
fn default_event_history_batch_interval_ms() -> u64 {
    50
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct SecurityConfig {
    /// gRPC authorization policy (ADR-0064).
    #[serde(default)]
    pub grpc: GrpcSecurityConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(deny_unknown_fields)]
pub struct GrpcSecurityConfig {
    /// Role-enforcement mode: `"legacy"` or `"tier"`.
    #[serde(default)]
    pub enforcement: GrpcEnforcementConfig,
    /// Per-principal role assignments (principal name -> role).
    #[serde(default)]
    pub roles: HashMap<String, GrpcRoleConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum GrpcEnforcementConfig {
    /// Preserve pre-v0.24.0 role authorization behavior. Listener
    /// `max_tier` caps still apply in this mode, but per-principal
    /// role ceilings are not enforced. Operators who need this
    /// behavior after v0.24.0 must set `enforcement = "legacy"`
    /// explicitly.
    Legacy,
    /// Enforce per-principal role ceilings in addition to listener
    /// `max_tier` caps. **Default since v0.24.0** after the
    /// migration window documented in `docs/CONFIGURATION.md`.
    /// Existing deployments that do not configure
    /// `[security.grpc.roles]` will fail validation at startup with
    /// a message pointing at the migration checklist; operators who
    /// have not staged their config can opt back into `legacy`
    /// explicitly.
    #[default]
    Tier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrpcRoleConfig {
    Observer,
    Automation,
    Operator,
}

/// Prefix-based dynamic neighbor range. Inbound connections from IPs
/// within `prefix` are automatically accepted and inherit configuration
/// from the referenced `peer_group`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
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
    /// TCP-AO keyring installed as prefix MKTs on the passive listener and
    /// inherited accepted sockets. Nonpreferred successor keys may be appended
    /// live with SIGHUP. Dynamic ranges never inherit authentication from their
    /// peer group.
    #[serde(default)]
    pub tcp_ao: Option<TcpAoKeyringConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RpkiConfig {
    /// RTR cache servers to connect to.
    #[serde(default)]
    pub cache_servers: Vec<CacheServer>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CacheServer {
    /// RTR cache endpoint as `host:port`.
    pub address: String,
    /// RTR refresh interval in seconds. Default 3600.
    #[serde(default = "default_rpki_refresh")]
    pub refresh_interval: u64,
    /// RTR retry interval in seconds. Default 600.
    #[serde(default = "default_rpki_retry")]
    pub retry_interval: u64,
    /// RTR expire interval in seconds. Default 7200.
    #[serde(default = "default_rpki_expire")]
    pub expire_interval: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BmpConfig {
    /// `sysName` information TLV sent in the BMP INITIATION message.
    #[serde(default = "default_bmp_sys_name")]
    pub sys_name: String,
    /// `sysDescr` information TLV sent in the BMP INITIATION message.
    #[serde(default)]
    pub sys_descr: String,
    /// BMP collectors to stream route-monitoring data to.
    #[serde(default)]
    pub collectors: Vec<BmpCollector>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BmpCollector {
    /// Collector endpoint as `host:port`.
    pub address: String,
    /// Seconds between reconnect attempts. Default 30.
    #[serde(default = "default_bmp_reconnect")]
    pub reconnect_interval: u64,
    /// Which route-monitoring streams this collector receives.
    /// Default preserves pre-RFC 8671 behavior: pre-policy Adj-RIB-In only.
    #[serde(default = "default_bmp_monitor")]
    pub monitor: Vec<BmpMonitorView>,
    /// BMP wire version framed for this collector: 3 (RFC 7854,
    /// default) or 4 (TLV framing per draft-ietf-grow-bmp-tlv-20 —
    /// pre-IANA; code points may renumber at RFC publication).
    #[serde(default = "default_bmp_version")]
    pub version: u8,
}

/// A BMP route-monitoring stream selection (per collector).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BmpMonitorView {
    /// Pre-policy Adj-RIB-In route monitoring (RFC 7854).
    RibInPre,
    /// Post-policy Adj-RIB-Out route monitoring (RFC 8671).
    RibOutPost,
    /// Loc-RIB instance monitoring with collector-connect table sync
    /// (RFC 9069).
    LocRib,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MrtConfig {
    /// Directory MRT dump files are written to.
    pub output_dir: String,
    /// Seconds between RIB dumps. Default 7200.
    #[serde(default = "default_mrt_dump_interval")]
    pub dump_interval: u64,
    /// Gzip-compress dump files.
    #[serde(default)]
    pub compress: bool,
    /// Dump filename prefix. Default `"rib"`.
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

fn default_bmp_version() -> u8 {
    3
}

fn default_bmp_monitor() -> Vec<BmpMonitorView> {
    vec![BmpMonitorView::RibInPre]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[allow(clippy::struct_excessive_bools)]
#[serde(deny_unknown_fields)]
pub struct Global {
    /// Local autonomous system number.
    pub asn: u32,
    /// BGP router ID in IPv4 dotted-quad form (e.g. `"192.0.2.1"`).
    pub router_id: String,
    /// TCP listen port for inbound BGP sessions (conventionally 179).
    pub listen_port: u16,
    /// Cluster ID for route reflection (RFC 4456). Defaults to `router_id`
    /// when any neighbor is configured as a route reflector client.
    pub cluster_id: Option<String>,
    /// Maximum number of dynamic (prefix-based) neighbors. Default 100.
    #[serde(default)]
    pub dynamic_neighbor_limit: Option<u32>,
    /// Number of tokio runtime worker threads. Unset (the default) caps to
    /// `min(available CPU parallelism, 8)`: spawning one worker per core on a
    /// high-core-count host over-provisions the async runtime (each worker
    /// reserves a stack and a scheduler slot) for what is an I/O-bound daemon,
    /// not a CPU-bound one. Capping reduces virtual-address reservation and
    /// scheduler footprint — same-host benchmarks showed it to be RSS-neutral,
    /// so this is runtime right-sizing, not a memory optimization. A value of `0` is
    /// treated as unset. The `RUSTBGPD_WORKER_THREADS` environment variable
    /// overrides this field. **Restart-required:** the runtime is built once at
    /// startup, so a change only takes effect on the next restart, not on SIGHUP.
    #[serde(default)]
    pub worker_threads: Option<usize>,
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
    /// ADR-0066 multipath-relax (FRR's `bgp bestpath as-path multipath-relax`).
    /// When `true`, unicast ECMP groups equal-cost candidates by `AS_PATH`
    /// *length* instead of an exact `AS_PATH` match, so equal-length paths through
    /// different ASes co-install as multipath. Off by default (exact match). It
    /// is a best-path-wide knob, so it lives here rather than per
    /// `[[fib_tables]]`; it is inert unless a table sets `maximum_paths`,
    /// `maximum_paths_ebgp`, or `maximum_paths_ibgp` above 1.
    #[serde(default)]
    pub multipath_relax: bool,
    /// ADR-0068 weighted multipath (FRR's `bgp bestpath bandwidth`). When `true`,
    /// unicast ECMP next-hops are weighted by their Link Bandwidth Extended
    /// Community (draft-ietf-idr-link-bandwidth) when the whole equal-cost group
    /// carries one; otherwise they stay equal-cost. Off by default. Like
    /// `multipath_relax` it is a best-path-wide knob and is inert unless a table
    /// sets `maximum_paths`, `maximum_paths_ebgp`, or `maximum_paths_ibgp` above
    /// 1.
    #[serde(default)]
    pub link_bandwidth_weighted: bool,
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
    /// Publish one durable, daemon-private MRT warm-cache checkpoint during
    /// coordinated shutdown. Off by default. This tranche only publishes the
    /// checkpoint and a generation-bound restart marker; boot never loads or
    /// serves routes from the cache.
    ///
    /// The checkpoint directory is fixed at
    /// `<runtime_state_dir>/warm-bundle-v1`. The setting is read at startup;
    /// changing it requires a daemon restart.
    #[serde(default)]
    pub warm_cache_checkpoint_on_shutdown: bool,
    /// Directory for daemon-owned runtime state files.
    #[serde(default = "default_runtime_state_dir")]
    pub runtime_state_dir: String,
    /// Telemetry and control-plane listeners (Prometheus, gRPC,
    /// looking glass) plus logging format.
    pub telemetry: TelemetryConfig,
}

fn default_runtime_state_dir() -> String {
    "/var/lib/rustbgpd".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TelemetryConfig {
    /// Prometheus metrics HTTP listener address (e.g., "0.0.0.0:9179").
    /// If absent, no metrics HTTP server is started. Metrics are still
    /// collected for gRPC health and internal counters.
    #[serde(default)]
    pub prometheus_addr: Option<String>,
    /// Log output format (`"json"`).
    pub log_format: String,
    /// gRPC TCP listener.
    #[serde(default)]
    pub grpc_tcp: Option<GrpcTcpListenerConfig>,
    /// gRPC Unix-domain-socket listener.
    #[serde(default)]
    pub grpc_uds: Option<GrpcUdsListenerConfig>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrpcTcpListenerConfig {
    /// Enable this listener. Default `true`.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Listen address (e.g. `"127.0.0.1:50051"`).
    pub address: Option<String>,
    /// Listener access mode: `"read_only"` or `"read_write"`.
    pub access_mode: Option<GrpcAccessModeConfig>,
    /// ADR-0064 per-method listener ceiling. When omitted, the
    /// listener preserves the compatibility cap implied by
    /// `access_mode`.
    pub max_tier: Option<GrpcMaxTierConfig>,
    /// Path to a bearer-token file for client authentication.
    pub token_file: Option<String>,
    /// Stable audit principal label for non-mTLS bearer-token
    /// listeners. Native mTLS listeners derive the audit principal
    /// from the client certificate instead.
    pub principal: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct GrpcUdsListenerConfig {
    /// Enable this listener. Default `true`.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Unix socket path.
    pub path: Option<String>,
    /// Socket file mode bits. Default `0o600`.
    #[serde(default = "default_grpc_uds_mode")]
    pub mode: u32,
    /// Listener access mode: `"read_only"` or `"read_write"`.
    pub access_mode: Option<GrpcAccessModeConfig>,
    /// ADR-0064 per-method listener ceiling. When omitted, the
    /// listener preserves the compatibility cap implied by
    /// `access_mode`.
    pub max_tier: Option<GrpcMaxTierConfig>,
    /// Path to a bearer-token file for client authentication.
    pub token_file: Option<String>,
    /// Stable audit principal label for this Unix-domain-socket
    /// listener. Filesystem permissions authenticate the socket, but
    /// this gives audit logs an operator-controlled identity.
    pub principal: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrpcAccessModeConfig {
    ReadOnly,
    ReadWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum GrpcMaxTierConfig {
    Read,
    SensitiveRead,
    Mutating,
    OperatorOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum EvpnDuplicateMacActionConfig {
    /// Count/report threshold crossings but do not suppress local
    /// originations. This preserves pre-quarantine behavior.
    #[default]
    Detect,
    /// Withdraw and suppress locally-originated Type 2 routes for the
    /// quarantined `(VNI, MAC)` until `recovery_seconds` elapses.
    SuppressLocal,
}

/// Per-`[[evpn_instances]]` RFC 7432 §15.1 duplicate-MAC detector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvpnDuplicateMacDetectionConfig {
    /// Action to take when `threshold` moves occur within
    /// `window_seconds`. Defaults to detect-only.
    #[serde(default)]
    pub action: EvpnDuplicateMacActionConfig,
    /// RFC 7432 M window in seconds. Default 180.
    #[serde(default = "default_duplicate_mac_window_seconds")]
    pub window_seconds: u64,
    /// RFC 7432 N move threshold. Default 5.
    #[serde(default = "default_duplicate_mac_threshold")]
    pub threshold: u32,
    /// Suppression hold time in seconds for `suppress_local`. Default
    /// 540 (three M windows). Must still be non-zero in detect-only mode
    /// so reloads can flip the action without introducing invalid state.
    #[serde(default = "default_duplicate_mac_recovery_seconds")]
    pub recovery_seconds: u64,
}

impl Default for EvpnDuplicateMacDetectionConfig {
    fn default() -> Self {
        Self {
            action: EvpnDuplicateMacActionConfig::default(),
            window_seconds: default_duplicate_mac_window_seconds(),
            threshold: default_duplicate_mac_threshold(),
            recovery_seconds: default_duplicate_mac_recovery_seconds(),
        }
    }
}

fn default_enabled() -> bool {
    true
}

fn default_duplicate_mac_window_seconds() -> u64 {
    rustbgpd_evpn::DEFAULT_DUPLICATE_MAC_WINDOW.as_secs()
}

const fn default_duplicate_mac_threshold() -> u32 {
    rustbgpd_evpn::DEFAULT_DUPLICATE_MAC_THRESHOLD
}

fn default_duplicate_mac_recovery_seconds() -> u64 {
    rustbgpd_evpn::DEFAULT_DUPLICATE_MAC_RECOVERY.as_secs()
}

fn default_grpc_uds_mode() -> u32 {
    0o600
}

#[derive(Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Neighbor {
    /// Peer IP address (IPv4 or IPv6).
    pub address: String,
    /// Interface name required for IPv6 link-local / BGP unnumbered peers.
    pub interface: Option<String>,
    /// Peer autonomous system number. Equal to `global.asn` for iBGP.
    pub remote_asn: u32,
    /// Free-form operator description.
    pub description: Option<String>,
    /// Optional peer-group reference for inherited transport/policy defaults.
    pub peer_group: Option<String>,
    /// Hold time in seconds: 0 disables, otherwise >= 3. Default 90.
    pub hold_time: Option<u16>,
    /// Send hold time in seconds (RFC 9687): tear the session down when
    /// the peer stops draining its TCP socket for this long. 0 disables.
    /// Non-zero values must be greater than the effective `hold_time`
    /// (RFC 9687 §4.4). Default: the greater of 480s (8 minutes) or 2×
    /// the effective `hold_time` (RFC 9687 §6).
    pub send_hold_time: Option<u32>,
    /// Slow-peer detection: backlog threshold as a percentage (1-100)
    /// of the outbound writer buffer. The peer is a slow-peer candidate
    /// while its buffered outbound frames stay at or above this
    /// fraction. Default: 50.
    pub slow_peer_threshold_pct: Option<u8>,
    /// Slow-peer detection: how long (seconds) the backlog must stay
    /// above `slow_peer_threshold_pct` before the peer is flagged slow
    /// (status flag, warn log, `bgp_peer_slow` metric). 0 disables
    /// detection. Default: 30.
    pub slow_peer_duration: Option<u32>,
    /// Move a flagged-slow peer onto the per-peer (ungrouped) update
    /// path so it stops holding back its update-group's shared encode;
    /// it regroups when the flag clears. Requires detection
    /// (`slow_peer_duration` > 0). Default: false (detection alone is
    /// purely observational).
    pub slow_peer_isolation: Option<bool>,
    /// Maximum prefixes accepted from this peer before the session is
    /// torn down. Unset = unlimited.
    pub max_prefixes: Option<u32>,
    /// Maximum unique IPv4-unicast prefixes accepted from this peer
    /// before the session is torn down with Cease/1. Enforced
    /// independently of `max_prefixes` (ADR-0108). Unset = unlimited.
    pub max_prefixes_ipv4: Option<u32>,
    /// Maximum unique IPv6-unicast prefixes accepted from this peer
    /// before the session is torn down with Cease/1. Enforced
    /// independently of `max_prefixes` (ADR-0108). Unset = unlimited.
    pub max_prefixes_ipv6: Option<u32>,
    /// TCP MD5 signature password (RFC 2385).
    pub md5_password: Option<String>,
    /// Static-neighbor TCP-AO (RFC 5925) keyring. Installed on active-open
    /// sockets and the passive listener when configured. Nonpreferred
    /// successor keys may be appended live with SIGHUP.
    pub tcp_ao: Option<TcpAoKeyringConfig>,
    /// Single-hop BFD (RFC 5880/5881) attachment, referencing a
    /// `[[bfd_profiles]]` entry. Presence enables BFD for this neighbor.
    pub bfd: Option<BfdConfig>,
    /// GTSM TTL security (RFC 5082): require TTL 255 from a directly
    /// connected peer.
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
    /// Optimal Route Reflection vantage point (RFC 9107): an IP address
    /// identifying this client's IGP location as a BGP-LS topology node
    /// (a link interface/neighbor address, or an address covered by a
    /// Prefix NLRI). Requires `route_reflector_client = true` (iBGP).
    pub orr_vantage: Option<IpAddr>,
    /// Mark this eBGP neighbor as a transparent route-server client.
    ///
    /// When enabled, outbound unicast advertisements preserve the original
    /// next hop and suppress automatic local-AS prepend. Explicit export
    /// policy next-hop rewrites still apply.
    pub route_server_client: Option<bool>,
    /// RFC 7947 §2.3.2 per-client best-path for this route-server
    /// client: when the Loc-RIB best is denied by this peer's export
    /// policy, advertise the best export-policy-permitted candidate
    /// instead of hiding the prefix (path-hiding mitigation for clients
    /// without Add-Path). Requires `route_server_client = true`.
    /// Families where the session negotiates Add-Path send use Add-Path
    /// instead — the negotiated capability outranks this fallback.
    pub per_client_best: Option<bool>,
    /// Pre-policy `NEXT_HOP` ownership enforcement for this route-server
    /// client (ADR-0107, RFC 7948 §4.8). `"strict_peer"` accepts a
    /// unicast announcement only when every address component of its
    /// decoded wire next-hop identity is the advertising session's own
    /// address; non-conforming announcements are rejected before import
    /// policy runs, fail-closed and treat-as-withdraw for previously
    /// accepted identities. Requires `route_server_client = true`.
    /// Unset = no ownership enforcement (RFC 7947 transparency only).
    pub next_hop_ownership: Option<NextHopOwnershipConfig>,
    /// Honor RFC 1997 `NO_EXPORT`/`NO_EXPORT_SUBCONFED` at egress: routes
    /// received with either community are not advertised to this neighbor
    /// when it is eBGP. Default: `true` unless `route_server_client` is
    /// set (route servers pass communities through transparently and let
    /// clients enforce them). Set explicitly to override either default.
    pub interpret_rfc1997: Option<bool>,
    /// Interpret RFC 7947 §2.3.2 route-server control communities set by
    /// this neighbor: per-target announce suppression (`0:PEER`,
    /// `RS:0:PEER`), announce-only (`RS:PEER` / `RS:1:PEER` overriding
    /// `0:RS` / `RS:0:0`), and prepend toward a target
    /// (`RS:101|102|103:PEER`, RFC 8195 large-community forms). Matched
    /// control communities are scrubbed from this session's outbound
    /// announcements. Default: `false` — opt-in per member, because an
    /// enabled session is excluded from update-group sharing (per-target
    /// outcomes cannot share a staged winner), which at large fanout
    /// costs per-peer Adj-RIB-Out and per-peer encode for the session.
    pub rs_control_communities: Option<bool>,
    /// Local BGP Role for RFC 9234 route-leak prevention. eBGP only.
    pub role: Option<BgpRoleConfig>,
    /// Require the peer to advertise a compatible BGP Role capability.
    pub strict_role: Option<bool>,
    /// Advertise willingness to receive Address-Prefix ORF entries from this
    /// peer (RFC 5291/5292) and apply them to its outbound advertisements.
    pub prefix_orf_receive: Option<bool>,
    /// Never treat IPv4 unicast as available on this session (true
    /// IPv6-only peering). When `true`, IPv4 unicast is excluded from our
    /// advertised `MultiProtocol` capability and the RFC 4760 §8
    /// implicit-IPv4 fallback is suppressed; a session whose family
    /// intersection ends up empty is rejected with OPEN error /
    /// Unsupported Capability. Default: `false` (RFC-default implicit
    /// IPv4). Rejected at config load when the neighbor's effective
    /// `families` resolve to IPv4 unicast only.
    pub disable_ipv4_unicast: Option<bool>,
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
    /// Inline import policy statements for this neighbor.
    #[serde(default)]
    pub import_policy: Vec<PolicyStatementConfig>,
    /// Inline export policy statements for this neighbor.
    #[serde(default)]
    pub export_policy: Vec<PolicyStatementConfig>,
    /// Named policy chain for import (mutually exclusive with `import_policy`).
    #[serde(default)]
    pub import_policy_chain: Vec<String>,
    /// Named policy chain for export (mutually exclusive with `export_policy`).
    #[serde(default)]
    pub export_policy_chain: Vec<String>,
}

// Manual Debug: never render `md5_password` (mirrors `TcpAoConfig`; the
// `tcp_ao` field redacts through `TcpAoConfig`'s own Debug).
impl fmt::Debug for Neighbor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Neighbor")
            .field("address", &self.address)
            .field("interface", &self.interface)
            .field("remote_asn", &self.remote_asn)
            .field("description", &self.description)
            .field("peer_group", &self.peer_group)
            .field("hold_time", &self.hold_time)
            .field("send_hold_time", &self.send_hold_time)
            .field("slow_peer_threshold_pct", &self.slow_peer_threshold_pct)
            .field("slow_peer_duration", &self.slow_peer_duration)
            .field("slow_peer_isolation", &self.slow_peer_isolation)
            .field("max_prefixes", &self.max_prefixes)
            .field("max_prefixes_ipv4", &self.max_prefixes_ipv4)
            .field("max_prefixes_ipv6", &self.max_prefixes_ipv6)
            .field(
                "md5_password",
                &self.md5_password.as_ref().map(|_| "<redacted>"),
            )
            .field("tcp_ao", &self.tcp_ao)
            .field("bfd", &self.bfd)
            .field("ttl_security", &self.ttl_security)
            .field("families", &self.families)
            .field("graceful_restart", &self.graceful_restart)
            .field("gr_restart_time", &self.gr_restart_time)
            .field("gr_stale_routes_time", &self.gr_stale_routes_time)
            .field("llgr_stale_time", &self.llgr_stale_time)
            .field("local_ipv6_nexthop", &self.local_ipv6_nexthop)
            .field("route_reflector_client", &self.route_reflector_client)
            .field("orr_vantage", &self.orr_vantage)
            .field("route_server_client", &self.route_server_client)
            .field("per_client_best", &self.per_client_best)
            .field("next_hop_ownership", &self.next_hop_ownership)
            .field("interpret_rfc1997", &self.interpret_rfc1997)
            .field("rs_control_communities", &self.rs_control_communities)
            .field("role", &self.role)
            .field("strict_role", &self.strict_role)
            .field("prefix_orf_receive", &self.prefix_orf_receive)
            .field("disable_ipv4_unicast", &self.disable_ipv4_unicast)
            .field("remove_private_as", &self.remove_private_as)
            .field("add_path", &self.add_path)
            .field("log_level", &self.log_level)
            .field("import_policy", &self.import_policy)
            .field("export_policy", &self.export_policy)
            .field("import_policy_chain", &self.import_policy_chain)
            .field("export_policy_chain", &self.export_policy_chain)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TcpAoConfig {
    /// TCP-AO Master Key Tuple secret. 1..=80 bytes.
    pub key: String,
    /// Sender `KeyID` (`sndid` in Linux's TCP-AO UAPI).
    pub send_id: u8,
    /// Receiver `KeyID` (`rcvid` in Linux's TCP-AO UAPI).
    pub recv_id: u8,
    /// Linux TCP-AO MAC/KDF algorithm name, e.g. `"hmac(sha256)"`.
    pub algorithm: String,
    /// Mark this key as the preferred current send key for socket installation.
    /// Changing the preferred selection on live sockets remains
    /// restart-required.
    #[serde(default)]
    pub preferred: bool,
    /// Mark this key as deprecated for local startup selection and health
    /// metadata. Deprecated keys are still installed and may remain usable
    /// when peer-selected, but rustbgpd never selects one as its startup
    /// fallback. Changing this flag on an existing live MKT remains
    /// restart-required.
    #[serde(default)]
    pub deprecated: bool,
}

impl fmt::Debug for TcpAoConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TcpAoConfig")
            .field("key", &"<redacted>")
            .field("send_id", &self.send_id)
            .field("recv_id", &self.recv_id)
            .field("algorithm", &self.algorithm)
            .field("preferred", &self.preferred)
            .field("deprecated", &self.deprecated)
            .finish()
    }
}

/// Ordered TCP-AO keyring. A singleton retains the legacy table wire shape;
/// two or more entries use an ordered array of tables. Live reload supports
/// appending nonpreferred successor keys without redefining existing entries.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TcpAoKeyringConfig(pub Vec<TcpAoConfig>);

impl TcpAoKeyringConfig {
    pub fn iter(&self) -> std::slice::Iter<'_, TcpAoConfig> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> IntoIterator for &'a TcpAoKeyringConfig {
    type Item = &'a TcpAoConfig;
    type IntoIter = std::slice::Iter<'a, TcpAoConfig>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl fmt::Debug for TcpAoKeyringConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("TcpAoKeyringConfig").field(&self.0).finish()
    }
}

impl From<TcpAoConfig> for TcpAoKeyringConfig {
    fn from(key: TcpAoConfig) -> Self {
        Self(vec![key])
    }
}

#[derive(Deserialize, JsonSchema)]
#[serde(untagged)]
enum TcpAoKeyringWire {
    Singleton(TcpAoConfig),
    Ordered(#[schemars(length(min = 1, max = 256))] Vec<TcpAoConfig>),
}

impl JsonSchema for TcpAoKeyringConfig {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("TcpAoKeyringConfig")
    }

    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        TcpAoKeyringWire::json_schema(generator)
    }
}

impl<'de> Deserialize<'de> for TcpAoKeyringConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(match TcpAoKeyringWire::deserialize(deserializer)? {
            TcpAoKeyringWire::Singleton(key) => Self(vec![key]),
            TcpAoKeyringWire::Ordered(keys) => Self(keys),
        })
    }
}

impl Serialize for TcpAoKeyringConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self.0.as_slice() {
            [key] => key.serialize(serializer),
            keys => keys.serialize(serializer),
        }
    }
}

#[derive(Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PeerGroupConfig {
    /// Hold time inherited by neighbors in this group. See the
    /// neighbor-level `hold_time`.
    pub hold_time: Option<u16>,
    /// Send hold time in seconds (RFC 9687) inherited by neighbors in
    /// this group. See the neighbor-level `send_hold_time`.
    pub send_hold_time: Option<u32>,
    /// Slow-peer backlog threshold inherited by neighbors in this
    /// group. See the neighbor-level `slow_peer_threshold_pct`.
    pub slow_peer_threshold_pct: Option<u8>,
    /// Slow-peer persistence duration inherited by neighbors in this
    /// group. See the neighbor-level `slow_peer_duration`.
    pub slow_peer_duration: Option<u32>,
    /// Slow-peer isolation inherited by neighbors in this group. See
    /// the neighbor-level `slow_peer_isolation`.
    pub slow_peer_isolation: Option<bool>,
    /// Prefix limit inherited by neighbors in this group. See the
    /// neighbor-level `max_prefixes`.
    pub max_prefixes: Option<u32>,
    /// IPv4-unicast prefix limit inherited by neighbors in this group.
    /// See the neighbor-level `max_prefixes_ipv4`.
    pub max_prefixes_ipv4: Option<u32>,
    /// IPv6-unicast prefix limit inherited by neighbors in this group.
    /// See the neighbor-level `max_prefixes_ipv6`.
    pub max_prefixes_ipv6: Option<u32>,
    /// TCP MD5 signature password (RFC 2385) inherited by neighbors in
    /// this group.
    pub md5_password: Option<String>,
    /// GTSM TTL security (RFC 5082) inherited by neighbors in this group.
    pub ttl_security: Option<bool>,
    /// Single-hop BFD attachment inherited by neighbors in this group (unless
    /// the neighbor sets its own `bfd`). References a `[[bfd_profiles]]` entry.
    pub bfd: Option<BfdConfig>,
    /// Address families to negotiate (e.g., `["ipv4_unicast", "ipv6_unicast"]`).
    #[serde(default)]
    pub families: Vec<String>,
    /// Enable Graceful Restart (RFC 4724). See the neighbor-level
    /// `graceful_restart`.
    pub graceful_restart: Option<bool>,
    /// GR restart time (seconds). See the neighbor-level `gr_restart_time`.
    pub gr_restart_time: Option<u16>,
    /// GR stale-routes time (seconds). See the neighbor-level
    /// `gr_stale_routes_time`.
    pub gr_stale_routes_time: Option<u64>,
    /// LLGR stale time (RFC 9494, seconds). See the neighbor-level
    /// `llgr_stale_time`.
    pub llgr_stale_time: Option<u32>,
    /// Explicit IPv6 next-hop. See the neighbor-level `local_ipv6_nexthop`.
    pub local_ipv6_nexthop: Option<String>,
    /// Mark neighbors in this group as route reflector clients (RFC 4456).
    pub route_reflector_client: Option<bool>,
    /// Optimal Route Reflection vantage point (RFC 9107) inherited by
    /// neighbors in this group. See the neighbor-level `orr_vantage`.
    pub orr_vantage: Option<IpAddr>,
    /// Mark neighbors in this group as transparent route-server clients.
    /// See the neighbor-level `route_server_client`.
    pub route_server_client: Option<bool>,
    /// RFC 7947 §2.3.2 per-client best-path inherited by neighbors in
    /// this group. See the neighbor-level `per_client_best`.
    pub per_client_best: Option<bool>,
    /// ADR-0107 `NEXT_HOP` ownership enforcement inherited by neighbors in
    /// this group. See the neighbor-level `next_hop_ownership`.
    pub next_hop_ownership: Option<NextHopOwnershipConfig>,
    /// RFC 1997 `NO_EXPORT` egress enforcement inherited by neighbors in
    /// this group. See the neighbor-level `interpret_rfc1997`.
    pub interpret_rfc1997: Option<bool>,
    /// RFC 7947 route-server control-community interpretation inherited
    /// by neighbors in this group. See the neighbor-level
    /// `rs_control_communities`.
    pub rs_control_communities: Option<bool>,
    /// Local BGP Role (RFC 9234) inherited by neighbors in this group.
    pub role: Option<BgpRoleConfig>,
    /// Require a compatible BGP Role capability from peers in this group.
    pub strict_role: Option<bool>,
    /// Advertise willingness to receive Address-Prefix ORF entries (RFC
    /// 5291/5292) from peers in this group.
    pub prefix_orf_receive: Option<bool>,
    /// Never treat IPv4 unicast as available for peers in this group
    /// (true IPv6-only peering). See the neighbor-level
    /// `disable_ipv4_unicast` for semantics.
    pub disable_ipv4_unicast: Option<bool>,
    /// Remove private ASNs before eBGP advertisement (`"remove"`,
    /// `"all"`, or `"replace"`). See the neighbor-level `remove_private_as`.
    pub remove_private_as: Option<String>,
    /// Add-Path (RFC 7911) configuration inherited by neighbors in this
    /// group.
    pub add_path: Option<AddPathConfig>,
    /// Override log level for peers in this group.
    pub log_level: Option<String>,
    /// Inline import policy statements for peers in this group.
    #[serde(default)]
    pub import_policy: Vec<PolicyStatementConfig>,
    /// Inline export policy statements for peers in this group.
    #[serde(default)]
    pub export_policy: Vec<PolicyStatementConfig>,
    /// Named policy chain for import (mutually exclusive with `import_policy`).
    #[serde(default)]
    pub import_policy_chain: Vec<String>,
    /// Named policy chain for export (mutually exclusive with `export_policy`).
    #[serde(default)]
    pub export_policy_chain: Vec<String>,
}

// Manual Debug: never render `md5_password` (mirrors `TcpAoConfig`).
impl fmt::Debug for PeerGroupConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerGroupConfig")
            .field("hold_time", &self.hold_time)
            .field("send_hold_time", &self.send_hold_time)
            .field("slow_peer_threshold_pct", &self.slow_peer_threshold_pct)
            .field("slow_peer_duration", &self.slow_peer_duration)
            .field("slow_peer_isolation", &self.slow_peer_isolation)
            .field("max_prefixes", &self.max_prefixes)
            .field("max_prefixes_ipv4", &self.max_prefixes_ipv4)
            .field("max_prefixes_ipv6", &self.max_prefixes_ipv6)
            .field(
                "md5_password",
                &self.md5_password.as_ref().map(|_| "<redacted>"),
            )
            .field("ttl_security", &self.ttl_security)
            .field("bfd", &self.bfd)
            .field("families", &self.families)
            .field("graceful_restart", &self.graceful_restart)
            .field("gr_restart_time", &self.gr_restart_time)
            .field("gr_stale_routes_time", &self.gr_stale_routes_time)
            .field("llgr_stale_time", &self.llgr_stale_time)
            .field("local_ipv6_nexthop", &self.local_ipv6_nexthop)
            .field("route_reflector_client", &self.route_reflector_client)
            .field("orr_vantage", &self.orr_vantage)
            .field("route_server_client", &self.route_server_client)
            .field("per_client_best", &self.per_client_best)
            .field("next_hop_ownership", &self.next_hop_ownership)
            .field("interpret_rfc1997", &self.interpret_rfc1997)
            .field("rs_control_communities", &self.rs_control_communities)
            .field("role", &self.role)
            .field("strict_role", &self.strict_role)
            .field("prefix_orf_receive", &self.prefix_orf_receive)
            .field("disable_ipv4_unicast", &self.disable_ipv4_unicast)
            .field("remove_private_as", &self.remove_private_as)
            .field("add_path", &self.add_path)
            .field("log_level", &self.log_level)
            .field("import_policy", &self.import_policy)
            .field("export_policy", &self.export_policy)
            .field("import_policy_chain", &self.import_policy_chain)
            .field("export_policy_chain", &self.export_policy_chain)
            .finish()
    }
}

/// ADR-0107 route-server `NEXT_HOP` ownership enforcement modes
/// (RFC 7948 §4.8).
///
/// Only the strict pilot ships today. The broader `same_as` and
/// `explicit_authorized` relationships RFC 7948 permits are deferred
/// until a generation-consistent authoritative fleet inventory exists
/// (ADR-0107 §1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum NextHopOwnershipConfig {
    /// Accept a unicast announcement only when its complete wire
    /// next-hop identity is the advertising session's own address.
    StrictPeer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BgpRoleConfig {
    Provider,
    #[serde(alias = "rs")]
    RouteServer,
    #[serde(alias = "rs-client")]
    RouteServerClient,
    Customer,
    Peer,
}

impl BgpRoleConfig {
    pub(crate) const fn to_wire(self) -> BgpRole {
        match self {
            Self::Provider => BgpRole::Provider,
            Self::RouteServer => BgpRole::RouteServer,
            Self::RouteServerClient => BgpRole::RouteServerClient,
            Self::Customer => BgpRole::Customer,
            Self::Peer => BgpRole::Peer,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
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
    /// Experimental Paths-Limit preference per received Add-Path family.
    /// Zero or absent disables Paths-Limit advertisement.
    pub receive_max: Option<u16>,
}

/// Per-neighbor / per-peer-group BFD attachment (RFC 5880/5881, ADR-0067).
///
/// The presence of this block enables single-hop asynchronous BFD for the
/// neighbor; it references a `[[bfd_profiles]]` entry for the timers. Static
/// neighbors only — dynamic-neighbor BFD is deferred (see ADR-0067).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BfdConfig {
    /// Name of the `[[bfd_profiles]]` entry providing the timers.
    pub profile: String,
    /// Whether BFD is enabled. Defaults to `true`; the field exists so a
    /// neighbor can override an inherited peer-group `bfd` block to *disable*
    /// BFD (`bfd = { profile = "...", enabled = false }`). A disabled block runs
    /// no session — the actor skips it — so the effective session set is fully
    /// expressible inline, which the restart-required reload pin relies on.
    #[serde(default = "default_bfd_enabled")]
    pub enabled: bool,
    /// RFC 5882 strict mode: when true, the BGP session is not allowed to reach
    /// Established until the BFD session is Up. Default false — BGP may
    /// establish first, and a later BFD-down tears it down faster than the hold
    /// timer.
    #[serde(default)]
    pub strict: bool,
}

fn default_bfd_enabled() -> bool {
    true
}

/// A named BFD timing profile referenced by `[neighbors.bfd]` /
/// `[peer_groups.<name>.bfd]`. Intervals are in **milliseconds**.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BfdProfileConfig {
    /// Unique profile name (referenced by `bfd.profile`).
    pub name: String,
    /// Desired minimum transmit interval (ms). Default 300; validated ≥ 100.
    #[serde(default = "default_bfd_interval_ms")]
    pub min_tx_interval: u32,
    /// Required minimum receive interval (ms). Default 300; validated ≥ 100.
    #[serde(default = "default_bfd_interval_ms")]
    pub min_rx_interval: u32,
    /// Detection multiplier — detection time is `multiplier × negotiated
    /// interval`. Default 3; validated ≥ 2.
    #[serde(default = "default_bfd_multiplier")]
    pub multiplier: u32,
}

fn default_bfd_interval_ms() -> u32 {
    300
}

fn default_bfd_multiplier() -> u32 {
    3
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
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
    /// Import-decision explain cache tuning (ADR-0073). Diagnostic
    /// retention only — does not affect which routes are accepted.
    #[serde(default)]
    pub explain: PolicyExplainConfig,
    /// `.rpol` policy-language files (ADR-0096) compiled at config
    /// load. Relative paths resolve against the config file's
    /// directory and are rewritten to absolute paths after load (so
    /// runtime config snapshots and transaction candidates stay
    /// loadable regardless of the daemon's working directory).
    /// Compile diagnostics are config load errors. The policies they
    /// define share one namespace with `[policy.definitions]`; chains
    /// reference them by name, parameterized policies by call-form
    /// (`"customer-in(200)"`).
    #[serde(default)]
    pub rpol_files: Vec<String>,
    /// Additional policy roots for `.rpol` `import` resolution
    /// (LAN-300). Imports resolve against the importing file's
    /// directory first, then these directories in order, and the
    /// resolved file must stay inside the main file's directory or one
    /// of these roots. Relative entries resolve against the config
    /// file's directory and are rewritten absolute at load, like
    /// `rpol_files`.
    #[serde(default)]
    pub rpol_roots: Vec<String>,
    /// Compiled `.rpol` policy registry (populated at load, not
    /// serialized). `PartialEq` is resolved-content-based across each
    /// unit's whole module graph, so config diffs see an edit to any
    /// imported `.rpol` module as a policy change and an unchanged
    /// reload as a no-op.
    #[serde(skip)]
    pub rpol: rustbgpd_policy::rpol::RpolPolicySet,
    /// External dataset file bindings (LAN-305): `[policy.datasets.<name>]`
    /// maps each `dataset` declared in an `.rpol` file to the snapshot
    /// file its content loads from. Every declared dataset needs an
    /// entry and every entry needs a declaration — both directions are
    /// load errors. Relative paths resolve against the config file's
    /// directory and are rewritten absolute at load, like `rpol_files`.
    #[serde(default)]
    pub datasets: HashMap<String, DatasetFileConfig>,
    /// Live dataset handles (name → shared handle), populated at load,
    /// not serialized. `PartialEq` is handle identity: a SIGHUP reload
    /// reuses the running handles (content swaps happen *inside* them
    /// and are invisible here), so unchanged configs diff as no-ops
    /// while a rebind (new dataset, kind change) diffs as a policy
    /// change.
    #[serde(skip)]
    pub dataset_bindings: rustbgpd_policy::datasets::DatasetBindings,
    /// What the dataset load step observed (populated at load, not
    /// serialized, excluded from equality): which datasets swapped
    /// content vs. the prior bindings, and which failed to refresh
    /// (prior snapshot retained). The reload path turns `swapped` into
    /// the dependency-scoped peer refresh and `failed` into metrics.
    #[serde(skip)]
    pub dataset_events: DatasetLoadEvents,
}

/// One `[policy.datasets.<name>]` binding (LAN-305).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DatasetFileConfig {
    /// Path of the dataset snapshot file: one entry per line, `#`
    /// comments, entries in `.rpol` set-literal syntax for the
    /// declared kind. Producers should write-temp-then-rename so the
    /// daemon never reads a torn file.
    pub path: String,
}

/// Load-time dataset observations (LAN-305). Deliberately **excluded
/// from config equality**: these are events about one load, not
/// configuration identity — two configs differing only here are the
/// same config.
#[derive(Debug, Clone, Default)]
pub struct DatasetLoadEvents {
    /// Datasets whose content swapped vs. the prior bindings
    /// (generation bumped). Drives the dependency-scoped peer refresh.
    pub swapped: Vec<String>,
    /// `(name, reason)` for datasets whose file failed to load/parse;
    /// the prior snapshot was retained.
    pub failed: Vec<(String, String)>,
}

impl PartialEq for DatasetLoadEvents {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for DatasetLoadEvents {}

/// Tuning for the per-session import-decision cache that backs
/// `rbgp policy explain` / `PolicyService.ExplainImportPolicy`
/// (ADR-0073).
///
/// This is **diagnostic retention**, not policy evaluation behaviour:
/// shrinking or disabling the cache changes only what the explain
/// surface can answer, never which routes the import chain admits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyExplainConfig {
    /// Whether the per-session import-decision cache is populated.
    /// Default `true`. This is the performance control: when `false`
    /// the inbound UPDATE path skips building and storing any decision
    /// snapshot — a single boolean check, no per-NLRI attribute /
    /// modification clone. Turn it off on hot full-table peers where
    /// the explain surface isn't worth the write-path cost.
    #[serde(default = "default_explain_enabled")]
    pub enabled: bool,
    /// Per-peer cache capacity (entries). Each entry is one
    /// `(AFI, SAFI, prefix, path_id)` import decision. Default 4096 —
    /// a fabric / partial-table starter size (hundreds–low-thousands
    /// of prefixes fully observable). It is **not** sized for internet
    /// full-table retention: a 100k-prefix peer keeps the cache
    /// saturated, so explain becomes a coin-flip versus an evicted
    /// answer. Operators who want reliable full-table explain raise
    /// this toward their expected retained-prefix count for the peer
    /// and own the memory cost.
    #[serde(default = "default_explain_cache_size")]
    pub cache_size: usize,
}

fn default_explain_enabled() -> bool {
    true
}

fn default_explain_cache_size() -> usize {
    4096
}

impl Default for PolicyExplainConfig {
    fn default() -> Self {
        Self {
            enabled: default_explain_enabled(),
            cache_size: default_explain_cache_size(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NeighborSetConfig {
    /// Neighbor IP addresses in this set.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// Remote ASNs in this set.
    #[serde(default)]
    pub remote_asns: Vec<u32>,
    /// Peer-group names in this set.
    #[serde(default)]
    pub peer_groups: Vec<String>,
}

/// A named policy definition with configurable default action.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NamedPolicyConfig {
    /// Default action when no statement matches: `"permit"` (default) or `"deny"`.
    #[serde(default = "default_policy_action_str")]
    pub default_action: String,
    /// Policy statements evaluated in order; first match wins.
    #[serde(default)]
    pub statements: Vec<PolicyStatementConfig>,
}

fn default_policy_action_str() -> String {
    "permit".to_string()
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PolicyStatementConfig {
    /// Action when the statement matches: `"permit"` or `"deny"`.
    pub action: String,
    /// CIDR prefix to match. Optional when any other match criterion is set.
    pub prefix: Option<String>,
    /// Minimum prefix length (inclusive) for the `prefix` match.
    pub ge: Option<u8>,
    /// Maximum prefix length (inclusive) for the `prefix` match.
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AsPathPrependConfig {
    /// ASN to prepend.
    pub asn: u32,
    /// Number of times to prepend it.
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
///   Required and non-empty unless `auto_derive_route_target = true`; each
///   entry parses through [`rustbgpd_evpn::RouteTarget`].
/// - `auto_derive_route_target` — derive the RFC 8365 §5.1.2.1 VXLAN RT from
///   `[global].asn` and `vni`. Off by default; requires a 2-octet AS.
/// - `local_vtep_ip` — VXLAN tunnel source IP for this EVI. Required,
///   must be a unicast address (rejects unspecified / multicast /
///   loopback).
/// - `bridge` — optional Linux bridge name this EVI is bound to.
///   Kernel reconciliation reports `NotReady` until the named bridge exists.
/// - `bridge_vlan` — optional local Linux bridge VLAN selector
///   (`1..=4094`). Valid only with `bridge`; ADR-0089 v1 keeps EVPN
///   Ethernet Tag ID `0`, so this is not a wire-protocol tag.
/// - `advertise_svi_mac` — toggle for Type 2 origination of the SVI's
///   own MAC address (RFC 9135 §6.1). Off by default. Origination is
///   gated on dataplane readiness for the instance.
/// - `sticky_macs` — list of MAC addresses (`aa:bb:cc:dd:ee:ff` form)
///   that, when learned by the local kernel, are originated with the
///   RFC 7432 §15.4 "sticky" bit set in the MAC Mobility extended
///   community. **Not** a static FDB: rustbgpd does not synthesize
///   Type 2s for these MACs; the flag only marks them on origination.
///   Empty by default. See ADR-0056.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvpnInstanceConfig {
    /// Local VNI for this instance (`1..=16_777_215`).
    pub vni: u32,
    /// Route Distinguisher (RFC 4364 §4.2). Textual form: `asn:val` or `ipv4:val`.
    pub rd: String,
    /// Bidirectional Route Targets — each entry applies to both import and export.
    #[serde(default)]
    pub route_targets: Vec<String>,
    /// Derive the RFC 8365 §5.1.2.1 VXLAN Route Target from `[global].asn` and `vni`.
    #[serde(default)]
    pub auto_derive_route_target: bool,
    /// VXLAN tunnel source IP for this EVI.
    pub local_vtep_ip: String,
    /// Optional Linux bridge name this EVI is bound to for kernel
    /// dataplane probing, readiness reporting, and local origination
    /// that depends on observed bridge state.
    #[serde(default)]
    pub bridge: Option<String>,
    /// Optional local Linux bridge VLAN selector for ADR-0089
    /// VLAN-aware bridge attribution. This is not an EVPN Ethernet Tag.
    #[serde(default)]
    pub bridge_vlan: Option<u32>,
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
    /// **Runtime-drivable via `EvpnService.ApplyEvpnRuntime` L2VNI redefine;
    /// SIGHUP remains restart-required.** A config-file reload still reverts
    /// edits to the instance table, but a runtime L2VNI redefine that flips
    /// this knob converges cleanly through the dataplane diff's standard
    /// `FdbNhg → SingleDst` transition (#210). When toggled across a daemon
    /// restart instead, stale tagged FDB rows from a prior run stay in place
    /// until the next periodic drift cycle (≤ 60 s, slice 3.5 PR 2).
    #[serde(default = "default_enabled")]
    pub apply_aliasing_ecmp: bool,
    /// RFC 7432 §15.1 duplicate-MAC detection and optional local
    /// quarantine policy. Default is detect-only with the RFC M/N
    /// window (5 moves in 180s). `action = "suppress_local"` is
    /// opt-in and withdraws/suppresses locally-originated Type 2 routes
    /// for the offending `(VNI, MAC)` until `recovery_seconds` elapses.
    #[serde(default)]
    pub duplicate_mac_detection: EvpnDuplicateMacDetectionConfig,
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
/// **Operator prerequisite**: the VRF device and L3 VXLAN device must
/// exist and satisfy the readiness predicates in ADR-0058 §3 before
/// rustbgpd originates or installs anything. By default those links are
/// operator-provisioned; deployments that want rustbgpd to own their
/// lifecycle can opt in with matching ADR-0091 `[[managed_netdevs.vrfs]]`
/// and `[[managed_netdevs.l3vxlans]]` rows.
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
///   and export. Tenant identity on the wire. Required and non-empty unless
///   `auto_derive_route_target = true`.
/// - `auto_derive_route_target` — derive the L3VNI / IP-VRF RT as plain
///   `AS:VNI` from `[global].asn` and the L3VNI (matching FRR's default
///   tenant-VRF auto-RT — the RFC 8365 opaque form is MAC-VRF-only and
///   would not import against FRR for L3VNIs). Off by default; requires a
///   2-octet AS.
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvpnIpVrfConfig {
    /// Operator-facing tenant handle.
    pub name: String,
    /// L3VNI (`1..=16_777_215`).
    pub vni: u32,
    /// Route Distinguisher (`asn:value` or `ipv4:value`).
    pub rd: String,
    /// Bidirectional Route Targets — applied to both import and export.
    #[serde(default)]
    pub route_targets: Vec<String>,
    /// Derive the L3VNI / IP-VRF Route Target as `AS:VNI` from `[global].asn`
    /// and L3VNI (FRR-compatible tenant-VRF auto-RT, not the RFC 8365 form).
    #[serde(default)]
    pub auto_derive_route_target: bool,
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
    /// Outbound Type 5 overlay-index mode (ADR-0087). `"interface_less"`
    /// (default) keeps the RFC 9136 §4.4.2 shape — Gateway Address zero,
    /// Router's MAC extended community. `"gateway_ip"` opts into RFC 9136
    /// §4.1/§4.2 GW-IP overlay index: a kernel route whose via lands on a
    /// connected subnet of this VRF originates with that via in the
    /// Gateway Address and no Router's MAC extcomm; routes without an
    /// eligible via fall back to the interface-less shape. `"esi"` opts
    /// into RFC 9136 §4.3 ESI overlay index and requires
    /// `overlay_index_esi` + `overlay_index_mac`. `"gateway_ip"` and
    /// `"esi"` both require at least one `[[evpn_instances]].ip_vrf`-linked L2VNI
    /// (the receive side needs it to scope recursive resolution).
    #[serde(default)]
    pub overlay_index_mode: OverlayIndexModeConfig,
    /// Non-zero ESI used when `overlay_index_mode = "esi"`.
    #[serde(default)]
    pub overlay_index_esi: Option<String>,
    /// Router's MAC extended community used when
    /// `overlay_index_mode = "esi"`. This names the virtual appliance /
    /// transit-switch MAC, not the PE/NVE router MAC.
    #[serde(default)]
    pub overlay_index_mac: Option<String>,
    /// Optional L2VNI disambiguator for ESI mode when this IP-VRF links
    /// more than one L2VNI.
    #[serde(default)]
    pub overlay_index_l2vni: Option<u32>,
}

/// ADR-0091 opt-in block for rustbgpd-managed EVPN Linux netdevs.
///
/// v1 accepts `[[managed_netdevs.bridges]]`, fixed-VNI
/// `[[managed_netdevs.vxlans]]`, collect-metadata
/// `[[managed_netdevs.svd_vxlans]]`, `[[managed_netdevs.vrfs]]`,
/// `[[managed_netdevs.l3vxlans]]`, and `[[managed_netdevs.vlan_uppers]]` rows.
/// The `owner_token` is required when at least one row is configured and is
/// used only to derive durable `IFLA_ALT_IFNAME` ownership stamps:
/// `rustbgpd:<class>:<owner_token>:<link_name>`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManagedNetdevsConfig {
    /// Stable deployment-local owner token. Empty only when no rows are
    /// configured.
    #[serde(default)]
    pub owner_token: String,
    /// Managed bridge rows.
    #[serde(default)]
    pub bridges: Vec<ManagedBridgeNetdevConfig>,
    /// Managed fixed-VNI VXLAN rows.
    #[serde(default)]
    pub vxlans: Vec<ManagedVxlanNetdevConfig>,
    /// Managed collect-metadata / Single VXLAN Device rows. Each row is shared
    /// by the configured `[[evpn_instances]]` on its bridge that carry
    /// `bridge_vlan`; rustbgpd derives the bridge VLAN -> VNI mappings from
    /// those instances.
    #[serde(default)]
    pub svd_vxlans: Vec<ManagedSvdVxlanNetdevConfig>,
    /// Managed VRF rows.
    #[serde(default)]
    pub vrfs: Vec<ManagedVrfNetdevConfig>,
    /// Managed L3 VXLAN rows.
    #[serde(default)]
    pub l3vxlans: Vec<ManagedL3VxlanNetdevConfig>,
    /// Managed VLAN upper rows. These are helper links for the existing
    /// VLAN-upper `AF_INET` / `AF_INET6` MAC+IP attribution path and must match
    /// a configured `[[evpn_instances]]` `bridge` + `bridge_vlan` binding.
    #[serde(default)]
    pub vlan_uppers: Vec<ManagedVlanUpperNetdevConfig>,
}

/// One managed Linux bridge row (ADR-0091 bridge-first tranche).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManagedBridgeNetdevConfig {
    /// Linux bridge interface name.
    pub name: String,
    /// Desired protected bridge `vlan_filtering` value.
    pub vlan_filtering: bool,
}

/// One managed fixed-VNI VXLAN row (ADR-0091 VXLAN tranche).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManagedVxlanNetdevConfig {
    /// Linux VXLAN interface name.
    pub name: String,
    /// Fixed VXLAN VNI (`1..=16_777_215`).
    pub vni: u32,
    /// Local source IP for VXLAN encapsulation.
    pub local: std::net::IpAddr,
    /// UDP destination port. Defaults to the IANA VXLAN port.
    #[serde(default = "default_vxlan_dstport")]
    pub dstport: u16,
    /// Bridge this VXLAN device must be enslaved to before it can satisfy
    /// EVPN readiness.
    pub bridge: String,
    /// Linux VXLAN learning mode. ADR-0091 fixed-VNI lifecycle requires
    /// `false` (`nolearning`); the field exists so typos or intentional
    /// deviations fail validation explicitly instead of silently using the
    /// default.
    #[serde(default)]
    pub learning: bool,
}

/// One managed collect-metadata / Single VXLAN Device row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManagedSvdVxlanNetdevConfig {
    /// Linux VXLAN interface name.
    pub name: String,
    /// Optional local source IP for VXLAN encapsulation. If omitted, rustbgpd
    /// creates the common SVD shape without a pinned local address.
    #[serde(default)]
    pub local: Option<std::net::IpAddr>,
    /// UDP destination port. Defaults to the IANA VXLAN port.
    #[serde(default = "default_vxlan_dstport")]
    pub dstport: u16,
    /// VLAN-aware bridge this SVD VXLAN device must be enslaved to. Matching
    /// `[[evpn_instances]]` rows on this bridge with `bridge_vlan` provide the
    /// managed VLAN -> VNI mappings.
    pub bridge: String,
    /// Linux VXLAN learning mode. ADR-0091 SVD lifecycle requires `false`
    /// (`nolearning`); the field exists so typos or intentional deviations fail
    /// validation explicitly instead of silently using the default.
    #[serde(default)]
    pub learning: bool,
}

/// One managed Linux VRF row (ADR-0091 VRF/L3VXLAN substrate tranche).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManagedVrfNetdevConfig {
    /// Linux VRF interface name.
    pub name: String,
    /// Desired VRF table id (`IFLA_VRF_TABLE`).
    pub table_id: u32,
}

/// One managed L3 VXLAN row (ADR-0091 VRF/L3VXLAN substrate tranche).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManagedL3VxlanNetdevConfig {
    /// Linux L3 VXLAN interface name.
    pub name: String,
    /// Fixed VXLAN VNI (`1..=16_777_215`).
    pub vni: u32,
    /// Local source IP for VXLAN encapsulation.
    pub local: std::net::IpAddr,
    /// UDP destination port. Defaults to the IANA VXLAN port.
    #[serde(default = "default_vxlan_dstport")]
    pub dstport: u16,
    /// VRF device this L3 VXLAN must be enslaved to.
    pub vrf: String,
    /// Router MAC this L3 VXLAN must carry.
    pub router_mac: String,
    /// Linux VXLAN learning mode. ADR-0091 L3VXLAN lifecycle requires
    /// `false` (`nolearning`); the field exists so typos or intentional
    /// deviations fail validation explicitly instead of silently using the
    /// default.
    #[serde(default)]
    pub learning: bool,
}

/// One managed Linux VLAN upper row (ADR-0091 VLAN-upper tranche).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ManagedVlanUpperNetdevConfig {
    /// Linux VLAN upper interface name.
    pub name: String,
    /// Parent Linux bridge name.
    pub bridge: String,
    /// Linux VLAN id (`1..=4094`).
    pub vlan: u16,
}

const fn default_vxlan_dstport() -> u16 {
    4789
}

/// Serde form of [`rustbgpd_evpn::OverlayIndexMode`] (ADR-0087).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum OverlayIndexModeConfig {
    /// RFC 9136 §4.4.2 Interface-less — the default, byte-for-byte the
    /// pre-ADR-0087 behavior.
    #[default]
    InterfaceLess,
    /// RFC 9136 §4.1/§4.2 GW-IP overlay index.
    GatewayIp,
    /// RFC 9136 §4.3 ESI overlay index.
    Esi,
}

/// Explicit opt-in for ordinary unicast kernel FIB export.
///
/// ADR-0061 keeps the general FIB path separate from EVPN L3VNI and
/// RFC 7999 BLACKHOLE discard. The operator must name every Linux
/// route table rustbgpd may write to; the daemon never silently takes
/// over `main`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FibTableConfig {
    /// Operator-facing handle for status output and CLI/API filters.
    /// Unique across `[[fib_tables]]`.
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
    /// Address families eligible for install. Defaults to both IPv4
    /// and IPv6 unicast when the `[[fib_tables]]` block itself is
    /// present.
    #[serde(default = "default_fib_families")]
    pub families: Vec<String>,
    /// Optional peer-group allow-list. When non-empty, routes learned from
    /// peers outside these groups are rejected before kernel apply.
    #[serde(default)]
    pub allowed_peer_groups: Vec<String>,
    /// Optional neighbor address allow-list. When non-empty, routes learned
    /// from peers outside this list are rejected before kernel apply.
    #[serde(default)]
    pub allowed_neighbors: Vec<String>,
    /// Optional hard cap for the table. If the eligible route count exceeds
    /// this value, rustbgpd freezes table growth and replacement while still
    /// allowing already-owned rows to be repaired or withdrawn.
    pub max_routes: Option<u32>,
    /// Optional maximum number of equal-cost next-hops to install per prefix
    /// (unicast multipath / ECMP, ADR-0066). Unset or `1` programs a single
    /// next-hop — exactly today's behavior. Higher values install up to this
    /// many equal-cost paths as a kernel `RTA_MULTIPATH` route. Applies to any
    /// homogeneous eBGP or iBGP equal-cost group that does not have a per-class
    /// override below. Distinct from `max_routes`, which caps the number of
    /// prefixes (rows), not the next-hops per row. Validated `>= 1`, capped at
    /// 256.
    #[serde(default)]
    pub maximum_paths: Option<u32>,
    /// Per-class ECMP cap for **eBGP** equal-cost groups (FRR's
    /// `maximum-paths`). Overrides `maximum_paths` for eBGP best routes; when
    /// unset, eBGP groups fall back to `maximum_paths` (then `1`). Validated
    /// `>= 1`, capped at 256.
    #[serde(default)]
    pub maximum_paths_ebgp: Option<u32>,
    /// Per-class ECMP cap for **iBGP** equal-cost groups (FRR's
    /// `maximum-paths ibgp`). Overrides `maximum_paths` for iBGP best routes;
    /// when unset, iBGP groups fall back to `maximum_paths` (then `1`).
    /// Validated `>= 1`, capped at 256.
    #[serde(default)]
    pub maximum_paths_ibgp: Option<u32>,
}

pub(crate) fn default_fib_families() -> Vec<String> {
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
/// - `df_preference` — RFC 9785 Designated Forwarder preference
///   value (`0..=65535`, default 32768). Used only by
///   `"highest-preference"` / `"lowest-preference"`; default-modulo
///   and HRW require the default because they ignore preference.
/// - `df_algorithm` — DF election algorithm string. Gate 8 accepts
///   `"default-modulo"` (RFC 7432 §8.5) and
///   `"highest-random-weight"` (RFC 8584 §3.2), plus RFC 9785
///   `"highest-preference"` / `"lowest-preference"` (revertive;
///   local Don't-Preempt/non-revertive behavior is deferred).
///   Default `"default-modulo"`.
/// - `redundancy_mode` — `"all-active"` (default) or
///   `"single-active"`; single-active sets the ESI Label extcomm flag
///   and prevents receiver-side all-active aliasing ECMP for remote
///   single-active ES reachability.
/// - `originator_ip` — IP this PE uses as the Type 4 ES route's
///   originator address. Typically equals `evpn_instances[].local_vtep_ip`.
/// - `interface` — optional attachment-circuit link binding
///   (ADR-0085 decision 1). When set, the ES's drain state follows
///   that link's carrier (`IFF_LOWER_UP`): carrier loss drains the
///   ES immediately; a link absent from the kernel counts as down
///   (fail-closed). Unbound segments behave as before — drain only
///   via the ADR-0084 RPC.
/// - `recovery_delay_secs` — hold-off after carrier returns before
///   the link drain is released (ADR-0085 decision 3). Default 30,
///   range `0..=3600`; the timer re-arms on every up edge, so a
///   flapping circuit stays drained until it holds carrier for the
///   full window. Only meaningful — and only accepted — together
///   with `interface`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EthernetSegmentConfig {
    /// 10-byte ESI in colon-separated hex (`XX:XX:XX:XX:XX:XX:XX:XX:XX:XX`).
    pub esi: String,
    /// VNIs participating in this ES. Each must already be declared
    /// in `[[evpn_instances]]`.
    pub member_vnis: Vec<u32>,
    /// RFC 9785 DF preference. Default 32768.
    #[serde(default = "default_df_preference")]
    pub df_preference: u32,
    /// DF algorithm string. Default `"default-modulo"`.
    #[serde(default = "default_df_algorithm")]
    pub df_algorithm: String,
    /// RFC 9785 Don't-Preempt (non-revertive DF). Default `false`. Only
    /// valid with `highest-preference` / `lowest-preference`.
    #[serde(default)]
    pub df_dont_preempt: bool,
    /// Redundancy mode string. Default `"all-active"`.
    #[serde(default = "default_redundancy_mode")]
    pub redundancy_mode: String,
    /// Originator IP carried on the Type 4 ES route.
    pub originator_ip: String,
    /// ADR-0085 decision 1: name of the local attachment-circuit
    /// link whose carrier drives this ES's link drain. Optional —
    /// unbound segments are drained only via the ADR-0084 RPC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    /// ADR-0085 decision 3: seconds to hold the link drain after
    /// carrier returns (default 30, range `0..=3600`). Rejected
    /// without `interface` — it has no meaning unbound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_delay_secs: Option<u64>,
}

fn default_df_preference() -> u32 {
    32_768
}

fn default_df_algorithm() -> String {
    "default-modulo".to_string()
}

fn default_redundancy_mode() -> String {
    "all-active".to_string()
}

/// JSON Schema for the TOML config file, pretty-printed with a trailing
/// newline. Emitted by `rustbgpd --dump-config-schema` and committed at
/// `docs/rustbgpd.schema.json` (freshness-checked in `config::tests`).
pub fn config_json_schema() -> String {
    let schema = schemars::schema_for!(Config);
    let mut json = serde_json::to_string_pretty(&schema)
        .expect("config JSON Schema serialization cannot fail");
    json.push('\n');
    json
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
    #[error(
        "invalid send_hold_time {value}: must be 0 (disabled) or greater than hold_time \
         {hold_time} (RFC 9687 §4.4)"
    )]
    InvalidSendHoldTime { value: u32, hold_time: u16 },
    #[error(
        "invalid slow_peer_threshold_pct {value}: must be between 1 and 100 \
         (percent of the outbound writer buffer)"
    )]
    InvalidSlowPeerThreshold { value: u8 },
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
    #[error("invalid event_history config: {reason}")]
    InvalidEventHistoryConfig { reason: String },
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
    #[error("invalid managed netdev config: {reason}")]
    InvalidManagedNetdev { reason: String },
    #[error("invalid FIB table config: {reason}")]
    InvalidFibTable { reason: String },
    #[error("invalid BFD config: {reason}")]
    InvalidBfd { reason: String },
    #[error("rpol policy file {path:?}: {reason}")]
    InvalidRpolFile { path: String, reason: String },
}
