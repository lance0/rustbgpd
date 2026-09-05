//! Read-only Model Context Protocol server over rustbgpd's gRPC explain
//! surfaces.
//!
//! The server speaks MCP over stdio (newline-delimited JSON-RPC on stdin and
//! stdout) and is a plain gRPC client of a running daemon. An MCP host spawns
//! it as a subprocess on the operator's own workstation; adopting it adds no
//! process to the router.
//!
//! # Read-only by two independent controls
//!
//! 1. **No write tool exists in this binary.** Every tool is registered in
//!    [`TOOL_METHOD_PATHS`] with the gRPC method it calls, and a contract test
//!    fails the build if any entry names a method the daemon classifies as
//!    `mutating` or `operator_only`. There is no call-time gate to bypass and
//!    no hidden tool to enable.
//! 2. **The documented deployment** points the server at a listener capped at
//!    `max_tier = "sensitive_read"` whose principal maps to the `observer`
//!    role.
//!
//! Neither control is sufficient alone. Control 1 is a property of this source
//! tree, not of the daemon: a daemon serving an owner-only Unix socket with no
//! configured principal authorizes the reserved implicit principal
//! `local-operator` at Operator tier, so a colocated deployment hands this
//! process the daemon's highest credentials and only control 1 stands between
//! them and a write. Control 2 is a property of one daemon's configuration,
//! which this process cannot verify and does not attempt to.

#![deny(unsafe_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::{Json, Parameters};
use rmcp::model::{ErrorData, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use rustbgpd_api::proto;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use tonic::metadata::AsciiMetadataValue;
use tonic::service::Interceptor;
use tonic::service::interceptor::InterceptedService;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};

/// Every tool this server registers, paired with the gRPC method it calls.
///
/// This is the tool surface's machine-checkable contract. `tests/inventory_contract.rs`
/// asserts each path exists in `docs/reference/grpc-method-inventory.json` and
/// carries a `read` or `sensitive_read` tier, so a write RPC cannot reach the
/// tool surface without failing the build.
pub const TOOL_METHOD_PATHS: &[(&str, &str)] = &[
    (
        "rbgp_explain_export",
        "/rustbgpd.v1.RibService/ExplainAdvertisedRoute",
    ),
    (
        "rbgp_explain_import",
        "/rustbgpd.v1.PolicyService/ExplainImportPolicy",
    ),
    (
        "rbgp_explain_best_path",
        "/rustbgpd.v1.RibService/ExplainBestPath",
    ),
    (
        "rbgp_list_rejected",
        "/rustbgpd.v1.PolicyService/ListRejectedRoutes",
    ),
    (
        "rbgp_list_peers",
        "/rustbgpd.v1.NeighborService/ListNeighbors",
    ),
    ("rbgp_get_health", "/rustbgpd.v1.ControlService/GetHealth"),
    (
        "rbgp_explain_evpn_route",
        "/rustbgpd.v1.RibService/ExplainEvpnRoute",
    ),
];

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

/// The two endpoint families the server accepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DaemonEndpoint {
    /// A complete `http://` or `https://` URI.
    Tcp(String),
    /// An absolute Unix-domain socket path.
    Uds(PathBuf),
}

impl DaemonEndpoint {
    /// The URI handed to tonic's channel builder.
    #[must_use]
    pub fn channel_uri(&self) -> String {
        match self {
            Self::Tcp(uri) => uri.clone(),
            Self::Uds(path) => format!("unix://{}", path.display()),
        }
    }
}

/// Parse a daemon endpoint, matching the `birdwatcher-adapter` contract:
/// complete HTTP(S) TCP URIs, or `unix:///absolute/path`.
///
/// # Errors
///
/// Returns [`std::io::ErrorKind::InvalidInput`] for a relative socket path, a
/// bare `unix:` prefix, a scheme this server does not speak, or a URI tonic
/// itself rejects.
pub fn parse_daemon_endpoint(addr: &str) -> Result<DaemonEndpoint, std::io::Error> {
    if let Some(path) = addr.strip_prefix("unix://") {
        if path.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid gRPC endpoint: unix:// path must not be empty",
            ));
        }
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "invalid gRPC endpoint: Unix socket path must be absolute: {}",
                    path.display()
                ),
            ));
        }
        return Ok(DaemonEndpoint::Uds(path));
    }

    if addr.starts_with("unix:") {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid gRPC endpoint: use unix:///absolute/path",
        ));
    }

    if !(addr.starts_with("http://") || addr.starts_with("https://")) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "invalid gRPC endpoint: expected http://, https://, or unix:///absolute/path",
        ));
    }

    Endpoint::from_shared(addr.to_string()).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid gRPC endpoint: {error}"),
        )
    })?;
    Ok(DaemonEndpoint::Tcp(addr.to_string()))
}

/// Attaches a bearer token to every outbound request when one is configured.
#[derive(Clone)]
pub struct BearerInterceptor {
    authorization: Option<AsciiMetadataValue>,
}

impl BearerInterceptor {
    /// Build an interceptor that attaches `authorization` when a token was
    /// configured, and nothing otherwise.
    #[must_use]
    pub fn new(authorization: Option<AsciiMetadataValue>) -> Self {
        Self { authorization }
    }
}

impl Interceptor for BearerInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(value) = &self.authorization {
            request
                .metadata_mut()
                .insert("authorization", value.clone());
        }
        Ok(request)
    }
}

/// The authenticated channel every generated client is built over.
pub type Upstream = InterceptedService<Channel, BearerInterceptor>;

/// Read a bearer token from `token_file` and render it as an `authorization`
/// metadata value.
///
/// # Errors
///
/// Returns an error when the file cannot be read, is empty, or holds bytes
/// that are not valid ASCII gRPC metadata.
pub fn load_bearer_authorization(
    token_file: Option<&Path>,
) -> Result<Option<AsciiMetadataValue>, std::io::Error> {
    let Some(token_file) = token_file else {
        return Ok(None);
    };
    let raw = std::fs::read_to_string(token_file)?;
    let token = raw.trim_end();
    if token.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("token file is empty: {}", token_file.display()),
        ));
    }
    let value = AsciiMetadataValue::try_from(format!("Bearer {token}")).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "invalid token file {}: authorization value must be valid ASCII gRPC metadata",
                token_file.display()
            ),
        )
    })?;
    Ok(Some(value))
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Map a `tonic::Status` onto an MCP error.
///
/// `InvalidArgument` and `NotFound` are caller mistakes and map to
/// `invalid_params`; everything else is `internal_error`. `PermissionDenied`
/// names the tier problem explicitly, because that is the failure an operator
/// hits after wiring this server to a listener capped below `sensitive_read`
/// or to a principal without the `observer` role.
#[must_use]
pub fn map_status(status: &Status) -> ErrorData {
    let detail = status.message().to_string();
    match status.code() {
        tonic::Code::InvalidArgument | tonic::Code::NotFound => {
            ErrorData::invalid_params(format!("{}: {detail}", status.code().description()), None)
        }
        tonic::Code::PermissionDenied => ErrorData::internal_error(
            format!(
                "daemon refused the call: {detail}. Every tool here calls a `sensitive_read` \
                 method, so the configured listener needs `max_tier = \"sensitive_read\"` and a \
                 principal mapped to a role that grants it (`observer`)."
            ),
            None,
        ),
        tonic::Code::Unauthenticated => ErrorData::internal_error(
            format!(
                "daemon rejected the credential: {detail}. Check `--grpc-token-file` against the \
                 listener's configured principal."
            ),
            None,
        ),
        code => ErrorData::internal_error(format!("{}: {detail}", code.description()), None),
    }
}

// ---------------------------------------------------------------------------
// Tool parameter and result types
// ---------------------------------------------------------------------------

/// Address family scope accepted by the explain tools.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    /// Let the daemon apply its own default for the request.
    #[default]
    Unspecified,
    /// IPv4 unicast.
    Ipv4Unicast,
    /// IPv6 unicast.
    Ipv6Unicast,
}

impl Family {
    fn as_proto(self) -> i32 {
        match self {
            Self::Unspecified => proto::AddressFamily::Unspecified as i32,
            Self::Ipv4Unicast => proto::AddressFamily::Ipv4Unicast as i32,
            Self::Ipv6Unicast => proto::AddressFamily::Ipv6Unicast as i32,
        }
    }
}

/// Render a generated enum name as the `snake_case` token the rest of the tool
/// surface uses: `ADDRESS_FAMILY_IPV4_UNICAST` becomes `ipv4_unicast`.
fn strip_enum_prefix(name: &str, prefix: &str) -> String {
    name.strip_prefix(prefix).unwrap_or(name).to_lowercase()
}

fn family_label(value: i32) -> String {
    proto::AddressFamily::try_from(value).map_or_else(
        |_| format!("unknown({value})"),
        |family| strip_enum_prefix(family.as_str_name(), "ADDRESS_FAMILY_"),
    )
}

/// "Why is this prefix not advertised to that peer?"
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExplainExportParams {
    /// IPv4 or IPv6 literal of the peer the route would be advertised to.
    pub peer_address: String,
    /// Prefix to explain, without the length (e.g. `203.0.113.0`).
    pub prefix: String,
    /// Prefix length in bits.
    pub prefix_length: u32,
}

/// One rung of the export decision ladder.
#[derive(Debug, Serialize, JsonSchema)]
pub struct GateStep {
    /// Position in live evaluation order, starting at 1.
    pub step: u32,
    /// Stable gate name (`split_horizon`, `rr_reflection`, `export_policy`, ...).
    pub gate: String,
    /// Reason code for this step.
    pub code: String,
    /// `pass`, `stop`, `not_applicable`, or `unspecified`.
    pub verdict: String,
    /// Human-readable detail; not a stable machine-parsable grammar.
    pub detail: String,
}

/// The export-gate ladder plus the decision it produced.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ExplainExportResult {
    /// `advertise`, `deny`, `no_best_route`, or `unsupported_family`.
    pub decision: String,
    /// Peer the explain was scoped to.
    pub peer_address: String,
    /// Prefix explained, in CIDR form.
    pub prefix: String,
    /// Next hop the route would carry.
    pub next_hop: String,
    /// Adj-RIB-In source peer of the explained route.
    pub route_peer_address: String,
    /// Full gate ladder in live evaluation order. A `stop` step names the gate
    /// that halted the route.
    pub gates: Vec<GateStep>,
    /// The gate that stopped the route, when one did.
    pub stopped_at_gate: Option<String>,
    /// Reason codes and messages attached to the decision.
    pub reasons: Vec<ReasonLine>,
    /// Attribute modifications export policy would apply, rendered as
    /// `field = value` lines. Empty when policy changes nothing.
    pub modifications: Vec<String>,
    /// True when the decision is `advertise` but an identical route already
    /// sits in the advertised state, so the live path suppresses
    /// re-announcement. Send-side state only — it never means the peer holds
    /// the route.
    pub already_advertised: bool,
}

/// A decision reason code with its message.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ReasonLine {
    /// Stable `snake_case` reason code.
    pub code: String,
    /// Human-readable message.
    pub message: String,
}

/// "Why didn't this prefix come in?"
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExplainImportParams {
    /// IPv4 or IPv6 literal of the peer whose import-decision cache to consult.
    pub peer_address: String,
    /// Prefix to explain, without the length.
    pub prefix: String,
    /// Prefix length in bits.
    pub prefix_length: u32,
    /// Address family scope. Defaults to unspecified.
    #[serde(default)]
    pub family: Family,
    /// RFC 7911 path identifier. Omit to return every matching path.
    #[serde(default)]
    pub path_id: Option<u32>,
}

/// One cached import decision.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ImportMatch {
    /// `permit`, `deny`, `withdrawn`, `evicted`, `stale`, `not_seen`,
    /// `cache_disabled`, or `no_session`. The last three are configuration or
    /// session facts, not "the prefix was rejected".
    pub outcome: String,
    /// Prefix this match covers, in CIDR form.
    pub prefix: String,
    /// RFC 7911 path identifier.
    pub path_id: u32,
    /// Deciding chain member, or `chain_default_permit`. Empty for an inline
    /// deny or an absent chain.
    pub matched_policy: String,
    /// RPKI origin-validation state at evaluation time.
    pub rpki_validation: String,
    /// ASPA path-verification state at evaluation time.
    pub aspa_validation: String,
    /// Attribute modifications applied on import, as `field = value` lines.
    pub modifications: Vec<String>,
    /// Per-term rendered trace lines for an rpol member, in walk order. Empty
    /// for TOML members.
    pub statements: Vec<String>,
}

/// Cached import decisions for one prefix on one session.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ExplainImportResult {
    /// Peer whose cache was consulted.
    pub peer_address: String,
    /// Prefix explained, in CIDR form.
    pub prefix: String,
    /// Address family the request was scoped to.
    pub family: String,
    /// The session's current import-policy generation. A match recorded under
    /// an older generation reports the `stale` outcome.
    pub current_policy_generation: u64,
    /// One entry per cached `(peer, prefix, path_id)` the request resolves to.
    pub matches: Vec<ImportMatch>,
}

/// "Which path won for this prefix, and why?"
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExplainBestPathParams {
    /// Prefix to explain, without the length.
    pub prefix: String,
    /// Prefix length in bits.
    pub prefix_length: u32,
    /// Optional peer to scope the explanation to. Empty gives the global view.
    #[serde(default)]
    pub peer_address: String,
}

/// One non-winning path and the step that eliminated it.
#[derive(Debug, Serialize, JsonSchema)]
pub struct BestPathCandidateLine {
    /// Adj-RIB-In source peer of this candidate.
    pub peer_address: String,
    /// Candidate's next hop.
    pub next_hop: String,
    /// `AS_PATH` rendering.
    pub as_path: String,
    /// Decisive best-path step against the winner, in the stable `snake_case`
    /// step vocabulary.
    pub vs_best_reason: String,
    /// Compared values behind `vs_best_reason`, candidate's value first.
    /// Human-oriented text, not a stable grammar.
    pub vs_best_detail: String,
    /// Equal-cost multipath eligibility versus the best route.
    pub multipath: String,
}

/// The best-path winner and the candidates it beat.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ExplainBestPathResult {
    /// Prefix explained, in CIDR form.
    pub prefix: String,
    /// Peer the explanation was scoped to; empty for the global view.
    pub peer_address: String,
    /// Source peer of the winning path.
    pub best_peer_address: String,
    /// Next hop of the winning path.
    pub best_next_hop: String,
    /// `AS_PATH` of the winning path.
    pub best_as_path: String,
    /// The step at which the runner-up was eliminated, or `only_path`.
    pub best_reason: String,
    /// Compared values behind `best_reason`, winner's value first.
    pub best_reason_detail: String,
    /// Every non-best path the RIB knows for the prefix, in the daemon's order.
    pub candidates: Vec<BestPathCandidateLine>,
}

/// "What did this peer send that we threw away?"
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ListRejectedParams {
    /// IPv4 or IPv6 literal of the peer whose retention store to list.
    pub peer_address: String,
    /// Maximum rejections to return. `0` or omitted returns everything the
    /// daemon retained; a smaller value sets `truncated` when it bites.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// One retained rejection.
#[derive(Debug, Serialize, JsonSchema)]
pub struct RejectedRouteLine {
    /// Prefix, in CIDR form.
    pub prefix: String,
    /// RFC 7911 path identifier.
    pub path_id: u32,
    /// Canonical `snake_case` reject-reason token.
    pub reason: String,
    /// Sub-mechanism detail: matched policy name, or the gate's sub-reason.
    pub reason_detail: String,
    /// Wire next hop the rejected announcement carried.
    pub next_hop: String,
    /// `AS_PATH` rendering; truncated with a trailing ellipsis at the retention
    /// byte budget.
    pub as_path: String,
    /// RPKI origin-validation state at rejection time.
    pub rpki_validation: String,
    /// ASPA path-verification state at rejection time.
    pub aspa_validation: String,
    /// Rejection wall-clock time as Unix nanoseconds.
    pub rejected_at_unix_ns: i64,
}

/// Retained rejections for one peer, with the retention state that gives an
/// empty listing its meaning.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ListRejectedResult {
    /// Peer whose store was listed.
    pub peer_address: String,
    /// Whether the session retains rejected routes at all. When this is false
    /// an empty `routes` list is a configuration fact and says nothing about
    /// whether routes were rejected.
    pub retention_enabled: bool,
    /// The session's retention cap. When the daemon returned exactly this many
    /// rejections, older ones were displaced.
    pub capacity: u32,
    /// Human-readable statement of what an empty or full listing means here.
    pub retention_note: String,
    /// The rejections, oldest ordering as the daemon returned them.
    pub routes: Vec<RejectedRouteLine>,
    /// Rejections the daemon returned that `limit` cut from `routes`. `0` means
    /// the list is complete with respect to what the daemon retained.
    pub truncated_by_limit: usize,
    /// Older retained rejections this session's bounded store displaced since
    /// its last reset. Absent when the daemon predates the field.
    pub evictions_since_reset: Option<u64>,
}

/// Exact EVPN route key, mirroring the `rbgp evpn explain` selector vocabulary.
///
/// Every variant is an exact key, not a filter. Type 2 with `ip` omitted
/// selects the MAC-only key rather than every host IP under that MAC.
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "route_type", rename_all = "snake_case")]
pub enum EvpnKey {
    /// Type 2 MAC/IP. Omitting `ip` selects the MAC-only key.
    MacIp {
        /// Ethernet Tag; `0` for a single-tag EVI.
        #[serde(default)]
        ethernet_tag: u32,
        /// MAC address, colon-separated.
        mac: String,
        /// Exact host address. Omit for the MAC-only key.
        #[serde(default)]
        ip: Option<String>,
    },
    /// Type 3 inclusive multicast, by exact originator.
    Imet {
        /// Ethernet Tag; `0` for a single-tag EVI.
        #[serde(default)]
        ethernet_tag: u32,
        /// Originating VTEP address.
        originator_ip: String,
    },
    /// Type 4 Ethernet Segment route, by exact segment and originator.
    Es {
        /// Ethernet Segment Identifier.
        esi: String,
        /// Originating VTEP address.
        originator_ip: String,
    },
    /// Type 5 IP prefix. Host bits must be zero.
    IpPrefix {
        /// Ethernet Tag; `0` for a single-tag EVI.
        #[serde(default)]
        ethernet_tag: u32,
        /// Canonical CIDR prefix.
        prefix: String,
    },
    /// Type 1 per-ES Ethernet A-D. The Ethernet Tag is always `MAX_ET` and is
    /// not a caller parameter.
    EadPerEs {
        /// Ethernet Segment Identifier.
        esi: String,
    },
    /// Type 1 per-EVI Ethernet A-D. `MAX_ET` is not a per-EVI key.
    EadPerEvi {
        /// Ethernet Segment Identifier.
        esi: String,
        /// Ethernet Tag; must not be `MAX_ET`.
        ethernet_tag: u32,
    },
}

impl EvpnKey {
    fn into_selector(self, rd: String) -> proto::EvpnRouteSelector {
        use proto::evpn_route_selector::Route;
        let route = match self {
            Self::MacIp {
                ethernet_tag,
                mac,
                ip,
            } => Route::MacIp(proto::EvpnMacIpSelector {
                ethernet_tag,
                mac,
                ip: ip.unwrap_or_default(),
            }),
            Self::Imet {
                ethernet_tag,
                originator_ip,
            } => Route::Imet(proto::EvpnImetSelector {
                ethernet_tag,
                originator_ip,
            }),
            Self::Es { esi, originator_ip } => {
                Route::Es(proto::EvpnEsSelector { esi, originator_ip })
            }
            Self::IpPrefix {
                ethernet_tag,
                prefix,
            } => Route::IpPrefix(proto::EvpnIpPrefixSelector {
                ethernet_tag,
                prefix,
            }),
            // MAX_ET identifies the per-ES form; the caller does not supply it.
            Self::EadPerEs { esi } => Route::EadPerEs(proto::EvpnEadSelector {
                esi,
                ethernet_tag: u32::MAX,
            }),
            Self::EadPerEvi { esi, ethernet_tag } => {
                Route::EadPerEvi(proto::EvpnEadSelector { esi, ethernet_tag })
            }
        };
        proto::EvpnRouteSelector {
            rd,
            route: Some(route),
        }
    }
}

/// "What happened to this exact EVPN route?"
#[derive(Debug, Deserialize, Serialize, JsonSchema)]
pub struct ExplainEvpnRouteParams {
    /// Route Distinguisher, `asn:nn` or `ip:nn`.
    pub rd: String,
    /// The exact route key.
    pub key: EvpnKey,
    /// Optional peer whose retained accepted state to look up. Absence of
    /// retained state is not an import-rejection explanation.
    #[serde(default)]
    pub received_from: Option<String>,
    /// Optional peer to evaluate current export eligibility toward.
    #[serde(default)]
    pub advertised_to: Option<String>,
}

/// One EVPN route as the daemon holds it.
#[derive(Debug, Serialize, JsonSchema)]
pub struct EvpnRouteLine {
    /// RFC 7432 route type (1-5).
    pub route_type: u32,
    /// Route Distinguisher.
    pub rd: String,
    /// Ethernet Segment Identifier; empty when the type carries none.
    pub esi: String,
    /// Ethernet Tag as the daemon renders it.
    pub ethernet_tag: String,
    /// MAC address; empty for types that carry none.
    pub mac: String,
    /// Host IP; empty for types that carry none.
    pub ip: String,
    /// Type 5 prefix; empty for other types.
    pub prefix: String,
    /// Next hop.
    pub next_hop: String,
    /// Peer this route came from; empty when locally originated.
    pub peer_address: String,
    /// `AS_PATH` rendering.
    pub as_path: String,
    /// MPLS label 1.
    pub label: u32,
}

/// Current export evaluation toward one peer.
#[derive(Debug, Serialize, JsonSchema)]
pub struct EvpnExportResult {
    /// Peer the export was evaluated toward.
    pub peer_address: String,
    /// `advertise`, `deny`, `no_best_route`, or `unsupported_family`.
    pub decision: String,
    /// Full gate ladder in live evaluation order.
    pub gates: Vec<GateStep>,
    /// The gate that stopped the route, when one did.
    pub stopped_at_gate: Option<String>,
    /// Reason codes and messages attached to the decision.
    pub reasons: Vec<ReasonLine>,
    /// Attribute modifications export policy would apply.
    pub modifications: Vec<String>,
    /// Dry-run staged result from the installed best. No state was changed.
    pub staged: Option<EvpnRouteLine>,
    /// Committed local Adj-RIB-Out entry. This is send-side state only: it is
    /// not proof the peer received or installed the route.
    pub advertised: Option<EvpnRouteLine>,
    /// True when an identical route already sits in the advertised state.
    pub already_advertised: bool,
    /// True when outbound state for this peer has pending work.
    pub outbound_dirty: bool,
}

/// Selection and export story for one exact EVPN route.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ExplainEvpnRouteResult {
    /// Installed Loc-RIB route. **Read `selection_note` before trusting this**
    /// — while selection is deferred it can differ from fresh selection.
    pub best: Option<EvpnRouteLine>,
    /// Fresh selection winner, recomputed for this query.
    pub selection_best: Option<EvpnRouteLine>,
    /// The requested source when it is not the fresh winner, otherwise the
    /// winner's runner-up.
    pub compared: Option<EvpnRouteLine>,
    /// How many candidates the selection considered.
    pub candidate_count: u64,
    /// Why `selection_best` beats `compared`. Absent when nothing was compared.
    pub selection_reason: Option<ReasonLine>,
    /// True when selection is deferred, so `best` may be stale.
    pub selection_deferred: bool,
    /// Plain statement of whether `best` is current. Always populated.
    pub selection_note: String,
    /// Peer whose retained accepted state was looked up; empty when none was
    /// requested.
    pub received_from: String,
    /// The retained accepted route from that peer, when one is retained.
    pub received: Option<EvpnRouteLine>,
    /// What the `received` field does and does not establish. Always populated.
    pub received_note: String,
    /// Current export evaluation, when `advertised_to` was supplied.
    pub export: Option<EvpnExportResult>,
}

/// No parameters.
#[derive(Debug, Default, Deserialize, Serialize, JsonSchema)]
pub struct NoParams {}

/// One configured neighbor.
#[derive(Debug, Serialize, JsonSchema)]
pub struct PeerLine {
    /// Neighbor address.
    pub address: String,
    /// Peer AS.
    pub peer_as: u32,
    /// BGP FSM state.
    pub state: String,
    /// Seconds in the current state.
    pub uptime_seconds: u64,
    /// Routes accepted from this peer.
    pub routes_received: u64,
    /// Routes advertised to this peer.
    pub routes_advertised: u64,
}

/// The neighbor table.
#[derive(Debug, Serialize, JsonSchema)]
pub struct ListPeersResult {
    /// Configured neighbors, ordered numerically by address.
    pub peers: Vec<PeerLine>,
}

/// Daemon liveness and headline counters.
#[derive(Debug, Serialize, JsonSchema)]
pub struct HealthResult {
    /// Whether the daemon reports itself healthy.
    pub healthy: bool,
    /// Seconds since daemon start.
    pub uptime_seconds: u64,
    /// Established sessions.
    pub active_peers: u32,
    /// Routes in the Loc-RIB.
    pub total_routes: u32,
    /// Daemon package version. Empty from a daemon predating the field.
    pub daemon_version: String,
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// The MCP server: a gRPC client of one daemon, exposing seven read-only tools.
#[derive(Clone)]
pub struct RustbgpdMcp {
    upstream: Upstream,
    tool_router: ToolRouter<Self>,
}

#[tool_router(router = tool_router)]
impl RustbgpdMcp {
    /// Build a server over an already-constructed upstream channel.
    #[must_use]
    pub fn new(upstream: Upstream) -> Self {
        Self {
            upstream,
            tool_router: Self::tool_router(),
        }
    }

    /// Explain the export decision for one prefix toward one peer, as the full
    /// ordered gate ladder the live export path evaluates.
    #[tool(
        name = "rbgp_explain_export",
        description = "Explain why a prefix is or is not advertised to a peer, as the daemon's \
                       full ordered export-gate ladder (split horizon, RR reflection, family, \
                       LLGR, ORF, RT membership, export policy, Adj-RIB-Out). A `stop` verdict \
                       names the gate that halted the route."
    )]
    pub async fn explain_export(
        &self,
        Parameters(params): Parameters<ExplainExportParams>,
    ) -> Result<Json<ExplainExportResult>, ErrorData> {
        let mut client = proto::rib_service_client::RibServiceClient::new(self.upstream.clone());
        let response = client
            .explain_advertised_route(proto::ExplainAdvertisedRouteRequest {
                peer_address: params.peer_address.clone(),
                prefix: params.prefix.clone(),
                prefix_length: params.prefix_length,
                ..Default::default()
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();

        let gates = gate_ladder(&response.gates);

        Ok(Json(ExplainExportResult {
            decision: decision_label(response.decision),
            peer_address: response.peer_address,
            prefix: format!("{}/{}", response.prefix, response.prefix_length),
            next_hop: response.next_hop,
            route_peer_address: response.route_peer_address,
            stopped_at_gate: stopped_at_gate(&gates),
            gates,
            reasons: response
                .reasons
                .into_iter()
                .map(|reason| ReasonLine {
                    code: reason.code,
                    message: reason.message,
                })
                .collect(),
            modifications: render_modifications(response.modifications.as_ref()),
            already_advertised: response.already_advertised,
        }))
    }

    /// Explain the cached import decision for one prefix on one session.
    #[tool(
        name = "rbgp_explain_import",
        description = "Explain why a prefix from a peer was accepted or rejected on import, with \
                       the matched policy, RPKI and ASPA validation state, applied modifications, \
                       and the per-term policy trace. Outcomes `cache_disabled`, `no_session`, \
                       and `evicted` mean the question could not be answered — they are not \
                       rejections."
    )]
    pub async fn explain_import(
        &self,
        Parameters(params): Parameters<ExplainImportParams>,
    ) -> Result<Json<ExplainImportResult>, ErrorData> {
        let mut client =
            proto::policy_service_client::PolicyServiceClient::new(self.upstream.clone());
        let response = client
            .explain_import_policy(proto::ExplainImportPolicyRequest {
                peer_address: params.peer_address,
                afi_safi: params.family.as_proto(),
                prefix: params.prefix,
                prefix_length: params.prefix_length,
                path_id: params.path_id,
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();

        Ok(Json(ExplainImportResult {
            peer_address: response.peer_address,
            prefix: format!("{}/{}", response.prefix, response.prefix_length),
            family: family_label(response.afi_safi),
            current_policy_generation: response.current_policy_generation,
            matches: response
                .matches
                .into_iter()
                .map(|entry| ImportMatch {
                    outcome: import_outcome_label(entry.outcome),
                    prefix: format!("{}/{}", entry.prefix, entry.prefix_length),
                    path_id: entry.path_id,
                    matched_policy: entry.matched_policy,
                    rpki_validation: entry.rpki_validation,
                    aspa_validation: entry.aspa_validation,
                    modifications: render_modifications(entry.modifications.as_ref()),
                    statements: render_statements(&entry.statements),
                })
                .collect(),
        }))
    }

    /// Explain which path won best-path selection for a prefix.
    #[tool(
        name = "rbgp_explain_best_path",
        description = "Explain which path won best-path selection for a prefix and at which \
                       decision step, listing every losing candidate with the step that \
                       eliminated it. Optionally scoped to one peer."
    )]
    pub async fn explain_best_path(
        &self,
        Parameters(params): Parameters<ExplainBestPathParams>,
    ) -> Result<Json<ExplainBestPathResult>, ErrorData> {
        let mut client = proto::rib_service_client::RibServiceClient::new(self.upstream.clone());
        let response = client
            .explain_best_path(proto::ExplainBestPathRequest {
                prefix: params.prefix,
                prefix_length: params.prefix_length,
                peer_address: params.peer_address,
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();

        let best = response.best_route.unwrap_or_default();
        Ok(Json(ExplainBestPathResult {
            prefix: format!("{}/{}", response.prefix, response.prefix_length),
            peer_address: response.peer_address,
            best_as_path: render_as_path(&best.as_path),
            best_peer_address: best.peer_address,
            best_next_hop: best.next_hop,
            best_reason: response.best_reason,
            best_reason_detail: response.best_reason_detail,
            candidates: response
                .candidates
                .into_iter()
                .map(|candidate| {
                    let route = candidate.route.unwrap_or_default();
                    BestPathCandidateLine {
                        as_path: render_as_path(&route.as_path),
                        peer_address: route.peer_address,
                        next_hop: route.next_hop,
                        vs_best_reason: candidate.vs_best_reason,
                        vs_best_detail: candidate.vs_best_detail,
                        multipath: candidate.multipath,
                    }
                })
                .collect(),
        }))
    }

    /// List the rejections one peer's session retained.
    #[tool(
        name = "rbgp_list_rejected",
        description = "List the routes a peer announced that the daemon rejected and retained, \
                       with the reject-reason token and validation state. Always read \
                       `retention_enabled`: when it is false the list is empty because retention \
                       is off, not because nothing was rejected."
    )]
    pub async fn list_rejected(
        &self,
        Parameters(params): Parameters<ListRejectedParams>,
    ) -> Result<Json<ListRejectedResult>, ErrorData> {
        let mut client =
            proto::policy_service_client::PolicyServiceClient::new(self.upstream.clone());
        let response = client
            .list_rejected_routes(proto::ListRejectedRoutesRequest {
                peer_address: params.peer_address,
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();

        let retained = response.routes.len();
        let limit = params
            .limit
            .filter(|limit| *limit > 0)
            .map_or(retained, |limit| limit as usize);
        let truncated_by_limit = retained.saturating_sub(limit);
        let at_capacity = response.capacity > 0 && retained >= response.capacity as usize;

        Ok(Json(ListRejectedResult {
            retention_note: retention_note(response.retention_enabled, at_capacity, retained),
            peer_address: response.peer_address,
            retention_enabled: response.retention_enabled,
            capacity: response.capacity,
            routes: response
                .routes
                .into_iter()
                .take(limit)
                .map(|route| RejectedRouteLine {
                    prefix: format!("{}/{}", route.prefix, route.prefix_length),
                    path_id: route.path_id,
                    reason: route.reason,
                    reason_detail: route.reason_detail,
                    next_hop: route.next_hop,
                    as_path: route.as_path,
                    rpki_validation: route.rpki_validation,
                    aspa_validation: route.aspa_validation,
                    rejected_at_unix_ns: route.rejected_at_unix_ns,
                })
                .collect(),
            truncated_by_limit,
            evictions_since_reset: response.evictions_since_reset,
        }))
    }

    /// List configured neighbors and their session state.
    #[tool(
        name = "rbgp_list_peers",
        description = "List the daemon's configured BGP neighbors with session state, peer AS, \
                       uptime, and received/advertised route counts."
    )]
    pub async fn list_peers(
        &self,
        Parameters(_): Parameters<NoParams>,
    ) -> Result<Json<ListPeersResult>, ErrorData> {
        let mut client =
            proto::neighbor_service_client::NeighborServiceClient::new(self.upstream.clone());
        let response = client
            .list_neighbors(proto::ListNeighborsRequest {})
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();

        Ok(Json(ListPeersResult {
            peers: response
                .neighbors
                .into_iter()
                .map(|neighbor| {
                    let config = neighbor.config.unwrap_or_default();
                    PeerLine {
                        address: config.address,
                        peer_as: config.remote_asn,
                        state: session_state_label(neighbor.state),
                        uptime_seconds: neighbor.uptime_seconds,
                        routes_received: neighbor.prefixes_received,
                        routes_advertised: neighbor.prefixes_sent,
                    }
                })
                .collect(),
        }))
    }

    /// Report daemon liveness and headline counters.
    #[tool(
        name = "rbgp_get_health",
        description = "Report daemon liveness, uptime, established-peer count, Loc-RIB route \
                       count, and package version."
    )]
    pub async fn get_health(
        &self,
        Parameters(_): Parameters<NoParams>,
    ) -> Result<Json<HealthResult>, ErrorData> {
        let mut client =
            proto::control_service_client::ControlServiceClient::new(self.upstream.clone());
        let response = client
            .get_health(proto::HealthRequest {})
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();

        Ok(Json(HealthResult {
            healthy: response.healthy,
            uptime_seconds: response.uptime_seconds,
            active_peers: response.active_peers,
            total_routes: response.total_routes,
            daemon_version: response.daemon_version,
        }))
    }

    /// Explain one exact EVPN route: selection story plus current export.
    #[tool(
        name = "rbgp_explain_evpn_route",
        description = "Explain one exact EVPN route (RFC 7432 Types 1-5): the selection story \
                       (installed best, fresh selection, compared candidate, candidate count, \
                       deciding reason) and, when `advertised_to` is given, the current export \
                       gate ladder toward that peer. Every key is exact, not a filter. Two \
                       results must not be over-read, and the response states both in words: an \
                       empty `received` for a peer is NOT an import-rejection explanation and NOT \
                       proof the peer never sent the key — import rejection history is not \
                       retained, so it supports no conclusion about what the peer sent. And when \
                       `selection_deferred` is true, the installed `best` may differ from fresh \
                       selection, so reporting it as current state would be wrong. Read \
                       `received_note` and `selection_note`."
    )]
    pub async fn explain_evpn_route(
        &self,
        Parameters(params): Parameters<ExplainEvpnRouteParams>,
    ) -> Result<Json<ExplainEvpnRouteResult>, ErrorData> {
        let mut client = proto::rib_service_client::RibServiceClient::new(self.upstream.clone());
        let received_from = params.received_from.unwrap_or_default();
        let response = client
            .explain_evpn_route(proto::ExplainEvpnRouteRequest {
                key: Some(params.key.into_selector(params.rd)),
                received_from: received_from.clone(),
                advertised_to: params.advertised_to.unwrap_or_default(),
            })
            .await
            .map_err(|status| map_status(&status))?
            .into_inner();

        let received = response.received.as_ref().map(evpn_route_line);
        Ok(Json(ExplainEvpnRouteResult {
            selection_note: selection_note(
                response.selection_deferred,
                response.selection_best.is_some(),
            ),
            received_note: received_note(&response.received_from, received.is_some()),
            best: response.best.as_ref().map(evpn_route_line),
            selection_best: response.selection_best.as_ref().map(evpn_route_line),
            compared: response.compared.as_ref().map(evpn_route_line),
            candidate_count: response.candidate_count,
            selection_reason: response.selection_reason.map(|reason| ReasonLine {
                code: reason.code,
                message: reason.message,
            }),
            selection_deferred: response.selection_deferred,
            received_from: response.received_from,
            received,
            export: response.export.map(|export| {
                let gates = gate_ladder(&export.gates);
                EvpnExportResult {
                    peer_address: export.peer_address,
                    decision: decision_label(export.decision),
                    stopped_at_gate: stopped_at_gate(&gates),
                    gates,
                    reasons: export
                        .reasons
                        .into_iter()
                        .map(|reason| ReasonLine {
                            code: reason.code,
                            message: reason.message,
                        })
                        .collect(),
                    modifications: render_modifications(export.modifications.as_ref()),
                    staged: export.staged.as_ref().map(evpn_route_line),
                    advertised: export.advertised.as_ref().map(evpn_route_line),
                    already_advertised: export.already_advertised,
                    outbound_dirty: export.outbound_dirty,
                }
            }),
        }))
    }
}

#[allow(
    clippy::unused_async_trait_impl,
    reason = "the #[tool_handler] macro emits the async ServerHandler methods; get_info resolves \
              immediately and has no call to await"
)]
#[tool_handler(router = self.tool_router)]
impl ServerHandler for RustbgpdMcp {
    fn get_info(&self) -> ServerInfo {
        // `ServerInfo` and `Implementation` are `#[non_exhaustive]`, so this
        // starts from a default and assigns the fields it owns.
        let mut info = ServerInfo::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info.server_info = Implementation::new("rustbgpd-mcp", env!("CARGO_PKG_VERSION"));
        info.instructions = Some(
            "Read-only view of a running rustbgpd daemon. Every tool calls a read-tier gRPC \
             method; this server registers no tool that can change daemon state. Start from \
             rbgp_explain_export for \"why is this prefix not advertised to that peer\" — it \
             returns the daemon's own ordered export-gate ladder, so the answer comes from live \
             evaluation rather than inference."
                .into(),
        );
        info
    }
}

// ---------------------------------------------------------------------------
// Host configuration
// ---------------------------------------------------------------------------

/// Render paste-ready `mcpServers` JSON for an MCP host.
///
/// The token argument is never echoed: the rendered config names a placeholder
/// path so a real token value cannot leak into a pasted snippet.
#[must_use]
pub fn print_config(command: &str, grpc_addr: &str, uses_token: bool) -> String {
    let mut args = vec![
        serde_json::Value::from("--grpc-addr"),
        serde_json::Value::from(grpc_addr),
    ];
    if uses_token {
        args.push(serde_json::Value::from("--grpc-token-file"));
        args.push(serde_json::Value::from("/path/to/rustbgpd-observer.token"));
    }
    let config = serde_json::json!({
        "mcpServers": {
            "rustbgpd": {
                "command": command,
                "args": args,
            }
        }
    });
    serde_json::to_string_pretty(&config)
        .unwrap_or_else(|error| format!("{{\"error\": \"{error}\"}}"))
}

// ---------------------------------------------------------------------------
// Label helpers
// ---------------------------------------------------------------------------

fn decision_label(value: i32) -> String {
    match proto::ExplainDecision::try_from(value) {
        Ok(proto::ExplainDecision::Advertise) => "advertise".into(),
        Ok(proto::ExplainDecision::Deny) => "deny".into(),
        Ok(proto::ExplainDecision::NoBestRoute) => "no_best_route".into(),
        Ok(proto::ExplainDecision::UnsupportedFamily) => "unsupported_family".into(),
        Ok(proto::ExplainDecision::Unspecified) => "unspecified".into(),
        Err(_) => format!("unknown({value})"),
    }
}

fn verdict_label(value: i32) -> String {
    match proto::ExportGateVerdict::try_from(value) {
        Ok(proto::ExportGateVerdict::Pass) => "pass".into(),
        Ok(proto::ExportGateVerdict::Stop) => "stop".into(),
        Ok(proto::ExportGateVerdict::NotApplicable) => "not_applicable".into(),
        Ok(proto::ExportGateVerdict::Unspecified) => "unspecified".into(),
        Err(_) => format!("unknown({value})"),
    }
}

fn import_outcome_label(value: i32) -> String {
    match proto::ImportExplainOutcome::try_from(value) {
        Ok(proto::ImportExplainOutcome::Permit) => "permit".into(),
        Ok(proto::ImportExplainOutcome::Deny) => "deny".into(),
        Ok(proto::ImportExplainOutcome::Withdrawn) => "withdrawn".into(),
        Ok(proto::ImportExplainOutcome::Evicted) => "evicted".into(),
        Ok(proto::ImportExplainOutcome::Stale) => "stale".into(),
        Ok(proto::ImportExplainOutcome::NotSeen) => "not_seen".into(),
        Ok(proto::ImportExplainOutcome::CacheDisabled) => "cache_disabled".into(),
        Ok(proto::ImportExplainOutcome::NoSession) => "no_session".into(),
        Ok(proto::ImportExplainOutcome::Unspecified) => "unspecified".into(),
        Err(_) => format!("unknown({value})"),
    }
}

fn session_state_label(value: i32) -> String {
    proto::SessionState::try_from(value).map_or_else(
        |_| format!("unknown({value})"),
        |state| strip_enum_prefix(state.as_str_name(), "SESSION_STATE_"),
    )
}

fn retention_note(enabled: bool, at_capacity: bool, retained: usize) -> String {
    if !enabled {
        return "reject retention is disabled on this session ([policy.reject_retention]); an \
                empty list is a configuration fact and does not mean nothing was rejected"
            .into();
    }
    if at_capacity {
        return "the retention store is at capacity, so this listing shows the most recent \
                rejections and older ones were displaced"
            .into();
    }
    if retained == 0 {
        return "reject retention is enabled and the store is empty: this session has rejected \
                nothing since its last reset"
            .into();
    }
    "reject retention is enabled and the store is below capacity, so this listing is complete for \
     this session"
        .into()
}

fn render_modifications(modifications: Option<&proto::ExplainModifications>) -> Vec<String> {
    let Some(modifications) = modifications else {
        return Vec::new();
    };
    let mut lines = Vec::new();
    if let Some(value) = modifications.set_local_pref {
        lines.push(format!("set_local_pref = {value}"));
    }
    if let Some(value) = modifications.set_med {
        lines.push(format!("set_med = {value}"));
    }
    if !modifications.set_next_hop.is_empty() {
        lines.push(format!("set_next_hop = {}", modifications.set_next_hop));
    }
    push_list(
        &mut lines,
        "communities_add",
        &modifications.communities_add,
    );
    push_list(
        &mut lines,
        "communities_remove",
        &modifications.communities_remove,
    );
    push_list(
        &mut lines,
        "extended_communities_add",
        &modifications.extended_communities_add,
    );
    push_list(
        &mut lines,
        "extended_communities_remove",
        &modifications.extended_communities_remove,
    );
    push_list(
        &mut lines,
        "large_communities_add",
        &modifications.large_communities_add,
    );
    push_list(
        &mut lines,
        "large_communities_remove",
        &modifications.large_communities_remove,
    );
    if let Some(asn) = modifications.as_path_prepend_asn {
        let count = modifications.as_path_prepend_count.unwrap_or(1);
        lines.push(format!("as_path_prepend = {asn} x{count}"));
    }
    lines
}

/// Number an export gate ladder in live evaluation order.
fn gate_ladder(gates: &[proto::ExportGateStep]) -> Vec<GateStep> {
    gates
        .iter()
        .enumerate()
        .map(|(index, step)| GateStep {
            step: u32::try_from(index + 1).unwrap_or(u32::MAX),
            gate: step.gate.clone(),
            code: step.code.clone(),
            verdict: verdict_label(step.verdict),
            detail: step.detail.clone(),
        })
        .collect()
}

/// Name the rung that halted the route, when one did.
fn stopped_at_gate(gates: &[GateStep]) -> Option<String> {
    gates
        .iter()
        .find(|step| step.verdict == "stop")
        .map(|step| step.gate.clone())
}

fn evpn_route_line(entry: &proto::EvpnRouteEntry) -> EvpnRouteLine {
    EvpnRouteLine {
        route_type: entry.route_type,
        rd: entry.rd.clone(),
        esi: entry.esi.clone(),
        ethernet_tag: entry.ethernet_tag.clone(),
        mac: entry.mac.clone(),
        ip: entry.ip.clone(),
        prefix: entry.prefix.clone(),
        next_hop: entry.next_hop.clone(),
        peer_address: entry.peer_address.clone(),
        as_path: render_as_path(&entry.as_path),
        label: entry.label,
    }
}

/// State in words whether the installed best is current.
///
/// A bare `selection_deferred: true` sitting beside `best` is easy to skim
/// past, and reporting a deferred `best` as current state is wrong. This says
/// so in the result itself.
fn selection_note(deferred: bool, has_fresh: bool) -> String {
    if deferred {
        return "SELECTION IS DEFERRED: the installed `best` may be stale and may differ from \
                `selection_best`. Do not report `best` as current state; `selection_best` is the \
                fresh winner for this query."
            .into();
    }
    if has_fresh {
        return "selection is not deferred, so the installed `best` reflects current selection"
            .into();
    }
    "selection is not deferred and no candidate was selected for this key".into()
}

/// State in words what an absent retained source does and does not establish.
fn received_note(received_from: &str, present: bool) -> String {
    if received_from.is_empty() {
        return "no accepted-source lookup was requested; `received` is empty for that reason \
                alone"
            .into();
    }
    if present {
        return format!("retained accepted state from {received_from}");
    }
    format!(
        "no retained accepted state from {received_from}. This is NOT an import-rejection \
         explanation and NOT proof that the peer never sent this key: import rejection history \
         is not retained for EVPN, so absence supports no conclusion about what the peer sent."
    )
}

/// Render an `AS_PATH` as the space-separated ASN list operators read.
fn render_as_path(as_path: &[u32]) -> String {
    as_path
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Flatten the per-term import trace into readable lines.
///
/// `.rpol` members carry rendered `term_traces` in walk order; TOML members
/// carry none, so those fall back to a line naming the deciding statement and
/// its action.
fn render_statements(statements: &[proto::ImportExplainStatementStep]) -> Vec<String> {
    let mut lines = Vec::new();
    for step in statements {
        if step.term_traces.is_empty() {
            let mut line = format!("{}: {}", step.policy_name, step.action);
            if step.default_action {
                line.push_str(" (default action)");
            }
            if !step.matched_conditions.is_empty() {
                let _ = write!(line, " [{}]", step.matched_conditions.join(", "));
            }
            lines.push(line);
        } else {
            lines.extend(
                step.term_traces
                    .iter()
                    .map(|trace| format!("{}: {trace}", step.policy_name)),
            );
        }
    }
    lines
}

fn push_list<T: std::fmt::Display>(lines: &mut Vec<String>, label: &str, values: &[T]) {
    if values.is_empty() {
        return;
    }
    let rendered: Vec<String> = values.iter().map(ToString::to_string).collect();
    lines.push(format!("{label} = [{}]", rendered.join(", ")));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parsing_accepts_the_two_supported_families() {
        assert_eq!(
            parse_daemon_endpoint("http://127.0.0.1:50051").unwrap(),
            DaemonEndpoint::Tcp("http://127.0.0.1:50051".into())
        );
        assert_eq!(
            parse_daemon_endpoint("unix:///run/rustbgpd/api.sock").unwrap(),
            DaemonEndpoint::Uds(PathBuf::from("/run/rustbgpd/api.sock"))
        );
        assert_eq!(
            parse_daemon_endpoint("unix:///run/rustbgpd/api.sock")
                .unwrap()
                .channel_uri(),
            "unix:///run/rustbgpd/api.sock"
        );
    }

    #[test]
    fn endpoint_parsing_rejects_malformed_input() {
        for addr in [
            "unix://",
            "unix://relative/path",
            "unix:/run/rustbgpd/api.sock",
            "127.0.0.1:50051",
            "grpc://127.0.0.1:50051",
        ] {
            assert!(
                parse_daemon_endpoint(addr).is_err(),
                "{addr} must not parse as an endpoint"
            );
        }
    }

    #[test]
    fn caller_mistakes_map_to_invalid_params_and_the_rest_to_internal_error() {
        assert_eq!(
            map_status(&Status::invalid_argument("bad prefix")).code,
            rmcp::model::ErrorCode::INVALID_PARAMS
        );
        assert_eq!(
            map_status(&Status::not_found("no such peer")).code,
            rmcp::model::ErrorCode::INVALID_PARAMS
        );
        assert_eq!(
            map_status(&Status::unavailable("daemon down")).code,
            rmcp::model::ErrorCode::INTERNAL_ERROR
        );
    }

    #[test]
    fn permission_denied_names_the_tier_problem() {
        let error = map_status(&Status::permission_denied("tier"));
        assert_eq!(error.code, rmcp::model::ErrorCode::INTERNAL_ERROR);
        assert!(
            error.message.contains("sensitive_read") && error.message.contains("observer"),
            "operators hitting this need the tier and role named: {}",
            error.message
        );
    }

    #[test]
    fn disabled_retention_never_reads_as_nothing_rejected() {
        let note = retention_note(false, false, 0);
        assert!(note.contains("disabled"), "{note}");
        assert!(
            note.contains("does not mean nothing was rejected"),
            "{note}"
        );

        let empty = retention_note(true, false, 0);
        assert!(empty.contains("rejected nothing"), "{empty}");

        let full = retention_note(true, true, 32);
        assert!(full.contains("displaced"), "{full}");
    }

    #[test]
    fn modifications_render_only_the_fields_policy_set() {
        assert!(render_modifications(None).is_empty());
        assert!(
            render_modifications(Some(&proto::ExplainModifications::default())).is_empty(),
            "an all-default modifications message means policy changed nothing"
        );

        let lines = render_modifications(Some(&proto::ExplainModifications {
            set_local_pref: Some(200),
            large_communities_add: vec!["64500:1:2".into()],
            as_path_prepend_asn: Some(64500),
            as_path_prepend_count: Some(3),
            ..Default::default()
        }));
        assert_eq!(
            lines,
            vec![
                "set_local_pref = 200".to_string(),
                "large_communities_add = [64500:1:2]".to_string(),
                "as_path_prepend = 64500 x3".to_string(),
            ]
        );
    }

    #[test]
    fn enum_labels_are_stable_snake_case_and_survive_unknown_values() {
        assert_eq!(decision_label(proto::ExplainDecision::Deny as i32), "deny");
        assert_eq!(verdict_label(proto::ExportGateVerdict::Stop as i32), "stop");
        assert_eq!(
            import_outcome_label(proto::ImportExplainOutcome::CacheDisabled as i32),
            "cache_disabled"
        );
        assert_eq!(decision_label(9999), "unknown(9999)");
        assert_eq!(verdict_label(9999), "unknown(9999)");
        assert_eq!(import_outcome_label(9999), "unknown(9999)");
        assert_eq!(session_state_label(9999), "unknown(9999)");
        assert_eq!(family_label(9999), "unknown(9999)");
        assert_eq!(
            session_state_label(proto::SessionState::Established as i32),
            "established"
        );
        assert_eq!(
            family_label(proto::AddressFamily::Ipv4Unicast as i32),
            "ipv4_unicast"
        );
    }

    #[test]
    fn families_map_onto_the_v1_unicast_scope() {
        assert_eq!(
            Family::Ipv4Unicast.as_proto(),
            proto::AddressFamily::Ipv4Unicast as i32
        );
        assert_eq!(
            Family::default().as_proto(),
            proto::AddressFamily::Unspecified as i32
        );
    }

    #[test]
    fn printed_host_config_carries_a_placeholder_not_a_token() {
        let rendered = print_config(
            "/usr/local/bin/rustbgpd-mcp",
            "http://rr1.example.net:50051",
            true,
        );
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert_eq!(
            parsed["mcpServers"]["rustbgpd"]["command"],
            "/usr/local/bin/rustbgpd-mcp"
        );
        assert_eq!(
            parsed["mcpServers"]["rustbgpd"]["args"],
            serde_json::json!([
                "--grpc-addr",
                "http://rr1.example.net:50051",
                "--grpc-token-file",
                "/path/to/rustbgpd-observer.token"
            ])
        );

        let without = print_config(
            "/usr/local/bin/rustbgpd-mcp",
            "http://127.0.0.1:50051",
            false,
        );
        assert!(!without.contains("token"), "{without}");
    }

    #[test]
    fn a_deferred_selection_says_the_installed_best_may_be_stale() {
        let deferred = selection_note(true, true);
        assert!(deferred.contains("DEFERRED"), "{deferred}");
        assert!(
            deferred.contains("may be stale") && deferred.contains("Do not report `best`"),
            "a bare boolean is skimmable; the note must say what not to conclude: {deferred}"
        );

        let settled = selection_note(false, true);
        assert!(settled.contains("reflects current selection"), "{settled}");
        assert!(!settled.contains("DEFERRED"), "{settled}");
    }

    #[test]
    fn an_absent_retained_source_is_not_an_import_rejection() {
        let absent = received_note("192.0.2.1", false);
        assert!(
            absent.contains("NOT an import-rejection explanation")
                && absent.contains("NOT proof that the peer never sent"),
            "absence must not read as evidence: {absent}"
        );

        let present = received_note("192.0.2.1", true);
        assert!(present.contains("retained accepted state"), "{present}");
        assert!(!present.contains("NOT proof"), "{present}");

        let unrequested = received_note("", false);
        assert!(
            unrequested.contains("no accepted-source lookup was requested"),
            "an unrequested lookup must not read as an absent one: {unrequested}"
        );
    }

    #[test]
    fn evpn_keys_map_onto_the_exact_selector_forms() {
        use proto::evpn_route_selector::Route;

        // Omitting `ip` selects the MAC-only key, not every host IP.
        let mac_only = EvpnKey::MacIp {
            ethernet_tag: 0,
            mac: "aa:bb:cc:dd:ee:01".into(),
            ip: None,
        }
        .into_selector("65001:100".into());
        assert_eq!(mac_only.rd, "65001:100");
        match mac_only.route {
            Some(Route::MacIp(selector)) => assert!(selector.ip.is_empty()),
            other => panic!("expected a MAC/IP selector, got {other:?}"),
        }

        // MAX_ET identifies the per-ES form and is not a caller parameter.
        match (EvpnKey::EadPerEs { esi: "es-1".into() })
            .into_selector("65001:100".into())
            .route
        {
            Some(Route::EadPerEs(selector)) => assert_eq!(selector.ethernet_tag, u32::MAX),
            other => panic!("expected a per-ES A-D selector, got {other:?}"),
        }

        match (EvpnKey::EadPerEvi {
            esi: "es-1".into(),
            ethernet_tag: 7,
        })
        .into_selector("65001:100".into())
        .route
        {
            Some(Route::EadPerEvi(selector)) => assert_eq!(selector.ethernet_tag, 7),
            other => panic!("expected a per-EVI A-D selector, got {other:?}"),
        }
    }

    #[test]
    fn the_gate_ladder_is_numbered_and_names_its_stop() {
        let gates = gate_ladder(&[
            proto::ExportGateStep {
                gate: "split_horizon".into(),
                code: "split_horizon".into(),
                verdict: proto::ExportGateVerdict::Pass as i32,
                detail: String::new(),
            },
            proto::ExportGateStep {
                gate: "export_policy".into(),
                code: "policy_denied".into(),
                verdict: proto::ExportGateVerdict::Stop as i32,
                detail: String::new(),
            },
        ]);
        assert_eq!(gates.iter().map(|g| g.step).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(stopped_at_gate(&gates).as_deref(), Some("export_policy"));
        assert_eq!(stopped_at_gate(&gates[..1]), None);
    }

    #[tokio::test]
    async fn every_registered_tool_declares_a_grpc_method() {
        let server = RustbgpdMcp::new(InterceptedService::new(
            Endpoint::from_static("http://127.0.0.1:1").connect_lazy(),
            BearerInterceptor::new(None),
        ));
        let mut registered: Vec<String> = server
            .tool_router
            .list_all()
            .iter()
            .map(|tool| tool.name.to_string())
            .collect();
        registered.sort();

        let mut declared: Vec<String> = TOOL_METHOD_PATHS
            .iter()
            .map(|(name, _)| (*name).to_string())
            .collect();
        declared.sort();

        assert_eq!(
            registered, declared,
            "TOOL_METHOD_PATHS must name exactly the tools the router registers — \
             an unlisted tool would escape the inventory contract test"
        );
    }
}
