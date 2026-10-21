//! gRPC injection service — unicast, `FlowSpec`, and EVPN route add/delete RPCs.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::actor_read::rib_manager_read;
use crate::audit::{GrpcAuditHandle, GrpcRequestSummary, safe_summary_value, set_request_summary};
use crate::proto;
use crate::route_distinguisher::parse_rd;
use crate::server::{AccessMode, read_only_rejection};
use rustbgpd_rib::AttrSet;
use rustbgpd_rib::injection_lease::{
    InjectedKey, InjectedKeyCursor, InjectionLeases, LeaseConflict, LeaseGeneration, LeasedKeyRow,
    LeasedKeysPage, LeasedKeysResume, validate_lease, validate_owner,
};
use rustbgpd_rib::manager::ROUTE_QUERY_MAX_PAGE_SIZE;
use rustbgpd_rib::update::{
    PeerRouteExport, RouteExportDisposition, RouteExportPageError, RouteExportVersion,
};
use rustbgpd_rib::{
    EvpnRibRoute, FlowSpecRoute, InjectOutcome, ReplayComplete, RibCommandError, RibUpdate, Route,
    RouteOrigin,
};
use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, BitmaskMatch, EthernetSegmentIdentifier, EthernetTagId, EvpnImet,
    EvpnIpPrefixRoute, EvpnIpPrefixValue, EvpnMacIp, EvpnRoute, EvpnRouteKey, ExtendedCommunity,
    FlowSpecComponent, FlowSpecPrefix, FlowSpecRule, Ipv4Prefix, Ipv6Prefix, Ipv6PrefixOffset,
    LargeCommunity, MacAddress, MplsLabel, NumericMatch, Origin, PathAttribute, Prefix,
    RouteDistinguisher,
};

/// gRPC service for injecting and withdrawing locally-originated routes.
pub struct InjectionService {
    access_mode: AccessMode,
    rib_tx: mpsc::Sender<RibUpdate>,
    leases: Arc<InjectionLeases>,
}

impl InjectionService {
    /// Create an injection service backed by the given RIB channel and the
    /// daemon-wide lease table that RIB manager owns
    /// ([`rustbgpd_rib::RibManager::injection_leases`], ADR-0141). Requiring
    /// the table here means a service that accepts leased adds can always
    /// renew and list them.
    pub fn new(
        rib_tx: mpsc::Sender<RibUpdate>,
        access_mode: AccessMode,
        leases: Arc<InjectionLeases>,
    ) -> Self {
        Self {
            access_mode,
            rib_tx,
            leases,
        }
    }
}

/// Validate a request's lease and return its owner and duration.
fn parse_lease(lease: Option<proto::InjectionLease>) -> Result<(String, u32), Status> {
    let lease = lease.ok_or_else(|| Status::invalid_argument("lease is required"))?;
    validate_lease(&lease.owner, lease.lease_seconds).map_err(Status::invalid_argument)?;
    Ok((lease.owner, lease.lease_seconds))
}

/// Validate a delete's expected owner; `""` means unowned.
fn parse_delete_owner(owner: &str) -> Result<(), Status> {
    if owner.is_empty() {
        return Ok(());
    }
    validate_owner(owner).map_err(Status::invalid_argument)
}

fn generation_to_proto(generation: LeaseGeneration) -> proto::LeaseGeneration {
    proto::LeaseGeneration {
        incarnation: generation.incarnation,
        sequence: generation.sequence,
    }
}

/// Keys per `ListLeasedKeys` page when the request leaves it 0.
const DEFAULT_LEASED_KEYS_PAGE_SIZE: usize = 100;

/// The page token resuming a walk after `cursor`, bound to the walk's
/// daemon incarnation and owner generation:
/// `t1:<incarnation>:<sequence, or w<watermark> without a live lease>:<key>`,
/// where the key is
/// `u:<addr>/<len>:<path_id>` or `f:<afi>:<hex NLRI>`. Clients treat it as
/// opaque.
fn leased_keys_token(owner: &str, page: &LeasedKeysPage, cursor: &InjectedKeyCursor) -> String {
    let sequence = page.generation.map_or_else(
        || format!("w{}", page.watermark),
        |generation| generation.sequence.to_string(),
    );
    // Owners are `[A-Za-z0-9._-]`, so the owner field holds no separator.
    let mut token = format!("t1:{owner}:{}:{sequence}:", page.incarnation);
    match cursor {
        InjectedKeyCursor::Unicast(prefix, path_id) => {
            let _ = write!(
                token,
                "u:{}/{}:{path_id}",
                prefix.addr_string(),
                prefix.prefix_len()
            );
        }
        InjectedKeyCursor::FlowSpec(afi, nlri) => {
            let _ = write!(token, "f:{afi}:");
            for byte in nlri {
                let _ = write!(token, "{byte:02x}");
            }
        }
    }
    token
}

fn parse_leased_keys_token(token: &str, owner: &str) -> Result<LeasedKeysResume, Status> {
    let invalid = || Status::invalid_argument("invalid page_token");
    let rest = token.strip_prefix("t1:").ok_or_else(invalid)?;
    let (token_owner, rest) = rest.split_once(':').ok_or_else(invalid)?;
    // Two owners without a live lease share the same binding, so a token is
    // only valid for the owner whose walk produced it.
    if token_owner != owner {
        return Err(Status::invalid_argument(
            "page_token belongs to a different owner",
        ));
    }
    let (incarnation, rest) = rest.split_once(':').ok_or_else(invalid)?;
    let (sequence, key) = rest.split_once(':').ok_or_else(invalid)?;
    let incarnation: u64 = incarnation.parse().map_err(|_| invalid())?;
    let (generation, watermark) = match sequence.strip_prefix('w') {
        Some(watermark) => (None, watermark.parse().map_err(|_| invalid())?),
        None => (
            Some(LeaseGeneration {
                incarnation,
                sequence: sequence.parse().map_err(|_| invalid())?,
            }),
            0,
        ),
    };
    Ok(LeasedKeysResume {
        incarnation,
        generation,
        watermark,
        after: parse_leased_key_cursor(key)?,
    })
}

fn parse_leased_key_cursor(token: &str) -> Result<InjectedKeyCursor, Status> {
    let invalid = || Status::invalid_argument("invalid page_token");
    if let Some(rest) = token.strip_prefix("u:") {
        let (prefix, path_id) = rest.rsplit_once(':').ok_or_else(invalid)?;
        let (addr, len) = prefix.rsplit_once('/').ok_or_else(invalid)?;
        let len: u32 = len.parse().map_err(|_| invalid())?;
        let prefix = parse_route_key_prefix(addr, len).map_err(|_| invalid())?;
        let path_id = path_id.parse().map_err(|_| invalid())?;
        return Ok(InjectedKeyCursor::Unicast(prefix, path_id));
    }
    let rest = token.strip_prefix("f:").ok_or_else(invalid)?;
    let (afi, hex) = rest.split_once(':').ok_or_else(invalid)?;
    // A listing's cursor is one rule: at most 4,095 bytes plus a 2-byte
    // length prefix. Refuse anything longer before decoding it.
    if hex.len() % 2 != 0 || hex.len() > 2 * 4097 || !hex.is_ascii() {
        return Err(invalid());
    }
    let nlri = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| invalid())?;
    // Only a cursor a listing could have produced: a FlowSpec AFI and exactly
    // one complete rule. Anything else would silently skip or repeat keys.
    let afi = match afi.parse::<u16>().map_err(|_| invalid())? {
        1 => Afi::Ipv4,
        2 => Afi::Ipv6,
        _ => return Err(invalid()),
    };
    match rustbgpd_wire::flowspec::decode_flowspec_nlri(&nlri, afi) {
        Ok(rules) if rules.len() == 1 => Ok(InjectedKeyCursor::FlowSpec(afi as u16, nlri)),
        _ => Err(invalid()),
    }
}

fn leased_key_to_proto(row: &LeasedKeyRow) -> proto::LeasedKey {
    let key = match &row.key {
        InjectedKey::Unicast(prefix, path_id) => {
            proto::leased_key::Key::Path(proto::LeasedPathKey {
                prefix: prefix.addr_string(),
                prefix_length: u32::from(prefix.prefix_len()),
                path_id: *path_id,
            })
        }
        InjectedKey::FlowSpec(key) => proto::leased_key::Key::FlowSpec(proto::LeasedFlowSpecKey {
            afi_safi: if key.afi == Afi::Ipv6 {
                proto::AddressFamily::Ipv6Flowspec
            } else {
                proto::AddressFamily::Ipv4Flowspec
            } as i32,
            components: crate::rib_service::flowspec_components_to_proto(&key.rule),
        }),
    };
    proto::LeasedKey {
        key: Some(key),
        generation: Some(generation_to_proto(row.generation)),
        lease_remaining_ms: millis(row.remaining),
    }
}

/// Lease time left in whole milliseconds, rounded up: 0 only once the
/// deadline has passed, when a renewal is refused, never for a sub-millisecond
/// remainder that can still renew.
pub(crate) fn millis(duration: std::time::Duration) -> u32 {
    u32::try_from(duration.as_nanos().div_ceil(1_000_000)).unwrap_or(u32::MAX)
}

/// Audit summary of a completed delete, naming the owner and generation the
/// removed entry held rather than the requested owner, so an override names
/// the owner it bypassed (ADR-0141 §8). A nonempty requested owner that
/// differs is kept as `requested_owner`. An unowned entry deleted without an owner or
/// override leaves the summary unset.
fn finish_delete_summary(
    audit: Option<&GrpcAuditHandle>,
    requested_owner: &str,
    override_owner: bool,
    removal: &rustbgpd_rib::InjectedRemoval,
) {
    let Some(audit) = audit else { return };
    let (owner, generation) = removal
        .tag
        .as_ref()
        .map_or(("", None), |tag| (&*tag.owner, Some(tag.generation)));
    if owner.is_empty() && requested_owner.is_empty() && !override_owner {
        return;
    }
    let mut summary = lease_summary(owner, generation, override_owner)
        .as_str()
        .to_string();
    if !requested_owner.is_empty() && requested_owner != owner {
        let _ = write!(
            summary,
            " requested_owner={}",
            safe_summary_value(requested_owner)
        );
    }
    audit.set_summary(GrpcRequestSummary::new(summary));
}

fn lease_summary(
    owner: &str,
    generation: Option<LeaseGeneration>,
    override_owner: bool,
) -> GrpcRequestSummary {
    let mut summary = format!("owner={}", safe_summary_value(owner));
    if let Some(generation) = generation {
        let _ = write!(
            summary,
            " generation={}:{}",
            generation.incarnation, generation.sequence
        );
    }
    if override_owner {
        summary.push_str(" override_owner=true");
    }
    GrpcRequestSummary::new(summary)
}

/// Sentinel peer address for locally-injected routes.
pub(crate) const LOCAL_PEER: std::net::IpAddr = std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Parse a prefix address + length + next-hop from a gRPC request.
///
/// An unspecified next hop of either family means next-hop self; it is
/// stored as the prefix family's unspecified address, which export resolves
/// per session.
/// The prefix of a local unicast route key, as `DeletePath` and
/// `ListPathExportDispositions` name it.
fn parse_route_key_prefix(prefix: &str, prefix_length: u32) -> Result<Prefix, Status> {
    let addr: IpAddr = prefix
        .parse()
        .map_err(|e| Status::invalid_argument(format!("invalid prefix address: {e}")))?;
    match addr {
        IpAddr::V4(v4) => {
            let len = u8::try_from(prefix_length)
                .ok()
                .filter(|&l| l <= 32)
                .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=32"))?;
            Ok(Prefix::V4(Ipv4Prefix::new(v4, len)))
        }
        IpAddr::V6(v6) => {
            let len = u8::try_from(prefix_length)
                .ok()
                .filter(|&l| l <= 128)
                .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=128"))?;
            Ok(Prefix::V6(Ipv6Prefix::new(v6, len)))
        }
    }
}

/// Peers per `ListPathExportDispositions` page when the request leaves it 0.
const DEFAULT_EXPORT_PAGE_SIZE: usize = 100;

/// Longest `ListPathExportDispositions` page token this process issues,
/// with room to spare.
const EXPORT_PAGE_TOKEN_MAX_LEN: usize = 256;

/// The opaque continuation of a `ListPathExportDispositions` walk: the
/// route key, the walk version the RIB reported and the last listed peer,
/// signed so that only this process's tokens resume.
fn encode_export_page_token(
    prefix: Prefix,
    path_id: u32,
    peer: IpAddr,
    version: RouteExportVersion,
) -> String {
    crate::rib_service::sign_page_token(&format!(
        "pe1|{:016x}|{:016x}|{prefix}|{path_id}|{peer}",
        version.roster, version.route
    ))
}

/// Where a `ListPathExportDispositions` page resumes. A token this process
/// did not issue, or one issued for another route key, is
/// `INVALID_ARGUMENT`.
fn decode_export_page_token(
    token: &str,
    prefix: Prefix,
    path_id: u32,
) -> Result<(IpAddr, RouteExportVersion), Status> {
    let invalid = || Status::invalid_argument("invalid page_token");
    if token.len() > EXPORT_PAGE_TOKEN_MAX_LEN {
        return Err(invalid());
    }
    let payload = crate::rib_service::verified_page_token_payload(token).ok_or_else(invalid)?;
    let parts: Vec<_> = payload.split('|').collect();
    let ["pe1", roster, route, key_prefix, key_path_id, peer] = parts.as_slice() else {
        return Err(invalid());
    };
    if *key_prefix != prefix.to_string() || *key_path_id != path_id.to_string() {
        return Err(Status::invalid_argument(
            "page_token belongs to another route key",
        ));
    }
    let version = RouteExportVersion {
        roster: u64::from_str_radix(roster, 16).map_err(|_| invalid())?,
        route: u64::from_str_radix(route, 16).map_err(|_| invalid())?,
    };
    Ok((peer.parse().map_err(|_| invalid())?, version))
}

fn export_disposition_to_proto(row: PeerRouteExport) -> proto::PathExportDispositionEntry {
    let disposition = match row.disposition {
        RouteExportDisposition::Committed => proto::PathExportDisposition::Committed,
        RouteExportDisposition::Withheld => proto::PathExportDisposition::Withheld,
        RouteExportDisposition::Pending => proto::PathExportDisposition::Pending,
    };
    proto::PathExportDispositionEntry {
        peer_address: row.peer.to_string(),
        peer_interface: row
            .peer_interface
            .as_deref()
            .unwrap_or_default()
            .to_string(),
        disposition: disposition as i32,
        reason: row.reason,
        explain_code: row.explain_code.to_string(),
        detail: row.detail,
        advertised_path_id: row.advertised_path_id,
        deny_validation: row.deny_validation,
    }
}

fn parse_prefix_and_nexthop(
    prefix_str: &str,
    prefix_length: u32,
    next_hop_str: &str,
) -> Result<(Prefix, IpAddr), Status> {
    let addr: IpAddr = prefix_str
        .parse()
        .map_err(|e| Status::invalid_argument(format!("invalid prefix address: {e}")))?;
    let nh: IpAddr = next_hop_str
        .parse()
        .map_err(|e| Status::invalid_argument(format!("invalid next_hop: {e}")))?;
    let nh = if nh.is_unspecified() {
        match addr {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        }
    } else {
        parse_unicast_nexthop(next_hop_str)?
    };
    match addr {
        IpAddr::V4(v4) => {
            let len = u8::try_from(prefix_length)
                .ok()
                .filter(|&l| l <= 32)
                .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=32"))?;
            Ok((Prefix::V4(Ipv4Prefix::new(v4, len)), nh))
        }
        IpAddr::V6(v6) => {
            let len = u8::try_from(prefix_length)
                .ok()
                .filter(|&l| l <= 128)
                .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=128"))?;
            // IPv6 unicast MP_REACH carries a 16- or 32-octet next hop
            // (RFC 2545); RFC 8950 covers only IPv4 NLRI over an IPv6 next hop.
            if nh.is_ipv4() {
                return Err(Status::invalid_argument(
                    "an IPv6 prefix requires an IPv6 next_hop",
                ));
            }
            Ok((Prefix::V6(Ipv6Prefix::new(v6, len)), nh))
        }
    }
}

/// Parse the Type 5 prefix fields from the injection API.
fn parse_evpn_ip_prefix(prefix_str: &str, prefix_length: u32) -> Result<EvpnIpPrefixValue, Status> {
    if prefix_str.is_empty() {
        return Err(Status::invalid_argument("prefix is required for Type 5"));
    }
    let addr: IpAddr = prefix_str
        .parse()
        .map_err(|e| Status::invalid_argument(format!("invalid Type 5 prefix address: {e}")))?;
    match addr {
        IpAddr::V4(v4) => {
            let len = u8::try_from(prefix_length)
                .ok()
                .filter(|&l| l <= 32)
                .ok_or_else(|| {
                    Status::invalid_argument("prefix_length must be 0..=32 for Type 5 IPv4")
                })?;
            Ok(EvpnIpPrefixValue::V4(Ipv4Prefix::new(v4, len)))
        }
        IpAddr::V6(v6) => {
            let len = u8::try_from(prefix_length)
                .ok()
                .filter(|&l| l <= 128)
                .ok_or_else(|| {
                    Status::invalid_argument("prefix_length must be 0..=128 for Type 5 IPv6")
                })?;
            Ok(EvpnIpPrefixValue::V6(Ipv6Prefix::new(v6, len)))
        }
    }
}

const fn evpn_prefix_family_matches(prefix: EvpnIpPrefixValue, ip: IpAddr) -> bool {
    matches!(
        (prefix, ip),
        (EvpnIpPrefixValue::V4(_), IpAddr::V4(_)) | (EvpnIpPrefixValue::V6(_), IpAddr::V6(_))
    )
}

const fn zero_gateway_for_prefix(prefix: EvpnIpPrefixValue) -> IpAddr {
    match prefix {
        EvpnIpPrefixValue::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        EvpnIpPrefixValue::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
    }
}

fn parse_type5_gateway(
    gateway_str: &str,
    prefix: EvpnIpPrefixValue,
    next_hop: IpAddr,
) -> Result<IpAddr, Status> {
    if !evpn_prefix_family_matches(prefix, next_hop) {
        return Err(Status::invalid_argument(
            "Type 5 prefix and next_hop must use the same IP family",
        ));
    }
    if gateway_str.is_empty() {
        return Ok(zero_gateway_for_prefix(prefix));
    }
    let gateway: IpAddr = gateway_str
        .parse()
        .map_err(|e| Status::invalid_argument(format!("invalid Type 5 gateway: {e}")))?;
    if gateway.is_unspecified() {
        return Err(Status::invalid_argument(
            "gateway must not be zero; omit gateway for interface-less Type 5",
        ));
    }
    let is_broadcast = matches!(gateway, IpAddr::V4(v4) if v4.is_broadcast());
    if gateway.is_multicast() || is_broadcast {
        return Err(Status::invalid_argument(
            "Type 5 gateway must be a unicast address",
        ));
    }
    if !evpn_prefix_family_matches(prefix, gateway) {
        return Err(Status::invalid_argument(
            "Type 5 gateway and prefix must use the same IP family",
        ));
    }
    Ok(gateway)
}

/// Parse a unicast next-hop string and reject unspecified / multicast /
/// broadcast values. Shared by `AddPath` and `AddEvpnRoute` so all
/// next-hop-carrying injection surfaces apply the same guardrails.
fn parse_unicast_nexthop(s: &str) -> Result<IpAddr, Status> {
    let nh: IpAddr = s
        .parse()
        .map_err(|e| Status::invalid_argument(format!("invalid next_hop: {e}")))?;
    match nh {
        IpAddr::V4(v4) => {
            if v4.is_unspecified() {
                return Err(Status::invalid_argument("next_hop must not be 0.0.0.0"));
            }
            if v4.is_multicast() {
                return Err(Status::invalid_argument("next_hop must not be multicast"));
            }
            if v4.is_broadcast() {
                return Err(Status::invalid_argument(
                    "next_hop must not be 255.255.255.255",
                ));
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_unspecified() {
                return Err(Status::invalid_argument("next_hop must not be ::"));
            }
            if v6.is_multicast() {
                return Err(Status::invalid_argument("next_hop must not be multicast"));
            }
        }
    }
    Ok(nh)
}

/// `ErrorInfo.domain` of every lease conflict.
const LEASE_ERROR_DOMAIN: &str = "rustbgpd";

/// `google.rpc.Status`, the payload of the `grpc-status-details-bin`
/// trailer. Declared here so the existing `prost` encodes it.
#[derive(Clone, PartialEq, prost::Message)]
struct RpcStatus {
    #[prost(int32, tag = "1")]
    code: i32,
    #[prost(string, tag = "2")]
    message: String,
    #[prost(message, repeated, tag = "3")]
    details: Vec<prost_types::Any>,
}

/// `google.rpc.ErrorInfo` without `metadata`, which a lease conflict leaves
/// empty.
#[derive(Clone, PartialEq, prost::Message)]
struct ErrorInfo {
    #[prost(string, tag = "1")]
    reason: String,
    #[prost(string, tag = "2")]
    domain: String,
}

/// `FAILED_PRECONDITION` for an ADR-0141 ownership or generation refusal,
/// with a `google.rpc.ErrorInfo` detail whose `reason` names the conflict.
/// The reason is contract; the message is not.
fn lease_conflict_status(conflict: LeaseConflict, message: String) -> Status {
    status_with_reason(tonic::Code::FailedPrecondition, conflict.reason(), message)
}

/// `ErrorInfo.reason` of a `ListLeasedKeys` page whose walk crossed a daemon
/// restart or an owner generation change.
const WALK_INVALIDATED: &str = "WALK_INVALIDATED";

/// `code` with a `google.rpc.ErrorInfo` detail naming `reason` in the
/// `rustbgpd` domain.
fn status_with_reason(code: tonic::Code, reason: &str, message: String) -> Status {
    use prost::Message as _;
    let info = ErrorInfo {
        reason: reason.to_string(),
        domain: LEASE_ERROR_DOMAIN.to_string(),
    };
    let details = RpcStatus {
        code: code as i32,
        message: message.clone(),
        details: vec![prost_types::Any {
            type_url: "type.googleapis.com/google.rpc.ErrorInfo".to_string(),
            value: info.encode_to_vec(),
        }],
    };
    Status::with_details(code, message, details.encode_to_vec().into())
}

/// Map a RIB-side command error into the right gRPC status code.
fn map_rib_command_error(operation: &str, error: RibCommandError) -> Status {
    match error {
        RibCommandError::NotFound(message) => Status::not_found(message),
        RibCommandError::FailedPrecondition(conflict, message) => {
            lease_conflict_status(conflict, message)
        }
        RibCommandError::ResourceExhausted(message) => Status::resource_exhausted(message),
        RibCommandError::Internal(message) => Status::internal(format!("{operation}: {message}")),
    }
}

/// Parse a Large Community string in `"global:local1:local2"` format.
fn parse_large_community(s: &str) -> Result<LargeCommunity, String> {
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err("expected format global:local1:local2".to_string());
    }
    let global_admin: u32 = parts[0]
        .parse()
        .map_err(|_| format!("invalid global_admin {:?}", parts[0]))?;
    let local_data1: u32 = parts[1]
        .parse()
        .map_err(|_| format!("invalid local_data1 {:?}", parts[1]))?;
    let local_data2: u32 = parts[2]
        .parse()
        .map_err(|_| format!("invalid local_data2 {:?}", parts[2]))?;
    Ok(LargeCommunity::new(global_admin, local_data1, local_data2))
}

/// Build the local route an `AddPath` request describes.
fn build_injected_route(req: proto::AddPathRequest) -> Result<Route, Status> {
    let (prefix, next_hop_ip) =
        parse_prefix_and_nexthop(&req.prefix, req.prefix_length, &req.next_hop)?;

    let origin = match req.origin {
        0 => Origin::Igp,
        1 => Origin::Egp,
        2 => Origin::Incomplete,
        other => {
            return Err(Status::invalid_argument(format!(
                "origin must be 0 (igp), 1 (egp), or 2 (incomplete); got {other}"
            )));
        }
    };

    let mut attributes = vec![PathAttribute::Origin(origin)];

    // NEXT_HOP attribute only for an IPv4 next hop, which parsing allows
    // only on an IPv4 prefix; any IPv6 next hop uses MP_REACH_NLRI.
    if let IpAddr::V4(nh) = next_hop_ip {
        attributes.push(PathAttribute::NextHop(nh));
    }

    if req.as_path.is_empty() {
        attributes.push(PathAttribute::AsPath(AsPath { segments: vec![] }));
    } else {
        attributes.push(PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(req.as_path)],
        }));
    }

    if let Some(local_pref) = req.local_pref {
        attributes.push(PathAttribute::LocalPref(local_pref));
    }
    if let Some(med) = req.med {
        attributes.push(PathAttribute::Med(med));
    }
    if !req.communities.is_empty() {
        attributes.push(PathAttribute::Communities(req.communities));
    }
    if !req.extended_communities.is_empty() {
        attributes.push(PathAttribute::ExtendedCommunities(
            req.extended_communities
                .iter()
                .map(|&v| ExtendedCommunity::new(v))
                .collect(),
        ));
    }
    if !req.large_communities.is_empty() {
        let mut lcs = Vec::with_capacity(req.large_communities.len());
        for s in &req.large_communities {
            let lc = parse_large_community(s).map_err(|e| {
                Status::invalid_argument(format!("invalid large_community {s:?}: {e}"))
            })?;
            lcs.push(lc);
        }
        attributes.push(PathAttribute::LargeCommunities(lcs));
    }

    Ok(Route {
        prefix,
        next_hop: next_hop_ip,
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: LOCAL_PEER,
        attributes: AttrSet::new(attributes),
        received_at: rustbgpd_rib::route::ReceivedAt::now(),
        origin_type: RouteOrigin::Local,
        peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: req.path_id,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
    })
}

/// Build the local rule an `AddFlowSpec` request describes.
fn build_injected_flowspec(req: proto::AddFlowSpecRequest) -> Result<FlowSpecRoute, Status> {
    let afi = parse_flowspec_afi(req.afi_safi)?;

    let components = parse_flowspec_components(&req.components, afi)?;
    let rule = FlowSpecRule { components };
    rule.validate()
        .map_err(|e| Status::invalid_argument(format!("invalid FlowSpec rule: {e}")))?;
    validate_flowspec_rule_encoded_len(&rule, afi)?;

    let mut attributes: Vec<PathAttribute> = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
    ];

    // Build extended communities from FlowSpec actions
    let mut ecs: Vec<ExtendedCommunity> = req
        .extended_communities
        .iter()
        .map(|&v| ExtendedCommunity::new(v))
        .collect();
    for action in &req.actions {
        if let Some(ec) = flowspec_action_to_ec(action)? {
            ecs.push(ec);
        }
    }
    if !ecs.is_empty() {
        attributes.push(PathAttribute::ExtendedCommunities(ecs));
    }
    if !req.communities.is_empty() {
        attributes.push(PathAttribute::Communities(req.communities));
    }

    Ok(FlowSpecRoute {
        rule,
        afi,
        peer: LOCAL_PEER,
        attributes,
        received_at: std::time::Instant::now(),
        origin_type: RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    })
}

#[tonic::async_trait]
impl proto::injection_service_server::InjectionService for InjectionService {
    async fn add_path(
        &self,
        request: Request<proto::AddPathRequest>,
    ) -> Result<Response<proto::AddPathResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let route = build_injected_route(request.into_inner())?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::InjectRoute {
                route,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::unavailable("RIB manager unavailable"))?;

        let outcome = match reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|error| map_rib_command_error("inject failed", error))?
        {
            InjectOutcome::Created => proto::PathInjectOutcome::Created,
            InjectOutcome::Replaced => proto::PathInjectOutcome::Replaced,
            InjectOutcome::Unchanged => proto::PathInjectOutcome::Unchanged,
        };

        Ok(Response::new(proto::AddPathResponse {
            outcome: outcome as i32,
        }))
    }

    async fn delete_path(
        &self,
        request: Request<proto::DeletePathRequest>,
    ) -> Result<Response<proto::DeletePathResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.get_ref();
        parse_delete_owner(&req.owner)?;
        if !req.owner.is_empty() || req.override_owner {
            set_request_summary(
                &request,
                lease_summary(&req.owner, None, req.override_owner),
            );
        }
        let audit = request.extensions().get::<GrpcAuditHandle>().cloned();
        let req = request.into_inner();
        let (requested_owner, override_owner) = (req.owner.clone(), req.override_owner);

        let prefix = parse_route_key_prefix(&req.prefix, req.prefix_length)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::WithdrawInjected {
                prefix,
                path_id: req.path_id,
                allow_missing: req.allow_missing,
                owner: req.owner,
                override_owner: req.override_owner,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::unavailable("RIB manager unavailable"))?;

        let removal = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|error| map_rib_command_error("withdraw failed", error))?;
        finish_delete_summary(audit.as_ref(), &requested_owner, override_owner, &removal);
        let outcome = if removal.removed {
            proto::PathDeleteOutcome::Deleted
        } else {
            proto::PathDeleteOutcome::NotPresent
        };

        Ok(Response::new(proto::DeletePathResponse {
            outcome: outcome as i32,
        }))
    }

    async fn add_flow_spec(
        &self,
        request: Request<proto::AddFlowSpecRequest>,
    ) -> Result<Response<proto::AddFlowSpecResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let route = build_injected_flowspec(request.into_inner())?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::InjectFlowSpec {
                route,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::unavailable("RIB manager unavailable"))?;

        let outcome = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|error| map_rib_command_error("FlowSpec inject failed", error))?;
        let outcome = match outcome {
            InjectOutcome::Created => proto::FlowSpecInjectOutcome::Created,
            InjectOutcome::Replaced => proto::FlowSpecInjectOutcome::Replaced,
            InjectOutcome::Unchanged => proto::FlowSpecInjectOutcome::Unchanged,
        };

        Ok(Response::new(proto::AddFlowSpecResponse {
            outcome: outcome as i32,
        }))
    }

    async fn delete_flow_spec(
        &self,
        request: Request<proto::DeleteFlowSpecRequest>,
    ) -> Result<Response<proto::DeleteFlowSpecResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.get_ref();
        parse_delete_owner(&req.owner)?;
        if !req.owner.is_empty() || req.override_owner {
            set_request_summary(
                &request,
                lease_summary(&req.owner, None, req.override_owner),
            );
        }
        let audit = request.extensions().get::<GrpcAuditHandle>().cloned();
        let req = request.into_inner();
        let (requested_owner, override_owner) = (req.owner.clone(), req.override_owner);
        let afi = parse_flowspec_afi(req.afi_safi)?;

        let components = parse_flowspec_components(&req.components, afi)?;
        let rule = FlowSpecRule { components };
        rule.validate()
            .map_err(|e| Status::invalid_argument(format!("invalid FlowSpec rule: {e}")))?;
        validate_flowspec_rule_encoded_len(&rule, afi)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::WithdrawFlowSpec {
                key: rustbgpd_rib::FlowSpecKey { afi, rule },
                allow_missing: req.allow_missing,
                owner: req.owner,
                override_owner: req.override_owner,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::unavailable("RIB manager unavailable"))?;

        let removal = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|error| map_rib_command_error("FlowSpec withdraw failed", error))?;
        finish_delete_summary(audit.as_ref(), &requested_owner, override_owner, &removal);

        let outcome = if removal.removed {
            proto::FlowSpecDeleteOutcome::Deleted
        } else {
            proto::FlowSpecDeleteOutcome::NotPresent
        };

        Ok(Response::new(proto::DeleteFlowSpecResponse {
            outcome: outcome as i32,
        }))
    }

    async fn add_leased_path(
        &self,
        request: Request<proto::AddLeasedPathRequest>,
    ) -> Result<Response<proto::AddLeasedPathResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let (owner, lease_seconds) = parse_lease(request.get_ref().lease.clone())?;
        set_request_summary(&request, lease_summary(&owner, None, false));
        let audit = request.extensions().get::<GrpcAuditHandle>().cloned();
        let path = request
            .into_inner()
            .path
            .ok_or_else(|| Status::invalid_argument("path is required"))?;
        let route = build_injected_route(path)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::InjectLeasedRoute {
                route,
                owner: owner.clone(),
                lease_seconds,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::unavailable("RIB manager unavailable"))?;
        let (outcome, generation) = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|error| map_rib_command_error("leased inject failed", error))?;
        if let Some(audit) = audit {
            audit.set_summary(lease_summary(&owner, Some(generation), false));
        }
        let outcome = match outcome {
            InjectOutcome::Created => proto::PathInjectOutcome::Created,
            InjectOutcome::Replaced => proto::PathInjectOutcome::Replaced,
            InjectOutcome::Unchanged => proto::PathInjectOutcome::Unchanged,
        };
        Ok(Response::new(proto::AddLeasedPathResponse {
            result: Some(proto::AddPathResponse {
                outcome: outcome as i32,
            }),
            generation: Some(generation_to_proto(generation)),
        }))
    }

    async fn add_leased_flow_spec(
        &self,
        request: Request<proto::AddLeasedFlowSpecRequest>,
    ) -> Result<Response<proto::AddLeasedFlowSpecResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let (owner, lease_seconds) = parse_lease(request.get_ref().lease.clone())?;
        set_request_summary(&request, lease_summary(&owner, None, false));
        let audit = request.extensions().get::<GrpcAuditHandle>().cloned();
        let rule = request
            .into_inner()
            .rule
            .ok_or_else(|| Status::invalid_argument("rule is required"))?;
        let route = build_injected_flowspec(rule)?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::InjectLeasedFlowSpec {
                route,
                owner: owner.clone(),
                lease_seconds,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::unavailable("RIB manager unavailable"))?;
        let (outcome, generation) = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|error| map_rib_command_error("leased FlowSpec inject failed", error))?;
        if let Some(audit) = audit {
            audit.set_summary(lease_summary(&owner, Some(generation), false));
        }
        let outcome = match outcome {
            InjectOutcome::Created => proto::FlowSpecInjectOutcome::Created,
            InjectOutcome::Replaced => proto::FlowSpecInjectOutcome::Replaced,
            InjectOutcome::Unchanged => proto::FlowSpecInjectOutcome::Unchanged,
        };
        Ok(Response::new(proto::AddLeasedFlowSpecResponse {
            result: Some(proto::AddFlowSpecResponse {
                outcome: outcome as i32,
            }),
            generation: Some(generation_to_proto(generation)),
        }))
    }

    async fn renew_lease(
        &self,
        request: Request<proto::RenewLeaseRequest>,
    ) -> Result<Response<proto::RenewLeaseResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.get_ref();
        validate_lease(&req.owner, req.lease_seconds).map_err(Status::invalid_argument)?;
        let generation = req
            .generation
            .as_ref()
            .map(|generation| LeaseGeneration {
                incarnation: generation.incarnation,
                sequence: generation.sequence,
            })
            .ok_or_else(|| Status::invalid_argument("generation is required"))?;
        set_request_summary(&request, lease_summary(&req.owner, Some(generation), false));
        let remaining = self
            .leases
            .renew(&req.owner, generation, req.lease_seconds)
            .ok_or_else(|| {
                tracing::debug!(owner = %req.owner, "injection lease renewal rejected");
                lease_conflict_status(
                    LeaseConflict::GenerationNotLive,
                    "lease generation is not live; re-add the owner's desired state".to_string(),
                )
            })?;
        Ok(Response::new(proto::RenewLeaseResponse {
            generation: Some(generation_to_proto(generation)),
            lease_remaining_ms: millis(remaining),
        }))
    }

    async fn list_path_export_dispositions(
        &self,
        request: Request<proto::ListPathExportDispositionsRequest>,
    ) -> Result<Response<proto::ListPathExportDispositionsResponse>, Status> {
        let req = request.into_inner();
        let prefix = parse_route_key_prefix(&req.prefix, req.prefix_length)?;
        let after = if req.page_token.is_empty() {
            None
        } else {
            Some(decode_export_page_token(
                &req.page_token,
                prefix,
                req.path_id,
            )?)
        };
        let page_size = match req.page_size {
            0 => DEFAULT_EXPORT_PAGE_SIZE,
            size => usize::try_from(size)
                .unwrap_or(usize::MAX)
                .min(ROUTE_QUERY_MAX_PAGE_SIZE),
        };
        let page = rib_manager_read(&self.rib_tx, |reply| RibUpdate::QueryLocalRouteExport {
            prefix,
            path_id: req.path_id,
            after,
            page_size,
            reply,
        })
        .await?
        .map_err(|error| match error {
            RouteExportPageError::NoRoute => Status::not_found(format!(
                "no local route {}/{} with path_id {}",
                req.prefix, req.prefix_length, req.path_id
            )),
            RouteExportPageError::Invalidated => Status::aborted(
                "the local route or the Established peer set changed during pagination; \
                 restart with an empty page_token",
            ),
        })?;
        let next_page_token = match page.peers.last() {
            Some(row) if page.more => {
                encode_export_page_token(prefix, req.path_id, row.peer, page.version)
            }
            _ => String::new(),
        };
        Ok(Response::new(proto::ListPathExportDispositionsResponse {
            peers: page
                .peers
                .into_iter()
                .map(export_disposition_to_proto)
                .collect(),
            next_page_token,
        }))
    }

    async fn list_leased_keys(
        &self,
        request: Request<proto::ListLeasedKeysRequest>,
    ) -> Result<Response<proto::ListLeasedKeysResponse>, Status> {
        let req = request.into_inner();
        validate_owner(&req.owner).map_err(Status::invalid_argument)?;
        let resume = if req.page_token.is_empty() {
            None
        } else {
            Some(parse_leased_keys_token(&req.page_token, &req.owner)?)
        };
        let page_size = match req.page_size {
            0 => DEFAULT_LEASED_KEYS_PAGE_SIZE,
            size => usize::try_from(size)
                .unwrap_or(usize::MAX)
                .min(ROUTE_QUERY_MAX_PAGE_SIZE),
        };
        let page = rib_manager_read(&self.rib_tx, |reply| RibUpdate::QueryLeasedKeys {
            owner: req.owner.clone(),
            resume,
            page_size,
            reply,
        })
        .await?
        .ok_or_else(|| {
            status_with_reason(
                tonic::Code::Aborted,
                WALK_INVALIDATED,
                "the daemon restarted or the owner's lease generation changed since this \
                 listing began; restart it with an empty page_token"
                    .to_string(),
            )
        })?;
        let next_page_token = if page.more {
            page.rows
                .last()
                .map(|row| leased_keys_token(&req.owner, &page, &row.cursor))
                .unwrap_or_default()
        } else {
            String::new()
        };
        Ok(Response::new(proto::ListLeasedKeysResponse {
            keys: page.rows.iter().map(leased_key_to_proto).collect(),
            next_page_token,
            generation: page.generation.map(generation_to_proto),
        }))
    }

    async fn list_injection_leases(
        &self,
        request: Request<proto::ListInjectionLeasesRequest>,
    ) -> Result<Response<proto::ListInjectionLeasesResponse>, Status> {
        let owner = request.into_inner().owner;
        let leases = self
            .leases
            .list((!owner.is_empty()).then_some(owner.as_str()))
            .into_iter()
            .map(|row| proto::InjectionLeaseEntry {
                owner: row.owner.to_string(),
                generation: Some(generation_to_proto(row.generation)),
                lease_seconds: row.lease_seconds,
                lease_remaining_ms: millis(row.remaining),
            })
            .collect();
        Ok(Response::new(proto::ListInjectionLeasesResponse { leases }))
    }

    async fn mark_replay_complete(
        &self,
        request: Request<proto::MarkReplayCompleteRequest>,
    ) -> Result<Response<proto::MarkReplayCompleteResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.get_ref();
        validate_owner(&req.owner).map_err(Status::invalid_argument)?;
        set_request_summary(
            &request,
            GrpcRequestSummary::new(format!(
                "owner={} incarnation={}",
                safe_summary_value(&req.owner),
                req.incarnation
            )),
        );
        let req = request.into_inner();
        // The primary channel, not the query lane: the signal must follow
        // the controller's earlier injections through the RIB queue.
        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::MarkReplayComplete {
                owner: req.owner,
                incarnation: req.incarnation,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::unavailable("RIB manager unavailable"))?;
        let result = reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|error| map_rib_command_error("replay-complete signal failed", error))?;
        let (outcome, awaiting) = match result {
            ReplayComplete::Released => (proto::ReplayCompleteOutcome::Released, vec![]),
            ReplayComplete::Recorded { awaiting } => {
                (proto::ReplayCompleteOutcome::Recorded, awaiting)
            }
            ReplayComplete::NotExpected => (proto::ReplayCompleteOutcome::NotExpected, vec![]),
            ReplayComplete::NotHolding => (proto::ReplayCompleteOutcome::NotHolding, vec![]),
        };
        Ok(Response::new(proto::MarkReplayCompleteResponse {
            outcome: outcome as i32,
            awaiting,
        }))
    }

    async fn add_evpn_route(
        &self,
        request: Request<proto::AddEvpnRouteRequest>,
    ) -> Result<Response<proto::AddEvpnRouteResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();

        let rd = parse_rd(&req.rd)?;
        let next_hop = parse_unicast_nexthop(&req.next_hop)?;

        let (evpn_route, attributes) = match req.route_type {
            2 => build_type2(&req, rd)?,
            3 => build_type3(&req, rd)?,
            5 => build_type5(&req, rd, next_hop)?,
            other => {
                return Err(Status::invalid_argument(format!(
                    "route_type {other} not supported for injection (supported: 2, 3, 5)"
                )));
            }
        };

        let router_id = match next_hop {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
        };
        let rib_route = EvpnRibRoute {
            route: evpn_route,
            next_hop,
            link_local_next_hop: None,
            peer: LOCAL_PEER,
            attributes: AttrSet::new(attributes),
            received_at: std::time::Instant::now(),
            origin_type: RouteOrigin::Local,
            peer_router_id: router_id,
            is_stale: false,
            is_llgr_stale: false,
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::InjectEvpn {
                route: rib_route,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::unavailable("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|error| map_rib_command_error("EVPN inject failed", error))?;

        Ok(Response::new(proto::AddEvpnRouteResponse {}))
    }

    async fn delete_evpn_route(
        &self,
        request: Request<proto::DeleteEvpnRouteRequest>,
    ) -> Result<Response<proto::DeleteEvpnRouteResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let rd = parse_rd(&req.rd)?;

        let key = match req.route_type {
            2 => {
                reject_delete_type5_only_fields(&req, 2)?;
                let mac = parse_mac(&req.mac)?;
                EvpnRouteKey::MacIp {
                    rd,
                    ethernet_tag: EthernetTagId(req.ethernet_tag),
                    mac,
                    ip: parse_optional_ip(&req.ip)?,
                }
            }
            3 => {
                reject_delete_type5_only_fields(&req, 3)?;
                if !req.mac.is_empty() {
                    return Err(Status::invalid_argument(
                        "mac is Type 2 only; must be empty for Type 3 IMET withdrawal",
                    ));
                }
                let ip = parse_ip_required(&req.ip, "ip (originator_ip)")?;
                EvpnRouteKey::Imet {
                    rd,
                    ethernet_tag: EthernetTagId(req.ethernet_tag),
                    originator_ip: ip,
                }
            }
            5 => {
                if req.ethernet_tag != 0 {
                    return Err(Status::invalid_argument(
                        "ethernet_tag must be 0 for Type 5 IP Prefix withdrawal",
                    ));
                }
                if !req.mac.is_empty() {
                    return Err(Status::invalid_argument(
                        "mac is Type 2 only; must be empty for Type 5 IP Prefix withdrawal",
                    ));
                }
                if !req.ip.is_empty() {
                    return Err(Status::invalid_argument(
                        "ip is Type 2/3 only; must be empty for Type 5 IP Prefix withdrawal",
                    ));
                }
                let prefix = parse_evpn_ip_prefix(&req.prefix, req.prefix_length)?;
                EvpnRouteKey::IpPrefix {
                    rd,
                    ethernet_tag: EthernetTagId(req.ethernet_tag),
                    prefix,
                }
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "route_type {other} not supported for withdrawal (supported: 2, 3, 5)"
                )));
            }
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::WithdrawEvpn {
                key,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::unavailable("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|error| map_rib_command_error("EVPN withdraw failed", error))?;

        Ok(Response::new(proto::DeleteEvpnRouteResponse {}))
    }
}

/// Parse the `AddressFamily` field for `FlowSpec` requests.
fn parse_flowspec_afi(value: i32) -> Result<Afi, Status> {
    match value {
        x if x == proto::AddressFamily::Ipv4Flowspec as i32 => Ok(Afi::Ipv4),
        x if x == proto::AddressFamily::Ipv6Flowspec as i32 => Ok(Afi::Ipv6),
        _ => Err(Status::invalid_argument(
            "afi_safi must be IPV4_FLOWSPEC or IPV6_FLOWSPEC",
        )),
    }
}

/// Convert proto `FlowSpecComponent` messages into wire types.
fn parse_flowspec_components(
    components: &[proto::FlowSpecComponent],
    afi: Afi,
) -> Result<Vec<FlowSpecComponent>, Status> {
    if components.is_empty() {
        return Err(Status::invalid_argument(
            "at least one FlowSpec component is required",
        ));
    }
    let mut result = Vec::with_capacity(components.len());
    for c in components {
        if c.r#type != 1 && c.r#type != 2 && c.offset != 0 {
            return Err(Status::invalid_argument(format!(
                "offset is only valid for destination/source prefix components (type 1/2), got type {}",
                c.r#type
            )));
        }
        let comp = match c.r#type {
            1 => {
                // Destination prefix
                let prefix = parse_flowspec_prefix(&c.prefix, afi, "destination prefix", c.offset)?;
                FlowSpecComponent::DestinationPrefix(prefix)
            }
            2 => {
                // Source prefix
                let prefix = parse_flowspec_prefix(&c.prefix, afi, "source prefix", c.offset)?;
                FlowSpecComponent::SourcePrefix(prefix)
            }
            3 => FlowSpecComponent::IpProtocol(parse_numeric_value(&c.value, "ip_protocol")?),
            4 => FlowSpecComponent::Port(parse_numeric_value(&c.value, "port")?),
            5 => FlowSpecComponent::DestinationPort(parse_numeric_value(&c.value, "dst_port")?),
            6 => FlowSpecComponent::SourcePort(parse_numeric_value(&c.value, "src_port")?),
            7 => FlowSpecComponent::IcmpType(parse_numeric_value(&c.value, "icmp_type")?),
            8 => FlowSpecComponent::IcmpCode(parse_numeric_value(&c.value, "icmp_code")?),
            9 => FlowSpecComponent::TcpFlags(parse_bitmask_value(&c.value, "tcp_flags")?),
            10 => FlowSpecComponent::PacketLength(parse_numeric_value(&c.value, "packet_length")?),
            11 => FlowSpecComponent::Dscp(parse_numeric_value(&c.value, "dscp")?),
            12 => FlowSpecComponent::Fragment(parse_bitmask_value(&c.value, "fragment")?),
            13 => {
                if afi != Afi::Ipv6 {
                    return Err(Status::invalid_argument(
                        "FlowLabel (type 13) is only valid for IPv6 FlowSpec",
                    ));
                }
                FlowSpecComponent::FlowLabel(parse_numeric_value(&c.value, "flow_label")?)
            }
            other => {
                return Err(Status::invalid_argument(format!(
                    "unsupported FlowSpec component type {other}"
                )));
            }
        };
        result.push(comp);
    }
    Ok(result)
}

fn validate_flowspec_rule_encoded_len(rule: &FlowSpecRule, afi: Afi) -> Result<(), Status> {
    rule.validate_encoded_len(afi)
        .map_err(|e| Status::invalid_argument(format!("invalid FlowSpec rule: {e}")))
}

/// Parse a prefix string (e.g., "10.0.0.0/24") into a `FlowSpecPrefix`.
fn parse_flowspec_prefix(
    s: &str,
    afi: Afi,
    label: &str,
    offset: u32,
) -> Result<FlowSpecPrefix, Status> {
    let parts: Vec<&str> = s.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err(Status::invalid_argument(format!(
            "{label}: expected format \"addr/len\""
        )));
    }
    let addr: IpAddr = parts[0]
        .parse()
        .map_err(|e| Status::invalid_argument(format!("{label}: invalid address: {e}")))?;
    let len: u8 = parts[1]
        .parse()
        .map_err(|e| Status::invalid_argument(format!("{label}: invalid prefix length: {e}")))?;

    match (afi, addr) {
        (Afi::Ipv4, IpAddr::V4(v4)) => {
            if offset != 0 {
                return Err(Status::invalid_argument(format!(
                    "{label}: offset is only valid for IPv6 FlowSpec"
                )));
            }
            Ok(FlowSpecPrefix::V4(Ipv4Prefix::new(v4, len)))
        }
        (Afi::Ipv6, IpAddr::V6(v6)) => {
            let offset_u8 = u8::try_from(offset).map_err(|_| {
                Status::invalid_argument(format!("{label}: offset must be 0..=255"))
            })?;
            Ok(FlowSpecPrefix::V6(Ipv6PrefixOffset {
                prefix: Ipv6Prefix::new(v6, len),
                offset: offset_u8,
            }))
        }
        _ => Err(Status::invalid_argument(format!(
            "{label}: address family mismatch"
        ))),
    }
}

fn split_match_terms(s: &str, label: &str) -> Result<Vec<(String, bool)>, Status> {
    let mut terms = Vec::new();
    let mut current = String::new();
    let mut and_bit_for_current = false;

    for ch in s.chars() {
        match ch {
            ',' | '&' => {
                let token = current.trim();
                if token.is_empty() {
                    return Err(Status::invalid_argument(format!(
                        "{label}: empty term in {s:?}"
                    )));
                }
                terms.push((token.to_string(), and_bit_for_current));
                current.clear();
                and_bit_for_current = ch == '&';
            }
            _ => current.push(ch),
        }
    }

    let token = current.trim();
    if token.is_empty() {
        return Err(Status::invalid_argument(format!(
            "{label}: empty term in {s:?}"
        )));
    }
    terms.push((token.to_string(), and_bit_for_current));
    Ok(terms)
}

/// Parse a numeric operator expression into one or more `NumericMatch` terms.
///
/// Supports comma-separated OR terms and `&`-separated AND terms. Each term may
/// start with any combination of `=`, `<`, `>` (e.g. `=80`, `>=1024`, `<4096`).
/// A bare integer is treated as an exact match for backwards compatibility.
fn parse_numeric_value(s: &str, label: &str) -> Result<Vec<NumericMatch>, Status> {
    let terms = split_match_terms(s, label)?;
    let len = terms.len();
    let mut result = Vec::with_capacity(len);

    for (idx, (token, and_bit)) in terms.into_iter().enumerate() {
        let op_len = token
            .chars()
            .take_while(|c| matches!(c, '=' | '<' | '>' | '!'))
            .count();
        let (ops, value_part) = token.split_at(op_len);
        // `!=` is the not-equal form the read-back renders (`<>` spelled out).
        let (lt, gt, eq) = match ops {
            "!=" => (true, true, false),
            ops if ops.contains('!') => {
                return Err(Status::invalid_argument(format!(
                    "{label}: invalid operator in {token:?}"
                )));
            }
            ops => (ops.contains('<'), ops.contains('>'), ops.contains('=')),
        };
        let value_str = value_part.trim();
        let value: u64 = value_str.parse().map_err(|e| {
            Status::invalid_argument(format!("{label}: invalid value {token:?}: {e}"))
        })?;
        result.push(NumericMatch {
            end_of_list: idx + 1 == len,
            and_bit,
            lt,
            gt,
            eq: if ops.is_empty() { true } else { eq },
            value,
        });
    }

    Ok(result)
}

/// Parse a bitmask operator expression into one or more `BitmaskMatch` terms.
///
/// Supports comma-separated OR terms and `&`-separated AND terms. Each term is
/// parsed as a decimal or hex (with `0x` prefix) integer. The parser accepts the
/// subset emitted by `format_bitmask_ops()` and preserves AND chaining.
fn parse_bitmask_value(s: &str, label: &str) -> Result<Vec<BitmaskMatch>, Status> {
    let terms = split_match_terms(s, label)?;
    let len = terms.len();
    let mut result = Vec::with_capacity(len);

    for (idx, (token, and_bit)) in terms.into_iter().enumerate() {
        let mut trimmed = token.trim_start_matches('=').trim();
        let not_bit = if let Some(rest) = trimmed.strip_prefix('!') {
            trimmed = rest.trim_start();
            true
        } else {
            false
        };
        if let Some(rest) = trimmed.strip_suffix("/match") {
            trimmed = rest.trim_end();
        }
        let value: u16 = if let Some(hex) = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
        {
            u16::from_str_radix(hex, 16).map_err(|e| {
                Status::invalid_argument(format!("{label}: invalid hex value {token:?}: {e}"))
            })?
        } else {
            trimmed.parse().map_err(|e| {
                Status::invalid_argument(format!("{label}: invalid value {token:?}: {e}"))
            })?
        };
        result.push(BitmaskMatch {
            end_of_list: idx + 1 == len,
            and_bit,
            not_bit,
            match_bit: true,
            value,
        });
    }

    Ok(result)
}

/// Convert a proto `FlowSpecAction` into a wire `ExtendedCommunity`.
fn flowspec_action_to_ec(
    action: &proto::FlowSpecAction,
) -> Result<Option<ExtendedCommunity>, Status> {
    use rustbgpd_wire::flowspec::FlowSpecAction;
    let Some(ref inner) = action.action else {
        return Ok(None);
    };
    let wire_action = match inner {
        proto::flow_spec_action::Action::TrafficRate(r) => FlowSpecAction::TrafficRateBytes {
            asn: 0,
            rate: r.rate,
        },
        proto::flow_spec_action::Action::TrafficAction(a) => FlowSpecAction::TrafficAction {
            sample: a.sample,
            terminal: a.terminal,
        },
        proto::flow_spec_action::Action::TrafficMarking(m) => FlowSpecAction::TrafficMarking {
            dscp: u8::try_from(m.dscp)
                .map_err(|_| Status::invalid_argument("dscp must be 0..=63"))?,
        },
        proto::flow_spec_action::Action::TrafficRatePackets(r) => {
            FlowSpecAction::TrafficRatePackets {
                asn: 0,
                rate: r.rate,
            }
        }
        proto::flow_spec_action::Action::Redirect(r) => return parse_redirect(&r.route_target),
    };
    Ok(Some(ExtendedCommunity::from_flowspec_action(&wire_action)))
}

/// Parse `FlowSpecRedirect.route_target` into one of the RFC 8955 §7.4 /
/// RFC 7674 redirect communities. The Route Target grammar picks the form;
/// RFC 5396 asdot (`high.low:value`) selects the 4-octet-AS form for any ASN,
/// which is how a listing renders one whose ASN fits in 16 bits.
fn parse_redirect(s: &str) -> Result<Option<ExtendedCommunity>, Status> {
    if let Some((admin, value)) = s.split_once(':')
        && let Some((high, low)) = admin.split_once('.')
        && !low.contains('.')
    {
        let invalid = || {
            Status::invalid_argument(format!(
                "redirect route_target {s:?}: asdot form is \"high.low:value\" with 16-bit parts"
            ))
        };
        let high: u16 = high.parse().map_err(|_| invalid())?;
        let low: u16 = low.parse().map_err(|_| invalid())?;
        let value: u16 = value.parse().map_err(|_| invalid())?;
        let asn = (u32::from(high) << 16) | u32::from(low);
        return Ok(Some(ExtendedCommunity::from_flowspec_action(
            &rustbgpd_wire::flowspec::FlowSpecAction::Redirect4Octet { asn, value },
        )));
    }
    // RFC 7674 §1: each redirect keeps its Route Target's layout (types 0x00,
    // 0x01 from RFC 4360, 0x02 from RFC 5668) under types 0x80, 0x81, 0x82,
    // with sub-type 0x08 in place of the Route Target's 0x02.
    let mut bytes = parse_route_target(s)?.as_u64().to_be_bytes();
    bytes[0] |= 0x80;
    bytes[1] = 0x08;
    Ok(Some(ExtendedCommunity::new(u64::from_be_bytes(bytes))))
}

/// Parse a request MAC through the grammar shared with the configuration
/// loader, reporting a refusal as `INVALID_ARGUMENT` with the offending
/// input.
pub(crate) fn parse_mac(s: &str) -> Result<MacAddress, Status> {
    rustbgpd_evpn::parse_mac_address(s)
        .map_err(|e| Status::invalid_argument(format!("invalid MAC {s:?}: {e}")))
}

fn parse_router_mac(s: &str) -> Result<MacAddress, Status> {
    let mac = parse_mac(s)?;
    let octets = mac.octets();
    if octets.iter().all(|&b| b == 0) {
        return Err(Status::invalid_argument(
            "router_mac must be a unicast non-zero MAC",
        ));
    }
    if (octets[0] & 0x01) != 0 {
        return Err(Status::invalid_argument(
            "router_mac must be a unicast non-zero MAC",
        ));
    }
    Ok(mac)
}

fn parse_optional_ip(s: &str) -> Result<Option<IpAddr>, Status> {
    if s.is_empty() {
        return Ok(None);
    }
    s.parse()
        .map(Some)
        .map_err(|e| Status::invalid_argument(format!("invalid IP: {e}")))
}

fn parse_ip_required(s: &str, field: &str) -> Result<IpAddr, Status> {
    if s.is_empty() {
        return Err(Status::invalid_argument(format!("{field} is required")));
    }
    s.parse()
        .map_err(|e| Status::invalid_argument(format!("invalid {field}: {e}")))
}

/// Reject Type-5-only inputs on Type 2/3 requests so controller mistakes
/// don't look like successful injections.
fn reject_type5_only_fields(
    req: &proto::AddEvpnRouteRequest,
    route_type: u32,
) -> Result<(), Status> {
    if !req.prefix.is_empty() {
        return Err(Status::invalid_argument(format!(
            "prefix is Type 5 only; must be empty for Type {route_type}"
        )));
    }
    if req.prefix_length != 0 {
        return Err(Status::invalid_argument(format!(
            "prefix_length is Type 5 only; must be 0 for Type {route_type}"
        )));
    }
    if !req.router_mac.is_empty() {
        return Err(Status::invalid_argument(format!(
            "router_mac is Type 5 only; must be empty for Type {route_type}"
        )));
    }
    if !req.gateway.is_empty() {
        return Err(Status::invalid_argument(format!(
            "gateway is Type 5 only; must be empty for Type {route_type}"
        )));
    }
    Ok(())
}

/// Reject Type-5-only withdrawal key fields on Type 2/3 deletes so stale
/// controller payload fields cannot hide a mismatched route identity.
fn reject_delete_type5_only_fields(
    req: &proto::DeleteEvpnRouteRequest,
    route_type: u32,
) -> Result<(), Status> {
    if !req.prefix.is_empty() {
        return Err(Status::invalid_argument(format!(
            "prefix is Type 5 only; must be empty for Type {route_type} withdrawal"
        )));
    }
    if req.prefix_length != 0 {
        return Err(Status::invalid_argument(format!(
            "prefix_length is Type 5 only; must be 0 for Type {route_type} withdrawal"
        )));
    }
    Ok(())
}

/// Assemble a Type 2 MAC/IP route + its path attributes from the request.
fn build_type2(
    req: &proto::AddEvpnRouteRequest,
    rd: RouteDistinguisher,
) -> Result<(EvpnRoute, Vec<PathAttribute>), Status> {
    reject_type5_only_fields(req, 2)?;
    let mac = parse_mac(&req.mac)?;
    let ip = parse_optional_ip(&req.ip)?;
    if req.label == 0 {
        return Err(Status::invalid_argument(
            "label (VNI) is required for Type 2",
        ));
    }
    // The wire format reserves 24 bits for label / VNI per RFC 7432 §7.2;
    // `MplsLabel::new` masks silently, so reject out-of-range inputs at
    // the API boundary instead of letting the controller-supplied value
    // round-trip differently than it sent.
    if req.label > 0x00FF_FFFF {
        return Err(Status::invalid_argument(
            "label must fit in 24 bits (0..=16777215)",
        ));
    }
    if req.label2 > 0x00FF_FFFF {
        return Err(Status::invalid_argument(
            "label2 must fit in 24 bits (0..=16777215)",
        ));
    }
    let label2 = (req.label2 != 0).then(|| MplsLabel::new(req.label2));
    let route = EvpnRoute::MacIp(EvpnMacIp {
        rd,
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(req.ethernet_tag),
        mac,
        ip,
        label1: MplsLabel::new(req.label),
        label2,
    });
    Ok((route, build_common_attrs(req)?))
}

/// Assemble a Type 3 IMET route + attributes. IMET carries no MAC/label —
/// just RD, ethernet-tag, and originator-IP (taken from `ip`).
fn build_type3(
    req: &proto::AddEvpnRouteRequest,
    rd: RouteDistinguisher,
) -> Result<(EvpnRoute, Vec<PathAttribute>), Status> {
    reject_type5_only_fields(req, 3)?;
    // Reject Type-2-only fields explicitly — silently ignoring them
    // makes controller mistakes look like successful injects.
    if !req.mac.is_empty() {
        return Err(Status::invalid_argument(
            "mac is Type 2 only; must be empty for Type 3 IMET",
        ));
    }
    if req.label != 0 {
        return Err(Status::invalid_argument(
            "label is Type 2 only; must be 0 for Type 3 IMET",
        ));
    }
    if req.label2 != 0 {
        return Err(Status::invalid_argument(
            "label2 is Type 2 only; must be 0 for Type 3 IMET",
        ));
    }
    let originator_ip = parse_ip_required(&req.ip, "ip (originator_ip for Type 3)")?;
    let route = EvpnRoute::Imet(EvpnImet {
        rd,
        ethernet_tag: EthernetTagId(req.ethernet_tag),
        originator_ip,
    });
    Ok((route, build_common_attrs(req)?))
}

/// Assemble a Type 5 IP Prefix route + attributes.
///
/// Empty `gateway` keeps the original interface-less shape. A non-empty
/// gateway enables controller-injected overlay-index Type 5 while keeping ESI
/// zero; native IP-VRF local origination still uses gateway zero.
fn build_type5(
    req: &proto::AddEvpnRouteRequest,
    rd: RouteDistinguisher,
    next_hop: IpAddr,
) -> Result<(EvpnRoute, Vec<PathAttribute>), Status> {
    if req.ethernet_tag != 0 {
        return Err(Status::invalid_argument(
            "ethernet_tag must be 0 for Type 5 IP Prefix",
        ));
    }
    if !req.mac.is_empty() {
        return Err(Status::invalid_argument(
            "mac is Type 2 only; must be empty for Type 5 IP Prefix",
        ));
    }
    if !req.ip.is_empty() {
        return Err(Status::invalid_argument(
            "ip is Type 2/3 only; must be empty for Type 5 IP Prefix",
        ));
    }
    if req.label2 != 0 {
        return Err(Status::invalid_argument(
            "label2 is Type 2 only; must be 0 for Type 5 IP Prefix",
        ));
    }
    if req.label == 0 {
        return Err(Status::invalid_argument(
            "label (L3VNI) is required for Type 5 IP Prefix",
        ));
    }
    if req.label > 0x00FF_FFFF {
        return Err(Status::invalid_argument(
            "label must fit in 24 bits (0..=16777215)",
        ));
    }
    if req.route_targets.is_empty() {
        return Err(Status::invalid_argument(
            "at least one route_targets entry is required for Type 5 IP Prefix",
        ));
    }
    if !req.disable_vxlan_encap && req.router_mac.is_empty() {
        return Err(Status::invalid_argument(
            "router_mac is required for Type 5 VXLAN injection",
        ));
    }
    if req.disable_vxlan_encap && !req.router_mac.is_empty() {
        return Err(Status::invalid_argument(
            "router_mac requires VXLAN encapsulation; omit router_mac when disable_vxlan_encap is true",
        ));
    }

    let prefix = parse_evpn_ip_prefix(&req.prefix, req.prefix_length)?;
    let gateway = parse_type5_gateway(&req.gateway, prefix, next_hop)?;

    let route = EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
        rd,
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(req.ethernet_tag),
        prefix,
        gateway,
        label: MplsLabel::new(req.label),
    });

    let mut attrs = build_common_attrs(req)?;
    if !req.router_mac.is_empty() {
        push_extended_community(
            &mut attrs,
            ExtendedCommunity::router_mac(parse_router_mac(&req.router_mac)?.octets()),
        );
    }

    Ok((route, attrs))
}

/// Build the per-route attribute vector shared by Type 2, Type 3, and Type 5:
/// Origin=IGP, empty `AS_PATH`, LocalPref=100, and optional RTs +
/// VXLAN Encapsulation ext communities.
fn build_common_attrs(req: &proto::AddEvpnRouteRequest) -> Result<Vec<PathAttribute>, Status> {
    let mut attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(100),
    ];
    let mut ecs: Vec<ExtendedCommunity> = Vec::new();
    for rt in &req.route_targets {
        ecs.push(parse_route_target(rt)?);
    }
    // Default-false (proto3) → encap community attached, matching the
    // VXLAN-EVPN deployment target. The field is inverted so SDN
    // controllers that omit it still get the right behavior.
    if !req.disable_vxlan_encap {
        ecs.push(ExtendedCommunity::bgp_encapsulation(8));
    }
    if !ecs.is_empty() {
        attrs.push(PathAttribute::ExtendedCommunities(ecs));
    }
    Ok(attrs)
}

fn push_extended_community(attrs: &mut Vec<PathAttribute>, community: ExtendedCommunity) {
    if let Some(PathAttribute::ExtendedCommunities(ecs)) = attrs
        .iter_mut()
        .find(|attr| matches!(attr, PathAttribute::ExtendedCommunities(_)))
    {
        ecs.push(community);
    } else {
        attrs.push(PathAttribute::ExtendedCommunities(vec![community]));
    }
}

pub(crate) fn parse_route_target(s: &str) -> Result<ExtendedCommunity, Status> {
    let (admin, val) = s.split_once(':').ok_or_else(|| {
        Status::invalid_argument(format!("route_target must be \"admin:value\"; got {s:?}"))
    })?;
    let value: u32 = val
        .parse()
        .map_err(|_| Status::invalid_argument("route_target value must be u32"))?;

    // RFC 4360 Type 0x01: IPv4-admin RT — `dotted.quad.ipv4:u16`.
    // Recognized when the admin part parses as an IPv4 address and the
    // value fits in 16 bits. EVPN deployments commonly use this form for
    // RTs whose admin ID is a router-id (loopback) rather than an ASN.
    if let Ok(ipv4) = admin.parse::<std::net::Ipv4Addr>() {
        let v16 = u16::try_from(value).map_err(|_| {
            Status::invalid_argument("IPv4-admin route_target value must fit in u16")
        })?;
        let a = ipv4.octets();
        let v = v16.to_be_bytes();
        // Type=0x01 (transitive IPv4-admin), Subtype=0x02 (RT).
        return Ok(ExtendedCommunity::new(u64::from_be_bytes([
            0x01, 0x02, a[0], a[1], a[2], a[3], v[0], v[1],
        ])));
    }

    let admin_num: u64 = admin.parse().map_err(|_| {
        Status::invalid_argument("route_target admin must be numeric ASN or dotted IPv4 address")
    })?;
    if let Ok(admin16) = u16::try_from(admin_num) {
        // Type=0x00 (transitive 2-octet AS), Subtype=0x02 (RT).
        let a = admin16.to_be_bytes();
        let v = value.to_be_bytes();
        Ok(ExtendedCommunity::new(u64::from_be_bytes([
            0x00, 0x02, a[0], a[1], v[0], v[1], v[2], v[3],
        ])))
    } else {
        // Type=0x02 (transitive 4-octet AS), Subtype=0x02 (RT).
        let admin32 =
            u32::try_from(admin_num).map_err(|_| Status::invalid_argument("RT ASN > 32 bits"))?;
        let v16 = u16::try_from(value)
            .map_err(|_| Status::invalid_argument("RT 4-octet ASN takes u16 value"))?;
        let a = admin32.to_be_bytes();
        let v = v16.to_be_bytes();
        Ok(ExtendedCommunity::new(u64::from_be_bytes([
            0x02, 0x02, a[0], a[1], a[2], a[3], v[0], v[1],
        ])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::injection_service_server::InjectionService as _;
    use rustbgpd_wire::flowspec::FlowSpecAction;

    fn make_service() -> InjectionService {
        let (tx, _rx) = mpsc::channel(16);
        InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new()))
    }

    fn make_service_with_rx() -> (InjectionService, mpsc::Receiver<RibUpdate>) {
        let (tx, rx) = mpsc::channel(16);
        (
            InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new())),
            rx,
        )
    }

    fn add_path_request(origin: u32, next_hop: &str) -> Request<proto::AddPathRequest> {
        Request::new(proto::AddPathRequest {
            prefix: "10.0.0.0".into(),
            prefix_length: 24,
            next_hop: next_hop.into(),
            origin,
            as_path: vec![],
            local_pref: None,
            med: None,
            communities: vec![],
            extended_communities: vec![],
            large_communities: vec![],
            path_id: 0,
        })
    }

    fn oversized_flowspec_component() -> proto::FlowSpecComponent {
        let value = (0..2_200)
            .map(|i| format!("={i}"))
            .collect::<Vec<_>>()
            .join(" & ");
        proto::FlowSpecComponent {
            r#type: 4,
            prefix: String::new(),
            value,
            offset: 0,
        }
    }

    fn oversized_flowspec_rule() -> FlowSpecRule {
        let mut ops: Vec<NumericMatch> = (0..2_200)
            .map(|i| NumericMatch {
                end_of_list: false,
                and_bit: i != 0,
                lt: false,
                gt: false,
                eq: true,
                value: i,
            })
            .collect();
        ops.last_mut().expect("non-empty test rule").end_of_list = true;
        FlowSpecRule {
            components: vec![FlowSpecComponent::Port(ops)],
        }
    }

    #[test]
    fn rib_command_error_maps_not_found_without_string_matching() {
        let err = map_rib_command_error(
            "withdraw failed",
            RibCommandError::NotFound("missing route".to_string()),
        );
        assert_eq!(err.code(), tonic::Code::NotFound);
        assert_eq!(err.message(), "missing route");
    }

    #[test]
    fn rib_command_error_maps_internal_without_string_matching() {
        let err = map_rib_command_error(
            "inject failed",
            RibCommandError::Internal("storage not found during lookup".to_string()),
        );
        assert_eq!(err.code(), tonic::Code::Internal);
        assert_eq!(
            err.message(),
            "inject failed: storage not found during lookup"
        );
    }

    /// Load-bearing: a closed RIB command channel means the mutation was
    /// never accepted, which the documented status contract reports as
    /// `UNAVAILABLE`; only a reply lost after acceptance stays `INTERNAL`.
    #[tokio::test]
    async fn add_path_send_failure_is_unavailable() {
        let (tx, rx) = mpsc::channel(1);
        drop(rx);
        let svc =
            InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new()));
        let err = svc
            .add_path(add_path_request(0, "192.0.2.1"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unavailable);
        assert_eq!(err.message(), "RIB manager unavailable");
    }

    /// An unspecified next hop of either family is next-hop self: it reaches
    /// the RIB as the prefix family's unspecified address, with a stored
    /// `NEXT_HOP` only for an IPv4 prefix. EVPN injection still rejects it.
    /// The read is served on a read-only listener, maps the RIB's page to
    /// the wire, resumes after the token's peer, clamps the page size, and
    /// reports a missing local route as `NOT_FOUND`. The first page carries
    /// no cursor; a stale token is `ABORTED`, and a forged, legacy or
    /// other-key token is `INVALID_ARGUMENT` without reaching the RIB.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one paged exchange drives the mapping, resume, clamp, not-found and token checks"
    )]
    async fn list_path_export_dispositions_pages_and_maps_rows() {
        use rustbgpd_rib::update::{PeerRouteExport, RouteExportDisposition, RouteExportPage};

        let version = RouteExportVersion {
            roster: 5,
            route: 0xfeed,
        };
        let (tx, mut rx) = mpsc::channel(16);
        let svc = InjectionService::new(tx, AccessMode::ReadOnly, Arc::new(InjectionLeases::new()));
        let responder = tokio::spawn(async move {
            let mut seen = Vec::new();
            while let Some(update) = rx.recv().await {
                let RibUpdate::QueryLocalRouteExport {
                    prefix,
                    path_id,
                    after,
                    page_size,
                    reply,
                } = update
                else {
                    panic!("expected QueryLocalRouteExport");
                };
                seen.push((prefix, path_id, after, page_size));
                let page = if path_id != 7 {
                    Err(RouteExportPageError::NoRoute)
                } else if after.is_some_and(|(_, seen)| seen != version) {
                    Err(RouteExportPageError::Invalidated)
                } else {
                    Ok(RouteExportPage {
                        peers: vec![
                            PeerRouteExport {
                                peer: "192.0.2.1".parse().unwrap(),
                                peer_interface: None,
                                disposition: RouteExportDisposition::Withheld,
                                reason: "family_suppressed:missing_ipv6_next_hop".to_string(),
                                explain_code: "family_not_sendable",
                                detail: "withheld".to_string(),
                                advertised_path_id: 0,
                                deny_validation: vec![],
                            },
                            PeerRouteExport {
                                peer: "192.0.2.2".parse().unwrap(),
                                peer_interface: Some("eth0".into()),
                                disposition: RouteExportDisposition::Withheld,
                                reason: "export_policy".to_string(),
                                explain_code: "policy_denied",
                                detail: "denied".to_string(),
                                advertised_path_id: 0,
                                deny_validation: vec!["rpki_invalid".to_string()],
                            },
                        ],
                        more: after.is_none(),
                        version,
                    })
                };
                reply.send(page).ok();
            }
            seen
        });
        let request = |page_size, page_token: &str, path_id| {
            Request::new(proto::ListPathExportDispositionsRequest {
                prefix: "2001:db8::7".into(),
                prefix_length: 128,
                path_id,
                page_size,
                page_token: page_token.into(),
            })
        };
        let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8::7".parse().unwrap(), 128));
        let peer2: IpAddr = "192.0.2.2".parse().unwrap();

        let first = svc
            .list_path_export_dispositions(request(0, "", 7))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            decode_export_page_token(&first.next_page_token, prefix, 7).unwrap(),
            (peer2, version)
        );
        let row = &first.peers[0];
        assert_eq!(row.peer_address, "192.0.2.1");
        assert_eq!(
            row.disposition,
            proto::PathExportDisposition::Withheld as i32
        );
        assert_eq!(row.reason, "family_suppressed:missing_ipv6_next_hop");
        assert_eq!(row.explain_code, "family_not_sendable");
        assert_eq!(first.peers[1].deny_validation, ["rpki_invalid"]);
        // The scope of a link-local destination travels beside its address.
        assert_eq!(
            (
                row.peer_interface.as_str(),
                first.peers[1].peer_interface.as_str()
            ),
            ("", "eth0")
        );
        let last = svc
            .list_path_export_dispositions(request(5000, &first.next_page_token, 7))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(last.next_page_token, "");
        let missing = svc
            .list_path_export_dispositions(request(1, "", 8))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);
        // A token this process issued for an older walk version.
        let stale = encode_export_page_token(
            prefix,
            7,
            peer2,
            RouteExportVersion {
                roster: 4,
                ..version
            },
        );
        let aborted = svc
            .list_path_export_dispositions(request(1, &stale, 7))
            .await
            .unwrap_err();
        assert_eq!(aborted.code(), tonic::Code::Aborted);
        // Rejected before the RIB: a bare peer address (the earlier token
        // form), a token with an altered field, and another key's token.
        let altered = first.next_page_token.replacen("pe1|", "pe1|1", 1);
        for (token, path_id) in [
            ("not-an-address", 7),
            ("192.0.2.2", 7),
            (altered.as_str(), 7),
            (first.next_page_token.as_str(), 8),
        ] {
            let error = svc
                .list_path_export_dispositions(request(1, token, path_id))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument, "{token}");
        }

        drop(svc);
        assert_eq!(
            responder.await.unwrap(),
            vec![
                (prefix, 7, None, DEFAULT_EXPORT_PAGE_SIZE),
                (prefix, 7, Some((peer2, version)), ROUTE_QUERY_MAX_PAGE_SIZE),
                (prefix, 8, None, 1),
                (
                    prefix,
                    7,
                    Some((
                        peer2,
                        RouteExportVersion {
                            roster: 4,
                            ..version
                        }
                    )),
                    1
                ),
            ]
        );
    }

    /// The paged walk against a real RIB, mutated between page calls: a
    /// route deleted mid-walk is `ABORTED` where a never-added key is
    /// `NOT_FOUND`, and a peer flap between pages is `ABORTED` rather than
    /// a resumed walk that silently skips or repeats a peer.
    #[tokio::test]
    async fn export_disposition_walk_aborts_on_mid_walk_changes() {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(
            rib_tx.clone(),
            AccessMode::ReadWrite,
            Arc::new(InjectionLeases::new()),
        );
        let mut outbound = Vec::new();
        let mut peer_up = |octet: u8| {
            let (outbound_tx, outbound_rx) = mpsc::channel(64);
            outbound.push(outbound_rx);
            RibUpdate::PeerUp {
                peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet)),
                session_id: 0,
                peer_asn: 65_010,
                peer_router_id: Ipv4Addr::UNSPECIFIED,
                outbound_tx,
                export_policy: None,
                sendable_families: vec![(Afi::Ipv4, rustbgpd_wire::Safi::Unicast)],
                is_ebgp: true,
                route_reflector_client: false,
                orr_vantage: None,
                per_client_best: false,
                interpret_rfc1997: true,
                add_path_send_families: vec![],
                add_path_send_max: 0,
                negotiated_orf_recv: vec![],
                negotiated_llgr_families: vec![],
            }
        };
        for update in [peer_up(1), peer_up(2), peer_up(3)] {
            rib_tx.send(update).await.unwrap();
        }
        let add = |path_id| {
            svc.add_path(Request::new(proto::AddPathRequest {
                prefix: "203.0.113.7".into(),
                prefix_length: 32,
                next_hop: "0.0.0.0".into(),
                path_id,
                ..Default::default()
            }))
        };
        let list = |path_id, page_token: String| {
            svc.list_path_export_dispositions(Request::new(
                proto::ListPathExportDispositionsRequest {
                    prefix: "203.0.113.7".into(),
                    prefix_length: 32,
                    path_id,
                    page_size: 2,
                    page_token,
                },
            ))
        };
        add(1).await.unwrap();

        // Peer flap between pages: down then up again leaves the same
        // peer set, but the first page described the previous session.
        let first = list(1, String::new()).await.unwrap().into_inner();
        assert_eq!(first.peers.len(), 2);
        rib_tx
            .send(RibUpdate::PeerDown {
                peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                session_id: 0,
            })
            .await
            .unwrap();
        rib_tx.send(peer_up(1)).await.unwrap();
        let flapped = list(1, first.next_page_token).await.unwrap_err();
        assert_eq!(flapped.code(), tonic::Code::Aborted);

        // A restarted walk completes when nothing moves between pages.
        let first = list(1, String::new()).await.unwrap().into_inner();
        let rest = list(1, first.next_page_token.clone())
            .await
            .unwrap()
            .into_inner();
        assert_eq!(rest.peers.len(), 1);
        assert_eq!(rest.next_page_token, "");

        // Route deleted between pages.
        svc.delete_path(Request::new(proto::DeletePathRequest {
            prefix: "203.0.113.7".into(),
            prefix_length: 32,
            path_id: 1,
            ..Default::default()
        }))
        .await
        .unwrap();
        let deleted = list(1, first.next_page_token).await.unwrap_err();
        assert_eq!(deleted.code(), tonic::Code::Aborted);
        let never = list(2, String::new()).await.unwrap_err();
        assert_eq!(never.code(), tonic::Code::NotFound);
        let restarted = list(1, String::new()).await.unwrap_err();
        assert_eq!(restarted.code(), tonic::Code::NotFound);

        drop((svc, rib_tx, outbound));
        manager_task.await.unwrap();
    }

    #[tokio::test]
    async fn add_path_accepts_unspecified_next_hop_as_self() {
        let (svc, mut rx) = make_service_with_rx();
        let responder = tokio::spawn(async move {
            let mut routes = Vec::new();
            while let Some(update) = rx.recv().await {
                let RibUpdate::InjectRoute { route, reply } = update else {
                    panic!("expected InjectRoute");
                };
                reply.send(Ok(InjectOutcome::Created)).ok();
                routes.push(route);
            }
            routes
        });
        let cases = [
            ("10.0.0.0", 24, "0.0.0.0", "0.0.0.0"),
            ("10.0.0.0", 24, "::", "0.0.0.0"),
            ("2001:db8:ff::", 48, "::", "::"),
            ("2001:db8:ff::", 48, "0.0.0.0", "::"),
        ];
        for (prefix, prefix_length, next_hop, _) in cases {
            svc.add_path(Request::new(proto::AddPathRequest {
                prefix: prefix.into(),
                prefix_length,
                next_hop: next_hop.into(),
                ..Default::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{prefix} via {next_hop}: {error}"));
        }
        let evpn = svc
            .add_evpn_route(Request::new(proto::AddEvpnRouteRequest {
                route_type: 2,
                rd: "65000:100".into(),
                mac: "02:00:00:00:00:01".into(),
                next_hop: "0.0.0.0".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(evpn.code(), tonic::Code::InvalidArgument);
        drop(svc);
        let routes = responder.await.unwrap();
        assert_eq!(routes.len(), cases.len());
        for (route, (prefix, _, next_hop, stored)) in routes.iter().zip(cases) {
            let stored: IpAddr = stored.parse().unwrap();
            assert_eq!(route.next_hop, stored, "{prefix} via {next_hop}");
            let body = route
                .attributes
                .iter()
                .find_map(|attribute| match attribute {
                    PathAttribute::NextHop(next_hop) => Some(IpAddr::V4(*next_hop)),
                    _ => None,
                });
            let expected_body = stored.is_ipv4().then_some(stored);
            assert_eq!(body, expected_body, "{prefix} via {next_hop}");
        }
    }

    #[tokio::test]
    async fn add_flow_spec_rejects_oversized_rule_before_rib_update() {
        let (svc, mut rx) = make_service_with_rx();
        let err = svc
            .add_flow_spec(Request::new(proto::AddFlowSpecRequest {
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                components: vec![oversized_flowspec_component()],
                actions: vec![],
                communities: vec![],
                extended_communities: vec![],
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("FlowSpec NLRI rule length"));
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn delete_flow_spec_rejects_oversized_rule_before_rib_update() {
        let (svc, mut rx) = make_service_with_rx();
        let err = svc
            .delete_flow_spec(Request::new(proto::DeleteFlowSpecRequest {
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                components: vec![oversized_flowspec_component()],
                allow_missing: false,
                owner: String::new(),
                override_owner: false,
            }))
            .await
            .unwrap_err();

        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("FlowSpec NLRI rule length"));
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn add_path_rejects_multicast_next_hop() {
        let svc = make_service();
        let req = Request::new(proto::AddPathRequest {
            prefix: "10.0.0.0".into(),
            prefix_length: 24,
            next_hop: "224.0.0.1".into(),
            origin: 0,
            as_path: vec![],
            local_pref: None,
            med: None,
            communities: vec![],
            extended_communities: vec![],
            large_communities: vec![],
            path_id: 0,
        });
        let err = svc.add_path(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("multicast"));
    }

    #[tokio::test]
    async fn add_path_rejects_origin_above_two() {
        let svc = make_service();
        for origin in [3u32, 255] {
            let err = svc
                .add_path(add_path_request(origin, "10.0.0.1"))
                .await
                .unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "origin {origin}");
            assert!(
                err.message().contains("origin"),
                "message must name the field: {}",
                err.message()
            );
        }
    }

    /// An IPv6 prefix has no encoding for an IPv4 next hop: IPv6 unicast
    /// `MP_REACH` needs 16 or 32 octets, and a stored `NEXT_HOP` would sit
    /// beside `MP_REACH`. The reverse pairing (RFC 8950) stays accepted.
    #[tokio::test]
    async fn add_path_rejects_ipv6_prefix_with_ipv4_next_hop() {
        let (svc, mut rx) = make_service_with_rx();
        let responder = tokio::spawn(async move {
            let mut routes = Vec::new();
            while let Some(update) = rx.recv().await {
                let RibUpdate::InjectRoute { route, reply } = update else {
                    panic!("expected InjectRoute");
                };
                reply.send(Ok(InjectOutcome::Created)).ok();
                routes.push(route);
            }
            routes
        });
        let err = svc
            .add_path(Request::new(proto::AddPathRequest {
                prefix: "2001:db8:ff::".into(),
                prefix_length: 48,
                next_hop: "192.0.2.1".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("IPv6 next_hop"), "{}", err.message());

        // IPv4 prefix, IPv6 next hop: accepted, with no stored NEXT_HOP.
        svc.add_path(add_path_request(0, "2001:db8::1"))
            .await
            .unwrap();
        drop(svc);
        let routes = responder.await.unwrap();
        assert_eq!(routes.len(), 1, "only the RFC 8950 route reaches the RIB");
        assert_eq!(routes[0].next_hop, "2001:db8::1".parse::<IpAddr>().unwrap());
        assert!(
            !routes[0]
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::NextHop(_)))
        );
    }

    #[tokio::test]
    async fn add_path_accepts_valid_origins() {
        for (origin, expected) in [
            (0u32, Origin::Igp),
            (1, Origin::Egp),
            (2, Origin::Incomplete),
        ] {
            let (svc, mut rx) = make_service_with_rx();
            let reply_task = tokio::spawn(async move {
                match rx.recv().await.expect("one RibUpdate") {
                    RibUpdate::InjectRoute { route, reply } => {
                        reply.send(Ok(InjectOutcome::Created)).ok();
                        route
                    }
                    _ => panic!("expected InjectRoute"),
                }
            });
            svc.add_path(add_path_request(origin, "10.0.0.1"))
                .await
                .unwrap();
            let route = reply_task.await.unwrap();
            assert!(
                route
                    .attributes
                    .iter()
                    .any(|a| matches!(a, PathAttribute::Origin(o) if *o == expected)),
                "origin {origin} must map to {expected:?}"
            );
        }
    }

    #[tokio::test]
    async fn add_path_rejects_broadcast_next_hop() {
        let svc = make_service();
        let err = svc
            .add_path(add_path_request(0, "255.255.255.255"))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("255.255.255.255"));
    }

    #[tokio::test]
    async fn add_evpn_route_rejects_broadcast_next_hop() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 2,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "02:00:00:aa:bb:cc".into(),
            ip: String::new(),
            label: 100,
            label2: 0,
            next_hop: "255.255.255.255".into(),
            route_targets: vec![],
            disable_vxlan_encap: false,
            prefix: String::new(),
            prefix_length: 0,
            router_mac: String::new(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("255.255.255.255"));
    }

    #[tokio::test]
    async fn add_path_rejected_on_read_only_listener() {
        let (tx, mut rx) = mpsc::channel(16);
        let svc = InjectionService::new(tx, AccessMode::ReadOnly, Arc::new(InjectionLeases::new()));
        let req = Request::new(proto::AddPathRequest {
            prefix: "10.0.0.0".into(),
            prefix_length: 24,
            next_hop: "10.0.0.1".into(),
            origin: 0,
            as_path: vec![],
            local_pref: None,
            med: None,
            communities: vec![],
            extended_communities: vec![],
            large_communities: vec![],
            path_id: 0,
        });
        let err = svc.add_path(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn non_evpn_mutations_rejected_on_read_only_listener() {
        let (tx, mut rx) = mpsc::channel(16);
        let svc = InjectionService::new(tx, AccessMode::ReadOnly, Arc::new(InjectionLeases::new()));

        let err = svc
            .delete_path(Request::new(proto::DeletePathRequest {
                prefix: "10.0.0.0".into(),
                prefix_length: 24,
                path_id: 0,
                allow_missing: false,
                owner: String::new(),
                override_owner: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = svc
            .add_flow_spec(Request::new(proto::AddFlowSpecRequest {
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                components: Vec::new(),
                actions: Vec::new(),
                communities: Vec::new(),
                extended_communities: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        let err = svc
            .delete_flow_spec(Request::new(proto::DeleteFlowSpecRequest {
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                components: Vec::new(),
                allow_missing: false,
                owner: String::new(),
                override_owner: false,
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);

        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    /// Every numeric operator the injection API accepts renders, in the
    /// read-back, as a value it accepts again with the same flags, so a
    /// listed `FlowSpec` key deletes unchanged.
    ///
    /// Break-to-red: rendering not-equal-or-equal as `?`, or rejecting the
    /// rendered `!=`, fails here.
    #[test]
    fn rendered_numeric_operators_parse_back_to_the_same_flags() {
        for (lt, gt, eq) in [
            (false, false, true),
            (true, false, false),
            (false, true, false),
            (true, false, true),
            (false, true, true),
            (true, true, false),
            (true, true, true),
        ] {
            let op = NumericMatch {
                end_of_list: true,
                and_bit: false,
                lt,
                gt,
                eq,
                value: 80,
            };
            let rendered = crate::rib_service::format_numeric_ops(std::slice::from_ref(&op));
            let parsed = parse_numeric_value(&rendered, "port")
                .unwrap_or_else(|error| panic!("{rendered:?}: {error}"));
            assert_eq!(parsed, vec![op], "{rendered:?}");
        }
        assert_eq!(
            parse_numeric_value("!80", "port").unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }

    #[test]
    fn parse_numeric_value_supports_multiple_terms() {
        let ops = parse_numeric_value(">=1024 & <=65535", "port").unwrap();
        assert_eq!(ops.len(), 2);
        assert!(!ops[0].and_bit);
        assert!(ops[0].gt);
        assert!(ops[0].eq);
        assert_eq!(ops[0].value, 1024);
        assert!(ops[1].and_bit);
        assert!(ops[1].lt);
        assert!(ops[1].eq);
        assert_eq!(ops[1].value, 65535);
        assert!(ops[1].end_of_list);
    }

    #[test]
    fn parse_bitmask_value_supports_multiple_terms() {
        let ops = parse_bitmask_value("0x02 & 0x04", "tcp_flags").unwrap();
        assert_eq!(ops.len(), 2);
        assert_eq!(ops[0].value, 0x0002);
        assert!(!ops[0].and_bit);
        assert_eq!(ops[1].value, 0x0004);
        assert!(ops[1].and_bit);
        assert!(ops[1].end_of_list);
    }

    #[test]
    fn parse_bitmask_value_supports_not_and_match_suffix() {
        let ops = parse_bitmask_value("!0x02/match", "fragment").unwrap();
        assert_eq!(ops.len(), 1);
        assert!(ops[0].not_bit);
        assert!(ops[0].match_bit);
        assert_eq!(ops[0].value, 0x0002);
    }

    #[test]
    fn parse_flowspec_components_rejects_offset_on_non_prefix() {
        let err = parse_flowspec_components(
            &[proto::FlowSpecComponent {
                r#type: 3,
                prefix: String::new(),
                value: "6".into(),
                offset: 12,
            }],
            Afi::Ipv4,
        )
        .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("offset is only valid"));
    }

    #[test]
    fn parse_flowspec_prefix_rejects_ipv4_offset() {
        let err =
            parse_flowspec_prefix("192.0.2.0/24", Afi::Ipv4, "destination prefix", 4).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("IPv6 FlowSpec"));
    }

    #[test]
    fn validate_flowspec_rule_encoded_len_rejects_oversized_rule() {
        let err =
            validate_flowspec_rule_encoded_len(&oversized_flowspec_rule(), Afi::Ipv4).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("FlowSpec NLRI rule length"));
    }

    #[test]
    fn parse_rd_type0_ibgp() {
        let rd = parse_rd("65000:100").unwrap();
        assert_eq!(rd.rd_type(), 0);
        assert_eq!(rd.octets()[2..4], [0xFD, 0xE8]); // 65000 big-endian
        assert_eq!(rd.octets()[4..8], [0, 0, 0, 100]);
    }

    #[test]
    fn parse_rd_type1_ipv4() {
        let rd = parse_rd("10.0.0.1:100").unwrap();
        assert_eq!(rd.rd_type(), 1);
        assert_eq!(rd.octets()[2..6], [10, 0, 0, 1]);
        assert_eq!(rd.octets()[6..8], [0, 100]);
    }

    #[test]
    fn parse_rd_type2_asn32() {
        let rd = parse_rd("4200000000:100").unwrap();
        assert_eq!(rd.rd_type(), 2);
        // 4_200_000_000 = 0xFA56_EA00
        assert_eq!(rd.octets()[2..6], [0xFA, 0x56, 0xEA, 0x00]);
        assert_eq!(rd.octets()[6..8], [0, 100]);
    }

    #[test]
    fn parse_rd_rejects_malformed() {
        assert!(parse_rd("not-an-rd").is_err());
        assert!(parse_rd("65000").is_err());
        assert!(parse_rd("99999999999999:1").is_err()); // ASN > 32 bits
    }

    #[test]
    fn parse_mac_roundtrip() {
        let mac = parse_mac("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac.octets(), [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn parse_mac_rejects_malformed() {
        assert!(parse_mac("aa:bb:cc").is_err());
        assert!(parse_mac("aa:bb:cc:dd:ee:gg").is_err());
        // Same grammar as the configuration parser: exactly two hex
        // digits per octet, so short groups and signed groups (which
        // `u8::from_str_radix` would otherwise accept) are rejected.
        assert!(parse_mac("2:0:0:0:0:1").is_err());
        assert!(parse_mac("+2:+0:+0:+0:+0:+1").is_err());
        assert!(parse_mac("00f:00:00:00:00:01").is_err());
    }

    #[tokio::test]
    async fn raw_rd_round_trips_add_and_delete_evpn_route() {
        let rd = RouteDistinguisher([0, 2, 0, 0, 0xfd, 0xe8, 0, 100]);
        let (tx, mut rx) = mpsc::channel(2);
        let service =
            InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new()));
        let actor = tokio::spawn(async move {
            let Some(RibUpdate::InjectEvpn { route, reply }) = rx.recv().await else {
                panic!("expected injection");
            };
            let key = route.key();
            assert_eq!(rustbgpd_rib::event::evpn_key_rd(&key), Some(rd));
            let output = crate::rib_service::evpn_route_to_proto(&route);
            assert_eq!(output.rd, "0x00020000fde80064");
            reply.send(Ok(())).unwrap();
            let Some(RibUpdate::WithdrawEvpn {
                key: removed,
                reply,
            }) = rx.recv().await
            else {
                panic!("expected withdrawal");
            };
            assert_eq!(removed, key);
            reply.send(Ok(())).unwrap();
        });
        service
            .add_evpn_route(Request::new(proto::AddEvpnRouteRequest {
                route_type: 2,
                rd: "0X00020000FDE80064".into(),
                mac: "02:00:00:00:00:01".into(),
                label: 100,
                next_hop: "192.0.2.1".into(),
                ..Default::default()
            }))
            .await
            .unwrap();
        service
            .delete_evpn_route(Request::new(proto::DeleteEvpnRouteRequest {
                route_type: 2,
                rd: crate::route_distinguisher::format_rd(rd),
                mac: "02:00:00:00:00:01".into(),
                ..Default::default()
            }))
            .await
            .unwrap();
        actor.await.unwrap();
    }

    #[tokio::test]
    async fn add_evpn_type2_reaches_rib_channel() {
        let (tx, mut rx) = mpsc::channel::<RibUpdate>(16);
        let svc =
            InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new()));

        // Drive the reply side: accept one InjectEvpn, reply Ok(()).
        let reply_task = tokio::spawn(async move {
            let update = rx.recv().await.expect("service should send one RibUpdate");
            match update {
                RibUpdate::InjectEvpn { route, reply } => {
                    assert_eq!(route.route.route_type(), 2);
                    reply.send(Ok(())).ok();
                    Some(route.key())
                }
                _ => panic!("expected InjectEvpn"),
            }
        });

        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 2,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "02:00:00:aa:bb:cc".into(),
            ip: String::new(),
            label: 100,
            label2: 0,
            next_hop: "10.0.0.2".into(),
            route_targets: vec!["65000:200".into()],
            disable_vxlan_encap: false,
            prefix: String::new(),
            prefix_length: 0,
            router_mac: String::new(),
            gateway: String::new(),
        });
        svc.add_evpn_route(req).await.unwrap();
        let key = reply_task.await.unwrap().unwrap();
        // Round-trip the key's wire form to confirm field propagation.
        let EvpnRouteKey::MacIp { mac, .. } = key else {
            panic!("expected MacIp key");
        };
        assert_eq!(mac.0, [0x02, 0x00, 0x00, 0xAA, 0xBB, 0xCC]);
    }

    /// Regression: a controller that omits `disable_vxlan_encap` (proto3
    /// default-false) MUST get the RFC 8365 §5.1.2 VXLAN Encapsulation
    /// ext community attached. The earlier field name (`vxlan_encap`)
    /// inverted the semantics — proto3 default-false meant "no encap"
    /// for clients that didn't know to set it, silently breaking VXLAN
    /// fabrics. The rename to `disable_vxlan_encap` aligns proto3
    /// default-false with the operationally-correct behavior.
    #[tokio::test]
    async fn add_evpn_default_request_attaches_vxlan_encap_community() {
        let (tx, mut rx) = mpsc::channel::<RibUpdate>(16);
        let svc =
            InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new()));

        let reply_task = tokio::spawn(async move {
            let update = rx.recv().await.expect("service should send one RibUpdate");
            match update {
                RibUpdate::InjectEvpn { route, reply } => {
                    reply.send(Ok(())).ok();
                    route
                }
                _ => panic!("expected InjectEvpn"),
            }
        });

        // disable_vxlan_encap left at its proto3 default (false) — same
        // shape any non-CLI gRPC client would produce by omitting the
        // field. The fix means the default attaches the encap community.
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 2,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "02:00:00:aa:bb:cc".into(),
            ip: String::new(),
            label: 100,
            label2: 0,
            next_hop: "10.0.0.2".into(),
            route_targets: vec![],
            disable_vxlan_encap: false,
            prefix: String::new(),
            prefix_length: 0,
            router_mac: String::new(),
            gateway: String::new(),
        });
        svc.add_evpn_route(req).await.unwrap();
        let route = reply_task.await.unwrap();

        let has_vxlan_encap = route.attributes.iter().any(|a| {
            if let PathAttribute::ExtendedCommunities(ecs) = a {
                ecs.iter().any(|ec| ec.as_bgp_encapsulation() == Some(8))
            } else {
                false
            }
        });
        assert!(
            has_vxlan_encap,
            "default-constructed AddEvpnRouteRequest must yield a route \
             carrying the RFC 8365 VXLAN encap ext community"
        );
    }

    /// Regression: setting `disable_vxlan_encap = true` actually
    /// suppresses the community.
    #[tokio::test]
    async fn add_evpn_disable_vxlan_encap_suppresses_community() {
        let (tx, mut rx) = mpsc::channel::<RibUpdate>(16);
        let svc =
            InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new()));

        let reply_task = tokio::spawn(async move {
            let update = rx.recv().await.expect("service should send one RibUpdate");
            match update {
                RibUpdate::InjectEvpn { route, reply } => {
                    reply.send(Ok(())).ok();
                    route
                }
                _ => panic!("expected InjectEvpn"),
            }
        });

        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 2,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "02:00:00:aa:bb:cc".into(),
            ip: String::new(),
            label: 100,
            label2: 0,
            next_hop: "10.0.0.2".into(),
            route_targets: vec![],
            disable_vxlan_encap: true,
            prefix: String::new(),
            prefix_length: 0,
            router_mac: String::new(),
            gateway: String::new(),
        });
        svc.add_evpn_route(req).await.unwrap();
        let route = reply_task.await.unwrap();

        let has_vxlan_encap = route.attributes.iter().any(|a| {
            if let PathAttribute::ExtendedCommunities(ecs) = a {
                ecs.iter().any(|ec| ec.as_bgp_encapsulation() == Some(8))
            } else {
                false
            }
        });
        assert!(
            !has_vxlan_encap,
            "disable_vxlan_encap=true must suppress the encap community"
        );
    }

    #[tokio::test]
    async fn add_evpn_type2_rejects_zero_vni() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 2,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ip: String::new(),
            label: 0,
            label2: 0,
            next_hop: "10.0.0.2".into(),
            route_targets: vec![],
            disable_vxlan_encap: false,
            prefix: String::new(),
            prefix_length: 0,
            router_mac: String::new(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("VNI"));
    }

    #[tokio::test]
    async fn add_evpn_rejects_type5_only_fields_on_type2_and_type3() {
        let svc = make_service();

        let type2_with_prefix = Request::new(proto::AddEvpnRouteRequest {
            route_type: 2,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "02:00:00:aa:bb:cc".into(),
            ip: String::new(),
            label: 100,
            label2: 0,
            next_hop: "10.0.0.2".into(),
            route_targets: vec![],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: String::new(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(type2_with_prefix).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("prefix"));

        let type2_with_router_mac = Request::new(proto::AddEvpnRouteRequest {
            route_type: 2,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "02:00:00:aa:bb:cc".into(),
            ip: String::new(),
            label: 100,
            label2: 0,
            next_hop: "10.0.0.2".into(),
            route_targets: vec![],
            disable_vxlan_encap: false,
            prefix: String::new(),
            prefix_length: 0,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(type2_with_router_mac).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("router_mac"));

        let type2_with_gateway = Request::new(proto::AddEvpnRouteRequest {
            route_type: 2,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "02:00:00:aa:bb:cc".into(),
            ip: String::new(),
            label: 100,
            label2: 0,
            next_hop: "10.0.0.2".into(),
            route_targets: vec![],
            disable_vxlan_encap: false,
            prefix: String::new(),
            prefix_length: 0,
            router_mac: String::new(),
            gateway: "192.0.2.10".into(),
        });
        let err = svc.add_evpn_route(type2_with_gateway).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("gateway"));

        let type3_with_prefix = Request::new(proto::AddEvpnRouteRequest {
            route_type: 3,
            rd: "65000:300".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: "10.0.0.3".into(),
            label: 0,
            label2: 0,
            next_hop: "10.0.0.3".into(),
            route_targets: vec![],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: String::new(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(type3_with_prefix).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("prefix"));
    }

    #[tokio::test]
    async fn add_evpn_type5_reaches_rib_channel() {
        let (tx, mut rx) = mpsc::channel::<RibUpdate>(16);
        let svc =
            InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new()));

        let reply_task = tokio::spawn(async move {
            let update = rx.recv().await.expect("service should send one RibUpdate");
            match update {
                RibUpdate::InjectEvpn { route, reply } => {
                    assert_eq!(route.route.route_type(), 5);
                    reply.send(Ok(())).ok();
                    route
                }
                _ => panic!("expected InjectEvpn"),
            }
        });

        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 5000,
            label2: 0,
            next_hop: "192.0.2.10".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: String::new(),
        });
        svc.add_evpn_route(req).await.unwrap();
        let route = reply_task.await.unwrap();

        assert_eq!(route.next_hop, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
        let EvpnRoute::IpPrefix(t5) = route.route else {
            panic!("expected Type 5 IP Prefix route");
        };
        assert_eq!(t5.ethernet_tag, EthernetTagId(0));
        assert_eq!(t5.label.value(), 5000);
        assert_eq!(t5.gateway, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert!(
            matches!(t5.prefix, EvpnIpPrefixValue::V4(p) if p.addr == Ipv4Addr::new(10, 50, 0, 0) && p.len == 24)
        );

        let ext_comms: Vec<ExtendedCommunity> = route
            .attributes
            .iter()
            .filter_map(|a| match a {
                PathAttribute::ExtendedCommunities(ecs) => Some(ecs.as_slice()),
                _ => None,
            })
            .flatten()
            .copied()
            .collect();
        assert!(
            ext_comms
                .iter()
                .any(|ec| ec.as_bgp_encapsulation() == Some(8)),
            "Type 5 VXLAN injection should keep the default encap community"
        );
        assert!(
            ext_comms
                .iter()
                .any(|ec| ec.as_router_mac() == Some([0x02, 0, 0, 0, 0x50, 0])),
            "Type 5 VXLAN injection should attach Router MAC"
        );
        assert!(
            ext_comms
                .iter()
                .any(|ec| *ec == parse_route_target("65000:5000").unwrap()),
            "Type 5 injection should attach requested route targets"
        );
    }

    #[tokio::test]
    async fn add_evpn_type5_overlay_gateway_reaches_rib_channel() {
        let (tx, mut rx) = mpsc::channel::<RibUpdate>(16);
        let svc =
            InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new()));

        let reply_task = tokio::spawn(async move {
            let update = rx.recv().await.expect("service should send one RibUpdate");
            match update {
                RibUpdate::InjectEvpn { route, reply } => {
                    assert_eq!(route.route.route_type(), 5);
                    reply.send(Ok(())).ok();
                    route
                }
                _ => panic!("expected InjectEvpn"),
            }
        });

        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 5000,
            label2: 0,
            next_hop: "192.0.2.10".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: "192.0.2.254".into(),
        });
        svc.add_evpn_route(req).await.unwrap();
        let route = reply_task.await.unwrap();

        let EvpnRoute::IpPrefix(t5) = route.route else {
            panic!("expected Type 5 IP Prefix route");
        };
        assert_eq!(t5.esi, EthernetSegmentIdentifier::ZERO);
        assert_eq!(t5.ethernet_tag, EthernetTagId(0));
        assert_eq!(t5.label.value(), 5000);
        assert_eq!(t5.gateway, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 254)));
        assert!(
            matches!(t5.prefix, EvpnIpPrefixValue::V4(p) if p.addr == Ipv4Addr::new(10, 50, 0, 0) && p.len == 24)
        );
    }

    #[tokio::test]
    async fn add_evpn_type5_ipv6_reaches_rib_channel() {
        let (tx, mut rx) = mpsc::channel::<RibUpdate>(16);
        let svc =
            InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new()));

        let reply_task = tokio::spawn(async move {
            let update = rx.recv().await.expect("service should send one RibUpdate");
            match update {
                RibUpdate::InjectEvpn { route, reply } => {
                    assert_eq!(route.route.route_type(), 5);
                    reply.send(Ok(())).ok();
                    route
                }
                _ => panic!("expected InjectEvpn"),
            }
        });

        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 5000,
            label2: 0,
            next_hop: "2001:db8::10".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: false,
            prefix: "2001:db8:50::".into(),
            prefix_length: 48,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: String::new(),
        });
        svc.add_evpn_route(req).await.unwrap();
        let route = reply_task.await.unwrap();

        assert_eq!(route.next_hop, IpAddr::V6("2001:db8::10".parse().unwrap()));
        let EvpnRoute::IpPrefix(t5) = route.route else {
            panic!("expected Type 5 IP Prefix route");
        };
        assert_eq!(t5.gateway, IpAddr::V6(Ipv6Addr::UNSPECIFIED));
        assert!(
            matches!(t5.prefix, EvpnIpPrefixValue::V6(p) if p.addr == "2001:db8:50::".parse::<Ipv6Addr>().unwrap() && p.len == 48)
        );
    }

    #[tokio::test]
    async fn add_evpn_type5_requires_router_mac_for_vxlan() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 5000,
            label2: 0,
            next_hop: "192.0.2.10".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: String::new(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("router_mac"));
    }

    #[tokio::test]
    async fn add_evpn_type5_rejects_router_mac_without_vxlan() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 5000,
            label2: 0,
            next_hop: "192.0.2.10".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: true,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("disable_vxlan_encap"));
    }

    #[tokio::test]
    async fn add_evpn_type5_rejects_nonzero_ethernet_tag() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 100,
            mac: String::new(),
            ip: String::new(),
            label: 5000,
            label2: 0,
            next_hop: "192.0.2.10".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("ethernet_tag"));
    }

    #[tokio::test]
    async fn add_evpn_type5_rejects_zero_l3vni() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 0,
            label2: 0,
            next_hop: "192.0.2.10".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("L3VNI"));
    }

    #[tokio::test]
    async fn add_evpn_type5_rejects_prefix_next_hop_family_mismatch() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 5000,
            label2: 0,
            next_hop: "2001:db8::1".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("same IP family"));
    }

    #[tokio::test]
    async fn add_evpn_type5_rejects_gateway_family_mismatch() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 5000,
            label2: 0,
            next_hop: "192.0.2.10".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: "2001:db8::1".into(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("gateway and prefix"));
    }

    #[tokio::test]
    async fn add_evpn_type5_rejects_explicit_zero_gateway() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 5000,
            label2: 0,
            next_hop: "192.0.2.10".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: "0.0.0.0".into(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("omit gateway"));
    }

    #[tokio::test]
    async fn add_evpn_type5_rejects_multicast_gateway() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 5000,
            label2: 0,
            next_hop: "192.0.2.10".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: "224.0.0.1".into(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("unicast"));
    }

    #[tokio::test]
    async fn add_evpn_type5_rejects_broadcast_gateway() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 5000,
            label2: 0,
            next_hop: "192.0.2.10".into(),
            route_targets: vec!["65000:5000".into()],
            disable_vxlan_encap: false,
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
            router_mac: "02:00:00:00:50:00".into(),
            gateway: "255.255.255.255".into(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("unicast"));
    }

    #[tokio::test]
    async fn delete_evpn_type5_reaches_rib_channel() {
        let (tx, mut rx) = mpsc::channel::<RibUpdate>(16);
        let svc =
            InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new()));

        let reply_task = tokio::spawn(async move {
            let update = rx.recv().await.expect("service should send one RibUpdate");
            match update {
                RibUpdate::WithdrawEvpn { key, reply } => {
                    reply.send(Ok(())).ok();
                    key
                }
                _ => panic!("expected WithdrawEvpn"),
            }
        });

        let req = Request::new(proto::DeleteEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
        });
        svc.delete_evpn_route(req).await.unwrap();
        let key = reply_task.await.unwrap();
        assert!(matches!(
            key,
            EvpnRouteKey::IpPrefix {
                ethernet_tag: EthernetTagId(0),
                prefix: EvpnIpPrefixValue::V4(p),
                ..
            } if p.addr == Ipv4Addr::new(10, 50, 0, 0) && p.len == 24
        ));
    }

    #[tokio::test]
    async fn delete_evpn_type5_rejects_nonzero_ethernet_tag() {
        let svc = make_service();
        let req = Request::new(proto::DeleteEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 100,
            mac: String::new(),
            ip: String::new(),
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
        });
        let err = svc.delete_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("ethernet_tag"));
    }

    #[tokio::test]
    async fn delete_evpn_rejects_cross_type_key_fields() {
        let svc = make_service();

        let type2_with_prefix = Request::new(proto::DeleteEvpnRouteRequest {
            route_type: 2,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "02:00:00:aa:bb:cc".into(),
            ip: String::new(),
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
        });
        let err = svc.delete_evpn_route(type2_with_prefix).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("prefix"));

        let type3_with_mac = Request::new(proto::DeleteEvpnRouteRequest {
            route_type: 3,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "02:00:00:aa:bb:cc".into(),
            ip: "192.0.2.10".into(),
            prefix: String::new(),
            prefix_length: 0,
        });
        let err = svc.delete_evpn_route(type3_with_mac).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("mac"));

        let type5_with_ip = Request::new(proto::DeleteEvpnRouteRequest {
            route_type: 5,
            rd: "65000:5000".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: "192.0.2.10".into(),
            prefix: "10.50.0.0".into(),
            prefix_length: 24,
        });
        let err = svc.delete_evpn_route(type5_with_ip).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
        assert!(err.message().contains("ip"));
    }

    #[tokio::test]
    async fn add_evpn_rejects_unsupported_route_type() {
        let svc = make_service();
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 4,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: String::new(),
            ip: String::new(),
            label: 0,
            label2: 0,
            next_hop: "10.0.0.2".into(),
            route_targets: vec![],
            disable_vxlan_encap: false,
            prefix: String::new(),
            prefix_length: 0,
            router_mac: String::new(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn add_evpn_rejected_on_read_only_listener() {
        let (tx, _rx) = mpsc::channel(16);
        let svc = InjectionService::new(tx, AccessMode::ReadOnly, Arc::new(InjectionLeases::new()));
        let req = Request::new(proto::AddEvpnRouteRequest {
            route_type: 2,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ip: String::new(),
            label: 100,
            label2: 0,
            next_hop: "10.0.0.2".into(),
            route_targets: vec![],
            disable_vxlan_encap: false,
            prefix: String::new(),
            prefix_length: 0,
            router_mac: String::new(),
            gateway: String::new(),
        });
        let err = svc.add_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[tokio::test]
    async fn delete_evpn_rejected_on_read_only_listener() {
        let (tx, mut rx) = mpsc::channel(16);
        let svc = InjectionService::new(tx, AccessMode::ReadOnly, Arc::new(InjectionLeases::new()));
        let req = Request::new(proto::DeleteEvpnRouteRequest {
            route_type: 2,
            rd: "65000:100".into(),
            ethernet_tag: 0,
            mac: "aa:bb:cc:dd:ee:ff".into(),
            ip: String::new(),
            prefix: String::new(),
            prefix_length: 0,
        });
        let err = svc.delete_evpn_route(req).await.unwrap_err();
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    fn flowspec_rate(rate: f32) -> proto::FlowSpecAction {
        proto::FlowSpecAction {
            action: Some(proto::flow_spec_action::Action::TrafficRate(
                proto::FlowSpecTrafficRate { rate },
            )),
        }
    }

    fn flowspec_rule_components() -> Vec<proto::FlowSpecComponent> {
        vec![
            proto::FlowSpecComponent {
                r#type: 1,
                prefix: "203.0.113.0/24".into(),
                value: String::new(),
                offset: 0,
            },
            proto::FlowSpecComponent {
                r#type: 4,
                prefix: String::new(),
                value: "=80".into(),
                offset: 0,
            },
        ]
    }

    async fn add_rate(svc: &InjectionService, rate: f32) -> proto::FlowSpecInjectOutcome {
        let response = svc
            .add_flow_spec(Request::new(proto::AddFlowSpecRequest {
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                components: flowspec_rule_components(),
                actions: vec![flowspec_rate(rate)],
                communities: vec![],
                extended_communities: vec![],
            }))
            .await
            .expect("add accepted")
            .into_inner();
        response.outcome()
    }

    async fn delete_rule(
        svc: &InjectionService,
        allow_missing: bool,
    ) -> Result<proto::DeleteFlowSpecResponse, Status> {
        svc.delete_flow_spec(Request::new(proto::DeleteFlowSpecRequest {
            afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
            components: flowspec_rule_components(),
            allow_missing,
            owner: String::new(),
            override_owner: false,
        }))
        .await
        .map(Response::into_inner)
    }

    fn rate_ec(rate: f32) -> Vec<ExtendedCommunity> {
        vec![
            flowspec_action_to_ec(&flowspec_rate(rate))
                .unwrap()
                .unwrap(),
        ]
    }

    async fn list_local_flowspec(
        rib: &crate::rib_service::RibService,
    ) -> proto::ListFlowSpecResponse {
        use proto::rib_service_server::RibService as _;
        rib.list_flow_spec_routes(Request::new(proto::ListFlowSpecRequest {
            afi_safi: 0,
            received_peer_address: "0.0.0.0".into(),
            advertised_peer_address: String::new(),
        }))
        .await
        .unwrap()
        .into_inner()
    }

    /// Delete present, missing by default, missing with `allow_missing`, and
    /// present with `allow_missing`; leaves no local rule behind.
    async fn assert_delete_outcomes(svc: &InjectionService) {
        assert_eq!(
            delete_rule(svc, false).await.unwrap().outcome(),
            proto::FlowSpecDeleteOutcome::Deleted
        );
        assert_eq!(
            delete_rule(svc, false).await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            delete_rule(svc, true).await.unwrap().outcome(),
            proto::FlowSpecDeleteOutcome::NotPresent
        );
        assert_eq!(
            add_rate(svc, 0.0).await,
            proto::FlowSpecInjectOutcome::Created
        );
        assert_eq!(
            delete_rule(svc, true).await.unwrap().outcome(),
            proto::FlowSpecDeleteOutcome::Deleted
        );
    }

    /// The controller contract against a real RIB: add reports created /
    /// replaced / unchanged from the local Adj-RIB-In, a received rule that
    /// out-selects the local one does not mask a real replacement, the
    /// 0.0.0.0 received view lists exactly the injected rules, and a missing
    /// delete is `NOT_FOUND` unless `allow_missing` is set.
    #[tokio::test]
    async fn flowspec_injection_reports_local_outcomes_and_reconciles() {
        use proto::rib_service_server::RibService as _;

        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(
            rib_tx.clone(),
            AccessMode::ReadWrite,
            Arc::new(InjectionLeases::new()),
        );
        let rib = crate::rib_service::RibService::new(rib_tx.clone());

        assert_eq!(
            add_rate(&svc, 0.0).await,
            proto::FlowSpecInjectOutcome::Created
        );
        assert_eq!(
            add_rate(&svc, 0.0).await,
            proto::FlowSpecInjectOutcome::Unchanged
        );
        assert_eq!(
            add_rate(&svc, 1000.0).await,
            proto::FlowSpecInjectOutcome::Replaced
        );

        // A received rule with the same key and a higher LOCAL_PREF now owns
        // Loc-RIB, so a local replacement no longer changes selection.
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let components = parse_flowspec_components(&flowspec_rule_components(), Afi::Ipv4)
            .expect("valid test rule");
        rib_tx
            .send(RibUpdate::RoutesReceived {
                session_id: 0,
                peer: source,
                announced: vec![],
                withdrawn: vec![],
                flowspec_announced: vec![FlowSpecRoute {
                    rule: FlowSpecRule { components },
                    afi: Afi::Ipv4,
                    peer: source,
                    attributes: vec![
                        PathAttribute::Origin(Origin::Igp),
                        PathAttribute::AsPath(AsPath { segments: vec![] }),
                        PathAttribute::LocalPref(200),
                        PathAttribute::ExtendedCommunities(rate_ec(5000.0)),
                    ],
                    received_at: std::time::Instant::now(),
                    origin_type: RouteOrigin::Ibgp,
                    peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
                    is_stale: false,
                    is_llgr_stale: false,
                    path_id: 0,
                }],
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
                validated_with: None,
            })
            .await
            .unwrap();
        assert_eq!(
            add_rate(&svc, 2000.0).await,
            proto::FlowSpecInjectOutcome::Replaced
        );
        assert_eq!(
            add_rate(&svc, 2000.0).await,
            proto::FlowSpecInjectOutcome::Unchanged
        );

        let selected = rib
            .list_flow_spec_routes(Request::new(proto::ListFlowSpecRequest::default()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(selected.routes.len(), 1);
        assert_eq!(selected.routes[0].peer_address, source.to_string());
        assert_eq!(selected.routes[0].actions, vec![flowspec_rate(5000.0)]);

        let local = list_local_flowspec(&rib).await;
        assert!(local.received_view);
        assert_eq!(local.received_routes.len(), 1, "{local:?}");
        let row = &local.received_routes[0];
        assert!(!row.selected, "the received rule out-selects the local one");
        let route = row.route.as_ref().unwrap();
        assert_eq!(route.peer_address, "0.0.0.0");
        assert_eq!(route.actions, vec![flowspec_rate(2000.0)]);
        assert_eq!(
            row.validation,
            proto::FlowSpecValidationStatus::Disabled as i32
        );

        assert_delete_outcomes(&svc).await;
        let local = list_local_flowspec(&rib).await;
        assert!(local.received_view);
        assert_eq!(local.received_routes.len(), 0);

        drop((svc, rib, rib_tx));
        manager_task.await.unwrap();
    }

    /// With receive-side validation enabled, the reconciliation read reports
    /// every injected rule as LOCAL, complete and not pending, whatever its
    /// shape: a rule with no covering unicast route and a rule with no
    /// destination (both infeasible for a received candidate) are trusted
    /// local origination.
    #[tokio::test]
    async fn flowspec_reconciliation_reports_local_when_validation_enabled() {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        )
        .with_flowspec_validation(65000);
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(
            rib_tx.clone(),
            AccessMode::ReadWrite,
            Arc::new(InjectionLeases::new()),
        );
        let rib = crate::rib_service::RibService::new(rib_tx.clone());

        assert_eq!(
            add_rate(&svc, 0.0).await,
            proto::FlowSpecInjectOutcome::Created
        );
        let destinationless = svc
            .add_flow_spec(Request::new(proto::AddFlowSpecRequest {
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                components: vec![proto::FlowSpecComponent {
                    r#type: 3,
                    prefix: String::new(),
                    value: "=17".into(),
                    offset: 0,
                }],
                actions: vec![flowspec_rate(0.0)],
                communities: vec![],
                extended_communities: vec![],
            }))
            .await
            .expect("add accepted")
            .into_inner();
        assert_eq!(
            destinationless.outcome(),
            proto::FlowSpecInjectOutcome::Created
        );

        let local = list_local_flowspec(&rib).await;
        assert!(local.received_view);
        assert_eq!(local.received_routes.len(), 2, "{local:?}");
        for row in &local.received_routes {
            assert_eq!(
                row.validation,
                proto::FlowSpecValidationStatus::Local as i32,
                "{row:?}"
            );
            assert!(row.reason.is_empty(), "{row:?}");
            assert!(!row.pending, "{row:?}");
            assert!(row.selected, "{row:?}");
            assert_eq!(row.route.as_ref().unwrap().peer_address, "0.0.0.0");
        }

        drop((svc, rib, rib_tx));
        manager_task.await.unwrap();
    }

    fn flowspec_redirect(route_target: &str) -> proto::FlowSpecAction {
        proto::FlowSpecAction {
            action: Some(proto::flow_spec_action::Action::Redirect(
                proto::FlowSpecRedirect {
                    route_target: route_target.into(),
                },
            )),
        }
    }

    fn redirect_action(route_target: &str) -> Result<FlowSpecAction, Status> {
        Ok(flowspec_action_to_ec(&flowspec_redirect(route_target))?
            .unwrap()
            .as_flowspec_action()
            .expect("a redirect community"))
    }

    /// Each RFC 8955 §7.4 / RFC 7674 redirect form, at its field bounds. An
    /// ASN above 65535 selects the 4-octet form instead of truncating into
    /// the 2-octet one; asdot selects the 4-octet form for a 16-bit ASN.
    #[test]
    fn redirect_route_target_selects_each_form() {
        let ipv4 = Ipv4Addr::new(192, 0, 2, 1);
        for (route_target, expected) in [
            (
                "65535:4294967295",
                FlowSpecAction::Redirect2Octet {
                    asn: 65535,
                    value: u32::MAX,
                },
            ),
            ("0:0", FlowSpecAction::Redirect2Octet { asn: 0, value: 0 }),
            (
                "192.0.2.1:65535",
                FlowSpecAction::RedirectIpv4 {
                    addr: ipv4,
                    value: 65535,
                },
            ),
            (
                "65536:7",
                FlowSpecAction::Redirect4Octet {
                    asn: 65536,
                    value: 7,
                },
            ),
            (
                "4294967295:65535",
                FlowSpecAction::Redirect4Octet {
                    asn: u32::MAX,
                    value: 65535,
                },
            ),
            (
                "0.65001:100",
                FlowSpecAction::Redirect4Octet {
                    asn: 65001,
                    value: 100,
                },
            ),
            (
                "1.10:5",
                FlowSpecAction::Redirect4Octet {
                    asn: 65546,
                    value: 5,
                },
            ),
        ] {
            assert_eq!(
                redirect_action(route_target).unwrap(),
                expected,
                "{route_target}"
            );
        }
    }

    #[test]
    fn redirect_route_target_rejects_malformed_forms() {
        for route_target in [
            "",
            "65001",
            ":100",
            "65001:",
            "asn:100",
            "-1:100",
            "65001:4294967296",
            "4294967296:1",
            "65536:65536",
            "192.0.2.1:65536",
            "192.0.2.256:1",
            "192.0.2:1",
            "0.65536:1",
            "65536.0:1",
            "0.1:65536",
            "1.:1",
            ".1:1",
            "65001:100:1",
        ] {
            let err = redirect_action(route_target).unwrap_err();
            assert_eq!(err.code(), tonic::Code::InvalidArgument, "{route_target}");
        }
    }

    /// Every typed action form survives `AddFlowSpec` → `ListFlowSpecRoutes`
    /// unchanged, and each action community is also echoed raw.
    #[tokio::test]
    async fn flowspec_typed_actions_round_trip_through_injection() {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(
            rib_tx.clone(),
            AccessMode::ReadWrite,
            Arc::new(InjectionLeases::new()),
        );
        let rib = crate::rib_service::RibService::new(rib_tx.clone());

        let actions = vec![
            proto::FlowSpecAction {
                action: Some(proto::flow_spec_action::Action::TrafficRatePackets(
                    proto::FlowSpecTrafficRatePackets { rate: 500.0 },
                )),
            },
            flowspec_redirect("65001:100"),
            flowspec_redirect("192.0.2.1:200"),
            flowspec_redirect("4200000000:300"),
            flowspec_redirect("0.65001:400"),
        ];
        svc.add_flow_spec(Request::new(proto::AddFlowSpecRequest {
            afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
            components: flowspec_rule_components(),
            actions: actions.clone(),
            communities: vec![],
            extended_communities: vec![],
        }))
        .await
        .expect("add accepted");

        let local = list_local_flowspec(&rib).await;
        assert_eq!(local.received_routes.len(), 1, "{local:?}");
        let route = local.received_routes[0].route.as_ref().unwrap();
        assert_eq!(route.actions, actions);
        let raw: Vec<u64> = actions
            .iter()
            .map(|action| flowspec_action_to_ec(action).unwrap().unwrap().as_u64())
            .collect();
        assert_eq!(route.extended_communities, raw);

        drop((svc, rib, rib_tx));
        manager_task.await.unwrap();
    }

    async fn add_unicast(
        svc: &InjectionService,
        next_hop: &str,
        communities: Vec<u32>,
    ) -> proto::PathInjectOutcome {
        svc.add_path(Request::new(proto::AddPathRequest {
            prefix: "203.0.113.0".into(),
            prefix_length: 24,
            next_hop: next_hop.into(),
            communities,
            ..Default::default()
        }))
        .await
        .expect("add accepted")
        .into_inner()
        .outcome()
    }

    async fn delete_unicast(
        svc: &InjectionService,
        allow_missing: bool,
    ) -> Result<proto::PathDeleteOutcome, Status> {
        svc.delete_path(Request::new(proto::DeletePathRequest {
            prefix: "203.0.113.0".into(),
            prefix_length: 24,
            path_id: 0,
            allow_missing,
            owner: String::new(),
            override_owner: false,
        }))
        .await
        .map(|response| response.into_inner().outcome())
    }

    /// The unicast controller contract against a real RIB: add reports
    /// created / replaced / unchanged, an unspecified next hop is a distinct
    /// payload from a specific one, and a missing delete is `NOT_FOUND`
    /// unless `allow_missing` is set.
    #[tokio::test]
    async fn unicast_injection_reports_local_outcomes() {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(
            rib_tx.clone(),
            AccessMode::ReadWrite,
            Arc::new(InjectionLeases::new()),
        );

        assert_eq!(
            add_unicast(&svc, "0.0.0.0", vec![1]).await,
            proto::PathInjectOutcome::Created
        );
        assert_eq!(
            add_unicast(&svc, "::", vec![1]).await,
            proto::PathInjectOutcome::Unchanged,
            "both unspecified forms are the same next-hop-self route"
        );
        assert_eq!(
            add_unicast(&svc, "0.0.0.0", vec![2]).await,
            proto::PathInjectOutcome::Replaced
        );
        assert_eq!(
            add_unicast(&svc, "192.0.2.1", vec![2]).await,
            proto::PathInjectOutcome::Replaced
        );

        assert_eq!(
            delete_unicast(&svc, false).await.unwrap(),
            proto::PathDeleteOutcome::Deleted
        );
        assert_eq!(
            delete_unicast(&svc, false).await.unwrap_err().code(),
            tonic::Code::NotFound
        );
        assert_eq!(
            delete_unicast(&svc, true).await.unwrap(),
            proto::PathDeleteOutcome::NotPresent
        );
        assert_eq!(
            add_unicast(&svc, "0.0.0.0", vec![]).await,
            proto::PathInjectOutcome::Created
        );
        assert_eq!(
            delete_unicast(&svc, true).await.unwrap(),
            proto::PathDeleteOutcome::Deleted
        );

        drop((svc, rib_tx));
        manager_task.await.unwrap();
    }

    /// `ListLeasedKeys` maps an owner's unicast and `FlowSpec` keys to the
    /// keys `DeletePath` and `DeleteFlowSpec` take, with the generation the
    /// leased adds returned; its token resumes after the last key; a bad
    /// owner or token is `INVALID_ARGUMENT`. Served on read-only listeners.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one controller session: add, page, resume, delete the listed keys and reject bad input"
    )]
    async fn list_leased_keys_returns_delete_keys_and_resumes_by_token() {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let leases = manager.injection_leases();
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(rib_tx.clone(), AccessMode::ReadWrite, Arc::clone(&leases));
        let generation = svc
            .add_leased_path(Request::new(leased_path("ctl", 30)))
            .await
            .unwrap()
            .into_inner()
            .generation;
        svc.add_leased_flow_spec(Request::new(proto::AddLeasedFlowSpecRequest {
            rule: Some(proto::AddFlowSpecRequest {
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                components: flowspec_rule_components(),
                actions: vec![flowspec_rate(0.0)],
                communities: vec![],
                extended_communities: vec![],
            }),
            lease: Some(proto::InjectionLease {
                owner: "ctl".into(),
                lease_seconds: 30,
            }),
        }))
        .await
        .unwrap();
        let reader =
            InjectionService::new(rib_tx.clone(), AccessMode::ReadOnly, Arc::clone(&leases));
        let list = |page_token: String, owner: &str| {
            reader.list_leased_keys(Request::new(proto::ListLeasedKeysRequest {
                owner: owner.into(),
                page_size: 1,
                page_token,
            }))
        };

        let first = list(String::new(), "ctl").await.unwrap().into_inner();
        assert_eq!(first.keys.len(), 1);
        assert_eq!(
            first.keys[0].key,
            Some(proto::leased_key::Key::Path(proto::LeasedPathKey {
                prefix: "198.51.100.7".into(),
                prefix_length: 32,
                path_id: 0,
            }))
        );
        assert_eq!(first.keys[0].generation, generation);
        assert!((25_000..=30_000).contains(&first.keys[0].lease_remaining_ms));
        assert!(first.next_page_token.contains(":u:198.51.100.7/32:0"));
        assert_eq!(first.generation, generation, "the walk's generation");

        // The token is bound to the owner whose walk produced it.
        assert_eq!(
            list(first.next_page_token.clone(), "other")
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
        let second = list(first.next_page_token, "ctl")
            .await
            .unwrap()
            .into_inner();
        let Some(proto::leased_key::Key::FlowSpec(rule)) = second.keys[0].key.clone() else {
            panic!("the second key is the FlowSpec rule");
        };
        assert_eq!(rule.afi_safi, proto::AddressFamily::Ipv4Flowspec as i32);
        assert_eq!(second.keys[0].generation, generation);
        assert_eq!(second.next_page_token, "");

        // The listed keys are exactly what the deletes take.
        let Some(proto::leased_key::Key::Path(path)) = first.keys[0].key.clone() else {
            panic!("the first key is the path");
        };
        svc.delete_path(Request::new(proto::DeletePathRequest {
            prefix: path.prefix,
            prefix_length: path.prefix_length,
            path_id: path.path_id,
            owner: "ctl".into(),
            ..Default::default()
        }))
        .await
        .unwrap();
        svc.delete_flow_spec(Request::new(proto::DeleteFlowSpecRequest {
            afi_safi: rule.afi_safi,
            components: rule.components,
            owner: "ctl".into(),
            ..Default::default()
        }))
        .await
        .unwrap();
        assert_eq!(
            list(String::new(), "ctl").await.unwrap().into_inner().keys,
            []
        );

        for (token, owner) in [
            ("u:198.51.100.7/32:0", "ctl"),
            ("t1:ctl:1:w1:u:198.51.100.7/33:0", "ctl"),
            ("t1:ctl:1:-:u:198.51.100.7/32:0", "ctl"),
            ("t1:ctl:1:x:u:198.51.100.7/32:0", "ctl"),
            ("t1:ctl:1:w1:f:1:abc", "ctl"),
            ("t1:ctl:1:w1:f:65535:", "ctl"),
            ("t1:ctl:1:w1:f:1:", "ctl"),
            ("t1:ctl:1:w1:f:1:030481", "ctl"),
            (&*format!("t1:ctl:1:w1:f:1:{}", "00".repeat(4098)), "ctl"),
            ("x", "ctl"),
            ("", ""),
            ("", "bad owner"),
        ] {
            let error = list(token.into(), owner).await.unwrap_err();
            assert_eq!(
                error.code(),
                tonic::Code::InvalidArgument,
                "{token:?} {owner:?}"
            );
        }
        let other = list(String::new(), "other").await.unwrap().into_inner();
        assert_eq!(other.keys, []);
        assert_eq!(other.next_page_token, "");
        assert_eq!(
            other.generation, None,
            "no lease: the walk has no generation"
        );

        drop((svc, reader));
        drop(rib_tx);
        manager_task.await.unwrap();
    }

    /// Leased rules using the not-equal operators list as keys that
    /// `DeleteFlowSpec` accepts unchanged: add, list, delete as listed.
    #[tokio::test]
    async fn listed_not_equal_flowspec_keys_delete_as_listed() {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let leases = manager.injection_leases();
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(rib_tx.clone(), AccessMode::ReadWrite, Arc::clone(&leases));
        for (octet, port) in [(1, "<>80"), (2, "<>=80")] {
            svc.add_leased_flow_spec(Request::new(proto::AddLeasedFlowSpecRequest {
                rule: Some(proto::AddFlowSpecRequest {
                    afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                    components: vec![
                        proto::FlowSpecComponent {
                            r#type: 1,
                            prefix: format!("203.0.113.{octet}/32"),
                            value: String::new(),
                            offset: 0,
                        },
                        proto::FlowSpecComponent {
                            r#type: 4,
                            prefix: String::new(),
                            value: port.into(),
                            offset: 0,
                        },
                    ],
                    actions: vec![flowspec_rate(0.0)],
                    communities: vec![],
                    extended_communities: vec![],
                }),
                lease: Some(proto::InjectionLease {
                    owner: "ctl".into(),
                    lease_seconds: 30,
                }),
            }))
            .await
            .unwrap();
        }
        let list = || {
            svc.list_leased_keys(Request::new(proto::ListLeasedKeysRequest {
                owner: "ctl".into(),
                ..Default::default()
            }))
        };
        let listed = list().await.unwrap().into_inner().keys;
        assert_eq!(listed.len(), 2);
        // A FlowSpec cursor resumes: one rule per page, then the other.
        let first = svc
            .list_leased_keys(Request::new(proto::ListLeasedKeysRequest {
                owner: "ctl".into(),
                page_size: 1,
                page_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(first.next_page_token.contains(":f:1:"));
        let rest = svc
            .list_leased_keys(Request::new(proto::ListLeasedKeysRequest {
                owner: "ctl".into(),
                page_size: 1,
                page_token: first.next_page_token,
            }))
            .await
            .unwrap()
            .into_inner();
        // Compare the keys: lease_remaining_ms moves between reads.
        let keys =
            |rows: &[proto::LeasedKey]| rows.iter().map(|row| row.key.clone()).collect::<Vec<_>>();
        assert_eq!(
            keys(&[first.keys, rest.keys].concat()),
            keys(&listed),
            "two pages hold both rules in order"
        );
        for key in listed {
            let Some(proto::leased_key::Key::FlowSpec(rule)) = key.key else {
                panic!("a FlowSpec key");
            };
            svc.delete_flow_spec(Request::new(proto::DeleteFlowSpecRequest {
                afi_safi: rule.afi_safi,
                components: rule.components.clone(),
                owner: "ctl".into(),
                ..Default::default()
            }))
            .await
            .unwrap_or_else(|error| panic!("{:?}: {error}", rule.components));
        }
        assert_eq!(list().await.unwrap().into_inner().keys, []);
        drop(svc);
        drop(rib_tx);
        manager_task.await.unwrap();
    }

    /// A page token from a previous daemon process is never accepted: the
    /// restarted daemon answers `ABORTED`, never an empty page that would
    /// read as "this owner holds nothing more".
    #[tokio::test]
    async fn a_leased_key_token_from_a_previous_process_is_aborted() {
        fn daemon() -> (
            InjectionService,
            mpsc::Sender<RibUpdate>,
            tokio::task::JoinHandle<()>,
        ) {
            let (rib_tx, rib_rx) = mpsc::channel(64);
            let manager = rustbgpd_rib::RibManager::new(
                rib_rx,
                mpsc::channel(1).1,
                None,
                None,
                rustbgpd_telemetry::BgpMetrics::new(),
            );
            let leases = manager.injection_leases();
            let task = tokio::spawn(manager.run());
            (
                InjectionService::new(rib_tx.clone(), AccessMode::ReadWrite, Arc::clone(&leases)),
                rib_tx,
                task,
            )
        }
        fn request(page_token: String) -> Request<proto::ListLeasedKeysRequest> {
            Request::new(proto::ListLeasedKeysRequest {
                owner: "ctl".into(),
                page_size: 1,
                page_token,
            })
        }

        let (before, before_tx, before_task) = daemon();
        for octet in [7, 8] {
            let mut request = leased_path("ctl", 30);
            request.path.as_mut().unwrap().prefix = format!("198.51.100.{octet}");
            before.add_leased_path(Request::new(request)).await.unwrap();
        }
        let first = before
            .list_leased_keys(request(String::new()))
            .await
            .unwrap()
            .into_inner();
        assert!(first.next_page_token.starts_with("t1:"));
        drop((before, before_tx));
        before_task.await.unwrap();

        let (after, after_tx, after_task) = daemon();
        let error = after
            .list_leased_keys(request(first.next_page_token))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Aborted);
        assert_eq!(
            error_info_reason(&error, tonic::Code::Aborted),
            WALK_INVALIDATED
        );
        drop((after, after_tx));
        after_task.await.unwrap();
    }

    fn leased_path(owner: &str, lease_seconds: u32) -> proto::AddLeasedPathRequest {
        proto::AddLeasedPathRequest {
            path: Some(proto::AddPathRequest {
                prefix: "198.51.100.7".into(),
                prefix_length: 32,
                next_hop: "0.0.0.0".into(),
                communities: vec![0xFFFF_029A],
                ..Default::default()
            }),
            lease: Some(proto::InjectionLease {
                owner: owner.into(),
                lease_seconds,
            }),
        }
    }

    /// ADR-0141 §3: a leased add creates leased state or no state. Both
    /// leased adds reach the RIB as owned intent, never as a permanent
    /// `InjectRoute` or `InjectFlowSpec`. A leased method the server does not
    /// serve, as on a daemon that predates leases, answers `UNIMPLEMENTED`
    /// from the generated service's fallback before any handler or RIB work.
    ///
    /// Break-to-red: a leased add forwarded as a plain injection fails the
    /// owned-intent match.
    #[tokio::test]
    async fn leased_adds_never_fall_back_to_permanent_injection() {
        use tower::ServiceExt as _;

        let (tx, mut rx) = mpsc::channel(4);
        let svc = Arc::new(InjectionService::new(
            tx.clone(),
            AccessMode::ReadWrite,
            Arc::new(InjectionLeases::new()),
        ));
        let path = tokio::spawn({
            let svc = Arc::clone(&svc);
            async move {
                svc.add_leased_path(Request::new(leased_path("ctl", 30)))
                    .await
            }
        });
        let RibUpdate::InjectLeasedRoute {
            owner,
            lease_seconds,
            ..
        } = rx.recv().await.unwrap()
        else {
            panic!("a leased path add must reach the RIB as owned intent");
        };
        assert_eq!((owner.as_str(), lease_seconds), ("ctl", 30));
        assert_eq!(
            path.await.unwrap().unwrap_err().code(),
            tonic::Code::Internal
        );
        let rule = tokio::spawn({
            let svc = Arc::clone(&svc);
            async move {
                svc.add_leased_flow_spec(Request::new(proto::AddLeasedFlowSpecRequest {
                    rule: Some(proto::AddFlowSpecRequest {
                        afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                        components: flowspec_rule_components(),
                        actions: vec![flowspec_rate(0.0)],
                        communities: vec![],
                        extended_communities: vec![],
                    }),
                    lease: Some(proto::InjectionLease {
                        owner: "ctl".into(),
                        lease_seconds: 30,
                    }),
                }))
                .await
            }
        });
        let RibUpdate::InjectLeasedFlowSpec { owner, .. } = rx.recv().await.unwrap() else {
            panic!("a leased FlowSpec add must reach the RIB as owned intent");
        };
        assert_eq!(owner, "ctl");
        assert_eq!(
            rule.await.unwrap().unwrap_err().code(),
            tonic::Code::Internal
        );

        let server = proto::injection_service_server::InjectionServiceServer::new(
            InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new())),
        );
        let request = tonic::codegen::http::Request::builder()
            .method("POST")
            .uri("/rustbgpd.v1.InjectionService/AddLeasedRoute")
            .header("content-type", "application/grpc")
            .body(tonic::body::Body::empty())
            .unwrap();
        let response = server.oneshot(request).await.unwrap();
        assert_eq!(
            response
                .headers()
                .get("grpc-status")
                .map(tonic::codegen::http::HeaderValue::as_bytes),
            Some(&b"12"[..]),
            "an unserved method is UNIMPLEMENTED"
        );
        assert!(rx.try_recv().is_err(), "nothing reached the RIB");
    }

    /// Malformed leases are `INVALID_ARGUMENT` before anything reaches the
    /// RIB: no lease, a bad owner, and a duration outside 5..=3600.
    #[tokio::test]
    async fn leased_add_validation_rejects_before_the_rib() {
        let (svc, mut rx) = make_service_with_rx();
        let mut missing = leased_path("ctl", 30);
        missing.lease = None;
        for (request, field) in [
            (missing, "lease"),
            (leased_path("", 30), "owner"),
            (leased_path(&"x".repeat(65), 30), "owner"),
            (leased_path("ctl/a", 30), "owner"),
            (leased_path("ctl", 0), "lease_seconds"),
            (leased_path("ctl", 4), "lease_seconds"),
            (leased_path("ctl", 3601), "lease_seconds"),
        ] {
            // Bounded: a request that wrongly passes validation waits for a
            // RIB reply that never comes.
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                svc.add_leased_path(Request::new(request)),
            )
            .await
            .unwrap_or_else(|_| panic!("{field}: reached the RIB"))
            .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument, "{field}");
            assert!(error.message().contains(field), "{}", error.message());
        }
        let error = svc
            .renew_lease(Request::new(proto::RenewLeaseRequest {
                owner: "ctl".into(),
                generation: Some(proto::LeaseGeneration::default()),
                lease_seconds: 0,
            }))
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert!(matches!(
            rx.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Empty)
        ));
    }

    /// A service built from the RIB manager's lease table renews and lists
    /// the leases its own leased adds create: there is no configuration in
    /// which a leased add succeeds but its renewal is unavailable.
    ///
    /// Break-to-red: a constructor that keeps its own table instead of the
    /// one it is given refuses the renewal with `FAILED_PRECONDITION`.
    #[tokio::test]
    async fn a_service_renews_the_leases_its_adds_create() {
        let (rib_tx, rib_rx) = mpsc::channel(16);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let svc = InjectionService::new(
            rib_tx.clone(),
            AccessMode::ReadWrite,
            manager.injection_leases(),
        );
        let manager_task = tokio::spawn(manager.run());
        let generation = svc
            .add_leased_path(Request::new(leased_path("ctl", 30)))
            .await
            .unwrap()
            .into_inner()
            .generation;
        let renewed = svc
            .renew_lease(Request::new(proto::RenewLeaseRequest {
                owner: "ctl".into(),
                generation,
                lease_seconds: 30,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(renewed.generation, generation);
        let listed = svc
            .list_injection_leases(Request::new(proto::ListInjectionLeasesRequest::default()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            listed
                .leases
                .iter()
                .map(|row| row.owner.as_str())
                .collect::<Vec<_>>(),
            ["ctl"]
        );
        drop(svc);
        drop(rib_tx);
        manager_task.await.unwrap();
    }

    /// Renewal and listing are served from the lease table and never wait
    /// behind the RIB: they complete with the RIB channel full and unread.
    #[tokio::test]
    async fn renewal_never_waits_behind_the_rib() {
        let (tx, _rx) = mpsc::channel(1);
        tx.try_send(RibUpdate::ExpireInjectionLeases { leases: vec![] })
            .unwrap();
        let leases = Arc::new(InjectionLeases::new());
        let generation = leases.admit("ctl", 30).unwrap().generation;
        let svc = InjectionService::new(tx, AccessMode::ReadWrite, Arc::clone(&leases));
        let renewed = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            svc.renew_lease(Request::new(proto::RenewLeaseRequest {
                owner: "ctl".into(),
                generation: Some(generation_to_proto(generation)),
                lease_seconds: 10,
            })),
        )
        .await
        .expect("renewal does not wait for the RIB")
        .unwrap();
        assert_eq!(renewed.into_inner().lease_remaining_ms, 10_000);
    }

    /// Leased adds of both families and `RenewLease` record the owner and the
    /// generation they ended with in the audit summary; a refused renewal
    /// records the owner and the generation it asked for.
    ///
    /// Break-to-red: an add that records only the requested owner loses the
    /// generation.
    #[tokio::test]
    async fn leased_add_and_renew_audits_name_owner_and_generation() {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let leases = manager.injection_leases();
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(rib_tx.clone(), AccessMode::ReadWrite, Arc::clone(&leases));
        let audited = |audit: &GrpcAuditHandle| {
            audit
                .summary()
                .map(|summary| summary.as_str().to_string())
                .unwrap_or_default()
        };
        let with_audit = |message| {
            let audit = GrpcAuditHandle::default();
            let mut request = Request::new(message);
            request.extensions_mut().insert(audit.clone());
            (request, audit)
        };

        let (request, audit) = with_audit(leased_path("ctl", 30));
        let generation = svc
            .add_leased_path(request)
            .await
            .unwrap()
            .into_inner()
            .generation
            .unwrap();
        let expected = format!(
            "owner=ctl generation={}:{}",
            generation.incarnation, generation.sequence
        );
        assert_eq!(audited(&audit), expected);

        let audit = GrpcAuditHandle::default();
        let mut request = Request::new(proto::AddLeasedFlowSpecRequest {
            rule: Some(proto::AddFlowSpecRequest {
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                components: flowspec_rule_components(),
                actions: vec![flowspec_rate(0.0)],
                communities: vec![],
                extended_communities: vec![],
            }),
            lease: Some(proto::InjectionLease {
                owner: "ctl".into(),
                lease_seconds: 30,
            }),
        });
        request.extensions_mut().insert(audit.clone());
        svc.add_leased_flow_spec(request).await.unwrap();
        assert_eq!(audited(&audit), expected);

        let renew = |generation| proto::RenewLeaseRequest {
            owner: "ctl".into(),
            generation: Some(generation),
            lease_seconds: 30,
        };
        let audit = GrpcAuditHandle::default();
        let mut request = Request::new(renew(generation));
        request.extensions_mut().insert(audit.clone());
        svc.renew_lease(request).await.unwrap();
        assert_eq!(audited(&audit), expected);

        let stale = proto::LeaseGeneration {
            sequence: generation.sequence + 1,
            ..generation
        };
        let audit = GrpcAuditHandle::default();
        let mut request = Request::new(renew(stale));
        request.extensions_mut().insert(audit.clone());
        assert_eq!(
            svc.renew_lease(request).await.unwrap_err().code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            audited(&audit),
            format!(
                "owner=ctl generation={}:{}",
                stale.incarnation, stale.sequence
            )
        );

        drop((svc, rib_tx));
        manager_task.await.unwrap();
    }

    /// A delete's audit names the owner and generation the removed entry held,
    /// for both families: an override with no requested owner names the
    /// owner it bypassed, and an override with a different requested owner
    /// keeps that as `requested_owner` beside the real one.
    ///
    /// Break-to-red: building the summary from the request logs `owner=`
    /// and `owner=other`.
    #[tokio::test]
    async fn delete_audit_names_the_removed_entry_owner() {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(
            rib_tx.clone(),
            AccessMode::ReadWrite,
            Arc::new(InjectionLeases::new()),
        );
        let generation = svc
            .add_leased_path(Request::new(leased_path("ctl", 30)))
            .await
            .unwrap()
            .into_inner()
            .generation
            .unwrap();
        svc.add_leased_flow_spec(Request::new(proto::AddLeasedFlowSpecRequest {
            rule: Some(proto::AddFlowSpecRequest {
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                components: flowspec_rule_components(),
                actions: vec![flowspec_rate(0.0)],
                communities: vec![],
                extended_communities: vec![],
            }),
            lease: Some(proto::InjectionLease {
                owner: "ctl".into(),
                lease_seconds: 30,
            }),
        }))
        .await
        .unwrap();
        let held = format!(
            "owner=ctl generation={}:{} override_owner=true",
            generation.incarnation, generation.sequence
        );
        let audited = |audit: &GrpcAuditHandle| {
            audit
                .summary()
                .map(|summary| summary.as_str().to_string())
                .unwrap_or_default()
        };

        let audit = GrpcAuditHandle::default();
        let mut request = Request::new(proto::DeletePathRequest {
            prefix: "198.51.100.7".into(),
            prefix_length: 32,
            path_id: 0,
            allow_missing: false,
            owner: String::new(),
            override_owner: true,
        });
        request.extensions_mut().insert(audit.clone());
        assert_eq!(
            svc.delete_path(request)
                .await
                .unwrap()
                .into_inner()
                .outcome(),
            proto::PathDeleteOutcome::Deleted
        );
        assert_eq!(audited(&audit), held);

        let audit = GrpcAuditHandle::default();
        let mut request = Request::new(proto::DeleteFlowSpecRequest {
            afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
            components: flowspec_rule_components(),
            allow_missing: false,
            owner: "other".into(),
            override_owner: true,
        });
        request.extensions_mut().insert(audit.clone());
        assert_eq!(
            svc.delete_flow_spec(request)
                .await
                .unwrap()
                .into_inner()
                .outcome(),
            proto::FlowSpecDeleteOutcome::Deleted
        );
        assert_eq!(audited(&audit), format!("{held} requested_owner=other"));

        drop((svc, rib_tx));
        manager_task.await.unwrap();
    }

    /// A lease with less than a millisecond left is listed as 1 ms, not 0,
    /// because it can still renew; 0 is reserved for a passed deadline.
    ///
    /// Break-to-red: truncating to whole milliseconds lists it as 0.
    #[tokio::test(start_paused = true)]
    async fn remaining_zero_means_the_renewal_is_refused() {
        let (rib_tx, _rib_rx) = mpsc::channel(1);
        let leases = Arc::new(InjectionLeases::new());
        let generation = leases.admit("ctl", 5).unwrap().generation;
        let svc = InjectionService::new(rib_tx, AccessMode::ReadWrite, Arc::clone(&leases));
        let listed = || async {
            svc.list_injection_leases(Request::new(proto::ListInjectionLeasesRequest::default()))
                .await
                .unwrap()
                .into_inner()
                .leases[0]
                .lease_remaining_ms
        };
        tokio::time::advance(
            std::time::Duration::from_secs(5) - std::time::Duration::from_micros(500),
        )
        .await;
        assert_eq!(listed().await, 1);
        assert_eq!(millis(std::time::Duration::ZERO), 0);
        tokio::time::advance(std::time::Duration::from_micros(500)).await;
        assert_eq!(listed().await, 0);
        let refused = svc
            .renew_lease(Request::new(proto::RenewLeaseRequest {
                owner: "ctl".into(),
                generation: Some(generation_to_proto(generation)),
                lease_seconds: 5,
            }))
            .await
            .unwrap_err();
        assert_eq!(lease_conflict_reason(&refused), "GENERATION_NOT_LIVE");
    }

    /// The `ErrorInfo` reason of a lease conflict, decoded from the status
    /// details exactly as a client reads the `grpc-status-details-bin`
    /// trailer.
    fn lease_conflict_reason(status: &Status) -> String {
        error_info_reason(status, tonic::Code::FailedPrecondition)
    }

    /// The `ErrorInfo` reason of a status with code `code`, decoded as a
    /// client reads it.
    fn error_info_reason(status: &Status, code: tonic::Code) -> String {
        use prost::Message as _;
        assert_eq!(status.code(), code, "{status:?}");
        let details = RpcStatus::decode(status.details()).expect("google.rpc.Status");
        assert_eq!(details.code, code as i32);
        let [any] = details.details.as_slice() else {
            panic!("one detail expected: {details:?}");
        };
        assert_eq!(any.type_url, "type.googleapis.com/google.rpc.ErrorInfo");
        let info = ErrorInfo::decode(any.value.as_slice()).expect("google.rpc.ErrorInfo");
        assert_eq!(info.domain, "rustbgpd");
        info.reason
    }

    /// `MarkReplayComplete` through a running RIB holding one grace window
    /// for two listed controllers: each outcome maps to its enum value, the
    /// partial signal lists who is still awaited, and a stale incarnation is
    /// `FAILED_PRECONDITION` with reason `INCARNATION_MISMATCH`.
    #[tokio::test]
    async fn mark_replay_complete_maps_every_outcome() {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        )
        .with_eor_grace(rustbgpd_rib::EorGraceConfig {
            peers: vec![rustbgpd_rib::EorGracePeerConfig {
                peer: "192.0.2.2".parse().unwrap(),
                deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(600),
                families: vec![(Afi::Ipv4, rustbgpd_wire::Safi::Unicast)],
            }],
            replay_owners: vec!["ctl-a".into(), "ctl-b".into()],
        });
        let leases = manager.injection_leases();
        let incarnation = leases.incarnation();
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(rib_tx.clone(), AccessMode::ReadWrite, leases);
        let mark = |owner: &str, incarnation: u64| {
            Request::new(proto::MarkReplayCompleteRequest {
                owner: owner.into(),
                incarnation,
            })
        };
        let outcome =
            |response: proto::MarkReplayCompleteResponse| (response.outcome(), response.awaiting);

        let response = svc
            .mark_replay_complete(mark("ctl-a", incarnation))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            outcome(response),
            (
                proto::ReplayCompleteOutcome::Recorded,
                vec!["ctl-b".to_string()]
            )
        );
        let stale = svc
            .mark_replay_complete(mark("ctl-b", incarnation ^ 1))
            .await
            .unwrap_err();
        assert_eq!(lease_conflict_reason(&stale), "INCARNATION_MISMATCH");
        let response = svc
            .mark_replay_complete(mark("unlisted", incarnation))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            outcome(response),
            (proto::ReplayCompleteOutcome::NotExpected, vec![])
        );
        let invalid = svc
            .mark_replay_complete(mark("bad owner", incarnation))
            .await
            .unwrap_err();
        assert_eq!(invalid.code(), tonic::Code::InvalidArgument);
        let response = svc
            .mark_replay_complete(mark("ctl-b", incarnation))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            outcome(response),
            (proto::ReplayCompleteOutcome::Released, vec![])
        );
        let response = svc
            .mark_replay_complete(mark("ctl-a", incarnation))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            outcome(response),
            (proto::ReplayCompleteOutcome::NotHolding, vec![])
        );

        let read_only = InjectionService::new(
            rib_tx.clone(),
            AccessMode::ReadOnly,
            Arc::new(InjectionLeases::new()),
        );
        assert!(
            read_only
                .mark_replay_complete(mark("ctl-a", incarnation))
                .await
                .is_err()
        );
        drop((svc, read_only, rib_tx));
        manager_task.await.unwrap();
    }

    /// Every lease-ownership refusal carries its `ErrorInfo` reason through
    /// the RIB-to-API boundary, on every RPC that can raise it:
    /// `OWNER_MISMATCH` for a key another owner holds, `KEY_UNOWNED` for a key
    /// no owner holds, and `GENERATION_NOT_LIVE` for a refused renewal.
    ///
    /// Break-to-red: mapping `KeyUnowned` to `OWNER_MISMATCH` fails the
    /// unowned cases.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one table of every lease conflict across the six mutating RPCs and renewal"
    )]
    async fn lease_conflicts_carry_a_machine_readable_reason() {
        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let leases = manager.injection_leases();
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(rib_tx.clone(), AccessMode::ReadWrite, leases);

        let lease = |owner: &str| {
            Some(proto::InjectionLease {
                owner: owner.into(),
                lease_seconds: 30,
            })
        };
        let owned_path = || leased_path("ctl", 30).path.unwrap();
        let unowned_path = || proto::AddPathRequest {
            prefix: "203.0.113.0".into(),
            prefix_length: 24,
            next_hop: "0.0.0.0".into(),
            ..Default::default()
        };
        let rule = |port: &str| {
            let mut components = flowspec_rule_components();
            components[1].value = port.into();
            proto::AddFlowSpecRequest {
                afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                components,
                actions: vec![flowspec_rate(0.0)],
                communities: vec![],
                extended_communities: vec![],
            }
        };
        let delete_path = |path: proto::AddPathRequest, owner: &str| proto::DeletePathRequest {
            prefix: path.prefix,
            prefix_length: path.prefix_length,
            path_id: 0,
            allow_missing: false,
            owner: owner.into(),
            override_owner: false,
        };
        let delete_rule = |port: &str, owner: &str| proto::DeleteFlowSpecRequest {
            afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
            components: rule(port).components,
            allow_missing: false,
            owner: owner.into(),
            override_owner: false,
        };

        // "ctl" owns a route and the =80 rule; the /24 and the =443 rule are
        // unowned.
        let generation = svc
            .add_leased_path(Request::new(leased_path("ctl", 30)))
            .await
            .unwrap()
            .into_inner()
            .generation;
        svc.add_leased_flow_spec(Request::new(proto::AddLeasedFlowSpecRequest {
            rule: Some(rule("=80")),
            lease: lease("ctl"),
        }))
        .await
        .unwrap();
        svc.add_path(Request::new(unowned_path())).await.unwrap();
        svc.add_flow_spec(Request::new(rule("=443"))).await.unwrap();

        let leased_path_add = |path, owner| {
            svc.add_leased_path(Request::new(proto::AddLeasedPathRequest {
                path: Some(path),
                lease: lease(owner),
            }))
        };
        let leased_rule_add = |port, owner| {
            svc.add_leased_flow_spec(Request::new(proto::AddLeasedFlowSpecRequest {
                rule: Some(rule(port)),
                lease: lease(owner),
            }))
        };
        let cases = [
            (
                "AddLeasedPath onto another owner's key",
                leased_path_add(owned_path(), "other").await.unwrap_err(),
                "OWNER_MISMATCH",
            ),
            (
                "AddLeasedPath onto an unowned key",
                leased_path_add(unowned_path(), "ctl").await.unwrap_err(),
                "KEY_UNOWNED",
            ),
            (
                "AddLeasedFlowSpec onto another owner's key",
                leased_rule_add("=80", "other").await.unwrap_err(),
                "OWNER_MISMATCH",
            ),
            (
                "AddLeasedFlowSpec onto an unowned key",
                leased_rule_add("=443", "ctl").await.unwrap_err(),
                "KEY_UNOWNED",
            ),
            (
                "AddPath onto an owned key",
                svc.add_path(Request::new(owned_path())).await.unwrap_err(),
                "OWNER_MISMATCH",
            ),
            (
                "AddFlowSpec onto an owned key",
                svc.add_flow_spec(Request::new(rule("=80")))
                    .await
                    .unwrap_err(),
                "OWNER_MISMATCH",
            ),
            (
                "DeletePath by the wrong owner",
                svc.delete_path(Request::new(delete_path(owned_path(), "")))
                    .await
                    .unwrap_err(),
                "OWNER_MISMATCH",
            ),
            (
                "DeletePath of an unowned key by an owner",
                svc.delete_path(Request::new(delete_path(unowned_path(), "ctl")))
                    .await
                    .unwrap_err(),
                "KEY_UNOWNED",
            ),
            (
                "DeleteFlowSpec by the wrong owner",
                svc.delete_flow_spec(Request::new(delete_rule("=80", "other")))
                    .await
                    .unwrap_err(),
                "OWNER_MISMATCH",
            ),
            (
                "DeleteFlowSpec of an unowned key by an owner",
                svc.delete_flow_spec(Request::new(delete_rule("=443", "ctl")))
                    .await
                    .unwrap_err(),
                "KEY_UNOWNED",
            ),
            (
                "RenewLease of a generation that is not live",
                svc.renew_lease(Request::new(proto::RenewLeaseRequest {
                    owner: "other".into(),
                    generation,
                    lease_seconds: 30,
                }))
                .await
                .unwrap_err(),
                "GENERATION_NOT_LIVE",
            ),
        ];
        for (case, status, reason) in &cases {
            assert_eq!(lease_conflict_reason(status), *reason, "{case}");
        }

        drop((svc, rib_tx));
        manager_task.await.unwrap();
    }

    /// The controller contract against a real RIB: a leased add returns the
    /// owner's generation, renewal of that generation succeeds and of any
    /// other is `FAILED_PRECONDITION`, the lease table lists it, and the
    /// local read-back carries owner, generation and remaining lease.
    #[tokio::test]
    #[expect(
        clippy::too_many_lines,
        reason = "one controller session: add, renew, stale renewals, list, read-back and delete"
    )]
    async fn leased_injection_renewal_and_read_back() {
        use proto::rib_service_server::RibService as _;

        let (rib_tx, rib_rx) = mpsc::channel(64);
        let manager = rustbgpd_rib::RibManager::new(
            rib_rx,
            mpsc::channel(1).1,
            None,
            None,
            rustbgpd_telemetry::BgpMetrics::new(),
        );
        let leases = manager.injection_leases();
        let manager_task = tokio::spawn(manager.run());
        let svc = InjectionService::new(rib_tx.clone(), AccessMode::ReadWrite, Arc::clone(&leases));
        let rib = crate::rib_service::RibService::new(rib_tx.clone())
            .with_injection_leases(Arc::clone(&leases));

        let added = svc
            .add_leased_path(Request::new(leased_path("ctl", 30)))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            added.result.unwrap().outcome(),
            proto::PathInjectOutcome::Created
        );
        let generation = added.generation.unwrap();
        assert_eq!(generation.incarnation, leases.incarnation());

        let renewed = svc
            .renew_lease(Request::new(proto::RenewLeaseRequest {
                owner: "ctl".into(),
                generation: Some(generation),
                lease_seconds: 60,
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(renewed.generation, Some(generation));
        assert_eq!(renewed.lease_remaining_ms, 60_000);

        for (owner, stale) in [
            (
                "ctl",
                proto::LeaseGeneration {
                    sequence: generation.sequence + 1,
                    ..generation
                },
            ),
            (
                "ctl",
                proto::LeaseGeneration {
                    incarnation: generation.incarnation ^ 1,
                    ..generation
                },
            ),
            ("other", generation),
        ] {
            let error = svc
                .renew_lease(Request::new(proto::RenewLeaseRequest {
                    owner: owner.into(),
                    generation: Some(stale),
                    lease_seconds: 60,
                }))
                .await
                .unwrap_err();
            assert_eq!(error.code(), tonic::Code::FailedPrecondition);
        }

        let listed = svc
            .list_injection_leases(Request::new(proto::ListInjectionLeasesRequest::default()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(listed.leases.len(), 1);
        assert_eq!(listed.leases[0].owner, "ctl");
        assert_eq!(listed.leases[0].lease_seconds, 60);

        let local = rib
            .list_received_routes(Request::new(proto::ListRoutesRequest {
                neighbor_address: "0.0.0.0".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(local.routes.len(), 1);
        let row = &local.routes[0];
        assert_eq!(row.injection_owner, "ctl");
        assert_eq!(row.lease_generation, Some(generation));
        assert!(
            row.lease_remaining_ms
                .is_some_and(|ms| ms > 0 && ms <= 60_000)
        );

        // A leased rule joins the owner's generation. The locally injected
        // view reports its lease; the selected view does not.
        let rule = svc
            .add_leased_flow_spec(Request::new(proto::AddLeasedFlowSpecRequest {
                rule: Some(proto::AddFlowSpecRequest {
                    afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
                    components: flowspec_rule_components(),
                    actions: vec![flowspec_rate(0.0)],
                    communities: vec![],
                    extended_communities: vec![],
                }),
                lease: Some(proto::InjectionLease {
                    owner: "ctl".into(),
                    lease_seconds: 30,
                }),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(rule.generation, Some(generation));
        let list_rules = |received: &str| proto::ListFlowSpecRequest {
            afi_safi: proto::AddressFamily::Ipv4Flowspec as i32,
            received_peer_address: received.into(),
            ..Default::default()
        };
        let local = rib
            .list_flow_spec_routes(Request::new(list_rules("0.0.0.0")))
            .await
            .unwrap()
            .into_inner();
        let entry = local.received_routes[0].route.as_ref().unwrap();
        assert_eq!(entry.injection_owner, "ctl");
        assert_eq!(entry.lease_generation, Some(generation));
        assert!(
            entry
                .lease_remaining_ms
                .is_some_and(|ms| ms > 0 && ms <= 60_000)
        );
        let selected = rib
            .list_flow_spec_routes(Request::new(list_rules("")))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(selected.routes.len(), 1);
        assert_eq!(selected.routes[0].injection_owner, "");
        assert_eq!(selected.routes[0].lease_remaining_ms, None);

        // An unowned delete of the owned route is refused; the owner's works.
        let delete = |owner: &str| proto::DeletePathRequest {
            prefix: "198.51.100.7".into(),
            prefix_length: 32,
            path_id: 0,
            allow_missing: false,
            owner: owner.into(),
            override_owner: false,
        };
        assert_eq!(
            svc.delete_path(Request::new(delete("")))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(
            svc.delete_path(Request::new(delete("ctl")))
                .await
                .unwrap()
                .into_inner()
                .outcome(),
            proto::PathDeleteOutcome::Deleted
        );

        drop((svc, rib, rib_tx));
        manager_task.await.unwrap();
    }
}
