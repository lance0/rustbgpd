//! gRPC injection service — `AddPath` / `DeletePath` / `AddFlowSpec` / `DeleteFlowSpec`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};

use crate::proto;
use crate::server::{AccessMode, read_only_rejection};
use rustbgpd_rib::{FlowSpecRoute, RibUpdate, Route, RouteOrigin};
use rustbgpd_wire::{
    Afi, AsPath, AsPathSegment, BitmaskMatch, ExtendedCommunity, FlowSpecComponent, FlowSpecPrefix,
    FlowSpecRule, Ipv4Prefix, Ipv6Prefix, Ipv6PrefixOffset, LargeCommunity, NumericMatch, Origin,
    PathAttribute, Prefix,
};

/// gRPC service for injecting and withdrawing locally-originated routes.
pub struct InjectionService {
    access_mode: AccessMode,
    rib_tx: mpsc::Sender<RibUpdate>,
}

impl InjectionService {
    /// Create a new injection service backed by the given RIB channel.
    pub fn new(rib_tx: mpsc::Sender<RibUpdate>, access_mode: AccessMode) -> Self {
        Self {
            access_mode,
            rib_tx,
        }
    }
}

/// Sentinel peer address for locally-injected routes.
const LOCAL_PEER: std::net::IpAddr = std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// Parse a prefix address + length + next-hop from a gRPC request.
#[expect(clippy::result_large_err)]
fn parse_prefix_and_nexthop(
    prefix_str: &str,
    prefix_length: u32,
    next_hop_str: &str,
) -> Result<(Prefix, IpAddr), Status> {
    let addr: IpAddr = prefix_str
        .parse()
        .map_err(|e| Status::invalid_argument(format!("invalid prefix address: {e}")))?;
    match addr {
        IpAddr::V4(v4) => {
            let len = u8::try_from(prefix_length)
                .ok()
                .filter(|&l| l <= 32)
                .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=32"))?;
            let nh: Ipv4Addr = next_hop_str
                .parse()
                .map_err(|e| Status::invalid_argument(format!("invalid next_hop: {e}")))?;
            if nh.is_unspecified() {
                return Err(Status::invalid_argument("next_hop must not be 0.0.0.0"));
            }
            if nh.is_multicast() {
                return Err(Status::invalid_argument("next_hop must not be multicast"));
            }
            Ok((Prefix::V4(Ipv4Prefix::new(v4, len)), IpAddr::V4(nh)))
        }
        IpAddr::V6(v6) => {
            let len = u8::try_from(prefix_length)
                .ok()
                .filter(|&l| l <= 128)
                .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=128"))?;
            let nh: Ipv6Addr = next_hop_str
                .parse()
                .map_err(|e| Status::invalid_argument(format!("invalid next_hop: {e}")))?;
            if nh.is_unspecified() {
                return Err(Status::invalid_argument("next_hop must not be ::"));
            }
            if nh.is_multicast() {
                return Err(Status::invalid_argument("next_hop must not be multicast"));
            }
            Ok((Prefix::V6(Ipv6Prefix::new(v6, len)), IpAddr::V6(nh)))
        }
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

#[tonic::async_trait]
impl proto::injection_service_server::InjectionService for InjectionService {
    async fn add_path(
        &self,
        request: Request<proto::AddPathRequest>,
    ) -> Result<Response<proto::AddPathResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();

        let (prefix, next_hop_ip) =
            parse_prefix_and_nexthop(&req.prefix, req.prefix_length, &req.next_hop)?;

        let origin = match req.origin {
            0 => Origin::Igp,
            1 => Origin::Egp,
            _ => Origin::Incomplete,
        };

        let mut attributes = vec![PathAttribute::Origin(origin)];

        // NEXT_HOP attribute only for IPv4 (IPv6 uses MP_REACH_NLRI)
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

        let route = Route {
            prefix,
            next_hop: next_hop_ip,
            peer: LOCAL_PEER,
            attributes: std::sync::Arc::new(attributes),
            received_at: std::time::Instant::now(),
            origin_type: RouteOrigin::Local,
            peer_router_id: std::net::Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: req.path_id,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::InjectRoute {
                route,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|e| Status::internal(format!("inject failed: {e}")))?;

        Ok(Response::new(proto::AddPathResponse {}))
    }

    async fn delete_path(
        &self,
        request: Request<proto::DeletePathRequest>,
    ) -> Result<Response<proto::DeletePathResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();

        let addr: IpAddr = req
            .prefix
            .parse()
            .map_err(|e| Status::invalid_argument(format!("invalid prefix address: {e}")))?;

        let prefix = match addr {
            IpAddr::V4(v4) => {
                let len = u8::try_from(req.prefix_length)
                    .ok()
                    .filter(|&l| l <= 32)
                    .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=32"))?;
                Prefix::V4(Ipv4Prefix::new(v4, len))
            }
            IpAddr::V6(v6) => {
                let len = u8::try_from(req.prefix_length)
                    .ok()
                    .filter(|&l| l <= 128)
                    .ok_or_else(|| Status::invalid_argument("prefix_length must be 0..=128"))?;
                Prefix::V6(Ipv6Prefix::new(v6, len))
            }
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::WithdrawInjected {
                prefix,
                path_id: req.path_id,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|e| Status::internal(format!("withdraw failed: {e}")))?;

        Ok(Response::new(proto::DeletePathResponse {}))
    }

    async fn add_flow_spec(
        &self,
        request: Request<proto::AddFlowSpecRequest>,
    ) -> Result<Response<proto::AddFlowSpecResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let afi = parse_flowspec_afi(req.afi_safi)?;

        let components = parse_flowspec_components(&req.components, afi)?;
        let rule = FlowSpecRule { components };
        rule.validate()
            .map_err(|e| Status::invalid_argument(format!("invalid FlowSpec rule: {e}")))?;

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

        let route = FlowSpecRoute {
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
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::InjectFlowSpec {
                route,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|e| Status::internal(format!("inject failed: {e}")))?;

        Ok(Response::new(proto::AddFlowSpecResponse {}))
    }

    async fn delete_flow_spec(
        &self,
        request: Request<proto::DeleteFlowSpecRequest>,
    ) -> Result<Response<proto::DeleteFlowSpecResponse>, Status> {
        if let Some(status) = read_only_rejection(self.access_mode) {
            return Err(status);
        }
        let req = request.into_inner();
        let afi = parse_flowspec_afi(req.afi_safi)?;

        let components = parse_flowspec_components(&req.components, afi)?;
        let rule = FlowSpecRule { components };
        rule.validate()
            .map_err(|e| Status::invalid_argument(format!("invalid FlowSpec rule: {e}")))?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.rib_tx
            .send(RibUpdate::WithdrawFlowSpec {
                rule,
                reply: reply_tx,
            })
            .await
            .map_err(|_| Status::internal("RIB manager unavailable"))?;

        reply_rx
            .await
            .map_err(|_| Status::internal("RIB manager dropped reply"))?
            .map_err(|e| Status::internal(format!("withdraw failed: {e}")))?;

        Ok(Response::new(proto::DeleteFlowSpecResponse {}))
    }
}

/// Parse the `AddressFamily` field for `FlowSpec` requests.
#[expect(clippy::result_large_err)]
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
#[expect(clippy::result_large_err)]
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

/// Parse a prefix string (e.g., "10.0.0.0/24") into a `FlowSpecPrefix`.
#[expect(clippy::result_large_err)]
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

#[expect(clippy::result_large_err)]
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
#[expect(clippy::result_large_err)]
fn parse_numeric_value(s: &str, label: &str) -> Result<Vec<NumericMatch>, Status> {
    let terms = split_match_terms(s, label)?;
    let len = terms.len();
    let mut result = Vec::with_capacity(len);

    for (idx, (token, and_bit)) in terms.into_iter().enumerate() {
        let op_len = token
            .chars()
            .take_while(|c| matches!(c, '=' | '<' | '>'))
            .count();
        let (ops, value_part) = token.split_at(op_len);
        let eq = ops.contains('=');
        let lt = ops.contains('<');
        let gt = ops.contains('>');
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
#[expect(clippy::result_large_err)]
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
#[expect(clippy::result_large_err)]
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
        proto::flow_spec_action::Action::Redirect(r) => {
            let parts: Vec<&str> = r.route_target.splitn(2, ':').collect();
            if parts.len() != 2 {
                return Err(Status::invalid_argument(
                    "redirect route_target must be \"ASN:value\"",
                ));
            }
            let asn: u16 = parts[0]
                .parse()
                .map_err(|_| Status::invalid_argument("redirect ASN must be u16"))?;
            let value: u32 = parts[1]
                .parse()
                .map_err(|_| Status::invalid_argument("redirect value must be u32"))?;
            FlowSpecAction::Redirect2Octet { asn, value }
        }
    };
    Ok(Some(ExtendedCommunity::from_flowspec_action(&wire_action)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::injection_service_server::InjectionService as _;

    fn make_service() -> InjectionService {
        let (tx, _rx) = mpsc::channel(16);
        InjectionService::new(tx, AccessMode::ReadWrite)
    }

    #[tokio::test]
    async fn add_path_rejects_zero_next_hop() {
        let svc = make_service();
        let req = Request::new(proto::AddPathRequest {
            prefix: "10.0.0.0".into(),
            prefix_length: 24,
            next_hop: "0.0.0.0".into(),
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
        assert!(err.message().contains("0.0.0.0"));
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
    async fn add_path_rejected_on_read_only_listener() {
        let (tx, mut rx) = mpsc::channel(16);
        let svc = InjectionService::new(tx, AccessMode::ReadOnly);
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
}
