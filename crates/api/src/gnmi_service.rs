//! Read-only `OpenConfig` gNMI surface.
#![allow(deprecated)]

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rustbgpd_fsm::SessionState;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::gnmi;
use crate::peer_types::{PeerInfo, PeerManagerCommand};

const GNMI_VERSION: &str = "0.10.0";
const DEFAULT_NETWORK_INSTANCE: &str = "DEFAULT";
const DEFAULT_PROTOCOL_NAME: &str = "BGP";

type PeerSnapshotFuture = Pin<Box<dyn Future<Output = Result<Vec<PeerInfo>, Status>> + Send>>;
type PeerSnapshotFn = Arc<dyn Fn() -> PeerSnapshotFuture + Send + Sync>;

/// Read-only gNMI target for the supported `OpenConfig` operational-state subset.
#[derive(Clone)]
pub struct GnmiService {
    asn: u32,
    router_id: String,
    peer_snapshot: PeerSnapshotFn,
}

type SubscribeStream =
    Pin<Box<dyn Stream<Item = Result<gnmi::SubscribeResponse, Status>> + Send + 'static>>;

impl GnmiService {
    /// Create a gNMI service backed by the daemon's peer manager.
    pub fn new(
        asn: u32,
        router_id: String,
        peer_mgr_tx: tokio::sync::mpsc::Sender<PeerManagerCommand>,
    ) -> Self {
        Self::with_peer_snapshot(asn, router_id, move || {
            let peer_mgr_tx = peer_mgr_tx.clone();
            Box::pin(async move {
                let (reply, rx) = tokio::sync::oneshot::channel();
                peer_mgr_tx
                    .send(PeerManagerCommand::ListPeers { reply })
                    .await
                    .map_err(|_| Status::internal("peer manager unavailable"))?;
                rx.await
                    .map_err(|_| Status::internal("peer manager dropped reply"))
            })
        })
    }

    fn with_peer_snapshot<F, Fut>(asn: u32, router_id: impl Into<String>, peer_snapshot: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Vec<PeerInfo>, Status>> + Send + 'static,
    {
        Self {
            asn,
            router_id: router_id.into(),
            peer_snapshot: Arc::new(move || Box::pin(peer_snapshot())),
        }
    }

    async fn render_get(&self, request: gnmi::GetRequest) -> Result<gnmi::GetResponse, Status> {
        validate_get_request(&request)?;
        let mut notifications = Vec::with_capacity(request.path.len());
        for path in request.path {
            let full_path = combine_paths(request.prefix.as_ref(), &path)?;
            let query = parse_supported_path(&full_path)?;
            let updates = self.render_query(&query).await?;
            notifications.push(gnmi::Notification {
                timestamp: now_nanos(),
                prefix: None,
                update: updates,
                delete: Vec::new(),
                atomic: false,
            });
        }

        Ok(gnmi::GetResponse {
            notification: notifications,
            error: None,
            extension: Vec::new(),
        })
    }

    async fn render_query(&self, query: &SupportedPath) -> Result<Vec<gnmi::Update>, Status> {
        match query {
            SupportedPath::Global { leaf } => Ok(render_global_updates(
                self.asn,
                &self.router_id,
                leaf.as_ref().copied(),
            )),
            SupportedPath::Neighbor { address, leaf } => {
                let peers = (self.peer_snapshot)().await?;
                render_neighbor_updates(&peers, self.asn, *address, leaf.as_ref().copied())
            }
            SupportedPath::AllNeighbors { leaf } => {
                let mut peers = (self.peer_snapshot)().await?;
                peers.sort_by_key(|peer| peer.address);
                let mut updates = Vec::new();
                for peer in &peers {
                    updates.extend(render_one_neighbor_updates(
                        peer,
                        self.asn,
                        leaf.as_ref().copied(),
                    ));
                }
                Ok(updates)
            }
        }
    }
}

fn supported_models() -> Vec<gnmi::ModelData> {
    vec![
        gnmi::ModelData {
            name: "openconfig-network-instance".to_string(),
            organization: "OpenConfig working group".to_string(),
            version: "4.7.0".to_string(),
        },
        gnmi::ModelData {
            name: "openconfig-bgp".to_string(),
            organization: "OpenConfig working group".to_string(),
            version: "9.9.1".to_string(),
        },
        gnmi::ModelData {
            name: "openconfig-policy-types".to_string(),
            organization: "OpenConfig working group".to_string(),
            version: "3.3.0".to_string(),
        },
    ]
}

fn supported_encodings() -> Vec<i32> {
    vec![gnmi::Encoding::Json as i32, gnmi::Encoding::JsonIetf as i32]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GlobalLeaf {
    As,
    RouterId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NeighborLeaf {
    NeighborAddress,
    Enabled,
    PeerAs,
    LocalAs,
    SessionState,
    EstablishedTransitions,
    UpdatesSent,
    UpdatesReceived,
    NotificationsSent,
    NotificationsReceived,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SupportedPath {
    Global {
        leaf: Option<GlobalLeaf>,
    },
    Neighbor {
        address: IpAddr,
        leaf: Option<NeighborLeaf>,
    },
    AllNeighbors {
        leaf: Option<NeighborLeaf>,
    },
}

fn validate_get_request(request: &gnmi::GetRequest) -> Result<(), Status> {
    if request.path.is_empty() {
        return Err(Status::invalid_argument(
            "gNMI Get requires at least one path",
        ));
    }
    let data_type = gnmi::get_request::DataType::try_from(request.r#type).map_err(|_| {
        Status::invalid_argument(format!("unknown gNMI Get data type {}", request.r#type))
    })?;
    match data_type {
        gnmi::get_request::DataType::All
        | gnmi::get_request::DataType::State
        | gnmi::get_request::DataType::Operational => {}
        gnmi::get_request::DataType::Config => {
            return Err(Status::unimplemented(
                "gNMI Get supports operational state only",
            ));
        }
    }

    let encoding = gnmi::Encoding::try_from(request.encoding).map_err(|_| {
        Status::invalid_argument(format!("unknown gNMI encoding {}", request.encoding))
    })?;
    match encoding {
        gnmi::Encoding::Json | gnmi::Encoding::JsonIetf => Ok(()),
        _ => Err(Status::unimplemented(format!(
            "gNMI encoding {} is not supported",
            encoding.as_str_name()
        ))),
    }
}

fn combine_paths(prefix: Option<&gnmi::Path>, path: &gnmi::Path) -> Result<gnmi::Path, Status> {
    if prefix.is_some_and(|prefix| !prefix.element.is_empty()) || !path.element.is_empty() {
        return Err(Status::invalid_argument(
            "legacy string path elements are not supported; use PathElem",
        ));
    }

    let mut elem = prefix.map_or_else(Vec::new, |prefix| prefix.elem.clone());
    elem.extend(path.elem.clone());
    Ok(gnmi::Path {
        element: Vec::new(),
        origin: path
            .origin
            .clone()
            .if_empty(prefix.map_or(String::new(), |prefix| prefix.origin.clone())),
        target: path
            .target
            .clone()
            .if_empty(prefix.map_or(String::new(), |prefix| prefix.target.clone())),
        elem,
    })
}

trait EmptyFallback {
    fn if_empty(self, fallback: Self) -> Self;
}

impl EmptyFallback for String {
    fn if_empty(self, fallback: Self) -> Self {
        if self.is_empty() { fallback } else { self }
    }
}

fn parse_supported_path(path: &gnmi::Path) -> Result<SupportedPath, Status> {
    if !path.element.is_empty() {
        return Err(Status::invalid_argument(
            "legacy string path elements are not supported; use PathElem",
        ));
    }
    if !path.origin.is_empty() && path.origin != "openconfig" {
        return Err(Status::invalid_argument(format!(
            "unsupported gNMI origin {}",
            path.origin
        )));
    }

    let elem = &path.elem;
    if elem.len() < 7 {
        return Err(Status::unimplemented("unsupported OpenConfig path"));
    }
    expect_no_keys(&elem[0], "network-instances")?;
    expect_key_alias(
        &elem[1],
        "network-instance",
        "name",
        &[DEFAULT_NETWORK_INSTANCE, "default"],
    )?;
    expect_no_keys(&elem[2], "protocols")?;
    expect_protocol_key(&elem[3])?;
    expect_no_keys(&elem[4], "bgp")?;

    match elem[5].name.as_str() {
        "global" => parse_global_path(&elem[6..]),
        "neighbors" => parse_neighbors_path(&elem[6..]),
        _ => Err(Status::unimplemented("unsupported OpenConfig BGP path")),
    }
}

fn parse_global_path(tail: &[gnmi::PathElem]) -> Result<SupportedPath, Status> {
    if tail.is_empty() {
        return Err(Status::unimplemented(
            "unsupported OpenConfig BGP global path",
        ));
    }
    expect_no_keys(&tail[0], "state")?;
    let leaf = match tail.get(1).map(|elem| elem.name.as_str()) {
        None => None,
        Some("as") if tail.len() == 2 => Some(GlobalLeaf::As),
        Some("router-id") if tail.len() == 2 => Some(GlobalLeaf::RouterId),
        Some(_) => {
            return Err(Status::unimplemented(
                "unsupported OpenConfig BGP global state path",
            ));
        }
    };
    if let Some(elem) = tail.get(1) {
        ensure_no_extra_leaf_keys(elem)?;
    }
    Ok(SupportedPath::Global { leaf })
}

fn parse_neighbors_path(tail: &[gnmi::PathElem]) -> Result<SupportedPath, Status> {
    if tail.is_empty() {
        return Err(Status::unimplemented(
            "unsupported OpenConfig BGP neighbors path",
        ));
    }
    let neighbor = &tail[0];
    if neighbor.name != "neighbor" {
        return Err(Status::unimplemented(
            "unsupported OpenConfig BGP neighbors path",
        ));
    }
    let address = match neighbor.key.get("neighbor-address") {
        Some(raw) => Some(raw.parse::<IpAddr>().map_err(|_| {
            Status::invalid_argument(format!("invalid neighbor-address key {raw}"))
        })?),
        None if neighbor.key.is_empty() => None,
        None => {
            return Err(Status::invalid_argument(
                "neighbor key must be neighbor-address",
            ));
        }
    };
    if neighbor.key.len() > usize::from(address.is_some()) {
        return Err(Status::invalid_argument(
            "neighbor supports only the neighbor-address key",
        ));
    }

    if tail.len() == 1 {
        return Ok(match address {
            Some(address) => SupportedPath::Neighbor {
                address,
                leaf: None,
            },
            None => SupportedPath::AllNeighbors { leaf: None },
        });
    }
    expect_no_keys(&tail[1], "state")?;
    let leaf = parse_neighbor_state_leaf(&tail[2..])?;
    Ok(match address {
        Some(address) => SupportedPath::Neighbor { address, leaf },
        None => SupportedPath::AllNeighbors { leaf },
    })
}

fn parse_neighbor_state_leaf(tail: &[gnmi::PathElem]) -> Result<Option<NeighborLeaf>, Status> {
    if tail.is_empty() {
        return Ok(None);
    }
    let first = &tail[0];
    match first.name.as_str() {
        "neighbor-address" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(Some(NeighborLeaf::NeighborAddress))
        }
        "enabled" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(Some(NeighborLeaf::Enabled))
        }
        "peer-as" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(Some(NeighborLeaf::PeerAs))
        }
        "local-as" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(Some(NeighborLeaf::LocalAs))
        }
        "session-state" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(Some(NeighborLeaf::SessionState))
        }
        "established-transitions" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(Some(NeighborLeaf::EstablishedTransitions))
        }
        "messages" => parse_neighbor_messages_leaf(&tail[1..]),
        _ => Err(Status::unimplemented(
            "unsupported OpenConfig BGP neighbor state path",
        )),
    }
}

fn parse_neighbor_messages_leaf(tail: &[gnmi::PathElem]) -> Result<Option<NeighborLeaf>, Status> {
    if tail.is_empty() {
        return Ok(None);
    }
    expect_name_no_keys(&tail[0], &["sent", "received"])?;
    match (
        tail[0].name.as_str(),
        tail.get(1).map(|elem| elem.name.as_str()),
    ) {
        ("sent" | "received", None) => Ok(None),
        ("sent", Some("UPDATE")) if tail.len() == 2 => {
            ensure_no_extra_leaf_keys(&tail[1])?;
            Ok(Some(NeighborLeaf::UpdatesSent))
        }
        ("received", Some("UPDATE")) if tail.len() == 2 => {
            ensure_no_extra_leaf_keys(&tail[1])?;
            Ok(Some(NeighborLeaf::UpdatesReceived))
        }
        ("sent", Some("NOTIFICATION")) if tail.len() == 2 => {
            ensure_no_extra_leaf_keys(&tail[1])?;
            Ok(Some(NeighborLeaf::NotificationsSent))
        }
        ("received", Some("NOTIFICATION")) if tail.len() == 2 => {
            ensure_no_extra_leaf_keys(&tail[1])?;
            Ok(Some(NeighborLeaf::NotificationsReceived))
        }
        _ => Err(Status::unimplemented(
            "unsupported OpenConfig BGP neighbor message counter path",
        )),
    }
}

fn expect_no_keys(elem: &gnmi::PathElem, name: &str) -> Result<(), Status> {
    if elem.name != name {
        return Err(Status::unimplemented("unsupported OpenConfig path"));
    }
    ensure_no_extra_leaf_keys(elem)
}

fn expect_name_no_keys(elem: &gnmi::PathElem, names: &[&str]) -> Result<(), Status> {
    if !names.contains(&elem.name.as_str()) {
        return Err(Status::unimplemented("unsupported OpenConfig path"));
    }
    ensure_no_extra_leaf_keys(elem)
}

fn expect_key_alias(
    elem: &gnmi::PathElem,
    name: &str,
    key: &str,
    values: &[&str],
) -> Result<(), Status> {
    if elem.name != name {
        return Err(Status::unimplemented("unsupported OpenConfig path"));
    }
    if elem.key.len() != 1 || !elem.key.contains_key(key) {
        return Err(Status::invalid_argument(format!(
            "{name} requires only the {key} key",
        )));
    }
    let value = &elem.key[key];
    if values.iter().any(|candidate| value == candidate) {
        Ok(())
    } else {
        Err(Status::not_found(format!(
            "{name}[{key}={value}] is not present",
        )))
    }
}

fn expect_protocol_key(elem: &gnmi::PathElem) -> Result<(), Status> {
    if elem.name != "protocol" {
        return Err(Status::unimplemented("unsupported OpenConfig path"));
    }
    if elem.key.len() != 2 || !elem.key.contains_key("identifier") || !elem.key.contains_key("name")
    {
        return Err(Status::invalid_argument(
            "protocol requires identifier and name keys",
        ));
    }
    let identifier = &elem.key["identifier"];
    if !matches!(
        identifier.as_str(),
        "BGP" | "openconfig-policy-types:BGP" | "oc-pol-types:BGP"
    ) {
        return Err(Status::not_found(format!(
            "protocol identifier {identifier} is not present",
        )));
    }
    let name = &elem.key["name"];
    if name != DEFAULT_PROTOCOL_NAME {
        return Err(Status::not_found(format!(
            "protocol name {name} is not present"
        )));
    }
    Ok(())
}

fn ensure_no_extra_leaf_keys(elem: &gnmi::PathElem) -> Result<(), Status> {
    if elem.key.is_empty() {
        Ok(())
    } else {
        Err(Status::invalid_argument(format!(
            "{} does not accept keys",
            elem.name
        )))
    }
}

fn render_global_updates(asn: u32, router_id: &str, leaf: Option<GlobalLeaf>) -> Vec<gnmi::Update> {
    match leaf {
        Some(GlobalLeaf::As) => vec![uint_update(global_leaf_path("as"), u64::from(asn))],
        Some(GlobalLeaf::RouterId) => vec![string_update(global_leaf_path("router-id"), router_id)],
        None => vec![
            uint_update(global_leaf_path("as"), u64::from(asn)),
            string_update(global_leaf_path("router-id"), router_id),
        ],
    }
}

fn render_neighbor_updates(
    peers: &[PeerInfo],
    local_as: u32,
    address: IpAddr,
    leaf: Option<NeighborLeaf>,
) -> Result<Vec<gnmi::Update>, Status> {
    let peer = peers
        .iter()
        .find(|peer| peer.address == address)
        .ok_or_else(|| Status::not_found(format!("neighbor {address} not found")))?;
    Ok(render_one_neighbor_updates(peer, local_as, leaf))
}

fn render_one_neighbor_updates(
    peer: &PeerInfo,
    local_as: u32,
    leaf: Option<NeighborLeaf>,
) -> Vec<gnmi::Update> {
    let leaves = match leaf {
        Some(leaf) => vec![leaf],
        None => vec![
            NeighborLeaf::NeighborAddress,
            NeighborLeaf::Enabled,
            NeighborLeaf::PeerAs,
            NeighborLeaf::LocalAs,
            NeighborLeaf::SessionState,
            NeighborLeaf::EstablishedTransitions,
            NeighborLeaf::UpdatesSent,
            NeighborLeaf::UpdatesReceived,
            NeighborLeaf::NotificationsSent,
            NeighborLeaf::NotificationsReceived,
        ],
    };

    leaves
        .into_iter()
        .map(|leaf| match leaf {
            NeighborLeaf::NeighborAddress => string_update(
                neighbor_leaf_path(peer.address, leaf),
                &peer.address.to_string(),
            ),
            NeighborLeaf::Enabled => {
                bool_update(neighbor_leaf_path(peer.address, leaf), peer.enabled)
            }
            NeighborLeaf::PeerAs => uint_update(
                neighbor_leaf_path(peer.address, leaf),
                u64::from(peer.remote_asn),
            ),
            NeighborLeaf::LocalAs => {
                uint_update(neighbor_leaf_path(peer.address, leaf), u64::from(local_as))
            }
            NeighborLeaf::SessionState => string_update(
                neighbor_leaf_path(peer.address, leaf),
                session_state_name(peer.state),
            ),
            NeighborLeaf::EstablishedTransitions => {
                uint_update(neighbor_leaf_path(peer.address, leaf), peer.flap_count)
            }
            NeighborLeaf::UpdatesSent => {
                uint_update(neighbor_leaf_path(peer.address, leaf), peer.updates_sent)
            }
            NeighborLeaf::UpdatesReceived => uint_update(
                neighbor_leaf_path(peer.address, leaf),
                peer.updates_received,
            ),
            NeighborLeaf::NotificationsSent => uint_update(
                neighbor_leaf_path(peer.address, leaf),
                peer.notifications_sent,
            ),
            NeighborLeaf::NotificationsReceived => uint_update(
                neighbor_leaf_path(peer.address, leaf),
                peer.notifications_received,
            ),
        })
        .collect()
}

fn session_state_name(state: SessionState) -> &'static str {
    match state {
        SessionState::Idle => "IDLE",
        SessionState::Connect => "CONNECT",
        SessionState::Active => "ACTIVE",
        SessionState::OpenSent => "OPENSENT",
        SessionState::OpenConfirm => "OPENCONFIRM",
        SessionState::Established => "ESTABLISHED",
    }
}

fn global_leaf_path(leaf: &str) -> gnmi::Path {
    mounted_path(&[pe("bgp"), pe("global"), pe("state"), pe(leaf)])
}

fn neighbor_leaf_path(address: IpAddr, leaf: NeighborLeaf) -> gnmi::Path {
    let mut elems = vec![
        pe("bgp"),
        pe("neighbors"),
        keyed_pe("neighbor", "neighbor-address", &address.to_string()),
        pe("state"),
    ];
    match leaf {
        NeighborLeaf::NeighborAddress => elems.push(pe("neighbor-address")),
        NeighborLeaf::Enabled => elems.push(pe("enabled")),
        NeighborLeaf::PeerAs => elems.push(pe("peer-as")),
        NeighborLeaf::LocalAs => elems.push(pe("local-as")),
        NeighborLeaf::SessionState => elems.push(pe("session-state")),
        NeighborLeaf::EstablishedTransitions => elems.push(pe("established-transitions")),
        NeighborLeaf::UpdatesSent => {
            elems.push(pe("messages"));
            elems.push(pe("sent"));
            elems.push(pe("UPDATE"));
        }
        NeighborLeaf::UpdatesReceived => {
            elems.push(pe("messages"));
            elems.push(pe("received"));
            elems.push(pe("UPDATE"));
        }
        NeighborLeaf::NotificationsSent => {
            elems.push(pe("messages"));
            elems.push(pe("sent"));
            elems.push(pe("NOTIFICATION"));
        }
        NeighborLeaf::NotificationsReceived => {
            elems.push(pe("messages"));
            elems.push(pe("received"));
            elems.push(pe("NOTIFICATION"));
        }
    }
    mounted_path(&elems)
}

fn mounted_path(tail: &[gnmi::PathElem]) -> gnmi::Path {
    let mut elem = vec![
        pe("network-instances"),
        keyed_pe("network-instance", "name", DEFAULT_NETWORK_INSTANCE),
        pe("protocols"),
        protocol_pe(),
    ];
    elem.extend_from_slice(tail);
    gnmi::Path {
        element: Vec::new(),
        origin: String::new(),
        elem,
        target: String::new(),
    }
}

fn pe(name: &str) -> gnmi::PathElem {
    gnmi::PathElem {
        name: name.to_string(),
        key: HashMap::new(),
    }
}

fn keyed_pe(name: &str, key: &str, value: &str) -> gnmi::PathElem {
    gnmi::PathElem {
        name: name.to_string(),
        key: HashMap::from([(key.to_string(), value.to_string())]),
    }
}

fn protocol_pe() -> gnmi::PathElem {
    gnmi::PathElem {
        name: "protocol".to_string(),
        key: HashMap::from([
            ("identifier".to_string(), "BGP".to_string()),
            ("name".to_string(), DEFAULT_PROTOCOL_NAME.to_string()),
        ]),
    }
}

fn string_update(path: gnmi::Path, value: &str) -> gnmi::Update {
    typed_update(path, gnmi::typed_value::Value::StringVal(value.to_string()))
}

fn uint_update(path: gnmi::Path, value: u64) -> gnmi::Update {
    typed_update(path, gnmi::typed_value::Value::UintVal(value))
}

fn bool_update(path: gnmi::Path, value: bool) -> gnmi::Update {
    typed_update(path, gnmi::typed_value::Value::BoolVal(value))
}

fn typed_update(path: gnmi::Path, value: gnmi::typed_value::Value) -> gnmi::Update {
    gnmi::Update {
        path: Some(path),
        value: None,
        val: Some(gnmi::TypedValue { value: Some(value) }),
        duplicates: 0,
    }
}

fn now_nanos() -> i64 {
    let Ok(duration) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return 0;
    };
    i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
}

#[tonic::async_trait]
impl gnmi::g_nmi_server::GNmi for GnmiService {
    async fn capabilities(
        &self,
        _request: Request<gnmi::CapabilityRequest>,
    ) -> Result<Response<gnmi::CapabilityResponse>, Status> {
        Ok(Response::new(gnmi::CapabilityResponse {
            supported_models: supported_models(),
            supported_encodings: supported_encodings(),
            g_nmi_version: GNMI_VERSION.to_string(),
            extension: Vec::new(),
        }))
    }

    async fn get(
        &self,
        request: Request<gnmi::GetRequest>,
    ) -> Result<Response<gnmi::GetResponse>, Status> {
        Ok(Response::new(self.render_get(request.into_inner()).await?))
    }

    async fn set(
        &self,
        _request: Request<gnmi::SetRequest>,
    ) -> Result<Response<gnmi::SetResponse>, Status> {
        Err(Status::unimplemented("gNMI Set is not supported"))
    }

    type SubscribeStream = SubscribeStream;

    async fn subscribe(
        &self,
        _request: Request<tonic::Streaming<gnmi::SubscribeRequest>>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        Err(Status::unimplemented(
            "gNMI Subscribe is not implemented in this slice",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnmi::g_nmi_server::GNmi as _;
    use rustbgpd_transport::RemovePrivateAs;

    fn test_service(peers: Vec<PeerInfo>) -> GnmiService {
        GnmiService::with_peer_snapshot(65001, "192.0.2.1", move || {
            let peers = peers.clone();
            async move { Ok(peers) }
        })
    }

    fn test_peer(address: IpAddr) -> PeerInfo {
        PeerInfo {
            address,
            interface: None,
            remote_asn: 65002,
            description: String::new(),
            peer_group: None,
            state: SessionState::Established,
            enabled: true,
            prefix_count: 0,
            hold_time: None,
            max_prefixes: None,
            families: Vec::new(),
            remove_private_as: RemovePrivateAs::Disabled,
            route_server_client: false,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 1,
            updates_received: 11,
            updates_sent: 12,
            notifications_received: 2,
            notifications_sent: 3,
            flap_count: 4,
            uptime_secs: 0,
            last_error: String::new(),
            is_dynamic: false,
            stale: false,
        }
    }

    fn get_request(path: gnmi::Path) -> Request<gnmi::GetRequest> {
        Request::new(gnmi::GetRequest {
            prefix: None,
            path: vec![path],
            r#type: gnmi::get_request::DataType::State as i32,
            encoding: gnmi::Encoding::JsonIetf as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        })
    }

    fn update_values(response: &gnmi::GetResponse) -> Vec<&gnmi::typed_value::Value> {
        response
            .notification
            .iter()
            .flat_map(|notification| &notification.update)
            .map(|update| update.val.as_ref().unwrap().value.as_ref().unwrap())
            .collect()
    }

    #[tokio::test]
    async fn capabilities_advertises_version_models_and_encodings() {
        let response = test_service(Vec::new())
            .capabilities(Request::new(gnmi::CapabilityRequest {
                extension: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.g_nmi_version, GNMI_VERSION);
        assert_eq!(
            response.supported_encodings,
            vec![gnmi::Encoding::Json as i32, gnmi::Encoding::JsonIetf as i32]
        );
        let model_names = response
            .supported_models
            .iter()
            .map(|model| model.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            model_names,
            vec![
                "openconfig-network-instance",
                "openconfig-bgp",
                "openconfig-policy-types"
            ]
        );
        let model_versions = response
            .supported_models
            .iter()
            .map(|model| {
                (
                    model.name.as_str(),
                    model.organization.as_str(),
                    model.version.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            model_versions,
            vec![
                (
                    "openconfig-network-instance",
                    "OpenConfig working group",
                    "4.7.0"
                ),
                ("openconfig-bgp", "OpenConfig working group", "9.9.1"),
                (
                    "openconfig-policy-types",
                    "OpenConfig working group",
                    "3.3.0"
                )
            ]
        );
    }

    #[tokio::test]
    async fn get_rejects_empty_path_list() {
        let get_err = test_service(Vec::new())
            .get(Request::new(gnmi::GetRequest {
                prefix: None,
                path: Vec::new(),
                r#type: gnmi::get_request::DataType::State as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(get_err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn set_is_stably_closed() {
        let err = test_service(Vec::new())
            .set(Request::new(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: Vec::new(),
                extension: Vec::new(),
                union_replace: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        assert!(err.message().contains("not supported"));
    }

    #[tokio::test]
    async fn get_global_state_renders_supported_leaves() {
        let response = test_service(Vec::new())
            .get(get_request(mounted_path(&[
                pe("bgp"),
                pe("global"),
                pe("state"),
            ])))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            update_values(&response),
            vec![
                &gnmi::typed_value::Value::UintVal(65001),
                &gnmi::typed_value::Value::StringVal("192.0.2.1".to_string())
            ]
        );
    }

    #[tokio::test]
    async fn get_neighbor_state_renders_supported_leaves() {
        let peer = test_peer("203.0.113.2".parse().unwrap());
        let response = test_service(vec![peer])
            .get(get_request(mounted_path(&[
                pe("bgp"),
                pe("neighbors"),
                keyed_pe("neighbor", "neighbor-address", "203.0.113.2"),
                pe("state"),
            ])))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.notification[0].update.len(), 10);
        assert_eq!(
            update_values(&response),
            vec![
                &gnmi::typed_value::Value::StringVal("203.0.113.2".to_string()),
                &gnmi::typed_value::Value::BoolVal(true),
                &gnmi::typed_value::Value::UintVal(65002),
                &gnmi::typed_value::Value::UintVal(65001),
                &gnmi::typed_value::Value::StringVal("ESTABLISHED".to_string()),
                &gnmi::typed_value::Value::UintVal(4),
                &gnmi::typed_value::Value::UintVal(12),
                &gnmi::typed_value::Value::UintVal(11),
                &gnmi::typed_value::Value::UintVal(3),
                &gnmi::typed_value::Value::UintVal(2)
            ]
        );
    }

    #[tokio::test]
    async fn get_neighbor_message_leaf_renders_single_counter() {
        let peer = test_peer("203.0.113.2".parse().unwrap());
        let response = test_service(vec![peer])
            .get(get_request(mounted_path(&[
                pe("bgp"),
                pe("neighbors"),
                keyed_pe("neighbor", "neighbor-address", "203.0.113.2"),
                pe("state"),
                pe("messages"),
                pe("sent"),
                pe("UPDATE"),
            ])))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(
            update_values(&response),
            vec![&gnmi::typed_value::Value::UintVal(12)]
        );
    }

    #[tokio::test]
    async fn path_parser_accepts_documented_aliases() {
        let response = test_service(Vec::new())
            .get(get_request(mounted_path(&[
                pe("bgp"),
                pe("global"),
                pe("state"),
                pe("as"),
            ])))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            update_values(&response),
            vec![&gnmi::typed_value::Value::UintVal(65001)]
        );

        let alias_path = gnmi::Path {
            element: Vec::new(),
            origin: String::new(),
            target: String::new(),
            elem: vec![
                pe("network-instances"),
                keyed_pe("network-instance", "name", "default"),
                pe("protocols"),
                gnmi::PathElem {
                    name: "protocol".to_string(),
                    key: HashMap::from([
                        (
                            "identifier".to_string(),
                            "openconfig-policy-types:BGP".to_string(),
                        ),
                        ("name".to_string(), "BGP".to_string()),
                    ]),
                },
                pe("bgp"),
                pe("global"),
                pe("state"),
                pe("router-id"),
            ],
        };
        let response = test_service(Vec::new())
            .get(get_request(alias_path))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            update_values(&response),
            vec![&gnmi::typed_value::Value::StringVal(
                "192.0.2.1".to_string()
            )]
        );
    }

    #[tokio::test]
    async fn get_maps_unsupported_missing_and_malformed_paths() {
        let unsupported = test_service(Vec::new())
            .get(get_request(mounted_path(&[
                pe("bgp"),
                pe("global"),
                pe("state"),
                pe("total-prefixes"),
            ])))
            .await
            .unwrap_err();
        assert_eq!(unsupported.code(), tonic::Code::Unimplemented);

        let missing = test_service(Vec::new())
            .get(get_request(mounted_path(&[
                pe("bgp"),
                pe("neighbors"),
                keyed_pe("neighbor", "neighbor-address", "203.0.113.2"),
                pe("state"),
            ])))
            .await
            .unwrap_err();
        assert_eq!(missing.code(), tonic::Code::NotFound);

        let malformed = test_service(Vec::new())
            .get(get_request(mounted_path(&[
                pe("bgp"),
                pe("neighbors"),
                keyed_pe("neighbor", "bad-key", "203.0.113.2"),
                pe("state"),
            ])))
            .await
            .unwrap_err();
        assert_eq!(malformed.code(), tonic::Code::InvalidArgument);
    }
}
