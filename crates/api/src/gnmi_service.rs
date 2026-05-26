//! Read-only `OpenConfig` gNMI surface.

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustbgpd_fsm::SessionState;
use tokio_stream::{Stream, wrappers::ReceiverStream};
use tonic::{Request, Response, Status};

use crate::gnmi;
use crate::peer_types::{PeerInfo, PeerManagerCommand};

const GNMI_VERSION: &str = "0.10.0";
const DEFAULT_NETWORK_INSTANCE: &str = "DEFAULT";
const DEFAULT_PROTOCOL_NAME: &str = "BGP";
const MAX_SUBSCRIPTIONS: usize = 16;
const SUBSCRIBE_CHANNEL_DEPTH: usize = 16;
const MIN_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// Upper bound on a client-requested `STREAM` `SAMPLE` interval. Clamps absurd
/// values (a client could otherwise request an interval of centuries) so a
/// subscription always resamples within a sane bound.
// `from_secs(3600)` (1 hour) is kept over `from_hours` to stay within the
// workspace MSRV.
#[allow(clippy::duration_suboptimal_units)]
const MAX_SAMPLE_INTERVAL: Duration = Duration::from_secs(3600);
/// Application-level ceiling on concurrent `Subscribe` streams. `MAX_SUBSCRIPTIONS`
/// bounds the paths within a single request; this bounds how many open streams the
/// target will service at once so a flood of collectors cannot exhaust resources.
const MAX_CONCURRENT_SUBSCRIPTIONS: usize = 64;

type PeerSnapshotFuture = Pin<Box<dyn Future<Output = Result<Vec<PeerInfo>, Status>> + Send>>;
type PeerSnapshotFn = Arc<dyn Fn() -> PeerSnapshotFuture + Send + Sync>;

/// Read-only gNMI target for the supported `OpenConfig` operational-state subset.
#[derive(Clone)]
pub struct GnmiService {
    asn: u32,
    router_id: String,
    peer_snapshot: PeerSnapshotFn,
    /// Bounds concurrent `Subscribe` streams; a permit is held for the lifetime
    /// of each open stream.
    subscribe_slots: Arc<tokio::sync::Semaphore>,
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
            subscribe_slots: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_SUBSCRIPTIONS)),
        }
    }

    async fn render_get(&self, request: gnmi::GetRequest) -> Result<gnmi::GetResponse, Status> {
        validate_get_request(&request)?;
        let encoding = gnmi::Encoding::try_from(request.encoding).unwrap_or(gnmi::Encoding::Json);

        // Parse every requested path before touching any snapshot so a malformed
        // or unsupported path fails fast without a peer-manager round-trip.
        let queries = request
            .path
            .iter()
            .map(|path| {
                let full_path = combine_paths(request.prefix.as_ref(), path)?;
                parse_supported_path(&full_path)
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Snapshot peers once per request (a multi-path Get otherwise fans out
        // one peer-manager round-trip per neighbor path); sort once for stable
        // ordering across the whole response.
        let peers = if queries.iter().any(SupportedPath::needs_peers) {
            let mut peers = (self.peer_snapshot)().await?;
            peers.sort_by_key(|peer| peer.address);
            Some(peers)
        } else {
            None
        };

        let mut notifications = Vec::with_capacity(queries.len());
        for query in &queries {
            let updates = self.render_query(query, peers.as_deref(), encoding)?;
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
            // `error` is the deprecated top-level error field; per-RPC errors are
            // returned as a gRPC `Status` instead.
            #[allow(deprecated)]
            error: None,
            extension: Vec::new(),
        })
    }

    fn render_query(
        &self,
        query: &SupportedPath,
        peers: Option<&[PeerInfo]>,
        encoding: gnmi::Encoding,
    ) -> Result<Vec<gnmi::Update>, Status> {
        match query {
            SupportedPath::Global { leaf } => Ok(render_global_updates(
                self.asn,
                &self.router_id,
                leaf.as_ref().copied(),
                encoding,
            )),
            SupportedPath::Neighbor { address, select } => {
                let peers = peers.unwrap_or(&[]);
                render_neighbor_updates(peers, self.asn, *address, *select, encoding)
            }
            SupportedPath::AllNeighbors { select } => {
                let peers = peers.unwrap_or(&[]);
                let mut updates = Vec::new();
                for peer in peers {
                    updates.extend(render_one_neighbor_updates(
                        peer, self.asn, *select, encoding,
                    ));
                }
                Ok(updates)
            }
        }
    }

    async fn render_subscription_snapshot(
        &self,
        plan: &SubscriptionPlan,
        include_sync: bool,
    ) -> Result<Vec<gnmi::SubscribeResponse>, Status> {
        let mut updates = Vec::new();
        if !plan.updates_only {
            // Snapshot peers once per snapshot/tick (the subscription may carry
            // multiple neighbor paths; otherwise each path fans out its own
            // peer-manager round-trip). Global-only plans skip the snapshot.
            let peers = if plan.paths.iter().any(SupportedPath::needs_peers) {
                let mut peers = (self.peer_snapshot)().await?;
                peers.sort_by_key(|peer| peer.address);
                Some(peers)
            } else {
                None
            };
            for query in &plan.paths {
                updates.extend(self.render_query(query, peers.as_deref(), plan.encoding)?);
            }
        }

        let mut responses = Vec::new();
        if !updates.is_empty() {
            responses.push(gnmi::SubscribeResponse {
                response: Some(gnmi::subscribe_response::Response::Update(
                    gnmi::Notification {
                        timestamp: now_nanos(),
                        prefix: None,
                        update: updates,
                        delete: Vec::new(),
                        atomic: false,
                    },
                )),
                extension: Vec::new(),
            });
        }
        if include_sync {
            responses.push(sync_response());
        }
        Ok(responses)
    }

    /// Render a snapshot and forward it (then any error) over `tx`. Returns
    /// `false` when the task should stop (client gone or render error).
    async fn forward_snapshot(
        &self,
        plan: &SubscriptionPlan,
        include_sync: bool,
        tx: &tokio::sync::mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
    ) -> bool {
        match self.render_subscription_snapshot(plan, include_sync).await {
            Ok(responses) => {
                for response in responses {
                    if tx.send(Ok(response)).await.is_err() {
                        return false;
                    }
                }
                true
            }
            Err(err) => {
                let _ = tx.send(Err(err)).await;
                false
            }
        }
    }

    /// POLL task: emit the initial data tree once, then a fresh snapshot per
    /// Poll request, until the client disconnects.
    async fn run_poll(
        self,
        plan: SubscriptionPlan,
        mut inbound: tonic::Streaming<gnmi::SubscribeRequest>,
        tx: tokio::sync::mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
    ) {
        if !self.forward_snapshot(&plan, true, &tx).await {
            return;
        }
        loop {
            match inbound.message().await {
                Ok(Some(gnmi::SubscribeRequest {
                    request: Some(gnmi::subscribe_request::Request::Poll(_)),
                    ..
                })) => {
                    if !self.forward_snapshot(&plan, true, &tx).await {
                        return;
                    }
                }
                Ok(Some(_)) => {
                    let _ = tx
                        .send(Err(Status::invalid_argument(
                            "POLL subscription accepts only Poll requests after setup",
                        )))
                        .await;
                    return;
                }
                Ok(None) => return,
                Err(err) => {
                    let _ = tx.send(Err(err)).await;
                    return;
                }
            }
        }
    }

    /// STREAM/SAMPLE task: emit an initial snapshot + sync, then a fresh sample
    /// every `sample_interval`, exiting promptly when the client disconnects.
    async fn run_stream_sample(
        self,
        plan: SubscriptionPlan,
        tx: tokio::sync::mpsc::Sender<Result<gnmi::SubscribeResponse, Status>>,
    ) {
        let mut include_sync = true;
        loop {
            if !self.forward_snapshot(&plan, include_sync, &tx).await {
                return;
            }
            include_sync = false;
            // Sleep until the next sample, but bail out promptly if the client
            // disconnects (or the server drops the receiver) instead of waiting
            // out a full interval first.
            tokio::select! {
                () = tokio::time::sleep(plan.sample_interval) => {}
                () = tx.closed() => return,
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

/// The set of neighbor leaves a path selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NeighborSelect {
    /// The full supported `state` leaf set (bare `.../neighbor[..]` or `.../state`).
    AllState,
    /// All `messages` counters (a bare `.../state/messages` container Get).
    Messages,
    /// Only the `messages/sent` counters (bare `.../messages/sent` container).
    MessagesSent,
    /// Only the `messages/received` counters (bare `.../messages/received`).
    MessagesReceived,
    /// A single specific leaf.
    One(NeighborLeaf),
}

impl NeighborSelect {
    /// Expand this selection into the concrete ordered list of leaves to render.
    fn leaves(self) -> Vec<NeighborLeaf> {
        match self {
            NeighborSelect::AllState => vec![
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
            NeighborSelect::Messages => vec![
                NeighborLeaf::UpdatesSent,
                NeighborLeaf::UpdatesReceived,
                NeighborLeaf::NotificationsSent,
                NeighborLeaf::NotificationsReceived,
            ],
            NeighborSelect::MessagesSent => {
                vec![NeighborLeaf::UpdatesSent, NeighborLeaf::NotificationsSent]
            }
            NeighborSelect::MessagesReceived => vec![
                NeighborLeaf::UpdatesReceived,
                NeighborLeaf::NotificationsReceived,
            ],
            NeighborSelect::One(leaf) => vec![leaf],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SupportedPath {
    Global {
        leaf: Option<GlobalLeaf>,
    },
    Neighbor {
        address: IpAddr,
        select: NeighborSelect,
    },
    AllNeighbors {
        select: NeighborSelect,
    },
}

impl SupportedPath {
    /// Whether rendering this path requires the peer snapshot (global state is
    /// served from static config and needs no peer-manager round-trip).
    fn needs_peers(&self) -> bool {
        matches!(
            self,
            SupportedPath::Neighbor { .. } | SupportedPath::AllNeighbors { .. }
        )
    }
}

#[derive(Clone, Debug)]
struct SubscriptionPlan {
    mode: gnmi::subscription_list::Mode,
    paths: Vec<SupportedPath>,
    updates_only: bool,
    sample_interval: Duration,
    encoding: gnmi::Encoding,
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
        // gNMI `ALL` means config + state. rustbgpd has no config datastore (Set
        // is closed; ADR-0070), so this is a state-only operational target: it
        // serves the state subset for `ALL`/`STATE`/`OPERATIONAL`. `ALL` is the
        // collector default, so it must not be rejected — there is simply no
        // config half to add. `CONFIG` alone has nothing to return.
        gnmi::get_request::DataType::All
        | gnmi::get_request::DataType::State
        | gnmi::get_request::DataType::Operational => {}
        gnmi::get_request::DataType::Config => {
            return Err(Status::unimplemented(
                "gNMI Get supports operational state only",
            ));
        }
    }

    validate_encoding(request.encoding)
}

fn validate_encoding(raw: i32) -> Result<(), Status> {
    let encoding = gnmi::Encoding::try_from(raw)
        .map_err(|_| Status::invalid_argument(format!("unknown gNMI encoding {raw}")))?;
    match encoding {
        gnmi::Encoding::Json | gnmi::Encoding::JsonIetf => Ok(()),
        _ => Err(Status::unimplemented(format!(
            "gNMI encoding {} is not supported",
            encoding.as_str_name()
        ))),
    }
}

fn parse_subscription_list(list: &gnmi::SubscriptionList) -> Result<SubscriptionPlan, Status> {
    validate_encoding(list.encoding)?;
    let encoding = gnmi::Encoding::try_from(list.encoding).map_err(|_| {
        Status::invalid_argument(format!("unknown gNMI encoding {}", list.encoding))
    })?;
    let mode = gnmi::subscription_list::Mode::try_from(list.mode)
        .map_err(|_| Status::invalid_argument(format!("unknown Subscribe mode {}", list.mode)))?;
    if list.subscription.is_empty() {
        return Err(Status::invalid_argument(
            "gNMI Subscribe requires at least one subscription",
        ));
    }
    if list.subscription.len() > MAX_SUBSCRIPTIONS {
        return Err(Status::invalid_argument(format!(
            "gNMI Subscribe supports at most {MAX_SUBSCRIPTIONS} paths",
        )));
    }

    let mut paths = Vec::with_capacity(list.subscription.len());
    let mut sample_interval = MIN_SAMPLE_INTERVAL;
    for subscription in &list.subscription {
        validate_subscription_mode(mode, subscription)?;
        let path = subscription
            .path
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("subscription path is required"))?;
        let full_path = combine_paths(list.prefix.as_ref(), path)?;
        paths.push(parse_supported_path(&full_path)?);

        if mode == gnmi::subscription_list::Mode::Stream {
            // Honor the client's requested interval, clamped to
            // [MIN_SAMPLE_INTERVAL, MAX_SAMPLE_INTERVAL] (a missing/zero interval
            // defaults to the floor; an absurd value is capped). The shared sample
            // timer ticks at the *largest* clamped interval across subscriptions
            // so no subscription is sampled faster than it asked for.
            let requested = Duration::from_nanos(subscription.sample_interval)
                .clamp(MIN_SAMPLE_INTERVAL, MAX_SAMPLE_INTERVAL);
            sample_interval = sample_interval.max(requested);
        }
    }

    Ok(SubscriptionPlan {
        mode,
        paths,
        updates_only: list.updates_only,
        sample_interval,
        encoding,
    })
}

fn validate_subscription_mode(
    list_mode: gnmi::subscription_list::Mode,
    subscription: &gnmi::Subscription,
) -> Result<(), Status> {
    let mode = gnmi::SubscriptionMode::try_from(subscription.mode).map_err(|_| {
        Status::invalid_argument(format!("unknown subscription mode {}", subscription.mode))
    })?;
    match list_mode {
        gnmi::subscription_list::Mode::Once | gnmi::subscription_list::Mode::Poll => {
            if mode == gnmi::SubscriptionMode::OnChange {
                Err(Status::unimplemented(
                    "gNMI Subscribe ON_CHANGE is not supported",
                ))
            } else {
                Ok(())
            }
        }
        gnmi::subscription_list::Mode::Stream => match mode {
            gnmi::SubscriptionMode::Sample => Ok(()),
            gnmi::SubscriptionMode::OnChange => Err(Status::unimplemented(
                "gNMI Subscribe ON_CHANGE is not supported",
            )),
            gnmi::SubscriptionMode::TargetDefined => Err(Status::unimplemented(
                "gNMI Subscribe TARGET_DEFINED is not supported",
            )),
        },
    }
}

fn combine_paths(prefix: Option<&gnmi::Path>, path: &gnmi::Path) -> Result<gnmi::Path, Status> {
    // `Path.element` is the deprecated legacy string form; we only support `PathElem`.
    #[allow(deprecated)]
    if prefix.is_some_and(|prefix| !prefix.element.is_empty()) || !path.element.is_empty() {
        return Err(Status::invalid_argument(
            "legacy string path elements are not supported; use PathElem",
        ));
    }

    let mut elem = prefix.map_or_else(Vec::new, |prefix| prefix.elem.clone());
    elem.extend(path.elem.clone());
    Ok(gnmi::Path {
        #[allow(deprecated)]
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
    // Reject the deprecated legacy string path form; structured `PathElem` only.
    #[allow(deprecated)]
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
    // The shortest supported path reaches the `{global,neighbors}` selector at
    // element index 5 (the `bgp` container is element 4):
    // `network-instances/network-instance/protocols/protocol/bgp/{global,neighbors}`.
    // a subtree Get above `/state` (e.g. `.../bgp/global`) is valid and renders
    // the whole supported subtree, so bound-check per level rather than demanding
    // a full leaf path.
    if elem.len() < 6 {
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
    // A bare `.../bgp/global` subtree Get renders both supported global leaves.
    if tail.is_empty() {
        return Ok(SupportedPath::Global { leaf: None });
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
    // A bare `.../bgp/neighbors` subtree Get renders every neighbor's full
    // supported leaf set.
    if tail.is_empty() {
        return Ok(SupportedPath::AllNeighbors {
            select: NeighborSelect::AllState,
        });
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
        // A bare `.../neighbor[addr]` (or `.../neighbors/neighbor`) renders the
        // full supported state leaf set.
        return Ok(match address {
            Some(address) => SupportedPath::Neighbor {
                address,
                select: NeighborSelect::AllState,
            },
            None => SupportedPath::AllNeighbors {
                select: NeighborSelect::AllState,
            },
        });
    }
    expect_no_keys(&tail[1], "state")?;
    let select = parse_neighbor_state_leaf(&tail[2..])?;
    Ok(match address {
        Some(address) => SupportedPath::Neighbor { address, select },
        None => SupportedPath::AllNeighbors { select },
    })
}

fn parse_neighbor_state_leaf(tail: &[gnmi::PathElem]) -> Result<NeighborSelect, Status> {
    // A bare `.../state` container Get renders the full supported state leaf set.
    if tail.is_empty() {
        return Ok(NeighborSelect::AllState);
    }
    let first = &tail[0];
    match first.name.as_str() {
        "neighbor-address" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(NeighborSelect::One(NeighborLeaf::NeighborAddress))
        }
        "enabled" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(NeighborSelect::One(NeighborLeaf::Enabled))
        }
        "peer-as" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(NeighborSelect::One(NeighborLeaf::PeerAs))
        }
        "local-as" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(NeighborSelect::One(NeighborLeaf::LocalAs))
        }
        "session-state" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(NeighborSelect::One(NeighborLeaf::SessionState))
        }
        "established-transitions" if tail.len() == 1 => {
            ensure_no_extra_leaf_keys(first)?;
            Ok(NeighborSelect::One(NeighborLeaf::EstablishedTransitions))
        }
        "messages" => parse_neighbor_messages_leaf(&tail[1..]),
        _ => Err(Status::unimplemented(
            "unsupported OpenConfig BGP neighbor state path",
        )),
    }
}

fn parse_neighbor_messages_leaf(tail: &[gnmi::PathElem]) -> Result<NeighborSelect, Status> {
    // A bare `.../state/messages` container renders only the message counters,
    // not the whole state subtree.
    if tail.is_empty() {
        return Ok(NeighborSelect::Messages);
    }
    expect_name_no_keys(&tail[0], &["sent", "received"])?;
    match (
        tail[0].name.as_str(),
        tail.get(1).map(|elem| elem.name.as_str()),
    ) {
        // A bare `.../messages/sent` or `.../messages/received` container renders
        // only that direction's counters.
        ("sent", None) => Ok(NeighborSelect::MessagesSent),
        ("received", None) => Ok(NeighborSelect::MessagesReceived),
        ("sent", Some("UPDATE")) if tail.len() == 2 => {
            ensure_no_extra_leaf_keys(&tail[1])?;
            Ok(NeighborSelect::One(NeighborLeaf::UpdatesSent))
        }
        ("received", Some("UPDATE")) if tail.len() == 2 => {
            ensure_no_extra_leaf_keys(&tail[1])?;
            Ok(NeighborSelect::One(NeighborLeaf::UpdatesReceived))
        }
        ("sent", Some("NOTIFICATION")) if tail.len() == 2 => {
            ensure_no_extra_leaf_keys(&tail[1])?;
            Ok(NeighborSelect::One(NeighborLeaf::NotificationsSent))
        }
        ("received", Some("NOTIFICATION")) if tail.len() == 2 => {
            ensure_no_extra_leaf_keys(&tail[1])?;
            Ok(NeighborSelect::One(NeighborLeaf::NotificationsReceived))
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

fn render_global_updates(
    asn: u32,
    router_id: &str,
    leaf: Option<GlobalLeaf>,
    encoding: gnmi::Encoding,
) -> Vec<gnmi::Update> {
    let as_update = || leaf_update(global_leaf_path("as"), &LeafValue::U32(asn), encoding);
    let router_id_update = || {
        leaf_update(
            global_leaf_path("router-id"),
            &LeafValue::Str(router_id.to_string()),
            encoding,
        )
    };
    match leaf {
        Some(GlobalLeaf::As) => vec![as_update()],
        Some(GlobalLeaf::RouterId) => vec![router_id_update()],
        None => vec![as_update(), router_id_update()],
    }
}

fn render_neighbor_updates(
    peers: &[PeerInfo],
    local_as: u32,
    address: IpAddr,
    select: NeighborSelect,
    encoding: gnmi::Encoding,
) -> Result<Vec<gnmi::Update>, Status> {
    let peer = peers
        .iter()
        .find(|peer| peer.address == address)
        .ok_or_else(|| Status::not_found(format!("neighbor {address} not found")))?;
    Ok(render_one_neighbor_updates(
        peer, local_as, select, encoding,
    ))
}

fn render_one_neighbor_updates(
    peer: &PeerInfo,
    local_as: u32,
    select: NeighborSelect,
    encoding: gnmi::Encoding,
) -> Vec<gnmi::Update> {
    select
        .leaves()
        .into_iter()
        .map(|leaf| {
            let value = neighbor_leaf_value(peer, local_as, leaf);
            leaf_update(neighbor_leaf_path(peer.address, leaf), &value, encoding)
        })
        .collect()
}

fn neighbor_leaf_value(peer: &PeerInfo, local_as: u32, leaf: NeighborLeaf) -> LeafValue {
    match leaf {
        NeighborLeaf::NeighborAddress => LeafValue::Str(peer.address.to_string()),
        NeighborLeaf::Enabled => LeafValue::Bool(peer.enabled),
        NeighborLeaf::PeerAs => LeafValue::U32(peer.remote_asn),
        // `local-as` is derived from the global ASN: rustbgpd is single-AS and
        // has no per-neighbor local-as override.
        NeighborLeaf::LocalAs => LeafValue::U32(local_as),
        NeighborLeaf::SessionState => LeafValue::Str(session_state_name(peer.state).to_string()),
        // `established-transitions` is sourced from `flap_count`, which counts
        // transitions *out of* Established — an off-by-one approximation of the
        // OpenConfig definition (transitions *into* Established).
        NeighborLeaf::EstablishedTransitions => LeafValue::U64(peer.flap_count),
        NeighborLeaf::UpdatesSent => LeafValue::U64(peer.updates_sent),
        NeighborLeaf::UpdatesReceived => LeafValue::U64(peer.updates_received),
        NeighborLeaf::NotificationsSent => LeafValue::U64(peer.notifications_sent),
        NeighborLeaf::NotificationsReceived => LeafValue::U64(peer.notifications_received),
    }
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
        #[allow(deprecated)]
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
    // `protocol[identifier=BGP][name=BGP]` is hardcoded: rustbgpd runs a single,
    // conventionally-named BGP instance, so the protocol name is always `BGP`.
    gnmi::PathElem {
        name: "protocol".to_string(),
        key: HashMap::from([
            ("identifier".to_string(), "BGP".to_string()),
            ("name".to_string(), DEFAULT_PROTOCOL_NAME.to_string()),
        ]),
    }
}

/// A typed `OpenConfig` leaf value, carried until it is JSON-encoded for the
/// requested gNMI encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
enum LeafValue {
    /// A JSON-string leaf (`router-id`, `neighbor-address`, `session-state`).
    Str(String),
    /// A uint32 leaf rendered as a bare JSON number (`as`, `peer-as`, `local-as`).
    U32(u32),
    /// A uint64 leaf; RFC7951 requires uint64/int64 to be JSON *strings*
    /// (`established-transitions`, the `messages` counters).
    U64(u64),
    /// A boolean leaf rendered as a JSON literal (`enabled`).
    Bool(bool),
}

impl LeafValue {
    /// Render this leaf as a single RFC7951 JSON value (the form used by both
    /// `JSON_IETF` and, for this small scalar set, `JSON`).
    fn to_json_bytes(&self) -> Vec<u8> {
        match self {
            LeafValue::Str(value) => json_quote(value).into_bytes(),
            LeafValue::U32(value) => value.to_string().into_bytes(),
            // RFC7951: 64-bit integers are encoded as JSON strings.
            LeafValue::U64(value) => format!("\"{value}\"").into_bytes(),
            LeafValue::Bool(value) => if *value { "true" } else { "false" }
                .to_string()
                .into_bytes(),
        }
    }
}

/// Quote and escape a string as a JSON string literal.
fn json_quote(value: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                // `write!` to a String is infallible.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn leaf_update(path: gnmi::Path, value: &LeafValue, encoding: gnmi::Encoding) -> gnmi::Update {
    let json = value.to_json_bytes();
    // The requested encoding selects which `TypedValue` oneof carries the leaf:
    // a Get for JSON_IETF/JSON must return RFC7951/JSON bytes, not the scalar
    // PROTO oneof variants (string_val/uint_val/bool_val).
    let typed = match encoding {
        gnmi::Encoding::JsonIetf => gnmi::typed_value::Value::JsonIetfVal(json),
        _ => gnmi::typed_value::Value::JsonVal(json),
    };
    gnmi::Update {
        path: Some(path),
        // `value` is the deprecated pre-`TypedValue` field; we populate `val`.
        #[allow(deprecated)]
        value: None,
        val: Some(gnmi::TypedValue { value: Some(typed) }),
        duplicates: 0,
    }
}

fn sync_response() -> gnmi::SubscribeResponse {
    gnmi::SubscribeResponse {
        response: Some(gnmi::subscribe_response::Response::SyncResponse(true)),
        extension: Vec::new(),
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
        request: Request<tonic::Streaming<gnmi::SubscribeRequest>>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let mut inbound = request.into_inner();
        let first = inbound
            .message()
            .await?
            .ok_or_else(|| Status::invalid_argument("missing initial Subscribe request"))?;
        let list = match first.request {
            Some(gnmi::subscribe_request::Request::Subscribe(list)) => list,
            Some(gnmi::subscribe_request::Request::Poll(_)) => {
                return Err(Status::invalid_argument(
                    "first Subscribe request must carry a subscription list",
                ));
            }
            None => return Err(Status::invalid_argument("empty Subscribe request")),
        };
        let plan = parse_subscription_list(&list)?;

        // Bound concurrent streams (independent of the per-request path cap). The
        // owned permit is held for the lifetime of the stream — moved into the
        // long-lived POLL/STREAM tasks, or kept on the stack across the ONCE
        // render — and is released when the stream ends or the client drops.
        let permit = Arc::clone(&self.subscribe_slots)
            .try_acquire_owned()
            .map_err(|_| {
                Status::resource_exhausted("gNMI Subscribe stream limit reached; try again later")
            })?;

        match plan.mode {
            gnmi::subscription_list::Mode::Once => {
                let responses = self.render_subscription_snapshot(&plan, true).await?;
                drop(permit);
                Ok(Response::new(Box::pin(tokio_stream::iter(
                    responses.into_iter().map(Ok),
                ))))
            }
            gnmi::subscription_list::Mode::Poll => {
                let service = self.clone();
                let (tx, rx) = tokio::sync::mpsc::channel(SUBSCRIBE_CHANNEL_DEPTH);
                tokio::spawn(async move {
                    // Hold the concurrency permit for the lifetime of the task.
                    let _permit = permit;
                    service.run_poll(plan, inbound, tx).await;
                });
                Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
            }
            gnmi::subscription_list::Mode::Stream => {
                let service = self.clone();
                let (tx, rx) = tokio::sync::mpsc::channel(SUBSCRIBE_CHANNEL_DEPTH);
                tokio::spawn(async move {
                    // Hold the concurrency permit for the lifetime of the task.
                    let _permit = permit;
                    service.run_stream_sample(plan, tx).await;
                });
                Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
            }
        }
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
            local_role: None,
            strict_role: false,
            remote_role: None,
            role_negotiated: false,
            add_path_receive: false,
            add_path_send: false,
            add_path_send_max: 1,
            updates_received: 11,
            updates_sent: 12,
            notifications_received: 2,
            notifications_sent: 3,
            otc_routes_blocked: 0,
            import_policy_routes_permitted: 0,
            import_policy_routes_denied: 0,
            export_policy_routes_permitted: 0,
            export_policy_routes_denied: 0,
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

    /// Decode each leaf's `JSON_IETF` value (the encoding used by `get_request`)
    /// into its raw JSON text.
    fn json_ietf_values(response: &gnmi::GetResponse) -> Vec<String> {
        response
            .notification
            .iter()
            .flat_map(|notification| &notification.update)
            .map(
                |update| match update.val.as_ref().unwrap().value.as_ref().unwrap() {
                    gnmi::typed_value::Value::JsonIetfVal(bytes) => {
                        String::from_utf8(bytes.clone()).unwrap()
                    }
                    other => panic!("expected json_ietf_val, got {other:?}"),
                },
            )
            .collect()
    }

    fn subscription_list(
        mode: gnmi::subscription_list::Mode,
        subscription_mode: gnmi::SubscriptionMode,
        path: gnmi::Path,
    ) -> gnmi::SubscriptionList {
        gnmi::SubscriptionList {
            prefix: None,
            subscription: vec![gnmi::Subscription {
                path: Some(path),
                mode: subscription_mode as i32,
                sample_interval: 0,
                suppress_redundant: false,
                heartbeat_interval: 0,
            }],
            qos: None,
            mode: mode as i32,
            allow_aggregation: false,
            use_models: Vec::new(),
            encoding: gnmi::Encoding::JsonIetf as i32,
            updates_only: false,
        }
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

        // `as` is a uint32 (bare JSON number); `router-id` is a JSON string.
        assert_eq!(
            json_ietf_values(&response),
            vec!["65001".to_string(), "\"192.0.2.1\"".to_string()]
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
        // RFC7951: uint32 leaves (peer-as/local-as) are bare numbers; uint64
        // counters (established-transitions, the messages counters) are quoted
        // strings; enabled is a bool literal; address/session-state are strings.
        assert_eq!(
            json_ietf_values(&response),
            vec![
                "\"203.0.113.2\"".to_string(),
                "true".to_string(),
                "65002".to_string(),
                "65001".to_string(),
                "\"ESTABLISHED\"".to_string(),
                "\"4\"".to_string(),
                "\"12\"".to_string(),
                "\"11\"".to_string(),
                "\"3\"".to_string(),
                "\"2\"".to_string(),
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

        // A uint64 counter is a quoted JSON string under RFC7951.
        assert_eq!(json_ietf_values(&response), vec!["\"12\"".to_string()]);
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
        assert_eq!(json_ietf_values(&response), vec!["65001".to_string()]);

        let alias_path = gnmi::Path {
            #[allow(deprecated)]
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
            json_ietf_values(&response),
            vec!["\"192.0.2.1\"".to_string()]
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

    #[test]
    fn leaf_values_render_rfc7951_json() {
        let json = |value: LeafValue| String::from_utf8(value.to_json_bytes()).unwrap();
        // String leaf → quoted JSON string.
        assert_eq!(
            json(LeafValue::Str("ESTABLISHED".to_string())),
            "\"ESTABLISHED\""
        );
        // uint32 leaf → bare JSON number.
        assert_eq!(json(LeafValue::U32(65001)), "65001");
        // uint64 leaf → quoted JSON string (RFC7951).
        assert_eq!(json(LeafValue::U64(42)), "\"42\"");
        // bool leaf → JSON literal.
        assert_eq!(json(LeafValue::Bool(true)), "true");
        assert_eq!(json(LeafValue::Bool(false)), "false");
        // Strings are escaped.
        assert_eq!(json(LeafValue::Str("a\"b\\c".to_string())), r#""a\"b\\c""#);
    }

    #[tokio::test]
    async fn get_uses_requested_encoding_oneof() {
        // JSON_IETF → json_ietf_val.
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
        let value = response.notification[0].update[0]
            .val
            .as_ref()
            .unwrap()
            .value
            .clone()
            .unwrap();
        assert_eq!(
            value,
            gnmi::typed_value::Value::JsonIetfVal(b"65001".to_vec())
        );

        // JSON → json_val.
        let json_request = Request::new(gnmi::GetRequest {
            prefix: None,
            path: vec![mounted_path(&[
                pe("bgp"),
                pe("global"),
                pe("state"),
                pe("as"),
            ])],
            r#type: gnmi::get_request::DataType::State as i32,
            encoding: gnmi::Encoding::Json as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        });
        let response = test_service(Vec::new())
            .get(json_request)
            .await
            .unwrap()
            .into_inner();
        let value = response.notification[0].update[0]
            .val
            .as_ref()
            .unwrap()
            .value
            .clone()
            .unwrap();
        assert_eq!(value, gnmi::typed_value::Value::JsonVal(b"65001".to_vec()));
    }

    #[tokio::test]
    async fn get_bgp_global_subtree_renders_both_leaves() {
        let response = test_service(Vec::new())
            .get(get_request(mounted_path(&[pe("bgp"), pe("global")])))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            json_ietf_values(&response),
            vec!["65001".to_string(), "\"192.0.2.1\"".to_string()]
        );
    }

    #[tokio::test]
    async fn get_bgp_neighbors_subtree_renders_all_neighbors() {
        let peers = vec![
            test_peer("203.0.113.2".parse().unwrap()),
            test_peer("203.0.113.3".parse().unwrap()),
        ];
        let response = test_service(peers)
            .get(get_request(mounted_path(&[pe("bgp"), pe("neighbors")])))
            .await
            .unwrap()
            .into_inner();
        // Two neighbors, ten supported state leaves each.
        assert_eq!(response.notification[0].update.len(), 20);
        // First leaf of each neighbor is its (sorted) address.
        let values = json_ietf_values(&response);
        assert_eq!(values[0], "\"203.0.113.2\"".to_string());
        assert_eq!(values[10], "\"203.0.113.3\"".to_string());
    }

    #[tokio::test]
    async fn get_messages_container_renders_only_counters() {
        let peer = test_peer("203.0.113.2".parse().unwrap());
        let response = test_service(vec![peer])
            .get(get_request(mounted_path(&[
                pe("bgp"),
                pe("neighbors"),
                keyed_pe("neighbor", "neighbor-address", "203.0.113.2"),
                pe("state"),
                pe("messages"),
            ])))
            .await
            .unwrap()
            .into_inner();
        // Only the four message counters (updates sent/received, notifications
        // sent/received) — not the full state subtree.
        assert_eq!(response.notification[0].update.len(), 4);
        assert_eq!(
            json_ietf_values(&response),
            vec![
                "\"12\"".to_string(),
                "\"11\"".to_string(),
                "\"3\"".to_string(),
                "\"2\"".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn multi_path_get_snapshots_peers_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let service = GnmiService::with_peer_snapshot(65001, "192.0.2.1", move || {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            async move { Ok(vec![test_peer("203.0.113.2".parse().unwrap())]) }
        });

        let request = Request::new(gnmi::GetRequest {
            prefix: None,
            path: vec![
                mounted_path(&[
                    pe("bgp"),
                    pe("neighbors"),
                    keyed_pe("neighbor", "neighbor-address", "203.0.113.2"),
                    pe("state"),
                ]),
                mounted_path(&[pe("bgp"), pe("neighbors")]),
            ],
            r#type: gnmi::get_request::DataType::All as i32,
            encoding: gnmi::Encoding::JsonIetf as i32,
            use_models: Vec::new(),
            extension: Vec::new(),
        });
        service.get(request).await.unwrap();
        // Two neighbor paths, but the peer snapshot is fetched exactly once.
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn global_only_get_does_not_snapshot_peers() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_clone = Arc::clone(&calls);
        let service = GnmiService::with_peer_snapshot(65001, "192.0.2.1", move || {
            calls_clone.fetch_add(1, Ordering::SeqCst);
            async move { Ok(Vec::new()) }
        });
        service
            .get(get_request(mounted_path(&[pe("bgp"), pe("global")])))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn subscribe_plan_accepts_once_poll_and_sample() {
        let path = mounted_path(&[pe("bgp"), pe("global"), pe("state")]);

        let once = parse_subscription_list(&subscription_list(
            gnmi::subscription_list::Mode::Once,
            gnmi::SubscriptionMode::TargetDefined,
            path.clone(),
        ))
        .unwrap();
        assert_eq!(once.mode, gnmi::subscription_list::Mode::Once);

        let poll = parse_subscription_list(&subscription_list(
            gnmi::subscription_list::Mode::Poll,
            gnmi::SubscriptionMode::TargetDefined,
            path.clone(),
        ))
        .unwrap();
        assert_eq!(poll.mode, gnmi::subscription_list::Mode::Poll);

        let stream = parse_subscription_list(&subscription_list(
            gnmi::subscription_list::Mode::Stream,
            gnmi::SubscriptionMode::Sample,
            path,
        ))
        .unwrap();
        assert_eq!(stream.mode, gnmi::subscription_list::Mode::Stream);
        assert_eq!(stream.sample_interval, MIN_SAMPLE_INTERVAL);
    }

    #[test]
    fn subscribe_plan_rejects_on_change_target_defined_and_too_many_paths() {
        let path = mounted_path(&[pe("bgp"), pe("global"), pe("state")]);
        let on_change = parse_subscription_list(&subscription_list(
            gnmi::subscription_list::Mode::Stream,
            gnmi::SubscriptionMode::OnChange,
            path.clone(),
        ))
        .unwrap_err();
        assert_eq!(on_change.code(), tonic::Code::Unimplemented);

        let target_defined = parse_subscription_list(&subscription_list(
            gnmi::subscription_list::Mode::Stream,
            gnmi::SubscriptionMode::TargetDefined,
            path.clone(),
        ))
        .unwrap_err();
        assert_eq!(target_defined.code(), tonic::Code::Unimplemented);

        let mut too_many = subscription_list(
            gnmi::subscription_list::Mode::Once,
            gnmi::SubscriptionMode::TargetDefined,
            path.clone(),
        );
        too_many.subscription = (0..=MAX_SUBSCRIPTIONS)
            .map(|_| gnmi::Subscription {
                path: Some(path.clone()),
                mode: gnmi::SubscriptionMode::TargetDefined as i32,
                sample_interval: 0,
                suppress_redundant: false,
                heartbeat_interval: 0,
            })
            .collect();
        let err = parse_subscription_list(&too_many).unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn subscribe_snapshot_reuses_get_renderer_and_emits_sync() {
        let service = test_service(Vec::new());
        let plan = parse_subscription_list(&subscription_list(
            gnmi::subscription_list::Mode::Once,
            gnmi::SubscriptionMode::TargetDefined,
            mounted_path(&[pe("bgp"), pe("global"), pe("state")]),
        ))
        .unwrap();

        let responses = service
            .render_subscription_snapshot(&plan, true)
            .await
            .unwrap();
        assert_eq!(responses.len(), 2);
        assert!(matches!(
            responses[0].response,
            Some(gnmi::subscribe_response::Response::Update(_))
        ));
        assert_eq!(
            responses[1].response,
            Some(gnmi::subscribe_response::Response::SyncResponse(true))
        );
    }

    /// Build a single-path STREAM/SAMPLE subscription list with an explicit
    /// `sample_interval` (in nanoseconds) so the interval-floor logic is testable.
    fn stream_sample_list(sample_interval_nanos: u64) -> gnmi::SubscriptionList {
        gnmi::SubscriptionList {
            prefix: None,
            subscription: vec![gnmi::Subscription {
                path: Some(mounted_path(&[pe("bgp"), pe("global"), pe("state")])),
                mode: gnmi::SubscriptionMode::Sample as i32,
                sample_interval: sample_interval_nanos,
                suppress_redundant: false,
                heartbeat_interval: 0,
            }],
            qos: None,
            mode: gnmi::subscription_list::Mode::Stream as i32,
            allow_aggregation: false,
            use_models: Vec::new(),
            encoding: gnmi::Encoding::JsonIetf as i32,
            updates_only: false,
        }
    }

    #[test]
    fn stream_sample_interval_honors_request_above_floor() {
        // A 5s request is kept as-is (it is already above the 1s floor).
        let plan = parse_subscription_list(&stream_sample_list(5_000_000_000)).unwrap();
        assert_eq!(plan.sample_interval, Duration::from_secs(5));
    }

    #[test]
    fn stream_sample_interval_raises_sub_floor_request_to_floor() {
        // A 1ms request is raised up to the 1s floor.
        let plan = parse_subscription_list(&stream_sample_list(1_000_000)).unwrap();
        assert_eq!(plan.sample_interval, MIN_SAMPLE_INTERVAL);
    }

    #[test]
    fn stream_sample_interval_defaults_zero_to_floor() {
        // A missing/zero interval defaults to the floor.
        let plan = parse_subscription_list(&stream_sample_list(0)).unwrap();
        assert_eq!(plan.sample_interval, MIN_SAMPLE_INTERVAL);
    }

    #[test]
    fn stream_sample_interval_caps_absurd_request_to_ceiling() {
        // An absurd interval (u64::MAX ns ≈ centuries) is capped to the ceiling.
        let plan = parse_subscription_list(&stream_sample_list(u64::MAX)).unwrap();
        assert_eq!(plan.sample_interval, MAX_SAMPLE_INTERVAL);
    }

    #[test]
    fn stream_sample_interval_takes_largest_floored_across_subscriptions() {
        // The shared sample timer ticks at the largest floored interval so no
        // subscription is sampled faster than it requested.
        let path = mounted_path(&[pe("bgp"), pe("global"), pe("state")]);
        let subscription = |nanos| gnmi::Subscription {
            path: Some(path.clone()),
            mode: gnmi::SubscriptionMode::Sample as i32,
            sample_interval: nanos,
            suppress_redundant: false,
            heartbeat_interval: 0,
        };
        let list = gnmi::SubscriptionList {
            prefix: None,
            subscription: vec![
                subscription(0),             // -> floor (1s)
                subscription(2_000_000_000), // -> 2s
                subscription(1_000_000),     // -> floor (1s)
            ],
            qos: None,
            mode: gnmi::subscription_list::Mode::Stream as i32,
            allow_aggregation: false,
            use_models: Vec::new(),
            encoding: gnmi::Encoding::JsonIetf as i32,
            updates_only: false,
        };
        let plan = parse_subscription_list(&list).unwrap();
        assert_eq!(plan.sample_interval, Duration::from_secs(2));
    }

    // --- Subscribe RPC-level harness ---------------------------------------
    //
    // Drives the real `subscribe` RPC over an in-process TCP server+client so the
    // bidi stream (and interactive POLL) exercise the full codec path, matching
    // the CLI crate's mock-server pattern.

    use crate::gnmi::g_nmi_client::GNmiClient;
    use crate::gnmi::g_nmi_server::GNmiServer;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::{Channel, Server};

    struct SubscribeHarness {
        client: GNmiClient<Channel>,
        shutdown: Option<oneshot::Sender<()>>,
    }

    impl Drop for SubscribeHarness {
        fn drop(&mut self) {
            if let Some(tx) = self.shutdown.take() {
                let _ = tx.send(());
            }
        }
    }

    async fn serve(service: GnmiService) -> SubscribeHarness {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        tokio::spawn(async move {
            Server::builder()
                .add_service(GNmiServer::new(service))
                .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async {
                    let _ = shutdown_rx.await;
                })
                .await
                .unwrap();
        });
        let channel = Channel::from_shared(format!("http://{addr}"))
            .unwrap()
            .connect()
            .await
            .unwrap();
        SubscribeHarness {
            client: GNmiClient::new(channel),
            shutdown: Some(shutdown_tx),
        }
    }

    fn subscribe_msg(list: gnmi::SubscriptionList) -> gnmi::SubscribeRequest {
        gnmi::SubscribeRequest {
            request: Some(gnmi::subscribe_request::Request::Subscribe(list)),
            extension: Vec::new(),
        }
    }

    fn poll_msg() -> gnmi::SubscribeRequest {
        gnmi::SubscribeRequest {
            request: Some(gnmi::subscribe_request::Request::Poll(gnmi::Poll {})),
            extension: Vec::new(),
        }
    }

    #[tokio::test]
    async fn subscribe_once_streams_update_then_sync_then_ends() {
        let mut harness = serve(test_service(Vec::new())).await;
        let list = subscription_list(
            gnmi::subscription_list::Mode::Once,
            gnmi::SubscriptionMode::TargetDefined,
            mounted_path(&[pe("bgp"), pe("global"), pe("state")]),
        );
        let mut stream = harness
            .client
            .subscribe(tokio_stream::iter(vec![subscribe_msg(list)]))
            .await
            .unwrap()
            .into_inner();

        let first = stream.message().await.unwrap().unwrap();
        assert!(matches!(
            first.response,
            Some(gnmi::subscribe_response::Response::Update(_))
        ));
        let second = stream.message().await.unwrap().unwrap();
        assert_eq!(
            second.response,
            Some(gnmi::subscribe_response::Response::SyncResponse(true))
        );
        // ONCE closes the stream after the sync.
        assert!(stream.message().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn subscribe_poll_sends_initial_snapshot_then_per_poll() {
        let mut harness = serve(test_service(Vec::new())).await;
        let list = subscription_list(
            gnmi::subscription_list::Mode::Poll,
            gnmi::SubscriptionMode::TargetDefined,
            mounted_path(&[pe("bgp"), pe("global"), pe("state")]),
        );
        // A channel-backed request stream so we can interleave Poll requests.
        let (req_tx, req_rx) = tokio::sync::mpsc::channel(4);
        req_tx.send(subscribe_msg(list)).await.unwrap();
        let mut stream = harness
            .client
            .subscribe(ReceiverStream::new(req_rx))
            .await
            .unwrap()
            .into_inner();

        // POLL emits the initial data tree once, then a sync.
        let first = stream.message().await.unwrap().unwrap();
        assert!(matches!(
            first.response,
            Some(gnmi::subscribe_response::Response::Update(_))
        ));
        assert_eq!(
            stream.message().await.unwrap().unwrap().response,
            Some(gnmi::subscribe_response::Response::SyncResponse(true))
        );

        // A Poll triggers a fresh snapshot (update + sync).
        req_tx.send(poll_msg()).await.unwrap();
        assert!(matches!(
            stream.message().await.unwrap().unwrap().response,
            Some(gnmi::subscribe_response::Response::Update(_))
        ));
        assert_eq!(
            stream.message().await.unwrap().unwrap().response,
            Some(gnmi::subscribe_response::Response::SyncResponse(true))
        );
    }

    #[tokio::test]
    async fn subscribe_stream_sample_emits_initial_sync_and_resamples() {
        let mut harness = serve(test_service(Vec::new())).await;
        // 1s floor; a couple of ticks is enough to confirm resampling.
        let mut stream = harness
            .client
            .subscribe(tokio_stream::iter(vec![subscribe_msg(stream_sample_list(
                0,
            ))]))
            .await
            .unwrap()
            .into_inner();

        // First sample: update then sync.
        assert!(matches!(
            stream.message().await.unwrap().unwrap().response,
            Some(gnmi::subscribe_response::Response::Update(_))
        ));
        assert_eq!(
            stream.message().await.unwrap().unwrap().response,
            Some(gnmi::subscribe_response::Response::SyncResponse(true))
        );
        // Second sample (after the floor): a fresh update, no repeated sync.
        assert!(matches!(
            stream.message().await.unwrap().unwrap().response,
            Some(gnmi::subscribe_response::Response::Update(_))
        ));
        // Dropping the client end lets the sample task exit promptly via select!.
        drop(stream);
    }

    #[tokio::test]
    async fn subscribe_concurrency_cap_returns_resource_exhausted() {
        // A service whose concurrency ceiling is exhausted by a single live
        // stream rejects the next Subscribe with RESOURCE_EXHAUSTED.
        let mut service = test_service(Vec::new());
        service.subscribe_slots = Arc::new(tokio::sync::Semaphore::new(1));
        let mut harness = serve(service).await;

        // Open a long-lived STREAM that holds the only permit. Keep the stream
        // handle alive (it owns the permit) for the rest of the test.
        let mut held = harness
            .client
            .subscribe(tokio_stream::iter(vec![subscribe_msg(stream_sample_list(
                0,
            ))]))
            .await
            .unwrap()
            .into_inner();
        // Drain the first sample so the server task is definitely running and
        // holding its permit before the second subscribe races in.
        let _ = held.message().await.unwrap();

        // The handler rejects before opening the response stream, so the status
        // surfaces either on the initial `subscribe` call or on the first
        // `message()` of the returned (trailers-only) stream.
        let err = match harness
            .client
            .subscribe(tokio_stream::iter(vec![subscribe_msg(stream_sample_list(
                0,
            ))]))
            .await
        {
            Err(status) => status,
            Ok(response) => response
                .into_inner()
                .message()
                .await
                .expect_err("expected a RESOURCE_EXHAUSTED status, got a message"),
        };
        assert_eq!(err.code(), tonic::Code::ResourceExhausted);
    }
}
