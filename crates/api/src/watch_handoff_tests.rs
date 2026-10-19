//! Reconnect handoff for automation clients without durable replay: open
//! `WatchEvents`, await only its response headers, then read state. Every
//! transition after that read must arrive on the stream.
//!
//! Both services run behind one real HTTP/2 server on an in-memory duplex
//! pipe, on a paused current-thread runtime. The fake peer manager answers a
//! session subscription only after a paused-clock delay, which completes only
//! once every other task is blocked. A server that sent headers before
//! subscribing would let the client read state and see the transition land
//! before the receiver existed.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use rustbgpd_fsm::SessionState;
use rustbgpd_rib::{
    EffectiveDistributionMode, NeighborRibSnapshot, NeighborRibSnapshotResponse, RibUpdate,
};
use tokio::sync::{broadcast, mpsc};
use tonic::transport::{Channel, Endpoint, Server, Uri};

use crate::NeighborService;
use crate::event_service::EventService;
use crate::peer_types::{
    PeerManagerCommand, SessionEvent, SessionLifecycleEvent, SessionLifecycleEventType,
};
use crate::proto;
use crate::proto::event_service_client::EventServiceClient;
use crate::proto::event_service_server::EventServiceServer;
use crate::proto::neighbor_service_client::NeighborServiceClient;
use crate::proto::neighbor_service_server::NeighborServiceServer;
use crate::server::AccessMode;
use crate::test_support::peer_info;

const PEER: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2));
/// Paused-clock latency of the subscription reply; it elapses only when the
/// runtime is otherwise idle.
const SUBSCRIBE_LATENCY: Duration = Duration::from_secs(1);
/// Hang guard on the paused clock; it fires only when nothing else can run.
const NO_MORE_EVENTS: Duration = Duration::from_secs(60);

/// One peer whose session state is readable through `ListNeighbors`.
#[derive(Clone)]
struct FakeDaemon {
    state: Arc<Mutex<SessionState>>,
    events: broadcast::Sender<Arc<SessionEvent>>,
}

impl FakeDaemon {
    fn new(state: SessionState) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
            events: broadcast::channel(16).0,
        }
    }

    /// The session changes state before the peer manager publishes the
    /// transition, as `try_send_lifecycle_state_changed` follows the FSM
    /// state change in the daemon.
    fn transition(&self, event_type: SessionLifecycleEventType, new: SessionState) {
        let old = std::mem::replace(&mut *self.state.lock().unwrap(), new);
        let _ = self
            .events
            .send(Arc::new(SessionEvent::Lifecycle(SessionLifecycleEvent {
                event_type,
                peer: PEER,
                peer_label: None,
                timestamp: "0".to_string(),
                old_state: Some(old),
                new_state: Some(new),
                session_role: Some("primary".to_string()),
                reason: String::new(),
            })));
    }

    fn spawn_peer_manager(&self) -> mpsc::Sender<PeerManagerCommand> {
        let (tx, mut rx) = mpsc::channel(16);
        let daemon = self.clone();
        tokio::spawn(async move {
            while let Some(command) = rx.recv().await {
                match command {
                    PeerManagerCommand::ListPeers { reply } => {
                        let mut peer = peer_info(PEER);
                        peer.state = *daemon.state.lock().unwrap();
                        let _ = reply.send(vec![peer]);
                    }
                    PeerManagerCommand::SubscribeSessionEvents { reply } => {
                        let events = daemon.events.clone();
                        tokio::spawn(async move {
                            tokio::time::sleep(SUBSCRIBE_LATENCY).await;
                            let _ = reply.send(events.subscribe());
                        });
                    }
                    _ => panic!("unexpected peer-manager command"),
                }
            }
        });
        tx
    }
}

fn spawn_rib() -> mpsc::Sender<RibUpdate> {
    let (tx, mut rx) = mpsc::channel(16);
    tokio::spawn(async move {
        while let Some(update) = rx.recv().await {
            let RibUpdate::QueryNeighborRibSnapshots { peers, reply, .. } = update else {
                panic!("unexpected RIB query");
            };
            let snapshots = peers
                .into_iter()
                .map(|peer| NeighborRibSnapshot {
                    peer,
                    advertised_count: 0,
                    policy_stats: rustbgpd_rib::NeighborPolicyStats::default(),
                    outbound: rustbgpd_rib::PeerOutboundState {
                        update_group: String::new(),
                        effective_distribution_mode: EffectiveDistributionMode::Unknown,
                        selection_deferral: Vec::new(),
                        outbound_prefix_limits: Vec::new(),
                    },
                    remote_asn: None,
                    gr_retention: Vec::new(),
                    outbound_resync: rustbgpd_rib::OutboundResyncState::default(),
                })
                .collect();
            let _ = reply.send(NeighborRibSnapshotResponse {
                snapshots,
                comparison: None,
                retained: Vec::new(),
            });
        }
    });
    tx
}

async fn connect(
    daemon: &FakeDaemon,
) -> (EventServiceClient<Channel>, NeighborServiceClient<Channel>) {
    let peer_tx = daemon.spawn_peer_manager();
    let rib_tx = spawn_rib();
    let events = EventService::new(rib_tx.clone(), peer_tx.clone());
    let neighbors = NeighborService::new(65001, AccessMode::ReadOnly, peer_tx, rib_tx, None);
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    tokio::spawn(
        Server::builder()
            .add_service(EventServiceServer::new(events))
            .add_service(NeighborServiceServer::new(neighbors))
            .serve_with_incoming(tokio_stream::once(Ok::<_, std::io::Error>(server_io))),
    );
    let mut client_io = Some(client_io);
    let channel = Endpoint::from_static("http://watch-handoff.test")
        .connect_with_connector(tower::service_fn(move |_: Uri| {
            let io = client_io.take();
            async move {
                io.map(TokioIo::new)
                    .ok_or_else(|| std::io::Error::other("reused"))
            }
        }))
        .await
        .unwrap();
    (
        EventServiceClient::new(channel.clone()),
        NeighborServiceClient::new(channel),
    )
}

/// Resolves when the response headers arrive, not on a first event.
async fn open_session_watch(
    client: &mut EventServiceClient<Channel>,
) -> tonic::Streaming<proto::BgpEvent> {
    client
        .watch_events(proto::WatchEventsRequest {
            categories: vec![proto::EventCategory::Session as i32],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner()
}

async fn read_state(client: &mut NeighborServiceClient<Channel>) -> proto::SessionState {
    let neighbors = client
        .list_neighbors(proto::ListNeighborsRequest::default())
        .await
        .unwrap()
        .into_inner()
        .neighbors;
    assert_eq!(neighbors.len(), 1);
    neighbors[0].state()
}

/// `(old_state, new_state)` of the next session event, or `None` when the
/// stream has nothing more to deliver.
async fn next_transition(
    stream: &mut tonic::Streaming<proto::BgpEvent>,
) -> Option<(String, String)> {
    let event = tokio::time::timeout(NO_MORE_EVENTS, stream.message())
        .await
        .ok()?
        .unwrap()?;
    let Some(proto::bgp_event::Payload::Session(session)) = event.payload else {
        panic!("expected a session event, got {event:?}");
    };
    Some((session.old_state, session.new_state))
}

fn states(old: SessionState, new: SessionState) -> (String, String) {
    (old.as_str().to_string(), new.as_str().to_string())
}

/// Load-bearing break: returning the `WatchEvents` response before the
/// session subscription completes (for example, subscribing on the stream's
/// first poll) loses the transition below.
#[tokio::test(start_paused = true)]
async fn watch_opened_before_the_state_read_carries_the_next_transition() {
    let daemon = FakeDaemon::new(SessionState::Established);
    let (mut events, mut neighbors) = connect(&daemon).await;

    let mut stream = open_session_watch(&mut events).await;
    assert_eq!(
        read_state(&mut neighbors).await,
        proto::SessionState::Established
    );
    daemon.transition(SessionLifecycleEventType::Lost, SessionState::Idle);

    assert_eq!(
        next_transition(&mut stream).await,
        Some(states(SessionState::Established, SessionState::Idle)),
        "the transition after the state read must reach the watch",
    );
}

/// The wrong order: a transition between the state read and the watch is
/// lost. The client still believes the session is established, and the
/// first event it receives starts from a state it never saw.
#[tokio::test(start_paused = true)]
async fn state_read_before_the_watch_misses_a_transition_in_the_gap() {
    let daemon = FakeDaemon::new(SessionState::Established);
    let (mut events, mut neighbors) = connect(&daemon).await;

    assert_eq!(
        read_state(&mut neighbors).await,
        proto::SessionState::Established
    );
    daemon.transition(SessionLifecycleEventType::Lost, SessionState::Idle);
    let mut stream = open_session_watch(&mut events).await;
    daemon.transition(
        SessionLifecycleEventType::StateChanged,
        SessionState::Connect,
    );

    assert_eq!(
        next_transition(&mut stream).await,
        Some(states(SessionState::Idle, SessionState::Connect)),
    );
    assert_eq!(next_transition(&mut stream).await, None);
}
