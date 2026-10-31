//! A `[[dynamic_neighbors]]` member whose session ends keeps its RIB identity
//! while graceful restart may still hold routes on either side: the routes
//! the RIB retains for it, and ours it may retain as our helper (RFC 4724
//! §4.2). A reconnect at the address within that window resumes as the same
//! RIB peer; one that never comes is deleted once both retentions lapse.
//! Each test drives the real peer manager into a real RIB.

use super::inbound_admission::localhost_inbound_stream;
use super::*;

use rustbgpd_rib::update::OutboundRouteUpdate;
use rustbgpd_rib::{PeerEndpoint, PeerId, PeerRetention, RibManager};

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const MEMBER: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));

/// A dynamic-range manager wired to a running RIB.
fn manager_with_rib() -> (
    PeerManager,
    mpsc::Sender<RibUpdate>,
    tokio::task::JoinHandle<()>,
) {
    let (rib_tx, rib_rx) = mpsc::channel(64);
    let (_query_tx, query_rx) = mpsc::channel(4);
    let rib = RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new());
    let rib_task = tokio::spawn(rib.run());
    let mgr = PeerManager::new_with_config(
        mpsc::channel(16).1,
        mpsc::channel(1).1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx.clone(),
        None,
        None,
        make_dynamic_manager_config(),
    );
    (mgr, rib_tx, rib_task)
}

/// Accept the member through the real inbound path. Returns the client end,
/// which must stay open.
async fn accept(mgr: &mut PeerManager) -> TcpStream {
    let (server, client) = localhost_inbound_stream().await;
    mgr.handle_inbound(server, sock(MEMBER), None, None).await;
    assert!(
        mgr.peers.contains_key(&key(MEMBER)),
        "the member is accepted"
    );
    assert!(
        mgr.peers[&key(MEMBER)]
            .transport_config
            .peer
            .graceful_restart,
        "the range's group has graceful restart on by default"
    );
    client
}

/// The member's RIB identity, as its session resolves it once the OPEN
/// validates: the slot's handle, or a new one for an empty slot.
fn open_validated(mgr: &mut PeerManager) -> PeerId {
    let slot = &mgr.peers[&key(MEMBER)].transport_config.rib_peer;
    if let Some(peer) = slot.get() {
        return peer;
    }
    let peer = PeerId::allocate(PeerEndpoint::new(MEMBER, None));
    let slot = rustbgpd_transport::RibPeerSlot::assigned(peer);
    mgr.peers
        .get_mut(&key(MEMBER))
        .unwrap()
        .transport_config
        .rib_peer = slot.clone();
    mgr.rib_peers.insert(key(MEMBER), slot);
    peer
}

/// The member's session goes idle.
async fn idle(mgr: &mut PeerManager) {
    let session_id = mgr.peers[&key(MEMBER)].session_id();
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id,
        role: rustbgpd_transport::SessionRole::Primary,
        peer_addr: MEMBER,
    })
    .await;
    assert!(mgr.peers.is_empty(), "the idle member leaves the inventory");
}

/// A session of `peer` whose OPEN made it our GR helper (`helper`) and
/// listed IPv4 unicast for its own retention (`restarting` marks the
/// session after its restart); ORF-gated when `orf`.
fn session(
    peer: PeerId,
    session_id: u64,
    helper: bool,
    restarting: bool,
    orf: bool,
    outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
) -> [RibUpdate; 2] {
    [
        RibUpdate::SetPeerGracefulRestartContext {
            peer,
            session_id,
            peer_restart_state: restarting,
            peer_gr_helper: helper,
            peer_gr_families: vec![FAMILY],
            peer_enhanced_refresh: true,
            peer_llgr_families: vec![],
            local_llgr_stale_time: 0,
        },
        RibUpdate::PeerUp {
            per_client_best: false,
            interpret_rfc1997: true,
            session_id,
            peer,
            peer_asn: 65002,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: None,
            sendable_families: vec![FAMILY],
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: if orf { vec![FAMILY] } else { vec![] },
            negotiated_llgr_families: vec![],
        },
    ]
}

fn route(peer: PeerId, octet: u8) -> rustbgpd_rib::Route {
    rustbgpd_rib::Route {
        prefix: rustbgpd_wire::Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
            Ipv4Addr::new(198, 51, 100, octet),
            32,
        )),
        next_hop: MEMBER,
        link_local_next_hop: None,
        next_hop_scope: None,
        peer,
        attributes: rustbgpd_rib::AttrSet::new(vec![rustbgpd_wire::PathAttribute::Origin(
            rustbgpd_wire::Origin::Igp,
        )]),
        received_at: rustbgpd_rib::route::ReceivedAt::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
    }
}

fn announce(peer: PeerId, session_id: u64, octets: impl IntoIterator<Item = u8>) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer,
        session_id,
        announced: octets.into_iter().map(|octet| route(peer, octet)).collect(),
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

/// The member's session ends with GR retention, as its teardown reports it.
fn graceful_end(peer: PeerId, session_id: u64) -> RibUpdate {
    RibUpdate::PeerGracefulRestart {
        peer,
        session_id,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![FAMILY],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    }
}

async fn send_all(rib_tx: &mpsc::Sender<RibUpdate>, updates: impl IntoIterator<Item = RibUpdate>) {
    for update in updates {
        rib_tx.send(update).await.unwrap();
    }
}

async fn retention(rib_tx: &mpsc::Sender<RibUpdate>, peer: PeerId) -> PeerRetention {
    let (reply, response) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryPeerRetention { peer, reply })
        .await
        .unwrap();
    response.await.unwrap()
}

async fn loc_rib_count(rib_tx: &mpsc::Sender<RibUpdate>) -> usize {
    let (reply, response) = oneshot::channel();
    rib_tx
        .send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    response.await.unwrap()
}

/// Whether any update queued so far carries the family's End-of-RIB.
async fn end_of_rib_sent(
    rib_tx: &mpsc::Sender<RibUpdate>,
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> bool {
    loc_rib_count(rib_tx).await;
    let mut sent = false;
    while let Ok(update) = rx.try_recv() {
        sent |= update.end_of_rib.contains(&FAMILY);
    }
    sent
}

/// The ticket's shape: a GR member drops, the RIB retains its routes, and it
/// reconnects inside the restart time. The reconnect is the same RIB peer,
/// so its End-of-RIB ends the retention: the route it re-sent stays, the rest
/// are swept. Red proof: deleting the member at idle, as before, purges the
/// retained routes at once and gives the reconnect a new handle.
#[tokio::test]
async fn retained_member_reconnects_as_the_same_peer_and_its_eor_ends_retention() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let _first = accept(&mut mgr).await;
    let peer = open_validated(&mut mgr);
    let (tx, _rx) = mpsc::channel(16);
    send_all(&rib_tx, session(peer, 1, false, false, false, tx)).await;
    send_all(&rib_tx, [announce(peer, 1, 1..=3), graceful_end(peer, 1)]).await;

    idle(&mut mgr).await;
    assert_eq!(
        retention(&rib_tx, peer).await.stale_routes,
        3,
        "the RIB still retains the member's routes"
    );
    assert_eq!(loc_rib_count(&rib_tx).await, 3);
    assert_eq!(
        mgr.dynamic_peer_count, 1,
        "the retained member keeps its slot"
    );

    let _second = accept(&mut mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 1, "the reconnect reuses that slot");
    let resumed = open_validated(&mut mgr);
    assert_eq!(resumed, peer, "the reconnect resumes on the same handle");
    let (tx, _rx) = mpsc::channel(16);
    send_all(&rib_tx, session(peer, 2, false, true, false, tx)).await;
    send_all(
        &rib_tx,
        [
            announce(peer, 2, [1]),
            RibUpdate::EndOfRib {
                peer,
                session_id: 2,
                afi: FAMILY.0,
                safi: FAMILY.1,
            },
        ],
    )
    .await;
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 0);
    assert_eq!(
        loc_rib_count(&rib_tx).await,
        1,
        "End-of-RIB swept what the member did not re-send"
    );
    rib_task.abort();
}

/// A member that never returns is deleted once both retentions lapse: the
/// RIB's GR timer sweeps its routes, and as our helper it may hold ours for
/// our restart time plus a hold time; then its identity is released and
/// its slot freed. Red proof: deleting at idle purges the routes before
/// their restart time; keeping the member past both windows never frees it.
#[tokio::test(start_paused = true)]
async fn retained_member_that_never_returns_is_deleted_after_both_retentions() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let _first = accept(&mut mgr).await;
    let peer = open_validated(&mut mgr);
    let config = mgr.peers[&key(MEMBER)].transport_config.peer.clone();
    let ours = Duration::from_secs(
        u64::from(config.gr_restart_time)
            + u64::from(config.llgr_stale_time)
            + u64::from(config.hold_time),
    );
    let (tx, _rx) = mpsc::channel(16);
    send_all(&rib_tx, session(peer, 1, true, false, false, tx)).await;
    send_all(&rib_tx, [announce(peer, 1, 1..=3), graceful_end(peer, 1)]).await;
    let ended = tokio::time::Instant::now();

    idle(&mut mgr).await;
    let retained = retention(&rib_tx, peer).await;
    assert_eq!(retained.stale_routes, 3);
    assert!(retained.peer_may_retain_ours);
    assert_eq!(
        mgr.next_retained_dynamic_check(),
        retained.next_deadline,
        "checked again at the RIB's GR timer"
    );

    // The GR timer sweeps the routes; the member may still hold ours.
    tokio::time::sleep_until(ended + Duration::from_secs(121)).await;
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 0);
    mgr.settle_due_retained_dynamic().await;
    assert_eq!(
        mgr.dynamic_peer_count, 1,
        "kept while the member may hold ours"
    );
    assert!(peer.is_live());

    tokio::time::sleep_until(ended + ours + Duration::from_secs(1)).await;
    mgr.settle_due_retained_dynamic().await;
    assert_eq!(mgr.dynamic_peer_count, 0, "deleted once both have lapsed");
    assert_eq!(mgr.next_retained_dynamic_check(), None);
    assert!(!mgr.rib_peers.contains_key(&key(MEMBER)));
    loc_rib_count(&rib_tx).await;
    assert!(!peer.is_live(), "its identity is released");
    rib_task.abort();
}

/// LAN-2741's shape through the real path: an ORF-gated GR helper goes idle
/// with nothing retained on our side, and reconnects. The helper may still
/// hold our routes stale and drops them at our End-of-RIB, so the
/// reconnect's End-of-RIB waits for the gated table as a configured
/// neighbor's does. Red proof: deleting the member at idle forgets that, and
/// the End-of-RIB goes out at once.
#[tokio::test]
async fn retained_helper_reconnect_keeps_its_orf_end_of_rib_hold() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let _first = accept(&mut mgr).await;
    let peer = open_validated(&mut mgr);
    let (tx, _rx) = mpsc::channel(16);
    send_all(&rib_tx, session(peer, 1, true, false, true, tx)).await;
    send_all(
        &rib_tx,
        [RibUpdate::PeerDown {
            peer,
            session_id: 1,
        }],
    )
    .await;

    idle(&mut mgr).await;
    let _second = accept(&mut mgr).await;
    let resumed = open_validated(&mut mgr);
    let (tx, mut rx) = mpsc::channel(16);
    send_all(&rib_tx, session(resumed, 2, true, false, true, tx)).await;
    assert!(
        !end_of_rib_sent(&rib_tx, &mut rx).await,
        "the ORF-gated End-of-RIB waits for the gated table"
    );
    send_all(
        &rib_tx,
        [RibUpdate::RouteRefreshRequest {
            queued: Arc::default(),
            peer: resumed,
            session_id: 2,
            afi: FAMILY.0,
            safi: FAMILY.1,
        }],
    )
    .await;
    assert!(
        end_of_rib_sent(&rib_tx, &mut rx).await,
        "the refresh's table carries the held End-of-RIB"
    );
    rib_task.abort();
}

/// A member with nothing retained either way is deleted at idle, as before,
/// and a range removal deletes a retained one at once.
#[tokio::test]
async fn unretained_member_goes_at_idle_and_a_removed_range_takes_a_retained_one() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let _first = accept(&mut mgr).await;
    let peer = open_validated(&mut mgr);
    let (tx, _rx) = mpsc::channel(16);
    send_all(&rib_tx, session(peer, 1, false, false, false, tx)).await;
    send_all(
        &rib_tx,
        [RibUpdate::PeerDown {
            peer,
            session_id: 1,
        }],
    )
    .await;
    idle(&mut mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert_eq!(mgr.next_retained_dynamic_check(), None);

    let _second = accept(&mut mgr).await;
    let peer = open_validated(&mut mgr);
    let (tx, _rx) = mpsc::channel(16);
    send_all(&rib_tx, session(peer, 2, false, false, false, tx)).await;
    send_all(&rib_tx, [announce(peer, 2, [1]), graceful_end(peer, 2)]).await;
    idle(&mut mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 1);
    mgr.delete_dynamic_range("127.0.0.0/8").unwrap();
    assert!(mgr.next_retained_dynamic_check() <= Some(tokio::time::Instant::now()));
    mgr.settle_due_retained_dynamic().await;
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 0);
    rib_task.abort();
}

/// Retain the member once: accepted, its OPEN validated, its routes
/// retained by a GR end, then idle. Returns its handle.
async fn retained_member(mgr: &mut PeerManager, rib_tx: &mpsc::Sender<RibUpdate>) -> PeerId {
    let _client = accept(mgr).await;
    let peer = open_validated(mgr);
    let (tx, _rx) = mpsc::channel(16);
    send_all(rib_tx, session(peer, 1, false, false, false, tx)).await;
    send_all(rib_tx, [announce(peer, 1, [1]), graceful_end(peer, 1)]).await;
    idle(mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 1, "the member is retained");
    peer
}

/// A configuration rollback that drops the member's range deletes a
/// retained member at once, with the live ones it reaps.
#[tokio::test]
async fn rollback_without_the_range_deletes_a_retained_member_at_once() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let peer = retained_member(&mut mgr, &rib_tx).await;
    mgr.dynamic_ranges.clear();
    assert_eq!(
        mgr.reap_dynamic_peers_not_allowed_by_current_ranges().await,
        1
    );
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert_eq!(mgr.next_retained_dynamic_check(), None);
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 0);
    rib_task.abort();
}

/// A static neighbor added at a retained member's address is a new
/// neighbor: the member is deleted first, and the neighbor gets its own
/// handle, not the member's retained routes.
#[tokio::test]
async fn static_neighbor_at_a_retained_address_replaces_the_member() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let peer = retained_member(&mut mgr, &rib_tx).await;
    mgr.add_peer(make_config(MEMBER, 65002), false)
        .await
        .unwrap();
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert_eq!(mgr.next_retained_dynamic_check(), None);
    assert_ne!(
        mgr.rib_peer_of(&key(MEMBER)),
        peer,
        "the static neighbor has its own handle"
    );
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 0);
    rib_task.abort();
}

/// A retained member keeps its place under `dynamic_neighbor_limit`: at the
/// limit another address is refused, and the member's reconnect is admitted
/// into the place it holds.
#[tokio::test]
async fn retained_member_holds_its_place_under_the_limit() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    mgr.dynamic_neighbor_limit = 1;
    retained_member(&mut mgr, &rib_tx).await;
    let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));
    let (server, _refused) = localhost_inbound_stream().await;
    mgr.handle_inbound(server, sock(other), None, None).await;
    assert!(mgr.peers.is_empty(), "the limit refuses another address");
    let _client = accept(&mut mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 1);
    rib_task.abort();
}
