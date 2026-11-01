//! A `[[dynamic_neighbors]]` member whose session ends keeps its RIB identity
//! while graceful restart may still hold routes on either side: the routes
//! the RIB retains for it, and ours it may retain as our helper (RFC 4724
//! §4.2). A reconnect at the address within that window resumes as the same
//! RIB peer; one that never comes is deleted once both retentions lapse.
//! Most tests drive the real peer manager into a real RIB.

use super::inbound_admission::localhost_inbound_stream;
use super::*;

use rustbgpd_api::peer_types::SessionLifecycleEventType;
use rustbgpd_rib::update::OutboundRouteUpdate;
use rustbgpd_rib::{PeerEndpoint, PeerId, PeerRetention, RibManager};
use rustbgpd_transport::{SessionEndRetention, SessionRole};

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const MEMBER: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 9));
const MEMBER_ASN: u32 = 65002;

/// The session ended with GR retention of its routes.
const THEIRS: SessionEndRetention = SessionEndRetention {
    established: true,
    theirs: true,
    ours_for: None,
};
/// The session ended with the member, as our helper, holding ours for 120 s.
const OURS: SessionEndRetention = SessionEndRetention {
    established: true,
    theirs: false,
    ours_for: Some(Duration::from_secs(120)),
};
/// Both.
const BOTH: SessionEndRetention = SessionEndRetention {
    established: true,
    theirs: true,
    ours_for: Some(Duration::from_secs(120)),
};
/// Nothing held after an Established period, as after a Hard Reset.
const HARD_RESET: SessionEndRetention = SessionEndRetention {
    established: true,
    theirs: false,
    ours_for: None,
};
/// A session that never reached Established.
const NOTHING: SessionEndRetention = SessionEndRetention {
    established: false,
    theirs: false,
    ours_for: None,
};

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
    (manager_on(rib_tx.clone()), rib_tx, rib_task)
}

fn manager_on(rib_tx: mpsc::Sender<RibUpdate>) -> PeerManager {
    PeerManager::new_with_config(
        mpsc::channel(16).1,
        mpsc::channel(1).1,
        65001,
        Ipv4Addr::new(10, 0, 0, 1),
        None,
        None,
        BgpMetrics::new(),
        rib_tx,
        None,
        None,
        make_dynamic_manager_config(),
    )
}

/// Accept `addr` through the real inbound path. Returns the client end,
/// which must stay open.
async fn accept_at(mgr: &mut PeerManager, addr: IpAddr) -> TcpStream {
    let (server, client) = localhost_inbound_stream().await;
    mgr.handle_inbound(server, sock(addr), None, None).await;
    client
}

async fn accept(mgr: &mut PeerManager) -> TcpStream {
    let client = accept_at(mgr, MEMBER).await;
    assert!(
        mgr.peers.contains_key(&key(MEMBER)),
        "the member is accepted"
    );
    client
}

/// The member's OPEN from `asn` validates: its session resolves its RIB
/// identity and reports the OPEN. Returns the identity.
async fn open_from(mgr: &mut PeerManager, asn: u32) -> PeerId {
    let managed = &mgr.peers[&key(MEMBER)];
    let peer = managed
        .transport_config
        .rib_peer
        .resolve(|| PeerEndpoint::new(MEMBER, None), asn);
    let session_id = managed.session_id();
    mgr.handle_session_notification(SessionNotification::OpenReceived {
        session_id,
        role: SessionRole::Primary,
        peer_addr: MEMBER,
        remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
        peer_asn: asn,
    })
    .await;
    peer
}

async fn open_validated(mgr: &mut PeerManager) -> PeerId {
    open_from(mgr, MEMBER_ASN).await
}

/// The member's session goes idle after its session reported `end`.
async fn idle(mgr: &mut PeerManager, end: SessionEndRetention) {
    let managed = &mgr.peers[&key(MEMBER)];
    managed.handle().publish_session_end_retention(end);
    let session_id = managed.session_id();
    mgr.handle_session_notification(SessionNotification::BackToIdle {
        session_id,
        role: SessionRole::Primary,
        peer_addr: MEMBER,
    })
    .await;
    assert!(mgr.peers.is_empty(), "the idle member leaves the inventory");
}

/// Run the due checks as the run loop does, through each batched query.
async fn settle(mgr: &mut PeerManager) {
    loop {
        mgr.check_due_retained_dynamic();
        let Some(pass) = mgr.retention.pass.as_mut() else {
            return;
        };
        let answer = (&mut pass.answer).await.unwrap();
        mgr.finish_retention_pass(answer);
    }
}

/// A session of `peer` from `asn` whose OPEN made it our GR helper
/// (`helper`) and listed IPv4 unicast for its own retention (`restarting`
/// marks the session after its restart); ORF-gated when `orf`.
fn session(
    peer: PeerId,
    session_id: u64,
    asn: u32,
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
            peer_asn: asn,
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

fn presence_events(mgr: &PeerManager, event_type: SessionLifecycleEventType) -> usize {
    mgr.session_event_history
        .iter()
        .filter(|event| event.event_type == event_type && event.peer == MEMBER)
        .count()
}

/// Retain the member once: accepted, its OPEN validated, `octets` routes
/// retained by a GR end, then idle after a session that reported `end`.
/// Returns its handle.
async fn retained_member(
    mgr: &mut PeerManager,
    rib_tx: &mpsc::Sender<RibUpdate>,
    end: SessionEndRetention,
) -> PeerId {
    let _client = accept(mgr).await;
    let peer = open_validated(mgr).await;
    let (tx, _rx) = mpsc::channel(16);
    send_all(
        rib_tx,
        session(
            peer,
            1,
            MEMBER_ASN,
            end.ours_for.is_some(),
            false,
            false,
            tx,
        ),
    )
    .await;
    send_all(rib_tx, [announce(peer, 1, [1, 2, 3])]).await;
    let last = if end.theirs {
        graceful_end(peer, 1)
    } else {
        RibUpdate::PeerDown {
            peer,
            session_id: 1,
        }
    };
    send_all(rib_tx, [last]).await;
    idle(mgr, end).await;
    settle(mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 1, "the member is retained");
    peer
}

/// The ticket's shape: a GR member drops, the RIB retains its routes, and it
/// reconnects inside the restart time. The reconnect is the same RIB peer
/// and the same managed neighbor (no second `PEER_ADDED`), so its
/// End-of-RIB ends the retention: the route it re-sent stays, the rest are
/// swept. Its session's own end, which reports that it reached Established,
/// then decides, not the old retention. Red proof: deleting the member at
/// idle purges the retained routes at once and gives the reconnect a new
/// handle; resuming the old retention regardless keeps it past a Hard Reset.
#[tokio::test]
async fn retained_member_reconnects_as_the_same_peer_and_its_eor_ends_retention() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let peer = retained_member(&mut mgr, &rib_tx, THEIRS).await;
    assert_eq!(
        retention(&rib_tx, peer).await.stale_routes,
        3,
        "the RIB still retains the member's routes"
    );
    assert_eq!(loc_rib_count(&rib_tx).await, 3);

    let _second = accept(&mut mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 1, "the reconnect reuses that slot");
    assert_eq!(
        presence_events(&mgr, SessionLifecycleEventType::PeerAdded),
        1
    );
    assert_eq!(
        open_validated(&mut mgr).await,
        peer,
        "it resumes the same handle"
    );
    let (tx, _rx) = mpsc::channel(16);
    send_all(
        &rib_tx,
        session(peer, 2, MEMBER_ASN, false, true, false, tx),
    )
    .await;
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
    assert_eq!(mgr.dynamic_peer_count, 1);
    assert_eq!(
        presence_events(&mgr, SessionLifecycleEventType::PeerRemoved),
        0
    );

    // The reconnect's own end decides: it reached Established, so the old
    // retention is not restored, and a Hard Reset end holds nothing.
    idle(&mut mgr, HARD_RESET).await;
    assert!(mgr.retained_dynamic.is_empty());
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert_eq!(
        presence_events(&mgr, SessionLifecycleEventType::PeerRemoved),
        1
    );
    rib_task.abort();
}

/// A member that never returns is deleted once both retentions lapse: the
/// RIB's GR timer sweeps its routes, and as our helper it may hold ours for
/// the window its session reported plus a hold time; then its identity is
/// released, its slot freed, and its `PEER_REMOVED` published. Red proof:
/// deleting at idle purges the routes before their restart time; keeping the
/// member past both windows never frees it.
#[tokio::test(start_paused = true)]
async fn retained_member_that_never_returns_is_deleted_after_both_retentions() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let _first = accept(&mut mgr).await;
    let peer = open_validated(&mut mgr).await;
    let hold = u64::from(mgr.peers[&key(MEMBER)].transport_config.peer.hold_time);
    let (tx, _rx) = mpsc::channel(16);
    send_all(
        &rib_tx,
        session(peer, 1, MEMBER_ASN, true, false, false, tx),
    )
    .await;
    send_all(&rib_tx, [announce(peer, 1, 1..=3), graceful_end(peer, 1)]).await;
    let ended = tokio::time::Instant::now();

    idle(&mut mgr, BOTH).await;
    settle(&mut mgr).await;
    let retained = retention(&rib_tx, peer).await;
    assert_eq!(retained.stale_routes, 3);
    assert_eq!(
        mgr.next_retained_dynamic_check(),
        retained.next_deadline,
        "checked again at the RIB's GR timer"
    );

    // The GR timer sweeps the routes; the member may still hold ours.
    tokio::time::sleep_until(ended + Duration::from_secs(121)).await;
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 0);
    settle(&mut mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 1, "kept while it may hold ours");
    assert_eq!(
        mgr.next_retained_dynamic_check(),
        Some(ended + Duration::from_secs(120 + hold))
    );
    assert!(peer.is_live());

    tokio::time::sleep_until(ended + Duration::from_secs(120 + hold + 1)).await;
    settle(&mut mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 0, "deleted once both have lapsed");
    assert_eq!(mgr.next_retained_dynamic_check(), None);
    assert!(!mgr.rib_peers.contains_key(&key(MEMBER)));
    assert_eq!(
        presence_events(&mgr, SessionLifecycleEventType::PeerRemoved),
        1
    );
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
    let peer = open_validated(&mut mgr).await;
    let (tx, _rx) = mpsc::channel(16);
    send_all(&rib_tx, session(peer, 1, MEMBER_ASN, true, false, true, tx)).await;
    send_all(
        &rib_tx,
        [RibUpdate::PeerDown {
            peer,
            session_id: 1,
        }],
    )
    .await;

    idle(&mut mgr, OURS).await;
    let _second = accept(&mut mgr).await;
    let resumed = open_validated(&mut mgr).await;
    let (tx, mut rx) = mpsc::channel(16);
    send_all(
        &rib_tx,
        session(resumed, 2, MEMBER_ASN, true, false, true, tx),
    )
    .await;
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

/// A connection from the retained address that never sends an OPEN resumes
/// nothing: its slot names no RIB peer, and when it goes idle the retention
/// stands exactly as it was, deadlines included, so a scanner cannot extend
/// it. Red proof: reusing the resolved slot before the OPEN, or dropping the
/// retention at the reconnect, renews the window at the second idle.
#[tokio::test(start_paused = true)]
async fn unvalidated_reconnect_leaves_the_retention_unchanged() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let peer = retained_member(&mut mgr, &rib_tx, BOTH).await;
    let before = &mgr.retained_dynamic[&key(MEMBER)];
    let (retained_at, ours_until) = (before.retained_at, before.ours_until);
    assert!(ours_until.is_some());

    tokio::time::advance(Duration::from_secs(100)).await;
    let _probe = accept(&mut mgr).await;
    assert_eq!(
        mgr.peers[&key(MEMBER)].transport_config.rib_peer.get(),
        None,
        "no RIB peer before an OPEN validates"
    );
    assert_eq!(mgr.dynamic_peer_count, 1);
    idle(&mut mgr, NOTHING).await;
    let after = &mgr.retained_dynamic[&key(MEMBER)];
    assert_eq!(after.retained_at, retained_at);
    assert_eq!(after.ours_until, ours_until, "the deadline is unchanged");
    assert!(after.theirs);
    assert_eq!(mgr.rib_peer_of(&key(MEMBER)), peer);
    assert_eq!(mgr.dynamic_peer_count, 1);
    settle(&mut mgr).await;
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 3);
    rib_task.abort();
}

/// A reconnect from another AS at the address, as on an accept-any range,
/// is another speaker: its session takes a new handle, and what was
/// retained for the last one is purged and its identity released. Red
/// proof: resuming the handle whatever the AS hands the new speaker the old
/// one's stale routes.
#[tokio::test]
async fn reconnect_from_another_as_does_not_inherit_the_retained_routes() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let peer = retained_member(&mut mgr, &rib_tx, THEIRS).await;
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 3);
    let _second = accept(&mut mgr).await;
    let other = open_from(&mut mgr, 65099).await;
    assert_ne!(other, peer, "another AS gets its own handle");
    assert!(mgr.retained_dynamic.is_empty());
    assert_eq!(
        mgr.dynamic_peer_count, 1,
        "the live neighbor keeps the slot"
    );
    let (tx, _rx) = mpsc::channel(16);
    send_all(&rib_tx, session(other, 2, 65099, false, true, false, tx)).await;
    assert_eq!(retention(&rib_tx, other).await.stale_routes, 0);
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 0);
    assert_eq!(
        loc_rib_count(&rib_tx).await,
        0,
        "the old speaker's routes are purged"
    );
    assert!(!peer.is_live(), "its identity is released");
    rib_task.abort();
}

/// A member with nothing retained either way, as after a Hard Reset, is
/// deleted at idle, as before; and a range removal deletes a retained one
/// with no RIB query. Red proof: without the admission re-check the
/// retained member outlives its range.
#[tokio::test]
async fn unretained_member_goes_at_idle_and_a_removed_range_takes_a_retained_one() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let _first = accept(&mut mgr).await;
    let peer = open_validated(&mut mgr).await;
    let (tx, _rx) = mpsc::channel(16);
    send_all(
        &rib_tx,
        session(peer, 1, MEMBER_ASN, true, false, false, tx),
    )
    .await;
    send_all(
        &rib_tx,
        [RibUpdate::PeerDown {
            peer,
            session_id: 1,
        }],
    )
    .await;
    idle(&mut mgr, NOTHING).await;
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert!(mgr.retained_dynamic.is_empty());

    let peer = retained_member(&mut mgr, &rib_tx, THEIRS).await;
    mgr.delete_dynamic_range("127.0.0.0/8").unwrap();
    assert!(mgr.retention.admission_dirty);
    assert_eq!(mgr.release_unadmitted_retained_dynamic(), 1);
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 0);
    rib_task.abort();
}

/// A configuration rollback that drops the member's range deletes a
/// retained member at once, with the live ones it reaps.
#[tokio::test]
async fn rollback_without_the_range_deletes_a_retained_member_at_once() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let peer = retained_member(&mut mgr, &rib_tx, THEIRS).await;
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

/// While a transaction snapshot is staged, its ranges do not delete a
/// retained member: a rollback could not bring it back. Commit or rollback
/// decides. Red proof: deleting under the staged ranges loses the member
/// the rollback restores the range for.
#[tokio::test]
async fn staged_ranges_do_not_delete_a_retained_member() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    retained_member(&mut mgr, &rib_tx, THEIRS).await;
    let ranges = std::mem::take(&mut mgr.dynamic_ranges);
    mgr.config_snapshot_staged = true;
    mgr.retained_dynamic.get_mut(&key(MEMBER)).unwrap().check_at =
        Some(tokio::time::Instant::now());
    settle(&mut mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 1, "kept while staged");
    assert!(mgr.retention.admission_dirty);

    // Rollback restores the range; the re-check keeps the member.
    mgr.dynamic_ranges = ranges;
    mgr.config_snapshot_staged = false;
    assert_eq!(mgr.release_unadmitted_retained_dynamic(), 0);
    assert_eq!(mgr.dynamic_peer_count, 1);
    rib_task.abort();
}

/// A static neighbor added at a retained member's address is a new
/// neighbor: the member is deleted once the add succeeds, and the neighbor
/// gets its own handle and counters. Red proof: without the deletion the
/// static neighbor runs on the member's handle and retained routes.
#[tokio::test]
async fn static_neighbor_at_a_retained_address_replaces_the_member() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let peer = retained_member(&mut mgr, &rib_tx, THEIRS).await;
    mgr.add_peer(make_config(MEMBER, MEMBER_ASN), false)
        .await
        .unwrap();
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert!(mgr.retained_dynamic.is_empty());
    assert_ne!(
        mgr.rib_peer_of(&key(MEMBER)),
        peer,
        "the static neighbor has its own handle"
    );
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 0);
    rib_task.abort();
}

/// A retained member whose routes the RIB retains keeps its place under
/// `dynamic_neighbor_limit`: at the limit another address is refused, and
/// the member's reconnect is admitted into the place it holds. One kept
/// only while it may hold our routes gives its place to a new address.
#[tokio::test]
async fn retained_members_and_the_limit() {
    let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    mgr.dynamic_neighbor_limit = 1;
    retained_member(&mut mgr, &rib_tx, THEIRS).await;
    let _refused = accept_at(&mut mgr, other).await;
    assert!(mgr.peers.is_empty(), "the limit refuses another address");
    let _client = accept(&mut mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 1);
    rib_task.abort();

    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    mgr.dynamic_neighbor_limit = 1;
    let peer = retained_member(&mut mgr, &rib_tx, OURS).await;
    let _admitted = accept_at(&mut mgr, other).await;
    assert!(
        mgr.peers.contains_key(&key(other)),
        "the ours-only member gave way"
    );
    assert!(mgr.retained_dynamic.is_empty());
    assert_eq!(mgr.dynamic_peer_count, 1);
    loc_rib_count(&rib_tx).await;
    assert!(!peer.is_live());
    rib_task.abort();
}

/// However many members are due, a check is one batched RIB query, sent
/// without waiting in the actor; an unanswered query backs off,
/// doubling. Here five members go idle against a RIB that does not answer.
/// Red proof: a query per member, or a fixed retry, fails the counts.
#[tokio::test(start_paused = true)]
async fn due_members_share_one_query_and_an_unanswered_one_backs_off() {
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let mut mgr = manager_on(rib_tx);
    let members: Vec<IpAddr> = (20..25)
        .map(|octet| IpAddr::V4(Ipv4Addr::new(127, 0, 0, octet)))
        .collect();
    let mut clients = Vec::new();
    for &member in &members {
        clients.push(accept_at(&mut mgr, member).await);
        let managed = &mgr.peers[&key(member)];
        managed
            .transport_config
            .rib_peer
            .resolve(|| PeerEndpoint::new(member, None), MEMBER_ASN);
        managed.handle().publish_session_end_retention(THEIRS);
        let session_id = managed.session_id();
        mgr.handle_session_notification(SessionNotification::BackToIdle {
            session_id,
            role: SessionRole::Primary,
            peer_addr: member,
        })
        .await;
    }
    assert_eq!(mgr.retained_dynamic.len(), 5);
    while let Ok(update) = rib_rx.try_recv() {
        assert!(
            !matches!(update, RibUpdate::QueryPeerRetentions { .. }),
            "idle never waits on the RIB"
        );
    }

    let mut retry = Duration::from_secs(1);
    for _ in 0..3 {
        mgr.check_due_retained_dynamic();
        let pass = mgr.retention.pass.as_mut().expect("one pass");
        let mut held_replies = Vec::new();
        let mut queries = 0;
        while let Some(update) = tokio::time::timeout(Duration::from_millis(1), rib_rx.recv())
            .await
            .ok()
            .flatten()
        {
            if let RibUpdate::QueryPeerRetentions { peers, reply } = update {
                assert_eq!(peers.len(), 5);
                queries += 1;
                held_replies.push(reply);
            }
        }
        assert_eq!(queries, 1, "one query for every due member");
        let answer = (&mut pass.answer).await.unwrap();
        let unanswered = tokio::time::Instant::now();
        mgr.finish_retention_pass(answer);
        assert_eq!(mgr.next_retained_dynamic_check(), Some(unanswered + retry));
        tokio::time::sleep_until(unanswered + retry).await;
        retry *= 2;
        drop(held_replies);
    }
    drop(clients);
}

/// An answer about an earlier retention of the address does not apply to a
/// newer one: here the member was deleted and retained anew while the query
/// was out, and the answer that nothing is retained must not delete the new
/// retention. Red proof: matching the answer by address alone deletes it.
#[tokio::test]
async fn an_answer_about_an_earlier_retention_is_ignored() {
    let (rib_tx, mut rib_rx) = mpsc::channel(64);
    let mut mgr = manager_on(rib_tx);
    let _client = accept(&mut mgr).await;
    mgr.peers[&key(MEMBER)]
        .transport_config
        .rib_peer
        .resolve(|| PeerEndpoint::new(MEMBER, None), MEMBER_ASN);
    idle(&mut mgr, THEIRS).await;
    mgr.check_due_retained_dynamic();
    let reply = loop {
        if let RibUpdate::QueryPeerRetentions { reply, .. } = rib_rx.recv().await.unwrap() {
            break reply;
        }
    };
    let _ = reply.send(vec![PeerRetention {
        stale_routes: 0,
        next_deadline: None,
    }]);
    let pass = mgr.retention.pass.as_mut().expect("one pass");
    let answer = (&mut pass.answer).await.unwrap();

    // Meanwhile the address was retained anew.
    let newer = mgr.retained_dynamic.get_mut(&key(MEMBER)).unwrap();
    newer.retained_at += Duration::from_millis(1);
    let check_at = newer.check_at;
    mgr.finish_retention_pass(answer);
    let newer = &mgr.retained_dynamic[&key(MEMBER)];
    assert!(newer.theirs, "the newer retention still holds the routes");
    assert_eq!(newer.check_at, check_at);
    assert_eq!(mgr.dynamic_peer_count, 1);
}

/// Complete the member's handshake from `asn` over `client` with a GR
/// capability that lists no family (a helper only, FRR's default), then
/// deliver the session's notifications as the run loop would.
async fn establish_from(mgr: &mut PeerManager, client: &mut TcpStream, asn: u32) {
    use super::collision::{read_bgp_message, send_bgp_message};
    let mut buf = BytesMut::new();
    assert!(matches!(
        read_bgp_message(client, &mut buf).await,
        Message::Open(_)
    ));
    send_bgp_message(client, &Message::Open(helper_open(asn))).await;
    assert!(matches!(
        read_bgp_message(client, &mut buf).await,
        Message::Keepalive
    ));
    send_bgp_message(client, &Message::Keepalive).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !mgr.peers[&key(MEMBER)].handle().is_established() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the session establishes");
    while let Ok(notification) = mgr.session_notify_rx.try_recv() {
        mgr.handle_session_notification(notification).await;
    }
}

/// Close the client end and deliver the session's notifications until it
/// went idle, as the run loop would.
async fn drop_until_idle(mgr: &mut PeerManager, client: TcpStream) {
    drop(client);
    while mgr.peers.contains_key(&key(MEMBER)) {
        let notification =
            tokio::time::timeout(Duration::from_secs(5), mgr.session_notify_rx.recv())
                .await
                .expect("the session reports going idle")
                .unwrap();
        mgr.handle_session_notification(notification).await;
    }
}

/// The blocker's shape end to end, with the session's own report of its
/// end: a member whose OPEN carries a GR capability listing no family is
/// still our helper, so its transport loss keeps its identity for the
/// window it may hold our routes, and its counters. Its reconnect from the
/// same AS resumes both. Red proof: keying the hold of ours on listed
/// families deletes the member at idle.
#[tokio::test]
async fn helper_only_member_is_retained_from_its_sessions_own_end() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let mut client = accept(&mut mgr).await;
    establish_from(&mut mgr, &mut client, MEMBER_ASN).await;
    let peer = mgr.peers[&key(MEMBER)]
        .transport_config
        .rib_peer
        .get()
        .expect("the validated OPEN resolved its identity");
    drop_until_idle(&mut mgr, client).await;
    let retained = &mgr.retained_dynamic[&key(MEMBER)];
    assert!(!retained.theirs, "no family listed: nothing of theirs held");
    assert!(retained.ours_until.is_some(), "it may hold ours");
    assert_eq!(mgr.neighbor_counters[&key(MEMBER)].flaps(), 1);

    let mut client = accept(&mut mgr).await;
    establish_from(&mut mgr, &mut client, MEMBER_ASN).await;
    let live = &mgr.peers[&key(MEMBER)].transport_config;
    assert_eq!(
        live.rib_peer.get(),
        Some(peer),
        "it resumes the same handle"
    );
    assert_eq!(
        live.neighbor_counters.flaps(),
        1,
        "its fresh counter block continues the old"
    );
    drop(client);
    loc_rib_count(&rib_tx).await;
    rib_task.abort();
}

/// A reconnect from another AS starts its counters at zero, as a new
/// neighbor does, while the same AS continues them. Red proof: handing the
/// reconnect the retained counter block carries the old speaker's counts.
#[tokio::test]
async fn reconnect_from_another_as_counts_afresh() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let mut client = accept(&mut mgr).await;
    establish_from(&mut mgr, &mut client, MEMBER_ASN).await;
    drop_until_idle(&mut mgr, client).await;
    assert_eq!(mgr.neighbor_counters[&key(MEMBER)].flaps(), 1);

    let mut client = accept(&mut mgr).await;
    establish_from(&mut mgr, &mut client, 65099).await;
    assert!(mgr.retained_dynamic.is_empty());
    assert_eq!(mgr.neighbor_counters[&key(MEMBER)].flaps(), 0);
    assert_eq!(
        mgr.peers[&key(MEMBER)]
            .transport_config
            .neighbor_counters
            .flaps(),
        0
    );
    drop(client);
    loc_rib_count(&rib_tx).await;
    rib_task.abort();
}

/// An in-range connection refused before its session starts, here for a
/// missing peer group, does not evict a neighbor kept while it may hold our
/// routes. Red proof: evicting at the limit check loses the member to a
/// connection that is dropped anyway.
#[tokio::test]
async fn a_refused_accept_evicts_nothing() {
    let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    mgr.dynamic_neighbor_limit = 1;
    retained_member(&mut mgr, &rib_tx, OURS).await;
    mgr.current_config.peer_groups.clear();
    let _refused = accept_at(&mut mgr, other).await;
    assert!(mgr.peers.is_empty(), "the connection is refused");
    assert!(mgr.retained_dynamic.contains_key(&key(MEMBER)));
    assert_eq!(mgr.dynamic_peer_count, 1);
    rib_task.abort();
}

/// A reconnect reset before its OPEN, here by an operator reset, never
/// reached Established, as its session's own end report says: the
/// retention it waited on stands unchanged and keeps its owner, so the
/// retained handle is neither orphaned nor its routes left behind. Red
/// proof: reporting every session end as Established drops the retention,
/// leaving the old handle live with its stale routes and no owner.
#[tokio::test]
async fn reconnect_reset_before_its_open_leaves_the_retention() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let peer = retained_member(&mut mgr, &rib_tx, THEIRS).await;
    let retained_at = mgr.retained_dynamic[&key(MEMBER)].retained_at;

    let _client = accept(&mut mgr).await;
    mgr.reset_peer(key(MEMBER), None).await.unwrap();
    while mgr.peers.contains_key(&key(MEMBER)) {
        let notification =
            tokio::time::timeout(Duration::from_secs(5), mgr.session_notify_rx.recv())
                .await
                .expect("the reset session reports going idle")
                .unwrap();
        mgr.handle_session_notification(notification).await;
    }
    let retained = mgr
        .retained_dynamic
        .get(&key(MEMBER))
        .expect("the retention stands");
    assert_eq!(retained.retained_at, retained_at);
    assert!(retained.theirs);
    assert_eq!(mgr.dynamic_peer_count, 1);
    assert_eq!(mgr.rib_peer_of(&key(MEMBER)), peer, "it keeps its owner");
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 3);
    assert!(peer.is_live());
    rib_task.abort();
}

/// An OPEN from `asn`, router ID 10.0.0.2, whose GR capability lists no
/// family: a helper only, FRR's default.
fn helper_open(asn: u32) -> OpenMessage {
    OpenMessage {
        version: 4,
        my_as: u16::try_from(asn).unwrap(),
        hold_time: 90,
        bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn },
            Capability::GracefulRestart {
                restart_state: false,
                notification: false,
                restart_time: 120,
                families: vec![],
            },
        ],
    }
}

/// A retained member reconnects, and before that session's OPEN a second
/// connection from the address arrives and sends its OPEN from `asn`. Its
/// router ID is higher, so it wins the collision and is promoted. Returns the
/// retained handle and the winner's client end.
async fn collision_winner_from(mgr: &mut PeerManager, asn: u32) -> (PeerId, TcpStream, TcpStream) {
    use super::collision::{read_bgp_message, send_bgp_message};
    let mut client = accept(mgr).await;
    establish_from(mgr, &mut client, MEMBER_ASN).await;
    let peer = mgr.peers[&key(MEMBER)]
        .transport_config
        .rib_peer
        .get()
        .unwrap();
    drop_until_idle(mgr, client).await;
    assert!(mgr.retained_dynamic.contains_key(&key(MEMBER)));

    let primary = accept(mgr).await;
    let mut winner = accept_at(mgr, MEMBER).await;
    assert!(
        mgr.peers[&key(MEMBER)].pending_inbound.is_some(),
        "the second connection is a collision candidate"
    );
    let mut buf = BytesMut::new();
    assert!(matches!(
        read_bgp_message(&mut winner, &mut buf).await,
        Message::Open(_)
    ));
    send_bgp_message(&mut winner, &Message::Open(helper_open(asn))).await;
    while mgr.peers[&key(MEMBER)].pending_inbound.is_some() {
        let notification =
            tokio::time::timeout(Duration::from_secs(5), mgr.session_notify_rx.recv())
                .await
                .expect("the candidate reports its OPEN")
                .unwrap();
        mgr.handle_session_notification(notification).await;
    }
    (peer, primary, winner)
}

/// A collision winner from the same AS is the retained neighbor: it resumes
/// the handle and continues the counters. Red proof: handing off only to a
/// session that was already the primary at its OPEN loses the counts.
#[tokio::test]
async fn same_as_collision_winner_continues_the_retained_neighbor() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let (peer, _primary, _winner) = collision_winner_from(&mut mgr, MEMBER_ASN).await;
    let live = &mgr.peers[&key(MEMBER)].transport_config;
    assert_eq!(live.rib_peer.get(), Some(peer));
    assert_eq!(live.neighbor_counters.flaps(), 1, "the counters continue");
    assert_eq!(mgr.neighbor_counters[&key(MEMBER)].flaps(), 1);
    loc_rib_count(&rib_tx).await;
    rib_task.abort();
}

/// A collision winner from another AS is another speaker: the old identity is
/// released, with what was retained for it, and the winner counts afresh.
/// Red proof: without the handoff on promotion the old identity stays live
/// and owns nothing.
#[tokio::test]
async fn other_as_collision_winner_releases_the_retained_identity() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let (peer, _primary, _winner) = collision_winner_from(&mut mgr, 65099).await;
    assert!(mgr.retained_dynamic.is_empty());
    let live = &mgr.peers[&key(MEMBER)].transport_config;
    assert_ne!(
        live.rib_peer.get(),
        Some(peer),
        "the winner has its own handle"
    );
    assert_eq!(live.neighbor_counters.flaps(), 0);
    loc_rib_count(&rib_tx).await;
    assert!(!peer.is_live(), "the old identity is released");
    rib_task.abort();
}

/// An Established member goes idle while a staged transaction's ranges no
/// longer admit it: the provisional ranges do not reject the retention, so a
/// rollback finds it intact. Red proof: rejecting against the staged ranges
/// deletes the identity and its routes before the commit.
#[tokio::test]
async fn staged_ranges_do_not_reject_a_retention_at_idle() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let _client = accept(&mut mgr).await;
    let peer = open_validated(&mut mgr).await;
    let (tx, _rx) = mpsc::channel(16);
    send_all(
        &rib_tx,
        session(peer, 1, MEMBER_ASN, false, false, false, tx),
    )
    .await;
    send_all(
        &rib_tx,
        [announce(peer, 1, [1, 2, 3]), graceful_end(peer, 1)],
    )
    .await;
    let ranges = std::mem::take(&mut mgr.dynamic_ranges);
    mgr.config_snapshot_staged = true;
    idle(&mut mgr, THEIRS).await;
    assert!(
        mgr.retained_dynamic.contains_key(&key(MEMBER)),
        "kept while staged"
    );
    assert!(mgr.retention.admission_dirty);
    assert_eq!(mgr.dynamic_peer_count, 1);

    // Rollback restores the range; the re-check keeps the member.
    mgr.dynamic_ranges = ranges;
    mgr.config_snapshot_staged = false;
    assert_eq!(mgr.release_unadmitted_retained_dynamic(), 0);
    settle(&mut mgr).await;
    assert_eq!(mgr.dynamic_peer_count, 1);
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 3);
    rib_task.abort();
}

/// The primary reconnect's OPEN from the retained AS validates, and its
/// slot resolves to the retained handle before Established (as an
/// export-policy update can make it), while its `OpenReceived` still waits in
/// the manager's queue. A candidate then wins the collision against the
/// primary's identity and sends its OPEN from another AS. The winner runs on
/// its own handle and counter block: the old identity is released, not the
/// winner's. Red proof: a candidate that shares the primary's slot inherits
/// the retained handle, which the handoff then releases under the winner.
#[tokio::test]
async fn another_as_candidate_winning_after_the_primary_resolved_has_its_own_identity() {
    use super::collision::{read_bgp_message, send_bgp_message};
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let mut client = accept(&mut mgr).await;
    establish_from(&mut mgr, &mut client, MEMBER_ASN).await;
    let peer = mgr.peers[&key(MEMBER)]
        .transport_config
        .rib_peer
        .get()
        .unwrap();
    drop_until_idle(&mut mgr, client).await;

    // The primary's OPEN from the retained AS validates; its report waits in
    // the manager's queue, so the range's AS is not pinned yet.
    let mut primary = accept(&mut mgr).await;
    let mut buf = BytesMut::new();
    assert!(matches!(
        read_bgp_message(&mut primary, &mut buf).await,
        Message::Open(_)
    ));
    send_bgp_message(&mut primary, &Message::Open(helper_open(MEMBER_ASN))).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let rustbgpd_transport::StateQueryOutcome::State(state) = mgr.peers[&key(MEMBER)]
                .handle()
                .query_state_outcome(Duration::from_secs(1))
                .await
                && state.fsm_state == SessionState::OpenConfirm
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the primary validates its OPEN");
    assert_eq!(
        mgr.peers[&key(MEMBER)]
            .transport_config
            .rib_peer
            .resolve(|| PeerEndpoint::new(MEMBER, None), MEMBER_ASN),
        peer,
        "the primary resolved the retained handle"
    );

    // A candidate wins against the primary's known identity at once (the
    // primary is in OpenConfirm), then sends its OPEN from another AS.
    let primary_session = mgr.peers[&key(MEMBER)].session_id();
    let mut winner = accept_at(&mut mgr, MEMBER).await;
    assert_ne!(
        mgr.peers[&key(MEMBER)].session_id(),
        primary_session,
        "the candidate is promoted"
    );
    let mut buf = BytesMut::new();
    assert!(matches!(
        read_bgp_message(&mut winner, &mut buf).await,
        Message::Open(_)
    ));
    send_bgp_message(&mut winner, &Message::Open(helper_open(65099))).await;
    let winner_session = mgr.peers[&key(MEMBER)].session_id();
    loop {
        let notification =
            tokio::time::timeout(Duration::from_secs(5), mgr.session_notify_rx.recv())
                .await
                .expect("the winner reports its OPEN")
                .unwrap();
        let winners_open = matches!(
            notification,
            SessionNotification::OpenReceived { session_id, .. } if session_id == winner_session
        );
        mgr.handle_session_notification(notification).await;
        if winners_open {
            break;
        }
    }
    mgr.reconcile_retained_dynamic_candidates();
    mgr.release_orphaned_retained_handles();

    let live = &mgr.peers[&key(MEMBER)].transport_config;
    // The winner's session resolves its slot on first use, as here.
    let own = live
        .rib_peer
        .resolve(|| PeerEndpoint::new(MEMBER, None), 65099);
    assert_ne!(own, peer, "the winner has its own handle");
    assert_eq!(live.neighbor_counters.flaps(), 0, "it counts afresh");
    assert_eq!(mgr.neighbor_counters[&key(MEMBER)].flaps(), 0);
    assert!(mgr.retained_dynamic.is_empty());
    loc_rib_count(&rib_tx).await;
    assert!(!peer.is_live(), "the old identity is released");
    assert!(own.is_live(), "the winner's own is not");
    drop((primary, winner));
    rib_task.abort();
}

/// A reconnect from another AS resolves a new handle when its OPEN
/// validates, before the manager handles that OPEN. A rollback without the
/// range reaps the reconnect first: both the retained handle and the
/// reconnect's own are deleted and released. Red proof: reaping only the
/// handle the manager records leaves the reconnect's live with no owner.
#[tokio::test]
async fn rollback_before_the_reconnects_open_is_handled_releases_both_handles() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let peer = retained_member(&mut mgr, &rib_tx, THEIRS).await;
    let _client = accept(&mut mgr).await;
    let own = mgr.peers[&key(MEMBER)]
        .transport_config
        .rib_peer
        .resolve(|| PeerEndpoint::new(MEMBER, None), 65099);
    assert_ne!(own, peer);

    mgr.dynamic_ranges.clear();
    assert_eq!(
        mgr.reap_dynamic_peers_not_allowed_by_current_ranges().await,
        1
    );
    mgr.release_orphaned_retained_handles();
    assert_eq!(mgr.dynamic_peer_count, 0);
    assert!(mgr.retained_dynamic.is_empty());
    loc_rib_count(&rib_tx).await;
    assert!(!peer.is_live(), "the retained handle is released");
    assert!(!own.is_live(), "and the reconnect's own");
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 0);
    rib_task.abort();
}

/// A reconnect's OPEN from another AS validates, but its session resolves
/// its slot only on first use, which can come while the rollback reap is
/// stopping it: after the reap has taken the retention, before the session
/// has joined. That late handle is still released. Here the late use is a
/// task that resolves the reconnect's slot; on this single-threaded runtime
/// it runs at the reap's first yield, past its read of the slots. Red
/// proof: reading the slots when the reap starts finds nothing, and the
/// handle allocated afterwards stays live with no owner.
#[tokio::test]
async fn rollback_releases_a_handle_resolved_while_the_reap_stops_the_reconnect() {
    use super::collision::{read_bgp_message, send_bgp_message};
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let peer = retained_member(&mut mgr, &rib_tx, THEIRS).await;
    let mut client = accept(&mut mgr).await;
    let mut buf = BytesMut::new();
    assert!(matches!(
        read_bgp_message(&mut client, &mut buf).await,
        Message::Open(_)
    ));
    send_bgp_message(&mut client, &Message::Open(helper_open(65099))).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let rustbgpd_transport::StateQueryOutcome::State(state) = mgr.peers[&key(MEMBER)]
                .handle()
                .query_state_outcome(Duration::from_secs(1))
                .await
                && state.fsm_state == SessionState::OpenConfirm
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the reconnect validates its OPEN");
    let slot = mgr.peers[&key(MEMBER)].transport_config.rib_peer.clone();
    let late = slot.clone();
    let resolver =
        tokio::spawn(async move { late.resolve(|| PeerEndpoint::new(MEMBER, None), 65099) });
    assert_eq!(slot.get(), None, "not resolved when the reap starts");

    mgr.dynamic_ranges.clear();
    assert_eq!(
        mgr.reap_dynamic_peers_not_allowed_by_current_ranges().await,
        1
    );
    let own = resolver.await.unwrap();
    assert_ne!(own, peer);
    mgr.release_orphaned_retained_handles();
    loc_rib_count(&rib_tx).await;
    assert!(!own.is_live(), "the late handle is released");
    assert!(!peer.is_live(), "and the retained one");
    drop(client);
    rib_task.abort();
}

/// A retained reconnect's primary OPEN is handled while a candidate's OPEN
/// is queued. Promotion sync resolves the candidate's own handle, but the
/// primary establishes before its dump, so the candidate loses. When the
/// primary's OPEN comes from another AS, its handoff removes the retention
/// before the run loop reconciles the candidate, and the candidate's handle
/// must still be released.
#[tokio::test]
async fn another_as_primary_handoff_releases_losing_candidate_identity() {
    primary_handoff_releases_losing_candidate(65099).await;
}

#[tokio::test]
async fn same_as_primary_handoff_releases_losing_candidate_identity() {
    primary_handoff_releases_losing_candidate(MEMBER_ASN).await;
}

async fn primary_handoff_releases_losing_candidate(primary_asn: u32) {
    use super::collision::{read_bgp_message, send_bgp_message};
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let retained = retained_member(&mut mgr, &rib_tx, OURS).await;
    let _primary_socket = accept(&mut mgr).await;
    let primary_session = mgr.peers[&key(MEMBER)].session_id();
    // Both accept before either OPEN, so both legitimately copy the wildcard ASN.
    let mut candidate = accept_at(&mut mgr, MEMBER).await;
    let candidate_session = mgr.peers[&key(MEMBER)]
        .pending_inbound
        .as_ref()
        .unwrap()
        .session_id;
    let slot = mgr.retained_dynamic[&key(MEMBER)]
        .candidate
        .as_ref()
        .unwrap()
        .slot
        .clone();

    // Existing collision-race fixture: primary answers OpenConfirm to the
    // first query, but rejects retirement because its KEEPALIVE arrived.
    let counters = Arc::new(FakePeerCounters::default());
    counters
        .established_before_dump
        .store(true, Ordering::SeqCst);
    let fake = fake_peer_handle(
        MEMBER,
        SessionState::OpenConfirm,
        Some(Ipv4Addr::new(10, 0, 0, 2)),
        counters.clone(),
    );
    let (original, _) = mgr
        .peers
        .replace_handle(&key(MEMBER), fake, primary_session)
        .unwrap();
    original.abort_for_transport_safety_and_wait().await;
    // The primary represented by the fake has established, so its own slot
    // must already have resolved, just as SessionUp does in production.
    let primary_peer = mgr.peers[&key(MEMBER)]
        .transport_config
        .rib_peer
        .resolve(|| PeerEndpoint::new(MEMBER, None), primary_asn);
    // The canceled socket never validated OPEN, so no notification precedes ours.
    while mgr.session_notify_rx.try_recv().is_ok() {}
    let mut buf = BytesMut::new();
    assert!(matches!(
        read_bgp_message(&mut candidate, &mut buf).await,
        Message::Open(_)
    ));
    send_bgp_message(&mut candidate, &Message::Open(helper_open(65099))).await;
    let notice = tokio::time::timeout(Duration::from_secs(5), mgr.session_notify_rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(notice, SessionNotification::OpenReceived { session_id, .. } if session_id == candidate_session)
    );
    // Put the candidate's later OPEN behind the primary's handler, exactly as
    // the shared lossless notification channel can order the two producers.
    mgr.session_notify_tx.send(notice).unwrap();
    mgr.handle_session_notification(SessionNotification::OpenReceived {
        session_id: primary_session,
        role: SessionRole::Primary,
        peer_addr: MEMBER,
        remote_router_id: Ipv4Addr::new(10, 0, 0, 2),
        peer_asn: primary_asn,
    })
    .await;

    let candidate_peer = slot
        .get()
        .expect("the real promotion export-policy sync resolved the candidate");
    assert_ne!(candidate_peer, retained);
    assert!(mgr.peers[&key(MEMBER)].pending_inbound.is_none());
    assert_eq!(mgr.peers[&key(MEMBER)].session_id(), primary_session);
    assert_eq!(mgr.retained_dynamic.is_empty(), primary_asn != MEMBER_ASN);
    mgr.reconcile_retained_dynamic_candidates();
    mgr.release_orphaned_retained_handles();
    assert_eq!(loc_rib_count(&rib_tx).await, 0);
    assert!(
        !candidate_peer.is_live(),
        "the losing candidate's identity is released after the handoff"
    );
    assert_eq!(retained.is_live(), primary_asn == MEMBER_ASN);

    // Final dynamic auto-removal sees only the winning primary's slot.
    idle(&mut mgr, HARD_RESET).await;
    mgr.reconcile_retained_dynamic_candidates();
    mgr.release_orphaned_retained_handles();
    assert_eq!(loc_rib_count(&rib_tx).await, 0);
    assert!(!primary_peer.is_live(), "the primary is deleted normally");
    assert!(mgr.retained_dynamic.is_empty());
    rib_task.abort();
}

/// A collision candidate that resolved its own handle is still attached to
/// the retention when the reconnect, which reached Established, goes idle.
/// The idle handler stops the candidate and drops the retention before the
/// run loop reconciles candidates, so the drop itself must queue the
/// candidate's handle for release.
#[tokio::test]
async fn established_reconnect_idle_releases_attached_candidate_identity() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let retained = retained_member(&mut mgr, &rib_tx, OURS).await;
    let _primary_socket = accept(&mut mgr).await;
    let _candidate_socket = accept_at(&mut mgr, MEMBER).await;
    assert!(mgr.peers[&key(MEMBER)].pending_inbound.is_some());
    // The reconnect resumed the retained identity, as SessionUp does.
    let primary_peer = mgr.peers[&key(MEMBER)]
        .transport_config
        .rib_peer
        .resolve(|| PeerEndpoint::new(MEMBER, None), MEMBER_ASN);
    assert_eq!(primary_peer, retained);
    // The candidate's OPEN came from another AS: its own, distinct handle.
    let candidate_peer = mgr.retained_dynamic[&key(MEMBER)]
        .candidate
        .as_ref()
        .unwrap()
        .slot
        .resolve(|| PeerEndpoint::new(MEMBER, None), 65099);
    assert_ne!(candidate_peer, retained);
    assert!(candidate_peer.is_live());

    idle(&mut mgr, HARD_RESET).await;
    assert!(mgr.retained_dynamic.is_empty());
    mgr.reconcile_retained_dynamic_candidates();
    mgr.release_orphaned_retained_handles();
    assert_eq!(loc_rib_count(&rib_tx).await, 0);
    assert!(
        !candidate_peer.is_live(),
        "the attached candidate's identity is released with the retention"
    );
    rib_task.abort();
}

/// A member auto-removed behind a full RIB mailbox that does not drain
/// defers its cleanup. Its reconnect, and a new address, are refused at once
/// and counted rather than waiting for room, so no new identity joins the
/// queue; once the cleanup is admitted the reconnect is accepted.
#[tokio::test]
async fn accepts_behind_a_deferred_cleanup_are_refused_without_waiting() {
    let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));
    let (rib_tx, mut rib_rx) = mpsc::channel(1);
    let mut mgr = manager_on(rib_tx.clone());
    let _client = accept(&mut mgr).await;
    let peer = open_validated(&mut mgr).await;
    while rib_rx.try_recv().is_ok() {}
    rib_tx
        .try_send(RibUpdate::ReleasePeer {
            peer: PeerId::UNASSIGNED,
        })
        .unwrap();
    idle(&mut mgr, NOTHING).await;
    assert_eq!(
        mgr.deferred_rib.queue.len(),
        2,
        "deferred behind the full mailbox"
    );

    for addr in [MEMBER, other] {
        let _client = tokio::time::timeout(Duration::from_secs(5), accept_at(&mut mgr, addr))
            .await
            .expect("the accept is refused without waiting for mailbox room");
        assert!(mgr.peers.is_empty(), "{addr} is refused");
    }
    assert_eq!(
        inbound_drop_metric(&mgr.metrics, "rib_cleanup_pending"),
        Some(2.0)
    );
    assert_eq!(
        mgr.deferred_rib.queue.len(),
        2,
        "no new identity joins the queue"
    );

    let drain = tokio::spawn(async move {
        let mut admitted = Vec::new();
        for _ in 0..3 {
            admitted.push(rib_rx.recv().await.unwrap());
        }
        (admitted, rib_rx)
    });
    mgr.flush_deferred_rib_updates(super::OperatorReadAdmission::Served)
        .await
        .unwrap();
    let (admitted, _rib_rx) = tokio::time::timeout(Duration::from_secs(5), drain)
        .await
        .unwrap()
        .unwrap();
    assert!(
        matches!(
            admitted[1..],
            [
                RibUpdate::PeerDeleted { peer: deleted, .. },
                RibUpdate::ReleasePeer { peer: released },
            ] if deleted == peer && released == peer
        ),
        "the member's cleanup reaches the RIB in order"
    );
    let _client = accept(&mut mgr).await;
}

/// A static neighbor added at a retained member's address starts its session
/// before the member's identity is deleted. Behind a full RIB mailbox that
/// deletion is deferred, so the add completes only once it is admitted,
/// keeping the old identity's label reap ahead of anything the new session
/// sends.
#[tokio::test]
async fn a_static_add_replacing_a_retained_member_waits_for_its_deferred_deletion() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let retained = retained_member(&mut mgr, &rib_tx, THEIRS).await;
    let (stalled_tx, mut stalled_rx) = mpsc::channel(1);
    mgr.rib_tx = stalled_tx.clone();
    stalled_tx
        .try_send(RibUpdate::ReleasePeer {
            peer: PeerId::UNASSIGNED,
        })
        .unwrap();
    let drain = tokio::spawn(async move {
        let mut admitted = Vec::new();
        while let Some(update) = stalled_rx.recv().await {
            let done = matches!(update, RibUpdate::ReleasePeer { peer } if peer == retained);
            admitted.push(update);
            if done {
                break;
            }
        }
        admitted
    });
    mgr.add_peer(make_config(MEMBER, MEMBER_ASN), false)
        .await
        .unwrap();
    assert!(
        mgr.deferred_rib.queue.is_empty(),
        "the add completes only once the retained identity's deletion is admitted"
    );
    let admitted = tokio::time::timeout(Duration::from_secs(5), drain)
        .await
        .unwrap()
        .unwrap();
    let deleted = admitted.iter().position(
        |update| matches!(update, RibUpdate::PeerDeleted { peer, .. } if *peer == retained),
    );
    assert_eq!(
        deleted,
        Some(admitted.len() - 2),
        "PeerDeleted, then ReleasePeer"
    );
    rib_task.abort();
}

/// A member kept for graceful restart reconnects while an unrelated
/// neighbor's cleanup is deferred: it resumes the identity it kept, so it is
/// admitted rather than refused until its connect-retry timer, which could
/// outlast its stale routes.
#[tokio::test]
async fn a_retained_reconnect_is_admitted_behind_unrelated_deferred_cleanup() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let _peer = retained_member(&mut mgr, &rib_tx, THEIRS).await;
    let (stalled_tx, _stalled_rx) = mpsc::channel(1);
    mgr.rib_tx = stalled_tx.clone();
    stalled_tx
        .try_send(RibUpdate::ReleasePeer {
            peer: PeerId::UNASSIGNED,
        })
        .unwrap();
    mgr.reap_deleted_peer_metric_series_for_key(&PeerKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        None,
    ));
    let _client = tokio::time::timeout(Duration::from_secs(5), accept_at(&mut mgr, MEMBER))
        .await
        .expect("the reconnect does not wait for mailbox room");
    assert!(
        mgr.peers.contains_key(&key(MEMBER)),
        "the reconnect is admitted"
    );
    assert!(mgr.retained_dynamic.contains_key(&key(MEMBER)));
    assert_eq!(
        inbound_drop_metric(&mgr.metrics, "rib_cleanup_pending"),
        Some(0.0)
    );
    rib_task.abort();
}

/// A collision candidate beside a retained reconnect resolves its own RIB
/// identity, so it is refused while any cleanup is deferred, like a new
/// dynamic neighbor: no new identity joins the queue.
#[tokio::test]
async fn a_candidate_beside_a_retained_reconnect_is_refused_behind_deferred_cleanup() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let _peer = retained_member(&mut mgr, &rib_tx, OURS).await;
    let _primary = accept(&mut mgr).await;
    let (stalled_tx, _stalled_rx) = mpsc::channel(1);
    mgr.rib_tx = stalled_tx.clone();
    stalled_tx
        .try_send(RibUpdate::ReleasePeer {
            peer: PeerId::UNASSIGNED,
        })
        .unwrap();
    mgr.reap_deleted_peer_metric_series_for_key(&PeerKey::new(
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9)),
        None,
    ));
    let _candidate = tokio::time::timeout(Duration::from_secs(5), accept_at(&mut mgr, MEMBER))
        .await
        .expect("the candidate does not wait for mailbox room");
    assert!(
        mgr.peers[&key(MEMBER)].pending_inbound.is_none(),
        "the candidate is refused"
    );
    assert!(mgr.retained_dynamic[&key(MEMBER)].candidate.is_none());
    assert_eq!(
        inbound_drop_metric(&mgr.metrics, "rib_cleanup_pending"),
        Some(1.0)
    );
    rib_task.abort();
}

/// The `(peer, range, retention)` label sets of the retained-neighbor
/// series, each with whether its deadline is still ahead of the wall clock.
fn retention_series(mgr: &PeerManager) -> Vec<(String, String, String, bool)> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let mut series: Vec<_> = mgr
        .metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|family| family.name() == "bgp_dynamic_neighbor_retained_until_timestamp_seconds")
        .flat_map(|family| family.get_metric().to_vec())
        .map(|metric| {
            let label = |name: &str| {
                metric
                    .get_label()
                    .iter()
                    .find(|pair| pair.name() == name)
                    .map(|pair| pair.value().to_string())
                    .unwrap()
            };
            (
                label("peer"),
                label("range"),
                label("retention"),
                metric.get_gauge().get_value() > now,
            )
        })
        .collect();
    series.sort();
    series
}

/// `rbgp doctor`'s `dynamic_neighbors.retained` reads what a retained member
/// holds, and until when, from these series: both retentions with the range,
/// from the first check that sees the RIB retain its routes; nothing while
/// a reconnect is live; both again when that reconnect fails before
/// Established; the hold of ours alone once the GR timer sweeps its routes;
/// nothing once it is deleted. Red proof: dropping any publish or clear
/// leaves a series wrong below.
#[tokio::test(start_paused = true)]
async fn retained_member_series_name_its_range_reasons_and_deadlines() {
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    let peer = retained_member(&mut mgr, &rib_tx, BOTH).await;
    let accepted = &mgr.retained_dynamic[&key(MEMBER)].accepted;
    let range = format!("{}/{}", accepted.addr, accepted.prefix_len);
    let holding = |retentions: &[&str]| -> Vec<(String, String, String, bool)> {
        retentions
            .iter()
            .map(|retention| {
                (
                    MEMBER.to_string(),
                    range.clone(),
                    (*retention).to_string(),
                    true,
                )
            })
            .collect()
    };
    assert_eq!(
        retention_series(&mgr),
        holding(&["its_routes", "our_routes"])
    );

    // A live reconnect is a neighbor row, not a retained one.
    let _probe = accept(&mut mgr).await;
    assert_eq!(retention_series(&mgr), holding(&[]));
    idle(&mut mgr, NOTHING).await;
    assert_eq!(
        retention_series(&mgr),
        holding(&["its_routes", "our_routes"]),
        "a reconnect that never reached Established leaves both"
    );

    // The GR timer sweeps its routes; it may still hold ours.
    tokio::time::sleep(Duration::from_secs(121)).await;
    assert_eq!(retention(&rib_tx, peer).await.stale_routes, 0);
    settle(&mut mgr).await;
    assert_eq!(retention_series(&mgr), holding(&["our_routes"]));

    // Evicted for a new address at the limit: nothing is left.
    mgr.dynamic_neighbor_limit = 1;
    let _other = accept_at(&mut mgr, IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10))).await;
    assert!(mgr.retained_dynamic.is_empty(), "the member gave way");
    assert_eq!(retention_series(&mgr), holding(&[]));
    rib_task.abort();

    // A member kept only while it may hold ours waits for no check: it is
    // listed from the moment it goes idle.
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    retained_member(&mut mgr, &rib_tx, OURS).await;
    assert_eq!(retention_series(&mgr), holding(&["our_routes"]));
    rib_task.abort();
}

/// At the dynamic limit behind a full RIB mailbox, a new address evicts a
/// member kept only while it may hold our routes, which defers that
/// identity's cleanup. The new address is then refused and counted rather
/// than admitted as a new identity beside the deferred cleanup.
#[tokio::test]
async fn an_eviction_behind_a_full_mailbox_refuses_the_new_identity() {
    let other = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10));
    let (mut mgr, rib_tx, rib_task) = manager_with_rib();
    mgr.dynamic_neighbor_limit = 1;
    let _peer = retained_member(&mut mgr, &rib_tx, OURS).await;
    let (stalled_tx, _stalled_rx) = mpsc::channel(1);
    mgr.rib_tx = stalled_tx.clone();
    stalled_tx
        .try_send(RibUpdate::ReleasePeer {
            peer: PeerId::UNASSIGNED,
        })
        .unwrap();
    assert!(mgr.deferred_rib.queue.is_empty());
    let _refused = tokio::time::timeout(Duration::from_secs(5), accept_at(&mut mgr, other))
        .await
        .expect("refused without waiting for mailbox room");
    assert!(mgr.retained_dynamic.is_empty(), "the member was evicted");
    assert_eq!(mgr.deferred_rib.queue.len(), 2, "its cleanup is deferred");
    assert!(
        !mgr.peers.contains_key(&key(other)),
        "the new address is refused"
    );
    assert_eq!(
        inbound_drop_metric(&mgr.metrics, "rib_cleanup_pending"),
        Some(1.0)
    );
    rib_task.abort();
}
