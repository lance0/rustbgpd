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
        mgr.check_due_retained_dynamic().await;
        let Some(pass) = mgr.retention.pass.as_mut() else {
            return;
        };
        let answer = (&mut pass.answer).await.unwrap();
        mgr.finish_retention_pass(answer).await;
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
    assert_eq!(mgr.release_unadmitted_retained_dynamic().await, 1);
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
    assert_eq!(mgr.release_unadmitted_retained_dynamic().await, 0);
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
        mgr.check_due_retained_dynamic().await;
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
        mgr.finish_retention_pass(answer).await;
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
    mgr.check_due_retained_dynamic().await;
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
    mgr.finish_retention_pass(answer).await;
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
    let open = OpenMessage {
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
    };
    send_bgp_message(client, &Message::Open(open)).await;
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
