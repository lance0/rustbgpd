//! A session end that arrives after its session was already retired (an
//! aborted session task delivers what it held once the channel has room)
//! must not abort, restart or double-mark retention that belongs to a later
//! session. A repeated `PeerDown` for the newest ended session still runs
//! the teardown: the peer manager relies on it to purge what that session
//! retained.
use super::*;
use crate::PeerId;
use crate::test_support::peer_v4;

fn test_manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

fn peer() -> PeerId {
    peer_v4(Ipv4Addr::new(192, 0, 2, 1))
}

fn peer_up(manager: &mut RibManager, session_id: u64) {
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    manager.handle_update(RibUpdate::PeerUp {
        peer: peer(),
        session_id,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 254),
        outbound_tx,
        export_policy: None,
        sendable_families: Vec::new(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
}

/// One route received from the peer's current session.
fn receive_route(manager: &mut RibManager) {
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24);
    let mut rib = AdjRibIn::new(peer());
    rib.insert(make_route(prefix, Ipv4Addr::new(192, 0, 2, 1)));
    manager.ribs.insert(peer(), rib);
    manager.register_unicast_announcer(peer(), Prefix::V4(prefix));
}

fn peer_down(manager: &mut RibManager, session_id: u64) {
    manager.handle_update(RibUpdate::PeerDown {
        peer: peer(),
        session_id,
    });
}

fn restart(manager: &mut RibManager, session_id: u64) {
    manager.handle_update(RibUpdate::PeerGracefulRestart {
        peer: peer(),
        session_id,
        restart_time: 90,
        stale_routes_time: 120,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    });
}

/// `(routes held for the peer, of which retained as stale, in graceful
/// restart)`.
fn retention(manager: &RibManager) -> (usize, u64, bool) {
    let rib = manager.ribs.get(&peer());
    (
        rib.map_or(0, AdjRibIn::len),
        rib.map_or(0, AdjRibIn::retained_stale_count),
        manager.gr_peers.contains_key(&peer()),
    )
}

/// Whether exactly `count` session ends were discarded as stale.
fn discarded(manager: &RibManager, count: u32) -> bool {
    let total: f64 = manager
        .metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_rib_stale_peer_down_ignored_total")
        .map_or(0.0, |family| {
            family
                .get_metric()
                .iter()
                .map(|metric| metric.get_counter().get_value())
                .sum()
        });
    (total - f64::from(count)).abs() < f64::EPSILON
}

/// Session 1 ended and session 2 then went down under graceful restart.
fn second_session_retained() -> RibManager {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    peer_down(&mut manager, 1);
    peer_up(&mut manager, 2);
    receive_route(&mut manager);
    restart(&mut manager, 2);
    assert_eq!(retention(&manager), (1, 1, true));
    manager
}

/// Mutation-red: without the late-end check the `PeerDown` of session 1
/// finds no registration and aborts session 2's retention.
#[test]
fn late_peer_down_keeps_a_newer_sessions_retention() {
    let mut manager = second_session_retained();
    peer_down(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
    assert!(discarded(&manager, 1));
}

/// Mutation-red: without the late-end check session 1's restart end marks
/// the family stale a second time, which deletes the routes session 2 left.
#[test]
fn late_restart_end_does_not_mark_a_newer_sessions_routes_stale_twice() {
    let mut manager = second_session_retained();
    restart(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
    assert!(discarded(&manager, 1));
}

/// Mutation-red: with a strict comparison for the retaining end, session
/// 1's held restart end starts graceful-restart state for a session that
/// was already torn down.
#[test]
fn late_restart_end_after_its_own_peer_down_starts_no_retention() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    peer_down(&mut manager, 1);
    restart(&mut manager, 1);
    assert_eq!(retention(&manager), (0, 0, false));
    assert!(discarded(&manager, 1));
}

/// The peer manager's `PeerDown` after a session's own restart end (its
/// fence after a NOTIFICATION that kept retention, and the source
/// retirement barrier) still purges what that session retained.
/// Mutation-red: an inclusive comparison for `PeerDown` discards it and the
/// routes stay retained.
#[test]
fn repeated_peer_down_still_purges_what_the_session_retained() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    restart(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
    peer_down(&mut manager, 1);
    assert_eq!(retention(&manager), (0, 0, false));
    assert!(discarded(&manager, 0));
}

/// A second `PeerDown` for the same session with no retention begun in
/// between is accepted and finds nothing to tear down.
/// Mutation-red: an inclusive comparison for `PeerDown` counts it as a
/// discard.
#[test]
fn repeated_peer_down_without_retention_is_an_empty_teardown() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    peer_down(&mut manager, 1);
    peer_down(&mut manager, 1);
    assert_eq!(retention(&manager), (0, 0, false));
    assert!(discarded(&manager, 0));
}

/// One session task keeps its id across reconnects: a later epoch of an id
/// that already ended is live again and ends normally. The late-end check
/// applies only to a peer with no live session, so this pins that scope.
#[test]
fn a_session_id_that_re_establishes_ends_normally_again() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    peer_down(&mut manager, 1);
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    restart(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
    assert!(discarded(&manager, 0));
}

/// Session id 0 names an emitter without identity and is never late.
/// Mutation-red: dropping the id-0 exemption discards its restart end.
#[test]
fn session_id_zero_is_never_late() {
    let mut manager = test_manager();
    peer_up(&mut manager, 5);
    peer_down(&mut manager, 5);
    receive_route(&mut manager);
    restart(&mut manager, 0);
    assert_eq!(retention(&manager), (1, 1, true));
}

/// The remembered id goes with the neighbor: a deletion or a released
/// handle forgets it, so it cannot outlive a deleted or dynamic neighbor.
/// Mutation-red: without the removal the map keeps the entry, and an older
/// session id at the same handle is treated as late after the deletion.
#[test]
fn deletion_and_release_forget_the_ended_session_id() {
    let mut manager = test_manager();
    peer_up(&mut manager, 5);
    peer_down(&mut manager, 5);
    assert_eq!(manager.ended_session_ids.get(&peer()), Some(&5));
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: peer(),
        label: None,
        keep_series: false,
    });
    assert!(manager.ended_session_ids.is_empty());
    receive_route(&mut manager);
    restart(&mut manager, 3);
    assert_eq!(retention(&manager), (1, 1, true));

    peer_down(&mut manager, 3);
    assert_eq!(manager.ended_session_ids.get(&peer()), Some(&3));
    manager.handle_update(RibUpdate::ReleasePeer { peer: peer() });
    assert!(manager.ended_session_ids.is_empty());
}
