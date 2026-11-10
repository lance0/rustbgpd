//! A session end that finds no session registered for the peer (an aborted
//! session task delivers what it held once the channel has room) is decided
//! by who owns the peer's retained routes, not by the order of session ids:
//! a restart end is discarded, and a `PeerDown` ends retention only when
//! its own session created it. The peer manager's `PeerDown` after a
//! session's own restart end therefore still purges what that session
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

/// Mutation-red: without the owner check the `PeerDown` of session 1 finds
/// no registration and aborts session 2's retention.
#[test]
fn late_peer_down_keeps_another_sessions_retention() {
    let mut manager = second_session_retained();
    peer_down(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
    assert!(discarded(&manager, 1));
}

/// Mutation-red (with the owner check disabled as well, which also stops
/// it): an accepted restart end from the unregistered session 1 marks the
/// family stale a second time, which deletes the routes session 2 left.
#[test]
fn late_restart_end_does_not_mark_another_sessions_routes_stale_twice() {
    let mut manager = second_session_retained();
    restart(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
}

/// Mutation-red: an accepted restart end from the unregistered session 1
/// starts graceful-restart state for a session that was already torn down.
#[test]
fn late_restart_end_after_its_own_peer_down_starts_no_retention() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    peer_down(&mut manager, 1);
    restart(&mut manager, 1);
    assert_eq!(retention(&manager), (0, 0, false));
}

/// The peer manager's `PeerDown` after a session's own restart end (its
/// fence after a NOTIFICATION that kept retention, the source retirement
/// barrier, the link-down purge) still purges what that session retained.
/// Mutation-red: discarding every `PeerDown` that finds retention leaves
/// the routes retained.
#[test]
fn peer_down_from_the_owner_purges_what_it_retained() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    restart(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
    peer_down(&mut manager, 1);
    assert_eq!(retention(&manager), (0, 0, false));
    assert!(discarded(&manager, 0));
    assert!(manager.retention_owner.is_empty());
}

/// A collision's survivor can be the older session id: 6 registers over 5
/// and goes down, 5 takes the registration back, later retains, and its
/// own `PeerDown` then purges.
/// Mutation-red: a rule that discards an end older than the newest ended
/// session id discards `PeerDown{5}` and the routes stay stale until the
/// restart timer.
#[test]
fn older_collision_survivor_still_purges_its_own_retention() {
    let mut manager = test_manager();
    peer_up(&mut manager, 5);
    peer_up(&mut manager, 6);
    peer_down(&mut manager, 6);
    receive_route(&mut manager);
    restart(&mut manager, 5);
    assert_eq!(retention(&manager), (1, 1, true));
    peer_down(&mut manager, 5);
    assert_eq!(retention(&manager), (0, 0, false));
    assert!(discarded(&manager, 0));
}

/// The peer manager fences a pending candidate (a higher id that never
/// registered) and then the primary, with the primary already down under
/// graceful restart. The candidate's `PeerDown` does not own the retention
/// and leaves it; the primary's then purges it.
/// Mutation-red: a rule keyed on id order lets the candidate's higher id
/// block the primary's purge.
#[test]
fn candidate_fence_does_not_block_the_primarys_purge() {
    let mut manager = test_manager();
    peer_up(&mut manager, 5);
    receive_route(&mut manager);
    restart(&mut manager, 5);
    peer_down(&mut manager, 6);
    assert_eq!(retention(&manager), (1, 1, true));
    peer_down(&mut manager, 5);
    assert_eq!(retention(&manager), (0, 0, false));
}

/// A held restart end delivered between the neighbor's `PeerDeleted` and
/// its `ReleasePeer` recreates nothing: no graceful-restart state and no
/// metric series under the deleted peer's label.
/// Mutation-red: an accepted restart end sets `bgp_gr_active` for the
/// deleted peer and starts its restart timer.
#[test]
fn restart_end_after_deletion_recreates_nothing() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: peer(),
        label: None,
        keep_series: false,
    });
    restart(&mut manager, 1);
    assert_eq!(retention(&manager), (0, 0, false));
    assert!(manager.gr_stale_deadlines.get(&peer()).is_none());
    let label = peer().label();
    let series: Vec<String> = manager
        .metrics
        .registry()
        .gather()
        .into_iter()
        .filter(|family| {
            family.get_metric().iter().any(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|pair| pair.name() == "peer" && pair.value() == label)
            })
        })
        .map(|family| family.name().to_owned())
        .collect();
    assert_eq!(series, Vec::<String>::new());
    manager.handle_update(RibUpdate::ReleasePeer { peer: peer() });
    assert!(manager.retention_owner.is_empty());
}

/// A second `PeerDown` for the same session with no retention begun in
/// between is accepted and finds nothing to tear down.
/// Mutation-red: discarding every unregistered `PeerDown` counts it.
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
/// that already ended is registered again and ends normally. The rule
/// applies only to a peer with no session registered, so this pins that
/// scope.
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

/// Session id 0 names an emitter without identity and keeps the accept-all
/// behaviour: its restart end retains without a registration, and its
/// `PeerDown` ends retention whoever created it.
/// Mutation-red: dropping the id-0 exemption discards both.
#[test]
fn session_id_zero_keeps_accept_all() {
    let mut manager = test_manager();
    receive_route(&mut manager);
    restart(&mut manager, 0);
    assert_eq!(retention(&manager), (1, 1, true));
    peer_down(&mut manager, 0);
    assert_eq!(retention(&manager), (0, 0, false));

    let mut manager = second_session_retained();
    peer_down(&mut manager, 0);
    assert_eq!(retention(&manager), (0, 0, false));
}
