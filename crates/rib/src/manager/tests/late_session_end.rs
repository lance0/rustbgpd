//! A session end delivered by a dropped session's hand-off
//! (`RibUpdate::LateSessionEnd`) can arrive after the session was retired
//! and after a later session came and went. With no session registered it
//! must not start retention or end another session's. Every other session
//! end keeps its authoritative handling: the peer manager's `PeerDown` for a
//! session that never registered still purges whatever the peer retains.
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
    peer_up_superseding(manager, session_id, None);
}

/// A `PeerUp` whose session replaces the retired session `supersedes`.
fn peer_up_superseding(manager: &mut RibManager, session_id: u64, supersedes: Option<u64>) {
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    manager.handle_update(RibUpdate::PeerUp {
        peer: peer(),
        session_id,
        supersedes: supersedes.and_then(std::num::NonZeroU64::new),
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

fn restart_end(session_id: u64) -> RibUpdate {
    RibUpdate::PeerGracefulRestart {
        peer: peer(),
        session_id,
        restart_time: 90,
        stale_routes_time: 120,
        gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    }
}

fn restart(manager: &mut RibManager, session_id: u64) {
    manager.handle_update(restart_end(session_id));
}

/// The session's `PeerDown`, delivered by its hand-off.
fn late_down(manager: &mut RibManager, session_id: u64) {
    manager.handle_update(RibUpdate::LateSessionEnd(Box::new(RibUpdate::PeerDown {
        peer: peer(),
        session_id,
    })));
}

/// The session's restart end, delivered by its hand-off.
fn late_restart(manager: &mut RibManager, session_id: u64) {
    manager.handle_update(RibUpdate::LateSessionEnd(Box::new(restart_end(session_id))));
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
    counted(manager, "bgp_rib_stale_peer_down_ignored_total", count)
}

/// Whether the registration failed over exactly `count` times.
fn failed_over(manager: &RibManager, count: u32) -> bool {
    counted(
        manager,
        "bgp_rib_outbound_registration_failover_total",
        count,
    )
}

/// The peer's live-session records, oldest first.
fn live(manager: &RibManager) -> Vec<u64> {
    manager
        .live_sessions
        .get(&peer())
        .into_iter()
        .flatten()
        .map(|record| record.session_id)
        .collect()
}

/// Whether the counter family `name` sums to exactly `count`.
fn counted(manager: &RibManager, name: &str, count: u32) -> bool {
    let total: f64 = manager
        .metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == name)
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

/// Mutation-red: with the late check disabled the `PeerDown` of session 1
/// finds no registration and aborts session 2's retention.
#[test]
fn late_peer_down_keeps_another_sessions_retention() {
    let mut manager = second_session_retained();
    late_down(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
    assert!(discarded(&manager, 1));
}

/// Mutation-red: with the late check disabled session 1's restart end
/// marks the family stale a second time, which deletes the routes session
/// 2 left.
#[test]
fn late_restart_end_does_not_mark_another_sessions_routes_stale_twice() {
    let mut manager = second_session_retained();
    late_restart(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
}

/// Mutation-red: with the late check disabled session 1's held restart end
/// starts graceful-restart state for a session that was already torn down.
#[test]
fn late_restart_end_after_its_own_peer_down_starts_no_retention() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    peer_down(&mut manager, 1);
    late_restart(&mut manager, 1);
    assert_eq!(retention(&manager), (0, 0, false));
}

/// A late `PeerDown` from the session that created the retention still
/// ends it (a held link-down purge, or the drop closing its own epoch).
/// Mutation-red: discarding every late `PeerDown` that finds retention
/// leaves the routes retained.
#[test]
fn late_peer_down_from_the_owner_purges_what_it_retained() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    restart(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
    late_down(&mut manager, 1);
    assert_eq!(retention(&manager), (0, 0, false));
    assert!(discarded(&manager, 0));
    assert!(manager.retention_owner.is_empty());
}

/// A collision's survivor can be the older session id: 6 registers over 5
/// and goes down, 5 takes the registration back, later retains, and its
/// own late `PeerDown` then purges.
/// Mutation-red: discarding every late `PeerDown` that finds retention
/// leaves the routes stale until the restart timer.
#[test]
fn older_collision_survivor_still_purges_its_own_retention() {
    let mut manager = test_manager();
    peer_up(&mut manager, 5);
    peer_up(&mut manager, 6);
    peer_down(&mut manager, 6);
    receive_route(&mut manager);
    restart(&mut manager, 5);
    assert_eq!(retention(&manager), (1, 1, true));
    late_down(&mut manager, 5);
    assert_eq!(retention(&manager), (0, 0, false));
    assert!(discarded(&manager, 0));
}

/// A held restart end delivered between the neighbor's `PeerDeleted` and
/// its `ReleasePeer` recreates nothing: no graceful-restart state and no
/// metric series under the deleted peer's label.
/// Mutation-red: with the late check disabled the restart end sets
/// `bgp_gr_active` for the deleted peer and starts its restart timer.
#[test]
fn late_restart_end_after_deletion_recreates_nothing() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: peer(),
        label: None,
        keep_series: false,
    });
    late_restart(&mut manager, 1);
    assert_eq!(retention(&manager), (0, 0, false));
    assert!(manager.gr_stale_deadlines.get(&peer()).is_none());
    assert_eq!(series_for_peer(&manager), Vec::<String>::new());
}

/// With another session registered, a late end takes the ordinary
/// session-identity dispatch: discarded as a superseded session's, and the
/// registered session is untouched.
/// Mutation-red: none of its own; it pins that the late arm does not
/// bypass the existing stale-session discard.
#[test]
fn late_end_with_another_session_registered_is_the_ordinary_stale_discard() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    peer_up(&mut manager, 2);
    receive_route(&mut manager);
    late_down(&mut manager, 1);
    late_restart(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 0, false));
    assert_eq!(manager.current_session_id(peer()), Some(2));
    assert!(discarded(&manager, 2));
}

/// Every metric family with a series under the test peer's label.
fn series_for_peer(manager: &RibManager) -> Vec<String> {
    let label = peer().label();
    manager
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
        .collect()
}

/// A late `PeerDown` delivered between the neighbor's `PeerDeleted` and
/// its `ReleasePeer` has nothing to tear down and republishes nothing
/// under the deleted peer's label.
/// Mutation-red: running the ordinary teardown for it republishes
/// `bgp_rib_adj_out_prefixes` for the deleted peer.
#[test]
fn late_peer_down_after_deletion_recreates_nothing() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    manager.handle_update(RibUpdate::PeerDeleted {
        peer: peer(),
        label: None,
        keep_series: false,
    });
    assert_eq!(series_for_peer(&manager), Vec::<String>::new());
    late_down(&mut manager, 1);
    assert_eq!(retention(&manager), (0, 0, false));
    assert_eq!(series_for_peer(&manager), Vec::<String>::new());
}

/// A late `PeerDown` with nothing retained is discarded without a count:
/// whatever removed the registration already tore the session down. The
/// context the session staged is still dropped.
/// Mutation-red: a discard that skips the staged-context removal leaves
/// the entry behind.
#[test]
fn late_peer_down_without_retention_drops_only_staged_context() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    peer_down(&mut manager, 1);
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer: peer(),
        session_id: 1,
        peer_group: None,
    });
    assert_eq!(manager.pending_peer_policy_context.len(), 1);
    late_down(&mut manager, 1);
    assert_eq!(retention(&manager), (0, 0, false));
    assert!(manager.pending_peer_policy_context.is_empty());
    assert!(discarded(&manager, 0));
}

/// A session that inherited its predecessor's registration and never
/// delivered its own `PeerUp` is ended by the peer manager with a late
/// `PeerDown` under its own id. That drops what it staged and nothing
/// else: the predecessor stays registered, or keeps the retention its
/// restart end created.
/// Mutation-red: a late end that ran the peer's teardown clears the
/// registration, or the retained route.
#[test]
fn late_peer_down_of_an_unregistered_heir_drops_only_its_staged_context() {
    let stage = |manager: &mut RibManager| {
        manager.handle_update(RibUpdate::SetPeerPolicyContext {
            peer: peer(),
            session_id: 2,
            peer_group: None,
        });
        assert_eq!(manager.pending_peer_policy_context.len(), 1);
    };

    let mut registered = test_manager();
    peer_up(&mut registered, 1);
    receive_route(&mut registered);
    stage(&mut registered);
    late_down(&mut registered, 2);
    assert!(registered.pending_peer_policy_context.is_empty());
    assert_eq!(registered.current_session_id(peer()), Some(1));
    assert_eq!(retention(&registered), (1, 0, false));

    let mut retained = test_manager();
    peer_up(&mut retained, 1);
    receive_route(&mut retained);
    restart(&mut retained, 1);
    stage(&mut retained);
    late_down(&mut retained, 2);
    assert!(retained.pending_peer_policy_context.is_empty());
    assert_eq!(retention(&retained), (1, 1, true));
}

/// Session id 0 names an emitter without identity and is never late.
/// Mutation-red: dropping the id-0 exemption discards both ends.
#[test]
fn late_end_with_session_id_zero_keeps_accept_all() {
    let mut manager = test_manager();
    receive_route(&mut manager);
    late_restart(&mut manager, 0);
    assert_eq!(retention(&manager), (1, 1, true));

    let mut manager = second_session_retained();
    late_down(&mut manager, 0);
    assert_eq!(retention(&manager), (0, 0, false));
}

/// An authoritative `PeerDown` from a session that does not own the
/// retention still purges it, as before: session 1 retains, and the peer
/// manager ends a replacement that never registered. Covers a reset or
/// BFD-down during the replacement's handshake (id 2), the capacity-disable
/// fence for an inbound candidate that never established (id 9), and a
/// candidate fence sent while the primary owns retention.
/// Mutation-red: applying the late check to an ordinary `PeerDown` discards
/// it and the routes stay retained until the timer.
#[test]
fn authoritative_peer_down_from_a_non_owner_still_purges() {
    for never_registered in [2, 9] {
        let mut manager = test_manager();
        peer_up(&mut manager, 1);
        receive_route(&mut manager);
        restart(&mut manager, 1);
        assert_eq!(retention(&manager), (1, 1, true));
        peer_down(&mut manager, never_registered);
        assert_eq!(retention(&manager), (0, 0, false));
        assert!(discarded(&manager, 0));
    }
}

/// An ordinary restart end that finds no registration keeps the accept-all
/// behaviour it had.
/// Mutation-red: applying the late check to an ordinary restart end
/// discards it.
#[test]
fn authoritative_restart_end_without_registration_still_retains() {
    let mut manager = test_manager();
    receive_route(&mut manager);
    restart(&mut manager, 7);
    assert_eq!(retention(&manager), (1, 1, true));
}

/// The recorded owner goes with the neighbor's handle.
/// Mutation-red: without the removal on release the entry stays.
#[test]
fn release_forgets_the_retention_owner() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    restart(&mut manager, 1);
    assert_eq!(manager.retention_owner.get(&peer()), Some(&1));
    manager.handle_update(RibUpdate::ReleasePeer { peer: peer() });
    assert!(manager.retention_owner.is_empty());
}

/// Session 1 was retired by the peer manager and its replacement, session
/// 2, named it at `PeerUp`; session 2 then went down under graceful restart
/// before anything more arrived from session 1.
fn replacement_retained() -> RibManager {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    peer_up_superseding(&mut manager, 2, Some(1));
    assert_eq!(live(&manager), [2]);
    receive_route(&mut manager);
    restart(&mut manager, 2);
    manager
}

/// The reported order: the replaced session's `PeerDown` is still in
/// transit when its replacement goes down under graceful restart. The
/// replacement's routes are retained, and the old `PeerDown` then leaves
/// them alone, whether it arrives plain or marked late.
/// Mutation-red: with the superseded record kept, the restart end fails
/// over to session 1 and nothing is retained; with the superseded check
/// removed from the `PeerDown` handler, the plain `PeerDown` finds no
/// registration and purges the retention.
#[test]
fn replacement_restart_end_retains_while_the_replaced_peer_down_is_in_transit() {
    for late in [false, true] {
        let mut manager = replacement_retained();
        assert_eq!(retention(&manager), (1, 1, true));
        assert!(failed_over(&manager, 0));
        if late {
            late_down(&mut manager, 1);
        } else {
            peer_down(&mut manager, 1);
        }
        assert_eq!(retention(&manager), (1, 1, true), "late: {late}");
        assert!(discarded(&manager, 1));
    }
}

/// A restart end from the superseded session after its replacement
/// retained must not mark the family stale a second time.
/// Mutation-red: with the superseded check removed from the restart-end
/// handler, the plain restart end deletes the routes session 2 left.
#[test]
fn superseded_restart_end_does_not_touch_the_replacements_retention() {
    for late in [false, true] {
        let mut manager = replacement_retained();
        if late {
            late_restart(&mut manager, 1);
        } else {
            restart(&mut manager, 1);
        }
        assert_eq!(retention(&manager), (1, 1, true), "late: {late}");
        assert_eq!(manager.retention_owner.get(&peer()), Some(&2));
    }
}

/// A `PeerUp` that names no superseded session keeps the collision
/// handling: either session may survive, so the first stays live and the
/// second's end fails over to it, under graceful restart too. The second
/// half is the reported order without the name, and it still fails over.
#[test]
fn peer_up_naming_no_session_keeps_the_collision_failover() {
    let mut manager = test_manager();
    peer_up(&mut manager, 5);
    peer_up(&mut manager, 6);
    assert_eq!(live(&manager), [5, 6]);
    peer_down(&mut manager, 6);
    assert_eq!(manager.current_session_id(peer()), Some(5));
    assert!(failed_over(&manager, 1));

    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    peer_up(&mut manager, 2);
    receive_route(&mut manager);
    restart(&mut manager, 2);
    assert_eq!(manager.current_session_id(peer()), Some(1));
    assert_eq!(retention(&manager), (0, 0, false));
    assert!(failed_over(&manager, 1));
}

/// A replacement that arrives while a collision is unresolved retires only
/// the session it names. The collision candidate (9) stays live and still
/// takes the registration when the replacement goes down.
/// Mutation-red: retiring every other session at a superseding `PeerUp`
/// leaves no survivor, so the replacement's end tears the peer down.
#[test]
fn replacement_during_a_collision_retires_only_the_named_session() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    peer_up(&mut manager, 9);
    peer_up_superseding(&mut manager, 2, Some(1));
    assert_eq!(live(&manager), [9, 2]);
    peer_down(&mut manager, 1);
    assert_eq!(manager.current_session_id(peer()), Some(2));
    peer_down(&mut manager, 2);
    assert_eq!(manager.current_session_id(peer()), Some(9));
    assert!(failed_over(&manager, 1));
}

/// While the replacement is registered, everything the superseded session
/// still delivers is discarded and the replacement's route stays.
/// Mutation-red: without the `PeerUp` check, session 1's `PeerUp` takes the
/// registration back and resets the replacement's routes.
#[test]
fn superseded_session_messages_leave_the_registered_replacement_alone() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    peer_up_superseding(&mut manager, 2, Some(1));
    receive_route(&mut manager);
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer(),
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    restart(&mut manager, 1);
    peer_down(&mut manager, 1);
    late_down(&mut manager, 1);
    peer_up(&mut manager, 1);
    assert_eq!(live(&manager), [2]);
    assert_eq!(retention(&manager), (1, 0, false));
    assert!(discarded(&manager, 3));
    assert!(failed_over(&manager, 0));
}

/// An End-of-RIB the superseded session still delivers must not complete
/// the sweep of the routes its replacement left retained.
/// Mutation-red: with the superseded record kept there is no retention to
/// sweep (the restart end failed over); the discard itself is the
/// session-identity gate for a peer with no session registered.
#[test]
fn superseded_end_of_rib_does_not_sweep_the_replacements_retention() {
    let mut manager = replacement_retained();
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer(),
        session_id: 1,
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
    });
    assert_eq!(retention(&manager), (1, 1, true));
}

/// A replacement over a session that already went down under graceful
/// restart is the ordinary restart reconnect: the retained routes stay for
/// the replacement's End-of-RIB.
#[test]
fn replacement_of_a_restarting_session_keeps_its_retention() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    receive_route(&mut manager);
    restart(&mut manager, 1);
    peer_up_superseding(&mut manager, 2, Some(1));
    assert_eq!(retention(&manager), (1, 1, true));
    late_down(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
    assert!(discarded(&manager, 1));
}

/// Context the superseded session staged for a registration it never made
/// goes with it.
/// Mutation-red: without the removal at `PeerUp` the entry stays.
#[test]
fn superseding_peer_up_drops_what_the_retired_session_staged() {
    let mut manager = test_manager();
    manager.handle_update(RibUpdate::SetPeerPolicyContext {
        peer: peer(),
        session_id: 1,
        peer_group: None,
    });
    assert_eq!(manager.pending_peer_policy_context.len(), 1);
    peer_up_superseding(&mut manager, 2, Some(1));
    assert!(manager.pending_peer_policy_context.is_empty());
}

/// A session cannot supersede itself.
/// Mutation-red: without the filter its own id is recorded.
#[test]
fn superseding_itself_names_nothing() {
    let mut manager = test_manager();
    peer_up_superseding(&mut manager, 2, Some(2));
    assert!(manager.superseded_session.is_empty());
    assert_eq!(live(&manager), [2]);
}

/// The recorded superseded session goes with the neighbor's handle.
/// Mutation-red: without the removal on release the entry stays.
#[test]
fn release_forgets_the_superseded_session() {
    let mut manager = test_manager();
    peer_up_superseding(&mut manager, 2, Some(1));
    assert_eq!(manager.superseded_session.get(&peer()), Some(&1));
    manager.handle_update(RibUpdate::ReleasePeer { peer: peer() });
    assert!(manager.superseded_session.is_empty());
}

/// Notification retirement may queue an inherited owner's cleanup while its
/// disabled replacement never registers. Only the inherited ID owns that GR.
#[test]
fn deferred_cleanup_of_an_unregistered_replacement_purges_its_inherited_owner() {
    let mut manager = test_manager();
    peer_up(&mut manager, 41);
    receive_route(&mut manager);
    restart(&mut manager, 41);
    late_down(&mut manager, 42);
    assert_eq!(
        retention(&manager),
        (1, 1, true),
        "the unregistered actor owns no retention"
    );
    late_down(&mut manager, 41);
    assert_eq!(
        retention(&manager),
        (0, 0, false),
        "the final inherited owner must purge its retention"
    );
}

/// A deferred manager cleanup can outlive several independently registered
/// replacements, beyond the latest superseded-session record.
#[test]
fn deferred_old_owner_cleanup_preserves_gr_after_multiple_replacements() {
    let mut manager = test_manager();
    peer_up(&mut manager, 1);
    peer_up_superseding(&mut manager, 2, Some(1));
    peer_up_superseding(&mut manager, 3, Some(2));
    receive_route(&mut manager);
    restart(&mut manager, 3);
    assert_eq!(retention(&manager), (1, 1, true));
    late_down(&mut manager, 1);
    assert_eq!(retention(&manager), (1, 1, true));
    assert!(failed_over(&manager, 0));
}
