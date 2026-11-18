//! An ordinary input reaches selection between two startup release batches.

use super::*;
use crate::update::{RoutePage, RoutePageError, RoutePageVersion, RouteQueryFilter, RouteQueryKey};

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TARGET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const ROUTES: u32 = 2_049;

fn update(announced: Vec<Route>, withdrawn: Vec<(Prefix, u32)>) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 1,
        announced,
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

fn held_families(rx: mpsc::Receiver<RibUpdate>, waiters: &[(PeerId, (Afi, Safi))]) -> RibManager {
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new()).with_selection_deferral(
        SelectionDeferralConfig {
            timeout: Duration::from_mins(1),
            waiters: waiters
                .iter()
                .map(|&(peer, family)| SelectionDeferralWaiterConfig {
                    peer: peer.into(),
                    families: vec![family],
                })
                .collect(),
        },
    )
}

fn gated_source(rx: mpsc::Receiver<RibUpdate>) -> RibManager {
    let source = peer_v4(SOURCE);
    let mut manager = held_families(rx, &[(source, FAMILY)]);
    manager.test_force_ungrouped = true;
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: source,
        session_id: 1,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![FAMILY],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    register_test_peer(&mut manager, source, 1);
    assert!(manager.selection_deferred(FAMILY));
    manager
}

fn private_receiver(
    manager: &mut RibManager,
    address: Ipv4Addr,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    let mut registration = registering_peer_up(peer, 2);
    let RibUpdate::PeerUp {
        outbound_tx,
        sendable_families,
        ..
    } = &mut registration
    else {
        unreachable!()
    };
    let (tx, rx) = mpsc::channel(64);
    *outbound_tx = tx;
    *sendable_families = vec![FAMILY];
    manager.handle_update(registration);
    assert!(manager.grouped_member_of(peer).is_none());
    assert!(manager.eor_pending(peer).contains(&FAMILY));
    rx
}

fn apply(rows: &mut BTreeSet<Prefix>, update: &OutboundRouteUpdate) {
    for &(prefix, _) in update.unicast_withdrawals() {
        assert!(rows.remove(&prefix), "withdrew an unadvertised prefix");
    }
    for route in update.announce.iter() {
        assert!(
            rows.insert(route.prefix),
            "announced an unchanged prefix twice"
        );
    }
}

fn receive_held_rows(manager: &mut RibManager, evpn: Vec<EvpnRibRoute>) -> BTreeSet<Prefix> {
    let routes: Vec<_> = (0..ROUTES).map(|n| make_indexed_route(n, SOURCE)).collect();
    let expected = routes.iter().map(|r| r.prefix).collect();
    let mut received = update(routes, vec![]);
    if let RibUpdate::RoutesReceived { evpn_announced, .. } = &mut received {
        *evpn_announced = evpn;
    }
    manager.handle_update(received);
    drain_route_chunks(manager);
    assert_eq!(manager.loc_rib.len(), 0);
    expected
}

fn start_release(manager: &mut RibManager) -> BTreeSet<Prefix> {
    let expected = receive_held_rows(manager, vec![]);
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(SOURCE),
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });

    expected
}

#[tokio::test(start_paused = true)]
async fn input_queued_mid_release_precedes_the_last_batch_and_its_marker() {
    let (tx, rx) = mpsc::channel(16);
    let mut manager = gated_source(rx);
    let mut outbound = private_receiver(&mut manager, TARGET);
    let mut expected = start_release(&mut manager);

    // Drive the real continuations until this receiver has admitted its first batch.
    let mut admitted = BTreeSet::new();
    for _ in 0..ROUTES * 4 {
        assert!(
            manager.selection_convergence_held(FAMILY),
            "release completed in one turn"
        );
        if !manager.release_delivery_pending() {
            manager.resync_dirty_peers_bounded();
        }
        while let Ok(envelope) = outbound.try_recv() {
            apply(&mut admitted, &envelope);
            assert!(envelope.end_of_rib.is_empty());
        }
        if !admitted.is_empty() && !manager.release_delivery_pending() {
            break;
        }
        let before = manager.loc_rib.len();
        manager.advance_unicast_release();
        assert!(
            manager.loc_rib.len() - before <= 1024,
            "family-sized selection turn"
        );
    }
    let removed = *admitted
        .first()
        .expect("receiver saw the first release batch");
    assert!(admitted.len() < expected.len());
    assert!(expected.remove(&removed));

    // Submit both mutations to the normal primary FIFO while work remains.
    let mut other = make_v6_route(
        Ipv6Prefix::new(Ipv6Addr::LOCALHOST, 128),
        Ipv6Addr::LOCALHOST,
    );
    set_peer(&mut other, peer_v4(SOURCE));
    let probe = other.prefix;
    let mut events = manager.route_events_tx.subscribe();
    tx.try_send(update(vec![other], vec![(removed, 0)]))
        .unwrap();
    let task = tokio::spawn(manager.run_actor());
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let envelope = outbound.recv().await.expect("live receiver");
            apply(&mut admitted, &envelope);
            if !envelope.end_of_rib.is_empty() {
                assert_eq!(envelope.end_of_rib, [FAMILY]);
                assert_eq!(
                    admitted, expected,
                    "every live prefix at the initial marker"
                );
                break;
            }
        }
    })
    .await
    .expect("release did not finish");

    drop(tx);
    let final_state = task.await.unwrap();
    assert!(!final_state.eor_pending(peer_v4(TARGET)).contains(&FAMILY));
    assert!(!final_state.owes(peer_v4(TARGET), FAMILY));
    while let Ok(envelope) = outbound.try_recv() {
        assert!(envelope.end_of_rib.is_empty());
        assert!(envelope.announce.is_empty());
        assert_eq!(envelope.unicast_withdrawals().count(), 0);
    }
    let mut saw_probe = false;
    let mut saw_withdrawal = false;
    let mut v4_added_after_probe = 0;
    while let Ok(event) = events.try_recv() {
        if event.prefix == probe && event.event_type == RouteEventType::Added {
            saw_probe = true;
        }
        saw_withdrawal |= event.prefix == removed && event.event_type == RouteEventType::Withdrawn;
        if saw_probe
            && matches!(event.prefix, Prefix::V4(_))
            && event.event_type == RouteEventType::Added
        {
            v4_added_after_probe += 1;
        }
    }
    assert!(saw_probe && saw_withdrawal);
    assert!(
        v4_added_after_probe > 0,
        "the unrelated update waited for all released prefixes"
    );
}

#[test]
fn one_release_poll_admits_only_a_bounded_page_of_group_members() {
    let (_tx, rx) = mpsc::channel(8);
    let waiter = peer_v4(Ipv4Addr::new(203, 0, 113, 254));
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: waiter.into(),
                families: vec![FAMILY],
            }],
        });
    let connect = |manager: &mut RibManager, last| {
        let peer = peer_v4(Ipv4Addr::new(203, 0, 113, last));
        let mut registration = registering_peer_up(peer, u64::from(last));
        let (tx, rx) = mpsc::channel(8);
        let RibUpdate::PeerUp {
            outbound_tx,
            sendable_families,
            ..
        } = &mut registration
        else {
            unreachable!()
        };
        *outbound_tx = tx;
        *sendable_families = vec![FAMILY];
        manager.handle_update(registration);
        assert!(manager.grouped_member_of(peer).is_some());
        rx
    };
    let mut existing = connect(&mut manager, 2);
    register_test_peer(&mut manager, peer_v4(SOURCE), 1);
    let route = make_indexed_route(1000, SOURCE);
    let prefix = route.prefix;
    manager.handle_update(update(vec![route], vec![]));
    drain_route_chunks(&mut manager);
    assert!(
        std::iter::from_fn(|| existing.try_recv().ok())
            .any(|message| message.announce.iter().any(|row| row.prefix == prefix))
    );

    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: waiter,
        session_id: 254,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![FAMILY],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    register_test_peer(&mut manager, waiter, 254);
    assert!(manager.selection_deferred(FAMILY));
    let mut group: Vec<_> = (3..40)
        .map(|last| (connect(&mut manager, last), false, false))
        .collect();
    for (rx, _, _) in &mut group {
        assert!(rx.try_recv().is_err(), "a held initial row left early");
    }
    manager.handle_update(RibUpdate::EndOfRib {
        peer: waiter,
        session_id: 254,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    let mut polls_with_rows = 0;
    for _ in 0..500 {
        if !manager.unicast_release_runnable() {
            break;
        }
        manager.advance_unicast_release();
        let mut rows_this_poll = 0;
        for (rx, saw_row, saw_marker) in &mut group {
            while let Ok(message) = rx.try_recv() {
                for row in message.announce.iter() {
                    assert_eq!(row.prefix, prefix);
                    assert!(!*saw_row && !*saw_marker);
                    *saw_row = true;
                    rows_this_poll += 1;
                }
                if message.end_of_rib.contains(&FAMILY) {
                    assert!(*saw_row && !*saw_marker);
                    *saw_marker = true;
                }
            }
        }
        assert!(rows_this_poll <= 16, "one poll visited the entire group");
        polls_with_rows += usize::from(rows_this_poll != 0);
    }
    assert_eq!(polls_with_rows, 3);
    assert!(!manager.unicast_release_runnable());
    assert!(group.iter().all(|(_, row, marker)| *row && *marker));
    assert!(
        std::iter::from_fn(|| existing.try_recv().ok())
            .all(|message| message.announce.is_empty() && !message.end_of_rib.contains(&FAMILY))
    );
}

fn page(
    manager: &mut RibManager,
    accept_releasing: bool,
    filter: Option<RouteQueryFilter>,
    cursor: Option<(RouteQueryKey, RoutePageVersion)>,
) -> oneshot::Receiver<Result<RoutePage, RoutePageError>> {
    let (reply, response) = oneshot::channel();
    let (after, expected_version) = cursor.unzip();
    manager.serve_general_query(RibUpdate::QueryRoutesPage {
        accept_releasing,
        scope: RouteQueryScope::Best,
        filter,
        after,
        expected_version,
        page_size: 1,
        reply,
    });
    response
}

#[tokio::test(start_paused = true)]
async fn marked_pages_report_partial_and_empty_results_while_legacy_reads_wait() {
    let (tx, rx) = mpsc::channel(8);
    let mut manager = gated_source(rx);
    let expected = start_release(&mut manager);
    while manager.unicast_release_in_progress(Afi::Ipv4)
        && (manager.loc_rib.len() < 2 || manager.release_delivery_pending())
    {
        manager.advance_unicast_release();
    }
    let first = page(&mut manager, true, None, None)
        .try_recv()
        .unwrap()
        .unwrap();
    assert_eq!(first.releasing, [true, false]);
    assert!(first.has_more && first.total < u64::from(ROUTES));
    let empty = page(&mut manager, true, Some(Box::new(|_| false)), None)
        .try_recv()
        .unwrap()
        .unwrap();
    assert_eq!(empty.releasing, [true, false]);
    assert!(empty.routes.is_empty() && !empty.has_more);
    let mut legacy = page(&mut manager, false, None, None);
    let absent = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 51), 32));
    let (reply, mut missing) = oneshot::channel();
    manager.serve_general_query(RibUpdate::LookupBestPath {
        prefix: absent,
        reply,
    });
    assert!(matches!(
        legacy.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        missing.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    let prior_count = manager.loc_rib.len();
    while manager.unicast_release_runnable() && manager.loc_rib.len() == prior_count {
        manager.advance_unicast_release();
    }
    assert!(manager.loc_rib.len() > prior_count);
    let cursor = (route_query_key(first.routes.last().unwrap()), first.version);
    assert!(matches!(
        page(&mut manager, true, None, Some(cursor)).try_recv(),
        Ok(Err(RoutePageError::Invalidated))
    ));
    let task = tokio::spawn(manager.run_actor());
    let completed = legacy.await.unwrap().unwrap();
    assert_eq!(completed.releasing, [false, false]);
    assert_eq!(completed.total, expected.len() as u64);
    assert!(missing.await.unwrap().is_none());
    drop(tx);
    drop(task.await.unwrap());
}

fn gr_session(
    manager: &mut RibManager,
    peer: PeerId,
    session_id: u64,
    family: (Afi, Safi),
) -> mpsc::Receiver<OutboundRouteUpdate> {
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![family],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let mut up = registering_peer_up(peer, session_id);
    let RibUpdate::PeerUp {
        outbound_tx,
        sendable_families,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    let (tx, rx) = mpsc::channel(64);
    *outbound_tx = tx;
    *sendable_families = vec![family];
    manager.handle_update(up);
    rx
}

#[derive(Default)]
struct InitialTable {
    rows: BTreeSet<Prefix>,
    markers: usize,
}

impl InitialTable {
    fn receive(&mut self, receiver: &mut mpsc::Receiver<OutboundRouteUpdate>) {
        while let Ok(message) = receiver.try_recv() {
            assert_eq!(self.markers, 0, "delivery after the initial marker");
            apply(&mut self.rows, &message);
            if !message.end_of_rib.is_empty() {
                assert_eq!(message.end_of_rib, [FAMILY]);
                self.markers += 1;
            }
        }
    }
}

#[test]
fn rearmed_collision_stage_keeps_the_private_cursor_open_until_its_live_replay_finishes() {
    let survivor = peer_v4(Ipv4Addr::new(203, 0, 113, 10));
    let new_waiter = peer_v4(Ipv4Addr::new(203, 0, 113, 11));
    let evpn_waiter = peer_v4(Ipv4Addr::new(203, 0, 113, 12));
    let evpn = (Afi::L2Vpn, Safi::Evpn);
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = held_families(
        rx,
        &[
            (survivor, FAMILY),
            (new_waiter, FAMILY),
            (evpn_waiter, evpn),
        ],
    );
    manager.test_force_ungrouped = true;
    let _surviving_session = gr_session(&mut manager, survivor, 11, FAMILY);
    let _replacement = gr_session(&mut manager, survivor, 12, FAMILY);
    let _evpn = gr_session(&mut manager, evpn_waiter, 1, evpn);
    register_test_peer(&mut manager, peer_v4(SOURCE), 1);
    let mut target = private_receiver(&mut manager, TARGET);
    let mut wanted = receive_held_rows(&mut manager, vec![make_evpn_imet(SOURCE, 7)]);
    manager.handle_update(RibUpdate::PeerDown {
        peer: survivor,
        session_id: 12,
    });
    assert!(manager.unicast_release_runnable() && !manager.selection_deferred(FAMILY));
    let mut first = InitialTable::default();
    while first.rows.is_empty() || manager.release_delivery_pending() {
        assert!(manager.unicast_release_runnable());
        manager.advance_unicast_release();
        if !manager.release_delivery_pending() {
            manager.resync_dirty_peers_bounded();
        }
        first.receive(&mut target);
    }
    assert_eq!(first.markers, 0);
    let processed = *first.rows.first().unwrap();
    let pending = *wanted
        .iter()
        .find(|prefix| manager.loc_rib.get(prefix).is_none())
        .unwrap();

    let _new = gr_session(&mut manager, new_waiter, 1, FAMILY);
    assert!(manager.selection_deferred(FAMILY));
    assert!(!manager.unicast_release_runnable());
    assert!(manager.unicast_release_in_progress(FAMILY.0));
    let late_address = Ipv4Addr::new(192, 0, 2, 3);
    let mut late = private_receiver(&mut manager, late_address);
    manager.handle_update(update(vec![], vec![(processed, 0), (pending, 0)]));
    drain_route_chunks(&mut manager);
    wanted.remove(&processed);
    wanted.remove(&pending);
    let mut second = InitialTable::default();
    for _ in 0..8 {
        manager.resync_dirty_peers_bounded();
        first.receive(&mut target);
        second.receive(&mut late);
    }
    assert_eq!((first.markers, second.markers), (0, 0));
    assert!(
        manager.owes(peer_v4(TARGET), FAMILY),
        "open cursor lost its tail"
    );
    manager.handle_update(RibUpdate::BeginRouteRefresh {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    manager.handle_update(RibUpdate::EndRouteRefresh {
        peer: survivor,
        session_id: 11,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    assert!(manager.selection_deferred(FAMILY));
    manager.handle_update(RibUpdate::EndOfRib {
        peer: new_waiter,
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    for _ in 0..ROUTES {
        if !manager.unicast_release_runnable() && !manager.resync_tick_pending() {
            break;
        }
        manager.advance_unicast_release();
        if !manager.release_delivery_pending() {
            manager.resync_dirty_peers_bounded();
        }
        first.receive(&mut target);
        second.receive(&mut late);
    }
    for table in [first, second] {
        assert_eq!(table.rows, wanted);
        assert_eq!(table.markers, 1);
    }
    assert!(!manager.selection_convergence_held(FAMILY));
    assert!(manager.selection_deferred(evpn));
    assert_eq!(manager.loc_rib.evpn_len(), 0);
}

#[test]
fn repeated_mutation_of_a_crowded_prefix_allows_cold_release_keys_to_finish() {
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = gated_source(rx);
    let mut hot = make_indexed_route(0, SOURCE);
    // More paths than two selection budgets; more cold keys than one
    // inventory batch. The hot prefix is in the first inventory batch.
    let cold: Vec<_> = (1..=300).map(|n| make_indexed_route(n, SOURCE)).collect();
    let mut all = cold.clone();
    all.extend((0..2500).map(|id| {
        let mut route = hot.clone();
        route.path_id = id;
        route
    }));
    manager.handle_update(update(all, vec![]));
    drain_route_chunks(&mut manager);
    assert!(manager.loc_rib.is_empty());
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(SOURCE),
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    let mut mutations = 0;
    for _ in 0..256 {
        manager.advance_unicast_release();
        if cold
            .iter()
            .all(|route| manager.loc_rib.get(&route.prefix).is_some())
        {
            break;
        }
        if !manager.release_delivery_pending() {
            mutations += 1;
            hot.next_hop = if hot.next_hop == IpAddr::V4(SOURCE) {
                IpAddr::V4(TARGET)
            } else {
                IpAddr::V4(SOURCE)
            };
            manager.handle_update(update(vec![hot.clone()], vec![]));
            drain_route_chunks(&mut manager);
        }
    }
    assert!(
        mutations >= 2,
        "the input did not change between release steps"
    );
    assert!(
        cold.iter()
            .all(|route| manager.loc_rib.get(&route.prefix).is_some()),
        "the contested prefix starved cold keys in a later inventory batch"
    );
    drain_unicast_release(&mut manager);
    assert_eq!(manager.loc_rib.len(), cold.len() + 1);
    assert_eq!(
        manager.loc_rib.get(&hot.prefix).unwrap().next_hop,
        hot.next_hop
    );
    assert!(!manager.selection_convergence_held(FAMILY));
}

#[test]
fn live_joins_on_both_sides_of_enrollment_receive_the_full_released_family() {
    let (_tx, rx) = mpsc::channel(8);
    let source = peer_v4(SOURCE);
    let v6 = (Afi::Ipv6, Safi::Unicast);
    let v6_waiter = peer_v4(Ipv4Addr::new(203, 0, 113, 254));
    let mut manager = held_families(rx, &[(source, FAMILY), (v6_waiter, v6)]);
    manager.test_force_ungrouped = true;
    let _source = gr_session(&mut manager, source, 1, FAMILY);
    let mut v6_receiver = gr_session(&mut manager, v6_waiter, 1, v6);
    for n in 10..50 {
        register_test_peer(&mut manager, peer_v4(Ipv4Addr::new(10, 0, 0, n)), 1);
    }
    let expected = start_release(&mut manager);
    // The first peer page ends among 10.0.0.10..49, before any key is consumed.
    manager.advance_unicast_release();
    assert_eq!(manager.loc_rib.len(), 0);
    let mut receivers: Vec<_> = [Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(203, 0, 113, 1)]
        .map(|address| {
            (
                private_receiver(&mut manager, address),
                InitialTable::default(),
            )
        })
        .into();
    while manager.loc_rib.is_empty() || manager.release_delivery_pending() {
        assert!(manager.unicast_release_runnable());
        manager.advance_unicast_release();
    }
    assert!(manager.loc_rib.len() < expected.len());
    receivers.push((
        private_receiver(&mut manager, TARGET),
        InitialTable::default(),
    ));

    for _ in 0..ROUTES {
        if !manager.unicast_release_runnable() && !manager.resync_tick_pending() {
            break;
        }
        manager.advance_unicast_release();
        if !manager.release_delivery_pending() {
            manager.resync_dirty_peers_bounded();
        }
        for (receiver, table) in &mut receivers {
            table.receive(receiver);
        }
    }
    for (_, table) in receivers {
        assert_eq!(table.markers, 1);
        assert_eq!(table.rows, expected);
    }
    assert!(manager.selection_deferred(v6));
    assert!(!manager.release_peer_batch(None, 1).is_empty());
    manager.handle_update(RibUpdate::EndOfRib {
        peer: v6_waiter,
        session_id: 1,
        afi: v6.0,
        safi: v6.1,
    });
    drain_unicast_release(&mut manager);
    manager.resync_dirty_peers_bounded();
    assert_eq!(v6_receiver.try_recv().unwrap().end_of_rib, [v6]);
    assert!(!manager.unicast_release_runnable());
    assert!(manager.release_peer_batch(None, 1).is_empty());
    let later = peer_v4(Ipv4Addr::new(203, 0, 113, 2));
    register_test_peer(&mut manager, later, 7);
    assert_eq!(manager.current_session_id(later), Some(7));
    assert!(manager.release_peer_batch(None, 1).is_empty());
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one release transcript checks admission, refusal and corrective replay of per-client-best denials"
)]
fn refused_pcb_release_keeps_member_denials_for_corrective_admission() {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = gated_source(rx);
    manager.test_force_ungrouped = false;
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let deny = PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Deny,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: Some(200),
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }]);
    let register = |manager: &mut RibManager, peer: PeerId| {
        let (tx, rx) = mpsc::channel(8);
        let mut registration = registering_peer_up(peer, 2);
        if let RibUpdate::PeerUp {
            outbound_tx,
            export_policy,
            sendable_families,
            per_client_best,
            ..
        } = &mut registration
        {
            *outbound_tx = tx;
            *export_policy = Some(deny.clone());
            *sendable_families = vec![FAMILY];
            *per_client_best = true;
        }
        manager.handle_update(registration);
        rx
    };
    let fast = peer_v4(TARGET);
    let slow = peer_v4(Ipv4Addr::new(192, 0, 2, 3));
    let mut fast_rx = register(&mut manager, fast);
    let mut slow_rx = register(&mut manager, slow);
    let gid = manager.grouped_member_of(fast).unwrap();
    assert_eq!(manager.grouped_member_of(slow), Some(gid));
    assert!(manager.group_ribs[&gid].per_client_best);
    let denied = 385;
    let mut routes: Vec<_> = (1..=denied)
        .map(|path_id| {
            let mut path = make_route_with_lp(prefix, SOURCE, 300);
            path.path_id = path_id;
            path
        })
        .collect();
    routes.push(make_route_with_lp(prefix, SOURCE, 100));
    manager.handle_update(update(routes, vec![]));
    drain_route_chunks(&mut manager);
    let sender = manager.outbound_peers[&slow].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}

    let totals = |manager: &RibManager| {
        [fast, slow].map(|peer| {
            manager
                .export_policy_counters
                .get(&peer)
                .map_or(0, |counters| {
                    counters.snapshot().export_policy_routes_denied
                })
        })
    };
    let before_release = totals(&manager);
    let mut events = manager.route_events_tx.subscribe();
    let captures = manager.adj_rib_out_commit_stats.group_table_captures;
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(SOURCE),
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    let mut fast_denials = HashSet::new();
    while manager.unicast_release_runnable() {
        let prior = totals(&manager);
        manager.advance_unicast_release();
        let current = totals(&manager);
        for i in 0..2 {
            assert!(current[i] - prior[i] <= 128, "unpaced policy counters");
        }
        let before = fast_denials.len();
        while let Ok(event) = events.try_recv() {
            if event.event_type == RouteEventType::PolicyFiltered {
                assert_eq!(event.target_peer, Some(fast.addr()));
                assert!(fast_denials.insert(event.path_id), "duplicate denial");
            }
        }
        assert!(fast_denials.len() - before <= 128, "unpaced denial events");
    }
    assert_eq!(fast_denials, (1..=denied).collect());
    assert_eq!(
        totals(&manager),
        before_release.map(|n| n + u64::from(denied)),
        "policy evaluations count even when the writer refuses the send"
    );
    assert_eq!(
        manager.adj_rib_out_commit_stats.group_table_captures,
        captures
    );
    assert!(manager.dirty_peers.contains(&slow));
    assert!(!manager.policy_filtered_routes.contains_key(&slow));
    let mut rows = 0;
    let mut markers = 0;
    while let Ok(update) = fast_rx.try_recv() {
        rows += update.announce.len();
        if update.end_of_rib.contains(&FAMILY) {
            assert_eq!(rows, 1);
            markers += 1;
        }
    }
    assert_eq!((rows, markers), (1, 1));
    while let Ok(update) = slow_rx.try_recv() {
        assert!(update.announce.is_empty() && update.end_of_rib.is_empty());
    }
    manager.resync_dirty_peers_bounded();
    let mut recovered = HashSet::new();
    while let Ok(event) = events.try_recv() {
        if event.event_type == RouteEventType::PolicyFiltered {
            assert_eq!(event.target_peer, Some(slow.addr()));
            assert!(recovered.insert(event.path_id));
        }
    }
    assert_eq!(recovered, fast_denials);
    assert!(!manager.dirty_peers.contains(&slow));
    let mut rows = 0;
    let mut markers = 0;
    while let Ok(update) = slow_rx.try_recv() {
        rows += update.announce.len();
        if update.end_of_rib.contains(&FAMILY) {
            assert_eq!(rows, 1);
            markers += 1;
        }
    }
    assert_eq!((rows, markers), (1, 1));
}
