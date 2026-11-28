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
            assert_eq!(envelope.end_of_rib, []);
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
        assert_eq!(envelope.end_of_rib, []);
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
    assert_ne!(manager.release_peer_batch(None, 1), []);
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
    assert_eq!(manager.release_peer_batch(None, 1), []);
    let later = peer_v4(Ipv4Addr::new(203, 0, 113, 2));
    register_test_peer(&mut manager, later, 7);
    assert_eq!(manager.current_session_id(later), Some(7));
    assert_eq!(manager.release_peer_batch(None, 1), []);
}

fn deny_local_pref_from(local_pref: u32) -> rustbgpd_policy::PolicyChain {
    use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};
    PolicyChain::new(vec![Policy {
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
            match_local_pref_ge: Some(local_pref),
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications::default(),
        }],
        default_action: PolicyAction::Permit,
    }])
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one release transcript checks admission, refusal and corrective replay of per-client-best denials"
)]
fn refused_pcb_release_keeps_member_denials_for_corrective_admission() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = gated_source(rx);
    manager.test_force_ungrouped = false;
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let deny = deny_local_pref_from(200);
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

// Work a startup release spends on one group of route-server clients that
// were Established during the hold. `per_client` selects RFC 7947 per-client
// best; the ordinary single-best group of the same shape is the control.

const PROBE_SOURCE: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
const V6: (Afi, Safi) = (Afi::Ipv6, Safi::Unicast);

#[derive(Debug)]
struct ReleaseWork {
    polls: usize,
    longest_fenced_polls: usize,
    longest_fenced: Duration,
    elapsed: Duration,
    handoffs: usize,
}

fn client(n: usize) -> PeerId {
    let high = u8::try_from(n / 200).unwrap();
    let low = u8::try_from(n % 200).unwrap() + 1;
    peer_v4(Ipv4Addr::new(10, 200, high, low))
}

fn held_client_group(
    members: usize,
    rows: u32,
    per_client: bool,
) -> (
    RibManager,
    mpsc::Sender<RibUpdate>,
    Vec<mpsc::Receiver<OutboundRouteUpdate>>,
) {
    let (tx, rx) = mpsc::channel(64);
    let mut manager = gated_source(rx);
    manager.test_force_ungrouped = false;
    let receivers = (0..members)
        .map(|n| {
            let mut registration = registering_peer_up(client(n), 2);
            let RibUpdate::PeerUp {
                outbound_tx,
                sendable_families,
                per_client_best,
                ..
            } = &mut registration
            else {
                unreachable!()
            };
            // No send is refused, so every count below is the clean path.
            let (out, rx) = mpsc::channel(rows as usize + 64);
            *outbound_tx = out;
            *sendable_families = vec![FAMILY];
            *per_client_best = per_client;
            manager.handle_update(registration);
            rx
        })
        .collect();
    let gid = manager
        .grouped_member_of(client(0))
        .expect("grouped client");
    for n in 0..members {
        assert_eq!(manager.grouped_member_of(client(n)), Some(gid));
    }
    assert_eq!(manager.group_ribs[&gid].per_client_best, per_client);
    manager.handle_update(update(
        (0..rows).map(|n| make_indexed_route(n, SOURCE)).collect(),
        vec![],
    ));
    drain_route_chunks(&mut manager);
    assert_eq!(manager.loc_rib.len(), 0);
    assert!(manager.selection_deferred(FAMILY));
    (manager, tx, receivers)
}

#[test]
fn paged_release_counts_preexisting_refusals_as_slots_become_visible() {
    use super::exportability::MockExactExportEncoder;
    use crate::update::ExactExportKey;

    // A 16-member delivery page leaves the last client on a third page.
    let (mut manager, _tx, mut receivers) = held_client_group(33, 2, false);
    let prefix = make_indexed_route(0, SOURCE).prefix;
    let allowed = make_indexed_route(1, SOURCE).prefix;
    let refused = ExactExportKey::Unicast(prefix, 0);
    let encoder = MockExactExportEncoder::accepting(1);
    encoder.set_profile(1, [refused.clone()]);
    for n in 0..receivers.len() {
        let peer = client(n);
        manager.peer_export_encoders.insert(peer, encoder.clone());
        manager.set_exact_export_rejection(peer, refused.clone(), true);
    }
    let gid = manager.grouped_member_of(client(0)).unwrap();
    assert!(manager.group_ribs[&gid].table.get(&prefix, 0).is_none());

    drive_release(&mut manager);

    assert!(manager.group_ribs[&gid].table.get(&prefix, 0).is_some());
    for (n, receiver) in receivers.iter_mut().enumerate() {
        let peer = client(n);
        let mut wire = BTreeSet::new();
        while let Ok(update) = receiver.try_recv() {
            apply(&mut wire, &update);
        }
        assert_eq!(wire, BTreeSet::from([allowed]), "client {n}");
        assert!(manager.peer_unexportable[&peer].contains(&refused));
        assert!(manager.initial_group_admitted_counts(peer).is_none());
        assert_eq!(
            manager.grouped_advertised_count(peer),
            Some(1),
            "client {n}"
        );
        assert_eq!(manager.grouped_family_counts(peer), Some(vec![(FAMILY, 1)]));
    }
}

fn source_end_of_rib() -> RibUpdate {
    RibUpdate::EndOfRib {
        peer: peer_v4(SOURCE),
        session_id: 1,
        afi: FAMILY.0,
        safi: FAMILY.1,
    }
}

fn drive_release(manager: &mut RibManager) -> ReleaseWork {
    let handoffs = EXECUTOR_HANDOFFS.with(|handoffs| handoffs.get().0);
    let start = Instant::now();
    manager.handle_update(source_end_of_rib());
    let mut work = ReleaseWork {
        polls: 0,
        longest_fenced_polls: 0,
        longest_fenced: Duration::ZERO,
        elapsed: Duration::ZERO,
        handoffs: 0,
    };
    let mut run = 0;
    let mut fence = None;
    // The actor loop admits primary input and timers only when this is false.
    while manager.unicast_release_runnable() {
        let opened = *fence.get_or_insert_with(Instant::now);
        manager.advance_unicast_release();
        work.polls += 1;
        if manager.release_delivery_pending() {
            run += 1;
            work.longest_fenced_polls = work.longest_fenced_polls.max(run);
        } else {
            if run > 0 {
                work.longest_fenced = work.longest_fenced.max(opened.elapsed());
            }
            run = 0;
            fence = None;
        }
    }
    work.elapsed = start.elapsed();
    work.handoffs = EXECUTOR_HANDOFFS.with(|handoffs| handoffs.get().0) - handoffs;
    work
}

/// Row-carrying envelopes for the busiest member, and the largest envelope.
fn tally(receivers: &mut [mpsc::Receiver<OutboundRouteUpdate>], rows: u32) -> (usize, usize) {
    let (mut most, mut largest) = (0, 0);
    for receiver in receivers {
        let (mut envelopes, mut seen, mut markers) = (0, BTreeSet::new(), 0);
        while let Ok(update) = receiver.try_recv() {
            if !update.announce.is_empty() {
                envelopes += 1;
                largest = largest.max(update.announce.len());
                apply(&mut seen, &update);
            }
            markers += usize::from(update.end_of_rib.contains(&FAMILY));
        }
        assert_eq!((seen.len(), markers), (rows as usize, 1));
        most = most.max(envelopes);
    }
    (most, largest)
}

#[test]
fn a_per_client_best_release_batch_is_not_paged_by_prefix_times_member() {
    for (members, rows) in [(4_usize, 64_u32), (32, 64), (32, 256), (40, 1_024)] {
        let [ordinary, per_client] = [false, true].map(|per_client| {
            let (mut manager, _tx, mut receivers) = held_client_group(members, rows, per_client);
            let work = drive_release(&mut manager);
            let (envelopes, largest) = tally(&mut receivers, rows);
            eprintln!(
                "release-work per_client_best={per_client} members={members} rows={rows} \
                 fenced_polls={} total_polls={} handoffs={} envelopes_per_member={envelopes} \
                 max_rows_per_envelope={largest}",
                work.longest_fenced_polls, work.polls, work.handoffs
            );
            (work, envelopes, largest)
        });
        // One source and one candidate: four ranking units a prefix, 128 a poll.
        // Nothing else separates the two groups: no poll per prefix, none per
        // member, and in particular no denial poll for a member with no denials.
        let ranking = (rows as usize).div_ceil(32) + 2;
        assert!(
            per_client.0.longest_fenced_polls <= ordinary.0.longest_fenced_polls + ranking,
            "{members}x{rows}: {} fenced polls against {} for the ordinary group",
            per_client.0.longest_fenced_polls,
            ordinary.0.longest_fenced_polls
        );
        assert_eq!(per_client.0.handoffs, ordinary.0.handoffs);
        assert_eq!((per_client.1, per_client.2), (1, rows as usize));
        assert_eq!((ordinary.1, ordinary.2), (1, rows as usize));
    }
}

const TIMED_SHAPES: [(usize, u32); 2] = [(32, 16_384), (150, 16_384)];

#[test]
#[ignore = "indicative wall-clock probe; run by name in an optimized profile"]
fn timing_client_group_release_direct_drive() {
    for (members, rows) in TIMED_SHAPES {
        for per_client in [false, true] {
            let (mut manager, _tx, mut receivers) = held_client_group(members, rows, per_client);
            let work = drive_release(&mut manager);
            let (envelopes, largest) = tally(&mut receivers, rows);
            eprintln!(
                "release-direct per_client_best={per_client} members={members} rows={rows} \
                 wall_ms={:.1} longest_fenced_ms={:.1} fenced_polls={} total_polls={} \
                 ns_per_poll={} handoffs={} envelopes_per_member={envelopes} \
                 max_rows_per_envelope={largest}",
                work.elapsed.as_secs_f64() * 1e3,
                work.longest_fenced.as_secs_f64() * 1e3,
                work.longest_fenced_polls,
                work.polls,
                work.elapsed.as_nanos() / work.polls as u128,
                work.handoffs
            );
        }
    }
}

/// An unrelated peer's IPv6 UPDATE, timed from the primary queue to its receiver.
async fn primary_lane_probe(
    tx: &mpsc::Sender<RibUpdate>,
    receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
    n: u32,
) -> Duration {
    let [high, low] = [n >> 16, n & 0xffff].map(|half| u16::try_from(half).unwrap());
    let prefix = Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, high, low), 128);
    let mut probe = update(vec![make_v6_route(prefix, PROBE_SOURCE)], vec![]);
    if let RibUpdate::RoutesReceived { peer, .. } = &mut probe {
        *peer = PeerId::from_addr(IpAddr::V6(PROBE_SOURCE));
    }
    let sent = Instant::now();
    tx.send(probe).await.unwrap();
    loop {
        let update = tokio::time::timeout(Duration::from_mins(20), receiver.recv())
            .await
            .expect("probe delivered")
            .expect("actor alive");
        if update
            .announce
            .iter()
            .any(|row| row.prefix == Prefix::V6(prefix))
        {
            return sent.elapsed();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "indicative wall-clock probe; run by name in an optimized profile"]
async fn timing_client_group_release_through_the_actor_loop() {
    for (members, rows) in TIMED_SHAPES {
        for per_client in [false, true] {
            let (mut manager, tx, receivers) = held_client_group(members, rows, per_client);
            manager.handle_update(registering_peer_up(
                PeerId::from_addr(IpAddr::V6(PROBE_SOURCE)),
                1,
            ));
            let mut registration = registering_peer_up(peer_v4(Ipv4Addr::new(203, 0, 113, 9)), 1);
            let RibUpdate::PeerUp {
                outbound_tx,
                sendable_families,
                ..
            } = &mut registration
            else {
                unreachable!()
            };
            let (out, mut probe_rx) = mpsc::channel(64);
            *outbound_tx = out;
            *sendable_families = vec![V6];
            manager.handle_update(registration);
            let actor = tokio::spawn(manager.run());
            let idle = primary_lane_probe(&tx, &mut probe_rx, 0).await;

            let start = Instant::now();
            tx.send(source_end_of_rib()).await.unwrap();
            let clients: Vec<_> = receivers
                .into_iter()
                .map(|mut receiver| {
                    tokio::spawn(async move {
                        let (mut envelopes, mut seen, mut largest) = (0_usize, 0_usize, 0_usize);
                        loop {
                            let update = receiver.recv().await.expect("actor alive");
                            if !update.announce.is_empty() {
                                envelopes += 1;
                                seen += update.announce.len();
                                largest = largest.max(update.announce.len());
                            }
                            if update.end_of_rib.contains(&FAMILY) {
                                return (envelopes, seen, largest, Instant::now());
                            }
                        }
                    })
                })
                .collect();
            let all = tokio::spawn(async move {
                let mut results = Vec::new();
                for client in clients {
                    results.push(client.await.unwrap());
                }
                results
            });
            let (mut probes, mut worst, mut total) = (0_u32, Duration::ZERO, Duration::ZERO);
            while !all.is_finished() {
                probes += 1;
                let wait = primary_lane_probe(&tx, &mut probe_rx, probes).await;
                worst = worst.max(wait);
                total += wait;
            }
            let results = all.await.unwrap();
            let last_marker = results.iter().map(|r| r.3).max().unwrap();
            eprintln!(
                "release-actor per_client_best={per_client} members={members} rows={rows} \
                 wall_ms={:.1} probe_idle_us={} probe_worst_ms={:.1} probe_mean_ms={:.2} \
                 probes={probes} envelopes_per_member={}..{} rows_per_member={}..{} \
                 max_rows_per_envelope={}",
                (last_marker - start).as_secs_f64() * 1e3,
                idle.as_micros(),
                worst.as_secs_f64() * 1e3,
                total.as_secs_f64() * 1e3 / f64::from(probes.max(1)),
                results.iter().map(|r| r.0).min().unwrap(),
                results.iter().map(|r| r.0).max().unwrap(),
                results.iter().map(|r| r.1).min().unwrap(),
                results.iter().map(|r| r.1).max().unwrap(),
                results.iter().map(|r| r.2).max().unwrap(),
            );
            drop(tx);
            actor.await.unwrap();
        }
    }
}

// A route-server client group whose members also source routes, checked
// against a ranking computed here from the announced candidates.

const RS_AS: u32 = 65_000;
const OTHER_SOURCE: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const DENIED_FROM: u32 = 200;

fn client_addr(n: usize) -> Ipv4Addr {
    let IpAddr::V4(address) = client(n).addr() else {
        unreachable!()
    };
    address
}

fn client_asn(n: usize) -> u32 {
    64_600 + u32::try_from(n).unwrap()
}

fn rs_client(
    manager: &mut RibManager,
    n: usize,
    rs_control: bool,
    capacity: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    if rs_control {
        manager.handle_update(RibUpdate::SetPeerRsControl {
            peer: client(n),
            session_id: 2,
            rs_control_asn: Some(RS_AS),
        });
    }
    let mut registration = registering_peer_up(client(n), 2);
    let RibUpdate::PeerUp {
        peer_asn,
        outbound_tx,
        export_policy,
        sendable_families,
        per_client_best,
        ..
    } = &mut registration
    else {
        unreachable!()
    };
    let (tx, rx) = mpsc::channel(capacity);
    *peer_asn = client_asn(n);
    *outbound_tx = tx;
    *export_policy = Some(deny_local_pref_from(DENIED_FROM));
    *sendable_families = vec![FAMILY];
    *per_client_best = true;
    manager.handle_update(registration);
    rx
}

fn candidate(n: u32, source: Ipv4Addr, local_pref: u32) -> Route {
    let Prefix::V4(prefix) = make_indexed_route(n, source).prefix else {
        unreachable!()
    };
    make_route_with_lp(prefix, source, local_pref)
}

/// Standard community `0:asn`: do not announce to that client.
fn hidden_from(mut route: Route, asn: u32) -> Route {
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.push(PathAttribute::Communities(vec![asn]));
    });
    route
}

fn routes_from(
    peer: PeerId,
    session_id: u64,
    announced: Vec<Route>,
    withdrawn: Vec<Prefix>,
) -> RibUpdate {
    RibUpdate::RoutesReceived {
        peer,
        session_id,
        announced,
        withdrawn: withdrawn.into_iter().map(|prefix| (prefix, 0)).collect(),
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    }
}

/// Every announced candidate, as the test sent it.
#[derive(Default)]
struct Candidates(BTreeMap<Prefix, Vec<Route>>);

impl Candidates {
    fn send(&mut self, manager: &mut RibManager, session_id: u64, announced: Vec<Route>) {
        let peer = announced[0].peer;
        for route in &announced {
            let paths = self.0.entry(route.prefix).or_default();
            paths.retain(|old| (old.peer, old.path_id) != (route.peer, route.path_id));
            paths.push(route.clone());
        }
        manager.handle_update(routes_from(peer, session_id, announced, vec![]));
        drain_route_chunks(manager);
    }

    fn withdraw(
        &mut self,
        manager: &mut RibManager,
        peer: PeerId,
        session_id: u64,
        prefixes: Vec<Prefix>,
    ) {
        for prefix in &prefixes {
            let paths = self.0.get_mut(prefix).expect("announced prefix");
            paths.retain(|old| old.peer != peer);
            if paths.is_empty() {
                self.0.remove(prefix);
            }
        }
        manager.handle_update(routes_from(peer, session_id, vec![], prefixes));
        drain_route_chunks(manager);
    }

    /// The first candidate in best-path order that policy permits, the
    /// client did not source and no control community hides from it.
    fn table(
        &self,
        member: PeerId,
        rs_control_asn: Option<u32>,
    ) -> BTreeMap<Prefix, (PeerId, u32)> {
        let mut table = BTreeMap::new();
        for (prefix, paths) in &self.0 {
            let mut ranked: Vec<_> = paths.iter().collect();
            ranked.sort_by(|a, b| crate::best_path::best_path_cmp(a, b));
            if let Some(best) = ranked.into_iter().find(|route| {
                route.local_pref() < DENIED_FROM
                    && route.peer != member
                    && !rs_control_asn.is_some_and(|asn| route.communities().contains(&asn))
            }) {
                table.insert(*prefix, (best.peer, best.local_pref()));
            }
        }
        table
    }
}

#[derive(Default)]
struct ClientTable {
    rows: BTreeMap<Prefix, (PeerId, u32)>,
    envelopes: usize,
    largest: usize,
    markers: usize,
    // A corrective resync may repeat a row the client already holds.
    replayed: bool,
}

impl ClientTable {
    fn receive(&mut self, receiver: &mut mpsc::Receiver<OutboundRouteUpdate>) {
        while let Ok(update) = receiver.try_recv() {
            let rows = !update.announce.is_empty() || update.unicast_withdrawals().next().is_some();
            assert!(!rows || self.markers == 0, "a row followed End-of-RIB");
            self.envelopes += usize::from(rows);
            self.largest = self.largest.max(update.announce.len());
            for &(prefix, _) in update.unicast_withdrawals() {
                assert!(
                    self.rows.remove(&prefix).is_some(),
                    "withdrew {prefix} twice"
                );
            }
            for route in update.announce.iter() {
                assert_eq!(route.path_id, 0);
                let row = (route.peer, route.local_pref());
                assert!(
                    self.rows.insert(route.prefix, row) != Some(row) || self.replayed,
                    "announced {} unchanged",
                    route.prefix
                );
            }
            self.markers += usize::from(update.end_of_rib.contains(&FAMILY));
        }
    }
}

fn denials(manager: &RibManager, peer: PeerId) -> BTreeSet<(Prefix, PeerId, u32)> {
    manager
        .policy_filtered_routes
        .get(&peer)
        .into_iter()
        .flat_map(|routes| routes.values())
        .flat_map(crate::manager::PolicyFilteredBucket::iter)
        .map(|key| {
            assert_eq!(key.target_peer, peer);
            (key.prefix, key.source_peer, key.path_id)
        })
        .collect()
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one transcript populates the group, changes it under a hold and checks every client"
)]
fn per_client_best_release_matches_the_ranking_for_every_client() {
    const CLIENTS: usize = 20;
    const SLOW: usize = 7;
    const CROWDED: u32 = 900;
    let source = peer_v4(SOURCE);
    let other = peer_v4(OTHER_SOURCE);
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    manager.test_force_ungrouped = false;
    register_test_peer(&mut manager, source, 77);
    register_test_peer(&mut manager, other, 1);
    // Even clients enforce control communities, on both 16-member pages.
    let rs_control = |n: usize| n.is_multiple_of(2).then(|| client_asn(n));
    let mut receivers: Vec<_> = (0..CLIENTS)
        .map(|n| rs_client(&mut manager, n, rs_control(n).is_some(), 512))
        .collect();
    let gid = manager.grouped_member_of(client(0)).expect("grouped");
    for n in 0..CLIENTS {
        assert_eq!(manager.grouped_member_of(client(n)), Some(gid));
    }
    assert!(manager.group_ribs[&gid].per_client_best);
    for receiver in &mut receivers {
        while receiver.try_recv().is_ok() {}
    }

    // Populate: every prefix has two to four candidates of mixed preference,
    // some denied, some hidden from one control-enforcing client.
    let mut sent = Candidates::default();
    let mut tables: Vec<ClientTable> = (0..CLIENTS).map(|_| ClientTable::default()).collect();
    let lp = |n: u32, salt: u32| 100 + 10 * ((n * 7 + salt * 13) % 12);
    let from_source = |n: u32| {
        let route = candidate(n, SOURCE, lp(n, 1));
        match n % 11 {
            0 => hidden_from(route, client_asn(4)),
            5 => hidden_from(route, client_asn(18)),
            _ => route,
        }
    };
    sent.send(&mut manager, 77, (0..300).map(from_source).collect());
    sent.send(
        &mut manager,
        1,
        (0..300)
            .map(|n| candidate(n, OTHER_SOURCE, lp(n, 2)))
            .collect(),
    );
    for member in [0_usize, 1] {
        let salt = 3 + u32::try_from(member).unwrap();
        sent.send(
            &mut manager,
            2,
            (0..300)
                .filter(|n| n % 3 != salt % 3)
                .map(|n| candidate(n, client_addr(member), lp(n, salt)))
                .collect(),
        );
    }
    for (n, receiver) in receivers.iter_mut().enumerate() {
        tables[n].receive(receiver);
        assert_eq!(
            tables[n].rows,
            sent.table(client(n), rs_control(n)),
            "client {n} before the hold"
        );
        tables[n].envelopes = 0;
    }
    // Control communities change what a client is sent.
    assert_ne!(
        sent.table(client(4), rs_control(4)),
        sent.table(client(4), None)
    );

    // Hold the family with the tables populated, then change it underneath.
    manager = manager.with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_mins(1),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: source.into(),
            families: vec![FAMILY],
        }],
    });
    arm_selection_waiter(&mut manager, source, &[FAMILY]);
    assert!(manager.selection_deferred(FAMILY));
    for n in 0..CLIENTS {
        manager.owe_eor(client(n), FAMILY);
    }
    let prefix_of = |n: u32| candidate(n, SOURCE, 0).prefix;
    // Whole prefixes disappear, a winner disappears, a client becomes the
    // source of the best path, a denied path takes the top rank, and new
    // prefixes arrive. One prefix has more denied paths than a denial page.
    for (peer, session) in [(source, 77), (other, 1), (client(0), 2), (client(1), 2)] {
        let gone: Vec<_> = (0..300)
            .filter(|n| n % 7 == 0)
            .map(prefix_of)
            .filter(|prefix| {
                sent.0
                    .get(prefix)
                    .is_some_and(|paths| paths.iter().any(|route| route.peer == peer))
            })
            .collect();
        sent.withdraw(&mut manager, peer, session, gone);
    }
    let winners_gone = (0..300).filter(|n| n % 7 == 1).map(prefix_of).collect();
    sent.withdraw(&mut manager, source, 77, winners_gone);
    sent.send(
        &mut manager,
        2,
        (0..360)
            .filter(|n| n % 7 == 2 || *n >= 300)
            .map(|n| candidate(n, client_addr(0), 190))
            .collect(),
    );
    let mut denied: Vec<_> = (0..360)
        .filter(|n| n % 7 == 3 || *n >= 330)
        .map(|n| candidate(n, OTHER_SOURCE, 300))
        .collect();
    denied.extend((1..=200).map(|path_id| {
        let mut path = candidate(CROWDED, OTHER_SOURCE, 300);
        path.path_id = path_id;
        path
    }));
    sent.send(&mut manager, 1, denied);
    sent.send(
        &mut manager,
        77,
        (300..360)
            .chain([CROWDED])
            .map(|n| candidate(n, SOURCE, 120))
            .collect(),
    );
    sent.send(
        &mut manager,
        2,
        vec![candidate(CROWDED, client_addr(1), 150)],
    );
    for (n, receiver) in receivers.iter_mut().enumerate() {
        tables[n].receive(receiver);
        assert_eq!(
            (tables[n].envelopes, tables[n].markers),
            (0, 0),
            "client {n} was sent a change under the hold"
        );
    }
    // One client's writer is full for the whole release.
    let slow = manager.outbound_peers[&client(SLOW)].clone();
    while slow.try_send(OutboundRouteUpdate::default()).is_ok() {}

    manager.handle_update(RibUpdate::EndOfRib {
        peer: source,
        session_id: 77,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    drain_unicast_release(&mut manager);
    assert!(manager.dirty_peers.contains(&client(SLOW)));
    crate::manager::tests::assert_paced_fallbacks(
        &manager.metrics,
        &[("release_fanout", "writer_unavailable", 1.0)],
    );
    let expected = |n: usize| sent.table(client(n), rs_control(n));
    for (n, receiver) in receivers.iter_mut().enumerate() {
        if n == SLOW {
            continue;
        }
        tables[n].receive(receiver);
        assert_eq!(tables[n].rows, expected(n), "client {n} after the release");
        assert_eq!(tables[n].markers, 1, "client {n} End-of-RIB");
        // One stage for the batch and one for the crowded prefix.
        assert_eq!(tables[n].envelopes, 2, "client {n} envelopes");
    }
    // The refused client recovers through its corrective resync.
    tables[SLOW].receive(&mut receivers[SLOW]);
    assert_eq!((tables[SLOW].envelopes, tables[SLOW].markers), (0, 0));
    drain_resync_ticks(&mut manager);
    assert!(!manager.dirty_peers.contains(&client(SLOW)));
    tables[SLOW].replayed = true;
    tables[SLOW].receive(&mut receivers[SLOW]);
    assert_eq!(tables[SLOW].rows, expected(SLOW), "refused client");
    assert_eq!(tables[SLOW].markers, 1, "refused client End-of-RIB");

    // A client that sources the best path takes the next one.
    let taken_over = prefix_of(2);
    assert_eq!(expected(3)[&taken_over].0, client(0));
    assert_ne!(expected(0)[&taken_over].0, client(0));
    // Denials are the group's, minus the client's own paths.
    let group = &manager.group_ribs[&gid];
    let all: HashSet<Prefix> = sent.0.keys().copied().collect();
    let crowded = prefix_of(CROWDED);
    for (n, table) in tables.iter().enumerate() {
        let from_group: BTreeSet<_> = group
            .policy_filtered_for_member(client(n), &all)
            .into_iter()
            .map(|key| (key.prefix, key.source_peer, key.path_id))
            .collect();
        let recorded = denials(&manager, client(n));
        assert_eq!(recorded, from_group, "client {n} denials");
        assert_eq!(
            recorded.iter().filter(|key| key.0 == crowded).count(),
            200,
            "client {n} crowded prefix"
        );
        assert!(recorded.contains(&(prefix_of(3), other, 0)));
        assert!(recorded.iter().all(|key| sent.0.contains_key(&key.0)));
        assert_eq!(
            group.advertised_count_for(client(n)),
            table.rows.len(),
            "client {n} advertised count"
        );
    }

    // The synchronous ranking of every prefix finds nothing left to change.
    let before: Vec<_> = (0..CLIENTS).map(|n| denials(&manager, client(n))).collect();
    let mut events = manager.route_events_tx.subscribe();
    manager.distribute_changes(&all, &all);
    for (n, receiver) in receivers.iter_mut().enumerate() {
        assert!(receiver.try_recv().is_err(), "client {n} synchronous delta");
        assert_eq!(denials(&manager, client(n)), before[n]);
    }
    assert!(events.try_recv().is_err());
}

#[test]
fn a_denial_heavy_per_client_best_batch_is_staged_in_bounded_parts() {
    const PREFIXES: u32 = 3_000;
    const DENIED: u32 = 8;
    // Nine work units a prefix: the first stage to reach 2,048 holds 228.
    const STAGE: u32 = 228;
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = gated_source(rx);
    manager.test_force_ungrouped = false;
    let mut receivers: Vec<_> = (0..4)
        .map(|n| rs_client(&mut manager, n, false, 256))
        .collect();
    let mut routes = Vec::new();
    for n in 0..PREFIXES {
        routes.push(candidate(n, SOURCE, 100));
        routes.extend((1..=DENIED).map(|path_id| {
            let mut path = candidate(n, SOURCE, 300);
            path.path_id = path_id;
            path
        }));
    }
    manager.handle_update(update(routes, vec![]));
    drain_route_chunks(&mut manager);
    let denied = |manager: &RibManager| {
        manager
            .export_policy_counters
            .get(&client(0))
            .map_or(0, |counters| {
                counters.snapshot().export_policy_routes_denied
            })
    };
    let before_release = denied(&manager);
    manager.handle_update(source_end_of_rib());
    let mut largest = 0;
    while manager.unicast_release_runnable() {
        let before = denied(&manager);
        manager.advance_unicast_release();
        largest = largest.max(denied(&manager) - before);
    }
    // Each prefix is under a denial page, so none is staged alone. A full
    // batch of 1,024 prefixes carries 8,192 denials, more than one group
    // stage or member page may.
    assert_eq!(largest, u64::from(STAGE * DENIED), "denials in one poll");
    assert_eq!(
        denied(&manager) - before_release,
        u64::from(PREFIXES * DENIED)
    );
    for (n, receiver) in receivers.iter_mut().enumerate() {
        let mut table = ClientTable::default();
        table.receive(receiver);
        assert_eq!((table.rows.len(), table.markers), (PREFIXES as usize, 1));
        assert_eq!(table.largest, STAGE as usize, "client {n}");
        assert_eq!(
            denials(&manager, client(n)).len(),
            (PREFIXES * DENIED) as usize
        );
    }
}

mod per_client_best_release;

/// A staged release delivery owns the actor until its members have consumed
/// it: the overtake lane is closed and reads nothing ahead of the channel.
#[tokio::test(start_paused = true)]
async fn a_staged_release_delivery_keeps_the_overtake_lane_closed() {
    use crate::manager::Overtake;
    use rustbgpd_telemetry::metrics::RibInboundOvertakeSeam;
    let (tx, rx) = mpsc::channel(16);
    let mut manager = gated_source(rx);
    let _outbound = private_receiver(&mut manager, TARGET);
    let _expected = start_release(&mut manager);
    for _ in 0..ROUTES * 4 {
        if manager.release_delivery_pending() {
            break;
        }
        manager.advance_unicast_release();
    }
    assert!(manager.release_delivery_pending());
    let other = Ipv4Addr::new(198, 51, 100, 77);
    let small = Ipv4Addr::new(198, 51, 100, 78);
    let table = (0..600_u32)
        .map(|n| make_route(Ipv4Prefix::new(Ipv4Addr::from(0x0b00_0000 + n), 32), other))
        .collect();
    tx.try_send(super::lifecycle::test_routes_received(
        peer_v4(other),
        table,
    ))
    .unwrap();
    tx.try_send(super::lifecycle::test_routes_received(
        peer_v4(small),
        vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 9), 32),
            small,
        )],
    ))
    .unwrap();
    assert!(matches!(
        manager.take_overtake(RibInboundOvertakeSeam::Drain),
        Overtake::Keep
    ));
    assert_eq!(manager.parked.len(), 0, "a closed lane reads nothing");
}

/// While a restart's selection deferral may still hold a family, a queued
/// `PeerUp` can arm the hold for every prefix of it, so nothing passes
/// queued session work: with the gate dormant, and with it armed.
#[tokio::test(start_paused = true)]
async fn a_selection_deferral_that_may_hold_keeps_the_overtake_lane_closed() {
    use crate::manager::Overtake;
    use rustbgpd_telemetry::metrics::RibInboundOvertakeSeam;
    for armed in [false, true] {
        let (tx, rx) = mpsc::channel(16);
        let mut manager = if armed {
            gated_source(rx)
        } else {
            held_families(rx, &[(peer_v4(SOURCE), FAMILY)])
        };
        let deferral = manager.selection_deferral.as_ref().unwrap();
        assert!(deferral.may_hold());
        assert_eq!(deferral.is_gated(FAMILY), armed);
        let other = Ipv4Addr::new(198, 51, 100, 77);
        let small = Ipv4Addr::new(198, 51, 100, 78);
        let table = (0..600_u32)
            .map(|n| make_route(Ipv4Prefix::new(Ipv4Addr::from(0x0b00_0000 + n), 32), other))
            .collect();
        tx.try_send(super::lifecycle::test_routes_received(
            peer_v4(other),
            table,
        ))
        .unwrap();
        tx.try_send(super::lifecycle::test_routes_received(
            peer_v4(small),
            vec![make_route(
                Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 9), 32),
                small,
            )],
        ))
        .unwrap();
        assert!(
            matches!(
                manager.take_overtake(RibInboundOvertakeSeam::Drain),
                Overtake::Keep
            ),
            "armed={armed}"
        );
        assert_eq!(manager.parked.len(), 0, "armed={armed}: nothing is read");
        // The same queue passes once the deferral is gone.
        manager.selection_deferral = None;
        assert!(
            matches!(
                manager.take_overtake(RibInboundOvertakeSeam::Drain),
                Overtake::Admit(_)
            ),
            "armed={armed}"
        );
    }
}
