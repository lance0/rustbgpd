//! Drive the registration owner one turn at a time to change a live partial replay.
use super::*;
use crate::SelectionDeferralConfig;
use crate::SelectionDeferralWaiterConfig;
use crate::manager::tests::update_groups::community_chain;

const TAG: u32 = 0xfde8_0019;
const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);

const V4_ROWS: u16 = 2300;

fn replay_fixture() -> (RibManager, mpsc::Sender<RibUpdate>, Inventory) {
    let (mut manager, tx, mut expected) = fixture(V4_ROWS);
    manager.initial_member_replays.min_routes = Some(1);
    expected.retain(|key, _| matches!(key, Prefix::V4(_)));
    (manager, tx, expected)
}

fn member(
    manager: &mut RibManager,
    peer: PeerId,
    capacity: usize,
    policy: bool,
    orf_hold: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (out, rx) = mpsc::channel(capacity);
    let mut up = test_peer_up(peer, 7, out);
    let RibUpdate::PeerUp {
        is_ebgp,
        route_reflector_client,
        export_policy,
        negotiated_orf_recv,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *is_ebgp = false;
    *route_reflector_client = true;
    *export_policy = policy.then(|| community_chain(TAG));
    if orf_hold {
        negotiated_orf_recv.push(FAMILY);
    }
    manager.handle_update(up);
    rx
}

fn first_page(
    manager: &mut RibManager,
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
) -> OutboundRouteUpdate {
    for _ in 0..256 {
        if let Ok(page) = rx.try_recv() {
            assert!(page.end_of_rib.is_empty(), "early End-of-RIB");
            assert!(
                !page.announce.is_empty() && page.announce.len() < usize::from(V4_ROWS),
                "expected a partial initial view"
            );
            return page;
        }
        manager.advance_pending_initial_registration();
    }
    panic!("no first page");
}

#[tokio::test(start_paused = true)]
async fn full_replay_writer_resumes_without_a_whole_table_resync_and_a_sibling_finishes() {
    let (mut manager, tx, expected) = replay_fixture();
    let peer = receiver(1);
    let mut slow = member(&mut manager, peer, 1, true, false);
    let first = first_page(&mut manager, &mut slow);
    let mut sibling = member(&mut manager, receiver(2), 64, true, false);
    // Hold the admitted first page's latch. The sibling must finish while this writer is stopped.
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    let actor = tokio::spawn(manager.run_actor());
    assert_initial(&mut sibling, &expected, &[FAMILY]).await;
    let mut actual: Inventory = first
        .announce
        .iter()
        .map(|row| {
            assert_eq!(row.communities(), [TAG]);
            (row.prefix, (row.peer, row.local_pref()))
        })
        .collect();
    assert_eq!(first.announce.len(), actual.len());
    drop(first);
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let page = slow.recv().await.unwrap();
            assert_eq!(page.unicast_withdrawals().count(), 0);
            for row in page.announce.iter() {
                assert_eq!(row.communities(), [TAG]);
                assert!(
                    actual
                        .insert(row.prefix, (row.peer, row.local_pref()))
                        .is_none()
                );
            }
            if !page.end_of_rib.is_empty() {
                assert_eq!(page.end_of_rib, [FAMILY]);
                assert_eq!(actual, expected);
                break;
            }
        }
    })
    .await
    .expect("writer resumed");
    drop(tx);
    let manager = actor.await.unwrap();
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
    assert!(!manager.dirty_peers.contains(&peer));
    assert!(slow.is_empty() && sibling.is_empty());
}

#[tokio::test(start_paused = true)]
async fn replacing_the_sender_with_the_same_session_id_restarts_at_the_first_page() {
    let (mut manager, tx, expected) = replay_fixture();
    let peer = receiver(1);
    let mut old = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut old);
    let old_sender = manager.outbound_peers[&peer].clone();
    let mut current = member(&mut manager, peer, 64, false, false);
    finish(&mut manager);
    assert!(!old_sender.same_channel(&manager.outbound_peers[&peer]));
    assert_eq!(manager.actual_unicast_advertised_count(peer), 0);
    assert!(manager.outbound_operation_live(peer));
    // The predecessor still owns the per-peer operation until transport releases its page.
    drop(first);
    let actor = tokio::spawn(manager.run_actor());
    assert_initial(&mut current, &expected, &[FAMILY]).await;
    assert!(
        old.try_recv().is_err(),
        "a retired sender received a later page"
    );
    drop(tx);
    let manager = actor.await.unwrap();
    assert_eq!(
        manager.neighbor_rib_snapshot(peer).advertised_count,
        expected.len()
    );
    assert!(old.is_empty() && current.is_empty());
}

#[tokio::test(start_paused = true)]
async fn regroup_mid_replay_retires_the_old_policy_pages_and_owes_one_marker() {
    let (mut manager, tx, expected) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 64, false, false);
    let first = first_page(&mut manager, &mut rx);
    for row in first.announce.iter() {
        assert_eq!(row.communities(), &[] as &[u32]);
    }
    drop(first);
    let old = manager.grouped_member_of(peer).unwrap();
    let (reply, result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer,
        export_policy: Some(community_chain(TAG)),
        reply,
    });
    let actor = tokio::spawn(manager.run_actor());
    result.await.unwrap().unwrap();
    let mut seen = BTreeSet::new();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let page = rx.recv().await.unwrap();
            for row in page.announce.iter() {
                assert_eq!(row.communities(), [TAG], "stale policy after regroup");
                assert!(
                    seen.insert(row.prefix),
                    "duplicate current-policy announcement"
                );
            }
            if !page.end_of_rib.is_empty() {
                assert_eq!(page.end_of_rib, [FAMILY]);
                assert_eq!(seen, expected.keys().copied().collect());
                break;
            }
        }
    })
    .await
    .expect("regroup completed");
    drop(tx);
    let manager = actor.await.unwrap();
    assert_ne!(manager.grouped_member_of(peer), Some(old));
    assert!(rx.is_empty());
}

#[tokio::test(start_paused = true)]
async fn route_refresh_at_a_partial_page_waits_for_the_initial_marker() {
    use rustbgpd_wire::RouteRefreshSubtype::{BoRR, EoRR};

    let (mut manager, tx, expected) = replay_fixture();
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 1, false, false);
    let first = first_page(&mut manager, &mut rx);
    let mut initial: BTreeSet<_> = first.announce.iter().map(|row| row.prefix).collect();
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer,
        session_id: 7,
        afi: FAMILY.0,
        safi: FAMILY.1,
        queued: Arc::default(),
    });
    // A marker retry on a full writer must also respect the active replay.
    manager.resync_dirty_peers_bounded();
    drop(first);
    let actor = tokio::spawn(manager.run_actor());
    let keys: BTreeSet<_> = expected.keys().copied().collect();
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut initial_eor = false;
        loop {
            let page = rx.recv().await.unwrap();
            if initial_eor {
                assert_eq!(
                    page.refresh_markers,
                    [(FAMILY.0, FAMILY.1, BoRR), (FAMILY.0, FAMILY.1, EoRR)]
                );
                assert_eq!(page.end_of_rib, [FAMILY]);
                assert_eq!(page.announce.len(), keys.len());
                assert_eq!(
                    page.announce
                        .iter()
                        .map(|row| row.prefix)
                        .collect::<BTreeSet<_>>(),
                    keys
                );
                break;
            }
            assert!(
                page.refresh_markers.is_empty(),
                "refresh overtook initial EoR"
            );
            assert!(page.announce.iter().all(|row| initial.insert(row.prefix)));
            if !page.end_of_rib.is_empty() {
                assert_eq!(page.end_of_rib, [FAMILY]);
                assert_eq!(initial, keys, "marker covers every initial page");
                initial_eor = true;
            }
        }
    })
    .await
    .expect("initial replay and requested refresh");
    drop(tx);
    let _ = actor.await.unwrap();
    assert!(rx.is_empty());
}

#[tokio::test(start_paused = true)]
async fn selection_release_preserves_the_initial_orf_hold_on_a_large_unicast_table() {
    let (manager, tx, expected) = replay_fixture();
    let mut manager = manager.with_selection_deferral(SelectionDeferralConfig {
        timeout: Duration::from_secs(30),
        waiters: vec![SelectionDeferralWaiterConfig {
            peer: receiver(9).into(),
            families: vec![FAMILY],
        }],
    });
    let waiter = receiver(9);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: waiter,
        session_id: 7,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![FAMILY],
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let _waiter_rx = member(&mut manager, waiter, 64, false, false);
    let peer = receiver(1);
    let mut rx = member(&mut manager, peer, 64, false, true);
    assert!(manager.selection_convergence_held(FAMILY));
    assert!(rx.is_empty());
    manager.handle_update(RibUpdate::EndOfRib {
        peer: waiter,
        session_id: 7,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    drain_unicast_release(&mut manager);
    assert!(!manager.selection_convergence_held(FAMILY));
    assert!(manager.peer_orf_pending[&peer].contains(&FAMILY));
    assert!(rx.is_empty(), "ORF keeps both replay and marker held");
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        queued: Arc::default(),
        peer,
        session_id: 7,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    let actor = tokio::spawn(manager.run_actor());
    assert_initial(&mut rx, &expected, &[FAMILY]).await;
    drop(tx);
    let _ = actor.await.unwrap();
    assert!(rx.is_empty());
}

// The transport's action_only_profile_equivalence_matches_final_wire_bytes
// covers the matching eBGP profile. Here the two keys share a staged action
// flip while only one has reached this receiver's actual ledger.
#[tokio::test(start_paused = true)]
async fn action_only_repair_suppresses_only_the_already_admitted_key() {
    use crate::manager::tests::exportability::MockExactExportEncoder;
    use crate::manager::tests::update_groups::deny_statement;
    use rustbgpd_policy::{NextHopAction, Policy, PolicyAction, PolicyChain};

    let (mut manager, tx, expected) = replay_fixture();
    let peer = receiver(1);
    let (out, mut rx) = mpsc::channel(1);
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 7,
        encoder: MockExactExportEncoder::equivalent_next_hop_actions(1),
    });
    let mut up = test_peer_up(peer, 7, out);
    let RibUpdate::PeerUp { export_policy, .. } = &mut up else {
        unreachable!()
    };
    let mut permit = deny_statement(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
    permit.prefix = None;
    permit.action = PolicyAction::Permit;
    permit.modifications.set_local_pref = Some(100);
    let mut high = permit.clone();
    high.match_local_pref_ge = Some(200);
    high.modifications.set_next_hop = Some(NextHopAction::Self_);
    *export_policy = Some(PolicyChain::new(vec![Policy {
        entries: vec![high, permit],
        default_action: PolicyAction::Deny,
    }]));
    manager.handle_update(up);
    let first = first_page(&mut manager, &mut rx);
    let mut seen: BTreeSet<_> = first.announce.iter().map(|row| row.prefix).collect();
    let old = first.announce[0].prefix;
    let new = *expected.keys().find(|key| !seen.contains(*key)).unwrap();
    let gid = manager.grouped_member_of(peer).unwrap();
    let builds = manager.adj_rib_out_commit_stats.resync_builds;
    manager.handle_update(test_routes_received(
        peer_v4(SOURCE),
        [old, new]
            .into_iter()
            .map(|key| route(key, SOURCE, 200))
            .collect(),
    ));
    drain_route_chunks(&mut manager);
    for key in [old, new] {
        assert_eq!(
            manager.group_ribs[&gid].nh_override((key, 0)),
            Some(NextHopAction::Self_)
        );
    }
    drop(first);
    let actor = tokio::spawn(manager.run_actor());
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let page = rx.recv().await.unwrap();
            assert_eq!(page.unicast_withdrawals().count(), 0);
            for (row, action) in page.announce.iter().zip(page.next_hop_override.iter()) {
                assert!(
                    seen.insert(row.prefix),
                    "wire-equivalent action replayed a prior key"
                );
                if row.prefix == new {
                    assert_eq!(action.as_ref(), Some(&NextHopAction::Self_));
                    assert_eq!(row.local_pref(), 100);
                }
            }
            if !page.end_of_rib.is_empty() {
                assert_eq!(page.end_of_rib, [FAMILY]);
                break;
            }
        }
    })
    .await
    .expect("initial end-of-RIB");
    assert_eq!(seen, expected.keys().copied().collect());
    drop(tx);
    let manager = actor.await.unwrap();
    assert_eq!(manager.adj_rib_out_commit_stats.resync_builds, builds);
}
