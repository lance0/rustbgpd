use super::*;
use crate::update::OutboundRouteUpdate;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 81);
const OBSERVER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 82);
const WAITER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 83);

pub(super) fn connect(
    manager: &mut RibManager,
    address: Ipv4Addr,
    capacity: usize,
    waiter: bool,
    private: bool,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(address);
    let export_policy = private.then(|| {
        let mut chain =
            deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))]);
        let entry = &mut chain.policies[0].policy.entries[0];
        entry.prefix = None;
        entry.match_neighbor_set = Some(rustbgpd_policy::NeighborSetMatch {
            addresses: vec![],
            remote_asns: vec![u32::MAX],
            peer_groups: vec![],
        });
        rustbgpd_policy::PolicyChain::from_named(chain.policies)
    });
    let session_id = u64::from(address.octets()[3]);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: if waiter { vec![FAMILY] } else { vec![] },
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (outbound_tx, outbound_rx) = mpsc::channel(capacity);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65000,
        peer_router_id: address,
        outbound_tx,
        export_policy,
        sendable_families: vec![FAMILY],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    outbound_rx
}

fn inject_host(manager: &mut RibManager, host: Ipv4Prefix) {
    let mut route = make_route(host, SOURCE);
    set_peer(&mut route, crate::PeerId::LOCAL);
    route.origin_type = crate::route::RouteOrigin::Local;
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
    ]);
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute { route, reply });
    result.try_recv().unwrap().unwrap();
}

#[expect(
    clippy::too_many_lines,
    reason = "one transcript preserves an actually admitted pre-hold route across a real failed RTBH admission and dirty retry"
)]
fn assert_rtbh_dirty_recovery_preserves_frozen_ordinary(grouped: bool, regroup: bool) {
    let observer = peer_v4(OBSERVER);
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![FAMILY],
            }],
        });
    let _source_rx = connect(&mut manager, SOURCE, 64, false, false);
    let mut observer_rx = connect(&mut manager, OBSERVER, 1, false, !grouped);
    assert_eq!(manager.grouped_member_of(observer).is_some(), grouped);
    let initial = observer_rx.try_recv().unwrap();
    assert_eq!(initial.end_of_rib, vec![FAMILY]);
    assert!(initial.announce.is_empty());
    let ordinary = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: u64::from(SOURCE.octets()[3]),
        announced: vec![make_route_with_lp(ordinary, SOURCE, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    let admitted = observer_rx
        .try_recv()
        .expect("ordinary row is admitted before any waiter reconnects");
    assert_eq!(admitted.announce.len(), 1);
    assert_eq!(admitted.announce[0].prefix, Prefix::V4(ordinary));
    assert_eq!(admitted.end_of_rib, [] as [(Afi, Safi); 0]);
    let mut wire = std::collections::HashMap::from([(
        (Prefix::V4(ordinary), 0),
        admitted.announce[0].clone(),
    )]);
    assert!(!manager.dirty_peers.contains(&observer));

    let _waiter_rx = connect(&mut manager, WAITER, 64, true, false);
    assert!(manager.selection_deferred(FAMILY));
    let first = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
    let second = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    inject_host(&mut manager, first);
    assert_eq!(manager.outbound_peers[&observer].capacity(), 0);
    assert!(!manager.dirty_peers.contains(&observer));
    inject_host(&mut manager, second);
    assert!(
        manager.dirty_peers.contains(&observer),
        "second RTBH admission really failed"
    );
    assert_eq!(
        manager.loc_rib.get(&Prefix::V4(second)).unwrap().peer,
        crate::PeerId::LOCAL
    );
    assert_eq!(
        manager.loc_rib.get(&Prefix::V4(ordinary)).unwrap().peer,
        peer_v4(SOURCE)
    );
    let first_admitted = observer_rx.try_recv().unwrap();
    assert_eq!(first_admitted.end_of_rib, [] as [(Afi, Safi); 0]);
    assert_eq!(first_admitted.announce.len(), 1);
    assert_eq!(first_admitted.announce[0].prefix, Prefix::V4(first));
    wire.insert((Prefix::V4(first), 0), first_admitted.announce[0].clone());

    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    let mut recovered_second = false;
    let mut updates = 0;
    while let Ok(update) = observer_rx.try_recv() {
        updates += 1;
        assert!(
            update.end_of_rib.is_empty(),
            "the observer's initial EoR was sent before the hold"
        );
        assert_eq!(
            update.refresh_markers,
            [] as [(Afi, Safi, rustbgpd_wire::RouteRefreshSubtype); 0]
        );
        for &(prefix, path_id) in &update.withdraw {
            assert_ne!(
                prefix,
                Prefix::V4(ordinary),
                "dirty recovery must preserve the pre-hold ordinary advertisement"
            );
            assert!(
                wire.remove(&(prefix, path_id)).is_some(),
                "no unknown withdrawals"
            );
        }
        for route in update.announce.iter() {
            recovered_second |= route.prefix == Prefix::V4(second);
            wire.insert((route.prefix, route.path_id), route.clone());
        }
    }
    eprintln!(
        "grouped={grouped}: retry updates={updates} dirty={} proof={}",
        manager.dirty_peers.contains(&observer),
        manager.pending_group_admitted.contains_record(observer),
    );
    assert!(
        recovered_second,
        "available capacity must export the missed RTBH before deferral ends"
    );
    assert!(manager.selection_deferred(FAMILY));
    assert!(
        manager.dirty_peers.contains(&observer),
        "held ordinary recovery remains owned until release"
    );
    if grouped {
        assert!(manager.pending_group_admitted.contains_record(observer));
    }
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    let empty_retry = apply_wire(&mut observer_rx, &mut wire);
    assert!(
        empty_retry
            .iter()
            .all(|update| update.announce.is_empty() && update.withdraw.is_empty()),
        "a caught-up partial recovery must park frozen work instead of replaying admitted RTBH"
    );
    assert!(manager.dirty_peers.contains(&observer));
    let (reply, mut count) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryAdvertisedCount {
        peer: observer,
        reply,
    });
    assert_eq!(count.try_recv().unwrap(), 3);
    assert_eq!(wire.len(), 3);
    for prefix in [Prefix::V4(ordinary), Prefix::V4(first), Prefix::V4(second)] {
        assert!(wire.contains_key(&(prefix, 0)));
    }
    if regroup {
        let policy = private_policy(None);
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
            peer: observer,
            export_policy: Some(policy),
            reply,
        });
        response.try_recv().unwrap().unwrap();
        apply_wire(&mut observer_rx, &mut wire);
        assert!(manager.grouped_member_of(observer).is_none());
        assert_eq!(
            manager.adj_ribs_out[&observer].len(),
            2,
            "keys-only handoff cannot invent the frozen body"
        );
        let (reply, mut count) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryAdvertisedCount {
            peer: observer,
            reply,
        });
        assert_eq!(count.try_recv().unwrap(), 3);
        assert_eq!(manager.neighbor_rib_snapshot(observer).advertised_count, 3);
        assert_eq!(manager.outbound_family_usage(observer, Afi::Ipv4, false), 3);
        let violation = super::outbound_prefix_limits::prepare(
            &mut manager,
            1,
            super::outbound_prefix_limits::limit_config(&[(observer, Some(2), None)], &[]),
        )
        .unwrap_err();
        assert_eq!(violation[0].usage, 3);
        super::outbound_prefix_limits::prepare(
            &mut manager,
            2,
            super::outbound_prefix_limits::limit_config(&[(observer, Some(3), None)], &[]),
        )
        .unwrap();
        super::outbound_prefix_limits::apply(&mut manager, 2, true).unwrap();
        let limited = manager
            .outbound_prefix_limit_rows(observer)
            .into_iter()
            .find(|row| row.family == "ipv4_unicast")
            .unwrap();
        assert_eq!((limited.usage, limited.headroom), (3, Some(0)));
        assert!(
            (gauge_metric_value(
                &manager.metrics,
                "bgp_rib_adj_out_prefixes",
                &[
                    ("peer", observer.label().as_str()),
                    ("family", "ipv4_unicast")
                ]
            ) - 3.0)
                .abs()
                < f64::EPSILON
        );
        let (reply, mut stats) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryBmpPeerStats { reply });
        let stats = stats.try_recv().unwrap();
        assert_eq!(
            stats.adj_rib_out_post[&observer]
                .iter()
                .find(|(family, _)| *family == FAMILY)
                .unwrap()
                .1,
            3
        );
        let (reply, mut page) = oneshot::channel();
        manager.handle_update(RibUpdate::QueryRoutesPage {
            scope: crate::update::RouteQueryScope::Advertised { peer: observer },
            filter: None,
            after: None,
            expected_version: None,
            page_size: 16,
            reply,
        });
        assert!(matches!(
            page.try_recv().unwrap(),
            Err(crate::update::RoutePageError::ResyncInProgress)
        ));
        assert_eq!(wire.len(), 3);
    }
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: u64::from(WAITER.octets()[3]),
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    while let Ok(update) = observer_rx.try_recv() {
        assert_eq!(update.end_of_rib, [] as [(Afi, Safi); 0]);
        for key in &update.withdraw {
            assert!(wire.remove(key).is_some());
        }
        for route in update.announce.iter() {
            wire.insert((route.prefix, route.path_id), route.clone());
        }
    }
    assert!(!manager.selection_deferred(FAMILY));
    assert!(!manager.dirty_peers.contains(&observer));
    assert!(!manager.pending_group_admitted.contains_record(observer));
    assert_eq!(wire.len(), 3);
    assert_eq!(manager.ribs.values().map(AdjRibIn::len).sum::<usize>(), 3);
    assert!(
        manager
            .ribs
            .values()
            .flat_map(AdjRibIn::iter)
            .all(|route| !route.is_stale && !route.is_llgr_stale)
    );
}

#[test]
fn grouped_dirty_resync_exports_rtbh_beside_a_frozen_ordinary_advertisement() {
    assert_rtbh_dirty_recovery_preserves_frozen_ordinary(true, false);
}

#[test]
fn private_dirty_resync_exports_rtbh_without_withdrawing_a_frozen_ordinary_advertisement() {
    assert_rtbh_dirty_recovery_preserves_frozen_ordinary(false, false);
}

fn target_with_policy(
    manager: &mut RibManager,
    policy: rustbgpd_policy::PolicyChain,
    mode: usize,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let peer = peer_v4(OBSERVER);
    let session_id = u64::from(OBSERVER.octets()[3]);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![],
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (tx, rx) = mpsc::channel(1);
    let mut up = super::lifecycle::test_peer_up(peer, session_id, tx);
    if let RibUpdate::PeerUp {
        export_policy,
        per_client_best,
        add_path_send_families,
        add_path_send_max,
        sendable_families,
        ..
    } = &mut up
    {
        *export_policy = Some(policy);
        *per_client_best = mode != 2;
        *sendable_families = vec![FAMILY];
        if mode == 2 {
            *add_path_send_families = vec![FAMILY];
            *add_path_send_max = 4;
        }
    }
    manager.handle_update(up);
    rx
}

pub(super) fn manager_with_dormant_waiter() -> RibManager {
    let (_tx, rx) = mpsc::channel(16);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new()).with_selection_deferral(
        SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![FAMILY],
            }],
        },
    )
}

fn inject_aggregate(manager: &mut RibManager, prefix: Ipv4Prefix, path_id: u32, tagged: bool) {
    let mut route = make_route_with_lp(prefix, SOURCE, 50);
    set_peer(&mut route, crate::PeerId::LOCAL);
    route.origin_type = crate::route::RouteOrigin::Local;
    route.path_id = path_id;
    if tagged {
        AttrSet::edit(&mut route.attributes, |attributes| {
            attributes.push(PathAttribute::Communities(vec![
                rustbgpd_wire::COMMUNITY_BLACKHOLE,
            ]));
        });
    }
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute { route, reply });
    result.try_recv().unwrap().unwrap();
}

fn apply_wire(
    rx: &mut mpsc::Receiver<OutboundRouteUpdate>,
    wire: &mut std::collections::HashMap<(Prefix, u32), Route>,
) -> Vec<OutboundRouteUpdate> {
    let updates: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    for update in &updates {
        for key in &update.withdraw {
            assert!(wire.remove(key).is_some(), "no unknown withdrawal");
        }
        for route in update.announce.iter() {
            wire.insert((route.prefix, route.path_id), route.clone());
        }
    }
    updates
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one transcript checks target-specific frozen intent and exact local delete identity in three selection modes"
)]
fn dirty_recovery_preserves_target_ordinary_choice_when_global_rtbh_is_denied() {
    for mode in 0..3 {
        for old_local in [false, true] {
            let mut manager = manager_with_dormant_waiter();
            let _source_rx = connect(&mut manager, SOURCE, 64, false, false);
            let mut policy =
                deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))]);
            let entry = &mut policy.policies[0].policy.entries[0];
            entry.prefix = None;
            entry.match_community = vec![rustbgpd_policy::CommunityMatch::Standard {
                value: rustbgpd_wire::COMMUNITY_BLACKHOLE,
            }];
            if mode == 1 {
                let mut private = entry.clone();
                private.match_community.clear();
                private.match_neighbor_set = Some(rustbgpd_policy::NeighborSetMatch {
                    addresses: vec![],
                    remote_asns: vec![u32::MAX],
                    peer_groups: vec![],
                });
                policy.policies[0].policy.entries.push(private);
            }
            let mut rx = target_with_policy(
                &mut manager,
                rustbgpd_policy::PolicyChain::from_named(policy.policies),
                mode,
            );
            let _initial = rx.try_recv().unwrap();
            assert_eq!(
                manager.grouped_member_of(peer_v4(OBSERVER)).is_some(),
                mode == 0
            );
            let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
            if old_local {
                inject_aggregate(&mut manager, prefix, 42, false);
            } else {
                manager.handle_update(RibUpdate::RoutesReceived {
                    peer: peer_v4(SOURCE),
                    session_id: u64::from(SOURCE.octets()[3]),
                    announced: vec![make_route_with_lp(prefix, SOURCE, 100)],
                    withdrawn: vec![],
                    flowspec_announced: vec![],
                    flowspec_withdrawn: vec![],
                    evpn_announced: vec![],
                    evpn_withdrawn: vec![],
                    validated_with: None,
                });
                drain_route_chunks(&mut manager);
            }
            let mut wire = std::collections::HashMap::new();
            apply_wire(&mut rx, &mut wire);
            assert_eq!(wire.len(), 1);
            let original = wire.values().next().unwrap().clone();
            let _waiter = connect(&mut manager, WAITER, 64, true, false);
            inject_aggregate(&mut manager, prefix, 99, true);
            assert_eq!(
                manager.loc_rib.get(&Prefix::V4(prefix)).unwrap().path_id,
                99
            );
            let suppressed = apply_wire(&mut rx, &mut wire);
            assert!(
                suppressed
                    .iter()
                    .all(|update| update.withdraw.is_empty() && update.announce.is_empty())
            );
            assert_eq!(wire.values().next().unwrap().peer, original.peer);
            let first = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
            let second = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
            inject_host(&mut manager, first);
            inject_host(&mut manager, second);
            assert!(manager.dirty_peers.contains(&peer_v4(OBSERVER)));
            apply_wire(&mut rx, &mut wire);
            manager.distribute_changes(&HashSet::new(), &HashSet::new());
            let recovery = apply_wire(&mut rx, &mut wire);
            assert!(recovery.iter().all(|update| update.end_of_rib.is_empty()));
            assert_eq!(wire.len(), 3, "mode={mode}, old_local={old_local}");
            assert_eq!(
                wire.values()
                    .find(|route| route.prefix == Prefix::V4(prefix))
                    .unwrap()
                    .peer,
                original.peer
            );
            let (reply, mut count) = oneshot::channel();
            manager.handle_update(RibUpdate::QueryAdvertisedCount {
                peer: peer_v4(OBSERVER),
                reply,
            });
            assert_eq!(count.try_recv().unwrap(), 3);
            if old_local {
                let (reply, mut result) = oneshot::channel();
                manager.handle_update(RibUpdate::WithdrawInjected {
                    prefix: Prefix::V4(prefix),
                    path_id: 42,
                    allow_missing: false,
                    owner: String::new(),
                    override_owner: false,
                    reply,
                });
                result.try_recv().unwrap().unwrap();
                let removed = apply_wire(&mut rx, &mut wire);
                assert!(
                    removed
                        .iter()
                        .flat_map(|update| &update.withdraw)
                        .any(|(key, _)| *key == Prefix::V4(prefix))
                );
                assert_eq!(wire.len(), 2);
            }
            manager.handle_update(RibUpdate::EndOfRib {
                peer: peer_v4(WAITER),
                session_id: u64::from(WAITER.octets()[3]),
                afi: FAMILY.0,
                safi: FAMILY.1,
            });
            apply_wire(&mut rx, &mut wire);
            manager.distribute_changes(&HashSet::new(), &HashSet::new());
            apply_wire(&mut rx, &mut wire);
            assert!(!manager.dirty_peers.contains(&peer_v4(OBSERVER)));
            assert!(
                !manager
                    .pending_group_admitted
                    .contains_record(peer_v4(OBSERVER))
            );
            assert_eq!(wire.len(), if old_local { 2 } else { 3 });
            assert!(
                manager
                    .ribs
                    .values()
                    .flat_map(AdjRibIn::iter)
                    .all(|route| !route.is_stale && !route.is_llgr_stale)
            );
        }
    }
}

#[test]
fn policy_stripped_blackhole_removal_withdraws_original_rtbh_intent() {
    for dormant_reclassification in [false, true] {
        let mut manager = manager_with_dormant_waiter();
        let _source_rx = connect(&mut manager, SOURCE, 64, false, false);
        let mut policy =
            deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))]);
        let entry = &mut policy.policies[0].policy.entries[0];
        entry.prefix = None;
        entry.action = rustbgpd_policy::PolicyAction::Permit;
        entry.modifications.communities_remove = vec![rustbgpd_wire::COMMUNITY_BLACKHOLE];
        let mut rx = target_with_policy(
            &mut manager,
            rustbgpd_policy::PolicyChain::from_named(policy.policies),
            0,
        );
        let _initial = rx.try_recv().unwrap();
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let mut wire = std::collections::HashMap::new();
        if dormant_reclassification {
            inject_aggregate(&mut manager, prefix, 17, false);
            apply_wire(&mut rx, &mut wire);
        }
        inject_aggregate(&mut manager, prefix, 17, true);
        apply_wire(&mut rx, &mut wire);
        assert_eq!(wire.len(), 1);
        assert!(wire.values().all(|route| {
            !route
                .communities()
                .contains(&rustbgpd_wire::COMMUNITY_BLACKHOLE)
        }));
        let _waiter = connect(&mut manager, WAITER, 64, true, false);
        inject_aggregate(&mut manager, prefix, 17, false);
        let updates = apply_wire(&mut rx, &mut wire);
        assert_eq!(
            updates
                .iter()
                .map(|update| update.withdraw.len())
                .sum::<usize>(),
            1
        );
        assert!(updates.iter().all(|update| update.end_of_rib.is_empty()));
        assert_eq!(wire.len(), 0);
        assert!(manager.loc_rib.get(&Prefix::V4(prefix)).is_none());
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one encoder-refusal transcript checks frozen OLD, capacity, overlay and release ownership at the final commit seam"
)]
fn final_encoder_refusal_keeps_frozen_ordinary_capacity_and_recovery_owned() {
    let mut manager = manager_with_dormant_waiter();
    let observer = peer_v4(OBSERVER);
    let _source_rx = connect(&mut manager, SOURCE, 64, false, false);
    let encoder = super::exportability::MockExactExportEncoder::accepting(1);
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer: observer,
        session_id: u64::from(OBSERVER.octets()[3]),
        encoder: encoder.clone(),
    });
    let mut policy = deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))]);
    let entry = &mut policy.policies[0].policy.entries[0];
    entry.prefix = None;
    entry.match_neighbor_set = Some(rustbgpd_policy::NeighborSetMatch {
        addresses: vec![],
        remote_asns: vec![u32::MAX],
        peer_groups: vec![],
    });
    let mut rx = target_with_policy(
        &mut manager,
        rustbgpd_policy::PolicyChain::from_named(policy.policies),
        1,
    );
    let _initial = rx.try_recv().unwrap();
    super::outbound_prefix_limits::prepare(
        &mut manager,
        1,
        super::outbound_prefix_limits::limit_config(&[(observer, Some(1), None)], &[]),
    )
    .unwrap();
    super::outbound_prefix_limits::apply(&mut manager, 1, true).unwrap();
    while rx.try_recv().is_ok() {}
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: u64::from(SOURCE.octets()[3]),
        announced: vec![make_route_with_lp(prefix, SOURCE, 100)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    let mut wire = std::collections::HashMap::new();
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), 1);
    let old = wire.values().next().unwrap().clone();
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let key = crate::update::ExactExportKey::Unicast(Prefix::V4(prefix), 0);
    encoder.set_profile(2, [key.clone()]);
    inject_aggregate(&mut manager, prefix, 99, true);
    let refused = apply_wire(&mut rx, &mut wire);
    assert!(refused.iter().all(|update| update.withdraw.is_empty()
        && update.announce.is_empty()
        && update.end_of_rib.is_empty()));
    assert_eq!(wire.len(), 1);
    assert_eq!(wire.values().next().unwrap().peer, old.peer);
    assert!(
        encoder.probed().contains(&key),
        "candidate really reached exact-export refusal"
    );
    assert!(
        manager.selection_resync_held(observer),
        "late backstop retains current-session recovery ownership"
    );
    assert!(manager.dirty_peers.contains(&observer));
    assert!(
        !manager
            .peer_unexportable
            .get(&observer)
            .is_some_and(|overlay| overlay.contains(&key)),
        "a rejected replacement does not erase the old admitted row's truth"
    );
    let state = manager
        .outbound_prefix_limit_rows(observer)
        .into_iter()
        .find(|state| state.family == "ipv4_unicast")
        .unwrap();
    assert_eq!((state.usage, state.headroom), (1, Some(0)));
    let host = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
    inject_host(&mut manager, host);
    apply_wire(&mut rx, &mut wire);
    assert_eq!(
        wire.len(),
        1,
        "a frozen prefix still occupies the one-prefix budget"
    );
    assert!(!wire.keys().any(|(prefix, _)| *prefix == Prefix::V4(host)));
    encoder.set_profile(3, []);
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: u64::from(WAITER.octets()[3]),
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    apply_wire(&mut rx, &mut wire);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    apply_wire(&mut rx, &mut wire);
    assert!(!manager.selection_deferred(FAMILY));
    assert!(!manager.selection_resync_held(observer));
    assert!(!manager.dirty_peers.contains(&observer));
    assert_eq!(wire.len(), 1);
    assert!(
        wire.values()
            .all(|route| !route.is_stale && !route.is_llgr_stale)
    );
}

pub(super) fn private_policy(strip_blackhole: Option<u32>) -> rustbgpd_policy::PolicyChain {
    let mut policy = deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))]);
    let mut private = policy.policies[0].policy.entries[0].clone();
    private.prefix = None;
    private.match_neighbor_set = Some(rustbgpd_policy::NeighborSetMatch {
        addresses: vec![],
        remote_asns: vec![u32::MAX],
        peer_groups: vec![],
    });
    policy.policies[0].policy.entries = vec![private];
    if let Some(blackhole) = strip_blackhole {
        let mut permit = policy.policies[0].policy.entries[0].clone();
        permit.match_neighbor_set = None;
        permit.action = rustbgpd_policy::PolicyAction::Permit;
        permit.modifications.communities_remove = vec![blackhole];
        policy.policies[0].policy.entries.push(permit);
    }
    rustbgpd_policy::PolicyChain::from_named(policy.policies)
}

#[test]
fn dirty_group_to_private_keeps_actual_counts_and_refuses_incomplete_listing() {
    assert_rtbh_dirty_recovery_preserves_frozen_ordinary(true, true);
}

#[test]
fn clean_group_to_private_preserves_original_local_source_provenance() {
    for rtbh in [false, true] {
        let mut manager = manager_with_dormant_waiter();
        let observer = peer_v4(OBSERVER);
        let _source = connect(&mut manager, SOURCE, 64, false, false);
        let blackhole = rustbgpd_wire::COMMUNITY_BLACKHOLE;
        let mut policy =
            deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0))]);
        let entry = &mut policy.policies[0].policy.entries[0];
        entry.prefix = None;
        entry.action = rustbgpd_policy::PolicyAction::Permit;
        entry.modifications.communities_remove = vec![blackhole];
        let mut rx = target_with_policy(
            &mut manager,
            rustbgpd_policy::PolicyChain::from_named(policy.policies),
            0,
        );
        let _initial = rx.try_recv().unwrap();
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let original_id = if rtbh { 0 } else { 17 };
        inject_aggregate(&mut manager, prefix, original_id, rtbh);
        let mut wire = std::collections::HashMap::new();
        apply_wire(&mut rx, &mut wire);
        let _waiter = connect(&mut manager, WAITER, 64, true, false);
        let host = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
        inject_host(&mut manager, host);
        assert!(!manager.dirty_peers.contains(&observer));
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
            peer: observer,
            export_policy: Some(private_policy(Some(blackhole))),
            reply,
        });
        response.try_recv().unwrap().unwrap();
        assert!(manager.grouped_member_of(observer).is_none());
        assert!(manager.dirty_peers.contains(&observer));
        apply_wire(&mut rx, &mut wire);
        if rtbh {
            inject_aggregate(&mut manager, prefix, original_id, false);
        } else {
            manager.distribute_changes(&HashSet::new(), &HashSet::new());
        }
        apply_wire(&mut rx, &mut wire);
        assert_eq!(
            wire.contains_key(&(Prefix::V4(prefix), 0)),
            !rtbh,
            "regroup keeps the old original local path ID and pre-policy eligibility"
        );
        assert!(manager.selection_deferred(FAMILY));
        manager.handle_update(RibUpdate::EndOfRib {
            peer: peer_v4(WAITER),
            session_id: u64::from(WAITER.octets()[3]),
            afi: FAMILY.0,
            safi: FAMILY.1,
        });
        apply_wire(&mut rx, &mut wire);
        manager.distribute_changes(&HashSet::new(), &HashSet::new());
        apply_wire(&mut rx, &mut wire);
        assert!(!manager.dirty_peers.contains(&observer));
        assert_eq!(wire.len(), 2);
    }
}

#[test]
fn ipv6_selection_hold_does_not_keep_ipv4_only_recovery_or_initial_eor_pending() {
    let v6 = (Afi::Ipv6, Safi::Unicast);
    let (_tx, input) = mpsc::channel(16);
    let mut manager = RibManager::new(input, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![v6],
            }],
        });
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let mut rx = connect(&mut manager, OBSERVER, 1, false, false);
    rx.try_recv().unwrap();
    let waiter = peer_v4(WAITER);
    let session_id = u64::from(WAITER.octets()[3]);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: waiter,
        session_id,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![v6],
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (tx, _waiter) = mpsc::channel(64);
    let mut up = super::lifecycle::test_peer_up(waiter, session_id, tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    {
        *sendable_families = vec![v6];
    }
    manager.handle_update(up);
    assert!(manager.selection_deferred(v6));
    assert!(!manager.selection_deferred(FAMILY));
    let first = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
    let second = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    inject_host(&mut manager, first);
    inject_host(&mut manager, second);
    assert!(manager.dirty_peers.contains(&peer_v4(OBSERVER)));
    let mut wire = std::collections::HashMap::new();
    apply_wire(&mut rx, &mut wire);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), 2);
    assert!(!manager.dirty_peers.contains(&peer_v4(OBSERVER)));
    assert!(
        !manager
            .pending_group_admitted
            .contains_record(peer_v4(OBSERVER))
    );
    assert!(manager.selection_deferred(v6));
    let late_addr = Ipv4Addr::new(192, 0, 2, 84);
    let mut late = connect(&mut manager, late_addr, 1, false, false);
    let data = late.try_recv().unwrap();
    assert_eq!(data.announce.len(), 2);
    assert_eq!(data.end_of_rib, [] as [(Afi, Safi); 0]);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    let recovery = late.try_recv().unwrap();
    assert_eq!(recovery.end_of_rib, vec![FAMILY]);
    assert!(!manager.dirty_peers.contains(&peer_v4(late_addr)));
    assert!(manager.selection_deferred(v6));
}

#[test]
fn replacement_channel_drops_old_frozen_source_and_count_state() {
    let mut manager = manager_with_dormant_waiter();
    let observer = peer_v4(OBSERVER);
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let mut old = connect(&mut manager, OBSERVER, 1, false, false);
    old.try_recv().unwrap();
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    inject_aggregate(&mut manager, prefix, 17, false);
    old.try_recv().unwrap();
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let host = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
    inject_host(&mut manager, host);
    old.try_recv().unwrap();
    assert_eq!(manager.actual_unicast_advertised_count(observer), 2);
    manager.handle_update(RibUpdate::PeerDown {
        peer: observer,
        session_id: u64::from(OBSERVER.octets()[3]),
    });
    assert!(!manager.pending_group_admitted.contains_record(observer));
    assert!(!manager.adj_ribs_out.contains_key(&observer));
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: observer,
        session_id: 182,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![],
        peer_enhanced_refresh: false,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (tx, mut fresh) = mpsc::channel(8);
    manager.handle_update(super::lifecycle::test_peer_up(observer, 182, tx));
    let data = fresh.try_recv().unwrap();
    assert_eq!(
        data.announce
            .iter()
            .map(|route| route.prefix)
            .collect::<Vec<_>>(),
        vec![Prefix::V4(host)]
    );
    assert_eq!(data.end_of_rib, [] as [(Afi, Safi); 0]);
    assert_eq!(manager.actual_unicast_advertised_count(observer), 1);
    assert!(
        manager.adj_ribs_out[&observer]
            .local_export_source(&Prefix::V4(prefix), 0)
            .is_none()
    );
    assert_eq!(
        manager.live_sessions[&observer]
            .last()
            .unwrap()
            .selection_partial_pending,
        [false; 4]
    );
    manager.handle_update(RibUpdate::PeerDown {
        peer: observer,
        session_id: u64::from(OBSERVER.octets()[3]),
    });
    assert_eq!(manager.outbound_session_ids[&observer], 182);
    assert_eq!(manager.actual_unicast_advertised_count(observer), 1);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one mixed-family transcript follows actual pre-hold VPN admission through a failed RTBH send, partial recovery and release"
)]
fn held_group_vpn_inventory_does_not_block_unicast_rtbh_recovery() {
    let vpn_family = (Afi::Ipv4, Safi::MplsVpn);
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![FAMILY, vpn_family],
            }],
        });
    let mut source_rx = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (tx, mut rx) = mpsc::channel(1);
    let mut up = super::lifecycle::test_peer_up(observer, 82, tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    {
        *sendable_families = vec![FAMILY, vpn_family];
    }
    manager.handle_update(up);
    rx.try_recv().unwrap();
    let old_vpn = make_vpn_rib_route(SOURCE, 31, 100, 100);
    let key = old_vpn.key();
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![old_vpn.clone()],
        withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);
    let old = rx.try_recv().unwrap();
    assert_eq!(old.vpn_announce.len(), 1);
    assert_eq!(old.vpn_announce[0].key(), key);
    while source_rx.try_recv().is_ok() {}
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: peer_v4(WAITER),
        session_id: 83,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![FAMILY, vpn_family],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (tx, _waiter) = mpsc::channel(64);
    let mut up = super::lifecycle::test_peer_up(peer_v4(WAITER), 83, tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    {
        *sendable_families = vec![FAMILY, vpn_family];
    }
    manager.handle_update(up);
    assert!(manager.selection_deferred(vpn_family));
    assert!(manager.grouped_member_of(observer).is_some());
    let first = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
    let second = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    inject_host(&mut manager, first);
    inject_host(&mut manager, second);
    assert!(manager.dirty_peers.contains(&observer));
    let first_update = rx.try_recv().unwrap();
    assert_eq!(first_update.announce[0].prefix, Prefix::V4(first));
    assert!(first_update.vpn_announce.is_empty() && first_update.vpn_withdraw.is_empty());
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    let updates: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert!(
        updates
            .iter()
            .flat_map(|update| update.announce.iter())
            .any(|route| route.prefix == Prefix::V4(second)),
        "held VPN must not block the missed RTBH"
    );
    assert!(
        updates
            .iter()
            .all(|update| update.vpn_announce.is_empty() && update.vpn_withdraw.is_empty())
    );
    assert_eq!(
        manager.initial_group_admitted_counts(observer).unwrap()[2],
        1
    );
    assert!(manager.dirty_peers.contains(&observer));
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![],
        withdrawn: vec![key.clone()],
    });
    drain_route_chunks(&mut manager);
    let updates: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert!(
        updates
            .iter()
            .all(|update| update.vpn_announce.is_empty() && update.vpn_withdraw.is_empty())
    );
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 83,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    while rx.try_recv().is_ok() {}
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 83,
        afi: vpn_family.0,
        safi: vpn_family.1,
    });
    let updates: Vec<_> = std::iter::from_fn(|| rx.try_recv().ok()).collect();
    assert_eq!(
        updates
            .iter()
            .flat_map(|update| update.vpn_withdraw.iter())
            .filter(|withdraw| **withdraw == key)
            .count(),
        1
    );
    while rx.try_recv().is_ok() {}
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    while rx.try_recv().is_ok() {}
    assert!(!manager.dirty_peers.contains(&observer));
    assert!(!manager.pending_group_admitted.contains_record(observer));
    assert_eq!(manager.actual_unicast_advertised_count(observer), 2);
}

#[test]
fn held_add_path_prefix_keeps_capacity_until_its_last_actual_path_leaves() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (tx, mut rx) = mpsc::channel(1);
    let mut registration = super::lifecycle::test_peer_up(observer, 82, tx);
    if let RibUpdate::PeerUp {
        per_client_best,
        add_path_send_families,
        add_path_send_max,
        ..
    } = &mut registration
    {
        *per_client_best = true;
        *add_path_send_families = vec![FAMILY];
        *add_path_send_max = 2;
    }
    manager.handle_update(registration);
    rx.try_recv().unwrap();
    super::outbound_prefix_limits::prepare(
        &mut manager,
        1,
        super::outbound_prefix_limits::limit_config(&[(observer, Some(1), None)], &[]),
    )
    .unwrap();
    super::outbound_prefix_limits::apply(&mut manager, 1, true).unwrap();
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let mut wire = std::collections::HashMap::new();
    inject_aggregate(&mut manager, prefix, 17, false);
    apply_wire(&mut rx, &mut wire);
    inject_aggregate(&mut manager, prefix, 23, false);
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), 2);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    apply_wire(&mut rx, &mut wire);
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawInjected {
        prefix: Prefix::V4(prefix),
        path_id: 17,
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    result.try_recv().unwrap().unwrap();
    apply_wire(&mut rx, &mut wire);
    assert_eq!(
        wire.len(),
        1,
        "only the removed original source's actual path leaves"
    );
    assert_eq!(manager.actual_unicast_advertised_count(observer), 1);
    let rows = manager.outbound_prefix_limit_rows(observer);
    let usage = rows
        .iter()
        .find(|row| row.family == "ipv4_unicast")
        .unwrap();
    assert_eq!(
        (usage.usage, usage.headroom),
        (1, Some(0)),
        "one actual path still consumes its prefix slot"
    );
    inject_host(
        &mut manager,
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 100), 32),
    );
    apply_wire(&mut rx, &mut wire);
    assert_eq!(
        wire.len(),
        1,
        "another prefix cannot take a still-advertised Add-Path slot"
    );
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 83,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    apply_wire(&mut rx, &mut wire);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    apply_wire(&mut rx, &mut wire);
    assert!(!manager.dirty_peers.contains(&observer));
    assert!(!manager.pending_group_admitted.contains_record(observer));
    assert_eq!(wire.len(), 1);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one dual-stack transcript verifies the released family's omitted data and one terminal while another family remains held"
)]
fn partial_family_release_wakes_omitted_data_before_its_initial_eor() {
    let v6 = (Afi::Ipv6, Safi::Unicast);
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![FAMILY, v6],
            }],
        });
    let (tx, mut source_rx) = mpsc::channel(64);
    let mut up = super::lifecycle::test_peer_up(peer_v4(SOURCE), 81, tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    {
        *sendable_families = vec![FAMILY, v6];
    }
    manager.handle_update(up);
    source_rx.try_recv().unwrap();
    let ordinary = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![make_route(ordinary, SOURCE)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: peer_v4(WAITER),
        session_id: 83,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![FAMILY, v6],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (tx, _waiter_rx) = mpsc::channel(64);
    let mut up = super::lifecycle::test_peer_up(peer_v4(WAITER), 83, tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    {
        *sendable_families = vec![FAMILY, v6];
    }
    manager.handle_update(up);
    let observer = peer_v4(Ipv4Addr::new(192, 0, 2, 84));
    let (tx, mut rx) = mpsc::channel(1);
    let mut up = super::lifecycle::test_peer_up(observer, 84, tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    {
        *sendable_families = vec![FAMILY, v6];
    }
    manager.handle_update(up);
    assert!(rx.try_recv().is_err());
    let mut wire = std::collections::HashMap::new();
    inject_host(
        &mut manager,
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32),
    );
    inject_host(
        &mut manager,
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32),
    );
    apply_wire(&mut rx, &mut wire);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), 2);
    assert!(manager.selection_partial_caught_up(observer));
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 83,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    let mut updates = apply_wire(&mut rx, &mut wire);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    updates.extend(apply_wire(&mut rx, &mut wire));
    assert!(
        wire.contains_key(&(Prefix::V4(ordinary), 0)),
        "releasing IPv4 wakes its omitted data while IPv6 remains held"
    );
    assert_eq!(
        updates
            .iter()
            .flat_map(|update| &update.end_of_rib)
            .filter(|family| **family == FAMILY)
            .count(),
        1
    );
    assert_eq!(
        updates
            .iter()
            .flat_map(|update| &update.end_of_rib)
            .filter(|family| **family == v6)
            .count(),
        0
    );
    assert!(manager.selection_deferred(v6));
    assert!(manager.dirty_peers.contains(&observer));
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 83,
        afi: v6.0,
        safi: v6.1,
    });
    let mut updates = apply_wire(&mut rx, &mut wire);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    updates.extend(apply_wire(&mut rx, &mut wire));
    assert_eq!(
        updates
            .iter()
            .flat_map(|update| &update.end_of_rib)
            .filter(|family| **family == v6)
            .count(),
        1
    );
    assert_eq!(
        updates
            .iter()
            .flat_map(|update| &update.end_of_rib)
            .filter(|family| **family == FAMILY)
            .count(),
        0
    );
    assert!(!manager.dirty_peers.contains(&observer));
    assert!(!manager.pending_group_admitted.contains_record(observer));
    assert_eq!(wire.len(), 3);
}

#[test]
fn refused_partial_admission_proof_keeps_actual_inventory_and_counts_until_release() {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let mut rx = connect(&mut manager, OBSERVER, 1, false, false);
    rx.try_recv().unwrap();
    let ordinary = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![make_route(ordinary, SOURCE)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    let mut wire = std::collections::HashMap::new();
    apply_wire(&mut rx, &mut wire);
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let first = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
    let second = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32);
    inject_host(&mut manager, first);
    inject_host(&mut manager, second);
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), 2);
    manager
        .pending_group_admitted
        .fail_next_allocation_for_test();
    manager.distribute_changes_to_targets(&HashSet::new(), &HashSet::from([observer]));
    assert!(
        manager.pending_group_admitted.get(&observer).is_none(),
        "the actual proof reservation was refused"
    );
    assert!(manager.group_recovery_fallback(observer).is_some());
    apply_wire(&mut rx, &mut wire);
    assert_eq!(
        wire.len(),
        2,
        "unknown held OLD refuses partial admission rather than discarding its proof"
    );
    assert_eq!(manager.actual_unicast_advertised_count(observer), 2);
    assert_eq!(manager.neighbor_rib_snapshot(observer).advertised_count, 2);
    assert_cached_actual_surfaces(&mut manager, observer, 2);
    assert!(manager.dirty_peers.contains(&observer));
    assert!(wire.contains_key(&(Prefix::V4(ordinary), 0)));
    assert!(!wire.contains_key(&(Prefix::V4(second), 0)));
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 83,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    apply_wire(&mut rx, &mut wire);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), 3);
    assert_eq!(manager.actual_unicast_advertised_count(observer), 3);
    assert_cached_actual_surfaces(&mut manager, observer, 3);
    assert!(!manager.dirty_peers.contains(&observer));
    assert!(!manager.pending_group_admitted.contains_record(observer));
}

fn assert_cached_actual_surfaces(manager: &mut RibManager, peer: PeerId, expected: u32) {
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryBmpPeerStats { reply });
    let stats = result.try_recv().unwrap();
    assert_eq!(
        stats.adj_rib_out_post[&peer]
            .iter()
            .find(|(family, _)| *family == FAMILY)
            .unwrap()
            .1,
        u64::from(expected)
    );
    for metric in ["bgp_rib_adj_out_prefixes", "bgp_outbound_prefix_usage"] {
        let actual = gauge_metric_value(
            &manager.metrics,
            metric,
            &[("peer", peer.label().as_str()), ("family", "ipv4_unicast")],
        );
        assert!(
            (actual - f64::from(expected)).abs() < f64::EPSILON,
            "{metric}: {actual} instead of {expected}"
        );
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one VPN-only frozen handoff follows a real writer miss through private ownership, proof refusal and exact release recovery"
)]
fn private_vpn_only_handoff_refuses_unproved_unicast_admission() {
    let vpn = (Afi::Ipv4, Safi::MplsVpn);
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![vpn],
            }],
        });
    let register = |manager: &mut RibManager, address: Ipv4Addr, capacity| {
        let (tx, rx) = mpsc::channel(capacity);
        let mut up =
            super::lifecycle::test_peer_up(peer_v4(address), u64::from(address.octets()[3]), tx);
        if let RibUpdate::PeerUp {
            sendable_families, ..
        } = &mut up
        {
            *sendable_families = vec![FAMILY, vpn];
        }
        manager.handle_update(up);
        rx
    };
    let _source = register(&mut manager, SOURCE, 64);
    let observer = peer_v4(OBSERVER);
    let mut rx = register(&mut manager, OBSERVER, 1);
    rx.try_recv().unwrap();
    let route = make_vpn_rib_route(SOURCE, 31, 100, 100);
    let vpn_key = route.key();
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![route],
        withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);
    assert_eq!(rx.try_recv().unwrap().vpn_announce.len(), 1);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: peer_v4(WAITER),
        session_id: 83,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![vpn],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let _waiter = register(&mut manager, WAITER, 64);
    assert!(manager.selection_deferred(vpn));
    assert!(!manager.selection_deferred(FAMILY));
    // A real empty IPv4 refresh occupies the writer without adding a prefix.
    manager.handle_update(RibUpdate::RouteRefreshRequest {
        peer: observer,
        session_id: 82,
        afi: FAMILY.0,
        safi: FAMILY.1,
        queued: Arc::default(),
    });
    assert_eq!(manager.outbound_peers[&observer].capacity(), 0);
    let host = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
    inject_host(&mut manager, host);
    assert!(manager.dirty_peers.contains(&observer));
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer: observer,
        export_policy: Some(private_policy(None)),
        reply,
    });
    result.try_recv().unwrap().unwrap();
    assert!(manager.grouped_member_of(observer).is_none());
    assert_eq!(manager.adj_ribs_out[&observer].len(), 0);
    assert_eq!(manager.adj_ribs_out[&observer].vpn_len(), 0);
    assert_eq!(
        manager.initial_group_admitted_counts(observer).unwrap()[..4],
        [0, 0, 1, 0]
    );
    let marker = rx.try_recv().unwrap();
    assert_eq!(marker.end_of_rib, vec![FAMILY]);
    manager
        .pending_group_admitted
        .fail_next_allocation_for_test();
    manager.distribute_changes_to_targets(&HashSet::new(), &HashSet::from([observer]));
    assert!(manager.pending_group_admitted.get(&observer).is_none());
    let mut wire = std::collections::HashMap::new();
    apply_wire(&mut rx, &mut wire);
    assert_eq!(
        wire.len(),
        0,
        "a private VPN-only keys handoff must reserve before admitting new unicast"
    );
    assert_eq!(manager.actual_unicast_advertised_count(observer), 0);
    let (reply, mut page) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryVpnRoutesPage {
        scope: crate::update::RouteQueryScope::Advertised { peer: observer },
        filter: None,
        after: None,
        expected_version: None,
        page_size: 16,
        reply,
    });
    assert!(matches!(
        page.try_recv().unwrap(),
        Err(crate::update::RoutePageError::ResyncInProgress)
    ));
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 83,
        afi: vpn.0,
        safi: vpn.1,
    });
    let mut updates = apply_wire(&mut rx, &mut wire);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    updates.extend(apply_wire(&mut rx, &mut wire));
    assert_eq!(wire.len(), 1);
    assert!(updates.iter().all(|update| update.vpn_withdraw.is_empty()));
    assert!(manager.adj_ribs_out[&observer].get_vpn(&vpn_key).is_some());
    assert_eq!(manager.actual_unicast_advertised_count(observer), 1);
    assert!(!manager.dirty_peers.contains(&observer));
    assert!(!manager.pending_group_admitted.contains_record(observer));
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one mixed UC/VPN private handoff verifies actual OLD withdrawals after proof refusal, held source removal and release"
)]
fn refused_private_handoff_withdraws_removed_old_unicast_and_vpn_at_release() {
    let vpn = (Afi::Ipv4, Safi::MplsVpn);
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![FAMILY, vpn],
            }],
        });
    let register = |manager: &mut RibManager, address: Ipv4Addr, capacity| {
        let (tx, rx) = mpsc::channel(capacity);
        let mut up =
            super::lifecycle::test_peer_up(peer_v4(address), u64::from(address.octets()[3]), tx);
        if let RibUpdate::PeerUp {
            sendable_families, ..
        } = &mut up
        {
            *sendable_families = vec![FAMILY, vpn];
        }
        manager.handle_update(up);
        rx
    };
    let _source = register(&mut manager, SOURCE, 64);
    let observer = peer_v4(OBSERVER);
    let mut rx = register(&mut manager, OBSERVER, 1);
    rx.try_recv().unwrap();
    let old = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let mut wire = std::collections::HashMap::new();
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![make_route(old, SOURCE)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    apply_wire(&mut rx, &mut wire);
    let route = make_vpn_rib_route(SOURCE, 31, 100, 100);
    let old_vpn = route.key();
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![route],
        withdrawn: vec![],
    });
    drain_route_chunks(&mut manager);
    assert_eq!(rx.try_recv().unwrap().vpn_announce[0].key(), old_vpn);
    let mut vpn_wire = HashSet::from([old_vpn.clone()]);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: peer_v4(WAITER),
        session_id: 83,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![FAMILY, vpn],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let _waiter = register(&mut manager, WAITER, 64);
    let hosts = [1, 2, 3].map(|n| Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, n), 32));
    for host in hosts {
        inject_host(&mut manager, host);
    }
    assert!(manager.dirty_peers.contains(&observer));
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer: observer,
        export_policy: Some(private_policy(None)),
        reply,
    });
    result.try_recv().unwrap().unwrap();
    assert!(manager.grouped_member_of(observer).is_none());
    assert_eq!(manager.adj_ribs_out[&observer].len(), 0);
    assert_eq!(manager.adj_ribs_out[&observer].vpn_len(), 0);
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), 2);
    manager
        .pending_group_admitted
        .fail_next_allocation_for_test();
    manager.distribute_changes_to_targets(&HashSet::new(), &HashSet::from([observer]));
    assert!(
        manager.pending_group_admitted.get(&observer).is_none(),
        "proof reservation must really refuse"
    );
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), 2);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![],
        withdrawn: vec![(Prefix::V4(old), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![],
        withdrawn: vec![old_vpn.clone()],
    });
    drain_route_chunks(&mut manager);
    let held = apply_wire(&mut rx, &mut wire);
    assert!(held.iter().all(|update| update.vpn_withdraw.is_empty()));
    assert!(wire.contains_key(&(Prefix::V4(old), 0)));
    for family in [FAMILY, vpn] {
        manager.handle_update(RibUpdate::EndOfRib {
            peer: peer_v4(WAITER),
            session_id: 83,
            afi: family.0,
            safi: family.1,
        });
        for update in apply_wire(&mut rx, &mut wire) {
            assert_eq!(update.end_of_rib, [] as [(Afi, Safi); 0]);
            for key in update.vpn_withdraw {
                assert!(vpn_wire.remove(&key), "no unknown VPN withdrawals");
            }
            for route in update.vpn_announce.iter() {
                vpn_wire.insert(route.key());
            }
        }
    }
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    for update in apply_wire(&mut rx, &mut wire) {
        assert_eq!(update.end_of_rib, [] as [(Afi, Safi); 0]);
        for key in update.vpn_withdraw {
            assert!(vpn_wire.remove(&key), "no unknown VPN withdrawals");
        }
        for route in update.vpn_announce.iter() {
            vpn_wire.insert(route.key());
        }
    }
    assert!(
        !wire.contains_key(&(Prefix::V4(old), 0)),
        "removed frozen OLD unicast must not survive proof refusal and release"
    );
    assert_eq!(
        vpn_wire.len(),
        0,
        "removed frozen OLD VPN must not survive proof refusal and release"
    );
    assert_eq!(wire.len(), 3);
    for host in hosts {
        assert!(wire.contains_key(&(Prefix::V4(host), 0)));
    }
    assert_eq!(manager.actual_unicast_advertised_count(observer), 3);
    assert_cached_actual_surfaces(&mut manager, observer, 3);
    assert!(!manager.dirty_peers.contains(&observer));
    assert!(!manager.pending_group_admitted.contains_record(observer));
    assert!(!manager.pending_extra_withdraws.contains_key(&observer));
}

#[derive(Clone, Copy)]
enum RefusedRtbhRemoval {
    Delete,
    Expire,
    Demote,
    PolicyDeny,
}

#[expect(
    clippy::too_many_lines,
    reason = "one dual-stack failure transcript verifies local removal, actual wire, refusal duties, counts and release"
)]
async fn assert_removed_rtbh_after_proof_refusal(
    ipv6: bool,
    removal: RefusedRtbhRemoval,
    writer_full: bool,
) {
    let family = (if ipv6 { Afi::Ipv6 } else { Afi::Ipv4 }, Safi::Unicast);
    let prefix = |last: u16, host: bool| {
        if ipv6 {
            Prefix::V6(Ipv6Prefix::new(
                Ipv6Addr::new(0x2001, 0xdb8, last, 0, 0, 0, 0, 1),
                if host { 128 } else { 64 },
            ))
        } else {
            Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::new(198, 51, u8::try_from(last).unwrap(), 1),
                if host { 32 } else { 24 },
            ))
        }
    };
    let ordinary = prefix(1, false);
    let first = prefix(2, !matches!(removal, RefusedRtbhRemoval::Demote));
    let second = prefix(3, true);
    let route = |prefix| {
        let mut route = match prefix {
            Prefix::V4(prefix) => make_route(prefix, SOURCE),
            Prefix::V6(prefix) => make_v6_route(prefix, "2001:db8::81".parse().unwrap()),
        };
        set_peer(&mut route, peer_v4(SOURCE));
        route
    };
    let local = |prefix, tagged| {
        let mut route = route(prefix);
        set_peer(&mut route, LOCAL_PEER);
        route.origin_type = crate::route::RouteOrigin::Local;
        route.attributes = AttrSet::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath { segments: vec![] }),
            PathAttribute::Communities(if tagged {
                vec![rustbgpd_wire::COMMUNITY_BLACKHOLE]
            } else {
                vec![]
            }),
        ]);
        route
    };
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![family],
            }],
        });
    let connect = |manager: &mut RibManager, address: Ipv4Addr, capacity, waiter| {
        let peer = peer_v4(address);
        let session_id = u64::from(address.octets()[3]);
        manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
            peer,
            session_id,
            peer_restart_state: false,
            peer_gr_helper: true,
            peer_gr_families: if waiter { vec![family] } else { vec![] },
            peer_enhanced_refresh: true,
            peer_llgr_families: vec![],
            local_llgr_stale_time: 0,
        });
        let (tx, rx) = mpsc::channel(capacity);
        let mut up = super::lifecycle::test_peer_up(peer, session_id, tx);
        if let RibUpdate::PeerUp {
            sendable_families,
            is_ebgp,
            ..
        } = &mut up
        {
            *sendable_families = vec![family];
            *is_ebgp = true;
        }
        manager.handle_update(up);
        rx
    };
    let _source = connect(&mut manager, SOURCE, 64, false);
    let observer = peer_v4(OBSERVER);
    let mut rx = connect(&mut manager, OBSERVER, 1, false);
    rx.try_recv().unwrap();
    let limits = if ipv6 {
        (None, Some(3))
    } else {
        (Some(3), None)
    };
    super::outbound_prefix_limits::prepare(
        &mut manager,
        1,
        super::outbound_prefix_limits::limit_config(&[(observer, limits.0, limits.1)], &[]),
    )
    .unwrap();
    super::outbound_prefix_limits::apply(&mut manager, 1, true).unwrap();
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![route(ordinary)],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    let mut wire = std::collections::HashMap::new();
    apply_wire(&mut rx, &mut wire);
    let _waiter = connect(&mut manager, WAITER, 64, true);
    let generation = if matches!(removal, RefusedRtbhRemoval::Expire) {
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectLeasedRoute {
            route: local(first, false),
            owner: "refusal-expiry".to_string(),
            lease_seconds: 5,
            reply,
        });
        Some(result.try_recv().unwrap().unwrap().1)
    } else {
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectRoute {
            route: local(first, matches!(removal, RefusedRtbhRemoval::Demote)),
            reply,
        });
        result.try_recv().unwrap().unwrap();
        None
    };
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute {
        route: local(second, false),
        reply,
    });
    result.try_recv().unwrap().unwrap();
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), 2);
    assert!(wire.contains_key(&(first, 0)));
    assert!(!wire.contains_key(&(second, 0)));
    manager
        .pending_group_admitted
        .fail_next_allocation_for_test();
    manager.distribute_changes_to_targets(&HashSet::new(), &HashSet::from([observer]));
    assert!(manager.pending_group_admitted.get(&observer).is_none());
    assert!(manager.group_recovery_fallback(observer).is_some());
    assert!(apply_wire(&mut rx, &mut wire).is_empty());
    let occupied = writer_full.then(|| {
        manager.outbound_peers[&observer]
            .clone()
            .try_reserve_owned()
            .unwrap()
    });
    match removal {
        RefusedRtbhRemoval::Delete => {
            let (reply, mut result) = oneshot::channel();
            manager.handle_update(RibUpdate::WithdrawInjected {
                prefix: first,
                path_id: 0,
                allow_missing: false,
                owner: String::new(),
                override_owner: false,
                reply,
            });
            assert!(result.try_recv().unwrap().unwrap().removed);
        }
        RefusedRtbhRemoval::Expire => {
            tokio::time::advance(Duration::from_secs(6)).await;
            let (leases, _) = manager.injection_leases().take_expired();
            assert_eq!(leases.len(), 1);
            assert_eq!(Some(leases[0].generation), generation);
            manager.handle_update(RibUpdate::ExpireInjectionLeases { leases });
        }
        RefusedRtbhRemoval::Demote => {
            let (reply, mut result) = oneshot::channel();
            manager.handle_update(RibUpdate::InjectRoute {
                route: local(first, false),
                reply,
            });
            assert_eq!(
                result.try_recv().unwrap().unwrap(),
                crate::update::InjectOutcome::Replaced
            );
        }
        RefusedRtbhRemoval::PolicyDeny => {
            let (reply, mut result) = oneshot::channel();
            manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
                peer: observer,
                export_policy: Some(deny_prefixes_chain(&[first])),
                reply,
            });
            result.try_recv().unwrap().unwrap();
        }
    }
    if let Some(occupied) = occupied {
        assert_eq!(manager.actual_unicast_advertised_count(observer), 2);
        assert!(
            manager.adj_ribs_out[&observer]
                .local_export_source(&first, 0)
                .is_some()
        );
        assert!(apply_wire(&mut rx, &mut wire).is_empty());
        drop(occupied);
        manager.distribute_changes(&HashSet::new(), &HashSet::new());
    }
    let updates = apply_wire(&mut rx, &mut wire);
    assert!(manager.selection_deferred(family));
    assert!(
        updates
            .iter()
            .all(|update| update.announce.is_empty() && update.end_of_rib.is_empty())
    );
    assert_eq!(
        updates
            .iter()
            .flat_map(|update| &update.withdraw)
            .copied()
            .collect::<Vec<_>>(),
        [(first, 0)]
    );
    assert!(
        wire.contains_key(&(ordinary, 0)),
        "received OLD remains frozen"
    );
    assert!(
        !wire.contains_key(&(first, 0)),
        "removed RTBH must withdraw despite proof refusal"
    );
    assert!(
        !wire.contains_key(&(second, 0)),
        "missing proof permits no new admission"
    );
    assert_eq!(manager.actual_unicast_advertised_count(observer), 1);
    assert_eq!(manager.neighbor_rib_snapshot(observer).advertised_count, 1);
    let rows = manager.outbound_prefix_limit_rows(observer);
    let row = rows
        .iter()
        .find(|row| row.family == if ipv6 { "ipv6_unicast" } else { "ipv4_unicast" })
        .unwrap();
    assert_eq!((row.usage, row.headroom), (1, Some(2)));
    assert!(manager.dirty_peers.contains(&observer));
    assert!(manager.group_recovery_fallback(observer).is_some());
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    assert!(
        apply_wire(&mut rx, &mut wire).is_empty(),
        "held retry must not debit or withdraw twice"
    );
    assert_eq!(manager.actual_unicast_advertised_count(observer), 1);
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 83,
        afi: family.0,
        safi: family.1,
    });
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    while let Ok(update) = rx.try_recv() {
        assert_eq!(update.end_of_rib, []);
        for key in update.withdraw {
            assert!(
                wire.remove(&key).is_some() || key == (first, 0),
                "only known obsolete RTBH may receive a conservative repeated withdrawal"
            );
        }
        for route in update.announce.iter() {
            wire.insert((route.prefix, route.path_id), route.clone());
        }
    }
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    apply_wire(&mut rx, &mut wire);
    let expected = if matches!(removal, RefusedRtbhRemoval::Demote) {
        3
    } else {
        2
    };
    assert_eq!(wire.len(), expected);
    assert!(wire.contains_key(&(ordinary, 0)) && wire.contains_key(&(second, 0)));
    assert_eq!(manager.actual_unicast_advertised_count(observer), expected);
    assert!(!manager.dirty_peers.contains(&observer));
    assert!(!manager.pending_group_admitted.contains_record(observer));
}

#[tokio::test(start_paused = true)]
async fn refused_proof_still_withdraws_deleted_ipv4_rtbh() {
    assert_removed_rtbh_after_proof_refusal(false, RefusedRtbhRemoval::Delete, false).await;
}

#[tokio::test(start_paused = true)]
async fn refused_proof_still_withdraws_deleted_ipv6_rtbh() {
    assert_removed_rtbh_after_proof_refusal(true, RefusedRtbhRemoval::Delete, false).await;
}

#[tokio::test(start_paused = true)]
async fn refused_proof_still_withdraws_expired_ipv4_rtbh() {
    assert_removed_rtbh_after_proof_refusal(false, RefusedRtbhRemoval::Expire, false).await;
}

#[tokio::test(start_paused = true)]
async fn refused_proof_still_withdraws_expired_ipv6_rtbh() {
    assert_removed_rtbh_after_proof_refusal(true, RefusedRtbhRemoval::Expire, false).await;
}

#[tokio::test(start_paused = true)]
async fn refused_proof_still_withdraws_demoted_ipv4_rtbh() {
    assert_removed_rtbh_after_proof_refusal(false, RefusedRtbhRemoval::Demote, false).await;
}

#[tokio::test(start_paused = true)]
async fn refused_proof_still_withdraws_demoted_ipv6_rtbh() {
    assert_removed_rtbh_after_proof_refusal(true, RefusedRtbhRemoval::Demote, false).await;
}

#[tokio::test(start_paused = true)]
async fn refused_proof_still_withdraws_policy_denied_ipv4_rtbh() {
    assert_removed_rtbh_after_proof_refusal(false, RefusedRtbhRemoval::PolicyDeny, false).await;
}

#[tokio::test(start_paused = true)]
async fn refused_proof_still_withdraws_policy_denied_ipv6_rtbh() {
    assert_removed_rtbh_after_proof_refusal(true, RefusedRtbhRemoval::PolicyDeny, false).await;
}

#[tokio::test(start_paused = true)]
async fn refused_proof_still_withdraws_only_after_writer_admission() {
    assert_removed_rtbh_after_proof_refusal(false, RefusedRtbhRemoval::Delete, true).await;
}

fn assert_late_waiter_advertised_truth(
    manager: &mut RibManager,
    observer: crate::PeerId,
    expected: usize,
    stage: &str,
) {
    let (reply, mut count) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryAdvertisedCount {
        peer: observer,
        reply,
    });
    let count = count.try_recv().unwrap();
    let (reply, mut neighbors) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryNeighborRibSnapshots {
        peers: vec![observer],
        comparison: None,
        include_retained: false,
        reply,
    });
    let neighbors = neighbors.try_recv().unwrap();
    let neighbor_count = neighbors.snapshots[0].advertised_count;
    let (reply, mut bmp) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryBmpPeerStats { reply });
    let bmp = bmp.try_recv().unwrap();
    let bmp_count: u64 = bmp.adj_rib_out_post[&observer]
        .iter()
        .filter(|(family, _)| family.1 == Safi::Unicast)
        .map(|(_, count)| count)
        .sum();
    let (reply, mut listing) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryRoutesPage {
        scope: crate::update::RouteQueryScope::Advertised { peer: observer },
        filter: None,
        after: None,
        expected_version: None,
        page_size: 16,
        reply,
    });
    let listing = listing.try_recv().unwrap();
    eprintln!(
        "{stage}: wire={expected} advertised={count} neighbor={neighbor_count} bmp={bmp_count} listing={listing:?}"
    );
    assert_eq!(
        (count, neighbor_count, bmp_count),
        (expected, expected, u64::try_from(expected).unwrap()),
        "{stage}: public advertised counts must describe actual writer admission"
    );
    match listing {
        Ok(page) => {
            assert_eq!(
                page.total,
                u64::try_from(expected).unwrap(),
                "{stage}: successful listing total"
            );
            assert_eq!(
                page.routes.len(),
                expected,
                "{stage}: successful listing bodies"
            );
        }
        Err(crate::update::RoutePageError::ResyncInProgress) => {}
        Err(error) => panic!("{stage}: unexpected advertised listing error: {error:?}"),
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one production-driven late-waiter transcript checks wire admission and public counts through the hold"
)]
fn assert_late_waiter_private_counts(ipv6: bool, refuse_capture: bool, fresh_channel: bool) {
    let family = (if ipv6 { Afi::Ipv6 } else { Afi::Ipv4 }, Safi::Unicast);
    let mut manager =
        manager_with_dormant_waiter().with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![family],
            }],
        });
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (tx, mut rx) = mpsc::channel(64);
    let registration = |outbound_tx| {
        let mut up = super::lifecycle::test_peer_up(observer, 82, outbound_tx);
        if let RibUpdate::PeerUp {
            sendable_families,
            per_client_best,
            add_path_send_families,
            add_path_send_max,
            ..
        } = &mut up
        {
            *sendable_families = vec![family];
            *per_client_best = true;
            *add_path_send_families = vec![family];
            *add_path_send_max = 2;
        }
        up
    };
    manager.handle_update(registration(tx.clone()));
    let initial = rx.try_recv().unwrap();
    assert_eq!(initial.end_of_rib, [family]);
    let host = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
    let ordinary = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let mut wire = std::collections::HashMap::new();
    let route_in_family = |mut route: Route| {
        if ipv6 {
            route.prefix = Prefix::V6(if route.prefix == Prefix::V4(host) {
                Ipv6Prefix::new("2001:db8:1::1".parse().unwrap(), 128)
            } else {
                Ipv6Prefix::new("2001:db8:2::".parse().unwrap(), 64)
            });
            route.next_hop = "2001:db8::81".parse().unwrap();
        }
        route
    };
    let mut local = route_in_family(make_route_with_lp(host, SOURCE, 50));
    set_peer(&mut local, LOCAL_PEER);
    local.origin_type = crate::route::RouteOrigin::Local;
    local.path_id = 17;
    let local_prefix = local.prefix;
    let (reply, mut injected) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute {
        route: local,
        reply,
    });
    injected.try_recv().unwrap().unwrap();
    apply_wire(&mut rx, &mut wire);
    let mut sibling = route_in_family(make_route_with_lp(host, SOURCE, 10));
    sibling.path_id = 11;
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![sibling, route_in_family(make_route(ordinary, SOURCE))],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), 3);
    assert_late_waiter_advertised_truth(&mut manager, observer, wire.len(), "before hold");
    let before = wire.clone();
    if refuse_capture {
        assert!(
            ipv6,
            "the source has no IPv6 export and consumes no capture allocation"
        );
        manager
            .pending_group_admitted
            .fail_next_allocation_for_test();
    }
    let waiter = peer_v4(WAITER);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: waiter,
        session_id: 83,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![family],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (waiter_tx, _waiter_rx) = mpsc::channel(64);
    let mut waiter_up = super::lifecycle::test_peer_up(waiter, 83, waiter_tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut waiter_up
    {
        *sendable_families = vec![family];
    }
    manager.handle_update(waiter_up);
    if refuse_capture {
        assert!(manager.pending_group_admitted.get(&observer).is_none());
        assert!(manager.group_recovery_fallback(observer).is_some());
    }
    assert!(manager.selection_deferred(family));
    assert_eq!(manager.outbound_session_ids[&observer], 82);
    assert!(manager.outbound_peers[&observer].same_channel(&tx));
    let updates = apply_wire(&mut rx, &mut wire);
    assert!(updates.iter().all(|update| update.end_of_rib.is_empty()));
    assert_eq!(wire.keys().collect::<HashSet<_>>(), before.keys().collect());
    assert_late_waiter_advertised_truth(&mut manager, observer, wire.len(), "after hold arms");
    if fresh_channel {
        let (fresh_tx, mut fresh_rx) = mpsc::channel(64);
        manager.handle_update(registration(fresh_tx));
        let mut fresh_wire = std::collections::HashMap::new();
        let updates = apply_wire(&mut fresh_rx, &mut fresh_wire);
        assert!(
            updates
                .iter()
                .all(|update| update.withdraw.is_empty() && update.end_of_rib.is_empty())
        );
        assert_eq!(fresh_wire.len(), 1);
        assert_late_waiter_advertised_truth(&mut manager, observer, 1, "fresh channel while held");
        assert!(rx.try_recv().is_err());
        manager.handle_update(RibUpdate::EndOfRib {
            peer: peer_v4(WAITER),
            session_id: 83,
            afi: family.0,
            safi: family.1,
        });
        let updates = apply_wire(&mut fresh_rx, &mut fresh_wire);
        assert_eq!(
            updates
                .iter()
                .flat_map(|update| &update.end_of_rib)
                .filter(|marker| **marker == family)
                .count(),
            1
        );
        assert_eq!(fresh_wire.len(), 3);
        assert_late_waiter_advertised_truth(
            &mut manager,
            observer,
            3,
            "fresh channel after release",
        );
        assert!(!manager.pending_group_admitted.contains_record(observer));
        return;
    }
    if refuse_capture {
        let mut ban = route_in_family(make_route_with_lp(host, SOURCE, 50));
        ban.prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:3::1".parse().unwrap(), 128));
        ban.path_id = 29;
        set_peer(&mut ban, LOCAL_PEER);
        ban.origin_type = crate::route::RouteOrigin::Local;
        let ban_prefix = ban.prefix;
        let (reply, mut injected) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectRoute { route: ban, reply });
        injected.try_recv().unwrap().unwrap();
        let updates = apply_wire(&mut rx, &mut wire);
        assert!(
            updates
                .iter()
                .all(|update| update.withdraw.is_empty() && update.end_of_rib.is_empty())
        );
        assert_eq!(
            wire.len(),
            4,
            "complete actual bodies permit RTBH without a key ledger"
        );
        assert_late_waiter_advertised_truth(
            &mut manager,
            observer,
            4,
            "retained body after RTBH add",
        );
        let (reply, mut removed) = oneshot::channel();
        manager.handle_update(RibUpdate::WithdrawInjected {
            prefix: ban_prefix,
            path_id: 29,
            allow_missing: false,
            owner: String::new(),
            override_owner: false,
            reply,
        });
        removed.try_recv().unwrap().unwrap();
        let updates = apply_wire(&mut rx, &mut wire);
        assert!(
            updates
                .iter()
                .all(|update| update.announce.is_empty() && update.end_of_rib.is_empty())
        );
        assert_eq!(wire.len(), 3);
        assert_late_waiter_advertised_truth(
            &mut manager,
            observer,
            3,
            "retained body after RTBH delete",
        );
    }
    if !refuse_capture {
        let (reply, mut removed) = oneshot::channel();
        manager.handle_update(RibUpdate::WithdrawInjected {
            prefix: local_prefix,
            path_id: 17,
            allow_missing: false,
            owner: String::new(),
            override_owner: false,
            reply,
        });
        removed.try_recv().unwrap().unwrap();
        let updates = apply_wire(&mut rx, &mut wire);
        assert!(
            updates
                .iter()
                .all(|update| update.announce.is_empty() && update.end_of_rib.is_empty())
        );
        assert_eq!(wire.len(), 2);
        assert_late_waiter_advertised_truth(
            &mut manager,
            observer,
            wire.len(),
            "after RTBH delete",
        );
    }
    let removed_prefix = route_in_family(make_route(ordinary, SOURCE)).prefix;
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![],
        withdrawn: vec![(removed_prefix, 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    let updates = apply_wire(&mut rx, &mut wire);
    assert!(updates.iter().all(|update| update.announce.is_empty()
        && update.withdraw.is_empty()
        && update.end_of_rib.is_empty()));
    assert_late_waiter_advertised_truth(
        &mut manager,
        observer,
        wire.len(),
        "after frozen source withdrawal",
    );
    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 83,
        afi: family.0,
        safi: family.1,
    });
    apply_wire(&mut rx, &mut wire);
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), if refuse_capture { 2 } else { 1 });
    assert!(!wire.keys().any(|key| key.0 == removed_prefix));
    assert_late_waiter_advertised_truth(&mut manager, observer, wire.len(), "after release");
    assert!(!manager.dirty_peers.contains(&observer));
    assert!(!manager.pending_group_admitted.contains_record(observer));
    assert!(!manager.pending_extra_withdraws.contains_key(&observer));
}

#[test]
fn late_waiter_private_keeps_actual_advertised_counts() {
    assert_late_waiter_private_counts(false, false, false);
}

#[test]
fn late_waiter_private_ipv6_keeps_actual_advertised_counts() {
    assert_late_waiter_private_counts(true, false, false);
}

#[test]
fn late_waiter_private_refused_capture_keeps_actual_advertised_counts() {
    assert_late_waiter_private_counts(true, true, false);
}

#[test]
fn late_waiter_private_fresh_channel_does_not_inherit_actual_admission() {
    assert_late_waiter_private_counts(true, true, true);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[expect(
    clippy::too_many_lines,
    reason = "the real private capture is paused at two checkpoints to prove readiness service and fence queued queries and mutations"
)]
async fn late_waiter_private_capture_services_readiness_before_completion() {
    let family = (Afi::Ipv6, Safi::Unicast);
    let (tx, rx) = mpsc::channel(8);
    let (query_tx, query_rx) = mpsc::channel(8);
    let (readiness_tx, readiness_rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new())
        .with_readiness_queries(readiness_rx)
        .with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![family],
            }],
        });
    let _source_rx = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (outbound_tx, mut outbound_rx) = mpsc::channel(1024);
    let mut up = super::lifecycle::test_peer_up(observer, 82, outbound_tx);
    if let RibUpdate::PeerUp {
        sendable_families,
        per_client_best,
        ..
    } = &mut up
    {
        *sendable_families = vec![family];
        *per_client_best = true;
    }
    manager.handle_update(up);
    outbound_rx.try_recv().unwrap();
    let received = (0_u128..128)
        .map(|index| {
            let mut route = make_route(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24), SOURCE);
            route.prefix = Prefix::V6(Ipv6Prefix::new(
                Ipv6Addr::from(0x2001_0db8_0000_0000_0000_0000_0000_0000 + index),
                128,
            ));
            route.next_hop = "2001:db8::81".parse().unwrap();
            route
        })
        .collect();
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: received,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    let mut wire = std::collections::HashMap::new();
    apply_wire(&mut outbound_rx, &mut wire);
    assert_eq!(wire.len(), 128);
    let waiter = peer_v4(WAITER);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: waiter,
        session_id: 83,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![family],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (waiter_tx, _waiter_rx) = mpsc::channel(1024);
    let mut waiter_up = super::lifecycle::test_peer_up(waiter, 83, waiter_tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut waiter_up
    {
        *sendable_families = vec![family];
    }
    let (entered_tx, mut entered_rx) = mpsc::unbounded_channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let release_rx = std::sync::Mutex::new(release_rx);
    let calls = std::sync::atomic::AtomicUsize::new(0);
    manager.replacement_readiness_test_hook = Some(Arc::new(move |stage| {
        if stage == "common_capture" {
            let call = calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if call < 2 {
                entered_tx.send(call).unwrap();
                release_rx
                    .lock()
                    .unwrap()
                    .recv_timeout(Duration::from_secs(10))
                    .unwrap();
            }
        }
    }));
    let capture = tokio::spawn(async move {
        let update = manager.rx.recv().await.unwrap();
        manager.handle_update(update);
        manager
    });
    tx.send(waiter_up).await.unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), entered_rx.recv())
            .await
            .unwrap(),
        Some(0)
    );
    let (reply, mut readiness) = oneshot::channel();
    readiness_tx
        .try_send(crate::update::RibReadinessQuery::LocRibCount {
            reply,
            enqueued: std::time::Instant::now(),
        })
        .unwrap();
    let (reply, mut general) = oneshot::channel();
    query_tx
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();
    tx.try_send(RibUpdate::PeerDown {
        peer: peer_v4(SOURCE),
        session_id: 81,
    })
    .unwrap();
    release_tx.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), entered_rx.recv())
            .await
            .unwrap(),
        Some(1)
    );
    let interior_reply = readiness.try_recv();
    let general_held = matches!(general.try_recv(), Err(oneshot::error::TryRecvError::Empty));
    let mutation_held = tx.capacity() == 7;
    release_tx.send(()).unwrap();
    let mut manager = capture.await.unwrap();
    manager.replacement_readiness_test_hook = None;
    assert_eq!(interior_reply, Ok(Ok(128)));
    assert!(general_held && mutation_held);
    assert_eq!(
        manager.pending_group_admitted.get(&observer).unwrap().len(),
        128
    );
    assert_eq!(wire.len(), 128);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one actual limited Add-Path transcript checks retained complete bodies, sibling capacity and the queued headroom recovery"
)]
fn late_waiter_private_refused_capture_keeps_known_capacity_and_recovers_intent() {
    let family = (Afi::Ipv6, Safi::Unicast);
    let mut manager =
        manager_with_dormant_waiter().with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: peer_v4(WAITER),
                families: vec![family],
            }],
        });
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (tx, mut rx) = mpsc::channel(64);
    let registration = |outbound_tx| {
        let mut up = super::lifecycle::test_peer_up(observer, 82, outbound_tx);
        if let RibUpdate::PeerUp {
            sendable_families,
            per_client_best,
            add_path_send_families,
            add_path_send_max,
            ..
        } = &mut up
        {
            *sendable_families = vec![family];
            *per_client_best = true;
            *add_path_send_families = vec![family];
            *add_path_send_max = 2;
        }
        up
    };
    manager.handle_update(registration(tx.clone()));
    assert_eq!(rx.try_recv().unwrap().end_of_rib, [family]);
    super::outbound_prefix_limits::prepare(
        &mut manager,
        1,
        super::outbound_prefix_limits::limit_config(&[(observer, None, Some(2))], &[]),
    )
    .unwrap();
    super::outbound_prefix_limits::apply(&mut manager, 1, true).unwrap();
    let host = Ipv6Prefix::new("2001:db8:1::1".parse().unwrap(), 128);
    let ordinary = Ipv6Prefix::new("2001:db8:2::".parse().unwrap(), 64);
    let blocked = Ipv6Prefix::new("2001:db8:3::1".parse().unwrap(), 128);
    let local_route = |prefix, path_id| {
        let mut route = make_route_with_lp(
            Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32),
            SOURCE,
            50,
        );
        route.prefix = Prefix::V6(prefix);
        route.next_hop = "2001:db8::81".parse().unwrap();
        route.path_id = path_id;
        set_peer(&mut route, LOCAL_PEER);
        route.origin_type = crate::route::RouteOrigin::Local;
        route
    };
    let inject = |manager: &mut RibManager, route| {
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectRoute { route, reply });
        result.try_recv().unwrap().unwrap();
    };
    let capacity = |manager: &RibManager| {
        let row = manager
            .outbound_prefix_limit_rows(observer)
            .into_iter()
            .find(|row| row.family == "ipv6_unicast")
            .unwrap();
        assert_ne!(
            row.usage,
            u64::MAX,
            "complete private bodies retain known prefix usage"
        );
        (row.usage, row.headroom)
    };
    inject(&mut manager, local_route(host, 17));
    let mut wire = std::collections::HashMap::new();
    apply_wire(&mut rx, &mut wire);
    let mut sibling = make_route_with_lp(
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32),
        SOURCE,
        10,
    );
    sibling.prefix = Prefix::V6(host);
    sibling.next_hop = "2001:db8::81".parse().unwrap();
    sibling.path_id = 11;
    let mut received = sibling.clone();
    received.prefix = Prefix::V6(ordinary);
    received.path_id = 0;
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![sibling, received],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    apply_wire(&mut rx, &mut wire);
    assert_eq!(wire.len(), 3);
    assert_eq!(capacity(&manager), (2, Some(0)));
    manager
        .pending_group_admitted
        .fail_next_allocation_for_test();
    let waiter = peer_v4(WAITER);
    manager.handle_update(RibUpdate::SetPeerGracefulRestartContext {
        peer: waiter,
        session_id: 83,
        peer_restart_state: false,
        peer_gr_helper: true,
        peer_gr_families: vec![family],
        peer_enhanced_refresh: true,
        peer_llgr_families: vec![],
        local_llgr_stale_time: 0,
    });
    let (waiter_tx, _waiter_rx) = mpsc::channel(64);
    let mut up = super::lifecycle::test_peer_up(waiter, 83, waiter_tx);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut up
    {
        *sendable_families = vec![family];
    }
    manager.handle_update(up);
    assert!(manager.pending_group_admitted.get(&observer).is_none());
    assert!(manager.group_recovery_fallback(observer).is_some());
    let updates = apply_wire(&mut rx, &mut wire);
    assert!(updates.iter().all(|update| update.end_of_rib.is_empty()));
    assert_eq!(wire.len(), 3);
    inject(&mut manager, local_route(blocked, 29));
    let updates = apply_wire(&mut rx, &mut wire);
    assert!(updates.iter().all(|update| update.announce.is_empty()
        && update.withdraw.is_empty()
        && update.end_of_rib.is_empty()));
    assert_eq!(wire.len(), 3);
    assert_eq!(capacity(&manager), (2, Some(0)));
    let (reply, mut removed) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawInjected {
        prefix: Prefix::V6(host),
        path_id: 17,
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    removed.try_recv().unwrap().unwrap();
    let updates = apply_wire(&mut rx, &mut wire);
    assert!(
        updates
            .iter()
            .all(|update| update.announce.is_empty() && update.end_of_rib.is_empty())
    );
    assert_eq!(wire.len(), 2);
    assert_eq!(
        capacity(&manager),
        (2, Some(0)),
        "received sibling still owns the host prefix slot"
    );
    assert_late_waiter_advertised_truth(
        &mut manager,
        observer,
        2,
        "limited body after local sibling deletion",
    );
    manager.handle_update(RibUpdate::EndOfRib {
        peer: waiter,
        session_id: 83,
        afi: family.0,
        safi: family.1,
    });
    let mut terminals = apply_wire(&mut rx, &mut wire)
        .iter()
        .flat_map(|update| &update.end_of_rib)
        .filter(|marker| **marker == family)
        .count();
    manager.distribute_changes(&HashSet::new(), &HashSet::new());
    terminals += apply_wire(&mut rx, &mut wire)
        .iter()
        .flat_map(|update| &update.end_of_rib)
        .filter(|marker| **marker == family)
        .count();
    // Its initial End-of-RIB went out at registration, before the hold.
    assert_eq!(terminals, 0);
    assert_eq!(wire.len(), 2);
    assert!(wire.keys().any(|key| key.0 == Prefix::V6(ordinary)));
    // Rank migration withdraws H's last OLD path. ADR-0113 allows H and B
    // to compete in batch order for that freed slot, without a preference.
    assert_ne!(
        wire.keys().any(|key| key.0 == Prefix::V6(host)),
        wire.keys().any(|key| key.0 == Prefix::V6(blocked)),
        "exactly one competing prefix fills the remaining slot"
    );
    assert_eq!(capacity(&manager), (2, Some(0)));
    assert_late_waiter_advertised_truth(
        &mut manager,
        observer,
        2,
        "limited body after selection release",
    );
    assert!(!manager.pending_group_admitted.contains_record(observer));
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![],
        withdrawn: vec![(Prefix::V6(ordinary), 0)],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    let updates = apply_wire(&mut rx, &mut wire);
    assert!(
        updates
            .iter()
            .all(|update| update.announce.is_empty() && update.end_of_rib.is_empty())
    );
    assert_eq!(wire.len(), 1);
    assert_eq!(capacity(&manager), (1, Some(1)));
    assert!(
        manager.drain_outbound_limit_recovery(),
        "last-prefix withdrawal queues existing capacity recovery"
    );
    let updates = apply_wire(&mut rx, &mut wire);
    assert!(
        updates
            .iter()
            .all(|update| update.withdraw.is_empty() && update.end_of_rib.is_empty())
    );
    assert_eq!(wire.len(), 2);
    assert_eq!(
        wire.keys().map(|key| key.0).collect::<HashSet<_>>(),
        HashSet::from([Prefix::V6(host), Prefix::V6(blocked)]),
        "queued recovery fills the freed ordinary slot with remaining intent"
    );
    assert!(!wire.keys().any(|key| key.0 == Prefix::V6(ordinary)));
    assert_eq!(capacity(&manager), (2, Some(0)));
    assert_late_waiter_advertised_truth(
        &mut manager,
        observer,
        2,
        "limited body after queued intent recovery",
    );
    assert!(!manager.dirty_peers.contains(&observer));
}

/// Refused proof while a deleted RTBH path's key is re-announced for its
/// surviving sibling. With Add-Path (a private receiver) the sibling only
/// moves rank: withdraw the deleted path's key and keep the sibling's old
/// key. With one path per prefix (a grouped receiver) the replacement has no
/// other key, so the deleted path stays: the prefix must never lose its
/// blackhole. `held_counts` also checks the advertised count inside the hold.
#[expect(
    clippy::too_many_lines,
    reason = "one transcript covers pre-hold admission, refused proof, the replacement and release"
)]
fn assert_refused_proof_rtbh_replacement(add_path: bool, held_counts: bool) {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (tx, mut rx) = mpsc::channel(64);
    let registration = |tx| {
        let mut up = super::lifecycle::test_peer_up(observer, 82, tx);
        if let RibUpdate::PeerUp {
            per_client_best,
            add_path_send_families,
            add_path_send_max,
            sendable_families,
            ..
        } = &mut up
        {
            *sendable_families = vec![FAMILY];
            if add_path {
                *per_client_best = true;
                *add_path_send_families = vec![FAMILY];
                *add_path_send_max = 2;
            }
        }
        up
    };
    manager.handle_update(registration(tx));
    // Add-Path receivers are private; a single-best one joins a group.
    assert_eq!(manager.grouped_member_of(observer).is_some(), !add_path);
    let mut wire = std::collections::HashMap::new();
    apply_wire(&mut rx, &mut wire);
    // A configured limit makes recovery depend on exact admission proof.
    super::outbound_prefix_limits::prepare(
        &mut manager,
        1,
        super::outbound_prefix_limits::limit_config(&[(observer, Some(3), None)], &[]),
    )
    .unwrap();
    super::outbound_prefix_limits::apply(&mut manager, 1, true).unwrap();
    let host = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
    let prefix = Prefix::V4(host);
    let first = u32::from(add_path);
    // Path 17 ranks first on local preference; path 23 second.
    for (path_id, preference) in [(17, 200), (23, 100)] {
        let mut route = make_route_with_lp(host, SOURCE, preference);
        set_peer(&mut route, crate::PeerId::LOCAL);
        route.origin_type = crate::route::RouteOrigin::Local;
        route.path_id = path_id;
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectRoute { route, reply });
        result.try_recv().unwrap().unwrap();
    }
    // A received row admitted before the hold stays frozen, which holds
    // this receiver's recovery on exact admission proof.
    let ordinary = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24));
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
            SOURCE,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    apply_wire(&mut rx, &mut wire);
    assert!(wire.contains_key(&(ordinary, first)));
    assert_eq!(wire[&(prefix, first)].local_pref(), 200);
    assert_eq!(
        wire.get(&(prefix, 2)).map(Route::local_pref),
        add_path.then_some(100)
    );
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let writer = manager.outbound_peers[&observer].clone();
    // A new RTBH waits behind a full writer, so the retry must reserve proof.
    let pending = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32));
    let occupied: Vec<_> = std::iter::from_fn(|| writer.clone().try_reserve_owned().ok()).collect();
    inject_host(
        &mut manager,
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32),
    );
    drop(occupied);
    assert!(apply_wire(&mut rx, &mut wire).is_empty());
    manager
        .pending_group_admitted
        .fail_next_allocation_for_test();
    manager.distribute_changes_to_targets(&HashSet::new(), &HashSet::from([observer]));
    assert!(manager.pending_group_admitted.get(&observer).is_none());
    assert!(manager.group_recovery_fallback(observer).is_some());
    // The private Add-Path receiver's complete bodies still prove the new
    // RTBH's capacity; a grouped receiver waits for the refused proof.
    let admitted = apply_wire(&mut rx, &mut wire);
    assert_eq!(admitted.is_empty(), !add_path);
    assert_eq!(wire.contains_key(&(pending, first)), add_path);
    let before = wire.len();
    if held_counts {
        assert_eq!(manager.actual_unicast_advertised_count(observer), before);
    }

    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::WithdrawInjected {
        prefix,
        path_id: 17,
        allow_missing: false,
        owner: String::new(),
        override_owner: false,
        reply,
    });
    assert!(result.try_recv().unwrap().unwrap().removed);
    let updates = apply_wire(&mut rx, &mut wire);
    assert!(manager.selection_deferred(FAMILY));
    assert!(
        updates.iter().all(|update| update.announce.is_empty()),
        "re-announcing path 23 needs the refused admission"
    );
    let withdrawn: Vec<_> = updates
        .iter()
        .flat_map(|update| &update.withdraw)
        .copied()
        .collect();
    if add_path {
        assert_eq!(withdrawn, [(prefix, 1)], "the deleted rank-1 path leaves");
        assert_eq!(
            wire.get(&(prefix, 2)).map(Route::local_pref),
            Some(100),
            "the surviving RTBH path keeps its old rank"
        );
        if held_counts {
            assert_eq!(
                manager.actual_unicast_advertised_count(observer),
                before - 1
            );
        }
    } else {
        assert_eq!(withdrawn, [], "the replacement has no other key");
        assert_eq!(
            wire.get(&(prefix, 0)).map(Route::local_pref),
            Some(200),
            "the prefix stays blackholed until the replacement is admitted"
        );
        assert_eq!(manager.actual_unicast_advertised_count(observer), before);
    }
    assert!(wire.keys().any(|key| key.0 == prefix));

    manager.handle_update(RibUpdate::EndOfRib {
        peer: peer_v4(WAITER),
        session_id: 83,
        afi: FAMILY.0,
        safi: FAMILY.1,
    });
    for _ in 0..3 {
        manager.distribute_changes(&HashSet::new(), &HashSet::new());
        apply_wire(&mut rx, &mut wire);
    }
    assert_eq!(wire[&(prefix, first)].local_pref(), 100);
    assert!(
        wire.values().all(|route| route.local_pref() != 200),
        "the deleted path never returns"
    );
    let expected = HashSet::from([(prefix, first), (pending, first), (ordinary, first)]);
    assert_eq!(wire.keys().copied().collect::<HashSet<_>>(), expected);
    assert_eq!(
        manager.actual_unicast_advertised_count(observer),
        wire.len()
    );
    assert!(!manager.dirty_peers.contains(&observer));
}

#[test]
fn refused_proof_withdraws_a_deleted_add_path_rtbh_and_keeps_its_moved_sibling() {
    assert_refused_proof_rtbh_replacement(true, false);
}

#[test]
#[ignore = "LAN-2702: the held count omits the RTBH admitted under refused proof"]
fn refused_proof_add_path_rtbh_admission_keeps_held_advertised_count() {
    assert_refused_proof_rtbh_replacement(true, true);
}

#[test]
fn refused_proof_keeps_a_single_best_prefix_blackholed_across_rtbh_replacement() {
    assert_refused_proof_rtbh_replacement(false, true);
}

/// The refused-proof replacement salvage is linear in the batch: replacing
/// all `siblings` Add-Path RTBH sources at once re-announces every sibling
/// key, and each re-announcement must not rescan the prefix's siblings.
#[expect(
    clippy::too_many_lines,
    reason = "one transcript covers setup, refused proof and the batched replacement"
)]
fn refused_replacement_salvage_visits(siblings: u32) -> usize {
    let mut manager = manager_with_dormant_waiter();
    let _source = connect(&mut manager, SOURCE, 64, false, false);
    let observer = peer_v4(OBSERVER);
    let (tx, mut rx) = mpsc::channel(256);
    let registration = |tx| {
        let mut up = super::lifecycle::test_peer_up(observer, 82, tx);
        if let RibUpdate::PeerUp {
            per_client_best,
            add_path_send_families,
            add_path_send_max,
            sendable_families,
            ..
        } = &mut up
        {
            *per_client_best = true;
            *sendable_families = vec![FAMILY];
            *add_path_send_families = vec![FAMILY];
            *add_path_send_max = siblings;
        }
        up
    };
    manager.handle_update(registration(tx.clone()));
    let mut wire = std::collections::HashMap::new();
    apply_wire(&mut rx, &mut wire);
    super::outbound_prefix_limits::prepare(
        &mut manager,
        1,
        super::outbound_prefix_limits::limit_config(&[(observer, Some(8), None)], &[]),
    )
    .unwrap();
    super::outbound_prefix_limits::apply(&mut manager, 1, true).unwrap();
    let host = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32);
    let prefix = Prefix::V4(host);
    for rank in 0..siblings {
        let mut route = make_route_with_lp(host, SOURCE, 1000 - rank);
        set_peer(&mut route, crate::PeerId::LOCAL);
        route.origin_type = crate::route::RouteOrigin::Local;
        route.path_id = 100 + rank;
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectRoute { route, reply });
        result.try_recv().unwrap().unwrap();
    }
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: peer_v4(SOURCE),
        session_id: 81,
        announced: vec![make_route(
            Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
            SOURCE,
        )],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    drain_route_chunks(&mut manager);
    apply_wire(&mut rx, &mut wire);
    assert_eq!(
        wire.keys().filter(|key| key.0 == prefix).count(),
        siblings as usize
    );
    let _waiter = connect(&mut manager, WAITER, 64, true, false);
    let writer = manager.outbound_peers[&observer].clone();
    let occupied: Vec<_> = std::iter::from_fn(|| writer.clone().try_reserve_owned().ok()).collect();
    inject_host(
        &mut manager,
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 2), 32),
    );
    drop(occupied);
    manager
        .pending_group_admitted
        .fail_next_allocation_for_test();
    manager.distribute_changes_to_targets(&HashSet::new(), &HashSet::from([observer]));
    assert!(manager.group_recovery_fallback(observer).is_some());
    // Complete private bodies still admit the new RTBH host.
    apply_wire(&mut rx, &mut wire);
    let before: Vec<_> = wire.keys().filter(|key| key.0 == prefix).copied().collect();
    // One backpressured batch replaces every RTBH source: each new source
    // takes over its predecessor's key in place, so the refused batch
    // re-announces every sibling key over a departing exempt row.
    let occupied: Vec<_> = std::iter::from_fn(|| writer.clone().try_reserve_owned().ok()).collect();
    for rank in 0..siblings {
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::WithdrawInjected {
            prefix,
            path_id: 100 + rank,
            allow_missing: false,
            owner: String::new(),
            override_owner: false,
            reply,
        });
        assert!(result.try_recv().unwrap().unwrap().removed);
        let mut route = make_route_with_lp(host, SOURCE, 1000 - rank);
        set_peer(&mut route, crate::PeerId::LOCAL);
        route.origin_type = crate::route::RouteOrigin::Local;
        route.path_id = 200 + rank;
        let (reply, mut result) = oneshot::channel();
        manager.handle_update(RibUpdate::InjectRoute { route, reply });
        result.try_recv().unwrap().unwrap();
    }
    drop(occupied);
    manager.refused_replacement_salvage_visits = 0;
    manager.distribute_changes_to_targets(&HashSet::new(), &HashSet::from([observer]));
    assert!(manager.group_recovery_fallback(observer).is_some());
    let updates = apply_wire(&mut rx, &mut wire);
    assert!(
        updates.iter().all(|update| update.withdraw.is_empty()),
        "no RTBH key leaves while its replacement waits for admission"
    );
    let mut after: Vec<_> = wire.keys().filter(|key| key.0 == prefix).copied().collect();
    let mut before = before;
    before.sort_unstable();
    after.sort_unstable();
    assert_eq!(after, before, "every sibling key keeps a blackhole");
    manager.refused_replacement_salvage_visits
}

#[test]
fn refused_replacement_salvage_work_is_linear_in_add_path_siblings() {
    for siblings in [4, 16, 64] {
        let visits = refused_replacement_salvage_visits(siblings);
        let bound = 3 * siblings as usize + 8;
        assert!(
            visits > siblings as usize && visits <= bound,
            "{siblings} siblings cost {visits} salvage visits; bound {bound}"
        );
    }
}
