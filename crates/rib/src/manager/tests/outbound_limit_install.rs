use super::*;
use std::num::NonZeroU32;
use std::sync::Mutex;

use super::exportability::MockExactExportEncoder;
use super::outbound_prefix_limits::{
    announce, apply, limit_config, prepare, register_peer_with_families,
};
use crate::update::ExactExportKey;

fn install_route(afi: Afi, index: u32, source: PeerId) -> Route {
    let mut route = if afi == Afi::Ipv4 {
        make_indexed_route(index, Ipv4Addr::new(192, 0, 2, 240))
    } else {
        make_v6_route(
            Ipv6Prefix::new(
                Ipv6Addr::from((0x2001_0db8_u128 << 96) | u128::from(index)),
                128,
            ),
            Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1),
        )
    };
    route.peer = source;
    route.is_stale = index.is_multiple_of(2);
    route
}

fn install_fixture(
    selected: Afi,
    excluded: u32,
) -> (
    RibManager,
    PeerId,
    BTreeSet<Prefix>,
    mpsc::Receiver<OutboundRouteUpdate>,
) {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 241));
    let mut output = register_peer_with_families(&mut manager, peer, &dual_stack_sendable());
    assert!(manager.grouped_member_of(peer).is_some());
    let source = peer_v4(Ipv4Addr::new(192, 0, 2, 240));
    let rejected: Vec<_> = (0..excluded)
        .map(|index| {
            ExactExportKey::Unicast(install_route(selected, 1000 + index, source).prefix, 0)
        })
        .collect();
    let encoder = MockExactExportEncoder::accepting(1);
    encoder.set_profile(1, rejected.clone());
    manager.peer_export_encoders.insert(peer, encoder);
    let accepted: Vec<_> = [Afi::Ipv4, Afi::Ipv6]
        .into_iter()
        .flat_map(|afi| (0..4).map(move |index| install_route(afi, index, source)))
        .collect();
    let expected = accepted.iter().map(|route| route.prefix).collect();
    let mut remote = accepted;
    remote.extend((0..excluded).map(|index| install_route(selected, 1000 + index, source)));
    announce(&mut manager, source, remote);
    announce(
        &mut manager,
        peer,
        (0..excluded)
            .map(|index| install_route(selected, 2000 + index, peer))
            .collect(),
    );
    let mut wire = BTreeSet::new();
    while let Ok(update) = output.try_recv() {
        for route in update.announce.iter() {
            wire.insert(route.prefix);
        }
        for (prefix, _) in update.withdraw {
            wire.remove(&prefix);
        }
    }
    assert_eq!(wire, expected);
    for key in rejected {
        assert!(manager.peer_unexportable[&peer].contains(&key));
    }
    // Stale rejection residue must be visited even when no group slot matches.
    manager
        .peer_unexportable
        .entry(peer)
        .or_default()
        .extend((0..excluded).map(|index| {
            ExactExportKey::Unicast(install_route(selected, 3000 + index, source).prefix, 0)
        }));
    (manager, peer, expected, output)
}

fn selected_config(
    peer: PeerId,
    afi: Afi,
    cap: Option<u32>,
) -> crate::update::OutboundPrefixLimitConfig {
    if afi == Afi::Ipv4 {
        limit_config(&[(peer, cap, None)], &[])
    } else {
        limit_config(&[(peer, None, cap)], &[])
    }
}

fn assert_inventory(manager: &RibManager, peer: PeerId, afi: Afi, expected: &BTreeSet<Prefix>) {
    let entry = &manager.outbound_prefix_limits[&peer];
    let expected: BTreeSet<_> = expected
        .iter()
        .copied()
        .filter(|prefix| prefix_family(prefix).0 == afi)
        .collect();
    assert_eq!(entry.grouped_len(afi), expected.len());
    for prefix in expected {
        assert!(
            entry.grouped_contains(&prefix),
            "missing admitted prefix {prefix}"
        );
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "real Apply dispatch checks interior replies, its pending acknowledgement and three fenced lanes together"
)]
fn observe_apply(manager: &mut RibManager, txn: u64) -> BTreeMap<&'static str, usize> {
    let expected_count = manager.loc_rib.len();
    let before: BTreeMap<_, _> = manager
        .ribs
        .iter()
        .map(|(peer, rib)| (*peer, (rib.len(), rib.maintained_stale_route_counts())))
        .collect();
    let (query_tx, query_rx) = mpsc::channel(1);
    manager.query_rx = query_rx;
    let (reply, general) = oneshot::channel();
    query_tx
        .try_send(RibUpdate::QueryLocRibCount { reply })
        .unwrap();
    let general = Arc::new(Mutex::new(general));
    let (tx, rx) = mpsc::channel(1);
    manager.rx = rx;
    let (reply, mutation) = oneshot::channel();
    tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
    let mutation = Arc::new(Mutex::new(mutation));
    let (summary_tx, summary_rx) = mpsc::channel(1);
    manager.summary_rx = Some(summary_rx);
    let (reply, summary) = oneshot::channel();
    summary_tx
        .try_send(crate::RibSummaryQuery::NeighborRibSnapshots {
            peers: Vec::new(),
            comparison: None,
            include_retained: true,
            reply,
        })
        .unwrap();
    let summary = Arc::new(Mutex::new(summary));
    let (readiness_tx, readiness_rx) = mpsc::channel(1);
    manager.readiness_rx = Some(readiness_rx);
    let pending = Arc::new(Mutex::new(
        None::<oneshot::Receiver<Result<usize, crate::RibReadinessError>>>,
    ));
    let stages = Arc::new(Mutex::new(BTreeMap::<&'static str, usize>::new()));
    let (reply, response) = oneshot::channel();
    let response = Arc::new(Mutex::new(response));
    manager.flush_poll_budget = Duration::ZERO;
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let pending = Arc::clone(&pending);
        let stages = Arc::clone(&stages);
        let general = Arc::clone(&general);
        let mutation = Arc::clone(&mutation);
        let summary = Arc::clone(&summary);
        let response = Arc::clone(&response);
        move |stage| {
            assert!(matches!(
                general.lock().unwrap().try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                mutation.lock().unwrap().try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert!(matches!(
                summary.lock().unwrap().try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            if stage.starts_with("outbound_limit_") || stage.starts_with("grouped_") {
                assert!(
                    matches!(
                        response.lock().unwrap().try_recv(),
                        Err(oneshot::error::TryRecvError::Empty)
                    ),
                    "Apply acknowledged before its inventory work completed"
                );
            }
            if let Some(mut response) = pending.lock().unwrap().take() {
                assert_eq!(
                    response
                        .try_recv()
                        .expect("preceding actual-install checkpoint must answer readiness")
                        .unwrap(),
                    expected_count
                );
            }
            *stages.lock().unwrap().entry(stage).or_default() += 1;
            let (reply, response) = oneshot::channel();
            readiness_tx
                .try_send(crate::RibReadinessQuery::LocRibCount {
                    reply,
                    enqueued: Instant::now(),
                })
                .unwrap();
            *pending.lock().unwrap() = Some(response);
        }
    }));
    manager.handle_update(RibUpdate::ApplyOutboundPrefixLimits {
        txn,
        activate: true,
        reply,
    });
    manager.replacement_readiness_test_hook = None;
    assert_eq!(response.lock().unwrap().try_recv().unwrap(), Ok(()));
    assert_eq!(
        pending
            .lock()
            .unwrap()
            .take()
            .expect("Apply must install a readiness owner")
            .try_recv()
            .unwrap()
            .unwrap(),
        expected_count
    );
    assert_eq!(manager.loc_rib.len(), expected_count);
    assert_eq!(
        manager
            .ribs
            .iter()
            .map(|(peer, rib)| (*peer, (rib.len(), rib.maintained_stale_route_counts())))
            .collect::<BTreeMap<_, _>>(),
        before
    );
    assert_eq!(manager.primary_backlog(), 1);
    manager.drain_queries(1);
    assert_eq!(general.lock().unwrap().try_recv().unwrap(), expected_count);
    manager.drain_summary_queries();
    assert!(summary.lock().unwrap().try_recv().is_ok());
    let queued = manager.rx.try_recv().unwrap();
    manager.handle_update(queued);
    assert_eq!(mutation.lock().unwrap().try_recv().unwrap(), expected_count);
    stages.lock().unwrap().clone()
}

fn install_services_excluded_inputs(afi: Afi) {
    for excluded in [0, 8] {
        let (mut manager, peer, expected, _output) = install_fixture(afi, excluded);
        let gid = manager.grouped_member_of(peer).unwrap();
        let table_count = manager.group_ribs[&gid].table.len();
        let rejected = manager.peer_unexportable.get(&peer).map_or(0, HashSet::len);
        prepare(&mut manager, 1, selected_config(peer, afi, Some(64))).unwrap();
        let stages = observe_apply(&mut manager, 1);
        assert_eq!(
            stages["grouped_advertised_input"], table_count,
            "both AFIs and source/rejected exclusions must checkpoint before filtering"
        );
        if rejected != 0 {
            assert_eq!(
                stages["grouped_family_count_input"],
                rejected * 2,
                "preflight and surviving unlimited-family counts visit all rejection residue"
            );
        }
        assert_eq!(
            stages["outbound_limit_install_inventory"], 2,
            "materialization must service allocation edges"
        );
        assert_inventory(&manager, peer, afi, &expected);
        assert_eq!(manager.outbound_limit_recovery_for(peer), Vec::<Afi>::new());
    }
}

#[test]
fn outbound_limit_install_services_excluded_inputs_ipv4() {
    install_services_excluded_inputs(Afi::Ipv4);
}

#[test]
fn outbound_limit_install_services_excluded_inputs_ipv6() {
    install_services_excluded_inputs(Afi::Ipv6);
}

fn install_reserves_unique_prefix_growth(afi: Afi) {
    const PREFIXES: u32 = 32_768;
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 241));
    let mut output = register_peer_with_families(&mut manager, peer, &dual_stack_sendable());
    let source = peer_v4(Ipv4Addr::new(192, 0, 2, 240));
    let routes: Vec<_> = (0..PREFIXES)
        .map(|index| install_route(afi, index, source))
        .collect();
    let expected = routes.iter().map(|route| route.prefix).collect();
    for chunk in routes.chunks(256) {
        announce(&mut manager, source, chunk.to_vec());
        while output.try_recv().is_ok() {}
    }
    assert!(!manager.dirty_peers.contains(&peer));
    let gid = manager.grouped_member_of(peer).unwrap();
    // A controlled second path tests unique-prefix collection, not Add-Path grouping.
    let mut duplicate = install_route(afi, 0, source);
    duplicate.path_id = 7;
    manager
        .group_ribs
        .get_mut(&gid)
        .unwrap()
        .table
        .insert(duplicate);
    assert_eq!(
        manager.group_ribs[&gid].table.len(),
        usize::try_from(PREFIXES).unwrap() + 1
    );
    prepare(
        &mut manager,
        1,
        selected_config(peer, afi, Some(PREFIXES + 1)),
    )
    .unwrap();
    apply(&mut manager, 1, true).unwrap();
    assert_inventory(&manager, peer, afi, &expected);
    assert_eq!(manager.loc_rib.len(), usize::try_from(PREFIXES).unwrap());
    assert_eq!(
        manager.ribs[&source].len(),
        usize::try_from(PREFIXES).unwrap()
    );
}

#[test]
fn outbound_limit_install_reserves_unique_prefix_growth_ipv4() {
    install_reserves_unique_prefix_growth(Afi::Ipv4);
}

#[test]
fn outbound_limit_install_reserves_unique_prefix_growth_ipv6() {
    install_reserves_unique_prefix_growth(Afi::Ipv6);
}

/// Split horizon hides the member's own routes from its projection, so a
/// member originating most of the shared table must not retain capacity for
/// the whole table: the limit bounds the set for its lifetime.
fn install_reservation_is_bounded_by_limit(afi: Afi) {
    const ORIGINATED: u32 = 32_768;
    const LIMIT: u32 = 64;
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let member = peer_v4(Ipv4Addr::new(192, 0, 2, 241));
    let mut output = register_peer_with_families(&mut manager, member, &dual_stack_sendable());
    let other = peer_v4(Ipv4Addr::new(192, 0, 2, 240));
    let originated: Vec<_> = (0..ORIGINATED)
        .map(|index| install_route(afi, index, member))
        .collect();
    for chunk in originated.chunks(256) {
        announce(&mut manager, member, chunk.to_vec());
        while output.try_recv().is_ok() {}
    }
    let remote: Vec<_> = (0..4)
        .map(|index| install_route(afi, 100_000 + index, other))
        .collect();
    let expected = remote.iter().map(|route| route.prefix).collect();
    announce(&mut manager, other, remote);
    while output.try_recv().is_ok() {}
    let gid = manager.grouped_member_of(member).unwrap();
    assert_eq!(
        manager.group_ribs[&gid].table.unicast_prefix_count(afi),
        usize::try_from(ORIGINATED).unwrap() + 4
    );
    prepare(&mut manager, 1, selected_config(member, afi, Some(LIMIT))).unwrap();
    apply(&mut manager, 1, true).unwrap();
    assert_inventory(&manager, member, afi, &expected);
    let capacity = manager.outbound_prefix_limits[&member].grouped_capacity(afi);
    assert!(
        capacity <= 2 * LIMIT as usize,
        "retained capacity {capacity} exceeds twice the limit {LIMIT}"
    );
}

#[test]
fn outbound_limit_install_reservation_is_bounded_by_limit_ipv4() {
    install_reservation_is_bounded_by_limit(Afi::Ipv4);
}

#[test]
fn outbound_limit_install_reservation_is_bounded_by_limit_ipv6() {
    install_reservation_is_bounded_by_limit(Afi::Ipv6);
}

#[test]
fn outbound_limit_install_retires_only_removed_family_and_keeps_recovery_idempotent() {
    let (mut manager, peer, expected, mut output) = install_fixture(Afi::Ipv4, 8);
    let config = limit_config(&[(peer, Some(64), Some(64))], &[]);
    prepare(&mut manager, 1, config.clone()).unwrap();
    observe_apply(&mut manager, 1);
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        assert_inventory(&manager, peer, afi, &expected);
    }
    let retry = observe_apply(&mut manager, 1);
    assert!(!retry.contains_key("outbound_limit_install_inventory"));
    assert!(!retry.contains_key("outbound_limit_inventory_retirement"));
    prepare(&mut manager, 2, config).unwrap();
    let unchanged = observe_apply(&mut manager, 2);
    assert!(!unchanged.contains_key("outbound_limit_install_inventory"));
    assert!(!unchanged.contains_key("outbound_limit_inventory_retirement"));
    prepare(
        &mut manager,
        3,
        limit_config(&[(peer, None, Some(64))], &[]),
    )
    .unwrap();
    let removed_v4 = observe_apply(&mut manager, 3);
    assert_eq!(
        removed_v4["outbound_limit_inventory_retirement"], 6,
        "four old prefixes and both allocation boundaries checkpoint"
    );
    assert_eq!(
        manager.outbound_prefix_limits[&peer].grouped_len(Afi::Ipv4),
        0
    );
    assert_inventory(&manager, peer, Afi::Ipv6, &expected);
    assert_eq!(
        manager.outbound_prefix_limits[&peer]
            .family(Afi::Ipv6)
            .unwrap()
            .limit,
        NonZeroU32::new(64)
    );
    assert_eq!(manager.outbound_limit_recovery_for(peer), [Afi::Ipv4]);
    prepare(&mut manager, 4, limit_config(&[], &[])).unwrap();
    let removed_v6 = observe_apply(&mut manager, 4);
    assert_eq!(removed_v6["outbound_limit_inventory_retirement"], 6);
    assert!(!manager.outbound_prefix_limits.contains_key(&peer));
    assert_eq!(
        manager.outbound_limit_recovery_for(peer),
        [Afi::Ipv4, Afi::Ipv6]
    );
    observe_apply(&mut manager, 4);
    assert_eq!(
        manager.outbound_limit_recovery_for(peer),
        [Afi::Ipv4, Afi::Ipv6]
    );
    assert!(
        output.try_recv().is_err(),
        "install/removal schedules recovery without rewriting wire state inline"
    );
}

#[test]
fn outbound_limit_install_empty_inventory_still_services_allocation_and_retirement() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = peer_v4(Ipv4Addr::new(192, 0, 2, 241));
    let _output = register_peer_with_families(&mut manager, peer, &dual_stack_sendable());
    prepare(&mut manager, 1, selected_config(peer, Afi::Ipv4, Some(1))).unwrap();
    let installed = observe_apply(&mut manager, 1);
    assert_eq!(installed["outbound_limit_install_inventory"], 2);
    assert_eq!(
        manager.outbound_prefix_limits[&peer].grouped_len(Afi::Ipv4),
        0
    );
    prepare(&mut manager, 2, limit_config(&[], &[])).unwrap();
    let removed = observe_apply(&mut manager, 2);
    assert_eq!(removed["outbound_limit_inventory_retirement"], 2);
    assert!(!manager.outbound_prefix_limits.contains_key(&peer));
    assert_eq!(manager.outbound_limit_recovery_for(peer), [Afi::Ipv4]);
}

#[test]
fn outbound_limit_install_skips_replaced_session_and_commits_other_live_target() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let replaced = peer_v4(Ipv4Addr::new(192, 0, 2, 241));
    let _replaced_output =
        register_peer_with_families(&mut manager, replaced, &dual_stack_sendable());
    let live = peer_v4(Ipv4Addr::new(192, 0, 2, 242));
    let _live_output = register_peer_with_families(&mut manager, live, &dual_stack_sendable());
    let source = peer_v4(Ipv4Addr::new(192, 0, 2, 240));
    announce(
        &mut manager,
        source,
        (0..4)
            .map(|index| install_route(Afi::Ipv4, index, source))
            .collect(),
    );
    let expected = manager
        .grouped_advertised_routes_iter(live)
        .unwrap()
        .map(|route| route.prefix)
        .collect();
    prepare(
        &mut manager,
        1,
        limit_config(&[(replaced, Some(64), None), (live, Some(64), None)], &[]),
    )
    .unwrap();
    manager.outbound_session_ids.insert(replaced, 99);
    let installed = observe_apply(&mut manager, 1);
    assert_eq!(
        installed["outbound_limit_install_inventory"], 2,
        "only the surviving target builds a new inventory"
    );
    assert!(!manager.outbound_prefix_limits.contains_key(&replaced));
    assert_inventory(&manager, live, Afi::Ipv4, &expected);
    manager.install_registration_outbound_limits(replaced);
    assert_eq!(
        manager.outbound_prefix_limits[&replaced]
            .family(Afi::Ipv4)
            .unwrap()
            .limit,
        NonZeroU32::new(64),
        "the skipped generation's next registration resolves the committed configuration"
    );
    assert_eq!(manager.outbound_limit_recovery_for(live), Vec::<Afi>::new());
    assert_eq!(
        manager.outbound_limit_recovery_for(replaced),
        Vec::<Afi>::new()
    );
}

#[test]
fn outbound_limit_install_rejects_prepared_epoch_drift_without_partial_publication() {
    let (mut manager, peer, expected, _output) = install_fixture(Afi::Ipv4, 8);
    prepare(&mut manager, 1, selected_config(peer, Afi::Ipv4, Some(32))).unwrap();
    apply(&mut manager, 1, true).unwrap();
    prepare(
        &mut manager,
        2,
        limit_config(&[(peer, Some(16), Some(64))], &[]),
    )
    .unwrap();
    manager.outbound_limit_control.advance_epoch_for_test();
    assert!(
        apply(&mut manager, 2, true)
            .unwrap_err()
            .contains("epoch advanced")
    );
    assert_inventory(&manager, peer, Afi::Ipv4, &expected);
    assert_eq!(
        manager.outbound_prefix_limits[&peer]
            .family(Afi::Ipv4)
            .unwrap()
            .limit,
        NonZeroU32::new(32)
    );
    assert_eq!(
        manager.outbound_prefix_limits[&peer]
            .family(Afi::Ipv6)
            .unwrap()
            .limit,
        None
    );
    assert_eq!(
        manager.outbound_prefix_limits[&peer].grouped_len(Afi::Ipv6),
        0
    );
    assert_eq!(manager.outbound_limit_recovery_for(peer), Vec::<Afi>::new());
    manager.install_registration_outbound_limits(peer);
    assert_eq!(
        manager.outbound_prefix_limits[&peer]
            .family(Afi::Ipv4)
            .unwrap()
            .limit,
        NonZeroU32::new(32),
        "the refused transaction must not replace the running resolver tables"
    );
    assert_eq!(
        manager.outbound_prefix_limits[&peer]
            .family(Afi::Ipv6)
            .unwrap()
            .limit,
        None
    );
}
