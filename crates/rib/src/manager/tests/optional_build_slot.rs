//! Real Prepare and registration commands competing for the single build slot.

use super::lifecycle::{test_peer_up, test_routes_received};
use super::*;

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 99);

fn neighbor(n: u8) -> PeerId {
    peer_v4(Ipv4Addr::new(198, 51, 100, n))
}

fn join(
    manager: &mut RibManager,
    peer: PeerId,
    policy: Option<&rustbgpd_policy::PolicyChain>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (sender, receiver) = mpsc::channel(128);
    let mut up = test_peer_up(peer, 1, sender);
    let RibUpdate::PeerUp { export_policy, .. } = &mut up else {
        unreachable!()
    };
    *export_policy = policy.cloned();
    manager.handle_update(up);
    receiver
}

fn fixture() -> (RibManager, mpsc::Receiver<OutboundRouteUpdate>) {
    let (_tx, updates) = mpsc::channel(8);
    let mut manager = RibManager::new(updates, dummy_query_rx(), None, None, BgpMetrics::new());
    let mut established = join(
        &mut manager,
        neighbor(1),
        Some(&deny_default_prefix_chain()),
    );
    register_test_peer(&mut manager, peer_v4(SOURCE), 0);
    let routes = (0..2050)
        .map(|n| make_route(Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000 + n), 32), SOURCE))
        .collect();
    manager.handle_update(test_routes_received(peer_v4(SOURCE), routes));
    drain_route_chunks(&mut manager);
    while established.try_recv().is_ok() {}
    manager.first_group_build_min_routes = 1;
    manager.initial_dump_defer_min_routes = 1;
    (manager, established)
}

fn prepare(
    manager: &mut RibManager,
    target: &rustbgpd_policy::PolicyChain,
) -> oneshot::Receiver<Result<(), String>> {
    let (reply, response) = oneshot::channel();
    manager.handle_update(RibUpdate::PrepareExportPolicyDestination {
        peer: neighbor(1),
        export_policy: Some(target.clone()),
        reply,
    });
    response
}

fn target_policy() -> rustbgpd_policy::PolicyChain {
    deny_prefixes_chain(&[Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 32))])
}

fn finish_registrations(manager: &mut RibManager) {
    for _ in 0..64 {
        if manager.pending_initial_registrations.is_empty() && manager.first_group_build.is_none() {
            return;
        }
        manager.advance_pending_initial_registration();
    }
    panic!("queued registrations did not settle");
}

#[test]
fn legacy_prepare_first_releases_an_idle_holder_for_a_cold_registration() {
    let (mut manager, mut established) = fixture();
    let target = target_policy();
    let mut response = prepare(&mut manager, &target);
    let prepared_gid = manager
        .pending_destination_prestage
        .as_ref()
        .unwrap()
        .destination;
    let cold = neighbor(2);
    let _cold_receiver = join(&mut manager, cold, None);
    assert!(manager.first_group_build.is_none());
    assert!(manager.prestaging_destination(prepared_gid));
    // A warm join with a configured policy can register while the unrelated
    // preparation retains the only private slot.
    let warm = neighbor(3);
    let _warm_receiver = join(&mut manager, warm, Some(&deny_default_prefix_chain()));
    for _ in 0..2 {
        manager.advance_pending_initial_registration();
    }
    assert_eq!(
        manager.grouped_member_of(warm),
        manager.grouped_member_of(neighbor(1))
    );
    assert!(manager.pending_destination_prestage.is_some() && manager.first_group_build.is_none());
    while manager.pending_destination_prestage.is_some() {
        manager.advance_destination_prestage();
    }
    assert_eq!(response.try_recv().unwrap(), Ok(()));
    assert_eq!(manager.prepared_destination, Some(prepared_gid));

    // This successful caller issues neither commit nor discard. The waiting
    // registration must acquire the slot without a caller lifetime or timeout.
    manager.advance_pending_initial_registration();
    assert!(manager.optional_destination_retirement_active());
    assert!(manager.first_group_build.is_none());
    assert!(!manager.group_ribs.contains_key(&prepared_gid));

    let late = neighbor(4);
    let _late_receiver = join(&mut manager, late, Some(&target));
    assert!(!manager.outbound_peers.contains_key(&late));
    let second_warm = neighbor(5);
    let _second_receiver = join(
        &mut manager,
        second_warm,
        Some(&deny_default_prefix_chain()),
    );
    for _ in 0..3 {
        manager.advance_pending_initial_registration();
    }
    assert_eq!(
        manager.grouped_member_of(second_warm),
        manager.grouped_member_of(warm)
    );
    assert!(manager.optional_destination_retirement_active());
    let marker = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 66), 32);
    manager.handle_update(test_routes_received(
        peer_v4(SOURCE),
        vec![make_route(marker, SOURCE)],
    ));
    drain_route_chunks(&mut manager);
    assert!(manager.loc_rib.get(&Prefix::V4(marker)).is_some());
    assert!(
        std::iter::from_fn(|| established.try_recv().ok()).any(|update| update
            .announce
            .iter()
            .any(|route| route.prefix == Prefix::V4(marker)))
    );
    let mut pages = 0;
    while manager.optional_destination_retirement_active() {
        manager.advance_pending_initial_registration();
        assert!(manager.first_group_build.is_none() && !manager.outbound_peers.contains_key(&late));
        let spent = manager.advance_optional_destination_retirement();
        assert!(spent <= crate::loc_rib::REGISTRATION_PAGE_SIZE);
        pages += 1;
        assert!(pages < 64);
    }
    assert!(pages >= 2);
    finish_registrations(&mut manager);
    assert!(manager.outbound_peers.contains_key(&cold));
    let actual = manager.grouped_member_of(late).unwrap();
    assert!(
        manager.group_ribs[&actual]
            .table
            .get(&Prefix::V4(marker), 0)
            .is_some()
    );
    // Losing the optional acceleration changes neither the original policy
    // transaction's authority nor the target it commits when it finally arrives.
    let (reply, mut applied) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer: neighbor(1),
        export_policy: Some(target),
        reply,
    });
    applied.try_recv().unwrap().unwrap();
    assert_eq!(manager.grouped_member_of(neighbor(1)), Some(actual));
}

#[test]
fn cold_first_leaves_optional_prepare_unallocated() {
    let (mut manager, _established) = fixture();
    let _cold = join(&mut manager, neighbor(2), None);
    assert!(manager.first_group_build.is_some());
    let result = prepare(&mut manager, &target_policy()).try_recv().unwrap();
    assert!(result.is_err());
    assert!(
        manager.pending_destination_prestage.is_none() && manager.prepared_destination.is_none()
    );
    finish_registrations(&mut manager);
    assert!(manager.outbound_peers.contains_key(&neighbor(2)));
}

#[test]
fn external_cancellation_of_pending_prepare_releases_the_slot() {
    let (mut manager, _established) = fixture();
    let response = prepare(&mut manager, &target_policy());
    let _cold = join(&mut manager, neighbor(2), None);
    manager.advance_pending_initial_registration();
    assert!(manager.pending_destination_prestage.is_some() && manager.first_group_build.is_none());
    drop(response);
    manager.advance_destination_prestage();
    assert!(manager.pending_destination_prestage.is_none());
    assert!(manager.optional_destination_retirement_active());
    manager.advance_pending_initial_registration();
    assert!(manager.first_group_build.is_none());
    // Cancellation preceded the first staging slice. Only empty table and walk buffers remain.
    let spent = manager.advance_optional_destination_retirement();
    assert!((1..=crate::loc_rib::REGISTRATION_PAGE_SIZE).contains(&spent));
    assert!(manager.first_group_slot_available());
    finish_registrations(&mut manager);
    assert!(manager.outbound_peers.contains_key(&neighbor(2)));
}
