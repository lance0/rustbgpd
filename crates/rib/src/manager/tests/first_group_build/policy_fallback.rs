use super::*;
use crate::manager::tests::cursor_presize::{prefix_dataset, rpol_chain};
use crate::manager::tests::local_route_export::allowed_dataset_chain;
use rustbgpd_policy::PolicyChain;

fn start_policy(
    manager: &mut RibManager,
    policy: PolicyChain,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (tx, rx) = mpsc::channel(64);
    let mut up = test_peer_up(receiver(1), 1, tx);
    let RibUpdate::PeerUp {
        export_policy,
        is_ebgp,
        route_reflector_client,
        sendable_families,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *export_policy = Some(policy);
    *is_ebgp = false;
    *route_reflector_client = true;
    *sendable_families = DUAL.to_vec();
    manager.handle_update(up);
    rx
}

fn reach_fallback(manager: &mut RibManager) {
    for _ in 0..64 {
        if manager.live_sessions[&receiver(1)]
            .last()
            .unwrap()
            .registration_policy_fallback
        {
            assert!(!manager.outbound_peers.contains_key(&receiver(1)));
            return;
        }
        assert!(
            manager.first_group_build.is_some(),
            "the current founder must take the authoritative path"
        );
        manager.advance_pending_initial_registration();
    }
    panic!("private policy build did not relinquish the slot");
}

#[test]
fn policy_founder_rechecks_a_dataset_changed_after_a_page() {
    let (mut manager, _tx, inventory) = fixture(1200);
    let (chain, handle) = allowed_dataset_chain(
        "policy p { term t { if route.prefix in allowed { reject } accept } }",
        false,
    );
    let mut rx = start_policy(&mut manager, chain);
    let rejected = staged_keys(&mut manager, &inventory)[0][0];
    assert_eq!(handle.refresh(prefix_dataset([rejected])), Some(2));
    reach_fallback(&mut manager);
    assert!(rx.is_empty());
    finish(&mut manager);
    let group = &manager.group_ribs[&manager.grouped_member_of(receiver(1)).unwrap()];
    assert!(group.table.get(&rejected, 0).is_none());
    assert_eq!(group.table.len(), inventory.len() - 1);
    assert_eq!(
        retained_policy_rejection_keys(&manager, receiver(1))
            .iter()
            .map(|key| key.prefix)
            .collect::<Vec<_>>(),
        [rejected]
    );
    assert_eq!(
        manager
            .export_policy_for(receiver(1))
            .unwrap()
            .hit_counters()
            .evals(),
        inventory.len() as u64
    );
    assert!(
        std::iter::from_fn(|| rx.try_recv().ok())
            .all(|update| update.announce.iter().all(|row| row.prefix != rejected))
    );
}

fn route_without_origin_as(prefix: Prefix, local_pref: u32) -> Route {
    let mut no_origin_as = route(prefix, OTHER, local_pref);
    AttrSet::edit(&mut no_origin_as.attributes, |attrs| {
        let path = attrs
            .iter_mut()
            .find_map(|attr| match attr {
                PathAttribute::AsPath(path) => Some(path),
                _ => None,
            })
            .unwrap();
        path.segments = vec![AsPathSegment::AsSet(vec![65001])];
    });
    no_origin_as
}

#[test]
fn policy_founder_discards_superseded_evaluation_error() {
    let (mut manager, _tx, inventory) = fixture(1200);
    // An AS_SET-only route cannot supply the origin ASN to this action.
    let chain = rpol_chain(
        "policy p { term t { set med route.origin-as; accept } }",
        &rustbgpd_policy::datasets::DatasetBindings::new(),
    );
    let _rx = start_policy(&mut manager, chain);
    let changed = staged_keys(&mut manager, &inventory)[0][0];
    manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        vec![route_without_origin_as(changed, 160)],
    ));
    drain_route_chunks(&mut manager);
    manager.advance_first_group_build();
    assert!(!manager.first_group_contains(changed));
    manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        vec![route(changed, OTHER, 125)],
    ));
    drain_route_chunks(&mut manager);
    reach_fallback(&mut manager);
    finish(&mut manager);
    let group = &manager.group_ribs[&manager.grouped_member_of(receiver(1)).unwrap()];
    assert_eq!(group.table.get(&changed, 0).unwrap().local_pref(), 125);
    let hits = manager
        .export_policy_for(receiver(1))
        .unwrap()
        .hit_counters();
    assert_eq!(hits.evals(), inventory.len() as u64);
    assert_eq!(hits.eval_errors(), 0);
    assert!(hits.last_error().is_none());
}

#[test]
fn policy_founder_replays_latest_router_id_after_wire_equal_repair() {
    let (mut manager, _tx, inventory) = fixture(1200);
    let chain = rpol_chain(
        "policy p { term t { accept } }",
        &rustbgpd_policy::datasets::DatasetBindings::new(),
    );
    let mut rx = start_policy(&mut manager, chain);
    let changed = staged_keys(&mut manager, &inventory)[0][0];
    let router_id = Ipv4Addr::new(203, 0, 113, 91);
    // The first update queues repair. Before its turn the source restores
    // its wire attributes, with different metadata from the staged winner.
    for pref in [150, 100] {
        let mut next = route(changed, SOURCE, pref);
        next.peer_router_id = router_id;
        manager.handle_update(test_routes_received(peer_v4(SOURCE), vec![next]));
        drain_route_chunks(&mut manager);
    }
    assert_eq!(
        manager.loc_rib.get(&changed).unwrap().peer_router_id,
        router_id
    );
    for _ in 0..64 {
        manager.advance_pending_initial_registration();
        assert!(
            !manager.live_sessions[&receiver(1)]
                .last()
                .unwrap()
                .registration_policy_fallback
        );
        if manager.grouped_member_of(receiver(1)).is_some() {
            break;
        }
    }
    let group = &manager.group_ribs[&manager.grouped_member_of(receiver(1)).unwrap()];
    assert_eq!(
        group.table.get(&changed, 0).unwrap().peer_router_id,
        router_id
    );
    let mut replayed = Vec::new();
    while let Ok(update) = rx.try_recv() {
        replayed.extend(
            update
                .announce
                .iter()
                .filter(|route| route.prefix == changed)
                .map(|route| route.peer_router_id),
        );
    }
    assert_eq!(replayed, [router_id]);
    assert_eq!(
        manager
            .export_policy_for(receiver(1))
            .unwrap()
            .hit_counters()
            .evals(),
        inventory.len() as u64
    );
}

#[test]
fn policy_founder_reconnect_gets_a_fresh_scan_while_fallback_retires() {
    let (mut manager, _tx, inventory) = fixture(1200);
    let (chain, handle) = allowed_dataset_chain(
        "policy p { term t { if route.prefix in allowed { reject } accept } }",
        false,
    );
    let old = start_policy(&mut manager, chain.clone());
    let rejected = staged_keys(&mut manager, &inventory)[0][0];
    assert_eq!(handle.refresh(prefix_dataset([rejected])), Some(2));
    reach_fallback(&mut manager);
    assert!(manager.first_group_retiring_slots().is_some());
    // Same numeric session ID, distinct sender. The old fallback decision
    // cannot bypass pacing for this replacement session.
    let current = start_policy(&mut manager, chain);
    staged_keys(&mut manager, &inventory);
    assert!(old.is_empty() && current.is_empty());
    finish(&mut manager);
    assert!(old.is_empty() && !current.is_empty());
    let group = &manager.group_ribs[&manager.grouped_member_of(receiver(1)).unwrap()];
    assert!(group.table.get(&rejected, 0).is_none());
    assert_eq!(group.table.len(), inventory.len() - 1);
}

#[test]
fn policy_founder_uses_authoritative_order_for_multiple_errors() {
    let (mut manager, _tx, inventory) = fixture(1200);
    let chain = rpol_chain(
        "policy p { term first { if route.local-pref == 160 { set med route.origin-as; accept } } term second { set med route.origin-as; accept } }",
        &rustbgpd_policy::datasets::DatasetBindings::new(),
    );
    let [a, b] = prefixes(42);
    manager.handle_update(test_routes_received(
        peer_v4(OTHER),
        vec![
            route_without_origin_as(a, 160),
            route_without_origin_as(b, 170),
        ],
    ));
    drain_route_chunks(&mut manager);
    let _rx = start_policy(&mut manager, chain);
    assert!(manager.first_group_build.is_some());
    reach_fallback(&mut manager);
    finish(&mut manager);
    let hits = manager
        .export_policy_for(receiver(1))
        .unwrap()
        .hit_counters();
    assert_eq!(hits.evals(), inventory.len() as u64);
    assert_eq!(hits.eval_errors(), 2);
    assert!(hits.last_error().is_some());
    assert_eq!(
        retained_policy_rejection_keys(&manager, receiver(1)).len(),
        2
    );
}

#[test]
fn policy_founder_with_two_errors_falls_back_after_its_first_page() {
    use crate::loc_rib::REGISTRATION_PAGE_SIZE;
    use crate::manager::slice_timing::group_work;

    let (mut manager, _tx, inventory) = fixture(4096);
    let chain = rpol_chain(
        "policy p { term t { set med route.origin-as; accept } }",
        &rustbgpd_policy::datasets::DatasetBindings::new(),
    );
    // Every fourth winner has no origin AS, so any page evaluates several errors.
    let broken: Vec<_> = inventory
        .keys()
        .step_by(4)
        .map(|&prefix| route_without_origin_as(prefix, 160))
        .collect();
    let errors = broken.len() as u64;
    manager.handle_update(test_routes_received(peer_v4(OTHER), broken));
    drain_route_chunks(&mut manager);
    let before = group_work();
    let _rx = start_policy(&mut manager, chain);
    assert!(manager.first_group_build.is_some());
    reach_fallback(&mut manager);
    let discovered = group_work()
        .get("first_group_discovery")
        .copied()
        .unwrap_or(0)
        - before.get("first_group_discovery").copied().unwrap_or(0);
    assert!(
        discovered <= REGISTRATION_PAGE_SIZE,
        "fell back after {discovered} bucket visits of {} routes",
        inventory.len()
    );
    finish(&mut manager);
    let hits = manager
        .export_policy_for(receiver(1))
        .unwrap()
        .hit_counters();
    assert_eq!(hits.evals(), inventory.len() as u64);
    assert_eq!(hits.eval_errors(), errors);
}
