use super::evpn_group_storage::{fixture, fixture_with_rtc, received, stage};
use super::*;
use crate::update::ExactExportKey;
use std::sync::atomic::{AtomicUsize, Ordering};

fn install_routes(manager: &mut RibManager, gid: usize, count: u8) -> Vec<EvpnRibRoute> {
    (1..=count)
        .map(|suffix| {
            let mut route = received(100);
            route.route = make_evpn_imet(Ipv4Addr::new(198, 51, 100, suffix), 1).route;
            assert_eq!(stage(manager, gid, &route).deltas.len(), 1);
            route
        })
        .collect()
}

#[test]
fn evpn_completeness_checkpoints_every_visited_row_and_preserves_refusal() {
    let (mut manager, _member, gid, _output) = fixture();
    let routes = install_routes(&mut manager, gid, 7);
    let group = manager.group_ribs.get_mut(&gid).unwrap();
    assert!(group.evpn_projection_complete());
    let mut visits = 0;
    assert!(group.evpn_projection_complete_with_checkpoint(&mut || visits += 1));
    assert_eq!(visits, routes.len());

    let missing = make_evpn_imet(Ipv4Addr::new(198, 51, 100, 99), 1);
    group.table.remove_evpn(&routes[0].key());
    group.table.insert_evpn(missing.clone());
    // Cardinalities still match; the full-table lookup must reject the row
    // without received metadata and checkpoint that row before returning.
    let expected = group
        .table
        .iter_evpn()
        .position(|route| route.key() == missing.key())
        .unwrap()
        + 1;
    visits = 0;
    assert!(!group.evpn_projection_complete_with_checkpoint(&mut || visits += 1));
    assert_eq!(visits, expected);
}

#[test]
fn evpn_projection_checkpoints_wholly_excluded_rtc_source_and_rejection_rows() {
    let (mut manager, member, gid, _output) = fixture();
    let routes = install_routes(&mut manager, gid, 7);
    let membership = RtcMembership::default();
    let rejected = routes
        .iter()
        .map(|route| ExactExportKey::Evpn(route.key()))
        .collect::<HashSet<_>>();
    for (target, rtc, overlay) in [
        (member, Some(&membership), None),
        (routes[0].peer, None, None),
        (member, None, Some(&rejected)),
    ] {
        let mut visits = 0;
        let yielded = manager.group_ribs[&gid]
            .evpn_member_projection_with_checkpoint(
                target,
                manager.cluster_id,
                rtc,
                overlay,
                || visits += 1,
            )
            .count();
        assert_eq!(yielded, 0);
        assert_eq!(visits, routes.len());
    }
}

#[test]
fn evpn_shared_empty_capture_checkpoints_completeness_count_and_population() {
    let (mut manager, member, gid, _output) = fixture_with_rtc(true);
    let routes = install_routes(&mut manager, gid, 7);
    manager
        .peer_rt_membership
        .insert(member, RtcMembership::default());
    let visits = Arc::new(AtomicUsize::new(0));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let visits = visits.clone();
        move |seam| {
            if seam == "capture_evpn" {
                visits.fetch_add(1, Ordering::SeqCst);
            }
        }
    }));
    assert!(
        manager.with_replacement_readiness(|manager| manager.capture_shared_evpn_admitted(member))
    );
    assert_eq!(
        visits.load(Ordering::SeqCst),
        routes.len() * 3,
        "completeness, filtered cardinality and population each visit every excluded row"
    );
    let handle = manager.evpn_recovery_handle(member).unwrap();
    assert_eq!(
        manager.evpn_recovery.proof_keys(handle).unwrap().unwrap(),
        [] as [rustbgpd_wire::EvpnRouteKey; 0]
    );
}

#[test]
fn evpn_private_capture_preserves_keys_and_checkpoints_projection_and_insertion() {
    let (mut manager, member, _gid, _output) = fixture();
    let routes: Vec<_> = (1..=7)
        .map(|suffix| make_evpn_imet(Ipv4Addr::new(198, 51, 100, suffix), 1))
        .collect();
    for route in &routes {
        manager
            .adj_ribs_out
            .get_mut(&member)
            .unwrap()
            .insert_evpn(route.clone());
    }
    let visits = Arc::new(AtomicUsize::new(0));
    manager.replacement_readiness_test_hook = Some(Arc::new({
        let visits = visits.clone();
        move |seam| {
            if seam == "capture_evpn" {
                visits.fetch_add(1, Ordering::SeqCst);
            }
        }
    }));
    assert!(
        manager.with_replacement_readiness(|manager| manager.capture_private_evpn_admitted(member))
    );
    assert_eq!(
        visits.load(Ordering::SeqCst),
        routes.len() * 2,
        "both the actual-key producer and ledger insertion visit every row"
    );
    let handle = manager.evpn_recovery_handle(member).unwrap();
    let proof: HashSet<_> = manager
        .evpn_recovery
        .proof_keys(handle)
        .unwrap()
        .unwrap()
        .iter()
        .copied()
        .collect();
    assert_eq!(proof, routes.iter().map(EvpnRibRoute::key).collect());
}

#[test]
fn evpn_denial_replacement_checkpoints_retained_and_inserted_rows() {
    let (mut manager, _member, gid, _output) = fixture();
    let routes = install_routes(&mut manager, gid, 3);
    let group = manager.group_ribs.get_mut(&gid).unwrap();
    let old = (
        routes[0].peer,
        None,
        routes[0].extended_communities().to_vec(),
    );
    for route in &routes {
        group.evpn_policy_denied.insert(route.key(), old.clone());
    }
    let new = make_evpn_imet(Ipv4Addr::new(198, 51, 100, 99), 1);
    let replacement = (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77)), None, Vec::new());
    let inserted = (IpAddr::V4(Ipv4Addr::new(192, 0, 2, 88)), None, Vec::new());
    let keys = HashSet::from([routes[0].key(), routes[1].key()]);
    let mut visits = 0;
    group.replace_evpn_denials_with_checkpoint(
        &keys,
        [
            (routes[0].key(), replacement.clone()),
            (new.key(), inserted.clone()),
        ],
        &mut || visits += 1,
    );
    assert_eq!(visits, routes.len() + 2);
    assert_eq!(group.evpn_policy_denied.len(), 3);
    assert_eq!(group.evpn_policy_denied[&routes[0].key()], replacement);
    assert!(!group.evpn_policy_denied.contains_key(&routes[1].key()));
    assert_eq!(group.evpn_policy_denied[&routes[2].key()], old);
    assert_eq!(group.evpn_policy_denied[&new.key()], inserted);
}

#[test]
fn shared_capture_proof_iteration_checkpoints_masked_and_trailing_rows() {
    let (mut manager, member, gid, _output) = fixture();
    let routes = install_routes(&mut manager, gid, 32);
    manager.peer_unexportable.insert(
        member,
        routes[1..]
            .iter()
            .map(|route| ExactExportKey::Evpn(route.key()))
            .collect(),
    );
    assert!(manager.capture_shared_evpn_admitted(member));
    let handle = manager.evpn_recovery_handle(member).unwrap();
    let view = manager.evpn_recovery.proof(handle).unwrap().unwrap();
    let mut visits = 0;
    let keys = view
        .iter_with_checkpoint(|force| {
            assert!(!force);
            visits += 1;
        })
        .collect::<Vec<_>>();
    assert_eq!(keys, [routes[0].key()]);
    assert!(manager.group_ribs[&gid].evpn_recovery_universe.is_some());
    assert_eq!(
        visits,
        routes.len(),
        "all unmarked and trailing universe rows need checkpoints"
    );
}
