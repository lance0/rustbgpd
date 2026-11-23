//! The same single-best exports through cold synchronous and paced registration.
use super::*;
use crate::manager::tests::update_groups::{community_chain, deny_statement};
use rustbgpd_policy::{CHAIN_DEFAULT_PERMIT_ATTRIBUTION, PolicyChain};

const TAG: u32 = 0xfde8_0011;

fn policy(tag: u32) -> PolicyChain {
    let mut terms = community_chain(tag).policies;
    let permit = &mut terms[0];
    permit.name = Some("cold-export".into());
    let mut deny = deny_statement(Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0));
    deny.prefix = None;
    deny.match_local_pref_ge = Some(150);
    permit.policy.entries.insert(0, deny);
    PolicyChain::from_named(terms)
}

fn registration(
    peer: PeerId,
    session: u64,
    tag: u32,
) -> (RibUpdate, mpsc::Receiver<OutboundRouteUpdate>) {
    let (tx, rx) = mpsc::channel(64);
    let mut up = test_peer_up(peer, session, tx);
    let RibUpdate::PeerUp {
        is_ebgp,
        route_reflector_client,
        sendable_families,
        export_policy,
        ..
    } = &mut up
    else {
        unreachable!()
    };
    *is_ebgp = false;
    *route_reflector_client = true;
    *sendable_families = DUAL.to_vec();
    *export_policy = Some(policy(tag));
    (up, rx)
}

fn announce(
    manager: &mut RibManager,
    inventory: &mut Inventory,
    prefix: Prefix,
    source: Ipv4Addr,
    lp: u32,
) {
    manager.handle_update(test_routes_received(
        peer_v4(source),
        vec![route(prefix, source, lp)],
    ));
    drain_route_chunks(manager);
    assert_eq!(manager.loc_rib.get(&prefix).unwrap().peer, peer_v4(source));
    inventory.insert(prefix, (peer_v4(source), lp));
}

fn check_replay(rx: &mut mpsc::Receiver<OutboundRouteUpdate>, expected: &Inventory, tag: u32) {
    let mut seen = Inventory::new();
    let mut ends = HashSet::new();
    while let Ok(update) = rx.try_recv() {
        assert_eq!(update.unicast_withdrawals().count(), 0);
        for row in update.announce.iter() {
            assert!(!ends.contains(&crate::manager::helpers::prefix_family(&row.prefix)));
            assert_eq!(row.path_id, 0);
            assert_eq!(row.communities(), &[tag]);
            assert!(
                seen.insert(row.prefix, (row.peer, row.local_pref()))
                    .is_none()
            );
        }
        for family in update.end_of_rib {
            assert!(ends.insert(family), "duplicate End-of-RIB");
        }
    }
    assert_eq!(ends, DUAL.into_iter().collect());
    assert_eq!(&seen, expected);
}

fn check_installed(
    manager: &RibManager,
    peer: PeerId,
    inventory: &Inventory,
    tag: u32,
) -> Inventory {
    let group = &manager.group_ribs[&manager.grouped_member_of(peer).unwrap()];
    let mut permits = Inventory::new();
    let mut denials = HashSet::new();
    for (&prefix, &(source, lp)) in inventory {
        let input = manager.loc_rib.get(&prefix).expect("input still installed");
        assert_eq!((input.peer, input.local_pref()), (source, lp));
        assert!(input.communities().is_empty(), "export modified its source");
        if lp < 150 {
            permits.insert(prefix, (source, lp));
        } else {
            denials.insert(PolicyFilteredRouteKey {
                target_peer: peer,
                source_peer: source,
                prefix,
                path_id: 0,
            });
        }
    }
    let table = group
        .table
        .iter()
        .map(|row| {
            assert_eq!(row.communities(), &[tag]);
            (row.prefix, (row.peer, row.local_pref()))
        })
        .collect::<Inventory>();
    assert_eq!(table, permits);
    let keys = inventory.keys().copied().collect();
    let residue: HashSet<_> = group
        .policy_filtered_for_member(peer, &keys)
        .into_iter()
        .collect();
    assert_eq!(residue, denials);
    assert_eq!(retained_policy_rejection_keys(manager, peer), denials);
    let mut event_keys = HashSet::new();
    for event in manager.route_event_history.iter().filter(|event| {
        event.event_type == RouteEventType::PolicyFiltered && event.target_peer == Some(peer.addr())
    }) {
        assert_eq!(event.reason, "policy_denied");
        assert!(event_keys.insert(PolicyFilteredRouteKey {
            target_peer: peer,
            source_peer: PeerId::from_addr(event.peer.unwrap()),
            prefix: event.prefix,
            path_id: event.path_id,
        }));
    }
    assert_eq!(event_keys, denials);
    let stats = manager.neighbor_rib_snapshot(peer).policy_stats;
    assert_eq!(stats.export_policy_routes_permitted, permits.len() as u64);
    assert_eq!(stats.export_policy_routes_denied, denials.len() as u64);
    for (label, action, count) in [
        (CHAIN_DEFAULT_PERMIT_ATTRIBUTION, "permit", permits.len()),
        ("cold-export", "deny", denials.len()),
    ] {
        let observed =
            policy_metric_value(&manager.metrics, &peer.label(), label, "export", action);
        let expected = f64::from(u32::try_from(count).unwrap());
        assert!(
            (observed - expected).abs() < f64::EPSILON,
            "{label} {action}: {observed}"
        );
    }
    permits
}

#[test]
fn paced_and_synchronous_policy_builds_preserve_table_denials_and_counters() {
    let founder = receiver(1);
    let second = receiver(2);
    for paced in [false, true] {
        let (mut manager, _tx, mut inventory) = fixture(1200);
        for prefix in prefixes(7) {
            announce(&mut manager, &mut inventory, prefix, OTHER, 180);
        }
        if !paced {
            manager.first_group_build_min_routes = usize::MAX;
        }
        let (up, mut first) = registration(founder, 1, TAG);
        manager.handle_update(up);
        assert_eq!(manager.first_group_build.is_some(), paced);
        if paced {
            staged_keys(&mut manager, &inventory);
            assert!(first.is_empty());
        }
        let (up, mut next) = registration(second, 2, TAG);
        manager.handle_update(up);
        if paced {
            assert!(next.is_empty());
        }
        finish(&mut manager);
        for (peer, rx) in [(founder, &mut first), (second, &mut next)] {
            let permits = check_installed(&manager, peer, &inventory, TAG);
            check_replay(rx, &permits, TAG);
        }
        assert_eq!(
            manager.grouped_member_of(founder),
            manager.grouped_member_of(second)
        );
        for peer in [founder, second] {
            let hits = manager.export_policy_for(peer).unwrap().hit_counters();
            assert_eq!(hits.evals(), inventory.len() as u64);
            assert_eq!(hits.term_hits(0, 0), Some(2));
            assert_eq!(hits.term_hits(0, 1), Some(inventory.len() as u64 - 2));
        }
    }
}

#[test]
fn policy_build_repairs_walked_routes_before_accounting_and_replay() {
    let (mut manager, _tx, mut inventory) = fixture(1200);
    let founder = receiver(1);
    let (up, mut rx) = registration(founder, 1, TAG);
    manager.handle_update(up);
    let walked = staged_keys(&mut manager, &inventory);
    let before = crate::manager::slice_timing::group_work();
    // Repair an undiscovered key first. Later bucket discovery must skip its second evaluation.
    let ahead = *inventory
        .keys()
        .find(|&&prefix| !manager.first_group_contains(prefix))
        .unwrap();
    announce(&mut manager, &mut inventory, ahead, OTHER, 120);
    let mut withdrawal = test_routes_received(peer_v4(SOURCE), vec![]);
    let RibUpdate::RoutesReceived { withdrawn, .. } = &mut withdrawal else {
        unreachable!()
    };
    for [_, denied, reverted] in walked {
        announce(&mut manager, &mut inventory, denied, OTHER, 155);
        announce(&mut manager, &mut inventory, reverted, OTHER, 175);
    }
    manager.advance_first_group_build();
    assert!(manager.first_group_contains(ahead), "pre-discovery repair");
    for [removed, _, reverted] in walked {
        announce(&mut manager, &mut inventory, removed, SOURCE, 140);
        withdrawn.push((removed, 0));
        inventory.remove(&removed).unwrap();
        assert!(
            !manager.first_group_contains(reverted),
            "repair must have removed the permitted row"
        );
        announce(&mut manager, &mut inventory, reverted, OTHER, 125);
    }
    manager.handle_update(withdrawal);
    drain_route_chunks(&mut manager);
    let marker = prefixes(1500)[0];
    announce(&mut manager, &mut inventory, marker, OTHER, 125);
    assert!(manager.first_group_build.is_some() && rx.is_empty());
    // Drive only the private owner. A synchronous fallback would leave the
    // founder queued for a later call to advance_pending_initial_registration.
    for _ in 0..64 {
        if manager.first_group_build.is_none() {
            break;
        }
        manager.advance_first_group_build();
    }
    assert!(manager.first_group_build.is_none() && manager.grouped_member_of(founder).is_some());
    let after = crate::manager::slice_timing::group_work();
    let work = |name| after.get(name).unwrap_or(&0) - before.get(name).unwrap_or(&0);
    assert_eq!(work("first_group_repairs"), 10);
    assert_eq!(work("group_inverse_evals"), 8);
    assert_eq!(work("group_denials_removed"), 2);
    let permitted = check_installed(&manager, founder, &inventory, TAG);
    check_replay(&mut rx, &permitted, TAG);

    // A synchronous join after all edits evaluates each final route once.
    let (mut control, _tx, _) = fixture(0);
    control.first_group_build_min_routes = usize::MAX;
    for source in [SOURCE, OTHER] {
        let rows = inventory
            .iter()
            .filter(|(_, (peer, _))| *peer == peer_v4(source))
            .map(|(&prefix, &(_, lp))| route(prefix, source, lp))
            .collect();
        control.handle_update(test_routes_received(peer_v4(source), rows));
        drain_route_chunks(&mut control);
    }
    let (up, mut control_rx) = registration(founder, 1, TAG);
    control.handle_update(up);
    assert_eq!(
        check_installed(&control, founder, &inventory, TAG),
        permitted
    );
    check_replay(&mut control_rx, &permitted, TAG);
    let paced_hits = manager.export_policy_for(founder).unwrap().hit_counters();
    let sync_hits = control.export_policy_for(founder).unwrap().hit_counters();
    assert_eq!(paced_hits.evals(), sync_hits.evals());
    assert_eq!(paced_hits.snapshot(), sync_hits.snapshot());
}

#[test]
fn policy_change_on_waiting_session_discards_the_previous_policy_output() {
    let (mut manager, _tx, mut inventory) = fixture(1200);
    let peer = receiver(1);
    announce(&mut manager, &mut inventory, prefixes(9)[0], OTHER, 200);
    let (up, mut rx) = registration(peer, 7, TAG);
    manager.handle_update(up);
    staged_keys(&mut manager, &inventory);
    let next_tag = TAG + 1;
    manager.handle_update(RibUpdate::SetPeerSessionExportPolicy {
        peer,
        session_id: 7,
        export_policy: Some(policy(next_tag)),
    });
    finish(&mut manager);
    let permitted = check_installed(&manager, peer, &inventory, next_tag);
    check_replay(&mut rx, &permitted, next_tag);
}

#[test]
fn reconnect_without_orf_or_orr_joins_the_complete_policy_group() {
    for orf in [true, false] {
        let (mut manager, _tx, inventory) = fixture(1200);
        let founder = receiver(1);
        let returning = receiver(2);
        let (mut previous, mut old_rx) = registration(returning, 7, TAG);
        let RibUpdate::PeerUp {
            negotiated_orf_recv,
            orr_vantage,
            ..
        } = &mut previous
        else {
            unreachable!()
        };
        if orf {
            negotiated_orf_recv.push(DUAL[0]);
        } else {
            *orr_vantage = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        manager.handle_update(previous);
        assert!(manager.outbound_peers.contains_key(&returning));
        assert!(manager.grouped_member_of(returning).is_none());
        let (up, mut first) = registration(founder, 1, TAG);
        manager.handle_update(up);
        staged_keys(&mut manager, &inventory);

        if orf {
            // Clearing the list keeps ORF receive negotiated until reconnect.
            for action in [OrfAction::Add, OrfAction::RemoveAll] {
                let (reply, mut result) = oneshot::channel();
                manager.handle_update(RibUpdate::PeerOrfUpdate {
                    peer: returning,
                    session_id: 7,
                    afi: Afi::Ipv4,
                    safi: Safi::Unicast,
                    when: WhenToRefresh::Defer,
                    groups: vec![vec![AddressPrefixOrf {
                        action,
                        match_: OrfMatch::Permit,
                        sequence: 1,
                        min_len: 0,
                        max_len: 32,
                        prefix: (action == OrfAction::Add).then_some(prefixes(7)[0]),
                    }]],
                    reply,
                });
                result.try_recv().unwrap().unwrap();
                assert_eq!(
                    manager.peer_orf_filters.contains_key(&returning),
                    action == OrfAction::Add
                );
                assert!(manager.grouped_member_of(returning).is_none());
            }
        } else {
            assert!(manager.peer_orr_vantage.contains_key(&returning));
        }

        while old_rx.try_recv().is_ok() {}
        let (up, mut current) = registration(returning, 7, TAG);
        manager.handle_update(up);
        assert!(manager.grouped_member_of(returning).is_none() && current.is_empty());
        finish(&mut manager);
        assert_eq!(
            manager.grouped_member_of(returning),
            Some(manager.grouped_member_of(founder).unwrap())
        );
        assert!(!manager.peer_orr_vantage.contains_key(&returning));
        check_replay(&mut current, &inventory, TAG);
        check_replay(&mut first, &inventory, TAG);
        assert!(old_rx.is_empty());
    }
}

#[test]
fn installed_policy_replacement_wins_while_the_founder_retires_its_pages() {
    use crate::loc_rib::REGISTRATION_PAGE_SIZE;
    use crate::manager::slice_timing::take_first_group_retirement_work;

    let (mut manager, _tx, mut inventory) = fixture(2400);
    let incumbent = receiver(1);
    let founder = receiver(2);
    announce(&mut manager, &mut inventory, prefixes(5)[0], OTHER, 180);
    manager.first_group_build_min_routes = usize::MAX;
    let (mut old_up, mut old_rx) = registration(incumbent, 1, TAG + 1);
    let RibUpdate::PeerUp { export_policy, .. } = &mut old_up else {
        unreachable!()
    };
    *export_policy = Some(community_chain(TAG + 1));
    manager.handle_update(old_up);
    check_replay(&mut old_rx, &inventory, TAG + 1);
    let old_gid = manager.grouped_member_of(incumbent).unwrap();

    manager.first_group_build_min_routes = 1;
    let (up, mut current) = registration(founder, 1, TAG);
    manager.handle_update(up);
    for _ in 0..16 {
        manager.advance_first_group_build();
        if inventory
            .keys()
            .filter(|&&p| manager.first_group_contains(p))
            .count()
            > crate::loc_rib::REGISTRATION_PAGE_SIZE
        {
            break;
        }
    }
    assert!(current.is_empty());
    // Leave a full page and one displaced winner for cancellation to retire.
    let changed: Vec<_> = inventory
        .iter_mut()
        .filter(|(_, (source, _))| *source == peer_v4(SOURCE))
        .take(REGISTRATION_PAGE_SIZE + 1)
        .map(|(&key, (_, pref))| {
            *pref = 110;
            route(key, SOURCE, *pref)
        })
        .collect();
    assert_eq!(changed.len(), REGISTRATION_PAGE_SIZE + 1);
    manager.handle_update(test_routes_received(peer_v4(SOURCE), changed));
    drain_route_chunks(&mut manager);
    let (reply, mut result) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPolicy {
        peer: incumbent,
        export_policy: Some(policy(TAG)),
        reply,
    });
    result.try_recv().unwrap().unwrap();
    let winning_gid = manager.grouped_member_of(incumbent).unwrap();
    assert_ne!(old_gid, winning_gid);
    assert!(manager.grouped_member_of(founder).is_none());
    let committed_chain = Arc::clone(manager.export_policy_for(incumbent).unwrap().hit_counters());
    let before = committed_chain.snapshot();

    take_first_group_retirement_work();
    manager.advance_first_group_build();
    assert_eq!(
        take_first_group_retirement_work(),
        [0, 0, REGISTRATION_PAGE_SIZE]
    );
    manager.advance_first_group_build();
    assert_eq!(
        take_first_group_retirement_work(),
        [REGISTRATION_PAGE_SIZE - 1, 0, 1]
    );
    assert!(
        manager
            .first_group_retiring_slots()
            .is_some_and(|slots| slots > 0)
    );
    assert!(current.is_empty());
    finish(&mut manager);
    assert_eq!(manager.grouped_member_of(founder), Some(winning_gid));
    let permits = check_installed(&manager, founder, &inventory, TAG);
    check_replay(&mut current, &permits, TAG);
    let installed = manager.export_policy_for(founder).unwrap().hit_counters();
    assert!(Arc::ptr_eq(installed, &committed_chain));
    assert_eq!(
        installed.snapshot(),
        before,
        "joining the winning table must not evaluate the policy again"
    );
    assert_eq!(installed.evals(), inventory.len() as u64);
}
