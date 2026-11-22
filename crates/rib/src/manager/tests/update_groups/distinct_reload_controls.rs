use super::*;
use crate::manager::{distinct_reload_visits, reset_distinct_reload_visits};
use rustbgpd_policy::NextHopAction;

fn fixture_prefix(index: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 51, index, 0), 24)
}

fn replace(manager: &mut RibManager, peer: PeerId, policy: &PolicyChain) {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: batch_replacements(&[peer], policy),
        reply,
    });
    assert_eq!(response.try_recv().unwrap().unwrap(), Vec::<PeerId>::new());
    assert_eq!(
        manager
            .authoritative_transition_receipts
            .last()
            .unwrap()
            .shared_members,
        1
    );
}

fn assert_delta(
    receiver: &mut mpsc::Receiver<OutboundRouteUpdate>,
    announced: &[(Prefix, u32)],
    withdrawn: &[(Prefix, u32)],
) {
    let mut announcements = Vec::new();
    let mut withdrawals = Vec::new();
    while let Ok(update) = receiver.try_recv().map(delivered) {
        announcements.extend(
            update
                .announce
                .iter()
                .map(|route| (route.prefix, route.path_id)),
        );
        withdrawals.extend(update.unicast_withdrawals().copied());
    }
    assert_eq!(announcements, announced);
    assert_eq!(withdrawals, withdrawn);
}

fn denial_events(manager: &RibManager, peer: PeerId, prefix: Prefix) -> usize {
    manager
        .route_event_history
        .iter()
        .filter(|event| {
            event.event_type == RouteEventType::PolicyFiltered
                && event.target_peer == Some(peer.addr())
                && event.prefix == prefix
                && event.path_id == 0
        })
        .count()
}

#[test]
fn distinct_reload_restamps_new_and_retained_denials_and_withdraws_nothing_for_superset() {
    let permit = mods_chain(RouteModifications::default());
    let deny = deny_chain(fixture_prefix(0));
    let prefix = Prefix::V4(fixture_prefix(0));
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager_with_policy(&permit, 1, 2, None);
    let peer = peers[0];
    assert!(!manager.policy_filtered_routes.contains_key(&peer));
    reset_distinct_reload_visits();
    replace(&mut manager, peer, &deny);
    assert_delta(&mut receivers[0], &[], &[(prefix, 0)]);
    assert!(manager.policy_filtered_routes[&peer].contains_key(&prefix));
    assert_eq!(denial_events(&manager, peer, prefix), 1);
    assert_eq!(distinct_reload_visits(), (2, 1, 2));

    // Only the member's prior denial requires the scope now. Both old and new
    // offered routes are identical on the intersection, so only the added key is sent.
    reset_distinct_reload_visits();
    replace(&mut manager, peer, &permit);
    assert_delta(&mut receivers[0], &[(prefix, 0)], &[]);
    assert!(!manager.policy_filtered_routes.contains_key(&peer));
    assert_eq!(denial_events(&manager, peer, prefix), 1);
    assert_eq!(distinct_reload_visits(), (2, 2, 0));

    replace(&mut manager, peer, &deny);
    assert_delta(&mut receivers[0], &[], &[(prefix, 0)]);
    assert!(manager.policy_filtered_routes[&peer].contains_key(&prefix));
    assert_eq!(denial_events(&manager, peer, prefix), 2);
}

#[test]
fn distinct_reload_equal_cardinality_replacement_announces_and_withdraws() {
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager_with_policy(&deny_chain(fixture_prefix(0)), 1, 2, None);
    reset_distinct_reload_visits();
    replace(&mut manager, peers[0], &deny_chain(fixture_prefix(1)));
    assert_delta(
        &mut receivers[0],
        &[(Prefix::V4(fixture_prefix(0)), 0)],
        &[(Prefix::V4(fixture_prefix(1)), 0)],
    );
    assert_eq!(distinct_reload_visits(), (2, 1, 1));
}

#[test]
fn distinct_reload_full_writer_skips_denial_scope_and_heals_the_withdrawal() {
    let permit = mods_chain(RouteModifications::default());
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager_with_policy(&permit, 1, 2, None);
    let peer = peers[0];
    let sender = manager.outbound_peers[&peer].clone();
    while sender.try_send(OutboundRouteUpdate::default()).is_ok() {}
    reset_distinct_reload_visits();
    replace(&mut manager, peer, &deny_chain(fixture_prefix(0)));
    assert_eq!(distinct_reload_visits(), (0, 0, 2));
    assert!(manager.dirty_peers.contains(&peer));
    assert_delta(&mut receivers[0], &[], &[]);

    drain_resync_ticks(&mut manager);
    assert!(!manager.dirty_peers.contains(&peer));
    let denied = Prefix::V4(fixture_prefix(0));
    let retained = Prefix::V4(fixture_prefix(1));
    let mut withdrawals = Vec::new();
    while let Ok(update) = receivers[0].try_recv().map(delivered) {
        assert!(update.announce.iter().all(|route| route.prefix == retained));
        withdrawals.extend(update.unicast_withdrawals().copied());
    }
    assert_eq!(withdrawals, [(denied, 0)]);
    assert!(manager.policy_filtered_routes[&peer].contains_key(&denied));
}

#[test]
fn distinct_reload_next_hop_only_change_uses_paced_replacement() {
    let community = 0xFDE8_7101;
    let old = community_chain(community);
    let new = community_chain_with(community, |mods| {
        mods.set_next_hop = Some(NextHopAction::Self_);
    });
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager_with_policy(&old, 1, 1, None);
    reset_distinct_reload_visits();
    assert_eq!(apply_paced_batch(&mut manager, &peers, &new), peers);
    assert_eq!(distinct_reload_visits(), (0, 0, 0));
    let update = receivers[0].try_recv().map(delivered).unwrap();
    assert_eq!(update.announce.len(), 1);
    assert_eq!(update.announce[0].prefix, Prefix::V4(fixture_prefix(0)));
    assert_eq!(*update.next_hop_override, [Some(NextHopAction::Self_)]);
    assert_eq!(update.unicast_withdrawals().count(), 0);
    assert!(receivers[0].try_recv().is_err());
}

#[test]
fn distinct_reload_restores_shared_wire_state_after_a_later_replacement_fails() {
    let old = community_chain(0xFDE8_7101);
    let new = community_chain(0xFDE8_7102);
    let (mut manager, peers, mut receivers) =
        direct_clean_transition_manager_with_policy(&old, 2, 1, None);
    let peer = peers[0];
    let prefix = Prefix::V4(fixture_prefix(0));
    let old_gid = manager.grouped_member_of(peer).unwrap();
    let old_route = manager.group_ribs[&old_gid]
        .table
        .get(&prefix, 0)
        .unwrap()
        .clone();
    reset_distinct_reload_visits();
    replace(&mut manager, peer, &new);
    assert_eq!(distinct_reload_visits(), (0, 0, 0));
    let forward = receivers[0].try_recv().map(delivered).unwrap();
    assert_eq!(forward.announce.len(), 1);
    assert_eq!(forward.announce[0].prefix, prefix);
    assert_eq!(forward.announce[0].communities(), [0xFDE8_7102]);
    assert_eq!(forward.unicast_withdrawals().count(), 0);
    assert!(receivers[0].try_recv().is_err());

    // Exercise the RIB's actual refusal for an overlapping transition on the next unit.
    manager.pending_clean_policy_transition = Some(
        crate::manager::distribution::PendingCleanPolicyTransition::new(
            batch_replacements(&peers[1..], &new),
            None,
        ),
    );
    let (reply, mut rejected) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: batch_replacements(&peers[1..], &new),
        reply,
    });
    assert!(rejected.try_recv().unwrap().is_err());
    manager.pending_clean_policy_transition = None;

    reset_distinct_reload_visits();
    let (reply, mut restored) = oneshot::channel();
    manager.handle_update(RibUpdate::RestorePeerExportPoliciesAuthoritatively {
        replacements: batch_replacements(&[peer], &old),
        reply,
    });
    assert_eq!(
        restored.try_recv().unwrap().unwrap(),
        [crate::update::PeerExportPolicyRestoreReceipt::Restored { peer }]
    );
    assert_eq!(distinct_reload_visits(), (0, 0, 0));
    let undo = receivers[0].try_recv().map(delivered).unwrap();
    assert_eq!(undo.announce.len(), 1);
    let route = &undo.announce[0];
    assert_eq!(
        (
            route.prefix,
            route.path_id,
            route.next_hop,
            route.link_local_next_hop,
            &route.next_hop_scope,
            route.peer,
            &route.attributes
        ),
        (
            old_route.prefix,
            old_route.path_id,
            old_route.next_hop,
            old_route.link_local_next_hop,
            &old_route.next_hop_scope,
            old_route.peer,
            &old_route.attributes
        )
    );
    assert_eq!(undo.unicast_withdrawals().count(), 0);
    assert_eq!(*undo.next_hop_override, [None]);
    assert_eq!(manager.grouped_member_of(peer), Some(old_gid));
    assert_eq!(manager.export_chains.get(&peer), Some(&Some(old)));
    assert!(receivers.iter_mut().all(|rx| rx.try_recv().is_err()));
}
