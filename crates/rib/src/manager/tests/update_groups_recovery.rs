use std::collections::HashSet;
use std::num::NonZeroU32;

use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

use super::exportability::MockExactExportEncoder;
use super::*;
use crate::update::{ExactExportKey, PeerExportPolicyReplacement};

fn prefix(octet: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32)
}

fn peer_up(
    peer: IpAddr,
    tx: mpsc::Sender<OutboundRouteUpdate>,
    policy: Option<PolicyChain>,
) -> RibUpdate {
    RibUpdate::PeerUp {
        peer,
        session_id: 0,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx: tx,
        export_policy: policy,
        sendable_families: ipv4_sendable(),
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    }
}

fn source_update(manager: &mut RibManager, announce: &[u8], withdraw: &[u8]) {
    let source = Ipv4Addr::new(192, 0, 2, 1);
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source.into(),
        session_id: 0,
        announced: announce
            .iter()
            .map(|octet| make_route(prefix(*octet), source))
            .collect(),
        withdrawn: withdraw
            .iter()
            .map(|octet| (Prefix::V4(prefix(*octet)), 0))
            .collect(),
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    while manager.process_next_route_chunk() {}
}

fn policy(denied: u8, marker: u32) -> PolicyChain {
    let deny = PolicyStatement {
        prefix: Some(Prefix::V4(prefix(denied))),
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
        match_local_pref_ge: None,
        match_local_pref_le: None,
        match_med_ge: None,
        match_med_le: None,
        match_next_hop: None,
        modifications: RouteModifications::default(),
    };
    let permit = PolicyStatement {
        prefix: None,
        action: PolicyAction::Permit,
        modifications: RouteModifications {
            communities_add: vec![marker],
            ..RouteModifications::default()
        },
        ..deny.clone()
    };
    PolicyChain::new(vec![Policy {
        entries: vec![deny, permit],
        default_action: PolicyAction::Deny,
    }])
}

#[test]
fn a_failed_initial_dump_has_no_admitted_withdrawal_duties() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    source_update(&mut manager, &[1], &[]);
    let member: IpAddr = Ipv4Addr::new(10, 220, 2, 1).into();
    let (outbound, mut receiver) = mpsc::channel(1);
    outbound.try_send(OutboundRouteUpdate::default()).unwrap();
    manager.handle_update(peer_up(member, outbound, None));
    assert!(manager.dirty_peers.contains(&member));
    assert!(manager.pending_group_admitted[&member].is_empty());
    source_update(&mut manager, &[], &[1]);
    receiver.try_recv().unwrap();
    while manager.resync_dirty_peers_bounded() {}
    let eor = receiver.try_recv().unwrap();
    assert!(eor.announce.is_empty());
    assert!(
        eor.withdraw.is_empty(),
        "the initial route was never admitted"
    );
    assert_eq!(eor.end_of_rib, ipv4_sendable());
    assert!(!manager.dirty_peers.contains(&member));
    assert!(!manager.pending_group_admitted.contains_key(&member));
}

#[test]
fn a_clean_regroup_never_seeds_a_prefix_blocked_by_the_member_limit() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let member: IpAddr = Ipv4Addr::new(10, 220, 2, 1).into();
    let (outbound, mut receiver) = mpsc::channel(16);
    manager.handle_update(peer_up(member, outbound, None));
    receiver.try_recv().unwrap();
    manager
        .outbound_prefix_limits
        .entry(member)
        .or_default()
        .family_mut(Afi::Ipv4)
        .unwrap()
        .limit = NonZeroU32::new(1);
    source_update(&mut manager, &[1, 2], &[]);
    let update = receiver.try_recv().unwrap();
    assert_eq!(update.announce.len(), 1);
    let admitted = update.announce[0].prefix;
    assert_eq!(
        manager.group_ribs[&manager.grouped_member_of(member).unwrap()]
            .table
            .len(),
        2
    );
    manager.test_force_ungrouped = true;
    manager.recompute_update_group(member);
    let private = &manager.adj_ribs_out[&member];
    assert_eq!(
        private.len(),
        1,
        "the blocked shared row was never advertised"
    );
    assert!(private.get(&admitted, 0).is_some());
}

#[test]
fn a_batched_refusal_retains_source_keys_for_targeted_recovery() {
    for probe_refusal in [false, true] {
        let (_tx, rx) = mpsc::channel(1);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        let member: IpAddr = Ipv4Addr::new(10, 220, 2, 1).into();
        let (outbound, mut receiver) = mpsc::channel(if probe_refusal { 16 } else { 1 });
        manager.handle_update(peer_up(member, outbound, Some(policy(3, 1))));
        receiver.try_recv().unwrap();
        let encoder = MockExactExportEncoder::accepting(1);
        manager.peer_export_encoders.insert(member, encoder.clone());
        source_update(&mut manager, &[1, 2, 3], &[]);
        let initial = receiver.try_recv().unwrap();
        let mut admitted: HashSet<_> = initial
            .announce
            .iter()
            .map(|route| (route.prefix, route.path_id))
            .collect();
        assert_eq!(
            admitted,
            HashSet::from([(Prefix::V4(prefix(1)), 0), (Prefix::V4(prefix(2)), 0)])
        );
        if probe_refusal {
            encoder.set_profile(2, [ExactExportKey::Unicast(Prefix::V4(prefix(3)), 0)]);
        }
        let source_group = manager.grouped_member_of(member).unwrap();
        let (reply, mut response) = oneshot::channel();
        manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
            replacements: vec![PeerExportPolicyReplacement {
                peer: member,
                export_policy: Some(policy(1, 2)),
            }],
            reply,
        });
        assert_eq!(response.try_recv().unwrap(), Ok(()));
        assert_ne!(manager.grouped_member_of(member), Some(source_group));
        assert_eq!(
            manager
                .policy_transition_stats
                .batched_authoritative_shared_members,
            1
        );
        assert_eq!(
            manager
                .policy_transition_stats
                .batched_authoritative_fallback_members,
            0
        );
        while manager.resync_dirty_peers_bounded() {}
        while let Ok(update) = receiver.try_recv() {
            for key in update.withdraw {
                assert!(
                    admitted.remove(&key),
                    "withdrawal lacks admitted source proof"
                );
            }
            for route in update.announce.iter() {
                if update.announce_source_exclusion != Some(route.peer) {
                    admitted.insert((route.prefix, route.path_id));
                }
            }
        }
        let expected = if probe_refusal {
            HashSet::from([(Prefix::V4(prefix(2)), 0)])
        } else {
            HashSet::from([(Prefix::V4(prefix(2)), 0), (Prefix::V4(prefix(3)), 0)])
        };
        assert_eq!(
            admitted, expected,
            "old policy keys must not leak after refusal"
        );
        assert!(!manager.dirty_peers.contains(&member));
        assert!(!manager.pending_group_admitted.contains_key(&member));
    }
}

fn rejected_prior_slot_is_withdrawn(lane_only: bool) {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let source_a = Ipv4Addr::new(10, 220, 2, 1);
    let source_b = Ipv4Addr::new(10, 220, 2, 2);
    let source_c = Ipv4Addr::new(10, 220, 2, 3);
    let member: IpAddr = source_a.into();
    let (outbound, mut receiver) = mpsc::channel(16);
    let mut registration = peer_up(member, outbound, None);
    if let RibUpdate::PeerUp {
        per_client_best,
        is_ebgp,
        ..
    } = &mut registration
    {
        *per_client_best = true;
        *is_ebgp = true;
    }
    manager.handle_update(registration);
    receiver.try_recv().unwrap();
    let encoder = MockExactExportEncoder::accepting(1);
    manager.peer_export_encoders.insert(member, encoder.clone());
    let inject = |manager: &mut RibManager, source, preference| {
        manager.handle_update(RibUpdate::RoutesReceived {
            peer: IpAddr::V4(source),
            session_id: 0,
            announced: vec![make_route_with_lp(prefix(1), source, preference)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        while manager.process_next_route_chunk() {}
    };
    inject(&mut manager, source_b, 100);
    let first = receiver.try_recv().unwrap();
    assert_eq!(first.announce.len(), 1);
    assert_eq!(first.announce[0].peer, IpAddr::V4(source_b));
    inject(&mut manager, source_a, 300);
    while let Ok(update) = receiver.try_recv() {
        assert_eq!(update.withdraw, Vec::<(Prefix, u32)>::new());
        assert!(
            update
                .announce
                .iter()
                .all(|route| update.announce_source_exclusion == Some(route.peer)
                    || route.peer == IpAddr::V4(source_b))
        );
    }
    assert!(manager.grouped_member_of(member).is_some());
    encoder.set_profile(2, [ExactExportKey::Unicast(Prefix::V4(prefix(1)), 0)]);
    if lane_only {
        inject(&mut manager, source_b, 200);
    } else {
        inject(&mut manager, source_c, 400);
    }
    let mut withdrawals = Vec::new();
    while let Ok(update) = receiver.try_recv() {
        withdrawals.extend(update.withdraw);
        assert!(
            update
                .announce
                .iter()
                .all(|route| update.announce_source_exclusion == Some(route.peer))
        );
    }
    assert_eq!(
        withdrawals,
        vec![(Prefix::V4(prefix(1)), 0)],
        "an exact rejection must remove the previously admitted runner-up"
    );
}

#[test]
fn clean_pcb_source_promotion_rejection_withdraws_the_old_lane_slot() {
    rejected_prior_slot_is_withdrawn(false);
}

#[test]
fn clean_pcb_lane_only_rejection_withdraws_the_old_lane_slot() {
    rejected_prior_slot_is_withdrawn(true);
}

#[test]
fn deleting_a_clean_otc_blocked_key_emits_no_unknown_withdrawal() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let member: IpAddr = Ipv4Addr::new(10, 220, 2, 1).into();
    manager.handle_update(RibUpdate::SetPeerExportContext {
        peer: member,
        session_id: 0,
        local_role: Some(rustbgpd_wire::BgpRole::Customer),
    });
    let (outbound, mut receiver) = mpsc::channel(16);
    let mut registration = peer_up(member, outbound, None);
    if let RibUpdate::PeerUp {
        per_client_best,
        is_ebgp,
        ..
    } = &mut registration
    {
        *per_client_best = true;
        *is_ebgp = true;
    }
    manager.handle_update(registration);
    receiver.try_recv().unwrap();
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let mut route = make_route(prefix(1), source);
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.push(PathAttribute::OnlyToCustomer(64_496));
    });
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source.into(),
        session_id: 0,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    });
    while manager.process_next_route_chunk() {}
    while let Ok(update) = receiver.try_recv() {
        assert!(update.announce.is_empty());
        assert_eq!(update.withdraw, Vec::<(Prefix, u32)>::new());
    }
    assert_eq!(
        manager.group_ribs[&manager.grouped_member_of(member).unwrap()]
            .table
            .len(),
        1
    );
    source_update(&mut manager, &[], &[1]);
    while let Ok(update) = receiver.try_recv() {
        assert!(update.announce.is_empty());
        assert!(
            update.withdraw.is_empty(),
            "the staged OTC route was never admitted"
        );
    }
}

#[test]
fn a_same_session_table_replay_rejection_withdraws_the_actual_prior() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let member: IpAddr = Ipv4Addr::new(10, 220, 2, 1).into();
    let (outbound, mut receiver) = mpsc::channel(16);
    manager.handle_update(peer_up(member, outbound, None));
    receiver.try_recv().unwrap();
    let encoder = MockExactExportEncoder::accepting(1);
    manager.peer_export_encoders.insert(member, encoder.clone());
    source_update(&mut manager, &[1], &[]);
    assert_eq!(receiver.try_recv().unwrap().announce.len(), 1);
    encoder.set_profile(2, [ExactExportKey::Unicast(Prefix::V4(prefix(1)), 0)]);
    manager.send_initial_table(member);
    let mut withdrawals = Vec::new();
    while let Ok(update) = receiver.try_recv() {
        withdrawals.extend(update.withdraw);
        assert!(update.announce.is_empty());
    }
    assert_eq!(withdrawals, vec![(Prefix::V4(prefix(1)), 0)]);
    assert!(!manager.pending_group_admitted.contains_key(&member));
}
