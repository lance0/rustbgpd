use std::collections::HashSet;
use std::num::NonZeroU32;

use rustbgpd_policy::{Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications};

use super::exportability::MockExactExportEncoder;
use super::*;
use crate::update::{ExactExportKey, PeerExportPolicyReplacement};

fn prefix(octet: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, octet), 32)
}

pub(super) fn peer_up(
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

#[test]
fn non_full_encoder_refusal_retains_the_owed_withdrawal_for_recovery() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    source_update(&mut manager, &[1], &[]);
    let member: IpAddr = Ipv4Addr::new(10, 220, 4, 1).into();
    let (outbound, mut receiver) = mpsc::channel(16);
    manager.handle_update(peer_up(member, outbound, None));
    let initial = receiver.try_recv().unwrap();
    assert_eq!(initial.announce.len(), 1);
    assert_eq!(initial.announce[0].prefix, Prefix::V4(prefix(1)));
    while receiver.try_recv().is_ok() {}
    assert!(!manager.outbound_channel_full(member));
    let encoder = manager.peer_export_encoders.remove(&member).unwrap();
    source_update(&mut manager, &[], &[1]);
    assert!(manager.dirty_peers.contains(&member));
    assert!(manager.pending_group_admitted.get(&member).is_none());
    assert_eq!(
        manager.group_recovery_fallback(member),
        Some(crate::manager::update_groups::RecoveryFallbackCause::MissingProof)
    );
    assert!(!manager.outbound_channel_full(member));
    assert!(receiver.try_recv().is_err());
    manager.peer_export_encoders.insert(member, encoder);
    while manager.resync_dirty_peers_bounded() {}
    let recovered = receiver.try_recv().unwrap();
    assert_eq!(recovered.withdraw, vec![(Prefix::V4(prefix(1)), 0)]);
    assert!(!manager.dirty_peers.contains(&member));
    assert_eq!(manager.group_recovery_fallback(member), None);
}

#[test]
fn missing_completed_proof_resync_counts_fallback_and_keeps_the_owed_withdrawal() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    source_update(&mut manager, &[1], &[]);
    let member: IpAddr = Ipv4Addr::new(10, 220, 4, 6).into();
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
    let key = (Prefix::V4(prefix(1)), 0);
    let delivered = receiver.try_recv().unwrap();
    assert_eq!(delivered.announce.len(), 1);
    assert_eq!(
        (delivered.announce[0].prefix, delivered.announce[0].path_id),
        key
    );
    while receiver.try_recv().is_ok() {}
    assert!(manager.mark_outbound_dirty(member));
    assert!(
        manager
            .pending_group_admitted
            .get(&member)
            .unwrap()
            .contains(&ExactExportKey::Unicast(key.0, key.1))
    );

    // Stage the real withdrawal without emitting; then lose only its proof.
    let source: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
    assert!(
        manager
            .ribs
            .get_mut(&source)
            .unwrap()
            .withdraw(&key.0, key.1)
    );
    let affected = HashSet::from([key.0]);
    let changed = manager.recompute_best(&affected);
    let gid = manager.grouped_member_of(member).unwrap();
    let stage = manager.stage_update_groups(
        &changed,
        &affected,
        &mut crate::manager::distribution::ExportMemo::default(),
        None,
    );
    assert!(
        stage[&gid]
            .deltas
            .iter()
            .any(|delta| delta.prefix == key.0 && delta.new.is_none())
    );
    assert!(manager.group_ribs[&gid].tombstones.contains(&key));
    assert!(manager.pending_group_admitted.remove(&member));
    assert!(manager.pending_group_admitted.get(&member).is_none());
    assert_eq!(manager.group_recovery_fallback(member), None);
    assert_eq!(fallback_count(&manager, "missing_proof"), 0.0);
    assert!(!manager.outbound_channel_full(member));
    assert!(receiver.try_recv().is_err());

    while manager.resync_dirty_peers_bounded() {}
    let recovered = receiver.try_recv().unwrap();
    assert_eq!(recovered.withdraw, vec![key]);
    assert_eq!(fallback_count(&manager, "missing_proof"), 1.0);
    assert!(!manager.dirty_peers.contains(&member));
    assert_eq!(manager.group_recovery_fallback(member), None);
    assert!(manager.outbound_peers.contains_key(&member));
    assert!(receiver.try_recv().is_err());
}

fn fallback_count(manager: &RibManager, cause: &str) -> f64 {
    manager
        .metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_update_group_recovery_fallback_total")
        .unwrap()
        .get_metric()
        .iter()
        .find(|metric| {
            metric
                .get_label()
                .iter()
                .any(|label| label.name() == "cause" && label.value() == cause)
        })
        .unwrap()
        .get_counter()
        .get_value()
}

fn gauge(manager: &RibManager, name: &str) -> f64 {
    manager
        .metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == name)
        .unwrap()
        .get_metric()[0]
        .get_gauge()
        .get_value()
}

/// The exported caps are the ledger's compiled-in limits, one per scope.
#[test]
fn recovery_limit_gauges_export_the_fixed_caps() {
    use crate::manager::update_groups::admitted_recovery::{DAEMON_LIMIT_BYTES, PEER_LIMIT_BYTES};
    let (_tx, rx) = mpsc::channel(1);
    let manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    for (scope, limit) in [("peer", PEER_LIMIT_BYTES), ("daemon", DAEMON_LIMIT_BYTES)] {
        assert_eq!(
            gauge_metric_value(
                &manager.metrics,
                "bgp_update_group_recovery_limit_bytes",
                &[("scope", scope)],
            ),
            f64::from(u32::try_from(limit).unwrap()),
            "{scope}"
        );
    }
}

#[test]
fn common_recovery_charge_is_truthful_at_startup_capture_and_release() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let header = f64::from(u32::try_from(manager.pending_group_admitted.bytes()).unwrap());
    assert!(header > 0.0);
    assert_eq!(gauge(&manager, "bgp_update_group_recovery_entries"), 0.0);
    assert_eq!(gauge(&manager, "bgp_update_group_recovery_bytes"), header);
    assert_eq!(
        gauge(&manager, "bgp_update_group_recovery_peak_bytes"),
        header
    );
    source_update(&mut manager, &[1, 2], &[]);
    let member: IpAddr = Ipv4Addr::new(10, 220, 4, 2).into();
    let (outbound, mut receiver) = mpsc::channel(16);
    manager.handle_update(peer_up(member, outbound, None));
    while receiver.try_recv().is_ok() {}
    manager.mark_outbound_dirty(member);
    assert_eq!(gauge(&manager, "bgp_update_group_recovery_entries"), 2.0);
    assert_eq!(
        gauge(&manager, "bgp_update_group_recovery_bytes"),
        f64::from(u32::try_from(manager.pending_group_admitted.bytes()).unwrap())
    );
    assert!(gauge(&manager, "bgp_update_group_recovery_bytes") > header);
    while manager.resync_dirty_peers_bounded() {}
    assert!(receiver.try_recv().is_ok());
    assert_eq!(gauge(&manager, "bgp_update_group_recovery_entries"), 0.0);
    assert_eq!(gauge(&manager, "bgp_update_group_recovery_bytes"), header);
    assert!(gauge(&manager, "bgp_update_group_recovery_peak_bytes") > header);
}

#[test]
fn proof_refused_initial_dump_settles_without_a_second_replay() {
    use crate::manager::update_groups::admitted_recovery::AdmittedRecovery;

    for refuse_seed in [true, false] {
        let (_tx, rx) = mpsc::channel(1);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        let prefixes = if refuse_seed {
            vec![1, 2]
        } else {
            (1..=128).collect()
        };
        source_update(&mut manager, &prefixes, &[]);
        let member: IpAddr = Ipv4Addr::new(10, 220, 4, 10).into();
        manager.pending_group_admitted = AdmittedRecovery::with_test_limits(
            if refuse_seed { 0 } else { 1024 },
            512 * 1024 * 1024,
        );
        let healthy_bytes = manager.pending_group_admitted.bytes();
        if !refuse_seed {
            // The fresh session has admitted nothing. The seed fits while
            // its full announcement exceeds the same peer budget.
            manager
                .pending_group_admitted
                .insert_empty_with_checkpoint(member, &mut |_| {})
                .unwrap();
        }
        let (outbound, mut receiver) = mpsc::channel(16);
        manager.handle_update(peer_up(member, outbound, None));
        let gid = manager.grouped_member_of(member).unwrap();

        let initial = receiver.try_recv().unwrap();
        assert_eq!(initial.announce.len(), prefixes.len());
        assert!(initial.withdraw.is_empty() && initial.end_of_rib.is_empty());
        let eor = receiver.try_recv().unwrap();
        assert!(eor.announce.is_empty() && eor.withdraw.is_empty());
        assert_eq!(eor.end_of_rib, ipv4_sendable());
        assert_eq!(fallback_count(&manager, "peer_limit"), 1.0);
        assert!(!manager.dirty_peers.contains(&member));
        assert!(!manager.group_ribs[&gid].dirty_members.contains(&member));
        assert!(!manager.pending_group_admitted.contains_record(member));
        assert_eq!(manager.group_recovery_fallback(member), None);
        assert_eq!(manager.pending_group_admitted.bytes(), healthy_bytes);
        assert!(!manager.resync_dirty_peers_bounded());
        assert!(
            receiver.try_recv().is_err(),
            "the completed dump must not replay"
        );
    }
}

#[test]
fn proof_refused_refresh_settles_only_its_own_recovery_state() {
    use crate::manager::route_refresh::{FamilyReplayKind, FamilyReplayOutcome};
    use crate::manager::update_groups::admitted_recovery::AdmittedRecovery;
    use rustbgpd_wire::RouteRefreshSubtype;

    for already_dirty in [false, true] {
        let (_tx, rx) = mpsc::channel(1);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        source_update(&mut manager, &[1, 2], &[]);
        let member: IpAddr = Ipv4Addr::new(10, 220, 4, 11).into();
        let (outbound, mut receiver) = mpsc::channel(16);
        let mut registration = peer_up(member, outbound, None);
        if let RibUpdate::PeerUp {
            sendable_families, ..
        } = &mut registration
        {
            sendable_families.push((Afi::Ipv6, Safi::Unicast));
        }
        manager.handle_update(registration);
        assert_eq!(receiver.try_recv().unwrap().announce.len(), 2);
        assert_eq!(receiver.try_recv().unwrap().end_of_rib.len(), 2);
        let gid = manager.grouped_member_of(member).unwrap();
        manager.pending_group_admitted = AdmittedRecovery::with_test_limits(0, 512 * 1024 * 1024);
        let healthy_bytes = manager.pending_group_admitted.bytes();
        if already_dirty {
            assert!(manager.mark_outbound_dirty(member));
            manager
                .pending_eor
                .entry(member)
                .or_default()
                .insert((Afi::Ipv6, Safi::Unicast));
        }
        let encoder = MockExactExportEncoder::accepting(1);
        encoder.set_profile(2, [ExactExportKey::Unicast(Prefix::V4(prefix(1)), 0)]);
        manager.peer_export_encoders.insert(member, encoder);
        assert_eq!(
            manager.send_route_refresh_response_inner(
                member,
                Afi::Ipv4,
                Safi::Unicast,
                FamilyReplayKind::PeerRefresh {
                    suppress_eor: false
                },
            ),
            FamilyReplayOutcome::Committed
        );
        let response = receiver.try_recv().unwrap();
        assert_eq!(response.announce.len(), 1);
        assert_eq!(response.announce[0].prefix, Prefix::V4(prefix(2)));
        assert_eq!(response.withdraw, vec![(Prefix::V4(prefix(1)), 0)]);
        assert_eq!(response.end_of_rib, ipv4_sendable());
        assert_eq!(
            response.refresh_markers,
            vec![
                (Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::BoRR),
                (Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::EoRR),
            ]
        );
        assert_eq!(fallback_count(&manager, "peer_limit"), 1.0);
        if already_dirty {
            assert!(manager.dirty_peers.contains(&member));
            assert!(manager.group_ribs[&gid].dirty_members.contains(&member));
            assert!(manager.group_recovery_fallback(member).is_some());
            assert!(manager.pending_eor[&member].contains(&(Afi::Ipv6, Safi::Unicast)));
        } else {
            assert!(!manager.dirty_peers.contains(&member));
            assert!(!manager.group_ribs[&gid].dirty_members.contains(&member));
            assert!(!manager.pending_group_admitted.contains_record(member));
            assert_eq!(manager.group_recovery_fallback(member), None);
            assert_eq!(manager.pending_group_admitted.bytes(), healthy_bytes);
            assert!(!manager.resync_dirty_peers_bounded());
        }
        assert!(
            receiver.try_recv().is_err(),
            "the refresh must enqueue once"
        );
    }
}

#[test]
fn proof_refused_initial_dump_still_retries_a_failed_eor() {
    use crate::manager::update_groups::admitted_recovery::AdmittedRecovery;

    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    source_update(&mut manager, &[1, 2], &[]);
    let member: IpAddr = Ipv4Addr::new(10, 220, 4, 12).into();
    manager.pending_group_admitted = AdmittedRecovery::with_test_limits(0, 512 * 1024 * 1024);
    let (outbound, mut receiver) = mpsc::channel(1);
    manager.handle_update(peer_up(member, outbound, None));
    assert_eq!(receiver.try_recv().unwrap().announce.len(), 2);
    assert!(manager.dirty_peers.contains(&member));
    assert!(manager.pending_eor[&member].contains(&(Afi::Ipv4, Safi::Unicast)));
    let mut delivered_eor = Vec::new();
    for _ in 0..4 {
        manager.resync_dirty_peers_bounded();
        while let Ok(update) = receiver.try_recv() {
            delivered_eor.extend(update.end_of_rib);
        }
        if !manager.dirty_peers.contains(&member) {
            break;
        }
    }
    assert_eq!(delivered_eor, ipv4_sendable());
    assert!(!manager.dirty_peers.contains(&member));
    assert!(!manager.pending_eor.contains_key(&member));
    assert_eq!(manager.group_recovery_fallback(member), None);
}

#[test]
fn common_recovery_cap_refusal_keeps_owed_withdrawals_without_reset() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    source_update(&mut manager, &[1, 2], &[]);
    let member: IpAddr = Ipv4Addr::new(10, 220, 4, 3).into();
    let (outbound, mut receiver) = mpsc::channel(16);
    manager.handle_update(peer_up(member, outbound, None));
    while receiver.try_recv().is_ok() {}
    manager.pending_group_admitted =
        crate::manager::update_groups::admitted_recovery::AdmittedRecovery::with_test_limits(
            0,
            512 * 1024 * 1024,
        );
    manager.mark_outbound_dirty(member);
    assert!(manager.pending_group_admitted.get(&member).is_none());
    assert_eq!(
        manager.group_recovery_fallback(member),
        Some(crate::manager::update_groups::RecoveryFallbackCause::PeerLimit)
    );
    source_update(&mut manager, &[], &[1]);
    while manager.resync_dirty_peers_bounded() {}
    let recovered = receiver.try_recv().unwrap();
    assert!(recovered.withdraw.contains(&(Prefix::V4(prefix(1)), 0)));
    assert!(manager.outbound_peers.contains_key(&member));
    assert!(!manager.dirty_peers.contains(&member));
    assert_eq!(manager.group_recovery_fallback(member), None);
}

#[test]
fn common_recovery_fallback_does_not_invent_private_flowspec_delivery() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    source_update(&mut manager, &[1], &[]);
    let member: IpAddr = Ipv4Addr::new(10, 220, 4, 5).into();
    let (outbound, mut receiver) = mpsc::channel(16);
    let mut registration = peer_up(member, outbound, None);
    if let RibUpdate::PeerUp {
        sendable_families, ..
    } = &mut registration
    {
        sendable_families.push((Afi::Ipv4, Safi::FlowSpec));
    }
    manager.handle_update(registration);
    while receiver.try_recv().is_ok() {}
    manager.pending_group_admitted =
        crate::manager::update_groups::admitted_recovery::AdmittedRecovery::with_test_limits(
            0,
            512 * 1024 * 1024,
        );
    manager.mark_outbound_dirty(member);
    assert_eq!(
        manager.group_recovery_fallback(member),
        Some(crate::manager::update_groups::RecoveryFallbackCause::PeerLimit)
    );

    let flowspec = make_flowspec_route(Ipv4Addr::new(192, 0, 2, 1));
    let key = ExactExportKey::FlowSpec(flowspec.selection_key());
    let encoder = MockExactExportEncoder::accepting(1);
    encoder.set_profile(1, [key.clone()]);
    manager.peer_export_encoders.insert(member, encoder);
    assert!(
        manager
            .try_send_and_commit_outbound_update(
                member,
                crate::manager::distribution::OutboundCommitBatch {
                    flowspec_announce: vec![flowspec],
                    ..crate::manager::distribution::OutboundCommitBatch::with_unicast(
                        vec![make_route(prefix(1), Ipv4Addr::new(192, 0, 2, 1))].into(),
                        vec![None].into(),
                    )
                },
            )
            .is_ok()
    );
    let update = receiver.try_recv().unwrap();
    assert_eq!(update.announce.len(), 1);
    assert!(update.flowspec_announce.is_empty());
    assert_eq!(
        update.flowspec_withdraw,
        [] as [crate::route::FlowSpecKey; 0]
    );
    assert!(manager.peer_unexportable[&member].contains(&key));
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
    assert!(
        manager
            .pending_group_admitted
            .get(&member)
            .unwrap()
            .is_empty()
    );
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

#[test]
fn budget_refused_batched_narrowing_keeps_current_withdrawal_duties() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let member: IpAddr = Ipv4Addr::new(10, 220, 4, 4).into();
    let (outbound, mut receiver) = mpsc::channel(16);
    manager.handle_update(peer_up(member, outbound, Some(policy(3, 1))));
    while receiver.try_recv().is_ok() {}
    source_update(&mut manager, &[1, 2, 3], &[]);
    let initial = receiver.try_recv().unwrap();
    assert!(
        initial
            .announce
            .iter()
            .any(|route| route.prefix == Prefix::V4(prefix(1)))
    );
    let encoder = manager.peer_export_encoders.remove(&member).unwrap();
    manager.pending_group_admitted =
        crate::manager::update_groups::admitted_recovery::AdmittedRecovery::with_test_limits(
            0,
            512 * 1024 * 1024,
        );
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::ReplacePeerExportPoliciesAuthoritatively {
        replacements: vec![PeerExportPolicyReplacement {
            peer: member,
            export_policy: Some(policy(1, 2)),
        }],
        reply,
    });
    assert_eq!(response.try_recv().unwrap(), Ok(()));
    assert_eq!(
        manager
            .policy_transition_stats
            .batched_authoritative_shared_members,
        1
    );
    assert!(manager.dirty_peers.contains(&member));
    assert!(manager.pending_group_admitted.get(&member).is_none());
    manager.peer_export_encoders.insert(member, encoder);
    while manager.resync_dirty_peers_bounded() {}
    let recovered = receiver.try_recv().unwrap();
    assert!(recovered.withdraw.contains(&(Prefix::V4(prefix(1)), 0)));
    assert!(!manager.dirty_peers.contains(&member));
    assert!(manager.outbound_peers.contains_key(&member));
    assert_eq!(manager.group_recovery_fallback(member), None);
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

#[test]
fn grouped_capture_orders_real_old_values_and_recovers_exact_withdrawals() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let keys: Vec<_> = (1..=64).rev().collect();
    source_update(&mut manager, &keys, &[]);
    let peers = [
        IpAddr::from(Ipv4Addr::new(10, 222, 4, 1)),
        IpAddr::from(Ipv4Addr::new(10, 222, 4, 2)),
    ];
    let mut receivers = Vec::new();
    for peer in peers {
        let (outbound, mut receiver) = mpsc::channel(128);
        manager.handle_update(peer_up(peer, outbound, None));
        let mut admitted = HashSet::new();
        while let Ok(update) = receiver.try_recv() {
            admitted.extend(update.announce.iter().map(|route| route.prefix));
        }
        assert_eq!(
            admitted,
            keys.iter().map(|n| Prefix::V4(prefix(*n))).collect()
        );
        assert!(manager.mark_outbound_dirty(peer));
        let proof = manager.pending_group_admitted.get(&peer).unwrap();
        assert_eq!(proof.len(), 64);
        for n in &keys {
            assert!(proof.contains(&ExactExportKey::Unicast(Prefix::V4(prefix(*n)), 0)));
        }
        receivers.push(receiver);
    }
    let withdrawn: Vec<_> = keys.iter().copied().filter(|n| n % 2 == 0).collect();
    source_update(&mut manager, &[], &withdrawn);
    while manager.resync_dirty_peers_bounded() {}
    for (peer, mut receiver) in peers.into_iter().zip(receivers) {
        let mut actual = Vec::new();
        while let Ok(update) = receiver.try_recv() {
            actual.extend(update.withdraw);
        }
        assert_eq!(actual.len(), withdrawn.len());
        assert_eq!(
            actual.into_iter().collect::<HashSet<_>>(),
            withdrawn
                .iter()
                .map(|n| (Prefix::V4(prefix(*n)), 0))
                .collect()
        );
        assert!(!manager.dirty_peers.contains(&peer));
        assert!(!manager.pending_group_admitted.contains_record(peer));
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the actor control follows actual admission through capture and owed-withdrawal recovery for both families"
)]
fn full_old_capture_keeps_actual_proof(vpn: bool, vpn_capable: bool) {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(192, 0, 2, 254)),
        BgpMetrics::new(),
    );
    let member: IpAddr = Ipv4Addr::new(10, 222, 4, 1).into();
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let (outbound, mut receiver) = mpsc::channel(16);
    let mut registration = peer_up(member, outbound, None);
    if let RibUpdate::PeerUp {
        sendable_families,
        route_reflector_client,
        ..
    } = &mut registration
    {
        if vpn_capable {
            sendable_families.push((Afi::Ipv4, Safi::MplsVpn));
        }
        *route_reflector_client = true;
    }
    manager.handle_update(registration);
    while receiver.try_recv().is_ok() {}
    let expected: HashSet<_> = if vpn {
        let routes: Vec<_> = (1..=128)
            .map(|n| make_vpn_rib_route(source, n, 100, 100))
            .collect();
        let mut expected: HashSet<_> = routes
            .iter()
            .map(|r| ExactExportKey::Vpn(r.key()))
            .collect();
        manager.handle_update(RibUpdate::VpnRoutesReceived {
            peer: source.into(),
            session_id: 0,
            announced: routes,
            withdrawn: vec![],
        });
        source_update(&mut manager, &(1..=128).collect::<Vec<_>>(), &[]);
        expected.extend((1..=128).map(|n| ExactExportKey::Unicast(Prefix::V4(prefix(n)), 0)));
        expected
    } else {
        source_update(&mut manager, &(1..=128).collect::<Vec<_>>(), &[]);
        (1..=128)
            .map(|n| ExactExportKey::Unicast(Prefix::V4(prefix(n)), 0))
            .collect()
    };
    let mut delivered = HashSet::new();
    while let Ok(update) = receiver.try_recv() {
        delivered.extend(
            update
                .announce
                .iter()
                .map(|r| ExactExportKey::Unicast(r.prefix, r.path_id)),
        );
        delivered.extend(
            update
                .vpn_announce
                .iter()
                .map(|r| ExactExportKey::Vpn(r.key())),
        );
    }
    assert_eq!(
        delivered, expected,
        "capture must describe actual admitted OLD"
    );
    let gid = manager.grouped_member_of(member).unwrap();
    assert!(
        manager.group_ribs[&gid]
            .recovery_snapshot_for_test()
            .is_none()
    );
    assert!(manager.mark_outbound_dirty(member));
    let proof = manager.pending_group_admitted.get(&member).unwrap();
    assert_eq!(proof.iter().collect::<HashSet<_>>(), expected);
    assert_eq!(
        manager.group_ribs[&gid]
            .recovery_snapshot_for_test()
            .is_some(),
        !vpn_capable,
        "full OLD representation follows negotiated VPN capability, not current VPN row count"
    );
    let withdrawn = if vpn {
        let key = make_vpn_rib_route(source, 1, 100, 100).key();
        manager.handle_update(RibUpdate::VpnRoutesReceived {
            peer: source.into(),
            session_id: 0,
            announced: vec![],
            withdrawn: vec![key.clone()],
        });
        ExactExportKey::Vpn(key)
    } else {
        source_update(&mut manager, &[], &[1]);
        ExactExportKey::Unicast(Prefix::V4(prefix(1)), 0)
    };
    while manager.resync_dirty_peers_bounded() {}
    let mut withdrawals = Vec::new();
    while let Ok(update) = receiver.try_recv() {
        withdrawals.extend(
            update
                .withdraw
                .into_iter()
                .map(|(p, id)| ExactExportKey::Unicast(p, id)),
        );
        withdrawals.extend(update.vpn_withdraw.into_iter().map(ExactExportKey::Vpn));
    }
    assert_eq!(withdrawals, vec![withdrawn]);
    assert!(!manager.dirty_peers.contains(&member));
    assert!(!manager.pending_group_admitted.contains_record(member));
    assert_eq!(manager.group_recovery_fallback(member), None);
}

#[test]
fn vpn_capable_unicast_only_full_old_capture_stays_flat_and_keeps_owed_withdrawals() {
    full_old_capture_keeps_actual_proof(false, true);
}

#[test]
fn mixed_uc_vpn_full_old_capture_stays_flat_and_keeps_owed_withdrawals() {
    full_old_capture_keeps_actual_proof(true, true);
}

#[test]
fn indexed_pure_unicast_full_old_capture_keeps_owed_withdrawals() {
    full_old_capture_keeps_actual_proof(false, false);
}

#[test]
fn initial_dump_creates_an_indexed_pool_before_eor_deferral() {
    use crate::manager::update_groups::admitted_recovery::Key;

    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    source_update(&mut manager, &(1..=128).collect::<Vec<_>>(), &[]);
    let member: IpAddr = Ipv4Addr::new(10, 222, 4, 2).into();
    let (outbound, mut receiver) = mpsc::channel(1);
    manager.handle_update(peer_up(member, outbound, None));
    let delivered = receiver.try_recv().unwrap();
    assert_eq!(delivered.announce.len(), 128);
    assert!(manager.dirty_peers.contains(&member));
    let group = &manager.group_ribs[&manager.grouped_member_of(member).unwrap()];
    let hint = group.recovery_snapshot_for_test().unwrap();
    let shape = manager
        .pending_group_admitted
        .full_old_shape_with_checkpoint(
            Some(hint),
            &group.table,
            true,
            |route| Some(Key::Unicast(route.prefix, route.path_id)),
            |_| None,
            &mut |_| {},
        )
        .unwrap();
    assert_eq!(shape.count, 128);
    assert_eq!(shape.comparisons, 128);
    assert_eq!(
        shape.fallback, None,
        "initial/empty admission must publish an indexed pool too"
    );
    assert_eq!(
        manager.pending_group_admitted.get(&member).unwrap().len(),
        128
    );
}

#[test]
fn optional_index_share_and_flat_refusal_count_once_and_keep_the_owed_withdrawal() {
    use crate::manager::update_groups::RecoveryFallbackCause;
    use crate::manager::update_groups::admitted_recovery::AdmittedRecovery;

    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let member = Ipv4Addr::new(10, 222, 4, 3);
    let (outbound, mut receiver) = mpsc::channel(16);
    manager.handle_update(peer_up(member.into(), outbound, None));
    while receiver.try_recv().is_ok() {}
    source_update(&mut manager, &(1..=128).collect::<Vec<_>>(), &[]);
    assert_eq!(receiver.try_recv().unwrap().announce.len(), 128);
    // These staged own-source rows must never enter the actual admitted OLD set.
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: member.into(),
        session_id: 0,
        announced: (0..2_000)
            .map(|n| make_route(Ipv4Prefix::new(Ipv4Addr::from(n), 32), member))
            .collect(),
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
    }
    let gid = manager.grouped_member_of(member.into()).unwrap();
    assert!(manager.group_ribs[&gid].table.len() >= 2_000);
    let mut ledger = AdmittedRecovery::with_test_limits(8 * 1024, 512 * 1024 * 1024);
    let keeper: IpAddr = Ipv4Addr::new(10, 222, 4, 240).into();
    let spare: IpAddr = Ipv4Addr::new(10, 222, 4, 241).into();
    ledger.insert_empty(keeper).unwrap();
    ledger.insert_empty(spare).unwrap();
    ledger.remove(&spare); // Retain the second record slot, so capture registration cannot consume the fault.
    ledger.fail_next_allocation_for_test();
    manager.pending_group_admitted = ledger;
    assert!(manager.mark_outbound_dirty(member.into()));
    assert_eq!(
        manager
            .pending_group_admitted
            .optional_share_attempts_for_test(),
        1
    );
    assert_eq!(
        manager
            .pending_group_admitted
            .optional_share_refusals_for_test(),
        1
    );
    // The oversized optional pool refuses by cap; the fitting flat proof reaches
    // the injected allocator fault. Propagating the first refusal gives the wrong cause.
    assert_eq!(
        manager.group_recovery_fallback(member.into()),
        Some(RecoveryFallbackCause::AllocationFailure)
    );
    assert_eq!(fallback_count(&manager, "allocation_failure"), 1.0);
    assert!(manager.pending_group_admitted.get(&member.into()).is_none());
    source_update(&mut manager, &[], &[1]);
    while manager.resync_dirty_peers_bounded() {}
    let mut withdrawals = Vec::new();
    while let Ok(update) = receiver.try_recv() {
        withdrawals.extend(update.withdraw);
    }
    assert_eq!(withdrawals, vec![(Prefix::V4(prefix(1)), 0)]);
    assert_eq!(
        manager
            .pending_group_admitted
            .optional_share_attempts_for_test(),
        1
    );
    assert_eq!(fallback_count(&manager, "allocation_failure"), 1.0);
    assert!(!manager.dirty_peers.contains(&member.into()));
    assert_eq!(manager.group_recovery_fallback(member.into()), None);
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the actor control keeps actual delivery, retained old ownership, slot churn and exact recovery proof in one ordered scenario"
)]
fn actual_full_old_slot_churn_stops_searching_but_keeps_every_admitted_key() {
    use crate::manager::update_groups::admitted_recovery::{FullCaptureFallback, Key};

    const COUNT: u32 = 5_000;
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let first: IpAddr = Ipv4Addr::new(10, 222, 4, 4).into();
    let second: IpAddr = Ipv4Addr::new(10, 222, 4, 5).into();
    let source = Ipv4Addr::new(192, 0, 2, 1);
    let (first_tx, mut first_rx) = mpsc::channel(64);
    let (second_tx, mut second_rx) = mpsc::channel(1024);
    manager.handle_update(peer_up(first, first_tx, None));
    manager.handle_update(peer_up(second, second_tx, None));
    while first_rx.try_recv().is_ok() {}
    while second_rx.try_recv().is_ok() {}
    let inject = |manager: &mut RibManager,
                  announce: std::ops::Range<u32>,
                  withdraw: std::ops::Range<u32>| {
        manager.handle_update(RibUpdate::RoutesReceived {
            peer: source.into(),
            session_id: 0,
            announced: announce
                .map(|n| make_route(Ipv4Prefix::new(Ipv4Addr::from(n), 32), source))
                .collect(),
            withdrawn: withdraw
                .map(|n| (Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(n), 32)), 0))
                .collect(),
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
            validated_with: None,
        });
        while manager.process_next_route_chunk() {}
    };
    inject(&mut manager, 0..COUNT, 0..0);
    let mut first_delivered = 0;
    while let Ok(update) = first_rx.try_recv() {
        first_delivered += update.announce.len();
    }
    let mut second_delivered = 0;
    while let Ok(update) = second_rx.try_recv() {
        second_delivered += update.announce.len();
    }
    assert_eq!(first_delivered, COUNT as usize);
    assert_eq!(second_delivered, COUNT as usize);
    assert!(manager.mark_outbound_dirty(first));
    let gid = manager.grouped_member_of(first).unwrap();
    let hint = manager.group_ribs[&gid]
        .recovery_snapshot_for_test()
        .unwrap();
    while manager.outbound_peers[&first]
        .try_send(OutboundRouteUpdate::default())
        .is_ok()
    {}
    assert!(manager.outbound_channel_full(first));
    inject(&mut manager, COUNT..2 * COUNT, 0..COUNT);
    let mut admitted = HashSet::new();
    while let Ok(update) = second_rx.try_recv() {
        admitted.extend(
            update
                .announce
                .iter()
                .map(|route| ExactExportKey::Unicast(route.prefix, route.path_id)),
        );
    }
    assert_eq!(admitted.len(), COUNT as usize);
    assert!(!manager.dirty_peers.contains(&second));
    assert_eq!(
        manager.group_ribs[&gid].recovery_snapshot_for_test(),
        Some(hint)
    );
    let group = &manager.group_ribs[&gid];
    let shape = manager
        .pending_group_admitted
        .full_old_shape_with_checkpoint(
            Some(hint),
            &group.table,
            true,
            |route| Some(Key::Unicast(route.prefix, route.path_id)),
            |_| None,
            &mut |_| {},
        )
        .unwrap();
    assert_eq!(
        shape.count, COUNT as usize,
        "the count must continue after lookup stops"
    );
    assert_eq!(shape.mismatches, 4_097);
    assert_eq!(shape.fallback, Some(FullCaptureFallback::SlotChurn));
    assert!(shape.comparisons < 90_000);
    assert!(manager.mark_outbound_dirty(second));
    let proof = manager.pending_group_admitted.get(&second).unwrap();
    assert_eq!(proof.iter().collect::<HashSet<_>>(), admitted);
    assert!(!proof.contains(&ExactExportKey::Unicast(
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0), 32)),
        0
    )));
    assert_eq!(manager.group_recovery_fallback(second), None);
    assert_eq!(
        manager.pending_group_admitted.get(&first).unwrap().len(),
        COUNT as usize
    );
}
