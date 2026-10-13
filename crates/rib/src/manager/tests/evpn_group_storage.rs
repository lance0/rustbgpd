use super::exportability::MockExactExportEncoder;
use super::*;
use crate::manager::distribution::OutboundCommitBatch;
use crate::manager::helpers::evpn_routes_equal;
use crate::manager::update_groups::{EvpnGroupStageOutput, emit_evpn_group_deltas_for_member};
use crate::update::ExactExportKey;

pub(super) fn fixture() -> (
    RibManager,
    IpAddr,
    usize,
    mpsc::Receiver<OutboundRouteUpdate>,
) {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(
        rx,
        dummy_query_rx(),
        None,
        Some(Ipv4Addr::new(192, 0, 2, 254)),
        BgpMetrics::new(),
    );
    let member: IpAddr = Ipv4Addr::new(192, 0, 2, 30).into();
    let (sender, mut output) = mpsc::channel(8);
    register(&mut manager, member, sender);
    while output.try_recv().is_ok() {}
    let gid = manager.grouped_member_of(member).unwrap();
    assert!(!manager.group_ribs[&gid].owns_evpn);
    manager.group_ribs.get_mut(&gid).unwrap().owns_evpn = true;
    assert!(manager.register_evpn_recovery(member, false));
    (manager, member, gid, output)
}

fn register(manager: &mut RibManager, peer: IpAddr, sender: mpsc::Sender<OutboundRouteUpdate>) {
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id: 7,
        peer_asn: 65000,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 30),
        outbound_tx: sender,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::L2Vpn, Safi::Evpn)],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
}

pub(super) fn stage(
    manager: &mut RibManager,
    gid: usize,
    route: &EvpnRibRoute,
) -> EvpnGroupStageOutput {
    manager
        .loc_rib
        .recompute_evpn(route.key(), [route].into_iter());
    manager.stage_group_evpn_keys(gid, &HashSet::from([route.key()]))
}

fn events(
    manager: &RibManager,
    gid: usize,
    output: &EvpnGroupStageOutput,
    member: IpAddr,
    membership: Option<&RtcMembership>,
    rejected: Option<&HashSet<ExactExportKey>>,
) -> (Vec<EvpnRibRoute>, Vec<rustbgpd_wire::EvpnRouteKey>) {
    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    emit_evpn_group_deltas_for_member(
        &manager.group_ribs[&gid],
        &output.deltas,
        member,
        manager.cluster_id,
        membership,
        rejected,
        &mut announce,
        &mut withdraw,
    );
    (announce, withdraw)
}

fn rt(value: u16) -> ExtendedCommunity {
    ExtendedCommunity::new(0x0002_FDE9_0000_0000 | u64::from(value))
}

fn private_events(
    manager: &RibManager,
    gid: usize,
    key: rustbgpd_wire::EvpnRouteKey,
    member: IpAddr,
    private: &crate::adj_rib_out::AdjRibOut,
    membership: Option<&RtcMembership>,
) -> (Vec<EvpnRibRoute>, Vec<rustbgpd_wire::EvpnRouteKey>) {
    let group = &manager.group_ribs[&gid];
    let mut stats = NeighborPolicyStats::default();
    let metrics = BgpMetrics::new();
    let label = member.to_string();
    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    RibManager::stage_evpn_routes(
        &manager.loc_rib,
        private,
        &manager.peer_is_rr_client,
        &HashSet::from([key]),
        &mut crate::manager::distribution::ExportTarget::Peer {
            peer: member,
            peer_asn: Some(65000),
            peer_group: None,
            metrics: &metrics,
            policy_stats: &mut stats,
            peer_label: &label,
        },
        group.is_ebgp,
        group.interpret_rfc1997,
        group.is_rr_client,
        manager.cluster_id,
        Some(&group.sendable),
        Some(&group.llgr),
        group.export_chain.as_ref(),
        membership,
        &mut announce,
        &mut withdraw,
        false,
    );
    (announce, withdraw)
}

fn membership(value: u16) -> RtcMembership {
    RtcMembership {
        has_default: false,
        entries: vec![make_rtc_rib_route(Ipv4Addr::new(192, 0, 2, 40), value, 100).nlri],
    }
}

pub(super) fn received(value: u16) -> EvpnRibRoute {
    let mut route = make_evpn_imet(Ipv4Addr::new(192, 0, 2, 10), 1);
    route.attributes = AttrSet::new(vec![PathAttribute::ExtendedCommunities(vec![rt(value)])]);
    route
}

fn strip_rts() -> PolicyChain {
    let mut statement = deny_default_prefix_chain().policies[0].policy.entries[0].clone();
    statement.prefix = None;
    statement.action = rustbgpd_policy::PolicyAction::Permit;
    statement.modifications.extended_communities_remove = vec![rt(100), rt(200), rt(300)];
    PolicyChain::new(vec![rustbgpd_policy::Policy {
        entries: vec![statement],
        default_action: rustbgpd_policy::PolicyAction::Deny,
    }])
}

#[test]
fn group_storage_preserves_type_one_through_six_full_values_and_received_arcs() {
    let (mut manager, member, gid, _output) = fixture();
    let mut routes = super::evpn_dataplane_query::relevant_routes();
    routes.extend(super::evpn_dataplane_query::irrelevant_routes());
    routes.push(make_evpn_smet(Ipv4Addr::new(192, 0, 2, 10), 3));
    let mut types = BTreeSet::new();
    for route in &routes {
        let output = stage(&mut manager, gid, route);
        assert_eq!(output.deltas.len(), 1);
        let entry = manager.group_ribs[&gid].evpn_entry(&route.key()).unwrap();
        assert_eq!(entry.route.route, route.route);
        assert_eq!(entry.route.next_hop, route.next_hop);
        assert_eq!(entry.route.link_local_next_hop, route.link_local_next_hop);
        assert_eq!(entry.route.origin_type, route.origin_type);
        assert_eq!(entry.route.peer_router_id, route.peer_router_id);
        assert!(Arc::ptr_eq(&entry.route.attributes, &route.attributes));
        assert!(Arc::ptr_eq(&entry.input.attributes, &route.attributes));
        types.insert(route.route_type());
    }
    assert_eq!(types, BTreeSet::from([1, 2, 3, 4, 5, 6]));
    assert_eq!(manager.group_ribs[&gid].table.evpn_len(), routes.len());
    assert_eq!(
        manager.group_ribs[&gid]
            .evpn_member_projection(member, manager.cluster_id, None, None)
            .count(),
        routes.len()
    );
    let owner = manager.evpn_recovery_handle(member).unwrap();
    assert!(
        manager.evpn_recovery.is_dormant(owner),
        "healthy staging does not capture all member keys"
    );
}

#[test]
fn policy_hidden_rt_flip_preserves_old_membership_and_suppresses_equal_member_values() {
    let (mut manager, member, gid, _output) = fixture();
    manager.group_ribs.get_mut(&gid).unwrap().export_chain = Some(strip_rts());
    let a = received(100);
    let initial = stage(&mut manager, gid, &a);
    let filter100 = membership(100);
    let filter200 = membership(200);
    assert_eq!(
        events(&manager, gid, &initial, member, Some(&filter100), None)
            .0
            .len(),
        1
    );
    assert!(
        events(&manager, gid, &initial, member, Some(&filter200), None)
            .0
            .is_empty()
    );
    let b = received(200);
    let flip = stage(&mut manager, gid, &b);
    assert_eq!(flip.deltas.len(), 1);
    assert_eq!(
        flip.deltas[0]
            .old
            .as_ref()
            .unwrap()
            .route
            .extended_communities(),
        []
    );
    assert_eq!(
        flip.deltas[0]
            .new
            .as_ref()
            .unwrap()
            .route
            .extended_communities(),
        []
    );
    let old_view = events(&manager, gid, &flip, member, Some(&filter100), None);
    assert!(old_view.0.is_empty());
    assert_eq!(old_view.1, vec![a.key()]);
    let new_view = events(&manager, gid, &flip, member, Some(&filter200), None);
    assert_eq!(new_view.0.len(), 1);
    assert_eq!(new_view.1, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
    let mut c = b.clone();
    c.attributes = AttrSet::new(vec![PathAttribute::ExtendedCommunities(vec![
        rt(200),
        rt(300),
    ])]);
    let input_only = stage(&mut manager, gid, &c);
    assert_eq!(input_only.deltas.len(), 1);
    assert!(evpn_routes_equal(
        &input_only.deltas[0].old.as_ref().unwrap().route,
        &input_only.deltas[0].new.as_ref().unwrap().route
    ));
    let unchanged = events(&manager, gid, &input_only, member, Some(&filter200), None);
    assert!(unchanged.0.is_empty() && unchanged.1.is_empty());
    let unfiltered = events(&manager, gid, &input_only, member, None, None);
    assert!(unfiltered.0.is_empty() && unfiltered.1.is_empty());
    assert!(stage(&mut manager, gid, &c).deltas.is_empty());
}

#[test]
fn source_flip_uses_direct_source_exclusion_and_private_equality() {
    let (mut manager, member, gid, _output) = fixture();
    let a = received(100);
    let old_source = a.peer;
    stage(&mut manager, gid, &a);
    let mut b = a.clone();
    b.peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    b.peer_router_id = Ipv4Addr::new(192, 0, 2, 20);
    let flip = stage(&mut manager, gid, &b);
    let former = events(&manager, gid, &flip, old_source, None, None);
    assert_eq!(former.0.len(), 1);
    assert_eq!(former.1, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
    let current = events(&manager, gid, &flip, b.peer, None, None);
    assert!(current.0.is_empty());
    assert_eq!(current.1, vec![a.key()]);
    let third = events(&manager, gid, &flip, member, None, None);
    assert_eq!(third.0.len(), 1);
    assert!(evpn_routes_equal(&third.0[0], &b));
}

#[test]
fn exact_export_overlay_filters_admitted_views_but_changed_candidates_are_reprobed() {
    let (mut manager, member, gid, mut output) = fixture();
    let owner = manager.evpn_recovery_handle(member).unwrap();
    assert!(manager.capture_shared_evpn_admitted(member));
    let a = received(100);
    let initial = stage(&mut manager, gid, &a);
    let rejected = HashSet::from([ExactExportKey::Evpn(a.key())]);
    assert_eq!(
        manager.group_ribs[&gid]
            .evpn_member_projection(member, manager.cluster_id, None, Some(&rejected))
            .count(),
        0
    );
    let candidate = events(&manager, gid, &initial, member, None, Some(&rejected));
    assert_eq!(candidate.0.len(), 1);
    let encoder = MockExactExportEncoder::accepting(1);
    encoder.set_profile(2, [ExactExportKey::Evpn(a.key())]);
    manager.peer_export_encoders.insert(member, encoder.clone());
    assert!(manager.try_send_and_commit_outbound_update(
        member,
        OutboundCommitBatch {
            evpn_announce: candidate.0,
            ..OutboundCommitBatch::default()
        }
    ));
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
    }
    assert!(manager.peer_unexportable[&member].contains(&ExactExportKey::Evpn(a.key())));
    assert_eq!(manager.evpn_recovery.proof(owner).unwrap().unwrap(), []);
    assert_eq!(
        manager.group_ribs[&gid]
            .evpn_member_projection(
                member,
                manager.cluster_id,
                None,
                manager.peer_unexportable.get(&member)
            )
            .count(),
        0
    );

    let mut replacement = a.clone();
    replacement.next_hop = "192.0.2.11".parse().unwrap();
    let changed = stage(&mut manager, gid, &replacement);
    let reprobed = events(
        &manager,
        gid,
        &changed,
        member,
        None,
        manager.peer_unexportable.get(&member),
    );
    assert_eq!(reprobed.0.len(), 1);
    assert_eq!(reprobed.1, [] as [rustbgpd_wire::EvpnRouteKey; 0]);
    encoder.set_profile(3, []);
    assert!(manager.try_send_and_commit_outbound_update(
        member,
        OutboundCommitBatch {
            evpn_announce: reprobed.0,
            evpn_withdraw: reprobed.1,
            ..OutboundCommitBatch::default()
        }
    ));
    let admitted = output.try_recv().unwrap();
    assert_eq!(admitted.evpn_announce.len(), 1);
    assert_eq!(admitted.evpn_announce[0].key(), replacement.key());
    assert_eq!(admitted.evpn_announce[0].next_hop, replacement.next_hop);
    assert_eq!(
        admitted.evpn_withdraw,
        [] as [rustbgpd_wire::EvpnRouteKey; 0]
    );
    assert!(output.try_recv().is_err());
    assert!(
        manager
            .peer_unexportable
            .get(&member)
            .is_none_or(|overlay| { !overlay.contains(&ExactExportKey::Evpn(replacement.key())) })
    );
    assert_eq!(
        manager.evpn_recovery.proof(owner).unwrap(),
        Some([replacement.key()].as_slice())
    );
    let mut projection = manager.group_ribs[&gid].evpn_member_projection(
        member,
        manager.cluster_id,
        None,
        manager.peer_unexportable.get(&member),
    );
    let accepted = projection.next().unwrap();
    assert_eq!(accepted.key(), replacement.key());
    assert_eq!(accepted.next_hop, replacement.next_hop);
    assert!(projection.next().is_none());
}

#[test]
fn first_full_capture_precedes_staging_and_survives_rtc_change_and_repeated_regroup() {
    let (mut manager, member, gid, _output) = fixture();
    let old = received(100);
    stage(&mut manager, gid, &old);
    manager.peer_rt_membership.insert(member, membership(100));
    for _ in 0..8 {
        manager.outbound_peers[&member]
            .try_send(OutboundRouteUpdate::default())
            .unwrap();
    }
    let displaced = stage(&mut manager, gid, &received(200));
    let owner = manager.evpn_recovery_handle(member).unwrap();
    assert_eq!(
        manager.evpn_recovery.proof(owner).unwrap(),
        Some([old.key()].as_slice())
    );
    assert_eq!(
        displaced.deltas[0].old.as_ref().unwrap().input.attributes,
        old.attributes
    );
    manager.mark_outbound_dirty(member);
    manager.peer_rt_membership.insert(member, membership(200));
    let mut new = received(200);
    if let EvpnRoute::Imet(route) = &mut new.route {
        route.ethernet_tag = EthernetTagId(2);
    }
    stage(&mut manager, gid, &new);
    assert_eq!(
        manager.evpn_recovery.proof(owner).unwrap(),
        Some([old.key()].as_slice())
    );
    manager.peer_interpret_rfc1997.remove(&member);
    manager.recompute_update_group(member);
    manager.peer_interpret_rfc1997.insert(member);
    manager.recompute_update_group(member);
    assert_eq!(
        manager.evpn_recovery.proof(owner).unwrap(),
        Some([old.key()].as_slice())
    );
}

#[test]
fn rejected_metadata_only_update_matches_private_reprobe_and_delivery() {
    let (mut manager, member, gid, mut output) = fixture();
    assert!(manager.capture_shared_evpn_admitted(member));
    let original = received(100);
    let initial = stage(&mut manager, gid, &original);
    let encoder = MockExactExportEncoder::accepting(1);
    encoder.set_profile(2, [ExactExportKey::Evpn(original.key())]);
    manager.peer_export_encoders.insert(member, encoder.clone());
    assert!(manager.try_send_and_commit_outbound_update(
        member,
        OutboundCommitBatch {
            evpn_announce: events(&manager, gid, &initial, member, None, None).0,
            ..OutboundCommitBatch::default()
        }
    ));
    while let Ok(update) = output.try_recv() {
        assert!(update.evpn_announce.is_empty() && update.evpn_withdraw.is_empty());
    }
    assert!(manager.peer_unexportable[&member].contains(&ExactExportKey::Evpn(original.key())));
    assert!(
        manager.adj_ribs_out[&member]
            .get_evpn(&original.key())
            .is_none()
    );

    let mut updated = original.clone();
    updated.peer_router_id = Ipv4Addr::new(198, 51, 100, 10);
    assert!(evpn_routes_equal(&original, &updated));
    let staged = stage(&mut manager, gid, &updated);
    let actual = events(
        &manager,
        gid,
        &staged,
        member,
        None,
        manager.peer_unexportable.get(&member),
    );
    let expected = private_events(
        &manager,
        gid,
        updated.key(),
        member,
        &manager.adj_ribs_out[&member],
        None,
    );
    assert_eq!(
        expected.0.len(),
        1,
        "private admission has no old slot to suppress"
    );
    assert_eq!(actual.0.len(), expected.0.len());
    assert!(evpn_routes_equal(&actual.0[0], &expected.0[0]));
    assert_eq!(actual.0[0].peer_router_id, updated.peer_router_id);
    assert_eq!(actual.1, expected.1);

    encoder.set_profile(3, []);
    assert!(manager.try_send_and_commit_outbound_update(
        member,
        OutboundCommitBatch {
            evpn_announce: actual.0,
            evpn_withdraw: actual.1,
            ..OutboundCommitBatch::default()
        }
    ));
    let admitted = output.try_recv().unwrap();
    assert_eq!(admitted.evpn_announce.len(), 1);
    assert_eq!(
        admitted.evpn_announce[0].peer_router_id,
        updated.peer_router_id
    );
    assert_eq!(
        admitted.evpn_withdraw,
        [] as [rustbgpd_wire::EvpnRouteKey; 0]
    );
    assert!(output.try_recv().is_err());
    assert!(
        manager
            .peer_unexportable
            .get(&member)
            .is_none_or(|overlay| { !overlay.contains(&ExactExportKey::Evpn(updated.key())) })
    );
}

#[test]
fn private_capture_reads_only_actual_admitted_keys_without_settling_the_shared_feed() {
    let (mut manager, member, _gid, _output) = fixture();
    let old = received(100);
    manager
        .adj_ribs_out
        .get_mut(&member)
        .unwrap()
        .insert_evpn(old.clone());
    assert!(manager.capture_private_evpn_admitted(member));
    let owner = manager.evpn_recovery_handle(member).unwrap();
    assert_eq!(
        manager.evpn_recovery.proof(owner).unwrap(),
        Some([old.key()].as_slice())
    );
    assert!(
        !manager.finish_evpn_recovery(member),
        "capture is not a completed shared delivery barrier"
    );
}

#[test]
fn same_token_replay_captures_old_shared_projection_without_guessing_an_empty_heal() {
    let (mut manager, member, gid, _output) = fixture();
    let old = received(100);
    let owner = manager.evpn_recovery_handle(member).unwrap();
    stage(&mut manager, gid, &old);
    manager
        .loc_rib
        .recompute_evpn(old.key(), std::iter::empty());
    let sender = manager.outbound_peers[&member].clone();
    register(&mut manager, member, sender);
    assert_eq!(manager.evpn_recovery_handle(member), Some(owner));
    assert_eq!(
        manager.evpn_recovery.proof(owner).unwrap(),
        Some([old.key()].as_slice())
    );
    assert!(manager.dirty_peers.contains(&member));
    assert!(!manager.finish_evpn_recovery(member));
    assert!(
        !manager.settle_evpn_recovery(member, [].into_iter()),
        "an empty partial replay never proves that the old key was withdrawn"
    );
}

#[test]
fn per_key_events_and_end_state_match_the_private_export_tail() {
    let (mut manager, member, gid, _output) = fixture();
    manager.group_ribs.get_mut(&gid).unwrap().export_chain = Some(strip_rts());
    let filter = membership(100);
    let mut private = crate::adj_rib_out::AdjRibOut::with_capacity(member, 1);
    let mut shared_view = HashMap::new();
    let mut third = received(100);
    third.attributes = AttrSet::new(vec![PathAttribute::ExtendedCommunities(vec![
        rt(100),
        rt(200),
    ])]);
    let mut own = third.clone();
    own.peer = member;
    for route in [received(100), received(200), third.clone(), own, third] {
        let staged = stage(&mut manager, gid, &route);
        let actual = events(&manager, gid, &staged, member, Some(&filter), None);
        let (announce, withdraw) =
            private_events(&manager, gid, route.key(), member, &private, Some(&filter));
        assert_eq!(
            actual.1, withdraw,
            "same-key withdrawals must match each pass"
        );
        assert_eq!(actual.0.len(), announce.len());
        assert!(
            actual
                .0
                .iter()
                .zip(&announce)
                .all(|(a, b)| evpn_routes_equal(a, b))
        );
        for key in actual.1 {
            assert!(
                shared_view.remove(&key).is_some(),
                "never withdraw an unadmitted key"
            );
        }
        for entry in actual.0 {
            shared_view.insert(entry.key(), entry);
        }
        for key in withdraw {
            assert!(private.remove_evpn(&key));
        }
        for entry in announce {
            private.insert_evpn(entry);
        }
        assert_eq!(shared_view.len(), private.evpn_len());
        assert!(
            private
                .iter_evpn()
                .all(|entry| evpn_routes_equal(entry, &shared_view[&entry.key()]))
        );
    }
}

#[test]
fn es_import_and_captured_source_rr_role_use_received_projection_input() {
    let (mut manager, member, gid, _output) = fixture();
    let mut route = super::evpn_dataplane_query::irrelevant_routes()
        .pop()
        .unwrap();
    let es_import = ExtendedCommunity::es_import_rt([2, 1, 2, 3, 4, 5]);
    route.attributes = AttrSet::new(vec![PathAttribute::ExtendedCommunities(vec![es_import])]);
    manager.peer_is_rr_client.insert(route.peer, true);
    stage(&mut manager, gid, &route);
    let filter = RtcMembership {
        has_default: false,
        entries: vec![rustbgpd_wire::RtcNlri::new(65000, es_import.as_u64(), 96).unwrap()],
    };
    let group = manager.group_ribs.get_mut(&gid).unwrap();
    group.is_rr_client = false;
    assert_eq!(
        group
            .evpn_member_projection(member, manager.cluster_id, Some(&filter), None)
            .count(),
        1
    );
    manager.peer_is_rr_client.insert(route.peer, false);
    // The OLD entry retains the old source role; current source metadata
    // is not allowed to reinterpret its earlier admitted projection.
    assert_eq!(
        manager.group_ribs[&gid]
            .evpn_member_projection(member, manager.cluster_id, Some(&filter), None)
            .count(),
        1
    );
    let displaced = stage(&mut manager, gid, &route);
    assert!(
        displaced.deltas[0]
            .old
            .as_ref()
            .unwrap()
            .input
            .source_is_rr_client
    );
    assert!(displaced.deltas[0].new.is_none());
    assert_eq!(
        events(&manager, gid, &displaced, member, Some(&filter), None).1,
        vec![route.key()]
    );
}

#[test]
fn router_id_only_change_refreshes_storage_and_replay_without_an_ordinary_event() {
    let (mut manager, member, gid, _output) = fixture();
    let original = received(100);
    stage(&mut manager, gid, &original);
    let mut updated = original.clone();
    updated.peer_router_id = Ipv4Addr::new(198, 51, 100, 10);
    assert_eq!(updated.key(), original.key());
    assert_eq!(updated.peer, original.peer);
    assert_eq!(updated.next_hop, original.next_hop);
    assert!(Arc::ptr_eq(&updated.attributes, &original.attributes));
    assert!(evpn_routes_equal(&original, &updated));
    let staged = stage(&mut manager, gid, &updated);
    assert_eq!(staged.deltas.len(), 1);
    assert_eq!(
        staged.deltas[0].old.as_ref().unwrap().route.peer_router_id,
        original.peer_router_id
    );
    assert_eq!(
        manager.group_ribs[&gid]
            .table
            .get_evpn(&updated.key())
            .unwrap()
            .peer_router_id,
        updated.peer_router_id
    );
    let replay = manager.group_ribs[&gid]
        .evpn_member_projection(member, manager.cluster_id, None, None)
        .next()
        .unwrap();
    assert_eq!(replay.peer_router_id, updated.peer_router_id);
    let ordinary = events(&manager, gid, &staged, member, None, None);
    assert!(ordinary.0.is_empty() && ordinary.1.is_empty());
}

#[test]
fn gr_llgr_transitions_refresh_flags_and_link_local_metadata_without_ordinary_events() {
    let (mut manager, member, gid, _output) = fixture();
    let mut original = received(100);
    original.next_hop = "2001:db8::10".parse().unwrap();
    stage(&mut manager, gid, &original);
    for (gr, llgr, companion) in [
        (true, false, Some("fe80::10".parse::<Ipv6Addr>().unwrap())),
        (false, true, Some("fe80::20".parse::<Ipv6Addr>().unwrap())),
        (false, false, None),
    ] {
        let mut updated = original.clone();
        updated.is_stale = gr;
        updated.is_llgr_stale = llgr;
        updated.link_local_next_hop = companion;
        assert!(evpn_routes_equal(&original, &updated));
        let staged = stage(&mut manager, gid, &updated);
        assert_eq!(staged.deltas.len(), 1);
        let stored = manager.group_ribs[&gid]
            .table
            .get_evpn(&updated.key())
            .unwrap();
        assert_eq!(stored.is_stale, gr);
        assert_eq!(stored.is_llgr_stale, llgr);
        assert_eq!(stored.link_local_next_hop, companion);
        let replay = manager.group_ribs[&gid]
            .evpn_member_projection(member, manager.cluster_id, None, None)
            .next()
            .unwrap();
        assert_eq!(replay.is_stale, gr);
        assert_eq!(replay.is_llgr_stale, llgr);
        assert_eq!(replay.link_local_next_hop, companion);
        let ordinary = events(&manager, gid, &staged, member, None, None);
        assert!(ordinary.0.is_empty() && ordinary.1.is_empty());
    }
}
