use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rustbgpd_policy::{Policy, PolicyStatement, RouteModifications};
use rustbgpd_wire::{
    Ipv4Prefix, Ipv6Prefix, MplsLabelEntry, Origin, PathAttribute, RouteDistinguisher, VpnNlri,
    VpnPrefix,
};

use super::*;

#[test]
fn canceled_update_group_snapshot_does_not_invoke_builder() {
    let (reply, receiver) = tokio::sync::oneshot::channel::<UpdateGroupSnapshot>();
    drop(receiver);
    send_update_group_snapshot(reply, |_| panic!("canceled query materialized"));
}

fn test_snapshot_row(peer: IpAddr) -> UpdateGroupPeerSnapshot {
    let input = UpdateGroupClassifierInput {
        policy_fingerprint: None,
        policy_provenance: None,
        policy_requires_peer_context: false,
        target_is_ebgp: true,
        target_is_rr_client: false,
        target_local_role: None,
        interpret_rfc1997: true,
        sendable_families: vec![(Afi::Ipv4 as u16, Safi::Unicast as u8)],
        llgr_families: Vec::new(),
        add_path_send: false,
        per_client_best: false,
        orr_vantage: None,
        orf_installed: false,
    };
    UpdateGroupPeerSnapshot {
        peer,
        classification: classify_update_group(input.clone()),
        input,
        runtime_membership: "group:0".to_string(),
    }
}

fn unsorted_mixed_snapshot_peers() -> Vec<IpAddr> {
    vec![
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
    ]
}

#[test]
fn snapshot_peer_order_key_is_fixed_stack_storage() {
    fn require_copy<T: Copy>(value: T) -> T {
        value
    }

    let v4: [u8; 17] = snapshot_peer_order_key(&IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
    let v6: [u8; 17] =
        snapshot_peer_order_key(&IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 1, 2, 3, 4, 5, 6)));
    assert_eq!(v4, [0, 192, 0, 2, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    assert_eq!(
        v6,
        [
            1, 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6
        ]
    );
    assert_eq!(std::mem::size_of_val(&require_copy(v4)), 17);
    assert_eq!(std::mem::align_of_val(&v6), 1);
    assert!(!std::mem::needs_drop::<[u8; 17]>());
}

#[test]
fn snapshot_materializer_uses_stack_key_for_fixed_mixed_roster() {
    let (reply, _receiver) = tokio::sync::oneshot::channel::<UpdateGroupSnapshot>();
    let mut peers = Vec::with_capacity(1_000);
    for index in (0..500_u32).rev() {
        peers.push(IpAddr::V6(Ipv6Addr::from(
            0x2001_0db8_0000_0000_0000_0000_0000_0000_u128 + u128::from(index),
        )));
        peers.push(IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + index)));
    }
    let expected = (0..500_u32)
        .map(|index| IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + index)))
        .chain((0..500_u128).map(|index| {
            IpAddr::V6(Ipv6Addr::from(
                0x2001_0db8_0000_0000_0000_0000_0000_0000_u128 + index,
            ))
        }))
        .collect::<Vec<_>>();
    SNAPSHOT_PEER_ORDER_KEY_CALLS.store(0, std::sync::atomic::Ordering::Relaxed);
    let mut builds = 0;

    let snapshot = materialize_update_group_snapshot(&reply, &mut peers, |peer| {
        builds += 1;
        test_snapshot_row(peer)
    })
    .expect("open snapshot query materializes");

    assert_eq!(snapshot.peers.len(), 1_000);
    assert_eq!(builds, 1_000);
    assert!(
        SNAPSHOT_PEER_ORDER_KEY_CALLS.load(std::sync::atomic::Ordering::Relaxed) >= 1_000,
        "the materializer must route every peer through the stack key helper"
    );
    assert_eq!(
        snapshot
            .peers
            .into_iter()
            .map(|row| row.peer)
            .collect::<Vec<_>>(),
        expected,
        "snapshot order is independently derived from the legacy family/address contract"
    );
}

#[test]
fn canceled_update_group_snapshot_stops_between_sorted_rows() {
    let (reply, receiver) = tokio::sync::oneshot::channel::<UpdateGroupSnapshot>();
    let mut receiver = Some(receiver);
    let mut peers = unsorted_mixed_snapshot_peers();
    let mut observed = Vec::new();

    let snapshot = materialize_update_group_snapshot(&reply, &mut peers, |peer| {
        observed.push(peer);
        if observed.len() == 3 {
            drop(receiver.take());
        }
        test_snapshot_row(peer)
    });

    assert!(snapshot.is_none(), "a canceled snapshot must not be sent");
    assert_eq!(
        observed,
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
        ],
        "cancellation after K=3 row builds must stop before row K+1"
    );
}

#[test]
fn canceled_after_address_collection_does_not_sort_or_build_rows() {
    let (reply, receiver) = tokio::sync::oneshot::channel::<UpdateGroupSnapshot>();
    let mut peers = unsorted_mixed_snapshot_peers();
    let collected_order = peers.clone();
    drop(receiver);

    let snapshot = materialize_update_group_snapshot(&reply, &mut peers, |_| {
        panic!("canceled snapshot built a row")
    });

    assert!(snapshot.is_none());
    assert_eq!(
        peers, collected_order,
        "post-collection cancellation must be observed before sorting"
    );
}

#[test]
fn cancellation_from_last_row_does_not_complete_snapshot() {
    let (reply, receiver) = tokio::sync::oneshot::channel::<UpdateGroupSnapshot>();
    let mut receiver = Some(receiver);
    let mut peers = unsorted_mixed_snapshot_peers();
    let row_count = peers.len();
    let mut built = 0;

    let snapshot = materialize_update_group_snapshot(&reply, &mut peers, |peer| {
        built += 1;
        if built == row_count {
            drop(receiver.take());
        }
        test_snapshot_row(peer)
    });

    assert_eq!(built, row_count, "the receiver closes from the final row");
    assert!(
        snapshot.is_none(),
        "final cancellation must prevent completing the snapshot"
    );
}

#[test]
fn update_group_snapshot_preserves_legacy_mixed_address_order() {
    let (reply, receiver) = tokio::sync::oneshot::channel::<UpdateGroupSnapshot>();
    let mut peers = unsorted_mixed_snapshot_peers();
    send_update_group_snapshot(reply, |reply| {
        materialize_update_group_snapshot(reply, &mut peers, test_snapshot_row)
    });

    let snapshot = receiver
        .blocking_recv()
        .expect("complete snapshot is delivered");
    assert_eq!(
        snapshot
            .peers
            .iter()
            .map(|row| row.peer)
            .collect::<Vec<_>>(),
        vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
        ]
    );
}
use crate::test_support::make_route;

fn comparison_key() -> GroupKey {
    GroupKey {
        chain: Some(1),
        target_is_ebgp: true,
        target_is_rr_client: false,
        target_local_role: None,
        interpret_rfc1997: true,
        sendable_ipv4_unicast: true,
        sendable_ipv6_unicast: false,
        sendable_vpnv4: false,
        sendable_vpnv6: false,
        rtc_negotiated: false,
        per_client_best: false,
        llgr_families: vec![(1, 1)],
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GrowthSnapshot {
    key_slots: usize,
    interned_chains: usize,
    registered_members: usize,
    active_cells: usize,
    active_cell_members: usize,
    inactive_key_slots: usize,
    dirty_peers: usize,
    regroup_baselines: usize,
    extra_withdraw_sets: usize,
}

fn growth_snapshot(manager: &RibManager) -> GrowthSnapshot {
    let active_cells = manager.group_ribs.len();
    GrowthSnapshot {
        key_slots: manager.update_groups.groups.len(),
        interned_chains: manager.update_groups.chains.len(),
        registered_members: manager.update_groups.members.len(),
        active_cells,
        active_cell_members: manager
            .group_ribs
            .values()
            .map(|group| group.members.len())
            .sum(),
        inactive_key_slots: manager
            .update_groups
            .groups
            .len()
            .saturating_sub(active_cells),
        dirty_peers: manager.dirty_peers.len(),
        regroup_baselines: manager.pending_regroup_baseline.len(),
        extra_withdraw_sets: manager.pending_extra_withdraws.len(),
    }
}

fn empty_policy(default_action: PolicyAction) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: Vec::new(),
        default_action,
    }])
}

fn register_growth_peer(
    manager: &mut RibManager,
    peer: IpAddr,
    session_id: u64,
) -> tokio::sync::mpsc::Receiver<crate::update::OutboundRouteUpdate> {
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel(16);
    manager.handle_update(crate::RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65_000,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
    assert_eq!(
        outbound_rx.try_recv().unwrap().end_of_rib,
        vec![(Afi::Ipv4, Safi::Unicast)]
    );
    outbound_rx
}

fn replace_growth_policy(manager: &mut RibManager, peer: IpAddr, policy: Option<PolicyChain>) {
    assert_eq!(
        manager.replace_peer_export_policy_synchronously(peer, policy),
        Ok(())
    );
}

/// Load-bearing bounded-growth regression: removing the production
/// membership erase in `remove_update_group_member`, or the empty-cell
/// reap in `leave_group_without_gauge_refresh`, makes the post-delete
/// snapshot differ from `quiescent` on the first completed cycle.
#[test]
fn repeated_regroup_delete_recreate_returns_to_bounded_state() {
    const REPEATED_CYCLES: u64 = 16;
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let (_query_tx, query_rx) = tokio::sync::mpsc::channel(1);
    let mut manager = RibManager::new(
        rx,
        query_rx,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    );
    let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 45));
    let permit = empty_policy(PolicyAction::Permit);
    let deny = empty_policy(PolicyAction::Deny);

    // Warm the finite key set once. The registry deliberately retains one
    // slot per distinct key/chain for process-stable group IDs; the live
    // group cell and every member/transient entry must still be reaped.
    let receiver = register_growth_peer(&mut manager, peer, 1);
    replace_growth_policy(&mut manager, peer, Some(permit.clone()));
    replace_growth_policy(&mut manager, peer, Some(deny.clone()));
    replace_growth_policy(&mut manager, peer, None);
    manager.handle_update(crate::RibUpdate::PeerDown {
        peer,
        session_id: 1,
    });
    manager.handle_update(crate::RibUpdate::PeerDeleted { peer });
    drop(receiver);

    let active = GrowthSnapshot {
        key_slots: 3,
        interned_chains: 2,
        registered_members: 1,
        active_cells: 1,
        active_cell_members: 1,
        inactive_key_slots: 2,
        dirty_peers: 0,
        regroup_baselines: 0,
        extra_withdraw_sets: 0,
    };
    let quiescent = GrowthSnapshot {
        key_slots: 3,
        interned_chains: 2,
        registered_members: 0,
        active_cells: 0,
        active_cell_members: 0,
        inactive_key_slots: 3,
        dirty_peers: 0,
        regroup_baselines: 0,
        extra_withdraw_sets: 0,
    };
    assert_eq!(growth_snapshot(&manager), quiescent, "warm-up teardown");

    for cycle in 0..REPEATED_CYCLES {
        let session_id = cycle + 2;
        let receiver = register_growth_peer(&mut manager, peer, session_id);
        assert_eq!(growth_snapshot(&manager), active, "cycle {cycle}: join");

        replace_growth_policy(&mut manager, peer, Some(permit.clone()));
        assert_eq!(
            growth_snapshot(&manager),
            active,
            "cycle {cycle}: first regroup"
        );
        replace_growth_policy(&mut manager, peer, Some(deny.clone()));
        assert_eq!(
            growth_snapshot(&manager),
            active,
            "cycle {cycle}: second regroup"
        );
        replace_growth_policy(&mut manager, peer, None);
        assert_eq!(
            growth_snapshot(&manager),
            active,
            "cycle {cycle}: return regroup"
        );

        manager.handle_update(crate::RibUpdate::PeerDown { peer, session_id });
        manager.handle_update(crate::RibUpdate::PeerDeleted { peer });
        drop(receiver);
        assert_eq!(
            growth_snapshot(&manager),
            quiescent,
            "cycle {cycle}: delete must return to the bounded steady state"
        );
    }
}

fn compare(manager: &mut RibManager, left: IpAddr, right: IpAddr) -> UpdateGroupPeerComparison {
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    manager.handle_update(crate::RibUpdate::QueryUpdateGroupComparison {
        primary: left,
        comparison: right,
        reply: tx,
    });
    rx.try_recv().unwrap()
}

#[test]
fn comparison_reasons_cover_every_group_key_axis() {
    use UpdateGroupComparisonDifference as D;
    let base = comparison_key();
    macro_rules! check {
        ($field:ident = $value:expr => $reason:expr) => {{
            let mut key = base.clone();
            key.$field = $value;
            assert_eq!(grouped_differences(&base, &key), vec![$reason]);
        }};
    }
    check!(chain = Some(2) => D::ExportPolicy);
    check!(target_is_ebgp = false => D::SessionKind);
    check!(target_is_rr_client = true => D::RouteReflectorClient);
    check!(target_local_role = Some(1) => D::LocalRole);
    check!(interpret_rfc1997 = false => D::Rfc1997Mode);
    check!(sendable_ipv4_unicast = false => D::NegotiatedFamilies);
    check!(sendable_ipv6_unicast = true => D::NegotiatedFamilies);
    check!(sendable_vpnv4 = true => D::NegotiatedFamilies);
    check!(sendable_vpnv6 = true => D::NegotiatedFamilies);
    check!(rtc_negotiated = true => D::NegotiatedFamilies);
    check!(per_client_best = true => D::PerClientBest);
    check!(llgr_families = vec![(2, 1)] => D::LlgrFamilies);
    let mut combined = base.clone();
    combined.chain = None;
    combined.target_is_ebgp = false;
    combined.sendable_ipv4_unicast = false;
    combined.sendable_ipv6_unicast = true;
    combined.llgr_families.clear();
    assert_eq!(
        grouped_differences(&base, &combined),
        vec![
            D::ExportPolicy,
            D::SessionKind,
            D::NegotiatedFamilies,
            D::LlgrFamilies,
        ]
    );
}

#[test]
fn comparison_verdicts_use_runtime_identity_and_preserve_sides() {
    use UpdateGroupComparisonMembership as M;
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let (_query_tx, query_rx) = tokio::sync::mpsc::channel(1);
    let mut manager = RibManager::new(
        rx,
        query_rx,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    );
    manager.update_groups.groups = vec![comparison_key(), comparison_key()];
    manager
        .update_groups
        .members
        .insert(MEMBER, GroupMembership::Grouped(0));
    manager
        .update_groups
        .members
        .insert(OTHER1, GroupMembership::Grouped(1));
    let separate = compare(&mut manager, MEMBER, OTHER1);
    assert_eq!(separate.verdict, UpdateGroupComparisonVerdict::Separate);
    assert_eq!(separate.primary_update_group, "group:0");
    assert!(separate.differences.is_empty());
    assert_eq!(
        compare(&mut manager, MEMBER, OTHER2).verdict,
        UpdateGroupComparisonVerdict::Unknown
    );
    assert_eq!(
        compare(&mut manager, OTHER2, MEMBER).verdict,
        UpdateGroupComparisonVerdict::Unknown
    );
    let absent: IpAddr = "192.0.2.254".parse().unwrap();
    assert_eq!(
        compare(&mut manager, OTHER2, absent).verdict,
        UpdateGroupComparisonVerdict::Unknown
    );

    for (private, expected) in [
        (GroupMembership::PolicyPeerContext, M::PolicyPeerContext),
        (GroupMembership::AddPathSend, M::AddPathSend),
        (GroupMembership::PerClientBest, M::PerClientBest),
        (GroupMembership::OrrVantage, M::OrrVantage),
        (GroupMembership::OrfInstalled, M::OrfInstalled),
        (GroupMembership::SlowPeer, M::SlowPeer),
    ] {
        manager.update_groups.members.insert(OTHER1, private);
        assert_eq!(
            compare(&mut manager, OTHER2, OTHER1).verdict,
            UpdateGroupComparisonVerdict::Unknown
        );
        let left = compare(&mut manager, OTHER1, MEMBER);
        let right = compare(&mut manager, MEMBER, OTHER1);
        assert_eq!(
            (left.verdict, left.primary_membership),
            (UpdateGroupComparisonVerdict::Private, expected)
        );
        assert_eq!(
            (right.verdict, right.comparison_membership),
            (UpdateGroupComparisonVerdict::Private, expected)
        );
        assert_eq!(right.primary_membership, M::Grouped);
    }
    manager
        .update_groups
        .members
        .insert(OTHER1, GroupMembership::Grouped(0));
    assert_eq!(
        compare(&mut manager, MEMBER, OTHER1).verdict,
        UpdateGroupComparisonVerdict::Shared
    );
}

#[test]
fn effective_distribution_mode_precedence_is_deterministic() {
    use crate::EffectiveDistributionMode;

    assert_eq!(
        classify_effective_distribution_mode(false, true, true, true),
        EffectiveDistributionMode::Unknown
    );
    assert_eq!(
        classify_effective_distribution_mode(true, true, true, true),
        EffectiveDistributionMode::AddPath
    );
    assert_eq!(
        classify_effective_distribution_mode(true, false, true, true),
        EffectiveDistributionMode::PerClientBest
    );
    assert_eq!(
        classify_effective_distribution_mode(true, false, false, true),
        EffectiveDistributionMode::Orr
    );
    assert_eq!(
        classify_effective_distribution_mode(true, false, false, false),
        EffectiveDistributionMode::SingleBest
    );
}

#[test]
fn uncommitted_policy_transition_cleanup_refuses_owned_groups() {
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let (_query_tx, query_rx) = tokio::sync::mpsc::channel(1);
    let mut manager = RibManager::new(
        rx,
        query_rx,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    );
    manager.group_ribs.insert(7, empty_group());
    assert!(manager.discard_uncommitted_policy_transition_group(7));
    assert!(!manager.group_ribs.contains_key(&7));

    let mut owned = empty_group();
    owned.members.insert(MEMBER);
    manager.group_ribs.insert(8, owned);
    assert!(!manager.discard_uncommitted_policy_transition_group(8));
    assert!(manager.group_ribs.contains_key(&8));
}

const MEMBER: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1));
const OTHER1: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 2));
const OTHER2: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 3));

fn prefix(n: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 100, n, 0), 24))
}

fn route(p: Prefix, src: IpAddr) -> Route {
    let Prefix::V4(v4) = p else { unreachable!() };
    let IpAddr::V4(src4) = src else {
        unreachable!()
    };
    let mut route = make_route(v4, src4);
    route.peer = src;
    route
}

fn empty_group() -> GroupRibOut {
    GroupRibOut::new(
        None,
        false,
        false,
        true,
        None,
        vec![(Afi::Ipv4, Safi::Unicast)],
        vec![],
        false,
        0,
    )
}

/// Per-client-best sibling of [`empty_group`] with a caller-chosen
/// export chain — the ONLY way a per-client-best group can exist
/// until the ADR-0126 Phase 3 classifier flip.
fn per_client_best_group(chain: Option<PolicyChain>) -> GroupRibOut {
    GroupRibOut::new(
        chain,
        false,
        false,
        true,
        None,
        vec![(Afi::Ipv4, Safi::Unicast)],
        vec![],
        true,
        0,
    )
}

fn announce_delta(p: Prefix, src: IpAddr, old: Option<IpAddr>) -> GroupDelta {
    let new = route(p, src);
    let source_attrs = capture_source_attrs(&new);
    GroupDelta {
        prefix: p,
        path_id: 0,
        new: Some((new, None)),
        old_source: old,
        policy_label: None,
        source_attrs,
        lane: None,
    }
}

fn withdraw_delta(p: Prefix, old: Option<IpAddr>) -> GroupDelta {
    GroupDelta {
        prefix: p,
        path_id: 0,
        new: None,
        old_source: old,
        policy_label: None,
        source_attrs: None,
        lane: None,
    }
}

/// Risk-2 exhaustive source-flip matrix: every combination of
/// `{old_source} × {new source | withdraw}` for a fixed member,
/// asserted against the per-peer-path reference semantics:
///
/// - the member HAD the key iff an old entry existed with a source
///   other than the member (split horizon excluded own-sourced);
/// - the member GETS the key iff the new entry exists with a source
///   other than the member;
/// - expected announce ⇔ GETS; expected withdraw ⇔ HAD ∧ ¬GETS
///   (announce-replaces is BGP implicit withdraw).
#[test]
fn source_flip_matrix_exhaustive() {
    let old_sources = [None, Some(MEMBER), Some(OTHER1), Some(OTHER2)];
    // `None` = withdraw delta; `Some(src)` = announce sourced by src.
    let new_sources = [None, Some(MEMBER), Some(OTHER1), Some(OTHER2)];
    for old in old_sources {
        for new in new_sources {
            if new.is_none() && old.is_none() {
                // A withdraw delta always has an old entry (the
                // staging body only withdraws existing keys).
                continue;
            }
            let p = prefix(1);
            let delta = match new {
                Some(src) => announce_delta(p, src, old),
                None => withdraw_delta(p, old),
            };
            let mut announce = Vec::new();
            let mut withdraw = Vec::new();
            let mut nh_flags = Vec::new();
            emit_group_deltas_for_member(
                std::slice::from_ref(&delta),
                MEMBER,
                None,
                &mut announce,
                &mut withdraw,
                &mut nh_flags,
            );

            let member_had = old.is_some_and(|s| s != MEMBER);
            let member_gets = new.is_some_and(|s| s != MEMBER);
            let expect_announce = usize::from(member_gets);
            let expect_withdraw = usize::from(member_had && !member_gets);
            assert_eq!(
                announce.len(),
                expect_announce,
                "announce mismatch for old={old:?} new={new:?}"
            );
            assert_eq!(
                withdraw.len(),
                expect_withdraw,
                "withdraw mismatch for old={old:?} new={new:?}"
            );
            assert_eq!(
                nh_flags.len(),
                announce.len(),
                "nh flags must stay aligned with announces"
            );
            if member_gets {
                assert_eq!(announce[0].peer, new.unwrap());
            }
        }
    }
}

// --- ADR-0126 Phase 1: per-client-best group staging (winner walk
// --- + exception lane), dark behind the unchanged classifier. The
// --- groups below exist only because these tests construct them.

use crate::adj_rib_in::AdjRibIn;
use crate::test_support::make_route_with_lp;

const PCB_GID: usize = 91;

fn staging_manager() -> RibManager {
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let (_query_tx, query_rx) = tokio::sync::mpsc::channel(1);
    RibManager::new(
        rx,
        query_rx,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    )
}

/// A candidate with a controlled best-path rank (higher `lp` ranks
/// first) whose next hop IS its source peer, so a
/// [`deny_next_hop_statement`] discriminates candidates per source.
fn cand(p: Prefix, src: IpAddr, lp: u32) -> Route {
    let Prefix::V4(v4) = p else { unreachable!() };
    let IpAddr::V4(src4) = src else {
        unreachable!()
    };
    make_route_with_lp(v4, src4, lp)
}

/// Seed one Adj-RIB-In candidate plus the announcing-peers reverse
/// index — everything the per-client-best walk reads.
fn seed(manager: &mut RibManager, route: Route) {
    let peers = manager
        .unicast_prefix_peers
        .entry(route.prefix)
        .or_default();
    if !peers.contains(&route.peer) {
        peers.push(route.peer);
    }
    manager
        .ribs
        .entry(route.peer)
        .or_insert_with(|| AdjRibIn::new(route.peer))
        .insert(route);
}

fn unseed(manager: &mut RibManager, peer: IpAddr, p: Prefix) {
    if let Some(rib) = manager.ribs.get_mut(&peer) {
        rib.withdraw(&p, 0);
    }
    if let Some(peers) = manager.unicast_prefix_peers.get_mut(&p) {
        peers.retain(|entry| *entry != peer);
    }
}

fn stage_pcb(manager: &mut RibManager, prefixes: &[Prefix]) -> GroupStageOutput {
    let set: HashSet<Prefix> = prefixes.iter().copied().collect();
    let mut memo = super::super::distribution::ExportMemo::default();
    manager.stage_group_prefixes(PCB_GID, &set, &mut memo)
}

fn deny_next_hop_statement(next_hop: IpAddr) -> PolicyStatement {
    PolicyStatement {
        prefix: None,
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
        match_next_hop: Some(next_hop),
        modifications: RouteModifications::default(),
    }
}

/// Chain denying the given sources (by their next hop), permitting
/// everything else.
fn deny_sources_chain(denied: &[IpAddr]) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: denied
            .iter()
            .copied()
            .map(deny_next_hop_statement)
            .collect(),
        default_action: PolicyAction::Permit,
    }])
}

/// (permits, denies) summed over the accumulator's totals rows.
fn eval_totals(evals: &GroupEvalAccumulator) -> (u64, u64) {
    let mut permits = 0;
    let mut denies = 0;
    for (_, action, n) in &evals.totals {
        match action {
            PolicyAction::Permit => permits += n,
            PolicyAction::Deny => denies += n,
        }
    }
    (permits, denies)
}

/// Source peers with at least one recorded per-source row — the
/// candidates the walk actually evaluated.
fn eval_sources(evals: &GroupEvalAccumulator) -> HashSet<IpAddr> {
    evals.per_source.keys().copied().collect()
}

fn lane_source(manager: &RibManager, p: Prefix) -> Option<IpAddr> {
    manager
        .group_ribs
        .get(&PCB_GID)
        .unwrap()
        .runner_up
        .get(&p)
        .map(|entry| entry.route.peer)
}

/// Sorted `(winner_source, [v4, v6])` rows of the group's
/// `lane_counts`.
fn lane_count_rows(manager: &RibManager) -> Vec<(IpAddr, [usize; 2])> {
    let mut rows: Vec<(IpAddr, [usize; 2])> = manager
        .group_ribs
        .get(&PCB_GID)
        .unwrap()
        .lane_counts
        .iter()
        .map(|(&peer, &counts)| (peer, counts))
        .collect();
    rows.sort();
    rows
}

/// [`cand`] plus one standard community — a source-attribute
/// difference a [`strip_communities_chain`] erases post-policy.
fn cand_with_comm(p: Prefix, src: IpAddr, lp: u32, comm: u32) -> Route {
    let mut route = cand(p, src, lp);
    let mut attrs = (*route.attributes).clone();
    attrs.push(PathAttribute::Communities(vec![comm]));
    route.attributes = Arc::new(attrs);
    route
}

/// Permit-all chain whose modifications remove the given
/// communities, so candidates differing only in them converge to
/// one post-policy form.
fn strip_communities_chain(comms: Vec<u32>) -> PolicyChain {
    PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            action: PolicyAction::Permit,
            match_next_hop: None,
            modifications: RouteModifications {
                communities_remove: comms,
                ..RouteModifications::default()
            },
            ..deny_next_hop_statement(OTHER1)
        }],
        default_action: PolicyAction::Permit,
    }])
}

/// Winner = best permitted candidate, lane = first distinct-source
/// permitted candidate, early exit before the third candidate.
#[test]
fn pcb_winner_and_lane_from_permitted_candidates() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    seed(&mut m, cand(p, MEMBER, 100));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));

    let out = stage_pcb(&mut m, &[p]);

    assert_eq!(out.deltas.len(), 1);
    let delta = &out.deltas[0];
    let (winner, _) = delta.new.as_ref().expect("winner announce");
    assert_eq!((winner.peer, winner.path_id), (OTHER1, 0));
    assert_eq!(delta.old_source, None);
    assert_eq!(out.lane_deltas.len(), 1);
    assert_eq!(
        out.lane_deltas[0].new.as_ref().map(|r| r.route.peer),
        Some(OTHER2)
    );
    assert_eq!(out.lane_deltas[0].old_source, None);

    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(group.table.get(&p, 0).map(|r| r.peer), Some(OTHER1));
    assert_eq!(lane_source(&m, p), Some(OTHER2));
    // Early exit: the third candidate is never evaluated.
    assert_eq!(eval_totals(&out.evals), (2, 0));
    assert_eq!(eval_sources(&out.evals), HashSet::from([OTHER1, OTHER2]));
}

/// ADR-0126 divergence 2: the chain denies the best candidate, the
/// walk stages the first permitted one (where plain grouped staging
/// stages nothing), and the denial is recorded with residue.
#[test]
fn pcb_denied_best_walks_to_first_permitted() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    seed(&mut m, cand(p, MEMBER, 100));
    m.group_ribs.insert(
        PCB_GID,
        per_client_best_group(Some(deny_sources_chain(&[OTHER1]))),
    );

    let out = stage_pcb(&mut m, &[p]);

    assert_eq!(out.deltas.len(), 1);
    let (winner, _) = out.deltas[0].new.as_ref().expect("winner announce");
    assert_eq!(winner.peer, OTHER2);
    assert_eq!(lane_source(&m, p), Some(MEMBER));
    assert_eq!(eval_totals(&out.evals), (2, 1));
    assert_eq!(
        eval_sources(&out.evals),
        HashSet::from([OTHER1, OTHER2, MEMBER])
    );
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert!(
        group
            .policy_filtered
            .get(&p)
            .is_some_and(|denials| denials.contains_key(&(OTHER1, 0)))
    );
}

/// A same-source remainder is stepped over WITHOUT evaluation: the
/// winner's source never sees its own candidates (split horizon)
/// and every other member stops at the winner, so no per-peer walk
/// records those evals.
#[test]
fn pcb_same_source_remainder_leaves_lane_empty_without_evals() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    let mut second = cand(p, OTHER1, 200);
    second.path_id = 1;
    seed(&mut m, second);
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));

    let out = stage_pcb(&mut m, &[p]);

    assert_eq!(out.deltas.len(), 1);
    assert_eq!(lane_source(&m, p), None);
    assert!(out.lane_deltas.is_empty());
    assert_eq!(eval_totals(&out.evals), (1, 0));
    assert_eq!(eval_sources(&out.evals), HashSet::from([OTHER1]));
}

/// All candidates denied: nothing staged, the existing entry is
/// withdrawn, and the lane clears through the same transition
/// encoding (no early exit — every candidate is evaluated).
#[test]
fn pcb_all_denied_withdraws_and_clears_lane() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    let mut group = per_client_best_group(Some(empty_policy(PolicyAction::Deny)));
    group.apply_delta(&announce_delta(p, OTHER1, None));
    group.apply_lane(
        p,
        Some(RunnerUp {
            route: route(p, OTHER2),
            nh: None,
            source_attrs: None,
            policy_label: None,
            winner_source: OTHER1,
        }),
    );
    m.group_ribs.insert(PCB_GID, group);

    let out = stage_pcb(&mut m, &[p]);

    assert_eq!(out.deltas.len(), 1);
    assert!(out.deltas[0].new.is_none(), "withdraw of path_id 0");
    assert_eq!(out.deltas[0].old_source, Some(OTHER1));
    assert_eq!(out.lane_deltas.len(), 1);
    assert!(out.lane_deltas[0].new.is_none());
    assert_eq!(out.lane_deltas[0].old_source, Some(OTHER2));
    assert_eq!(lane_source(&m, p), None);
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert!(group.table.get(&p, 0).is_none());
    assert_eq!(eval_totals(&out.evals), (0, 2));
}

/// No candidates at all: same withdraw + lane-clear shape, zero
/// evaluations.
#[test]
fn pcb_no_candidates_stages_nothing_and_clears() {
    let mut m = staging_manager();
    let p = prefix(1);
    let mut group = per_client_best_group(None);
    group.apply_delta(&announce_delta(p, OTHER1, None));
    group.apply_lane(
        p,
        Some(RunnerUp {
            route: route(p, OTHER2),
            nh: None,
            source_attrs: None,
            policy_label: None,
            winner_source: OTHER1,
        }),
    );
    m.group_ribs.insert(PCB_GID, group);

    let out = stage_pcb(&mut m, &[p]);

    assert_eq!(out.deltas.len(), 1);
    assert!(out.deltas[0].new.is_none());
    assert_eq!(out.lane_deltas.len(), 1);
    assert!(out.lane_deltas[0].new.is_none());
    assert_eq!(lane_source(&m, p), None);
    assert_eq!(eval_totals(&out.evals), (0, 0));
}

/// Single candidate: winner staged, lane empty, one evaluation.
#[test]
fn pcb_single_candidate_winner_no_lane() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));

    let out = stage_pcb(&mut m, &[p]);

    assert_eq!(out.deltas.len(), 1);
    let (winner, _) = out.deltas[0].new.as_ref().expect("winner announce");
    assert_eq!(winner.peer, OTHER1);
    assert_eq!(lane_source(&m, p), None);
    assert!(out.lane_deltas.is_empty());
    assert_eq!(eval_totals(&out.evals), (1, 0));
}

/// The take-last hazard pin: the winner's staged label is captured
/// at the winner's own permit point. A trailing denial (evaluated
/// while searching for a runner-up) is the accumulator's LAST
/// evaluation — labeling the staged entry from `take_last` would
/// stamp the winner with the denying policy.
#[test]
fn pcb_winner_label_is_captured_at_its_permit_point() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    let mut chain = PolicyChain::new(vec![
        Policy {
            entries: vec![deny_next_hop_statement(OTHER2)],
            default_action: PolicyAction::Permit,
        },
        Policy {
            entries: Vec::new(),
            default_action: PolicyAction::Permit,
        },
    ]);
    chain.policies[0].name = Some("screen".to_string());
    chain.policies[1].name = Some("tail".to_string());
    m.group_ribs
        .insert(PCB_GID, per_client_best_group(Some(chain)));

    let out = stage_pcb(&mut m, &[p]);

    assert_eq!(out.deltas.len(), 1);
    // Chain permits attribute to the LAST policy; the trailing
    // denial attributes to "screen". The winner keeps "tail".
    assert_eq!(out.deltas[0].policy_label.as_deref(), Some("tail"));
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(
        group
            .staged_labels
            .get(&(p, 0))
            .and_then(|label| label.as_deref()),
        Some("tail")
    );
    assert_eq!(
        group
            .policy_filtered
            .get(&p)
            .and_then(|denials| denials.get(&(OTHER2, 0)))
            .and_then(|label| label.as_deref()),
        Some("screen")
    );
    assert_eq!(lane_source(&m, p), None);
    assert_eq!(eval_totals(&out.evals), (1, 1));
}

/// The ADR-0126 Decision 5 lane/source-flip matrix: every lane
/// transition ({appears, content-flip, source-flip, retires,
/// unchanged}) crossed with the winner axis ({unchanged,
/// content-change, source-flip}), asserted on the pass-2 delta
/// encoding AND the committed lane state. A content-equal
/// same-source lane reinstall is suppressed (no transition); a
/// source flip never is (`routes_equal` includes the source peer).
///
/// "Winner source-flip × lane unchanged" is realized with a NEW
/// distinct source overtaking the old winner — with a static chain
/// the retiring winner's lane successor is otherwise the new
/// winner itself, so this is the only reachable shape of that cell.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive lane/source-flip matrix enumerates every cell inline"
)]
fn pcb_lane_transition_matrix_exhaustive() {
    const A: IpAddr = OTHER1;
    const B: IpAddr = OTHER2;
    const C: IpAddr = MEMBER;
    struct Case {
        name: &'static str,
        initial: &'static [(IpAddr, u32)],
        remove: &'static [IpAddr],
        add: &'static [(IpAddr, u32)],
        /// Expected pass-2 winner announce as (source,
        /// `old_source`); `None` = equality-suppressed (winner
        /// unchanged).
        expect_winner: Option<(IpAddr, Option<IpAddr>)>,
        /// Expected pass-2 lane transition as (new source or
        /// `None` = lane empties, old lane source); outer `None` =
        /// suppressed (no transition).
        expect_lane: Option<(Option<IpAddr>, Option<IpAddr>)>,
        /// Committed lane content after pass 2.
        lane_state: Option<IpAddr>,
    }
    let cases = [
        Case {
            name: "appears/winner-unchanged",
            initial: &[(A, 300)],
            remove: &[],
            add: &[(B, 200)],
            expect_winner: None,
            expect_lane: Some((Some(B), None)),
            lane_state: Some(B),
        },
        Case {
            name: "content-flip/winner-unchanged (lane-only delta)",
            initial: &[(A, 300), (B, 200)],
            remove: &[],
            add: &[(B, 250)],
            expect_winner: None,
            expect_lane: Some((Some(B), Some(B))),
            lane_state: Some(B),
        },
        Case {
            name: "source-flip/winner-unchanged (lane-only delta)",
            initial: &[(A, 300), (B, 200), (C, 100)],
            remove: &[B],
            add: &[],
            expect_winner: None,
            expect_lane: Some((Some(C), Some(B))),
            lane_state: Some(C),
        },
        Case {
            name: "retires/winner-unchanged (lane-only delta)",
            initial: &[(A, 300), (B, 200)],
            remove: &[B],
            add: &[],
            expect_winner: None,
            expect_lane: Some((None, Some(B))),
            lane_state: None,
        },
        Case {
            name: "unchanged/winner-unchanged (content-equal reinstall suppressed)",
            initial: &[(A, 300), (B, 200)],
            remove: &[],
            add: &[(B, 200)],
            expect_winner: None,
            expect_lane: None,
            lane_state: Some(B),
        },
        Case {
            name: "appears/winner-content-change",
            initial: &[(A, 300)],
            remove: &[],
            add: &[(A, 400), (B, 200)],
            expect_winner: Some((A, Some(A))),
            expect_lane: Some((Some(B), None)),
            lane_state: Some(B),
        },
        Case {
            name: "content-flip/winner-content-change",
            initial: &[(A, 300), (B, 200)],
            remove: &[],
            add: &[(A, 400), (B, 250)],
            expect_winner: Some((A, Some(A))),
            expect_lane: Some((Some(B), Some(B))),
            lane_state: Some(B),
        },
        Case {
            name: "source-flip/winner-content-change",
            initial: &[(A, 300), (B, 200), (C, 100)],
            remove: &[B],
            add: &[(A, 400)],
            expect_winner: Some((A, Some(A))),
            expect_lane: Some((Some(C), Some(B))),
            lane_state: Some(C),
        },
        Case {
            name: "retires/winner-content-change",
            initial: &[(A, 300), (B, 200)],
            remove: &[B],
            add: &[(A, 400)],
            expect_winner: Some((A, Some(A))),
            expect_lane: Some((None, Some(B))),
            lane_state: None,
        },
        Case {
            name: "unchanged/winner-content-change",
            initial: &[(A, 300), (B, 200)],
            remove: &[],
            add: &[(A, 400)],
            expect_winner: Some((A, Some(A))),
            expect_lane: None,
            lane_state: Some(B),
        },
        Case {
            name: "appears/winner-source-flip",
            initial: &[(A, 300)],
            remove: &[A],
            add: &[(B, 200), (C, 100)],
            expect_winner: Some((B, Some(A))),
            expect_lane: Some((Some(C), None)),
            lane_state: Some(C),
        },
        Case {
            name: "content-flip/winner-source-flip",
            initial: &[(A, 400), (C, 200)],
            remove: &[A],
            add: &[(B, 300), (C, 250)],
            expect_winner: Some((B, Some(A))),
            expect_lane: Some((Some(C), Some(C))),
            lane_state: Some(C),
        },
        Case {
            name: "source-flip/winner-source-flip",
            initial: &[(A, 400), (B, 300), (C, 200)],
            remove: &[A],
            add: &[],
            expect_winner: Some((B, Some(A))),
            expect_lane: Some((Some(C), Some(B))),
            lane_state: Some(C),
        },
        Case {
            name: "retires/winner-source-flip",
            initial: &[(A, 400), (B, 300)],
            remove: &[A],
            add: &[],
            expect_winner: Some((B, Some(A))),
            expect_lane: Some((None, Some(B))),
            lane_state: None,
        },
        Case {
            name: "unchanged/winner-source-flip (lane suppressed across the flip)",
            initial: &[(A, 400), (C, 200)],
            remove: &[A],
            add: &[(B, 300)],
            expect_winner: Some((B, Some(A))),
            expect_lane: None,
            lane_state: Some(C),
        },
    ];
    for case in &cases {
        let mut m = staging_manager();
        let p = prefix(7);
        m.group_ribs.insert(PCB_GID, per_client_best_group(None));
        for &(src, lp) in case.initial {
            seed(&mut m, cand(p, src, lp));
        }
        let _ = stage_pcb(&mut m, &[p]);
        for &src in case.remove {
            unseed(&mut m, src, p);
        }
        for &(src, lp) in case.add {
            seed(&mut m, cand(p, src, lp));
        }

        let out = stage_pcb(&mut m, &[p]);

        let announces: Vec<&GroupDelta> = out.deltas.iter().filter(|d| d.new.is_some()).collect();
        match case.expect_winner {
            Some((src, old)) => {
                assert_eq!(announces.len(), 1, "{}: winner delta count", case.name);
                let delta = announces[0];
                let (winner, _) = delta.new.as_ref().unwrap();
                assert_eq!(winner.peer, src, "{}: winner source", case.name);
                assert_eq!(delta.old_source, old, "{}: winner old_source", case.name);
            }
            None => {
                assert!(
                    announces.is_empty(),
                    "{}: winner delta must be suppressed",
                    case.name
                );
            }
        }
        assert!(
            out.deltas.iter().all(|d| d.new.is_some()),
            "{}: no withdraw deltas in this matrix",
            case.name
        );
        match case.expect_lane {
            Some((new, old)) => {
                assert_eq!(out.lane_deltas.len(), 1, "{}: lane delta count", case.name);
                let lane = &out.lane_deltas[0];
                assert_eq!(lane.prefix, p, "{}: lane prefix", case.name);
                assert_eq!(
                    lane.new.as_ref().map(|entry| entry.route.peer),
                    new,
                    "{}: lane new source",
                    case.name
                );
                assert_eq!(lane.old_source, old, "{}: lane old_source", case.name);
            }
            None => {
                assert!(
                    out.lane_deltas.is_empty(),
                    "{}: lane transition must be suppressed",
                    case.name
                );
            }
        }
        assert_eq!(
            lane_source(&m, p),
            case.lane_state,
            "{}: committed lane state",
            case.name
        );
    }
}

/// [`RunnerUp::winner_source`] carries the source of the winner the
/// lane entry substitutes for — in the ordinary case AND when the
/// walk stepped past a denied Loc-RIB best, where the winner is
/// NOT the best and no seam could re-derive it from the Loc-RIB.
#[test]
fn pcb_runner_up_records_winner_source() {
    // Ordinary: winner OTHER1, runner-up OTHER2.
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let out = stage_pcb(&mut m, &[p]);
    let lane = out.lane_deltas[0].new.as_ref().expect("lane announce");
    assert_eq!((lane.route.peer, lane.winner_source), (OTHER2, OTHER1));
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(
        group.runner_up.get(&p).map(|entry| entry.winner_source),
        Some(OTHER1)
    );

    // Denied best (the `pcb_denied_best_walks_to_first_permitted`
    // scenario): the chain denies OTHER1, the winner walks on to
    // OTHER2, and the lane entry substitutes for OTHER2.
    let mut m = staging_manager();
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    seed(&mut m, cand(p, MEMBER, 100));
    m.group_ribs.insert(
        PCB_GID,
        per_client_best_group(Some(deny_sources_chain(&[OTHER1]))),
    );
    let out = stage_pcb(&mut m, &[p]);
    let lane = out.lane_deltas[0].new.as_ref().expect("lane announce");
    assert_eq!((lane.route.peer, lane.winner_source), (MEMBER, OTHER2));
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(
        group.runner_up.get(&p).map(|entry| entry.winner_source),
        Some(OTHER2)
    );
}

/// `lane_counts` lifecycle: insert increments the winner-source
/// row, a content replace under the same winner leaves it alone,
/// and lane removal drops the zeroed row.
#[test]
fn pcb_lane_counts_insert_replace_remove() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));

    let _ = stage_pcb(&mut m, &[p]);
    assert_eq!(lane_count_rows(&m), vec![(OTHER1, [1, 0])]);

    // Content replace, same winner source: a lane transition is
    // recorded, the count row is unchanged.
    seed(&mut m, cand(p, OTHER2, 250));
    let out = stage_pcb(&mut m, &[p]);
    assert_eq!(out.lane_deltas.len(), 1);
    assert_eq!(lane_count_rows(&m), vec![(OTHER1, [1, 0])]);

    // Runner-up retires: the lane empties, the zeroed row drops.
    unseed(&mut m, OTHER2, p);
    let out = stage_pcb(&mut m, &[p]);
    assert_eq!(out.lane_deltas.len(), 1);
    assert!(out.lane_deltas[0].new.is_none());
    assert!(lane_count_rows(&m).is_empty());
}

/// Winner source-flip under an unchanged runner-up: the lane route
/// is content-equal so NO [`LaneDelta`] is encoded, yet the count
/// must move from the old winner's row to the new one's — exactly
/// what `apply_lane`'s unconditional replace (Decision 6) carries.
#[test]
fn pcb_lane_count_moves_on_winner_flip_without_lane_delta() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 400));
    seed(&mut m, cand(p, MEMBER, 200));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let _ = stage_pcb(&mut m, &[p]);
    assert_eq!(lane_count_rows(&m), vec![(OTHER1, [1, 0])]);

    // OTHER1 retires, a NEW distinct source OTHER2 overtakes:
    // winner OTHER1 → OTHER2, runner-up stays MEMBER.
    unseed(&mut m, OTHER1, p);
    seed(&mut m, cand(p, OTHER2, 300));
    let out = stage_pcb(&mut m, &[p]);
    assert!(
        out.lane_deltas.is_empty(),
        "unchanged lane route is suppressed across the winner flip"
    );
    assert_eq!(lane_source(&m, p), Some(MEMBER));
    assert_eq!(lane_count_rows(&m), vec![(OTHER2, [1, 0])]);
}

/// ADR-0126 Decision 5: lane entries carry SOURCE attributes so
/// rs-control tag transitions extend to them. A control-community
/// change on the runner-up's source that the chain erases
/// post-policy must still record a [`LaneDelta`]; full equality —
/// post-policy route AND source-control input — stays suppressed.
/// (`capture_source_attrs` returns `None` for community-less
/// sources, so the reachable divergence needs communities on the
/// source; `None` vs `None` is always source-control-equal.)
#[test]
fn pcb_lane_source_attr_change_records_transition() {
    const COMM_OLD: u32 = 0xFDE9_0001;
    const COMM_NEW: u32 = 0xFDE9_0002;
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand_with_comm(p, OTHER2, 200, COMM_OLD));
    m.group_ribs.insert(
        PCB_GID,
        per_client_best_group(Some(strip_communities_chain(vec![COMM_OLD, COMM_NEW]))),
    );
    let out = stage_pcb(&mut m, &[p]);
    assert_eq!(out.lane_deltas.len(), 1);
    let staged = out.lane_deltas[0].new.as_ref().expect("lane announce");
    assert_eq!(
        source_control_input(staged.source_attrs.as_ref()).0,
        &[COMM_OLD]
    );
    let staged_route = staged.route.clone();

    // Content-equal reinstall, source-control input unchanged:
    // suppressed.
    seed(&mut m, cand_with_comm(p, OTHER2, 200, COMM_OLD));
    let out = stage_pcb(&mut m, &[p]);
    assert!(out.lane_deltas.is_empty(), "full equality is suppressed");

    // Source control community flips; the chain strips both, so
    // the post-policy lane route is unchanged — the transition
    // must be recorded anyway.
    seed(&mut m, cand_with_comm(p, OTHER2, 200, COMM_NEW));
    let out = stage_pcb(&mut m, &[p]);
    assert_eq!(out.lane_deltas.len(), 1);
    let lane = out.lane_deltas[0]
        .new
        .as_ref()
        .expect("announce, not a retire");
    assert!(
        routes_equal(&lane.route, &staged_route),
        "post-policy lane route unchanged — only the source attrs moved"
    );
    assert_eq!(
        source_control_input(lane.source_attrs.as_ref()).0,
        &[COMM_NEW]
    );
}

/// Darkness proof, plain-group side: a plain group over the same
/// candidate inputs never touches the lane — no `lane_deltas`, no
/// `runner_up` state — and stages the Loc-RIB best exactly as
/// before (the rest of this file's suite pins the full shape).
#[test]
fn plain_group_same_inputs_stages_no_lane() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    let _ = m.recompute_best(&HashSet::from([p]));
    m.group_ribs.insert(PCB_GID, empty_group());

    let out = stage_pcb(&mut m, &[p]);

    assert!(out.lane_deltas.is_empty());
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert!(group.runner_up.is_empty());
    assert_eq!(out.deltas.len(), 1);
    let (staged, _) = out.deltas[0].new.as_ref().expect("Loc-RIB best staged");
    assert_eq!(staged.peer, OTHER1);
}

/// Darkness proof, emit side: every existing emit consumer reads
/// only `deltas`, so its output is identical with the lane
/// transitions present or cleared.
#[test]
fn pcb_emit_consumers_ignore_lane_fields() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let _ = stage_pcb(&mut m, &[p]);
    // Winner content-change + lane content-change: both delta
    // kinds present in one pass.
    seed(&mut m, cand(p, OTHER1, 400));
    seed(&mut m, cand(p, OTHER2, 250));
    let mut out = stage_pcb(&mut m, &[p]);
    assert!(!out.lane_deltas.is_empty());

    let member_emit = |deltas: &[GroupDelta]| {
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_flags = Vec::new();
        emit_group_deltas_for_member(
            deltas,
            MEMBER,
            None,
            &mut announce,
            &mut withdraw,
            &mut nh_flags,
        );
        let keys: Vec<(Prefix, IpAddr)> = announce.iter().map(|r| (r.prefix, r.peer)).collect();
        (keys, withdraw, nh_flags.len())
    };
    let with_lane = (
        member_emit(&out.deltas),
        out.withdrawn_keys().collect::<Vec<_>>(),
        out.member_scoped_withdraws(MEMBER).collect::<Vec<_>>(),
    );
    out.build_shared_emit();
    let shared_with_lane: Vec<(Prefix, IpAddr)> = out
        .shared_announce
        .iter()
        .map(|r| (r.prefix, r.peer))
        .collect();
    let shared_withdraw_with_lane = out.shared_withdraw.clone();

    out.lane_deltas.clear();
    let without_lane = (
        member_emit(&out.deltas),
        out.withdrawn_keys().collect::<Vec<_>>(),
        out.member_scoped_withdraws(MEMBER).collect::<Vec<_>>(),
    );
    out.build_shared_emit();
    let shared_without_lane: Vec<(Prefix, IpAddr)> = out
        .shared_announce
        .iter()
        .map(|r| (r.prefix, r.peer))
        .collect();

    assert_eq!(with_lane, without_lane);
    assert_eq!(shared_with_lane, shared_without_lane);
    assert_eq!(shared_withdraw_with_lane, out.shared_withdraw);
}

/// The `join_group` table-build seam: lane commits live in the
/// staging pass's commit block, so a full-table build pass whose
/// output is DISCARDED (exactly what `join_group` runs before the
/// first member replays) still leaves a fully populated lane. The
/// pass is driven directly here against a fixture group cell.
#[test]
fn pcb_table_build_pass_populates_lane() {
    let mut m = staging_manager();
    let overlapped = prefix(1);
    let single = prefix(2);
    seed(&mut m, cand(overlapped, OTHER1, 300));
    seed(&mut m, cand(overlapped, OTHER2, 200));
    seed(&mut m, cand(single, OTHER1, 300));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));

    let _ = stage_pcb(&mut m, &[overlapped, single]);

    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(
        group.table.get(&overlapped, 0).map(|r| r.peer),
        Some(OTHER1)
    );
    assert_eq!(group.table.get(&single, 0).map(|r| r.peer), Some(OTHER1));
    // O(overlapped prefixes): only the prefix with a distinct-
    // source runner-up occupies the lane.
    assert_eq!(group.runner_up.len(), 1);
    assert_eq!(lane_source(&m, overlapped), Some(OTHER2));
}

// --- ADR-0126 Phase 2 (read-only seams): the adv(m) derivation
// --- (`adv_entry`, Decision 4) and the derived views routed
// --- through it — queries, counts, and join-counter replay.

/// A lane entry with a full payload, for driving `adv_entry`
/// directly.
fn lane_entry(route: Route, winner_source: IpAddr, label: &str, comm: Option<u32>) -> RunnerUp {
    RunnerUp {
        route,
        nh: Some(NextHopAction::Self_),
        source_attrs: comm.map(|c| Arc::new(vec![PathAttribute::Communities(vec![c])])),
        policy_label: Some(Arc::from(label)),
        winner_source,
    }
}

/// ADR-0126 Decision 4 `adv_entry` matrix: non-own passthrough
/// with the table residue; own-sourced + lane → the runner-up's
/// payload (route, nh, source attrs, label all from the lane);
/// own-sourced + empty lane → nothing; and the `per_client_best`
/// gate keeping a plain group's read path at the historical skip
/// rule even with a lane entry forced in.
#[test]
fn adv_entry_derivation_matrix() {
    let p = prefix(1);

    // Non-own staged entry: passthrough with its table residue.
    let mut group = per_client_best_group(None);
    group.apply_delta(&GroupDelta {
        prefix: p,
        path_id: 0,
        new: Some((route(p, OTHER1), Some(NextHopAction::Self_))),
        old_source: None,
        policy_label: Some(Arc::from("staged")),
        source_attrs: Some(Arc::new(vec![PathAttribute::Communities(vec![7])])),
        lane: None,
    });
    let adv = group
        .adv_entry(MEMBER, &p, 0)
        .expect("non-own staged entry");
    assert_eq!((adv.route.peer, adv.route.path_id), (OTHER1, 0));
    assert!(matches!(adv.nh, Some(NextHopAction::Self_)));
    assert_eq!(source_control_input(adv.source_attrs).0, &[7]);
    assert_eq!(adv.policy_label.map(|label| &**label), Some("staged"));

    // Own-sourced + lane: the runner-up substitutes with ITS
    // payload, at the same (prefix, path_id 0) slot.
    let mut group = per_client_best_group(None);
    group.apply_delta(&announce_delta(p, MEMBER, None));
    group.apply_lane(
        p,
        Some(lane_entry(route(p, OTHER2), MEMBER, "lane", Some(9))),
    );
    let adv = group.adv_entry(MEMBER, &p, 0).expect("lane substitutes");
    assert_eq!((adv.route.peer, adv.route.path_id), (OTHER2, 0));
    assert!(matches!(adv.nh, Some(NextHopAction::Self_)));
    assert_eq!(source_control_input(adv.source_attrs).0, &[9]);
    assert_eq!(adv.policy_label.map(|label| &**label), Some("lane"));
    // Any other member still sees the staged winner (with the
    // winner's residue: none was staged for it).
    let adv = group.adv_entry(OTHER1, &p, 0).expect("staged winner");
    assert_eq!(adv.route.peer, MEMBER);
    assert!(adv.nh.is_none());
    assert!(adv.policy_label.is_none());

    // Own-sourced + empty lane: nothing.
    let mut group = per_client_best_group(None);
    group.apply_delta(&announce_delta(p, MEMBER, None));
    assert!(group.adv_entry(MEMBER, &p, 0).is_none());

    // Plain group: the flag gates the lane off even were one
    // somehow populated — the plain-group read path is provably
    // the historical `peer == member ⇒ skip` rule.
    let mut group = empty_group();
    group.apply_delta(&announce_delta(p, MEMBER, None));
    group.apply_lane(p, Some(lane_entry(route(p, OTHER2), MEMBER, "lane", None)));
    assert!(group.adv_entry(MEMBER, &p, 0).is_none());
    assert_eq!(
        group.adv_entry(OTHER1, &p, 0).map(|adv| adv.route.peer),
        Some(MEMBER)
    );

    // No staged entry at all: nothing, lane or not.
    assert!(group.adv_entry(MEMBER, &prefix(2), 0).is_none());
}

/// Decision 4 count synthesis: `advertised_count_for` and
/// `family_counts_for` (table − own + lane) agree with a
/// brute-force fold over `adv_entry` — the synthesis and the
/// materialized derivation are the same function, which IS the
/// Decision 4 claim.
#[test]
fn pcb_counts_agree_with_adv_entry_fold() {
    let mut m = staging_manager();
    let (p1, p2, p3) = (prefix(1), prefix(2), prefix(3));
    // p1: MEMBER wins, OTHER1 runner-up; p2: OTHER1 wins, OTHER2
    // runner-up; p3: OTHER1 wins, no runner-up.
    seed(&mut m, cand(p1, MEMBER, 300));
    seed(&mut m, cand(p1, OTHER1, 200));
    seed(&mut m, cand(p2, OTHER1, 300));
    seed(&mut m, cand(p2, OTHER2, 200));
    seed(&mut m, cand(p3, OTHER1, 300));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let _ = stage_pcb(&mut m, &[p1, p2, p3]);

    let group = m.group_ribs.get(&PCB_GID).unwrap();
    for member in [MEMBER, OTHER1, OTHER2] {
        let folded = group
            .table
            .iter()
            .filter_map(|staged| group.adv_entry(member, &staged.prefix, staged.path_id))
            .count();
        assert_eq!(
            group.advertised_count_for(member),
            folded,
            "synthesized count diverged from the adv_entry fold for {member}"
        );
        let family_total: u64 = group
            .family_counts_for(member)
            .iter()
            .map(|(_, count)| *count)
            .sum();
        assert_eq!(
            family_total,
            u64::try_from(folded).unwrap(),
            "family counts diverged from the adv_entry fold for {member}"
        );
    }
    // Hand-computed: MEMBER = 3 − 1 own + 1 lane; OTHER1 = 3 − 2
    // own + 1 lane (p2's runner-up; its own p3 winner has none);
    // OTHER2 sources no winner.
    assert_eq!(group.advertised_count_for(MEMBER), 3);
    assert_eq!(group.advertised_count_for(OTHER1), 2);
    assert_eq!(group.advertised_count_for(OTHER2), 3);
    assert_eq!(
        group.family_counts_for(MEMBER),
        vec![((Afi::Ipv4, Safi::Unicast), 3)]
    );
    assert_eq!(
        group.family_counts_for(OTHER1),
        vec![((Afi::Ipv4, Safi::Unicast), 2)]
    );
}

/// The lane term is per family: a v6 substitution lands in the v6
/// row only, and an own-sourced v4 slot without a lane entry still
/// drops out of both the family row and the summed count.
#[test]
fn pcb_family_counts_lane_term_is_per_family() {
    use crate::test_support::make_v6_route;
    let p4 = prefix(1);
    let p6 = Prefix::V6(Ipv6Prefix::new(
        std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
        64,
    ));
    let mut group = per_client_best_group(None);
    // v4 winner sourced by MEMBER, no runner-up.
    group.apply_delta(&announce_delta(p4, MEMBER, None));
    // v6 winner sourced by MEMBER with a v6 runner-up in the lane.
    let mut w6 = make_v6_route(
        match p6 {
            Prefix::V6(prefix) => prefix,
            Prefix::V4(_) => unreachable!(),
        },
        std::net::Ipv6Addr::LOCALHOST,
    );
    w6.peer = MEMBER;
    group.apply_delta(&GroupDelta {
        prefix: p6,
        path_id: 0,
        new: Some((w6.clone(), None)),
        old_source: None,
        policy_label: None,
        source_attrs: None,
        lane: None,
    });
    let mut r6 = w6;
    r6.peer = OTHER2;
    group.apply_lane(p6, Some(lane_entry(r6, MEMBER, "lane", None)));

    assert_eq!(
        group.family_counts_for(MEMBER),
        vec![((Afi::Ipv6, Safi::Unicast), 1)],
        "only the v6 row gains the lane term"
    );
    assert_eq!(group.advertised_count_for(MEMBER), 1);
    // A member sourcing nothing sees both staged winners.
    assert_eq!(
        group.family_counts_for(OTHER1),
        vec![
            ((Afi::Ipv4, Safi::Unicast), 1),
            ((Afi::Ipv6, Safi::Unicast), 1),
        ]
    );
}

/// The advertised iterators yield adv(m): the lane route at the
/// winner's prefix for source(w) — `path_id` 0, nothing else changed
/// — while a member sourcing nothing sees the staged table
/// unchanged. Covers the unordered iterator, the ordered variant
/// (prefix ordering preserved), and the materialized wrapper.
#[test]
fn pcb_advertised_iterators_substitute_lane_entry() {
    let mut m = staging_manager();
    let (p1, p2, p3) = (prefix(1), prefix(2), prefix(3));
    seed(&mut m, cand(p1, MEMBER, 300));
    seed(&mut m, cand(p1, OTHER1, 200));
    seed(&mut m, cand(p2, OTHER1, 300));
    seed(&mut m, cand(p3, OTHER1, 300));
    seed(&mut m, cand(p3, OTHER2, 200));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let _ = stage_pcb(&mut m, &[p1, p2, p3]);
    for peer in [MEMBER, OTHER2] {
        m.update_groups
            .members
            .insert(peer, GroupMembership::Grouped(PCB_GID));
    }

    // MEMBER sources p1's winner: its view substitutes the lane
    // route (OTHER1's candidate) there and nowhere else.
    let mut rows: Vec<(Prefix, IpAddr, u32)> = m
        .grouped_advertised_routes_iter(MEMBER)
        .unwrap()
        .map(|r| (r.prefix, r.peer, r.path_id))
        .collect();
    rows.sort();
    assert_eq!(
        rows,
        vec![(p1, OTHER1, 0), (p2, OTHER1, 0), (p3, OTHER1, 0)]
    );
    // OTHER2 sources no winner: the staged table, split horizon
    // moot, no substitution anywhere.
    let mut rows: Vec<(Prefix, IpAddr)> = m
        .grouped_advertised_routes_iter(OTHER2)
        .unwrap()
        .map(|r| (r.prefix, r.peer))
        .collect();
    rows.sort();
    assert_eq!(rows, vec![(p1, MEMBER), (p2, OTHER1), (p3, OTHER1)]);

    // Ordered variant: the substitution keeps the winner's prefix
    // position, so the prefix-index order is unchanged.
    let ordered: Vec<(Prefix, IpAddr)> = m
        .grouped_advertised_routes_ordered_iter(MEMBER, None)
        .unwrap()
        .map(|r| (r.prefix, r.peer))
        .collect();
    assert_eq!(ordered, vec![(p1, OTHER1), (p2, OTHER1), (p3, OTHER1)]);

    // Materialized wrapper delegates to the same derivation.
    let materialized = m.grouped_advertised_routes(MEMBER).unwrap();
    assert_eq!(materialized.len(), 3);
    assert!(materialized.iter().all(|r| r.peer == OTHER1));
}

/// A page boundary ON a substituted row: the caller's cursor
/// carries the yielded lane route's source peer, while the staged
/// key ranks past it — resume must not duplicate the prefix.
#[test]
fn pcb_ordered_iterator_resumes_past_substituted_row() {
    let mut m = staging_manager();
    let (p1, p2) = (prefix(1), prefix(2));
    // Winner source OTHER2 ranks ABOVE lane source MEMBER in the
    // cursor key order, so the underlying staged-key filter alone
    // would re-yield p1 on resume.
    seed(&mut m, cand(p1, OTHER2, 300));
    seed(&mut m, cand(p1, MEMBER, 200));
    seed(&mut m, cand(p2, OTHER1, 300));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let _ = stage_pcb(&mut m, &[p1, p2]);
    m.update_groups
        .members
        .insert(OTHER2, GroupMembership::Grouped(PCB_GID));

    let full: Vec<(Prefix, IpAddr)> = m
        .grouped_advertised_routes_ordered_iter(OTHER2, None)
        .unwrap()
        .map(|r| (r.prefix, r.peer))
        .collect();
    assert_eq!(full, vec![(p1, MEMBER), (p2, OTHER1)]);

    let cursor = m
        .grouped_advertised_routes_ordered_iter(OTHER2, None)
        .unwrap()
        .next()
        .map(crate::update::route_query_key)
        .unwrap();
    assert_eq!(cursor, (p1, MEMBER, 0));
    let resumed: Vec<(Prefix, IpAddr)> = m
        .grouped_advertised_routes_ordered_iter(OTHER2, Some(cursor))
        .unwrap()
        .map(|r| (r.prefix, r.peer))
        .collect();
    assert_eq!(
        resumed,
        vec![(p2, OTHER1)],
        "the substituted prefix must not repeat past its own cursor"
    );
}

/// The actor-level count queries synthesize adv(m): the unlimited
/// branch of `grouped_advertised_count` and the BMP stat-17
/// `grouped_family_counts` both include the lane substitution, and
/// the exact-export rejection overlay subtracts a substituted slot
/// (it is on the member's wire).
#[test]
fn pcb_grouped_count_queries_include_lane_term() {
    let mut m = staging_manager();
    let (p1, p2) = (prefix(1), prefix(2));
    seed(&mut m, cand(p1, MEMBER, 300));
    seed(&mut m, cand(p1, OTHER1, 200));
    seed(&mut m, cand(p2, OTHER1, 300));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let _ = stage_pcb(&mut m, &[p1, p2]);
    m.update_groups
        .members
        .insert(MEMBER, GroupMembership::Grouped(PCB_GID));

    assert_eq!(m.grouped_advertised_count(MEMBER), Some(2));
    assert_eq!(
        m.grouped_family_counts(MEMBER),
        Some(vec![((Afi::Ipv4, Safi::Unicast), 2)])
    );

    // Reject the substituted slot: it counts against the member's
    // view exactly like a staged-entry slot would.
    m.peer_unexportable
        .entry(MEMBER)
        .or_default()
        .insert(ExactExportKey::Unicast(p1, 0));
    assert_eq!(m.grouped_advertised_count(MEMBER), Some(1));
    assert_eq!(
        m.grouped_family_counts(MEMBER),
        Some(vec![((Afi::Ipv4, Safi::Unicast), 1)])
    );
}

/// Join-counter replay delivers one permit per adv(m) slot: the
/// staged label for non-own entries and the LANE entry's label
/// where the member sourced the winner (Decision 2's over-replay
/// posture — the runner-up's permit WAS evaluated). Totals and
/// per-label attribution both match the hand-computed expectation;
/// a member with an own-sourced slot and no lane gets nothing for
/// it.
#[test]
fn pcb_join_counters_replay_lane_permit() {
    let (p1, p2) = (prefix(1), prefix(2));
    let mut group = per_client_best_group(None);
    // p1: winner MEMBER (label "win"), runner-up OTHER2 in the
    // lane (label "lane"). p2: winner OTHER1 (label "win").
    group.apply_delta(&GroupDelta {
        prefix: p1,
        path_id: 0,
        new: Some((route(p1, MEMBER), None)),
        old_source: None,
        policy_label: Some(Arc::from("win")),
        source_attrs: None,
        lane: None,
    });
    group.apply_lane(
        p1,
        Some(lane_entry(route(p1, OTHER2), MEMBER, "lane", None)),
    );
    group.apply_delta(&GroupDelta {
        prefix: p2,
        path_id: 0,
        new: Some((route(p2, OTHER1), None)),
        old_source: None,
        policy_label: Some(Arc::from("win")),
        source_attrs: None,
        lane: None,
    });
    let mut m = staging_manager();
    m.group_ribs.insert(PCB_GID, group);

    // MEMBER sourced p1's winner: replay = p2's staged permit
    // ("win") + p1's lane permit ("lane").
    m.apply_group_join_counters(MEMBER, PCB_GID, None);
    // OTHER1 sourced p2's winner with NO lane entry: replay =
    // p1's staged permit only.
    m.apply_group_join_counters(OTHER1, PCB_GID, None);

    let stats = |peer: IpAddr| {
        m.export_policy_stats
            .get(&peer)
            .map_or(0, |stats| stats.export_policy_routes_permitted)
    };
    assert_eq!(stats(MEMBER), 2);
    assert_eq!(stats(OTHER1), 1);

    // Label attribution: the substituted permit carries the LANE
    // entry's label, not the winner's.
    let gathered = m.metrics.registry().gather();
    let family = gathered
        .iter()
        .find(|family| family.name() == "bgp_policy_routes_total")
        .expect("policy routes counter family registered");
    let permits = |peer: IpAddr, policy: &str| {
        let peer_label = peer.to_string();
        family
            .metric
            .iter()
            .find(|metric| {
                let has = |name: &str, value: &str| {
                    metric
                        .get_label()
                        .iter()
                        .any(|label| label.name() == name && label.value() == value)
                };
                has("peer", &peer_label)
                    && has("policy", policy)
                    && has("direction", "export")
                    && has("action", "permit")
            })
            .map_or(0.0, |metric| metric.get_counter().value())
    };
    assert!((permits(MEMBER, "lane") - 1.0).abs() < f64::EPSILON);
    assert!((permits(MEMBER, "win") - 1.0).abs() < f64::EPSILON);
    assert!((permits(OTHER1, "win") - 1.0).abs() < f64::EPSILON);
    assert!(permits(OTHER1, "lane").abs() < f64::EPSILON);
}

// --- ADR-0126 Phase 2 (steady-state emit): the Decision 5 matrix
// --- arms + member-scoped lane emission, proven against adv(m).

const FOURTH: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 4));
const RS_ASN: u32 = 65000;
const TARGET_ASN: u32 = 64512;

/// Fixed per-source LP so every (winner, lane) state in the
/// steady-state matrix is a pure seed-set choice: OTHER1 = 300
/// outranks OTHER2 = 200 outranks MEMBER = 100.
fn matrix_lp(src: IpAddr) -> u32 {
    if src == OTHER1 {
        300
    } else if src == OTHER2 {
        200
    } else {
        100
    }
}

/// Winner-delta + lane-delta + tag-transition walks for one member
/// — the per-member exception path of the fanout driver, in its
/// exact call order.
fn emit_walk(
    out: &GroupStageOutput,
    member: IpAddr,
    rs_control: Option<(u32, u32)>,
) -> (Vec<Route>, Vec<(Prefix, u32)>) {
    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    let mut nh_flags = Vec::new();
    emit_group_deltas_for_member(
        &out.deltas,
        member,
        rs_control,
        &mut announce,
        &mut withdraw,
        &mut nh_flags,
    );
    emit_lane_deltas_for_member(
        &out.lane_deltas,
        member,
        rs_control,
        &mut announce,
        &mut withdraw,
        &mut nh_flags,
    );
    emit_rs_tag_transitions(
        &out.rs_transitions,
        member,
        rs_control,
        &mut announce,
        &mut withdraw,
        &mut nh_flags,
    );
    assert_eq!(
        nh_flags.len(),
        announce.len(),
        "nh flags must stay aligned with announces"
    );
    (announce, withdraw)
}

/// [`emit_walk`] plus the driver's dispatch property: when the
/// pre-built shared payload covers the member
/// (`shared_applies_to`), the walk must produce exactly the shared
/// emission — the exception-routing invariant (a member NOT in
/// `exceptions` is exactly served by the shared payload).
fn member_emission(out: &GroupStageOutput, member: IpAddr) -> (Vec<Route>, Vec<(Prefix, u32)>) {
    let (announce, withdraw) = emit_walk(out, member, None);
    if out.shared_applies_to(member) {
        assert_eq!(
            announce.len(),
            out.shared_announce.len(),
            "shared/walk announce count diverged for {member}"
        );
        for (walked, shared) in announce.iter().zip(out.shared_announce.iter()) {
            assert!(
                routes_equal(walked, shared),
                "shared/walk announce diverged for {member}"
            );
        }
        assert_eq!(
            withdraw, out.shared_withdraw,
            "shared/walk withdraw diverged for {member}"
        );
    }
    (announce, withdraw)
}

/// ADR-0126 Decision 5 steady-state reference matrix. Every
/// (winner-source × lane) group state over sources {OTHER1,
/// OTHER2, MEMBER} — (∅,∅), (A,∅), (A,B), (A,C), (B,∅), (B,C)
/// with runner-up source ≠ winner source by construction —
/// crossed as (old → new) transitions, staged through the REAL
/// per-client-best pass and emitted per member exactly as the
/// fanout driver would (shared payload where it applies, the
/// per-member walks otherwise — [`member_emission`] asserts both
/// agree). After folding each pass's emission, every member's
/// simulated wire must equal adv(m) (`adv_entry`, Decision 4); no
/// duplicate announce, duplicate withdraw, or announce+withdraw
/// composition may escape; a lane-only transition emits exactly
/// one member-scoped delta toward `source(w)`; an identity
/// transition emits nothing at all.
#[test]
#[expect(
    clippy::too_many_lines,
    reason = "the exhaustive steady-state matrix folds every transition inline"
)]
fn pcb_steady_state_emission_matrix_matches_adv() {
    type State = (Option<IpAddr>, Option<IpAddr>);
    const A: IpAddr = OTHER1;
    const B: IpAddr = OTHER2;
    const C: IpAddr = MEMBER;
    let members = [A, B, C, FOURTH];
    let states: [State; 6] = [
        (None, None),
        (Some(A), None),
        (Some(A), Some(B)),
        (Some(A), Some(C)),
        (Some(B), None),
        (Some(B), Some(C)),
    ];
    for &old_state in &states {
        for &new_state in &states {
            let p = prefix(9);
            let mut m = staging_manager();
            m.group_ribs.insert(PCB_GID, per_client_best_group(None));
            let mut wires: HashMap<IpAddr, HashMap<(Prefix, u32), Route>> =
                members.iter().map(|&peer| (peer, HashMap::new())).collect();
            for (pass, state) in [(1u8, old_state), (2, new_state)] {
                if pass == 2 {
                    for src in [A, B, C] {
                        unseed(&mut m, src, p);
                    }
                }
                for src in state.0.into_iter().chain(state.1) {
                    seed(&mut m, cand(p, src, matrix_lp(src)));
                }
                let mut out = stage_pcb(&mut m, &[p]);
                out.build_shared_emit();
                let group = m.group_ribs.get(&PCB_GID).unwrap();
                let mut emitted: HashMap<IpAddr, usize> = HashMap::new();
                for &member in &members {
                    let case =
                        format!("{old_state:?} -> {new_state:?}, pass {pass}, member {member}");
                    let (announce, withdraw) = member_emission(&out, member);
                    let announce_keys: Vec<(Prefix, u32)> =
                        announce.iter().map(|r| (r.prefix, r.path_id)).collect();
                    let unique: HashSet<(Prefix, u32)> = announce_keys.iter().copied().collect();
                    assert_eq!(
                        unique.len(),
                        announce_keys.len(),
                        "{case}: duplicate announce"
                    );
                    let unique_withdraw: HashSet<(Prefix, u32)> =
                        withdraw.iter().copied().collect();
                    assert_eq!(
                        unique_withdraw.len(),
                        withdraw.len(),
                        "{case}: duplicate withdraw"
                    );
                    assert!(
                        unique.is_disjoint(&unique_withdraw),
                        "{case}: announce+withdraw of one key"
                    );
                    emitted.insert(member, announce.len() + withdraw.len());
                    let wire = wires.get_mut(&member).unwrap();
                    for key in &withdraw {
                        wire.remove(key);
                    }
                    for route in announce {
                        wire.insert((route.prefix, route.path_id), route);
                    }
                    let adv: HashMap<(Prefix, u32), &Route> = group
                        .table
                        .iter()
                        .filter_map(|staged| {
                            group
                                .adv_entry(member, &staged.prefix, staged.path_id)
                                .map(|adv| ((staged.prefix, staged.path_id), adv.route))
                        })
                        .collect();
                    assert_eq!(
                        wire.keys().copied().collect::<HashSet<_>>(),
                        adv.keys().copied().collect::<HashSet<_>>(),
                        "{case}: wire keys diverged from adv(m)"
                    );
                    for (key, advertised) in &adv {
                        assert!(
                            routes_equal(&wire[key], advertised),
                            "{case}: wire route diverged from adv(m) at {key:?}"
                        );
                    }
                }
                if pass == 2 {
                    let case = format!("{old_state:?} -> {new_state:?}");
                    if old_state == new_state {
                        assert!(
                            emitted.values().all(|&n| n == 0),
                            "{case}: identity transition must emit nothing"
                        );
                    } else if old_state.0 == new_state.0 && old_state.0.is_some() {
                        let winner = old_state.0.unwrap();
                        for &member in &members {
                            assert_eq!(
                                emitted[&member],
                                usize::from(member == winner),
                                "{case}: lane-only scoping for {member}"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// A lane-only transition (winner untouched) is member-scoped:
/// `source(w)` — and nobody else — receives the delta, the target
/// leaves the shared payload (exception routing), and the wire
/// delta is exactly announce-`r'` / withdraw-`(prefix, 0)`.
#[test]
fn pcb_lane_only_transition_targets_winner_source_only() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let _ = stage_pcb(&mut m, &[p]);

    // Content flip: the runner-up is replaced in place.
    seed(&mut m, cand(p, OTHER2, 250));
    let mut out = stage_pcb(&mut m, &[p]);
    out.build_shared_emit();
    assert!(
        out.deltas.is_empty(),
        "winner must stay equality-suppressed"
    );
    assert_eq!(out.lane_deltas.len(), 1);
    assert_eq!(out.lane_deltas[0].emit_target, Some(OTHER1));
    assert!(
        !out.shared_applies_to(OTHER1),
        "the lane target must not ride the shared payload"
    );
    assert!(out.shared_announce.is_empty() && out.shared_withdraw.is_empty());
    let (announce, withdraw) = member_emission(&out, OTHER1);
    assert_eq!(announce.len(), 1);
    assert_eq!((announce[0].peer, announce[0].path_id), (OTHER2, 0));
    assert!(withdraw.is_empty());
    for member in [OTHER2, MEMBER, FOURTH] {
        let (announce, withdraw) = member_emission(&out, member);
        assert!(
            announce.is_empty() && withdraw.is_empty(),
            "lane-only emission leaked to {member}"
        );
    }

    // Retire: the runner-up disappears.
    unseed(&mut m, OTHER2, p);
    let mut out = stage_pcb(&mut m, &[p]);
    out.build_shared_emit();
    assert!(out.deltas.is_empty());
    assert_eq!(out.lane_deltas.len(), 1);
    assert!(out.lane_deltas[0].new.is_none());
    assert_eq!(out.lane_deltas[0].emit_target, Some(OTHER1));
    let (announce, withdraw) = member_emission(&out, OTHER1);
    assert!(announce.is_empty());
    assert_eq!(withdraw, vec![(p, 0)]);
    for member in [OTHER2, MEMBER, FOURTH] {
        let (announce, withdraw) = member_emission(&out, member);
        assert!(
            announce.is_empty() && withdraw.is_empty(),
            "lane retire leaked to {member}"
        );
    }
}

/// All-candidates-gone with a populated lane: every member
/// withdraws the slot — the old `source(w)` included, whose wire
/// held the runner-up at the same path-id-free key (its withdraw
/// rides the lane-retire arm, exactly once — the winner withdraw
/// arm skips it, so no duplicate composes).
#[test]
fn pcb_all_gone_with_lane_withdraws_old_winner_source() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let _ = stage_pcb(&mut m, &[p]);

    unseed(&mut m, OTHER1, p);
    unseed(&mut m, OTHER2, p);
    let mut out = stage_pcb(&mut m, &[p]);
    out.build_shared_emit();
    assert_eq!(out.deltas.len(), 1);
    assert!(out.deltas[0].new.is_none());
    assert_eq!(out.lane_deltas.len(), 1);
    assert_eq!(out.lane_deltas[0].emit_target, Some(OTHER1));
    for member in [OTHER1, OTHER2, MEMBER, FOURTH] {
        let (announce, withdraw) = member_emission(&out, member);
        assert!(announce.is_empty(), "{member}: nothing to announce");
        assert_eq!(
            withdraw,
            vec![(p, 0)],
            "{member}: exactly one withdraw of the slot"
        );
    }
}

/// rs-control applies to the lane substitution from the LANE
/// entry's SOURCE attributes — on the winner-delta arm (pass 1:
/// the new source's slot reads `GroupDelta::lane`) and the
/// lane-delta arm alike: an announced substitution is rewritten
/// (control communities scrubbed) toward an rs-control target
/// while a transparent target receives it untouched, and a
/// suppressing tag collapses the substitution to a withdraw of
/// the held runner-up (over-withdraw is the safe direction).
#[test]
fn pcb_lane_emission_applies_rs_control() {
    let rs = Some((RS_ASN, TARGET_ASN));
    // Announce-override form RS:TARGET — control-space (scrubbed)
    // but not suppressing.
    let scrub_comm = (RS_ASN << 16) | TARGET_ASN;
    // Target-specific deny form 0:TARGET.
    let deny_comm = TARGET_ASN;
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand_with_comm(p, OTHER2, 200, scrub_comm));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let out = stage_pcb(&mut m, &[p]);

    // Pass 1: the winner announce supersedes the lane delta — the
    // winner arm substitutes toward its own source, rs-aware.
    assert_eq!(out.lane_deltas[0].emit_target, None);
    let (announce, withdraw) = emit_walk(&out, OTHER1, rs);
    assert_eq!((announce.len(), withdraw.len()), (1, 0));
    assert_eq!(announce[0].peer, OTHER2);
    assert!(
        announce[0].communities().is_empty(),
        "control community must be scrubbed toward the rs target"
    );
    let (announce, _) = emit_walk(&out, OTHER1, None);
    assert_eq!(
        announce[0].communities(),
        &[scrub_comm],
        "transparent target receives the untouched substitution"
    );

    // Lane-only content+tag change to a suppressing form: the rs
    // target's substitution collapses to a withdraw of the held
    // runner-up; a transparent target still gets the announce.
    seed(&mut m, cand_with_comm(p, OTHER2, 250, deny_comm));
    let out = stage_pcb(&mut m, &[p]);
    assert!(out.deltas.is_empty());
    assert_eq!(out.lane_deltas[0].emit_target, Some(OTHER1));
    let (announce, withdraw) = emit_walk(&out, OTHER1, rs);
    assert!(announce.is_empty());
    assert_eq!(withdraw, vec![(p, 0)]);
    let (announce, withdraw) = emit_walk(&out, OTHER1, None);
    assert_eq!((announce.len(), withdraw.len()), (1, 0));
    assert_eq!(announce[0].communities(), &[deny_comm]);
}

/// A tag-only lane transition (post-policy content equal, SOURCE
/// control communities moved): nothing toward a transparent
/// target — its wire form is unchanged and the per-peer path
/// would equality-suppress — while an rs-control target whose
/// suppression verdict flips gets exactly the re-announce /
/// withdraw.
#[test]
fn pcb_lane_tag_only_transition_emits_only_on_verdict_flips() {
    let rs = Some((RS_ASN, TARGET_ASN));
    let deny_comm = TARGET_ASN;
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand_with_comm(p, OTHER2, 200, deny_comm));
    m.group_ribs.insert(
        PCB_GID,
        per_client_best_group(Some(strip_communities_chain(vec![deny_comm]))),
    );
    let _ = stage_pcb(&mut m, &[p]);

    // Tag off: content-equal post-policy, the verdict flips to
    // announce for the rs target.
    seed(&mut m, cand(p, OTHER2, 200));
    let out = stage_pcb(&mut m, &[p]);
    assert!(out.deltas.is_empty());
    assert_eq!(out.lane_deltas.len(), 1);
    assert!(out.lane_deltas[0].content_unchanged);
    assert_eq!(out.lane_deltas[0].emit_target, Some(OTHER1));
    let (announce, withdraw) = emit_walk(&out, OTHER1, None);
    assert!(
        announce.is_empty() && withdraw.is_empty(),
        "transparent target: wire form unchanged, nothing may emit"
    );
    let (announce, withdraw) = emit_walk(&out, OTHER1, rs);
    assert_eq!(
        (announce.len(), withdraw.len()),
        (1, 0),
        "suppression lifted: re-announce toward the rs target"
    );

    // Tag back on: the verdict flips to suppressed — withdraw.
    seed(&mut m, cand_with_comm(p, OTHER2, 200, deny_comm));
    let out = stage_pcb(&mut m, &[p]);
    assert_eq!(out.lane_deltas.len(), 1);
    assert!(out.lane_deltas[0].content_unchanged);
    let (announce, withdraw) = emit_walk(&out, OTHER1, None);
    assert!(announce.is_empty() && withdraw.is_empty());
    let (announce, withdraw) = emit_walk(&out, OTHER1, rs);
    assert!(announce.is_empty());
    assert_eq!(withdraw, vec![(p, 0)]);
}

/// `has_tagged_route` scans the lane: a control-tagged lane
/// source must push `source(w)` onto the per-member walk even
/// when every staged winner is untagged.
#[test]
fn has_tagged_route_scans_lane_deltas() {
    let scrub_comm = (RS_ASN << 16) | TARGET_ASN;
    let p = prefix(1);
    let mut m = staging_manager();
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand_with_comm(p, OTHER2, 200, scrub_comm));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let out = stage_pcb(&mut m, &[p]);
    assert!(
        out.has_tagged_route(RS_ASN),
        "a tagged lane source must divert rs members to the walk"
    );
    assert!(
        !out.has_tagged_route(RS_ASN + 1),
        "another rs identity sees no control form"
    );

    let mut m = staging_manager();
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let out = stage_pcb(&mut m, &[p]);
    assert!(
        !out.has_tagged_route(RS_ASN),
        "an untagged pass keeps the shared emission"
    );
}

/// The winner-side rs-tag transition for per-client-best groups
/// (the zero-delta, source-attrs-moved case Phase 1 deliberately
/// skipped): recorded by the pcb staging arm, committed to the
/// source-attr residue, and emitted toward rs-control members
/// through the existing transition emitter.
#[test]
fn pcb_winner_rs_tag_transition_recorded_and_emitted() {
    let deny_comm = TARGET_ASN;
    // Control-space form naming another target — lifts the
    // suppression toward TARGET_ASN.
    let other_comm = TARGET_ASN + 1;
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand_with_comm(p, OTHER1, 300, deny_comm));
    m.group_ribs.insert(
        PCB_GID,
        per_client_best_group(Some(strip_communities_chain(vec![deny_comm, other_comm]))),
    );
    let out = stage_pcb(&mut m, &[p]);
    assert_eq!(out.deltas.len(), 1);
    assert!(out.rs_transitions.is_empty());

    // The winner's source tag moves while the chain erases it
    // post-policy: zero deltas, one recorded transition, residue
    // committed.
    seed(&mut m, cand_with_comm(p, OTHER1, 300, other_comm));
    let out = stage_pcb(&mut m, &[p]);
    assert!(
        out.deltas.is_empty(),
        "content-equal winner reinstall stays suppressed"
    );
    assert_eq!(out.rs_transitions.len(), 1);
    let transition = &out.rs_transitions[0];
    assert_eq!(
        source_control_input(transition.prior_source_attrs.as_ref()).0,
        &[deny_comm]
    );
    assert_eq!(
        source_control_input(transition.source_attrs.as_ref()).0,
        &[other_comm]
    );
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(group.source_control((p, 0)).0, &[other_comm]);

    // Suppression toward TARGET_ASN was on (0:TARGET) and lifts:
    // the rs member re-announces, a transparent member sees
    // nothing.
    let (announce, withdraw) = emit_walk(&out, MEMBER, Some((RS_ASN, TARGET_ASN)));
    assert_eq!((announce.len(), withdraw.len()), (1, 0));
    let (announce, withdraw) = emit_walk(&out, MEMBER, None);
    assert!(announce.is_empty() && withdraw.is_empty());
}

/// Darkness, emit side: a per-client-best group whose lane is
/// empty (no overlapped sources) stages and emits exactly like a
/// plain group over the same table — delta shape, per-member walk
/// output, and exception routing alike.
#[test]
fn pcb_empty_lane_emits_like_plain_group() {
    const PLAIN_GID: usize = 92;
    let mut m = staging_manager();
    let (p1, p2) = (prefix(1), prefix(2));
    seed(&mut m, cand(p1, OTHER1, 300));
    seed(&mut m, cand(p2, OTHER2, 300));
    let _ = m.recompute_best(&HashSet::from([p1, p2]));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    m.group_ribs.insert(PLAIN_GID, empty_group());
    let prefixes: HashSet<Prefix> = HashSet::from([p1, p2]);
    let mut memo = super::super::distribution::ExportMemo::default();
    let mut pcb = m.stage_group_prefixes(PCB_GID, &prefixes, &mut memo);
    let mut plain = m.stage_group_prefixes(PLAIN_GID, &prefixes, &mut memo);
    pcb.build_shared_emit();
    plain.build_shared_emit();

    assert!(pcb.lane_deltas.is_empty());
    let shape = |out: &GroupStageOutput| {
        let mut rows: Vec<(Prefix, u32, Option<IpAddr>)> = out
            .deltas
            .iter()
            .map(|d| (d.prefix, d.path_id, d.new.as_ref().map(|(r, _)| r.peer)))
            .collect();
        rows.sort();
        rows
    };
    assert_eq!(shape(&pcb), shape(&plain));
    for member in [OTHER1, OTHER2, MEMBER] {
        assert_eq!(
            pcb.shared_applies_to(member),
            plain.shared_applies_to(member),
            "exception routing diverged for {member}"
        );
        let keys = |routes: &[Route]| {
            let mut keys: Vec<(Prefix, u32, IpAddr)> = routes
                .iter()
                .map(|r| (r.prefix, r.path_id, r.peer))
                .collect();
            keys.sort();
            keys
        };
        let (pcb_announce, mut pcb_withdraw) = emit_walk(&pcb, member, None);
        let (plain_announce, mut plain_withdraw) = emit_walk(&plain, member, None);
        assert_eq!(
            keys(&pcb_announce),
            keys(&plain_announce),
            "announce set diverged for {member}"
        );
        pcb_withdraw.sort();
        plain_withdraw.sort();
        assert_eq!(
            pcb_withdraw, plain_withdraw,
            "withdraw set diverged for {member}"
        );
    }
}

/// Dirty-member resync: full-table announce minus own-sourced;
/// tombstones withdraw unless the member still retains the key
/// (staged by another source). Over-withdrawing keys now staged by
/// the member itself is the deliberate safe direction.
#[test]
fn dirty_resync_replays_table_and_tombstones() {
    let mut group = empty_group();
    let (k1, k2, k3, k4) = (prefix(1), prefix(2), prefix(3), prefix(4));
    group.apply_delta(&announce_delta(k1, OTHER1, None));
    group.apply_delta(&announce_delta(k2, MEMBER, None));
    group.apply_delta(&announce_delta(k4, MEMBER, None));
    group.tombstones.insert((k1, 0)); // retained via OTHER1 — no withdraw
    group.tombstones.insert((k3, 0)); // gone — withdraw
    group.tombstones.insert((k4, 0)); // member-sourced now — safe over-withdraw

    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    let mut nh_flags = Vec::new();
    RibManager::assemble_group_resync(
        &group,
        MEMBER,
        None,
        true,
        false,
        None,
        None,
        &mut announce,
        &mut withdraw,
        &mut nh_flags,
    );
    let announced: HashSet<Prefix> = announce.iter().map(|r| r.prefix).collect();
    assert_eq!(
        announced,
        HashSet::from([k1]),
        "own-sourced entries excluded"
    );
    let withdrawn: HashSet<(Prefix, u32)> = withdraw.into_iter().collect();
    assert_eq!(withdrawn, HashSet::from([(k3, 0), (k4, 0)]));
    assert_eq!(nh_flags.len(), announce.len());
}

/// Regroup one-shot diff: entries `routes_equal` to the baseline
/// are suppressed, changed entries announce, baseline keys no
/// longer retained withdraw — and `force` bypasses only the
/// equality suppression.
#[test]
fn regroup_baseline_diff_and_force() {
    let mut group = empty_group();
    let (k1, k5, k6) = (prefix(1), prefix(5), prefix(6));
    group.apply_delta(&announce_delta(k1, OTHER1, None));
    group.apply_delta(&announce_delta(k6, OTHER2, None));

    let mut baseline: FxHashMap<(Prefix, u32), Route> = FxHashMap::default();
    baseline.insert((k1, 0), route(k1, OTHER1)); // unchanged — suppressed
    baseline.insert((k5, 0), route(k5, OTHER1)); // gone — withdraw
    baseline.insert((k6, 0), route(k6, OTHER1)); // source flipped — announce

    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    let mut nh_flags = Vec::new();
    RibManager::assemble_group_resync(
        &group,
        MEMBER,
        None,
        true,
        false,
        Some(&baseline),
        None,
        &mut announce,
        &mut withdraw,
        &mut nh_flags,
    );
    let announced: HashSet<Prefix> = announce.iter().map(|r| r.prefix).collect();
    assert_eq!(announced, HashSet::from([k6]));
    let withdrawn: HashSet<(Prefix, u32)> = withdraw.into_iter().collect();
    assert_eq!(withdrawn, HashSet::from([(k5, 0)]));

    // Force (GShut refresh): every retained entry re-announces.
    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    let mut nh_flags = Vec::new();
    RibManager::assemble_group_resync(
        &group,
        MEMBER,
        None,
        false,
        true,
        Some(&baseline),
        None,
        &mut announce,
        &mut withdraw,
        &mut nh_flags,
    );
    let announced: HashSet<Prefix> = announce.iter().map(|r| r.prefix).collect();
    assert_eq!(announced, HashSet::from([k1, k6]));
    let withdrawn: HashSet<(Prefix, u32)> = withdraw.into_iter().collect();
    assert_eq!(withdrawn, HashSet::from([(k5, 0)]));
}

/// The per-peer update-group gauge tracks membership: it reports the
/// group id after grouping, changes on regroup, drops to the ungrouped
/// sentinel on the fallback path, and is reaped on peer-down.
#[test]
fn peer_update_group_gauge_tracks_membership() {
    let (_tx, rx) = tokio::sync::mpsc::channel(1);
    let (_query_tx, query_rx) = tokio::sync::mpsc::channel(1);
    let mut manager = RibManager::new(
        rx,
        query_rx,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    );
    let peer = MEMBER.to_string();

    // Grouped: the gauge reports the peer's group id.
    manager
        .update_groups
        .members
        .insert(MEMBER, GroupMembership::Grouped(2));
    manager.refresh_update_group_gauges();
    assert_eq!(manager.metrics.peer_update_group(&peer), 2);

    // Regroup: moving to another group id updates the gauge.
    manager
        .update_groups
        .members
        .insert(MEMBER, GroupMembership::Grouped(5));
    manager.refresh_update_group_gauges();
    assert_eq!(manager.metrics.peer_update_group(&peer), 5);

    // Grouped → fallback: the ungrouped sentinel, which can never
    // collide with a real (≥ 0) group id.
    manager
        .update_groups
        .members
        .insert(MEMBER, GroupMembership::OrrVantage);
    manager.refresh_update_group_gauges();
    assert_eq!(
        manager.metrics.peer_update_group(&peer),
        rustbgpd_telemetry::BgpMetrics::UPDATE_GROUP_UNGROUPED
    );

    // Peer-down: the series is reaped. Re-reading re-instantiates a
    // fresh child at 0 (the default), proving the stale -1 series was
    // removed rather than left behind.
    manager.update_groups.members.remove(&MEMBER);
    manager.metrics.reap_peer_series(&peer);
    assert_eq!(
        manager.metrics.peer_update_group(&peer),
        0,
        "reaped series must be removed; a fresh read defaults to 0, not the stale -1"
    );
}

/// Carried-over extra withdraws (a dirty member regrouping) emit
/// unless the member retains the key in the new group.
#[test]
fn extra_withdraws_respect_retained_keys() {
    let mut group = empty_group();
    let (k1, k7) = (prefix(1), prefix(7));
    group.apply_delta(&announce_delta(k1, OTHER1, None));
    let extras: HashSet<(Prefix, u32)> = HashSet::from([(k1, 0), (k7, 0)]);

    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    let mut nh_flags = Vec::new();
    RibManager::assemble_group_resync(
        &group,
        MEMBER,
        None,
        true,
        false,
        None,
        Some(&extras),
        &mut announce,
        &mut withdraw,
        &mut nh_flags,
    );
    let withdrawn: HashSet<(Prefix, u32)> = withdraw.into_iter().collect();
    assert_eq!(
        withdrawn,
        HashSet::from([(k7, 0)]),
        "a key still retained (k1 via OTHER1) must not be withdrawn"
    );
}

// --- ADR-0126 Phase 2: dirty-resync substitution + channel-full
// --- lane residue (`assemble_group_resync` routed through
// --- `adv_entry`; `member_scoped_withdraws` lane-retire arm).

/// `(announce, withdraw, nh_flags)` of one assembled resync.
type ResyncEmission = (Vec<Route>, Vec<(Prefix, u32)>, Vec<Option<NextHopAction>>);

/// Run [`RibManager::assemble_group_resync`] and return
/// `(announce, withdraw, nh_flags)`.
fn resync(
    group: &GroupRibOut,
    member: IpAddr,
    rs_control: Option<(u32, u32)>,
    is_dirty: bool,
    is_force: bool,
    extras: Option<&HashSet<(Prefix, u32)>>,
) -> ResyncEmission {
    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    let mut nh_flags = Vec::new();
    RibManager::assemble_group_resync(
        group,
        member,
        rs_control,
        is_dirty,
        is_force,
        None,
        extras,
        &mut announce,
        &mut withdraw,
        &mut nh_flags,
    );
    assert_eq!(
        nh_flags.len(),
        announce.len(),
        "nh flags must stay aligned with announces"
    );
    (announce, withdraw, nh_flags)
}

/// Assert a folded wire equals the member's `adv_entry`-derived
/// view — the ADR-0126 Decision 4 invariant every resync must
/// converge to.
fn assert_wire_is_adv(group: &GroupRibOut, member: IpAddr, wire: &HashMap<(Prefix, u32), Route>) {
    let adv: HashMap<(Prefix, u32), &Route> = group
        .table
        .iter()
        .filter_map(|staged| {
            group
                .adv_entry(member, &staged.prefix, staged.path_id)
                .map(|adv| ((staged.prefix, staged.path_id), adv.route))
        })
        .collect();
    assert_eq!(
        wire.keys().copied().collect::<HashSet<_>>(),
        adv.keys().copied().collect::<HashSet<_>>(),
        "wire keys diverged from adv(m) for {member}"
    );
    for (key, advertised) in &adv {
        assert!(
            routes_equal(&wire[key], advertised),
            "wire route diverged from adv(m) at {key:?} for {member}"
        );
    }
}

/// Fold a resync emission onto a simulated wire (withdraws first;
/// announces are implicit replaces).
fn fold_wire(
    wire: &mut HashMap<(Prefix, u32), Route>,
    announce: Vec<Route>,
    withdraw: &[(Prefix, u32)],
) {
    for key in withdraw {
        wire.remove(key);
    }
    for route in announce {
        wire.insert((route.prefix, route.path_id), route);
    }
}

/// Dirty-resync substitution matrix (ADR-0126 Decision 4): the
/// dirty member sourcing the staged winner receives the LANE entry
/// — route and nh residue both the lane's — where one exists;
/// nothing for the slot where the lane is empty (tombstone
/// withdraws still apply); a dirty member NOT sourcing the winner
/// sees the staged winners unchanged.
#[test]
fn pcb_dirty_resync_substitutes_lane_for_winner_source() {
    let mut group = per_client_best_group(None);
    let (k1, k2, k3, k4) = (prefix(1), prefix(2), prefix(3), prefix(4));
    group.apply_delta(&announce_delta(k1, OTHER1, None)); // plain slot
    group.apply_delta(&announce_delta(k2, MEMBER, None)); // winner == member, lane below
    group.apply_delta(&announce_delta(k3, MEMBER, None)); // winner == member, lane empty
    group.apply_lane(
        k2,
        Some(lane_entry(route(k2, OTHER2), MEMBER, "lane", None)),
    );
    group.tombstones.insert((k3, 0)); // wire may hold a displaced entry
    group.tombstones.insert((k4, 0)); // gone from the table entirely

    let (announce, withdraw, nh_flags) = resync(&group, MEMBER, None, true, false, None);
    let announced: HashMap<Prefix, IpAddr> = announce.iter().map(|r| (r.prefix, r.peer)).collect();
    assert_eq!(
        announced,
        HashMap::from([(k1, OTHER1), (k2, OTHER2)]),
        "k2 substitutes the lane entry; k3's empty lane announces nothing"
    );
    let k2_pos = announce.iter().position(|r| r.prefix == k2).unwrap();
    assert!(
        matches!(nh_flags[k2_pos], Some(NextHopAction::Self_)),
        "the substituted slot carries the LANE's nh residue"
    );
    let withdrawn: HashSet<(Prefix, u32)> = withdraw.into_iter().collect();
    assert_eq!(withdrawn, HashSet::from([(k3, 0), (k4, 0)]));

    // Wire end-state == adv(m): fold onto a wire that held every
    // tombstoned key (worst-case missed sends).
    let mut wire: HashMap<(Prefix, u32), Route> =
        HashMap::from([((k3, 0), route(k3, OTHER2)), ((k4, 0), route(k4, OTHER2))]);
    let (announce, withdraw, _) = resync(&group, MEMBER, None, true, false, None);
    fold_wire(&mut wire, announce, &withdraw);
    assert_wire_is_adv(&group, MEMBER, &wire);

    // A dirty member that does NOT source the winner is untouched
    // by the lane: it receives the staged winners.
    let (announce, withdraw, _) = resync(&group, OTHER1, None, true, false, None);
    let announced: HashMap<Prefix, IpAddr> = announce.iter().map(|r| (r.prefix, r.peer)).collect();
    assert_eq!(announced, HashMap::from([(k2, MEMBER), (k3, MEMBER)]));
    let withdrawn: HashSet<(Prefix, u32)> = withdraw.into_iter().collect();
    assert_eq!(
        withdrawn,
        HashSet::from([(k4, 0)]),
        "k3 is retained for OTHER1 via the staged winner"
    );
}

/// Force-refresh (RFC 8326 `GShut`) re-announces adv(m) — the lane
/// substitution included — and withdraws nothing.
#[test]
fn pcb_force_resync_reannounces_substitution() {
    let mut group = per_client_best_group(None);
    let (k1, k2) = (prefix(1), prefix(2));
    group.apply_delta(&announce_delta(k1, OTHER1, None));
    group.apply_delta(&announce_delta(k2, MEMBER, None));
    group.apply_lane(
        k2,
        Some(lane_entry(route(k2, OTHER2), MEMBER, "lane", None)),
    );

    let (announce, withdraw, _) = resync(&group, MEMBER, None, false, true, None);
    let announced: HashMap<Prefix, IpAddr> = announce.iter().map(|r| (r.prefix, r.peer)).collect();
    assert_eq!(announced, HashMap::from([(k1, OTHER1), (k2, OTHER2)]));
    assert!(withdraw.is_empty(), "force-only withdraws nothing");
}

/// Retention through `adv_entry`: a recorded lane withdraw is
/// delivered while the lane is still empty (the wire held the
/// retired substitution) and dropped once the lane refills — the
/// substituted announce replaces it, never composing
/// announce+withdraw of one key. Wire end-state == adv(m) both
/// ways.
#[test]
fn pcb_recorded_lane_withdraw_delivered_iff_lane_empty() {
    let k = prefix(1);
    let mut group = per_client_best_group(None);
    group.apply_delta(&announce_delta(k, MEMBER, None));
    let extras: HashSet<(Prefix, u32)> = HashSet::from([(k, 0)]);
    // The member's wire still holds the retired substitution.
    let stale_wire = HashMap::from([((k, 0), route(k, OTHER2))]);

    // Lane empty: the withdraw MUST be delivered.
    let (announce, withdraw, _) = resync(&group, MEMBER, None, true, false, Some(&extras));
    assert!(announce.is_empty());
    assert_eq!(withdraw, vec![(k, 0)]);
    let mut wire = stale_wire.clone();
    fold_wire(&mut wire, announce, &withdraw);
    assert_wire_is_adv(&group, MEMBER, &wire);

    // Lane refilled before the resync ran: the recorded withdraw
    // is dropped and the substituted announce replaces it.
    group.apply_lane(k, Some(lane_entry(route(k, OTHER2), MEMBER, "lane", None)));
    let (announce, withdraw, _) = resync(&group, MEMBER, None, true, false, Some(&extras));
    assert!(
        withdraw.is_empty(),
        "a still-substituted key must not be withdrawn"
    );
    assert_eq!(announce.len(), 1);
    assert_eq!((announce[0].prefix, announce[0].peer), (k, OTHER2));
    let mut wire = stale_wire;
    fold_wire(&mut wire, announce, &withdraw);
    assert_wire_is_adv(&group, MEMBER, &wire);
}

/// rs-control on the substituted resync slot decides from the
/// LANE entry's source attributes: a suppressing tag collapses the
/// substitution to a skip + dirty over-withdraw (today's
/// rs-suppressed staged shape), a non-suppressing control tag is
/// scrubbed toward the rs member and left untouched toward a
/// transparent one.
#[test]
fn pcb_resync_substitution_applies_rs_control() {
    let rs = Some((RS_ASN, TARGET_ASN));
    let scrub_comm = (RS_ASN << 16) | TARGET_ASN;
    let deny_comm = TARGET_ASN;
    let k = prefix(1);

    // Suppressing tag: skip + withdraw, and the extras filter
    // agrees (a suppressed substitution does not retain).
    let mut group = per_client_best_group(None);
    group.apply_delta(&announce_delta(k, MEMBER, None));
    group.apply_lane(
        k,
        Some(lane_entry(
            route(k, OTHER2),
            MEMBER,
            "lane",
            Some(deny_comm),
        )),
    );
    let extras: HashSet<(Prefix, u32)> = HashSet::from([(k, 0)]);
    let (announce, withdraw, _) = resync(&group, MEMBER, rs, true, false, Some(&extras));
    assert!(
        announce.is_empty(),
        "suppressed substitution never announces"
    );
    assert_eq!(withdraw, vec![(k, 0)]);

    // Non-suppressing control tag: announced, rewritten from the
    // lane's attributes.
    let mut group = per_client_best_group(None);
    group.apply_delta(&announce_delta(k, MEMBER, None));
    let mut substituted = route(k, OTHER2);
    let mut attrs = (*substituted.attributes).clone();
    attrs.push(PathAttribute::Communities(vec![scrub_comm]));
    substituted.attributes = Arc::new(attrs);
    group.apply_lane(
        k,
        Some(lane_entry(substituted, MEMBER, "lane", Some(scrub_comm))),
    );
    let (announce, withdraw, _) = resync(&group, MEMBER, rs, true, false, None);
    assert!(withdraw.is_empty());
    assert_eq!(announce.len(), 1);
    assert!(
        announce[0].communities().is_empty(),
        "control community must be scrubbed toward the rs member"
    );
    let (announce, _, _) = resync(&group, MEMBER, None, true, false, None);
    assert_eq!(
        announce[0].communities(),
        &[scrub_comm],
        "transparent member receives the untouched substitution"
    );
}

/// Darkness at the resync seam: an empty-lane per-client-best
/// group resyncs byte-identically to a plain group over the same
/// table, tombstones, and extras.
#[test]
fn pcb_empty_lane_resync_matches_plain_group() {
    let (k1, k2, k3) = (prefix(1), prefix(2), prefix(3));
    let build = |mut group: GroupRibOut| {
        group.apply_delta(&announce_delta(k1, OTHER1, None));
        group.apply_delta(&announce_delta(k2, MEMBER, None));
        group.tombstones.insert((k2, 0));
        group.tombstones.insert((k3, 0));
        group
    };
    let pcb = build(per_client_best_group(None));
    let plain = build(empty_group());
    let extras: HashSet<(Prefix, u32)> = HashSet::from([(k1, 0), (k3, 0)]);
    for (is_dirty, is_force) in [(true, false), (false, true)] {
        let (pcb_announce, mut pcb_withdraw, _) =
            resync(&pcb, MEMBER, None, is_dirty, is_force, Some(&extras));
        let (plain_announce, mut plain_withdraw, _) =
            resync(&plain, MEMBER, None, is_dirty, is_force, Some(&extras));
        let keys = |routes: &[Route]| {
            let mut keys: Vec<(Prefix, u32, IpAddr)> = routes
                .iter()
                .map(|r| (r.prefix, r.path_id, r.peer))
                .collect();
            keys.sort();
            keys
        };
        assert_eq!(
            keys(&pcb_announce),
            keys(&plain_announce),
            "announce diverged (dirty={is_dirty}, force={is_force})"
        );
        pcb_withdraw.sort();
        plain_withdraw.sort();
        assert_eq!(
            pcb_withdraw, plain_withdraw,
            "withdraw diverged (dirty={is_dirty}, force={is_force})"
        );
    }
}

/// The channel-full residue seam: a lane RETIRE records
/// `(prefix, 0)` toward its `emit_target` alone; a lane announce
/// records nothing (announces heal through resync); a superseded
/// transition records nothing (a winner delta owns its slot); the
/// source-flip arm keeps recording when the delta carries a lane —
/// the resync retention guard filters it while the substitution
/// stands.
#[test]
fn lane_retire_records_member_scoped_withdraw() {
    let (p1, p2, p3) = (prefix(1), prefix(2), prefix(3));
    let mut out = GroupStageOutput::default();
    out.lane_deltas.push(LaneDelta {
        prefix: p1,
        new: None,
        old_source: Some(OTHER2),
        emit_target: Some(MEMBER),
        prior_source_attrs: None,
        content_unchanged: false,
    });
    out.lane_deltas.push(LaneDelta {
        prefix: p2,
        new: Some(lane_entry(route(p2, OTHER2), OTHER1, "lane", None)),
        old_source: None,
        emit_target: Some(OTHER1),
        prior_source_attrs: None,
        content_unchanged: false,
    });
    out.lane_deltas.push(LaneDelta {
        prefix: p3,
        new: None,
        old_source: Some(OTHER2),
        emit_target: None,
        prior_source_attrs: None,
        content_unchanged: false,
    });
    assert_eq!(
        out.member_scoped_withdraws(MEMBER).collect::<Vec<_>>(),
        vec![(p1, 0)],
        "only the retire toward MEMBER is recorded"
    );
    assert!(
        out.member_scoped_withdraws(OTHER1).next().is_none(),
        "a lane announce leaves no residue"
    );
    assert!(out.member_scoped_withdraws(OTHER2).next().is_none());

    let mut out = GroupStageOutput::default();
    let mut delta = announce_delta(p1, MEMBER, Some(OTHER1));
    delta.lane = Some(lane_entry(route(p1, OTHER1), MEMBER, "lane", None));
    out.deltas.push(delta);
    assert_eq!(
        out.member_scoped_withdraws(MEMBER).collect::<Vec<_>>(),
        vec![(p1, 0)],
        "the source-flip arm records regardless of the lane"
    );
}

/// Channel-full round trips through the REAL staging pass: a lost
/// per-member emission — (a) a lane retire, (b) a lane fill's
/// substituted announce, (c) a source flip ONTO the member with a
/// populated lane — recorded exactly as the channel-full site
/// records it (tombstones from `withdrawn_keys`, extras from
/// `member_scoped_withdraws`), then resynced; the victim's wire
/// must converge to the `adv_entry`-derived adv(m) with no
/// announce+withdraw composition.
#[test]
fn pcb_channel_full_lost_emission_converges_to_adv() {
    let p = prefix(1);
    // Mimic the fanout driver's channel-full arm for `victim`,
    // then run its dirty resync and fold onto `wire`.
    let lose_and_resync =
        |m: &mut RibManager, victim: IpAddr, wire: &mut HashMap<(Prefix, u32), Route>| {
            let out = stage_pcb(m, &[p]);
            let group = m.group_ribs.get_mut(&PCB_GID).unwrap();
            group.tombstones.extend(out.withdrawn_keys());
            let extras: HashSet<(Prefix, u32)> = out.member_scoped_withdraws(victim).collect();
            let group = m.group_ribs.get(&PCB_GID).unwrap();
            let (announce, withdraw, _) = resync(group, victim, None, true, false, Some(&extras));
            let announce_keys: HashSet<(Prefix, u32)> =
                announce.iter().map(|r| (r.prefix, r.path_id)).collect();
            assert!(
                announce_keys.is_disjoint(&withdraw.iter().copied().collect()),
                "announce+withdraw of one key escaped for {victim}"
            );
            fold_wire(wire, announce, &withdraw);
            assert_wire_is_adv(group, victim, wire);
        };

    // (a) Lane retire lost: OTHER1 sources the winner, its wire
    // holds the substitution, the runner-up disappears.
    let mut m = staging_manager();
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    let out = stage_pcb(&mut m, &[p]);
    let mut wire = HashMap::new();
    let (announce, withdraw) = emit_walk(&out, OTHER1, None);
    fold_wire(&mut wire, announce, &withdraw);
    assert_eq!(wire[&(p, 0)].peer, OTHER2, "wire holds the substitution");
    unseed(&mut m, OTHER2, p);
    lose_and_resync(&mut m, OTHER1, &mut wire);
    assert!(wire.is_empty(), "the retire withdraw must be delivered");

    // (b) Substituted announce lost: the lane fills under an
    // unchanged winner; the resync re-derives the announce.
    let mut m = staging_manager();
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    seed(&mut m, cand(p, OTHER1, 300));
    let out = stage_pcb(&mut m, &[p]);
    let mut wire = HashMap::new();
    let (announce, withdraw) = emit_walk(&out, OTHER1, None);
    fold_wire(&mut wire, announce, &withdraw);
    assert!(wire.is_empty(), "winner's own source starts empty");
    seed(&mut m, cand(p, OTHER2, 200));
    lose_and_resync(&mut m, OTHER1, &mut wire);
    assert_eq!(
        wire[&(p, 0)].peer,
        OTHER2,
        "the substitution was re-derived"
    );

    // (c) Source flip ONTO the member with a populated lane: the
    // recorded source-flip withdraw must be filtered (the lane
    // substitutes) and the substituted announce delivered.
    let mut m = staging_manager();
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, MEMBER, 100));
    let out = stage_pcb(&mut m, &[p]);
    let mut wire = HashMap::new();
    let (announce, withdraw) = emit_walk(&out, MEMBER, None);
    fold_wire(&mut wire, announce, &withdraw);
    assert_eq!(wire[&(p, 0)].peer, OTHER1, "wire holds the staged winner");
    seed(&mut m, cand(p, MEMBER, 400));
    lose_and_resync(&mut m, MEMBER, &mut wire);
    assert_eq!(
        wire[&(p, 0)].peer,
        OTHER1,
        "the new winner's source ends on the runner-up"
    );
}

// --- ADR-0126 Phase 2 (cold replays): refresh/join replay, the
// --- regroup baseline snapshot, and the force-refresh prior — all
// --- routed through `adv_entry`.

/// The three-slot replay fixture: k1 a plain slot (OTHER1), k2
/// winner MEMBER with the lane holding OTHER2 (nh residue, source
/// communities from `lane_comm`), k3 winner MEMBER with no lane.
fn replay_group(lane_comm: Option<u32>) -> GroupRibOut {
    let mut group = per_client_best_group(None);
    group.apply_delta(&announce_delta(prefix(1), OTHER1, None));
    group.apply_delta(&announce_delta(prefix(2), MEMBER, None));
    group.apply_delta(&announce_delta(prefix(3), MEMBER, None));
    group.apply_lane(
        prefix(2),
        Some(lane_entry(
            route(prefix(2), OTHER2),
            MEMBER,
            "lane",
            lane_comm,
        )),
    );
    group
}

/// Register `member` as a live outbound peer (real `PeerUp`, IPv4
/// unicast, the permissive test exact encoder unless one is
/// pending) and point its membership at the constructed group,
/// bypassing the classifier so the fixture controls the group cell
/// exactly. The registration's own dump is drained so a test
/// observes only what it triggers.
fn register_pcb_member(
    m: &mut RibManager,
    member: IpAddr,
    mut group: GroupRibOut,
) -> tokio::sync::mpsc::Receiver<crate::update::OutboundRouteUpdate> {
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel(8);
    m.handle_update(crate::update::RibUpdate::PeerUp {
        peer: member,
        session_id: 0,
        peer_asn: TARGET_ASN,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
        is_ebgp: false,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    while outbound_rx.try_recv().is_ok() {}
    group.members.insert(member);
    m.group_ribs.insert(PCB_GID, group);
    m.update_groups
        .members
        .insert(member, GroupMembership::Grouped(PCB_GID));
    outbound_rx
}

/// Fold every queued outbound update into
/// `(prefix → (source, nh flag), withdraws)`.
#[expect(
    clippy::type_complexity,
    reason = "one folded wire tuple keeps the replay assertions single-call"
)]
fn folded_outbound(
    rx: &mut tokio::sync::mpsc::Receiver<crate::update::OutboundRouteUpdate>,
) -> (
    HashMap<Prefix, (IpAddr, Option<NextHopAction>)>,
    Vec<(Prefix, u32)>,
) {
    let mut announced = HashMap::new();
    let mut withdrawn = Vec::new();
    while let Ok(update) = rx.try_recv() {
        assert_eq!(
            update.next_hop_override.len(),
            update.announce.len(),
            "nh flags must stay aligned with announces"
        );
        for (route, nh) in update.announce.iter().zip(update.next_hop_override.iter()) {
            announced.insert(route.prefix, (route.peer, nh.clone()));
        }
        withdrawn.extend(update.withdraw.iter().copied());
    }
    (announced, withdrawn)
}

/// RFC 2918 refresh replay substitution matrix through the REAL
/// grouped refresh arm: the member sourcing k2's winner receives
/// the LANE entry there (route, nh residue both the lane's), the
/// laneless own-sourced k3 replays nothing, and the plain k1 slot
/// is untouched.
#[test]
fn pcb_route_refresh_replays_lane_substitution() {
    let mut m = staging_manager();
    let mut rx = register_pcb_member(&mut m, MEMBER, replay_group(None));
    m.send_route_refresh_response(MEMBER, Afi::Ipv4, Safi::Unicast);
    let (announced, withdrawn) = folded_outbound(&mut rx);
    assert_eq!(
        announced.keys().copied().collect::<HashSet<_>>(),
        HashSet::from([prefix(1), prefix(2)]),
        "k2 substitutes the lane entry; k3's empty lane replays nothing"
    );
    assert_eq!(announced[&prefix(1)], (OTHER1, None));
    assert_eq!(
        announced[&prefix(2)],
        (OTHER2, Some(NextHopAction::Self_)),
        "the substituted slot carries the LANE's route and nh residue"
    );
    assert!(withdrawn.is_empty());
}

/// rs-control at the refresh replay decides the substituted slot
/// from the LANE entry's source attributes: a suppressing tag
/// removes exactly that slot from the replay.
#[test]
fn pcb_route_refresh_rs_member_suppresses_tagged_lane() {
    let mut m = staging_manager();
    // Community == the member's ASN ⇒ suppressed toward it.
    let mut rx = register_pcb_member(&mut m, MEMBER, replay_group(Some(TARGET_ASN)));
    m.peer_rs_control.insert(MEMBER, RS_ASN);
    m.send_route_refresh_response(MEMBER, Afi::Ipv4, Safi::Unicast);
    let (announced, withdrawn) = folded_outbound(&mut rx);
    assert_eq!(
        announced.keys().copied().collect::<Vec<_>>(),
        vec![prefix(1)],
        "the suppressed lane source removes the substituted slot"
    );
    assert!(withdrawn.is_empty());
}

/// Join / initial-dump replay substitution matrix, plus the
/// Decision 4 agreement the counters replay must keep: the
/// replayed announce set and `apply_group_join_counters`'s permit
/// count (run by the same dump) are the same fold over adv(m).
#[test]
fn pcb_initial_dump_replays_substitution_and_join_counters_agree() {
    let mut m = staging_manager();
    let mut rx = register_pcb_member(&mut m, MEMBER, replay_group(None));
    let permitted_before = m
        .export_policy_stats
        .get(&MEMBER)
        .map_or(0, |stats| stats.export_policy_routes_permitted);
    m.send_initial_table(MEMBER);
    let (announced, withdrawn) = folded_outbound(&mut rx);
    assert_eq!(
        announced.keys().copied().collect::<HashSet<_>>(),
        HashSet::from([prefix(1), prefix(2)])
    );
    assert_eq!(announced[&prefix(1)], (OTHER1, None));
    assert_eq!(announced[&prefix(2)], (OTHER2, Some(NextHopAction::Self_)));
    assert!(withdrawn.is_empty());
    let permitted = m
        .export_policy_stats
        .get(&MEMBER)
        .map_or(0, |stats| stats.export_policy_routes_permitted)
        - permitted_before;
    assert_eq!(
        permitted,
        u64::try_from(announced.len()).unwrap(),
        "the join replay and its counter replay diverged over adv(m)"
    );
}

/// Darkness at the replay seams: an empty-lane per-client-best
/// group refresh-replays byte-identically to a plain group over
/// the same table.
#[test]
fn pcb_empty_lane_refresh_replay_matches_plain_group() {
    let build = |mut group: GroupRibOut| {
        group.apply_delta(&announce_delta(prefix(1), OTHER1, None));
        group.apply_delta(&announce_delta(prefix(2), MEMBER, None));
        group
    };
    let mut replays = [build(per_client_best_group(None)), build(empty_group())]
        .into_iter()
        .map(|group| {
            let mut m = staging_manager();
            let mut rx = register_pcb_member(&mut m, MEMBER, group);
            m.send_route_refresh_response(MEMBER, Afi::Ipv4, Safi::Unicast);
            let (announced, withdrawn) = folded_outbound(&mut rx);
            let mut announced: Vec<_> = announced.into_iter().collect();
            announced.sort_by_key(|(prefix, _)| *prefix);
            (announced, withdrawn)
        });
    let pcb = replays.next().unwrap();
    let plain = replays.next().unwrap();
    assert_eq!(pcb, plain);
}

/// RFC 8326 `GShut` force-refresh routes through the resync arm with
/// `is_force = true` (the ADR-0126 Decision 4 replay set): driven
/// through the REAL `RefreshPeerOutbound` path, it re-announces
/// adv(m) — the lane substitution included, with the lane's nh
/// residue — and withdraws nothing.
#[test]
fn pcb_force_refresh_reannounces_lane_substitution() {
    let mut m = staging_manager();
    let mut rx = register_pcb_member(&mut m, MEMBER, replay_group(None));
    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
    m.handle_refresh_peer_outbound(MEMBER, reply_tx);
    let (announced, withdrawn) = folded_outbound(&mut rx);
    assert_eq!(
        announced.keys().copied().collect::<HashSet<_>>(),
        HashSet::from([prefix(1), prefix(2)])
    );
    assert_eq!(announced[&prefix(2)], (OTHER2, Some(NextHopAction::Self_)));
    assert!(withdrawn.is_empty(), "force-only withdraws nothing");
}

/// Exact-export encoder rejecting exactly one unicast prefix — the
/// smallest instrument that makes the force prior's owed-withdrawal
/// decision observable.
struct RejectPrefixExactExport(Prefix);
struct RejectPrefixSnapshot(Prefix);

impl crate::update::ExactExportSnapshot for RejectPrefixSnapshot {
    fn owner_id(&self) -> u64 {
        7
    }

    fn generation(&self) -> u64 {
        1
    }

    fn probe_announcement(
        &self,
        candidate: crate::update::ExactExportCandidate<'_>,
    ) -> Result<crate::update::ExactExportResult, crate::update::ExactExportError> {
        match candidate {
            crate::update::ExactExportCandidate::Unicast { route, .. }
                if route.prefix == self.0 =>
            {
                Err(crate::update::ExactExportError::new(
                    crate::update::ExactExportErrorCode::MessageTooLong,
                    "synthetic per-prefix ceiling",
                ))
            }
            _ => Ok(crate::update::ExactExportResult {
                encoded_len: 64,
                max_len: 4_096,
                generation: 1,
            }),
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl crate::update::ExactExportEncoder for RejectPrefixExactExport {
    fn owner_id(&self) -> u64 {
        7
    }

    fn snapshot(&self) -> Arc<dyn crate::update::ExactExportSnapshot> {
        Arc::new(RejectPrefixSnapshot(self.0))
    }
}

/// The force-refresh `group_prior` is adv(m): the substituted slot
/// IS the member's prior wire, so an exact-export rejection of the
/// substituted announce owes the withdrawal that removes it —
/// under the historical own-source skip the slot was absent from
/// the prior and the stale substitution leaked on the peer.
#[test]
fn pcb_force_prior_covers_substituted_slot_for_exact_rejection() {
    let mut m = staging_manager();
    m.handle_update(crate::update::RibUpdate::SetPeerExportEncoder {
        peer: MEMBER,
        session_id: 0,
        encoder: Arc::new(RejectPrefixExactExport(prefix(2))),
    });
    let mut rx = register_pcb_member(&mut m, MEMBER, replay_group(None));
    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
    m.handle_refresh_peer_outbound(MEMBER, reply_tx);
    let (announced, withdrawn) = folded_outbound(&mut rx);
    assert_eq!(
        announced.keys().copied().collect::<Vec<_>>(),
        vec![prefix(1)],
        "the rejected substitution must not be announced"
    );
    assert_eq!(
        withdrawn,
        vec![(prefix(2), 0)],
        "a rejected previously-advertised substitution owes its withdrawal"
    );
    assert!(
        m.peer_unexportable
            .get(&MEMBER)
            .is_some_and(|keys| keys.contains(&ExactExportKey::Unicast(prefix(2), 0))),
        "the rejection must land in the member's overlay"
    );
}

/// Regroup baseline interplay (ADR-0126 Decision 4): the snapshot
/// records adv(m) — the LANE entry's wire form at a substituted
/// slot — so the destination-side one-shot diff suppresses an
/// unchanged substitution, announces a changed one, and withdraws
/// a retired one.
#[test]
fn pcb_member_view_snapshot_records_substitution_for_regroup_diff() {
    let (k1, k2) = (prefix(1), prefix(2));
    let mut group = per_client_best_group(None);
    group.apply_delta(&announce_delta(k1, OTHER1, None));
    group.apply_delta(&announce_delta(k2, MEMBER, None));
    group.apply_lane(
        k2,
        Some(lane_entry(route(k2, OTHER2), MEMBER, "lane", None)),
    );

    let baseline = group.member_view_snapshot(MEMBER, None, &HashSet::new());
    assert_eq!(baseline.len(), 2);
    assert_eq!(
        baseline[&(k2, 0)].peer,
        OTHER2,
        "the baseline records adv(m), not the staged winner"
    );

    let regroup_diff = |group: &GroupRibOut| {
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_flags = Vec::new();
        RibManager::assemble_group_resync(
            group,
            MEMBER,
            None,
            false,
            false,
            Some(&baseline),
            None,
            &mut announce,
            &mut withdraw,
            &mut nh_flags,
        );
        (announce, withdraw)
    };

    // Unchanged substitution: the one-shot diff is byte-empty.
    let (announce, withdraw) = regroup_diff(&group);
    assert!(
        announce.is_empty() && withdraw.is_empty(),
        "an unchanged substitution must be equality-suppressed"
    );

    // Changed substitution: announced (implicit replace), never
    // withdrawn.
    group.apply_lane(
        k2,
        Some(lane_entry(cand(k2, OTHER2, 250), MEMBER, "lane", None)),
    );
    let (announce, withdraw) = regroup_diff(&group);
    assert_eq!(announce.len(), 1);
    assert_eq!((announce[0].prefix, announce[0].peer), (k2, OTHER2));
    assert!(
        !routes_equal(&announce[0], &baseline[&(k2, 0)]),
        "the announce is the CHANGED lane content"
    );
    assert!(withdraw.is_empty());

    // Retired substitution: the baseline key is no longer
    // retained — withdrawn.
    group.apply_lane(k2, None);
    let (announce, withdraw) = regroup_diff(&group);
    assert!(announce.is_empty());
    assert_eq!(withdraw, vec![(k2, 0)]);
}

fn vpn_key(n: u8) -> VpnRouteKey {
    VpnRouteKey {
        route_distinguisher: RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, n]),
        prefix: VpnPrefix::v4(Ipv4Addr::new(10, 210, n, 0), 24).unwrap(),
    }
}

fn vpn_route(n: u8, src: IpAddr) -> VpnRibRoute {
    let key = vpn_key(n);
    VpnRibRoute {
        nlri: VpnNlri {
            labels: vec![MplsLabelEntry::try_new(100, 0, true).unwrap()],
            route_distinguisher: key.route_distinguisher,
            prefix: key.prefix,
        },
        next_hop: src,
        link_local_next_hop: None,
        peer: src,
        attributes: std::sync::Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: std::time::Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    }
}

fn vpn_announce_delta(n: u8, src: IpAddr, old: Option<IpAddr>) -> VpnGroupDelta {
    VpnGroupDelta {
        key: vpn_key(n),
        new: Some(vpn_route(n, src)),
        old: old.map(|peer| vpn_route(n, peer)),
        policy_label: None,
    }
}

fn vpn_withdraw_delta(n: u8, old: Option<IpAddr>) -> VpnGroupDelta {
    VpnGroupDelta {
        key: vpn_key(n),
        new: None,
        old: old.map(|peer| vpn_route(n, peer)),
        policy_label: None,
    }
}

/// Risk-2 exhaustive VPN source-flip matrix: every combination of
/// `{old source} × {new source | withdraw}` for a fixed member,
/// asserted against the per-peer-path reference semantics (design
/// §2.2, `pass ≡ true`): announce ⇔ GETS; withdraw ⇔ HAD ∧ ¬GETS.
#[test]
fn vpn_source_flip_matrix_exhaustive() {
    let old_sources = [None, Some(MEMBER), Some(OTHER1), Some(OTHER2)];
    let new_sources = [None, Some(MEMBER), Some(OTHER1), Some(OTHER2)];
    for old in old_sources {
        for new in new_sources {
            if new.is_none() && old.is_none() {
                // A withdraw delta always has an old entry.
                continue;
            }
            let delta = match new {
                Some(src) => vpn_announce_delta(1, src, old),
                None => vpn_withdraw_delta(1, old),
            };
            let mut announce = Vec::new();
            let mut withdraw = Vec::new();
            let count_delta = emit_vpn_group_deltas_for_member(
                std::slice::from_ref(&delta),
                MEMBER,
                None,
                &mut announce,
                &mut withdraw,
            );

            let member_had = old.is_some_and(|s| s != MEMBER);
            let member_gets = new.is_some_and(|s| s != MEMBER);
            assert_eq!(
                announce.len(),
                usize::from(member_gets),
                "announce mismatch for old={old:?} new={new:?}"
            );
            assert_eq!(
                withdraw.len(),
                usize::from(member_had && !member_gets),
                "withdraw mismatch for old={old:?} new={new:?}"
            );
            assert_eq!(
                count_delta[0],
                i64::from(member_gets && !member_had) - i64::from(member_had && !member_gets),
                "count delta mismatch for old={old:?} new={new:?}"
            );
            if member_gets {
                assert_eq!(announce[0].peer, new.unwrap());
            }
            if member_had && !member_gets {
                assert_eq!(withdraw[0].nlri_key, vpn_key(1));
                assert_eq!(withdraw[0].path_id, 0);
            }
        }
    }
}

/// VPN dirty-member resync: full-VPN-table announce minus
/// own-sourced; VPN tombstones withdraw unless the member still
/// retains the key via another source; own-sourced tombstones are a
/// safe over-withdraw. Force bypasses only the equality suppression.
#[test]
fn vpn_dirty_resync_replays_table_and_tombstones() {
    let mut group = empty_group();
    group.apply_vpn_delta(&vpn_announce_delta(1, OTHER1, None));
    group.apply_vpn_delta(&vpn_announce_delta(2, MEMBER, None));
    group.vpn_tombstones.insert(vpn_key(1)); // retained via OTHER1 — no withdraw
    group.vpn_tombstones.insert(vpn_key(3)); // gone — withdraw
    group.vpn_tombstones.insert(vpn_key(2)); // member-sourced — safe over-withdraw

    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    RibManager::assemble_group_vpn_resync(
        &group,
        MEMBER,
        None,
        true,
        false,
        None,
        None,
        &mut announce,
        &mut withdraw,
    );
    let announced: HashSet<VpnRouteKey> = announce.iter().map(|r| r.nlri.key()).collect();
    assert_eq!(
        announced,
        HashSet::from([vpn_key(1)]),
        "own-sourced entries excluded"
    );
    let withdrawn: HashSet<VpnRouteKey> = withdraw.iter().map(|k| k.nlri_key).collect();
    assert_eq!(withdrawn, HashSet::from([vpn_key(2), vpn_key(3)]));

    // Regroup one-shot diff: unchanged baseline entry suppressed,
    // baseline key no longer retained withdrawn.
    let mut baseline: FxHashMap<VpnRouteKey, VpnRibRoute> = FxHashMap::default();
    baseline.insert(vpn_key(1), vpn_route(1, OTHER1)); // unchanged — suppressed
    baseline.insert(vpn_key(5), vpn_route(5, OTHER1)); // gone — withdraw
    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    RibManager::assemble_group_vpn_resync(
        &group,
        MEMBER,
        None,
        true,
        false,
        Some(&baseline),
        None,
        &mut announce,
        &mut withdraw,
    );
    assert!(announce.is_empty(), "baseline-equal entries suppressed");
    let withdrawn: HashSet<VpnRouteKey> = withdraw.iter().map(|k| k.nlri_key).collect();
    assert!(withdrawn.contains(&vpn_key(5)));

    // Force re-announces every retained entry.
    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    RibManager::assemble_group_vpn_resync(
        &group,
        MEMBER,
        None,
        false,
        true,
        Some(&baseline),
        None,
        &mut announce,
        &mut withdraw,
    );
    let announced: HashSet<VpnRouteKey> = announce.iter().map(|r| r.nlri.key()).collect();
    assert_eq!(announced, HashSet::from([vpn_key(1)]));
}

/// VPN count synthesis tracks `apply_vpn_delta` (announce, source
/// flip, withdraw), and `family_counts_for` buckets VPN by family.
#[test]
fn vpn_counts_and_family_synthesis_track_deltas() {
    let mut group = GroupRibOut::new(
        None,
        false,
        false,
        true,
        None,
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)],
        vec![],
        false,
        0,
    );
    assert!(group.stages_vpn());
    group.apply_delta(&announce_delta(prefix(1), OTHER1, None));
    group.apply_vpn_delta(&vpn_announce_delta(1, OTHER1, None));
    group.apply_vpn_delta(&vpn_announce_delta(2, MEMBER, None));
    assert_eq!(group.vpn_advertised_count_for(MEMBER), 1);
    assert_eq!(group.vpn_advertised_count_for(OTHER1), 1);
    assert_eq!(group.vpn_advertised_count_for(OTHER2), 2);
    // Unicast count synthesis is untouched by the VPN entries.
    assert_eq!(group.advertised_count_for(MEMBER), 1);
    assert_eq!(
        group.family_counts_for(MEMBER),
        vec![
            ((Afi::Ipv4, Safi::Unicast), 1),
            ((Afi::Ipv4, Safi::MplsVpn), 1)
        ]
    );
    let view = group.member_vpn_view_snapshot(MEMBER, None, &HashSet::new());
    assert_eq!(view.len(), 1);
    assert!(view.contains_key(&vpn_key(1)));

    // Source flip key 1 OTHER1 → MEMBER keeps counts exact.
    group.apply_vpn_delta(&vpn_announce_delta(1, MEMBER, Some(OTHER1)));
    assert_eq!(group.vpn_advertised_count_for(MEMBER), 0);
    assert_eq!(group.vpn_advertised_count_for(OTHER1), 2);

    // Withdraw drops the entry and its label residue.
    group.apply_vpn_delta(&vpn_withdraw_delta(1, Some(MEMBER)));
    assert_eq!(group.vpn_advertised_count_for(OTHER1), 1);
    assert_eq!(group.table.vpn_len(), 1);
    assert!(!group.vpn_staged_labels.contains_key(&vpn_key(1)));

    // An RTC-negotiated sendable set stages VPN too (v2 slice 2):
    // Φ is applied per member at emit, not by a staging gate.
    let rtc_group = GroupRibOut::new(
        None,
        false,
        false,
        true,
        None,
        vec![
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv4, Safi::MplsVpn),
            (Afi::Ipv4, Safi::RtConstrain),
        ],
        vec![],
        false,
        0,
    );
    assert!(rtc_group.stages_vpn());
    assert!(rtc_group.rtc_negotiated());
}

/// Inline (unlabelled) staged entries leave NO slot in either label
/// residue map. Absent and present-`None` are the same verdict at
/// every reader, so the unlabelled case — the whole table when no
/// export policy is configured — must not pay a slot per staged
/// route. Asserted on map occupancy: the resolved label is `None`
/// either way, so occupancy is the only observable difference.
#[test]
fn inline_staged_entries_leave_no_label_residue() {
    let mut group = GroupRibOut::new(
        None,
        false,
        false,
        true,
        None,
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv4, Safi::MplsVpn)],
        vec![],
        false,
        0,
    );
    let key = (prefix(1), 0);
    let resolved = |g: &GroupRibOut| {
        (
            g.staged_labels
                .get(&key)
                .and_then(|l| l.as_deref())
                .is_none(),
            g.vpn_staged_labels
                .get(&vpn_key(1))
                .cloned()
                .unwrap_or(None)
                .is_none(),
        )
    };

    // Unlabelled announce: no slot, and the readers still see None.
    group.apply_delta(&announce_delta(prefix(1), OTHER1, None));
    group.apply_vpn_delta(&vpn_announce_delta(1, OTHER1, None));
    assert!(!group.staged_labels.contains_key(&key));
    assert!(!group.vpn_staged_labels.contains_key(&vpn_key(1)));
    assert_eq!(resolved(&group), (true, true));

    // A labelled restage DOES take a slot — the residue still
    // carries what join-time counter replay reads.
    let mut labelled = announce_delta(prefix(1), OTHER1, Some(OTHER1));
    labelled.policy_label = Some(Arc::from("export-chain"));
    group.apply_delta(&labelled);
    let mut vpn_labelled = vpn_announce_delta(1, OTHER1, Some(OTHER1));
    vpn_labelled.policy_label = Some(Arc::from("export-chain"));
    group.apply_vpn_delta(&vpn_labelled);
    assert_eq!(
        group.staged_labels.get(&key).and_then(|l| l.as_deref()),
        Some("export-chain")
    );
    assert_eq!(
        group
            .vpn_staged_labels
            .get(&vpn_key(1))
            .and_then(|label| label.as_deref()),
        Some("export-chain")
    );

    // Restaging inline REMOVES the slot rather than retaining the
    // stale label — a skipped insert would leak the old verdict
    // into the joining member's replayed counters.
    group.apply_delta(&announce_delta(prefix(1), OTHER1, Some(OTHER1)));
    group.apply_vpn_delta(&vpn_announce_delta(1, OTHER1, Some(OTHER1)));
    assert!(!group.staged_labels.contains_key(&key));
    assert!(!group.vpn_staged_labels.contains_key(&vpn_key(1)));
    assert_eq!(resolved(&group), (true, true));
}

/// Shared staging must retain the evaluator's policy-label allocation from
/// one delta through the group-table residue. Two routes ending in the
/// same policy therefore share one backing label rather than allocating a
/// `String` per staged key.
///
/// Red proof: rebuilding either stored label with
/// `Arc::from(label.as_ref())` leaves the operator-visible text unchanged
/// but makes the pointer-identity assertion fail.
#[test]
fn staged_policy_labels_share_the_evaluation_allocation() {
    let mut group = empty_group();
    let label: Arc<str> = Arc::from("shared-export-policy");
    for n in [1, 2] {
        let mut delta = announce_delta(prefix(n), OTHER1, None);
        delta.policy_label = Some(Arc::clone(&label));
        group.apply_delta(&delta);
    }

    let first = group
        .staged_labels
        .get(&(prefix(1), 0))
        .and_then(Option::as_ref)
        .expect("first route carries its terminal policy");
    let second = group
        .staged_labels
        .get(&(prefix(2), 0))
        .and_then(Option::as_ref)
        .expect("second route carries its terminal policy");
    assert_eq!(first.as_ref(), "shared-export-policy");
    assert!(Arc::ptr_eq(&label, first));
    assert!(Arc::ptr_eq(first, second));
}

/// An RTC membership over a specific Route Target (full 96-bit
/// origin-AS + RT prefix).
fn membership(rts: &[u64]) -> RtcMembership {
    let mut entries: Vec<rustbgpd_wire::RtcNlri> = rts
        .iter()
        .map(|&rt| {
            let global_admin = (rt >> 32) & 0xFFFF;
            rustbgpd_wire::RtcNlri::new(global_admin as u32, rt, 96).unwrap()
        })
        .collect();
    entries.sort_unstable();
    entries.dedup();
    RtcMembership {
        has_default: false,
        entries,
    }
}

/// RT extended community `65000:n` (two-octet-AS route target).
const fn rt(n: u64) -> u64 {
    0x0002_FDE8_0000_0000 | n
}

fn vpn_route_with_rts(n: u8, src: IpAddr, rts: &[u64]) -> VpnRibRoute {
    let mut route = vpn_route(n, src);
    route.attributes = std::sync::Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::ExtendedCommunities(
            rts.iter().copied().map(ExtendedCommunity::new).collect(),
        ),
    ]);
    route
}

/// The Φ dimension of the emit matrix (design §2.2): `had`/`gets`
/// consult `pass_m` via the REUSED `RtcMembership::matches_any` —
/// route-mutates-out-of-Φ withdraws, into-Φ announces without a
/// spurious withdraw, strict-empty membership receives nothing and
/// withdraws nothing (`had` = false for entries it never had).
#[test]
fn vpn_matrix_rt_filter_dimension() {
    let phi1 = membership(&[rt(1)]);
    let empty = RtcMembership::default();
    let old_r1 = vpn_route_with_rts(1, OTHER1, &[rt(1)]);
    let new_r2 = vpn_route_with_rts(1, OTHER1, &[rt(2)]);

    // Attr change flips the RT out of Φ: had ∧ ¬gets → withdraw.
    let delta = VpnGroupDelta {
        key: vpn_key(1),
        new: Some(new_r2.clone()),
        old: Some(old_r1.clone()),
        policy_label: None,
    };
    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    let d = emit_vpn_group_deltas_for_member(
        std::slice::from_ref(&delta),
        MEMBER,
        Some(&phi1),
        &mut announce,
        &mut withdraw,
    );
    assert!(announce.is_empty());
    assert_eq!(withdraw.len(), 1);
    assert_eq!(d, [-1, 0]);

    // The reverse mutation (into Φ): ¬had ∧ gets → announce only.
    let delta = VpnGroupDelta {
        key: vpn_key(1),
        new: Some(old_r1.clone()),
        old: Some(new_r2.clone()),
        policy_label: None,
    };
    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    let d = emit_vpn_group_deltas_for_member(
        std::slice::from_ref(&delta),
        MEMBER,
        Some(&phi1),
        &mut announce,
        &mut withdraw,
    );
    assert_eq!(announce.len(), 1);
    assert!(withdraw.is_empty());
    assert_eq!(d, [1, 0]);

    // Strict-empty membership: silent for both directions.
    for delta in [
        VpnGroupDelta {
            key: vpn_key(1),
            new: Some(old_r1.clone()),
            old: None,
            policy_label: None,
        },
        VpnGroupDelta {
            key: vpn_key(1),
            new: None,
            old: Some(old_r1.clone()),
            policy_label: None,
        },
    ] {
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let d = emit_vpn_group_deltas_for_member(
            std::slice::from_ref(&delta),
            MEMBER,
            Some(&empty),
            &mut announce,
            &mut withdraw,
        );
        assert!(announce.is_empty() && withdraw.is_empty());
        assert_eq!(d, [0, 0]);
    }
}

/// The Φ dimension of the dirty resync (design §2.4): announce only
/// Φ-passing entries; the failing-retention backstop (over-)withdraws
/// table keys outside Φ (healing a membership delta missed while
/// dirty); the snapshot is Φ-filtered.
#[test]
fn vpn_dirty_resync_rt_filter_dimension() {
    let phi1 = membership(&[rt(1)]);
    let mut group = GroupRibOut::new(
        None,
        false,
        false,
        true,
        None,
        vec![
            (Afi::Ipv4, Safi::Unicast),
            (Afi::Ipv4, Safi::MplsVpn),
            (Afi::Ipv4, Safi::RtConstrain),
        ],
        vec![],
        false,
        0,
    );
    let in_phi = vpn_route_with_rts(1, OTHER1, &[rt(1)]);
    let out_phi = vpn_route_with_rts(2, OTHER1, &[rt(2)]);
    group.apply_vpn_delta(&VpnGroupDelta {
        key: in_phi.nlri.key(),
        new: Some(in_phi.clone()),
        old: None,
        policy_label: None,
    });
    group.apply_vpn_delta(&VpnGroupDelta {
        key: out_phi.nlri.key(),
        new: Some(out_phi.clone()),
        old: None,
        policy_label: None,
    });

    // A membership narrow missed while dirty lands the leaving key
    // in the extra-withdraw residue; the resync announces only the
    // Φ-passing table and withdraws the residue (Φ-aware retention:
    // a staged-but-Φ-failing key is NOT retained).
    let extras: HashSet<VpnRouteKey> = HashSet::from([out_phi.nlri.key()]);
    let mut announce = Vec::new();
    let mut withdraw = Vec::new();
    RibManager::assemble_group_vpn_resync(
        &group,
        MEMBER,
        Some(&phi1),
        true,
        false,
        None,
        Some(&extras),
        &mut announce,
        &mut withdraw,
    );
    let announced: HashSet<VpnRouteKey> = announce.iter().map(|r| r.nlri.key()).collect();
    assert_eq!(announced, HashSet::from([in_phi.nlri.key()]));
    let withdrawn: HashSet<VpnRouteKey> = withdraw.iter().map(|k| k.nlri_key).collect();
    assert_eq!(
        withdrawn,
        HashSet::from([out_phi.nlri.key()]),
        "a staged key failing Φ is not retained — the extras withdraw must emit"
    );

    // Snapshot under Φ = the true advertised set.
    let view = group.member_vpn_view_snapshot(MEMBER, Some(&phi1), &HashSet::new());
    assert_eq!(view.len(), 1);
    assert!(view.contains_key(&in_phi.nlri.key()));

    // Count recompute-from-table under Φ.
    assert_eq!(
        group.vpn_member_counts_from_table(MEMBER, Some(&phi1)),
        [1, 0]
    );
    group.recompute_vpn_member_counts(MEMBER, Some(&phi1));
    assert_eq!(group.vpn_advertised_count_for(MEMBER), 1);
    assert_eq!(
        group.family_counts_for(MEMBER),
        vec![((Afi::Ipv4, Safi::MplsVpn), 1)]
    );
}

/// The join replay dimension: a joining member's view is the table
/// minus its own-sourced entries, with O(1) count synthesis kept in
/// lockstep by `apply_delta` (announce, replace, withdraw).
#[test]
fn join_view_and_count_synthesis_track_deltas() {
    let mut group = empty_group();
    let (k1, k2) = (prefix(1), prefix(2));
    group.apply_delta(&announce_delta(k1, OTHER1, None));
    group.apply_delta(&announce_delta(k2, MEMBER, None));
    assert_eq!(group.advertised_count_for(MEMBER), 1);
    assert_eq!(group.advertised_count_for(OTHER1), 1);
    assert_eq!(group.advertised_count_for(OTHER2), 2);
    assert_eq!(
        group.family_counts_for(MEMBER),
        vec![((Afi::Ipv4, Safi::Unicast), 1)]
    );
    let view = group.member_view_snapshot(MEMBER, None, &HashSet::new());
    assert_eq!(view.len(), 1);
    assert!(view.contains_key(&(k1, 0)));

    // Source flip k1 OTHER1 → MEMBER keeps counts exact.
    group.apply_delta(&announce_delta(k1, MEMBER, Some(OTHER1)));
    assert_eq!(group.advertised_count_for(MEMBER), 0);
    assert_eq!(group.advertised_count_for(OTHER1), 2);

    // Withdraw drops the entry and its residue.
    group.apply_delta(&withdraw_delta(k1, Some(MEMBER)));
    assert_eq!(group.advertised_count_for(OTHER1), 1);
    assert_eq!(group.table.len(), 1);
}

// --- ADR-0126 staging trigger: per-client-best groups stage from
// --- the widened all-affected set, plain groups from
// --- `best_changed` exactly.

const OTHER3: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 9, 0, 4));

/// Plain sibling of [`per_client_best_group`] with a caller-chosen
/// export chain — the staging-trigger control group.
fn plain_group_with_chain(chain: Option<PolicyChain>) -> GroupRibOut {
    GroupRibOut::new(
        chain,
        false,
        false,
        true,
        None,
        vec![(Afi::Ipv4, Safi::Unicast)],
        vec![],
        false,
        0,
    )
}

/// A candidate change that leaves the Loc-RIB best untouched
/// (`best_changed` empty, the prefix carried by `all_affected`
/// alone) must still restage a per-client-best group: the walk's
/// input is the candidate list, not the Loc-RIB best. The chain
/// denies the Loc-RIB best, so the advertised winner is the
/// second-ranked candidate — withdrawing IT moves the wire while
/// the best stands.
#[test]
fn pcb_group_restages_from_all_affected_without_best_change() {
    let mut m = staging_manager();
    let p = prefix(1);
    let mut rx = register_pcb_member(
        &mut m,
        MEMBER,
        per_client_best_group(Some(deny_sources_chain(&[OTHER1]))),
    );
    seed(&mut m, cand(p, OTHER1, 300)); // Loc-RIB best, chain-denied
    seed(&mut m, cand(p, OTHER2, 200)); // advertised winner
    seed(&mut m, cand(p, OTHER3, 100));
    let changed = m.recompute_best(&HashSet::from([p]));
    m.distribute_changes(&changed, &HashSet::from([p]));
    let (announced, _) = folded_outbound(&mut rx);
    assert_eq!(
        announced[&p].0, OTHER2,
        "precondition: the winner is the second-ranked candidate"
    );

    // Withdraw the WINNER's candidate — not the Loc-RIB best, so
    // selection reports no best change.
    unseed(&mut m, OTHER2, p);
    let changed = m.recompute_best(&HashSet::from([p]));
    assert!(
        changed.is_empty(),
        "precondition: the Loc-RIB best is unmoved"
    );
    m.distribute_changes(&changed, &HashSet::from([p]));
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(
        group.table.get(&p, 0).map(|r| r.peer),
        Some(OTHER3),
        "the widened pass restages the next permitted candidate"
    );
    let (announced, withdrawn) = folded_outbound(&mut rx);
    assert_eq!(
        announced.get(&p).map(|(source, _)| *source),
        Some(OTHER3),
        "the member receives the new winner"
    );
    assert!(withdrawn.is_empty());
}

/// The staging-trigger control: a plain group with the same
/// candidates and chain stages Loc-RIB-best-or-nothing, so the
/// same candidate withdrawal correctly restages nothing.
#[test]
fn plain_group_denied_best_does_not_restage_on_candidate_withdrawal() {
    let mut m = staging_manager();
    let p = prefix(1);
    let mut rx = register_pcb_member(
        &mut m,
        MEMBER,
        plain_group_with_chain(Some(deny_sources_chain(&[OTHER1]))),
    );
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    seed(&mut m, cand(p, OTHER3, 100));
    let changed = m.recompute_best(&HashSet::from([p]));
    m.distribute_changes(&changed, &HashSet::from([p]));

    unseed(&mut m, OTHER2, p);
    let changed = m.recompute_best(&HashSet::from([p]));
    assert!(changed.is_empty());
    m.distribute_changes(&changed, &HashSet::from([p]));
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert!(
        group.table.get(&p, 0).is_none(),
        "the denied Loc-RIB best stages nothing for a plain group"
    );
    let (announced, withdrawn) = folded_outbound(&mut rx);
    assert!(announced.is_empty() && withdrawn.is_empty());
}

/// The lane-stale shape from the `OpenBGPD` issue-#21 family: the
/// permitted winner IS the (unmoved) Loc-RIB best and the
/// runner-up candidate is withdrawn — `best_changed` stays empty.
/// The widened pass retires the lane and withdraws the substituted
/// slot from `source(w)`; staging only `best_changed` would leave
/// the lane stale and the withdrawn route on that member's wire.
#[test]
fn pcb_lane_retires_when_runner_up_withdrawn_without_best_change() {
    let mut m = staging_manager();
    let p = prefix(1);
    let mut rx = register_pcb_member(&mut m, OTHER1, per_client_best_group(None));
    seed(&mut m, cand(p, OTHER1, 300)); // winner = Loc-RIB best, member-sourced
    seed(&mut m, cand(p, OTHER2, 200)); // runner-up
    let changed = m.recompute_best(&HashSet::from([p]));
    m.distribute_changes(&changed, &HashSet::from([p]));
    let (announced, _) = folded_outbound(&mut rx);
    assert_eq!(
        announced[&p].0, OTHER2,
        "precondition: source(w) holds the lane substitution"
    );
    assert_eq!(lane_source(&m, p), Some(OTHER2));

    unseed(&mut m, OTHER2, p);
    let changed = m.recompute_best(&HashSet::from([p]));
    assert!(
        changed.is_empty(),
        "precondition: the Loc-RIB best is unmoved"
    );
    m.distribute_changes(&changed, &HashSet::from([p]));
    assert_eq!(
        lane_source(&m, p),
        None,
        "the widened pass retires the lane"
    );
    let (announced, withdrawn) = folded_outbound(&mut rx);
    assert!(announced.is_empty());
    assert_eq!(
        withdrawn,
        vec![(p, 0)],
        "the substituted slot is withdrawn from source(w)"
    );
}

/// Cost guard for the widened pass (ADR-0126 Decision 2 pricing):
/// a candidate change below both slots restages the prefix through
/// the walk, but winner-equality and lane suppression make it a
/// no-op — zero deltas, zero lane transitions.
#[test]
fn pcb_widened_pass_with_unchanged_winner_and_lane_is_noop() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(p, OTHER2, 200));
    seed(&mut m, cand(p, OTHER3, 100));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let _ = stage_pcb(&mut m, &[p]);

    // The third-ranked candidate churns — below the winner AND the
    // lane; the prefix arrives via `all_affected` alone.
    unseed(&mut m, OTHER3, p);
    let mut memo = super::super::distribution::ExportMemo::default();
    let staged = m.stage_update_groups(&HashSet::new(), &HashSet::from([p]), &mut memo);
    let out = staged.get(&PCB_GID).expect("per-client-best group staged");
    assert!(out.deltas.is_empty(), "unchanged winner stays suppressed");
    assert!(
        out.lane_deltas.is_empty(),
        "unchanged lane stays suppressed"
    );
    assert_eq!(lane_source(&m, p), Some(OTHER2));
}

/// Plain groups keep the exact `best_changed` staging input: an
/// all-affected-only pass stages no plain group at all (the
/// widened set is never even built without a per-client-best
/// group), and a mixed pass never leaks all-affected extras into a
/// plain group's staging.
#[test]
fn plain_group_staging_keeps_best_changed_exactly() {
    const PLAIN_GID: usize = 92;
    let mut m = staging_manager();
    let (p, q) = (prefix(1), prefix(2));
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, cand(q, OTHER2, 300));
    let _ = m.recompute_best(&HashSet::from([p, q]));
    m.group_ribs.insert(PLAIN_GID, empty_group());
    let mut memo = super::super::distribution::ExportMemo::default();
    let staged = m.stage_update_groups(&HashSet::new(), &HashSet::from([p]), &mut memo);
    assert!(
        staged.is_empty(),
        "an all-affected-only pass stages no plain group"
    );
    let staged = m.stage_update_groups(&HashSet::from([p]), &HashSet::from([p, q]), &mut memo);
    let out = staged
        .get(&PLAIN_GID)
        .expect("plain group staged over best_changed");
    assert_eq!(out.deltas.len(), 1);
    assert_eq!(
        out.deltas[0].prefix, p,
        "all-affected extras never reach a plain group"
    );
}

// --- ADR-0126 Decision 5: RFC 9234 OTC egress for per-client-best
// --- groups is enforced at the central pre-commit backstop — the
// --- walk records blocked staged output, never acts on it.

fn with_otc_attr(mut route: Route) -> Route {
    let mut attrs = (*route.attributes).clone();
    attrs.push(PathAttribute::OnlyToCustomer(64_496));
    route.attributes = Arc::new(attrs);
    route
}

/// [`per_client_best_group`] under a role RFC 9234 blocks OTC
/// egress for. `local_role` is group-uniform (in the group key), so
/// the snapshot is the walk's only role input.
fn per_client_best_customer_group() -> GroupRibOut {
    let mut group = per_client_best_group(None);
    group.local_role = Some(BgpRole::Customer);
    group
}

/// Register `member` on the UNGROUPED per-client-best path — the
/// grouped path's correctness oracle — with the staging knobs of
/// [`per_client_best_group`] (iBGP RR client) so both sides run
/// the same export gates. Since the ADR-0126 Phase 3 flip a
/// unicast-only per-client-best peer classifies Groupable, so the
/// slow-isolation override (which changes membership only, never
/// an export gate) keeps this fixture on the per-peer path.
fn register_ungrouped_pcb_peer(
    m: &mut RibManager,
    member: IpAddr,
) -> tokio::sync::mpsc::Receiver<crate::update::OutboundRouteUpdate> {
    m.slow_isolated_peers.insert(member);
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel(8);
    m.handle_update(crate::update::RibUpdate::PeerUp {
        peer: member,
        session_id: 0,
        peer_asn: TARGET_ASN,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![(Afi::Ipv4, Safi::Unicast)],
        is_ebgp: false,
        route_reflector_client: true,
        orr_vantage: None,
        per_client_best: true,
        interpret_rfc1997: true,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![],
        negotiated_llgr_families: vec![],
    });
    while outbound_rx.try_recv().is_ok() {}
    outbound_rx
}

/// Feed inbound routes through the REAL chunked distribution pass.
fn receive_routes(m: &mut RibManager, source: IpAddr, announced: Vec<Route>) {
    m.handle_update(crate::update::RibUpdate::RoutesReceived {
        peer: source,
        session_id: 0,
        announced,
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    while m.process_next_route_chunk() {}
}

/// Every queued envelope folded to the wire-relevant fields.
#[derive(Debug, PartialEq, Default)]
struct DrainedWire {
    announced: Vec<(Prefix, IpAddr)>,
    withdrawn: Vec<(Prefix, u32)>,
    otc_blocked: Vec<(Prefix, IpAddr)>,
}

fn drain_wire(
    rx: &mut tokio::sync::mpsc::Receiver<crate::update::OutboundRouteUpdate>,
) -> DrainedWire {
    let mut wire = DrainedWire::default();
    while let Ok(update) = rx.try_recv() {
        wire.announced
            .extend(update.announce.iter().map(|r| (r.prefix, r.peer)));
        wire.withdrawn.extend(update.withdraw.iter().copied());
        wire.otc_blocked
            .extend(update.otc_blocked.iter().map(|r| (r.prefix, r.peer)));
    }
    wire
}

/// No in-walk gate (ADR-0126 Decision 5): a blocked winner stays
/// staged in the table and the pass RECORDS it — into the pass
/// output and, committed, the persistent residue — including on a
/// later equality-suppressed restage. `source(w)` never sees its
/// own winner in the residue derivation.
#[test]
fn pcb_otc_blocked_winner_stays_staged_and_residue_recorded() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, with_otc_attr(cand(p, OTHER1, 300)));
    seed(&mut m, cand(p, OTHER2, 200));
    m.group_ribs
        .insert(PCB_GID, per_client_best_customer_group());

    let out = stage_pcb(&mut m, &[p]);

    assert_eq!(out.deltas.len(), 1);
    assert!(
        out.deltas[0].new.is_some(),
        "blocked winner is staged, not withdrawn"
    );
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    let staged = group
        .table
        .get(&p, 0)
        .expect("blocked winner stays in the table");
    assert_eq!(staged.peer, OTHER1);
    assert!(
        staged
            .attributes
            .iter()
            .any(|attr| matches!(attr, PathAttribute::OnlyToCustomer(_))),
        "the staged form keeps the OTC attribute"
    );
    assert_eq!(lane_source(&m, p), Some(OTHER2));
    assert_eq!(out.otc_blocked.len(), 1);
    assert_eq!(out.otc_blocked[0].peer, OTHER1);
    let blocked = group.otc_blocked_for_member(MEMBER, None);
    assert_eq!(
        blocked.iter().map(|r| r.peer).collect::<Vec<_>>(),
        vec![OTHER1],
        "non-source members see the blocked winner"
    );
    assert!(
        group.otc_blocked_for_member(OTHER1, None).is_empty(),
        "source(w) receives the clean runner-up — nothing blocked for it"
    );

    // Equality-suppressed restage: no delta, residue re-recorded.
    let out = stage_pcb(&mut m, &[p]);
    assert!(out.deltas.is_empty());
    assert_eq!(out.otc_blocked.len(), 1);
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(group.otc_blocked_for_member(MEMBER, None).len(), 1);
}

/// A blocked runner-up is DERIVED from the lane at consumption
/// (both slots share the `(prefix, 0)` residue key, so it is never
/// stored): only `source(w)` — whose adv(m) is the runner-up —
/// sees it, prefix scoping applies, and with BOTH slots blocked
/// each member sees exactly blocked(adv(m)).
#[test]
fn pcb_otc_blocked_runner_up_derived_toward_winner_source() {
    let mut m = staging_manager();
    let p = prefix(1);
    seed(&mut m, cand(p, OTHER1, 300));
    seed(&mut m, with_otc_attr(cand(p, OTHER2, 200)));
    m.group_ribs
        .insert(PCB_GID, per_client_best_customer_group());

    let out = stage_pcb(&mut m, &[p]);

    assert!(out.otc_blocked.is_empty(), "a clean winner records nothing");
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert!(
        group.otc_blocked_for_member(MEMBER, None).is_empty(),
        "non-source members receive the clean winner"
    );
    assert_eq!(
        group
            .otc_blocked_for_member(OTHER1, None)
            .iter()
            .map(|r| r.peer)
            .collect::<Vec<_>>(),
        vec![OTHER2],
        "source(w)'s derived view is the blocked runner-up"
    );
    assert!(
        group
            .otc_blocked_for_member(OTHER1, Some(&HashSet::from([prefix(2)])))
            .is_empty(),
        "prefix scoping applies to the lane term"
    );

    // Both slots blocked: winner rides the residue map, runner-up
    // the lane — per member exactly blocked(adv(m)).
    seed(&mut m, with_otc_attr(cand(p, OTHER1, 300)));
    let out = stage_pcb(&mut m, &[p]);
    assert_eq!(out.otc_blocked.len(), 1);
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(
        group
            .otc_blocked_for_member(MEMBER, None)
            .iter()
            .map(|r| r.peer)
            .collect::<Vec<_>>(),
        vec![OTHER1]
    );
    assert_eq!(
        group
            .otc_blocked_for_member(OTHER1, None)
            .iter()
            .map(|r| r.peer)
            .collect::<Vec<_>>(),
        vec![OTHER2]
    );
}

/// The scoped lane query returns exactly the unscoped result
/// restricted to the scope, whichever side it iterates (staged
/// scope smaller or larger than the lane), for every member shape
/// — including a prefix whose winner AND runner-up are both
/// blocked (residue arm + lane arm overlap). Every scoped call
/// also runs the `assert_scoped_visit_bound` tripwire: restoring
/// the per-member full lane scan makes the one-prefix scopes here
/// visit the whole lane and panics the bound.
#[test]
fn pcb_otc_blocked_scoped_query_matches_unscoped_across_scope_shapes() {
    let mut m = staging_manager();
    let staged: Vec<Prefix> = (1..=3).map(prefix).collect();
    for &p in &staged {
        seed(&mut m, cand(p, OTHER1, 300));
        seed(&mut m, with_otc_attr(cand(p, OTHER2, 200)));
    }
    m.group_ribs
        .insert(PCB_GID, per_client_best_customer_group());
    stage_pcb(&mut m, &staged);
    // Overlap cell: prefix 2's winner turns blocked too, so its
    // residue entry (toward everyone but the source) coexists with
    // its blocked lane entry (toward the winner source).
    seed(&mut m, with_otc_attr(cand(prefix(2), OTHER1, 300)));
    stage_pcb(&mut m, &[prefix(2)]);
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(group.runner_up.len(), 3);

    let view = |routes: Vec<Route>| {
        let mut view: Vec<(Prefix, IpAddr)> = routes
            .iter()
            .map(|route| (route.prefix, route.peer))
            .collect();
        view.sort_unstable();
        view
    };
    for member in [MEMBER, OTHER1, OTHER2] {
        let unscoped = view(group.otc_blocked_for_member(member, None));
        // Probe branch: scopes smaller than the lane, hitting and
        // missing entries.
        for scope in [
            HashSet::from([prefix(1)]),
            HashSet::from([prefix(2)]),
            HashSet::from([prefix(9)]),
            HashSet::from([prefix(2), prefix(9)]),
        ] {
            let expected: Vec<(Prefix, IpAddr)> = unscoped
                .iter()
                .copied()
                .filter(|(p, _)| scope.contains(p))
                .collect();
            assert_eq!(
                view(group.otc_blocked_for_member(member, Some(&scope))),
                expected,
                "member {member} scope {scope:?}"
            );
        }
        // Scan branch: a scope wider than the lane covers it all.
        let wide: HashSet<Prefix> = (1..=4).map(prefix).collect();
        assert_eq!(
            view(group.otc_blocked_for_member(member, Some(&wide))),
            unscoped,
            "member {member} wide scope"
        );
    }
}

/// The scoped denial query returns the member-restamped denial set
/// restricted to the scope, on both iteration sides, with the
/// member's own-sourced denials excluded — asserted against an
/// expectation built from the staging inputs, not the residue.
#[test]
fn pcb_policy_filtered_scoped_query_matches_full_residue() {
    let mut m = staging_manager();
    let staged: Vec<Prefix> = (1..=3).map(prefix).collect();
    for &p in &staged {
        seed(&mut m, cand(p, OTHER1, 300));
        seed(&mut m, cand(p, OTHER2, 200));
    }
    m.group_ribs.insert(
        PCB_GID,
        per_client_best_group(Some(deny_sources_chain(&[OTHER1]))),
    );
    stage_pcb(&mut m, &staged);
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(group.policy_filtered.len(), 3);

    let sorted = |mut keys: Vec<PolicyFilteredRouteKey>| {
        keys.sort_unstable_by_key(|key| (key.prefix, key.source_peer, key.path_id));
        keys
    };
    let wide: HashSet<Prefix> = (1..=4).map(prefix).collect();
    let scopes = [
        HashSet::from([prefix(1)]),
        HashSet::from([prefix(9)]),
        HashSet::from([prefix(1), prefix(9)]),
        wide,
    ];
    // Every staged prefix denied OTHER1's candidate at path 0 —
    // visible to every member except OTHER1 itself.
    for member in [MEMBER, OTHER2] {
        for scope in &scopes {
            let expected: Vec<PolicyFilteredRouteKey> = staged
                .iter()
                .filter(|p| scope.contains(p))
                .map(|&p| PolicyFilteredRouteKey {
                    target_peer: member,
                    source_peer: OTHER1,
                    prefix: p,
                    path_id: 0,
                })
                .collect();
            assert_eq!(
                sorted(group.policy_filtered_for_member(member, scope)),
                sorted(expected),
                "member {member} scope {scope:?}"
            );
        }
    }
    for scope in &scopes {
        assert!(
            group.policy_filtered_for_member(OTHER1, scope).is_empty(),
            "own-sourced denials are excluded, scope {scope:?}"
        );
    }
}

/// Backstop parity through the REAL commit path: a delivered clean
/// winner replaced by an OTC-carrying one is stripped at the
/// pre-commit backstop and converted to exactly the withdraw the
/// ungrouped per-client-best path emits for identical inputs —
/// while the group table keeps the blocked winner — and the
/// refresh/join replays of the steady blocked state are silent on
/// both sides.
#[test]
fn pcb_otc_transition_emission_matches_ungrouped_per_client_best() {
    let p = prefix(1);
    let run = |grouped: bool| -> Vec<DrainedWire> {
        let mut m = staging_manager();
        let mut rx = if grouped {
            register_pcb_member(&mut m, MEMBER, per_client_best_customer_group())
        } else {
            register_ungrouped_pcb_peer(&mut m, MEMBER)
        };
        m.peer_local_roles.insert(MEMBER, Some(BgpRole::Customer));
        let mut passes = Vec::new();
        receive_routes(&mut m, OTHER1, vec![cand(p, OTHER1, 300)]);
        passes.push(drain_wire(&mut rx));
        receive_routes(&mut m, OTHER1, vec![with_otc_attr(cand(p, OTHER1, 300))]);
        passes.push(drain_wire(&mut rx));
        m.send_route_refresh_response(MEMBER, Afi::Ipv4, Safi::Unicast);
        passes.push(drain_wire(&mut rx));
        m.send_initial_table(MEMBER);
        passes.push(drain_wire(&mut rx));
        if grouped {
            let group = m.group_ribs.get(&PCB_GID).unwrap();
            assert_eq!(
                group.table.get(&p, 0).map(|r| r.peer),
                Some(OTHER1),
                "the blocked winner stays staged behind the stripped emissions"
            );
        }
        passes
    };
    let grouped = run(true);
    let ungrouped = run(false);
    assert_eq!(grouped, ungrouped, "grouped-vs-ungrouped wire divergence");
    assert_eq!(grouped[0].announced, vec![(p, OTHER1)]);
    assert!(grouped[0].withdrawn.is_empty() && grouped[0].otc_blocked.is_empty());
    assert_eq!(
        grouped[1],
        DrainedWire {
            announced: vec![],
            withdrawn: vec![(p, 0)],
            otc_blocked: vec![(p, OTHER1)],
        },
        "the blocked replacement converts to a withdraw plus its diagnostic"
    );
    assert_eq!(
        grouped[2],
        DrainedWire::default(),
        "a steady blocked identity replays silently on refresh"
    );
    assert_eq!(
        grouped[3],
        DrainedWire::default(),
        "a same-session join replay of the steady blocked state stays silent"
    );
}

/// The one deliberate deviation from the ungrouped path, pinned: a
/// NEWLY blocked identity that was never delivered. The ungrouped
/// path's Adj-RIB-Out gate keeps it silent; a group member's prior
/// wire view is group-derived, so the backstop emits one defensive
/// withdraw (an RFC 4271 no-op — over-withdraw is the safe
/// direction) alongside the diagnostic. Steady-state replays are
/// silent on both sides afterwards.
#[test]
fn pcb_otc_fresh_blocked_prefix_emits_one_defensive_withdraw() {
    let p = prefix(1);
    let run = |grouped: bool| -> (DrainedWire, DrainedWire) {
        let mut m = staging_manager();
        let mut rx = if grouped {
            register_pcb_member(&mut m, MEMBER, per_client_best_customer_group())
        } else {
            register_ungrouped_pcb_peer(&mut m, MEMBER)
        };
        m.peer_local_roles.insert(MEMBER, Some(BgpRole::Customer));
        receive_routes(&mut m, OTHER1, vec![with_otc_attr(cand(p, OTHER1, 300))]);
        let pass = drain_wire(&mut rx);
        m.send_route_refresh_response(MEMBER, Afi::Ipv4, Safi::Unicast);
        (pass, drain_wire(&mut rx))
    };
    let (grouped_pass, grouped_refresh) = run(true);
    let (ungrouped_pass, ungrouped_refresh) = run(false);
    assert_eq!(
        grouped_pass,
        DrainedWire {
            announced: vec![],
            withdrawn: vec![(p, 0)],
            otc_blocked: vec![(p, OTHER1)],
        },
        "grouped: one defensive withdraw beside the diagnostic"
    );
    assert_eq!(
        ungrouped_pass,
        DrainedWire {
            announced: vec![],
            withdrawn: vec![],
            otc_blocked: vec![(p, OTHER1)],
        },
        "ungrouped: the Adj-RIB-Out gate keeps the fresh case silent"
    );
    assert_eq!(grouped_refresh, DrainedWire::default());
    assert_eq!(ungrouped_refresh, DrainedWire::default());
}

/// Lane variant through the real path: a blocked runner-up
/// substituting toward `source(w)` is stripped/suppressed exactly
/// like the ungrouped outcome (which stages the same route as the
/// member's first non-own permitted candidate) — modulo the pinned
/// defensive withdraw on the fresh edge — and its diagnostic is
/// the LANE route.
#[test]
fn pcb_otc_blocked_lane_substitution_matches_ungrouped_toward_winner_source() {
    let p = prefix(1);
    let run = |grouped: bool| -> (DrainedWire, DrainedWire) {
        let mut m = staging_manager();
        let mut rx = if grouped {
            register_pcb_member(&mut m, MEMBER, per_client_best_customer_group())
        } else {
            register_ungrouped_pcb_peer(&mut m, MEMBER)
        };
        m.peer_local_roles.insert(MEMBER, Some(BgpRole::Customer));
        // The member sources the winner; its derived view is the
        // runner-up. The winner pass's emission toward the member
        // is not under test — drained and discarded.
        receive_routes(&mut m, MEMBER, vec![cand(p, MEMBER, 300)]);
        let _ = drain_wire(&mut rx);
        receive_routes(&mut m, OTHER2, vec![with_otc_attr(cand(p, OTHER2, 200))]);
        let pass = drain_wire(&mut rx);
        m.send_route_refresh_response(MEMBER, Afi::Ipv4, Safi::Unicast);
        (pass, drain_wire(&mut rx))
    };
    let (grouped_pass, grouped_refresh) = run(true);
    let (ungrouped_pass, ungrouped_refresh) = run(false);
    assert!(grouped_pass.announced.is_empty() && ungrouped_pass.announced.is_empty());
    assert_eq!(
        grouped_pass.otc_blocked,
        vec![(p, OTHER2)],
        "the diagnostic is the LANE route toward source(w)"
    );
    assert_eq!(ungrouped_pass.otc_blocked, vec![(p, OTHER2)]);
    assert_eq!(
        grouped_pass.withdrawn,
        vec![(p, 0)],
        "fresh blocked edge: the pinned defensive withdraw"
    );
    assert!(ungrouped_pass.withdrawn.is_empty());
    assert_eq!(grouped_refresh, DrainedWire::default());
    assert_eq!(ungrouped_refresh, DrainedWire::default());
}

/// The Decision 4 count synthesis reports the backstop's outcome:
/// `advertised_count_for` and `family_counts_for` agree with a
/// brute-force fold over `adv_entry_post_backstop` for every
/// member — across a blocked winner with a clean lane, a clean
/// winner with a blocked lane, a laneless blocked winner, and a
/// clean control — and stay in agreement as blocked slots flip
/// clean (the residue rebuild and the lane decrement seams).
#[test]
fn pcb_otc_counts_agree_with_post_backstop_fold() {
    let mut m = staging_manager();
    let (p1, p2, p3, p4) = (prefix(1), prefix(2), prefix(3), prefix(4));
    // p1: blocked winner OTHER1, clean runner-up OTHER2.
    seed(&mut m, with_otc_attr(cand(p1, OTHER1, 300)));
    seed(&mut m, cand(p1, OTHER2, 200));
    // p2: clean winner MEMBER, blocked runner-up OTHER2.
    seed(&mut m, cand(p2, MEMBER, 300));
    seed(&mut m, with_otc_attr(cand(p2, OTHER2, 200)));
    // p3: clean winner OTHER1 (control).
    seed(&mut m, cand(p3, OTHER1, 300));
    // p4: blocked winner OTHER1, empty lane.
    seed(&mut m, with_otc_attr(cand(p4, OTHER1, 300)));
    m.group_ribs
        .insert(PCB_GID, per_client_best_customer_group());
    let _ = stage_pcb(&mut m, &[p1, p2, p3, p4]);

    let assert_agreement = |m: &RibManager| {
        let group = m.group_ribs.get(&PCB_GID).unwrap();
        for member in [MEMBER, OTHER1, OTHER2] {
            let folded = group
                .table
                .iter()
                .filter_map(|staged| {
                    group.adv_entry_post_backstop(member, &staged.prefix, staged.path_id)
                })
                .count();
            assert_eq!(
                group.advertised_count_for(member),
                folded,
                "synthesized count diverged from the post-backstop fold for {member}"
            );
            let family_total: u64 = group
                .family_counts_for(member)
                .iter()
                .map(|(_, count)| *count)
                .sum();
            assert_eq!(
                family_total,
                u64::try_from(folded).unwrap(),
                "family counts diverged from the post-backstop fold for {member}"
            );
        }
    };
    assert_agreement(&m);
    // Hand-computed over the four staged slots. MEMBER: p1 and p4
    // blocked winners suppressed, p2 own-sourced with a blocked
    // lane suppressed — only p3. OTHER1: its own p1 slot
    // substitutes the CLEAN lane entry, p2's clean winner counts,
    // p3/p4 own-sourced with no lane. OTHER2: p1/p4 suppressed,
    // p2 and p3 clean winners count.
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(group.advertised_count_for(MEMBER), 1);
    assert_eq!(group.advertised_count_for(OTHER1), 2);
    assert_eq!(group.advertised_count_for(OTHER2), 2);
    assert_eq!(
        group.family_counts_for(MEMBER),
        vec![((Afi::Ipv4, Safi::Unicast), 1)]
    );

    // p2's runner-up flips clean: the blocked-lane row retires and
    // MEMBER's substituted slot counts again.
    seed(&mut m, cand(p2, OTHER2, 210));
    let _ = stage_pcb(&mut m, &[p2]);
    assert_agreement(&m);
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(group.advertised_count_for(MEMBER), 2);

    // p1's winner flips clean: the residue rebuild drops its row;
    // only p4's laneless blocked winner stays suppressed.
    seed(&mut m, cand(p1, OTHER1, 300));
    let _ = stage_pcb(&mut m, &[p1]);
    assert_agreement(&m);
    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert_eq!(group.advertised_count_for(MEMBER), 3);
    assert_eq!(group.advertised_count_for(OTHER2), 3);
}

/// The advertised iterators yield adv(m) minus the backstop's
/// strip: a blocked winner disappears toward non-source members, a
/// blocked lane substitution disappears toward `source(w)`, while
/// clean winners and a clean substitution flow unchanged. The
/// ordered variant and the materialized wrapper agree.
#[test]
fn pcb_advertised_iterators_skip_backstop_stripped_slots() {
    let mut m = staging_manager();
    let (p1, p2, p3, p4) = (prefix(1), prefix(2), prefix(3), prefix(4));
    seed(&mut m, with_otc_attr(cand(p1, OTHER1, 300)));
    seed(&mut m, cand(p1, OTHER2, 200));
    seed(&mut m, cand(p2, MEMBER, 300));
    seed(&mut m, with_otc_attr(cand(p2, OTHER2, 200)));
    seed(&mut m, cand(p3, OTHER1, 300));
    seed(&mut m, with_otc_attr(cand(p4, OTHER1, 300)));
    m.group_ribs
        .insert(PCB_GID, per_client_best_customer_group());
    let _ = stage_pcb(&mut m, &[p1, p2, p3, p4]);
    for peer in [MEMBER, OTHER1, OTHER2] {
        m.update_groups
            .members
            .insert(peer, GroupMembership::Grouped(PCB_GID));
    }

    let rows = |peer: IpAddr| -> Vec<(Prefix, IpAddr)> {
        let mut rows: Vec<(Prefix, IpAddr)> = m
            .grouped_advertised_routes_iter(peer)
            .unwrap()
            .map(|r| (r.prefix, r.peer))
            .collect();
        rows.sort();
        rows
    };
    assert_eq!(rows(MEMBER), vec![(p3, OTHER1)]);
    assert_eq!(
        rows(OTHER1),
        vec![(p1, OTHER2), (p2, MEMBER)],
        "source(w)'s clean lane substitution stays visible"
    );
    assert_eq!(rows(OTHER2), vec![(p2, MEMBER), (p3, OTHER1)]);

    let ordered: Vec<(Prefix, IpAddr)> = m
        .grouped_advertised_routes_ordered_iter(MEMBER, None)
        .unwrap()
        .map(|r| (r.prefix, r.peer))
        .collect();
    assert_eq!(ordered, vec![(p3, OTHER1)]);
    let materialized = m.grouped_advertised_routes(OTHER1).unwrap();
    assert_eq!(materialized.len(), 2);
}

/// Seam-interplay pin: a slot that is BOTH exact-export-rejected
/// and OTC-blocked subtracts ONCE. The synthesis's OTC term
/// already removed it, so the rejection overlay must skip it — in
/// the count and in the per-family BMP stat 17 synthesis alike —
/// while a rejected CLEAN slot still subtracts.
#[test]
fn pcb_rejected_and_otc_blocked_slot_subtracts_once() {
    let mut m = staging_manager();
    let (p1, p2) = (prefix(1), prefix(2));
    seed(&mut m, with_otc_attr(cand(p1, OTHER1, 300)));
    seed(&mut m, cand(p2, OTHER1, 300));
    m.group_ribs
        .insert(PCB_GID, per_client_best_customer_group());
    let _ = stage_pcb(&mut m, &[p1, p2]);
    m.update_groups
        .members
        .insert(MEMBER, GroupMembership::Grouped(PCB_GID));

    assert_eq!(m.grouped_advertised_count(MEMBER), Some(1));
    assert_eq!(
        m.grouped_family_counts(MEMBER),
        Some(vec![((Afi::Ipv4, Safi::Unicast), 1)])
    );

    // Rejecting the blocked slot changes nothing: the route was
    // never on the member's wire and the OTC term already
    // subtracted it.
    m.peer_unexportable
        .entry(MEMBER)
        .or_default()
        .insert(ExactExportKey::Unicast(p1, 0));
    assert_eq!(
        m.grouped_advertised_count(MEMBER),
        Some(1),
        "a rejected+blocked slot must not subtract twice"
    );
    assert_eq!(
        m.grouped_family_counts(MEMBER),
        Some(vec![((Afi::Ipv4, Safi::Unicast), 1)])
    );

    // A rejected clean slot still subtracts.
    m.peer_unexportable
        .entry(MEMBER)
        .or_default()
        .insert(ExactExportKey::Unicast(p2, 0));
    assert_eq!(m.grouped_advertised_count(MEMBER), Some(0));
    assert_eq!(m.grouped_family_counts(MEMBER), Some(vec![]));
}

/// The subtraction is role-gated: under a non-blocking role (none
/// here; Provider and internal peers take the same RFC 9234
/// predicate) OTC-carrying winners and substitutions flow through
/// every query and count unchanged.
#[test]
fn pcb_otc_subtraction_is_role_gated() {
    let mut m = staging_manager();
    let (p1, p2) = (prefix(1), prefix(2));
    seed(&mut m, with_otc_attr(cand(p1, OTHER1, 300)));
    seed(&mut m, cand(p1, OTHER2, 200));
    seed(&mut m, cand(p2, MEMBER, 300));
    seed(&mut m, with_otc_attr(cand(p2, OTHER2, 200)));
    m.group_ribs.insert(PCB_GID, per_client_best_group(None));
    let _ = stage_pcb(&mut m, &[p1, p2]);
    m.update_groups
        .members
        .insert(MEMBER, GroupMembership::Grouped(PCB_GID));

    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert!(
        group.otc_blocked.is_empty(),
        "a non-blocking role records no residue"
    );
    assert_eq!(group.advertised_count_for(MEMBER), 2);
    assert_eq!(m.grouped_advertised_count(MEMBER), Some(2));
    let mut rows: Vec<(Prefix, IpAddr)> = m
        .grouped_advertised_routes_iter(MEMBER)
        .unwrap()
        .map(|r| (r.prefix, r.peer))
        .collect();
    rows.sort();
    assert_eq!(rows, vec![(p1, OTHER1), (p2, OTHER2)]);
}

/// A plain group in a blocking role never stages a blocked route
/// (its in-walk gate rejects it), so its residue names
/// never-staged routes — the count synthesis and the iterators
/// must subtract exactly nothing and stay identical to the
/// table-derived view.
#[test]
fn plain_group_otc_residue_subtracts_nothing_from_counts() {
    let mut m = staging_manager();
    let (p1, p2) = (prefix(1), prefix(2));
    seed(&mut m, with_otc_attr(cand(p1, OTHER1, 300)));
    seed(&mut m, cand(p2, OTHER1, 300));
    let _ = m.recompute_best(&HashSet::from([p1, p2]));
    let mut group = empty_group();
    group.local_role = Some(BgpRole::Customer);
    m.group_ribs.insert(PCB_GID, group);
    let _ = stage_pcb(&mut m, &[p1, p2]);
    m.update_groups
        .members
        .insert(MEMBER, GroupMembership::Grouped(PCB_GID));

    let group = m.group_ribs.get(&PCB_GID).unwrap();
    assert!(
        group.table.get(&p1, 0).is_none(),
        "the in-walk gate keeps the blocked best out of a plain table"
    );
    assert!(
        !group.otc_blocked.is_empty(),
        "the diagnostic residue is recorded regardless"
    );
    assert_eq!(group.advertised_count_for(MEMBER), 1);
    assert_eq!(m.grouped_advertised_count(MEMBER), Some(1));
    assert_eq!(
        m.grouped_family_counts(MEMBER),
        Some(vec![((Afi::Ipv4, Safi::Unicast), 1)])
    );
    let rows: Vec<Prefix> = m
        .grouped_advertised_routes_iter(MEMBER)
        .unwrap()
        .map(|r| r.prefix)
        .collect();
    assert_eq!(rows, vec![p2]);
}

/// Grouped-vs-ungrouped parity for the operator-facing query
/// surfaces under RFC 9234 — the missing OTC × query × BMP
/// intersection: with a blocked winner, a blocked lane
/// substitution toward `source(w)`, and a clean control prefix,
/// the grouped member's advertised-routes query, advertised
/// count, and per-family stat 17 synthesis all equal the
/// ungrouped per-client-best path's post-backstop Adj-RIB-Out.
/// The announced wire agrees too (withdraw parity modulo the
/// pinned fresh-blocked defensive withdraw is covered by the
/// dedicated backstop tests above).
#[test]
fn pcb_otc_query_surfaces_match_ungrouped_post_backstop() {
    let (p1, p2, p3) = (prefix(1), prefix(2), prefix(3));
    let feed = |m: &mut RibManager| {
        // p1: blocked winner OTHER1 over a clean OTHER2 runner-up.
        receive_routes(m, OTHER1, vec![with_otc_attr(cand(p1, OTHER1, 300))]);
        receive_routes(m, OTHER2, vec![cand(p1, OTHER2, 200)]);
        // p2: MEMBER sources the winner; its derived view is the
        // BLOCKED runner-up.
        receive_routes(m, MEMBER, vec![cand(p2, MEMBER, 300)]);
        receive_routes(m, OTHER2, vec![with_otc_attr(cand(p2, OTHER2, 200))]);
        // p3: clean control.
        receive_routes(m, OTHER1, vec![cand(p3, OTHER1, 300)]);
    };

    let mut grouped = staging_manager();
    let mut grouped_rx =
        register_pcb_member(&mut grouped, MEMBER, per_client_best_customer_group());
    grouped
        .peer_local_roles
        .insert(MEMBER, Some(BgpRole::Customer));
    feed(&mut grouped);
    let mut grouped_wire = drain_wire(&mut grouped_rx);

    let mut ungrouped = staging_manager();
    let mut ungrouped_rx = register_ungrouped_pcb_peer(&mut ungrouped, MEMBER);
    ungrouped
        .peer_local_roles
        .insert(MEMBER, Some(BgpRole::Customer));
    feed(&mut ungrouped);
    let mut ungrouped_wire = drain_wire(&mut ungrouped_rx);

    // The ungrouped Adj-RIB-Out is the oracle: post-backstop,
    // blocked routes were never committed.
    let oracle_rib = ungrouped.adj_ribs_out.get(&MEMBER).unwrap();
    let mut oracle: Vec<(Prefix, IpAddr)> = oracle_rib.iter().map(|r| (r.prefix, r.peer)).collect();
    oracle.sort();
    assert_eq!(oracle, vec![(p3, OTHER1)]);

    let mut rows: Vec<(Prefix, IpAddr)> = grouped
        .grouped_advertised_routes(MEMBER)
        .unwrap()
        .iter()
        .map(|r| (r.prefix, r.peer))
        .collect();
    rows.sort();
    assert_eq!(rows, oracle, "advertised-routes query divergence");
    assert_eq!(
        grouped.grouped_advertised_count(MEMBER),
        Some(oracle_rib.len()),
        "advertised-count divergence"
    );
    assert_eq!(
        grouped.grouped_family_counts(MEMBER),
        Some(oracle_rib.family_counts()),
        "BMP stat 17 family-count divergence"
    );

    grouped_wire.announced.sort();
    ungrouped_wire.announced.sort();
    assert_eq!(
        grouped_wire.announced, ungrouped_wire.announced,
        "announced wire divergence"
    );
}

/// A SINGLE-BEST group reaching the backstop with an OTC-blocked
/// announce is still a bug — its in-walk gate must reject before
/// the shared table commit; only per-client-best groups defer to
/// the backstop.
#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "single-best group staging must reject OTC")]
fn single_best_group_otc_at_backstop_trips_debug_assert() {
    let mut m = staging_manager();
    let (outbound_tx, _outbound_rx) = tokio::sync::mpsc::channel(8);
    m.outbound_peers.insert(MEMBER, outbound_tx);
    m.peer_export_encoders
        .insert(MEMBER, super::super::permissive_test_exact_export_encoder());
    m.peer_local_roles.insert(MEMBER, Some(BgpRole::Customer));
    m.update_groups
        .members
        .insert(MEMBER, GroupMembership::Grouped(PCB_GID));
    m.group_ribs.insert(PCB_GID, empty_group());
    let announce: Arc<[Route]> = vec![with_otc_attr(route(prefix(1), OTHER1))].into();
    let nh: Arc<[Option<NextHopAction>]> = vec![None].into();
    let _ = m.try_send_and_commit_outbound_update(
        MEMBER,
        nh,
        announce,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
}

/// The per-client-best counterpart of the assert test: the same
/// backstop entry does NOT panic — the blocked announce strips,
/// the pending-gated conversion emits its withdraw, and the
/// diagnostic delivers (clearing the pending edge).
#[test]
fn per_client_best_group_otc_at_backstop_strips_with_pending_gated_withdraw() {
    let mut m = staging_manager();
    let (outbound_tx, mut outbound_rx) = tokio::sync::mpsc::channel(8);
    m.outbound_peers.insert(MEMBER, outbound_tx);
    m.peer_export_encoders
        .insert(MEMBER, super::super::permissive_test_exact_export_encoder());
    m.peer_local_roles.insert(MEMBER, Some(BgpRole::Customer));
    m.update_groups
        .members
        .insert(MEMBER, GroupMembership::Grouped(PCB_GID));
    m.group_ribs
        .insert(PCB_GID, per_client_best_customer_group());
    let blocked = with_otc_attr(route(prefix(1), OTHER1));
    m.pending_otc_blocked
        .entry(MEMBER)
        .or_default()
        .insert((prefix(1), 0), blocked.clone());
    let announce: Arc<[Route]> = vec![blocked].into();
    let nh: Arc<[Option<NextHopAction>]> = vec![None].into();
    assert!(m.try_send_and_commit_outbound_update(
        MEMBER,
        nh,
        announce,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    ));
    let update = outbound_rx.try_recv().unwrap();
    assert!(
        update.announce.is_empty(),
        "the blocked announce is stripped"
    );
    assert_eq!(
        update.withdraw,
        vec![(prefix(1), 0)],
        "a pending (newly blocked) identity converts to a withdraw"
    );
    assert_eq!(update.otc_blocked.len(), 1);
    assert!(
        !m.pending_otc_blocked.contains_key(&MEMBER),
        "the delivered diagnostic retires the pending edge"
    );
}

/// ADR-0105 exclusion (ADR-0126 Decision 8): a per-client-best
/// group on EITHER side rejects the clean-transition inventory
/// even when every other clean term holds; plain groups with the
/// same tables stay eligible.
#[test]
fn per_client_best_groups_are_excluded_from_clean_transition_inventory() {
    let mut m = staging_manager();
    let build = |per_client_best: bool| {
        let mut group = if per_client_best {
            per_client_best_group(None)
        } else {
            empty_group()
        };
        group.apply_delta(&announce_delta(prefix(1), OTHER1, None));
        group
    };
    m.group_ribs.insert(1, build(false));
    m.group_ribs.insert(2, build(false));
    m.group_ribs.insert(3, build(true));
    m.group_ribs.insert(4, build(true));
    assert!(
        m.begin_clean_policy_transition_inventory(1, 2).is_some(),
        "plain groups stay eligible"
    );
    for (source, destination) in [(3, 4), (3, 2), (1, 4)] {
        assert!(
            m.begin_clean_policy_transition_inventory(source, destination)
                .is_none(),
            "a per-client-best side must reject the fast path ({source} -> {destination})"
        );
    }
}

/// [`route`] plus one standard community — the smallest wire-form
/// difference between a source and a destination staged entry, and,
/// with a control-space value, an RFC 7947 tag for [`RS_ASN`].
fn route_with_comm(p: Prefix, src: IpAddr, comm: u32) -> Route {
    let mut route = route(p, src);
    let mut attrs = (*route.attributes).clone();
    attrs.push(PathAttribute::Communities(vec![comm]));
    route.attributes = Arc::new(attrs);
    route
}

/// [`announce_delta`] for a caller-built route (which carries its own
/// prefix and source), so the source attrs match the staged entry.
fn announce_route_delta(new: Route) -> GroupDelta {
    let source_attrs = capture_source_attrs(&new);
    GroupDelta {
        prefix: new.prefix,
        path_id: 0,
        new: Some((new, None)),
        old_source: None,
        policy_label: None,
        source_attrs,
        lane: None,
    }
}

/// A group whose table holds exactly the given staged entries.
fn group_with(deltas: &[GroupDelta]) -> GroupRibOut {
    let mut group = empty_group();
    for delta in deltas {
        group.apply_delta(delta);
    }
    group
}

const CLEAN_SOURCE: usize = 1;
const CLEAN_DESTINATION: usize = 2;

/// Run one inventory chunk over `keys` against the manager's current
/// group tables.
fn extend_inventory(m: &RibManager, keys: &[(Prefix, u32)], rs_asns: &[u32]) -> Option<()> {
    let mut inventory = CleanPolicyTransitionInventoryBuilder::default();
    m.extend_clean_policy_transition_inventory(
        CLEAN_SOURCE,
        CLEAN_DESTINATION,
        keys,
        rs_asns,
        &mut inventory,
    )
}

fn inventory_manager(source: GroupRibOut, destination: GroupRibOut) -> RibManager {
    let mut m = staging_manager();
    m.group_ribs.insert(CLEAN_SOURCE, source);
    m.group_ribs.insert(CLEAN_DESTINATION, destination);
    m
}

/// Degradation paths of the clean-transition inventory walk, each of
/// which hands the whole cohort back to the authoritative per-peer
/// machinery: a source flip under the snapshot, and an RFC 7947
/// control-form community in the delta. Both are asserted against the
/// accepting shape so the `None` is attributable to the tested term
/// and not to the wire-form change that carries it.
#[test]
fn clean_transition_inventory_degrades_on_source_flip_and_control_tag() {
    // Control-space for RS_ASN: administrator 0 (`0:TARGET_ASN`, the
    // "do not announce to TARGET_ASN" form).
    const TAGGED_COMM: u32 = TARGET_ASN;
    // Administrator is neither 0 nor RS_ASN nor the RFC 1997
    // well-known space: a pure wire-form change, no per-target
    // divergence.
    const PLAIN_COMM: u32 = (64513 << 16) | 7;
    let keys = [(prefix(1), 0)];
    let staged = |src, comm: Option<u32>| match comm {
        Some(comm) => group_with(&[announce_route_delta(route_with_comm(prefix(1), src, comm))]),
        None => group_with(&[announce_delta(prefix(1), src, None)]),
    };

    let m = inventory_manager(staged(OTHER1, None), staged(OTHER2, None));
    assert!(
        extend_inventory(&m, &keys, &[]).is_none(),
        "a source flip under the snapshot degrades the cohort"
    );

    let m = inventory_manager(staged(OTHER1, None), staged(OTHER1, Some(PLAIN_COMM)));
    assert!(
        extend_inventory(&m, &keys, &[RS_ASN]).is_some(),
        "the same-source wire-form change alone stays on the shared path"
    );

    let m = inventory_manager(staged(OTHER1, None), staged(OTHER1, Some(TAGGED_COMM)));
    assert!(
        extend_inventory(&m, &keys, &[RS_ASN]).is_none(),
        "a control-form community in the delta degrades the cohort"
    );
    assert!(
        extend_inventory(&m, &keys, &[]).is_some(),
        "with no rs-control ASN in the cohort the same delta stays shared"
    );
}

/// Table drift on either side between the snapshot and the walk:
/// a key the snapshot recorded is gone, so the inventory can no
/// longer describe the old-to-new wire delta and degrades.
#[test]
fn clean_transition_inventory_degrades_on_table_drift() {
    let keys = [(prefix(1), 0)];
    let staged = || group_with(&[announce_delta(prefix(1), OTHER1, None)]);

    let m = inventory_manager(staged(), group_with(&[]));
    assert!(
        extend_inventory(&m, &keys, &[]).is_none(),
        "the destination no longer stages the snapshot key"
    );

    let m = inventory_manager(group_with(&[]), staged());
    assert!(
        extend_inventory(&m, &keys, &[]).is_none(),
        "the source no longer stages the snapshot key"
    );

    let m = inventory_manager(staged(), staged());
    assert!(
        extend_inventory(&m, &keys, &[]).is_some(),
        "an undrifted pair completes the chunk"
    );
}
