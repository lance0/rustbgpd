//! Cancellation work under spent credit, and the typed overlay identities
//! that must survive the per-mark-pass lookup index.

use super::exportability::MockExactExportEncoder;
use super::lifecycle::{test_peer_up, test_routes_received};
use super::work_scaling::{Work, assert_linear, checkpoints_in};
use super::*;
use crate::manager::outbound_owing::{OwedFamily, OwedKey};
use crate::route::{LabeledRibRouteKey, VpnRibRouteKey};
use crate::update::ExactExportKey;

const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
const TARGET: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);
const CREDIT: usize = 4;
const OVERLAY_WORK: &str = "owing_cancel_overlay";

fn manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
        .with_outbound_row_credit(CREDIT);
    manager.test_force_ungrouped = true;
    super::distribution_window::untimed_window(&mut manager);
    manager
}

fn register(
    manager: &mut RibManager,
    peer: PeerId,
    encoder: Arc<MockExactExportEncoder>,
) -> mpsc::Receiver<OutboundRouteUpdate> {
    let (outbound_tx, output) = mpsc::channel(4096);
    manager.handle_update(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 0,
        encoder,
    });
    let mut up = test_peer_up(peer, 0, outbound_tx);
    if let RibUpdate::PeerUp {
        peer_asn,
        peer_router_id,
        ..
    } = &mut up
    {
        *peer_asn = if peer == peer_v4(SOURCE) {
            65001
        } else {
            65002
        };
        *peer_router_id = session_router_id(peer.addr());
    }
    manager.handle_update(up);
    output
}

fn route(index: usize) -> Route {
    let mut route = make_indexed_route(u32::try_from(index).unwrap(), SOURCE);
    route.attributes = AttrSet::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001])],
        }),
    ]);
    route
}

fn receive(manager: &mut RibManager, announced: Vec<Route>, withdrawn: Vec<(Prefix, u32)>) {
    let mut update = test_routes_received(peer_v4(SOURCE), announced);
    if let RibUpdate::RoutesReceived {
        withdrawn: removed, ..
    } = &mut update
    {
        *removed = withdrawn;
    }
    manager.handle_update(update);
    drain_route_chunks(manager);
}

fn cancellation_work(size: usize) -> Work {
    let mut manager = manager();
    let source = peer_v4(SOURCE);
    let target = peer_v4(TARGET);
    let mut source_rx = register(&mut manager, source, MockExactExportEncoder::accepting(1));
    while source_rx.try_recv().is_ok() {}

    // A real initial dump probes every route without the ordinary per-pass
    // credit budget. Its rejected source routes remain live throughout churn.
    let rejected_routes: Vec<_> = (0..8 * size).map(route).collect();
    let rejected: HashSet<_> = rejected_routes
        .iter()
        .map(|route| ExactExportKey::Unicast(route.prefix, route.path_id))
        .collect();
    receive(&mut manager, rejected_routes, vec![]);
    let encoder = MockExactExportEncoder::accepting(2);
    encoder.set_profile(2, rejected.iter().cloned());
    let mut output = register(&mut manager, target, encoder);
    let initial: Vec<_> = std::iter::from_fn(|| output.try_recv().ok()).collect();
    assert!(initial.iter().all(|update| {
        update.announce.is_empty() && update.unicast_withdrawals().next().is_none()
    }));
    drop(initial);
    assert_eq!(manager.peer_unexportable[&target], rejected);
    assert_eq!(manager.ribs[&source].len(), 8 * size);
    assert!(manager.grouped_member_of(target).is_none());
    assert!(manager.owing(target).is_none());
    assert!(!manager.dirty_peers.contains(&target));
    assert_eq!(manager.outbound_credit_rows(target), 0);
    assert!(!manager.outbound_operation_live(target));

    receive(
        &mut manager,
        (1_000_000..1_000_000 + CREDIT).map(route).collect(),
        vec![],
    );
    // Dequeue but retain the envelopes, as a session blocked on its writer
    // does: channel capacity is available while all row credit stays spent.
    let held: Vec<_> = std::iter::from_fn(|| output.try_recv().ok()).collect();
    assert_eq!(
        held.iter()
            .map(|update| update.announce.len())
            .sum::<usize>(),
        CREDIT
    );
    assert!(
        held.iter()
            .all(|update| update.unicast_withdrawals().next().is_none())
    );
    assert_eq!(manager.outbound_credit_rows(target), CREDIT);
    assert!(manager.outbound_peers[&target].capacity() > 0);

    let fresh: Vec<_> = (2_000_000..2_000_000 + size).map(route).collect();
    let withdrawn: Vec<_> = fresh
        .iter()
        .map(|route| (route.prefix, route.path_id))
        .collect();
    let announce_work = checkpoints_in(|| receive(&mut manager, fresh, vec![]));
    assert_eq!(
        announce_work.get(OVERLAY_WORK).copied().unwrap_or(0),
        0,
        "live candidates do not need an overlay scan"
    );
    assert_eq!(
        manager.owed_key_count(target, OwedFamily::IPV4_UNICAST),
        size
    );
    assert!(!manager.owes_whole(target, OwedFamily::IPV4_UNICAST));
    assert!(!manager.dirty_peers.contains(&target));
    assert!(output.try_recv().is_err(), "no fresh route was admitted");

    let work = checkpoints_in(|| receive(&mut manager, vec![], withdrawn.clone()));
    assert!(
        manager.owing(target).is_none(),
        "every unadvertised withdrawal cancels"
    );
    assert!(!manager.dirty_peers.contains(&target));
    assert_eq!(
        manager.peer_unexportable[&target], rejected,
        "unrelated live rejections survive cancellation"
    );
    assert_eq!(manager.ribs[&source].len(), 8 * size + CREDIT);
    assert_eq!(manager.adj_ribs_out[&target].len(), CREDIT);
    for (prefix, path_id) in withdrawn {
        assert!(
            manager.adj_ribs_out[&target]
                .get(&prefix, path_id)
                .is_none()
        );
    }
    assert!(
        output.try_recv().is_err(),
        "no unadvertised key is withdrawn in the outbound stream"
    );
    assert_eq!(manager.outbound_credit_rows(target), CREDIT);
    drop(held);
    assert_eq!(manager.outbound_credit_rows(target), 0);
    manager.resync_dirty_peers_bounded();
    assert!(
        output.try_recv().is_err(),
        "cancellation leaves no delayed outbound work"
    );
    work
}

#[test]
fn owed_cancellation_overlay_work_is_linear() {
    // The stage counts examined source entries, including failed matches.
    // Restoring per-key scans must retain that observation for the red proof.
    assert_linear(
        "owed cancellation overlays",
        &[OVERLAY_WORK],
        cancellation_work,
    );
}

#[test]
fn rejection_identity_keeps_only_its_typed_nlri_across_path_ranks() {
    let peer = peer_v4(TARGET);
    let other = peer_v4(Ipv4Addr::new(192, 0, 2, 3));
    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 64));
    let vpn4 = make_vpn_rib_route(SOURCE, 1, 100, 100).nlri.key();
    let mut other_rd = vpn4;
    other_rd.route_distinguisher = "65000:2".parse().unwrap();
    let mut vpn6 = vpn4;
    vpn6.prefix = VpnPrefix::v6("2001:db8::".parse().unwrap(), 64).unwrap();
    let cases = [
        (ExactExportKey::Unicast(v4, 17), OwedKey::Unicast(v4)),
        (ExactExportKey::Unicast(v6, 17), OwedKey::Unicast(v6)),
        (
            ExactExportKey::Labeled(LabeledRibRouteKey {
                prefix: v4,
                path_id: 17,
            }),
            OwedKey::Labeled(v4),
        ),
        (
            ExactExportKey::Labeled(LabeledRibRouteKey {
                prefix: v6,
                path_id: 17,
            }),
            OwedKey::Labeled(v6),
        ),
        (
            ExactExportKey::Vpn(VpnRibRouteKey {
                nlri_key: vpn4,
                path_id: 17,
            }),
            OwedKey::Vpn(vpn4),
        ),
        (
            ExactExportKey::Vpn(VpnRibRouteKey {
                nlri_key: other_rd,
                path_id: 17,
            }),
            OwedKey::Vpn(other_rd),
        ),
        (
            ExactExportKey::Vpn(VpnRibRouteKey {
                nlri_key: vpn6,
                path_id: 17,
            }),
            OwedKey::Vpn(vpn6),
        ),
    ];
    for (rejection, kept) in &cases {
        let mut manager = manager();
        manager.peer_unexportable.insert(
            peer,
            HashSet::from([
                rejection.clone(),
                rejection.nlri_identity(),
                ExactExportKey::Evpn(make_evpn_imet(SOURCE, 1).key()),
                ExactExportKey::BgpLs(make_bgpls_route(SOURCE, 1, 100).key()),
            ]),
        );
        let (mut rejections, mut pending_otc) = (None, None);
        for (_, candidate) in &cases {
            assert_eq!(
                manager.owed_key_kept(peer, candidate, &mut rejections, &mut pending_otc),
                candidate == kept,
                "rejected {rejection:?}, checked {candidate:?}"
            );
        }
        assert_eq!(
            rejections.as_ref().unwrap().len(),
            1,
            "two outbound ranks refer to one owed NLRI"
        );
        assert!(
            !manager.owed_key_kept(other, kept, &mut None, &mut None),
            "another receiver's rejection does not keep this key"
        );
    }
}

#[test]
fn pending_otc_identity_is_a_unicast_prefix_in_one_peer() {
    // Predicate coverage: this deliberately isolates pending diagnostics
    // without claiming a complete lifecycle for a pending-only overlay.
    let mut manager = manager();
    let peer = peer_v4(TARGET);
    let other = peer_v4(Ipv4Addr::new(192, 0, 2, 3));
    let mut blocked = route(50);
    blocked.path_id = 17;
    let mut sibling = blocked.clone();
    sibling.path_id = 29;
    let prefix = blocked.prefix;
    manager.pending_otc_blocked.insert(
        peer,
        HashMap::from([((prefix, 17), blocked), ((prefix, 29), sibling)]),
    );
    let (mut rejections, mut pending_otc) = (None, None);
    assert!(manager.owed_key_kept(
        peer,
        &OwedKey::Unicast(prefix),
        &mut rejections,
        &mut pending_otc
    ));
    assert_eq!(pending_otc.as_ref().unwrap().len(), 1);
    assert!(!manager.owed_key_kept(
        peer,
        &OwedKey::Unicast(route(51).prefix),
        &mut rejections,
        &mut pending_otc
    ));
    assert!(!manager.owed_key_kept(
        peer,
        &OwedKey::Labeled(prefix),
        &mut rejections,
        &mut pending_otc
    ));
    assert!(!manager.owed_key_kept(other, &OwedKey::Unicast(prefix), &mut None, &mut None));
    manager.pending_otc_blocked.remove(&peer);
    assert!(
        !manager.owed_key_kept(peer, &OwedKey::Unicast(prefix), &mut None, &mut None),
        "the next marking pass does not reuse an old index"
    );
}

#[test]
fn evpn_rejection_keeps_direct_identity_lookup() {
    let mut manager = manager();
    let peer = peer_v4(TARGET);
    let key = make_evpn_imet(SOURCE, 1).key();
    manager
        .peer_unexportable
        .insert(peer, HashSet::from([ExactExportKey::Evpn(key)]));
    let (mut rejections, mut pending_otc) = (None, None);
    let work = checkpoints_in(|| {
        assert!(manager.owed_key_kept(
            peer,
            &OwedKey::Evpn(key),
            &mut rejections,
            &mut pending_otc
        ));
        assert!(!manager.owed_key_kept(
            peer,
            &OwedKey::Evpn(make_evpn_imet(SOURCE, 2).key()),
            &mut rejections,
            &mut pending_otc
        ));
    });
    assert!(rejections.is_none() && pending_otc.is_none());
    assert_eq!(work.get(OVERLAY_WORK).copied().unwrap_or(0), 0);
}

#[test]
fn candidates_admitted_rows_and_recovery_residue_skip_overlay_indexes() {
    let mut manager = manager();
    let peer = peer_v4(TARGET);
    manager.peer_unexportable.insert(
        peer,
        HashSet::from([ExactExportKey::Unicast(route(90).prefix, 1)]),
    );
    let mut blocked = route(91);
    blocked.path_id = 1;
    manager
        .pending_otc_blocked
        .insert(peer, HashMap::from([((blocked.prefix, 1), blocked)]));
    let check = |manager: &RibManager, prefix| {
        let (mut rejections, mut pending_otc) = (None, None);
        let work = checkpoints_in(|| {
            assert!(manager.owed_key_kept(
                peer,
                &OwedKey::Unicast(prefix),
                &mut rejections,
                &mut pending_otc
            ));
        });
        assert!(rejections.is_none() && pending_otc.is_none());
        assert_eq!(work.get(OVERLAY_WORK).copied().unwrap_or(0), 0);
    };

    let offered = route(92);
    manager
        .ribs
        .entry(peer_v4(SOURCE))
        .or_insert_with(|| AdjRibIn::new(peer_v4(SOURCE)))
        .insert(offered.clone());
    manager.register_unicast_announcer(peer_v4(SOURCE), offered.prefix);
    check(&manager, offered.prefix);

    let mut admitted = route(93);
    admitted.peer = PeerId::LOCAL;
    admitted.origin_type = crate::route::RouteOrigin::Local;
    admitted.path_id = 17;
    let admitted_prefix = admitted.prefix;
    manager
        .adj_ribs_out
        .entry(peer)
        .or_insert_with(|| AdjRibOut::new(peer))
        .insert(admitted);
    check(&manager, admitted_prefix);

    manager
        .pending_extra_withdraws
        .entry(peer)
        .or_default()
        .unicast
        .insert((route(94).prefix, 3));
    check(&manager, route(95).prefix);
}
