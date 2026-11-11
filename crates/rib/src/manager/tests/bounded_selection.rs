//! VPN and labeled-unicast selection on the receive path reads the paths an
//! UPDATE changed plus the stored best, not every stored path of the key.
//!
//! The differential test drives random receives (announce, replace and
//! withdraw with Add-Path IDs, a withdraw and an announce of one path in one
//! message), GR stale marking, LLGR promotion and session teardown, and
//! after every step compares the Loc-RIB best of every key with the minimum
//! over all stored paths. The work test bounds the candidate reads of one
//! non-best change.

use proptest::prelude::*;

use super::work_scaling::checkpoints_in;
use super::*;
use crate::loc_rib::LocRib;
use crate::route::{LabeledRibRoute, LabeledRibRouteKey, VpnRibRouteKey};
use crate::test_support::peer_v4;

const PEERS: u8 = 3;
const KEYS: u8 = 3;
const PATHS: u32 = 4;
const VPN: (Afi, Safi) = (Afi::Ipv4, Safi::MplsVpn);
const LABELED: (Afi, Safi) = (Afi::Ipv4, Safi::LabeledUnicast);

fn source(peer: u8) -> Ipv4Addr {
    Ipv4Addr::new(192, 0, 2, peer + 1)
}

/// Attribute variants with few distinct ranks, so most pairs tie down to the
/// peer address and path identifier steps.
fn variant_attrs(variant: u8) -> Arc<AttrSet> {
    let mut attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::LocalPref(if variant.is_multiple_of(2) { 100 } else { 200 }),
    ];
    if variant >= 2 {
        attrs.push(PathAttribute::Med(5));
    }
    AttrSet::new(attrs)
}

fn vpn_route(peer: u8, key: u8, path_id: u32, variant: u8) -> VpnRibRoute {
    let mut route = make_vpn_rib_route(source(peer), key, 100 + u32::from(variant), 100);
    route.attributes = variant_attrs(variant);
    // One BGP Identifier everywhere: the peer address step decides ties.
    route.peer_router_id = Ipv4Addr::new(192, 0, 2, 1);
    route.path_id = path_id;
    route
}

fn labeled_route(peer: u8, key: u8, path_id: u32, variant: u8) -> LabeledRibRoute {
    let mut route = make_labeled_rib_route(source(peer), key, 100 + u32::from(variant), 100);
    route.attributes = variant_attrs(variant);
    route.peer_router_id = Ipv4Addr::new(192, 0, 2, 1);
    route.path_id = path_id;
    route
}

fn receive_vpn(
    manager: &mut RibManager,
    peer: u8,
    announced: Vec<VpnRibRoute>,
    withdrawn: Vec<VpnRibRouteKey>,
) {
    let peer = peer_v4(source(peer));
    register_test_peer(manager, peer, 0);
    manager.handle_update(RibUpdate::VpnRoutesReceived {
        peer,
        session_id: 0,
        announced,
        withdrawn,
    });
    drain_route_chunks(manager);
}

fn receive_labeled(
    manager: &mut RibManager,
    peer: u8,
    announced: Vec<LabeledRibRoute>,
    withdrawn: Vec<LabeledRibRouteKey>,
) {
    let peer = peer_v4(source(peer));
    register_test_peer(manager, peer, 0);
    manager.handle_update(RibUpdate::LabeledRoutesReceived {
        peer,
        session_id: 0,
        announced,
        withdrawn,
    });
    drain_route_chunks(manager);
}

#[derive(Debug, Clone)]
enum Op {
    /// One received UPDATE: withdrawals are applied before announcements,
    /// so a path in both lists ends present.
    Receive {
        peer: u8,
        vpn: bool,
        announce: Vec<(u8, u32, u8)>,
        withdraw: Vec<(u8, u32)>,
    },
    /// GR entry seam: mark the family stale in place, then recompute.
    MarkStale { peer: u8, vpn: bool },
    /// LLGR promotion seam: GR-stale to LLGR-stale in place, then recompute.
    PromoteLlgr { peer: u8, vpn: bool },
    /// Production `PeerDown` teardown.
    SessionDown { peer: u8 },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    let announce = proptest::collection::vec((0..KEYS, 0..PATHS, 0u8..4), 0..4);
    let withdraw = proptest::collection::vec((0..KEYS, 0..PATHS), 0..4);
    prop_oneof![
        12 => (0..PEERS, any::<bool>(), announce, withdraw).prop_map(
            |(peer, vpn, announce, withdraw)| Op::Receive { peer, vpn, announce, withdraw }
        ),
        1 => (0..PEERS, any::<bool>()).prop_map(|(peer, vpn)| Op::MarkStale { peer, vpn }),
        1 => (0..PEERS, any::<bool>()).prop_map(|(peer, vpn)| Op::PromoteLlgr { peer, vpn }),
        1 => (0..PEERS).prop_map(|peer| Op::SessionDown { peer }),
    ]
}

fn apply(manager: &mut RibManager, op: &Op) {
    match op {
        Op::Receive {
            peer,
            vpn: true,
            announce,
            withdraw,
        } => receive_vpn(
            manager,
            *peer,
            announce
                .iter()
                .map(|&(key, path_id, variant)| vpn_route(*peer, key, path_id, variant))
                .collect(),
            withdraw
                .iter()
                .map(|&(key, path_id)| vpn_route(*peer, key, path_id, 0).key())
                .collect(),
        ),
        Op::Receive {
            peer,
            vpn: false,
            announce,
            withdraw,
        } => receive_labeled(
            manager,
            *peer,
            announce
                .iter()
                .map(|&(key, path_id, variant)| labeled_route(*peer, key, path_id, variant))
                .collect(),
            withdraw
                .iter()
                .map(|&(key, path_id)| labeled_route(*peer, key, path_id, 0).key())
                .collect(),
        ),
        Op::MarkStale { peer, vpn } => {
            let Some(rib) = manager.ribs.get_mut(&peer_v4(source(*peer))) else {
                return;
            };
            if *vpn {
                let mut affected: HashSet<_> = rib.iter_vpn().map(VpnRibRoute::key).collect();
                affected.extend(rib.mark_stale_vpn(VPN));
                manager.recompute_vpn_keys(&affected);
            } else {
                let mut affected: HashSet<_> =
                    rib.iter_labeled().map(LabeledRibRoute::key).collect();
                affected.extend(rib.mark_stale_labeled(LABELED));
                manager.recompute_labeled_keys(&affected);
            }
        }
        Op::PromoteLlgr { peer, vpn } => {
            let Some(rib) = manager.ribs.get_mut(&peer_v4(source(*peer))) else {
                return;
            };
            let mut intern = crate::attr_intern::AttrInternTable::new();
            if *vpn {
                let affected = rib.promote_to_llgr_stale_vpn(VPN, &mut intern);
                manager.recompute_vpn_keys(&affected.into_iter().collect());
            } else {
                let affected = rib.promote_to_llgr_stale_labeled(LABELED, &mut intern);
                manager.recompute_labeled_keys(&affected.into_iter().collect());
            }
        }
        Op::SessionDown { peer } => manager.handle_update(RibUpdate::PeerDown {
            peer: peer_v4(source(*peer)),
            session_id: 0,
        }),
    }
}

/// The fields the Loc-RIB change check compares.
macro_rules! assert_same_best {
    ($step:expr, $key:expr, $expected:expr, $actual:expr) => {
        match ($expected, $actual) {
            (None, None) => {}
            (Some(expected), Some(actual)) => assert!(
                expected.peer == actual.peer
                    && expected.path_id == actual.path_id
                    && expected.is_stale == actual.is_stale
                    && expected.is_llgr_stale == actual.is_llgr_stale
                    && expected.next_hop == actual.next_hop
                    && expected.peer_router_id == actual.peer_router_id
                    && expected.nlri == actual.nlri
                    && expected.attributes == actual.attributes,
                "step {}: best mismatch for {:?}:\n expected {expected:?}\n actual {actual:?}",
                $step,
                $key,
            ),
            (expected, actual) => panic!(
                "step {}: best presence mismatch for {:?}: expected {expected:?}, actual {actual:?}",
                $step, $key,
            ),
        }
    };
}

/// The Loc-RIB best of every key equals the minimum over every stored path.
fn check_bests(manager: &RibManager, step: usize) {
    let mut reference = LocRib::new();
    for key in 0..KEYS {
        let vpn = vpn_route(0, key, 0, 0).nlri.key();
        reference.recompute_vpn(
            vpn,
            manager
                .ribs
                .values()
                .flat_map(|rib| rib.iter_vpn_for_nlri(&vpn)),
        );
        assert_same_best!(
            step,
            vpn,
            reference.get_vpn(&vpn),
            manager.loc_rib.get_vpn(&vpn)
        );

        let labeled = labeled_route(0, key, 0, 0).nlri.key();
        reference.recompute_labeled(
            labeled,
            manager
                .ribs
                .values()
                .flat_map(|rib| rib.iter_labeled_for_prefix(&labeled)),
        );
        assert_same_best!(
            step,
            labeled,
            reference.get_labeled(&labeled),
            manager.loc_rib.get_labeled(&labeled)
        );
    }
}

fn manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    })]

    #[test]
    fn vpn_and_labeled_receive_selection_matches_full_rescan(
        ops in proptest::collection::vec(op_strategy(), 1..80)
    ) {
        let mut manager = manager();
        for (step, op) in ops.iter().enumerate() {
            apply(&mut manager, op);
            check_bests(&manager, step);
        }
    }
}

/// A better path arrives while another peer holds the best, the best is
/// replaced by a worse path, and the best is withdrawn: the three receives
/// where the stored best must not simply be kept.
#[test]
fn receive_selection_follows_a_challenger_a_worse_best_and_a_withdrawn_best() {
    let mut manager = manager();
    receive_vpn(&mut manager, 0, vec![vpn_route(0, 0, 1, 0)], vec![]);
    receive_labeled(&mut manager, 0, vec![labeled_route(0, 0, 1, 0)], vec![]);
    let vpn = vpn_route(0, 0, 0, 0).nlri.key();
    let labeled = labeled_route(0, 0, 0, 0).nlri.key();
    let bests = |manager: &RibManager| {
        let vpn = manager.loc_rib.get_vpn(&vpn).unwrap();
        let labeled = manager.loc_rib.get_labeled(&labeled).unwrap();
        assert_eq!((vpn.peer, vpn.path_id), (labeled.peer, labeled.path_id));
        (vpn.peer, vpn.path_id, vpn.local_pref_attr())
    };

    // Challenger from another peer wins on LOCAL_PREF.
    receive_vpn(&mut manager, 1, vec![vpn_route(1, 0, 7, 1)], vec![]);
    receive_labeled(&mut manager, 1, vec![labeled_route(1, 0, 7, 1)], vec![]);
    assert_eq!(bests(&manager), (peer_v4(source(1)), 7, Some(200)));
    check_bests(&manager, 0);

    // The best is replaced by a worse version of itself: peer 0 wins the tie.
    receive_vpn(&mut manager, 1, vec![vpn_route(1, 0, 7, 0)], vec![]);
    receive_labeled(&mut manager, 1, vec![labeled_route(1, 0, 7, 0)], vec![]);
    assert_eq!(bests(&manager), (peer_v4(source(0)), 1, Some(100)));
    check_bests(&manager, 1);

    // The best is withdrawn: the other peer's path takes over.
    receive_vpn(&mut manager, 0, vec![], vec![vpn_route(0, 0, 1, 0).key()]);
    receive_labeled(
        &mut manager,
        0,
        vec![],
        vec![labeled_route(0, 0, 1, 0).key()],
    );
    assert_eq!(bests(&manager), (peer_v4(source(1)), 7, Some(100)));
    check_bests(&manager, 2);
}

/// Selection checkpoints once per candidate it reads. `[replace, withdraw]`
/// of one non-best path of a key that holds `stored` paths from one session,
/// as `(vpn, labeled)` selection-stage checkpoints.
fn non_best_change_reads(stored: u32) -> [(usize, usize); 2] {
    let mut manager = manager();
    // Path 1 is the best; every other path ties below it.
    let paths = |variant_of: fn(u32) -> u8| (1..=stored).map(move |id| (id, variant_of(id)));
    let first_best = |id| u8::from(id == 1);
    receive_vpn(
        &mut manager,
        0,
        paths(first_best)
            .map(|(id, v)| vpn_route(0, 0, id, v))
            .collect(),
        vec![],
    );
    receive_labeled(
        &mut manager,
        0,
        paths(first_best)
            .map(|(id, v)| labeled_route(0, 0, id, v))
            .collect(),
        vec![],
    );
    let stage = |work: &super::work_scaling::Work, stage| work.get(stage).copied().unwrap_or(0);
    let steps: [(Vec<_>, Vec<_>, Vec<_>, Vec<_>); 2] = [
        (
            vec![vpn_route(0, 0, 2, 2)],
            vec![],
            vec![labeled_route(0, 0, 2, 2)],
            vec![],
        ),
        (
            vec![],
            vec![vpn_route(0, 0, 3, 0).key()],
            vec![],
            vec![labeled_route(0, 0, 3, 0).key()],
        ),
    ];
    let mut reads = [(0, 0); 2];
    for (step, (vpn_in, vpn_out, labeled_in, labeled_out)) in steps.into_iter().enumerate() {
        let work = checkpoints_in(|| receive_vpn(&mut manager, 0, vpn_in, vpn_out));
        reads[step].0 = stage(&work, "selection_vpn");
        let work = checkpoints_in(|| receive_labeled(&mut manager, 0, labeled_in, labeled_out));
        reads[step].1 = stage(&work, "selection_labeled");
        check_bests(&manager, step);
    }
    let rib = &manager.ribs[&peer_v4(source(0))];
    let expected = usize::try_from(stored).unwrap() - 1;
    assert_eq!((rib.vpn_len(), rib.labeled_len()), (expected, expected));
    let vpn = vpn_route(0, 0, 0, 0).nlri.key();
    let labeled = labeled_route(0, 0, 0, 0).nlri.key();
    assert_eq!(manager.loc_rib.get_vpn(&vpn).unwrap().path_id, 1);
    assert_eq!(manager.loc_rib.get_labeled(&labeled).unwrap().path_id, 1);
    reads
}

#[test]
fn non_best_change_reads_do_not_grow_with_stored_paths() {
    let small = non_best_change_reads(64);
    let large = non_best_change_reads(1024);
    assert_eq!(small, large, "candidate reads at 64 and 1,024 stored paths");
    for (vpn, labeled) in large {
        assert!(
            (1..=16).contains(&vpn) && (1..=16).contains(&labeled),
            "selection checkpoints per non-best change: vpn {vpn}, labeled {labeled}"
        );
    }
}
