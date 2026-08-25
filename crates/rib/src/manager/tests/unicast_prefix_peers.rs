use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_wire::{Ipv4Prefix, Prefix};

use super::super::{AdjRibInEpoch, PrefixAnnouncers, UnicastPrefixPeers};
use super::*;

fn peer(n: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, n))
}

fn prefix(n: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, n), 32))
}

fn manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

fn peer_up(manager: &mut RibManager, peer: IpAddr, session_id: u64) {
    let (outbound_tx, _outbound_rx) = mpsc::channel(8);
    manager.handle_update(RibUpdate::PeerUp {
        peer,
        session_id,
        peer_asn: 65001,
        peer_router_id: Ipv4Addr::new(192, 0, 2, 254),
        outbound_tx,
        export_policy: None,
        sendable_families: Vec::new(),
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        per_client_best: false,
        interpret_rfc1997: true,
        add_path_send_families: Vec::new(),
        add_path_send_max: 0,
        negotiated_orf_recv: Vec::new(),
        negotiated_llgr_families: Vec::new(),
    });
}

fn seed_route(manager: &mut RibManager, source: IpAddr, p: Prefix) {
    let IpAddr::V4(source_v4) = source else {
        unreachable!()
    };
    let Prefix::V4(prefix_v4) = p else {
        unreachable!()
    };
    manager
        .ribs
        .entry(source)
        .or_insert_with(|| AdjRibIn::new(source))
        .insert(make_route(prefix_v4, source_v4));
    manager.register_unicast_announcer(source, p);
}

fn make_add_path_route(source: IpAddr, p: Prefix, path_id: u32, med: u32) -> Route {
    let IpAddr::V4(source) = source else {
        unreachable!()
    };
    let Prefix::V4(prefix) = p else {
        unreachable!()
    };
    let mut route = make_route(prefix, source);
    Arc::make_mut(&mut route.attributes).push(PathAttribute::Med(med));
    route.path_id = path_id;
    route
}

fn routes_received(
    manager: &mut RibManager,
    source: IpAddr,
    session_id: u64,
    announced: Vec<Route>,
    withdrawn: Vec<(Prefix, u32)>,
) {
    manager.handle_update(RibUpdate::RoutesReceived {
        peer: source,
        session_id,
        announced,
        withdrawn,
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
    });
    drain_route_chunks(manager);
}

fn route_identity(route: &Route) -> (IpAddr, u32, u32) {
    (route.peer, route.path_id, route.med())
}

fn assert_prefix_state(
    manager: &RibManager,
    p: Prefix,
    expected: &[(IpAddr, u32, u32)],
    expected_best: Option<(IpAddr, u32, u32)>,
) {
    let mut full = manager
        .ribs
        .values()
        .flat_map(|rib| rib.iter_prefix(&p))
        .map(route_identity)
        .collect::<Vec<_>>();
    full.sort_unstable();
    let mut indexed =
        RibManager::unicast_candidates(&manager.ribs, &manager.unicast_prefix_peers, &p)
            .map(route_identity)
            .collect::<Vec<_>>();
    indexed.sort_unstable();
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    assert_eq!(full, expected);
    assert_eq!(indexed, full);
    for (source, _, _) in &full {
        assert!(
            manager
                .unicast_prefix_peers
                .peers(&p)
                .any(|peer| peer == *source)
        );
    }
    let mut oracle = crate::LocRib::new();
    oracle.recompute(p, manager.ribs.values().flat_map(|rib| rib.iter_prefix(&p)));
    assert_eq!(
        oracle.get(&p).map(route_identity),
        manager.loc_rib.get(&p).map(route_identity)
    );
    assert_eq!(manager.loc_rib.get(&p).map(route_identity), expected_best);
}

#[test]
fn representation_sizes_are_frozen() {
    assert_eq!(size_of::<AdjRibInEpoch>(), 4);
    assert_eq!(size_of::<PrefixAnnouncers>(), 8);
}

#[test]
fn singleton_is_inline_and_duplicate_neutral() {
    let mut index = UnicastPrefixPeers::default();
    index.register(peer(1), prefix(1));
    index.register(peer(1), prefix(1));
    assert!(matches!(
        index.prefixes[&prefix(1)],
        PrefixAnnouncers::Inline(_)
    ));
    assert!(index.spills.is_empty());
    assert_eq!(index.peers(&prefix(1)).collect::<Vec<_>>(), [peer(1)]);
}

#[test]
fn spill_enumerates_two_and_three_once_each() {
    let mut index = UnicastPrefixPeers::default();
    for n in 1..=3 {
        index.register(peer(n), prefix(1));
    }
    index.register(peer(2), prefix(1));
    assert_eq!(
        index.peers(&prefix(1)).collect::<Vec<_>>(),
        [peer(1), peer(2), peer(3)]
    );
}

#[test]
fn spill_collapse_sheds_heap_and_reuses_slot() {
    let mut index = UnicastPrefixPeers::default();
    for n in 1..=3 {
        index.register(peer(n), prefix(1));
    }
    assert!(index.spills[0].spilled());
    index.prune_to_live(&prefix(1), |candidate| candidate == peer(1));
    assert_eq!(index.spills.len(), 1);
    assert_eq!(index.spills[0].capacity(), 2);
    assert_eq!(index.free_spills, [0]);
    index.register(peer(1), prefix(2));
    index.register(peer(2), prefix(2));
    assert_eq!(index.spills.len(), 1);
    assert!(index.free_spills.is_empty());
    for n in 3..=20 {
        index.prune_to_live(&prefix(2), |candidate| candidate == peer(1));
        index.register(peer(n), prefix(2));
        assert_eq!(index.spills.len(), 1, "spill high-water must stay bounded");
    }
}

#[test]
fn retired_address_gets_new_epoch_and_stale_entries_do_not_resolve() {
    let mut index = UnicastPrefixPeers::default();
    index.register(peer(1), prefix(1));
    let first = index.peer_epochs[&peer(1)];
    index.retire_peer(peer(1));
    assert!(index.peers(&prefix(1)).next().is_none());
    index.register(peer(1), prefix(2));
    let second = index.peer_epochs[&peer(1)];
    assert!(second.0 > first.0);
    assert!(index.peers(&prefix(1)).next().is_none());
    assert_eq!(index.peers(&prefix(2)).collect::<Vec<_>>(), [peer(1)]);
}

#[test]
#[should_panic(expected = "Adj-RIB-In epoch space exhausted")]
fn epoch_exhaustion_panics_instead_of_wrapping() {
    let mut index = UnicastPrefixPeers {
        next_epoch: u32::MAX,
        ..UnicastPrefixPeers::default()
    };
    let _ = index.epoch_for_peer(peer(1));
}

#[test]
fn production_teardown_retires_before_same_address_reuse() {
    let source = peer(1);
    let old_prefix = prefix(1);
    let mut manager = manager();
    peer_up(&mut manager, source, 1);
    seed_route(&mut manager, source, old_prefix);
    let first = manager.unicast_prefix_peers.peer_epochs[&source];

    manager.handle_update(RibUpdate::PeerDown {
        peer: source,
        session_id: 1,
    });
    assert!(
        !manager
            .unicast_prefix_peers
            .peer_epochs
            .contains_key(&source)
    );
    assert!(
        !manager
            .unicast_prefix_peers
            .epoch_peers
            .contains_key(&first)
    );
    assert!(
        manager
            .unicast_prefix_peers
            .peers(&old_prefix)
            .next()
            .is_none()
    );

    peer_up(&mut manager, source, 2);
    seed_route(&mut manager, source, prefix(2));
    assert!(manager.unicast_prefix_peers.peer_epochs[&source].0 > first.0);
    assert!(
        manager
            .unicast_prefix_peers
            .peers(&old_prefix)
            .next()
            .is_none()
    );
}

#[test]
fn production_replacement_and_collision_failback_retire_incarnations() {
    let source = peer(1);
    let mut manager = manager();
    peer_up(&mut manager, source, 1);
    seed_route(&mut manager, source, prefix(1));
    let first = manager.unicast_prefix_peers.peer_epochs[&source];

    peer_up(&mut manager, source, 2);
    assert!(
        !manager
            .unicast_prefix_peers
            .epoch_peers
            .contains_key(&first)
    );
    seed_route(&mut manager, source, prefix(2));
    let second = manager.unicast_prefix_peers.peer_epochs[&source];
    assert!(second.0 > first.0);

    manager.handle_update(RibUpdate::PeerDown {
        peer: source,
        session_id: 2,
    });
    assert!(
        !manager
            .unicast_prefix_peers
            .epoch_peers
            .contains_key(&second)
    );
    seed_route(&mut manager, source, prefix(3));
    assert!(manager.unicast_prefix_peers.peer_epochs[&source].0 > second.0);
    assert!(
        manager
            .unicast_prefix_peers
            .peers(&prefix(2))
            .next()
            .is_none()
    );
}

#[test]
fn production_gr_and_llgr_reestablishment_preserve_epoch() {
    for llgr in [false, true] {
        let source = peer(if llgr { 2 } else { 1 });
        let mut manager = manager();
        peer_up(&mut manager, source, 1);
        seed_route(&mut manager, source, prefix(1));
        let epoch = manager.unicast_prefix_peers.peer_epochs[&source];
        if llgr {
            manager.llgr_peers.insert(source, HashSet::new());
        } else {
            manager.gr_peers.insert(source, HashSet::new());
        }
        peer_up(&mut manager, source, 2);
        assert_eq!(manager.unicast_prefix_peers.peer_epochs[&source], epoch);
        assert_eq!(manager.unicast_prefix_peers.epoch_peers[&epoch], source);
        assert_eq!(
            manager
                .unicast_prefix_peers
                .peers(&prefix(1))
                .collect::<Vec<_>>(),
            [source]
        );
    }
}

#[test]
fn production_add_path_replacement_lifecycle_matches_full_scan() {
    let a = peer(1);
    let b = peer(2);
    let p = prefix(1);
    let a10 = (a, 10, 10);
    let a20 = (a, 20, 20);
    let b30 = (b, 0, 30);
    let mut manager = manager();
    peer_up(&mut manager, a, 1);
    peer_up(&mut manager, b, 10);
    routes_received(
        &mut manager,
        b,
        10,
        vec![make_add_path_route(b, p, 0, 30)],
        vec![],
    );
    routes_received(
        &mut manager,
        a,
        1,
        vec![
            make_add_path_route(a, p, 10, 10),
            make_add_path_route(a, p, 20, 20),
        ],
        vec![],
    );
    assert_prefix_state(&manager, p, &[a10, a20, b30], Some(a10));

    let old_epoch = manager.unicast_prefix_peers.peer_epochs[&a];
    peer_up(&mut manager, a, 2);
    assert!(
        !manager
            .unicast_prefix_peers
            .epoch_peers
            .contains_key(&old_epoch)
    );
    assert_prefix_state(&manager, p, &[b30], Some(b30));
    routes_received(
        &mut manager,
        a,
        2,
        vec![
            make_add_path_route(a, p, 10, 10),
            make_add_path_route(a, p, 20, 20),
        ],
        vec![],
    );
    assert_prefix_state(&manager, p, &[a10, a20, b30], Some(a10));

    manager.handle_update(RibUpdate::PeerDown {
        peer: a,
        session_id: 1,
    });
    assert_prefix_state(&manager, p, &[a10, a20, b30], Some(a10));
    manager.handle_update(RibUpdate::PeerDown {
        peer: a,
        session_id: 2,
    });
    assert_prefix_state(&manager, p, &[b30], Some(b30));

    peer_up(&mut manager, a, 3);
    routes_received(
        &mut manager,
        a,
        3,
        vec![
            make_add_path_route(a, p, 10, 10),
            make_add_path_route(a, p, 20, 20),
        ],
        vec![],
    );
    routes_received(&mut manager, a, 3, vec![], vec![(p, 20)]);
    assert_prefix_state(&manager, p, &[a10, b30], Some(a10));
    routes_received(
        &mut manager,
        a,
        3,
        vec![make_add_path_route(a, p, 20, 20)],
        vec![],
    );
    routes_received(&mut manager, a, 3, vec![], vec![(p, 10)]);
    assert_prefix_state(&manager, p, &[a20, b30], Some(a20));
    routes_received(&mut manager, a, 3, vec![], vec![(p, 20)]);
    assert_prefix_state(&manager, p, &[b30], Some(b30));
    routes_received(&mut manager, b, 10, vec![], vec![(p, 0)]);
    assert_prefix_state(&manager, p, &[], None);
    assert!(manager.unicast_prefix_peers.peers(&p).next().is_none());
}
