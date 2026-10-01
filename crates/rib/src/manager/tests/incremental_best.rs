//! Differential proof for the incremental best-path recompute and the
//! announcing-peers reverse index (`UnicastPrefixPeers`).
//!
//! Random operation sequences — announces (incl. same-peer attr changes,
//! Add-Path ties, refresh-style replays), withdrawals, session teardown,
//! GR stale marking, LLGR promotion, `EoR` sweeps/clears, peer registration,
//! route refresh, ORF pushes, and outbound channel pressure — use production
//! announce, withdraw, teardown, refresh, ORF, and `EoR` paths. Stale marking
//! and LLGR promotion still mutate the Adj-RIB-In directly. After every step:
//!
//! 1. the Loc-RIB best for every prefix must be IDENTICAL to a
//!    from-scratch full-scan recompute over every peer's Adj-RIB-In (the
//!    pre-index reference semantics), and
//! 2. the reverse index must satisfy its never-under-count contract:
//!    every (prefix, peer) pair present in an Adj-RIB-In is indexed
//!    (over-counting is allowed — stale entries are pruned lazily), and
//! 3. the three reachable peer-keyed refresh/ORF maps have no empty values.
//!    GR/LLGR and live-session maps intentionally permit empty values;
//!    VPN/RTC extra-withdraw residue is outside this unicast generator.

use std::time::Instant;

use proptest::prelude::*;
use rustbgpd_wire::{AddressPrefixOrf, OrfAction, OrfMatch, WhenToRefresh};

use super::*;
use crate::attr_set::AttrSet;
use crate::loc_rib::LocRib;
use crate::route::RouteOrigin;

const FAMILY: (Afi, Safi) = (Afi::Ipv4, Safi::Unicast);
const PEERS: u8 = 4;
const PREFIXES: u8 = 6;

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "one lifecycle compares four export modes and ECMP through invalidation, withdrawal, and recovery"
)]
fn srv6_unicast_eligibility_covers_incremental_export_multipath_and_recovery() {
    use crate::best_path::{BestPathReason, MultipathEligibility};
    use crate::srv6::tests::service_attribute;

    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let topology_peer = Ipv4Addr::new(10, 9, 9, 9);
    manager.handle_update(RibUpdate::BgpLsRoutesReceived {
        session_id: 0,
        peer: topology_peer.into(),
        announced: crate::orr::fixtures::square_topology(topology_peer),
        withdrawn: vec![],
    });
    let mut receivers = Vec::new();
    for (octet, add_path, per_client_best, vantage) in [
        (30, 0, false, None),
        (31, 2, false, None),
        (32, 0, true, None),
        (33, 0, false, Some(vantage_at_node_a())),
    ] {
        let peer = IpAddr::V4(Ipv4Addr::new(192, 0, 2, octet));
        let (outbound_tx, mut out) = mpsc::channel(16);
        manager.handle_update(RibUpdate::PeerUp {
            per_client_best,
            interpret_rfc1997: true,
            session_id: 0,
            peer,
            peer_asn: 65000,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx,
            export_policy: None,
            sendable_families: vec![FAMILY],
            is_ebgp: vantage.is_none(),
            route_reflector_client: vantage.is_some(),
            orr_vantage: vantage,
            add_path_send_families: if add_path > 0 { vec![FAMILY] } else { vec![] },
            add_path_send_max: add_path,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        });
        while out.try_recv().is_ok() {}
        receivers.push((peer, out));
    }
    assert!(manager.orr.spf.contains_key(&vantage_at_node_a()));
    let sid = "2001:db8:111:1::".parse().unwrap();
    let valid_service = service_attribute(5, sid, 19, Some([40, 24, 16, 0, 0, 0]));
    let mut fallback = build_route(0, 0, 0, 0, Instant::now());
    fallback.next_hop = "2001:db8::10".parse().unwrap();
    AttrSet::edit(&mut fallback.attributes, |attrs| {
        attrs.push(valid_service.clone());
    });
    let mut invalid = build_route(1, 0, 0, 0, Instant::now());
    invalid.next_hop = "2001:db8::11".parse().unwrap();
    AttrSet::edit(&mut invalid.attributes, |attrs| {
        attrs[2] = PathAttribute::LocalPref(200);
    });
    AttrSet::edit(&mut invalid.attributes, |attrs| {
        attrs.push(service_attribute(5, sid, 19, Some([100, 24, 16, 0, 0, 0])));
    });
    let announce = |manager: &mut RibManager, route: &Route| {
        manager.enqueue_routes_received(
            route.peer,
            vec![route.clone()],
            vec![],
            vec![],
            vec![],
            vec![],
            vec![],
            None,
        );
        drain_route_chunks(manager);
    };
    announce(&mut manager, &fallback);
    for (_, out) in &mut receivers {
        let mut routes = Vec::new();
        while let Ok(update) = out.try_recv() {
            routes.extend(update.announce.iter().cloned());
        }
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].peer, fallback.peer);
    }
    announce(&mut manager, &invalid);
    assert_eq!(
        manager.loc_rib.get(&fallback.prefix).unwrap().peer,
        fallback.peer
    );
    for (_, out) in &mut receivers {
        while let Ok(update) = out.try_recv() {
            assert!(update.announce.is_empty());
            assert_eq!(update.withdraw.len(), 0);
        }
    }
    for peer in std::iter::once(None).chain(receivers.iter().map(|(peer, _)| Some(*peer))) {
        let (reply, mut response) = oneshot::channel();
        manager.handle_explain_best_path(fallback.prefix, peer, reply);
        let explain = response.try_recv().unwrap().unwrap();
        assert_eq!(explain.best.unwrap().peer, fallback.peer);
        assert_eq!(explain.candidates.len(), 1);
        assert_eq!(explain.candidates[0].route.attributes, invalid.attributes);
        assert_eq!(
            explain.candidates[0].vs_best_reason,
            BestPathReason::Srv6SidInvalid
        );
        assert_eq!(explain.candidates[0].multipath, MultipathEligibility::None);
        assert_eq!(explain.candidates[0].advertised_path_id, 0);
        assert!(explain.best_reason.is_none());
    }
    // With equal BGP preferences, the invalid sibling must still stay out of ECMP.
    AttrSet::edit(&mut invalid.attributes, |attrs| {
        attrs[2] = PathAttribute::LocalPref(100);
    });
    announce(&mut manager, &invalid);
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryFibInstallCandidates {
        max_paths: 8,
        relax: true,
        weighted: false,
        deadline: tokio::time::Instant::now() + Duration::from_secs(5),
        reply,
    });
    let fib = response.try_recv().unwrap();
    assert_eq!(fib.len(), 1);
    assert_eq!(fib[0].next_hops.len(), 1);

    manager.enqueue_routes_received(
        fallback.peer,
        vec![],
        vec![(fallback.prefix, 0)],
        vec![],
        vec![],
        vec![],
        vec![],
        None,
    );
    drain_route_chunks(&mut manager);
    assert!(manager.loc_rib.get(&fallback.prefix).is_none());
    assert_eq!(
        manager.ribs[&invalid.peer]
            .get(&invalid.prefix, 0)
            .unwrap()
            .attributes,
        invalid.attributes
    );
    assert!(
        manager
            .unicast_prefix_peers
            .peers(&invalid.prefix)
            .any(|peer| peer == invalid.peer)
    );
    for (_, out) in &mut receivers {
        let mut withdrawn = Vec::new();
        while let Ok(update) = out.try_recv() {
            assert!(update.announce.is_empty());
            withdrawn.extend(update.withdraw);
        }
        assert_eq!(withdrawn.len(), 1);
    }
    let (reply, mut response) = oneshot::channel();
    manager.handle_explain_best_path(invalid.prefix, None, reply);
    let explain = response.try_recv().unwrap().unwrap();
    assert!(explain.best.is_none());
    assert_eq!(explain.candidates.len(), 1);
    assert_eq!(
        explain.candidates[0].vs_best_reason,
        BestPathReason::Srv6SidInvalid
    );

    AttrSet::edit(&mut invalid.attributes, |attrs| {
        *attrs.last_mut().unwrap() = valid_service;
    });
    announce(&mut manager, &invalid);
    assert_eq!(
        manager.loc_rib.get(&invalid.prefix).unwrap().peer,
        invalid.peer
    );
    for (_, out) in &mut receivers {
        let mut announced = Vec::new();
        while let Ok(update) = out.try_recv() {
            announced.extend(update.announce.iter().cloned());
        }
        assert_eq!(announced.len(), 1);
        assert_eq!(announced[0].peer, invalid.peer);
    }
    // Replacing the installed winner itself exercises the owner fast-path rescan.
    AttrSet::edit(&mut invalid.attributes, |attrs| {
        *attrs.last_mut().unwrap() = service_attribute(5, sid, 19, Some([100, 24, 16, 0, 0, 0]));
    });
    announce(&mut manager, &invalid);
    assert!(manager.loc_rib.get(&invalid.prefix).is_none());
    for (_, out) in &mut receivers {
        let mut withdrawn = Vec::new();
        while let Ok(update) = out.try_recv() {
            assert!(update.announce.is_empty());
            withdrawn.extend(update.withdraw);
        }
        assert_eq!(withdrawn.len(), 1);
    }
}

#[test]
fn srv6_local_injection_retains_invalid_input_without_selecting_it() {
    use crate::srv6::tests::service_attribute;
    let (_tx, rx) = mpsc::channel(16);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let sid = "2001:db8:111:1::".parse().unwrap();
    let mut route = build_route(0, 0, 0, 0, Instant::now());
    route.peer = LOCAL_PEER;
    route.origin_type = RouteOrigin::Local;
    route.next_hop = "2001:db8::10".parse().unwrap();
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.push(service_attribute(5, sid, 19, Some([100, 24, 16, 0, 0, 0])));
    });
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute {
        route: route.clone(),
        reply,
    });
    assert!(response.try_recv().unwrap().is_ok());
    assert!(manager.loc_rib.get(&route.prefix).is_none());
    assert_eq!(
        manager.ribs[&LOCAL_PEER]
            .get(&route.prefix, 0)
            .unwrap()
            .attributes,
        route.attributes
    );
    AttrSet::edit(&mut route.attributes, |attrs| {
        *attrs.last_mut().unwrap() = service_attribute(5, sid, 19, Some([40, 24, 16, 0, 0, 0]));
    });
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectRoute {
        route: route.clone(),
        reply,
    });
    assert!(response.try_recv().unwrap().is_ok());
    assert_eq!(
        manager.loc_rib.get(&route.prefix).unwrap().attributes,
        route.attributes
    );
    let mut evpn =
        super::evpn::make_evpn_macip(Ipv4Addr::UNSPECIFIED, [0, 1, 2, 3, 4, 5], None, false);
    evpn.peer = LOCAL_PEER;
    evpn.origin_type = RouteOrigin::Local;
    evpn.next_hop = "2001:db8::10".parse().unwrap();
    AttrSet::edit(&mut evpn.attributes, |attrs| {
        attrs.push(service_attribute(6, sid, 23, Some([100, 24, 16, 0, 0, 0])));
    });
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectEvpn {
        route: evpn.clone(),
        reply,
    });
    assert!(response.try_recv().unwrap().is_ok());
    assert!(manager.loc_rib.get_evpn(&evpn.key()).is_none());
    assert_eq!(
        manager.ribs[&LOCAL_PEER]
            .get_evpn(&evpn.key())
            .unwrap()
            .attributes,
        evpn.attributes
    );
    AttrSet::edit(&mut evpn.attributes, |attrs| {
        *attrs.last_mut().unwrap() = service_attribute(6, sid, 23, Some([40, 24, 16, 0, 0, 0]));
    });
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::InjectEvpn {
        route: evpn.clone(),
        reply,
    });
    assert!(response.try_recv().unwrap().is_ok());
    assert_eq!(
        manager.loc_rib.get_evpn(&evpn.key()).unwrap().attributes,
        evpn.attributes
    );
}

fn peer_addr(peer: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10 + peer))
}

fn prefix_of(index: u8) -> Prefix {
    Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 100 + index, 0, 0), 16))
}

/// Deterministic route for (peer, prefix, `path_id`, variant). `variant`
/// selects the attribute payload; it deliberately does NOT depend on
/// `path_id`, so one peer announcing the same variant on two path IDs
/// produces full-tie candidates (`best_path_cmp` Equal) — the case the
/// announce fast path must hand to the full rescan.
fn build_route(peer: u8, prefix: u8, path_id: u8, variant: u8, received_at: Instant) -> Route {
    Route {
        prefix: prefix_of(prefix),
        next_hop: peer_addr(peer),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: peer_addr(peer),
        attributes: AttrSet::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::LocalPref(100 + u32::from(variant % 2) * 10),
            PathAttribute::Med(u32::from(variant)),
        ]),
        received_at: crate::route::ReceivedAt::from_instant(received_at),
        origin_type: if peer < 2 {
            RouteOrigin::Ebgp
        } else {
            RouteOrigin::Ibgp
        },
        peer_router_id: Ipv4Addr::new(192, 0, 2, peer),
        is_stale: false,
        is_llgr_stale: false,
        path_id: u32::from(path_id),
        validation_state: RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        received_as_path: None,
        aspa_context: crate::route::AspaContextId::DEFAULT,
    }
}

#[derive(Debug, Clone)]
enum Op {
    /// Real announce path: `enqueue_routes_received` → chunk drain →
    /// `recompute_best_after_announce`. Re-announcing an existing
    /// (prefix, `path_id`) with a new variant is the same-peer attr-change /
    /// refresh-replay case.
    Announce {
        peer: u8,
        routes: Vec<(u8, u8, u8)>,
    },
    /// Real withdraw path → `recompute_best_after_withdraw`.
    Withdraw {
        peer: u8,
        keys: Vec<(u8, u8)>,
    },
    /// Production `PeerDown` teardown, registered or not.
    SessionDown {
        peer: u8,
    },
    /// RFC 4724 GR entry seam: mark the family stale (consecutive-restart
    /// re-mark deletes already-stale routes), then recompute.
    MarkStale {
        peer: u8,
    },
    /// RFC 9494 promotion seam: GR-stale → LLGR-stale with in-place
    /// `LLGR_STALE` community injection, then recompute.
    PromoteLlgr {
        peer: u8,
    },
    /// Production End-of-RIB sweep for the GR family.
    EorClear {
        peer: u8,
    },
    PeerUp {
        peer: u8,
        orf: bool,
    },
    PlainRefresh {
        peer: u8,
    },
    OrfPush {
        peer: u8,
        kind: u8,
    },
    FullChannel {
        peer: u8,
        full: bool,
    },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    let route = (0..PREFIXES, 0u8..2, 0u8..3);
    prop_oneof![
        5 => (0..PEERS, proptest::collection::vec(route, 1..5))
            .prop_map(|(peer, routes)| Op::Announce { peer, routes }),
        3 => (0..PEERS, proptest::collection::vec((0..PREFIXES, 0u8..2), 1..5))
            .prop_map(|(peer, keys)| Op::Withdraw { peer, keys }),
        1 => (0..PEERS).prop_map(|peer| Op::SessionDown { peer }),
        1 => (0..PEERS).prop_map(|peer| Op::MarkStale { peer }),
        1 => (0..PEERS).prop_map(|peer| Op::PromoteLlgr { peer }),
        1 => (0..PEERS).prop_map(|peer| Op::EorClear { peer }),
        2 => (0..PEERS, any::<bool>()).prop_map(|(peer, orf)| Op::PeerUp { peer, orf }),
        2 => (0..PEERS).prop_map(|peer| Op::PlainRefresh { peer }),
        2 => (0..PEERS, 0u8..3).prop_map(|(peer, kind)| Op::OrfPush { peer, kind }),
        1 => (0..PEERS, any::<bool>()).prop_map(|(peer, full)| Op::FullChannel { peer, full }),
    ]
}

struct Channels {
    receivers: [Option<mpsc::Receiver<crate::update::OutboundRouteUpdate>>; PEERS as usize],
    permits: [Vec<mpsc::OwnedPermit<crate::update::OutboundRouteUpdate>>; PEERS as usize],
    full: [bool; PEERS as usize],
    orf: [bool; PEERS as usize],
}

impl Channels {
    fn new() -> Self {
        Self {
            receivers: std::array::from_fn(|_| None),
            permits: std::array::from_fn(|_| Vec::new()),
            full: [false; PEERS as usize],
            orf: [false; PEERS as usize],
        }
    }

    fn drain_open(&mut self) {
        for (index, receiver) in self.receivers.iter_mut().enumerate() {
            if !self.full[index]
                && let Some(receiver) = receiver
            {
                while receiver.try_recv().is_ok() {}
            }
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "one dispatcher keeps generated lifecycle operations and their postconditions together"
)]
fn apply(manager: &mut RibManager, channels: &mut Channels, op: &Op, received_at: Instant) {
    match op {
        Op::Announce { peer, routes } => {
            let announced = routes
                .iter()
                .map(|&(prefix, path_id, variant)| {
                    build_route(*peer, prefix, path_id, variant, received_at)
                })
                .collect();
            manager.enqueue_routes_received(
                peer_addr(*peer),
                announced,
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                None,
            );
            drain_route_chunks(manager);
        }
        Op::Withdraw { peer, keys } => {
            let withdrawn = keys
                .iter()
                .map(|&(prefix, path_id)| (prefix_of(prefix), u32::from(path_id)))
                .collect();
            manager.enqueue_routes_received(
                peer_addr(*peer),
                vec![],
                withdrawn,
                vec![],
                vec![],
                vec![],
                vec![],
                None,
            );
            drain_route_chunks(manager);
        }
        Op::SessionDown { peer } => {
            let index = usize::from(*peer);
            let peer = peer_addr(*peer);
            manager.handle_update(RibUpdate::PeerDown {
                peer,
                session_id: 0,
            });
            channels.permits[index].clear();
            channels.receivers[index] = None;
            channels.full[index] = false;
            channels.orf[index] = false;
            assert!(
                !manager.ribs.contains_key(&peer),
                "PeerDown retained {peer}'s routes"
            );
            for (name, present) in [
                (
                    "pending_refresh",
                    manager.pending_refresh.contains_key(&peer),
                ),
                (
                    "peer_orf_pending",
                    manager.peer_orf_pending.contains_key(&peer),
                ),
                (
                    "peer_orf_filters",
                    manager.peer_orf_filters.contains_key(&peer),
                ),
            ] {
                assert!(!present, "PeerDown retained {name} for {peer}");
            }
        }
        Op::MarkStale { peer } => {
            if let Some(rib) = manager.ribs.get_mut(&peer_addr(*peer)) {
                let mut affected: HashSet<Prefix> = rib.iter().map(|r| r.prefix).collect();
                affected.extend(rib.mark_stale(FAMILY));
                manager.recompute_best(&affected);
                manager
                    .gr_peers
                    .entry(peer_addr(*peer))
                    .or_default()
                    .insert(FAMILY);
            }
        }
        Op::PromoteLlgr { peer } => {
            if let Some(rib) = manager.ribs.get_mut(&peer_addr(*peer)) {
                let affected: HashSet<Prefix> = rib
                    .promote_to_llgr_stale(FAMILY, &mut crate::attr_intern::AttrInternTable::new())
                    .into_iter()
                    .collect();
                manager.recompute_best(&affected);
            }
        }
        Op::EorClear { peer } => {
            let peer = peer_addr(*peer);
            let stale: Vec<_> = manager
                .ribs
                .get(&peer)
                .into_iter()
                .flat_map(AdjRibIn::iter)
                .filter(|route| route.is_stale || route.is_llgr_stale)
                .map(|route| (route.prefix, route.path_id))
                .collect();
            manager.handle_end_of_rib(peer, FAMILY.0, FAMILY.1);
            if let Some(rib) = manager.ribs.get(&peer) {
                for (prefix, path_id) in stale {
                    assert!(
                        rib.get(&prefix, path_id).is_none(),
                        "End-of-RIB retained stale route {prefix} path {path_id} from {peer}"
                    );
                }
            }
        }
        Op::PeerUp { peer, orf } => {
            let address = peer_addr(*peer);
            if manager.outbound_peers.contains_key(&address) {
                return;
            }
            let (outbound_tx, outbound_rx) = mpsc::channel(8);
            manager.handle_update(RibUpdate::PeerUp {
                per_client_best: false,
                interpret_rfc1997: true,
                session_id: 0,
                peer: address,
                peer_asn: 65000,
                peer_router_id: Ipv4Addr::UNSPECIFIED,
                outbound_tx,
                export_policy: None,
                sendable_families: vec![FAMILY],
                is_ebgp: true,
                route_reflector_client: false,
                orr_vantage: None,
                add_path_send_families: vec![],
                add_path_send_max: 0,
                negotiated_orf_recv: if *orf { vec![FAMILY] } else { vec![] },
                negotiated_llgr_families: vec![],
            });
            channels.receivers[usize::from(*peer)] = Some(outbound_rx);
            channels.orf[usize::from(*peer)] = *orf;
        }
        Op::PlainRefresh { peer } => {
            let address = peer_addr(*peer);
            if manager.outbound_peers.contains_key(&address) {
                manager.handle_update(RibUpdate::RouteRefreshRequest {
                    queued: Arc::default(),
                    peer: address,
                    session_id: 0,
                    afi: FAMILY.0,
                    safi: FAMILY.1,
                });
            }
        }
        Op::OrfPush { peer, kind } => {
            let address = peer_addr(*peer);
            if channels.orf[usize::from(*peer)] {
                let entries = match kind {
                    0 => vec![],
                    1 => vec![AddressPrefixOrf {
                        action: OrfAction::Add,
                        match_: OrfMatch::Permit,
                        sequence: 10,
                        min_len: 8,
                        max_len: 32,
                        prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
                    }],
                    _ => vec![AddressPrefixOrf {
                        action: OrfAction::RemoveAll,
                        match_: OrfMatch::Permit,
                        sequence: 0,
                        min_len: 0,
                        max_len: 0,
                        prefix: None,
                    }],
                };
                let (reply, mut response) = oneshot::channel();
                manager.handle_update(RibUpdate::PeerOrfUpdate {
                    peer: address,
                    session_id: 0,
                    afi: FAMILY.0,
                    safi: FAMILY.1,
                    when: WhenToRefresh::Defer,
                    entries,
                    reply,
                });
                assert!(response.try_recv().unwrap().is_ok());
            }
        }
        Op::FullChannel { peer, full } => {
            let index = usize::from(*peer);
            let Some(sender) = manager.outbound_peers.get(&peer_addr(*peer)) else {
                return;
            };
            channels.full[index] = *full;
            if *full {
                while let Ok(permit) = sender.clone().try_reserve_owned() {
                    channels.permits[index].push(permit);
                }
            } else {
                channels.permits[index].clear();
            }
        }
    }
    channels.drain_open();
}

/// Payload-identity comparison mirroring everything `LocRib::recompute`'s
/// change detection can observe, minus `received_at` (an unchanged best is
/// deliberately not reinstalled, so its clone keeps the older timestamp).
fn same_route(a: &Route, b: &Route) -> bool {
    a.prefix == b.prefix
        && a.peer == b.peer
        && a.path_id == b.path_id
        && a.next_hop == b.next_hop
        && a.link_local_next_hop == b.link_local_next_hop
        && a.next_hop_scope == b.next_hop_scope
        && a.peer_router_id == b.peer_router_id
        && a.is_stale == b.is_stale
        && a.is_llgr_stale == b.is_llgr_stale
        && a.origin_type == b.origin_type
        && a.validation_state == b.validation_state
        && a.aspa_state == b.aspa_state
        && a.attributes == b.attributes
}

fn check_invariants(manager: &RibManager, step: usize) {
    // Key presence is meaningful for these collections. GR/LLGR and live
    // sessions deliberately use empty values during their own transitions.
    for peer in (0..PEERS).map(peer_addr) {
        assert!(
            manager
                .pending_refresh
                .get(&peer)
                .is_none_or(|families| !families.is_empty()),
            "step {step}: empty pending_refresh for {peer}"
        );
        assert!(
            manager
                .peer_orf_pending
                .get(&peer)
                .is_none_or(|families| !families.is_empty()),
            "step {step}: empty peer_orf_pending for {peer}"
        );
        assert!(
            manager
                .peer_orf_filters
                .get(&peer)
                .is_none_or(|families| !families.is_empty()),
            "step {step}: empty peer_orf_filters for {peer}"
        );
    }
    // Index contract: never under-count. Every (prefix, peer) actually
    // present in an Adj-RIB-In must be indexed.
    for (peer, rib) in &manager.ribs {
        for route in rib.iter() {
            assert!(
                manager
                    .unicast_prefix_peers
                    .peers(&route.prefix)
                    .any(|indexed| indexed == *peer),
                "step {step}: index under-counts: peer {peer} holds {} but is not indexed",
                route.prefix,
            );
        }
    }

    // Loc-RIB equivalence: from-scratch full scan over every peer's
    // Adj-RIB-In (the pre-index reference collection) must select a best
    // identical to what the incremental/indexed path installed.
    let mut reference = LocRib::new();
    for index in 0..PREFIXES {
        let prefix = prefix_of(index);
        reference.recompute(
            prefix,
            manager
                .ribs
                .values()
                .flat_map(|rib| rib.iter_prefix(&prefix)),
        );
        match (reference.get(&prefix), manager.loc_rib.get(&prefix)) {
            (None, None) => {}
            (Some(expected), Some(actual)) => assert!(
                same_route(expected, actual),
                "step {step}: best mismatch for {prefix}:\n expected {expected:?}\n actual {actual:?}",
            ),
            (expected, actual) => panic!(
                "step {step}: best presence mismatch for {prefix}: \
                 expected {expected:?}, actual {actual:?}",
            ),
        }
    }
}

#[test]
fn lifecycle_ops_remove_stale_routes_and_restore_fallback() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let received_at = Instant::now();
    let mut channels = Channels::new();
    let ops = [
        Op::Announce {
            peer: 1,
            routes: vec![(1, 0, 0)],
        },
        Op::Announce {
            peer: 0,
            routes: vec![(0, 0, 0), (1, 0, 1)],
        },
        Op::MarkStale { peer: 0 },
        Op::Announce {
            peer: 0,
            routes: vec![(1, 0, 1)],
        },
        Op::EorClear { peer: 0 },
    ];
    for (step, op) in ops.iter().enumerate() {
        apply(&mut manager, &mut channels, op, received_at);
        check_invariants(&manager, step);
    }
    assert!(manager.ribs[&peer_addr(0)].get(&prefix_of(0), 0).is_none());
    assert!(manager.ribs[&peer_addr(0)].get(&prefix_of(1), 0).is_some());
    assert_eq!(
        manager.loc_rib.get(&prefix_of(1)).unwrap().peer,
        peer_addr(0)
    );

    apply(
        &mut manager,
        &mut channels,
        &Op::SessionDown { peer: 0 },
        received_at,
    );
    check_invariants(&manager, ops.len());
    assert_eq!(
        manager.loc_rib.get(&prefix_of(1)).unwrap().peer,
        peer_addr(1)
    );

    apply(
        &mut manager,
        &mut channels,
        &Op::Announce {
            peer: 0,
            routes: vec![(2, 0, 0)],
        },
        received_at,
    );
    apply(
        &mut manager,
        &mut channels,
        &Op::MarkStale { peer: 0 },
        received_at,
    );
    apply(
        &mut manager,
        &mut channels,
        &Op::PromoteLlgr { peer: 0 },
        received_at,
    );
    apply(
        &mut manager,
        &mut channels,
        &Op::EorClear { peer: 0 },
        received_at,
    );
    assert!(manager.ribs[&peer_addr(0)].get(&prefix_of(2), 0).is_none());
    assert!(manager.loc_rib.get(&prefix_of(2)).is_none());
}

#[test]
fn refresh_orf_and_full_channel_leave_no_peer_map_residue() {
    let (_tx, rx) = mpsc::channel(8);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let mut channels = Channels::new();
    let received_at = Instant::now();
    for (step, op) in [
        Op::PeerUp {
            peer: 0,
            orf: false,
        },
        Op::PlainRefresh { peer: 0 },
        Op::SessionDown { peer: 0 },
        Op::PeerUp { peer: 1, orf: true },
        Op::OrfPush { peer: 1, kind: 2 },
        Op::FullChannel {
            peer: 1,
            full: true,
        },
        Op::Announce {
            peer: 2,
            routes: vec![(0, 0, 0)],
        },
        Op::FullChannel {
            peer: 1,
            full: false,
        },
        Op::SessionDown { peer: 1 },
    ]
    .iter()
    .enumerate()
    {
        apply(&mut manager, &mut channels, op, received_at);
        if step == 1 {
            assert!(!manager.pending_refresh.contains_key(&peer_addr(0)));
        }
        if step == 4 {
            assert!(!manager.peer_orf_filters.contains_key(&peer_addr(1)));
            assert!(!manager.peer_orf_pending.contains_key(&peer_addr(1)));
        }
        if step == 6 {
            assert!(manager.dirty_peers.contains(&peer_addr(1)));
        }
        if step == 7 {
            manager.resync_dirty_peers_bounded();
            assert!(!manager.dirty_peers.contains(&peer_addr(1)));
        }
        check_invariants(&manager, step);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    #[test]
    fn incremental_best_path_matches_full_rescan(
        ops in proptest::collection::vec(op_strategy(), 1..80)
    ) {
        let (_tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
        let received_at = Instant::now();
        let mut channels = Channels::new();
        for (step, op) in ops.iter().enumerate() {
            apply(&mut manager, &mut channels, op, received_at);
            check_invariants(&manager, step);
        }
    }
}
