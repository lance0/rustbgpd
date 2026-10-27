use super::*;
use std::sync::Mutex;

const FAMILIES: [(Afi, Safi); 7] = [
    (Afi::Ipv4, Safi::Unicast),
    (Afi::Ipv4, Safi::FlowSpec),
    (Afi::L2Vpn, Safi::Evpn),
    (Afi::BgpLs, Safi::BgpLs),
    (Afi::Ipv4, Safi::MplsVpn),
    (Afi::Ipv4, Safi::LabeledUnicast),
    (Afi::Ipv4, Safi::RtConstrain),
];

fn insert_snapshot_routes(rib: &mut AdjRibIn, index: u32, stale: bool, llgr: bool) {
    let peer = Ipv4Addr::new(10, 0, 0, 1);
    let prefix = Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000 + index), 32);
    let mut route = make_route(prefix, peer);
    route.is_stale = stale;
    route.is_llgr_stale = llgr;
    rib.insert(route);

    let mut route = make_flowspec_route(peer);
    route.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
        rustbgpd_wire::FlowSpecPrefix::V4(prefix),
    )];
    route.is_stale = stale;
    route.is_llgr_stale = llgr;
    rib.insert_flowspec(route);

    let mut route = make_evpn_imet(peer, index);
    route.is_stale = stale;
    route.is_llgr_stale = llgr;
    rib.insert_evpn(route);

    let mut route = make_bgpls_route(peer, 0, 100);
    route.nlri.payload = index.to_be_bytes().to_vec().into();
    route.is_stale = stale;
    route.is_llgr_stale = llgr;
    rib.insert_bgpls(route);

    let mut route = make_vpn_rib_route(peer, 0, 100, 100);
    route.nlri.prefix = VpnPrefix::v4(prefix.addr, prefix.len).unwrap();
    route.is_stale = stale;
    route.is_llgr_stale = llgr;
    rib.insert_vpn(route);

    let mut route = make_labeled_rib_route(peer, 0, 100, 100);
    route.nlri.prefix = Prefix::V4(prefix);
    route.is_stale = stale;
    route.is_llgr_stale = llgr;
    rib.insert_labeled(route);

    let mut route = make_rtc_rib_route(peer, u16::try_from(index).unwrap(), 100);
    route.is_stale = stale;
    route.is_llgr_stale = llgr;
    rib.insert_rtc(route);
}

fn insert_snapshot_siblings(rib: &mut AdjRibIn, index: u16) {
    let peer = Ipv4Addr::new(10, 0, 0, 1);
    let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, index);
    let prefix = Ipv6Prefix::new(addr, 128);
    let mut route = make_v6_route(prefix, addr);
    route.peer = peer_v4(peer);
    rib.insert(route);

    let mut route = make_flowspec_route(peer);
    route.afi = Afi::Ipv6;
    route.rule.components = vec![rustbgpd_wire::FlowSpecComponent::DestinationPrefix(
        rustbgpd_wire::FlowSpecPrefix::V6(rustbgpd_wire::Ipv6PrefixOffset { prefix, offset: 0 }),
    )];
    rib.insert_flowspec(route);

    let mut route = make_bgpls_route(peer, 0, 100);
    route.family = BgpLsFamily::LinkStateVpn;
    route.nlri.route_distinguisher = Some([0, 0, 0xfd, 0xe8, 0, 0, 0, 1]);
    route.nlri.payload = index.to_be_bytes().to_vec().into();
    rib.insert_bgpls(route);

    let mut route = make_vpn_rib_route(peer, 0, 100, 100);
    route.nlri.prefix = VpnPrefix::v6(addr, 128).unwrap();
    rib.insert_vpn(route);

    let mut route = make_labeled_rib_route(peer, 0, 100, 100);
    route.nlri.prefix = Prefix::V6(prefix);
    rib.insert_labeled(route);
}

fn snapshot_inventory_shape(manager: &RibManager, peer: PeerId) -> [(usize, usize); 7] {
    [
        manager
            .refresh_stale_routes
            .get(&peer)
            .map_or((0, 0), |set| (set.len(), set.capacity())),
        manager
            .refresh_stale_flowspec
            .get(&peer)
            .map_or((0, 0), |set| (set.len(), set.capacity())),
        manager
            .refresh_stale_evpn
            .get(&peer)
            .map_or((0, 0), |set| (set.len(), set.capacity())),
        manager
            .refresh_stale_bgpls
            .get(&peer)
            .map_or((0, 0), |set| (set.len(), set.capacity())),
        manager
            .refresh_stale_vpn
            .get(&peer)
            .map_or((0, 0), |set| (set.len(), set.capacity())),
        manager
            .refresh_stale_labeled
            .get(&peer)
            .map_or((0, 0), |set| (set.len(), set.capacity())),
        manager
            .refresh_stale_rtc
            .get(&peer)
            .map_or((0, 0), |set| (set.len(), set.capacity())),
    ]
}

fn snapshot_route_counts(rib: &AdjRibIn) -> [usize; 7] {
    [
        rib.len(),
        rib.flowspec_len(),
        rib.evpn_len(),
        rib.bgpls_len(),
        rib.vpn_len(),
        rib.labeled_len(),
        rib.rtc_len(),
    ]
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "all seven actual BoRR writers check interior replies, exclusions and sibling inventories together"
)]
fn borr_actual_caller_services_snapshot_and_retirement_readiness() {
    for (family_index, &(afi, safi)) in FAMILIES.iter().enumerate() {
        let (tx, rx) = mpsc::channel(1);
        let (query_tx, query_rx) = mpsc::channel(1);
        let (readiness_tx, readiness_rx) = mpsc::channel(1);
        let mut manager = RibManager::new(rx, query_rx, None, None, BgpMetrics::new())
            .with_readiness_queries(readiness_rx);
        manager.flush_poll_budget = Duration::ZERO;
        let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
        manager.outbound_session_ids.insert(peer, 2);
        let mut rib = AdjRibIn::new(peer);
        for index in 0..4 {
            insert_snapshot_routes(&mut rib, index, index == 2, index == 3);
        }
        for index in 0..2 {
            insert_snapshot_siblings(&mut rib, index);
        }
        manager.ribs.insert(peer, rib);
        for route in manager.ribs[&peer].iter().filter(|route| {
            matches!(route.prefix, Prefix::V4(_)) && !route.is_stale && !route.is_llgr_stale
        }) {
            manager
                .loc_rib
                .recompute(route.prefix, std::iter::once(route));
        }
        assert_eq!(manager.loc_rib.len(), 2);
        let siblings = [
            (Afi::Ipv6, Safi::Unicast),
            (Afi::Ipv6, Safi::FlowSpec),
            (Afi::BgpLs, Safi::BgpLsVpn),
            (Afi::Ipv6, Safi::MplsVpn),
            (Afi::Ipv6, Safi::LabeledUnicast),
        ];
        for (afi, safi) in siblings {
            manager.handle_update(RibUpdate::BeginRouteRefresh {
                peer,
                session_id: 2,
                afi,
                safi,
            });
        }
        let counts = snapshot_route_counts(&manager.ribs[&peer]);
        assert_eq!(counts, [6, 6, 4, 6, 6, 6, 4]);
        let (reply, mut mutation) = oneshot::channel();
        tx.try_send(RibUpdate::QueryLocRibCount { reply }).unwrap();
        let (reply, general) = oneshot::channel();
        query_tx
            .try_send(RibUpdate::QueryLocRibCount { reply })
            .unwrap();
        let general = Arc::new(Mutex::new(general));

        for watched in ["borr_snapshot", "borr_retirement"] {
            let visits = Arc::new(Mutex::new(BTreeMap::<&'static str, usize>::new()));
            let pending =
                Mutex::new(None::<oneshot::Receiver<Result<usize, crate::RibReadinessError>>>);
            manager.replacement_readiness_test_hook = Some(Arc::new({
                let visits = Arc::clone(&visits);
                let readiness_tx = readiness_tx.clone();
                let general = Arc::clone(&general);
                move |stage| {
                    assert!(matches!(
                        general.lock().unwrap().try_recv(),
                        Err(oneshot::error::TryRecvError::Empty)
                    ));
                    let mut visits = visits.lock().unwrap();
                    let count = visits.entry(stage).or_default();
                    *count += 1;
                    if stage == watched {
                        match *count {
                            1 => {
                                let (reply, response) = oneshot::channel();
                                readiness_tx
                                    .try_send(crate::RibReadinessQuery::LocRibCount {
                                        reply,
                                        enqueued: std::time::Instant::now(),
                                    })
                                    .unwrap();
                                *pending.lock().unwrap() = Some(response);
                            }
                            2 => assert_eq!(
                                pending
                                    .lock()
                                    .unwrap()
                                    .as_mut()
                                    .unwrap()
                                    .try_recv()
                                    .unwrap(),
                                Ok(2),
                                "{family_index}: {watched} must answer inside its walk"
                            ),
                            _ => {}
                        }
                    }
                }
            }));
            manager.handle_update(RibUpdate::BeginRouteRefresh {
                peer,
                session_id: 2,
                afi,
                safi,
            });
            manager.replacement_readiness_test_hook = None;
            let visits = visits.lock().unwrap();
            assert_eq!(
                visits.get("borr_snapshot").copied().unwrap_or(0),
                counts[family_index],
                "every visited record, including excluded records, checkpoints"
            );
            if watched == "borr_retirement" {
                let expected = if matches!(family_index, 2 | 6) { 2 } else { 4 };
                assert_eq!(
                    visits.get(watched).copied().unwrap_or(0),
                    expected,
                    "duplicate BoRR visits old keys of both families"
                );
            }
            assert_eq!(manager.refresh_stale_counts[&(peer, afi, safi)], 2);
            assert_eq!(manager.primary_backlog(), 1);
            assert!(matches!(
                mutation.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            ));
            assert_eq!(snapshot_route_counts(&manager.ribs[&peer]), counts);
            assert_eq!(manager.loc_rib.len(), 2);
            for (afi, safi) in siblings {
                assert_eq!(manager.refresh_stale_counts[&(peer, afi, safi)], 2);
            }
            let expected = if matches!(family_index, 2 | 6) { 2 } else { 4 };
            assert_eq!(
                snapshot_inventory_shape(&manager, peer)[family_index].0,
                expected
            );
        }
        manager.drain_general_queries_if_unfenced();
        assert_eq!(general.lock().unwrap().try_recv().unwrap(), 2);
        assert!(matches!(
            mutation.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }
}

#[test]
fn borr_production_writers_bound_inventory_growth() {
    let (_tx, rx) = mpsc::channel(1);
    let mut manager = RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new());
    let peer = peer_v4(Ipv4Addr::new(10, 0, 0, 1));
    manager.ribs.insert(peer, AdjRibIn::new(peer));
    let mut inserted = 0;
    let mut previous = [(0_usize, 0_usize); 7];
    for count in [0, 14_336, 14_337, 28_672, 28_673, 32_768] {
        let rib = manager.ribs.get_mut(&peer).unwrap();
        for index in inserted..count {
            insert_snapshot_routes(rib, index, false, false);
        }
        inserted = count;
        for (afi, safi) in FAMILIES {
            manager.handle_update(RibUpdate::BeginRouteRefresh {
                peer,
                session_id: 0,
                afi,
                safi,
            });
            assert_eq!(
                manager
                    .refresh_stale_counts
                    .get(&(peer, afi, safi))
                    .copied()
                    .unwrap_or(0),
                usize::try_from(count).unwrap()
            );
        }
        let shape = snapshot_inventory_shape(&manager, peer);
        for (index, (len, capacity)) in shape.into_iter().enumerate() {
            assert_eq!(len, usize::try_from(count).unwrap());
            if matches!(count, 14_337 | 28_673) {
                assert!(
                    capacity.saturating_sub(previous[index].1) <= crate::fast_hash::SHARD_SPLIT_AT,
                    "{:?}: one added route grew capacity {} -> {capacity}",
                    FAMILIES[index],
                    previous[index].1
                );
            }
        }
        assert_eq!(
            snapshot_route_counts(&manager.ribs[&peer]),
            [usize::try_from(count).unwrap(); 7]
        );
        previous = shape;
    }
}
