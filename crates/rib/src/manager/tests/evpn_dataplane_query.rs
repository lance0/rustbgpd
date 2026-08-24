use super::*;
use crate::adj_rib_in::AdjRibIn;
use rustbgpd_wire::{
    EvpnEadPerEs, EvpnEadPerEvi, EvpnEs, EvpnIpPrefixRoute, EvpnIpPrefixValue, EvpnMacIp, EvpnRoute,
};

const PEER: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 9);
const RD: RouteDistinguisher = RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 9]);
const ESI: EthernetSegmentIdentifier =
    EthernetSegmentIdentifier::new([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

fn manager() -> RibManager {
    let (_tx, rx) = mpsc::channel(8);
    RibManager::new(rx, dummy_query_rx(), None, None, BgpMetrics::new())
}

fn rib_route(route: EvpnRoute) -> EvpnRibRoute {
    EvpnRibRoute {
        route,
        next_hop: IpAddr::V4(PEER),
        link_local_next_hop: None,
        peer: IpAddr::V4(PEER),
        attributes: Arc::new(vec![]),
        received_at: Instant::now(),
        origin_type: crate::route::RouteOrigin::Ibgp,
        peer_router_id: PEER,
        is_stale: false,
        is_llgr_stale: false,
    }
}

fn relevant_routes() -> Vec<EvpnRibRoute> {
    vec![
        rib_route(EvpnRoute::EadPerEs(EvpnEadPerEs {
            rd: RD,
            esi: ESI,
            ethernet_tag: EthernetTagId::MAX_ET,
            label: MplsLabel::new(100),
        })),
        rib_route(EvpnRoute::EadPerEvi(EvpnEadPerEvi {
            rd: RD,
            esi: ESI,
            ethernet_tag: EthernetTagId(100),
            label: MplsLabel::new(100),
        })),
        rib_route(EvpnRoute::MacIp(EvpnMacIp {
            rd: RD,
            esi: ESI,
            ethernet_tag: EthernetTagId(100),
            mac: MacAddress::new([0x02, 0, 0, 0, 0, 1]),
            ip: Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))),
            label1: MplsLabel::new(100),
            label2: None,
        })),
        rib_route(EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
            rd: RD,
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            prefix: EvpnIpPrefixValue::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
            gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            label: MplsLabel::new(5000),
        })),
    ]
}

fn irrelevant_routes() -> Vec<EvpnRibRoute> {
    vec![
        make_evpn_imet(PEER, 100),
        rib_route(EvpnRoute::Es(EvpnEs {
            rd: RD,
            esi: ESI,
            originator_ip: IpAddr::V4(PEER),
        })),
    ]
}

fn install_and_recompute(manager: &mut RibManager, route: EvpnRibRoute) {
    let key = route.key();
    manager
        .ribs
        .entry(IpAddr::V4(PEER))
        .or_insert_with(|| AdjRibIn::new(IpAddr::V4(PEER)))
        .insert_evpn(route);
    manager.recompute_and_distribute_evpn(&HashSet::from([key]));
}

fn withdraw_and_recompute(manager: &mut RibManager, route: &EvpnRibRoute) {
    let key = route.key();
    assert!(
        manager
            .ribs
            .get_mut(&IpAddr::V4(PEER))
            .unwrap()
            .withdraw_evpn(&key)
    );
    manager.recompute_and_distribute_evpn(&HashSet::from([key]));
}

fn query(
    manager: &mut RibManager,
    known_generation: Option<u64>,
) -> crate::update::EvpnDataplaneRoutesResponse {
    let (reply, mut response) = oneshot::channel();
    manager.handle_update(RibUpdate::QueryEvpnDataplaneRoutes {
        known_generation,
        reply,
    });
    response.try_recv().expect("actor replies synchronously")
}

#[test]
fn initial_snapshot_filters_exact_types_and_equal_token_does_zero_work() {
    let mut manager = manager();
    for route in relevant_routes().into_iter().chain(irrelevant_routes()) {
        install_and_recompute(&mut manager, route);
    }

    let initial = query(&mut manager, None);
    let routes = initial
        .routes
        .expect("startup must receive a full snapshot");
    let mut types: Vec<u8> = routes.iter().map(EvpnRibRoute::route_type).collect();
    types.sort_unstable();
    assert_eq!(types, vec![1, 1, 2, 5]);
    assert_eq!(initial.generation, 4);
    let visits = manager.evpn_dataplane_query_row_visits;

    let unchanged = query(&mut manager, Some(initial.generation));
    assert!(unchanged.routes.is_none());
    assert_eq!(manager.evpn_dataplane_query_row_visits, visits);
}

#[test]
fn type_three_and_four_changes_do_not_advance_projection_generation() {
    let mut manager = manager();
    for route in irrelevant_routes() {
        install_and_recompute(&mut manager, route.clone());
        assert_eq!(manager.evpn_dataplane_generation, 0);
        assert_eq!(manager.evpn_dataplane_route_count, 0);
        withdraw_and_recompute(&mut manager, &route);
        assert_eq!(manager.evpn_dataplane_generation, 0);
        assert_eq!(manager.evpn_dataplane_route_count, 0);
    }
}

#[test]
fn every_relevant_shape_add_change_withdraw_advances_exactly_once() {
    let mut manager = manager();
    let mut expected = 0;
    for mut route in relevant_routes() {
        install_and_recompute(&mut manager, route.clone());
        expected += 1;
        assert_eq!(manager.evpn_dataplane_generation, expected);
        assert_eq!(manager.evpn_dataplane_route_count, 1);

        route.next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
        install_and_recompute(&mut manager, route.clone());
        expected += 1;
        assert_eq!(manager.evpn_dataplane_generation, expected);
        assert_eq!(manager.evpn_dataplane_route_count, 1);

        withdraw_and_recompute(&mut manager, &route);
        expected += 1;
        assert_eq!(manager.evpn_dataplane_generation, expected);
        assert_eq!(manager.evpn_dataplane_route_count, 0);
    }

    let routes: Vec<_> = relevant_routes()
        .into_iter()
        .chain(irrelevant_routes())
        .collect();
    let keys: HashSet<_> = routes.iter().map(EvpnRibRoute::key).collect();
    let rib = manager
        .ribs
        .entry(IpAddr::V4(PEER))
        .or_insert_with(|| AdjRibIn::new(IpAddr::V4(PEER)));
    for route in routes {
        rib.insert_evpn(route);
    }
    manager.recompute_and_distribute_evpn(&keys);
    assert_eq!(
        manager.evpn_dataplane_generation,
        expected + 1,
        "one completed recompute call advances once even when four relevant keys change"
    );
    assert_eq!(manager.evpn_dataplane_route_count, 4);
    assert_eq!(manager.loc_rib.evpn_len(), 6);
    let response = query(&mut manager, None);
    assert_eq!(response.routes.unwrap().len(), 4);
}

#[test]
fn canceled_query_skips_work_and_generation_wraps_as_an_equality_token() {
    let mut manager = manager();
    manager.evpn_dataplane_generation = u64::MAX;
    let route = relevant_routes().pop().unwrap();
    install_and_recompute(&mut manager, route);
    assert_eq!(manager.evpn_dataplane_generation, 0);

    let visits = manager.evpn_dataplane_query_row_visits;
    let (reply, response) = oneshot::channel();
    drop(response);
    manager.handle_update(RibUpdate::QueryEvpnDataplaneRoutes {
        known_generation: Some(u64::MAX),
        reply,
    });
    assert_eq!(manager.evpn_dataplane_query_row_visits, visits);

    assert!(query(&mut manager, Some(u64::MAX)).routes.is_some());
    assert!(query(&mut manager, Some(0)).routes.is_none());
}
