use super::*;

fn rd_routes() -> [EvpnRibRoute; 2] {
    let route = crate::test_support::evpn_event(
        RouteEventType::Added,
        Some("192.0.2.1".parse().unwrap()),
        None,
    )
    .best
    .unwrap();
    [
        rustbgpd_wire::RouteDistinguisher([0, 0, 0xfd, 0xe8, 0, 0, 0, 100]),
        rustbgpd_wire::RouteDistinguisher([0, 2, 0, 0, 0xfd, 0xe8, 0, 100]),
    ]
    .map(|rd| {
        let mut route = route.clone();
        let EvpnRoute::MacIp(mac) = &mut route.route else {
            unreachable!()
        };
        mac.rd = rd;
        route
    })
}

#[tokio::test]
async fn rd_output_round_trips_legacy_best_and_both_peer_filters() {
    let routes = rd_routes();
    let (tx, mut rx) = mpsc::channel(8);
    let service = RibService::new(tx);
    let expected = routes.clone();
    let actor = tokio::spawn(async move {
        while let Some(update) = rx.recv().await {
            match update {
                RibUpdate::QueryEvpnRoutes { filter, reply } => {
                    reply.send(matching(&expected, filter.as_ref())).unwrap();
                }
                RibUpdate::QueryEvpnRoutesPage { filter, reply, .. } => {
                    let rows = matching(&expected, filter.as_ref());
                    reply
                        .send(Ok(rustbgpd_rib::EvpnRoutePage {
                            total: rows.len() as u64,
                            routes: rows,
                            has_more: false,
                            version: RoutePageVersion {
                                epoch: 1,
                                generation: 1,
                            },
                        }))
                        .unwrap();
                }
                _ => panic!("expected EVPN read"),
            }
        }
    });
    for route in routes {
        let row = evpn_route_to_proto(&route);
        assert_eq!(
            parse_rd(&row.rd).unwrap(),
            rustbgpd_rib::event::evpn_key_rd(&route.key()).unwrap()
        );
        let inputs = [row.rd.clone(), row.rd.to_ascii_uppercase()];
        for rd_filter in inputs {
            let legacy = service
                .list_evpn_routes(Request::new(proto::ListEvpnRequest {
                    rd_filter: rd_filter.clone(),
                    ..Default::default()
                }))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(legacy.routes, vec![row.clone()]);
            let best = service
                .list_best_evpn_routes(Request::new(proto::ListBestEvpnRoutesRequest {
                    rd_filter: rd_filter.clone(),
                    ..Default::default()
                }))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(best.routes, vec![row.clone()]);
            for advertised in [false, true] {
                let request = Request::new(proto::ListPeerEvpnRoutesRequest {
                    neighbor_address: "192.0.2.1".into(),
                    rd_filter: rd_filter.clone(),
                    ..Default::default()
                });
                let page = if advertised {
                    service.list_advertised_evpn_routes(request).await
                } else {
                    service.list_received_evpn_routes(request).await
                }
                .unwrap()
                .into_inner();
                assert_eq!(page.routes, vec![row.clone()]);
            }
        }
    }
    drop(service);
    actor.await.unwrap();
}

#[tokio::test]
async fn rd_output_round_trips_evpn_explain_exact_selector() {
    let routes = rd_routes();
    let (tx, mut rx) = mpsc::channel(8);
    let service = RibService::new(tx);
    let expected = routes.clone();
    let actor = tokio::spawn(async move {
        while let Some(RibUpdate::ExplainEvpnRoute { key, reply, .. }) = rx.recv().await {
            let route = expected
                .iter()
                .find(|route| route.key() == key)
                .unwrap()
                .clone();
            reply
                .send(rustbgpd_rib::update::ExplainEvpnRoute {
                    key,
                    received_from: None,
                    best: Some(route),
                    received: None,
                    selection_best: None,
                    compared: None,
                    candidate_count: 1,
                    reason: None,
                    reason_detail: String::new(),
                    selection_deferred: false,
                    export: None,
                    srv6_argument: None,
                })
                .unwrap();
        }
    });
    for route in routes {
        let row = evpn_route_to_proto(&route);
        for rd in [row.rd.clone(), row.rd.to_ascii_uppercase()] {
            let response = service
                .explain_evpn_route(Request::new(proto::ExplainEvpnRouteRequest {
                    key: Some(proto::EvpnRouteSelector {
                        rd,
                        route: Some(proto::evpn_route_selector::Route::MacIp(
                            proto::EvpnMacIpSelector {
                                ethernet_tag: 0,
                                mac: row.mac.clone(),
                                ip: row.ip.clone(),
                            },
                        )),
                    }),
                    ..Default::default()
                }))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.best, Some(row.clone()));
            assert_eq!(
                parse_evpn_selector(response.key.as_ref().unwrap()).unwrap(),
                route.key()
            );
        }
    }
    drop(service);
    actor.await.unwrap();
}

#[tokio::test]
async fn rd_output_round_trips_vpn_explain_and_filter() {
    let (tx, mut rx) = mpsc::channel(8);
    let service = RibService::new(tx);
    let (_, _, mut vpn, ..) = non_unicast_routes("192.0.2.1".parse().unwrap());
    vpn.nlri.route_distinguisher =
        rustbgpd_wire::RouteDistinguisher([0, 2, 0, 0, 0xfd, 0xe8, 0, 100]);
    let row = vpn_route_to_proto(&vpn);
    assert_eq!(row.route_distinguisher_str, "0x00020000fde80064");
    let actor = tokio::spawn(async move {
        while let Some(update) = rx.recv().await {
            match update {
                RibUpdate::QueryVpnRoutesPage { filter, reply, .. } => {
                    assert!(filter.unwrap()(&vpn));
                    reply
                        .send(Ok(rustbgpd_rib::RibRowsPage {
                            routes: vec![vpn.clone()],
                            total: 1,
                            has_more: false,
                            version: RoutePageVersion {
                                epoch: 1,
                                generation: 1,
                            },
                        }))
                        .unwrap();
                }
                RibUpdate::ExplainAdvertisedRoute {
                    rd,
                    peer,
                    prefix,
                    reply,
                    ..
                } => {
                    assert_eq!(rd, Some(vpn.nlri.route_distinguisher));
                    reply
                        .send(Ok(ExplainAdvertisedRoute {
                            decision: ExplainDecision::Advertise,
                            peer,
                            prefix,
                            next_hop: None,
                            path_id: 0,
                            route_peer: None,
                            route_type: None,
                            reasons: vec![],
                            modifications: rustbgpd_policy::RouteModifications::default(),
                            orr_vantage: None,
                            orr_candidates: vec![],
                            gates: vec![],
                            update_group_id: None,
                            already_advertised: false,
                            rd,
                            source: None,
                        }))
                        .unwrap();
                }
                _ => panic!("expected VPN filter or explain"),
            }
        }
    });
    for rd in [
        row.route_distinguisher_str.clone(),
        row.route_distinguisher_str.to_ascii_uppercase(),
    ] {
        let page = service
            .list_vpn_rib_routes(Request::new(proto::ListVpnRibRoutesRequest {
                view: proto::FamilyRouteView::Best as i32,
                rd_filter: rd.clone(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.routes, vec![row.clone()]);
        let explain = service
            .explain_advertised_route(Request::new(proto::ExplainAdvertisedRouteRequest {
                peer_address: "192.0.2.2".into(),
                prefix: "203.0.113.0".into(),
                prefix_length: 24,
                rd,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(explain.rd, row.route_distinguisher_str);
    }
    drop(service);
    actor.await.unwrap();
}

#[test]
fn empty_required_rd_selector_still_refuses() {
    let selector = proto::EvpnRouteSelector {
        rd: String::new(),
        route: Some(proto::evpn_route_selector::Route::MacIp(
            proto::EvpnMacIpSelector {
                ethernet_tag: 0,
                mac: "02:00:00:00:00:01".into(),
                ip: String::new(),
            },
        )),
    };
    assert_eq!(
        parse_evpn_selector(&selector).unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
}
