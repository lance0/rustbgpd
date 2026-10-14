use super::*;

#[test]
fn family_page_tokens_bind_family_scope_filters_and_version() {
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let scope = RouteQueryScope::Received { peer: Some(peer) };
    let version = RoutePageVersion {
        epoch: 2,
        generation: 3,
    };
    let identity = family_query_identity("vpn", "canonical-filter");
    let token = encode_family_page_token(
        scope,
        &identity,
        "0000fde800000001~10.0.0.0/24~192.0.2.1~7",
        version,
    );
    let (_, after, expected) =
        family_page_params(1, &token, scope, &identity, parse_vpn_page_key).unwrap();
    assert_eq!(after.unwrap().2, 7);
    assert_eq!(expected, Some(version));
    for (scope, identity) in [
        (RouteQueryScope::Best, identity.clone()),
        (RouteQueryScope::Advertised { peer }, identity.clone()),
        (scope, family_query_identity("labeled", "canonical-filter")),
        (scope, family_query_identity("vpn", "different-filter")),
    ] {
        assert_eq!(
            family_page_params(1, &token, scope, &identity, parse_vpn_page_key)
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    let altered = token.replacen("~7", "~8", 1);
    assert!(decode_family_page_token(&altered).is_err());
    assert!(decode_family_page_token(&"x".repeat(1025)).is_err());
    assert!(parse_family_prefix("10.0.0.1/24").is_err());
    assert!(parse_family_prefix("2001:db8::1/64").is_err());
    assert!(family_page_scope(3, "192.0.2.1").is_err());
    assert!(family_page_scope(1, "").is_err());
    assert!(family_page_scope(2, "invalid").is_err());
}

#[tokio::test]
async fn vpn_pages_preserve_raw_rd_identity_across_continuation_and_filtering() {
    let peer = "192.0.2.1".parse().unwrap();
    let (_, _, mut first, _, _) = non_unicast_routes(peer);
    first.nlri.route_distinguisher =
        rustbgpd_wire::RouteDistinguisher([0, 2, 0, 0, 0xfd, 0xe8, 0, 100]);
    let mut second = first.clone();
    second.nlri.route_distinguisher.0[7] = 101;
    let (tx, rx) = mpsc::channel(8);
    let (query_tx, query_rx) = mpsc::channel(1);
    let manager = rustbgpd_rib::RibManager::new(
        rx,
        query_rx,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    );
    let actor = tokio::spawn(manager.run());
    tx.send(RibUpdate::VpnRoutesReceived {
        peer,
        session_id: 1,
        announced: vec![second.clone(), first.clone()],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let svc = RibService::new(tx.clone());
    let request = proto::ListVpnRoutesPageRequest {
        view: proto::FamilyRouteView::Received as i32,
        peer_filter: peer.to_string(),
        page_size: 1,
        ..Default::default()
    };
    let page = svc
        .list_vpn_routes_page(Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(page.total_count, 2);
    assert_eq!(
        page.routes[0].route_distinguisher,
        first.nlri.route_distinguisher.0
    );
    assert_ne!(page.next_page_token, "");
    let mut continuation = request.clone();
    continuation.page_token = page.next_page_token;
    let page = svc
        .list_vpn_routes_page(Request::new(continuation))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(page.routes.len(), 1);
    assert_eq!(
        page.routes[0].route_distinguisher,
        second.nlri.route_distinguisher.0
    );
    assert!(
        page.next_page_token.is_empty(),
        "continuation must finish without repeating rows"
    );
    for (rd, expected) in [("0x00020000fde80064", 1), ("65000:100", 0)] {
        let mut filtered = request.clone();
        filtered.rd_filter = rd.into();
        let page = svc
            .list_vpn_routes_page(Request::new(filtered))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.total_count, expected);
        if expected == 1 {
            assert_eq!(
                page.routes[0].route_distinguisher,
                first.nlri.route_distinguisher.0
            );
        }
    }
    drop(svc);
    drop(tx);
    drop(query_tx);
    actor.await.unwrap();
}

#[tokio::test]
async fn raw_page_filters_preserve_rd_and_rt_encoding_and_reject_non_targets() {
    let peer = "192.0.2.1".parse().unwrap();
    let (mut route, ..) = non_unicast_routes(peer);
    let raw = "0x00020000fde80064";
    let rd = parse_family_rd(raw).unwrap().unwrap();
    assert_eq!(rd.to_string(), "65000:100");
    let EvpnRoute::Imet(ref mut imet) = route.route else {
        unreachable!()
    };
    imet.rd = rd;
    let request = proto::ListEvpnRoutesPageRequest {
        rd_filter: raw.into(),
        ..Default::default()
    };
    let (filter, raw_identity) = evpn_loc_filter(&request).unwrap();
    assert!(filter.unwrap()(&route));
    let (_, text_identity) = evpn_loc_filter(&proto::ListEvpnRoutesPageRequest {
        rd_filter: "65000:100".into(),
        ..Default::default()
    })
    .unwrap();
    assert_ne!(
        raw_identity, text_identity,
        "same display must not merge typed filters"
    );
    let version = RoutePageVersion {
        epoch: 1,
        generation: 2,
    };
    let token =
        encode_evpn_page_token(RouteQueryScope::Best, &raw_identity, &route, version).unwrap();
    let (tx, _rx) = mpsc::channel(1);
    let svc = RibService::new(tx);
    assert_eq!(
        svc.list_evpn_routes_page(Request::new(proto::ListEvpnRoutesPageRequest {
            rd_filter: "65000:100".into(),
            page_token: token,
            ..Default::default()
        }))
        .await
        .unwrap_err()
        .code(),
        tonic::Code::InvalidArgument
    );
    assert_eq!(
        parse_family_route_target("0x02020000fde80064").unwrap(),
        Some(0x0202_0000_fde8_0064)
    );
    assert_ne!(
        parse_family_route_target("RT:65000:100").unwrap(),
        parse_family_route_target("0x02020000fde80064").unwrap()
    );
    for invalid in [
        "0x00030000fde80064",
        "0xffff0000fde80064",
        "0xzz020000fde80064",
        "0x0202",
    ] {
        assert!(parse_family_route_target(invalid).is_err(), "{invalid}");
    }
    assert!(parse_family_rd("0x00").is_err());
}

#[tokio::test]
async fn rtc_raw_target_filter_matches_only_the_exact_full_wire_membership() {
    let peer = "192.0.2.1".parse().unwrap();
    let (_, _, _, _, mut route) = non_unicast_routes(peer);
    route.nlri.prefix_len = 96;
    route.nlri.route_target_bits = 0x0202_0000_fde8_0064;
    let (tx, mut rx) = mpsc::channel(1);
    let svc = RibService::new(tx);
    let task = tokio::spawn(async move {
        let Some(RibUpdate::QueryRtcRoutesPage { filter, reply, .. }) = rx.recv().await else {
            panic!("expected RTC page");
        };
        let filter = filter.unwrap();
        assert!(filter(&route));
        let mut wrong_type = route.clone();
        wrong_type.nlri.route_target_bits = 0x0002_fde8_0000_0064;
        assert!(
            !filter(&wrong_type),
            "equal display is not equal target bytes"
        );
        let mut partial = route.clone();
        partial.nlri.prefix_len = 80;
        assert!(!filter(&partial));
        reply
            .send(Ok(rustbgpd_rib::RibRowsPage {
                routes: vec![route],
                total: 1,
                has_more: false,
                version: RoutePageVersion {
                    epoch: 1,
                    generation: 2,
                },
            }))
            .unwrap();
    });
    let page = svc
        .list_rtc_routes_page(Request::new(proto::ListRtcRoutesPageRequest {
            view: proto::FamilyRouteView::Received as i32,
            peer_filter: peer.to_string(),
            route_target_filter: "0x02020000fde80064".into(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(page.total_count, 1);
    assert_eq!(page.routes[0].route_target, "RT:65000:100");
    task.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one typed route fixture follows filter validation, page response and invalidated continuation"
)]
async fn evpn_loc_filters_and_page_scope_are_applied_before_materialization() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, ExtendedCommunity, MacAddress,
        MplsLabel,
    };
    let source: IpAddr = "192.0.2.1".parse().unwrap();
    let (mut route, ..) = non_unicast_routes(source);
    let mac = MacAddress([0, 1, 2, 3, 4, 5]);
    let esi = EthernetSegmentIdentifier([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    route.route = EvpnRoute::MacIp(EvpnMacIp {
        rd: "65000:100".parse().unwrap(),
        esi,
        ethernet_tag: EthernetTagId(0),
        mac,
        ip: None,
        label1: MplsLabel::new(101),
        label2: Some(MplsLabel::new(202)),
    });
    route.attributes = AttrSet::new(vec![PathAttribute::ExtendedCommunities(vec![
        ExtendedCommunity::bgp_encapsulation(8),
    ])]);
    let req = proto::ListEvpnRoutesPageRequest {
        route_type_filter: 2,
        peer_filter: source.to_string(),
        rd_filter: "65000:100".into(),
        mac_filter: mac.to_string(),
        esi_filter: esi.to_string(),
        vni_filter: Some(202),
        page_size: 1,
        ..Default::default()
    };
    let (filter, identity) = evpn_loc_filter(&req).unwrap();
    assert!(filter.as_ref().unwrap()(&route));
    let mut wrong = route.clone();
    wrong.attributes = AttrSet::new(Vec::new());
    assert!(
        !filter.as_ref().unwrap()(&wrong),
        "MPLS label cannot satisfy a VNI filter"
    );
    let mut wrong = route.clone();
    wrong.peer = "192.0.2.2".parse().unwrap();
    assert!(!filter.as_ref().unwrap()(&wrong));
    for changed in [
        proto::ListEvpnRoutesPageRequest {
            vni_filter: Some(999),
            ..req.clone()
        },
        proto::ListEvpnRoutesPageRequest {
            mac_filter: "00:01:02:03:04:06".into(),
            ..req.clone()
        },
        proto::ListEvpnRoutesPageRequest {
            esi_filter: "00:01:02:03:04:05:06:07:08:0a".into(),
            ..req.clone()
        },
        proto::ListEvpnRoutesPageRequest {
            route_type_filter: 3,
            ..req.clone()
        },
    ] {
        assert!(!evpn_loc_filter(&changed).unwrap().0.unwrap()(&route));
    }
    assert!(
        evpn_loc_filter(&proto::ListEvpnRoutesPageRequest {
            mac_filter: "bad".into(),
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        evpn_loc_filter(&proto::ListEvpnRoutesPageRequest {
            esi_filter: "bad".into(),
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        evpn_loc_filter(&proto::ListEvpnRoutesPageRequest {
            vni_filter: Some(1 << 24),
            ..Default::default()
        })
        .is_err()
    );
    let (tx, mut rx) = mpsc::channel(1);
    let svc = RibService::new(tx);
    let task = tokio::spawn(async move {
        let Some(RibUpdate::QueryEvpnRoutesPage {
            scope,
            filter,
            page_size,
            after,
            reply,
            ..
        }) = rx.recv().await
        else {
            panic!("expected EVPN page");
        };
        assert_eq!(scope, RouteQueryScope::Best);
        assert_eq!(page_size, 1);
        assert!(after.is_none());
        assert!(filter.unwrap()(&route));
        reply
            .send(Ok(rustbgpd_rib::EvpnRoutePage {
                routes: vec![route],
                total: 2,
                has_more: true,
                version: RoutePageVersion {
                    epoch: 8,
                    generation: 9,
                },
            }))
            .unwrap();
    });
    let response = svc
        .list_evpn_routes_page(Request::new(req))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.routes.len(), 1);
    assert_eq!(response.total_count, 2);
    let cursor = decode_evpn_page_token(&response.next_page_token).unwrap();
    assert_eq!(cursor.scope, RouteQueryScope::Best);
    assert_eq!(cursor.query_identity, identity);
    assert_eq!(cursor.version.generation, 9);
    task.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one typed route fixture follows filter validation, page response and invalidated continuation"
)]
async fn vpn_family_page_response_filters_and_invalidation() {
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let destination: IpAddr = "192.0.2.2".parse().unwrap();
    let (_, _, route, _, _) = non_unicast_routes(peer);
    let (tx, mut rx) = mpsc::channel(1);
    let svc = RibService::new(tx);
    let task = tokio::spawn(async move {
        let Some(RibUpdate::QueryVpnRoutesPage {
            scope,
            filter,
            page_size,
            after,
            expected_version,
            reply,
        }) = rx.recv().await
        else {
            panic!("expected Vpn page");
        };
        assert_eq!(scope, RouteQueryScope::Advertised { peer: destination });
        assert_eq!(page_size, 1);
        assert!(after.is_none());
        assert!(expected_version.is_none());
        assert!(
            filter.as_ref().unwrap()(&route),
            "advertised destination must not filter source rows"
        );
        let mut wrong = route.clone();
        wrong.nlri.route_distinguisher = "65000:101".parse().unwrap();
        assert!(!filter.unwrap()(&wrong));
        reply
            .send(Ok(rustbgpd_rib::RibRowsPage {
                routes: vec![route],
                total: 2,
                has_more: true,
                version: RoutePageVersion {
                    epoch: 1,
                    generation: 2,
                },
            }))
            .unwrap();
        let Some(RibUpdate::QueryVpnRoutesPage {
            after,
            expected_version,
            reply,
            ..
        }) = rx.recv().await
        else {
            panic!("expected continuation");
        };
        assert!(after.is_some());
        assert_eq!(expected_version.unwrap().generation, 2);
        reply.send(Err(RoutePageError::Invalidated)).unwrap();
    });
    let request = proto::ListVpnRoutesPageRequest {
        view: proto::FamilyRouteView::Advertised as i32,
        peer_filter: destination.to_string(),
        page_size: 1,
        afi_safi: "l3vpn_ipv6_unicast".into(),
        prefix_filter: "2001:db8:100::/64".into(),
        rd_filter: "65000:100".into(),
        ..Default::default()
    };
    let response = svc
        .list_vpn_routes_page(Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.routes[0].peer_address, peer.to_string());
    assert_eq!(response.total_count, 2);
    let mut continuation = request.clone();
    continuation.page_token = response.next_page_token.clone();
    assert_eq!(
        svc.list_vpn_routes_page(Request::new(continuation.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    continuation.peer_filter = peer.to_string();
    assert_eq!(
        svc.list_vpn_routes_page(Request::new(continuation))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    for bad in [
        proto::ListVpnRoutesPageRequest {
            view: 99,
            ..request.clone()
        },
        proto::ListVpnRoutesPageRequest {
            peer_filter: String::new(),
            ..request.clone()
        },
        proto::ListVpnRoutesPageRequest {
            page_size: 1001,
            ..request.clone()
        },
        proto::ListVpnRoutesPageRequest {
            afi_safi: "ipv4_unicast".into(),
            ..request.clone()
        },
        proto::ListVpnRoutesPageRequest {
            page_token: "malformed".into(),
            ..request.clone()
        },
    ] {
        assert_eq!(
            svc.list_vpn_routes_page(Request::new(bad))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    task.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one typed route fixture follows filter validation, page response and invalidated continuation"
)]
async fn labeled_family_page_response_filters_and_invalidation() {
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let destination: IpAddr = "192.0.2.2".parse().unwrap();
    let (_, _, _, route, _) = non_unicast_routes(peer);
    let (tx, mut rx) = mpsc::channel(1);
    let svc = RibService::new(tx);
    let task = tokio::spawn(async move {
        let Some(RibUpdate::QueryLabeledRoutesPage {
            scope,
            filter,
            page_size,
            after,
            expected_version,
            reply,
        }) = rx.recv().await
        else {
            panic!("expected Labeled page");
        };
        assert_eq!(scope, RouteQueryScope::Advertised { peer: destination });
        assert_eq!(page_size, 1);
        assert!(after.is_none());
        assert!(expected_version.is_none());
        assert!(
            filter.as_ref().unwrap()(&route),
            "advertised destination must not filter source rows"
        );
        let mut wrong = route.clone();
        wrong.nlri.prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:201::".parse().unwrap(), 64));
        assert!(!filter.unwrap()(&wrong));
        reply
            .send(Ok(rustbgpd_rib::RibRowsPage {
                routes: vec![route],
                total: 2,
                has_more: true,
                version: RoutePageVersion {
                    epoch: 1,
                    generation: 2,
                },
            }))
            .unwrap();
        let Some(RibUpdate::QueryLabeledRoutesPage {
            after,
            expected_version,
            reply,
            ..
        }) = rx.recv().await
        else {
            panic!("expected continuation");
        };
        assert!(after.is_some());
        assert_eq!(expected_version.unwrap().generation, 2);
        reply.send(Err(RoutePageError::Invalidated)).unwrap();
    });
    let request = proto::ListLabeledRoutesPageRequest {
        view: proto::FamilyRouteView::Advertised as i32,
        peer_filter: destination.to_string(),
        page_size: 1,
        afi_safi: "ipv6_labeled_unicast".into(),
        prefix_filter: "2001:db8:200::/64".into(),
        ..Default::default()
    };
    let response = svc
        .list_labeled_routes_page(Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.routes[0].peer_address, peer.to_string());
    assert_eq!(response.total_count, 2);
    let mut continuation = request.clone();
    continuation.page_token = response.next_page_token.clone();
    assert_eq!(
        svc.list_labeled_routes_page(Request::new(continuation.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    continuation.peer_filter = peer.to_string();
    assert_eq!(
        svc.list_labeled_routes_page(Request::new(continuation))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    for bad in [
        proto::ListLabeledRoutesPageRequest {
            view: 99,
            ..request.clone()
        },
        proto::ListLabeledRoutesPageRequest {
            peer_filter: String::new(),
            ..request.clone()
        },
        proto::ListLabeledRoutesPageRequest {
            page_size: 1001,
            ..request.clone()
        },
        proto::ListLabeledRoutesPageRequest {
            afi_safi: "ipv4_unicast".into(),
            ..request.clone()
        },
        proto::ListLabeledRoutesPageRequest {
            page_token: "malformed".into(),
            ..request.clone()
        },
    ] {
        assert_eq!(
            svc.list_labeled_routes_page(Request::new(bad))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    task.await.unwrap();
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one typed route fixture follows filter validation, page response and invalidated continuation"
)]
async fn rtc_family_page_response_filters_and_invalidation() {
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let destination: IpAddr = "192.0.2.2".parse().unwrap();
    let (_, _, _, _, route) = non_unicast_routes(peer);
    let (tx, mut rx) = mpsc::channel(1);
    let svc = RibService::new(tx);
    let task = tokio::spawn(async move {
        let Some(RibUpdate::QueryRtcRoutesPage {
            scope,
            filter,
            page_size,
            after,
            expected_version,
            reply,
        }) = rx.recv().await
        else {
            panic!("expected Rtc page");
        };
        assert_eq!(scope, RouteQueryScope::Advertised { peer: destination });
        assert_eq!(page_size, 1);
        assert!(after.is_none());
        assert!(expected_version.is_none());
        assert!(
            filter.as_ref().unwrap()(&route),
            "advertised destination must not filter source rows"
        );
        let mut wrong = route.clone();
        wrong.nlri.origin_as = 65001;
        assert!(!filter.unwrap()(&wrong));
        reply
            .send(Ok(rustbgpd_rib::RibRowsPage {
                routes: vec![route],
                total: 2,
                has_more: true,
                version: RoutePageVersion {
                    epoch: 1,
                    generation: 2,
                },
            }))
            .unwrap();
        let Some(RibUpdate::QueryRtcRoutesPage {
            after,
            expected_version,
            reply,
            ..
        }) = rx.recv().await
        else {
            panic!("expected continuation");
        };
        assert!(after.is_some());
        assert_eq!(expected_version.unwrap().generation, 2);
        reply.send(Err(RoutePageError::Invalidated)).unwrap();
    });
    let request = proto::ListRtcRoutesPageRequest {
        view: proto::FamilyRouteView::Advertised as i32,
        peer_filter: destination.to_string(),
        page_size: 1,
        origin_as_filter: Some(0),
        ..Default::default()
    };
    let response = svc
        .list_rtc_routes_page(Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.routes[0].peer_address, peer.to_string());
    assert_eq!(response.total_count, 2);
    let mut continuation = request.clone();
    continuation.page_token = response.next_page_token.clone();
    assert_eq!(
        svc.list_rtc_routes_page(Request::new(continuation.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    continuation.peer_filter = peer.to_string();
    assert_eq!(
        svc.list_rtc_routes_page(Request::new(continuation))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    for bad in [
        proto::ListRtcRoutesPageRequest {
            view: 99,
            ..request.clone()
        },
        proto::ListRtcRoutesPageRequest {
            peer_filter: String::new(),
            ..request.clone()
        },
        proto::ListRtcRoutesPageRequest {
            page_size: 1001,
            ..request.clone()
        },
    ] {
        assert_eq!(
            svc.list_rtc_routes_page(Request::new(bad))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    task.await.unwrap();
}

#[tokio::test]
async fn grouped_vpn_resync_refusal_is_failed_precondition() {
    let (tx, mut rx) = mpsc::channel(1);
    let svc = RibService::new(tx);
    let actor = tokio::spawn(async move {
        let Some(RibUpdate::QueryVpnRoutesPage { reply, .. }) = rx.recv().await else {
            panic!("expected VPN page");
        };
        reply.send(Err(RoutePageError::ResyncInProgress)).unwrap();
    });
    let error = svc
        .list_vpn_routes_page(Request::new(proto::ListVpnRoutesPageRequest {
            view: proto::FamilyRouteView::Advertised as i32,
            peer_filter: "192.0.2.1".into(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);
    assert_eq!(
        error.message(),
        "advertised VPN state is resynchronizing; retry after export settles"
    );
    actor.await.unwrap();
}
