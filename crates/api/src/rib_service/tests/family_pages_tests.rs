use super::*;

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one table sends every page size through all nine bounded family paths"
)]
async fn family_and_evpn_page_sizes_default_and_clamp_before_actor_dispatch() {
    let (tx, mut rx) = mpsc::channel(1);
    let service = RibService::new(tx);
    let actor = tokio::spawn(async move {
        for expected in [100, 1, 1000, 1000, 1000] {
            for _ in 0..9 {
                match rx.recv().await.unwrap() {
                    RibUpdate::QueryVpnRoutesPage {
                        page_size, reply, ..
                    } => {
                        assert_eq!(page_size, expected);
                        reply.send(Err(RoutePageError::Invalidated)).unwrap();
                    }
                    RibUpdate::QueryLabeledRoutesPage {
                        page_size, reply, ..
                    } => {
                        assert_eq!(page_size, expected);
                        reply.send(Err(RoutePageError::Invalidated)).unwrap();
                    }
                    RibUpdate::QueryRtcRoutesPage {
                        page_size, reply, ..
                    } => {
                        assert_eq!(page_size, expected);
                        reply.send(Err(RoutePageError::Invalidated)).unwrap();
                    }
                    RibUpdate::QueryEvpnRoutesPage {
                        page_size, reply, ..
                    } => {
                        assert_eq!(page_size, expected);
                        reply.send(Err(RoutePageError::Invalidated)).unwrap();
                    }
                    RibUpdate::QueryBgpLsRoutesPage {
                        page_size, reply, ..
                    } => {
                        assert_eq!(page_size, expected);
                        reply.send(Err(RoutePageError::Invalidated)).unwrap();
                    }
                    RibUpdate::QueryOrrTopologyNodesPage {
                        page_size, reply, ..
                    } => {
                        assert_eq!(page_size, expected);
                        reply.send(Err(RoutePageError::Invalidated)).unwrap();
                    }
                    RibUpdate::QueryOrrTopologyLinksPage {
                        page_size, reply, ..
                    } => {
                        assert_eq!(page_size, expected);
                        reply.send(Err(RoutePageError::Invalidated)).unwrap();
                    }
                    _ => panic!("expected bounded family page"),
                }
            }
        }
    });
    for page_size in [0, 1, 1000, 1001, u32::MAX] {
        for method in 0..9 {
            let view = proto::FamilyRouteView::Best as i32;
            let result = match method {
                0 => service
                    .list_vpn_rib_routes(Request::new(proto::ListVpnRibRoutesRequest {
                        view,
                        page_size,
                        ..Default::default()
                    }))
                    .await
                    .map(|_| ()),
                1 => service
                    .list_labeled_rib_routes(Request::new(proto::ListLabeledRibRoutesRequest {
                        view,
                        page_size,
                        ..Default::default()
                    }))
                    .await
                    .map(|_| ()),
                2 => service
                    .list_rtc_rib_routes(Request::new(proto::ListRtcRibRoutesRequest {
                        view,
                        page_size,
                        ..Default::default()
                    }))
                    .await
                    .map(|_| ()),
                3 => service
                    .list_best_evpn_routes(Request::new(proto::ListBestEvpnRoutesRequest {
                        page_size,
                        ..Default::default()
                    }))
                    .await
                    .map(|_| ()),
                6 => service
                    .list_bgp_ls_rib_routes(Request::new(proto::ListBgpLsRibRoutesRequest {
                        view,
                        page_size,
                        ..Default::default()
                    }))
                    .await
                    .map(|_| ()),
                7 => service
                    .list_orr_topology_nodes(Request::new(proto::ListOrrTopologyNodesRequest {
                        page_size,
                        ..Default::default()
                    }))
                    .await
                    .map(|_| ()),
                8 => service
                    .list_orr_topology_links(Request::new(proto::ListOrrTopologyLinksRequest {
                        page_size,
                        ..Default::default()
                    }))
                    .await
                    .map(|_| ()),
                _ => {
                    let request = Request::new(proto::ListPeerEvpnRoutesRequest {
                        neighbor_address: "192.0.2.1".into(),
                        page_size,
                        ..Default::default()
                    });
                    if method == 4 {
                        service.list_received_evpn_routes(request).await
                    } else {
                        service.list_advertised_evpn_routes(request).await
                    }
                    .map(|_| ())
                }
            };
            assert_eq!(
                result.unwrap_err().code(),
                tonic::Code::Aborted,
                "method {method}, page_size {page_size} must reach the actor"
            );
        }
    }
    actor.await.unwrap();
}

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
    let (size, after, expected) =
        family_page_params(u32::MAX, &token, scope, &identity, parse_vpn_page_key).unwrap();
    assert_eq!(size, 1000);
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
    assert!(decode_family_page_token(&altered, FAMILY_PAGE_TOKEN_MAX_LEN).is_err());
    assert!(decode_family_page_token(&"x".repeat(1025), FAMILY_PAGE_TOKEN_MAX_LEN).is_err());
    assert!(parse_family_prefix("10.0.0.1/24", 24).is_err());
    assert!(parse_family_prefix("2001:db8::1/64", 64).is_err());
    assert!(parse_vpn_page_key("0000fde800000001~10.0.0.1/24~192.0.2.1~7").is_err());
    assert!(parse_labeled_page_key("2001:db8::1/64~192.0.2.1~7").is_err());
    assert!(family_page_scope(0, "192.0.2.1", "").is_err());
    assert!(family_page_scope(2, "", "").is_err());
    assert!(family_page_scope(3, "invalid", "").is_err());
}

#[tokio::test]
async fn family_rpc_views_and_selectors_reject_before_actor_dispatch() {
    let (tx, mut rx) = mpsc::channel(8);
    let service = RibService::new(tx);
    let best = proto::FamilyRouteView::Best as i32;
    let received = proto::FamilyRouteView::Received as i32;
    let advertised = proto::FamilyRouteView::Advertised as i32;
    for (view, neighbor, source) in [
        (0, "", ""),
        (99, "", ""),
        (best, "192.0.2.1", ""),
        (received, "", ""),
        (advertised, "", ""),
        (received, "192.0.2.1", "192.0.2.2"),
        (advertised, "192.0.2.1", "192.0.2.2"),
        (best, "", "invalid"),
    ] {
        for family in 0..3 {
            let result = match family {
                0 => service
                    .list_vpn_rib_routes(Request::new(proto::ListVpnRibRoutesRequest {
                        view,
                        neighbor_address: neighbor.into(),
                        source_peer_filter: source.into(),
                        ..Default::default()
                    }))
                    .await
                    .map(|_| ()),
                1 => service
                    .list_labeled_rib_routes(Request::new(proto::ListLabeledRibRoutesRequest {
                        view,
                        neighbor_address: neighbor.into(),
                        source_peer_filter: source.into(),
                        ..Default::default()
                    }))
                    .await
                    .map(|_| ()),
                _ => service
                    .list_rtc_rib_routes(Request::new(proto::ListRtcRibRoutesRequest {
                        view,
                        neighbor_address: neighbor.into(),
                        source_peer_filter: source.into(),
                        ..Default::default()
                    }))
                    .await
                    .map(|_| ()),
            };
            assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
        }
    }
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn family_rpc_typed_families_and_prefix_boundaries_reject_before_dispatch() {
    let (tx, mut rx) = mpsc::channel(8);
    let service = RibService::new(tx);
    let view = proto::FamilyRouteView::Best as i32;
    for afi_safi in [proto::AddressFamily::Ipv4Unicast as i32, i32::MAX] {
        let vpn = service
            .list_vpn_rib_routes(Request::new(proto::ListVpnRibRoutesRequest {
                view,
                afi_safi,
                ..Default::default()
            }))
            .await;
        let labeled = service
            .list_labeled_rib_routes(Request::new(proto::ListLabeledRibRoutesRequest {
                view,
                afi_safi,
                ..Default::default()
            }))
            .await;
        let rtc = service
            .list_rtc_rib_routes(Request::new(proto::ListRtcRibRoutesRequest {
                view,
                afi_safi,
                ..Default::default()
            }))
            .await;
        assert_eq!(vpn.unwrap_err().code(), tonic::Code::InvalidArgument);
        assert_eq!(labeled.unwrap_err().code(), tonic::Code::InvalidArgument);
        assert_eq!(rtc.unwrap_err().code(), tonic::Code::InvalidArgument);
    }
    for (prefix, length) in [
        ("", 1),
        ("10.0.0.0/24", 24),
        ("10.0.0.0", 33),
        ("2001:db8::", 129),
    ] {
        let vpn = service
            .list_vpn_rib_routes(Request::new(proto::ListVpnRibRoutesRequest {
                view,
                prefix_filter: prefix.into(),
                prefix_filter_length: length,
                ..Default::default()
            }))
            .await;
        let labeled = service
            .list_labeled_rib_routes(Request::new(proto::ListLabeledRibRoutesRequest {
                view,
                prefix_filter: prefix.into(),
                prefix_filter_length: length,
                ..Default::default()
            }))
            .await;
        assert_eq!(vpn.unwrap_err().code(), tonic::Code::InvalidArgument);
        assert_eq!(labeled.unwrap_err().code(), tonic::Code::InvalidArgument);
    }
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one real actor fixture checks exact and longer-prefix continuations for both typed family requests"
)]
async fn typed_family_prefix_pages_match_exact_and_longer_routes_in_the_real_rib() {
    let source: IpAddr = "192.0.2.1".parse().unwrap();
    let (_, _, vpn, labeled, _) = non_unicast_routes(source);
    let mut vpn_longer = vpn.clone();
    vpn_longer.nlri.prefix =
        rustbgpd_wire::VpnPrefix::v6("2001:db8:100:0:1::".parse().unwrap(), 80).unwrap();
    let mut labeled_longer = labeled.clone();
    labeled_longer.nlri.prefix = Prefix::V6(rustbgpd_wire::Ipv6Prefix::new(
        "2001:db8:200:0:1::".parse().unwrap(),
        80,
    ));
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
        peer: source,
        session_id: 0,
        announced: vec![vpn, vpn_longer],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    tx.send(RibUpdate::LabeledRoutesReceived {
        peer: source,
        session_id: 0,
        announced: vec![labeled, labeled_longer],
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let service = RibService::new(tx.clone());
    let vpn_request = proto::ListVpnRibRoutesRequest {
        view: proto::FamilyRouteView::Best as i32,
        source_peer_filter: source.to_string(),
        afi_safi: proto::AddressFamily::L3vpnIpv6Unicast as i32,
        prefix_filter: "2001:db8:100::".into(),
        prefix_filter_length: 64,
        page_size: 1,
        ..Default::default()
    };
    let exact = service
        .list_vpn_rib_routes(Request::new(vpn_request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(exact.total_count, 1);
    assert_eq!(exact.routes[0].prefix, "2001:db8:100::/64");
    let mut longer_request = vpn_request.clone();
    longer_request.longer_prefixes = true;
    let longer = service
        .list_vpn_rib_routes(Request::new(longer_request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(longer.total_count, 2);
    assert_eq!(longer.routes.len(), 1);
    assert_ne!(longer.next_page_token, "");
    let mut continuation = longer_request.clone();
    continuation.page_token = longer.next_page_token.clone();
    let final_page = service
        .list_vpn_rib_routes(Request::new(continuation))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(final_page.routes.len(), 1);
    assert_ne!(final_page.routes[0].prefix, longer.routes[0].prefix);
    assert_eq!(final_page.next_page_token, "");
    longer_request.longer_prefixes = false;
    longer_request.page_token = longer.next_page_token;
    assert_eq!(
        service
            .list_vpn_rib_routes(Request::new(longer_request))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    let labeled_request = proto::ListLabeledRibRoutesRequest {
        view: proto::FamilyRouteView::Best as i32,
        source_peer_filter: source.to_string(),
        afi_safi: proto::AddressFamily::Ipv6LabeledUnicast as i32,
        prefix_filter: "2001:db8:200::".into(),
        prefix_filter_length: 64,
        page_size: 1,
        ..Default::default()
    };
    let exact = service
        .list_labeled_rib_routes(Request::new(labeled_request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(exact.total_count, 1);
    assert_eq!(exact.routes[0].prefix, "2001:db8:200::/64");
    let mut longer_request = labeled_request.clone();
    longer_request.longer_prefixes = true;
    let longer = service
        .list_labeled_rib_routes(Request::new(longer_request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(longer.total_count, 2);
    assert_eq!(longer.routes.len(), 1);
    assert_ne!(longer.next_page_token, "");
    let mut continuation = longer_request.clone();
    continuation.page_token = longer.next_page_token.clone();
    let final_page = service
        .list_labeled_rib_routes(Request::new(continuation))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(final_page.routes.len(), 1);
    assert_ne!(final_page.routes[0].prefix, longer.routes[0].prefix);
    assert_eq!(final_page.next_page_token, "");
    longer_request.longer_prefixes = false;
    longer_request.page_token = longer.next_page_token;
    assert_eq!(
        service
            .list_labeled_rib_routes(Request::new(longer_request))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    let unknown_source = proto::ListVpnRibRoutesRequest {
        source_peer_filter: "192.0.2.99".into(),
        ..vpn_request
    };
    assert_eq!(
        service
            .list_vpn_rib_routes(Request::new(unknown_source))
            .await
            .unwrap()
            .into_inner()
            .total_count,
        0
    );
    drop(service);
    drop(tx);
    drop(query_tx);
    actor.await.unwrap();
}

#[tokio::test]
async fn evpn_peer_filter_acknowledgement_preserves_unfiltered_calls() {
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let (route, ..) = non_unicast_routes(peer);
    let (tx, mut rx) = mpsc::channel(8);
    let service = RibService::new(tx);
    let actor = tokio::spawn(async move {
        for _ in 0..8 {
            let Some(RibUpdate::QueryEvpnRoutesPage { reply, .. }) = rx.recv().await else {
                panic!("expected EVPN page");
            };
            reply
                .send(Ok(rustbgpd_rib::EvpnRoutePage {
                    routes: vec![route.clone()],
                    total: 1,
                    has_more: false,
                    version: RoutePageVersion {
                        epoch: 1,
                        generation: 2,
                    },
                }))
                .unwrap();
        }
    });
    for advertised in [false, true] {
        for (mac, esi, vni, expected) in [
            ("", "", None, None),
            ("00:11:22:33:44:55", "", None, Some("mac,esi,vni")),
            (
                "",
                "00:01:02:03:04:05:06:07:08:09",
                None,
                Some("mac,esi,vni"),
            ),
            ("", "", Some(0), Some("mac,esi,vni")),
        ] {
            let request = Request::new(proto::ListPeerEvpnRoutesRequest {
                neighbor_address: if advertised {
                    "192.0.2.2".into()
                } else {
                    peer.to_string()
                },
                mac_filter: mac.into(),
                esi_filter: esi.into(),
                vni_filter: vni,
                ..Default::default()
            });
            let response = if advertised {
                service.list_advertised_evpn_routes(request).await
            } else {
                service.list_received_evpn_routes(request).await
            }
            .unwrap();
            assert_eq!(
                response
                    .metadata()
                    .get("x-rustbgpd-evpn-peer-filters")
                    .map(|v| v.to_str().unwrap()),
                expected
            );
            assert_eq!(response.into_inner().total_count, 1);
        }
    }
    actor.await.unwrap();
}

#[tokio::test]
async fn evpn_peer_raw_rd_filter_changes_reject_foreign_continuation() {
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let (route, ..) = non_unicast_routes(peer);
    let raw_type0 = "0x0000fde800000064";
    let raw_type2 = "0x00020000fde80064";
    let type0 = parse_family_rd(raw_type0).unwrap().unwrap();
    let type2 = parse_family_rd(raw_type2).unwrap().unwrap();
    assert_eq!(type0.to_string(), type2.to_string());
    assert_ne!(type0, type2);
    let (filter0, identity0) = peer_evpn_filter(3, raw_type0, "", "", None).unwrap();
    let (filter2, identity2) = peer_evpn_filter(3, raw_type2, "", "", None).unwrap();
    assert!(filter0.unwrap()(&route));
    assert!(!filter2.unwrap()(&route));
    assert_ne!(identity0, identity2);
    let (tx, mut rx) = mpsc::channel(1);
    let service = RibService::new(tx);
    for advertised in [false, true] {
        let scope = if advertised {
            RouteQueryScope::Advertised { peer }
        } else {
            RouteQueryScope::Received { peer: Some(peer) }
        };
        let token = encode_evpn_page_token(
            scope,
            &identity0,
            &route,
            RoutePageVersion {
                epoch: 1,
                generation: 2,
            },
        )
        .unwrap();
        let request = proto::ListPeerEvpnRoutesRequest {
            neighbor_address: peer.to_string(),
            rd_filter: raw_type0.into(),
            route_type_filter: 3,
            page_token: token,
            ..Default::default()
        };
        for changed in [
            proto::ListPeerEvpnRoutesRequest {
                rd_filter: raw_type2.into(),
                ..request.clone()
            },
            proto::ListPeerEvpnRoutesRequest {
                mac_filter: "00:01:02:03:04:05".into(),
                ..request.clone()
            },
            proto::ListPeerEvpnRoutesRequest {
                esi_filter: "00:01:02:03:04:05:06:07:08:09".into(),
                ..request.clone()
            },
            proto::ListPeerEvpnRoutesRequest {
                vni_filter: Some(100),
                ..request.clone()
            },
        ] {
            let result = if advertised {
                service
                    .list_advertised_evpn_routes(Request::new(changed))
                    .await
            } else {
                service
                    .list_received_evpn_routes(Request::new(changed))
                    .await
            };
            assert_eq!(result.unwrap_err().code(), tonic::Code::InvalidArgument);
        }
    }
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "the actor and API checks keep combined filter negatives and source identity visible for both peer directions"
)]
async fn evpn_peer_pages_apply_mac_esi_vni_filters_and_preserve_source() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, ExtendedCommunity, MacAddress,
        MplsLabel,
    };
    let source: IpAddr = "192.0.2.1".parse().unwrap();
    let destination: IpAddr = "192.0.2.2".parse().unwrap();
    let (mut route, ..) = non_unicast_routes(source);
    let mac = MacAddress([0, 1, 2, 3, 4, 5]);
    let esi = EthernetSegmentIdentifier([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    route.route = EvpnRoute::MacIp(EvpnMacIp {
        rd: parse_family_rd("0x00020000fde80064").unwrap().unwrap(),
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
    let (tx, mut rx) = mpsc::channel(8);
    let service = RibService::new(tx);
    let actor = tokio::spawn(async move {
        for scope_expected in [
            RouteQueryScope::Received { peer: Some(source) },
            RouteQueryScope::Advertised { peer: destination },
        ] {
            let Some(RibUpdate::QueryEvpnRoutesPage {
                scope,
                filter,
                reply,
                ..
            }) = rx.recv().await
            else {
                panic!("expected peer EVPN page");
            };
            assert_eq!(scope, scope_expected);
            let filter = filter.unwrap();
            assert!(filter(&route));
            let mut wrong = route.clone();
            let EvpnRoute::MacIp(mac_ip) = &mut wrong.route else {
                unreachable!()
            };
            mac_ip.mac.0[5] = 6;
            assert!(!filter(&wrong));
            let mut wrong = route.clone();
            let EvpnRoute::MacIp(mac_ip) = &mut wrong.route else {
                unreachable!()
            };
            mac_ip.esi.0[9] = 10;
            assert!(!filter(&wrong));
            let mut wrong = route.clone();
            wrong.attributes = AttrSet::new(Vec::new());
            assert!(!filter(&wrong), "a raw MPLS label is not a VXLAN VNI");
            reply
                .send(Ok(rustbgpd_rib::EvpnRoutePage {
                    routes: vec![route.clone()],
                    total: 1,
                    has_more: false,
                    version: RoutePageVersion {
                        epoch: 1,
                        generation: 2,
                    },
                }))
                .unwrap();
        }
    });
    for advertised in [false, true] {
        let neighbor = if advertised { destination } else { source };
        let request = proto::ListPeerEvpnRoutesRequest {
            neighbor_address: neighbor.to_string(),
            route_type_filter: 2,
            rd_filter: "0x00020000fde80064".into(),
            mac_filter: mac.to_string(),
            esi_filter: esi.to_string(),
            vni_filter: Some(202),
            ..Default::default()
        };
        for bad in [
            proto::ListPeerEvpnRoutesRequest {
                mac_filter: "bad".into(),
                ..request.clone()
            },
            proto::ListPeerEvpnRoutesRequest {
                esi_filter: "bad".into(),
                ..request.clone()
            },
            proto::ListPeerEvpnRoutesRequest {
                vni_filter: Some(1 << 24),
                ..request.clone()
            },
        ] {
            let error = if advertised {
                service.list_advertised_evpn_routes(Request::new(bad)).await
            } else {
                service.list_received_evpn_routes(Request::new(bad)).await
            }
            .unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument);
        }
        let response = if advertised {
            service
                .list_advertised_evpn_routes(Request::new(request))
                .await
        } else {
            service
                .list_received_evpn_routes(Request::new(request))
                .await
        }
        .unwrap()
        .into_inner();
        assert_eq!(response.total_count, 1);
        assert_eq!(response.routes[0].peer_address, source.to_string());
        assert_eq!(response.next_page_token, "");
    }
    actor.await.unwrap();
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
    let request = proto::ListVpnRibRoutesRequest {
        view: proto::FamilyRouteView::Received as i32,
        neighbor_address: peer.to_string(),
        page_size: 1,
        ..Default::default()
    };
    let page = svc
        .list_vpn_rib_routes(Request::new(request.clone()))
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
        .list_vpn_rib_routes(Request::new(continuation))
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
            .list_vpn_rib_routes(Request::new(filtered))
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
    let request = proto::ListBestEvpnRoutesRequest {
        rd_filter: raw.into(),
        ..Default::default()
    };
    let (filter, raw_identity) = evpn_loc_filter(&request).unwrap();
    assert!(filter.unwrap()(&route));
    let (_, text_identity) = evpn_loc_filter(&proto::ListBestEvpnRoutesRequest {
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
        svc.list_best_evpn_routes(Request::new(proto::ListBestEvpnRoutesRequest {
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
        .list_rtc_rib_routes(Request::new(proto::ListRtcRibRoutesRequest {
            view: proto::FamilyRouteView::Received as i32,
            neighbor_address: peer.to_string(),
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
    let req = proto::ListBestEvpnRoutesRequest {
        route_type_filter: 2,
        source_peer_filter: source.to_string(),
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
        proto::ListBestEvpnRoutesRequest {
            vni_filter: Some(999),
            ..req.clone()
        },
        proto::ListBestEvpnRoutesRequest {
            mac_filter: "00:01:02:03:04:06".into(),
            ..req.clone()
        },
        proto::ListBestEvpnRoutesRequest {
            esi_filter: "00:01:02:03:04:05:06:07:08:0a".into(),
            ..req.clone()
        },
        proto::ListBestEvpnRoutesRequest {
            route_type_filter: 3,
            ..req.clone()
        },
    ] {
        assert!(!evpn_loc_filter(&changed).unwrap().0.unwrap()(&route));
    }
    assert!(
        evpn_loc_filter(&proto::ListBestEvpnRoutesRequest {
            mac_filter: "bad".into(),
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        evpn_loc_filter(&proto::ListBestEvpnRoutesRequest {
            esi_filter: "bad".into(),
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        evpn_loc_filter(&proto::ListBestEvpnRoutesRequest {
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
        .list_best_evpn_routes(Request::new(req))
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
    let request = proto::ListVpnRibRoutesRequest {
        view: proto::FamilyRouteView::Advertised as i32,
        neighbor_address: destination.to_string(),
        page_size: 1,
        afi_safi: proto::AddressFamily::L3vpnIpv6Unicast as i32,
        prefix_filter: "2001:db8:100::".into(),
        prefix_filter_length: 64,
        rd_filter: "65000:100".into(),
        ..Default::default()
    };
    let response = svc
        .list_vpn_rib_routes(Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.routes[0].peer_address, peer.to_string());
    assert_eq!(response.total_count, 2);
    let mut continuation = request.clone();
    continuation.page_token = response.next_page_token.clone();
    assert_eq!(
        svc.list_vpn_rib_routes(Request::new(continuation.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    continuation.neighbor_address = peer.to_string();
    assert_eq!(
        svc.list_vpn_rib_routes(Request::new(continuation))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    for bad in [
        proto::ListVpnRibRoutesRequest {
            view: 99,
            ..request.clone()
        },
        proto::ListVpnRibRoutesRequest {
            neighbor_address: String::new(),
            ..request.clone()
        },
        proto::ListVpnRibRoutesRequest {
            afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            ..request.clone()
        },
        proto::ListVpnRibRoutesRequest {
            page_token: "malformed".into(),
            ..request.clone()
        },
    ] {
        assert_eq!(
            svc.list_vpn_rib_routes(Request::new(bad))
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
    let request = proto::ListLabeledRibRoutesRequest {
        view: proto::FamilyRouteView::Advertised as i32,
        neighbor_address: destination.to_string(),
        page_size: 1,
        afi_safi: proto::AddressFamily::Ipv6LabeledUnicast as i32,
        prefix_filter: "2001:db8:200::".into(),
        prefix_filter_length: 64,
        ..Default::default()
    };
    let response = svc
        .list_labeled_rib_routes(Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.routes[0].peer_address, peer.to_string());
    assert_eq!(response.total_count, 2);
    let mut continuation = request.clone();
    continuation.page_token = response.next_page_token.clone();
    assert_eq!(
        svc.list_labeled_rib_routes(Request::new(continuation.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    continuation.neighbor_address = peer.to_string();
    assert_eq!(
        svc.list_labeled_rib_routes(Request::new(continuation))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    for bad in [
        proto::ListLabeledRibRoutesRequest {
            view: 99,
            ..request.clone()
        },
        proto::ListLabeledRibRoutesRequest {
            neighbor_address: String::new(),
            ..request.clone()
        },
        proto::ListLabeledRibRoutesRequest {
            afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            ..request.clone()
        },
        proto::ListLabeledRibRoutesRequest {
            page_token: "malformed".into(),
            ..request.clone()
        },
    ] {
        assert_eq!(
            svc.list_labeled_rib_routes(Request::new(bad))
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
    let request = proto::ListRtcRibRoutesRequest {
        view: proto::FamilyRouteView::Advertised as i32,
        neighbor_address: destination.to_string(),
        page_size: 1,
        origin_as_filter: Some(0),
        ..Default::default()
    };
    let response = svc
        .list_rtc_rib_routes(Request::new(request.clone()))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(response.routes[0].peer_address, peer.to_string());
    assert_eq!(response.total_count, 2);
    let mut continuation = request.clone();
    continuation.page_token = response.next_page_token.clone();
    assert_eq!(
        svc.list_rtc_rib_routes(Request::new(continuation.clone()))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::Aborted
    );
    continuation.neighbor_address = peer.to_string();
    assert_eq!(
        svc.list_rtc_rib_routes(Request::new(continuation))
            .await
            .unwrap_err()
            .code(),
        tonic::Code::InvalidArgument
    );
    for bad in [
        proto::ListRtcRibRoutesRequest {
            view: 99,
            ..request.clone()
        },
        proto::ListRtcRibRoutesRequest {
            neighbor_address: String::new(),
            ..request.clone()
        },
    ] {
        assert_eq!(
            svc.list_rtc_rib_routes(Request::new(bad))
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
        .list_vpn_rib_routes(Request::new(proto::ListVpnRibRoutesRequest {
            view: proto::FamilyRouteView::Advertised as i32,
            neighbor_address: "192.0.2.1".into(),
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

fn bgpls_route_with_payload(peer: IpAddr, nlri_type: u16, payload: Vec<u8>) -> BgpLsRibRoute {
    let mut route = bgpls_test_routes(peer).remove(0);
    route.nlri = rustbgpd_wire::bgpls::BgpLsNlri {
        nlri_type: rustbgpd_wire::bgpls::BgpLsNlriType::from_u16(nlri_type),
        route_distinguisher: None,
        payload: payload.into(),
    };
    route
}

/// A real actor walk returns every selected BGP-LS row exactly once, in
/// identity order, through continuation tokens; a cursor carrying a
/// maximum-length opaque NLRI still continues.
#[tokio::test]
async fn bgpls_pages_walk_every_route_once_through_the_real_rib() {
    let first: IpAddr = "192.0.2.1".parse().unwrap();
    let second: IpAddr = "192.0.2.2".parse().unwrap();
    let mut routes = bgpls_test_routes(first);
    // Seven short rows put the maximum-length NLRI at the third page tail.
    for index in 0..7u8 {
        routes.push(bgpls_route_with_payload(first, 0xfde9, vec![index; 3]));
    }
    routes.push(bgpls_route_with_payload(
        first,
        0xfdea,
        vec![0x5a; usize::from(u16::MAX)],
    ));
    routes.push(bgpls_route_with_payload(first, 0xfdeb, vec![1]));
    let foreign = bgpls_route_with_payload(second, 0xfdec, vec![2]);
    let (tx, rx) = mpsc::channel(8);
    let (_query_tx, query_rx) = mpsc::channel(1);
    let manager = rustbgpd_rib::RibManager::new(
        rx,
        query_rx,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    );
    let actor = tokio::spawn(manager.run());
    for (peer, announced) in [(first, routes), (second, vec![foreign])] {
        tx.send(RibUpdate::BgpLsRoutesReceived {
            peer,
            session_id: 0,
            announced,
            withdrawn: vec![],
        })
        .await
        .unwrap();
    }
    let service = RibService::new(tx.clone());
    let request = proto::ListBgpLsRibRoutesRequest {
        view: proto::FamilyRouteView::Best as i32,
        source_peer_filter: first.to_string(),
        page_size: 3,
        ..Default::default()
    };
    let mut walked = Vec::new();
    let mut next = request.clone();
    loop {
        let page = service
            .list_bgp_ls_rib_routes(Request::new(next.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.total_count, 11);
        assert!(page.routes.len() <= 3);
        walked.extend(page.routes.into_iter().map(|route| {
            assert_eq!(route.peer_address, first.to_string());
            (
                route.afi_safi,
                route.nlri_type,
                route.route_distinguisher,
                route.payload,
            )
        }));
        if page.next_page_token.is_empty() {
            break;
        }
        next.page_token = page.next_page_token;
    }
    assert_eq!(walked.len(), 11);
    let mut sorted = walked.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(walked, sorted, "rows must be unique and in identity order");
    assert_eq!(walked[10].0, proto::AddressFamily::BgpLsVpn as i32);
    assert_eq!(walked[8].3.len(), usize::from(u16::MAX));

    let vpn_only = service
        .list_bgp_ls_rib_routes(Request::new(proto::ListBgpLsRibRoutesRequest {
            afi_safi: proto::AddressFamily::BgpLsVpn as i32,
            nlri_type_filter: 0xfde8,
            ..request.clone()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(vpn_only.total_count, 1);
    assert_eq!(vpn_only.next_page_token, "");
    let received = service
        .list_bgp_ls_rib_routes(Request::new(proto::ListBgpLsRibRoutesRequest {
            view: proto::FamilyRouteView::Received as i32,
            neighbor_address: second.to_string(),
            ..Default::default()
        }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(received.total_count, 1);
    assert_eq!(received.routes[0].peer_address, second.to_string());
    drop((service, tx));
    actor.await.unwrap();
}

/// Altered, foreign, oversized and malformed BGP-LS tokens are rejected
/// before they reach the RIB actor.
#[tokio::test]
async fn bgpls_page_tokens_reject_forgery_and_foreign_queries() {
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let route = bgpls_test_routes(peer).remove(1);
    let scope = RouteQueryScope::Best;
    let identity = family_query_identity("bgpls", "None:None:0");
    let key = encode_bgpls_page_key(&route);
    let token = encode_family_page_token(
        scope,
        &identity,
        &key,
        RoutePageVersion {
            epoch: 1,
            generation: 2,
        },
    );
    let (size, after, version) = family_page_params_within(
        u32::MAX,
        &token,
        scope,
        &identity,
        BGPLS_PAGE_TOKEN_MAX_LEN,
        parse_bgpls_page_key,
    )
    .unwrap();
    assert_eq!(size, 1000);
    assert_eq!(version.unwrap().generation, 2);
    let after = after.unwrap();
    assert_eq!(after.0, BgpLsFamily::LinkStateVpn);
    assert_eq!(after.2, route.nlri.route_distinguisher);
    assert_eq!(after.3, route.nlri.payload);
    for bad in [
        "linkstate~fde8~-~aabbcc~192.0.2.1",
        "linkstate~fde8~0000fde800000064~aabbcc~192.0.2.1~0",
        "linkstate_vpn~fde8~-~aabbcc~192.0.2.1~0",
        "linkstate~fde8~-~aabbc~192.0.2.1~0",
        "linkstate~fde~-~aabbcc~192.0.2.1~0",
        "other~fde8~-~aabbcc~192.0.2.1~0",
    ] {
        assert!(parse_bgpls_page_key(bad).is_err(), "{bad}");
    }

    let (tx, mut rx) = mpsc::channel(1);
    let service = RibService::new(tx);
    let request = proto::ListBgpLsRibRoutesRequest {
        view: proto::FamilyRouteView::Best as i32,
        page_token: token.clone(),
        ..Default::default()
    };
    let foreign = encode_family_page_token(
        scope,
        &family_query_identity("vpn", "None:None:0"),
        &key,
        RoutePageVersion::default(),
    );
    for bad in [
        token.replacen("aabbcc", "aabbcd", 1),
        format!("{token}0"),
        "garbage".to_string(),
        "x".repeat(BGPLS_PAGE_TOKEN_MAX_LEN + 1),
        foreign,
    ] {
        assert_eq!(
            service
                .list_bgp_ls_rib_routes(Request::new(proto::ListBgpLsRibRoutesRequest {
                    page_token: bad,
                    ..request.clone()
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    for bad in [
        proto::ListBgpLsRibRoutesRequest {
            nlri_type_filter: 1,
            ..request.clone()
        },
        proto::ListBgpLsRibRoutesRequest {
            afi_safi: proto::AddressFamily::BgpLs as i32,
            ..request.clone()
        },
        proto::ListBgpLsRibRoutesRequest {
            afi_safi: proto::AddressFamily::Ipv4Unicast as i32,
            page_token: String::new(),
            ..request.clone()
        },
    ] {
        assert_eq!(
            service
                .list_bgp_ls_rib_routes(Request::new(bad))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    assert!(
        rx.try_recv().is_err(),
        "rejections must not reach the actor"
    );
}

/// One IS-IS Link NLRI route `local -> remote` with an IGP metric and an
/// optional Link Local/Remote Identifier (TLV 258) separating parallel links.
fn topology_link_route(peer: IpAddr, local: u8, remote: u8, link_id: Option<u8>) -> BgpLsRibRoute {
    use rustbgpd_wire::{BgpLsTlv, encode_bgpls_tlvs};
    let encode = |tlvs: &[BgpLsTlv]| {
        let mut bytes = Vec::new();
        encode_bgpls_tlvs(tlvs, &mut bytes).unwrap();
        bytes::Bytes::from(bytes)
    };
    let node = |id: u8| {
        encode(&[
            BgpLsTlv::new(
                rustbgpd_wire::BGP_LS_TLV_AUTONOMOUS_SYSTEM,
                bytes::Bytes::from_static(&[0, 0, 0xfc, 0]),
            ),
            BgpLsTlv::new(
                rustbgpd_wire::BGP_LS_TLV_IGP_ROUTER_ID,
                bytes::Bytes::from(vec![0, 0, 0, 0, 0, id]),
            ),
        ])
    };
    let mut tlvs = vec![
        BgpLsTlv::new(
            rustbgpd_wire::BGP_LS_TLV_LOCAL_NODE_DESCRIPTORS,
            node(local),
        ),
        BgpLsTlv::new(
            rustbgpd_wire::BGP_LS_TLV_REMOTE_NODE_DESCRIPTORS,
            node(remote),
        ),
    ];
    if let Some(id) = link_id {
        tlvs.push(BgpLsTlv::new(
            258,
            bytes::Bytes::from(vec![0, 0, 0, id, 0, 0, 0, id]),
        ));
    }
    let mut payload = vec![2_u8];
    payload.extend_from_slice(&0_u64.to_be_bytes());
    payload.extend_from_slice(&encode(&tlvs));
    let metric = encode(&[BgpLsTlv::new(
        rustbgpd_wire::BGP_LS_TLV_IGP_METRIC,
        bytes::Bytes::from_static(&[0, 0, 10]),
    )]);
    let mut route = bgpls_test_routes(peer).remove(0);
    route.nlri = rustbgpd_wire::bgpls::BgpLsNlri {
        nlri_type: rustbgpd_wire::bgpls::BgpLsNlriType::Link,
        route_distinguisher: None,
        payload: payload.into(),
    };
    route.attributes = AttrSet::new(vec![rustbgpd_wire::PathAttribute::Unknown(
        rustbgpd_wire::RawAttribute {
            flags: 0x80,
            type_code: 29,
            data: metric,
        },
    )]);
    route
}

/// Real actor walks return every ORR node and link once in identity
/// order through continuation tokens, including two parallel links that
/// differ only in their Link NLRI.
#[tokio::test]
async fn orr_topology_pages_walk_every_element_once_through_the_real_rib() {
    let peer: IpAddr = "192.0.2.1".parse().unwrap();
    let mut routes: Vec<_> = (1..=5)
        .map(|node| topology_link_route(peer, node, node % 5 + 1, None))
        .collect();
    routes.push(topology_link_route(peer, 1, 3, Some(1)));
    routes.push(topology_link_route(peer, 1, 3, Some(2)));
    let (tx, rx) = mpsc::channel(8);
    let (_query_tx, query_rx) = mpsc::channel(1);
    let manager = rustbgpd_rib::RibManager::new(
        rx,
        query_rx,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    );
    let actor = tokio::spawn(manager.run());
    tx.send(RibUpdate::BgpLsRoutesReceived {
        peer,
        session_id: 0,
        announced: routes,
        withdrawn: vec![],
    })
    .await
    .unwrap();
    let service = RibService::new(tx.clone());

    let mut nodes = Vec::new();
    let mut request = proto::ListOrrTopologyNodesRequest {
        page_size: 2,
        ..Default::default()
    };
    loop {
        let page = service
            .list_orr_topology_nodes(Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.total_count, 5);
        assert!(page.nodes.len() <= 2);
        nodes.extend(page.nodes.into_iter().map(|node| node.key));
        if page.next_page_token.is_empty() {
            break;
        }
        request.page_token = page.next_page_token;
    }
    let mut sorted = nodes.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(nodes, sorted);
    assert_eq!(nodes.len(), 5);

    let mut links = Vec::new();
    let mut request = proto::ListOrrTopologyLinksRequest {
        page_size: 1,
        ..Default::default()
    };
    loop {
        let page = service
            .list_orr_topology_links(Request::new(request.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(page.total_count, 7);
        links.extend(
            page.links
                .into_iter()
                .map(|link| (link.local_key, link.remote_key)),
        );
        if page.next_page_token.is_empty() {
            break;
        }
        request.page_token = page.next_page_token;
    }
    assert_eq!(links.len(), 7, "parallel links are not skipped");
    assert!(links.windows(2).all(|pair| pair[0] <= pair[1]));
    let parallel = links
        .iter()
        .filter(|(local, remote)| local == &nodes[0] && remote == &nodes[2])
        .count();
    assert_eq!(parallel, 2);

    let legacy = service
        .list_topology_links(Request::new(proto::ListTopologyLinksRequest {}))
        .await
        .unwrap()
        .into_inner()
        .links;
    assert_eq!(legacy.len(), links.len());
    drop((service, tx));
    actor.await.unwrap();
}

/// Altered, foreign, oversized and malformed topology tokens, and a
/// signed link cursor that is not a Link NLRI, never reach the actor.
#[tokio::test]
async fn orr_topology_page_tokens_reject_forgery_and_foreign_queries() {
    let (tx, mut rx) = mpsc::channel(1);
    let service = RibService::new(tx);
    let scope = RouteQueryScope::Best;
    let version = RoutePageVersion {
        epoch: 1,
        generation: 2,
    };
    let nodes = family_query_identity("orr-nodes", "");
    let links = family_query_identity("orr-links", "");
    let node_token = encode_family_page_token(scope, &nodes, "02aabb", version);
    let link = topology_link_route("192.0.2.1".parse().unwrap(), 1, 2, None);
    let link_cursor = format!("-~{}", hex_octets(&link.nlri.payload));
    let link_token = encode_family_page_token(scope, &links, &link_cursor, version);
    let (_, after, _) = family_page_params_within(
        0,
        &link_token,
        scope,
        &links,
        BGPLS_PAGE_TOKEN_MAX_LEN,
        parse_orr_link_page_key,
    )
    .unwrap();
    let after = after.unwrap();
    assert_eq!(
        after.0,
        link.nlri.local_node_key().unwrap().as_bytes(),
        "the cursor re-derives the ordering key"
    );
    assert_eq!(after.1, link.nlri.remote_node_key().unwrap().as_bytes());

    let bad_nodes = [
        node_token.replacen("02aabb", "02aabc", 1),
        "garbage".to_string(),
        "x".repeat(BGPLS_PAGE_TOKEN_MAX_LEN + 1),
        encode_family_page_token(scope, &links, "02aabb", version),
        encode_family_page_token(scope, &nodes, "", version),
        encode_family_page_token(scope, &nodes, "0g", version),
    ];
    for token in bad_nodes {
        assert_eq!(
            service
                .list_orr_topology_nodes(Request::new(proto::ListOrrTopologyNodesRequest {
                    page_token: token,
                    ..Default::default()
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    let bad_links = [
        link_token.replacen('~', "~0", 1),
        node_token.clone(),
        encode_family_page_token(scope, &links, "-~02aabb", version),
        encode_family_page_token(scope, &links, "0102~00", version),
        encode_family_page_token(scope, &links, &link_cursor.replace('~', ""), version),
    ];
    for token in bad_links {
        assert_eq!(
            service
                .list_orr_topology_links(Request::new(proto::ListOrrTopologyLinksRequest {
                    page_token: token,
                    ..Default::default()
                }))
                .await
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    assert!(
        rx.try_recv().is_err(),
        "rejections must not reach the actor"
    );
}
