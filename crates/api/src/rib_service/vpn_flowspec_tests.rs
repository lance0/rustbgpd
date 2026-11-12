use super::*;
use rustbgpd_rib::AttrSet;
use std::time::Instant;

fn scoped_rows() -> Vec<FlowSpecRoute> {
    [Afi::Ipv4, Afi::Ipv6]
        .into_iter()
        .flat_map(|afi| {
            [
                None,
                Some(parse_rd("65000:1").unwrap()),
                Some(parse_rd("0x00020000fde80001").unwrap()),
            ]
            .into_iter()
            .map(move |rd| FlowSpecRoute {
                afi,
                rd,
                rule: rustbgpd_wire::FlowSpecRule {
                    components: vec![rustbgpd_wire::FlowSpecComponent::Port(vec![
                        rustbgpd_wire::NumericMatch {
                            end_of_list: true,
                            and_bit: false,
                            lt: false,
                            gt: false,
                            eq: true,
                            value: 80,
                        },
                    ])],
                },
                peer: PeerId::LOCAL,
                attributes: AttrSet::new(vec![PathAttribute::ExtendedCommunities(vec![
                    rustbgpd_wire::ExtendedCommunity::new(0x0002_fde8_0000_0064),
                    rustbgpd_wire::ExtendedCommunity::new(0x0202_0000_fde8_0001),
                    rustbgpd_wire::ExtendedCommunity::new(0x4002_fde8_0000_0001),
                ])]),
                received_at: Instant::now(),
                origin_type: rustbgpd_rib::RouteOrigin::Local,
                peer_router_id: Ipv4Addr::UNSPECIFIED,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
            })
        })
        .collect()
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "every family and view shares the same scoped projection assertions"
)]
async fn vpn_family_filters_every_query_view_before_copying_rows() {
    use proto::rib_service_server::RibService as _;
    let (tx, mut rx) = mpsc::channel(1);
    let service = RibService::new(tx);
    let actor = tokio::spawn(async move {
        while let Some(query) = rx.recv().await {
            match query {
                RibUpdate::QueryFlowSpecRoutes { filter, reply }
                | RibUpdate::QueryAdvertisedFlowSpecRoutes { filter, reply, .. } => {
                    let filter = filter.expect("UNSPECIFIED must also exclude VPN in the actor");
                    reply
                        .send(
                            scoped_rows()
                                .into_iter()
                                .filter(|row| filter(row))
                                .collect(),
                        )
                        .unwrap();
                }
                RibUpdate::QueryReceivedFlowSpecRoutes { filter, reply, .. } => {
                    // Synthetic rows test filter/serializer isolation only; real VPN receive is discarded.
                    let filter =
                        filter.expect("received and local views have the same family boundary");
                    let rows = scoped_rows()
                        .into_iter()
                        .map(|route| ReceivedFlowSpecRoute {
                            route,
                            selected: true,
                            validation: FlowSpecValidationStatus::Disabled,
                            reason: None,
                            pending: false,
                            injection: None,
                        })
                        .filter(|row| filter(row))
                        .collect();
                    reply.send(rows).unwrap();
                }
                _ => panic!("unexpected non-FlowSpec query"),
            }
        }
    });
    for (received, advertised) in [
        ("", ""),
        ("0.0.0.0", ""),
        ("192.0.2.1", ""),
        ("", "192.0.2.2"),
    ] {
        for (family, count) in [(0, 2), (3, 1), (4, 1), (13, 2), (14, 2)] {
            let response = service
                .list_flow_spec_routes(Request::new(proto::ListFlowSpecRequest {
                    afi_safi: family,
                    received_peer_address: received.into(),
                    advertised_peer_address: advertised.into(),
                }))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(response.received_view, !received.is_empty());
            assert_eq!(response.advertised_view, !advertised.is_empty());
            let rows = if received.is_empty() {
                response.routes
            } else {
                response
                    .received_routes
                    .into_iter()
                    .map(|row| row.route.unwrap())
                    .collect()
            };
            assert_eq!(
                rows.len(),
                count,
                "family {family}, received {received}, advertised {advertised}"
            );
            for row in rows {
                if family == 0 {
                    assert!(matches!(row.afi_safi, 3 | 4));
                } else {
                    assert_eq!(row.afi_safi, family);
                }
                if family >= 13 {
                    assert_ne!(row.rd, "");
                    assert_eq!(row.route_targets, ["65000:100", "0.65000:1"]);
                    assert_eq!(
                        parse_rd(&row.rd).unwrap().rd_type(),
                        if row.rd.starts_with("0x") { 2 } else { 0 }
                    );
                } else {
                    assert_eq!(row.rd, "");
                    assert!(
                        row.route_targets.is_empty(),
                        "global raw RTs do not imply VPN scope"
                    );
                }
                assert_eq!(
                    row.extended_communities,
                    vec![
                        0x0002_fde8_0000_0064,
                        0x0202_0000_fde8_0001,
                        0x4002_fde8_0000_0001
                    ]
                );
            }
        }
    }
    drop(service);
    actor.await.unwrap();
}

#[tokio::test]
async fn vpn_local_probe_acknowledges_an_empty_read_without_a_peer() {
    use proto::rib_service_server::RibService as _;
    let (tx, mut rx) = mpsc::channel(1);
    let service = RibService::new(tx);
    let actor = tokio::spawn(async move {
        for _ in 0..2 {
            let RibUpdate::QueryReceivedFlowSpecRoutes {
                peer,
                filter,
                reply,
            } = rx.recv().await.unwrap()
            else {
                panic!("read-only local probe")
            };
            assert_eq!(peer, PeerId::LOCAL);
            assert!(filter.is_some());
            reply.send(Vec::new()).unwrap();
        }
    });
    for family in [13, 14] {
        let response = service
            .list_flow_spec_routes(Request::new(proto::ListFlowSpecRequest {
                afi_safi: family,
                received_peer_address: "0.0.0.0".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(response.received_view);
        assert!(!response.advertised_view);
        assert!(response.routes.is_empty() && response.received_routes.is_empty());
    }
    actor.await.unwrap();
}

#[test]
fn vpn_route_projection_preserves_rd_encoding_and_exact_rt_types() {
    for mut route in scoped_rows().into_iter().filter(|route| route.rd.is_some()) {
        for text in [
            "65535:4294967295",
            "192.0.2.1:65535",
            "4294967295:65535",
            "0x00020000fde80001",
        ] {
            route.rd = Some(parse_rd(text).unwrap());
            let row = flowspec_route_to_proto(&route);
            assert_eq!(parse_rd(&row.rd).unwrap(), route.rd.unwrap());
            assert_eq!(row.afi_safi, if route.afi == Afi::Ipv4 { 13 } else { 14 });
        }
    }
    for raw in [
        0x4002_fde8_0000_0001,
        0x4102_c000_0201_0001,
        0x4202_0000_fde8_0001,
        0x8008_fde8_0000_0001,
    ] {
        assert_eq!(
            flowspec_scope_rt_to_proto(rustbgpd_wire::ExtendedCommunity::new(raw)),
            None
        );
    }
}
