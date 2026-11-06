use super::*;
use proto::injection_service_server::InjectionService as _;

fn vpn_request(family: proto::AddressFamily) -> proto::AddFlowSpecRequest {
    proto::AddFlowSpecRequest {
        afi_safi: family as i32,
        rd: "65000:1".into(),
        route_targets: vec!["65000:100".into()],
        components: vec![proto::FlowSpecComponent {
            r#type: 4,
            value: "=80".into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

async fn rejected_before_rib<T>(call: impl std::future::Future<Output = Result<T, Status>>) {
    let result = tokio::time::timeout(std::time::Duration::from_secs(1), call)
        .await
        .expect("invalid input must not wait for the RIB");
    assert_eq!(
        result.err().expect("request must fail").code(),
        tonic::Code::InvalidArgument
    );
}

async fn reject_add_modes(service: &InjectionService, request: &proto::AddFlowSpecRequest) {
    let lease = Some(proto::InjectionLease {
        owner: "scope-check".into(),
        lease_seconds: 30,
    });
    rejected_before_rib(service.add_flow_spec(Request::new(request.clone()))).await;
    rejected_before_rib(service.add_leased_flow_spec(Request::new(
        proto::AddLeasedFlowSpecRequest {
            rule: Some(request.clone()),
            lease: lease.clone(),
        },
    )))
    .await;
    rejected_before_rib(service.add_guarded_flow_spec(Request::new(
        proto::AddGuardedFlowSpecRequest {
            rule: Some(request.clone()),
            lease,
            window: Some(proto::MutationWindow {
                incarnation: 1,
                sequence: 1,
            }),
            revision: 1,
        },
    )))
    .await;
}

async fn reject_key_modes(service: &InjectionService, request: &proto::AddFlowSpecRequest) {
    reject_add_modes(service, request).await;
    rejected_before_rib(
        service.delete_flow_spec(Request::new(proto::DeleteFlowSpecRequest {
            afi_safi: request.afi_safi,
            rd: request.rd.clone(),
            components: request.components.clone(),
            ..Default::default()
        })),
    )
    .await;
    rejected_before_rib(service.delete_guarded_flow_spec(Request::new(
        proto::DeleteGuardedFlowSpecRequest {
            afi_safi: request.afi_safi,
            rd: request.rd.clone(),
            components: request.components.clone(),
            owner: "scope-check".into(),
            revision: 1,
        },
    )))
    .await;
    rejected_before_rib(service.list_flow_spec_export_dispositions(Request::new(
        proto::ListFlowSpecExportDispositionsRequest {
            afi_safi: request.afi_safi,
            rd: request.rd.clone(),
            components: request.components.clone(),
            ..Default::default()
        },
    )))
    .await;
}

#[tokio::test]
async fn vpn_scope_refusals_precede_every_key_enqueue() {
    let (tx, mut rx) = mpsc::channel(64);
    let leases = Arc::new(InjectionLeases::new());
    let service = InjectionService::new(tx, AccessMode::ReadWrite, Arc::clone(&leases));
    for family in [
        proto::AddressFamily::L3vpnIpv4Flowspec,
        proto::AddressFamily::L3vpnIpv6Flowspec,
    ] {
        for rd in ["", "bad", "0x", "0xffff000000000001"] {
            let request = proto::AddFlowSpecRequest {
                rd: rd.into(),
                ..vpn_request(family)
            };
            reject_key_modes(&service, &request).await;
        }
    }
    for family in [0, 1, 3, 4, 999] {
        let request = proto::AddFlowSpecRequest {
            afi_safi: family,
            ..vpn_request(proto::AddressFamily::L3vpnIpv4Flowspec)
        };
        reject_key_modes(&service, &request).await;
    }
    for (family, prefix) in [
        (proto::AddressFamily::L3vpnIpv4Flowspec, "2001:db8::/64"),
        (proto::AddressFamily::L3vpnIpv6Flowspec, "192.0.2.0/24"),
    ] {
        let request = proto::AddFlowSpecRequest {
            components: vec![proto::FlowSpecComponent {
                r#type: 1,
                prefix: prefix.into(),
                ..Default::default()
            }],
            ..vpn_request(family)
        };
        reject_key_modes(&service, &request).await;
    }
    let request = proto::AddFlowSpecRequest {
        components: vec![proto::FlowSpecComponent {
            r#type: 13,
            value: "=1".into(),
            ..Default::default()
        }],
        ..vpn_request(proto::AddressFamily::L3vpnIpv4Flowspec)
    };
    reject_key_modes(&service, &request).await;
    assert_eq!(leases.list(None).len(), 0);
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn vpn_rt_refusals_precede_all_add_modes() {
    let (tx, mut rx) = mpsc::channel(64);
    let leases = Arc::new(InjectionLeases::new());
    let service = InjectionService::new(tx, AccessMode::ReadWrite, Arc::clone(&leases));
    for family in [
        proto::AddressFamily::L3vpnIpv4Flowspec,
        proto::AddressFamily::L3vpnIpv6Flowspec,
    ] {
        for targets in [
            vec![],
            vec!["65000:1", "65000:1"],
            vec!["1.0:1", "65536:1"],
            vec!["65536:65536"],
            vec!["65536.0:1"],
            vec!["192.0.2.1:65536"],
        ] {
            let request = proto::AddFlowSpecRequest {
                route_targets: targets.into_iter().map(str::to_owned).collect(),
                ..vpn_request(family)
            };
            reject_add_modes(&service, &request).await;
        }
        let duplicate = proto::AddFlowSpecRequest {
            extended_communities: vec![parse_flowspec_route_target("65000:100").unwrap().as_u64()],
            ..vpn_request(family)
        };
        reject_add_modes(&service, &duplicate).await;
        for raw in [
            0x4002_fde8_0000_0001,
            0x0103_c000_0201_0001,
            0x8008_fde8_0000_0001,
        ] {
            let request = proto::AddFlowSpecRequest {
                route_targets: vec![],
                extended_communities: vec![raw],
                ..vpn_request(family)
            };
            reject_add_modes(&service, &request).await;
        }
    }
    for family in [
        proto::AddressFamily::Ipv4Flowspec,
        proto::AddressFamily::Ipv6Flowspec,
    ] {
        let request = proto::AddFlowSpecRequest {
            afi_safi: family as i32,
            rd: String::new(),
            ..vpn_request(family)
        };
        reject_add_modes(&service, &request).await;
        let raw_only = proto::AddFlowSpecRequest {
            route_targets: vec![],
            extended_communities: vec![0x0002_fde8_0000_0064],
            ..request
        };
        assert!(
            build_injected_flowspec(raw_only).is_ok(),
            "global raw RT passthrough remains legal"
        );
    }
    assert_eq!(leases.list(None).len(), 0);
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

fn component_bytes(bytes: usize) -> Vec<proto::FlowSpecComponent> {
    // One type byte, then two-byte (=1) or three-byte (=256) numeric terms.
    let term_bytes = bytes - 1;
    let mut terms = vec!["=1"; term_bytes / 2];
    if !term_bytes.is_multiple_of(2) {
        terms.pop();
        terms.push("=256");
    }
    vec![proto::FlowSpecComponent {
        r#type: 4,
        value: terms.join(","),
        ..Default::default()
    }]
}

#[tokio::test]
async fn vpn_length_includes_rd_on_every_key_path() {
    let (tx, mut rx) = mpsc::channel(64);
    let service =
        InjectionService::new(tx, AccessMode::ReadWrite, Arc::new(InjectionLeases::new()));
    for family in [
        proto::AddressFamily::L3vpnIpv4Flowspec,
        proto::AddressFamily::L3vpnIpv6Flowspec,
    ] {
        let request = proto::AddFlowSpecRequest {
            components: component_bytes(4087),
            ..vpn_request(family)
        };
        let route = build_injected_flowspec(request.clone()).unwrap();
        assert_eq!(route.rule.encoded_len(route.afi), 4087);
        assert_eq!(
            parse_flowspec_key(request.afi_safi, &request.rd, &request.components)
                .unwrap()
                .rule,
            route.rule
        );
        let oversized = proto::AddFlowSpecRequest {
            components: component_bytes(4088),
            ..request
        };
        reject_key_modes(&service, &oversized).await;
    }
    for family in [
        proto::AddressFamily::Ipv4Flowspec,
        proto::AddressFamily::Ipv6Flowspec,
    ] {
        let request = proto::AddFlowSpecRequest {
            afi_safi: family as i32,
            components: component_bytes(4095),
            ..Default::default()
        };
        let route = build_injected_flowspec(request).unwrap();
        assert_eq!(route.rule.encoded_len(route.afi), 4095);
    }
    assert!(matches!(
        rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn vpn_rd_and_rt_encodings_are_lossless() {
    for family in [
        proto::AddressFamily::L3vpnIpv4Flowspec,
        proto::AddressFamily::L3vpnIpv6Flowspec,
    ] {
        for rd in [
            "65535:4294967295",
            "192.0.2.1:65535",
            "4294967295:65535",
            "0x00020000fde80064",
        ] {
            let request = proto::AddFlowSpecRequest {
                rd: rd.into(),
                ..vpn_request(family)
            };
            let route = build_injected_flowspec(request).unwrap();
            assert_eq!(
                parse_originated_rd(&format_rd(route.rd.unwrap())).unwrap(),
                route.rd.unwrap()
            );
        }
    }
    for (text, raw) in [
        ("65535:4294967295", 0x0002_ffff_ffff_ffff),
        ("192.0.2.1:65535", 0x0102_c000_0201_ffff),
        ("4294967295:65535", 0x0202_ffff_ffff_ffff),
        ("65535.65535:65535", 0x0202_ffff_ffff_ffff),
        ("0.65000:1", 0x0202_0000_fde8_0001),
    ] {
        let target = parse_flowspec_route_target(text).unwrap();
        assert_eq!(target.as_u64(), raw);
        assert!(is_flowspec_scope_rt(target));
        assert_eq!(
            parse_redirect(text).unwrap().unwrap().as_u64(),
            (raw & !0x00ff_0000_0000_0000) | 0x8008_0000_0000_0000
        );
    }
    for text in [
        "",
        "a:1",
        "65536:65536",
        "4294967296:1",
        "65000:4294967296",
        "0.65536:1",
        "65536.0:1",
        "1.2.3:1",
        "1.2.3.4:65536",
    ] {
        assert_eq!(
            parse_flowspec_route_target(text).unwrap_err().code(),
            tonic::Code::InvalidArgument
        );
    }
}

#[test]
fn vpn_rt_canonicalization_preserves_other_payload_bytes_and_order() {
    let raw = vec![
        0x4002_fde8_0000_0001,
        0xff04_0102_0304_0506,
        0x0202_0000_fde8_0001,
        0xff04_0102_0304_0506,
        0x0002_fde8_0000_0064,
    ];
    let request = proto::AddFlowSpecRequest {
        route_targets: vec![],
        extended_communities: raw,
        ipv6_extended_communities: vec![vec![0xff; 20], vec![0xff; 20]],
        ..vpn_request(proto::AddressFamily::L3vpnIpv6Flowspec)
    };
    let original = build_injected_flowspec(request.clone()).unwrap();
    let typed = proto::AddFlowSpecRequest {
        route_targets: vec!["0.65000:1".into(), "65000:100".into()],
        extended_communities: request
            .extended_communities
            .iter()
            .copied()
            .filter(|raw| !is_flowspec_scope_rt(ExtendedCommunity::new(*raw)))
            .collect(),
        ..request.clone()
    };
    assert_eq!(
        build_injected_flowspec(typed).unwrap().attributes,
        original.attributes
    );
    let values = original
        .attributes
        .iter()
        .find_map(PathAttribute::extended_communities)
        .unwrap();
    assert_eq!(
        values
            .iter()
            .map(|value| value.as_u64())
            .collect::<Vec<_>>(),
        vec![
            0x4002_fde8_0000_0001,
            0xff04_0102_0304_0506,
            0xff04_0102_0304_0506,
            0x0002_fde8_0000_0064,
            0x0202_0000_fde8_0001
        ]
    );
    let duplicate_raw = proto::AddFlowSpecRequest {
        extended_communities: vec![0x0002_fde8_0000_0064; 2],
        ..request
    };
    let route = build_injected_flowspec(duplicate_raw).unwrap();
    assert_eq!(
        route
            .attributes
            .iter()
            .find_map(PathAttribute::extended_communities)
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn vpn_cursor_keeps_legacy_global_forms_and_rejects_impossible_scopes() {
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        let rule = FlowSpecRule {
            components: parse_flowspec_components(&component_bytes(3), afi).unwrap(),
        };
        let mut bytes = Vec::new();
        rustbgpd_wire::flowspec::try_encode_flowspec_nlri(&[rule], &mut bytes, afi).unwrap();
        let mut hex = String::new();
        for byte in &bytes {
            write!(hex, "{byte:02x}").unwrap();
        }
        let global = format!("f:{}:{hex}", afi as u16);
        assert!(matches!(
            parse_leased_key_cursor(&global).unwrap(),
            InjectedKeyCursor::FlowSpec(_, None, _)
        ));
        let scoped = format!("{global}:r00020000fde80001");
        assert!(matches!(
            parse_leased_key_cursor(&scoped).unwrap(),
            InjectedKeyCursor::FlowSpec(_, Some(_), _)
        ));
        for bad in [
            format!("{global}:rffff000000000001"),
            format!("{global}:r0002"),
            format!("f:{}:{hex}{hex}", afi as u16),
            format!("{scoped}:trailing"),
            format!("f:25:{hex}"),
        ] {
            assert_eq!(
                parse_leased_key_cursor(&bad).unwrap_err().code(),
                tonic::Code::InvalidArgument
            );
        }
        let oversized = FlowSpecRule {
            components: parse_flowspec_components(&component_bytes(4088), afi).unwrap(),
        };
        let mut bytes = Vec::new();
        rustbgpd_wire::flowspec::try_encode_flowspec_nlri(&[oversized], &mut bytes, afi).unwrap();
        let mut hex = String::new();
        for byte in &bytes {
            write!(hex, "{byte:02x}").unwrap();
        }
        assert_eq!(
            parse_leased_key_cursor(&format!("f:{}:{hex}:r0000000000000001", afi as u16))
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
}

#[test]
fn vpn_prefix_validation_preserves_only_the_matching_bits() {
    for (afi, prefix, offset) in [
        (Afi::Ipv4, "192.0.2.0/33", 0),
        (Afi::Ipv6, "2001:db8::/129", 0),
        (Afi::Ipv6, "2001:db8::/64", 64),
        (Afi::Ipv6, "2001:db8::/0", 1),
        (Afi::Ipv6, "2001:db8::/128", 255),
    ] {
        assert_eq!(
            parse_flowspec_prefix(prefix, afi, "test", offset)
                .unwrap_err()
                .code(),
            tonic::Code::InvalidArgument
        );
    }
    assert_eq!(
        parse_flowspec_prefix("2001:db8:1234::/64", Afi::Ipv6, "test", 32).unwrap(),
        parse_flowspec_prefix("::1234:0:0:0:0:0/64", Afi::Ipv6, "test", 32).unwrap()
    );
    assert!(parse_flowspec_prefix("::/0", Afi::Ipv6, "test", 0).is_ok());
}

#[test]
fn vpn_api_rules_use_rd_in_the_one_and_two_byte_length_boundary() {
    for family in [
        proto::AddressFamily::L3vpnIpv4Flowspec,
        proto::AddressFamily::L3vpnIpv6Flowspec,
    ] {
        for payload in [239, 240, 4095] {
            let route = build_injected_flowspec(proto::AddFlowSpecRequest {
                components: component_bytes(payload - 8),
                ..vpn_request(family)
            })
            .unwrap();
            let vpn = rustbgpd_wire::VpnFlowSpecRule {
                rd: route.rd.unwrap(),
                rule: route.rule,
            };
            let mut encoded = Vec::new();
            rustbgpd_wire::flowspec::try_encode_vpn_flowspec_nlri_for_afi(
                std::slice::from_ref(&vpn),
                &mut encoded,
                route.afi,
            )
            .unwrap();
            assert_eq!(encoded.len(), payload + if payload < 240 { 1 } else { 2 });
            if payload == 239 {
                assert_eq!(encoded[0], 239);
            }
            if payload == 240 {
                assert_eq!(&encoded[..2], &[0xf0, 0xf0]);
            }
            assert_eq!(
                rustbgpd_wire::flowspec::decode_vpn_flowspec_nlri_for_afi(&encoded, route.afi)
                    .unwrap(),
                vec![vpn]
            );
        }
    }
}

fn communicated_actions() -> Vec<proto::FlowSpecAction> {
    use proto::flow_spec_action::Action;
    let mut actions = vec![
        Action::TrafficRate(proto::FlowSpecTrafficRate { rate: 0.0 }),
        Action::TrafficRate(proto::FlowSpecTrafficRate { rate: 1000.0 }),
        Action::TrafficRatePackets(proto::FlowSpecTrafficRatePackets { rate: 500.0 }),
        Action::TrafficMarking(proto::FlowSpecTrafficMarking { dscp: 46 }),
    ];
    for target in ["65000:1", "192.0.2.1:2", "4200000000:3", "0.65000:4"] {
        actions.push(Action::Redirect(proto::FlowSpecRedirect {
            route_target: target.into(),
        }));
    }
    for (address, copy) in [
        ("192.0.2.10", false),
        ("192.0.2.10", true),
        ("2001:db8::10", false),
        ("2001:db8::10", true),
    ] {
        actions.push(Action::RedirectIp(proto::FlowSpecRedirectIp {
            address: address.into(),
            copy,
        }));
    }
    actions
        .into_iter()
        .map(|action| proto::FlowSpecAction {
            action: Some(action),
        })
        .collect()
}

#[tokio::test]
async fn vpn_communicated_actions_round_trip_on_real_local_rules() {
    use proto::rib_service_server::RibService as _;
    let (tx, rx) = mpsc::channel(64);
    let manager = rustbgpd_rib::RibManager::new(
        rx,
        mpsc::channel(1).1,
        None,
        None,
        rustbgpd_telemetry::BgpMetrics::new(),
    );
    let service = InjectionService::new(
        tx.clone(),
        AccessMode::ReadWrite,
        manager.injection_leases(),
    );
    let reader = crate::rib_service::RibService::new(tx);
    let task = tokio::spawn(manager.run());
    for (family, source) in [
        (proto::AddressFamily::L3vpnIpv4Flowspec, "192.0.2.0/24"),
        (
            proto::AddressFamily::L3vpnIpv6Flowspec,
            "2001:db8:1234::/48",
        ),
    ] {
        for action in communicated_actions() {
            let request = proto::AddFlowSpecRequest {
                components: vec![proto::FlowSpecComponent {
                    r#type: 2,
                    prefix: source.into(),
                    ..Default::default()
                }],
                actions: vec![action.clone()],
                ..vpn_request(family)
            };
            service.add_flow_spec(Request::new(request)).await.unwrap();
            let rows = reader
                .list_flow_spec_routes(Request::new(proto::ListFlowSpecRequest {
                    afi_safi: family as i32,
                    received_peer_address: "0.0.0.0".into(),
                    ..Default::default()
                }))
                .await
                .unwrap()
                .into_inner();
            assert_eq!(rows.received_routes.len(), 1);
            let row = rows.received_routes[0].route.as_ref().unwrap();
            assert_eq!(row.rd, "65000:1");
            assert_eq!(row.actions, [action]);
            assert_eq!(row.route_targets, ["65000:100"]);
            for raw in [false, true] {
                let request = proto::AddFlowSpecRequest {
                    afi_safi: row.afi_safi,
                    rd: row.rd.clone(),
                    components: row.components.clone(),
                    actions: if raw { Vec::new() } else { row.actions.clone() },
                    route_targets: if raw {
                        Vec::new()
                    } else {
                        row.route_targets.clone()
                    },
                    extended_communities: if raw {
                        row.extended_communities.clone()
                    } else {
                        Vec::new()
                    },
                    ipv6_extended_communities: if raw {
                        row.ipv6_extended_communities.clone()
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                };
                assert_eq!(
                    service
                        .add_flow_spec(Request::new(request))
                        .await
                        .unwrap()
                        .into_inner()
                        .outcome(),
                    proto::FlowSpecInjectOutcome::Unchanged
                );
            }
        }
    }
    drop((service, reader));
    task.await.unwrap();
}

#[test]
fn vpn_ipv6_fragment_reserved_bits_do_not_create_distinct_keys() {
    let components = |value: &str| {
        vec![proto::FlowSpecComponent {
            r#type: 12,
            value: value.into(),
            ..Default::default()
        }]
    };
    for family in [
        proto::AddressFamily::Ipv6Flowspec,
        proto::AddressFamily::L3vpnIpv6Flowspec,
    ] {
        let rd = if family == proto::AddressFamily::Ipv6Flowspec {
            ""
        } else {
            "65000:1"
        };
        assert_eq!(
            parse_flowspec_key(family as i32, rd, &components("0xff")).unwrap(),
            parse_flowspec_key(family as i32, rd, &components("0x0e")).unwrap()
        );
    }
    assert_ne!(
        parse_flowspec_key(3, "", &components("0xff")).unwrap(),
        parse_flowspec_key(3, "", &components("0x0e")).unwrap()
    );
}

#[test]
fn vpn_many_typed_targets_keep_exact_duplicate_checks() {
    let mut request = vpn_request(proto::AddressFamily::L3vpnIpv6Flowspec);
    request.route_targets = (0..8192).map(|value| format!("65000:{value}")).collect();
    let route = build_injected_flowspec(request.clone()).unwrap();
    assert_eq!(
        route
            .attributes
            .iter()
            .find_map(PathAttribute::extended_communities)
            .unwrap()
            .len(),
        8192
    );
    request.route_targets.push("65000:8191".into());
    assert_eq!(
        build_injected_flowspec(request).unwrap_err().code(),
        tonic::Code::InvalidArgument
    );
}
