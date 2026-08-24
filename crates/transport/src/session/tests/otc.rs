use super::*;

fn otc(asn: u32) -> PathAttribute {
    PathAttribute::OnlyToCustomer(asn)
}

fn otc_routes_blocked_count(session: &PeerSession, reason: &str) -> u64 {
    session
        .metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == "bgp_otc_routes_blocked_total")
        .and_then(|family| {
            family.get_metric().iter().find_map(|metric| {
                metric
                    .get_label()
                    .iter()
                    .any(|label| label.name() == "reason" && label.value() == reason)
                    .then(|| {
                        #[expect(
                            clippy::cast_possible_truncation,
                            clippy::cast_sign_loss,
                            reason = "Prometheus counters are monotonic non-negative integers exposed as f64"
                        )]
                        let value = metric.get_counter().value() as u64;
                        value
                    })
            })
        })
        .unwrap_or(0)
}

#[test]
fn otc_egress_adds_local_asn_for_provider_peer_and_route_server() {
    for role in [BgpRole::Provider, BgpRole::Peer, BgpRole::RouteServer] {
        let mut session = make_test_session(65001, 65002);
        session.config.peer.local_role = Some(role);
        let route = make_route(100);
        let attrs =
            session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::OnlyToCustomer(65001))),
            "role {role:?} must add OTC(local AS) on eBGP unicast egress"
        );
    }
}

#[test]
fn otc_egress_preserves_existing_otc() {
    let mut session = make_test_session(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    let route = replace_route_attrs(
        &make_route(100),
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            otc(64512),
        ],
    );
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    let otcs: Vec<u32> = attrs
        .iter()
        .filter_map(|a| match a {
            PathAttribute::OnlyToCustomer(asn) | PathAttribute::OnlyToCustomerPartial(asn) => {
                Some(*asn)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        otcs,
        vec![64512],
        "E1 must not overwrite or duplicate an existing OTC attribute"
    );
}

#[test]
fn otc_egress_blocks_unicast_to_provider_peer_or_route_server_client() {
    for role in [BgpRole::Customer, BgpRole::Peer, BgpRole::RouteServerClient] {
        for (prefix, route_next_hop) in [
            (
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            ),
            (
                Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 64)),
                IpAddr::V6("2001:db8::2".parse().unwrap()),
            ),
        ] {
            let mut session = make_test_session(65001, 65002);
            session.config.peer.local_role = Some(role);
            let mut attributes = vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
                otc(65002),
            ];
            if let IpAddr::V4(next_hop) = route_next_hop {
                attributes.push(PathAttribute::NextHop(next_hop));
            }
            let mut route = replace_route_attrs(&make_route(100), attributes);
            route.prefix = prefix;
            route.next_hop = route_next_hop;
            assert!(
                session.otc_egress_blocks_unicast(&route),
                "role {role:?} must not propagate an OTC-tagged {prefix} route"
            );
        }
    }
}

#[tokio::test]
async fn otc_ingress_adds_remote_asn_for_route_from_provider_unicast() {
    for role in [BgpRole::Customer, BgpRole::Peer, BgpRole::RouteServerClient] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        session.config.peer.local_role = Some(role);
        session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let update = UpdateMessage::build(
            &[Ipv4NlriEntry { path_id: 0, prefix }],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        );
        session.process_update(update).await;
        let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
            panic!("expected RoutesReceived");
        };
        assert_eq!(announced.len(), 1);
        assert!(
            announced[0]
                .attributes
                .iter()
                .any(|a| matches!(a, PathAttribute::OnlyToCustomer(65002))),
            "I3 must add OTC(remote AS) for local role {role:?} receiving untagged unicast"
        );
    }
}

#[tokio::test]
async fn otc_ingress_provider_drops_tagged_unicast_from_customer_but_keeps_withdrawals() {
    for role in [BgpRole::Provider, BgpRole::RouteServer] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        session.config.peer.local_role = Some(role);
        session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
        let announced_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let withdrawn_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            otc(65002),
        ];
        let update = UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: announced_prefix,
            }],
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: withdrawn_prefix,
            }],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        );
        session.process_update(update).await;
        let RibUpdate::RoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().unwrap()
        else {
            panic!("expected RoutesReceived");
        };
        assert!(
            announced.is_empty(),
            "I1 must drop tagged unicast announces for local role {role:?}"
        );
        assert_eq!(
            withdrawn,
            vec![(Prefix::V4(withdrawn_prefix), 0)],
            "I1 must preserve withdrawals from the same UPDATE for local role {role:?}"
        );
    }
}

#[tokio::test]
async fn otc_ingress_provider_applies_role_rule_to_partial_typed_otc() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::OnlyToCustomerPartial(65_002),
    ];
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry { path_id: 0, prefix }],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    assert!(rib_rx.try_recv().is_err(), "E0 OTC must trigger I1 like C0");
}

/// An OTC safety rejection replaces accepted classic and MP-unicast routes
/// with exact withdrawals. First-seen rejected identities remain silent.
#[expect(
    clippy::too_many_lines,
    reason = "pins classic and MP replacement withdrawal, first-seen gating, accounting, and explain state"
)]
#[tokio::test]
async fn otc_replacements_withdraw_accepted_classic_and_mp_routes_only() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};
    use rustbgpd_wire::{MpReachNlri, NlriEntry};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.import_explain_enabled = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);
    let accepted_v4 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let first_seen_v4 = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let accepted_v6 = Prefix::V6(Ipv6Prefix::new("2001:db8:440:1::".parse().unwrap(), 64));
    let first_seen_v6 = Prefix::V6(Ipv6Prefix::new("2001:db8:440:2::".parse().unwrap(), 64));
    let attrs = |mp_announced: Vec<NlriEntry>, blocked: bool| {
        let mut attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        if blocked {
            attrs.push(otc(65002));
        }
        attrs.push(PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: "2001:db8::2".parse().unwrap(),
            link_local_next_hop: None,
            announced: mp_announced,
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }));
        attrs
    };
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: accepted_v4,
            }],
            &[],
            &attrs(
                vec![NlriEntry {
                    path_id: 0,
                    prefix: accepted_v6,
                }],
                false,
            ),
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected accepted classic and MP routes");
    };
    assert_eq!(announced.len(), 2);

    session
        .process_update(UpdateMessage::build(
            &[
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: accepted_v4,
                },
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: first_seen_v4,
                },
            ],
            &[],
            &attrs(
                vec![
                    NlriEntry {
                        path_id: 0,
                        prefix: accepted_v6,
                    },
                    NlriEntry {
                        path_id: 0,
                        prefix: first_seen_v6,
                    },
                ],
                true,
            ),
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("accepted OTC replacements must become withdrawals")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn.len(), 2);
    assert!(withdrawn.contains(&(Prefix::V4(accepted_v4), 0)));
    assert!(withdrawn.contains(&(accepted_v6, 0)));
    assert_eq!(session.known_prefix_count(), 0);
    assert!(
        rib_rx.try_recv().is_err(),
        "first-seen rejects must stay silent"
    );

    let key = |prefix| ImportDecisionKey {
        afi: match prefix {
            Prefix::V4(_) => Afi::Ipv4,
            Prefix::V6(_) => Afi::Ipv6,
        },
        safi: Safi::Unicast,
        prefix,
        path_id: 0,
    };
    for prefix in [Prefix::V4(accepted_v4), accepted_v6] {
        match session
            .import_decision_cache
            .lookup(&key(prefix), session.import_policy_generation)
        {
            LookupResult::Hit(decision) => {
                assert_eq!(decision.outcome, CachedOutcome::Withdrawn);
            }
            other => panic!("expected OTC-withdrawn {prefix}, got {other:?}"),
        }
    }
    for prefix in [Prefix::V4(first_seen_v4), first_seen_v6] {
        assert!(matches!(
            session
                .import_decision_cache
                .lookup(&key(prefix), session.import_policy_generation),
            LookupResult::NotSeen
        ));
    }
}

#[tokio::test]
async fn otc_ingress_peer_drops_tagged_unicast_from_wrong_as() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Peer);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        otc(64512),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    assert!(
        rib_rx.try_recv().is_err(),
        "I2 must drop tagged unicast announces whose OTC ASN is not the peer AS"
    );
}

#[tokio::test]
async fn otc_ingress_malformed_length_withdraws_a_real_accepted_replacement() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let announced_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let overlap_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let first_seen_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let accepted_attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    session
        .process_update(UpdateMessage::build(
            &[
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: announced_prefix,
                },
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: overlap_prefix,
                },
            ],
            &[],
            &accepted_attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected initial accepted route");
    };
    assert_eq!(announced.len(), 2);

    let malformed_attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
            flags: rustbgpd_wire::constants::attr_flags::OPTIONAL
                | rustbgpd_wire::constants::attr_flags::TRANSITIVE,
            type_code: rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER,
            data: Bytes::from_static(&[0, 0, 0]),
        }),
    ];
    let update = UpdateMessage::build(
        &[
            Ipv4NlriEntry {
                path_id: 0,
                prefix: announced_prefix,
            },
            Ipv4NlriEntry {
                path_id: 0,
                prefix: overlap_prefix,
            },
            Ipv4NlriEntry {
                path_id: 0,
                prefix: first_seen_prefix,
            },
        ],
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: overlap_prefix,
        }],
        &malformed_attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx.try_recv().unwrap()
    else {
        panic!("expected RoutesReceived");
    };
    assert!(
        announced.is_empty(),
        "malformed OTC length must use treat-as-withdraw behavior for unicast"
    );
    assert_eq!(withdrawn.len(), 2);
    assert!(withdrawn.contains(&(Prefix::V4(announced_prefix), 0)));
    assert!(withdrawn.contains(&(Prefix::V4(overlap_prefix), 0)));
    assert!(!withdrawn.contains(&(Prefix::V4(first_seen_prefix), 0)));
    assert!(
        rib_rx.try_recv().is_err(),
        "first-seen malformed route stays silent"
    );
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
}

#[tokio::test]
async fn otc_ingress_wrong_flags_are_role_independent_treat_as_withdraw() {
    let cases = [
        (
            rustbgpd_wire::constants::attr_flags::TRANSITIVE,
            &[0, 0, 0, 1][..],
        ),
        (
            rustbgpd_wire::constants::attr_flags::OPTIONAL,
            &[0, 0, 0, 1][..],
        ),
        (0, &[0, 0, 0, 1][..]),
        // The flags error wins when the value length is also malformed.
        (0, &[0, 0, 1][..]),
    ];
    for (flags, value) in cases {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        session.config.peer.local_role = None;
        let (client, _server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        rfc7606_drain(&mut rib_rx);
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, flags), 32);
        let base = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        session
            .process_update(UpdateMessage::build(
                &[Ipv4NlriEntry { path_id: 0, prefix }],
                &[],
                &base,
                true,
                false,
                Ipv4UnicastMode::Body,
            ))
            .await;
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::RoutesReceived { announced, .. }) if announced.len() == 1
        ));

        let mut malformed = base;
        malformed.push(PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
            flags,
            type_code: rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER,
            data: Bytes::copy_from_slice(value),
        }));
        let blocked_before = session.otc_routes_blocked;
        let malformed_counter_before = otc_routes_blocked_count(&session, "malformed_length");
        session
            .process_update(UpdateMessage::build(
                &[Ipv4NlriEntry { path_id: 0, prefix }],
                &[],
                &malformed,
                true,
                false,
                Ipv4UnicastMode::Body,
            ))
            .await;
        let RibUpdate::RoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().unwrap()
        else {
            panic!("wrong-flags OTC must reach RIB as withdrawal");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec![(Prefix::V4(prefix), 0)]);
        assert_eq!(session.fsm.state(), SessionState::Established);
        assert_eq!(
            session.otc_routes_blocked, blocked_before,
            "flags errors must not be mislabeled malformed_length"
        );
        assert_eq!(
            otc_routes_blocked_count(&session, "malformed_length"),
            malformed_counter_before,
            "flags errors must not increment the malformed_length metric"
        );
        assert_single_malformed_disposition(&session, "treat_as_withdraw");
    }
}

#[test]
fn rib_staged_otc_denial_publishes_existing_egress_diagnostics() {
    let mut session = make_test_session(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Customer);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let sink = install_recording_sink(&mut session);
    let route = replace_route_attrs(
        &make_route(100),
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![64512])],
            }),
            otc(64512),
        ],
    );
    let blocked_before = session.otc_routes_blocked;
    let mut update = empty_outbound_update();
    update.otc_blocked.push(route.clone());

    session.send_route_update(update);

    assert_eq!(session.otc_routes_blocked, blocked_before + 1);
    let events = sink.snapshot();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].direction, crate::event_sink::OtcDirection::Egress);
    assert_eq!(events[0].reason.as_str(), "egress_to_upstream_via_otc");
    assert_eq!(events[0].prefixes, vec![route.prefix.to_string()]);
    assert_eq!(events[0].otc_value, Some(64512));
}

#[tokio::test]
async fn otc_ingress_provider_publishes_structured_event() {
    // I1: Provider/RouteServer receives OTC-tagged unicast from a
    // Customer/RouteServerClient — the legacy counter increments and
    // a single `OtcRouteBlockedEvent` should be published with the
    // matching reason, the announced prefixes, both role labels, and
    // the decoded OTC value.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let sink = install_recording_sink(&mut session);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 64999])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        otc(65002),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let events = sink.snapshot();
    assert_eq!(events.len(), 1, "exactly one event per blocked UPDATE");
    let event = &events[0];
    assert_eq!(event.reason.as_str(), "ingress_from_customer_rsclient");
    assert_eq!(event.direction, crate::event_sink::OtcDirection::Ingress);
    assert_eq!(event.prefixes, vec![prefix.to_string()]);
    assert_eq!(event.local_role, Some(BgpRole::Provider));
    assert_eq!(event.otc_value, Some(65002));
    // AS_PATH stays lossless via `to_aspath_string`.
    assert_eq!(event.as_path, "65002 64999");
}

#[tokio::test]
async fn otc_ingress_peer_mismatch_publishes_structured_event() {
    // I2: Peer role with OTC ASN != peer ASN.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Peer);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let sink = install_recording_sink(&mut session);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        // OTC ASN 64512 disagrees with the peer's negotiated ASN
        // (65002). RFC 9234 §5 says to reject.
        otc(64512),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let events = sink.snapshot();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.reason.as_str(), "ingress_peer_mismatch");
    assert_eq!(event.otc_value, Some(64512));
    assert_eq!(event.local_role, Some(BgpRole::Peer));
}

#[tokio::test]
async fn otc_ingress_malformed_publishes_structured_event_with_no_otc_value() {
    // Malformed OTC length: the codec cannot decode an ASN, so the
    // event's otc_value field is None.
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let sink = install_recording_sink(&mut session);
    let announced_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
            flags: rustbgpd_wire::constants::attr_flags::OPTIONAL
                | rustbgpd_wire::constants::attr_flags::TRANSITIVE,
            type_code: rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER,
            data: Bytes::from_static(&[0, 0, 0]),
        }),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: announced_prefix,
        }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    let events = sink.snapshot();
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event.reason.as_str(), "malformed_length");
    assert!(
        event.otc_value.is_none(),
        "malformed_length must not surface a decoded OTC value"
    );
    assert_eq!(event.local_role, None);
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_single_malformed_disposition(&session, "treat_as_withdraw");
}

#[tokio::test]
async fn otc_ingress_truncated_framing_publishes_malformed_length_diagnostics() {
    let cases = [
        ("ordinary length", &[0xc0, 35][..]),
        ("ordinary value", &[0xc0, 35, 4, 0, 0, 1][..]),
        ("extended length", &[0xd0, 35, 0][..]),
        ("extended value", &[0xd0, 35, 0, 4, 0, 0, 1][..]),
    ];
    for (index, (case, malformed_otc)) in cases.into_iter().enumerate() {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        session.config.peer.local_role = None;
        let (client, _server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        rfc7606_drain(&mut rib_rx);
        let sink = install_recording_sink(&mut session);
        let prefix = Ipv4Prefix::new(
            Ipv4Addr::new(203, 0, 113, u8::try_from(index + 1).unwrap()),
            32,
        );

        session
            .process_update(rfc7606_update(rfc7606_attr_bytes(&[]), &[prefix]))
            .await;
        assert!(
            matches!(
                rib_rx.try_recv(),
                Ok(RibUpdate::RoutesReceived { announced, .. }) if announced.len() == 1
            ),
            "{case}: expected the clean route to be accepted"
        );

        let blocked_before = session.otc_routes_blocked;
        let malformed_counter_before = otc_routes_blocked_count(&session, "malformed_length");
        session
            .process_update(rfc7606_update(rfc7606_attr_bytes(malformed_otc), &[prefix]))
            .await;
        let RibUpdate::RoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().unwrap()
        else {
            panic!("{case}: truncated OTC framing must reach the RIB as a withdrawal");
        };
        assert!(announced.is_empty(), "{case}");
        assert_eq!(withdrawn, vec![(Prefix::V4(prefix), 0)], "{case}");
        assert_eq!(session.otc_routes_blocked, blocked_before + 1, "{case}");
        assert_eq!(
            otc_routes_blocked_count(&session, "malformed_length"),
            malformed_counter_before + 1,
            "{case}"
        );
        let events = sink.snapshot();
        assert_eq!(events.len(), 1, "{case}");
        assert_eq!(
            events[0].reason,
            rustbgpd_telemetry::reason_labels::OtcBlockReason::MalformedLength,
            "{case}"
        );
        assert_eq!(events[0].prefixes, vec![prefix.to_string()], "{case}");
        assert_eq!(events[0].local_role, None, "{case}");
        assert_eq!(events[0].otc_value, None, "{case}");
        assert_eq!(session.fsm.state(), SessionState::Established, "{case}");
        assert_single_malformed_disposition(&session, "treat_as_withdraw");
    }
}

#[tokio::test]
async fn otc_ingress_event_collects_mp_reach_v6_prefixes() {
    // Regression: the event's prefix list must include IPv6 unicast
    // MP_REACH_NLRI announcements, not just IPv4 body NLRI. Otherwise
    // an operator reading the event would see "blocked 0 prefixes" on
    // an IPv6-only OTC violation.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    install_dual_stack_session(&mut session, false);
    let sink = install_recording_sink(&mut session);
    let v6_prefix = Ipv6Prefix::new(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32);
    let mp_reach = rustbgpd_wire::MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        link_local_next_hop: None,
        announced: vec![rustbgpd_wire::NlriEntry {
            path_id: 0,
            prefix: Prefix::V6(v6_prefix),
        }],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    };
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        otc(65002),
        PathAttribute::MpReachNlri(mp_reach),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    let events = sink.snapshot();
    assert_eq!(events.len(), 1);
    assert!(
        events[0]
            .prefixes
            .iter()
            .any(|p| p == &v6_prefix.to_string()),
        "OtcRouteBlockedEvent must surface MP_REACH IPv6 announcements"
    );
}

#[tokio::test]
async fn otc_ingress_event_excludes_unnegotiated_mp_unicast() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let sink = install_recording_sink(&mut session);
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let v6_prefix = Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 48);
    let mp_reach = rustbgpd_wire::MpReachNlri {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        link_local_next_hop: None,
        announced: vec![rustbgpd_wire::NlriEntry {
            path_id: 0,
            prefix: Prefix::V6(v6_prefix),
        }],
        flowspec_announced: vec![],
        evpn_announced: vec![],
        bgpls_announced: vec![],
        labeled_announced: vec![],
        vpn_announced: vec![],
        rtc_announced: vec![],
    };
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        otc(65002),
        PathAttribute::MpReachNlri(mp_reach),
    ];
    let blocked_before = session.otc_routes_blocked;
    let otc_counter_before = otc_routes_blocked_count(&session, "ingress_from_customer_rsclient");
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: v4_prefix,
            }],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;

    assert_eq!(session.otc_routes_blocked, blocked_before + 1);
    assert_eq!(
        otc_routes_blocked_count(&session, "ingress_from_customer_rsclient"),
        otc_counter_before + 1
    );
    let events = sink.snapshot();
    assert_eq!(events.len(), 1);
    assert_eq!(
        events[0].reason,
        rustbgpd_telemetry::reason_labels::OtcBlockReason::IngressFromCustomerRsclient
    );
    assert_eq!(events[0].prefixes, vec![v4_prefix.to_string()]);
    assert!(!events[0].prefixes.contains(&v6_prefix.to_string()));
}

#[tokio::test]
async fn otc_ingress_malformed_without_reachable_nlri_resets_without_block_event() {
    // RFC 7606 §5.2: a malformed-length OTC UPDATE with no reachable
    // NLRI must reset rather than applying a vacuous treat-as-withdraw.
    // The OTC event contract still forbids a zero-prefix block event.
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = None;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    rfc7606_drain(&mut rib_rx);
    let sink = install_recording_sink(&mut session);
    let baseline_blocked = session.otc_routes_blocked;
    let baseline_malformed_counter = otc_routes_blocked_count(&session, "malformed_length");
    let withdrawn_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let mut withdrawn = Vec::new();
    rustbgpd_wire::nlri::encode_nlri(&[withdrawn_prefix], &mut withdrawn);
    // No announced NLRI — only the withdrawal.
    let update = UpdateMessage {
        withdrawn_routes: Bytes::from(withdrawn),
        path_attributes: Bytes::from(rfc7606_attr_bytes(&[0xc0, 35])),
        nlri: Bytes::new(),
    };
    session.process_update(update).await;
    assert!(
        sink.snapshot().is_empty(),
        "no announced unicast → no structured OtcRouteBlockedEvent"
    );
    assert_eq!(
        session.otc_routes_blocked, baseline_blocked,
        "rejected=0 must not bump the per-peer counter"
    );
    assert_eq!(
        otc_routes_blocked_count(&session, "malformed_length"),
        baseline_malformed_counter,
        "no reachable NLRI must not bump the malformed_length metric"
    );
    assert_ne!(session.fsm.state(), SessionState::Established);
    while let Ok(update) = rib_rx.try_recv() {
        assert!(!matches!(update, RibUpdate::RoutesReceived { .. }));
    }
    assert_single_malformed_disposition(&session, "session_reset");
}

#[tokio::test]
async fn otc_ingress_no_event_when_no_decision() {
    // Untagged UPDATE from a customer arrives at a Customer-role
    // local — no OTC rule fires, so the sink must stay empty.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Customer);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let sink = install_recording_sink(&mut session);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    assert!(
        sink.snapshot().is_empty(),
        "OTC sink must stay silent when no decision fired"
    );
}

/// Load-bearing role-independent propagation proof: valid canonical and
/// Partial-bearing OTC stay typed across decode, import policy, the RIB
/// handoff, and ordinary egress preparation when no local Role is configured.
#[tokio::test]
async fn otc_roleless_canonical_and_partial_roundtrip_ingress_rib_egress_bytes() {
    for partial in [false, true] {
        let (mut inbound, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        inbound.config.peer.local_role = None;
        install_test_negotiated_session(&mut inbound, negotiated_session(65002, false));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            if partial {
                PathAttribute::OnlyToCustomerPartial(64_512)
            } else {
                PathAttribute::OnlyToCustomer(64_512)
            },
        ];
        inbound
            .process_update(UpdateMessage::build(
                &[Ipv4NlriEntry { path_id: 0, prefix }],
                &[],
                &attrs,
                true,
                false,
                Ipv4UnicastMode::Body,
            ))
            .await;
        let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
            panic!("valid role-less OTC must reach the RIB");
        };
        let [route] = announced.as_slice() else {
            panic!("expected one accepted route");
        };
        assert!(route.attributes.iter().any(|attr| match attr {
            PathAttribute::OnlyToCustomer(asn) => *asn == 64_512 && !partial,
            PathAttribute::OnlyToCustomerPartial(asn) => *asn == 64_512 && partial,
            _ => false,
        }));

        let mut outbound = make_test_session(65003, 65004);
        outbound.config.peer.local_role = None;
        assert!(!outbound.otc_egress_blocks_unicast(route));
        let emitted_attrs =
            outbound.prepare_outbound_attributes(route, true, Ipv4Addr::new(10, 0, 0, 3), None);
        let bytes = UpdateMessage::build(
            &[Ipv4NlriEntry { path_id: 0, prefix }],
            &[],
            &emitted_attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        )
        .path_attributes;
        let expected = [
            rustbgpd_wire::constants::attr_flags::OPTIONAL
                | rustbgpd_wire::constants::attr_flags::TRANSITIVE
                | if partial {
                    rustbgpd_wire::constants::attr_flags::PARTIAL
                } else {
                    0
                },
            rustbgpd_wire::constants::attr_type::ONLY_TO_CUSTOMER,
            4,
            0,
            0,
            0xfc,
            0x00,
        ];
        assert!(
            bytes
                .windows(expected.len())
                .any(|window| window == expected),
            "role-less egress must preserve typed OTC flags and bytes"
        );
    }
}
