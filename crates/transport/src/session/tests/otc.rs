use super::*;

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
            PathAttribute::OnlyToCustomer(64512),
        ],
    );
    let attrs = session.prepare_outbound_attributes(&route, true, Ipv4Addr::new(10, 0, 0, 1), None);
    let otcs: Vec<u32> = attrs
        .iter()
        .filter_map(|a| match a {
            PathAttribute::OnlyToCustomer(asn) => Some(*asn),
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
                PathAttribute::OnlyToCustomer(65002),
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
        session.negotiated = Some(negotiated_session(65002, false));
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
        session.negotiated = Some(negotiated_session(65002, false));
        let announced_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let withdrawn_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::OnlyToCustomer(65002),
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
            attrs.push(PathAttribute::OnlyToCustomer(65002));
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
    session.negotiated = Some(negotiated_session(65002, false));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::OnlyToCustomer(64512),
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
    session.config.peer.local_role = Some(BgpRole::Provider);
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    let announced_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let overlap_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
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
    assert_eq!(session.known_prefix_count(), 0);
}

#[test]
fn rib_staged_otc_denial_publishes_existing_egress_diagnostics() {
    let mut session = make_test_session(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Customer);
    session.negotiated = Some(negotiated_session(65002, false));
    let sink = install_recording_sink(&mut session);
    let route = replace_route_attrs(
        &make_route(100),
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![64512])],
            }),
            PathAttribute::OnlyToCustomer(64512),
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
    session.negotiated = Some(negotiated_session(65002, false));
    let sink = install_recording_sink(&mut session);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 64999])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        PathAttribute::OnlyToCustomer(65002),
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
    session.negotiated = Some(negotiated_session(65002, false));
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
        PathAttribute::OnlyToCustomer(64512),
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
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.negotiated = Some(negotiated_session(65002, false));
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
}

#[tokio::test]
async fn otc_ingress_event_collects_mp_reach_v6_prefixes() {
    // Regression: the event's prefix list must include IPv6 unicast
    // MP_REACH_NLRI announcements, not just IPv4 body NLRI. Otherwise
    // an operator reading the event would see "blocked 0 prefixes" on
    // an IPv6-only OTC violation.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.negotiated = Some(negotiated_session(65002, false));
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
        PathAttribute::OnlyToCustomer(65002),
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
async fn otc_ingress_skips_event_when_rejected_count_is_zero() {
    // Regression: a malformed-length OTC UPDATE that carries only
    // withdrawals (no announced unicast) must not produce a
    // zero-count OtcRouteBlockedEvent — the proto contract is
    // "blocks one or more unicast routes". The withdrawal still
    // processes through the normal path; only the structured event
    // and the per-peer counter bump are skipped.
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Provider);
    session.negotiated = Some(negotiated_session(65002, false));
    let sink = install_recording_sink(&mut session);
    let baseline_blocked = session.otc_routes_blocked;
    let withdrawn_prefix = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
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
    // No announced NLRI — only the withdrawal.
    let update = UpdateMessage::build(
        &[],
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
    assert!(
        sink.snapshot().is_empty(),
        "no announced unicast → no structured OtcRouteBlockedEvent"
    );
    assert_eq!(
        session.otc_routes_blocked, baseline_blocked,
        "rejected=0 must not bump the per-peer counter"
    );
    // Withdrawal still surfaces through the RIB path.
    let RibUpdate::RoutesReceived { withdrawn, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(withdrawn, vec![(Prefix::V4(withdrawn_prefix), 0)]);
}

#[tokio::test]
async fn otc_ingress_no_event_when_no_decision() {
    // Untagged UPDATE from a customer arrives at a Customer-role
    // local — no OTC rule fires, so the sink must stay empty.
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.local_role = Some(BgpRole::Customer);
    session.negotiated = Some(negotiated_session(65002, false));
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
