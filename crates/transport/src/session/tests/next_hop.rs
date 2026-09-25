use super::*;

#[tokio::test]
async fn process_update_accepts_ipv4_mp_link_local_for_scoped_unnumbered_peer() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let negotiated = negotiated_session(65002, true);
    session.negotiated = Some(Arc::new(negotiated));
    let next_hop: Ipv6Addr = "fe80::1".parse().unwrap();
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6(next_hop),
            link_local_next_hop: Some(next_hop),
            announced: vec![NlriEntry {
                path_id: 0,
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach);
    session.process_update(update).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].next_hop, IpAddr::V6(next_hop));
    assert_eq!(announced[0].link_local_next_hop, Some(next_hop));
    let scope = announced[0]
        .next_hop_scope
        .as_ref()
        .expect("link-local next-hop must carry scope toward FIB");
    assert_eq!(scope.interface.as_ref(), "eth1");
    assert_eq!(scope.ifindex, 7);
}

#[tokio::test]
async fn import_policy_next_hop_rewrite_clears_ipv4_mp_link_local_companion() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let negotiated = negotiated_session(65002, true);
    session.negotiated = Some(Arc::new(negotiated));
    let replacement_next_hop: IpAddr = "2001:db8::99".parse().unwrap();
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![PolicyStatement {
            prefix: None,
            ge: None,
            le: None,
            action: PolicyAction::Permit,
            match_community: vec![],
            match_as_path: None,
            match_neighbor_set: None,
            match_route_type: None,
            match_evpn_route_type: None,
            match_rpki_validation: None,
            match_aspa_validation: None,
            match_as_path_length_ge: None,
            match_as_path_length_le: None,
            match_local_pref_ge: None,
            match_local_pref_le: None,
            match_med_ge: None,
            match_med_le: None,
            match_next_hop: None,
            modifications: RouteModifications {
                set_next_hop: Some(rustbgpd_policy::NextHopAction::Specific(
                    replacement_next_hop,
                )),
                ..Default::default()
            },
        }],
        default_action: PolicyAction::Deny,
    }])));
    let received_next_hop: Ipv6Addr = "fe80::1".parse().unwrap();
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6(received_next_hop),
            link_local_next_hop: Some(received_next_hop),
            announced: vec![NlriEntry {
                path_id: 0,
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach);
    session.process_update(update).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(announced[0].next_hop, replacement_next_hop);
    assert_eq!(announced[0].link_local_next_hop, None);
    assert_eq!(announced[0].next_hop_scope, None);
}

/// A scoped link-local peer that did not negotiate Extended Next Hop must
/// not import an IPv4-over-IPv6 link-local `MP_REACH`. Without RFC 8950 the
/// 32-octet next hop is not the expected length (RFC 7606 §7.11), so the
/// session resets rather than dropping the route silently. The positive case
/// is `process_update_accepts_ipv4_mp_link_local_for_scoped_unnumbered_peer`.
#[tokio::test]
async fn process_update_rejects_ipv4_mp_link_local_without_extended_nexthop() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    rfc7606_drain(&mut rib_rx);
    let next_hop: Ipv6Addr = "fe80::1".parse().unwrap();
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            next_hop: IpAddr::V6(next_hop),
            link_local_next_hop: Some(next_hop),
            announced: vec![NlriEntry {
                path_id: 0,
                prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach);
    session.process_update(update).await;
    while let Ok(message) = rib_rx.try_recv() {
        assert!(
            !matches!(message, RibUpdate::RoutesReceived { .. }),
            "no route may reach the RIB"
        );
    }
    assert_ne!(session.fsm.state(), SessionState::Established);
    let notification = read_until_notification(&mut server).await;
    assert_eq!(
        notification.code,
        rustbgpd_wire::notification::NotificationCode::UpdateMessage
    );
    assert_eq!(
        notification.subcode,
        rustbgpd_wire::notification::update_subcode::OPTIONAL_ATTRIBUTE_ERROR
    );
}

/// ADR-0107 strict-peer ownership covers IPv4 `MP_REACH` with a 4-octet
/// next hop on a session without Extended Next Hop, now that the form is
/// imported: a foreign next hop must be rejected, not slip past the gate.
#[tokio::test]
async fn strict_peer_next_hop_rejects_foreign_ipv4_mp_without_extended_nexthop() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.next_hop_ownership_strict_peer = true;
    install_test_negotiated_session(&mut session, negotiated_session(65002, false));
    let update = |next_hop: Ipv4Addr| {
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                next_hop: IpAddr::V4(next_hop),
                link_local_next_hop: None,
                announced: vec![NlriEntry {
                    path_id: 0,
                    prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
                }],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            }),
        ];
        UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach)
    };
    session
        .process_update(update(Ipv4Addr::new(10, 0, 0, 2)))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1, "conforming next hop must be accepted");
    session
        .process_update(update(Ipv4Addr::new(10, 0, 0, 9)))
        .await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx.try_recv().unwrap()
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty(), "foreign next hop must be rejected");
    assert_eq!(
        withdrawn,
        vec![(
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
            0
        )]
    );
}

#[tokio::test]
async fn process_update_ignores_ipv4_body_nlri_for_scoped_unnumbered_peer() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let negotiated = negotiated_session(65002, true);
    session.negotiated = Some(Arc::new(negotiated));
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1)),
    ];
    let update = UpdateMessage::build(
        &[],
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
        }],
        &attrs,
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    session.process_update(update).await;
    assert!(
        rib_rx.try_recv().is_err(),
        "scoped link-local peers must not import IPv4 body NLRI"
    );
}

#[tokio::test]
async fn route_server_client_extended_nexthop_preserves_ipv6_next_hop() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.route_server_client = true;
    let negotiated = negotiated_session(65002, true);
    session.negotiated = Some(Arc::new(negotiated));
    let v6_nh: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let update = OutboundRouteUpdate {
        replay: None,
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: IpAddr::V6(v6_nh),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
            ]),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }]
        .into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(mp.afi, Afi::Ipv4);
    assert_eq!(mp.safi, Safi::Unicast);
    assert_eq!(mp.next_hop, IpAddr::V6(v6_nh));
}

#[tokio::test]
async fn unnumbered_ipv4_extended_nexthop_sends_link_local_mp_reach() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, true);
    session.negotiated = Some(Arc::new(negotiated));
    let update = OutboundRouteUpdate {
        replay: None,
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![make_route(100)].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("IPv4 unnumbered must use MP_REACH");
    let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
    assert_eq!(mp.afi, Afi::Ipv4);
    assert_eq!(mp.safi, Safi::Unicast);
    assert_eq!(mp.next_hop, IpAddr::V6(link_local));
    assert_eq!(mp.link_local_next_hop, Some(link_local));
}

#[tokio::test]
async fn unnumbered_ipv4_recomputes_link_local_companion_after_next_hop_self() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, true);
    session.negotiated = Some(Arc::new(negotiated));
    let remote_ll: Ipv6Addr = "fe80::2".parse().unwrap();
    let mut route = make_route(100);
    route.next_hop = IpAddr::V6(remote_ll);
    route.link_local_next_hop = Some(remote_ll);
    let update = OutboundRouteUpdate {
        replay: None,
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![route].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("IPv4 unnumbered must use MP_REACH");
    let local_ll: Ipv6Addr = "fe80::1".parse().unwrap();
    assert_eq!(mp.next_hop, IpAddr::V6(local_ll));
    assert_eq!(
        mp.link_local_next_hop,
        Some(local_ll),
        "next-hop-self must not preserve the original remote link-local companion"
    );
}

#[tokio::test]
async fn extended_nexthop_clears_companion_when_primary_next_hop_is_rewritten() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, true);
    session.negotiated = Some(Arc::new(negotiated));
    let mut route = make_route(100);
    route.next_hop = IpAddr::V6("2001:db8::2".parse().unwrap());
    route.link_local_next_hop = Some("fe80::2".parse().unwrap());
    let update = OutboundRouteUpdate {
        replay: None,
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![route].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("IPv4 extended next-hop must use MP_REACH");
    assert_eq!(mp.next_hop, IpAddr::V6("2001:db8::1".parse().unwrap()));
    assert_eq!(
        mp.link_local_next_hop, None,
        "stale link-local companion must be cleared when the primary next-hop changes"
    );
}

#[tokio::test]
async fn unnumbered_ipv4_without_extended_nexthop_does_not_fallback_to_body_nlri() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session.negotiated = Some(Arc::new(negotiated));
    let update = OutboundRouteUpdate {
        replay: None,
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![make_route(100)].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    };
    session.send_route_update(update);
    let mut header = [0_u8; 19];
    let result =
        tokio::time::timeout(Duration::from_millis(100), server.read_exact(&mut header)).await;
    assert!(
        result.is_err(),
        "scoped link-local peer must fail closed instead of sending IPv4 body NLRI"
    );
}

#[tokio::test]
async fn ipv4_route_with_ipv6_next_hop_gates_reflection_on_extended_nexthop() {
    let mut route = make_route(100);
    route.next_hop = "2001:db8::1".parse().unwrap();
    Arc::make_mut(&mut route.attributes).retain(|attr| !matches!(attr, PathAttribute::NextHop(_)));

    for (remote_asn, route_server_client) in [(65001, false), (65002, true)] {
        for extended_nexthop in [true, false] {
            let (mut session, _rib_rx) = make_test_session_with_rib(65001, remote_asn);
            session.config.route_server_client = route_server_client;
            session.negotiated = Some(Arc::new(negotiated_session(remote_asn, extended_nexthop)));
            let profile = session.publish_export_profile();
            let result = profile.probe_announcement(ExportCandidate::Unicast {
                route: &route,
                next_hop_override: None,
            });
            if extended_nexthop {
                result.unwrap();
                let export::PreparedUnicastCandidate::Mp { next_hop, .. } =
                    profile.prepare_unicast_candidate(&route, None).unwrap()
                else {
                    panic!("IPv6 next-hop reflection must use MP_REACH");
                };
                assert_eq!(next_hop, route.next_hop);
            } else {
                let Err(error) = result else {
                    panic!("unchanged IPv6 next-hop requires Extended Next Hop");
                };
                assert_eq!(error, ExportProbeError::Ipv4RequiresExtendedNextHop);
            }
        }
    }
}

#[tokio::test]
async fn ipv4_route_with_ipv6_next_hop_allows_ipv4_rewrite_without_extended_nexthop() {
    use rustbgpd_policy::NextHopAction;

    let mut route = make_route(100);
    route.next_hop = "2001:db8::1".parse().unwrap();
    Arc::make_mut(&mut route.attributes).retain(|attr| !matches!(attr, PathAttribute::NextHop(_)));
    let local_ipv4 = Ipv4Addr::new(10, 0, 0, 1);
    let specific_ipv4 = Ipv4Addr::new(192, 0, 2, 99);

    for (remote_asn, route_server_client, nh_override, expected) in [
        (65002, false, None, local_ipv4),
        (65001, false, Some(NextHopAction::Self_), local_ipv4),
        (65002, true, Some(NextHopAction::Self_), local_ipv4),
        (
            65001,
            false,
            Some(NextHopAction::Specific(IpAddr::V4(specific_ipv4))),
            specific_ipv4,
        ),
    ] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, remote_asn);
        session.config.route_server_client = route_server_client;
        session.negotiated = Some(Arc::new(negotiated_session(remote_asn, false)));
        let profile = session.publish_export_profile();
        profile
            .probe_announcement(ExportCandidate::Unicast {
                route: &route,
                next_hop_override: nh_override.as_ref(),
            })
            .unwrap();
        let export::PreparedUnicastCandidate::Ipv4Body { attrs, .. } = profile
            .prepare_unicast_candidate(&route, nh_override.as_ref())
            .unwrap()
        else {
            panic!("IPv4 rewrite without Extended Next Hop must use body NLRI");
        };
        assert!(attrs.contains(&PathAttribute::NextHop(expected)));
    }
}

#[tokio::test]
async fn route_server_client_ipv6_preserves_next_hop() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.route_server_client = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session.negotiated = Some(Arc::new(negotiated));
    let v6_nh: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let update = OutboundRouteUpdate {
        replay: None,
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![Route {
            prefix: Prefix::V6(Ipv6Prefix::new(v6_nh, 64)),
            next_hop: IpAddr::V6(v6_nh),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
            ]),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }]
        .into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(mp.afi, Afi::Ipv6);
    assert_eq!(mp.safi, Safi::Unicast);
    assert_eq!(mp.next_hop, IpAddr::V6(v6_nh));
    assert_eq!(mp.link_local_next_hop, None);
}

#[tokio::test]
async fn ipv6_next_hop_self_clears_stale_link_local_companion() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session.negotiated = Some(Arc::new(negotiated));
    let remote_global: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let mut route = make_v6_unicast_route(remote_global);
    route.link_local_next_hop = Some("fe80::2".parse().unwrap());
    let update = OutboundRouteUpdate {
        replay: None,
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![route].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(mp.afi, Afi::Ipv6);
    assert_eq!(mp.safi, Safi::Unicast);
    assert_eq!(mp.next_hop, IpAddr::V6("2001:db8::1".parse().unwrap()));
    assert_eq!(
        mp.link_local_next_hop, None,
        "IPv6 next-hop-self must not preserve an upstream link-local companion"
    );
}

#[tokio::test]
async fn scoped_peer_does_not_send_ipv6_unicast_with_link_local_primary_next_hop() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
    configure_scoped_link_local_peer(&mut session);
    session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65001, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session.negotiated = Some(Arc::new(negotiated));
    let route_next_hop = "2001:db8::2".parse().unwrap();
    let update = OutboundRouteUpdate {
        replay: None,
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![make_v6_unicast_route(route_next_hop)].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![Some(rustbgpd_policy::NextHopAction::Self_)].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        rtc_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    };
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(mp.next_hop, IpAddr::V6(route_next_hop));
    assert_eq!(
        mp.link_local_next_hop, None,
        "IPv6 unicast must not reuse the IPv4 ENHE scoped link-local relaxation"
    );
}

/// ADR-0107 strict-peer `NEXT_HOP` ownership, classic IPv4 body NLRI: a
/// conforming next-hop (the session's own address) is accepted; a foreign
/// next-hop is rejected pre-policy — withdrawals from the same UPDATE
/// still flow, a previously accepted identity is retired treat-as-withdraw
/// style, and a first-seen rejection stays silent. The spoofed UPDATE
/// carries RFC 7999 BLACKHOLE, pinning ADR-0107 §5: a community is never
/// an ownership bypass. Break-to-red: eager prototype construction fails the
/// conforming zero count; per-identity ownership construction fails count one.
#[tokio::test]
async fn strict_peer_next_hop_rejects_foreign_ipv4_body_and_withdraws_replacement() {
    use rustbgpd_telemetry::reason_labels::ImportRejectReason;

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.next_hop_ownership_strict_peer = true;
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let accepted = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
    let first_seen = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let withdrawn_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
    let attrs = |next_hop: Ipv4Addr, blackhole: bool| {
        let mut attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(next_hop),
        ];
        if blackhole {
            // RFC 7999 BLACKHOLE (65535:666).
            attrs.push(PathAttribute::Communities(vec![0xFFFF_029A]));
        }
        attrs
    };
    // Conforming: the wire next-hop is the advertising session's address.
    session
        .process_update(UpdateMessage::build(
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: accepted,
            }],
            &[],
            &attrs(Ipv4Addr::new(10, 0, 0, 2), false),
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(
        announced.len(),
        1,
        "conforming next-hop must be accepted under strict_peer"
    );
    assert_eq!(rejected_route_prototype_builds(&session), 0);
    // Foreign next-hop (another member's address) + BLACKHOLE: rejected
    // pre-policy; the accepted identity is withdrawn, the first-seen one
    // stays silent, and the explicit withdrawal is preserved.
    session
        .process_update(UpdateMessage::build(
            &[
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: accepted,
                },
                Ipv4NlriEntry {
                    path_id: 0,
                    prefix: first_seen,
                },
            ],
            &[Ipv4NlriEntry {
                path_id: 0,
                prefix: withdrawn_prefix,
            }],
            &attrs(Ipv4Addr::new(10, 0, 0, 9), true),
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
        panic!("expected RoutesReceived");
    };
    assert!(
        announced.is_empty(),
        "foreign next-hop must be rejected even with BLACKHOLE attached"
    );
    assert_eq!(withdrawn.len(), 2);
    assert!(withdrawn.contains(&(Prefix::V4(withdrawn_prefix), 0)));
    assert!(
        withdrawn.contains(&(Prefix::V4(accepted), 0)),
        "rejected replacement must retire the exact prior identity"
    );
    assert!(
        !withdrawn.contains(&(Prefix::V4(first_seen), 0)),
        "first-seen rejections must stay silent"
    );
    assert_eq!(session.known_prefix_count(), 0);
    let retained = session.rejected_routes.snapshot();
    assert_eq!(retained.len(), 2);
    assert_eq!(retained[0].1.rejected_at, retained[1].1.rejected_at);
    assert_eq!(rejected_route_prototype_builds(&session), 1);
    for (key, entry) in retained {
        assert!(
            key == retention_key(accepted) || key == retention_key(first_seen),
            "ownership retention must keep each rejected identity"
        );
        assert_eq!(entry.reason, ImportRejectReason::NextHopOwnership);
        assert_eq!(entry.next_hop, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))));
    }
}

/// ADR-0107 strict-peer over MP IPv6 unicast: a conforming global
/// next-hop is accepted; a foreign one is rejected with exact replacement
/// withdrawal and explain tombstones (mirrors the OTC sibling test).
#[expect(
    clippy::too_many_lines,
    reason = "pins conforming acceptance, foreign rejection, replacement withdrawal, first-seen gating, and explain tombstones in one flow"
)]
#[tokio::test]
async fn strict_peer_next_hop_rejects_foreign_ipv6_mp_and_withdraws_replacement() {
    use super::import_decision_cache::{CachedOutcome, ImportDecisionKey, LookupResult};
    use rustbgpd_wire::{MpReachNlri, NlriEntry};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.next_hop_ownership_strict_peer = true;
    session.import_explain_enabled = true;
    session.peer_ip = "2001:db8::2".parse().unwrap();
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);
    let accepted = Prefix::V6(Ipv6Prefix::new("2001:db8:473:1::".parse().unwrap(), 64));
    let first_seen = Prefix::V6(Ipv6Prefix::new("2001:db8:473:2::".parse().unwrap(), 64));
    let attrs = |next_hop: &str, announced: Vec<NlriEntry>| {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: next_hop.parse().unwrap(),
                link_local_next_hop: None,
                announced,
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            }),
        ]
    };
    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &attrs(
                "2001:db8::2",
                vec![NlriEntry {
                    path_id: 0,
                    prefix: accepted,
                }],
            ),
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected conforming MP route accepted");
    };
    assert_eq!(announced.len(), 1);

    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &attrs(
                "2001:db8::99",
                vec![
                    NlriEntry {
                        path_id: 0,
                        prefix: accepted,
                    },
                    NlriEntry {
                        path_id: 0,
                        prefix: first_seen,
                    },
                ],
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
        .expect("accepted replacement must become a withdrawal")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![(accepted, 0)]);
    assert_eq!(session.known_prefix_count(), 0);
    assert!(
        rib_rx.try_recv().is_err(),
        "first-seen rejects must stay silent"
    );
    let key = |prefix| ImportDecisionKey {
        afi: Afi::Ipv6,
        safi: Safi::Unicast,
        prefix,
        path_id: 0,
    };
    match session
        .import_decision_cache
        .lookup(&key(accepted), session.import_policy_generation)
    {
        LookupResult::Hit(decision) => {
            assert_eq!(decision.outcome, CachedOutcome::Withdrawn);
        }
        other => panic!("expected ownership-withdrawn {accepted}, got {other:?}"),
    }
    assert!(matches!(
        session
            .import_decision_cache
            .lookup(&key(first_seen), session.import_policy_generation),
        LookupResult::NotSeen
    ));
}

/// An IPv4 session cannot own an IPv6 `MP_REACH_NLRI` next hop; strict-peer
/// rejects the replacement as foreign and retires an existing route.
#[tokio::test]
async fn strict_peer_ipv4_session_rejects_ipv6_mp_replacement() {
    use rustbgpd_telemetry::reason_labels::ImportRejectReason;
    use rustbgpd_wire::{MpReachNlri, NlriEntry};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:737::".parse().unwrap(), 48));
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            next_hop: "2001:db8::2".parse().unwrap(),
            link_local_next_hop: None,
            announced: vec![NlriEntry { path_id: 0, prefix }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected initial route");
    };
    assert_eq!(announced.len(), 1);

    session.config.next_hop_ownership_strict_peer = true;
    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &attrs,
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
        .expect("foreign replacement must withdraw")
    else {
        panic!("expected RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![(prefix, 0)]);
    let retained = session.rejected_routes.snapshot();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].1.reason, ImportRejectReason::NextHopOwnership);
    assert_eq!(retained[0].1.next_hop, Some("2001:db8::2".parse().unwrap()));
}

/// ADR-0107 §2: a global + link-local next-hop pair always fails closed
/// under the strict pilot — the companion cannot be mapped to the single
/// session address even when the global component matches, and it is
/// never silently ignored.
#[tokio::test]
async fn strict_peer_next_hop_rejects_link_local_companion_pair() {
    use rustbgpd_wire::{MpReachNlri, NlriEntry};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.next_hop_ownership_strict_peer = true;
    session.peer_ip = "2001:db8::2".parse().unwrap();
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
            // Global component matches the session; the link-local
            // companion is still unverifiable under strict_peer.
            next_hop: "2001:db8::2".parse().unwrap(),
            link_local_next_hop: Some("fe80::2".parse().unwrap()),
            announced: vec![NlriEntry {
                path_id: 0,
                prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:473:3::".parse().unwrap(), 64)),
            }],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    session
        .process_update(UpdateMessage::build(
            &[],
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        ))
        .await;
    assert!(
        rib_rx.try_recv().is_err(),
        "a paired link-local companion must fail closed under strict_peer"
    );
}

/// The ownership gate is opt-in: without `next_hop_ownership =
/// "strict_peer"` a third-party next-hop keeps flowing (RFC 7947
/// transparency), pinning that ADR-0107 changes nothing by default.
#[tokio::test]
async fn next_hop_ownership_disabled_by_default_accepts_foreign_next_hop() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 9)),
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
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(
        announced.len(),
        1,
        "default (unset) must preserve transparent behavior"
    );
}

/// Send one outbound update to an Extended Next Hop session and return the
/// raw UPDATE as written to the wire.
async fn send_extended_nexthop_update(
    route_server_client: bool,
    scoped: bool,
    announce: Vec<Route>,
    withdraw: Vec<(Prefix, u32)>,
) -> UpdateMessage {
    let next_hop_override = vec![None; announce.len()];
    send_unicast_update(
        true,
        route_server_client,
        scoped,
        announce,
        next_hop_override,
        withdraw,
    )
    .await
}

/// Send one outbound unicast update and return the raw UPDATE as written.
async fn send_unicast_update(
    extended_nexthop: bool,
    route_server_client: bool,
    scoped: bool,
    announce: Vec<Route>,
    next_hop_override: Vec<Option<rustbgpd_policy::NextHopAction>>,
    withdraw: Vec<(Prefix, u32)>,
) -> UpdateMessage {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    if scoped {
        configure_scoped_link_local_peer(&mut session);
    }
    session.config.route_server_client = route_server_client;
    session.config.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.negotiated = Some(Arc::new(negotiated_session(65002, extended_nexthop)));
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.next_hop_override = next_hop_override.into();
    update.announce = announce.into();
    update.withdraw = withdraw;
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    msg
}

/// `(type code, value)` for each attribute in an encoded path-attribute block.
fn attribute_values(mut attrs: &[u8]) -> Vec<(u8, &[u8])> {
    let mut out = Vec::new();
    while let [flags, code, rest @ ..] = attrs {
        let (len, rest) = if flags & 0x10 == 0 {
            (usize::from(rest[0]), &rest[1..])
        } else {
            (
                usize::from(u16::from_be_bytes([rest[0], rest[1]])),
                &rest[2..],
            )
        };
        out.push((*code, &rest[..len]));
        attrs = &rest[len..];
    }
    out
}

/// Attribute type codes present in an encoded path-attribute block.
fn attribute_type_codes(attrs: &[u8]) -> Vec<u8> {
    attribute_values(attrs)
        .into_iter()
        .map(|(code, _)| code)
        .collect()
}

#[tokio::test]
async fn extended_nexthop_ipv4_next_hop_uses_body_nlri() {
    // Route-server client route passed through with its IPv4 next hop.
    let msg = send_extended_nexthop_update(true, false, vec![make_route(100)], vec![]).await;
    assert!(msg.withdrawn_routes.is_empty());
    assert_eq!(&msg.nlri[..], &[24, 10, 0, 0], "10.0.0.0/24 in body NLRI");
    let codes = attribute_type_codes(&msg.path_attributes);
    assert!(!codes.contains(&14), "no MP_REACH_NLRI: {codes:?}");
    // NEXT_HOP: flags 0x40, type 3, length 4, 10.0.0.2.
    assert!(
        msg.path_attributes
            .windows(7)
            .any(|w| w == [0x40, 3, 4, 10, 0, 0, 2]),
        "classic NEXT_HOP 10.0.0.2 expected"
    );
}

#[tokio::test]
async fn extended_nexthop_ipv4_withdrawal_uses_body_withdrawn_routes() {
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let msg = send_extended_nexthop_update(true, false, vec![], vec![(prefix, 0)]).await;
    assert_eq!(&msg.withdrawn_routes[..], &[24, 10, 0, 0]);
    assert!(msg.path_attributes.is_empty(), "no MP_UNREACH_NLRI");
    assert!(msg.nlri.is_empty());
}

#[tokio::test]
async fn extended_nexthop_ipv6_next_hop_still_uses_mp_reach() {
    let mut route = make_route(100);
    route.next_hop = IpAddr::V6("2001:db8::2".parse().unwrap());
    Arc::make_mut(&mut route.attributes).retain(|attr| !matches!(attr, PathAttribute::NextHop(_)));
    let msg = send_extended_nexthop_update(true, false, vec![route], vec![]).await;
    assert!(msg.nlri.is_empty(), "IPv4 NLRI must stay in MP_REACH_NLRI");
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("MP_REACH_NLRI");
    assert_eq!((mp.afi, mp.safi), (Afi::Ipv4, Safi::Unicast));
    assert_eq!(mp.next_hop, IpAddr::V6("2001:db8::2".parse().unwrap()));
}

#[tokio::test]
async fn scoped_extended_nexthop_ipv4_withdrawal_stays_mp_unreach() {
    // Unnumbered receivers ignore IPv4 body NLRI, so the MP form stays.
    let prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24));
    let msg = send_extended_nexthop_update(false, true, vec![], vec![(prefix, 0)]).await;
    assert!(msg.withdrawn_routes.is_empty());
    assert_eq!(attribute_type_codes(&msg.path_attributes), vec![15]);
}

#[tokio::test]
async fn specific_ipv4_next_hop_override_is_the_body_next_hop() {
    // Source route carries NEXT_HOP 10.0.0.2; export policy sets 192.0.2.99.
    let set = Some(rustbgpd_policy::NextHopAction::Specific(IpAddr::V4(
        Ipv4Addr::new(192, 0, 2, 99),
    )));
    for extended_nexthop in [true, false] {
        let msg = send_unicast_update(
            extended_nexthop,
            true,
            false,
            vec![make_route(100)],
            vec![set.clone()],
            vec![],
        )
        .await;
        assert_eq!(&msg.nlri[..], &[24, 10, 0, 0], "ENH={extended_nexthop}");
        let codes = attribute_type_codes(&msg.path_attributes);
        assert!(!codes.contains(&14), "ENH={extended_nexthop}: {codes:?}");
        assert_eq!(
            codes.iter().position(|&c| c == 3),
            codes.iter().rposition(|&c| c == 3)
        );
        assert!(
            msg.path_attributes
                .windows(7)
                .any(|w| w == [0x40, 3, 4, 192, 0, 2, 99]),
            "ENH={extended_nexthop}: NEXT_HOP must carry the policy address"
        );
    }
}

#[tokio::test]
async fn extended_nexthop_mixed_batch_splits_ipv4_body_and_mp_exactly_once() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.route_server_client = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, true);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    session.negotiated = Some(Arc::new(negotiated));

    let v4_nh = make_route(100); // 10.0.0.0/24 via 10.0.0.2
    let mut v6_nh = make_route(100); // 10.1.0.0/24 via 2001:db8::2
    v6_nh.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 1, 0, 0), 24));
    v6_nh.next_hop = IpAddr::V6("2001:db8::2".parse().unwrap());
    Arc::make_mut(&mut v6_nh.attributes).retain(|attr| !matches!(attr, PathAttribute::NextHop(_)));
    let mut v6_route = v6_nh.clone(); // 2001:db8:5::/48 via 2001:db8::3
    v6_route.prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:5::".parse().unwrap(), 48));
    v6_route.next_hop = IpAddr::V6("2001:db8::3".parse().unwrap());
    let withdrawn = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 9, 0, 0), 24));

    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.next_hop_override = vec![None; 3].into();
    update.announce = vec![v4_nh, v6_nh, v6_route].into();
    update.withdraw = vec![(withdrawn, 0)];
    session.send_route_update(update);

    // Exactly four UPDATEs, in send order: body withdrawal, IPv4 body
    // announcement, IPv4 MP_REACH (IPv6 next hop), IPv6 MP_REACH.
    let mut msgs = Vec::new();
    for _ in 0..4 {
        let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
            panic!("expected UPDATE");
        };
        msgs.push(msg);
    }
    let mut header = [0_u8; 19];
    assert!(
        tokio::time::timeout(Duration::from_millis(100), server.read_exact(&mut header))
            .await
            .is_err(),
        "no fifth message"
    );

    assert_eq!(&msgs[0].withdrawn_routes[..], &[24, 10, 9, 0]);
    assert!(msgs[0].path_attributes.is_empty() && msgs[0].nlri.is_empty());

    assert!(msgs[1].withdrawn_routes.is_empty());
    assert_eq!(&msgs[1].nlri[..], &[24, 10, 0, 0]);
    let codes = attribute_type_codes(&msgs[1].path_attributes);
    assert!(!codes.contains(&14) && !codes.contains(&15), "{codes:?}");
    assert!(
        msgs[1]
            .path_attributes
            .windows(7)
            .any(|w| w == [0x40, 3, 4, 10, 0, 0, 2])
    );

    // MP_REACH value: AFI(2) SAFI(1) NH-len(1) NH reserved(1) NLRI.
    let mp_reach = |msg: &UpdateMessage| -> Vec<u8> {
        assert!(msg.withdrawn_routes.is_empty() && msg.nlri.is_empty());
        let attrs = attribute_values(&msg.path_attributes);
        assert!(!attrs.iter().any(|(code, _)| *code == 15));
        let mut reach = attrs.iter().filter(|(code, _)| *code == 14);
        let value = reach.next().expect("MP_REACH_NLRI").1.to_vec();
        assert!(reach.next().is_none(), "one MP_REACH_NLRI");
        value
    };
    let mut v4_mp = vec![0, 1, 1, 16];
    v4_mp.extend_from_slice(&"2001:db8::2".parse::<Ipv6Addr>().unwrap().octets());
    v4_mp.extend_from_slice(&[0, 24, 10, 1, 0]);
    assert_eq!(mp_reach(&msgs[2]), v4_mp);
    let mut v6_mp = vec![0, 2, 1, 16];
    v6_mp.extend_from_slice(&"2001:db8::3".parse::<Ipv6Addr>().unwrap().octets());
    v6_mp.extend_from_slice(&[0, 48, 0x20, 0x01, 0x0d, 0xb8, 0, 5]);
    assert_eq!(mp_reach(&msgs[3]), v6_mp);
}
