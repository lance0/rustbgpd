use super::*;
use rustbgpd_rib::AttrSet;

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
        PathAttribute::MpReachNlri(Box::new(MpReachNlri {
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
        })),
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
        PathAttribute::MpReachNlri(Box::new(MpReachNlri {
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
        })),
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
    let mut negotiated = negotiated_session(65002, false);
    negotiated.link_local_next_hop = true;
    install_test_negotiated_session(&mut session, negotiated);
    rfc7606_drain(&mut rib_rx);
    let next_hop: Ipv6Addr = "fe80::1".parse().unwrap();
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(Box::new(MpReachNlri {
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
        })),
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
            PathAttribute::MpReachNlri(Box::new(MpReachNlri {
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
            })),
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
            attributes: AttrSet::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
            ]),
            received_at: rustbgpd_rib::route::ReceivedAt::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            received_as_path: None,
            aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
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
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.retain(|attr| !matches!(attr, PathAttribute::NextHop(_)));
    });

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
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.retain(|attr| !matches!(attr, PathAttribute::NextHop(_)));
    });
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
            attributes: AttrSet::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
            ]),
            received_at: rustbgpd_rib::route::ReceivedAt::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            received_as_path: None,
            aspa_context: rustbgpd_rib::route::AspaContextId::DEFAULT,
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
            PathAttribute::MpReachNlri(Box::new(MpReachNlri {
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
            })),
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
        PathAttribute::MpReachNlri(Box::new(MpReachNlri {
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
        })),
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
        PathAttribute::MpReachNlri(Box::new(MpReachNlri {
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
        })),
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

#[tokio::test]
async fn scoped_extended_nexthop_global_self_hop_has_no_link_local_companion() {
    let msg =
        send_unicast_update(true, false, true, vec![make_route(100)], vec![None], vec![]).await;
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("scoped IPv4 uses MP_REACH");
    assert_eq!((mp.afi, mp.safi), (Afi::Ipv4, Safi::Unicast));
    assert_eq!(mp.next_hop, "2001:db8::1".parse::<IpAddr>().unwrap());
    assert_eq!(mp.link_local_next_hop, None);
}

/// Send one unchanged-next-hop route carrying a link-local companion through
/// the real export path and return the companion that reached the wire.
async fn exported_link_local_companion(
    remote_asn: u32,
    route_server_client: bool,
    scoped_outbound: bool,
    source_ifindex: Option<u32>,
    afi: Afi,
) -> Option<Ipv6Addr> {
    let primary: IpAddr = "2001:db8::2".parse().unwrap();
    let companion: Ipv6Addr = "fe80::a8c1:1".parse().unwrap();
    let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
    let prefix = match afi {
        Afi::Ipv4 => Prefix::V4(v4_prefix),
        _ => Prefix::V6(Ipv6Prefix::new("2001:db8:5::".parse().unwrap(), 48)),
    };
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, remote_asn);
    session.config.route_server_client = route_server_client;
    if scoped_outbound {
        configure_scoped_link_local_peer(&mut session);
    }
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(remote_asn, true);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    session.negotiated = Some(Arc::new(negotiated));
    let mut route = make_sourced_route(Ipv4Addr::new(10, 0, 0, 3), v4_prefix, 65003);
    route.prefix = prefix;
    route.next_hop = primary;
    route.link_local_next_hop = Some(companion);
    route.next_hop_scope = source_ifindex.map(|ifindex| {
        Box::new(rustbgpd_rib::NextHopScope {
            interface: Arc::from("eth1"),
            ifindex,
        })
    });
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.retain(|attr| !matches!(attr, PathAttribute::NextHop(_)));
    });
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.announce = vec![route].into();
    update.next_hop_override = vec![None].into();
    session.send_route_update(update);
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("IPv6 primary uses MP_REACH");
    assert_eq!((mp.afi, mp.safi), (afi, Safi::Unicast));
    assert_eq!(mp.next_hop, primary, "the global next hop stays unchanged");
    assert_eq!(mp.announced, vec![NlriEntry { path_id: 0, prefix }]);
    mp.link_local_next_hop
}

/// RFC 2545 §3: a received link-local companion is forwarded only to a peer
/// on the link it was received from. Everyone else gets the 16-octet form.
#[tokio::test]
async fn unchanged_next_hop_forwards_link_local_companion_only_on_its_link() {
    let companion: Ipv6Addr = "fe80::a8c1:1".parse().unwrap();
    // (case, remote ASN, route-server client, scoped outbound, source ifindex, kept)
    let cases = [
        (
            "route-server client off link",
            65002,
            true,
            false,
            None,
            false,
        ),
        (
            "route-server client, scoped source",
            65002,
            true,
            false,
            Some(7),
            false,
        ),
        (
            "ibgp over global transport",
            65001,
            false,
            false,
            None,
            false,
        ),
        (
            "ibgp over global transport, scoped source",
            65001,
            false,
            false,
            Some(7),
            false,
        ),
        ("same interface", 65001, false, true, Some(7), true),
        ("other interface", 65001, false, true, Some(8), false),
        (
            "scoped outbound, unscoped source",
            65001,
            false,
            true,
            None,
            false,
        ),
    ];
    for (case, remote_asn, rs_client, scoped, source_ifindex, kept) in cases {
        for afi in [Afi::Ipv4, Afi::Ipv6] {
            assert_eq!(
                exported_link_local_companion(remote_asn, rs_client, scoped, source_ifindex, afi)
                    .await,
                kept.then_some(companion),
                "{case} {afi:?}"
            );
        }
    }
}

#[tokio::test]
async fn received_link_local_companion_records_the_receiving_interface() {
    for scoped in [false, true] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        if scoped {
            configure_scoped_link_local_peer(&mut session);
        }
        let mut negotiated = negotiated_session(65002, false);
        negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
        session.negotiated = Some(Arc::new(negotiated));
        let prefix = Prefix::V6(Ipv6Prefix::new("2001:db8:5::".parse().unwrap(), 48));
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::MpReachNlri(Box::new(MpReachNlri {
                afi: Afi::Ipv6,
                safi: Safi::Unicast,
                next_hop: "2001:db8::2".parse().unwrap(),
                link_local_next_hop: Some("fe80::a8c1:1".parse().unwrap()),
                announced: vec![NlriEntry { path_id: 0, prefix }],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            })),
        ];
        let update = UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::Body);
        session.process_update(update).await;
        let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
            panic!("expected RoutesReceived");
        };
        assert_eq!(announced.len(), 1);
        assert_eq!(
            announced[0].link_local_next_hop,
            Some("fe80::a8c1:1".parse().unwrap())
        );
        assert_eq!(
            announced[0]
                .next_hop_scope
                .as_deref()
                .map(|scope| (scope.interface.as_ref(), scope.ifindex)),
            scoped.then_some(("eth1", 7)),
            "scoped={scoped}"
        );
    }
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
    AttrSet::edit(&mut route.attributes, |attrs| {
        attrs.retain(|attr| !matches!(attr, PathAttribute::NextHop(_)));
    });
    let msg = send_extended_nexthop_update(true, false, vec![route], vec![]).await;
    assert!(msg.nlri.is_empty(), "IPv4 NLRI must stay in MP_REACH_NLRI");
    let mut codes = attribute_type_codes(&msg.path_attributes);
    codes.sort_unstable();
    assert_eq!(codes, vec![1, 2, 14]);
    let parsed = msg.parse(true, false, &[]).unwrap();
    assert!(
        parsed
            .attributes
            .contains(&PathAttribute::Origin(Origin::Igp))
    );
    assert!(parsed.attributes.contains(&PathAttribute::AsPath(AsPath {
        segments: vec![AsPathSegment::AsSequence(vec![65002])],
    })));
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
    AttrSet::edit(&mut v6_nh.attributes, |attrs| {
        attrs.retain(|attr| !matches!(attr, PathAttribute::NextHop(_)));
    });
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

#[tokio::test]
async fn negotiated_link_local_receives_unicast_and_normalizes_legacy_pairs() {
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        for (primary, companion, expected) in [
            ("fe80::1", None, "fe80::1"),
            ("fe80::1", Some("fe80::2"), "fe80::2"),
            ("::", Some("fe80::2"), "fe80::2"),
        ] {
            let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
            configure_scoped_link_local_peer(&mut session);
            let mut neg = negotiated_session(65002, true);
            neg.link_local_next_hop = true;
            neg.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
            session.negotiated = Some(Arc::new(neg));
            let prefix = if afi == Afi::Ipv4 {
                make_route(100).prefix
            } else {
                make_v6_unicast_route("2001:db8::1".parse().unwrap()).prefix
            };
            let mut mp = MpReachNlri {
                afi,
                safi: Safi::Unicast,
                next_hop: primary.parse().unwrap(),
                link_local_next_hop: None,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            };
            mp.link_local_next_hop = companion.map(|s| s.parse().unwrap());
            mp.announced.push(NlriEntry { path_id: 0, prefix });
            let attrs = vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
                PathAttribute::MpReachNlri(Box::new(mp)),
            ];
            session
                .process_update(UpdateMessage::build(
                    &[],
                    &[],
                    &attrs,
                    true,
                    false,
                    Ipv4UnicastMode::MpReach,
                ))
                .await;
            let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
                panic!("expected routes");
            };
            assert_eq!(announced.len(), 1, "{afi:?} {primary} {companion:?}");
            assert_eq!(announced[0].next_hop, expected.parse::<IpAddr>().unwrap());
            assert_eq!(announced[0].link_local_next_hop, None);
            assert_eq!(announced[0].next_hop_scope.as_ref().unwrap().ifindex, 7);
        }
    }
}

#[tokio::test]
async fn negotiated_link_local_sends_sixteen_bytes_for_both_unicast_families() {
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
        configure_scoped_link_local_peer(&mut session);
        session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
        let (client, mut server) = connected_stream_pair().await;
        session.test_install_stream(client);
        let mut neg = negotiated_session(65002, true);
        neg.link_local_next_hop = true;
        neg.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        session.negotiated = Some(Arc::new(neg));
        let route = if afi == Afi::Ipv4 {
            make_route(100)
        } else {
            make_v6_unicast_route("2001:db8::2".parse().unwrap())
        };
        let mut update = empty_outbound_update();
        update.exact_export_snapshot = Some(session.publish_export_profile());
        update.announce = vec![route].into();
        update.next_hop_override = vec![None].into();
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
        assert_eq!(mp.afi, afi);
        assert_eq!(mp.next_hop, "fe80::1".parse::<IpAddr>().unwrap());
        assert_eq!(
            mp.link_local_next_hop, None,
            "16-byte next hop has no second slot"
        );
        let values = attribute_values(&msg.path_attributes);
        assert_eq!(
            values.iter().find(|(code, _)| *code == 14).unwrap().1[3],
            16
        );
        let expected = mp.announced.clone();
        let mut withdrawal = empty_outbound_update();
        withdrawal.exact_export_snapshot = Some(session.publish_export_profile());
        withdrawal.withdraw = expected
            .iter()
            .map(|nlri| (nlri.prefix, nlri.path_id))
            .collect();
        session.send_route_update(withdrawal);
        let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
            panic!("expected withdrawal");
        };
        let parsed = msg.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::MpUnreachNlri(mp) => Some(mp),
                _ => None,
            })
            .unwrap();
        assert_eq!((mp.afi, mp.safi), (afi, Safi::Unicast));
        assert_eq!(mp.withdrawn, expected);
    }
}

#[tokio::test]
async fn legacy_ipv4_link_local_reflection_requires_source_scope() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    session.config.route_server_client = true;
    session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
    let neg = negotiated_session(65002, true);
    assert!(!neg.link_local_next_hop);
    session.negotiated = Some(Arc::new(neg));
    let profile = super::super::export::SessionExportProfile::capture(&session);
    let mut route = make_route(100);
    route.next_hop = "fe80::2".parse().unwrap();
    route.link_local_next_hop = Some("fe80::2".parse().unwrap());
    route.next_hop_scope = session.link_local_next_hop_scope.clone().map(Box::new);
    assert!(profile.prepare_unicast_candidate(&route, None).is_ok());
    route.next_hop_scope.as_mut().unwrap().ifindex += 1;
    for missing_scope in [false, true] {
        if missing_scope {
            route.next_hop_scope = None;
        }
        assert!(matches!(
            profile.prepare_unicast_candidate(&route, None),
            Err(super::super::export::ExportProbeError::LinkLocalNextHopScope)
        ));
    }
}

#[tokio::test]
async fn reflected_link_local_requires_same_scope_or_explicit_self() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
    configure_scoped_link_local_peer(&mut session);
    session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
    let mut neg = negotiated_session(65001, true);
    neg.link_local_next_hop = true;
    neg.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    session.negotiated = Some(Arc::new(neg));
    let profile = super::super::export::SessionExportProfile::capture(&session);
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        let mut route = if afi == Afi::Ipv4 {
            make_route(100)
        } else {
            make_v6_unicast_route("fe80::2".parse().unwrap())
        };
        route.next_hop = "fe80::2".parse().unwrap();
        route.next_hop_scope = session.link_local_next_hop_scope.clone().map(Box::new);
        assert!(profile.prepare_unicast_candidate(&route, None).is_ok());
        route.next_hop_scope.as_mut().unwrap().ifindex += 1;
        assert!(profile.prepare_unicast_candidate(&route, None).is_err());
        for specific in ["fe80::2", "fe80::3"] {
            assert!(
                profile
                    .prepare_unicast_candidate(
                        &route,
                        Some(&rustbgpd_policy::NextHopAction::Specific(
                            specific.parse().unwrap()
                        ))
                    )
                    .is_err(),
                "an arbitrary specific link-local override does not establish scope"
            );
        }
        assert!(
            profile
                .prepare_unicast_candidate(
                    &route,
                    Some(&rustbgpd_policy::NextHopAction::Specific(
                        "fe80::1".parse().unwrap()
                    ))
                )
                .is_ok()
        );
        assert!(
            profile
                .prepare_unicast_candidate(&route, Some(&rustbgpd_policy::NextHopAction::Self_))
                .is_ok()
        );
        if afi == Afi::Ipv6 {
            session.config.local_ipv6_nexthop = None;
            let no_local = super::super::export::SessionExportProfile::capture(&session);
            assert!(
                no_local
                    .prepare_unicast_candidate(&route, Some(&rustbgpd_policy::NextHopAction::Self_))
                    .is_err(),
                "self without a usable local address must not bypass source scope"
            );
        }
        route.next_hop_scope = None;
        assert!(profile.prepare_unicast_candidate(&route, None).is_err());
    }
}

#[tokio::test]
async fn link_local_malformed_replacement_withdraws_negotiated_route() {
    for afi in [Afi::Ipv4, Afi::Ipv6] {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        configure_scoped_link_local_peer(&mut session);
        let mut neg = negotiated_session(65002, true);
        neg.link_local_next_hop = true;
        neg.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        session.negotiated = Some(Arc::new(neg));
        let prefix = if afi == Afi::Ipv4 {
            make_route(100).prefix
        } else {
            make_v6_unicast_route("2001:db8::1".parse().unwrap()).prefix
        };
        for bad in [false, true] {
            let mp = MpReachNlri {
                afi,
                safi: Safi::Unicast,
                next_hop: "fe80::2".parse().unwrap(),
                link_local_next_hop: bad.then(|| "fe80::3".parse().unwrap()),
                announced: vec![NlriEntry { path_id: 0, prefix }],
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
                PathAttribute::MpReachNlri(Box::new(mp)),
            ];
            let mut update =
                UpdateMessage::build(&[], &[], &attrs, true, false, Ipv4UnicastMode::MpReach);
            if bad {
                // Corrupt the wire value after the encoder's validity assertions.
                let mut raw = update.path_attributes.to_vec();
                let valid = "fe80::3".parse::<Ipv6Addr>().unwrap().octets();
                let offset = raw.windows(16).position(|w| w == valid).unwrap();
                raw[offset..offset + 16]
                    .copy_from_slice(&"2001:db8::bad".parse::<Ipv6Addr>().unwrap().octets());
                update.path_attributes = raw.into();
            }
            session.process_update(update).await;
            let RibUpdate::RoutesReceived {
                announced,
                withdrawn,
                ..
            } = rib_rx.try_recv().unwrap()
            else {
                panic!("expected routes");
            };
            if bad {
                assert!(announced.is_empty());
                assert_eq!(withdrawn, vec![(prefix, 0)]);
            } else {
                assert_eq!(announced.len(), 1);
            }
        }
    }
}

#[tokio::test]
async fn link_local_capability_advertisement_requires_opt_in_and_scoped_peer() {
    for (address, scoped, opt_in, expected) in [
        ("[fe80::2]:179", true, true, true),
        // The default leaves capability 77 off even for a scoped peer.
        ("[fe80::2]:179", true, false, false),
        ("[fe80::2]:179", false, true, false),
        ("[2001:db8::2]:179", true, true, false),
        ("192.0.2.2:179", true, true, false),
    ] {
        let mut peer = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
        if opt_in {
            peer.link_local_next_hop = true;
        }
        let mut config = TransportConfig::new(peer, address.parse().unwrap());
        if scoped {
            config.peer_interface = Some("eth1".into());
            config.peer_scope_id = Some(7);
        }
        let (_tx, rx) = mpsc::channel(8);
        let (rib_tx, _rib_rx) = mpsc::channel(64);
        let session = PeerSession::new(
            config,
            BgpMetrics::new(),
            rx,
            rib_tx,
            None,
            None,
            None,
            None,
            None,
            false,
        );
        assert_eq!(
            session.config.peer.link_local_next_hop, expected,
            "{address} scoped={scoped} opt_in={opt_in}"
        );
    }
}

#[tokio::test]
async fn negotiated_link_local_omits_unscoped_companion_from_global_next_hop() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
    configure_scoped_link_local_peer(&mut session);
    let mut neg = negotiated_session(65001, true);
    neg.link_local_next_hop = true;
    session.negotiated = Some(Arc::new(neg));
    let profile = super::super::export::SessionExportProfile::capture(&session);
    let mut route = make_v6_unicast_route("2001:db8::2".parse().unwrap());
    route.link_local_next_hop = Some("fe80::2".parse().unwrap());
    for same_scope in [false, true] {
        if same_scope {
            route.next_hop_scope = session.link_local_next_hop_scope.clone().map(Box::new);
        }
        let super::super::export::PreparedUnicastCandidate::Mp {
            next_hop,
            link_local_next_hop,
            ..
        } = profile.prepare_unicast_candidate(&route, None).unwrap()
        else {
            panic!("expected MP_REACH");
        };
        assert_eq!(next_hop, route.next_hop);
        assert_eq!(
            link_local_next_hop,
            same_scope.then_some("fe80::2".parse().unwrap())
        );
    }
}

#[tokio::test]
async fn link_local_next_hop_peer_up_and_reconnect_update_sendable_families() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
    for negotiated in [true, false] {
        let mut neg = negotiated_session(65002, true);
        neg.link_local_next_hop = negotiated;
        neg.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
        session
            .execute_actions(vec![Action::SessionEstablished(Box::new(neg))])
            .await;
        let mut registered = None;
        while let Ok(message) = rib_rx.try_recv() {
            if let RibUpdate::PeerUp {
                sendable_families, ..
            } = message
            {
                registered = Some(sendable_families);
            }
        }
        let families = registered.expect("session must register with the RIB");
        assert!(families.contains(&(Afi::Ipv4, Safi::Unicast)));
        assert_eq!(families.contains(&(Afi::Ipv6, Safi::Unicast)), negotiated);
        assert_eq!(
            session.negotiated.as_ref().unwrap().link_local_next_hop,
            negotiated
        );
        session.execute_actions(vec![Action::SessionDown]).await;
        assert!(session.negotiated.is_none());
        while rib_rx.try_recv().is_ok() {}
    }
}

/// A permit statement rewriting the next hop, optionally for one prefix and
/// with a `LOCAL_PREF` (a distinct modification set).
fn next_hop_statement(
    action: rustbgpd_policy::NextHopAction,
    prefix: Option<Ipv4Prefix>,
    local_pref: Option<u32>,
) -> PolicyStatement {
    PolicyStatement {
        prefix: prefix.map(Prefix::V4),
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
            set_next_hop: Some(action),
            set_local_pref: local_pref,
            ..Default::default()
        },
    }
}

fn import_prefix(third_octet: u8) -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 51, third_octet, 0), 24)
}

/// Import one body IPv4 UPDATE carrying `prefixes` through `process_update`
/// under `statements`, returning the routes as the RIB stores them.
async fn import_body_update(
    statements: Vec<PolicyStatement>,
    prefixes: &[Ipv4Prefix],
) -> Vec<Route> {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.negotiated = Some(Arc::new(negotiated_session(65002, false)));
    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: statements,
        default_action: PolicyAction::Deny,
    }])));
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ];
    let announced: Vec<_> = prefixes
        .iter()
        .map(|&prefix| Ipv4NlriEntry { path_id: 0, prefix })
        .collect();
    let update = UpdateMessage::build(&announced, &[], &attrs, true, false, Ipv4UnicastMode::Body);
    session.process_update(update).await;
    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), prefixes.len());
    announced
}

/// Import a body IPv4 route under a policy that rewrites every next hop.
async fn imported_with_next_hop_action(action: rustbgpd_policy::NextHopAction) -> Route {
    let routes = import_body_update(
        vec![next_hop_statement(action, None, None)],
        &[import_prefix(100), import_prefix(101)],
    )
    .await;
    // Both NLRI of one UPDATE keep sharing one stored attribute set.
    assert!(Arc::ptr_eq(&routes[0].attributes, &routes[1].attributes));
    routes.into_iter().next().unwrap()
}

/// Prefix-dependent import outcomes interleaved A/B/A in one UPDATE still
/// share one aligned attribute set per outcome.
#[tokio::test]
async fn interleaved_import_outcomes_share_aligned_next_hop_sets() {
    use rustbgpd_policy::NextHopAction;

    let (a, b) = (import_prefix(100), import_prefix(101));
    let routes = import_body_update(
        vec![
            next_hop_statement(NextHopAction::Self_, Some(a), None),
            next_hop_statement(NextHopAction::Self_, Some(b), Some(200)),
            next_hop_statement(NextHopAction::Self_, Some(import_prefix(102)), None),
        ],
        &[a, b, import_prefix(102)],
    )
    .await;
    for route in &routes {
        assert!(
            route
                .attributes
                .contains(&PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)))
        );
    }
    assert!(!Arc::ptr_eq(&routes[0].attributes, &routes[1].attributes));
    assert!(Arc::ptr_eq(&routes[0].attributes, &routes[2].attributes));
}

/// Peers that pass the next hop through (iBGP, route-server clients) must
/// receive the import-resolved next hop, not the received address the
/// stored `NEXT_HOP` attribute held before import `next-hop self`.
#[tokio::test]
async fn import_next_hop_self_is_what_passthrough_exports_advertise() {
    let route = imported_with_next_hop_action(rustbgpd_policy::NextHopAction::Self_).await;
    let resolved = Ipv4Addr::new(10, 0, 0, 1);
    assert_eq!(route.next_hop, IpAddr::V4(resolved));
    for (remote_asn, route_server_client, extended_nexthop) in [
        (65001, false, false),
        (65001, false, true),
        (65003, true, false),
    ] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, remote_asn);
        session.config.route_server_client = route_server_client;
        session.negotiated = Some(Arc::new(negotiated_session(remote_asn, extended_nexthop)));
        let profile = session.publish_export_profile();
        let candidate = profile.prepare_unicast_candidate(&route, None).unwrap();
        let export::PreparedUnicastCandidate::Ipv4Body { attrs, .. } = candidate else {
            panic!(
                "IPv4 next hop must keep body NLRI (remote AS {remote_asn}, extended next hop {extended_nexthop})"
            );
        };
        let next_hops: Vec<_> = attrs
            .iter()
            .filter(|attr| matches!(attr, PathAttribute::NextHop(_)))
            .collect();
        assert_eq!(
            next_hops,
            [&PathAttribute::NextHop(resolved)],
            "remote AS {remote_asn}, route-server client {route_server_client}, \
             extended next hop {extended_nexthop}"
        );
    }
}

/// An import IPv6 next hop on a body IPv4 route leaves no IPv4 `NEXT_HOP` to
/// pass through: without Extended Next Hop the route is not exportable to a
/// passthrough peer, and with it the IPv6 next hop is sent.
#[tokio::test]
async fn import_ipv6_next_hop_is_not_exported_as_the_received_ipv4_next_hop() {
    let ipv6: IpAddr = "2001:db8::9".parse().unwrap();
    let route = imported_with_next_hop_action(rustbgpd_policy::NextHopAction::Specific(ipv6)).await;
    assert_eq!(route.next_hop, ipv6);
    for extended_nexthop in [false, true] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
        session.negotiated = Some(Arc::new(negotiated_session(65001, extended_nexthop)));
        let profile = session.publish_export_profile();
        let candidate = profile.prepare_unicast_candidate(&route, None);
        if extended_nexthop {
            let Ok(export::PreparedUnicastCandidate::Mp { next_hop, .. }) = candidate else {
                panic!("IPv6 next hop must use MP_REACH");
            };
            assert_eq!(next_hop, ipv6);
        } else {
            let Err(error) = candidate else {
                panic!("an IPv6 next hop needs Extended Next Hop for IPv4 NLRI");
            };
            assert_eq!(error, ExportProbeError::Ipv4RequiresExtendedNextHop);
        }
    }
}

const RECEIVED_IPV6_NEXT_HOP: &str = "2001:db8::2";

fn set_next_hop_import(action: rustbgpd_policy::NextHopAction) -> PolicyChain {
    PolicyChain::new(vec![Policy {
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
                set_next_hop: Some(action),
                ..Default::default()
            },
        }],
        default_action: PolicyAction::Deny,
    }])
}

/// Receive one IPv6 unicast route over IPv4 transport (127.0.0.1) under an
/// import next-hop `action`, and return it as stored.
async fn import_ipv6_over_ipv4_transport(
    action: rustbgpd_policy::NextHopAction,
    local_ipv6_nexthop: Option<Ipv6Addr>,
) -> Route {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.local_ipv6_nexthop = local_ipv6_nexthop;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session.negotiated = Some(Arc::new(negotiated));
    session.install_import_policy(Some(set_next_hop_import(action)));
    session
        .process_update(ipv6_announce(
            Ipv6Prefix::new("2001:db8:100::".parse().unwrap(), 48),
            0,
        ))
        .await;
    let RibUpdate::RoutesReceived { mut announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    announced.remove(0)
}

/// Export `route` over IPv4 transport to an IPv6-unicast peer and return the
/// raw UPDATE as written.
async fn export_ipv6_raw(
    route: Route,
    remote_asn: u32,
    next_hop_override: Option<rustbgpd_policy::NextHopAction>,
) -> Vec<u8> {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, remote_asn);
    session.config.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(remote_asn, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session.negotiated = Some(Arc::new(negotiated));
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.next_hop_override = vec![next_hop_override].into();
    update.announce = vec![route].into();
    session.send_route_update(update);
    read_single_raw_bgp_message(&mut server).await
}

/// The `MP_REACH_NLRI` value of a raw UPDATE: (AFI, next-hop length,
/// next-hop bytes).
fn raw_mp_reach_next_hop(raw: &[u8]) -> (u16, u8, Vec<u8>) {
    let body = &raw[19..];
    let withdrawn_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let attrs_start = 2 + withdrawn_len + 2;
    let attrs_len = usize::from(u16::from_be_bytes([
        body[2 + withdrawn_len],
        body[3 + withdrawn_len],
    ]));
    let (_, value) = attribute_values(&body[attrs_start..attrs_start + attrs_len])
        .into_iter()
        .find(|(code, _)| *code == 14)
        .unwrap_or_else(|| panic!("no MP_REACH_NLRI in {raw:02x?}"));
    let nh_len = value[3];
    (
        u16::from_be_bytes([value[0], value[1]]),
        nh_len,
        value[4..4 + usize::from(nh_len)].to_vec(),
    )
}

fn ipv6_bytes(addr: &str) -> Vec<u8> {
    addr.parse::<Ipv6Addr>().unwrap().octets().to_vec()
}

/// Import `next-hop self` on IPv4 transport has no IPv6 self address unless
/// `local_ipv6_nexthop` is configured; the route keeps its received next hop
/// rather than taking the IPv4 socket address.
#[tokio::test]
async fn import_next_hop_self_on_ipv4_transport_keeps_an_ipv6_next_hop() {
    use rustbgpd_policy::NextHopAction;
    let route = import_ipv6_over_ipv4_transport(NextHopAction::Self_, None).await;
    let raw = export_ipv6_raw(route.clone(), 65001, None).await;
    assert_eq!(
        raw_mp_reach_next_hop(&raw),
        (2, 16, ipv6_bytes(RECEIVED_IPV6_NEXT_HOP)),
        "iBGP passthrough UPDATE {raw:02x?}"
    );
    assert_eq!(
        route.next_hop,
        RECEIVED_IPV6_NEXT_HOP.parse::<IpAddr>().unwrap()
    );

    let route =
        import_ipv6_over_ipv4_transport(NextHopAction::Self_, Some("2001:db8::7".parse().unwrap()))
            .await;
    assert_eq!(route.next_hop, "2001:db8::7".parse::<IpAddr>().unwrap());
    let raw = export_ipv6_raw(route, 65001, None).await;
    assert_eq!(
        raw_mp_reach_next_hop(&raw),
        (2, 16, ipv6_bytes("2001:db8::7")),
        "iBGP passthrough UPDATE {raw:02x?}"
    );
}

/// An IPv4 `set next-hop` does not apply to an IPv6 route (as FRR's
/// `set ip next-hop`): the route keeps its received next hop.
#[tokio::test]
async fn import_ipv4_set_next_hop_does_not_apply_to_an_ipv6_route() {
    let route = import_ipv6_over_ipv4_transport(
        rustbgpd_policy::NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))),
        None,
    )
    .await;
    let raw = export_ipv6_raw(route.clone(), 65001, None).await;
    assert_eq!(
        raw_mp_reach_next_hop(&raw),
        (2, 16, ipv6_bytes(RECEIVED_IPV6_NEXT_HOP)),
        "iBGP passthrough UPDATE {raw:02x?}"
    );
    assert_eq!(
        route.next_hop,
        RECEIVED_IPV6_NEXT_HOP.parse::<IpAddr>().unwrap()
    );
}

/// The next hop an export preparation selected, or its refusal.
fn prepared_next_hop(
    result: Result<super::super::export::PreparedUnicastCandidate, ExportProbeError>,
) -> Result<IpAddr, ExportProbeError> {
    result.map(|candidate| match candidate {
        super::super::export::PreparedUnicastCandidate::Mp { next_hop, .. } => next_hop,
        super::super::export::PreparedUnicastCandidate::Ipv4Body { .. } => {
            panic!("IPv6 prepares as MP_REACH")
        }
    })
}

/// Final guard: an IPv6 route whose next hop is IPv4 is refused at export
/// preparation, never encoded with a 4-octet IPv6 `MP_REACH_NLRI` next hop.
#[tokio::test]
async fn ipv6_route_with_an_ipv4_next_hop_is_refused_at_export() {
    let mut route = make_v6_unicast_route(RECEIVED_IPV6_NEXT_HOP.parse().unwrap());
    route.next_hop = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let local_ipv6: IpAddr = "2001:db8::1".parse().unwrap();
    let set_ipv4 =
        rustbgpd_policy::NextHopAction::Specific(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)));
    for (remote_asn, next_hop_override, expected) in [
        (65001, None, Err(ExportProbeError::MissingIpv6NextHop)),
        // eBGP rewrites the next hop to the local IPv6 address.
        (65002, None, Ok(local_ipv6)),
        // Policy evaluation drops this override; the guard still holds.
        (
            65001,
            Some(&set_ipv4),
            Err(ExportProbeError::MissingIpv6NextHop),
        ),
        (
            65002,
            Some(&set_ipv4),
            Err(ExportProbeError::MissingIpv6NextHop),
        ),
    ] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, remote_asn);
        session.config.local_ipv6_nexthop = Some("2001:db8::1".parse().unwrap());
        let mut negotiated = negotiated_session(remote_asn, false);
        negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
        session.negotiated = Some(Arc::new(negotiated));
        let profile = session.publish_export_profile();
        let refused = expected.is_err();
        assert_eq!(
            prepared_next_hop(profile.prepare_unicast_candidate(&route, next_hop_override)),
            expected,
            "AS{remote_asn} override {next_hop_override:?}"
        );
        // The RIB's exact-export preflight refuses it the same way.
        let probe = profile.probe_announcement(ExportCandidate::Unicast {
            route: &route,
            next_hop_override,
        });
        assert_eq!(probe.is_err(), refused, "AS{remote_asn} preflight");
    }
}

/// The `MP_REACH_NLRI` family and next hop of a raw UPDATE: (AFI, SAFI,
/// next-hop length, next-hop bytes); `None` for an UPDATE without one, such
/// as an End-of-RIB marker.
fn raw_mp_reach_family_next_hop(raw: &[u8]) -> Option<(u16, u8, u8, Vec<u8>)> {
    let body = &raw[19..];
    let withdrawn_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    let attrs_start = 2 + withdrawn_len + 2;
    let (_, value) = attribute_values(&body[attrs_start..])
        .into_iter()
        .find(|(code, _)| *code == 14)?;
    let nh_len = value[3];
    Some((
        u16::from_be_bytes([value[0], value[1]]),
        value[2],
        nh_len,
        value[4..4 + usize::from(nh_len)].to_vec(),
    ))
}

fn labeled_route_with(prefix: Prefix, next_hop: IpAddr) -> rustbgpd_rib::LabeledRibRoute {
    let mut route = make_labeled_rib_route(100);
    route.nlri.prefix = prefix;
    route.next_hop = next_hop;
    route.peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    route
}

fn vpn_route_with(prefix: VpnPrefix, next_hop: IpAddr) -> rustbgpd_rib::VpnRibRoute {
    let mut route = make_vpn_rib_route(100);
    route.nlri.prefix = prefix;
    route.next_hop = next_hop;
    route.peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    route
}

const MPLS_FAMILIES: [(Afi, Safi); 4] = [
    (Afi::Ipv4, Safi::LabeledUnicast),
    (Afi::Ipv6, Safi::LabeledUnicast),
    (Afi::Ipv4, Safi::MplsVpn),
    (Afi::Ipv6, Safi::MplsVpn),
];

/// A dual-stack export policy shared across families sets an IPv4 next hop.
/// Through the real RIB staging, exact-export preflight and transport
/// encoder, labeled-IPv6 and `VPNv6` routes keep their IPv6 next hop (16 and
/// 24 octets), while labeled-IPv4 and `VPNv4` routes take the IPv4 one (4 and
/// 12 octets). A `VPNv6` route stored with an IPv4 next hop (the 12-octet form
/// the decoder accepts) is withheld rather than encoded. Explain reports the
/// next hop that reaches the wire.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered RIB-to-wire scenario across four MPLS families"
)]
async fn ipv4_export_set_next_hop_skips_labeled_ipv6_and_vpnv6_on_the_wire() {
    let (mut session, rib_rx) =
        make_test_session_with_metrics_and_identity(BgpMetrics::new(), SessionIdentity::primary(7));
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = MPLS_FAMILIES.to_vec();
    install_test_negotiated_session(&mut session, negotiated);
    session.publish_export_profile();
    let (_query_tx, query_rx) = mpsc::channel(8);
    let manager = rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, BgpMetrics::new());
    let manager_task = tokio::spawn(manager.run());

    let set_ipv4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let policy = set_next_hop_import(rustbgpd_policy::NextHopAction::Specific(set_ipv4));
    let (outbound_tx, mut outbound_rx) = mpsc::channel(16);
    session
        .rib_tx
        .send(RibUpdate::SetPeerExportEncoder {
            peer: session.peer_ip,
            session_id: 7,
            encoder: session.export_encoder.clone(),
        })
        .await
        .unwrap();
    session
        .rib_tx
        .send(RibUpdate::PeerUp {
            peer: session.peer_ip,
            session_id: 7,
            peer_asn: 65002,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            outbound_tx,
            export_policy: Some(policy),
            sendable_families: MPLS_FAMILIES.to_vec(),
            is_ebgp: true,
            route_reflector_client: false,
            orr_vantage: None,
            per_client_best: false,
            interpret_rfc1997: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: vec![],
            negotiated_llgr_families: vec![],
        })
        .await
        .unwrap();

    let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
    let v6_next_hop: IpAddr = RECEIVED_IPV6_NEXT_HOP.parse().unwrap();
    let labeled_v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24));
    let labeled_v6 = Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48));
    let vpn_v4 = VpnPrefix::v4(Ipv4Addr::new(10, 0, 2, 0), 24).unwrap();
    let vpn_v6 = VpnPrefix::v6("2001:db8:2::".parse().unwrap(), 48).unwrap();
    let vpn_v6_stored_ipv4 = VpnPrefix::v6("2001:db8:3::".parse().unwrap(), 48).unwrap();
    session
        .rib_tx
        .send(RibUpdate::LabeledRoutesReceived {
            peer: source,
            session_id: 0,
            announced: vec![
                labeled_route_with(labeled_v4, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
                labeled_route_with(labeled_v6, v6_next_hop),
            ],
            withdrawn: vec![],
        })
        .await
        .unwrap();
    session
        .rib_tx
        .send(RibUpdate::VpnRoutesReceived {
            peer: source,
            session_id: 0,
            announced: vec![
                vpn_route_with(vpn_v4, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7))),
                vpn_route_with(vpn_v6, v6_next_hop),
                vpn_route_with(vpn_v6_stored_ipv4, IpAddr::V4(Ipv4Addr::new(192, 0, 2, 8))),
            ],
            withdrawn: vec![],
        })
        .await
        .unwrap();

    // Forward every RIB export (End-of-RIB included) to the transport until
    // all four sendable routes have been staged.
    let (mut labeled_seen, mut vpn_seen) = (Vec::new(), Vec::new());
    while !(labeled_seen.contains(&labeled_v4)
        && labeled_seen.contains(&labeled_v6)
        && vpn_seen.contains(&vpn_v4)
        && vpn_seen.contains(&vpn_v6))
    {
        let update = tokio::time::timeout(Duration::from_secs(3), outbound_rx.recv())
            .await
            .unwrap_or_else(|_| {
                panic!("RIB export; staged labeled {labeled_seen:?}, VPN {vpn_seen:?}")
            })
            .expect("outbound channel open");
        labeled_seen.extend(update.labeled_announce.iter().map(|r| r.nlri.prefix));
        vpn_seen.extend(update.vpn_announce.iter().map(|r| r.nlri.prefix));
        session.send_route_update(update);
    }
    assert!(
        !vpn_seen.contains(&vpn_v6_stored_ipv4),
        "VPNv6 route with an IPv4 next hop staged for the wire: {vpn_seen:?}"
    );

    let rd_zero = [0_u8; 8];
    let with_rd = |ip: Vec<u8>| [rd_zero.to_vec(), ip].concat();
    let mut expected = vec![
        (1, 4, 4, vec![192, 0, 2, 9]),
        (2, 4, 16, ipv6_bytes(RECEIVED_IPV6_NEXT_HOP)),
        (1, 128, 12, with_rd(vec![192, 0, 2, 9])),
        (2, 128, 24, with_rd(ipv6_bytes(RECEIVED_IPV6_NEXT_HOP))),
    ];
    let mut wire = Vec::new();
    while wire.len() < expected.len() {
        let raw = tokio::time::timeout(
            Duration::from_secs(3),
            read_single_raw_bgp_message(&mut server),
        )
        .await
        .unwrap_or_else(|_| panic!("UPDATE on the wire; read so far {wire:?}"));
        wire.extend(raw_mp_reach_family_next_hop(&raw));
    }
    wire.sort();
    expected.sort();
    assert_eq!(wire, expected, "MP_REACH (AFI, SAFI, NH-Len, next hop)");

    // Explain reports the next hop that reached the wire, and no
    // inapplicable IPv4 next-hop modification.
    for (prefix, rd, labeled, next_hop) in [
        (labeled_v4, None, true, set_ipv4),
        (labeled_v6, None, true, v6_next_hop),
        (
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 2, 0), 24)),
            Some(()),
            false,
            set_ipv4,
        ),
        (
            Prefix::V6(Ipv6Prefix::new("2001:db8:2::".parse().unwrap(), 48)),
            Some(()),
            false,
            v6_next_hop,
        ),
    ] {
        let (reply, explained) = oneshot::channel();
        session
            .rib_tx
            .send(RibUpdate::ExplainAdvertisedRoute {
                peer: session.peer_ip,
                prefix,
                rd: rd.map(|()| RouteDistinguisher([0, 0, 0xFD, 0xE8, 0, 0, 0, 1])),
                labeled,
                source: None,
                reply,
            })
            .await
            .unwrap();
        let explain = explained.await.unwrap().unwrap();
        assert_eq!(explain.next_hop, Some(next_hop), "explain {prefix}");
        let expected_mod = next_hop
            .is_ipv4()
            .then_some(rustbgpd_policy::NextHopAction::Specific(set_ipv4));
        assert_eq!(
            explain.modifications.set_next_hop, expected_mod,
            "explain modifications {prefix}"
        );
    }

    drop(session);
    manager_task.abort();
}

/// Final guard: a labeled-IPv6 or `VPNv6` route whose next hop is IPv4 is
/// refused at export preparation (live send and exact-export preflight),
/// never encoded as a 4-octet labeled or 12-octet VPN next hop under AFI 2.
/// The IPv4 families keep their existing next-hop rules.
#[tokio::test]
async fn ipv6_labeled_and_vpn_routes_with_an_ipv4_next_hop_are_refused_at_export() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
    let mut negotiated = negotiated_session(65001, false);
    negotiated.negotiated_families = MPLS_FAMILIES.to_vec();
    session.negotiated = Some(Arc::new(negotiated));
    let profile = session.publish_export_profile();
    let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
    let ipv6: IpAddr = RECEIVED_IPV6_NEXT_HOP.parse().unwrap();
    let ipv4_mapped: IpAddr = "::ffff:192.0.2.9".parse().unwrap();
    let v4 = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24));
    let v6 = Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48));
    let vpn4 = VpnPrefix::v4(Ipv4Addr::new(10, 0, 2, 0), 24).unwrap();
    let vpn6 = VpnPrefix::v6("2001:db8:2::".parse().unwrap(), 48).unwrap();
    let refused = || Some(ExportProbeError::MissingIpv6NextHop);
    for (route, expected) in [
        (labeled_route_with(v6, ipv4), refused()),
        (labeled_route_with(v6, ipv6), None),
        // An IPv4-mapped IPv6 next hop (RFC 4798 form) is an IPv6 address.
        (labeled_route_with(v6, ipv4_mapped), None),
        (labeled_route_with(v4, ipv4), None),
        // Labeled IPv4 with an IPv6 next hop still needs Extended Next Hop.
        (
            labeled_route_with(v4, ipv6),
            Some(ExportProbeError::Ipv4RequiresExtendedNextHop),
        ),
    ] {
        let live = profile.prepare_labeled_candidate(&route).err();
        assert_eq!(
            live, expected,
            "labeled {} via {}",
            route.nlri.prefix, route.next_hop
        );
        let probe = profile
            .probe_announcement(ExportCandidate::Labeled(&route))
            .err();
        assert_eq!(probe, expected, "labeled preflight {}", route.nlri.prefix);
    }
    for (route, expected) in [
        (vpn_route_with(vpn6, ipv4), refused()),
        (vpn_route_with(vpn6, ipv6), None),
        (vpn_route_with(vpn6, ipv4_mapped), None),
        (vpn_route_with(vpn4, ipv4), None),
        // VPNv4 with an IPv6 next hop still needs Extended Next Hop.
        (
            vpn_route_with(vpn4, ipv6),
            Some(ExportProbeError::Vpnv4RequiresExtendedNextHop),
        ),
    ] {
        let live = profile.prepare_vpn_candidate(&route).err();
        assert_eq!(
            live, expected,
            "VPN {:?} via {}",
            route.nlri.prefix, route.next_hop
        );
        let probe = profile
            .probe_announcement(ExportCandidate::Vpn(&route))
            .err();
        assert_eq!(probe, expected, "VPN preflight {:?}", route.nlri.prefix);
    }
}

/// Which Extended Next Hop tuple a labeled-IPv4 test session negotiated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LabeledEnhe {
    None,
    /// `<1,1,2>` only: IPv4 unicast, not labeled IPv4.
    UnicastOnly,
    /// `<1,4,2>`.
    Labeled,
}

fn labeled_ipv4_negotiated(remote_asn: u32, enhe: LabeledEnhe) -> NegotiatedSession {
    let mut negotiated = negotiated_session(remote_asn, enhe == LabeledEnhe::UnicastOnly);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::LabeledUnicast)];
    if enhe == LabeledEnhe::Labeled {
        negotiated
            .extended_nexthop_families
            .insert((Afi::Ipv4, Safi::LabeledUnicast), Afi::Ipv6);
    }
    negotiated
}

/// RFC 8950 §5: a labeled-IPv4 (AFI 1 / SAFI 4) route with an IPv6 next hop
/// goes only to a peer that negotiated `<1,4,2>`. Without it, both live
/// preparation and the exact-export preflight refuse the route under the
/// Extended Next Hop reason; `<1,1,2>` for IPv4 unicast does not stand in for
/// it. An IPv4 next hop needs no capability.
#[tokio::test]
async fn labeled_ipv4_route_with_ipv6_next_hop_requires_labeled_extended_nexthop() {
    let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let ipv6: IpAddr = RECEIVED_IPV6_NEXT_HOP.parse().unwrap();
    for enhe in [
        LabeledEnhe::None,
        LabeledEnhe::UnicastOnly,
        LabeledEnhe::Labeled,
    ] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65001);
        session.negotiated = Some(Arc::new(labeled_ipv4_negotiated(65001, enhe)));
        let profile = session.publish_export_profile();
        for next_hop in [ipv4, ipv6] {
            let route = labeled_route_with(
                Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24)),
                next_hop,
            );
            let expected = (next_hop.is_ipv6() && enhe != LabeledEnhe::Labeled)
                .then_some(ExportProbeError::Ipv4RequiresExtendedNextHop);
            let live = profile.prepare_labeled_candidate(&route);
            assert_eq!(
                live.as_ref().err(),
                expected.as_ref(),
                "{enhe:?} via {next_hop}"
            );
            if let Ok(prepared) = live {
                assert_eq!(prepared.next_hop, next_hop, "{enhe:?}: next hop unchanged");
            }
            let probe = profile
                .probe_announcement(ExportCandidate::Labeled(&route))
                .err();
            assert_eq!(probe, expected, "{enhe:?} preflight via {next_hop}");
        }
    }
}

/// Labeled-IPv4 export through the real RIB staging, exact-export preflight,
/// transport encoder and a socket read, for both sources of an IPv6 next hop:
/// a route received with one (from an Extended Next Hop peer), and an export
/// policy `set next-hop <IPv6>`. A control route keeps its IPv4 next hop.
///
/// With `<1,4,2>` negotiated the IPv6 next hops reach the wire as 16 octets.
/// Without it neither route is staged or encoded, and each is counted as
/// `bgp_exact_export_rejections_total{reason="ipv4_requires_extended_next_hop"}`.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered RIB-to-wire scenario per Extended Next Hop state"
)]
async fn labeled_ipv4_ipv6_next_hop_export_requires_extended_nexthop_on_the_wire() {
    let received_v6: IpAddr = RECEIVED_IPV6_NEXT_HOP.parse().unwrap();
    let set_v6: IpAddr = "2001:db8::9".parse().unwrap();
    let ipv4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7));
    let received_prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 1, 0), 24));
    let set_prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 2, 0), 24));
    let control_prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 3, 0), 24));

    for enhe in [LabeledEnhe::None, LabeledEnhe::Labeled] {
        let rib_metrics = BgpMetrics::new();
        let (mut session, rib_rx) = make_test_session_with_metrics_and_identity(
            BgpMetrics::new(),
            SessionIdentity::primary(7),
        );
        let (client, mut server) = connected_stream_pair().await;
        session.test_install_stream(client);
        install_test_negotiated_session(&mut session, labeled_ipv4_negotiated(65002, enhe));
        session.publish_export_profile();
        let (_query_tx, query_rx) = mpsc::channel(8);
        let manager =
            rustbgpd_rib::RibManager::new(rib_rx, query_rx, None, None, rib_metrics.clone());
        let manager_task = tokio::spawn(manager.run());

        // Rewrite only `set_prefix` to an IPv6 next hop; permit the rest.
        let mut set_statement =
            set_next_hop_import(rustbgpd_policy::NextHopAction::Specific(set_v6)).policies[0]
                .policy
                .entries[0]
                .clone();
        set_statement.prefix = Some(set_prefix);
        let mut permit = set_statement.clone();
        permit.prefix = None;
        permit.modifications = RouteModifications::default();
        let policy = PolicyChain::new(vec![Policy {
            entries: vec![set_statement, permit],
            default_action: PolicyAction::Deny,
        }]);

        let (outbound_tx, mut outbound_rx) = mpsc::channel(16);
        session
            .rib_tx
            .send(RibUpdate::SetPeerExportEncoder {
                peer: session.peer_ip,
                session_id: 7,
                encoder: session.export_encoder.clone(),
            })
            .await
            .unwrap();
        session
            .rib_tx
            .send(RibUpdate::PeerUp {
                peer: session.peer_ip,
                session_id: 7,
                peer_asn: 65002,
                peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
                outbound_tx,
                export_policy: Some(policy),
                sendable_families: vec![(Afi::Ipv4, Safi::LabeledUnicast)],
                is_ebgp: true,
                route_reflector_client: false,
                orr_vantage: None,
                per_client_best: false,
                interpret_rfc1997: true,
                add_path_send_families: vec![],
                add_path_send_max: 0,
                negotiated_orf_recv: vec![],
                negotiated_llgr_families: vec![],
            })
            .await
            .unwrap();
        session
            .rib_tx
            .send(RibUpdate::LabeledRoutesReceived {
                peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
                session_id: 0,
                announced: vec![
                    labeled_route_with(received_prefix, received_v6),
                    labeled_route_with(set_prefix, ipv4),
                    labeled_route_with(control_prefix, ipv4),
                ],
                withdrawn: vec![],
            })
            .await
            .unwrap();

        let mut expected = vec![(control_prefix, 4, ipv4)];
        if enhe == LabeledEnhe::Labeled {
            expected.push((received_prefix, 16, received_v6));
            expected.push((set_prefix, 16, set_v6));
        }
        let rejections = || {
            counter_samples(&rib_metrics, "bgp_exact_export_rejections_total")
                .into_iter()
                .filter(|(labels, _)| {
                    labels["family"] == "ipv4_labeled_unicast"
                        && labels["reason"] == "ipv4_requires_extended_next_hop"
                })
                .map(|(_, value)| value)
                .sum::<f64>()
        };
        let expected_rejections = if enhe == LabeledEnhe::Labeled {
            0.0
        } else {
            2.0
        };

        // Forward every RIB export (End-of-RIB included) to the transport
        // until each expected route is staged and every refusal is counted.
        let mut staged = Vec::new();
        while !(expected.iter().all(|(prefix, ..)| staged.contains(prefix))
            && rejections() >= expected_rejections)
        {
            let update = tokio::time::timeout(Duration::from_secs(3), outbound_rx.recv())
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "{enhe:?}: RIB export; staged {staged:?}, rejections {}",
                        rejections()
                    )
                })
                .expect("outbound channel open");
            staged.extend(update.labeled_announce.iter().map(|r| r.nlri.prefix));
            session.send_route_update(update);
        }
        assert_eq!(staged.len(), expected.len(), "{enhe:?}: staged {staged:?}");
        assert!(
            (rejections() - expected_rejections).abs() < f64::EPSILON,
            "{enhe:?}: rejections {}",
            rejections()
        );

        let mut wire = Vec::new();
        while wire.len() < expected.len() {
            let raw = tokio::time::timeout(
                Duration::from_secs(3),
                read_single_raw_bgp_message(&mut server),
            )
            .await
            .unwrap_or_else(|_| panic!("{enhe:?}: UPDATE on the wire; read so far {wire:?}"));
            let body = &raw[19..];
            let withdrawn_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
            let Some((_, value)) = attribute_values(&body[2 + withdrawn_len + 2..])
                .into_iter()
                .find(|(code, _)| *code == 14)
            else {
                continue; // End-of-RIB
            };
            assert_eq!(&value[..3], &[0, 1, 4], "{enhe:?}: AFI 1 / SAFI 4");
            let nh_len = value[3];
            let Message::Update(update) = rustbgpd_wire::decode_message(
                &mut Bytes::from(raw.clone()),
                rustbgpd_wire::MAX_MESSAGE_LEN,
            )
            .unwrap() else {
                panic!("expected UPDATE");
            };
            let parsed = update.parse(true, false, &[]).unwrap();
            for attr in &parsed.attributes {
                if let PathAttribute::MpReachNlri(mp) = attr {
                    for entry in &mp.labeled_announced {
                        wire.push((entry.nlri.prefix, nh_len, mp.next_hop));
                    }
                }
            }
        }
        wire.sort();
        expected.sort();
        assert_eq!(wire, expected, "{enhe:?}: (prefix, NH-Len, next hop)");

        drop(session);
        manager_task.abort();
    }
}
