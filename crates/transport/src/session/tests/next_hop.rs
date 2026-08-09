use super::*;

#[tokio::test]
async fn process_update_accepts_ipv4_mp_link_local_for_scoped_unnumbered_peer() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let negotiated = negotiated_session(65002, true);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
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
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
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

#[tokio::test]
async fn process_update_rejects_ipv4_mp_link_local_without_extended_nexthop() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
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
    // Fail closed on the route, gracefully: a scoped link-local peer that did
    // not negotiate Extended Next Hop must not import an IPv4-over-IPv6
    // link-local MP_REACH (no route reaches the RIB), but the route is dropped
    // per-route (ignore + WARN at the ENH gate), not by tearing the session
    // down with a NOTIFICATION. Pinning both ends guards against a regression in
    // either direction — silently accepting the route, or escalating to a
    // session reset. The positive case is covered by
    // `process_update_accepts_ipv4_mp_link_local_for_scoped_unnumbered_peer`.
    assert!(rib_rx.try_recv().is_err(), "no route may reach the RIB");
    assert_eq!(
        session.notifications_sent, 0,
        "the route is dropped at the Extended-Next-Hop gate, not via NOTIFICATION"
    );
}

#[tokio::test]
async fn process_update_ignores_ipv4_body_nlri_for_scoped_unnumbered_peer() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let negotiated = negotiated_session(65002, true);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
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
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let v6_nh: Ipv6Addr = "2001:db8::1".parse().unwrap();
    let update = OutboundRouteUpdate {
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
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let update = OutboundRouteUpdate {
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
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let remote_ll: Ipv6Addr = "fe80::2".parse().unwrap();
    let mut route = make_route(100);
    route.next_hop = IpAddr::V6(remote_ll);
    route.link_local_next_hop = Some(remote_ll);
    let update = OutboundRouteUpdate {
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
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut route = make_route(100);
    route.next_hop = IpAddr::V6("2001:db8::2".parse().unwrap());
    route.link_local_next_hop = Some("fe80::2".parse().unwrap());
    let update = OutboundRouteUpdate {
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
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let update = OutboundRouteUpdate {
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
async fn route_server_client_ipv6_preserves_next_hop() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.route_server_client = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let v6_nh: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let update = OutboundRouteUpdate {
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
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let remote_global: Ipv6Addr = "2001:db8::2".parse().unwrap();
    let mut route = make_v6_unicast_route(remote_global);
    route.link_local_next_hop = Some("fe80::2".parse().unwrap());
    let update = OutboundRouteUpdate {
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
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let route_next_hop = "2001:db8::2".parse().unwrap();
    let update = OutboundRouteUpdate {
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
    session.negotiated = Some(negotiated_session(65002, false));
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
    session.negotiated = Some(negotiated_session(65002, false));
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
