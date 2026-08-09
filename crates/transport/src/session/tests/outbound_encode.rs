use super::*;

#[tokio::test]
async fn send_route_update_batches_ipv4_routes_with_identical_attributes() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
    ]);
    let route1 = Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::clone(&attrs),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let route2 = Route {
        prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)),
        ..route1.clone()
    };
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![route1, route2].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None, None].into(),
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
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    assert_eq!(parsed.announced.len(), 2);
}

#[tokio::test]
async fn send_route_update_splits_ipv6_routes_by_next_hop() {
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
    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
    ]);
    let route1 = Route {
        prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 64)),
        next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::clone(&attrs),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let route2 = Route {
        prefix: Prefix::V6(Ipv6Prefix::new("2001:db8:2::".parse().unwrap(), 64)),
        next_hop: IpAddr::V6("2001:db8::2".parse().unwrap()),
        ..route1.clone()
    };
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![route1, route2].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![None, None].into(),
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
    });
    let Message::Update(first) = read_single_bgp_message(&mut server).await else {
        panic!("expected first UPDATE");
    };
    let first = first.parse(true, false, &[]).unwrap();
    let first_mp = first
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(first_mp.announced.len(), 1);
    let Message::Update(second) = read_single_bgp_message(&mut server).await else {
        panic!("expected second UPDATE");
    };
    let second = second.parse(true, false, &[]).unwrap();
    let second_mp = second
        .attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .unwrap();
    assert_eq!(second_mp.announced.len(), 1);
    assert_ne!(first_mp.next_hop, second_mp.next_hop);
}

/// A single attribute group whose NLRI exceeds one 4096-byte UPDATE must be
/// split across multiple wire UPDATEs with every prefix advertised — not
/// truncated. Before the size-aware chunker, `send_route_update` built one
/// oversized UPDATE per attribute group; `enqueue_bulk` rejected it
/// (`MessageTooLong`) and returned early, silently advertising nothing while
/// the RIB believed the whole group was sent.
#[tokio::test]
async fn send_route_update_splits_oversized_ipv4_group_across_updates() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.route_server_client = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);

    // One shared attribute set + next hop => one attribute group. 1500 /24s
    // (4 NLRI bytes each = 6000 bytes) cannot fit a single 4096-byte UPDATE.
    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
    ]);
    let count: u32 = 1500;
    let route = |i: u32| Route {
        prefix: Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::from(0x1400_0000_u32 | (i << 8)),
            24,
        )),
        next_hop: IpAddr::V4(Ipv4Addr::new(10, 9, 0, 1)),
        link_local_next_hop: None,
        next_hop_scope: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::clone(&attrs),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        aspa_context: rustbgpd_wire::AspaValidationContext::default(),
    };
    let routes: Vec<Route> = (0..count).map(route).collect();
    let sent_before = session.updates_sent;
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: routes.into(),
        next_hop_override: vec![None; count as usize].into(),
        ..empty_outbound_update()
    });

    // Drain every emitted UPDATE: each must fit the limit, and the union of
    // announced prefixes must cover all 1500 with none dropped or duplicated.
    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut updates = 0usize;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(
            raw.len() <= 4096,
            "emitted UPDATE is {} bytes, over the 4096 limit",
            raw.len()
        );
        let mut buf = Bytes::from(raw);
        let Message::Update(u) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = u.parse(true, false, &[]).unwrap();
        for e in &parsed.announced {
            assert!(
                seen.insert(u32::from(e.prefix.addr)),
                "prefix advertised more than once"
            );
        }
        updates += 1;
    }
    assert!(
        updates >= 2,
        "oversized group must split across multiple UPDATEs, got {updates}"
    );
    assert_eq!(
        seen.len(),
        count as usize,
        "every prefix in the oversized group must be advertised"
    );
    assert_eq!(
        session.updates_sent - sent_before,
        updates as u64,
        "updates_sent must count exactly the emitted wire UPDATEs"
    );
}

/// The withdrawal path has the same single-UPDATE construction as the
/// announcement path: a large IPv4 withdrawal set must also split across
/// multiple wire UPDATEs, none over 4096 bytes, covering every prefix.
#[tokio::test]
async fn send_route_update_splits_oversized_ipv4_withdrawals_across_updates() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.config.route_server_client = true;
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);

    let count: u32 = 2000;
    let withdraw: Vec<(Prefix, u32)> = (0..count)
        .map(|i| {
            (
                Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::from(0x1400_0000_u32 | (i << 8)),
                    24,
                )),
                0u32,
            )
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        withdraw,
        ..empty_outbound_update()
    });

    let mut seen: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let mut updates = 0usize;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(
            raw.len() <= 4096,
            "withdrawal UPDATE is {} bytes",
            raw.len()
        );
        let mut buf = Bytes::from(raw);
        let Message::Update(u) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = u.parse(true, false, &[]).unwrap();
        for e in &parsed.withdrawn {
            assert!(
                seen.insert(u32::from(e.prefix.addr)),
                "prefix withdrawn twice"
            );
        }
        updates += 1;
    }
    assert!(
        updates >= 2,
        "oversized withdrawal must split across multiple UPDATEs, got {updates}"
    );
    assert_eq!(
        seen.len(),
        count as usize,
        "every prefix in the oversized withdrawal must be sent"
    );
}

/// Extended Next Hop carries IPv4 NLRI in `MP_REACH` rather than the UPDATE
/// body. Keep that construction path covered by the same oversized-group
/// regression as ordinary IPv4 announcements.
#[tokio::test]
async fn send_route_update_splits_oversized_ipv4_mp_reach_across_updates() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    session.config.local_ipv6_nexthop = Some("fe80::1".parse().unwrap());
    session.config.route_server_client = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    install_test_negotiated_session(&mut session, negotiated_session(65002, true));

    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
    ]);
    let count: u32 = 1500;
    let routes: Vec<Route> = (0..count)
        .map(|i| Route {
            prefix: Prefix::V4(Ipv4Prefix::new(
                Ipv4Addr::from(0x1400_0000_u32 | (i << 8)),
                24,
            )),
            next_hop: IpAddr::V6("fe80::2".parse().unwrap()),
            link_local_next_hop: Some("fe80::2".parse().unwrap()),
            next_hop_scope: None,
            peer: IpAddr::V6("fe80::2".parse().unwrap()),
            attributes: Arc::clone(&attrs),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: routes.into(),
        next_hop_override: vec![None; count as usize].into(),
        ..empty_outbound_update()
    });

    let mut seen = std::collections::HashSet::new();
    let mut updates = 0usize;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(raw.len() <= 4096, "MP_REACH UPDATE is {} bytes", raw.len());
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .expect("Extended Next Hop announcement must use MP_REACH");
        assert_eq!((mp.afi, mp.safi), (Afi::Ipv4, Safi::Unicast));
        for entry in &mp.announced {
            let Prefix::V4(prefix) = entry.prefix else {
                panic!("IPv4 MP_REACH contained non-IPv4 NLRI");
            };
            assert!(seen.insert(u32::from(prefix.addr)));
        }
        updates += 1;
    }
    assert!(updates >= 2, "oversized MP_REACH group was not split");
    assert_eq!(seen.len(), count as usize);
}

/// Extended Next Hop also moves IPv4 withdrawals into `MP_UNREACH`. Verify an
/// oversized set is split without dropping or duplicating any withdrawn NLRI.
#[tokio::test]
async fn send_route_update_splits_oversized_ipv4_mp_unreach_across_updates() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    configure_scoped_link_local_peer(&mut session);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    install_test_negotiated_session(&mut session, negotiated_session(65002, true));

    let count: u32 = 2000;
    let withdraw = (0..count)
        .map(|i| {
            (
                Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::from(0x1400_0000_u32 | (i << 8)),
                    24,
                )),
                0,
            )
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        withdraw,
        ..empty_outbound_update()
    });

    let mut seen = std::collections::HashSet::new();
    let mut updates = 0usize;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(
            raw.len() <= 4096,
            "MP_UNREACH UPDATE is {} bytes",
            raw.len()
        );
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::MpUnreachNlri(mp) => Some(mp),
                _ => None,
            })
            .expect("Extended Next Hop withdrawal must use MP_UNREACH");
        assert_eq!((mp.afi, mp.safi), (Afi::Ipv4, Safi::Unicast));
        for entry in &mp.withdrawn {
            let Prefix::V4(prefix) = entry.prefix else {
                panic!("IPv4 MP_UNREACH contained non-IPv4 NLRI");
            };
            assert!(seen.insert(u32::from(prefix.addr)));
        }
        updates += 1;
    }
    assert!(updates >= 2, "oversized MP_UNREACH set was not split");
    assert_eq!(seen.len(), count as usize);
}

/// IPv6 unicast previously bypassed every size-aware sender: one large
/// `MP_REACH/MP_UNREACH` group reached `enqueue_bulk` after the RIB had already
/// committed the complete logical batch. Pin both directions at the standard
/// limit, then prove that the same announcement legitimately stays whole for
/// a peer advertising Extended Messages.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one standard announce/withdraw plus extended-limit parity receipt"
)]
async fn send_route_update_chunks_ipv6_at_negotiated_message_limit() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.route_server_client = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    install_test_negotiated_session(&mut session, negotiated);

    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
    ]);
    let count: u32 = 700;
    let prefix = |i: u32| {
        Ipv6Prefix::new(
            Ipv6Addr::from(0x2001_0db8_0001_0000_0000_0000_0000_0000_u128 + u128::from(i)),
            128,
        )
    };
    let routes: Vec<Route> = (0..count)
        .map(|i| Route {
            prefix: Prefix::V6(prefix(i)),
            next_hop: IpAddr::V6("2001:db8::2".parse().unwrap()),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V6("2001:db8::2".parse().unwrap()),
            attributes: Arc::clone(&attrs),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: routes.clone().into(),
        next_hop_override: vec![None; count as usize].into(),
        ..empty_outbound_update()
    });

    let mut announced = std::collections::HashSet::new();
    let mut announce_updates = 0;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(raw.len() <= 4096, "IPv6 UPDATE is {} bytes", raw.len());
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let mp = parsed.attributes.iter().find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        });
        if let Some(mp) = mp {
            for entry in &mp.announced {
                assert!(announced.insert(entry.prefix));
            }
            announce_updates += 1;
        }
    }
    assert!(announce_updates >= 2);
    assert_eq!(announced.len(), count as usize);

    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        withdraw: (0..count).map(|i| (Prefix::V6(prefix(i)), 0)).collect(),
        ..empty_outbound_update()
    });
    let mut withdrawn = std::collections::HashSet::new();
    let mut withdraw_updates = 0;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(raw.len() <= 4096, "IPv6 withdrawal is {} bytes", raw.len());
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        if let Some(mp) = parsed.attributes.iter().find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        }) {
            for entry in &mp.withdrawn {
                assert!(withdrawn.insert(entry.prefix));
            }
            withdraw_updates += 1;
        }
    }
    assert!(withdraw_updates >= 2);
    assert_eq!(withdrawn.len(), count as usize);

    session.negotiated.as_mut().unwrap().peer_extended_message = true;
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: routes.into(),
        next_hop_override: vec![None; count as usize].into(),
        ..empty_outbound_update()
    });
    let raw = tokio::time::timeout(
        Duration::from_secs(1),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    .unwrap();
    assert!(raw.len() > 4096 && raw.len() <= 65_535);
    let mut buf = Bytes::from(raw);
    let Message::Update(update) =
        rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN).unwrap()
    else {
        panic!("expected Extended Message IPv6 announcement UPDATE");
    };
    let parsed = update.parse(true, false, &[]).unwrap();
    let extended_announced = parsed
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            PathAttribute::MpReachNlri(mp) => Some(&mp.announced),
            _ => None,
        })
        .unwrap();
    assert_eq!(extended_announced.len(), count as usize);
    assert_eq!(
        extended_announced
            .iter()
            .map(|entry| entry.prefix)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        count as usize
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            read_single_raw_bgp_message(&mut server)
        )
        .await
        .is_err(),
        "Extended Message peer should receive this group in one UPDATE"
    );

    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        withdraw: (0..count).map(|i| (Prefix::V6(prefix(i)), 0)).collect(),
        ..empty_outbound_update()
    });
    let raw = tokio::time::timeout(
        Duration::from_secs(1),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    .unwrap();
    assert!(raw.len() > 4096 && raw.len() <= 65_535);
    let mut buf = Bytes::from(raw);
    let Message::Update(update) =
        rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN).unwrap()
    else {
        panic!("expected Extended Message IPv6 withdrawal UPDATE");
    };
    let parsed = update.parse(true, false, &[]).unwrap();
    let extended_withdrawn = parsed
        .attributes
        .iter()
        .find_map(|attribute| match attribute {
            PathAttribute::MpUnreachNlri(mp) => Some(&mp.withdrawn),
            _ => None,
        })
        .unwrap();
    assert_eq!(extended_withdrawn.len(), count as usize);
    assert_eq!(
        extended_withdrawn
            .iter()
            .map(|entry| entry.prefix)
            .collect::<std::collections::HashSet<_>>()
            .len(),
        count as usize
    );
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            read_single_raw_bgp_message(&mut server)
        )
        .await
        .is_err(),
        "Extended Message peer should receive this withdrawal in one UPDATE"
    );
}

/// Extended Messages should not freeze MP batches at the conservative 1,024
/// entry first probe. Use a large shared attribute so 1,024 entries fit while
/// 2,048 do not; the sender must remember that failed upper bound, make
/// monotonic progress with a later in-between probe, and preserve exact order.
#[tokio::test]
async fn extended_ipv6_chunk_probe_grows_bounded_without_reordering() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.route_server_client = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    negotiated.peer_extended_message = true;
    install_test_negotiated_session(&mut session, negotiated);

    let padding = Bytes::from(vec![0x5a; 36_000]);
    let attrs = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
            flags: rustbgpd_wire::constants::attr_flags::OPTIONAL
                | rustbgpd_wire::constants::attr_flags::TRANSITIVE,
            type_code: 99,
            data: padding,
        }),
    ]);
    let count = 3_500_u32;
    let expected: Vec<Prefix> = (0..count)
        .map(|i| {
            Prefix::V6(Ipv6Prefix::new(
                Ipv6Addr::from(0x2001_0db8_0003_0000_0000_0000_0000_0000_u128 + u128::from(i)),
                128,
            ))
        })
        .collect();
    let routes: Vec<Route> = expected
        .iter()
        .copied()
        .map(|prefix| Route {
            prefix,
            next_hop: IpAddr::V6("2001:db8::2".parse().unwrap()),
            link_local_next_hop: None,
            next_hop_scope: None,
            peer: IpAddr::V6("2001:db8::2".parse().unwrap()),
            attributes: Arc::clone(&attrs),
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce: routes.into(),
        next_hop_override: vec![None; count as usize].into(),
        ..empty_outbound_update()
    });

    let mut actual = Vec::new();
    let mut chunk_sizes = Vec::new();
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(
            raw.len() <= 65_535,
            "Extended UPDATE is {} bytes",
            raw.len()
        );
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN)
                .unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let announced = parsed
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::MpReachNlri(mp) => Some(&mp.announced),
                _ => None,
            })
            .expect("IPv6 announcement uses MP_REACH");
        chunk_sizes.push(announced.len());
        actual.extend(announced.iter().map(|entry| entry.prefix));
    }
    assert_eq!(
        actual, expected,
        "IPv6 NLRI must be emitted exactly once in order"
    );
    assert_eq!(chunk_sizes.first(), Some(&1024));
    assert!(
        chunk_sizes.iter().any(|size| *size > 1024),
        "a proven Extended Message candidate must grow beyond 1,024: {chunk_sizes:?}"
    );
}

/// Pin the same bounded-growth invariant for the fallible `FlowSpec` encoder.
#[tokio::test]
async fn extended_flowspec_chunk_probe_grows_and_preserves_exact_order() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::FlowSpec)];
    negotiated.peer_extended_message = true;
    install_test_negotiated_session(&mut session, negotiated);

    let padding = Bytes::from(vec![0xa5; 36_000]);
    let count = 3_500_u32;
    let rules: Vec<FlowSpecRule> = (0..count)
        .map(|i| FlowSpecRule {
            components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V6(
                Ipv6PrefixOffset {
                    prefix: Ipv6Prefix::new(
                        Ipv6Addr::from(
                            0x2001_0db8_0004_0000_0000_0000_0000_0000_u128 + u128::from(i),
                        ),
                        128,
                    ),
                    offset: 0,
                },
            ))],
        })
        .collect();
    let routes = rules
        .iter()
        .cloned()
        .map(|rule| FlowSpecRoute {
            rule,
            afi: Afi::Ipv6,
            peer: IpAddr::V6("2001:db8::2".parse().unwrap()),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
                    flags: rustbgpd_wire::constants::attr_flags::OPTIONAL
                        | rustbgpd_wire::constants::attr_flags::TRANSITIVE,
                    type_code: 99,
                    data: padding.clone(),
                }),
            ],
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        flowspec_announce: routes,
        ..empty_outbound_update()
    });

    let mut actual = Vec::new();
    let mut chunk_sizes = Vec::new();
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(
            raw.len() <= 65_535,
            "Extended UPDATE is {} bytes",
            raw.len()
        );
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN)
                .unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let announced = parsed
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::MpReachNlri(mp) => Some(&mp.flowspec_announced),
                _ => None,
            })
            .expect("FlowSpec announcement uses MP_REACH");
        chunk_sizes.push(announced.len());
        actual.extend(announced.iter().cloned());
    }
    assert_eq!(
        actual, rules,
        "FlowSpec rules must be emitted exactly once in order"
    );
    assert_eq!(chunk_sizes.first(), Some(&1024));
    assert!(
        chunk_sizes.iter().any(|size| *size > 1024),
        "a proven Extended Message candidate must grow beyond 1,024: {chunk_sizes:?}"
    );
}

/// Load-bearing: retaining `failed_upper` after a successful chunk leaves the
/// first region's failed 1,024-entry probe as a permanent cap. This real
/// `FlowSpec` encoder receipt starts with entries large enough to force a
/// 512-entry chunk, then switches to small entries that must pack beyond that
/// stale 1,024-entry upper bound without reordering or duplication.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one real-encoder mixed-entry receipt"
)]
async fn extended_flowspec_chunk_probe_resets_failed_upper_for_smaller_entries() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::FlowSpec)];
    negotiated.peer_extended_message = true;
    install_test_negotiated_session(&mut session, negotiated);

    let large_rules = 700_u32;
    let rule_count = 12_000_u32;
    let rules: Vec<FlowSpecRule> = (0..rule_count)
        .map(|i| {
            let components = if i < large_rules {
                let prefix =
                    FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V6(Ipv6PrefixOffset {
                        prefix: Ipv6Prefix::new(
                            Ipv6Addr::from(
                                0x2001_0db8_0005_0000_0000_0000_0000_0000_u128 + u128::from(i),
                            ),
                            128,
                        ),
                        offset: 0,
                    }));
                let mut ports: Vec<NumericMatch> = (0..48)
                    .map(|port| NumericMatch {
                        end_of_list: false,
                        and_bit: port != 0,
                        lt: false,
                        gt: false,
                        eq: true,
                        value: port,
                    })
                    .collect();
                ports.last_mut().unwrap().end_of_list = true;
                vec![prefix, FlowSpecComponent::Port(ports)]
            } else {
                vec![FlowSpecComponent::IpProtocol(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: u64::from(i % 200),
                }])]
            };
            FlowSpecRule { components }
        })
        .collect();
    let routes = rules
        .iter()
        .cloned()
        .map(|rule| FlowSpecRoute {
            rule,
            afi: Afi::Ipv6,
            peer: IpAddr::V6("2001:db8::2".parse().unwrap()),
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            received_at: Instant::now(),
            origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        flowspec_announce: routes,
        ..empty_outbound_update()
    });

    let mut actual = Vec::new();
    let mut chunk_sizes = Vec::new();
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(raw.len() <= usize::from(rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN));
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN)
                .unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let announced = parsed
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::MpReachNlri(mp) => Some(&mp.flowspec_announced),
                _ => None,
            })
            .expect("FlowSpec announcement uses MP_REACH");
        chunk_sizes.push(announced.len());
        actual.extend(announced.iter().cloned());
    }

    assert_eq!(actual, rules, "FlowSpec rules must stay exact and ordered");
    assert_eq!(
        chunk_sizes.first(),
        Some(&512),
        "large first region must halve"
    );
    assert!(
        chunk_sizes.contains(&4096),
        "smaller later entries must reach the bounded 4,096-entry probe beyond the earlier failed upper bound: {chunk_sizes:?}"
    );
}

#[tokio::test]
async fn destinationless_flowspec_withdrawal_uses_explicit_afi() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::FlowSpec), (Afi::Ipv6, Safi::FlowSpec)];
    install_test_negotiated_session(&mut session, negotiated);
    let rule = FlowSpecRule {
        components: vec![FlowSpecComponent::IpProtocol(vec![NumericMatch {
            end_of_list: true,
            and_bit: false,
            lt: false,
            gt: false,
            eq: true,
            value: 6,
        }])],
    };
    let route = |afi| FlowSpecRoute {
        rule: rule.clone(),
        afi,
        peer: "192.0.2.1".parse().unwrap(),
        attributes: vec![PathAttribute::Origin(Origin::Igp)],
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    };
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        flowspec_announce: vec![route(Afi::Ipv4), route(Afi::Ipv6)],
        ..empty_outbound_update()
    });
    for expected_afi in [Afi::Ipv4, Afi::Ipv6] {
        let Message::Update(update) = read_single_bgp_message(&mut server).await else {
            panic!("expected FlowSpec announcement");
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .unwrap();
        assert_eq!(mp.afi, expected_afi);
        assert_eq!(mp.flowspec_announced, vec![rule.clone()]);
    }

    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        flowspec_withdraw: vec![
            rustbgpd_rib::FlowSpecKey {
                afi: Afi::Ipv6,
                rule: rule.clone(),
            },
            rustbgpd_rib::FlowSpecKey {
                afi: Afi::Ipv4,
                rule: rule.clone(),
            },
        ],
        ..empty_outbound_update()
    });
    for expected_afi in [Afi::Ipv4, Afi::Ipv6] {
        let Message::Update(update) = read_single_bgp_message(&mut server).await else {
            panic!("expected FlowSpec withdrawal");
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attribute| match attribute {
                PathAttribute::MpUnreachNlri(mp) => Some(mp),
                _ => None,
            })
            .unwrap();
        assert_eq!(mp.afi, expected_afi);
        assert_eq!(mp.flowspec_withdrawn, vec![rule.clone()]);
    }
}

/// `FlowSpec`'s structured NLRI encoder is fallible, so batching must use
/// `try_build` while shrinking both total-message overflow and structured
/// encoding overflow. Cover v4/v6 announcements and withdrawals, plus the
/// Extended Message ceiling, without dropping or duplicating a rule.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "dual-family reach/unreach chunk receipt"
)]
async fn send_route_update_chunks_flowspec_without_infallible_build() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::FlowSpec), (Afi::Ipv6, Safi::FlowSpec)];
    install_test_negotiated_session(&mut session, negotiated);

    let count: u32 = 500;
    let rule = |afi: Afi, i: u32| FlowSpecRule {
        components: vec![FlowSpecComponent::DestinationPrefix(match afi {
            Afi::Ipv6 => FlowSpecPrefix::V6(Ipv6PrefixOffset {
                prefix: Ipv6Prefix::new(
                    Ipv6Addr::from(0x2001_0db8_0002_0000_0000_0000_0000_0000_u128 + u128::from(i)),
                    128,
                ),
                offset: 0,
            }),
            // The test feeds IPv4 and IPv6 only.
            _ => FlowSpecPrefix::V4(Ipv4Prefix::new(Ipv4Addr::from(0x0a00_0000_u32 + i), 32)),
        })],
    };
    let routes: Vec<FlowSpecRoute> = [Afi::Ipv4, Afi::Ipv6]
        .into_iter()
        .flat_map(|afi| {
            (0..count).map(move |i| FlowSpecRoute {
                rule: rule(afi, i),
                afi,
                peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                attributes: vec![PathAttribute::Origin(Origin::Igp)],
                received_at: Instant::now(),
                origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
                peer_router_id: Ipv4Addr::UNSPECIFIED,
                is_stale: false,
                is_llgr_stale: false,
                path_id: 0,
            })
        })
        .collect();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        flowspec_announce: routes.clone(),
        ..empty_outbound_update()
    });
    let mut announced = std::collections::HashSet::new();
    let mut announce_updates = 0;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(raw.len() <= 4096, "FlowSpec UPDATE is {} bytes", raw.len());
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        if let Some(mp) = parsed.attributes.iter().find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        }) {
            for rule in &mp.flowspec_announced {
                assert!(announced.insert(rule.clone()));
            }
            announce_updates += 1;
        }
    }
    assert!(announce_updates >= 3, "both family groups must be emitted");
    assert_eq!(announced.len(), (count * 2) as usize);

    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        flowspec_withdraw: routes.iter().map(FlowSpecRoute::selection_key).collect(),
        ..empty_outbound_update()
    });
    let mut withdrawn = std::collections::HashSet::new();
    let mut withdraw_updates = 0;
    while let Ok(raw) = tokio::time::timeout(
        Duration::from_millis(500),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    {
        assert!(raw.len() <= 4096);
        let mut buf = Bytes::from(raw);
        let Message::Update(update) =
            rustbgpd_wire::decode_message(&mut buf, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            continue;
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        if let Some(mp) = parsed.attributes.iter().find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        }) {
            for rule in &mp.flowspec_withdrawn {
                assert!(withdrawn.insert(rule.clone()));
            }
            withdraw_updates += 1;
        }
    }
    assert!(withdraw_updates >= 3);
    assert_eq!(withdrawn.len(), (count * 2) as usize);

    session.negotiated.as_mut().unwrap().peer_extended_message = true;
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        flowspec_announce: routes,
        ..empty_outbound_update()
    });
    let first = tokio::time::timeout(
        Duration::from_secs(1),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    .unwrap();
    let second = tokio::time::timeout(
        Duration::from_secs(1),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    .unwrap();
    assert!(first.len() <= 65_535 && second.len() <= 65_535);
    assert!(
        tokio::time::timeout(
            Duration::from_millis(200),
            read_single_raw_bgp_message(&mut server)
        )
        .await
        .is_err(),
        "one Extended Message UPDATE per FlowSpec family expected"
    );
}

#[tokio::test]
async fn send_route_update_uses_ipv6_specific_next_hop_override() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv6, Safi::Unicast)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let route = make_v6_unicast_route("2001:db8::1".parse().unwrap());
    let override_nh =
        rustbgpd_policy::NextHopAction::Specific(IpAddr::V6("2001:db8::42".parse().unwrap()));
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![route].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![Some(override_nh)].into(),
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
    });
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
    assert_eq!(mp.next_hop, IpAddr::V6("2001:db8::42".parse().unwrap()));
}
