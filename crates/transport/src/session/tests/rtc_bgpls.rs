use super::*;

#[tokio::test]
async fn send_route_update_emits_bgpls_reach_and_unreach() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::BgpLs, Safi::BgpLs)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let route = make_bgpls_route(0xcc);
    let key = route.key();
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![route.clone()],
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
        panic!("expected BGP-LS MP_REACH UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpReachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("BGP-LS announcement must use MP_REACH");
    assert_eq!(mp.afi, Afi::BgpLs);
    assert_eq!(mp.safi, Safi::BgpLs);
    assert_eq!(mp.next_hop, route.next_hop);
    assert_eq!(mp.bgpls_announced, vec![route.nlri.clone()]);
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![key],
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
        panic!("expected BGP-LS MP_UNREACH UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("BGP-LS withdrawal must use MP_UNREACH");
    assert_eq!(mp.afi, Afi::BgpLs);
    assert_eq!(mp.safi, Safi::BgpLs);
    assert_eq!(mp.bgpls_withdrawn, vec![route.nlri]);
}

#[tokio::test]
async fn oversized_bgpls_output_tears_down_session() {
    use rustbgpd_wire::notification::{NotificationCode, cease_subcode};
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::BgpLs, Safi::BgpLs)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut route = make_bgpls_route(0xdd);
    route.nlri = BgpLsNlri::try_new(
        BgpLsNlriType::Unknown(65_000),
        None,
        Bytes::from(vec![0xab; usize::from(rustbgpd_wire::MAX_MESSAGE_LEN)]),
    )
    .expect("oversize-for-peer fixture still fits BGP-LS NLRI length");
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![route],
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
    assert!(
        session.read_half.is_none(),
        "structurally unsendable BGP-LS output must tear down the peer"
    );
    let join = session
        .writer_join
        .take()
        .expect("writer_join stays for run-loop observation after teardown");
    let Message::Notification(notif) = read_single_bgp_message(&mut server).await else {
        panic!("expected Cease/Out-of-Resources for oversize BGP-LS output");
    };
    assert_eq!(notif.code, NotificationCode::Cease);
    assert_eq!(notif.subcode, cease_subcode::OUT_OF_RESOURCES);
    let result = tokio::time::timeout(Duration::from_secs(2), join)
        .await
        .expect("writer should exit after oversize-triggered teardown")
        .expect("writer join should not panic");
    assert!(
        matches!(result, Err(super::writer::WriterExit::TornDown)),
        "oversize output routes through the out-of-resources hard close, got: {result:?}"
    );
}

/// Import-policy denial retires an accepted RTC identity exactly once,
/// deduplicates an overlapping explicit withdrawal, keeps first-seen denials
/// silent, and reconciles max-prefix plus Enhanced Refresh accounting.
///
/// Break-to-red: deleting denied-key collection leaves the accepted route and
/// stale refresh identity live; appending without `known_rtc.remove` duplicates
/// the overlap and emits a first-seen withdrawal; capturing refresh state
/// without the synthetic withdrawal leaves the stale count unchanged.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered refresh sequence proves replacement, deduplication, and accounting"
)]
async fn denied_rtc_replacements_reconcile_exact_refresh_identity() {
    use rustbgpd_wire::{MpReachNlri, MpUnreachNlri, RtcNlri};

    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    let family = (Afi::Ipv4, Safi::RtConstrain);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![family];
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = true;
    install_test_negotiated_session(&mut session, negotiated);

    let nlri =
        |admin: u16| RtcNlri::new(65002, 0x0002_FDEA_0000_0000 | u64::from(admin), 96).unwrap();
    let first = nlri(11);
    let overlap = nlri(22);
    let first_seen = nlri(33);
    let key = |nlri| rustbgpd_rib::RtcRibRouteKey { nlri, path_id: 0 };
    let base_attrs = || {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
        ]
    };
    let reach = |nlris: Vec<RtcNlri>| {
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: nlris,
        })
    };
    let unreach = |nlris: Vec<RtcNlri>| {
        PathAttribute::MpUnreachNlri(MpUnreachNlri {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            withdrawn: vec![],
            flowspec_withdrawn: vec![],
            evpn_withdrawn: vec![],
            bgpls_withdrawn: vec![],
            labeled_withdrawn: vec![],
            vpn_withdrawn: vec![],
            rtc_withdrawn: nlris,
        })
    };
    let update = |mut attributes: Vec<PathAttribute>, reach_attr, unreach_attr| {
        attributes.push(reach_attr);
        if let Some(unreach_attr) = unreach_attr {
            attributes.push(unreach_attr);
        }
        UpdateMessage::build(&[], &[], &attributes, true, false, Ipv4UnicastMode::Body)
    };

    session
        .process_update(update(base_attrs(), reach(vec![first, overlap]), None))
        .await;
    let RibUpdate::RtcRoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("accepted RTC routes reach the RIB")
    else {
        panic!("expected RtcRoutesReceived");
    };
    assert_eq!(announced.len(), 2);
    assert!(withdrawn.is_empty());
    assert_eq!(session.known_prefix_count(), 2);

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::RtConstrain,
        RouteRefreshSubtype::BoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::BeginRouteRefresh {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            ..
        })
    ));
    assert_eq!(session.refresh_accounting_stale_count(family), Some(2));

    session.install_import_policy(Some(PolicyChain::new(vec![Policy {
        entries: vec![],
        default_action: PolicyAction::Deny,
    }])));

    session
        .process_update(update(base_attrs(), reach(vec![first]), None))
        .await;
    let RibUpdate::RtcRoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("denied RTC replacement reaches the RIB")
    else {
        panic!("expected RtcRoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![key(first)]);
    assert_eq!(session.known_prefix_count(), 1);
    assert_eq!(session.refresh_accounting_stale_count(family), Some(1));

    session
        .process_update(update(
            base_attrs(),
            reach(vec![overlap]),
            Some(unreach(vec![overlap])),
        ))
        .await;
    let RibUpdate::RtcRoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx.try_recv().expect("overlap reaches the RIB once")
    else {
        panic!("expected RtcRoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(withdrawn, vec![key(overlap)]);
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.refresh_accounting_stale_count(family), Some(0));

    session
        .process_update(update(base_attrs(), reach(vec![first_seen]), None))
        .await;
    assert!(
        rib_rx.try_recv().is_err(),
        "first-seen RTC denial is silent"
    );
    assert!(!session.known_rtc.contains(&key(first_seen)));
    assert_eq!(session.known_prefix_count(), 0);
    assert_eq!(session.refresh_accounting_stale_count(family), Some(0));

    buffer_route_refresh(
        &mut session,
        Afi::Ipv4,
        Safi::RtConstrain,
        RouteRefreshSubtype::EoRR,
    );
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::EndRouteRefresh {
            afi: Afi::Ipv4,
            safi: Safi::RtConstrain,
            ..
        })
    ));
    assert_eq!(session.refresh_accounting_window_count(), 0);
}

/// Import-policy denial retires an accepted BGP-LS identity exactly once for
/// SAFI 71 and 72, deduplicates an overlapping explicit withdrawal, keeps
/// first-seen denials silent, and reconciles max-prefix plus Enhanced Refresh.
///
/// Break-to-red: deleting denied-key collection leaves the accepted topology
/// object and stale refresh identity live; appending without
/// `known_bgpls.remove` duplicates the overlap and emits first-seen state;
/// omitting the synthetic withdrawal from refresh capture leaves stale count.
#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "one ordered refresh sequence covers both BGP-LS SAFIs"
)]
async fn denied_bgpls_replacements_reconcile_exact_refresh_identity_for_both_safis() {
    use rustbgpd_rib::BgpLsFamily;
    use rustbgpd_wire::{MpReachNlri, MpUnreachNlri};

    fn nlri(safi: Safi, suffix: u8) -> BgpLsNlri {
        match safi {
            Safi::BgpLs => decode_bgpls_nlri(&[0xfd, 0xe8, 0, 3, 0xaa, 0xbb, suffix]),
            Safi::BgpLsVpn => decode_bgpls_vpn_nlri(&[
                0xfd, 0xe8, 0, 11, // 8-byte RD + 3-byte opaque payload
                0, 0, 0xfd, 0xea, 0, 0, 0, 44, 0xaa, 0xbb, suffix,
            ]),
            _ => unreachable!("fixture covers only BGP-LS SAFIs"),
        }
        .expect("fixture BGP-LS NLRI decodes")
        .pop()
        .expect("fixture contains one BGP-LS NLRI")
    }

    #[expect(
        clippy::too_many_lines,
        reason = "the per-SAFI sequence proves replacement, deduplication, and accounting"
    )]
    async fn exercise(safi: Safi) {
        let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
        let afi = Afi::BgpLs;
        let family = (afi, safi);
        let bgpls_family = BgpLsFamily::from_afi_safi(afi, safi).unwrap();
        let mut negotiated = negotiated_session(65002, false);
        negotiated.negotiated_families = vec![family];
        negotiated.peer_route_refresh = true;
        negotiated.peer_enhanced_route_refresh = true;
        install_test_negotiated_session(&mut session, negotiated);

        let first = nlri(safi, 11);
        let overlap = nlri(safi, 22);
        let first_seen = nlri(safi, 33);
        let key = |nlri: &BgpLsNlri| rustbgpd_rib::BgpLsRouteKey {
            family: bgpls_family,
            nlri: nlri.key(),
            path_id: 0,
        };
        let base_attrs = || {
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65002])],
                }),
            ]
        };
        let reach = |nlris: Vec<BgpLsNlri>| {
            PathAttribute::MpReachNlri(MpReachNlri {
                afi,
                safi,
                next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)),
                link_local_next_hop: None,
                announced: vec![],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: nlris,
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            })
        };
        let unreach = |nlris: Vec<BgpLsNlri>| {
            PathAttribute::MpUnreachNlri(MpUnreachNlri {
                afi,
                safi,
                withdrawn: vec![],
                flowspec_withdrawn: vec![],
                evpn_withdrawn: vec![],
                bgpls_withdrawn: nlris,
                labeled_withdrawn: vec![],
                vpn_withdrawn: vec![],
                rtc_withdrawn: vec![],
            })
        };
        let update = |mut attributes: Vec<PathAttribute>, reach_attr, unreach_attr| {
            attributes.push(reach_attr);
            if let Some(unreach_attr) = unreach_attr {
                attributes.push(unreach_attr);
            }
            UpdateMessage::build(&[], &[], &attributes, true, false, Ipv4UnicastMode::Body)
        };

        session
            .process_update(update(
                base_attrs(),
                reach(vec![first.clone(), overlap.clone()]),
                None,
            ))
            .await;
        let RibUpdate::BgpLsRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().expect("accepted BGP-LS routes reach RIB")
        else {
            panic!("expected BgpLsRoutesReceived");
        };
        assert_eq!(announced.len(), 2);
        assert!(withdrawn.is_empty());
        assert_eq!(session.known_prefix_count(), 2);

        buffer_route_refresh(&mut session, afi, safi, RouteRefreshSubtype::BoRR);
        session.process_read_buffer().await;
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::BeginRouteRefresh {
                afi: Afi::BgpLs,
                safi: marker_safi,
                ..
            }) if marker_safi == safi
        ));
        assert_eq!(session.refresh_accounting_stale_count(family), Some(2));

        session.install_import_policy(Some(PolicyChain::new(vec![Policy {
            entries: vec![],
            default_action: PolicyAction::Deny,
        }])));

        session
            .process_update(update(base_attrs(), reach(vec![first.clone()]), None))
            .await;
        let RibUpdate::BgpLsRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx
            .try_recv()
            .expect("denied BGP-LS replacement reaches RIB")
        else {
            panic!("expected BgpLsRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec![key(&first)]);
        assert_eq!(session.known_prefix_count(), 1);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(1));

        session
            .process_update(update(
                base_attrs(),
                reach(vec![overlap.clone()]),
                Some(unreach(vec![overlap.clone()])),
            ))
            .await;
        let RibUpdate::BgpLsRoutesReceived {
            announced,
            withdrawn,
            ..
        } = rib_rx.try_recv().expect("BGP-LS overlap reaches RIB once")
        else {
            panic!("expected BgpLsRoutesReceived");
        };
        assert!(announced.is_empty());
        assert_eq!(withdrawn, vec![key(&overlap)]);
        assert_eq!(session.known_prefix_count(), 0);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(0));

        session
            .process_update(update(base_attrs(), reach(vec![first_seen.clone()]), None))
            .await;
        assert!(
            rib_rx.try_recv().is_err(),
            "first-seen BGP-LS denial is silent"
        );
        assert!(!session.known_bgpls.contains(&key(&first_seen)));
        assert_eq!(session.known_prefix_count(), 0);
        assert_eq!(session.refresh_accounting_stale_count(family), Some(0));

        buffer_route_refresh(&mut session, afi, safi, RouteRefreshSubtype::EoRR);
        session.process_read_buffer().await;
        assert!(matches!(
            rib_rx.try_recv(),
            Ok(RibUpdate::EndRouteRefresh {
                afi: Afi::BgpLs,
                safi: marker_safi,
                ..
            }) if marker_safi == safi
        ));
        assert_eq!(session.refresh_accounting_window_count(), 0);
    }

    exercise(Safi::BgpLs).await;
    exercise(Safi::BgpLsVpn).await;
}

/// RTC `MP_REACH` carries the membership NLRI verbatim with the stored
/// next-hop; the locally-originated default (stored with an unspecified
/// next-hop) is emitted with the session-local address. The withdraw uses
/// the same NLRI codec via `MP_UNREACH`.
#[expect(
    clippy::too_many_lines,
    reason = "pins announce grouping, both next-hop forms, and the withdraw in one wire sequence"
)]
#[tokio::test]
async fn send_route_update_emits_rtc_reach_and_unreach() {
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    let session_local_ip = client.local_addr().unwrap().ip();
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::RtConstrain)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let route = make_rtc_rib_route(100);
    let key = route.key();
    // A locally-originated default rides in the same update; its stored
    // next-hop is unspecified and must be rewritten to the session-local
    // address on the wire.
    let local_default = rustbgpd_rib::RtcRibRoute {
        nlri: rustbgpd_wire::RtcNlri::DEFAULT,
        next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        peer: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        attributes: Arc::new(vec![PathAttribute::Origin(Origin::Igp)]),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Local,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        is_stale: false,
        is_llgr_stale: false,
        path_id: 0,
    };
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_announce: vec![route.clone(), local_default],
        rtc_withdraw: vec![],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    });
    // Distinct next-hops (stored vs session-local) split into two UPDATEs.
    let mut seen_nlris = Vec::new();
    let mut seen_next_hops = Vec::new();
    for _ in 0..2 {
        let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
            panic!("expected RTC MP_REACH UPDATE");
        };
        let parsed = msg.parse(true, false, &[]).unwrap();
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .expect("RTC announcement must use MP_REACH");
        assert_eq!(mp.afi, Afi::Ipv4);
        assert_eq!(mp.safi, Safi::RtConstrain);
        seen_nlris.extend(mp.rtc_announced.iter().copied());
        seen_next_hops.push(mp.next_hop);
    }
    assert!(
        seen_nlris.contains(&route.nlri),
        "membership NLRI must ride through verbatim"
    );
    assert!(
        seen_nlris.contains(&rustbgpd_wire::RtcNlri::DEFAULT),
        "default NLRI must be emitted"
    );
    assert!(
        seen_next_hops.contains(&route.next_hop),
        "stored RTC next-hop must pass through unchanged"
    );
    assert!(
        seen_next_hops.contains(&session_local_ip),
        "local default must be emitted with the session-local address, got {seen_next_hops:?}"
    );
    session.send_route_update(OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce_source_exclusion: None,
        otc_blocked: vec![],
        announce: vec![].into(),
        withdraw: vec![],
        end_of_rib: vec![],
        refresh_markers: vec![],
        next_hop_override: vec![].into(),
        flowspec_announce: vec![],
        flowspec_withdraw: vec![],
        evpn_announce: vec![],
        evpn_withdraw: vec![],
        bgpls_announce: vec![],
        bgpls_withdraw: vec![],
        vpn_announce: vec![],
        labeled_announce: vec![],
        vpn_withdraw: vec![],
        labeled_withdraw: vec![],
        rtc_announce: vec![],
        rtc_withdraw: vec![key],
        request_refresh_all_negotiated: false,
        shared_group_encode: None,
    });
    let Message::Update(msg) = read_single_bgp_message(&mut server).await else {
        panic!("expected RTC MP_UNREACH UPDATE");
    };
    let parsed = msg.parse(true, false, &[]).unwrap();
    let mp = parsed
        .attributes
        .iter()
        .find_map(|attr| match attr {
            PathAttribute::MpUnreachNlri(mp) => Some(mp),
            _ => None,
        })
        .expect("RTC withdrawal must use MP_UNREACH");
    assert_eq!(mp.afi, Afi::Ipv4);
    assert_eq!(mp.safi, Safi::RtConstrain);
    assert_eq!(mp.rtc_withdrawn, vec![route.nlri]);
}

/// iBGP reflection of an RTC route on an RR adds `ORIGINATOR_ID` and
/// `CLUSTER_LIST` — identical semantics to the VPN preparation.
#[test]
fn prepare_outbound_attributes_rtc_adds_rr_attrs_for_ibgp_reflection() {
    let mut session = make_test_session(65001, 65001);
    let cluster_id = Ipv4Addr::new(10, 0, 0, 9);
    let source_id = Ipv4Addr::new(10, 0, 0, 42);
    session.config.cluster_id = Some(cluster_id);
    let mut route = make_rtc_rib_route(100);
    route.origin_type = rustbgpd_rib::RouteOrigin::Ibgp;
    route.peer_router_id = source_id;
    route.attributes = Arc::new(vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath { segments: vec![] }),
        PathAttribute::LocalPref(200),
    ]);
    let attrs = session.prepare_outbound_attributes_rtc(&route, false);
    assert!(
        attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::OriginatorId(id) if *id == source_id))
    );
    assert!(
        attrs.iter().any(
            |a| matches!(a, PathAttribute::ClusterList(ids) if ids.as_slice() == [cluster_id])
        )
    );
    assert!(!attrs.iter().any(|a| matches!(
        a,
        PathAttribute::NextHop(_) | PathAttribute::MpReachNlri(_) | PathAttribute::MpUnreachNlri(_)
    )));
}
