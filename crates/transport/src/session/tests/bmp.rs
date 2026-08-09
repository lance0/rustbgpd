use super::*;

#[tokio::test]
async fn session_established_emits_bmp_peer_up() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.local_open_pdu = Some(Bytes::from_static(&[1, 2, 3]));
    session.remote_open_pdu = Some(Bytes::from_static(&[4, 5, 6]));
    session
        .execute_actions(vec![Action::SessionEstablished(Box::new(
            negotiated_session(65002, false),
        ))])
        .await;
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::PeerUp {
            peer_info,
            local_open,
            remote_open,
            ..
        } => {
            assert_eq!(peer_info.peer_addr, session.peer_ip);
            assert_eq!(peer_info.peer_asn, 65002);
            assert_eq!(local_open.as_ref(), &[1, 2, 3]);
            assert_eq!(remote_open.as_ref(), &[4, 5, 6]);
        }
        other => panic!("expected BMP PeerUp, got {other:?}"),
    }
}

#[tokio::test]
async fn accept_any_session_established_uses_learned_asn_for_bmp_and_rib() {
    let (mut session, mut rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 0);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session
        .execute_actions(vec![Action::SessionEstablished(Box::new(
            negotiated_session(65099, false),
        ))])
        .await;
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::PeerUp { peer_info, .. } => {
            assert_eq!(peer_info.peer_asn, 65099);
        }
        other => panic!("expected BMP PeerUp, got {other:?}"),
    }
    match recv_peer_up_after_export_context(&mut rib_rx).await {
        RibUpdate::PeerUp { peer_asn, .. } => {
            assert_eq!(peer_asn, 65099);
        }
        _ => panic!("expected RIB PeerUp"),
    }
}

#[tokio::test]
async fn session_down_emits_bmp_peer_down() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.established_at = Some(Instant::now());
    session.last_down_reason = Some(PeerDownReason::RemoteNoNotification);
    session.execute_actions(vec![Action::SessionDown]).await;
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::PeerDown { peer_info, reason } => {
            assert_eq!(peer_info.peer_addr, session.peer_ip);
            assert!(matches!(reason, PeerDownReason::RemoteNoNotification));
        }
        other => panic!("expected BMP PeerDown, got {other:?}"),
    }
}

#[tokio::test]
async fn inbound_update_emits_bmp_route_monitoring() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    let update = rustbgpd_wire::UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        true,
        false,
        rustbgpd_wire::Ipv4UnicastMode::Body,
    );
    let encoded = rustbgpd_wire::encode_message(&Message::Update(update)).unwrap();
    session.read_buf.buf.extend_from_slice(&encoded);
    session.process_read_buffer().await;
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::RouteMonitoring {
            peer_info,
            update_pdu,
        } => {
            assert_eq!(peer_info.peer_addr, session.peer_ip);
            assert_eq!(update_pdu.as_ref(), encoded.as_ref());
        }
        other => panic!("expected BMP RouteMonitoring, got {other:?}"),
    }
}

/// Load-bearing RFC 6793 ingress proof: deleting legacy `AS4_PATH`
/// reconstruction hides the high local ASN behind `AS_TRANS` and leaves the
/// seeded route installed. Re-encoding the BMP payload canonicalizes the
/// deliberately extended-length type 17 and breaks byte equality; escalating
/// the loop to a reset breaks the Established-state assertion.
#[tokio::test]
async fn legacy_as4_suffix_reaches_loop_detection_after_raw_bmp_tap() {
    const LOCAL_ASN: u32 = 4_200_000_001;
    let (mut session, mut rib_rx, mut bmp_rx) =
        make_test_session_with_rib_and_bmp(LOCAL_ASN, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    while bmp_rx.try_recv().is_ok() {}

    let mut negotiated = negotiated_session(65002, false);
    negotiated.four_octet_as = false;
    install_test_negotiated_session(&mut session, negotiated);
    let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);

    let seed = UpdateMessage::try_build(
        &[Ipv4NlriEntry { path_id: 0, prefix }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002, 65003])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
        ],
        false,
        false,
        Ipv4UnicastMode::Body,
    )
    .unwrap();
    let seed = rustbgpd_wire::encode_message(&Message::Update(seed)).unwrap();
    session.read_buf.buf.extend_from_slice(&seed);
    session.process_read_buffer().await;
    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx.try_recv().expect("seed route reaches the RIB")
    else {
        panic!("expected seed RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    assert!(withdrawn.is_empty());
    assert!(matches!(
        bmp_rx.try_recv(),
        Ok(BmpEvent::RouteMonitoring { .. })
    ));

    let mut attrs = vec![0x40, 1, 1, 0, 0x40, 2, 6, 2, 2];
    attrs.extend_from_slice(&65002u16.to_be_bytes());
    attrs.extend_from_slice(&23456u16.to_be_bytes());
    // Valid but deliberately non-canonical: a 10-byte AS4_PATH value uses
    // the two-octet Extended Length field, so decode + re-encode changes it.
    attrs.extend_from_slice(&[0xD0, 17, 0, 10, 2, 2]);
    attrs.extend_from_slice(&65002u32.to_be_bytes());
    attrs.extend_from_slice(&LOCAL_ASN.to_be_bytes());
    attrs.extend_from_slice(&[0x40, 3, 4, 10, 0, 0, 2]);
    let mut nlri = Vec::new();
    rustbgpd_wire::nlri::encode_nlri(&[prefix], &mut nlri);
    let update = UpdateMessage {
        withdrawn_routes: Bytes::new(),
        path_attributes: Bytes::from(attrs),
        nlri: Bytes::from(nlri),
    };
    let encoded = rustbgpd_wire::encode_message(&Message::Update(update)).unwrap();
    assert!(
        encoded.windows(4).any(|bytes| bytes == [0xD0, 17, 0, 10]),
        "fixture must carry non-canonical extended-length type 17"
    );
    session.read_buf.buf.extend_from_slice(&encoded);
    session.process_read_buffer().await;

    let RibUpdate::RoutesReceived {
        announced,
        withdrawn,
        ..
    } = rib_rx
        .try_recv()
        .expect("loop replacement must withdraw the installed route")
    else {
        panic!("expected loop-withdraw RoutesReceived");
    };
    assert!(announced.is_empty());
    assert_eq!(
        withdrawn,
        vec![(Prefix::V4(prefix), 0)],
        "the reconstructed local ASN must withdraw the exact installed route"
    );
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::RouteMonitoring { update_pdu, .. } => {
            assert_eq!(
                update_pdu.as_ref(),
                encoded.as_ref(),
                "pre-policy BMP must retain the untouched legacy wire UPDATE"
            );
            assert!(
                update_pdu
                    .windows(4)
                    .any(|bytes| bytes == [0xD0, 17, 0, 10]),
                "BMP must retain the deliberately non-canonical type-17 header"
            );
        }
        other => panic!("expected BMP RouteMonitoring, got {other:?}"),
    }
    assert_eq!(session.fsm.state(), SessionState::Established);
}

/// RFC 4271 §5.1.5 requires a received eBGP `LOCAL_PREF` to be ignored,
/// while RFC 7854 pre-policy BMP reports the unprocessed wire UPDATE. Pin
/// both sides of that boundary together: the RIB route loses the attribute,
/// but BMP retains the byte-exact PDU that carried it.
#[tokio::test]
async fn ebgp_local_pref_is_ignored_after_pre_policy_bmp_tap() {
    let (mut session, mut rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast)];
    let update = UpdateMessage::build(
        &[Ipv4NlriEntry {
            path_id: 0,
            prefix: Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24),
        }],
        &[],
        &[
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            PathAttribute::LocalPref(500),
        ],
        true,
        false,
        Ipv4UnicastMode::Body,
    );
    let encoded = rustbgpd_wire::encode_message(&Message::Update(update)).unwrap();
    session.read_buf.buf.extend_from_slice(&encoded);
    session.process_read_buffer().await;

    let RibUpdate::RoutesReceived { announced, .. } = rib_rx.try_recv().unwrap() else {
        panic!("expected RoutesReceived");
    };
    assert_eq!(announced.len(), 1);
    assert_eq!(
        announced[0].local_pref_attr(),
        None,
        "peer-supplied eBGP LOCAL_PREF must not reach the RIB"
    );
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::RouteMonitoring { update_pdu, .. } => {
            assert_eq!(
                update_pdu.as_ref(),
                encoded.as_ref(),
                "pre-policy BMP must preserve the original wire LOCAL_PREF"
            );
        }
        other => panic!("expected BMP RouteMonitoring, got {other:?}"),
    }
}

/// Inbound EVPN UPDATE → BMP `RouteMonitoring` with byte-equal `update_pdu`.
///
/// The BMP emit site at `crates/transport/src/session/io.rs` has no AFI/SAFI
/// filter — every UPDATE flows to the collector with the raw wire bytes.
/// This regression test locks that behavior in: it negotiates L2VPN/EVPN,
/// pushes a Type 2 (MAC/IP) `MP_REACH_NLRI` UPDATE, and asserts that the
/// `BmpEvent::RouteMonitoring` carries the original encoded bytes
/// unchanged. A future refactor that quietly added a unicast-only family
/// gate would fail this test.
#[tokio::test]
async fn inbound_evpn_update_emits_bmp_route_monitoring() {
    use rustbgpd_wire::attribute::MpReachNlri;
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel,
        RouteDistinguisher,
    };
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.negotiated_families = vec![(Afi::L2Vpn, Safi::Evpn)];
    let evpn_route = EvpnRoute::MacIp(EvpnMacIp {
        rd: RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]),
        esi: EthernetSegmentIdentifier::ZERO,
        ethernet_tag: EthernetTagId(0),
        mac: MacAddress([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]),
        ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        label1: MplsLabel::new(100),
        label2: None,
    });
    let attrs = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002])],
        }),
        PathAttribute::MpReachNlri(MpReachNlri {
            afi: Afi::L2Vpn,
            safi: Safi::Evpn,
            next_hop: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            link_local_next_hop: None,
            announced: vec![],
            flowspec_announced: vec![],
            evpn_announced: vec![evpn_route],
            bgpls_announced: vec![],
            labeled_announced: vec![],
            vpn_announced: vec![],
            rtc_announced: vec![],
        }),
    ];
    let update = rustbgpd_wire::UpdateMessage::build(
        &[],
        &[],
        &attrs,
        true,
        false,
        rustbgpd_wire::Ipv4UnicastMode::Body,
    );
    let encoded = rustbgpd_wire::encode_message(&Message::Update(update)).unwrap();
    session.read_buf.buf.extend_from_slice(&encoded);
    session.process_read_buffer().await;
    match bmp_rx.recv().await.unwrap() {
        BmpEvent::RouteMonitoring {
            peer_info,
            update_pdu,
        } => {
            assert_eq!(peer_info.peer_addr, session.peer_ip);
            assert_eq!(
                update_pdu.as_ref(),
                encoded.as_ref(),
                "BMP RouteMonitoring update_pdu must be byte-equal to the inbound \
                 EVPN UPDATE — collectors parse the inner MP_REACH_NLRI to \
                 discover AFI=25/SAFI=70"
            );
        }
        other => panic!("expected BMP RouteMonitoring, got {other:?}"),
    }
}

/// `PeerUp` builds the initial Adj-RIB-Out synchronously, so the RIB must
/// already know the peer's group when it evaluates export policy for that
/// first full-table dump. With the context sent afterwards the dump
/// escaped a group-scoped deny that every later update honored — on a
/// route server with group-scoped export filtering, a leak at session
/// establishment.
#[tokio::test]
async fn initial_table_dump_applies_peer_group_export_policy() {
    assert!(
        initial_dump_announcements(Some("rs-members"))
            .await
            .is_empty(),
        "initial dump to an rs-members peer must be filtered by the \
         group-scoped export deny, not just later updates"
    );
    // Control: the dump is not empty for some unrelated reason.
    assert_eq!(
        initial_dump_announcements(Some("transit")).await.len(),
        1,
        "a peer outside the denied group must still receive the initial dump"
    );
}

/// Outbound UPDATE → RFC 8671 rib-out BMP `RouteMonitoring`, byte-exact
/// with what went on the wire, remote peer identity preserved.
#[tokio::test]
async fn outbound_update_emits_rib_out_bmp_route_monitoring() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.announce = vec![make_route(100)].into();
    update.next_hop_override = vec![None].into();
    session.send_route_update(update);
    let wire = read_single_raw_bgp_message(&mut server).await;
    let pdu = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    assert_eq!(
        pdu.as_ref(),
        &wire[..],
        "BMP rib-out PDU must be byte-exact with the transmitted UPDATE"
    );
}

/// Withdraws and End-of-RIB markers are UPDATEs through the same byte
/// funnel — both are tapped (`EoR` for free, no special-casing).
#[tokio::test]
async fn outbound_withdraw_and_eor_emit_rib_out_bmp() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.withdraw = vec![(
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
        0,
    )];
    update.end_of_rib = vec![(Afi::Ipv4, Safi::Unicast)];
    session.send_route_update(update);
    // Wire order: withdraw UPDATE, then the 23-byte EoR UPDATE.
    let withdraw_wire = read_single_raw_bgp_message(&mut server).await;
    let eor_wire = read_single_raw_bgp_message(&mut server).await;
    assert_eq!(eor_wire.len(), 23, "IPv4 unicast EoR is the empty UPDATE");
    let withdraw_pdu = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    let eor_pdu = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    assert_eq!(withdraw_pdu.as_ref(), &withdraw_wire[..]);
    assert_eq!(eor_pdu.as_ref(), &eor_wire[..]);
}

/// The rib-out tap is off by default (`bmp_rib_out = false`), and even
/// when on it never taps non-UPDATE bulk traffic (ROUTE-REFRESH).
#[tokio::test]
async fn rib_out_tap_default_off_and_skips_non_update_messages() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_route_refresh = true;
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    // Default: bmp_rib_out is false — outbound UPDATE not tapped.
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.announce = vec![make_route(100)].into();
    update.next_hop_override = vec![None].into();
    session.send_route_update(update);
    let _ = read_single_raw_bgp_message(&mut server).await;
    assert!(
        bmp_rx.try_recv().is_err(),
        "rib-out tap must be off unless a collector monitors rib_out_post"
    );
    // Enabled: ROUTE-REFRESH goes through the same bulk channel but is
    // not route monitoring.
    session.config.bmp_rib_out = true;
    let mut refresh = empty_outbound_update();
    refresh.request_refresh_all_negotiated = true;
    session.send_route_update(refresh);
    let _ = read_single_raw_bgp_message(&mut server).await;
    assert!(
        bmp_rx.try_recv().is_err(),
        "non-UPDATE bulk messages must not be tapped"
    );
}

/// Outbound `VPNv4` UPDATE (SAFI 128) → rib-out BMP, byte-exact — the tap
/// sits below the family senders so `RD/label/MP_REACH` encoding is
/// mirrored exactly as transmitted.
#[tokio::test]
async fn outbound_vpn_update_emits_rib_out_bmp_byte_exact() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::MplsVpn)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.vpn_announce = vec![make_vpn_rib_route(4093)];
    session.send_route_update(update);
    let wire = read_single_raw_bgp_message(&mut server).await;
    let pdu = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    assert_eq!(pdu.as_ref(), &wire[..]);
}

/// Outbound EVPN UPDATE (AFI 25 / SAFI 70) → rib-out BMP, byte-exact.
#[tokio::test]
async fn outbound_evpn_update_emits_rib_out_bmp_byte_exact() {
    use rustbgpd_wire::{
        EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel,
        RouteDistinguisher,
    };
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let mut negotiated = negotiated_session(65002, false);
    negotiated.negotiated_families = vec![(Afi::L2Vpn, Safi::Evpn)];
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    let evpn_route = rustbgpd_rib::EvpnRibRoute {
        route: EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac: MacAddress([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]),
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            label1: MplsLabel::new(100),
            label2: None,
        }),
        next_hop: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)),
        link_local_next_hop: None,
        peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        attributes: Arc::new(vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65002])],
            }),
        ]),
        received_at: Instant::now(),
        origin_type: rustbgpd_rib::RouteOrigin::Ebgp,
        peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
        is_stale: false,
        is_llgr_stale: false,
    };
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.evpn_announce = vec![evpn_route];
    session.send_route_update(update);
    let wire = read_single_raw_bgp_message(&mut server).await;
    let pdu = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    assert_eq!(pdu.as_ref(), &wire[..]);
}

/// The rib-out tap keeps the non-blocking posture: a full BMP event
/// channel drops the event and bumps `bmp_source_drops_total` — it
/// never blocks or tears down the session. But the drop is no longer
/// silent: the UPDATE did reach the wire, so the session latches the
/// divergence for the forced peer-state reset (see
/// `bmp_channel_full_after_wire_send_forces_peer_state_reset`).
#[tokio::test]
async fn rib_out_tap_full_channel_increments_source_drop_counter() {
    let (mut session, _rib_rx, _bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    // The helper's BMP channel holds 16 events; never drain it. The
    // 17th tapped UPDATE hits Full and must count a source drop.
    for _ in 0..17 {
        let mut update = empty_outbound_update();
        update.exact_export_snapshot = Some(session.publish_export_profile());
        update.announce = vec![make_route(100)].into();
        update.next_hop_override = vec![None].into();
        session.send_route_update(update);
    }
    let drops: u64 = session
        .metrics
        .registry()
        .gather()
        .iter()
        .filter(|f| f.name() == "bmp_source_drops_total")
        .flat_map(|f| f.metric.iter())
        .map(|m| {
            #[expect(
                clippy::cast_possible_truncation,
                clippy::cast_sign_loss,
                reason = "Prometheus counters are monotonic non-negative integers exposed as f64"
            )]
            let v = m.counter.value() as u64;
            v
        })
        .sum();
    assert_eq!(drops, 1, "17th event over a 16-deep channel drops once");
    assert!(
        session.writer_bulk_tx.is_some(),
        "a BMP-side drop must never tear down the BGP session"
    );
    assert!(
        session.bmp_stream_diverged,
        "a dropped rib-out RouteMonitoring must latch the divergence"
    );
    assert!(
        session.bmp_repair_timer.is_some(),
        "the bounded-latency repair timer must be armed"
    );
}

/// Outbound-writer saturation ordering: the UPDATE that failed to
/// enqueue is never mirrored to BMP (RFC 8671 mirrors what was actually
/// sent), and the saturation teardown ends in a BMP `PeerDown` ordered
/// after the last mirrored `RouteMonitoring` on the same channel — a
/// collector sees an explicit resync signal (discard peer state; the
/// re-established session re-floods), never a silent gap.
#[tokio::test]
async fn writer_saturation_orders_bmp_peer_down_after_last_mirrored_update() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    match bmp_rx.try_recv().unwrap() {
        BmpEvent::PeerUp { .. } => {}
        other => panic!("expected BMP PeerUp, got {other:?}"),
    }
    // Swap in a capacity-1 bulk channel that is never drained: the
    // first UPDATE enqueues (and is mirrored), the second hits Full.
    let (bulk_tx, _bulk_rx) = mpsc::channel(1);
    session.writer_bulk_tx = Some(bulk_tx);
    for lp in [100, 200] {
        let mut update = empty_outbound_update();
        update.exact_export_snapshot = Some(session.publish_export_profile());
        update.announce = vec![make_route(lp)].into();
        update.next_hop_override = vec![None].into();
        session.send_route_update(update);
    }
    assert!(
        session.writer_bulk_tx.is_none(),
        "bulk-channel Full must trigger the saturation teardown"
    );
    // Run-loop follow-through: the writer exit surfaces as a TCP
    // disconnect and drives the FSM out of Established.
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert_ne!(session.fsm.state(), SessionState::Established);
    // BMP stream order: the mirrored UPDATE, then PeerDown. Nothing
    // for the UPDATE that never reached the wire.
    let _mirrored = expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    match bmp_rx.try_recv().unwrap() {
        BmpEvent::PeerDown { reason, .. } => match reason {
            PeerDownReason::LocalNotification(pdu) => {
                // 19-byte header, then code 6 (Cease) / subcode 8
                // (Out of Resources).
                assert_eq!(&pdu[19..21], &[6, 8], "Cease/8 NOTIFICATION PDU");
            }
            other => panic!("expected reason 1 (local NOTIFICATION), got {other:?}"),
        },
        other => panic!("expected BMP PeerDown after the last mirrored RM, got {other:?}"),
    }
    assert!(
        bmp_rx.try_recv().is_err(),
        "no RouteMonitoring may be emitted for the UPDATE that never reached the wire"
    );
}

/// The inverse saturation case — the wire send succeeded but the BMP
/// channel was full: the divergence is repaired by forcing a synthetic
/// PeerDown/PeerUp pair (RFC 7854 peer-state reset) ahead of the next
/// emission, so collectors detect the reset instead of keeping a
/// silently incomplete Adj-RIB-Out view forever.
#[tokio::test]
async fn bmp_channel_full_after_wire_send_forces_peer_state_reset() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.config.bmp_rib_out = true;
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    let negotiated = negotiated_session(65002, false);
    session
        .negotiated_families
        .clone_from(&negotiated.negotiated_families);
    session.negotiated = Some(negotiated);
    session.local_open_pdu = Some(Bytes::from_static(&[1, 2, 3]));
    session.remote_open_pdu = Some(Bytes::from_static(&[4, 5, 6]));
    // 16 mirrored UPDATEs fill the channel; the 17th reaches the wire
    // but its RouteMonitoring is dropped → divergence latched.
    for _ in 0..17 {
        let mut update = empty_outbound_update();
        update.exact_export_snapshot = Some(session.publish_export_profile());
        update.announce = vec![make_route(100)].into();
        update.next_hop_override = vec![None].into();
        session.send_route_update(update);
    }
    assert!(session.bmp_stream_diverged);
    for _ in 0..16 {
        expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    }
    // Next emission repairs the stream first: PeerDown, PeerUp, then
    // the new RouteMonitoring — in that order, on the same channel.
    let mut update = empty_outbound_update();
    update.exact_export_snapshot = Some(session.publish_export_profile());
    update.announce = vec![make_route(300)].into();
    update.next_hop_override = vec![None].into();
    session.send_route_update(update);
    assert!(!session.bmp_stream_diverged, "repair must clear the latch");
    assert!(session.bmp_repair_timer.is_none());
    match bmp_rx.try_recv().unwrap() {
        BmpEvent::PeerDown { reason, .. } => assert!(
            matches!(reason, PeerDownReason::LocalNoNotification(0)),
            "synthetic reset uses reason 2 with FSM event code 0, got {reason:?}"
        ),
        other => panic!("expected synthetic BMP PeerDown, got {other:?}"),
    }
    match bmp_rx.try_recv().unwrap() {
        BmpEvent::PeerUp { local_open, .. } => {
            assert_eq!(local_open.as_ref(), &[1, 2, 3], "cached OPEN replayed");
        }
        other => panic!("expected synthetic BMP PeerUp, got {other:?}"),
    }
    expect_rib_out_rm(bmp_rx.try_recv().unwrap());
    assert!(bmp_rx.try_recv().is_err());
}

/// A session that goes quiet right after the drop is repaired from the
/// run loop's `bmp_repair_timer` arm instead of waiting for its next
/// UPDATE: retry re-arms while the channel is saturated and emits the
/// PeerDown/PeerUp reset once it drains.
#[tokio::test]
async fn bmp_repair_timer_retries_until_channel_drains() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    // Fill the 16-deep channel, then latch divergence with one more RM.
    let tx = session.bmp_tx.clone().unwrap();
    for _ in 0..16 {
        tx.try_send(BmpEvent::StatsReport {
            peer_info: session.build_bmp_peer_info(),
            adj_rib_in_routes: 0,
            adj_rib_out_post: None,
        })
        .unwrap();
    }
    session.emit_bmp_event(BmpEvent::RouteMonitoring {
        peer_info: session.build_bmp_peer_info(),
        update_pdu: Bytes::from_static(&[0xde, 0xad]),
    });
    assert!(session.bmp_stream_diverged);
    // Channel still full: the retry must keep the latch and re-arm.
    session.bmp_repair_timer = None;
    session.retry_bmp_stream_repair();
    assert!(session.bmp_stream_diverged);
    assert!(session.bmp_repair_timer.is_some(), "retry must re-arm");
    // Drain, then retry succeeds.
    for _ in 0..16 {
        bmp_rx.try_recv().unwrap();
    }
    session.retry_bmp_stream_repair();
    assert!(!session.bmp_stream_diverged);
    assert!(session.bmp_repair_timer.is_none());
    assert!(matches!(
        bmp_rx.try_recv().unwrap(),
        BmpEvent::PeerDown { .. }
    ));
    assert!(matches!(
        bmp_rx.try_recv().unwrap(),
        BmpEvent::PeerUp { .. }
    ));
}

/// `PeerDown` is never lost to a full BMP channel: the session awaits
/// channel space (bounded — the `BmpManager` loop always drains) rather
/// than dropping the one signal that tells collectors to discard the
/// peer's state.
#[tokio::test]
async fn bmp_peer_down_survives_full_channel() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.established_at = Some(Instant::now());
    session.last_down_reason = Some(PeerDownReason::RemoteNoNotification);
    let tx = session.bmp_tx.clone().unwrap();
    for _ in 0..16 {
        tx.try_send(BmpEvent::StatsReport {
            peer_info: session.build_bmp_peer_info(),
            adj_rib_in_routes: 0,
            adj_rib_out_post: None,
        })
        .unwrap();
    }
    // Consumer (the BmpManager stand-in) drains concurrently; the
    // awaited PeerDown send completes once space frees up.
    let drain = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        while let Some(event) = bmp_rx.recv().await {
            if matches!(event, BmpEvent::PeerDown { .. }) {
                return true;
            }
        }
        false
    });
    session.execute_actions(vec![Action::SessionDown]).await;
    drop(session);
    assert!(
        drain.await.unwrap(),
        "PeerDown must be delivered even when the channel was full"
    );
}

/// LAN-200: a TCP disconnect abandons any pending BMP divergence repair.
/// Otherwise the run loop's `bmp_repair_timer` arm could fire after the
/// socket died and emit a synthetic `PeerDown`/`PeerUp` for a dead session
/// — which the reconnect would then stack a real `PeerUp` on top of.
#[tokio::test]
async fn tcp_disconnect_clears_bmp_repair_latch() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    session.tcp_ao_info = Some(crate::TcpAoInfoSnapshot {
        has_current_key: true,
        has_rnext_key: true,
        ao_required: true,
        accept_icmps: false,
        current_key: 7,
        rnext_key: 9,
        pkt_good: 12,
        pkt_bad: 0,
        pkt_key_not_found: 0,
        pkt_ao_required: 0,
        pkt_dropped_icmp: 0,
        keys: Vec::new(),
    });
    // Latch divergence + arm the repair timer via a dropped RM on a full
    // channel.
    let tx = session.bmp_tx.clone().unwrap();
    for _ in 0..16 {
        tx.try_send(BmpEvent::StatsReport {
            peer_info: session.build_bmp_peer_info(),
            adj_rib_in_routes: 0,
            adj_rib_out_post: None,
        })
        .unwrap();
    }
    session.emit_bmp_event(BmpEvent::RouteMonitoring {
        peer_info: session.build_bmp_peer_info(),
        update_pdu: Bytes::from_static(&[0xde, 0xad]),
    });
    assert!(session.bmp_stream_diverged);
    assert!(session.bmp_repair_timer.is_some());
    // Drain so a stray repair *could* succeed if it fired.
    for _ in 0..16 {
        bmp_rx.try_recv().unwrap();
    }
    // TCP disconnect must abandon the repair outright.
    session.handle_tcp_disconnect();
    assert!(session.tcp_ao_info.is_none(), "disconnect clears AO health");
    assert!(
        !session.bmp_stream_diverged,
        "disconnect clears the divergence latch"
    );
    assert!(
        session.bmp_repair_timer.is_none(),
        "disconnect disarms the repair timer"
    );
    // A late repair-timer fire on the dead session must emit nothing.
    session.retry_bmp_stream_repair();
    assert!(
        bmp_rx.try_recv().is_err(),
        "no synthetic PeerDown/PeerUp for a dead session"
    );
}

/// LAN-201: a partial repair attempt — `PeerDown` enqueued, `PeerUp` hits
/// a full channel — leaves the latch set and retries. The collector-visible
/// sequence carries a duplicate `PeerDown`, which is acceptable: RFC 7854
/// `PeerDown` is idempotent (the collector has already discarded peer state
/// from the first one), and the pair still ends in exactly one `PeerUp`.
#[tokio::test]
async fn repair_partial_enqueue_duplicate_peer_down_is_acceptable() {
    let (mut session, _rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    session.negotiated = Some(negotiated_session(65002, false));
    let tx = session.bmp_tx.clone().unwrap();
    // Leave exactly one free slot in the 16-deep channel: PeerDown will
    // enqueue, the following PeerUp hits Full.
    for _ in 0..15 {
        tx.try_send(BmpEvent::StatsReport {
            peer_info: session.build_bmp_peer_info(),
            adj_rib_in_routes: 0,
            adj_rib_out_post: None,
        })
        .unwrap();
    }
    session.bmp_stream_diverged = true;
    // Partial attempt: PeerDown enqueues, PeerUp returns Full → incomplete.
    assert!(
        !session.repair_bmp_stream(&tx),
        "PeerUp Full leaves the repair incomplete"
    );
    assert!(
        session.bmp_stream_diverged,
        "latch stays set after a partial attempt"
    );
    // Drain the 15 fillers; the 16th queued item is the partial PeerDown.
    for _ in 0..15 {
        assert!(matches!(
            bmp_rx.try_recv().unwrap(),
            BmpEvent::StatsReport { .. }
        ));
    }
    assert!(
        matches!(bmp_rx.try_recv().unwrap(), BmpEvent::PeerDown { .. }),
        "partial attempt enqueued a PeerDown"
    );
    // Channel now empty → the retry completes the reset: PeerDown, PeerUp.
    assert!(
        session.repair_bmp_stream(&tx),
        "retry completes once the channel drains"
    );
    assert!(!session.bmp_stream_diverged);
    assert!(matches!(
        bmp_rx.try_recv().unwrap(),
        BmpEvent::PeerDown { .. }
    ));
    assert!(matches!(
        bmp_rx.try_recv().unwrap(),
        BmpEvent::PeerUp { .. }
    ));
    assert!(
        bmp_rx.try_recv().is_err(),
        "the completed reset ends in exactly one PeerUp"
    );
}
