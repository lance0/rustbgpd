use super::*;

fn raw_refresh(body_len: usize, subtype: u8) -> Bytes {
    let length = 19 + body_len;
    let mut raw = vec![0xff; 16];
    raw.extend_from_slice(&u16::try_from(length).unwrap().to_be_bytes());
    raw.push(5);
    raw.resize(length, 0);
    if body_len >= 2 {
        raw[20] = 1;
    }
    if body_len >= 3 {
        raw[21] = subtype;
    }
    if body_len >= 4 {
        raw[22] = 1;
    }
    Bytes::from(raw)
}

async fn refresh_session(
    enhanced: bool,
    peer_extended: bool,
) -> (
    PeerSession,
    TcpStream,
    mpsc::Receiver<RibUpdate>,
    mpsc::Receiver<BmpEvent>,
) {
    let (mut session, mut rib_rx, mut bmp_rx) = make_test_session_with_rib_and_bmp(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    // Complete the establishment writes before testing a subsequent frame.
    assert!(matches!(
        read_single_bgp_message(&mut server).await,
        Message::Open(_)
    ));
    assert!(matches!(
        read_single_bgp_message(&mut server).await,
        Message::Keepalive
    ));
    let mut negotiated = negotiated_session(65002, false);
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = enhanced;
    negotiated.peer_extended_message = peer_extended;
    install_test_negotiated_session(&mut session, negotiated);
    while rib_rx.try_recv().is_ok() {}
    while bmp_rx.try_recv().is_ok() {}
    (session, server, rib_rx, bmp_rx)
}

async fn assert_bad_refresh(
    body_len: usize,
    subtype: u8,
    local_extended: bool,
    peer_extended: bool,
) {
    let (mut session, mut server, _rib_rx, mut bmp_rx) = refresh_session(true, peer_extended).await;
    session
        .read_buf
        .set_max_message_len(if local_extended { 65535 } else { 4096 });
    let raw = raw_refresh(body_len, subtype);
    session.read_buf.buf.extend_from_slice(&raw);
    session.process_read_buffer().await;
    let sent = tokio::time::timeout(
        Duration::from_secs(2),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    .expect("malformed ERR must send NOTIFICATION before closing");
    assert_eq!(&sent[19..21], &[7, 1]);
    let limit = if peer_extended { 65535 } else { 4096 };
    assert!(sent.len() <= limit);
    if raw.len() <= limit - 21 {
        assert_eq!(
            &sent[21..],
            raw.as_ref(),
            "include the complete offending PDU"
        );
    } else {
        assert_eq!(sent.len(), 21, "unrepresentable PDU must have empty Data");
    }
    assert_ne!(session.fsm.state(), SessionState::Established);
    let BmpEvent::PeerDown {
        reason: PeerDownReason::LocalNotification(pdu),
        ..
    } = bmp_rx.try_recv().unwrap()
    else {
        panic!("expected BMP local notification cause");
    };
    assert_eq!(pdu.as_ref(), sent, "BMP must carry the bytes sent on TCP");
}

#[tokio::test]
async fn malformed_err_marker_uses_route_refresh_error_and_original_pdu() {
    for (body, subtype) in [(3, 1), (5, 1), (8, 1), (5, 2)] {
        assert_bad_refresh(body, subtype, false, false).await;
    }
}

#[tokio::test]
async fn route_refresh_error_data_obeys_peer_receive_limit_and_asymmetry() {
    for (length, local_extended, peer_extended) in [
        (4075, false, false),
        (4076, false, false),
        (4075, true, false),
        (4076, true, false),
        (4076, false, true),
        (65514, true, true),
        (65515, true, true),
        (65514, true, false),
    ] {
        assert_bad_refresh(length - 19, 1, local_extended, peer_extended).await;
    }
}

#[tokio::test]
async fn peer_extended_advertisement_does_not_raise_our_receive_limit() {
    let (mut session, mut server, _rib_rx, _bmp_rx) = refresh_session(true, true).await;
    session.read_buf.set_max_message_len(4096);
    session
        .read_buf
        .buf
        .extend_from_slice(&raw_refresh(4097 - 19, 1));
    session.process_read_buffer().await;
    let sent = tokio::time::timeout(
        Duration::from_secs(2),
        read_single_raw_bgp_message(&mut server),
    )
    .await
    .unwrap();
    assert_eq!(
        &sent[19..21],
        &[1, 2],
        "reject frame exceeding our advertised receive limit before ERR parsing"
    );
}

#[tokio::test(start_paused = true)]
async fn identifiable_unknown_err_subtypes_ignore_before_orf_decode() {
    for body in [3, 4, 7] {
        let (mut session, _server, mut rib_rx, _bmp_rx) = refresh_session(true, false).await;
        let deadline = session.timers.hold.as_ref().unwrap().deadline();
        tokio::time::advance(Duration::from_secs(1)).await;
        session
            .read_buf
            .buf
            .extend_from_slice(&raw_refresh(body, 3));
        session.process_read_buffer().await;
        assert_eq!(session.fsm.state(), SessionState::Established);
        assert!(
            rib_rx.try_recv().is_err(),
            "unknown subtype must not reach RIB"
        );
        assert!(session.read_buf.buf.is_empty());
        let after = session.timers.hold.as_ref().unwrap().deadline();
        if body >= 4 {
            assert!(
                after > deadline,
                "complete negotiated header preserves hold rearm"
            );
        } else {
            assert_eq!(
                after, deadline,
                "missing SAFI cannot identify a negotiated family"
            );
        }
        let samples = counter_samples(&session.metrics, "bgp_messages_received_total");
        assert!(samples.iter().any(|(labels, value)| {
            labels
                .get("type")
                .is_some_and(|kind| kind == "route_refresh")
                && (*value - 1.0).abs() < f64::EPSILON
        }));
    }
}

#[tokio::test]
async fn refresh_brackets_updates_on_tcp_and_only_non_err_sends_eor() {
    for enhanced in [false, true] {
        let (mut session, mut server, _rib_rx, _bmp_rx) = refresh_session(enhanced, false).await;
        let family = (Afi::Ipv4, Safi::Unicast);
        let mut update = empty_outbound_update();
        update.exact_export_snapshot = Some(session.publish_export_profile());
        update.announce = vec![make_sourced_route(
            Ipv4Addr::new(10, 0, 0, 3),
            Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
            65003,
        )]
        .into();
        update.withdraw = vec![(
            Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)),
            0,
        )];
        update.end_of_rib = vec![family];
        update.refresh_markers = vec![
            (family.0, family.1, RouteRefreshSubtype::BoRR),
            (family.0, family.1, RouteRefreshSubtype::EoRR),
        ];
        session.send_route_update(update);
        // A final KEEPALIVE is a FIFO sentinel after the complete batch.
        // Seeing it proves no unexpected EoR or refresh marker remained queued.
        session.enqueue_bulk(&Message::Keepalive).unwrap();
        let mut frames = Vec::new();
        loop {
            let frame = tokio::time::timeout(
                Duration::from_secs(2),
                read_single_raw_bgp_message(&mut server),
            )
            .await
            .unwrap();
            if frame[18] == 4 {
                break;
            }
            frames.push(frame);
        }
        if enhanced {
            assert_eq!(frames.first().unwrap()[18], 5);
            assert_eq!(frames.first().unwrap()[21], 1);
            assert_eq!(frames.last().unwrap()[18], 5);
            assert_eq!(frames.last().unwrap()[21], 2);
            assert!(
                frames[1..frames.len() - 1]
                    .iter()
                    .all(|frame| frame[18] == 2 && frame.len() > 23)
            );
            assert_eq!(frames.len(), 4, "BoRR, withdrawal, announcement, EoRR");
        } else {
            assert_eq!(frames.len(), 3, "withdrawal, announcement, EoR");
            assert!(frames.iter().all(|frame| frame[18] == 2));
            assert_eq!(&frames.last().unwrap()[19..], &[0, 0, 0, 0]);
        }
    }
}

#[tokio::test]
#[expect(
    clippy::too_many_lines,
    reason = "real RIB lifecycle and TCP assertions stay together to make initial EoR ordering explicit"
)]
async fn gr_orf_first_refresh_sends_initial_eor_before_any_borr_on_tcp() {
    let (mut session, mut server, _session_rib_rx, _bmp_rx) = refresh_session(true, false).await;
    let family = (Afi::Ipv4, Safi::Unicast);
    let peer = session.peer_ip;
    let (tx, rx) = mpsc::channel(64);
    let (_query_tx, query_rx) = mpsc::channel(8);
    let manager = tokio::spawn(
        rustbgpd_rib::RibManager::new(rx, query_rx, None, None, BgpMetrics::new()).run(),
    );
    let route = make_sourced_route(
        Ipv4Addr::new(10, 0, 0, 3),
        Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24),
        65003,
    );
    tx.send(RibUpdate::RoutesReceived {
        session_id: 0,
        peer: route.peer,
        announced: vec![route],
        withdrawn: vec![],
        flowspec_announced: vec![],
        flowspec_withdrawn: vec![],
        evpn_announced: vec![],
        evpn_withdrawn: vec![],
        validated_with: None,
    })
    .await
    .unwrap();
    let peer_up = |outbound_tx| RibUpdate::PeerUp {
        per_client_best: false,
        interpret_rfc1997: true,
        session_id: 0,
        peer,
        peer_asn: 65002,
        peer_router_id: Ipv4Addr::UNSPECIFIED,
        outbound_tx,
        export_policy: None,
        sendable_families: vec![family],
        is_ebgp: true,
        route_reflector_client: false,
        orr_vantage: None,
        add_path_send_families: vec![],
        add_path_send_max: 0,
        negotiated_orf_recv: vec![family],
        negotiated_llgr_families: vec![],
    };
    let (old_tx, mut old_rx) = mpsc::channel(64);
    session.publish_export_profile();
    tx.send(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 0,
        encoder: session.export_encoder.clone(),
    })
    .await
    .unwrap();
    tx.send(peer_up(old_tx)).await.unwrap();
    assert_eq!(old_rx.recv().await.unwrap().end_of_rib, vec![family]);
    tx.send(RibUpdate::PeerGracefulRestart {
        session_id: 0,
        peer,
        restart_time: 120,
        stale_routes_time: 360,
        gr_families: vec![family],
        peer_llgr_capable: false,
        peer_llgr_families: vec![],
        llgr_stale_time: 0,
    })
    .await
    .unwrap();
    let (out_tx, mut out_rx) = mpsc::channel(64);
    tx.send(RibUpdate::SetPeerExportEncoder {
        peer,
        session_id: 0,
        encoder: session.export_encoder.clone(),
    })
    .await
    .unwrap();
    tx.send(peer_up(out_tx)).await.unwrap();
    // Primary-lane round trip proves PeerUp ran, without a timing assumption.
    let (reply, done) = oneshot::channel();
    tx.send(RibUpdate::QueryLocRibCount { reply })
        .await
        .unwrap();
    assert_eq!(
        done.await.unwrap(),
        1,
        "fixture route must reach the Loc-RIB"
    );
    assert!(
        out_rx.try_recv().is_err(),
        "ORF must defer the restarter's initial EoR"
    );
    for initial in [true, false] {
        tx.send(RibUpdate::RouteRefreshRequest {
            queued: Arc::default(),
            session_id: 0,
            peer,
            afi: family.0,
            safi: family.1,
        })
        .await
        .unwrap();
        loop {
            let update = tokio::time::timeout(Duration::from_secs(2), out_rx.recv())
                .await
                .unwrap_or_else(|_| panic!("refresh response timed out; initial={initial}"))
                .unwrap();
            let complete = !initial || update.end_of_rib.contains(&family);
            session.send_route_update(update);
            if complete {
                break;
            }
        }
    }
    session.enqueue_bulk(&Message::Keepalive).unwrap();
    let mut frames = Vec::new();
    loop {
        let frame = tokio::time::timeout(
            Duration::from_secs(2),
            read_single_raw_bgp_message(&mut server),
        )
        .await
        .unwrap();
        if frame[18] == 4 {
            break;
        }
        frames.push(frame);
    }
    assert_eq!(frames.len(), 5, "initial UPDATE/EoR then BoRR/UPDATE/EoRR");
    assert_eq!(frames[0][18], 2);
    assert!(frames[0].len() > 23);
    assert_eq!(&frames[1][18..], &[2, 0, 0, 0, 0]);
    assert_eq!((frames[2][18], frames[2][21]), (5, 1));
    assert_eq!(frames[3][18], 2);
    assert!(frames[3].len() > 23);
    assert_eq!((frames[4][18], frames[4][21]), (5, 2));
    drop(tx);
    manager.await.unwrap();
}

#[tokio::test]
async fn short_and_non_err_refresh_keep_generic_length_error() {
    for (enhanced, body, subtype) in [(true, 0, 1), (true, 2, 1), (false, 3, 1), (true, 3, 0)] {
        let (mut session, mut server, _rib_rx, mut bmp_rx) = refresh_session(enhanced, false).await;
        session
            .read_buf
            .buf
            .extend_from_slice(&raw_refresh(body, subtype));
        session.process_read_buffer().await;
        let sent = tokio::time::timeout(
            Duration::from_secs(2),
            read_single_raw_bgp_message(&mut server),
        )
        .await
        .unwrap();
        assert_eq!(&sent[19..21], &[1, 2]);
        let BmpEvent::PeerDown {
            reason: PeerDownReason::LocalNotification(pdu),
            ..
        } = bmp_rx.try_recv().unwrap()
        else {
            panic!("generic decode error must retain its local notification cause");
        };
        assert_eq!(pdu.as_ref(), sent);
    }
}

#[tokio::test]
async fn valid_err_markers_still_reach_rib() {
    let (mut session, _server, mut rib_rx, _bmp_rx) = refresh_session(true, false).await;
    session.read_buf.buf.extend_from_slice(&raw_refresh(4, 1));
    session.read_buf.buf.extend_from_slice(&raw_refresh(4, 2));
    session.process_read_buffer().await;
    assert!(matches!(
        rib_rx.try_recv().unwrap(),
        RibUpdate::BeginRouteRefresh { .. }
    ));
    assert!(matches!(
        rib_rx.try_recv().unwrap(),
        RibUpdate::EndRouteRefresh { .. }
    ));
    assert_eq!(session.fsm.state(), SessionState::Established);
}
