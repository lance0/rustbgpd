use super::*;

fn pacing_routes(count: u32, distinct: bool) -> Vec<Route> {
    (0..count)
        .map(|index| {
            let mut route = make_route(100);
            route.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((20 << 24) | index), 32));
            Arc::make_mut(&mut route.attributes).push(PathAttribute::Med(if distinct {
                index
            } else {
                0
            }));
            route
        })
        .collect()
}

fn pacing_update(session: &PeerSession, routes: Vec<Route>) -> OutboundRouteUpdate {
    OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce: routes.into(),
        end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
        ..OutboundRouteUpdate::default()
    }
}

/// A current-thread runtime cannot drain the writer during synchronous encode.
/// Both the terminal and the next envelope must follow every distinct group.
#[tokio::test]
async fn outbound_pacing_drains_more_than_writer_capacity_in_order() {
    let (mut session, commands, mut rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    recv_peer_up_after_export_context(&mut rib_rx).await;
    read_single_bgp_message(&mut server).await;
    read_single_bgp_message(&mut server).await;
    let outbound = session.outbound_tx.clone();
    outbound
        .try_send(pacing_update(&session, pacing_routes(5_000, true)))
        .unwrap();
    let mut sentinel = pacing_routes(5_001, true).pop().unwrap();
    sentinel.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 1), 32));
    let sentinel_prefix = sentinel.prefix;
    outbound
        .try_send(pacing_update(&session, vec![sentinel]))
        .unwrap();
    let actor = tokio::spawn(async move { session.run().await });
    let mut seen = std::collections::HashSet::new();
    let mut eors = 0;
    while eors < 2 {
        let Message::Update(message) = read_single_bgp_message(&mut server).await else {
            panic!("unexpected non-UPDATE during paced replay");
        };
        let parsed = message.parse(true, false, &[]).unwrap();
        if parsed.announced.is_empty() {
            eors += 1;
            assert_eq!(seen.len(), if eors == 1 { 5_000 } else { 5_001 });
            continue;
        }
        assert_eq!(
            parsed.announced.len(),
            1,
            "distinct MED requires one frame per prefix"
        );
        let prefix = parsed.announced[0].prefix;
        if Prefix::V4(prefix) == sentinel_prefix {
            assert_eq!(eors, 1, "second envelope overtook first EoR");
        } else {
            assert_eq!(eors, 0);
        }
        assert!(seen.insert(prefix), "duplicate prefix {prefix}");
        let expected = if Prefix::V4(prefix) == sentinel_prefix {
            5_000
        } else {
            u32::from(prefix.addr) & 0x00ff_ffff
        };
        assert!(parsed.attributes.contains(&PathAttribute::Med(expected)));
    }
    let (reply, response) = oneshot::channel();
    commands
        .send(PeerCommand::QueryState { reply })
        .await
        .unwrap();
    assert_eq!(response.await.unwrap().fsm_state, SessionState::Established);
    commands.send(PeerCommand::Shutdown).await.unwrap();
    actor.await.unwrap().unwrap();
}

/// A held one-slot writer is deterministic and does not depend on TCP window
/// tuning. Snapshots and a head-of-FIFO shutdown still run while admission waits.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_full_writer_services_snapshot_and_shutdown() {
    let (mut session, commands, _rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    session.writer_join.take().unwrap().abort();
    let (bulk, _held) = mpsc::channel(1);
    bulk.try_send(Bytes::from_static(b"held")).unwrap();
    session.writer_bulk_tx = Some(bulk);
    let update = pacing_update(&session, pacing_routes(5_000, true));
    session.handle_outbound_route_update(update);
    assert!(session.pending_outbound.is_some());
    let actor = tokio::spawn(async move {
        session.run().await.unwrap();
        assert!(session.pending_outbound.is_none());
        assert!(session.outbound_admission_timer.is_none());
    });
    let (reply, response) = oneshot::channel();
    commands
        .send(PeerCommand::QueryState { reply })
        .await
        .unwrap();
    assert_eq!(response.await.unwrap().fsm_state, SessionState::Established);
    commands.send(PeerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn outbound_pacing_resource_deadline_is_finite_with_send_hold_disabled() {
    let (mut session, commands, _rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    session.config.peer.hold_time = 0;
    session.config.peer.send_hold_time = 0;
    session.writer_join.take().unwrap().abort();
    let (bulk, _held) = mpsc::channel(1);
    bulk.try_send(Bytes::from_static(b"held")).unwrap();
    session.writer_bulk_tx = Some(bulk);
    let (priority, mut priority_rx) = mpsc::unbounded_channel();
    session.writer_priority_tx = Some(priority);
    let update = pacing_update(&session, pacing_routes(2, true));
    session.handle_outbound_route_update(update);
    let deadline = session
        .outbound_admission_timer
        .as_ref()
        .unwrap()
        .deadline();
    assert_eq!(
        deadline - tokio::time::Instant::now(),
        Duration::from_secs(u64::from(rustbgpd_fsm::default_send_hold_time(0)))
    );
    let actor = tokio::spawn(async move {
        session.run().await.unwrap();
        assert!(session.pending_outbound.is_none());
    });
    tokio::time::advance(
        (deadline - tokio::time::Instant::now())
            .checked_sub(Duration::from_millis(1))
            .unwrap(),
    )
    .await;
    let (reply, response) = oneshot::channel();
    commands
        .send(PeerCommand::QueryState { reply })
        .await
        .unwrap();
    response.await.unwrap();
    assert!(
        priority_rx.try_recv().is_err(),
        "resource timeout fired early"
    );
    tokio::time::advance(Duration::from_millis(1)).await;
    let mut encoded = priority_rx
        .recv()
        .await
        .expect("finite Cease/8 admission expiry");
    let message =
        rustbgpd_wire::decode_message(&mut encoded, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap();
    assert!(matches!(
        message,
        Message::Notification(NotificationMessage {
            code: NotificationCode::Cease,
            subcode: 8,
            ..
        })
    ));
    commands.send(PeerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

#[tokio::test]
async fn outbound_pacing_exact_capacity_finishes_without_waiting_for_drain() {
    let (mut session, _wire) = shared_group_member(65001).await;
    session.writer_join.take().unwrap().abort();
    let (bulk, _held) = mpsc::channel(1);
    session.writer_bulk_tx = Some(bulk);
    let mut update = pacing_update(&session, pacing_routes(1, true));
    update.end_of_rib.clear();
    session.handle_outbound_route_update(update);
    assert!(session.pending_outbound.is_none());
    assert!(session.outbound_admission_timer.is_none());
}

#[tokio::test]
async fn outbound_pacing_shared_encoder_full_does_not_truncate_group() {
    use super::super::shared_group::{ProgressiveUnicastEncode, StreamTerminal};
    let (mut encoder, _wire) = shared_group_member(65001).await;
    encoder.writer_join.take().unwrap().abort();
    let (bulk, mut own) = mpsc::channel(1);
    encoder.writer_bulk_tx = Some(bulk);
    let (mut consumer, _wire) = shared_group_member(65001).await;
    consumer.writer_join.take().unwrap().abort();
    let (bulk, mut other) = mpsc::channel(5_001);
    consumer.writer_bulk_tx = Some(bulk);
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());
    let routes = pacing_routes(5_000, true);
    let excluded = Ipv4Addr::new(192, 0, 2, 254);
    let update = shared_group_envelope(&encoder, &shared, excluded, &routes);
    encoder.handle_outbound_route_update(update);
    assert!(encoder.pending_outbound.is_some());
    let published = shared
        .cell
        .get()
        .unwrap()
        .downcast_ref::<ProgressiveUnicastEncode>()
        .unwrap();
    assert_eq!(
        published.test_snapshot(),
        (5_000, Some(StreamTerminal::Complete))
    );
    let update = shared_group_envelope(&consumer, &shared, excluded, &routes);
    consumer.handle_outbound_route_update(update);
    while consumer.pending_outbound.is_some() {
        consumer.advance_pending_outbound();
    }
    assert_eq!(
        other.len(),
        5_000,
        "healthy consumer receives complete publication while elected member remains full"
    );
    let mut seen = std::collections::HashSet::new();
    for _ in 0..5_000 {
        let mine = own
            .try_recv()
            .expect("first unsent cursor resumes each frame");
        let theirs = other.try_recv().unwrap();
        assert_eq!(mine, theirs);
        let mut bytes = mine;
        let Message::Update(message) =
            rustbgpd_wire::decode_message(&mut bytes, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            panic!("expected UPDATE")
        };
        let parsed = message.parse(true, false, &[]).unwrap();
        assert_eq!(parsed.announced.len(), 1);
        assert!(seen.insert(parsed.announced[0].prefix));
        encoder.advance_pending_outbound();
    }
    assert_eq!(seen.len(), 5_000);
    assert!(encoder.pending_outbound.is_none());
    assert!(own.is_empty());
}

#[tokio::test]
async fn outbound_pacing_slice_frame_count_preserves_grouping() {
    for distinct in [false, true] {
        let (mut session, _wire) = shared_group_member(65001).await;
        session.writer_join.take().unwrap().abort();
        let (bulk, mut receiver) = mpsc::channel(6_000);
        session.writer_bulk_tx = Some(bulk);
        let mut update = pacing_update(&session, pacing_routes(5_000, distinct));
        update.end_of_rib.clear();
        session.handle_outbound_route_update(update);
        while session.pending_outbound.is_some() {
            session.advance_pending_outbound();
        }
        let sliced = receiver.len();
        while receiver.try_recv().is_ok() {}
        let mut update = pacing_update(&session, pacing_routes(5_000, distinct));
        update.end_of_rib.clear();
        session.send_route_update(update);
        let unsliced = receiver.len();
        eprintln!("distinct={distinct}: sliced={sliced}, unsliced={unsliced}");
        if distinct {
            assert_eq!((sliced, unsliced), (5_000, 5_000));
        } else {
            assert!(
                sliced <= unsliced + 2,
                "at most one extra frame per slice boundary"
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn outbound_pacing_stalled_writer_keeps_policy_apply_restore_fifo() {
    let (mut session, commands, mut rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _wire) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    recv_peer_up_after_export_context(&mut rib_rx).await;
    session.writer_join.take().unwrap().abort();
    let (bulk, _held) = mpsc::channel(1);
    bulk.try_send(Bytes::from_static(b"held")).unwrap();
    session.writer_bulk_tx = Some(bulk);
    let update = pacing_update(&session, pacing_routes(2, true));
    session.handle_outbound_route_update(update);
    while rib_rx.try_recv().is_ok() {}
    let actor = tokio::spawn(async move { session.run().await });
    let (reply, lost_ack) = oneshot::channel();
    drop(lost_ack);
    commands
        .send(PeerCommand::UpdateExportPolicy {
            policy: Some(Box::new(PolicyChain::new(vec![Policy {
                entries: vec![],
                default_action: PolicyAction::Deny,
            }]))),
            reply,
        })
        .await
        .unwrap();
    tokio::time::timeout(
        Duration::from_millis(500),
        crate::PeerHandle::update_export_policy_via(commands.clone(), None),
    )
    .await
    .expect("restore must not wait for pending writer capacity")
    .unwrap();
    for expected_present in [true, false] {
        let RibUpdate::SetPeerSessionExportPolicy { export_policy, .. } =
            rib_rx.recv().await.unwrap()
        else {
            panic!("expected FIFO policy replay record")
        };
        assert_eq!(
            export_policy.is_some(),
            expected_present,
            "lost ACK must not erase admitted mutation"
        );
    }
    commands.send(PeerCommand::Shutdown).await.unwrap();
    actor.await.unwrap().unwrap();
}

#[tokio::test]
async fn outbound_pacing_keeps_original_snapshot_across_config_publication() {
    let (mut session, _wire) = shared_group_member(65001).await;
    session.writer_join.take().unwrap().abort();
    let (bulk, mut receiver) = mpsc::channel(1);
    session.writer_bulk_tx = Some(bulk);
    let update = pacing_update(&session, pacing_routes(2, true));
    session.handle_outbound_route_update(update);
    let (reply, response) = oneshot::channel();
    let _ = session
        .handle_command(PeerCommand::UpdateGracefulShutdown {
            enabled: true,
            reply,
        })
        .await;
    response.await.unwrap().unwrap();
    let mut captured = vec![receiver.try_recv().unwrap()];
    while session.pending_outbound.is_some() {
        session.advance_pending_outbound();
        while let Ok(frame) = receiver.try_recv() {
            captured.push(frame);
        }
    }
    let update = pacing_update(&session, pacing_routes(1, true));
    session.handle_outbound_route_update(update);
    while session.pending_outbound.is_some() {
        while let Ok(frame) = receiver.try_recv() {
            captured.push(frame);
        }
        session.advance_pending_outbound();
    }
    while let Ok(frame) = receiver.try_recv() {
        captured.push(frame);
    }
    assert_eq!(captured.len(), 5, "old routes, old EoR, new route, new EoR");
    for (index, mut frame) in captured.into_iter().enumerate() {
        let Message::Update(message) =
            rustbgpd_wire::decode_message(&mut frame, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            panic!("expected UPDATE")
        };
        let parsed = message.parse(true, false, &[]).unwrap();
        let has_gshut = parsed.attributes.iter().any(|attr| matches!(attr, PathAttribute::Communities(values) if values.contains(&0xffff_0000)));
        assert_eq!(
            has_gshut,
            index == 3,
            "only next envelope uses newly published graceful shutdown profile"
        );
    }
}

#[tokio::test]
async fn outbound_pacing_mixed_family_markers_and_overrides_fit_one_slot() {
    let (mut session, _wire) = shared_group_member(65001).await;
    session.writer_join.take().unwrap().abort();
    let mut negotiated = session.negotiated.as_deref().unwrap().clone();
    negotiated.negotiated_families = vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)];
    negotiated.peer_route_refresh = true;
    negotiated.peer_enhanced_route_refresh = true;
    session.negotiated = Some(Arc::new(negotiated));
    let (bulk, mut receiver) = mpsc::channel(1);
    session.writer_bulk_tx = Some(bulk);
    let v4 = make_route(100);
    let v6 = make_v6_unicast_route("2001:db8::1".parse().unwrap());
    let override_v4 = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    let override_v6 = IpAddr::V6("2001:db8::20".parse().unwrap());
    let update = OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        withdraw: vec![(v4.prefix, 0), (v6.prefix, 0)],
        announce: vec![v4, v6].into(),
        next_hop_override: vec![
            Some(rustbgpd_policy::NextHopAction::Specific(override_v4)),
            Some(rustbgpd_policy::NextHopAction::Specific(override_v6)),
        ]
        .into(),
        request_refresh_all_negotiated: true,
        refresh_markers: vec![
            (Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::BoRR),
            (Afi::Ipv4, Safi::Unicast, RouteRefreshSubtype::EoRR),
        ],
        end_of_rib: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
        ..OutboundRouteUpdate::default()
    };
    session.handle_outbound_route_update(update);
    let mut messages = Vec::new();
    loop {
        while let Ok(mut bytes) = receiver.try_recv() {
            messages.push(
                rustbgpd_wire::decode_message(&mut bytes, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap(),
            );
        }
        if session.pending_outbound.is_none() {
            break;
        }
        session.advance_pending_outbound();
    }
    assert_eq!(
        messages.len(),
        9,
        "two requests, BoRR, both withdrawals, both announcements, EoRR, IPv6 EoR"
    );
    for (index, expected) in [
        (0, RouteRefreshSubtype::Normal),
        (1, RouteRefreshSubtype::Normal),
        (2, RouteRefreshSubtype::BoRR),
        (7, RouteRefreshSubtype::EoRR),
    ] {
        assert!(
            matches!(&messages[index], Message::RouteRefresh(message) if message.subtype() == expected)
        );
    }
    let Message::Update(v4) = &messages[5] else {
        panic!("IPv4 announcement")
    };
    assert!(
        v4.parse(true, false, &[])
            .unwrap()
            .attributes
            .contains(&PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 20)))
    );
    let Message::Update(v6) = &messages[6] else {
        panic!("IPv6 announcement")
    };
    assert!(
        v6.parse(true, false, &[]).unwrap().attributes.iter().any(
            |attr| matches!(attr, PathAttribute::MpReachNlri(mp) if mp.next_hop == override_v6)
        )
    );
    assert!(session.writer_bulk_tx.is_some());
}

#[tokio::test]
async fn outbound_pacing_closed_writer_retires_admission_deadline() {
    for expiry_first in [false, true] {
        let (mut session, _wire) = shared_group_member(65001).await;
        session.writer_join.take().unwrap().abort();
        let (bulk, held) = mpsc::channel(1);
        bulk.try_send(Bytes::from_static(b"held")).unwrap();
        session.writer_bulk_tx = Some(bulk);
        let update = pacing_update(&session, pacing_routes(2, true));
        session.handle_outbound_route_update(update);
        assert!(session.outbound_admission_timer.is_some());
        drop(held);
        if expiry_first {
            session.expire_outbound_admission();
        } else {
            session.advance_pending_outbound();
        }
        assert!(
            session.writer_bulk_tx.is_some(),
            "resource expiry must leave the writer-exit path to report its own cause"
        );
        assert!(session.pending_outbound.is_none());
        assert!(
            session.outbound_admission_timer.is_none(),
            "writer exit must retain its own failure cause"
        );
    }
}
