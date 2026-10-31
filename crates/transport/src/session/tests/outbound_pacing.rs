use super::*;

fn pacing_routes(count: u32, distinct: bool) -> Vec<Route> {
    (0..count)
        .map(|index| {
            let mut route = make_route(100);
            route.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((20 << 24) | index), 32));
            AttrSet::edit(&mut route.attributes, |attrs| {
                attrs.push(PathAttribute::Med(if distinct { index } else { 0 }));
            });
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
    session.handle_outbound_route_update(update).await;
    assert!(session.pending_outbound.is_some());
    let actor = tokio::spawn(async move {
        session.run().await.unwrap();
        // Shutdown abandons the envelope: at most its inventory release remains.
        assert!(
            session
                .pending_outbound
                .as_ref()
                .is_none_or(super::outbound::PendingOutbound::retiring)
        );
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

/// Terminal shutdown with the session as last owner of a large unsent
/// inventory: the session task exits without waiting for the release, the
/// session it drops owns none of it, and the remainder is freed one slice per
/// step off the session turn.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_session_exit_hands_inventory_to_paced_release() {
    const SLICE: usize = super::shared_group::PROGRESSIVE_SLICE_ROUTES;
    let (mut session, commands, _rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    session.writer_join.take().unwrap().abort();
    // A full one-slot writer queue keeps every route unsent.
    let (bulk, _held) = mpsc::channel(1);
    bulk.try_send(Bytes::from_static(b"held")).unwrap();
    session.writer_bulk_tx = Some(bulk);
    let held = make_route(100).attributes;
    let base = Arc::strong_count(&held);
    let live = || Arc::strong_count(&held) - base;
    let total = 5 * SLICE;
    let routes = (0..u32::try_from(total).unwrap())
        .map(|index| Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((20 << 24) | index), 32)),
            attributes: Arc::clone(&held),
            ..make_route(100)
        })
        .collect();
    session
        .handle_outbound_route_update(pacing_update(&session, routes))
        .await;
    assert_eq!(live(), total, "nothing was sent");

    commands.send(PeerCommand::Shutdown).await.unwrap();
    // Poll the session task by hand, so each recorded release is one
    // synchronous step: a single poll of the session, or one clock advance
    // (paused time) in which any other task (the paced release) runs once.
    let mut released = Vec::new();
    let started = tokio::time::Instant::now();
    {
        let mut run = std::pin::pin!(session.run());
        loop {
            let before = live();
            let polled =
                std::future::poll_fn(|cx| std::task::Poll::Ready(run.as_mut().poll(cx))).await;
            released.push(before - live());
            if let std::task::Poll::Ready(result) = polled {
                result.unwrap();
                break;
            }
            let before = live();
            tokio::time::advance(std::time::Duration::from_millis(1)).await;
            released.push(before - live());
        }
    }
    assert!(
        started.elapsed() <= 2 * super::writer::CLOSE_FLUSH_BUDGET,
        "the session task exits on its close budget, not after the release"
    );
    assert!(live() > 0, "the exit does not wait for the release");
    let before = live();
    drop(session);
    released.push(before - live());
    for _ in 0..2 * total / SLICE {
        let before = live();
        tokio::task::yield_now().await;
        released.push(before - live());
    }
    assert_eq!(live(), 0, "every route is released: {released:?}");
    assert!(
        released.iter().all(|&batch| batch <= SLICE),
        "one step released more than a slice: {released:?}"
    );
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
    session.handle_outbound_route_update(update).await;
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

const QUEUE_SLICE: usize = super::shared_group::PROGRESSIVE_SLICE_ROUTES;
const QUEUED_ROUTES: usize = 5 * QUEUE_SLICE;

/// Counts the live entries of queued envelopes: routes by their shared
/// attribute set, byte payloads by the owner `marker` they share.
struct QueuedInventory {
    held: Arc<AttrSet>,
    base: usize,
    marker: Arc<()>,
}

impl QueuedInventory {
    fn live(&self) -> usize {
        Arc::strong_count(&self.held) - self.base + Arc::strong_count(&self.marker) - 1
    }

    fn marked(&self) -> Bytes {
        // Held only so the payload's drop releases it.
        struct Marked {
            _owner: Arc<()>,
        }
        impl AsRef<[u8]> for Marked {
            fn as_ref(&self) -> &[u8] {
                b"marked"
            }
        }
        Bytes::from_owner(Marked {
            _owner: Arc::clone(&self.marker),
        })
    }

    /// `per_family` entries of every heap-owning payload outside the
    /// announce families, each counted by [`Self::live`] except the
    /// `FlowSpec` withdrawals, whose keys own no shared handle to count.
    fn add_other_families(&self, update: &mut OutboundRouteUpdate, per_family: usize) {
        let bgpls = make_bgpls_route(1);
        update.flowspec_announce = (0..per_family)
            .map(|_| FlowSpecRoute {
                attributes: vec![PathAttribute::Unknown(rustbgpd_wire::RawAttribute {
                    flags: 0xc0,
                    type_code: 250,
                    data: self.marked(),
                })],
                ..make_flowspec_route()
            })
            .collect();
        update.flowspec_withdraw = (0..per_family)
            .map(|_| FlowSpecKey {
                afi: Afi::Ipv4,
                rule: make_flowspec_route().rule,
            })
            .collect();
        update.bgpls_announce = (0..per_family)
            .map(|_| rustbgpd_rib::BgpLsRibRoute {
                attributes: Arc::clone(&self.held),
                ..bgpls.clone()
            })
            .collect();
        update.bgpls_withdraw = (0..per_family)
            .map(|_| {
                let mut nlri = bgpls.nlri.key();
                nlri.payload = self.marked();
                rustbgpd_rib::BgpLsRouteKey {
                    family: bgpls.family,
                    nlri,
                    path_id: 0,
                }
            })
            .collect();
        update.rtc_announce = (0..per_family)
            .map(|_| rustbgpd_rib::RtcRibRoute {
                attributes: Arc::clone(&self.held),
                ..make_rtc_rib_route(1)
            })
            .collect();
        update.otc_blocked = (0..per_family)
            .map(|_| Route {
                attributes: Arc::clone(&self.held),
                ..make_route(100)
            })
            .collect();
    }
}

/// An Established session whose active envelope waits on a full writer
/// queue, so it cannot finish within the close-drain budget, and a second
/// full-table envelope, not yet queued, that is the last owner of its
/// routes. The returned writer receiver keeps that queue full.
async fn queued_last_owner_session() -> (
    PeerSession,
    mpsc::Sender<PeerCommand>,
    mpsc::Receiver<RibUpdate>,
    mpsc::Receiver<Bytes>,
    OutboundRouteUpdate,
    QueuedInventory,
) {
    let (mut session, commands, rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    session.writer_join.take().unwrap().abort();
    let (bulk, writer) = mpsc::channel(1);
    bulk.try_send(Bytes::from_static(b"held")).unwrap();
    session.writer_bulk_tx = Some(bulk);
    session
        .handle_outbound_route_update(pacing_update(&session, pacing_routes(5_000, true)))
        .await;

    let held = make_route(100).attributes;
    let base = Arc::strong_count(&held);
    let routes = (0..u32::try_from(QUEUED_ROUTES).unwrap())
        .map(|index| Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((20 << 24) | index), 32)),
            attributes: Arc::clone(&held),
            ..make_route(100)
        })
        .collect();
    let envelope = pacing_update(&session, routes);
    let inventory = QueuedInventory {
        held,
        base,
        marker: Arc::new(()),
    };
    assert_eq!(inventory.live(), QUEUED_ROUTES);
    (session, commands, rib_rx, writer, envelope, inventory)
}

/// Poll the session task by hand, so each recorded release is one
/// synchronous step: a single poll of the session, or one clock advance
/// (paused time) in which any other task (the paced release) runs once.
/// Returns the time `run()` took to exit.
async fn run_by_step(
    session: &mut PeerSession,
    inventory: &QueuedInventory,
    released: &mut Vec<usize>,
) -> std::time::Duration {
    let started = tokio::time::Instant::now();
    let mut run = std::pin::pin!(session.run());
    loop {
        let before = inventory.live();
        let polled = std::future::poll_fn(|cx| std::task::Poll::Ready(run.as_mut().poll(cx))).await;
        released.push(before - inventory.live());
        if let std::task::Poll::Ready(result) = polled {
            result.unwrap();
            return started.elapsed();
        }
        let before = inventory.live();
        tokio::time::advance(std::time::Duration::from_millis(1)).await;
        released.push(before - inventory.live());
    }
}

/// Drop the session, then give the paced release room to finish, recording
/// each step; every queued route must be freed, no step above one slice.
async fn finish_queued_release(
    session: PeerSession,
    inventory: &QueuedInventory,
    mut released: Vec<usize>,
) {
    let before = inventory.live();
    drop(session);
    released.push(before - inventory.live());
    for _ in 0..4 * QUEUED_ROUTES / QUEUE_SLICE {
        let before = inventory.live();
        tokio::task::yield_now().await;
        released.push(before - inventory.live());
    }
    let nonzero: Vec<_> = released
        .iter()
        .copied()
        .enumerate()
        .filter(|(_, batch)| *batch > 0)
        .collect();
    assert_eq!(
        inventory.live(),
        0,
        "queued routes are all released: {nonzero:?}"
    );
    assert!(
        released.iter().all(|&batch| batch <= QUEUE_SLICE),
        "one step released more than {QUEUE_SLICE} queued routes; nonzero steps: {nonzero:?}"
    );
}

/// Session teardown discards the RIB-to-session queue unsent, and a queued
/// envelope may hold the last reference to its inventory: the release is
/// paced like the active envelope's, never one synchronous drop, and the
/// teardown neither waits for it nor runs past the close-drain budget.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_session_down_paces_queued_inventory_release() {
    let (mut session, commands, _rib_rx, _writer, envelope, inventory) =
        queued_last_owner_session().await;
    session.outbound_tx.try_send(envelope).unwrap();
    commands.send(PeerCommand::Shutdown).await.unwrap();
    let mut released = Vec::new();
    let elapsed = run_by_step(&mut session, &inventory, &mut released).await;
    assert!(
        elapsed <= 2 * super::writer::CLOSE_FLUSH_BUDGET,
        "the session task exits on its close budget, not after the release"
    );
    assert!(
        inventory.live() > 0,
        "the teardown does not wait for the release"
    );
    finish_queued_release(session, &inventory, released).await;
}

/// A session task can exit while Established, without the teardown that
/// discards the queue (here every command sender is gone). The queue still
/// drops with the session, so the exit hands it to the paced release too.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_exit_without_session_down_paces_queued_inventory_release() {
    let (mut session, commands, _rib_rx, _writer, envelope, inventory) =
        queued_last_owner_session().await;
    session.outbound_tx.try_send(envelope).unwrap();
    drop(commands);
    let mut released = Vec::new();
    run_by_step(&mut session, &inventory, &mut released).await;
    assert_eq!(
        session.fsm.state(),
        SessionState::Established,
        "this exit never tore the session down"
    );
    assert!(
        inventory.live() > 0,
        "the exit does not wait for the release"
    );
    finish_queued_release(session, &inventory, released).await;
}

/// A sender that reserved its permit before the teardown (the RIB reserves
/// before it commits) still delivers after the queue is closed. That
/// envelope is paced as well, not stranded in the old channel and freed
/// whole by whichever handle to it drops last.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_permit_reserved_before_teardown_is_paced() {
    let (mut session, commands, rib_rx, _writer, envelope, inventory) =
        queued_last_owner_session().await;
    let permit = session.outbound_tx.clone().try_reserve_owned().unwrap();
    commands.send(PeerCommand::Shutdown).await.unwrap();
    let mut released = Vec::new();
    run_by_step(&mut session, &inventory, &mut released).await;
    let sender = permit.send(envelope);
    assert!(sender.is_closed(), "the old queue is closed");
    assert_eq!(inventory.live(), QUEUED_ROUTES);
    // The RIB still holds senders to the old queue (its registration is
    // buffered in `rib_rx`); dropping them is its PeerDown turn.
    let before = inventory.live();
    drop(rib_rx);
    drop(sender);
    released.push(before - inventory.live());
    finish_queued_release(session, &inventory, released).await;
}

/// `FlowSpec`, BGP-LS, RT-Constrain and OTC-blocked payloads stay in the
/// envelope while it sends. A queued envelope holding only those is
/// retired as well, a slice per step, not dropped whole.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_session_down_paces_queued_other_family_release() {
    let (mut session, commands, _rib_rx, _writer, envelope, inventory) =
        queued_last_owner_session().await;
    drop(envelope);
    let mut update = pacing_update(&session, Vec::new());
    inventory.add_other_families(&mut update, QUEUE_SLICE + 1);
    session.outbound_tx.try_send(update).unwrap();
    commands.send(PeerCommand::Shutdown).await.unwrap();
    let mut released = Vec::new();
    run_by_step(&mut session, &inventory, &mut released).await;
    assert!(
        inventory.live() > 0,
        "the teardown does not wait for the release"
    );
    finish_queued_release(session, &inventory, released).await;
}

/// A mixed envelope shares one slice budget across its unicast routes and
/// every other family: its last unicast slice must not carry the rest out
/// in the same step.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_session_down_paces_queued_mixed_family_release() {
    let (mut session, commands, _rib_rx, _writer, mut envelope, inventory) =
        queued_last_owner_session().await;
    inventory.add_other_families(&mut envelope, QUEUE_SLICE / 2);
    session.outbound_tx.try_send(envelope).unwrap();
    commands.send(PeerCommand::Shutdown).await.unwrap();
    let mut released = Vec::new();
    run_by_step(&mut session, &inventory, &mut released).await;
    assert!(
        inventory.live() > 0,
        "the teardown does not wait for the release"
    );
    finish_queued_release(session, &inventory, released).await;
}

#[tokio::test]
async fn outbound_pacing_samples_backlog_before_envelope_completion() {
    let (mut session, _commands, mut rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    recv_peer_up_after_export_context(&mut rib_rx).await;
    while let Ok(update) = rib_rx.try_recv() {
        assert!(!matches!(update, RibUpdate::PeerSlowState { .. }));
    }
    session.writer_join.take().unwrap().abort();
    session.config.slow_peer_duration = 60;
    session.config.slow_peer_threshold_pct = 50;
    session.config.slow_peer_isolation = true;
    let (bulk, mut held) = mpsc::channel(2);
    session.writer_bulk_tx = Some(bulk);

    let update = pacing_update(&session, pacing_routes(3, true));
    session.handle_outbound_route_update(update).await;
    assert!(session.pending_outbound.is_some());
    assert_eq!(session.writer_bulk_tx.as_ref().unwrap().capacity(), 0);
    assert_eq!(
        session
            .metrics
            .peer_outbound_queue_depth(&session.peer_label),
        2
    );
    let since = session.slow_peer_backlog_since.unwrap();
    assert!(session.slow_peer_timer.is_some());

    for _ in 0..3 {
        session.advance_pending_outbound();
        assert!(session.pending_outbound.is_some());
        assert_eq!(session.slow_peer_backlog_since, Some(since));
        assert!(!session.slow_peer);
        assert_eq!(session.metrics.peer_slow(&session.peer_label), 0);
        assert!(rib_rx.try_recv().is_err());
    }

    // The detector uses elapsed wall-clock time, not an observation count.
    // Seed its private episode timestamp to avoid sleeping in the regression.
    session.slow_peer_backlog_since = Some(
        std::time::Instant::now()
            .checked_sub(Duration::from_secs(61))
            .unwrap(),
    );
    session.evaluate_slow_peer();
    session.evaluate_slow_peer();
    assert!(session.slow_peer);
    assert_eq!(session.metrics.peer_slow(&session.peer_label), 1);
    assert!(matches!(
        rib_rx.try_recv().unwrap(),
        RibUpdate::PeerSlowState { slow: true, .. }
    ));
    assert!(
        rib_rx.try_recv().is_err(),
        "one isolation event per transition"
    );

    held.try_recv().unwrap();
    held.try_recv().unwrap();
    session.sample_outbound_queue_depth();
    assert!(session.pending_outbound.is_some());
    assert_eq!(
        session
            .metrics
            .peer_outbound_queue_depth(&session.peer_label),
        0
    );
    assert!(!session.slow_peer);
    assert_eq!(session.metrics.peer_slow(&session.peer_label), 0);
    assert!(session.slow_peer_backlog_since.is_none());
    assert!(session.slow_peer_timer.is_none());
    assert!(matches!(
        rib_rx.try_recv().unwrap(),
        RibUpdate::PeerSlowState { slow: false, .. }
    ));
    session.evaluate_slow_peer();
    assert!(
        rib_rx.try_recv().is_err(),
        "one recovery event per transition"
    );
}

#[tokio::test]
async fn outbound_pacing_exact_capacity_finishes_without_waiting_for_drain() {
    let (mut session, _wire) = shared_group_member(65001).await;
    session.writer_join.take().unwrap().abort();
    let (bulk, _held) = mpsc::channel(1);
    session.writer_bulk_tx = Some(bulk);
    let mut update = pacing_update(&session, pacing_routes(1, true));
    update.end_of_rib.clear();
    session.handle_outbound_route_update(update).await;
    assert!(session.pending_outbound.is_none());
    assert!(session.outbound_admission_timer.is_none());
}

#[tokio::test(start_paused = true)]
async fn outbound_pacing_releases_deadline_after_filtered_slice() {
    use super::super::shared_group::{ProgressiveGroupEncode, StreamTerminal};

    for shared_fallback in [false, true] {
        let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
        let (client, _wire) = connected_stream_pair().await;
        session.config.route_server_client = true;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        session.writer_join.take().unwrap().abort();
        session.config.peer.send_hold_time = 1;
        let (bulk, mut receiver) = mpsc::channel(1);
        bulk.try_send(Bytes::from_static(b"held")).unwrap();
        session.writer_bulk_tx = Some(bulk);

        let excluded = Ipv4Addr::new(10, 0, 0, 2);
        let mut routes = pacing_routes(3, true);
        for route in &mut routes[1..] {
            route.peer = PeerId::from_addr(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
        }
        let update = if shared_fallback {
            let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());
            let update = shared_group_envelope(&session, &shared, excluded, &Arc::new(routes));
            let encode = ProgressiveGroupEncode::test_new(
                (*session.publish_export_profile()).clone(),
                &update,
            );
            encode.test_finish(StreamTerminal::Failed);
            assert!(
                shared
                    .cell
                    .set(Arc::new(encode) as Arc<dyn std::any::Any + Send + Sync>)
                    .is_ok()
            );
            update
        } else {
            let mut update = pacing_update(&session, routes);
            update.end_of_rib.clear();
            update.announce_source_exclusion = Some(PeerId::from_addr(IpAddr::V4(excluded)));
            update
        };
        session.handle_outbound_route_update(update).await;
        let original_deadline = session
            .outbound_admission_timer
            .as_ref()
            .unwrap()
            .deadline();

        receiver.try_recv().unwrap();
        let admitted = session.writer_bulk_admitted;
        session.advance_pending_outbound();
        assert!(session.pending_outbound.is_some());
        assert_eq!(
            session.writer_bulk_admitted, admitted,
            "excluded slice admits no frame"
        );
        assert_eq!(session.writer_bulk_tx.as_ref().unwrap().capacity(), 1);
        assert!(
            session.outbound_admission_timer.is_none(),
            "available capacity ends the admission stall even without a frame"
        );

        tokio::time::advance(Duration::from_secs(2)).await;
        session.advance_pending_outbound();
        let renewed_deadline = session
            .outbound_admission_timer
            .as_ref()
            .unwrap()
            .deadline();
        assert!(renewed_deadline > original_deadline);
        assert_eq!(
            renewed_deadline - tokio::time::Instant::now(),
            Duration::from_secs(1)
        );
        assert!(session.pending_outbound.is_some());
        session.advance_pending_outbound();
        assert_eq!(
            session
                .outbound_admission_timer
                .as_ref()
                .unwrap()
                .deadline(),
            renewed_deadline
        );

        receiver.try_recv().unwrap();
        session.advance_pending_outbound();
        assert!(session.pending_outbound.is_none());
        assert!(session.outbound_admission_timer.is_none());
        assert_eq!(session.fsm.state(), SessionState::Established);
        assert_eq!(session.config.neighbor_counters.notifications_sent(), 0);
    }
}

#[tokio::test]
async fn outbound_pacing_shared_encoder_full_does_not_truncate_group() {
    use super::super::shared_group::{ProgressiveGroupEncode, StreamTerminal};
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
    let routes = Arc::new(routes);
    let update = shared_group_envelope(&encoder, &shared, excluded, &routes);
    encoder.handle_outbound_route_update(update).await;
    assert!(encoder.pending_outbound.is_some());
    let published = shared
        .cell
        .get()
        .unwrap()
        .downcast_ref::<ProgressiveGroupEncode>()
        .unwrap();
    assert_eq!(
        published.test_snapshot(),
        (5_000, Some(StreamTerminal::Complete))
    );
    let update = shared_group_envelope(&consumer, &shared, excluded, &routes);
    consumer.handle_outbound_route_update(update).await;
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
        session.handle_outbound_route_update(update).await;
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
    session.handle_outbound_route_update(update).await;
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
    session.handle_outbound_route_update(update).await;
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
    session.handle_outbound_route_update(update).await;
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
    session.handle_outbound_route_update(update).await;
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
        session.handle_outbound_route_update(update).await;
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
