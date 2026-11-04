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
/// inventory: the session task exits without waiting for the release, and
/// dropping the session hands the remainder to the paced release, which
/// frees it one slice per step off the session turn.
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

/// An Established session whose full writer queue keeps `total` routes
/// unsent, each sharing `held`, with what keeps its channels open.
struct Parked {
    session: PeerSession,
    _commands: mpsc::Sender<PeerCommand>,
    _rib_rx: mpsc::Receiver<RibUpdate>,
    _server: TcpStream,
    _held_rx: mpsc::Receiver<Bytes>,
}

async fn parked_session(held: &Arc<AttrSet>, total: usize) -> Parked {
    let (mut session, commands, rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    session.writer_join.take().unwrap().abort();
    let (bulk, held_rx) = mpsc::channel(1);
    bulk.try_send(Bytes::from_static(b"held")).unwrap();
    session.writer_bulk_tx = Some(bulk);
    let routes = (0..u32::try_from(total).unwrap())
        .map(|index| Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((20 << 24) | index), 32)),
            attributes: Arc::clone(held),
            ..make_route(100)
        })
        .collect();
    session
        .handle_outbound_route_update(pacing_update(&session, routes))
        .await;
    Parked {
        session,
        _commands: commands,
        _rib_rx: rib_rx,
        _server: server,
        _held_rx: held_rx,
    }
}

/// A session dropped while its task unwinds skips the hand-off, so the drop
/// cannot panic again mid-unwind; the inventory is freed in that turn.
/// Mutation-red: handing off while panicking leaves the routes alive after
/// the join, held by the release task.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_unwinding_session_skips_the_hand_off() {
    const SLICE: usize = super::shared_group::PROGRESSIVE_SLICE_ROUTES;
    let held = make_route(100).attributes;
    let base = Arc::strong_count(&held);
    let parked = parked_session(&held, 5 * SLICE).await;
    let (fail, failure) = oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        let _parked = parked;
        failure.await.unwrap();
        panic!("session owner panicked");
    });
    tokio::task::yield_now().await;
    fail.send(()).unwrap();
    assert!(task.await.unwrap_err().is_panic());
    assert_eq!(Arc::strong_count(&held) - base, 0);
}

/// A session dropped on a thread without a runtime cannot spawn the paced
/// release; it frees the inventory in that turn instead of panicking.
/// Mutation-red: handing off without a runtime panics in `tokio::spawn`.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_session_dropped_off_runtime_does_not_panic() {
    const SLICE: usize = super::shared_group::PROGRESSIVE_SLICE_ROUTES;
    let held = make_route(100).attributes;
    let base = Arc::strong_count(&held);
    let parked = parked_session(&held, 5 * SLICE).await;
    let joined = std::thread::spawn(move || drop(parked)).join();
    assert!(joined.is_ok(), "dropping off the runtime must not panic");
    assert_eq!(Arc::strong_count(&held) - base, 0);
}

/// An aborted session task never returns from `run()`, as on the
/// transport-safety abort and a shutdown deadline's expiry. Dropping its
/// session still hands a large unsent inventory to the paced release.
/// Mutation-red: handing off only when `run()` returns frees it all in the
/// abort's turn.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_aborted_session_hands_inventory_to_paced_release() {
    const SLICE: usize = super::shared_group::PROGRESSIVE_SLICE_ROUTES;
    let held = make_route(100).attributes;
    let base = Arc::strong_count(&held);
    let live = || Arc::strong_count(&held) - base;
    let total = 5 * SLICE;
    let Parked {
        mut session,
        _commands,
        _rib_rx,
        _server,
        _held_rx,
    } = parked_session(&held, total).await;
    assert_eq!(live(), total, "nothing was sent");

    // Cancel the way an abort does: drop the parked `run()` future, then the
    // session it borrowed, each as one synchronous step.
    let mut released = Vec::new();
    {
        let mut run = std::pin::pin!(session.run());
        let before = live();
        let polled = std::future::poll_fn(|cx| std::task::Poll::Ready(run.as_mut().poll(cx))).await;
        assert!(polled.is_pending(), "the session is parked in its run loop");
        released.push(before - live());
    }
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
                rd: None,
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
/// routes. The returned writer receiver keeps that queue full, and the
/// returned peer end of the connection keeps it open, so only the close
/// under test ends the session.
async fn queued_last_owner_session() -> (
    PeerSession,
    TcpStream,
    mpsc::Sender<PeerCommand>,
    mpsc::Receiver<RibUpdate>,
    mpsc::Receiver<Bytes>,
    OutboundRouteUpdate,
    QueuedInventory,
) {
    let (mut session, commands, rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, peer) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    session.writer_join.take().unwrap().abort();
    let (bulk, writer) = mpsc::channel(1);
    bulk.try_send(Bytes::from_static(b"held")).unwrap();
    session.writer_bulk_tx = Some(bulk);
    // The stand-in writer reports no completed writes, so only its one-slot
    // frame queue paces admission here, not the byte budget.
    session.writer_completed = None;
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
    (session, peer, commands, rib_rx, writer, envelope, inventory)
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

/// The Shutdown command closed the session with its Cease NOTIFICATION,
/// not through a remote disconnect.
fn assert_administrative_close(session: &PeerSession) {
    assert_eq!(
        session.config.neighbor_counters.notifications_sent(),
        1,
        "the administrative close, not a remote disconnect, ended the session"
    );
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
    let (mut session, _peer, commands, _rib_rx, _writer, envelope, inventory) =
        queued_last_owner_session().await;
    session.outbound_tx.try_send(envelope).unwrap();
    commands.send(PeerCommand::Shutdown).await.unwrap();
    let mut released = Vec::new();
    let elapsed = run_by_step(&mut session, &inventory, &mut released).await;
    assert_administrative_close(&session);
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

/// T11 (transport), with a real operation latch. A queued envelope's latch
/// and credit charge stay held while its inventory is queued, active and
/// retiring, and both are released once it finishes: after its completion
/// and after a shutdown abort. Red if the session dropped either guard on
/// taking the envelope: the latch or the credit reads released while routes
/// remain.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_queued_latch_and_credit_release_after_completion_and_abort() {
    for abort in [false, true] {
        let (mut session, _peer, commands, _rib_rx, mut writer, mut envelope, inventory) =
            queued_last_owner_session().await;
        let credit = Arc::new(rustbgpd_rib::OutboundCredit::default());
        envelope.credit = Some(rustbgpd_rib::OutboundCharge::new(&credit, 7));
        let latch = Arc::new(rustbgpd_rib::OperationLatch::new(Arc::default()));
        let weak = Arc::downgrade(&latch);
        envelope.latch = Some(latch);
        session.outbound_tx.try_send(envelope).unwrap();
        let held = || weak.strong_count() == 1 && credit.rows() == 7;
        let mut intermediate = 0;
        if abort {
            commands.send(PeerCommand::Shutdown).await.unwrap();
            let mut released = Vec::new();
            run_by_step(&mut session, &inventory, &mut released).await;
            assert!(held(), "held while its inventory is queued");
            drop(session);
            for _ in 0..4 * QUEUED_ROUTES / QUEUE_SLICE {
                if inventory.live() > 0 && inventory.live() < QUEUED_ROUTES {
                    assert!(held(), "held mid-retirement");
                    intermediate += 1;
                }
                tokio::task::yield_now().await;
            }
        } else {
            let mut run = std::pin::pin!(session.run());
            for _ in 0..1_000_000 {
                if inventory.live() == 0 && weak.strong_count() == 0 {
                    break;
                }
                let polled =
                    std::future::poll_fn(|cx| std::task::Poll::Ready(run.as_mut().poll(cx))).await;
                assert!(polled.is_pending(), "the session stays up");
                while writer.try_recv().is_ok() {}
                if inventory.live() > 0 && inventory.live() < QUEUED_ROUTES {
                    assert!(held(), "held while its inventory is active");
                    intermediate += 1;
                }
                tokio::time::advance(std::time::Duration::from_millis(1)).await;
            }
        }
        assert!(intermediate > 0, "abort {abort}: observed mid-way");
        assert_eq!(inventory.live(), 0, "abort {abort}");
        assert_eq!(weak.strong_count(), 0, "abort {abort}: latch released");
        assert_eq!(credit.rows(), 0, "abort {abort}: credit released");
    }
}

/// A session task can exit while Established, without the teardown that
/// discards the queue (here every command sender is gone). The queue still
/// drops with the session, so the exit hands it to the paced release too.
#[tokio::test(start_paused = true)]
async fn outbound_pacing_exit_without_session_down_paces_queued_inventory_release() {
    let (mut session, _peer, commands, _rib_rx, _writer, envelope, inventory) =
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
    let (mut session, _peer, commands, rib_rx, _writer, envelope, inventory) =
        queued_last_owner_session().await;
    let permit = session.outbound_tx.clone().try_reserve_owned().unwrap();
    commands.send(PeerCommand::Shutdown).await.unwrap();
    let mut released = Vec::new();
    run_by_step(&mut session, &inventory, &mut released).await;
    assert_administrative_close(&session);
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
    let (mut session, _peer, commands, _rib_rx, _writer, envelope, inventory) =
        queued_last_owner_session().await;
    drop(envelope);
    let mut update = pacing_update(&session, Vec::new());
    inventory.add_other_families(&mut update, QUEUE_SLICE + 1);
    session.outbound_tx.try_send(update).unwrap();
    commands.send(PeerCommand::Shutdown).await.unwrap();
    let mut released = Vec::new();
    run_by_step(&mut session, &inventory, &mut released).await;
    assert_administrative_close(&session);
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
    let (mut session, _peer, commands, _rib_rx, _writer, mut envelope, inventory) =
        queued_last_owner_session().await;
    inventory.add_other_families(&mut envelope, QUEUE_SLICE / 2);
    session.outbound_tx.try_send(envelope).unwrap();
    commands.send(PeerCommand::Shutdown).await.unwrap();
    let mut released = Vec::new();
    run_by_step(&mut session, &inventory, &mut released).await;
    assert_administrative_close(&session);
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

/// Replace the writer with one the test drains and completes by hand: a
/// frame queue far deeper than any test fills, so only the byte budget can
/// hold admission, and a completion watermark the test advances.
fn hand_writer(
    session: &mut PeerSession,
) -> (mpsc::Receiver<Bytes>, tokio::sync::watch::Sender<u64>) {
    hand_writer_with(session, 1 << 16)
}

/// [`hand_writer`] with a frame queue of `slots`.
fn hand_writer_with(
    session: &mut PeerSession,
    slots: usize,
) -> (mpsc::Receiver<Bytes>, tokio::sync::watch::Sender<u64>) {
    session.writer_join.take().unwrap().abort();
    let (bulk, frames) = mpsc::channel(slots);
    let (completed_tx, completed) = tokio::sync::watch::channel(0);
    session.writer_bulk_tx = Some(bulk);
    session.writer_completed = Some(completed);
    session.writer_bytes = Some(Arc::new(super::super::writer::WriterBytes::new(
        session
            .metrics
            .outbound_writer_bytes_gauges(&session.peer_label),
    )));
    session.writer_bulk_admitted = 0;
    (frames, completed_tx)
}

/// Routes whose frames are large enough that a modest table crosses the
/// byte budget: one frame per route (distinct MED), each carrying 32
/// communities.
fn heavy_routes(count: u32) -> Vec<Route> {
    pacing_routes(count, true)
        .into_iter()
        .map(|mut route| {
            AttrSet::edit(&mut route.attributes, |attrs| {
                attrs.push(PathAttribute::Communities((0..32).collect()));
            });
            route
        })
        .collect()
}

/// Admit as the run loop does until the session stops on its own: the
/// envelope finishes, or admission waits for writer bytes that are still
/// held (a wait the writer has since satisfied resumes, as `ready` would).
fn admit_until_blocked(session: &mut PeerSession) {
    for _ in 0..10_000 {
        match session.pending_outbound.as_ref() {
            Some(pending) if !pending.bytes_blocked() || !session.writer_bytes_exhausted() => {
                session.advance_pending_outbound();
            }
            _ => return,
        }
    }
    panic!("admission never settled");
}

/// Drain every frame queued for the hand writer and report it written.
fn complete_all(
    session: &PeerSession,
    frames: &mut mpsc::Receiver<Bytes>,
    completed: &tokio::sync::watch::Sender<u64>,
    sink: &mut Vec<Bytes>,
) {
    while let Ok(frame) = frames.try_recv() {
        sink.push(frame);
    }
    completed.send_replace(session.writer_bulk_admitted);
    if let Some(bytes) = &session.writer_bytes {
        bytes.completed(session.writer_bulk_admitted);
    }
}

/// The peer's view of `frames`: each announced route's index, in order,
/// and `None` for an End-of-RIB.
fn delivered(frames: Vec<Bytes>) -> Vec<Option<u32>> {
    let mut seen = Vec::new();
    for mut frame in frames {
        let Message::Update(message) =
            rustbgpd_wire::decode_message(&mut frame, rustbgpd_wire::MAX_MESSAGE_LEN).unwrap()
        else {
            panic!("non-UPDATE bulk frame");
        };
        let parsed = message.parse(true, false, &[]).unwrap();
        if parsed.announced.is_empty() {
            seen.push(None);
        }
        for route in parsed.announced {
            seen.push(Some(u32::from(route.prefix.addr) & 0x00ff_ffff));
        }
    }
    seen
}

/// Whether the pending envelope's wait resolves within ten minutes of the
/// paused clock.
async fn envelope_wakes(session: &PeerSession) -> bool {
    let pending = session.pending_outbound.as_ref().unwrap();
    tokio::time::timeout(
        Duration::from_secs(600),
        pending.ready(session.writer_bulk_tx.as_ref()),
    )
    .await
    .is_ok()
}

const BYTE_BUDGET: u64 = super::super::writer::WRITER_BYTE_BUDGET;

/// A reader that stops draining holds the writer at its byte budget, not at
/// its frame count: admission stops with the cursor kept, and with send hold
/// enabled no deadline runs and no Cease is queued. Completing the backlog wakes and resumes the same
/// envelope, and the peer receives every route exactly once, in order, each
/// envelope's End-of-RIB after its routes.
#[tokio::test(start_paused = true)]
async fn paused_writer_plateaus_at_byte_budget_and_resumes_in_order() {
    const ROUTES: u32 = 6_000;
    let (mut session, _commands, _rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    let (mut frames, completed) = hand_writer(&mut session);

    let mut routes = heavy_routes(ROUTES + 1);
    let last = routes.split_off(ROUTES as usize);
    session
        .handle_outbound_route_update(pacing_update(&session, routes))
        .await;
    session
        .outbound_tx
        .try_send(pacing_update(&session, last))
        .unwrap();

    admit_until_blocked(&mut session);
    let held = session.writer_bytes_held();
    let pending = session.pending_outbound.as_ref().expect("cursor retained");
    assert!(pending.bytes_blocked(), "admission waits on bytes");
    assert!(held >= BYTE_BUDGET, "stopped below the budget: {held}");
    let first = frames.try_recv().unwrap();
    let frame = u64::try_from(first.len()).unwrap();
    assert!(
        held < BYTE_BUDGET + 2_048 * frame,
        "at most one admission step past the budget: {held}"
    );
    assert!(
        frames.len() < frames.max_capacity() / 4,
        "the frame count does not hold admission"
    );
    assert!(
        session.outbound_admission_timer.is_none(),
        "no deadline runs"
    );
    assert!(session.writer_priority_tx.is_some(), "no teardown");
    assert_eq!(session.fsm.state(), SessionState::Established);
    session.sample_outbound_queue_depth();
    assert_eq!(
        session
            .metrics
            .peer_outbound_writer_bytes(&session.peer_label),
        i64::try_from(held).unwrap()
    );
    let admitted = session.writer_bulk_admitted;
    for _ in 0..8 {
        session.advance_pending_outbound();
    }
    assert_eq!(
        session.writer_bulk_admitted, admitted,
        "paused stays paused"
    );

    // Nothing wakes the envelope while the reader stays paused.
    assert!(
        !envelope_wakes(&session).await,
        "a paused writer leaves the envelope waiting"
    );

    // The reader resumes.
    let mut sink = vec![first];
    complete_all(&session, &mut frames, &completed, &mut sink);
    assert!(
        envelope_wakes(&session).await,
        "a completed write wakes the waiting envelope"
    );
    for _ in 0..1_000 {
        admit_until_blocked(&mut session);
        complete_all(&session, &mut frames, &completed, &mut sink);
        if session.pending_outbound.is_none() {
            let Ok(update) = session.outbound_rx.try_recv() else {
                break;
            };
            session.handle_outbound_route_update(update).await;
        }
    }
    assert!(session.pending_outbound.is_none());
    session.sample_outbound_queue_depth();
    assert_eq!(
        session
            .metrics
            .peer_outbound_writer_bytes(&session.peer_label),
        0
    );

    let mut expected: Vec<_> = (0..ROUTES).map(Some).collect();
    expected.extend([None, Some(ROUTES), None]);
    assert_eq!(
        delivered(sink),
        expected,
        "every route once, in order, each End-of-RIB after its routes"
    );
}

/// The waiting envelope wakes on the first completed byte that brings the
/// backlog under the budget, not before: at exactly the budget it is still
/// held, so an earlier wake would only spin the session.
#[tokio::test(start_paused = true)]
async fn byte_wait_wakes_exactly_when_the_backlog_drops_under_the_budget() {
    let (mut session, _commands, _rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    let (_frames, completed) = hand_writer(&mut session);
    session
        .handle_outbound_route_update(pacing_update(&session, heavy_routes(6_000)))
        .await;
    admit_until_blocked(&mut session);
    let at_budget = session.writer_bulk_admitted - BYTE_BUDGET;
    completed.send_replace(at_budget);
    assert!(session.writer_bytes_exhausted());
    assert!(!envelope_wakes(&session).await, "still at the budget");
    completed.send_replace(at_budget + 1);
    assert!(envelope_wakes(&session).await, "one byte under the budget");
}

/// Ask the running session for its state, so that every event it was
/// handed before has been processed.
async fn settle(commands: &mpsc::Sender<PeerCommand>) -> SessionState {
    let (reply, response) = oneshot::channel();
    commands
        .send(PeerCommand::QueryState { reply })
        .await
        .unwrap();
    response.await.unwrap().fsm_state
}

fn assert_cease_out_of_resources(mut encoded: Bytes) {
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
}

/// With RFC 9687 send hold disabled, a byte wait still has the documented
/// finite resource deadline. Each completed write re-arms it, even one that
/// leaves the backlog over the budget, so a reader that keeps reading is
/// never torn down; once writes stop completing, the deadline sends
/// Cease/Out-of-Resources one interval after the last of them.
#[tokio::test(start_paused = true)]
async fn byte_wait_deadline_rearms_on_each_write_and_ends_a_stopped_reader() {
    let (mut session, commands, _rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    session.config.peer.hold_time = 0;
    session.config.peer.send_hold_time = 0;
    let (_frames, completed) = hand_writer(&mut session);
    let (priority, mut priority_rx) = mpsc::unbounded_channel();
    session.writer_priority_tx = Some(priority);
    session
        .handle_outbound_route_update(pacing_update(&session, heavy_routes(6_000)))
        .await;
    admit_until_blocked(&mut session);
    assert!(session.writer_bytes_held() >= BYTE_BUDGET + 3);
    let interval = Duration::from_secs(u64::from(rustbgpd_fsm::default_send_hold_time(0)));
    let armed = session
        .outbound_admission_timer
        .as_ref()
        .expect("a byte wait with send hold disabled has a deadline")
        .deadline();
    assert_eq!(armed - tokio::time::Instant::now(), interval);
    let actor = tokio::spawn(async move {
        let _ = session.run().await;
    });
    let just_before = interval.checked_sub(Duration::from_millis(1)).unwrap();
    for written in 1..=3 {
        tokio::time::advance(just_before).await;
        completed.send_replace(written);
        assert_eq!(settle(&commands).await, SessionState::Established);
        assert!(
            priority_rx.try_recv().is_err(),
            "torn down while writes complete"
        );
    }
    tokio::time::advance(just_before).await;
    settle(&commands).await;
    assert!(priority_rx.try_recv().is_err(), "deadline fired early");
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_cease_out_of_resources(priority_rx.recv().await.expect("Cease/8"));
    commands.send(PeerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

/// With send hold enabled a byte wait runs no admission deadline, even when
/// the step that crossed the budget also filled the frame queue: a write is
/// in flight and the writer's send hold bounds it, while a peer that keeps
/// completing writes, however slowly, is not sent Cease/8. With send hold
/// disabled the same state runs the deadline.
#[tokio::test(start_paused = true)]
async fn bytes_and_frames_exhausted_together_defer_to_the_send_hold() {
    for send_hold in [true, false] {
        let (mut session, _commands, _rib_rx) = make_test_session_with_channels(65001, 65002, 64);
        let (client, _server) = connected_stream_pair().await;
        session.test_install_stream(client);
        establish_test_session(&mut session, 65002).await;
        session.timers.hold = None;
        if !send_hold {
            session.config.peer.send_hold_time = 0;
        }
        let (_frames, _completed) = hand_writer(&mut session);
        // Over the budget already, and the only frame slot taken.
        session.writer_bulk_admitted = BYTE_BUDGET;
        let (bulk, _held) = mpsc::channel(1);
        bulk.try_send(Bytes::from_static(b"held")).unwrap();
        session.writer_bulk_tx = Some(bulk);
        session
            .handle_outbound_route_update(pacing_update(&session, heavy_routes(10)))
            .await;
        let pending = session.pending_outbound.as_ref().unwrap();
        assert!(pending.bytes_blocked());
        assert_eq!(
            session.outbound_admission_timer.is_some(),
            !send_hold,
            "send hold {send_hold}"
        );
    }
}

/// A peer that stops reading altogether is still torn down with send hold
/// enabled, though the byte budget now holds admission long before the
/// frame queue fills: the writer has a write in flight, and its send hold
/// ends it within the send hold of that write's start. Real sockets with
/// small buffers on a paused clock, which also advances while socket I/O is
/// still landing, so the write that finally blocks can start at any virtual
/// time: the test records each write's start and checks, every tick, that
/// the session is not still up past the latest start plus the send hold
/// plus one tick.
#[tokio::test(start_paused = true)]
async fn a_stopped_reader_behind_the_byte_budget_meets_the_send_hold() {
    use super::super::writer::LAST_WRITE_START;
    const SEND_HOLD: u64 = 600;
    let tick = Duration::from_secs(10);
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    session.commands = cmd_rx;
    let (server, _peer) = small_buffer_pair().await;
    session.config.peer.send_hold_time = u32::try_from(SEND_HOLD).unwrap();
    session.test_install_stream(server);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    let metrics = session.metrics.clone();
    let label = session.peer_label.clone();
    session
        .outbound_tx
        .try_send(pacing_update(&session, heavy_routes(6_000)))
        .unwrap();
    let actor = tokio::spawn(async move {
        let _ = session.run().await;
    });
    let mut torn_down = false;
    for _ in 0..1_000 {
        tokio::time::sleep(tick).await;
        if settle(&cmd_tx).await != SessionState::Established {
            torn_down = true;
            break;
        }
        let started = LAST_WRITE_START
            .with(std::cell::Cell::get)
            .expect("the writer has written");
        assert!(
            tokio::time::Instant::now() <= started + Duration::from_secs(SEND_HOLD) + tick,
            "still up {:?} after the last write began",
            tokio::time::Instant::now().saturating_duration_since(started)
        );
    }
    assert!(torn_down, "a stopped reader was never torn down");
    assert_eq!(metrics.peer_outbound_writer_bytes(&label), 0);
    cmd_tx.send(PeerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

/// A listener and client pair with 4 KiB socket buffers, so a peer that
/// stops reading stalls the writer after a few frames: the server end for
/// the session, the client end for the peer.
async fn small_buffer_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        socket.connect(addr).await.unwrap()
    });
    let (server, _) = listener.accept().await.unwrap();
    socket2::SockRef::from(&server)
        .set_send_buffer_size(4096)
        .unwrap();
    (server, connect.await.unwrap())
}

/// Through the real run loop and writer: a peer that stops reading leaves
/// the writer holding its byte budget plus at most one admission step, the
/// envelope behind stays in the RIB channel, and the session stays up. Once
/// the peer reads, every route arrives exactly once, in order, each
/// envelope's End-of-RIB after its routes.
#[tokio::test]
async fn a_paused_reader_holds_the_real_writer_at_its_budget_and_resumes_in_order() {
    // Full frames, so one admission step is a few frames.
    const ROUTES: u32 = 400_000;
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    session.commands = cmd_rx;
    let (server, mut peer) = small_buffer_pair().await;
    session.test_install_stream(server);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    read_single_bgp_message(&mut peer).await;
    read_single_bgp_message(&mut peer).await;
    let metrics = session.metrics.clone();
    let label = session.peer_label.clone();
    let outbound = session.outbound_tx.clone();
    let mut routes = pacing_routes(ROUTES + 1, false);
    let last = routes.split_off(ROUTES as usize);
    outbound.try_send(pacing_update(&session, routes)).unwrap();
    outbound.try_send(pacing_update(&session, last)).unwrap();
    let actor = tokio::spawn(async move {
        let _ = session.run().await;
    });

    // Settled: the session answers many state queries in a row, each one a
    // full turn of its loop, without the backlog or the RIB channel moving.
    // A session still admitting would move them between turns.
    let observe = || {
        (
            metrics.peer_outbound_writer_bytes(&label),
            outbound.capacity(),
        )
    };
    let started = std::time::Instant::now();
    let mut unchanged = 0;
    while unchanged < 64 {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the session never settled"
        );
        let before = observe();
        assert_eq!(settle(&cmd_tx).await, SessionState::Established);
        unchanged = if observe() == before {
            unchanged + 1
        } else {
            0
        };
    }
    let held = metrics.peer_outbound_writer_bytes(&label);
    assert!(
        held >= i64::try_from(BYTE_BUDGET).unwrap(),
        "settled below the budget: {held}"
    );
    assert!(
        held < i64::try_from(BYTE_BUDGET).unwrap() + 64 * 1024,
        "at most one admission step past the budget: {held}"
    );
    assert_eq!(
        outbound.max_capacity() - outbound.capacity(),
        1,
        "the envelope behind waits in the RIB channel"
    );
    assert_eq!(settle(&cmd_tx).await, SessionState::Established);

    let mut seen = Vec::new();
    while seen
        .iter()
        .filter(|entry: &&Option<u32>| entry.is_none())
        .count()
        < 2
    {
        let message =
            tokio::time::timeout(Duration::from_secs(30), read_single_bgp_message(&mut peer))
                .await
                .expect("delivery resumes once the peer reads");
        let Message::Update(message) = message else {
            panic!("non-UPDATE before the End-of-RIBs");
        };
        let parsed = message.parse(true, false, &[]).unwrap();
        if parsed.announced.is_empty() {
            seen.push(None);
        }
        for route in parsed.announced {
            seen.push(Some(u32::from(route.prefix.addr) & 0x00ff_ffff));
        }
    }
    let mut expected: Vec<_> = (0..ROUTES).map(Some).collect();
    expected.extend([None, Some(ROUTES), None]);
    assert_eq!(seen, expected, "every route once, in order");
    cmd_tx.send(PeerCommand::Shutdown).await.unwrap();
    actor.await.unwrap();
}

/// The slow-peer detector sees a lagging peer by its writer's unwritten
/// bytes: at production frame capacity, with full frames, the byte budget
/// holds admission far below the frame threshold, which alone would never
/// start an episode.
#[tokio::test(start_paused = true)]
async fn a_lagging_peer_held_by_bytes_is_flagged_slow_at_production_queue_capacity() {
    let (mut session, _commands, _rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    let (mut frames, completed) = hand_writer_with(&mut session, super::super::OUTBOUND_BUFFER);
    // Shared attributes pack each frame full, as many real tables do.
    session
        .handle_outbound_route_update(pacing_update(&session, pacing_routes(140_000, false)))
        .await;
    admit_until_blocked(&mut session);
    assert!(session.writer_bytes_exhausted());
    let frame_threshold = (super::super::OUTBOUND_BUFFER
        * usize::from(session.config.slow_peer_threshold_pct))
    .div_ceil(100);
    assert!(
        frames.len() < frame_threshold,
        "frames alone stay under the threshold"
    );
    session.evaluate_slow_peer();
    assert!(
        session.slow_peer_backlog_since.is_some(),
        "an episode starts"
    );
    assert!(session.slow_peer_timer.is_some());
    session.slow_peer_backlog_since = std::time::Instant::now().checked_sub(Duration::from_secs(
        u64::from(session.config.slow_peer_duration),
    ));
    session.evaluate_slow_peer();
    assert!(session.slow_peer, "flagged slow");

    let mut sink = Vec::new();
    complete_all(&session, &mut frames, &completed, &mut sink);
    session.evaluate_slow_peer();
    assert!(!session.slow_peer, "cleared once the backlog drains");
}

/// Both shared paths stop at the byte budget and resume without a gap: the
/// elected encoder stops its own copy at the budget but still publishes the
/// whole stream, a follower stops its snapshot at its own budget, and each
/// resumes from its first unsent chunk. The follower drains to the end while
/// the encoder's reader stays paused.
#[tokio::test(start_paused = true)]
async fn shared_members_stop_at_their_byte_budget_and_resume_without_gaps() {
    const ROUTES: u32 = 6_000;
    let shared = Arc::new(rustbgpd_rib::SharedGroupEncode::default());
    let announce = Arc::new(heavy_routes(ROUTES));
    let excluded = Ipv4Addr::new(10, 99, 0, 1);

    let (mut encoder, _encoder_wire) = shared_group_member(65001).await;
    let (mut encoder_frames, encoder_done) = hand_writer(&mut encoder);
    encoder
        .handle_outbound_route_update(shared_group_envelope(
            &encoder, &shared, excluded, &announce,
        ))
        .await;
    let (chunks, terminal) = shared
        .cell
        .get()
        .expect("the encoder publishes the stream")
        .downcast_ref::<super::shared_group::ProgressiveGroupEncode>()
        .unwrap()
        .test_snapshot();
    assert_eq!(
        terminal,
        Some(super::shared_group::StreamTerminal::Complete),
        "publication does not wait for the encoder's own reader"
    );
    assert_eq!(chunks, ROUTES as usize);
    admit_until_blocked(&mut encoder);
    let mut encoder_sink = Vec::new();
    while let Ok(frame) = encoder_frames.try_recv() {
        encoder_sink.push(frame);
    }
    let chunk = encoder_sink.iter().map(Bytes::len).max().unwrap() as u64;
    assert!(encoder.pending_outbound.as_ref().unwrap().bytes_blocked());
    assert!(
        encoder.writer_bytes_held() < BYTE_BUDGET + chunk,
        "the encoder's own copy stops at the budget"
    );

    let (mut follower, _follower_wire) = shared_group_member(65001).await;
    let (mut follower_frames, follower_done) = hand_writer(&mut follower);
    follower
        .handle_outbound_route_update(shared_group_envelope(
            &follower, &shared, excluded, &announce,
        ))
        .await;
    admit_until_blocked(&mut follower);
    assert!(follower.pending_outbound.as_ref().unwrap().bytes_blocked());
    assert!(
        follower.writer_bytes_held() < BYTE_BUDGET + chunk,
        "the follower's snapshot stops at its budget"
    );
    let mut follower_sink = Vec::new();
    for _ in 0..1_000 {
        complete_all(
            &follower,
            &mut follower_frames,
            &follower_done,
            &mut follower_sink,
        );
        if follower.pending_outbound.is_none() {
            break;
        }
        admit_until_blocked(&mut follower);
    }
    assert!(follower.pending_outbound.is_none(), "the follower finished");
    assert!(encoder.pending_outbound.as_ref().unwrap().bytes_blocked());

    for _ in 0..1_000 {
        complete_all(
            &encoder,
            &mut encoder_frames,
            &encoder_done,
            &mut encoder_sink,
        );
        if encoder.pending_outbound.is_none() {
            break;
        }
        admit_until_blocked(&mut encoder);
    }
    assert!(encoder.pending_outbound.is_none(), "the encoder finished");
    let every: Vec<_> = (0..ROUTES).map(Some).collect();
    for (member, sink) in [("encoder", encoder_sink), ("follower", follower_sink)] {
        let mut seen = delivered(sink);
        seen.sort_unstable();
        assert_eq!(seen, every, "{member}: every route once");
    }
}

/// Each slow-peer threshold is the configured share of its own limit: the
/// frame queue's capacity and the writer's byte budget. One frame, or one
/// byte, under the share starts no episode; reaching it does.
#[tokio::test(start_paused = true)]
async fn slow_peer_thresholds_are_the_configured_share_of_frames_and_bytes() {
    let (mut session, _commands, _rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let (_frames, _completed) = hand_writer_with(&mut session, super::super::OUTBOUND_BUFFER);
    let pct = usize::from(session.config.slow_peer_threshold_pct);
    let frames = (super::super::OUTBOUND_BUFFER * pct).div_ceil(100);
    let bytes = (BYTE_BUDGET * pct as u64).div_ceil(100);
    let bulk = session.writer_bulk_tx.clone().unwrap();
    for _ in 1..frames {
        bulk.try_send(Bytes::from_static(b"frame")).unwrap();
    }
    session.evaluate_slow_peer();
    assert!(session.slow_peer_backlog_since.is_none(), "one frame under");
    bulk.try_send(Bytes::from_static(b"frame")).unwrap();
    session.evaluate_slow_peer();
    assert!(
        session.slow_peer_backlog_since.is_some(),
        "at the frame share"
    );

    let (fresh, _fresh_frames) = mpsc::channel(super::super::OUTBOUND_BUFFER);
    session.writer_bulk_tx = Some(fresh);
    session.evaluate_slow_peer();
    assert!(session.slow_peer_backlog_since.is_none(), "drained");
    session.writer_bulk_admitted = bytes - 1;
    session.evaluate_slow_peer();
    assert!(session.slow_peer_backlog_since.is_none(), "one byte under");
    session.writer_bulk_admitted = bytes;
    session.evaluate_slow_peer();
    assert!(
        session.slow_peer_backlog_since.is_some(),
        "at the byte share"
    );
}

/// A write that completes in the same turn as the admission deadline is
/// progress even when the expiry is handled first: the deadline is re-armed
/// for a full interval instead of sending Cease/8. With no further progress
/// the next expiry ends the session.
#[tokio::test(start_paused = true)]
async fn a_write_completing_with_the_deadline_rearms_it() {
    let (mut session, _commands, _rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    session.timers.hold = None;
    session.config.peer.hold_time = 0;
    session.config.peer.send_hold_time = 0;
    let (_frames, completed) = hand_writer(&mut session);
    let (priority, mut priority_rx) = mpsc::unbounded_channel();
    session.writer_priority_tx = Some(priority);
    session
        .handle_outbound_route_update(pacing_update(&session, heavy_routes(6_000)))
        .await;
    admit_until_blocked(&mut session);
    let interval = session.admission_deadline();
    tokio::time::advance(interval).await;
    completed.send_replace(1);
    session.expire_outbound_admission();
    assert!(
        priority_rx.try_recv().is_err(),
        "no Cease/8 beside fresh progress"
    );
    let rearmed = session
        .outbound_admission_timer
        .as_ref()
        .expect("the deadline runs again")
        .deadline();
    assert_eq!(rearmed - tokio::time::Instant::now(), interval);
    session.expire_outbound_admission();
    assert_cease_out_of_resources(priority_rx.try_recv().expect("Cease/8"));
}
