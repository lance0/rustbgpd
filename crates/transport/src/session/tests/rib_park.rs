//! A session whose inbound delivery is held by a full RIB ingest channel
//! keeps servicing its outbound queue, timers and terminal commands, while
//! leaving further peer input unread (TCP backpressure, ADR-0078).
//!
//! Wire assertions run on real time: with a paused clock the runtime can
//! auto-advance past a timeout before loopback bytes become readable. The
//! hold-time test needs a paused clock, so it observes the writer's and the
//! session's send counters instead of the wire.
use super::*;

/// An Established session whose RIB channel is already full, so the first
/// inbound UPDATE (`held`) parks it.
struct RibPark {
    session: PeerSession,
    commands: mpsc::Sender<PeerCommand>,
    rib_rx: mpsc::Receiver<RibUpdate>,
    server: TcpStream,
    outbound: mpsc::Sender<OutboundRouteUpdate>,
    /// Placeholder batches that fill the RIB channel ahead of `held`.
    fillers: usize,
    /// The update the test hands the session while it is parked.
    queued: OutboundRouteUpdate,
}

fn held() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24)
}
fn later() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24)
}
fn unread() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24)
}
fn exported() -> Ipv4Prefix {
    Ipv4Prefix::new(Ipv4Addr::new(20, 0, 0, 0), 16)
}

fn encoded_announce(prefix: Ipv4Prefix) -> Vec<u8> {
    rustbgpd_wire::encode_message(&Message::Update(ipv4_announce(prefix, 0, false)))
        .unwrap()
        .to_vec()
}

async fn rib_park() -> RibPark {
    let (mut session, commands, mut rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, server) = connected_stream_pair().await;
    session.test_install_stream(client);
    // From here no step waits on I/O until the session parks, so a paused
    // clock stays at the instant the hold and KEEPALIVE timers were armed.
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    let mut fillers = 0;
    while session
        .rib_tx
        .try_send(placeholder_routes_received())
        .is_ok()
    {
        fillers += 1;
    }
    let mut route = make_route(100);
    route.prefix = Prefix::V4(exported());
    let queued = OutboundRouteUpdate {
        exact_export_snapshot: Some(session.publish_export_profile()),
        announce: vec![route].into(),
        ..OutboundRouteUpdate::default()
    };
    let outbound = session.outbound_tx.clone();
    RibPark {
        session,
        commands,
        rib_rx,
        server,
        outbound,
        fillers,
        queued,
    }
}

fn counter(metrics: &BgpMetrics, name: &str, labels: &[(&str, &str)]) -> f64 {
    metrics
        .registry()
        .gather()
        .into_iter()
        .find(|family| family.name() == name)
        .and_then(|family| {
            family.get_metric().iter().find_map(|metric| {
                labels
                    .iter()
                    .all(|(name, value)| {
                        metric
                            .get_label()
                            .iter()
                            .any(|label| label.name() == *name && label.value() == *value)
                    })
                    .then(|| metric.get_counter().get_value())
            })
        })
        .unwrap_or(0.0)
}

/// Handshake: the session has met the full RIB channel. Bounded spin, so a
/// session that never parks fails instead of hanging.
async fn until_parked(metrics: &BgpMetrics, peer: &str) {
    for _ in 0..1_000_000 {
        if counter(
            metrics,
            "bgp_inbound_rib_backpressure_total",
            &[("peer", peer)],
        ) >= 1.0
        {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("the session never parked on the full RIB channel");
}

/// Hold `held` for the full RIB channel with `behind` buffered after it,
/// seeded into the read buffer so no short socket read can split them.
async fn park_with_buffered(session: &mut PeerSession, behind: &[u8]) {
    session
        .read_buf
        .buf
        .extend_from_slice(&encoded_announce(held()));
    session.read_buf.buf.extend_from_slice(behind);
    session.process_read_buffer().await;
    assert_eq!(session.rib_backlog.len(), 1, "`held` must be held");
    assert_eq!(&session.read_buf.buf[..], behind, "`behind` stays buffered");
}

/// The next frame other than the handshake's OPEN and KEEPALIVEs, within a
/// real-time bound.
async fn next_frame_after_handshake(server: &mut TcpStream) -> Option<Message> {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match read_single_bgp_message(server).await {
                Message::Open(_) | Message::Keepalive => {}
                message => return message,
            }
        }
    })
    .await
    .ok()
}

fn announced_v4(update: &RibUpdate) -> Vec<Prefix> {
    match update {
        RibUpdate::RoutesReceived { announced, .. } => {
            announced.iter().map(|route| route.prefix).collect()
        }
        _ => Vec::new(),
    }
}

/// Mutation-red: without the outbound arm serviced while parked, the queued
/// update stays in `outbound_rx` until the RIB drains, so no UPDATE reaches
/// the wire.
#[tokio::test]
async fn rib_park_drains_outbound_to_the_wire() {
    let RibPark {
        mut session,
        commands: _commands,
        rib_rx: _rib_rx,
        mut server,
        outbound,
        queued,
        ..
    } = rib_park().await;
    let (metrics, peer) = (session.metrics.clone(), session.peer_label.clone());
    let run = session.run();
    let steps = async {
        server.write_all(&encoded_announce(held())).await.unwrap();
        until_parked(&metrics, &peer).await;
        outbound.try_send(queued).unwrap();
        let frame = next_frame_after_handshake(&mut server).await;
        let Some(Message::Update(update)) = frame else {
            panic!("a parked session must still drain outbound, got {frame:?}");
        };
        let parsed = update.parse(true, false, &[]).unwrap();
        assert_eq!(
            parsed
                .announced
                .iter()
                .map(|nlri| nlri.prefix)
                .collect::<Vec<_>>(),
            vec![exported()]
        );
    };
    tokio::select! {
        result = run => panic!("run() ended while parked: {result:?}"),
        () = steps => {}
    }
}

fn cease_out_of_resources(metrics: &BgpMetrics, peer: &str) -> f64 {
    counter(
        metrics,
        "bgp_notifications_sent_total",
        &[("peer", peer), ("code", "6"), ("subcode", "8")],
    )
}

/// KEEPALIVEs are writer-owned (ADR-0078) and keep flowing while parked.
/// With nothing more from the peer, the first hold expiry is deferred for
/// the wait itself and the second closes the session as a local overload:
/// Cease/Out of Resources, not Hold Timer Expired. Its `PeerDown` then
/// follows the held UPDATE.
/// Mutation-red: with the hold arm unpolled while parked nothing expires;
/// with an unbounded renewal budget no Cease is sent.
#[tokio::test(start_paused = true)]
async fn rib_park_exhausted_stall_budget_sends_cease_then_peer_down() {
    let RibPark {
        mut session,
        commands: _commands,
        mut rib_rx,
        mut server,
        fillers,
        ..
    } = rib_park().await;
    let (metrics, peer) = (session.metrics.clone(), session.peer_label.clone());
    let keepalives = || {
        counter(
            &metrics,
            "bgp_messages_sent_total",
            &[("peer", &peer), ("type", "keepalive")],
        )
    };
    let rearmed = || {
        counter(
            &metrics,
            "bgp_hold_timer_rearmed_pending_input_total",
            &[("peer", &peer)],
        )
    };
    let hold_expiries = || {
        counter(
            &metrics,
            "bgp_notifications_sent_total",
            &[("peer", &peer), ("code", "4")],
        )
    };
    let established = tokio::time::Instant::now();
    let before = keepalives();
    {
        let run = session.run();
        let steps = async {
            server.write_all(&encoded_announce(held())).await.unwrap();
            until_parked(&metrics, &peer).await;
            tokio::time::sleep_until(established + Duration::from_secs(89)).await;
            assert_eq!(
                keepalives() - before,
                2.0,
                "writer KEEPALIVEs at 30 s and 60 s"
            );
            assert_eq!(rearmed(), 0.0, "the hold time has not elapsed yet");
            tokio::time::sleep_until(established + Duration::from_secs(91)).await;
            assert_eq!(rearmed(), 1.0, "the first expiry is deferred for the wait");
            assert_eq!(cease_out_of_resources(&metrics, &peer), 0.0);
            tokio::time::sleep_until(established + Duration::from_secs(182)).await;
            assert_eq!(
                cease_out_of_resources(&metrics, &peer),
                1.0,
                "an exhausted stall budget closes with Cease/Out of Resources"
            );
            assert_eq!(hold_expiries(), 0.0, "not Hold Timer Expired");
        };
        tokio::select! {
            result = run => panic!("run() ended while parked: {result:?}"),
            () = steps => {}
        }
    }
    assert_ne!(session.fsm.state(), SessionState::Established);
    assert!(
        matches!(
            session.rib_backlog.back(),
            Some((RibUpdate::PeerDown { .. }, _))
        ),
        "the teardown's PeerDown waits behind the held UPDATE"
    );
    for _ in 0..fillers {
        assert_eq!(announced_v4(&rib_rx.try_recv().unwrap()), []);
    }
    deliver_held_rib_messages(&mut session).await;
    assert_eq!(
        announced_v4(&rib_rx.try_recv().unwrap()),
        vec![Prefix::V4(held())]
    );
    assert!(matches!(
        rib_rx.try_recv().unwrap(),
        RibUpdate::PeerDown { .. }
    ));
}

/// A parked session (`held`, with `behind` buffered) whose hold expiries a
/// test drives directly.
async fn parked(behind: &[u8]) -> RibPark {
    let mut park = rib_park().await;
    park_with_buffered(&mut park.session, behind).await;
    park
}

/// One hold expiry as the run loop observes it. True when the session
/// survives it.
async fn hold_expiry(session: &mut PeerSession) -> bool {
    session.timers.hold = None;
    session.handle_hold_timer_expiry().await;
    session.read_half.is_some()
}

/// The peer writes `bytes`; returns once the session's socket holds at
/// least one unread byte (a peek, so the session still reads it).
async fn peer_sends(server: &mut TcpStream, session: &mut PeerSession, bytes: &[u8]) {
    server.write_all(bytes).await.unwrap();
    let mut peek = [0_u8; 1];
    let read_half = session.read_half.as_mut().unwrap();
    assert_eq!(read_half.peek(&mut peek).await.unwrap(), 1);
}

fn keepalive_pdu() -> Vec<u8> {
    rustbgpd_wire::encode_message(&Message::Keepalive)
        .unwrap()
        .to_vec()
}

/// A one-byte trickle buys no more than the stall budget: two deferred
/// expiries, then Cease/Out of Resources by the third hold time.
/// Mutation-red: an unbounded budget keeps the session up on garbage.
#[tokio::test]
async fn rib_park_one_byte_trickle_closes_by_the_third_hold_time() {
    let RibPark {
        mut session,
        mut server,
        commands: _commands,
        rib_rx: _rib_rx,
        ..
    } = parked(&[]).await;
    let (metrics, peer) = (session.metrics.clone(), session.peer_label.clone());
    assert!(hold_expiry(&mut session).await, "the wait itself earns one");
    peer_sends(&mut server, &mut session, &[0]).await;
    assert!(hold_expiry(&mut session).await, "newly read bytes earn one");
    peer_sends(&mut server, &mut session, &[0]).await;
    assert!(!hold_expiry(&mut session).await, "the budget is spent");
    assert_eq!(cease_out_of_resources(&metrics, &peer), 1.0);
}

/// Bytes already queued in the socket before silence cannot be told from
/// fresh ones, so they may buy a renewal, but no more than the budget, and
/// each costs at most one probe of buffer.
/// Mutation-red: an unbounded budget renews once per probe of the reservoir.
#[tokio::test]
async fn rib_park_old_socket_reservoir_closes_by_the_third_hold_time() {
    let RibPark {
        mut session,
        mut server,
        commands: _commands,
        rib_rx: _rib_rx,
        ..
    } = parked(&[]).await;
    let reservoir = keepalive_pdu().repeat(2_000);
    assert!(reservoir.len() >= 32 * 1024);
    peer_sends(&mut server, &mut session, &reservoir).await;
    assert!(hold_expiry(&mut session).await);
    assert!(hold_expiry(&mut session).await);
    assert!(
        !hold_expiry(&mut session).await,
        "the reservoir buys no more"
    );
    assert!(
        session.read_buf.buf.len() <= 4096,
        "one probe read: {} bytes",
        session.read_buf.buf.len()
    );
}

/// Waits that end and restart cannot grow the read buffer past two
/// maximum-size messages: each re-park resets the renewal budget, but the
/// probe only refills up to the cap, whatever the number of waits.
/// Mutation-red: probing past the cap appends another 4 KiB each cycle.
#[tokio::test]
async fn rib_park_repeated_waits_keep_the_read_buffer_capped() {
    let later_pdu = encoded_announce(later());
    let RibPark {
        mut session,
        mut server,
        commands: _commands,
        mut rib_rx,
        ..
    } = parked(&later_pdu).await;
    // Without RFC 8654 frames the cap is two 4096-byte messages.
    session
        .read_buf
        .set_max_message_len(rustbgpd_wire::MAX_MESSAGE_LEN);
    let cap = 2 * usize::from(rustbgpd_wire::MAX_MESSAGE_LEN);
    peer_sends(&mut server, &mut session, &later_pdu.repeat(2_000)).await;
    let mut peak = 0;
    for _ in 0..16 {
        assert!(hold_expiry(&mut session).await);
        assert!(hold_expiry(&mut session).await, "each wait reads new bytes");
        peak = peak.max(session.read_buf.buf.len());
        assert!(
            session.read_buf.buf.len() <= cap,
            "read buffer {} bytes past the {cap}-byte cap",
            session.read_buf.buf.len()
        );
        // Admit only the held UPDATE: the wait ends and the next buffered
        // UPDATE parks again at once, starting a new wait.
        rib_rx.try_recv().unwrap();
        let reserved = inbound::poll_rib_reserve(&mut session.rib_reserve).await;
        session.advance_rib_backlog(reserved).await;
        assert_eq!(session.rib_backlog.len(), 1, "parked again");
    }
    assert_eq!(peak, cap, "the probes reached the cap");
}

/// The first deferral belongs to the wait itself: a peer whose next frame is
/// a partial extended message (its tail held back by our closed receive
/// window) is not expired at the first deadline.
/// Mutation-red: requiring a complete frame or newly read bytes for the
/// first renewal expires it.
#[tokio::test]
async fn rib_park_partial_extended_frame_gets_its_first_deadline() {
    let mut header = vec![0xff_u8; 16];
    header.extend_from_slice(&6_000_u16.to_be_bytes());
    header.push(2);
    header.extend_from_slice(&[0; 11]);
    let RibPark {
        mut session,
        commands: _commands,
        rib_rx: _rib_rx,
        server: _server,
        ..
    } = rib_park().await;
    session
        .read_buf
        .set_max_message_len(rustbgpd_wire::EXTENDED_MAX_MESSAGE_LEN);
    park_with_buffered(&mut session, &header).await;
    assert!(!session.read_buf.has_complete_frame());
    assert!(
        hold_expiry(&mut session).await,
        "the first deadline is deferred"
    );
}

/// The budget counts renewals since the last processed peer PDU: admitting
/// the head of a longer backlog, or draining it, leaves it spent, and the
/// next peer PDU processed restores the full allowance.
/// Mutation-red: not resetting on a processed PDU expires the next wait at
/// its first deadline; resetting whenever the head is admitted grants more
/// than the budget within one wait.
#[tokio::test]
async fn rib_park_budget_resets_on_processed_peer_input() {
    let RibPark {
        mut session,
        mut server,
        commands: _commands,
        mut rib_rx,
        ..
    } = parked(&[]).await;
    session.send_to_rib(placeholder_routes_received()).unwrap();
    assert_eq!(session.rib_backlog.len(), 2);
    assert!(hold_expiry(&mut session).await);
    rib_rx.try_recv().unwrap();
    let reserved = inbound::poll_rib_reserve(&mut session.rib_reserve).await;
    session.advance_rib_backlog(reserved).await;
    assert_eq!(session.rib_backlog.len(), 1, "only the head was admitted");
    assert_eq!(session.parked_hold_renewals, 1, "the wait goes on");
    while rib_rx.try_recv().is_ok() {}
    deliver_held_rib_messages(&mut session).await;
    assert!(session.rib_backlog.is_empty());
    assert_eq!(session.parked_hold_renewals, 1, "no peer PDU processed yet");
    assert_eq!(session.fsm.state(), SessionState::Established);
    while session
        .rib_tx
        .try_send(placeholder_routes_received())
        .is_ok()
    {}
    // Parking on a peer UPDATE processes it: the budget is restored.
    park_with_buffered(&mut session, &[]).await;
    assert_eq!(session.parked_hold_renewals, 0);
    assert!(hold_expiry(&mut session).await, "a full allowance again");
    peer_sends(&mut server, &mut session, &[0]).await;
    assert!(hold_expiry(&mut session).await);
}

/// The M63 shape: a park outlasts the 9 s hold time once, with the peer's
/// KEEPALIVEs queued, and the RIB drains before the next deadline. The
/// session survives on its first deferral and starts the next wait afresh.
#[tokio::test]
async fn rib_park_m63_shape_survives_one_long_park() {
    let RibPark {
        mut session,
        mut server,
        commands: _commands,
        mut rib_rx,
        ..
    } = parked(&[]).await;
    peer_sends(&mut server, &mut session, &keepalive_pdu()).await;
    assert!(hold_expiry(&mut session).await);
    while rib_rx.try_recv().is_ok() {}
    deliver_held_rib_messages(&mut session).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(session.timers.hold.is_some(), "hold re-armed");
    // The queued KEEPALIVE, once read and processed, restores the budget.
    let mut input = [0_u8; 64];
    let read = session
        .read_half
        .as_ref()
        .unwrap()
        .try_read(&mut input)
        .unwrap();
    session.read_buf.buf.extend_from_slice(&input[..read]);
    session.process_read_buffer().await;
    assert_eq!(session.parked_hold_renewals, 0);
}

/// Waits that our own RIB-bound messages start (an RFC 9324 revalidation
/// chunk, a refresh timeout), not peer input, do not restore the budget: a
/// silent peer is closed at its second deadline however often such waits
/// end and restart.
/// Mutation-red: resetting the budget whenever a wait drains keeps the
/// silent peer up on the free first deferral of each new wait.
#[tokio::test]
async fn rib_park_local_waits_do_not_renew_a_silent_peer() {
    let RibPark {
        mut session,
        commands: _commands,
        mut rib_rx,
        server: _server,
        ..
    } = parked(&[]).await;
    let mut survived = 0;
    for _ in 0..10 {
        if !hold_expiry(&mut session).await {
            break;
        }
        survived += 1;
        // The RIB admits the held message: this wait ends.
        rib_rx.try_recv().unwrap();
        deliver_held_rib_messages(&mut session).await;
        assert!(session.rib_backlog.is_empty());
        // A locally generated batch finds the channel full: a new wait.
        session.send_to_rib(placeholder_routes_received()).unwrap();
        assert_eq!(session.rib_backlog.len(), 1);
    }
    assert_eq!(
        survived, 1,
        "a silent peer gets only the free first deferral since its last PDU"
    );
}

/// A live peer whose unprocessed input already fills the read buffer to the
/// probe cap (a large RFC 8654 read) still earns its second deferral: the
/// full buffer is its evidence, and nothing more is read.
/// Mutation-red: requiring newly read bytes at the cap closes it at the
/// second hold time.
#[tokio::test]
async fn rib_park_full_read_buffer_counts_for_the_second_deferral() {
    let behind = keepalive_pdu().repeat(8192 / 19 + 1);
    let RibPark {
        mut session,
        mut server,
        commands: _commands,
        rib_rx: _rib_rx,
        ..
    } = parked(&behind).await;
    session
        .read_buf
        .set_max_message_len(rustbgpd_wire::MAX_MESSAGE_LEN);
    let full = session.read_buf.buf.len();
    assert!(full >= 2 * usize::from(rustbgpd_wire::MAX_MESSAGE_LEN));
    assert!(hold_expiry(&mut session).await, "first deferral");
    peer_sends(&mut server, &mut session, &keepalive_pdu()).await;
    assert!(
        hold_expiry(&mut session).await,
        "a live peer still sending is not closed at the second hold time"
    );
    assert_eq!(
        session.read_buf.buf.len(),
        full,
        "nothing read past the cap"
    );
    assert!(
        !hold_expiry(&mut session).await,
        "the count cap still holds"
    );
}

/// Run a parked session with graceful restart negotiated until its stall
/// budget is spent; return the RIB message its teardown queued.
async fn exhausted_with_graceful_restart(notification_gr: bool) -> RibUpdate {
    let RibPark {
        mut session,
        commands: _commands,
        rib_rx: _rib_rx,
        server: _server,
        ..
    } = parked(&[]).await;
    session.config.peer.graceful_restart = true;
    let mut negotiated = (*session.negotiated.clone().unwrap()).clone();
    negotiated.peer_gr_capable = true;
    negotiated.peer_notification_gr = notification_gr;
    negotiated.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    session.negotiated = Some(Arc::new(negotiated));
    {
        let run = session.run();
        // Past the second deadline: 90 s deferred, 180 s spent.
        let steps = tokio::time::sleep(Duration::from_secs(182));
        tokio::select! {
            result = run => panic!("run() ended while parked: {result:?}"),
            () = steps => {}
        }
    }
    assert_ne!(session.fsm.state(), SessionState::Established);
    session
        .rib_backlog
        .pop_back()
        .expect("a teardown message")
        .0
}

/// RFC 8538: the stall budget's Cease is a NOTIFICATION, so a graceful
/// restart peer without the N bit has its routes purged, not retained.
/// Mutation-red: without the NOTIFICATION latch the teardown queues
/// `PeerGracefulRestart`.
#[tokio::test(start_paused = true)]
async fn rib_park_stall_cease_purges_without_notification_gr() {
    assert!(matches!(
        exhausted_with_graceful_restart(false).await,
        RibUpdate::PeerDown { .. }
    ));
}

/// RFC 8538: with Notification GR (the N bit) negotiated, the same Cease
/// keeps the graceful-restart retention.
#[tokio::test(start_paused = true)]
async fn rib_park_stall_cease_retains_with_notification_gr() {
    assert!(matches!(
        exhausted_with_graceful_restart(true).await,
        RibUpdate::PeerGracefulRestart { .. }
    ));
}

/// Repeated administrative resets while parked: the first closes the
/// Established session at once; its reconnect, and every later reset, wait
/// for the held messages, so the backlog stays at the held UPDATE plus one
/// `PeerDown` however many resets arrive.
/// Mutation-red: running a reset that has no Established session to close
/// restarts the session and appends a `PeerDown` per reset pair; polling the
/// reconnect timer while parked starts a new connection.
#[tokio::test(start_paused = true)]
async fn rib_park_repeated_resets_keep_the_backlog_bounded() {
    let RibPark {
        mut session,
        commands,
        mut rib_rx,
        mut server,
        ..
    } = rib_park().await;
    let (metrics, peer) = (session.metrics.clone(), session.peer_label.clone());
    let ceases = || {
        counter(
            &metrics,
            "bgp_notifications_sent_total",
            &[("peer", &peer), ("code", "6")],
        )
    };
    {
        let run = session.run();
        let steps = async {
            server.write_all(&encoded_announce(held())).await.unwrap();
            until_parked(&metrics, &peer).await;
            commands
                .send(PeerCommand::AdministrativeReset { reason: None })
                .await
                .unwrap();
            for _ in 0..1_000_000 {
                if ceases() >= 1.0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert_eq!(ceases(), 1.0, "the first reset must close at once");
            for _ in 0..4 {
                commands
                    .send(PeerCommand::AdministrativeReset { reason: None })
                    .await
                    .unwrap();
            }
            // Well past any reconnect delay.
            tokio::time::sleep(Duration::from_secs(600)).await;
        };
        tokio::select! {
            result = run => panic!("run() ended while parked: {result:?}"),
            () = steps => {}
        }
    }
    assert_eq!(
        session.rib_backlog.len(),
        2,
        "the held UPDATE and one PeerDown, whatever the reset count"
    );
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(matches!(
        session.deferred_command,
        Some(PeerCommand::AdministrativeReset { .. })
    ));
    // Every retained command still runs, in order, once the RIB drains: a
    // Stop queued after the resets wins, and a later query sees it applied.
    commands
        .send(PeerCommand::Stop { reason: None })
        .await
        .unwrap();
    let (reply, response) = oneshot::channel();
    commands
        .send(PeerCommand::QueryState { reply })
        .await
        .unwrap();
    let state = {
        let run = session.run();
        let steps = async {
            let mut response = std::pin::pin!(response);
            let mut seen = Vec::new();
            loop {
                tokio::select! {
                    update = rib_rx.recv() => seen.push(update.unwrap()),
                    state = &mut response => {
                        // The reply can win the select while admitted
                        // messages still wait in the channel.
                        while let Ok(update) = rib_rx.try_recv() {
                            seen.push(update);
                        }
                        let first_down = seen
                            .iter()
                            .position(|update| matches!(update, RibUpdate::PeerDown { .. }))
                            .expect("the reset's PeerDown is delivered");
                        assert!(
                            seen[..first_down]
                                .iter()
                                .any(|update| announced_v4(update) == [Prefix::V4(held())]),
                            "the held UPDATE precedes the first PeerDown"
                        );
                        return state.unwrap();
                    }
                }
            }
        };
        tokio::select! {
            result = run => panic!("run() ended: {result:?}"),
            state = steps => state,
        }
    };
    assert_eq!(state.fsm_state, SessionState::Idle);
    assert!(session.stop_requested, "the Stop after the resets applied");
    assert!(session.reconnect_timer.is_none());
}

/// An operator shutdown while parked puts the Cease on the wire at once.
/// The RIB then sees the held UPDATE before the session's `PeerDown`, and
/// `run()` returns only after both were admitted.
/// Mutation-red: with the command arm unpolled while parked, the Cease waits
/// for the RIB to drain.
#[tokio::test]
async fn rib_park_shutdown_sends_cease_then_delivers_in_order() {
    let RibPark {
        mut session,
        commands,
        mut rib_rx,
        mut server,
        fillers,
        ..
    } = rib_park().await;
    let (metrics, peer) = (session.metrics.clone(), session.peer_label.clone());
    let mut run = std::pin::pin!(session.run());
    let steps = async {
        server.write_all(&encoded_announce(held())).await.unwrap();
        until_parked(&metrics, &peer).await;
        commands.send(PeerCommand::Shutdown).await.unwrap();
        let frame = next_frame_after_handshake(&mut server).await;
        let Some(Message::Notification(cease)) = frame else {
            panic!("a parked session must send the Cease promptly, got {frame:?}");
        };
        assert_eq!(cease.code, NotificationCode::Cease);
        assert_eq!(cease.subcode, cease_subcode::ADMINISTRATIVE_SHUTDOWN);
    };
    tokio::select! {
        result = &mut run => panic!("run() ended before the RIB drained: {result:?}"),
        () = steps => {}
    }
    // Fillers, then the session's own messages up to its `PeerDown`.
    let drain = async {
        let mut announced = Vec::new();
        for _ in 0..fillers {
            assert_eq!(announced_v4(&rib_rx.recv().await.unwrap()), []);
        }
        loop {
            let update = rib_rx.recv().await.unwrap();
            if matches!(update, RibUpdate::PeerDown { .. }) {
                return announced;
            }
            announced.extend(announced_v4(&update));
        }
    };
    // Bounded: the test owns the session, so its RIB sender never closes and
    // a missing flush would otherwise hang instead of failing.
    let (result, announced) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(run, drain) })
            .await
            .expect("run() must deliver the held UPDATE and PeerDown, then return");
    result.unwrap();
    assert_eq!(
        announced,
        vec![Prefix::V4(held())],
        "the held UPDATE must precede PeerDown"
    );
}

/// While parked the session processes no further buffered PDU and reads
/// nothing more from TCP: `later`, read together with `held`, stays in the
/// read buffer and `unread` stays in the kernel socket.
/// Mutation-red: processing the rest of the buffer consumes `later`; reading
/// TCP while parked pulls `unread` into the buffer.
#[tokio::test]
async fn rib_park_leaves_further_input_unread() {
    let RibPark {
        mut session,
        commands: _commands,
        rib_rx: _rib_rx,
        mut server,
        ..
    } = rib_park().await;
    let later_pdu = encoded_announce(later());
    let unread_pdu = encoded_announce(unread());
    park_with_buffered(&mut session, &later_pdu).await;
    // The socket is readable before the run loop is polled, and nothing else
    // is ready: one poll lets a wrongly enabled read arm run, and a correct
    // loop returns Pending without touching the socket.
    peer_sends(&mut server, &mut session, &unread_pdu).await;
    {
        let mut run = std::pin::pin!(session.run());
        let polled = std::future::poll_fn(|cx| std::task::Poll::Ready(run.as_mut().poll(cx))).await;
        assert!(polled.is_pending(), "a parked session must stay idle");
    }
    assert_eq!(
        &session.read_buf.buf[..],
        &later_pdu[..],
        "the PDU behind the held one must stay buffered, unprocessed"
    );
    let mut socket = vec![0_u8; unread_pdu.len() + 1];
    let read = session
        .read_half
        .as_ref()
        .unwrap()
        .try_read(&mut socket)
        .unwrap();
    assert_eq!(
        &socket[..read],
        &unread_pdu[..],
        "TCP input must stay unread"
    );
}

/// Once the RIB drains, the held UPDATE is delivered first, and the PDU that
/// waited behind it in the read buffer follows without any further socket
/// input to wake the session.
/// Mutation-red: not resuming the buffered input when the backlog empties
/// leaves `later` unprocessed until the peer happens to send again.
#[tokio::test]
async fn rib_park_delivers_the_held_update_first() {
    let RibPark {
        mut session,
        commands: _commands,
        mut rib_rx,
        server: _server,
        fillers,
        ..
    } = rib_park().await;
    park_with_buffered(&mut session, &encoded_announce(later())).await;
    let run = session.run();
    let steps = async {
        for _ in 0..fillers {
            assert_eq!(announced_v4(&rib_rx.recv().await.unwrap()), []);
        }
        for expected in [held(), later()] {
            let update = tokio::time::timeout(Duration::from_secs(5), rib_rx.recv())
                .await
                .expect("the parked input must resume once the RIB drains")
                .unwrap();
            assert_eq!(announced_v4(&update), vec![Prefix::V4(expected)]);
        }
    };
    tokio::select! {
        result = run => panic!("run() ended: {result:?}"),
        () = steps => {}
    }
}

/// A Shutdown that an owned wait (the shared-group encode's command poll)
/// moved into `deferred_command` while the session is parked runs at once,
/// like one taken by the command arm.
/// Mutation-red: running deferred commands only once the backlog is empty
/// keeps the Cease waiting for the RIB.
#[tokio::test]
async fn rib_park_runs_a_deferred_shutdown() {
    let RibPark {
        mut session,
        commands: _commands,
        rib_rx: _rib_rx,
        mut server,
        ..
    } = rib_park().await;
    session
        .read_buf
        .buf
        .extend_from_slice(&encoded_announce(held()));
    session.process_read_buffer().await;
    assert_eq!(session.rib_backlog.len(), 1, "the UPDATE must be held");
    session.deferred_command = Some(PeerCommand::Shutdown);
    let run = session.run();
    let steps = async {
        let frame = next_frame_after_handshake(&mut server).await;
        let Some(Message::Notification(cease)) = frame else {
            panic!("a deferred Shutdown must still run while parked, got {frame:?}");
        };
        assert_eq!(cease.code, NotificationCode::Cease);
    };
    tokio::select! {
        result = run => panic!("run() ended: {result:?}"),
        () = steps => {}
    }
}

/// While parked, an envelope larger than the writer queue still reaches the
/// writer in full: the pending-envelope arm resumes it each time the writer
/// frees a slot.
/// Mutation-red: not polling that continuation while parked leaves the rest
/// of the envelope, and its End-of-RIB, unsent until the RIB drains.
#[tokio::test]
async fn rib_park_continues_a_multi_slice_envelope() {
    const ROUTES: u32 = 200;
    let RibPark {
        mut session,
        commands: _commands,
        rib_rx: _rib_rx,
        server: _server,
        outbound,
        ..
    } = rib_park().await;
    // A one-slot writer queue the test drains by hand.
    session.writer_join.take().unwrap().abort();
    let (bulk, mut frames) = mpsc::channel(1);
    session.writer_bulk_tx = Some(bulk);
    park_with_buffered(&mut session, &[]).await;
    // A distinct MED per route: one frame each.
    let routes: Vec<Route> = (0..ROUTES)
        .map(|index| {
            let mut route = make_route(100);
            route.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::from((20 << 24) | index), 32));
            AttrSet::edit(&mut route.attributes, |attrs| {
                attrs.push(PathAttribute::Med(index));
            });
            route
        })
        .collect();
    outbound
        .try_send(OutboundRouteUpdate {
            exact_export_snapshot: Some(session.publish_export_profile()),
            announce: routes.into(),
            end_of_rib: vec![(Afi::Ipv4, Safi::Unicast)],
            ..OutboundRouteUpdate::default()
        })
        .unwrap();
    {
        let run = session.run();
        let steps = async {
            let mut announced = 0;
            loop {
                let mut frame = tokio::time::timeout(Duration::from_secs(5), frames.recv())
                    .await
                    .expect("a parked session must keep feeding its writer")
                    .unwrap();
                let Message::Update(update) =
                    rustbgpd_wire::decode_message(&mut frame, rustbgpd_wire::MAX_MESSAGE_LEN)
                        .unwrap()
                else {
                    panic!("expected UPDATE frames");
                };
                let parsed = update.parse(true, false, &[]).unwrap();
                if parsed.announced.is_empty() && parsed.withdrawn.is_empty() {
                    break;
                }
                announced += parsed.announced.len();
            }
            assert_eq!(announced, ROUTES as usize, "every route before End-of-RIB");
        };
        tokio::select! {
            result = run => panic!("run() ended while parked: {result:?}"),
            () = steps => {}
        }
    }
    assert_eq!(session.rib_backlog.len(), 1, "still parked throughout");
}

/// Deliver the fillers, then check the held UPDATE reaches the RIB before
/// the teardown's `PeerDown`.
async fn assert_held_then_peer_down(
    session: &mut PeerSession,
    rib_rx: &mut mpsc::Receiver<RibUpdate>,
    fillers: usize,
) {
    assert!(
        matches!(
            session.rib_backlog.back(),
            Some((RibUpdate::PeerDown { .. }, _))
        ),
        "the teardown's PeerDown waits behind the held UPDATE"
    );
    for _ in 0..fillers {
        assert_eq!(announced_v4(&rib_rx.try_recv().unwrap()), []);
    }
    deliver_held_rib_messages(session).await;
    assert_eq!(
        announced_v4(&rib_rx.try_recv().unwrap()),
        vec![Prefix::V4(held())]
    );
    assert!(matches!(
        rib_rx.try_recv().unwrap(),
        RibUpdate::PeerDown { .. }
    ));
}

/// A writer that exits while the session is parked tears the session down
/// before the RIB is released; its `PeerDown` follows the held UPDATE.
/// Mutation-red: with the writer-exit arm unpolled while parked, the session
/// stays Established on a dead writer.
#[tokio::test(start_paused = true)]
async fn rib_park_observes_writer_exit() {
    let RibPark {
        mut session,
        commands: _commands,
        mut rib_rx,
        server: _server,
        fillers,
        ..
    } = parked(&[]).await;
    session.timers.hold = None;
    session.writer_join.as_ref().unwrap().abort();
    {
        let run = session.run();
        let steps = tokio::time::sleep(Duration::from_secs(1));
        tokio::select! {
            result = run => panic!("run() ended while parked: {result:?}"),
            () = steps => {}
        }
    }
    assert_ne!(session.fsm.state(), SessionState::Established);
    assert_held_then_peer_down(&mut session, &mut rib_rx, fillers).await;
}

/// An envelope that waits on a full writer while the session is parked hits
/// the admission deadline: Cease/Out of Resources and a teardown before the
/// RIB is released, then the `PeerDown` behind the held UPDATE.
/// Mutation-red: with the admission timer unpolled while parked, the session
/// stays Established behind its full writer.
#[tokio::test(start_paused = true)]
async fn rib_park_expires_writer_admission() {
    let RibPark {
        mut session,
        commands: _commands,
        mut rib_rx,
        server: _server,
        outbound,
        fillers,
        ..
    } = parked(&[]).await;
    let (metrics, peer) = (session.metrics.clone(), session.peer_label.clone());
    session.timers.hold = None;
    // A writer queue that never frees a slot; the real writer stays up to
    // carry the Cease and exit.
    let (bulk, _held_frames) = mpsc::channel(1);
    bulk.try_send(Bytes::from_static(b"held")).unwrap();
    session.writer_bulk_tx = Some(bulk);
    let mut route = make_route(100);
    route.prefix = Prefix::V4(exported());
    outbound
        .try_send(OutboundRouteUpdate {
            exact_export_snapshot: Some(session.publish_export_profile()),
            announce: vec![route].into(),
            ..OutboundRouteUpdate::default()
        })
        .unwrap();
    {
        let run = session.run();
        // Past the 480 s admission deadline (RFC 9687's default send hold).
        let steps = tokio::time::sleep(Duration::from_secs(500));
        tokio::select! {
            result = run => panic!("run() ended while parked: {result:?}"),
            () = steps => {}
        }
    }
    assert_eq!(cease_out_of_resources(&metrics, &peer), 1.0);
    assert_ne!(session.fsm.state(), SessionState::Established);
    assert_held_then_peer_down(&mut session, &mut rib_rx, fillers).await;
}
