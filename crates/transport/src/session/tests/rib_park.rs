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

/// KEEPALIVEs are writer-owned (ADR-0078) and keep flowing while parked. A
/// peer that then sends nothing for the negotiated 90 s hold time is expired
/// while the session is still parked: none of its input is pending.
/// Mutation-red: with the hold arm unpolled while parked, no Hold Timer
/// Expired NOTIFICATION is sent until the RIB drains.
#[tokio::test(start_paused = true)]
async fn rib_park_keeps_keepalives_and_expires_a_silent_peer() {
    let RibPark {
        mut session,
        commands: _commands,
        rib_rx: _rib_rx,
        mut server,
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
    let hold_expiries = || {
        counter(
            &metrics,
            "bgp_notifications_sent_total",
            &[("peer", &peer), ("code", "4")],
        )
    };
    let established = tokio::time::Instant::now();
    let before = keepalives();
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
        assert_eq!(hold_expiries(), 0.0, "the hold time has not elapsed yet");
        tokio::time::sleep_until(established + Duration::from_secs(91)).await;
        assert_eq!(
            hold_expiries(),
            1.0,
            "a parked session must still expire a silent peer"
        );
    };
    tokio::select! {
        result = run => panic!("run() ended while parked: {result:?}"),
        () = steps => {}
    }
}

/// ADR-0078 rule 3 while parked: the peer's input waiting behind the held
/// UPDATE proves it alive, so each hold expiry re-arms instead of tearing
/// down a session that only our RIB is holding up.
/// Mutation-red: expiring the hold timer whenever input is parked sends Hold
/// Timer Expired to a live peer.
#[tokio::test(start_paused = true)]
async fn rib_park_rearms_hold_on_pending_input() {
    let RibPark {
        mut session,
        commands: _commands,
        rib_rx: _rib_rx,
        mut server,
        ..
    } = rib_park().await;
    let (metrics, peer) = (session.metrics.clone(), session.peer_label.clone());
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
    let run = session.run();
    let steps = async {
        // One write: the KEEPALIVE lands in the read buffer behind `held`.
        let mut input = encoded_announce(held());
        input.extend_from_slice(&rustbgpd_wire::encode_message(&Message::Keepalive).unwrap());
        server.write_all(&input).await.unwrap();
        until_parked(&metrics, &peer).await;
        tokio::time::sleep_until(established + Duration::from_secs(200)).await;
        assert_eq!(hold_expiries(), 0.0, "a live peer must not be expired");
        assert_eq!(rearmed(), 2.0, "hold re-armed at 90 s and 180 s");
    };
    tokio::select! {
        result = run => panic!("run() ended while parked: {result:?}"),
        () = steps => {}
    }
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
    let (result, announced) = tokio::join!(run, drain);
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
    let (metrics, peer) = (session.metrics.clone(), session.peer_label.clone());
    let later_pdu = encoded_announce(later());
    let unread_pdu = encoded_announce(unread());
    {
        let run = session.run();
        let steps = async {
            let mut both = encoded_announce(held());
            both.extend_from_slice(&later_pdu);
            server.write_all(&both).await.unwrap();
            until_parked(&metrics, &peer).await;
            server.write_all(&unread_pdu).await.unwrap();
            // Proving an absence: give a session that wrongly reads its
            // socket ample time to do so.
            tokio::time::sleep(Duration::from_millis(200)).await;
        };
        tokio::select! {
            result = run => panic!("run() ended while parked: {result:?}"),
            () = steps => {}
        }
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
        mut server,
        fillers,
        ..
    } = rib_park().await;
    let (metrics, peer) = (session.metrics.clone(), session.peer_label.clone());
    let run = session.run();
    let steps = async {
        let mut both = encoded_announce(held());
        both.extend_from_slice(&encoded_announce(later()));
        server.write_all(&both).await.unwrap();
        until_parked(&metrics, &peer).await;
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
