//! A session stops reading and processing peer input while the routes it
//! has sent to the RIB and that are not yet finished there reach its ingest
//! budget, and resumes, in stream order, once the RIB returns enough of
//! them. The tests stand in for the RIB: a route message is finished when
//! the test drops it.
//!
//! Tests that drive `run()` use real time for the reasons given in
//! `rib_park.rs`; every wait in them is a handshake on observable state.
use super::rib_park::counter;
use super::*;
use rustbgpd_rib::ingest_budget::{INGEST_BUDGET_ROUTES, INGEST_RESUME_ROUTES, IngestBudget};

/// Routes per burst UPDATE: one leaves the gate open, two close it, and one
/// still unfinished keeps it closed.
const BLOCK: usize = 600;
const _: () = assert!(BLOCK < INGEST_BUDGET_ROUTES && 2 * BLOCK >= INGEST_BUDGET_ROUTES);
const _: () = assert!(BLOCK > INGEST_RESUME_ROUTES);

struct Metered {
    session: PeerSession,
    commands: mpsc::Sender<PeerCommand>,
    rib_rx: mpsc::Receiver<RibUpdate>,
    server: TcpStream,
    budget: Arc<IngestBudget>,
}

/// An Established session that charges its route messages to a budget, as
/// every session outside the unit-test constructors does.
async fn metered_session() -> Metered {
    let (mut session, commands, mut rib_rx) = make_test_session_with_channels(65001, 65002, 64);
    let (client, server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib_rx.try_recv().is_ok() {}
    let budget = IngestBudget::new();
    session.ingest_budget = Some(Arc::clone(&budget));
    Metered {
        session,
        commands,
        rib_rx,
        server,
        budget,
    }
}

/// The `index`th prefix of `block`, `len` bits long.
fn block_prefix(block: u8, index: usize, len: u8) -> Ipv4Prefix {
    let index = u32::try_from(index).unwrap();
    let address = (u32::from(block) << 24) + (index << (32 - u32::from(len)));
    Ipv4Prefix::new(Ipv4Addr::from(address), len)
}

/// One encoded UPDATE announcing `count` prefixes of `block`.
fn block_pdu(block: u8, count: usize, len: u8) -> Vec<u8> {
    let entries: Vec<_> = (0..count)
        .map(|index| Ipv4NlriEntry {
            path_id: 0,
            prefix: block_prefix(block, index, len),
        })
        .collect();
    let update = UpdateMessage::build(
        &entries,
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
        Ipv4UnicastMode::Body,
    );
    rustbgpd_wire::encode_message(&Message::Update(update))
        .unwrap()
        .to_vec()
}

fn burst_pdu(block: u8) -> Vec<u8> {
    block_pdu(block, BLOCK, 24)
}

/// The block and route count of a session's route message, or `None` for
/// anything else (the other source's placeholder among them).
fn burst_block(update: &RibUpdate) -> Option<(u8, usize)> {
    let RibUpdate::SessionRoutes { routes, .. } = update else {
        return None;
    };
    let RibUpdate::RoutesReceived { announced, .. } = routes.as_ref() else {
        return None;
    };
    let Prefix::V4(first) = announced.first()?.prefix else {
        return None;
    };
    Some((first.addr.octets()[0], announced.len()))
}

async fn buffer_and_process(session: &mut PeerSession, pdus: &[Vec<u8>]) {
    for pdu in pdus {
        session.read_buf.buf.extend_from_slice(pdu);
    }
    session.process_read_buffer().await;
}

/// With the budget spent the session processes no further buffered PDU. The
/// gate stays closed above the resume mark, and the next PDU processed is
/// the next in the stream.
/// Red proof: without the gate in `process_read_buffer` the third UPDATE is
/// delivered at once.
#[tokio::test]
async fn spent_budget_holds_buffered_input_and_resumes_in_stream_order() {
    let Metered {
        mut session,
        mut rib_rx,
        budget,
        commands: _commands,
        server: _server,
    } = metered_session().await;
    let third = block_pdu(30, 1, 24);
    buffer_and_process(&mut session, &[burst_pdu(10), burst_pdu(20), third.clone()]).await;
    assert_eq!(budget.unfinished(), 2 * BLOCK);
    assert!(session.ingest_gate_closed);
    assert_eq!(&session.read_buf.buf[..], &third[..], "the third waits");
    let first = rib_rx.try_recv().unwrap();
    let second = rib_rx.try_recv().unwrap();
    assert_eq!(burst_block(&first), Some((10, BLOCK)));
    assert_eq!(burst_block(&second), Some((20, BLOCK)));
    assert!(rib_rx.try_recv().is_err());

    drop(first);
    session.reopen_ingest_gate().await;
    assert!(
        rib_rx.try_recv().is_err(),
        "{BLOCK} unfinished routes are above the resume mark"
    );
    drop(second);
    session.reopen_ingest_gate().await;
    assert_eq!(burst_block(&rib_rx.try_recv().unwrap()), Some((30, 1)));
    assert!(session.read_buf.buf.is_empty());
    assert!(!session.ingest_gate_closed);
}

/// The starvation regression, as a count: an unpaced burst source has at
/// most two messages in the RIB's queue, so another source's update is
/// dispatched after at most two of them, and the burst still arrives whole
/// and in order.
/// Red proof: without the gate all eight burst messages are queued ahead of
/// the other source's update.
#[tokio::test]
async fn unpaced_burst_leaves_at_most_two_messages_ahead_of_another_source() {
    const BURST: u8 = 8;
    let Metered {
        mut session,
        mut rib_rx,
        budget,
        commands: _commands,
        server: _server,
    } = metered_session().await;
    let burst: Vec<_> = (0..BURST).map(|block| burst_pdu(10 + block)).collect();
    // The peer wrote the whole burst before the RIB finished anything.
    buffer_and_process(&mut session, &burst).await;
    let ahead = rib_rx.len();
    // Another session's update enters the shared queue now.
    session
        .rib_tx
        .try_send(placeholder_routes_received())
        .unwrap();
    assert_eq!(ahead, 2, "burst messages ahead of the other source");

    let mut blocks = Vec::new();
    let mut other_after = None;
    let mut deepest = rib_rx.len();
    while let Ok(update) = rib_rx.try_recv() {
        match burst_block(&update) {
            Some((block, routes)) => {
                assert_eq!(routes, BLOCK);
                blocks.push(block);
            }
            None => other_after = Some(blocks.len()),
        }
        // The RIB finishes the message; the session reads on if it may.
        drop(update);
        session.reopen_ingest_gate().await;
        deepest = deepest.max(rib_rx.len());
    }
    assert_eq!(other_after, Some(2), "dispatched after two burst messages");
    assert_eq!(blocks, (10..10 + BURST).collect::<Vec<_>>(), "burst order");
    assert!(
        deepest <= 3,
        "queue depth {deepest}: two burst and the other"
    );
    assert_eq!(budget.unfinished(), 0);
    assert!(session.read_buf.buf.is_empty());
}

/// A message larger than the whole budget is admitted while the gate is
/// open, closes it, and reopens it when the RIB finishes it: input is never
/// held waiting for budget it could not get.
/// Red proof: a gate that admitted a message only when it fits the remaining
/// budget would never deliver this one.
#[tokio::test]
async fn message_larger_than_the_budget_is_admitted_and_reopens_the_gate() {
    let oversized = INGEST_BUDGET_ROUTES + 76;
    let Metered {
        mut session,
        mut rib_rx,
        budget,
        commands: _commands,
        server: _server,
    } = metered_session().await;
    buffer_and_process(
        &mut session,
        &[block_pdu(40, oversized, 16), block_pdu(30, 1, 24)],
    )
    .await;
    let big = rib_rx.try_recv().unwrap();
    assert_eq!(burst_block(&big), Some((40, oversized)));
    assert_eq!(budget.unfinished(), oversized);
    assert!(rib_rx.try_recv().is_err(), "the next UPDATE waits");
    drop(big);
    session.reopen_ingest_gate().await;
    assert_eq!(burst_block(&rib_rx.try_recv().unwrap()), Some((30, 1)));
}

/// Every route-bearing variant a session sends carries a permit, so no
/// family goes around the budget; other messages are sent as they are.
/// Red proof: wrapping only `RoutesReceived` leaves the typed families bare.
#[tokio::test]
async fn every_route_family_a_session_sends_is_charged() {
    let Metered {
        mut session,
        mut rib_rx,
        commands: _commands,
        server: _server,
        ..
    } = metered_session().await;
    let (peer, session_id) = (session.rib_peer(), session.session_identity.id);
    let route_messages = [
        placeholder_routes_received(),
        RibUpdate::BgpLsRoutesReceived {
            peer,
            session_id,
            announced: vec![],
            withdrawn: vec![],
        },
        RibUpdate::VpnRoutesReceived {
            peer,
            session_id,
            announced: vec![],
            withdrawn: vec![],
        },
        RibUpdate::LabeledRoutesReceived {
            peer,
            session_id,
            announced: vec![],
            withdrawn: vec![],
        },
        RibUpdate::RtcRoutesReceived {
            peer,
            session_id,
            announced: vec![],
            withdrawn: vec![],
        },
    ];
    for message in route_messages {
        session.deliver_routes_to_rib(message).unwrap();
        assert!(matches!(
            rib_rx.try_recv().unwrap(),
            RibUpdate::SessionRoutes { .. }
        ));
    }
    session
        .send_to_rib(RibUpdate::EndOfRib {
            peer,
            session_id,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .unwrap();
    assert!(matches!(
        rib_rx.try_recv().unwrap(),
        RibUpdate::EndOfRib { .. }
    ));
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

/// A peer whose KEEPALIVEs sit unread behind the gate is not expired by our
/// hold timer: the wait follows the bounded policy of a full RIB channel.
/// The first expiry is deferred for the wait, the second for the peer's
/// unread bytes, and only a third with still nothing processed closes the
/// session, as a local overload (Cease/Out of Resources), not as Hold Timer
/// Expired.
/// Red proof: without the gate in the hold expiry, the first expiry sends
/// Hold Timer Expired.
#[tokio::test]
async fn hold_expiry_behind_the_gate_follows_the_parked_policy() {
    let Metered {
        mut session,
        rib_rx: _rib_rx,
        mut server,
        commands: _commands,
        ..
    } = metered_session().await;
    let (metrics, peer) = (session.metrics.clone(), session.peer_label.clone());
    let notifications = |code: &str| {
        counter(
            &metrics,
            "bgp_notifications_sent_total",
            &[("peer", &peer), ("code", code)],
        )
    };
    buffer_and_process(&mut session, &[burst_pdu(10), burst_pdu(20)]).await;
    assert!(session.ingest_gate_closed);
    assert!(session.rib_backlog.is_empty(), "the RIB channel has room");

    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive)
        .unwrap()
        .to_vec();
    peer_sends(&mut server, &mut session, &keepalive).await;
    assert!(hold_expiry(&mut session).await, "the wait itself earns one");
    assert!(
        hold_expiry(&mut session).await,
        "unread peer bytes earn one"
    );
    assert_eq!(notifications("4"), 0.0, "never Hold Timer Expired");
    assert_eq!(notifications("6"), 0.0);
    assert_eq!(
        counter(
            &metrics,
            "bgp_hold_timer_rearmed_pending_input_total",
            &[("peer", &peer)],
        ),
        2.0
    );
    assert!(
        !hold_expiry(&mut session).await,
        "three hold times with nothing processed close the session"
    );
    assert_eq!(notifications("6"), 1.0, "Cease/Out of Resources");
    assert_eq!(notifications("4"), 0.0);
}

/// Once the RIB returns the budget, the unread KEEPALIVE is processed and
/// the deferral budget is whole again.
/// Red proof: without the reset on a processed PDU the count stays at one.
#[tokio::test]
async fn processed_input_after_the_gate_reopens_restores_the_hold_budget() {
    let Metered {
        mut session,
        mut rib_rx,
        commands: _commands,
        server: _server,
        ..
    } = metered_session().await;
    let keepalive = rustbgpd_wire::encode_message(&Message::Keepalive)
        .unwrap()
        .to_vec();
    buffer_and_process(&mut session, &[burst_pdu(10), burst_pdu(20), keepalive]).await;
    assert!(hold_expiry(&mut session).await);
    assert_eq!(session.parked_hold_renewals, 1);
    assert!(session.timers.hold.is_some(), "the hold timer is re-armed");
    while rib_rx.try_recv().is_ok() {}
    session.reopen_ingest_gate().await;
    assert!(
        session.read_buf.buf.is_empty(),
        "the KEEPALIVE is processed"
    );
    assert_eq!(session.parked_hold_renewals, 0);
    assert_eq!(session.fsm.state(), SessionState::Established);
}

/// The routes of an ended connection keep their permits on the old budget:
/// they do not pace the next connection of the same neighbor.
/// Red proof: with one budget for the session's lifetime the gate is still
/// closed after the session end.
#[tokio::test]
async fn session_end_starts_a_fresh_budget() {
    let Metered {
        mut session,
        mut rib_rx,
        budget,
        commands: _commands,
        server: _server,
    } = metered_session().await;
    buffer_and_process(&mut session, &[burst_pdu(10), burst_pdu(20)]).await;
    assert!(session.ingest_gate_closed);
    session.drive_fsm(Event::ManualStop { reason: None }).await;
    assert_eq!(budget.unfinished(), 2 * BLOCK, "the RIB still holds both");
    // The run loop's next turn sees the fresh budget.
    session.reopen_ingest_gate().await;
    assert!(!session.ingest_gate_closed);
    let mut last = None;
    while let Ok(update) = rib_rx.try_recv() {
        last = Some(update);
    }
    assert!(
        matches!(last, Some(RibUpdate::PeerDown { .. })),
        "the session end is sent without waiting for budget"
    );
    assert_eq!(budget.unfinished(), 0);
}

/// Handshake: `budget` holds at least `routes`. Bounded spin, so a session
/// that never reads fails instead of hanging.
async fn until_unfinished(budget: &IngestBudget, routes: usize) {
    for _ in 0..1_000_000 {
        if budget.unfinished() >= routes {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("the session never sent {routes} routes");
}

/// Handshake: the run loop has gone around its `select!` once more.
async fn run_loop_turn(commands: &mpsc::Sender<PeerCommand>) {
    let (reply, response) = oneshot::channel();
    commands
        .send(PeerCommand::QueryState { reply })
        .await
        .unwrap();
    response.await.unwrap();
}

/// Through the run loop and a real socket: behind a closed gate the socket
/// stays unread, so the kernel receive window paces the peer, while the loop
/// keeps answering commands; when the RIB returns the budget the loop is
/// woken and reads on.
/// Red proof: a read arm that ignores the gate pulls the third UPDATE into
/// the read buffer; without the wake-up arm the third UPDATE never arrives.
#[tokio::test]
async fn run_loop_leaves_the_socket_unread_behind_the_gate_and_wakes_on_budget() {
    let Metered {
        mut session,
        mut rib_rx,
        mut server,
        commands,
        budget,
    } = metered_session().await;
    let bounded = Duration::from_secs(10);
    let held = {
        let run = session.run();
        let steps = tokio::time::timeout(bounded, async {
            server.write_all(&burst_pdu(10)).await.unwrap();
            server.write_all(&burst_pdu(20)).await.unwrap();
            until_unfinished(&budget, 2 * BLOCK).await;
            let held = [rib_rx.recv().await.unwrap(), rib_rx.recv().await.unwrap()];
            server.write_all(&block_pdu(30, 1, 24)).await.unwrap();
            // Each turn is a chance for an ungated read arm to win.
            for _ in 0..64 {
                run_loop_turn(&commands).await;
            }
            held
        });
        tokio::select! {
            result = run => panic!("run() ended behind the gate: {result:?}"),
            held = steps => held.expect("the gate closes within the bound"),
        }
    };
    assert!(
        session.read_buf.buf.is_empty(),
        "the third UPDATE stays in the socket"
    );
    assert!(rib_rx.try_recv().is_err());

    let run = session.run();
    let steps = tokio::time::timeout(bounded, async {
        // The loop is waiting with its read arm closed.
        run_loop_turn(&commands).await;
        drop(held);
        rib_rx.recv().await.unwrap()
    });
    let third = tokio::select! {
        result = run => panic!("run() ended behind the gate: {result:?}"),
        third = steps => third.expect("returned budget wakes the run loop"),
    };
    assert_eq!(burst_block(&third), Some((30, 1)));
}

/// The gate closes inside `process_read_buffer` with the stream's tail still
/// buffered, and the RIB returns the budget before the run loop next looks
/// at the gate. The peer sends nothing more; the buffered tail must still be
/// processed.
/// Red proof: a run loop that reopens the gate without processing the
/// buffer leaves the tail until the peer's next byte.
#[tokio::test]
async fn budget_returned_before_the_run_loop_looks_still_processes_the_buffered_tail() {
    let Metered {
        mut session,
        mut rib_rx,
        budget,
        commands: _commands,
        server: _server,
    } = metered_session().await;
    buffer_and_process(
        &mut session,
        &[burst_pdu(10), burst_pdu(20), block_pdu(30, 1, 24)],
    )
    .await;
    assert!(session.ingest_gate_closed, "the gate closed mid-buffer");
    assert!(
        session.read_buf.has_complete_frame(),
        "the tail is buffered"
    );
    // The RIB (another thread in production) finishes both messages now.
    drop(rib_rx.try_recv().unwrap());
    drop(rib_rx.try_recv().unwrap());
    assert_eq!(budget.unfinished(), 0);
    let run = session.run();
    let tail = tokio::time::timeout(Duration::from_secs(3), rib_rx.recv());
    let tail = tokio::select! {
        result = run => panic!("run() ended: {result:?}"),
        tail = tail => tail,
    };
    let tail = tail.expect("the buffered tail is processed once the budget returned");
    assert_eq!(burst_block(&tail.unwrap()), Some((30, 1)));
}

/// Boundary: the RIB's return lands exactly on the resume mark, with the
/// run loop already waiting behind the gate. The loop is woken, reopens the
/// gate and reads on.
/// Red proof: a wake-up only below the mark, or a gate that reopens only
/// below it, leaves the third UPDATE in the socket.
#[tokio::test]
async fn budget_returned_to_exactly_the_resume_mark_wakes_the_run_loop() {
    const _: () = assert!(2 * INGEST_RESUME_ROUTES >= INGEST_BUDGET_ROUTES);
    let Metered {
        mut session,
        mut rib_rx,
        mut server,
        commands,
        budget,
    } = metered_session().await;
    let run = session.run();
    let steps = tokio::time::timeout(Duration::from_secs(10), async {
        for block in [10, 20] {
            let pdu = block_pdu(block, INGEST_RESUME_ROUTES, 24);
            server.write_all(&pdu).await.unwrap();
        }
        until_unfinished(&budget, 2 * INGEST_RESUME_ROUTES).await;
        let first = rib_rx.recv().await.unwrap();
        let _second = rib_rx.recv().await.unwrap();
        server.write_all(&block_pdu(30, 1, 24)).await.unwrap();
        // The loop is waiting with its read arm closed.
        run_loop_turn(&commands).await;
        drop(first);
        assert_eq!(budget.unfinished(), INGEST_RESUME_ROUTES);
        rib_rx.recv().await.unwrap()
    });
    let third = tokio::select! {
        result = run => panic!("run() ended behind the gate: {result:?}"),
        third = steps => third.expect("a return to the resume mark wakes the run loop"),
    };
    assert_eq!(burst_block(&third), Some((30, 1)));
}
