//! An administrative reset (`rbgp neighbor reset`) never leaves the peer's
//! routes retained under Graceful Restart or Long-Lived Graceful Restart,
//! whatever the session's state when the reset arrives, N bit or not. Other
//! teardowns keep their retention. A real `RibManager` answers what stays
//! retained; the clock is paused, so no restart or stale timer runs out.
use super::abort_handoff::{GatedRib, established, first, receive, tcp_fails};
use super::run_loop::negotiate_graceful_restart;
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Retention {
    Gr,
    Llgr,
}

/// Make the Established `session`'s end retain its routes: Graceful Restart
/// with a restart time the paused clock never reaches, or LLGR only (RFC
/// 9494 §4.2: no GR family, one LLGR family).
fn retain(session: &mut PeerSession, retention: Retention, notification_gr: bool) {
    negotiate_graceful_restart(session, notification_gr);
    let mut negotiated = (*session.negotiated.clone().unwrap()).clone();
    negotiated.peer_restart_time = 120;
    if retention == Retention::Llgr {
        negotiated.peer_gr_families.clear();
        negotiated.peer_llgr_capable = true;
        negotiated.peer_llgr_families = vec![rustbgpd_wire::LlgrFamily {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
            forwarding_preserved: false,
            stale_time: 3600,
        }];
        session.config.llgr_stale_time = 3600;
    }
    session.negotiated = Some(Arc::new(negotiated));
}

/// One Established session holding one received route in a real RIB.
async fn session_with_one_route(
    retention: Retention,
    notification_gr: bool,
) -> (GatedRib, PeerSession, TcpStream) {
    let mut rib = GatedRib::spawn();
    let (mut session, _commands, peer) = established(&rib, 1).await;
    retain(&mut session, retention, notification_gr);
    receive(&mut session, first());
    session.process_read_buffer().await;
    rib.release().await;
    assert_eq!(rib.loc_rib_count().await, 1, "the route is installed");
    (rib, session, peer)
}

/// Queue a route-bearing envelope without its export snapshot: the close
/// drain raises Cease/8 on it.
async fn queue_unadmittable_update(session: &PeerSession) {
    session
        .outbound_tx
        .send(OutboundRouteUpdate {
            announce: vec![make_route(100)].into(),
            next_hop_override: vec![None].into(),
            ..OutboundRouteUpdate::default()
        })
        .await
        .unwrap();
}

/// The reset's close drain raises Cease/8. With the N bit a plain Cease/8 is
/// a graceful NOTIFICATION that both sides must answer with retention (RFC
/// 8538 §4), so the reset sends it as a Hard Reset carrying the Cease/8
/// (§3.1): the session ends with `PeerDown` and the route is gone. Without
/// the N bit the plain Cease/8 already purges (RFC 4724 §4).
/// Mutation-red: without the Hard Reset, the N-bit case sends a plain 6/8,
/// queues `PeerGracefulRestart`, and keeps the route as stale.
#[tokio::test(start_paused = true)]
async fn a_reset_whose_close_drain_raises_cease_8_never_retains() {
    let mut got = Vec::new();
    for notification_gr in [false, true] {
        let (mut rib, mut session, mut peer) =
            session_with_one_route(Retention::Gr, notification_gr).await;
        let rib_peer = session.rib_peer();
        let (event_tx, mut events) = mpsc::channel(8);
        session.session_event_tx = Some(event_tx);
        queue_unadmittable_update(&session).await;

        let _ = session
            .handle_command(PeerCommand::AdministrativeReset { reason: None })
            .await;
        rib.release().await;

        let wire = read_until_notification(&mut peer).await;
        let event = events.try_recv().expect("the sent NOTIFICATION event");
        got.push((
            notification_gr,
            wire.subcode,
            wire.data.to_vec(),
            rib.ends.clone(),
            rib.retained_stale(rib_peer).await,
            rib.loc_rib_count().await,
            session.config.neighbor_counters.notifications_sent(),
            event.subcode,
            event.failure_cause,
        ));
    }
    let cause = Some(crate::handle::SessionFailureCause::ExportSnapshotMissing);
    assert_eq!(
        got,
        vec![
            (
                false,
                cease_subcode::OUT_OF_RESOURCES,
                vec![],
                vec![("PeerDown", 1)],
                0,
                0,
                1,
                cease_subcode::OUT_OF_RESOURCES,
                cause,
            ),
            (
                true,
                cease_subcode::HARD_RESET,
                vec![
                    NotificationCode::Cease.as_u8(),
                    cease_subcode::OUT_OF_RESOURCES
                ],
                vec![("PeerDown", 1)],
                0,
                0,
                1,
                cease_subcode::HARD_RESET,
                cause,
            ),
        ],
        "(N bit, wire subcode, wire data, session ends, routes retained as stale, \
         Loc-RIB routes, NOTIFICATIONs sent, event subcode, event failure cause)"
    );
}

/// Move a session that is Idle after a retaining close into `state`.
/// Returns the peer end of any replacement connection, to keep it open.
async fn enter(session: &mut PeerSession, state: SessionState) -> Option<TcpStream> {
    if state == SessionState::Idle {
        return None;
    }
    if matches!(state, SessionState::Connect | SessionState::Active) {
        // No connection installed: the dial is outstanding, or failed.
        session.drive_fsm(Event::ManualStart).await;
        if state == SessionState::Active {
            session.drive_fsm(Event::TcpConnectionFails).await;
        }
        return None;
    }
    let (client, server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    if state == SessionState::OpenConfirm {
        session
            .drive_fsm(Event::OpenReceived(rustbgpd_wire::OpenMessage {
                version: 4,
                my_as: 65002,
                hold_time: 90,
                bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
                capabilities: vec![
                    Capability::MultiProtocol {
                        afi: Afi::Ipv4,
                        safi: Safi::Unicast,
                    },
                    Capability::FourOctetAs { asn: 65002 },
                ],
            }))
            .await;
    }
    Some(server)
}

/// A session lost to a TCP failure leaves its routes retained (GR or LLGR).
/// A reset that reaches the session afterwards, in Idle or while it
/// reconnects, purges them and still brings the session back: from Idle it
/// starts a connection, from the other states it returns to Idle with the
/// reconnect timer armed.
/// Mutation-red: without the purge in the Idle reset, the Idle cases keep
/// the route as stale.
#[tokio::test(start_paused = true)]
async fn a_reset_in_any_state_purges_routes_retained_by_an_earlier_close() {
    let mut got = Vec::new();
    let mut want = Vec::new();
    for retention in [Retention::Gr, Retention::Llgr] {
        for state in [
            SessionState::Idle,
            SessionState::Connect,
            SessionState::Active,
            SessionState::OpenSent,
            SessionState::OpenConfirm,
        ] {
            let (mut rib, mut session, _peer) = session_with_one_route(retention, false).await;
            let rib_peer = session.rib_peer();
            tcp_fails(&mut session).await;
            rib.release().await;
            assert_eq!(
                rib.retained_stale(rib_peer).await,
                1,
                "{retention:?}: the TCP loss retains the route"
            );
            let _replacement = enter(&mut session, state).await;
            assert_eq!(session.fsm.state(), state);

            let _ = session
                .handle_command(PeerCommand::AdministrativeReset { reason: None })
                .await;
            rib.release().await;

            got.push((
                retention,
                state,
                rib.retained_stale(rib_peer).await,
                rib.loc_rib_count().await,
                session.fsm.state(),
                session.reconnect_timer.is_some(),
            ));
            let (after, timer) = if state == SessionState::Idle {
                (SessionState::Connect, false)
            } else {
                (SessionState::Idle, true)
            };
            want.push((retention, state, 0, 0, after, timer));
        }
    }
    assert_eq!(
        got, want,
        "(retention, state at reset, routes retained as stale, Loc-RIB routes, \
         state after, reconnect timer armed)"
    );
}

/// Guard: every teardown that is not an administrative reset keeps its
/// retention under the N bit: a TCP loss, a hold-timer expiry, a graceful
/// NOTIFICATION from the peer, and a local Cease/8 raised by the close drain
/// of an administrative stop.
#[tokio::test(start_paused = true)]
async fn other_teardowns_still_retain_under_notification_gr() {
    let mut got = Vec::new();
    for cause in ["tcp loss", "hold timer", "peer notification", "stop drain"] {
        let (mut rib, mut session, _peer) = session_with_one_route(Retention::Gr, true).await;
        let rib_peer = session.rib_peer();
        match cause {
            "tcp loss" => tcp_fails(&mut session).await,
            "hold timer" => session.drive_fsm(Event::HoldTimerExpires).await,
            "peer notification" => {
                session
                    .drive_fsm(Event::NotificationReceived(NotificationMessage::new(
                        NotificationCode::Cease,
                        cease_subcode::OUT_OF_RESOURCES,
                        Bytes::new(),
                    )))
                    .await;
            }
            _ => {
                queue_unadmittable_update(&session).await;
                let _ = session
                    .handle_command(PeerCommand::Stop { reason: None })
                    .await;
            }
        }
        rib.release().await;
        got.push((cause, rib.ends.clone(), rib.retained_stale(rib_peer).await));
    }
    assert_eq!(
        got,
        ["tcp loss", "hold timer", "peer notification", "stop drain"]
            .map(|cause| (cause, vec![("PeerGracefulRestart", 1)], 1))
            .to_vec(),
        "(cause, session ends, routes retained as stale)"
    );
}
