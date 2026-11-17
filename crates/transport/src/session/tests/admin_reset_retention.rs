//! An administrative reset (`rbgp neighbor reset`) and a final stop (a
//! disable, a config `admin_down` or a deletion) never leave the peer's
//! routes retained under Graceful Restart or Long-Lived Graceful Restart,
//! whatever the session's state when they arrive, N bit or not. Other
//! teardowns keep their retention. A real `RibManager` answers what stays
//! retained; the clock is paused, so no restart or stale timer runs out.
use super::abort_handoff::{GatedRib, established, first, receive, tcp_fails};
use super::rib_park::counter;
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

/// The close drain of a reset or a final stop raises Cease/8. With the N bit
/// a plain Cease/8 is a graceful NOTIFICATION that both sides must answer
/// with retention (RFC 8538 §4), so it is sent as a Hard Reset carrying the
/// Cease/8 (§3.1): the session ends with `PeerDown` and the route is gone.
/// Without the N bit the plain Cease/8 already purges (RFC 4724 §4).
/// Mutation-red: without the Hard Reset, the N-bit case sends a plain 6/8,
/// queues `PeerGracefulRestart`, and keeps the route as stale.
#[tokio::test(start_paused = true)]
async fn a_reset_or_stop_whose_close_drain_raises_cease_8_never_retains() {
    let mut got = Vec::new();
    let mut want = Vec::new();
    let cause = Some(crate::handle::SessionFailureCause::ExportSnapshotMissing);
    for (command, notification_gr) in [
        ("reset", false),
        ("reset", true),
        ("stop", false),
        ("stop", true),
    ] {
        let (mut rib, mut session, mut peer) =
            session_with_one_route(Retention::Gr, notification_gr).await;
        let rib_peer = session.rib_peer();
        let (event_tx, mut events) = mpsc::channel(8);
        session.session_event_tx = Some(event_tx);
        queue_unadmittable_update(&session).await;

        let command_sent = if command == "reset" {
            PeerCommand::AdministrativeReset { reason: None }
        } else {
            PeerCommand::Stop { reason: None }
        };
        let _ = session.handle_command(command_sent).await;
        rib.release().await;

        let wire = read_until_notification(&mut peer).await;
        let event = events.try_recv().expect("the sent NOTIFICATION event");
        got.push((
            command,
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
        let (subcode, data) = if notification_gr {
            (
                cease_subcode::HARD_RESET,
                vec![
                    NotificationCode::Cease.as_u8(),
                    cease_subcode::OUT_OF_RESOURCES,
                ],
            )
        } else {
            (cease_subcode::OUT_OF_RESOURCES, vec![])
        };
        want.push((
            command,
            notification_gr,
            subcode,
            data,
            vec![("PeerDown", 1)],
            0,
            0,
            1,
            subcode,
            cause,
        ));
    }
    assert_eq!(
        got, want,
        "(command, N bit, wire subcode, wire data, session ends, routes retained as \
         stale, Loc-RIB routes, NOTIFICATIONs sent, event subcode, event failure cause)"
    );
}

/// A final stop (`rbgp neighbor disable`, a config `admin_down`, a deletion)
/// of a peer that negotiated the N bit ends the session for good on both
/// sides: Cease / Hard Reset wrapping the Administrative Shutdown and any RFC
/// 9003 communication (RFC 8538 §5.1, §5.2), then `PeerDown`, for GR and
/// LLGR. The event and the sent-NOTIFICATION metric report the outer
/// subcode. Without the N bit the plain Cease/2 is unchanged and already
/// purges (RFC 4724 §4).
/// Mutation-red: without the Hard Reset, the N-bit cases send a plain 6/2,
/// queue `PeerGracefulRestart`, and keep the route as stale.
#[tokio::test(start_paused = true)]
async fn a_final_stop_hard_resets_under_notification_gr() {
    let communication = rustbgpd_wire::notification::encode_shutdown_communication("maintenance");
    let mut got = Vec::new();
    let mut want = Vec::new();
    for retention in [Retention::Gr, Retention::Llgr] {
        for notification_gr in [true, false] {
            for reason in [None, Some(communication.clone())] {
                let (mut rib, mut session, mut peer) =
                    session_with_one_route(retention, notification_gr).await;
                let rib_peer = session.rib_peer();
                let (event_tx, mut events) = mpsc::channel(8);
                session.session_event_tx = Some(event_tx);

                let _ = session
                    .handle_command(PeerCommand::Stop {
                        reason: reason.clone(),
                    })
                    .await;
                rib.release().await;

                let wire = read_until_notification(&mut peer).await;
                let event = events.try_recv().expect("the sent NOTIFICATION event");
                let (metrics, label) = (session.metrics.clone(), session.peer_label.clone());
                let sent = |subcode: u8| {
                    counter(
                        &metrics,
                        "bgp_notifications_sent_total",
                        &[
                            ("peer", &label),
                            ("code", "6"),
                            ("subcode", &subcode.to_string()),
                        ],
                    )
                };
                got.push((
                    retention,
                    notification_gr,
                    reason.is_some(),
                    wire.subcode,
                    wire.data.to_vec(),
                    event.subcode,
                    event.shutdown_reason,
                    sent(wire.subcode),
                    rib.ends.clone(),
                    rib.retained_stale(rib_peer).await,
                    rib.loc_rib_count().await,
                ));
                let inner = reason.clone().unwrap_or_default().to_vec();
                let (subcode, data) = if notification_gr {
                    let mut data = vec![
                        NotificationCode::Cease.as_u8(),
                        cease_subcode::ADMINISTRATIVE_SHUTDOWN,
                    ];
                    data.extend_from_slice(&inner);
                    (cease_subcode::HARD_RESET, data)
                } else {
                    (cease_subcode::ADMINISTRATIVE_SHUTDOWN, inner)
                };
                want.push((
                    retention,
                    notification_gr,
                    reason.is_some(),
                    subcode,
                    data,
                    subcode,
                    reason.is_some().then(|| "maintenance".to_string()),
                    1.0,
                    vec![("PeerDown", 1)],
                    0,
                    0,
                ));
            }
        }
    }
    assert_eq!(
        got, want,
        "(retention, N bit, reason, wire subcode, wire data, event subcode, event \
         communication, sent metric at the wire subcode, session ends, routes retained \
         as stale, Loc-RIB routes)"
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
/// A reset or a final stop that reaches the session afterwards, in Idle or
/// while it reconnects, purges them. A reset still brings the session back:
/// from Idle it starts a connection, from the other states it returns to
/// Idle with the reconnect timer armed. A stop leaves it Idle.
/// Mutation-red: without the purge in the Idle reset, the Idle reset cases
/// keep the route as stale; without the stop's purge, every stop case does.
#[tokio::test(start_paused = true)]
async fn a_reset_or_stop_in_any_state_purges_routes_retained_by_an_earlier_close() {
    let mut got = Vec::new();
    let mut want = Vec::new();
    for (command, retention) in [
        ("reset", Retention::Gr),
        ("reset", Retention::Llgr),
        ("stop", Retention::Gr),
        ("stop", Retention::Llgr),
    ] {
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

            let command_sent = if command == "reset" {
                PeerCommand::AdministrativeReset { reason: None }
            } else {
                PeerCommand::Stop { reason: None }
            };
            let _ = session.handle_command(command_sent).await;
            rib.release().await;

            got.push((
                command,
                retention,
                state,
                rib.retained_stale(rib_peer).await,
                rib.loc_rib_count().await,
                session.fsm.state(),
                session.reconnect_timer.is_some(),
            ));
            let (after, timer) = if command == "stop" {
                (SessionState::Idle, false)
            } else if state == SessionState::Idle {
                (SessionState::Connect, false)
            } else {
                (SessionState::Idle, true)
            };
            want.push((command, retention, state, 0, 0, after, timer));
        }
    }
    assert_eq!(
        got, want,
        "(command, retention, state at the command, routes retained as stale, \
         Loc-RIB routes, state after, reconnect timer armed)"
    );
}

/// Guard: every teardown that is not an administrative reset or a final stop
/// keeps its retention under the N bit: a TCP loss, a hold-timer expiry, a
/// graceful NOTIFICATION from the peer, a stop for a peer expected back (a
/// dynamic peer bounced onto new configuration) with or without a Cease/8
/// raised by its close drain, and the shutdown that daemon shutdown and a
/// changed peer's delete-then-re-add send. Those last ones send a plain
/// Cease/Administrative Shutdown.
#[tokio::test(start_paused = true)]
async fn other_teardowns_still_retain_under_notification_gr() {
    let causes = [
        "tcp loss",
        "hold timer",
        "peer notification",
        "reconnect stop",
        "reconnect stop drain",
        "shutdown",
    ];
    let mut got = Vec::new();
    for cause in causes {
        let (mut rib, mut session, mut peer) = session_with_one_route(Retention::Gr, true).await;
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
            "reconnect stop" => {
                let _ = session
                    .handle_command(PeerCommand::StopForReconnect { reason: None })
                    .await;
            }
            "reconnect stop drain" => {
                queue_unadmittable_update(&session).await;
                let _ = session
                    .handle_command(PeerCommand::StopForReconnect { reason: None })
                    .await;
            }
            _ => {
                let _ = session.handle_command(PeerCommand::Shutdown).await;
            }
        }
        rib.release().await;
        let wire = if matches!(cause, "reconnect stop" | "shutdown") {
            Some(read_until_notification(&mut peer).await.subcode)
        } else {
            None
        };
        got.push((
            cause,
            wire,
            rib.ends.clone(),
            rib.retained_stale(rib_peer).await,
        ));
    }
    assert_eq!(
        got,
        causes
            .map(|cause| (
                cause,
                matches!(cause, "reconnect stop" | "shutdown")
                    .then_some(cease_subcode::ADMINISTRATIVE_SHUTDOWN),
                vec![("PeerGracefulRestart", 1)],
                1
            ))
            .to_vec(),
        "(cause, wire Cease subcode, session ends, routes retained as stale)"
    );
}

/// A final stop marks only its own teardown as a Hard Reset. When the same
/// session is started and re-established afterwards, the shutdown that
/// daemon shutdown sends, and a stop for a peer expected back, still send a
/// plain Cease/Administrative Shutdown and retain the routes, for GR and LLGR.
/// Mutation-red: if `manual_stop` left the Hard Reset marking set, the later
/// shutdown sends a Hard Reset, queues `PeerDown`, and keeps nothing.
#[tokio::test(start_paused = true)]
async fn a_restarted_session_after_a_final_stop_keeps_graceful_teardowns() {
    let mut got = Vec::new();
    let mut want = Vec::new();
    for retention in [Retention::Gr, Retention::Llgr] {
        for command in ["shutdown", "reconnect stop"] {
            let (mut rib, mut session, mut peer) = session_with_one_route(retention, true).await;
            let rib_peer = session.rib_peer();
            let _ = session
                .handle_command(PeerCommand::Stop { reason: None })
                .await;
            rib.release().await;
            let stop_wire = read_until_notification(&mut peer).await.subcode;

            let (client, mut peer) = connected_stream_pair().await;
            session.test_install_stream(client);
            let _ = session.handle_command(PeerCommand::Start).await;
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
            session.drive_fsm(Event::KeepaliveReceived).await;
            assert_eq!(session.fsm.state(), SessionState::Established);
            retain(&mut session, retention, true);
            receive(&mut session, first());
            session.process_read_buffer().await;
            rib.release().await;

            let command_sent = if command == "shutdown" {
                PeerCommand::Shutdown
            } else {
                PeerCommand::StopForReconnect { reason: None }
            };
            let _ = session.handle_command(command_sent).await;
            rib.release().await;
            got.push((
                retention,
                command,
                stop_wire,
                read_until_notification(&mut peer).await.subcode,
                rib.ends.clone(),
                rib.retained_stale(rib_peer).await,
                rib.loc_rib_count().await,
            ));
            want.push((
                retention,
                command,
                cease_subcode::HARD_RESET,
                cease_subcode::ADMINISTRATIVE_SHUTDOWN,
                vec![("PeerDown", 1), ("PeerGracefulRestart", 1)],
                1,
                1,
            ));
        }
    }
    assert_eq!(
        got, want,
        "(retention, command, final stop wire subcode, later wire subcode, session ends, \
         routes retained as stale, Loc-RIB routes)"
    );
}
