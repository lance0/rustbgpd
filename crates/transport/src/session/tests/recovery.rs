use super::*;
use rustbgpd_rib::{EvpnRecoveryExhaustionCause, EvpnRecoveryReset};

fn request(session: &PeerSession) -> EvpnRecoveryReset {
    EvpnRecoveryReset {
        peer: session.peer_ip,
        session_id: session.session_identity.id,
        outbound: session.outbound_tx.clone(),
        cause: EvpnRecoveryExhaustionCause::PeerLimit,
        limiting_peer: Some(session.peer_ip),
        attempted_peer_bytes: 17,
        attempted_daemon_bytes: 18,
        peer_limit_bytes: 16,
        daemon_limit_bytes: 256,
    }
}

fn accepted_resets(session: &PeerSession) -> f64 {
    counter_samples(
        &session.metrics,
        "bgp_evpn_recovery_provenance_exhausted_total",
    )
    .iter()
    .map(|(_, count)| count)
    .sum()
}

#[tokio::test]
async fn evpn_recovery_guard_current_idle_token_does_not_start_or_count() {
    let (mut session, mut rib) = make_test_session_with_rib(65001, 65002);
    let reset = request(&session);
    assert!(!reset.outbound.is_closed());
    assert_eq!(
        session
            .handle_command(PeerCommand::ResetEvpnRecoverySession { request: reset })
            .await,
        ControlFlow::Continue(())
    );
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(accepted_resets(&session), 0.0);
    assert!(rib.try_recv().is_err());
}

#[tokio::test]
async fn evpn_recovery_queued_before_tcp_loss_cannot_reset_same_actor_reconnect() {
    let (mut session, mut rib) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let reset = request(&session);
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert!(reset.outbound.is_closed());
    assert_eq!(session.fsm.state(), SessionState::Idle);
    while rib.try_recv().is_ok() {}
    assert_eq!(
        session
            .handle_command(PeerCommand::ResetEvpnRecoverySession {
                request: reset.clone(),
            })
            .await,
        ControlFlow::Continue(())
    );
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(accepted_resets(&session), 0.0);
    let (client, _replacement_server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    assert_eq!(session.session_identity.id, reset.session_id);
    assert_eq!(
        session
            .handle_command(PeerCommand::ResetEvpnRecoverySession { request: reset })
            .await,
        ControlFlow::Continue(())
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_eq!(accepted_resets(&session), 0.0);
}

#[tokio::test]
async fn evpn_recovery_guard_reset_counts_once_and_fences_same_actor_reconnect() {
    let (mut session, mut rib) = make_test_session_with_rib(65001, 65002);
    let (client, mut server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib.try_recv().is_ok() {}
    let reset = request(&session);
    assert_eq!(
        session
            .handle_command(PeerCommand::ResetEvpnRecoverySession {
                request: reset.clone(),
            })
            .await,
        ControlFlow::Continue(())
    );
    let notification = read_until_notification(&mut server).await;
    assert_eq!(notification.subcode, cease_subcode::ADMINISTRATIVE_RESET);
    assert_eq!(
        rustbgpd_wire::notification::decode_shutdown_communication(&notification.data).unwrap(),
        "recovery_provenance_exhausted"
    );
    assert_eq!(accepted_resets(&session), 1.0);
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(reset.outbound.is_closed());
    assert_eq!(
        session
            .handle_command(PeerCommand::ResetEvpnRecoverySession {
                request: reset.clone(),
            })
            .await,
        ControlFlow::Continue(())
    );
    assert_eq!(
        session.fsm.state(),
        SessionState::Idle,
        "stale reset must not invoke ManualStart"
    );
    assert_eq!(accepted_resets(&session), 1.0);

    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    assert_eq!(session.session_identity.id, reset.session_id);
    assert!(!session.outbound_tx.same_channel(&reset.outbound));
    assert_eq!(
        session
            .handle_command(PeerCommand::ResetEvpnRecoverySession { request: reset })
            .await,
        ControlFlow::Continue(())
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert_eq!(accepted_resets(&session), 1.0);
    let fresh = request(&session);
    assert_eq!(
        session
            .handle_command(PeerCommand::ResetEvpnRecoverySession { request: fresh })
            .await,
        ControlFlow::Continue(())
    );
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert_eq!(accepted_resets(&session), 2.0);
}

#[tokio::test]
async fn evpn_recovery_guard_rejects_wrong_actor_peer_or_connection() {
    let (mut session, mut rib) = make_test_session_with_rib(65001, 65002);
    let (client, _server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    while rib.try_recv().is_ok() {}
    let original = request(&session);
    for wrong in ["actor", "peer", "connection", "closed"] {
        let mut reset = original.clone();
        let (_keep_receiver, _keep_sender) = match wrong {
            "actor" => {
                reset.session_id += 1;
                (None, None)
            }
            "peer" => {
                reset.peer = "192.0.2.99".parse().unwrap();
                (None, None)
            }
            _ => {
                let (sender, receiver) = mpsc::channel(1);
                reset.outbound = sender.clone();
                if wrong == "closed" {
                    drop(receiver);
                    (None, Some(sender))
                } else {
                    (Some(receiver), Some(sender))
                }
            }
        };
        assert_eq!(
            session
                .handle_command(PeerCommand::ResetEvpnRecoverySession { request: reset })
                .await,
            ControlFlow::Continue(())
        );
        assert_eq!(session.fsm.state(), SessionState::Established, "{wrong}");
        assert_eq!(accepted_resets(&session), 0.0, "{wrong}");
        assert!(rib.try_recv().is_err(), "{wrong}");
    }
}
