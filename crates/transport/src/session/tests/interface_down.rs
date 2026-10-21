//! Fast external failover: `PeerCommand::InterfaceDown` on a live session.

use super::*;
use crate::link::{InterfaceAddress, LinkDownCause, LinkDownEvent};

fn loopback_event(cause: LinkDownCause, local: &str) -> Arc<LinkDownEvent> {
    Arc::new(LinkDownEvent {
        ifindex: 1,
        ifname: "lo".into(),
        cause,
        addresses: vec![InterfaceAddress {
            local: local.parse().unwrap(),
            prefix: "127.0.0.0".parse().unwrap(),
            prefix_len: 8,
        }],
    })
}

/// An Established session whose peer advertised Graceful Restart for
/// IPv4 unicast, so an ordinary transport loss would retain its routes.
async fn established_gr_session() -> (PeerSession, TcpStream, mpsc::Receiver<RibUpdate>) {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    session.config.peer.graceful_restart = true;
    let (client, server) = connected_stream_pair().await;
    session.test_install_stream(client);
    establish_test_session(&mut session, 65002).await;
    let negotiated = Arc::make_mut(session.negotiated.as_mut().expect("negotiated"));
    negotiated.peer_gr_capable = true;
    negotiated.peer_restart_time = 120;
    negotiated.peer_gr_families = vec![rustbgpd_wire::GracefulRestartFamily {
        afi: Afi::Ipv4,
        safi: Safi::Unicast,
        forwarding_preserved: false,
    }];
    while rib_rx.try_recv().is_ok() {}
    (session, server, rib_rx)
}

#[tokio::test]
async fn interface_down_purges_instead_of_retaining_and_reconnects() {
    for cause in [
        LinkDownCause::CarrierLost,
        LinkDownCause::AdminDown,
        LinkDownCause::InterfaceRemoved,
        LinkDownCause::AddressRemoved,
    ] {
        let (mut session, mut server, mut rib_rx) = established_gr_session().await;
        let event = loopback_event(cause, "127.0.0.1");

        assert_eq!(
            session
                .handle_command(PeerCommand::InterfaceDown(Arc::clone(&event)))
                .await,
            ControlFlow::Continue(())
        );

        assert_eq!(session.fsm.state(), SessionState::Idle, "{cause:?}");
        match rib_rx.try_recv() {
            Ok(RibUpdate::PeerDown { peer, .. }) => assert_eq!(peer, session.peer_ip),
            Ok(RibUpdate::PeerGracefulRestart { .. }) => {
                panic!("{cause:?}: routes retained under GR after an interface down")
            }
            _ => panic!("{cause:?}: expected PeerDown"),
        }
        assert!(
            session.reconnect_timer.is_some(),
            "{cause:?}: a failover stop is not an operator stop; the session must reconnect"
        );
        assert_eq!(session.last_error, event.teardown_cause());
        assert!(
            session.last_error.contains(cause.as_str()),
            "{cause:?}: distinct teardown cause, got {:?}",
            session.last_error
        );
        assert!(!session.suppress_gr_retention, "latch is per teardown");

        // No NOTIFICATION reaches the wire: the peer sees only the close.
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), server.read_to_end(&mut rest)).await;
        let mut types = Vec::new();
        let mut at = 0;
        while at + 19 <= rest.len() {
            types.push(rest[at + 18]);
            at += usize::from(u16::from_be_bytes([rest[at + 16], rest[at + 17]])).max(19);
        }
        assert!(
            !types.contains(&3),
            "{cause:?}: fast external failover must not send a NOTIFICATION; saw types {types:?}"
        );
    }
}

#[tokio::test]
async fn interface_down_records_local_no_notification_down_reason() {
    let (mut session, _server, _rib_rx) = established_gr_session().await;
    assert_eq!(
        session
            .handle_command(PeerCommand::InterfaceDown(loopback_event(
                LinkDownCause::CarrierLost,
                "127.0.0.1",
            )))
            .await,
        ControlFlow::Continue(())
    );
    let samples = counter_samples(&session.metrics, "bgp_session_down_total");
    assert!(
        samples.iter().any(|(labels, value)| {
            labels.get("reason").map(String::as_str) == Some("local_no_notification")
                && (*value - 1.0).abs() < f64::EPSILON
        }),
        "{samples:?}"
    );
}

#[tokio::test]
async fn interface_down_on_another_interface_leaves_the_session_alone() {
    let (mut session, _server, mut rib_rx) = established_gr_session().await;
    // The interface carries 127.0.0.2, not this socket's 127.0.0.1.
    assert_eq!(
        session
            .handle_command(PeerCommand::InterfaceDown(loopback_event(
                LinkDownCause::CarrierLost,
                "127.0.0.2",
            )))
            .await,
        ControlFlow::Continue(())
    );
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(rib_rx.try_recv().is_err());
    assert_eq!(session.last_error, "");
}

#[tokio::test]
async fn interface_down_without_a_connection_is_a_no_op() {
    let (mut session, mut rib_rx) = make_test_session_with_rib(65001, 65002);
    assert_eq!(
        session
            .handle_command(PeerCommand::InterfaceDown(loopback_event(
                LinkDownCause::CarrierLost,
                "127.0.0.1",
            )))
            .await,
        ControlFlow::Continue(())
    );
    assert_eq!(session.fsm.state(), SessionState::Idle);
    assert!(rib_rx.try_recv().is_err());
    assert_eq!(session.last_error, "");
}

/// Control for the purge assertion above: the same session losing TCP for
/// an ordinary transport reason keeps the GR helper behavior.
#[tokio::test]
async fn ordinary_transport_loss_still_retains_under_gr() {
    let (mut session, _server, mut rib_rx) = established_gr_session().await;
    session.handle_tcp_disconnect();
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::PeerGracefulRestart { .. })
    ));
}
