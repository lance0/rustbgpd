//! Fast external failover: `PeerCommand::InterfaceDown` on a live session.

use super::*;
use crate::link::{InterfaceAddress, LinkDownCause, LinkDownEvent};

fn loopback_event(cause: LinkDownCause, local: &str) -> Arc<LinkDownEvent> {
    Arc::new(LinkDownEvent {
        ifindex: 1,
        ifname: "lo".into(),
        cause,
        observed_at: std::time::Instant::now(),
        addresses: vec![InterfaceAddress {
            local: local.parse().unwrap(),
            prefix: "127.0.0.0".parse().unwrap(),
            prefix_len: 8,
        }],
    })
}

async fn deliver(session: &mut PeerSession, event: Arc<LinkDownEvent>) {
    assert_eq!(
        session
            .handle_command(PeerCommand::InterfaceDown(event))
            .await,
        ControlFlow::Continue(())
    );
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

        deliver(&mut session, Arc::clone(&event)).await;

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
    deliver(
        &mut session,
        loopback_event(LinkDownCause::CarrierLost, "127.0.0.1"),
    )
    .await;
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

/// TCP loss first (for example ENETUNREACH after the address goes), then the
/// confirmed interface-down: the routes already retained under GR are purged.
#[tokio::test]
async fn interface_down_after_tcp_loss_purges_retained_routes() {
    let (mut session, _server, mut rib_rx) = established_gr_session().await;
    session.handle_tcp_disconnect();
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::PeerGracefulRestart { .. })
    ));

    // An event for another interface leaves the retention alone.
    deliver(
        &mut session,
        loopback_event(LinkDownCause::CarrierLost, "127.0.0.2"),
    )
    .await;
    assert!(rib_rx.try_recv().is_err());

    deliver(
        &mut session,
        loopback_event(LinkDownCause::AddressRemoved, "127.0.0.1"),
    )
    .await;
    match rib_rx.try_recv() {
        Ok(RibUpdate::PeerDown { peer, .. }) => assert_eq!(peer, session.peer_ip),
        _ => panic!("expected the retained routes to be purged"),
    }
    assert!(session.gr_retained_connection.is_none());
    assert!(session.last_error.contains("local address removed"));
}

/// A delivery delayed past a reconnect must not stop the healthy replacement
/// connection, even though it runs over the same addresses.
#[tokio::test]
async fn interface_down_observed_before_the_connection_is_ignored() {
    let stale = loopback_event(LinkDownCause::CarrierLost, "127.0.0.1");
    tokio::time::sleep(Duration::from_millis(5)).await;
    let (mut session, _server, mut rib_rx) = established_gr_session().await;
    deliver(&mut session, stale).await;
    assert_eq!(session.fsm.state(), SessionState::Established);
    assert!(rib_rx.try_recv().is_err());
}

/// iBGP over a directly connected link is untouched, as is an accept-any
/// peer whose OPEN has not identified it yet; transport decides from the
/// negotiated ASN, whatever the manager believed.
#[tokio::test]
async fn interface_down_ignores_ibgp_and_unidentified_peers() {
    let (mut ibgp, mut rib_rx) = make_test_session_with_rib(65001, 65001);
    let (client, _server) = connected_stream_pair().await;
    ibgp.test_install_stream(client);
    establish_test_session(&mut ibgp, 65001).await;
    while rib_rx.try_recv().is_ok() {}
    deliver(
        &mut ibgp,
        loopback_event(LinkDownCause::CarrierLost, "127.0.0.1"),
    )
    .await;
    assert_eq!(ibgp.fsm.state(), SessionState::Established);

    // Accept-any child (configured ASN 0) that negotiated the local ASN.
    let (mut accept_any, _rib_rx) = make_test_session_with_rib(65001, 0);
    let (client, _server) = connected_stream_pair().await;
    accept_any.test_install_stream(client);
    accept_any.drive_fsm(Event::ManualStart).await;
    let event = loopback_event(LinkDownCause::CarrierLost, "127.0.0.1");
    deliver(&mut accept_any, Arc::clone(&event)).await;
    assert!(
        accept_any.read_half.is_some(),
        "an unidentified peer is not provably eBGP; its connection stays"
    );
    // Accept-any child whose OPEN carried the local ASN: negotiated iBGP.
    let (mut learned, _rib_rx) = make_test_session_with_rib(65001, 0);
    let (client, _server) = connected_stream_pair().await;
    learned.test_install_stream(client);
    establish_test_session(&mut learned, 65001).await;
    deliver(
        &mut learned,
        loopback_event(LinkDownCause::CarrierLost, "127.0.0.1"),
    )
    .await;
    assert_eq!(learned.fsm.state(), SessionState::Established);
}

/// A writer blocked on a dead link is aborted with its backlog: nothing queued
/// reaches the wire after the failover, and the socket is reset.
#[tokio::test]
async fn interface_down_discards_a_blocked_writer_backlog() {
    const FRAMES: usize = 512;
    const FRAME_LEN: usize = 4096;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connect = tokio::spawn(async move {
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.set_recv_buffer_size(4096).unwrap();
        socket.connect(addr).await.unwrap()
    });
    let (stream, _) = listener.accept().await.unwrap();
    socket2::SockRef::from(&stream)
        .set_send_buffer_size(4096)
        .unwrap();
    let mut peer = connect.await.unwrap();
    let (mut session, _rib_rx) = make_test_session_with_rib(65001, 65002);
    session.test_install_stream(stream);
    establish_test_session(&mut session, 65002).await;
    let bulk_tx = session.writer_bulk_tx.clone().unwrap();
    for _ in 0..FRAMES {
        bulk_tx
            .send(Bytes::from(vec![0u8; FRAME_LEN]))
            .await
            .unwrap();
    }
    drop(bulk_tx);

    deliver(
        &mut session,
        loopback_event(LinkDownCause::CarrierLost, "127.0.0.1"),
    )
    .await;
    assert!(
        session.writer_join.is_none(),
        "the writer is aborted and joined, not left draining"
    );

    let mut received = 0;
    let mut buf = vec![0u8; 65536];
    let drained = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match peer.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => received += n,
            }
        }
    })
    .await;
    assert!(drained.is_ok(), "the old socket must close promptly");
    assert!(
        received < FRAMES * FRAME_LEN,
        "the queued backlog must not reach the peer ({received} bytes did)"
    );
}

/// Failover during reconnect: the replacement is mid-handshake (`OpenSent`)
/// when the confirmed interface-down arrives. The routes retained from the
/// lost connection are purged, and the replacement on the same link closes.
#[tokio::test]
async fn interface_down_during_reconnect_purges_retained_routes() {
    let (mut session, _server, mut rib_rx) = established_gr_session().await;
    session.handle_tcp_disconnect();
    session.drive_fsm(Event::TcpConnectionFails).await;
    assert!(matches!(
        rib_rx.try_recv(),
        Ok(RibUpdate::PeerGracefulRestart { .. })
    ));
    let (client, _replacement_server) = connected_stream_pair().await;
    session.test_install_stream(client);
    session.drive_fsm(Event::ManualStart).await;
    assert_eq!(session.fsm.state(), SessionState::OpenSent);

    deliver(
        &mut session,
        loopback_event(LinkDownCause::CarrierLost, "127.0.0.1"),
    )
    .await;
    match rib_rx.try_recv() {
        Ok(RibUpdate::PeerDown { peer, .. }) => assert_eq!(peer, session.peer_ip),
        _ => panic!("the retained routes must be purged while a replacement handshakes"),
    }
    assert!(session.gr_retained_connection.is_none());
    assert!(
        session.read_half.is_none(),
        "the replacement on the same link closes too"
    );
}
