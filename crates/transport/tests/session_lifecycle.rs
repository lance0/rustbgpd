//! Integration tests for the transport layer using a mock BGP peer.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use bytes::{Bytes, BytesMut};
use rustbgpd_fsm::{PeerConfig, SessionState};
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{
    PeerHandle, SessionIdentity, SessionLifecycleNotification, SessionNotification,
    SessionNotificationDirection, TransportConfig,
};
use rustbgpd_wire::{
    Afi, Capability, Message, NotificationMessage, OpenMessage, Safi, decode_message,
    encode_message, notification::NotificationCode, peek_message_length,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// Local ASN for tests.
const LOCAL_ASN: u32 = 65001;
/// Remote (mock peer) ASN.
const REMOTE_ASN: u32 = 65002;

fn test_peer_config() -> PeerConfig {
    PeerConfig {
        local_asn: LOCAL_ASN,
        remote_asn: REMOTE_ASN,
        local_router_id: Ipv4Addr::new(10, 0, 0, 1),
        hold_time: 90,
        connect_retry_secs: 5,
        families: vec![(Afi::Ipv4, Safi::Unicast)],
        graceful_restart: false,
        gr_restart_time: 120,
        llgr_stale_time: 0,
        add_path_receive: false,
        add_path_send: false,
        add_path_send_max: 0,
    }
}

fn mock_open() -> OpenMessage {
    OpenMessage {
        version: 4,
        my_as: REMOTE_ASN as u16,
        hold_time: 90,
        bgp_identifier: Ipv4Addr::new(10, 0, 0, 2),
        capabilities: vec![
            Capability::MultiProtocol {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            },
            Capability::FourOctetAs { asn: REMOTE_ASN },
        ],
    }
}

/// Read a complete BGP message from a TCP stream.
async fn read_bgp_message(stream: &mut tokio::net::TcpStream, buf: &mut BytesMut) -> Message {
    loop {
        // Check if we have a complete message
        if let Ok(Some(len)) = peek_message_length(buf, rustbgpd_wire::MAX_MESSAGE_LEN) {
            let len = usize::from(len);
            if buf.len() >= len {
                let frame = buf.split_to(len);
                let mut bytes = frame.freeze();
                return decode_message(&mut bytes, rustbgpd_wire::MAX_MESSAGE_LEN)
                    .expect("valid message");
            }
        }
        // Need more data
        let n = stream.read_buf(buf).await.expect("TCP read");
        assert!(n > 0, "unexpected EOF from peer");
    }
}

/// Send a BGP message over a TCP stream.
async fn send_bgp_message(stream: &mut tokio::net::TcpStream, msg: &Message) {
    let encoded = encode_message(msg).expect("encode");
    stream.write_all(&encoded).await.expect("write");
    stream.flush().await.expect("flush");
}

/// Create a TransportConfig pointing at the given listener address.
fn transport_config(addr: SocketAddr) -> TransportConfig {
    TransportConfig {
        peer: test_peer_config(),
        remote_addr: addr,
        connect_timeout: Duration::from_secs(5),
        max_prefixes: None,
        md5_password: None,
        ttl_security: false,
        local_ipv6_nexthop: None,
        peer_group: None,
        gr_stale_routes_time: 360,
        llgr_stale_time: 0,
        gr_restart_until: None,
        route_reflector_client: false,
        route_server_client: false,
        remove_private_as: rustbgpd_transport::RemovePrivateAs::Disabled,
        cluster_id: None,
    }
}

#[tokio::test]
async fn full_handshake_reaches_established() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let handle = PeerHandle::spawn(
        transport_config(addr),
        metrics.clone(),
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        false,
    );
    handle.start().await.unwrap();

    // Accept the inbound connection from rustbgpd
    let (mut peer_stream, _) = listener.accept().await.unwrap();
    let mut buf = BytesMut::with_capacity(4096);

    // Read the OPEN from rustbgpd
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Open(_)));

    // Send our OPEN + KEEPALIVE
    send_bgp_message(&mut peer_stream, &Message::Open(mock_open())).await;
    send_bgp_message(&mut peer_stream, &Message::Keepalive).await;

    // Read the KEEPALIVE from rustbgpd (it sends one after receiving our OPEN)
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Keepalive));

    // Session should now be Established — verify via metrics
    // Give a moment for the FSM to process
    tokio::time::sleep(Duration::from_millis(50)).await;

    let families = metrics.registry().gather();
    let established = families
        .iter()
        .find(|f| f.name() == "bgp_session_established_total");
    assert!(established.is_some(), "established metric should exist");

    // Clean shutdown
    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn open_sets_gr_restart_state_during_restart_window() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let mut cfg = transport_config(addr);
    cfg.peer.graceful_restart = true;
    cfg.gr_restart_until = Some(Instant::now() + Duration::from_secs(30));
    let handle = PeerHandle::spawn(cfg, metrics, rib_tx, None, None, None, None, None, false);
    handle.start().await.unwrap();

    let (mut peer_stream, _) = listener.accept().await.unwrap();
    let mut buf = BytesMut::with_capacity(4096);
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    let Message::Open(open) = msg else {
        panic!("expected OPEN");
    };
    assert!(open.capabilities.iter().any(|cap| matches!(
        cap,
        Capability::GracefulRestart {
            restart_state: true,
            ..
        }
    )));

    drop(peer_stream);
    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn open_clears_gr_restart_state_after_restart_window_expires() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let mut cfg = transport_config(addr);
    cfg.peer.graceful_restart = true;
    cfg.gr_restart_until = Some(Instant::now() - Duration::from_secs(1));
    let handle = PeerHandle::spawn(cfg, metrics, rib_tx, None, None, None, None, None, false);
    handle.start().await.unwrap();

    let (mut peer_stream, _) = listener.accept().await.unwrap();
    let mut buf = BytesMut::with_capacity(4096);
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    let Message::Open(open) = msg else {
        panic!("expected OPEN");
    };
    assert!(open.capabilities.iter().any(|cap| matches!(
        cap,
        Capability::GracefulRestart {
            restart_state: false,
            ..
        }
    )));

    drop(peer_stream);
    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn peer_disconnect_triggers_retry() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let handle = PeerHandle::spawn(
        transport_config(addr),
        metrics.clone(),
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        false,
    );
    handle.start().await.unwrap();

    // Accept first connection
    let (mut peer_stream, _) = listener.accept().await.unwrap();
    let mut buf = BytesMut::with_capacity(4096);

    // Read OPEN
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Open(_)));

    // Drop the connection (simulate peer crash)
    drop(peer_stream);

    // The FSM should retry — accept the second connection
    let (mut peer_stream2, _) = tokio::time::timeout(Duration::from_secs(15), listener.accept())
        .await
        .expect("should retry connection")
        .unwrap();

    let mut buf2 = BytesMut::with_capacity(4096);
    let msg = read_bgp_message(&mut peer_stream2, &mut buf2).await;
    assert!(matches!(msg, Message::Open(_)));

    drop(peer_stream2);
    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn notification_from_peer_tears_down() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let (event_tx, mut event_rx) = mpsc::channel(16);
    let handle = PeerHandle::spawn_with_identity(
        transport_config(addr),
        metrics.clone(),
        rib_tx,
        None,
        None,
        None,
        Some(event_tx),
        None,
        None,
        false,
        SessionIdentity::primary(1),
    );
    handle.start().await.unwrap();

    let (mut peer_stream, _) = listener.accept().await.unwrap();
    let mut buf = BytesMut::with_capacity(4096);

    // Read OPEN
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Open(_)));

    // Send our OPEN
    send_bgp_message(&mut peer_stream, &Message::Open(mock_open())).await;

    // Read KEEPALIVE from rustbgpd
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Keepalive));

    // Now send a NOTIFICATION instead of KEEPALIVE to tear down
    let notif = NotificationMessage::new(NotificationCode::Cease, 0, Bytes::new());
    send_bgp_message(&mut peer_stream, &Message::Notification(notif)).await;

    // Give time for FSM to process and retry
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Verify notification received metric
    let families = metrics.registry().gather();
    let notif_metric = families
        .iter()
        .find(|f| f.name() == "bgp_notifications_received_total");
    assert!(notif_metric.is_some(), "notification metric should exist");
    let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
        .await
        .expect("notification event timeout")
        .expect("notification event channel closed");
    assert_eq!(event.direction, SessionNotificationDirection::Received);
    assert_eq!(event.code, NotificationCode::Cease.as_u8());
    assert_eq!(event.peer_addr, addr.ip());

    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn keepalive_exchange_in_established() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    // Use a short hold time to get frequent keepalives
    let mut config = transport_config(addr);
    config.peer.hold_time = 9; // keepalive interval = 3s

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let handle = PeerHandle::spawn(
        config,
        metrics.clone(),
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        false,
    );
    handle.start().await.unwrap();

    let (mut peer_stream, _) = listener.accept().await.unwrap();
    let mut buf = BytesMut::with_capacity(4096);

    // Complete handshake
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Open(_)));

    let mut peer_open = mock_open();
    peer_open.hold_time = 9;
    send_bgp_message(&mut peer_stream, &Message::Open(peer_open)).await;
    send_bgp_message(&mut peer_stream, &Message::Keepalive).await;

    // Read the initial KEEPALIVE
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Keepalive));

    // Wait for a keepalive from rustbgpd (should come within ~3 seconds)
    let msg = tokio::time::timeout(
        Duration::from_secs(5),
        read_bgp_message(&mut peer_stream, &mut buf),
    )
    .await
    .expect("should receive keepalive within interval");
    assert!(matches!(msg, Message::Keepalive));

    // Send a keepalive back to keep the session alive
    send_bgp_message(&mut peer_stream, &Message::Keepalive).await;

    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn stop_command_sends_cease() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let (event_tx, mut event_rx) = mpsc::channel(16);
    let handle = PeerHandle::spawn_with_identity(
        transport_config(addr),
        metrics.clone(),
        rib_tx,
        None,
        None,
        None,
        Some(event_tx),
        None,
        None,
        false,
        SessionIdentity::primary(1),
    );
    handle.start().await.unwrap();

    let (mut peer_stream, _) = listener.accept().await.unwrap();
    let mut buf = BytesMut::with_capacity(4096);

    // Complete handshake to Established
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Open(_)));

    send_bgp_message(&mut peer_stream, &Message::Open(mock_open())).await;
    send_bgp_message(&mut peer_stream, &Message::Keepalive).await;

    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Keepalive));

    // Give FSM time to reach Established
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Send Stop command — should trigger Cease NOTIFICATION
    handle.stop(None).await.unwrap();

    // Read the NOTIFICATION from rustbgpd
    let msg = tokio::time::timeout(
        Duration::from_secs(2),
        read_bgp_message(&mut peer_stream, &mut buf),
    )
    .await
    .expect("should receive NOTIFICATION");
    match msg {
        Message::Notification(n) => {
            assert_eq!(n.code, NotificationCode::Cease);
        }
        other => panic!("expected NOTIFICATION, got {other:?}"),
    }
    let event = tokio::time::timeout(Duration::from_secs(1), event_rx.recv())
        .await
        .expect("notification event timeout")
        .expect("notification event channel closed");
    assert_eq!(event.direction, SessionNotificationDirection::Sent);
    assert_eq!(event.code, NotificationCode::Cease.as_u8());
    assert_eq!(event.peer_addr, addr.ip());

    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn connect_failure_retries() {
    // Bind to a port, then drop the listener so connection is refused
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let metrics = BgpMetrics::new();
    let mut config = transport_config(addr);
    config.connect_timeout = Duration::from_millis(500);
    config.peer.connect_retry_secs = 1;

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let handle = PeerHandle::spawn(
        config,
        metrics.clone(),
        rib_tx,
        None,
        None,
        None,
        None,
        None,
        false,
    );
    handle.start().await.unwrap();

    // Let it fail and retry a couple times
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify state transition metrics were recorded (multiple transitions
    // through Connect → Active cycle)
    let families = metrics.registry().gather();
    let transitions = families
        .iter()
        .find(|f| f.name() == "bgp_session_state_transitions_total");
    assert!(transitions.is_some(), "should have state transitions");

    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn state_changed_uses_bounded_lifecycle_channel() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<SessionNotification>();
    let (lifecycle_tx, mut lifecycle_rx) = mpsc::channel::<SessionLifecycleNotification>(8);

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let handle = PeerHandle::spawn_with_identity_and_lifecycle(
        transport_config(addr),
        metrics.clone(),
        rib_tx,
        None,
        None,
        Some(notify_tx),
        None,
        Some(lifecycle_tx),
        None,
        None,
        false,
        SessionIdentity::primary(42),
    );
    handle.start().await.unwrap();

    let (_peer_stream, _) = listener.accept().await.unwrap();

    let event = tokio::time::timeout(Duration::from_secs(5), lifecycle_rx.recv())
        .await
        .expect("should receive lifecycle event within timeout")
        .expect("lifecycle channel should be open");

    match event {
        SessionLifecycleNotification::StateChanged {
            session_id,
            peer_addr,
            ..
        } => {
            assert_eq!(session_id, 42);
            assert_eq!(peer_addr, addr.ip());
        }
    }

    assert!(
        notify_rx.try_recv().is_err(),
        "ordinary StateChanged events should not use the lossless collision channel"
    );

    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn legacy_identity_constructor_preserves_state_changed_notifications() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<SessionNotification>();
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let handle = PeerHandle::spawn_with_identity(
        transport_config(addr),
        metrics,
        rib_tx,
        None,
        None,
        Some(notify_tx),
        None,
        None,
        None,
        false,
        SessionIdentity::primary(7),
    );
    handle.start().await.unwrap();

    let (_peer_stream, _) = listener.accept().await.unwrap();
    let notification = tokio::time::timeout(Duration::from_secs(5), notify_rx.recv())
        .await
        .expect("legacy StateChanged notification should arrive")
        .expect("notification channel should stay open");

    assert!(
        matches!(
            notification,
            SessionNotification::StateChanged { session_id: 7, .. }
        ),
        "legacy constructor must keep StateChanged on the notification channel"
    );

    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn lifecycle_only_channel_receives_collision_adjacent_state_changes() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    let (lifecycle_tx, mut lifecycle_rx) = mpsc::channel::<SessionLifecycleNotification>(8);
    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let handle = PeerHandle::spawn_with_identity_and_lifecycle(
        transport_config(addr),
        metrics,
        rib_tx,
        None,
        None,
        None,
        None,
        Some(lifecycle_tx),
        None,
        None,
        false,
        SessionIdentity::primary(9),
    );
    handle.start().await.unwrap();

    let (mut peer_stream, _) = listener.accept().await.unwrap();
    let mut buf = BytesMut::with_capacity(4096);
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Open(_)));
    send_bgp_message(&mut peer_stream, &Message::Open(mock_open())).await;
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Keepalive));
    let notif = NotificationMessage::new(NotificationCode::Cease, 0, Bytes::new());
    send_bgp_message(&mut peer_stream, &Message::Notification(notif)).await;

    let mut saw_open_confirm = false;
    loop {
        let notification = tokio::time::timeout(Duration::from_secs(5), lifecycle_rx.recv())
            .await
            .expect("lifecycle notifications should arrive")
            .expect("lifecycle channel should stay open");
        match notification {
            SessionLifecycleNotification::StateChanged {
                session_id,
                new: SessionState::OpenConfirm,
                ..
            } => {
                assert_eq!(session_id, 9);
                saw_open_confirm = true;
            }
            SessionLifecycleNotification::StateChanged {
                session_id,
                new: SessionState::Idle,
                ..
            } => {
                assert_eq!(session_id, 9);
                assert!(
                    saw_open_confirm,
                    "OpenConfirm should arrive before the terminal Idle transition"
                );
                break;
            }
            SessionLifecycleNotification::StateChanged { .. } => {}
        }
    }

    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn open_confirm_sends_session_notification() {
    // Verify that reaching OpenConfirm sends SessionNotification::OpenReceived
    // with the correct remote_router_id. This exercises the fix for the bug
    // where self.negotiated (set at Established) was read instead of
    // self.fsm.negotiated() (set at OpenConfirm).
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<SessionNotification>();

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let handle = PeerHandle::spawn(
        transport_config(addr),
        metrics.clone(),
        rib_tx,
        None,
        None,
        Some(notify_tx),
        None,
        None,
        false,
    );
    handle.start().await.unwrap();

    // Accept the connection from rustbgpd
    let (mut peer_stream, _) = listener.accept().await.unwrap();
    let mut buf = BytesMut::with_capacity(4096);

    // Read the OPEN from rustbgpd
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Open(_)));

    // Send our OPEN — this should cause rustbgpd to transition to OpenConfirm
    // and send a SessionNotification::OpenReceived
    send_bgp_message(&mut peer_stream, &Message::Open(mock_open())).await;

    // The OpenReceived notification should arrive before Established (no
    // KEEPALIVE sent yet). Ordinary StateChanged events use the bounded
    // lifecycle channel rather than this lossless collision channel.
    let notification = loop {
        let notification = tokio::time::timeout(Duration::from_secs(5), notify_rx.recv())
            .await
            .expect("should receive notification within timeout")
            .expect("channel should not be closed");
        if matches!(notification, SessionNotification::StateChanged { .. }) {
            continue;
        }
        break notification;
    };

    match notification {
        SessionNotification::OpenReceived {
            remote_router_id, ..
        } => {
            assert_eq!(
                remote_router_id,
                Ipv4Addr::new(10, 0, 0, 2),
                "should have remote router-id from OPEN"
            );
        }
        other => panic!("expected OpenReceived, got {other:?}"),
    }

    // Clean shutdown
    handle.shutdown().await.unwrap().unwrap();
}

#[tokio::test]
async fn query_state_returns_router_id_at_open_confirm() {
    // Verify that QueryState exposes remote_router_id during OpenConfirm
    // (not just after SessionEstablished). This is critical for collision
    // detection: handle_inbound() reads remote_router_id via QueryState
    // when the existing session is already in OpenConfirm.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = BgpMetrics::new();

    let (notify_tx, mut notify_rx) = mpsc::unbounded_channel::<SessionNotification>();

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let handle = PeerHandle::spawn(
        transport_config(addr),
        metrics.clone(),
        rib_tx,
        None,
        None,
        Some(notify_tx),
        None,
        None,
        false,
    );
    handle.start().await.unwrap();

    // Accept the connection from rustbgpd
    let (mut peer_stream, _) = listener.accept().await.unwrap();
    let mut buf = BytesMut::with_capacity(4096);

    // Read the OPEN from rustbgpd
    let msg = read_bgp_message(&mut peer_stream, &mut buf).await;
    assert!(matches!(msg, Message::Open(_)));

    // Send our OPEN — rustbgpd transitions to OpenConfirm
    send_bgp_message(&mut peer_stream, &Message::Open(mock_open())).await;

    // Wait for the OpenReceived notification to confirm we're in OpenConfirm.
    // Ordinary StateChanged events use the bounded lifecycle channel rather
    // than this lossless collision channel.
    let notification = loop {
        let notification = tokio::time::timeout(Duration::from_secs(5), notify_rx.recv())
            .await
            .expect("should receive notification within timeout")
            .expect("channel should not be closed");
        if matches!(notification, SessionNotification::StateChanged { .. }) {
            continue;
        }
        break notification;
    };
    assert!(matches!(
        notification,
        SessionNotification::OpenReceived { .. }
    ));

    // Now query state — remote_router_id should be available even though
    // we haven't sent KEEPALIVE yet (session is NOT Established)
    let state = handle
        .query_state()
        .await
        .expect("query_state should succeed");
    assert_eq!(
        state.remote_router_id,
        Some(Ipv4Addr::new(10, 0, 0, 2)),
        "remote_router_id should be available at OpenConfirm, not just Established"
    );

    // Clean shutdown
    handle.shutdown().await.unwrap().unwrap();
}
