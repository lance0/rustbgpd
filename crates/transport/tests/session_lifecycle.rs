//! Integration tests for the transport layer using a mock BGP peer.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use rustbgpd_fsm::PeerConfig;
use rustbgpd_rib::RibUpdate;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_transport::{PeerHandle, SessionNotification, TransportConfig};
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
        if let Ok(Some(len)) = peek_message_length(buf) {
            let len = usize::from(len);
            if buf.len() >= len {
                let frame = buf.split_to(len);
                let mut bytes = frame.freeze();
                return decode_message(&mut bytes).expect("valid message");
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
        .find(|f| f.get_name() == "bgp_session_established_total");
    assert!(established.is_some(), "established metric should exist");

    // Clean shutdown
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
    let handle = PeerHandle::spawn(
        transport_config(addr),
        metrics.clone(),
        rib_tx,
        None,
        None,
        None,
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
        .find(|f| f.get_name() == "bgp_notifications_received_total");
    assert!(notif_metric.is_some(), "notification metric should exist");

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
    let handle = PeerHandle::spawn(config, metrics.clone(), rib_tx, None, None, None);
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
    let handle = PeerHandle::spawn(
        transport_config(addr),
        metrics.clone(),
        rib_tx,
        None,
        None,
        None,
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
    handle.stop().await.unwrap();

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
    let handle = PeerHandle::spawn(config, metrics.clone(), rib_tx, None, None, None);
    handle.start().await.unwrap();

    // Let it fail and retry a couple times
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify state transition metrics were recorded (multiple transitions
    // through Connect → Active cycle)
    let families = metrics.registry().gather();
    let transitions = families
        .iter()
        .find(|f| f.get_name() == "bgp_session_state_transitions_total");
    assert!(transitions.is_some(), "should have state transitions");

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

    let (notify_tx, mut notify_rx) = mpsc::channel::<SessionNotification>(16);

    let (rib_tx, _rib_rx) = mpsc::channel::<RibUpdate>(64);
    let handle = PeerHandle::spawn(
        transport_config(addr),
        metrics.clone(),
        rib_tx,
        None,
        None,
        Some(notify_tx),
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

    // The notification should arrive before Established (no KEEPALIVE sent yet)
    let notification = tokio::time::timeout(Duration::from_secs(5), notify_rx.recv())
        .await
        .expect("should receive notification within timeout")
        .expect("channel should not be closed");

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
