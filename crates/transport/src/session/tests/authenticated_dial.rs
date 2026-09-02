//! Loopback proofs for the authenticated non-BGP dial used by RTR clients:
//! the kernel enforces the installed TCP MD5 / TCP-AO material on both ends,
//! so a matching key completes the handshake and a mismatched or absent key
//! never yields an accepted connection.

use super::*;
use crate::socket_opts::{
    TcpAoSocketRole, TcpAoSupport, probe_tcp_ao_support, set_tcp_ao_config, set_tcp_md5sig,
};
use crate::{
    TcpAoAlgorithm, TcpAoConfig, TcpAoKeyring, TransportAuthSecret, connect_authenticated,
    preflight_authenticated_dial,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;

fn loopback_listener() -> Socket {
    Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap()
}

fn bind_listen(socket: &Socket) -> SocketAddr {
    let any: SocketAddr = "127.0.0.1:0".parse().unwrap();
    socket.bind(&any.into()).unwrap();
    socket.listen(4).unwrap();
    socket.set_nonblocking(true).unwrap();
    socket.local_addr().unwrap().as_socket().unwrap()
}

fn try_accept(listener: &Socket) -> bool {
    match listener.accept() {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
        Err(e) => panic!("accept failed: {e}"),
    }
}

async fn wait_accepted(listener: &Socket) -> bool {
    for _ in 0..40 {
        if try_accept(listener) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    false
}

const HANDSHAKE: Duration = Duration::from_secs(5);
const SHORT: Duration = Duration::from_millis(500);

/// The listener drops a mis-signed or unsigned SYN silently, so the dial can
/// only time out; prove the bounded dial reports that and that no child was
/// ever queued for accept.
async fn assert_no_session(
    listener: &Socket,
    dial: impl std::future::Future<Output = std::io::Result<TcpStream>>,
    expect_key_hint: bool,
) {
    let err = dial
        .await
        .expect_err("handshake must not complete without the listener's key");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut, "{err}");
    assert_eq!(
        err.to_string().contains("TCP MD5 / TCP-AO key"),
        expect_key_hint,
        "{err}"
    );
    assert!(!try_accept(listener), "listener must not accept a session");
}

#[tokio::test]
async fn md5_dial_completes_with_matching_key_and_never_without_it() {
    let listener = loopback_listener();
    set_tcp_md5sig(&listener, "127.0.0.1:0".parse().unwrap(), "rtr-md5-secret").unwrap();
    let addr = bind_listen(&listener);

    let key = TransportAuthSecret::from("rtr-md5-secret");
    let stream = connect_authenticated(addr, Some(&key), None, "rtr-test", HANDSHAKE)
        .await
        .unwrap();
    assert!(wait_accepted(&listener).await);
    drop(stream);

    let wrong = TransportAuthSecret::from("not-the-key");
    assert_no_session(
        &listener,
        connect_authenticated(addr, Some(&wrong), None, "rtr-test", SHORT),
        true,
    )
    .await;
    assert_no_session(
        &listener,
        connect_authenticated(addr, None, None, "rtr-test", SHORT),
        false,
    )
    .await;
}

#[test]
fn preflight_reports_refused_md5_material_without_connecting() {
    let remote: SocketAddr = "127.0.0.1:3323".parse().unwrap();
    let ok = TransportAuthSecret::from("rtr-md5-secret");
    preflight_authenticated_dial(remote, Some(&ok), None, "rtr-test").unwrap();

    let too_long = TransportAuthSecret::from("k".repeat(81));
    let err = preflight_authenticated_dial(remote, Some(&too_long), None, "rtr-test").unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

fn ao_key(secret: &str, send_id: u8, recv_id: u8) -> TcpAoConfig {
    TcpAoConfig {
        key: TransportAuthSecret::from(secret),
        send_id,
        recv_id,
        algorithm: TcpAoAlgorithm::HmacSha256,
        preferred: false,
        deprecated: false,
    }
}

#[tokio::test]
async fn tcp_ao_dial_completes_with_matching_mkt_and_never_without_it() {
    if probe_tcp_ao_support() != TcpAoSupport::Supported {
        eprintln!("skipping: kernel does not support TCP-AO");
        return;
    }
    let listener = loopback_listener();
    // The listener's MKT mirrors the client's KeyIDs: the client sends with
    // KeyID 1 and expects 2, so the listener receives 1 and sends 2.
    set_tcp_ao_config(
        &listener,
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        32,
        &ao_key("rtr-ao-secret", 2, 1),
        TcpAoSocketRole::Listener,
    )
    .unwrap();
    let addr = bind_listen(&listener);

    let ring = TcpAoKeyring(vec![ao_key("rtr-ao-secret", 1, 2)]);
    let stream = connect_authenticated(addr, None, Some(&ring), "rtr-test", HANDSHAKE)
        .await
        .unwrap();
    assert!(wait_accepted(&listener).await);
    drop(stream);

    let wrong = TcpAoKeyring(vec![ao_key("not-the-key", 1, 2)]);
    assert_no_session(
        &listener,
        connect_authenticated(addr, None, Some(&wrong), "rtr-test", SHORT),
        true,
    )
    .await;
    assert_no_session(
        &listener,
        connect_authenticated(addr, None, None, "rtr-test", SHORT),
        false,
    )
    .await;
}
