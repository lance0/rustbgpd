use std::time::Duration;

use rustbgpd_transport::BgpListener;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
mod inbound_auth {
    use std::io::Write;
    use std::net::{IpAddr, SocketAddr};
    use std::time::Duration;

    use rustbgpd_transport::{
        AcceptedConnection, BgpListener, ListenerSocketOptions, Md5ListenerKey,
        TcpAoListenerOwnerKind, TtlSecurityListenerPolicy, set_tcp_md5sig,
    };
    use tokio::io::AsyncReadExt;
    use tokio::sync::mpsc;

    const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
    const ACCEPT_TIMEOUT: Duration = Duration::from_secs(2);
    const READ_TIMEOUT: Duration = Duration::from_secs(1);

    async fn bind_listener(
        options: ListenerSocketOptions,
    ) -> (SocketAddr, mpsc::Receiver<AcceptedConnection>) {
        let (accept_tx, accept_rx) = mpsc::channel(4);
        let listener =
            BgpListener::bind_with_options("127.0.0.1:0".parse().unwrap(), accept_tx, options)
                .await
                .expect("listener bind with inbound auth options");
        let addr = listener.local_addr().unwrap();
        tokio::spawn(listener.run());
        (addr, accept_rx)
    }

    /// Blocking loopback client. `md5_password` signs every segment for the
    /// server address; `source` binds an explicit 127/8 source address; `ttl`
    /// overrides the outgoing IPv4 TTL.
    fn connect_client(
        server: SocketAddr,
        source: Option<IpAddr>,
        md5_password: Option<&str>,
        ttl: Option<u32>,
    ) -> std::io::Result<std::net::TcpStream> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )?;
        if let Some(password) = md5_password {
            set_tcp_md5sig(&socket, server, password)?;
        }
        if let Some(ttl) = ttl {
            socket.set_ttl_v4(ttl)?;
        }
        if let Some(source) = source {
            socket.bind(&SocketAddr::new(source, 0).into())?;
        }
        socket.connect_timeout(&server.into(), CONNECT_TIMEOUT)?;
        Ok(socket.into())
    }

    async fn spawn_connect(
        server: SocketAddr,
        source: Option<IpAddr>,
        md5_password: Option<String>,
        ttl: Option<u32>,
    ) -> std::io::Result<std::net::TcpStream> {
        tokio::task::spawn_blocking(move || {
            connect_client(server, source, md5_password.as_deref(), ttl)
        })
        .await
        .expect("client connect task")
    }

    async fn expect_accept(rx: &mut mpsc::Receiver<AcceptedConnection>) -> AcceptedConnection {
        tokio::time::timeout(ACCEPT_TIMEOUT, rx.recv())
            .await
            .expect("listener did not accept connection")
            .expect("accept channel closed")
    }

    /// Write from the blocking client and expect the bytes to arrive on the
    /// accepted stream.
    async fn expect_data_flows(mut client: std::net::TcpStream, mut accepted: AcceptedConnection) {
        tokio::task::spawn_blocking(move || {
            client.write_all(b"ping").expect("client write");
            // Keep the client socket open until the server has read.
            std::thread::sleep(Duration::from_millis(500));
        });
        let mut buf = [0u8; 4];
        tokio::time::timeout(READ_TIMEOUT, accepted.stream.read_exact(&mut buf))
            .await
            .expect("inbound data did not arrive on the accepted connection")
            .expect("read accepted stream");
        assert_eq!(&buf, b"ping");
    }

    /// Write from the blocking client and expect the accepted stream to see
    /// nothing: the kernel must drop the client's segments.
    async fn expect_data_blocked(
        mut client: std::net::TcpStream,
        mut accepted: AcceptedConnection,
    ) {
        tokio::task::spawn_blocking(move || {
            let _ = client.write_all(b"ping");
            std::thread::sleep(Duration::from_millis(1500));
        });
        let mut buf = [0u8; 4];
        let read = tokio::time::timeout(READ_TIMEOUT, accepted.stream.read_exact(&mut buf)).await;
        assert!(
            read.is_err(),
            "inbound data from a GTSM-violating peer reached the accepted connection"
        );
    }

    fn md5_options(peer: IpAddr, prefix_len: u8, password: &str) -> ListenerSocketOptions {
        ListenerSocketOptions {
            md5_keys: vec![Md5ListenerKey {
                peer,
                prefix_len,
                password: password.into(),
            }],
            ..ListenerSocketOptions::default()
        }
    }

    /// A static neighbor's configured MD5 password must be enforced on the
    /// inbound half: an unsigned connection may not even complete the
    /// handshake, while a correctly signed one establishes and carries data
    /// (proving the accepted child inherited the key).
    #[tokio::test]
    async fn md5_host_key_rejects_unsigned_static_inbound() {
        let password = "lan902-static-secret";
        let (addr, mut accept_rx) =
            bind_listener(md5_options("127.0.0.1".parse().unwrap(), 32, password)).await;

        let unsigned = spawn_connect(addr, None, None, None).await;
        assert!(
            unsigned.is_err(),
            "unsigned inbound connection completed against an MD5-protected static neighbor"
        );

        let signed = spawn_connect(addr, None, Some(password.to_string()), None)
            .await
            .expect("signed inbound connection");
        let accepted = expect_accept(&mut accept_rx).await;
        assert!(accepted.tcp_ao_info.is_none());
        expect_data_flows(signed, accepted).await;
    }

    /// A dynamic-neighbor range's MD5 password must be enforced for every
    /// address in the range via a prefix-scoped kernel key (TCP_MD5SIG_EXT):
    /// unsigned members are rejected, signed members establish.
    #[tokio::test]
    async fn md5_prefix_key_rejects_unsigned_dynamic_inbound() {
        let password = "lan902-dynamic-secret";
        let (addr, mut accept_rx) =
            bind_listener(md5_options("127.0.0.0".parse().unwrap(), 8, password)).await;

        let unsigned = spawn_connect(addr, Some("127.0.0.2".parse().unwrap()), None, None).await;
        assert!(
            unsigned.is_err(),
            "unsigned inbound connection completed against an MD5-protected dynamic range"
        );

        let signed = spawn_connect(
            addr,
            Some("127.0.0.3".parse().unwrap()),
            Some(password.to_string()),
            None,
        )
        .await
        .expect("signed inbound connection from dynamic range");
        let accepted = expect_accept(&mut accept_rx).await;
        assert_eq!(
            accepted.peer_addr.ip(),
            "127.0.0.3".parse::<IpAddr>().unwrap()
        );
        expect_data_flows(signed, accepted).await;
    }

    /// Peer-scoped listener keys must not affect uncovered peers on the
    /// shared listener: a peer outside every configured selector stays
    /// plaintext.
    #[tokio::test]
    async fn md5_keys_leave_uncovered_peers_plaintext() {
        let (addr, mut accept_rx) = bind_listener(md5_options(
            "127.0.0.9".parse().unwrap(),
            32,
            "covered-only",
        ))
        .await;

        let plaintext = spawn_connect(addr, None, None, None)
            .await
            .expect("uncovered plaintext inbound connection");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_flows(plaintext, accepted).await;
    }

    /// GTSM for a static neighbor: after accept, segments arriving with a
    /// TTL below 255 must be dropped in the kernel, while a compliant
    /// TTL-255 sender's data arrives.
    #[tokio::test]
    async fn ttl_security_rejects_low_ttl_static_inbound() {
        let options = ListenerSocketOptions {
            ttl_security: vec![TtlSecurityListenerPolicy {
                owner: TcpAoListenerOwnerKind::Static,
                peer: "127.0.0.1".parse().unwrap(),
                prefix_len: 32,
                enforce: true,
            }],
            ..ListenerSocketOptions::default()
        };
        let (addr, mut accept_rx) = bind_listener(options).await;

        // Default loopback TTL (64) violates strict RFC 5082 §3.2.
        let low_ttl = spawn_connect(addr, None, None, None)
            .await
            .expect("TCP handshake for low-TTL client");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_blocked(low_ttl, accepted).await;

        let compliant = spawn_connect(addr, None, None, Some(255))
            .await
            .expect("TCP handshake for TTL-255 client");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_flows(compliant, accepted).await;
    }

    /// GTSM for a dynamic range, with a static exception inside it: the
    /// range member is enforced, the static neighbor resolves to its own
    /// non-enforcing policy.
    #[tokio::test]
    async fn ttl_security_dynamic_range_with_static_exception() {
        let options = ListenerSocketOptions {
            ttl_security: vec![
                TtlSecurityListenerPolicy {
                    owner: TcpAoListenerOwnerKind::Dynamic,
                    peer: "127.0.0.0".parse().unwrap(),
                    prefix_len: 8,
                    enforce: true,
                },
                TtlSecurityListenerPolicy {
                    owner: TcpAoListenerOwnerKind::Static,
                    peer: "127.0.0.1".parse().unwrap(),
                    prefix_len: 32,
                    enforce: false,
                },
            ],
            ..ListenerSocketOptions::default()
        };
        let (addr, mut accept_rx) = bind_listener(options).await;

        let range_member = spawn_connect(addr, Some("127.0.0.7".parse().unwrap()), None, None)
            .await
            .expect("TCP handshake for dynamic-range client");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_blocked(range_member, accepted).await;

        let static_exception = spawn_connect(addr, None, None, None)
            .await
            .expect("TCP handshake for static-exception client");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_flows(static_exception, accepted).await;
    }

    /// Reload-time inventory replacement: a password change takes effect on
    /// the live listener (old rejected, new accepted), and removing the key
    /// returns the selector to plaintext.
    #[tokio::test]
    async fn replace_inbound_auth_swaps_and_removes_md5_keys() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        let (accept_tx, mut accept_rx) = mpsc::channel(4);
        let listener = BgpListener::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            accept_tx,
            md5_options(peer, 32, "old-secret"),
        )
        .await
        .expect("listener bind with initial MD5 key");
        let addr = listener.local_addr().unwrap();
        let control = listener.tcp_ao_rotation_handle();
        tokio::spawn(listener.run());

        let signed_old = spawn_connect(addr, None, Some("old-secret".to_string()), None)
            .await
            .expect("inbound signed with the initial password");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_flows(signed_old, accepted).await;

        control
            .replace_inbound_auth(
                vec![Md5ListenerKey {
                    peer,
                    prefix_len: 32,
                    password: "new-secret".into(),
                }],
                Vec::new(),
            )
            .await
            .expect("replace listener MD5 inventory");

        let stale = spawn_connect(addr, None, Some("old-secret".to_string()), None).await;
        assert!(
            stale.is_err(),
            "old password still accepted after inventory replacement"
        );
        let signed_new = spawn_connect(addr, None, Some("new-secret".to_string()), None)
            .await
            .expect("inbound signed with the replaced password");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_flows(signed_new, accepted).await;

        control
            .replace_inbound_auth(Vec::new(), Vec::new())
            .await
            .expect("remove listener MD5 inventory");
        let plaintext = spawn_connect(addr, None, None, None)
            .await
            .expect("plaintext inbound after key removal");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_flows(plaintext, accepted).await;
    }
}

#[tokio::test]
async fn socket2_backed_listener_accepts_tcp_connections() {
    let (accept_tx, mut accept_rx) = mpsc::channel(4);
    let listener = BgpListener::bind("127.0.0.1:0".parse().unwrap(), accept_tx)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let listener_task = tokio::spawn(listener.run());
    let client = TcpStream::connect(addr).await.unwrap();

    let accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
        .await
        .expect("listener did not accept connection")
        .expect("accept channel closed");

    assert_eq!(
        accepted.peer_addr.ip(),
        std::net::IpAddr::from([127, 0, 0, 1])
    );
    assert_eq!(accepted.stream.local_addr().unwrap(), addr);
    assert!(accepted.tcp_ao_info.is_none());

    drop(client);
    listener_task.abort();
}
