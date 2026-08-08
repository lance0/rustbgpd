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
        TcpAoListenerOwnerKind, TtlSecurityListenerPolicy, set_gtsm, set_tcp_md5sig,
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

    /// Dual-family loopback listener in the production shape: both family
    /// sockets behind one accept loop, with the complete both-family auth
    /// inventory routed per family by the transport layer.
    async fn bind_dual_listener(
        options: ListenerSocketOptions,
    ) -> (
        SocketAddr,
        SocketAddr,
        mpsc::Receiver<AcceptedConnection>,
        rustbgpd_transport::TcpAoListenerHandle,
    ) {
        let (accept_tx, accept_rx) = mpsc::channel(4);
        let listener = BgpListener::bind_dual_with_options(
            "127.0.0.1:0".parse().unwrap(),
            "[::1]:0".parse().unwrap(),
            accept_tx,
            options,
        )
        .await
        .expect("dual-family listener bind");
        let addrs = listener.local_addrs();
        let v4 = *addrs.iter().find(|addr| addr.is_ipv4()).unwrap();
        let v6 = *addrs.iter().find(|addr| addr.is_ipv6()).unwrap();
        let control = listener.tcp_ao_rotation_handle();
        tokio::spawn(listener.run());
        (v4, v6, accept_rx, control)
    }

    /// Blocking loopback client for either family. `md5_password` signs
    /// every segment for the server address; `source` binds an explicit
    /// loopback source address; `ttl` overrides the outgoing IPv4 TTL or
    /// IPv6 hop limit.
    fn connect_client(
        server: SocketAddr,
        source: Option<IpAddr>,
        md5_password: Option<&str>,
        ttl: Option<u32>,
    ) -> std::io::Result<std::net::TcpStream> {
        let domain = if server.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket =
            socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        if let Some(password) = md5_password {
            set_tcp_md5sig(&socket, server, password)?;
        }
        if let Some(ttl) = ttl {
            if server.is_ipv4() {
                socket.set_ttl_v4(ttl)?;
            } else {
                socket.set_unicast_hops_v6(ttl)?;
            }
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

    /// Connect with full GTSM enabled before the handshake. This makes the
    /// client send its SYN with TTL/Hop-Limit 255 and reject a passive-open
    /// SYN-ACK unless the listening socket also emitted it with 255.
    async fn spawn_gtsm_connect(
        server: SocketAddr,
        source: Option<IpAddr>,
    ) -> std::io::Result<std::net::TcpStream> {
        tokio::task::spawn_blocking(move || {
            let domain = if server.is_ipv4() {
                socket2::Domain::IPV4
            } else {
                socket2::Domain::IPV6
            };
            let socket =
                socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
            set_gtsm(&socket, server)?;
            if let Some(source) = source {
                socket.bind(&SocketAddr::new(source, 0).into())?;
            }
            socket.connect_timeout(&server.into(), CONNECT_TIMEOUT)?;
            Ok(socket.into())
        })
        .await
        .expect("GTSM client connect task")
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

        let compliant = spawn_gtsm_connect(addr, None)
            .await
            .expect("GTSM TCP handshake with TTL-255 SYN-ACK");
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

    /// Reload-time GTSM addition must raise the already-listening socket's
    /// outbound TTL before the next passive open. The GTSM client enforces
    /// TTL 255 on the SYN-ACK, so this handshake fails against the kernel's
    /// ordinary listener default even though accepted-child setup is correct.
    #[tokio::test]
    async fn replace_inbound_auth_enables_passive_open_gtsm() {
        let (accept_tx, mut accept_rx) = mpsc::channel(4);
        let listener = BgpListener::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            accept_tx,
            ListenerSocketOptions::default(),
        )
        .await
        .expect("listener bind without initial GTSM policy");
        let addr = listener.local_addr().unwrap();
        let control = listener.tcp_ao_rotation_handle();
        tokio::spawn(listener.run());

        control
            .replace_inbound_auth(
                Vec::new(),
                vec![TtlSecurityListenerPolicy {
                    owner: TcpAoListenerOwnerKind::Static,
                    peer: "127.0.0.1".parse().unwrap(),
                    prefix_len: 32,
                    enforce: true,
                }],
            )
            .await
            .expect("add GTSM policy to live listener");

        let client = spawn_gtsm_connect(addr, None)
            .await
            .expect("GTSM TCP handshake after live policy addition");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_flows(client, accepted).await;
    }

    /// LAN-907: an IPv6 neighbor's MD5 password must be enforced on the
    /// inbound half of the dual-family listener — unsigned IPv6 connections
    /// are rejected in the kernel, signed ones establish — while the
    /// sibling IPv4 key on the same listener keeps protecting its own peer.
    #[tokio::test]
    async fn md5_host_key_rejects_unsigned_static_inbound_ipv6() {
        let v6_password = "lan907-v6-secret";
        let v4_password = "lan907-v4-secret";
        let options = ListenerSocketOptions {
            md5_keys: vec![
                Md5ListenerKey {
                    peer: "::1".parse().unwrap(),
                    prefix_len: 128,
                    password: v6_password.into(),
                },
                Md5ListenerKey {
                    peer: "127.0.0.1".parse().unwrap(),
                    prefix_len: 32,
                    password: v4_password.into(),
                },
            ],
            ..ListenerSocketOptions::default()
        };
        let (v4_addr, v6_addr, mut accept_rx, _control) = bind_dual_listener(options).await;

        let unsigned = spawn_connect(v6_addr, None, None, None).await;
        assert!(
            unsigned.is_err(),
            "unsigned inbound IPv6 connection completed against an MD5-protected neighbor"
        );

        let signed = spawn_connect(v6_addr, None, Some(v6_password.to_string()), None)
            .await
            .expect("signed inbound IPv6 connection");
        let accepted = expect_accept(&mut accept_rx).await;
        assert!(accepted.peer_addr.ip().is_ipv6());
        expect_data_flows(signed, accepted).await;

        // The IPv4 key landed on the IPv4 socket, not the IPv6 one.
        let signed_v4 = spawn_connect(v4_addr, None, Some(v4_password.to_string()), None)
            .await
            .expect("signed inbound IPv4 connection");
        let accepted = expect_accept(&mut accept_rx).await;
        assert!(accepted.peer_addr.ip().is_ipv4());
        expect_data_flows(signed_v4, accepted).await;
    }

    /// LAN-907: GTSM for an IPv6 neighbor (`IPV6_MINHOPCOUNT`): after
    /// accept, segments arriving with a hop limit below 255 must be dropped
    /// in the kernel, while a compliant hop-limit-255 sender's data arrives.
    #[tokio::test]
    async fn ttl_security_rejects_low_hop_limit_static_inbound_ipv6() {
        let options = ListenerSocketOptions {
            ttl_security: vec![TtlSecurityListenerPolicy {
                owner: TcpAoListenerOwnerKind::Static,
                peer: "::1".parse().unwrap(),
                prefix_len: 128,
                enforce: true,
            }],
            ..ListenerSocketOptions::default()
        };
        let (_v4_addr, v6_addr, mut accept_rx, _control) = bind_dual_listener(options).await;

        // Default loopback hop limit (64) violates strict RFC 5082 §3.2.
        let low_hops = spawn_connect(v6_addr, None, None, None)
            .await
            .expect("TCP handshake for low-hop-limit client");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_blocked(low_hops, accepted).await;

        let compliant = spawn_gtsm_connect(v6_addr, None)
            .await
            .expect("GTSM TCP handshake with hop-limit-255 SYN-ACK");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_flows(compliant, accepted).await;
    }

    /// LAN-907 reload path: `replace_inbound_auth` fans each family's MD5
    /// inventory out to its own socket. Rotating only the IPv6 password
    /// takes effect on the IPv6 socket while the IPv4 key stays enforced
    /// and untouched.
    #[tokio::test]
    async fn replace_inbound_auth_routes_families_on_dual_listener() {
        let options = ListenerSocketOptions {
            md5_keys: vec![
                Md5ListenerKey {
                    peer: "::1".parse().unwrap(),
                    prefix_len: 128,
                    password: "v6-old".into(),
                },
                Md5ListenerKey {
                    peer: "127.0.0.1".parse().unwrap(),
                    prefix_len: 32,
                    password: "v4-secret".into(),
                },
            ],
            ..ListenerSocketOptions::default()
        };
        let (v4_addr, v6_addr, mut accept_rx, control) = bind_dual_listener(options).await;

        control
            .replace_inbound_auth(
                vec![
                    Md5ListenerKey {
                        peer: "::1".parse().unwrap(),
                        prefix_len: 128,
                        password: "v6-new".into(),
                    },
                    Md5ListenerKey {
                        peer: "127.0.0.1".parse().unwrap(),
                        prefix_len: 32,
                        password: "v4-secret".into(),
                    },
                ],
                Vec::new(),
            )
            .await
            .expect("replace dual-family listener MD5 inventory");

        let stale = spawn_connect(v6_addr, None, Some("v6-old".to_string()), None).await;
        assert!(
            stale.is_err(),
            "old IPv6 password still accepted after inventory replacement"
        );
        let signed_new = spawn_connect(v6_addr, None, Some("v6-new".to_string()), None)
            .await
            .expect("inbound IPv6 signed with the replaced password");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_flows(signed_new, accepted).await;

        let v4_still = spawn_connect(v4_addr, None, Some("v4-secret".to_string()), None)
            .await
            .expect("inbound IPv4 signed with the retained password");
        let accepted = expect_accept(&mut accept_rx).await;
        expect_data_flows(v4_still, accepted).await;
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

/// LAN-907: the daemon listens on both address families, so an inbound IPv6
/// BGP connection must establish — it could not while the listener was
/// IPv4-only — and both family sockets feed the one shared accept channel.
#[tokio::test]
async fn dual_stack_listener_accepts_ipv4_and_ipv6_inbound() {
    let (accept_tx, mut accept_rx) = mpsc::channel(4);
    let listener = BgpListener::bind_dual_with_options(
        "127.0.0.1:0".parse().unwrap(),
        "[::1]:0".parse().unwrap(),
        accept_tx,
        rustbgpd_transport::ListenerSocketOptions::default(),
    )
    .await
    .expect("dual-family listener bind");
    let addrs = listener.local_addrs();
    let v6_addr = *addrs.iter().find(|addr| addr.is_ipv6()).unwrap();
    let v4_addr = *addrs.iter().find(|addr| addr.is_ipv4()).unwrap();
    tokio::spawn(listener.run());

    let _v6_client = TcpStream::connect(v6_addr)
        .await
        .expect("inbound IPv6 BGP connection must establish");
    let accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
        .await
        .expect("listener did not accept the IPv6 connection")
        .expect("accept channel closed");
    assert!(accepted.peer_addr.ip().is_ipv6());

    let _v4_client = TcpStream::connect(v4_addr)
        .await
        .expect("inbound IPv4 BGP connection must establish");
    let accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
        .await
        .expect("listener did not accept the IPv4 connection")
        .expect("accept channel closed");
    assert!(accepted.peer_addr.ip().is_ipv4());
}

/// `IPV6_V6ONLY` is set explicitly on the IPv6 socket: a v4-mapped
/// connection can never arrive through it, so the two family sockets cannot
/// race for IPv4 clients and IPv4 peers always meet the IPv4 socket's
/// kernel auth inventory. An IPv4 connection to the IPv6 socket's port must
/// never surface on the accept channel.
#[tokio::test]
async fn ipv6_socket_never_accepts_v4_mapped_connections() {
    let (accept_tx, mut accept_rx) = mpsc::channel(4);
    let listener = BgpListener::bind_dual_with_options(
        "0.0.0.0:0".parse().unwrap(),
        "[::]:0".parse().unwrap(),
        accept_tx,
        rustbgpd_transport::ListenerSocketOptions::default(),
    )
    .await
    .expect("dual-family wildcard listener bind");
    let addrs = listener.local_addrs();
    let v6_port = addrs.iter().find(|addr| addr.is_ipv6()).unwrap().port();
    tokio::spawn(listener.run());

    // With IPV6_V6ONLY=1 nothing listens on the v4 side of the IPv6 port
    // (unless an unrelated process owns it); either way our listener must
    // not accept it.
    let _ = TcpStream::connect(("127.0.0.1", v6_port)).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(750), accept_rx.recv())
            .await
            .is_err(),
        "a v4-mapped connection reached the IPv6 BGP listener socket"
    );
}

/// Occupy `addr` with a plain OS listener so a family bind deterministically
/// fails with EADDRINUSE (SO_REUSEADDR does not defeat an active listener).
fn occupy(addr: std::net::SocketAddr) -> std::net::TcpListener {
    std::net::TcpListener::bind(addr).expect("occupier bind")
}

/// LAN-907 graceful degradation: when the IPv6 family cannot be bound the
/// daemon must keep serving IPv4 instead of failing startup.
#[tokio::test]
async fn dual_bind_serves_ipv4_when_ipv6_family_unavailable() {
    let occupier = occupy("[::1]:0".parse().unwrap());
    let port = occupier.local_addr().unwrap().port();

    let (accept_tx, mut accept_rx) = mpsc::channel(4);
    let listener = BgpListener::bind_dual_with_options(
        format!("127.0.0.1:{port}").parse().unwrap(),
        format!("[::1]:{port}").parse().unwrap(),
        accept_tx,
        rustbgpd_transport::ListenerSocketOptions::default(),
    )
    .await
    .expect("IPv6 bind failure must degrade, not fail startup");
    let addrs = listener.local_addrs();
    assert_eq!(addrs.len(), 1, "exactly one family bound: {addrs:?}");
    assert!(addrs[0].is_ipv4());
    tokio::spawn(listener.run());

    let _client = TcpStream::connect(addrs[0])
        .await
        .expect("IPv4 inbound must still establish");
    let accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
        .await
        .expect("degraded listener did not accept the IPv4 connection")
        .expect("accept channel closed");
    assert!(accepted.peer_addr.ip().is_ipv4());
}

/// LAN-907 graceful degradation, mirrored: when the IPv4 family cannot be
/// bound the daemon must keep serving IPv6.
#[tokio::test]
async fn dual_bind_serves_ipv6_when_ipv4_family_unavailable() {
    // Find a port where the v4 side is occupied and the v6 side is free.
    let mut attempt = 0;
    let (listener, mut accept_rx, _occupier) = loop {
        let occupier = occupy("127.0.0.1:0".parse().unwrap());
        let port = occupier.local_addr().unwrap().port();
        let (accept_tx, accept_rx) = mpsc::channel(4);
        match BgpListener::bind_dual_with_options(
            format!("127.0.0.1:{port}").parse().unwrap(),
            format!("[::1]:{port}").parse().unwrap(),
            accept_tx,
            rustbgpd_transport::ListenerSocketOptions::default(),
        )
        .await
        {
            Ok(listener) if listener.local_addrs().len() == 1 => {
                break (listener, accept_rx, occupier);
            }
            _ => {
                attempt += 1;
                assert!(attempt < 10, "no port with free v6 side found");
            }
        }
    };
    let addrs = listener.local_addrs();
    assert!(addrs[0].is_ipv6());
    tokio::spawn(listener.run());

    let _client = TcpStream::connect(addrs[0])
        .await
        .expect("IPv6 inbound must still establish");
    let accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
        .await
        .expect("degraded listener did not accept the IPv6 connection")
        .expect("accept channel closed");
    assert!(accepted.peer_addr.ip().is_ipv6());
}

/// Both families unavailable stays fatal, exactly as a failed single-family
/// bind was before dual-family listening.
#[tokio::test]
async fn dual_bind_fails_when_both_families_unavailable() {
    let mut attempt = 0;
    let (_v4_occupier, _v6_occupier, error) = loop {
        let v4_occupier = occupy("127.0.0.1:0".parse().unwrap());
        let port = v4_occupier.local_addr().unwrap().port();
        let Ok(v6_occupier) = std::net::TcpListener::bind(format!("[::1]:{port}")) else {
            attempt += 1;
            assert!(attempt < 10, "no port occupiable on both families found");
            continue;
        };
        let (accept_tx, _accept_rx) = mpsc::channel(4);
        let error = match BgpListener::bind_dual_with_options(
            format!("127.0.0.1:{port}").parse().unwrap(),
            format!("[::1]:{port}").parse().unwrap(),
            accept_tx,
            rustbgpd_transport::ListenerSocketOptions::default(),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("bind must fail when both families are unavailable"),
        };
        break (v4_occupier, v6_occupier, error);
    };
    let message = error.to_string();
    assert!(
        message.contains("both address families")
            && message.contains("IPv4")
            && message.contains("IPv6"),
        "error must name both families: {message}"
    );
}
