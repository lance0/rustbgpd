//! BGP inbound TCP listener.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::config::TcpAoConfig;
use crate::socket_opts::TcpAoInfoSnapshot;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Match Tokio's default listener backlog.
const DEFAULT_LISTEN_BACKLOG: i32 = 1024;

/// An accepted inbound TCP connection.
pub struct AcceptedConnection {
    /// The raw TCP stream for the accepted connection.
    pub stream: TcpStream,
    /// Socket address of the remote peer, including IPv6 scope when available.
    pub peer_addr: SocketAddr,
    /// Runtime TCP-AO socket information when the peer matched a configured
    /// listener MKT and Linux inspection succeeded.
    pub tcp_ao_info: Option<TcpAoInfoSnapshot>,
}

/// TCP-AO key to install on the inbound listener socket.
#[derive(Clone)]
pub struct TcpAoListenerKey {
    /// Remote network address matched by this listener MKT.
    pub peer: IpAddr,
    /// Prefix length for the remote network.
    pub prefix_len: u8,
    /// TCP-AO key configuration for the peer.
    pub config: TcpAoConfig,
}

/// Socket options installed before the BGP listener enters `listen(2)`.
#[derive(Clone, Default)]
pub struct ListenerSocketOptions {
    /// Static-neighbor TCP-AO MKTs for passive opens.
    pub tcp_ao_keys: Vec<TcpAoListenerKey>,
}

/// BGP inbound listener. Accepts TCP connections and forwards them
/// to the `PeerManager` for matching against known peers.
pub struct BgpListener {
    listener: TcpListener,
    accept_tx: mpsc::Sender<AcceptedConnection>,
    tcp_ao_keys: TcpAoListenerKeyIndex,
}

/// Immutable, family-split prefix-length index for listener MKTs.
///
/// Lookup performs at most 33 IPv4 or 129 IPv6 hash probes regardless of the
/// configured key count. When validated overlapping ranges are present, the
/// lowest original index wins, preserving the previous linear-scan semantics.
struct TcpAoListenerKeyIndex {
    keys: Vec<TcpAoListenerKey>,
    v4: Vec<HashMap<u32, usize>>,
    v6: Vec<HashMap<u128, usize>>,
}

impl TcpAoListenerKeyIndex {
    fn new(keys: Vec<TcpAoListenerKey>) -> Self {
        let mut index = Self {
            v4: (0..=32).map(|_| HashMap::new()).collect(),
            v6: (0..=128).map(|_| HashMap::new()).collect(),
            keys,
        };
        for (key_index, key) in index.keys.iter().enumerate() {
            match key.peer {
                IpAddr::V4(addr) if key.prefix_len <= 32 => {
                    index.v4[usize::from(key.prefix_len)]
                        .entry(mask_v4(addr.into(), key.prefix_len))
                        .or_insert(key_index);
                }
                IpAddr::V6(addr) if key.prefix_len <= 128 => {
                    index.v6[usize::from(key.prefix_len)]
                        .entry(mask_v6(addr.into(), key.prefix_len))
                        .or_insert(key_index);
                }
                _ => {}
            }
        }
        index
    }

    fn find(&self, addr: IpAddr) -> Option<&TcpAoListenerKey> {
        let key_index = match addr {
            IpAddr::V4(addr) => self
                .v4
                .iter()
                .enumerate()
                .filter_map(|(prefix_len, bucket)| {
                    bucket.get(&mask_v4(
                        addr.into(),
                        u8::try_from(prefix_len).expect("IPv4 index is bounded to 32"),
                    ))
                })
                .min(),
            IpAddr::V6(addr) => self
                .v6
                .iter()
                .enumerate()
                .filter_map(|(prefix_len, bucket)| {
                    bucket.get(&mask_v6(
                        addr.into(),
                        u8::try_from(prefix_len).expect("IPv6 index is bounded to 128"),
                    ))
                })
                .min(),
        }?;
        self.keys.get(*key_index)
    }
}

fn mask_v4(addr: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        addr & (u32::MAX << (32 - prefix_len))
    }
}

fn mask_v6(addr: u128, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        addr & (u128::MAX << (128 - prefix_len))
    }
}

impl BgpListener {
    /// Create a new listener bound to the given address.
    ///
    /// # Errors
    ///
    /// Returns an error if binding fails.
    #[allow(
        clippy::unused_async,
        reason = "preserve the existing async public API for callers"
    )]
    pub async fn bind(
        addr: SocketAddr,
        accept_tx: mpsc::Sender<AcceptedConnection>,
    ) -> std::io::Result<Self> {
        Self::bind_with_options(addr, accept_tx, ListenerSocketOptions::default()).await
    }

    /// Create a new listener with explicit pre-listen socket options.
    ///
    /// # Errors
    ///
    /// Returns an error if binding or pre-listen option installation fails.
    #[allow(
        clippy::unused_async,
        reason = "preserve the existing async public API for callers"
    )]
    pub async fn bind_with_options(
        addr: SocketAddr,
        accept_tx: mpsc::Sender<AcceptedConnection>,
        options: ListenerSocketOptions,
    ) -> std::io::Result<Self> {
        let tcp_ao_keys = options.tcp_ao_keys.len();
        let listener = bind_socket2_listener(addr, &options)?;
        let bound_addr = listener.local_addr().unwrap_or(addr);
        info!(
            addr = %bound_addr,
            requested_addr = %addr,
            tcp_ao_keys,
            "BGP listener bound"
        );
        Ok(Self {
            listener,
            accept_tx,
            tcp_ao_keys: TcpAoListenerKeyIndex::new(options.tcp_ao_keys),
        })
    }

    /// Return the local socket address the listener is bound to.
    ///
    /// This is primarily useful for tests that bind port `0`; production
    /// callers already know the configured listen address.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS cannot report the listener's local address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the accept loop until the channel is closed.
    pub async fn run(self) {
        loop {
            match self.listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let peer_ip = peer_addr.ip();
                    debug!(%peer_ip, "inbound TCP connection");
                    let tcp_ao_info = match self.inspect_tcp_ao_accept(&stream, peer_ip) {
                        Ok(info) => info,
                        Err(err) => {
                            warn!(peer = %peer_ip, error = %err, "rejecting TCP-AO-protected inbound connection");
                            continue;
                        }
                    };
                    let conn = AcceptedConnection {
                        stream,
                        peer_addr,
                        tcp_ao_info,
                    };
                    if self.accept_tx.send(conn).await.is_err() {
                        warn!("accept channel closed, listener shutting down");
                        return;
                    }
                }
                Err(e) => {
                    error!(error = %e, "BGP listener accept error");
                }
            }
        }
    }

    fn inspect_tcp_ao_accept(
        &self,
        stream: &TcpStream,
        peer_ip: IpAddr,
    ) -> std::io::Result<Option<TcpAoInfoSnapshot>> {
        let Some(key) = self.tcp_ao_keys.find(peer_ip) else {
            return Ok(None);
        };

        match crate::socket_opts::get_tcp_ao_info(stream) {
            Ok(info) => {
                info!(
                    peer = %peer_ip,
                    current_key = info.current_key,
                    rnext_key = info.rnext_key,
                    has_current_key = info.has_current_key,
                    has_rnext_key = info.has_rnext_key,
                    ao_required = info.ao_required,
                    accept_icmps = info.accept_icmps,
                    pkt_good = info.pkt_good,
                    pkt_bad = info.pkt_bad,
                    pkt_key_not_found = info.pkt_key_not_found,
                    pkt_ao_required = info.pkt_ao_required,
                    pkt_dropped_icmp = info.pkt_dropped_icmp,
                    "TCP-AO accepted socket inspected"
                );
                if !accepted_tcp_ao_info_is_valid(&info, key.config.send_id, key.config.recv_id) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        format!(
                            "TCP-AO accepted socket state is inconsistent: expected current/rnext keys {}/{}, got has_current_key={}, current_key={}, has_rnext_key={}, rnext_key={}, pkt_bad={}, pkt_key_not_found={}, pkt_ao_required={}",
                            key.config.send_id,
                            key.config.recv_id,
                            info.has_current_key,
                            info.current_key,
                            info.has_rnext_key,
                            info.rnext_key,
                            info.pkt_bad,
                            info.pkt_key_not_found,
                            info.pkt_ao_required
                        ),
                    ));
                }
                Ok(Some(info))
            }
            Err(err) => Err(err),
        }
    }
}

fn accepted_tcp_ao_info_is_valid(
    info: &TcpAoInfoSnapshot,
    expected_send_id: u8,
    expected_recv_id: u8,
) -> bool {
    info.has_current_key
        && info.current_key == expected_send_id
        && info.has_rnext_key
        && info.rnext_key == expected_recv_id
        && info.pkt_bad == 0
        && info.pkt_key_not_found == 0
        && info.pkt_ao_required == 0
}

#[cfg(test)]
impl TcpAoListenerKey {
    fn covers(&self, addr: IpAddr) -> bool {
        match (self.peer, addr) {
            (IpAddr::V4(network), IpAddr::V4(addr)) if self.prefix_len <= 32 => {
                mask_v4(network.into(), self.prefix_len) == mask_v4(addr.into(), self.prefix_len)
            }
            (IpAddr::V6(network), IpAddr::V6(addr)) if self.prefix_len <= 128 => {
                mask_v6(network.into(), self.prefix_len) == mask_v6(addr.into(), self.prefix_len)
            }
            _ => false,
        }
    }
}

fn bind_socket2_listener(
    addr: SocketAddr,
    options: &ListenerSocketOptions,
) -> std::io::Result<TcpListener> {
    bind_socket2_listener_with(addr, options, install_listener_tcp_ao_key)
}

fn bind_socket2_listener_with<F>(
    addr: SocketAddr,
    options: &ListenerSocketOptions,
    mut install_tcp_ao: F,
) -> std::io::Result<TcpListener>
where
    F: FnMut(&Socket, &TcpAoListenerKey) -> std::io::Result<()>,
{
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SockAddr::from(addr))?;
    for key in &options.tcp_ao_keys {
        // This installs a peer-specific MKT, not the socket-wide
        // `ao_required` bit. Linux tcp_ao_required() returns true for either
        // ao_info->ao_required or a matching MKT, and tcp_inbound_hash()
        // rejects unsigned packets in that case. A global requirement would
        // also reject non-AO peers on the shared BGP listener.
        install_tcp_ao(&socket, key).map_err(|err| listener_tcp_ao_error(key, &err))?;
        debug!(peer = %key.peer, "TCP-AO listener key configured");
    }
    socket.listen(DEFAULT_LISTEN_BACKLOG)?;
    socket.set_nonblocking(true)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

fn install_listener_tcp_ao_key(socket: &Socket, key: &TcpAoListenerKey) -> std::io::Result<()> {
    crate::socket_opts::set_tcp_ao_config(
        socket,
        key.peer,
        key.prefix_len,
        &key.config,
        crate::socket_opts::TcpAoSocketRole::Listener,
    )
}

fn listener_tcp_ao_error(key: &TcpAoListenerKey, err: &std::io::Error) -> std::io::Error {
    std::io::Error::new(
        err.kind(),
        format!(
            "failed to install TCP-AO listener key for peer {}/{} \
             (send_id={}, recv_id={}, algorithm={}): {err}",
            key.peer,
            key.prefix_len,
            key.config.send_id,
            key.config.recv_id,
            key.config.algorithm.linux_name()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TcpAoAlgorithm, TcpAoConfig};
    use std::cell::RefCell;
    use std::net::Ipv4Addr;

    fn tcp_ao_config() -> TcpAoConfig {
        TcpAoConfig {
            key: "secret".to_string(),
            send_id: 1,
            recv_id: 1,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }
    }

    fn tcp_ao_info(current_key: u8, pkt_good: u64) -> TcpAoInfoSnapshot {
        TcpAoInfoSnapshot {
            has_current_key: true,
            has_rnext_key: false,
            ao_required: false,
            accept_icmps: false,
            current_key,
            rnext_key: 0,
            pkt_good,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
        }
    }

    #[test]
    fn prefix_mkt_matching_covers_v4_and_v6_without_cross_family_matches() {
        let config = tcp_ao_config();
        let v4 = TcpAoListenerKey {
            peer: "192.0.2.0".parse().unwrap(),
            prefix_len: 24,
            config: config.clone(),
        };
        let v6 = TcpAoListenerKey {
            peer: "2001:db8::".parse().unwrap(),
            prefix_len: 32,
            config,
        };
        assert!(v4.covers("192.0.2.200".parse().unwrap()));
        assert!(!v4.covers("192.0.3.1".parse().unwrap()));
        assert!(v6.covers("2001:db8:ffff::1".parse().unwrap()));
        assert!(!v6.covers("2001:db9::1".parse().unwrap()));
        assert!(!v6.covers("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn listener_key_index_matches_linear_lookup_for_exact_prefix_miss_and_families() {
        let config = tcp_ao_config();
        let keys = vec![
            TcpAoListenerKey {
                peer: "192.0.2.9".parse().unwrap(),
                prefix_len: 32,
                config: config.clone(),
            },
            TcpAoListenerKey {
                peer: "198.51.100.0".parse().unwrap(),
                prefix_len: 24,
                config: config.clone(),
            },
            TcpAoListenerKey {
                peer: "2001:db8:1::".parse().unwrap(),
                prefix_len: 48,
                config,
            },
        ];
        let probes = [
            "192.0.2.9",
            "192.0.2.10",
            "198.51.100.254",
            "198.51.101.1",
            "2001:db8:1::1234",
            "2001:db8:2::1",
        ];
        let index = TcpAoListenerKeyIndex::new(keys.clone());

        for probe in probes.map(|probe| probe.parse::<IpAddr>().unwrap()) {
            let linear = keys.iter().position(|key| key.covers(probe));
            let indexed = index
                .find(probe)
                .and_then(|found| index.keys.iter().position(|key| std::ptr::eq(key, found)));
            assert_eq!(indexed, linear, "{probe}");
        }
    }

    #[test]
    fn listener_key_index_preserves_first_match_across_many_keys() {
        let config = tcp_ao_config();
        let mut keys = vec![TcpAoListenerKey {
            peer: "10.0.0.0".parse().unwrap(),
            prefix_len: 8,
            config: config.clone(),
        }];
        keys.extend((0_u32..5_000).map(|offset| TcpAoListenerKey {
            peer: IpAddr::V4(Ipv4Addr::from(
                u32::from(Ipv4Addr::new(10, 0, 0, 0)) + offset,
            )),
            prefix_len: 32,
            config: config.clone(),
        }));
        keys.push(TcpAoListenerKey {
            peer: "2001:db8::".parse().unwrap(),
            prefix_len: 32,
            config,
        });
        let index = TcpAoListenerKeyIndex::new(keys.clone());

        for probe in ["10.0.0.0", "10.0.19.135", "10.255.255.255", "2001:db8::5"] {
            let probe = probe.parse::<IpAddr>().unwrap();
            let linear = keys.iter().position(|key| key.covers(probe));
            let indexed = index
                .find(probe)
                .and_then(|found| index.keys.iter().position(|key| std::ptr::eq(key, found)));
            assert_eq!(indexed, linear, "{probe}");
        }
        assert!(index.find("203.0.113.1".parse().unwrap()).is_none());
    }

    #[test]
    fn protected_accept_requires_expected_keys_and_clean_auth_counters() {
        let mut valid = tcp_ao_info(7, 0);
        valid.has_rnext_key = true;
        valid.rnext_key = 9;
        assert!(accepted_tcp_ao_info_is_valid(&valid, 7, 9));
        assert!(!accepted_tcp_ao_info_is_valid(&valid, 8, 9));
        assert!(!accepted_tcp_ao_info_is_valid(&valid, 7, 8));
        let mut bad = valid;
        bad.pkt_bad = 1;
        assert!(!accepted_tcp_ao_info_is_valid(&bad, 7, 9));
        let mut missing = valid;
        missing.pkt_key_not_found = 1;
        assert!(!accepted_tcp_ao_info_is_valid(&missing, 7, 9));
    }

    #[tokio::test]
    async fn bind_socket2_listener_installs_tcp_ao_keys_before_listen() {
        let installed = RefCell::new(Vec::new());
        let options = ListenerSocketOptions {
            tcp_ao_keys: vec![TcpAoListenerKey {
                peer: IpAddr::from(Ipv4Addr::new(192, 0, 2, 1)),
                prefix_len: 32,
                config: tcp_ao_config(),
            }],
        };

        let listener =
            bind_socket2_listener_with("127.0.0.1:0".parse().unwrap(), &options, |_socket, key| {
                installed.borrow_mut().push(key.peer);
                Ok(())
            })
            .unwrap();

        assert!(listener.local_addr().unwrap().port() > 0);
        assert_eq!(
            installed.into_inner(),
            vec![IpAddr::from(Ipv4Addr::new(192, 0, 2, 1))]
        );
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn bind_socket2_listener_fails_when_tcp_ao_key_install_fails() {
        let installed = RefCell::new(Vec::new());
        let options = ListenerSocketOptions {
            tcp_ao_keys: vec![TcpAoListenerKey {
                peer: IpAddr::from(Ipv4Addr::new(192, 0, 2, 1)),
                prefix_len: 32,
                config: tcp_ao_config(),
            }],
        };

        let err =
            bind_socket2_listener_with("127.0.0.1:0".parse().unwrap(), &options, |_socket, key| {
                installed.borrow_mut().push(key.peer);
                Err(std::io::Error::other("tcp-ao install failed"))
            })
            .expect_err("listener bind must fail when TCP-AO key install fails");

        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        let message = err.to_string();
        assert!(message.contains("192.0.2.1"), "{message}");
        assert!(message.contains("send_id=1"), "{message}");
        assert!(message.contains("recv_id=1"), "{message}");
        assert!(message.contains("hmac(sha256)"), "{message}");
        assert_eq!(
            installed.into_inner(),
            vec![IpAddr::from(Ipv4Addr::new(192, 0, 2, 1))]
        );
        tokio::task::yield_now().await;
    }

    /// Bounded privileged/kernel receipt for GitHub #158. Run on a Linux host
    /// with `CONFIG_TCP_AO=y`:
    /// `cargo test -p rustbgpd-transport dynamic_prefix_tcp_ao_kernel_receipt -- --ignored`
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a Linux kernel with CONFIG_TCP_AO=y"]
    async fn dynamic_prefix_tcp_ao_kernel_receipt() {
        use std::time::Duration;

        fn connect_from(
            source: Ipv4Addr,
            destination: SocketAddr,
            tcp_ao: Option<&TcpAoConfig>,
        ) -> std::io::Result<Socket> {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.bind(&SockAddr::from(SocketAddr::new(source.into(), 0)))?;
            if let Some(config) = tcp_ao {
                crate::socket_opts::set_tcp_ao_config(
                    &socket,
                    destination.ip(),
                    32,
                    config,
                    crate::socket_opts::TcpAoSocketRole::ActiveOpen,
                )?;
            }
            socket.connect_timeout(&SockAddr::from(destination), Duration::from_secs(2))?;
            Ok(socket)
        }

        let config = tcp_ao_config();
        let (accept_tx, mut accept_rx) = mpsc::channel(4);
        let listener = BgpListener::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            accept_tx,
            ListenerSocketOptions {
                tcp_ao_keys: vec![TcpAoListenerKey {
                    peer: "127.0.0.0".parse().unwrap(),
                    prefix_len: 24,
                    config: config.clone(),
                }],
            },
        )
        .await
        .unwrap();
        let destination = listener.local_addr().unwrap();
        let task = tokio::spawn(listener.run());

        let signed_config = config.clone();
        let signed = tokio::task::spawn_blocking(move || {
            connect_from(
                "127.0.0.2".parse().unwrap(),
                destination,
                Some(&signed_config),
            )
        })
        .await
        .unwrap()
        .unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            accepted.peer_addr.ip(),
            "127.0.0.2".parse::<IpAddr>().unwrap()
        );
        assert!(accepted.tcp_ao_info.is_some());

        let protected_unsigned = tokio::task::spawn_blocking(move || {
            connect_from("127.0.0.3".parse().unwrap(), destination, None)
        })
        .await
        .unwrap();
        assert!(protected_unsigned.is_err());

        let unprotected = tokio::task::spawn_blocking(move || {
            connect_from("127.0.1.2".parse().unwrap(), destination, None)
        })
        .await
        .unwrap()
        .unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            accepted.peer_addr.ip(),
            "127.0.1.2".parse::<IpAddr>().unwrap()
        );
        assert!(accepted.tcp_ao_info.is_none());

        drop((signed, unprotected));
        task.abort();
    }
}
