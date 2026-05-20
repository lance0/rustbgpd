//! BGP inbound TCP listener.

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
    /// IP address of the remote peer.
    pub peer_addr: IpAddr,
    /// Runtime TCP-AO socket information when the peer matched a configured
    /// listener MKT and Linux inspection succeeded.
    pub tcp_ao_info: Option<TcpAoInfoSnapshot>,
}

/// TCP-AO key to install on the inbound listener socket.
#[derive(Clone)]
pub struct TcpAoListenerKey {
    /// Remote peer address matched by this listener MKT.
    pub peer: IpAddr,
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
    tcp_ao_peers: Vec<IpAddr>,
}

impl BgpListener {
    /// Create a new listener bound to the given address.
    ///
    /// # Errors
    ///
    /// Returns an error if binding fails.
    #[allow(clippy::unused_async)] // Preserve the existing async public API for callers.
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
    #[allow(clippy::unused_async)] // Preserve the async API shape for callers.
    pub async fn bind_with_options(
        addr: SocketAddr,
        accept_tx: mpsc::Sender<AcceptedConnection>,
        options: ListenerSocketOptions,
    ) -> std::io::Result<Self> {
        let tcp_ao_keys = options.tcp_ao_keys.len();
        let tcp_ao_peers = options.tcp_ao_keys.iter().map(|key| key.peer).collect();
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
            tcp_ao_peers,
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
                    let tcp_ao_info = self.inspect_tcp_ao_accept(&stream, peer_ip);
                    let conn = AcceptedConnection {
                        stream,
                        peer_addr: peer_ip,
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
    ) -> Option<TcpAoInfoSnapshot> {
        if !self.tcp_ao_peers.contains(&peer_ip) {
            return None;
        }

        match crate::socket_opts::get_tcp_ao_info(stream) {
            Ok(info) => {
                info!(
                    peer = %peer_ip,
                    current_key = info.current_key,
                    rnext_key = info.rnext_key,
                    has_current_key = info.has_current_key,
                    has_rnext_key = info.has_rnext_key,
                    ao_required = info.ao_required,
                    pkt_good = info.pkt_good,
                    pkt_bad = info.pkt_bad,
                    pkt_key_not_found = info.pkt_key_not_found,
                    pkt_ao_required = info.pkt_ao_required,
                    "TCP-AO accepted socket inspected"
                );
                Some(info)
            }
            Err(err) => {
                warn!(
                    peer = %peer_ip,
                    error = %err,
                    "failed to inspect TCP-AO accepted socket"
                );
                None
            }
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
        &key.config,
        crate::socket_opts::TcpAoSocketRole::Listener,
    )
}

fn listener_tcp_ao_error(key: &TcpAoListenerKey, err: &std::io::Error) -> std::io::Error {
    std::io::Error::new(
        err.kind(),
        format!(
            "failed to install TCP-AO listener key for peer {} \
             (send_id={}, recv_id={}, algorithm={}): {err}",
            key.peer,
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

    #[tokio::test]
    async fn bind_socket2_listener_installs_tcp_ao_keys_before_listen() {
        let installed = RefCell::new(Vec::new());
        let options = ListenerSocketOptions {
            tcp_ao_keys: vec![TcpAoListenerKey {
                peer: IpAddr::from(Ipv4Addr::new(192, 0, 2, 1)),
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
}
