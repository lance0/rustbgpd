//! BGP inbound TCP listener.

use std::net::{IpAddr, SocketAddr};

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
}

/// BGP inbound listener. Accepts TCP connections and forwards them
/// to the `PeerManager` for matching against known peers.
pub struct BgpListener {
    listener: TcpListener,
    accept_tx: mpsc::Sender<AcceptedConnection>,
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
        let listener = bind_socket2_listener(addr)?;
        let bound_addr = listener.local_addr().unwrap_or(addr);
        info!(addr = %bound_addr, requested_addr = %addr, "BGP listener bound");
        Ok(Self {
            listener,
            accept_tx,
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
                    let conn = AcceptedConnection {
                        stream,
                        peer_addr: peer_ip,
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
}

fn bind_socket2_listener(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SockAddr::from(addr))?;
    socket.listen(DEFAULT_LISTEN_BACKLOG)?;
    socket.set_nonblocking(true)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}
