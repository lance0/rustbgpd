//! BGP inbound TCP listener.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::config::{TcpAoConfig, TcpAoKeyring};
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
    pub config: TcpAoKeyring,
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

/// Resolved ownership of an accepted peer's listener MKT under the current
/// disjoint configuration contract.
///
/// Phase 2 must add an explicit static/dynamic owner kind: a host-length
/// dynamic prefix is indistinguishable in today's public listener-key shape.
enum TcpAoListenerOwner<'a> {
    HostPrefix(&'a TcpAoListenerKey),
    ShorterPrefix(&'a TcpAoListenerKey),
}

impl TcpAoListenerOwner<'_> {
    fn key(&self) -> &TcpAoListenerKey {
        match self {
            Self::HostPrefix(key) | Self::ShorterPrefix(key) => key,
        }
    }
}

/// Immutable, family-split owner index for listener MKTs.
///
/// Resolution is deterministic: host-length selector first, otherwise
/// longest-prefix match. Once owner kind is explicit, the same buckets support
/// the required static-exact-first/dynamic-LPM rule without collapsing any MKT.
struct TcpAoListenerKeyIndex {
    keys: Vec<TcpAoListenerKey>,
    v4: Vec<HashMap<u32, Vec<usize>>>,
    v6: Vec<HashMap<u128, Vec<usize>>>,
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
                        .or_default()
                        .push(key_index);
                }
                IpAddr::V6(addr) if key.prefix_len <= 128 => {
                    index.v6[usize::from(key.prefix_len)]
                        .entry(mask_v6(addr.into(), key.prefix_len))
                        .or_default()
                        .push(key_index);
                }
                _ => {}
            }
        }
        index
    }

    fn resolve(&self, addr: IpAddr) -> Option<TcpAoListenerOwner<'_>> {
        let (exact, dynamic) = match addr {
            IpAddr::V4(addr) => {
                let value = u32::from(addr);
                let exact = self.v4[32]
                    .get(&value)
                    .and_then(|indices| indices.first())
                    .copied();
                let dynamic =
                    self.v4[..32]
                        .iter()
                        .enumerate()
                        .rev()
                        .find_map(|(prefix_len, bucket)| {
                            bucket
                                .get(&mask_v4(
                                    value,
                                    u8::try_from(prefix_len).expect("IPv4 index is bounded to 32"),
                                ))
                                .and_then(|indices| indices.first())
                                .copied()
                        });
                (exact, dynamic)
            }
            IpAddr::V6(addr) => {
                let value = u128::from(addr);
                let exact = self.v6[128]
                    .get(&value)
                    .and_then(|indices| indices.first())
                    .copied();
                let dynamic =
                    self.v6[..128]
                        .iter()
                        .enumerate()
                        .rev()
                        .find_map(|(prefix_len, bucket)| {
                            bucket
                                .get(&mask_v6(
                                    value,
                                    u8::try_from(prefix_len).expect("IPv6 index is bounded to 128"),
                                ))
                                .and_then(|indices| indices.first())
                                .copied()
                        });
                (exact, dynamic)
            }
        };
        if let Some(index) = exact {
            self.keys.get(index).map(TcpAoListenerOwner::HostPrefix)
        } else {
            dynamic
                .and_then(|index| self.keys.get(index))
                .map(TcpAoListenerOwner::ShorterPrefix)
        }
    }

    /// Return every configured protected owner whose selector covers `addr`.
    /// Validation currently makes this a singleton. Keeping the complete seam
    /// here prevents the keyring tranche from accidentally treating inherited
    /// keys from a less-specific, still-configured protected owner as foreign.
    #[allow(
        dead_code,
        reason = "consumed by the following overlap/keyring tranche"
    )]
    fn owned_union(&self, addr: IpAddr) -> Vec<&TcpAoListenerKey> {
        match addr {
            IpAddr::V4(addr) => self
                .v4
                .iter()
                .enumerate()
                .flat_map(|(prefix_len, bucket)| {
                    bucket
                        .get(&mask_v4(
                            addr.into(),
                            u8::try_from(prefix_len).expect("IPv4 index is bounded to 32"),
                        ))
                        .into_iter()
                        .flatten()
                })
                .filter_map(|index| self.keys.get(*index))
                .collect(),
            IpAddr::V6(addr) => self
                .v6
                .iter()
                .enumerate()
                .flat_map(|(prefix_len, bucket)| {
                    bucket
                        .get(&mask_v6(
                            addr.into(),
                            u8::try_from(prefix_len).expect("IPv6 index is bounded to 128"),
                        ))
                        .into_iter()
                        .flatten()
                })
                .filter_map(|index| self.keys.get(*index))
                .collect(),
        }
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
        let Some(owner) = self.tcp_ao_keys.resolve(peer_ip) else {
            return Ok(None);
        };
        let key = owner.key();

        // Compare the accepted child's inventory to a fresh raw listener
        // receipt. No secret-bearing receipt survives this accept operation.
        let receipt = crate::socket_opts::capture_tcp_ao_keyring_receipt(
            &self.listener,
            key.peer,
            key.prefix_len,
            &key.config,
            false,
        )?;
        let initial = crate::socket_opts::get_tcp_ao_info_for_receipt(
            stream,
            &receipt,
            peer_ip,
            key.peer,
            key.prefix_len,
            &key.config,
        )?;
        // Validate the handshake-selected Current and initial RNext before
        // mutating either selection. Both must identify the resolved owner's
        // inherited MKT; a deprecated key remains valid when peer-selected.
        ensure_accepted_tcp_ao_info_valid(&initial, false)?;

        let selected_key = key.config.selected().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "TCP-AO listener keyring has no selectable non-deprecated key",
            )
        })?;
        crate::socket_opts::set_tcp_ao_rnext(stream, selected_key.recv_id)?;
        let info = crate::socket_opts::get_tcp_ao_info_for_receipt(
            stream,
            &receipt,
            peer_ip,
            key.peer,
            key.prefix_len,
            &key.config,
        )?;
        ensure_accepted_tcp_ao_info_valid(&info, true)?;
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
        Ok(Some(info))
    }
}

fn ensure_accepted_tcp_ao_info_valid(
    info: &TcpAoInfoSnapshot,
    require_nondeprecated_rnext: bool,
) -> std::io::Result<()> {
    if accepted_tcp_ao_info_is_valid(info, require_nondeprecated_rnext) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "TCP-AO accepted socket state is inconsistent: has_current_key={}, current_key={}, has_rnext_key={}, rnext_key={}, pkt_bad={}, pkt_key_not_found={}, pkt_ao_required={}",
                info.has_current_key,
                info.current_key,
                info.has_rnext_key,
                info.rnext_key,
                info.pkt_bad,
                info.pkt_key_not_found,
                info.pkt_ao_required
            ),
        ))
    }
}

fn accepted_tcp_ao_info_is_valid(
    info: &TcpAoInfoSnapshot,
    require_nondeprecated_rnext: bool,
) -> bool {
    let current = info
        .keys
        .iter()
        .filter(|key| key.is_current && key.send_id == info.current_key)
        .collect::<Vec<_>>();
    let rnext = info
        .keys
        .iter()
        .filter(|key| {
            key.is_rnext
                && key.recv_id == info.rnext_key
                && (!require_nondeprecated_rnext || !key.deprecated)
        })
        .collect::<Vec<_>>();
    info.has_current_key
        && info.has_rnext_key
        && info.pkt_bad == 0
        && info.pkt_key_not_found == 0
        && info.pkt_ao_required == 0
        && current.len() == 1
        && rnext.len() == 1
        && info.keys.iter().all(|key| key.pkt_bad == 0)
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
    F: FnMut(&Socket, &TcpAoListenerKey, &TcpAoConfig) -> std::io::Result<()>,
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
        for config in &key.config {
            install_tcp_ao(&socket, key, config)
                .map_err(|err| listener_tcp_ao_error(key, config, &err))?;
            debug!(peer = %key.peer, send_id = config.send_id, "TCP-AO listener key configured");
        }
    }
    socket.listen(DEFAULT_LISTEN_BACKLOG)?;
    socket.set_nonblocking(true)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

fn install_listener_tcp_ao_key(
    socket: &Socket,
    key: &TcpAoListenerKey,
    config: &TcpAoConfig,
) -> std::io::Result<()> {
    crate::socket_opts::set_tcp_ao_config(
        socket,
        key.peer,
        key.prefix_len,
        config,
        crate::socket_opts::TcpAoSocketRole::Listener,
    )
}

fn listener_tcp_ao_error(
    key: &TcpAoListenerKey,
    config: &TcpAoConfig,
    err: &std::io::Error,
) -> std::io::Error {
    std::io::Error::new(
        err.kind(),
        format!(
            "failed to install TCP-AO listener key for peer {}/{} \
             (send_id={}, recv_id={}, algorithm={}): {err}",
            key.peer,
            key.prefix_len,
            config.send_id,
            config.recv_id,
            config.algorithm.linux_name()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TcpAoAlgorithm, TcpAoConfig};
    use std::cell::RefCell;
    use std::net::Ipv4Addr;

    fn tcp_ao_config() -> TcpAoKeyring {
        TcpAoConfig {
            key: "secret".to_string(),
            send_id: 1,
            recv_id: 1,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }
        .into()
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
            keys: vec![crate::TcpAoKeyState {
                peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                prefix_len: 32,
                send_id: current_key,
                recv_id: 9,
                algorithm: TcpAoAlgorithm::HmacSha256,
                is_current: true,
                is_rnext: true,
                preferred: false,
                deprecated: false,
                vrf_ifindex: None,
                pkt_good,
                pkt_bad: 0,
            }],
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
            let indexed = index.resolve(probe).and_then(|owner| {
                index
                    .keys
                    .iter()
                    .position(|key| std::ptr::eq(key, owner.key()))
            });
            assert_eq!(indexed, linear, "{probe}");
        }
    }

    #[test]
    fn listener_owner_resolution_prefers_host_prefix_then_shorter_lpm() {
        let config = tcp_ao_config();
        let keys = vec![
            TcpAoListenerKey {
                peer: "10.0.0.0".parse().unwrap(),
                prefix_len: 8,
                config: config.clone(),
            },
            TcpAoListenerKey {
                peer: "10.20.0.0".parse().unwrap(),
                prefix_len: 16,
                config: config.clone(),
            },
            TcpAoListenerKey {
                peer: "10.20.30.40".parse().unwrap(),
                prefix_len: 32,
                config,
            },
        ];
        let index = TcpAoListenerKeyIndex::new(keys.clone());

        for (probe, expected, exact) in [
            ("10.20.30.40", 2, true),
            ("10.20.30.41", 1, false),
            ("10.21.0.1", 0, false),
        ] {
            let owner = index.resolve(probe.parse().unwrap()).unwrap();
            let actual = index
                .keys
                .iter()
                .position(|key| std::ptr::eq(key, owner.key()))
                .unwrap();
            assert_eq!(actual, expected, "{probe}");
            assert_eq!(matches!(owner, TcpAoListenerOwner::HostPrefix(_)), exact);
        }
        assert!(index.resolve("203.0.113.1".parse().unwrap()).is_none());
    }

    #[test]
    fn listener_owner_index_retains_same_selector_keys_and_covering_union() {
        let config = tcp_ao_config();
        let keys = vec![
            TcpAoListenerKey {
                peer: "10.0.0.0".parse().unwrap(),
                prefix_len: 8,
                config: config.clone(),
            },
            TcpAoListenerKey {
                peer: "10.20.0.0".parse().unwrap(),
                prefix_len: 16,
                config: config.clone(),
            },
            TcpAoListenerKey {
                peer: "10.20.0.0".parse().unwrap(),
                prefix_len: 16,
                config,
            },
        ];
        let index = TcpAoListenerKeyIndex::new(keys);
        let union = index.owned_union("10.20.30.40".parse().unwrap());
        assert_eq!(union.len(), 3, "all covering owners/MKTs must be retained");
        assert_eq!(union.iter().filter(|key| key.prefix_len == 16).count(), 2);
    }

    #[test]
    fn protected_accept_requires_expected_keys_and_clean_auth_counters() {
        let mut valid = tcp_ao_info(7, 0);
        valid.has_rnext_key = true;
        valid.rnext_key = 9;
        assert!(accepted_tcp_ao_info_is_valid(&valid, false));
        assert!(accepted_tcp_ao_info_is_valid(&valid, true));
        let mut bad = valid.clone();
        bad.pkt_bad = 1;
        assert!(!accepted_tcp_ao_info_is_valid(&bad, false));
        let mut missing = valid;
        missing.pkt_key_not_found = 1;
        assert!(!accepted_tcp_ao_info_is_valid(&missing, false));

        let mut wrong_current = tcp_ao_info(7, 0);
        wrong_current.has_rnext_key = true;
        wrong_current.rnext_key = 9;
        wrong_current.current_key = 8;
        assert!(!accepted_tcp_ao_info_is_valid(&wrong_current, false));

        let mut wrong_rnext = tcp_ao_info(7, 0);
        wrong_rnext.has_rnext_key = true;
        wrong_rnext.rnext_key = 8;
        assert!(!accepted_tcp_ao_info_is_valid(&wrong_rnext, false));
    }

    #[test]
    fn protected_accept_initial_validation_allows_deprecated_current() {
        let mut info = tcp_ao_info(7, 0);
        info.has_rnext_key = true;
        info.rnext_key = 9;
        info.keys[0].deprecated = true;
        assert!(accepted_tcp_ao_info_is_valid(&info, false));
        assert!(!accepted_tcp_ao_info_is_valid(&info, true));
    }

    #[test]
    fn protected_accept_allows_deprecated_current_but_requires_selected_final_rnext() {
        let mut info = tcp_ao_info(7, 0);
        info.has_rnext_key = true;
        info.rnext_key = 10;
        info.keys[0].deprecated = true;
        info.keys.push(crate::TcpAoKeyState {
            peer: info.keys[0].peer,
            prefix_len: info.keys[0].prefix_len,
            send_id: 8,
            recv_id: 10,
            algorithm: TcpAoAlgorithm::HmacSha256,
            is_current: false,
            is_rnext: true,
            preferred: true,
            deprecated: false,
            vrf_ifindex: None,
            pkt_good: 0,
            pkt_bad: 0,
        });
        info.keys[0].is_rnext = false;
        assert!(accepted_tcp_ao_info_is_valid(&info, false));
        assert!(accepted_tcp_ao_info_is_valid(&info, true));

        info.keys[1].deprecated = true;
        assert!(accepted_tcp_ao_info_is_valid(&info, false));
        assert!(!accepted_tcp_ao_info_is_valid(&info, true));
    }

    #[tokio::test]
    async fn bind_socket2_listener_installs_tcp_ao_keys_before_listen() {
        let installed = RefCell::new(Vec::new());
        let mut second = tcp_ao_config().0.remove(0);
        second.send_id = 2;
        second.recv_id = 2;
        let options = ListenerSocketOptions {
            tcp_ao_keys: vec![TcpAoListenerKey {
                peer: IpAddr::from(Ipv4Addr::new(192, 0, 2, 1)),
                prefix_len: 32,
                config: TcpAoKeyring(vec![tcp_ao_config().0.remove(0), second]),
            }],
        };

        let listener = bind_socket2_listener_with(
            "127.0.0.1:0".parse().unwrap(),
            &options,
            |_socket, _key, config| {
                installed.borrow_mut().push(config.send_id);
                Ok(())
            },
        )
        .unwrap();

        assert!(listener.local_addr().unwrap().port() > 0);
        assert_eq!(installed.into_inner(), vec![1, 2]);
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn bind_socket2_listener_fails_when_tcp_ao_key_install_fails() {
        let installed = RefCell::new(Vec::new());
        let mut second = tcp_ao_config().0.remove(0);
        second.send_id = 2;
        second.recv_id = 2;
        let options = ListenerSocketOptions {
            tcp_ao_keys: vec![TcpAoListenerKey {
                peer: IpAddr::from(Ipv4Addr::new(192, 0, 2, 1)),
                prefix_len: 32,
                config: TcpAoKeyring(vec![tcp_ao_config().0.remove(0), second]),
            }],
        };

        let err = bind_socket2_listener_with(
            "127.0.0.1:0".parse().unwrap(),
            &options,
            |_socket, _key, config| {
                installed.borrow_mut().push(config.send_id);
                if config.send_id == 2 {
                    Err(std::io::Error::other("tcp-ao install failed"))
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("listener bind must fail when TCP-AO key install fails");

        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        let message = err.to_string();
        assert!(message.contains("192.0.2.1"), "{message}");
        assert!(message.contains("send_id=2"), "{message}");
        assert!(message.contains("recv_id=2"), "{message}");
        assert!(message.contains("hmac(sha256)"), "{message}");
        assert_eq!(installed.into_inner(), vec![1, 2]);
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
                signed_config.selected(),
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
        let info = accepted.tcp_ao_info.as_ref().expect("accepted AO snapshot");
        assert_eq!(info.keys.len(), 1);
        let key = &info.keys[0];
        assert_eq!(key.peer, "127.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(key.prefix_len, 24);
        let config = config.selected().unwrap();
        assert_eq!(key.send_id, config.send_id);
        assert_eq!(key.recv_id, config.recv_id);
        assert_eq!(key.algorithm, config.algorithm);
        assert!(key.is_current);
        assert!(key.is_rnext);

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
