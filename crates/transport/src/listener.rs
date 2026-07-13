//! BGP inbound TCP listener.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use crate::config::{TCP_AO_MAX_INSPECT_KEYS, TcpAoConfig, TcpAoKeyring};
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
    /// Configuration owner kind. This remains explicit even for host-length
    /// dynamic ranges so passive-open resolution never infers ownership from
    /// prefix length.
    pub owner: TcpAoListenerOwnerKind,
    /// Remote network address matched by this listener MKT.
    pub peer: IpAddr,
    /// Prefix length for the remote network.
    pub prefix_len: u8,
    /// TCP-AO key configuration for the peer.
    pub config: TcpAoKeyring,
}

/// Configuration owner of a listener MKT selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpAoListenerOwnerKind {
    /// Exact static-neighbor address.
    Static,
    /// Dynamic-neighbor prefix, including `/32` and `/128` ranges.
    Dynamic,
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

/// Immutable, family-split owner index for listener MKTs.
///
/// Resolution is deterministic: static exact match first, otherwise dynamic
/// longest-prefix match. Owner kind is explicit so a dynamic `/32` or `/128`
/// remains dynamic and cannot shadow a static neighbor by insertion order.
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

    fn resolve(&self, addr: IpAddr) -> Option<&TcpAoListenerKey> {
        let (static_exact, dynamic) = match addr {
            IpAddr::V4(addr) => {
                let value = u32::from(addr);
                let static_exact = self.v4[32]
                    .get(&value)
                    .into_iter()
                    .flatten()
                    .find(|index| self.keys[**index].owner == TcpAoListenerOwnerKind::Static)
                    .copied();
                let dynamic = self
                    .v4
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(prefix_len, bucket)| {
                        bucket
                            .get(&mask_v4(
                                value,
                                u8::try_from(prefix_len).expect("IPv4 index is bounded to 32"),
                            ))
                            .into_iter()
                            .flatten()
                            .find(|index| {
                                self.keys[**index].owner == TcpAoListenerOwnerKind::Dynamic
                            })
                            .copied()
                    });
                (static_exact, dynamic)
            }
            IpAddr::V6(addr) => {
                let value = u128::from(addr);
                let static_exact = self.v6[128]
                    .get(&value)
                    .into_iter()
                    .flatten()
                    .find(|index| self.keys[**index].owner == TcpAoListenerOwnerKind::Static)
                    .copied();
                let dynamic = self
                    .v6
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(prefix_len, bucket)| {
                        bucket
                            .get(&mask_v6(
                                value,
                                u8::try_from(prefix_len).expect("IPv6 index is bounded to 128"),
                            ))
                            .into_iter()
                            .flatten()
                            .find(|index| {
                                self.keys[**index].owner == TcpAoListenerOwnerKind::Dynamic
                            })
                            .copied()
                    });
                (static_exact, dynamic)
            }
        };
        static_exact
            .or(dynamic)
            .and_then(|index| self.keys.get(index))
    }

    /// Return every configured protected owner whose selector covers `addr`.
    /// Every returned owner's MKT inventory is expected on an accepted child;
    /// the resolved owner controls Current/RNext selection.
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
        let key = owner;
        let covering_owners = self.tcp_ao_keys.owned_union(peer_ip);
        let receipt_owners = covering_owners
            .iter()
            .map(|owned| crate::socket_opts::TcpAoMktOwner {
                peer: owned.peer,
                prefix_len: owned.prefix_len,
                keyring: &owned.config,
            })
            .collect::<Vec<_>>();

        // Compare the accepted child's inventory to the union of every
        // configured owner whose selector covers this peer. No secret-bearing
        // receipt survives this accept operation.
        let receipt =
            crate::socket_opts::capture_tcp_ao_owned_receipt(&self.listener, &receipt_owners)?;
        let initial = crate::socket_opts::get_tcp_ao_info_for_receipt(stream, &receipt, peer_ip)?;
        // Validate the handshake-selected Current and initial RNext before
        // mutating either selection. Both must identify the resolved owner's
        // inherited MKT; a deprecated key remains valid when peer-selected.
        ensure_accepted_tcp_ao_info_valid(&initial, key, false)?;

        let selected_key = key.config.selected().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "TCP-AO listener keyring has no selectable non-deprecated key",
            )
        })?;
        crate::socket_opts::set_tcp_ao_rnext(stream, selected_key.recv_id)?;
        let info = crate::socket_opts::get_tcp_ao_info_for_receipt(stream, &receipt, peer_ip)?;
        ensure_accepted_tcp_ao_info_valid(&info, key, true)?;
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
    owner: &TcpAoListenerKey,
    require_nondeprecated_rnext: bool,
) -> std::io::Result<()> {
    if accepted_tcp_ao_info_is_valid(info, owner, require_nondeprecated_rnext) {
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
    owner: &TcpAoListenerKey,
    require_nondeprecated_rnext: bool,
) -> bool {
    let selected_rnext = owner.config.selected().map(|key| key.recv_id);
    let belongs_to_owner = |state: &&crate::TcpAoKeyState| {
        owner.config.iter().any(|config| {
            config.send_id == state.send_id
                && config.recv_id == state.recv_id
                && config.algorithm == state.algorithm
        })
    };
    let current = info
        .keys
        .iter()
        .filter(|key| {
            key.peer == owner.peer
                && key.prefix_len == owner.prefix_len
                && key.is_current
                && key.send_id == info.current_key
                && belongs_to_owner(key)
        })
        .take(2)
        .count();
    let rnext = info
        .keys
        .iter()
        .filter(|key| {
            key.is_rnext
                && key.peer == owner.peer
                && key.prefix_len == owner.prefix_len
                && key.recv_id == info.rnext_key
                && belongs_to_owner(key)
                && (!require_nondeprecated_rnext
                    || (!key.deprecated && selected_rnext == Some(key.recv_id)))
        })
        .take(2)
        .count();
    info.has_current_key
        && info.has_rnext_key
        && info.pkt_bad == 0
        && info.pkt_key_not_found == 0
        && info.pkt_ao_required == 0
        && current == 1
        && rnext == 1
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
    validate_listener_tcp_ao_capacity(options)?;
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

fn validate_listener_tcp_ao_capacity(options: &ListenerSocketOptions) -> std::io::Result<()> {
    let key_count = options
        .tcp_ao_keys
        .iter()
        .try_fold(0usize, |count, owner| {
            count.checked_add(owner.config.0.len()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TCP-AO listener key count overflow",
                )
            })
        })?;
    if key_count > TCP_AO_MAX_INSPECT_KEYS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "TCP-AO listener key count {key_count} exceeds inspection limit \
                 {TCP_AO_MAX_INSPECT_KEYS}"
            ),
        ));
    }
    Ok(())
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

    fn tcp_ao_owner() -> TcpAoListenerKey {
        let mut config = tcp_ao_config();
        config.0[0].send_id = 7;
        config.0[0].recv_id = 9;
        TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Static,
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            prefix_len: 32,
            config,
        }
    }

    fn listener_options_with_key_count(key_count: usize) -> ListenerSocketOptions {
        let tcp_ao_keys = (0..key_count.div_ceil(256))
            .map(|owner_index| {
                let owner_key_count = (key_count - owner_index * 256).min(256);
                let config = (0..owner_key_count)
                    .map(|key_id| TcpAoConfig {
                        key: "secret".to_string(),
                        send_id: u8::try_from(key_id).expect("owner key count is bounded to 256"),
                        recv_id: u8::try_from(key_id).expect("owner key count is bounded to 256"),
                        algorithm: TcpAoAlgorithm::HmacSha256,
                        preferred: false,
                        deprecated: false,
                    })
                    .collect();
                TcpAoListenerKey {
                    owner: TcpAoListenerOwnerKind::Static,
                    peer: IpAddr::V4(Ipv4Addr::new(
                        192,
                        0,
                        2,
                        u8::try_from(owner_index + 1).expect("test owner index fits IPv4"),
                    )),
                    prefix_len: 32,
                    config: TcpAoKeyring(config),
                }
            })
            .collect();
        ListenerSocketOptions { tcp_ao_keys }
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
            owner: TcpAoListenerOwnerKind::Dynamic,
            peer: "192.0.2.0".parse().unwrap(),
            prefix_len: 24,
            config: config.clone(),
        };
        let v6 = TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Dynamic,
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
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "192.0.2.9".parse().unwrap(),
                prefix_len: 32,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "198.51.100.0".parse().unwrap(),
                prefix_len: 24,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
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
                .resolve(probe)
                .and_then(|owner| index.keys.iter().position(|key| std::ptr::eq(key, owner)));
            assert_eq!(indexed, linear, "{probe}");
        }
    }

    #[test]
    fn listener_owner_resolution_prefers_host_prefix_then_shorter_lpm() {
        let config = tcp_ao_config();
        let keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "10.0.0.0".parse().unwrap(),
                prefix_len: 8,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "10.20.0.0".parse().unwrap(),
                prefix_len: 16,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
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
                .position(|key| std::ptr::eq(key, owner))
                .unwrap();
            assert_eq!(actual, expected, "{probe}");
            assert_eq!(owner.owner == TcpAoListenerOwnerKind::Static, exact);
        }
        assert!(index.resolve("203.0.113.1".parse().unwrap()).is_none());
    }

    #[test]
    fn listener_owner_identity_keeps_host_length_dynamic_below_static_exact() {
        let config = tcp_ao_config();
        let keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "192.0.2.9".parse().unwrap(),
                prefix_len: 32,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: "192.0.2.9".parse().unwrap(),
                prefix_len: 32,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "2001:db8::9".parse().unwrap(),
                prefix_len: 128,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: "2001:db8::9".parse().unwrap(),
                prefix_len: 128,
                config,
            },
        ];
        let index = TcpAoListenerKeyIndex::new(keys);
        let reversed = TcpAoListenerKeyIndex::new(index.keys.iter().cloned().rev().collect());
        for candidate in [&index, &reversed] {
            for address in ["192.0.2.9", "2001:db8::9"] {
                let owner = candidate.resolve(address.parse().unwrap()).unwrap();
                assert_eq!(owner.owner, TcpAoListenerOwnerKind::Static, "{address}");
                assert_eq!(candidate.owned_union(address.parse().unwrap()).len(), 2);
            }
        }
    }

    #[test]
    fn listener_owner_index_retains_same_selector_keys_and_covering_union() {
        let config = tcp_ao_config();
        let keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "10.0.0.0".parse().unwrap(),
                prefix_len: 8,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "10.20.0.0".parse().unwrap(),
                prefix_len: 16,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
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
        let owner = tcp_ao_owner();
        let mut valid = tcp_ao_info(7, 0);
        valid.has_rnext_key = true;
        valid.rnext_key = 9;
        assert!(accepted_tcp_ao_info_is_valid(&valid, &owner, false));
        assert!(accepted_tcp_ao_info_is_valid(&valid, &owner, true));
        let mut bad = valid.clone();
        bad.pkt_bad = 1;
        assert!(!accepted_tcp_ao_info_is_valid(&bad, &owner, false));
        let mut missing = valid;
        missing.pkt_key_not_found = 1;
        assert!(!accepted_tcp_ao_info_is_valid(&missing, &owner, false));

        let mut wrong_current = tcp_ao_info(7, 0);
        wrong_current.has_rnext_key = true;
        wrong_current.rnext_key = 9;
        wrong_current.current_key = 8;
        assert!(!accepted_tcp_ao_info_is_valid(
            &wrong_current,
            &owner,
            false
        ));

        let mut wrong_rnext = tcp_ao_info(7, 0);
        wrong_rnext.has_rnext_key = true;
        wrong_rnext.rnext_key = 8;
        assert!(!accepted_tcp_ao_info_is_valid(&wrong_rnext, &owner, false));
    }

    #[test]
    fn protected_accept_initial_validation_allows_deprecated_current() {
        let owner = tcp_ao_owner();
        let mut info = tcp_ao_info(7, 0);
        info.has_rnext_key = true;
        info.rnext_key = 9;
        info.keys[0].deprecated = true;
        assert!(accepted_tcp_ao_info_is_valid(&info, &owner, false));
        assert!(!accepted_tcp_ao_info_is_valid(&info, &owner, true));
    }

    #[test]
    fn protected_accept_allows_deprecated_current_but_requires_selected_final_rnext() {
        let mut owner = tcp_ao_owner();
        owner.config.0[0].deprecated = true;
        owner.config.0.push(TcpAoConfig {
            key: "selected".to_string(),
            send_id: 8,
            recv_id: 10,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        });
        owner.config.0.push(TcpAoConfig {
            key: "other".to_string(),
            send_id: 9,
            recv_id: 11,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        });
        let mut info = tcp_ao_info(7, 0);
        info.has_rnext_key = true;
        info.rnext_key = 11;
        info.keys[0].deprecated = true;
        info.keys.push(crate::TcpAoKeyState {
            peer: info.keys[0].peer,
            prefix_len: info.keys[0].prefix_len,
            send_id: 9,
            recv_id: 11,
            algorithm: TcpAoAlgorithm::HmacSha256,
            is_current: false,
            is_rnext: true,
            preferred: false,
            deprecated: false,
            vrf_ifindex: None,
            pkt_good: 0,
            pkt_bad: 0,
        });
        info.keys.push(crate::TcpAoKeyState {
            peer: info.keys[0].peer,
            prefix_len: info.keys[0].prefix_len,
            send_id: 8,
            recv_id: 10,
            algorithm: TcpAoAlgorithm::HmacSha256,
            is_current: false,
            is_rnext: false,
            preferred: true,
            deprecated: false,
            vrf_ifindex: None,
            pkt_good: 0,
            pkt_bad: 0,
        });
        info.keys[0].is_rnext = false;
        assert!(accepted_tcp_ao_info_is_valid(&info, &owner, false));
        assert!(
            !accepted_tcp_ao_info_is_valid(&info, &owner, true),
            "an unselected non-deprecated RNext must not satisfy final validation"
        );

        info.rnext_key = 10;
        info.keys[1].is_rnext = false;
        info.keys[2].is_rnext = true;
        assert!(accepted_tcp_ao_info_is_valid(&info, &owner, true));
    }

    #[test]
    fn protected_accept_selection_must_belong_to_resolved_owner() {
        let owner = tcp_ao_owner();
        let mut info = tcp_ao_info(7, 0);
        info.has_rnext_key = true;
        info.rnext_key = 9;
        info.keys[0].peer = "192.0.2.0".parse().unwrap();
        info.keys[0].prefix_len = 24;
        assert!(
            !accepted_tcp_ao_info_is_valid(&info, &owner, false),
            "Current/RNext selected from a covering owner must not satisfy the static owner"
        );

        info.keys.push(crate::TcpAoKeyState {
            peer: owner.peer,
            prefix_len: owner.prefix_len,
            send_id: 8,
            recv_id: 10,
            algorithm: TcpAoAlgorithm::HmacSha256,
            is_current: false,
            is_rnext: false,
            preferred: true,
            deprecated: false,
            vrf_ifindex: None,
            pkt_good: 0,
            pkt_bad: 0,
        });
        assert!(!accepted_tcp_ao_info_is_valid(&info, &owner, false));
    }

    #[test]
    fn protected_accept_same_selector_selection_must_match_static_owner_keyring() {
        let owner = tcp_ao_owner();
        let mut info = tcp_ao_info(2, 0);
        info.has_rnext_key = true;
        info.rnext_key = 10;
        info.keys[0].send_id = 2;
        info.keys[0].recv_id = 10;
        assert_eq!(info.keys[0].peer, owner.peer);
        assert_eq!(info.keys[0].prefix_len, owner.prefix_len);
        assert!(
            !accepted_tcp_ao_info_is_valid(&info, &owner, false),
            "a same-selector dynamic owner's key must not satisfy static-owner selection"
        );
    }

    #[tokio::test]
    async fn bind_socket2_listener_installs_tcp_ao_keys_before_listen() {
        let installed = RefCell::new(Vec::new());
        let mut second = tcp_ao_config().0.remove(0);
        second.send_id = 2;
        second.recv_id = 2;
        let options = ListenerSocketOptions {
            tcp_ao_keys: vec![TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
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
                owner: TcpAoListenerOwnerKind::Static,
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

    #[test]
    fn listener_tcp_ao_capacity_accepts_4096_and_rejects_4097_before_install() {
        let at_limit = listener_options_with_key_count(TCP_AO_MAX_INSPECT_KEYS);
        validate_listener_tcp_ao_capacity(&at_limit).expect("4,096 listener MKTs must be valid");

        let over_limit = listener_options_with_key_count(TCP_AO_MAX_INSPECT_KEYS + 1);
        let installed = RefCell::new(0usize);
        let err = bind_socket2_listener_with(
            "127.0.0.1:0".parse().unwrap(),
            &over_limit,
            |_socket, _key, _config| {
                *installed.borrow_mut() += 1;
                Ok(())
            },
        )
        .expect_err("4,097 listener MKTs must fail before socket programming");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("4097"), "{err}");
        assert_eq!(*installed.borrow(), 0);
    }

    /// Bounded privileged/kernel receipt for GitHub #158. Run on a Linux host
    /// with `CONFIG_TCP_AO=y`:
    /// `cargo test -p rustbgpd-transport overlapping_tcp_ao_owned_union_kernel_receipt -- --ignored`
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a Linux kernel with CONFIG_TCP_AO=y"]
    #[expect(
        clippy::too_many_lines,
        reason = "privileged receipt covers overlapping owners and a two-key lifecycle"
    )]
    async fn overlapping_tcp_ao_owned_union_kernel_receipt() {
        use std::time::Duration;

        fn connect_from(
            source: Ipv4Addr,
            destination: SocketAddr,
            tcp_ao: Option<&TcpAoKeyring>,
        ) -> std::io::Result<Socket> {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.bind(&SockAddr::from(SocketAddr::new(source.into(), 0)))?;
            if let Some(keyring) = tcp_ao {
                for (index, config) in keyring.startup_order().into_iter().enumerate() {
                    let role = if index == 0 {
                        crate::socket_opts::TcpAoSocketRole::ActiveOpen
                    } else {
                        crate::socket_opts::TcpAoSocketRole::Listener
                    };
                    crate::socket_opts::set_tcp_ao_config(
                        &socket,
                        destination.ip(),
                        32,
                        config,
                        role,
                    )?;
                }
            }
            socket.connect_timeout(&SockAddr::from(destination), Duration::from_secs(2))?;
            Ok(socket)
        }

        let covering_config = TcpAoKeyring(vec![TcpAoConfig {
            key: "kernel-receipt-covering-secret".to_string(),
            send_id: 1,
            recv_id: 1,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }]);
        let static_config = TcpAoKeyring(vec![
            TcpAoConfig {
                key: "kernel-receipt-old-secret".to_string(),
                send_id: 2,
                recv_id: 2,
                algorithm: TcpAoAlgorithm::HmacSha256,
                preferred: false,
                deprecated: true,
            },
            TcpAoConfig {
                key: "kernel-receipt-next-secret".to_string(),
                send_id: 3,
                recv_id: 3,
                algorithm: TcpAoAlgorithm::HmacSha256,
                preferred: true,
                deprecated: false,
            },
        ]);
        let (accept_tx, mut accept_rx) = mpsc::channel(4);
        let listener = BgpListener::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            accept_tx,
            ListenerSocketOptions {
                tcp_ao_keys: vec![
                    TcpAoListenerKey {
                        owner: TcpAoListenerOwnerKind::Dynamic,
                        peer: "127.0.0.0".parse().unwrap(),
                        prefix_len: 24,
                        config: covering_config,
                    },
                    TcpAoListenerKey {
                        owner: TcpAoListenerOwnerKind::Static,
                        peer: "127.0.0.2".parse().unwrap(),
                        prefix_len: 32,
                        config: static_config.clone(),
                    },
                ],
            },
        )
        .await
        .unwrap();
        let destination = listener.local_addr().unwrap();
        let task = tokio::spawn(listener.run());

        let signed_config = static_config.clone();
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
        let info = accepted.tcp_ao_info.as_ref().expect("accepted AO snapshot");
        assert_eq!(info.current_key, 3);
        assert_eq!(info.rnext_key, 3);
        assert_eq!(
            info.keys.len(),
            3,
            "GET_KEYS must return the complete covering-owner union"
        );
        let find_key = |peer: &str, prefix_len, send_id, recv_id| {
            let peer = peer.parse::<IpAddr>().unwrap();
            info.keys
                .iter()
                .find(|key| {
                    key.peer == peer
                        && key.prefix_len == prefix_len
                        && key.send_id == send_id
                        && key.recv_id == recv_id
                })
                .unwrap_or_else(|| {
                    panic!(
                        "missing GET_KEYS entry {peer}/{prefix_len} \
                         send_id={send_id} recv_id={recv_id}: {:?}",
                        info.keys
                    )
                })
        };
        let covering = find_key("127.0.0.0", 24, 1, 1);
        assert_eq!(covering.algorithm, TcpAoAlgorithm::HmacSha256);
        assert!(!covering.is_current);
        assert!(!covering.is_rnext);
        let old = find_key("127.0.0.2", 32, 2, 2);
        assert_eq!(old.algorithm, TcpAoAlgorithm::HmacSha256);
        assert!(old.deprecated);
        assert!(!old.preferred);
        assert!(!old.is_current);
        assert!(!old.is_rnext);
        let selected = find_key("127.0.0.2", 32, 3, 3);
        assert_eq!(selected.algorithm, TcpAoAlgorithm::HmacSha256);
        assert!(selected.preferred);
        assert!(!selected.deprecated);
        assert!(selected.is_current);
        assert!(selected.is_rnext);
        let rendered = format!("{info:?}");
        assert!(!rendered.contains("kernel-receipt-covering-secret"));
        assert!(!rendered.contains("kernel-receipt-old-secret"));
        assert!(!rendered.contains("kernel-receipt-next-secret"));

        let mut mismatched = static_config.clone();
        mismatched.0[1].key = "kernel-receipt-wrong-secret".to_string();
        let protected_mismatch = tokio::task::spawn_blocking(move || {
            connect_from("127.0.0.2".parse().unwrap(), destination, Some(&mismatched))
        })
        .await
        .unwrap();
        assert!(
            protected_mismatch.is_err(),
            "selected-key secret mismatch must fail closed"
        );

        let protected_unsigned = tokio::task::spawn_blocking(move || {
            connect_from("127.0.0.2".parse().unwrap(), destination, None)
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
