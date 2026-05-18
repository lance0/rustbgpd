//! Platform-specific socket options for BGP sessions.
//!
//! TCP MD5 authentication (RFC 2385) and GTSM / TTL security (RFC 5082)
//! require raw `setsockopt` calls that are only available on Linux.
//!
//! These are the only `unsafe` blocks in the project — they exist because
//! there is no safe Rust API for `TCP_MD5SIG` or `IP_MINTTL`.

use std::io;
#[cfg(target_os = "linux")]
use std::net::IpAddr;
use std::net::SocketAddr;

#[cfg(target_os = "linux")]
use crate::config::{TcpAoAlgorithm, TcpAoConfig};
use socket2::Socket;

/// Set TCP MD5 signature on a socket for a specific peer.
///
/// This implements RFC 2385 by calling `setsockopt(TCP_MD5SIG)` on Linux.
/// The password is associated with a specific peer address.
#[cfg(target_os = "linux")]
#[allow(unsafe_code, clippy::cast_possible_truncation)]
pub fn set_tcp_md5sig(socket: &Socket, peer: SocketAddr, password: &str) -> io::Result<()> {
    use std::mem;

    const TCP_MD5SIG: libc::c_int = 14;

    #[allow(clippy::struct_field_names)]
    #[repr(C)]
    struct TcpMd5Sig {
        tcpm_addr: libc::sockaddr_storage,
        tcpm_flags: u8,
        tcpm_prefixlen: u8,
        tcpm_keylen: u16,
        tcpm_ifindex: libc::c_int,
        tcpm_key: [u8; 80],
    }

    let peer_sa: socket2::SockAddr = peer.into();
    let mut sig: TcpMd5Sig = unsafe { mem::zeroed() };

    // Copy the sockaddr into the struct
    let sa_bytes = peer_sa.as_ptr().cast::<u8>();
    let sa_len = peer_sa.len() as usize;
    let dst = (&raw mut sig.tcpm_addr).cast::<u8>();
    unsafe {
        std::ptr::copy_nonoverlapping(sa_bytes, dst, sa_len);
    }

    let key_bytes = password.as_bytes();
    if key_bytes.len() > 80 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MD5 password exceeds 80 bytes",
        ));
    }
    // Safe: we checked key_bytes.len() <= 80, which fits in u16
    sig.tcpm_keylen = key_bytes.len() as u16;
    sig.tcpm_key[..key_bytes.len()].copy_from_slice(key_bytes);

    let fd = {
        use std::os::unix::io::AsRawFd;
        socket.as_raw_fd()
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_MD5SIG,
            (&raw const sig).cast(),
            // Safe: size_of TcpMd5Sig is well under u32::MAX
            mem::size_of::<TcpMd5Sig>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn set_tcp_md5sig(_socket: &Socket, _peer: SocketAddr, _password: &str) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP MD5 authentication is only supported on Linux",
    ))
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpAoSocketRole {
    ActiveOpen,
    Listener,
}

/// A single Linux TCP-AO Master Key Tuple for a peer address.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct TcpAoKey<'a> {
    pub(crate) peer: IpAddr,
    pub(crate) scope_id: u32,
    pub(crate) prefix_len: u8,
    pub(crate) send_id: u8,
    pub(crate) recv_id: u8,
    pub(crate) algorithm: TcpAoAlgorithm,
    pub(crate) mac_len: u8,
    pub(crate) key: &'a [u8],
    pub(crate) set_current: bool,
    pub(crate) set_rnext: bool,
}

#[cfg(target_os = "linux")]
#[repr(C, align(8))]
struct TcpAoAdd {
    addr: libc::sockaddr_storage,
    alg_name: [u8; 64],
    ifindex: libc::c_int,
    flags: u32,
    reserved2: u16,
    prefix: u8,
    sndid: u8,
    rcvid: u8,
    maclen: u8,
    keyflags: u8,
    keylen: u8,
    key: [u8; 80],
}

#[cfg(target_os = "linux")]
#[repr(C, align(8))]
#[allow(dead_code)]
struct TcpAoInfoOpt {
    flags: u32,
    reserved2: u16,
    current_key: u8,
    rnext: u8,
    pkt_good: u64,
    pkt_bad: u64,
    pkt_key_not_found: u64,
    pkt_ao_required: u64,
    pkt_dropped_icmp: u64,
}

/// Result of probing whether the running host supports Linux TCP-AO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpAoSupport {
    Supported,
    Unsupported,
    ProbeFailed(String),
}

#[cfg(target_os = "linux")]
const TCP_AO_ADD_KEY: libc::c_int = 38;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
const TCP_AO_INFO: libc::c_int = 40;
#[cfg(target_os = "linux")]
const TCP_AO_MAXKEYLEN: usize = 80;
#[cfg(target_os = "linux")]
const TCP_AO_ADD_SET_CURRENT: u32 = 1 << 0;
#[cfg(target_os = "linux")]
const TCP_AO_ADD_SET_RNEXT: u32 = 1 << 1;

/// Add a TCP-AO key to a socket.
///
/// The public transport config only carries one key per static neighbor in
/// the first runtime slice. Active-open sockets install it as both current and
/// rnext so the initial SYN is signed. Listener sockets install the same MKT
/// without current/rnext flags because Linux rejects those flags on listening
/// sockets.
#[cfg(target_os = "linux")]
pub(crate) fn set_tcp_ao_config(
    socket: &Socket,
    peer: IpAddr,
    config: &TcpAoConfig,
    role: TcpAoSocketRole,
) -> io::Result<()> {
    let key = tcp_ao_key_from_config(peer, config, role);
    set_tcp_ao_key(socket, &key)
}

#[cfg(target_os = "linux")]
fn tcp_ao_key_from_config(
    peer: IpAddr,
    config: &TcpAoConfig,
    role: TcpAoSocketRole,
) -> TcpAoKey<'_> {
    let prefix_len = match peer {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    TcpAoKey {
        peer,
        scope_id: 0,
        prefix_len,
        send_id: config.send_id,
        recv_id: config.recv_id,
        algorithm: config.algorithm,
        mac_len: 0,
        key: config.key.as_bytes(),
        set_current: matches!(role, TcpAoSocketRole::ActiveOpen),
        set_rnext: matches!(role, TcpAoSocketRole::ActiveOpen),
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub(crate) fn set_tcp_ao_config(
    _socket: &Socket,
    _peer: std::net::IpAddr,
    _config: &crate::config::TcpAoConfig,
    _role: TcpAoSocketRole,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-AO authentication is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TcpAoSocketRole {
    ActiveOpen,
    Listener,
}

/// Add a TCP-AO key to a socket.
#[cfg(target_os = "linux")]
#[allow(dead_code, unsafe_code, clippy::cast_possible_truncation)]
pub(crate) fn set_tcp_ao_key(socket: &Socket, key: &TcpAoKey<'_>) -> io::Result<()> {
    let add = build_tcp_ao_add(key)?;
    let fd = {
        use std::os::unix::io::AsRawFd;
        socket.as_raw_fd()
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_AO_ADD_KEY,
            (&raw const add).cast(),
            std::mem::size_of::<TcpAoAdd>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Probe TCP-AO support without relying on distro package metadata.
#[cfg(target_os = "linux")]
#[must_use]
pub fn probe_tcp_ao_support() -> TcpAoSupport {
    use socket2::{Domain, Protocol, Type};

    let (socket, peer) = match Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)) {
        Ok(socket) => (socket, IpAddr::from([0, 0, 0, 0])),
        Err(ipv4_err) => match Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)) {
            Ok(socket) => (socket, IpAddr::from([0u16; 8])),
            Err(ipv6_err) => {
                return TcpAoSupport::ProbeFailed(format!(
                    "IPv4 probe socket failed: {ipv4_err}; IPv6 probe socket failed: {ipv6_err}"
                ));
            }
        },
    };
    let key = TcpAoKey {
        peer,
        scope_id: 0,
        prefix_len: 0,
        send_id: 100,
        recv_id: 100,
        algorithm: TcpAoAlgorithm::HmacSha1,
        mac_len: 0,
        key: b"rustbgpd-tcp-ao-probe",
        set_current: false,
        set_rnext: false,
    };

    match set_tcp_ao_key(&socket, &key) {
        Ok(()) => TcpAoSupport::Supported,
        Err(err) if err.raw_os_error() == Some(libc::ENOPROTOOPT) => TcpAoSupport::Unsupported,
        Err(err) => TcpAoSupport::ProbeFailed(err.to_string()),
    }
}

#[cfg(not(target_os = "linux"))]
#[must_use]
pub fn probe_tcp_ao_support() -> TcpAoSupport {
    TcpAoSupport::Unsupported
}

#[cfg(target_os = "linux")]
fn build_tcp_ao_add(key: &TcpAoKey<'_>) -> io::Result<TcpAoAdd> {
    let max_prefix = match key.peer {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    if key.prefix_len > max_prefix {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("TCP-AO prefix length exceeds {max_prefix}"),
        ));
    }
    if key.key.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP-AO key must not be empty",
        ));
    }
    if key.key.len() > TCP_AO_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP-AO key exceeds 80 bytes",
        ));
    }

    let mut add: TcpAoAdd = unsafe { std::mem::zeroed() };
    write_sockaddr(&mut add.addr, key.peer, key.scope_id);
    write_alg_name(&mut add.alg_name, key.algorithm.linux_name())?;
    if key.set_current {
        add.flags |= TCP_AO_ADD_SET_CURRENT;
    }
    if key.set_rnext {
        add.flags |= TCP_AO_ADD_SET_RNEXT;
    }
    add.prefix = key.prefix_len;
    add.sndid = key.send_id;
    add.rcvid = key.recv_id;
    add.maclen = key.mac_len;
    add.keylen = u8::try_from(key.key.len()).expect("TCP-AO key length was validated");
    add.key[..key.key.len()].copy_from_slice(key.key);

    Ok(add)
}

#[cfg(target_os = "linux")]
fn write_alg_name(dst: &mut [u8; 64], name: &str) -> io::Result<()> {
    if name.len() >= dst.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP-AO algorithm name exceeds Linux UAPI buffer",
        ));
    }
    dst[..name.len()].copy_from_slice(name.as_bytes());
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn write_sockaddr(storage: &mut libc::sockaddr_storage, peer: IpAddr, scope_id: u32) {
    match peer {
        IpAddr::V4(addr) => {
            let sin = unsafe { &mut *(std::ptr::from_mut(storage).cast::<libc::sockaddr_in>()) };
            sin.sin_family =
                libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET fits sa_family_t");
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from(addr).to_be(),
            };
        }
        IpAddr::V6(addr) => {
            let sin6 = unsafe { &mut *(std::ptr::from_mut(storage).cast::<libc::sockaddr_in6>()) };
            sin6.sin6_family =
                libc::sa_family_t::try_from(libc::AF_INET6).expect("AF_INET6 fits sa_family_t");
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: addr.octets(),
            };
            sin6.sin6_scope_id = scope_id;
        }
    }
}

/// Enable GTSM (Generalized TTL Security Mechanism, RFC 5082) on a socket.
///
/// Sets `IP_MINTTL` to 254 (accept only TTL >= 254, i.e., directly connected)
/// and sets outgoing TTL to 255.
#[cfg(target_os = "linux")]
#[allow(unsafe_code, clippy::cast_possible_truncation)]
pub fn set_gtsm(socket: &Socket) -> io::Result<()> {
    const IP_MINTTL: libc::c_int = 21;
    let min_ttl: libc::c_int = 254;

    let fd = {
        use std::os::unix::io::AsRawFd;
        socket.as_raw_fd()
    };

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            IP_MINTTL,
            (&raw const min_ttl).cast(),
            // Safe: size_of c_int is well under u32::MAX
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    // socket2 0.6 renamed `set_ttl` → `set_ttl_v4` for the IPv4 path.
    // GTSM (RFC 5082) on this socket is IPv4-only, so the IPv4-specific
    // setter is the correct call.
    socket.set_ttl_v4(255)?;

    Ok(())
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn set_gtsm(_socket: &Socket) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "GTSM / TTL security is only supported on Linux",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::mem;

    fn base_key() -> TcpAoKey<'static> {
        TcpAoKey {
            peer: IpAddr::from([192, 0, 2, 1]),
            scope_id: 0,
            prefix_len: 32,
            send_id: 7,
            recv_id: 9,
            algorithm: TcpAoAlgorithm::HmacSha256,
            mac_len: 12,
            key: b"0123456789abcdef",
            set_current: true,
            set_rnext: true,
        }
    }

    #[test]
    fn tcp_ao_uapi_layout_matches_linux_header() {
        assert_eq!(mem::size_of::<TcpAoAdd>(), 288);
        assert_eq!(mem::align_of::<TcpAoAdd>(), 8);
        assert_eq!(mem::offset_of!(TcpAoAdd, addr), 0);
        assert_eq!(mem::offset_of!(TcpAoAdd, alg_name), 128);
        assert_eq!(mem::offset_of!(TcpAoAdd, ifindex), 192);
        assert_eq!(mem::offset_of!(TcpAoAdd, flags), 196);
        assert_eq!(mem::offset_of!(TcpAoAdd, prefix), 202);
        assert_eq!(mem::offset_of!(TcpAoAdd, sndid), 203);
        assert_eq!(mem::offset_of!(TcpAoAdd, rcvid), 204);
        assert_eq!(mem::offset_of!(TcpAoAdd, maclen), 205);
        assert_eq!(mem::offset_of!(TcpAoAdd, keyflags), 206);
        assert_eq!(mem::offset_of!(TcpAoAdd, keylen), 207);
        assert_eq!(mem::offset_of!(TcpAoAdd, key), 208);

        assert_eq!(mem::size_of::<TcpAoInfoOpt>(), 48);
        assert_eq!(mem::align_of::<TcpAoInfoOpt>(), 8);
        assert_eq!(mem::offset_of!(TcpAoInfoOpt, current_key), 6);
        assert_eq!(mem::offset_of!(TcpAoInfoOpt, rnext), 7);
        assert_eq!(mem::offset_of!(TcpAoInfoOpt, pkt_good), 8);
    }

    #[test]
    fn tcp_ao_constants_match_linux_header() {
        assert_eq!(TCP_AO_ADD_KEY, 38);
        assert_eq!(TCP_AO_INFO, 40);
        assert_eq!(TCP_AO_MAXKEYLEN, 80);
        assert_eq!(TCP_AO_ADD_SET_CURRENT, 1);
        assert_eq!(TCP_AO_ADD_SET_RNEXT, 2);
    }

    #[test]
    fn tcp_ao_add_encodes_peer_key_and_algorithm() {
        let add = build_tcp_ao_add(&base_key()).unwrap();

        assert_eq!(add.prefix, 32);
        assert_eq!(add.sndid, 7);
        assert_eq!(add.rcvid, 9);
        assert_eq!(add.maclen, 12);
        assert_eq!(add.keylen, 16);
        assert_eq!(add.flags, TCP_AO_ADD_SET_CURRENT | TCP_AO_ADD_SET_RNEXT);
        assert_eq!(&add.key[..16], b"0123456789abcdef");

        let alg = add
            .alg_name
            .iter()
            .take_while(|&&c| c != 0)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(alg, b"hmac(sha256)");

        let sin = unsafe { &*(std::ptr::from_ref(&add.addr).cast::<libc::sockaddr_in>()) };
        assert_eq!(
            sin.sin_family,
            libc::sa_family_t::try_from(libc::AF_INET).unwrap()
        );
        assert_eq!(sin.sin_port, 0);
        assert_eq!(
            sin.sin_addr.s_addr,
            u32::from(std::net::Ipv4Addr::new(192, 0, 2, 1)).to_be()
        );
    }

    #[test]
    fn tcp_ao_add_encodes_ipv6_peer() {
        let key = TcpAoKey {
            peer: "2001:db8::1".parse().unwrap(),
            scope_id: 42,
            prefix_len: 128,
            algorithm: TcpAoAlgorithm::CmacAes128,
            ..base_key()
        };
        let add = build_tcp_ao_add(&key).unwrap();
        let sin6 = unsafe { &*(std::ptr::from_ref(&add.addr).cast::<libc::sockaddr_in6>()) };
        assert_eq!(
            sin6.sin6_family,
            libc::sa_family_t::try_from(libc::AF_INET6).unwrap()
        );
        assert_eq!(sin6.sin6_port, 0);
        assert_eq!(sin6.sin6_scope_id, 42);
        assert_eq!(
            sin6.sin6_addr.s6_addr,
            "2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
        );
    }

    #[test]
    fn tcp_ao_rejects_invalid_prefix_and_key_lengths() {
        let mut key = base_key();
        key.prefix_len = 33;
        assert!(build_tcp_ao_add(&key).is_err());

        let mut key = base_key();
        key.key = b"";
        assert!(build_tcp_ao_add(&key).is_err());

        let too_long = [0u8; TCP_AO_MAXKEYLEN + 1];
        let mut key = base_key();
        key.key = &too_long;
        assert!(build_tcp_ao_add(&key).is_err());
    }

    #[test]
    fn tcp_ao_rejects_algorithm_names_without_nul_room() {
        let mut alg_name = [0u8; 64];
        assert!(write_alg_name(&mut alg_name, &"x".repeat(64)).is_err());
    }

    #[test]
    fn tcp_ao_config_for_active_open_sets_current_and_rnext() {
        let config = TcpAoConfig {
            key: "secret".to_string(),
            send_id: 10,
            recv_id: 11,
            algorithm: TcpAoAlgorithm::HmacSha1,
            preferred: false,
            deprecated: false,
        };

        let key = tcp_ao_key_from_config(
            IpAddr::from([198, 51, 100, 1]),
            &config,
            TcpAoSocketRole::ActiveOpen,
        );

        assert_eq!(key.prefix_len, 32);
        assert_eq!(key.send_id, 10);
        assert_eq!(key.recv_id, 11);
        assert_eq!(key.algorithm, TcpAoAlgorithm::HmacSha1);
        assert_eq!(key.key, b"secret");
        assert!(key.set_current);
        assert!(key.set_rnext);
    }

    #[test]
    fn tcp_ao_config_for_listener_does_not_set_current_or_rnext() {
        let config = TcpAoConfig {
            key: "secret".to_string(),
            send_id: 10,
            recv_id: 11,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        };

        let key = tcp_ao_key_from_config(
            "2001:db8::1".parse().unwrap(),
            &config,
            TcpAoSocketRole::Listener,
        );

        assert_eq!(key.prefix_len, 128);
        assert_eq!(key.algorithm, TcpAoAlgorithm::HmacSha256);
        assert!(!key.set_current);
        assert!(!key.set_rnext);
    }

    #[test]
    fn tcp_ao_probe_classifies_kernel_response() {
        let support = probe_tcp_ao_support();
        if let TcpAoSupport::ProbeFailed(err) = support {
            assert!(!err.is_empty());
        }
    }
}
