//! Platform-specific socket options for BGP sessions.
//!
//! TCP MD5 authentication (RFC 2385) and GTSM / TTL security (RFC 5082)
//! require raw `setsockopt` calls that are only available on Linux.
//!
//! These are the only `unsafe` blocks in the project — they exist because
//! there is no safe Rust API for `TCP_MD5SIG` or `IP_MINTTL`.

use std::io;
use std::net::SocketAddr;

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

    socket.set_ttl(255)?;

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
