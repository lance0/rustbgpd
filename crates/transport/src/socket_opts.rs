//! Platform-specific socket options for BGP sessions.
//!
//! TCP MD5 authentication (RFC 2385) and GTSM / TTL security (RFC 5082)
//! require raw socket options that are only available on Linux. TCP-AO
//! (RFC 5925) uses the same boundary for `setsockopt` and `getsockopt`.
//!
//! These are the only `unsafe` blocks in the project — they exist because
//! there is no safe Rust API for `TCP_MD5SIG`, `IP_MINTTL`, or TCP-AO.

use std::io;
#[cfg(target_os = "linux")]
use std::net::IpAddr;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;

use crate::config::{TCP_AO_MAX_INSPECT_KEYS, TcpAoAlgorithm};
#[cfg(target_os = "linux")]
use crate::config::{TcpAoConfig, TcpAoKeyring};
use socket2::Socket;
#[cfg(target_os = "linux")]
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "linux")]
const TCP_MD5SIG_MAXKEYLEN: usize = 80;

/// Linux `tcp_md5sig`. The key buffer is populated only for the duration of
/// one `setsockopt` call and is scrubbed, together with its length, on drop.
#[cfg(target_os = "linux")]
#[repr(C)]
#[allow(
    clippy::struct_field_names,
    reason = "field names mirror the Linux tcp_md5sig ABI"
)]
struct TcpMd5Sig {
    tcpm_addr: libc::sockaddr_storage,
    tcpm_flags: u8,
    tcpm_prefixlen: u8,
    tcpm_keylen: u16,
    tcpm_ifindex: libc::c_int,
    tcpm_key: [u8; TCP_MD5SIG_MAXKEYLEN],
}

#[cfg(target_os = "linux")]
impl TcpMd5Sig {
    fn zeroed() -> Self {
        // SAFETY: this is a C UAPI record made entirely of integer/byte fields.
        unsafe { std::mem::zeroed() }
    }

    fn scrub(&mut self) {
        self.tcpm_key.zeroize();
        self.tcpm_keylen.zeroize();
    }
}

#[cfg(target_os = "linux")]
impl Drop for TcpMd5Sig {
    fn drop(&mut self) {
        self.scrub();
    }
}

/// Set TCP MD5 signature on a socket for a specific peer.
///
/// This implements RFC 2385 by calling `setsockopt(TCP_MD5SIG)` on Linux.
/// The password is associated with a specific peer address.
#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    reason = "Linux socket option ABI requires raw libc structs and socklen_t casts"
)]
pub fn set_tcp_md5sig(socket: &Socket, peer: SocketAddr, password: &str) -> io::Result<()> {
    use std::mem;

    const TCP_MD5SIG: libc::c_int = 14;

    let peer_sa: socket2::SockAddr = peer.into();
    let mut sig = TcpMd5Sig::zeroed();

    // Copy the sockaddr into the struct
    let sa_bytes = peer_sa.as_ptr().cast::<u8>();
    let sa_len = peer_sa.len() as usize;
    let dst = (&raw mut sig.tcpm_addr).cast::<u8>();
    unsafe {
        std::ptr::copy_nonoverlapping(sa_bytes, dst, sa_len);
    }

    let key_bytes = password.as_bytes();
    if key_bytes.len() > TCP_MD5SIG_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "MD5 password exceeds 80 bytes",
        ));
    }
    // Safe: we checked key_bytes.len() <= 80, which fits in u16
    sig.tcpm_keylen = key_bytes.len() as u16;
    sig.tcpm_key[..key_bytes.len()].copy_from_slice(key_bytes);

    let fd = socket.as_raw_fd();

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
impl Drop for TcpAoAdd {
    fn drop(&mut self) {
        self.scrub();
    }
}

#[cfg(target_os = "linux")]
impl TcpAoAdd {
    fn scrub(&mut self) {
        self.alg_name.zeroize();
        self.key.zeroize();
        self.keylen.zeroize();
    }
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

/// Linux `tcp_ao_getsockopt`. This raw type contains the MKT secret copied
/// back by the kernel, so it deliberately implements neither formatting nor
/// cloning and scrubs every secret-bearing byte on drop.
#[cfg(target_os = "linux")]
#[repr(C, align(8))]
struct TcpAoGetSockOpt {
    addr: libc::sockaddr_storage,
    alg_name: [u8; 64],
    key: [u8; 80],
    nkeys: u32,
    flags: u16,
    sndid: u8,
    rcvid: u8,
    prefix: u8,
    maclen: u8,
    keyflags: u8,
    keylen: u8,
    ifindex: libc::c_int,
    pkt_good: u64,
    pkt_bad: u64,
}

#[cfg(target_os = "linux")]
impl TcpAoGetSockOpt {
    fn zeroed() -> Self {
        // SAFETY: this is a C UAPI record made entirely of integer/byte fields.
        unsafe { std::mem::zeroed() }
    }
}

/// Secret-bearing, kernel-normalized MKT fields used only while reconciling
/// socket inventories. Selection flags and packet counters are intentionally
/// excluded: Linux may change those when a listener MKT is inherited by a
/// connected child, but the cryptographic identity must remain identical.
///
/// This type deliberately implements neither formatting nor cloning. Its
/// secret buffer is scrubbed when the short-lived reconciliation value drops.
#[cfg(target_os = "linux")]
struct TcpAoMktCore {
    send_id: u8,
    recv_id: u8,
    algorithm: TcpAoAlgorithm,
    mac_len: u8,
    key_flags: u8,
    vrf_ifindex: Option<u32>,
    // Heap-backed so moving a receipt relocates only the Vec pointer rather
    // than copying secret bytes through un-scrubbed stack locations.
    key: Zeroizing<Vec<u8>>,
}

#[cfg(target_os = "linux")]
struct TcpAoMktMetadata {
    peer: IpAddr,
    prefix_len: u8,
    preferred: bool,
    deprecated: bool,
}

/// One configured listener owner used to build an owned-union receipt.
#[cfg(target_os = "linux")]
pub(crate) struct TcpAoMktOwner<'a> {
    pub(crate) peer: IpAddr,
    pub(crate) prefix_len: u8,
    pub(crate) keyring: &'a TcpAoKeyring,
}

/// Opaque proof that a complete add-only inventory was normalized and
/// reconciled without mutating the target socket. Secret-bearing normalized
/// cores stay inside this module and are scrubbed on drop.
#[cfg(target_os = "linux")]
pub(crate) struct TcpAoAddOnlyPreflight {
    desired: TcpAoMktReceipt,
    present: Vec<bool>,
    selection: Option<TcpAoSelection>,
}

#[cfg(not(target_os = "linux"))]
pub(crate) struct TcpAoAddOnlyPreflight;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, PartialEq, Eq)]
struct TcpAoSelection {
    has_current: bool,
    current: u8,
    has_rnext: bool,
    rnext: u8,
}

/// A live add-only apply failure, annotated with whether target-socket
/// mutation may have begun. Callers must discard a connected stream whenever
/// `mutation_started` is true: a failed add or verification can leave an MKT
/// installed even though the generation did not commit.
pub(crate) struct TcpAoAddOnlyApplyError {
    error: io::Error,
    mutation_started: bool,
}

impl TcpAoAddOnlyApplyError {
    #[must_use]
    pub(crate) const fn mutation_started(&self) -> bool {
        self.mutation_started
    }

    pub(crate) fn into_inner(self) -> io::Error {
        self.error
    }
}

impl std::fmt::Display for TcpAoAddOnlyApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.error.fmt(f)
    }
}

impl std::fmt::Debug for TcpAoAddOnlyApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpAoAddOnlyApplyError")
            .field("error", &self.error)
            .field("mutation_started", &self.mutation_started)
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl PartialEq for TcpAoMktCore {
    fn eq(&self, other: &Self) -> bool {
        self.send_id == other.send_id
            && self.recv_id == other.recv_id
            && self.algorithm == other.algorithm
            && self.mac_len == other.mac_len
            && self.key_flags == other.key_flags
            && self.vrf_ifindex == other.vrf_ifindex
            && tcp_ao_secret_eq(self.key.as_slice(), other.key.as_slice())
    }
}

#[cfg(target_os = "linux")]
impl Eq for TcpAoMktCore {}

/// A pre-connect MKT receipt. It is intentionally crate-private and cannot be
/// cloned or formatted, so key material cannot escape into session state or
/// logs. Active open retains it only across the connect syscall; passive open
/// obtains the equivalent listener receipt synchronously during accept.
#[cfg(target_os = "linux")]
pub(crate) struct TcpAoMktReceipt {
    cores: Vec<TcpAoMktCore>,
    metadata: Vec<TcpAoMktMetadata>,
}

/// Short-lived proof used to classify an accepted child against the complete
/// current listener inventory or its exact immediately previous inventory.
/// The previous mask is meaningful only while the listener retains the
/// adjacent generation that produced it.
#[cfg(target_os = "linux")]
pub(crate) struct TcpAoAcceptedGenerationReceipt {
    current: TcpAoMktReceipt,
    previous: Option<Vec<bool>>,
}

#[cfg(not(target_os = "linux"))]
pub(crate) struct TcpAoAcceptedGenerationReceipt;

/// Exact generation relation proved from one accepted-child inventory read.
#[cfg(target_os = "linux")]
pub(crate) enum TcpAoAcceptedGeneration {
    Current(TcpAoInfoSnapshot),
    Previous(TcpAoInfoSnapshot),
}

#[cfg(not(target_os = "linux"))]
pub(crate) enum TcpAoAcceptedGeneration {
    Current(TcpAoInfoSnapshot),
    Previous(TcpAoInfoSnapshot),
}

#[cfg(not(target_os = "linux"))]
pub(crate) struct TcpAoMktReceipt;

#[cfg(not(target_os = "linux"))]
pub(crate) struct TcpAoMktOwner<'a> {
    pub(crate) peer: std::net::IpAddr,
    pub(crate) prefix_len: u8,
    pub(crate) keyring: &'a crate::config::TcpAoKeyring,
}

#[cfg(target_os = "linux")]
impl Drop for TcpAoGetSockOpt {
    fn drop(&mut self) {
        self.scrub();
    }
}

#[cfg(target_os = "linux")]
impl TcpAoGetSockOpt {
    fn scrub(&mut self) {
        self.alg_name.zeroize();
        self.key.zeroize();
        self.keylen.zeroize();
    }
}

/// Redacted per-MKT Linux TCP-AO state. No key material, key length, or
/// key-derived identifier is retained in this projection.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors independent Linux selection and local rollover flags"
)]
pub struct TcpAoKeyState {
    pub peer: std::net::IpAddr,
    pub prefix_len: u8,
    pub send_id: u8,
    pub recv_id: u8,
    pub algorithm: TcpAoAlgorithm,
    pub is_current: bool,
    pub is_rnext: bool,
    pub preferred: bool,
    pub deprecated: bool,
    /// VRF L3-master ifindex when Linux marks this MKT `TCP_AO_KEYF_IFINDEX`.
    /// This is not an IPv6 link-local scope ID.
    pub vrf_ifindex: Option<u32>,
    pub pkt_good: u64,
    pub pkt_bad: u64,
}

/// Runtime TCP-AO socket state returned by Linux `getsockopt(TCP_AO_INFO)`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "mirrors independent Linux TCP_AO_INFO flag bits"
)]
pub struct TcpAoInfoSnapshot {
    /// Whether Linux reports a valid current key ID.
    pub has_current_key: bool,
    /// Whether Linux reports a valid `RNext` key ID.
    pub has_rnext_key: bool,
    /// Whether the socket requires TCP-AO for matching packets.
    pub ao_required: bool,
    /// Whether incoming ICMPs are accepted for this TCP-AO socket.
    pub accept_icmps: bool,
    /// Current TCP-AO `KeyID`.
    pub current_key: u8,
    /// `RNext` TCP-AO `KeyID`.
    pub rnext_key: u8,
    /// Verified TCP-AO segments.
    pub pkt_good: u64,
    /// Segments that failed TCP-AO verification.
    pub pkt_bad: u64,
    /// Segments whose TCP-AO `KeyID` did not match an MKT.
    pub pkt_key_not_found: u64,
    /// Segments that were missing a required TCP-AO signature.
    pub pkt_ao_required: u64,
    /// ICMPs dropped by TCP-AO policy.
    pub pkt_dropped_icmp: u64,
    /// Ordered, redacted kernel MKT inventory for this socket.
    pub keys: Vec<TcpAoKeyState>,
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
const TCP_AO_GET_KEYS: libc::c_int = 41;
#[cfg(target_os = "linux")]
const TCP_AO_MAXKEYLEN: usize = 80;
#[cfg(target_os = "linux")]
const TCP_AO_TARGET_BIG_ENDIAN: bool = cfg!(target_endian = "big");

/// Return the numeric mask for a bit in a Linux UAPI `u32` C bitfield word.
///
/// Linux big-endian C ABIs allocate the first declared bitfield from the most
/// significant bit; little-endian ABIs allocate it from the least significant
/// bit. The surrounding `repr(C)` records stay identical on both targets.
#[cfg(target_os = "linux")]
const fn tcp_ao_u32_bitfield_mask(index: u32, big_endian: bool) -> u32 {
    let shift = if big_endian {
        u32::BITS - 1 - index
    } else {
        index
    };
    1u32 << shift
}

/// Return the numeric mask for a bit in a Linux UAPI `u16` C bitfield word.
#[cfg(target_os = "linux")]
const fn tcp_ao_u16_bitfield_mask(index: u32, big_endian: bool) -> u16 {
    let shift = if big_endian {
        u16::BITS - 1 - index
    } else {
        index
    };
    1u16 << shift
}

#[cfg(target_os = "linux")]
const TCP_AO_ADD_SET_CURRENT: u32 = tcp_ao_u32_bitfield_mask(0, TCP_AO_TARGET_BIG_ENDIAN);
#[cfg(target_os = "linux")]
const TCP_AO_ADD_SET_RNEXT: u32 = tcp_ao_u32_bitfield_mask(1, TCP_AO_TARGET_BIG_ENDIAN);
#[cfg(target_os = "linux")]
const TCP_AO_INFO_SET_CURRENT: u32 = tcp_ao_u32_bitfield_mask(0, TCP_AO_TARGET_BIG_ENDIAN);
#[cfg(target_os = "linux")]
const TCP_AO_INFO_SET_RNEXT: u32 = tcp_ao_u32_bitfield_mask(1, TCP_AO_TARGET_BIG_ENDIAN);
#[cfg(target_os = "linux")]
const TCP_AO_INFO_AO_REQUIRED: u32 = tcp_ao_u32_bitfield_mask(2, TCP_AO_TARGET_BIG_ENDIAN);
#[cfg(target_os = "linux")]
const TCP_AO_INFO_SET_COUNTERS: u32 = tcp_ao_u32_bitfield_mask(3, TCP_AO_TARGET_BIG_ENDIAN);
#[cfg(target_os = "linux")]
const TCP_AO_INFO_ACCEPT_ICMPS: u32 = tcp_ao_u32_bitfield_mask(4, TCP_AO_TARGET_BIG_ENDIAN);
#[cfg(target_os = "linux")]
const TCP_AO_GET_IS_CURRENT: u16 = tcp_ao_u16_bitfield_mask(0, TCP_AO_TARGET_BIG_ENDIAN);
#[cfg(target_os = "linux")]
const TCP_AO_GET_IS_RNEXT: u16 = tcp_ao_u16_bitfield_mask(1, TCP_AO_TARGET_BIG_ENDIAN);
#[cfg(target_os = "linux")]
const TCP_AO_GET_ALL: u16 = tcp_ao_u16_bitfield_mask(2, TCP_AO_TARGET_BIG_ENDIAN);
// `keyflags` is an ordinary one-byte flag field, not a C bitfield word, so its
// numeric masks are endian-independent.
#[cfg(target_os = "linux")]
const TCP_AO_KEYF_IFINDEX: u8 = 1 << 0;
#[cfg(target_os = "linux")]
const TCP_AO_KEYF_EXCLUDE_OPT: u8 = 1 << 1;
#[cfg(target_os = "linux")]
const TCP_AO_KEY_QUERY_ATTEMPTS: usize = 3;

/// Add a TCP-AO key to a socket.
///
/// Active-open sockets install the selected key as both current and rnext so
/// the initial SYN is signed. Listener sockets and non-selected active-open
/// keyring entries install MKTs without current/rnext flags because Linux
/// rejects those flags on listening sockets and only one key may be selected.
///
/// Do not set `TCP_AO_INFO.ao_required` here. Linux treats peers matching an
/// MKT as TCP-AO candidates, while the global `ao_required` bit would require
/// TCP-AO from every inbound peer on rustbgpd's shared BGP listener, including
/// static neighbors that intentionally do not configure TCP-AO.
#[cfg(target_os = "linux")]
pub(crate) fn set_tcp_ao_config(
    socket: &Socket,
    peer: IpAddr,
    prefix_len: u8,
    config: &TcpAoConfig,
    role: TcpAoSocketRole,
) -> io::Result<()> {
    let key = tcp_ao_key_from_config(peer, prefix_len, config, role);
    set_tcp_ao_key(socket, &key)
}

#[cfg(target_os = "linux")]
fn tcp_ao_key_from_config(
    peer: IpAddr,
    prefix_len: u8,
    config: &TcpAoConfig,
    role: TcpAoSocketRole,
) -> TcpAoKey<'_> {
    TcpAoKey {
        peer,
        scope_id: 0,
        prefix_len,
        send_id: config.send_id,
        recv_id: config.recv_id,
        algorithm: config.algorithm,
        mac_len: 0,
        key: config.key.as_ref().as_bytes(),
        set_current: matches!(role, TcpAoSocketRole::ActiveOpen),
        set_rnext: matches!(role, TcpAoSocketRole::ActiveOpen),
    }
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub(crate) fn set_tcp_ao_config(
    _socket: &Socket,
    _peer: std::net::IpAddr,
    _prefix_len: u8,
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
#[allow(
    dead_code,
    unsafe_code,
    clippy::cast_possible_truncation,
    reason = "TCP-AO key installation uses raw Linux socket-option ABI structs"
)]
pub(crate) fn set_tcp_ao_key(socket: &impl AsRawFd, key: &TcpAoKey<'_>) -> io::Result<()> {
    let add = build_tcp_ao_add(key)?;
    let fd = socket.as_raw_fd();

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            TCP_AO_ADD_KEY,
            std::ptr::from_ref(add.as_ref()).cast(),
            std::mem::size_of::<TcpAoAdd>() as libc::socklen_t,
        )
    };

    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn rotation_record_matches_owner(
    raw: &TcpAoGetSockOpt,
    peer: IpAddr,
    prefix_len: u8,
    connected_peer: Option<IpAddr>,
    config: &TcpAoConfig,
) -> io::Result<bool> {
    let state = decode_tcp_ao_key_state(raw)?;
    let connected_prefix = connected_peer.map(|peer| if peer.is_ipv4() { 32 } else { 128 });
    let selector_matches = (state.peer == peer && state.prefix_len == prefix_len)
        || connected_peer.is_some_and(|connected| {
            state.peer == connected && Some(state.prefix_len) == connected_prefix
        });
    Ok(selector_matches
        && state.send_id == config.send_id
        && state.recv_id == config.recv_id
        && state.algorithm == config.algorithm
        && state.vrf_ifindex.is_none()
        && raw.keyflags == 0)
}

#[cfg(target_os = "linux")]
fn matching_rotation_core(
    keys: &[TcpAoGetSockOpt],
    peer: IpAddr,
    prefix_len: u8,
    connected_peer: Option<IpAddr>,
    config: &TcpAoConfig,
) -> io::Result<Option<TcpAoMktCore>> {
    let mut matched = None;
    for raw in keys {
        if rotation_record_matches_owner(raw, peer, prefix_len, connected_peer, config)? {
            if matched.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TCP-AO kernel inventory contains duplicate rotation keys",
                ));
            }
            matched = Some(mkt_core(raw)?);
        }
    }
    Ok(matched)
}

#[cfg(target_os = "linux")]
fn normalized_config_core(
    peer: IpAddr,
    prefix_len: u8,
    config: &TcpAoConfig,
) -> io::Result<TcpAoMktCore> {
    let domain = if peer.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let scratch = Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    let key = tcp_ao_key_from_config(peer, prefix_len, config, TcpAoSocketRole::Listener);
    set_tcp_ao_key(&scratch, &key)?;
    let keys = get_tcp_ao_keys_with(|entries| query_tcp_ao_keys(&scratch, entries))?;
    matching_rotation_core(&keys, peer, prefix_len, None, config)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TCP-AO kernel did not return the normalized candidate key",
        )
    })
}

#[cfg(target_os = "linux")]
fn prefixes_overlap(left: IpAddr, left_len: u8, right: IpAddr, right_len: u8) -> bool {
    fn mask_v4(address: u32, prefix_len: u8) -> u32 {
        if prefix_len == 0 {
            0
        } else {
            address & (u32::MAX << (32 - prefix_len))
        }
    }
    fn mask_v6(address: u128, prefix_len: u8) -> u128 {
        if prefix_len == 0 {
            0
        } else {
            address & (u128::MAX << (128 - prefix_len))
        }
    }

    let shared_len = left_len.min(right_len);
    match (left, right) {
        (IpAddr::V4(left), IpAddr::V4(right)) if shared_len <= 32 => {
            mask_v4(left.into(), shared_len) == mask_v4(right.into(), shared_len)
        }
        (IpAddr::V6(left), IpAddr::V6(right)) if shared_len <= 128 => {
            mask_v6(left.into(), shared_len) == mask_v6(right.into(), shared_len)
        }
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn desired_add_only_receipt(
    owners: &[TcpAoMktOwner<'_>],
    connected_peer: Option<IpAddr>,
) -> io::Result<TcpAoMktReceipt> {
    let expected = owners
        .iter()
        .map(|owner| owner.keyring.0.len())
        .sum::<usize>();
    if expected > TCP_AO_MAX_INSPECT_KEYS {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP-AO desired inventory exceeds inspection capacity",
        ));
    }

    let flattened = owners
        .iter()
        .flat_map(|owner| {
            owner
                .keyring
                .iter()
                .map(move |config| (owner.peer, owner.prefix_len, config))
        })
        .collect::<Vec<_>>();
    for (index, (left_peer, left_prefix, left)) in flattened.iter().enumerate() {
        for (right_peer, right_prefix, right) in flattened.iter().skip(index + 1) {
            let selectors_overlap = connected_peer.is_some()
                || prefixes_overlap(*left_peer, *left_prefix, *right_peer, *right_prefix);
            if selectors_overlap && (left.send_id == right.send_id || left.recv_id == right.recv_id)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TCP-AO desired inventory has a directional KeyID collision on overlapping selectors",
                ));
            }
        }
    }

    let mut cores = Vec::with_capacity(expected);
    let mut metadata = Vec::with_capacity(expected);
    for owner in owners {
        for config in owner.keyring {
            cores.push(normalized_config_core(
                owner.peer,
                owner.prefix_len,
                config,
            )?);
            metadata.push(TcpAoMktMetadata {
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                preferred: config.preferred,
                deprecated: config.deprecated,
            });
        }
    }
    Ok(TcpAoMktReceipt { cores, metadata })
}

#[cfg(target_os = "linux")]
fn selection(info: &TcpAoInfoSnapshot) -> TcpAoSelection {
    TcpAoSelection {
        has_current: info.has_current_key,
        current: info.current_key,
        has_rnext: info.has_rnext_key,
        rnext: info.rnext_key,
    }
}

#[cfg(target_os = "linux")]
fn query_rotation_inventory(
    socket: &impl AsRawFd,
    connected_peer: Option<IpAddr>,
) -> io::Result<(Option<TcpAoInfoSnapshot>, Vec<TcpAoGetSockOpt>)> {
    if connected_peer.is_some() {
        let (info, keys) = get_tcp_ao_snapshot_with(
            || get_tcp_ao_info_only(socket),
            || get_tcp_ao_keys_with(|entries| query_tcp_ao_keys(socket, entries)),
        )?;
        Ok((Some(info), keys))
    } else {
        Ok((
            None,
            get_tcp_ao_keys_with(|entries| query_tcp_ao_keys(socket, entries))?,
        ))
    }
}

#[cfg(target_os = "linux")]
fn reconcile_add_only_subset(
    keys: &[TcpAoGetSockOpt],
    desired: &TcpAoMktReceipt,
    connected_peer: Option<IpAddr>,
) -> io::Result<Vec<bool>> {
    let mut present = vec![false; desired.cores.len()];
    for raw in keys {
        let state = decode_tcp_ao_key_state(raw)?;
        let core = mkt_core(raw)?;
        let matches = desired
            .cores
            .iter()
            .zip(&desired.metadata)
            .enumerate()
            .filter(|(index, (candidate, metadata))| {
                !present[*index]
                    && match connected_peer {
                        Some(peer) => target_record_matches_receipt_entry(&state, peer, metadata),
                        None => {
                            state.peer == metadata.peer && state.prefix_len == metadata.prefix_len
                        }
                    }
                    && core == **candidate
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TCP-AO target inventory contains a foreign, redefined, duplicate, or ambiguous MKT",
            ));
        }
        present[matches[0]] = true;
    }
    Ok(present)
}

#[cfg(target_os = "linux")]
fn require_current_subset(
    current: &[TcpAoMktOwner<'_>],
    desired: &[TcpAoMktOwner<'_>],
    present: &[bool],
) -> io::Result<()> {
    let desired_entries = desired
        .iter()
        .flat_map(|owner| {
            owner
                .keyring
                .iter()
                .map(move |config| (owner.peer, owner.prefix_len, config))
        })
        .collect::<Vec<_>>();
    for owner in current {
        for config in owner.keyring {
            let matches = desired_entries
                .iter()
                .enumerate()
                .filter(|(_, (peer, prefix_len, desired))| {
                    *peer == owner.peer
                        && *prefix_len == owner.prefix_len
                        && desired.send_id == config.send_id
                        && desired.recv_id == config.recv_id
                        && desired.algorithm == config.algorithm
                })
                .map(|(index, _)| index)
                .collect::<Vec<_>>();
            if matches.len() != 1 || !present[matches[0]] {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TCP-AO target inventory is missing or redefines a current-generation MKT",
                ));
            }
        }
    }
    Ok(())
}

/// Normalize every desired MKT and reconcile the complete target inventory
/// before the first live `setsockopt`. Existing target records must be an
/// exact cryptographic subset of the desired generation, and every current
/// record must already be present.
#[cfg(target_os = "linux")]
pub(crate) fn preflight_tcp_ao_add_only(
    socket: &impl AsRawFd,
    current: &[TcpAoMktOwner<'_>],
    desired: &[TcpAoMktOwner<'_>],
    connected_peer: Option<IpAddr>,
) -> io::Result<TcpAoAddOnlyPreflight> {
    let desired_receipt = desired_add_only_receipt(desired, connected_peer)?;
    let (info, keys) = query_rotation_inventory(socket, connected_peer)?;
    let present = reconcile_add_only_subset(&keys, &desired_receipt, connected_peer)?;
    require_current_subset(current, desired, &present)?;
    let selection = info.as_ref().map(selection);
    Ok(TcpAoAddOnlyPreflight {
        desired: desired_receipt,
        present,
        selection,
    })
}

#[cfg(target_os = "linux")]
fn apply_error(error: io::Error, mutation_started: bool) -> TcpAoAddOnlyApplyError {
    TcpAoAddOnlyApplyError {
        error,
        mutation_started,
    }
}

#[cfg(target_os = "linux")]
fn run_add_only_sequence<V, A>(
    present: &mut Vec<bool>,
    mut verify: V,
    mut add: A,
) -> Result<bool, TcpAoAddOnlyApplyError>
where
    V: FnMut() -> io::Result<Vec<bool>>,
    A: FnMut(usize) -> io::Result<()>,
{
    let mut mutation_started = false;
    *present = verify().map_err(|error| apply_error(error, false))?;
    for index in 0..present.len() {
        if present[index] {
            continue;
        }
        let before = verify().map_err(|error| apply_error(error, mutation_started))?;
        if before != *present {
            return Err(apply_error(
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "TCP-AO target inventory changed between add-only verification steps",
                ),
                mutation_started,
            ));
        }
        mutation_started = true;
        add(index).map_err(|error| apply_error(error, mutation_started))?;
        let after = verify().map_err(|error| apply_error(error, mutation_started))?;
        let mut expected = present.clone();
        expected[index] = true;
        if after != expected {
            return Err(apply_error(
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TCP-AO post-add inventory did not contain exactly the expected desired subset",
                ),
                mutation_started,
            ));
        }
        *present = after;
    }
    if present.iter().any(|present| !present) {
        return Err(apply_error(
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TCP-AO add-only inventory did not converge",
            ),
            mutation_started,
        ));
    }
    let final_present = verify().map_err(|error| apply_error(error, mutation_started))?;
    if final_present != *present {
        return Err(apply_error(
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "TCP-AO target inventory changed after add-only convergence",
            ),
            mutation_started,
        ));
    }
    Ok(mutation_started)
}

/// Consume a complete preflight proof, revalidate it immediately before the
/// first mutation and around every add, and return the final connected-socket
/// snapshot when applicable.
#[cfg(target_os = "linux")]
pub(crate) fn apply_tcp_ao_add_only(
    socket: &impl AsRawFd,
    mut preflight: TcpAoAddOnlyPreflight,
    desired: &[TcpAoMktOwner<'_>],
    connected_peer: Option<IpAddr>,
) -> Result<Option<TcpAoInfoSnapshot>, TcpAoAddOnlyApplyError> {
    let configs = desired
        .iter()
        .flat_map(|owner| {
            owner
                .keyring
                .iter()
                .map(move |config| (owner.peer, owner.prefix_len, config))
        })
        .collect::<Vec<_>>();
    if configs.len() != preflight.desired.cores.len() {
        return Err(apply_error(
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP-AO apply inventory differs from its preflight proof",
            ),
            false,
        ));
    }
    for (index, (peer, prefix_len, config)) in configs.iter().enumerate() {
        let metadata = &preflight.desired.metadata[index];
        let normalized = normalized_config_core(*peer, *prefix_len, config)
            .map_err(|error| apply_error(error, false))?;
        if metadata.peer != *peer
            || metadata.prefix_len != *prefix_len
            || metadata.preferred != config.preferred
            || metadata.deprecated != config.deprecated
            || normalized != preflight.desired.cores[index]
        {
            return Err(apply_error(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TCP-AO apply inventory differs from its normalized preflight proof",
                ),
                false,
            ));
        }
    }

    let desired_receipt = &preflight.desired;
    let expected_selection = preflight.selection;
    let verify = || -> io::Result<Vec<bool>> {
        let (info, keys) = query_rotation_inventory(socket, connected_peer)?;
        if info
            .as_ref()
            .map(selection)
            .zip(expected_selection)
            .is_some_and(|(actual, expected)| actual != expected)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TCP-AO add-only generation changed Current/RNext selection",
            ));
        }
        reconcile_add_only_subset(&keys, desired_receipt, connected_peer)
    };
    // Exact desired additions made by a prior interrupted retry are safe; any
    // foreign or redefined record is rejected by `verify`.
    let mutation_started = run_add_only_sequence(&mut preflight.present, verify, |index| {
        let (peer, prefix_len, config) = configs[index];
        let key = tcp_ao_key_from_config(peer, prefix_len, config, TcpAoSocketRole::Listener);
        set_tcp_ao_key(socket, &key)
    })?;
    connected_peer
        .map(|peer| get_tcp_ao_info_for_receipt(socket, desired_receipt, peer))
        .transpose()
        .map_err(|error| apply_error(error, mutation_started))
}

/// Inspect runtime TCP-AO socket state.
#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    reason = "TCP-AO inspection uses raw Linux getsockopt ABI structs"
)]
fn get_tcp_ao_info_only(socket: &impl AsRawFd) -> io::Result<TcpAoInfoSnapshot> {
    let mut info: TcpAoInfoOpt = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<TcpAoInfoOpt>() as libc::socklen_t;

    let ret = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_AO_INFO,
            (&raw mut info).cast(),
            &raw mut len,
        )
    };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let returned_len = usize::try_from(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TCP-AO info length does not fit usize",
        )
    })?;
    let expected_len = std::mem::size_of::<TcpAoInfoOpt>();
    if returned_len < expected_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("short TCP-AO info response: {returned_len} < {expected_len}"),
        ));
    }

    Ok(TcpAoInfoSnapshot::from_raw(&info))
}

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "TCP-AO key inventory uses the raw Linux getsockopt ABI"
)]
fn query_tcp_ao_keys(socket: &impl AsRawFd, entries: &mut [TcpAoGetSockOpt]) -> io::Result<usize> {
    let capacity = entries.len();
    let Some(first) = entries.first_mut() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "empty TCP-AO key dump buffer",
        ));
    };
    first.nkeys = u32::try_from(capacity).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP-AO key dump capacity exceeds u32",
        )
    })?;
    first.flags = TCP_AO_GET_ALL;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<TcpAoGetSockOpt>())
        .expect("TCP-AO key record size fits socklen_t");
    let ret = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_AO_GET_KEYS,
            entries.as_mut_ptr().cast(),
            &raw mut len,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    let returned_len = usize::try_from(len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TCP-AO key record length does not fit usize",
        )
    })?;
    validate_tcp_ao_key_record_len(returned_len)?;
    usize::try_from(entries[0].nkeys).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "TCP-AO key count does not fit usize",
        )
    })
}

#[cfg(target_os = "linux")]
fn validate_tcp_ao_key_record_len(returned_len: usize) -> io::Result<()> {
    let known_len = std::mem::size_of::<TcpAoGetSockOpt>();
    if returned_len < known_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("short TCP-AO key record: {returned_len} < {known_len}"),
        ));
    }
    // Linux returns its current structure size for version negotiation. A
    // newer kernel may append fields; all fields consumed here are in the
    // known prefix and the input stride remains our userspace structure size.
    Ok(())
}

#[cfg(target_os = "linux")]
fn get_tcp_ao_keys_with<F>(mut query: F) -> io::Result<Vec<TcpAoGetSockOpt>>
where
    F: FnMut(&mut [TcpAoGetSockOpt]) -> io::Result<usize>,
{
    let mut capacity = 1;
    for _ in 0..TCP_AO_KEY_QUERY_ATTEMPTS {
        // Allocate the complete zero-only buffer before the syscall. Once the
        // kernel writes secrets, records remain stationary: retries drop this
        // Vec in place, and ordering is applied only to redacted projections.
        let mut raw = (0..capacity)
            .map(|_| TcpAoGetSockOpt::zeroed())
            .collect::<Vec<_>>();
        let matched = query(&mut raw)?;
        if matched > TCP_AO_MAX_INSPECT_KEYS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "TCP-AO key count {matched} exceeds safety limit {TCP_AO_MAX_INSPECT_KEYS}"
                ),
            ));
        }
        if matched > capacity {
            capacity = matched;
            continue;
        }
        raw.truncate(matched);
        for record in &raw {
            decode_tcp_ao_key_state(record)?;
        }
        return Ok(raw);
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "TCP-AO key inventory changed during bounded query",
    ))
}

#[cfg(target_os = "linux")]
fn decode_tcp_ao_key_state(raw: &TcpAoGetSockOpt) -> io::Result<TcpAoKeyState> {
    let peer = read_sockaddr(&raw.addr)?;
    let max_prefix = if peer.is_ipv4() { 32 } else { 128 };
    if raw.prefix > max_prefix {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TCP-AO key prefix",
        ));
    }
    let key_len = usize::from(raw.keylen);
    if key_len == 0 || key_len > TCP_AO_MAXKEYLEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TCP-AO key length",
        ));
    }
    let nul = raw
        .alg_name
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "unterminated TCP-AO algorithm name",
            )
        })?;
    let name = std::str::from_utf8(&raw.alg_name[..nul])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid TCP-AO algorithm name"))?;
    let canonical = if name == "cmac(aes)" {
        "cmac(aes128)"
    } else {
        name
    };
    let algorithm = TcpAoAlgorithm::from_linux_name(canonical)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unknown TCP-AO algorithm"))?;
    if raw.keyflags & !(TCP_AO_KEYF_IFINDEX | TCP_AO_KEYF_EXCLUDE_OPT) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown TCP-AO key flags",
        ));
    }
    let vrf_ifindex = if raw.keyflags & TCP_AO_KEYF_IFINDEX != 0 {
        Some(u32::try_from(raw.ifindex).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid TCP-AO VRF ifindex")
        })?)
    } else {
        if raw.ifindex != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TCP-AO ifindex lacks TCP_AO_KEYF_IFINDEX",
            ));
        }
        None
    };
    Ok(TcpAoKeyState {
        peer,
        prefix_len: raw.prefix,
        send_id: raw.sndid,
        recv_id: raw.rcvid,
        algorithm,
        is_current: raw.flags & TCP_AO_GET_IS_CURRENT != 0,
        is_rnext: raw.flags & TCP_AO_GET_IS_RNEXT != 0,
        preferred: false,
        deprecated: false,
        vrf_ifindex,
        pkt_good: raw.pkt_good,
        pkt_bad: raw.pkt_bad,
    })
}

#[cfg(target_os = "linux")]
fn redacted_tcp_ao_keys(keys: &[TcpAoGetSockOpt]) -> io::Result<Vec<TcpAoKeyState>> {
    let mut states = keys
        .iter()
        .map(decode_tcp_ao_key_state)
        .collect::<io::Result<Vec<_>>>()?;
    states.sort_by_key(|key| (key.peer, key.prefix_len, key.send_id, key.recv_id));
    Ok(states)
}

#[cfg(target_os = "linux")]
fn tcp_ao_inventory_consistent(info: &TcpAoInfoSnapshot, keys: &[TcpAoGetSockOpt]) -> bool {
    let current = keys
        .iter()
        .filter(|key| key.flags & TCP_AO_GET_IS_CURRENT != 0)
        .collect::<Vec<_>>();
    let rnext = keys
        .iter()
        .filter(|key| key.flags & TCP_AO_GET_IS_RNEXT != 0)
        .collect::<Vec<_>>();
    (!info.has_current_key || (current.len() == 1 && current[0].sndid == info.current_key))
        && (!info.has_rnext_key || (rnext.len() == 1 && rnext[0].rcvid == info.rnext_key))
        && (info.has_current_key || current.is_empty())
        && (info.has_rnext_key || rnext.is_empty())
}

#[cfg(target_os = "linux")]
fn get_tcp_ao_snapshot_with<I, K>(
    mut info_query: I,
    mut key_query: K,
) -> io::Result<(TcpAoInfoSnapshot, Vec<TcpAoGetSockOpt>)>
where
    I: FnMut() -> io::Result<TcpAoInfoSnapshot>,
    K: FnMut() -> io::Result<Vec<TcpAoGetSockOpt>>,
{
    for _ in 0..TCP_AO_KEY_QUERY_ATTEMPTS {
        // Read INFO after the key dump so counters that change during
        // GET_KEYS are not hidden by an earlier snapshot.
        let keys = key_query()?;
        let info = info_query()?;
        if tcp_ao_inventory_consistent(&info, &keys) {
            return Ok((info, keys));
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "TCP-AO INFO and key inventory remained inconsistent",
    ))
}

/// Inspect socket-wide and per-key TCP-AO state as one all-or-none freshness
/// result. The two Linux syscalls are cross-checked and retried on a transition.
#[cfg(target_os = "linux")]
pub(crate) fn get_tcp_ao_info(socket: &impl AsRawFd) -> io::Result<TcpAoInfoSnapshot> {
    let (mut info, keys) = get_tcp_ao_snapshot_with(
        || get_tcp_ao_info_only(socket),
        || get_tcp_ao_keys_with(|entries| query_tcp_ao_keys(socket, entries)),
    )?;
    info.keys = redacted_tcp_ao_keys(&keys)?;
    drop(keys);
    Ok(info)
}

#[cfg(target_os = "linux")]
fn mkt_core(raw: &TcpAoGetSockOpt) -> io::Result<TcpAoMktCore> {
    let state = decode_tcp_ao_key_state(raw)?;
    let key_len = usize::from(raw.keylen);
    Ok(TcpAoMktCore {
        send_id: state.send_id,
        recv_id: state.recv_id,
        algorithm: state.algorithm,
        mac_len: raw.maclen,
        key_flags: raw.keyflags,
        vrf_ifindex: state.vrf_ifindex,
        key: Zeroizing::new(raw.key[..key_len].to_vec()),
    })
}

#[cfg(target_os = "linux")]
fn raw_matches_owner(
    raw: &TcpAoGetSockOpt,
    peer: IpAddr,
    prefix_len: u8,
    config: &TcpAoConfig,
) -> io::Result<bool> {
    let state = decode_tcp_ao_key_state(raw)?;
    Ok(state.peer == peer
        && state.prefix_len == prefix_len
        && state.send_id == config.send_id
        && state.recv_id == config.recv_id
        // Compare the decoded canonical algorithm. Linux reports AES-CMAC as
        // `cmac(aes)` even though the add-key API accepts `cmac(aes128)`.
        && state.algorithm == config.algorithm
        && state.vrf_ifindex.is_none()
        && raw.keyflags == 0)
}

#[cfg(target_os = "linux")]
fn tcp_ao_secret_eq(lhs: &[u8], rhs: &[u8]) -> bool {
    // Mirror the bearer-token comparison contract: include the length in the
    // accumulated difference and walk the longer input so neither the first
    // mismatching byte nor a length mismatch short-circuits comparison.
    let max_len = lhs.len().max(rhs.len());
    let mut diff = lhs.len() ^ rhs.len();
    for index in 0..max_len {
        let left = lhs.get(index).copied().unwrap_or(0);
        let right = rhs.get(index).copied().unwrap_or(0);
        diff |= usize::from(left ^ right);
    }
    diff == 0
}

#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "singleton receipt helper retained for focused ABI tests"
)]
fn receipt_from_raw_inventory(
    keys: &[TcpAoGetSockOpt],
    peer: IpAddr,
    prefix_len: u8,
    config: &TcpAoConfig,
    exact_inventory: bool,
) -> io::Result<TcpAoMktReceipt> {
    let mut matching = Vec::new();
    for raw in keys {
        if raw_matches_owner(raw, peer, prefix_len, config)? {
            matching.push(raw);
        }
    }
    if matching.len() != 1 || (exact_inventory && keys.len() != 1) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TCP-AO kernel MKT inventory does not exactly contain the configured owner",
        ));
    }
    Ok(TcpAoMktReceipt {
        cores: vec![mkt_core(matching[0])?],
        metadata: vec![TcpAoMktMetadata {
            peer,
            prefix_len,
            preferred: config.preferred,
            deprecated: config.deprecated,
        }],
    })
}

#[cfg(target_os = "linux")]
fn keyring_receipt_from_raw_inventory(
    keys: &[TcpAoGetSockOpt],
    peer: IpAddr,
    prefix_len: u8,
    keyring: &TcpAoKeyring,
    exact_inventory: bool,
) -> io::Result<TcpAoMktReceipt> {
    let mut cores = Vec::with_capacity(keyring.0.len());
    let mut metadata = Vec::with_capacity(keyring.0.len());
    let mut used = vec![false; keys.len()];
    for config in keyring {
        let mut found = None;
        for (index, raw) in keys.iter().enumerate() {
            if !used[index] && raw_matches_owner(raw, peer, prefix_len, config)? {
                if found.is_some() {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "TCP-AO kernel MKT inventory contains a duplicate configured key",
                    ));
                }
                found = Some(index);
            }
        }
        let index = found.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TCP-AO kernel MKT inventory is missing a configured key",
            )
        })?;
        used[index] = true;
        cores.push(mkt_core(&keys[index])?);
        metadata.push(TcpAoMktMetadata {
            peer,
            prefix_len,
            preferred: config.preferred,
            deprecated: config.deprecated,
        });
    }
    if exact_inventory && used.iter().any(|matched| !matched) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TCP-AO kernel MKT inventory contains a foreign key",
        ));
    }
    Ok(TcpAoMktReceipt { cores, metadata })
}

#[cfg(target_os = "linux")]
fn owned_receipt_from_raw_inventory(
    keys: &[TcpAoGetSockOpt],
    owners: &[TcpAoMktOwner<'_>],
) -> io::Result<TcpAoMktReceipt> {
    let expected_len = owners.iter().map(|owner| owner.keyring.0.len()).sum();
    let mut cores = Vec::with_capacity(expected_len);
    let mut metadata = Vec::with_capacity(expected_len);
    let mut used = vec![false; keys.len()];
    for owner in owners {
        for config in owner.keyring {
            let mut found = None;
            for (index, raw) in keys.iter().enumerate() {
                if !used[index] && raw_matches_owner(raw, owner.peer, owner.prefix_len, config)? {
                    if found.is_some() {
                        return Err(io::Error::new(
                            io::ErrorKind::PermissionDenied,
                            "TCP-AO listener inventory contains a duplicate owned key",
                        ));
                    }
                    found = Some(index);
                }
            }
            let index = found.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "TCP-AO listener inventory is missing an owned key",
                )
            })?;
            used[index] = true;
            cores.push(mkt_core(&keys[index])?);
            metadata.push(TcpAoMktMetadata {
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                preferred: config.preferred,
                deprecated: config.deprecated,
            });
        }
    }
    Ok(TcpAoMktReceipt { cores, metadata })
}

/// Capture the kernel-normalized cryptographic identity of one configured
/// owner. The returned secret-bearing receipt must remain short-lived.
#[cfg(target_os = "linux")]
#[allow(
    dead_code,
    reason = "singleton compatibility seam retained for Phase 1 callers"
)]
pub(crate) fn capture_tcp_ao_mkt_receipt(
    socket: &impl AsRawFd,
    peer: IpAddr,
    prefix_len: u8,
    config: &TcpAoConfig,
    exact_inventory: bool,
) -> io::Result<TcpAoMktReceipt> {
    let keys = get_tcp_ao_keys_with(|entries| query_tcp_ao_keys(socket, entries))?;
    receipt_from_raw_inventory(&keys, peer, prefix_len, config, exact_inventory)
}

#[cfg(target_os = "linux")]
pub(crate) fn capture_tcp_ao_keyring_receipt(
    socket: &impl AsRawFd,
    peer: IpAddr,
    prefix_len: u8,
    keyring: &TcpAoKeyring,
    exact_inventory: bool,
) -> io::Result<TcpAoMktReceipt> {
    let keys = get_tcp_ao_keys_with(|entries| query_tcp_ao_keys(socket, entries))?;
    keyring_receipt_from_raw_inventory(&keys, peer, prefix_len, keyring, exact_inventory)
}

/// Capture the complete current covering-owner receipt and, when the listener
/// can prove an adjacent predecessor, mark exactly the entries inherited by
/// that predecessor. `previous_key_counts` is aligned to `owners`; listener
/// code derives it with owner-kind-aware identity matching.
#[cfg(target_os = "linux")]
pub(crate) fn capture_tcp_ao_accepted_generation_receipt(
    socket: &impl AsRawFd,
    owners: &[TcpAoMktOwner<'_>],
    previous_key_counts: Option<&[usize]>,
) -> io::Result<TcpAoAcceptedGenerationReceipt> {
    let previous = previous_key_counts
        .map(|counts| {
            if counts.len() != owners.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TCP-AO previous listener inventory is not aligned to current owners",
                ));
            }
            let expected = owners
                .iter()
                .map(|owner| owner.keyring.0.len())
                .sum::<usize>();
            let mut mask = Vec::with_capacity(expected);
            for (owner, previous_count) in owners.iter().zip(counts) {
                if *previous_count > owner.keyring.0.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "TCP-AO previous listener keyring is not a current-keyring prefix",
                    ));
                }
                mask.extend((0..owner.keyring.0.len()).map(|index| index < *previous_count));
            }
            Ok(mask)
        })
        .transpose()?;
    let keys = get_tcp_ao_keys_with(|entries| query_tcp_ao_keys(socket, entries))?;
    let current = owned_receipt_from_raw_inventory(&keys, owners)?;
    if previous
        .as_ref()
        .is_some_and(|mask| mask.len() != current.cores.len())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP-AO previous listener inventory has an invalid receipt shape",
        ));
    }
    Ok(TcpAoAcceptedGenerationReceipt { current, previous })
}

/// Capture a complete listener-generation receipt. Unlike accepted-child
/// reconciliation (which asks for the covering-owner subset), generation
/// commit owns every listener MKT and therefore rejects any foreign record.
#[cfg(target_os = "linux")]
pub(crate) fn capture_tcp_ao_complete_owned_receipt(
    socket: &impl AsRawFd,
    owners: &[TcpAoMktOwner<'_>],
) -> io::Result<TcpAoMktReceipt> {
    let keys = get_tcp_ao_keys_with(|entries| query_tcp_ao_keys(socket, entries))?;
    let expected = owners
        .iter()
        .map(|owner| owner.keyring.0.len())
        .sum::<usize>();
    if keys.len() != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TCP-AO listener inventory contains keys outside the desired generation",
        ));
    }
    owned_receipt_from_raw_inventory(&keys, owners)
}

#[cfg(target_os = "linux")]
fn target_record_matches_receipt_entry(
    state: &TcpAoKeyState,
    connected_peer: IpAddr,
    metadata: &TcpAoMktMetadata,
) -> bool {
    let exact_prefix = if connected_peer.is_ipv4() { 32 } else { 128 };
    (state.peer == metadata.peer && state.prefix_len == metadata.prefix_len)
        || (state.peer == connected_peer && state.prefix_len == exact_prefix)
}

#[cfg(target_os = "linux")]
fn annotate_tcp_ao_receipt(
    info: &mut TcpAoInfoSnapshot,
    keys: &[TcpAoGetSockOpt],
    receipt: &TcpAoMktReceipt,
    connected_peer: IpAddr,
) -> io::Result<()> {
    annotate_tcp_ao_receipt_subset(info, keys, receipt, connected_peer, None)
}

#[cfg(target_os = "linux")]
fn annotate_tcp_ao_receipt_subset(
    info: &mut TcpAoInfoSnapshot,
    keys: &[TcpAoGetSockOpt],
    receipt: &TcpAoMktReceipt,
    connected_peer: IpAddr,
    expected: Option<&[bool]>,
) -> io::Result<()> {
    if expected.is_some_and(|mask| mask.len() != receipt.cores.len()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "TCP-AO accepted-generation receipt has an invalid mask shape",
        ));
    }
    let expected_entry = |index: usize| expected.is_none_or(|mask| mask[index]);
    let expected_len = expected.map_or(receipt.cores.len(), |mask| {
        mask.iter().filter(|included| **included).count()
    });
    let mut states = keys
        .iter()
        .map(decode_tcp_ao_key_state)
        .collect::<io::Result<Vec<_>>>()?;
    let mut matching = Vec::new();
    let mut expected_matched = vec![false; receipt.cores.len()];
    for (index, raw) in keys.iter().enumerate() {
        let core = mkt_core(raw)?;
        if let Some(expected_index) =
            receipt
                .cores
                .iter()
                .enumerate()
                .position(|(expected_index, expected)| {
                    expected_entry(expected_index)
                        && !expected_matched[expected_index]
                        && target_record_matches_receipt_entry(
                            &states[index],
                            connected_peer,
                            &receipt.metadata[expected_index],
                        )
                        && core == *expected
                })
        {
            expected_matched[expected_index] = true;
            matching.push((index, expected_index));
        }
    }
    // A connected socket must inherit exactly the complete expected-owned
    // keyring inventory. Missing, foreign, duplicated, or cryptographically
    // changed records all fail closed.
    if matching.len() != expected_len
        || keys.len() != expected_len
        || expected_matched
            .iter()
            .enumerate()
            .any(|(index, matched)| expected_entry(index) && !matched)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "TCP-AO connected-socket MKT inventory differs from its kernel-normalized source",
        ));
    }
    for (matched, expected) in matching {
        let metadata = &receipt.metadata[expected];
        states[matched].peer = metadata.peer;
        states[matched].prefix_len = metadata.prefix_len;
        states[matched].preferred = metadata.preferred;
        states[matched].deprecated = metadata.deprecated;
    }
    states.sort_by_key(|key| (key.peer, key.prefix_len, key.send_id, key.recv_id));
    info.keys = states;
    Ok(())
}

/// Read an accepted child once and classify only an exact current inventory or
/// an exact adjacent-previous inventory. Arbitrary prefixes, partial successor
/// applications, older generations, and foreign records all fail closed.
#[cfg(target_os = "linux")]
pub(crate) fn inspect_tcp_ao_accepted_generation(
    socket: &impl AsRawFd,
    receipt: &TcpAoAcceptedGenerationReceipt,
    connected_peer: IpAddr,
) -> io::Result<TcpAoAcceptedGeneration> {
    let (info, keys) = get_tcp_ao_snapshot_with(
        || get_tcp_ao_info_only(socket),
        || get_tcp_ao_keys_with(|entries| query_tcp_ao_keys(socket, entries)),
    )?;
    if keys.len() == receipt.current.cores.len() {
        let mut current = info;
        annotate_tcp_ao_receipt(&mut current, &keys, &receipt.current, connected_peer)?;
        return Ok(TcpAoAcceptedGeneration::Current(current));
    }
    if let Some(previous) = receipt.previous.as_deref()
        && keys.len() == previous.iter().filter(|included| **included).count()
    {
        let mut previous_info = info;
        annotate_tcp_ao_receipt_subset(
            &mut previous_info,
            &keys,
            &receipt.current,
            connected_peer,
            Some(previous),
        )?;
        return Ok(TcpAoAcceptedGeneration::Previous(previous_info));
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "TCP-AO accepted socket matches neither current nor immediate previous listener inventory",
    ))
}

#[cfg(target_os = "linux")]
pub(crate) fn get_tcp_ao_info_for_accepted_generation_receipt(
    socket: &impl AsRawFd,
    receipt: &TcpAoAcceptedGenerationReceipt,
    connected_peer: IpAddr,
) -> io::Result<TcpAoInfoSnapshot> {
    get_tcp_ao_info_for_receipt(socket, &receipt.current, connected_peer)
}

/// Add only the current-generation suffix missing from an exact
/// adjacent-previous accepted child, then require one exact final inventory
/// and unchanged Current/RNext selection. The child is still exclusively
/// owned by the listener; callers must discard it on any error.
#[cfg(target_os = "linux")]
pub(crate) fn reconcile_tcp_ao_accepted_previous(
    socket: &impl AsRawFd,
    receipt: &TcpAoAcceptedGenerationReceipt,
    owners: &[TcpAoMktOwner<'_>],
    connected_peer: IpAddr,
    initial: &TcpAoInfoSnapshot,
) -> Result<TcpAoInfoSnapshot, TcpAoAddOnlyApplyError> {
    let Some(previous) = receipt.previous.as_deref() else {
        return Err(apply_error(
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP-AO accepted child has no adjacent previous-generation proof",
            ),
            false,
        ));
    };
    let configs = owners
        .iter()
        .flat_map(|owner| {
            owner
                .keyring
                .iter()
                .map(move |config| (owner.peer, owner.prefix_len, config))
        })
        .collect::<Vec<_>>();
    if configs.len() != receipt.current.cores.len() || previous.len() != configs.len() {
        return Err(apply_error(
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "TCP-AO accepted-child repair inventory differs from its listener receipt",
            ),
            false,
        ));
    }
    let expected_selection = selection(initial);
    let mut mutation_started = false;
    for (index, (peer, prefix_len, config)) in configs.into_iter().enumerate() {
        if previous[index] {
            continue;
        }
        let metadata = &receipt.current.metadata[index];
        if metadata.peer != peer
            || metadata.prefix_len != prefix_len
            || metadata.preferred != config.preferred
            || metadata.deprecated != config.deprecated
        {
            return Err(apply_error(
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TCP-AO accepted-child repair metadata differs from its listener receipt",
                ),
                mutation_started,
            ));
        }
        mutation_started = true;
        let key = tcp_ao_key_from_config(peer, prefix_len, config, TcpAoSocketRole::Listener);
        set_tcp_ao_key(socket, &key).map_err(|error| apply_error(error, mutation_started))?;
    }
    let final_info = get_tcp_ao_info_for_receipt(socket, &receipt.current, connected_peer)
        .map_err(|error| apply_error(error, mutation_started))?;
    if selection(&final_info) != expected_selection {
        return Err(apply_error(
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "TCP-AO accepted-child repair changed Current/RNext selection",
            ),
            mutation_started,
        ));
    }
    Ok(final_info)
}

/// Reconcile a connected socket against a pre-connect/listener raw kernel MKT
/// receipt and return a redacted runtime snapshot. The receipt comparison is
/// unordered with respect to selection flags and counters; inventory and core
/// identity remain exact and fail closed.
#[cfg(target_os = "linux")]
pub(crate) fn get_tcp_ao_info_for_receipt(
    socket: &impl AsRawFd,
    receipt: &TcpAoMktReceipt,
    connected_peer: IpAddr,
) -> io::Result<TcpAoInfoSnapshot> {
    let (mut info, keys) = get_tcp_ao_snapshot_with(
        || get_tcp_ao_info_only(socket),
        || get_tcp_ao_keys_with(|entries| query_tcp_ao_keys(socket, entries)),
    )?;
    annotate_tcp_ao_receipt(&mut info, &keys, receipt, connected_peer)?;
    Ok(info)
}

/// Select only `RNext` on an accepted child. `Current` is peer-selected by the
/// authenticated handshake and must never be overwritten by the passive side.
#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    reason = "TCP-AO RNext selection uses the raw Linux TCP_AO_INFO ABI"
)]
pub(crate) fn set_tcp_ao_rnext(socket: &impl AsRawFd, recv_id: u8) -> io::Result<()> {
    // Linux assigns both policy flags on every TCP_AO_INFO set. Preserve them
    // without copying Current, RNext-presence, or counter setter bits from the
    // getter into this deliberately fresh setter.
    let current = get_tcp_ao_info_only(socket)?;
    let info = tcp_ao_rnext_update(recv_id, &current);
    let ret = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_TCP,
            TCP_AO_INFO,
            std::ptr::from_ref(&info).cast(),
            std::mem::size_of::<TcpAoInfoOpt>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn tcp_ao_rnext_update(recv_id: u8, current: &TcpAoInfoSnapshot) -> TcpAoInfoOpt {
    let mut flags = TCP_AO_INFO_SET_RNEXT;
    if current.ao_required {
        flags |= TCP_AO_INFO_AO_REQUIRED;
    }
    if current.accept_icmps {
        flags |= TCP_AO_INFO_ACCEPT_ICMPS;
    }
    debug_assert_eq!(flags & TCP_AO_INFO_SET_CURRENT, 0);
    debug_assert_eq!(flags & TCP_AO_INFO_SET_COUNTERS, 0);
    TcpAoInfoOpt {
        flags,
        reserved2: 0,
        current_key: 0,
        rnext: recv_id,
        pkt_good: 0,
        pkt_bad: 0,
        pkt_key_not_found: 0,
        pkt_ao_required: 0,
        pkt_dropped_icmp: 0,
    }
}

/// Inspect runtime TCP-AO socket state.
#[cfg(not(target_os = "linux"))]
pub(crate) fn get_tcp_ao_info<T>(_socket: &T) -> io::Result<TcpAoInfoSnapshot> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-AO inspection is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
#[allow(
    dead_code,
    reason = "singleton compatibility seam retained for Phase 1 callers"
)]
pub(crate) fn capture_tcp_ao_mkt_receipt<T>(
    _socket: &T,
    _peer: std::net::IpAddr,
    _prefix_len: u8,
    _config: &crate::config::TcpAoConfig,
    _exact_inventory: bool,
) -> io::Result<TcpAoMktReceipt> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-AO inspection is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn capture_tcp_ao_keyring_receipt<T>(
    _socket: &T,
    _peer: std::net::IpAddr,
    _prefix_len: u8,
    _keyring: &crate::config::TcpAoKeyring,
    _exact_inventory: bool,
) -> io::Result<TcpAoMktReceipt> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-AO inspection is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn capture_tcp_ao_accepted_generation_receipt<T>(
    _socket: &T,
    owners: &[TcpAoMktOwner<'_>],
    previous_key_counts: Option<&[usize]>,
) -> io::Result<TcpAoAcceptedGenerationReceipt> {
    for owner in owners {
        let _ = (owner.peer, owner.prefix_len, owner.keyring);
    }
    let _ = previous_key_counts;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-AO inspection is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn capture_tcp_ao_complete_owned_receipt<T>(
    _socket: &T,
    owners: &[TcpAoMktOwner<'_>],
) -> io::Result<TcpAoMktReceipt> {
    for owner in owners {
        let _ = (owner.peer, owner.prefix_len, owner.keyring);
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-AO inspection is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn get_tcp_ao_info_for_receipt<T>(
    _socket: &T,
    _receipt: &TcpAoMktReceipt,
    _connected_peer: std::net::IpAddr,
) -> io::Result<TcpAoInfoSnapshot> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-AO inspection is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn inspect_tcp_ao_accepted_generation<T>(
    _socket: &T,
    _receipt: &TcpAoAcceptedGenerationReceipt,
    _connected_peer: std::net::IpAddr,
) -> io::Result<TcpAoAcceptedGeneration> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-AO inspection is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn get_tcp_ao_info_for_accepted_generation_receipt<T>(
    _socket: &T,
    _receipt: &TcpAoAcceptedGenerationReceipt,
    _connected_peer: std::net::IpAddr,
) -> io::Result<TcpAoInfoSnapshot> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-AO inspection is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn reconcile_tcp_ao_accepted_previous<T>(
    _socket: &T,
    _receipt: &TcpAoAcceptedGenerationReceipt,
    owners: &[TcpAoMktOwner<'_>],
    _connected_peer: std::net::IpAddr,
    _initial: &TcpAoInfoSnapshot,
) -> Result<TcpAoInfoSnapshot, TcpAoAddOnlyApplyError> {
    for owner in owners {
        let _ = (owner.peer, owner.prefix_len, owner.keyring);
    }
    Err(TcpAoAddOnlyApplyError {
        error: io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP-AO inspection is only supported on Linux",
        ),
        mutation_started: false,
    })
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn set_tcp_ao_rnext<T>(_socket: &T, _recv_id: u8) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-AO RNext selection is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn preflight_tcp_ao_add_only<T>(
    _socket: &T,
    current: &[TcpAoMktOwner<'_>],
    desired: &[TcpAoMktOwner<'_>],
    _connected_peer: Option<std::net::IpAddr>,
) -> io::Result<TcpAoAddOnlyPreflight> {
    for owner in current.iter().chain(desired) {
        let _ = (owner.peer, owner.prefix_len, owner.keyring);
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TCP-AO live rotation is only supported on Linux",
    ))
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn apply_tcp_ao_add_only<T>(
    _socket: &T,
    _preflight: TcpAoAddOnlyPreflight,
    desired: &[TcpAoMktOwner<'_>],
    _connected_peer: Option<std::net::IpAddr>,
) -> Result<Option<TcpAoInfoSnapshot>, TcpAoAddOnlyApplyError> {
    for owner in desired {
        let _ = (owner.peer, owner.prefix_len, owner.keyring);
    }
    Err(TcpAoAddOnlyApplyError {
        error: io::Error::new(
            io::ErrorKind::Unsupported,
            "TCP-AO live rotation is only supported on Linux",
        ),
        mutation_started: false,
    })
}

#[cfg(target_os = "linux")]
impl TcpAoInfoSnapshot {
    fn from_raw(info: &TcpAoInfoOpt) -> Self {
        Self {
            has_current_key: info.flags & TCP_AO_INFO_SET_CURRENT != 0,
            has_rnext_key: info.flags & TCP_AO_INFO_SET_RNEXT != 0,
            ao_required: info.flags & TCP_AO_INFO_AO_REQUIRED != 0,
            accept_icmps: info.flags & TCP_AO_INFO_ACCEPT_ICMPS != 0,
            current_key: info.current_key,
            rnext_key: info.rnext,
            pkt_good: info.pkt_good,
            pkt_bad: info.pkt_bad,
            pkt_key_not_found: info.pkt_key_not_found,
            pkt_ao_required: info.pkt_ao_required,
            pkt_dropped_icmp: info.pkt_dropped_icmp,
            keys: Vec::new(),
        }
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
fn build_tcp_ao_add(key: &TcpAoKey<'_>) -> io::Result<Box<TcpAoAdd>> {
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

    // Allocate before copying the secret so the initialized raw record never
    // moves between stack/heap locations before its zeroizing Drop runs.
    let mut add = Box::new(unsafe { std::mem::zeroed::<TcpAoAdd>() });
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

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "decode the address prefix shared with Linux sockaddr_in and sockaddr_in6"
)]
fn read_sockaddr(storage: &libc::sockaddr_storage) -> io::Result<IpAddr> {
    match libc::c_int::from(storage.ss_family) {
        libc::AF_INET => {
            // SAFETY: AF_INET selects sockaddr_in, whose ABI-compatible prefix
            // is stored in this kernel-filled sockaddr_storage.
            let sin = unsafe { &*(std::ptr::from_ref(storage).cast::<libc::sockaddr_in>()) };
            Ok(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            // SAFETY: AF_INET6 selects sockaddr_in6, whose ABI-compatible
            // prefix is stored in this kernel-filled sockaddr_storage.
            let sin6 = unsafe { &*(std::ptr::from_ref(storage).cast::<libc::sockaddr_in6>()) };
            Ok(IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TCP-AO key address family",
        )),
    }
}

/// Enable GTSM (Generalized TTL Security Mechanism, RFC 5082) on a socket.
///
/// Sets GTSM for the remote address family: accept only directly connected
/// packets and send with TTL/Hop-Limit 255.
#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    reason = "GTSM requires raw Linux socket options and socklen_t casts"
)]
pub fn set_gtsm(socket: &Socket, remote: SocketAddr) -> io::Result<()> {
    if remote.is_ipv6() {
        return set_gtsm_v6(socket);
    }
    set_gtsm_v4(socket)
}

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    reason = "IPv4 GTSM requires raw Linux socket options and socklen_t casts"
)]
fn set_gtsm_v4(socket: &Socket) -> io::Result<()> {
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

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    clippy::cast_possible_truncation,
    reason = "IPv6 GTSM requires raw Linux socket options and socklen_t casts"
)]
fn set_gtsm_v6(socket: &Socket) -> io::Result<()> {
    let min_hops: libc::c_int = 254;
    let fd = socket.as_raw_fd();

    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MINHOPCOUNT,
            (&raw const min_hops).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    socket.set_unicast_hops_v6(255)?;
    Ok(())
}

/// Stub for non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn set_gtsm(_socket: &Socket, _remote: SocketAddr) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "GTSM / TTL security is only supported on Linux",
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::mem;

    // Stable, dependency-free negative trait assertion. If `$ty` implements
    // `$trait`, both marker implementations apply and inference fails E0283.
    macro_rules! assert_not_impl {
        ($ty:ty: $trait:path) => {
            const _: fn() = || {
                struct IfImpl;
                trait Ambiguous<A> {
                    fn check() {}
                }
                impl<T: ?Sized> Ambiguous<()> for T {}
                impl<T: ?Sized + $trait> Ambiguous<IfImpl> for T {}
                let _ = <$ty as Ambiguous<_>>::check;
            };
        };
    }

    assert_not_impl!(TcpAoAdd: std::fmt::Debug);
    assert_not_impl!(TcpAoAdd: Clone);
    assert_not_impl!(TcpAoGetSockOpt: std::fmt::Debug);
    assert_not_impl!(TcpAoGetSockOpt: Clone);
    assert_not_impl!(TcpAoMktCore: std::fmt::Debug);
    assert_not_impl!(TcpAoMktCore: Clone);

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
    fn tcp_md5sig_uapi_layout_and_secret_scrub_match_linux_header() {
        assert_eq!(mem::size_of::<TcpMd5Sig>(), 216);
        assert_eq!(mem::align_of::<TcpMd5Sig>(), 8);
        assert_eq!(mem::offset_of!(TcpMd5Sig, tcpm_addr), 0);
        assert_eq!(mem::offset_of!(TcpMd5Sig, tcpm_flags), 128);
        assert_eq!(mem::offset_of!(TcpMd5Sig, tcpm_prefixlen), 129);
        assert_eq!(mem::offset_of!(TcpMd5Sig, tcpm_keylen), 130);
        assert_eq!(mem::offset_of!(TcpMd5Sig, tcpm_ifindex), 132);
        assert_eq!(mem::offset_of!(TcpMd5Sig, tcpm_key), 136);

        let mut sig = TcpMd5Sig::zeroed();
        sig.tcpm_keylen = 15;
        sig.tcpm_key[..15].copy_from_slice(b"secret-sentinel");
        sig.scrub();

        assert_eq!(sig.tcpm_keylen, 0);
        assert!(sig.tcpm_key.iter().all(|byte| *byte == 0));
        assert!(mem::needs_drop::<TcpMd5Sig>());
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

        assert_eq!(mem::size_of::<TcpAoGetSockOpt>(), 304);
        assert_eq!(mem::align_of::<TcpAoGetSockOpt>(), 8);
        assert_eq!(mem::offset_of!(TcpAoGetSockOpt, addr), 0);
        assert_eq!(mem::offset_of!(TcpAoGetSockOpt, alg_name), 128);
        assert_eq!(mem::offset_of!(TcpAoGetSockOpt, key), 192);
        assert_eq!(mem::offset_of!(TcpAoGetSockOpt, nkeys), 272);
        assert_eq!(mem::offset_of!(TcpAoGetSockOpt, flags), 276);
        assert_eq!(mem::offset_of!(TcpAoGetSockOpt, sndid), 278);
        assert_eq!(mem::offset_of!(TcpAoGetSockOpt, ifindex), 284);
        assert_eq!(mem::offset_of!(TcpAoGetSockOpt, pkt_good), 288);
    }

    #[test]
    fn tcp_ao_constants_match_linux_header() {
        assert_eq!(TCP_AO_ADD_KEY, 38);
        assert_eq!(TCP_AO_INFO, 40);
        assert_eq!(TCP_AO_GET_KEYS, 41);
        assert_eq!(TCP_AO_MAXKEYLEN, 80);
        assert_eq!(
            TCP_AO_ADD_SET_CURRENT,
            tcp_ao_u32_bitfield_mask(0, TCP_AO_TARGET_BIG_ENDIAN)
        );
        assert_eq!(
            TCP_AO_ADD_SET_RNEXT,
            tcp_ao_u32_bitfield_mask(1, TCP_AO_TARGET_BIG_ENDIAN)
        );
        assert_eq!(
            TCP_AO_INFO_SET_CURRENT,
            tcp_ao_u32_bitfield_mask(0, TCP_AO_TARGET_BIG_ENDIAN)
        );
        assert_eq!(
            TCP_AO_INFO_SET_RNEXT,
            tcp_ao_u32_bitfield_mask(1, TCP_AO_TARGET_BIG_ENDIAN)
        );
        assert_eq!(
            TCP_AO_INFO_AO_REQUIRED,
            tcp_ao_u32_bitfield_mask(2, TCP_AO_TARGET_BIG_ENDIAN)
        );
        assert_eq!(
            TCP_AO_INFO_ACCEPT_ICMPS,
            tcp_ao_u32_bitfield_mask(4, TCP_AO_TARGET_BIG_ENDIAN)
        );
        assert_eq!(
            TCP_AO_GET_IS_CURRENT,
            tcp_ao_u16_bitfield_mask(0, TCP_AO_TARGET_BIG_ENDIAN)
        );
        assert_eq!(
            TCP_AO_GET_IS_RNEXT,
            tcp_ao_u16_bitfield_mask(1, TCP_AO_TARGET_BIG_ENDIAN)
        );
        assert_eq!(
            TCP_AO_GET_ALL,
            tcp_ao_u16_bitfield_mask(2, TCP_AO_TARGET_BIG_ENDIAN)
        );
        assert_eq!(TCP_AO_KEYF_IFINDEX, 1);
        assert_eq!(TCP_AO_KEYF_EXCLUDE_OPT, 2);
    }

    #[test]
    fn tcp_ao_c_bitfield_masks_cover_little_and_big_endian_abis() {
        assert_eq!(tcp_ao_u32_bitfield_mask(0, false), 1);
        assert_eq!(tcp_ao_u32_bitfield_mask(1, false), 2);
        assert_eq!(tcp_ao_u32_bitfield_mask(4, false), 16);
        assert_eq!(tcp_ao_u32_bitfield_mask(0, true), 1 << 31);
        assert_eq!(tcp_ao_u32_bitfield_mask(1, true), 1 << 30);
        assert_eq!(tcp_ao_u32_bitfield_mask(4, true), 1 << 27);

        assert_eq!(tcp_ao_u16_bitfield_mask(0, false), 1);
        assert_eq!(tcp_ao_u16_bitfield_mask(1, false), 2);
        assert_eq!(tcp_ao_u16_bitfield_mask(2, false), 4);
        assert_eq!(tcp_ao_u16_bitfield_mask(0, true), 1 << 15);
        assert_eq!(tcp_ao_u16_bitfield_mask(1, true), 1 << 14);
        assert_eq!(tcp_ao_u16_bitfield_mask(2, true), 1 << 13);
    }

    #[test]
    fn tcp_ao_get_keys_accepts_extended_kernel_record_size() {
        let known = mem::size_of::<TcpAoGetSockOpt>();
        assert!(validate_tcp_ao_key_record_len(known).is_ok());
        assert!(validate_tcp_ao_key_record_len(known + 16).is_ok());
        assert_eq!(
            validate_tcp_ao_key_record_len(known - 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    fn raw_dump_key(peer: IpAddr, algorithm: &str, secret: &[u8]) -> TcpAoGetSockOpt {
        let mut raw = TcpAoGetSockOpt::zeroed();
        write_sockaddr(&mut raw.addr, peer, 0);
        write_alg_name(&mut raw.alg_name, algorithm).unwrap();
        raw.key[..secret.len()].copy_from_slice(secret);
        raw.keylen = u8::try_from(secret.len()).unwrap();
        raw.prefix = if peer.is_ipv4() { 32 } else { 128 };
        raw.sndid = 7;
        raw.rcvid = 9;
        raw.flags = TCP_AO_GET_IS_CURRENT | TCP_AO_GET_IS_RNEXT;
        raw.pkt_good = 11;
        raw
    }

    #[test]
    fn tcp_ao_get_keys_retries_count_growth_and_orders_projection() {
        let mut calls = 0;
        let keys = get_tcp_ao_keys_with(|entries| {
            calls += 1;
            if calls == 1 {
                return Ok(2);
            }
            entries[0] = raw_dump_key("2001:db8::2".parse().unwrap(), "hmac(sha256)", b"two");
            entries[1] = raw_dump_key("192.0.2.1".parse().unwrap(), "hmac(sha1)", b"one");
            Ok(2)
        })
        .unwrap();
        assert_eq!(calls, 2);
        let states = redacted_tcp_ao_keys(&keys).unwrap();
        assert_eq!(states[0].peer, "192.0.2.1".parse::<IpAddr>().unwrap());
        assert_eq!(states[1].peer, "2001:db8::2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn tcp_ao_get_keys_bounds_growth_and_retries() {
        let err = get_tcp_ao_keys_with(|_| Ok(TCP_AO_MAX_INSPECT_KEYS + 1))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let err = get_tcp_ao_keys_with(|entries| Ok(entries.len() + 1))
            .err()
            .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn tcp_ao_get_keys_canonicalizes_cmac_and_rejects_bad_records() {
        let raw = raw_dump_key(IpAddr::from([192, 0, 2, 1]), "cmac(aes)", b"secret");
        assert_eq!(
            decode_tcp_ao_key_state(&raw).unwrap().algorithm,
            TcpAoAlgorithm::CmacAes128
        );

        let mut bad = raw_dump_key(IpAddr::from([192, 0, 2, 1]), "hmac(sha1)", b"secret");
        bad.keylen = 0;
        assert_eq!(
            decode_tcp_ao_key_state(&bad).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );

        let mut vrf = raw_dump_key(IpAddr::from([192, 0, 2, 1]), "hmac(sha1)", b"secret");
        vrf.keyflags = TCP_AO_KEYF_IFINDEX;
        vrf.ifindex = 9;
        assert_eq!(decode_tcp_ao_key_state(&vrf).unwrap().vrf_ifindex, Some(9));
        vrf.keyflags = 0;
        assert_eq!(
            decode_tcp_ao_key_state(&vrf).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        vrf.keyflags = 1 << 7;
        assert_eq!(
            decode_tcp_ao_key_state(&vrf).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        bad.keylen = 6;
        bad.alg_name.fill(b'x');
        assert_eq!(
            decode_tcp_ao_key_state(&bad).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        bad.alg_name.fill(0);
        write_alg_name(&mut bad.alg_name, "unknown").unwrap();
        assert_eq!(
            decode_tcp_ao_key_state(&bad).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn tcp_ao_secret_buffers_scrub_without_formatting() {
        let mut add = build_tcp_ao_add(&base_key()).unwrap();
        add.scrub();
        assert!(add.alg_name.iter().all(|byte| *byte == 0));
        assert!(add.key.iter().all(|byte| *byte == 0));
        assert_eq!(add.keylen, 0);

        let mut raw = raw_dump_key(IpAddr::from([192, 0, 2, 1]), "hmac(sha256)", b"secret");
        raw.scrub();
        assert!(raw.alg_name.iter().all(|byte| *byte == 0));
        assert!(raw.key.iter().all(|byte| *byte == 0));
        assert_eq!(raw.keylen, 0);

        assert!(std::mem::needs_drop::<TcpAoAdd>());
        assert!(std::mem::needs_drop::<TcpAoGetSockOpt>());
        assert!(std::mem::needs_drop::<TcpAoMktCore>());
        let raw = raw_dump_key(IpAddr::from([192, 0, 2, 1]), "hmac(sha256)", b"secret");
        let core = mkt_core(&raw).unwrap();
        let heap_address = core.key.as_ptr();
        let moved = core;
        let _: &Zeroizing<Vec<u8>> = &moved.key;
        assert_eq!(
            moved.key.as_ptr(),
            heap_address,
            "moving a core must not copy secret bytes"
        );
    }

    #[test]
    fn tcp_ao_secret_comparison_covers_content_and_length() {
        assert!(tcp_ao_secret_eq(b"shared secret", b"shared secret"));
        assert!(!tcp_ao_secret_eq(b"shared secret", b"shared secreu"));
        assert!(!tcp_ao_secret_eq(b"shared secret", b"shared secret!"));
        assert!(!tcp_ao_secret_eq(b"shared secret!", b"shared secret"));
    }

    #[test]
    fn tcp_ao_kernel_receipt_reconciles_normalized_core_and_rejects_inventory_drift() {
        let owner = IpAddr::from([192, 0, 2, 0]);
        let connected = IpAddr::from([192, 0, 2, 9]);
        let config = TcpAoConfig {
            key: "secret".into(),
            send_id: 7,
            recv_id: 9,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        };
        let info_raw = TcpAoInfoOpt {
            flags: TCP_AO_INFO_SET_CURRENT | TCP_AO_INFO_SET_RNEXT,
            reserved2: 0,
            current_key: 7,
            rnext: 9,
            pkt_good: 1,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
        };
        let mut listener_raw = raw_dump_key(owner, "hmac(sha256)", b"secret");
        listener_raw.prefix = 24;
        listener_raw.flags = 0;
        listener_raw.pkt_good = 0;
        let receipt =
            receipt_from_raw_inventory(&[listener_raw], owner, 24, &config, false).unwrap();

        let mut child_raw = raw_dump_key(connected, "hmac(sha256)", b"secret");
        child_raw.pkt_good = 101;
        let keys = vec![child_raw];
        let mut info = TcpAoInfoSnapshot::from_raw(&info_raw);
        annotate_tcp_ao_receipt(&mut info, &keys, &receipt, connected).unwrap();
        assert!(info.keys[0].preferred);
        assert_eq!(info.keys[0].peer, owner);
        assert_eq!(info.keys[0].prefix_len, 24);

        assert_eq!(
            annotate_tcp_ao_receipt(&mut info, &[], &receipt, connected)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        let wrong_secret = vec![raw_dump_key(connected, "hmac(sha256)", b"wrong")];
        assert_eq!(
            annotate_tcp_ao_receipt(&mut info, &wrong_secret, &receipt, connected)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        let extra = vec![
            raw_dump_key(connected, "hmac(sha256)", b"secret"),
            raw_dump_key(IpAddr::from([192, 0, 2, 2]), "hmac(sha256)", b"other"),
        ];
        assert_eq!(
            annotate_tcp_ao_receipt(&mut info, &extra, &receipt, connected)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );

        for mut wrong in [
            raw_dump_key(IpAddr::from([192, 0, 2, 2]), "hmac(sha256)", b"secret"),
            raw_dump_key(connected, "hmac(sha1)", b"secret"),
            raw_dump_key(connected, "hmac(sha256)", b"secret"),
        ] {
            if wrong.alg_name.starts_with(b"hmac(sha256)")
                && read_sockaddr(&wrong.addr).unwrap() == connected
            {
                wrong.sndid = 8;
            }
            let wrong = vec![wrong];
            assert_eq!(
                annotate_tcp_ao_receipt(&mut info, &wrong, &receipt, connected)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn tcp_ao_raw_config_receipt_accepts_kernel_normalized_aes_cmac_material() {
        let peer = IpAddr::from([192, 0, 2, 1]);
        let config = TcpAoConfig {
            key: "cmac-master13".into(),
            send_id: 7,
            recv_id: 9,
            algorithm: TcpAoAlgorithm::CmacAes128,
            preferred: false,
            deprecated: false,
        };
        assert_eq!(config.key.as_ref().len(), 13);
        let normalized = [0xa5; 16];
        let raw = raw_dump_key(peer, "cmac(aes)", &normalized);
        let receipt = receipt_from_raw_inventory(&[raw], peer, 32, &config, true).unwrap();
        assert_eq!(receipt.cores[0].key.as_slice(), normalized);
        assert_ne!(
            receipt.cores[0].key.as_slice(),
            config.key.as_ref().as_bytes()
        );
    }

    #[test]
    fn tcp_ao_keyring_receipt_requires_and_annotates_complete_owned_inventory() {
        let owner = IpAddr::from([192, 0, 2, 0]);
        let connected = IpAddr::from([192, 0, 2, 9]);
        let first = TcpAoConfig {
            key: "old".into(),
            send_id: 7,
            recv_id: 9,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: true,
        };
        let second = TcpAoConfig {
            key: "next".into(),
            send_id: 8,
            recv_id: 10,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        };
        let ring = TcpAoKeyring(vec![first, second]);
        let mut listener_first = raw_dump_key(owner, "hmac(sha256)", b"old");
        listener_first.prefix = 24;
        let mut listener_second = raw_dump_key(owner, "hmac(sha256)", b"next");
        listener_second.prefix = 24;
        listener_second.sndid = 8;
        listener_second.rcvid = 10;
        let receipt = keyring_receipt_from_raw_inventory(
            &[listener_first, listener_second],
            owner,
            24,
            &ring,
            true,
        )
        .unwrap();

        let mut child_first = raw_dump_key(connected, "hmac(sha256)", b"old");
        child_first.flags = TCP_AO_GET_IS_CURRENT;
        let mut child_second = raw_dump_key(connected, "hmac(sha256)", b"next");
        child_second.sndid = 8;
        child_second.rcvid = 10;
        child_second.flags = TCP_AO_GET_IS_RNEXT;
        let info_raw = TcpAoInfoOpt {
            flags: TCP_AO_INFO_SET_CURRENT | TCP_AO_INFO_SET_RNEXT,
            reserved2: 0,
            current_key: 7,
            rnext: 10,
            pkt_good: 1,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
        };
        let mut info = TcpAoInfoSnapshot::from_raw(&info_raw);
        annotate_tcp_ao_receipt(&mut info, &[child_first, child_second], &receipt, connected)
            .unwrap();
        assert_eq!(info.keys.len(), 2);
        assert!(
            info.keys
                .iter()
                .find(|key| key.send_id == 7)
                .unwrap()
                .deprecated
        );
        assert!(
            info.keys
                .iter()
                .find(|key| key.send_id == 8)
                .unwrap()
                .preferred
        );

        let missing = vec![raw_dump_key(connected, "hmac(sha256)", b"old")];
        assert_eq!(
            annotate_tcp_ao_receipt(&mut info, &missing, &receipt, connected)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn accepted_generation_receipt_allows_only_exact_current_or_adjacent_previous() {
        let owner = IpAddr::from([192, 0, 2, 0]);
        let connected = IpAddr::from([192, 0, 2, 9]);
        let configs = [("old", 7, 9), ("selected", 8, 10), ("successor", 11, 13)];
        let ring = TcpAoKeyring(
            configs
                .iter()
                .map(|(secret, send_id, recv_id)| TcpAoConfig {
                    key: (*secret).into(),
                    send_id: *send_id,
                    recv_id: *recv_id,
                    algorithm: TcpAoAlgorithm::HmacSha256,
                    preferred: *send_id == 8,
                    deprecated: *send_id == 7,
                })
                .collect(),
        );
        let listener = configs
            .iter()
            .map(|(secret, send_id, recv_id)| {
                let mut raw = raw_dump_key(owner, "hmac(sha256)", secret.as_bytes());
                raw.prefix = 24;
                raw.sndid = *send_id;
                raw.rcvid = *recv_id;
                raw.flags = 0;
                raw
            })
            .collect::<Vec<_>>();
        let receipt =
            keyring_receipt_from_raw_inventory(&listener, owner, 24, &ring, true).unwrap();
        let info_raw = TcpAoInfoOpt {
            flags: TCP_AO_INFO_SET_CURRENT | TCP_AO_INFO_SET_RNEXT,
            reserved2: 0,
            current_key: 8,
            rnext: 10,
            pkt_good: 1,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
        };
        let child = |entries: &[usize]| {
            entries
                .iter()
                .map(|index| {
                    let (secret, send_id, recv_id) = configs[*index];
                    let mut raw = raw_dump_key(connected, "hmac(sha256)", secret.as_bytes());
                    raw.sndid = send_id;
                    raw.rcvid = recv_id;
                    raw.flags = 0;
                    raw
                })
                .collect::<Vec<_>>()
        };
        let previous = [true, true, false];

        let mut current_info = TcpAoInfoSnapshot::from_raw(&info_raw);
        annotate_tcp_ao_receipt(&mut current_info, &child(&[0, 1, 2]), &receipt, connected)
            .unwrap();
        assert_eq!(current_info.keys.len(), 3);

        let mut previous_info = TcpAoInfoSnapshot::from_raw(&info_raw);
        annotate_tcp_ao_receipt_subset(
            &mut previous_info,
            &child(&[0, 1]),
            &receipt,
            connected,
            Some(&previous),
        )
        .unwrap();
        assert_eq!(previous_info.keys.len(), 2);

        for invalid in [child(&[0]), child(&[0, 2]), child(&[0, 1, 2])] {
            let mut info = TcpAoInfoSnapshot::from_raw(&info_raw);
            assert_eq!(
                annotate_tcp_ao_receipt_subset(
                    &mut info,
                    &invalid,
                    &receipt,
                    connected,
                    Some(&previous),
                )
                .unwrap_err()
                .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }

    #[test]
    fn tcp_ao_owned_union_receipt_requires_exact_child_inventory_and_keeps_owners() {
        let connected = IpAddr::from([192, 0, 2, 9]);
        let covering_peer = IpAddr::from([192, 0, 2, 0]);
        let covering = TcpAoKeyring(vec![TcpAoConfig {
            key: "covering".into(),
            send_id: 7,
            recv_id: 9,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }]);
        let exact = TcpAoKeyring(vec![TcpAoConfig {
            key: "exact".into(),
            send_id: 8,
            recv_id: 10,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        }]);
        let owners = [
            TcpAoMktOwner {
                peer: covering_peer,
                prefix_len: 24,
                keyring: &covering,
            },
            TcpAoMktOwner {
                peer: connected,
                prefix_len: 32,
                keyring: &exact,
            },
        ];
        let mut listener_covering = raw_dump_key(covering_peer, "hmac(sha256)", b"covering");
        listener_covering.prefix = 24;
        let mut listener_exact = raw_dump_key(connected, "hmac(sha256)", b"exact");
        listener_exact.sndid = 8;
        listener_exact.rcvid = 10;
        let receipt =
            owned_receipt_from_raw_inventory(&[listener_covering, listener_exact], &owners)
                .unwrap();

        let child_covering = raw_dump_key(connected, "hmac(sha256)", b"covering");
        let mut child_exact = raw_dump_key(connected, "hmac(sha256)", b"exact");
        child_exact.sndid = 8;
        child_exact.rcvid = 10;
        let mut info = TcpAoInfoSnapshot::from_raw(&TcpAoInfoOpt {
            flags: 0,
            reserved2: 0,
            current_key: 0,
            rnext: 0,
            pkt_good: 0,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
        });
        annotate_tcp_ao_receipt(
            &mut info,
            &[child_covering, child_exact],
            &receipt,
            connected,
        )
        .unwrap();
        assert_eq!(info.keys.len(), 2);
        assert!(
            info.keys.iter().any(|key| {
                key.peer == covering_peer && key.prefix_len == 24 && key.send_id == 7
            })
        );
        assert!(info.keys.iter().any(|key| {
            key.peer == connected && key.prefix_len == 32 && key.send_id == 8 && key.preferred
        }));

        let missing = [raw_dump_key(connected, "hmac(sha256)", b"covering")];
        assert_eq!(
            annotate_tcp_ao_receipt(&mut info, &missing, &receipt, connected)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        let mut foreign = raw_dump_key(connected, "hmac(sha256)", b"foreign");
        foreign.sndid = 99;
        foreign.rcvid = 100;
        let extra = [
            raw_dump_key(connected, "hmac(sha256)", b"covering"),
            {
                let mut exact = raw_dump_key(connected, "hmac(sha256)", b"exact");
                exact.sndid = 8;
                exact.rcvid = 10;
                exact
            },
            foreign,
        ];
        assert_eq!(
            annotate_tcp_ao_receipt(&mut info, &extra, &receipt, connected)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn tcp_ao_passive_rnext_update_preserves_policy_without_forcing_current_or_counters() {
        let current = TcpAoInfoSnapshot::from_raw(&TcpAoInfoOpt {
            flags: TCP_AO_INFO_SET_CURRENT
                | TCP_AO_INFO_SET_RNEXT
                | TCP_AO_INFO_AO_REQUIRED
                | TCP_AO_INFO_ACCEPT_ICMPS,
            reserved2: 0,
            current_key: 7,
            rnext: 9,
            pkt_good: 11,
            pkt_bad: 13,
            pkt_key_not_found: 17,
            pkt_ao_required: 19,
            pkt_dropped_icmp: 23,
        });
        let update = tcp_ao_rnext_update(29, &current);
        assert_eq!(
            update.flags,
            TCP_AO_INFO_SET_RNEXT | TCP_AO_INFO_AO_REQUIRED | TCP_AO_INFO_ACCEPT_ICMPS
        );
        assert_eq!(update.flags & TCP_AO_INFO_SET_CURRENT, 0);
        assert_eq!(update.flags & TCP_AO_INFO_SET_COUNTERS, 0);
        assert_eq!(update.current_key, 0);
        assert_eq!(update.rnext, 29);
        assert_eq!(update.pkt_good, 0);
        assert_eq!(update.pkt_bad, 0);
        assert_eq!(update.pkt_key_not_found, 0);
        assert_eq!(update.pkt_ao_required, 0);
        assert_eq!(update.pkt_dropped_icmp, 0);
    }

    #[test]
    fn tcp_ao_composite_snapshot_uses_trailing_info_counters() {
        let key_queried = std::cell::Cell::new(false);
        let (info, _) = get_tcp_ao_snapshot_with(
            || {
                Ok(TcpAoInfoSnapshot::from_raw(&TcpAoInfoOpt {
                    flags: TCP_AO_INFO_SET_CURRENT | TCP_AO_INFO_SET_RNEXT,
                    reserved2: 0,
                    current_key: 7,
                    rnext: 9,
                    pkt_good: 1,
                    pkt_bad: u64::from(key_queried.get()),
                    pkt_key_not_found: 0,
                    pkt_ao_required: 0,
                    pkt_dropped_icmp: 0,
                }))
            },
            || {
                key_queried.set(true);
                Ok(vec![raw_dump_key(
                    IpAddr::from([192, 0, 2, 1]),
                    "hmac(sha256)",
                    b"secret",
                )])
            },
        )
        .unwrap();
        assert!(key_queried.get());
        assert_eq!(info.pkt_bad, 1);
    }

    #[test]
    fn tcp_ao_composite_snapshot_retries_inconsistent_key_selection() {
        let info = TcpAoInfoSnapshot::from_raw(&TcpAoInfoOpt {
            flags: TCP_AO_INFO_SET_CURRENT | TCP_AO_INFO_SET_RNEXT,
            reserved2: 0,
            current_key: 7,
            rnext: 9,
            pkt_good: 1,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
        });
        let mut calls = 0;
        let (_, keys) = get_tcp_ao_snapshot_with(
            || Ok(info.clone()),
            || {
                calls += 1;
                let mut raw = raw_dump_key(IpAddr::from([192, 0, 2, 1]), "hmac(sha256)", b"secret");
                if calls == 1 {
                    raw.sndid = 8;
                }
                Ok(vec![raw])
            },
        )
        .unwrap();
        assert_eq!(calls, 2);
        assert_eq!(decode_tcp_ao_key_state(&keys[0]).unwrap().send_id, 7);

        let err = get_tcp_ao_snapshot_with(
            || Ok(info.clone()),
            || {
                let mut raw = raw_dump_key(IpAddr::from([192, 0, 2, 1]), "hmac(sha256)", b"secret");
                raw.sndid = 8;
                Ok(vec![raw])
            },
        )
        .err()
        .unwrap();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn tcp_ao_info_snapshot_maps_raw_flags_and_counters() {
        let raw = TcpAoInfoOpt {
            flags: TCP_AO_INFO_SET_CURRENT | TCP_AO_INFO_SET_RNEXT | TCP_AO_INFO_ACCEPT_ICMPS,
            reserved2: 0,
            current_key: 7,
            rnext: 9,
            pkt_good: 11,
            pkt_bad: 13,
            pkt_key_not_found: 17,
            pkt_ao_required: 19,
            pkt_dropped_icmp: 23,
        };

        let snapshot = TcpAoInfoSnapshot::from_raw(&raw);

        assert!(snapshot.has_current_key);
        assert!(snapshot.has_rnext_key);
        assert!(!snapshot.ao_required);
        assert!(snapshot.accept_icmps);
        assert_eq!(snapshot.current_key, 7);
        assert_eq!(snapshot.rnext_key, 9);
        assert_eq!(snapshot.pkt_good, 11);
        assert_eq!(snapshot.pkt_bad, 13);
        assert_eq!(snapshot.pkt_key_not_found, 17);
        assert_eq!(snapshot.pkt_ao_required, 19);
        assert_eq!(snapshot.pkt_dropped_icmp, 23);
    }

    #[test]
    fn tcp_ao_add_encodes_peer_key_and_algorithm() {
        let add = build_tcp_ao_add(&base_key()).unwrap();

        assert_eq!(add.prefix, 32);
        assert_eq!(add.sndid, 7);
        assert_eq!(add.rcvid, 9);
        assert_eq!(add.maclen, 12);
        assert_eq!(add.keyflags, 0);
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
            key: "secret".into(),
            send_id: 10,
            recv_id: 11,
            algorithm: TcpAoAlgorithm::HmacSha1,
            preferred: false,
            deprecated: false,
        };

        let key = tcp_ao_key_from_config(
            IpAddr::from([198, 51, 100, 1]),
            24,
            &config,
            TcpAoSocketRole::ActiveOpen,
        );

        assert_eq!(key.prefix_len, 24);
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
            key: "secret".into(),
            send_id: 10,
            recv_id: 11,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        };

        let key = tcp_ao_key_from_config(
            "2001:db8::1".parse().unwrap(),
            48,
            &config,
            TcpAoSocketRole::Listener,
        );

        assert_eq!(key.prefix_len, 48);
        assert_eq!(key.algorithm, TcpAoAlgorithm::HmacSha256);
        assert!(!key.set_current);
        assert!(!key.set_rnext);
    }

    #[test]
    fn add_only_sequence_marks_nth_add_failure_as_mutating() {
        let actual = std::cell::RefCell::new(vec![true, false, false]);
        let adds = std::cell::Cell::new(0_usize);
        let mut present = vec![true, false, false];
        let error = run_add_only_sequence(
            &mut present,
            || Ok(actual.borrow().clone()),
            |index| {
                adds.set(adds.get() + 1);
                if adds.get() == 2 {
                    return Err(io::Error::other("injected second add failure"));
                }
                actual.borrow_mut()[index] = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.mutation_started());
        assert_eq!(adds.get(), 2);
    }

    #[test]
    fn add_only_sequence_marks_post_inventory_failure_as_mutating() {
        let actual = std::cell::RefCell::new(vec![true, false]);
        let mut present = actual.borrow().clone();
        let error = run_add_only_sequence(
            &mut present,
            || Ok(actual.borrow().clone()),
            |_index| Ok(()),
        )
        .unwrap_err();
        assert!(error.mutation_started());
        assert!(error.to_string().contains("post-add inventory"));
    }

    #[test]
    fn add_only_sequence_marks_post_add_selection_failure_as_mutating() {
        let actual = std::cell::RefCell::new(vec![true, false]);
        let verifies = std::cell::Cell::new(0_usize);
        let mut present = actual.borrow().clone();
        let error = run_add_only_sequence(
            &mut present,
            || {
                verifies.set(verifies.get() + 1);
                if verifies.get() == 3 {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "injected Current/RNext drift",
                    ));
                }
                Ok(actual.borrow().clone())
            },
            |index| {
                actual.borrow_mut()[index] = true;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.mutation_started());
        assert!(error.to_string().contains("Current/RNext"));
    }

    #[test]
    fn tcp_ao_probe_classifies_kernel_response() {
        let support = probe_tcp_ao_support();
        if let TcpAoSupport::ProbeFailed(err) = support {
            assert!(!err.is_empty());
        }
    }
}
