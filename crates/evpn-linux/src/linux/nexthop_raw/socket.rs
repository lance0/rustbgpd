//! Async wrapper around a dedicated `NETLINK_ROUTE` socket for
//! FDB nexthop group programming.
//!
//! ADR-0059 §3 mandates a socket distinct from the daemon's primary
//! `rtnetlink::Handle` so nexthop-group programming doesn't compete
//! with the existing FDB / link / route traffic. The socket uses
//! `netlink-sys::TokioSocket` directly (no rtnetlink request/response
//! machinery) so we can emit our own clean-room wire bytes per the
//! sibling `encode` module.
//!
//! ## Concurrency
//!
//! Every send→ACK pairing must run atomically against a single
//! socket: two concurrent awaits would race their ACKs and could
//! swap them. We enforce this at the borrow checker with `&mut self`
//! on every operation. Slice 3's reconcile actor owns exactly one
//! [`NexthopSocket`], so the constraint is free in practice.
//!
//! ## Address-family coverage
//!
//! `add_fdb_member` accepts both IPv4 and IPv6 gateways (ADR-0059
//! slice 3.5 PR 3). The encoder picks `nh_family = AF_INET` /
//! `AF_INET6` from the gateway form.

use std::io;
use std::net::IpAddr;

use netlink_sys::{AsyncSocket, AsyncSocketExt, SocketAddr, TokioSocket, protocols::NETLINK_ROUTE};
use thiserror::Error;
use tracing::debug;

use super::encode::{
    NexthopEncodeError, encode_add_fdb_group, encode_add_fdb_member, encode_del, encode_dump,
};
use super::uapi::{NHA_FDB, NHA_GATEWAY, NHA_GROUP, NHA_ID, NexthopGrp, RTM_NEWNEXTHOP};
use crate::dataplane::{KernelNexthop, KernelNexthopKind};
use crate::nh_id_alloc::NhIdAllocator;

/// Netlink message type for ACK / error responses.
const NLMSG_ERROR: u16 = 2;
/// Netlink message type for no-op messages (skip during parse).
const NLMSG_NOOP: u16 = 1;
/// Netlink message type marking the end of a multi-part response
/// (we don't expect these for our request/reply pattern but skip
/// them defensively).
const NLMSG_DONE: u16 = 3;
/// Size of the fixed `nlmsghdr` prefix on every netlink message.
const NLMSGHDR_SIZE: usize = 16;

/// Linux's `EEXIST` errno. Treat as idempotent ACK on add per
/// ADR-0059 §5 invariant 8.
const EEXIST: i32 = 17;
/// Linux's `ENOENT` errno. Treat as idempotent ACK on del per
/// ADR-0059 §5 invariant 8.
const ENOENT: i32 = 2;

/// One member of an FDB nexthop group.
///
/// Constructed via [`Self::new`] / [`Self::with_weight`] so the
/// kernel's "id != 0" invariant is enforced before the encoder
/// sees the value. The on-wire reserved fields are always zero
/// and unreachable from callers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NexthopGroupMember {
    id: u32,
    weight: u8,
}

impl NexthopGroupMember {
    /// Construct a member with uniform weight (weight = 0, which
    /// the kernel interprets as weight 1).
    ///
    /// # Errors
    ///
    /// Returns [`NexthopValidationError::ZeroId`] if `id == 0`.
    pub fn new(id: u32) -> Result<Self, NexthopValidationError> {
        if id == 0 {
            return Err(NexthopValidationError::ZeroId);
        }
        Ok(Self { id, weight: 0 })
    }

    /// Construct a member with an explicit weight byte.
    ///
    /// # Errors
    ///
    /// Returns [`NexthopValidationError::ZeroId`] if `id == 0`.
    pub fn with_weight(id: u32, weight: u8) -> Result<Self, NexthopValidationError> {
        if id == 0 {
            return Err(NexthopValidationError::ZeroId);
        }
        Ok(Self { id, weight })
    }

    /// Nexthop ID this member references.
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Kernel-visible weight (0 means weight 1).
    #[must_use]
    pub fn weight(&self) -> u8 {
        self.weight
    }
}

/// Input-validation failures that fire before any netlink send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum NexthopValidationError {
    /// Caller tried to construct a group with no members.
    #[error("nexthop group must have at least one member")]
    EmptyGroup,
    /// Caller-supplied group contains the same nexthop ID twice.
    #[error("nexthop group contains duplicate member id {0}")]
    DuplicateMemberId(u32),
    /// Caller supplied id 0; reserved by the kernel.
    #[error("nexthop id 0 is reserved")]
    ZeroId,
}

/// Failures that can come back from [`NexthopSocket`] operations.
#[derive(Debug, Error)]
pub enum NexthopError {
    /// Underlying socket I/O failed.
    #[error("netlink I/O: {0}")]
    Io(#[from] io::Error),
    /// Kernel returned a non-zero errno in the ACK. Positive errno
    /// (we negate the on-wire `-errno`).
    #[error("kernel returned errno {0}")]
    Kernel(i32),
    /// Receive buffer was shorter than the declared `nlmsg_len`.
    #[error("netlink datagram truncated")]
    Truncated,
    /// Got something other than `NLMSG_ERROR` for our seq.
    #[error("unexpected netlink message type {0} for our seq")]
    UnexpectedMessage(u16),
    /// Caller-side validation failed before the send.
    #[error("nexthop validation: {0}")]
    Validation(#[from] NexthopValidationError),
    /// Local netlink request encoding failed before the send.
    #[error("nexthop encode: {0}")]
    Encode(#[from] NexthopEncodeError),
}

/// A `NETLINK_ROUTE` socket dedicated to FDB nexthop group
/// programming.
pub struct NexthopSocket {
    socket: TokioSocket,
    seq: u32,
}

impl NexthopSocket {
    /// Open a new `NETLINK_ROUTE` socket, bind to a kernel-assigned
    /// pid, and connect the peer endpoint to the kernel (pid 0).
    /// Doesn't subscribe to any multicast groups; slice 2 is
    /// request/reply only.
    ///
    /// # Errors
    ///
    /// Returns [`NexthopError::Io`] if `NETLINK_ROUTE` socket open,
    /// `bind_auto`, or peer-`connect` fails.
    pub fn connect() -> Result<Self, NexthopError> {
        let mut socket = TokioSocket::new(NETLINK_ROUTE)?;
        socket.socket_mut().bind_auto()?;
        socket.socket_mut().connect(&SocketAddr::new(0, 0))?;
        Ok(Self { socket, seq: 1 })
    }

    /// Install one per-VTEP FDB nexthop. The nexthop ID must be
    /// non-zero. ADR-0059 slice 3.5 PR 3 enables IPv6 gateways
    /// alongside IPv4 — the encoder picks `nh_family = AF_INET` or
    /// `AF_INET6` from the gateway form.
    ///
    /// # Errors
    ///
    /// - [`NexthopError::Validation`] with `ZeroId` if `id == 0`.
    /// - [`NexthopError::Encode`] if the local netlink request would exceed
    ///   netlink length fields.
    /// - [`NexthopError::Io`] on socket failure.
    /// - [`NexthopError::Kernel`] on kernel-side errno ≠ 0
    ///   (`EEXIST` is treated as idempotent ACK).
    pub async fn add_fdb_member(&mut self, id: u32, gateway: IpAddr) -> Result<(), NexthopError> {
        if id == 0 {
            return Err(NexthopValidationError::ZeroId.into());
        }
        let seq = self.next_seq();
        let bytes = encode_add_fdb_member(seq, id, gateway)?;
        self.exchange(seq, &bytes, /* idempotent_eexist */ true)
            .await
    }

    /// Install an FDB nexthop group whose members reference per-VTEP
    /// nexthops already in the kernel (typically pre-installed by
    /// [`Self::add_fdb_member`] calls).
    ///
    /// # Errors
    ///
    /// - [`NexthopError::Validation`] with `ZeroId`, `EmptyGroup`,
    ///   or `DuplicateMemberId` on precondition violation.
    /// - [`NexthopError::Encode`] if the local netlink request would exceed
    ///   netlink length fields.
    /// - [`NexthopError::Io`] on socket failure.
    /// - [`NexthopError::Kernel`] on kernel-side errno ≠ 0
    ///   (`EEXIST` is treated as idempotent ACK).
    pub async fn add_fdb_group(
        &mut self,
        id: u32,
        members: &[NexthopGroupMember],
    ) -> Result<(), NexthopError> {
        if id == 0 {
            return Err(NexthopValidationError::ZeroId.into());
        }
        if members.is_empty() {
            return Err(NexthopValidationError::EmptyGroup.into());
        }
        // Duplicate scan: sort a small Vec of ids, compare adjacent.
        let mut ids: Vec<u32> = members.iter().map(|m| m.id).collect();
        ids.sort_unstable();
        for w in ids.windows(2) {
            if w[0] == w[1] {
                return Err(NexthopValidationError::DuplicateMemberId(w[0]).into());
            }
        }

        // Project the domain-shaped members into wire-shaped NexthopGrp.
        let wire: Vec<NexthopGrp> = members
            .iter()
            .map(|m| NexthopGrp {
                id: m.id,
                weight: m.weight,
                resvd1: 0,
                resvd2: 0,
            })
            .collect();

        let seq = self.next_seq();
        let bytes = encode_add_fdb_group(seq, id, &wire)?;
        self.exchange(seq, &bytes, /* idempotent_eexist */ true)
            .await
    }

    /// Dump every rustbgpd-tagged L2 FDB nexthop in the kernel,
    /// filtered client-side by [`NhIdAllocator::is_ours`] + presence
    /// of `NHA_FDB`. ADR-0059 slice 3b uses this from the
    /// reconcile actor's first `reconcile_once` pass (via the
    /// `NexthopOps::dump_owned_nexthops` trait method on
    /// `LinuxDataplane`, which forwards here) so the allocator can
    /// reserve any IDs left behind by a prior daemon instance,
    /// preventing accidental `NLM_F_REPLACE`-style overwrites of
    /// kernel state still referenced by stale FDB rows. Adoption is
    /// intentionally deferred past `connect()` so allocator + refcount
    /// state stays owned by the actor (ADR-0059 §7 boundary).
    ///
    /// Kernel is allowed to emit `NHA_GROUP_TYPE` and
    /// `NHA_OP_FLAGS` on dump even when we never set them on add;
    /// the parser tolerates both gracefully (research §1).
    ///
    /// # Errors
    ///
    /// - [`NexthopError::Encode`] if the local netlink request would exceed
    ///   netlink length fields.
    /// - [`NexthopError::Io`] on socket failure.
    /// - [`NexthopError::Kernel`] on a kernel-side error frame.
    /// - [`NexthopError::Truncated`] / [`NexthopError::UnexpectedMessage`]
    ///   if the multipart parser hits a malformed datagram.
    pub async fn dump_owned(&mut self) -> Result<Vec<KernelNexthop>, NexthopError> {
        self.dump_owned_with_class(NexthopDumpClass::L2FdbNhg).await
    }

    /// Dump every rustbgpd-tagged L3VXLAN FDB nexthop in the kernel,
    /// filtered client-side by [`NhIdAllocator::is_l3_ours`] +
    /// presence of `NHA_FDB`. This is intentionally separate from
    /// [`Self::dump_owned`] so L2 adoption cannot see L3 NHID ranges.
    ///
    /// # Errors
    ///
    /// Same failure modes as [`Self::dump_owned`].
    pub async fn dump_owned_l3(&mut self) -> Result<Vec<KernelNexthop>, NexthopError> {
        self.dump_owned_with_class(NexthopDumpClass::L3FdbNhg).await
    }

    async fn dump_owned_with_class(
        &mut self,
        class: NexthopDumpClass,
    ) -> Result<Vec<KernelNexthop>, NexthopError> {
        let seq = self.next_seq();
        let bytes = encode_dump(seq)?;
        self.socket.send(&bytes).await?;

        let mut out: Vec<KernelNexthop> = Vec::new();
        // Multipart dumps can span many datagrams; keep reading
        // until we see NLMSG_DONE (or NLMSG_ERROR).
        loop {
            let (buf, _addr) = self.socket.recv_from_full().await?;
            match drain_dump_datagram_for_class(&buf, seq, class, &mut out)? {
                DumpProgress::Continue => {}
                DumpProgress::Done => return Ok(out),
                DumpProgress::KernelError(e) => return Err(NexthopError::Kernel(e)),
            }
        }
    }

    /// Remove the nexthop named by `id`. Returns Ok if the entry
    /// didn't exist (`ENOENT` is treated as idempotent ACK per
    /// ADR-0059 §5 invariant 8).
    ///
    /// # Errors
    ///
    /// - [`NexthopError::Validation`] with `ZeroId` if `id == 0`.
    /// - [`NexthopError::Encode`] if the local netlink request would exceed
    ///   netlink length fields.
    /// - [`NexthopError::Io`] on socket failure.
    /// - [`NexthopError::Kernel`] on kernel-side errno ≠ 0 other
    ///   than `ENOENT` (which is treated as idempotent ACK).
    pub async fn del(&mut self, id: u32) -> Result<(), NexthopError> {
        if id == 0 {
            return Err(NexthopValidationError::ZeroId.into());
        }
        let seq = self.next_seq();
        let bytes = encode_del(seq, id)?;
        self.exchange(seq, &bytes, /* idempotent_eexist */ false)
            .await
    }

    fn next_seq(&mut self) -> u32 {
        let s = self.seq;
        self.seq = self.seq.wrapping_add(1);
        if self.seq == 0 {
            self.seq = 1; // skip 0 to keep "our seq" cleanly non-zero
        }
        s
    }

    /// Send `bytes`, then loop reading datagrams until we see an
    /// `NLMSG_ERROR` matching `seq`. Returns Ok on errno=0 ACK or
    /// on idempotent EEXIST/ENOENT per `idempotent_eexist` /
    /// del-path semantics.
    async fn exchange(
        &mut self,
        seq: u32,
        bytes: &[u8],
        idempotent_eexist: bool,
    ) -> Result<(), NexthopError> {
        self.socket.send(bytes).await?;

        // Loop in case multiple netlink messages share one datagram
        // or another sender's traffic interleaves (rare on our
        // dedicated socket but cheap to handle correctly).
        loop {
            let (buf, _addr) = self.socket.recv_from_full().await?;
            if let Some(outcome) = parse_response_for_seq(&buf, seq)? {
                return match outcome {
                    AckOutcome::Ok => Ok(()),
                    AckOutcome::Errno(EEXIST) if idempotent_eexist => {
                        debug!(seq, "nexthop: EEXIST treated as idempotent ACK");
                        Ok(())
                    }
                    AckOutcome::Errno(ENOENT) if !idempotent_eexist => {
                        debug!(seq, "nexthop: ENOENT on del treated as idempotent ACK");
                        Ok(())
                    }
                    AckOutcome::Errno(e) => Err(NexthopError::Kernel(e)),
                };
            }
            // No message matching our seq in this datagram; loop and read again.
        }
    }
}

/// Outcome of parsing a single `NLMSG_ERROR` for our seq.
enum AckOutcome {
    Ok,
    Errno(i32),
}

/// Walk `buf` as a sequence of netlink messages. For the first
/// message whose `nlmsg_seq` matches `seq`, return:
///
/// - `Ok(Some(AckOutcome::Ok))` if it's an `NLMSG_ERROR` with errno 0,
/// - `Ok(Some(AckOutcome::Errno(e)))` for nonzero errno (positive),
/// - `Err(NexthopError::UnexpectedMessage(t))` if it's a different
///   `nlmsg_type` than `NLMSG_ERROR`.
///
/// If no message in `buf` matches `seq`, returns `Ok(None)` so the
/// caller can read the next datagram.
fn parse_response_for_seq(buf: &[u8], seq: u32) -> Result<Option<AckOutcome>, NexthopError> {
    let mut offset = 0;
    while offset + NLMSGHDR_SIZE <= buf.len() {
        let header_slice = &buf[offset..offset + NLMSGHDR_SIZE];
        let nlmsg_len = read_u32_ne(header_slice, 0)? as usize;
        let nlmsg_type = read_u16_ne(header_slice, 4)?;
        let nlmsg_seq = read_u32_ne(header_slice, 8)?;

        if nlmsg_len < NLMSGHDR_SIZE || offset + nlmsg_len > buf.len() {
            return Err(NexthopError::Truncated);
        }

        if nlmsg_seq != seq {
            // Not our reply; advance past this message (aligned to 4 bytes).
            offset += nla_align(nlmsg_len);
            continue;
        }

        // Match. Expect NLMSG_ERROR for the request/reply pattern.
        match nlmsg_type {
            NLMSG_ERROR => {
                // Payload starts at offset + NLMSGHDR_SIZE; first
                // 4 bytes are the i32 errno (native-endian, on-wire
                // negative-errno convention — kernel sends -EEXIST
                // as -17, we negate to 17).
                if nlmsg_len < NLMSGHDR_SIZE + 4 {
                    return Err(NexthopError::Truncated);
                }
                let raw = read_i32_ne(buf, offset + NLMSGHDR_SIZE)?;
                if raw == 0 {
                    return Ok(Some(AckOutcome::Ok));
                }
                // Kernel sends negative errno; produce positive.
                // unsigned_abs() yields u32; clamp to i32 to avoid
                // wrap in the (impossible) raw == i32::MIN case.
                let positive = i32::try_from(raw.unsigned_abs()).unwrap_or(i32::MAX);
                return Ok(Some(AckOutcome::Errno(positive)));
            }
            NLMSG_NOOP | NLMSG_DONE => {
                // Skip; continue scanning the rest of the datagram.
                offset += nla_align(nlmsg_len);
            }
            other => return Err(NexthopError::UnexpectedMessage(other)),
        }
    }
    Ok(None)
}

const fn nla_align(len: usize) -> usize {
    (len + 3) & !3
}

fn read_bytes<const N: usize>(buf: &[u8], offset: usize) -> Result<[u8; N], NexthopError> {
    let end = offset.checked_add(N).ok_or(NexthopError::Truncated)?;
    let slice = buf.get(offset..end).ok_or(NexthopError::Truncated)?;
    let mut out = [0u8; N];
    out.copy_from_slice(slice);
    Ok(out)
}

fn read_u16_ne(buf: &[u8], offset: usize) -> Result<u16, NexthopError> {
    Ok(u16::from_ne_bytes(read_bytes(buf, offset)?))
}

fn read_u32_ne(buf: &[u8], offset: usize) -> Result<u32, NexthopError> {
    Ok(u32::from_ne_bytes(read_bytes(buf, offset)?))
}

fn read_i32_ne(buf: &[u8], offset: usize) -> Result<i32, NexthopError> {
    Ok(i32::from_ne_bytes(read_bytes(buf, offset)?))
}

/// Per-datagram dump-pump state.
enum DumpProgress {
    /// Keep reading: this datagram had only `RTM_NEWNEXTHOP` rows and
    /// no terminator. Multipart dumps span many datagrams.
    Continue,
    /// Saw `NLMSG_DONE` — dump complete.
    Done,
    /// Kernel returned an error frame for our seq.
    KernelError(i32),
}

/// Size of the on-wire `nhmsg` struct (`u8` family + `u8` scope +
/// `u8` protocol + `u8` resvd + `u32` flags = 8 bytes natural).
const NHMSG_SIZE: usize = 8;

/// Which rustbgpd NHID ownership domain a dump should return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NexthopDumpClass {
    /// Existing ADR-0059 L2 FDB-NHG IDs.
    L2FdbNhg,
    /// LAN-75 L3VXLAN FDB-NHG IDs.
    L3FdbNhg,
}

impl NexthopDumpClass {
    fn accepts(self, id: u32) -> bool {
        match self {
            Self::L2FdbNhg => NhIdAllocator::is_ours(id),
            Self::L3FdbNhg => NhIdAllocator::is_l3_ours(id),
        }
    }
}

/// Walk `buf` as a sequence of netlink messages. For each
/// `RTM_NEWNEXTHOP` matching our `seq`, parse it through
/// [`parse_dump_message_for_class`] and append owned entries
/// (filtered by tag bits + `NHA_FDB`) to `out`. Returns the
/// per-datagram progress state.
fn drain_dump_datagram_for_class(
    buf: &[u8],
    seq: u32,
    class: NexthopDumpClass,
    out: &mut Vec<KernelNexthop>,
) -> Result<DumpProgress, NexthopError> {
    let mut offset = 0;
    while offset + NLMSGHDR_SIZE <= buf.len() {
        let hdr = &buf[offset..offset + NLMSGHDR_SIZE];
        let nlmsg_len = read_u32_ne(hdr, 0)? as usize;
        let nlmsg_type = read_u16_ne(hdr, 4)?;
        let nlmsg_seq = read_u32_ne(hdr, 8)?;

        if nlmsg_len < NLMSGHDR_SIZE || offset + nlmsg_len > buf.len() {
            return Err(NexthopError::Truncated);
        }

        // Multipart messages share our seq; non-matching seqs are
        // either someone else's traffic (impossible on our dedicated
        // socket but cheap to skip) or noise.
        if nlmsg_seq != seq {
            offset += nla_align(nlmsg_len);
            continue;
        }

        match nlmsg_type {
            NLMSG_DONE => return Ok(DumpProgress::Done),
            NLMSG_ERROR => {
                if nlmsg_len < NLMSGHDR_SIZE + 4 {
                    return Err(NexthopError::Truncated);
                }
                let raw = read_i32_ne(buf, offset + NLMSGHDR_SIZE)?;
                if raw == 0 {
                    // Kernel-side ACK with no data (shouldn't happen on
                    // a dump request) — treat as end-of-dump.
                    return Ok(DumpProgress::Done);
                }
                let positive = i32::try_from(raw.unsigned_abs()).unwrap_or(i32::MAX);
                return Ok(DumpProgress::KernelError(positive));
            }
            RTM_NEWNEXTHOP => {
                if let Some(entry) = parse_dump_message_for_class(
                    &buf[offset + NLMSGHDR_SIZE..offset + nlmsg_len],
                    class,
                )? {
                    out.push(entry);
                }
                offset += nla_align(nlmsg_len);
            }
            NLMSG_NOOP => {
                offset += nla_align(nlmsg_len);
            }
            other => return Err(NexthopError::UnexpectedMessage(other)),
        }
    }
    Ok(DumpProgress::Continue)
}

/// Parse one `RTM_NEWNEXTHOP` body (without the `nlmsghdr`). Returns
/// `Some` if the entry passes the rustbgpd-owned filter (tag bits +
/// `NHA_FDB`); `None` if it's a foreign nexthop or non-FDB entry we
/// should ignore on adoption.
///
/// Tolerates unknown attributes including `NHA_GROUP_TYPE` and
/// `NHA_OP_FLAGS` (research §1).
fn parse_dump_message_for_class(
    body: &[u8],
    class: NexthopDumpClass,
) -> Result<Option<KernelNexthop>, NexthopError> {
    if body.len() < NHMSG_SIZE {
        return Err(NexthopError::Truncated);
    }
    // Skip the nhmsg fixed header; we don't read its fields for dump.
    let mut attrs = &body[NHMSG_SIZE..];

    let mut id: Option<u32> = None;
    let mut is_fdb = false;
    let mut gateway: Option<IpAddr> = None;
    let mut member_ids: Option<Vec<u32>> = None;

    while attrs.len() >= 4 {
        let nla_len = read_u16_ne(attrs, 0)? as usize;
        let nla_type = read_u16_ne(attrs, 2)?;
        if nla_len < 4 || nla_len > attrs.len() {
            return Err(NexthopError::Truncated);
        }
        let payload = &attrs[4..nla_len];
        match nla_type {
            NHA_ID if payload.len() == 4 => {
                id = Some(read_u32_ne(payload, 0)?);
            }
            NHA_FDB => {
                is_fdb = true;
            }
            NHA_GATEWAY => match payload.len() {
                4 => {
                    let v4 = read_bytes(payload, 0)?;
                    gateway = Some(IpAddr::V4(v4.into()));
                }
                16 => {
                    let v6 = read_bytes(payload, 0)?;
                    gateway = Some(IpAddr::V6(v6.into()));
                }
                _ => {} // malformed; ignore
            },
            NHA_GROUP => {
                // Payload is an array of `nexthop_grp` (8 bytes each).
                let chunks = payload.chunks_exact(8);
                if !chunks.remainder().is_empty() {
                    return Err(NexthopError::Truncated);
                }
                let mut ids = Vec::with_capacity(payload.len() / 8);
                for chunk in chunks {
                    ids.push(read_u32_ne(chunk, 0)?);
                }
                member_ids = Some(ids);
            }
            // Tolerate NHA_GROUP_TYPE, NHA_OP_FLAGS, NHA_OIF, etc. —
            // we don't need them for adoption.
            _ => {}
        }
        // Advance past the aligned attribute.
        let advance = nla_align(nla_len);
        if advance > attrs.len() {
            break;
        }
        attrs = &attrs[advance..];
    }

    // Filter: must have an ID, must be rustbgpd-tagged in the
    // selected ownership domain, and must be FDB.
    let Some(nh_id) = id else { return Ok(None) };
    if !class.accepts(nh_id) || !is_fdb {
        return Ok(None);
    }

    let kind = if let Some(member_ids) = member_ids {
        KernelNexthopKind::Group { member_ids }
    } else if let Some(gateway) = gateway {
        KernelNexthopKind::Member { gateway }
    } else {
        // Tagged + FDB but neither group nor gateway — malformed;
        // skip rather than fail the whole dump.
        return Ok(None);
    };

    Ok(Some(KernelNexthop { id: nh_id, kind }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ack_bytes(seq: u32, errno: i32) -> Vec<u8> {
        // 16 nlmsghdr + 4 errno + 16 echoed original header = 36
        let mut buf = Vec::with_capacity(36);
        buf.extend_from_slice(&36u32.to_ne_bytes()); // len
        buf.extend_from_slice(&NLMSG_ERROR.to_ne_bytes()); // type
        buf.extend_from_slice(&0u16.to_ne_bytes()); // flags
        buf.extend_from_slice(&seq.to_ne_bytes()); // seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid
        buf.extend_from_slice(&errno.to_ne_bytes());
        buf.resize(36, 0);
        buf
    }

    #[test]
    fn parse_ack_zero_errno_is_ok() {
        let buf = ack_bytes(42, 0);
        let out = parse_response_for_seq(&buf, 42).unwrap().unwrap();
        assert!(matches!(out, AckOutcome::Ok));
    }

    #[test]
    fn parse_ack_negative_errno_is_positive_kernel_variant() {
        // Kernel sends -EEXIST = -17.
        let buf = ack_bytes(42, -17);
        let out = parse_response_for_seq(&buf, 42).unwrap().unwrap();
        match out {
            AckOutcome::Errno(e) => assert_eq!(e, 17),
            AckOutcome::Ok => panic!("expected Errno, got Ok"),
        }
    }

    #[test]
    fn parse_skips_mismatched_seq_returns_none() {
        let buf = ack_bytes(99, 0);
        assert!(parse_response_for_seq(&buf, 42).unwrap().is_none());
    }

    #[test]
    fn parse_truncated_datagram_errors() {
        // Claims len=36 but only provides 20.
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&36u32.to_ne_bytes());
        buf[4..6].copy_from_slice(&NLMSG_ERROR.to_ne_bytes());
        buf[8..12].copy_from_slice(&42u32.to_ne_bytes());
        assert!(matches!(
            parse_response_for_seq(&buf, 42),
            Err(NexthopError::Truncated)
        ));
    }

    #[test]
    fn parse_unexpected_type_errors() {
        // Type 999, our seq.
        let mut buf = vec![0u8; 36];
        buf[0..4].copy_from_slice(&36u32.to_ne_bytes());
        buf[4..6].copy_from_slice(&999u16.to_ne_bytes());
        buf[8..12].copy_from_slice(&42u32.to_ne_bytes());
        assert!(matches!(
            parse_response_for_seq(&buf, 42),
            Err(NexthopError::UnexpectedMessage(999))
        ));
    }

    #[test]
    fn native_read_helpers_report_truncated() {
        assert!(matches!(
            read_u32_ne(&[1, 2, 3], 0),
            Err(NexthopError::Truncated)
        ));
        assert!(matches!(
            read_u16_ne(&[1, 2], usize::MAX),
            Err(NexthopError::Truncated)
        ));
    }

    #[test]
    fn nexthop_group_member_rejects_zero() {
        assert!(matches!(
            NexthopGroupMember::new(0),
            Err(NexthopValidationError::ZeroId)
        ));
        assert!(matches!(
            NexthopGroupMember::with_weight(0, 10),
            Err(NexthopValidationError::ZeroId)
        ));
    }

    #[test]
    fn nexthop_group_member_accessors() {
        let m = NexthopGroupMember::with_weight(7, 42).unwrap();
        assert_eq!(m.id(), 7);
        assert_eq!(m.weight(), 42);
    }

    // -----------------------------------------------------------------
    // dump_owned multipart parser tests
    // -----------------------------------------------------------------

    use super::super::uapi::{NHA_GROUP_TYPE, NHA_OP_FLAGS};

    /// Build an `RTM_NEWNEXTHOP` body (nhmsg + attrs). The caller
    /// wraps it with `wrap_dump_msg` to produce a full netlink
    /// message including `nlmsghdr`.
    fn build_dump_body(attrs: &[(u16, Vec<u8>)]) -> Vec<u8> {
        let mut body = Vec::new();
        // nhmsg: 8 bytes zeroed.
        body.extend_from_slice(&[0u8; NHMSG_SIZE]);
        for (kind, payload) in attrs {
            let nla_len = 4 + payload.len();
            let nla_len_u16 = u16::try_from(nla_len).expect("test payload fits u16");
            body.extend_from_slice(&nla_len_u16.to_ne_bytes());
            body.extend_from_slice(&kind.to_ne_bytes());
            body.extend_from_slice(payload);
            // Pad to 4-byte alignment.
            let pad = nla_align(nla_len) - nla_len;
            body.resize(body.len() + pad, 0);
        }
        body
    }

    /// Wrap a body in an `RTM_NEWNEXTHOP` nlmsghdr with seq=42.
    fn wrap_dump_msg(body: &[u8]) -> Vec<u8> {
        let total = NLMSGHDR_SIZE + body.len();
        let mut buf = Vec::with_capacity(total);
        let total_u32 = u32::try_from(total).expect("test datagram fits u32");
        buf.extend_from_slice(&total_u32.to_ne_bytes());
        buf.extend_from_slice(&RTM_NEWNEXTHOP.to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes()); // flags
        buf.extend_from_slice(&42u32.to_ne_bytes()); // seq
        buf.extend_from_slice(&0u32.to_ne_bytes()); // pid
        buf.extend_from_slice(body);
        buf
    }

    /// Append an `NLMSG_DONE` terminator.
    fn nlmsg_done(seq: u32) -> Vec<u8> {
        let mut buf = Vec::with_capacity(NLMSGHDR_SIZE);
        let size_u32 = u32::try_from(NLMSGHDR_SIZE).expect("NLMSGHDR_SIZE fits u32");
        buf.extend_from_slice(&size_u32.to_ne_bytes());
        buf.extend_from_slice(&NLMSG_DONE.to_ne_bytes());
        buf.extend_from_slice(&0u16.to_ne_bytes());
        buf.extend_from_slice(&seq.to_ne_bytes());
        buf.extend_from_slice(&0u32.to_ne_bytes());
        buf
    }

    #[test]
    fn parse_member_dump_decodes_id_and_gateway() {
        let id = 0x3000_0001u32;
        let body = build_dump_body(&[
            (NHA_ID, id.to_ne_bytes().to_vec()),
            (NHA_GATEWAY, vec![10, 0, 0, 2]),
            (NHA_FDB, vec![]),
        ]);
        let entry = parse_dump_message_for_class(&body, NexthopDumpClass::L2FdbNhg)
            .unwrap()
            .expect("entry");
        assert_eq!(entry.id, id);
        match entry.kind {
            KernelNexthopKind::Member { gateway } => {
                assert_eq!(gateway, "10.0.0.2".parse::<IpAddr>().unwrap());
            }
            KernelNexthopKind::Group { .. } => panic!("expected Member, got Group"),
        }
    }

    #[test]
    fn parse_group_dump_decodes_member_ids() {
        let id = 0x4000_0001u32;
        // Two members: (id=12, weight=0, resvd1=0, resvd2=0), (id=13, …)
        let mut group_payload = Vec::new();
        for member_id in [12u32, 13u32] {
            group_payload.extend_from_slice(&member_id.to_ne_bytes());
            group_payload.extend_from_slice(&[0u8, 0, 0, 0]);
        }
        let body = build_dump_body(&[
            (NHA_ID, id.to_ne_bytes().to_vec()),
            (NHA_GROUP, group_payload),
            (NHA_FDB, vec![]),
        ]);
        let entry = parse_dump_message_for_class(&body, NexthopDumpClass::L2FdbNhg)
            .unwrap()
            .expect("entry");
        assert_eq!(entry.id, id);
        match entry.kind {
            KernelNexthopKind::Group { member_ids } => {
                assert_eq!(member_ids, vec![12, 13]);
            }
            KernelNexthopKind::Member { .. } => panic!("expected Group, got Member"),
        }
    }

    #[test]
    fn parse_dump_tolerates_unknown_attrs() {
        // Kernel often emits NHA_GROUP_TYPE + NHA_OP_FLAGS on dump
        // even when we didn't set them; parser must skip them.
        let id = 0x3000_0007u32;
        let body = build_dump_body(&[
            (NHA_ID, id.to_ne_bytes().to_vec()),
            (NHA_GROUP_TYPE, vec![0, 0]),
            (NHA_OP_FLAGS, vec![0, 0, 0, 0]),
            (NHA_GATEWAY, vec![10, 0, 0, 9]),
            (NHA_FDB, vec![]),
        ]);
        let entry = parse_dump_message_for_class(&body, NexthopDumpClass::L2FdbNhg)
            .unwrap()
            .expect("entry");
        assert!(matches!(entry.kind, KernelNexthopKind::Member { .. }));
    }

    #[test]
    fn parse_dump_errors_on_oversized_attr_len() {
        let mut body = Vec::new();
        body.extend_from_slice(&[0u8; NHMSG_SIZE]);
        body.extend_from_slice(&8u16.to_ne_bytes());
        body.extend_from_slice(&NHA_ID.to_ne_bytes());

        assert!(matches!(
            parse_dump_message_for_class(&body, NexthopDumpClass::L2FdbNhg),
            Err(NexthopError::Truncated)
        ));
    }

    #[test]
    fn parse_group_dump_rejects_trailing_partial_member() {
        let id = 0x4000_0001u32;
        let mut group_payload = Vec::new();
        group_payload.extend_from_slice(&12u32.to_ne_bytes());
        group_payload.extend_from_slice(&[0u8, 0, 0, 0]);
        group_payload.extend_from_slice(&13u32.to_ne_bytes());

        let body = build_dump_body(&[
            (NHA_ID, id.to_ne_bytes().to_vec()),
            (NHA_GROUP, group_payload),
            (NHA_FDB, vec![]),
        ]);
        assert!(matches!(
            parse_dump_message_for_class(&body, NexthopDumpClass::L2FdbNhg),
            Err(NexthopError::Truncated)
        ));
    }

    #[test]
    fn parse_dump_filters_by_tag_bits() {
        // FRR-tagged ID (0x1000_xxxx) — not ours.
        let body = build_dump_body(&[
            (NHA_ID, 0x1000_0001u32.to_ne_bytes().to_vec()),
            (NHA_GATEWAY, vec![10, 0, 0, 5]),
            (NHA_FDB, vec![]),
        ]);
        assert!(
            parse_dump_message_for_class(&body, NexthopDumpClass::L2FdbNhg)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn parse_l2_dump_ignores_l3_tags() {
        let body = build_dump_body(&[
            (NHA_ID, 0x5000_0001u32.to_ne_bytes().to_vec()),
            (NHA_GATEWAY, vec![10, 0, 0, 5]),
            (NHA_FDB, vec![]),
        ]);
        assert!(
            parse_dump_message_for_class(&body, NexthopDumpClass::L2FdbNhg)
                .unwrap()
                .is_none(),
            "legacy L2 dump must not adopt L3 member IDs"
        );

        let mut group_payload = Vec::new();
        group_payload.extend_from_slice(&0x5000_0001u32.to_ne_bytes());
        group_payload.extend_from_slice(&[0u8, 0, 0, 0]);
        let group_body = build_dump_body(&[
            (NHA_ID, 0x6000_0001u32.to_ne_bytes().to_vec()),
            (NHA_GROUP, group_payload),
            (NHA_FDB, vec![]),
        ]);
        assert!(
            parse_dump_message_for_class(&group_body, NexthopDumpClass::L2FdbNhg)
                .unwrap()
                .is_none(),
            "legacy L2 dump must not adopt L3 group IDs"
        );
    }

    #[test]
    fn parse_l3_dump_accepts_only_l3_tags() {
        let l3_member_body = build_dump_body(&[
            (NHA_ID, 0x5000_0001u32.to_ne_bytes().to_vec()),
            (NHA_GATEWAY, vec![10, 0, 0, 5]),
            (NHA_FDB, vec![]),
        ]);
        let entry = parse_dump_message_for_class(&l3_member_body, NexthopDumpClass::L3FdbNhg)
            .unwrap()
            .expect("l3 member");
        assert_eq!(entry.id, 0x5000_0001);
        assert!(matches!(entry.kind, KernelNexthopKind::Member { .. }));

        let l2_member_body = build_dump_body(&[
            (NHA_ID, 0x3000_0001u32.to_ne_bytes().to_vec()),
            (NHA_GATEWAY, vec![10, 0, 0, 2]),
            (NHA_FDB, vec![]),
        ]);
        assert!(
            parse_dump_message_for_class(&l2_member_body, NexthopDumpClass::L3FdbNhg)
                .unwrap()
                .is_none(),
            "L3 dump must not adopt L2 member IDs"
        );

        let mut group_payload = Vec::new();
        for member_id in [0x5000_0001u32, 0x5000_0002] {
            group_payload.extend_from_slice(&member_id.to_ne_bytes());
            group_payload.extend_from_slice(&[0u8, 0, 0, 0]);
        }
        let l3_group_body = build_dump_body(&[
            (NHA_ID, 0x6000_0001u32.to_ne_bytes().to_vec()),
            (NHA_GROUP, group_payload),
            (NHA_FDB, vec![]),
        ]);
        let group = parse_dump_message_for_class(&l3_group_body, NexthopDumpClass::L3FdbNhg)
            .unwrap()
            .expect("l3 group");
        match group.kind {
            KernelNexthopKind::Group { member_ids } => {
                assert_eq!(member_ids, vec![0x5000_0001, 0x5000_0002]);
            }
            KernelNexthopKind::Member { .. } => panic!("expected Group, got Member"),
        }
    }

    #[test]
    fn parse_dump_skips_non_fdb() {
        // Rustbgpd-tagged but no NHA_FDB attribute — L3 nexthop, not ours.
        let body = build_dump_body(&[
            (NHA_ID, 0x3000_0001u32.to_ne_bytes().to_vec()),
            (NHA_GATEWAY, vec![10, 0, 0, 2]),
        ]);
        assert!(
            parse_dump_message_for_class(&body, NexthopDumpClass::L2FdbNhg)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn drain_dump_datagram_terminates_on_nlmsg_done() {
        let id = 0x3000_0001u32;
        let entry_body = build_dump_body(&[
            (NHA_ID, id.to_ne_bytes().to_vec()),
            (NHA_GATEWAY, vec![10, 0, 0, 2]),
            (NHA_FDB, vec![]),
        ]);
        let mut buf = wrap_dump_msg(&entry_body);
        buf.extend_from_slice(&nlmsg_done(42));

        let mut out = Vec::new();
        let progress =
            drain_dump_datagram_for_class(&buf, 42, NexthopDumpClass::L2FdbNhg, &mut out).unwrap();
        assert!(matches!(progress, DumpProgress::Done));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, id);
    }

    #[test]
    fn drain_dump_datagram_continues_without_terminator() {
        let entry_body = build_dump_body(&[
            (NHA_ID, 0x3000_0002u32.to_ne_bytes().to_vec()),
            (NHA_GATEWAY, vec![10, 0, 0, 3]),
            (NHA_FDB, vec![]),
        ]);
        let buf = wrap_dump_msg(&entry_body);
        let mut out = Vec::new();
        let progress =
            drain_dump_datagram_for_class(&buf, 42, NexthopDumpClass::L2FdbNhg, &mut out).unwrap();
        assert!(matches!(progress, DumpProgress::Continue));
        assert_eq!(out.len(), 1);
    }
}
