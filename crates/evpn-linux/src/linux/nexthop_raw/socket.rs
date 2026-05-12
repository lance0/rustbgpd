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
//! ## IPv4 only (slice 2)
//!
//! `add_fdb_member` rejects [`IpAddr::V6`] with
//! [`NexthopError::Ipv6Unsupported`]. The kernel accepts v6 next-hops
//! for FDB nexthops, but we haven't captured a v6 fixture and haven't
//! round-tripped it on a real kernel; deferring to a follow-up keeps
//! the slice tight.

use std::io;
use std::net::IpAddr;

use netlink_sys::{AsyncSocket, AsyncSocketExt, SocketAddr, TokioSocket, protocols::NETLINK_ROUTE};
use thiserror::Error;
use tracing::debug;

use super::encode::{encode_add_fdb_group, encode_add_fdb_member, encode_del};
use super::uapi::NexthopGrp;

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
    /// Slice 2 does not support IPv6 gateways yet.
    #[error("IPv6 gateways are not supported in this slice; capture a v6 fixture first")]
    Ipv6Unsupported,
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
    /// non-zero and the gateway must be IPv4 (slice 2 limitation).
    ///
    /// # Errors
    ///
    /// - [`NexthopError::Validation`] with `ZeroId` if `id == 0`.
    /// - [`NexthopError::Ipv6Unsupported`] if `gateway` is IPv6.
    /// - [`NexthopError::Io`] on socket failure.
    /// - [`NexthopError::Kernel`] on kernel-side errno ≠ 0
    ///   (`EEXIST` is treated as idempotent ACK).
    pub async fn add_fdb_member(&mut self, id: u32, gateway: IpAddr) -> Result<(), NexthopError> {
        if id == 0 {
            return Err(NexthopValidationError::ZeroId.into());
        }
        match gateway {
            IpAddr::V4(_) => {}
            IpAddr::V6(_) => return Err(NexthopError::Ipv6Unsupported),
        }
        let seq = self.next_seq();
        let bytes = encode_add_fdb_member(seq, id, gateway);
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
        let bytes = encode_add_fdb_group(seq, id, &wire);
        self.exchange(seq, &bytes, /* idempotent_eexist */ true)
            .await
    }

    /// Remove the nexthop named by `id`. Returns Ok if the entry
    /// didn't exist (`ENOENT` is treated as idempotent ACK per
    /// ADR-0059 §5 invariant 8).
    ///
    /// # Errors
    ///
    /// - [`NexthopError::Validation`] with `ZeroId` if `id == 0`.
    /// - [`NexthopError::Io`] on socket failure.
    /// - [`NexthopError::Kernel`] on kernel-side errno ≠ 0 other
    ///   than `ENOENT` (which is treated as idempotent ACK).
    pub async fn del(&mut self, id: u32) -> Result<(), NexthopError> {
        if id == 0 {
            return Err(NexthopValidationError::ZeroId.into());
        }
        let seq = self.next_seq();
        let bytes = encode_del(seq, id);
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
        let nlmsg_len = u32::from_ne_bytes(header_slice[0..4].try_into().unwrap()) as usize;
        let nlmsg_type = u16::from_ne_bytes(header_slice[4..6].try_into().unwrap());
        let nlmsg_seq = u32::from_ne_bytes(header_slice[8..12].try_into().unwrap());

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
                let errno_bytes: [u8; 4] = buf[offset + NLMSGHDR_SIZE..offset + NLMSGHDR_SIZE + 4]
                    .try_into()
                    .unwrap();
                let raw = i32::from_ne_bytes(errno_bytes);
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
}
