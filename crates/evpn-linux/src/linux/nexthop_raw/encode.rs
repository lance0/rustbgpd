//! Netlink message encoders for `RTM_NEWNEXTHOP` / `RTM_DELNEXTHOP`
//! with `NHA_FDB`, implementing the wire shape pinned in ADR-0059 §4.
//!
//! Three pure functions producing raw `Vec<u8>` ready for
//! `sendmsg` over a `NETLINK_ROUTE` socket. No I/O, no async.
//! Slice 3's reconcile actor calls these through the higher-level
//! [`super::NexthopSocket`] wrapper.
//!
//! ## Wire shape
//!
//! Every emitted message is:
//!
//! ```text
//! nlmsghdr (16 bytes)  + nhmsg (8 bytes) + attributes (variable)
//! ```
//!
//! Multi-byte fields in the netlink header and `nhmsg` are
//! **native-endian** (netlink is host byte order). The `NHA_GATEWAY`
//! attribute payload, by contrast, is **network byte order** — that's
//! the IP address as it appears on the wire, not as a `u32` host value.
//!
//! ## Reference: iproute2 strace decode
//!
//! The expected-bytes constants in the test module below were derived
//! from real `ip nexthop add` / `ip nexthop del` invocations captured
//! via strace on iproute2 6.1.0 / kernel 6.17. See
//! `captures/README.md` for the full decode.
//!
//! Our encoder emits `NLM_F_CREATE | NLM_F_REPLACE` (idempotent
//! reconcile semantics — ADR-0059 §5 invariant 3 requires REPLACE for
//! atomic alias-set update) whereas iproute2's `ip nexthop add` emits
//! `NLM_F_EXCL | NLM_F_CREATE` (one-shot CLI semantics, fail-if-exists).
//! All other fields (attribute order, attribute lengths, `nh_family`,
//! struct sizes) match iproute2 byte-for-byte.

use std::net::IpAddr;

use super::uapi::{
    NHA_FDB, NHA_GATEWAY, NHA_GROUP, NHA_ID, NexthopGrp, Nhmsg, RTM_DELNEXTHOP, RTM_GETNEXTHOP,
    RTM_NEWNEXTHOP,
};

// ---------------------------------------------------------------------
// netlink/rtnetlink primitives — not exposed beyond this module.
// ---------------------------------------------------------------------

/// `NLM_F_REQUEST` — every userspace-to-kernel message sets this.
const NLM_F_REQUEST: u16 = 0x01;
/// `NLM_F_DUMP` — request a multipart dump response.
const NLM_F_DUMP: u16 = 0x300; // ROOT | MATCH
/// `NLM_F_ACK` — request an ACK / NACK reply.
const NLM_F_ACK: u16 = 0x04;
/// `NLM_F_REPLACE` — replace any existing entry (idempotent).
const NLM_F_REPLACE: u16 = 0x100;
/// `NLM_F_CREATE` — create if missing.
const NLM_F_CREATE: u16 = 0x400;

/// `AF_INET` — IPv4 family marker for the `nhmsg.nh_family` byte.
const AF_INET: u8 = 2;

/// `AF_INET6` — IPv6 family marker for the `nhmsg.nh_family` byte.
const AF_INET6: u8 = 10;

/// `AF_UNSPEC` — used by groups and deletes.
const AF_UNSPEC: u8 = 0;

/// Pad `len` up to the next multiple of 4 (netlink's attribute
/// alignment).
const fn nla_align(len: usize) -> usize {
    (len + 3) & !3
}

/// Push an `nlattr { len, kind }` + payload + 4-byte alignment pad.
fn push_attr(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let total_len = 4 + payload.len();
    let len_u16: u16 = total_len
        .try_into()
        .expect("netlink attribute length exceeds u16");
    out.extend_from_slice(&len_u16.to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    // Pad to 4-byte alignment.
    let padded = nla_align(total_len);
    out.resize(out.len() + (padded - total_len), 0);
}

/// Emit the `Nhmsg` struct as 8 bytes, native-endian.
fn push_nhmsg(out: &mut Vec<u8>, msg: Nhmsg) {
    out.push(msg.nh_family);
    out.push(msg.nh_scope);
    out.push(msg.nh_protocol);
    out.push(msg.resvd);
    out.extend_from_slice(&msg.nh_flags.to_ne_bytes());
}

/// Build the `nlmsghdr` (16 bytes) given the body length. Returns
/// the prepended header bytes.
fn build_nlmsghdr(body_len: usize, msg_type: u16, flags: u16, seq: u32) -> [u8; 16] {
    let total_len: u32 = (16 + body_len)
        .try_into()
        .expect("netlink message length exceeds u32");
    let mut hdr = [0u8; 16];
    hdr[0..4].copy_from_slice(&total_len.to_ne_bytes());
    hdr[4..6].copy_from_slice(&msg_type.to_ne_bytes());
    hdr[6..8].copy_from_slice(&flags.to_ne_bytes());
    hdr[8..12].copy_from_slice(&seq.to_ne_bytes());
    // nlmsg_pid = 0 ("kernel fills in" semantics on the way out).
    hdr
}

// ---------------------------------------------------------------------
// Public-to-the-module encoder API.
// ---------------------------------------------------------------------

/// Encode `RTM_NEWNEXTHOP` for one per-VTEP FDB nexthop pointing
/// at `gateway`. The on-wire attribute order is `NHA_ID`,
/// `NHA_GATEWAY`, `NHA_FDB` — matches iproute2's `ip nexthop add`.
///
/// IPv4 gateways encode `nh_family = AF_INET` with a 4-byte
/// `NHA_GATEWAY` payload; IPv6 gateways encode `nh_family = AF_INET6`
/// with a 16-byte payload (ADR-0059 slice 3.5 PR 3). Caller is
/// responsible for `id != 0`.
pub(crate) fn encode_add_fdb_member(seq: u32, id: u32, gateway: IpAddr) -> Vec<u8> {
    // Initial capacity sized to the v6 worst case (16 + 8 + 8 +
    // 20 + 4 = 56 bytes); v4 path reuses the same buffer at 44.
    let mut body = Vec::with_capacity(8 + 8 + 20 + 4);

    // nhmsg: family follows the gateway form (iproute2 convention).
    // The on-wire payload is the gateway as it appears on the network
    // — `octets()` returns big-endian bytes for both v4 and v6.
    let (family, gateway_bytes): (u8, Vec<u8>) = match gateway {
        IpAddr::V4(v4) => (AF_INET, v4.octets().to_vec()),
        IpAddr::V6(v6) => (AF_INET6, v6.octets().to_vec()),
    };
    push_nhmsg(
        &mut body,
        Nhmsg {
            nh_family: family,
            nh_scope: 0,
            nh_protocol: 0,
            resvd: 0,
            nh_flags: 0,
        },
    );

    // Attributes in iproute2 order: NHA_ID, NHA_GATEWAY, NHA_FDB.
    push_attr(&mut body, NHA_ID, &id.to_ne_bytes());
    push_attr(&mut body, NHA_GATEWAY, &gateway_bytes);
    push_attr(&mut body, NHA_FDB, &[]); // zero-length flag.

    let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    let hdr = build_nlmsghdr(body.len(), RTM_NEWNEXTHOP, flags, seq);

    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&body);
    out
}

/// Encode `RTM_NEWNEXTHOP` for a group naming the `members` by
/// nexthop ID. The members carry weight 0 (= weight 1 per kernel
/// semantics) and zero reserved fields; group type defaults to
/// MPATH (kernel default — we omit `NHA_GROUP_TYPE`).
pub(crate) fn encode_add_fdb_group(seq: u32, id: u32, members: &[NexthopGrp]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + 8 + (4 + 8 * members.len()) + 4);

    // nhmsg: AF_UNSPEC for groups (no per-message gateway).
    push_nhmsg(
        &mut body,
        Nhmsg {
            nh_family: AF_UNSPEC,
            nh_scope: 0,
            nh_protocol: 0,
            resvd: 0,
            nh_flags: 0,
        },
    );

    push_attr(&mut body, NHA_ID, &id.to_ne_bytes());

    // NHA_GROUP payload = concatenated NexthopGrp entries, each 8 bytes.
    let mut group_payload = Vec::with_capacity(8 * members.len());
    for m in members {
        group_payload.extend_from_slice(&m.id.to_ne_bytes());
        group_payload.push(m.weight);
        group_payload.push(m.resvd1);
        group_payload.extend_from_slice(&m.resvd2.to_ne_bytes());
    }
    push_attr(&mut body, NHA_GROUP, &group_payload);

    push_attr(&mut body, NHA_FDB, &[]);

    let flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    let hdr = build_nlmsghdr(body.len(), RTM_NEWNEXTHOP, flags, seq);

    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&body);
    out
}

/// Encode `RTM_DELNEXTHOP` for the nexthop named by `id`. Body is
/// just `nhmsg(AF_UNSPEC) + NHA_ID(id)`.
pub(crate) fn encode_del(seq: u32, id: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + 8);

    push_nhmsg(
        &mut body,
        Nhmsg {
            nh_family: AF_UNSPEC,
            nh_scope: 0,
            nh_protocol: 0,
            resvd: 0,
            nh_flags: 0,
        },
    );

    push_attr(&mut body, NHA_ID, &id.to_ne_bytes());

    let flags = NLM_F_REQUEST | NLM_F_ACK;
    let hdr = build_nlmsghdr(body.len(), RTM_DELNEXTHOP, flags, seq);

    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&body);
    out
}

/// Encode an `RTM_GETNEXTHOP` dump request — empty filter, kernel
/// returns every nexthop. Slice 3b's startup-adoption pass filters
/// the response client-side by tag bits (`is_ours`) since the kernel
/// doesn't expose a tag-bit filter attribute.
pub(crate) fn encode_dump(seq: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);

    push_nhmsg(
        &mut body,
        Nhmsg {
            nh_family: AF_UNSPEC,
            nh_scope: 0,
            nh_protocol: 0,
            resvd: 0,
            nh_flags: 0,
        },
    );

    let flags = NLM_F_REQUEST | NLM_F_DUMP;
    let hdr = build_nlmsghdr(body.len(), RTM_GETNEXTHOP, flags, seq);

    let mut out = Vec::with_capacity(16 + body.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&body);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Zero out `nlmsg_seq` (offset 8..12) so byte-fixture compares
    /// don't depend on the caller-supplied sequence number.
    fn normalize_seq(bytes: &mut [u8]) {
        assert!(bytes.len() >= 16, "less than an nlmsghdr");
        bytes[8..12].fill(0);
    }

    /// Confirm `nlmsg_pid` (offset 12..16) is zero — the kernel
    /// fills it in on the way back. A non-zero value means we
    /// fed the test a reply by mistake.
    fn assert_outbound_pid_zero(bytes: &[u8]) {
        assert!(bytes.len() >= 16, "less than an nlmsghdr");
        assert_eq!(
            &bytes[12..16],
            &[0u8; 4],
            "outbound nlmsg_pid must be 0 ('kernel fills in')",
        );
    }

    // -----------------------------------------------------------------
    // Expected-bytes constants derived from the strace captures in
    // `captures/*.log`. Layout reasoning is documented inline so a
    // future reader can audit each byte against the UAPI spec.
    //
    // All constants use the iproute2 attribute order
    // (NHA_ID, NHA_GATEWAY?, NHA_FDB) and the iproute2 nh_family
    // policy (AF_INET for v4 per-VTEP, AF_UNSPEC for groups/deletes)
    // but with our encoder's NLM_F_CREATE|NLM_F_REPLACE flags rather
    // than iproute2's NLM_F_EXCL|NLM_F_CREATE.
    //
    // `nlmsg_seq` is zeroed for byte-comparison (see normalize_seq).
    // -----------------------------------------------------------------

    /// Expected bytes for `encode_add_fdb_member(seq=0, id=12, 10.0.0.2)`.
    ///
    /// Total 44 bytes = 16 `nlmsghdr` + 8 `nhmsg` + 8 `NHA_ID` + 8 `NHA_GATEWAY` + 4 `NHA_FDB`.
    const ADD_FDB_MEMBER_ID12_TO_10_0_0_2: &[u8] = &[
        // nlmsghdr (16 bytes)
        0x2C, 0x00, 0x00, 0x00, // nlmsg_len  = 44
        0x68, 0x00, // nlmsg_type = RTM_NEWNEXTHOP (104 = 0x68)
        0x05,
        0x05, // nlmsg_flags = REQUEST(1) | ACK(4) | CREATE(0x400) | REPLACE(0x100) = 0x505
        0x00, 0x00, 0x00, 0x00, // nlmsg_seq  = 0 (normalized)
        0x00, 0x00, 0x00, 0x00, // nlmsg_pid  = 0
        // nhmsg (8 bytes)
        0x02, // nh_family = AF_INET
        0x00, // nh_scope = RT_SCOPE_UNIVERSE
        0x00, // nh_protocol = RTPROT_UNSPEC
        0x00, // resvd
        0x00, 0x00, 0x00, 0x00, // nh_flags = 0
        // NHA_ID (8 bytes: 4 header + 4 payload)
        0x08, 0x00, // nla_len = 8
        0x01, 0x00, // nla_type = NHA_ID
        0x0C, 0x00, 0x00, 0x00, // id = 12
        // NHA_GATEWAY (8 bytes: 4 header + 4 IPv4 payload)
        0x08, 0x00, // nla_len = 8
        0x06, 0x00, // nla_type = NHA_GATEWAY
        0x0A, 0x00, 0x00, 0x02, // 10.0.0.2 in network byte order
        // NHA_FDB (4 bytes: 4 header + 0 payload)
        0x04, 0x00, // nla_len = 4
        0x0B, 0x00, // nla_type = NHA_FDB
    ];

    /// Expected bytes for `encode_add_fdb_member(seq=0, id=13, 10.0.0.3)`.
    /// Identical shape to `ADD_FDB_MEMBER_ID12_TO_10_0_0_2` with id and
    /// gateway bytes substituted.
    const ADD_FDB_MEMBER_ID13_TO_10_0_0_3: &[u8] = &[
        0x2C, 0x00, 0x00, 0x00, // nlmsg_len = 44
        0x68, 0x00, // RTM_NEWNEXTHOP
        0x05, 0x05, // flags
        0x00, 0x00, 0x00, 0x00, // seq
        0x00, 0x00, 0x00, 0x00, // pid
        0x02, 0x00, 0x00, 0x00, // nhmsg: AF_INET
        0x00, 0x00, 0x00, 0x00, // nh_flags
        0x08, 0x00, 0x01, 0x00, // NHA_ID header
        0x0D, 0x00, 0x00, 0x00, // id = 13
        0x08, 0x00, 0x06, 0x00, // NHA_GATEWAY header
        0x0A, 0x00, 0x00, 0x03, // 10.0.0.3
        0x04, 0x00, 0x0B, 0x00, // NHA_FDB
    ];

    /// Expected bytes for `encode_add_fdb_group(seq=0, id=200, [12,13])`.
    /// Total 56 bytes = 16 `nlmsghdr` + 8 `nhmsg` + 8 `NHA_ID` + 20 `NHA_GROUP` + 4 `NHA_FDB`.
    const ADD_FDB_GROUP_ID200_MEMBERS_12_13: &[u8] = &[
        0x38, 0x00, 0x00, 0x00, // nlmsg_len = 56
        0x68, 0x00, // RTM_NEWNEXTHOP
        0x05, 0x05, // flags
        0x00, 0x00, 0x00, 0x00, // seq
        0x00, 0x00, 0x00, 0x00, // pid
        0x00, 0x00, 0x00, 0x00, // nhmsg: AF_UNSPEC (groups)
        0x00, 0x00, 0x00, 0x00, // nh_flags
        // NHA_ID
        0x08, 0x00, 0x01, 0x00, // header
        0xC8, 0x00, 0x00, 0x00, // id = 200
        // NHA_GROUP (20 bytes: 4 header + 2 * 8-byte NexthopGrp)
        0x14, 0x00, // nla_len = 20
        0x02, 0x00, // nla_type = NHA_GROUP
        // NexthopGrp[0]: id=12
        0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // NexthopGrp[1]: id=13
        0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // NHA_FDB
        0x04, 0x00, 0x0B, 0x00,
    ];

    /// Expected bytes for `encode_del(seq=0, id=200)`.
    /// Total 32 bytes = 16 `nlmsghdr` + 8 `nhmsg` + 8 `NHA_ID`.
    const DEL_ID200: &[u8] = &[
        0x20, 0x00, 0x00, 0x00, // nlmsg_len = 32
        0x69, 0x00, // RTM_DELNEXTHOP (105 = 0x69)
        0x05, 0x00, // flags = REQUEST(1) | ACK(4) = 0x05 (no CREATE/REPLACE on del)
        0x00, 0x00, 0x00, 0x00, // seq
        0x00, 0x00, 0x00, 0x00, // pid
        0x00, 0x00, 0x00, 0x00, // nhmsg: AF_UNSPEC
        0x00, 0x00, 0x00, 0x00, // nh_flags
        0x08, 0x00, 0x01, 0x00, // NHA_ID header
        0xC8, 0x00, 0x00, 0x00, // id = 200
    ];

    #[test]
    fn add_fdb_member_v4_matches_expected_bytes_id12() {
        let mut bytes = encode_add_fdb_member(42, 12, "10.0.0.2".parse().unwrap());
        assert_outbound_pid_zero(&bytes);
        normalize_seq(&mut bytes);
        assert_eq!(bytes, ADD_FDB_MEMBER_ID12_TO_10_0_0_2);
    }

    #[test]
    fn add_fdb_member_v4_matches_expected_bytes_id13() {
        let mut bytes = encode_add_fdb_member(42, 13, "10.0.0.3".parse().unwrap());
        assert_outbound_pid_zero(&bytes);
        normalize_seq(&mut bytes);
        assert_eq!(bytes, ADD_FDB_MEMBER_ID13_TO_10_0_0_3);
    }

    #[test]
    fn add_fdb_group_matches_expected_bytes() {
        let members = [
            NexthopGrp {
                id: 12,
                weight: 0,
                resvd1: 0,
                resvd2: 0,
            },
            NexthopGrp {
                id: 13,
                weight: 0,
                resvd1: 0,
                resvd2: 0,
            },
        ];
        let mut bytes = encode_add_fdb_group(42, 200, &members);
        assert_outbound_pid_zero(&bytes);
        normalize_seq(&mut bytes);
        assert_eq!(bytes, ADD_FDB_GROUP_ID200_MEMBERS_12_13);
    }

    #[test]
    fn del_matches_expected_bytes() {
        let mut bytes = encode_del(42, 200);
        assert_outbound_pid_zero(&bytes);
        normalize_seq(&mut bytes);
        assert_eq!(bytes, DEL_ID200);
    }

    #[test]
    fn seq_field_propagates_to_header() {
        // Encoder writes the caller-supplied seq into bytes[8..12].
        let bytes = encode_add_fdb_member(0xDEAD_BEEF, 12, "10.0.0.2".parse().unwrap());
        assert_eq!(&bytes[8..12], &0xDEAD_BEEFu32.to_ne_bytes());
    }

    #[test]
    fn empty_group_still_encodes_but_kernel_will_reject() {
        // The encoder doesn't enforce non-empty (NexthopSocket
        // does, before calling). This test pins the encoder's
        // mechanical behaviour: it produces a valid-shaped message
        // with a zero-payload NHA_GROUP.
        let bytes = encode_add_fdb_group(0, 99, &[]);
        // 16 nlmsghdr + 8 nhmsg + 8 NHA_ID + 4 empty-NHA_GROUP + 4 NHA_FDB = 40
        assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), 40);
    }
}
