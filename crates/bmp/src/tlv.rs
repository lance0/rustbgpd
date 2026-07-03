//! BMP version 4 TLV code points and encode helpers
//! (draft-ietf-grow-bmp-tlv-20).
//!
//! **Pre-IANA caveat:** every code point in this module comes from the
//! IANA Considerations of draft-ietf-grow-bmp-tlv-20 (§9) and may be
//! renumbered when the draft is published as an RFC. Keep all
//! draft-tlv code points in this one module so a renumber is a
//! single-file change.
//!
//! Encode-only, like the rest of this crate: BMP is unidirectional
//! (router → collector) and the daemon never parses BMP.

use bytes::{BufMut, BytesMut};

// ── "BMP Route Monitoring TLVs" registry (§9) ──────────────────────
// TLVs in Route Monitoring messages are always *indexed* (§4.3).

/// Sequence Number TLV (§5.6.2).
pub const RM_TLV_SEQUENCE_NUMBER: u16 = 1;
/// Extended Flags TLV (§5.6.3).
pub const RM_TLV_EXTENDED_FLAGS: u16 = 2;
/// Timestamp TLV (§5.6.1).
pub const RM_TLV_TIMESTAMP: u16 = 3;
/// Group TLV (§5.2.1): binds a Group Index (G-bit set) to a list of
/// NLRI indexes.
pub const RM_TLV_GROUP: u16 = 4;
/// VRF/Table Name TLV (§5.2.2).
pub const RM_TLV_VRF_TABLE_NAME: u16 = 5;
/// Stateless Parsing TLV (§5.2.3): one BGP capability per TLV, encoded
/// exactly as in the BGP OPEN.
pub const RM_TLV_STATELESS_PARSING: u16 = 6;
/// BGP Message TLV (§5.2): carries the BGP UPDATE PDU. Mandatory in
/// every v4 Route Monitoring message, index 0.
pub const RM_TLV_BGP_MESSAGE: u16 = 7;

/// Path Marking TLV (draft-ietf-grow-bmp-path-marking-tlv-05 §2, §7):
/// 4-octet Path Status bitmap + optional 2-octet Reason Code.
///
/// **Known type-code collision, renumber expected:** path-marking-05
/// self-assigns type 5 against an old revision of the base TLV draft
/// whose RM registry only held values 1-4 (its §7 says "populated with
/// initial values 1-4. This document adds value 5"), but
/// draft-ietf-grow-bmp-tlv-20 §9 has since taken 5 for the VRF/Table
/// Name TLV ([`RM_TLV_VRF_TABLE_NAME`]) and grown to 7. We follow the
/// latest path-marking revision verbatim; expect IANA to renumber this
/// (likely to 8+) at RFC publication. We never emit the VRF/Table Name
/// RM TLV, so our own v4 output stays unambiguous.
pub const RM_TLV_PATH_MARKING: u16 = 5;

// ── Path Status bits (path-marking-05 §3.1, Table 1) ───────────────
// Only the bits rustbgpd can derive honestly are defined here. The
// remaining registered bits (Invalid 0x01, Nonselected 0x04, Primary
// 0x08, Backup 0x10, Non-installed 0x20, Best-external 0x40, Add-Path
// 0x80, Filtered-in 0x100, Filtered-out 0x200, Suppressed 0x800) are
// FIB/damping/filter concepts a route reflector without a forwarding
// plane cannot attest to — left unset rather than fabricated.

/// Best (§3.1): the RFC 4271 §9.1 decision-process winner. Every
/// Loc-RIB route is Best by definition.
pub const PATH_STATUS_BEST: u32 = 0x0000_0002;
/// Stale (§3.1): declared stale by BGP Graceful Restart (RFC 4724
/// §4.1). We also set it for RFC 9494 LLGR-stale — a strict subset of
/// GR-stale semantics.
pub const PATH_STATUS_STALE: u32 = 0x0000_0400;

// ── Reason Codes (path-marking-05 §3.2, Table 2) ───────────────────
// 2-octet optional codes naming the decisive decision-process step.
// 0x0001/0x0002 (Invalid due to AS loop / unresolvable nexthop) and
// 0x000B (AIGP) are never emitted — we don't mark Invalid, and the
// selection ladder has no AIGP step.

/// Not preferred for local preference (§3.2).
pub const REASON_LOCAL_PREF: u16 = 0x0003;
/// Not preferred for AS Path Length (§3.2).
pub const REASON_AS_PATH_LEN: u16 = 0x0004;
/// Not preferred for origin (§3.2).
pub const REASON_ORIGIN: u16 = 0x0005;
/// Not preferred for MED (§3.2).
pub const REASON_MED: u16 = 0x0006;
/// Not preferred for peer type (eBGP over iBGP, §3.2).
pub const REASON_PEER_TYPE: u16 = 0x0007;
/// Not preferred for IGP cost (§3.2).
pub const REASON_IGP_COST: u16 = 0x0008;
/// Not preferred for router ID (§3.2; RFC 4456 substitutes
/// `ORIGINATOR_ID` for the BGP identifier on reflected routes).
pub const REASON_ROUTER_ID: u16 = 0x0009;
/// Not preferred for peer address (§3.2).
pub const REASON_PEER_ADDRESS: u16 = 0x000A;

// ── "BMP Stats Reports TLVs" registry (§9) ─────────────────────────
// Stats Reports TLVs are *not* indexed — indexed TLVs apply only to
// Route Monitoring (§4.3).

/// Stats TLV (§5.4): mandatory container enclosing the RFC 7854 Stats
/// Count and stats data in a v4 Stats Report.
pub const STATS_TLV_STATS: u16 = 1;

// ── Index field (§4.3) ─────────────────────────────────────────────

/// G-bit: top-most bit of the 2-byte index flags a Group Index
/// (§4.3, §5.2.1).
pub const INDEX_G_BIT: u16 = 0x8000;
/// Index 0: the TLV applies to all NLRIs in the BGP UPDATE (§4.3).
pub const INDEX_ALL_NLRI: u16 = 0;

/// TLV length field: value length only. Indexed TLVs exclude the
/// 2-byte index from the reported length (§4.3). BGP framing bounds
/// PDUs at 65535 (RFC 8654), so a v4 TLV value always fits.
fn tlv_len(value: &[u8]) -> u16 {
    debug_assert!(u16::try_from(value.len()).is_ok(), "TLV value overflow");
    u16::try_from(value.len()).unwrap_or(u16::MAX)
}

/// Append an IANA-registered indexed TLV (§4.3, Figure 4):
/// type(2, E=0) + length(2, value only) + index(2, G-bit included in
/// `index`) + value. Used for Route Monitoring message TLVs.
pub fn put_indexed_tlv(buf: &mut BytesMut, tlv_type: u16, index: u16, value: &[u8]) {
    buf.put_u16(tlv_type);
    buf.put_u16(tlv_len(value));
    buf.put_u16(index);
    buf.put_slice(value);
}

/// Append an IANA-registered non-indexed TLV (§4.1, Figure 1):
/// type(2, E=0) + length(2) + value. Used for Stats Reports TLVs.
pub fn put_tlv(buf: &mut BytesMut, tlv_type: u16, value: &[u8]) {
    buf.put_u16(tlv_type);
    buf.put_u16(tlv_len(value));
    buf.put_slice(value);
}

/// Append a Path Marking TLV (path-marking-05 §2): 4-octet Path
/// Status bitmap, then the optional 2-octet Reason Code only when one
/// applies. Indexed like every RM TLV (tlv-20 §4.3); callers pass
/// [`INDEX_ALL_NLRI`] when the enclosed UPDATE carries a single NLRI.
pub fn put_path_marking_tlv(buf: &mut BytesMut, index: u16, status: u32, reason: Option<u16>) {
    let mut value = [0u8; 6];
    value[..4].copy_from_slice(&status.to_be_bytes());
    let len = match reason {
        Some(code) => {
            value[4..6].copy_from_slice(&code.to_be_bytes());
            6
        }
        None => 4,
    };
    put_indexed_tlv(buf, RM_TLV_PATH_MARKING, index, &value[..len]);
}

/// Append a Group TLV (§5.2.1): type 4, index = `group_index` with the
/// G-bit forced on, value = the 2-byte NLRI indexes (1-based, §4.3).
pub fn put_group_tlv(buf: &mut BytesMut, group_index: u16, nlri_indexes: &[u16]) {
    debug_assert!(nlri_indexes.len() >= 2, "Group TLV needs 2+ NLRI indexes");
    let mut value = Vec::with_capacity(nlri_indexes.len() * 2);
    for idx in nlri_indexes {
        debug_assert!(
            *idx != 0 && *idx & INDEX_G_BIT == 0,
            "Group TLV must reference plain non-zero NLRI indexes"
        );
        value.extend_from_slice(&idx.to_be_bytes());
    }
    put_indexed_tlv(buf, RM_TLV_GROUP, INDEX_G_BIT | group_index, &value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_tlv_shape_length_excludes_index() {
        let mut buf = BytesMut::new();
        put_indexed_tlv(&mut buf, RM_TLV_BGP_MESSAGE, INDEX_ALL_NLRI, &[0xAA, 0xBB]);
        // type=7, length=2 (value only, §4.3), index=0, value.
        assert_eq!(&buf[..], &[0x00, 0x07, 0x00, 0x02, 0x00, 0x00, 0xAA, 0xBB]);
    }

    #[test]
    fn plain_tlv_shape() {
        let mut buf = BytesMut::new();
        put_tlv(&mut buf, STATS_TLV_STATS, &[0x01, 0x02, 0x03]);
        assert_eq!(&buf[..], &[0x00, 0x01, 0x00, 0x03, 0x01, 0x02, 0x03]);
    }

    #[test]
    fn group_tlv_sets_g_bit_and_packs_nlri_indexes() {
        let mut buf = BytesMut::new();
        put_group_tlv(&mut buf, 0x000B, &[1, 2, 3, 10]);
        assert_eq!(
            &buf[..],
            &[
                0x00, 0x04, // type 4 (Group TLV, §5.2.1)
                0x00, 0x08, // length: 4 × 2-byte NLRI indexes
                0x80, 0x0B, // G-bit | group index 0x000B
                0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0A,
            ]
        );
    }

    /// path-marking-05 §2 golden shape: type 5, 4-byte status bitmap,
    /// reason code present only when supplied (it is optional), length
    /// excluding the 2-byte index per tlv-20 §4.3.
    #[test]
    fn path_marking_tlv_with_and_without_reason() {
        let mut buf = BytesMut::new();
        put_path_marking_tlv(
            &mut buf,
            INDEX_ALL_NLRI,
            PATH_STATUS_BEST | PATH_STATUS_STALE,
            Some(REASON_LOCAL_PREF),
        );
        assert_eq!(
            &buf[..],
            &[
                0x00, 0x05, // type 5 (Path Marking, path-marking-05 §7)
                0x00, 0x06, // length: status(4) + reason(2)
                0x00, 0x00, // index 0 = all NLRIs
                0x00, 0x00, 0x04, 0x02, // Best | Stale
                0x00, 0x03, // reason: local preference
            ]
        );

        let mut buf = BytesMut::new();
        put_path_marking_tlv(&mut buf, INDEX_ALL_NLRI, PATH_STATUS_BEST, None);
        assert_eq!(
            &buf[..],
            &[0x00, 0x05, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
        );
    }

    #[test]
    fn indexed_tlv_with_nlri_ordinal() {
        let mut buf = BytesMut::new();
        put_indexed_tlv(&mut buf, RM_TLV_TIMESTAMP, 7, &[0xFF]);
        assert_eq!(&buf[..], &[0x00, 0x03, 0x00, 0x01, 0x00, 0x07, 0xFF]);
    }
}
