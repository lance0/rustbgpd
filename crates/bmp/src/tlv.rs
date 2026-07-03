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

    #[test]
    fn indexed_tlv_with_nlri_ordinal() {
        let mut buf = BytesMut::new();
        put_indexed_tlv(&mut buf, RM_TLV_TIMESTAMP, 7, &[0xFF]);
        assert_eq!(&buf[..], &[0x00, 0x03, 0x00, 0x01, 0x00, 0x07, 0xFF]);
    }
}
