//! BMP message encoding (RFC 7854, plus BMP version 4 framing per
//! draft-ietf-grow-bmp-tlv-20).
//!
//! Encodes BMP messages for transmission to collectors.
//! No decode is needed — BMP is unidirectional (router → collector).
//!
//! Every encoder takes a [`BmpVersion`]. Under `V3` the output is
//! byte-identical to the pre-v4 encoders. Under `V4` (§3 of the
//! draft) the common-header version byte is 4 on every message type;
//! Route Monitoring wraps the UPDATE PDU in the BGP Message TLV
//! (§5.2) and Stats Reports wrap count + stats in the Stats TLV
//! (§5.4). All other message types already provision TLV data in v3
//! (§5.5), so only their version byte changes.

use std::net::IpAddr;
use std::time::UNIX_EPOCH;

use bytes::{BufMut, Bytes, BytesMut};

use crate::tlv;
use crate::types::{
    BmpLocRibConfig, BmpPeerInfo, BmpPeerType, BmpVersion, LOC_RIB_TABLE_NAME, PeerDownReason,
};

// BMP message types (RFC 7854 §4.1)
const BMP_MSG_ROUTE_MONITORING: u8 = 0;
const BMP_MSG_STATS_REPORT: u8 = 1;
const BMP_MSG_PEER_DOWN: u8 = 2;
const BMP_MSG_PEER_UP: u8 = 3;
const BMP_MSG_INITIATION: u8 = 4;
const BMP_MSG_TERMINATION: u8 = 5;

// BMP common header length: version(1) + length(4) + type(1) = 6
const BMP_COMMON_HEADER_LEN: usize = 6;

// Per-peer header length: type(1) + flags(1) + distinguisher(8) + address(16) + AS(4) + BGP ID(4) + timestamp(8) = 42
const PER_PEER_HEADER_LEN: usize = 42;

// BMP Initiation TLV types
const BMP_INIT_TLV_SYS_DESCR: u16 = 1;
const BMP_INIT_TLV_SYS_NAME: u16 = 2;
const BMP_TLV_STRING_MAX_LEN: usize = u16::MAX as usize;

// BMP Termination TLV types
const BMP_TERM_TLV_STRING: u16 = 0;
const BMP_TERM_TLV_REASON: u16 = 1;

// BMP Peer Up Information TLV: VRF/Table Name (RFC 9069 §5.2.2)
const BMP_PEER_UP_TLV_VRF_TABLE_NAME: u16 = 3;

// Peer Down reason: Local system closed, TLV data follows (RFC 9069 §5.3)
const PEER_DOWN_REASON_LOCAL_TLV: u8 = 6;

// Per-peer header flags
const PEER_FLAG_V: u8 = 0x80; // IPv6 peer
const PEER_FLAG_L: u8 = 0x40; // Post-policy
const PEER_FLAG_A: u8 = 0x20; // 2-byte AS in per-peer header (legacy)
const PEER_FLAG_O: u8 = 0x10; // Adj-RIB-Out (RFC 8671)

/// Stat counter for Stats Report messages.
///
/// RFC 7854 numeric stat types (4-byte or 8-byte `Stat Data`):
/// - 32-bit: 0-6, 11-13
/// - 64-bit: 7-8, plus RFC 8671 Adj-RIB-Out gauges 14-15
///
/// AFI/SAFI-qualified stat types 9-10 and 16-17 must use
/// [`AfiStatCounter`].
#[derive(Debug, Clone)]
pub struct StatCounter {
    /// RFC 7854 stat type code (0-8, 11-13).
    pub stat_type: u16,
    /// Counter or gauge value.
    pub value: u64,
}

/// AFI/SAFI-qualified stat counter (RFC 7854 stat types 9-10,
/// RFC 8671 types 16-17). Payload: AFI(2) + SAFI(1) + count(8).
#[derive(Debug, Clone)]
pub struct AfiStatCounter {
    /// Stat type code (9, 10, 16, or 17).
    pub stat_type: u16,
    /// Address Family Identifier.
    pub afi: u16,
    /// Subsequent Address Family Identifier.
    pub safi: u8,
    /// Counter value.
    pub value: u64,
}

/// Returns the value size for RFC 7854 numeric stat types.
/// Returns `None` for AFI/SAFI-qualified or unknown types.
fn numeric_stat_size(stat_type: u16) -> Option<usize> {
    match stat_type {
        // 4-byte counters: types 0-6, 11-13
        0..=6 | 11..=13 => Some(4),
        // 64-bit gauges: types 7-8, RFC 8671 Adj-RIB-Out types 14-15
        7 | 8 | 14 | 15 => Some(8),
        // AFI/SAFI-qualified and unknown type formats are not encoded
        // by this numeric-only helper.
        _ => None,
    }
}

fn is_afi_stat(stat_type: u16) -> bool {
    matches!(stat_type, 9 | 10 | 16 | 17)
}

/// Encode the per-peer header (42 bytes, RFC 7854 §4.2).
fn encode_per_peer_header(info: &BmpPeerInfo, buf: &mut BytesMut) {
    buf.put_u8(info.peer_type as u8);

    let mut flags: u8 = 0;
    if info.peer_type == BmpPeerType::LocRib {
        // RFC 9069 §4.2: peer type 3 has its OWN flags registry — only
        // F (0x80, filtered view) is defined and we never filter, so
        // the byte is always 0. The RFC 7854 V/L/A/O bits do not exist
        // here (never V, even when the monitored routes are IPv6).
    } else {
        if info.is_ipv6 {
            flags |= PEER_FLAG_V;
        }
        if info.is_post_policy {
            flags |= PEER_FLAG_L;
        }
        if !info.is_as4 {
            flags |= PEER_FLAG_A;
        }
        if info.is_rib_out {
            flags |= PEER_FLAG_O;
        }
    }
    buf.put_u8(flags);

    // Peer distinguisher (8 bytes, 0 for Global type)
    buf.put_u64(0);

    // Peer address (16 bytes — IPv4 uses 12 zero bytes + 4-byte address per RFC 7854 §4.2)
    put_ipaddr_16(buf, info.peer_addr);

    buf.put_u32(info.peer_asn);
    buf.put_slice(&info.peer_bgp_id.octets());

    // Timestamp seconds (4 bytes) + microseconds (4 bytes).
    let (secs, usecs) = match info.timestamp.duration_since(UNIX_EPOCH) {
        Ok(d) => (
            u32::try_from(d.as_secs()).unwrap_or(u32::MAX),
            d.subsec_micros(),
        ),
        Err(_) => (0, 0),
    };
    buf.put_u32(secs);
    buf.put_u32(usecs);
}

/// Write the BMP common header (6 bytes) at the beginning of a buffer.
fn write_common_header(buf: &mut [u8], msg_type: u8, version: BmpVersion) {
    buf[0] = version.header_byte();
    #[expect(
        clippy::cast_possible_truncation,
        reason = "BMP common header length is a 32-bit field and callers build bounded in-memory messages"
    )]
    let len = buf.len() as u32;
    buf[1..5].copy_from_slice(&len.to_be_bytes());
    buf[5] = msg_type;
}

fn put_tlv_string(buf: &mut BytesMut, tlv_type: u16, value: &str) {
    let value = truncate_tlv_string(value);
    if !value.is_empty() {
        buf.put_u16(tlv_type);
        buf.put_u16(u16::try_from(value.len()).unwrap_or(u16::MAX));
        buf.put_slice(value.as_bytes());
    }
}

fn tlv_string_wire_len(value: &str) -> usize {
    let value = truncate_tlv_string(value);
    if value.is_empty() { 0 } else { 4 + value.len() }
}

fn truncate_tlv_string(value: &str) -> &str {
    if value.len() <= BMP_TLV_STRING_MAX_LEN {
        return value;
    }

    let mut end = BMP_TLV_STRING_MAX_LEN;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// Encode an IP address into 16 bytes per RFC 7854 §4.2.
/// IPv4: 12 zero bytes followed by 4-byte address (not IPv4-mapped).
/// IPv6: 16-byte address.
fn put_ipaddr_16(buf: &mut BytesMut, addr: IpAddr) {
    match addr {
        IpAddr::V4(v4) => {
            buf.put_bytes(0, 12);
            buf.put_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.put_slice(&v6.octets());
        }
    }
}

/// Encode BMP Initiation message (Type 4, RFC 7854 §4.3).
/// Already TLV-based in v3 — v4 changes only the version byte.
#[must_use]
pub fn encode_initiation(sys_name: &str, sys_descr: &str, version: BmpVersion) -> Bytes {
    let tlv_len = tlv_string_wire_len(sys_name) + tlv_string_wire_len(sys_descr);
    let total = BMP_COMMON_HEADER_LEN + tlv_len;

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    put_tlv_string(&mut buf, BMP_INIT_TLV_SYS_DESCR, sys_descr);
    put_tlv_string(&mut buf, BMP_INIT_TLV_SYS_NAME, sys_name);

    write_common_header(&mut buf, BMP_MSG_INITIATION, version);
    buf.freeze()
}

/// Encode BMP Peer Up Notification (Type 3, RFC 7854 §4.10).
/// Already TLV-provisioned in v3 — v4 changes only the version byte.
#[must_use]
pub fn encode_peer_up(
    info: &BmpPeerInfo,
    local_addr: IpAddr,
    local_port: u16,
    remote_port: u16,
    local_open: &[u8],
    remote_open: &[u8],
    version: BmpVersion,
) -> Bytes {
    let total =
        BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN + 20 + local_open.len() + remote_open.len();

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    encode_per_peer_header(info, &mut buf);
    put_ipaddr_16(&mut buf, local_addr);
    buf.put_u16(local_port);
    buf.put_u16(remote_port);
    buf.put_slice(local_open);
    buf.put_slice(remote_open);

    write_common_header(&mut buf, BMP_MSG_PEER_UP, version);
    buf.freeze()
}

/// Encode BMP Peer Down Notification (Type 2, RFC 7854 §4.9).
/// In v4 optional TLV data may trail the reason (draft §5.3); we emit
/// none, so only the version byte changes.
#[must_use]
pub fn encode_peer_down(info: &BmpPeerInfo, reason: &PeerDownReason, version: BmpVersion) -> Bytes {
    let reason_len = match reason {
        PeerDownReason::LocalNotification(pdu) | PeerDownReason::RemoteNotification(pdu) => {
            1 + pdu.len()
        }
        PeerDownReason::LocalNoNotification(_) => 1 + 2,
        PeerDownReason::RemoteNoNotification => 1,
    };
    let total = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN + reason_len;

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    encode_per_peer_header(info, &mut buf);

    match reason {
        PeerDownReason::LocalNotification(pdu) => {
            buf.put_u8(1);
            buf.put_slice(pdu);
        }
        PeerDownReason::LocalNoNotification(code) => {
            buf.put_u8(2);
            buf.put_u16(*code);
        }
        PeerDownReason::RemoteNotification(pdu) => {
            buf.put_u8(3);
            buf.put_slice(pdu);
        }
        PeerDownReason::RemoteNoNotification => {
            buf.put_u8(4);
        }
    }

    write_common_header(&mut buf, BMP_MSG_PEER_DOWN, version);
    buf.freeze()
}

/// Encode the RFC 9069 Peer Up Notification for the emulated Loc-RIB
/// instance peer (peer type 3).
///
/// Local address and ports are zero-filled ("not applicable"), the sent
/// OPEN is the fabricated PDU from [`BmpLocRibConfig::open_pdu`], the
/// received OPEN is a byte-identical repeat of it (§5.2), and the
/// VRF/Table Name Information TLV (type 3) carries `"global"` for the
/// default Loc-RIB instance.
#[must_use]
pub fn encode_loc_rib_peer_up(
    cfg: &BmpLocRibConfig,
    timestamp: std::time::SystemTime,
    version: BmpVersion,
) -> Bytes {
    let info = cfg.peer_info(timestamp);
    let table_name = LOC_RIB_TABLE_NAME.as_bytes();
    let total = BMP_COMMON_HEADER_LEN
        + PER_PEER_HEADER_LEN
        + 20
        + 2 * cfg.open_pdu.len()
        + 4
        + table_name.len();

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    encode_per_peer_header(&info, &mut buf);
    buf.put_bytes(0, 16); // local address: zero-filled
    buf.put_u16(0); // local port
    buf.put_u16(0); // remote port
    buf.put_slice(&cfg.open_pdu); // sent OPEN (fabricated)
    buf.put_slice(&cfg.open_pdu); // received OPEN: repeat of the sent OPEN
    buf.put_u16(BMP_PEER_UP_TLV_VRF_TABLE_NAME);
    buf.put_u16(u16::try_from(table_name.len()).unwrap_or(u16::MAX));
    buf.put_slice(table_name);

    write_common_header(&mut buf, BMP_MSG_PEER_UP, version);
    buf.freeze()
}

/// Encode the RFC 9069 Peer Down Notification for the emulated Loc-RIB
/// instance peer: reason code 6 ("Local system closed, TLV data
/// follows") with the VRF/Table Name TLV echoed from the Peer Up.
#[must_use]
pub fn encode_loc_rib_peer_down(
    cfg: &BmpLocRibConfig,
    timestamp: std::time::SystemTime,
    version: BmpVersion,
) -> Bytes {
    let info = cfg.peer_info(timestamp);
    let table_name = LOC_RIB_TABLE_NAME.as_bytes();
    let total = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN + 1 + 4 + table_name.len();

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    encode_per_peer_header(&info, &mut buf);
    buf.put_u8(PEER_DOWN_REASON_LOCAL_TLV);
    buf.put_u16(BMP_PEER_UP_TLV_VRF_TABLE_NAME);
    buf.put_u16(u16::try_from(table_name.len()).unwrap_or(u16::MAX));
    buf.put_slice(table_name);

    write_common_header(&mut buf, BMP_MSG_PEER_DOWN, version);
    buf.freeze()
}

/// Encode BMP Route Monitoring message (Type 0, RFC 7854 §4.6).
///
/// Carries a raw BGP UPDATE PDU (including 19-byte header): bare
/// after the per-peer header in v3; enclosed in the mandatory BGP
/// Message TLV (type 7, index 0) in v4 (draft §5.2).
#[must_use]
pub fn encode_route_monitoring(
    info: &BmpPeerInfo,
    update_pdu: &[u8],
    version: BmpVersion,
) -> Bytes {
    // v4 adds type(2) + length(2) + index(2) around the PDU.
    let tlv_overhead = match version {
        BmpVersion::V3 => 0,
        BmpVersion::V4 => 6,
    };
    let total = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN + tlv_overhead + update_pdu.len();

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    encode_per_peer_header(info, &mut buf);
    match version {
        BmpVersion::V3 => buf.put_slice(update_pdu),
        BmpVersion::V4 => {
            tlv::put_indexed_tlv(
                &mut buf,
                tlv::RM_TLV_BGP_MESSAGE,
                tlv::INDEX_ALL_NLRI,
                update_pdu,
            );
        }
    }

    write_common_header(&mut buf, BMP_MSG_ROUTE_MONITORING, version);
    buf.freeze()
}

/// Encode BMP Statistics Report (Type 1, RFC 7854 §4.8).
///
/// `counters` are RFC 7854 numeric stat types (0-8, 11-13).
/// `afi_counters` are AFI/SAFI-qualified stat types (9-10).
/// Stat types placed in the wrong list are silently skipped.
///
/// In v4 the Stats Count and stats data are enclosed in the mandatory
/// Stats TLV, code point 1 (draft §5.4; not indexed — indexed TLVs
/// apply only to Route Monitoring, §4.3).
#[must_use]
pub fn encode_stats_report(
    info: &BmpPeerInfo,
    counters: &[StatCounter],
    afi_counters: &[AfiStatCounter],
    version: BmpVersion,
) -> Bytes {
    let numeric_len: usize = counters
        .iter()
        .filter_map(|c| numeric_stat_size(c.stat_type).map(|sz| 4 + sz))
        .sum();
    // AFI/SAFI counters: type(2) + len(2) + AFI(2) + SAFI(1) + value(8) = 15
    let afi_len: usize = afi_counters
        .iter()
        .filter(|c| is_afi_stat(c.stat_type))
        .count()
        * 15;
    let num_valid = counters
        .iter()
        .filter(|c| numeric_stat_size(c.stat_type).is_some())
        .count()
        + afi_counters
            .iter()
            .filter(|c| is_afi_stat(c.stat_type))
            .count();
    let stats_body_len = 4 + numeric_len + afi_len; // Stats Count + stats data
    // v4 adds the Stats TLV header: type(2) + length(2).
    let tlv_overhead = match version {
        BmpVersion::V3 => 0,
        BmpVersion::V4 => 4,
    };
    let total = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN + tlv_overhead + stats_body_len;

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    encode_per_peer_header(info, &mut buf);

    if version == BmpVersion::V4 {
        buf.put_u16(tlv::STATS_TLV_STATS);
        buf.put_u16(u16::try_from(stats_body_len).unwrap_or(u16::MAX));
    }

    #[expect(
        clippy::cast_possible_truncation,
        reason = "BMP stats-report item count is a 32-bit field and counts process-owned vectors"
    )]
    buf.put_u32(num_valid as u32);

    for counter in counters {
        if let Some(sz) = numeric_stat_size(counter.stat_type) {
            buf.put_u16(counter.stat_type);
            #[expect(
                clippy::cast_possible_truncation,
                reason = "BMP 4-octet stat counters are encoded in their declared protocol field width"
            )]
            if sz == 4 {
                buf.put_u16(4);
                buf.put_u32(counter.value as u32);
            } else {
                buf.put_u16(8);
                buf.put_u64(counter.value);
            }
        }
    }

    for counter in afi_counters {
        if is_afi_stat(counter.stat_type) {
            buf.put_u16(counter.stat_type);
            buf.put_u16(11); // AFI(2) + SAFI(1) + value(8) = 11
            buf.put_u16(counter.afi);
            buf.put_u8(counter.safi);
            buf.put_u64(counter.value);
        }
    }

    write_common_header(&mut buf, BMP_MSG_STATS_REPORT, version);
    buf.freeze()
}

/// Encode BMP Termination message (Type 5, RFC 7854 §4.5).
/// Already TLV-based in v3 — v4 changes only the version byte.
#[must_use]
pub fn encode_termination(reason: u16, message: &str, version: BmpVersion) -> Bytes {
    let reason_tlv_len = 4 + 2; // type(2) + len(2) + value(2)
    let msg_tlv_len = tlv_string_wire_len(message);
    let total = BMP_COMMON_HEADER_LEN + reason_tlv_len + msg_tlv_len;

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    put_tlv_string(&mut buf, BMP_TERM_TLV_STRING, message);

    // Reason TLV (type=1, 2-byte value)
    buf.put_u16(BMP_TERM_TLV_REASON);
    buf.put_u16(2);
    buf.put_u16(reason);

    write_common_header(&mut buf, BMP_MSG_TERMINATION, version);
    buf.freeze()
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::types::BmpPeerType;

    fn sample_peer_info() -> BmpPeerInfo {
        BmpPeerInfo {
            peer_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            peer_asn: 65002,
            peer_bgp_id: Ipv4Addr::new(10, 0, 0, 2),
            peer_type: BmpPeerType::Global,
            is_ipv6: false,
            is_post_policy: false,
            is_rib_out: false,
            is_as4: true,
            timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        }
    }

    fn verify_common_header(buf: &[u8], expected_type: u8) {
        assert!(buf.len() >= BMP_COMMON_HEADER_LEN);
        assert_eq!(buf[0], 3, "version");
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        assert_eq!(len as usize, buf.len(), "length");
        assert_eq!(buf[5], expected_type, "message type");
    }

    fn verify_per_peer_header(buf: &[u8], info: &BmpPeerInfo) {
        assert!(buf.len() >= PER_PEER_HEADER_LEN);
        assert_eq!(buf[0], info.peer_type as u8, "peer type");

        let expected_flags = if info.is_ipv6 { PEER_FLAG_V } else { 0 }
            | if info.is_post_policy { PEER_FLAG_L } else { 0 }
            | if info.is_as4 { 0 } else { PEER_FLAG_A }
            | if info.is_rib_out { PEER_FLAG_O } else { 0 };
        assert_eq!(buf[1], expected_flags, "flags");

        let asn = u32::from_be_bytes([buf[26], buf[27], buf[28], buf[29]]);
        assert_eq!(asn, info.peer_asn, "peer ASN");

        let bgp_id = Ipv4Addr::new(buf[30], buf[31], buf[32], buf[33]);
        assert_eq!(bgp_id, info.peer_bgp_id, "peer BGP ID");
    }

    #[test]
    fn initiation_message_encoding() {
        let msg = encode_initiation("rustbgpd", "test daemon", BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_INITIATION);

        let payload = &msg[BMP_COMMON_HEADER_LEN..];

        let tlv_type = u16::from_be_bytes([payload[0], payload[1]]);
        assert_eq!(tlv_type, BMP_INIT_TLV_SYS_DESCR);
        let tlv_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        assert_eq!(tlv_len, "test daemon".len());

        let offset = 4 + tlv_len;
        let tlv_type = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
        assert_eq!(tlv_type, BMP_INIT_TLV_SYS_NAME);
    }

    #[test]
    fn peer_up_encoding() {
        let info = sample_peer_info();
        let msg = encode_peer_up(
            &info,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            179,
            12345,
            &[0xFF; 29],
            &[0xFE; 29],
            BmpVersion::V3,
        );
        verify_common_header(&msg, BMP_MSG_PEER_UP);
        verify_per_peer_header(&msg[BMP_COMMON_HEADER_LEN..], &info);
        assert_eq!(
            msg.len(),
            BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN + 20 + 58
        );
    }

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write;
        b.iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    }

    /// draft-ietf-grow-bmp-tlv-20 pin: v3 output stays byte-identical.
    /// Full-message hex fixtures captured from the pre-v4 encoders —
    /// any diff here is a v3 wire regression.
    #[test]
    fn v3_golden_bytes_regression() {
        let info = sample_peer_info();
        assert_eq!(
            hex(&encode_route_monitoring(&info, &[0xAB; 23], BmpVersion::V3)),
            "030000004700000000000000000000000000000000000000000000000a0000020000fdea0a00\
             00026553f10000000000ababababababababababababababababababababababab"
        );
        let counters = vec![StatCounter {
            stat_type: 7,
            value: 42,
        }];
        let afi_counters = vec![AfiStatCounter {
            stat_type: 17,
            afi: 1,
            safi: 1,
            value: 10,
        }];
        assert_eq!(
            hex(&encode_stats_report(
                &info,
                &counters,
                &afi_counters,
                BmpVersion::V3
            )),
            "030000004f01000000000000000000000000000000000000000000000a0000020000fdea0a00\
             00026553f100000000000000000200070008000000000000002a0011000b00010100000000000\
             0000a"
        );
        assert_eq!(
            hex(&encode_peer_up(
                &info,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                179,
                54321,
                &[0xFF; 21],
                &[0xFE; 21],
                BmpVersion::V3,
            )),
            "030000006e03000000000000000000000000000000000000000000000a0000020000fdea0a00\
             00026553f100000000000000000000000000000000000a00000100b3d431ffffffffffffffff\
             fffffffffffffffffffffffffffefefefefefefefefefefefefefefefefefefefefe"
        );
        assert_eq!(
            hex(&encode_peer_down(
                &info,
                &PeerDownReason::LocalNoNotification(6),
                BmpVersion::V3
            )),
            "030000003302000000000000000000000000000000000000000000000a0000020000fdea0a00\
             00026553f10000000000020006"
        );
        assert_eq!(
            hex(&encode_initiation("rustbgpd", "test", BmpVersion::V3)),
            "030000001a040001000474657374000200087275737462677064"
        );
        assert_eq!(
            hex(&encode_termination(0, "bye", BmpVersion::V3)),
            "03000000130500000003627965000100020000"
        );
    }

    /// draft-ietf-grow-bmp-tlv-20 §5.2: v4 Route Monitoring golden
    /// bytes — version byte 4, per-peer header, then the mandatory BGP
    /// Message TLV (type 7, index 0) whose value is the exact UPDATE
    /// PDU.
    #[test]
    fn v4_route_monitoring_wraps_pdu_in_bgp_message_tlv() {
        let info = sample_peer_info();
        let pdu = [0xAB; 23];
        let msg = encode_route_monitoring(&info, &pdu, BmpVersion::V4);

        assert_eq!(msg[0], 4, "BMP version 4 (draft §3)");
        let len = u32::from_be_bytes(msg[1..5].try_into().unwrap());
        assert_eq!(len as usize, msg.len(), "common-header length");
        assert_eq!(
            msg.len(),
            BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN + 6 + pdu.len(),
            "TLV adds type(2)+length(2)+index(2)"
        );
        assert_eq!(msg[5], BMP_MSG_ROUTE_MONITORING);

        let tlv = &msg[BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN..];
        assert_eq!(
            u16::from_be_bytes([tlv[0], tlv[1]]),
            crate::tlv::RM_TLV_BGP_MESSAGE,
            "BGP Message TLV type 7 (§5.2, §9)"
        );
        assert_eq!(
            u16::from_be_bytes([tlv[2], tlv[3]]) as usize,
            pdu.len(),
            "length excludes the 2-byte index (§4.3)"
        );
        assert_eq!(
            u16::from_be_bytes([tlv[4], tlv[5]]),
            0,
            "index 0 = whole message (§5.2)"
        );
        assert_eq!(&tlv[6..], &pdu, "value = exact UPDATE PDU");
        // Everything before the TLV is byte-identical to v3.
        let v3 = encode_route_monitoring(&info, &pdu, BmpVersion::V3);
        assert_eq!(
            &msg[5..BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN],
            &v3[5..BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN],
            "type + per-peer header unchanged"
        );
    }

    /// draft-ietf-grow-bmp-tlv-20 §5.4: v4 Stats Report golden bytes —
    /// Stats Count + stats data enclosed in the mandatory Stats TLV
    /// (code point 1, not indexed — §4.3 scopes indexed TLVs to Route
    /// Monitoring only).
    #[test]
    fn v4_stats_report_wraps_in_stats_tlv() {
        let info = sample_peer_info();
        let counters = vec![StatCounter {
            stat_type: 7,
            value: 42,
        }];
        let afi_counters = vec![AfiStatCounter {
            stat_type: 17,
            afi: 1,
            safi: 1,
            value: 10,
        }];
        let v3 = encode_stats_report(&info, &counters, &afi_counters, BmpVersion::V3);
        let msg = encode_stats_report(&info, &counters, &afi_counters, BmpVersion::V4);

        assert_eq!(msg[0], 4, "BMP version 4");
        let len = u32::from_be_bytes(msg[1..5].try_into().unwrap());
        assert_eq!(len as usize, msg.len());
        assert_eq!(msg.len(), v3.len() + 4, "Stats TLV adds type(2)+length(2)");
        assert_eq!(msg[5], BMP_MSG_STATS_REPORT);

        let tlv = &msg[BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN..];
        assert_eq!(
            u16::from_be_bytes([tlv[0], tlv[1]]),
            crate::tlv::STATS_TLV_STATS,
            "Stats TLV code point 1 (§5.4, §9)"
        );
        let stats_body = &v3[BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN..];
        assert_eq!(
            u16::from_be_bytes([tlv[2], tlv[3]]) as usize,
            stats_body.len(),
            "TLV length = Stats Count + stats data"
        );
        assert_eq!(
            &tlv[4..],
            stats_body,
            "value = the exact v3 count + stats bytes"
        );
    }

    /// draft-ietf-grow-bmp-tlv-20 §3 + §5.5: message types that already
    /// provision TLV data in v3 (Peer Up/Down incl. the RFC 9069
    /// Loc-RIB variants, Initiation, Termination) change only the
    /// common-header version byte in v4.
    #[test]
    fn v4_version_byte_only_for_tlv_provisioned_messages() {
        let info = sample_peer_info();
        let cfg = sample_loc_rib_config();
        let local = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let pairs: Vec<(Bytes, Bytes)> = vec![
            (
                encode_peer_up(
                    &info,
                    local,
                    179,
                    54321,
                    &[0xFF; 21],
                    &[0xFE; 21],
                    BmpVersion::V3,
                ),
                encode_peer_up(
                    &info,
                    local,
                    179,
                    54321,
                    &[0xFF; 21],
                    &[0xFE; 21],
                    BmpVersion::V4,
                ),
            ),
            (
                encode_peer_down(&info, &PeerDownReason::RemoteNoNotification, BmpVersion::V3),
                encode_peer_down(&info, &PeerDownReason::RemoteNoNotification, BmpVersion::V4),
            ),
            (
                encode_loc_rib_peer_up(&cfg, ts(), BmpVersion::V3),
                encode_loc_rib_peer_up(&cfg, ts(), BmpVersion::V4),
            ),
            (
                encode_loc_rib_peer_down(&cfg, ts(), BmpVersion::V3),
                encode_loc_rib_peer_down(&cfg, ts(), BmpVersion::V4),
            ),
            (
                encode_initiation("rustbgpd", "test", BmpVersion::V3),
                encode_initiation("rustbgpd", "test", BmpVersion::V4),
            ),
            (
                encode_termination(0, "bye", BmpVersion::V3),
                encode_termination(0, "bye", BmpVersion::V4),
            ),
        ];
        for (v3, v4) in pairs {
            assert_eq!(v3[0], 3);
            assert_eq!(v4[0], 4);
            assert_eq!(v3[1..], v4[1..], "v4 differs only in the version byte");
        }
    }

    #[test]
    fn peer_down_local_notification() {
        let info = sample_peer_info();
        let reason = PeerDownReason::LocalNotification(Bytes::from_static(&[0xFF; 21]));
        let msg = encode_peer_down(&info, &reason, BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_PEER_DOWN);
        assert_eq!(msg[BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN], 1);
    }

    #[test]
    fn peer_down_remote_no_notification() {
        let info = sample_peer_info();
        let msg = encode_peer_down(&info, &PeerDownReason::RemoteNoNotification, BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_PEER_DOWN);
        let offset = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN;
        assert_eq!(msg[offset], 4);
        assert_eq!(msg.len(), offset + 1);
    }

    #[test]
    fn route_monitoring_encoding() {
        let info = sample_peer_info();
        let update_pdu = vec![0xAA; 50];
        let msg = encode_route_monitoring(&info, &update_pdu, BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_ROUTE_MONITORING);
        let pdu_offset = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN;
        assert_eq!(&msg[pdu_offset..], &update_pdu[..]);
    }

    #[test]
    fn stats_report_encoding() {
        let info = sample_peer_info();
        let counters = vec![StatCounter {
            stat_type: 0,
            value: 42,
        }];
        let afi_counters = vec![AfiStatCounter {
            stat_type: 9,
            afi: 1,
            safi: 1,
            value: 1000,
        }];
        let msg = encode_stats_report(&info, &counters, &afi_counters, BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_STATS_REPORT);
        let count_offset = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN;
        let count = u32::from_be_bytes([
            msg[count_offset],
            msg[count_offset + 1],
            msg[count_offset + 2],
            msg[count_offset + 3],
        ]);
        assert_eq!(count, 2);
    }

    #[test]
    fn stats_report_skips_mismatched_types() {
        let info = sample_peer_info();
        // Put AFI-type in simple list — should be skipped
        let counters = vec![StatCounter {
            stat_type: 9,
            value: 42,
        }];
        let msg = encode_stats_report(&info, &counters, &[], BmpVersion::V3);
        let count_offset = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN;
        let count = u32::from_be_bytes([
            msg[count_offset],
            msg[count_offset + 1],
            msg[count_offset + 2],
            msg[count_offset + 3],
        ]);
        assert_eq!(count, 0);
    }

    #[test]
    fn termination_encoding() {
        let msg = encode_termination(0, "shutting down", BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_TERMINATION);
    }

    #[test]
    fn initiation_empty_fields() {
        let msg = encode_initiation("", "", BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_INITIATION);
        assert_eq!(msg.len(), BMP_COMMON_HEADER_LEN);
    }

    #[test]
    fn initiation_oversized_tlv_string_truncates_without_length_wrap() {
        let sys_descr = "a".repeat(BMP_TLV_STRING_MAX_LEN + 1);
        let msg = encode_initiation("rustbgpd", &sys_descr, BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_INITIATION);

        let payload = &msg[BMP_COMMON_HEADER_LEN..];
        let descr_len = u16::from_be_bytes([payload[2], payload[3]]);
        assert_eq!(descr_len, u16::MAX);

        let name_offset = 4 + BMP_TLV_STRING_MAX_LEN;
        assert_eq!(
            u16::from_be_bytes([payload[name_offset], payload[name_offset + 1]]),
            BMP_INIT_TLV_SYS_NAME
        );
        assert_eq!(
            msg.len(),
            BMP_COMMON_HEADER_LEN + 4 + BMP_TLV_STRING_MAX_LEN + 4 + "rustbgpd".len()
        );
    }

    #[test]
    fn initiation_oversized_tlv_string_truncates_on_char_boundary() {
        let sys_descr = format!("{}é", "a".repeat(BMP_TLV_STRING_MAX_LEN - 1));
        let msg = encode_initiation("", &sys_descr, BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_INITIATION);

        let payload = &msg[BMP_COMMON_HEADER_LEN..];
        let descr_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
        assert_eq!(descr_len, BMP_TLV_STRING_MAX_LEN - 1);
        assert_eq!(msg.len(), BMP_COMMON_HEADER_LEN + 4 + descr_len);
    }

    #[test]
    fn peer_down_local_no_notification() {
        let info = sample_peer_info();
        let msg = encode_peer_down(
            &info,
            &PeerDownReason::LocalNoNotification(6),
            BmpVersion::V3,
        );
        verify_common_header(&msg, BMP_MSG_PEER_DOWN);
        let offset = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN;
        assert_eq!(msg[offset], 2);
        assert_eq!(u16::from_be_bytes([msg[offset + 1], msg[offset + 2]]), 6);
    }

    #[test]
    fn ipv6_peer_flags_set() {
        let mut info = sample_peer_info();
        info.is_ipv6 = true;
        info.peer_addr = IpAddr::V6("2001:db8::2".parse().unwrap());
        let msg = encode_route_monitoring(&info, &[0u8; 23], BmpVersion::V3);
        assert_ne!(msg[BMP_COMMON_HEADER_LEN + 1] & PEER_FLAG_V, 0);
    }

    /// RFC 8671 golden bytes: post-policy Adj-RIB-Out route monitoring
    /// carries O(0x10) + L(0x40) in the per-peer header flags, with the
    /// version-3 common header and the exact PDU bytes.
    #[test]
    fn rib_out_route_monitoring_sets_o_and_l_flags() {
        let mut info = sample_peer_info();
        info.is_rib_out = true;
        info.is_post_policy = true;
        let pdu = [0xAB; 23];
        let msg = encode_route_monitoring(&info, &pdu, BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_ROUTE_MONITORING);
        assert_eq!(msg[0], 3, "BMP version 3");
        assert_eq!(
            msg[BMP_COMMON_HEADER_LEN + 1],
            PEER_FLAG_O | PEER_FLAG_L,
            "flags must be exactly O|L for post-policy Adj-RIB-Out"
        );
        assert_eq!(&msg[BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN..], &pdu);
    }

    /// Non-route-monitoring messages built from the normal (rib-in)
    /// peer info keep O=0 — RFC 8671 receivers SHOULD ignore O in Peer
    /// Up/Down, and we never set it there.
    #[test]
    fn non_route_monitoring_messages_keep_o_flag_clear() {
        let info = sample_peer_info();
        let peer_up = encode_peer_up(
            &info,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            179,
            12345,
            &[0xFF; 29],
            &[0xFE; 29],
            BmpVersion::V3,
        );
        let peer_down =
            encode_peer_down(&info, &PeerDownReason::RemoteNoNotification, BmpVersion::V3);
        let stats = encode_stats_report(&info, &[], &[], BmpVersion::V3);
        for msg in [&peer_up, &peer_down, &stats] {
            assert_eq!(
                msg[BMP_COMMON_HEADER_LEN + 1] & PEER_FLAG_O,
                0,
                "O flag must be clear on non-route-monitoring messages"
            );
        }
    }

    /// RFC 8671 stat type 15 (post-policy Adj-RIB-Out total) is a
    /// 64-bit gauge; type 17 is its per-AFI/SAFI variant.
    #[test]
    fn rib_out_stats_15_and_17_encoding() {
        let info = sample_peer_info();
        let counters = vec![StatCounter {
            stat_type: 15,
            value: 0x0102_0304_0506_0708,
        }];
        let afi_counters = vec![AfiStatCounter {
            stat_type: 17,
            afi: 2,
            safi: 128,
            value: 77,
        }];
        let msg = encode_stats_report(&info, &counters, &afi_counters, BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_STATS_REPORT);
        let count_offset = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN;
        let count = u32::from_be_bytes(msg[count_offset..count_offset + 4].try_into().unwrap());
        assert_eq!(count, 2);
        // Type 15: type(2)=15, len(2)=8, value(8)
        let s = count_offset + 4;
        assert_eq!(u16::from_be_bytes([msg[s], msg[s + 1]]), 15);
        assert_eq!(u16::from_be_bytes([msg[s + 2], msg[s + 3]]), 8);
        assert_eq!(
            u64::from_be_bytes(msg[s + 4..s + 12].try_into().unwrap()),
            0x0102_0304_0506_0708
        );
        // Type 17: type(2)=17, len(2)=11, AFI(2)=2, SAFI(1)=128, value(8)
        let t = s + 12;
        assert_eq!(u16::from_be_bytes([msg[t], msg[t + 1]]), 17);
        assert_eq!(u16::from_be_bytes([msg[t + 2], msg[t + 3]]), 11);
        assert_eq!(u16::from_be_bytes([msg[t + 4], msg[t + 5]]), 2);
        assert_eq!(msg[t + 6], 128);
        assert_eq!(
            u64::from_be_bytes(msg[t + 7..t + 15].try_into().unwrap()),
            77
        );
    }

    fn sample_loc_rib_config() -> BmpLocRibConfig {
        BmpLocRibConfig {
            local_asn: 65001,
            router_id: Ipv4Addr::new(10, 0, 0, 1),
            // Any opaque PDU stands in for the fabricated OPEN — the
            // codec copies it verbatim into both OPEN fields.
            open_pdu: Bytes::from_static(&[0xAB; 37]),
        }
    }

    fn ts() -> std::time::SystemTime {
        UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000)
    }

    /// RFC 9069 golden bytes for the Loc-RIB per-peer header: peer type
    /// 3, flags 0 (its own registry — only F defined, never set by us),
    /// zero-filled peer address, distinguisher 0 (global instance),
    /// Peer AS = local AS, BGP ID = local router-id.
    #[test]
    fn loc_rib_per_peer_header_golden() {
        let cfg = sample_loc_rib_config();
        let msg = encode_route_monitoring(&cfg.peer_info(ts()), &[0xCD; 23], BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_ROUTE_MONITORING);
        let hdr = &msg[BMP_COMMON_HEADER_LEN..];
        assert_eq!(hdr[0], 3, "peer type 3 (Loc-RIB instance)");
        assert_eq!(hdr[1], 0, "flags 0 (F clear, no V/L/A/O bits exist)");
        assert_eq!(&hdr[2..10], &[0u8; 8], "peer distinguisher 0");
        assert_eq!(&hdr[10..26], &[0u8; 16], "peer address zero-filled");
        assert_eq!(u32::from_be_bytes(hdr[26..30].try_into().unwrap()), 65001);
        assert_eq!(&hdr[30..34], &[10, 0, 0, 1], "BGP ID = local router-id");
        assert_eq!(
            u32::from_be_bytes(hdr[34..38].try_into().unwrap()),
            1_700_000_000,
            "timestamp = route install time"
        );
    }

    /// Even a hostile `BmpPeerInfo` with every RFC 7854 flag bool set
    /// must encode flags 0 under peer type 3 — the registry is per
    /// peer type and only F exists there.
    #[test]
    fn loc_rib_flags_zero_even_with_flag_bools_set() {
        let info = BmpPeerInfo {
            peer_addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer_asn: 65001,
            peer_bgp_id: Ipv4Addr::new(10, 0, 0, 1),
            peer_type: BmpPeerType::LocRib,
            is_ipv6: true,
            is_post_policy: true,
            is_rib_out: true,
            is_as4: false,
            timestamp: ts(),
        };
        let msg = encode_route_monitoring(&info, &[0u8; 23], BmpVersion::V3);
        assert_eq!(msg[BMP_COMMON_HEADER_LEN + 1], 0);
    }

    /// RFC 9069 §5.2 Peer Up: zero local address/ports, sent OPEN =
    /// received OPEN = the fabricated PDU, VRF/Table Name TLV (type 3)
    /// = "global".
    #[test]
    fn loc_rib_peer_up_fabricated_open_and_table_name_tlv() {
        let cfg = sample_loc_rib_config();
        let msg = encode_loc_rib_peer_up(&cfg, ts(), BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_PEER_UP);
        assert_eq!(msg[BMP_COMMON_HEADER_LEN], 3, "peer type 3");

        let body = &msg[BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN..];
        assert_eq!(&body[..16], &[0u8; 16], "local address zero-filled");
        assert_eq!(&body[16..20], &[0u8; 4], "local + remote ports zero");
        let open_len = cfg.open_pdu.len();
        assert_eq!(&body[20..20 + open_len], &cfg.open_pdu[..], "sent OPEN");
        assert_eq!(
            &body[20 + open_len..20 + 2 * open_len],
            &cfg.open_pdu[..],
            "received OPEN is a byte-identical repeat of the sent OPEN"
        );
        let tlv = &body[20 + 2 * open_len..];
        assert_eq!(u16::from_be_bytes([tlv[0], tlv[1]]), 3, "TLV type 3");
        assert_eq!(
            u16::from_be_bytes([tlv[2], tlv[3]]) as usize,
            "global".len()
        );
        assert_eq!(&tlv[4..], b"global");
        assert_eq!(tlv.len(), 4 + "global".len(), "nothing after the TLV");
    }

    /// RFC 9069 §5.3 Peer Down: reason code 6 with the VRF/Table Name
    /// TLV echoed.
    #[test]
    fn loc_rib_peer_down_reason_6_with_table_name_tlv() {
        let cfg = sample_loc_rib_config();
        let msg = encode_loc_rib_peer_down(&cfg, ts(), BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_PEER_DOWN);
        assert_eq!(msg[BMP_COMMON_HEADER_LEN], 3, "peer type 3");
        let body = &msg[BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN..];
        assert_eq!(body[0], 6, "reason 6: local system closed, TLV follows");
        assert_eq!(u16::from_be_bytes([body[1], body[2]]), 3, "TLV type 3");
        assert_eq!(&body[5..], b"global");
    }

    /// RFC 9069 stats: type 8 (Loc-RIB total, 64-bit gauge) + type 10
    /// (per-AFI/SAFI Loc-RIB count).
    #[test]
    fn loc_rib_stats_8_and_10_encoding() {
        let cfg = sample_loc_rib_config();
        let counters = vec![StatCounter {
            stat_type: 8,
            value: 15,
        }];
        let afi_counters = vec![AfiStatCounter {
            stat_type: 10,
            afi: 1,
            safi: 1,
            value: 15,
        }];
        let msg = encode_stats_report(
            &cfg.peer_info(ts()),
            &counters,
            &afi_counters,
            BmpVersion::V3,
        );
        verify_common_header(&msg, BMP_MSG_STATS_REPORT);
        let count_offset = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN;
        assert_eq!(
            u32::from_be_bytes(msg[count_offset..count_offset + 4].try_into().unwrap()),
            2
        );
        // Type 8: type(2)=8, len(2)=8, value(8)
        let s = count_offset + 4;
        assert_eq!(u16::from_be_bytes([msg[s], msg[s + 1]]), 8);
        assert_eq!(u16::from_be_bytes([msg[s + 2], msg[s + 3]]), 8);
        assert_eq!(
            u64::from_be_bytes(msg[s + 4..s + 12].try_into().unwrap()),
            15
        );
        // Type 10: type(2)=10, len(2)=11, AFI(2)=1, SAFI(1)=1, value(8)
        let t = s + 12;
        assert_eq!(u16::from_be_bytes([msg[t], msg[t + 1]]), 10);
        assert_eq!(u16::from_be_bytes([msg[t + 2], msg[t + 3]]), 11);
        assert_eq!(u16::from_be_bytes([msg[t + 4], msg[t + 5]]), 1);
        assert_eq!(msg[t + 6], 1);
        assert_eq!(
            u64::from_be_bytes(msg[t + 7..t + 15].try_into().unwrap()),
            15
        );
    }

    #[test]
    fn termination_no_message() {
        let msg = encode_termination(1, "", BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_TERMINATION);
        assert_eq!(msg.len(), BMP_COMMON_HEADER_LEN + 6);
    }

    #[test]
    fn ipv4_address_encoding_uses_12_zero_bytes() {
        // RFC 7854 §4.2: IPv4 peer address is 12 zero bytes + 4-byte IPv4 (NOT IPv4-mapped ::ffff:)
        let info = sample_peer_info(); // IPv4 10.0.0.2
        let msg = encode_route_monitoring(&info, &[0u8; 23], BmpVersion::V3);
        // Per-peer header starts at offset 6 (after common header)
        // Address field is at offset 6 + 2 (type+flags) + 8 (distinguisher) = 16
        let addr_offset = BMP_COMMON_HEADER_LEN + 2 + 8;
        let addr_bytes = &msg[addr_offset..addr_offset + 16];
        // First 12 bytes must be all zeros (NOT 0x0000_FFFF pattern)
        assert_eq!(
            &addr_bytes[..12],
            &[0u8; 12],
            "first 12 bytes must be zero for IPv4"
        );
        assert_eq!(
            &addr_bytes[12..],
            &[10, 0, 0, 2],
            "last 4 bytes must be IPv4 address"
        );
    }

    #[test]
    fn per_peer_header_timestamp_saturates_at_u32_max() {
        let mut info = sample_peer_info();
        info.timestamp = UNIX_EPOCH + std::time::Duration::from_secs(u64::from(u32::MAX) + 1);

        let msg = encode_route_monitoring(&info, &[0u8; 23], BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_ROUTE_MONITORING);

        let timestamp_offset = BMP_COMMON_HEADER_LEN + 34;
        let secs = u32::from_be_bytes([
            msg[timestamp_offset],
            msg[timestamp_offset + 1],
            msg[timestamp_offset + 2],
            msg[timestamp_offset + 3],
        ]);
        assert_eq!(secs, u32::MAX);
    }

    #[test]
    fn ipv6_address_encoding_full_16_bytes() {
        let mut info = sample_peer_info();
        info.is_ipv6 = true;
        info.peer_addr = IpAddr::V6("2001:db8::2".parse().unwrap());
        let msg = encode_route_monitoring(&info, &[0u8; 23], BmpVersion::V3);
        let addr_offset = BMP_COMMON_HEADER_LEN + 2 + 8;
        let addr_bytes = &msg[addr_offset..addr_offset + 16];
        let expected: std::net::Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert_eq!(addr_bytes, &expected.octets());
    }

    #[test]
    fn peer_up_local_ipv4_address_encoding() {
        let info = sample_peer_info();
        let msg = encode_peer_up(
            &info,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            179,
            12345,
            &[0xFF; 29],
            &[0xFE; 29],
            BmpVersion::V3,
        );
        // Local address is right after per-peer header
        let local_addr_offset = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN;
        let local_addr = &msg[local_addr_offset..local_addr_offset + 16];
        assert_eq!(
            &local_addr[..12],
            &[0u8; 12],
            "local IPv4: first 12 bytes zero"
        );
        assert_eq!(
            &local_addr[12..],
            &[10, 0, 0, 1],
            "local IPv4: last 4 bytes"
        );
    }

    #[test]
    fn afi_stat_counter_encoding() {
        let info = sample_peer_info();
        let afi_counters = vec![AfiStatCounter {
            stat_type: 9,
            afi: 1,
            safi: 1,
            value: 500,
        }];
        let msg = encode_stats_report(&info, &[], &afi_counters, BmpVersion::V3);
        verify_common_header(&msg, BMP_MSG_STATS_REPORT);
        let count_offset = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN;
        let count = u32::from_be_bytes([
            msg[count_offset],
            msg[count_offset + 1],
            msg[count_offset + 2],
            msg[count_offset + 3],
        ]);
        assert_eq!(count, 1);
        // Verify AFI/SAFI payload: type(2) + len(2) + AFI(2) + SAFI(1) + value(8)
        let stat_offset = count_offset + 4;
        let stat_type = u16::from_be_bytes([msg[stat_offset], msg[stat_offset + 1]]);
        assert_eq!(stat_type, 9);
        let stat_len = u16::from_be_bytes([msg[stat_offset + 2], msg[stat_offset + 3]]);
        assert_eq!(stat_len, 11);
        let afi = u16::from_be_bytes([msg[stat_offset + 4], msg[stat_offset + 5]]);
        assert_eq!(afi, 1);
        assert_eq!(msg[stat_offset + 6], 1); // SAFI
    }
}
