//! BMP message encoding (RFC 7854).
//!
//! Encodes BMP messages for transmission to collectors.
//! No decode is needed — BMP is unidirectional (router → collector).

use std::net::IpAddr;
use std::time::UNIX_EPOCH;

use bytes::{BufMut, Bytes, BytesMut};

use crate::types::{BmpPeerInfo, PeerDownReason};

// BMP message types (RFC 7854 §4.1)
const BMP_MSG_ROUTE_MONITORING: u8 = 0;
const BMP_MSG_STATS_REPORT: u8 = 1;
const BMP_MSG_PEER_DOWN: u8 = 2;
const BMP_MSG_PEER_UP: u8 = 3;
const BMP_MSG_INITIATION: u8 = 4;
const BMP_MSG_TERMINATION: u8 = 5;

// BMP version
const BMP_VERSION: u8 = 3;

// BMP common header length: version(1) + length(4) + type(1) = 6
const BMP_COMMON_HEADER_LEN: usize = 6;

// Per-peer header length: type(1) + flags(1) + distinguisher(8) + address(16) + AS(4) + BGP ID(4) + timestamp(8) = 42
const PER_PEER_HEADER_LEN: usize = 42;

// BMP Initiation TLV types
const BMP_INIT_TLV_SYS_DESCR: u16 = 1;
const BMP_INIT_TLV_SYS_NAME: u16 = 2;

// BMP Termination TLV types
const BMP_TERM_TLV_STRING: u16 = 0;
const BMP_TERM_TLV_REASON: u16 = 1;

// Per-peer header flags
const PEER_FLAG_V: u8 = 0x80; // IPv6 peer
const PEER_FLAG_L: u8 = 0x40; // Post-policy
const PEER_FLAG_A: u8 = 0x20; // 2-byte AS in per-peer header (legacy)

/// Stat counter for Stats Report messages.
///
/// RFC 7854 numeric stat types (4-byte or 8-byte `Stat Data`):
/// - 32-bit: 0-6, 11-13
/// - 64-bit: 7-8
///
/// AFI/SAFI-qualified stat types 9-10 must use [`AfiStatCounter`].
#[derive(Debug, Clone)]
pub struct StatCounter {
    pub stat_type: u16,
    pub value: u64,
}

/// AFI/SAFI-qualified stat counter (RFC 7854 stat types 9-10).
/// Payload: AFI(2) + SAFI(1) + count(8).
#[derive(Debug, Clone)]
pub struct AfiStatCounter {
    pub stat_type: u16,
    pub afi: u16,
    pub safi: u8,
    pub value: u64,
}

/// Returns the value size for RFC 7854 numeric stat types.
/// Returns `None` for AFI/SAFI-qualified or unknown types.
fn numeric_stat_size(stat_type: u16) -> Option<usize> {
    match stat_type {
        // 4-byte counters: types 0-6, 11-13
        0..=6 | 11..=13 => Some(4),
        // 64-bit gauges: types 7-8
        7 | 8 => Some(8),
        // AFI/SAFI-qualified and unknown type formats are not encoded
        // by this numeric-only helper.
        _ => None,
    }
}

fn is_afi_stat(stat_type: u16) -> bool {
    matches!(stat_type, 9 | 10)
}

/// Encode the per-peer header (42 bytes, RFC 7854 §4.2).
fn encode_per_peer_header(info: &BmpPeerInfo, buf: &mut BytesMut) {
    buf.put_u8(info.peer_type as u8);

    let mut flags: u8 = 0;
    if info.is_ipv6 {
        flags |= PEER_FLAG_V;
    }
    if info.is_post_policy {
        flags |= PEER_FLAG_L;
    }
    if !info.is_as4 {
        flags |= PEER_FLAG_A;
    }
    buf.put_u8(flags);

    // Peer distinguisher (8 bytes, 0 for Global type)
    buf.put_u64(0);

    // Peer address (16 bytes — IPv4 uses 12 zero bytes + 4-byte address per RFC 7854 §4.2)
    put_ipaddr_16(buf, info.peer_addr);

    buf.put_u32(info.peer_asn);
    buf.put_slice(&info.peer_bgp_id.octets());

    // Timestamp seconds (4 bytes) + microseconds (4 bytes)
    #[expect(clippy::cast_possible_truncation)]
    let (secs, usecs) = match info.timestamp.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as u32, d.subsec_micros()),
        Err(_) => (0, 0),
    };
    buf.put_u32(secs);
    buf.put_u32(usecs);
}

/// Write the BMP common header (6 bytes) at the beginning of a buffer.
fn write_common_header(buf: &mut [u8], msg_type: u8) {
    buf[0] = BMP_VERSION;
    #[expect(clippy::cast_possible_truncation)]
    let len = buf.len() as u32;
    buf[1..5].copy_from_slice(&len.to_be_bytes());
    buf[5] = msg_type;
}

fn put_tlv_string(buf: &mut BytesMut, tlv_type: u16, value: &str) {
    if !value.is_empty() {
        buf.put_u16(tlv_type);
        #[expect(clippy::cast_possible_truncation)]
        buf.put_u16(value.len() as u16);
        buf.put_slice(value.as_bytes());
    }
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
#[must_use]
pub fn encode_initiation(sys_name: &str, sys_descr: &str) -> Bytes {
    let tlv_len = if sys_name.is_empty() {
        0
    } else {
        4 + sys_name.len()
    } + if sys_descr.is_empty() {
        0
    } else {
        4 + sys_descr.len()
    };
    let total = BMP_COMMON_HEADER_LEN + tlv_len;

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    put_tlv_string(&mut buf, BMP_INIT_TLV_SYS_DESCR, sys_descr);
    put_tlv_string(&mut buf, BMP_INIT_TLV_SYS_NAME, sys_name);

    write_common_header(&mut buf, BMP_MSG_INITIATION);
    buf.freeze()
}

/// Encode BMP Peer Up Notification (Type 3, RFC 7854 §4.10).
#[must_use]
pub fn encode_peer_up(
    info: &BmpPeerInfo,
    local_addr: IpAddr,
    local_port: u16,
    remote_port: u16,
    local_open: &[u8],
    remote_open: &[u8],
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

    write_common_header(&mut buf, BMP_MSG_PEER_UP);
    buf.freeze()
}

/// Encode BMP Peer Down Notification (Type 2, RFC 7854 §4.9).
#[must_use]
pub fn encode_peer_down(info: &BmpPeerInfo, reason: &PeerDownReason) -> Bytes {
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

    write_common_header(&mut buf, BMP_MSG_PEER_DOWN);
    buf.freeze()
}

/// Encode BMP Route Monitoring message (Type 0, RFC 7854 §4.6).
///
/// Wraps a raw BGP UPDATE PDU (including 19-byte header).
#[must_use]
pub fn encode_route_monitoring(info: &BmpPeerInfo, update_pdu: &[u8]) -> Bytes {
    let total = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN + update_pdu.len();

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    encode_per_peer_header(info, &mut buf);
    buf.put_slice(update_pdu);

    write_common_header(&mut buf, BMP_MSG_ROUTE_MONITORING);
    buf.freeze()
}

/// Encode BMP Statistics Report (Type 1, RFC 7854 §4.8).
///
/// `counters` are RFC 7854 numeric stat types (0-8, 11-13).
/// `afi_counters` are AFI/SAFI-qualified stat types (9-10).
/// Stat types placed in the wrong list are silently skipped.
#[must_use]
pub fn encode_stats_report(
    info: &BmpPeerInfo,
    counters: &[StatCounter],
    afi_counters: &[AfiStatCounter],
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
    let total = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN + 4 + numeric_len + afi_len;

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    encode_per_peer_header(info, &mut buf);

    #[expect(clippy::cast_possible_truncation)]
    buf.put_u32(num_valid as u32);

    for counter in counters {
        if let Some(sz) = numeric_stat_size(counter.stat_type) {
            buf.put_u16(counter.stat_type);
            #[expect(clippy::cast_possible_truncation)]
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

    write_common_header(&mut buf, BMP_MSG_STATS_REPORT);
    buf.freeze()
}

/// Encode BMP Termination message (Type 5, RFC 7854 §4.5).
#[must_use]
pub fn encode_termination(reason: u16, message: &str) -> Bytes {
    let reason_tlv_len = 4 + 2; // type(2) + len(2) + value(2)
    let msg_tlv_len = if message.is_empty() {
        0
    } else {
        4 + message.len()
    };
    let total = BMP_COMMON_HEADER_LEN + reason_tlv_len + msg_tlv_len;

    let mut buf = BytesMut::with_capacity(total);
    buf.put_bytes(0, BMP_COMMON_HEADER_LEN);
    put_tlv_string(&mut buf, BMP_TERM_TLV_STRING, message);

    // Reason TLV (type=1, 2-byte value)
    buf.put_u16(BMP_TERM_TLV_REASON);
    buf.put_u16(2);
    buf.put_u16(reason);

    write_common_header(&mut buf, BMP_MSG_TERMINATION);
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
            is_as4: true,
            timestamp: UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
        }
    }

    fn verify_common_header(buf: &[u8], expected_type: u8) {
        assert!(buf.len() >= BMP_COMMON_HEADER_LEN);
        assert_eq!(buf[0], BMP_VERSION, "version");
        let len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
        assert_eq!(len as usize, buf.len(), "length");
        assert_eq!(buf[5], expected_type, "message type");
    }

    fn verify_per_peer_header(buf: &[u8], info: &BmpPeerInfo) {
        assert!(buf.len() >= PER_PEER_HEADER_LEN);
        assert_eq!(buf[0], info.peer_type as u8, "peer type");

        let expected_flags = if info.is_ipv6 { PEER_FLAG_V } else { 0 }
            | if info.is_post_policy { PEER_FLAG_L } else { 0 }
            | if info.is_as4 { 0 } else { PEER_FLAG_A };
        assert_eq!(buf[1], expected_flags, "flags");

        let asn = u32::from_be_bytes([buf[26], buf[27], buf[28], buf[29]]);
        assert_eq!(asn, info.peer_asn, "peer ASN");

        let bgp_id = Ipv4Addr::new(buf[30], buf[31], buf[32], buf[33]);
        assert_eq!(bgp_id, info.peer_bgp_id, "peer BGP ID");
    }

    #[test]
    fn initiation_message_encoding() {
        let msg = encode_initiation("rustbgpd", "test daemon");
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
        );
        verify_common_header(&msg, BMP_MSG_PEER_UP);
        verify_per_peer_header(&msg[BMP_COMMON_HEADER_LEN..], &info);
        assert_eq!(
            msg.len(),
            BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN + 20 + 58
        );
    }

    #[test]
    fn peer_down_local_notification() {
        let info = sample_peer_info();
        let reason = PeerDownReason::LocalNotification(Bytes::from_static(&[0xFF; 21]));
        let msg = encode_peer_down(&info, &reason);
        verify_common_header(&msg, BMP_MSG_PEER_DOWN);
        assert_eq!(msg[BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN], 1);
    }

    #[test]
    fn peer_down_remote_no_notification() {
        let info = sample_peer_info();
        let msg = encode_peer_down(&info, &PeerDownReason::RemoteNoNotification);
        verify_common_header(&msg, BMP_MSG_PEER_DOWN);
        let offset = BMP_COMMON_HEADER_LEN + PER_PEER_HEADER_LEN;
        assert_eq!(msg[offset], 4);
        assert_eq!(msg.len(), offset + 1);
    }

    #[test]
    fn route_monitoring_encoding() {
        let info = sample_peer_info();
        let update_pdu = vec![0xAA; 50];
        let msg = encode_route_monitoring(&info, &update_pdu);
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
        let msg = encode_stats_report(&info, &counters, &afi_counters);
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
        let msg = encode_stats_report(&info, &counters, &[]);
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
        let msg = encode_termination(0, "shutting down");
        verify_common_header(&msg, BMP_MSG_TERMINATION);
    }

    #[test]
    fn initiation_empty_fields() {
        let msg = encode_initiation("", "");
        verify_common_header(&msg, BMP_MSG_INITIATION);
        assert_eq!(msg.len(), BMP_COMMON_HEADER_LEN);
    }

    #[test]
    fn peer_down_local_no_notification() {
        let info = sample_peer_info();
        let msg = encode_peer_down(&info, &PeerDownReason::LocalNoNotification(6));
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
        let msg = encode_route_monitoring(&info, &[0u8; 23]);
        assert_ne!(msg[BMP_COMMON_HEADER_LEN + 1] & PEER_FLAG_V, 0);
    }

    #[test]
    fn termination_no_message() {
        let msg = encode_termination(1, "");
        verify_common_header(&msg, BMP_MSG_TERMINATION);
        assert_eq!(msg.len(), BMP_COMMON_HEADER_LEN + 6);
    }

    #[test]
    fn ipv4_address_encoding_uses_12_zero_bytes() {
        // RFC 7854 §4.2: IPv4 peer address is 12 zero bytes + 4-byte IPv4 (NOT IPv4-mapped ::ffff:)
        let info = sample_peer_info(); // IPv4 10.0.0.2
        let msg = encode_route_monitoring(&info, &[0u8; 23]);
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
    fn ipv6_address_encoding_full_16_bytes() {
        let mut info = sample_peer_info();
        info.is_ipv6 = true;
        info.peer_addr = IpAddr::V6("2001:db8::2".parse().unwrap());
        let msg = encode_route_monitoring(&info, &[0u8; 23]);
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
        let msg = encode_stats_report(&info, &[], &afi_counters);
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
