use bytes::{Buf, BufMut};

use crate::capability::{Afi, Safi};
use crate::constants::{HEADER_LEN, MARKER, MAX_MESSAGE_LEN, message_type};
use crate::error::{DecodeError, EncodeError};
use crate::orf::{
    OrfPayload, decode_route_refresh_orf, encode_route_refresh_orf, route_refresh_orf_len,
};

/// ROUTE-REFRESH base body length (AFI u16 + subtype u8 + SAFI u8). An ORF
/// message (RFC 5291 §5.2) extends the body beyond this with ORF entries.
const BODY_LEN: usize = 4;

/// Total wire length of a plain ROUTE-REFRESH message (header + base body).
const TOTAL_LEN: usize = HEADER_LEN + BODY_LEN;

/// ROUTE-REFRESH demarcation subtype (RFC 7313).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RouteRefreshSubtype {
    /// Normal route refresh request (subtype 0).
    Normal,
    /// Beginning of Route Refresh (subtype 1, RFC 7313).
    BoRR,
    /// End of Route Refresh (subtype 2, RFC 7313).
    EoRR,
    /// Unrecognized subtype value.
    Unknown(
        /// The raw subtype byte.
        u8,
    ),
}

impl RouteRefreshSubtype {
    /// Create from a raw subtype byte.
    #[must_use]
    pub fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Normal,
            1 => Self::BoRR,
            2 => Self::EoRR,
            other => Self::Unknown(other),
        }
    }

    /// Return the raw byte value for this subtype.
    #[must_use]
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Normal => 0,
            Self::BoRR => 1,
            Self::EoRR => 2,
            Self::Unknown(value) => value,
        }
    }
}

/// BGP ROUTE-REFRESH message (RFC 2918 + RFC 7313 + RFC 5291 ORF).
///
/// Requests a peer to re-advertise its Adj-RIB-Out for the specified
/// address family. RFC 7313 reuses the third octet as a demarcation subtype
/// (BoRR/EoRR). Raw wire values are stored so that unknown AFI/SAFI or
/// subtype values can be decoded without error — the transport layer decides
/// whether to act on or ignore them.
///
/// When the message body extends beyond the 4-byte AFI/Reserved/SAFI header,
/// the trailing bytes are an RFC 5291 ORF section, decoded into [`orf`]. A
/// plain or Enhanced Route Refresh has [`orf`] set to `None`.
///
/// [`orf`]: RouteRefreshMessage::orf
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    /// Raw AFI value from the wire.
    pub afi_raw: u16,
    /// Raw demarcation subtype byte from the wire.
    pub subtype_raw: u8,
    /// Raw SAFI value from the wire.
    pub safi_raw: u8,
    /// RFC 5291 ORF section, present when the body extends past the 4-byte
    /// header. `None` for a plain (RFC 2918) or Enhanced (RFC 7313) refresh.
    pub orf: Option<OrfPayload>,
}

impl RouteRefreshMessage {
    /// Create a normal (subtype 0) ROUTE-REFRESH from typed AFI/SAFI values.
    #[must_use]
    pub fn new(afi: Afi, safi: Safi) -> Self {
        Self::new_with_subtype(afi, safi, RouteRefreshSubtype::Normal)
    }

    /// Create a ROUTE-REFRESH with an explicit subtype.
    #[must_use]
    pub fn new_with_subtype(afi: Afi, safi: Safi, subtype: RouteRefreshSubtype) -> Self {
        Self {
            afi_raw: afi as u16,
            subtype_raw: subtype.as_u8(),
            safi_raw: safi as u8,
            orf: None,
        }
    }

    /// Create an ORF-carrying ROUTE-REFRESH (RFC 5291 §5.2). The third octet
    /// is Reserved (subtype 0) for an ORF message.
    #[must_use]
    pub fn new_with_orf(afi: Afi, safi: Safi, orf: OrfPayload) -> Self {
        Self {
            afi_raw: afi as u16,
            subtype_raw: 0,
            safi_raw: safi as u8,
            orf: Some(orf),
        }
    }

    /// Try to interpret the raw AFI as a known address family.
    #[must_use]
    pub fn afi(&self) -> Option<Afi> {
        Afi::from_u16(self.afi_raw)
    }

    /// Try to interpret the raw SAFI as a known sub-address family.
    #[must_use]
    pub fn safi(&self) -> Option<Safi> {
        Safi::from_u8(self.safi_raw)
    }

    /// Decode the demarcation subtype.
    #[must_use]
    pub fn subtype(&self) -> RouteRefreshSubtype {
        RouteRefreshSubtype::from_u8(self.subtype_raw)
    }

    /// Decode a ROUTE-REFRESH message body from a buffer.
    ///
    /// A 4-byte body is a plain/Enhanced refresh (`orf: None`). A longer body
    /// carries an RFC 5291 ORF section, decoded into `orf`. A malformed ORF
    /// *entry* does not fail the decode — it is surfaced via
    /// [`crate::orf::OrfEntries::Malformed`] so the caller can apply the RFC
    /// 5291 §5.2 reset semantics instead of tearing the session down.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the body length is below 4 or the buffer is
    /// truncated relative to the declared body length. Unknown AFI/SAFI values
    /// and unknown subtypes are preserved.
    pub fn decode(buf: &mut impl Buf, body_len: usize) -> Result<Self, DecodeError> {
        if body_len < BODY_LEN {
            return Err(DecodeError::InvalidLength {
                length: u16::try_from(HEADER_LEN + body_len).unwrap_or(u16::MAX),
            });
        }
        if buf.remaining() < body_len {
            return Err(DecodeError::Incomplete {
                needed: body_len,
                available: buf.remaining(),
            });
        }

        let afi_raw = buf.get_u16();
        let subtype_raw = buf.get_u8();
        let safi_raw = buf.get_u8();

        let orf = if body_len > BODY_LEN {
            // Bound the ORF parse to the declared body so a buffer carrying
            // more than one message cannot over-read.
            let mut orf_buf = buf.copy_to_bytes(body_len - BODY_LEN);
            let family = Afi::from_u16(afi_raw).zip(Safi::from_u8(safi_raw));
            Some(decode_route_refresh_orf(&mut orf_buf, family)?)
        } else {
            None
        };

        Ok(Self {
            afi_raw,
            subtype_raw,
            safi_raw,
            orf,
        })
    }

    /// Encode a complete ROUTE-REFRESH message (header + body) into a buffer
    /// using the standard 4096-byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if the total message length (with an ORF
    /// section) exceeds the maximum BGP message size.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
        self.encode_with_limit(buf, MAX_MESSAGE_LEN)
    }

    /// Encode with a custom maximum message length. RFC 8654 §3: Extended
    /// Messages apply to every message type except OPEN and KEEPALIVE, so a
    /// ROUTE-REFRESH (e.g. with a large ORF section) may use the extended
    /// 65535-byte limit when negotiated — and MUST stay within 4096 bytes
    /// when it was not.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::MessageTooLong`] if the encoded message exceeds
    /// `max_message_len`.
    pub fn encode_with_limit(
        &self,
        buf: &mut impl BufMut,
        max_message_len: u16,
    ) -> Result<(), EncodeError> {
        let total = self.encoded_len();
        if total > usize::from(max_message_len) {
            return Err(EncodeError::MessageTooLong { size: total });
        }
        let total_u16 = u16::try_from(total).map_err(|_| EncodeError::ValueOutOfRange {
            field: "route_refresh_message_length",
            value: total.to_string(),
        })?;
        buf.put_slice(&MARKER);
        buf.put_u16(total_u16);
        buf.put_u8(message_type::ROUTE_REFRESH);
        buf.put_u16(self.afi_raw);
        buf.put_u8(self.subtype_raw);
        buf.put_u8(self.safi_raw);
        if let Some(orf) = &self.orf {
            encode_route_refresh_orf(orf, buf)?;
        }
        Ok(())
    }

    /// Total encoded size on the wire (header + base body + any ORF section).
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        TOTAL_LEN + self.orf.as_ref().map_or(0, route_refresh_orf_len)
    }
}

impl std::fmt::Display for RouteRefreshMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let subtype = match self.subtype() {
            RouteRefreshSubtype::Normal => "Normal".to_string(),
            RouteRefreshSubtype::BoRR => "BoRR".to_string(),
            RouteRefreshSubtype::EoRR => "EoRR".to_string(),
            RouteRefreshSubtype::Unknown(value) => format!("Unknown({value})"),
        };

        let orf = if let Some(payload) = &self.orf {
            format!(
                " ORF(when={:?}, groups={})",
                payload.when_to_refresh,
                payload.groups.len()
            )
        } else {
            String::new()
        };
        match (self.afi(), self.safi()) {
            (Some(afi), Some(safi)) => {
                write!(
                    f,
                    "ROUTE-REFRESH subtype={subtype} AFI={afi:?} SAFI={safi:?}{orf}"
                )
            }
            _ => write!(
                f,
                "ROUTE-REFRESH subtype={subtype} AFI={} SAFI={}{orf}",
                self.afi_raw, self.safi_raw
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};

    use super::*;

    #[test]
    fn roundtrip_ipv4_unicast() {
        let msg = RouteRefreshMessage::new(Afi::Ipv4, Safi::Unicast);
        let mut buf = BytesMut::with_capacity(TOTAL_LEN);
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), TOTAL_LEN);

        let mut bytes = buf.freeze();
        bytes.advance(HEADER_LEN);
        let decoded = RouteRefreshMessage::decode(&mut bytes, BODY_LEN).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.afi(), Some(Afi::Ipv4));
        assert_eq!(decoded.safi(), Some(Safi::Unicast));
        assert_eq!(decoded.subtype(), RouteRefreshSubtype::Normal);
    }

    #[test]
    fn roundtrip_ipv6_unicast() {
        let msg = RouteRefreshMessage::new(Afi::Ipv6, Safi::Unicast);
        let mut buf = BytesMut::with_capacity(TOTAL_LEN);
        msg.encode(&mut buf).unwrap();

        let mut bytes = buf.freeze();
        bytes.advance(HEADER_LEN);
        let decoded = RouteRefreshMessage::decode(&mut bytes, BODY_LEN).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.afi(), Some(Afi::Ipv6));
        assert_eq!(decoded.safi(), Some(Safi::Unicast));
        assert_eq!(decoded.subtype(), RouteRefreshSubtype::Normal);
    }

    #[test]
    fn roundtrip_borr() {
        let msg = RouteRefreshMessage::new_with_subtype(
            Afi::Ipv4,
            Safi::Unicast,
            RouteRefreshSubtype::BoRR,
        );
        let mut buf = BytesMut::with_capacity(TOTAL_LEN);
        msg.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        bytes.advance(HEADER_LEN);
        let decoded = RouteRefreshMessage::decode(&mut bytes, BODY_LEN).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.subtype(), RouteRefreshSubtype::BoRR);
    }

    #[test]
    fn roundtrip_eorr() {
        let msg = RouteRefreshMessage::new_with_subtype(
            Afi::Ipv6,
            Safi::Unicast,
            RouteRefreshSubtype::EoRR,
        );
        let mut buf = BytesMut::with_capacity(TOTAL_LEN);
        msg.encode(&mut buf).unwrap();
        let mut bytes = buf.freeze();
        bytes.advance(HEADER_LEN);
        let decoded = RouteRefreshMessage::decode(&mut bytes, BODY_LEN).unwrap();
        assert_eq!(decoded, msg);
        assert_eq!(decoded.subtype(), RouteRefreshSubtype::EoRR);
    }

    #[test]
    fn plain_four_byte_body_has_no_orf() {
        // Regression: a 4-byte body is a plain/Enhanced refresh, never ORF.
        let data: &[u8] = &[0, 1, 0, 1];
        let mut buf = Bytes::copy_from_slice(data);
        let msg = RouteRefreshMessage::decode(&mut buf, 4).unwrap();
        assert_eq!(msg.orf, None);
    }

    #[test]
    fn reject_body_length_three() {
        let data: &[u8] = &[0, 1, 0];
        let mut buf = Bytes::copy_from_slice(data);
        assert!(RouteRefreshMessage::decode(&mut buf, 3).is_err());
    }

    #[test]
    fn reject_truncated_orf_body() {
        // body_len claims 10 but only 4 bytes are present.
        let data: &[u8] = &[0, 1, 0, 1];
        let mut buf = Bytes::copy_from_slice(data);
        assert!(RouteRefreshMessage::decode(&mut buf, 10).is_err());
    }

    #[test]
    fn roundtrip_orf_route_refresh() {
        use crate::nlri::{Ipv4Prefix, Prefix};
        use crate::orf::{
            AddressPrefixOrf, OrfAction, OrfEntries, OrfEntryGroup, OrfMatch, OrfPayload, OrfType,
            WhenToRefresh,
        };
        use std::net::Ipv4Addr;

        let payload = OrfPayload {
            when_to_refresh: WhenToRefresh::Immediate,
            groups: vec![OrfEntryGroup {
                orf_type: OrfType::AddressPrefix,
                entries: OrfEntries::AddressPrefix(vec![AddressPrefixOrf {
                    action: OrfAction::Add,
                    match_: OrfMatch::Permit,
                    sequence: 10,
                    min_len: 24,
                    max_len: 32,
                    prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
                }]),
            }],
        };
        let msg = RouteRefreshMessage::new_with_orf(Afi::Ipv4, Safi::Unicast, payload);

        let mut buf = BytesMut::with_capacity(msg.encoded_len());
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), msg.encoded_len());

        let mut bytes = buf.freeze();
        bytes.advance(HEADER_LEN);
        let body_len = msg.encoded_len() - HEADER_LEN;
        let decoded = RouteRefreshMessage::decode(&mut bytes, body_len).unwrap();
        assert_eq!(decoded, msg);
        assert!(decoded.orf.is_some());
    }

    #[test]
    fn decode_unknown_afi_succeeds() {
        let data: &[u8] = &[0, 99, 0, 1];
        let mut buf = Bytes::copy_from_slice(data);
        let msg = RouteRefreshMessage::decode(&mut buf, 4).unwrap();
        assert_eq!(msg.afi_raw, 99);
        assert_eq!(msg.afi(), None);
        assert_eq!(msg.safi(), Some(Safi::Unicast));
        assert_eq!(msg.subtype(), RouteRefreshSubtype::Normal);
    }

    #[test]
    fn decode_unknown_safi_succeeds() {
        let data: &[u8] = &[0, 1, 0, 99];
        let mut buf = Bytes::copy_from_slice(data);
        let msg = RouteRefreshMessage::decode(&mut buf, 4).unwrap();
        assert_eq!(msg.safi_raw, 99);
        assert_eq!(msg.safi(), None);
        assert_eq!(msg.afi(), Some(Afi::Ipv4));
        assert_eq!(msg.subtype(), RouteRefreshSubtype::Normal);
    }

    #[test]
    fn decode_orf_unknown_safi_preserves_address_prefix_group_as_raw() {
        use crate::constants::orf;
        use crate::orf::{OrfEntries, OrfType, WhenToRefresh};

        let data: &[u8] = &[
            0,
            1,
            0,
            128, // AFI IPv4, Reserved, future/unknown SAFI.
            orf::WHEN_IMMEDIATE,
            orf::TYPE_ADDRESS_PREFIX,
            0,
            8,
            orf::ACTION_ADD,
            0,
            0,
            0,
            1,
            0,
            0,
            40,
        ];
        let mut buf = Bytes::copy_from_slice(data);
        let msg = RouteRefreshMessage::decode(&mut buf, data.len()).unwrap();
        let payload = msg.orf.unwrap();
        assert_eq!(payload.when_to_refresh, WhenToRefresh::Immediate);
        assert_eq!(payload.groups[0].orf_type, OrfType::AddressPrefix);
        assert_eq!(
            payload.groups[0].entries,
            OrfEntries::Raw(Bytes::from_static(&[orf::ACTION_ADD, 0, 0, 0, 1, 0, 0, 40]))
        );
    }

    #[test]
    fn decode_unknown_subtype_succeeds() {
        let data: &[u8] = &[0, 1, 9, 1];
        let mut buf = Bytes::copy_from_slice(data);
        let msg = RouteRefreshMessage::decode(&mut buf, 4).unwrap();
        assert_eq!(msg.subtype(), RouteRefreshSubtype::Unknown(9));
    }

    #[test]
    fn encoded_len_is_23() {
        let msg = RouteRefreshMessage::new(Afi::Ipv4, Safi::Unicast);
        assert_eq!(msg.encoded_len(), 23);
    }

    #[test]
    fn display_known_family() {
        let msg = RouteRefreshMessage::new(Afi::Ipv6, Safi::Unicast);
        let s = format!("{msg}");
        assert!(s.contains("Ipv6"));
        assert!(s.contains("Unicast"));
        assert!(s.contains("Normal"));
    }

    #[test]
    fn display_unknown_family() {
        let msg = RouteRefreshMessage {
            afi_raw: 99,
            subtype_raw: 7,
            safi_raw: 42,
            orf: None,
        };
        let s = format!("{msg}");
        assert!(s.contains("99"));
        assert!(s.contains("42"));
        assert!(s.contains("Unknown(7)"));
    }
}
