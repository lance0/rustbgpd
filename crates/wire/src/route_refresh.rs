use bytes::{Buf, BufMut};

use crate::capability::{Afi, Safi};
use crate::constants::{HEADER_LEN, MARKER, message_type};
use crate::error::{DecodeError, EncodeError};

/// ROUTE-REFRESH message body length (AFI u16 + subtype u8 + SAFI u8).
const BODY_LEN: usize = 4;

/// Total wire length of a ROUTE-REFRESH message (header + body).
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

/// BGP ROUTE-REFRESH message (RFC 2918 + RFC 7313).
///
/// Requests a peer to re-advertise its Adj-RIB-Out for the specified
/// address family. RFC 7313 reuses the third octet as a demarcation subtype
/// (BoRR/EoRR). Raw wire values are stored so that unknown AFI/SAFI or
/// subtype values can be decoded without error — the transport layer decides
/// whether to act on or ignore them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    /// Raw AFI value from the wire.
    pub afi_raw: u16,
    /// Raw demarcation subtype byte from the wire.
    pub subtype_raw: u8,
    /// Raw SAFI value from the wire.
    pub safi_raw: u8,
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
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the body length is not exactly 4.
    /// Unknown AFI/SAFI values and unknown subtypes are preserved.
    pub fn decode(buf: &mut impl Buf, body_len: usize) -> Result<Self, DecodeError> {
        if body_len != BODY_LEN {
            return Err(DecodeError::InvalidLength {
                length: u16::try_from(HEADER_LEN + body_len).unwrap_or(u16::MAX),
            });
        }
        if buf.remaining() < BODY_LEN {
            return Err(DecodeError::Incomplete {
                needed: BODY_LEN,
                available: buf.remaining(),
            });
        }

        let afi_raw = buf.get_u16();
        let subtype_raw = buf.get_u8();
        let safi_raw = buf.get_u8();

        Ok(Self {
            afi_raw,
            subtype_raw,
            safi_raw,
        })
    }

    /// Encode a complete ROUTE-REFRESH message (header + body) into a buffer.
    ///
    /// # Errors
    ///
    /// This encoding is infallible for valid values, but returns
    /// [`EncodeError`] for API consistency.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
        buf.put_slice(&MARKER);
        #[expect(clippy::cast_possible_truncation)]
        buf.put_u16(TOTAL_LEN as u16);
        buf.put_u8(message_type::ROUTE_REFRESH);
        buf.put_u16(self.afi_raw);
        buf.put_u8(self.subtype_raw);
        buf.put_u8(self.safi_raw);
        Ok(())
    }

    /// Total encoded size on the wire (header + body).
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        TOTAL_LEN
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

        match (self.afi(), self.safi()) {
            (Some(afi), Some(safi)) => {
                write!(
                    f,
                    "ROUTE-REFRESH subtype={subtype} AFI={afi:?} SAFI={safi:?}"
                )
            }
            _ => write!(
                f,
                "ROUTE-REFRESH subtype={subtype} AFI={} SAFI={}",
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
    fn reject_wrong_body_length() {
        let data: &[u8] = &[0, 1, 0, 1, 0xFF];
        let mut buf = Bytes::copy_from_slice(data);
        assert!(RouteRefreshMessage::decode(&mut buf, 5).is_err());
    }

    #[test]
    fn reject_body_length_three() {
        let data: &[u8] = &[0, 1, 0];
        let mut buf = Bytes::copy_from_slice(data);
        assert!(RouteRefreshMessage::decode(&mut buf, 3).is_err());
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
        };
        let s = format!("{msg}");
        assert!(s.contains("99"));
        assert!(s.contains("42"));
        assert!(s.contains("Unknown(7)"));
    }
}
