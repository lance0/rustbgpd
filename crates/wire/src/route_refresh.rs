use bytes::{Buf, BufMut};

use crate::capability::{Afi, Safi};
use crate::constants::{HEADER_LEN, MARKER, message_type};
use crate::error::{DecodeError, EncodeError};

/// ROUTE-REFRESH message body length (AFI u16 + Reserved u8 + SAFI u8).
const BODY_LEN: usize = 4;

/// Total wire length of a ROUTE-REFRESH message (header + body).
const TOTAL_LEN: usize = HEADER_LEN + BODY_LEN;

/// BGP ROUTE-REFRESH message (RFC 2918).
///
/// Requests a peer to re-advertise its Adj-RIB-Out for the specified
/// address family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRefreshMessage {
    pub afi: Afi,
    pub safi: Safi,
}

impl RouteRefreshMessage {
    /// Decode a ROUTE-REFRESH message body from a buffer.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError`] if the body length is not exactly 4, or if
    /// the AFI/SAFI values are unrecognized.
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
        let _reserved = buf.get_u8();
        let safi_raw = buf.get_u8();

        let afi = Afi::from_u16(afi_raw).ok_or(DecodeError::MalformedOptionalParameter {
            offset: 0,
            detail: format!("unknown AFI {afi_raw} in ROUTE-REFRESH"),
        })?;
        let safi = Safi::from_u8(safi_raw).ok_or(DecodeError::MalformedOptionalParameter {
            offset: 2,
            detail: format!("unknown SAFI {safi_raw} in ROUTE-REFRESH"),
        })?;

        Ok(Self { afi, safi })
    }

    /// Encode a complete ROUTE-REFRESH message (header + body) into a buffer.
    ///
    /// # Errors
    ///
    /// This encoding is infallible for valid AFI/SAFI combinations, but
    /// returns [`EncodeError`] for API consistency.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
        // Header
        buf.put_slice(&MARKER);
        #[expect(clippy::cast_possible_truncation)]
        buf.put_u16(TOTAL_LEN as u16);
        buf.put_u8(message_type::ROUTE_REFRESH);
        // Body
        buf.put_u16(self.afi as u16);
        buf.put_u8(0); // reserved
        buf.put_u8(self.safi as u8);
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
        write!(f, "ROUTE-REFRESH AFI={:?} SAFI={:?}", self.afi, self.safi)
    }
}

#[cfg(test)]
mod tests {
    use bytes::{Bytes, BytesMut};

    use super::*;

    #[test]
    fn roundtrip_ipv4_unicast() {
        let msg = RouteRefreshMessage {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        };
        let mut buf = BytesMut::with_capacity(TOTAL_LEN);
        msg.encode(&mut buf).unwrap();
        assert_eq!(buf.len(), TOTAL_LEN);

        // Skip header for decode
        let mut bytes = buf.freeze();
        bytes.advance(HEADER_LEN);
        let decoded = RouteRefreshMessage::decode(&mut bytes, BODY_LEN).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn roundtrip_ipv6_unicast() {
        let msg = RouteRefreshMessage {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        };
        let mut buf = BytesMut::with_capacity(TOTAL_LEN);
        msg.encode(&mut buf).unwrap();

        let mut bytes = buf.freeze();
        bytes.advance(HEADER_LEN);
        let decoded = RouteRefreshMessage::decode(&mut bytes, BODY_LEN).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn reject_wrong_body_length() {
        let data: &[u8] = &[0, 1, 0, 1, 0xFF]; // 5 bytes
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
    fn reject_unknown_afi() {
        let data: &[u8] = &[0, 99, 0, 1]; // AFI=99
        let mut buf = Bytes::copy_from_slice(data);
        assert!(RouteRefreshMessage::decode(&mut buf, 4).is_err());
    }

    #[test]
    fn reject_unknown_safi() {
        let data: &[u8] = &[0, 1, 0, 99]; // SAFI=99
        let mut buf = Bytes::copy_from_slice(data);
        assert!(RouteRefreshMessage::decode(&mut buf, 4).is_err());
    }

    #[test]
    fn encoded_len_is_23() {
        let msg = RouteRefreshMessage {
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        };
        assert_eq!(msg.encoded_len(), 23);
    }

    #[test]
    fn display_format() {
        let msg = RouteRefreshMessage {
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        };
        let s = format!("{msg}");
        assert!(s.contains("Ipv6"));
        assert!(s.contains("Unicast"));
    }
}
