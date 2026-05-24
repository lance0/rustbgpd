//! BFD control-packet codec (RFC 5880 §4.1, mandatory section).
//!
//! Only the 24-byte mandatory control section is supported — authentication
//! (the optional trailing section) is out of scope, so packets with the `A`
//! bit set are decoded structurally and left for the session layer to discard.

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::DecodeError;
use crate::state::SessionState;

/// Length of the mandatory BFD control packet section, in bytes (RFC 5880 §4.1).
pub const CONTROL_PACKET_LEN: u8 = 24;

/// BFD diagnostic code (RFC 5880 §4.1, 5-bit field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Diagnostic {
    /// No diagnostic (0).
    None,
    /// Control detection time expired (1).
    ControlDetectionTimeExpired,
    /// Echo function failed (2).
    EchoFailed,
    /// Neighbor signaled session down (3).
    NeighborSignaledDown,
    /// Forwarding plane reset (4).
    ForwardingPlaneReset,
    /// Path down (5).
    PathDown,
    /// Concatenated path down (6).
    ConcatenatedPathDown,
    /// Administratively down (7).
    AdministrativelyDown,
    /// Reverse concatenated path down (8).
    ReverseConcatenatedPathDown,
    /// A reserved / unassigned diagnostic value (9..=31).
    Reserved(u8),
}

impl Diagnostic {
    /// The 5-bit wire value.
    #[must_use]
    pub fn to_wire(self) -> u8 {
        match self {
            Diagnostic::None => 0,
            Diagnostic::ControlDetectionTimeExpired => 1,
            Diagnostic::EchoFailed => 2,
            Diagnostic::NeighborSignaledDown => 3,
            Diagnostic::ForwardingPlaneReset => 4,
            Diagnostic::PathDown => 5,
            Diagnostic::ConcatenatedPathDown => 6,
            Diagnostic::AdministrativelyDown => 7,
            Diagnostic::ReverseConcatenatedPathDown => 8,
            Diagnostic::Reserved(v) => v & 0x1f,
        }
    }

    /// Decode the 5-bit wire value. Total — unknown values map to `Reserved`.
    #[must_use]
    pub fn from_wire(value: u8) -> Diagnostic {
        match value & 0x1f {
            0 => Diagnostic::None,
            1 => Diagnostic::ControlDetectionTimeExpired,
            2 => Diagnostic::EchoFailed,
            3 => Diagnostic::NeighborSignaledDown,
            4 => Diagnostic::ForwardingPlaneReset,
            5 => Diagnostic::PathDown,
            6 => Diagnostic::ConcatenatedPathDown,
            7 => Diagnostic::AdministrativelyDown,
            8 => Diagnostic::ReverseConcatenatedPathDown,
            other => Diagnostic::Reserved(other),
        }
    }
}

/// A decoded / to-be-encoded BFD control packet (mandatory section).
///
/// Interval fields are in **microseconds** on the wire (RFC 5880 §4.1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "these are the literal RFC 5880 §4.1 flag bits (P/F/C/A/D/M)"
)]
pub struct ControlPacket {
    /// Diagnostic code describing the last session-state change.
    pub diagnostic: Diagnostic,
    /// Sender's session state.
    pub state: SessionState,
    /// Poll bit (`P`) — the sender requests an immediate `Final` response.
    pub poll: bool,
    /// Final bit (`F`) — response to a received `Poll`.
    pub final_bit: bool,
    /// Control Plane Independent bit (`C`).
    pub control_plane_independent: bool,
    /// Authentication Present bit (`A`). Always `false` when this crate emits.
    pub auth_present: bool,
    /// Demand bit (`D`).
    pub demand: bool,
    /// Multipoint bit (`M`). Always `false` (point-to-point only).
    pub multipoint: bool,
    /// Detection time multiplier (non-zero).
    pub detect_mult: u8,
    /// Sender's discriminator (non-zero).
    pub my_discriminator: u32,
    /// Discriminator the sender believes is the receiver's (0 until learned).
    pub your_discriminator: u32,
    /// Sender's desired minimum transmit interval (microseconds).
    pub desired_min_tx_interval: u32,
    /// Sender's required minimum receive interval (microseconds).
    pub required_min_rx_interval: u32,
    /// Sender's required minimum echo receive interval (microseconds).
    pub required_min_echo_rx_interval: u32,
}

impl ControlPacket {
    /// Encode the mandatory 24-byte control section.
    ///
    /// This is a faithful codec: it serializes the struct verbatim (including
    /// the `auth_present` / `multipoint` flags and any zero `detect_mult` /
    /// `my_discriminator`), which lets tests round-trip and construct
    /// deliberately-invalid inputs for [`ControlPacket::decode`]. Validity is
    /// enforced on the *receive* side by `decode`, and on the *emit* side by the
    /// session, which only ever builds packets with `auth_present`/`multipoint`
    /// clear and non-zero discriminator/detect-mult.
    #[must_use]
    pub fn encode(&self) -> Bytes {
        let mut buf = BytesMut::with_capacity(CONTROL_PACKET_LEN as usize);
        // Byte 0: Version (1) in the high 3 bits, Diagnostic in the low 5.
        buf.put_u8((1 << 5) | self.diagnostic.to_wire());
        // Byte 1: State (2 bits) then P F C A D M.
        let mut flags = self.state.to_wire() << 6;
        if self.poll {
            flags |= 0x20;
        }
        if self.final_bit {
            flags |= 0x10;
        }
        if self.control_plane_independent {
            flags |= 0x08;
        }
        if self.auth_present {
            flags |= 0x04;
        }
        if self.demand {
            flags |= 0x02;
        }
        if self.multipoint {
            flags |= 0x01;
        }
        buf.put_u8(flags);
        buf.put_u8(self.detect_mult);
        buf.put_u8(CONTROL_PACKET_LEN);
        buf.put_u32(self.my_discriminator);
        buf.put_u32(self.your_discriminator);
        buf.put_u32(self.desired_min_tx_interval);
        buf.put_u32(self.required_min_rx_interval);
        buf.put_u32(self.required_min_echo_rx_interval);
        buf.freeze()
    }

    /// Decode a BFD control packet, enforcing the RFC 5880 §6.8.6 structural
    /// "MUST be discarded" rules (version, length, zero detect-mult, zero
    /// my-discriminator, multipoint).
    ///
    /// # Errors
    /// Returns [`DecodeError`] for any malformed or must-discard packet.
    pub fn decode(buf: &[u8]) -> Result<ControlPacket, DecodeError> {
        if buf.len() < CONTROL_PACKET_LEN as usize {
            return Err(DecodeError::Incomplete {
                needed: CONTROL_PACKET_LEN as usize,
                available: buf.len(),
            });
        }
        let version = buf[0] >> 5;
        if version != 1 {
            return Err(DecodeError::UnsupportedVersion { version });
        }
        let multipoint = buf[1] & 0x01 != 0;
        if multipoint {
            return Err(DecodeError::MultipointSet);
        }
        let detect_mult = buf[2];
        if detect_mult == 0 {
            return Err(DecodeError::ZeroDetectMult);
        }
        let auth_present = buf[1] & 0x04 != 0;
        let length = buf[3];
        // With no authentication the length is exactly 24; with auth it may be
        // longer (the trailing section is ignored here). Either way it must fit.
        if !auth_present && length != CONTROL_PACKET_LEN {
            return Err(DecodeError::InvalidLength {
                length,
                available: buf.len(),
            });
        }
        if (length as usize) < CONTROL_PACKET_LEN as usize || length as usize > buf.len() {
            return Err(DecodeError::InvalidLength {
                length,
                available: buf.len(),
            });
        }
        let my_discriminator = be_u32(buf, 4);
        if my_discriminator == 0 {
            return Err(DecodeError::ZeroMyDiscriminator);
        }
        Ok(ControlPacket {
            diagnostic: Diagnostic::from_wire(buf[0] & 0x1f),
            state: SessionState::from_wire(buf[1] >> 6),
            poll: buf[1] & 0x20 != 0,
            final_bit: buf[1] & 0x10 != 0,
            control_plane_independent: buf[1] & 0x08 != 0,
            auth_present,
            demand: buf[1] & 0x02 != 0,
            multipoint,
            detect_mult,
            my_discriminator,
            your_discriminator: be_u32(buf, 8),
            desired_min_tx_interval: be_u32(buf, 12),
            required_min_rx_interval: be_u32(buf, 16),
            required_min_echo_rx_interval: be_u32(buf, 20),
        })
    }
}

/// Read a big-endian `u32` at `offset`. Caller guarantees `buf.len() >= offset + 4`.
fn be_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ControlPacket {
        ControlPacket {
            diagnostic: Diagnostic::NeighborSignaledDown,
            state: SessionState::Up,
            poll: true,
            final_bit: false,
            control_plane_independent: false,
            auth_present: false,
            demand: false,
            multipoint: false,
            detect_mult: 3,
            my_discriminator: 0x1122_3344,
            your_discriminator: 0x5566_7788,
            desired_min_tx_interval: 300_000,
            required_min_rx_interval: 300_000,
            required_min_echo_rx_interval: 0,
        }
    }

    #[test]
    fn roundtrip_preserves_all_fields() {
        let pkt = sample();
        let bytes = pkt.encode();
        assert_eq!(bytes.len(), CONTROL_PACKET_LEN as usize);
        assert_eq!(ControlPacket::decode(&bytes).unwrap(), pkt);
    }

    #[test]
    fn encodes_version_one_and_length_24() {
        let bytes = sample().encode();
        assert_eq!(bytes[0] >> 5, 1, "version must be 1");
        assert_eq!(bytes[3], CONTROL_PACKET_LEN, "length field must be 24");
    }

    #[test]
    fn flag_bits_map_to_the_right_positions() {
        let mut pkt = sample();
        pkt.poll = false;
        pkt.final_bit = true;
        pkt.demand = true;
        let bytes = pkt.encode();
        // Sta=Up(3) in bits 7-6, F in bit 4, D in bit 1.
        assert_eq!(bytes[1] >> 6, 3);
        assert_eq!(bytes[1] & 0x20, 0, "poll clear");
        assert_eq!(bytes[1] & 0x10, 0x10, "final set");
        assert_eq!(bytes[1] & 0x02, 0x02, "demand set");
    }

    #[test]
    fn rejects_short_buffer() {
        assert!(matches!(
            ControlPacket::decode(&[0u8; 10]),
            Err(DecodeError::Incomplete {
                needed: 24,
                available: 10
            })
        ));
    }

    #[test]
    fn rejects_bad_version() {
        let mut bytes = sample().encode().to_vec();
        bytes[0] = 2 << 5; // version 2
        assert!(matches!(
            ControlPacket::decode(&bytes),
            Err(DecodeError::UnsupportedVersion { version: 2 })
        ));
    }

    #[test]
    fn rejects_zero_detect_mult_and_zero_my_discriminator_and_multipoint() {
        let mut z = sample();
        z.detect_mult = 0;
        assert!(matches!(
            ControlPacket::decode(&z.encode()),
            Err(DecodeError::ZeroDetectMult)
        ));

        let mut m = sample();
        m.my_discriminator = 0;
        assert!(matches!(
            ControlPacket::decode(&m.encode()),
            Err(DecodeError::ZeroMyDiscriminator)
        ));

        let mut mp = sample();
        mp.multipoint = true;
        assert!(matches!(
            ControlPacket::decode(&mp.encode()),
            Err(DecodeError::MultipointSet)
        ));
    }

    #[test]
    fn rejects_wrong_length_without_auth() {
        let mut bytes = sample().encode().to_vec();
        bytes[3] = 36; // claim auth-sized length with A clear
        assert!(matches!(
            ControlPacket::decode(&bytes),
            Err(DecodeError::InvalidLength { length: 36, .. })
        ));
    }
}
