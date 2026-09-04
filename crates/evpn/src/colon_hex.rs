//! Operator text form of the EVPN identifiers that RFC 7432 carries as
//! raw octets.
//!
//! `rustbgpd_wire` implements `Display` for [`MacAddress`] and
//! [`EthernetSegmentIdentifier`] but no `FromStr`: the on-the-wire form
//! is raw bytes, not the colon-separated hex that operators type. The
//! configuration loader and the gRPC services both accept that text
//! form, and this module is the one parser they share, so an input
//! cannot load through one entry point and be refused by the other.
//!
//! The grammar is strict: exactly six (MAC) or ten (ESI) groups
//! separated by `:`, each group exactly two hex digits in either case,
//! and nothing else. A leading sign, a one- or three-digit group,
//! surrounding whitespace, and a trailing separator are all rejected.

use rustbgpd_wire::{EthernetSegmentIdentifier, MacAddress};

/// Why [`parse_mac_address`] or [`parse_esi`] refused an input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ColonHexParseError {
    /// The input did not split into the expected number of `:`-separated
    /// groups.
    #[error("expected {expected} colon-separated hex octets")]
    GroupCount {
        /// Number of groups the identifier requires.
        expected: usize,
    },
    /// A group was not exactly two characters wide.
    #[error("each octet must be exactly 2 hex digits")]
    OctetWidth,
    /// A group held something other than two hex digits.
    #[error("invalid hex octet")]
    InvalidHex,
}

/// Parse a MAC address from its `aa:bb:cc:dd:ee:ff` text form.
///
/// # Errors
///
/// Returns [`ColonHexParseError`] unless the input is exactly six
/// `:`-separated groups of exactly two hex digits.
pub fn parse_mac_address(raw: &str) -> Result<MacAddress, ColonHexParseError> {
    parse_octets(raw).map(MacAddress::new)
}

/// Parse an Ethernet Segment Identifier from its
/// `00:11:22:33:44:55:66:77:88:99` text form.
///
/// # Errors
///
/// Returns [`ColonHexParseError`] unless the input is exactly ten
/// `:`-separated groups of exactly two hex digits.
pub fn parse_esi(raw: &str) -> Result<EthernetSegmentIdentifier, ColonHexParseError> {
    parse_octets(raw).map(EthernetSegmentIdentifier::new)
}

fn parse_octets<const N: usize>(raw: &str) -> Result<[u8; N], ColonHexParseError> {
    let groups: Vec<&str> = raw.split(':').collect();
    if groups.len() != N {
        return Err(ColonHexParseError::GroupCount { expected: N });
    }
    let mut out = [0u8; N];
    for (slot, group) in out.iter_mut().zip(groups) {
        if group.len() != 2 {
            return Err(ColonHexParseError::OctetWidth);
        }
        // `u8::from_str_radix` accepts a leading `+`, so the digit check
        // has to be explicit for the grammar to be exactly two hex digits.
        if !group.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ColonHexParseError::InvalidHex);
        }
        *slot = u8::from_str_radix(group, 16).map_err(|_| ColonHexParseError::InvalidHex)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::ColonHexParseError::{GroupCount, InvalidHex, OctetWidth};
    use super::*;

    const MAC: &str = "aa:bb:cc:dd:ee:ff";
    const ESI: &str = "00:11:22:33:44:55:66:77:88:99";

    #[test]
    fn mac_accepts_strict_forms() {
        let expected = MacAddress::new([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(parse_mac_address(MAC), Ok(expected));
        assert_eq!(parse_mac_address("AA:BB:CC:DD:EE:FF"), Ok(expected));
        assert_eq!(parse_mac_address("aA:Bb:cC:Dd:eE:Ff"), Ok(expected));
        assert_eq!(
            parse_mac_address("00:00:00:00:00:00"),
            Ok(MacAddress::new([0; 6]))
        );
        assert_eq!(
            parse_mac_address("ff:ff:ff:ff:ff:ff"),
            Ok(MacAddress::new([0xff; 6]))
        );
        assert_eq!(parse_mac_address(MAC).unwrap().to_string(), MAC);
    }

    #[test]
    fn mac_rejects_loose_forms() {
        let cases = [
            ("aa:bb:cc:dd:ee", GroupCount { expected: 6 }),
            ("aa:bb:cc:dd:ee:ff:00", GroupCount { expected: 6 }),
            ("aa:bb:cc:dd:ee:ff:", GroupCount { expected: 6 }),
            ("", GroupCount { expected: 6 }),
            ("aabbccddeeff", GroupCount { expected: 6 }),
            ("aa-bb-cc-dd-ee-ff", GroupCount { expected: 6 }),
            ("2:0:0:0:0:1", OctetWidth),
            ("00f:00:00:00:00:01", OctetWidth),
            (" aa:bb:cc:dd:ee:ff", OctetWidth),
            ("aa:bb:cc:dd:ee:ff ", OctetWidth),
            ("+2:+0:+0:+0:+0:+1", InvalidHex),
            ("-2:00:00:00:00:01", InvalidHex),
            ("aa:bb:cc:dd:ee:gg", InvalidHex),
            ("aa:bb:cc:dd:ee: f", InvalidHex),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_mac_address(input), Err(expected), "{input:?}");
        }
    }

    #[test]
    fn esi_accepts_strict_forms() {
        let expected = EthernetSegmentIdentifier::new([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        ]);
        assert_eq!(parse_esi(ESI), Ok(expected));
        assert_eq!(
            parse_esi("0A:1B:2C:3D:4E:5F:6a:7b:8c:9d"),
            Ok(EthernetSegmentIdentifier::new([
                0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x6a, 0x7b, 0x8c, 0x9d,
            ]))
        );
        assert_eq!(
            parse_esi("00:00:00:00:00:00:00:00:00:00"),
            Ok(EthernetSegmentIdentifier::new([0; 10]))
        );
        assert_eq!(
            parse_esi("ff:ff:ff:ff:ff:ff:ff:ff:ff:ff"),
            Ok(EthernetSegmentIdentifier::new([0xff; 10]))
        );
        assert_eq!(parse_esi(ESI).unwrap().to_string(), ESI);
    }

    #[test]
    fn esi_rejects_loose_forms() {
        let cases = [
            ("00:11:22:33:44:55:66:77:88", GroupCount { expected: 10 }),
            (
                "00:11:22:33:44:55:66:77:88:99:aa",
                GroupCount { expected: 10 },
            ),
            (
                "00:11:22:33:44:55:66:77:88:99:",
                GroupCount { expected: 10 },
            ),
            ("", GroupCount { expected: 10 }),
            ("not-an-esi", GroupCount { expected: 10 }),
            ("0:11:22:33:44:55:66:77:88:99", OctetWidth),
            ("000:11:22:33:44:55:66:77:88:99", OctetWidth),
            (" 00:11:22:33:44:55:66:77:88:99", OctetWidth),
            ("00:11:22:33:44:55:66:77:88:99 ", OctetWidth),
            ("+0:11:22:33:44:55:66:77:88:99", InvalidHex),
            ("-0:11:22:33:44:55:66:77:88:99", InvalidHex),
            ("00:11:22:33:44:55:66:77:88:9g", InvalidHex),
        ];
        for (input, expected) in cases {
            assert_eq!(parse_esi(input), Err(expected), "{input:?}");
        }
    }
}
