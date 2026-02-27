use std::net::Ipv4Addr;

use bytes::Bytes;

/// Origin attribute values per RFC 4271 §5.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

impl Origin {
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Igp),
            1 => Some(Self::Egp),
            2 => Some(Self::Incomplete),
            _ => None,
        }
    }
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Igp => write!(f, "IGP"),
            Self::Egp => write!(f, "EGP"),
            Self::Incomplete => write!(f, "INCOMPLETE"),
        }
    }
}

/// `AS_PATH` segment types per RFC 4271 §4.3.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsPathSegment {
    /// `AS_SET` — unordered set of ASNs.
    AsSet(Vec<u32>),
    /// `AS_SEQUENCE` — ordered sequence of ASNs.
    AsSequence(Vec<u32>),
}

/// `AS_PATH` attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsPath {
    pub segments: Vec<AsPathSegment>,
}

impl AsPath {
    /// Count the total number of ASNs in the path for best-path comparison.
    /// `AS_SET` counts as 1 regardless of size (RFC 4271 §9.1.2.2).
    #[must_use]
    pub fn len(&self) -> usize {
        self.segments
            .iter()
            .map(|seg| match seg {
                AsPathSegment::AsSequence(asns) => asns.len(),
                AsPathSegment::AsSet(_) => 1,
            })
            .sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }
}

/// A known path attribute or raw preserved bytes.
///
/// Known attributes are decoded into typed variants. Unknown attributes
/// are preserved as `RawAttribute` for pass-through with the Partial bit.
///
/// Type definitions are exported in M0. Decode logic is M1 scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathAttribute {
    Origin(Origin),
    AsPath(AsPath),
    NextHop(Ipv4Addr),
    LocalPref(u32),
    Med(u32),
    /// Unknown or unrecognized attribute, preserved for re-advertisement.
    Unknown(RawAttribute),
}

/// Raw attribute preserved for pass-through (RFC 4271 §5).
///
/// On re-advertisement, the Partial bit (0x20) is OR'd into `flags`.
/// All other flags and bytes are preserved unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAttribute {
    pub flags: u8,
    pub type_code: u8,
    pub data: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origin_from_u8_roundtrip() {
        assert_eq!(Origin::from_u8(0), Some(Origin::Igp));
        assert_eq!(Origin::from_u8(1), Some(Origin::Egp));
        assert_eq!(Origin::from_u8(2), Some(Origin::Incomplete));
        assert_eq!(Origin::from_u8(3), None);
    }

    #[test]
    fn origin_ordering() {
        assert!(Origin::Igp < Origin::Egp);
        assert!(Origin::Egp < Origin::Incomplete);
    }

    #[test]
    fn as_path_length_calculation() {
        let path = AsPath {
            segments: vec![
                AsPathSegment::AsSequence(vec![65001, 65002, 65003]),
                AsPathSegment::AsSet(vec![65004, 65005]),
            ],
        };
        // Sequence: 3 ASNs, Set: counts as 1 → total 4
        assert_eq!(path.len(), 4);
    }

    #[test]
    fn as_path_empty() {
        let path = AsPath { segments: vec![] };
        assert!(path.is_empty());
        assert_eq!(path.len(), 0);
    }
}
