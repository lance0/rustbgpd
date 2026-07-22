//! BGP-LS NLRI codec (RFC 9552).
//!
//! The daemon's ADR-0077 receive/API slice uses this module from
//! `MP_REACH_NLRI` / `MP_UNREACH_NLRI` dispatch while keeping BGP-LS objects
//! opaque. Reflection/export and local topology production are separate daemon
//! features, not wire-crate behavior.

use bytes::Bytes;
use std::fmt::Write as _;

use crate::error::{DecodeError, EncodeError};

/// BGP-LS AFI (RFC 9552 §5.2).
pub const BGP_LS_AFI: u16 = 16_388;
/// BGP-LS SAFI (RFC 9552 §5.2).
pub const BGP_LS_SAFI: u8 = 71;
/// BGP-LS VPN SAFI (RFC 9552 §5.2).
pub const BGP_LS_VPN_SAFI: u8 = 72;
/// BGP-LS VPN Route Distinguisher length in octets (RFC 9552 §5.2).
pub const BGP_LS_ROUTE_DISTINGUISHER_LEN: usize = 8;

const HEADER_LEN: usize = 4;
const KNOWN_NLRI_MIN_PAYLOAD_LEN: usize = 9;
const TLV_HEADER_LEN: usize = 4;

/// BGP-LS NLRI type values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum BgpLsNlriType {
    /// Node NLRI (type 1).
    Node,
    /// Link NLRI (type 2).
    Link,
    /// IPv4 Topology Prefix NLRI (type 3).
    Ipv4TopologyPrefix,
    /// IPv6 Topology Prefix NLRI (type 4).
    Ipv6TopologyPrefix,
    /// Unknown or future NLRI type, preserved opaquely.
    Unknown(u16),
}

impl BgpLsNlriType {
    /// Convert a raw 16-bit BGP-LS NLRI type into a typed value.
    #[must_use]
    pub fn from_u16(value: u16) -> Self {
        match value {
            1 => Self::Node,
            2 => Self::Link,
            3 => Self::Ipv4TopologyPrefix,
            4 => Self::Ipv6TopologyPrefix,
            other => Self::Unknown(other),
        }
    }

    /// Return the raw 16-bit BGP-LS NLRI type.
    #[must_use]
    pub fn as_u16(self) -> u16 {
        match self {
            Self::Node => 1,
            Self::Link => 2,
            Self::Ipv4TopologyPrefix => 3,
            Self::Ipv6TopologyPrefix => 4,
            Self::Unknown(value) => value,
        }
    }

    /// Return true for the four base NLRI types defined by RFC 9552.
    #[must_use]
    pub fn is_known(self) -> bool {
        !matches!(self, Self::Unknown(_))
    }
}

/// A single BGP-LS TLV.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct BgpLsTlv {
    /// TLV type code.
    pub type_code: u16,
    /// Raw TLV value bytes.
    pub value: Bytes,
}

impl BgpLsTlv {
    /// Construct a BGP-LS TLV.
    #[must_use]
    pub fn new(type_code: u16, value: Bytes) -> Self {
        Self { type_code, value }
    }
}

/// A byte-stable BGP-LS NLRI.
///
/// The `payload` field is the Link-State NLRI value after the outer type and
/// total-length fields. For BGP-LS VPN NLRIs, the route distinguisher is split
/// into `route_distinguisher` and excluded from `payload`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BgpLsNlri {
    /// NLRI type.
    pub nlri_type: BgpLsNlriType,
    /// Optional 8-byte route distinguisher for BGP-LS VPN SAFI 72.
    pub route_distinguisher: Option<[u8; BGP_LS_ROUTE_DISTINGUISHER_LEN]>,
    /// Raw Link-State NLRI payload bytes.
    pub payload: Bytes,
}

impl BgpLsNlri {
    /// Construct an NLRI after checking that it can be encoded.
    ///
    /// # Errors
    ///
    /// Returns `EncodeError` when the combined route distinguisher and payload
    /// length cannot fit in the 16-bit Total NLRI Length field.
    pub fn try_new(
        nlri_type: BgpLsNlriType,
        route_distinguisher: Option<[u8; BGP_LS_ROUTE_DISTINGUISHER_LEN]>,
        payload: Bytes,
    ) -> Result<Self, EncodeError> {
        let nlri = Self {
            nlri_type,
            route_distinguisher,
            payload,
        };
        nlri.validate_encoded_len()?;
        Ok(nlri)
    }

    /// Return this NLRI's route-key identity.
    #[must_use]
    pub fn key(&self) -> BgpLsNlriKey {
        BgpLsNlriKey {
            nlri_type: self.nlri_type,
            route_distinguisher: self.route_distinguisher,
            payload: self.payload.clone(),
        }
    }

    /// Return the BGP-LS Protocol-ID for known base NLRI types.
    #[must_use]
    pub fn protocol_id(&self) -> Option<u8> {
        if self.nlri_type.is_known() && self.payload.len() >= KNOWN_NLRI_MIN_PAYLOAD_LEN {
            Some(self.payload[0])
        } else {
            None
        }
    }

    /// Return the BGP-LS Instance Identifier for known base NLRI types.
    #[must_use]
    pub fn identifier(&self) -> Option<u64> {
        if self.nlri_type.is_known() && self.payload.len() >= KNOWN_NLRI_MIN_PAYLOAD_LEN {
            let mut bytes = [0_u8; 8];
            bytes.copy_from_slice(&self.payload[1..KNOWN_NLRI_MIN_PAYLOAD_LEN]);
            Some(u64::from_be_bytes(bytes))
        } else {
            None
        }
    }

    /// Return the descriptor TLV bytes for known base NLRI types.
    #[must_use]
    pub fn descriptor_bytes(&self) -> Option<&[u8]> {
        if self.nlri_type.is_known() && self.payload.len() >= KNOWN_NLRI_MIN_PAYLOAD_LEN {
            Some(&self.payload[KNOWN_NLRI_MIN_PAYLOAD_LEN..])
        } else {
            None
        }
    }

    /// Decode descriptor TLVs for known base NLRI types.
    ///
    /// Unknown NLRI types are intentionally opaque and return `None`.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError` if a known NLRI's descriptor TLV bytes are
    /// structurally truncated.
    pub fn descriptor_tlvs(&self) -> Result<Option<Vec<BgpLsTlv>>, DecodeError> {
        let Some(bytes) = self.descriptor_bytes() else {
            return Ok(None);
        };
        decode_bgpls_nlri_tlvs(bytes).map(Some)
    }

    fn total_len(&self) -> usize {
        self.payload.len()
            + self
                .route_distinguisher
                .map_or(0, |_| BGP_LS_ROUTE_DISTINGUISHER_LEN)
    }

    fn validate_encoded_len(&self) -> Result<(), EncodeError> {
        let total_len = self.total_len();
        if total_len > u16::MAX as usize {
            return Err(EncodeError::ValueOutOfRange {
                field: "BGP-LS NLRI total length",
                value: total_len.to_string(),
            });
        }
        Ok(())
    }
}

/// Opaque BGP-LS route-key identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BgpLsNlriKey {
    /// NLRI type.
    pub nlri_type: BgpLsNlriType,
    /// Optional 8-byte route distinguisher for BGP-LS VPN SAFI 72.
    pub route_distinguisher: Option<[u8; BGP_LS_ROUTE_DISTINGUISHER_LEN]>,
    /// Raw key payload bytes.
    pub payload: Bytes,
}

/// Decode one or more BGP-LS AFI 16388 / SAFI 71 NLRIs.
///
/// # Errors
///
/// Returns `DecodeError` if an NLRI header, known-NLRI payload, or known-NLRI
/// descriptor TLV is structurally truncated.
pub fn decode_bgpls_nlri(input: &[u8]) -> Result<Vec<BgpLsNlri>, DecodeError> {
    Ok(decode_bgpls_nlri_inner(input, false)?.0)
}

/// Like [`decode_bgpls_nlri`] but also returns the number of NLRIs discarded
/// for out-of-order descriptor TLVs, so the session layer can observe the
/// otherwise-silent RFC 9552 drop with peer context.
///
/// # Errors
///
/// Same fatal boundary as [`decode_bgpls_nlri`].
pub(crate) fn decode_bgpls_nlri_counted(
    input: &[u8],
) -> Result<(Vec<BgpLsNlri>, u32), DecodeError> {
    decode_bgpls_nlri_inner(input, false)
}

/// Decode one or more BGP-LS AFI 16388 / SAFI 72 VPN NLRIs.
///
/// # Errors
///
/// Returns `DecodeError` if an NLRI header, route distinguisher,
/// known-NLRI payload, or known-NLRI descriptor TLV is structurally truncated.
pub fn decode_bgpls_vpn_nlri(input: &[u8]) -> Result<Vec<BgpLsNlri>, DecodeError> {
    Ok(decode_bgpls_nlri_inner(input, true)?.0)
}

/// Like [`decode_bgpls_vpn_nlri`] but also returns the number of NLRIs
/// discarded for out-of-order descriptor TLVs (see [`decode_bgpls_nlri_counted`]).
///
/// # Errors
///
/// Same fatal boundary as [`decode_bgpls_vpn_nlri`].
pub(crate) fn decode_bgpls_vpn_nlri_counted(
    input: &[u8],
) -> Result<(Vec<BgpLsNlri>, u32), DecodeError> {
    decode_bgpls_nlri_inner(input, true)
}

/// Encode BGP-LS NLRIs into `out`.
///
/// NLRIs with `route_distinguisher = Some(_)` are encoded using the VPN shape
/// from RFC 9552 §5.2. The caller remains responsible for placing the bytes in
/// the matching SAFI; this module is not connected to MP-BGP dispatch.
///
/// # Errors
///
/// Returns `EncodeError` if any NLRI cannot fit in the 16-bit Total NLRI Length
/// field. On error, `out` is restored to its original length.
pub fn encode_bgpls_nlri(routes: &[BgpLsNlri], out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let original_len = out.len();
    for route in routes {
        if let Err(error) = encode_one_bgpls_nlri(route, out) {
            out.truncate(original_len);
            return Err(error);
        }
    }
    Ok(())
}

/// Decode a sequence of BGP-LS TLVs.
///
/// # Errors
///
/// Returns `DecodeError` if a TLV header or value is structurally truncated.
pub fn decode_bgpls_tlvs(input: &[u8]) -> Result<Vec<BgpLsTlv>, DecodeError> {
    let mut tlvs = Vec::new();
    visit_bgpls_tlvs(input, |type_code, value| {
        tlvs.push(BgpLsTlv {
            type_code,
            value: Bytes::copy_from_slice(value),
        });
    })?;
    Ok(tlvs)
}

/// Validate a sequence of BGP-LS TLV boundaries without retaining values.
///
/// # Errors
///
/// Returns `DecodeError` if a TLV header or value is structurally truncated.
pub(crate) fn validate_bgpls_tlv_framing(input: &[u8]) -> Result<(), DecodeError> {
    visit_bgpls_tlvs(input, |_, _| {})
}

fn visit_bgpls_tlvs(input: &[u8], mut visit: impl FnMut(u16, &[u8])) -> Result<(), DecodeError> {
    let mut offset = 0;
    while offset < input.len() {
        let remaining = input.len() - offset;
        if remaining < TLV_HEADER_LEN {
            return Err(malformed(format!(
                "BGP-LS TLV header truncated at offset {offset}: need {TLV_HEADER_LEN} bytes, have {remaining}"
            )));
        }

        let type_code = u16::from_be_bytes([input[offset], input[offset + 1]]);
        let value_len = u16::from_be_bytes([input[offset + 2], input[offset + 3]]) as usize;
        offset += TLV_HEADER_LEN;

        let remaining = input.len() - offset;
        if remaining < value_len {
            return Err(malformed(format!(
                "BGP-LS TLV {type_code} truncated at offset {offset}: need {value_len} value bytes, have {remaining}"
            )));
        }

        visit(type_code, &input[offset..offset + value_len]);
        offset += value_len;
    }
    Ok(())
}

/// Encode BGP-LS TLVs into `out`.
///
/// # Errors
///
/// Returns `EncodeError` if any TLV value cannot fit in the 16-bit Length
/// field. On error, `out` is restored to its original length.
pub fn encode_bgpls_tlvs(tlvs: &[BgpLsTlv], out: &mut Vec<u8>) -> Result<(), EncodeError> {
    let original_len = out.len();
    for tlv in tlvs {
        if tlv.value.len() > u16::MAX as usize {
            out.truncate(original_len);
            return Err(EncodeError::ValueOutOfRange {
                field: "BGP-LS TLV length",
                value: tlv.value.len().to_string(),
            });
        }
        let value_len =
            u16::try_from(tlv.value.len()).map_err(|_| EncodeError::ValueOutOfRange {
                field: "BGP-LS TLV length",
                value: tlv.value.len().to_string(),
            })?;
        out.extend_from_slice(&tlv.type_code.to_be_bytes());
        out.extend_from_slice(&value_len.to_be_bytes());
        out.extend_from_slice(&tlv.value);
    }
    Ok(())
}

/// Decode BGP-LS NLRIs, also returning the number of *recoverable* discards.
///
/// The `u32` is the count of known NLRIs dropped for out-of-order descriptor
/// TLVs (RFC 9552 fault management): the NLRI is isolated, the session survives.
/// Structurally fatal input still returns `Err`, so a discarded NLRI never
/// hides a framing/length error — the two paths stay distinct.
fn decode_bgpls_nlri_inner(input: &[u8], vpn: bool) -> Result<(Vec<BgpLsNlri>, u32), DecodeError> {
    let mut routes = Vec::new();
    let mut discarded = 0_u32;
    let mut offset = 0;
    while offset < input.len() {
        let remaining = input.len() - offset;
        if remaining < HEADER_LEN {
            return Err(malformed(format!(
                "BGP-LS NLRI header truncated at offset {offset}: need {HEADER_LEN} bytes, have {remaining}"
            )));
        }

        let type_raw = u16::from_be_bytes([input[offset], input[offset + 1]]);
        let total_len = u16::from_be_bytes([input[offset + 2], input[offset + 3]]) as usize;
        offset += HEADER_LEN;

        let remaining = input.len() - offset;
        if remaining < total_len {
            return Err(malformed(format!(
                "BGP-LS NLRI type {type_raw} truncated at offset {offset}: need {total_len} bytes, have {remaining}"
            )));
        }

        let value = &input[offset..offset + total_len];
        let (route_distinguisher, payload) = split_bgpls_value(value, vpn, type_raw, offset)?;
        let nlri_type = BgpLsNlriType::from_u16(type_raw);
        if validate_bgpls_payload(nlri_type, payload, offset)? {
            routes.push(BgpLsNlri {
                nlri_type,
                route_distinguisher,
                payload: Bytes::copy_from_slice(payload),
            });
        } else {
            // Recoverable RFC 9552 fault: out-of-order descriptor TLVs.
            // Drop just this NLRI, keep the session, and surface the count.
            discarded = discarded.saturating_add(1);
        }
        offset += total_len;
    }
    Ok((routes, discarded))
}

fn split_bgpls_value(
    value: &[u8],
    vpn: bool,
    type_raw: u16,
    offset: usize,
) -> Result<(Option<[u8; BGP_LS_ROUTE_DISTINGUISHER_LEN]>, &[u8]), DecodeError> {
    if !vpn {
        return Ok((None, value));
    }
    if value.len() < BGP_LS_ROUTE_DISTINGUISHER_LEN {
        return Err(malformed(format!(
            "BGP-LS VPN NLRI type {type_raw} route distinguisher truncated at offset {offset}: need {BGP_LS_ROUTE_DISTINGUISHER_LEN} bytes, have {}",
            value.len()
        )));
    }

    let mut rd = [0_u8; BGP_LS_ROUTE_DISTINGUISHER_LEN];
    rd.copy_from_slice(&value[..BGP_LS_ROUTE_DISTINGUISHER_LEN]);
    Ok((Some(rd), &value[BGP_LS_ROUTE_DISTINGUISHER_LEN..]))
}

fn validate_bgpls_payload(
    nlri_type: BgpLsNlriType,
    payload: &[u8],
    offset: usize,
) -> Result<bool, DecodeError> {
    if !nlri_type.is_known() {
        return Ok(true);
    }
    if payload.len() < KNOWN_NLRI_MIN_PAYLOAD_LEN {
        return Err(malformed(format!(
            "BGP-LS {:?} payload truncated at offset {offset}: need at least {KNOWN_NLRI_MIN_PAYLOAD_LEN} bytes, have {}",
            nlri_type,
            payload.len()
        )));
    }
    let tlvs = decode_bgpls_tlvs(&payload[KNOWN_NLRI_MIN_PAYLOAD_LEN..])?;
    Ok(bgpls_nlri_tlv_order_violation(&tlvs).is_none())
}

fn decode_bgpls_nlri_tlvs(input: &[u8]) -> Result<Vec<BgpLsTlv>, DecodeError> {
    let tlvs = decode_bgpls_tlvs(input)?;
    if let Some((left, right)) = bgpls_nlri_tlv_order_violation(&tlvs) {
        return Err(malformed(format!(
            "BGP-LS NLRI TLVs out of canonical order: {} before {}",
            describe_bgpls_tlv_for_order(left),
            describe_bgpls_tlv_for_order(right)
        )));
    }
    Ok(tlvs)
}

fn bgpls_nlri_tlv_order_violation(tlvs: &[BgpLsTlv]) -> Option<(&BgpLsTlv, &BgpLsTlv)> {
    for window in tlvs.windows(2) {
        if !bgpls_nlri_tlv_le(&window[0], &window[1]) {
            return Some((&window[0], &window[1]));
        }
    }
    None
}

fn describe_bgpls_tlv_for_order(tlv: &BgpLsTlv) -> String {
    let mut value_hex = String::new();
    for byte in tlv.value.iter().take(8) {
        write!(&mut value_hex, "{byte:02x}").expect("writing to String cannot fail");
    }
    if tlv.value.len() > 8 {
        value_hex.push_str("...");
    }
    format!(
        "type {} len {} value 0x{}",
        tlv.type_code,
        tlv.value.len(),
        value_hex
    )
}

fn bgpls_nlri_tlv_le(left: &BgpLsTlv, right: &BgpLsTlv) -> bool {
    match left.type_code.cmp(&right.type_code) {
        std::cmp::Ordering::Less => true,
        std::cmp::Ordering::Greater => false,
        std::cmp::Ordering::Equal => match left.value.len().cmp(&right.value.len()) {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => left.value.as_ref() <= right.value.as_ref(),
        },
    }
}

fn encode_one_bgpls_nlri(route: &BgpLsNlri, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    route.validate_encoded_len()?;
    let total_len = u16::try_from(route.total_len()).map_err(|_| EncodeError::ValueOutOfRange {
        field: "BGP-LS NLRI total length",
        value: route.total_len().to_string(),
    })?;
    out.extend_from_slice(&route.nlri_type.as_u16().to_be_bytes());
    out.extend_from_slice(&total_len.to_be_bytes());
    if let Some(rd) = route.route_distinguisher {
        out.extend_from_slice(&rd);
    }
    out.extend_from_slice(&route.payload);
    Ok(())
}

fn malformed(detail: String) -> DecodeError {
    DecodeError::MalformedField {
        message_type: "UPDATE",
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_payload() -> Bytes {
        let mut payload = Vec::new();
        payload.push(2); // IS-IS Level 2
        payload.extend_from_slice(&42_u64.to_be_bytes());
        encode_bgpls_tlvs(
            &[
                BgpLsTlv::new(256, Bytes::from_static(&[0, 0, 253, 232])),
                BgpLsTlv::new(515, Bytes::from_static(&[0x03, 0x00, 0x00, 0x01])),
            ],
            &mut payload,
        )
        .expect("fixture TLVs encode");
        Bytes::from(payload)
    }

    fn unordered_node_payload() -> Bytes {
        let mut payload = Vec::new();
        payload.push(3);
        payload.extend_from_slice(&7_u64.to_be_bytes());
        encode_bgpls_tlvs(
            &[
                BgpLsTlv::new(515, Bytes::from_static(&[1])),
                BgpLsTlv::new(256, Bytes::from_static(&[1])),
            ],
            &mut payload,
        )
        .expect("fixture TLVs encode");
        Bytes::from(payload)
    }

    #[test]
    fn bgpls_constants_match_rfc9552() {
        assert_eq!(BGP_LS_AFI, 16_388);
        assert_eq!(BGP_LS_SAFI, 71);
        assert_eq!(BGP_LS_VPN_SAFI, 72);
    }

    #[test]
    fn decode_known_node_nlri_with_tlvs() {
        let route = BgpLsNlri::try_new(BgpLsNlriType::Node, None, node_payload())
            .expect("fixture route encodes");
        let mut bytes = Vec::new();
        encode_bgpls_nlri(std::slice::from_ref(&route), &mut bytes).expect("fixture NLRI encodes");

        let decoded = decode_bgpls_nlri(&bytes).expect("fixture NLRI decodes");
        assert_eq!(decoded, vec![route]);
        assert_eq!(decoded[0].protocol_id(), Some(2));
        assert_eq!(decoded[0].identifier(), Some(42));

        let tlvs = decoded[0]
            .descriptor_tlvs()
            .expect("descriptor TLVs parse")
            .expect("known NLRI has descriptors");
        assert_eq!(tlvs.len(), 2);
        assert_eq!(tlvs[0].type_code, 256);
        assert_eq!(tlvs[0].value.as_ref(), &[0, 0, 253, 232]);
        assert_eq!(tlvs[1].type_code, 515);
    }

    #[test]
    fn unknown_nlri_type_roundtrips_opaque_payload() {
        let payload = Bytes::from_static(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        let route = BgpLsNlri::try_new(BgpLsNlriType::Unknown(65_000), None, payload)
            .expect("fixture route encodes");
        let mut bytes = Vec::new();
        encode_bgpls_nlri(std::slice::from_ref(&route), &mut bytes).expect("fixture NLRI encodes");

        let decoded = decode_bgpls_nlri(&bytes).expect("unknown NLRI decodes opaquely");
        assert_eq!(decoded, vec![route]);
        assert_eq!(decoded[0].protocol_id(), None);
        assert!(
            decoded[0]
                .descriptor_tlvs()
                .expect("unknown NLRI remains opaque")
                .is_none()
        );
    }

    #[test]
    fn vpn_nlri_roundtrips_route_distinguisher() {
        let rd = [0x00, 0x00, 0xfd, 0xe8, 0x00, 0x00, 0x00, 0x2a];
        let route = BgpLsNlri::try_new(BgpLsNlriType::Ipv4TopologyPrefix, Some(rd), node_payload())
            .expect("fixture route encodes");
        let mut bytes = Vec::new();
        encode_bgpls_nlri(std::slice::from_ref(&route), &mut bytes).expect("fixture NLRI encodes");

        let decoded = decode_bgpls_vpn_nlri(&bytes).expect("fixture VPN NLRI decodes");
        assert_eq!(decoded, vec![route]);
        assert_eq!(decoded[0].route_distinguisher, Some(rd));
        assert_eq!(decoded[0].protocol_id(), Some(2));
    }

    #[test]
    fn multiple_nlri_roundtrip_preserves_order() {
        let routes = vec![
            BgpLsNlri::try_new(BgpLsNlriType::Node, None, node_payload())
                .expect("node route encodes"),
            BgpLsNlri::try_new(
                BgpLsNlriType::Unknown(65_001),
                None,
                Bytes::from_static(&[1, 2, 3]),
            )
            .expect("unknown route encodes"),
        ];
        let mut bytes = Vec::new();
        encode_bgpls_nlri(&routes, &mut bytes).expect("routes encode");

        let decoded = decode_bgpls_nlri(&bytes).expect("routes decode");
        assert_eq!(decoded, routes);
    }

    #[test]
    fn truncated_nlri_header_errors() {
        let err = decode_bgpls_nlri(&[0, 1, 0]).expect_err("short header must fail");
        assert!(err.to_string().contains("NLRI header truncated"));
    }

    #[test]
    fn truncated_nlri_value_errors() {
        let bytes = [0, 1, 0, 10, 0, 1, 2];
        let err = decode_bgpls_nlri(&bytes).expect_err("short value must fail");
        assert!(err.to_string().contains("NLRI type 1 truncated"));
    }

    #[test]
    fn truncated_known_payload_errors() {
        let bytes = [0, 1, 0, 3, 1, 2, 3];
        let err = decode_bgpls_nlri(&bytes).expect_err("short known payload must fail");
        assert!(err.to_string().contains("Node payload truncated"));
    }

    #[test]
    fn truncated_vpn_route_distinguisher_errors() {
        let bytes = [0, 1, 0, 4, 1, 2, 3, 4];
        let err = decode_bgpls_vpn_nlri(&bytes).expect_err("short RD must fail");
        assert!(err.to_string().contains("route distinguisher truncated"));
    }

    #[test]
    fn truncated_tlv_header_errors() {
        let mut payload = Vec::new();
        payload.push(3);
        payload.extend_from_slice(&7_u64.to_be_bytes());
        payload.extend_from_slice(&[0, 1, 0]);
        let route =
            BgpLsNlri::try_new(BgpLsNlriType::Link, None, Bytes::from(payload)).expect("fits");
        let mut bytes = Vec::new();
        encode_bgpls_nlri(&[route], &mut bytes).expect("encodes");

        let err = decode_bgpls_nlri(&bytes).expect_err("truncated TLV header must fail");
        assert!(err.to_string().contains("TLV header truncated"));
    }

    #[test]
    fn truncated_tlv_value_errors() {
        let mut payload = Vec::new();
        payload.push(3);
        payload.extend_from_slice(&7_u64.to_be_bytes());
        payload.extend_from_slice(&[0, 1, 0, 4, 0xaa]);
        let route =
            BgpLsNlri::try_new(BgpLsNlriType::Link, None, Bytes::from(payload)).expect("fits");
        let mut bytes = Vec::new();
        encode_bgpls_nlri(&[route], &mut bytes).expect("encodes");

        let err = decode_bgpls_nlri(&bytes).expect_err("truncated TLV value must fail");
        assert!(err.to_string().contains("TLV 1 truncated"));
    }

    #[test]
    fn unordered_known_nlri_tlvs_are_discarded() {
        let route =
            BgpLsNlri::try_new(BgpLsNlriType::Node, None, unordered_node_payload()).expect("fits");
        let mut bytes = Vec::new();
        encode_bgpls_nlri(&[route], &mut bytes).expect("encodes");

        let decoded = decode_bgpls_nlri(&bytes).expect("unordered NLRI is isolatable");
        assert!(
            decoded.is_empty(),
            "unordered descriptor TLVs must discard the NLRI without resetting the session"
        );
    }

    #[test]
    fn unordered_known_nlri_tlvs_discard_only_that_nlri() {
        let bad = BgpLsNlri::try_new(BgpLsNlriType::Node, None, unordered_node_payload())
            .expect("bad fixture fits");
        let good = BgpLsNlri::try_new(BgpLsNlriType::Node, None, node_payload())
            .expect("good fixture fits");
        let mut bytes = Vec::new();
        encode_bgpls_nlri(&[bad, good.clone()], &mut bytes).expect("encodes");

        let decoded = decode_bgpls_nlri(&bytes).expect("batch decode survives one bad NLRI");
        assert_eq!(decoded, vec![good]);
    }

    #[test]
    fn counted_decode_reports_recoverable_discards() {
        let bad = BgpLsNlri::try_new(BgpLsNlriType::Node, None, unordered_node_payload())
            .expect("bad fixture fits");
        let good = BgpLsNlri::try_new(BgpLsNlriType::Node, None, node_payload())
            .expect("good fixture fits");
        let mut bytes = Vec::new();
        encode_bgpls_nlri(&[bad, good.clone()], &mut bytes).expect("encodes");

        let (decoded, discarded) =
            decode_bgpls_nlri_counted(&bytes).expect("batch decode survives one bad NLRI");
        assert_eq!(decoded, vec![good], "only the well-ordered NLRI survives");
        assert_eq!(
            discarded, 1,
            "the out-of-order NLRI is counted as discarded"
        );
    }

    #[test]
    fn counted_decode_does_not_count_fatal_errors() {
        // A structurally truncated known payload is fatal (session-resetting):
        // it must surface as Err, never as a recoverable discard count.
        let bytes = [0, 1, 0, 3, 1, 2, 3];
        decode_bgpls_nlri_counted(&bytes).expect_err("truncation stays fatal");
    }

    #[test]
    fn public_tlv_decoder_is_syntax_only_for_bgpls_attributes() {
        let mut bytes = Vec::new();
        encode_bgpls_tlvs(
            &[
                BgpLsTlv::new(515, Bytes::from_static(&[1])),
                BgpLsTlv::new(256, Bytes::from_static(&[1])),
            ],
            &mut bytes,
        )
        .expect("fixture TLVs encode");

        let tlvs = decode_bgpls_tlvs(&bytes).expect("standalone TLV decode is syntax-only");
        assert_eq!(tlvs[0].type_code, 515);
        assert_eq!(tlvs[1].type_code, 256);
    }

    #[test]
    fn descriptor_tlv_order_error_names_offending_pair() {
        let mut bytes = Vec::new();
        encode_bgpls_tlvs(
            &[
                BgpLsTlv::new(515, Bytes::from_static(&[1])),
                BgpLsTlv::new(256, Bytes::from_static(&[1])),
            ],
            &mut bytes,
        )
        .expect("fixture TLVs encode");

        let err = decode_bgpls_nlri_tlvs(&bytes).expect_err("unordered descriptors fail");
        assert!(
            err.to_string()
                .contains("type 515 len 1 value 0x01 before type 256 len 1 value 0x01")
        );
    }

    #[test]
    fn descriptor_tlv_order_error_disambiguates_equal_types() {
        let mut bytes = Vec::new();
        encode_bgpls_tlvs(
            &[
                BgpLsTlv::new(256, Bytes::from_static(&[2])),
                BgpLsTlv::new(256, Bytes::from_static(&[1])),
            ],
            &mut bytes,
        )
        .expect("fixture TLVs encode");

        let err = decode_bgpls_nlri_tlvs(&bytes).expect_err("unordered descriptors fail");
        assert!(
            err.to_string()
                .contains("type 256 len 1 value 0x02 before type 256 len 1 value 0x01")
        );
    }

    #[test]
    fn encode_oversized_nlri_restores_buffer() {
        let route = BgpLsNlri {
            nlri_type: BgpLsNlriType::Node,
            route_distinguisher: Some([0; BGP_LS_ROUTE_DISTINGUISHER_LEN]),
            payload: Bytes::from(vec![0; u16::MAX as usize]),
        };
        let mut bytes = vec![0xaa, 0xbb];
        let err = encode_bgpls_nlri(&[route], &mut bytes).expect_err("oversized route must fail");
        assert_eq!(
            err,
            EncodeError::ValueOutOfRange {
                field: "BGP-LS NLRI total length",
                value: (u16::MAX as usize + BGP_LS_ROUTE_DISTINGUISHER_LEN).to_string()
            }
        );
        assert_eq!(bytes, vec![0xaa, 0xbb]);
    }

    #[test]
    fn encode_oversized_tlv_restores_buffer() {
        let tlv = BgpLsTlv::new(1, Bytes::from(vec![0; u16::MAX as usize + 1]));
        let mut bytes = vec![0xaa, 0xbb];
        let err = encode_bgpls_tlvs(&[tlv], &mut bytes).expect_err("oversized TLV must fail");
        assert_eq!(
            err,
            EncodeError::ValueOutOfRange {
                field: "BGP-LS TLV length",
                value: (u16::MAX as usize + 1).to_string()
            }
        );
        assert_eq!(bytes, vec![0xaa, 0xbb]);
    }

    #[test]
    fn key_uses_opaque_payload_identity() {
        let route = BgpLsNlri::try_new(
            BgpLsNlriType::Unknown(6),
            Some([1, 2, 3, 4, 5, 6, 7, 8]),
            Bytes::from_static(&[9, 10, 11]),
        )
        .expect("fixture route encodes");

        let key = route.key();
        assert_eq!(key.nlri_type, BgpLsNlriType::Unknown(6));
        assert_eq!(key.route_distinguisher, Some([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(key.payload.as_ref(), &[9, 10, 11]);
    }
}
