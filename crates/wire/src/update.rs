use crate::attribute::PathAttribute;
use crate::constants::{HEADER_LEN, MAX_MESSAGE_LEN};
use crate::error::{DecodeError, EncodeError};
use crate::header::{BgpHeader, MessageType};
use crate::nlri::{Ipv4NlriEntry, Ipv4Prefix};
use crate::{Afi, Safi};
use bytes::{Buf, BufMut, Bytes};
/// How IPv4 unicast NLRI should be encoded in an outbound UPDATE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv4UnicastMode {
    /// Encode IPv4 announcements/withdrawals in the legacy body NLRI fields.
    Body,
    /// Encode IPv4 announcements/withdrawals in `MP_REACH_NLRI` /
    /// `MP_UNREACH_NLRI` attributes instead of the body fields.
    MpReach,
}
/// A decoded BGP UPDATE message (RFC 4271 §4.3).
///
/// Stores the three variable-length sections as raw `Bytes`.
/// Call [`parse()`](Self::parse) to decode NLRI and path attributes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateMessage {
    /// Raw withdrawn routes (NLRI encoding).
    pub withdrawn_routes: Bytes,
    /// Raw path attributes.
    pub path_attributes: Bytes,
    /// Raw Network Layer Reachability Information.
    pub nlri: Bytes,
}
/// A fully parsed UPDATE message with decoded prefixes and attributes.
///
/// Uses [`Ipv4NlriEntry`] to carry Add-Path path IDs alongside each prefix.
/// For non-Add-Path peers, `path_id` is always 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedUpdate {
    /// Withdrawn IPv4 NLRI entries.
    pub withdrawn: Vec<Ipv4NlriEntry>,
    /// Decoded path attributes.
    pub attributes: Vec<PathAttribute>,
    /// Announced IPv4 NLRI entries.
    pub announced: Vec<Ipv4NlriEntry>,
    /// Count of known BGP-LS NLRIs discarded during decode for out-of-order
    /// descriptor TLVs (RFC 9552 fault management): the affected NLRI is
    /// isolated, the session survives. Fatal framing errors are not counted
    /// here — they abort the decode. Lets the session observe the otherwise
    /// silent drop with peer context.
    pub bgpls_nlri_discarded: u32,
}
/// A parsed UPDATE from [`UpdateMessage::parse_revised`]: the cleanly decoded
/// parts plus the malformed attributes recovered per RFC 7606.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisedParsedUpdate {
    /// The parsed UPDATE. A successfully decoded attribute that fails
    /// validation may be retained in `update.attributes` for observation
    /// alongside its treat-as-withdraw disposition.
    pub update: ParsedUpdate,
    /// Malformed attributes recovered without aborting the parse, each with
    /// its RFC 7606 disposition. Empty means the UPDATE decoded cleanly.
    pub malformed: Vec<crate::attribute::MalformedAttribute>,
}
impl UpdateMessage {
    /// Decode an UPDATE message body from a buffer.
    /// The header must already be consumed; `body_len` is
    /// `header.length - HEADER_LEN`.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UpdateLengthMismatch`] if the body is too short
    /// or length fields are inconsistent, or [`DecodeError::Incomplete`] if
    /// the buffer has fewer bytes than `body_len`.
    pub fn decode(buf: &mut impl Buf, body_len: usize) -> Result<Self, DecodeError> {
        // Minimum body: withdrawn_len(2) + attrs_len(2) = 4
        if body_len < 4 {
            return Err(DecodeError::UpdateLengthMismatch {
                detail: format!("body too short: {body_len} bytes (need at least 4)"),
            });
        }
        if buf.remaining() < body_len {
            return Err(DecodeError::Incomplete {
                needed: body_len,
                available: buf.remaining(),
            });
        }
        let withdrawn_routes_len = buf.get_u16();
        // Validate withdrawn routes fit in remaining body
        // body_len = 2 (withdrawn_len) + withdrawn_routes + 2 (attrs_len) + attrs + nlri
        let after_withdrawn = body_len
            .checked_sub(2)
            .and_then(|v| v.checked_sub(usize::from(withdrawn_routes_len)))
            .ok_or_else(|| DecodeError::UpdateLengthMismatch {
                detail: format!("withdrawn routes length {withdrawn_routes_len} exceeds body"),
            })?;
        if after_withdrawn < 2 {
            return Err(DecodeError::UpdateLengthMismatch {
                detail: format!(
                    "no room for path attributes length after {withdrawn_routes_len} \
                     bytes of withdrawn routes"
                ),
            });
        }
        let withdrawn_routes = buf.copy_to_bytes(usize::from(withdrawn_routes_len));
        let path_attributes_len = buf.get_u16();
        let nlri_len = after_withdrawn
            .checked_sub(2)
            .and_then(|v| v.checked_sub(usize::from(path_attributes_len)))
            .ok_or_else(|| DecodeError::UpdateLengthMismatch {
                detail: format!(
                    "path attributes length {path_attributes_len} exceeds remaining body"
                ),
            })?;
        let path_attributes = buf.copy_to_bytes(usize::from(path_attributes_len));
        let nlri = buf.copy_to_bytes(nlri_len);
        Ok(Self {
            withdrawn_routes,
            path_attributes,
            nlri,
        })
    }
    /// Parse the raw UPDATE into decoded prefixes and path attributes.
    ///
    /// `four_octet_as` controls whether AS numbers in `AS_PATH` are 2 or 4 bytes
    /// wide (determined by capability negotiation).
    ///
    /// `add_path_ipv4` indicates whether the peer is sending Add-Path path IDs
    /// for IPv4 body NLRI (RFC 7911). When false, decoded entries have `path_id = 0`.
    ///
    /// # Errors
    ///
    /// Returns `DecodeError` if NLRI or attribute data is malformed.
    pub fn parse(
        &self,
        four_octet_as: bool,
        add_path_ipv4: bool,
        add_path_families: &[(Afi, Safi)],
    ) -> Result<ParsedUpdate, DecodeError> {
        let withdrawn = if add_path_ipv4 {
            crate::nlri::decode_nlri_addpath(&self.withdrawn_routes)?
        } else {
            crate::nlri::decode_nlri(&self.withdrawn_routes)?
                .into_iter()
                .map(|prefix| Ipv4NlriEntry { path_id: 0, prefix })
                .collect()
        };
        let (attributes, bgpls_nlri_discarded) = crate::attribute::decode_path_attributes_counted(
            &self.path_attributes,
            four_octet_as,
            add_path_families,
        )?;
        let announced = if add_path_ipv4 {
            crate::nlri::decode_nlri_addpath(&self.nlri)?
        } else {
            crate::nlri::decode_nlri(&self.nlri)?
                .into_iter()
                .map(|prefix| Ipv4NlriEntry { path_id: 0, prefix })
                .collect()
        };
        Ok(ParsedUpdate {
            withdrawn,
            attributes,
            announced,
            bgpls_nlri_discarded,
        })
    }
    /// Parse the raw UPDATE with RFC 7606 revised error handling.
    ///
    /// Like [`parse()`](Self::parse), but a malformed path attribute does not
    /// abort the parse: it is recorded in `malformed` with its RFC 7606
    /// disposition and, if decoding succeeded before validation failed, may
    /// also be retained in `update.attributes` for observation (see
    /// [`crate::attribute::decode_path_attributes_revised`]). The caller
    /// applies the strongest recorded disposition (§3 (h)).
    ///
    /// `is_ibgp` selects the internal-neighbor disposition branch for
    /// `LOCAL_PREF` / `ORIGINATOR_ID` / `CLUSTER_LIST` (§7.5, §7.9, §7.10).
    ///
    /// # Errors
    ///
    /// Returns `DecodeError` only for session-reset-class problems: malformed
    /// or duplicated `MP_REACH_NLRI`/`MP_UNREACH_NLRI` (§7.11), or
    /// syntactically incorrect body NLRI / Withdrawn Routes fields (§5.3 —
    /// treat-as-withdraw is impossible when the NLRI itself cannot be parsed,
    /// §3 (j)).
    pub fn parse_revised(
        &self,
        four_octet_as: bool,
        is_ibgp: bool,
        add_path_ipv4: bool,
        add_path_families: &[(Afi, Safi)],
    ) -> Result<RevisedParsedUpdate, DecodeError> {
        let withdrawn = if add_path_ipv4 {
            crate::nlri::decode_nlri_addpath(&self.withdrawn_routes)?
        } else {
            crate::nlri::decode_nlri(&self.withdrawn_routes)?
                .into_iter()
                .map(|prefix| Ipv4NlriEntry { path_id: 0, prefix })
                .collect()
        };
        let decoded = crate::attribute::decode_path_attributes_revised(
            &self.path_attributes,
            four_octet_as,
            is_ibgp,
            add_path_families,
        )?;
        let announced = if add_path_ipv4 {
            crate::nlri::decode_nlri_addpath(&self.nlri)?
        } else {
            crate::nlri::decode_nlri(&self.nlri)?
                .into_iter()
                .map(|prefix| Ipv4NlriEntry { path_id: 0, prefix })
                .collect()
        };
        Ok(RevisedParsedUpdate {
            update: ParsedUpdate {
                withdrawn,
                attributes: decoded.attributes,
                announced,
                bgpls_nlri_discarded: decoded.bgpls_nlri_discarded,
            },
            malformed: decoded.malformed,
        })
    }
    /// Encode a complete UPDATE message (header + body) into a buffer.
    ///
    /// `max_message_len` is the negotiated maximum: 4096 normally, or 65535
    /// when Extended Messages (RFC 8654) has been negotiated.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::MessageTooLong`] if the encoded message exceeds
    /// the negotiated maximum message size.
    pub fn encode_with_limit(
        &self,
        buf: &mut impl BufMut,
        max_message_len: u16,
    ) -> Result<(), EncodeError> {
        let body_len =
            2 + self.withdrawn_routes.len() + 2 + self.path_attributes.len() + self.nlri.len();
        let total_len = HEADER_LEN + body_len;
        if total_len > usize::from(max_message_len) {
            return Err(EncodeError::MessageTooLong { size: total_len });
        }
        let header = BgpHeader {
            #[expect(
                clippy::cast_possible_truncation,
                reason = "codec bounds or masks the value before narrowing to the protocol field width"
            )]
            length: total_len as u16,
            message_type: MessageType::Update,
        };
        header.encode(buf);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "codec bounds or masks the value before narrowing to the protocol field width"
        )]
        buf.put_u16(self.withdrawn_routes.len() as u16);
        buf.put_slice(&self.withdrawn_routes);
        #[expect(
            clippy::cast_possible_truncation,
            reason = "codec bounds or masks the value before narrowing to the protocol field width"
        )]
        buf.put_u16(self.path_attributes.len() as u16);
        buf.put_slice(&self.path_attributes);
        buf.put_slice(&self.nlri);
        Ok(())
    }
    /// Encode using the standard 4096-byte limit.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::MessageTooLong`] if the encoded message exceeds
    /// the standard 4096-byte maximum.
    pub fn encode(&self, buf: &mut impl BufMut) -> Result<(), EncodeError> {
        self.encode_with_limit(buf, MAX_MESSAGE_LEN)
    }
    /// Build an `UpdateMessage` from structured data.
    ///
    /// Encodes NLRI, withdrawn routes, and path attributes into the raw
    /// `Bytes` fields that `encode()` expects.
    ///
    /// When `add_path` is true, path IDs are included in the wire encoding.
    /// When false, only the prefix is encoded (path IDs are ignored).
    ///
    /// # Panics
    ///
    /// Panics if locally constructed path attributes cannot be encoded. Use
    /// [`Self::try_build`] when the attributes come from an untrusted or
    /// unchecked source.
    #[must_use]
    pub fn build(
        announced: &[Ipv4NlriEntry],
        withdrawn: &[Ipv4NlriEntry],
        attributes: &[PathAttribute],
        four_octet_as: bool,
        add_path: bool,
        ipv4_unicast_mode: Ipv4UnicastMode,
    ) -> Self {
        Self::try_build(
            announced,
            withdrawn,
            attributes,
            four_octet_as,
            add_path,
            ipv4_unicast_mode,
        )
        .expect("structured UPDATE attributes must be validated before build")
    }
    /// Fallible form of [`Self::build`].
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError`] if any structured path attribute contains a
    /// value that cannot be represented on the wire.
    pub fn try_build(
        announced: &[Ipv4NlriEntry],
        withdrawn: &[Ipv4NlriEntry],
        attributes: &[PathAttribute],
        four_octet_as: bool,
        add_path: bool,
        ipv4_unicast_mode: Ipv4UnicastMode,
    ) -> Result<Self, EncodeError> {
        let mut withdrawn_buf = Vec::new();
        if matches!(ipv4_unicast_mode, Ipv4UnicastMode::Body) {
            if add_path {
                crate::nlri::encode_nlri_addpath(withdrawn, &mut withdrawn_buf);
            } else {
                let prefixes: Vec<Ipv4Prefix> = withdrawn.iter().map(|e| e.prefix).collect();
                crate::nlri::encode_nlri(&prefixes, &mut withdrawn_buf);
            }
        }
        let mut attrs_buf = Vec::new();
        if !attributes.is_empty() {
            crate::attribute::encode_path_attributes(
                attributes,
                &mut attrs_buf,
                four_octet_as,
                add_path,
            )?;
        }
        let mut nlri_buf = Vec::new();
        if matches!(ipv4_unicast_mode, Ipv4UnicastMode::Body) {
            if add_path {
                crate::nlri::encode_nlri_addpath(announced, &mut nlri_buf);
            } else {
                let prefixes: Vec<Ipv4Prefix> = announced.iter().map(|e| e.prefix).collect();
                crate::nlri::encode_nlri(&prefixes, &mut nlri_buf);
            }
        }
        Ok(Self {
            withdrawn_routes: Bytes::from(withdrawn_buf),
            path_attributes: Bytes::from(attrs_buf),
            nlri: Bytes::from(nlri_buf),
        })
    }
    /// Total encoded size in bytes.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        HEADER_LEN
            + 2
            + self.withdrawn_routes.len()
            + 2
            + self.path_attributes.len()
            + self.nlri.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MAX_MESSAGE_LEN;
    use crate::{NlriEntry, Prefix};
    use bytes::BytesMut;
    #[test]
    fn decode_minimal_update() {
        // withdrawn_len=0, attrs_len=0, no NLRI
        let body: &[u8] = &[0, 0, 0, 0];
        let mut buf = Bytes::copy_from_slice(body);
        let msg = UpdateMessage::decode(&mut buf, 4).unwrap();
        assert!(msg.withdrawn_routes.is_empty());
        assert!(msg.path_attributes.is_empty());
        assert!(msg.nlri.is_empty());
    }
    #[test]
    fn decode_with_withdrawn_routes() {
        // withdrawn_len=3, withdrawn=[0x18, 0x0A, 0x00] (10.0.0.0/24), attrs_len=0
        let body: &[u8] = &[0, 3, 0x18, 0x0A, 0x00, 0, 0];
        let mut buf = Bytes::copy_from_slice(body);
        let msg = UpdateMessage::decode(&mut buf, 7).unwrap();
        assert_eq!(msg.withdrawn_routes.as_ref(), &[0x18, 0x0A, 0x00]);
        assert!(msg.path_attributes.is_empty());
        assert!(msg.nlri.is_empty());
    }
    #[test]
    fn decode_with_all_sections() {
        let mut body = BytesMut::new();
        body.put_u16(2); // withdrawn_len
        body.put_slice(&[0x10, 0x0A]); // withdrawn
        body.put_u16(3); // attrs_len
        body.put_slice(&[0x40, 0x01, 0x00]); // attrs (fake)
        body.put_slice(&[0x18, 0xC0, 0xA8]); // NLRI (fake)
        let total = body.len();
        let mut buf = body.freeze();
        let msg = UpdateMessage::decode(&mut buf, total).unwrap();
        assert_eq!(msg.withdrawn_routes.len(), 2);
        assert_eq!(msg.path_attributes.len(), 3);
        assert_eq!(msg.nlri.len(), 3);
    }
    #[test]
    fn reject_withdrawn_overflow() {
        // withdrawn_len=100, but body is only 6 bytes
        let body: &[u8] = &[0, 100, 0, 0, 0, 0];
        let mut buf = Bytes::copy_from_slice(body);
        assert!(matches!(
            UpdateMessage::decode(&mut buf, 6),
            Err(DecodeError::UpdateLengthMismatch { .. })
        ));
    }
    #[test]
    fn reject_attrs_overflow() {
        // withdrawn_len=0, attrs_len=100, but body is only 4 bytes
        let body: &[u8] = &[0, 0, 0, 100];
        let mut buf = Bytes::copy_from_slice(body);
        assert!(matches!(
            UpdateMessage::decode(&mut buf, 4),
            Err(DecodeError::UpdateLengthMismatch { .. })
        ));
    }
    #[test]
    fn encode_decode_roundtrip() {
        let original = UpdateMessage {
            withdrawn_routes: Bytes::from_static(&[0x18, 0x0A, 0x00]),
            path_attributes: Bytes::from_static(&[0x40, 0x01, 0x00]),
            nlri: Bytes::from_static(&[0x18, 0xC0, 0xA8]),
        };
        let mut encoded = BytesMut::with_capacity(original.encoded_len());
        original.encode(&mut encoded).unwrap();
        let mut bytes = encoded.freeze();
        let header = BgpHeader::decode(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        assert_eq!(header.message_type, MessageType::Update);
        let body_len = usize::from(header.length) - HEADER_LEN;
        let decoded = UpdateMessage::decode(&mut bytes, body_len).unwrap();
        assert_eq!(original, decoded);
    }
    /// Helper to create an `Ipv4NlriEntry` with `path_id=0`.
    fn entry(prefix: Ipv4Prefix) -> Ipv4NlriEntry {
        Ipv4NlriEntry { path_id: 0, prefix }
    }
    #[test]
    fn build_roundtrip() {
        use crate::attribute::{AsPath, AsPathSegment, Origin};
        let announced = vec![
            entry(Ipv4Prefix::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24)),
            entry(Ipv4Prefix::new(std::net::Ipv4Addr::new(192, 168, 1, 0), 24)),
        ];
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::NextHop(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let msg = UpdateMessage::build(&announced, &[], &attrs, true, false, Ipv4UnicastMode::Body);
        let parsed = msg.parse(true, false, &[]).unwrap();
        assert_eq!(parsed.announced, announced);
        assert!(parsed.withdrawn.is_empty());
        assert_eq!(parsed.attributes, attrs);
    }
    #[test]
    fn build_ipv4_mp_mode_omits_body_nlri() {
        use crate::attribute::{AsPath, AsPathSegment, MpReachNlri, Origin};
        use std::net::{IpAddr, Ipv6Addr};
        let announced = vec![entry(Ipv4Prefix::new(
            std::net::Ipv4Addr::new(10, 0, 0, 0),
            24,
        ))];
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::MpReachNlri(MpReachNlri {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                next_hop: IpAddr::V6(Ipv6Addr::LOCALHOST),
                link_local_next_hop: None,
                announced: vec![NlriEntry {
                    path_id: 0,
                    prefix: Prefix::V4(announced[0].prefix),
                }],
                flowspec_announced: vec![],
                evpn_announced: vec![],
                bgpls_announced: vec![],
                labeled_announced: vec![],
                vpn_announced: vec![],
                rtc_announced: vec![],
            }),
        ];
        let msg = UpdateMessage::build(
            &announced,
            &[],
            &attrs,
            true,
            false,
            Ipv4UnicastMode::MpReach,
        );
        assert!(msg.withdrawn_routes.is_empty());
        assert!(msg.nlri.is_empty());
        let parsed = msg.parse(true, false, &[]).unwrap();
        assert!(parsed.announced.is_empty());
        let mp = parsed
            .attributes
            .iter()
            .find_map(|attr| match attr {
                PathAttribute::MpReachNlri(mp) => Some(mp),
                _ => None,
            })
            .unwrap();
        assert_eq!(mp.afi, Afi::Ipv4);
        assert_eq!(mp.safi, Safi::Unicast);
        assert_eq!(mp.announced.len(), 1);
        assert_eq!(mp.announced[0].prefix, Prefix::V4(announced[0].prefix));
        assert_eq!(mp.next_hop, IpAddr::V6(Ipv6Addr::LOCALHOST));
    }
    #[test]
    fn build_withdrawal_only() {
        let withdrawn = vec![entry(Ipv4Prefix::new(
            std::net::Ipv4Addr::new(10, 0, 0, 0),
            24,
        ))];
        let msg = UpdateMessage::build(&[], &withdrawn, &[], true, false, Ipv4UnicastMode::Body);
        let parsed = msg.parse(true, false, &[]).unwrap();
        assert!(parsed.announced.is_empty());
        assert_eq!(parsed.withdrawn, withdrawn);
        assert!(parsed.attributes.is_empty());
    }
    #[test]
    fn build_announce_only() {
        use crate::attribute::Origin;
        let announced = vec![entry(Ipv4Prefix::new(
            std::net::Ipv4Addr::new(10, 1, 0, 0),
            16,
        ))];
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let msg = UpdateMessage::build(&announced, &[], &attrs, true, false, Ipv4UnicastMode::Body);
        // Verify it encodes and decodes properly
        let mut encoded = BytesMut::with_capacity(msg.encoded_len());
        msg.encode(&mut encoded).unwrap();
        let mut bytes = encoded.freeze();
        let header = BgpHeader::decode(&mut bytes, MAX_MESSAGE_LEN).unwrap();
        let body_len = usize::from(header.length) - HEADER_LEN;
        let decoded = UpdateMessage::decode(&mut bytes, body_len).unwrap();
        let parsed = decoded.parse(true, false, &[]).unwrap();
        assert_eq!(parsed.announced, announced);
        assert_eq!(parsed.attributes, attrs);
    }
    #[test]
    fn build_mixed() {
        use crate::attribute::Origin;
        let announced = vec![entry(Ipv4Prefix::new(
            std::net::Ipv4Addr::new(10, 0, 0, 0),
            24,
        ))];
        let withdrawn = vec![entry(Ipv4Prefix::new(
            std::net::Ipv4Addr::new(172, 16, 0, 0),
            16,
        ))];
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::NextHop(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let msg = UpdateMessage::build(
            &announced,
            &withdrawn,
            &attrs,
            true,
            false,
            Ipv4UnicastMode::Body,
        );
        let parsed = msg.parse(true, false, &[]).unwrap();
        assert_eq!(parsed.announced, announced);
        assert_eq!(parsed.withdrawn, withdrawn);
        assert_eq!(parsed.attributes, attrs);
    }
    #[test]
    fn build_roundtrip_with_add_path() {
        use crate::attribute::{AsPath, AsPathSegment, Origin};
        let announced = vec![
            Ipv4NlriEntry {
                path_id: 1,
                prefix: Ipv4Prefix::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24),
            },
            Ipv4NlriEntry {
                path_id: 2,
                prefix: Ipv4Prefix::new(std::net::Ipv4Addr::new(10, 0, 0, 0), 24),
            },
        ];
        let withdrawn = vec![Ipv4NlriEntry {
            path_id: 3,
            prefix: Ipv4Prefix::new(std::net::Ipv4Addr::new(192, 168, 0, 0), 16),
        }];
        let attrs = vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::NextHop(std::net::Ipv4Addr::new(10, 0, 0, 1)),
        ];
        let msg = UpdateMessage::build(
            &announced,
            &withdrawn,
            &attrs,
            true,
            true,
            Ipv4UnicastMode::Body,
        );
        let parsed = msg.parse(true, true, &[]).unwrap();
        assert_eq!(parsed.announced, announced);
        assert_eq!(parsed.withdrawn, withdrawn);
        assert_eq!(parsed.attributes, attrs);
    }
    #[test]
    fn reject_message_too_long() {
        let msg = UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::from(vec![0u8; 4096]),
            nlri: Bytes::new(),
        };
        let mut buf = BytesMut::with_capacity(5000);
        assert!(matches!(
            msg.encode(&mut buf),
            Err(EncodeError::MessageTooLong { .. })
        ));
    }

    #[test]
    fn parse_revised_recovers_malformed_attribute_and_keeps_nlri() {
        // ORIGIN + AS_PATH + NEXT_HOP + malformed MED (length 3), one
        // announced prefix. RFC 7606: the malformed attribute is reported
        // with its disposition; the NLRI still parses.
        let mut attrs = vec![0x40, 1, 1, 0]; // ORIGIN
        attrs.extend([0x40, 2, 6, 2, 1, 0, 0, 0xFD, 0xE9]); // AS_PATH (65001)
        attrs.extend([0x40, 3, 4, 10, 0, 0, 2]); // NEXT_HOP
        attrs.extend([0x80, 4, 3, 0, 0, 1]); // MED, bad length
        let msg = UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::from(attrs),
            nlri: Bytes::from_static(&[24, 203, 0, 113]),
        };
        // The legacy parse still aborts on the same bytes.
        assert!(msg.parse(true, false, &[]).is_err());
        let revised = msg.parse_revised(true, false, false, &[]).unwrap();
        assert_eq!(revised.update.attributes.len(), 3);
        assert_eq!(revised.update.announced.len(), 1);
        assert_eq!(revised.malformed.len(), 1);
        assert_eq!(revised.malformed[0].type_code, 4);
    }
    #[test]
    fn parse_revised_still_rejects_unparseable_nlri() {
        // RFC 7606 §5.3 / §3 (j): treat-as-withdraw is impossible when the
        // NLRI field itself cannot be parsed — hard error (session reset).
        let msg = UpdateMessage {
            withdrawn_routes: Bytes::new(),
            path_attributes: Bytes::new(),
            nlri: Bytes::from_static(&[33, 10, 0, 0, 0]), // prefix length 33
        };
        assert!(msg.parse_revised(true, false, false, &[]).is_err());
    }
}
