//! Streaming reader for MRT `TABLE_DUMP_V2` files (RFC 6396 §4.3,
//! RFC 8050 Add-Path subtypes).
//!
//! Counterpart to the encoder in [`crate::codec`]: validates the leading
//! `PEER_INDEX_TABLE`, then yields one decoded [`SnapshotEntry`] per RIB
//! entry. Everything the writer emits round-trips; records the reader
//! does not understand (non-`TABLE_DUMP_V2` MRT types, unknown
//! `TABLE_DUMP_V2` subtypes, `RIB_GENERIC` with an AFI/SAFI other than
//! L2VPN/EVPN) are skipped and counted, not treated as errors. A RIB
//! entry's `MP_REACH_NLRI` is accepted in both the RFC 6396 §4.3.4
//! reduced form the writer emits and the full RFC 4760 form other
//! collectors write; see [`decode_table_dump_v2_mp_reach_next_hop`] in
//! `rustbgpd_wire`.
//!
//! Input is treated as hostile — this will read an untrusted file at
//! daemon boot. Every length field is bounds-checked, malformed input
//! surfaces as a typed [`ReadError`] (never a panic), and hard caps
//! bound the work done per file:
//!
//! - [`MAX_RECORD_LEN`](crate::reader::MAX_RECORD_LEN): a single record
//!   payload may not exceed 16 MiB.
//! - [`MAX_TOTAL_ENTRIES`](crate::reader::MAX_TOTAL_ENTRIES): at most
//!   2^28 RIB entries per file.
//! - [`MAX_DECOMPRESSED_LEN`](crate::reader::MAX_DECOMPRESSED_LEN):
//!   gzip input may not inflate past 4 GiB.
use crate::codec::{
    PEER_INDEX_TABLE, RIB_GENERIC, RIB_IPV4_UNICAST, RIB_IPV4_UNICAST_ADDPATH, RIB_IPV6_UNICAST,
    RIB_IPV6_UNICAST_ADDPATH, TABLE_DUMP_V2,
};
use bytes::Bytes;
use rustbgpd_rib::update::MrtPeerEntry;
use rustbgpd_wire::constants::{attr_flags, attr_type};
use rustbgpd_wire::error::DecodeError;
use rustbgpd_wire::mrt::decode_table_dump_v2_mp_reach_next_hop;
use rustbgpd_wire::notification::update_subcode;
use rustbgpd_wire::{Afi, ErrorDisposition, Ipv4Prefix, Ipv6Prefix, PathAttribute, Prefix, Safi};
use std::borrow::Cow;
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

/// Maximum accepted payload length for a single MRT record (16 MiB).
///
/// The largest record the writer can legitimately produce is a
/// `PEER_INDEX_TABLE` with 65535 peers (~1.6 MiB) or a RIB record with
/// 65535 entries of typical attribute size (a few MiB); 16 MiB leaves
/// ample headroom while rejecting length-field garbage early.
pub const MAX_RECORD_LEN: usize = 16 * 1024 * 1024;
/// Maximum total RIB entries accepted per file (2^28 ≈ 268 M).
///
/// Generous for a full Adj-RIB-In dump across many peers, but bounds
/// the memory and CPU a hostile file can demand at boot.
pub const MAX_TOTAL_ENTRIES: u64 = 1 << 28;
/// Maximum gzip-decompressed size accepted by [`decompress_if_gzip`]
/// (4 GiB) — bounds decompression-bomb inputs.
pub const MAX_DECOMPRESSED_LEN: u64 = 4 * 1024 * 1024 * 1024;
/// MRT common header: timestamp(4) + type(2) + subtype(2) + length(4).
const MRT_HEADER_LEN: usize = 12;

/// MRT read/decode errors. All variants are recoverable in the sense
/// that the caller can discard the snapshot and boot cold.
#[derive(Debug, Error)]
pub enum ReadError {
    /// Input ended before a complete structure could be read.
    #[error("truncated MRT data at offset {offset}: {context}")]
    Truncated {
        /// Absolute byte offset where more data was expected.
        offset: usize,
        /// What was being read when the input ran out.
        context: &'static str,
    },
    /// No `TABLE_DUMP_V2` record found in the input.
    #[error("no TABLE_DUMP_V2 records in input")]
    Empty,
    /// The first `TABLE_DUMP_V2` record was not a `PEER_INDEX_TABLE`.
    #[error("first TABLE_DUMP_V2 record must be PEER_INDEX_TABLE, got subtype {subtype}")]
    MissingPeerIndexTable {
        /// The subtype actually encountered.
        subtype: u16,
    },
    /// A second `PEER_INDEX_TABLE` appeared mid-file (RFC 6396 allows
    /// exactly one, at the head).
    #[error("duplicate PEER_INDEX_TABLE at offset {offset}")]
    DuplicatePeerIndexTable {
        /// Absolute byte offset of the duplicate record's header.
        offset: usize,
    },
    /// A record's length field exceeds [`MAX_RECORD_LEN`].
    #[error("MRT record at offset {offset} declares {len} payload bytes, cap is {MAX_RECORD_LEN}")]
    RecordTooLarge {
        /// Absolute byte offset of the record's header.
        offset: usize,
        /// The declared payload length.
        len: u32,
    },
    /// A RIB entry referenced a peer index outside the peer table.
    #[error("RIB entry references peer index {index}, peer table has {peer_count} peers")]
    BadPeerIndex {
        /// The out-of-range index.
        index: u16,
        /// Number of peers in the `PEER_INDEX_TABLE`.
        peer_count: usize,
    },
    /// Structurally invalid data inside a record.
    #[error("malformed MRT record at offset {offset}: {context}")]
    Malformed {
        /// Absolute byte offset of the offending data.
        offset: usize,
        /// Description of the violation.
        context: String,
    },
    /// The file declares more RIB entries than [`MAX_TOTAL_ENTRIES`].
    #[error("total RIB entries exceed cap of {cap}")]
    TooManyEntries {
        /// The cap that was exceeded.
        cap: u64,
    },
    /// A BGP path attribute failed to decode.
    #[error("path attribute decode failed: {0}")]
    AttributeDecode(#[from] DecodeError),
    /// Gzip decompression failed.
    #[error("gzip decompression failed: {0}")]
    Gzip(String),
    /// Gzip input inflated past [`MAX_DECOMPRESSED_LEN`].
    #[error("decompressed size exceeds cap of {MAX_DECOMPRESSED_LEN} bytes")]
    DecompressedTooLarge,
}

fn malformed(offset: usize, context: impl Into<String>) -> ReadError {
    ReadError::Malformed {
        offset,
        context: context.into(),
    }
}

/// NLRI of a decoded RIB entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotNlri {
    /// IPv4/IPv6 unicast prefix (subtypes 2, 4, 8, 9).
    Unicast(Prefix),
    /// `RIB_GENERIC` NLRI, kept as raw bytes. The writer only emits
    /// L2VPN/EVPN here; the bytes are the canonical EVPN route TLV
    /// (`route_type + length + body`) decodable with
    /// [`rustbgpd_wire::decode_evpn_nlri`].
    Generic {
        /// Address family identifier from the record header.
        afi: u16,
        /// Subsequent address family identifier from the record header.
        safi: u8,
        /// Raw NLRI bytes.
        nlri: Bytes,
    },
}

/// One decoded RIB entry from a `TABLE_DUMP_V2` file.
#[derive(Debug, Clone)]
pub struct SnapshotEntry {
    /// The NLRI this entry belongs to.
    pub nlri: SnapshotNlri,
    /// Index into the `PEER_INDEX_TABLE` (validated in range).
    pub peer_index: u16,
    /// The resolved peer table entry for `peer_index`.
    pub peer: MrtPeerEntry,
    /// Unix timestamp when this route was originated.
    pub originated_time: u32,
    /// Add-Path path identifier (RFC 8050). Legacy non-Add-Path subtypes
    /// always use 0; Add-Path subtypes may also legitimately carry 0.
    /// Inspect [`Self::add_path`] to distinguish the record subtype.
    pub path_id: u32,
    /// Whether this entry came from an RFC 8050 Add-Path RIB subtype.
    ///
    /// This is separate from `path_id`: zero is a valid path identifier and
    /// therefore cannot identify the record subtype by itself.
    pub add_path: bool,
    /// Decoded path attributes, excluding `MP_REACH_NLRI` — inside a RIB
    /// entry it carries only the next hop (RFC 6396 §4.3.4), which is
    /// surfaced via `next_hop` / `link_local_next_hop` instead.
    pub attributes: Vec<PathAttribute>,
    /// Next-hop: from the `MP_REACH_NLRI` if present, else from a
    /// `NEXT_HOP` attribute, else `None`.
    pub next_hop: Option<IpAddr>,
    /// Link-local IPv6 next-hop when the `MP_REACH_NLRI` carried the
    /// 32-byte global + link-local form.
    pub link_local_next_hop: Option<Ipv6Addr>,
}

/// Bounds-checked cursor over one record's payload. `base` is the
/// payload's absolute file offset, so errors report file positions.
struct Cur<'a> {
    buf: &'a [u8],
    pos: usize,
    base: usize,
}

impl<'a> Cur<'a> {
    fn new(buf: &'a [u8], base: usize) -> Self {
        Self { buf, pos: 0, base }
    }
    fn offset(&self) -> usize {
        self.base + self.pos
    }
    fn rel_pos(&self) -> usize {
        self.pos
    }
    fn is_empty(&self) -> bool {
        self.pos == self.buf.len()
    }
    fn take(&mut self, n: usize, context: &'static str) -> Result<&'a [u8], ReadError> {
        if self.buf.len() - self.pos < n {
            return Err(ReadError::Truncated {
                offset: self.offset(),
                context,
            });
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self, context: &'static str) -> Result<u8, ReadError> {
        Ok(self.take(1, context)?[0])
    }
    fn u16(&mut self, context: &'static str) -> Result<u16, ReadError> {
        let s = self.take(2, context)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self, context: &'static str) -> Result<u32, ReadError> {
        let s = self.take(4, context)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
}

/// Read the MRT common header at `start` and return
/// `(type, subtype, payload)` with the payload bounds-checked against
/// both [`MAX_RECORD_LEN`] and the remaining input.
fn read_record(data: &[u8], start: usize) -> Result<(u16, u16, &[u8]), ReadError> {
    if data.len() - start < MRT_HEADER_LEN {
        return Err(ReadError::Truncated {
            offset: data.len(),
            context: "MRT common header",
        });
    }
    let mrt_type = u16::from_be_bytes([data[start + 4], data[start + 5]]);
    let subtype = u16::from_be_bytes([data[start + 6], data[start + 7]]);
    let len_field = u32::from_be_bytes([
        data[start + 8],
        data[start + 9],
        data[start + 10],
        data[start + 11],
    ]);
    let len = usize::try_from(len_field).map_err(|_| ReadError::RecordTooLarge {
        offset: start,
        len: len_field,
    })?;
    if len > MAX_RECORD_LEN {
        return Err(ReadError::RecordTooLarge {
            offset: start,
            len: len_field,
        });
    }
    let payload_start = start + MRT_HEADER_LEN;
    if data.len() - payload_start < len {
        return Err(ReadError::Truncated {
            offset: data.len(),
            context: "MRT record payload",
        });
    }
    Ok((mrt_type, subtype, &data[payload_start..payload_start + len]))
}

/// Decoded attribute block of one RIB entry.
struct EntryAttributes {
    attributes: Vec<PathAttribute>,
    next_hop: Option<IpAddr>,
    link_local_next_hop: Option<Ipv6Addr>,
    discarded_path_attributes: u64,
    discarded_bgpls_nlris: u64,
}

/// Split a RIB entry's attribute block: walk the TLV framing with
/// bounds checks, peel off the next-hop-only `MP_REACH_NLRI`, and decode
/// the remaining attributes with the revised wire decoder. Four-octet ASNs
/// match the writer, while `is_ibgp = true` is the conservative all-lanes
/// default on incomplete evidence: an MRT peer table does not preserve the
/// original session relationship. Only attribute-discard recovery is safe for
/// a snapshot entry; any stronger disposition still fails the decode.
fn decode_entry_attributes(attrs: &[u8], base: usize) -> Result<EntryAttributes, ReadError> {
    let mut cur = Cur::new(attrs, base);
    let mut other: Vec<u8> = Vec::with_capacity(attrs.len());
    let mut mp_next_hop: Option<(IpAddr, Option<Ipv6Addr>)> = None;
    while !cur.is_empty() {
        let span_start = cur.rel_pos();
        let attr_offset = cur.offset();
        let flags = cur.u8("attribute flags")?;
        let type_code = cur.u8("attribute type")?;
        let value_len = if flags & attr_flags::EXTENDED_LENGTH == 0 {
            usize::from(cur.u8("attribute length")?)
        } else {
            usize::from(cur.u16("extended attribute length")?)
        };
        let value_offset = cur.offset();
        let value = cur.take(value_len, "attribute value")?;
        if type_code == attr_type::MP_REACH_NLRI {
            if mp_next_hop.is_some() {
                return Err(malformed(attr_offset, "duplicate MP_REACH_NLRI"));
            }
            let flags_mask = attr_flags::OPTIONAL | attr_flags::TRANSITIVE;
            if flags & flags_mask != attr_flags::OPTIONAL {
                return Err(ReadError::AttributeDecode(
                    DecodeError::UpdateAttributeError {
                        subcode: update_subcode::ATTRIBUTE_FLAGS_ERROR,
                        data: attrs[span_start..cur.rel_pos()].to_vec(),
                        detail: format!(
                            "type {} flags {:#04x} (expected {:#04x})",
                            type_code,
                            flags & flags_mask,
                            attr_flags::OPTIONAL
                        ),
                    },
                ));
            }
            mp_next_hop = Some(
                decode_table_dump_v2_mp_reach_next_hop(value)
                    .map_err(|err| malformed(value_offset, err.to_string()))?,
            );
        } else {
            other.extend_from_slice(&attrs[span_start..cur.rel_pos()]);
        }
    }
    let decoded =
        rustbgpd_wire::attribute::decode_path_attributes_revised(&other, true, true, &[])?;
    if let Some(malformed) = decoded
        .malformed
        .iter()
        .find(|malformed| malformed.disposition != ErrorDisposition::AttributeDiscard)
    {
        return Err(ReadError::AttributeDecode(malformed.error.clone()));
    }
    let discarded_path_attributes = u64::try_from(decoded.malformed.len())
        .map_err(|_| malformed(base, "discarded path-attribute count exceeds u64"))?;
    let discarded_bgpls_nlris = u64::from(decoded.bgpls_nlri_discarded);
    let attributes = decoded.attributes;
    let (next_hop, link_local_next_hop) = match mp_next_hop {
        Some((nh, ll)) => (Some(nh), ll),
        None => (
            attributes.iter().find_map(|a| match a {
                PathAttribute::NextHop(v4) => Some(IpAddr::V4(*v4)),
                _ => None,
            }),
            None,
        ),
    };
    Ok(EntryAttributes {
        attributes,
        next_hop,
        link_local_next_hop,
        discarded_path_attributes,
        discarded_bgpls_nlris,
    })
}

/// Entry plus recovery observations held privately until it is yielded.
///
/// Keeping the observations beside the pending entry prevents a later failure
/// in the same MRT record from incrementing counters for routes the iterator
/// never exposes.
struct PendingSnapshotEntry {
    entry: SnapshotEntry,
    discarded_path_attributes: u64,
    discarded_bgpls_nlris: u64,
}

/// Streaming reader over a `TABLE_DUMP_V2` byte buffer.
///
/// Construction eagerly validates the `PEER_INDEX_TABLE` (skipping any
/// leading non-`TABLE_DUMP_V2` records); iteration then yields one
/// [`SnapshotEntry`] per RIB entry. The first error fuses the iterator:
/// after yielding `Err`, `next()` returns `None`.
pub struct SnapshotReader<'a> {
    data: &'a [u8],
    pos: usize,
    collector_bgp_id: Ipv4Addr,
    view_name: String,
    peers: Vec<MrtPeerEntry>,
    pending: VecDeque<PendingSnapshotEntry>,
    skipped_records: u64,
    discarded_path_attributes: u64,
    discarded_bgpls_nlris: u64,
    total_entries: u64,
    entry_cap: u64,
    fused: bool,
}

impl<'a> SnapshotReader<'a> {
    /// Open a reader over raw (already decompressed) MRT bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReadError::Empty`] if the input holds no
    /// `TABLE_DUMP_V2` records, [`ReadError::MissingPeerIndexTable`]
    /// if the first one is not a `PEER_INDEX_TABLE`, or a framing
    /// error ([`ReadError::Truncated`] / [`ReadError::RecordTooLarge`] /
    /// [`ReadError::Malformed`]) if the peer table is corrupt.
    pub fn new(data: &'a [u8]) -> Result<Self, ReadError> {
        let mut pos = 0;
        let mut skipped_records = 0_u64;
        loop {
            if pos == data.len() {
                return Err(ReadError::Empty);
            }
            let (mrt_type, subtype, payload) = read_record(data, pos)?;
            let payload_start = pos + MRT_HEADER_LEN;
            pos = payload_start + payload.len();
            if mrt_type != TABLE_DUMP_V2 {
                skipped_records += 1;
                continue;
            }
            if subtype != PEER_INDEX_TABLE {
                return Err(ReadError::MissingPeerIndexTable { subtype });
            }
            let (collector_bgp_id, view_name, peers) =
                parse_peer_index_table(payload, payload_start)?;
            return Ok(Self {
                data,
                pos,
                collector_bgp_id,
                view_name,
                peers,
                pending: VecDeque::new(),
                skipped_records,
                discarded_path_attributes: 0,
                discarded_bgpls_nlris: 0,
                total_entries: 0,
                entry_cap: MAX_TOTAL_ENTRIES,
                fused: false,
            });
        }
    }

    /// Collector BGP identifier from the `PEER_INDEX_TABLE`.
    #[must_use]
    pub fn collector_bgp_id(&self) -> Ipv4Addr {
        self.collector_bgp_id
    }

    /// UTF-8 view name from the `PEER_INDEX_TABLE`.
    #[must_use]
    pub fn view_name(&self) -> &str {
        &self.view_name
    }

    /// Peer table entries, in `PEER_INDEX_TABLE` order.
    #[must_use]
    pub fn peers(&self) -> &[MrtPeerEntry] {
        &self.peers
    }

    /// Number of records skipped so far (non-`TABLE_DUMP_V2` types,
    /// unknown subtypes, and non-EVPN `RIB_GENERIC` records).
    #[must_use]
    pub fn skipped_records(&self) -> u64 {
        self.skipped_records
    }

    /// Number of malformed path-attribute instances omitted from entries
    /// successfully yielded so far under attribute-discard recovery.
    #[must_use]
    pub fn discarded_path_attributes(&self) -> u64 {
        self.discarded_path_attributes
    }

    /// Number of malformed BGP-LS NLRIs omitted from path attributes on
    /// entries successfully yielded so far.
    #[must_use]
    pub fn discarded_bgpls_nlris(&self) -> u64 {
        self.discarded_bgpls_nlris
    }

    #[cfg(test)]
    fn set_entry_cap(&mut self, cap: u64) {
        self.entry_cap = cap;
    }

    fn check_entry_budget(&mut self, count: u64) -> Result<(), ReadError> {
        self.total_entries = self.total_entries.saturating_add(count);
        if self.total_entries > self.entry_cap {
            return Err(ReadError::TooManyEntries {
                cap: self.entry_cap,
            });
        }
        Ok(())
    }

    /// Parse the record at `self.pos`, pushing any decoded entries onto
    /// `self.pending`, and advance past it.
    fn parse_next_record(&mut self) -> Result<(), ReadError> {
        let data = self.data;
        let start = self.pos;
        let (mrt_type, subtype, payload) = read_record(data, start)?;
        let payload_start = start + MRT_HEADER_LEN;
        self.pos = payload_start + payload.len();
        if mrt_type != TABLE_DUMP_V2 {
            self.skipped_records += 1;
            return Ok(());
        }
        match subtype {
            PEER_INDEX_TABLE => Err(ReadError::DuplicatePeerIndexTable { offset: start }),
            RIB_IPV4_UNICAST => self.parse_unicast(payload, payload_start, false, false),
            RIB_IPV6_UNICAST => self.parse_unicast(payload, payload_start, true, false),
            RIB_IPV4_UNICAST_ADDPATH => self.parse_unicast(payload, payload_start, false, true),
            RIB_IPV6_UNICAST_ADDPATH => self.parse_unicast(payload, payload_start, true, true),
            RIB_GENERIC => self.parse_generic(payload, payload_start),
            _ => {
                self.skipped_records += 1;
                Ok(())
            }
        }
    }

    /// Parse a `RIB_IPV4_UNICAST` / `RIB_IPV6_UNICAST` record
    /// (optionally the RFC 8050 `_ADDPATH` variant).
    fn parse_unicast(
        &mut self,
        payload: &'a [u8],
        base: usize,
        v6: bool,
        add_path: bool,
    ) -> Result<(), ReadError> {
        let mut cur = Cur::new(payload, base);
        let _seq = cur.u32("RIB sequence number")?;
        let prefix_len = cur.u8("prefix length")?;
        let max_len = if v6 { 128 } else { 32 };
        if prefix_len > max_len {
            return Err(malformed(
                cur.offset(),
                format!("prefix length {prefix_len} exceeds /{max_len}"),
            ));
        }
        let n_bytes = usize::from(prefix_len).div_ceil(8);
        let prefix_bytes = cur.take(n_bytes, "prefix bytes")?;
        let prefix = if v6 {
            let mut octets = [0_u8; 16];
            octets[..n_bytes].copy_from_slice(prefix_bytes);
            Prefix::V6(Ipv6Prefix {
                addr: Ipv6Addr::from(octets),
                len: prefix_len,
            })
        } else {
            let mut octets = [0_u8; 4];
            octets[..n_bytes].copy_from_slice(prefix_bytes);
            Prefix::V4(Ipv4Prefix {
                addr: Ipv4Addr::from(octets),
                len: prefix_len,
            })
        };
        let count = cur.u16("RIB entry count")?;
        self.check_entry_budget(u64::from(count))?;
        let nlri = SnapshotNlri::Unicast(prefix);
        for _ in 0..count {
            self.parse_entry(&mut cur, add_path, &nlri)?;
        }
        if !cur.is_empty() {
            return Err(malformed(cur.offset(), "trailing bytes in RIB record"));
        }
        Ok(())
    }

    /// Parse a `RIB_GENERIC` record (RFC 6396 §4.3.5). Only L2VPN/EVPN
    /// is understood (the only AFI/SAFI the writer emits); any other
    /// AFI/SAFI has an NLRI of unknown framing, so the whole record is
    /// skipped and counted.
    fn parse_generic(&mut self, payload: &'a [u8], base: usize) -> Result<(), ReadError> {
        let mut cur = Cur::new(payload, base);
        let _seq = cur.u32("RIB sequence number")?;
        let afi = cur.u16("RIB_GENERIC AFI")?;
        let safi = cur.u8("RIB_GENERIC SAFI")?;
        if afi != Afi::L2Vpn as u16 || safi != Safi::Evpn as u8 {
            self.skipped_records += 1;
            return Ok(());
        }
        // EVPN NLRI TLV: route_type(1) + length(1) + body.
        let nlri_start = cur.rel_pos();
        let _route_type = cur.u8("EVPN route type")?;
        let body_len = cur.u8("EVPN NLRI length")?;
        cur.take(usize::from(body_len), "EVPN NLRI body")?;
        let nlri_bytes = Bytes::copy_from_slice(&payload[nlri_start..cur.rel_pos()]);
        let count = cur.u16("RIB entry count")?;
        self.check_entry_budget(u64::from(count))?;
        let nlri = SnapshotNlri::Generic {
            afi,
            safi,
            nlri: nlri_bytes,
        };
        for _ in 0..count {
            self.parse_entry(&mut cur, false, &nlri)?;
        }
        if !cur.is_empty() {
            return Err(malformed(cur.offset(), "trailing bytes in RIB record"));
        }
        Ok(())
    }

    /// Parse a single RIB entry and push it onto `pending`.
    fn parse_entry(
        &mut self,
        cur: &mut Cur<'a>,
        add_path: bool,
        nlri: &SnapshotNlri,
    ) -> Result<(), ReadError> {
        let path_id = if add_path {
            cur.u32("path identifier")?
        } else {
            0
        };
        let peer_index = cur.u16("peer index")?;
        let Some(peer) = self.peers.get(usize::from(peer_index)) else {
            return Err(ReadError::BadPeerIndex {
                index: peer_index,
                peer_count: self.peers.len(),
            });
        };
        let originated_time = cur.u32("originated time")?;
        let attr_len = cur.u16("attribute length")?;
        let attr_base = cur.offset();
        let attrs = cur.take(usize::from(attr_len), "attribute bytes")?;
        let decoded = decode_entry_attributes(attrs, attr_base)?;
        self.pending.push_back(PendingSnapshotEntry {
            entry: SnapshotEntry {
                nlri: nlri.clone(),
                peer_index,
                peer: peer.clone(),
                originated_time,
                path_id,
                add_path,
                attributes: decoded.attributes,
                next_hop: decoded.next_hop,
                link_local_next_hop: decoded.link_local_next_hop,
            },
            discarded_path_attributes: decoded.discarded_path_attributes,
            discarded_bgpls_nlris: decoded.discarded_bgpls_nlris,
        });
        Ok(())
    }
}

impl Iterator for SnapshotReader<'_> {
    type Item = Result<SnapshotEntry, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.fused {
            return None;
        }
        loop {
            if let Some(pending) = self.pending.pop_front() {
                let Some(discarded_path_attributes) = self
                    .discarded_path_attributes
                    .checked_add(pending.discarded_path_attributes)
                else {
                    self.fused = true;
                    return Some(Err(malformed(
                        self.pos,
                        "discarded path-attribute counter overflow",
                    )));
                };
                let Some(discarded_bgpls_nlris) = self
                    .discarded_bgpls_nlris
                    .checked_add(pending.discarded_bgpls_nlris)
                else {
                    self.fused = true;
                    return Some(Err(malformed(
                        self.pos,
                        "discarded BGP-LS NLRI counter overflow",
                    )));
                };
                self.discarded_path_attributes = discarded_path_attributes;
                self.discarded_bgpls_nlris = discarded_bgpls_nlris;
                return Some(Ok(pending.entry));
            }
            if self.pos >= self.data.len() {
                return None;
            }
            if let Err(e) = self.parse_next_record() {
                self.fused = true;
                return Some(Err(e));
            }
        }
    }
}

/// Parse the `PEER_INDEX_TABLE` payload: collector BGP ID, view name,
/// and the peer entries. Reads all four peer-type combinations
/// (IPv4/IPv6 × AS2/AS4) even though the writer always emits AS4.
fn parse_peer_index_table(
    payload: &[u8],
    base: usize,
) -> Result<(Ipv4Addr, String, Vec<MrtPeerEntry>), ReadError> {
    let mut cur = Cur::new(payload, base);
    let id = cur.take(4, "collector BGP ID")?;
    let collector_bgp_id = Ipv4Addr::new(id[0], id[1], id[2], id[3]);
    let view_name_len = cur.u16("view name length")?;
    let view_name_offset = cur.offset();
    let view_name_bytes = cur.take(usize::from(view_name_len), "view name")?;
    let view_name = std::str::from_utf8(view_name_bytes)
        .map_err(|_| malformed(view_name_offset, "view name is not valid UTF-8"))?
        .to_owned();
    let peer_count = cur.u16("peer count")?;
    let mut peers = Vec::with_capacity(usize::from(peer_count).min(1024));
    for _ in 0..peer_count {
        let peer_type = cur.u8("peer type")?;
        let bgp_id = cur.take(4, "peer BGP ID")?;
        let peer_bgp_id = Ipv4Addr::new(bgp_id[0], bgp_id[1], bgp_id[2], bgp_id[3]);
        let peer_addr = if peer_type & 0b01 == 0 {
            let a = cur.take(4, "peer IPv4 address")?;
            IpAddr::V4(Ipv4Addr::new(a[0], a[1], a[2], a[3]))
        } else {
            let a: [u8; 16] = cur
                .take(16, "peer IPv6 address")?
                .try_into()
                .expect("take(16) returns 16 bytes");
            IpAddr::V6(Ipv6Addr::from(a))
        };
        let peer_asn = if peer_type & 0b10 == 0 {
            u32::from(cur.u16("peer AS (2 octet)")?)
        } else {
            cur.u32("peer AS (4 octet)")?
        };
        peers.push(MrtPeerEntry {
            peer_addr,
            peer_bgp_id,
            peer_asn,
        });
    }
    if !cur.is_empty() {
        return Err(malformed(
            cur.offset(),
            "trailing bytes in PEER_INDEX_TABLE",
        ));
    }
    Ok((collector_bgp_id, view_name, peers))
}

/// Transparently gunzip a snapshot file's bytes if they carry the gzip
/// magic, otherwise return them borrowed. Decompression is capped at
/// [`MAX_DECOMPRESSED_LEN`].
///
/// # Errors
///
/// Returns [`ReadError::Gzip`] on corrupt gzip data and
/// [`ReadError::DecompressedTooLarge`] if the output exceeds the cap.
pub fn decompress_if_gzip(data: &[u8]) -> Result<Cow<'_, [u8]>, ReadError> {
    if data.len() < 2 || data[..2] != [0x1f, 0x8b] {
        return Ok(Cow::Borrowed(data));
    }
    let mut out = Vec::new();
    let mut limited =
        std::io::Read::take(flate2::read::GzDecoder::new(data), MAX_DECOMPRESSED_LEN + 1);
    std::io::Read::read_to_end(&mut limited, &mut out)
        .map_err(|e| ReadError::Gzip(e.to_string()))?;
    match u64::try_from(out.len()) {
        Ok(n) if n <= MAX_DECOMPRESSED_LEN => Ok(Cow::Owned(out)),
        _ => Err(ReadError::DecompressedTooLarge),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{RibEntry, encode_rib_entries, encode_snapshot};
    use rustbgpd_rib::route::{EvpnRibRoute, Route, RouteOrigin};
    use rustbgpd_wire::{
        AsPath, AsPathSegment, Ipv4Prefix, Ipv6Prefix, Origin, RpkiValidation, decode_evpn_nlri,
    };
    use std::sync::Arc;
    use std::time::Instant;

    const COLLECTOR: Ipv4Addr = Ipv4Addr::new(1, 2, 3, 4);
    const TS: u32 = 1_700_000_000;

    fn make_peer(addr: IpAddr, asn: u32) -> MrtPeerEntry {
        let bgp_id = match addr {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => Ipv4Addr::new(10, 0, 0, 1),
        };
        MrtPeerEntry {
            peer_addr: addr,
            peer_bgp_id: bgp_id,
            peer_asn: asn,
        }
    }

    fn base_attrs() -> Vec<PathAttribute> {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(AsPath {
                segments: vec![AsPathSegment::AsSequence(vec![65001])],
            }),
            PathAttribute::LocalPref(100),
        ]
    }

    fn make_route(prefix: Prefix, peer: IpAddr, next_hop: IpAddr) -> Route {
        Route {
            prefix,
            next_hop,
            link_local_next_hop: None,
            next_hop_scope: None,
            peer,
            attributes: Arc::new(base_attrs()),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 1),
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
            aspa_context: rustbgpd_wire::AspaValidationContext::default(),
        }
    }

    fn make_evpn_macip(peer: IpAddr, next_hop: IpAddr) -> EvpnRibRoute {
        use rustbgpd_wire::{
            EthernetSegmentIdentifier, EthernetTagId, EvpnMacIp, EvpnRoute, MacAddress, MplsLabel,
            RouteDistinguisher,
        };
        let route = EvpnRoute::MacIp(EvpnMacIp {
            rd: RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            mac: MacAddress([0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01]),
            ip: Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
            label1: MplsLabel::new(100),
            label2: None,
        });
        EvpnRibRoute {
            route,
            next_hop,
            link_local_next_hop: None,
            peer,
            attributes: Arc::new(base_attrs()),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    fn make_evpn_ipprefix(peer: IpAddr, next_hop: IpAddr) -> EvpnRibRoute {
        use rustbgpd_wire::{
            EthernetSegmentIdentifier, EthernetTagId, EvpnIpPrefixRoute, EvpnIpPrefixValue,
            EvpnRoute, MplsLabel, RouteDistinguisher,
        };
        let route = EvpnRoute::IpPrefix(EvpnIpPrefixRoute {
            rd: RouteDistinguisher([0x00, 0x00, 0xFD, 0xE8, 0x00, 0x00, 0x00, 0x64]),
            esi: EthernetSegmentIdentifier::ZERO,
            ethernet_tag: EthernetTagId(0),
            prefix: EvpnIpPrefixValue::V4(Ipv4Prefix {
                addr: Ipv4Addr::new(192, 0, 2, 0),
                len: 24,
            }),
            gateway: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            label: MplsLabel::new(200),
        });
        EvpnRibRoute {
            route,
            next_hop,
            link_local_next_hop: None,
            peer,
            attributes: Arc::new(base_attrs()),
            received_at: Instant::now(),
            origin_type: RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::new(10, 0, 0, 2),
            is_stale: false,
            is_llgr_stale: false,
        }
    }

    fn v4_prefix(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix {
            addr: Ipv4Addr::new(a, b, c, d),
            len,
        })
    }

    fn drain(reader: &mut SnapshotReader<'_>) -> (Vec<SnapshotEntry>, Option<ReadError>) {
        let mut entries = Vec::new();
        for item in reader.by_ref() {
            match item {
                Ok(e) => entries.push(e),
                Err(e) => return (entries, Some(e)),
            }
        }
        (entries, None)
    }

    /// Build a raw MRT record with the given type/subtype around `payload`.
    fn raw_record(mrt_type: u16, subtype: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&TS.to_be_bytes());
        buf.extend_from_slice(&mrt_type.to_be_bytes());
        buf.extend_from_slice(&subtype.to_be_bytes());
        buf.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    /// Append one IPv4-unicast RIB record whose single entry carries `attrs`.
    fn append_v4_rib_with_attributes(data: &mut Vec<u8>, attrs: &[u8]) {
        append_v4_rib_attribute_entries(data, &[attrs]);
    }

    fn append_v4_rib_attribute_entries(data: &mut Vec<u8>, attribute_blocks: &[&[u8]]) {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.push(24);
        payload.extend_from_slice(&[192, 168, 1]);
        payload.extend_from_slice(&u16::try_from(attribute_blocks.len()).unwrap().to_be_bytes());
        for attrs in attribute_blocks {
            payload.extend_from_slice(&0u16.to_be_bytes());
            payload.extend_from_slice(&TS.to_be_bytes());
            payload.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
            payload.extend_from_slice(attrs);
        }
        data.extend_from_slice(&raw_record(13, 2, &payload));
    }

    /// `MP_UNREACH_NLRI` carrying one BGP-LS Node NLRI whose descriptor TLVs
    /// are out of canonical order. RFC 9552 isolates that NLRI and counts it.
    fn discarded_bgpls_mp_unreach_attribute() -> Vec<u8> {
        let mut nlri = Vec::new();
        nlri.extend_from_slice(&1_u16.to_be_bytes()); // Node NLRI.
        nlri.extend_from_slice(&19_u16.to_be_bytes());
        nlri.push(3); // OSPFv2 protocol ID.
        nlri.extend_from_slice(&7_u64.to_be_bytes());
        nlri.extend_from_slice(&515_u16.to_be_bytes());
        nlri.extend_from_slice(&1_u16.to_be_bytes());
        nlri.push(1);
        nlri.extend_from_slice(&256_u16.to_be_bytes());
        nlri.extend_from_slice(&1_u16.to_be_bytes());
        nlri.push(1);

        let mut value = Vec::new();
        value.extend_from_slice(&(Afi::BgpLs as u16).to_be_bytes());
        value.push(Safi::BgpLs as u8);
        value.extend_from_slice(&nlri);
        let mut attribute = vec![
            attr_flags::OPTIONAL,
            attr_type::MP_UNREACH_NLRI,
            u8::try_from(value.len()).unwrap(),
        ];
        attribute.extend_from_slice(&value);
        attribute
    }

    // ---- round-trip: writer output must read back with full fidelity ----

    #[test]
    fn roundtrip_ipv4_unicast() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let peer = make_peer(peer_addr, 65001);
        let routes = vec![
            make_route(v4_prefix(192, 168, 0, 0, 16), peer_addr, nh),
            make_route(v4_prefix(198, 51, 100, 0, 24), peer_addr, nh),
        ];
        let data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &routes, &[], TS).unwrap();
        let mut reader = SnapshotReader::new(&data).unwrap();
        assert_eq!(reader.collector_bgp_id(), COLLECTOR);
        assert_eq!(reader.view_name(), "");
        assert_eq!(reader.peers().len(), 1);
        assert_eq!(reader.peers()[0].peer_addr, peer_addr);
        assert_eq!(reader.peers()[0].peer_bgp_id, peer.peer_bgp_id);
        assert_eq!(reader.peers()[0].peer_asn, 65001);
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none(), "unexpected error: {err:?}");
        assert_eq!(entries.len(), 2);
        assert_eq!(reader.skipped_records(), 0);
        assert_eq!(reader.discarded_path_attributes(), 0);
        assert_eq!(reader.discarded_bgpls_nlris(), 0);
        // Writer sorts prefixes; 192.168/16 < 198.51.100/24.
        assert_eq!(entries[0].nlri, SnapshotNlri::Unicast(routes[0].prefix));
        assert_eq!(entries[1].nlri, SnapshotNlri::Unicast(routes[1].prefix));
        for e in &entries {
            assert_eq!(e.peer_index, 0);
            assert_eq!(e.peer.peer_asn, 65001);
            assert_eq!(e.path_id, 0);
            assert_eq!(e.next_hop, Some(nh));
            assert_eq!(e.link_local_next_hop, None);
            // Writer synthesizes NEXT_HOP after ORIGIN + AS_PATH.
            let mut expected = base_attrs();
            expected.insert(2, PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 9)));
            assert_eq!(e.attributes, expected);
        }
    }

    #[test]
    fn roundtrip_ipv6_unicast_with_link_local() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let global = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let peer = make_peer(peer_addr, 65001);
        let mut route = make_route(
            Prefix::V6(Ipv6Prefix {
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                len: 32,
            }),
            peer_addr,
            IpAddr::V6(global),
        );
        route.link_local_next_hop = Some(link_local);
        let data = encode_snapshot(
            COLLECTOR,
            std::slice::from_ref(&peer),
            std::slice::from_ref(&route),
            &[],
            TS,
        )
        .unwrap();
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none(), "unexpected error: {err:?}");
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.nlri, SnapshotNlri::Unicast(route.prefix));
        assert_eq!(e.next_hop, Some(IpAddr::V6(global)));
        assert_eq!(e.link_local_next_hop, Some(link_local));
        // The synthesized MP_REACH is consumed into next_hop; the
        // remaining attributes must equal the route's originals.
        assert_eq!(e.attributes, base_attrs());
    }

    #[test]
    fn roundtrip_rfc8950_ipv4_with_ipv6_next_hop() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let nh = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 99);
        let peer = make_peer(peer_addr, 65001);
        let route = make_route(v4_prefix(203, 0, 113, 0, 24), peer_addr, IpAddr::V6(nh));
        let data = encode_snapshot(
            COLLECTOR,
            std::slice::from_ref(&peer),
            std::slice::from_ref(&route),
            &[],
            TS,
        )
        .unwrap();
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none(), "unexpected error: {err:?}");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].nlri, SnapshotNlri::Unicast(route.prefix));
        assert_eq!(entries[0].next_hop, Some(IpAddr::V6(nh)));
        assert_eq!(entries[0].attributes, base_attrs());
    }

    #[test]
    fn roundtrip_addpath_v4_and_v6() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9));
        let peer = make_peer(peer_addr, 65001);
        let mut r1 = make_route(v4_prefix(10, 0, 0, 0, 8), peer_addr, nh);
        r1.path_id = 1;
        let mut r2 = make_route(v4_prefix(10, 0, 0, 0, 8), peer_addr, nh);
        r2.path_id = 2;
        let mut r3 = make_route(
            Prefix::V6(Ipv6Prefix {
                addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                len: 32,
            }),
            peer_addr,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        );
        r3.path_id = 7;
        let data = encode_snapshot(
            COLLECTOR,
            std::slice::from_ref(&peer),
            &[r1, r2, r3],
            &[],
            TS,
        )
        .unwrap();
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none(), "unexpected error: {err:?}");
        assert_eq!(entries.len(), 3);
        let v4_ids: Vec<u32> = entries
            .iter()
            .filter(|e| matches!(e.nlri, SnapshotNlri::Unicast(Prefix::V4(_))))
            .map(|e| e.path_id)
            .collect();
        assert_eq!(v4_ids, vec![1, 2]);
        let v6_ids: Vec<u32> = entries
            .iter()
            .filter(|e| matches!(e.nlri, SnapshotNlri::Unicast(Prefix::V6(_))))
            .map(|e| e.path_id)
            .collect();
        assert_eq!(v6_ids, vec![7]);
    }

    #[test]
    fn roundtrip_evpn_rib_generic() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let nh = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99));
        let peer = make_peer(peer_addr, 65002);
        let evpn = vec![
            make_evpn_macip(peer_addr, nh),
            make_evpn_ipprefix(peer_addr, nh),
        ];
        let data = encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &evpn, TS).unwrap();
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none(), "unexpected error: {err:?}");
        assert_eq!(entries.len(), 2);
        let mut decoded_routes = Vec::new();
        for e in &entries {
            let SnapshotNlri::Generic { afi, safi, nlri } = &e.nlri else {
                panic!("EVPN entry must be Generic NLRI");
            };
            assert_eq!(*afi, 25);
            assert_eq!(*safi, 70);
            assert_eq!(e.next_hop, Some(nh));
            assert_eq!(e.attributes, base_attrs());
            let mut routes = decode_evpn_nlri(nlri).expect("EVPN NLRI must decode");
            assert_eq!(routes.len(), 1);
            decoded_routes.append(&mut routes);
        }
        // Both original EVPN routes must round-trip (order may differ).
        for original in &evpn {
            assert!(
                decoded_routes.contains(&original.route),
                "EVPN route missing after round-trip: {:?}",
                original.route
            );
        }
    }

    #[test]
    fn roundtrip_empty_snapshot() {
        let data = encode_snapshot(COLLECTOR, &[], &[], &[], TS).unwrap();
        let mut reader = SnapshotReader::new(&data).unwrap();
        assert!(reader.peers().is_empty());
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none());
        assert!(entries.is_empty());
    }

    #[test]
    fn roundtrip_gzip() {
        use std::io::Write;
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = make_peer(peer_addr, 65001);
        let route = make_route(v4_prefix(192, 168, 0, 0, 16), peer_addr, peer_addr);
        let plain = encode_snapshot(
            COLLECTOR,
            std::slice::from_ref(&peer),
            std::slice::from_ref(&route),
            &[],
            TS,
        )
        .unwrap();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(&plain).unwrap();
        let gz = enc.finish().unwrap();
        let decompressed = decompress_if_gzip(&gz).unwrap();
        assert!(matches!(decompressed, Cow::Owned(_)));
        assert_eq!(decompressed.as_ref(), plain.as_slice());
        let mut reader = SnapshotReader::new(&decompressed).unwrap();
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none());
        assert_eq!(entries.len(), 1);
        // Plain input passes through borrowed.
        let passthrough = decompress_if_gzip(&plain).unwrap();
        assert!(matches!(passthrough, Cow::Borrowed(_)));
    }

    // ---- malformed / hostile input ----

    #[test]
    fn empty_file_is_typed_error() {
        assert!(matches!(SnapshotReader::new(&[]), Err(ReadError::Empty)));
    }

    #[test]
    fn junk_header_length_overflow() {
        // Type 13 record whose length field is 0xFFFF_FFFF.
        let mut buf = Vec::new();
        buf.extend_from_slice(&TS.to_be_bytes());
        buf.extend_from_slice(&13u16.to_be_bytes());
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            SnapshotReader::new(&buf),
            Err(ReadError::RecordTooLarge { len: u32::MAX, .. })
        ));
    }

    #[test]
    fn short_header_is_truncated() {
        let full = encode_snapshot(COLLECTOR, &[], &[], &[], TS).unwrap();
        assert!(matches!(
            SnapshotReader::new(&full[..6]),
            Err(ReadError::Truncated { .. })
        ));
    }

    #[test]
    fn rib_before_peer_index_table() {
        let data = raw_record(13, 2, &[0; 16]);
        assert!(matches!(
            SnapshotReader::new(&data),
            Err(ReadError::MissingPeerIndexTable { subtype: 2 })
        ));
    }

    #[test]
    fn only_foreign_record_types_is_empty() {
        // A BGP4MP (type 16) record but no TABLE_DUMP_V2 at all.
        let data = raw_record(16, 4, &[0; 8]);
        assert!(matches!(SnapshotReader::new(&data), Err(ReadError::Empty)));
    }

    #[test]
    fn duplicate_peer_index_table_is_error() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        let copy = data.clone();
        data.extend_from_slice(&copy);
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (_, err) = drain(&mut reader);
        assert!(matches!(
            err,
            Some(ReadError::DuplicatePeerIndexTable { .. })
        ));
    }

    #[test]
    fn bad_peer_index_is_error() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        let entry = RibEntry {
            peer_index: 7,
            originated_time: TS,
            path_id: 0,
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
        };
        encode_rib_entries(&mut data, TS, 0, &v4_prefix(10, 0, 0, 0, 8), &[entry]).unwrap();
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (_, err) = drain(&mut reader);
        assert!(matches!(
            err,
            Some(ReadError::BadPeerIndex {
                index: 7,
                peer_count: 1
            })
        ));
    }

    #[test]
    fn unknown_subtypes_and_foreign_types_are_skipped_with_counter() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = make_peer(peer_addr, 65001);
        let route = make_route(v4_prefix(192, 168, 0, 0, 16), peer_addr, peer_addr);
        let mut data = encode_snapshot(
            COLLECTOR,
            std::slice::from_ref(&peer),
            std::slice::from_ref(&route),
            &[],
            TS,
        )
        .unwrap();
        // Unknown TABLE_DUMP_V2 subtype (3 = RIB_IPV4_MULTICAST).
        data.extend_from_slice(&raw_record(13, 3, &[0xAB; 10]));
        // Foreign MRT type (16 = BGP4MP).
        data.extend_from_slice(&raw_record(16, 4, &[0xCD; 10]));
        // RIB_GENERIC with a non-EVPN AFI/SAFI (IPv4 FlowSpec).
        let mut generic = Vec::new();
        generic.extend_from_slice(&0u32.to_be_bytes());
        generic.extend_from_slice(&1u16.to_be_bytes());
        generic.push(133);
        generic.extend_from_slice(&[0xEF; 6]);
        data.extend_from_slice(&raw_record(13, 6, &generic));
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none(), "skips must not error: {err:?}");
        assert_eq!(entries.len(), 1);
        assert_eq!(reader.skipped_records(), 3);
    }

    #[test]
    fn attr_length_overflowing_record_is_truncated_error() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        // RIB_IPV4_UNICAST payload: seq + /24 prefix + count=1 + entry
        // whose attr_len (0xFFFF) runs past the record end.
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.push(24);
        payload.extend_from_slice(&[192, 168, 1]);
        payload.extend_from_slice(&1u16.to_be_bytes());
        payload.extend_from_slice(&0u16.to_be_bytes()); // peer index
        payload.extend_from_slice(&TS.to_be_bytes()); // originated
        payload.extend_from_slice(&0xFFFFu16.to_be_bytes()); // attr_len
        data.extend_from_slice(&raw_record(13, 2, &payload));
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (_, err) = drain(&mut reader);
        assert!(matches!(err, Some(ReadError::Truncated { .. })));
    }

    /// RFC 7606 §7.6 permits omitting only the malformed attribute while the
    /// rest of the snapshot entry remains usable.
    #[test]
    fn nonzero_length_atomic_aggregate_is_discarded_and_counted() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        // ATOMIC_AGGREGATE with flags 0x40, length 1, one value byte.
        let attr = [attr_flags::TRANSITIVE, attr_type::ATOMIC_AGGREGATE, 1, 0];
        append_v4_rib_with_attributes(&mut data, &attr);
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none(), "unexpected error: {err:?}");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].attributes.is_empty());
        assert_eq!(reader.discarded_path_attributes(), 1);
        assert_eq!(reader.discarded_bgpls_nlris(), 0);
    }

    #[test]
    fn treat_as_withdraw_attribute_still_fails_and_fuses() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        // LOCAL_PREF must be four bytes. The conservative internal-neighbor
        // classification makes this treat-as-withdraw rather than discard.
        let attr = [attr_flags::TRANSITIVE, attr_type::LOCAL_PREF, 3, 0, 0, 100];
        append_v4_rib_with_attributes(&mut data, &attr);
        let mut reader = SnapshotReader::new(&data).unwrap();
        assert!(matches!(
            reader.next(),
            Some(Err(ReadError::AttributeDecode(
                DecodeError::UpdateAttributeError { .. }
            )))
        ));
        assert!(reader.next().is_none());
        assert_eq!(reader.discarded_path_attributes(), 0);
        assert_eq!(reader.discarded_bgpls_nlris(), 0);
    }

    #[test]
    fn reduced_mp_reach_flag_conflict_fails_and_fuses() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        let attr = [
            attr_flags::OPTIONAL | attr_flags::TRANSITIVE,
            attr_type::MP_REACH_NLRI,
            5,
            4,
            192,
            0,
            2,
            1,
        ];
        let expected =
            rustbgpd_wire::attribute::decode_path_attributes_revised(&attr, true, true, &[])
                .unwrap_err();
        assert!(matches!(
            &expected,
            DecodeError::UpdateAttributeError {
                subcode: update_subcode::ATTRIBUTE_FLAGS_ERROR,
                ..
            }
        ));
        append_v4_rib_with_attributes(&mut data, &attr);
        let mut reader = SnapshotReader::new(&data).unwrap();
        let Some(Err(ReadError::AttributeDecode(actual))) = reader.next() else {
            panic!("expected reduced MP_REACH attribute-flags failure");
        };
        assert_eq!(actual, expected);
        assert!(reader.next().is_none());
        assert_eq!(reader.discarded_path_attributes(), 0);
        assert_eq!(reader.discarded_bgpls_nlris(), 0);
    }

    /// Collectors that write the full RFC 4760 `MP_REACH_NLRI` (AFI, SAFI,
    /// NH-Len, next hop, reserved octet) into a RIB entry must read back like
    /// the RFC 6396 §4.3.4 reduced form.
    #[test]
    fn full_form_mp_reach_in_rib_entry_yields_next_hop() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        let attr = [
            attr_flags::OPTIONAL,
            attr_type::MP_REACH_NLRI,
            9,
            0,
            1, // AFI 1
            1, // SAFI 1
            4, // NH-Len
            192,
            0,
            2,
            1,
            0, // reserved
        ];
        append_v4_rib_with_attributes(&mut data, &attr);
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none(), "unexpected error: {err:?}");
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].next_hop,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(entries[0].link_local_next_hop, None);
        assert!(entries[0].attributes.is_empty());
    }

    #[test]
    fn recovery_counters_exclude_entries_not_yielded_before_record_failure() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        let discarded = [attr_flags::TRANSITIVE, attr_type::ATOMIC_AGGREGATE, 1, 0];
        let stronger = [attr_flags::TRANSITIVE, attr_type::LOCAL_PREF, 3, 0, 0, 100];
        append_v4_rib_attribute_entries(&mut data, &[&discarded, &stronger]);
        let mut reader = SnapshotReader::new(&data).unwrap();
        assert!(matches!(
            reader.next(),
            Some(Err(ReadError::AttributeDecode(_)))
        ));
        assert!(reader.next().is_none());
        assert_eq!(reader.discarded_path_attributes(), 0);
        assert_eq!(reader.discarded_bgpls_nlris(), 0);
    }

    #[test]
    fn duplicate_ordinary_attribute_keeps_first_and_counts_duplicate() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        let attrs = [
            attr_flags::TRANSITIVE,
            attr_type::LOCAL_PREF,
            4,
            0,
            0,
            0,
            100,
            attr_flags::TRANSITIVE,
            attr_type::LOCAL_PREF,
            4,
            0,
            0,
            0,
            200,
        ];
        append_v4_rib_with_attributes(&mut data, &attrs);
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none(), "unexpected error: {err:?}");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attributes, vec![PathAttribute::LocalPref(100)]);
        assert_eq!(reader.discarded_path_attributes(), 1);
        assert_eq!(reader.discarded_bgpls_nlris(), 0);
    }

    #[test]
    fn bgpls_nlri_discard_is_counted_separately() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        append_v4_rib_with_attributes(&mut data, &discarded_bgpls_mp_unreach_attribute());
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (entries, err) = drain(&mut reader);
        assert!(err.is_none(), "unexpected error: {err:?}");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].attributes.len(), 1);
        assert_eq!(reader.discarded_path_attributes(), 0);
        assert_eq!(reader.discarded_bgpls_nlris(), 1);
    }

    #[test]
    fn bad_prefix_length_is_malformed() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        let mut payload = Vec::new();
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.push(33); // /33 is invalid for IPv4
        data.extend_from_slice(&raw_record(13, 2, &payload));
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (_, err) = drain(&mut reader);
        assert!(matches!(err, Some(ReadError::Malformed { .. })));
    }

    #[test]
    fn truncated_peer_table_is_error() {
        // Peer table claiming 2 peers but carrying only the header.
        let mut payload = Vec::new();
        payload.extend_from_slice(&COLLECTOR.octets());
        payload.extend_from_slice(&0u16.to_be_bytes()); // view name len
        payload.extend_from_slice(&2u16.to_be_bytes()); // peer count
        let data = raw_record(13, 1, &payload);
        assert!(matches!(
            SnapshotReader::new(&data),
            Err(ReadError::Truncated { .. })
        ));
    }

    #[test]
    fn peer_table_as2_and_ipv6_peer_types_parse() {
        // Writer always emits AS4, but the reader accepts all four
        // RFC 6396 peer-type combinations.
        let mut payload = Vec::new();
        payload.extend_from_slice(&COLLECTOR.octets());
        payload.extend_from_slice(&0u16.to_be_bytes());
        payload.extend_from_slice(&2u16.to_be_bytes());
        // Peer 0: IPv4 + AS2.
        payload.push(0b00);
        payload.extend_from_slice(&[9, 9, 9, 9]); // bgp id
        payload.extend_from_slice(&[10, 0, 0, 1]); // addr
        payload.extend_from_slice(&65001u16.to_be_bytes());
        // Peer 1: IPv6 + AS4.
        payload.push(0b11);
        payload.extend_from_slice(&[9, 9, 9, 10]);
        payload.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());
        payload.extend_from_slice(&4_200_000_000u32.to_be_bytes());
        let data = raw_record(13, 1, &payload);
        let reader = SnapshotReader::new(&data).unwrap();
        assert_eq!(reader.peers().len(), 2);
        assert_eq!(reader.peers()[0].peer_asn, 65001);
        assert_eq!(
            reader.peers()[0].peer_addr,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(reader.peers()[1].peer_asn, 4_200_000_000);
        assert_eq!(
            reader.peers()[1].peer_addr,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    /// The entry-level error carries the absolute file offset of the
    /// attribute value the shared wire decoder rejected.
    #[test]
    fn rib_entry_mp_reach_trailing_octets_fail_the_entry_at_absolute_offset() {
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        let attr = [
            attr_flags::OPTIONAL,
            attr_type::MP_REACH_NLRI,
            6,
            4,
            192,
            0,
            2,
            1,
            0xAB,
        ];
        // The attribute value starts 3 octets after the attribute header.
        let value_offset = data.len() + 12 + 4 + 1 + 3 + 2 + 2 + 4 + 2 + 3;
        append_v4_rib_with_attributes(&mut data, &attr);
        let mut reader = SnapshotReader::new(&data).unwrap();
        let (entries, err) = drain(&mut reader);
        assert!(entries.is_empty());
        let Some(ReadError::Malformed { offset, context }) = err else {
            panic!("expected Malformed, got {err:?}");
        };
        assert!(context.contains("1 trailing octets"), "{context}");
        assert_eq!(offset, value_offset);
    }

    #[test]
    fn entry_cap_is_enforced() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = make_peer(peer_addr, 65001);
        let routes = vec![
            make_route(v4_prefix(192, 168, 0, 0, 16), peer_addr, peer_addr),
            make_route(v4_prefix(198, 51, 100, 0, 24), peer_addr, peer_addr),
        ];
        let data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &routes, &[], TS).unwrap();
        let mut reader = SnapshotReader::new(&data).unwrap();
        reader.set_entry_cap(1);
        let (entries, err) = drain(&mut reader);
        assert_eq!(entries.len(), 1);
        assert!(matches!(err, Some(ReadError::TooManyEntries { cap: 1 })));
    }

    #[test]
    fn iterator_fuses_after_error() {
        let data = raw_record(13, 1, &[0; 2]); // truncated peer table
        assert!(SnapshotReader::new(&data).is_err());
        // And a reader that errors mid-iteration stays fused.
        let peer = make_peer(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 65001);
        let mut data =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &[], &[], TS).unwrap();
        data.extend_from_slice(&raw_record(13, 2, &[0; 3])); // truncated RIB record
        let mut reader = SnapshotReader::new(&data).unwrap();
        assert!(matches!(reader.next(), Some(Err(_))));
        assert!(reader.next().is_none());
        assert!(reader.next().is_none());
    }

    #[test]
    fn corrupt_gzip_is_typed_error() {
        assert!(matches!(
            decompress_if_gzip(&[0x1f, 0x8b, 0xde, 0xad, 0xbe, 0xef]),
            Err(ReadError::Gzip(_))
        ));
    }

    /// Mini-fuzz: truncating a rich snapshot at every byte boundary
    /// must never panic — it yields either a typed error or a subset
    /// of the entries (MRT has no trailer, so a cut at a record
    /// boundary is indistinguishable from a shorter file).
    #[test]
    fn truncation_at_every_boundary_never_panics() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = make_peer(peer_addr, 65001);
        let mut addpath = make_route(v4_prefix(10, 0, 0, 0, 8), peer_addr, peer_addr);
        addpath.path_id = 3;
        let routes = vec![
            make_route(v4_prefix(192, 168, 0, 0, 16), peer_addr, peer_addr),
            make_route(
                Prefix::V6(Ipv6Prefix {
                    addr: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                    len: 32,
                }),
                peer_addr,
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            ),
            addpath,
        ];
        let evpn = vec![make_evpn_macip(peer_addr, peer_addr)];
        let full =
            encode_snapshot(COLLECTOR, std::slice::from_ref(&peer), &routes, &evpn, TS).unwrap();
        let full_count = {
            let mut r = SnapshotReader::new(&full).unwrap();
            let (entries, err) = drain(&mut r);
            assert!(err.is_none());
            entries.len()
        };
        assert_eq!(full_count, 4);
        for cut in 0..full.len() {
            match SnapshotReader::new(&full[..cut]) {
                Err(_) => {}
                Ok(mut reader) => {
                    let (entries, _err) = drain(&mut reader);
                    assert!(
                        entries.len() <= full_count,
                        "truncated input at {cut} yielded more entries than the full file"
                    );
                }
            }
        }
    }

    /// Flipping each byte of a valid snapshot must never panic.
    #[test]
    fn bitflip_at_every_byte_never_panics() {
        let peer_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer = make_peer(peer_addr, 65001);
        let route = make_route(v4_prefix(192, 168, 0, 0, 16), peer_addr, peer_addr);
        let full = encode_snapshot(
            COLLECTOR,
            std::slice::from_ref(&peer),
            std::slice::from_ref(&route),
            &[],
            TS,
        )
        .unwrap();
        for i in 0..full.len() {
            let mut mutated = full.clone();
            mutated[i] ^= 0xFF;
            if let Ok(mut reader) = SnapshotReader::new(&mutated) {
                let _ = drain(&mut reader);
            }
        }
    }
}
