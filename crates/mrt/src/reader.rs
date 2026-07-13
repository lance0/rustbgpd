//! Streaming reader for MRT `TABLE_DUMP_V2` files (RFC 6396 §4.3,
//! RFC 8050 Add-Path subtypes).
//!
//! Counterpart to the encoder in [`crate::codec`]: validates the leading
//! `PEER_INDEX_TABLE`, then yields one decoded [`SnapshotEntry`] per RIB
//! entry. Everything the writer emits round-trips; records the reader
//! does not understand (non-`TABLE_DUMP_V2` MRT types, unknown
//! `TABLE_DUMP_V2` subtypes, `RIB_GENERIC` with an AFI/SAFI other than
//! L2VPN/EVPN) are skipped and counted, not treated as errors.
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
use rustbgpd_wire::{Afi, Ipv4Prefix, Ipv6Prefix, PathAttribute, Prefix, Safi};
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
    /// Decoded path attributes, excluding `MP_REACH_NLRI` — the MRT
    /// reduced form (RFC 6396 §4.3.4) carries only the next-hop, which
    /// is surfaced via `next_hop` / `link_local_next_hop` instead.
    pub attributes: Vec<PathAttribute>,
    /// Next-hop: from the reduced `MP_REACH_NLRI` if present, else
    /// from a `NEXT_HOP` attribute, else `None`.
    pub next_hop: Option<IpAddr>,
    /// Link-local IPv6 next-hop when the reduced `MP_REACH_NLRI`
    /// carried the 32-byte global + link-local form.
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

/// Decode the MRT-reduced `MP_REACH_NLRI` value (RFC 6396 §4.3.4):
/// NH-Len byte followed by 4, 16, or 32 next-hop octets.
fn parse_reduced_mp_reach(
    value: &[u8],
    offset: usize,
) -> Result<(IpAddr, Option<Ipv6Addr>), ReadError> {
    let Some((&nh_len, rest)) = value.split_first() else {
        return Err(malformed(offset, "empty MP_REACH_NLRI value"));
    };
    if rest.len() != usize::from(nh_len) {
        return Err(malformed(
            offset,
            format!(
                "MP_REACH_NLRI NH-Len {nh_len} does not match {} value bytes",
                rest.len()
            ),
        ));
    }
    match nh_len {
        4 => {
            let o: [u8; 4] = rest.try_into().expect("length checked above");
            Ok((IpAddr::V4(Ipv4Addr::from(o)), None))
        }
        16 => {
            let o: [u8; 16] = rest.try_into().expect("length checked above");
            Ok((IpAddr::V6(Ipv6Addr::from(o)), None))
        }
        32 => {
            let g: [u8; 16] = rest[..16].try_into().expect("length checked above");
            let ll: [u8; 16] = rest[16..].try_into().expect("length checked above");
            Ok((IpAddr::V6(Ipv6Addr::from(g)), Some(Ipv6Addr::from(ll))))
        }
        other => Err(malformed(
            offset,
            format!("unsupported MP_REACH_NLRI NH-Len {other}"),
        )),
    }
}

/// Decoded attribute block of one RIB entry.
struct EntryAttributes {
    attributes: Vec<PathAttribute>,
    next_hop: Option<IpAddr>,
    link_local_next_hop: Option<Ipv6Addr>,
}

/// Split a RIB entry's attribute block: walk the TLV framing with
/// bounds checks, peel off the MRT-reduced `MP_REACH_NLRI`, and decode
/// the remaining attributes with the standard wire decoder
/// (`four_octet_as = true`, matching the writer).
fn decode_entry_attributes(attrs: &[u8], base: usize) -> Result<EntryAttributes, ReadError> {
    let mut cur = Cur::new(attrs, base);
    let mut other: Vec<u8> = Vec::with_capacity(attrs.len());
    let mut reduced: Option<(IpAddr, Option<Ipv6Addr>)> = None;
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
        let value = cur.take(value_len, "attribute value")?;
        if type_code == attr_type::MP_REACH_NLRI {
            if reduced.is_some() {
                return Err(malformed(attr_offset, "duplicate MP_REACH_NLRI"));
            }
            reduced = Some(parse_reduced_mp_reach(value, attr_offset)?);
        } else {
            other.extend_from_slice(&attrs[span_start..cur.rel_pos()]);
        }
    }
    let attributes = rustbgpd_wire::attribute::decode_path_attributes(&other, true, &[])?;
    let (next_hop, link_local_next_hop) = match reduced {
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
    })
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
    pending: VecDeque<SnapshotEntry>,
    skipped_records: u64,
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
        self.pending.push_back(SnapshotEntry {
            nlri: nlri.clone(),
            peer_index,
            peer: peer.clone(),
            originated_time,
            path_id,
            add_path,
            attributes: decoded.attributes,
            next_hop: decoded.next_hop,
            link_local_next_hop: decoded.link_local_next_hop,
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
            if let Some(entry) = self.pending.pop_front() {
                return Some(Ok(entry));
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

    #[test]
    fn reduced_mp_reach_bad_nh_len_is_malformed() {
        assert!(matches!(
            parse_reduced_mp_reach(&[5, 1, 2, 3, 4, 5], 0),
            Err(ReadError::Malformed { .. })
        ));
        assert!(matches!(
            parse_reduced_mp_reach(&[], 0),
            Err(ReadError::Malformed { .. })
        ));
        // NH-Len valid but value short.
        assert!(matches!(
            parse_reduced_mp_reach(&[16, 0, 0], 0),
            Err(ReadError::Malformed { .. })
        ));
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
