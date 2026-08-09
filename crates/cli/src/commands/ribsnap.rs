//! `rbgp diff snapshot from-mrt` — convert an RFC 6396 `TABLE_DUMP_V2`
//! MRT dump into an `rbgp-ribsnap/1` NDJSON snapshot for `rbgp diff
//! advertised` (adapter contract `from-mrt/1`, see docs/ribdiff.md).
//!
//! Honesty contract: `TABLE_DUMP_V2` is, by default, a *collector RIB
//! view* — not a per-client post-policy Adj-RIB-Out. The required
//! `--view` flag is the producer's attestation of what the dump actually
//! is: only `adj-rib-out-capture` (the dump was produced by capturing
//! one client's post-policy advertised routes) yields a snapshot;
//! `loc-rib` and `adj-rib-in` are refused (exit 2) because comparing
//! them against an Adj-RIB-Out would manufacture false divergence or,
//! worse, false equality.
//!
//! Fail-closed emission: output is buffered and printed only after the
//! entire dump parses; the counted completion trailer is therefore only
//! ever present on a fully-converted snapshot. Any parse error exits 2
//! with nothing written to stdout.
//!
//! Wire notes (RFC 6396 §4.3.4): AS_PATH is always 4-octet;
//! `MP_REACH_NLRI` inside RIB entries is abbreviated to next-hop-only,
//! but some collectors emit the full RFC 4760 form — a leading zero
//! octet can only be an AFI high byte (next-hop length 0 is invalid),
//! which disambiguates. RFC 8050 Add-Path subtypes (8/9) carry a path
//! identifier per entry, emitted as `path_id`.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use crate::output;
use rustbgpd_wire::constants::{attr_flags, attr_type};

/// Snapshot emitted.
pub const EXIT_OK: i32 = 0;
/// Refused (non-comparable view) or malformed/unreadable input.
pub const EXIT_REFUSED: i32 = 2;

/// MRT message type for `TABLE_DUMP_V2` (RFC 6396 §4.3).
const TABLE_DUMP_V2: u16 = 13;
/// Subtypes ingested (plus RFC 8050 Add-Path variants). Everything else
/// — `PEER_INDEX_TABLE`, multicast, `RIB_GENERIC` — is skipped.
const RIB_IPV4_UNICAST: u16 = 2;
const RIB_IPV6_UNICAST: u16 = 4;
const RIB_IPV4_UNICAST_ADDPATH: u16 = 8;
const RIB_IPV6_UNICAST_ADDPATH: u16 = 9;

/// Options for `rbgp diff snapshot from-mrt`.
pub struct FromMrtOpts<'a> {
    pub file: &'a Path,
    /// Producer's attestation of what the dump is. Only
    /// `adj-rib-out-capture` is comparable.
    pub view: &'a str,
    /// Peer the captured routes were advertised **to**.
    pub peer: &'a str,
    pub peer_asn: u32,
    /// Free-form provenance label appended to the header `source`.
    pub source: Option<&'a str>,
    pub generation: u64,
}

/// An attribute outside the typed snapshot fields, preserved as its wire
/// triple (flags, type code, value octets) in `unknown_attrs`.
pub(crate) type UnknownWireAttr = (u8, u8, Vec<u8>);

/// One decoded RIB entry, reduced to the `rbgp-ribsnap/1` route fields.
/// Absent attributes stay `None`/empty — never defaulted.
#[derive(Default)]
pub(crate) struct SnapRoute {
    pub(crate) path_id: Option<u32>,
    pub(crate) origin: Option<u8>,
    pub(crate) as_path: Vec<u32>,
    pub(crate) next_hop: Option<IpAddr>,
    pub(crate) med: Option<u32>,
    pub(crate) local_pref: Option<u32>,
    pub(crate) communities: Vec<u32>,
    pub(crate) extended_communities: Vec<u64>,
    pub(crate) large_communities: Vec<[u32; 3]>,
    /// Untyped attributes preserved byte-exact (see `unknown_attrs` in
    /// docs/ribdiff.md). The MRT adapter leaves this empty (documented
    /// limitation); the BMP adapter fills it.
    pub(crate) unknown_attrs: Vec<UnknownWireAttr>,
}

/// Run the adapter: print the snapshot to stdout on success, an error to
/// stderr on refusal, and return the exit code.
pub fn from_mrt(opts: &FromMrtOpts<'_>) -> i32 {
    let result = run(opts);
    let stdout = std::io::stdout();
    emit_mrt_snapshot(result, &mut stdout.lock())
}

fn emit_mrt_snapshot(result: Result<String, String>, writer: &mut dyn std::io::Write) -> i32 {
    match result {
        Ok(snapshot) => match output::write_bytes(writer, snapshot.as_bytes()) {
            Ok(()) => EXIT_OK,
            Err(error) => {
                output::report_write_error("MRT snapshot output", &error);
                EXIT_REFUSED
            }
        },
        Err(e) => {
            eprintln!("Error: {e}");
            EXIT_REFUSED
        }
    }
}

fn run(opts: &FromMrtOpts<'_>) -> Result<String, String> {
    if opts.view != "adj-rib-out-capture" {
        return Err(format!(
            "view {:?} is not comparable against an Adj-RIB-Out: a TABLE_DUMP_V2 dump of a \
             {} is not a per-client post-policy advertised view, and comparing it would \
             report false divergence (or false equality). Re-capture the incumbent's \
             per-client Adj-RIB-Out and attest it with --view adj-rib-out-capture.",
            opts.view,
            match opts.view {
                "loc-rib" => "Loc-RIB (collector/local best paths)".to_string(),
                "adj-rib-in" => "pre-policy Adj-RIB-In".to_string(),
                other => format!("{other} view"),
            }
        ));
    }
    let peer: IpAddr = opts
        .peer
        .parse()
        .map_err(|e| format!("invalid --peer address {:?}: {e}", opts.peer))?;
    let data = std::fs::read(opts.file)
        .map_err(|e| format!("cannot read {}: {e}", opts.file.display()))?;
    let routes = parse_mrt(&data).map_err(|e| format!("{}: {e}", opts.file.display()))?;
    Ok(render(opts, peer, &routes))
}

/// Render the full NDJSON snapshot (header, routes, counted trailer).
fn render(opts: &FromMrtOpts<'_>, peer: IpAddr, routes: &[(IpAddr, u8, SnapRoute)]) -> String {
    let mut out = String::new();
    // Adapter contract `from-mrt/1` (see docs/ribdiff.md): adapter id +
    // attested view + optional free-form label.
    let mut source = "from-mrt/1 view=adj-rib-out-capture".to_string();
    if let Some(label) = opts.source {
        let _ = write!(source, " {label}");
    }
    let header = serde_json::json!({
        "record": "header",
        "schema": super::diff::SNAPSHOT_SCHEMA,
        "source": source,
        "generation": opts.generation,
    });
    out.push_str(&header.to_string());
    out.push('\n');
    for (addr, len, route) in routes {
        out.push_str(&route_record_json(peer, opts.peer_asn, *addr, *len, route));
        out.push('\n');
    }
    let trailer = serde_json::json!({"record": "trailer", "routes": routes.len()});
    out.push_str(&trailer.to_string());
    out.push('\n');
    out
}

/// Render one `rbgp-ribsnap/1` route record (shared by the MRT and BMP
/// adapters). Absent attributes are omitted, never defaulted.
pub(crate) fn route_record_json(
    peer: IpAddr,
    peer_asn: u32,
    addr: IpAddr,
    len: u8,
    route: &SnapRoute,
) -> String {
    let mut record = serde_json::json!({
        "record": "route",
        "peer": peer.to_string(),
        "peer_asn": peer_asn,
        "prefix": format!("{addr}/{len}"),
    });
    let object = record.as_object_mut().expect("literal object");
    if let Some(origin) = route.origin {
        object.insert("origin".into(), origin.into());
    }
    if !route.as_path.is_empty() {
        object.insert("as_path".into(), route.as_path.clone().into());
    }
    if let Some(next_hop) = route.next_hop {
        object.insert("next_hop".into(), next_hop.to_string().into());
    }
    if let Some(med) = route.med {
        object.insert("med".into(), med.into());
    }
    if let Some(local_pref) = route.local_pref {
        object.insert("local_pref".into(), local_pref.into());
    }
    if !route.communities.is_empty() {
        object.insert("communities".into(), route.communities.clone().into());
    }
    if !route.extended_communities.is_empty() {
        object.insert(
            "extended_communities".into(),
            route.extended_communities.clone().into(),
        );
    }
    if !route.large_communities.is_empty() {
        let rendered: Vec<String> = route
            .large_communities
            .iter()
            .map(|[a, b, c]| format!("{a}:{b}:{c}"))
            .collect();
        object.insert("large_communities".into(), rendered.into());
    }
    if !route.unknown_attrs.is_empty() {
        let rendered: Vec<serde_json::Value> = route
            .unknown_attrs
            .iter()
            .map(|(flags, type_code, value)| {
                let hex: String = value.iter().fold(String::new(), |mut s, b| {
                    let _ = write!(s, "{b:02x}");
                    s
                });
                serde_json::json!({"flags": flags, "type_code": type_code, "value": hex})
            })
            .collect();
        object.insert("unknown_attrs".into(), rendered.into());
    }
    if let Some(path_id) = route.path_id {
        object.insert("path_id".into(), path_id.into());
    }
    record.to_string()
}

/// Bounds-checked big-endian reader over a byte slice (shared by the MRT
/// and BMP adapters).
pub(crate) struct Cursor<'a> {
    buf: &'a [u8],
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub(crate) fn remaining(&self) -> &'a [u8] {
        self.buf
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.buf.len() < n {
            return Err(format!(
                "truncated record: need {n} bytes, have {}",
                self.buf.len()
            ));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn read_u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn read_u16(&mut self) -> Result<u16, String> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn read_u32(&mut self) -> Result<u32, String> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn read_u64(&mut self) -> Result<u64, String> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(b.try_into().expect("length checked")))
    }
}

/// Parse a `TABLE_DUMP_V2` dump into (prefix, length, route) entries, one
/// per RIB entry (Add-Path duplicates stay duplicates — the snapshot
/// format compares multiplicity).
fn parse_mrt(data: &[u8]) -> Result<Vec<(IpAddr, u8, SnapRoute)>, String> {
    let mut cur = Cursor::new(data);
    let mut routes = Vec::new();
    let mut rib_records = 0_usize;
    while !cur.is_empty() {
        let _timestamp = cur.read_u32()?;
        let mrt_type = cur.read_u16()?;
        let subtype = cur.read_u16()?;
        let length = cur.read_u32()? as usize;
        let payload = cur.take(length)?;
        if mrt_type != TABLE_DUMP_V2 {
            continue;
        }
        let (v6, addpath) = match subtype {
            RIB_IPV4_UNICAST => (false, false),
            RIB_IPV6_UNICAST => (true, false),
            RIB_IPV4_UNICAST_ADDPATH => (false, true),
            RIB_IPV6_UNICAST_ADDPATH => (true, true),
            _ => continue,
        };
        parse_rib_record(payload, v6, addpath, &mut routes)
            .map_err(|e| format!("TABLE_DUMP_V2 subtype {subtype}: {e}"))?;
        rib_records += 1;
    }
    if rib_records == 0 {
        return Err(
            "no TABLE_DUMP_V2 IPv4/IPv6 unicast RIB records found (is this a RIB dump?)"
                .to_string(),
        );
    }
    Ok(routes)
}

/// Parse one `RIB_IPV4_UNICAST`/`RIB_IPV6_UNICAST` record (RFC 6396
/// §4.3.2), optionally with RFC 8050 path identifiers. Every RIB entry
/// becomes one snapshot route record.
fn parse_rib_record(
    payload: &[u8],
    v6: bool,
    addpath: bool,
    routes: &mut Vec<(IpAddr, u8, SnapRoute)>,
) -> Result<(), String> {
    let mut cur = Cursor::new(payload);
    let _sequence = cur.read_u32()?;
    let prefix_len = cur.read_u8()?;
    let prefix_bytes = cur.take((prefix_len as usize).div_ceil(8))?;
    let addr = decode_prefix(prefix_bytes, prefix_len, v6)?;
    let entry_count = cur.read_u16()?;
    for _ in 0..entry_count {
        let _peer_index = cur.read_u16()?;
        let _originated_time = cur.read_u32()?;
        let path_id = if addpath { Some(cur.read_u32()?) } else { None };
        let attr_len = cur.read_u16()? as usize;
        let attrs = cur.take(attr_len)?;
        let mut route = parse_attributes(attrs)?;
        route.path_id = path_id;
        routes.push((addr, prefix_len, route));
    }
    Ok(())
}

fn decode_prefix(bytes: &[u8], prefix_len: u8, v6: bool) -> Result<IpAddr, String> {
    if v6 {
        if prefix_len > 128 {
            return Err(format!("IPv6 prefix length {prefix_len} exceeds 128"));
        }
        let mut octets = [0_u8; 16];
        octets[..bytes.len()].copy_from_slice(bytes);
        Ok(IpAddr::V6(Ipv6Addr::from(octets)))
    } else {
        if prefix_len > 32 {
            return Err(format!("IPv4 prefix length {prefix_len} exceeds 32"));
        }
        let mut octets = [0_u8; 4];
        octets[..bytes.len()].copy_from_slice(bytes);
        Ok(IpAddr::V4(Ipv4Addr::from(octets)))
    }
}

/// Walk one RIB entry's BGP path attributes. A purpose-built walk rather
/// than the wire crate's UPDATE decoder because RFC 6396 §4.3.4
/// abbreviates `MP_REACH_NLRI` inside RIB entries (next-hop only, no
/// AFI/SAFI/NLRI), which the standard decoder rejects.
fn parse_attributes(mut buf: &[u8]) -> Result<SnapRoute, String> {
    let mut route = SnapRoute::default();
    while !buf.is_empty() {
        if buf.len() < 3 {
            return Err("truncated path attribute header".to_string());
        }
        let flags = buf[0];
        let type_code = buf[1];
        let (value_len, header_len) = if flags & attr_flags::EXTENDED_LENGTH != 0 {
            if buf.len() < 4 {
                return Err("truncated extended-length path attribute".to_string());
            }
            (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
        } else {
            (buf[2] as usize, 3)
        };
        if buf.len() < header_len + value_len {
            return Err(format!("path attribute type {type_code} value truncated"));
        }
        let value = &buf[header_len..header_len + value_len];
        buf = &buf[header_len + value_len..];
        match type_code {
            attr_type::ORIGIN => {
                let &[origin] = value else {
                    return Err(format!("ORIGIN length {} != 1", value.len()));
                };
                if origin > 2 {
                    return Err(format!("invalid ORIGIN {origin}"));
                }
                route.origin = Some(origin);
            }
            attr_type::AS_PATH => route.as_path = parse_as_path(value)?,
            attr_type::NEXT_HOP => {
                let octets: [u8; 4] = value
                    .try_into()
                    .map_err(|_| format!("NEXT_HOP length {} != 4", value.len()))?;
                route.next_hop = Some(IpAddr::V4(Ipv4Addr::from(octets)));
            }
            attr_type::MULTI_EXIT_DISC => {
                let octets: [u8; 4] = value
                    .try_into()
                    .map_err(|_| format!("MULTI_EXIT_DISC length {} != 4", value.len()))?;
                route.med = Some(u32::from_be_bytes(octets));
            }
            attr_type::LOCAL_PREF => {
                let octets: [u8; 4] = value
                    .try_into()
                    .map_err(|_| format!("LOCAL_PREF length {} != 4", value.len()))?;
                route.local_pref = Some(u32::from_be_bytes(octets));
            }
            attr_type::COMMUNITIES => {
                if !value.len().is_multiple_of(4) {
                    return Err(format!(
                        "COMMUNITIES length {} not a multiple of 4",
                        value.len()
                    ));
                }
                route.communities = value
                    .chunks_exact(4)
                    .map(|c| u32::from_be_bytes([c[0], c[1], c[2], c[3]]))
                    .collect();
            }
            attr_type::EXTENDED_COMMUNITIES => {
                if !value.len().is_multiple_of(8) {
                    return Err(format!(
                        "EXTENDED_COMMUNITIES length {} not a multiple of 8",
                        value.len()
                    ));
                }
                route.extended_communities = value
                    .chunks_exact(8)
                    .map(|c| u64::from_be_bytes(c.try_into().expect("chunk of 8")))
                    .collect();
            }
            attr_type::LARGE_COMMUNITIES => {
                if !value.len().is_multiple_of(12) {
                    return Err(format!(
                        "LARGE_COMMUNITIES length {} not a multiple of 12",
                        value.len()
                    ));
                }
                route.large_communities = value
                    .chunks_exact(12)
                    .map(|c| {
                        [
                            u32::from_be_bytes([c[0], c[1], c[2], c[3]]),
                            u32::from_be_bytes([c[4], c[5], c[6], c[7]]),
                            u32::from_be_bytes([c[8], c[9], c[10], c[11]]),
                        ]
                    })
                    .collect();
            }
            attr_type::MP_REACH_NLRI => route.next_hop = Some(mp_reach_next_hop(value)?),
            _ => {}
        }
    }
    Ok(route)
}

/// Flatten AS_PATH segments (4-octet ASNs — mandatory in `TABLE_DUMP_V2`
/// per RFC 6396 §4.3.4). Segment boundaries are dropped: the snapshot
/// format compares the flattened sequence (documented consumer
/// limitation).
fn parse_as_path(mut value: &[u8]) -> Result<Vec<u32>, String> {
    let mut path = Vec::new();
    while !value.is_empty() {
        if value.len() < 2 {
            return Err("truncated AS_PATH segment header".to_string());
        }
        let asn_count = value[1] as usize;
        let segment_len = 2 + asn_count * 4;
        if value.len() < segment_len {
            return Err("truncated AS_PATH segment".to_string());
        }
        for chunk in value[2..segment_len].chunks_exact(4) {
            path.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        value = &value[segment_len..];
    }
    Ok(path)
}

/// Extract the next hop from a RIB-entry `MP_REACH_NLRI`.
///
/// RFC 6396 §4.3.4 form: next-hop length (1 octet) + next hop. Some
/// collectors emit the full RFC 4760 form instead (AFI + SAFI + length +
/// next hop + ...); a leading zero octet can only be an AFI high byte
/// (a next-hop length of 0 is invalid), which disambiguates the two.
fn mp_reach_next_hop(value: &[u8]) -> Result<IpAddr, String> {
    let (&first, _) = value
        .split_first()
        .ok_or_else(|| "empty MP_REACH_NLRI".to_string())?;
    let (nh_len, nh_start) = if first == 0 {
        if value.len() < 4 {
            return Err("truncated RFC 4760-form MP_REACH_NLRI".to_string());
        }
        (value[3] as usize, 4)
    } else {
        (first as usize, 1)
    };
    if value.len() < nh_start + nh_len {
        return Err("truncated MP_REACH_NLRI next hop".to_string());
    }
    let nh = &value[nh_start..nh_start + nh_len];
    match nh_len {
        4 => {
            let octets: [u8; 4] = nh.try_into().expect("length checked");
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        // 32 = global + link-local pair; the global address comes first.
        16 | 32 => {
            let octets: [u8; 16] = nh[..16].try_into().expect("length checked");
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        n => Err(format!("unsupported MP_REACH_NLRI next hop length {n}")),
    }
}

#[cfg(test)]
pub(crate) mod test_fixture {
    //! Hand-encoded `TABLE_DUMP_V2` bytes shared by the unit tests and
    //! the golden-fixture tests in `commands::diff`.

    use super::*;

    pub(crate) fn mrt_record(subtype: u16, payload: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0_u32.to_be_bytes()); // timestamp
        buf.extend_from_slice(&TABLE_DUMP_V2.to_be_bytes());
        buf.extend_from_slice(&subtype.to_be_bytes());
        buf.extend_from_slice(&u32::try_from(payload.len()).unwrap().to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    pub(crate) fn attr(type_code: u8, value: &[u8]) -> Vec<u8> {
        let mut buf = vec![0x40, type_code, u8::try_from(value.len()).unwrap()];
        buf.extend_from_slice(value);
        buf
    }

    /// AS_PATH with one AS_SEQUENCE segment of 4-octet ASNs.
    pub(crate) fn as_path_attr(asns: &[u32]) -> Vec<u8> {
        let mut value = vec![2, u8::try_from(asns.len()).unwrap()];
        for asn in asns {
            value.extend_from_slice(&asn.to_be_bytes());
        }
        attr(attr_type::AS_PATH, &value)
    }

    /// One RIB record's payload with `entries` of (path_id, attrs).
    pub(crate) fn rib_payload(
        prefix_len: u8,
        prefix: &[u8],
        entries: &[(Option<u32>, Vec<u8>)],
    ) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&1_u32.to_be_bytes()); // sequence
        payload.push(prefix_len);
        payload.extend_from_slice(prefix);
        payload.extend_from_slice(&u16::try_from(entries.len()).unwrap().to_be_bytes());
        for (path_id, attrs) in entries {
            payload.extend_from_slice(&0_u16.to_be_bytes()); // peer index
            payload.extend_from_slice(&0_u32.to_be_bytes()); // originated time
            if let Some(id) = path_id {
                payload.extend_from_slice(&id.to_be_bytes());
            }
            payload.extend_from_slice(&u16::try_from(attrs.len()).unwrap().to_be_bytes());
            payload.extend_from_slice(attrs);
        }
        payload
    }

    /// The full sample dump: a skipped `PEER_INDEX_TABLE`, an IPv4
    /// unicast record with the full attribute set (ORIGIN, AS_PATH,
    /// NEXT_HOP, MED, LOCAL_PREF, standard + extended + large
    /// communities), and an RFC 8050 Add-Path IPv6 record with two
    /// entries (abbreviated-form MP_REACH next hop, no MED).
    pub(crate) fn sample_dump() -> Vec<u8> {
        let mut dump = Vec::new();
        // PEER_INDEX_TABLE — skipped by the parser, content irrelevant.
        dump.extend_from_slice(&mrt_record(1, &[0_u8; 10]));

        // 203.0.113.0/24 via 192.0.2.1, path 65001 65002, MED 120,
        // LOCAL_PREF 100, community 65001:111, ext community (raw
        // 0x0002FDE90000006F = RT 65001:111), large 65001:1:1.
        let mut v4_attrs = attr(attr_type::ORIGIN, &[0]);
        v4_attrs.extend_from_slice(&as_path_attr(&[65001, 65002]));
        v4_attrs.extend_from_slice(&attr(attr_type::NEXT_HOP, &[192, 0, 2, 1]));
        v4_attrs.extend_from_slice(&attr(attr_type::MULTI_EXIT_DISC, &120_u32.to_be_bytes()));
        v4_attrs.extend_from_slice(&attr(attr_type::LOCAL_PREF, &100_u32.to_be_bytes()));
        v4_attrs.extend_from_slice(&attr(
            attr_type::COMMUNITIES,
            &((65001_u32 << 16) | 111).to_be_bytes(),
        ));
        v4_attrs.extend_from_slice(&attr(
            attr_type::EXTENDED_COMMUNITIES,
            &0x0002_FDE9_0000_006F_u64.to_be_bytes(),
        ));
        let mut large = Vec::new();
        large.extend_from_slice(&65001_u32.to_be_bytes());
        large.extend_from_slice(&1_u32.to_be_bytes());
        large.extend_from_slice(&1_u32.to_be_bytes());
        v4_attrs.extend_from_slice(&attr(attr_type::LARGE_COMMUNITIES, &large));
        dump.extend_from_slice(&mrt_record(
            RIB_IPV4_UNICAST,
            &rib_payload(24, &[203, 0, 113], &[(None, v4_attrs)]),
        ));

        // 2001:db8::/32 — two Add-Path entries (path ids 1 and 2) via
        // the RFC 6396 abbreviated MP_REACH form, no MED (stays absent).
        let mut nh = vec![16_u8];
        let v6_next_hop: Ipv6Addr = "2001:db8::1".parse().unwrap();
        nh.extend_from_slice(&v6_next_hop.octets());
        let mut v6_attrs = attr(attr_type::ORIGIN, &[0]);
        v6_attrs.extend_from_slice(&as_path_attr(&[65001]));
        v6_attrs.extend_from_slice(&attr(attr_type::MP_REACH_NLRI, &nh));
        dump.extend_from_slice(&mrt_record(
            RIB_IPV6_UNICAST_ADDPATH,
            &rib_payload(
                32,
                &[0x20, 0x01, 0x0d, 0xb8],
                &[(Some(1), v6_attrs.clone()), (Some(2), v6_attrs)],
            ),
        ));
        dump
    }
}

#[cfg(test)]
mod tests {
    use super::test_fixture::*;
    use super::*;
    use std::io::Write;

    fn write_dump(bytes: &[u8]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(bytes).unwrap();
        file.flush().unwrap();
        file
    }

    fn opts<'a>(file: &'a Path, view: &'a str) -> FromMrtOpts<'a> {
        FromMrtOpts {
            file,
            view,
            peer: "192.0.2.9",
            peer_asn: 64501,
            source: Some("m83-capture"),
            generation: 3,
        }
    }

    #[test]
    fn raw_ndjson_emitter_preserves_exact_bytes() {
        let snapshot = "{\"record\":\"header\"}\n{\"record\":\"trailer\",\"routes\":0}\n";
        let mut bytes = Vec::new();
        assert_eq!(
            emit_mrt_snapshot(Ok(snapshot.to_string()), &mut bytes),
            EXIT_OK
        );
        assert_eq!(bytes, snapshot.as_bytes());
    }

    /// Load-bearing: restoring the old `med != 0` emitter filter removes the
    /// attribute that the MRT parser decoded as explicitly present.
    #[test]
    fn mrt_adapter_preserves_explicit_med_zero() {
        let mut attrs = attr(attr_type::ORIGIN, &[0]);
        attrs.extend_from_slice(&attr(attr_type::NEXT_HOP, &[192, 0, 2, 1]));
        attrs.extend_from_slice(&attr(attr_type::MULTI_EXIT_DISC, &0_u32.to_be_bytes()));
        let dump = write_dump(&mrt_record(
            RIB_IPV4_UNICAST,
            &rib_payload(24, &[203, 0, 113], &[(None, attrs)]),
        ));
        let rendered = run(&opts(dump.path(), "adj-rib-out-capture")).unwrap();
        let route = rendered.lines().nth(1).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(route).unwrap()["med"],
            0
        );
    }

    struct FailAfter {
        remaining: usize,
    }

    impl Write for FailAfter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.remaining == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe));
            }
            let written = bytes.len().min(self.remaining);
            self.remaining -= written;
            Ok(written)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn partial_ndjson_broken_pipe_exits_two_without_unwinding() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            emit_mrt_snapshot(
                Ok("{\"record\":\"header\"}\n{\"record\":\"trailer\"}\n".to_string()),
                &mut FailAfter { remaining: 7 },
            )
        }));
        assert_eq!(result.expect("write failure must not panic"), EXIT_REFUSED);
    }

    #[test]
    fn emits_golden_snapshot_for_adj_rib_out_capture() {
        let dump = write_dump(&sample_dump());
        let rendered = run(&opts(dump.path(), "adj-rib-out-capture")).unwrap();
        let golden_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/ribsnap/from-mrt.expected.ndjson"
        );
        // BLESS=1 rewrites the golden (fixture refresh; review the diff).
        if std::env::var_os("BLESS").is_some() {
            std::fs::write(golden_path, &rendered).unwrap();
        }
        let golden = std::fs::read_to_string(golden_path).unwrap();
        assert_eq!(rendered, golden);
    }

    #[test]
    fn refuses_non_adj_rib_out_views() {
        let dump = write_dump(&sample_dump());
        for view in ["loc-rib", "adj-rib-in"] {
            let err = run(&opts(dump.path(), view)).unwrap_err();
            assert!(
                err.contains("not comparable against an Adj-RIB-Out"),
                "unexpected error for {view}: {err}"
            );
        }
        // The public entry point maps refusal to exit 2 with no stdout.
        assert_eq!(from_mrt(&opts(dump.path(), "loc-rib")), EXIT_REFUSED);
    }

    #[test]
    fn rejects_truncated_and_non_rib_dumps() {
        let mut truncated = sample_dump();
        truncated.truncate(truncated.len() - 3);
        let dump = write_dump(&truncated);
        assert!(run(&opts(dump.path(), "adj-rib-out-capture")).is_err());

        // Header-only PEER_INDEX_TABLE record: no unicast RIB records.
        let dump = write_dump(&mrt_record(1, &[0_u8; 4]));
        let err = run(&opts(dump.path(), "adj-rib-out-capture")).unwrap_err();
        assert!(err.contains("no TABLE_DUMP_V2"), "unexpected error: {err}");

        let dump = write_dump(&[]);
        assert!(run(&opts(dump.path(), "adj-rib-out-capture")).is_err());
    }

    #[test]
    fn full_form_mp_reach_next_hop_is_accepted() {
        // AFI(2)=2, SAFI(1)=1, nh_len(1)=16, nh(16), reserved(1).
        let mut value = vec![0, 2, 1, 16];
        let nh: Ipv6Addr = "2001:db8::2".parse().unwrap();
        value.extend_from_slice(&nh.octets());
        value.push(0);
        assert_eq!(
            mp_reach_next_hop(&value).unwrap(),
            "2001:db8::2".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn invalid_peer_address_is_refused() {
        let dump = write_dump(&sample_dump());
        let mut bad = opts(dump.path(), "adj-rib-out-capture");
        bad.peer = "not-an-ip";
        assert!(run(&bad).unwrap_err().contains("invalid --peer"));
    }
}
