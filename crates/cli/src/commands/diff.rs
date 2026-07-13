//! `rbgp diff advertised` — compare the daemon's live Adj-RIB-Out against a
//! canonical NDJSON snapshot of an incumbent route server's advertised view.
//!
//! The semantic comparison itself lives in `rustbgpctl::ribdiff`; this module
//! is the operator workflow around it: fail-closed NDJSON ingestion (versioned
//! header + counted completion trailer required — EOF alone is never
//! completeness), fail-closed gRPC pagination (repeated/cyclic page tokens,
//! mid-walk listing drift, and count mismatches all refuse the comparison),
//! per-peer processing that never holds both full sides at once, and the
//! 0/1/2 exit-code contract.
//!
//! Strictly read-only: the only RPCs issued are `ListNeighbors` and
//! `ListAdvertisedRoutes`.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{BufRead, BufReader, Read};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::connection::Connection;
use crate::error::CliError;
use crate::proto::neighbor_service_client::NeighborServiceClient;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{ListNeighborsRequest, ListRoutesRequest, Route};
use rustbgpctl::ribdiff::{
    self, AsPathSegment, AsSegmentKind, DiffClass, DiffLimits, DiffReport, FamilyId, Nlri,
    PathAttrs, PeerId, RoutePath, RouteSet, SnapshotMeta, UnknownAttr, Verdict,
};
use serde::Deserialize;

/// Versioned identifier of the accepted NDJSON snapshot schema (the
/// `schema` field of the header record).
pub const SNAPSHOT_SCHEMA: &str = "rbgp-ribsnap/1";

/// Complete inputs, no semantic differences.
pub const EXIT_IN_SYNC: i32 = 0;
/// Complete inputs, semantic differences found.
pub const EXIT_DIVERGENT: i32 = 1;
/// Incomplete / malformed / stale / mixed-generation / unsupported /
/// over-limit input, or an operational error. Equality is never asserted.
pub const EXIT_INCOMPARABLE: i32 = 2;

/// Attribute names accepted by `--ignore-attribute`.
const IGNORABLE_ATTRIBUTES: &[&str] = &[
    "origin",
    "as_path",
    "next_hop",
    "med",
    "local_pref",
    "communities",
    "extended_communities",
    "large_communities",
    "unknown",
];

/// Honest limitations of the live gRPC source, emitted verbatim in both
/// human and JSON output so a reader knows exactly what the comparison
/// could and could not see.
const LIVE_SOURCE_NOTES: &[&str] = &[
    "as_path: the daemon proto exposes a flattened ASN list, so AS_PATH is compared as a \
     single AS_SEQUENCE on both sides; AS_SET structure is not compared",
    "unknown attributes: path attributes outside the typed set (origin, as_path, next_hop, \
     med, local_pref, communities, extended/large communities) are not visible over gRPC \
     and are not compared",
    "generation: route-page tokens are process-local and mutation-fenced, so mid-walk \
     drift aborts the listing and requires a restart; the API still exposes no numeric \
     RIB generation, so the snapshot header's generation is adopted for the live side",
];

/// MED-conflation caveat, emitted only when the daemon never populated
/// `med_attr` in the run (an older daemon whose bare `med` field cannot
/// distinguish absent from 0). Daemons that populate `med_attr` are
/// compared exactly (absent = absent, 0 = 0) and need no caveat.
const MED_CONFLATION_NOTE: &str = "med: this daemon carries MED as a bare integer only \
     (no med_attr), so MED-absent and MED 0 are indistinguishable over gRPC; live med=0 \
     is compared as absent (snapshot producers should omit `med` when it is zero or absent)";

/// The live-source notes for one run: the MED-conflation caveat is
/// version-conditional, the rest are structural.
fn live_source_notes(med_attr_seen: bool) -> Vec<&'static str> {
    let mut notes = Vec::with_capacity(LIVE_SOURCE_NOTES.len() + 1);
    if !med_attr_seen {
        notes.push(MED_CONFLATION_NOTE);
    }
    notes.extend_from_slice(LIVE_SOURCE_NOTES);
    notes
}

/// Requested page size — matches the server's per-page cap.
const ROUTE_PAGE_SIZE: u32 = 1000;

type RibClient = RibServiceClient<
    tonic::service::interceptor::InterceptedService<
        tonic::transport::Channel,
        crate::connection::AuthInterceptor,
    >,
>;

/// Parsed CLI options for `rbgp diff advertised`.
pub struct AdvertisedDiffOpts {
    /// Peers to compare (empty = every peer present in the snapshot).
    pub peers: Vec<String>,
    /// Path to the incumbent NDJSON snapshot.
    pub against: PathBuf,
    /// Family filter (empty = ipv4_unicast + ipv6_unicast).
    pub families: Vec<String>,
    /// Maximum retained routes per side (also the engine `max_routes`).
    pub max_routes: usize,
    /// Maximum snapshot bytes read (also the engine `max_input_bytes`).
    pub max_input_bytes: u64,
    /// Attributes excluded from comparison on both sides.
    pub ignore_attributes: Vec<String>,
    /// Maximum detailed difference rows in human output.
    pub detail: usize,
    /// Overall wall-clock budget in seconds.
    pub deadline_seconds: u64,
    /// Emit the full JSON report instead of the human summary.
    pub json: bool,
}

/// Run the diff, print its report, and return the process exit code.
pub async fn advertised(connection: Connection, opts: &AdvertisedDiffOpts) -> i32 {
    match run(connection, opts).await {
        Ok((rendered, code)) => {
            print!("{rendered}");
            code
        }
        Err(e) => {
            eprintln!("Error: {e}");
            EXIT_INCOMPARABLE
        }
    }
}

fn op(msg: String) -> CliError {
    CliError::Rpc(msg)
}

/// Full pipeline; returns the rendered report and the exit code so tests
/// can assert byte-identical output across runs.
async fn run(connection: Connection, opts: &AdvertisedDiffOpts) -> Result<(String, i32), CliError> {
    let deadline = Instant::now() + Duration::from_secs(opts.deadline_seconds);
    let ignored = validate_ignore_attributes(&opts.ignore_attributes)?;
    let family_filter = parse_family_filter(&opts.families)?;
    let peer_filter = parse_peer_filter(&opts.peers)?;
    let limits = DiffLimits {
        max_routes: opts.max_routes,
        max_input_bytes: usize::try_from(opts.max_input_bytes).unwrap_or(usize::MAX),
        ..DiffLimits::default()
    };

    let file = std::fs::File::open(&opts.against).map_err(|e| {
        op(format!(
            "cannot open snapshot {}: {e}",
            opts.against.display()
        ))
    })?;
    let mut snapshot = parse_snapshot(file, opts, &family_filter, &peer_filter, &ignored)?;

    let requested: BTreeSet<IpAddr> = if peer_filter.is_empty() {
        snapshot.peers.keys().copied().collect()
    } else {
        peer_filter
    };
    if requested.is_empty() {
        return Err(op(
            "nothing to compare: the snapshot contains no route records and no --peer was given"
                .to_string(),
        ));
    }

    let mut neighbor_client =
        NeighborServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let neighbors = neighbor_client
        .list_neighbors(ListNeighborsRequest {})
        .await?
        .into_inner();
    let mut neighbor_map: BTreeMap<IpAddr, (u32, Vec<String>)> = BTreeMap::new();
    for state in &neighbors.neighbors {
        if let Some(config) = &state.config
            && let Ok(addr) = config.address.parse::<IpAddr>()
        {
            neighbor_map.insert(addr, (config.remote_asn, config.families.clone()));
        }
    }

    let mut rib_client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    // True once any live route carries `med_attr` — the daemon is
    // MED-absence-aware and the MED-conflation caveat does not apply.
    let mut med_attr_seen = false;

    let mut report = DiffReport {
        schema: ribdiff::SCHEMA_VERSION,
        normalization: ribdiff::NORMALIZATION,
        verdict: Verdict::InSync,
        incomparable_reasons: Vec::new(),
        incumbent: SnapshotMeta {
            source: snapshot.source.clone(),
            generation: snapshot.generation,
            complete: true,
        },
        rustbgpd: SnapshotMeta {
            source: "rustbgpd-grpc (adj-rib-out, advertised)".to_string(),
            generation: snapshot.generation,
            complete: true,
        },
        summaries: Vec::new(),
        entries: Vec::new(),
    };

    // ponytail: peers are processed one at a time and each peer's snapshot
    // bucket is dropped after its diff, so peak memory is one peer's table
    // per side, never both full sides; finer within-peer page-by-page
    // release only if a single peer's full table ever hurts.
    for peer_addr in &requested {
        let snapshot_bucket = snapshot.peers.remove(peer_addr);
        let Some((remote_asn, configured_families)) = neighbor_map.get(peer_addr) else {
            report.incomparable_reasons.push(format!(
                "peer {peer_addr}: not configured on the daemon; equality refused"
            ));
            continue;
        };
        if let Some(bucket) = &snapshot_bucket
            && bucket.asn != *remote_asn
        {
            report.incomparable_reasons.push(format!(
                "peer {peer_addr}: ASN mismatch (snapshot {} vs daemon {remote_asn}); \
                 equality refused",
                bucket.asn
            ));
            continue;
        }
        let mut family_unavailable = false;
        for family in &family_filter {
            let name = family_name(*family);
            if !configured_families.iter().any(|f| f == name) {
                report.incomparable_reasons.push(format!(
                    "peer {peer_addr}: requested family {name} is not configured; \
                     equality refused"
                ));
                family_unavailable = true;
            }
        }
        if family_unavailable {
            continue;
        }

        let peer_id = PeerId {
            address: *peer_addr,
            asn: *remote_asn,
            distinguisher: None,
        };
        let mut incumbent = RouteSet::with_limits(
            SnapshotMeta {
                source: snapshot.source.clone(),
                generation: snapshot.generation,
                complete: true,
            },
            limits,
        );
        for (family, nlri, path) in snapshot_bucket.map(|b| b.records).unwrap_or_default() {
            incumbent
                .insert(peer_id.clone(), family, nlri, path)
                .map_err(|e| op(format!("snapshot peer {peer_addr}: {e}")))?;
        }
        let mut live = RouteSet::with_limits(
            SnapshotMeta {
                source: "rustbgpd-grpc (adj-rib-out, advertised)".to_string(),
                generation: snapshot.generation,
                complete: true,
            },
            limits,
        );
        med_attr_seen |= fetch_advertised_into(
            &mut rib_client,
            &peer_id,
            &mut live,
            &family_filter,
            &ignored,
            opts.max_routes,
            deadline,
        )
        .await?;

        let peer_report = ribdiff::diff(&incumbent, &live);
        report.incomparable_reasons.extend(
            peer_report
                .incomparable_reasons
                .into_iter()
                .map(|r| format!("peer {peer_addr}: {r}")),
        );
        report.summaries.extend(peer_report.summaries);
        report.entries.extend(peer_report.entries);
    }

    report.verdict = if !report.incomparable_reasons.is_empty() {
        Verdict::Incomparable
    } else if report.entries.is_empty() {
        Verdict::InSync
    } else {
        Verdict::Divergent
    };
    let code = match report.verdict {
        Verdict::InSync => EXIT_IN_SYNC,
        Verdict::Divergent => EXIT_DIVERGENT,
        Verdict::Incomparable => EXIT_INCOMPARABLE,
    };
    let notes = live_source_notes(med_attr_seen);
    let rendered = if opts.json {
        render_json(&report, &ignored, &notes)?
    } else {
        render_human(&report, &ignored, &notes, opts.detail)
    };
    Ok((rendered, code))
}

// ---------------------------------------------------------------------------
// option parsing
// ---------------------------------------------------------------------------

fn validate_ignore_attributes(raw: &[String]) -> Result<Vec<String>, CliError> {
    let mut ignored: Vec<String> = Vec::new();
    for name in raw {
        if !IGNORABLE_ATTRIBUTES.contains(&name.as_str()) {
            return Err(CliError::Argument(format!(
                "unsupported --ignore-attribute {name:?}; expected one of: {}",
                IGNORABLE_ATTRIBUTES.join(", ")
            )));
        }
        if !ignored.contains(name) {
            ignored.push(name.clone());
        }
    }
    ignored.sort();
    Ok(ignored)
}

fn parse_family_filter(families: &[String]) -> Result<Vec<FamilyId>, CliError> {
    let mut parsed = Vec::new();
    for family in families {
        let id = match family.as_str() {
            "ipv4_unicast" | "ipv4-unicast" | "ipv4" => FamilyId::IPV4_UNICAST,
            "ipv6_unicast" | "ipv6-unicast" | "ipv6" => FamilyId::IPV6_UNICAST,
            other => {
                return Err(CliError::Argument(format!(
                    "unsupported family {other:?}; diff advertised supports ipv4_unicast \
                     and ipv6_unicast"
                )));
            }
        };
        if !parsed.contains(&id) {
            parsed.push(id);
        }
    }
    parsed.sort();
    Ok(parsed)
}

fn parse_peer_filter(peers: &[String]) -> Result<BTreeSet<IpAddr>, CliError> {
    peers
        .iter()
        .map(|p| {
            p.parse::<IpAddr>()
                .map_err(|e| CliError::Argument(format!("invalid --peer address {p:?}: {e}")))
        })
        .collect()
}

fn family_name(family: FamilyId) -> &'static str {
    if family == FamilyId::IPV4_UNICAST {
        "ipv4_unicast"
    } else if family == FamilyId::IPV6_UNICAST {
        "ipv6_unicast"
    } else {
        "unknown"
    }
}

fn family_retained(family: FamilyId, filter: &[FamilyId]) -> bool {
    filter.is_empty() || filter.contains(&family)
}

fn apply_ignores(attrs: &mut PathAttrs, ignored: &[String]) {
    for name in ignored {
        match name.as_str() {
            "origin" => attrs.origin = None,
            "as_path" => attrs.as_path.clear(),
            "next_hop" => attrs.next_hop = None,
            "med" => attrs.med = None,
            "local_pref" => attrs.local_pref = None,
            "communities" => attrs.communities.clear(),
            "extended_communities" => attrs.extended_communities.clear(),
            "large_communities" => attrs.large_communities.clear(),
            "unknown" => attrs.unknown.clear(),
            _ => unreachable!("validated in validate_ignore_attributes"),
        }
    }
}

fn parse_prefix(prefix: &str) -> Result<(IpAddr, u8, FamilyId), String> {
    let (addr, len) = prefix
        .split_once('/')
        .ok_or_else(|| format!("invalid prefix {prefix:?} (expected addr/len)"))?;
    let addr: IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid prefix address {addr:?}"))?;
    let len: u8 = len
        .parse()
        .map_err(|_| format!("invalid prefix length {len:?}"))?;
    let (family, max_len) = if addr.is_ipv4() {
        (FamilyId::IPV4_UNICAST, 32)
    } else {
        (FamilyId::IPV6_UNICAST, 128)
    };
    if len > max_len {
        return Err(format!("prefix length {len} exceeds {max_len}: {prefix}"));
    }
    Ok((addr, len, family))
}

/// Decode a lowercase/uppercase hex string into bytes (`unknown_attrs`
/// values). Odd length or non-hex digits are malformed.
fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return Err(format!(
            "invalid hex value {s:?} (expected an even number of hex digits)"
        ));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| format!("invalid hex value {s:?} (non-hex digit)"))
        })
        .collect()
}

fn parse_large_community(s: &str) -> Result<[u32; 3], String> {
    let parts: Vec<&str> = s.split(':').collect();
    let invalid = || format!("invalid large community {s:?} (expected global:data1:data2)");
    if parts.len() != 3 {
        return Err(invalid());
    }
    let mut out = [0u32; 3];
    for (slot, part) in out.iter_mut().zip(&parts) {
        *slot = part.parse().map_err(|_| invalid())?;
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// incumbent side: NDJSON snapshot ingestion
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderRecord {
    schema: String,
    source: String,
    generation: u64,
}

/// A standard community as either the raw u32 or an "ASN:value" string
/// (well-known aliases like NO_EXPORT are accepted too).
#[derive(Deserialize)]
#[serde(untagged)]
enum CommunityIn {
    Num(u32),
    Str(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RouteRecord {
    peer: IpAddr,
    peer_asn: u32,
    prefix: String,
    #[serde(default)]
    path_id: Option<u32>,
    #[serde(default)]
    origin: Option<u8>,
    #[serde(default)]
    as_path: Vec<u32>,
    #[serde(default)]
    next_hop: Option<IpAddr>,
    #[serde(default)]
    med: Option<u32>,
    #[serde(default)]
    local_pref: Option<u32>,
    #[serde(default)]
    communities: Vec<CommunityIn>,
    #[serde(default)]
    extended_communities: Vec<u64>,
    #[serde(default)]
    large_communities: Vec<String>,
    #[serde(default)]
    unknown_attrs: Vec<UnknownAttrRecord>,
}

/// An untyped path attribute preserved by a snapshot producer (e.g. the
/// from-bmp adapter): wire flags + type code + hex-encoded value octets.
/// Compared byte-exact by the engine ([`UnknownAttr`]).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnknownAttrRecord {
    type_code: u8,
    flags: u8,
    value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrailerRecord {
    routes: u64,
}

/// One snapshot peer's retained records under its declared ASN.
#[derive(Default)]
struct PeerBucket {
    asn: u32,
    records: Vec<(FamilyId, Nlri, RoutePath)>,
}

struct SnapshotData {
    source: String,
    generation: u64,
    peers: BTreeMap<IpAddr, PeerBucket>,
}

/// Parse and validate one NDJSON snapshot, fail-closed:
///
/// - the first line must be a `rbgp-ribsnap/1` header;
/// - the last line must be a trailer whose `routes` count matches the
///   number of route records read (EOF without a trailer is incomplete);
/// - unknown fields, blank lines, records after the trailer, duplicate
///   headers/trailers, and conflicting per-peer ASNs are all malformed;
/// - `--max-input-bytes` bounds bytes read (enforced by a capped reader
///   before any allocation) and `--max-routes` bounds retained records.
fn parse_snapshot(
    reader: impl Read,
    opts: &AdvertisedDiffOpts,
    family_filter: &[FamilyId],
    peer_filter: &BTreeSet<IpAddr>,
    ignored: &[String],
) -> Result<SnapshotData, CliError> {
    let path = opts.against.display();
    // The +1 lets us distinguish "exactly at the limit" from over it while
    // still bounding every allocation below the limit check.
    let mut reader = BufReader::new(reader.take(opts.max_input_bytes.saturating_add(1)));
    let mut line = String::new();
    let mut bytes_read: u64 = 0;
    let mut line_no: u64 = 0;
    let mut next_line = |line: &mut String, bytes_read: &mut u64, line_no: &mut u64| {
        line.clear();
        let n = reader
            .read_line(line)
            .map_err(|e| op(format!("{path}: read failed: {e}")))?;
        *bytes_read += n as u64;
        if *bytes_read > opts.max_input_bytes {
            return Err(op(format!(
                "{path}: max_input_bytes limit exceeded ({} > {}); refusing to compare \
                 truncated input",
                bytes_read, opts.max_input_bytes
            )));
        }
        if n > 0 {
            *line_no += 1;
        }
        Ok(n > 0)
    };
    let malformed = |line_no: u64, msg: String| -> CliError {
        op(format!("{path}:{line_no}: malformed snapshot: {msg}"))
    };

    if !next_line(&mut line, &mut bytes_read, &mut line_no)? {
        return Err(op(format!("{path}: empty snapshot (missing header)")));
    }
    let header = decode_record::<HeaderRecord>(&line, "header")
        .map_err(|msg| malformed(line_no, msg))?
        .ok_or_else(|| malformed(line_no, "first record must be a header".to_string()))?;
    if header.schema != SNAPSHOT_SCHEMA {
        return Err(malformed(
            line_no,
            format!(
                "unsupported snapshot schema {:?} (expected {SNAPSHOT_SCHEMA:?})",
                header.schema
            ),
        ));
    }

    let mut peers: BTreeMap<IpAddr, PeerBucket> = BTreeMap::new();
    let mut route_records: u64 = 0;
    let mut retained: usize = 0;
    let mut trailer: Option<TrailerRecord> = None;
    while next_line(&mut line, &mut bytes_read, &mut line_no)? {
        if trailer.is_some() {
            return Err(malformed(
                line_no,
                "content after the completion trailer".to_string(),
            ));
        }
        if let Some(t) = decode_record::<TrailerRecord>(&line, "trailer")
            .map_err(|msg| malformed(line_no, msg))?
        {
            trailer = Some(t);
            continue;
        }
        let Some(route) =
            decode_record::<RouteRecord>(&line, "route").map_err(|msg| malformed(line_no, msg))?
        else {
            return Err(malformed(
                line_no,
                "expected a route or trailer record".to_string(),
            ));
        };
        route_records += 1;
        if !peer_filter.is_empty() && !peer_filter.contains(&route.peer) {
            continue;
        }
        let (family, nlri, peer, asn, mut route_path) =
            convert_snapshot_route(route).map_err(|msg| malformed(line_no, msg))?;
        // The bucket is created even when the family filter drops the
        // record, so a snapshot peer stays a requested peer (its
        // availability is still checked) rather than silently vanishing.
        let bucket = peers.entry(peer).or_insert_with(|| PeerBucket {
            asn,
            ..PeerBucket::default()
        });
        if bucket.asn != asn {
            return Err(malformed(
                line_no,
                format!(
                    "peer {peer} appears with conflicting ASNs ({} and {asn})",
                    bucket.asn
                ),
            ));
        }
        if !family_retained(family, family_filter) {
            continue;
        }
        if retained >= opts.max_routes {
            return Err(op(format!(
                "{path}: max_routes limit exceeded (more than {} retained snapshot routes); \
                 refusing to compare truncated input",
                opts.max_routes
            )));
        }
        retained += 1;
        apply_ignores(&mut route_path.attrs, ignored);
        bucket.records.push((family, nlri, route_path));
    }

    let Some(trailer) = trailer else {
        return Err(op(format!(
            "{path}: missing completion trailer — EOF alone is not completeness; \
             refusing to compare a possibly-truncated snapshot"
        )));
    };
    if trailer.routes != route_records {
        return Err(op(format!(
            "{path}: trailer count mismatch (trailer declares {} routes, file contains \
             {route_records}); refusing to compare",
            trailer.routes
        )));
    }
    Ok(SnapshotData {
        source: header.source,
        generation: header.generation,
        peers,
    })
}

/// Decode one NDJSON line as the record type named `kind`. `Ok(None)`
/// means the line is valid JSON of a different record kind; `Err` means
/// the line is not valid JSON, has no `record` field, or names `kind` but
/// fails strict (deny-unknown-fields) decoding.
fn decode_record<T: serde::de::DeserializeOwned>(
    line: &str,
    kind: &str,
) -> Result<Option<T>, String> {
    let mut value: serde_json::Value =
        serde_json::from_str(line.trim_end()).map_err(|e| format!("invalid JSON: {e}"))?;
    let record = value
        .as_object_mut()
        .and_then(|object| object.remove("record"));
    match record.as_ref().and_then(serde_json::Value::as_str) {
        Some(record) if record == kind => serde_json::from_value(value)
            .map(Some)
            .map_err(|e| format!("invalid {kind} record: {e}")),
        Some(_) => Ok(None),
        None => Err("record field missing or not a string".to_string()),
    }
}

type SnapshotRoute = (FamilyId, Nlri, IpAddr, u32, RoutePath);

fn convert_snapshot_route(route: RouteRecord) -> Result<SnapshotRoute, String> {
    let (addr, len, family) = parse_prefix(&route.prefix)?;
    if let Some(origin) = route.origin
        && origin > 2
    {
        return Err(format!("invalid origin {origin} (expected 0, 1, or 2)"));
    }
    let mut communities = Vec::with_capacity(route.communities.len());
    for community in route.communities {
        communities.push(match community {
            CommunityIn::Num(value) => value,
            CommunityIn::Str(s) => crate::parse_community_str(&s)?,
        });
    }
    let large_communities = route
        .large_communities
        .iter()
        .map(|s| parse_large_community(s))
        .collect::<Result<Vec<_>, _>>()?;
    let unknown = route
        .unknown_attrs
        .into_iter()
        .map(|attr| {
            Ok(UnknownAttr {
                type_code: attr.type_code,
                flags: attr.flags,
                value: parse_hex(&attr.value)?,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let attrs = PathAttrs {
        origin: route.origin,
        as_path: as_path_segment(&route.as_path),
        next_hop: route.next_hop,
        med: route.med,
        local_pref: route.local_pref,
        communities,
        extended_communities: route.extended_communities,
        large_communities,
        unknown,
    };
    Ok((
        family,
        Nlri::Prefix { addr, len },
        route.peer,
        route.peer_asn,
        RoutePath {
            path_id: route.path_id,
            attrs,
        },
    ))
}

fn as_path_segment(asns: &[u32]) -> Vec<AsPathSegment> {
    if asns.is_empty() {
        Vec::new()
    } else {
        vec![AsPathSegment {
            kind: AsSegmentKind::Sequence,
            asns: asns.to_vec(),
        }]
    }
}

// ---------------------------------------------------------------------------
// live side: fail-closed Adj-RIB-Out pagination
// ---------------------------------------------------------------------------

/// Walk every page of `ListAdvertisedRoutes` for one peer, inserting into
/// `live` page by page (only one page is ever buffered). Fail-closed:
///
/// - a `next_page_token` already used in this walk (non-advancing or
///   cyclic pagination — the same page twice) refuses the comparison;
/// - the API's mutation-fenced token makes mid-walk drift fail with ABORTED;
///   a changing `total_count` remains a defense-in-depth check for older
///   daemons and refuses the comparison;
/// - the fetched route count must equal the server's `total_count`;
/// - `--max-routes` is enforced before each page is buffered into the set;
/// - the shared deadline is checked before every RPC.
///
/// Returns whether any fetched route carried `med_attr` (a
/// MED-absence-aware daemon); the MED-conflation caveat is dropped
/// from the report notes for such runs.
async fn fetch_advertised_into(
    client: &mut RibClient,
    peer: &PeerId,
    live: &mut RouteSet,
    family_filter: &[FamilyId],
    ignored: &[String],
    max_routes: usize,
    deadline: Instant,
) -> Result<bool, CliError> {
    let peer_addr = peer.address;
    let mut req = ListRoutesRequest {
        neighbor_address: peer_addr.to_string(),
        afi_safi: 0,
        page_size: ROUTE_PAGE_SIZE,
        page_token: String::new(),
        prefix_filter: String::new(),
        prefix_filter_length: 0,
        longer_prefixes: false,
        origin_asn: 0,
        community_filter: Vec::new(),
        large_community_filter: Vec::new(),
    };
    let mut seen_tokens: HashSet<String> = HashSet::new();
    let mut fetched: u64 = 0;
    let mut expected_total: Option<u64> = None;
    let mut med_attr_seen = false;
    loop {
        if Instant::now() >= deadline {
            return Err(op(format!(
                "deadline expired while fetching advertised routes for peer {peer_addr}; \
                 refusing a partial comparison (raise --deadline)"
            )));
        }
        let resp = client
            .list_advertised_routes(req.clone())
            .await?
            .into_inner();
        match expected_total {
            None => expected_total = Some(resp.total_count),
            Some(total) if total != resp.total_count => {
                return Err(op(format!(
                    "advertised listing for peer {peer_addr} changed during pagination \
                     (total_count {total} -> {}); the capture is stale — re-run against a \
                     quiescent RIB",
                    resp.total_count
                )));
            }
            Some(_) => {}
        }
        if fetched + resp.routes.len() as u64 > max_routes as u64 {
            return Err(op(format!(
                "max_routes limit exceeded while fetching advertised routes for peer \
                 {peer_addr} (more than {max_routes}); refusing to compare truncated input"
            )));
        }
        for route in &resp.routes {
            fetched += 1;
            med_attr_seen |= route.med_attr.is_some();
            let (family, nlri, path) = convert_live_route(route)
                .map_err(|msg| op(format!("daemon returned an unusable route: {msg}")))?;
            if !family_retained(family, family_filter) {
                continue;
            }
            let mut path = path;
            apply_ignores(&mut path.attrs, ignored);
            live.insert(peer.clone(), family, nlri, path)
                .map_err(|e| op(format!("live peer {peer_addr}: {e}")))?;
        }
        if resp.next_page_token.is_empty() {
            break;
        }
        if !seen_tokens.insert(resp.next_page_token.clone()) {
            return Err(op(format!(
                "repeated page token {:?} while fetching advertised routes for peer \
                 {peer_addr} (non-advancing or cyclic pagination); refusing to compare",
                resp.next_page_token
            )));
        }
        req.page_token = resp.next_page_token;
    }
    let total = expected_total.unwrap_or(0);
    if fetched != total {
        return Err(op(format!(
            "advertised listing for peer {peer_addr} is incomplete: fetched {fetched} \
             routes but the server reported total_count {total}; refusing to compare"
        )));
    }
    Ok(med_attr_seen)
}

fn convert_live_route(route: &Route) -> Result<(FamilyId, Nlri, RoutePath), String> {
    let (addr, len, family) = parse_prefix(&format!("{}/{}", route.prefix, route.prefix_length))?;
    let next_hop = if route.next_hop.is_empty() {
        None
    } else {
        Some(
            route
                .next_hop
                .parse::<IpAddr>()
                .map_err(|_| format!("invalid next hop {:?}", route.next_hop))?,
        )
    };
    let origin =
        u8::try_from(route.origin).map_err(|_| format!("invalid origin {}", route.origin))?;
    let large_communities = route
        .large_communities
        .iter()
        .map(|s| parse_large_community(s))
        .collect::<Result<Vec<_>, _>>()?;
    let attrs = PathAttrs {
        origin: Some(origin),
        as_path: as_path_segment(&route.as_path),
        next_hop,
        // `med_attr` is the honest optional field (absent = absent,
        // 0 = 0). Older daemons only carry the bare u32 where absent
        // and 0 are indistinguishable, so 0 maps to absent (see
        // MED_CONFLATION_NOTE).
        med: route.med_attr.or((route.med != 0).then_some(route.med)),
        // local_pref_attr is the honest optional field; the bare
        // `local_pref` is the effective (defaulted) value.
        local_pref: route.local_pref_attr,
        communities: route.communities.clone(),
        extended_communities: route.extended_communities.clone(),
        large_communities,
        unknown: Vec::new(),
    };
    Ok((
        family,
        Nlri::Prefix { addr, len },
        RoutePath {
            path_id: (route.path_id != 0).then_some(route.path_id),
            attrs,
        },
    ))
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

fn nlri_str(nlri: &Nlri) -> String {
    match nlri {
        Nlri::Prefix { addr, len } => format!("{addr}/{len}"),
        other => serde_json::to_string(other).unwrap_or_else(|_| "?".to_string()),
    }
}

fn ignored_display(ignored: &[String]) -> String {
    if ignored.is_empty() {
        "none".to_string()
    } else {
        ignored.join(", ")
    }
}

fn render_json(
    report: &DiffReport,
    ignored: &[String],
    notes: &[&str],
) -> Result<String, CliError> {
    let mut value = serde_json::to_value(report)?;
    let object = value
        .as_object_mut()
        .expect("DiffReport serializes to an object");
    object.insert("ignored_attributes".to_string(), serde_json::json!(ignored));
    object.insert("live_source_notes".to_string(), serde_json::json!(notes));
    Ok(format!("{}\n", serde_json::to_string_pretty(&value)?))
}

fn render_human(report: &DiffReport, ignored: &[String], notes: &[&str], detail: usize) -> String {
    use std::fmt::Write;

    let mut out = String::new();
    let _ = writeln!(
        out,
        "diff advertised: incumbent {:?} (generation {}) vs {}",
        report.incumbent.source, report.incumbent.generation, report.rustbgpd.source
    );
    let _ = writeln!(
        out,
        "schema {}; normalization {}; ignored attributes: {}",
        report.schema,
        report.normalization.version,
        ignored_display(ignored)
    );
    out.push_str("live-source notes:\n");
    for note in notes {
        let _ = writeln!(out, "  - {note}");
    }
    let verdict = match report.verdict {
        Verdict::InSync => "in_sync",
        Verdict::Divergent => "divergent",
        Verdict::Incomparable => "incomparable (equality refused)",
    };
    let _ = writeln!(out, "verdict: {verdict}");
    if !report.incomparable_reasons.is_empty() {
        out.push_str("reasons:\n");
        for reason in &report.incomparable_reasons {
            let _ = writeln!(out, "  - {reason}");
        }
    }
    if !report.summaries.is_empty() {
        out.push_str("per-peer summary:\n");
        for s in &report.summaries {
            let _ = writeln!(
                out,
                "  {} AS{} {}: matched {}, incumbent-only {}, rustbgpd-only {}, \
                 attribute-changed {}, multiplicity-changed {}",
                s.peer.address,
                s.peer.asn,
                family_name(s.family),
                s.matched,
                s.incumbent_only,
                s.rustbgpd_only,
                s.attribute_changed,
                s.multiplicity_changed
            );
        }
    }
    if !report.entries.is_empty() {
        let shown = report.entries.len().min(detail);
        let _ = writeln!(
            out,
            "differences ({} total, showing {shown}):",
            report.entries.len()
        );
        for entry in report.entries.iter().take(detail) {
            let marker = match entry.class {
                DiffClass::IncumbentOnly => "-",
                DiffClass::RustbgpdOnly => "+",
                DiffClass::AttributeChanged => "~",
                DiffClass::MultiplicityChanged => "*",
            };
            let class = match entry.class {
                DiffClass::IncumbentOnly => "incumbent-only",
                DiffClass::RustbgpdOnly => "rustbgpd-only",
                DiffClass::AttributeChanged => "attribute-changed",
                DiffClass::MultiplicityChanged => "multiplicity-changed",
            };
            let mut detail_text = String::new();
            for delta in &entry.attribute_deltas {
                let _ = write!(
                    detail_text,
                    " {}: {} -> {};",
                    delta.attribute, delta.incumbent, delta.rustbgpd
                );
            }
            let _ = writeln!(
                out,
                "  {marker} {} {} {} [{class}]{detail_text}",
                entry.peer.address,
                family_name(entry.family),
                nlri_str(&entry.nlri)
            );
        }
        if report.entries.len() > detail {
            let _ = writeln!(
                out,
                "  ... {} more differing NLRIs truncated (use --json for the full list)",
                report.entries.len() - detail
            );
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;
    use rustbgpd_api::proto as server_proto;
    use std::io::Write;

    const PEER: &str = "192.0.2.1";
    const PEER_ASN: u32 = 64501;

    fn json_type(value: &serde_json::Value) -> &'static str {
        match value {
            serde_json::Value::Null => "null",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Number(_) => "number",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::Object(_) => "object",
        }
    }

    fn validate_ribsnap_shape(
        value: &serde_json::Value,
        shape: &serde_json::Value,
    ) -> Result<(), String> {
        let object = value
            .as_object()
            .ok_or_else(|| "snapshot record is not an object".to_string())?;
        for (key, expected) in shape["required_json_types"].as_object().unwrap() {
            let field = object
                .get(key)
                .ok_or_else(|| format!("required rbgp-ribsnap/1 field {key:?} is absent"))?;
            let allowed: Vec<&str> = match expected {
                serde_json::Value::String(value) => vec![value.as_str()],
                serde_json::Value::Array(values) => {
                    values.iter().map(|value| value.as_str().unwrap()).collect()
                }
                _ => return Err(format!("invalid rbgp-ribsnap/1 type floor for {key:?}")),
            };
            if !allowed.contains(&json_type(field)) {
                return Err(format!("rbgp-ribsnap/1 field {key:?} changed JSON type"));
            }
        }
        for (key, expected) in shape["optional_json_types"].as_object().unwrap() {
            if let Some(field) = object.get(key) {
                let allowed: Vec<&str> = match expected {
                    serde_json::Value::String(value) => vec![value.as_str()],
                    serde_json::Value::Array(values) => {
                        values.iter().map(|value| value.as_str().unwrap()).collect()
                    }
                    _ => return Err(format!("invalid rbgp-ribsnap/1 type floor for {key:?}")),
                };
                if !allowed.contains(&json_type(field)) {
                    return Err(format!("rbgp-ribsnap/1 field {key:?} changed JSON type"));
                }
            }
        }
        Ok(())
    }

    fn ribsnap_inventory_contract() -> serde_json::Value {
        let inventory_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/v1-stable-surface.json"
        );
        let inventory: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(inventory_path).unwrap()).unwrap();
        inventory["cli"]["versioned_json_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|contract| contract["id"] == "rbgp-ribsnap/1")
            .expect("rbgp-ribsnap/1 contract is inventoried")
            .clone()
    }

    fn opts(against: &std::path::Path) -> AdvertisedDiffOpts {
        AdvertisedDiffOpts {
            peers: Vec::new(),
            against: against.to_path_buf(),
            families: Vec::new(),
            max_routes: 4_000_000,
            max_input_bytes: 1 << 30,
            ignore_attributes: Vec::new(),
            detail: 20,
            deadline_seconds: 120,
            json: false,
        }
    }

    fn snapshot_file(lines: &[String]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
        file.flush().unwrap();
        file
    }

    #[test]
    fn ribsnap_json_contract_floor_matches_producer_goldens() {
        let contract = ribsnap_inventory_contract();
        let shapes = contract["record_json_contracts"].as_object().unwrap();
        let mut observed_record_kinds = BTreeSet::new();
        for golden in contract["golden_files"].as_array().unwrap() {
            let relative_path = golden["path"].as_str().unwrap();
            let golden_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(relative_path);
            let bytes = std::fs::read(&golden_path).unwrap();
            for (line_index, line) in std::str::from_utf8(&bytes).unwrap().lines().enumerate() {
                let record: serde_json::Value =
                    serde_json::from_str(line).unwrap_or_else(|error| {
                        panic!(
                            "{}:{} is not JSON: {error}",
                            golden_path.display(),
                            line_index + 1
                        )
                    });
                let kind = record["record"].as_str().unwrap_or_else(|| {
                    panic!(
                        "{}:{} has no string record kind",
                        golden_path.display(),
                        line_index + 1
                    )
                });
                let shape = shapes.get(kind).unwrap_or_else(|| {
                    panic!(
                        "{}:{} has uninventoried record kind {kind:?}",
                        golden_path.display(),
                        line_index + 1
                    )
                });
                validate_ribsnap_shape(&record, shape).unwrap_or_else(|error| {
                    panic!("{}:{}: {error}", golden_path.display(), line_index + 1)
                });
                observed_record_kinds.insert(kind.to_string());
            }

            let opts = opts(&golden_path);
            parse_snapshot(&bytes[..], &opts, &[], &BTreeSet::new(), &[]).unwrap_or_else(|error| {
                panic!(
                    "pinned producer golden {} failed the rbgp-ribsnap/1 parser: {error}",
                    golden_path.display()
                )
            });
        }
        assert_eq!(
            observed_record_kinds,
            ["header", "route", "trailer"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
    }

    #[test]
    fn ribsnap_contract_rejects_required_field_deletion_from_each_producer_golden() {
        let contract = ribsnap_inventory_contract();
        let route_shape = &contract["record_json_contracts"]["route"];
        for golden in contract["golden_files"].as_array().unwrap() {
            let relative_path = golden["path"].as_str().unwrap();
            let golden_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../..")
                .join(relative_path);
            let mut records: Vec<serde_json::Value> = std::fs::read_to_string(&golden_path)
                .unwrap()
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            let route = records
                .iter_mut()
                .find(|record| record["record"] == "route")
                .unwrap_or_else(|| panic!("{} has no route record", golden_path.display()));
            route.as_object_mut().unwrap().remove("peer_asn");
            let error = validate_ribsnap_shape(route, route_shape).unwrap_err();
            assert!(error.contains("peer_asn"), "unexpected error: {error}");

            let mut bytes = records
                .iter()
                .map(serde_json::Value::to_string)
                .collect::<Vec<_>>()
                .join("\n")
                .into_bytes();
            bytes.push(b'\n');
            let opts = opts(&golden_path);
            assert!(
                parse_snapshot(&bytes[..], &opts, &[], &BTreeSet::new(), &[]).is_err(),
                "{} parsed after a required producer field was deleted",
                golden_path.display()
            );
        }
    }

    fn header_line() -> String {
        format!(
            r#"{{"record":"header","schema":"{SNAPSHOT_SCHEMA}","source":"incumbent-test","generation":7}}"#
        )
    }

    fn route_line(prefix: &str, med: Option<u32>) -> String {
        let mut value = serde_json::json!({
            "record": "route",
            "peer": PEER,
            "peer_asn": PEER_ASN,
            "prefix": prefix,
            "origin": 0,
            "as_path": [65001],
            "next_hop": "192.0.2.254",
            "communities": ["64501:100"],
        });
        if let Some(med) = med {
            value["med"] = serde_json::json!(med);
        }
        value.to_string()
    }

    fn trailer_line(routes: u64) -> String {
        format!(r#"{{"record":"trailer","routes":{routes}}}"#)
    }

    fn live_route(prefix: &str, med: u32) -> server_proto::Route {
        server_proto::Route {
            prefix: prefix.to_string(),
            prefix_length: 24,
            next_hop: "192.0.2.254".to_string(),
            origin: 0,
            as_path: vec![65001],
            med,
            communities: vec![(64501 << 16) | 100],
            ..Default::default()
        }
    }

    fn live_route_with_med_attr(
        prefix: &str,
        med: u32,
        med_attr: Option<u32>,
    ) -> server_proto::Route {
        server_proto::Route {
            med_attr,
            ..live_route(prefix, med)
        }
    }

    fn neighbor(addr: &str, asn: u32) -> server_proto::NeighborState {
        server_proto::NeighborState {
            config: Some(server_proto::NeighborConfig {
                address: addr.to_string(),
                remote_asn: asn,
                families: vec!["ipv4_unicast".to_string(), "ipv6_unicast".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    fn page(
        routes: Vec<server_proto::Route>,
        next_page_token: &str,
        total_count: u64,
    ) -> server_proto::ListRoutesResponse {
        server_proto::ListRoutesResponse {
            routes,
            next_page_token: next_page_token.to_string(),
            total_count,
        }
    }

    /// Spawn a mock daemon with the standard test peer and the given
    /// canned advertised-route pages.
    async fn server_with_pages(
        pages: Vec<server_proto::ListRoutesResponse>,
    ) -> crate::test_support::MockServerHandle {
        let server = spawn_mock_server(None).await;
        *server.state.list_neighbors_response.lock().await = vec![neighbor(PEER, PEER_ASN)];
        *server.state.list_route_pages.lock().await = pages;
        server
    }

    async fn run_against(
        server: &crate::test_support::MockServerHandle,
        opts: &AdvertisedDiffOpts,
    ) -> Result<(String, i32), CliError> {
        let connection = connect(&server.addr, None).await.unwrap();
        run(connection, opts).await
    }

    fn prefix(i: usize) -> String {
        format!("10.{}.{}.0/24", i / 250, i % 250)
    }

    // 150 routes cross the historical 100-row pagination boundary.
    fn many_route_lines(n: usize) -> Vec<String> {
        let mut lines = vec![header_line()];
        for i in 0..n {
            lines.push(route_line(&prefix(i), None));
        }
        lines.push(trailer_line(n as u64));
        lines
    }

    fn many_live_pages(n: usize, per_page: usize) -> Vec<server_proto::ListRoutesResponse> {
        let routes: Vec<server_proto::Route> = (0..n)
            .map(|i| {
                let full = prefix(i);
                let (addr, _) = full.split_once('/').unwrap();
                live_route(addr, 0)
            })
            .collect();
        let mut pages = Vec::new();
        let chunks: Vec<&[server_proto::Route]> = routes.chunks(per_page).collect();
        for (idx, chunk) in chunks.iter().enumerate() {
            let last = idx + 1 == chunks.len();
            let token = if last {
                String::new()
            } else {
                format!("p{}", idx + 1)
            };
            pages.push(page(chunk.to_vec(), &token, n as u64));
        }
        pages
    }

    #[tokio::test]
    async fn in_sync_above_pagination_boundary_exits_zero() {
        let file = snapshot_file(&many_route_lines(150));
        let server = server_with_pages(many_live_pages(150, 100)).await;
        let (rendered, code) = run_against(&server, &opts(file.path())).await.unwrap();
        assert_eq!(code, EXIT_IN_SYNC, "output was:\n{rendered}");
        assert!(rendered.contains("verdict: in_sync"));
        assert!(rendered.contains("matched 150"));
        // The pagination loop advanced through the canned tokens.
        let requests = server.state.list_route_requests.lock().await;
        let tokens: Vec<&str> = requests.iter().map(|r| r.page_token.as_str()).collect();
        assert_eq!(tokens, vec!["", "p1"]);
    }

    #[tokio::test]
    async fn divergent_attribute_exits_one() {
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", Some(10)),
            trailer_line(1),
        ]);
        let server = server_with_pages(vec![page(vec![live_route("10.0.0.0", 20)], "", 1)]).await;
        let (rendered, code) = run_against(&server, &opts(file.path())).await.unwrap();
        assert_eq!(code, EXIT_DIVERGENT, "output was:\n{rendered}");
        assert!(rendered.contains("verdict: divergent"));
        assert!(rendered.contains("med: 10 -> 20"));
    }

    #[tokio::test]
    async fn missing_trailer_is_incomplete_exits_two() {
        // EOF alone is NOT completeness.
        let file = snapshot_file(&[header_line(), route_line("10.0.0.0/24", None)]);
        let server = server_with_pages(vec![]).await;
        let err = run_against(&server, &opts(file.path())).await.unwrap_err();
        assert!(
            err.to_string().contains("missing completion trailer"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn trailer_count_mismatch_exits_two() {
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", None),
            trailer_line(2),
        ]);
        let server = server_with_pages(vec![]).await;
        let err = run_against(&server, &opts(file.path())).await.unwrap_err();
        assert!(
            err.to_string().contains("trailer count mismatch"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn malformed_snapshot_exits_two() {
        // Truncated JSON line.
        let file = snapshot_file(&[
            header_line(),
            r#"{"record":"route","peer":"192.0.2.1""#.to_string(),
        ]);
        let server = server_with_pages(vec![]).await;
        let err = run_against(&server, &opts(file.path())).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid JSON"),
            "unexpected error: {err}"
        );

        // Unknown schema version.
        let file = snapshot_file(&[
            header_line().replace(SNAPSHOT_SCHEMA, "rbgp-ribsnap/99"),
            trailer_line(0),
        ]);
        let err = run_against(&server, &opts(file.path())).await.unwrap_err();
        assert!(
            err.to_string().contains("unsupported snapshot schema"),
            "unexpected error: {err}"
        );

        // Unknown field in a route record (typo protection: a misspelled
        // attribute must not silently compare as absent).
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", Some(1)).replace("\"med\"", "\"medd\""),
            trailer_line(1),
        ]);
        let err = run_against(&server, &opts(file.path())).await.unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "unexpected error: {err}"
        );

        // Malformed unknown_attrs hex value.
        let file = snapshot_file(&[
            header_line(),
            format!(
                r#"{{"record":"route","peer":"{PEER}","peer_asn":{PEER_ASN},"prefix":"10.0.0.0/24","unknown_attrs":[{{"type_code":35,"flags":192,"value":"0zz0"}}]}}"#
            ),
            trailer_line(1),
        ]);
        let err = run_against(&server, &opts(file.path())).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid hex value"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn repeated_page_token_exits_two() {
        // Non-advancing: the server keeps returning the same token.
        let file = snapshot_file(&[header_line(), trailer_line(0)]);
        let server = server_with_pages(vec![
            page(vec![live_route("10.0.0.0", 0)], "p1", 3),
            page(vec![live_route("10.0.1.0", 0)], "p1", 3),
        ])
        .await;
        let mut pinned = opts(file.path());
        pinned.peers = vec![PEER.to_string()];
        let err = run_against(&server, &pinned).await.unwrap_err();
        assert!(
            err.to_string().contains("repeated page token"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn cyclic_page_token_exits_two() {
        // Duplicate page: p1 -> p2 -> p1 revisits an already-served page.
        let file = snapshot_file(&[header_line(), trailer_line(0)]);
        let server = server_with_pages(vec![
            page(vec![live_route("10.0.0.0", 0)], "p1", 9),
            page(vec![live_route("10.0.1.0", 0)], "p2", 9),
            page(vec![live_route("10.0.2.0", 0)], "p1", 9),
        ])
        .await;
        let mut pinned = opts(file.path());
        pinned.peers = vec![PEER.to_string()];
        let err = run_against(&server, &pinned).await.unwrap_err();
        assert!(
            err.to_string().contains("repeated page token"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn total_count_drift_across_pages_exits_two() {
        // The API exposes no generation token; total_count movement is the
        // RIB-changed-mid-capture detector.
        let file = snapshot_file(&[header_line(), trailer_line(0)]);
        let server = server_with_pages(vec![
            page(vec![live_route("10.0.0.0", 0)], "p1", 2),
            page(vec![live_route("10.0.1.0", 0)], "", 3),
        ])
        .await;
        let mut pinned = opts(file.path());
        pinned.peers = vec![PEER.to_string()];
        let err = run_against(&server, &pinned).await.unwrap_err();
        assert!(
            err.to_string().contains("changed during pagination"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn live_count_short_of_total_exits_two() {
        let file = snapshot_file(&[header_line(), trailer_line(0)]);
        let server = server_with_pages(vec![page(vec![live_route("10.0.0.0", 0)], "", 3)]).await;
        let mut pinned = opts(file.path());
        pinned.peers = vec![PEER.to_string()];
        let err = run_against(&server, &pinned).await.unwrap_err();
        assert!(
            err.to_string().contains("fetched 1 routes")
                && err.to_string().contains("total_count 3"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn max_routes_limit_enforced_exits_two() {
        // Snapshot side.
        let file = snapshot_file(&many_route_lines(5));
        let server = server_with_pages(vec![]).await;
        let mut limited = opts(file.path());
        limited.max_routes = 3;
        let err = run_against(&server, &limited).await.unwrap_err();
        assert!(
            err.to_string().contains("max_routes limit exceeded"),
            "unexpected error: {err}"
        );

        // Live side.
        let file = snapshot_file(&many_route_lines(2));
        let server = server_with_pages(many_live_pages(5, 5)).await;
        let mut limited = opts(file.path());
        limited.max_routes = 2;
        let err = run_against(&server, &limited).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("max_routes limit exceeded while fetching"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn max_input_bytes_limit_enforced_exits_two() {
        let file = snapshot_file(&many_route_lines(50));
        let server = server_with_pages(vec![]).await;
        let mut limited = opts(file.path());
        limited.max_input_bytes = 256;
        let err = run_against(&server, &limited).await.unwrap_err();
        assert!(
            err.to_string().contains("max_input_bytes limit exceeded"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn deadline_expiry_exits_two() {
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", None),
            trailer_line(1),
        ]);
        let server = server_with_pages(vec![page(vec![live_route("10.0.0.0", 0)], "", 1)]).await;
        let mut expired = opts(file.path());
        expired.deadline_seconds = 0;
        let err = run_against(&server, &expired).await.unwrap_err();
        assert!(
            err.to_string().contains("deadline expired"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn unavailable_peer_refuses_equal_verdict() {
        // Snapshot and live route sets would compare clean, but the peer is
        // not configured on the daemon: the aggregate equal verdict must be
        // refused (exit 2), never 0.
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", None),
            trailer_line(1),
        ]);
        let server = spawn_mock_server(None).await; // no neighbors configured
        let (rendered, code) = run_against(&server, &opts(file.path())).await.unwrap();
        assert_eq!(code, EXIT_INCOMPARABLE, "output was:\n{rendered}");
        assert!(rendered.contains("not configured on the daemon"));
        assert!(rendered.contains("incomparable"));
    }

    #[tokio::test]
    async fn snapshot_asn_mismatch_refuses_equal_verdict() {
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", None),
            trailer_line(1),
        ]);
        let server = spawn_mock_server(None).await;
        *server.state.list_neighbors_response.lock().await = vec![neighbor(PEER, 64999)];
        let (rendered, code) = run_against(&server, &opts(file.path())).await.unwrap();
        assert_eq!(code, EXIT_INCOMPARABLE, "output was:\n{rendered}");
        assert!(rendered.contains("ASN mismatch"));
    }

    #[tokio::test]
    async fn requested_family_not_configured_refuses_equal_verdict() {
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", None),
            trailer_line(1),
        ]);
        let server = spawn_mock_server(None).await;
        *server.state.list_neighbors_response.lock().await = vec![server_proto::NeighborState {
            config: Some(server_proto::NeighborConfig {
                address: PEER.to_string(),
                remote_asn: PEER_ASN,
                families: vec!["ipv4_unicast".to_string()],
                ..Default::default()
            }),
            ..Default::default()
        }];
        let mut v6 = opts(file.path());
        v6.families = vec!["ipv6_unicast".to_string()];
        let (rendered, code) = run_against(&server, &v6).await.unwrap();
        assert_eq!(code, EXIT_INCOMPARABLE, "output was:\n{rendered}");
        assert!(rendered.contains("family ipv6_unicast is not configured"));
    }

    #[tokio::test]
    async fn live_med_zero_compares_as_absent() {
        // The documented live-source MED conflation: snapshot omits med,
        // daemon reports med=0 — in sync.
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", None),
            trailer_line(1),
        ]);
        let server = server_with_pages(vec![page(vec![live_route("10.0.0.0", 0)], "", 1)]).await;
        let (rendered, code) = run_against(&server, &opts(file.path())).await.unwrap();
        assert_eq!(code, EXIT_IN_SYNC, "output was:\n{rendered}");
    }

    #[tokio::test]
    async fn med_attr_compares_exactly_and_drops_conflation_caveat() {
        // A MED-absence-aware daemon (med_attr populated): explicit
        // MED 0 stays 0 and absent stays absent, so a snapshot carrying
        // explicit med:0 diffs clean against a live med=0 — and the
        // MED-conflation caveat disappears from the report notes.
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", Some(0)),
            route_line("10.0.1.0/24", None),
            trailer_line(2),
        ]);
        let server = server_with_pages(vec![page(
            vec![
                live_route_with_med_attr("10.0.0.0", 0, Some(0)),
                live_route_with_med_attr("10.0.1.0", 0, None),
            ],
            "",
            2,
        )])
        .await;
        let mut json_opts = opts(file.path());
        json_opts.json = true;
        let (rendered, code) = run_against(&server, &json_opts).await.unwrap();
        assert_eq!(code, EXIT_IN_SYNC, "output was:\n{rendered}");
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let notes = value["live_source_notes"].as_array().unwrap();
        assert!(
            notes
                .iter()
                .all(|n| !n.as_str().unwrap().starts_with("med:")),
            "MED caveat should be dropped when med_attr is present: {notes:?}"
        );
        assert!(!notes.is_empty(), "structural notes remain");
    }

    #[tokio::test]
    async fn med_attr_missing_keeps_fallback_mapping_and_caveat() {
        // Older daemon (med_attr populated nowhere): live med=0 still
        // maps to absent and the MED-conflation caveat stays in the
        // report notes.
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", None),
            trailer_line(1),
        ]);
        let server = server_with_pages(vec![page(vec![live_route("10.0.0.0", 0)], "", 1)]).await;
        let mut json_opts = opts(file.path());
        json_opts.json = true;
        let (rendered, code) = run_against(&server, &json_opts).await.unwrap();
        assert_eq!(code, EXIT_IN_SYNC, "output was:\n{rendered}");
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        let notes = value["live_source_notes"].as_array().unwrap();
        assert!(
            notes
                .iter()
                .any(|n| n.as_str().unwrap().starts_with("med:")),
            "MED caveat should be kept for daemons without med_attr: {notes:?}"
        );
    }

    #[tokio::test]
    async fn ignore_attribute_med_suppresses_divergence_and_is_reported() {
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", Some(10)),
            trailer_line(1),
        ]);
        let server = server_with_pages(vec![page(vec![live_route("10.0.0.0", 20)], "", 1)]).await;
        let mut ignoring = opts(file.path());
        ignoring.ignore_attributes = vec!["med".to_string()];
        ignoring.json = true;
        let (rendered, code) = run_against(&server, &ignoring).await.unwrap();
        assert_eq!(code, EXIT_IN_SYNC, "output was:\n{rendered}");
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value["ignored_attributes"], serde_json::json!(["med"]));
        assert!(
            value["live_source_notes"]
                .as_array()
                .is_some_and(|n| !n.is_empty())
        );
        assert_eq!(value["schema"], ribdiff::SCHEMA_VERSION);

        // Human output carries the same normalization disclosures.
        let mut human = opts(file.path());
        human.ignore_attributes = vec!["med".to_string()];
        *server.state.list_route_pages.lock().await =
            vec![page(vec![live_route("10.0.0.0", 20)], "", 1)];
        let (rendered, _) = run_against(&server, &human).await.unwrap();
        assert!(rendered.contains("ignored attributes: med"));
        assert!(rendered.contains("live-source notes:"));
    }

    #[tokio::test]
    async fn output_is_byte_identical_across_runs() {
        let lines = [
            header_line(),
            route_line("10.0.0.0/24", Some(10)),
            route_line("10.0.1.0/24", None),
            trailer_line(2),
        ];
        let file = snapshot_file(&lines);
        let pages = || {
            vec![page(
                vec![live_route("10.0.0.0", 20), live_route("10.0.2.0", 0)],
                "",
                2,
            )]
        };
        let server = server_with_pages(pages()).await;
        let (first_human, first_code) = run_against(&server, &opts(file.path())).await.unwrap();
        *server.state.list_route_pages.lock().await = pages();
        let (second_human, second_code) = run_against(&server, &opts(file.path())).await.unwrap();
        assert_eq!(first_human, second_human);
        assert_eq!(first_code, second_code);
        assert_eq!(first_code, EXIT_DIVERGENT);

        let mut json_opts = opts(file.path());
        json_opts.json = true;
        *server.state.list_route_pages.lock().await = pages();
        let (first_json, _) = run_against(&server, &json_opts).await.unwrap();
        *server.state.list_route_pages.lock().await = pages();
        let (second_json, _) = run_against(&server, &json_opts).await.unwrap();
        assert_eq!(first_json, second_json);
    }

    /// Golden-fixture matrix for the incumbent snapshot adapters
    /// (LAN-308): each converter's output over a raw capture from a real
    /// M83 lab container must match its checked-in golden byte for byte
    /// (upstream schema drift breaks these first), parse as a valid
    /// `rbgp-ribsnap/1` snapshot, and diff clean against a mock daemon
    /// seeded with the same capture's wire-truth values under the
    /// adapter's documented ignore set.
    ///
    /// Fixture provenance + refresh procedure: deploy the M83 lab
    /// (tests/interop/m83-routeserver-multistack.clab.yml), start
    /// BIRD/gobgpd and inject the GoBGP member routes per the M83 test
    /// script, apply the attribute-marking route-map on FRR so the
    /// capture exercises MED + communities
    /// (`route-map RSOUT permit 10` + `set metric 55` +
    /// `set community 65003:99`, applied out toward 10.83.3.1), then:
    ///
    ///   bird:  birdc show route export routeserver all
    ///   frr:   vtysh -c "show ip bgp neighbor 10.83.3.1 \
    ///            advertised-routes detail json"   (and the summary
    ///            form, kept as the refusal fixture)
    ///   gobgp: gobgp neighbor 10.83.2.1 adj-out -j
    ///
    /// Versions at capture: BIRD 2.0.12, FRR 10.3.1, GoBGP 3.37.0.
    /// Regenerate the .expected.ndjson goldens by re-running the
    /// converters with `--generation 7` and the per-adapter args below.
    mod adapters {
        use super::*;

        const GENERATION: &str = "7";

        #[derive(Clone, Copy)]
        struct Converter {
            script: &'static str,
            raw_fixture: &'static str,
            golden: &'static str,
            peer: &'static str,
            source: &'static str,
        }

        const BIRD: Converter = Converter {
            script: "bird2-export-to-ribsnap.py",
            raw_fixture: "bird-m83-export.txt",
            golden: "bird-m83.expected.ndjson",
            peer: "10.83.1.1",
            source: "m83-bird-member",
        };
        const FRR: Converter = Converter {
            script: "frr-advertised-to-ribsnap.py",
            raw_fixture: "frr-m83-advertised-detail.json",
            golden: "frr-m83.expected.ndjson",
            peer: "10.83.3.1",
            source: "m83-frr-member",
        };
        const GOBGP: Converter = Converter {
            script: "gobgp-adjout-to-ribsnap.py",
            raw_fixture: "gobgp-m83-adjout.json",
            golden: "gobgp-m83.expected.ndjson",
            peer: "10.83.2.1",
            source: "m83-gobgp-member",
        };
        /// All snapshots record advertisement toward the M83 route
        /// server (10.83.x.1, AS 65500).
        const RS_ASN: u32 = 65500;

        fn fixture_path(name: &str) -> std::path::PathBuf {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/ribsnap")
                .join(name)
        }

        fn converter_output(converter: &Converter) -> std::process::Output {
            let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../scripts/ribsnap")
                .join(converter.script);
            std::process::Command::new("python3")
                .arg(script)
                .args(["--peer", converter.peer])
                .args(["--peer-asn", &RS_ASN.to_string()])
                .args(["--source", converter.source])
                .args(["--generation", GENERATION])
                .arg(fixture_path(converter.raw_fixture))
                .output()
                .expect("python3 must be runnable for the adapter golden tests")
        }

        /// Converter stdout must match the golden byte for byte and the
        /// golden must parse as a complete, valid snapshot.
        fn check_golden(converter: &Converter) -> SnapshotData {
            let output = converter_output(converter);
            assert!(
                output.status.success(),
                "{} failed: {}",
                converter.script,
                String::from_utf8_lossy(&output.stderr)
            );
            let golden_path = fixture_path(converter.golden);
            // BLESS=1 rewrites the golden (fixture refresh; review the diff).
            if std::env::var_os("BLESS").is_some() {
                std::fs::write(&golden_path, &output.stdout).unwrap();
            }
            let golden = std::fs::read(&golden_path).unwrap();
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&golden),
                "{} output diverged from {} — an upstream output-format \
                 change or a converter regression",
                converter.script,
                converter.golden
            );
            let opts = opts(&golden_path);
            parse_snapshot(&golden[..], &opts, &[], &BTreeSet::new(), &[])
                .expect("golden snapshot must parse as rbgp-ribsnap/1")
        }

        /// Mock daemon advertising the wire-truth routes captured from
        /// the same lab (what `rbgp rib recv` on the RS reported each
        /// member actually put on the wire).
        async fn wire_truth_server(
            peer: &str,
            routes: Vec<server_proto::Route>,
        ) -> crate::test_support::MockServerHandle {
            let server = spawn_mock_server(None).await;
            *server.state.list_neighbors_response.lock().await = vec![neighbor(peer, RS_ASN)];
            let total = routes.len() as u64;
            *server.state.list_route_pages.lock().await = vec![page(routes, "", total)];
            server
        }

        fn wire_route(
            prefix: &str,
            len: u32,
            next_hop: &str,
            as_path: Vec<u32>,
        ) -> server_proto::Route {
            server_proto::Route {
                prefix: prefix.to_string(),
                prefix_length: len,
                next_hop: next_hop.to_string(),
                origin: 0, // all M83 member routes were IGP-origin
                as_path,
                ..Default::default()
            }
        }

        async fn diff_golden_against(
            converter: &Converter,
            server: &crate::test_support::MockServerHandle,
            ignore: &[&str],
        ) -> (String, i32) {
            let mut opts = opts(&fixture_path(converter.golden));
            opts.ignore_attributes = ignore.iter().map(|s| s.to_string()).collect();
            run_against(server, &opts).await.unwrap()
        }

        #[tokio::test]
        async fn bird_golden_matches_and_diffs_clean() {
            check_golden(&BIRD);
            // Wire truth from the lab: BIRD advertised 4 statics with
            // next hop 10.83.1.2 and path [65001]. The BIRD export view
            // omits as_path/next_hop/origin for locally-originated
            // routes (pre-encoding view), hence the documented ignore
            // set; MED and communities compare for real.
            let routes = vec![
                server_proto::Route {
                    communities: vec![(65001 << 16) | 666],
                    ..wire_route("100.65.0.0", 24, "10.83.1.2", vec![65001])
                },
                wire_route("100.69.0.0", 24, "10.83.1.2", vec![65001]),
                wire_route("100.70.0.0", 24, "10.83.1.2", vec![65001]),
                server_proto::Route {
                    med: 120,
                    communities: vec![(65001 << 16) | 111],
                    large_communities: vec!["65001:1:1".to_string()],
                    ..wire_route("203.0.113.0", 24, "10.83.1.2", vec![65001])
                },
            ];
            let server = wire_truth_server(BIRD.peer, routes).await;
            let (rendered, code) =
                diff_golden_against(&BIRD, &server, &["as_path", "next_hop", "origin"]).await;
            assert_eq!(code, EXIT_IN_SYNC, "output was:\n{rendered}");
            assert!(rendered.contains("matched 4"));
        }

        #[tokio::test]
        async fn frr_golden_matches_and_diffs_clean() {
            check_golden(&FRR);
            // Wire truth: FRR advertised 3 networks with the RSOUT
            // route-map applied (MED 55, community 65003:99), path
            // [65003], next hop 10.83.3.2. The FRR detail view shows
            // pre-prepend AS path and placeholder next hops for
            // self-originated routes, hence the documented ignore set;
            // origin, MED, and communities compare for real.
            let routes = ["100.67.0.0", "100.68.0.0", "100.70.0.0"]
                .into_iter()
                .map(|p| server_proto::Route {
                    med: 55,
                    communities: vec![(65003 << 16) | 99],
                    ..wire_route(p, 24, "10.83.3.2", vec![65003])
                })
                .collect();
            let server = wire_truth_server(FRR.peer, routes).await;
            let (rendered, code) =
                diff_golden_against(&FRR, &server, &["as_path", "next_hop"]).await;
            assert_eq!(code, EXIT_IN_SYNC, "output was:\n{rendered}");
            assert!(rendered.contains("matched 3"));
        }

        #[tokio::test]
        async fn gobgp_golden_matches_and_diffs_clean() {
            check_golden(&GOBGP);
            // GoBGP adj-out is the true post-policy Adj-RIB-Out (own
            // ASN prepended, next hop rewritten): full attribute
            // comparison, no ignores.
            let routes = vec![
                wire_route("100.65.0.0", 24, "10.83.2.2", vec![65002]),
                server_proto::Route {
                    med: 77,
                    communities: vec![(65002 << 16) | 222],
                    large_communities: vec!["65002:2:2".to_string()],
                    ..wire_route("100.66.0.0", 24, "10.83.2.2", vec![65002])
                },
            ];
            let server = wire_truth_server(GOBGP.peer, routes).await;
            let (rendered, code) = diff_golden_against(&GOBGP, &server, &[]).await;
            assert_eq!(code, EXIT_IN_SYNC, "output was:\n{rendered}");
            assert!(rendered.contains("matched 2"));
        }

        /// The explained-difference outcome from the lab: the RS
        /// rejected 100.68.0.0/24 at import (RPKI-invalid per the M83
        /// VRP fixture), so the incumbent-side capture carries one
        /// route the rustbgpd side does not — exit 1 with an
        /// incumbent-only row, never a false "in sync".
        #[tokio::test]
        async fn frr_rov_rejection_reads_as_incumbent_only() {
            let routes = ["100.67.0.0", "100.70.0.0"]
                .into_iter()
                .map(|p| server_proto::Route {
                    med: 55,
                    communities: vec![(65003 << 16) | 99],
                    ..wire_route(p, 24, "10.83.3.2", vec![65003])
                })
                .collect();
            let server = wire_truth_server(FRR.peer, routes).await;
            let (rendered, code) =
                diff_golden_against(&FRR, &server, &["as_path", "next_hop"]).await;
            assert_eq!(code, EXIT_DIVERGENT, "output was:\n{rendered}");
            assert!(rendered.contains("verdict: divergent"));
            assert!(rendered.contains("100.68.0.0/24 [incumbent-only]"));
        }

        /// Drift protection for the refusal path: the FRR summary form
        /// (a real 10.3.1 capture) omits communities entirely, so the
        /// converter must refuse it (exit 2, nothing on stdout) rather
        /// than emit a snapshot that can never show a communities
        /// difference.
        #[test]
        fn frr_summary_form_is_refused() {
            let mut converter = FRR;
            converter.raw_fixture = "frr-m83-advertised-summary.json";
            let output = converter_output(&converter);
            assert_eq!(output.status.code(), Some(2));
            assert!(output.stdout.is_empty(), "refusal must not emit a snapshot");
            assert!(String::from_utf8_lossy(&output.stderr).contains("summary form"));
        }

        /// Malformed input is refused (exit 2, no stdout) by every
        /// converter — EOF-completeness fabrication is impossible
        /// because the trailer is only written after a full parse.
        #[test]
        fn garbage_input_is_refused_by_all_converters() {
            for converter in [&BIRD, &FRR, &GOBGP] {
                let mut bad = *converter;
                bad.raw_fixture = "bird-m83-export.txt"; // valid for BIRD only
                if converter.script == BIRD.script {
                    bad.raw_fixture = "gobgp-m83-adjout.json"; // JSON is not birdc text
                }
                let output = converter_output(&bad);
                assert_eq!(
                    output.status.code(),
                    Some(2),
                    "{} accepted foreign input",
                    converter.script
                );
                assert!(output.stdout.is_empty());
            }
        }

        /// `rbgp diff snapshot from-mrt` output (the from-mrt golden)
        /// round-trips through the snapshot parser and diffs clean
        /// against a daemon advertising the same routes — Add-Path
        /// duplicates compare by multiplicity, path IDs are never
        /// compared.
        #[tokio::test]
        async fn from_mrt_golden_diffs_clean() {
            let golden = fixture_path("from-mrt.expected.ndjson");
            let v6 = |path_id: u32| server_proto::Route {
                prefix: "2001:db8::".to_string(),
                prefix_length: 32,
                next_hop: "2001:db8::1".to_string(),
                origin: 0,
                as_path: vec![65001],
                path_id,
                ..Default::default()
            };
            let routes = vec![
                server_proto::Route {
                    prefix: "203.0.113.0".to_string(),
                    prefix_length: 24,
                    next_hop: "192.0.2.1".to_string(),
                    origin: 0,
                    as_path: vec![65001, 65002],
                    med: 120,
                    local_pref_attr: Some(100),
                    communities: vec![(65001 << 16) | 111],
                    extended_communities: vec![0x0002_FDE9_0000_006F],
                    large_communities: vec!["65001:1:1".to_string()],
                    ..Default::default()
                },
                v6(1),
                v6(2),
            ];
            let server = spawn_mock_server(None).await;
            *server.state.list_neighbors_response.lock().await = vec![neighbor("192.0.2.9", 64501)];
            *server.state.list_route_pages.lock().await = vec![page(routes, "", 3)];
            let (rendered, code) = run_against(&server, &opts(&golden)).await.unwrap();
            assert_eq!(code, EXIT_IN_SYNC, "output was:\n{rendered}");
            // Per-family summaries count NLRIs: 1 IPv4, 1 IPv6 (whose two
            // Add-Path copies matched as a multiplicity-2 multiset).
            assert!(rendered.contains("ipv4_unicast: matched 1"));
            assert!(rendered.contains("ipv6_unicast: matched 1"));
        }

        /// Wire-truth routes matching the from-bmp golden capture
        /// (crates/cli/src/commands/ribsnap_bmp.rs `golden_capture`,
        /// regenerated with `BLESS=1`).
        fn from_bmp_wire_truth() -> Vec<Vec<server_proto::Route>> {
            let peer_a = vec![
                server_proto::Route {
                    prefix: "100.64.0.0".to_string(),
                    prefix_length: 24,
                    next_hop: "192.0.2.254".to_string(),
                    origin: 1,
                    as_path: vec![65500],
                    local_pref_attr: Some(200),
                    extended_communities: vec![0x0002_FFDC_0000_0064],
                    large_communities: vec!["65500:7:9".to_string()],
                    path_id: 1,
                    ..Default::default()
                },
                server_proto::Route {
                    prefix: "203.0.113.0".to_string(),
                    prefix_length: 24,
                    next_hop: "192.0.2.254".to_string(),
                    origin: 0,
                    as_path: vec![65500, 64999],
                    med: 121,
                    communities: vec![(65500 << 16) | 100],
                    path_id: 1,
                    ..Default::default()
                },
                server_proto::Route {
                    prefix: "203.0.113.0".to_string(),
                    prefix_length: 24,
                    next_hop: "192.0.2.253".to_string(),
                    origin: 0,
                    as_path: vec![65500, 64998],
                    path_id: 2,
                    ..Default::default()
                },
            ];
            let peer_b = vec![
                server_proto::Route {
                    prefix: "100.65.0.0".to_string(),
                    prefix_length: 24,
                    next_hop: "192.0.2.254".to_string(),
                    origin: 0,
                    as_path: vec![65500, 64997],
                    ..Default::default()
                },
                server_proto::Route {
                    prefix: "2001:db8:100::".to_string(),
                    prefix_length: 48,
                    next_hop: "2001:db8::1".to_string(),
                    origin: 0,
                    as_path: vec![65500, 64997],
                    med: 51,
                    ..Default::default()
                },
            ];
            vec![peer_a, peer_b]
        }

        async fn from_bmp_server(
            pages: Vec<Vec<server_proto::Route>>,
        ) -> crate::test_support::MockServerHandle {
            let server = spawn_mock_server(None).await;
            *server.state.list_neighbors_response.lock().await =
                vec![neighbor("192.0.2.1", 65001), neighbor("2001:db8::2", 65002)];
            *server.state.list_route_pages.lock().await = pages
                .into_iter()
                .map(|routes| {
                    let total = routes.len() as u64;
                    page(routes, "", total)
                })
                .collect();
            server
        }

        /// End-to-end for the from-bmp adapter's in-sync verdict: the
        /// golden snapshot (BMP capture → canonical records) diffs
        /// clean against a daemon advertising the same wire truth.
        /// `--ignore-attribute unknown` reflects the documented live
        /// limitation: the snapshot preserves the capture's OTC and
        /// unknown transitive attributes byte-exact, but they are not
        /// visible over gRPC.
        #[tokio::test]
        async fn from_bmp_golden_diffs_clean() {
            let golden = fixture_path("from-bmp.expected.ndjson");
            let server = from_bmp_server(from_bmp_wire_truth()).await;
            let mut opts = opts(&golden);
            opts.ignore_attributes = vec!["unknown".to_string()];
            let (rendered, code) = run_against(&server, &opts).await.unwrap();
            assert_eq!(code, EXIT_IN_SYNC, "output was:\n{rendered}");
            assert!(rendered.contains("192.0.2.1 AS65001 ipv4_unicast: matched 2"));
            assert!(rendered.contains("2001:db8::2 AS65002 ipv4_unicast: matched 1"));
            assert!(rendered.contains("2001:db8::2 AS65002 ipv6_unicast: matched 1"));
        }

        /// End-to-end divergent verdict: preserved unknown attributes
        /// surface as divergence when not ignored (the operator must
        /// decide, never a silent drop), and an attribute delta on the
        /// live side reads as attribute-changed.
        #[tokio::test]
        async fn from_bmp_golden_divergence_is_reported() {
            let golden = fixture_path("from-bmp.expected.ndjson");
            // Unignored unknown attributes: the incumbent capture has
            // them, gRPC cannot see them.
            let server = from_bmp_server(from_bmp_wire_truth()).await;
            let (rendered, code) = run_against(&server, &opts(&golden)).await.unwrap();
            assert_eq!(code, EXIT_DIVERGENT, "output was:\n{rendered}");
            assert!(rendered.contains("100.64.0.0/24 [attribute-changed] unknown:"));

            // A real attribute delta (MED drift on the v6 route).
            let mut truth = from_bmp_wire_truth();
            truth[1][1].med = 999;
            let server = from_bmp_server(truth).await;
            let mut opts = opts(&golden);
            opts.ignore_attributes = vec!["unknown".to_string()];
            let (rendered, code) = run_against(&server, &opts).await.unwrap();
            assert_eq!(code, EXIT_DIVERGENT, "output was:\n{rendered}");
            assert!(rendered.contains("med: 51 -> 999"));
        }
    }

    #[tokio::test]
    async fn peer_filter_selects_and_content_after_trailer_is_malformed() {
        // --peer restricts the comparison to the named peer.
        let other_peer = serde_json::json!({
            "record": "route",
            "peer": "203.0.113.9",
            "peer_asn": 65099,
            "prefix": "10.9.0.0/24",
        })
        .to_string();
        let file = snapshot_file(&[
            header_line(),
            route_line("10.0.0.0/24", None),
            other_peer,
            trailer_line(2),
        ]);
        let server = server_with_pages(vec![page(vec![live_route("10.0.0.0", 0)], "", 1)]).await;
        let mut filtered = opts(file.path());
        filtered.peers = vec![PEER.to_string()];
        let (rendered, code) = run_against(&server, &filtered).await.unwrap();
        assert_eq!(code, EXIT_IN_SYNC, "output was:\n{rendered}");
        assert!(!rendered.contains("203.0.113.9"));

        // Records after the trailer are malformed.
        let file = snapshot_file(&[
            header_line(),
            trailer_line(0),
            route_line("10.0.0.0/24", None),
        ]);
        let err = run_against(&server, &opts(file.path())).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("content after the completion trailer"),
            "unexpected error: {err}"
        );
    }
}
