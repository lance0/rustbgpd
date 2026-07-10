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
    PathAttrs, PeerId, RoutePath, RouteSet, SnapshotMeta, Verdict,
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
];

/// Honest limitations of the live gRPC source, emitted verbatim in both
/// human and JSON output so a reader knows exactly what the comparison
/// could and could not see.
const LIVE_SOURCE_NOTES: &[&str] = &[
    "med: the daemon proto carries MED as a bare integer, so MED-absent and MED 0 are \
     indistinguishable over gRPC; live med=0 is compared as absent (snapshot producers \
     should omit `med` when it is zero or absent)",
    "as_path: the daemon proto exposes a flattened ASN list, so AS_PATH is compared as a \
     single AS_SEQUENCE on both sides; AS_SET structure is not compared",
    "unknown attributes: path attributes outside the typed set (origin, as_path, next_hop, \
     med, local_pref, communities, extended/large communities) are not visible over gRPC \
     and are not compared",
    "generation: the route-listing API exposes no RIB generation token; mid-walk listing \
     drift is detected via per-page total_count instead, and the snapshot header's \
     generation is adopted for the live side",
];

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
        fetch_advertised_into(
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
    let rendered = if opts.json {
        render_json(&report, &ignored)?
    } else {
        render_human(&report, &ignored, opts.detail)
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
    let attrs = PathAttrs {
        origin: route.origin,
        as_path: as_path_segment(&route.as_path),
        next_hop: route.next_hop,
        med: route.med,
        local_pref: route.local_pref,
        communities,
        extended_communities: route.extended_communities,
        large_communities,
        unknown: Vec::new(),
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
/// - `total_count` changing between pages means the listing moved under
///   the walk (the API exposes no generation token, so this is the drift
///   detector) and refuses the comparison;
/// - the fetched route count must equal the server's `total_count`;
/// - `--max-routes` is enforced before each page is buffered into the set;
/// - the shared deadline is checked before every RPC.
async fn fetch_advertised_into(
    client: &mut RibClient,
    peer: &PeerId,
    live: &mut RouteSet,
    family_filter: &[FamilyId],
    ignored: &[String],
    max_routes: usize,
    deadline: Instant,
) -> Result<(), CliError> {
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
    Ok(())
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
        // The proto carries MED as a bare u32: absent and 0 are
        // indistinguishable, so 0 maps to absent (see LIVE_SOURCE_NOTES).
        med: (route.med != 0).then_some(route.med),
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

fn render_json(report: &DiffReport, ignored: &[String]) -> Result<String, CliError> {
    let mut value = serde_json::to_value(report)?;
    let object = value
        .as_object_mut()
        .expect("DiffReport serializes to an object");
    object.insert("ignored_attributes".to_string(), serde_json::json!(ignored));
    object.insert(
        "live_source_notes".to_string(),
        serde_json::json!(LIVE_SOURCE_NOTES),
    );
    Ok(format!("{}\n", serde_json::to_string_pretty(&value)?))
}

fn render_human(report: &DiffReport, ignored: &[String], detail: usize) -> String {
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
    for note in LIVE_SOURCE_NOTES {
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
