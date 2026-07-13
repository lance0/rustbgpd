//! Canonical semantic route-record model and RIB comparison engine.
//!
//! Compares two captured route sets — rustbgpd's Adj-RIB-Out and an
//! incumbent route server's view of the same session — as a *multiset of
//! semantic paths* per (peer, family, NLRI). RFC 7911 path identifiers are
//! locally assigned, so they are retained for diagnostics but never
//! compared; two sides advertising the same paths under different numeric
//! IDs are in sync.
//!
//! Ingestion (gRPC pagination, MRT, BMP, vendor CLIs) is out of scope
//! here: adapters build [`RouteSet`]s through [`RouteSet::insert`] and
//! declare their provenance and completeness via [`SnapshotMeta`]. The
//! engine is pure and read-only.
//!
//! Invariants:
//! - equality is never reported from incomplete, truncated (over-limit),
//!   or mixed-generation input — such comparisons are `Incomparable`;
//! - no attribute is silently ignored: attributes the model does not type
//!   are carried in [`PathAttrs::unknown`] and compared byte-exact; the
//!   only ignored inputs are listed in [`NORMALIZATION`];
//! - reports are deterministic regardless of source ordering (ordered
//!   containers throughout — no hash-order dependence).

use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

/// Versioned identifier of the JSON result schema. Bump whenever the
/// shape of [`DiffReport`] or the canonicalization rules change.
pub const SCHEMA_VERSION: &str = "rbgp-ribdiff/1";

/// The normalization profile every report carries: the versioned
/// per-attribute canonicalization rules and the explicit list of inputs
/// the comparison ignores.
pub const NORMALIZATION: NormalizationProfile = NormalizationProfile {
    version: "v1",
    rules: &[
        "as_path: segment order and segment kind are significant; members of AS_SET / AS_CONFED_SET segments are sorted ascending",
        "communities, extended_communities, large_communities: sorted ascending; duplicates preserved",
        "med, local_pref: attribute absence is distinct from an explicit zero",
        "next_hop: compared as a canonical IP address",
        "unknown attributes: compared byte-exact (flags, type code, value), sorted by (type_code, flags, value); duplicates preserved",
        "paths: compared as a multiset per (peer, family, nlri); multiplicity differences are reported",
    ],
    ignored: &[
        "path_id (RFC 7911 identifiers are locally assigned; retained for diagnostics only)",
    ],
};

/// See [`NORMALIZATION`].
#[derive(Clone, Copy, Debug, Serialize)]
pub struct NormalizationProfile {
    /// Canonicalization rules version.
    pub version: &'static str,
    /// Human-readable per-attribute canonicalization rules.
    pub rules: &'static [&'static str],
    /// Inputs deliberately excluded from comparison.
    pub ignored: &'static [&'static str],
}

/// Provenance and completeness of one captured route set.
#[derive(Clone, Debug, Serialize)]
pub struct SnapshotMeta {
    /// Where the capture came from, e.g. `rustbgpd-grpc` or
    /// `mrt:dump-20260709`.
    pub source: String,
    /// Capture generation shared by the two sides of one comparison
    /// session. Snapshots from different generations (different capture
    /// rounds) are never reported equal.
    pub generation: u64,
    /// Whether the adapter observed a complete view (e.g. End-of-RIB seen,
    /// full dump read, all pages fetched). Incomplete captures are never
    /// reported equal.
    pub complete: bool,
}

/// Identity of the BGP peer a route was advertised to (or captured from).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PeerId {
    /// Peer transport address.
    pub address: IpAddr,
    /// Peer autonomous system number.
    pub asn: u32,
    /// Optional disambiguator when address + ASN is not unique — e.g. a
    /// BMP per-peer-header distinguisher or the peer's BGP identifier.
    pub distinguisher: Option<String>,
}

/// Address family as the wire (afi, safi) pair, so families beyond the
/// ones named here need no model change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct FamilyId {
    /// IANA Address Family Identifier.
    pub afi: u16,
    /// IANA Subsequent Address Family Identifier.
    pub safi: u8,
}

impl FamilyId {
    /// IPv4 unicast (1, 1).
    pub const IPV4_UNICAST: Self = Self { afi: 1, safi: 1 };
    /// IPv6 unicast (2, 1).
    pub const IPV6_UNICAST: Self = Self { afi: 2, safi: 1 };
}

/// An RFC 4364 route distinguisher, kept as its 8 wire octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Rd(pub [u8; 8]);

impl fmt::Display for Rd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        let rd_type = u16::from_be_bytes([b[0], b[1]]);
        match rd_type {
            0 => {
                let admin = u16::from_be_bytes([b[2], b[3]]);
                let assigned = u32::from_be_bytes([b[4], b[5], b[6], b[7]]);
                write!(f, "{admin}:{assigned}")
            }
            1 => {
                let assigned = u16::from_be_bytes([b[6], b[7]]);
                write!(f, "{}.{}.{}.{}:{assigned}", b[2], b[3], b[4], b[5])
            }
            2 => {
                let admin = u32::from_be_bytes([b[2], b[3], b[4], b[5]]);
                let assigned = u16::from_be_bytes([b[6], b[7]]);
                write!(f, "{admin}:{assigned}")
            }
            _ => {
                for octet in b {
                    write!(f, "{octet:02x}")?;
                }
                Ok(())
            }
        }
    }
}

impl Serialize for Rd {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// Typed NLRI identity. Identity fields stay typed (an RD, a label stack,
/// an Ethernet tag are never collapsed into a display string), and the
/// [`Nlri::Opaque`] escape hatch carries families this version does not
/// model without dropping them.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Nlri {
    /// IPv4/IPv6 (labeled) unicast prefix.
    Prefix {
        /// Prefix address.
        addr: IpAddr,
        /// Prefix length in bits.
        len: u8,
    },
    /// RFC 4364 / RFC 8277 VPN prefix.
    VpnPrefix {
        /// Route distinguisher.
        rd: Rd,
        /// MPLS label stack, outermost first.
        labels: Vec<u32>,
        /// Prefix address.
        addr: IpAddr,
        /// Prefix length in bits.
        len: u8,
    },
    /// RFC 7432 EVPN route.
    Evpn {
        /// EVPN route type (1–5).
        route_type: u8,
        /// Route distinguisher.
        rd: Rd,
        /// Ethernet tag identifier.
        ethernet_tag: u32,
        /// Remaining type-specific key octets (ESI / MAC / IP), verbatim.
        key: Vec<u8>,
    },
    /// Any family without a typed variant yet: raw NLRI octets, compared
    /// byte-exact under the record's [`FamilyId`].
    Opaque {
        /// Raw NLRI bytes as captured.
        bytes: Vec<u8>,
    },
}

impl Nlri {
    fn approx_bytes(&self) -> usize {
        match self {
            Nlri::Prefix { .. } => 18,
            Nlri::VpnPrefix { labels, .. } => 26 + labels.len() * 4,
            Nlri::Evpn { key, .. } => 14 + key.len(),
            Nlri::Opaque { bytes } => 1 + bytes.len(),
        }
    }
}

/// AS_PATH segment kind (RFC 4271 / RFC 5065). Kind is significant in
/// comparison: a SEQUENCE and a SET over the same ASNs differ.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AsSegmentKind {
    /// AS_SEQUENCE — ordered.
    Sequence,
    /// AS_SET — unordered; members are canonicalized sorted.
    Set,
    /// AS_CONFED_SEQUENCE — ordered.
    ConfedSequence,
    /// AS_CONFED_SET — unordered; members are canonicalized sorted.
    ConfedSet,
}

/// One AS_PATH segment.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct AsPathSegment {
    /// Segment kind.
    pub kind: AsSegmentKind,
    /// Member ASNs (order significant for sequence kinds).
    pub asns: Vec<u32>,
}

/// An attribute the model does not type. Represented and compared
/// byte-exact rather than dropped, so unknown transitive attributes
/// (e.g. an incumbent-added OTC or AIGP) still surface as divergence.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct UnknownAttr {
    /// BGP path attribute type code.
    pub type_code: u8,
    /// Wire flags octet.
    pub flags: u8,
    /// Raw value octets.
    pub value: Vec<u8>,
}

/// The compared, canonicalized attributes of one semantic path.
///
/// `Option` fields distinguish "attribute absent" from an explicit zero.
/// Canonicalization (applied on [`RouteSet::insert`]) is documented in
/// [`NORMALIZATION`].
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PathAttrs {
    /// ORIGIN (0 = IGP, 1 = EGP, 2 = INCOMPLETE).
    pub origin: Option<u8>,
    /// AS_PATH segments in wire order.
    pub as_path: Vec<AsPathSegment>,
    /// Next hop (from NEXT_HOP or MP_REACH_NLRI).
    pub next_hop: Option<IpAddr>,
    /// MULTI_EXIT_DISC.
    pub med: Option<u32>,
    /// LOCAL_PREF.
    pub local_pref: Option<u32>,
    /// RFC 1997 communities.
    pub communities: Vec<u32>,
    /// RFC 4360 extended communities as their 8 wire octets (big-endian).
    pub extended_communities: Vec<u64>,
    /// RFC 8092 large communities as (global admin, data 1, data 2).
    pub large_communities: Vec<[u32; 3]>,
    /// Attributes without a typed field above — never dropped.
    pub unknown: Vec<UnknownAttr>,
}

impl PathAttrs {
    fn canonicalize(&mut self) {
        for segment in &mut self.as_path {
            if matches!(segment.kind, AsSegmentKind::Set | AsSegmentKind::ConfedSet) {
                segment.asns.sort_unstable();
            }
        }
        self.communities.sort_unstable();
        self.extended_communities.sort_unstable();
        self.large_communities.sort_unstable();
        self.unknown.sort();
    }

    /// Number of distinct attributes carried (typed present + unknown).
    fn attr_count(&self) -> usize {
        usize::from(self.origin.is_some())
            + usize::from(!self.as_path.is_empty())
            + usize::from(self.next_hop.is_some())
            + usize::from(self.med.is_some())
            + usize::from(self.local_pref.is_some())
            + usize::from(!self.communities.is_empty())
            + usize::from(!self.extended_communities.is_empty())
            + usize::from(!self.large_communities.is_empty())
            + self.unknown.len()
    }

    fn approx_bytes(&self) -> usize {
        48 + self
            .as_path
            .iter()
            .map(|s| 8 + s.asns.len() * 4)
            .sum::<usize>()
            + self.communities.len() * 4
            + self.extended_communities.len() * 8
            + self.large_communities.len() * 12
            + self
                .unknown
                .iter()
                .map(|u| 4 + u.value.len())
                .sum::<usize>()
    }
}

/// One semantic path as advertised on one side.
#[derive(Clone, Debug, Serialize)]
pub struct RoutePath {
    /// Source-local RFC 7911 path identifier — diagnostics only, never
    /// part of comparison.
    pub path_id: Option<u32>,
    /// Canonicalized compared attributes.
    pub attrs: PathAttrs,
}

/// Hard resource bounds enforced while building a [`RouteSet`]. Any
/// violation fails the insert and marks the set truncated, which makes
/// the comparison [`Verdict::Incomparable`] — over-limit input can never
/// masquerade as equality.
#[derive(Clone, Copy, Debug)]
pub struct DiffLimits {
    /// Maximum distinct (peer, family, NLRI) keys per side. Default
    /// 4,000,000: a current full IPv4 + IPv6 table is ~1.2M routes;
    /// this leaves room for VPN/EVPN fan-out at a route server.
    pub max_routes: usize,
    /// Maximum paths per NLRI. Default 64: Add-Path route-server
    /// deployments advertise a handful of paths; 64 is far beyond any
    /// sane `send_max`.
    pub max_paths_per_nlri: usize,
    /// Maximum attributes per path (typed + unknown). Default 64: the
    /// attribute type space is 255, but real paths carry well under 20.
    pub max_attrs_per_path: usize,
    /// Maximum approximate size of one record (NLRI + attributes).
    /// Default 65,535: one maximal extended-message UPDATE.
    pub max_record_bytes: usize,
    /// Maximum approximate retained bytes per side. Default 1 GiB,
    /// sized so two full-table sides fit in a tooling box's memory.
    pub max_input_bytes: usize,
}

impl Default for DiffLimits {
    fn default() -> Self {
        Self {
            max_routes: 4_000_000,
            max_paths_per_nlri: 64,
            max_attrs_per_path: 64,
            max_record_bytes: 65_535,
            max_input_bytes: 1 << 30,
        }
    }
}

/// A resource bound was exceeded while building a [`RouteSet`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LimitExceeded {
    /// Which [`DiffLimits`] field was violated.
    pub limit: &'static str,
    /// The configured maximum.
    pub max: usize,
    /// The offending value.
    pub actual: usize,
}

impl fmt::Display for LimitExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} limit exceeded: {} > {}",
            self.limit, self.actual, self.max
        )
    }
}

impl std::error::Error for LimitExceeded {}

type RouteKey = (PeerId, FamilyId, Nlri);

/// One side's captured routes: a bounded multiset of semantic paths per
/// (peer, family, NLRI), plus provenance.
#[derive(Debug)]
pub struct RouteSet {
    meta: SnapshotMeta,
    limits: DiffLimits,
    routes: BTreeMap<RouteKey, Vec<RoutePath>>,
    approx_bytes: usize,
    truncated: bool,
}

impl RouteSet {
    /// Create an empty set with [`DiffLimits::default`].
    #[must_use]
    pub fn new(meta: SnapshotMeta) -> Self {
        Self::with_limits(meta, DiffLimits::default())
    }

    /// Create an empty set with explicit limits.
    #[must_use]
    pub fn with_limits(meta: SnapshotMeta, limits: DiffLimits) -> Self {
        Self {
            meta,
            limits,
            routes: BTreeMap::new(),
            approx_bytes: 0,
            truncated: false,
        }
    }

    /// Snapshot provenance.
    #[must_use]
    pub fn meta(&self) -> &SnapshotMeta {
        &self.meta
    }

    /// Number of distinct (peer, family, NLRI) keys.
    #[must_use]
    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    /// Whether any insert was refused for exceeding a limit. A truncated
    /// set never compares as in-sync.
    #[must_use]
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Add one path. The path's attributes are canonicalized on entry
    /// (see [`NORMALIZATION`]); duplicate semantic paths are kept — they
    /// carry multiplicity, they don't collapse.
    ///
    /// # Errors
    ///
    /// Returns [`LimitExceeded`] (leaving the stored routes unchanged and
    /// marking the set truncated) when any [`DiffLimits`] bound would be
    /// crossed.
    pub fn insert(
        &mut self,
        peer: PeerId,
        family: FamilyId,
        nlri: Nlri,
        mut path: RoutePath,
    ) -> Result<(), LimitExceeded> {
        path.attrs.canonicalize();

        let checks = || -> Result<(), LimitExceeded> {
            let attr_count = path.attrs.attr_count();
            if attr_count > self.limits.max_attrs_per_path {
                return Err(LimitExceeded {
                    limit: "max_attrs_per_path",
                    max: self.limits.max_attrs_per_path,
                    actual: attr_count,
                });
            }
            let record_bytes = nlri.approx_bytes() + path.attrs.approx_bytes();
            if record_bytes > self.limits.max_record_bytes {
                return Err(LimitExceeded {
                    limit: "max_record_bytes",
                    max: self.limits.max_record_bytes,
                    actual: record_bytes,
                });
            }
            if self.approx_bytes + record_bytes > self.limits.max_input_bytes {
                return Err(LimitExceeded {
                    limit: "max_input_bytes",
                    max: self.limits.max_input_bytes,
                    actual: self.approx_bytes + record_bytes,
                });
            }
            Ok(())
        };
        if let Err(e) = checks() {
            self.truncated = true;
            return Err(e);
        }
        let record_bytes = nlri.approx_bytes() + path.attrs.approx_bytes();

        let key = (peer, family, nlri);
        if !self.routes.contains_key(&key) && self.routes.len() >= self.limits.max_routes {
            self.truncated = true;
            return Err(LimitExceeded {
                limit: "max_routes",
                max: self.limits.max_routes,
                actual: self.routes.len() + 1,
            });
        }
        let paths = self.routes.entry(key).or_default();
        if paths.len() >= self.limits.max_paths_per_nlri {
            self.truncated = true;
            return Err(LimitExceeded {
                limit: "max_paths_per_nlri",
                max: self.limits.max_paths_per_nlri,
                actual: paths.len() + 1,
            });
        }
        paths.push(path);
        self.approx_bytes += record_bytes;
        Ok(())
    }
}

/// Overall comparison verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// Both complete same-generation captures, no divergence.
    InSync,
    /// Divergence found.
    Divergent,
    /// Equality cannot be asserted (incomplete / truncated /
    /// mixed-generation input). Any divergence found is still reported.
    Incomparable,
}

/// Divergence class of one (peer, family, NLRI).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffClass {
    /// Present only in the incumbent capture.
    IncumbentOnly,
    /// Present only in the rustbgpd capture.
    RustbgpdOnly,
    /// Present on both sides with different semantic paths.
    AttributeChanged,
    /// Same distinct semantic paths on both sides, different
    /// multiplicities (duplicate paths never collapse silently).
    MultiplicityChanged,
}

/// One side's paths for a diverging NLRI, grouped by identical semantic
/// attributes with their multiplicity and diagnostic path IDs.
#[derive(Clone, Debug, Serialize)]
pub struct PathReport {
    /// How many identical paths carried these attributes.
    pub count: usize,
    /// Source-local path IDs observed (diagnostics only).
    pub path_ids: Vec<u32>,
    /// The canonicalized attributes.
    pub attrs: PathAttrs,
}

/// Before/after value of one differing attribute.
#[derive(Clone, Debug, Serialize)]
pub struct AttrDelta {
    /// Attribute name (a [`PathAttrs`] field).
    pub attribute: &'static str,
    /// Incumbent-side value.
    pub incumbent: serde_json::Value,
    /// rustbgpd-side value.
    pub rustbgpd: serde_json::Value,
}

/// One diverging (peer, family, NLRI).
#[derive(Clone, Debug, Serialize)]
pub struct DiffEntry {
    /// Peer the routes were advertised to.
    pub peer: PeerId,
    /// Address family.
    pub family: FamilyId,
    /// NLRI identity.
    pub nlri: Nlri,
    /// Divergence class.
    pub class: DiffClass,
    /// Incumbent-side paths (empty for [`DiffClass::RustbgpdOnly`]).
    pub incumbent_paths: Vec<PathReport>,
    /// rustbgpd-side paths (empty for [`DiffClass::IncumbentOnly`]).
    pub rustbgpd_paths: Vec<PathReport>,
    /// Field-level before/after deltas, populated when each side carries
    /// exactly one distinct semantic path (the common non-Add-Path case);
    /// otherwise the full path lists above are the delta.
    pub attribute_deltas: Vec<AttrDelta>,
}

/// Per-(peer, family) NLRI counts, in deterministic key order.
#[derive(Clone, Debug, Serialize)]
pub struct PeerFamilySummary {
    /// Peer.
    pub peer: PeerId,
    /// Family.
    pub family: FamilyId,
    /// NLRIs whose path multisets matched exactly.
    pub matched: usize,
    /// NLRIs only in the incumbent capture.
    pub incumbent_only: usize,
    /// NLRIs only in the rustbgpd capture.
    pub rustbgpd_only: usize,
    /// NLRIs with differing semantic paths.
    pub attribute_changed: usize,
    /// NLRIs with matching paths at differing multiplicities.
    pub multiplicity_changed: usize,
}

/// The complete comparison result. Serializes to the versioned JSON
/// schema named by [`SCHEMA_VERSION`]; `entries` and `summaries` are in
/// deterministic (peer, family, NLRI) order.
#[derive(Debug, Serialize)]
pub struct DiffReport {
    /// Result schema version ([`SCHEMA_VERSION`]).
    pub schema: &'static str,
    /// Canonicalization rules this report was produced under.
    pub normalization: NormalizationProfile,
    /// Overall verdict.
    pub verdict: Verdict,
    /// Why the captures are incomparable (empty unless
    /// [`Verdict::Incomparable`]).
    pub incomparable_reasons: Vec<String>,
    /// Incumbent capture provenance.
    pub incumbent: SnapshotMeta,
    /// rustbgpd capture provenance.
    pub rustbgpd: SnapshotMeta,
    /// Per-(peer, family) counts.
    pub summaries: Vec<PeerFamilySummary>,
    /// Every diverging NLRI.
    pub entries: Vec<DiffEntry>,
}

impl DiffReport {
    /// True when divergence entries were found (independent of whether
    /// the captures were fully comparable).
    #[must_use]
    pub fn divergent(&self) -> bool {
        !self.entries.is_empty()
    }
}

/// Compare two captured route sets.
///
/// Pure and read-only. Equality ([`Verdict::InSync`]) is only possible
/// when both sets are complete, untruncated, and from the same capture
/// generation; otherwise the verdict is [`Verdict::Incomparable`] and any
/// divergence found is still listed.
#[must_use]
pub fn diff(incumbent: &RouteSet, rustbgpd: &RouteSet) -> DiffReport {
    let mut incomparable_reasons = Vec::new();
    if incumbent.meta.generation != rustbgpd.meta.generation {
        incomparable_reasons.push(format!(
            "capture generation mismatch: incumbent {} vs rustbgpd {}",
            incumbent.meta.generation, rustbgpd.meta.generation
        ));
    }
    for (label, set) in [("incumbent", incumbent), ("rustbgpd", rustbgpd)] {
        if !set.meta.complete {
            incomparable_reasons.push(format!("{label} capture is incomplete"));
        }
        if set.truncated {
            incomparable_reasons.push(format!("{label} capture was truncated by a resource limit"));
        }
    }

    let keys: BTreeSet<&RouteKey> = incumbent
        .routes
        .keys()
        .chain(rustbgpd.routes.keys())
        .collect();

    let mut entries = Vec::new();
    let mut summaries: BTreeMap<(PeerId, FamilyId), PeerFamilySummary> = BTreeMap::new();
    for key in keys {
        let (peer, family, nlri) = key;
        let incumbent_paths = incumbent.routes.get(key).map(Vec::as_slice).unwrap_or(&[]);
        let rustbgpd_paths = rustbgpd.routes.get(key).map(Vec::as_slice).unwrap_or(&[]);
        let class = classify(incumbent_paths, rustbgpd_paths);

        let summary =
            summaries
                .entry((peer.clone(), *family))
                .or_insert_with(|| PeerFamilySummary {
                    peer: peer.clone(),
                    family: *family,
                    matched: 0,
                    incumbent_only: 0,
                    rustbgpd_only: 0,
                    attribute_changed: 0,
                    multiplicity_changed: 0,
                });
        let Some(class) = class else {
            summary.matched += 1;
            continue;
        };
        match class {
            DiffClass::IncumbentOnly => summary.incumbent_only += 1,
            DiffClass::RustbgpdOnly => summary.rustbgpd_only += 1,
            DiffClass::AttributeChanged => summary.attribute_changed += 1,
            DiffClass::MultiplicityChanged => summary.multiplicity_changed += 1,
        }

        let incumbent_reports = group_paths(incumbent_paths);
        let rustbgpd_reports = group_paths(rustbgpd_paths);
        let attribute_deltas = if class == DiffClass::AttributeChanged
            && incumbent_reports.len() == 1
            && rustbgpd_reports.len() == 1
        {
            attr_deltas(&incumbent_reports[0].attrs, &rustbgpd_reports[0].attrs)
        } else {
            Vec::new()
        };
        entries.push(DiffEntry {
            peer: peer.clone(),
            family: *family,
            nlri: nlri.clone(),
            class,
            incumbent_paths: incumbent_reports,
            rustbgpd_paths: rustbgpd_reports,
            attribute_deltas,
        });
    }

    let verdict = if !incomparable_reasons.is_empty() {
        Verdict::Incomparable
    } else if entries.is_empty() {
        Verdict::InSync
    } else {
        Verdict::Divergent
    };
    DiffReport {
        schema: SCHEMA_VERSION,
        normalization: NORMALIZATION,
        verdict,
        incomparable_reasons,
        incumbent: incumbent.meta.clone(),
        rustbgpd: rustbgpd.meta.clone(),
        summaries: summaries.into_values().collect(),
        entries,
    }
}

/// Classify one NLRI. `None` = matched.
fn classify(incumbent: &[RoutePath], rustbgpd: &[RoutePath]) -> Option<DiffClass> {
    match (incumbent.is_empty(), rustbgpd.is_empty()) {
        (true, true) => return None, // unreachable via diff(); defensive
        (false, true) => return Some(DiffClass::IncumbentOnly),
        (true, false) => return Some(DiffClass::RustbgpdOnly),
        (false, false) => {}
    }
    let incumbent_multiset = multiset(incumbent);
    let rustbgpd_multiset = multiset(rustbgpd);
    if incumbent_multiset == rustbgpd_multiset {
        None
    } else if incumbent_multiset.keys().eq(rustbgpd_multiset.keys()) {
        Some(DiffClass::MultiplicityChanged)
    } else {
        Some(DiffClass::AttributeChanged)
    }
}

fn multiset(paths: &[RoutePath]) -> BTreeMap<&PathAttrs, usize> {
    let mut set = BTreeMap::new();
    for path in paths {
        *set.entry(&path.attrs).or_insert(0) += 1;
    }
    set
}

/// Group one side's paths by identical attributes, deterministically
/// ordered by attribute value; multiplicity and observed path IDs kept.
fn group_paths(paths: &[RoutePath]) -> Vec<PathReport> {
    let mut grouped: BTreeMap<&PathAttrs, PathReport> = BTreeMap::new();
    for path in paths {
        let report = grouped.entry(&path.attrs).or_insert_with(|| PathReport {
            count: 0,
            path_ids: Vec::new(),
            attrs: path.attrs.clone(),
        });
        report.count += 1;
        if let Some(id) = path.path_id {
            report.path_ids.push(id);
        }
    }
    grouped
        .into_values()
        .map(|mut report| {
            report.path_ids.sort_unstable();
            report
        })
        .collect()
}

fn json_value<T: Serialize>(value: &T) -> serde_json::Value {
    serde_json::to_value(value).unwrap_or(serde_json::Value::Null)
}

/// Field-level before/after deltas between two attribute sets.
fn attr_deltas(incumbent: &PathAttrs, rustbgpd: &PathAttrs) -> Vec<AttrDelta> {
    let mut deltas = Vec::new();
    macro_rules! delta {
        ($field:ident) => {
            if incumbent.$field != rustbgpd.$field {
                deltas.push(AttrDelta {
                    attribute: stringify!($field),
                    incumbent: json_value(&incumbent.$field),
                    rustbgpd: json_value(&rustbgpd.$field),
                });
            }
        };
    }
    delta!(origin);
    delta!(as_path);
    delta!(next_hop);
    delta!(med);
    delta!(local_pref);
    delta!(communities);
    delta!(extended_communities);
    delta!(large_communities);
    delta!(unknown);
    deltas
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::Instant;

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

    fn assert_json_shape(value: &serde_json::Value, shape: &serde_json::Value) {
        let object = value.as_object().expect("contract value is an object");
        for (key, expected) in shape["required_json_types"].as_object().unwrap() {
            let field = object
                .get(key)
                .unwrap_or_else(|| panic!("required rbgp-ribdiff/1 field {key:?} is absent"));
            let allowed: Vec<&str> = match expected {
                serde_json::Value::String(value) => vec![value.as_str()],
                serde_json::Value::Array(values) => {
                    values.iter().map(|value| value.as_str().unwrap()).collect()
                }
                _ => panic!("invalid rbgp-ribdiff/1 type floor for {key:?}"),
            };
            assert!(
                allowed.contains(&json_type(field)),
                "rbgp-ribdiff/1 field {key:?} changed JSON type"
            );
        }
        for (key, expected) in shape["optional_json_types"].as_object().unwrap() {
            if let Some(field) = object.get(key) {
                let allowed: Vec<&str> = match expected {
                    serde_json::Value::String(value) => vec![value.as_str()],
                    serde_json::Value::Array(values) => {
                        values.iter().map(|value| value.as_str().unwrap()).collect()
                    }
                    _ => panic!("invalid rbgp-ribdiff/1 type floor for {key:?}"),
                };
                assert!(allowed.contains(&json_type(field)));
            }
        }
    }

    fn assert_ribdiff_inventory_contract(value: &serde_json::Value) {
        let inventory_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/v1-stable-surface.json"
        );
        let inventory: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(inventory_path).unwrap()).unwrap();
        let contract = inventory["cli"]["versioned_json_contracts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|contract| contract["id"] == "rbgp-ribdiff/1")
            .expect("rbgp-ribdiff/1 contract is inventoried");
        assert_json_shape(value, contract);
        for nested in contract["nested_json_contracts"].as_array().unwrap() {
            match nested["path"].as_str().unwrap() {
                "entries[]" => value["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .for_each(|entry| assert_json_shape(entry, nested)),
                "incumbent" => assert_json_shape(&value["incumbent"], nested),
                "normalization" => assert_json_shape(&value["normalization"], nested),
                "rustbgpd" => assert_json_shape(&value["rustbgpd"], nested),
                "summaries[]" => value["summaries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .for_each(|summary| assert_json_shape(summary, nested)),
                path => panic!("unhandled rbgp-ribdiff/1 nested contract path {path}"),
            }
        }
    }

    fn meta(generation: u64) -> SnapshotMeta {
        SnapshotMeta {
            source: "test".to_string(),
            generation,
            complete: true,
        }
    }

    fn peer() -> PeerId {
        PeerId {
            address: "192.0.2.9".parse().unwrap(),
            asn: 65000,
            distinguisher: None,
        }
    }

    fn prefix(s: &str) -> (FamilyId, Nlri) {
        let (addr, len) = s.split_once('/').unwrap();
        let addr: IpAddr = addr.parse().unwrap();
        let family = if addr.is_ipv4() {
            FamilyId::IPV4_UNICAST
        } else {
            FamilyId::IPV6_UNICAST
        };
        (
            family,
            Nlri::Prefix {
                addr,
                len: len.parse().unwrap(),
            },
        )
    }

    fn attrs(next_hop: &str, asns: &[u32], med: Option<u32>, communities: &[u32]) -> PathAttrs {
        PathAttrs {
            origin: Some(0),
            as_path: vec![AsPathSegment {
                kind: AsSegmentKind::Sequence,
                asns: asns.to_vec(),
            }],
            next_hop: Some(next_hop.parse().unwrap()),
            med,
            communities: communities.to_vec(),
            ..PathAttrs::default()
        }
    }

    fn path(attrs: PathAttrs) -> RoutePath {
        RoutePath {
            path_id: None,
            attrs,
        }
    }

    fn build(generation: u64, routes: Vec<(&str, RoutePath)>) -> RouteSet {
        let mut set = RouteSet::new(meta(generation));
        for (pfx, route_path) in routes {
            let (family, nlri) = prefix(pfx);
            set.insert(peer(), family, nlri, route_path).unwrap();
        }
        set
    }

    // --- golden behaviors ---

    #[test]
    fn identical_sets_are_in_sync_across_families() {
        let routes = || {
            vec![
                ("10.0.0.0/24", path(attrs("192.0.2.1", &[65001], None, &[]))),
                (
                    "2001:db8::/32",
                    path(attrs("2001:db8::1", &[65001, 65002], Some(5), &[100])),
                ),
            ]
        };
        let report = diff(&build(1, routes()), &build(1, routes()));
        assert_eq!(report.verdict, Verdict::InSync);
        assert!(!report.divergent());
        assert_eq!(report.summaries.len(), 2);
        assert!(report.summaries.iter().all(|s| s.matched == 1));
    }

    #[test]
    fn reordered_input_and_reordered_lists_produce_identical_reports() {
        let a = |c: &[u32]| ("10.0.0.0/24", path(attrs("192.0.2.1", &[65001], None, c)));
        let b = |c: &[u32]| {
            (
                "10.1.0.0/24",
                path(attrs("192.0.2.2", &[65002], Some(9), c)),
            )
        };

        // Same semantic content: different insertion order, different
        // community wire order.
        let forward = build(1, vec![a(&[1, 2]), b(&[7, 8])]);
        let reversed = build(1, vec![b(&[8, 7]), a(&[2, 1])]);
        let incumbent = build(1, vec![a(&[2, 1])]);

        let report_fwd = serde_json::to_string(&diff(&incumbent, &forward)).unwrap();
        let report_rev = serde_json::to_string(&diff(&incumbent, &reversed)).unwrap();
        assert_eq!(report_fwd, report_rev);
    }

    #[test]
    fn path_ids_are_diagnostic_only() {
        let one = build(
            1,
            vec![
                (
                    "10.0.0.0/24",
                    RoutePath {
                        path_id: Some(1),
                        attrs: attrs("192.0.2.1", &[65001], None, &[]),
                    },
                ),
                (
                    "10.0.0.0/24",
                    RoutePath {
                        path_id: Some(2),
                        attrs: attrs("192.0.2.2", &[65001], None, &[]),
                    },
                ),
            ],
        );
        let other = build(
            1,
            vec![
                (
                    "10.0.0.0/24",
                    RoutePath {
                        path_id: Some(9),
                        attrs: attrs("192.0.2.2", &[65001], None, &[]),
                    },
                ),
                (
                    "10.0.0.0/24",
                    RoutePath {
                        path_id: Some(7),
                        attrs: attrs("192.0.2.1", &[65001], None, &[]),
                    },
                ),
            ],
        );
        let report = diff(&one, &other);
        assert_eq!(report.verdict, Verdict::InSync);
    }

    #[test]
    fn duplicate_paths_change_multiplicity_not_equality() {
        let single = build(
            1,
            vec![("10.0.0.0/24", path(attrs("192.0.2.1", &[65001], None, &[])))],
        );
        let double = build(
            1,
            vec![
                ("10.0.0.0/24", path(attrs("192.0.2.1", &[65001], None, &[]))),
                ("10.0.0.0/24", path(attrs("192.0.2.1", &[65001], None, &[]))),
            ],
        );
        let report = diff(&single, &double);
        assert_eq!(report.verdict, Verdict::Divergent);
        assert_eq!(report.entries.len(), 1);
        assert_eq!(report.entries[0].class, DiffClass::MultiplicityChanged);
        assert_eq!(report.entries[0].incumbent_paths[0].count, 1);
        assert_eq!(report.entries[0].rustbgpd_paths[0].count, 2);
        assert_eq!(report.summaries[0].multiplicity_changed, 1);
    }

    #[test]
    fn one_sided_prefixes_are_classified_per_side() {
        let incumbent = build(
            1,
            vec![("10.0.0.0/24", path(attrs("192.0.2.1", &[65001], None, &[])))],
        );
        let rustbgpd = build(
            1,
            vec![("10.1.0.0/24", path(attrs("192.0.2.1", &[65001], None, &[])))],
        );
        let report = diff(&incumbent, &rustbgpd);
        assert_eq!(report.verdict, Verdict::Divergent);
        let classes: Vec<DiffClass> = report.entries.iter().map(|e| e.class).collect();
        assert_eq!(
            classes,
            vec![DiffClass::IncumbentOnly, DiffClass::RustbgpdOnly]
        );
        assert!(report.entries[0].rustbgpd_paths.is_empty());
        assert!(report.entries[1].incumbent_paths.is_empty());
        assert_eq!(report.summaries[0].incumbent_only, 1);
        assert_eq!(report.summaries[0].rustbgpd_only, 1);
    }

    #[test]
    fn attribute_deltas_report_before_and_after_values() {
        let incumbent = build(
            1,
            vec![(
                "10.0.0.0/24",
                path(attrs("192.0.2.1", &[65001], Some(10), &[100])),
            )],
        );
        let rustbgpd = build(
            1,
            vec![(
                "10.0.0.0/24",
                path(attrs("192.0.2.1", &[65001], Some(20), &[200])),
            )],
        );
        let report = diff(&incumbent, &rustbgpd);
        assert_eq!(report.entries[0].class, DiffClass::AttributeChanged);
        let deltas = &report.entries[0].attribute_deltas;
        assert_eq!(
            deltas.iter().map(|d| d.attribute).collect::<Vec<_>>(),
            vec!["med", "communities"]
        );
        assert_eq!(deltas[0].incumbent, serde_json::json!(10));
        assert_eq!(deltas[0].rustbgpd, serde_json::json!(20));
        assert_eq!(deltas[1].incumbent, serde_json::json!([100]));
        assert_eq!(deltas[1].rustbgpd, serde_json::json!([200]));
    }

    #[test]
    fn every_compared_attribute_produces_a_named_delta() {
        let base = attrs("192.0.2.1", &[65001], Some(10), &[100]);
        type Mutation = Box<dyn Fn(&mut PathAttrs)>;
        let mutations: Vec<(&str, Mutation)> = vec![
            ("origin", Box::new(|a| a.origin = Some(2))),
            ("as_path", Box::new(|a| a.as_path[0].asns.push(65002))),
            (
                "next_hop",
                Box::new(|a| a.next_hop = Some("192.0.2.99".parse().unwrap())),
            ),
            ("med", Box::new(|a| a.med = None)),
            ("local_pref", Box::new(|a| a.local_pref = Some(200))),
            ("communities", Box::new(|a| a.communities.push(300))),
            (
                "extended_communities",
                Box::new(|a| a.extended_communities.push(1)),
            ),
            (
                "large_communities",
                Box::new(|a| a.large_communities.push([1, 2, 3])),
            ),
            (
                "unknown",
                Box::new(|a| {
                    a.unknown.push(UnknownAttr {
                        type_code: 35,
                        flags: 0xC0,
                        value: vec![0, 0, 0xFD, 0xE8],
                    });
                }),
            ),
        ];
        for (name, mutate) in mutations {
            let mut changed = base.clone();
            mutate(&mut changed);
            let deltas = attr_deltas(&base, &changed);
            assert_eq!(
                deltas.iter().map(|d| d.attribute).collect::<Vec<_>>(),
                vec![name]
            );
        }
    }

    #[test]
    fn med_absent_is_distinct_from_zero() {
        let absent = build(
            1,
            vec![("10.0.0.0/24", path(attrs("192.0.2.1", &[65001], None, &[])))],
        );
        let zero = build(
            1,
            vec![(
                "10.0.0.0/24",
                path(attrs("192.0.2.1", &[65001], Some(0), &[])),
            )],
        );
        assert_eq!(diff(&absent, &zero).verdict, Verdict::Divergent);
    }

    #[test]
    fn as_path_segment_kind_and_order_are_significant_but_set_order_is_not() {
        let seg = |kind, asns: &[u32]| PathAttrs {
            as_path: vec![AsPathSegment {
                kind,
                asns: asns.to_vec(),
            }],
            ..PathAttrs::default()
        };
        let build_one = |a: PathAttrs| build(1, vec![("10.0.0.0/24", path(a))]);

        // SEQUENCE order matters.
        let fwd = build_one(seg(AsSegmentKind::Sequence, &[65001, 65002]));
        let rev = build_one(seg(AsSegmentKind::Sequence, &[65002, 65001]));
        assert_eq!(diff(&fwd, &rev).verdict, Verdict::Divergent);

        // Segment kind matters.
        let seq = build_one(seg(AsSegmentKind::Sequence, &[65001]));
        let set = build_one(seg(AsSegmentKind::Set, &[65001]));
        assert_eq!(diff(&seq, &set).verdict, Verdict::Divergent);

        // SET member order is canonicalized.
        let set_a = build_one(seg(AsSegmentKind::Set, &[65002, 65001]));
        let set_b = build_one(seg(AsSegmentKind::Set, &[65001, 65002]));
        assert_eq!(diff(&set_a, &set_b).verdict, Verdict::InSync);
    }

    #[test]
    fn unknown_attributes_are_compared_never_dropped() {
        let with_unknown = |value: Vec<u8>| {
            let mut a = attrs("192.0.2.1", &[65001], None, &[]);
            a.unknown.push(UnknownAttr {
                type_code: 26,
                flags: 0xC0,
                value,
            });
            build(1, vec![("10.0.0.0/24", path(a))])
        };
        let report = diff(
            &with_unknown(vec![0, 0, 0, 1]),
            &with_unknown(vec![0, 0, 0, 2]),
        );
        assert_eq!(report.verdict, Verdict::Divergent);
        assert_eq!(report.entries[0].attribute_deltas[0].attribute, "unknown");

        let report = diff(
            &with_unknown(vec![0, 0, 0, 1]),
            &with_unknown(vec![0, 0, 0, 1]),
        );
        assert_eq!(report.verdict, Verdict::InSync);
    }

    #[test]
    fn typed_nlri_identity_distinguishes_rd_and_labels() {
        let vpn = |rd_low: u8| Nlri::VpnPrefix {
            rd: Rd([0, 0, 0xFD, 0xE8, 0, 0, 0, rd_low]),
            labels: vec![100],
            addr: "10.0.0.0".parse().unwrap(),
            len: 24,
        };
        let family = FamilyId { afi: 1, safi: 128 };
        let mut incumbent = RouteSet::new(meta(1));
        incumbent
            .insert(peer(), family, vpn(1), path(PathAttrs::default()))
            .unwrap();
        let mut rustbgpd = RouteSet::new(meta(1));
        rustbgpd
            .insert(peer(), family, vpn(2), path(PathAttrs::default()))
            .unwrap();
        let report = diff(&incumbent, &rustbgpd);
        // Different RDs are different NLRI identities, not attribute drift.
        assert_eq!(report.entries.len(), 2);
        assert_eq!(Rd([0, 0, 0xFD, 0xE8, 0, 0, 0, 1]).to_string(), "65000:1");
        assert_eq!(Rd([0, 1, 192, 0, 2, 1, 0, 5]).to_string(), "192.0.2.1:5");
    }

    // --- invariants: never equality from unsound input ---

    #[test]
    fn mixed_generation_or_incomplete_input_is_incomparable() {
        let routes = || vec![("10.0.0.0/24", path(attrs("192.0.2.1", &[65001], None, &[])))];

        let report = diff(&build(1, routes()), &build(2, routes()));
        assert_eq!(report.verdict, Verdict::Incomparable);
        assert!(report.incomparable_reasons[0].contains("generation"));

        let mut incomplete = build(1, routes());
        incomplete.meta.complete = false;
        let report = diff(&incomplete, &build(1, routes()));
        assert_eq!(report.verdict, Verdict::Incomparable);
        assert!(report.incomparable_reasons[0].contains("incomplete"));
    }

    #[test]
    fn truncated_input_is_incomparable_even_when_contents_match() {
        let limits = DiffLimits {
            max_routes: 1,
            ..DiffLimits::default()
        };
        let insert_two = || {
            let mut set = RouteSet::with_limits(meta(1), limits);
            let (family, nlri) = prefix("10.0.0.0/24");
            set.insert(peer(), family, nlri, path(PathAttrs::default()))
                .unwrap();
            let (family, nlri) = prefix("10.1.0.0/24");
            let err = set
                .insert(peer(), family, nlri, path(PathAttrs::default()))
                .unwrap_err();
            assert_eq!(err.limit, "max_routes");
            set
        };
        let (truncated, other) = (insert_two(), insert_two());
        assert!(truncated.is_truncated());
        let report = diff(&truncated, &other);
        assert_eq!(report.verdict, Verdict::Incomparable);
        assert!(
            report
                .incomparable_reasons
                .iter()
                .any(|r| r.contains("truncated"))
        );
    }

    #[test]
    fn every_limit_is_enforced() {
        let (family, nlri) = prefix("10.0.0.0/24");

        // max_paths_per_nlri
        let mut set = RouteSet::with_limits(
            meta(1),
            DiffLimits {
                max_paths_per_nlri: 1,
                ..DiffLimits::default()
            },
        );
        set.insert(peer(), family, nlri.clone(), path(PathAttrs::default()))
            .unwrap();
        let err = set
            .insert(peer(), family, nlri.clone(), path(PathAttrs::default()))
            .unwrap_err();
        assert_eq!(err.limit, "max_paths_per_nlri");

        // max_attrs_per_path
        let mut set = RouteSet::with_limits(
            meta(1),
            DiffLimits {
                max_attrs_per_path: 2,
                ..DiffLimits::default()
            },
        );
        let mut many = PathAttrs::default();
        for code in 20..25 {
            many.unknown.push(UnknownAttr {
                type_code: code,
                flags: 0,
                value: vec![],
            });
        }
        let err = set
            .insert(peer(), family, nlri.clone(), path(many))
            .unwrap_err();
        assert_eq!(err.limit, "max_attrs_per_path");

        // max_record_bytes
        let mut set = RouteSet::with_limits(
            meta(1),
            DiffLimits {
                max_record_bytes: 64,
                ..DiffLimits::default()
            },
        );
        let mut big = PathAttrs::default();
        big.unknown.push(UnknownAttr {
            type_code: 20,
            flags: 0,
            value: vec![0; 256],
        });
        let err = set
            .insert(peer(), family, nlri.clone(), path(big))
            .unwrap_err();
        assert_eq!(err.limit, "max_record_bytes");

        // max_input_bytes
        let mut set = RouteSet::with_limits(
            meta(1),
            DiffLimits {
                max_input_bytes: 100,
                ..DiffLimits::default()
            },
        );
        let _ = set.insert(peer(), family, nlri.clone(), path(PathAttrs::default()));
        let (family6, nlri6) = prefix("2001:db8::/32");
        let err = set
            .insert(peer(), family6, nlri6, path(PathAttrs::default()))
            .unwrap_err();
        assert_eq!(err.limit, "max_input_bytes");

        assert!(set.is_truncated());
    }

    // --- versioned JSON schema golden ---

    #[test]
    fn json_schema_golden() {
        let incumbent = build(
            1,
            vec![(
                "10.0.0.0/24",
                path(attrs("192.0.2.1", &[65001], Some(10), &[])),
            )],
        );
        let rustbgpd = build(
            1,
            vec![(
                "10.0.0.0/24",
                path(attrs("192.0.2.1", &[65001], Some(20), &[])),
            )],
        );
        let report = serde_json::to_value(diff(&incumbent, &rustbgpd)).unwrap();

        assert_ribdiff_inventory_contract(&report);

        assert_eq!(report["schema"], "rbgp-ribdiff/1");
        assert_eq!(report["normalization"]["version"], "v1");
        assert!(
            report["normalization"]["rules"]
                .as_array()
                .is_some_and(|r| !r.is_empty())
        );
        assert!(
            report["normalization"]["ignored"][0]
                .as_str()
                .unwrap()
                .starts_with("path_id")
        );
        assert_eq!(report["verdict"], "divergent");
        assert_eq!(
            report["summaries"][0],
            serde_json::json!({
                "peer": {"address": "192.0.2.9", "asn": 65000, "distinguisher": null},
                "family": {"afi": 1, "safi": 1},
                "matched": 0,
                "incumbent_only": 0,
                "rustbgpd_only": 0,
                "attribute_changed": 1,
                "multiplicity_changed": 0,
            })
        );
        assert_eq!(
            report["entries"][0],
            serde_json::json!({
                "peer": {"address": "192.0.2.9", "asn": 65000, "distinguisher": null},
                "family": {"afi": 1, "safi": 1},
                "nlri": {"type": "prefix", "addr": "10.0.0.0", "len": 24},
                "class": "attribute_changed",
                "incumbent_paths": [{
                    "count": 1,
                    "path_ids": [],
                    "attrs": {
                        "origin": 0,
                        "as_path": [{"kind": "sequence", "asns": [65001]}],
                        "next_hop": "192.0.2.1",
                        "med": 10,
                        "local_pref": null,
                        "communities": [],
                        "extended_communities": [],
                        "large_communities": [],
                        "unknown": [],
                    },
                }],
                "rustbgpd_paths": [{
                    "count": 1,
                    "path_ids": [],
                    "attrs": {
                        "origin": 0,
                        "as_path": [{"kind": "sequence", "asns": [65001]}],
                        "next_hop": "192.0.2.1",
                        "med": 20,
                        "local_pref": null,
                        "communities": [],
                        "extended_communities": [],
                        "large_communities": [],
                        "unknown": [],
                    },
                }],
                "attribute_deltas": [{"attribute": "med", "incumbent": 10, "rustbgpd": 20}],
            })
        );
    }

    // --- properties: symmetry + determinism over generated input ---

    fn lcg(state: &mut u64) -> u64 {
        *state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *state >> 33
    }

    fn random_entry(state: &mut u64) -> (String, RoutePath) {
        let n = lcg(state) as u32;
        let pfx = format!("{}/24", Ipv4Addr::from((n & 0x00FF_FFFF) << 8));
        let mut a = attrs(
            &format!("192.0.2.{}", lcg(state) % 250 + 1),
            &[65000 + (lcg(state) % 20) as u32],
            if lcg(state).is_multiple_of(2) {
                Some((lcg(state) % 100) as u32)
            } else {
                None
            },
            &[(lcg(state) % 500) as u32, (lcg(state) % 500) as u32],
        );
        if lcg(state).is_multiple_of(4) {
            a.unknown.push(UnknownAttr {
                type_code: 20 + (lcg(state) % 10) as u8,
                flags: 0xC0,
                value: vec![(lcg(state) % 256) as u8],
            });
        }
        (
            pfx,
            RoutePath {
                path_id: Some((lcg(state) % 8) as u32),
                attrs: a,
            },
        )
    }

    fn random_sides(seed: u64) -> (RouteSet, RouteSet) {
        let mut state = seed;
        let mut left = Vec::new();
        let mut right = Vec::new();
        for _ in 0..400 {
            let (pfx, route_path) = random_entry(&mut state);
            match lcg(&mut state) % 10 {
                // shared identical (sometimes duplicated on one side)
                0..=5 => {
                    left.push((pfx.clone(), route_path.clone()));
                    if lcg(&mut state).is_multiple_of(7) {
                        right.push((pfx.clone(), route_path.clone()));
                    }
                    right.push((pfx, route_path));
                }
                // shared with drift
                6..=7 => {
                    left.push((pfx.clone(), route_path.clone()));
                    let mut drifted = route_path;
                    drifted.attrs.med = Some(9999);
                    right.push((pfx, drifted));
                }
                // one-sided
                8 => left.push((pfx, route_path)),
                _ => right.push((pfx, route_path)),
            }
        }
        let build_side = |entries: &[(String, RoutePath)]| {
            let mut set = RouteSet::new(meta(1));
            for (pfx, route_path) in entries {
                let (family, nlri) = prefix(pfx);
                set.insert(peer(), family, nlri, route_path.clone())
                    .unwrap();
            }
            set
        };
        (build_side(&left), build_side(&right))
    }

    #[test]
    fn property_diff_is_symmetric() {
        for seed in 1..=5_u64 {
            let (a, b) = random_sides(seed);
            let ab = diff(&a, &b);
            let ba = diff(&b, &a);
            assert_eq!(ab.verdict, ba.verdict, "seed {seed}");
            assert_eq!(ab.entries.len(), ba.entries.len(), "seed {seed}");
            for (fwd, rev) in ab.entries.iter().zip(&ba.entries) {
                assert_eq!(fwd.nlri, rev.nlri, "seed {seed}");
                let mirrored = match rev.class {
                    DiffClass::IncumbentOnly => DiffClass::RustbgpdOnly,
                    DiffClass::RustbgpdOnly => DiffClass::IncumbentOnly,
                    other => other,
                };
                assert_eq!(fwd.class, mirrored, "seed {seed}");
            }
            for (fwd, rev) in ab.summaries.iter().zip(&ba.summaries) {
                assert_eq!(fwd.matched, rev.matched, "seed {seed}");
                assert_eq!(fwd.incumbent_only, rev.rustbgpd_only, "seed {seed}");
                assert_eq!(fwd.rustbgpd_only, rev.incumbent_only, "seed {seed}");
                assert_eq!(fwd.attribute_changed, rev.attribute_changed, "seed {seed}");
                assert_eq!(
                    fwd.multiplicity_changed, rev.multiplicity_changed,
                    "seed {seed}"
                );
            }
        }
    }

    #[test]
    fn property_diff_is_deterministic_under_insertion_order() {
        for seed in 1..=5_u64 {
            let (a, b) = random_sides(seed);
            let baseline = serde_json::to_string(&diff(&a, &b)).unwrap();
            // Rebuild both sides from reversed insertion order.
            let rebuild = |set: &RouteSet| {
                let mut rebuilt = RouteSet::new(set.meta.clone());
                let mut flat: Vec<_> = set
                    .routes
                    .iter()
                    .flat_map(|(key, paths)| paths.iter().map(move |p| (key.clone(), p.clone())))
                    .collect();
                flat.reverse();
                for ((peer_id, family, nlri), route_path) in flat {
                    rebuilt.insert(peer_id, family, nlri, route_path).unwrap();
                }
                rebuilt
            };
            let again = serde_json::to_string(&diff(&rebuild(&a), &rebuild(&b))).unwrap();
            assert_eq!(baseline, again, "seed {seed}");
        }
    }

    // --- scale receipt ---

    fn scale_sides(routes: usize) -> (RouteSet, RouteSet) {
        let mut incumbent = RouteSet::new(meta(1));
        let mut rustbgpd = RouteSet::new(meta(1));
        for i in 0..routes {
            let nlri = Nlri::Prefix {
                addr: IpAddr::V4(Ipv4Addr::from(u32::try_from(i).unwrap() << 8)),
                len: 24,
            };
            let base = attrs(
                "192.0.2.1",
                &[65000, 64500 + (i % 50) as u32],
                Some((i % 3) as u32),
                &[(65000 << 16) | (i % 100) as u32],
            );
            incumbent
                .insert(
                    peer(),
                    FamilyId::IPV4_UNICAST,
                    nlri.clone(),
                    path(base.clone()),
                )
                .unwrap();
            if i % 997 == 0 {
                continue; // missing from rustbgpd
            }
            let mut ours = base;
            if i % 1000 == 0 {
                ours.med = Some(9999); // attribute drift
            }
            rustbgpd
                .insert(peer(), FamilyId::IPV4_UNICAST, nlri, path(ours))
                .unwrap();
        }
        (incumbent, rustbgpd)
    }

    #[test]
    fn scale_receipt_100k_routes() {
        let routes = 100_000;
        let (incumbent, rustbgpd) = scale_sides(routes);
        let start = Instant::now();
        let report = diff(&incumbent, &rustbgpd);
        let elapsed = start.elapsed();
        assert_eq!(report.verdict, Verdict::Divergent);
        let summary = &report.summaries[0];
        // i % 997 == 0 → incumbent-only (101 of 100k); i % 1000 == 0 minus
        // the 997-multiples overlap (i = 0) → attribute drift.
        assert_eq!(summary.incumbent_only, 101);
        assert_eq!(summary.attribute_changed, 99);
        assert_eq!(summary.rustbgpd_only, 0);
        assert_eq!(
            summary.matched,
            routes - summary.incumbent_only - summary.attribute_changed
        );
        println!("scale receipt: {routes} routes/side diffed in {elapsed:?}");
    }

    /// Route-server-sized receipt; run with
    /// `cargo test -p rustbgpctl --release -- --ignored scale_receipt_1m`.
    #[test]
    #[ignore = "route-server-sized receipt; run explicitly in release"]
    fn scale_receipt_1m_routes() {
        let routes = 1_000_000;
        let build_start = Instant::now();
        let (incumbent, rustbgpd) = scale_sides(routes);
        let build_elapsed = build_start.elapsed();
        let start = Instant::now();
        let report = diff(&incumbent, &rustbgpd);
        let elapsed = start.elapsed();
        assert_eq!(report.verdict, Verdict::Divergent);
        println!(
            "scale receipt: {routes} routes/side, build {build_elapsed:?}, diff {elapsed:?}, {} entries",
            report.entries.len()
        );
    }
}
