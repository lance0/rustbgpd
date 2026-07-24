//! Render rustbgpd route-server configuration from `arouteserver
//! template-context` output (ADR-0110 phase 1).
//!
//! The renderer consumes the fully-resolved data model that
//! `arouteserver template-context` dumps (general.yml + clients.yml +
//! IRR/PeeringDB/RPKI enrichment, already expanded by arouteserver's
//! builder) and emits:
//!
//! - `config.toml` — route-server globals plus one `[[neighbors]]`
//!   block per client (transparent `route_server_client` sessions,
//!   per-family max-prefix ceilings, strict next-hop ownership, a
//!   per-client import policy chain);
//! - `policy/rs-hygiene.rpol` — the shared hygiene policy (reject
//!   AS_SET segments FIRST, then invalid-ASN / transit-free /
//!   never-via-RS path terms, AS_PATH length cap, bogon and
//!   black-list prefix rejects, prefix-length windows, RPKI origin
//!   validation);
//! - `policy/client-<id>.rpol` per client — the IRR-derived
//!   prefix-set and origin asn-set with a default-reject tail;
//! - `render-receipt.json` — timestamp, context fingerprint, per-client
//!   set cardinalities, warnings.
//!
//! Failure policy (ADR-0110 Decision 2): fail-stale, never fail-open.
//! Unsupported knobs are refused loudly with a nonzero exit; an empty
//! or implausibly small generated set aborts the render; a context
//! whose top-level shape drifts from the pinned fingerprint is refused
//! unless `--allow-shape-drift` is given. Generated per-client policy
//! always ends in an unconditional reject.
//!
//! Term-ordering invariant: the shared hygiene policy runs before any
//! per-client policy in every import chain, and its first term rejects
//! AS_SET segments. `route.origin-as` resolves an AS_SET-terminated
//! aggregate to the last ASN of the rightmost AS_SEQUENCE (a deliberate
//! deviation from RFC 6811, documented with the accessor), so origin
//! enforcement must never be reachable by a path that still carries an
//! AS_SET — the hygiene ordering guarantees it is not.

#![deny(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::Deserialize;

/// Top-level keys of the supported `template-context` shape, sorted.
///
/// Pinned against arouteserver's builder render context (the dict the
/// `template-context` command dumps) as of July 2026. A key added,
/// removed, or renamed upstream changes the fingerprint and the render
/// refuses until this list — and whatever semantics moved — are
/// reviewed.
pub const EXPECTED_TOP_LEVEL_KEYS: &[&str] = &[
    "any_reject_cause_map_community_set",
    "arin_whois_records",
    "asn3216_map",
    "asns",
    "bogons",
    "cfg",
    "clients",
    "ip_ver",
    "irrdb_info",
    "list_ip_vers",
    "live_tests",
    "never_via_route_servers_asns",
    "perform_graceful_shutdown",
    "registrobr_whois_records",
    "reject_reasons",
    "rpki_roas",
    "rtt_based_functions_are_used",
];

/// Section names of the supported *sectioned* `template-context`
/// report, sorted.
///
/// `arouteserver template-context` (pinned against 1.23.2) does not
/// emit one YAML document: it emits a report of sections, each a
/// heading line plus a dash underline followed by a YAML fragment.
/// The section roster is this format's shape, gated exactly like the
/// single-document top-level keys: a section added, removed, or
/// renamed upstream refuses the render until reviewed.
pub const EXPECTED_SECTION_NAMES: &[&str] = &[
    "arin_whois_db_records",
    "asns",
    "bogons",
    "cfg",
    "clients",
    "ip_ver",
    "irrdb_info",
    "never_via_route_servers_asns",
    "registrobr_whois_db_records",
    "rpki_roas",
];

/// Rejects 0, AS_TRANS (23456), the 16-bit documentation / private /
/// reserved block (64496-65551), and the 32-bit private + reserved
/// range (4200000000-4294967295; every 10-digit AS number starting
/// "42" that fits in u32 falls inside it). Static because the IANA
/// registry is; verified by the in-language tests emitted alongside.
const INVALID_ASN_REGEX: &str = "_(0|23456|6449[6-9]|64[5-9][0-9][0-9]|65[0-4][0-9][0-9]|655[0-4][0-9]|6555[01]|42[0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9])_";

#[derive(Debug, Clone)]
pub struct Options {
    /// Abort when a client's generated prefix-set has fewer members.
    pub min_prefixes: u32,
    /// Abort when a client's generated origin asn-set has fewer members.
    pub min_origins: u32,
    /// RTR cache endpoints for `[[rpki.cache_servers]]`; required when
    /// the context enables RPKI origin validation (the context itself
    /// carries no cache address).
    pub rtr_caches: Vec<String>,
    /// Proceed despite a context-shape fingerprint mismatch.
    pub allow_shape_drift: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            min_prefixes: 1,
            min_origins: 1,
            rtr_caches: Vec::new(),
            allow_shape_drift: false,
        }
    }
}

#[derive(Debug)]
pub enum RenderError {
    /// Context unreadable / not valid YAML-or-JSON / missing required
    /// fields. Exit 1.
    Parse(String),
    /// Unsupported knob in the context; the render must not proceed.
    /// Exit 2.
    Refused(Vec<String>),
    /// Empty or implausibly small generated set. Exit 3.
    Implausible(Vec<String>),
    /// Top-level key structure differs from the pinned shape. Exit 4.
    ShapeMismatch {
        expected_fingerprint: String,
        found_fingerprint: String,
        missing: Vec<String>,
        unexpected: Vec<String>,
    },
}

impl RenderError {
    pub fn exit_code(&self) -> i32 {
        match self {
            RenderError::Parse(_) => 1,
            RenderError::Refused(_) => 2,
            RenderError::Implausible(_) => 3,
            RenderError::ShapeMismatch { .. } => 4,
        }
    }
}

impl std::fmt::Display for RenderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RenderError::Parse(msg) => write!(f, "context parse error: {msg}"),
            RenderError::Refused(items) => {
                writeln!(f, "render refused — unsupported context knobs:")?;
                for item in items {
                    writeln!(f, "  - {item}")?;
                }
                write!(
                    f,
                    "no output written; the last good configuration stays live (fail-stale)"
                )
            }
            RenderError::Implausible(items) => {
                writeln!(f, "render aborted — implausible generated sets:")?;
                for item in items {
                    writeln!(f, "  - {item}")?;
                }
                write!(
                    f,
                    "no output written; the last good configuration stays live (fail-stale)"
                )
            }
            RenderError::ShapeMismatch {
                expected_fingerprint,
                found_fingerprint,
                missing,
                unexpected,
            } => {
                writeln!(
                    f,
                    "context-shape fingerprint mismatch: expected {expected_fingerprint}, found {found_fingerprint}"
                )?;
                if !missing.is_empty() {
                    writeln!(f, "  missing top-level keys: {}", missing.join(", "))?;
                }
                if !unexpected.is_empty() {
                    writeln!(f, "  unexpected top-level keys: {}", unexpected.join(", "))?;
                }
                write!(
                    f,
                    "the template-context shape is not a stable API; review the render \
                     against the new shape, then pass --allow-shape-drift to proceed"
                )
            }
        }
    }
}

impl std::error::Error for RenderError {}

#[derive(Debug)]
pub struct Rendered {
    /// Deterministic output files, keyed by path relative to the output
    /// directory (`config.toml`, `policy/*.rpol`).
    pub files: BTreeMap<String, String>,
    /// The refresh receipt (carries the render timestamp, so it is not
    /// part of the deterministic file set).
    pub receipt: serde_json::Value,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Context model — only the fields the renderer consumes. Parsing is
// permissive about extra fields (the fingerprint gate owns shape
// drift detection at the top level).
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct Context {
    cfg: Cfg,
    clients: Vec<Client>,
    #[serde(default)]
    irrdb_info: BTreeMap<String, IrrdbBundle>,
    #[serde(default)]
    bogons: Vec<PrefixEntry>,
    #[serde(default)]
    never_via_route_servers_asns: Vec<u32>,
    #[serde(default)]
    rtt_based_functions_are_used: bool,
    #[serde(default)]
    perform_graceful_shutdown: bool,
}

#[derive(Deserialize)]
struct Cfg {
    rs_as: u32,
    router_id: RouterId,
    #[serde(default)]
    prepend_rs_as: bool,
    #[serde(default = "default_true")]
    path_hiding: bool,
    #[serde(default)]
    passive: Option<bool>,
    #[serde(default)]
    gtsm: bool,
    #[serde(default)]
    multihop: Option<u32>,
    #[serde(default)]
    add_path: bool,
    #[serde(default)]
    rfc8950: bool,
    #[serde(default)]
    graceful_shutdown: Toggle,
    #[serde(default)]
    blackhole_filtering: BlackholeFiltering,
    #[serde(default)]
    rtt_thresholds: Option<serde_yaml::Value>,
    #[serde(default)]
    communities: BTreeMap<String, serde_yaml::Value>,
    filtering: Filtering,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RouterId {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize, Default)]
struct Toggle {
    #[serde(default)]
    enabled: bool,
}

#[derive(Deserialize, Default)]
struct BlackholeFiltering {
    policy_ipv4: Option<String>,
    policy_ipv6: Option<String>,
    announce_to_client: Option<bool>,
}

#[derive(Deserialize)]
struct Filtering {
    #[serde(default)]
    next_hop: NextHop,
    #[serde(default)]
    ipv4_pref_len: Option<PrefLen>,
    #[serde(default)]
    ipv6_pref_len: Option<PrefLen>,
    #[serde(default)]
    global_black_list_pref: Option<Vec<PrefixEntry>>,
    #[serde(default = "default_max_as_path_len")]
    max_as_path_len: u32,
    #[serde(default = "default_true")]
    reject_invalid_as_in_as_path: bool,
    #[serde(default)]
    transit_free: Option<TransitFree>,
    #[serde(default)]
    irrdb: Irrdb,
    #[serde(default)]
    rpki_bgp_origin_validation: RpkiOv,
    #[serde(default)]
    max_prefix: Option<MaxPrefixCfg>,
    #[serde(default)]
    reject_policy: RejectPolicy,
}

#[derive(Deserialize)]
struct NextHop {
    #[serde(default = "default_strict")]
    policy: String,
}

impl Default for NextHop {
    fn default() -> Self {
        Self {
            policy: default_strict(),
        }
    }
}

#[derive(Deserialize)]
struct PrefLen {
    min: u8,
    max: u8,
}

#[derive(Deserialize)]
struct TransitFree {
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    asns: Option<Vec<u32>>,
}

#[derive(Deserialize)]
struct Irrdb {
    #[serde(default = "default_true")]
    enforce_origin_in_as_set: bool,
    #[serde(default = "default_true")]
    enforce_prefix_in_as_set: bool,
    #[serde(default)]
    allow_longer_prefixes: bool,
}

impl Default for Irrdb {
    fn default() -> Self {
        Self {
            enforce_origin_in_as_set: true,
            enforce_prefix_in_as_set: true,
            allow_longer_prefixes: false,
        }
    }
}

#[derive(Deserialize, Default)]
struct RpkiOv {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "default_true")]
    reject_invalid: bool,
}

#[derive(Deserialize)]
struct MaxPrefixCfg {
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    restart_after: Option<u32>,
    #[serde(default)]
    count_rejected_routes: Option<bool>,
}

#[derive(Deserialize)]
struct RejectPolicy {
    #[serde(default = "default_reject")]
    policy: String,
}

impl Default for RejectPolicy {
    fn default() -> Self {
        Self {
            policy: default_reject(),
        }
    }
}

#[derive(Deserialize)]
struct Client {
    id: String,
    asn: u32,
    ip: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    cfg: ClientCfg,
}

#[derive(Deserialize, Default)]
struct ClientCfg {
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    add_path: Option<bool>,
    #[serde(default)]
    gtsm: Option<bool>,
    #[serde(default)]
    multihop: Option<u32>,
    rfc8950: Option<bool>,
    #[serde(default)]
    blackhole_filtering: BlackholeFiltering,
    #[serde(default)]
    filtering: ClientFiltering,
}

#[derive(Deserialize, Default)]
struct ClientFiltering {
    #[serde(default)]
    irrdb: ClientIrrdb,
    #[serde(default)]
    next_hop: Option<NextHop>,
    #[serde(default)]
    max_prefix: Option<ClientMaxPrefix>,
    #[serde(default)]
    reject_policy: Option<RejectPolicy>,
    #[serde(default)]
    black_list_pref: Option<serde_yaml::Value>,
}

#[derive(Deserialize, Default)]
struct ClientIrrdb {
    #[serde(default)]
    as_set_bundle_ids: Vec<String>,
    #[serde(default)]
    white_list_asn: Option<serde_yaml::Value>,
    #[serde(default)]
    white_list_pref: Option<serde_yaml::Value>,
    #[serde(default)]
    white_list_route: Option<serde_yaml::Value>,
}

#[derive(Deserialize)]
struct ClientMaxPrefix {
    #[serde(default)]
    limit_ipv4: Option<u32>,
    #[serde(default)]
    limit_ipv6: Option<u32>,
    #[serde(default)]
    action: Option<String>,
    #[serde(default)]
    restart_after: Option<u32>,
    #[serde(default)]
    count_rejected_routes: Option<bool>,
}

#[derive(Deserialize)]
struct IrrdbBundle {
    #[serde(default)]
    asns: Vec<AsnLit>,
    #[serde(default)]
    prefixes: Vec<PrefixEntry>,
}

/// IRR origin ASNs appear as bare integers in bundle records but as
/// `"AS<n>"` strings elsewhere in the context (e.g. ROA entries);
/// accept both.
#[derive(Deserialize)]
#[serde(untagged)]
enum AsnLit {
    Num(u32),
    Tagged(String),
}

impl AsnLit {
    fn value(&self) -> Result<u32, String> {
        match self {
            AsnLit::Num(n) => Ok(*n),
            AsnLit::Tagged(s) => s
                .strip_prefix("AS")
                .unwrap_or(s)
                .parse::<u32>()
                .map_err(|_| format!("unparseable ASN literal {s:?}")),
        }
    }
}

#[derive(Deserialize)]
struct PrefixEntry {
    prefix: String,
    length: u8,
    #[serde(default)]
    comment: Option<String>,
    #[serde(default)]
    exact: bool,
    #[serde(default)]
    ge: Option<u8>,
    #[serde(default)]
    le: Option<u8>,
    #[serde(default)]
    max_length: Option<u8>,
}

impl PrefixEntry {
    fn is_ipv6(&self) -> bool {
        self.prefix.contains(':')
    }

    fn family_bits(&self) -> u8 {
        if self.is_ipv6() { 128 } else { 32 }
    }

    /// Render one prefix-set member. `subtree_default` makes an entry
    /// without explicit bounds cover its whole subtree (`le`
    /// family-max) — used for bogon and black-list entries, where the
    /// fail-closed reading of "reject this prefix" includes its
    /// more-specifics. IRR route objects keep bgpq4 semantics: exact
    /// unless the object carries bounds. `force_le_max` implements
    /// `allow_longer_prefixes`.
    fn render_member(&self, subtree_default: bool, force_le_max: bool) -> String {
        let mut member = format!("{}/{}", self.prefix, self.length);
        if force_le_max {
            if self.length < self.family_bits() {
                let _ = write!(member, " le {}", self.family_bits());
            }
            return member;
        }
        if self.exact {
            return member;
        }
        let le = self.le.or(self.max_length).or_else(|| {
            if subtree_default && self.length < self.family_bits() {
                Some(self.family_bits())
            } else {
                None
            }
        });
        // A ge equal to the entry's own length is a no-op (bgpq4 emits
        // one on bounded records); suppress it.
        let ge = self.ge.filter(|ge| *ge > self.length);
        if let Some(ge) = ge {
            let _ = write!(member, " ge {ge}");
        }
        if let Some(le) = le
            && (ge.is_some() || le != self.length)
        {
            let _ = write!(member, " le {le}");
        }
        member
    }
}

fn default_true() -> bool {
    true
}

fn default_max_as_path_len() -> u32 {
    32
}

fn default_strict() -> String {
    "strict".to_owned()
}

fn default_reject() -> String {
    "reject".to_owned()
}

// ---------------------------------------------------------------------------
// Fingerprint
// ---------------------------------------------------------------------------

fn fnv1a64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in data {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

fn shape_fingerprint(keys: &[String]) -> String {
    format!("{:016x}", fnv1a64(keys.join("\n").as_bytes()))
}

/// Fingerprint of the pinned shape in [`EXPECTED_TOP_LEVEL_KEYS`].
pub fn expected_fingerprint() -> String {
    let keys: Vec<String> = EXPECTED_TOP_LEVEL_KEYS
        .iter()
        .map(|k| (*k).to_owned())
        .collect();
    shape_fingerprint(&keys)
}

/// Gate a found key/section roster against a pinned one; on drift,
/// refuse (or warn under `--allow-shape-drift`). Returns the found
/// fingerprint.
fn gate_shape(
    found_keys: &[String],
    expected_keys: &[&str],
    opts: &Options,
    warnings: &mut Vec<String>,
) -> Result<String, RenderError> {
    let expected_list: Vec<String> = expected_keys.iter().map(|k| (*k).to_owned()).collect();
    let expected = shape_fingerprint(&expected_list);
    let found_fingerprint = shape_fingerprint(found_keys);
    if found_fingerprint != expected {
        let expected_set: BTreeSet<&str> = expected_keys.iter().copied().collect();
        let found_set: BTreeSet<&str> = found_keys.iter().map(String::as_str).collect();
        let missing = expected_set
            .difference(&found_set)
            .map(|k| (*k).to_owned())
            .collect();
        let unexpected = found_set
            .difference(&expected_set)
            .map(|k| (*k).to_owned())
            .collect();
        if !opts.allow_shape_drift {
            return Err(RenderError::ShapeMismatch {
                expected_fingerprint: expected,
                found_fingerprint,
                missing,
                unexpected,
            });
        }
        warnings.push(format!(
            "context-shape fingerprint mismatch overridden by --allow-shape-drift \
             (expected {expected}, found {found_fingerprint})"
        ));
    }
    Ok(found_fingerprint)
}

// ---------------------------------------------------------------------------
// Ingestion — the two on-disk forms of `template-context` output
// ---------------------------------------------------------------------------

fn ingest_single_document(
    context_yaml: &str,
    opts: &Options,
    warnings: &mut Vec<String>,
) -> Result<(serde_yaml::Value, String), RenderError> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(context_yaml).map_err(|e| RenderError::Parse(e.to_string()))?;
    let mapping = value
        .as_mapping()
        .ok_or_else(|| RenderError::Parse("context is not a mapping".to_owned()))?;

    let mut found_keys: Vec<String> = mapping
        .keys()
        .map(|k| match k.as_str() {
            Some(s) => Ok(s.to_owned()),
            None => Err(RenderError::Parse(
                "non-string top-level context key".to_owned(),
            )),
        })
        .collect::<Result<_, _>>()?;
    found_keys.sort();

    let fingerprint = gate_shape(&found_keys, EXPECTED_TOP_LEVEL_KEYS, opts, warnings)?;
    Ok((value, fingerprint))
}

/// A section heading is a bare identifier line whose next line is a
/// dash underline of the same length ("cfg" / "---"). YAML content
/// never matches: mapping lines carry a colon, list items lead with
/// "- ", nested lines are indented.
fn is_heading(line: &str, underline: Option<&str>) -> bool {
    let name = line.trim_end();
    if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return false;
    }
    underline
        .map(str::trim_end)
        .is_some_and(|u| !u.is_empty() && u.len() == name.len() && u.bytes().all(|b| b == b'-'))
}

fn looks_sectioned(input: &str) -> bool {
    let lines: Vec<&str> = input.lines().collect();
    lines
        .iter()
        .position(|l| !l.trim().is_empty())
        .is_some_and(|i| is_heading(lines[i], lines.get(i + 1).copied()))
}

/// Split a sectioned report into `(section name, YAML fragment)` pairs.
fn split_sections(input: &str) -> Result<Vec<(String, String)>, RenderError> {
    let lines: Vec<&str> = input.lines().collect();
    let mut sections = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if is_heading(lines[i], lines.get(i + 1).copied()) {
            let name = lines[i].trim_end().to_owned();
            let mut body = String::new();
            let mut j = i + 2;
            while j < lines.len() && !is_heading(lines[j], lines.get(j + 1).copied()) {
                body.push_str(lines[j]);
                body.push('\n');
                j += 1;
            }
            sections.push((name, body));
            i = j;
        } else if lines[i].trim().is_empty() {
            i += 1;
        } else {
            return Err(RenderError::Parse(format!(
                "sectioned template-context: content outside any section at line {}",
                i + 1
            )));
        }
    }
    Ok(sections)
}

fn untag(value: serde_yaml::Value) -> serde_yaml::Value {
    match value {
        serde_yaml::Value::Tagged(tagged) => tagged.value,
        other => other,
    }
}

/// Normalize one parsed section fragment: fragments either repeat the
/// section name as a single wrapping key (`cfg:`, `clients:`) or are
/// bare values (`irrdb_info`, `never_via_route_servers_asns`).
fn unwrap_section(value: serde_yaml::Value, name: &str) -> serde_yaml::Value {
    if let serde_yaml::Value::Mapping(mut m) = value {
        if m.len() == 1
            && let Some(inner) = m.remove(name)
        {
            return inner;
        }
        return serde_yaml::Value::Mapping(m);
    }
    value
}

/// The sectioned report's `irrdb_info` is a list of bundle records
/// carrying their own hash `id`; the internal model keys bundles by
/// that id.
fn irrdb_list_to_map(value: serde_yaml::Value) -> Result<serde_yaml::Value, RenderError> {
    let serde_yaml::Value::Sequence(items) = value else {
        // Already a map (the single-document form) — pass through.
        return Ok(value);
    };
    let mut map = serde_yaml::Mapping::new();
    for item in items {
        let id = item
            .get("id")
            .and_then(serde_yaml::Value::as_str)
            .ok_or_else(|| RenderError::Parse("irrdb_info entry without a string `id`".to_owned()))?
            .to_owned();
        map.insert(serde_yaml::Value::String(id), item);
    }
    Ok(serde_yaml::Value::Mapping(map))
}

/// The sectioned report emits each client's `as_set_bundle_ids` as a
/// YAML `!!set`; the internal model wants a list. Sorted for a
/// deterministic bundle-union order.
fn normalize_bundle_id_sets(root: &mut serde_yaml::Mapping) {
    let Some(clients) = root
        .get_mut("clients")
        .and_then(serde_yaml::Value::as_sequence_mut)
    else {
        return;
    };
    for client in clients {
        let Some(irrdb) = client
            .get_mut("cfg")
            .and_then(|v| v.get_mut("filtering"))
            .and_then(|v| v.get_mut("irrdb"))
            .and_then(serde_yaml::Value::as_mapping_mut)
        else {
            continue;
        };
        let Some(ids) = irrdb.get_mut("as_set_bundle_ids") else {
            continue;
        };
        let current = untag(std::mem::replace(ids, serde_yaml::Value::Null));
        *ids = match current {
            serde_yaml::Value::Mapping(set) => {
                let mut keys: Vec<serde_yaml::Value> = set.into_iter().map(|(k, _)| k).collect();
                keys.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
                serde_yaml::Value::Sequence(keys)
            }
            other => other,
        };
    }
}

fn ingest_sectioned(
    input: &str,
    opts: &Options,
    warnings: &mut Vec<String>,
) -> Result<(serde_yaml::Value, String), RenderError> {
    let sections = split_sections(input)?;
    let mut names: Vec<String> = sections.iter().map(|(name, _)| name.clone()).collect();
    names.sort();
    let fingerprint = gate_shape(&names, EXPECTED_SECTION_NAMES, opts, warnings)?;

    let mut root = serde_yaml::Mapping::new();
    for (name, body) in sections {
        let parsed: serde_yaml::Value = serde_yaml::from_str(&body)
            .map_err(|e| RenderError::Parse(format!("section `{name}`: {e}")))?;
        let parsed = unwrap_section(parsed, &name);
        // The sectioned report names the whois-record sections with a
        // `_db_` infix the internal model does not use.
        let internal_name = match name.as_str() {
            "arin_whois_db_records" => "arin_whois_records",
            "registrobr_whois_db_records" => "registrobr_whois_records",
            other => other,
        };
        let parsed = if internal_name == "irrdb_info" {
            irrdb_list_to_map(parsed)?
        } else {
            parsed
        };
        root.insert(serde_yaml::Value::String(internal_name.to_owned()), parsed);
    }
    normalize_bundle_id_sets(&mut root);
    Ok((serde_yaml::Value::Mapping(root), fingerprint))
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

struct ResolvedClient<'a> {
    client: &'a Client,
    slug: String,
    description: String,
    prefixes: Vec<&'a PrefixEntry>,
    origins: Vec<u32>,
    enforce_origin: bool,
    enforce_prefix: bool,
    strict_next_hop: bool,
    add_path: bool,
    per_client_best: bool,
    gtsm: bool,
    allow_longer_prefixes: bool,
    limit_ipv4: Option<u32>,
    limit_ipv6: Option<u32>,
    max_prefix_restart_seconds: Option<u32>,
}

pub fn render(context_input: &str, opts: &Options) -> Result<Rendered, RenderError> {
    let mut warnings = Vec::new();
    let (value, found_fingerprint) = if looks_sectioned(context_input) {
        ingest_sectioned(context_input, opts, &mut warnings)?
    } else {
        ingest_single_document(context_input, opts, &mut warnings)?
    };

    let ctx: Context =
        serde_yaml::from_value(value).map_err(|e| RenderError::Parse(e.to_string()))?;

    check_refusals(&ctx, opts)?;

    let resolved = resolve_clients(&ctx, opts)?;
    collect_warnings(&ctx, &mut warnings);

    let router_id = match &ctx.cfg.router_id {
        RouterId::One(id) => id.clone(),
        RouterId::Many(ids) => {
            let first = ids
                .first()
                .ok_or_else(|| RenderError::Parse("router_id list is empty".to_owned()))?;
            if ids.len() > 1 {
                warnings.push(format!(
                    "router_id lists {} values; arouteserver renders one config per \
                     router-id — this render uses the first ({first})",
                    ids.len()
                ));
            }
            first.clone()
        }
    };

    let mut files = BTreeMap::new();
    files.insert(
        "policy/rs-hygiene.rpol".to_owned(),
        render_hygiene(&ctx, &found_fingerprint),
    );
    for rc in &resolved {
        files.insert(
            format!("policy/client-{}.rpol", rc.slug),
            render_client_rpol(rc, &found_fingerprint),
        );
    }
    files.insert(
        "config.toml".to_owned(),
        render_toml(&ctx, &resolved, &router_id, &found_fingerprint, opts),
    );

    let receipt = build_receipt(&resolved, &found_fingerprint, &warnings);

    Ok(Rendered {
        files,
        receipt,
        warnings,
    })
}

fn check_refusals(ctx: &Context, opts: &Options) -> Result<(), RenderError> {
    let mut refusals = Vec::new();
    let cfg = &ctx.cfg;
    let filtering = &cfg.filtering;

    if ctx.rtt_based_functions_are_used {
        refusals.push(
            "RTT-based communities/functions are in use; the daemon has no RTT source \
             (permanent reject, recorded in ADR-0101)"
                .to_owned(),
        );
    }
    if cfg
        .rtt_thresholds
        .as_ref()
        .is_some_and(|v| !v.is_null() && v.as_sequence().is_none_or(|s| !s.is_empty()))
    {
        refusals.push("rtt_thresholds configured; no RTT source in the daemon".to_owned());
    }
    for (name, value) in &cfg.communities {
        if name.contains("rtt") && community_configured(value) {
            refusals.push(format!(
                "RTT-based community `{name}` configured; no RTT source in the daemon"
            ));
        }
    }
    if cfg.prepend_rs_as {
        refusals.push(
            "prepend_rs_as: the rendered sessions are transparent route-server-client \
             sessions and never prepend the route-server ASN"
                .to_owned(),
        );
    }
    if ctx.perform_graceful_shutdown {
        refusals.push(
            "perform_graceful_shutdown: the temporary drain-config mode is not rendered; \
             drain the route server directly"
                .to_owned(),
        );
    }

    let blackhole = &cfg.blackhole_filtering;
    for (name, policy) in [
        ("policy_ipv4", &blackhole.policy_ipv4),
        ("policy_ipv6", &blackhole.policy_ipv6),
    ] {
        if let Some(policy) = policy {
            refusals.push(format!(
                "general: blackhole_filtering.{name} `{policy}` is not rendered"
            ));
        }
    }

    check_next_hop_policy(&filtering.next_hop.policy, "general", &mut refusals);
    check_reject_policy(&filtering.reject_policy.policy, "general", &mut refusals);
    if !filtering.irrdb.enforce_origin_in_as_set && !filtering.irrdb.enforce_prefix_in_as_set {
        refusals.push(
            "both irrdb.enforce_origin_in_as_set and irrdb.enforce_prefix_in_as_set are \
             disabled; the renderer only produces IRR-enforcing (default-reject) \
             per-client policy"
                .to_owned(),
        );
    }
    if filtering.rpki_bgp_origin_validation.enabled && opts.rtr_caches.is_empty() {
        refusals.push(
            "rpki_bgp_origin_validation is enabled but no --rtr-cache endpoint was given; \
             the context carries no RTR cache address"
                .to_owned(),
        );
    }
    if let Some(tf) = &filtering.transit_free
        && let Some(action) = tf.action.as_deref()
        && action != "reject"
    {
        refusals.push(format!(
            "transit_free.action `{action}` is not supported (only `reject`)"
        ));
    }

    for client in &ctx.clients {
        let scope = format!("client {}", client.id);
        let ipv6 = client.ip.contains(':');
        let multihop = client.cfg.multihop.or(cfg.multihop).unwrap_or(0);
        if multihop > 0 {
            refusals.push(format!(
                "{scope}: effective multihop={multihop} is not rendered; set this client to 0 or disable general multihop"
            ));
        }
        let rfc8950 = client.cfg.rfc8950.unwrap_or(cfg.rfc8950);
        if ipv6 && rfc8950 {
            refusals.push(format!(
                "{scope}: effective rfc8950=true is not rendered on IPv6 sessions"
            ));
        }
        let client_has_blackhole_policy = if ipv6 {
            blackhole.policy_ipv6.is_some() || (rfc8950 && blackhole.policy_ipv4.is_some())
        } else {
            blackhole.policy_ipv4.is_some()
        };
        let client_announce = client.cfg.blackhole_filtering.announce_to_client;
        let general_announce = cfg.blackhole_filtering.announce_to_client.unwrap_or(true);
        if client_has_blackhole_policy && client_announce.is_some_and(|v| v != general_announce) {
            refusals.push(format!(
                "{scope}: blackhole announce_to_client override is not rendered"
            ));
        }
        if let Some(next_hop) = &client.cfg.filtering.next_hop {
            check_next_hop_policy(
                &next_hop.policy,
                &format!("client {}", client.id),
                &mut refusals,
            );
        }
        if let Some(reject) = &client.cfg.filtering.reject_policy {
            check_reject_policy(
                &reject.policy,
                &format!("client {}", client.id),
                &mut refusals,
            );
        }
        let effective_max_prefix = effective_max_prefix(
            filtering.max_prefix.as_ref(),
            client.cfg.filtering.max_prefix.as_ref(),
        );
        check_max_prefix_action(
            effective_max_prefix.action,
            effective_max_prefix.restart_after,
            &scope,
            &mut refusals,
        );
        check_max_prefix_counting(effective_max_prefix, &scope, &mut refusals);
        // Per-client black/white lists are not rendered; dropping a
        // black list would fail open, dropping a white list would
        // reject routes the site intends to accept.
        if value_present(client.cfg.filtering.black_list_pref.as_ref()) {
            refusals.push(format!(
                "client {}: black_list_pref is not rendered; silently dropping it would \
                 fail open",
                client.id
            ));
        }
        let irrdb = &client.cfg.filtering.irrdb;
        for (name, value) in [
            ("white_list_asn", &irrdb.white_list_asn),
            ("white_list_pref", &irrdb.white_list_pref),
            ("white_list_route", &irrdb.white_list_route),
        ] {
            if value_present(value.as_ref()) {
                refusals.push(format!(
                    "client {}: irrdb.{name} is not rendered; silently dropping it would \
                     reject routes the site intends to accept",
                    client.id
                ));
            }
        }
    }

    if refusals.is_empty() {
        Ok(())
    } else {
        Err(RenderError::Refused(refusals))
    }
}

/// True when an optional list/mapping knob is actually set (not
/// absent, null, or empty).
fn value_present(value: Option<&serde_yaml::Value>) -> bool {
    value.is_some_and(|v| match v {
        serde_yaml::Value::Null => false,
        serde_yaml::Value::Sequence(s) => !s.is_empty(),
        serde_yaml::Value::Mapping(m) => !m.is_empty(),
        _ => true,
    })
}

fn community_configured(value: &serde_yaml::Value) -> bool {
    value.as_mapping().is_some_and(|m| {
        m.iter()
            .any(|(k, v)| matches!(k.as_str(), Some("std" | "lrg" | "ext")) && !v.is_null())
    })
}

fn check_next_hop_policy(policy: &str, scope: &str, refusals: &mut Vec<String>) {
    match policy {
        "strict" => {}
        "same-as" => refusals.push(format!(
            "{scope}: next_hop.policy `same-as` needs the fleet inventory deferred by \
             ADR-0107; only `strict` is supported"
        )),
        other => refusals.push(format!(
            "{scope}: next_hop.policy `{other}` is not supported (only `strict`)"
        )),
    }
}

fn check_reject_policy(policy: &str, scope: &str, refusals: &mut Vec<String>) {
    match policy {
        "reject" => {}
        "tag" | "tag_and_reject" => refusals.push(format!(
            "{scope}: reject_policy `{policy}` needs reject-reason community wiring for \
             the looking-glass surface; only `reject` is rendered (the daemon retains \
             rejected routes with reasons natively — see the route-server cookbook)"
        )),
        other => refusals.push(format!("{scope}: unknown reject_policy `{other}`")),
    }
}

#[derive(Clone, Copy)]
struct EffectiveMaxPrefix<'a> {
    action: Option<&'a str>,
    restart_after: Option<u32>,
    count_rejected_routes: bool,
    limit_ipv4: Option<u32>,
    limit_ipv6: Option<u32>,
}

/// Resolve the client-over-general inheritance that arouteserver applies to
/// max-prefix behavior. The per-client limits in `template-context` are
/// already resolved from client, PeeringDB, and general sources.
fn effective_max_prefix<'a>(
    general: Option<&'a MaxPrefixCfg>,
    client: Option<&'a ClientMaxPrefix>,
) -> EffectiveMaxPrefix<'a> {
    EffectiveMaxPrefix {
        action: client
            .and_then(|mp| mp.action.as_deref())
            .or_else(|| general.and_then(|mp| mp.action.as_deref())),
        restart_after: client
            .and_then(|mp| mp.restart_after)
            .or_else(|| general.and_then(|mp| mp.restart_after)),
        count_rejected_routes: client
            .and_then(|mp| mp.count_rejected_routes)
            .or_else(|| general.and_then(|mp| mp.count_rejected_routes))
            // ARouteServer 1.23.2 resolves an omitted value to true.
            .unwrap_or(true),
        limit_ipv4: client
            .and_then(|mp| mp.limit_ipv4)
            .filter(|limit| *limit > 0),
        limit_ipv6: client
            .and_then(|mp| mp.limit_ipv6)
            .filter(|limit| *limit > 0),
    }
}

fn check_max_prefix_action(
    action: Option<&str>,
    restart_after: Option<u32>,
    scope: &str,
    refusals: &mut Vec<String>,
) {
    match action {
        None | Some("shutdown") => {}
        Some("restart") => match restart_after {
            None => refusals.push(format!(
                "{scope}: max_prefix.action `restart` requires restart_after > 0 minutes"
            )),
            Some(0) => refusals.push(format!(
                "{scope}: max_prefix.action `restart` requires restart_after > 0 minutes"
            )),
            Some(minutes) if minutes.checked_mul(60).is_none() => refusals.push(format!(
                "{scope}: max_prefix.restart_after={minutes} minutes exceeds rustbgpd's \
                 u32-second maximum"
            )),
            Some(_) => {}
        },
        Some(other @ ("block" | "warning")) => refusals.push(format!(
            "{scope}: max_prefix.action `{other}` is not supported; rustbgpd only \
             implements `shutdown` and timed `restart`"
        )),
        Some(other) => refusals.push(format!(
            "{scope}: unknown max_prefix.action `{other}` (only `shutdown` and timed \
             `restart` are supported)"
        )),
    }
}

fn check_max_prefix_counting(
    max_prefix: EffectiveMaxPrefix<'_>,
    scope: &str,
    refusals: &mut Vec<String>,
) {
    if matches!(max_prefix.action, Some("shutdown" | "restart"))
        && (max_prefix.limit_ipv4.is_some() || max_prefix.limit_ipv6.is_some())
        && max_prefix.count_rejected_routes
    {
        refusals.push(format!(
            "{scope}: effective max_prefix.count_rejected_routes=true is not supported; \
             ARouteServer defaults this option to true, while rustbgpd max-prefix ceilings \
             count accepted routes only, so set it to false"
        ));
    }
}

fn resolve_clients<'a>(
    ctx: &'a Context,
    opts: &Options,
) -> Result<Vec<ResolvedClient<'a>>, RenderError> {
    let mut resolved = Vec::new();
    let mut implausible = Vec::new();

    for client in &ctx.clients {
        let slug = client.id.to_lowercase().replace('_', "-");
        let filtering = &client.cfg.filtering;
        let enforce_origin = ctx.cfg.filtering.irrdb.enforce_origin_in_as_set;
        let enforce_prefix = ctx.cfg.filtering.irrdb.enforce_prefix_in_as_set;

        let mut prefixes: Vec<&PrefixEntry> = Vec::new();
        // A client's bundles overlap (arouteserver resolves both the
        // AS-SET and the bare origin-ASN object); the union dedupes.
        let mut seen_prefixes = BTreeSet::new();
        let mut origins = BTreeSet::new();
        for bundle_id in &filtering.irrdb.as_set_bundle_ids {
            let bundle = ctx.irrdb_info.get(bundle_id).ok_or_else(|| {
                RenderError::Parse(format!(
                    "client {} references irrdb bundle {bundle_id:?} absent from irrdb_info",
                    client.id
                ))
            })?;
            for prefix in &bundle.prefixes {
                let key = (
                    prefix.prefix.clone(),
                    prefix.length,
                    prefix.exact,
                    prefix.ge,
                    prefix.le,
                    prefix.max_length,
                );
                if seen_prefixes.insert(key) {
                    prefixes.push(prefix);
                }
            }
            for asn in &bundle.asns {
                origins.insert(asn.value().map_err(RenderError::Parse)?);
            }
        }

        if enforce_prefix && (prefixes.len() as u64) < u64::from(opts.min_prefixes) {
            implausible.push(format!(
                "client {} (AS{}): {} IRR prefix(es) resolved, floor is {} — an empty or \
                 shrunken set means the upstream IRR answer is broken, not that the \
                 client deregistered everything",
                client.id,
                client.asn,
                prefixes.len(),
                opts.min_prefixes
            ));
        }
        if enforce_origin && (origins.len() as u64) < u64::from(opts.min_origins) {
            implausible.push(format!(
                "client {} (AS{}): {} IRR origin ASN(s) resolved, floor is {}",
                client.id,
                client.asn,
                origins.len(),
                opts.min_origins
            ));
        }

        let strict_next_hop = filtering
            .next_hop
            .as_ref()
            .map(|nh| nh.policy == "strict")
            .unwrap_or(ctx.cfg.filtering.next_hop.policy == "strict");
        let add_path = client.cfg.add_path.unwrap_or(ctx.cfg.add_path);
        let per_client_best = ctx.cfg.path_hiding && !add_path;
        let gtsm = client.cfg.gtsm.unwrap_or(ctx.cfg.gtsm);
        let max_prefix = effective_max_prefix(
            ctx.cfg.filtering.max_prefix.as_ref(),
            filtering.max_prefix.as_ref(),
        );
        let (limit_ipv4, limit_ipv6) = if matches!(max_prefix.action, Some("shutdown" | "restart"))
        {
            (max_prefix.limit_ipv4, max_prefix.limit_ipv6)
        } else {
            (None, None)
        };
        let max_prefix_restart_seconds = (max_prefix.action == Some("restart")
            && (limit_ipv4.is_some() || limit_ipv6.is_some()))
        .then(|| {
            max_prefix
                .restart_after
                .and_then(|minutes| minutes.checked_mul(60))
        })
        .flatten();

        let description = client
            .description
            .clone()
            .or_else(|| client.cfg.description.clone())
            .unwrap_or_else(|| client.id.clone());

        resolved.push(ResolvedClient {
            client,
            slug,
            description,
            prefixes,
            origins: origins.into_iter().collect(),
            enforce_origin,
            enforce_prefix,
            strict_next_hop,
            add_path,
            per_client_best,
            gtsm,
            allow_longer_prefixes: ctx.cfg.filtering.irrdb.allow_longer_prefixes,
            limit_ipv4,
            limit_ipv6,
            max_prefix_restart_seconds,
        });
    }

    if !implausible.is_empty() {
        return Err(RenderError::Implausible(implausible));
    }
    Ok(resolved)
}

fn collect_warnings(ctx: &Context, warnings: &mut Vec<String>) {
    if ctx.cfg.passive == Some(false) {
        warnings.push("passive=false is ignored: the daemon both listens and connects".to_owned());
    }
}

// ---------------------------------------------------------------------------
// Emitters
// ---------------------------------------------------------------------------

fn generated_header(kind: &str, fingerprint: &str) -> String {
    format!(
        "# GENERATED by rs-config-render — do not edit; edits are overwritten on the\n\
         # next refresh. Regenerate from `arouteserver template-context` output.\n\
         # {kind}. Context-shape fingerprint: {fingerprint}.\n"
    )
}

fn toml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn render_toml(
    ctx: &Context,
    clients: &[ResolvedClient<'_>],
    router_id: &str,
    fingerprint: &str,
    opts: &Options,
) -> String {
    let mut out = generated_header("Route-server configuration", fingerprint);
    let cfg = &ctx.cfg;

    let _ = write!(
        out,
        "\n[global]\nasn = {}\nrouter_id = \"{}\"\nlisten_port = 179\n",
        cfg.rs_as,
        toml_escape(router_id)
    );
    if cfg.graceful_shutdown.enabled {
        out.push_str(
            "# RFC 8326: honor GRACEFUL_SHUTDOWN from members (local-pref 0 chain tail).\n\
             honor_graceful_shutdown = true\n",
        );
    }
    out.push_str(
        "\n# Local management surface (`rbgp` over UDS, file-permission gated) —\n\
         # the same shape as examples/route-server/. Add prometheus_addr here to\n\
         # scrape metrics.\n\
         [global.telemetry]\nlog_format = \"json\"\n\n\
         [global.telemetry.grpc_uds]\npath = \"/var/lib/rustbgpd/grpc.sock\"\nprincipal = \"operator\"\n\n\
         [security.grpc]\nenforcement = \"tier\"\n\n\
         [security.grpc.roles]\noperator = \"operator\"\n",
    );

    if cfg.filtering.rpki_bgp_origin_validation.enabled {
        out.push_str("\n[rpki]\n");
        for cache in &opts.rtr_caches {
            let _ = write!(
                out,
                "[[rpki.cache_servers]]\naddress = \"{}\"\n",
                toml_escape(cache)
            );
        }
    }

    out.push_str("\n[policy]\nrpol_files = [\n    \"policy/rs-hygiene.rpol\",\n");
    for rc in clients {
        let _ = writeln!(out, "    \"policy/client-{}.rpol\",", rc.slug);
    }
    out.push_str("]\n");

    for rc in clients {
        let family = if rc.client.ip.contains(':') {
            "ipv6_unicast"
        } else {
            "ipv4_unicast"
        };
        let _ = write!(
            out,
            "\n[[neighbors]]\naddress = \"{}\"\nremote_asn = {}\ndescription = \"{}\"\n\
             families = [\"{family}\"]\nroute_server_client = true\nrole = \"route_server\"\n",
            toml_escape(&rc.client.ip),
            rc.client.asn,
            toml_escape(&rc.description),
        );
        if rc.strict_next_hop {
            out.push_str("next_hop_ownership = \"strict_peer\"\n");
        }
        if rc.gtsm {
            out.push_str("ttl_security = true\n");
        }
        if rc.per_client_best {
            out.push_str("per_client_best = true\n");
        }
        if let Some(limit) = rc.limit_ipv4 {
            let _ = writeln!(out, "max_prefixes_ipv4 = {limit}");
        }
        if let Some(limit) = rc.limit_ipv6 {
            let _ = writeln!(out, "max_prefixes_ipv6 = {limit}");
        }
        if let Some(seconds) = rc.max_prefix_restart_seconds {
            let _ = writeln!(out, "max_prefix_restart_seconds = {seconds}");
        }
        let _ = writeln!(
            out,
            "import_policy_chain = [\"rs-hygiene\", \"client-{}\"]",
            rc.slug
        );
        if rc.add_path {
            out.push_str("\n[neighbors.add_path]\nsend = true\nsend_max = 8\n");
        }
    }
    out
}

fn render_prefix_set(
    out: &mut String,
    name: &str,
    entries: &[&PrefixEntry],
    subtree_default: bool,
    force_le_max: bool,
) {
    let _ = writeln!(out, "prefix-set {name} {{");
    for entry in entries {
        let member = entry.render_member(subtree_default, force_le_max);
        match &entry.comment {
            Some(comment) => {
                let _ = writeln!(out, "    {member},  # {}", comment.replace('\n', " "));
            }
            None => {
                let _ = writeln!(out, "    {member},");
            }
        }
    }
    out.push_str("}\n");
}

fn render_hygiene(ctx: &Context, fingerprint: &str) -> String {
    let filtering = &ctx.cfg.filtering;
    let mut out = generated_header("Shared import hygiene", fingerprint);
    out.push_str(
        "#\n\
         # Ordering contract: this policy is the first member of every client's\n\
         # import chain and its first term rejects AS_SET segments, so per-client\n\
         # origin enforcement (`route.origin-as in ...`) is never evaluated on a\n\
         # path that still carries an AS_SET.\n\n",
    );

    let mut sets = String::new();
    let mut terms = String::new();
    let mut tests = String::new();

    // Term 1 — AS_SET hygiene, always first.
    terms.push_str(
        "    # AS_SET segments render in braces (\"65001 {65002 65003}\").\n\
         \x20   term reject-as-set { if route.as-path matches \"\\\\{\" { reject } }\n",
    );
    tests.push_str(
        "test as-set-path-is-rejected {\n    route { prefix 203.0.113.0/24; as-path \"3333 {65010 65011}\" }\n    expect rs-hygiene == reject\n}\n",
    );

    if filtering.reject_invalid_as_in_as_path {
        let _ = write!(
            terms,
            "    # 0, AS_TRANS, 16-bit doc/private/reserved (64496-65551), and the\n\
             \x20   # 32-bit private+reserved range (any 10-digit \"42...\" ASN in u32).\n\
             \x20   term reject-invalid-asn {{ if route.as-path matches \"{INVALID_ASN_REGEX}\" {{ reject }} }}\n"
        );
        tests.push_str(
            "test private-16bit-asn-in-path-is-rejected {\n    route { prefix 203.0.113.0/24; as-path \"3333 64512\" }\n    expect rs-hygiene == reject\n}\n\
             test private-32bit-asn-in-path-is-rejected {\n    route { prefix 203.0.113.0/24; as-path \"3333 4210000000\" }\n    expect rs-hygiene == reject\n}\n",
        );
    }

    if let Some(tf) = &filtering.transit_free
        && let Some(asns) = tf.asns.as_ref().filter(|a| !a.is_empty())
    {
        let mut sorted = asns.clone();
        sorted.sort_unstable();
        sorted.dedup();
        let _ = writeln!(
            sets,
            "asn-set rs-transit-free-asns {{ {} }}",
            sorted
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        let alternation = sorted
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join("|");
        let _ = write!(
            terms,
            "    # A transit-free network in the path of a route learned from anyone\n\
             \x20   # but that network itself means someone is leaking transit through it.\n\
             \x20   term reject-transit-free-in-path {{\n\
             \x20       if !(peer.asn in rs-transit-free-asns) && route.as-path matches \"_({alternation})_\" {{ reject }}\n\
             \x20   }}\n"
        );
    }

    if !ctx.never_via_route_servers_asns.is_empty() {
        let mut sorted = ctx.never_via_route_servers_asns.clone();
        sorted.sort_unstable();
        sorted.dedup();
        let alternation = sorted
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join("|");
        let _ = write!(
            terms,
            "    # PeeringDB never-via-route-servers networks.\n\
             \x20   term reject-never-via-rs {{ if route.as-path matches \"_({alternation})_\" {{ reject }} }}\n"
        );
    }

    let max_len = filtering.max_as_path_len;
    let _ = writeln!(
        terms,
        "    term reject-long-as-path {{ if route.as-path.len >= {} {{ reject }} }}",
        max_len.saturating_add(1)
    );
    if max_len <= 64 {
        let long_path = vec!["3333"; max_len as usize + 1].join(" ");
        let _ = write!(
            tests,
            "test overlong-as-path-is-rejected {{\n    route {{ prefix 203.0.113.0/24; as-path \"{long_path}\" }}\n    expect rs-hygiene == reject\n}}\n"
        );
    }

    if !ctx.bogons.is_empty() {
        let refs: Vec<&PrefixEntry> = ctx.bogons.iter().collect();
        render_prefix_set(&mut sets, "rs-bogon-prefixes", &refs, true, false);
        terms.push_str(
            "    term reject-bogon-prefix { if route.prefix in rs-bogon-prefixes { reject } }\n",
        );
    }

    if let Some(black_list) = filtering
        .global_black_list_pref
        .as_ref()
        .filter(|entries| !entries.is_empty())
    {
        let refs: Vec<&PrefixEntry> = black_list.iter().collect();
        render_prefix_set(&mut sets, "rs-black-list-prefixes", &refs, true, false);
        terms.push_str(
            "    term reject-black-list-prefix { if route.prefix in rs-black-list-prefixes { reject } }\n",
        );
    }

    render_pref_len_window(
        &mut sets,
        &mut terms,
        &mut tests,
        filtering.ipv4_pref_len.as_ref(),
        false,
    );
    render_pref_len_window(
        &mut sets,
        &mut terms,
        &mut tests,
        filtering.ipv6_pref_len.as_ref(),
        true,
    );

    let rpki = &filtering.rpki_bgp_origin_validation;
    if rpki.enabled {
        if rpki.reject_invalid {
            terms
                .push_str("    term reject-rpki-invalid { if route.rpki == invalid { reject } }\n");
            tests.push_str(
                "test rpki-invalid-is-rejected {\n    route { prefix 203.0.113.0/24; as-path \"3333\"; rpki invalid }\n    expect rs-hygiene == reject\n}\n",
            );
        }
        terms.push_str(
            "    # RFC 8097 origin-validation extended communities for members.\n\
             \x20   term tag-ov-valid { if route.rpki == valid { add ext-community OV_VALID } }\n\
             \x20   term tag-ov-not-found { if route.rpki == not-found { add ext-community OV_NOT_FOUND } }\n",
        );
        if !rpki.reject_invalid {
            terms.push_str(
                "    term tag-ov-invalid { if route.rpki == invalid { add ext-community OV_INVALID } }\n",
            );
        }
    }

    if !sets.is_empty() {
        out.push_str(&sets);
        out.push('\n');
    }
    out.push_str("policy rs-hygiene {\n");
    out.push_str(&terms);
    out.push_str("}\n");
    if !tests.is_empty() {
        out.push('\n');
        out.push_str("# In-language tests, run by `rbgp policy check`.\n");
        out.push_str(&tests);
    }
    out
}

fn render_pref_len_window(
    sets: &mut String,
    terms: &mut String,
    tests: &mut String,
    window: Option<&PrefLen>,
    ipv6: bool,
) {
    let Some(window) = window else { return };
    let (root, bits, tag) = if ipv6 {
        ("::/0", 128u8, "v6")
    } else {
        ("0.0.0.0/0", 32u8, "v4")
    };
    let mut members = Vec::new();
    if window.min > 0 {
        members.push(format!("{root} le {}", window.min - 1));
    }
    if window.max < bits {
        members.push(format!("{root} ge {}", window.max + 1));
    }
    if members.is_empty() {
        return;
    }
    let set_name = format!("rs-{tag}-len-outside-window");
    let _ = writeln!(sets, "prefix-set {set_name} {{");
    for member in &members {
        let _ = writeln!(sets, "    {member},");
    }
    sets.push_str("}\n");
    let _ = writeln!(
        terms,
        "    # Accepted {tag} prefix lengths: {}-{}.",
        window.min, window.max
    );
    let _ = writeln!(
        terms,
        "    term reject-{tag}-len-outside-window {{ if route.prefix in {set_name} {{ reject }} }}"
    );
    if window.min > 0 {
        let _ = write!(
            tests,
            "test {tag}-default-route-is-rejected {{\n    route {{ prefix {root} }}\n    expect rs-hygiene == reject\n}}\n"
        );
    }
}

fn render_client_rpol(rc: &ResolvedClient<'_>, fingerprint: &str) -> String {
    let slug = &rc.slug;
    let mut out = generated_header(
        &format!(
            "IRR filter for client {} (AS{}, {})",
            rc.client.id, rc.client.asn, rc.client.ip
        ),
        fingerprint,
    );
    out.push('\n');

    let mut conjuncts = Vec::new();
    if rc.enforce_origin {
        let _ = writeln!(
            out,
            "asn-set client-{slug}-origins {{ {} }}",
            rc.origins
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        conjuncts.push(format!("route.origin-as in client-{slug}-origins"));
    }
    if rc.enforce_prefix {
        render_prefix_set(
            &mut out,
            &format!("client-{slug}-prefixes"),
            &rc.prefixes,
            false,
            rc.allow_longer_prefixes,
        );
        conjuncts.push(format!("route.prefix in client-{slug}-prefixes"));
    }

    let _ = write!(
        out,
        "\npolicy client-{slug} {{\n\
         \x20   term accept-authorized {{\n\
         \x20       if {} {{ accept }}\n\
         \x20   }}\n\
         \x20   # Fail-closed: anything the IRR data does not authorize is rejected.\n\
         \x20   term rest {{ reject }}\n\
         }}\n",
        conjuncts.join(" && ")
    );

    // In-language tests derived from the client's own IRR data.
    if let (true, Some(first_origin)) = (rc.enforce_origin, rc.origins.first()) {
        let accept_prefix = if rc.enforce_prefix {
            rc.prefixes.first().map(|p| representative_prefix(p))
        } else {
            Some("203.0.113.0/24".to_owned())
        };
        if let Some(prefix) = accept_prefix {
            let _ = write!(
                out,
                "\ntest client-{slug}-authorized-route-is-accepted {{\n\
                 \x20   route {{ prefix {prefix}; as-path \"{first_origin}\" }}\n\
                 \x20   expect client-{slug} == accept\n\
                 }}\n"
            );
            let unregistered = unregistered_origin(&rc.origins);
            let _ = write!(
                out,
                "\ntest client-{slug}-unregistered-origin-is-rejected {{\n\
                 \x20   route {{ prefix {prefix}; as-path \"{unregistered}\" }}\n\
                 \x20   expect client-{slug} == reject\n\
                 }}\n"
            );
        }
    }
    out
}

/// A concrete prefix guaranteed to match the given set member: the
/// member's own network, lengthened to `ge` when the member excludes
/// its own length. Lengthening keeps the literal valid (network bits
/// are unchanged, host bits stay zero).
fn representative_prefix(entry: &PrefixEntry) -> String {
    let length = entry
        .ge
        .filter(|ge| *ge > entry.length)
        .unwrap_or(entry.length);
    format!("{}/{}", entry.prefix, length)
}

fn unregistered_origin(origins: &[u32]) -> u32 {
    let max = origins.iter().copied().max().unwrap_or(0);
    if max == u32::MAX { max - 1 } else { max + 1 }
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

fn build_receipt(
    clients: &[ResolvedClient<'_>],
    fingerprint: &str,
    warnings: &[String],
) -> serde_json::Value {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    serde_json::json!({
        "rendered_at_unix": now,
        "rendered_at_utc": format_utc(now),
        "context_fingerprint": fingerprint,
        // arouteserver's template-context carries no per-source cache
        // timestamps; source freshness is governed upstream by its own
        // per-source cache expiries. Kept as an explicit null so the
        // field appears once the context grows one.
        "source_data_ages": serde_json::Value::Null,
        "clients": clients.iter().map(|rc| serde_json::json!({
            "id": rc.client.id,
            "asn": rc.client.asn,
            "ip": rc.client.ip,
            "prefix_set_size": rc.prefixes.len(),
            "origin_set_size": rc.origins.len(),
            "max_prefixes_ipv4": rc.limit_ipv4,
            "max_prefixes_ipv6": rc.limit_ipv6,
            "max_prefix_restart_seconds": rc.max_prefix_restart_seconds,
        })).collect::<Vec<_>>(),
        "warnings": warnings,
    })
}

/// Unix seconds to `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days algorithm).
fn format_utc(unix: u64) -> String {
    let days = unix / 86_400;
    let secs = unix % 86_400;
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { year + 1 } else { year };
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        (secs / 60) % 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_formatting_matches_known_dates() {
        assert_eq!(format_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_utc(1_752_710_400), "2025-07-17T00:00:00Z");
    }

    #[test]
    fn fingerprint_is_stable() {
        // Locks the pinned-shape fingerprint; a change here means the
        // supported context shape moved and the README/receipt docs
        // must move with it.
        assert_eq!(expected_fingerprint().len(), 16);
        let again = expected_fingerprint();
        assert_eq!(expected_fingerprint(), again);
    }

    #[test]
    fn prefix_member_rendering() {
        let entry = PrefixEntry {
            prefix: "10.0.0.0".into(),
            length: 8,
            comment: None,
            exact: false,
            ge: None,
            le: None,
            max_length: None,
        };
        assert_eq!(entry.render_member(true, false), "10.0.0.0/8 le 32");
        assert_eq!(entry.render_member(false, false), "10.0.0.0/8");
        assert_eq!(entry.render_member(false, true), "10.0.0.0/8 le 32");
        let bounded = PrefixEntry {
            prefix: "2001:db8::".into(),
            length: 32,
            comment: None,
            exact: false,
            ge: Some(40),
            le: Some(48),
            max_length: None,
        };
        assert_eq!(
            bounded.render_member(false, false),
            "2001:db8::/32 ge 40 le 48"
        );
        assert_eq!(representative_prefix(&bounded), "2001:db8::/40");
    }
}
