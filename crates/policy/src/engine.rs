use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, OnceLock};

use regex::Regex;
use rustbgpd_wire::{
    AsPath, AsPathSegment, AspaValidation, ExtendedCommunity, LargeCommunity, PathAttribute,
    Prefix, RpkiValidation,
};

use crate::eval::PolicyHitCounters;
use crate::ir::CompiledChain;
use crate::sets::SetStore;

/// Implicit `LOCAL_PREF` used when a route arrives without the
/// attribute (e.g. eBGP-received with no `LOCAL_PREF` on the wire).
/// RFC 4271 §5.1.5 makes 100 the default for best-path purposes;
/// `match_local_pref_ge` / `match_local_pref_le` use the same
/// value so policy reads identically against routes regardless of
/// whether `LOCAL_PREF` is on the wire. `FRR` / `BIRD` / `GoBGP`
/// follow the same convention.
pub(crate) const IMPLICIT_LOCAL_PREF: u32 = 100;

/// Implicit `MED` used when a route arrives without the attribute.
/// RFC 4271 §5.1.4 specifies 0.
pub(crate) const IMPLICIT_MED: u32 = 0;

const EXACT_LIST_SET_THRESHOLD: usize = 32;

/// Action taken when a prefix matches a policy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Allow the route to pass.
    Permit,
    /// Reject the route.
    Deny,
}

/// The result of evaluating a policy: an action plus any route modifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResult {
    /// Whether the route is permitted or denied.
    pub action: PolicyAction,
    /// Attribute modifications to apply (empty when denied).
    pub modifications: RouteModifications,
}

impl PolicyResult {
    /// Create a `Permit` result with no modifications.
    #[must_use]
    pub fn permit() -> Self {
        Self {
            action: PolicyAction::Permit,
            modifications: RouteModifications::default(),
        }
    }

    /// Create a `Deny` result with no modifications.
    #[must_use]
    pub fn deny() -> Self {
        Self {
            action: PolicyAction::Deny,
            modifications: RouteModifications::default(),
        }
    }
}

/// Borrowed route data used for policy evaluation.
#[derive(Debug, Clone, Copy)]
pub struct RouteContext<'a> {
    /// The route's NLRI prefix, when the address family carries one.
    ///
    /// Prefix predicates do not match prefixless families such as BGP-LS
    /// topology NLRIs.
    pub prefix: Option<Prefix>,
    /// The route's resolved next-hop, if any.
    pub next_hop: Option<IpAddr>,
    /// Extended communities attached to the route.
    pub extended_communities: &'a [ExtendedCommunity],
    /// Standard communities (RFC 1997) as raw u32 values.
    pub communities: &'a [u32],
    /// Large communities (RFC 8092) attached to the route.
    pub large_communities: &'a [LargeCommunity],
    /// String representation of the `AS_PATH` for regex matching.
    pub as_path_str: &'a str,
    /// Number of ASNs in the `AS_PATH` (RFC 4271 length rules).
    pub as_path_len: usize,
    /// RPKI origin validation state (RFC 6811).
    pub validation_state: RpkiValidation,
    /// ASPA path verification state.
    pub aspa_state: AspaValidation,
    /// Evaluation peer IP address.
    pub peer_address: Option<IpAddr>,
    /// Evaluation peer remote ASN.
    pub peer_asn: Option<u32>,
    /// Evaluation peer-group name.
    pub peer_group: Option<&'a str>,
    /// Route source type.
    pub route_type: Option<RouteType>,
    /// EVPN route type (RFC 7432 §7) when the route is an EVPN NLRI:
    /// 1=EAD per-ES/per-EVI, 2=MAC/IP, 3=IMET, 4=ES, 5=IP Prefix
    /// (RFC 9136). `None` for non-EVPN routes — `match_evpn_route_type`
    /// never matches non-EVPN traffic.
    pub evpn_route_type: Option<u8>,
    /// Explicit `LOCAL_PREF` attribute value.
    pub local_pref: Option<u32>,
    /// Explicit MED attribute value.
    pub med: Option<u32>,
}

/// Route source class for policy matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteType {
    /// Locally originated route.
    Local,
    /// Learned from an iBGP peer.
    Internal,
    /// Learned from an eBGP peer.
    External,
}

/// Named neighbor-set match compiled from config.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NeighborSetMatch {
    /// Exact peer-address matches.
    pub addresses: Vec<IpAddr>,
    /// Peer remote ASNs that match.
    pub remote_asns: Vec<u32>,
    /// Peer-group names that match.
    pub peer_groups: Vec<String>,
}

impl NeighborSetMatch {
    /// Returns `true` if the evaluation peer matches any set member.
    #[must_use]
    pub fn matches(
        &self,
        peer_address: Option<IpAddr>,
        peer_asn: Option<u32>,
        peer_group: Option<&str>,
    ) -> bool {
        peer_address.is_some_and(|addr| self.addresses.contains(&addr))
            || peer_asn.is_some_and(|asn| self.remote_asns.contains(&asn))
            || peer_group.is_some_and(|group| self.peer_groups.iter().any(|name| name == group))
    }
}

/// What to do with the next-hop attribute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextHopAction {
    /// Rewrite next-hop to the local address ("self").
    Self_,
    /// Rewrite next-hop to a specific address.
    Specific(IpAddr),
}

/// Route attribute modifications to apply after a policy match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteModifications {
    /// Override `LOCAL_PREF` to this value.
    pub set_local_pref: Option<u32>,
    /// Override `MED` to this value.
    pub set_med: Option<u32>,
    /// Override the `NEXT_HOP` attribute.
    pub set_next_hop: Option<NextHopAction>,
    /// Standard communities (RFC 1997) to add.
    pub communities_add: Vec<u32>,
    /// Standard communities (RFC 1997) to remove.
    pub communities_remove: Vec<u32>,
    /// Extended communities to add.
    pub extended_communities_add: Vec<ExtendedCommunity>,
    /// Extended communities to remove.
    pub extended_communities_remove: Vec<ExtendedCommunity>,
    /// Large communities (RFC 8092) to add.
    pub large_communities_add: Vec<LargeCommunity>,
    /// Large communities (RFC 8092) to remove.
    pub large_communities_remove: Vec<LargeCommunity>,
    /// `(ASN, count)` — prepend `count` copies of `ASN` to the `AS_PATH`.
    pub as_path_prepend: Option<(u32, u8)>,
}

impl RouteModifications {
    /// Returns `true` if no modifications are configured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.set_local_pref.is_none()
            && self.set_med.is_none()
            && self.set_next_hop.is_none()
            && self.as_path_prepend.is_none()
            && self.communities_add.is_empty()
            && self.communities_remove.is_empty()
            && self.extended_communities_add.is_empty()
            && self.extended_communities_remove.is_empty()
            && self.large_communities_add.is_empty()
            && self.large_communities_remove.is_empty()
    }

    /// Merge another set of modifications into this one.
    ///
    /// Scalar fields (`set_local_pref`, `set_med`, `set_next_hop`,
    /// `as_path_prepend`): `other` wins if `Some`.
    /// List fields (community add/remove): merged with later policy winning
    /// on conflicts. A later remove cancels an earlier add of the same
    /// logical value, and a later add cancels an earlier remove.
    pub fn merge_from(&mut self, other: RouteModifications) {
        if other.set_local_pref.is_some() {
            self.set_local_pref = other.set_local_pref;
        }
        if other.set_med.is_some() {
            self.set_med = other.set_med;
        }
        if other.set_next_hop.is_some() {
            self.set_next_hop = other.set_next_hop;
        }
        if other.as_path_prepend.is_some() {
            self.as_path_prepend = other.as_path_prepend;
        }
        merge_exact_list(
            &mut self.communities_add,
            &mut self.communities_remove,
            other.communities_add,
            other.communities_remove,
        );
        merge_equivalent_list(
            &mut self.extended_communities_add,
            &mut self.extended_communities_remove,
            other.extended_communities_add,
            other.extended_communities_remove,
            extended_communities_equivalent,
        );
        merge_exact_list(
            &mut self.large_communities_add,
            &mut self.large_communities_remove,
            other.large_communities_add,
            other.large_communities_remove,
        );
    }
}

/// Merge add/remove lists where equality is exact and later policy wins.
fn merge_exact_list<T: Clone + Eq + Hash>(
    current_add: &mut Vec<T>,
    current_remove: &mut Vec<T>,
    new_add: Vec<T>,
    new_remove: Vec<T>,
) {
    retain_without(current_add, &new_remove);
    retain_without(current_remove, &new_add);
    current_add.extend(new_add);
    current_remove.extend(new_remove);
}

fn retain_without<T: Clone + Eq + Hash>(items: &mut Vec<T>, remove: &[T]) {
    if items.is_empty() || remove.is_empty() {
        return;
    }
    if use_exact_list_set(items.len(), remove.len()) {
        let remove_set: HashSet<T> = remove.iter().cloned().collect();
        items.retain(|existing| !remove_set.contains(existing));
    } else {
        items.retain(|existing| !remove.contains(existing));
    }
}

fn use_exact_list_set(left_len: usize, right_len: usize) -> bool {
    left_len > 4 && right_len > 4 && left_len.saturating_mul(right_len) > EXACT_LIST_SET_THRESHOLD
}

/// Merge add/remove lists where values have logical equivalence and later policy wins.
fn merge_equivalent_list<T: Copy>(
    current_add: &mut Vec<T>,
    current_remove: &mut Vec<T>,
    new_add: Vec<T>,
    new_remove: Vec<T>,
    equivalent: impl Fn(T, T) -> bool,
) {
    for item in &new_remove {
        current_add.retain(|existing| !equivalent(*existing, *item));
    }
    for item in &new_add {
        current_remove.retain(|existing| !equivalent(*existing, *item));
    }
    current_add.extend(new_add);
    current_remove.extend(new_remove);
}

/// A match criterion for community values (standard, extended, or large).
///
/// Extended community matching is encoding-agnostic: a 2-octet AS RT,
/// 4-octet AS RT, and IPv4-specific RT with the same decoded
/// `(global, local)` all match the same `CommunityMatch::RouteTarget`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityMatch {
    /// Match Route Target (sub-type 0x02) — extended community.
    RouteTarget {
        /// Global administrator (ASN).
        global: u32,
        /// Local administrator (assigned number).
        local: u32,
    },
    /// Match Route Origin (sub-type 0x03) — extended community.
    RouteOrigin {
        /// Global administrator (ASN).
        global: u32,
        /// Local administrator (assigned number).
        local: u32,
    },
    /// Match a standard community (RFC 1997) — raw u32 value.
    Standard {
        /// Community value (high 16 bits = ASN, low 16 bits = local).
        value: u32,
    },
    /// Match a large community (RFC 8092).
    LargeCommunity {
        /// Global administrator (4-byte ASN).
        global_admin: u32,
        /// First local data part.
        local_data1: u32,
        /// Second local data part.
        local_data2: u32,
    },
}

impl CommunityMatch {
    /// Check whether a single [`ExtendedCommunity`] matches this criterion.
    #[must_use]
    pub fn matches_ec(&self, ec: &ExtendedCommunity) -> bool {
        match self {
            CommunityMatch::RouteTarget { global, local } => {
                ec.route_target() == Some((*global, *local))
            }
            CommunityMatch::RouteOrigin { global, local } => {
                ec.route_origin() == Some((*global, *local))
            }
            CommunityMatch::Standard { .. } | CommunityMatch::LargeCommunity { .. } => false,
        }
    }

    /// Check whether a single standard community (u32) matches this criterion.
    #[must_use]
    pub fn matches_standard(&self, community: u32) -> bool {
        match self {
            CommunityMatch::Standard { value } => *value == community,
            _ => false,
        }
    }

    /// Check whether a single [`LargeCommunity`] matches this criterion.
    #[must_use]
    pub fn matches_large(&self, lc: &rustbgpd_wire::LargeCommunity) -> bool {
        match self {
            CommunityMatch::LargeCommunity {
                global_admin,
                local_data1,
                local_data2,
            } => {
                lc.global_admin == *global_admin
                    && lc.local_data1 == *local_data1
                    && lc.local_data2 == *local_data2
            }
            _ => false,
        }
    }

    #[inline]
    pub(crate) fn matches_route_communities(&self, ctx: &RouteContext<'_>) -> bool {
        match self {
            CommunityMatch::RouteTarget { .. } | CommunityMatch::RouteOrigin { .. } => ctx
                .extended_communities
                .iter()
                .any(|ec| self.matches_ec(ec)),
            CommunityMatch::Standard { value } => ctx.communities.contains(value),
            CommunityMatch::LargeCommunity { .. } => ctx
                .large_communities
                .iter()
                .any(|lc| self.matches_large(lc)),
        }
    }
}

/// Parse a community match string.
///
/// Supported formats:
/// - Extended community: `"RT:65001:100"` or `"RO:192.0.2.1:200"`
/// - Standard community: `"65001:100"` (`{ASN}:{value}`, both u16)
/// - Large community: `"LC:65001:100:200"` (`LC:{global}:{local1}:{local2}`)
/// - Well-known names: `"NO_EXPORT"`, `"NO_ADVERTISE"`, `"NO_EXPORT_SUBCONFED"`,
///   `"BLACKHOLE"` (RFC 7999 §5, `0xFFFF_029A`), `"GRACEFUL_SHUTDOWN"`
///   (RFC 8326 §3, `0xFFFF_0000`)
///
/// # Errors
///
/// Returns an error if the string cannot be parsed as any of the above formats.
pub fn parse_community_match(s: &str) -> Result<CommunityMatch, String> {
    if let Some(value) = well_known_community_value(s) {
        return Ok(CommunityMatch::Standard { value });
    }

    // Check for LC: prefix first (4 parts with LC: prefix)
    if let Some(rest) = s.strip_prefix("LC:") {
        let parts: Vec<&str> = rest.splitn(3, ':').collect();
        if parts.len() != 3 {
            return Err(format!(
                "invalid large community {s:?}: expected LC:global:local1:local2"
            ));
        }
        let global_admin: u32 = parts[0]
            .parse()
            .map_err(|_| format!("invalid global_admin {:?} in large community", parts[0]))?;
        let local_data1: u32 = parts[1]
            .parse()
            .map_err(|_| format!("invalid local_data1 {:?} in large community", parts[1]))?;
        let local_data2: u32 = parts[2]
            .parse()
            .map_err(|_| format!("invalid local_data2 {:?} in large community", parts[2]))?;
        return Ok(CommunityMatch::LargeCommunity {
            global_admin,
            local_data1,
            local_data2,
        });
    }

    // Use splitn(3, ':') so that IPv4 addresses (containing dots, not colons)
    // work correctly: "RT:192.0.2.1:100" → ["RT", "192.0.2.1", "100"]
    let parts: Vec<&str> = s.splitn(3, ':').collect();

    match parts.len() {
        // Standard community: "ASN:VALUE" (both u16)
        2 => {
            let asn: u16 = parts[0].parse().map_err(|_| {
                format!(
                    "invalid ASN {:?} in standard community: expected u16",
                    parts[0]
                )
            })?;
            let val: u16 = parts[1].parse().map_err(|_| {
                format!(
                    "invalid value {:?} in standard community: expected u16",
                    parts[1]
                )
            })?;
            Ok(CommunityMatch::Standard {
                value: (u32::from(asn) << 16) | u32::from(val),
            })
        }
        // Extended community: "TYPE:GLOBAL:LOCAL"
        3 => {
            let (global, local_must_fit_u16): (u32, bool) = if let Ok(asn) = parts[1].parse::<u32>()
            {
                (asn, asn > u32::from(u16::MAX))
            } else if let Ok(ipv4) = parts[1].parse::<Ipv4Addr>() {
                (u32::from(ipv4), true)
            } else {
                return Err(format!(
                    "invalid global admin {:?}: expected ASN (u32) or IPv4 address",
                    parts[1]
                ));
            };

            let local: u32 = parts[2]
                .parse()
                .map_err(|_| format!("invalid local admin {:?}: expected u32", parts[2]))?;

            if local_must_fit_u16 && local > u32::from(u16::MAX) {
                return Err(format!(
                    "invalid local admin {local:?}: exceeds 65535 for IPv4-specific or 4-octet-AS RT/RO"
                ));
            }

            match parts[0] {
                "RT" => Ok(CommunityMatch::RouteTarget { global, local }),
                "RO" => Ok(CommunityMatch::RouteOrigin { global, local }),
                other => Err(format!(
                    "unknown community type {other:?}, expected \"RT\" or \"RO\""
                )),
            }
        }
        _ => Err(format!(
            "expected ASN:VALUE, TYPE:GLOBAL:LOCAL, LC:G:L1:L2, or well-known name, got {s:?}"
        )),
    }
}

/// Resolve well-known standard community aliases.
///
/// The same alias surface is used by `parse_community_values` for the policy
/// *set* side (`set_community_add` / `set_community_remove`), so operators can
/// write aliases in either match or set positions without repeating numeric
/// values.
fn well_known_community_value(s: &str) -> Option<u32> {
    match s {
        "NO_EXPORT" => Some(rustbgpd_wire::COMMUNITY_NO_EXPORT),
        "NO_ADVERTISE" => Some(rustbgpd_wire::COMMUNITY_NO_ADVERTISE),
        "NO_EXPORT_SUBCONFED" => Some(rustbgpd_wire::COMMUNITY_NO_EXPORT_SUBCONFED),
        "BLACKHOLE" => Some(rustbgpd_wire::COMMUNITY_BLACKHOLE),
        "GRACEFUL_SHUTDOWN" => Some(rustbgpd_wire::COMMUNITY_GRACEFUL_SHUTDOWN),
        _ => None,
    }
}

/// Compiled `AS_PATH` regular expression for policy matching.
///
/// Supports Cisco/Quagga-style `_` as a boundary anchor that matches
/// start of string, end of string, or a space.
#[derive(Clone)]
pub struct AsPathRegex {
    regex: Regex,
    pattern: String,
}

impl AsPathRegex {
    /// Compile an `AS_PATH` regex pattern.
    ///
    /// The `_` character is expanded to `(?:^| |$|[{}])` before compilation,
    /// matching the Cisco/Quagga convention where `_` denotes an AS boundary.
    /// The `{`/`}` alternatives match `AS_SET` delimiters in the string
    /// representation (e.g. `"65001 {65002 65003}"`).
    ///
    /// # Errors
    ///
    /// Returns an error if the resulting regex is invalid.
    pub fn new(pattern: &str) -> Result<Self, String> {
        let expanded = pattern.replace('_', "(?:^| |$|[{}])");
        let regex =
            Regex::new(&expanded).map_err(|e| format!("invalid AS_PATH regex {pattern:?}: {e}"))?;
        Ok(Self {
            regex,
            pattern: pattern.to_string(),
        })
    }

    /// Check whether an `AS_PATH` string matches this regex.
    #[must_use]
    pub fn is_match(&self, aspath_str: &str) -> bool {
        self.regex.is_match(aspath_str)
    }

    /// The pattern as configured (before `_` boundary expansion).
    /// Explain surfaces render this back to the operator.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

impl PartialEq for AsPathRegex {
    fn eq(&self, other: &Self) -> bool {
        self.pattern == other.pattern
    }
}

impl Eq for AsPathRegex {}

impl fmt::Debug for AsPathRegex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsPathRegex")
            .field("pattern", &self.pattern)
            .finish_non_exhaustive()
    }
}

/// A single policy statement (match conditions + action + modifications).
///
/// Entries can match on prefix, next-hop, community, `AS_PATH` regex, or combinations.
/// When multiple conditions are specified, all must be true (AND).
/// Within community matching, any match suffices (OR).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStatement {
    /// Prefix to match. If `None`, the entry matches any prefix.
    pub prefix: Option<Prefix>,
    /// Minimum prefix length (inclusive).
    pub ge: Option<u8>,
    /// Maximum prefix length (inclusive).
    pub le: Option<u8>,
    /// Action to take when all conditions match.
    pub action: PolicyAction,
    /// Community match criteria (OR within the list).
    pub match_community: Vec<CommunityMatch>,
    /// `AS_PATH` regex match criterion.
    pub match_as_path: Option<AsPathRegex>,
    /// Evaluation peer neighbor-set match criterion.
    pub match_neighbor_set: Option<NeighborSetMatch>,
    /// Route source type match criterion.
    pub match_route_type: Option<RouteType>,
    /// EVPN route type (RFC 7432 §7 / RFC 9136) match criterion. Only
    /// matches EVPN NLRIs; non-EVPN routes are filtered out when this
    /// is set. Operators previously had to filter EVPN by RT or
    /// community match; this is the route-type-keyed shortcut.
    pub match_evpn_route_type: Option<u8>,
    /// RPKI validation state match criterion (RFC 6811).
    pub match_rpki_validation: Option<RpkiValidation>,
    /// ASPA path verification state match criterion.
    pub match_aspa_validation: Option<AspaValidation>,
    /// Minimum `AS_PATH` length (inclusive) to match.
    pub match_as_path_length_ge: Option<u32>,
    /// Maximum `AS_PATH` length (inclusive) to match.
    pub match_as_path_length_le: Option<u32>,
    /// Minimum `LOCAL_PREF` attribute value (inclusive) to match.
    pub match_local_pref_ge: Option<u32>,
    /// Maximum `LOCAL_PREF` attribute value (inclusive) to match.
    pub match_local_pref_le: Option<u32>,
    /// Minimum MED attribute value (inclusive) to match.
    pub match_med_ge: Option<u32>,
    /// Maximum MED attribute value (inclusive) to match.
    pub match_med_le: Option<u32>,
    /// Exact next-hop address to match.
    pub match_next_hop: Option<IpAddr>,
    /// Route modifications to apply when this statement matches.
    pub modifications: RouteModifications,
}

impl PolicyStatement {
    /// Check whether a route matches this statement.
    fn matches(&self, ctx: &RouteContext<'_>) -> bool {
        // A statement matches when every configured predicate matches (logical
        // AND). The checks are pure, side-effect-free reads, so evaluation order
        // does not change the result — only the cost. We evaluate cheapest-first
        // with early returns so that a cheap match failure skips the expensive
        // community scan and AS_PATH regex entirely. Ordering tiers (cheap →
        // expensive): O(1) scalar comparisons, then prefix masking, then the
        // neighbor-set, then the community scan, then the AS_PATH regex last.

        // --- Tier 1: O(1) scalar comparisons (near-free when the field is unset).
        if let Some(route_type) = self.match_route_type
            && ctx.route_type != Some(route_type)
        {
            return false;
        }
        if let Some(expected) = self.match_evpn_route_type
            && ctx.evpn_route_type != Some(expected)
        {
            return false;
        }
        if let Some(expected) = self.match_rpki_validation
            && expected != ctx.validation_state
        {
            return false;
        }
        if let Some(expected) = self.match_aspa_validation
            && expected != ctx.aspa_state
        {
            return false;
        }
        if let Some(v) = self.match_as_path_length_ge
            && ctx.as_path_len < v as usize
        {
            return false;
        }
        if let Some(v) = self.match_as_path_length_le
            && ctx.as_path_len > v as usize
        {
            return false;
        }

        // RFC 4271: when LOCAL_PREF is absent (e.g. an eBGP-received route with
        // no LOCAL_PREF on the wire), the implicit value for best-path purposes
        // is 100. RFC 4271 §5.1.5 doesn't mandate the same default for policy
        // *matching* — it leaves the question implementation-defined — but FRR /
        // BIRD / GoBGP all use the implicit default in their match semantics so
        // an operator's `match local-preference >= 100` works against routes the
        // engine itself treats as having LP=100. Matching that convention here
        // means a single policy reads identically against routes that arrive
        // with an explicit LOCAL_PREF (iBGP) and routes that don't (eBGP) — the
        // previous behavior silently failed to match eBGP routes against any LP
        // threshold.
        let candidate_local_pref = ctx.local_pref.unwrap_or(IMPLICIT_LOCAL_PREF);
        if let Some(v) = self.match_local_pref_ge
            && candidate_local_pref < v
        {
            return false;
        }
        if let Some(v) = self.match_local_pref_le
            && candidate_local_pref > v
        {
            return false;
        }

        // RFC 4271 §5.1.4: MED defaults to 0 when absent.
        let candidate_med = ctx.med.unwrap_or(IMPLICIT_MED);
        if let Some(v) = self.match_med_ge
            && candidate_med < v
        {
            return false;
        }
        if let Some(v) = self.match_med_le
            && candidate_med > v
        {
            return false;
        }

        if let Some(next_hop) = self.match_next_hop
            && ctx.next_hop != Some(next_hop)
        {
            return false;
        }

        // --- Tier 2: prefix match (O(1) masking; cheap and usually selective).
        if let Some(p) = self.prefix
            && !ctx
                .prefix
                .is_some_and(|candidate| self.matches_prefix(p, candidate))
        {
            return false;
        }

        // --- Tier 3: neighbor-set (peer address/ASN/group; O(1)-ish for a small
        // configured set).
        if let Some(set) = self.match_neighbor_set.as_ref()
            && !set.matches(ctx.peer_address, ctx.peer_asn, ctx.peer_group)
        {
            return false;
        }

        // --- Tier 4: community scan. Dispatch by criterion type so a standard
        // match never scans extended or large communities, and vice versa.
        if !self.match_community.is_empty() {
            let community_ok = self
                .match_community
                .iter()
                .any(|cm| cm.matches_route_communities(ctx));
            if !community_ok {
                return false;
            }
        }

        // --- Tier 5: AS_PATH regex (most expensive). Evaluated last.
        if let Some(regex) = self.match_as_path.as_ref()
            && !regex.is_match(ctx.as_path_str)
        {
            return false;
        }

        true
    }

    fn matches_prefix(&self, entry_prefix: Prefix, candidate: Prefix) -> bool {
        // Single scalar implementation shared with the IR evaluator's
        // `PrefixEq` node and the indexed `PrefixSet`.
        crate::sets::prefix_entry_matches(entry_prefix, self.ge, self.le, candidate)
    }
}

/// An ordered list of policy statements with a default action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Ordered list of statements; first match wins.
    pub entries: Vec<PolicyStatement>,
    /// Action when no statement matches.
    pub default_action: PolicyAction,
}

impl Policy {
    /// Evaluate a route against this policy. First matching entry wins.
    #[must_use]
    pub fn evaluate(&self, ctx: &RouteContext<'_>) -> PolicyResult {
        for entry in &self.entries {
            if entry.matches(ctx) {
                return match entry.action {
                    PolicyAction::Permit => PolicyResult {
                        action: PolicyAction::Permit,
                        modifications: entry.modifications.clone(),
                    },
                    PolicyAction::Deny => PolicyResult::deny(),
                };
            }
        }
        PolicyResult {
            action: self.default_action,
            modifications: RouteModifications::default(),
        }
    }
}

/// Convenience: evaluate an optional policy. Returns `Permit` with no modifications if no policy.
#[must_use]
pub fn evaluate_policy(policy: Option<&Policy>, ctx: &RouteContext<'_>) -> PolicyResult {
    match policy {
        Some(p) => p.evaluate(ctx),
        None => PolicyResult::permit(),
    }
}

/// A `Policy` carried alongside its optional configured name.
///
/// The name lives at the chain level — not on `Policy` itself — so the
/// dozens of test-only constructors that build bare `Policy` values
/// (most of `crates/policy/src/engine/tests/`) don't churn. The chain
/// is the only place a policy gets a stable identity, which matches how
/// names enter the system (via `resolve_chain` in `src/config/parse.rs`,
/// which already has the name in hand at the moment it builds each
/// `Policy`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedPolicy {
    /// Configured policy name (`None` for inline / anonymous policies).
    pub name: Option<String>,
    /// The policy itself. For an `.rpol`-backed member (`rpol` is
    /// `Some`) this is an empty placeholder — the chain compiler
    /// splices the pre-compiled body instead of reading `entries`.
    pub policy: Policy,
    /// Pre-compiled `.rpol` body (ADR-0096): a single-policy
    /// [`CompiledChain`] plus the set tables its guards reference,
    /// produced by the config resolver. `None` for TOML policies.
    ///
    /// Participates in `PartialEq`, so chain identity — what the
    /// ADR-0076 planner diffs — is the *compiled content*: two loads
    /// of the same `.rpol` source compare equal, an edited file
    /// compares unequal.
    pub rpol: Option<Arc<CompiledChain>>,
}

impl NamedPolicy {
    /// An `.rpol`-backed chain member: `compiled` must be a
    /// single-policy chain from `RpolFile::compile_policy`.
    #[must_use]
    pub fn from_rpol(name: String, compiled: Arc<CompiledChain>) -> Self {
        Self {
            name: Some(name),
            policy: Policy {
                entries: Vec::new(),
                default_action: PolicyAction::Permit,
            },
            rpol: Some(compiled),
        }
    }
}

impl From<Policy> for NamedPolicy {
    fn from(policy: Policy) -> Self {
        Self {
            name: None,
            policy,
            rpol: None,
        }
    }
}

// Deref to Policy is a pragmatic shortcut: many existing tests read
// `chain.policies[i].entries` / `.default_action` directly. Keeping
// those working transparently is worth the Deref-on-not-a-smart-pointer
// idiom — the alternative is a mechanical sweep across ~30 test sites
// that adds no signal. The wrapper has exactly one field that matters
// (`policy`), so the deref target is unambiguous.
impl std::ops::Deref for NamedPolicy {
    type Target = Policy;
    fn deref(&self) -> &Self::Target {
        &self.policy
    }
}

/// Per-route policy evaluation outcome with attribution to the
/// terminal-decision policy. Produced by
/// [`PolicyChain::evaluate_with_attribution`] alongside the existing
/// [`PolicyResult`] so the rich path doesn't churn the many sites that
/// match on `PolicyResult` directly.
///
/// `matched_policy` is the name of the policy that **terminated** chain
/// evaluation:
/// - For a Deny: the policy that issued the Deny (chain stops there).
/// - For a Permit (all policies permitted): the last policy in the
///   chain, since chain evaluation completes only after every policy
///   has permitted. With one named policy in the chain that's the named
///   one; with an empty chain it's `None`.
/// - For chains where the terminal policy is inline / anonymous, it's
///   `None` — the operator can read `"inline"` as the metric label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyEvaluation {
    /// The terminal action — `Permit` or `Deny`.
    pub action: PolicyAction,
    /// Configured name of the terminal-decision policy, if it has one.
    pub matched_policy: Option<String>,
}

/// An ordered sequence of policies evaluated in chain.
///
/// GoBGP-style semantics: each policy is evaluated in order. If a policy
/// returns `Permit`, its modifications are accumulated and evaluation
/// continues to the next policy. If a policy returns `Deny`, the route
/// is rejected immediately. After all policies, the route is permitted
/// with the accumulated modifications.
#[derive(Default)]
pub struct PolicyChain {
    /// Policies evaluated in order; modifications accumulate across permits.
    pub policies: Vec<NamedPolicy>,
    /// Lazily-compiled IR (ADR-0096), built on first evaluation and
    /// reused for every route thereafter. Deliberately excluded from
    /// `PartialEq`/`Clone`/`Debug`: chain identity is the configured
    /// `policies` (the ADR-0076 planner diffs chains structurally),
    /// and the cache is derived state. Invariant: `policies` must not
    /// be mutated after the first evaluation — config construction
    /// finishes all mutation (including the implicit gshut/blackhole
    /// appends) before a chain ever sees a route. `Arc` so
    /// [`share`](Self::share) handles reuse one compiled IR.
    compiled: OnceLock<Arc<CompiledChain>>,
    /// Live per-term guard-hit counters (ADR-0096 Decision 3.3),
    /// created lazily alongside the compiled IR and bumped by every
    /// [`evaluate_with_attribution`](Self::evaluate_with_attribution).
    /// Derived state like `compiled` (excluded from
    /// `PartialEq`/`Clone`/`Debug`); a cloned or replaced chain starts
    /// from zero — stats read as "since this chain instance was
    /// installed".
    hits: OnceLock<Arc<PolicyHitCounters>>,
}

impl Clone for PolicyChain {
    fn clone(&self) -> Self {
        // The clone gets a fresh cache: cloning is a construction-time
        // operation (config resolve, per-session distribution), and a
        // shared cache would leak stale IR into clones whose
        // `policies` are still being edited.
        Self {
            policies: self.policies.clone(),
            compiled: OnceLock::new(),
            hits: OnceLock::new(),
        }
    }
}

impl PartialEq for PolicyChain {
    fn eq(&self, other: &Self) -> bool {
        self.policies == other.policies
    }
}

impl Eq for PolicyChain {}

#[expect(
    clippy::missing_fields_in_debug,
    reason = "the compiled-IR cache is derived state, not chain identity"
)]
impl fmt::Debug for PolicyChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PolicyChain")
            .field("policies", &self.policies)
            .finish()
    }
}

impl PolicyChain {
    /// Create a chain from an ordered list of (unnamed) policies. Each
    /// becomes a `NamedPolicy` with `name = None`. Callers that have
    /// names in hand (the config resolver) build `NamedPolicy` values
    /// directly and assign to `policies`.
    #[must_use]
    pub fn new(policies: Vec<Policy>) -> Self {
        Self {
            policies: policies.into_iter().map(NamedPolicy::from).collect(),
            compiled: OnceLock::new(),
            hits: OnceLock::new(),
        }
    }

    /// Create a chain from a list of already-named policies.
    #[must_use]
    pub fn from_named(policies: Vec<NamedPolicy>) -> Self {
        Self {
            policies,
            compiled: OnceLock::new(),
            hits: OnceLock::new(),
        }
    }

    /// The compiled IR backing this chain (ADR-0096), compiled on
    /// first use. Each chain compiles through its own private
    /// [`SetStore`], so sets dedupe across the chain's policies;
    /// cross-chain sharing arrives when the config resolver compiles
    /// eagerly through one store (a later ADR-0096 slice —
    /// `crate::compile::compile_chain` already takes the store).
    #[must_use]
    pub fn compiled(&self) -> &CompiledChain {
        // Behind a pointer so an uncompiled chain stays pointer-sized —
        // chains are embedded in config/session structs (and api event
        // enums) that mostly never evaluate routes themselves.
        self.compiled
            .get_or_init(|| Arc::new(crate::compile::compile_chain(self, &mut SetStore::new())))
    }

    /// A shallow evaluation handle onto an **installed** chain: shares
    /// this chain's compiled IR and live hit counters instead of
    /// resetting them the way [`Clone`] does. For read-only borrow
    /// splitting (the RIB distribution passes clone the installed
    /// chain to release a `&self` borrow): evaluations through the
    /// handle land in the same counters, and the IR compiles once per
    /// install instead of once per pass. Not for chains still under
    /// construction — that is exactly what `Clone`'s fresh-cache
    /// semantics exist for.
    #[must_use]
    pub fn share(&self) -> Self {
        // `hit_counters()` materializes the compiled IR too.
        let hits = Arc::clone(self.hit_counters());
        Self {
            policies: self.policies.clone(),
            compiled: self
                .compiled
                .get()
                .map(Arc::clone)
                .map_or_else(OnceLock::new, OnceLock::from),
            hits: OnceLock::from(hits),
        }
    }

    /// Whether evaluating this chain needs the rendered `AS_PATH` string.
    ///
    /// True iff some statement carries an `AS_PATH` **regex** criterion
    /// (`match_as_path`) — that is the only consumer of
    /// `RouteContext.as_path_str`. `match_as_path_length_*` uses the cheap
    /// `as_path_len` count instead, so it does not count here. Export callers
    /// use this to skip building the string when no policy needs it; the string
    /// is otherwise allocated per (route × peer) for nothing.
    #[must_use]
    pub fn requires_as_path_string(&self) -> bool {
        self.compiled().requires_as_path_string()
    }

    /// Whether evaluating this chain depends on RPKI origin-validation state.
    ///
    /// Import-policy callers use this to decide whether a later VRP cache
    /// update must trigger Route Refresh for this peer. Chains that do not
    /// match on validation state are unaffected by cache churn and should not
    /// be refreshed.
    #[must_use]
    pub fn requires_rpki_validation(&self) -> bool {
        self.compiled().requires_rpki_validation()
    }

    /// Whether evaluating this chain depends on ASPA path-validation state.
    #[must_use]
    pub fn requires_aspa_validation(&self) -> bool {
        self.compiled().requires_aspa_validation()
    }

    /// Whether evaluating this chain depends on any external validation cache.
    #[must_use]
    pub fn requires_validation_state(&self) -> bool {
        self.requires_rpki_validation() || self.requires_aspa_validation()
    }

    /// Evaluate a route against this chain of policies.
    #[must_use]
    pub fn evaluate(&self, ctx: &RouteContext<'_>) -> PolicyResult {
        self.evaluate_with_attribution(ctx).0
    }

    /// Evaluate plus attribution — for telemetry / explain surfaces
    /// that need to label "which policy made this decision."
    ///
    /// Returns the same `PolicyResult` as [`evaluate`](Self::evaluate)
    /// plus a `PolicyEvaluation` carrying the terminal-decision
    /// policy's name (`None` for inline / anonymous, or for an empty
    /// chain). The action on the `PolicyEvaluation` matches the
    /// `PolicyResult.action`.
    #[must_use]
    pub fn evaluate_with_attribution(
        &self,
        ctx: &RouteContext<'_>,
    ) -> (PolicyResult, PolicyEvaluation) {
        self.compiled()
            .evaluate_with_attribution_counting(ctx, self.hit_counters())
    }

    /// The chain's live per-term hit counters (ADR-0096 Decision 3.3),
    /// shaped like [`compiled`](Self::compiled) and bumped on every
    /// evaluation. `Arc`-shared so a stats reader can snapshot without
    /// borrowing the chain.
    #[must_use]
    pub fn hit_counters(&self) -> &Arc<PolicyHitCounters> {
        self.hits
            .get_or_init(|| Arc::new(PolicyHitCounters::for_chain(self.compiled())))
    }

    /// Snapshot the per-term hit counters as labeled rows for the
    /// policy-stats surface, in chain walk order.
    #[must_use]
    pub fn term_hit_rows(&self) -> Vec<TermHitRow> {
        let compiled = self.compiled();
        let grid = self.hit_counters().snapshot();
        let mut rows = Vec::new();
        for (policy_index, (policy, hits)) in compiled.policies.iter().zip(&grid).enumerate() {
            for (term_index, (term, hits)) in policy.terms.iter().zip(hits).enumerate() {
                rows.push(TermHitRow {
                    policy_index,
                    policy: policy.name.clone(),
                    term_index,
                    term: term.name.clone(),
                    hits: *hits,
                });
            }
        }
        rows
    }

    /// The pre-IR chain walker, kept intact as the oracle for the
    /// golden decision-compatibility corpus
    /// (`engine/tests/ir_parity.rs`) and the `set_heavy` benchmark
    /// contrast. Not public API; deleted in a later ADR-0096 slice
    /// once the corpus has soaked.
    #[doc(hidden)]
    #[must_use]
    pub fn evaluate_with_attribution_legacy(
        &self,
        ctx: &RouteContext<'_>,
    ) -> (PolicyResult, PolicyEvaluation) {
        let mut accumulated = RouteModifications::default();
        for named in &self.policies {
            let result = named.policy.evaluate(ctx);
            match result.action {
                PolicyAction::Deny => {
                    return (
                        PolicyResult::deny(),
                        PolicyEvaluation {
                            action: PolicyAction::Deny,
                            matched_policy: named.name.clone(),
                        },
                    );
                }
                PolicyAction::Permit => accumulated.merge_from(result.modifications),
            }
        }
        // All policies permitted (including an empty chain). Attribute
        // to the last policy in the chain since chain evaluation
        // completes only after every policy permits.
        let matched_policy = self.policies.last().and_then(|n| n.name.clone());
        (
            PolicyResult {
                action: PolicyAction::Permit,
                modifications: accumulated,
            },
            PolicyEvaluation {
                action: PolicyAction::Permit,
                matched_policy,
            },
        )
    }
}

/// One row of the policy-stats surface: a term's live guard-hit count
/// with its naming context (see [`PolicyChain::term_hit_rows`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TermHitRow {
    /// 0-based position of the policy within the chain.
    pub policy_index: usize,
    /// Chain-member name (`None` = inline / anonymous).
    pub policy: Option<String>,
    /// 0-based term index within the policy.
    pub term_index: usize,
    /// `.rpol` term name; `None` for TOML statements.
    pub term: Option<String>,
    /// Times this term's guard matched since chain install.
    pub hits: u64,
}

/// Convenience: evaluate an optional policy chain. Returns `Permit` with no modifications if no chain.
#[must_use]
pub fn evaluate_chain(chain: Option<&PolicyChain>, ctx: &RouteContext<'_>) -> PolicyResult {
    match chain {
        Some(c) => c.evaluate(ctx),
        None => PolicyResult::permit(),
    }
}

/// Convenience: evaluate an optional chain with attribution. Returns
/// `(Permit, no-name)` if there's no chain — the operator-visible
/// "no policy is configured on this peer" case.
#[must_use]
pub fn evaluate_chain_with_attribution(
    chain: Option<&PolicyChain>,
    ctx: &RouteContext<'_>,
) -> (PolicyResult, PolicyEvaluation) {
    match chain {
        Some(c) => c.evaluate_with_attribution(ctx),
        None => (
            PolicyResult::permit(),
            PolicyEvaluation {
                action: PolicyAction::Permit,
                matched_policy: None,
            },
        ),
    }
}

/// Apply route modifications to a mutable attribute list.
///
/// Modifications are applied in a fixed order:
/// 1. `set_local_pref` — replace or add `LocalPref`
/// 2. `set_med` — replace or add `Med`
/// 3. `communities_add/remove` — modify `Communities`
/// 4. `extended_communities_add/remove` — modify `ExtendedCommunities`
/// 5. `large_communities_add/remove` — modify `LargeCommunities`
/// 6. `as_path_prepend` — prepend to the first `AS_SEQUENCE` or create one
///
/// Returns `Some(NextHopAction)` if the caller should rewrite the next-hop.
pub fn apply_modifications(
    attrs: &mut Vec<rustbgpd_wire::PathAttribute>,
    mods: &RouteModifications,
) -> Option<NextHopAction> {
    // 1. LOCAL_PREF
    if let Some(lp) = mods.set_local_pref {
        upsert_attr(
            attrs,
            |a| matches!(a, PathAttribute::LocalPref(_)),
            PathAttribute::LocalPref(lp),
        );
    }

    // 2. MED
    if let Some(med) = mods.set_med {
        upsert_attr(
            attrs,
            |a| matches!(a, PathAttribute::Med(_)),
            PathAttribute::Med(med),
        );
    }

    // 3. Standard communities
    apply_community_mods(
        attrs,
        &mods.communities_add,
        &mods.communities_remove,
        |a| match a {
            PathAttribute::Communities(c) => Some(c),
            _ => None,
        },
        |a| matches!(a, PathAttribute::Communities(_)),
        PathAttribute::Communities,
    );

    // 4. Extended communities
    apply_extended_community_mods(
        attrs,
        &mods.extended_communities_add,
        &mods.extended_communities_remove,
    );

    // 5. Large communities
    apply_community_mods(
        attrs,
        &mods.large_communities_add,
        &mods.large_communities_remove,
        |a| match a {
            PathAttribute::LargeCommunities(c) => Some(c),
            _ => None,
        },
        |a| matches!(a, PathAttribute::LargeCommunities(_)),
        PathAttribute::LargeCommunities,
    );

    // 6. AS_PATH prepend
    if let Some((asn, count)) = mods.as_path_prepend {
        apply_as_path_prepend(attrs, asn, count);
    }

    // 7. Next-hop: for Specific(IPv4), update PathAttribute::NextHop directly
    if let Some(NextHopAction::Specific(IpAddr::V4(v4))) = mods.set_next_hop {
        upsert_attr(
            attrs,
            |a| matches!(a, PathAttribute::NextHop(_)),
            PathAttribute::NextHop(v4),
        );
    }

    mods.set_next_hop.clone()
}

/// Replace or insert a single-valued attribute.
fn upsert_attr(
    attrs: &mut Vec<PathAttribute>,
    predicate: impl Fn(&PathAttribute) -> bool,
    new_attr: PathAttribute,
) {
    if let Some(existing) = attrs.iter_mut().find(|a| predicate(a)) {
        *existing = new_attr;
    } else {
        attrs.push(new_attr);
    }
}

/// Add/remove community-style attributes (standard, extended, large).
fn apply_community_mods<T: Clone + Eq + Hash>(
    attrs: &mut Vec<PathAttribute>,
    add: &[T],
    remove: &[T],
    extract: impl Fn(PathAttribute) -> Option<Vec<T>>,
    predicate: impl Fn(&PathAttribute) -> bool,
    wrap: impl Fn(Vec<T>) -> PathAttribute,
) {
    if add.is_empty() && remove.is_empty() {
        return;
    }

    let mut items = Vec::new();
    let mut found = false;
    let mut index = 0;
    while index < attrs.len() {
        if predicate(&attrs[index]) {
            let attr = attrs.remove(index);
            if !found {
                items = extract(attr).expect("community attribute predicate and extractor agree");
                found = true;
            }
        } else {
            index += 1;
        }
    }

    apply_exact_community_delta(&mut items, add, remove);
    if !items.is_empty() {
        attrs.push(wrap(items));
    }
}

fn apply_exact_community_delta<T: Clone + Eq + Hash>(items: &mut Vec<T>, add: &[T], remove: &[T]) {
    retain_without(items, remove);
    if add.is_empty() {
        return;
    }

    if use_exact_list_set(items.len(), add.len()) {
        let mut existing: HashSet<T> = items.iter().cloned().collect();
        for item in add {
            if existing.insert(item.clone()) {
                items.push(item.clone());
            }
        }
    } else {
        for item in add {
            if !items.contains(item) {
                items.push(item.clone());
            }
        }
    }
}

/// Add/remove extended communities using logical RT/RO equivalence.
///
/// Route Target and Route Origin communities are treated encoding-agnostically:
/// a 2-octet AS, 4-octet AS, and IPv4-specific RT/RO with the same decoded
/// `(global, local)` pair are considered the same logical value. Non-RT/RO
/// communities still compare by exact raw bytes.
fn apply_extended_community_mods(
    attrs: &mut Vec<PathAttribute>,
    add: &[ExtendedCommunity],
    remove: &[ExtendedCommunity],
) {
    if add.is_empty() && remove.is_empty() {
        return;
    }

    let mut items: Vec<ExtendedCommunity> = attrs
        .iter()
        .find_map(|a| match a {
            PathAttribute::ExtendedCommunities(c) => Some(c.clone()),
            _ => None,
        })
        .unwrap_or_default();

    items.retain(|ec| {
        !remove
            .iter()
            .any(|target| extended_communities_equivalent(*ec, *target))
    });

    for ec in add {
        if !items
            .iter()
            .any(|existing| extended_communities_equivalent(*existing, *ec))
        {
            items.push(*ec);
        }
    }

    attrs.retain(|a| !matches!(a, PathAttribute::ExtendedCommunities(_)));
    if !items.is_empty() {
        attrs.push(PathAttribute::ExtendedCommunities(items));
    }
}

fn extended_communities_equivalent(a: ExtendedCommunity, b: ExtendedCommunity) -> bool {
    match (a.route_target(), b.route_target()) {
        (Some(x), Some(y)) => x == y,
        _ => match (a.route_origin(), b.route_origin()) {
            (Some(x), Some(y)) => x == y,
            _ => a == b,
        },
    }
}

/// Prepend ASN to `AS_PATH`.
fn apply_as_path_prepend(attrs: &mut Vec<PathAttribute>, asn: u32, count: u8) {
    let prepend: Vec<u32> = vec![asn; count as usize];
    if let Some(existing) = attrs.iter_mut().find_map(|a| match a {
        PathAttribute::AsPath(p) => Some(p),
        _ => None,
    }) {
        if let Some(AsPathSegment::AsSequence(seq)) = existing.segments.first_mut() {
            if u8::try_from(seq.len() + prepend.len()).is_ok() {
                let mut new_seq = prepend;
                new_seq.extend(seq.iter());
                *seq = new_seq;
            } else {
                // Avoid overflowing the on-wire u8 segment length field. Two
                // adjacent AS_SEQUENCE segments are valid and preserve the
                // effective path ordering.
                existing
                    .segments
                    .insert(0, AsPathSegment::AsSequence(prepend));
            }
        } else {
            existing
                .segments
                .insert(0, AsPathSegment::AsSequence(prepend));
        }
    } else {
        attrs.push(PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(prepend)],
        }));
    }
}

/// Statement-level chain attribution for explain surfaces. Explain-only:
/// the live evaluation path never routes through this module.
pub mod explain;

#[cfg(test)]
mod tests;
