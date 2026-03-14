use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use regex::Regex;
use rustbgpd_wire::{
    AsPath, AsPathSegment, AspaValidation, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix,
    LargeCommunity, PathAttribute, Prefix, RpkiValidation,
};

/// Action taken when a prefix matches a policy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    /// Allow the route to pass.
    Permit,
    /// Reject the route.
    Deny,
}

/// The result of evaluating a policy: an action plus any route modifications.
#[derive(Debug, Clone)]
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
    /// The route's NLRI prefix.
    pub prefix: Prefix,
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
    /// ASPA upstream path verification state.
    pub aspa_state: AspaValidation,
    /// Evaluation peer IP address.
    pub peer_address: Option<IpAddr>,
    /// Evaluation peer remote ASN.
    pub peer_asn: Option<u32>,
    /// Evaluation peer-group name.
    pub peer_group: Option<&'a str>,
    /// Route source type.
    pub route_type: Option<RouteType>,
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
#[derive(Debug, Clone, Default)]
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
#[derive(Debug, Clone, Default)]
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
fn merge_exact_list<T: PartialEq>(
    current_add: &mut Vec<T>,
    current_remove: &mut Vec<T>,
    new_add: Vec<T>,
    new_remove: Vec<T>,
) {
    for item in &new_remove {
        current_add.retain(|existing| existing != item);
    }
    for item in &new_add {
        current_remove.retain(|existing| existing != item);
    }
    current_add.extend(new_add);
    current_remove.extend(new_remove);
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
}

/// Parse a community match string.
///
/// Supported formats:
/// - Extended community: `"RT:65001:100"` or `"RO:192.0.2.1:200"`
/// - Standard community: `"65001:100"` (`{ASN}:{value}`, both u16)
/// - Large community: `"LC:65001:100:200"` (`LC:{global}:{local1}:{local2}`)
/// - Well-known names: `"NO_EXPORT"`, `"NO_ADVERTISE"`, `"NO_EXPORT_SUBCONFED"`
///
/// # Errors
///
/// Returns an error if the string cannot be parsed as any of the above formats.
pub fn parse_community_match(s: &str) -> Result<CommunityMatch, String> {
    // Well-known community names (RFC 1997)
    match s {
        "NO_EXPORT" => return Ok(CommunityMatch::Standard { value: 0xFFFF_FF01 }),
        "NO_ADVERTISE" => return Ok(CommunityMatch::Standard { value: 0xFFFF_FF02 }),
        "NO_EXPORT_SUBCONFED" => return Ok(CommunityMatch::Standard { value: 0xFFFF_FF03 }),
        _ => {}
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
}

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
#[derive(Debug, Clone)]
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
        let prefix_ok = match self.prefix {
            Some(p) => self.matches_prefix(p, ctx.prefix),
            None => true,
        };

        let community_ok = if self.match_community.is_empty() {
            true
        } else {
            self.match_community.iter().any(|cm| {
                ctx.extended_communities.iter().any(|ec| cm.matches_ec(ec))
                    || ctx.communities.iter().any(|c| cm.matches_standard(*c))
                    || ctx.large_communities.iter().any(|lc| cm.matches_large(lc))
            })
        };

        let aspath_ok = match &self.match_as_path {
            Some(regex) => regex.is_match(ctx.as_path_str),
            None => true,
        };

        let neighbor_set_ok = self
            .match_neighbor_set
            .as_ref()
            .is_none_or(|set| set.matches(ctx.peer_address, ctx.peer_asn, ctx.peer_group));

        let route_type_ok = self.match_route_type.is_none_or(|route_type| {
            ctx.route_type
                .is_some_and(|candidate| candidate == route_type)
        });

        let rpki_ok = self
            .match_rpki_validation
            .is_none_or(|v| v == ctx.validation_state);

        let aspa_ok = self
            .match_aspa_validation
            .is_none_or(|v| v == ctx.aspa_state);

        let aspath_len_ok = self
            .match_as_path_length_ge
            .is_none_or(|v| ctx.as_path_len >= v as usize)
            && self
                .match_as_path_length_le
                .is_none_or(|v| ctx.as_path_len <= v as usize);

        let local_pref_ok = self
            .match_local_pref_ge
            .is_none_or(|v| ctx.local_pref.is_some_and(|candidate| candidate >= v))
            && self
                .match_local_pref_le
                .is_none_or(|v| ctx.local_pref.is_some_and(|candidate| candidate <= v));

        let med_ok = self
            .match_med_ge
            .is_none_or(|v| ctx.med.is_some_and(|candidate| candidate >= v))
            && self
                .match_med_le
                .is_none_or(|v| ctx.med.is_some_and(|candidate| candidate <= v));

        let next_hop_ok = self
            .match_next_hop
            .is_none_or(|next_hop| ctx.next_hop.is_some_and(|candidate| candidate == next_hop));

        prefix_ok
            && community_ok
            && aspath_ok
            && neighbor_set_ok
            && route_type_ok
            && rpki_ok
            && aspa_ok
            && aspath_len_ok
            && local_pref_ok
            && med_ok
            && next_hop_ok
    }

    fn matches_prefix(&self, entry_prefix: Prefix, candidate: Prefix) -> bool {
        match (entry_prefix, candidate) {
            (Prefix::V4(entry), Prefix::V4(cand)) => self.matches_v4(entry, cand),
            (Prefix::V6(entry), Prefix::V6(cand)) => self.matches_v6(entry, cand),
            _ => false,
        }
    }

    fn matches_v4(&self, entry: Ipv4Prefix, candidate: Ipv4Prefix) -> bool {
        let entry_bits = u32::from(entry.addr);
        let cand_bits = u32::from(candidate.addr);

        if entry.len > 0 {
            let mask = !((1u32 << (32 - entry.len)) - 1);
            if (entry_bits & mask) != (cand_bits & mask) {
                return false;
            }
        }

        let (min_len, max_len) = match (self.ge, self.le) {
            (None, None) => (entry.len, entry.len),
            (Some(ge), None) => (ge, 32),
            (None, Some(le)) => (entry.len, le),
            (Some(ge), Some(le)) => (ge, le),
        };

        candidate.len >= min_len && candidate.len <= max_len
    }

    fn matches_v6(&self, entry: Ipv6Prefix, candidate: Ipv6Prefix) -> bool {
        let entry_bits = u128::from(entry.addr);
        let cand_bits = u128::from(candidate.addr);

        if entry.len > 0 {
            let mask = !((1u128 << (128 - entry.len)) - 1);
            if (entry_bits & mask) != (cand_bits & mask) {
                return false;
            }
        }

        let (min_len, max_len) = match (self.ge, self.le) {
            (None, None) => (entry.len, entry.len),
            (Some(ge), None) => (ge, 128),
            (None, Some(le)) => (entry.len, le),
            (Some(ge), Some(le)) => (ge, le),
        };

        candidate.len >= min_len && candidate.len <= max_len
    }
}

/// An ordered list of policy statements with a default action.
#[derive(Debug, Clone)]
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
                return PolicyResult {
                    action: entry.action,
                    modifications: entry.modifications.clone(),
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

/// An ordered sequence of policies evaluated in chain.
///
/// GoBGP-style semantics: each policy is evaluated in order. If a policy
/// returns `Permit`, its modifications are accumulated and evaluation
/// continues to the next policy. If a policy returns `Deny`, the route
/// is rejected immediately. After all policies, the route is permitted
/// with the accumulated modifications.
#[derive(Debug, Clone, Default)]
pub struct PolicyChain {
    /// Policies evaluated in order; modifications accumulate across permits.
    pub policies: Vec<Policy>,
}

impl PolicyChain {
    /// Create a chain from an ordered list of policies.
    #[must_use]
    pub fn new(policies: Vec<Policy>) -> Self {
        Self { policies }
    }

    /// Evaluate a route against this chain of policies.
    #[must_use]
    pub fn evaluate(&self, ctx: &RouteContext<'_>) -> PolicyResult {
        let mut accumulated = RouteModifications::default();
        for policy in &self.policies {
            let result = policy.evaluate(ctx);
            match result.action {
                PolicyAction::Deny => return PolicyResult::deny(),
                PolicyAction::Permit => accumulated.merge_from(result.modifications),
            }
        }
        PolicyResult {
            action: PolicyAction::Permit,
            modifications: accumulated,
        }
    }
}

/// Convenience: evaluate an optional policy chain. Returns `Permit` with no modifications if no chain.
#[must_use]
pub fn evaluate_chain(chain: Option<&PolicyChain>, ctx: &RouteContext<'_>) -> PolicyResult {
    match chain {
        Some(c) => c.evaluate(ctx),
        None => PolicyResult::permit(),
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
            PathAttribute::Communities(c) => Some(c.clone()),
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
            PathAttribute::LargeCommunities(c) => Some(c.clone()),
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
fn apply_community_mods<T: Clone + PartialEq>(
    attrs: &mut Vec<PathAttribute>,
    add: &[T],
    remove: &[T],
    extract: impl Fn(&PathAttribute) -> Option<Vec<T>>,
    predicate: impl Fn(&PathAttribute) -> bool,
    wrap: impl Fn(Vec<T>) -> PathAttribute,
) {
    if add.is_empty() && remove.is_empty() {
        return;
    }
    let mut items: Vec<T> = attrs.iter().find_map(&extract).unwrap_or_default();
    items.retain(|v| !remove.contains(v));
    for v in add {
        if !items.contains(v) {
            items.push(v.clone());
        }
    }
    attrs.retain(|a| !predicate(a));
    if !items.is_empty() {
        attrs.push(wrap(items));
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

#[cfg(test)]
mod tests;
