use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use regex::Regex;
use rustbgpd_wire::{
    AsPath, AsPathSegment, ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, LargeCommunity,
    PathAttribute, Prefix, RpkiValidation,
};

/// Action taken when a prefix matches a policy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Permit,
    Deny,
}

/// The result of evaluating a policy: an action plus any route modifications.
#[derive(Debug, Clone)]
pub struct PolicyResult {
    pub action: PolicyAction,
    pub modifications: RouteModifications,
}

impl PolicyResult {
    #[must_use]
    pub fn permit() -> Self {
        Self {
            action: PolicyAction::Permit,
            modifications: RouteModifications::default(),
        }
    }

    #[must_use]
    pub fn deny() -> Self {
        Self {
            action: PolicyAction::Deny,
            modifications: RouteModifications::default(),
        }
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
    pub set_local_pref: Option<u32>,
    pub set_med: Option<u32>,
    pub set_next_hop: Option<NextHopAction>,
    pub communities_add: Vec<u32>,
    pub communities_remove: Vec<u32>,
    pub extended_communities_add: Vec<ExtendedCommunity>,
    pub extended_communities_remove: Vec<ExtendedCommunity>,
    pub large_communities_add: Vec<LargeCommunity>,
    pub large_communities_remove: Vec<LargeCommunity>,
    /// `(ASN, count)` — prepend `count` copies of `ASN` to the `AS_PATH`.
    pub as_path_prepend: Option<(u32, u8)>,
}

/// A match criterion for community values (standard, extended, or large).
///
/// Extended community matching is encoding-agnostic: a 2-octet AS RT,
/// 4-octet AS RT, and IPv4-specific RT with the same decoded
/// `(global, local)` all match the same `CommunityMatch::RouteTarget`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityMatch {
    /// Match Route Target (sub-type 0x02) — extended community.
    RouteTarget { global: u32, local: u32 },
    /// Match Route Origin (sub-type 0x03) — extended community.
    RouteOrigin { global: u32, local: u32 },
    /// Match a standard community (RFC 1997) — raw u32 value.
    Standard { value: u32 },
    /// Match a large community (RFC 8092).
    LargeCommunity {
        global_admin: u32,
        local_data1: u32,
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

    /// Check whether a single [`LargeCommunity`](rustbgpd_wire::LargeCommunity) matches this criterion.
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
/// Entries can match on prefix, community, `AS_PATH` regex, or combinations.
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
    pub action: PolicyAction,
    /// Community match criteria (OR within the list).
    pub match_community: Vec<CommunityMatch>,
    /// `AS_PATH` regex match criterion.
    pub match_as_path: Option<AsPathRegex>,
    /// RPKI validation state match criterion (RFC 6811).
    pub match_rpki_validation: Option<RpkiValidation>,
    /// Route modifications to apply when this statement matches.
    pub modifications: RouteModifications,
}

impl PolicyStatement {
    /// Check whether a route matches this statement.
    fn matches(
        &self,
        candidate: Prefix,
        ecs: &[ExtendedCommunity],
        communities: &[u32],
        lcs: &[rustbgpd_wire::LargeCommunity],
        aspath_str: &str,
        validation_state: RpkiValidation,
    ) -> bool {
        let prefix_ok = match self.prefix {
            Some(p) => self.matches_prefix(p, candidate),
            None => true,
        };

        let community_ok = if self.match_community.is_empty() {
            true
        } else {
            self.match_community.iter().any(|cm| {
                ecs.iter().any(|ec| cm.matches_ec(ec))
                    || communities.iter().any(|c| cm.matches_standard(*c))
                    || lcs.iter().any(|lc| cm.matches_large(lc))
            })
        };

        let aspath_ok = match &self.match_as_path {
            Some(regex) => regex.is_match(aspath_str),
            None => true,
        };

        let rpki_ok = self
            .match_rpki_validation
            .is_none_or(|v| v == validation_state);

        prefix_ok && community_ok && aspath_ok && rpki_ok
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
    pub entries: Vec<PolicyStatement>,
    pub default_action: PolicyAction,
}

impl Policy {
    /// Evaluate a route against this policy. First matching entry wins.
    #[must_use]
    pub fn evaluate(
        &self,
        prefix: Prefix,
        ecs: &[ExtendedCommunity],
        communities: &[u32],
        lcs: &[rustbgpd_wire::LargeCommunity],
        aspath_str: &str,
        validation_state: RpkiValidation,
    ) -> PolicyResult {
        for entry in &self.entries {
            if entry.matches(prefix, ecs, communities, lcs, aspath_str, validation_state) {
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
pub fn evaluate_policy(
    policy: Option<&Policy>,
    prefix: Prefix,
    ecs: &[ExtendedCommunity],
    communities: &[u32],
    lcs: &[rustbgpd_wire::LargeCommunity],
    aspath_str: &str,
    validation_state: RpkiValidation,
) -> PolicyResult {
    match policy {
        Some(p) => p.evaluate(prefix, ecs, communities, lcs, aspath_str, validation_state),
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
mod tests {
    use std::net::Ipv4Addr;

    use rustbgpd_wire::Ipv4Prefix;

    use super::*;

    fn v4_prefix(addr: [u8; 4], len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
            len,
        ))
    }

    fn v4_entry(addr: [u8; 4], len: u8) -> Prefix {
        v4_prefix(addr, len)
    }

    fn stmt(
        prefix: Option<Prefix>,
        action: PolicyAction,
        community: Vec<CommunityMatch>,
    ) -> PolicyStatement {
        PolicyStatement {
            prefix,
            ge: None,
            le: None,
            action,
            match_community: community,
            match_as_path: None,
            match_rpki_validation: None,
            modifications: RouteModifications::default(),
        }
    }

    /// Build a 2-octet AS specific Route Target EC.
    fn make_rt(asn: u16, value: u32) -> ExtendedCommunity {
        let mut b = [0u8; 8];
        b[0] = 0x00;
        b[1] = 0x02;
        b[2..4].copy_from_slice(&asn.to_be_bytes());
        b[4..8].copy_from_slice(&value.to_be_bytes());
        ExtendedCommunity::new(u64::from_be_bytes(b))
    }

    fn make_ro(asn: u16, value: u32) -> ExtendedCommunity {
        let mut b = [0u8; 8];
        b[0] = 0x00;
        b[1] = 0x03;
        b[2..4].copy_from_slice(&asn.to_be_bytes());
        b[4..8].copy_from_slice(&value.to_be_bytes());
        ExtendedCommunity::new(u64::from_be_bytes(b))
    }

    fn make_rt_as4(asn: u32, value: u16) -> ExtendedCommunity {
        let mut b = [0u8; 8];
        b[0] = 0x02;
        b[1] = 0x02;
        b[2..6].copy_from_slice(&asn.to_be_bytes());
        b[6..8].copy_from_slice(&value.to_be_bytes());
        ExtendedCommunity::new(u64::from_be_bytes(b))
    }

    // -----------------------------------------------------------------------
    // PolicyResult helpers
    // -----------------------------------------------------------------------

    #[test]
    fn policy_result_permit_helper() {
        let r = PolicyResult::permit();
        assert_eq!(r.action, PolicyAction::Permit);
        assert!(r.modifications.set_local_pref.is_none());
    }

    #[test]
    fn policy_result_deny_helper() {
        let r = PolicyResult::deny();
        assert_eq!(r.action, PolicyAction::Deny);
    }

    #[test]
    fn evaluate_policy_none_returns_permit() {
        let r = evaluate_policy(
            None,
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            RpkiValidation::NotFound,
        );
        assert_eq!(r.action, PolicyAction::Permit);
    }

    // -----------------------------------------------------------------------
    // Prefix matching (renamed types)
    // -----------------------------------------------------------------------

    #[test]
    fn exact_match_permit() {
        let pl = Policy {
            entries: vec![stmt(
                Some(v4_entry([10, 0, 0, 0], 8)),
                PolicyAction::Permit,
                vec![],
            )],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 1, 0, 0], 24),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
    }

    #[test]
    fn ge_le_range() {
        let pl = Policy {
            entries: vec![PolicyStatement {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: Some(16),
                le: Some(24),
                action: PolicyAction::Permit,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 1, 0, 0], 16),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
    }

    #[test]
    fn default_action_used_when_no_match() {
        let pl = Policy {
            entries: vec![stmt(
                Some(v4_entry([10, 0, 0, 0], 8)),
                PolicyAction::Deny,
                vec![],
            )],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(
                v4_prefix([192, 168, 0, 0], 16),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
    }

    #[test]
    fn first_match_wins() {
        let pl = Policy {
            entries: vec![
                stmt(Some(v4_entry([10, 0, 0, 0], 8)), PolicyAction::Deny, vec![]),
                stmt(
                    Some(v4_entry([10, 0, 0, 0], 8)),
                    PolicyAction::Permit,
                    vec![],
                ),
            ],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
    }

    // -----------------------------------------------------------------------
    // Community match parse tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_community_match_rt_asn() {
        let cm = parse_community_match("RT:65001:100").unwrap();
        assert_eq!(
            cm,
            CommunityMatch::RouteTarget {
                global: 65001,
                local: 100
            }
        );
    }

    #[test]
    fn parse_community_match_ro_asn() {
        let cm = parse_community_match("RO:65002:200").unwrap();
        assert_eq!(
            cm,
            CommunityMatch::RouteOrigin {
                global: 65002,
                local: 200
            }
        );
    }

    #[test]
    fn parse_community_match_rt_ipv4() {
        let cm = parse_community_match("RT:192.0.2.1:100").unwrap();
        assert_eq!(
            cm,
            CommunityMatch::RouteTarget {
                global: u32::from(Ipv4Addr::new(192, 0, 2, 1)),
                local: 100
            }
        );
    }

    #[test]
    fn parse_community_match_invalid_type() {
        assert!(parse_community_match("XX:1:2").is_err());
    }

    #[test]
    fn parse_community_match_rejects_impossible_ipv4_local() {
        assert!(parse_community_match("RT:192.0.2.1:70000").is_err());
    }

    #[test]
    fn parse_community_match_rejects_impossible_as4_local() {
        assert!(parse_community_match("RT:65551:70000").is_err());
    }

    #[test]
    fn parse_community_match_standard() {
        let cm = parse_community_match("65001:100").unwrap();
        assert_eq!(
            cm,
            CommunityMatch::Standard {
                value: (65001 << 16) | 100
            }
        );
    }

    #[test]
    fn parse_community_match_well_known() {
        assert_eq!(
            parse_community_match("NO_EXPORT").unwrap(),
            CommunityMatch::Standard { value: 0xFFFF_FF01 }
        );
    }

    // -----------------------------------------------------------------------
    // Community matching evaluation
    // -----------------------------------------------------------------------

    #[test]
    fn community_only_entry_matches() {
        let pl = Policy {
            entries: vec![stmt(
                None,
                PolicyAction::Deny,
                vec![CommunityMatch::RouteTarget {
                    global: 65001,
                    local: 100,
                }],
            )],
            default_action: PolicyAction::Permit,
        };
        let ecs = [make_rt(65001, 100)];
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &ecs,
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
    }

    #[test]
    fn community_only_entry_no_match() {
        let pl = Policy {
            entries: vec![stmt(
                None,
                PolicyAction::Deny,
                vec![CommunityMatch::RouteTarget {
                    global: 65001,
                    local: 100,
                }],
            )],
            default_action: PolicyAction::Permit,
        };
        let ecs = [make_rt(65002, 200)];
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &ecs,
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
    }

    #[test]
    fn prefix_and_community_both_required() {
        let pl = Policy {
            entries: vec![stmt(
                Some(v4_entry([10, 0, 0, 0], 8)),
                PolicyAction::Deny,
                vec![CommunityMatch::RouteTarget {
                    global: 65001,
                    local: 100,
                }],
            )],
            default_action: PolicyAction::Permit,
        };
        let ecs = [make_rt(65001, 100)];
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &ecs,
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
        // Prefix mismatch
        assert_eq!(
            pl.evaluate(
                v4_prefix([192, 168, 0, 0], 16),
                &ecs,
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
    }

    #[test]
    fn standard_community_match_hit() {
        let val = (65001u32 << 16) | 100;
        let pl = Policy {
            entries: vec![stmt(
                None,
                PolicyAction::Deny,
                vec![CommunityMatch::Standard { value: val }],
            )],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[val],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
    }

    #[test]
    fn mixed_standard_and_ec_or_semantics() {
        let pl = Policy {
            entries: vec![stmt(
                None,
                PolicyAction::Deny,
                vec![
                    CommunityMatch::Standard {
                        value: (65001 << 16) | 100,
                    },
                    CommunityMatch::RouteTarget {
                        global: 65002,
                        local: 200,
                    },
                ],
            )],
            default_action: PolicyAction::Permit,
        };
        let std_community = (65001u32 << 16) | 100;
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[std_community],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
        let ecs = [make_rt(65002, 200)];
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &ecs,
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
    }

    #[test]
    fn community_match_route_origin() {
        let pl = Policy {
            entries: vec![stmt(
                None,
                PolicyAction::Deny,
                vec![CommunityMatch::RouteOrigin {
                    global: 65001,
                    local: 100,
                }],
            )],
            default_action: PolicyAction::Permit,
        };
        let target_ecs = [make_rt(65001, 100)];
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &target_ecs,
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
        let origin_ecs = [make_ro(65001, 100)];
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &origin_ecs,
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
    }

    #[test]
    fn v6_exact_match() {
        use rustbgpd_wire::Ipv6Prefix;

        let pl = Policy {
            entries: vec![PolicyStatement {
                prefix: Some(Prefix::V6(Ipv6Prefix::new(
                    "2001:db8::".parse().unwrap(),
                    32,
                ))),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(
                Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::NotFound,
            )
            .action,
            PolicyAction::Deny
        );
        assert_eq!(
            pl.evaluate(
                Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48)),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::NotFound,
            )
            .action,
            PolicyAction::Permit
        );
    }

    // -----------------------------------------------------------------------
    // Large community matching
    // -----------------------------------------------------------------------

    #[test]
    fn parse_large_community_match() {
        let cm = parse_community_match("LC:65001:100:200").unwrap();
        assert_eq!(
            cm,
            CommunityMatch::LargeCommunity {
                global_admin: 65001,
                local_data1: 100,
                local_data2: 200,
            }
        );
    }

    #[test]
    fn parse_large_community_match_invalid() {
        assert!(parse_community_match("LC:65001:100").is_err());
        assert!(parse_community_match("LC:abc:100:200").is_err());
    }

    #[test]
    fn large_community_match_hit() {
        let pl = Policy {
            entries: vec![stmt(
                None,
                PolicyAction::Deny,
                vec![CommunityMatch::LargeCommunity {
                    global_admin: 65001,
                    local_data1: 100,
                    local_data2: 200,
                }],
            )],
            default_action: PolicyAction::Permit,
        };
        let lcs = [LargeCommunity::new(65001, 100, 200)];
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &lcs,
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
    }

    #[test]
    fn large_community_match_miss() {
        let pl = Policy {
            entries: vec![stmt(
                None,
                PolicyAction::Deny,
                vec![CommunityMatch::LargeCommunity {
                    global_admin: 65001,
                    local_data1: 100,
                    local_data2: 200,
                }],
            )],
            default_action: PolicyAction::Permit,
        };
        let lcs = [LargeCommunity::new(65001, 999, 200)];
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &lcs,
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
    }

    #[test]
    fn large_community_does_not_match_standard_or_ec() {
        let cm = CommunityMatch::LargeCommunity {
            global_admin: 65001,
            local_data1: 100,
            local_data2: 200,
        };
        assert!(!cm.matches_ec(&make_rt(65001, 100)));
        assert!(!cm.matches_standard((65001 << 16) | 100));
    }

    #[test]
    fn or_across_all_community_types() {
        let pl = Policy {
            entries: vec![stmt(
                None,
                PolicyAction::Deny,
                vec![
                    CommunityMatch::Standard {
                        value: (65001 << 16) | 100,
                    },
                    CommunityMatch::RouteTarget {
                        global: 65002,
                        local: 200,
                    },
                    CommunityMatch::LargeCommunity {
                        global_admin: 65003,
                        local_data1: 300,
                        local_data2: 400,
                    },
                ],
            )],
            default_action: PolicyAction::Permit,
        };
        // LC match
        let lcs = [LargeCommunity::new(65003, 300, 400)];
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &lcs,
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
        // EC match
        let ecs = [make_rt(65002, 200)];
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &ecs,
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
        // Standard match
        let std_c = (65001u32 << 16) | 100;
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[std_c],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
        // No match
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
    }

    // -----------------------------------------------------------------------
    // Policy with modifications
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_returns_modifications() {
        let pl = Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Permit,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: None,
                modifications: RouteModifications {
                    set_local_pref: Some(200),
                    ..RouteModifications::default()
                },
            }],
            default_action: PolicyAction::Deny,
        };
        let r = pl.evaluate(
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            RpkiValidation::NotFound,
        );
        assert_eq!(r.action, PolicyAction::Permit);
        assert_eq!(r.modifications.set_local_pref, Some(200));
    }

    // -----------------------------------------------------------------------
    // AsPathRegex
    // -----------------------------------------------------------------------

    #[test]
    fn aspath_regex_starts_with() {
        let r = AsPathRegex::new("^65100").unwrap();
        assert!(r.is_match("65100 65200"));
        assert!(!r.is_match("65200 65100"));
    }

    #[test]
    fn aspath_regex_ends_with() {
        let r = AsPathRegex::new("65200$").unwrap();
        assert!(r.is_match("65100 65200"));
        assert!(!r.is_match("65200 65100"));
    }

    #[test]
    fn aspath_regex_contains() {
        let r = AsPathRegex::new("65200").unwrap();
        assert!(r.is_match("65100 65200 65300"));
        assert!(!r.is_match("65100 65300"));
    }

    #[test]
    fn aspath_regex_exact() {
        let r = AsPathRegex::new("^65100$").unwrap();
        assert!(r.is_match("65100"));
        assert!(!r.is_match("65100 65200"));
    }

    #[test]
    fn aspath_regex_underscore_boundary() {
        // _65200_ should match 65200 as a separate AS number
        let r = AsPathRegex::new("_65200_").unwrap();
        assert!(r.is_match("65100 65200 65300"));
        assert!(r.is_match("65200"));
        assert!(!r.is_match("165200"));
    }

    #[test]
    fn aspath_regex_underscore_matches_as_set_braces() {
        // _ should match { and } delimiters in AS_SET representation
        let r = AsPathRegex::new("_65003_").unwrap();
        assert!(r.is_match("65001 {65003 65004}"));
        assert!(r.is_match("{65003}"));
        assert!(!r.is_match("65001 {650030 65004}"));
    }

    #[test]
    fn aspath_regex_raw_pattern() {
        let r = AsPathRegex::new("651[0-9]{2}").unwrap();
        assert!(r.is_match("65100"));
        assert!(r.is_match("65199"));
        assert!(!r.is_match("65200"));
    }

    #[test]
    fn aspath_regex_invalid_rejected() {
        assert!(AsPathRegex::new("[invalid").is_err());
    }

    // -----------------------------------------------------------------------
    // AS_PATH regex in policy evaluation
    // -----------------------------------------------------------------------

    #[test]
    fn aspath_match_in_policy() {
        let pl = Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: Some(AsPathRegex::new("^65100").unwrap()),
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "65100 65200",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "65200 65100",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
    }

    #[test]
    fn aspath_combined_with_prefix() {
        let pl = Policy {
            entries: vec![PolicyStatement {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: Some(AsPathRegex::new("_65200_").unwrap()),
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        };
        // Both match → deny
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "65100 65200",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
        // Prefix matches, aspath doesn't → permit
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "65100 65300",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
        // Aspath matches, prefix doesn't → permit
        assert_eq!(
            pl.evaluate(
                v4_prefix([192, 168, 0, 0], 16),
                &[],
                &[],
                &[],
                "65100 65200",
                RpkiValidation::NotFound,
            )
            .action,
            PolicyAction::Permit
        );
    }

    #[test]
    fn aspath_combined_with_community() {
        let pl = Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![CommunityMatch::Standard {
                    value: (65001 << 16) | 100,
                }],
                match_as_path: Some(AsPathRegex::new("_65200_").unwrap()),
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        };
        let std_c = (65001u32 << 16) | 100;
        // Both match → deny
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[std_c],
                &[],
                "65200",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Deny
        );
        // Community matches, aspath doesn't → permit
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[std_c],
                &[],
                "65300",
                RpkiValidation::NotFound
            )
            .action,
            PolicyAction::Permit
        );
    }

    // -----------------------------------------------------------------------
    // apply_modifications
    // -----------------------------------------------------------------------
    use rustbgpd_wire::{AsPath, AsPathSegment, PathAttribute};

    #[test]
    fn apply_set_local_pref_absent() {
        let mut attrs = vec![PathAttribute::Origin(rustbgpd_wire::Origin::Igp)];
        let mods = RouteModifications {
            set_local_pref: Some(200),
            ..Default::default()
        };
        apply_modifications(&mut attrs, &mods);
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(200)))
        );
    }

    #[test]
    fn apply_set_local_pref_present() {
        let mut attrs = vec![PathAttribute::LocalPref(100)];
        let mods = RouteModifications {
            set_local_pref: Some(200),
            ..Default::default()
        };
        apply_modifications(&mut attrs, &mods);
        assert_eq!(
            attrs
                .iter()
                .filter(|a| matches!(a, PathAttribute::LocalPref(_)))
                .count(),
            1
        );
        assert!(
            attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::LocalPref(200)))
        );
    }

    #[test]
    fn apply_set_med() {
        let mut attrs = vec![];
        let mods = RouteModifications {
            set_med: Some(50),
            ..Default::default()
        };
        apply_modifications(&mut attrs, &mods);
        assert!(attrs.iter().any(|a| matches!(a, PathAttribute::Med(50))));
    }

    #[test]
    fn apply_community_add_remove() {
        let c1 = (65001u32 << 16) | 100;
        let c2 = (65001u32 << 16) | 200;
        let mut attrs = vec![PathAttribute::Communities(vec![c1])];
        let mods = RouteModifications {
            communities_add: vec![c2],
            communities_remove: vec![c1],
            ..Default::default()
        };
        apply_modifications(&mut attrs, &mods);
        let comms = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::Communities(c) => Some(c),
                _ => None,
            })
            .unwrap();
        assert!(!comms.contains(&c1));
        assert!(comms.contains(&c2));
    }

    #[test]
    fn apply_extended_community_remove_matches_semantic_equivalent() {
        let mut attrs = vec![PathAttribute::ExtendedCommunities(vec![make_rt_as4(
            65001, 100,
        )])];
        let mods = RouteModifications {
            extended_communities_remove: vec![make_rt(65001, 100)],
            ..Default::default()
        };
        apply_modifications(&mut attrs, &mods);
        assert!(
            !attrs
                .iter()
                .any(|a| matches!(a, PathAttribute::ExtendedCommunities(_)))
        );
    }

    #[test]
    fn apply_extended_community_add_avoids_semantic_duplicate() {
        let existing = make_rt_as4(65001, 100);
        let mut attrs = vec![PathAttribute::ExtendedCommunities(vec![existing])];
        let mods = RouteModifications {
            extended_communities_add: vec![make_rt(65001, 100)],
            ..Default::default()
        };
        apply_modifications(&mut attrs, &mods);
        let ecs = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::ExtendedCommunities(c) => Some(c),
                _ => None,
            })
            .unwrap();
        assert_eq!(ecs, &[existing]);
    }

    #[test]
    fn apply_large_community_add_remove() {
        let lc1 = LargeCommunity::new(65001, 100, 200);
        let lc2 = LargeCommunity::new(65001, 300, 400);
        let mut attrs = vec![PathAttribute::LargeCommunities(vec![lc1])];
        let mods = RouteModifications {
            large_communities_add: vec![lc2],
            large_communities_remove: vec![lc1],
            ..Default::default()
        };
        apply_modifications(&mut attrs, &mods);
        let lcs = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::LargeCommunities(c) => Some(c),
                _ => None,
            })
            .unwrap();
        assert!(!lcs.contains(&lc1));
        assert!(lcs.contains(&lc2));
    }

    #[test]
    fn apply_as_path_prepend_existing() {
        let mut attrs = vec![PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65002, 65003])],
        })];
        let mods = RouteModifications {
            as_path_prepend: Some((65001, 2)),
            ..Default::default()
        };
        apply_modifications(&mut attrs, &mods);
        let path = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(p) => Some(p),
                _ => None,
            })
            .unwrap();
        match &path.segments[0] {
            AsPathSegment::AsSequence(seq) => {
                assert_eq!(seq, &[65001, 65001, 65002, 65003]);
            }
            AsPathSegment::AsSet(_) => panic!("expected AS_SEQUENCE"),
        }
    }

    #[test]
    fn apply_as_path_prepend_empty() {
        let mut attrs = vec![];
        let mods = RouteModifications {
            as_path_prepend: Some((65001, 3)),
            ..Default::default()
        };
        apply_modifications(&mut attrs, &mods);
        let path = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(p) => Some(p),
                _ => None,
            })
            .unwrap();
        match &path.segments[0] {
            AsPathSegment::AsSequence(seq) => {
                assert_eq!(seq, &[65001, 65001, 65001]);
            }
            AsPathSegment::AsSet(_) => panic!("expected AS_SEQUENCE"),
        }
    }

    #[test]
    fn apply_as_path_prepend_avoids_first_segment_overflow() {
        let long_seq: Vec<u32> = (0..250).map(|i| 65002 + i).collect();
        let mut attrs = vec![PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(long_seq.clone())],
        })];
        let mods = RouteModifications {
            as_path_prepend: Some((65001, 10)),
            ..Default::default()
        };
        apply_modifications(&mut attrs, &mods);
        let path = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(p) => Some(p),
                _ => None,
            })
            .unwrap();
        assert_eq!(path.segments.len(), 2);
        match &path.segments[0] {
            AsPathSegment::AsSequence(seq) => {
                assert_eq!(seq.len(), 10);
                assert!(seq.iter().all(|asn| *asn == 65001));
            }
            AsPathSegment::AsSet(_) => panic!("expected AS_SEQUENCE"),
        }
        match &path.segments[1] {
            AsPathSegment::AsSequence(seq) => assert_eq!(seq, &long_seq),
            AsPathSegment::AsSet(_) => panic!("expected AS_SEQUENCE"),
        }
    }

    #[test]
    fn apply_next_hop_self() {
        let mut attrs = vec![];
        let mods = RouteModifications {
            set_next_hop: Some(NextHopAction::Self_),
            ..Default::default()
        };
        let nh = apply_modifications(&mut attrs, &mods);
        assert_eq!(nh, Some(NextHopAction::Self_));
    }

    #[test]
    fn apply_noop_default() {
        let orig = vec![PathAttribute::Origin(rustbgpd_wire::Origin::Igp)];
        let mut attrs = orig.clone();
        let mods = RouteModifications::default();
        let nh = apply_modifications(&mut attrs, &mods);
        assert!(nh.is_none());
        assert_eq!(attrs, orig);
    }

    // --- RPKI validation matching ---

    #[test]
    fn rpki_match_invalid_deny() {
        let pl = Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: Some(RpkiValidation::Invalid),
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        };
        // Invalid route → matches deny rule
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::Invalid,
            )
            .action,
            PolicyAction::Deny
        );
        // Valid route → doesn't match, falls through to permit
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::Valid,
            )
            .action,
            PolicyAction::Permit
        );
        // NotFound route → doesn't match
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::NotFound,
            )
            .action,
            PolicyAction::Permit
        );
    }

    #[test]
    fn rpki_match_valid_accept() {
        let pl = Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Permit,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: Some(RpkiValidation::Valid),
                modifications: RouteModifications {
                    set_local_pref: Some(200),
                    ..RouteModifications::default()
                },
            }],
            default_action: PolicyAction::Permit,
        };
        // Valid route → matches, gets local_pref modification
        let r = pl.evaluate(
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            RpkiValidation::Valid,
        );
        assert_eq!(r.action, PolicyAction::Permit);
        assert_eq!(r.modifications.set_local_pref, Some(200));

        // NotFound route → doesn't match, gets default (no mods)
        let r = pl.evaluate(
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            RpkiValidation::NotFound,
        );
        assert_eq!(r.modifications.set_local_pref, None);
    }

    #[test]
    fn rpki_match_not_found() {
        let pl = Policy {
            entries: vec![PolicyStatement {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Permit,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: Some(RpkiValidation::NotFound),
                modifications: RouteModifications {
                    set_local_pref: Some(100),
                    ..RouteModifications::default()
                },
            }],
            default_action: PolicyAction::Permit,
        };
        // NotFound → matches
        let r = pl.evaluate(
            v4_prefix([10, 0, 0, 0], 8),
            &[],
            &[],
            &[],
            "",
            RpkiValidation::NotFound,
        );
        assert_eq!(r.modifications.set_local_pref, Some(100));
    }

    #[test]
    fn rpki_match_none_matches_all() {
        // No RPKI match criterion → matches any validation state
        let pl = Policy {
            entries: vec![PolicyStatement {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        };
        for state in [
            RpkiValidation::Valid,
            RpkiValidation::Invalid,
            RpkiValidation::NotFound,
        ] {
            assert_eq!(
                pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &[], &[], &[], "", state)
                    .action,
                PolicyAction::Deny,
                "state={state:?} should still match"
            );
        }
    }

    #[test]
    fn rpki_combined_with_prefix() {
        // Match: prefix 10.0.0.0/8 AND rpki=invalid → deny
        let pl = Policy {
            entries: vec![PolicyStatement {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: Some(RpkiValidation::Invalid),
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        };
        // Both match → deny
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::Invalid,
            )
            .action,
            PolicyAction::Deny
        );
        // Prefix matches, RPKI doesn't → permit
        assert_eq!(
            pl.evaluate(
                v4_prefix([10, 0, 0, 0], 8),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::Valid,
            )
            .action,
            PolicyAction::Permit
        );
        // RPKI matches, prefix doesn't → permit
        assert_eq!(
            pl.evaluate(
                v4_prefix([192, 168, 0, 0], 16),
                &[],
                &[],
                &[],
                "",
                RpkiValidation::Invalid,
            )
            .action,
            PolicyAction::Permit
        );
    }
}
