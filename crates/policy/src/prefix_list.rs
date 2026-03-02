use std::net::Ipv4Addr;

use rustbgpd_wire::{ExtendedCommunity, Ipv4Prefix, Ipv6Prefix, Prefix};

/// Action taken when a prefix matches a policy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Permit,
    Deny,
}

/// A match criterion for extended community values.
///
/// Matching is encoding-agnostic: a 2-octet AS RT, 4-octet AS RT, and
/// IPv4-specific RT with the same decoded `(global, local)` all match
/// the same `CommunityMatch::RouteTarget`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommunityMatch {
    /// Match Route Target (sub-type 0x02).
    RouteTarget { global: u32, local: u32 },
    /// Match Route Origin (sub-type 0x03).
    RouteOrigin { global: u32, local: u32 },
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
        }
    }
}

/// Parse a community match string like `"RT:65001:100"` or `"RO:192.0.2.1:200"`.
///
/// Format: `{RT|RO}:{global}:{local}` where `global` is a decimal ASN (u32)
/// or an IPv4 address (converted to u32), and `local` is a decimal u32.
///
/// # Errors
///
/// Returns an error if the string is not in the expected `TYPE:GLOBAL:LOCAL`
/// format, if the type is not `RT` or `RO`, or if global/local values cannot
/// be parsed.
pub fn parse_community_match(s: &str) -> Result<CommunityMatch, String> {
    // Use splitn(3, ':') so that IPv4 addresses (containing dots, not colons)
    // work correctly: "RT:192.0.2.1:100" → ["RT", "192.0.2.1", "100"]
    let parts: Vec<&str> = s.splitn(3, ':').collect();
    if parts.len() != 3 {
        return Err(format!("expected format TYPE:GLOBAL:LOCAL, got {s:?}"));
    }

    let global: u32 = if let Ok(asn) = parts[1].parse::<u32>() {
        asn
    } else if let Ok(ipv4) = parts[1].parse::<Ipv4Addr>() {
        u32::from(ipv4)
    } else {
        return Err(format!(
            "invalid global admin {:?}: expected ASN (u32) or IPv4 address",
            parts[1]
        ));
    };

    let local: u32 = parts[2]
        .parse()
        .map_err(|_| format!("invalid local admin {:?}: expected u32", parts[2]))?;

    match parts[0] {
        "RT" => Ok(CommunityMatch::RouteTarget { global, local }),
        "RO" => Ok(CommunityMatch::RouteOrigin { global, local }),
        other => Err(format!(
            "unknown community type {other:?}, expected \"RT\" or \"RO\""
        )),
    }
}

/// A single entry in a policy list.
///
/// Entries can match on prefix, extended community, or both. When both are
/// specified, both conditions must be true (AND). When multiple community
/// values are listed, the route must carry at least one (OR).
#[derive(Debug, Clone)]
pub struct PrefixListEntry {
    /// Prefix to match. If `None`, the entry matches any prefix.
    pub prefix: Option<Prefix>,
    /// Minimum prefix length (inclusive). If `None`, exact match on `prefix.len`.
    /// Only meaningful when `prefix` is `Some`.
    pub ge: Option<u8>,
    /// Maximum prefix length (inclusive). If `None`, defaults to max for AFI (32 or 128).
    /// Only meaningful when `prefix` is `Some`.
    pub le: Option<u8>,
    pub action: PolicyAction,
    /// Extended community match criteria. If non-empty, the route must carry
    /// at least one EC matching ANY of these (OR within the list).
    pub match_community: Vec<CommunityMatch>,
}

impl PrefixListEntry {
    /// Check whether a `(prefix, extended_communities)` pair matches this entry.
    fn matches(&self, candidate: Prefix, ecs: &[ExtendedCommunity]) -> bool {
        let prefix_ok = match self.prefix {
            Some(p) => self.matches_prefix(p, candidate),
            None => true,
        };

        let community_ok = if self.match_community.is_empty() {
            true
        } else {
            self.match_community
                .iter()
                .any(|cm| ecs.iter().any(|ec| cm.matches_ec(ec)))
        };

        prefix_ok && community_ok
    }

    /// Check whether `candidate` matches the prefix condition.
    fn matches_prefix(&self, entry_prefix: Prefix, candidate: Prefix) -> bool {
        match (entry_prefix, candidate) {
            (Prefix::V4(entry), Prefix::V4(cand)) => self.matches_v4(entry, cand),
            (Prefix::V6(entry), Prefix::V6(cand)) => self.matches_v6(entry, cand),
            _ => false, // AFI mismatch
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

/// An ordered list of policy entries with a default action.
#[derive(Debug, Clone)]
pub struct PrefixList {
    pub entries: Vec<PrefixListEntry>,
    pub default_action: PolicyAction,
}

impl PrefixList {
    /// Evaluate a prefix and its extended communities against this list.
    /// First matching entry wins.
    #[must_use]
    pub fn evaluate(&self, prefix: Prefix, ecs: &[ExtendedCommunity]) -> PolicyAction {
        for entry in &self.entries {
            if entry.matches(prefix, ecs) {
                return entry.action;
            }
        }
        self.default_action
    }
}

/// Convenience: evaluate an optional prefix list. Returns `Permit` if no list.
#[must_use]
pub fn check_prefix_list(
    list: Option<&PrefixList>,
    prefix: Prefix,
    ecs: &[ExtendedCommunity],
) -> PolicyAction {
    match list {
        Some(pl) => pl.evaluate(prefix, ecs),
        None => PolicyAction::Permit,
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

    /// Build a 2-octet AS specific Route Target EC.
    fn make_rt(asn: u16, value: u32) -> ExtendedCommunity {
        let mut b = [0u8; 8];
        b[0] = 0x00; // type: 2-octet AS specific
        b[1] = 0x02; // subtype: Route Target
        b[2..4].copy_from_slice(&asn.to_be_bytes());
        b[4..8].copy_from_slice(&value.to_be_bytes());
        ExtendedCommunity::new(u64::from_be_bytes(b))
    }

    /// Build a 2-octet AS specific Route Origin EC.
    fn make_ro(asn: u16, value: u32) -> ExtendedCommunity {
        let mut b = [0u8; 8];
        b[0] = 0x00;
        b[1] = 0x03; // subtype: Route Origin
        b[2..4].copy_from_slice(&asn.to_be_bytes());
        b[4..8].copy_from_slice(&value.to_be_bytes());
        ExtendedCommunity::new(u64::from_be_bytes(b))
    }

    // -----------------------------------------------------------------------
    // Existing prefix-only tests (updated with match_community: vec![])
    // -----------------------------------------------------------------------

    #[test]
    fn exact_match_permit() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: None,
                le: None,
                action: PolicyAction::Permit,
                match_community: vec![],
            }],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &[]),
            PolicyAction::Permit
        );
        // /24 inside 10.0.0.0/8 but exact match requires len==8
        assert_eq!(
            pl.evaluate(v4_prefix([10, 1, 0, 0], 24), &[]),
            PolicyAction::Deny
        );
    }

    #[test]
    fn ge_le_range() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: Some(16),
                le: Some(24),
                action: PolicyAction::Permit,
                match_community: vec![],
            }],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &[]),
            PolicyAction::Deny
        );
        assert_eq!(
            pl.evaluate(v4_prefix([10, 1, 0, 0], 16), &[]),
            PolicyAction::Permit
        );
        assert_eq!(
            pl.evaluate(v4_prefix([10, 1, 2, 0], 24), &[]),
            PolicyAction::Permit
        );
        assert_eq!(
            pl.evaluate(v4_prefix([10, 1, 2, 0], 25), &[]),
            PolicyAction::Deny
        );
    }

    #[test]
    fn ge_only() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(v4_entry([192, 168, 0, 0], 16)),
                ge: Some(24),
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 1, 0], 24), &[]),
            PolicyAction::Deny
        );
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 1, 128], 32), &[]),
            PolicyAction::Deny
        );
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 0, 0], 16), &[]),
            PolicyAction::Permit
        );
    }

    #[test]
    fn le_only() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(v4_entry([172, 16, 0, 0], 12)),
                ge: None,
                le: Some(16),
                action: PolicyAction::Permit,
                match_community: vec![],
            }],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([172, 16, 0, 0], 12), &[]),
            PolicyAction::Permit
        );
        assert_eq!(
            pl.evaluate(v4_prefix([172, 16, 0, 0], 16), &[]),
            PolicyAction::Permit
        );
        assert_eq!(
            pl.evaluate(v4_prefix([172, 16, 1, 0], 24), &[]),
            PolicyAction::Deny
        );
    }

    #[test]
    fn default_action_used_when_no_match() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 0, 0], 16), &[]),
            PolicyAction::Permit
        );
    }

    #[test]
    fn empty_list_uses_default() {
        let pl = PrefixList {
            entries: vec![],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &[]),
            PolicyAction::Deny
        );
    }

    #[test]
    fn first_match_wins() {
        let pl = PrefixList {
            entries: vec![
                PrefixListEntry {
                    prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                    ge: None,
                    le: None,
                    action: PolicyAction::Deny,
                    match_community: vec![],
                },
                PrefixListEntry {
                    prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                    ge: None,
                    le: None,
                    action: PolicyAction::Permit,
                    match_community: vec![],
                },
            ],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &[]),
            PolicyAction::Deny
        );
    }

    #[test]
    fn check_prefix_list_none_permits() {
        assert_eq!(
            check_prefix_list(None, v4_prefix([10, 0, 0, 0], 8), &[]),
            PolicyAction::Permit
        );
    }

    #[test]
    fn non_overlapping_prefix_no_match() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: Some(8),
                le: Some(32),
                action: PolicyAction::Deny,
                match_community: vec![],
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 0, 0], 16), &[]),
            PolicyAction::Permit
        );
    }

    #[test]
    fn v6_exact_match() {
        use rustbgpd_wire::Ipv6Prefix;

        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(Prefix::V6(Ipv6Prefix::new(
                    "2001:db8::".parse().unwrap(),
                    32,
                ))),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(
                Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
                &[]
            ),
            PolicyAction::Deny
        );
        // Different prefix length — no match
        assert_eq!(
            pl.evaluate(
                Prefix::V6(Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48)),
                &[]
            ),
            PolicyAction::Permit
        );
    }

    #[test]
    fn v6_afi_mismatch_no_match() {
        use rustbgpd_wire::Ipv6Prefix;

        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(Prefix::V6(Ipv6Prefix::new(
                    "2001:db8::".parse().unwrap(),
                    32,
                ))),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
            }],
            default_action: PolicyAction::Permit,
        };
        // IPv4 prefix doesn't match IPv6 entry
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &[]),
            PolicyAction::Permit
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
    fn parse_community_match_too_few_parts() {
        assert!(parse_community_match("RT:1").is_err());
    }

    #[test]
    fn parse_community_match_invalid_global() {
        assert!(parse_community_match("RT:not-a-number:1").is_err());
    }

    #[test]
    fn parse_community_match_invalid_local() {
        assert!(parse_community_match("RT:1:not-a-number").is_err());
    }

    // -----------------------------------------------------------------------
    // Community matching tests
    // -----------------------------------------------------------------------

    #[test]
    fn community_only_entry_matches() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![CommunityMatch::RouteTarget {
                    global: 65001,
                    local: 100,
                }],
            }],
            default_action: PolicyAction::Permit,
        };
        let ecs = [make_rt(65001, 100)];
        // Any prefix with the matching RT should be denied
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &ecs),
            PolicyAction::Deny
        );
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 0, 0], 16), &ecs),
            PolicyAction::Deny
        );
    }

    #[test]
    fn community_only_entry_no_match() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![CommunityMatch::RouteTarget {
                    global: 65001,
                    local: 100,
                }],
            }],
            default_action: PolicyAction::Permit,
        };
        // Route has RT:65002:200 — doesn't match RT:65001:100
        let ecs = [make_rt(65002, 200)];
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &ecs),
            PolicyAction::Permit
        );
    }

    #[test]
    fn prefix_and_community_both_required() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![CommunityMatch::RouteTarget {
                    global: 65001,
                    local: 100,
                }],
            }],
            default_action: PolicyAction::Permit,
        };
        let ecs = [make_rt(65001, 100)];
        // Both prefix and community match → deny
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &ecs),
            PolicyAction::Deny
        );
    }

    #[test]
    fn prefix_and_community_prefix_fails() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![CommunityMatch::RouteTarget {
                    global: 65001,
                    local: 100,
                }],
            }],
            default_action: PolicyAction::Permit,
        };
        let ecs = [make_rt(65001, 100)];
        // Community matches but prefix doesn't → permit (default)
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 0, 0], 16), &ecs),
            PolicyAction::Permit
        );
    }

    #[test]
    fn prefix_and_community_community_fails() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![CommunityMatch::RouteTarget {
                    global: 65001,
                    local: 100,
                }],
            }],
            default_action: PolicyAction::Permit,
        };
        // Prefix matches but community doesn't → permit (default)
        let ecs = [make_rt(65002, 200)];
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &ecs),
            PolicyAction::Permit
        );
    }

    #[test]
    fn multiple_communities_or() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![
                    CommunityMatch::RouteTarget {
                        global: 65001,
                        local: 100,
                    },
                    CommunityMatch::RouteTarget {
                        global: 65001,
                        local: 200,
                    },
                ],
            }],
            default_action: PolicyAction::Permit,
        };
        // Route has RT:65001:200 — matches second criterion
        let ecs = [make_rt(65001, 200)];
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &ecs),
            PolicyAction::Deny
        );
    }

    #[test]
    fn community_match_route_origin() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![CommunityMatch::RouteOrigin {
                    global: 65001,
                    local: 100,
                }],
            }],
            default_action: PolicyAction::Permit,
        };
        // RT doesn't match RO criterion
        let target_ecs = [make_rt(65001, 100)];
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &target_ecs),
            PolicyAction::Permit
        );
        // RO matches
        let origin_ecs = [make_ro(65001, 100)];
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &origin_ecs),
            PolicyAction::Deny
        );
    }

    #[test]
    fn backward_compat_prefix_only_empty_ecs() {
        // Existing prefix-only entries still work with empty EC slices
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Some(v4_entry([10, 0, 0, 0], 8)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &[]),
            PolicyAction::Deny
        );
    }

    #[test]
    fn community_no_match_on_empty_route_ecs() {
        // Community-match entry should not match a route with no ECs
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: None,
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![CommunityMatch::RouteTarget {
                    global: 65001,
                    local: 100,
                }],
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8), &[]),
            PolicyAction::Permit
        );
    }
}
