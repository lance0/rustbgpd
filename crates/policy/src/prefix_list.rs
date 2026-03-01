use rustbgpd_wire::{Ipv4Prefix, Ipv6Prefix, Prefix};

/// Action taken when a prefix matches a policy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Permit,
    Deny,
}

/// A single entry in a prefix list.
#[derive(Debug, Clone)]
pub struct PrefixListEntry {
    pub prefix: Prefix,
    /// Minimum prefix length (inclusive). If `None`, exact match on `prefix.len`.
    pub ge: Option<u8>,
    /// Maximum prefix length (inclusive). If `None`, defaults to max for AFI (32 or 128).
    pub le: Option<u8>,
    pub action: PolicyAction,
}

impl PrefixListEntry {
    /// Check whether `candidate` matches this entry.
    ///
    /// A prefix matches if:
    /// 1. The candidate and entry are the same AFI
    /// 2. The candidate's network bits (up to `self.prefix.len`) match
    /// 3. The candidate's prefix length falls within `[ge, le]`
    ///    (or exactly equals the entry prefix len when neither ge nor le is set)
    fn matches(&self, candidate: Prefix) -> bool {
        match (self.prefix, candidate) {
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

/// An ordered list of prefix-list entries with a default action.
#[derive(Debug, Clone)]
pub struct PrefixList {
    pub entries: Vec<PrefixListEntry>,
    pub default_action: PolicyAction,
}

impl PrefixList {
    /// Evaluate a prefix against this list. First matching entry wins.
    #[must_use]
    pub fn evaluate(&self, prefix: Prefix) -> PolicyAction {
        for entry in &self.entries {
            if entry.matches(prefix) {
                return entry.action;
            }
        }
        self.default_action
    }
}

/// Convenience: evaluate an optional prefix list. Returns `Permit` if no list.
#[must_use]
pub fn check_prefix_list(list: Option<&PrefixList>, prefix: Prefix) -> PolicyAction {
    match list {
        Some(pl) => pl.evaluate(prefix),
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

    #[test]
    fn exact_match_permit() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: v4_entry([10, 0, 0, 0], 8),
                ge: None,
                le: None,
                action: PolicyAction::Permit,
            }],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8)),
            PolicyAction::Permit
        );
        // /24 inside 10.0.0.0/8 but exact match requires len==8
        assert_eq!(
            pl.evaluate(v4_prefix([10, 1, 0, 0], 24)),
            PolicyAction::Deny
        );
    }

    #[test]
    fn ge_le_range() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: v4_entry([10, 0, 0, 0], 8),
                ge: Some(16),
                le: Some(24),
                action: PolicyAction::Permit,
            }],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(pl.evaluate(v4_prefix([10, 0, 0, 0], 8)), PolicyAction::Deny);
        assert_eq!(
            pl.evaluate(v4_prefix([10, 1, 0, 0], 16)),
            PolicyAction::Permit
        );
        assert_eq!(
            pl.evaluate(v4_prefix([10, 1, 2, 0], 24)),
            PolicyAction::Permit
        );
        assert_eq!(
            pl.evaluate(v4_prefix([10, 1, 2, 0], 25)),
            PolicyAction::Deny
        );
    }

    #[test]
    fn ge_only() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: v4_entry([192, 168, 0, 0], 16),
                ge: Some(24),
                le: None,
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 1, 0], 24)),
            PolicyAction::Deny
        );
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 1, 128], 32)),
            PolicyAction::Deny
        );
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 0, 0], 16)),
            PolicyAction::Permit
        );
    }

    #[test]
    fn le_only() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: v4_entry([172, 16, 0, 0], 12),
                ge: None,
                le: Some(16),
                action: PolicyAction::Permit,
            }],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([172, 16, 0, 0], 12)),
            PolicyAction::Permit
        );
        assert_eq!(
            pl.evaluate(v4_prefix([172, 16, 0, 0], 16)),
            PolicyAction::Permit
        );
        assert_eq!(
            pl.evaluate(v4_prefix([172, 16, 1, 0], 24)),
            PolicyAction::Deny
        );
    }

    #[test]
    fn default_action_used_when_no_match() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: v4_entry([10, 0, 0, 0], 8),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 0, 0], 16)),
            PolicyAction::Permit
        );
    }

    #[test]
    fn empty_list_uses_default() {
        let pl = PrefixList {
            entries: vec![],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(pl.evaluate(v4_prefix([10, 0, 0, 0], 8)), PolicyAction::Deny);
    }

    #[test]
    fn first_match_wins() {
        let pl = PrefixList {
            entries: vec![
                PrefixListEntry {
                    prefix: v4_entry([10, 0, 0, 0], 8),
                    ge: None,
                    le: None,
                    action: PolicyAction::Deny,
                },
                PrefixListEntry {
                    prefix: v4_entry([10, 0, 0, 0], 8),
                    ge: None,
                    le: None,
                    action: PolicyAction::Permit,
                },
            ],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(pl.evaluate(v4_prefix([10, 0, 0, 0], 8)), PolicyAction::Deny);
    }

    #[test]
    fn check_prefix_list_none_permits() {
        assert_eq!(
            check_prefix_list(None, v4_prefix([10, 0, 0, 0], 8)),
            PolicyAction::Permit
        );
    }

    #[test]
    fn non_overlapping_prefix_no_match() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: v4_entry([10, 0, 0, 0], 8),
                ge: Some(8),
                le: Some(32),
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(v4_prefix([192, 168, 0, 0], 16)),
            PolicyAction::Permit
        );
    }

    #[test]
    fn v6_exact_match() {
        use rustbgpd_wire::Ipv6Prefix;

        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(Prefix::V6(Ipv6Prefix::new(
                "2001:db8::".parse().unwrap(),
                32
            ))),
            PolicyAction::Deny
        );
        // Different prefix length — no match
        assert_eq!(
            pl.evaluate(Prefix::V6(Ipv6Prefix::new(
                "2001:db8:1::".parse().unwrap(),
                48
            ))),
            PolicyAction::Permit
        );
    }

    #[test]
    fn v6_afi_mismatch_no_match() {
        use rustbgpd_wire::Ipv6Prefix;

        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        };
        // IPv4 prefix doesn't match IPv6 entry
        assert_eq!(
            pl.evaluate(v4_prefix([10, 0, 0, 0], 8)),
            PolicyAction::Permit
        );
    }
}
