use rustbgpd_wire::Ipv4Prefix;

/// Action taken when a prefix matches a policy entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Permit,
    Deny,
}

/// A single entry in a prefix list.
#[derive(Debug, Clone)]
pub struct PrefixListEntry {
    pub prefix: Ipv4Prefix,
    /// Minimum prefix length (inclusive). If `None`, exact match on `prefix.len`.
    pub ge: Option<u8>,
    /// Maximum prefix length (inclusive). If `None`, defaults to 32.
    pub le: Option<u8>,
    pub action: PolicyAction,
}

impl PrefixListEntry {
    /// Check whether `candidate` matches this entry.
    ///
    /// A prefix matches if:
    /// 1. The candidate's network bits (up to `self.prefix.len`) match `self.prefix`
    /// 2. The candidate's prefix length falls within `[ge, le]`
    ///    (or exactly equals `self.prefix.len` when neither ge nor le is set)
    fn matches(&self, candidate: Ipv4Prefix) -> bool {
        // Check network bits: the candidate must be a subnet of our entry prefix
        let entry_bits = u32::from(self.prefix.addr);
        let cand_bits = u32::from(candidate.addr);

        if self.prefix.len > 0 {
            let mask = !((1u32 << (32 - self.prefix.len)) - 1);
            if (entry_bits & mask) != (cand_bits & mask) {
                return false;
            }
        }

        // Check prefix length range
        let (min_len, max_len) = match (self.ge, self.le) {
            (None, None) => (self.prefix.len, self.prefix.len),
            (Some(ge), None) => (ge, 32),
            (None, Some(le)) => (self.prefix.len, le),
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
    pub fn evaluate(&self, prefix: Ipv4Prefix) -> PolicyAction {
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
pub fn check_prefix_list(list: Option<&PrefixList>, prefix: Ipv4Prefix) -> PolicyAction {
    match list {
        Some(pl) => pl.evaluate(prefix),
        None => PolicyAction::Permit,
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn prefix(addr: [u8; 4], len: u8) -> Ipv4Prefix {
        Ipv4Prefix::new(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]), len)
    }

    #[test]
    fn exact_match_permit() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: prefix([10, 0, 0, 0], 8),
                ge: None,
                le: None,
                action: PolicyAction::Permit,
            }],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(pl.evaluate(prefix([10, 0, 0, 0], 8)), PolicyAction::Permit);
        // /24 inside 10.0.0.0/8 but exact match requires len==8
        assert_eq!(pl.evaluate(prefix([10, 1, 0, 0], 24)), PolicyAction::Deny);
    }

    #[test]
    fn ge_le_range() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: prefix([10, 0, 0, 0], 8),
                ge: Some(16),
                le: Some(24),
                action: PolicyAction::Permit,
            }],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(pl.evaluate(prefix([10, 0, 0, 0], 8)), PolicyAction::Deny);
        assert_eq!(pl.evaluate(prefix([10, 1, 0, 0], 16)), PolicyAction::Permit);
        assert_eq!(pl.evaluate(prefix([10, 1, 2, 0], 24)), PolicyAction::Permit);
        assert_eq!(pl.evaluate(prefix([10, 1, 2, 0], 25)), PolicyAction::Deny);
    }

    #[test]
    fn ge_only() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: prefix([192, 168, 0, 0], 16),
                ge: Some(24),
                le: None,
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        };
        // /24 and longer are denied
        assert_eq!(
            pl.evaluate(prefix([192, 168, 1, 0], 24)),
            PolicyAction::Deny
        );
        assert_eq!(
            pl.evaluate(prefix([192, 168, 1, 128], 32)),
            PolicyAction::Deny
        );
        // /16 is shorter than ge=24
        assert_eq!(
            pl.evaluate(prefix([192, 168, 0, 0], 16)),
            PolicyAction::Permit
        );
    }

    #[test]
    fn le_only() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: prefix([172, 16, 0, 0], 12),
                ge: None,
                le: Some(16),
                action: PolicyAction::Permit,
            }],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(
            pl.evaluate(prefix([172, 16, 0, 0], 12)),
            PolicyAction::Permit
        );
        assert_eq!(
            pl.evaluate(prefix([172, 16, 0, 0], 16)),
            PolicyAction::Permit
        );
        assert_eq!(pl.evaluate(prefix([172, 16, 1, 0], 24)), PolicyAction::Deny);
    }

    #[test]
    fn default_action_used_when_no_match() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: prefix([10, 0, 0, 0], 8),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        };
        assert_eq!(
            pl.evaluate(prefix([192, 168, 0, 0], 16)),
            PolicyAction::Permit
        );
    }

    #[test]
    fn empty_list_uses_default() {
        let pl = PrefixList {
            entries: vec![],
            default_action: PolicyAction::Deny,
        };
        assert_eq!(pl.evaluate(prefix([10, 0, 0, 0], 8)), PolicyAction::Deny);
    }

    #[test]
    fn first_match_wins() {
        let pl = PrefixList {
            entries: vec![
                PrefixListEntry {
                    prefix: prefix([10, 0, 0, 0], 8),
                    ge: None,
                    le: None,
                    action: PolicyAction::Deny,
                },
                PrefixListEntry {
                    prefix: prefix([10, 0, 0, 0], 8),
                    ge: None,
                    le: None,
                    action: PolicyAction::Permit,
                },
            ],
            default_action: PolicyAction::Permit,
        };
        // First entry matches and denies
        assert_eq!(pl.evaluate(prefix([10, 0, 0, 0], 8)), PolicyAction::Deny);
    }

    #[test]
    fn check_prefix_list_none_permits() {
        assert_eq!(
            check_prefix_list(None, prefix([10, 0, 0, 0], 8)),
            PolicyAction::Permit
        );
    }

    #[test]
    fn non_overlapping_prefix_no_match() {
        let pl = PrefixList {
            entries: vec![PrefixListEntry {
                prefix: prefix([10, 0, 0, 0], 8),
                ge: Some(8),
                le: Some(32),
                action: PolicyAction::Deny,
            }],
            default_action: PolicyAction::Permit,
        };
        // 192.168.0.0/16 does not overlap 10.0.0.0/8
        assert_eq!(
            pl.evaluate(prefix([192, 168, 0, 0], 16)),
            PolicyAction::Permit
        );
    }
}
