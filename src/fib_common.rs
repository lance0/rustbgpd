//! Shared FIB family-membership helpers used by the pure ADR-0061
//! intent/diff model (`crate::fib`) and the Linux runtime
//! (`crate::fib_runtime`). Kept in one place so the family-eligibility
//! and same-family predicates can't drift between the two layers.

use std::net::IpAddr;

use rustbgpd_wire::Prefix;

use crate::config::FibTableConfig;

/// True when the configured `[[fib_tables]]` entry permits the
/// prefix's family (`ipv4_unicast` / `ipv6_unicast`).
pub(crate) fn table_allows_prefix(table: &FibTableConfig, prefix: Prefix) -> bool {
    let wanted = match prefix {
        Prefix::V4(_) => "ipv4_unicast",
        Prefix::V6(_) => "ipv6_unicast",
    };
    table.families.iter().any(|family| family == wanted)
}

/// True when the prefix and next-hop are the same address family.
/// ADR-0061 does not support RFC 5549 v4-NLRI-over-v6-next-hop in the
/// first tranche; mixed-family routes are projection drops.
pub(crate) fn prefix_and_nexthop_same_family(prefix: Prefix, next_hop: IpAddr) -> bool {
    matches!(
        (prefix, next_hop),
        (Prefix::V4(_), IpAddr::V4(_)) | (Prefix::V6(_), IpAddr::V6(_))
    )
}
