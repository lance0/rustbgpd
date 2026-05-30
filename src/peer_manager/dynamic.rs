use std::net::IpAddr;

use tracing::{info, warn};

use crate::config::Config;

use super::PeerManager;

/// Resolved dynamic neighbor range used for prefix matching at connection time.
pub(super) struct DynamicRange {
    pub(super) addr: IpAddr,
    pub(super) prefix_len: u8,
    pub(super) peer_group: String,
    pub(super) remote_asn: u32,
    pub(super) description: Option<String>,
}

impl DynamicRange {
    /// True when `addr` falls within this range's prefix.
    fn covers(&self, addr: IpAddr) -> bool {
        match (addr, self.addr) {
            (IpAddr::V4(peer), IpAddr::V4(net)) => {
                if self.prefix_len > 32 {
                    return false;
                }
                let mask = if self.prefix_len == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - self.prefix_len)
                };
                (u32::from(peer) & mask) == (u32::from(net) & mask)
            }
            (IpAddr::V6(peer), IpAddr::V6(net)) => {
                if self.prefix_len > 128 {
                    return false;
                }
                let mask = if self.prefix_len == 0 {
                    0u128
                } else {
                    u128::MAX << (128 - self.prefix_len)
                };
                (u128::from(peer) & mask) == (u128::from(net) & mask)
            }
            _ => false, // IPv4/IPv6 mismatch
        }
    }
}

/// Select the most-specific (longest-prefix) dynamic range covering `addr`.
///
/// Overlapping ranges resolve by prefix length, not declaration order, so a
/// `/24` wins over a `/16` regardless of TOML order — the longest-prefix-match
/// behavior operators expect from FRR/GoBGP. Among equal-length matches (an
/// exact-duplicate prefix, which is a config-level concern) the last declared
/// wins, per `Iterator::max_by_key`.
fn select_dynamic_range(ranges: &[DynamicRange], addr: IpAddr) -> Option<&DynamicRange> {
    ranges
        .iter()
        .filter(|r| r.covers(addr))
        .max_by_key(|r| r.prefix_len)
}

/// Snapshot of a removed dynamic peer's unfired hot-apply intent. Carried
/// across the auto-removal that fires when a dynamic peer goes back to
/// Idle so a re-establishing peer at the same address inherits the retry.
/// Without this, a transient TCP drop on a `[[dynamic_neighbors]]` peer
/// that was mid-`pending_refresh` would silently drop the unfired Route
/// Refresh / export-apply — same correctness risk that
/// `ManagedPeer::pending_refresh` / `pending_export_apply` exist to close.
/// The RFC 8326 initiator toggle lives here too: dynamic auto-removal drops
/// the whole `ManagedPeer`, so this side table is the only place to preserve
/// an operator's maintenance-window `GShut` toggle across re-establishment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct DeadLetteredPending {
    pub(super) refresh: bool,
    pub(super) export_apply: bool,
    pub(super) graceful_shutdown: bool,
}

impl PeerManager {
    pub(super) fn parse_dynamic_ranges(config: &Config) -> Vec<DynamicRange> {
        config
            .dynamic_neighbors
            .iter()
            .filter_map(|dn| {
                let parts: Vec<&str> = dn.prefix.split('/').collect();
                let addr: IpAddr = parts.first()?.parse().ok()?;
                let prefix_len: u8 = parts.get(1)?.parse().ok()?;
                Some(DynamicRange {
                    addr,
                    prefix_len,
                    peer_group: dn.peer_group.clone(),
                    remote_asn: dn.remote_asn,
                    description: dn.description.clone(),
                })
            })
            .collect()
    }

    /// Find the dynamic neighbor range covering `addr`, preferring the
    /// **most specific** (longest-prefix) match when ranges overlap — so a
    /// `/24` wins over a `/16` regardless of TOML declaration order. This is
    /// the longest-prefix-match behavior operators expect from FRR/GoBGP;
    /// first-match-by-declaration-order would make the winning peer-group
    /// depend on config ordering, which surprises operators.
    pub(super) fn match_dynamic_range(&self, addr: IpAddr) -> Option<&DynamicRange> {
        select_dynamic_range(&self.dynamic_ranges, addr)
    }

    /// Snapshot any unfired hot-apply / Route Refresh intent for a peer
    /// about to be auto-removed, so a re-establishing peer at the same
    /// address inherits the retry. No-op if neither flag is set.
    /// Bounded at `dynamic_neighbor_limit` — over-cap evicts an
    /// arbitrary entry with `warn!` to surface pathological churn.
    pub(super) fn dead_letter_pending_for(&mut self, peer_addr: IpAddr) {
        let Some(peer_key) = self.unique_peer_key_for_address(peer_addr) else {
            return;
        };
        let Some(managed) = self.peers.get(&peer_key) else {
            return;
        };
        if !managed.pending_refresh
            && !managed.pending_export_apply
            && !managed.advertise_graceful_shutdown
        {
            return;
        }
        let entry = DeadLetteredPending {
            refresh: managed.pending_refresh,
            export_apply: managed.pending_export_apply,
            graceful_shutdown: managed.advertise_graceful_shutdown,
        };
        let cap = self.dynamic_neighbor_limit as usize;
        if cap > 0
            && !self.dead_lettered_pending.contains_key(&peer_addr)
            && self.dead_lettered_pending.len() >= cap
            && let Some(victim) = self.dead_lettered_pending.keys().next().copied()
        {
            warn!(
                %peer_addr,
                evicted = %victim,
                cap,
                "dead-letter pending table at cap, evicting an existing entry — \
                 dynamic peers churning faster than they re-establish"
            );
            self.dead_lettered_pending.remove(&victim);
        }
        self.dead_lettered_pending.insert(peer_addr, entry);
    }

    /// Drain any dead-lettered hot-apply / Route Refresh intent for a
    /// freshly accepted dynamic peer at this address and apply it to the
    /// new `ManagedPeer`. No-op if no entry exists.
    pub(super) fn restore_dead_lettered_pending(&mut self, peer_addr: IpAddr) {
        let Some(prev) = self.dead_lettered_pending.remove(&peer_addr) else {
            return;
        };
        let Some(managed) = self
            .unique_peer_key_for_address(peer_addr)
            .and_then(|key| self.peers.get_mut(&key))
        else {
            return;
        };
        managed.pending_refresh = prev.refresh;
        managed.pending_export_apply = prev.export_apply;
        managed.advertise_graceful_shutdown = prev.graceful_shutdown;
        info!(
            %peer_addr,
            pending_refresh = prev.refresh,
            pending_export_apply = prev.export_apply,
            advertise_graceful_shutdown = prev.graceful_shutdown,
            "restored dead-lettered hot-apply intent on dynamic peer re-establishment"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::{DynamicRange, select_dynamic_range};

    fn range(prefix: &str, group: &str) -> DynamicRange {
        let (addr, len) = prefix.split_once('/').expect("prefix has a '/'");
        DynamicRange {
            addr: addr.parse().expect("valid IP"),
            prefix_len: len.parse().expect("valid prefix length"),
            peer_group: group.to_string(),
            remote_asn: 65000,
            description: None,
        }
    }

    fn matched_group(ranges: &[DynamicRange], addr: &str) -> Option<String> {
        select_dynamic_range(ranges, addr.parse::<IpAddr>().expect("valid IP"))
            .map(|r| r.peer_group.clone())
    }

    #[test]
    fn most_specific_range_wins_when_wide_declared_first() {
        // /16 declared before the more-specific /24.
        let ranges = vec![range("10.0.0.0/16", "wide"), range("10.0.5.0/24", "narrow")];
        assert_eq!(
            matched_group(&ranges, "10.0.5.7").as_deref(),
            Some("narrow")
        );
        // An address inside the /16 but outside the /24 falls to the wider range.
        assert_eq!(matched_group(&ranges, "10.0.9.7").as_deref(), Some("wide"));
    }

    #[test]
    fn most_specific_range_wins_when_narrow_declared_first() {
        // Reversed declaration order — the result must not depend on it.
        let ranges = vec![range("10.0.5.0/24", "narrow"), range("10.0.0.0/16", "wide")];
        assert_eq!(
            matched_group(&ranges, "10.0.5.7").as_deref(),
            Some("narrow")
        );
        assert_eq!(matched_group(&ranges, "10.0.9.7").as_deref(), Some("wide"));
    }

    #[test]
    fn catch_all_default_route_loses_to_a_more_specific_range() {
        let ranges = vec![range("0.0.0.0/0", "any"), range("192.0.2.0/24", "doc")];
        assert_eq!(matched_group(&ranges, "192.0.2.1").as_deref(), Some("doc"));
        assert_eq!(
            matched_group(&ranges, "203.0.113.9").as_deref(),
            Some("any")
        );
    }

    #[test]
    fn no_match_returns_none_and_v4_v6_do_not_cross() {
        let ranges = vec![range("10.0.0.0/8", "v4"), range("2001:db8::/32", "v6")];
        assert_eq!(matched_group(&ranges, "192.168.1.1"), None);
        // A v6 peer must not match a v4 range, and vice versa.
        assert_eq!(matched_group(&ranges, "2001:db8::1").as_deref(), Some("v6"));
        assert_eq!(matched_group(&ranges, "10.1.2.3").as_deref(), Some("v4"));
    }
}
