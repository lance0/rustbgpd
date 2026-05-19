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

    /// Check whether a peer IP falls within any configured dynamic neighbor range.
    pub(super) fn match_dynamic_range(&self, addr: IpAddr) -> Option<&DynamicRange> {
        self.dynamic_ranges.iter().find(|r| {
            match (addr, r.addr) {
                (IpAddr::V4(peer), IpAddr::V4(net)) => {
                    if r.prefix_len > 32 {
                        return false;
                    }
                    let mask = if r.prefix_len == 0 {
                        0u32
                    } else {
                        u32::MAX << (32 - r.prefix_len)
                    };
                    (u32::from(peer) & mask) == (u32::from(net) & mask)
                }
                (IpAddr::V6(peer), IpAddr::V6(net)) => {
                    if r.prefix_len > 128 {
                        return false;
                    }
                    let mask = if r.prefix_len == 0 {
                        0u128
                    } else {
                        u128::MAX << (128 - r.prefix_len)
                    };
                    (u128::from(peer) & mask) == (u128::from(net) & mask)
                }
                _ => false, // IPv4/IPv6 mismatch
            }
        })
    }

    /// Snapshot any unfired hot-apply / Route Refresh intent for a peer
    /// about to be auto-removed, so a re-establishing peer at the same
    /// address inherits the retry. No-op if neither flag is set.
    /// Bounded at `dynamic_neighbor_limit` — over-cap evicts an
    /// arbitrary entry with `warn!` to surface pathological churn.
    pub(super) fn dead_letter_pending_for(&mut self, peer_addr: IpAddr) {
        let Some(managed) = self.peers.get(&peer_addr) else {
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
        let Some(managed) = self.peers.get_mut(&peer_addr) else {
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
