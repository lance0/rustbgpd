use std::collections::HashSet;
use std::net::IpAddr;

use rustbgpd_wire::{Afi, Prefix, Safi};
use tracing::info;

use super::RibManager;
use super::helpers::gauge_val;

impl RibManager {
    /// Sweep stale routes for a peer whose GR timer has expired.
    ///
    /// Two-phase timer (RFC 9494): if LLGR is configured for this peer,
    /// promote GR-stale routes to LLGR-stale instead of purging.
    pub(super) fn sweep_gr_stale(&mut self, peer: IpAddr) {
        let gr_families: Vec<(Afi, Safi)> = self
            .gr_peers
            .remove(&peer)
            .unwrap_or_default()
            .into_iter()
            .collect();
        self.gr_stale_deadlines.remove(&peer);
        self.gr_stale_routes_time.remove(&peer);
        let peer_label = peer.to_string();
        self.metrics.record_gr_timer_expired(&peer_label);

        // Check if LLGR applies
        if let Some(llgr_config) = self.llgr_peer_config.remove(&peer)
            && llgr_config.peer_llgr_capable
            && llgr_config.local_llgr_stale_time > 0
        {
            info!(%peer, "GR timer expired — promoting to LLGR stale phase");

            // Only promote families that are in BOTH the GR and LLGR capability sets.
            let llgr_family_set: HashSet<(Afi, Safi)> = llgr_config
                .peer_llgr_families
                .iter()
                .map(|f| (f.afi, f.safi))
                .collect();
            let llgr_families: Vec<(Afi, Safi)> = gr_families
                .iter()
                .copied()
                .filter(|f| llgr_family_set.contains(f))
                .collect();
            let non_llgr_families: Vec<(Afi, Safi)> = gr_families
                .iter()
                .copied()
                .filter(|f| !llgr_family_set.contains(f))
                .collect();

            // Compute effective stale time: min(local, peer per-family minimum)
            let peer_min_stale = llgr_config
                .peer_llgr_families
                .iter()
                .filter(|f| llgr_families.contains(&(f.afi, f.safi)))
                .map(|f| f.stale_time)
                .min()
                .unwrap_or(llgr_config.local_llgr_stale_time);
            let effective_stale_time = peer_min_stale.min(llgr_config.local_llgr_stale_time);

            let mut affected = HashSet::new();
            let mut rib_len = 0;
            if let Some(rib) = self.ribs.get_mut(&peer) {
                // Promote LLGR-negotiated families to LLGR-stale
                for &family in &llgr_families {
                    let promoted = rib.promote_to_llgr_stale(family);
                    for p in promoted {
                        affected.insert(p);
                    }
                }
                // Sweep families NOT in LLGR — these cannot be preserved
                for &family in &non_llgr_families {
                    let swept = rib.sweep_stale_family(family);
                    for p in swept {
                        affected.insert(p);
                    }
                }
                rib_len = rib.len();
            }
            if !non_llgr_families.is_empty() {
                info!(%peer, families = ?non_llgr_families, "swept stale routes for non-LLGR families");
            }
            if !affected.is_empty() {
                info!(%peer, count = affected.len(), "promoted routes to LLGR stale");
                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed, &affected);
            }
            self.metrics
                .set_rib_prefixes(&peer_label, "all", gauge_val(rib_len));

            // Set LLGR timer
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_secs(u64::from(effective_stale_time));
            self.llgr_stale_deadlines.insert(peer, deadline);
            self.llgr_peers
                .insert(peer, llgr_families.into_iter().collect());
            // GR remains "active" for metrics until LLGR completes
            return;
        }

        // No LLGR — purge stale routes
        info!(%peer, "graceful restart timer expired — sweeping stale routes");
        self.metrics.set_gr_active(&peer_label, false);
        self.metrics.set_gr_stale_routes(&peer_label, 0);

        if let Some(rib) = self.ribs.get_mut(&peer) {
            let swept = rib.sweep_stale();
            if !swept.is_empty() {
                info!(%peer, count = swept.len(), "swept stale routes");
                let affected: HashSet<Prefix> = swept.into_iter().collect();
                self.metrics
                    .set_rib_prefixes(&peer_label, "all", gauge_val(rib.len()));
                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed, &affected);
            }
        }
    }

    /// Sweep LLGR-stale routes for a peer whose LLGR timer has expired.
    pub(super) fn sweep_llgr_stale(&mut self, peer: IpAddr) {
        info!(%peer, "LLGR timer expired — sweeping LLGR-stale routes");
        self.llgr_peers.remove(&peer);
        self.llgr_stale_deadlines.remove(&peer);
        let peer_label = peer.to_string();
        self.metrics.set_gr_active(&peer_label, false);
        self.metrics.set_gr_stale_routes(&peer_label, 0);

        if let Some(rib) = self.ribs.get_mut(&peer) {
            let swept = rib.sweep_llgr_stale();
            if !swept.is_empty() {
                info!(%peer, count = swept.len(), "swept LLGR-stale routes");
                let affected: HashSet<Prefix> = swept.into_iter().collect();
                self.metrics
                    .set_rib_prefixes(&peer_label, "all", gauge_val(rib.len()));
                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed, &affected);
            }
        }
    }

    /// Find the nearest GR stale deadline, if any.
    pub(super) fn next_gr_deadline(&self) -> Option<tokio::time::Instant> {
        self.gr_stale_deadlines.values().copied().min()
    }

    /// Find the nearest LLGR stale deadline, if any.
    pub(super) fn next_llgr_deadline(&self) -> Option<tokio::time::Instant> {
        self.llgr_stale_deadlines.values().copied().min()
    }

    /// Find the nearest enhanced route refresh deadline, if any.
    pub(super) fn next_refresh_deadline(&self) -> Option<tokio::time::Instant> {
        self.refresh_deadlines.values().copied().min()
    }

    /// Sweep any inbound enhanced route refresh windows whose deadline has
    /// expired.
    pub(super) fn expire_refresh_windows(&mut self) {
        let now = tokio::time::Instant::now();
        let expired: Vec<(IpAddr, Afi, Safi)> = self
            .refresh_deadlines
            .iter()
            .filter(|&(_, &deadline)| deadline <= now)
            .map(|(&(peer, afi, safi), _)| (peer, afi, safi))
            .collect();
        for (peer, afi, safi) in expired {
            self.finish_route_refresh(peer, afi, safi, true);
        }
    }
}
