use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use rustbgpd_rpki::VrpTable;
use rustbgpd_wire::{Afi, EvpnRouteKey, FlowSpecRule, Prefix, Safi};
use tracing::info;

use super::RibManager;
use super::helpers::{LlgrPeerConfig, gauge_val, validate_route_aspa, validate_route_rpki};

impl RibManager {
    #[expect(clippy::too_many_arguments)]
    pub(super) fn handle_peer_graceful_restart(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        restart_time: u16,
        stale_routes_time: u64,
        gr_families: Vec<(Afi, Safi)>,
        peer_llgr_capable: bool,
        peer_llgr_families: Vec<rustbgpd_wire::LlgrFamily>,
        llgr_stale_time: u32,
    ) {
        // Same session-identity dispatch as `handle_peer_down`: a GR-down
        // from a superseded session (RFC 4271 §6.8 collision loser
        // processed after the winner's `PeerUp`) must not mark the
        // surviving session's routes stale or deregister its outbound
        // sender. A GR-down of the ACTIVE session while another live
        // session remains fails the registration over instead of entering
        // GR retention: stale-path retention exists to bridge a session
        // that is gone, but here an Established session for the address
        // is present and can be refreshed immediately — strictly better
        // than deadline-bounded staleness for a session that is not
        // coming back. When the id matches the registered session and no
        // other live session exists, GR stale-path retention proceeds
        // exactly as before stamping.
        use super::peer_lifecycle::SessionTeardownDisposition;
        match self.classify_session_teardown(peer, session_id, "PeerGracefulRestart") {
            SessionTeardownDisposition::DiscardStale => return,
            SessionTeardownDisposition::FailOver => {
                self.fail_over_registration(peer, session_id, "PeerGracefulRestart");
                return;
            }
            SessionTeardownDisposition::NoRegistration
            | SessionTeardownDisposition::TeardownActive => {}
        }

        info!(%peer, restart_time, stale_routes_time, llgr_stale_time, "peer entered graceful restart");

        let mut affected = HashSet::new();
        let mut fs_affected = HashSet::new();
        let mut evpn_affected: HashSet<EvpnRouteKey> = HashSet::new();

        if let Some(rib) = self.ribs.get_mut(&peer) {
            // EVPN has a single family tuple, so the inner mark_stale_evpn
            // call is identical for every entry in `gr_families`. Hoist
            // it out of the loop and call once when (L2Vpn, Evpn) is
            // among the GR-preserved families.
            for &family in &gr_families {
                rib.mark_stale(family);
                rib.mark_stale_flowspec(family);
            }
            if gr_families.contains(&(Afi::L2Vpn, Safi::Evpn)) {
                rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn));
            }
            let withdrawn = rib.withdraw_families_except(&gr_families);
            if !withdrawn.is_empty() {
                info!(%peer, count = withdrawn.len(), "withdrew non-GR family routes");
            }
            for prefix in withdrawn {
                affected.insert(prefix);
            }
            // EVPN has a single family tuple; sweep all EVPN routes if
            // the peer didn't advertise GR for (L2Vpn, Evpn).
            if !gr_families.contains(&(Afi::L2Vpn, Safi::Evpn)) {
                let withdrawn_evpn = rib.sweep_stale_evpn();
                // Also gather any non-stale EVPN routes that must be
                // dropped entirely; sweep_stale_evpn only removes stale
                // ones, so collect remaining keys here.
                let remaining: Vec<EvpnRouteKey> = rib
                    .iter_evpn()
                    .map(crate::route::EvpnRibRoute::key)
                    .collect();
                for key in remaining {
                    rib.withdraw_evpn(&key);
                    evpn_affected.insert(key);
                }
                for key in withdrawn_evpn {
                    evpn_affected.insert(key);
                }
            }
        }

        if let Some(rib) = self.ribs.get(&peer) {
            for route in rib.iter() {
                affected.insert(route.prefix);
            }
            for route in rib.iter_flowspec() {
                if gr_families.contains(&(route.afi, Safi::FlowSpec)) {
                    fs_affected.insert(route.rule.clone());
                }
            }
            if gr_families.contains(&(Afi::L2Vpn, Safi::Evpn)) {
                for route in rib.iter_evpn() {
                    evpn_affected.insert(route.key());
                }
            }
            self.metrics
                .set_rib_prefixes(&peer.to_string(), "all", gauge_val(rib.len()));
            self.metrics
                .set_rib_prefixes(&peer.to_string(), "evpn", gauge_val(rib.evpn_len()));
        }

        let changed = self.recompute_best(&affected);
        self.distribute_changes(&changed, &affected);
        if !fs_affected.is_empty() {
            self.recompute_and_distribute_flowspec(&fs_affected);
        }
        if !evpn_affected.is_empty() {
            self.recompute_and_distribute_evpn(&evpn_affected);
        }

        // Shared per-session outbound teardown (Adj-RIB-Out, export
        // policies/stats, ORF filter + gate, refresh state, ...). Peer
        // identity maps survive — the peer is expected back under GR.
        self.clear_outbound_peer_state(peer);

        let deadline =
            tokio::time::Instant::now() + std::time::Duration::from_secs(u64::from(restart_time));
        self.gr_stale_deadlines.insert(peer, deadline);
        self.gr_stale_routes_time.insert(peer, stale_routes_time);
        self.gr_peers
            .insert(peer, gr_families.into_iter().collect());

        if peer_llgr_capable && llgr_stale_time > 0 {
            self.llgr_peer_config.insert(
                peer,
                LlgrPeerConfig {
                    peer_llgr_capable,
                    peer_llgr_families,
                    local_llgr_stale_time: llgr_stale_time,
                    stale_routes_time,
                },
            );
        }

        let peer_label = peer.to_string();
        self.metrics.set_gr_active(&peer_label, true);
        let stale_count = self.ribs.get(&peer).map_or(0, |rib| {
            rib.iter().filter(|r| r.is_stale).count()
                + rib.iter_flowspec().filter(|r| r.is_stale).count()
                + rib.iter_evpn().filter(|r| r.is_stale).count()
        });
        self.metrics
            .set_gr_stale_routes(&peer_label, gauge_val(stale_count));
    }

    pub(super) fn handle_rpki_cache_update(&mut self, table: Arc<VrpTable>) {
        info!(
            vrps = table.len(),
            "RPKI cache update — re-validating routes"
        );
        self.vrp_table = Some(table);
        let Some(table) = self.vrp_table.as_ref() else {
            return;
        };
        self.metrics
            .set_rpki_vrp_count("ipv4", gauge_val(table.v4_count()));
        self.metrics
            .set_rpki_vrp_count("ipv6", gauge_val(table.v6_count()));

        let mut affected = HashSet::new();
        for rib in self.ribs.values_mut() {
            for route in rib.iter_mut() {
                let new_state = validate_route_rpki(route, table);
                if route.validation_state != new_state {
                    route.validation_state = new_state;
                    affected.insert(route.prefix);
                }
            }
        }

        if !affected.is_empty() {
            info!(
                changed = affected.len(),
                "RPKI re-validation changed routes"
            );
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
        }
    }

    pub(super) fn handle_aspa_cache_update(&mut self, table: Arc<rustbgpd_rpki::AspaTable>) {
        info!(
            records = table.len(),
            "ASPA cache update — re-validating routes"
        );
        self.aspa_table = Some(table);
        let Some(table) = self.aspa_table.as_ref() else {
            return;
        };
        self.metrics.set_aspa_records_total(gauge_val(table.len()));

        let mut affected = HashSet::new();
        for rib in self.ribs.values_mut() {
            for route in rib.iter_mut() {
                let new_state = validate_route_aspa(route, table);
                if route.aspa_state != new_state {
                    route.aspa_state = new_state;
                    affected.insert(route.prefix);
                }
            }
        }

        if !affected.is_empty() {
            info!(
                changed = affected.len(),
                "ASPA re-validation changed routes"
            );
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
        }
    }

    /// Sweep stale routes for a peer whose GR timer has expired.
    ///
    /// Two-phase timer (RFC 9494): if LLGR is configured for this peer,
    /// promote GR-stale routes to LLGR-stale instead of purging.
    #[expect(
        clippy::too_many_lines,
        reason = "LLGR promotion has unicast + FlowSpec paths"
    )]
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

        // Check if LLGR applies. Read — don't consume — the config: the
        // entry must survive the LLGR stale phase so that a peer
        // re-establishing during LLGR gets its captured stale_routes_time
        // (`handle_peer_up`) instead of the 360 s default, and so a second
        // GR-deadline expiry can re-promote. Terminal points remove it:
        // End-of-RIB completion, `sweep_llgr_stale`, the no-LLGR purge
        // below, and `handle_peer_down`.
        let llgr_config = self
            .llgr_peer_config
            .get(&peer)
            .filter(|c| c.peer_llgr_capable && c.local_llgr_stale_time > 0)
            .cloned();
        if let Some(llgr_config) = llgr_config {
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
            let mut fs_affected = HashSet::new();
            let mut evpn_affected: HashSet<EvpnRouteKey> = HashSet::new();
            let mut rib_len = 0;
            let mut evpn_len = 0;
            if let Some(rib) = self.ribs.get_mut(&peer) {
                // Promote LLGR-negotiated families to LLGR-stale
                for &family in &llgr_families {
                    let promoted = rib.promote_to_llgr_stale(family);
                    for p in promoted {
                        affected.insert(p);
                    }
                    let fs_promoted = rib.promote_to_llgr_stale_flowspec(family);
                    for r in fs_promoted {
                        fs_affected.insert(r);
                    }
                    let evpn_promoted = rib.promote_to_llgr_stale_evpn(family);
                    for k in evpn_promoted {
                        evpn_affected.insert(k);
                    }
                }
                // Sweep families NOT in LLGR — these cannot be preserved
                for &family in &non_llgr_families {
                    let swept = rib.sweep_stale_family(family);
                    for p in swept {
                        affected.insert(p);
                    }
                    let fs_swept = rib.sweep_stale_flowspec_family(family);
                    for r in fs_swept {
                        fs_affected.insert(r);
                    }
                    let evpn_swept = rib.sweep_stale_family_evpn(family);
                    for k in evpn_swept {
                        evpn_affected.insert(k);
                    }
                }
                rib_len = rib.len();
                evpn_len = rib.evpn_len();
                // GC the attribute intern table once per pass: LLGR
                // promotion adds the LLGR_STALE community (so the route's
                // attribute Arc is replaced) and non-LLGR sweeps drop
                // routes outright. Both leave the prior interned vectors
                // with strong_count==1, which sticks until some later
                // unicast withdraw happens to call gc_intern_table.
                rib.gc_intern_table();
            }
            if !non_llgr_families.is_empty() {
                info!(%peer, families = ?non_llgr_families, "swept stale routes for non-LLGR families");
            }
            if !affected.is_empty() {
                info!(%peer, count = affected.len(), "promoted routes to LLGR stale");
                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed, &affected);
            }
            if !fs_affected.is_empty() {
                self.recompute_and_distribute_flowspec(&fs_affected);
            }
            if !evpn_affected.is_empty() {
                self.recompute_and_distribute_evpn(&evpn_affected);
            }
            self.metrics
                .set_rib_prefixes(&peer_label, "all", gauge_val(rib_len));
            self.metrics
                .set_rib_prefixes(&peer_label, "evpn", gauge_val(evpn_len));

            // Set LLGR timer
            let deadline = tokio::time::Instant::now()
                + std::time::Duration::from_secs(u64::from(effective_stale_time));
            self.llgr_stale_deadlines.insert(peer, deadline);
            self.llgr_peers
                .insert(peer, llgr_families.into_iter().collect());
            // GR remains "active" for metrics until LLGR completes
            return;
        }

        // No LLGR — purge stale routes. Drop any LLGR config entry that
        // failed the promotion gate above (insertion is gated identically,
        // so this is defensive — but the map must not outlive GR).
        self.llgr_peer_config.remove(&peer);
        info!(%peer, "graceful restart timer expired — sweeping stale routes");
        self.metrics.set_gr_active(&peer_label, false);
        self.metrics.set_gr_stale_routes(&peer_label, 0);

        let (swept, fs_swept, evpn_swept, rib_len, evpn_len) =
            if let Some(rib) = self.ribs.get_mut(&peer) {
                let swept = rib.sweep_stale();
                let fs_swept = rib.sweep_stale_flowspec();
                let evpn_swept = rib.sweep_stale_evpn();
                rib.gc_intern_table();
                (swept, fs_swept, evpn_swept, rib.len(), rib.evpn_len())
            } else {
                (Vec::new(), Vec::new(), Vec::new(), 0, 0)
            };
        if !swept.is_empty() {
            info!(%peer, count = swept.len(), "swept stale routes");
            let affected: HashSet<Prefix> = swept.into_iter().collect();
            self.metrics
                .set_rib_prefixes(&peer_label, "all", gauge_val(rib_len));
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
        }
        if !fs_swept.is_empty() {
            let fs_affected: HashSet<FlowSpecRule> = fs_swept.into_iter().collect();
            self.recompute_and_distribute_flowspec(&fs_affected);
        }
        if !evpn_swept.is_empty() {
            let evpn_affected: HashSet<EvpnRouteKey> = evpn_swept.into_iter().collect();
            self.metrics
                .set_rib_prefixes(&peer_label, "evpn", gauge_val(evpn_len));
            self.recompute_and_distribute_evpn(&evpn_affected);
        }

        self.release_peer_state_if_departed(peer);
    }

    /// Sweep LLGR-stale routes for a peer whose LLGR timer has expired.
    pub(super) fn sweep_llgr_stale(&mut self, peer: IpAddr) {
        info!(%peer, "LLGR timer expired — sweeping LLGR-stale routes");
        self.llgr_peers.remove(&peer);
        self.llgr_stale_deadlines.remove(&peer);
        // LLGR is the last retention phase — the per-peer LLGR config has
        // no further reader once the stale routes are swept.
        self.llgr_peer_config.remove(&peer);
        let peer_label = peer.to_string();
        self.metrics.set_gr_active(&peer_label, false);
        self.metrics.set_gr_stale_routes(&peer_label, 0);

        let (swept, fs_swept, evpn_swept, rib_len, evpn_len) =
            if let Some(rib) = self.ribs.get_mut(&peer) {
                let swept = rib.sweep_llgr_stale();
                let fs_swept = rib.sweep_llgr_stale_flowspec();
                let evpn_swept = rib.sweep_llgr_stale_evpn();
                rib.gc_intern_table();
                (swept, fs_swept, evpn_swept, rib.len(), rib.evpn_len())
            } else {
                (Vec::new(), Vec::new(), Vec::new(), 0, 0)
            };
        if !swept.is_empty() {
            info!(%peer, count = swept.len(), "swept LLGR-stale routes");
            let affected: HashSet<Prefix> = swept.into_iter().collect();
            self.metrics
                .set_rib_prefixes(&peer_label, "all", gauge_val(rib_len));
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
        }
        if !fs_swept.is_empty() {
            let fs_affected: HashSet<FlowSpecRule> = fs_swept.into_iter().collect();
            self.recompute_and_distribute_flowspec(&fs_affected);
        }
        if !evpn_swept.is_empty() {
            let evpn_affected: HashSet<EvpnRouteKey> = evpn_swept.into_iter().collect();
            self.metrics
                .set_rib_prefixes(&peer_label, "evpn", gauge_val(evpn_len));
            self.recompute_and_distribute_evpn(&evpn_affected);
        }

        self.release_peer_state_if_departed(peer);
    }

    /// Release a departed peer's remaining per-peer state once GR/LLGR
    /// retention has expired.
    ///
    /// A GR flap routes session-down through `handle_peer_graceful_restart`,
    /// which deliberately keeps the Adj-RIB-In shell and the identity maps
    /// (`peer_asn` / `peer_bgp_id` / `peer_group` — the MRT `TABLE_DUMP_V2`
    /// peer index reads them) for the returning peer. If the peer never
    /// returns, the expiry sweeps remove only routes, so without this the
    /// empty shell and identity entries would leak forever.
    ///
    /// Re-using the full `PeerDown` teardown is safe here: the caller has
    /// already removed the GR/LLGR maps (its abort arms no-op), the ribs
    /// entry holds only swept-empty state, and the outbound state was
    /// cleared at GR entry (`clear_outbound_peer_state` no-ops). If the
    /// peer DID re-establish (`outbound_peers` is re-inserted by
    /// `handle_peer_up`) and only its End-of-RIB is late, identity and RIB
    /// state must survive the sweep — hence the guard. Retention expiry is
    /// a timer decision, not a session event, so it calls the
    /// unconditional teardown rather than the session-identity-gated
    /// `handle_peer_down` (there is no registered session to match here
    /// anyway — the guard just established that).
    fn release_peer_state_if_departed(&mut self, peer: IpAddr) {
        if !self.outbound_peers.contains_key(&peer) {
            info!(%peer, "GR retention expired without re-establishment — releasing per-peer state");
            self.peer_down_teardown(peer);
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
