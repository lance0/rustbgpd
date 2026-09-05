use std::borrow::Borrow;
use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::net::IpAddr;
use std::ops::Deref;
use std::sync::Arc;

use rustbgpd_rpki::VrpTable;
use rustbgpd_wire::{Afi, EvpnRouteKey, Prefix, Safi};
use tracing::info;

use super::RibManager;
use super::helpers::{
    AspaInvalidHopSummary, LlgrPeerConfig, gauge_val, validate_route_aspa_detailed,
    validate_route_rpki,
};
use crate::route::{BgpLsFamily, BgpLsRouteKey};

/// Deadline registry with a cached minimum. The actor loop probes the
/// nearest GR / LLGR / refresh deadline on every iteration; with the cache
/// that probe is O(1) while the registry is untouched, and the only full
/// scan happens on the first probe after an entry whose deadline equals the
/// cached minimum is removed or overwritten — conservative on ties: any tied
/// entry invalidates, even when another entry still holds that deadline.
/// Inserts fold into the cache directly.
///
/// Reads go through `Deref`; every mutation goes through the methods below
/// so the cache can never be bypassed. Values are never handed out `&mut`.
#[derive(Debug)]
pub(super) struct DeadlineMap<K> {
    map: HashMap<K, tokio::time::Instant>,
    min: Option<tokio::time::Instant>,
    /// True when `min` may be wrong and the next probe must rescan.
    stale: bool,
}

impl<K> Default for DeadlineMap<K> {
    fn default() -> Self {
        Self {
            map: HashMap::new(),
            min: None,
            stale: false,
        }
    }
}

impl<K: Eq + Hash> DeadlineMap<K> {
    pub(super) fn insert(
        &mut self,
        key: K,
        deadline: tokio::time::Instant,
    ) -> Option<tokio::time::Instant> {
        let prev = self.map.insert(key, deadline);
        if let Some(prev) = prev {
            self.note_removed(prev);
        }
        if !self.stale {
            self.min = Some(self.min.map_or(deadline, |min| min.min(deadline)));
        }
        prev
    }

    pub(super) fn remove<Q>(&mut self, key: &Q) -> Option<tokio::time::Instant>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let prev = self.map.remove(key);
        if let Some(prev) = prev {
            self.note_removed(prev);
        }
        prev
    }

    /// Keep only the entries whose key satisfies `keep`.
    pub(super) fn retain(&mut self, mut keep: impl FnMut(&K) -> bool) {
        let before = self.map.len();
        self.map.retain(|key, _| keep(key));
        if self.map.len() != before {
            // The dropped entries are not known here; rescan lazily.
            self.stale = !self.map.is_empty();
            if self.map.is_empty() {
                self.min = None;
            }
        }
    }

    /// Nearest deadline, or `None` when the registry is empty. O(1) unless
    /// the cached minimum was invalidated since the last probe.
    pub(super) fn min(&mut self) -> Option<tokio::time::Instant> {
        if self.stale {
            self.min = self.map.values().copied().min();
            self.stale = false;
        }
        self.min
    }

    #[cfg(test)]
    pub(super) fn is_stale(&self) -> bool {
        self.stale
    }

    /// Account for a removed or overwritten deadline. Invalidates on value
    /// equality with the cached minimum, so with tied minima removing any one
    /// of them forces a rescan (the cache never returns a stale answer, it
    /// just rescans more often than strictly necessary).
    fn note_removed(&mut self, removed: tokio::time::Instant) {
        if self.map.is_empty() {
            self.min = None;
            self.stale = false;
        } else if self.min == Some(removed) {
            self.stale = true;
        }
    }
}

impl<K> Deref for DeadlineMap<K> {
    type Target = HashMap<K, tokio::time::Instant>;

    fn deref(&self) -> &Self::Target {
        &self.map
    }
}

impl<'a, K> IntoIterator for &'a DeadlineMap<K> {
    type Item = (&'a K, &'a tokio::time::Instant);
    type IntoIter = std::collections::hash_map::Iter<'a, K, tokio::time::Instant>;

    fn into_iter(self) -> Self::IntoIter {
        self.map.iter()
    }
}

impl RibManager {
    #[expect(
        clippy::too_many_arguments,
        reason = "GR peer-up carries negotiated restart and LLGR session state together"
    )]
    #[expect(
        clippy::too_many_lines,
        reason = "GR entry owns session teardown plus per-family stale/withdraw behavior"
    )]
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
    ) -> bool {
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
            SessionTeardownDisposition::DiscardStale => return false,
            SessionTeardownDisposition::FailOver => {
                self.fail_over_registration(peer, session_id, "PeerGracefulRestart");
                return true;
            }
            SessionTeardownDisposition::NoRegistration
            | SessionTeardownDisposition::TeardownActive => {}
        }

        info!(%peer, restart_time, stale_routes_time, llgr_stale_time, "peer entered graceful restart");

        let mut affected = HashSet::new();
        let mut fs_affected = HashSet::new();
        let mut evpn_affected: HashSet<EvpnRouteKey> = HashSet::new();
        let mut bgpls_affected: HashSet<BgpLsRouteKey> = HashSet::new();
        let mut vpn_affected: HashSet<crate::route::VpnRibRouteKey> = HashSet::new();
        let mut labeled_affected: HashSet<crate::route::LabeledRibRouteKey> = HashSet::new();
        let mut rtc_affected: HashSet<crate::route::RtcRibRouteKey> = HashSet::new();

        if let Some(rib) = self.ribs.get_mut(&peer) {
            // RFC 4724 helper retention: mark GR-covered families stale.
            // Every mark helper returns the keys of routes that were
            // ALREADY GR-stale from a previous restart and were deleted
            // (RFC 4724 §4.1: no retention across consecutive restarts) —
            // collect them so the recompute below withdraws them
            // downstream. LLGR-stale routes are the RFC 9494 exception:
            // the helpers retain them unchanged across consecutive resets,
            // bounded by their surviving per-family original-LLST deadline
            // in `llgr_stale_deadlines`. Each helper is a family-scoped
            // no-op for non-matching tuples. EVPN has a single family
            // tuple, so its mark call is hoisted out of the loop and made
            // once when (L2Vpn, Evpn) is among the GR-preserved families.
            for &family in &gr_families {
                affected.extend(rib.mark_stale(family));
                fs_affected.extend(rib.mark_stale_flowspec(family));
                vpn_affected.extend(rib.mark_stale_vpn(family));
                labeled_affected.extend(rib.mark_stale_labeled(family));
                bgpls_affected.extend(rib.mark_stale_bgpls(family));
                rtc_affected.extend(rib.mark_stale_rtc(family));
            }
            if gr_families.contains(&(Afi::L2Vpn, Safi::Evpn)) {
                evpn_affected.extend(rib.mark_stale_evpn((Afi::L2Vpn, Safi::Evpn)));
            }
            let withdrawn = rib.withdraw_families_except(&gr_families);
            if !withdrawn.is_empty() {
                info!(%peer, count = withdrawn.len(), "withdrew non-GR family routes");
            }
            for prefix in withdrawn {
                affected.insert(prefix);
            }
            // RFC 4724-critical negative: only families IN the peer's
            // advertised GR capability are retained. A negotiated typed
            // family whose tuple is absent from `gr_families` is withdrawn
            // outright — mirroring the EVPN not-in-gr arm below.
            let keys: Vec<_> = rib
                .iter_flowspec()
                .filter(|route| !gr_families.contains(&(route.afi, Safi::FlowSpec)))
                .map(crate::route::FlowSpecRoute::key)
                .collect();
            for key in keys {
                rib.withdraw_flowspec(&key);
                fs_affected.insert(crate::route::FlowSpecKey {
                    afi: key.afi,
                    rule: key.rule,
                });
            }
            for &family in &[(Afi::Ipv4, Safi::MplsVpn), (Afi::Ipv6, Safi::MplsVpn)] {
                if !gr_families.contains(&family) {
                    let keys: Vec<crate::route::VpnRibRouteKey> = rib
                        .iter_vpn()
                        .filter(|r| r.afi_safi() == family)
                        .map(crate::route::VpnRibRoute::key)
                        .collect();
                    for key in keys {
                        rib.withdraw_vpn(&key);
                        vpn_affected.insert(key);
                    }
                }
            }
            for &family in &[
                (Afi::Ipv4, Safi::LabeledUnicast),
                (Afi::Ipv6, Safi::LabeledUnicast),
            ] {
                if !gr_families.contains(&family) {
                    let keys: Vec<crate::route::LabeledRibRouteKey> = rib
                        .iter_labeled()
                        .filter(|r| r.afi_safi() == family)
                        .map(crate::route::LabeledRibRoute::key)
                        .collect();
                    for key in keys {
                        rib.withdraw_labeled(&key);
                        labeled_affected.insert(key);
                    }
                }
            }
            for &family in &[(Afi::BgpLs, Safi::BgpLs), (Afi::BgpLs, Safi::BgpLsVpn)] {
                if !gr_families.contains(&family)
                    && let Some(fam) = BgpLsFamily::from_afi_safi(family.0, family.1)
                {
                    let keys: Vec<BgpLsRouteKey> = rib
                        .iter_bgpls()
                        .filter(|r| r.family == fam)
                        .map(crate::route::BgpLsRibRoute::key)
                        .collect();
                    for key in keys {
                        rib.withdraw_bgpls(&key);
                        bgpls_affected.insert(key);
                    }
                }
            }
            // RTC has a single family tuple (AFI 1 / SAFI 132).
            if !gr_families.contains(&crate::route::RtcRibRouteKey::afi_safi()) {
                rtc_affected.extend(rib.withdraw_all_rtc());
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
            // GR entry can prune entire non-preserved families while keeping
            // the peer Adj-RIB-In shell alive for preserved families. Reclaim
            // attribute sets stranded by those removals now rather than
            // waiting for an unrelated future withdraw on this peer.
            self.attr_intern.gc();
            self.metrics
                .set_rib_attr_intern_global_size(gauge_val(self.attr_intern.len()));
        }

        if let Some(rib) = self.ribs.get(&peer) {
            for route in rib.iter() {
                affected.insert(route.prefix);
            }
            for route in rib.iter_flowspec() {
                if gr_families.contains(&(route.afi, Safi::FlowSpec)) {
                    fs_affected.insert(route.selection_key());
                }
            }
            if gr_families.contains(&(Afi::L2Vpn, Safi::Evpn)) {
                for route in rib.iter_evpn() {
                    evpn_affected.insert(route.key());
                }
            }
            // Stale marking demotes the tiebreak rank without removing the
            // route, so every RETAINED key of a GR-covered typed family must
            // be recomputed too — the same full re-add the unicast/EVPN
            // paths do above. (BGP-LS stale routes deliberately stay in the
            // topology feed: `iter_bgpls` includes them, which is what keeps
            // ORR vantages resolved through the restart window.)
            for route in rib.iter_vpn() {
                if gr_families.contains(&route.afi_safi()) {
                    vpn_affected.insert(route.key());
                }
            }
            for route in rib.iter_labeled() {
                if gr_families.contains(&route.afi_safi()) {
                    labeled_affected.insert(route.key());
                }
            }
            for route in rib.iter_bgpls() {
                if gr_families.contains(&route.family.to_afi_safi()) {
                    bgpls_affected.insert(route.key());
                }
            }
            if gr_families.contains(&crate::route::RtcRibRouteKey::afi_safi()) {
                for route in rib.iter_rtc() {
                    rtc_affected.insert(route.key());
                }
            }
            self.metrics
                .set_rib_prefixes(&peer.to_string(), "all", gauge_val(rib.len()));
            self.metrics.set_rib_prefixes(
                &peer.to_string(),
                "flowspec",
                gauge_val(rib.flowspec_len()),
            );
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
        if !bgpls_affected.is_empty() {
            self.recompute_bgpls_keys(&bgpls_affected);
            // Reclaim attribute sets stranded by the BGP-LS withdrawals above.
            // The intern gc earlier in this method ran before this
            // recompute, while the Loc-RIB still held the selected-route Arc
            // clones, so those orphans survived (gc only frees a set whose sole
            // remaining holder is the intern table). Now that recompute_bgpls_keys
            // has dropped the Loc-RIB clones, gc reclaims them — mirroring the
            // receive path's recompute-then-gc ordering.
            self.gc_attr_intern();
        }
        if !vpn_affected.is_empty() {
            self.recompute_vpn_keys(&vpn_affected);
            // Same recompute-then-gc ordering rationale as BGP-LS above.
            self.gc_attr_intern();
        }
        if !labeled_affected.is_empty() {
            self.recompute_labeled_keys(&labeled_affected);
            // Same recompute-then-gc ordering rationale as BGP-LS above.
            self.gc_attr_intern();
        }
        if !rtc_affected.is_empty() {
            self.recompute_rtc_keys(&rtc_affected);
            // Same recompute-then-gc ordering rationale as BGP-LS above.
            self.gc_attr_intern();
        }
        // No RTC membership rebuild here even when routes were deleted:
        // `clear_outbound_peer_state` below drops this peer's
        // `peer_rt_membership` entry with the rest of the outbound state,
        // and the re-establish path (`register_active_session`) re-derives
        // membership from the preserved (stale) RTC Adj-RIB-In — which by
        // then reflects any deletions made above.

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
                + rib.iter_vpn().filter(|r| r.is_stale).count()
                + rib.iter_labeled().filter(|r| r.is_stale).count()
                + rib.iter_bgpls().filter(|r| r.is_stale).count()
                + rib.iter_rtc().filter(|r| r.is_stale).count()
        });
        self.metrics
            .set_gr_stale_routes(&peer_label, gauge_val(stale_count));
        true
    }

    pub(super) fn handle_rpki_cache_update(
        &mut self,
        table: Arc<VrpTable>,
        delta: Option<Vec<rustbgpd_rpki::VrpEntry>>,
    ) {
        let started = std::time::Instant::now();
        // The delta arm assumes every stored `validation_state` reflects the
        // previously distributed snapshot. Before the first table there is
        // no such baseline, so the first update always rescans fully.
        let delta = if self.vrp_table.is_some() {
            delta
        } else {
            None
        };
        let mode = if delta.is_some() { "delta" } else { "full" };
        self.vrp_table = Some(table);
        let Some(table) = self.vrp_table.as_ref().map(Arc::clone) else {
            return;
        };
        let vrps = table.len();
        self.metrics
            .set_rpki_vrp_count("ipv4", gauge_val(table.v4_count()));
        self.metrics
            .set_rpki_vrp_count("ipv6", gauge_val(table.v6_count()));

        let mut affected = HashSet::new();
        let mut routes_revalidated = 0_u64;
        let mut changed_routes = 0_u64;
        if let Some(delta) = delta {
            // A route's RFC 6811 outcome depends only on the VRPs covering
            // its prefix, and coverage is by VRP prefix length (max_len only
            // gates the Valid decision). Every entry that differs between
            // the previous and this snapshot is in `delta`, so the union of
            // the delta entries' covered sets is a superset of every route
            // whose outcome can change — including Valid→NotFound/Invalid
            // flips from withdrawals and overlap where a surviving VRP still
            // covers. Revalidating covered routes against the FULL new table
            // keeps outcomes identical to a full rescan; only the set of
            // routes revisited shrinks. Overlapping delta entries may visit
            // a route twice; revalidation is idempotent.
            for rib in self.ribs.values_mut() {
                for entry in &delta {
                    let Some(covering) = super::helpers::vrp_covering_prefix(entry) else {
                        continue;
                    };
                    routes_revalidated += rib.revalidate_rpki_covered(
                        &covering,
                        |route| validate_route_rpki(route, &table),
                        |prefix| {
                            changed_routes += 1;
                            affected.insert(prefix);
                        },
                    );
                }
            }
        } else {
            for rib in self.ribs.values_mut() {
                routes_revalidated += rib.revalidate_rpki_all(
                    |route| validate_route_rpki(route, &table),
                    |prefix| {
                        changed_routes += 1;
                        affected.insert(prefix);
                    },
                );
            }
        }

        if !affected.is_empty() {
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
        }
        info!(
            vrps,
            mode,
            routes_revalidated,
            changed_routes,
            affected_prefixes = affected.len(),
            elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "RPKI cache update re-validation complete"
        );
    }

    pub(super) fn handle_aspa_cache_update(
        &mut self,
        table: Arc<rustbgpd_rpki::AspaTable>,
        delta: Option<rustc_hash::FxHashSet<u32>>,
    ) {
        let started = std::time::Instant::now();
        // Delta filtering requires a previously distributed state baseline.
        // The first update must repair every route, even if tagged incremental.
        let delta = if self.aspa_table.is_some() {
            delta
        } else {
            None
        };
        let mode = if delta.is_some() { "delta" } else { "full" };
        self.aspa_table = Some(table);
        let Some(table) = self.aspa_table.as_ref() else {
            return;
        };
        let records = table.len();
        self.metrics.set_aspa_records(gauge_val(records));

        let mut affected = HashSet::new();
        let mut routes_scanned = 0_u64;
        let mut routes_revalidated = 0_u64;
        let mut changed_routes = 0_u64;
        let mut invalid_hops = AspaInvalidHopSummary::default();
        for rib in self.ribs.values_mut() {
            rib.for_each_route_mut_accounting_rpki(|route| {
                routes_scanned += 1;
                // A table update can affect a verdict only when its customer
                // ASN occurs in the route's AS_SEQUENCE or AS_SET. We still
                // scan every route; the delta avoids only detailed validation.
                if delta.as_ref().is_some_and(|changed| {
                    route
                        .as_path()
                        .is_none_or(|path| path.asns().all(|asn| !changed.contains(&asn)))
                }) {
                    return;
                }
                routes_revalidated += 1;
                let result = validate_route_aspa_detailed(route, table);
                if let Some(hop) = result.invalid_hop {
                    invalid_hops.observe(hop);
                }
                if route.aspa_state != result.state {
                    route.aspa_state = result.state;
                    changed_routes += 1;
                    affected.insert(route.prefix);
                }
            });
        }

        if !affected.is_empty() {
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
        }
        info!(
            records,
            mode,
            routes_scanned,
            routes_revalidated,
            changed_routes,
            affected_prefixes = affected.len(),
            invalid_hop_routes = invalid_hops.routes,
            suppressed_routes = invalid_hops.suppressed_routes,
            invalid_hops = %invalid_hops.render(),
            elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            "ASPA cache update re-validation complete"
        );
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
        // Timer arms call this outside `handle_update`; invalidate Received,
        // Best, and Advertised continuations before stale promotion/purge.
        self.advance_all_route_pages();
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

            let mut affected = HashSet::new();
            let mut fs_affected = HashSet::new();
            let mut evpn_affected: HashSet<EvpnRouteKey> = HashSet::new();
            let mut bgpls_affected: HashSet<BgpLsRouteKey> = HashSet::new();
            let mut vpn_affected: HashSet<crate::route::VpnRibRouteKey> = HashSet::new();
            let mut labeled_affected: HashSet<crate::route::LabeledRibRouteKey> = HashSet::new();
            let mut rtc_affected: HashSet<crate::route::RtcRibRouteKey> = HashSet::new();
            let mut rib_len = 0;
            let mut evpn_len = 0;
            if let Some(rib) = self.ribs.get_mut(&peer) {
                // Promote LLGR-negotiated families to LLGR-stale
                for &family in &llgr_families {
                    let promoted = rib.promote_to_llgr_stale(family, &mut self.attr_intern);
                    for p in promoted {
                        affected.insert(p);
                    }
                    let fs_promoted = rib.promote_to_llgr_stale_flowspec(family);
                    for r in fs_promoted {
                        fs_affected.insert(r);
                    }
                    let evpn_promoted =
                        rib.promote_to_llgr_stale_evpn(family, &mut self.attr_intern);
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
                // Typed families (VPN, BGP-LS, RTC) follow the same split:
                // LLGR-negotiated tuples promote to LLGR-stale (routes
                // carrying NO_LLGR are removed instead and their keys join
                // the affected sets so the recomputes below withdraw them
                // downstream); tuples outside the LLGR capability purge.
                // Each helper is a family-scoped no-op for non-matching
                // tuples.
                for &family in &llgr_families {
                    vpn_affected
                        .extend(rib.promote_to_llgr_stale_vpn(family, &mut self.attr_intern));
                    labeled_affected
                        .extend(rib.promote_to_llgr_stale_labeled(family, &mut self.attr_intern));
                    bgpls_affected
                        .extend(rib.promote_to_llgr_stale_bgpls(family, &mut self.attr_intern));
                    rtc_affected
                        .extend(rib.promote_to_llgr_stale_rtc(family, &mut self.attr_intern));
                }
                for &family in &non_llgr_families {
                    vpn_affected.extend(rib.sweep_stale_family_vpn(family));
                    labeled_affected.extend(rib.sweep_stale_family_labeled(family));
                    bgpls_affected.extend(rib.sweep_stale_family_bgpls(family));
                    rtc_affected.extend(rib.sweep_stale_family_rtc(family));
                }
                rib_len = rib.len();
                evpn_len = rib.evpn_len();
                // First GC catches interned sets made unreachable by direct
                // Adj-RIB-In mutation (LLGR COW promotion or non-LLGR family
                // sweeps). A second GC below runs after Loc-RIB recompute
                // drops selected-route clones that were still holding old
                // Arcs alive here.
                self.attr_intern.gc();
                self.metrics
                    .set_rib_attr_intern_global_size(gauge_val(self.attr_intern.len()));
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
            if !bgpls_affected.is_empty() {
                self.recompute_bgpls_keys(&bgpls_affected);
            }
            if !vpn_affected.is_empty() {
                self.recompute_vpn_keys(&vpn_affected);
            }
            if !labeled_affected.is_empty() {
                self.recompute_labeled_keys(&labeled_affected);
            }
            let rtc_changed = !rtc_affected.is_empty();
            if rtc_changed {
                self.recompute_rtc_keys(&rtc_affected);
            }
            if !affected.is_empty()
                || !fs_affected.is_empty()
                || !evpn_affected.is_empty()
                || !bgpls_affected.is_empty()
                || !vpn_affected.is_empty()
                || !labeled_affected.is_empty()
                || rtc_changed
            {
                self.gc_attr_intern();
            }
            if rtc_changed {
                // A non-LLGR purge (or a NO_LLGR removal during promotion)
                // shrank this peer's RTC Adj-RIB-In; if the peer
                // re-established (only its End-of-RIB was late), its RT
                // membership must shrink with it so uncovered VPN routes are
                // withdrawn from its Adj-RIB-Out. A promotion-only change
                // leaves the derived membership equal and the rebuild
                // no-ops.
                self.rebuild_rtc_membership_and_restage_vpn(peer);
            }
            self.metrics
                .set_rib_prefixes(&peer_label, "all", gauge_val(rib_len));
            self.metrics
                .set_rib_prefixes(&peer_label, "evpn", gauge_val(evpn_len));

            // Set the LLGR timer per family (RFC 9494 §4.3: stale time is
            // negotiated per AFI/SAFI): min(local config, the peer's
            // advertised stale time for that family). `or_insert` is the
            // original-LLST rule — a deadline that survived a
            // reconnect-then-down is re-used, never restarted, so total
            // retention stays bounded by the FIRST promotion's deadline.
            let now = tokio::time::Instant::now();
            for &(afi, safi) in &llgr_families {
                let peer_family_stale = llgr_config
                    .peer_llgr_families
                    .iter()
                    .filter(|f| (f.afi, f.safi) == (afi, safi))
                    .map(|f| f.stale_time)
                    .min()
                    .unwrap_or(llgr_config.local_llgr_stale_time);
                let effective = peer_family_stale.min(llgr_config.local_llgr_stale_time);
                if !self.llgr_stale_deadlines.contains_key(&(peer, afi, safi)) {
                    self.llgr_stale_deadlines.insert(
                        (peer, afi, safi),
                        now + std::time::Duration::from_secs(u64::from(effective)),
                    );
                }
            }
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
        // LLGR-stale routes from a PREVIOUS retention cycle (their original
        // per-family deadlines survive reconnects) are not touched by the
        // GR-stale sweeps below; they stay until those deadlines fire, so
        // retention accounting stays active while any remain.
        let llgr_retention_remains = self.llgr_stale_deadlines.keys().any(|&(p, _, _)| p == peer);
        if !llgr_retention_remains {
            self.metrics.set_gr_active(&peer_label, false);
            self.metrics.set_gr_stale_routes(&peer_label, 0);
        }

        let mut swept = Vec::new();
        let mut fs_swept = Vec::new();
        let mut evpn_swept = Vec::new();
        let mut bgpls_swept = Vec::new();
        let mut l3vpn_swept = Vec::new();
        let mut labeled_swept = Vec::new();
        let mut rtc_swept = Vec::new();
        let mut rib_len = 0;
        let mut evpn_len = 0;
        if let Some(rib) = self.ribs.get_mut(&peer) {
            swept = rib.sweep_stale();
            fs_swept = rib.sweep_stale_flowspec();
            evpn_swept = rib.sweep_stale_evpn();
            bgpls_swept = rib.sweep_stale_bgpls();
            l3vpn_swept = rib.sweep_stale_vpn();
            labeled_swept = rib.sweep_stale_labeled();
            rtc_swept = rib.sweep_stale_rtc();
            self.attr_intern.gc();
            self.metrics
                .set_rib_attr_intern_global_size(gauge_val(self.attr_intern.len()));
            rib_len = rib.len();
            evpn_len = rib.evpn_len();
        }
        let had_swept = !swept.is_empty();
        let had_fs_swept = !fs_swept.is_empty();
        let had_evpn_swept = !evpn_swept.is_empty();
        let had_bgpls_swept = !bgpls_swept.is_empty();
        let had_l3vpn_swept = !l3vpn_swept.is_empty();
        let had_labeled_swept = !labeled_swept.is_empty();
        let had_rtc_swept = !rtc_swept.is_empty();
        if had_swept {
            info!(%peer, count = swept.len(), "swept stale routes");
            let affected: HashSet<Prefix> = swept.into_iter().collect();
            self.metrics
                .set_rib_prefixes(&peer_label, "all", gauge_val(rib_len));
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
        }
        if had_fs_swept {
            let fs_affected: HashSet<crate::route::FlowSpecKey> = fs_swept.into_iter().collect();
            self.recompute_and_distribute_flowspec(&fs_affected);
        }
        if had_evpn_swept {
            let evpn_affected: HashSet<EvpnRouteKey> = evpn_swept.into_iter().collect();
            self.metrics
                .set_rib_prefixes(&peer_label, "evpn", gauge_val(evpn_len));
            self.recompute_and_distribute_evpn(&evpn_affected);
        }
        if had_bgpls_swept {
            // The sweep drops the stale entries from the topology feed, so
            // this recompute is also where ORR vantages resolved only by the
            // departed peer's links finally unresolve.
            let bgpls_affected: HashSet<BgpLsRouteKey> = bgpls_swept.into_iter().collect();
            self.recompute_bgpls_keys(&bgpls_affected);
        }
        if had_l3vpn_swept {
            let vpn_affected: HashSet<crate::route::VpnRibRouteKey> =
                l3vpn_swept.into_iter().collect();
            self.recompute_vpn_keys(&vpn_affected);
        }
        if had_labeled_swept {
            let labeled_affected: HashSet<crate::route::LabeledRibRouteKey> =
                labeled_swept.into_iter().collect();
            self.recompute_labeled_keys(&labeled_affected);
        }
        if had_rtc_swept {
            let rtc_affected: HashSet<crate::route::RtcRibRouteKey> =
                rtc_swept.into_iter().collect();
            self.recompute_rtc_keys(&rtc_affected);
        }
        if had_swept
            || had_fs_swept
            || had_evpn_swept
            || had_bgpls_swept
            || had_l3vpn_swept
            || had_labeled_swept
            || had_rtc_swept
        {
            self.gc_attr_intern();
        }
        if had_rtc_swept {
            // Same obligation as the LLGR branch: a re-established peer whose
            // End-of-RIB never arrived just lost its preserved RT interest,
            // so its VPN Adj-RIB-Out must restage under the shrunk membership.
            self.rebuild_rtc_membership_and_restage_vpn(peer);
        }

        if !llgr_retention_remains {
            self.release_peer_state_if_departed(peer);
        }
        self.prune_exact_export_rejections();
    }

    /// Sweep every (peer, AFI, SAFI) whose LLGR stale deadline has expired,
    /// grouped per peer. Called from the manager run loop's LLGR timer arm.
    pub(super) fn sweep_expired_llgr_stale(&mut self) {
        let now = tokio::time::Instant::now();
        let mut expired: std::collections::HashMap<IpAddr, Vec<(Afi, Safi)>> =
            std::collections::HashMap::new();
        for (&(peer, afi, safi), &deadline) in &self.llgr_stale_deadlines {
            if deadline <= now {
                expired.entry(peer).or_default().push((afi, safi));
            }
        }
        for (peer, families) in expired {
            self.sweep_llgr_stale(peer, &families);
        }
        self.prune_exact_export_rejections();
    }

    /// Sweep LLGR-stale routes for the given families of a peer whose LLGR
    /// stale deadlines have expired (RFC 9494 §4.3: the stale time — and so
    /// the sweep — is per AFI/SAFI; longer-lived families keep their routes).
    ///
    /// Deadlines survive re-establishment while routes remain LLGR-stale,
    /// so this can fire for a peer that is back up and awaiting End-of-RIB
    /// (`gr_peers`): the original Long-Lived Stale Time bounds retention
    /// regardless — routes the peer has not re-advertised by then are purged.
    #[expect(
        clippy::too_many_lines,
        reason = "family-scoped sweeps and recomputes across all seven route tables"
    )]
    pub(super) fn sweep_llgr_stale(&mut self, peer: IpAddr, families: &[(Afi, Safi)]) {
        if !families.is_empty() {
            // Like GR expiry, LLGR expiry is a direct timer mutation seam.
            self.advance_all_route_pages();
        }
        info!(%peer, ?families, "LLGR timer expired — sweeping LLGR-stale routes");
        let peer_label = peer.to_string();

        let mut swept = Vec::new();
        let mut fs_swept = Vec::new();
        let mut evpn_swept = Vec::new();
        let mut bgpls_swept = Vec::new();
        let mut l3vpn_swept = Vec::new();
        let mut labeled_swept = Vec::new();
        let mut rtc_swept = Vec::new();
        let mut rib_len = 0;
        let mut evpn_len = 0;
        let mut llgr_stale_remaining = 0;
        for &(afi, safi) in families {
            self.llgr_stale_deadlines.remove(&(peer, afi, safi));
            if let Some(awaiting) = self.llgr_peers.get_mut(&peer) {
                awaiting.remove(&(afi, safi));
            }
        }
        if let Some(rib) = self.ribs.get_mut(&peer) {
            // Each helper is a family-scoped no-op for non-matching tuples.
            for &family in families {
                swept.extend(rib.sweep_llgr_stale_family(family));
                fs_swept.extend(rib.sweep_llgr_stale_flowspec_family(family));
                evpn_swept.extend(rib.sweep_llgr_stale_family_evpn(family));
                bgpls_swept.extend(rib.sweep_llgr_stale_family_bgpls(family));
                l3vpn_swept.extend(rib.sweep_llgr_stale_family_vpn(family));
                labeled_swept.extend(rib.sweep_llgr_stale_family_labeled(family));
                rtc_swept.extend(rib.sweep_llgr_stale_family_rtc(family));
            }
            self.attr_intern.gc();
            self.metrics
                .set_rib_attr_intern_global_size(gauge_val(self.attr_intern.len()));
            rib_len = rib.len();
            evpn_len = rib.evpn_len();
            llgr_stale_remaining = rib.iter().filter(|r| r.is_llgr_stale).count()
                + rib.iter_flowspec().filter(|r| r.is_llgr_stale).count()
                + rib.iter_evpn().filter(|r| r.is_llgr_stale).count()
                + rib.iter_vpn().filter(|r| r.is_llgr_stale).count()
                + rib.iter_labeled().filter(|r| r.is_llgr_stale).count()
                + rib.iter_bgpls().filter(|r| r.is_llgr_stale).count()
                + rib.iter_rtc().filter(|r| r.is_llgr_stale).count();
        }
        let had_swept = !swept.is_empty();
        let had_fs_swept = !fs_swept.is_empty();
        let had_evpn_swept = !evpn_swept.is_empty();
        let had_bgpls_swept = !bgpls_swept.is_empty();
        let had_l3vpn_swept = !l3vpn_swept.is_empty();
        let had_labeled_swept = !labeled_swept.is_empty();
        let had_rtc_swept = !rtc_swept.is_empty();
        if had_swept {
            info!(%peer, count = swept.len(), "swept LLGR-stale routes");
            let affected: HashSet<Prefix> = swept.into_iter().collect();
            self.metrics
                .set_rib_prefixes(&peer_label, "all", gauge_val(rib_len));
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
        }
        if had_fs_swept {
            let fs_affected: HashSet<crate::route::FlowSpecKey> = fs_swept.into_iter().collect();
            self.recompute_and_distribute_flowspec(&fs_affected);
        }
        if had_evpn_swept {
            let evpn_affected: HashSet<EvpnRouteKey> = evpn_swept.into_iter().collect();
            self.metrics
                .set_rib_prefixes(&peer_label, "evpn", gauge_val(evpn_len));
            self.recompute_and_distribute_evpn(&evpn_affected);
        }
        if had_bgpls_swept {
            // The sweep drops the LLGR-stale entries from the topology feed,
            // so this recompute is also where ORR vantages that survived the
            // whole GR + LLGR retention on the departed peer's links finally
            // unresolve.
            let bgpls_affected: HashSet<BgpLsRouteKey> = bgpls_swept.into_iter().collect();
            self.recompute_bgpls_keys(&bgpls_affected);
        }
        if had_l3vpn_swept {
            let vpn_affected: HashSet<crate::route::VpnRibRouteKey> =
                l3vpn_swept.into_iter().collect();
            self.recompute_vpn_keys(&vpn_affected);
        }
        if had_labeled_swept {
            let labeled_affected: HashSet<crate::route::LabeledRibRouteKey> =
                labeled_swept.into_iter().collect();
            self.recompute_labeled_keys(&labeled_affected);
        }
        if had_rtc_swept {
            let rtc_affected: HashSet<crate::route::RtcRibRouteKey> =
                rtc_swept.into_iter().collect();
            self.recompute_rtc_keys(&rtc_affected);
        }
        if had_swept
            || had_fs_swept
            || had_evpn_swept
            || had_bgpls_swept
            || had_l3vpn_swept
            || had_labeled_swept
            || had_rtc_swept
        {
            self.gc_attr_intern();
        }
        if had_rtc_swept {
            // Same obligation as the GR-expiry sweeps: the down peer's
            // preserved RT interest dies here, so `peer_rt_membership` must
            // shrink with the Adj-RIB-In to stay consistent for the
            // re-establish path (which re-derives membership from this RIB).
            self.rebuild_rtc_membership_and_restage_vpn(peer);
        }

        self.prune_exact_export_rejections();

        // Terminal only when no family retains an LLGR deadline: other
        // families with longer stale times keep their retention (and the
        // peer's config, needed for a later re-promotion) alive.
        if self.llgr_stale_deadlines.keys().any(|&(p, _, _)| p == peer) {
            self.metrics
                .set_gr_stale_routes(&peer_label, gauge_val(llgr_stale_remaining));
            return;
        }
        self.llgr_peers.remove(&peer);
        if self.gr_peers.contains_key(&peer) {
            // Re-established and awaiting End-of-RIB: the GR machinery owns
            // the remaining lifecycle (and still reads `llgr_peer_config`).
            self.metrics
                .set_gr_stale_routes(&peer_label, gauge_val(llgr_stale_remaining));
            return;
        }
        // LLGR is the last retention phase — the per-peer LLGR config has
        // no further reader once the stale routes are swept.
        self.llgr_peer_config.remove(&peer);
        self.metrics.set_gr_active(&peer_label, false);
        self.metrics.set_gr_stale_routes(&peer_label, 0);
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
    pub(super) fn next_gr_deadline(&mut self) -> Option<tokio::time::Instant> {
        self.gr_stale_deadlines.min()
    }

    /// Find the nearest LLGR stale deadline, if any.
    pub(super) fn next_llgr_deadline(&mut self) -> Option<tokio::time::Instant> {
        self.llgr_stale_deadlines.min()
    }

    /// Find the nearest enhanced route refresh deadline, if any.
    pub(super) fn next_refresh_deadline(&mut self) -> Option<tokio::time::Instant> {
        self.refresh_deadlines.min()
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
        self.prune_exact_export_rejections();
    }
}
