use std::collections::HashSet;
use std::net::IpAddr;

use rustbgpd_wire::{Afi, EvpnRouteKey, Prefix, RouteRefreshSubtype, Safi};
use tracing::{debug, info, warn};

use super::helpers::{afi_safi_label, gauge_val, prefix_family};
use super::{PolicyFilteredRouteKey, RibManager};
use crate::ERR_REFRESH_TIMEOUT;
use crate::adj_rib_out::AdjRibOut;
use crate::route::{BgpLsFamily, FlowSpecKey, FlowSpecRoute, FlowSpecRouteKey};
use crate::update::OutboundRouteUpdate;

impl RibManager {
    pub(super) fn update_peer_refresh_metrics(&self, peer: IpAddr) {
        if let Some(families) = self.refresh_in_progress.get(&peer) {
            for &(afi, safi) in families {
                self.update_refresh_metrics(peer, afi, safi);
            }
        }
    }

    pub(super) fn clear_peer_refresh_metrics(&self, peer: IpAddr) {
        if let Some(families) = self.refresh_in_progress.get(&peer) {
            let peer_label = peer.to_string();
            for &(afi, safi) in families {
                let family_label = afi_safi_label(afi, safi);
                self.metrics
                    .set_route_refresh_in_progress(&peer_label, family_label, false);
                self.metrics
                    .set_route_refresh_stale_entries(&peer_label, family_label, 0);
            }
        }
    }

    fn update_refresh_metrics(&self, peer: IpAddr, afi: Afi, safi: Safi) {
        let active = self
            .refresh_in_progress
            .get(&peer)
            .is_some_and(|families| families.contains(&(afi, safi)));
        let stale_count = if active {
            self.refresh_stale_counts
                .get(&(peer, afi, safi))
                .copied()
                .unwrap_or(0)
        } else {
            0
        };
        let peer_label = peer.to_string();
        let family_label = afi_safi_label(afi, safi);
        self.metrics
            .set_route_refresh_in_progress(&peer_label, family_label, active);
        self.metrics.set_route_refresh_stale_entries(
            &peer_label,
            family_label,
            gauge_val(stale_count),
        );
    }

    pub(super) fn set_refresh_stale_count(
        &mut self,
        peer: IpAddr,
        afi: Afi,
        safi: Safi,
        count: usize,
    ) {
        if count == 0 {
            self.refresh_stale_counts.remove(&(peer, afi, safi));
        } else {
            self.refresh_stale_counts.insert((peer, afi, safi), count);
        }
    }

    pub(super) fn decrement_refresh_stale_count(
        &mut self,
        peer: IpAddr,
        afi: Afi,
        safi: Safi,
        count: usize,
    ) {
        if count == 0 {
            return;
        }
        let Some(stale_count) = self.refresh_stale_counts.get_mut(&(peer, afi, safi)) else {
            return;
        };
        *stale_count = stale_count.saturating_sub(count);
        if *stale_count == 0 {
            self.refresh_stale_counts.remove(&(peer, afi, safi));
        }
    }

    #[expect(
        clippy::too_many_lines,
        reason = "End-of-RIB handler covers GR and LLGR branches across the per-family stale lifecycles (unicast, FlowSpec, EVPN, VPN, BGP-LS, RTC)"
    )]
    pub(super) fn handle_end_of_rib(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        info!(%peer, ?afi, ?safi, "received End-of-RIB");
        let is_gr_peer = self.gr_peers.contains_key(&peer);
        let is_llgr_peer = self.llgr_peers.contains_key(&peer);
        if !is_gr_peer && !is_llgr_peer {
            debug!(%peer, ?afi, ?safi, "End-of-RIB received without active GR/LLGR state, ignoring");
        }
        if is_gr_peer {
            if let Some(awaiting) = self.gr_peers.get_mut(&peer) {
                awaiting.remove(&(afi, safi));
            }

            let fs_affected: HashSet<FlowSpecKey> = self
                .ribs
                .get(&peer)
                .map(|rib| {
                    rib.iter_flowspec()
                        .filter(|route| route.afi == afi)
                        .map(FlowSpecRoute::selection_key)
                        .collect()
                })
                .unwrap_or_default();

            let evpn_affected: HashSet<EvpnRouteKey> = if (afi, safi) == (Afi::L2Vpn, Safi::Evpn) {
                self.ribs
                    .get(&peer)
                    .map(|rib| {
                        rib.iter_evpn()
                            .map(crate::route::EvpnRibRoute::key)
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                HashSet::new()
            };

            // Collect the typed-family keys BEFORE the sweep below removes
            // the non-readvertised ones, so the recompute both withdraws
            // swept keys downstream and re-promotes the retained ones.
            let vpn_affected: HashSet<crate::route::VpnRibRouteKey> = if safi == Safi::MplsVpn {
                self.ribs
                    .get(&peer)
                    .map(|rib| {
                        rib.iter_vpn()
                            .filter(|route| route.afi_safi() == (afi, safi))
                            .map(crate::route::VpnRibRoute::key)
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                HashSet::new()
            };
            let labeled_affected: HashSet<crate::route::LabeledRibRouteKey> =
                if safi == Safi::LabeledUnicast {
                    self.ribs
                        .get(&peer)
                        .map(|rib| {
                            rib.iter_labeled()
                                .filter(|route| route.afi_safi() == (afi, safi))
                                .map(crate::route::LabeledRibRoute::key)
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    HashSet::new()
                };
            let bgpls_affected: HashSet<crate::route::BgpLsRouteKey> =
                if let Some(bgpls_family) = BgpLsFamily::from_afi_safi(afi, safi) {
                    self.ribs
                        .get(&peer)
                        .map(|rib| {
                            rib.iter_bgpls()
                                .filter(|route| route.family == bgpls_family)
                                .map(crate::route::BgpLsRibRoute::key)
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    HashSet::new()
                };
            let rtc_affected: HashSet<crate::route::RtcRibRouteKey> = if safi == Safi::RtConstrain {
                self.ribs
                    .get(&peer)
                    .map(|rib| rib.iter_rtc().map(crate::route::RtcRibRoute::key).collect())
                    .unwrap_or_default()
            } else {
                HashSet::new()
            };

            let mut rtc_swept = false;
            let mut swept_prefixes: Vec<Prefix> = Vec::new();
            if let Some(rib) = self.ribs.get_mut(&peer) {
                // RFC 4724 §4.1 End-of-RIB removal for every family: a
                // route still marked stale here was not re-advertised
                // during the restart window and is deleted (re-advertised
                // routes had their flag cleared on insert). Routes still
                // LLGR-stale are swept too: a peer that re-established
                // DURING the LLGR phase moved back to `gr_peers`
                // (`handle_peer_up`) while its unrefreshed routes kept
                // their LLGR-stale flag — they were equally not
                // re-advertised (RFC 9494 §4.2). The trailing clear is
                // flag/LLGR-community hygiene for the retained routes.
                // Each helper is a family-scoped no-op for non-matching
                // tuples.
                swept_prefixes = rib.sweep_stale_family((afi, safi));
                swept_prefixes.extend(rib.sweep_llgr_stale_family((afi, safi)));
                rib.clear_stale((afi, safi));
                rib.sweep_stale_flowspec_family((afi, safi));
                rib.sweep_llgr_stale_flowspec_family((afi, safi));
                rib.clear_stale_flowspec((afi, safi));
                rib.sweep_stale_family_evpn((afi, safi));
                rib.sweep_llgr_stale_family_evpn((afi, safi));
                rib.clear_stale_evpn((afi, safi));
                rib.sweep_stale_family_vpn((afi, safi));
                rib.sweep_llgr_stale_family_vpn((afi, safi));
                rib.clear_stale_vpn((afi, safi));
                rib.sweep_stale_family_labeled((afi, safi));
                rib.sweep_llgr_stale_family_labeled((afi, safi));
                rib.clear_stale_labeled((afi, safi));
                rib.sweep_stale_family_bgpls((afi, safi));
                rib.sweep_llgr_stale_family_bgpls((afi, safi));
                rib.clear_stale_bgpls((afi, safi));
                rtc_swept = !rib.sweep_stale_family_rtc((afi, safi)).is_empty();
                rtc_swept |= !rib.sweep_llgr_stale_family_rtc((afi, safi)).is_empty();
                rib.clear_stale_rtc((afi, safi));
            }
            // End-of-RIB resolves this family's LLGR retention (routes were
            // either re-advertised or swept just above), so its surviving
            // original-LLST deadline — kept across the re-establishment —
            // is retired here.
            self.llgr_stale_deadlines.remove(&(peer, afi, safi));

            // FlowSpec/EVPN affected keys were collected BEFORE the sweep,
            // so removed keys are already in their sets; the unicast set is
            // collected from the retained routes and needs the swept
            // prefixes joined in so their withdrawals distribute.
            let mut affected: HashSet<Prefix> = self
                .ribs
                .get(&peer)
                .map(|rib| rib.iter().map(|r| r.prefix).collect())
                .unwrap_or_default();
            affected.extend(swept_prefixes);
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
            if !fs_affected.is_empty() {
                self.recompute_and_distribute_flowspec(&fs_affected);
            }
            if !evpn_affected.is_empty() {
                self.recompute_and_distribute_evpn(&evpn_affected);
            }
            if !vpn_affected.is_empty() {
                self.recompute_vpn_keys(&vpn_affected);
            }
            if !labeled_affected.is_empty() {
                self.recompute_labeled_keys(&labeled_affected);
            }
            if !bgpls_affected.is_empty() {
                self.recompute_bgpls_keys(&bgpls_affected);
            }
            if !rtc_affected.is_empty() {
                self.recompute_rtc_keys(&rtc_affected);
            }
            self.gc_attr_intern();
            if rtc_swept {
                // The EoR sweep removed RT interest the peer did not
                // re-advertise: shrink its membership so no-longer-covered
                // VPN routes are withdrawn from its Adj-RIB-Out.
                self.rebuild_rtc_membership_and_restage_vpn(peer);
            }

            let peer_label = peer.to_string();
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

            let all_done = self.gr_peers.get(&peer).is_some_and(HashSet::is_empty);
            if all_done {
                info!(%peer, "graceful restart complete — all End-of-RIB received");
                self.gr_peers.remove(&peer);
                self.gr_stale_deadlines.remove(&peer);
                self.gr_stale_routes_time.remove(&peer);
                self.llgr_peer_config.remove(&peer);
                self.metrics.set_gr_active(&peer_label, false);
                self.metrics.set_gr_stale_routes(&peer_label, 0);
            }
        } else if is_llgr_peer {
            if let Some(awaiting) = self.llgr_peers.get_mut(&peer) {
                awaiting.remove(&(afi, safi));
            }

            let fs_affected: HashSet<FlowSpecKey> = self
                .ribs
                .get(&peer)
                .map(|rib| {
                    rib.iter_flowspec()
                        .filter(|route| route.afi == afi)
                        .map(FlowSpecRoute::selection_key)
                        .collect()
                })
                .unwrap_or_default();

            let evpn_affected: HashSet<EvpnRouteKey> = if (afi, safi) == (Afi::L2Vpn, Safi::Evpn) {
                self.ribs
                    .get(&peer)
                    .map(|rib| {
                        rib.iter_evpn()
                            .map(crate::route::EvpnRibRoute::key)
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                HashSet::new()
            };

            // Collect the typed-family keys BEFORE the sweep below removes
            // the non-readvertised ones, so the recompute both withdraws
            // swept keys downstream and re-promotes the retained ones —
            // the same shape as the GR arm above.
            let vpn_affected: HashSet<crate::route::VpnRibRouteKey> = if safi == Safi::MplsVpn {
                self.ribs
                    .get(&peer)
                    .map(|rib| {
                        rib.iter_vpn()
                            .filter(|route| route.afi_safi() == (afi, safi))
                            .map(crate::route::VpnRibRoute::key)
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                HashSet::new()
            };
            let labeled_affected: HashSet<crate::route::LabeledRibRouteKey> =
                if safi == Safi::LabeledUnicast {
                    self.ribs
                        .get(&peer)
                        .map(|rib| {
                            rib.iter_labeled()
                                .filter(|route| route.afi_safi() == (afi, safi))
                                .map(crate::route::LabeledRibRoute::key)
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    HashSet::new()
                };
            let bgpls_affected: HashSet<crate::route::BgpLsRouteKey> =
                if let Some(bgpls_family) = BgpLsFamily::from_afi_safi(afi, safi) {
                    self.ribs
                        .get(&peer)
                        .map(|rib| {
                            rib.iter_bgpls()
                                .filter(|route| route.family == bgpls_family)
                                .map(crate::route::BgpLsRibRoute::key)
                                .collect()
                        })
                        .unwrap_or_default()
                } else {
                    HashSet::new()
                };
            let rtc_affected: HashSet<crate::route::RtcRibRouteKey> = if safi == Safi::RtConstrain {
                self.ribs
                    .get(&peer)
                    .map(|rib| rib.iter_rtc().map(crate::route::RtcRibRoute::key).collect())
                    .unwrap_or_default()
            } else {
                HashSet::new()
            };

            let mut rtc_swept = false;
            let mut swept_prefixes: Vec<Prefix> = Vec::new();
            if let Some(rib) = self.ribs.get_mut(&peer) {
                // RFC-strict End-of-RIB removal for every family, matching
                // the GR arm: a route still LLGR-stale here was not
                // re-advertised during the LLGR window and is deleted
                // (RFC 4724 §4.1 via RFC 9494 §4.2). The trailing clear is
                // flag/LLGR-community hygiene for the retained routes.
                // Each helper is a family-scoped no-op for non-matching
                // tuples.
                swept_prefixes = rib.sweep_llgr_stale_family((afi, safi));
                rib.clear_llgr_stale((afi, safi));
                rib.sweep_llgr_stale_flowspec_family((afi, safi));
                rib.clear_llgr_stale_flowspec((afi, safi));
                rib.sweep_llgr_stale_family_evpn((afi, safi));
                rib.clear_llgr_stale_evpn((afi, safi));
                rib.sweep_llgr_stale_family_vpn((afi, safi));
                rib.clear_llgr_stale_vpn((afi, safi));
                rib.sweep_llgr_stale_family_labeled((afi, safi));
                rib.clear_llgr_stale_labeled((afi, safi));
                rib.sweep_llgr_stale_family_bgpls((afi, safi));
                rib.clear_llgr_stale_bgpls((afi, safi));
                rtc_swept = !rib.sweep_llgr_stale_family_rtc((afi, safi)).is_empty();
                rib.clear_llgr_stale_rtc((afi, safi));
            }
            // This family's LLGR retention is resolved — retire its deadline.
            self.llgr_stale_deadlines.remove(&(peer, afi, safi));

            // Same shape as the GR arm: FlowSpec/EVPN affected keys already
            // include the swept ones (collected pre-sweep); join the swept
            // unicast prefixes so their withdrawals distribute.
            let mut affected: HashSet<Prefix> = self
                .ribs
                .get(&peer)
                .map(|rib| rib.iter().map(|r| r.prefix).collect())
                .unwrap_or_default();
            affected.extend(swept_prefixes);
            let changed = self.recompute_best(&affected);
            self.distribute_changes(&changed, &affected);
            if !fs_affected.is_empty() {
                self.recompute_and_distribute_flowspec(&fs_affected);
            }
            if !evpn_affected.is_empty() {
                self.recompute_and_distribute_evpn(&evpn_affected);
            }
            if !vpn_affected.is_empty() {
                self.recompute_vpn_keys(&vpn_affected);
            }
            if !labeled_affected.is_empty() {
                self.recompute_labeled_keys(&labeled_affected);
            }
            if !bgpls_affected.is_empty() {
                self.recompute_bgpls_keys(&bgpls_affected);
            }
            if !rtc_affected.is_empty() {
                self.recompute_rtc_keys(&rtc_affected);
            }
            self.gc_attr_intern();
            if rtc_swept {
                // The EoR sweep removed LLGR-stale RT interest the peer did
                // not re-advertise: shrink its membership so no-longer-
                // covered VPN routes are withdrawn from its Adj-RIB-Out.
                self.rebuild_rtc_membership_and_restage_vpn(peer);
            }

            let peer_label = peer.to_string();
            let llgr_stale_count = self.ribs.get(&peer).map_or(0, |rib| {
                rib.iter().filter(|r| r.is_llgr_stale).count()
                    + rib.iter_flowspec().filter(|r| r.is_llgr_stale).count()
                    + rib.iter_evpn().filter(|r| r.is_llgr_stale).count()
                    + rib.iter_vpn().filter(|r| r.is_llgr_stale).count()
                    + rib.iter_labeled().filter(|r| r.is_llgr_stale).count()
                    + rib.iter_bgpls().filter(|r| r.is_llgr_stale).count()
                    + rib.iter_rtc().filter(|r| r.is_llgr_stale).count()
            });
            self.metrics
                .set_gr_stale_routes(&peer_label, gauge_val(llgr_stale_count));

            let all_done = self.llgr_peers.get(&peer).is_some_and(HashSet::is_empty);
            if all_done {
                info!(%peer, "LLGR complete — all End-of-RIB received");
                self.llgr_peers.remove(&peer);
                // The LLGR config outlives GR→LLGR promotion; LLGR
                // completion is a terminal point, mirror the GR arm above.
                self.llgr_peer_config.remove(&peer);
                self.metrics.set_gr_active(&peer_label, false);
                self.metrics.set_gr_stale_routes(&peer_label, 0);
            }
        }
        self.prune_exact_export_rejections();
    }

    pub(super) fn handle_route_refresh_request(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        info!(%peer, ?afi, ?safi, "handling route refresh request");
        self.send_route_refresh_response(peer, afi, safi);
    }

    pub(super) fn handle_begin_route_refresh(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        info!(%peer, ?afi, ?safi, "beginning enhanced route refresh");
        self.refresh_in_progress
            .entry(peer)
            .or_default()
            .insert((afi, safi));
        self.refresh_deadlines.insert(
            (peer, afi, safi),
            tokio::time::Instant::now() + ERR_REFRESH_TIMEOUT,
        );
        // RFC 7313 §4 refresh-stale snapshot, kept distinct from GR/LLGR
        // retention. Transport rejects a GR-capable peer's BoRR until
        // this family has received End-of-RIB, so a conforming current session
        // cannot open a refresh window while its initial GR replay is pending.
        // The GR/LLGR exclusions below remain defensive for retained state from
        // an older session or direct RIB test/control senders. At EoRR:
        //   1. snapshotted, not GR/LLGR-stale, not re-advertised → purged
        //      (RFC 7313 §4: not re-advertised between BoRR and EoRR).
        //   2. re-advertised inside the window → kept; the insert removed
        //      the snapshot key and cleared any GR/LLGR staleness
        //      (implicit-replace, RFC 4724 §4.1).
        //   3. defensive GR/LLGR-stale state at BoRR is not snapshotted, so its
        //      RFC 4724/RFC 9494 lifecycle remains authoritative.
        //   4. GR/LLGR-stale acquired DURING the window is unreachable — GR
        //      entry is session-down, which drops every refresh window for
        //      the peer (`clear_peer_refresh_state`).
        let mut stale_count = 0usize;
        if let Some(rib) = self.ribs.get(&peer) {
            if safi == Safi::FlowSpec {
                let stale = self.refresh_stale_flowspec.entry(peer).or_default();
                stale.retain(|key| key.afi != afi);
                for route in rib
                    .iter_flowspec()
                    .filter(|route| route.afi == afi && !route.is_stale && !route.is_llgr_stale)
                {
                    if stale.insert(route.key()) {
                        stale_count += 1;
                    }
                }
            } else if let Some(bgpls_family) = BgpLsFamily::from_afi_safi(afi, safi) {
                let stale = self.refresh_stale_bgpls.entry(peer).or_default();
                stale.retain(|key| key.family != bgpls_family);
                for route in rib.iter_bgpls().filter(|route| {
                    route.family == bgpls_family && !route.is_stale && !route.is_llgr_stale
                }) {
                    if stale.insert(route.key()) {
                        stale_count += 1;
                    }
                }
            } else if safi == Safi::MplsVpn {
                let stale = self.refresh_stale_vpn.entry(peer).or_default();
                stale.retain(|key| key.afi_safi() != (afi, safi));
                for route in rib.iter_vpn().filter(|route| {
                    route.afi_safi() == (afi, safi) && !route.is_stale && !route.is_llgr_stale
                }) {
                    if stale.insert(route.key()) {
                        stale_count += 1;
                    }
                }
            } else if safi == Safi::LabeledUnicast {
                let stale = self.refresh_stale_labeled.entry(peer).or_default();
                stale.retain(|key| key.afi_safi() != (afi, safi));
                for route in rib.iter_labeled().filter(|route| {
                    route.afi_safi() == (afi, safi) && !route.is_stale && !route.is_llgr_stale
                }) {
                    if stale.insert(route.key()) {
                        stale_count += 1;
                    }
                }
            } else if (afi, safi) == (Afi::L2Vpn, Safi::Evpn) {
                let stale = self.refresh_stale_evpn.entry(peer).or_default();
                stale.clear();
                for route in rib
                    .iter_evpn()
                    .filter(|route| !route.is_stale && !route.is_llgr_stale)
                {
                    if stale.insert(route.key()) {
                        stale_count += 1;
                    }
                }
            } else if safi == Safi::RtConstrain {
                // RTC is a single family (AFI 1 only), so clearing the whole
                // per-peer set is safe — the EVPN pattern, not the VPN one.
                let stale = self.refresh_stale_rtc.entry(peer).or_default();
                stale.clear();
                for route in rib
                    .iter_rtc()
                    .filter(|route| !route.is_stale && !route.is_llgr_stale)
                {
                    if stale.insert(route.key()) {
                        stale_count += 1;
                    }
                }
            } else {
                let stale = self.refresh_stale_routes.entry(peer).or_default();
                stale.retain(|(prefix, _)| prefix_family(prefix) != (afi, safi));
                for route in rib.iter().filter(|route| {
                    prefix_family(&route.prefix) == (afi, safi)
                        && !route.is_stale
                        && !route.is_llgr_stale
                }) {
                    if stale.insert((route.prefix, route.path_id)) {
                        stale_count += 1;
                    }
                }
            }
        }
        self.set_refresh_stale_count(peer, afi, safi, stale_count);
        self.update_refresh_metrics(peer, afi, safi);
    }

    pub(super) fn handle_end_route_refresh(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        self.finish_route_refresh(peer, afi, safi, false);
    }

    /// Re-advertise the Loc-RIB for a given family to a peer, followed by `EoR`.
    /// Called when a peer sends ROUTE-REFRESH (RFC 2918).
    pub(super) fn send_route_refresh_response(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        self.send_route_refresh_response_inner(peer, afi, safi, false);
    }

    /// `suppress_eor` is set by the selection-deferral release path, which
    /// has already queued/flushed the genuine convergence `EoR` for this
    /// peer and family: without it a plain-refresh (RFC 2918) peer would
    /// receive a second empty-UPDATE `EoR` from this response. An RFC 7313
    /// peer is unaffected either way — transport substitutes the response's
    /// own `end_of_rib` entry with the `EoRR` demarcation marker.
    #[expect(
        clippy::too_many_lines,
        reason = "route-refresh replay keeps family staging, ORF gating, and EoR together"
    )]
    pub(super) fn send_route_refresh_response_inner(
        &mut self,
        peer: IpAddr,
        afi: Afi,
        safi: Safi,
        suppress_eor: bool,
    ) {
        let family = (afi, safi);
        if self.selection_convergence_held(family) {
            self.selection_deferred_refresh
                .entry(peer)
                .or_default()
                .insert(family);
            debug!(%peer, ?afi, ?safi, "route-refresh response deferred behind RFC 4724 convergence gate");
            return;
        }
        // RFC 5291 §6: a ROUTE-REFRESH (plain or ORF-carrying) for this family
        // lifts the initial-advertisement gate, so this response is the first
        // advertisement of the family — filtered through any installed ORF.
        if let Some(pending) = self.peer_orf_pending.get_mut(&peer) {
            pending.remove(&family);
        }
        // A GR restarter's EoR for this family may have been withheld at
        // `PeerUp` (`send_initial_table`) because the family was ORF-gated:
        // this refresh response IS the gated flood, so the deferred EoR must
        // follow it — as a genuine EoR UPDATE, not this response's own
        // `end_of_rib` entry, which transport substitutes with an EoRR
        // demarcation when enhanced route refresh is negotiated. A restarter
        // ends its RFC 4724 deferral on EoR, not on the RFC 7313 markers.
        let deferred_eor = self
            .gr_deferred_eor
            .get(&peer)
            .is_some_and(|families| families.contains(&family));
        let orf_filter = self
            .peer_orf_filters
            .get(&peer)
            .and_then(|m| m.get(&family))
            .cloned();
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_override_flags: Vec<Option<rustbgpd_policy::NextHopAction>> = Vec::new();
        let mut fs_announce = Vec::new();
        let mut fs_withdraw = Vec::new();
        let mut evpn_announce = Vec::new();
        let mut evpn_withdraw = Vec::new();
        let mut bgpls_announce = Vec::new();
        let mut bgpls_withdraw = Vec::new();
        let mut vpn_announce = Vec::new();
        let mut vpn_withdraw = Vec::new();
        let mut labeled_announce = Vec::new();
        let mut labeled_withdraw = Vec::new();
        let mut rtc_announce = Vec::new();
        let mut rtc_withdraw = Vec::new();
        let export_pol = self
            .export_policy_for(peer)
            .map(rustbgpd_policy::PolicyChain::share);
        let sendable = self.peer_sendable_families.get(&peer).cloned();
        let llgr = self.peer_advertised_llgr_families.get(&peer).cloned();
        let rtc_filter = self.rtc_vpn_filter(peer, sendable.as_ref());
        let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
        let interpret_rfc1997 = self.peer_interpret_rfc1997.contains(&peer);
        let rs_control_asn = self.peer_rs_control.get(&peer).copied();
        let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
        let target_peer_asn = self.peer_asn.get(&peer).copied();
        let target_peer_group = self.peer_group.get(&peer).map(String::as_str);
        let cluster_id = self.cluster_id;
        let peer_add_path_send_max = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
        let peer_add_path_send_limits = self
            .peer_add_path_send_limits
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let peer_add_path_send_families = self
            .peer_add_path_send_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        // RFC 9107 ORR: the refresh replay re-derives the same
        // per-vantage best the live distribution path would send; an
        // unresolved vantage falls back to the standard single-best.
        let orr_ctx = self
            .peer_orr_vantage
            .get(&peer)
            .and_then(|vantage| self.orr.spf.get(vantage))
            .map(|spf| (&self.orr.topology, spf));
        let per_client_best = self.peer_per_client_best.contains(&peer);
        let loc_rib = &self.loc_rib;
        let target_peer_label = peer.to_string();
        let metrics = self.metrics.clone();
        let member_of = self.grouped_member_of(peer);
        // Resolved before the `policy_stats` borrow below (whole-`self`
        // method call).
        let vpn_member_of = self.vpn_grouped_member_of(peer);
        let policy_stats = self.export_policy_stats.entry(peer).or_default();

        let mut all_prefixes: HashSet<Prefix> = self
            .loc_rib
            .iter()
            .map(|r| r.prefix)
            .filter(|p| prefix_family(p) == family)
            .collect();
        for rib in self.ribs.values() {
            all_prefixes.extend(
                rib.iter()
                    .map(|r| r.prefix)
                    .filter(|p| prefix_family(p) == family),
            );
        }

        // Stage against an empty outbound view so ROUTE-REFRESH
        // re-advertises the current export set for this family rather than
        // diffing against what was already sent.
        let refresh_view = AdjRibOut::new(peer);
        let mut current_policy_filtered_routes: HashSet<PolicyFilteredRouteKey> = HashSet::new();

        if safi == Safi::FlowSpec {
            let flow_rules: HashSet<FlowSpecKey> = self
                .loc_rib
                .iter_flowspec()
                .filter(|route| route.afi == afi)
                .map(FlowSpecRoute::selection_key)
                .collect();
            if !flow_rules.is_empty() {
                Self::stage_flowspec_rules(
                    loc_rib,
                    &refresh_view,
                    &self.peer_is_rr_client,
                    &flow_rules,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut fs_announce,
                    &mut fs_withdraw,
                );
            }
        } else if (afi, safi) == (Afi::L2Vpn, Safi::Evpn) {
            let evpn_keys: HashSet<EvpnRouteKey> = self
                .loc_rib
                .iter_evpn()
                .map(crate::route::EvpnRibRoute::key)
                .collect();
            if !evpn_keys.is_empty() {
                Self::stage_evpn_routes(
                    loc_rib,
                    &refresh_view,
                    &self.peer_is_rr_client,
                    &evpn_keys,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut evpn_announce,
                    &mut evpn_withdraw,
                    false, // route refresh re-emits via empty refresh_view
                );
            }
        } else if let Some(bgpls_family) = BgpLsFamily::from_afi_safi(afi, safi) {
            let bgpls_keys: HashSet<crate::route::BgpLsRouteKey> = self
                .loc_rib
                .iter_bgpls()
                .filter(|route| route.family == bgpls_family)
                .map(crate::route::BgpLsRibRoute::key)
                .collect();
            if !bgpls_keys.is_empty() {
                Self::stage_bgpls_routes(
                    loc_rib,
                    &refresh_view,
                    &self.peer_is_rr_client,
                    &bgpls_keys,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    interpret_rfc1997,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut bgpls_announce,
                    &mut bgpls_withdraw,
                    false, // route refresh re-emits via empty refresh_view
                );
            }
        } else if safi == Safi::MplsVpn {
            // A member of a VPN-staging group replays the refreshed
            // family from the group table — own-sourced excluded,
            // Φ-filtered (the RFC 4684 gate the per-peer refresh would
            // have applied; RFC 7313 refresh under heterogeneous
            // memberships stays per-member exact), NO policy
            // re-evaluation (same shape as the unicast grouped arm
            // below).
            if let Some(gid) = vpn_member_of {
                if let Some(group) = self.group_ribs.get(&gid) {
                    for route in group.table.iter_vpn() {
                        if route.peer == peer
                            || route.afi_safi() != family
                            || !super::update_groups::rt_passes(rtc_filter.as_ref(), route)
                        {
                            continue;
                        }
                        vpn_announce.push(route.clone());
                    }
                }
                // Export counters for the replayed family, from the
                // group's staged residue (per-peer refresh re-eval
                // parity).
                self.apply_group_join_counters(peer, gid, Some(family));
            } else {
                let mut vpn_keys: HashSet<rustbgpd_wire::VpnRouteKey> = self
                    .loc_rib
                    .iter_vpn()
                    .filter(|route| route.afi_safi() == family)
                    .map(|route| route.nlri.key())
                    .collect();
                // An Add-Path-send refresh re-emits the staged top-N, which
                // draws from every Adj-RIB-In identity of the family.
                if peer_add_path_send_max > 0
                    && peer_add_path_send_families
                        .iter()
                        .any(|(_, safi)| *safi == Safi::MplsVpn)
                {
                    for rib in self.ribs.values() {
                        vpn_keys.extend(
                            rib.iter_vpn()
                                .filter(|route| route.afi_safi() == family)
                                .map(|route| route.nlri.key()),
                        );
                    }
                }
                if !vpn_keys.is_empty() {
                    let mut target = super::distribution::ExportTarget::Peer {
                        peer,
                        peer_asn: target_peer_asn,
                        peer_group: target_peer_group,
                        metrics: &metrics,
                        policy_stats: &mut *policy_stats,
                        peer_label: &target_peer_label,
                    };
                    Self::stage_vpn_routes(
                        loc_rib,
                        &self.ribs,
                        &refresh_view,
                        &self.peer_is_rr_client,
                        &vpn_keys,
                        &mut target,
                        target_is_ebgp,
                        interpret_rfc1997,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        llgr.as_ref(),
                        rtc_filter.as_ref(),
                        orr_ctx,
                        peer_add_path_send_max,
                        self.peer_add_path_send_limits.get(&peer),
                        &peer_add_path_send_families,
                        export_pol.as_ref(),
                        &mut vpn_announce,
                        &mut vpn_withdraw,
                        false, // route refresh re-emits via empty refresh_view
                    );
                }
            }
        } else if safi == Safi::LabeledUnicast {
            let mut labeled_keys: HashSet<Prefix> = self
                .loc_rib
                .iter_labeled()
                .filter(|route| route.afi_safi() == family)
                .map(|route| route.nlri.key())
                .collect();
            // An Add-Path-send refresh re-emits the staged top-N, which
            // draws from every Adj-RIB-In identity of the family.
            if peer_add_path_send_max > 0
                && peer_add_path_send_families
                    .iter()
                    .any(|(_, safi)| *safi == Safi::LabeledUnicast)
            {
                for rib in self.ribs.values() {
                    labeled_keys.extend(
                        rib.iter_labeled()
                            .filter(|route| route.afi_safi() == family)
                            .map(|route| route.nlri.key()),
                    );
                }
            }
            if !labeled_keys.is_empty() {
                let mut target = super::distribution::ExportTarget::Peer {
                    peer,
                    peer_asn: target_peer_asn,
                    peer_group: target_peer_group,
                    metrics: &metrics,
                    policy_stats: &mut *policy_stats,
                    peer_label: &target_peer_label,
                };
                Self::stage_labeled_routes(
                    loc_rib,
                    &self.ribs,
                    &refresh_view,
                    &self.peer_is_rr_client,
                    &labeled_keys,
                    &mut target,
                    target_is_ebgp,
                    interpret_rfc1997,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    orr_ctx,
                    peer_add_path_send_max,
                    self.peer_add_path_send_limits.get(&peer),
                    &peer_add_path_send_families,
                    export_pol.as_ref(),
                    &mut labeled_announce,
                    &mut labeled_withdraw,
                    false, // route refresh re-emits via empty refresh_view
                );
            }
        } else if safi == Safi::RtConstrain {
            let rtc_keys: HashSet<crate::route::RtcRibRouteKey> = self
                .loc_rib
                .iter_rtc()
                .map(crate::route::RtcRibRoute::key)
                .collect();
            if !rtc_keys.is_empty() {
                Self::stage_rtc_routes(
                    loc_rib,
                    &refresh_view,
                    &self.peer_is_rr_client,
                    &rtc_keys,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    interpret_rfc1997,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    export_pol.as_ref(),
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut rtc_announce,
                    &mut rtc_withdraw,
                    false, // route refresh re-emits via empty refresh_view
                );
            }
        } else if let Some(gid) = member_of {
            // A grouped member's refresh replay comes from the group
            // table — family-filtered, own-sourced excluded — with NO
            // policy re-evaluation: the export tail already ran when the
            // table was staged (same shape as the join replay in
            // `send_initial_table`). BoRR/EoRR markers stay per-peer via
            // the send below. ORF disqualifies from grouping, so the
            // deferred-ORF withdraw sweep in the per-peer arm can never
            // apply to a grouped member.
            if let Some(group) = self.group_ribs.get(&gid) {
                // LAN-474: same per-target divergence as the join
                // replay — suppressed entries skipped, announced tagged
                // entries rewritten per target.
                let rs_control = rs_control_asn.zip(target_peer_asn);
                for route in group.table.iter() {
                    if route.peer == peer
                        || prefix_family(&route.prefix) != family
                        || super::distribution::rs_control::rs_control_route_suppressed(
                            route, rs_control,
                        )
                    {
                        continue;
                    }
                    nh_override_flags.push(group.nh_override((route.prefix, route.path_id)));
                    let mut route = route.clone();
                    super::distribution::rs_control::rs_control_route_rewrite(
                        &mut route, rs_control,
                    );
                    announce.push(route);
                }
                current_policy_filtered_routes
                    .extend(group.policy_filtered_for_member(peer, &all_prefixes));
            }
            // Export counters for the replayed family, from the group's
            // staged residue (per-peer refresh re-eval parity).
            self.apply_group_join_counters(peer, gid, Some(family));
        } else {
            // Pass-scoped export memo: one refresh is a single peer, but
            // routes sharing an inbound attribute set still share the
            // post-modification attributes and AS_PATH match string.
            let mut export_memo = super::distribution::ExportMemo::default();
            for prefix in &all_prefixes {
                let prefix_family = prefix_family(prefix);
                let prefix_send_max = if peer_add_path_send_families.contains(&prefix_family) {
                    peer_add_path_send_limits
                        .get(&prefix_family)
                        .copied()
                        .unwrap_or(peer_add_path_send_max)
                } else {
                    0
                };
                if prefix_send_max > 0 {
                    let mut policy_filtered = Vec::new();
                    Self::distribute_multipath_prefix(
                        &self.ribs,
                        &self.unicast_prefix_peers,
                        &refresh_view,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        target_peer_asn,
                        target_peer_group,
                        prefix_send_max,
                        false,
                        target_is_ebgp,
                        interpret_rfc1997,
                        rs_control_asn,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        llgr.as_ref(),
                        export_pol.as_ref(),
                        orf_filter.as_ref(),
                        orr_ctx,
                        &mut export_memo,
                        &metrics,
                        policy_stats,
                        &target_peer_label,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        false, // route refresh re-emits all anyway via empty refresh_view
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                } else if per_client_best {
                    // RFC 7947 §2.3.2 per-client best-path: the refresh
                    // replay re-derives the same filtered best the live
                    // distribution path stages (path_id 0). See the
                    // `send_initial_table` arm for the mode-precedence
                    // notes (Add-Path outranks; ORR cannot coexist).
                    debug_assert!(orr_ctx.is_none(), "ORR vantage on a per-client-best peer");
                    let mut policy_filtered = Vec::new();
                    Self::distribute_multipath_prefix(
                        &self.ribs,
                        &self.unicast_prefix_peers,
                        &refresh_view,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        target_peer_asn,
                        target_peer_group,
                        1,
                        true,
                        target_is_ebgp,
                        interpret_rfc1997,
                        rs_control_asn,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        llgr.as_ref(),
                        export_pol.as_ref(),
                        orf_filter.as_ref(),
                        None,
                        &mut export_memo,
                        &metrics,
                        policy_stats,
                        &target_peer_label,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        false, // route refresh re-emits all anyway via empty refresh_view
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                } else if let Some((orr_topology, orr_spf)) = orr_ctx {
                    // ORR peer with a resolved vantage: per-vantage best.
                    let mut policy_filtered = Vec::new();
                    Self::distribute_orr_best_prefix(
                        &self.ribs,
                        &self.unicast_prefix_peers,
                        &refresh_view,
                        &self.peer_is_rr_client,
                        orr_topology,
                        orr_spf,
                        prefix,
                        peer,
                        target_peer_asn,
                        target_peer_group,
                        target_is_ebgp,
                        interpret_rfc1997,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        llgr.as_ref(),
                        export_pol.as_ref(),
                        orf_filter.as_ref(),
                        &mut export_memo,
                        &metrics,
                        policy_stats,
                        &target_peer_label,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        false,
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                } else {
                    let mut policy_filtered = Vec::new();
                    let mut target = super::distribution::ExportTarget::Peer {
                        peer,
                        peer_asn: target_peer_asn,
                        peer_group: target_peer_group,
                        metrics: &metrics,
                        policy_stats: &mut *policy_stats,
                        peer_label: &target_peer_label,
                    };
                    Self::distribute_single_best_prefix(
                        loc_rib,
                        &refresh_view,
                        &self.peer_is_rr_client,
                        prefix,
                        &mut target,
                        target_is_ebgp,
                        interpret_rfc1997,
                        rs_control_asn,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        llgr.as_ref(),
                        export_pol.as_ref(),
                        orf_filter.as_ref(),
                        &mut export_memo,
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                        &mut policy_filtered,
                        false,
                    );
                    current_policy_filtered_routes.extend(policy_filtered);
                }
            }
            // The refresh view is intentionally empty so permitted routes are
            // re-advertised for ROUTE-REFRESH. That empty view cannot discover
            // routes that were advertised before a deferred ORF update and are
            // now denied by the installed filter, so withdraw those explicitly
            // from the real Adj-RIB-Out.
            if let (Some(filter), Some(rib_out)) =
                (orf_filter.as_ref(), self.adj_ribs_out.get(&peer))
            {
                for route in rib_out
                    .iter()
                    .filter(|r| prefix_family(&r.prefix) == family && !filter.permits(&r.prefix))
                {
                    withdraw.push((route.prefix, route.path_id));
                }
            }
        }

        if self.outbound_peers.contains_key(&peer) {
            let mut group_prior = HashSet::new();
            if member_of.is_some()
                && let Some(routes) = self.grouped_advertised_routes(peer)
            {
                group_prior.extend(routes.into_iter().map(|route| {
                    crate::update::ExactExportKey::Unicast(route.prefix, route.path_id)
                }));
            }
            if let Some(gid) = vpn_member_of
                && let Some(group) = self.group_ribs.get(&gid)
            {
                let filter = self.member_rt_filter(peer);
                let rejected = self.peer_unexportable.get(&peer);
                group_prior.extend(group.table.iter_vpn().filter_map(|route| {
                    let key = crate::update::ExactExportKey::Vpn(route.key());
                    (route.peer != peer
                        && crate::manager::update_groups::rt_passes(filter.as_ref(), route)
                        && !rejected.is_some_and(|keys| keys.contains(&key)))
                    .then_some(key)
                }));
            }
            if !self.try_send_and_commit_outbound_update_with_group_prior(
                peer,
                nh_override_flags.into(),
                announce.into(),
                withdraw,
                if deferred_eor || suppress_eor {
                    vec![]
                } else {
                    vec![family]
                },
                vec![
                    (afi, safi, RouteRefreshSubtype::BoRR),
                    (afi, safi, RouteRefreshSubtype::EoRR),
                ],
                fs_announce,
                fs_withdraw,
                evpn_announce,
                evpn_withdraw,
                bgpls_announce,
                bgpls_withdraw,
                vpn_announce,
                vpn_withdraw,
                labeled_announce,
                labeled_withdraw,
                rtc_announce,
                rtc_withdraw,
                group_prior,
                None,
            ) {
                warn!(%peer, ?family, "outbound channel full during route refresh response");
                self.metrics.record_outbound_route_drop(&peer.to_string());
                self.pending_refresh.entry(peer).or_default().insert(family);
                self.mark_outbound_dirty(peer);
                return;
            }
            self.update_policy_filtered_routes_for_prefixes(
                peer,
                &all_prefixes,
                &current_policy_filtered_routes,
            );
            self.pending_refresh
                .entry(peer)
                .or_default()
                .remove(&family);
            if deferred_eor {
                if let Some(families) = self.gr_deferred_eor.get_mut(&peer) {
                    families.remove(&family);
                    if families.is_empty() {
                        self.gr_deferred_eor.remove(&peer);
                    }
                }
                self.pending_eor.entry(peer).or_default().insert(family);
                // The gated flood was just enqueued above; flushing now keeps
                // the EoR behind it on the channel. A dirty peer defers to the
                // resync paths instead — they flush pending EoR only AFTER a
                // successful resync, and flushing here would emit any OTHER
                // deferred families' EoR ahead of the resync that replays
                // their table.
                if !self.dirty_peers.contains(&peer) {
                    self.flush_pending_eor(peer);
                }
            }
        }
    }

    /// Try to send any deferred `EoR` markers for a peer.
    ///
    /// Called after a successful dirty-peer resync. If the send fails again,
    /// the peer is re-marked dirty for another attempt.
    pub(super) fn flush_pending_eor(&mut self, peer: IpAddr) {
        let Some(families) = self.pending_eor.remove(&peer) else {
            return;
        };
        let (blocked, ready): (HashSet<_>, HashSet<_>) = families
            .into_iter()
            .partition(|family| self.selection_convergence_held(*family));
        if !blocked.is_empty() {
            self.pending_eor.entry(peer).or_default().extend(blocked);
        }
        if ready.is_empty() {
            return;
        }
        let Some(tx) = self.outbound_peers.get(&peer) else {
            return;
        };
        let eor = OutboundRouteUpdate {
            end_of_rib: ready.iter().copied().collect(),
            ..OutboundRouteUpdate::default()
        };
        if tx.try_send(eor).is_err() {
            warn!(%peer, "outbound channel full — `EoR` still deferred");
            self.pending_eor.entry(peer).or_default().extend(ready);
            self.mark_outbound_dirty(peer);
        }
    }

    /// Retry any deferred enhanced route refresh responses for a peer.
    pub(super) fn retry_pending_refresh(&mut self, peer: IpAddr) {
        let Some(families) = self.pending_refresh.remove(&peer) else {
            return;
        };
        for (afi, safi) in families {
            self.send_route_refresh_response(peer, afi, safi);
        }
    }

    /// Finish an active inbound enhanced route refresh window for a peer/family.
    ///
    /// When `timed_out` is true, treats the timeout as an implicit end-of-
    /// refresh sweep and logs a warning before cleaning up unreplaced state.
    #[expect(
        clippy::too_many_lines,
        reason = "refresh finisher sweeps unreplaced unicast, FlowSpec, and EVPN routes and clears per-family tracking state"
    )]
    pub(super) fn finish_route_refresh(
        &mut self,
        peer: IpAddr,
        afi: Afi,
        safi: Safi,
        timed_out: bool,
    ) {
        let family = (afi, safi);
        self.refresh_deadlines.remove(&(peer, afi, safi));

        let active = self
            .refresh_in_progress
            .get(&peer)
            .is_some_and(|families| families.contains(&family));
        if !active {
            debug!(%peer, ?afi, ?safi, "End-of-RIB-Refresh without active refresh state, ignoring");
            return;
        }
        // Timeout completion reaches this method directly from the timer arm;
        // ordinary End-of-RIB-Refresh is already fenced by `handle_update`.
        // Advancing here covers both without relying on a later distribution.
        self.advance_all_route_pages();
        if timed_out {
            warn!(
                %peer,
                ?afi,
                ?safi,
                timeout_secs = ERR_REFRESH_TIMEOUT.as_secs(),
                "enhanced route refresh timed out — sweeping unreplaced routes"
            );
        }

        let stale_route_keys: Vec<(Prefix, u32)> = self
            .refresh_stale_routes
            .get(&peer)
            .map(|stale| {
                stale
                    .iter()
                    .copied()
                    .filter(|(prefix, _)| prefix_family(prefix) == family)
                    .collect()
            })
            .unwrap_or_default();
        let stale_flowspec_keys: Vec<FlowSpecRouteKey> = self
            .refresh_stale_flowspec
            .get(&peer)
            .map(|stale| {
                stale
                    .iter()
                    .filter(|key| key.afi == afi && safi == Safi::FlowSpec)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        let stale_evpn_keys: Vec<EvpnRouteKey> = if family == (Afi::L2Vpn, Safi::Evpn) {
            self.refresh_stale_evpn
                .get(&peer)
                .map(|stale| stale.iter().copied().collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let stale_bgpls_keys: Vec<crate::route::BgpLsRouteKey> =
            if let Some(bgpls_family) = BgpLsFamily::from_afi_safi(afi, safi) {
                self.refresh_stale_bgpls
                    .get(&peer)
                    .map(|stale| {
                        stale
                            .iter()
                            .filter(|key| key.family == bgpls_family)
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
        let stale_l3vpn_keys: Vec<crate::route::VpnRibRouteKey> = if safi == Safi::MplsVpn {
            self.refresh_stale_vpn
                .get(&peer)
                .map(|stale| {
                    stale
                        .iter()
                        .filter(|key| key.afi_safi() == family)
                        .cloned()
                        .collect()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let stale_labeled_keys: Vec<crate::route::LabeledRibRouteKey> =
            if safi == Safi::LabeledUnicast {
                self.refresh_stale_labeled
                    .get(&peer)
                    .map(|stale| {
                        stale
                            .iter()
                            .filter(|key| key.afi_safi() == family)
                            .copied()
                            .collect()
                    })
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
        let stale_rtc_keys: Vec<crate::route::RtcRibRouteKey> = if safi == Safi::RtConstrain {
            self.refresh_stale_rtc
                .get(&peer)
                .map(|stale| stale.iter().cloned().collect())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let mut affected = HashSet::new();
        let mut fs_affected = HashSet::new();
        let mut evpn_affected: HashSet<EvpnRouteKey> = HashSet::new();
        let mut bgpls_affected: HashSet<crate::route::BgpLsRouteKey> = HashSet::new();
        let mut vpn_affected: HashSet<crate::route::VpnRibRouteKey> = HashSet::new();
        let mut labeled_affected: HashSet<crate::route::LabeledRibRouteKey> = HashSet::new();
        let mut rtc_affected: HashSet<crate::route::RtcRibRouteKey> = HashSet::new();
        if let Some(rib) = self.ribs.get_mut(&peer) {
            for (prefix, path_id) in &stale_route_keys {
                if rib.withdraw(prefix, *path_id) {
                    affected.insert(*prefix);
                }
            }
            for key in &stale_flowspec_keys {
                if rib.withdraw_flowspec(key) {
                    fs_affected.insert(FlowSpecKey {
                        afi: key.afi,
                        rule: key.rule.clone(),
                    });
                }
            }
            for key in &stale_evpn_keys {
                if rib.withdraw_evpn(key) {
                    evpn_affected.insert(*key);
                }
            }
            for key in &stale_bgpls_keys {
                if rib.withdraw_bgpls(key) {
                    bgpls_affected.insert(key.clone());
                }
            }
            for key in &stale_l3vpn_keys {
                if rib.withdraw_vpn(key) {
                    vpn_affected.insert(key.clone());
                }
            }
            for key in &stale_labeled_keys {
                if rib.withdraw_labeled(key) {
                    labeled_affected.insert(*key);
                }
            }
            for key in &stale_rtc_keys {
                if rib.withdraw_rtc(key) {
                    rtc_affected.insert(key.clone());
                }
            }
            // Reclaim attribute interns dropped by the bulk withdraw —
            // each withdraw above can leave a `strong_count==1` Arc in
            // the intern table that wouldn't otherwise be GC'd until
            // some unrelated future withdraw on this peer.
            if !affected.is_empty()
                || !fs_affected.is_empty()
                || !evpn_affected.is_empty()
                || !bgpls_affected.is_empty()
                || !vpn_affected.is_empty()
                || !labeled_affected.is_empty()
                || !rtc_affected.is_empty()
            {
                self.attr_intern.gc();
                self.metrics
                    .set_rib_attr_intern_global_size(gauge_val(self.attr_intern.len()));
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

        let clear_route_stale_entry = if let Some(stale) = self.refresh_stale_routes.get_mut(&peer)
        {
            stale.retain(|(prefix, _)| prefix_family(prefix) != family);
            stale.is_empty()
        } else {
            false
        };
        if clear_route_stale_entry {
            self.refresh_stale_routes.remove(&peer);
        }

        let clear_flowspec_stale_entry =
            if let Some(stale) = self.refresh_stale_flowspec.get_mut(&peer) {
                stale.retain(|key| !(key.afi == afi && safi == Safi::FlowSpec));
                stale.is_empty()
            } else {
                false
            };
        if clear_flowspec_stale_entry {
            self.refresh_stale_flowspec.remove(&peer);
        }

        if family == (Afi::L2Vpn, Safi::Evpn) {
            self.refresh_stale_evpn.remove(&peer);
        }
        if safi == Safi::RtConstrain {
            self.refresh_stale_rtc.remove(&peer);
        }
        if let Some(bgpls_family) = BgpLsFamily::from_afi_safi(afi, safi) {
            let clear_bgpls_stale_entry =
                if let Some(stale) = self.refresh_stale_bgpls.get_mut(&peer) {
                    stale.retain(|key| key.family != bgpls_family);
                    stale.is_empty()
                } else {
                    false
                };
            if clear_bgpls_stale_entry {
                self.refresh_stale_bgpls.remove(&peer);
            }
        }
        if safi == Safi::MplsVpn {
            let clear_vpn_stale_entry = if let Some(stale) = self.refresh_stale_vpn.get_mut(&peer) {
                stale.retain(|key| key.afi_safi() != family);
                stale.is_empty()
            } else {
                false
            };
            if clear_vpn_stale_entry {
                self.refresh_stale_vpn.remove(&peer);
            }
        }
        if safi == Safi::LabeledUnicast {
            let clear_labeled_stale_entry =
                if let Some(stale) = self.refresh_stale_labeled.get_mut(&peer) {
                    stale.retain(|key| key.afi_safi() != family);
                    stale.is_empty()
                } else {
                    false
                };
            if clear_labeled_stale_entry {
                self.refresh_stale_labeled.remove(&peer);
            }
        }
        self.refresh_stale_counts.remove(&(peer, afi, safi));

        let clear_refresh_entry = if let Some(families) = self.refresh_in_progress.get_mut(&peer) {
            families.remove(&family);
            families.is_empty()
        } else {
            false
        };
        if clear_refresh_entry {
            self.refresh_in_progress.remove(&peer);
        }
        self.update_refresh_metrics(peer, afi, safi);

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
            // Reclaim attribute sets stranded by the stale-BGP-LS withdrawals
            // above. The earlier intern gc ran before this recompute,
            // while the Loc-RIB still held the selected-route Arc clones, so
            // those orphans survived (gc only frees a set whose sole remaining
            // holder is the intern table). Now that recompute_bgpls_keys has
            // dropped the Loc-RIB clones, gc reclaims them — mirroring the
            // receive path's recompute-then-gc ordering.
            self.gc_attr_intern();
        }
        if !vpn_affected.is_empty() {
            self.recompute_vpn_keys(&vpn_affected);
            // Same gc-after-recompute ordering as BGP-LS above: the swept VPN
            // routes' interned attribute sets stay alive in the Loc-RIB clone
            // until recompute_vpn_keys drops it, so gc must run after it.
            self.gc_attr_intern();
        }
        if !labeled_affected.is_empty() {
            self.recompute_labeled_keys(&labeled_affected);
            // Same gc-after-recompute ordering as VPN above.
            self.gc_attr_intern();
        }
        if !rtc_affected.is_empty() {
            self.recompute_rtc_keys(&rtc_affected);
            self.gc_attr_intern();
            // The sweep just mutated this peer's RTC Adj-RIB-In — its RT
            // membership shrank, so VPN routes no longer covered must be
            // withdrawn from this peer's Adj-RIB-Out.
            self.rebuild_rtc_membership_and_restage_vpn(peer);
        }
    }
}
