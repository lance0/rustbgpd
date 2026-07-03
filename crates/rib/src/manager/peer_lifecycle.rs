use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};

use rustbgpd_policy::PolicyChain;
use rustbgpd_wire::{EvpnRouteKey, FlowSpecRule, Prefix, Safi};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use super::helpers::prefix_family;
use super::{LiveSessionRecord, MAX_LIVE_SESSIONS_PER_PEER, PolicyFilteredRouteKey, RibManager};
use crate::adj_rib_out::AdjRibOut;
use crate::update::OutboundRouteUpdate;

/// How a session-down event (`PeerDown` / `PeerGracefulRestart`) relates
/// to the peer's registration state — the dispatch result of
/// [`RibManager::classify_session_teardown`]. Covers every interleaving
/// of `{PeerUp(winner), PeerUp(loser), PeerDown(loser)}` in the RFC 4271
/// §6.8 collision window.
pub(super) enum SessionTeardownDisposition {
    /// No registered session for the peer (never registered, already torn
    /// down, or in a GR window) — keep the pre-stamping accept-all
    /// behavior.
    NoRegistration,
    /// The stamped id is not the active registration: a teardown from a
    /// superseded (or already-dropped) session. Discarded whole; if the
    /// session was still tracked as live it has been pruned.
    DiscardStale,
    /// The ACTIVE session went down but another live session for the same
    /// address remains — fail the registration over to it instead of
    /// tearing the peer down.
    FailOver,
    /// The active session went down and no other live session remains —
    /// run the normal full teardown.
    TeardownActive,
}

impl RibManager {
    /// Session-down teardown, dispatched on session identity (see
    /// [`SessionTeardownDisposition`]): a stale teardown from a
    /// superseded session is discarded WHOLE — not just outbound
    /// deregistration but also the Adj-RIB-In clear, GR/LLGR aborts, and
    /// every other per-peer teardown, all of which would otherwise
    /// destroy the surviving session's state. A `PeerDown` of the active
    /// session while ANOTHER live session remains (the symmetric
    /// collision interleaving: the loser's `PeerUp` replaced the winner's
    /// registration before the loser went down) fails the registration
    /// over to the survivor instead of tearing the peer down.
    pub(super) fn handle_peer_down(&mut self, peer: IpAddr, session_id: u64) {
        match self.classify_session_teardown(peer, session_id, "PeerDown") {
            SessionTeardownDisposition::DiscardStale => {}
            SessionTeardownDisposition::FailOver => {
                self.fail_over_registration(peer, session_id, "PeerDown");
            }
            SessionTeardownDisposition::NoRegistration
            | SessionTeardownDisposition::TeardownActive => self.peer_down_teardown(peer),
        }
    }

    /// The session-identity dispatch shared by `handle_peer_down` and
    /// `handle_peer_graceful_restart`. Prunes the stamped session from
    /// `live_sessions` (it is down, whatever else happens) and classifies
    /// the event against the active registration. Discards are logged at
    /// INFO + counted in `bgp_rib_stale_peer_down_ignored_total`; a
    /// teardown for a peer with no registered session keeps the
    /// pre-stamping accept-all behavior and is never discarded.
    pub(super) fn classify_session_teardown(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        event: &str,
    ) -> SessionTeardownDisposition {
        let Some(&registered) = self.outbound_session_ids.get(&peer) else {
            // No registration — nothing to protect and nothing to fail
            // over to (`live_sessions` is empty for the peer whenever no
            // registration exists; a full teardown clears both together).
            return SessionTeardownDisposition::NoRegistration;
        };
        if registered != session_id {
            // Not the active session. If it was still tracked as live
            // (its PeerUp was superseded by a later registration), prune
            // it — this PeerDown is the collision loser finally going
            // down — then discard the teardown whole.
            if let Some(sessions) = self.live_sessions.get_mut(&peer) {
                sessions.retain(|s| s.session_id != session_id);
            }
            info!(
                %peer,
                event,
                stale_session_id = session_id,
                registered_session_id = registered,
                "discarding stale session teardown from a superseded session — \
                 the registered session's state is untouched"
            );
            self.metrics
                .record_rib_stale_peer_down_ignored(&peer.to_string());
            return SessionTeardownDisposition::DiscardStale;
        }
        // The active session went down. Prune it; if another live session
        // remains the registration fails over to it.
        let survivor_remains = {
            let sessions = self.live_sessions.entry(peer).or_default();
            sessions.retain(|s| s.session_id != session_id);
            !sessions.is_empty()
        };
        if survivor_remains {
            SessionTeardownDisposition::FailOver
        } else {
            self.live_sessions.remove(&peer);
            SessionTeardownDisposition::TeardownActive
        }
    }

    /// Session-identity gate for the data-plane-affecting messages a
    /// session emits while Established (`RoutesReceived`, `EndOfRib`,
    /// `BeginRouteRefresh`/`EndRouteRefresh`, `RouteRefreshRequest`,
    /// `PeerOrfUpdate`). Returns `true` when the message must be
    /// discarded: a registration exists for the peer and the stamped id
    /// is not the active session — a message from a superseded session
    /// (RFC 4271 §6.8 collision window) queued behind the replacement's
    /// `PeerUp`. Without the gate, such a message would mutate the
    /// REPLACEMENT session's state: stale routes landing in its
    /// Adj-RIB-In, a stale `EoR` prematurely completing its GR sweep, a
    /// stale `EoRR` closing its enhanced-refresh window early, or stale
    /// ORF entries installed as its outbound filter, or stale peer-group
    /// policy context being assigned to the replacement session.
    ///
    /// A message for a peer with NO registration keeps the pre-stamping
    /// accept-all behavior, mirroring the teardown rule in
    /// [`Self::classify_session_teardown`]. Unlike teardowns there is no
    /// GR-window case to protect here — per-producer FIFO means a
    /// session's data messages are always delivered between its own
    /// `PeerUp` (which registers) and its own down event (after which it
    /// emits nothing), so an unregistered data message can only come
    /// from a legacy emitter that never registered, and dropping those
    /// would change behavior for no safety gain.
    ///
    /// Discards are logged at INFO (same shape as the stale-teardown
    /// discard) and counted in
    /// `bgp_rib_stale_session_message_ignored_total{peer,kind}`.
    /// `kind` is bounded: `routes`, `eor`, `refresh`, `orf`,
    /// `policy_context`.
    pub(super) fn stale_session_message(
        &self,
        peer: IpAddr,
        session_id: u64,
        event: &'static str,
        kind: &'static str,
    ) -> bool {
        let Some(&registered) = self.outbound_session_ids.get(&peer) else {
            return false;
        };
        if registered == session_id {
            return false;
        }
        info!(
            %peer,
            event,
            stale_session_id = session_id,
            registered_session_id = registered,
            "discarding stale session message from a superseded session — \
             the registered session's state is untouched"
        );
        self.metrics
            .record_rib_stale_session_message_ignored(&peer.to_string(), kind);
        true
    }

    /// Hand the outbound registration to the most recent surviving live
    /// session after the active session's down event (the symmetric
    /// collision interleaving `PeerUp(winner)` → `PeerUp(loser)` →
    /// `PeerDown(loser)`, where the loser's `PeerUp` had replaced the
    /// winner's registration).
    ///
    /// Outbound: per-session state attributed to the dead active session
    /// is reset exactly like the replacement-`PeerUp` reset (GR/LLGR
    /// stale retention stays put — deadline-bounded as on a plain GR
    /// reconnect), then the survivor is re-registered and re-sent the
    /// initial table dump.
    ///
    /// Inbound: the survivor's Adj-RIB-In cannot be restored locally —
    /// the replacement reset already destroyed it, and while superseded
    /// the survivor's stamped `RoutesReceived` were discarded by the
    /// session-identity gate. Recovery is delegated to
    /// the peer: a ROUTE-REFRESH request (RFC 2918) is enqueued through
    /// the survivor's outbound channel for its negotiated families. The
    /// session task enforces the negotiated capability; if the peer never
    /// negotiated Route Refresh, inbound state stays empty until the
    /// peer's natural re-advertisement (its next own route change) — that
    /// staleness window is logged by the session task.
    pub(super) fn fail_over_registration(&mut self, peer: IpAddr, down_id: u64, event: &str) {
        let survivor_id = self
            .live_sessions
            .get(&peer)
            .and_then(|sessions| sessions.last())
            .map(|record| record.session_id);
        warn!(
            %peer,
            event,
            down_session_id = down_id,
            survivor_session_id = survivor_id,
            "active session went down with another live session present — \
             failing the outbound registration over to the survivor"
        );
        self.metrics
            .record_rib_outbound_registration_failover(&peer.to_string());
        // Same reset shape as the replacement-PeerUp: the dead session's
        // received routes go, GR/LLGR-retained routes stay (deadline-
        // bounded, swept on End-of-RIB or expiry).
        if !self.gr_peers.contains_key(&peer) && !self.llgr_peers.contains_key(&peer) {
            self.clear_policy_filtered_routes_for_peer(peer);
            self.clear_peer_adj_rib_in(peer);
        }
        self.clear_outbound_peer_state(peer);
        self.register_active_session(peer);
        self.request_inbound_refresh(peer);
    }

    /// Ask the active session's peer to re-advertise its routes
    /// (ROUTE-REFRESH request, RFC 2918) for the session's negotiated
    /// families — the inbound half of a registration failover. The
    /// manager only raises the flag; the family set is chosen by the
    /// session task from its authoritative negotiated set, because the
    /// manager's live-session record holds only the *sendable* (outbound)
    /// subset and a family negotiated for receive but pruned from it must
    /// still be refreshed. One-shot best-effort: a full outbound channel
    /// only loses the *request*; the peer's natural re-advertisement
    /// remains the fallback, and the outbound table resync is handled
    /// separately by the dirty-peer mechanism.
    fn request_inbound_refresh(&mut self, peer: IpAddr) {
        let Some(record) = self
            .live_sessions
            .get(&peer)
            .and_then(|sessions| sessions.last())
        else {
            return;
        };
        let update = OutboundRouteUpdate {
            announce: vec![],
            withdraw: vec![],
            end_of_rib: vec![],
            refresh_markers: vec![],
            next_hop_override: vec![],
            flowspec_announce: vec![],
            flowspec_withdraw: vec![],
            evpn_announce: vec![],
            evpn_withdraw: vec![],
            bgpls_announce: vec![],
            bgpls_withdraw: vec![],
            vpn_announce: vec![],
            labeled_announce: vec![],
            rtc_announce: vec![],
            vpn_withdraw: vec![],
            labeled_withdraw: vec![],
            rtc_withdraw: vec![],
            request_refresh_all_negotiated: true,
        };
        if record.outbound_tx.try_send(update).is_err() {
            warn!(
                %peer,
                "outbound channel full or closed — inbound ROUTE-REFRESH request \
                 after failover was dropped; Adj-RIB-In recovers only on the \
                 peer's natural re-advertisement"
            );
            self.metrics.record_outbound_route_drop(&peer.to_string());
        }
    }

    /// The unconditional `PeerDown` teardown body. Callers that bypass
    /// the session-identity gate are authoritative non-session events:
    /// peer deletion (config removed the neighbor) and GR/LLGR retention
    /// expiry (the peer never came back).
    pub(super) fn peer_down_teardown(&mut self, peer: IpAddr) {
        // Full teardown drops every live-session record with the
        // registration — any session event arriving for the address
        // afterwards is classified against an empty state (accept-all
        // for teardowns, fresh registration for PeerUp).
        self.live_sessions.remove(&peer);
        self.clear_policy_filtered_routes_for_peer(peer);
        if self.gr_peers.remove(&peer).is_some() {
            self.gr_stale_deadlines.remove(&peer);
            self.gr_stale_routes_time.remove(&peer);
            self.llgr_peer_config.remove(&peer);
            info!(%peer, "peer down during graceful restart — aborting GR");
            let peer_label = peer.to_string();
            self.metrics.set_gr_active(&peer_label, false);
            self.metrics.set_gr_stale_routes(&peer_label, 0);
        }

        if self.llgr_peers.remove(&peer).is_some() {
            self.llgr_stale_deadlines.remove(&peer);
            // The LLGR config survives GR→LLGR promotion (handle_peer_up
            // reads it on re-establishment), so an LLGR abort must drop it
            // here — the GR arm above won't fire for a peer already
            // promoted out of gr_peers.
            self.llgr_peer_config.remove(&peer);
            info!(%peer, "peer down during LLGR — aborting LLGR");
            let peer_label = peer.to_string();
            self.metrics.set_gr_active(&peer_label, false);
            self.metrics.set_gr_stale_routes(&peer_label, 0);
        }

        self.clear_peer_adj_rib_in(peer);

        self.metrics
            .set_adj_rib_out_prefixes(&peer.to_string(), "all", 0);
        self.metrics
            .set_adj_rib_out_prefixes(&peer.to_string(), "evpn", 0);
        self.clear_outbound_peer_state(peer);
        self.peer_asn.remove(&peer);
        self.peer_group.remove(&peer);
        self.peer_bgp_id.remove(&peer);
        self.force_outbound_peers.remove(&peer);
        self.clear_peer_refresh_metrics(peer);
    }

    /// Remove every Adj-RIB-In route learned from `peer` and redistribute
    /// the result. Shared by the `PeerDown` teardown and the
    /// replacement-`PeerUp` session reset (a new session for an address
    /// whose previous session was never torn down must not inherit its
    /// predecessor's received routes).
    fn clear_peer_adj_rib_in(&mut self, peer: IpAddr) {
        let Some(rib) = self.ribs.remove(&peer) else {
            return;
        };
        let affected: HashSet<Prefix> = rib.iter().map(|r| r.prefix).collect();
        let count = rib.len();
        let fs_affected: HashSet<FlowSpecRule> =
            rib.iter_flowspec().map(|r| r.rule.clone()).collect();
        let evpn_affected: HashSet<EvpnRouteKey> = rib
            .iter_evpn()
            .map(crate::route::EvpnRibRoute::key)
            .collect();
        let bgpls_affected: HashSet<crate::route::BgpLsRouteKey> = rib
            .iter_bgpls()
            .map(crate::route::BgpLsRibRoute::key)
            .collect();
        let vpn_affected: HashSet<crate::route::VpnRibRouteKey> =
            rib.iter_vpn().map(crate::route::VpnRibRoute::key).collect();
        let labeled_affected: HashSet<crate::route::LabeledRibRouteKey> = rib
            .iter_labeled()
            .map(crate::route::LabeledRibRoute::key)
            .collect();
        let rtc_affected: HashSet<crate::route::RtcRibRouteKey> =
            rib.iter_rtc().map(crate::route::RtcRibRoute::key).collect();
        debug!(%peer, cleared = count, "peer adj-rib-in cleared");
        self.metrics.set_rib_prefixes(&peer.to_string(), "all", 0);
        self.metrics.set_rib_prefixes(&peer.to_string(), "evpn", 0);
        let changed = self.recompute_best(&affected);
        self.distribute_changes(&changed, &affected);
        if !fs_affected.is_empty() {
            self.recompute_and_distribute_flowspec(&fs_affected);
        }
        if !evpn_affected.is_empty() {
            self.recompute_and_distribute_evpn(&evpn_affected);
        }
        // A departed peer's BGP-LS routes must fall back to the next-best
        // remaining candidate or be removed from the Loc-RIB (and withdrawn
        // downstream by the distribution step). Without this the entries
        // would strand in `loc_rib.bgpls_routes` until process restart and
        // surface through `ListBgpLsRoutes` as if still live.
        if !bgpls_affected.is_empty() {
            self.recompute_bgpls_keys(&bgpls_affected);
        }
        // Same fallback/withdraw obligation for the departed peer's
        // VPNv4/VPNv6 routes — same stranding hazard as BGP-LS above.
        if !vpn_affected.is_empty() {
            self.recompute_vpn_keys(&vpn_affected);
        }
        // Same fallback/withdraw obligation for the departed peer's
        // labeled-unicast routes.
        if !labeled_affected.is_empty() {
            self.recompute_labeled_keys(&labeled_affected);
        }
        // And for the departed peer's RT-Constrain routes.
        if !rtc_affected.is_empty() {
            self.recompute_rtc_keys(&rtc_affected);
        }
    }

    /// Handle a peer *deletion* (the neighbor was removed from the
    /// configuration — not a session flap, which keeps its series).
    ///
    /// The delete path queues this after the session's own `PeerDown`,
    /// so the per-peer teardown above (zeroed gauges, cleared maps) has
    /// already run when this arrives; re-running it here is a cheap
    /// no-op safety net for a peer that was deleted while never
    /// established. Afterwards, remove the deleted peer's metric label
    /// sets entirely — gauges frozen at their last value would
    /// otherwise keep advertising a peer that no longer exists.
    ///
    /// Deletion is a config decision, not a session event, so it runs the
    /// teardown unconditionally — the session-identity gate in
    /// `handle_peer_down` does not apply.
    pub(super) fn handle_peer_deleted(&mut self, peer: IpAddr) {
        self.peer_down_teardown(peer);
        self.metrics.reap_peer_series(&peer.to_string());
    }

    /// Clear the per-session outbound state shared by the `PeerDown` and
    /// graceful-restart teardown paths. Keeping ONE list prevents the two
    /// cleanup sites from drifting — the GR path historically missed maps
    /// added later (the ORF filter/gate leak). Peer-identity maps
    /// (`peer_asn`/`peer_group`/`peer_bgp_id`) stay out: GR keeps them for
    /// the returning peer; `PeerDown` removes them at its call site.
    pub(super) fn clear_outbound_peer_state(&mut self, peer: IpAddr) {
        let was_registered = self.outbound_peers.remove(&peer).is_some();
        self.outbound_session_ids.remove(&peer);
        // INFO, not debug: an outbound deregistration is the event that
        // historically wedged a still-Established session's advertisement
        // path (stale collision-loser `PeerDown` after the winner's
        // `PeerUp` — now discarded upstream by the session-identity gate
        // in `handle_peer_down`), so it stays visible at default log
        // level for attribution.
        info!(%peer, was_registered, "peer outbound registration cleared");
        self.metrics.set_rib_outbound_registered_peers(
            i64::try_from(self.outbound_peers.len()).unwrap_or(i64::MAX),
        );
        self.adj_ribs_out.remove(&peer);
        self.peer_export_policies.remove(&peer);
        self.peer_sendable_families.remove(&peer);
        self.peer_advertised_llgr_families.remove(&peer);
        self.peer_is_ebgp.remove(&peer);
        self.peer_is_rr_client.remove(&peer);
        // The ORR vantage binding is per-registration: dropping the last
        // peer bound to a vantage must also drop the vantage's cached
        // SPF (and re-arm the empty-state early-out). Consuming the
        // changed set is a defensive no-op here — removing a binding
        // never alters a surviving vantage's SPF surface (the topology
        // input is untouched; any topology change already ran through
        // the `recompute_bgpls_keys` seam) — but if it ever fires, the
        // affected peers still get their resync.
        if self.peer_orr_vantage.remove(&peer).is_some() {
            let changed = self.recompute_orr();
            self.resync_orr_bound_peers(&changed);
        }
        self.peer_add_path_send_max.remove(&peer);
        self.peer_add_path_send_families.remove(&peer);
        // ORF state is per-session (RFC 5291): a surviving §6 gate can never
        // be lifted by a reconnecting session that didn't negotiate ORF
        // (suppressing the family's flood indefinitely), and a surviving
        // filter keeps constraining churn the new session never asked to
        // filter. `handle_peer_up` re-arms the gate from the new session's
        // `negotiated_orf_recv`.
        self.peer_orf_filters.remove(&peer);
        self.peer_orf_pending.remove(&peer);
        // RT-Constrain membership is per-session too (RFC 4684 filters
        // derive from the session's Adj-RIB-In): `handle_peer_up` re-creates
        // it when the new session negotiates the family — empty-strict
        // normally, or re-derived from the GR-preserved (stale) RTC routes
        // on a graceful-restart re-establish.
        self.peer_rt_membership.remove(&peer);
        // The GR-deferred EoR is per-session too: the deferral pairs with
        // THIS session's §6 gate; a new session re-derives it on `PeerUp`.
        self.gr_deferred_eor.remove(&peer);
        self.dirty_peers.remove(&peer);
        self.pending_eor.remove(&peer);
        self.pending_route_batches.retain(|prb| prb.peer() != peer);
        // Drop per-peer export-policy counters alongside the rest of the
        // per-peer state. Without this the HashMap grows unbounded as
        // peers come and go (especially under dynamic neighbors), and
        // stale aggregates leak across peer-identity reuse. The reset
        // also gives operators consistent semantics: the import-side
        // counters reset on session-down (they live on PeerSessionState),
        // and the export-side aggregates do too — same per-session
        // contract in both directions. Operators that need across-flap
        // totals can subtract Prometheus snapshots
        // (`bgp_policy_routes_total` is monotonic per process).
        self.export_policy_stats.remove(&peer);
        self.clear_peer_refresh_state(peer);
    }

    #[expect(
        clippy::too_many_arguments,
        reason = "PeerUp mirrors the transport session registration payload"
    )]
    pub(super) fn handle_peer_up(
        &mut self,
        peer: IpAddr,
        session_id: u64,
        peer_asn: u32,
        peer_router_id: Ipv4Addr,
        outbound_tx: mpsc::Sender<OutboundRouteUpdate>,
        export_policy: Option<PolicyChain>,
        sendable_families: Vec<(rustbgpd_wire::Afi, rustbgpd_wire::Safi)>,
        is_ebgp: bool,
        route_reflector_client: bool,
        orr_vantage: Option<IpAddr>,
        add_path_send_families: Vec<(rustbgpd_wire::Afi, rustbgpd_wire::Safi)>,
        add_path_send_max: u32,
        negotiated_orf_recv: Vec<(rustbgpd_wire::Afi, rustbgpd_wire::Safi)>,
        negotiated_llgr_families: Vec<(rustbgpd_wire::Afi, rustbgpd_wire::Safi)>,
    ) {
        // Two live sessions for one peer address can overlap during the
        // RFC 4271 §6.8 collision window. A `PeerUp` that finds a
        // still-registered sender is a NEW session taking over from a
        // session that was never torn down here: treat it as a session
        // reset — clear the predecessor's Adj-RIB-In/Out and outbound
        // state before re-registering so nothing from the superseded
        // session lingers. The superseded session stays in
        // `live_sessions`: it may well still be Established (which of the
        // two collision sessions survives is decided by BGP-ID
        // comparison, not event order), so its record is kept for a
        // possible registration failover; its own `PeerDown`, whenever it
        // lands, prunes it (and is otherwise discarded as stale). GR/LLGR
        // retention is the exception to the reset: routes deliberately
        // held stale for a restarting peer stay put — deadline-bounded
        // and swept on End-of-RIB, exactly as on a plain GR reconnect.
        if self.outbound_peers.contains_key(&peer) {
            warn!(
                %peer,
                session_id,
                "peer up replaced a still-registered outbound sender — concurrent \
                 sessions for this peer (collision window); resetting the prior \
                 session's state and keeping it live for failover; its PeerDown \
                 will be matched by session id"
            );
            self.metrics
                .record_rib_outbound_registration_replaced(&peer.to_string());
            if !self.gr_peers.contains_key(&peer) && !self.llgr_peers.contains_key(&peer) {
                self.clear_policy_filtered_routes_for_peer(peer);
                self.clear_peer_adj_rib_in(peer);
            }
            self.clear_outbound_peer_state(peer);
        }

        let record = LiveSessionRecord {
            session_id,
            outbound_tx,
            peer_asn,
            peer_router_id,
            export_policy,
            sendable_families,
            is_ebgp,
            route_reflector_client,
            orr_vantage,
            add_path_send_families,
            add_path_send_max,
            negotiated_orf_recv,
            negotiated_llgr_families,
        };
        let sessions = self.live_sessions.entry(peer).or_default();
        // Same id = the same session re-announcing itself (legacy id-0
        // emitters collapse every session to one id): replace in place so
        // the map never holds two records for one session.
        sessions.retain(|s| s.session_id != session_id);
        sessions.push(record);
        if sessions.len() > MAX_LIVE_SESSIONS_PER_PEER {
            let dropped = sessions.remove(0);
            warn!(
                %peer,
                dropped_session_id = dropped.session_id,
                "live-session bound exceeded — dropping the oldest record; its \
                 eventual PeerDown will be discarded as stale"
            );
        }

        self.register_active_session(peer);
    }

    /// Register the most recent live session (the last `live_sessions`
    /// entry) as the peer's active outbound registration and send it the
    /// initial table dump. Shared by `handle_peer_up` and the
    /// registration failover; the caller has already cleared any prior
    /// registration's state.
    fn register_active_session(&mut self, peer: IpAddr) {
        let Some(record) = self
            .live_sessions
            .get(&peer)
            .and_then(|sessions| sessions.last())
        else {
            debug_assert!(false, "register_active_session with no live session");
            return;
        };
        let session_id = record.session_id;
        let peer_asn = record.peer_asn;
        let peer_router_id = record.peer_router_id;
        let outbound_tx = record.outbound_tx.clone();
        let export_policy = record.export_policy.clone();
        let sendable_families = record.sendable_families.clone();
        let is_ebgp = record.is_ebgp;
        let route_reflector_client = record.route_reflector_client;
        let orr_vantage = record.orr_vantage;
        let add_path_send_families = record.add_path_send_families.clone();
        let add_path_send_max = record.add_path_send_max;
        let negotiated_orf_recv = record.negotiated_orf_recv.clone();
        let negotiated_llgr_families = record.negotiated_llgr_families.clone();

        self.peer_asn.insert(peer, peer_asn);
        self.peer_bgp_id.insert(peer, peer_router_id);

        // RFC 5291 §6: gate the initial advertisement for ORF-receive families
        // until the peer sends a ROUTE-REFRESH, so we don't flood the full
        // table before its filter arrives. The gate is lifted in
        // `handle_route_refresh_request` / `handle_peer_orf_update`.
        if !negotiated_orf_recv.is_empty() {
            self.peer_orf_pending
                .insert(peer, negotiated_orf_recv.into_iter().collect());
        }

        if self.gr_peers.contains_key(&peer) {
            if let Some(&srt) = self.gr_stale_routes_time.get(&peer) {
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(srt);
                self.gr_stale_deadlines.insert(peer, deadline);
            }
            info!(%peer, "peer re-established during GR — waiting for End-of-RIB");
        } else if self.llgr_peers.contains_key(&peer)
            && let Some(llgr_families) = self.llgr_peers.remove(&peer)
        {
            self.llgr_stale_deadlines.remove(&peer);
            let srt = self
                .llgr_peer_config
                .get(&peer)
                .map_or(360, |c| c.stale_routes_time);
            self.gr_stale_routes_time.insert(peer, srt);
            self.gr_peers.insert(peer, llgr_families);
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(srt);
            self.gr_stale_deadlines.insert(peer, deadline);
            info!(%peer, stale_routes_time = srt, "peer re-established during LLGR — waiting for End-of-RIB");
        }

        // RFC 4684 decision: lazily self-originate the default (wildcard)
        // RTC NLRI the first time an RTC-capable peer comes up — rustbgpd
        // has no VRFs, so its own RT interest is "everything"; without
        // advertising that, RTC-filtering peers (e.g. GoBGP PEs) would
        // suppress their VPN routes toward us. Runs BEFORE the outbound
        // registration below so the recompute doesn't race the initial
        // dump: this peer receives the default exactly once, in
        // `send_initial_table`.
        if sendable_families.contains(&crate::route::RtcRibRouteKey::afi_safi()) {
            self.ensure_default_rtc_originated();
            // RFC 4684 strict rule: a peer that negotiated SAFI 132 starts
            // with an EMPTY membership — no VPN routes are advertised
            // (initial dump included) until its RT interest arrives.
            //
            // A GR/LLGR re-establish is the exception: the previous
            // session's RTC routes were preserved as stale in the
            // Adj-RIB-In (RFC 4724 helper retention), so the returning
            // peer's membership is re-derived from them — VPN routes flow
            // in the initial dump immediately instead of stalling until
            // the peer re-advertises its interest. Interest the peer does
            // NOT re-advertise is swept at End-of-RIB (or timer expiry),
            // which shrinks the membership and withdraws the uncovered
            // VPN routes.
            let membership = if self.gr_peers.contains_key(&peer) {
                self.rtc_membership_from_rib(peer)
            } else {
                super::RtcMembership::default()
            };
            self.peer_rt_membership.insert(peer, membership);
        } else {
            // A replacement session that dropped the family must not
            // inherit its predecessor's filter (not-negotiated ⇒ unfiltered).
            self.peer_rt_membership.remove(&peer);
        }

        debug!(%peer, "peer up — registering for outbound updates");
        let peer_label = peer.to_string();
        self.metrics.set_rib_prefixes(&peer_label, "all", 0);
        self.metrics.set_adj_rib_out_prefixes(&peer_label, "all", 0);
        self.outbound_peers.insert(peer, outbound_tx);
        self.outbound_session_ids.insert(peer, session_id);
        self.metrics.set_rib_outbound_registered_peers(
            i64::try_from(self.outbound_peers.len()).unwrap_or(i64::MAX),
        );
        self.peer_export_policies
            .insert(peer, export_policy.or_else(|| self.export_policy.clone()));
        self.peer_sendable_families.insert(peer, sendable_families);
        self.peer_advertised_llgr_families
            .insert(peer, negotiated_llgr_families);
        self.peer_is_ebgp.insert(peer, is_ebgp);
        self.peer_is_rr_client.insert(peer, route_reflector_client);
        if let Some(vantage) = orr_vantage {
            self.peer_orr_vantage.insert(peer, vantage);
            // The vantage may register after the BGP-LS routes arrived
            // (no mutation seam would fire), so seed its SPF here. The
            // changed set is deliberately NOT consumed: it can only name
            // this vantage when this peer is the first to bind it (other
            // vantages see an unchanged topology), and this peer's
            // per-vantage best flows through `send_initial_table` below —
            // a resync here would double-send the table.
            self.recompute_orr();
        }
        self.peer_add_path_send_families
            .insert(peer, add_path_send_families);
        self.peer_add_path_send_max.insert(peer, add_path_send_max);
        self.send_initial_table(peer);
    }

    /// Insert the local default RT-Constrain NLRI into the `LOCAL_PEER`
    /// Adj-RIB-In (lazy + idempotent) and run the RTC recompute so it flows
    /// to any already-established RTC peers. Never withdrawn — harmless if
    /// no RTC peer remains. No config knob by design.
    fn ensure_default_rtc_originated(&mut self) {
        use rustbgpd_wire::{AsPath, Origin, PathAttribute, RtcNlri};

        use super::helpers::LOCAL_PEER;
        use crate::adj_rib_in::AdjRibIn;
        use crate::route::{RouteOrigin, RtcRibRoute, RtcRibRouteKey};

        let key = RtcRibRouteKey {
            nlri: RtcNlri::DEFAULT,
            path_id: 0,
        };
        if self
            .ribs
            .get(&LOCAL_PEER)
            .is_some_and(|rib| rib.get_rtc(&key).is_some())
        {
            return;
        }
        let route = RtcRibRoute {
            nlri: RtcNlri::DEFAULT,
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer: LOCAL_PEER,
            // AS_PATH is well-known mandatory even when empty (local
            // origination over iBGP): RFC 7606 peers treat-as-withdraw an
            // UPDATE without it, which starves the RR of VPN routes (M75
            // finding). Matches every other local originator.
            attributes: std::sync::Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath { segments: vec![] }),
            ]),
            received_at: std::time::Instant::now(),
            origin_type: RouteOrigin::Local,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        };
        self.ribs
            .entry(LOCAL_PEER)
            .or_insert_with(|| AdjRibIn::new(LOCAL_PEER))
            .insert_rtc(route);
        info!("originated default RT-Constrain NLRI (local wildcard RT interest, RFC 4684)");
        let mut affected = HashSet::new();
        affected.insert(key);
        self.recompute_rtc_keys(&affected);
    }

    pub(super) fn handle_set_peer_policy_context(
        &mut self,
        peer: IpAddr,
        peer_group: Option<String>,
    ) {
        if let Some(peer_group) = peer_group {
            self.peer_group.insert(peer, peer_group);
        } else {
            self.peer_group.remove(&peer);
        }
    }

    /// Send the full Loc-RIB to a newly established peer (initial table dump).
    ///
    /// `AdjRibOut` is only populated after a successful channel send. On
    /// failure the peer is marked dirty so `distribute_changes()` will
    /// retry a full resync via the resync timer.
    #[expect(
        clippy::too_many_lines,
        reason = "initial dump stages every family queue before one Adj-RIB-Out commit"
    )]
    pub(super) fn send_initial_table(&mut self, peer: IpAddr) {
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
        let mut current_policy_filtered_routes: HashSet<PolicyFilteredRouteKey> = HashSet::new();
        let export_pol = self
            .export_policy_for(peer)
            .map(rustbgpd_policy::PolicyChain::share);
        let sendable = self.peer_sendable_families.get(&peer).cloned();
        let llgr = self.peer_advertised_llgr_families.get(&peer).cloned();
        let rtc_filter = self.rtc_vpn_filter(peer, sendable.as_ref());
        // RFC 5291 §6 initial-advertisement gate: suppress route advertisement
        // for families still awaiting the peer's first ROUTE-REFRESH. For a
        // non-GR peer the EoR is still emitted (an honest "empty table so
        // far"); for a GR restarter the EoR is deferred until the gated flood
        // is sent (see the `eor_families` carve-out below). The filtered flood
        // follows once the gate is lifted.
        let orf_gated = self
            .peer_orf_pending
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
        let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
        let target_peer_asn = self.peer_asn.get(&peer).copied();
        let target_peer_group = self.peer_group.get(&peer).map(String::as_str);
        let cluster_id = self.cluster_id;
        let peer_add_path_send_max = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
        let peer_add_path_send_families = self
            .peer_add_path_send_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        // RFC 9107 ORR: a late-joining peer bound to a resolved vantage
        // gets the per-vantage best in its initial dump (the SPF was
        // seeded at PeerUp); an unresolved vantage falls back to the
        // standard single-best.
        let orr_ctx = self
            .peer_orr_vantage
            .get(&peer)
            .and_then(|vantage| self.orr.spf.get(vantage))
            .map(|spf| (&self.orr.topology, spf));
        let loc_rib = &self.loc_rib;
        let target_peer_label = peer.to_string();
        let metrics = self.metrics.clone();
        let policy_stats = self.export_policy_stats.entry(peer).or_default();

        let mut all_prefixes: HashSet<Prefix> = self.loc_rib.iter().map(|r| r.prefix).collect();
        for rib in self.ribs.values() {
            all_prefixes.extend(rib.iter().map(|r| r.prefix));
        }

        // Stage against an empty outbound view so initial dump always
        // re-sends the full current table for this peer.
        let initial_view = AdjRibOut::new(peer);

        // Pass-scoped export memo: routes sharing an inbound attribute
        // set share the post-modification attributes across this dump.
        let mut export_memo = super::distribution::ExportMemo::default();

        for prefix in &all_prefixes {
            if orf_gated.contains(&prefix_family(prefix)) {
                continue;
            }
            let prefix_send_max = if peer_add_path_send_max > 0
                && peer_add_path_send_families.contains(&prefix_family(prefix))
            {
                peer_add_path_send_max
            } else {
                0
            };
            if prefix_send_max > 0 {
                let mut policy_filtered = Vec::new();
                Self::distribute_multipath_prefix(
                    &self.ribs,
                    &initial_view,
                    &self.peer_is_rr_client,
                    prefix,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    prefix_send_max,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    export_pol.as_ref(),
                    // ORF: gated families are skipped above; a non-gated family
                    // has no installed filter during the initial dump.
                    None,
                    orr_ctx,
                    &mut export_memo,
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut announce,
                    &mut withdraw,
                    &mut nh_override_flags,
                    &mut policy_filtered,
                    false, // initial dump — equality check is correct
                );
                current_policy_filtered_routes.extend(policy_filtered);
            } else if let Some((orr_topology, orr_spf)) = orr_ctx {
                // ORR peer with a resolved vantage: per-vantage best.
                let mut policy_filtered = Vec::new();
                Self::distribute_orr_best_prefix(
                    &self.ribs,
                    &initial_view,
                    &self.peer_is_rr_client,
                    orr_topology,
                    orr_spf,
                    prefix,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    export_pol.as_ref(),
                    // ORF: gated families are skipped above; a non-gated family
                    // has no installed filter during the initial dump.
                    None,
                    &mut export_memo,
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut announce,
                    &mut withdraw,
                    &mut nh_override_flags,
                    &mut policy_filtered,
                    false, // initial dump — equality check is correct
                );
                current_policy_filtered_routes.extend(policy_filtered);
            } else {
                let mut policy_filtered = Vec::new();
                Self::distribute_single_best_prefix(
                    loc_rib,
                    &initial_view,
                    &self.peer_is_rr_client,
                    prefix,
                    peer,
                    target_peer_asn,
                    target_peer_group,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    llgr.as_ref(),
                    export_pol.as_ref(),
                    // ORF: gated families are skipped above; a non-gated family
                    // has no installed filter during the initial dump.
                    None,
                    &mut export_memo,
                    &metrics,
                    policy_stats,
                    &target_peer_label,
                    &mut announce,
                    &mut withdraw,
                    &mut nh_override_flags,
                    &mut policy_filtered,
                    false, // initial dump — equality check is correct
                );
                current_policy_filtered_routes.extend(policy_filtered);
            }
        }

        let all_flowspec_rules: HashSet<FlowSpecRule> = self
            .loc_rib
            .iter_flowspec()
            .map(|route| route.rule.clone())
            .collect();
        if !all_flowspec_rules.is_empty() {
            Self::stage_flowspec_rules(
                loc_rib,
                &initial_view,
                &self.peer_is_rr_client,
                &all_flowspec_rules,
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

        // EVPN initial dump — without this, peers that join after the
        // fabric has converged see an EoR with zero EVPN routes and
        // operate with no EVPN reachability until unrelated RIB churn
        // forces redistribution. Mirrors the FlowSpec staging block.
        let all_evpn_keys: HashSet<rustbgpd_wire::EvpnRouteKey> = self
            .loc_rib
            .iter_evpn()
            .map(crate::route::EvpnRibRoute::key)
            .collect();
        if !all_evpn_keys.is_empty() {
            Self::stage_evpn_routes(
                loc_rib,
                &initial_view,
                &self.peer_is_rr_client,
                &all_evpn_keys,
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
                false, // initial dump — equality check is correct
            );
        }

        let all_bgpls_keys: HashSet<crate::route::BgpLsRouteKey> = self
            .loc_rib
            .iter_bgpls()
            .map(crate::route::BgpLsRibRoute::key)
            .collect();
        if !all_bgpls_keys.is_empty() {
            Self::stage_bgpls_routes(
                loc_rib,
                &initial_view,
                &self.peer_is_rr_client,
                &all_bgpls_keys,
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
                &mut bgpls_announce,
                &mut bgpls_withdraw,
                false, // initial dump — equality check is correct
            );
        }

        // VPNv4/VPNv6 initial dump — a peer that joins after the VPN table
        // has converged must still receive it before EoR. Mirrors the BGP-LS
        // staging block. For an Add-Path-send peer the staged top-N draws
        // from every Adj-RIB-In identity, not just the Loc-RIB bests.
        let mut all_l3vpn_keys: HashSet<rustbgpd_wire::VpnRouteKey> = self
            .loc_rib
            .iter_vpn()
            .map(|route| route.nlri.key())
            .collect();
        if peer_add_path_send_max > 0
            && peer_add_path_send_families
                .iter()
                .any(|(_, safi)| *safi == Safi::MplsVpn)
        {
            for rib in self.ribs.values() {
                all_l3vpn_keys.extend(rib.iter_vpn().map(|route| route.nlri.key()));
            }
        }
        if !all_l3vpn_keys.is_empty() {
            Self::stage_vpn_routes(
                loc_rib,
                &self.ribs,
                &initial_view,
                &self.peer_is_rr_client,
                &all_l3vpn_keys,
                peer,
                target_peer_asn,
                target_peer_group,
                target_is_ebgp,
                target_is_rr_client,
                cluster_id,
                sendable.as_ref(),
                llgr.as_ref(),
                rtc_filter.as_ref(),
                orr_ctx,
                peer_add_path_send_max,
                &peer_add_path_send_families,
                export_pol.as_ref(),
                &metrics,
                policy_stats,
                &target_peer_label,
                &mut vpn_announce,
                &mut vpn_withdraw,
                false, // initial dump — equality check is correct
            );
        }

        // Labeled-unicast initial dump — a peer that joins after the labeled
        // table has converged must still receive it before EoR. Mirrors the
        // VPN staging block. For an Add-Path-send peer the staged top-N
        // draws from every Adj-RIB-In identity, not just the Loc-RIB bests.
        let mut all_labeled_keys: HashSet<rustbgpd_wire::Prefix> = self
            .loc_rib
            .iter_labeled()
            .map(|route| route.nlri.key())
            .collect();
        if peer_add_path_send_max > 0
            && peer_add_path_send_families
                .iter()
                .any(|(_, safi)| *safi == Safi::LabeledUnicast)
        {
            for rib in self.ribs.values() {
                all_labeled_keys.extend(rib.iter_labeled().map(|route| route.nlri.key()));
            }
        }
        if !all_labeled_keys.is_empty() {
            Self::stage_labeled_routes(
                loc_rib,
                &self.ribs,
                &initial_view,
                &self.peer_is_rr_client,
                &all_labeled_keys,
                peer,
                target_peer_asn,
                target_peer_group,
                target_is_ebgp,
                target_is_rr_client,
                cluster_id,
                sendable.as_ref(),
                llgr.as_ref(),
                orr_ctx,
                peer_add_path_send_max,
                &peer_add_path_send_families,
                export_pol.as_ref(),
                &metrics,
                policy_stats,
                &target_peer_label,
                &mut labeled_announce,
                &mut labeled_withdraw,
                false, // initial dump — equality check is correct
            );
        }

        // RT-Constrain initial dump — a peer that joins after RTC state has
        // converged (incl. the locally-originated default) must receive it
        // before EoR. Mirrors the VPN staging block.
        let all_rtc_keys: HashSet<crate::route::RtcRibRouteKey> = self
            .loc_rib
            .iter_rtc()
            .map(crate::route::RtcRibRoute::key)
            .collect();
        if !all_rtc_keys.is_empty() {
            Self::stage_rtc_routes(
                loc_rib,
                &initial_view,
                &self.peer_is_rr_client,
                &all_rtc_keys,
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
                &mut rtc_announce,
                &mut rtc_withdraw,
                false, // initial dump — equality check is correct
            );
        }

        // Determine EoR families from this peer's sendable families
        let mut eor_families = self
            .peer_sendable_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        // RFC 4724: a GR RESTARTER takes our EoR as "this peer's initial
        // update is complete", proceeds with route selection, and sweeps the
        // stale routes it retained from our previous session. For an
        // ORF-gated family that EoR would arrive BEFORE the gated flood
        // (which waits on the peer's first ROUTE-REFRESH, RFC 5291 §6) —
        // sweeping everything we are about to re-announce, a self-inflicted
        // blackhole window. Withhold those families' EoR; it is emitted once
        // the gate lifts and the gated flood is sent
        // (`send_route_refresh_response` / `handle_peer_orf_update`). Non-GR
        // ORF peers keep the immediate EoR — a client that never sends
        // ROUTE-REFRESH must still see EoR. This runs after `handle_peer_up`'s
        // LLGR arm has moved a peer re-establishing during LLGR back into
        // `gr_peers`, so that restarter is covered too.
        if !orf_gated.is_empty() && self.gr_peers.contains_key(&peer) {
            let deferred: HashSet<(rustbgpd_wire::Afi, rustbgpd_wire::Safi)> = eor_families
                .iter()
                .copied()
                .filter(|family| orf_gated.contains(family))
                .collect();
            if !deferred.is_empty() {
                eor_families.retain(|family| !deferred.contains(family));
                self.gr_deferred_eor.insert(peer, deferred);
            }
        }

        let has_outbound_diff = !announce.is_empty()
            || !withdraw.is_empty()
            || !fs_announce.is_empty()
            || !fs_withdraw.is_empty()
            || !evpn_announce.is_empty()
            || !evpn_withdraw.is_empty()
            || !bgpls_announce.is_empty()
            || !bgpls_withdraw.is_empty()
            || !vpn_announce.is_empty()
            || !vpn_withdraw.is_empty()
            || !labeled_announce.is_empty()
            || !labeled_withdraw.is_empty()
            || !rtc_announce.is_empty()
            || !rtc_withdraw.is_empty();
        let sent = !has_outbound_diff
            || self.try_send_and_commit_outbound_update(
                peer,
                nh_override_flags,
                announce,
                withdraw,
                vec![],
                vec![],
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
            );
        if !sent {
            warn!(%peer, "outbound channel full or closed during initial dump — marking dirty");
            self.metrics.record_outbound_route_drop(&peer.to_string());
            for f in &eor_families {
                self.pending_eor.entry(peer).or_default().insert(*f);
            }
            self.dirty_peers.insert(peer);
            return;
        }
        self.update_policy_filtered_routes_for_prefixes(
            peer,
            &all_prefixes,
            &current_policy_filtered_routes,
        );

        // Send End-of-RIB markers for all sendable families
        if !eor_families.is_empty()
            && let Some(tx) = self.outbound_peers.get(&peer)
        {
            let eor = OutboundRouteUpdate {
                next_hop_override: vec![],
                announce: vec![],
                withdraw: vec![],
                end_of_rib: eor_families.clone(),
                refresh_markers: vec![],
                flowspec_announce: vec![],
                flowspec_withdraw: vec![],
                evpn_announce: vec![],
                evpn_withdraw: vec![],
                bgpls_announce: vec![],
                bgpls_withdraw: vec![],
                vpn_announce: vec![],
                labeled_announce: vec![],
                rtc_announce: vec![],
                vpn_withdraw: vec![],
                labeled_withdraw: vec![],
                rtc_withdraw: vec![],
                request_refresh_all_negotiated: false,
            };
            if tx.try_send(eor).is_err() {
                warn!(%peer, "outbound channel full — `EoR` deferred");
                for f in &eor_families {
                    self.pending_eor.entry(peer).or_default().insert(*f);
                }
                self.dirty_peers.insert(peer);
            }
        }
    }
}
