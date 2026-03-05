use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use rustbgpd_policy::{PolicyAction, PolicyChain, evaluate_chain};
use rustbgpd_rpki::VrpTable;
use rustbgpd_telemetry::BgpMetrics;
use rustbgpd_wire::{
    Afi, FlowSpecRule, LlgrFamily, Prefix, RouteRefreshSubtype, RpkiValidation, Safi,
};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};

use crate::event::{RouteEvent, RouteEventType};

use crate::adj_rib_in::AdjRibIn;
use crate::adj_rib_out::AdjRibOut;
use crate::loc_rib::LocRib;
use crate::update::{OutboundRouteUpdate, RibUpdate};

/// Sentinel peer address for locally-injected routes.
const LOCAL_PEER: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);

/// How long to wait before retrying distribution to dirty peers.
const DIRTY_RESYNC_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// How long to wait for an inbound enhanced route refresh window to complete
/// before sweeping unreplaced state.
const ERR_REFRESH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300);

/// Per-peer LLGR configuration stored when `PeerGracefulRestart` is received.
struct LlgrPeerConfig {
    peer_llgr_capable: bool,
    peer_llgr_families: Vec<LlgrFamily>,
    local_llgr_stale_time: u32,
}

/// Safe cast from usize to i64 for gauge metrics.
#[expect(clippy::cast_possible_wrap)]
fn gauge_val(n: usize) -> i64 {
    n as i64
}

/// Central RIB manager that owns all Adj-RIB-In, Loc-RIB, and Adj-RIB-Out state.
///
/// Runs as a single tokio task, receiving updates via an mpsc channel.
/// No `Arc<RwLock>` — all state is owned by this task.
pub struct RibManager {
    ribs: HashMap<IpAddr, AdjRibIn>,
    loc_rib: LocRib,
    adj_ribs_out: HashMap<IpAddr, AdjRibOut>,
    outbound_peers: HashMap<IpAddr, mpsc::Sender<OutboundRouteUpdate>>,
    export_policy: Option<PolicyChain>,
    peer_export_policies: HashMap<IpAddr, Option<PolicyChain>>,
    /// Families the transport can actually serialize per peer.
    peer_sendable_families: HashMap<IpAddr, Vec<(Afi, Safi)>>,
    /// Whether each registered outbound peer is eBGP (true) or iBGP (false).
    peer_is_ebgp: HashMap<IpAddr, bool>,
    /// Whether each registered outbound peer is a route reflector client.
    peer_is_rr_client: HashMap<IpAddr, bool>,
    /// Local cluster ID for route reflection (RFC 4456). `None` = not an RR.
    cluster_id: Option<Ipv4Addr>,
    /// Peers that failed a `try_send()` and need a full export resync.
    dirty_peers: HashSet<IpAddr>,
    /// `EoR` markers that failed to enqueue and must be retried.
    pending_eor: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Families with an outstanding enhanced route refresh response retry.
    pending_refresh: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Active inbound enhanced route refresh windows by peer/family.
    refresh_in_progress: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Per-peer/per-family deadlines for active enhanced route refresh windows.
    refresh_deadlines: HashMap<(IpAddr, Afi, Safi), tokio::time::Instant>,
    /// Unicast routes still awaiting replacement during an inbound refresh.
    refresh_stale_routes: HashMap<IpAddr, HashSet<(Prefix, u32)>>,
    /// `FlowSpec` routes still awaiting replacement during an inbound refresh.
    refresh_stale_flowspec: HashMap<IpAddr, HashSet<(Afi, FlowSpecRule, u32)>>,
    /// Peers currently undergoing graceful restart, keyed by peer address.
    /// Value is the set of (AFI, SAFI) families still awaiting End-of-RIB.
    gr_peers: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Deadlines for sweeping stale routes per GR peer.
    gr_stale_deadlines: HashMap<IpAddr, tokio::time::Instant>,
    /// Configured stale-routes-time per GR peer (seconds), used to reset
    /// the timer on `PeerUp` during graceful restart.
    gr_stale_routes_time: HashMap<IpAddr, u64>,
    /// Peers currently in LLGR stale phase (RFC 9494), keyed by peer address.
    /// Value is the set of (AFI, SAFI) families in LLGR.
    llgr_peers: HashMap<IpAddr, HashSet<(Afi, Safi)>>,
    /// Deadlines for sweeping LLGR-stale routes per peer.
    llgr_stale_deadlines: HashMap<IpAddr, tokio::time::Instant>,
    /// Configured per-peer LLGR parameters, stored on `PeerGracefulRestart`.
    llgr_peer_config: HashMap<IpAddr, LlgrPeerConfig>,
    /// Maximum Add-Path paths per prefix per peer (0 = single-best only).
    peer_add_path_send_max: HashMap<IpAddr, u32>,
    /// Families for which Add-Path Send/Both was negotiated per peer.
    peer_add_path_send_families: HashMap<IpAddr, Vec<(Afi, Safi)>>,
    /// Current RPKI VRP table for origin validation. `None` = no RPKI data.
    vrp_table: Option<Arc<VrpTable>>,
    route_events_tx: broadcast::Sender<RouteEvent>,
    metrics: BgpMetrics,
    rx: mpsc::Receiver<RibUpdate>,
}

/// Compare two routes for outbound equality (same attributes, next-hop, peer).
/// Used to avoid re-announcing unchanged routes to multi-path peers.
fn routes_equal(a: &crate::route::Route, b: &crate::route::Route) -> bool {
    a.next_hop == b.next_hop && a.peer == b.peer && a.attributes == b.attributes
}

#[must_use]
fn prefix_family(prefix: &Prefix) -> (Afi, Safi) {
    match prefix {
        Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
        Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
    }
}

/// iBGP split-horizon / RFC 4456 reflection logic, extracted as a free
/// function so it can be called when `self.adj_ribs_out` is mutably borrowed.
///
/// RFC 4456 reflection rules (when `cluster_id` is `Some`, i.e. we are an RR):
/// - eBGP-learned or Local routes: never suppress to anyone
/// - iBGP-learned from an RR client: reflect to all (clients + non-clients)
/// - iBGP-learned from a non-client: reflect to clients only
///
/// Standard iBGP split-horizon (no RR): suppress all iBGP-learned routes to iBGP peers.
fn should_suppress_ibgp_inner(
    route: &crate::route::Route,
    target_is_ebgp: bool,
    target_is_rr_client: bool,
    cluster_id: Option<Ipv4Addr>,
    peer_is_rr_client: &HashMap<IpAddr, bool>,
) -> bool {
    // eBGP targets never suppressed
    if target_is_ebgp {
        return false;
    }
    // eBGP-learned and Local routes always pass to iBGP peers
    if route.origin_type != crate::route::RouteOrigin::Ibgp {
        return false;
    }
    // At this point: route is iBGP-learned, target is iBGP
    match cluster_id {
        Some(_) => {
            // RR mode: check if source was a client
            let source_is_client = peer_is_rr_client.get(&route.peer).copied().unwrap_or(false);
            if source_is_client {
                // Client route → reflect to all (clients + non-clients)
                false
            } else {
                // Non-client route → reflect to clients only
                !target_is_rr_client
            }
        }
        None => {
            // Standard iBGP split-horizon: suppress all iBGP-learned
            true
        }
    }
}

/// Validate a route's origin against the VRP table (RFC 6811).
///
/// Extracts the origin ASN from the route's `AS_PATH` (last AS in rightmost
/// `AS_SEQUENCE`). Returns `NotFound` if no `AS_PATH` is present.
fn validate_route_rpki(route: &crate::route::Route, table: &VrpTable) -> RpkiValidation {
    let origin = route.as_path().and_then(rustbgpd_wire::AsPath::origin_asn);
    match origin {
        Some(asn) => table.validate(&route.prefix, asn),
        None => RpkiValidation::NotFound,
    }
}

impl RibManager {
    #[must_use]
    pub fn new(
        rx: mpsc::Receiver<RibUpdate>,
        export_policy: Option<PolicyChain>,
        cluster_id: Option<Ipv4Addr>,
        metrics: BgpMetrics,
    ) -> Self {
        let (route_events_tx, _) = broadcast::channel(4096);
        Self {
            ribs: HashMap::new(),
            loc_rib: LocRib::new(),
            adj_ribs_out: HashMap::new(),
            outbound_peers: HashMap::new(),
            export_policy,
            peer_export_policies: HashMap::new(),
            peer_sendable_families: HashMap::new(),
            peer_is_ebgp: HashMap::new(),
            peer_is_rr_client: HashMap::new(),
            cluster_id,
            dirty_peers: HashSet::new(),
            pending_eor: HashMap::new(),
            pending_refresh: HashMap::new(),
            refresh_in_progress: HashMap::new(),
            refresh_deadlines: HashMap::new(),
            refresh_stale_routes: HashMap::new(),
            refresh_stale_flowspec: HashMap::new(),
            gr_peers: HashMap::new(),
            gr_stale_deadlines: HashMap::new(),
            gr_stale_routes_time: HashMap::new(),
            llgr_peers: HashMap::new(),
            llgr_stale_deadlines: HashMap::new(),
            llgr_peer_config: HashMap::new(),
            peer_add_path_send_max: HashMap::new(),
            peer_add_path_send_families: HashMap::new(),
            vrp_table: None,
            route_events_tx,
            metrics,
            rx,
        }
    }

    #[must_use]
    fn peer_has_any_add_path_send(&self, peer: IpAddr) -> bool {
        self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0) > 0
            && self
                .peer_add_path_send_families
                .get(&peer)
                .is_some_and(|families| !families.is_empty())
    }

    #[must_use]
    fn add_path_send_max_for_prefix(&self, peer: IpAddr, prefix: &Prefix) -> u32 {
        let send_max = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
        if send_max == 0 {
            return 0;
        }
        let family = prefix_family(prefix);
        if self
            .peer_add_path_send_families
            .get(&peer)
            .is_some_and(|families| families.contains(&family))
        {
            send_max
        } else {
            0
        }
    }

    /// Resolve the export policy for a peer: per-peer if set, else global.
    fn export_policy_for(&self, peer: IpAddr) -> Option<&PolicyChain> {
        self.peer_export_policies
            .get(&peer)
            .and_then(|p| p.as_ref())
            .or(self.export_policy.as_ref())
    }

    /// Clear all enhanced route refresh state for a peer.
    fn clear_peer_refresh_state(&mut self, peer: IpAddr) {
        self.pending_refresh.remove(&peer);
        self.refresh_in_progress.remove(&peer);
        self.refresh_stale_routes.remove(&peer);
        self.refresh_stale_flowspec.remove(&peer);
        self.refresh_deadlines
            .retain(|(stale_peer, _, _), _| *stale_peer != peer);
    }

    /// Recompute Loc-RIB best path for a set of affected prefixes.
    /// Returns the set of prefixes that actually changed.
    /// Also emits route events to the broadcast channel.
    fn recompute_best(&mut self, affected: &HashSet<Prefix>) -> HashSet<Prefix> {
        let mut changed = HashSet::new();
        for prefix in affected {
            let previous_best = self.loc_rib.get(prefix).map(|r| (r.peer, r.path_id));
            let candidates: Vec<_> = self
                .ribs
                .values()
                .flat_map(|rib| rib.iter_prefix(prefix))
                .collect();
            let did_change = self.loc_rib.recompute(*prefix, candidates.into_iter());
            if did_change {
                changed.insert(*prefix);
                let current_best = self.loc_rib.get(prefix);
                match (previous_best, current_best) {
                    (None, Some(best)) => {
                        debug!(%prefix, peer = %best.peer, "best path added");
                        let _ = self.route_events_tx.send(RouteEvent {
                            event_type: RouteEventType::Added,
                            prefix: *prefix,
                            peer: Some(best.peer),
                            previous_peer: None,
                            timestamp: crate::event::unix_timestamp_now(),
                            path_id: best.path_id,
                        });
                    }
                    (Some((old_peer, old_path_id)), None) => {
                        debug!(%prefix, "best path removed");
                        let _ = self.route_events_tx.send(RouteEvent {
                            event_type: RouteEventType::Withdrawn,
                            prefix: *prefix,
                            peer: None,
                            previous_peer: Some(old_peer),
                            timestamp: crate::event::unix_timestamp_now(),
                            path_id: old_path_id,
                        });
                    }
                    (Some((old_peer, _old_path_id)), Some(best)) => {
                        debug!(%prefix, peer = %best.peer, "best path changed");
                        let _ = self.route_events_tx.send(RouteEvent {
                            event_type: RouteEventType::BestChanged,
                            prefix: *prefix,
                            peer: Some(best.peer),
                            previous_peer: Some(old_peer),
                            timestamp: crate::event::unix_timestamp_now(),
                            path_id: best.path_id,
                        });
                    }
                    (None, None) => {}
                }
            }
        }
        self.metrics
            .set_loc_rib_prefixes("all", gauge_val(self.loc_rib.len()));
        changed
    }

    /// Multi-path distribution for a single prefix to a single peer.
    ///
    /// Collects all candidates from all Adj-RIB-In entries, filters by
    /// split-horizon/iBGP/family/policy, sorts by best-path, takes top N,
    /// and diffs against `AdjRibOut` to produce announces and withdrawals.
    #[expect(clippy::too_many_arguments)]
    fn distribute_multipath_prefix(
        ribs: &HashMap<IpAddr, AdjRibIn>,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        prefix: &Prefix,
        target_peer: IpAddr,
        send_max: u32,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        announce: &mut Vec<crate::route::Route>,
        withdraw: &mut Vec<(Prefix, u32)>,
        nh_override_flags: &mut Vec<Option<rustbgpd_policy::NextHopAction>>,
    ) {
        use crate::best_path::best_path_cmp;

        // Sendable family check
        let family = match prefix {
            Prefix::V4(_) => (Afi::Ipv4, Safi::Unicast),
            Prefix::V6(_) => (Afi::Ipv6, Safi::Unicast),
        };
        if !sendable.is_some_and(|f| f.contains(&family)) {
            // Withdraw all previously advertised paths for this prefix
            for path_id in rib_out.path_ids_for_prefix(prefix) {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Collect all candidates across all Adj-RIB-In entries
        let mut candidates: Vec<&crate::route::Route> = ribs
            .values()
            .flat_map(|rib| rib.iter_prefix(prefix))
            .filter(|route| {
                // Split horizon: exclude routes from the target peer
                if route.peer == target_peer {
                    return false;
                }
                // iBGP split-horizon / RFC 4456 reflection
                if should_suppress_ibgp_inner(
                    route,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    peer_is_rr_client,
                ) {
                    return false;
                }
                true
            })
            .collect();

        // Sort by best-path preference (best first)
        candidates.sort_by(|a, b| best_path_cmp(a, b));

        // Walk candidates, evaluate export policy, assign path_ids 1..N
        let mut next_rank: u32 = 1;
        let limit = if send_max == u32::MAX {
            usize::MAX
        } else {
            send_max as usize
        };
        for candidate in &candidates {
            if (next_rank as usize) > limit {
                break;
            }

            // Export policy check per-candidate
            let aspath_str = candidate
                .as_path()
                .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string);
            let result = evaluate_chain(
                export_pol,
                *prefix,
                candidate.extended_communities(),
                candidate.communities(),
                candidate.large_communities(),
                &aspath_str,
                candidate.validation_state,
            );
            if result.action != PolicyAction::Permit {
                continue;
            }

            // Apply export modifications
            let mut modified = (*candidate).clone();
            let nh_action = rustbgpd_policy::apply_modifications(
                &mut modified.attributes,
                &result.modifications,
            );
            if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) = &nh_action {
                modified.next_hop = *addr;
            }
            modified.path_id = next_rank;

            // Only announce if different from what's already in AdjRibOut
            let changed = rib_out
                .get(prefix, next_rank)
                .is_none_or(|existing| !routes_equal(existing, &modified));
            if changed {
                nh_override_flags.push(nh_action);
                announce.push(modified);
            }

            next_rank += 1;
        }

        // Withdraw any previously advertised path_ids beyond the new set
        for path_id in rib_out.path_ids_for_prefix(prefix) {
            if path_id >= next_rank {
                withdraw.push((*prefix, path_id));
            }
        }
    }

    #[expect(clippy::too_many_arguments)]
    fn distribute_single_best_prefix(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        prefix: &Prefix,
        target_peer: IpAddr,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        announce: &mut Vec<crate::route::Route>,
        withdraw: &mut Vec<(Prefix, u32)>,
        nh_override_flags: &mut Vec<Option<rustbgpd_policy::NextHopAction>>,
    ) {
        let existing_path_ids = rib_out.path_ids_for_prefix(prefix);

        let Some(best) = loc_rib.get(prefix) else {
            for path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        };

        // Split horizon: don't send route back to its source
        if best.peer == target_peer {
            for path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // iBGP split-horizon / RFC 4456 reflection rules
        if should_suppress_ibgp_inner(
            best,
            target_is_ebgp,
            target_is_rr_client,
            cluster_id,
            peer_is_rr_client,
        ) {
            for path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Sendable family check
        let family = prefix_family(prefix);
        if !sendable.is_some_and(|f| f.contains(&family)) {
            for path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Export policy check
        let aspath_str = best
            .as_path()
            .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string);
        let result = evaluate_chain(
            export_pol,
            *prefix,
            best.extended_communities(),
            best.communities(),
            best.large_communities(),
            &aspath_str,
            best.validation_state,
        );
        if result.action != PolicyAction::Permit {
            for path_id in existing_path_ids {
                withdraw.push((*prefix, path_id));
            }
            return;
        }

        // Apply export modifications to a clone
        let mut modified = best.clone();
        let nh_action =
            rustbgpd_policy::apply_modifications(&mut modified.attributes, &result.modifications);
        if let Some(rustbgpd_policy::NextHopAction::Specific(addr)) = &nh_action {
            modified.next_hop = *addr;
        }
        modified.path_id = 0;

        let changed = rib_out
            .get(prefix, 0)
            .is_none_or(|existing| !routes_equal(existing, &modified));
        if changed {
            nh_override_flags.push(nh_action);
            announce.push(modified);
        }

        // Clean up any stale multi-path entries if this prefix was previously
        // advertised via Add-Path and is now single-best.
        for path_id in existing_path_ids {
            if path_id != 0 {
                withdraw.push((*prefix, path_id));
            }
        }
    }

    /// Stage `FlowSpec` announces and withdrawals for a set of rules.
    ///
    /// Uses `loc_rib` as the current best-route source and diffs against the
    /// provided outbound view. Passing an empty `AdjRibOut` view causes a full
    /// re-advertisement of the current `FlowSpec` export set, which is useful
    /// for initial table dump and ROUTE-REFRESH responses.
    #[expect(clippy::too_many_arguments)]
    fn stage_flowspec_rules(
        loc_rib: &LocRib,
        rib_out: &AdjRibOut,
        peer_is_rr_client: &HashMap<IpAddr, bool>,
        rules: &HashSet<FlowSpecRule>,
        target_is_ebgp: bool,
        target_is_rr_client: bool,
        cluster_id: Option<Ipv4Addr>,
        sendable: Option<&Vec<(Afi, Safi)>>,
        export_pol: Option<&PolicyChain>,
        fs_announce: &mut Vec<crate::route::FlowSpecRoute>,
        fs_withdraw: &mut Vec<FlowSpecRule>,
    ) {
        for rule in rules {
            if let Some(best) = loc_rib.get_flowspec(rule) {
                let fs_family = (best.afi, Safi::FlowSpec);
                if !sendable.is_some_and(|f| f.contains(&fs_family)) {
                    if rib_out.get_flowspec(rule).is_some() {
                        fs_withdraw.push(rule.clone());
                    }
                    continue;
                }

                // Reuse the existing iBGP split-horizon / RR check. Only
                // origin_type/peer/peer_router_id are relevant here.
                if should_suppress_ibgp_inner(
                    &crate::route::Route {
                        prefix: Prefix::V4(rustbgpd_wire::Ipv4Prefix::new(
                            Ipv4Addr::UNSPECIFIED,
                            0,
                        )),
                        next_hop: best.peer,
                        peer: best.peer,
                        attributes: vec![],
                        received_at: best.received_at,
                        origin_type: best.origin_type,
                        peer_router_id: best.peer_router_id,
                        is_stale: false,
                        is_llgr_stale: false,
                        path_id: 0,
                        validation_state: rustbgpd_wire::RpkiValidation::NotFound,
                    },
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    peer_is_rr_client,
                ) {
                    if rib_out.get_flowspec(rule).is_some() {
                        fs_withdraw.push(rule.clone());
                    }
                    continue;
                }

                let dest_prefix = best.rule.destination_prefix();
                let prefix_for_policy = dest_prefix.unwrap_or(Prefix::V4(
                    rustbgpd_wire::Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
                ));
                let aspath_str = best
                    .as_path()
                    .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string);
                let result = rustbgpd_policy::evaluate_chain(
                    export_pol,
                    prefix_for_policy,
                    best.extended_communities(),
                    best.communities(),
                    best.large_communities(),
                    &aspath_str,
                    rustbgpd_wire::RpkiValidation::NotFound,
                );
                if result.action == rustbgpd_policy::PolicyAction::Permit {
                    fs_announce.push(best.clone());
                } else if rib_out.get_flowspec(rule).is_some() {
                    fs_withdraw.push(rule.clone());
                }
            } else if rib_out.get_flowspec(rule).is_some() {
                fs_withdraw.push(rule.clone());
            }
        }
    }

    /// Distribute Loc-RIB changes to all registered outbound peers.
    ///
    /// For clean peers, only `changed_prefixes` are evaluated. Dirty peers
    /// (those that failed a previous `try_send()`) get a full export resync:
    /// all Loc-RIB and `AdjRibOut` prefixes are diffed to bring the peer's
    /// view back in sync. `AdjRibOut` is only committed after a successful
    /// channel send; on failure the peer stays dirty for retry via the
    /// resync timer.
    ///
    /// Routes are filtered by `sendable_families` (set at `PeerUp` time)
    /// so that Adj-RIB-Out only contains routes the transport can actually
    /// serialize for this peer. The transport retains `is_family_negotiated`
    /// as a safety net.
    #[expect(clippy::too_many_lines)]
    fn distribute_changes(
        &mut self,
        best_changed: &HashSet<Prefix>,
        all_affected: &HashSet<Prefix>,
    ) {
        if best_changed.is_empty() && all_affected.is_empty() && self.dirty_peers.is_empty() {
            return;
        }

        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            // For dirty peers, compute full prefix set from Loc-RIB + AdjRibOut
            let is_dirty = self.dirty_peers.contains(&peer);
            let effective_prefixes: HashSet<Prefix> = if is_dirty {
                let mut all: HashSet<Prefix> = self.loc_rib.iter().map(|r| r.prefix).collect();
                // For multi-path dirty resync, also include all Adj-RIB-In prefixes
                if self.peer_has_any_add_path_send(peer) {
                    for rib in self.ribs.values() {
                        all.extend(rib.iter().map(|r| r.prefix));
                    }
                }
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter().map(|r| r.prefix));
                }
                all
            } else {
                let mut prefixes = best_changed.clone();
                for prefix in all_affected {
                    if self.add_path_send_max_for_prefix(peer, prefix) > 0 {
                        prefixes.insert(*prefix);
                    }
                }
                prefixes
            };
            let effective_flowspec_rules: HashSet<FlowSpecRule> = if is_dirty {
                let mut all: HashSet<FlowSpecRule> = self
                    .loc_rib
                    .iter_flowspec()
                    .map(|route| route.rule.clone())
                    .collect();
                if let Some(rib_out) = self.adj_ribs_out.get(&peer) {
                    all.extend(rib_out.iter_flowspec().map(|route| route.rule.clone()));
                }
                all
            } else {
                HashSet::new()
            };

            if effective_prefixes.is_empty() && effective_flowspec_rules.is_empty() {
                continue;
            }

            let mut announce = Vec::new();
            let mut withdraw = Vec::new();
            let mut nh_override_flags: Vec<Option<rustbgpd_policy::NextHopAction>> = Vec::new();
            let mut fs_announce = Vec::new();
            let mut fs_withdraw = Vec::new();

            // Resolve export policy, sendable families, and RR state before
            // borrowing rib_out (which holds a &mut to self.adj_ribs_out).
            let export_pol = self.export_policy_for(peer).cloned();
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
            let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
            let cluster_id = self.cluster_id;
            let peer_add_path_send_max =
                self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
            let peer_add_path_send_families = self
                .peer_add_path_send_families
                .get(&peer)
                .cloned()
                .unwrap_or_default();
            let loc_rib = &self.loc_rib;

            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| AdjRibOut::new(peer));

            // Stage: compute delta without mutating AdjRibOut
            for prefix in &effective_prefixes {
                let prefix_send_max = if peer_add_path_send_max > 0
                    && peer_add_path_send_families.contains(&prefix_family(prefix))
                {
                    peer_add_path_send_max
                } else {
                    0
                };
                if prefix_send_max > 0 {
                    // Multi-path: collect all candidates, filter, sort, diff
                    Self::distribute_multipath_prefix(
                        &self.ribs,
                        rib_out,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        prefix_send_max,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        export_pol.as_ref(),
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                    );
                } else {
                    Self::distribute_single_best_prefix(
                        loc_rib,
                        rib_out,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        export_pol.as_ref(),
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                    );
                }
            }

            if is_dirty && !effective_flowspec_rules.is_empty() {
                Self::stage_flowspec_rules(
                    loc_rib,
                    rib_out,
                    &self.peer_is_rr_client,
                    &effective_flowspec_rules,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    export_pol.as_ref(),
                    &mut fs_announce,
                    &mut fs_withdraw,
                );
            }

            if (!announce.is_empty()
                || !withdraw.is_empty()
                || !fs_announce.is_empty()
                || !fs_withdraw.is_empty())
                && let Some(tx) = self.outbound_peers.get(&peer)
            {
                // If a prior initial dump / route-refresh EoR was deferred,
                // piggyback it on the successful dirty resync update so it
                // can't be starved behind the resync message on a small queue.
                let pending_eor = if is_dirty {
                    self.pending_eor
                        .get(&peer)
                        .map(|families| families.iter().copied().collect())
                        .unwrap_or_default()
                } else {
                    vec![]
                };
                let update = OutboundRouteUpdate {
                    next_hop_override: nh_override_flags.clone(),
                    announce: announce.clone(),
                    withdraw: withdraw.clone(),
                    end_of_rib: pending_eor.clone(),
                    refresh_markers: vec![],
                    flowspec_announce: fs_announce.clone(),
                    flowspec_withdraw: fs_withdraw.clone(),
                };
                if tx.try_send(update).is_err() {
                    warn!(%peer, "outbound channel full or closed — marking dirty for resync");
                    self.metrics.record_outbound_route_drop(&peer.to_string());
                    self.dirty_peers.insert(peer);
                } else {
                    // Commit: apply staged mutations to AdjRibOut
                    let rib_out = self
                        .adj_ribs_out
                        .get_mut(&peer)
                        .expect("rib_out just accessed");
                    for route in &announce {
                        rib_out.insert(route.clone());
                    }
                    for &(ref prefix, path_id) in &withdraw {
                        rib_out.withdraw(prefix, path_id);
                    }
                    for route in &fs_announce {
                        rib_out.insert_flowspec(route.clone());
                    }
                    for rule in &fs_withdraw {
                        rib_out.remove_flowspec(rule);
                    }
                    self.metrics.set_adj_rib_out_prefixes(
                        &peer.to_string(),
                        "all",
                        gauge_val(rib_out.len()),
                    );
                    self.metrics.set_adj_rib_out_prefixes(
                        &peer.to_string(),
                        "flowspec",
                        gauge_val(rib_out.flowspec_len()),
                    );
                    if is_dirty {
                        self.dirty_peers.remove(&peer);
                        if pending_eor.is_empty() {
                            self.flush_pending_eor(peer);
                        } else {
                            self.pending_eor.remove(&peer);
                        }
                        self.retry_pending_refresh(peer);
                    }
                }
            } else if is_dirty
                && announce.is_empty()
                && withdraw.is_empty()
                && fs_announce.is_empty()
                && fs_withdraw.is_empty()
            {
                // Dirty peer with no diff — already in sync
                self.dirty_peers.remove(&peer);
                self.flush_pending_eor(peer);
                self.retry_pending_refresh(peer);
            }
        }
    }

    /// Recompute `FlowSpec` Loc-RIB best routes for affected rules and
    /// distribute changes to all outbound peers.
    fn recompute_and_distribute_flowspec(
        &mut self,
        affected: &HashSet<rustbgpd_wire::FlowSpecRule>,
    ) {
        use crate::route::FlowSpecRoute;

        let mut changed_rules: HashSet<rustbgpd_wire::FlowSpecRule> = HashSet::new();

        for rule in affected {
            let candidates: Vec<&FlowSpecRoute> = self
                .ribs
                .values()
                .flat_map(|rib| rib.iter_flowspec_rule(rule))
                .collect();
            let did_change = self
                .loc_rib
                .recompute_flowspec(rule.clone(), candidates.into_iter());
            if did_change {
                changed_rules.insert(rule.clone());
            }
        }

        if changed_rules.is_empty() {
            return;
        }

        self.metrics
            .set_loc_rib_prefixes("flowspec", gauge_val(self.loc_rib.flowspec_len()));

        // Distribute FlowSpec changes to outbound peers
        let peers: Vec<IpAddr> = self.outbound_peers.keys().copied().collect();
        for peer in peers {
            let sendable = self.peer_sendable_families.get(&peer).cloned();
            let has_fs = sendable.as_ref().is_some_and(|families| {
                families.contains(&(rustbgpd_wire::Afi::Ipv4, rustbgpd_wire::Safi::FlowSpec))
                    || families.contains(&(rustbgpd_wire::Afi::Ipv6, rustbgpd_wire::Safi::FlowSpec))
            });
            if !has_fs {
                continue;
            }

            let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
            let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
            let export_pol = self.export_policy_for(peer).cloned();

            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| crate::adj_rib_out::AdjRibOut::new(peer));

            let mut fs_announce = Vec::new();
            let mut fs_withdraw = Vec::new();
            Self::stage_flowspec_rules(
                &self.loc_rib,
                rib_out,
                &self.peer_is_rr_client,
                &changed_rules,
                target_is_ebgp,
                target_is_rr_client,
                self.cluster_id,
                sendable.as_ref(),
                export_pol.as_ref(),
                &mut fs_announce,
                &mut fs_withdraw,
            );

            if (!fs_announce.is_empty() || !fs_withdraw.is_empty())
                && let Some(tx) = self.outbound_peers.get(&peer)
            {
                let update = OutboundRouteUpdate {
                    announce: vec![],
                    withdraw: vec![],
                    end_of_rib: vec![],
                    refresh_markers: vec![],
                    next_hop_override: vec![],
                    flowspec_announce: fs_announce.clone(),
                    flowspec_withdraw: fs_withdraw.clone(),
                };
                if tx.try_send(update).is_err() {
                    warn!(%peer, "outbound channel full — FlowSpec update deferred");
                    self.dirty_peers.insert(peer);
                } else {
                    // Commit to AdjRibOut
                    let rib_out = self
                        .adj_ribs_out
                        .get_mut(&peer)
                        .expect("rib_out just accessed");
                    for route in &fs_announce {
                        rib_out.insert_flowspec(route.clone());
                    }
                    for rule in &fs_withdraw {
                        rib_out.remove_flowspec(rule);
                    }
                    self.metrics.set_adj_rib_out_prefixes(
                        &peer.to_string(),
                        "flowspec",
                        gauge_val(rib_out.flowspec_len()),
                    );
                }
            }
        }
    }

    /// Send the full Loc-RIB to a newly established peer (initial table dump).
    ///
    /// `AdjRibOut` is only populated after a successful channel send. On
    /// failure the peer is marked dirty so `distribute_changes()` will
    /// retry a full resync via the resync timer.
    #[expect(clippy::too_many_lines)]
    fn send_initial_table(&mut self, peer: IpAddr) {
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_override_flags: Vec<Option<rustbgpd_policy::NextHopAction>> = Vec::new();
        let mut fs_announce = Vec::new();
        let mut fs_withdraw = Vec::new();
        let export_pol = self.export_policy_for(peer).cloned();
        let sendable = self.peer_sendable_families.get(&peer).cloned();
        let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
        let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
        let cluster_id = self.cluster_id;
        let peer_add_path_send_max = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
        let peer_add_path_send_families = self
            .peer_add_path_send_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let loc_rib = &self.loc_rib;

        let mut all_prefixes: HashSet<Prefix> = self.loc_rib.iter().map(|r| r.prefix).collect();
        for rib in self.ribs.values() {
            all_prefixes.extend(rib.iter().map(|r| r.prefix));
        }

        // Stage against an empty outbound view so initial dump always
        // re-sends the full current table for this peer.
        let initial_view = AdjRibOut::new(peer);

        for prefix in &all_prefixes {
            let prefix_send_max = if peer_add_path_send_max > 0
                && peer_add_path_send_families.contains(&prefix_family(prefix))
            {
                peer_add_path_send_max
            } else {
                0
            };
            if prefix_send_max > 0 {
                Self::distribute_multipath_prefix(
                    &self.ribs,
                    &initial_view,
                    &self.peer_is_rr_client,
                    prefix,
                    peer,
                    prefix_send_max,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    export_pol.as_ref(),
                    &mut announce,
                    &mut withdraw,
                    &mut nh_override_flags,
                );
            } else {
                Self::distribute_single_best_prefix(
                    loc_rib,
                    &initial_view,
                    &self.peer_is_rr_client,
                    prefix,
                    peer,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    export_pol.as_ref(),
                    &mut announce,
                    &mut withdraw,
                    &mut nh_override_flags,
                );
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
                target_is_ebgp,
                target_is_rr_client,
                cluster_id,
                sendable.as_ref(),
                export_pol.as_ref(),
                &mut fs_announce,
                &mut fs_withdraw,
            );
        }

        // Determine EoR families from this peer's sendable families
        let eor_families = self
            .peer_sendable_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();

        if let Some(tx) = self.outbound_peers.get(&peer) {
            if !announce.is_empty()
                || !withdraw.is_empty()
                || !fs_announce.is_empty()
                || !fs_withdraw.is_empty()
            {
                let update = OutboundRouteUpdate {
                    next_hop_override: nh_override_flags.clone(),
                    announce: announce.clone(),
                    withdraw: withdraw.clone(),
                    end_of_rib: vec![],
                    refresh_markers: vec![],
                    flowspec_announce: fs_announce.clone(),
                    flowspec_withdraw: fs_withdraw.clone(),
                };
                if tx.try_send(update).is_err() {
                    warn!(%peer, "outbound channel full or closed during initial dump — marking dirty");
                    self.metrics.record_outbound_route_drop(&peer.to_string());
                    for f in &eor_families {
                        self.pending_eor.entry(peer).or_default().insert(*f);
                    }
                    self.dirty_peers.insert(peer);
                    return;
                }
                // Commit: populate AdjRibOut with what was actually sent
                let rib_out = self
                    .adj_ribs_out
                    .entry(peer)
                    .or_insert_with(|| AdjRibOut::new(peer));
                for route in &announce {
                    rib_out.insert(route.clone());
                }
                for (prefix, path_id) in &withdraw {
                    rib_out.withdraw(prefix, *path_id);
                }
                for route in &fs_announce {
                    rib_out.insert_flowspec(route.clone());
                }
                for rule in &fs_withdraw {
                    rib_out.remove_flowspec(rule);
                }
                self.metrics.set_adj_rib_out_prefixes(
                    &peer.to_string(),
                    "all",
                    gauge_val(rib_out.len()),
                );
                self.metrics.set_adj_rib_out_prefixes(
                    &peer.to_string(),
                    "flowspec",
                    gauge_val(rib_out.flowspec_len()),
                );
            }

            // Send End-of-RIB markers for all sendable families
            if !eor_families.is_empty() {
                let eor = OutboundRouteUpdate {
                    next_hop_override: vec![],
                    announce: vec![],
                    withdraw: vec![],
                    end_of_rib: eor_families.clone(),
                    refresh_markers: vec![],
                    flowspec_announce: vec![],
                    flowspec_withdraw: vec![],
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

    /// Re-advertise the Loc-RIB for a given family to a peer, followed by `EoR`.
    /// Called when a peer sends ROUTE-REFRESH (RFC 2918).
    #[expect(clippy::too_many_lines)]
    fn send_route_refresh_response(&mut self, peer: IpAddr, afi: Afi, safi: Safi) {
        let family = (afi, safi);
        let mut announce = Vec::new();
        let mut withdraw = Vec::new();
        let mut nh_override_flags: Vec<Option<rustbgpd_policy::NextHopAction>> = Vec::new();
        let mut fs_announce = Vec::new();
        let mut fs_withdraw = Vec::new();
        let export_pol = self.export_policy_for(peer).cloned();
        let sendable = self.peer_sendable_families.get(&peer).cloned();
        let target_is_ebgp = self.peer_is_ebgp.get(&peer).copied().unwrap_or(true);
        let target_is_rr_client = self.peer_is_rr_client.get(&peer).copied().unwrap_or(false);
        let cluster_id = self.cluster_id;
        let peer_add_path_send_max = self.peer_add_path_send_max.get(&peer).copied().unwrap_or(0);
        let peer_add_path_send_families = self
            .peer_add_path_send_families
            .get(&peer)
            .cloned()
            .unwrap_or_default();
        let loc_rib = &self.loc_rib;

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

        if safi == Safi::FlowSpec {
            let flow_rules: HashSet<FlowSpecRule> = self
                .loc_rib
                .iter_flowspec()
                .filter(|route| route.afi == afi)
                .map(|route| route.rule.clone())
                .collect();
            if !flow_rules.is_empty() {
                Self::stage_flowspec_rules(
                    loc_rib,
                    &refresh_view,
                    &self.peer_is_rr_client,
                    &flow_rules,
                    target_is_ebgp,
                    target_is_rr_client,
                    cluster_id,
                    sendable.as_ref(),
                    export_pol.as_ref(),
                    &mut fs_announce,
                    &mut fs_withdraw,
                );
            }
        } else {
            for prefix in &all_prefixes {
                let prefix_send_max = if peer_add_path_send_max > 0
                    && peer_add_path_send_families.contains(&prefix_family(prefix))
                {
                    peer_add_path_send_max
                } else {
                    0
                };
                if prefix_send_max > 0 {
                    Self::distribute_multipath_prefix(
                        &self.ribs,
                        &refresh_view,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        prefix_send_max,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        export_pol.as_ref(),
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                    );
                } else {
                    Self::distribute_single_best_prefix(
                        loc_rib,
                        &refresh_view,
                        &self.peer_is_rr_client,
                        prefix,
                        peer,
                        target_is_ebgp,
                        target_is_rr_client,
                        cluster_id,
                        sendable.as_ref(),
                        export_pol.as_ref(),
                        &mut announce,
                        &mut withdraw,
                        &mut nh_override_flags,
                    );
                }
            }
        }

        if let Some(tx) = self.outbound_peers.get(&peer) {
            let update = OutboundRouteUpdate {
                next_hop_override: nh_override_flags.clone(),
                announce: announce.clone(),
                withdraw: withdraw.clone(),
                end_of_rib: vec![family],
                refresh_markers: vec![
                    (afi, safi, RouteRefreshSubtype::BoRR),
                    (afi, safi, RouteRefreshSubtype::EoRR),
                ],
                flowspec_announce: fs_announce.clone(),
                flowspec_withdraw: fs_withdraw.clone(),
            };
            if tx.try_send(update).is_err() {
                warn!(%peer, ?family, "outbound channel full during route refresh response");
                self.metrics.record_outbound_route_drop(&peer.to_string());
                self.pending_refresh.entry(peer).or_default().insert(family);
                self.dirty_peers.insert(peer);
                return;
            }
            self.pending_refresh
                .entry(peer)
                .or_default()
                .remove(&family);

            // Update AdjRibOut
            let rib_out = self
                .adj_ribs_out
                .entry(peer)
                .or_insert_with(|| AdjRibOut::new(peer));
            for route in &announce {
                rib_out.insert(route.clone());
            }
            for (prefix, path_id) in &withdraw {
                rib_out.withdraw(prefix, *path_id);
            }
            for route in &fs_announce {
                rib_out.insert_flowspec(route.clone());
            }
            for rule in &fs_withdraw {
                rib_out.remove_flowspec(rule);
            }
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "all",
                gauge_val(rib_out.len()),
            );
            self.metrics.set_adj_rib_out_prefixes(
                &peer.to_string(),
                "flowspec",
                gauge_val(rib_out.flowspec_len()),
            );
        }
    }

    /// Try to send any deferred `EoR` markers for a peer.
    ///
    /// Called after a successful dirty-peer resync. If the send fails again,
    /// the peer is re-marked dirty for another attempt.
    fn flush_pending_eor(&mut self, peer: IpAddr) {
        let Some(families) = self.pending_eor.remove(&peer) else {
            return;
        };
        if families.is_empty() {
            return;
        }
        let Some(tx) = self.outbound_peers.get(&peer) else {
            return;
        };
        let eor = OutboundRouteUpdate {
            next_hop_override: vec![],
            announce: vec![],
            withdraw: vec![],
            end_of_rib: families.iter().copied().collect(),
            refresh_markers: vec![],
            flowspec_announce: vec![],
            flowspec_withdraw: vec![],
        };
        if tx.try_send(eor).is_err() {
            warn!(%peer, "outbound channel full — `EoR` still deferred");
            self.pending_eor.insert(peer, families);
            self.dirty_peers.insert(peer);
        }
    }

    /// Retry any deferred enhanced route refresh responses for a peer.
    fn retry_pending_refresh(&mut self, peer: IpAddr) {
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
    fn finish_route_refresh(&mut self, peer: IpAddr, afi: Afi, safi: Safi, timed_out: bool) {
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
        let stale_flowspec_keys: Vec<(FlowSpecRule, u32)> = self
            .refresh_stale_flowspec
            .get(&peer)
            .map(|stale| {
                stale
                    .iter()
                    .filter(|(stale_afi, _, _)| *stale_afi == afi && safi == Safi::FlowSpec)
                    .map(|(_, rule, path_id)| (rule.clone(), *path_id))
                    .collect()
            })
            .unwrap_or_default();

        let mut affected = HashSet::new();
        let mut fs_affected = HashSet::new();
        if let Some(rib) = self.ribs.get_mut(&peer) {
            for (prefix, path_id) in &stale_route_keys {
                if rib.withdraw(prefix, *path_id) {
                    affected.insert(*prefix);
                }
            }
            for (rule, path_id) in &stale_flowspec_keys {
                if rib.withdraw_flowspec(rule, *path_id) {
                    fs_affected.insert(rule.clone());
                }
            }
            self.metrics
                .set_rib_prefixes(&peer.to_string(), "all", gauge_val(rib.len()));
            self.metrics.set_rib_prefixes(
                &peer.to_string(),
                "flowspec",
                gauge_val(rib.flowspec_len()),
            );
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
                stale.retain(|(stale_afi, _, _)| !(*stale_afi == afi && safi == Safi::FlowSpec));
                stale.is_empty()
            } else {
                false
            };
        if clear_flowspec_stale_entry {
            self.refresh_stale_flowspec.remove(&peer);
        }

        let clear_refresh_entry = if let Some(families) = self.refresh_in_progress.get_mut(&peer) {
            families.remove(&family);
            families.is_empty()
        } else {
            false
        };
        if clear_refresh_entry {
            self.refresh_in_progress.remove(&peer);
        }

        let changed = self.recompute_best(&affected);
        self.distribute_changes(&changed, &affected);
        if !fs_affected.is_empty() {
            self.recompute_and_distribute_flowspec(&fs_affected);
        }
    }

    /// Process a single `RibUpdate` message.
    #[expect(clippy::too_many_lines)]
    fn handle_update(&mut self, update: RibUpdate) {
        match update {
            RibUpdate::RoutesReceived {
                peer,
                announced,
                withdrawn,
                flowspec_announced,
                flowspec_withdrawn,
            } => {
                let active_refresh = self
                    .refresh_in_progress
                    .get(&peer)
                    .cloned()
                    .unwrap_or_default();
                let rib = self.ribs.entry(peer).or_insert_with(|| AdjRibIn::new(peer));
                let mut affected = HashSet::new();

                for &(prefix, path_id) in &withdrawn {
                    if rib.withdraw(&prefix, path_id) {
                        debug!(%peer, %prefix, path_id, "withdrawn");
                        affected.insert(prefix);
                    }
                    if active_refresh.contains(&prefix_family(&prefix))
                        && let Some(stale) = self.refresh_stale_routes.get_mut(&peer)
                    {
                        stale.remove(&(prefix, path_id));
                    }
                }

                for mut route in announced {
                    if let Some(ref table) = self.vrp_table {
                        route.validation_state = validate_route_rpki(&route, table);
                    }
                    debug!(%peer, prefix = %route.prefix, "announced");
                    affected.insert(route.prefix);
                    let prefix = route.prefix;
                    let path_id = route.path_id;
                    rib.insert(route);
                    if active_refresh.contains(&prefix_family(&prefix))
                        && let Some(stale) = self.refresh_stale_routes.get_mut(&peer)
                    {
                        stale.remove(&(prefix, path_id));
                    }
                }

                // FlowSpec routes
                let mut fs_affected: HashSet<rustbgpd_wire::FlowSpecRule> = HashSet::new();
                for rule in &flowspec_withdrawn {
                    if rib.withdraw_flowspec(rule, 0) {
                        debug!(%peer, rule = %rule, "flowspec withdrawn");
                        fs_affected.insert(rule.clone());
                    }
                    if active_refresh.iter().any(|(afi, safi)| {
                        *safi == Safi::FlowSpec && matches!(afi, Afi::Ipv4 | Afi::Ipv6)
                    }) && let Some(stale) = self.refresh_stale_flowspec.get_mut(&peer)
                    {
                        stale.retain(|(_, stale_rule, _)| stale_rule != rule);
                    }
                }
                for route in flowspec_announced {
                    debug!(%peer, rule = %route.rule, "flowspec announced");
                    let stale_key = (route.afi, route.rule.clone(), route.path_id);
                    fs_affected.insert(route.rule.clone());
                    rib.insert_flowspec(route);
                    if active_refresh.contains(&(stale_key.0, Safi::FlowSpec))
                        && let Some(stale) = self.refresh_stale_flowspec.get_mut(&peer)
                    {
                        stale.remove(&stale_key);
                    }
                }

                debug!(%peer, routes = rib.len(), "rib updated");
                let peer_label = peer.to_string();
                self.metrics
                    .set_rib_prefixes(&peer_label, "all", gauge_val(rib.len()));
                self.metrics.set_rib_prefixes(
                    &peer_label,
                    "flowspec",
                    gauge_val(rib.flowspec_len()),
                );
                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed, &affected);

                if !fs_affected.is_empty() {
                    self.recompute_and_distribute_flowspec(&fs_affected);
                }
            }

            RibUpdate::PeerDown { peer } => {
                // If GR was active for this peer, abort it and sweep stale routes
                if self.gr_peers.remove(&peer).is_some() {
                    self.gr_stale_deadlines.remove(&peer);
                    self.gr_stale_routes_time.remove(&peer);
                    self.llgr_peer_config.remove(&peer);
                    info!(%peer, "peer down during graceful restart — aborting GR");
                    let peer_label = peer.to_string();
                    self.metrics.set_gr_active(&peer_label, false);
                    self.metrics.set_gr_stale_routes(&peer_label, 0);
                }

                // If LLGR was active for this peer, abort it
                if self.llgr_peers.remove(&peer).is_some() {
                    self.llgr_stale_deadlines.remove(&peer);
                    info!(%peer, "peer down during LLGR — aborting LLGR");
                    let peer_label = peer.to_string();
                    self.metrics.set_gr_active(&peer_label, false);
                    self.metrics.set_gr_stale_routes(&peer_label, 0);
                }

                if let Some(rib) = self.ribs.get_mut(&peer) {
                    let affected: HashSet<Prefix> = rib.iter().map(|r| r.prefix).collect();
                    let count = rib.len();
                    // Collect FlowSpec rules before clearing
                    let fs_affected: HashSet<rustbgpd_wire::FlowSpecRule> =
                        rib.iter_flowspec().map(|r| r.rule.clone()).collect();
                    rib.clear();
                    rib.clear_flowspec();
                    debug!(%peer, cleared = count, "peer down — rib cleared");
                    self.metrics.set_rib_prefixes(&peer.to_string(), "all", 0);
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed, &affected);
                    if !fs_affected.is_empty() {
                        self.recompute_and_distribute_flowspec(&fs_affected);
                    }
                }
                // Clean up outbound state
                self.adj_ribs_out.remove(&peer);
                self.metrics
                    .set_adj_rib_out_prefixes(&peer.to_string(), "all", 0);
                self.outbound_peers.remove(&peer);
                self.peer_export_policies.remove(&peer);
                self.peer_sendable_families.remove(&peer);
                self.peer_is_ebgp.remove(&peer);
                self.peer_is_rr_client.remove(&peer);
                self.peer_add_path_send_max.remove(&peer);
                self.peer_add_path_send_families.remove(&peer);
                self.dirty_peers.remove(&peer);
                self.pending_eor.remove(&peer);
                self.clear_peer_refresh_state(peer);
            }

            RibUpdate::PeerUp {
                peer,
                outbound_tx,
                export_policy,
                sendable_families,
                is_ebgp,
                route_reflector_client,
                add_path_send_families,
                add_path_send_max,
            } => {
                // If the peer re-establishes during graceful restart, keep
                // routes stale and wait for End-of-RIB per family (RFC 4724
                // §4.2).  Reset the timer from restart_time (session window)
                // to stale_routes_time (EoR window).
                if self.gr_peers.contains_key(&peer) {
                    if let Some(&srt) = self.gr_stale_routes_time.get(&peer) {
                        let deadline =
                            tokio::time::Instant::now() + std::time::Duration::from_secs(srt);
                        self.gr_stale_deadlines.insert(peer, deadline);
                    }
                    info!(%peer, "peer re-established during GR — waiting for End-of-RIB");
                } else if self.llgr_peers.contains_key(&peer) {
                    // Peer re-established during LLGR — promote LLGR families
                    // back to GR-awaiting-EoR so EndOfRib clears the stale flag.
                    if let Some(llgr_families) = self.llgr_peers.remove(&peer) {
                        self.llgr_stale_deadlines.remove(&peer);
                        self.gr_peers.insert(peer, llgr_families);
                        // Use a generous deadline for EoR during LLGR re-establishment
                        let deadline =
                            tokio::time::Instant::now() + std::time::Duration::from_secs(360);
                        self.gr_stale_deadlines.insert(peer, deadline);
                        info!(%peer, "peer re-established during LLGR — waiting for End-of-RIB");
                    }
                }

                debug!(%peer, "peer up — registering for outbound updates");
                let peer_label = peer.to_string();
                self.metrics.set_rib_prefixes(&peer_label, "all", 0);
                self.metrics.set_adj_rib_out_prefixes(&peer_label, "all", 0);
                self.outbound_peers.insert(peer, outbound_tx);
                self.peer_export_policies.insert(peer, export_policy);
                self.peer_sendable_families.insert(peer, sendable_families);
                self.peer_is_ebgp.insert(peer, is_ebgp);
                self.peer_is_rr_client.insert(peer, route_reflector_client);
                self.peer_add_path_send_families
                    .insert(peer, add_path_send_families);
                self.peer_add_path_send_max.insert(peer, add_path_send_max);
                self.send_initial_table(peer);
            }

            RibUpdate::InjectRoute { route, reply } => {
                let prefix = route.prefix;
                let rib = self
                    .ribs
                    .entry(LOCAL_PEER)
                    .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
                rib.insert(route);
                debug!(%prefix, "injected local route");
                self.metrics
                    .set_rib_prefixes(&LOCAL_PEER.to_string(), "all", gauge_val(rib.len()));

                let mut affected = HashSet::new();
                affected.insert(prefix);
                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed, &affected);

                let _ = reply.send(Ok(()));
            }

            RibUpdate::WithdrawInjected {
                prefix,
                path_id,
                reply,
            } => {
                let rib = self
                    .ribs
                    .entry(LOCAL_PEER)
                    .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
                if rib.withdraw(&prefix, path_id) {
                    debug!(%prefix, "withdrawn injected route");
                    self.metrics.set_rib_prefixes(
                        &LOCAL_PEER.to_string(),
                        "all",
                        gauge_val(rib.len()),
                    );
                    let mut affected = HashSet::new();
                    affected.insert(prefix);
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed, &affected);
                    let _ = reply.send(Ok(()));
                } else {
                    let _ = reply.send(Err(format!("prefix {prefix} not found")));
                }
            }

            RibUpdate::QueryReceivedRoutes { peer, reply } => {
                let routes: Vec<_> = match peer {
                    Some(peer_addr) => self
                        .ribs
                        .get(&peer_addr)
                        .map(|rib| rib.iter().cloned().collect())
                        .unwrap_or_default(),
                    None => self
                        .ribs
                        .values()
                        .flat_map(|rib| rib.iter().cloned())
                        .collect(),
                };

                if reply.send(routes).is_err() {
                    warn!("query caller dropped before receiving response");
                }
            }

            RibUpdate::QueryBestRoutes { reply } => {
                let routes: Vec<_> = self.loc_rib.iter().cloned().collect();
                if reply.send(routes).is_err() {
                    warn!("query caller dropped before receiving response");
                }
            }

            RibUpdate::QueryAdvertisedRoutes { peer, reply } => {
                let routes: Vec<_> = self
                    .adj_ribs_out
                    .get(&peer)
                    .map(|rib| rib.iter().cloned().collect())
                    .unwrap_or_default();

                if reply.send(routes).is_err() {
                    warn!("query caller dropped before receiving response");
                }
            }

            RibUpdate::SubscribeRouteEvents { reply } => {
                let rx = self.route_events_tx.subscribe();
                let _ = reply.send(rx);
            }

            RibUpdate::QueryLocRibCount { reply } => {
                let _ = reply.send(self.loc_rib.len());
            }

            RibUpdate::QueryAdvertisedCount { peer, reply } => {
                let count = self.adj_ribs_out.get(&peer).map_or(0, AdjRibOut::len);
                let _ = reply.send(count);
            }

            RibUpdate::EndOfRib { peer, afi, safi } => {
                info!(%peer, ?afi, ?safi, "received End-of-RIB");
                let is_gr_peer = self.gr_peers.contains_key(&peer);
                let is_llgr_peer = self.llgr_peers.contains_key(&peer);
                if !is_gr_peer && !is_llgr_peer {
                    debug!(%peer, ?afi, ?safi, "End-of-RIB received without active GR/LLGR state, ignoring");
                }
                if is_gr_peer {
                    // Remove family from awaiting set
                    if let Some(awaiting) = self.gr_peers.get_mut(&peer) {
                        awaiting.remove(&(afi, safi));
                    }

                    // Clear stale flag on this family's routes
                    if let Some(rib) = self.ribs.get_mut(&peer) {
                        rib.clear_stale((afi, safi));
                    }

                    // Recompute best paths — routes are no longer demoted
                    let affected: HashSet<Prefix> = self
                        .ribs
                        .get(&peer)
                        .map(|rib| rib.iter().map(|r| r.prefix).collect())
                        .unwrap_or_default();
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed, &affected);

                    // Update stale routes metric after partial clear
                    let peer_label = peer.to_string();
                    let stale_count = self
                        .ribs
                        .get(&peer)
                        .map_or(0, |rib| rib.iter().filter(|r| r.is_stale).count());
                    self.metrics
                        .set_gr_stale_routes(&peer_label, gauge_val(stale_count));

                    // If all families received EoR, GR is complete
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
                    // EoR during LLGR phase — clear LLGR-stale flag for this family
                    if let Some(awaiting) = self.llgr_peers.get_mut(&peer) {
                        awaiting.remove(&(afi, safi));
                    }

                    // Clear LLGR-stale flag on this family's routes
                    if let Some(rib) = self.ribs.get_mut(&peer) {
                        rib.clear_llgr_stale((afi, safi));
                    }

                    // Recompute best paths — routes are no longer demoted
                    let affected: HashSet<Prefix> = self
                        .ribs
                        .get(&peer)
                        .map(|rib| rib.iter().map(|r| r.prefix).collect())
                        .unwrap_or_default();
                    let changed = self.recompute_best(&affected);
                    self.distribute_changes(&changed, &affected);

                    let peer_label = peer.to_string();
                    let llgr_stale_count = self
                        .ribs
                        .get(&peer)
                        .map_or(0, |rib| rib.iter().filter(|r| r.is_llgr_stale).count());
                    self.metrics
                        .set_gr_stale_routes(&peer_label, gauge_val(llgr_stale_count));

                    // If all LLGR families received EoR, LLGR is complete
                    let all_done = self.llgr_peers.get(&peer).is_some_and(HashSet::is_empty);
                    if all_done {
                        info!(%peer, "LLGR complete — all End-of-RIB received");
                        self.llgr_peers.remove(&peer);
                        self.llgr_stale_deadlines.remove(&peer);
                        self.metrics.set_gr_active(&peer_label, false);
                        self.metrics.set_gr_stale_routes(&peer_label, 0);
                    }
                }
            }

            RibUpdate::RouteRefreshRequest { peer, afi, safi } => {
                info!(%peer, ?afi, ?safi, "handling route refresh request");
                self.send_route_refresh_response(peer, afi, safi);
            }

            RibUpdate::BeginRouteRefresh { peer, afi, safi } => {
                info!(%peer, ?afi, ?safi, "beginning enhanced route refresh");
                self.refresh_in_progress
                    .entry(peer)
                    .or_default()
                    .insert((afi, safi));
                self.refresh_deadlines.insert(
                    (peer, afi, safi),
                    tokio::time::Instant::now() + ERR_REFRESH_TIMEOUT,
                );
                if let Some(rib) = self.ribs.get(&peer) {
                    if safi == Safi::FlowSpec {
                        let stale = self.refresh_stale_flowspec.entry(peer).or_default();
                        stale.retain(|(stale_afi, _, _)| *stale_afi != afi);
                        for route in rib.iter_flowspec().filter(|route| route.afi == afi) {
                            stale.insert((route.afi, route.rule.clone(), route.path_id));
                        }
                    } else {
                        let stale = self.refresh_stale_routes.entry(peer).or_default();
                        stale.retain(|(prefix, _)| prefix_family(prefix) != (afi, safi));
                        for route in rib
                            .iter()
                            .filter(|route| prefix_family(&route.prefix) == (afi, safi))
                        {
                            stale.insert((route.prefix, route.path_id));
                        }
                    }
                }
            }

            RibUpdate::EndRouteRefresh { peer, afi, safi } => {
                self.finish_route_refresh(peer, afi, safi, false);
            }

            RibUpdate::PeerGracefulRestart {
                peer,
                restart_time,
                stale_routes_time,
                gr_families,
                peer_llgr_capable,
                peer_llgr_families,
                llgr_stale_time,
            } => {
                info!(%peer, restart_time, stale_routes_time, llgr_stale_time, "peer entered graceful restart");

                let mut affected = HashSet::new();

                if let Some(rib) = self.ribs.get_mut(&peer) {
                    // Mark routes stale for families in the GR capability
                    for &family in &gr_families {
                        rib.mark_stale(family);
                    }
                    // Withdraw routes for families NOT in the GR capability
                    let withdrawn = rib.withdraw_families_except(&gr_families);
                    if !withdrawn.is_empty() {
                        info!(%peer, count = withdrawn.len(), "withdrew non-GR family routes");
                    }
                    for prefix in withdrawn {
                        affected.insert(prefix);
                    }
                }

                // Include stale routes in affected set for best-path recompute
                if let Some(rib) = self.ribs.get(&peer) {
                    for route in rib.iter() {
                        affected.insert(route.prefix);
                    }
                    self.metrics
                        .set_rib_prefixes(&peer.to_string(), "all", gauge_val(rib.len()));
                }

                let changed = self.recompute_best(&affected);
                self.distribute_changes(&changed, &affected);

                // Clean up outbound state — peer is down, dead channel would
                // cause wasteful dirty-peer resync attempts.
                self.outbound_peers.remove(&peer);
                self.adj_ribs_out.remove(&peer);
                self.peer_export_policies.remove(&peer);
                self.peer_sendable_families.remove(&peer);
                self.peer_is_ebgp.remove(&peer);
                self.peer_is_rr_client.remove(&peer);
                self.peer_add_path_send_max.remove(&peer);
                self.peer_add_path_send_families.remove(&peer);
                self.dirty_peers.remove(&peer);
                self.pending_eor.remove(&peer);
                self.clear_peer_refresh_state(peer);

                // Initial timer = restart_time (window for session re-establishment).
                // On PeerUp, this is reset to stale_routes_time for EoR.
                let deadline = tokio::time::Instant::now()
                    + std::time::Duration::from_secs(u64::from(restart_time));
                self.gr_stale_deadlines.insert(peer, deadline);
                self.gr_stale_routes_time.insert(peer, stale_routes_time);

                // Record awaiting families
                self.gr_peers
                    .insert(peer, gr_families.into_iter().collect());

                // Store LLGR config for two-phase timer
                if peer_llgr_capable && llgr_stale_time > 0 {
                    self.llgr_peer_config.insert(
                        peer,
                        LlgrPeerConfig {
                            peer_llgr_capable,
                            peer_llgr_families,
                            local_llgr_stale_time: llgr_stale_time,
                        },
                    );
                }

                // Metrics
                let peer_label = peer.to_string();
                self.metrics.set_gr_active(&peer_label, true);
                let stale_count = self
                    .ribs
                    .get(&peer)
                    .map_or(0, |rib| rib.iter().filter(|r| r.is_stale).count());
                self.metrics
                    .set_gr_stale_routes(&peer_label, gauge_val(stale_count));
            }

            RibUpdate::RpkiCacheUpdate { table } => {
                info!(
                    vrps = table.len(),
                    "RPKI cache update — re-validating routes"
                );
                self.vrp_table = Some(Arc::clone(&table));
                self.metrics
                    .set_rpki_vrp_count("ipv4", gauge_val(table.v4_count()));
                self.metrics
                    .set_rpki_vrp_count("ipv6", gauge_val(table.v6_count()));

                // Re-validate all routes in all Adj-RIB-Ins.
                let mut affected = HashSet::new();
                for rib in self.ribs.values_mut() {
                    for route in rib.iter_mut() {
                        let new_state = validate_route_rpki(route, &table);
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

            RibUpdate::InjectFlowSpec { route, reply } => {
                let rule = route.rule.clone();
                let rib = self
                    .ribs
                    .entry(LOCAL_PEER)
                    .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
                rib.insert_flowspec(route);
                debug!(rule = %rule, "injected local FlowSpec route");
                let mut fs_affected = HashSet::new();
                fs_affected.insert(rule);
                self.recompute_and_distribute_flowspec(&fs_affected);
                let _ = reply.send(Ok(()));
            }

            RibUpdate::WithdrawFlowSpec { rule, reply } => {
                let rib = self
                    .ribs
                    .entry(LOCAL_PEER)
                    .or_insert_with(|| AdjRibIn::new(LOCAL_PEER));
                if rib.withdraw_flowspec(&rule, 0) {
                    debug!(rule = %rule, "withdrawn injected FlowSpec route");
                    let mut fs_affected = HashSet::new();
                    fs_affected.insert(rule);
                    self.recompute_and_distribute_flowspec(&fs_affected);
                    let _ = reply.send(Ok(()));
                } else {
                    let _ = reply.send(Err(format!("FlowSpec rule {rule} not found")));
                }
            }

            RibUpdate::QueryFlowSpecRoutes { reply } => {
                let routes: Vec<_> = self.loc_rib.iter_flowspec().cloned().collect();
                if reply.send(routes).is_err() {
                    warn!("FlowSpec query caller dropped before receiving response");
                }
            }
        }
    }

    /// Sweep stale routes for a peer whose GR timer has expired.
    ///
    /// Two-phase timer (RFC 9494): if LLGR is configured for this peer,
    /// promote GR-stale routes to LLGR-stale instead of purging.
    fn sweep_gr_stale(&mut self, peer: IpAddr) {
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

            // Compute effective stale time: min(local, peer per-family)
            let peer_min_stale = llgr_config
                .peer_llgr_families
                .iter()
                .filter(|f| gr_families.contains(&(f.afi, f.safi)))
                .map(|f| f.stale_time)
                .min()
                .unwrap_or(llgr_config.local_llgr_stale_time);
            let effective_stale_time = peer_min_stale.min(llgr_config.local_llgr_stale_time);

            let mut affected = HashSet::new();
            let mut rib_len = 0;
            if let Some(rib) = self.ribs.get_mut(&peer) {
                for &family in &gr_families {
                    let promoted = rib.promote_to_llgr_stale(family);
                    for p in promoted {
                        affected.insert(p);
                    }
                }
                rib_len = rib.len();
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
                .insert(peer, gr_families.into_iter().collect());
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
    fn sweep_llgr_stale(&mut self, peer: IpAddr) {
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
    fn next_gr_deadline(&self) -> Option<tokio::time::Instant> {
        self.gr_stale_deadlines.values().copied().min()
    }

    /// Find the nearest LLGR stale deadline, if any.
    fn next_llgr_deadline(&self) -> Option<tokio::time::Instant> {
        self.llgr_stale_deadlines.values().copied().min()
    }

    /// Find the nearest enhanced route refresh deadline, if any.
    fn next_refresh_deadline(&self) -> Option<tokio::time::Instant> {
        self.refresh_deadlines.values().copied().min()
    }

    /// Sweep any inbound enhanced route refresh windows whose deadline has
    /// expired.
    fn expire_refresh_windows(&mut self) {
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

    /// Run the RIB manager event loop until the channel is closed.
    ///
    /// When dirty peers exist (from failed outbound sends), a persistent
    /// resync timer fires to retry distribution independently of both
    /// incoming mutations and non-mutating query traffic. The timer is
    /// started when `dirty_peers` transitions from empty to non-empty and
    /// reset after each retry tick; it is not recreated per loop iteration,
    /// so incoming messages cannot starve it.
    pub async fn run(mut self) {
        // Persistent timer: starts far in the future (disabled). Reset to
        // DIRTY_RESYNC_INTERVAL when dirty_peers becomes non-empty.
        let resync_sleep = tokio::time::sleep(DIRTY_RESYNC_INTERVAL);
        tokio::pin!(resync_sleep);
        let mut resync_armed = false;

        // GR stale sweep timer — reset each iteration to the nearest deadline.
        let gr_sleep = tokio::time::sleep(std::time::Duration::from_secs(86400));
        tokio::pin!(gr_sleep);

        // LLGR stale sweep timer — reset each iteration to the nearest deadline.
        let llgr_sleep = tokio::time::sleep(std::time::Duration::from_secs(86400));
        tokio::pin!(llgr_sleep);

        // Enhanced route refresh timer — reset each iteration to the nearest
        // active refresh deadline.
        let refresh_sleep = tokio::time::sleep(std::time::Duration::from_secs(86400));
        tokio::pin!(refresh_sleep);

        loop {
            // Arm the resync timer when dirty_peers transitions empty → non-empty.
            if !self.dirty_peers.is_empty() && !resync_armed {
                resync_sleep
                    .as_mut()
                    .reset(tokio::time::Instant::now() + DIRTY_RESYNC_INTERVAL);
                resync_armed = true;
            }

            // Arm the GR timer to the nearest stale deadline.
            let has_gr_timers = if let Some(deadline) = self.next_gr_deadline() {
                gr_sleep.as_mut().reset(deadline);
                true
            } else {
                false
            };

            // Arm the LLGR timer to the nearest stale deadline.
            let has_llgr_timers = if let Some(deadline) = self.next_llgr_deadline() {
                llgr_sleep.as_mut().reset(deadline);
                true
            } else {
                false
            };

            let has_refresh_timers = if let Some(deadline) = self.next_refresh_deadline() {
                refresh_sleep.as_mut().reset(deadline);
                true
            } else {
                false
            };

            let needs_timers =
                resync_armed || has_gr_timers || has_llgr_timers || has_refresh_timers;

            if needs_timers {
                tokio::select! {
                    update = self.rx.recv() => {
                        match update {
                            Some(update) => self.handle_update(update),
                            None => break,
                        }
                    }
                    () = resync_sleep.as_mut(), if resync_armed => {
                        debug!(
                            count = self.dirty_peers.len(),
                            "resync timer fired for dirty peers"
                        );
                        self.distribute_changes(&HashSet::new(), &HashSet::new());

                        // Reset for next tick if still dirty, otherwise disarm.
                        if self.dirty_peers.is_empty() {
                            resync_armed = false;
                        } else {
                            resync_sleep.as_mut().reset(
                                tokio::time::Instant::now() + DIRTY_RESYNC_INTERVAL,
                            );
                        }
                    }
                    () = gr_sleep.as_mut(), if has_gr_timers => {
                        // Find all peers whose GR deadline has expired
                        let now = tokio::time::Instant::now();
                        let expired: Vec<IpAddr> = self
                            .gr_stale_deadlines
                            .iter()
                            .filter(|&(_, &deadline)| deadline <= now)
                            .map(|(&peer, _)| peer)
                            .collect();
                        for peer in expired {
                            self.sweep_gr_stale(peer);
                        }
                    }
                    () = llgr_sleep.as_mut(), if has_llgr_timers => {
                        // Find all peers whose LLGR deadline has expired
                        let now = tokio::time::Instant::now();
                        let expired: Vec<IpAddr> = self
                            .llgr_stale_deadlines
                            .iter()
                            .filter(|&(_, &deadline)| deadline <= now)
                            .map(|(&peer, _)| peer)
                            .collect();
                        for peer in expired {
                            self.sweep_llgr_stale(peer);
                        }
                    }
                    () = refresh_sleep.as_mut(), if has_refresh_timers => {
                        self.expire_refresh_windows();
                    }
                }
            } else {
                // No timers needed — just wait for the next message.
                match self.rx.recv().await {
                    Some(update) => self.handle_update(update),
                    None => break,
                }
            }

            // Disarm if dirty_peers was cleared by a message handler (e.g. PeerDown).
            if self.dirty_peers.is_empty() {
                resync_armed = false;
            }
        }

        debug!("rib manager shutting down");
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, Instant};

    use rustbgpd_wire::{
        Afi, AsPath, AsPathSegment, FlowSpecComponent, FlowSpecPrefix, FlowSpecRule, Ipv4Prefix,
        Ipv6Prefix, Origin, PathAttribute, Prefix, Safi,
    };
    use tokio::sync::oneshot;

    use super::*;
    use crate::route::{FlowSpecRoute, Route};

    /// Default sendable families for IPv4-only test peers.
    fn ipv4_sendable() -> Vec<(Afi, Safi)> {
        vec![(Afi::Ipv4, Safi::Unicast)]
    }

    /// Sendable families for dual-stack test peers.
    fn dual_stack_sendable() -> Vec<(Afi, Safi)> {
        vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)]
    }

    /// Sendable families for IPv4 `FlowSpec` test peers.
    fn ipv4_flowspec_sendable() -> Vec<(Afi, Safi)> {
        vec![(Afi::Ipv4, Safi::FlowSpec)]
    }

    /// Drain the initial End-of-RIB marker sent at `PeerUp` time.
    async fn drain_eor(out_rx: &mut mpsc::Receiver<OutboundRouteUpdate>) {
        let eor = out_rx.recv().await.unwrap();
        assert!(eor.announce.is_empty());
        assert!(eor.withdraw.is_empty());
        assert!(!eor.end_of_rib.is_empty());
    }

    async fn query_best_routes(tx: &mpsc::Sender<RibUpdate>) -> Vec<Route> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }

    async fn query_received_routes(tx: &mpsc::Sender<RibUpdate>, peer: IpAddr) -> Vec<Route> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
        reply_rx.await.unwrap()
    }

    fn make_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
        Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(next_hop),
            peer: IpAddr::V4(next_hop),
            attributes: vec![],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        }
    }

    fn make_v6_route(prefix: Ipv6Prefix, next_hop: Ipv6Addr) -> Route {
        Route {
            prefix: Prefix::V6(prefix),
            next_hop: IpAddr::V6(next_hop),
            peer: IpAddr::V6(next_hop),
            attributes: vec![],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        }
    }

    fn make_route_with_lp(prefix: Ipv4Prefix, peer: Ipv4Addr, local_pref: u32) -> Route {
        Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(peer),
            peer: IpAddr::V4(peer),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![65001])],
                }),
                PathAttribute::LocalPref(local_pref),
            ],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        }
    }

    fn make_flowspec_route(peer: Ipv4Addr) -> FlowSpecRoute {
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
        FlowSpecRoute {
            rule: FlowSpecRule {
                components: vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
                    prefix,
                ))],
            },
            afi: Afi::Ipv4,
            peer: IpAddr::V4(peer),
            attributes: vec![],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
        }
    }

    #[tokio::test]
    async fn routes_received_and_queried() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, Prefix::V4(prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn peer_down_clears_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::PeerDown { peer }).await.unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert!(routes.is_empty());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn withdrawal_removes_route() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![
                make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1)),
                make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![],
            withdrawn: vec![(Prefix::V4(prefix1), 0)],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, Prefix::V4(prefix2));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn query_all_peers() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route(
                Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
                Ipv4Addr::new(10, 0, 0, 1),
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route(
                Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24),
                Ipv4Addr::new(10, 0, 0, 2),
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: None,
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 2);

        drop(tx);
        handle.await.unwrap();
    }

    // --- Loc-RIB integration tests ---

    #[tokio::test]
    async fn best_routes_returns_winner() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        // Peer1: local_pref 100
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Peer2: local_pref 200 — should win
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].peer, peer2);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn peer_down_promotes_second_best() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Peer2 goes down — peer1 should be promoted
        tx.send(RibUpdate::PeerDown { peer: peer2 }).await.unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].peer, peer1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn withdrawal_updates_best() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Peer2 withdraws the prefix
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![],
            withdrawn: vec![(Prefix::V4(prefix), 0)],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].peer, peer1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn different_best_per_prefix() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix_a = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let prefix_b = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        // Peer1 wins prefix_a (higher LP), peer2 wins prefix_b (higher LP)
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![
                make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 1), 200),
                make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 1), 100),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![
                make_route_with_lp(prefix_a, Ipv4Addr::new(1, 0, 0, 2), 100),
                make_route_with_lp(prefix_b, Ipv4Addr::new(1, 0, 0, 2), 200),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();

        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 2);

        let best_a = best
            .iter()
            .find(|r| r.prefix == Prefix::V4(prefix_a))
            .unwrap();
        let best_b = best
            .iter()
            .find(|r| r.prefix == Prefix::V4(prefix_b))
            .unwrap();
        assert_eq!(best_a.peer, peer1);
        assert_eq!(best_b.peer, peer2);

        drop(tx);
        handle.await.unwrap();
    }

    // --- M3 outbound distribution tests ---

    #[tokio::test]
    async fn peer_up_triggers_initial_table_dump() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Inject a route from source
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Register target for outbound
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Should receive initial table dump
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
        assert!(update.withdraw.is_empty());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_change_distributes_to_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn single_best_send_normalizes_path_id_to_zero() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        route.path_id = 42;

        tx.send(RibUpdate::RoutesReceived {
            peer: route.peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));
        assert_eq!(update.announce[0].path_id, 0);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn split_horizon_prevents_echo() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        // The route is FROM this peer — should not be sent back
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Force a query to serialize the event loop
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // Channel should be empty (no outbound update sent)
        assert!(out_rx.try_recv().is_err());

        drop(tx);
        handle.await.unwrap();
    }

    /// Like [`make_route`] but with iBGP origin (iBGP-learned route).
    fn make_ibgp_route(prefix: Ipv4Prefix, next_hop: Ipv4Addr) -> Route {
        Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(next_hop),
            peer: IpAddr::V4(next_hop),
            attributes: vec![],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ibgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        }
    }

    #[tokio::test]
    async fn ibgp_route_not_sent_to_ibgp_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        // Source: iBGP peer
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Target: iBGP peer (is_ebgp: false)
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // iBGP-learned route should NOT be sent to iBGP peer
        assert!(out_rx.try_recv().is_err());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn ibgp_route_sent_to_ebgp_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        // Source: iBGP peer
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Target: eBGP peer (is_ebgp: true)
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Initial dump includes the route (iBGP→eBGP is allowed)
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

        // Then EoR
        drain_eor(&mut out_rx).await;

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn ebgp_route_sent_to_ibgp_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        // Source: eBGP peer
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Target: iBGP peer (is_ebgp: false)
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Initial dump includes the route (eBGP→iBGP is allowed)
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

        // Then EoR
        drain_eor(&mut out_rx).await;

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn ibgp_split_horizon_withdraw_on_best_change() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        // Setup: eBGP source announces route, iBGP target receives it
        let ebgp_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let ibgp_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Register iBGP target peer
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: ibgp_target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // eBGP route → should be advertised to iBGP peer
        tx.send(RibUpdate::RoutesReceived {
            peer: ebgp_source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);

        // Now the eBGP source goes down, replaced by iBGP source
        tx.send(RibUpdate::PeerDown { peer: ebgp_source })
            .await
            .unwrap();

        // Withdraw should be sent to iBGP target
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.withdraw.len(), 1);

        // iBGP source announces the same prefix
        let ibgp_source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        tx.send(RibUpdate::RoutesReceived {
            peer: ibgp_source,
            announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 3))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Force serialization
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // iBGP-learned route should NOT be sent to iBGP peer
        assert!(out_rx.try_recv().is_err());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn local_route_sent_to_ibgp_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        // Register iBGP target peer first
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // Inject a local route
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let route = Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer: LOCAL_PEER,
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Local,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::InjectRoute {
            route,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let _ = reply_rx.await;

        // Local route SHOULD be sent to iBGP peer (unlike iBGP-learned routes)
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn local_route_in_initial_table_to_ibgp_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        // Inject a local route first
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let route = Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer: LOCAL_PEER,
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Local,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::InjectRoute {
            route,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let _ = reply_rx.await;

        // Register iBGP target peer — should receive local route in initial dump
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Initial dump should include the local route
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(prefix));

        // Then EoR
        drain_eor(&mut out_rx).await;

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn peer_down_cleans_up_outbound() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        tx.send(RibUpdate::PeerDown { peer }).await.unwrap();

        // Query advertised routes — should be empty after PeerDown
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer,
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert!(routes.is_empty());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn inject_route_enters_loc_rib_and_distributes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let route = Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer: LOCAL_PEER,
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Local,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::InjectRoute {
            route,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Should be in Loc-RIB
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].prefix, Prefix::V4(prefix));

        // Should have been distributed
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn withdraw_injected_removes_and_distributes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 16);
        let route = Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer: LOCAL_PEER,
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Local,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::InjectRoute {
            route,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let _ = reply_rx.await;

        // Consume the inject announcement
        let _ = out_rx.recv().await;

        // Now withdraw
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::WithdrawInjected {
            prefix: Prefix::V4(prefix),
            path_id: 0,
            reply: reply_tx,
        })
        .await
        .unwrap();
        assert!(reply_rx.await.unwrap().is_ok());

        // Should receive withdrawal
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.withdraw.len(), 1);
        assert_eq!(update.withdraw[0], (Prefix::V4(prefix), 0));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn export_policy_blocks_denied() {
        use rustbgpd_policy::{
            Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
        };

        let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let export_policy = PolicyChain::new(vec![Policy {
            entries: vec![PolicyStatement {
                prefix: Some(Prefix::V4(denied_prefix)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        }]);

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, Some(export_policy), None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        // This route matches the deny entry
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Force serialization
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // Should NOT have received the denied route
        assert!(out_rx.try_recv().is_err());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn query_advertised_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Wait for distribution
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();

        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].prefix, Prefix::V4(prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn per_peer_export_policy() {
        use rustbgpd_policy::{
            Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
        };

        let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        let allowed_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Peer1 gets a deny policy on 10.0.0.0/8, peer2 has no per-peer policy
        let peer1_export = Some(PolicyChain::new(vec![Policy {
            entries: vec![PolicyStatement {
                prefix: Some(Prefix::V4(denied_prefix)),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        }]));

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        let (send_filtered, mut recv_filtered) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: peer1,
            outbound_tx: send_filtered,
            export_policy: peer1_export,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut recv_filtered).await;

        let (send_unfiltered, mut recv_unfiltered) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: peer2,
            outbound_tx: send_unfiltered,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut recv_unfiltered).await;

        // Source peer sends both prefixes
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![
                make_route(denied_prefix, Ipv4Addr::new(10, 0, 0, 1)),
                make_route(allowed_prefix, Ipv4Addr::new(10, 0, 0, 1)),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Peer1: should get only the allowed prefix (denied_prefix blocked)
        let filtered = recv_filtered.recv().await.unwrap();
        assert_eq!(filtered.announce.len(), 1);
        assert_eq!(filtered.announce[0].prefix, Prefix::V4(allowed_prefix));

        // Peer2: should get both (no per-peer policy, no global policy)
        let unfiltered = recv_unfiltered.recv().await.unwrap();
        assert_eq!(unfiltered.announce.len(), 2);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn peer_down_cleans_up_export_policy() {
        use rustbgpd_policy::{
            Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
        };

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let (out_tx, _out_rx) = mpsc::channel(64);
        let policy = Some(PolicyChain::new(vec![Policy {
            entries: vec![PolicyStatement {
                prefix: Some(Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8))),
                ge: None,
                le: None,
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        }]));

        tx.send(RibUpdate::PeerUp {
            peer,
            outbound_tx: out_tx,
            export_policy: policy,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        tx.send(RibUpdate::PeerDown { peer }).await.unwrap();

        // Query to confirm loop processed PeerDown
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let routes = reply_rx.await.unwrap();
        assert!(routes.is_empty());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    #[expect(clippy::too_many_lines)]
    async fn channel_full_marks_dirty_and_resyncs() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);

        // Channel capacity 1: fills after one send
        let (out_tx, mut out_rx) = mpsc::channel(1);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // First route: should succeed (channel empty → fits)
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Drain the successful send so we can verify AdjRibOut
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);

        // Verify AdjRibOut has the route
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(advertised.len(), 1);

        // Send prefix2 — fills the channel (capacity 1)
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // DON'T drain — channel is now full. Withdraw prefix1 to trigger
        // another distribute_changes that will fail on try_send.
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![],
            withdrawn: vec![(Prefix::V4(prefix1), 0)],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Force serialization
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // After channel-full failure, AdjRibOut preserves last successfully
        // sent state: both prefix1 and prefix2 were sent before the failure.
        // The withdrawal of prefix1 was lost because the channel was full.
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(
            advertised.len(),
            2,
            "AdjRibOut preserves last successfully sent state (prefix1+prefix2)"
        );

        // Now drain the channel to allow resync
        let _ = out_rx.recv().await.unwrap();

        // Advance time to trigger the dirty-peer resync timer — no external
        // route mutation needed; the timer fires independently.
        tokio::time::advance(Duration::from_secs(2)).await;

        // Drain the resync update
        let resync = out_rx.recv().await.unwrap();

        // The resync should withdraw prefix1 (no longer in Loc-RIB). Prefix2
        // was already successfully enqueued before the channel filled, so it
        // does not need to be re-announced unless it diverged.
        assert!(
            resync.withdraw.contains(&(Prefix::V4(prefix1), 0)),
            "resync should withdraw prefix1 (no longer in Loc-RIB)"
        );
        assert!(
            !resync.withdraw.contains(&(Prefix::V4(prefix2), 0)),
            "resync should not withdraw prefix2"
        );

        // After successful resync, AdjRibOut should match Loc-RIB
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(
            advertised.len(),
            1,
            "AdjRibOut matches Loc-RIB after resync (only prefix2)"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn dirty_resync_not_starved_by_query_traffic() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        let (out_tx, mut out_rx) = mpsc::channel(1);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Announce prefix1
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        let _ = out_rx.recv().await.unwrap(); // drain

        // Withdraw prefix1 — channel is empty so this fills it
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![],
            withdrawn: vec![(Prefix::V4(prefix1), 0)],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // That send succeeded (channel was empty). Now announce again to fill.
        let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 8);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Don't drain — channel full. Send another route to trigger a failed
        // distribute_changes, marking the peer dirty.
        let prefix3 = Ipv4Prefix::new(Ipv4Addr::new(172, 16, 0, 0), 12);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix3, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Force serialization
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // Drain the outbound channel to allow resync
        let _ = out_rx.recv().await.unwrap();

        // Advance 500ms — not enough for the 1s timer
        tokio::time::advance(Duration::from_millis(500)).await;

        // Send several queries to exercise the "message churn" path.
        // With the old code (sleep recreated each iteration), each query
        // would reset the 1s countdown, starving the timer.
        for _ in 0..5 {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
                .await
                .unwrap();
            let _ = reply_rx.await;
        }

        // Advance the remaining 600ms — total 1100ms, past the 1s deadline
        // that was set before the query churn.
        tokio::time::advance(Duration::from_millis(600)).await;

        // The resync should fire despite the intervening queries.
        let resync = out_rx.recv().await.unwrap();
        assert!(
            !resync.announce.is_empty() || !resync.withdraw.is_empty(),
            "resync should produce updates despite query churn"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn initial_dump_failure_leaves_adjribout_empty() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Pre-populate Loc-RIB
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Use a closed channel (drop rx side immediately) to guarantee send failure
        let (out_tx, out_rx) = mpsc::channel(1);
        drop(out_rx);

        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // AdjRibOut should be empty since initial dump send failed
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert!(
            advertised.is_empty(),
            "AdjRibOut should be empty when initial dump send fails"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn initial_dump_failure_resyncs_via_timer() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Pre-populate Loc-RIB
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Use a full channel (capacity 1, pre-filled) to fail the initial dump
        // but keep the channel recoverable (unlike closed).
        let (out_tx, mut out_rx) = mpsc::channel(1);
        // Fill the channel so send_initial_table's try_send fails
        out_tx
            .send(OutboundRouteUpdate {
                next_hop_override: vec![],
                announce: vec![],
                withdraw: vec![],
                end_of_rib: vec![],
                refresh_markers: vec![],
                flowspec_announce: vec![],
                flowspec_withdraw: vec![],
            })
            .await
            .unwrap();

        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Force serialization — initial dump should have failed (channel full)
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert!(
            advertised.is_empty(),
            "AdjRibOut should be empty after failed initial dump"
        );

        // Drain the channel to make room for the resync
        let _ = out_rx.recv().await.unwrap();

        // Advance time to trigger the resync timer
        tokio::time::advance(Duration::from_secs(2)).await;

        // The resync should deliver the initial table
        let resync = out_rx.recv().await.unwrap();
        assert_eq!(
            resync.announce.len(),
            1,
            "resync should announce the route from Loc-RIB"
        );
        assert_eq!(resync.announce[0].prefix, Prefix::V4(prefix));
        assert!(resync.withdraw.is_empty());
        assert_eq!(resync.end_of_rib, ipv4_sendable());

        // AdjRibOut should now reflect Loc-RIB
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(
            advertised.len(),
            1,
            "AdjRibOut should match Loc-RIB after resync"
        );

        drop(tx);
        handle.await.unwrap();
    }

    // --- Route event streaming tests ---

    async fn subscribe_events(
        tx: &mpsc::Sender<RibUpdate>,
    ) -> tokio::sync::broadcast::Receiver<crate::event::RouteEvent> {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::SubscribeRouteEvents { reply: reply_tx })
            .await
            .unwrap();
        reply_rx.await.unwrap()
    }

    #[tokio::test]
    async fn route_event_added_on_new_best() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let mut events_rx = subscribe_events(&tx).await;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, crate::event::RouteEventType::Added);
        assert_eq!(event.prefix, Prefix::V4(prefix));
        assert_eq!(event.peer, Some(peer));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_withdrawn_on_last_removed() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Subscribe after route is added
        let mut events_rx = subscribe_events(&tx).await;

        // Withdraw the route
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![],
            withdrawn: vec![(Prefix::V4(prefix), 0)],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, crate::event::RouteEventType::Withdrawn);
        assert_eq!(event.prefix, Prefix::V4(prefix));
        assert!(event.peer.is_none());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_best_changed_on_better_path() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        // Peer1 announces first
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Subscribe after first route is installed
        let mut events_rx = subscribe_events(&tx).await;

        // Peer2 announces with higher local-pref — best changes
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, crate::event::RouteEventType::BestChanged);
        assert_eq!(event.prefix, Prefix::V4(prefix));
        assert_eq!(event.peer, Some(peer2));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multiple_subscribers_receive_same_events() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let mut sub1 = subscribe_events(&tx).await;
        let mut sub2 = subscribe_events(&tx).await;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let e1 = sub1.recv().await.unwrap();
        let e2 = sub2.recv().await.unwrap();
        assert_eq!(e1.prefix, Prefix::V4(prefix));
        assert_eq!(e2.prefix, Prefix::V4(prefix));
        assert_eq!(e1.event_type, e2.event_type);

        drop(tx);
        handle.await.unwrap();
    }

    // --- WatchRoutes event tests ---

    #[tokio::test]
    async fn route_event_withdrawn_carries_previous_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let mut events_rx = subscribe_events(&tx).await;

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![],
            withdrawn: vec![(Prefix::V4(prefix), 0)],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, RouteEventType::Withdrawn);
        assert!(event.peer.is_none());
        assert_eq!(event.previous_peer, Some(peer));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_best_changed_carries_both_peers() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);
        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 1), 100)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let mut events_rx = subscribe_events(&tx).await;

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_route_with_lp(prefix, Ipv4Addr::new(1, 0, 0, 2), 200)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, RouteEventType::BestChanged);
        assert_eq!(event.peer, Some(peer2));
        assert_eq!(event.previous_peer, Some(peer1));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_has_timestamp() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let mut events_rx = subscribe_events(&tx).await;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert!(!event.timestamp.is_empty());
        // Should be a valid integer (Unix seconds)
        let ts: u64 = event
            .timestamp
            .parse()
            .expect("timestamp should be numeric");
        assert!(ts > 0);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_added_has_no_previous_peer() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let mut events_rx = subscribe_events(&tx).await;

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, RouteEventType::Added);
        assert_eq!(event.peer, Some(peer));
        assert!(event.previous_peer.is_none());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_event_carries_best_path_id() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let mut events_rx = subscribe_events(&tx).await;

        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let mut route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));
        route.path_id = 42;
        let peer = route.peer;

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let event = events_rx.recv().await.unwrap();
        assert_eq!(event.event_type, RouteEventType::Added);
        assert_eq!(event.peer, Some(peer));
        assert_eq!(event.path_id, 42);

        drop(tx);
        handle.await.unwrap();
    }

    // --- Prometheus gauge tests ---

    #[tokio::test]
    #[expect(clippy::cast_possible_truncation)]
    async fn rib_prefixes_gauge_tracks_adjribin() {
        let metrics = BgpMetrics::new();
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, metrics.clone());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Serialize
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        let families = metrics.registry().gather();
        let rib_gauge = families
            .iter()
            .find(|f| f.get_name() == "bgp_rib_prefixes")
            .expect("bgp_rib_prefixes metric not found");
        let sample = rib_gauge.get_metric()[0].get_gauge().get_value();
        assert_eq!(sample as i64, 1);

        // PeerDown should zero the gauge
        tx.send(RibUpdate::PeerDown { peer }).await.unwrap();
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        let families = metrics.registry().gather();
        let rib_gauge = families
            .iter()
            .find(|f| f.get_name() == "bgp_rib_prefixes")
            .expect("bgp_rib_prefixes metric not found");
        let sample = rib_gauge.get_metric()[0].get_gauge().get_value();
        assert_eq!(sample as i64, 0);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    #[expect(clippy::cast_possible_truncation)]
    async fn loc_rib_gauge_tracks_best() {
        let metrics = BgpMetrics::new();
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, metrics.clone());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        let families = metrics.registry().gather();
        let loc_gauge = families
            .iter()
            .find(|f| f.get_name() == "bgp_rib_loc_prefixes")
            .expect("bgp_loc_rib_prefixes metric not found");
        let sample = loc_gauge.get_metric()[0].get_gauge().get_value();
        assert_eq!(sample as i64, 1);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    #[expect(clippy::cast_possible_truncation)]
    async fn adj_rib_out_gauge_tracks_advertised() {
        let metrics = BgpMetrics::new();
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, metrics.clone());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        let (out_tx, mut _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        let families = metrics.registry().gather();
        let out_gauge = families
            .iter()
            .find(|f| f.get_name() == "bgp_rib_adj_out_prefixes")
            .expect("bgp_adj_rib_out_prefixes metric not found");
        let sample = out_gauge.get_metric()[0].get_gauge().get_value();
        assert_eq!(sample as i64, 1);

        drop(tx);
        handle.await.unwrap();
    }

    // --- Query count tests ---

    #[tokio::test]
    async fn query_loc_rib_count() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 2, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![
                make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1)),
                make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1)),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryLocRibCount { reply: reply_tx })
            .await
            .unwrap();
        let count = reply_rx.await.unwrap();
        assert_eq!(count, 2);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn query_advertised_count() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        let (out_tx, mut _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Serialize
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedCount {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let count = reply_rx.await.unwrap();
        assert_eq!(count, 1);

        // Unknown peer returns 0
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedCount {
            peer: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 99)),
            reply: reply_tx,
        })
        .await
        .unwrap();
        let count = reply_rx.await.unwrap();
        assert_eq!(count, 0);

        drop(tx);
        handle.await.unwrap();
    }

    // --- Sendable families filtering tests ---

    #[tokio::test]
    async fn distribute_changes_filters_unsendable_families() {
        use rustbgpd_wire::Ipv6Prefix;

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);

        // Register peer with IPv4-only sendable families
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

        let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
        let v6_route = Route {
            prefix: Prefix::V6(v6_prefix),
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            peer: source,
            attributes: vec![],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };

        // Send both IPv4 and IPv6 routes
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![v4_route, v6_route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Should only receive IPv4 route
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(v4_prefix));
        assert!(update.withdraw.is_empty());

        // Adj-RIB-Out should only contain IPv4
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(advertised.len(), 1);
        assert_eq!(advertised[0].prefix, Prefix::V4(v4_prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn send_initial_table_filters_unsendable_families() {
        use rustbgpd_wire::Ipv6Prefix;

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

        let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
        let v6_route = Route {
            prefix: Prefix::V6(v6_prefix),
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            peer: source,
            attributes: vec![],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };

        // Pre-populate Loc-RIB with both IPv4 and IPv6 routes
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![v4_route, v6_route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Register peer with IPv4-only sendable families — initial dump
        // should filter out the IPv6 route
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Initial table dump should only contain IPv4
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].prefix, Prefix::V4(v4_prefix));
        assert!(update.withdraw.is_empty());

        // Adj-RIB-Out should only contain IPv4
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryAdvertisedRoutes {
            peer: target,
            reply: reply_tx,
        })
        .await
        .unwrap();
        let advertised = reply_rx.await.unwrap();
        assert_eq!(advertised.len(), 1);
        assert_eq!(advertised[0].prefix, Prefix::V4(v4_prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn dual_stack_peer_receives_both_families() {
        use rustbgpd_wire::Ipv6Prefix;

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

        let v4_route = make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1));
        let v6_route = Route {
            prefix: Prefix::V6(v6_prefix),
            next_hop: IpAddr::V6("2001:db8::1".parse().unwrap()),
            peer: source,
            attributes: vec![],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };

        // Pre-populate Loc-RIB
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![v4_route, v6_route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Register peer with dual-stack sendable families
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: dual_stack_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Should receive both routes in initial dump
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 2);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn send_initial_table_includes_flowspec_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
        let fs_rule = fs_route.rule.clone();

        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: vec![fs_route],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_flowspec_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert!(update.announce.is_empty());
        assert!(update.withdraw.is_empty());
        assert_eq!(update.flowspec_announce.len(), 1);
        assert_eq!(update.flowspec_announce[0].rule, fs_rule);
        assert!(update.flowspec_withdraw.is_empty());

        let eor = out_rx.recv().await.unwrap();
        assert_eq!(eor.end_of_rib, ipv4_flowspec_sendable());

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_refresh_flowspec_re_advertises_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
        let fs_rule = fs_route.rule.clone();

        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: vec![fs_route],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_flowspec_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Drain the initial dump and its EoR before triggering route refresh.
        let _ = out_rx.recv().await.unwrap();
        let _ = out_rx.recv().await.unwrap();

        tx.send(RibUpdate::RouteRefreshRequest {
            peer: target,
            afi: Afi::Ipv4,
            safi: Safi::FlowSpec,
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert!(update.announce.is_empty());
        assert!(update.withdraw.is_empty());
        assert_eq!(update.flowspec_announce.len(), 1);
        assert_eq!(update.flowspec_announce[0].rule, fs_rule);
        assert!(update.flowspec_withdraw.is_empty());
        assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::FlowSpec)]);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn enhanced_route_refresh_replacement_preserves_refreshed_route() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
        let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route.clone()],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::BeginRouteRefresh {
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::EndRouteRefresh {
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();

        let best = query_best_routes(&tx).await;
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].prefix, Prefix::V4(prefix));

        let received = query_received_routes(&tx, peer).await;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].prefix, Prefix::V4(prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn enhanced_route_refresh_eorr_sweeps_unreplaced_route() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
        let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
        let route1 = make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1));
        let route2 = make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1));

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route1.clone(), route2],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::BeginRouteRefresh {
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
        tokio::task::yield_now().await;

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route1],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tokio::task::yield_now().await;

        tx.send(RibUpdate::EndRouteRefresh {
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();

        let best = query_best_routes(&tx).await;
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].prefix, Prefix::V4(prefix1));

        let received = query_received_routes(&tx, peer).await;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].prefix, Prefix::V4(prefix1));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn enhanced_route_refresh_duplicate_borr_rebuilds_snapshot_safely() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route.clone()],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        for _ in 0..2 {
            tx.send(RibUpdate::BeginRouteRefresh {
                peer,
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
            })
            .await
            .unwrap();
        }

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::EndRouteRefresh {
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();

        let best = query_best_routes(&tx).await;
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].prefix, Prefix::V4(prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn enhanced_route_refresh_eorr_without_active_state_is_ignored() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(203, 0, 113, 0), 24);
        let route = make_route(prefix, Ipv4Addr::new(10, 0, 0, 1));

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::EndRouteRefresh {
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();

        let best = query_best_routes(&tx).await;
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].prefix, Prefix::V4(prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn enhanced_route_refresh_timeout_sweeps_unreplaced_routes() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix1 = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
        let prefix2 = Ipv4Prefix::new(Ipv4Addr::new(198, 51, 100, 0), 24);
        let route1 = make_route(prefix1, Ipv4Addr::new(10, 0, 0, 1));
        let route2 = make_route(prefix2, Ipv4Addr::new(10, 0, 0, 1));

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route1.clone(), route2],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::BeginRouteRefresh {
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
        tokio::task::yield_now().await;

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route1],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tokio::time::advance(ERR_REFRESH_TIMEOUT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let best = query_best_routes(&tx).await;
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].prefix, Prefix::V4(prefix1));

        let received = query_received_routes(&tx, peer).await;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].prefix, Prefix::V4(prefix1));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn enhanced_route_refresh_timeout_is_family_isolated() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 24);
        let v6_prefix = Ipv6Prefix::new(Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 0), 64);

        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![
                make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1)),
                make_v6_route(v6_prefix, Ipv6Addr::new(0x2001, 0xdb8, 1, 0, 0, 0, 0, 1)),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::BeginRouteRefresh {
            peer,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
        tokio::task::yield_now().await;

        tokio::time::advance(ERR_REFRESH_TIMEOUT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        let best = query_best_routes(&tx).await;
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].prefix, Prefix::V6(v6_prefix));

        let received = query_received_routes(&tx, peer).await;
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].prefix, Prefix::V6(v6_prefix));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn dirty_resync_retries_flowspec_updates() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (out_tx, mut out_rx) = mpsc::channel(1);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_flowspec_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // The initial EoR occupies the single slot, so the next FlowSpec
        // update will fail to enqueue and mark the peer dirty.
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let fs_route = make_flowspec_route(Ipv4Addr::new(10, 0, 0, 1));
        let fs_rule = fs_route.rule.clone();
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: vec![fs_route],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Drain the initial EoR to make room for the timer-driven resync.
        let initial = out_rx.recv().await.unwrap();
        assert_eq!(initial.end_of_rib, ipv4_flowspec_sendable());

        tokio::time::advance(Duration::from_secs(2)).await;

        let resync = out_rx.recv().await.unwrap();
        assert!(resync.announce.is_empty());
        assert!(resync.withdraw.is_empty());
        assert_eq!(resync.flowspec_announce.len(), 1);
        assert_eq!(resync.flowspec_announce[0].rule, fs_rule);
        assert!(resync.flowspec_withdraw.is_empty());

        drop(tx);
        handle.await.unwrap();
    }

    // --- Graceful Restart tests ---

    #[tokio::test]
    async fn gr_marks_stale_and_demotes_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);

        // Source enters graceful restart
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        })
        .await
        .unwrap();

        // Route should still be in Loc-RIB (stale but present)
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(best[0].is_stale, "route should be marked stale");

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_eor_clears_stale() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Source enters graceful restart
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        })
        .await
        .unwrap();

        // Verify stale
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert!(best[0].is_stale);

        // Send End-of-RIB
        tx.send(RibUpdate::EndOfRib {
            peer: source,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();

        // Route should no longer be stale
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(
            !best[0].is_stale,
            "route should no longer be stale after EoR"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_timer_sweeps_stale_routes() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Source enters graceful restart with short timer
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 5,
            stale_routes_time: 10,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        })
        .await
        .unwrap();

        // Route is stale but still in Loc-RIB
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(best[0].is_stale);

        // Advance past the GR timer (min(5, 10) = 5 seconds)
        tokio::time::advance(Duration::from_secs(6)).await;
        // Yield to let the manager process the expired GR timer
        tokio::task::yield_now().await;

        // Route should have been swept
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert!(best.is_empty(), "stale routes should be swept after timer");

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_peer_up_defers_stale_to_eor() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Source enters graceful restart
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        })
        .await
        .unwrap();

        // Verify route is stale
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert!(best[0].is_stale);

        // Source re-establishes — route should STILL be stale
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: source,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(best[0].is_stale, "route should still be stale after PeerUp");

        // End-of-RIB clears stale and completes GR
        tx.send(RibUpdate::EndOfRib {
            peer: source,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(
            !best[0].is_stale,
            "route should be non-stale after End-of-RIB"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_peer_up_timer_expires_sweeps_stale() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Source enters GR with short restart_time
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 5,
            stale_routes_time: 10,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        })
        .await
        .unwrap();

        // Advance past restart_time but before stale_routes_time
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;

        // Source re-establishes — timer resets to stale_routes_time (10s)
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: source,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // Route still stale (no EoR yet)
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert!(best[0].is_stale);

        // Advance past stale_routes_time — timer should sweep
        tokio::time::advance(Duration::from_secs(11)).await;
        tokio::task::yield_now().await;

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert!(best.is_empty(), "stale routes should be swept after timer");

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_peer_down_aborts_gr() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Source enters graceful restart
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        })
        .await
        .unwrap();

        // Source goes fully down during GR — aborts GR, clears all routes
        tx.send(RibUpdate::PeerDown { peer: source }).await.unwrap();

        // Routes should be gone
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert!(best.is_empty(), "routes cleared after PeerDown aborts GR");

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn gr_withdraws_non_gr_family_routes() {
        use rustbgpd_wire::Ipv6Prefix;

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source: IpAddr = "10.0.0.1".parse().unwrap();
        let v4_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let v6_prefix = Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32);

        // Source sends both IPv4 and IPv6 routes
        let v6_route = Route {
            prefix: Prefix::V6(v6_prefix),
            next_hop: "2001:db8::1".parse().unwrap(),
            peer: source,
            attributes: vec![],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(v4_prefix, Ipv4Addr::new(10, 0, 0, 1)), v6_route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Verify both routes present
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 2);

        // GR with only IPv4 in GR capability — IPv6 should be withdrawn
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 120,
            stale_routes_time: 360,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 0,
        })
        .await
        .unwrap();

        // IPv4 route should be stale, IPv6 route should be gone
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1, "only IPv4 route should remain");
        assert!(
            matches!(best[0].prefix, Prefix::V4(_)),
            "remaining route should be IPv4"
        );
        assert!(best[0].is_stale, "IPv4 route should be stale");

        drop(tx);
        handle.await.unwrap();
    }

    // --- LLGR (RFC 9494) tests ---

    #[tokio::test]
    async fn llgr_gr_timer_promotes_to_llgr_stale() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Source sends a route
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Source enters GR with LLGR enabled
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 5,
            stale_routes_time: 10,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: true,
            peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: false,
                stale_time: 3600,
            }],
            llgr_stale_time: 7200,
        })
        .await
        .unwrap();

        // Route should be GR-stale
        let best = query_best_routes(&tx).await;
        assert_eq!(best.len(), 1);
        assert!(best[0].is_stale);
        assert!(!best[0].is_llgr_stale);

        // Advance past GR timer — should promote to LLGR-stale
        tokio::time::advance(Duration::from_secs(6)).await;
        tokio::task::yield_now().await;

        let best = query_best_routes(&tx).await;
        assert_eq!(best.len(), 1, "route should still be present during LLGR");
        assert!(!best[0].is_stale, "GR-stale flag should be cleared");
        assert!(best[0].is_llgr_stale, "route should be LLGR-stale");

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn llgr_timer_sweeps_llgr_stale_routes() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // GR with LLGR, short timers for testing
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 2,
            stale_routes_time: 5,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: true,
            peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: false,
                stale_time: 10,
            }],
            llgr_stale_time: 10,
        })
        .await
        .unwrap();

        // Ensure manager processes PeerGracefulRestart before advancing time
        let best = query_best_routes(&tx).await;
        assert_eq!(best.len(), 1);
        assert!(best[0].is_stale);

        // Advance past GR timer → promotes to LLGR
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;

        let best = query_best_routes(&tx).await;
        assert_eq!(best.len(), 1);
        assert!(best[0].is_llgr_stale);

        // Advance past LLGR timer → sweeps routes
        tokio::time::advance(Duration::from_secs(11)).await;
        tokio::task::yield_now().await;

        let best = query_best_routes(&tx).await;
        assert!(best.is_empty(), "LLGR-stale routes should be swept");

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn llgr_eor_clears_llgr_stale() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 2,
            stale_routes_time: 5,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: true,
            peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: false,
                stale_time: 3600,
            }],
            llgr_stale_time: 3600,
        })
        .await
        .unwrap();

        // Ensure manager processes PeerGracefulRestart
        let best = query_best_routes(&tx).await;
        assert!(best[0].is_stale);

        // Advance past GR timer → LLGR phase
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;

        let best = query_best_routes(&tx).await;
        assert!(best[0].is_llgr_stale);

        // Peer re-establishes during LLGR
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: source,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // EoR should clear LLGR-stale
        tx.send(RibUpdate::EndOfRib {
            peer: source,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();

        let best = query_best_routes(&tx).await;
        assert_eq!(best.len(), 1);
        assert!(
            !best[0].is_llgr_stale,
            "LLGR-stale should be cleared by EoR"
        );
        assert!(!best[0].is_stale, "GR-stale should also be cleared");

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn llgr_peer_down_aborts_llgr() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 2,
            stale_routes_time: 5,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: true,
            peer_llgr_families: vec![rustbgpd_wire::LlgrFamily {
                afi: Afi::Ipv4,
                safi: Safi::Unicast,
                forwarding_preserved: false,
                stale_time: 3600,
            }],
            llgr_stale_time: 3600,
        })
        .await
        .unwrap();

        // Ensure manager processes PeerGracefulRestart
        let best = query_best_routes(&tx).await;
        assert!(best[0].is_stale);

        // Advance past GR timer → LLGR phase
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;

        let best = query_best_routes(&tx).await;
        assert!(best[0].is_llgr_stale);

        // PeerDown during LLGR — should clear everything
        tx.send(RibUpdate::PeerDown { peer: source }).await.unwrap();

        let best = query_best_routes(&tx).await;
        assert!(
            best.is_empty(),
            "routes should be cleared on PeerDown during LLGR"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn llgr_without_peer_capability_falls_through_to_sweep() {
        tokio::time::pause();

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 1))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // GR without LLGR capability — timer expiry should purge
        tx.send(RibUpdate::PeerGracefulRestart {
            peer: source,
            restart_time: 2,
            stale_routes_time: 5,
            gr_families: vec![(Afi::Ipv4, Safi::Unicast)],
            peer_llgr_capable: false,
            peer_llgr_families: vec![],
            llgr_stale_time: 3600, // local config, but peer doesn't support
        })
        .await
        .unwrap();

        // Ensure manager processes PeerGracefulRestart
        let best = query_best_routes(&tx).await;
        assert!(best[0].is_stale);

        // Advance past GR timer — should purge (no LLGR promotion)
        tokio::time::advance(Duration::from_secs(3)).await;
        tokio::task::yield_now().await;

        let best = query_best_routes(&tx).await;
        assert!(
            best.is_empty(),
            "routes should be purged when peer lacks LLGR"
        );

        drop(tx);
        handle.await.unwrap();
    }

    // --- Route Reflector tests ---

    #[tokio::test]
    async fn rr_client_route_reflected_to_all_ibgp() {
        // When RR receives a route from a client, it should reflect to all
        // iBGP peers (both clients and non-clients), except the source.
        let (tx, rx) = mpsc::channel(64);
        let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
        let manager = RibManager::new(rx, None, cluster_id, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        let client_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let nonclient_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        // Register source as iBGP client
        let (out_tx_src, _) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer: source,
            outbound_tx: out_tx_src,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Register client target
        let (client_tx, mut client_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer: client_target,
            outbound_tx: client_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut client_rx).await;

        // Register non-client target
        let (nonclient_tx, mut nonclient_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer: nonclient_target,
            outbound_tx: nonclient_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut nonclient_rx).await;

        // Source client sends a route
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 4))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Both targets should receive the reflected route
        let client_update = client_rx.recv().await.unwrap();
        assert!(
            !client_update.announce.is_empty(),
            "client should receive reflected route"
        );

        let nonclient_update = nonclient_rx.recv().await.unwrap();
        assert!(
            !nonclient_update.announce.is_empty(),
            "non-client should receive route reflected from client"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn rr_nonclient_route_reflected_to_clients_only() {
        // Route from non-client → reflect to clients only (not non-clients).
        let (tx, rx) = mpsc::channel(64);
        let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
        let manager = RibManager::new(rx, None, cluster_id, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)); // non-client
        let client_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let nonclient_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));

        // Register source as non-client
        let (out_tx_src, _) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer: source,
            outbound_tx: out_tx_src,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Register client target
        let (client_tx, mut client_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer: client_target,
            outbound_tx: client_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: true,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut client_rx).await;

        // Register non-client target
        let (nonclient_tx, mut nonclient_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer: nonclient_target,
            outbound_tx: nonclient_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut nonclient_rx).await;

        // Source sends a route
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Client should get the route
        let update_c = client_rx.recv().await.unwrap();
        assert!(
            !update_c.announce.is_empty(),
            "client should receive non-client route"
        );

        // Non-client should NOT get the route (suppressed by RR)
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            nonclient_rx.try_recv().is_err(),
            "non-client should not receive non-client route"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn non_rr_ibgp_split_horizon_unchanged() {
        // Without cluster_id (no RR), standard split-horizon applies
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        // Register target first (Loc-RIB empty, clean EoR)
        let (out_tx, mut out_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // Source sends iBGP route
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_ibgp_route(prefix, Ipv4Addr::new(10, 0, 0, 2))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // iBGP route should be suppressed (standard split-horizon)
        assert!(
            out_rx.try_recv().is_err(),
            "iBGP route should be suppressed without RR"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn rr_ebgp_route_to_all_ibgp() {
        // eBGP-learned routes should go to all iBGP peers regardless of RR role
        let (tx, rx) = mpsc::channel(64);
        let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
        let manager = RibManager::new(rx, None, cluster_id, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)); // iBGP non-client

        // Register target first (Loc-RIB empty, clean EoR)
        let (out_tx, mut out_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // eBGP source sends a route
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let source = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        tx.send(RibUpdate::RoutesReceived {
            peer: source,
            announced: vec![make_route(prefix, Ipv4Addr::new(10, 0, 0, 5))],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert!(
            !update.announce.is_empty(),
            "eBGP route should reach iBGP non-client"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn rr_local_route_to_all_ibgp() {
        // Local routes should pass to all iBGP peers even with RR
        let (tx, rx) = mpsc::channel(64);
        let cluster_id = Some(Ipv4Addr::new(10, 0, 0, 1));
        let manager = RibManager::new(rx, None, cluster_id, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));

        // Register target first (Loc-RIB empty, clean EoR)
        let (out_tx, mut out_rx) = mpsc::channel(16);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // Inject local route
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let route = Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            peer: LOCAL_PEER,
            attributes: vec![PathAttribute::Origin(Origin::Igp)],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Local,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };
        let (reply_tx, _) = oneshot::channel();
        tx.send(RibUpdate::InjectRoute {
            route,
            reply: reply_tx,
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert!(
            !update.announce.is_empty(),
            "local route should reach iBGP non-client via RR"
        );

        drop(tx);
        handle.await.unwrap();
    }

    // --- RPKI integration tests ---

    fn make_route_with_as_path(prefix: Ipv4Prefix, peer: Ipv4Addr, asns: Vec<u32>) -> Route {
        Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(peer),
            peer: IpAddr::V4(peer),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(asns)],
                }),
                PathAttribute::LocalPref(100),
            ],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        }
    }

    #[test]
    fn validate_route_rpki_valid() {
        use rustbgpd_rpki::{VrpEntry, VrpTable};
        let table = VrpTable::new(vec![VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
            max_len: 24,
            origin_asn: 65001,
        }]);
        let route = make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            Ipv4Addr::new(1, 0, 0, 1),
            vec![65001],
        );
        assert_eq!(
            super::validate_route_rpki(&route, &table),
            RpkiValidation::Valid,
        );
    }

    #[test]
    fn validate_route_rpki_invalid() {
        use rustbgpd_rpki::{VrpEntry, VrpTable};
        let table = VrpTable::new(vec![VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
            max_len: 24,
            origin_asn: 65001,
        }]);
        // Origin AS 65002 doesn't match VRP
        let route = make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            Ipv4Addr::new(1, 0, 0, 1),
            vec![65002],
        );
        assert_eq!(
            super::validate_route_rpki(&route, &table),
            RpkiValidation::Invalid,
        );
    }

    #[test]
    fn validate_route_rpki_not_found() {
        use rustbgpd_rpki::{VrpEntry, VrpTable};
        let table = VrpTable::new(vec![VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
            max_len: 24,
            origin_asn: 65001,
        }]);
        // Prefix 192.168.1.0/24 not covered by any VRP
        let route = make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24),
            Ipv4Addr::new(1, 0, 0, 1),
            vec![65001],
        );
        assert_eq!(
            super::validate_route_rpki(&route, &table),
            RpkiValidation::NotFound,
        );
    }

    #[test]
    fn validate_route_rpki_no_as_path() {
        use rustbgpd_rpki::{VrpEntry, VrpTable};
        let table = VrpTable::new(vec![VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
            max_len: 24,
            origin_asn: 65001,
        }]);
        // Route with no AS_PATH
        let route = make_route(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            Ipv4Addr::new(1, 0, 0, 1),
        );
        assert_eq!(
            super::validate_route_rpki(&route, &table),
            RpkiValidation::NotFound,
        );
    }

    #[test]
    fn validate_route_rpki_empty_as_path() {
        use rustbgpd_rpki::{VrpEntry, VrpTable};
        let table = VrpTable::new(vec![VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
            max_len: 24,
            origin_asn: 65001,
        }]);
        // Route with empty AS_PATH (no segments)
        let route = Route {
            prefix: Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24)),
            next_hop: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            peer: IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath { segments: vec![] }),
                PathAttribute::LocalPref(100),
            ],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: RpkiValidation::NotFound,
        };
        assert_eq!(
            super::validate_route_rpki(&route, &table),
            RpkiValidation::NotFound,
        );
    }

    #[tokio::test]
    async fn routes_validated_on_insert_with_vrp_table() {
        use rustbgpd_rpki::{VrpEntry, VrpTable};
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        // Send RPKI cache update first
        let table = Arc::new(VrpTable::new(vec![VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
            max_len: 24,
            origin_asn: 65001,
        }]));
        tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

        // Now send a route with matching origin
        let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let route = make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            Ipv4Addr::new(1, 0, 0, 1),
            vec![65001],
        );
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Query received routes — should have Valid validation state
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
        let routes = reply_rx.await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].validation_state, RpkiValidation::Valid);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn rpki_cache_update_revalidates_existing_routes() {
        use rustbgpd_rpki::{VrpEntry, VrpTable};
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let route = make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            Ipv4Addr::new(1, 0, 0, 1),
            vec![65001],
        );

        // Insert route (no VRP table yet → NotFound)
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Verify it's NotFound
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
        let routes = reply_rx.await.unwrap();
        assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

        // Now send VRP table that covers the route
        let table = Arc::new(VrpTable::new(vec![VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
            max_len: 24,
            origin_asn: 65001,
        }]));
        tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

        // Query again — should be Valid now
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
        let routes = reply_rx.await.unwrap();
        assert_eq!(routes[0].validation_state, RpkiValidation::Valid);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn rpki_cache_update_changes_best_path() {
        use rustbgpd_rpki::{VrpEntry, VrpTable};
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);

        // Both routes same LP, same AS_PATH length. peer1 has lower peer address → wins initially.
        let route1 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 1), vec![65001]);
        let route2 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 2), vec![65002]);

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![route1],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![route2],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Before RPKI: peer1 should be best (lower address)
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].peer, peer1);

        // Now send VRP that only validates peer2's origin
        let table = Arc::new(VrpTable::new(vec![VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
            max_len: 24,
            origin_asn: 65002,
        }]));
        tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

        // After RPKI: peer2 should be best (Valid > NotFound)
        // But peer1's route has origin 65001, not covered → still NotFound.
        // peer2's route has origin 65002, covered with matching ASN → Valid.
        // Wait a moment for processing...
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        // peer2 wins: Valid beats NotFound
        assert_eq!(best[0].peer, peer2);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn rpki_cache_update_invalid_demotes_best_path() {
        use rustbgpd_rpki::{VrpEntry, VrpTable};
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24);

        // peer1 has lower address → wins initially
        let route1 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 1), vec![65001]);
        let route2 = make_route_with_as_path(prefix, Ipv4Addr::new(1, 0, 0, 2), vec![65002]);

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![route1],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![route2],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // VRP covers the prefix but only for AS 65002 → peer1 (65001) becomes Invalid
        let table = Arc::new(VrpTable::new(vec![VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)),
            prefix_len: 24,
            max_len: 24,
            origin_asn: 65002,
        }]));
        tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

        // peer1 is now Invalid (VRP covers prefix but wrong origin), peer2 is Valid
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let best = reply_rx.await.unwrap();
        assert_eq!(best.len(), 1);
        assert_eq!(best[0].peer, peer2);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn rpki_no_table_all_not_found() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let route = make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            Ipv4Addr::new(1, 0, 0, 1),
            vec![65001],
        );
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
        let routes = reply_rx.await.unwrap();
        assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn rpki_cache_update_no_change_no_redistribution() {
        use rustbgpd_rpki::{VrpEntry, VrpTable};
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer = IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1));
        let (out_tx, mut out_rx) = mpsc::channel(16);

        tx.send(RibUpdate::PeerUp {
            peer,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // Insert route with origin 65001
        let route = make_route_with_as_path(
            Ipv4Prefix::new(Ipv4Addr::new(10, 0, 0, 0), 24),
            Ipv4Addr::new(1, 0, 0, 1),
            vec![65001],
        );
        tx.send(RibUpdate::RoutesReceived {
            peer,
            announced: vec![route],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Consume the outbound update from route insertion (split-horizon blocks it
        // since peer == route.peer, so nothing should arrive)
        // Send an unrelated VRP table that doesn't cover our prefix
        let table = Arc::new(VrpTable::new(vec![VrpEntry {
            prefix: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0)),
            prefix_len: 16,
            max_len: 24,
            origin_asn: 65099,
        }]));
        tx.send(RibUpdate::RpkiCacheUpdate { table }).await.unwrap();

        // Verify route stays NotFound — no VRP covers 10.0.0.0/24
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryReceivedRoutes {
            peer: Some(peer),
            reply: reply_tx,
        })
        .await
        .unwrap();
        let routes = reply_rx.await.unwrap();
        assert_eq!(routes[0].validation_state, RpkiValidation::NotFound);

        drop(tx);
        handle.await.unwrap();
    }

    // ---- Add-Path multi-path send tests ----

    /// Helper: build a route with specific peer, AS path, and `LOCAL_PREF` for
    /// multi-path tests. Routes from different peers with different AS paths
    /// are distinguishable by best-path ordering.
    fn make_multipath_route(
        prefix: Ipv4Prefix,
        peer: Ipv4Addr,
        asns: Vec<u32>,
        local_pref: u32,
    ) -> Route {
        Route {
            prefix: Prefix::V4(prefix),
            next_hop: IpAddr::V4(peer),
            peer: IpAddr::V4(peer),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(asns)],
                }),
                PathAttribute::LocalPref(local_pref),
            ],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        }
    }

    /// Helper: build an IPv6 route with specific peer, AS path, and
    /// `LOCAL_PREF` for dual-stack Add-Path tests.
    fn make_multipath_route_v6(
        prefix: Ipv6Prefix,
        peer: Ipv4Addr,
        next_hop: Ipv6Addr,
        asns: Vec<u32>,
        local_pref: u32,
    ) -> Route {
        Route {
            prefix: Prefix::V6(prefix),
            next_hop: IpAddr::V6(next_hop),
            peer: IpAddr::V4(peer),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(asns)],
                }),
                PathAttribute::LocalPref(local_pref),
            ],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        }
    }

    #[tokio::test]
    async fn multipath_send_advertises_multiple_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Inject two routes for the same prefix from different peers
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 1),
                vec![65001],
                200,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 2),
                vec![65002],
                100,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Register multi-path target (send_max=5)
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: ipv4_sendable(),
            add_path_send_max: 5,
        })
        .await
        .unwrap();

        // Initial dump should contain both routes
        let update = out_rx.recv().await.unwrap();
        assert_eq!(
            update.announce.len(),
            2,
            "multi-path peer should receive 2 routes"
        );
        // path_ids should be 1-indexed rank
        let mut path_ids: Vec<u32> = update.announce.iter().map(|r| r.path_id).collect();
        path_ids.sort_unstable();
        assert_eq!(path_ids, vec![1, 2]);
        // Higher LOCAL_PREF route should be path_id 1 (best)
        let best = update.announce.iter().find(|r| r.path_id == 1).unwrap();
        assert_eq!(best.next_hop, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multipath_send_respects_send_max() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let peer3 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Inject 3 routes
        for (peer, peer_addr, asn, lp) in [
            (peer1, Ipv4Addr::new(10, 0, 0, 1), 65001, 200),
            (peer2, Ipv4Addr::new(10, 0, 0, 2), 65002, 150),
            (peer3, Ipv4Addr::new(10, 0, 0, 3), 65003, 100),
        ] {
            tx.send(RibUpdate::RoutesReceived {
                peer,
                announced: vec![make_multipath_route(prefix, peer_addr, vec![asn], lp)],
                withdrawn: vec![],
                flowspec_announced: vec![],
                flowspec_withdrawn: vec![],
            })
            .await
            .unwrap();
        }

        // Register target with send_max=2
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: ipv4_sendable(),
            add_path_send_max: 2,
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert_eq!(
            update.announce.len(),
            2,
            "send_max=2 should limit to 2 routes"
        );
        // Should be the top 2 by LOCAL_PREF (200 and 150)
        let next_hops: Vec<IpAddr> = update.announce.iter().map(|r| r.next_hop).collect();
        assert!(next_hops.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(next_hops.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2))));

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multipath_send_split_horizon() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Inject route from peer1 and target (target's own route)
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 1),
                vec![65001],
                200,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: target,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 2),
                vec![65002],
                100,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Register multi-path target
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: ipv4_sendable(),
            add_path_send_max: 5,
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert_eq!(
            update.announce.len(),
            1,
            "split-horizon should exclude target's own route"
        );
        assert_eq!(
            update.announce[0].next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multipath_withdrawal_on_candidate_removal() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Register multi-path target first
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: ipv4_sendable(),
            add_path_send_max: 5,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // Inject 2 routes
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 1),
                vec![65001],
                200,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);

        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 2),
                vec![65002],
                100,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        let update = out_rx.recv().await.unwrap();
        // Should now have an announcement for the second path
        assert!(!update.announce.is_empty());

        // Now withdraw peer2's route
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![],
            withdrawn: vec![(Prefix::V4(prefix), 0)],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        let update = out_rx.recv().await.unwrap();
        // Should have a withdrawal for the removed path
        assert!(
            !update.withdraw.is_empty(),
            "removing a candidate should produce a withdrawal"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn single_best_peer_unaffected_by_multipath_config() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Inject 2 routes
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 1),
                vec![65001],
                200,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 2),
                vec![65002],
                100,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Register single-best target (send_max=0)
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert_eq!(
            update.announce.len(),
            1,
            "single-best peer should get only 1 route"
        );
        assert_eq!(
            update.announce[0].path_id, 0,
            "single-best peer should get path_id=0"
        );
        assert_eq!(
            update.announce[0].next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "single-best peer should get the best route"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multipath_peer_down_cleans_up_state() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // Register multi-path target
        let (out_tx, _out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: ipv4_sendable(),
            add_path_send_max: 5,
        })
        .await
        .unwrap();

        // Peer goes down
        tx.send(RibUpdate::PeerDown { peer: target }).await.unwrap();

        // Re-register as single-best (send_max=0) — should work fine,
        // state was properly cleaned up
        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 2),
                vec![65001],
                100,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (reconnect_tx, mut reconnect_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: reconnect_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        let update = reconnect_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1);
        assert_eq!(update.announce[0].path_id, 0);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multipath_send_incremental_route_addition() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Register multi-path target
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: ipv4_sendable(),
            add_path_send_max: 5,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // Add first route
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 1),
                vec![65001],
                200,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1, "first route announced");
        assert_eq!(update.announce[0].path_id, 1);

        // Add second route — should get an incremental update
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 2),
                vec![65002],
                100,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        let update = out_rx.recv().await.unwrap();
        // The new route should be announced (path_id 2)
        let new_announcements: Vec<_> = update
            .announce
            .iter()
            .filter(|r| r.next_hop == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
            .collect();
        assert!(
            !new_announcements.is_empty(),
            "second route should be announced incrementally"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multipath_send_mixed_peers_single_and_multi() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let source1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let source2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let multi_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let single_target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Inject 2 routes
        tx.send(RibUpdate::RoutesReceived {
            peer: source1,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 1),
                vec![65001],
                200,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: source2,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 2),
                vec![65002],
                100,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Register multi-path target
        let (multi_tx, mut multi_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: multi_target,
            outbound_tx: multi_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: ipv4_sendable(),
            add_path_send_max: 5,
        })
        .await
        .unwrap();

        // Register single-best target
        let (single_tx, mut single_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: single_target,
            outbound_tx: single_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: vec![],
            add_path_send_max: 0,
        })
        .await
        .unwrap();

        // Multi-path target gets 2 routes
        let multi_update = multi_rx.recv().await.unwrap();
        assert_eq!(multi_update.announce.len(), 2);

        // Single-best target gets 1 route
        let single_update = single_rx.recv().await.unwrap();
        assert_eq!(single_update.announce.len(), 1);
        assert_eq!(single_update.announce[0].path_id, 0);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multipath_send_ipv6_advertises_multiple_routes() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let prefix = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48);

        let mk = |peer_addr: Ipv4Addr, asn: u32, local_pref: u32| Route {
            prefix: Prefix::V6(prefix),
            next_hop: "2001:db8::1".parse().unwrap(),
            peer: IpAddr::V4(peer_addr),
            attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath {
                    segments: vec![AsPathSegment::AsSequence(vec![asn])],
                }),
                PathAttribute::LocalPref(local_pref),
            ],
            received_at: Instant::now(),
            origin_type: crate::route::RouteOrigin::Ebgp,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            is_stale: false,
            is_llgr_stale: false,
            path_id: 0,
            validation_state: rustbgpd_wire::RpkiValidation::NotFound,
        };

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![mk(Ipv4Addr::new(10, 0, 0, 1), 65001, 200)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![mk(Ipv4Addr::new(10, 0, 0, 2), 65002, 100)],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: vec![(Afi::Ipv6, Safi::Unicast)],
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![(Afi::Ipv6, Safi::Unicast)],
            add_path_send_max: 5,
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert_eq!(
            update.announce.len(),
            2,
            "IPv6 multi-path peer should receive both routes"
        );
        let mut path_ids: Vec<u32> = update.announce.iter().map(|r| r.path_id).collect();
        path_ids.sort_unstable();
        assert_eq!(path_ids, vec![1, 2]);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multipath_send_partial_negotiation_ipv4_only() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let prefix4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let prefix6 = Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48);

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![
                make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 1), vec![65001], 200),
                make_multipath_route_v6(
                    prefix6,
                    Ipv4Addr::new(10, 0, 0, 1),
                    "2001:db8::1".parse().unwrap(),
                    vec![65001],
                    200,
                ),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![
                make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 2), vec![65002], 100),
                make_multipath_route_v6(
                    prefix6,
                    Ipv4Addr::new(10, 0, 0, 2),
                    "2001:db8::2".parse().unwrap(),
                    vec![65002],
                    100,
                ),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: dual_stack_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
            add_path_send_max: 5,
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        let v4_routes: Vec<_> = update
            .announce
            .iter()
            .filter(|r| r.prefix == Prefix::V4(prefix4))
            .collect();
        let v6_routes: Vec<_> = update
            .announce
            .iter()
            .filter(|r| r.prefix == Prefix::V6(prefix6))
            .collect();
        assert_eq!(v4_routes.len(), 2, "IPv4 should use multi-path send");
        assert_eq!(v6_routes.len(), 1, "IPv6 should fall back to single-best");
        let mut v4_path_ids: Vec<u32> = v4_routes.iter().map(|r| r.path_id).collect();
        v4_path_ids.sort_unstable();
        assert_eq!(v4_path_ids, vec![1, 2]);
        assert_eq!(v6_routes[0].path_id, 0);
        drain_eor(&mut out_rx).await;

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multipath_send_partial_negotiation_ipv6_only() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let prefix4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);
        let prefix6 = Ipv6Prefix::new("2001:db8:2::".parse().unwrap(), 48);

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![
                make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 1), vec![65001], 200),
                make_multipath_route_v6(
                    prefix6,
                    Ipv4Addr::new(10, 0, 0, 1),
                    "2001:db8::1".parse().unwrap(),
                    vec![65001],
                    200,
                ),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![
                make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 2), vec![65002], 100),
                make_multipath_route_v6(
                    prefix6,
                    Ipv4Addr::new(10, 0, 0, 2),
                    "2001:db8::2".parse().unwrap(),
                    vec![65002],
                    100,
                ),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: dual_stack_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![(Afi::Ipv6, Safi::Unicast)],
            add_path_send_max: 5,
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        let v4_routes: Vec<_> = update
            .announce
            .iter()
            .filter(|r| r.prefix == Prefix::V4(prefix4))
            .collect();
        let v6_routes: Vec<_> = update
            .announce
            .iter()
            .filter(|r| r.prefix == Prefix::V6(prefix6))
            .collect();
        assert_eq!(v4_routes.len(), 1, "IPv4 should fall back to single-best");
        assert_eq!(v6_routes.len(), 2, "IPv6 should use multi-path send");
        assert_eq!(v4_routes[0].path_id, 0);
        let mut v6_path_ids: Vec<u32> = v6_routes.iter().map(|r| r.path_id).collect();
        v6_path_ids.sort_unstable();
        assert_eq!(v6_path_ids, vec![1, 2]);
        drain_eor(&mut out_rx).await;

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn route_refresh_partial_negotiation_respects_family_mode() {
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let prefix4 = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 10, 0), 24);
        let prefix6 = Ipv6Prefix::new("2001:db8:10::".parse().unwrap(), 48);

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![
                make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 1), vec![65001], 200),
                make_multipath_route_v6(
                    prefix6,
                    Ipv4Addr::new(10, 0, 0, 1),
                    "2001:db8::1".parse().unwrap(),
                    vec![65001],
                    200,
                ),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![
                make_multipath_route(prefix4, Ipv4Addr::new(10, 0, 0, 2), vec![65002], 100),
                make_multipath_route_v6(
                    prefix6,
                    Ipv4Addr::new(10, 0, 0, 2),
                    "2001:db8::2".parse().unwrap(),
                    vec![65002],
                    100,
                ),
            ],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: dual_stack_sendable(),
            is_ebgp: false,
            route_reflector_client: false,
            add_path_send_families: vec![(Afi::Ipv4, Safi::Unicast)],
            add_path_send_max: 5,
        })
        .await
        .unwrap();
        let _ = out_rx.recv().await.unwrap();
        drain_eor(&mut out_rx).await;

        tx.send(RibUpdate::RouteRefreshRequest {
            peer: target,
            afi: Afi::Ipv4,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
        let update = out_rx.recv().await.unwrap();
        let v4_routes: Vec<_> = update
            .announce
            .iter()
            .filter(|r| r.prefix == Prefix::V4(prefix4))
            .collect();
        assert_eq!(v4_routes.len(), 2, "IPv4 refresh should be multi-path");
        let mut v4_path_ids: Vec<u32> = v4_routes.iter().map(|r| r.path_id).collect();
        v4_path_ids.sort_unstable();
        assert_eq!(v4_path_ids, vec![1, 2]);
        assert_eq!(update.end_of_rib, vec![(Afi::Ipv4, Safi::Unicast)]);

        tx.send(RibUpdate::RouteRefreshRequest {
            peer: target,
            afi: Afi::Ipv6,
            safi: Safi::Unicast,
        })
        .await
        .unwrap();
        let update = out_rx.recv().await.unwrap();
        let v6_routes: Vec<_> = update
            .announce
            .iter()
            .filter(|r| r.prefix == Prefix::V6(prefix6))
            .collect();
        assert_eq!(v6_routes.len(), 1, "IPv6 refresh should be single-best");
        assert_eq!(v6_routes[0].path_id, 0);
        assert_eq!(update.end_of_rib, vec![(Afi::Ipv6, Safi::Unicast)]);

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multipath_send_max_one_uses_path_id_one() {
        // send_max=1 should behave like single-best but with path_id=1 (not 0).
        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, None, None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 1),
                vec![65001],
                200,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 2),
                vec![65002],
                100,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: ipv4_sendable(),
            add_path_send_max: 1,
        })
        .await
        .unwrap();

        let update = out_rx.recv().await.unwrap();
        assert_eq!(update.announce.len(), 1, "send_max=1 sends only one route");
        assert_eq!(
            update.announce[0].path_id, 1,
            "multi-path peer uses path_id=1 not 0"
        );
        assert_eq!(
            update.announce[0].next_hop,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            "should be the best route"
        );

        drop(tx);
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn multipath_all_candidates_denied_by_export_policy() {
        use rustbgpd_policy::{
            Policy, PolicyAction, PolicyChain, PolicyStatement, RouteModifications,
        };

        // Deny all prefixes in 192.168.0.0/16
        let denied_prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 0, 0), 16);
        let export_policy = PolicyChain::new(vec![Policy {
            entries: vec![PolicyStatement {
                prefix: Some(Prefix::V4(denied_prefix)),
                ge: None,
                le: Some(32),
                action: PolicyAction::Deny,
                match_community: vec![],
                match_as_path: None,
                match_rpki_validation: None,
                modifications: RouteModifications::default(),
            }],
            default_action: PolicyAction::Permit,
        }]);

        let (tx, rx) = mpsc::channel(64);
        let manager = RibManager::new(rx, Some(export_policy), None, BgpMetrics::new());
        let handle = tokio::spawn(manager.run());

        let peer1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let peer2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let target = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3));
        let prefix = Ipv4Prefix::new(Ipv4Addr::new(192, 168, 1, 0), 24);

        // Register multi-path target
        let (out_tx, mut out_rx) = mpsc::channel(64);
        tx.send(RibUpdate::PeerUp {
            peer: target,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: ipv4_sendable(),
            is_ebgp: true,
            route_reflector_client: false,
            add_path_send_families: ipv4_sendable(),
            add_path_send_max: 5,
        })
        .await
        .unwrap();
        drain_eor(&mut out_rx).await;

        // Inject 2 routes for the denied prefix
        tx.send(RibUpdate::RoutesReceived {
            peer: peer1,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 1),
                vec![65001],
                200,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();
        tx.send(RibUpdate::RoutesReceived {
            peer: peer2,
            announced: vec![make_multipath_route(
                prefix,
                Ipv4Addr::new(10, 0, 0, 2),
                vec![65002],
                100,
            )],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
        })
        .await
        .unwrap();

        // Force serialization — query to ensure all RoutesReceived processed
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(RibUpdate::QueryBestRoutes { reply: reply_tx })
            .await
            .unwrap();
        let _ = reply_rx.await;

        // No outbound updates should have been sent (all denied)
        assert!(
            out_rx.try_recv().is_err(),
            "all candidates denied by export policy — nothing sent"
        );

        drop(tx);
        handle.await.unwrap();
    }
}
