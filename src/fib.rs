//! Pure ADR-0061 general unicast FIB projection and diff model.
//!
//! This module intentionally keeps policy and ownership decisions separate from
//! Linux netlink I/O. It translates configured `[[fib_tables]]` plus Loc-RIB
//! best routes into desired kernel route intent, then compares that intent with
//! daemon-owned and observed kernel state. The runtime actor consumes the same
//! `FibPlan` shape without deciding ownership or foreign-route policy inline.

#![allow(
    dead_code,
    reason = "ADR-0061 keeps the pure FIB model usable from focused tests and runtime code"
)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use rustbgpd_rib::{FibInstallCandidate, RouteOrigin};
use rustbgpd_wire::Prefix;

use crate::config::FibTableConfig;
use crate::fib_common::{prefix_and_nexthop_same_family, table_allows_prefix};

const MAX_ROUTE_LIMIT_EXCEEDED_DROPS_PER_TABLE: usize = 128;

/// Desired general unicast FIB state derived from config and best routes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FibIntent {
    /// Desired daemon-owned route rows, keyed by table / metric / prefix.
    pub routes: BTreeMap<FibRouteKey, FibRoute>,
    /// Routes suppressed during projection with explicit reasons.
    pub drops: Vec<FibDrop>,
    /// Tables whose candidate count exceeded `max_routes`. New growth and
    /// replacement are suppressed, while eligible already-owned rows may still
    /// be repaired or withdrawn.
    pub frozen_tables: BTreeSet<FibTableKey>,
    /// Route keys still eligible while their table is frozen. Kept separate
    /// from `drops` so operator status payloads can stay bounded.
    pub frozen_eligible_keys: BTreeSet<FibRouteKey>,
}

/// Kernel table / metric identity for a configured FIB table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FibTableKey {
    /// Linux route table id.
    pub table_id: u32,
    /// Kernel route metric / priority.
    pub metric: u32,
}

/// Kernel route identity for ADR-0061-owned routes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct FibRouteKey {
    /// Linux route table id.
    pub table_id: u32,
    /// Kernel route metric / priority.
    pub metric: u32,
    /// Destination prefix.
    pub prefix: Prefix,
}

impl Ord for FibRouteKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.table_id
            .cmp(&other.table_id)
            .then_with(|| self.metric.cmp(&other.metric))
            .then_with(|| cmp_prefix(self.prefix, other.prefix))
    }
}

impl PartialOrd for FibRouteKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl FibRouteKey {
    pub(crate) fn table_key(self) -> FibTableKey {
        FibTableKey {
            table_id: self.table_id,
            metric: self.metric,
        }
    }
}

/// One desired daemon-owned kernel route plus status metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FibRoute {
    /// Operator-facing table name from `[[fib_tables]]`.
    pub table_name: String,
    /// Linux route identity.
    pub key: FibRouteKey,
    /// Kernel forwarding value.
    pub target: FibRouteTarget,
    /// Peer that supplied the Loc-RIB best route.
    pub peer: IpAddr,
    /// How the Loc-RIB best route was learned.
    pub origin_type: RouteOrigin,
    /// Add-Path path identifier from the selected best route.
    pub path_id: u32,
}

/// Kernel forwarding value for a route row.
///
/// Holds one or more equal-cost next-hops. The set is always canonically
/// sorted and deduplicated so that set-equality (used throughout
/// [`compute_fib_diff`]) is independent of input order, and so a single
/// next-hop compares equal whether the kernel reports it as `RTA_GATEWAY`
/// or as a one-element `RTA_MULTIPATH`. Length 1 is exactly today's
/// single-next-hop behavior (emitted as `RTA_GATEWAY`); length >1 is ECMP
/// (emitted as `RTA_MULTIPATH`). Never empty by construction.
///
/// `best` records the selected best route's next-hop (always a member of the
/// set). It is the scalar representative for status / events / owned-state
/// back-compat, so the surfaced `(next_hop, peer, path_id)` stays a consistent
/// tuple even though ECMP siblings can come from different peers. It is
/// **deliberately excluded from equality**: two targets with the same next-hop
/// *set* are the same kernel route regardless of which member was best, so the
/// reconcile diff must not flap when only best-path provenance moves.
#[derive(Debug, Clone)]
pub(crate) struct FibRouteTarget {
    /// Gateway / next-hop entries, sorted ascending by address and deduplicated.
    pub next_hops: Vec<FibNextHop>,
    /// The selected best route's next-hop; the scalar surface representative.
    best: IpAddr,
}

/// One forwarding next-hop in a [`FibRouteTarget`]: the gateway address plus its
/// ADR-0068 multipath weight. The weight is the Linux kernel weight (`1..=256`,
/// encoded as `rtnh_hops = weight - 1`); `1` everywhere means equal cost. Weight
/// is part of equality/ordering so a bandwidth change reprograms the kernel, and
/// it round-trips through `rtnh_hops` so a dumped route diffs stably.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FibNextHop {
    /// Gateway / next-hop address (sort key — ordered before `weight`).
    pub addr: IpAddr,
    /// Kernel multipath weight, `1..=256` (`1` = equal cost).
    pub weight: u16,
}

impl FibNextHop {
    /// An equal-cost (weight-1) next-hop — the ADR-0066 default shape.
    pub(crate) fn equal(addr: IpAddr) -> Self {
        Self { addr, weight: 1 }
    }
}

/// Enforce the canonical weight invariants on a `FibRouteTarget`'s next-hops
/// (ADR-0068), at every constructor, so a target can never *desire* a weight the
/// kernel cannot store — which would diff forever against the dumped route:
///
/// 1. Every weight is clamped to the kernel-representable `1..=256` (`rtnh_hops`
///    is a `u8`, so the kernel holds `weight - 1` in `0..=255`). This guards
///    corrupt/hand-edited persisted state and any future writer; RIB-computed
///    weights are already in range.
/// 2. A lone next-hop is forced to weight 1: it carries all traffic regardless,
///    and the kernel emits it as a weightless `RTA_GATEWAY`, so a dumped single
///    route always reads back weight 1. This keeps the diff stable when a
///    per-table cap (or a lone best) reduces a weighted group to one next-hop.
fn canonicalize_next_hop_weights(next_hops: &mut [FibNextHop]) {
    for nh in next_hops.iter_mut() {
        nh.weight = nh.weight.clamp(1, 256);
    }
    if let [only] = next_hops {
        only.weight = 1;
    }
}

impl PartialEq for FibRouteTarget {
    fn eq(&self, other: &Self) -> bool {
        self.next_hops == other.next_hops
    }
}

impl Eq for FibRouteTarget {}

impl FibRouteTarget {
    /// Single-next-hop target — today's default forwarding shape (weight 1, no
    /// multipath, so the weight is never emitted to the kernel).
    pub(crate) fn single(next_hop: IpAddr) -> Self {
        Self {
            next_hops: vec![FibNextHop::equal(next_hop)],
            best: next_hop,
        }
    }

    /// Build from a known best plus an arbitrary weighted set (e.g. projection or
    /// persisted owned-state). `best` is forced into the set (weight 1) if no
    /// entry carries its address, then the set is canonicalized (sorted by
    /// address, deduped by address keeping the first weight).
    pub(crate) fn from_set_with_best(
        best: IpAddr,
        next_hops: impl IntoIterator<Item = FibNextHop>,
    ) -> Self {
        let mut next_hops: Vec<FibNextHop> = next_hops.into_iter().collect();
        if !next_hops.iter().any(|nh| nh.addr == best) {
            next_hops.push(FibNextHop::equal(best));
        }
        next_hops.sort_unstable();
        next_hops.dedup_by_key(|nh| nh.addr);
        canonicalize_next_hop_weights(&mut next_hops);
        Self { next_hops, best }
    }

    /// Kernel-observed path: a dumped route carries no BGP best-path metadata,
    /// so the lowest-sorted member stands in as the representative. Equality
    /// ignores `best`, so this never affects diffing against owned state.
    /// Callers must ensure the input is non-empty.
    pub(crate) fn from_next_hops(next_hops: impl IntoIterator<Item = FibNextHop>) -> Self {
        let mut next_hops: Vec<FibNextHop> = next_hops.into_iter().collect();
        next_hops.sort_unstable();
        next_hops.dedup_by_key(|nh| nh.addr);
        canonicalize_next_hop_weights(&mut next_hops);
        let best = next_hops[0].addr;
        Self { next_hops, best }
    }

    /// The single representative next-hop for surface paths (per-route status,
    /// events, owned-state scalar back-compat) — the selected best route's
    /// next-hop, consistent with the row's `peer` / `path_id` / `origin_type`.
    pub(crate) fn primary(&self) -> IpAddr {
        self.best
    }
}

/// Daemon-owned route state. Updated only after successful apply ops.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FibOwnedState {
    /// Routes rustbgpd believes it owns.
    pub routes: BTreeMap<FibRouteKey, FibRoute>,
}

/// Observed kernel route snapshot for the Linux FIB actor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FibKernelSnapshot {
    /// Kernel rows matching route identities relevant to this actor.
    pub routes: BTreeMap<FibRouteKey, FibKernelRoute>,
}

/// Observed kernel route value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FibKernelRoute {
    /// Kernel forwarding value.
    pub target: FibRouteTarget,
    /// Kernel route protocol marker.
    pub protocol: FibKernelProtocol,
}

/// Route protocol marker needed for foreign-route preservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FibKernelProtocol {
    /// `RTPROT_BGP`.
    Bgp,
    /// Any non-BGP protocol.
    Other,
}

/// Suppression or conflict reason produced by projection / diff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FibDrop {
    /// The route's next-hop family is not supported for this first tranche.
    NextHopFamilyUnsupported {
        /// Table that would have received the route.
        table_name: String,
        /// Destination prefix.
        prefix: Prefix,
        /// Unsupported next-hop.
        next_hop: IpAddr,
    },
    /// A desired route key already exists in the kernel but is not daemon-owned.
    ForeignRouteExists {
        /// Conflicting key.
        key: FibRouteKey,
    },
    /// A row this daemon previously owned has been changed by an external
    /// writer. The kernel row must be preserved and ownership released.
    OwnedRouteDrifted {
        /// Previously-owned route.
        route: FibRoute,
    },
    /// A route was learned from a peer outside the table allow-list.
    PeerNotAllowed {
        /// Table that rejected the route.
        table_name: String,
        /// Destination prefix.
        prefix: Prefix,
        /// Peer that supplied the route.
        peer: IpAddr,
    },
    /// A table exceeded its configured hard route-count limit.
    RouteLimitExceeded {
        /// Table that rejected the route.
        table_name: String,
        /// Linux route identity that would have been installed.
        key: FibRouteKey,
        /// Next-hop that would have been installed.
        next_hop: IpAddr,
        /// Peer that supplied the route.
        peer: IpAddr,
        /// Configured maximum route count.
        limit: u32,
        /// Number of sampled `route_limit_exceeded` rows surfaced for
        /// this table/reason.
        sampled_rows: u64,
        /// Number of over-cap rows suppressed after the status sample
        /// cap was reached.
        suppressed_rows: u64,
        /// Total over-cap rows for this table/reason before sampling.
        total_rows: u64,
        /// Per-table status sample cap.
        sample_limit: u32,
    },
}

/// Pure route operation plan for the Linux apply actor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct FibPlan {
    /// Ordered route operations.
    pub ops: Vec<FibOp>,
    /// Conflicts or projection drops that suppressed an operation.
    pub drops: Vec<FibDrop>,
}

/// One pure FIB operation. No netlink is performed in this slice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FibOp {
    /// Add a missing daemon-owned route.
    Add(FibRoute),
    /// Refresh owned metadata for an already-owned route whose kernel value is
    /// still correct. `RTPROT_BGP` alone is not ownership proof, so this is
    /// deliberately not used to adopt pre-existing kernel rows after restart.
    Adopt(FibRoute),
    /// Replace an owned route when the kernel still matches the previously
    /// owned value but the desired forwarding value changed.
    Replace {
        /// Previously-owned route identity / metadata.
        previous: FibRoute,
        /// Desired replacement route.
        desired: FibRoute,
    },
    /// Remove a daemon-owned route no longer present in desired state.
    Remove(FibRoute),
    /// Release ownership without touching the kernel because the live row no
    /// longer matches what this daemon installed.
    Forget(FibRouteKey),
}

/// Equal-cost next-hops to install for one candidate in one table: the
/// candidate's best-first set, filtered to next-hops whose advertising peer
/// passes the table allow-list and whose family matches the prefix, capped at
/// `max_paths`. The per-hop peer filter matters for ECMP: equal-cost siblings
/// can come from different peers than the best route, and a disallowed peer
/// must not slip in as a sibling next-hop just because the best route's peer is
/// allowed. Empty means no installable next-hop (drop the row).
fn eligible_next_hops(
    candidate: &FibInstallCandidate,
    prefix: Prefix,
    max_paths: usize,
    peer_allowed: impl Fn(IpAddr) -> bool,
) -> Vec<FibNextHop> {
    candidate
        .next_hops
        .iter()
        .filter(|next_hop| peer_allowed(next_hop.peer))
        .filter(|next_hop| prefix_and_nexthop_same_family(prefix, next_hop.next_hop))
        .map(|next_hop| FibNextHop {
            addr: next_hop.next_hop,
            weight: next_hop.weight,
        })
        .take(max_paths)
        .collect()
}

/// Project configured FIB tables and Loc-RIB install candidates into desired
/// state. Each candidate carries the chosen best route plus its equal-cost
/// next-hop set (see [`rustbgpd_rib::FibInstallCandidate`]); a length-1 set is
/// exactly today's single-next-hop behavior.
#[must_use]
pub(crate) fn project_fib_intent(
    tables: &[FibTableConfig],
    candidates: &[FibInstallCandidate],
) -> FibIntent {
    project_fib_intent_with_peer_groups(tables, candidates, &BTreeMap::new())
}

/// Per-class ECMP width: the eBGP/iBGP override if set, else the table's overall
/// `maximum_paths`, else 1 (today's single-next-hop behavior). The equal-cost
/// group is homogeneous, so the best route's class selects the cap.
fn per_class_max_paths(table: &FibTableConfig, is_ebgp: bool) -> usize {
    if is_ebgp {
        table.maximum_paths_ebgp.or(table.maximum_paths)
    } else {
        table.maximum_paths_ibgp.or(table.maximum_paths)
    }
    .unwrap_or(1)
    .max(1) as usize
}

/// Project configured FIB tables and Loc-RIB install candidates using the
/// current RIB peer-group map for table allow-list checks.
#[must_use]
pub(crate) fn project_fib_intent_with_peer_groups(
    tables: &[FibTableConfig],
    candidates: &[FibInstallCandidate],
    peer_groups: &BTreeMap<IpAddr, String>,
) -> FibIntent {
    let mut intent = FibIntent::default();

    for table in tables {
        let mut table_routes: BTreeMap<FibRouteKey, FibRoute> = BTreeMap::new();
        let mut table_frozen = false;
        let mut route_limit_drops = RouteLimitDropCounters::default();
        let route_limit_drop_start = intent.drops.len();
        let allowed_neighbors = table
            .allowed_neighbors
            .iter()
            .filter_map(|neighbor| neighbor.parse::<IpAddr>().ok())
            .collect::<Vec<_>>();
        for candidate in candidates {
            let route = &candidate.best;
            if !table_allows_prefix(table, route.prefix) {
                continue;
            }
            if !table_allows_peer(table, &allowed_neighbors, route.peer, peer_groups) {
                intent.drops.push(FibDrop::PeerNotAllowed {
                    table_name: table.name.clone(),
                    prefix: route.prefix,
                    peer: route.peer,
                });
                continue;
            }
            // Per-class ECMP width for this candidate (homogeneous group ⇒ the
            // best route's class picks the cap). The RIB already gathered
            // siblings at the widest of these, so this re-caps the best-first set.
            let max_paths = per_class_max_paths(table, route.is_ebgp());
            // Keep only equal-cost next-hops from allowed peers whose family
            // matches the prefix, best-first, capped at the per-class width.
            let eligible = eligible_next_hops(candidate, route.prefix, max_paths, |peer| {
                table_allows_peer(table, &allowed_neighbors, peer, peer_groups)
            });
            // Fail closed if the *selected best route's* own next-hop did not
            // survive the eligibility filters (e.g. an IPv4 prefix advertised
            // with an IPv6 best next-hop). Installing only the surviving
            // siblings would leave the row's `peer` / `path_id` / `origin_type`
            // (all best-route metadata) describing a path we never programmed —
            // and matches today's single-path behavior, which drops a
            // wrong-family best outright.
            if !eligible.iter().any(|nh| nh.addr == route.next_hop) {
                intent.drops.push(FibDrop::NextHopFamilyUnsupported {
                    table_name: table.name.clone(),
                    prefix: route.prefix,
                    next_hop: route.next_hop,
                });
                continue;
            }

            let key = FibRouteKey {
                table_id: table.table_id,
                metric: table.metric,
                prefix: route.prefix,
            };
            if let Some(limit) = table.max_routes {
                let projected_len =
                    table_routes.len() + usize::from(!table_routes.contains_key(&key));
                if table_frozen || projected_len > limit as usize {
                    if !table_frozen {
                        table_frozen = true;
                        intent.frozen_tables.insert(FibTableKey {
                            table_id: table.table_id,
                            metric: table.metric,
                        });
                        for projected in table_routes.values() {
                            intent.frozen_eligible_keys.insert(projected.key);
                            push_route_limit_drop(
                                &mut intent,
                                &table.name,
                                projected,
                                limit,
                                &mut route_limit_drops,
                            );
                        }
                        table_routes.clear();
                    }
                    intent.frozen_eligible_keys.insert(key);
                    push_route_limit_drop_for_route(
                        &mut intent,
                        &table.name,
                        key,
                        route.next_hop,
                        route.peer,
                        limit,
                        &mut route_limit_drops,
                    );
                    continue;
                }
            }
            let projected = FibRoute {
                table_name: table.name.clone(),
                key,
                // Pin `best` to the selected best route's next-hop (guaranteed
                // present by the check above) so the scalar surface stays
                // consistent with the row's best-route metadata.
                target: FibRouteTarget::from_set_with_best(route.next_hop, eligible),
                peer: route.peer,
                origin_type: route.origin_type,
                path_id: route.path_id,
            };
            table_routes.insert(key, projected);
        }
        if table_frozen {
            annotate_route_limit_drops(
                &mut intent.drops[route_limit_drop_start..],
                route_limit_drops.sampled,
                route_limit_drops.total,
            );
            continue;
        }
        intent.routes.extend(table_routes);
    }

    intent
}

fn push_route_limit_drop(
    intent: &mut FibIntent,
    table_name: &str,
    route: &FibRoute,
    limit: u32,
    counters: &mut RouteLimitDropCounters,
) {
    push_route_limit_drop_for_route(
        intent,
        table_name,
        route.key,
        route.target.primary(),
        route.peer,
        limit,
        counters,
    );
}

#[derive(Default)]
struct RouteLimitDropCounters {
    sampled: usize,
    total: usize,
}

fn push_route_limit_drop_for_route(
    intent: &mut FibIntent,
    table_name: &str,
    key: FibRouteKey,
    next_hop: IpAddr,
    peer: IpAddr,
    limit: u32,
    counters: &mut RouteLimitDropCounters,
) {
    counters.total += 1;
    if counters.sampled >= MAX_ROUTE_LIMIT_EXCEEDED_DROPS_PER_TABLE {
        return;
    }
    intent.drops.push(FibDrop::RouteLimitExceeded {
        table_name: table_name.to_string(),
        key,
        next_hop,
        peer,
        limit,
        sampled_rows: 0,
        suppressed_rows: 0,
        total_rows: 0,
        sample_limit: u32::try_from(MAX_ROUTE_LIMIT_EXCEEDED_DROPS_PER_TABLE).unwrap(),
    });
    counters.sampled += 1;
}

fn annotate_route_limit_drops(drops: &mut [FibDrop], sampled_count: usize, total_count: usize) {
    let sampled_rows = u64::try_from(sampled_count).unwrap_or(u64::MAX);
    let total_rows = u64::try_from(total_count).unwrap_or(u64::MAX);
    let suppressed_rows =
        u64::try_from(total_count.saturating_sub(sampled_count)).unwrap_or(u64::MAX);
    for drop in drops {
        if let FibDrop::RouteLimitExceeded {
            sampled_rows: drop_sampled_rows,
            suppressed_rows: drop_suppressed_rows,
            total_rows: drop_total_rows,
            ..
        } = drop
        {
            *drop_sampled_rows = sampled_rows;
            *drop_suppressed_rows = suppressed_rows;
            *drop_total_rows = total_rows;
        }
    }
}

/// Compute the route operations needed to converge owned state to intent.
#[must_use]
pub(crate) fn compute_fib_diff(
    intent: &FibIntent,
    owned: &FibOwnedState,
    kernel: &FibKernelSnapshot,
) -> FibPlan {
    let mut plan = FibPlan {
        ops: Vec::new(),
        drops: intent
            .drops
            .iter()
            .filter(|drop| {
                !matches!(
                    drop,
                    FibDrop::RouteLimitExceeded { key, .. } if owned.routes.contains_key(key)
                )
            })
            .cloned()
            .collect(),
    };

    for (key, owned_route) in &owned.routes {
        if intent.frozen_tables.contains(&key.table_key())
            && intent.frozen_eligible_keys.contains(key)
        {
            match kernel.routes.get(key) {
                Some(route) if route.protocol == FibKernelProtocol::Other => {
                    push_owned_route_drifted(&mut plan, owned_route);
                }
                Some(route) if route.target != owned_route.target => {
                    push_owned_route_drifted(&mut plan, owned_route);
                }
                None => plan.ops.push(FibOp::Add(owned_route.clone())),
                Some(_) => {}
            }
            continue;
        }
        if intent.routes.contains_key(key) {
            continue;
        }
        match kernel.routes.get(key) {
            Some(route) if route.protocol == FibKernelProtocol::Other => {
                push_owned_route_drifted(&mut plan, owned_route);
            }
            Some(route) if route.target != owned_route.target => {
                push_owned_route_drifted(&mut plan, owned_route);
            }
            _ => plan.ops.push(FibOp::Remove(owned_route.clone())),
        }
    }

    for (key, desired) in &intent.routes {
        match (owned.routes.get(key), kernel.routes.get(key)) {
            (None | Some(_), None) if !intent.frozen_tables.contains(&key.table_key()) => {
                plan.ops.push(FibOp::Add(desired.clone()));
            }
            (None | Some(_), None) => {}
            (None, Some(_)) => {
                plan.drops.push(FibDrop::ForeignRouteExists { key: *key });
            }
            (Some(previous), Some(kernel_route))
                if kernel_route.protocol == FibKernelProtocol::Other =>
            {
                push_owned_route_drifted(&mut plan, previous);
            }
            (Some(previous), Some(kernel_route)) if kernel_route.target != previous.target => {
                // Kernel row drifted away from owned state — an external
                // writer changed it. Even when the drifted value happens to
                // match the new desired route, do not adopt it as ours; that
                // would let a later withdraw delete another owner's row.
                push_owned_route_drifted(&mut plan, previous);
            }
            (Some(previous), Some(_)) if previous.target != desired.target => {
                // Kernel still holds the value this daemon owns; the Loc-RIB
                // best route changed, so converge it.
                plan.ops.push(FibOp::Replace {
                    previous: previous.clone(),
                    desired: desired.clone(),
                });
            }
            (Some(owned_route), Some(_)) => {
                // Kernel value already matches desired, but the best
                // route's metadata (peer / origin / path id) may have
                // changed. Refresh owned state with a no-kernel-op
                // metadata refresh so `ListFibRoutes` does not
                // report stale provenance.
                if *owned_route != *desired {
                    plan.ops.push(FibOp::Adopt(desired.clone()));
                }
            }
        }
    }

    plan
}

fn push_owned_route_drifted(plan: &mut FibPlan, route: &FibRoute) {
    plan.drops.push(FibDrop::OwnedRouteDrifted {
        route: route.clone(),
    });
    plan.ops.push(FibOp::Forget(route.key));
}

/// Update owned state after a successful future apply operation.
pub(crate) fn record_fib_success(owned: &mut FibOwnedState, op: &FibOp) {
    match op {
        FibOp::Add(route) | FibOp::Adopt(route) => {
            owned.routes.insert(route.key, route.clone());
        }
        FibOp::Replace { desired, .. } => {
            owned.routes.insert(desired.key, desired.clone());
        }
        FibOp::Remove(route) => {
            owned.routes.remove(&route.key);
        }
        FibOp::Forget(key) => {
            owned.routes.remove(key);
        }
    }
}

fn table_allows_peer(
    table: &FibTableConfig,
    allowed_neighbors: &[IpAddr],
    peer: IpAddr,
    peer_groups: &BTreeMap<IpAddr, String>,
) -> bool {
    if table.allowed_neighbors.is_empty() && table.allowed_peer_groups.is_empty() {
        return true;
    }
    allowed_neighbors.contains(&peer)
        || peer_groups.get(&peer).is_some_and(|group| {
            table
                .allowed_peer_groups
                .iter()
                .any(|allowed| allowed == group)
        })
}

fn cmp_prefix(left: Prefix, right: Prefix) -> Ordering {
    match (left, right) {
        (Prefix::V4(a), Prefix::V4(b)) => a
            .addr
            .octets()
            .cmp(&b.addr.octets())
            .then(a.len.cmp(&b.len)),
        (Prefix::V6(a), Prefix::V6(b)) => a
            .addr
            .octets()
            .cmp(&b.addr.octets())
            .then(a.len.cmp(&b.len)),
        (Prefix::V4(_), Prefix::V6(_)) => Ordering::Less,
        (Prefix::V6(_), Prefix::V4(_)) => Ordering::Greater,
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;
    use std::time::Instant;

    use rustbgpd_rib::{FibInstallNextHop, Route, RouteOrigin};
    use rustbgpd_wire::{
        AsPath, Ipv4Prefix, Ipv6Prefix, Origin, PathAttribute, Prefix, RpkiValidation,
    };

    use super::*;
    use crate::config::FibTableConfig;

    /// Wrap a single best route as a one-next-hop install candidate (the
    /// shape the RIB returns when `maximum_paths` is unset / 1).
    fn candidate(route: Route) -> FibInstallCandidate {
        FibInstallCandidate {
            next_hops: vec![FibInstallNextHop {
                next_hop: route.next_hop,
                link_local_next_hop: route.link_local_next_hop,
                peer: route.peer,
                path_id: route.path_id,
                weight: 1,
            }],
            best: route,
        }
    }

    /// Wrap a slice of best routes as single-next-hop install candidates.
    fn candidates(routes: Vec<Route>) -> Vec<FibInstallCandidate> {
        routes.into_iter().map(candidate).collect()
    }

    /// Build a multi-next-hop install candidate: `best` keeps its own
    /// next-hop, and `extra` next-hops are appended as equal-cost siblings
    /// (best-first ordering, matching the RIB contract).
    fn multipath_candidate(best: Route, extra: &[&str]) -> FibInstallCandidate {
        let mut next_hops = vec![FibInstallNextHop {
            next_hop: best.next_hop,
            link_local_next_hop: best.link_local_next_hop,
            peer: best.peer,
            path_id: best.path_id,
            weight: 1,
        }];
        for (idx, nh) in extra.iter().enumerate() {
            next_hops.push(FibInstallNextHop {
                next_hop: ip(nh),
                link_local_next_hop: None,
                peer: ip("198.51.100.2"),
                path_id: u32::try_from(idx).unwrap() + 1,
                weight: 1,
            });
        }
        FibInstallCandidate { next_hops, best }
    }

    /// Like [`multipath_candidate`] but with explicit per-next-hop weights:
    /// `best_weight` for the best route and `(addr, weight)` for each sibling
    /// (mirrors what the RIB produces under `link_bandwidth_weighted`).
    fn weighted_multipath_candidate(
        best: Route,
        best_weight: u16,
        extra: &[(&str, u16)],
    ) -> FibInstallCandidate {
        let mut next_hops = vec![FibInstallNextHop {
            next_hop: best.next_hop,
            link_local_next_hop: best.link_local_next_hop,
            peer: best.peer,
            path_id: best.path_id,
            weight: best_weight,
        }];
        for (idx, (nh, weight)) in extra.iter().enumerate() {
            next_hops.push(FibInstallNextHop {
                next_hop: ip(nh),
                link_local_next_hop: None,
                peer: ip("198.51.100.2"),
                path_id: u32::try_from(idx).unwrap() + 1,
                weight: *weight,
            });
        }
        FibInstallCandidate { next_hops, best }
    }

    fn table(name: &str, table_id: u32, metric: u32, families: &[&str]) -> FibTableConfig {
        FibTableConfig {
            name: name.to_string(),
            table_id,
            metric,
            families: families
                .iter()
                .map(|family| (*family).to_string())
                .collect(),
            allowed_peer_groups: Vec::new(),
            allowed_neighbors: Vec::new(),
            max_routes: None,
            maximum_paths: None,
            maximum_paths_ebgp: None,
            maximum_paths_ibgp: None,
        }
    }

    fn v4_prefix(octet: u8, len: u8) -> Prefix {
        Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, octet, 0), len))
    }

    fn v6_prefix(segment: u16, len: u8) -> Prefix {
        Prefix::V6(Ipv6Prefix::new(
            Ipv6Addr::new(0x2001, 0x0db8, segment, 0, 0, 0, 0, 0),
            len,
        ))
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// Equal-cost (weight-1) next-hop from a string address — the common test shape.
    fn eq(s: &str) -> FibNextHop {
        FibNextHop::equal(ip(s))
    }

    /// Build a canonical target from equal-cost string addresses (test convenience).
    fn target_from_addrs<const N: usize>(addrs: [&str; N]) -> FibRouteTarget {
        FibRouteTarget::from_next_hops(addrs.into_iter().map(eq))
    }

    /// The next-hop addresses of a target, in canonical order (drops weights).
    fn addrs(target: &FibRouteTarget) -> Vec<IpAddr> {
        target.next_hops.iter().map(|nh| nh.addr).collect()
    }

    /// The (address, weight) pairs of a target, in canonical order.
    fn addr_weights(target: &FibRouteTarget) -> Vec<(IpAddr, u16)> {
        target
            .next_hops
            .iter()
            .map(|nh| (nh.addr, nh.weight))
            .collect()
    }

    fn route(prefix: Prefix, next_hop: IpAddr, origin_type: RouteOrigin, path_id: u32) -> Route {
        route_from_peer(prefix, next_hop, origin_type, path_id, ip("198.51.100.1"))
    }

    fn route_from_peer(
        prefix: Prefix,
        next_hop: IpAddr,
        origin_type: RouteOrigin,
        path_id: u32,
        peer: IpAddr,
    ) -> Route {
        Route {
            prefix,
            next_hop,
            link_local_next_hop: None,
            peer,
            attributes: Arc::new(vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(AsPath { segments: vec![] }),
            ]),
            received_at: Instant::now(),
            origin_type,
            peer_router_id: Ipv4Addr::new(192, 0, 2, 1),
            is_stale: false,
            is_llgr_stale: false,
            path_id,
            validation_state: RpkiValidation::NotFound,
            aspa_state: rustbgpd_wire::AspaValidation::Unknown,
        }
    }

    fn one_route(key: FibRouteKey, next_hop: &str) -> FibRoute {
        FibRoute {
            table_name: "edge".to_string(),
            key,
            target: FibRouteTarget::single(ip(next_hop)),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        }
    }

    fn key(prefix: Prefix) -> FibRouteKey {
        FibRouteKey {
            table_id: 1000,
            metric: 200,
            prefix,
        }
    }

    fn kernel(next_hop: &str, protocol: FibKernelProtocol) -> FibKernelRoute {
        FibKernelRoute {
            target: FibRouteTarget::single(ip(next_hop)),
            protocol,
        }
    }

    #[test]
    fn empty_tables_produce_empty_intent() {
        let routes = vec![route(
            v4_prefix(2, 24),
            ip("203.0.113.1"),
            RouteOrigin::Ebgp,
            0,
        )];

        let intent = project_fib_intent(&[], &candidates(routes));

        assert!(intent.routes.is_empty());
        assert!(intent.drops.is_empty());
    }

    #[test]
    fn projects_ipv4_and_ipv6_when_default_families_are_present() {
        let tables = vec![table("edge", 1000, 200, &["ipv4_unicast", "ipv6_unicast"])];
        let routes = vec![
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 11),
            route(
                v6_prefix(1, 48),
                ip("2001:db8:ffff::1"),
                RouteOrigin::Ibgp,
                12,
            ),
        ];

        let intent = project_fib_intent(&tables, &candidates(routes));

        assert_eq!(intent.routes.len(), 2);
        assert!(intent.drops.is_empty());
        assert!(
            intent
                .routes
                .values()
                .any(|route| route.origin_type == RouteOrigin::Ibgp && route.path_id == 12)
        );
    }

    #[test]
    fn table_family_filter_suppresses_other_family_without_drop() {
        let tables = vec![table("v4-only", 1000, 200, &["ipv4_unicast"])];
        let routes = vec![
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            route(
                v6_prefix(1, 48),
                ip("2001:db8:ffff::1"),
                RouteOrigin::Ebgp,
                0,
            ),
        ];

        let intent = project_fib_intent(&tables, &candidates(routes));

        assert_eq!(intent.routes.len(), 1);
        assert!(matches!(
            intent.routes.keys().next().unwrap().prefix,
            Prefix::V4(_)
        ));
        assert!(intent.drops.is_empty());
    }

    #[test]
    fn multiple_matching_tables_fan_out_same_best_route() {
        let tables = vec![
            table("edge-a", 1000, 200, &["ipv4_unicast"]),
            table("edge-b", 1001, 300, &["ipv4_unicast"]),
        ];
        let routes = vec![route(
            v4_prefix(2, 24),
            ip("203.0.113.1"),
            RouteOrigin::Local,
            7,
        )];

        let intent = project_fib_intent(&tables, &candidates(routes));

        assert_eq!(intent.routes.len(), 2);
        assert!(
            intent
                .routes
                .keys()
                .any(|key| key.table_id == 1000 && key.metric == 200)
        );
        assert!(
            intent
                .routes
                .keys()
                .any(|key| key.table_id == 1001 && key.metric == 300)
        );
        assert!(
            intent
                .routes
                .values()
                .all(|route| route.origin_type == RouteOrigin::Local)
        );
    }

    #[test]
    fn prefix_next_hop_family_mismatch_is_dropped() {
        let tables = vec![table("edge", 1000, 200, &["ipv4_unicast"])];
        let routes = vec![route(
            v4_prefix(2, 24),
            ip("2001:db8::1"),
            RouteOrigin::Ebgp,
            0,
        )];

        let intent = project_fib_intent(&tables, &candidates(routes));

        assert!(intent.routes.is_empty());
        assert!(matches!(
            intent.drops.as_slice(),
            [FibDrop::NextHopFamilyUnsupported { table_name, .. }] if table_name == "edge"
        ));
    }

    #[test]
    fn neighbor_allow_list_filters_fib_candidates() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.allowed_neighbors = vec!["198.51.100.2".to_string()];
        let routes = vec![
            route_from_peer(
                v4_prefix(2, 24),
                ip("203.0.113.1"),
                RouteOrigin::Ebgp,
                0,
                ip("198.51.100.1"),
            ),
            route_from_peer(
                v4_prefix(3, 24),
                ip("203.0.113.2"),
                RouteOrigin::Ebgp,
                0,
                ip("198.51.100.2"),
            ),
        ];

        let intent = project_fib_intent(&[table], &candidates(routes));

        assert_eq!(intent.routes.len(), 1);
        assert!(
            intent
                .routes
                .keys()
                .any(|key| key.prefix == v4_prefix(3, 24))
        );
        assert!(matches!(
            intent.drops.as_slice(),
            [FibDrop::PeerNotAllowed { peer, .. }] if *peer == ip("198.51.100.1")
        ));
    }

    #[test]
    fn peer_group_allow_list_uses_current_rib_peer_group_map() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.allowed_peer_groups = vec!["transit".to_string()];
        let routes = vec![
            route_from_peer(
                v4_prefix(2, 24),
                ip("203.0.113.1"),
                RouteOrigin::Ebgp,
                0,
                ip("198.51.100.1"),
            ),
            route_from_peer(
                v4_prefix(3, 24),
                ip("203.0.113.2"),
                RouteOrigin::Ebgp,
                0,
                ip("198.51.100.2"),
            ),
        ];
        let peer_groups = BTreeMap::from([
            (ip("198.51.100.1"), "ix".to_string()),
            (ip("198.51.100.2"), "transit".to_string()),
        ]);

        let intent =
            project_fib_intent_with_peer_groups(&[table], &candidates(routes), &peer_groups);

        assert_eq!(intent.routes.len(), 1);
        assert!(
            intent
                .routes
                .keys()
                .any(|key| key.prefix == v4_prefix(3, 24))
        );
        assert!(matches!(
            intent.drops.as_slice(),
            [FibDrop::PeerNotAllowed { peer, .. }] if *peer == ip("198.51.100.1")
        ));
    }

    #[test]
    fn route_count_limit_is_fail_closed_per_table() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.max_routes = Some(1);
        let routes = vec![
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            route(v4_prefix(3, 24), ip("203.0.113.2"), RouteOrigin::Ebgp, 0),
        ];

        let intent = project_fib_intent(&[table], &candidates(routes));

        assert!(intent.routes.is_empty());
        assert_eq!(intent.drops.len(), 2);
        assert!(intent.drops.iter().all(|drop| matches!(
            drop,
            FibDrop::RouteLimitExceeded {
                table_name,
                limit: 1,
                ..
            } if table_name == "edge"
        )));
    }

    #[test]
    fn route_count_limit_caps_status_drops_but_keeps_eligible_keys() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.max_routes = Some(1);
        let routes = (0..150)
            .map(|octet| {
                route(
                    v4_prefix(octet, 24),
                    ip("203.0.113.1"),
                    RouteOrigin::Ebgp,
                    0,
                )
            })
            .collect::<Vec<_>>();

        let intent = project_fib_intent(&[table], &candidates(routes));

        assert!(intent.routes.is_empty());
        assert!(intent.frozen_tables.contains(&FibTableKey {
            table_id: 1000,
            metric: 200,
        }));
        assert_eq!(intent.frozen_eligible_keys.len(), 150);
        assert_eq!(
            intent
                .drops
                .iter()
                .filter(|drop| matches!(drop, FibDrop::RouteLimitExceeded { .. }))
                .count(),
            MAX_ROUTE_LIMIT_EXCEEDED_DROPS_PER_TABLE
        );
        let FibDrop::RouteLimitExceeded {
            limit,
            sampled_rows,
            suppressed_rows,
            total_rows,
            sample_limit,
            ..
        } = &intent.drops[0]
        else {
            panic!("first drop should carry route-limit sampling metadata");
        };
        assert_eq!(*limit, 1);
        assert_eq!(
            *sampled_rows,
            u64::try_from(MAX_ROUTE_LIMIT_EXCEEDED_DROPS_PER_TABLE).unwrap()
        );
        assert_eq!(*suppressed_rows, 22);
        assert_eq!(*total_rows, 150);
        assert_eq!(
            *sample_limit,
            u32::try_from(MAX_ROUTE_LIMIT_EXCEEDED_DROPS_PER_TABLE).unwrap()
        );
    }

    #[test]
    fn route_count_limit_freezes_existing_owned_rows() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.max_routes = Some(1);
        let existing = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let routes = vec![
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            route(v4_prefix(3, 24), ip("203.0.113.2"), RouteOrigin::Ebgp, 0),
        ];
        let intent = project_fib_intent(&[table], &candidates(routes));
        let owned = FibOwnedState {
            routes: BTreeMap::from([(existing.key, existing.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(existing.key, kernel("203.0.113.1", FibKernelProtocol::Bgp))]),
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert!(plan.ops.is_empty());
        assert_eq!(plan.drops.len(), 1);
        assert!(matches!(
            plan.drops.as_slice(),
            [FibDrop::RouteLimitExceeded { key: dropped_key, .. }]
                if *dropped_key == key(v4_prefix(3, 24))
        ));
    }

    #[test]
    fn route_count_limit_still_withdraws_owned_rows_that_left_the_rib() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.max_routes = Some(1);
        let withdrawn = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let routes = vec![
            route(v4_prefix(3, 24), ip("203.0.113.2"), RouteOrigin::Ebgp, 0),
            route(v4_prefix(4, 24), ip("203.0.113.3"), RouteOrigin::Ebgp, 0),
        ];
        let intent = project_fib_intent(&[table], &candidates(routes));
        let owned = FibOwnedState {
            routes: BTreeMap::from([(withdrawn.key, withdrawn.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(
                withdrawn.key,
                kernel("203.0.113.1", FibKernelProtocol::Bgp),
            )]),
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Remove(withdrawn)]);
        assert_eq!(plan.drops.len(), 2);
        assert!(plan.drops.iter().all(|drop| matches!(
            drop,
            FibDrop::RouteLimitExceeded {
                table_name,
                limit: 1,
                ..
            } if table_name == "edge"
        )));
    }

    #[test]
    fn route_count_limit_still_detects_drifted_owned_rows() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.max_routes = Some(1);
        let existing = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let routes = vec![
            route(v4_prefix(2, 24), ip("203.0.113.9"), RouteOrigin::Ebgp, 0),
            route(v4_prefix(3, 24), ip("203.0.113.2"), RouteOrigin::Ebgp, 0),
        ];
        let intent = project_fib_intent(&[table], &candidates(routes));
        let owned = FibOwnedState {
            routes: BTreeMap::from([(existing.key, existing.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(existing.key, kernel("203.0.113.8", FibKernelProtocol::Bgp))]),
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Forget(existing.key)]);
        assert!(plan.drops.iter().any(
            |drop| matches!(drop, FibDrop::OwnedRouteDrifted { route } if route.key == existing.key)
        ));
        assert!(plan
            .drops
            .iter()
            .any(|drop| matches!(drop, FibDrop::RouteLimitExceeded { key: dropped_key, .. } if *dropped_key == key(v4_prefix(3, 24)))));
    }

    #[test]
    fn route_count_limit_restores_missing_owned_rows() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.max_routes = Some(1);
        let existing = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let routes = vec![
            route(v4_prefix(2, 24), ip("203.0.113.9"), RouteOrigin::Ebgp, 0),
            route(v4_prefix(3, 24), ip("203.0.113.2"), RouteOrigin::Ebgp, 0),
        ];
        let intent = project_fib_intent(&[table], &candidates(routes));
        let owned = FibOwnedState {
            routes: BTreeMap::from([(existing.key, existing.clone())]),
        };

        let plan = compute_fib_diff(&intent, &owned, &FibKernelSnapshot::default());

        assert_eq!(plan.ops, vec![FibOp::Add(existing)]);
        assert!(plan
            .drops
            .iter()
            .any(|drop| matches!(drop, FibDrop::RouteLimitExceeded { key: dropped_key, .. } if *dropped_key == key(v4_prefix(3, 24)))));
    }

    #[test]
    fn route_count_at_limit_installs_candidates() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.max_routes = Some(2);
        let routes = vec![
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            route(v4_prefix(3, 24), ip("203.0.113.2"), RouteOrigin::Ebgp, 0),
        ];

        let intent = project_fib_intent(&[table], &candidates(routes));

        assert_eq!(intent.routes.len(), 2);
        assert!(intent.drops.is_empty());
    }

    #[test]
    fn desired_absent_from_owned_and_kernel_emits_add() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let intent = FibIntent {
            routes: BTreeMap::from([(route.key, route.clone())]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(
            &intent,
            &FibOwnedState::default(),
            &FibKernelSnapshot::default(),
        );

        assert_eq!(plan.ops, vec![FibOp::Add(route)]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn desired_owned_with_same_kernel_value_is_noop() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(route.key, kernel("203.0.113.1", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(route.key, route)]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert!(plan.ops.is_empty());
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn desired_owned_with_same_value_but_changed_provenance_emits_adopt() {
        let key = key(v4_prefix(2, 24));
        let owned_route = one_route(key, "203.0.113.1");
        let mut desired = owned_route.clone();
        desired.peer = ip("198.51.100.9");
        desired.origin_type = RouteOrigin::Ibgp;
        desired.path_id = 7;
        let owned = FibOwnedState {
            routes: BTreeMap::from([(key, owned_route)]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(key, kernel("203.0.113.1", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(key, desired.clone())]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Adopt(desired)]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn desired_owned_with_changed_kernel_value_emits_replace() {
        let previous = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let desired = one_route(previous.key, "203.0.113.2");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(previous.key, previous.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(previous.key, kernel("203.0.113.1", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(desired.key, desired.clone())]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Replace { previous, desired }]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn replace_is_withheld_when_kernel_drifted_away_from_owned_value() {
        // Owned T0, kernel externally drifted to a third value, and the
        // Loc-RIB best route also moved. The kernel row no longer matches
        // what this daemon owns, so it must be reported as a conflict
        // rather than overwritten.
        let key = key(v4_prefix(2, 24));
        let previous = one_route(key, "203.0.113.1");
        let desired = one_route(key, "203.0.113.2");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(key, previous.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(key, kernel("203.0.113.9", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(key, desired)]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Forget(previous.key)]);
        assert_eq!(
            plan.drops,
            vec![FibDrop::OwnedRouteDrifted { route: previous }]
        );
    }

    #[test]
    fn adopt_is_withheld_when_kernel_drift_matches_new_desired_value() {
        // Owned T0, kernel externally drifted to T1, and the Loc-RIB best
        // route also moved to T1. Even though no kernel update is needed,
        // the row no longer matches what this daemon owns and must not be
        // adopted as daemon-owned metadata.
        let key = key(v4_prefix(2, 24));
        let previous = one_route(key, "203.0.113.1");
        let desired = one_route(key, "203.0.113.2");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(key, previous.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(key, kernel("203.0.113.2", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(key, desired)]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Forget(previous.key)]);
        assert_eq!(
            plan.drops,
            vec![FibDrop::OwnedRouteDrifted { route: previous }]
        );
    }

    #[test]
    fn owned_route_missing_from_desired_emits_remove() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(route.key, kernel("203.0.113.1", FibKernelProtocol::Bgp))]),
        };

        let plan = compute_fib_diff(&FibIntent::default(), &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Remove(route)]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn owned_route_missing_from_desired_with_drifted_kernel_value_releases_ownership() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(route.key, kernel("203.0.113.9", FibKernelProtocol::Bgp))]),
        };

        let plan = compute_fib_diff(&FibIntent::default(), &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Forget(route.key)]);
        assert_eq!(plan.drops, vec![FibDrop::OwnedRouteDrifted { route }]);
    }

    #[test]
    fn owned_route_changed_to_non_bgp_protocol_releases_ownership() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(route.key, kernel("203.0.113.1", FibKernelProtocol::Other))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(route.key, route.clone())]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Forget(route.key)]);
        assert_eq!(plan.drops, vec![FibDrop::OwnedRouteDrifted { route }]);
    }

    #[test]
    fn foreign_kernel_route_at_desired_key_blocks_add() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(route.key, kernel("203.0.113.9", FibKernelProtocol::Other))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(route.key, route.clone())]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &FibOwnedState::default(), &kernel);

        assert!(plan.ops.is_empty());
        assert_eq!(
            plan.drops,
            vec![FibDrop::ForeignRouteExists { key: route.key }]
        );
    }

    #[test]
    fn preexisting_bgp_kernel_route_with_same_value_is_foreign_without_owned_state() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(route.key, kernel("203.0.113.1", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(route.key, route.clone())]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &FibOwnedState::default(), &kernel);

        assert!(plan.ops.is_empty());
        assert_eq!(
            plan.drops,
            vec![FibDrop::ForeignRouteExists { key: route.key }]
        );
    }

    #[test]
    fn preexisting_bgp_kernel_route_with_wrong_value_is_foreign_without_owned_state() {
        let desired = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(desired.key, kernel("203.0.113.9", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(desired.key, desired.clone())]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &FibOwnedState::default(), &kernel);

        assert!(plan.ops.is_empty());
        assert_eq!(
            plan.drops,
            vec![FibDrop::ForeignRouteExists { key: desired.key }]
        );
    }

    #[test]
    fn foreign_kernel_route_not_owned_and_not_desired_is_ignored() {
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(
                key(v4_prefix(2, 24)),
                kernel("203.0.113.9", FibKernelProtocol::Other),
            )]),
        };

        let plan = compute_fib_diff(&FibIntent::default(), &FibOwnedState::default(), &kernel);

        assert!(plan.ops.is_empty());
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn owned_route_missing_from_kernel_readds_from_desired() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let owned = FibOwnedState {
            routes: BTreeMap::from([(route.key, route.clone())]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(route.key, route.clone())]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &owned, &FibKernelSnapshot::default());

        assert_eq!(plan.ops, vec![FibOp::Add(route)]);
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn record_success_updates_owned_state() {
        let route = one_route(key(v4_prefix(2, 24)), "203.0.113.1");
        let replacement = one_route(route.key, "203.0.113.2");
        let mut owned = FibOwnedState::default();

        record_fib_success(&mut owned, &FibOp::Add(route.clone()));
        assert_eq!(owned.routes.get(&route.key), Some(&route));

        record_fib_success(&mut owned, &FibOp::Adopt(route.clone()));
        assert_eq!(owned.routes.get(&route.key), Some(&route));

        record_fib_success(
            &mut owned,
            &FibOp::Replace {
                previous: route.clone(),
                desired: replacement.clone(),
            },
        );
        assert_eq!(owned.routes.get(&route.key), Some(&replacement));

        record_fib_success(&mut owned, &FibOp::Remove(replacement.clone()));
        assert!(owned.routes.is_empty());

        record_fib_success(&mut owned, &FibOp::Add(route.clone()));
        assert_eq!(owned.routes.get(&route.key), Some(&route));
        record_fib_success(&mut owned, &FibOp::Forget(route.key));
        assert!(owned.routes.is_empty());
    }

    #[test]
    fn target_from_next_hops_is_sorted_deduped_and_order_independent() {
        let target =
            target_from_addrs(["203.0.113.3", "203.0.113.1", "203.0.113.3", "203.0.113.2"]);
        assert_eq!(
            addrs(&target),
            vec![ip("203.0.113.1"), ip("203.0.113.2"), ip("203.0.113.3")]
        );
        // Canonical form is independent of input order.
        let reordered = target_from_addrs(["203.0.113.2", "203.0.113.3", "203.0.113.1"]);
        assert_eq!(target, reordered);
        assert_eq!(target.primary(), ip("203.0.113.1"));
    }

    #[test]
    fn ecmp_candidate_projects_multipath_target_when_enabled() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths = Some(2);
        let candidate = multipath_candidate(
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            &["203.0.113.2"],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        assert_eq!(intent.routes.len(), 1);
        let projected = intent.routes.values().next().unwrap();
        assert_eq!(
            addrs(&projected.target),
            vec![ip("203.0.113.1"), ip("203.0.113.2")]
        );
    }

    #[test]
    fn weighted_multipath_projects_per_next_hop_weights() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths = Some(2);
        // Best .1 weight 256, sibling .2 weight 64 (a 4:1 bandwidth ratio).
        let candidate = weighted_multipath_candidate(
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            256,
            &[("203.0.113.2", 64)],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        let projected = intent.routes.values().next().unwrap();
        // Canonical order is by address; weights ride along.
        assert_eq!(
            addr_weights(&projected.target),
            vec![(ip("203.0.113.1"), 256), (ip("203.0.113.2"), 64)]
        );
    }

    #[test]
    fn weighted_group_capped_to_one_normalizes_weight() {
        // A weighted two-path group, but the table only allows one path. The lone
        // survivor's weight must collapse to 1 — a single next-hop carries all
        // traffic and the kernel emits it weightless, so any other value would
        // diff forever against the dumped route.
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths = Some(1);
        let candidate = weighted_multipath_candidate(
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            256,
            &[("203.0.113.2", 64)],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        let projected = intent.routes.values().next().unwrap();
        assert_eq!(
            addr_weights(&projected.target),
            vec![(ip("203.0.113.1"), 1)]
        );
    }

    #[test]
    fn weight_change_breaks_target_equality_so_reconcile_reprograms() {
        // Same next-hop set, different weights ⇒ not equal, so the reconcile diff
        // emits a Replace and the kernel picks up the new distribution.
        let a = FibRouteTarget::from_next_hops([
            FibNextHop {
                addr: ip("203.0.113.1"),
                weight: 256,
            },
            FibNextHop {
                addr: ip("203.0.113.2"),
                weight: 64,
            },
        ]);
        let b = FibRouteTarget::from_next_hops([
            FibNextHop {
                addr: ip("203.0.113.1"),
                weight: 128,
            },
            FibNextHop {
                addr: ip("203.0.113.2"),
                weight: 128,
            },
        ]);
        assert_ne!(a, b);
        // Identical weights ⇒ equal, no spurious reprogram.
        let c = FibRouteTarget::from_next_hops([
            FibNextHop {
                addr: ip("203.0.113.2"),
                weight: 64,
            },
            FibNextHop {
                addr: ip("203.0.113.1"),
                weight: 256,
            },
        ]);
        assert_eq!(a, c);
    }

    #[test]
    fn target_clamps_weights_to_kernel_range() {
        // A corrupt/out-of-range weight (e.g. a hand-edited owned-state file) is
        // clamped into 1..=256 so the target never desires a weight the kernel's
        // u8 rtnh_hops cannot store — which would otherwise diff forever.
        let t = FibRouteTarget::from_next_hops([
            FibNextHop {
                addr: ip("203.0.113.1"),
                weight: 5000,
            },
            FibNextHop {
                addr: ip("203.0.113.2"),
                weight: 0,
            },
        ]);
        assert_eq!(
            addr_weights(&t),
            vec![(ip("203.0.113.1"), 256), (ip("203.0.113.2"), 1)]
        );
    }

    #[test]
    fn projected_primary_is_best_route_next_hop_not_lowest() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths = Some(2);
        // The best route's next-hop (.5) sorts after the sibling (.1). The
        // canonical set is ascending, but the scalar representative must remain
        // the best route's next-hop so it stays consistent with the row's
        // peer / path_id / origin_type.
        let candidate = multipath_candidate(
            route(v4_prefix(2, 24), ip("203.0.113.5"), RouteOrigin::Ebgp, 0),
            &["203.0.113.1"],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        let projected = intent.routes.values().next().unwrap();
        assert_eq!(
            addrs(&projected.target),
            vec![ip("203.0.113.1"), ip("203.0.113.5")]
        );
        assert_eq!(projected.target.primary(), ip("203.0.113.5"));
    }

    #[test]
    fn maximum_paths_caps_next_hop_set_best_first() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths = Some(2);
        // best .5, siblings .1 then .9 (best-first). Cap 2 keeps best + first
        // sibling (.5, .1); .9 is dropped. Canonical sort orders them ascending.
        let candidate = multipath_candidate(
            route(v4_prefix(2, 24), ip("203.0.113.5"), RouteOrigin::Ebgp, 0),
            &["203.0.113.1", "203.0.113.9"],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        let projected = intent.routes.values().next().unwrap();
        assert_eq!(
            addrs(&projected.target),
            vec![ip("203.0.113.1"), ip("203.0.113.5")]
        );
    }

    #[test]
    fn default_maximum_paths_keeps_single_best_next_hop() {
        // `maximum_paths` unset == today: even with equal-cost siblings present,
        // only the best next-hop is programmed (single-gateway shape).
        let table = table("edge", 1000, 200, &["ipv4_unicast"]);
        let candidate = multipath_candidate(
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            &["203.0.113.2", "203.0.113.3"],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        let projected = intent.routes.values().next().unwrap();
        assert_eq!(addrs(&projected.target), vec![ip("203.0.113.1")]);
    }

    #[test]
    fn maximum_paths_ebgp_caps_ebgp_group() {
        // Per-class eBGP cap applies even with no overall `maximum_paths`.
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths_ebgp = Some(2);
        let candidate = multipath_candidate(
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            &["203.0.113.2", "203.0.113.3"],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        let projected = intent.routes.values().next().unwrap();
        assert_eq!(
            projected.target.next_hops.len(),
            2,
            "eBGP group capped at maximum_paths_ebgp"
        );
    }

    #[test]
    fn maximum_paths_ibgp_caps_ibgp_group() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths_ibgp = Some(3);
        let candidate = multipath_candidate(
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ibgp, 0),
            &["203.0.113.2", "203.0.113.3", "203.0.113.4"],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        let projected = intent.routes.values().next().unwrap();
        assert_eq!(
            projected.target.next_hops.len(),
            3,
            "iBGP group capped at maximum_paths_ibgp"
        );
    }

    #[test]
    fn per_class_overrides_with_maximum_paths_fallback() {
        // `maximum_paths` is the shared fallback; the eBGP override wins for the
        // eBGP group, while the iBGP group (no override) falls back to it.
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths = Some(3);
        table.maximum_paths_ebgp = Some(2);
        let ebgp = multipath_candidate(
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            &["203.0.113.2", "203.0.113.3"],
        );
        let ibgp = multipath_candidate(
            route(v4_prefix(3, 24), ip("203.0.114.1"), RouteOrigin::Ibgp, 0),
            &["203.0.114.2", "203.0.114.3", "203.0.114.4"],
        );

        let intent = project_fib_intent(&[table], &[ebgp, ibgp]);

        let mut lens: Vec<usize> = intent
            .routes
            .values()
            .map(|r| r.target.next_hops.len())
            .collect();
        lens.sort_unstable();
        // eBGP capped at 2 (override), iBGP at 3 (fallback to maximum_paths).
        assert_eq!(lens, vec![2, 3]);
    }

    #[test]
    fn family_filter_keeps_only_matching_family_next_hops() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths = Some(4);
        // v4 prefix with a v4 best and a v6 sibling: only the v4 hop survives,
        // and the row is still installed (no drop).
        let candidate = multipath_candidate(
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            &["2001:db8::1"],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        assert_eq!(intent.routes.len(), 1);
        let projected = intent.routes.values().next().unwrap();
        assert_eq!(addrs(&projected.target), vec![ip("203.0.113.1")]);
        assert!(intent.drops.is_empty());
    }

    #[test]
    fn all_wrong_family_next_hops_drops_the_row() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths = Some(4);
        let candidate = multipath_candidate(
            route(v4_prefix(2, 24), ip("2001:db8::1"), RouteOrigin::Ebgp, 0),
            &[],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        assert!(intent.routes.is_empty());
        assert!(matches!(
            intent.drops.as_slice(),
            [FibDrop::NextHopFamilyUnsupported { .. }]
        ));
    }

    #[test]
    fn ecmp_excludes_sibling_next_hops_from_disallowed_peers() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths = Some(4);
        // Only the best route's peer is allowed. The equal-cost sibling comes
        // from a different (disallowed) peer and must not slip in as an ECMP
        // next-hop just because the best route's peer passed the allow-list.
        table.allowed_neighbors = vec!["198.51.100.1".to_string()];
        let candidate = multipath_candidate(
            route(v4_prefix(2, 24), ip("203.0.113.1"), RouteOrigin::Ebgp, 0),
            &["203.0.113.2"],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        assert_eq!(intent.routes.len(), 1);
        let projected = intent.routes.values().next().unwrap();
        assert_eq!(addrs(&projected.target), vec![ip("203.0.113.1")]);
        assert!(intent.drops.is_empty());
    }

    #[test]
    fn row_dropped_when_best_next_hop_filtered_even_if_sibling_survives() {
        let mut table = table("edge", 1000, 200, &["ipv4_unicast"]);
        table.maximum_paths = Some(4);
        // The selected best route's next-hop is the wrong family for the v4
        // prefix; a sibling is a valid v4 next-hop. Because the *best* path
        // can't be installed, the whole row is dropped (fail-closed) rather
        // than installing the sibling under best-route metadata that would then
        // describe an unprogrammed path.
        let candidate = multipath_candidate(
            route(v4_prefix(2, 24), ip("2001:db8::1"), RouteOrigin::Ebgp, 0),
            &["203.0.113.1"],
        );

        let intent = project_fib_intent(&[table], &[candidate]);

        assert!(intent.routes.is_empty());
        assert!(matches!(
            intent.drops.as_slice(),
            [FibDrop::NextHopFamilyUnsupported { next_hop, .. }] if *next_hop == ip("2001:db8::1")
        ));
    }

    #[test]
    fn reordered_multipath_set_does_not_trigger_replace() {
        // Owned, desired, and kernel all hold the same ECMP set in different
        // pre-canonical orders. Canonicalization must make them compare equal,
        // so the diff is a no-op.
        let key = key(v4_prefix(2, 24));
        let owned_route = FibRoute {
            table_name: "edge".to_string(),
            key,
            target: target_from_addrs(["203.0.113.1", "203.0.113.2"]),
            peer: ip("198.51.100.1"),
            origin_type: RouteOrigin::Ebgp,
            path_id: 0,
        };
        let mut desired = owned_route.clone();
        desired.target = target_from_addrs(["203.0.113.2", "203.0.113.1"]);
        let owned = FibOwnedState {
            routes: BTreeMap::from([(key, owned_route)]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(
                key,
                FibKernelRoute {
                    target: target_from_addrs(["203.0.113.2", "203.0.113.1"]),
                    protocol: FibKernelProtocol::Bgp,
                },
            )]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(key, desired)]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert!(
            plan.ops.is_empty(),
            "reordered-but-equal set should be a no-op: {:?}",
            plan.ops
        );
        assert!(plan.drops.is_empty());
    }

    #[test]
    fn multipath_set_growth_emits_replace() {
        let key = key(v4_prefix(2, 24));
        let previous = one_route(key, "203.0.113.1");
        let mut desired = previous.clone();
        desired.target = target_from_addrs(["203.0.113.1", "203.0.113.2"]);
        let owned = FibOwnedState {
            routes: BTreeMap::from([(key, previous.clone())]),
        };
        let kernel = FibKernelSnapshot {
            routes: BTreeMap::from([(key, kernel("203.0.113.1", FibKernelProtocol::Bgp))]),
        };
        let intent = FibIntent {
            routes: BTreeMap::from([(key, desired.clone())]),
            drops: vec![],
            ..FibIntent::default()
        };

        let plan = compute_fib_diff(&intent, &owned, &kernel);

        assert_eq!(plan.ops, vec![FibOp::Replace { previous, desired }]);
        assert!(plan.drops.is_empty());
    }
}
