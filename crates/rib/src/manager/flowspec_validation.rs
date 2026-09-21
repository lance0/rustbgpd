//! Actor-owned retained feasibility and resumable received-candidate walks.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::ops::Bound::{Excluded, Unbounded};
use std::ops::ControlFlow;
use std::time::Instant;

use rustbgpd_wire::{Afi, FlowSpecRule, Ipv4Prefix, Ipv6Prefix, PathAttribute, Prefix, Safi};

use super::RibManager;
use crate::adj_rib_in::AdjRibIn;
use crate::flowspec_validation::{self as feasibility, Feasibility, MoreSpecificCheck};
use crate::loc_rib::LocRib;
use crate::prefix_map::FamilyPrefixMap;
use crate::route::{FlowSpecKey, FlowSpecRoute, RouteOrigin};
use crate::update::{FlowSpecValidationStatus, ReceivedFlowSpecRoute, RibRowFilter};

const VALIDATION_VISITS_PER_TURN: usize = 256;
const DEPENDENCY_RULES_PER_TURN: usize = 16;

type CandidateId = (FlowSpecKey, IpAddr, u32);

/// Retained payload copy: the Adj-RIB-In row is overwritten before this
/// reconciliation runs, so an exact comparison needs the previous payload.
struct Candidate {
    attributes: Vec<PathAttribute>,
    origin: RouteOrigin,
    revision: u64,
    observed_unicast_revision: u64,
    completed: Option<Feasibility>,
    pending: bool,
    retain_selected: bool,
}

struct Job {
    id: CandidateId,
    revision: u64,
    check: MoreSpecificCheck,
    peers: Vec<IpAddr>,
    peer_index: usize,
    after: Option<(Prefix, usize)>,
}

#[derive(Clone, Copy)]
struct Change {
    revision: u64,
    repeated: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct DependencyScope {
    prefix: Prefix,
    descendants: bool,
}

struct DependencyScan {
    scope: DependencyScope,
    change: Change,
    destination: Option<Prefix>,
    after: Option<FlowSpecRule>,
}

impl DependencyScan {
    fn next_rule(
        &mut self,
        index: &FamilyPrefixMap<BTreeSet<FlowSpecRule>>,
    ) -> Option<FlowSpecKey> {
        if !self.scope.descendants {
            let rule = index
                .get(&self.scope.prefix)
                .and_then(|rules| self.next_in(rules))?;
            self.after = Some(rule.clone());
            return Some(self.key(rule));
        }
        for (destination, rules) in
            index.iter_from(Some(self.destination.unwrap_or(self.scope.prefix)))
        {
            if !prefix_covers(self.scope.prefix, destination) {
                return None;
            }
            if self.destination != Some(destination) {
                self.destination = Some(destination);
                self.after = None;
            }
            if let Some(rule) = self.next_in(rules) {
                self.after = Some(rule.clone());
                return Some(self.key(rule));
            }
        }
        None
    }

    fn next_in(&self, rules: &BTreeSet<FlowSpecRule>) -> Option<FlowSpecRule> {
        match &self.after {
            Some(after) => rules.range((Excluded(after), Unbounded)).next().cloned(),
            None => rules.first().cloned(),
        }
    }

    fn key(&self, rule: FlowSpecRule) -> FlowSpecKey {
        FlowSpecKey {
            afi: match self.scope.prefix {
                Prefix::V4(_) => Afi::Ipv4,
                Prefix::V6(_) => Afi::Ipv6,
            },
            rule,
        }
    }
}

fn prefix_covers(cover: Prefix, prefix: Prefix) -> bool {
    match (cover, prefix) {
        (Prefix::V4(cover), Prefix::V4(prefix)) => {
            prefix.len >= cover.len && Ipv4Prefix::new(prefix.addr, cover.len) == cover
        }
        (Prefix::V6(cover), Prefix::V6(prefix)) => {
            prefix.len >= cover.len && Ipv6Prefix::new(prefix.addr, cover.len) == cover
        }
        _ => false,
    }
}

/// Absent local AS means validation is disabled and all maps stay empty.
#[derive(Default)]
pub(super) struct ValidationState {
    local_as: Option<u32>,
    destinations: FamilyPrefixMap<BTreeSet<FlowSpecRule>>,
    candidates: HashMap<FlowSpecKey, HashMap<(IpAddr, u32), Candidate>>,
    revision: u64,
    unicast_revision: u64,
    changes: HashMap<DependencyScope, Change>,
    change_queue: VecDeque<DependencyScope>,
    dependency: Option<DependencyScan>,
    queues: [VecDeque<CandidateId>; 2],
    next_queue: usize,
    queued: HashSet<CandidateId>,
    active: Option<Job>,
}

impl ValidationState {
    pub(super) fn selection_candidates<'a>(
        &self,
        key: &FlowSpecKey,
        ribs: &'a HashMap<IpAddr, AdjRibIn>,
        loc: &LocRib,
        checkpoint: &impl Fn(),
    ) -> Vec<&'a FlowSpecRoute> {
        if self.local_as.is_none() {
            return ribs
                .values()
                .inspect(|_| checkpoint())
                .flat_map(AdjRibIn::iter_flowspec)
                .inspect(|_| checkpoint())
                .filter(|route| route.afi == key.afi && route.rule == key.rule)
                .collect();
        }
        self.candidates
            .get(key)
            .into_iter()
            .flat_map(|rows| rows.keys())
            .inspect(|_| checkpoint())
            .filter_map(|(peer, path_id)| {
                let route_key = crate::route::FlowSpecRouteKey {
                    afi: key.afi,
                    rule: key.rule.clone(),
                    path_id: *path_id,
                };
                ribs.get(peer)?.get_flowspec(&route_key)
            })
            .filter(|route| self.eligible(route, loc))
            .collect()
    }

    fn enqueue_dependency(&mut self, scope: DependencyScope, revision: u64) {
        if let Some(change) = self.changes.get_mut(&scope) {
            // Several affected prefixes in one atomic ingest batch are one
            // invalidation, not evidence of repeated changes during a scan.
            change.repeated |= change.revision != revision;
            change.revision = revision;
        } else {
            let repeated = self
                .dependency
                .as_ref()
                .is_some_and(|scan| scan.scope == scope);
            self.changes.insert(scope, Change { revision, repeated });
            self.change_queue.push_back(scope);
        }
    }

    fn next_revision(&mut self) -> u64 {
        self.revision = self.revision.wrapping_add(1);
        self.revision
    }

    fn enqueue(&mut self, id: CandidateId) {
        if self.queued.insert(id.clone()) {
            let family = usize::from(id.0.afi == Afi::Ipv6);
            self.queues[family].push_back(id);
        }
    }

    fn pop_runnable(&mut self, held: [bool; 2]) -> Option<CandidateId> {
        for offset in 0..2 {
            let family = (self.next_queue + offset) % 2;
            if !held[family]
                && let Some(id) = self.queues[family].pop_front()
            {
                self.next_queue = 1 - family;
                self.queued.remove(&id);
                return Some(id);
            }
        }
        None
    }

    fn candidate(&self, id: &CandidateId) -> Option<&Candidate> {
        self.candidates.get(&id.0)?.get(&(id.1, id.2))
    }

    fn candidate_mut(&mut self, id: &CandidateId) -> Option<&mut Candidate> {
        self.candidates.get_mut(&id.0)?.get_mut(&(id.1, id.2))
    }

    /// Reconcile one atomic affected set without rescanning the retained table
    /// for each rule. The temporary inventory borrows both keys and routes.
    fn sync_rules(
        &mut self,
        affected: &HashSet<FlowSpecKey>,
        ribs: &HashMap<IpAddr, AdjRibIn>,
        loc: &LocRib,
        checkpoint: &impl Fn(),
    ) {
        if self.local_as.is_none() || affected.is_empty() {
            return;
        }
        let mut groups: HashMap<_, Vec<&FlowSpecRoute>> = affected
            .iter()
            .inspect(|_| checkpoint())
            .map(|key| ((key.afi, &key.rule), Vec::new()))
            .collect();
        for route in ribs
            .values()
            .inspect(|_| checkpoint())
            .flat_map(AdjRibIn::iter_flowspec)
            .inspect(|_| checkpoint())
        {
            if let Some(rows) = groups.get_mut(&(route.afi, &route.rule)) {
                rows.push(route);
            }
        }
        let mut retired = false;
        for key in affected {
            checkpoint();
            let rows = groups.remove(&(key.afi, &key.rule)).unwrap_or_default();
            retired |= self.sync_rule(key, &rows, loc, checkpoint);
        }
        if retired {
            // Retirement is also batch-scoped: a multi-rule withdrawal must
            // not walk every queued candidate once per removed rule.
            let candidates = &self.candidates;
            let retained = |id: &CandidateId| {
                checkpoint();
                candidates
                    .get(&id.0)
                    .is_some_and(|rows| rows.contains_key(&(id.1, id.2)))
            };
            for queue in &mut self.queues {
                queue.retain(&retained);
            }
            self.queued.retain(&retained);
            if self.active.as_ref().is_some_and(|job| !retained(&job.id)) {
                self.active = None;
            }
        }
    }

    /// Reconcile retained `FlowSpec` mutations at the existing selection seam.
    fn sync_rule(
        &mut self,
        key: &FlowSpecKey,
        routes: &[&FlowSpecRoute],
        loc: &LocRib,
        checkpoint: &impl Fn(),
    ) -> bool {
        let Some(local_as) = self.local_as else {
            return false;
        };
        let mut retained = HashSet::new();
        for route in routes {
            checkpoint();
            let identity = (route.peer, route.path_id);
            retained.insert(identity);
            if self
                .candidates
                .get(key)
                .and_then(|rows| rows.get(&identity))
                .is_some_and(|old| {
                    // A re-received identical payload (route refresh, GR
                    // re-sync, periodic re-send) carries a fresh timestamp;
                    // only the payload decides whether the verdict is stale.
                    old.attributes == route.attributes && old.origin == route.origin_type
                })
            {
                continue;
            }
            let revision = self.next_revision();
            let result = begin_for_route(route, loc, local_as);
            let (completed, pending) = match result {
                ControlFlow::Break(verdict) => (Some(verdict), false),
                ControlFlow::Continue(_) => (None, true),
            };
            self.candidates.entry(key.clone()).or_default().insert(
                identity,
                Candidate {
                    attributes: route.attributes.clone(),
                    origin: route.origin_type,
                    revision,
                    observed_unicast_revision: self.unicast_revision,
                    completed,
                    pending,
                    // A replaced candidate never inherits another payload's result.
                    retain_selected: false,
                },
            );
            if pending {
                self.enqueue((key.clone(), route.peer, route.path_id));
            }
        }
        let retired = self.candidates.get_mut(key).is_some_and(|rows| {
            let before = rows.len();
            rows.retain(|identity, _| {
                checkpoint();
                retained.contains(identity)
            });
            rows.len() != before
        });
        if retained.is_empty() {
            self.candidates.remove(key);
            if let Some(destination) = key.rule.destination_prefix() {
                let empty = self.destinations.get_mut(&destination).is_some_and(|keys| {
                    keys.remove(&key.rule);
                    keys.is_empty()
                });
                if empty {
                    self.destinations.remove(&destination);
                }
            }
            if self.candidates.is_empty() {
                self.changes.clear();
                self.change_queue.clear();
                self.dependency = None;
            }
        } else if let Some(destination) = key.rule.destination_prefix() {
            self.destinations
                .entry_or_default(destination)
                .insert(key.rule.clone());
        }
        retired
    }

    fn invalidate_rule(
        &mut self,
        key: &FlowSpecKey,
        ribs: &HashMap<IpAddr, AdjRibIn>,
        loc: &LocRib,
        change: Change,
        checkpoint: &impl Fn(),
    ) {
        let Some(local_as) = self.local_as else {
            return;
        };
        let identities: Vec<_> = self
            .candidates
            .get(key)
            .into_iter()
            .flat_map(|rows| rows.keys())
            .inspect(|_| checkpoint())
            .copied()
            .collect();
        for (peer, path_id) in identities {
            checkpoint();
            let route_key = crate::route::FlowSpecRouteKey {
                afi: key.afi,
                rule: key.rule.clone(),
                path_id,
            };
            let Some(route) = ribs.get(&peer).and_then(|rib| rib.get_flowspec(&route_key)) else {
                continue;
            };
            if route.origin_type == RouteOrigin::Local {
                continue;
            }
            let id = (key.clone(), route.peer, route.path_id);
            if self
                .candidate(&id)
                .is_some_and(|candidate| candidate.observed_unicast_revision >= change.revision)
            {
                continue;
            }
            let revision = self.next_revision();
            let result = begin_for_route(route, loc, local_as);
            let Some(candidate) = self.candidate_mut(&id) else {
                continue;
            };
            candidate.revision = revision;
            candidate.observed_unicast_revision = change.revision;
            match result {
                ControlFlow::Break(verdict) => {
                    // Loss of cover and other already-proven failures do not
                    // wait behind a scan. This also revokes any old selection.
                    candidate.completed = Some(verdict);
                    candidate.pending = false;
                    candidate.retain_selected = false;
                }
                ControlFlow::Continue(_) => {
                    let selected = loc.get_flowspec(key).is_some_and(|selected| {
                        selected.peer == route.peer && selected.path_id == route.path_id
                    });
                    candidate.retain_selected = !change.repeated
                        && !candidate.pending
                        && selected
                        && candidate.completed == Some(Feasibility::Feasible);
                    candidate.pending = true;
                    self.enqueue(id);
                }
            }
        }
    }

    fn eligible(&self, route: &FlowSpecRoute, loc: &LocRib) -> bool {
        if self.local_as.is_none() || route.origin_type == RouteOrigin::Local {
            return true;
        }
        let key = route.selection_key();
        let Some(candidate) = self
            .candidates
            .get(&key)
            .and_then(|rows| rows.get(&(route.peer, route.path_id)))
        else {
            return false;
        };
        if candidate.pending {
            candidate.retain_selected
                && loc.get_flowspec(&key).is_some_and(|selected| {
                    selected.peer == route.peer && selected.path_id == route.path_id
                })
        } else {
            matches!(
                candidate.completed,
                Some(Feasibility::Feasible | Feasibility::Local)
            )
        }
    }
}

fn begin_for_route(
    flow: &FlowSpecRoute,
    loc: &LocRib,
    local_as: u32,
) -> ControlFlow<Feasibility, MoreSpecificCheck> {
    let covering = flow
        .rule
        .destination_prefix()
        .and_then(|prefix| loc.longest_match(&prefix).map(|(_, route)| route));
    feasibility::begin(flow, covering, local_as)
}

impl RibManager {
    pub(super) fn send_received_flowspec(
        &self,
        peer: IpAddr,
        filter: Option<&RibRowFilter<ReceivedFlowSpecRoute>>,
        reply: tokio::sync::oneshot::Sender<Vec<ReceivedFlowSpecRoute>>,
    ) {
        if let Some(rows) = self.collect_received_flowspec(peer, filter, || reply.is_closed()) {
            let _ = reply.send(rows);
        }
    }

    fn collect_received_flowspec(
        &self,
        peer: IpAddr,
        filter: Option<&RibRowFilter<ReceivedFlowSpecRoute>>,
        mut canceled: impl FnMut() -> bool,
    ) -> Option<Vec<ReceivedFlowSpecRoute>> {
        if canceled() {
            return None;
        }
        let mut rows = Vec::new();
        if let Some(rib) = self.ribs.get(&peer) {
            for (visited, route) in rib.iter_flowspec().enumerate() {
                // Count visited candidates, including those filtered out.
                if visited != 0 && visited.is_multiple_of(VALIDATION_VISITS_PER_TURN) && canceled()
                {
                    return None;
                }
                let key = route.selection_key();
                let state = self
                    .flowspec_validation
                    .candidates
                    .get(&key)
                    .and_then(|rows| rows.get(&(peer, route.path_id)));
                let (validation, reason, pending) = if self.flowspec_validation.local_as.is_none() {
                    (FlowSpecValidationStatus::Disabled, None, false)
                } else if let Some(state) = state {
                    let (status, reason) = match state.completed {
                        None => (FlowSpecValidationStatus::Pending, None),
                        Some(Feasibility::Local) => (FlowSpecValidationStatus::Local, None),
                        Some(Feasibility::Feasible) => (FlowSpecValidationStatus::Feasible, None),
                        Some(Feasibility::Infeasible(reason)) => {
                            (FlowSpecValidationStatus::Infeasible, Some(reason.as_str()))
                        }
                    };
                    (
                        status,
                        reason,
                        state.origin != RouteOrigin::Local
                            && (state.pending
                                || self.flowspec_validation.dependency.is_some()
                                || !self.flowspec_validation.changes.is_empty()
                                || !self.pending_route_batches.is_empty()),
                    )
                } else {
                    (FlowSpecValidationStatus::Pending, None, true)
                };
                let selected = self.loc_rib.get_flowspec(&key).is_some_and(|selected| {
                    selected.peer == peer && selected.path_id == route.path_id
                });
                let row = ReceivedFlowSpecRoute {
                    route: route.clone(),
                    selected,
                    validation,
                    reason,
                    pending,
                };
                if filter.is_none_or(|filter| filter(&row)) {
                    rows.push(row);
                }
            }
        }
        (!canceled()).then_some(rows)
    }

    /// Enable startup-only RFC 9117 receive-side `FlowSpec` validation.
    #[must_use]
    pub fn with_flowspec_validation(mut self, local_as: u32) -> Self {
        self.flowspec_validation.local_as = Some(local_as);
        self
    }

    pub(super) fn sync_flowspec_validation(&mut self, affected: &HashSet<FlowSpecKey>) {
        if self.flowspec_validation.local_as.is_none() {
            return;
        }
        let readiness = self.replacement_readiness.clone();
        let checkpoint =
            || super::replacement_readiness_checkpoint_at(&readiness, "flowspec_inventory", false);
        self.flowspec_validation
            .sync_rules(affected, &self.ribs, &self.loc_rib, &checkpoint);
    }

    pub(super) fn invalidate_flowspec_dependencies(&mut self, changed: &HashSet<Prefix>) {
        let state = &self.flowspec_validation;
        // No retained destination means nothing can depend on a unicast change;
        // skip the per-prefix ancestor and descendant probes entirely.
        if state.local_as.is_none()
            || changed.is_empty()
            || (state.destinations.family_len(Afi::Ipv4) == 0
                && state.destinations.family_len(Afi::Ipv6) == 0)
        {
            return;
        }
        self.with_selection_readiness(|manager| manager.queue_flowspec_dependencies(changed));
    }

    fn queue_flowspec_dependencies(&mut self, changed: &HashSet<Prefix>) {
        let readiness = self.replacement_readiness.clone();
        let checkpoint = || {
            super::replacement_readiness_checkpoint_at(
                &readiness,
                "flowspec_dependency_inventory",
                false,
            );
        };
        self.flowspec_validation.unicast_revision =
            self.flowspec_validation.unicast_revision.wrapping_add(1);
        let revision = self.flowspec_validation.unicast_revision;
        for prefix in changed {
            checkpoint();
            // A changed /32 can affect a broad FlowSpec destination, but it
            // must not enqueue one duplicate job for every unicast /32.
            for length in 0..prefix.prefix_len() {
                let ancestor = match prefix {
                    Prefix::V4(prefix) => Prefix::V4(Ipv4Prefix::new(prefix.addr, length)),
                    Prefix::V6(prefix) => Prefix::V6(Ipv6Prefix::new(prefix.addr, length)),
                };
                if self
                    .flowspec_validation
                    .destinations
                    .get(&ancestor)
                    .is_some()
                {
                    self.flowspec_validation.enqueue_dependency(
                        DependencyScope {
                            prefix: ancestor,
                            descendants: false,
                        },
                        revision,
                    );
                }
            }
            if self
                .flowspec_validation
                .destinations
                .children(prefix)
                .next()
                .is_some()
            {
                self.flowspec_validation.enqueue_dependency(
                    DependencyScope {
                        prefix: *prefix,
                        descendants: true,
                    },
                    revision,
                );
            }
        }
        // Only one candidate scan is active. Invalidate its native cursor now,
        // before delayed discovery could otherwise allow stale publication.
        let overlap = self.flowspec_validation.active.as_ref().is_some_and(|job| {
            job.id
                .0
                .rule
                .destination_prefix()
                .is_some_and(|destination| {
                    changed.iter().inspect(|_| checkpoint()).any(|prefix| {
                        prefix_covers(*prefix, destination) || prefix_covers(destination, *prefix)
                    })
                })
        });
        if overlap {
            let job = self
                .flowspec_validation
                .active
                .take()
                .expect("overlapping job exists");
            let next_revision = self.flowspec_validation.next_revision();
            if let Some(candidate) = self.flowspec_validation.candidate_mut(&job.id) {
                candidate.revision = next_revision;
                candidate.observed_unicast_revision = revision;
                candidate.retain_selected = false;
            }
            self.flowspec_validation.enqueue(job.id.clone());
            self.recompute_validated_flowspec(&HashSet::from([job.id.0]));
        }
    }

    fn process_flowspec_dependency_chunk(&mut self) -> bool {
        let readiness = self.replacement_readiness.clone();
        let checkpoint = || {
            super::replacement_readiness_checkpoint_at(&readiness, "flowspec_dependencies", false);
        };
        let mut processed = false;
        for _ in 0..DEPENDENCY_RULES_PER_TURN {
            checkpoint();
            if self.flowspec_validation.dependency.is_none() {
                let Some(scope) = self.flowspec_validation.change_queue.pop_front() else {
                    break;
                };
                let Some(change) = self.flowspec_validation.changes.remove(&scope) else {
                    continue;
                };
                self.flowspec_validation.dependency = Some(DependencyScan {
                    scope,
                    change,
                    destination: None,
                    after: None,
                });
            }
            processed = true;
            let scan = self
                .flowspec_validation
                .dependency
                .as_mut()
                .expect("dependency scan initialized");
            let Some(key) = scan.next_rule(&self.flowspec_validation.destinations) else {
                self.flowspec_validation.dependency = None;
                continue;
            };
            let change = scan.change;
            self.flowspec_validation.invalidate_rule(
                &key,
                &self.ribs,
                &self.loc_rib,
                change,
                &checkpoint,
            );
            self.recompute_validated_flowspec(&HashSet::from([key]));
        }
        processed
    }

    /// Advance at most one bounded candidate walk. Peers with no applicable
    /// routes also consume a visit so an empty fleet cannot create a long unit.
    pub(super) fn process_flowspec_validation_chunk(&mut self) -> bool {
        let Some(local_as) = self.flowspec_validation.local_as else {
            return false;
        };
        if self.flowspec_validation.active.is_none()
            && self
                .flowspec_validation
                .queues
                .iter()
                .all(VecDeque::is_empty)
            && self.flowspec_validation.dependency.is_none()
            && self.flowspec_validation.changes.is_empty()
        {
            return false;
        }
        // Ingest publishes all affected prefixes at its drained-batch tail.
        // Do not resume a native cursor against a partially mutated batch.
        if !self.pending_route_batches.is_empty() {
            return false;
        }
        let started = Instant::now();
        let processed = self.with_selection_readiness(|manager| {
            let dependencies = manager.process_flowspec_dependency_chunk();
            manager.advance_flowspec_validation(local_as) || dependencies
        });
        if processed {
            self.metrics
                .observe_rib_actor_work("flowspec_validation", started.elapsed());
        }
        processed
    }

    #[expect(
        clippy::too_many_lines,
        reason = "candidate scheduling, revision checks, and native cursor resumption share one bounded actor step"
    )]
    fn advance_flowspec_validation(&mut self, local_as: u32) -> bool {
        let readiness = self.replacement_readiness.clone();
        let checkpoint =
            || super::replacement_readiness_checkpoint_at(&readiness, "flowspec_validation", false);
        let held = [
            self.selection_deferred((Afi::Ipv4, Safi::Unicast)),
            self.selection_deferred((Afi::Ipv6, Safi::Unicast)),
        ];

        if self
            .flowspec_validation
            .active
            .as_ref()
            .is_some_and(|job| self.selection_deferred((job.id.0.afi, Safi::Unicast)))
        {
            let job = self
                .flowspec_validation
                .active
                .take()
                .expect("gated job exists");
            self.flowspec_validation.enqueue(job.id);
        }
        let mut work = 0;
        while work < VALIDATION_VISITS_PER_TURN {
            checkpoint();
            if self.flowspec_validation.active.is_none() {
                let Some(id) = self.flowspec_validation.pop_runnable(held) else {
                    return work != 0;
                };
                work += 1;
                let Some(candidate) = self.flowspec_validation.candidate(&id) else {
                    continue;
                };
                if !candidate.pending {
                    continue;
                }
                let revision = candidate.revision;
                let observed = self.flowspec_validation.unicast_revision;
                self.flowspec_validation
                    .candidate_mut(&id)
                    .expect("candidate exists")
                    .observed_unicast_revision = observed;
                let route_key = crate::route::FlowSpecRouteKey {
                    afi: id.0.afi,
                    rule: id.0.rule.clone(),
                    path_id: id.2,
                };
                let route = self
                    .ribs
                    .get(&id.1)
                    .and_then(|rib| rib.get_flowspec(&route_key));
                let Some(route) = route else { continue };
                match begin_for_route(route, &self.loc_rib, local_as) {
                    ControlFlow::Break(result) => {
                        self.finish_flowspec_validation(&id, revision, result);
                        continue;
                    }
                    ControlFlow::Continue(check) => {
                        self.flowspec_validation.active = Some(Job {
                            id,
                            revision,
                            check,
                            peers: self
                                .ribs
                                .keys()
                                .inspect(|_| checkpoint())
                                .copied()
                                .collect(),
                            peer_index: 0,
                            after: None,
                        });
                    }
                }
            }
            let mut job = self
                .flowspec_validation
                .active
                .take()
                .expect("active validation initialized");
            if !self
                .flowspec_validation
                .candidate(&job.id)
                .is_some_and(|candidate| candidate.pending && candidate.revision == job.revision)
            {
                work += 1;
                continue;
            }
            let mut done = false;
            while work < VALIDATION_VISITS_PER_TURN {
                let Some(peer) = job.peers.get(job.peer_index) else {
                    done = true;
                    break;
                };
                let destination = job
                    .id
                    .0
                    .rule
                    .destination_prefix()
                    .expect("validated destination");
                let mut exhausted = true;
                if let Some(rib) = self.ribs.get(peer) {
                    for (cursor, route) in rib.iter_covered_from(destination, job.after) {
                        checkpoint();
                        work += 1;
                        job.after = Some(cursor);
                        if job.check.visit(route).is_break() {
                            done = true;
                            break;
                        }
                        if work >= VALIDATION_VISITS_PER_TURN {
                            exhausted = false;
                            break;
                        }
                    }
                }
                if done {
                    break;
                }
                if exhausted {
                    work += 1;
                    job.peer_index += 1;
                    job.after = None;
                } else {
                    break;
                }
            }
            if done {
                self.finish_flowspec_validation(&job.id, job.revision, job.check.finish());
            } else {
                self.flowspec_validation.active = Some(job);
            }
        }
        true
    }

    fn finish_flowspec_validation(&mut self, id: &CandidateId, revision: u64, result: Feasibility) {
        let Some(candidate) = self.flowspec_validation.candidate_mut(id) else {
            return;
        };
        if candidate.revision != revision || !candidate.pending {
            return;
        }
        candidate.completed = Some(result);
        candidate.pending = false;
        candidate.retain_selected = false;
        self.recompute_validated_flowspec(&HashSet::from([id.0.clone()]));
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    use rustbgpd_telemetry::BgpMetrics;
    use rustbgpd_wire::{Afi, AsPath, AsPathSegment};
    use tokio::sync::mpsc;

    use super::*;
    use crate::route::Route;
    use crate::test_support::{make_flowspec_route, make_route};
    use crate::{RibUpdate, SelectionDeferralConfig, SelectionDeferralWaiterConfig};

    fn path(asn: u32) -> PathAttribute {
        PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![asn])],
        })
    }

    fn fixture() -> (RibManager, mpsc::Sender<RibUpdate>, FlowSpecRoute, Route) {
        let (tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, mpsc::channel(1).1, None, None, BgpMetrics::new())
            .with_flowspec_validation(65000);
        let peer = Ipv4Addr::new(198, 51, 100, 1);
        let mut flow = make_flowspec_route(peer);
        flow.attributes = vec![path(65001)];
        let mut cover = make_route(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 0, 0), 16), peer);
        cover.attributes = Arc::new(vec![path(65001)]);
        let mut rib = AdjRibIn::new(flow.peer);
        rib.insert(cover.clone());
        rib.insert_flowspec(flow.clone());
        manager.ribs.insert(flow.peer, rib);
        manager
            .loc_rib
            .recompute(cover.prefix, std::iter::once(&cover));
        manager.recompute_and_distribute_flowspec(&HashSet::from([flow.selection_key()]));
        (manager, tx, flow, cover)
    }

    fn drain(manager: &mut RibManager) {
        for _ in 0..10_000 {
            if !manager.process_flowspec_validation_chunk() {
                return;
            }
        }
        panic!("validation failed to drain");
    }

    fn child(cover: &Route, path_id: u32, asn: u32) -> Route {
        let mut route = cover.clone();
        route.prefix = Prefix::V4(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 2, 0), 25));
        route.path_id = path_id;
        route.attributes = Arc::new(vec![path(asn)]);
        route
    }

    fn selected(manager: &RibManager, flow: &FlowSpecRoute) -> bool {
        manager
            .loc_rib
            .get_flowspec(&flow.selection_key())
            .is_some()
    }

    #[test]
    fn flowspec_validation_retains_failure_and_recovers_without_flow_update() {
        let (mut manager, _tx, flow, cover) = fixture();
        assert!(!selected(&manager, &flow));
        drain(&mut manager);
        assert!(selected(&manager, &flow));

        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .withdraw(&cover.prefix, cover.path_id);
        manager.loc_rib.recompute(cover.prefix, std::iter::empty());
        manager.distribute_changes(
            &HashSet::from([cover.prefix]),
            &HashSet::from([cover.prefix]),
        );
        manager.process_flowspec_validation_chunk();
        assert!(
            !selected(&manager, &flow),
            "discovery of a lost cover needs no candidate scan"
        );
        let rows = manager
            .collect_received_flowspec(flow.peer, None, || false)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].reason, Some("no_covering_unicast"));
        assert!(!rows[0].pending);

        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .insert(cover.clone());
        manager
            .loc_rib
            .recompute(cover.prefix, std::iter::once(&cover));
        manager.distribute_changes(
            &HashSet::from([cover.prefix]),
            &HashSet::from([cover.prefix]),
        );
        drain(&mut manager);
        assert!(selected(&manager, &flow));
    }

    #[tokio::test]
    async fn flowspec_validation_cover_peer_teardown_retains_flow_and_update_recovers() {
        let (_tx, rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, mpsc::channel(1).1, None, None, BgpMetrics::new())
            .with_flowspec_validation(65000);
        let flow_peer = Ipv4Addr::new(198, 51, 100, 1);
        let cover_peer = Ipv4Addr::new(198, 51, 100, 2);
        let originator = Ipv4Addr::new(198, 51, 100, 3);
        let attributes = vec![path(65001), PathAttribute::OriginatorId(originator)];
        let mut flow = make_flowspec_route(flow_peer);
        flow.origin_type = RouteOrigin::Ibgp;
        flow.attributes = attributes.clone();
        let mut cover = make_route(Ipv4Prefix::new(Ipv4Addr::new(192, 0, 0, 0), 16), cover_peer);
        cover.origin_type = RouteOrigin::Ibgp;
        cover.attributes = Arc::new(attributes);
        // Separate reflector sessions preserve one originator identity. Losing
        // only the unicast session must leave the received FlowSpec available.
        for (peer, announced, flowspec_announced) in [
            (cover.peer, vec![cover.clone()], vec![]),
            (flow.peer, vec![], vec![flow.clone()]),
        ] {
            manager.handle_update(RibUpdate::RoutesReceived {
                peer,
                session_id: 0,
                announced,
                withdrawn: vec![],
                flowspec_announced,
                flowspec_withdrawn: vec![],
                evpn_announced: vec![],
                evpn_withdrawn: vec![],
            });
            while manager.process_next_route_chunk() {}
        }
        drain(&mut manager);
        assert!(selected(&manager, &flow));

        manager.handle_update(RibUpdate::PeerDown {
            peer: cover.peer,
            session_id: 0,
        });
        drain(&mut manager);
        assert!(!selected(&manager, &flow));
        let rows = manager
            .collect_received_flowspec(flow.peer, None, || false)
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].validation, FlowSpecValidationStatus::Infeasible);
        assert_eq!(rows[0].reason, Some("no_covering_unicast"));
        assert!(!rows[0].pending);
        assert_eq!(rows[0].route.received_at, flow.received_at);

        manager.handle_update(RibUpdate::RoutesReceived {
            peer: cover.peer,
            session_id: 0,
            announced: vec![cover],
            withdrawn: vec![],
            flowspec_announced: vec![],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        });
        while manager.process_next_route_chunk() {}
        drain(&mut manager);
        assert!(selected(&manager, &flow));
        let rows = manager
            .collect_received_flowspec(flow.peer, None, || false)
            .unwrap();
        assert_eq!(rows[0].validation, FlowSpecValidationStatus::Feasible);
        assert_eq!(rows[0].route.received_at, flow.received_at);
    }

    #[test]
    fn flowspec_validation_losing_add_path_churn_uses_all_affected_prefixes() {
        let (mut manager, _tx, flow, cover) = fixture();
        drain(&mut manager);
        let candidate = child(&cover, 9, 65002);
        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .insert(candidate.clone());
        // There is deliberately no best-path change or best-path event.
        manager.distribute_changes(&HashSet::new(), &HashSet::from([candidate.prefix]));
        drain(&mut manager);
        assert!(!selected(&manager, &flow));
        let rows = manager
            .collect_received_flowspec(flow.peer, None, || false)
            .unwrap();
        assert_eq!(rows[0].reason, Some("conflicting_more_specific"));
        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .withdraw(&candidate.prefix, candidate.path_id);
        manager.distribute_changes(&HashSet::new(), &HashSet::from([candidate.prefix]));
        drain(&mut manager);
        assert!(selected(&manager, &flow));
    }

    #[test]
    fn flowspec_validation_second_invalidation_revokes_and_old_revision_cannot_restore() {
        let (mut manager, _tx, flow, cover) = fixture();
        drain(&mut manager);
        let changed = HashSet::from([cover.prefix]);
        manager.invalidate_flowspec_dependencies(&changed);
        manager.process_flowspec_dependency_chunk();
        assert!(selected(&manager, &flow));
        let id = (flow.selection_key(), flow.peer, flow.path_id);
        let first_revision = manager.flowspec_validation.candidate(&id).unwrap().revision;
        manager.invalidate_flowspec_dependencies(&changed);
        manager.process_flowspec_dependency_chunk();
        assert!(!selected(&manager, &flow));
        manager.invalidate_flowspec_dependencies(&changed);
        manager.finish_flowspec_validation(&id, first_revision, Feasibility::Feasible);
        assert!(!selected(&manager, &flow));
        assert!(manager.flowspec_validation.candidate(&id).unwrap().pending);
        drain(&mut manager);
        assert!(selected(&manager, &flow));
    }

    #[test]
    fn flowspec_validation_replacement_never_inherits_previous_completed_verdict() {
        let (mut manager, _tx, mut flow, _cover) = fixture();
        drain(&mut manager);
        flow.attributes = vec![PathAttribute::AsPath(AsPath {
            segments: vec![AsPathSegment::AsSequence(vec![65001, 65001])],
        })];
        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .insert_flowspec(flow.clone());
        manager.recompute_and_distribute_flowspec(&HashSet::from([flow.selection_key()]));
        assert!(!selected(&manager, &flow));
        let rows = manager
            .collect_received_flowspec(flow.peer, None, || false)
            .unwrap();
        assert_eq!(rows[0].validation, FlowSpecValidationStatus::Pending);
        drain(&mut manager);
        assert!(selected(&manager, &flow));
    }

    #[tokio::test]
    async fn flowspec_validation_identical_re_receipt_keeps_selection_without_withdraw() {
        let (mut manager, _tx, mut flow, _cover) = fixture();
        drain(&mut manager);
        assert!(selected(&manager, &flow));
        let downstream = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
        let (out_tx, mut out_rx) = mpsc::channel(8);
        manager.handle_update(RibUpdate::PeerUp {
            peer: downstream,
            session_id: 0,
            peer_asn: 65002,
            peer_router_id: Ipv4Addr::UNSPECIFIED,
            outbound_tx: out_tx,
            export_policy: None,
            sendable_families: vec![(Afi::Ipv4, Safi::FlowSpec)],
            is_ebgp: true,
            route_reflector_client: false,
            per_client_best: false,
            interpret_rfc1997: true,
            orr_vantage: None,
            add_path_send_families: vec![],
            add_path_send_max: 0,
            negotiated_orf_recv: Vec::new(),
            negotiated_llgr_families: Vec::new(),
        });
        let initial = out_rx.try_recv().expect("initial FlowSpec table");
        assert_eq!(initial.flowspec_announce.len(), 1);
        while out_rx.try_recv().is_ok() {}

        // Same payload, fresh receipt: a route refresh, GR re-sync, or a
        // periodic re-send stamps a new timestamp and overwrites Adj-RIB-In.
        flow.received_at = Instant::now();
        manager.handle_update(RibUpdate::RoutesReceived {
            peer: flow.peer,
            session_id: 0,
            announced: vec![],
            withdrawn: vec![],
            flowspec_announced: vec![flow.clone()],
            flowspec_withdrawn: vec![],
            evpn_announced: vec![],
            evpn_withdrawn: vec![],
        });
        while manager.process_next_route_chunk() {}
        let rows = manager
            .collect_received_flowspec(flow.peer, None, || false)
            .unwrap();
        assert!(
            selected(&manager, &flow) && !rows[0].pending,
            "identical payload re-announced: selected dropped, validation={:?} pending={}",
            rows[0].validation,
            rows[0].pending
        );
        assert_eq!(rows[0].validation, FlowSpecValidationStatus::Feasible);
        let id = (flow.selection_key(), flow.peer, flow.path_id);
        assert!(!manager.flowspec_validation.candidate(&id).unwrap().pending);
        assert!(manager.flowspec_validation.queued.is_empty());
        assert!(
            out_rx.try_recv().is_err(),
            "unchanged rule must not reach downstream as a withdraw or re-announce"
        );
        drain(&mut manager);
        assert!(out_rx.try_recv().is_err());
    }

    #[test]
    fn flowspec_validation_native_cursor_bounds_one_prefix_with_many_add_paths() {
        let (mut manager, _tx, flow, cover) = fixture();
        for id in 1..=2000 {
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .insert(child(&cover, id, 65001));
        }
        assert!(manager.process_flowspec_validation_chunk());
        let job = manager.flowspec_validation.active.as_ref().unwrap();
        let (_, index) = job.after.unwrap();
        assert!(index <= VALIDATION_VISITS_PER_TURN);
        assert!(!selected(&manager, &flow));
        drain(&mut manager);
        assert!(selected(&manager, &flow));
    }

    #[test]
    fn flowspec_validation_burst_before_discovery_revokes_old_selection() {
        let (mut manager, _tx, flow, cover) = fixture();
        drain(&mut manager);
        let changed = HashSet::from([cover.prefix]);
        manager.invalidate_flowspec_dependencies(&changed);
        manager.invalidate_flowspec_dependencies(&changed);
        assert!(
            manager
                .collect_received_flowspec(flow.peer, None, || false)
                .unwrap()[0]
                .pending
        );
        manager.process_flowspec_dependency_chunk();
        assert!(!selected(&manager, &flow));
        let id = (flow.selection_key(), flow.peer, flow.path_id);
        assert!(
            !manager
                .flowspec_validation
                .candidate(&id)
                .unwrap()
                .retain_selected
        );
        drain(&mut manager);
        assert!(selected(&manager, &flow));
    }

    #[test]
    fn flowspec_validation_batch_inventory_and_retirement_visit_rows_once() {
        use rustbgpd_wire::{FlowSpecComponent, NumericMatch};
        use std::cell::Cell;

        let (mut manager, _tx, flow, _cover) = fixture();
        let mut affected = HashSet::new();
        let mut withdrawals = Vec::new();
        for port in 1..=64 {
            for path_id in 0..2 {
                let mut route = flow.clone();
                route.path_id = path_id;
                route
                    .rule
                    .components
                    .push(FlowSpecComponent::DestinationPort(vec![NumericMatch {
                        end_of_list: true,
                        and_bit: false,
                        lt: false,
                        gt: false,
                        eq: true,
                        value: port,
                    }]));
                affected.insert(route.selection_key());
                withdrawals.push(route.key());
                manager
                    .ribs
                    .get_mut(&flow.peer)
                    .unwrap()
                    .insert_flowspec(route);
            }
        }
        let visits = Cell::new(0);
        let checkpoint = || visits.set(visits.get() + 1);
        manager.flowspec_validation.sync_rules(
            &affected,
            &manager.ribs,
            &manager.loc_rib,
            &checkpoint,
        );
        assert_eq!(manager.flowspec_validation.candidates.len(), 65);
        assert_eq!(manager.flowspec_validation.queued.len(), 129);
        // Count actual inventory and retirement checkpoints, not elapsed time.
        // A per-key retained-table scan exceeds this linear bound by >5x.
        let bound = 8 * (129 + affected.len());
        assert!(visits.get() <= bound, "inventory visits: {}", visits.get());
        for key in withdrawals {
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .withdraw_flowspec(&key);
        }
        visits.set(0);
        manager.flowspec_validation.sync_rules(
            &affected,
            &manager.ribs,
            &manager.loc_rib,
            &checkpoint,
        );
        assert!(visits.get() <= bound, "retirement visits: {}", visits.get());
        assert_eq!(manager.flowspec_validation.candidates.len(), 1);
        assert_eq!(manager.flowspec_validation.queued.len(), 1);
        assert_eq!(
            manager
                .flowspec_validation
                .queues
                .iter()
                .map(VecDeque::len)
                .sum::<usize>(),
            1
        );
        assert_eq!(
            manager
                .flowspec_validation
                .destinations
                .get(&flow.rule.destination_prefix().unwrap())
                .unwrap()
                .len(),
            1
        );
        drain(&mut manager);
        assert!(manager.flowspec_validation.queued.is_empty());
        assert!(selected(&manager, &flow));

        let mut disabled = ValidationState::default();
        visits.set(0);
        disabled.sync_rules(&affected, &manager.ribs, &manager.loc_rib, &checkpoint);
        assert_eq!(visits.get(), 0, "off mode must not inventory routes");
        assert!(disabled.candidates.is_empty());
    }

    #[test]
    fn flowspec_validation_disabled_selector_checkpoints_nonmatching_rows() {
        use std::cell::Cell;

        use rustbgpd_wire::{FlowSpecComponent, NumericMatch};

        let (mut manager, _tx, flow, _cover) = fixture();
        manager.flowspec_validation = ValidationState::default();
        let port = |value| {
            FlowSpecComponent::DestinationPort(vec![NumericMatch {
                end_of_list: true,
                and_bit: false,
                lt: false,
                gt: false,
                eq: true,
                value,
            }])
        };
        for value in 1..=500 {
            let mut other = flow.clone();
            other.rule.components.push(port(value));
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .insert_flowspec(other);
        }
        let mut missing = flow.selection_key();
        missing.rule.components.push(port(501));
        for (key, expected) in [(flow.selection_key(), 1), (missing, 0)] {
            let visits = Cell::new(0);
            let rows = manager.flowspec_validation.selection_candidates(
                &key,
                &manager.ribs,
                &manager.loc_rib,
                &|| visits.set(visits.get() + 1),
            );
            assert_eq!(rows.len(), expected);
            assert_eq!(visits.get(), 502, "one peer plus every retained row");
        }
    }

    #[test]
    fn flowspec_validation_off_preserves_selection_without_unicast_cover() {
        let (mut manager, _tx, flow, cover) = fixture();
        manager.flowspec_validation = ValidationState::default();
        manager.loc_rib.recompute(cover.prefix, std::iter::empty());
        manager.recompute_and_distribute_flowspec(&HashSet::from([flow.selection_key()]));
        assert!(selected(&manager, &flow));
        let rows = manager
            .collect_received_flowspec(flow.peer, None, || false)
            .unwrap();
        assert_eq!(rows[0].validation, FlowSpecValidationStatus::Disabled);
        assert!(!rows[0].pending);
        assert!(manager.flowspec_validation.candidates.is_empty());
    }

    #[tokio::test]
    async fn flowspec_validation_without_rules_skips_dependency_probing() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let (_tx, rx) = mpsc::channel(8);
        let (_readiness_tx, readiness_rx) = mpsc::channel(8);
        let mut manager = RibManager::new(rx, mpsc::channel(1).1, None, None, BgpMetrics::new())
            .with_flowspec_validation(65000)
            .with_readiness_queries(readiness_rx);
        let probes = Arc::new(AtomicUsize::new(0));
        manager.replacement_readiness_test_hook = Some(Arc::new({
            let probes = Arc::clone(&probes);
            move |stage| {
                if stage == "flowspec_dependency_inventory" {
                    probes.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
        let revision = manager.flowspec_validation.unicast_revision;
        let changed: HashSet<Prefix> = (0..64)
            .map(|offset| {
                Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::from(0x0a00_0000_u32 + offset),
                    32,
                ))
            })
            .collect();
        manager.invalidate_flowspec_dependencies(&changed);
        assert_eq!(
            probes.load(Ordering::SeqCst),
            0,
            "no retained rule means no per-prefix dependency probing"
        );
        assert!(manager.flowspec_validation.change_queue.is_empty());
        assert_eq!(manager.flowspec_validation.unicast_revision, revision);
    }

    #[test]
    fn flowspec_validation_many_changes_coalesce_at_one_covering_destination() {
        use rustbgpd_wire::{FlowSpecComponent, FlowSpecPrefix};

        let (mut manager, _tx, mut flow, _cover) = fixture();
        let old_key = flow.selection_key();
        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .withdraw_flowspec(&flow.key());
        flow.rule.components = vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V4(
            Ipv4Prefix::new(Ipv4Addr::UNSPECIFIED, 0),
        ))];
        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .insert_flowspec(flow.clone());
        manager.recompute_and_distribute_flowspec(&HashSet::from([old_key, flow.selection_key()]));
        let changed = (0..4096)
            .map(|offset| {
                Prefix::V4(Ipv4Prefix::new(
                    Ipv4Addr::from(0x0a00_0000_u32 + offset),
                    32,
                ))
            })
            .collect();
        manager.invalidate_flowspec_dependencies(&changed);
        assert_eq!(manager.flowspec_validation.change_queue.len(), 1);
        assert!(
            !manager
                .flowspec_validation
                .changes
                .values()
                .next()
                .unwrap()
                .repeated,
            "one coalesced ingest mutation is one invalidation"
        );
        manager.invalidate_flowspec_dependencies(&changed);
        assert_eq!(manager.flowspec_validation.change_queue.len(), 1);
        assert!(
            manager
                .flowspec_validation
                .changes
                .values()
                .next()
                .unwrap()
                .repeated
        );
        drain(&mut manager);
        assert!(manager.flowspec_validation.changes.is_empty());
    }

    #[test]
    fn flowspec_validation_irrelevant_change_keeps_active_scan_revision() {
        let (mut manager, _tx, flow, cover) = fixture();
        for id in 1..=2000 {
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .insert(child(&cover, id, 65001));
        }
        manager.process_flowspec_validation_chunk();
        let id = (flow.selection_key(), flow.peer, flow.path_id);
        let revision = manager.flowspec_validation.candidate(&id).unwrap().revision;
        manager.invalidate_flowspec_dependencies(&HashSet::from([Prefix::V4(Ipv4Prefix::new(
            Ipv4Addr::new(203, 0, 113, 0),
            24,
        ))]));
        assert_eq!(
            manager.flowspec_validation.candidate(&id).unwrap().revision,
            revision
        );
        assert!(manager.flowspec_validation.active.is_some());
        drain(&mut manager);
        assert!(selected(&manager, &flow));
    }

    #[tokio::test]
    async fn flowspec_validation_cover_change_many_rules_has_bounded_discovery_and_interior_readiness()
     {
        use rustbgpd_wire::{FlowSpecComponent, NumericMatch};
        use std::sync::Mutex;
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::sync::oneshot;

        let (mut manager, _tx, flow, mut cover) = fixture();
        let mut affected = HashSet::from([flow.selection_key()]);
        for port in 1..=200 {
            let mut rule = flow.clone();
            rule.rule
                .components
                .push(FlowSpecComponent::DestinationPort(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: port,
                }]));
            affected.insert(rule.selection_key());
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .insert_flowspec(rule);
        }
        manager.recompute_and_distribute_flowspec(&affected);
        drain(&mut manager);
        assert_eq!(manager.loc_rib.flowspec_len(), 201);

        let (readiness_tx, readiness_rx) = mpsc::channel(8);
        manager = manager.with_readiness_queries(readiness_rx);
        manager.flush_poll_budget = Duration::ZERO;
        let sent = Arc::new(AtomicBool::new(false));
        let observed = Arc::new(AtomicBool::new(false));
        let pending = Arc::new(Mutex::new(
            None::<oneshot::Receiver<Result<usize, crate::RibReadinessError>>>,
        ));
        manager.replacement_readiness_test_hook = Some(Arc::new({
            let sent = Arc::clone(&sent);
            let observed = Arc::clone(&observed);
            let pending = Arc::clone(&pending);
            move |stage| {
                if let Some(mut reply) = pending.lock().unwrap().take() {
                    assert_eq!(reply.try_recv().unwrap().unwrap(), 1);
                    observed.store(true, Ordering::SeqCst);
                }
                if stage == "flowspec_dependencies" && !sent.swap(true, Ordering::SeqCst) {
                    let (reply, response) = oneshot::channel();
                    readiness_tx
                        .try_send(crate::RibReadinessQuery::LocRibCount {
                            reply,
                            enqueued: Instant::now(),
                        })
                        .unwrap();
                    *pending.lock().unwrap() = Some(response);
                }
            }
        }));
        cover.attributes = Arc::new(vec![path(65002)]);
        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .insert(cover.clone());
        manager
            .loc_rib
            .recompute(cover.prefix, std::iter::once(&cover));
        manager.invalidate_flowspec_dependencies(&HashSet::from([cover.prefix]));
        manager.process_flowspec_validation_chunk();
        assert!(
            observed.load(Ordering::SeqCst),
            "readiness must complete inside the work unit"
        );
        assert!(manager.loc_rib.flowspec_len() >= 201 - DEPENDENCY_RULES_PER_TURN);
        assert!(manager.flowspec_validation.dependency.is_some());
        manager.replacement_readiness_test_hook = None;
        drain(&mut manager);
        assert_eq!(manager.loc_rib.flowspec_len(), 0);
    }

    #[test]
    fn flowspec_validation_retired_paths_leave_no_queue_or_destination_orphans() {
        let (mut manager, _tx, flow, _cover) = fixture();
        for path_id in 1..=500 {
            let mut next = flow.clone();
            next.path_id = path_id;
            let key = next.key();
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .insert_flowspec(next);
            manager.recompute_and_distribute_flowspec(&HashSet::from([flow.selection_key()]));
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .withdraw_flowspec(&key);
            manager.recompute_and_distribute_flowspec(&HashSet::from([flow.selection_key()]));
            assert!(
                manager
                    .flowspec_validation
                    .queues
                    .iter()
                    .map(VecDeque::len)
                    .sum::<usize>()
                    <= 1
            );
        }
        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .withdraw_flowspec(&flow.key());
        manager.recompute_and_distribute_flowspec(&HashSet::from([flow.selection_key()]));
        drain(&mut manager);
        assert!(manager.flowspec_validation.candidates.is_empty());
        assert!(
            manager
                .flowspec_validation
                .queues
                .iter()
                .all(VecDeque::is_empty)
        );
        assert!(manager.flowspec_validation.queued.is_empty());
        assert!(manager.flowspec_validation.active.is_none());
        assert!(
            manager
                .flowspec_validation
                .destinations
                .iter_from(None)
                .next()
                .is_none()
        );
    }

    #[test]
    fn flowspec_validation_received_query_cancels_during_filtered_out_walk() {
        let (mut manager, _tx, flow, _cover) = fixture();
        for path_id in 1..=1000 {
            let mut next = flow.clone();
            next.path_id = path_id;
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .insert_flowspec(next);
        }
        let filter: RibRowFilter<ReceivedFlowSpecRoute> = Box::new(|_| false);
        let mut checks = 0;
        let rows = manager.collect_received_flowspec(flow.peer, Some(&filter), || {
            checks += 1;
            checks == 2
        });
        assert!(rows.is_none());
        assert_eq!(checks, 2);
    }

    #[tokio::test]
    async fn flowspec_validation_deferred_unicast_invalidates_and_parks_active_scan() {
        let (mut manager, _tx, flow, cover) = fixture();
        for id in 1..=500 {
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .insert(child(&cover, id, 65001));
        }
        manager.process_flowspec_validation_chunk();
        let id = (flow.selection_key(), flow.peer, flow.path_id);
        let revision = manager.flowspec_validation.candidate(&id).unwrap().revision;
        manager = manager.with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: flow.peer,
                families: vec![(Afi::Ipv4, Safi::Unicast)],
            }],
        });
        let conflicting = child(&cover, 600, 65002);
        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .insert(conflicting.clone());
        manager.distribute_changes(&HashSet::new(), &HashSet::from([conflicting.prefix]));
        assert_ne!(
            manager.flowspec_validation.candidate(&id).unwrap().revision,
            revision
        );
        manager.process_flowspec_validation_chunk();
        assert!(
            !manager.process_flowspec_validation_chunk(),
            "held queue must not spin"
        );
        assert!(!selected(&manager, &flow));
        manager.selection_deferral = None;
        drain(&mut manager);
        assert!(!selected(&manager, &flow));
        assert_eq!(
            manager
                .collect_received_flowspec(flow.peer, None, || false)
                .unwrap()[0]
                .reason,
            Some("conflicting_more_specific")
        );
    }

    #[tokio::test]
    async fn flowspec_validation_held_family_cannot_hide_runnable_family() {
        use rustbgpd_wire::{FlowSpecComponent, FlowSpecPrefix, Ipv6PrefixOffset, NumericMatch};

        let (mut manager, _tx, flow, cover) = fixture();
        let mut affected = HashSet::new();
        for port in 1..=400 {
            let mut next = flow.clone();
            next.rule
                .components
                .push(FlowSpecComponent::DestinationPort(vec![NumericMatch {
                    end_of_list: true,
                    and_bit: false,
                    lt: false,
                    gt: false,
                    eq: true,
                    value: port,
                }]));
            affected.insert(next.selection_key());
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .insert_flowspec(next);
        }
        for id in 1..=2000 {
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .insert(child(&cover, id, 65001));
        }
        let mut v6_cover = cover;
        v6_cover.prefix = Prefix::V6(Ipv6Prefix::new("2001:db8::".parse().unwrap(), 32));
        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .insert(v6_cover.clone());
        manager
            .loc_rib
            .recompute(v6_cover.prefix, std::iter::once(&v6_cover));
        let mut v6 = flow.clone();
        v6.afi = Afi::Ipv6;
        v6.rule.components = vec![FlowSpecComponent::DestinationPrefix(FlowSpecPrefix::V6(
            Ipv6PrefixOffset {
                prefix: Ipv6Prefix::new("2001:db8:1::".parse().unwrap(), 48),
                offset: 0,
            },
        ))];
        affected.insert(v6.selection_key());
        manager
            .ribs
            .get_mut(&flow.peer)
            .unwrap()
            .insert_flowspec(v6.clone());
        manager.recompute_and_distribute_flowspec(&affected);
        manager = manager.with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: flow.peer,
                families: vec![(Afi::Ipv4, Safi::Unicast)],
            }],
        });
        assert!(manager.flowspec_validation.queues[0].len() > VALIDATION_VISITS_PER_TURN);
        manager.process_flowspec_validation_chunk();
        assert!(
            selected(&manager, &v6),
            "held IPv4 jobs cannot strand IPv6 work"
        );
        assert!(
            !manager.process_flowspec_validation_chunk(),
            "only held jobs remain"
        );

        manager = manager.with_selection_deferral(SelectionDeferralConfig {
            timeout: Duration::from_secs(60),
            waiters: vec![SelectionDeferralWaiterConfig {
                peer: flow.peer,
                families: vec![(Afi::Ipv4, Safi::Unicast), (Afi::Ipv6, Safi::Unicast)],
            }],
        });
        manager.invalidate_flowspec_dependencies(&HashSet::from([v6_cover.prefix]));
        manager.process_flowspec_validation_chunk();
        assert!(
            !manager.process_flowspec_validation_chunk(),
            "both held families must sleep"
        );
        let first_v4 = manager.flowspec_validation.queues[0]
            .front()
            .unwrap()
            .clone();
        manager.selection_deferral = None;
        manager.process_flowspec_validation_chunk();
        assert_eq!(
            manager.flowspec_validation.active.as_ref().unwrap().id,
            first_v4,
            "release resumes the held family's FIFO"
        );
    }

    #[tokio::test]
    async fn flowspec_validation_actor_finishes_multiple_slices_without_new_input() {
        let (mut manager, tx, flow, cover) = fixture();
        for id in 1..=2000 {
            manager
                .ribs
                .get_mut(&flow.peer)
                .unwrap()
                .insert(child(&cover, id, 65001));
        }
        let metrics = manager.metrics.clone();
        let task = tokio::spawn(manager.run());
        // Observe the shared registry directly: querying the actor here would
        // wake a broken implementation and conceal its no-input stall.
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let selected = metrics
                    .registry()
                    .gather()
                    .iter()
                    .filter(|family| family.name() == "bgp_rib_loc_prefixes")
                    .flat_map(|family| family.get_metric().iter())
                    .any(|metric| {
                        metric
                            .get_label()
                            .iter()
                            .any(|label| label.value() == "flowspec")
                            && metric.get_gauge().value() >= 1.0
                    });
                if selected {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queued validation must make progress without new messages");
        drop(tx);
        task.await.unwrap();
    }
}
