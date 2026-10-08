//! ADR-0137 conditional-advertisement condition tracker.
//!
//! Each installed definition tracks an `observed` condition (present, absent,
//! or unknown) and an `applied` state (pending, advertise, or suppress).
//! Observations are recomputed only for definitions indexed by a condition
//! prefix that a selection pass reported as affected, so ordinary route churn
//! costs one hash probe per affected prefix and never walks the table. A
//! changed known observation must stay stable for `settle_time` before it
//! applies; `unknown` (a `condition_policy` evaluation error) cancels the
//! timer and holds the applied state.
//!
//! The export gate that consumes `applied` is ADR-0137 slice 3. Until then
//! the daemon refuses configs that define conditional advertisements, so
//! definitions are installed only by tests.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use rustbgpd_policy::{PolicyAction, PolicyChain, RouteContext};
use rustbgpd_wire::{Afi, Prefix, Safi};
use tokio::time::Instant;
use tracing::info;

use super::RibManager;
use super::helpers::{LOCAL_PEER, prefix_family};
use crate::fast_hash::FastMap;
use crate::route::Route;

/// Condition state in which a definition's controlled routes may be
/// advertised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConditionalAdvertiseIf {
    /// Advertise while a condition candidate is present.
    Present,
    /// Advertise while no condition candidate is present.
    Absent,
}

impl ConditionalAdvertiseIf {
    const fn label(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
        }
    }
}

/// One resolved conditional-advertisement definition (ADR-0137). Equality is
/// content identity: a reinstalled definition with equal content keeps its
/// tracker state.
#[derive(Clone, Debug, PartialEq)]
pub struct ConditionalAdvertisement {
    /// Configured definition name; the metric and log label.
    pub name: Arc<str>,
    /// Predicate selecting the controlled routes (consumed by the export gate).
    pub advertise_policy: PolicyChain,
    /// Condition state in which controlled routes may be advertised.
    pub advertise_if: ConditionalAdvertiseIf,
    /// Exact unicast prefixes whose candidates decide the condition.
    pub condition_prefixes: Vec<Prefix>,
    /// Optional predicate over each condition candidate.
    pub condition_policy: Option<PolicyChain>,
    /// How long a changed known observation must stay stable to apply.
    pub settle_time: Duration,
}

/// Observed condition of one definition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ConditionObservation {
    Present,
    Absent,
    /// A `condition_policy` evaluation error and no clean match.
    Unknown,
}

impl ConditionObservation {
    const fn label(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::Absent => "absent",
            Self::Unknown => "unknown",
        }
    }
}

/// The state the export gate uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AppliedConditionalState {
    /// Not yet settled since install at startup; suppresses.
    Pending,
    Advertise,
    Suppress,
}

#[derive(Clone, Debug)]
struct DefinitionState {
    definition: Arc<ConditionalAdvertisement>,
    observed: ConditionObservation,
    observed_since: Instant,
    deadline: Option<Instant>,
    applied: AppliedConditionalState,
}

/// Tracker state owned by the RIB actor.
#[derive(Default)]
pub(super) struct ConditionalAdvertisementTracker {
    definitions: BTreeMap<Arc<str>, DefinitionState>,
    by_prefix: FastMap<Prefix, Vec<Arc<str>>>,
    installed: bool,
    /// Condition candidates visited, for the no-table-walk proof.
    #[cfg(test)]
    candidate_visits: std::sync::atomic::AtomicUsize,
}

/// Tracker state captured by an install, for generation compensation. The
/// restore reinstates it instead of evaluating the restored definitions again.
#[derive(Clone, Debug)]
pub struct ConditionalAdvertisementCapture {
    definitions: BTreeMap<Arc<str>, DefinitionState>,
    installed: bool,
}

enum CandidateVerdict {
    Match,
    Miss,
    Error,
}

impl RibManager {
    /// Install a definition set (ADR-0137 Decision 6). The first install,
    /// at startup, leaves new definitions `pending` behind the debounce. A
    /// later install keeps the state of definitions with unchanged content
    /// and evaluates new or changed definitions immediately. Returns the
    /// prior state for compensation and the names whose applied state
    /// changed.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "ADR-0137 slice 3 installs definitions from the export-policy batch"
        )
    )]
    pub(super) fn install_conditional_advertisements(
        &mut self,
        definitions: Vec<ConditionalAdvertisement>,
    ) -> (ConditionalAdvertisementCapture, Vec<Arc<str>>) {
        let now = Instant::now();
        let startup = !self.conditional_advertisements.installed;
        let capture = ConditionalAdvertisementCapture {
            definitions: self.conditional_advertisements.definitions.clone(),
            installed: self.conditional_advertisements.installed,
        };
        let mut prior = std::mem::take(&mut self.conditional_advertisements.definitions);
        let mut next = BTreeMap::new();
        let mut transitions = Vec::new();
        for definition in definitions {
            let name = Arc::clone(&definition.name);
            let previous = prior.remove(&name);
            if let Some(state) = previous
                .as_ref()
                .filter(|state| *state.definition == definition)
            {
                next.insert(name, state.clone());
                continue;
            }
            let definition = Arc::new(definition);
            let observed = self.observe_condition(&definition);
            let deferred = self.condition_deferred(&definition);
            let prior_applied = previous.as_ref().map(|state| state.applied);
            let mut state = DefinitionState {
                definition,
                observed,
                observed_since: now,
                deadline: None,
                applied: prior_applied.unwrap_or(AppliedConditionalState::Pending),
            };
            if let Some(previous) = &previous
                && previous.definition.advertise_if != state.definition.advertise_if
            {
                self.metrics.reap_conditional_advertisement_series(
                    &name,
                    previous.definition.advertise_if.label(),
                    true,
                );
            }
            if observed != ConditionObservation::Unknown && !deferred {
                if startup {
                    self.arm_or_apply(&mut state, now, &mut transitions);
                } else {
                    Self::apply_observation(&self.metrics, &mut state, &mut transitions);
                }
            }
            self.publish_conditional_metrics(&state);
            next.insert(name, state);
        }
        for (name, state) in prior {
            self.metrics.reap_conditional_advertisement_series(
                &name,
                state.definition.advertise_if.label(),
                false,
            );
            if state.applied != AppliedConditionalState::Pending {
                transitions.push(name);
            }
        }
        self.conditional_advertisements.definitions = next;
        self.conditional_advertisements.installed = true;
        self.rebuild_conditional_index();
        (capture, transitions)
    }

    /// Reinstate the state captured by [`Self::install_conditional_advertisements`]
    /// (ADR-0137 Decision 6). The restored applied states and settle deadlines
    /// stand; only an observation the RIB has since changed restarts the
    /// debounce from now. Returns the names whose applied state differs from
    /// the replaced set.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "ADR-0137 slice 3 restores definitions from the export-policy rollback batch"
        )
    )]
    pub(super) fn restore_conditional_advertisements(
        &mut self,
        capture: ConditionalAdvertisementCapture,
    ) -> Vec<Arc<str>> {
        let now = Instant::now();
        let replaced = std::mem::replace(
            &mut self.conditional_advertisements.definitions,
            capture.definitions,
        );
        self.conditional_advertisements.installed = capture.installed;
        self.rebuild_conditional_index();
        for (name, state) in &replaced {
            let restored = self.conditional_advertisements.definitions.get(name);
            if restored.is_none_or(|restored| {
                restored.definition.advertise_if != state.definition.advertise_if
            }) {
                self.metrics.reap_conditional_advertisement_series(
                    name,
                    state.definition.advertise_if.label(),
                    restored.is_some(),
                );
            }
        }
        let names: Vec<_> = self
            .conditional_advertisements
            .definitions
            .keys()
            .cloned()
            .collect();
        let mut transitions = Vec::new();
        for name in &names {
            self.reobserve_definition(name, now, &mut transitions);
            if let Some(state) = self.conditional_advertisements.definitions.get(name) {
                self.publish_conditional_metrics(state);
            }
        }
        let mut changed: BTreeSet<Arc<str>> = transitions.into_iter().collect();
        for (name, state) in &replaced {
            let restored = self
                .conditional_advertisements
                .definitions
                .get(name)
                .map(|state| state.applied);
            if restored != Some(state.applied) {
                changed.insert(Arc::clone(name));
            }
        }
        for (name, state) in &self.conditional_advertisements.definitions {
            if !replaced.contains_key(name) && state.applied != AppliedConditionalState::Pending {
                changed.insert(Arc::clone(name));
            }
        }
        changed.into_iter().collect()
    }

    /// Recompute the observation of every definition indexed by an affected
    /// prefix. Called by each distribution pass, before deferral filtering,
    /// so held families keep observing while their timers stay unarmed.
    pub(super) fn observe_conditional_advertisement_prefixes<'a>(
        &mut self,
        affected: impl IntoIterator<Item = &'a Prefix>,
    ) -> Vec<Arc<str>> {
        if self.conditional_advertisements.definitions.is_empty() {
            return Vec::new();
        }
        let names: BTreeSet<Arc<str>> = affected
            .into_iter()
            .filter_map(|prefix| self.conditional_advertisements.by_prefix.get(prefix))
            .flatten()
            .cloned()
            .collect();
        let now = Instant::now();
        let mut transitions = Vec::new();
        for name in &names {
            self.reobserve_definition(name, now, &mut transitions);
        }
        transitions
    }

    /// A released RFC 4724 family re-observes its definitions and arms a
    /// fresh settle interval from the release time.
    pub(super) fn release_conditional_advertisement_family(&mut self, family: (Afi, Safi)) {
        if self.conditional_advertisements.definitions.is_empty() {
            return;
        }
        let names: Vec<_> = self
            .conditional_advertisements
            .definitions
            .iter()
            .filter(|(_, state)| {
                state
                    .definition
                    .condition_prefixes
                    .iter()
                    .any(|prefix| prefix_family(prefix) == family)
            })
            .map(|(name, _)| Arc::clone(name))
            .collect();
        let now = Instant::now();
        let mut transitions = Vec::new();
        for name in names {
            let Some(mut state) = self.conditional_advertisements.definitions.remove(&name) else {
                continue;
            };
            state.observed = self.observe_condition(&state.definition);
            state.observed_since = now;
            state.deadline = None;
            if state.observed != ConditionObservation::Unknown
                && !self.condition_deferred(&state.definition)
            {
                self.arm_or_apply(&mut state, now, &mut transitions);
            }
            self.publish_conditional_metrics(&state);
            self.conditional_advertisements
                .definitions
                .insert(name, state);
        }
    }

    /// Re-observe definitions whose `condition_policy` references a swapped
    /// dataset (ADR-0137 Decision 6), under the ordinary debounce.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "ADR-0137 slice 3 wires dataset refresh once definitions are installed"
        )
    )]
    pub(super) fn reevaluate_conditional_advertisement_datasets(
        &mut self,
        swapped: &[String],
    ) -> Vec<Arc<str>> {
        let names: Vec<_> = self
            .conditional_advertisements
            .definitions
            .iter()
            .filter(|(_, state)| {
                state
                    .definition
                    .condition_policy
                    .as_ref()
                    .is_some_and(|policy| {
                        swapped.iter().any(|name| policy.references_dataset(name))
                    })
            })
            .map(|(name, _)| Arc::clone(name))
            .collect();
        let now = Instant::now();
        let mut transitions = Vec::new();
        for name in &names {
            self.reobserve_definition(name, now, &mut transitions);
        }
        transitions
    }

    /// Earliest armed settle deadline.
    pub(super) fn next_conditional_advertisement_deadline(&self) -> Option<Instant> {
        self.conditional_advertisements
            .definitions
            .values()
            .filter_map(|state| state.deadline)
            .min()
    }

    /// Apply every definition whose settle deadline has passed. Returns the
    /// names whose applied state changed.
    pub(super) fn fire_conditional_advertisement_timers(&mut self) -> Vec<Arc<str>> {
        let now = Instant::now();
        let due: Vec<_> = self
            .conditional_advertisements
            .definitions
            .iter()
            .filter(|(_, state)| state.deadline.is_some_and(|deadline| deadline <= now))
            .map(|(name, _)| Arc::clone(name))
            .collect();
        let mut transitions = Vec::new();
        for name in due {
            let Some(state) = self.conditional_advertisements.definitions.get_mut(&name) else {
                continue;
            };
            state.deadline = None;
            Self::apply_observation(&self.metrics, state, &mut transitions);
        }
        transitions
    }

    fn reobserve_definition(&mut self, name: &Arc<str>, now: Instant, out: &mut Vec<Arc<str>>) {
        let Some(mut state) = self.conditional_advertisements.definitions.remove(name) else {
            return;
        };
        let observed = self.observe_condition(&state.definition);
        if observed != state.observed {
            state.observed = observed;
            state.observed_since = now;
            state.deadline = None;
            if observed != ConditionObservation::Unknown
                && !self.condition_deferred(&state.definition)
            {
                self.arm_or_apply(&mut state, now, out);
            }
            self.publish_conditional_metrics(&state);
        }
        self.conditional_advertisements
            .definitions
            .insert(Arc::clone(name), state);
    }

    fn arm_or_apply(&self, state: &mut DefinitionState, now: Instant, out: &mut Vec<Arc<str>>) {
        if state.definition.settle_time.is_zero() {
            Self::apply_observation(&self.metrics, state, out);
        } else {
            state.deadline = Some(now + state.definition.settle_time);
        }
    }

    /// Move `applied` to what a known observation implies. `unknown` holds.
    fn apply_observation(
        metrics: &rustbgpd_telemetry::BgpMetrics,
        state: &mut DefinitionState,
        out: &mut Vec<Arc<str>>,
    ) {
        let target = match (state.observed, state.definition.advertise_if) {
            (ConditionObservation::Unknown, _) => return,
            (ConditionObservation::Present, ConditionalAdvertiseIf::Present)
            | (ConditionObservation::Absent, ConditionalAdvertiseIf::Absent) => {
                AppliedConditionalState::Advertise
            }
            _ => AppliedConditionalState::Suppress,
        };
        if state.applied == target {
            return;
        }
        info!(
            definition = %state.definition.name,
            from = ?state.applied,
            to = ?target,
            observed = state.observed.label(),
            advertise_if = state.definition.advertise_if.label(),
            "conditional advertisement transition"
        );
        state.applied = target;
        metrics.record_conditional_advertisement_transition(&state.definition.name);
        metrics.set_conditional_advertisement_permitted(
            &state.definition.name,
            state.definition.advertise_if.label(),
            target == AppliedConditionalState::Advertise,
        );
        out.push(Arc::clone(&state.definition.name));
    }

    fn publish_conditional_metrics(&self, state: &DefinitionState) {
        let name = &state.definition.name;
        self.metrics
            .set_conditional_advertisement_condition(name, state.observed.label());
        self.metrics.set_conditional_advertisement_permitted(
            name,
            state.definition.advertise_if.label(),
            state.applied == AppliedConditionalState::Advertise,
        );
    }

    fn condition_deferred(&self, definition: &ConditionalAdvertisement) -> bool {
        definition
            .condition_prefixes
            .iter()
            .any(|prefix| self.selection_deferred(prefix_family(prefix)))
    }

    fn rebuild_conditional_index(&mut self) {
        let tracker = &mut self.conditional_advertisements;
        tracker.by_prefix.clear();
        for (name, state) in &tracker.definitions {
            for prefix in &state.definition.condition_prefixes {
                tracker
                    .by_prefix
                    .entry(*prefix)
                    .or_default()
                    .push(Arc::clone(name));
            }
        }
    }

    /// Any current candidate (received and import-accepted, stale, losing
    /// Add-Path, or locally injected) that satisfies the condition makes it
    /// present. An evaluation error is neither a match nor a miss.
    fn observe_condition(&self, definition: &ConditionalAdvertisement) -> ConditionObservation {
        let mut errored = false;
        for prefix in &definition.condition_prefixes {
            for route in Self::unicast_candidates(&self.ribs, &self.unicast_prefix_peers, prefix) {
                #[cfg(test)]
                self.conditional_advertisements
                    .candidate_visits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(policy) = &definition.condition_policy else {
                    return ConditionObservation::Present;
                };
                match self.condition_candidate_verdict(policy, route) {
                    CandidateVerdict::Match => return ConditionObservation::Present,
                    CandidateVerdict::Error => errored = true,
                    CandidateVerdict::Miss => {}
                }
            }
        }
        if errored {
            ConditionObservation::Unknown
        } else {
            ConditionObservation::Absent
        }
    }

    /// Evaluate `condition_policy` for one candidate. A received candidate
    /// sees its source peer's address, configured ASN, and group; a locally
    /// injected one (`LOCAL_PEER`) has no peer context at all.
    fn condition_candidate_verdict(&self, policy: &PolicyChain, route: &Route) -> CandidateVerdict {
        let (peer_address, peer_asn, peer_group): (Option<IpAddr>, Option<u32>, Option<&str>) =
            if route.peer == LOCAL_PEER {
                (None, None, None)
            } else {
                (
                    Some(route.peer),
                    self.peer_asn.get(&route.peer).copied(),
                    self.peer_group.get(&route.peer).map(String::as_str),
                )
            };
        let aspath_str = if policy.requires_as_path_string() {
            route
                .as_path()
                .map_or_else(String::new, rustbgpd_wire::AsPath::to_aspath_string)
        } else {
            String::new()
        };
        let ctx = RouteContext {
            prefix: Some(route.prefix),
            next_hop: Some(route.next_hop),
            extended_communities: route.extended_communities(),
            communities: route.communities(),
            large_communities: route.large_communities(),
            as_path_str: &aspath_str,
            as_path: route.as_path(),
            as_path_len: route.as_path().map_or(0, rustbgpd_wire::AsPath::len),
            origin_asn: route.as_path().and_then(rustbgpd_wire::AsPath::origin_asn),
            validation_state: route.validation_state,
            aspa_state: route.aspa_state,
            peer_address,
            peer_asn,
            peer_group,
            route_type: Some(super::distribution::route_type(route.origin_type)),
            family: Some(super::helpers::unicast_route_family(&route.prefix)),
            evpn_route_type: None,
            local_pref: route.local_pref_attr(),
            med: route.med_attr(),
        };
        let (_, evaluation) = policy.evaluate_with_attribution(&ctx);
        if evaluation.eval_error.is_some() {
            CandidateVerdict::Error
        } else if evaluation.action == PolicyAction::Permit {
            CandidateVerdict::Match
        } else {
            CandidateVerdict::Miss
        }
    }

    #[cfg(test)]
    pub(super) fn conditional_advertisement_state(
        &self,
        name: &str,
    ) -> Option<(
        ConditionObservation,
        AppliedConditionalState,
        Option<Instant>,
    )> {
        self.conditional_advertisements
            .definitions
            .get(name)
            .map(|state| (state.observed, state.applied, state.deadline))
    }

    #[cfg(test)]
    pub(super) fn conditional_advertisement_candidate_visits(&self) -> usize {
        self.conditional_advertisements
            .candidate_visits
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}
