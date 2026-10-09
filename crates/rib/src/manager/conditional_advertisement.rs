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
//! The tracker also owns the address-keyed attachments the export gate reads:
//! one install carries both, so the gate never sees an attachment whose
//! definition is missing. The gate itself ([`ConditionalGate`]) runs last
//! before the export chain in every unicast export body.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
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
    /// Configured label: `present` or `absent`.
    #[must_use]
    pub const fn label(self) -> &'static str {
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

impl AppliedConditionalState {
    const fn label(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Advertise => "advertise",
            Self::Suppress => "suppress",
        }
    }
}

/// One installed definition's state, for `ListConditionalAdvertisements`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConditionalAdvertisementStatus {
    /// Configured definition name.
    pub name: Arc<str>,
    /// Condition state in which controlled routes may be advertised.
    pub advertise_if: ConditionalAdvertiseIf,
    /// Each condition prefix with its own current observation: `present`,
    /// `absent`, or `unknown`.
    pub conditions: Vec<(Prefix, &'static str)>,
    /// Tracked observation of the whole condition.
    pub observed: &'static str,
    /// Time since the tracked observation last changed, or since install.
    pub observed_for: Duration,
    /// Applied gate state: `pending`, `advertise`, or `suppress`.
    pub applied: &'static str,
    /// Configured settle interval.
    pub settle_time: Duration,
    /// Time left before an armed settle timer applies the observation.
    pub settle_remaining: Option<Duration>,
    /// RFC 4724 selection deferral holds a condition family.
    pub selection_deferred: bool,
    /// Static neighbors with this definition attached.
    pub attached_peers: Vec<IpAddr>,
}

/// One complete conditional-advertisement install (ADR-0137): every
/// definition some static neighbor attaches, and each such neighbor's
/// attachment names in configured order. Static neighbors only, so the
/// neighbor address is the attachment key.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ConditionalAdvertisementSet {
    /// Resolved definitions referenced by at least one attachment.
    pub definitions: Vec<ConditionalAdvertisement>,
    /// Attached definition names per static neighbor address.
    pub attachments: BTreeMap<IpAddr, Vec<Arc<str>>>,
}

impl ConditionalAdvertisementSet {
    /// Whether an `advertise_policy` attached to `peer` references any of
    /// `datasets` (the dataset-refresh export dependency).
    #[must_use]
    pub fn advertise_policy_references(&self, peer: IpAddr, datasets: &[String]) -> bool {
        self.attachments.get(&peer).is_some_and(|names| {
            self.definitions.iter().any(|definition| {
                names.contains(&definition.name)
                    && datasets
                        .iter()
                        .any(|name| definition.advertise_policy.references_dataset(name))
            })
        })
    }

    /// Whether any `condition_policy` references one of `datasets`.
    #[must_use]
    pub fn condition_policy_references(&self, datasets: &[String]) -> bool {
        self.definitions.iter().any(|definition| {
            definition
                .condition_policy
                .as_ref()
                .is_some_and(|policy| datasets.iter().any(|name| policy.references_dataset(name)))
        })
    }
}

#[derive(Clone, Debug)]
struct DefinitionState {
    definition: Arc<ConditionalAdvertisement>,
    observed: ConditionObservation,
    /// Each condition prefix's own observation, in `condition_prefixes`
    /// order, recorded whenever `observed` is recomputed. The status query
    /// copies it instead of evaluating policies on the actor.
    conditions: Vec<ConditionObservation>,
    observed_since: Instant,
    deadline: Option<Instant>,
    applied: AppliedConditionalState,
}

/// Tracker state owned by the RIB actor.
#[derive(Default)]
pub(super) struct ConditionalAdvertisementTracker {
    definitions: BTreeMap<Arc<str>, DefinitionState>,
    /// Attached definition names per static neighbor address. Installed
    /// together with `definitions`; the only attachment state the gate reads.
    attachments: BTreeMap<IpAddr, Vec<Arc<str>>>,
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
    attachments: BTreeMap<IpAddr, Vec<Arc<str>>>,
    installed: bool,
}

enum CandidateVerdict {
    Match,
    Miss,
    Error(rustbgpd_policy::EvalError),
}

impl RibManager {
    /// Install a definition set (ADR-0137 Decision 6). The first install,
    /// at startup, leaves new definitions `pending` behind the debounce. A
    /// later install keeps the state of definitions with unchanged content
    /// and evaluates new or changed definitions immediately. Returns the
    /// prior state for compensation and the names whose applied state
    /// changed.
    pub(super) fn install_conditional_advertisements(
        &mut self,
        definitions: Vec<ConditionalAdvertisement>,
    ) -> (ConditionalAdvertisementCapture, Vec<Arc<str>>) {
        let now = Instant::now();
        let startup = !self.conditional_advertisements.installed;
        let capture = self.capture_conditional_advertisements();
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
            let (observed, conditions) = self.observe_condition(&definition);
            let deferred = self.condition_deferred(&definition);
            let prior_applied = previous.as_ref().map(|state| state.applied);
            let mut state = DefinitionState {
                definition,
                observed,
                conditions,
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

    fn capture_conditional_advertisements(&self) -> ConditionalAdvertisementCapture {
        ConditionalAdvertisementCapture {
            definitions: self.conditional_advertisements.definitions.clone(),
            attachments: self.conditional_advertisements.attachments.clone(),
            installed: self.conditional_advertisements.installed,
        }
    }

    /// Reinstate the state captured by [`Self::install_conditional_advertisements`]
    /// (ADR-0137 Decision 6). The restored applied states and settle deadlines
    /// stand; only an observation the RIB has since changed restarts the
    /// debounce from now. Returns the names whose applied state differs from
    /// the replaced set.
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
        self.conditional_advertisements.attachments = capture.attachments;
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
        // The restore itself changes `applied` back to the captured value:
        // that is a transition like any other, recorded before re-observation
        // so the captured deadline stands.
        for (name, state) in &self.conditional_advertisements.definitions {
            if let Some(previous) = replaced.get(name)
                && previous.applied != state.applied
            {
                Self::record_transition(&self.metrics, state, previous.applied);
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
            let Some(mut state) = self.conditional_advertisements.definitions.remove(name) else {
                continue;
            };
            // A state captured during selection deferral has no deadline;
            // if deferral was released while the failed generation was
            // installed, that release armed the replaced state, not this
            // one. Arm a fresh interval so it cannot stay unsettled forever.
            if state.deadline.is_none()
                && Self::target(&state).is_some_and(|target| target != state.applied)
                && !self.condition_deferred(&state.definition)
            {
                state.observed_since = now;
                self.arm_or_apply(&mut state, now, &mut transitions);
            }
            self.publish_conditional_metrics(&state);
            self.conditional_advertisements
                .definitions
                .insert(Arc::clone(name), state);
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
        self.mark_conditional_advertisement_peers_dirty(&transitions);
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
            (state.observed, state.conditions) = self.observe_condition(&state.definition);
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
        self.mark_conditional_advertisement_peers_dirty(&transitions);
    }

    /// Re-observe definitions whose `condition_policy` references a swapped
    /// dataset (ADR-0137 Decision 6), under the ordinary debounce.
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
        self.mark_conditional_advertisement_peers_dirty(&transitions);
        transitions
    }

    /// Re-observe the definitions whose `condition_policy` sees `source` as
    /// the peer context of a current condition candidate, after that peer's
    /// policy context (its group) changed without any route churn.
    pub(super) fn reobserve_conditional_advertisement_source(
        &mut self,
        source: IpAddr,
    ) -> Vec<Arc<str>> {
        let Some(rib) = self.ribs.get(&source) else {
            return Vec::new();
        };
        let names: Vec<_> = self
            .conditional_advertisements
            .definitions
            .iter()
            .filter(|(_, state)| {
                state.definition.condition_policy.is_some()
                    && state
                        .definition
                        .condition_prefixes
                        .iter()
                        .any(|prefix| rib.iter_prefix(prefix).next().is_some())
            })
            .map(|(name, _)| Arc::clone(name))
            .collect();
        let now = Instant::now();
        let mut transitions = Vec::new();
        for name in &names {
            self.reobserve_definition(name, now, &mut transitions);
        }
        self.mark_conditional_advertisement_peers_dirty(&transitions);
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

    /// Apply every definition whose settle deadline has passed, marking the
    /// attached peers of each applied transition dirty. Returns the names
    /// whose applied state changed.
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
        self.mark_conditional_advertisement_peers_dirty(&transitions);
        transitions
    }

    fn reobserve_definition(&mut self, name: &Arc<str>, now: Instant, out: &mut Vec<Arc<str>>) {
        let Some(mut state) = self.conditional_advertisements.definitions.remove(name) else {
            return;
        };
        let (observed, conditions) = self.observe_condition(&state.definition);
        state.conditions = conditions;
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

    /// The applied state a known observation implies; `unknown` implies none.
    fn target(state: &DefinitionState) -> Option<AppliedConditionalState> {
        match (state.observed, state.definition.advertise_if) {
            (ConditionObservation::Unknown, _) => None,
            (ConditionObservation::Present, ConditionalAdvertiseIf::Present)
            | (ConditionObservation::Absent, ConditionalAdvertiseIf::Absent) => {
                Some(AppliedConditionalState::Advertise)
            }
            _ => Some(AppliedConditionalState::Suppress),
        }
    }

    /// Move `applied` to what a known observation implies. `unknown` holds.
    fn apply_observation(
        metrics: &rustbgpd_telemetry::BgpMetrics,
        state: &mut DefinitionState,
        out: &mut Vec<Arc<str>>,
    ) {
        let Some(target) = Self::target(state) else {
            return;
        };
        if state.applied == target {
            return;
        }
        let from = state.applied;
        state.applied = target;
        Self::record_transition(metrics, state, from);
        out.push(Arc::clone(&state.definition.name));
    }

    /// Log and count a change of `applied` from `from` to its current value.
    fn record_transition(
        metrics: &rustbgpd_telemetry::BgpMetrics,
        state: &DefinitionState,
        from: AppliedConditionalState,
    ) {
        info!(
            definition = %state.definition.name,
            from = ?from,
            to = ?state.applied,
            observed = state.observed.label(),
            advertise_if = state.definition.advertise_if.label(),
            "conditional advertisement transition"
        );
        metrics.record_conditional_advertisement_transition(&state.definition.name);
        metrics.set_conditional_advertisement_permitted(
            &state.definition.name,
            state.definition.advertise_if.label(),
            state.applied == AppliedConditionalState::Advertise,
        );
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

    /// Every accepted Adj-RIB-In candidate for `prefix`, including one that
    /// selection skips (one with an invalid service SID): not
    /// `unicast_candidates`, which applies selection eligibility.
    fn condition_candidates<'a>(&'a self, prefix: &'a Prefix) -> impl Iterator<Item = &'a Route> {
        self.unicast_prefix_peers
            .peers(prefix)
            .filter_map(|peer| self.ribs.get(&peer))
            .flat_map(|rib| rib.iter_prefix(prefix))
    }

    /// Any current candidate (received and import-accepted, stale, losing
    /// Add-Path, or locally injected) that satisfies the condition makes it
    /// present. An evaluation error is neither a match nor a miss. Every
    /// prefix is observed, so the per-prefix results can be cached for the
    /// status query; each prefix still stops at its first match.
    fn observe_condition(
        &self,
        definition: &ConditionalAdvertisement,
    ) -> (ConditionObservation, Vec<ConditionObservation>) {
        let conditions: Vec<_> = definition
            .condition_prefixes
            .iter()
            .map(|prefix| self.observe_condition_prefix(definition, prefix))
            .collect();
        let observed = if conditions.contains(&ConditionObservation::Present) {
            ConditionObservation::Present
        } else if conditions.contains(&ConditionObservation::Unknown) {
            ConditionObservation::Unknown
        } else {
            ConditionObservation::Absent
        };
        (observed, conditions)
    }

    /// One condition prefix's observation.
    fn observe_condition_prefix(
        &self,
        definition: &ConditionalAdvertisement,
        prefix: &Prefix,
    ) -> ConditionObservation {
        let mut errored = false;
        for route in self.condition_candidates(prefix) {
            #[cfg(test)]
            self.conditional_advertisements
                .candidate_visits
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let Some(policy) = &definition.condition_policy else {
                return ConditionObservation::Present;
            };
            match self.condition_candidate_verdict(policy, route, true) {
                CandidateVerdict::Match => return ConditionObservation::Present,
                CandidateVerdict::Error(_) => errored = true,
                CandidateVerdict::Miss => {}
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
    fn condition_candidate_verdict(
        &self,
        policy: &PolicyChain,
        route: &Route,
        count_errors: bool,
    ) -> CandidateVerdict {
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
        if let Some(error) = evaluation.eval_error {
            // Live observations count; the explain walk must not skew metrics.
            if count_errors {
                self.metrics
                    .record_policy_eval_error("condition", error.kind.label());
            }
            CandidateVerdict::Error(error)
        } else if evaluation.action == PolicyAction::Permit {
            CandidateVerdict::Match
        } else {
            CandidateVerdict::Miss
        }
    }

    /// Install a complete definition and attachment set (ADR-0137 Decision 6,
    /// as amended: one address-keyed install the gate reads). Returns the
    /// capture that [`Self::handle_restore_conditional_advertisements`]
    /// reinstates on compensation.
    pub(super) fn handle_install_conditional_advertisements(
        &mut self,
        set: ConditionalAdvertisementSet,
    ) -> ConditionalAdvertisementCapture {
        let prior_attachments = self.conditional_advertisements.attachments.clone();
        let prior_definitions = self.conditional_definition_contents();
        let (capture, transitions) = self.install_conditional_advertisements(set.definitions);
        self.conditional_advertisements.attachments = set.attachments;
        self.settle_conditional_advertisement_change(
            &prior_attachments,
            &prior_definitions,
            &transitions,
        );
        capture
    }

    /// Reinstate a captured install: applied state and settle deadlines
    /// stand; peers whose attachments or gate inputs change are resynced.
    pub(super) fn handle_restore_conditional_advertisements(
        &mut self,
        capture: ConditionalAdvertisementCapture,
    ) {
        let prior_attachments = self.conditional_advertisements.attachments.clone();
        let prior_definitions = self.conditional_definition_contents();
        let transitions = self.restore_conditional_advertisements(capture);
        self.settle_conditional_advertisement_change(
            &prior_attachments,
            &prior_definitions,
            &transitions,
        );
    }

    /// Re-observe the definitions whose `condition_policy` references a
    /// swapped dataset, then resync the peers of any applied transition.
    /// Returns the prior state, for a generation that rolls the swap back.
    pub(super) fn handle_reobserve_conditional_advertisement_datasets(
        &mut self,
        datasets: &[String],
    ) -> ConditionalAdvertisementCapture {
        let capture = self.capture_conditional_advertisements();
        let _ = self.reevaluate_conditional_advertisement_datasets(datasets);
        capture
    }

    fn conditional_definition_contents(&self) -> BTreeMap<Arc<str>, Arc<ConditionalAdvertisement>> {
        self.conditional_advertisements
            .definitions
            .iter()
            .map(|(name, state)| (Arc::clone(name), Arc::clone(&state.definition)))
            .collect()
    }

    /// Regroup peers whose attachment presence changed and resync every
    /// registered peer whose gate inputs changed: its attachment list, the
    /// content of an attached definition, or an attached definition's
    /// applied state.
    fn settle_conditional_advertisement_change(
        &mut self,
        prior_attachments: &BTreeMap<IpAddr, Vec<Arc<str>>>,
        prior_definitions: &BTreeMap<Arc<str>, Arc<ConditionalAdvertisement>>,
        transitions: &[Arc<str>],
    ) {
        let current = self.conditional_definition_contents();
        let mut changed: BTreeSet<Arc<str>> = transitions.iter().cloned().collect();
        for name in prior_definitions.keys().chain(current.keys()) {
            if prior_definitions.get(name) != current.get(name) {
                changed.insert(Arc::clone(name));
            }
        }
        let attachments = &self.conditional_advertisements.attachments;
        let mut regroup = Vec::new();
        let mut dirty = BTreeSet::new();
        for peer in prior_attachments.keys().chain(attachments.keys()) {
            let before = prior_attachments.get(peer);
            let after = attachments.get(peer);
            if before.is_some() != after.is_some() {
                regroup.push(*peer);
            }
            if before != after
                || before
                    .into_iter()
                    .chain(after)
                    .flatten()
                    .any(|name| changed.contains(name))
            {
                dirty.insert(*peer);
            }
        }
        dirty.retain(|peer| self.outbound_peers.contains_key(peer));
        if dirty.is_empty() {
            return;
        }
        let mut regrouped = false;
        for peer in regroup {
            if self.update_groups.members.contains_key(&peer) {
                self.recompute_update_group(peer);
                regrouped = true;
            }
        }
        for peer in dirty {
            self.mark_outbound_dirty(peer);
        }
        if regrouped {
            self.distribute_changes_after_advertised_page_advance(
                &std::collections::HashSet::new(),
                &std::collections::HashSet::new(),
            );
        }
    }

    /// Mark every registered peer attached to one of `names` outbound-dirty
    /// (ADR-0137 Decision 4): the bounded resync re-evaluates its whole
    /// Adj-RIB-Out through the gate, so nothing else writes Adj-RIB-Out.
    pub(super) fn mark_conditional_advertisement_peers_dirty(&mut self, names: &[Arc<str>]) {
        if names.is_empty() {
            return;
        }
        let peers: Vec<IpAddr> = self
            .conditional_advertisements
            .attachments
            .iter()
            .filter(|(peer, attached)| {
                self.outbound_peers.contains_key(*peer)
                    && attached.iter().any(|name| names.contains(name))
            })
            .map(|(peer, _)| *peer)
            .collect();
        for peer in peers {
            self.mark_outbound_dirty(peer);
        }
    }

    /// Whether `peer` has any conditional advertisement attached.
    pub(super) fn peer_has_conditional_advertisements(&self, peer: IpAddr) -> bool {
        self.conditional_advertisements
            .attachments
            .contains_key(&peer)
    }

    /// The export gate for `peer`. Live staging gets `None` when nothing is
    /// attached or every attached definition is advertising, so a peer in
    /// steady state evaluates no predicate. Explain always gets the attached
    /// entries, with their condition rendered.
    pub(super) fn conditional_gate(&self, peer: IpAddr, explain: bool) -> Option<ConditionalGate> {
        let names = self.conditional_advertisements.attachments.get(&peer)?;
        let entries: Vec<GateEntry> = names
            .iter()
            .map(|name| {
                let state = self.conditional_advertisements.definitions.get(name);
                GateEntry {
                    name: Arc::clone(name),
                    definition: state.map(|state| Arc::clone(&state.definition)),
                    applied: state.map_or(AppliedConditionalState::Pending, |state| state.applied),
                    condition: if explain {
                        state.map_or_else(
                            || "definition is not installed; failing closed".to_string(),
                            |state| self.explain_condition(state),
                        )
                    } else {
                        String::new()
                    },
                }
            })
            .collect();
        if !explain
            && entries
                .iter()
                .all(|entry| entry.applied == AppliedConditionalState::Advertise)
        {
            return None;
        }
        Some(ConditionalGate { entries })
    }

    /// Explain rendering of the condition behind a definition's applied
    /// state, plus any observation still waiting out `settle_time`.
    fn explain_condition(&self, state: &DefinitionState) -> String {
        let definition = &state.definition;
        let mode = definition.advertise_if;
        let (first_present, condition_error) = self.scan_condition(definition);
        let applied_basis = match state.applied {
            AppliedConditionalState::Pending => None,
            AppliedConditionalState::Advertise => Some(mode),
            AppliedConditionalState::Suppress => Some(match mode {
                ConditionalAdvertiseIf::Present => ConditionalAdvertiseIf::Absent,
                ConditionalAdvertiseIf::Absent => ConditionalAdvertiseIf::Present,
            }),
        };
        let mut detail = match applied_basis {
            None => "pending initial evaluation".to_string(),
            Some(ConditionalAdvertiseIf::Present) => {
                let prefix = first_present.unwrap_or(definition.condition_prefixes[0]);
                format!(
                    "condition prefix {prefix} present (advertise if {})",
                    mode.label()
                )
            }
            Some(ConditionalAdvertiseIf::Absent) => {
                let prefixes = definition
                    .condition_prefixes
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", ");
                let noun = if definition.condition_prefixes.len() == 1 {
                    "prefix"
                } else {
                    "prefixes"
                };
                format!(
                    "condition {noun} {prefixes} absent (advertise if {})",
                    mode.label()
                )
            }
        };
        let applied_label = state.applied.label();
        if state.observed == ConditionObservation::Unknown {
            let (policy, term) = condition_error.map_or_else(
                || ("condition_policy".to_string(), "unknown".to_string()),
                |error| {
                    (
                        error.policy.unwrap_or_else(|| "inline".to_string()),
                        error.term.unwrap_or_else(|| "unnamed".to_string()),
                    )
                },
            );
            let _ = write!(
                detail,
                "; condition unknown: condition_policy {policy} failed in term {term}; holding {applied_label}"
            );
        } else if state.deadline.is_some() {
            let observed = state.observed.label();
            let for_secs = Instant::now()
                .saturating_duration_since(state.observed_since)
                .as_secs();
            let _ = write!(
                detail,
                "; observed {observed} for {for_secs}s, applies after settle_time {}s",
                definition.settle_time.as_secs()
            );
        }
        detail
    }

    /// Explain-only walk of the condition candidates: the first condition
    /// prefix with a matching candidate, and the first evaluation error.
    fn scan_condition(
        &self,
        definition: &ConditionalAdvertisement,
    ) -> (Option<Prefix>, Option<rustbgpd_policy::EvalError>) {
        let mut first_error = None;
        for prefix in &definition.condition_prefixes {
            for route in self.condition_candidates(prefix) {
                let Some(policy) = &definition.condition_policy else {
                    return (Some(*prefix), first_error);
                };
                match self.condition_candidate_verdict(policy, route, false) {
                    CandidateVerdict::Match => return (Some(*prefix), first_error),
                    CandidateVerdict::Error(error) => {
                        first_error.get_or_insert(error);
                    }
                    CandidateVerdict::Miss => {}
                }
            }
        }
        (None, first_error)
    }

    /// Serve `QueryConditionalAdvertisements`: every installed definition in
    /// name order, copied from tracked state. It evaluates no policy and
    /// visits no candidate, so its cost is the size of the install.
    pub(super) fn conditional_advertisement_status(&self) -> Vec<ConditionalAdvertisementStatus> {
        let now = Instant::now();
        let tracker = &self.conditional_advertisements;
        // One pass over the attachments; peers come out in address order.
        let mut attached: BTreeMap<&Arc<str>, Vec<IpAddr>> = BTreeMap::new();
        for (peer, names) in &tracker.attachments {
            for name in names {
                attached.entry(name).or_default().push(*peer);
            }
        }
        tracker
            .definitions
            .values()
            .map(|state| {
                let definition = &state.definition;
                ConditionalAdvertisementStatus {
                    name: Arc::clone(&definition.name),
                    advertise_if: definition.advertise_if,
                    conditions: definition
                        .condition_prefixes
                        .iter()
                        .zip(&state.conditions)
                        .map(|(prefix, observation)| (*prefix, observation.label()))
                        .collect(),
                    observed: state.observed.label(),
                    observed_for: now.saturating_duration_since(state.observed_since),
                    applied: state.applied.label(),
                    settle_time: definition.settle_time,
                    settle_remaining: state
                        .deadline
                        .map(|deadline| deadline.saturating_duration_since(now)),
                    selection_deferred: self.condition_deferred(definition),
                    attached_peers: attached.remove(&definition.name).unwrap_or_default(),
                }
            })
            .collect()
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

/// Gate step name in the explain ladder.
pub(super) const CONDITIONAL_GATE: &str = "conditional_advertisement";

/// One attached definition as the export gate sees it.
pub(super) struct GateEntry {
    name: Arc<str>,
    /// `None` only if an attachment names a definition the install lacks,
    /// which the atomic install rules out; the gate then fails closed.
    definition: Option<Arc<ConditionalAdvertisement>>,
    applied: AppliedConditionalState,
    /// Explain-only rendering of the condition; empty on live paths.
    condition: String,
}

/// The conditional-advertisement gate for one target peer (ADR-0137
/// Decision 4): its attached definitions in configured order.
pub(super) struct ConditionalGate {
    entries: Vec<GateEntry>,
}

/// One candidate's gate outcome.
pub(super) enum ConditionalVerdict<'g> {
    /// No conditional advertisement is attached to the target.
    NotAttached,
    /// No attached definition suppresses the route. Carries the first
    /// advertising definition, which explain names as the permit.
    Pass(Option<&'g GateEntry>),
    /// A non-advertising definition's `advertise_policy` selected the route.
    Suppressed(&'g GateEntry),
    /// A non-advertising definition's `advertise_policy` failed; fail closed.
    EvalError(&'g GateEntry, rustbgpd_policy::EvalError),
}

impl ConditionalGate {
    /// Whether a predicate the gate may evaluate reads the AS-path string.
    pub(super) fn requires_as_path_string(gate: Option<&Self>) -> bool {
        gate.is_some_and(|gate| {
            gate.entries.iter().any(|entry| {
                entry.applied != AppliedConditionalState::Advertise
                    && entry.definition.as_ref().is_some_and(|definition| {
                        definition.advertise_policy.requires_as_path_string()
                    })
            })
        })
    }

    /// Evaluate the gate for one candidate. `ctx` is the export chain's
    /// context: the candidate's source attributes with the target peer's
    /// context. Advertising definitions are never evaluated; only a clean
    /// rejection by every other attached definition passes.
    pub(super) fn evaluate<'g>(
        gate: Option<&'g Self>,
        ctx: &RouteContext<'_>,
    ) -> ConditionalVerdict<'g> {
        let Some(gate) = gate else {
            return ConditionalVerdict::NotAttached;
        };
        for entry in &gate.entries {
            if entry.applied == AppliedConditionalState::Advertise {
                continue;
            }
            let Some(definition) = &entry.definition else {
                return ConditionalVerdict::Suppressed(entry);
            };
            let (_, evaluation) = definition
                .advertise_policy
                .compiled()
                .evaluate_with_attribution(ctx);
            if let Some(error) = evaluation.eval_error {
                return ConditionalVerdict::EvalError(entry, error);
            }
            if evaluation.action == PolicyAction::Permit {
                return ConditionalVerdict::Suppressed(entry);
            }
        }
        ConditionalVerdict::Pass(
            gate.entries
                .iter()
                .find(|entry| entry.applied == AppliedConditionalState::Advertise),
        )
    }
}

impl ConditionalVerdict<'_> {
    /// Suppression is a silent withdraw, never a policy denial.
    pub(super) const fn suppresses(&self) -> bool {
        matches!(self, Self::Suppressed(_) | Self::EvalError(..))
    }

    pub(super) const fn code(&self) -> &'static str {
        match self {
            Self::Suppressed(_) => "conditional_advertisement_suppressed",
            Self::EvalError(..) => "conditional_advertisement_eval_error",
            Self::NotAttached | Self::Pass(_) => CONDITIONAL_GATE,
        }
    }

    pub(super) const fn verdict(&self) -> crate::update::ExportGateVerdict {
        use crate::update::ExportGateVerdict::{NotApplicable, Pass, Stop};
        match self {
            Self::Suppressed(_) | Self::EvalError(..) => Stop,
            Self::Pass(Some(_)) => Pass,
            Self::NotAttached | Self::Pass(None) => NotApplicable,
        }
    }

    pub(super) fn detail(&self) -> String {
        match self {
            Self::NotAttached => "no conditional advertisement attached".to_string(),
            Self::Pass(None) => "route not selected by any attached advertise policy".to_string(),
            Self::Pass(Some(entry)) => format!(
                "conditional advertisement {} permits: {}",
                entry.name, entry.condition
            ),
            Self::Suppressed(entry) => format!(
                "suppressed by conditional advertisement {}: {}",
                entry.name, entry.condition
            ),
            Self::EvalError(entry, error) => format!(
                "suppressed by conditional advertisement {}: advertise_policy {} failed in term {} \
                 (evaluation error); failing closed",
                entry.name,
                error.policy.as_deref().unwrap_or("inline"),
                error.term.as_deref().unwrap_or("unnamed"),
            ),
        }
    }

    /// Explain ladder step for this outcome.
    pub(super) fn step(&self) -> crate::update::ExportGateStep {
        crate::update::ExportGateStep {
            gate: CONDITIONAL_GATE,
            code: self.code(),
            verdict: self.verdict(),
            detail: self.detail(),
        }
    }
}
