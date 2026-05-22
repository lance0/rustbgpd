//! Generationed EVPN runtime model foundation (ADR-0063).
//!
//! This module models the committed runtime snapshot and the
//! coordinator-owned commit gate for mutation commands. The daemon
//! builds the public model from startup-resolved tables; the
//! `EvpnService.ApplyEvpnRuntime` path drives this coordinator to commit
//! narrow live mutation shapes (single L2VNI add/delete, single IP-VRF
//! add/delete, or single Ethernet Segment add), while other shapes fail
//! closed — see issue #210. SIGHUP file-driven EVPN edits remain
//! restart-required.

use std::{collections::BTreeMap, sync::Arc};

use crate::ip_vrf::IpVrfTable;
use crate::{EthernetSegment, EvpnInstanceTable};
use rustbgpd_wire::EthernetSegmentIdentifier;
use thiserror::Error;

const STARTUP_DISABLED_MESSAGE: &str = "startup snapshot active; runtime EVPN mutation disabled";
const COORDINATOR_IDLE_MESSAGE: &str = "runtime EVPN mutation coordinator idle";
const COORDINATOR_IN_PROGRESS_MESSAGE: &str = "runtime EVPN mutation in progress";
const COORDINATOR_COMMITTED_MESSAGE: &str = "runtime EVPN mutation committed";
const COORDINATOR_FAILED_MESSAGE: &str = "runtime EVPN mutation failed";

/// Generation number for the committed EVPN runtime model.
///
/// Generation `1` is the startup snapshot. Future ADR-0063 mutation
/// commands will allocate later generations only after validation
/// succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EvpnRuntimeGeneration(u64);

impl EvpnRuntimeGeneration {
    /// Startup generation. Zero is reserved for "unknown" on wire
    /// surfaces that use proto3 scalar defaults.
    pub const STARTUP: Self = Self(1);

    /// Raw generation value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Next generation value a future coordinator would publish after
    /// a candidate model validates and all required converge actions
    /// are planned.
    #[must_use]
    pub const fn next(self) -> Self {
        Self(self.0.saturating_add(1))
    }
}

/// High-level lifecycle of the committed runtime generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvpnRuntimeLifecycle {
    /// The committed generation is active and no coordinator drain or
    /// activation is in progress.
    Active,
    /// A future mutation has published a generation that is still
    /// activating downstream actors.
    Activating,
    /// A future mutation is draining owned state for a generation.
    Deleting,
    /// A future mutation encountered a retryable/degraded subsystem
    /// condition.
    Degraded,
}

impl EvpnRuntimeLifecycle {
    /// Stable lowercase label for CLI/docs/telemetry-style output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Activating => "activating",
            Self::Deleting => "deleting",
            Self::Degraded => "degraded",
        }
    }
}

/// Runtime mutation state for the coordinator surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvpnRuntimeMutationState {
    /// Mutation commands are not exposed in this foundation slice.
    Disabled,
    /// A future coordinator has no active operation.
    Idle,
    /// A future coordinator is applying an operation.
    InProgress,
    /// A future coordinator's last operation failed and requires
    /// operator attention or retry.
    Failed,
}

impl EvpnRuntimeMutationState {
    /// Stable lowercase label for CLI/docs/telemetry-style output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Idle => "idle",
            Self::InProgress => "in-progress",
            Self::Failed => "failed",
        }
    }
}

/// Immutable committed EVPN runtime model.
///
/// This shares the resolved domain tables that startup already hands
/// to downstream actors, so the read-only foundation does not keep a
/// second deep copy of the L2/IP-VRF model for the daemon lifetime. A
/// future coordinator will publish later generations only after
/// validation and converge planning succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimeModel {
    generation: EvpnRuntimeGeneration,
    lifecycle: EvpnRuntimeLifecycle,
    mutation_state: EvpnRuntimeMutationState,
    instances: Arc<EvpnInstanceTable>,
    ip_vrfs: Arc<IpVrfTable>,
    ethernet_segments: Arc<Vec<EthernetSegment>>,
    message: &'static str,
}

impl EvpnRuntimeModel {
    /// Build the startup runtime model from already-resolved config
    /// tables.
    #[must_use]
    pub fn startup<I, V>(instances: I, ip_vrfs: V, ethernet_segments: Vec<EthernetSegment>) -> Self
    where
        I: Into<Arc<EvpnInstanceTable>>,
        V: Into<Arc<IpVrfTable>>,
    {
        Self {
            generation: EvpnRuntimeGeneration::STARTUP,
            lifecycle: EvpnRuntimeLifecycle::Active,
            mutation_state: EvpnRuntimeMutationState::Disabled,
            instances: instances.into(),
            ip_vrfs: ip_vrfs.into(),
            ethernet_segments: Arc::new(ethernet_segments),
            message: STARTUP_DISABLED_MESSAGE,
        }
    }

    /// Build the startup model for a daemon path that has enabled the
    /// runtime mutation coordinator. The resolved tables are still the
    /// startup generation, but mutation state is `idle` instead of
    /// `disabled` so callers can distinguish a coordinator-backed model
    /// from the read-only foundation surface.
    #[must_use]
    pub fn coordinator_startup<I, V>(
        instances: I,
        ip_vrfs: V,
        ethernet_segments: Vec<EthernetSegment>,
    ) -> Self
    where
        I: Into<Arc<EvpnInstanceTable>>,
        V: Into<Arc<IpVrfTable>>,
    {
        Self {
            generation: EvpnRuntimeGeneration::STARTUP,
            lifecycle: EvpnRuntimeLifecycle::Active,
            mutation_state: EvpnRuntimeMutationState::Idle,
            instances: instances.into(),
            ip_vrfs: ip_vrfs.into(),
            ethernet_segments: Arc::new(ethernet_segments),
            message: COORDINATOR_IDLE_MESSAGE,
        }
    }

    fn from_candidate(
        generation: EvpnRuntimeGeneration,
        candidate: EvpnRuntimeCandidate,
        lifecycle: EvpnRuntimeLifecycle,
        mutation_state: EvpnRuntimeMutationState,
        message: &'static str,
    ) -> Self {
        Self {
            generation,
            lifecycle,
            mutation_state,
            instances: Arc::new(candidate.instances),
            ip_vrfs: Arc::new(candidate.ip_vrfs),
            ethernet_segments: Arc::new(candidate.ethernet_segments),
            message,
        }
    }

    fn with_status(
        &self,
        lifecycle: EvpnRuntimeLifecycle,
        mutation_state: EvpnRuntimeMutationState,
        message: &'static str,
    ) -> Self {
        Self {
            generation: self.generation,
            lifecycle,
            mutation_state,
            instances: self.instances.clone(),
            ip_vrfs: self.ip_vrfs.clone(),
            ethernet_segments: self.ethernet_segments.clone(),
            message,
        }
    }

    /// Current committed generation.
    #[must_use]
    pub const fn generation(&self) -> EvpnRuntimeGeneration {
        self.generation
    }

    /// Current high-level lifecycle.
    #[must_use]
    pub const fn lifecycle(&self) -> EvpnRuntimeLifecycle {
        self.lifecycle
    }

    /// Current mutation state.
    #[must_use]
    pub const fn mutation_state(&self) -> EvpnRuntimeMutationState {
        self.mutation_state
    }

    /// Resolved L2 EVPN instance table for the committed generation.
    #[must_use]
    pub fn instances(&self) -> &EvpnInstanceTable {
        self.instances.as_ref()
    }

    /// Resolved IP-VRF table for the committed generation.
    #[must_use]
    pub fn ip_vrfs(&self) -> &IpVrfTable {
        self.ip_vrfs.as_ref()
    }

    /// Resolved Ethernet Segment bindings for the committed generation.
    #[must_use]
    pub fn ethernet_segments(&self) -> &[EthernetSegment] {
        self.ethernet_segments.as_slice()
    }

    /// Operator-facing runtime status message.
    #[must_use]
    pub fn message(&self) -> &str {
        self.message
    }

    /// Compact operator/API summary of the current committed model.
    #[must_use]
    pub fn snapshot(&self) -> EvpnRuntimeSnapshot {
        EvpnRuntimeSnapshot::from_model(self)
    }

    /// Build a pure mutation plan for a fully validated candidate
    /// model without publishing it.
    ///
    /// The config layer remains responsible for syntactic and
    /// cross-table validation. This method only classifies the
    /// already-typed candidate into add/delete/redefine/unchanged
    /// buckets so a future coordinator can attach drain/replay
    /// actions before committing the next generation.
    #[must_use]
    pub fn plan_candidate(&self, candidate: &EvpnRuntimeCandidate) -> EvpnRuntimePlan {
        EvpnRuntimePlan {
            current_generation: self.generation,
            proposed_generation: self.generation.next(),
            evpn_instances: plan_evpn_instances(self.instances(), candidate.instances()),
            ip_vrfs: plan_ip_vrfs(self.ip_vrfs(), candidate.ip_vrfs()),
            ethernet_segments: plan_ethernet_segments(
                self.ethernet_segments.as_slice(),
                candidate.ethernet_segments(),
            ),
        }
    }
}

/// Fully validated candidate EVPN runtime model.
///
/// Construction accepts already-resolved domain tables. The daemon
/// config layer must call `resolve_evpn_instances`,
/// `resolve_evpn_ip_vrfs`, and `resolve_ethernet_segments` before it
/// creates this value; this type intentionally does not duplicate the
/// TOML parser's validation logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimeCandidate {
    instances: EvpnInstanceTable,
    ip_vrfs: IpVrfTable,
    ethernet_segments: Vec<EthernetSegment>,
}

impl EvpnRuntimeCandidate {
    /// Build a candidate from fully resolved EVPN runtime tables.
    #[must_use]
    pub fn new(
        instances: EvpnInstanceTable,
        ip_vrfs: IpVrfTable,
        ethernet_segments: Vec<EthernetSegment>,
    ) -> Self {
        Self {
            instances,
            ip_vrfs,
            ethernet_segments,
        }
    }

    /// Snapshot the currently committed model as a no-op candidate.
    #[must_use]
    pub fn from_model(model: &EvpnRuntimeModel) -> Self {
        Self {
            instances: model.instances().clone(),
            ip_vrfs: model.ip_vrfs().clone(),
            ethernet_segments: model.ethernet_segments.as_ref().clone(),
        }
    }

    /// Candidate L2 EVPN instances.
    #[must_use]
    pub const fn instances(&self) -> &EvpnInstanceTable {
        &self.instances
    }

    /// Candidate IP-VRF table.
    #[must_use]
    pub const fn ip_vrfs(&self) -> &IpVrfTable {
        &self.ip_vrfs
    }

    /// Candidate Ethernet Segment bindings.
    #[must_use]
    pub fn ethernet_segments(&self) -> &[EthernetSegment] {
        &self.ethernet_segments
    }
}

/// Accepts or rejects the convergence work required before a candidate
/// model may become the committed EVPN runtime generation.
///
/// The first coordinator slice keeps this trait synchronous and domain
/// local so tests can prove the commit gate without daemon actor wiring.
/// Later daemon code can back the trait with command queues that drain
/// and replay IMET, Type 2, Type 5, ES/DF, SVI, and dataplane state.
pub trait EvpnRuntimeConverger {
    /// Queue or perform all convergence required by `plan`.
    ///
    /// Returning `Ok(())` authorizes the coordinator to publish the
    /// candidate as the next committed generation. Returning an error
    /// leaves the previous generation committed.
    ///
    /// # Errors
    /// Returns [`EvpnRuntimeConvergeError`] when downstream convergence
    /// could not be queued safely.
    fn converge(
        &mut self,
        current: &EvpnRuntimeModel,
        candidate: &EvpnRuntimeCandidate,
        plan: &EvpnRuntimePlan,
    ) -> Result<(), EvpnRuntimeConvergeError>;
}

/// Convergence failure reported by a coordinator backend.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{message}")]
pub struct EvpnRuntimeConvergeError {
    message: String,
}

impl EvpnRuntimeConvergeError {
    /// Build a convergence error with an operator-facing reason.
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// Operator-facing failure reason.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// Outcome of a coordinator apply attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvpnRuntimeApplyOutcome {
    /// Candidate matched the committed model; no convergence or new
    /// generation was needed.
    Noop,
    /// Candidate converged and became the committed runtime generation.
    Committed,
}

impl EvpnRuntimeApplyOutcome {
    /// Stable lowercase label for logs/docs/tests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Noop => "noop",
            Self::Committed => "committed",
        }
    }
}

/// Successful coordinator apply result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimeApplyReport {
    /// Whether the candidate was a no-op or committed.
    pub outcome: EvpnRuntimeApplyOutcome,
    /// Plan used for the apply decision.
    pub plan: EvpnRuntimePlan,
    /// Committed generation after the apply attempt.
    pub committed_generation: EvpnRuntimeGeneration,
}

/// Failed coordinator apply result. The prior runtime generation remains
/// committed when this is returned.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("EVPN runtime convergence failed: {source}")]
pub struct EvpnRuntimeApplyError {
    plan: Box<EvpnRuntimePlan>,
    #[source]
    source: EvpnRuntimeConvergeError,
}

impl EvpnRuntimeApplyError {
    fn new(plan: EvpnRuntimePlan, source: EvpnRuntimeConvergeError) -> Self {
        Self {
            plan: Box::new(plan),
            source,
        }
    }

    /// Plan that failed to converge.
    #[must_use]
    pub fn plan(&self) -> &EvpnRuntimePlan {
        &self.plan
    }

    /// Convergence failure reason.
    #[must_use]
    pub const fn converge_error(&self) -> &EvpnRuntimeConvergeError {
        &self.source
    }
}

/// Coordinator-owned EVPN runtime model writer.
///
/// This type is the first ADR-0063 write boundary. It does not expose a
/// public gRPC API and does not mutate daemon actors directly; instead,
/// it proves the state-machine contract that later daemon wiring must
/// use: plan a fully validated candidate, ask a convergence backend to
/// queue all required drain/replay work, and only then publish the next
/// committed generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimeCoordinator {
    model: EvpnRuntimeModel,
    last_failed_plan: Option<EvpnRuntimePlan>,
    last_converge_error: Option<EvpnRuntimeConvergeError>,
}

impl EvpnRuntimeCoordinator {
    /// Build a coordinator over startup-resolved EVPN runtime tables.
    #[must_use]
    pub fn new<I, V>(instances: I, ip_vrfs: V, ethernet_segments: Vec<EthernetSegment>) -> Self
    where
        I: Into<Arc<EvpnInstanceTable>>,
        V: Into<Arc<IpVrfTable>>,
    {
        Self {
            model: EvpnRuntimeModel::coordinator_startup(instances, ip_vrfs, ethernet_segments),
            last_failed_plan: None,
            last_converge_error: None,
        }
    }

    /// Build a coordinator from an existing committed model, enabling
    /// mutation state while preserving the model's generation and tables.
    #[must_use]
    pub fn from_model(model: &EvpnRuntimeModel) -> Self {
        Self {
            model: model.with_status(
                EvpnRuntimeLifecycle::Active,
                EvpnRuntimeMutationState::Idle,
                COORDINATOR_IDLE_MESSAGE,
            ),
            last_failed_plan: None,
            last_converge_error: None,
        }
    }

    /// Current committed runtime model.
    #[must_use]
    pub const fn model(&self) -> &EvpnRuntimeModel {
        &self.model
    }

    /// Current committed runtime snapshot.
    #[must_use]
    pub fn snapshot(&self) -> EvpnRuntimeSnapshot {
        self.model.snapshot()
    }

    /// Plan a fully validated candidate against the committed model.
    #[must_use]
    pub fn plan_candidate(&self, candidate: &EvpnRuntimeCandidate) -> EvpnRuntimePlan {
        self.model.plan_candidate(candidate)
    }

    /// Most recent plan that failed convergence, if any.
    #[must_use]
    pub const fn last_failed_plan(&self) -> Option<&EvpnRuntimePlan> {
        self.last_failed_plan.as_ref()
    }

    /// Most recent convergence error, if any.
    #[must_use]
    pub const fn last_converge_error(&self) -> Option<&EvpnRuntimeConvergeError> {
        self.last_converge_error.as_ref()
    }

    /// Apply a fully validated candidate through the convergence gate.
    ///
    /// # Errors
    /// Returns [`EvpnRuntimeApplyError`] when the convergence backend
    /// rejects the plan. In that case the previous generation remains
    /// committed and the coordinator snapshot reports degraded/failed.
    pub fn apply_candidate<C>(
        &mut self,
        candidate: EvpnRuntimeCandidate,
        converger: &mut C,
    ) -> Result<EvpnRuntimeApplyReport, EvpnRuntimeApplyError>
    where
        C: EvpnRuntimeConverger,
    {
        let current = self.model.clone();
        let plan = current.plan_candidate(&candidate);
        if plan.is_noop() {
            return Ok(EvpnRuntimeApplyReport {
                outcome: EvpnRuntimeApplyOutcome::Noop,
                committed_generation: current.generation(),
                plan,
            });
        }

        self.model = current.with_status(
            EvpnRuntimeLifecycle::Active,
            EvpnRuntimeMutationState::InProgress,
            COORDINATOR_IN_PROGRESS_MESSAGE,
        );

        if let Err(source) = converger.converge(&current, &candidate, &plan) {
            self.model = current.with_status(
                EvpnRuntimeLifecycle::Degraded,
                EvpnRuntimeMutationState::Failed,
                COORDINATOR_FAILED_MESSAGE,
            );
            self.last_failed_plan = Some(plan.clone());
            self.last_converge_error = Some(source.clone());
            return Err(EvpnRuntimeApplyError::new(plan, source));
        }

        let committed_generation = plan.proposed_generation;
        self.model = EvpnRuntimeModel::from_candidate(
            committed_generation,
            candidate,
            EvpnRuntimeLifecycle::Active,
            EvpnRuntimeMutationState::Idle,
            COORDINATOR_COMMITTED_MESSAGE,
        );
        self.last_failed_plan = None;
        self.last_converge_error = None;
        Ok(EvpnRuntimeApplyReport {
            outcome: EvpnRuntimeApplyOutcome::Committed,
            committed_generation,
            plan,
        })
    }
}

/// Add/delete/redefine summary for one keyed EVPN runtime domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimeChangeSet<K> {
    /// Keys present only in the candidate model.
    pub added: Vec<K>,
    /// Keys present only in the committed model.
    pub deleted: Vec<K>,
    /// Keys present in both models but with changed row content.
    pub redefined: Vec<K>,
    /// Keys present in both models with identical row content.
    pub unchanged: Vec<K>,
}

impl<K> Default for EvpnRuntimeChangeSet<K> {
    fn default() -> Self {
        Self {
            added: Vec::new(),
            deleted: Vec::new(),
            redefined: Vec::new(),
            unchanged: Vec::new(),
        }
    }
}

impl<K> EvpnRuntimeChangeSet<K> {
    /// Whether this domain requires any converge work.
    #[must_use]
    pub fn has_changes(&self) -> bool {
        !(self.added.is_empty() && self.deleted.is_empty() && self.redefined.is_empty())
    }
}

/// Pure candidate plan for a future coordinator generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimePlan {
    /// Currently committed generation.
    pub current_generation: EvpnRuntimeGeneration,
    /// Generation that would be committed if the coordinator accepts
    /// this plan and queues every required converge action.
    pub proposed_generation: EvpnRuntimeGeneration,
    /// L2 EVPN instance changes keyed by VNI.
    pub evpn_instances: EvpnRuntimeChangeSet<u32>,
    /// IP-VRF changes keyed by operator-facing name.
    pub ip_vrfs: EvpnRuntimeChangeSet<String>,
    /// Ethernet Segment changes keyed by ESI.
    pub ethernet_segments: EvpnRuntimeChangeSet<EthernetSegmentIdentifier>,
}

impl EvpnRuntimePlan {
    /// True when the candidate is identical to the committed model.
    #[must_use]
    pub fn is_noop(&self) -> bool {
        !(self.evpn_instances.has_changes()
            || self.ip_vrfs.has_changes()
            || self.ethernet_segments.has_changes())
    }
}

/// Compact runtime state exported to gRPC/CLI surfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvpnRuntimeSnapshot {
    /// Committed runtime generation.
    pub generation: EvpnRuntimeGeneration,
    /// Committed generation lifecycle.
    pub lifecycle: EvpnRuntimeLifecycle,
    /// Runtime mutation/coordinator state.
    pub mutation_state: EvpnRuntimeMutationState,
    /// Number of configured L2 EVPN instances.
    pub evpn_instances_count: usize,
    /// Number of configured IP-VRFs.
    pub evpn_ip_vrfs_count: usize,
    /// Number of configured Ethernet Segments.
    pub ethernet_segments_count: usize,
    /// Total `(ES, member VNI)` bindings across Ethernet Segments.
    pub ethernet_segment_member_vnis_count: usize,
    /// Operator-facing summary.
    pub message: &'static str,
}

impl EvpnRuntimeSnapshot {
    /// Build a snapshot from a committed runtime model.
    #[must_use]
    pub fn from_model(model: &EvpnRuntimeModel) -> Self {
        Self {
            generation: model.generation,
            lifecycle: model.lifecycle,
            mutation_state: model.mutation_state,
            evpn_instances_count: model.instances.len(),
            evpn_ip_vrfs_count: model.ip_vrfs.len(),
            ethernet_segments_count: model.ethernet_segments.len(),
            ethernet_segment_member_vnis_count: model
                .ethernet_segments
                .iter()
                .map(|segment| segment.member_vnis.len())
                .sum(),
            message: model.message,
        }
    }

    /// Build a startup snapshot directly from resolved tables. Useful
    /// for legacy constructors that do not yet own a runtime model.
    #[must_use]
    pub fn startup_from_tables(
        instances: &EvpnInstanceTable,
        ip_vrfs: &IpVrfTable,
        ethernet_segments: &[EthernetSegment],
    ) -> Self {
        Self {
            generation: EvpnRuntimeGeneration::STARTUP,
            lifecycle: EvpnRuntimeLifecycle::Active,
            mutation_state: EvpnRuntimeMutationState::Disabled,
            evpn_instances_count: instances.len(),
            evpn_ip_vrfs_count: ip_vrfs.len(),
            ethernet_segments_count: ethernet_segments.len(),
            ethernet_segment_member_vnis_count: ethernet_segments
                .iter()
                .map(|segment| segment.member_vnis.len())
                .sum(),
            message: STARTUP_DISABLED_MESSAGE,
        }
    }
}

fn plan_evpn_instances(
    current: &EvpnInstanceTable,
    candidate: &EvpnInstanceTable,
) -> EvpnRuntimeChangeSet<u32> {
    let current = current
        .iter()
        .map(|instance| (instance.id.as_u32(), instance))
        .collect::<BTreeMap<_, _>>();
    let candidate = candidate
        .iter()
        .map(|instance| (instance.id.as_u32(), instance))
        .collect::<BTreeMap<_, _>>();
    diff_keyed_maps(&current, &candidate)
}

fn plan_ip_vrfs(current: &IpVrfTable, candidate: &IpVrfTable) -> EvpnRuntimeChangeSet<String> {
    let current = current
        .iter()
        .map(|vrf| (vrf.name.clone(), vrf))
        .collect::<BTreeMap<_, _>>();
    let candidate = candidate
        .iter()
        .map(|vrf| (vrf.name.clone(), vrf))
        .collect::<BTreeMap<_, _>>();
    diff_keyed_maps(&current, &candidate)
}

fn plan_ethernet_segments(
    current: &[EthernetSegment],
    candidate: &[EthernetSegment],
) -> EvpnRuntimeChangeSet<EthernetSegmentIdentifier> {
    let current = current
        .iter()
        .map(|segment| (segment.esi, segment))
        .collect::<BTreeMap<_, _>>();
    let candidate = candidate
        .iter()
        .map(|segment| (segment.esi, segment))
        .collect::<BTreeMap<_, _>>();
    diff_keyed_maps(&current, &candidate)
}

fn diff_keyed_maps<K, V>(
    current: &BTreeMap<K, &V>,
    candidate: &BTreeMap<K, &V>,
) -> EvpnRuntimeChangeSet<K>
where
    K: Ord + Clone,
    V: PartialEq,
{
    let mut out = EvpnRuntimeChangeSet::default();
    for (key, current_value) in current {
        match candidate.get(key) {
            None => out.deleted.push(key.clone()),
            Some(candidate_value) if *candidate_value == *current_value => {
                out.unchanged.push(key.clone());
            }
            Some(_) => out.redefined.push(key.clone()),
        }
    }
    for key in candidate.keys() {
        if !current.contains_key(key) {
            out.added.push(key.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ip_vrf::{IpVrf, IpVrfId};
    use crate::{DfAlgorithm, EvpnInstance, EvpnInstanceId, RouteTarget};
    use rustbgpd_wire::{EthernetSegmentIdentifier, MacAddress, RouteDistinguisher};

    fn instance(vni: u32, rd: &str, rt: &str) -> EvpnInstance {
        EvpnInstance::new(
            EvpnInstanceId::new(vni).unwrap(),
            rd.parse::<RouteDistinguisher>().unwrap(),
            vec![rt.parse::<RouteTarget>().unwrap()],
            "10.0.0.1".parse().unwrap(),
            None,
            false,
        )
        .unwrap()
    }

    fn instance_table(instances: Vec<EvpnInstance>) -> EvpnInstanceTable {
        let mut table = EvpnInstanceTable::new();
        for instance in instances {
            table.insert(instance).unwrap();
        }
        table
    }

    fn ip_vrf(name: &str, vni: u32, rd: &str, rt: &str, table_id: u32) -> IpVrf {
        IpVrf::new(
            name.to_string(),
            IpVrfId::new(vni).unwrap(),
            rd.parse::<RouteDistinguisher>().unwrap(),
            vec![rt.parse::<RouteTarget>().unwrap()],
            "10.0.0.1".parse().unwrap(),
            MacAddress::new([0x02, 0, 0, 0, 0, 1]),
            format!("vrf-{name}"),
            format!("vxl-{name}"),
            table_id,
        )
        .unwrap()
    }

    fn ip_vrf_table(vrfs: Vec<IpVrf>) -> IpVrfTable {
        let mut table = IpVrfTable::new();
        for vrf in vrfs {
            table.insert(vrf).unwrap();
        }
        table
    }

    fn segment(member_vnis: &[u32]) -> EthernetSegment {
        segment_with_esi([3, 0, 0, 0, 0, 0, 0, 0, 0, 1], member_vnis)
    }

    fn segment_with_esi(esi: [u8; 10], member_vnis: &[u32]) -> EthernetSegment {
        EthernetSegment {
            esi: EthernetSegmentIdentifier::new(esi),
            member_vnis: member_vnis
                .iter()
                .map(|vni| EvpnInstanceId::new(*vni).unwrap())
                .collect(),
            df_preference: 32_768,
            df_algorithm: DfAlgorithm::DefaultModulo,
            redundancy_mode: crate::RedundancyMode::AllActive,
            originator_ip: "10.0.0.1".parse().unwrap(),
        }
    }

    #[test]
    fn startup_model_reports_generation_one_active_disabled_mutation() {
        let model =
            EvpnRuntimeModel::startup(EvpnInstanceTable::new(), IpVrfTable::new(), Vec::new());

        assert_eq!(model.generation(), EvpnRuntimeGeneration::STARTUP);
        assert_eq!(model.generation().as_u64(), 1);
        assert_eq!(model.lifecycle(), EvpnRuntimeLifecycle::Active);
        assert_eq!(model.lifecycle().as_str(), "active");
        assert_eq!(model.mutation_state(), EvpnRuntimeMutationState::Disabled);
        assert_eq!(model.mutation_state().as_str(), "disabled");
    }

    #[test]
    fn snapshot_counts_tables_and_es_member_bindings() {
        let segments = vec![segment(&[100, 200]), segment(&[300])];
        let snapshot = EvpnRuntimeSnapshot::startup_from_tables(
            &EvpnInstanceTable::new(),
            &IpVrfTable::new(),
            &segments,
        );

        assert_eq!(snapshot.generation.as_u64(), 1);
        assert_eq!(snapshot.evpn_instances_count, 0);
        assert_eq!(snapshot.evpn_ip_vrfs_count, 0);
        assert_eq!(snapshot.ethernet_segments_count, 2);
        assert_eq!(snapshot.ethernet_segment_member_vnis_count, 3);
        assert_eq!(
            snapshot.message,
            "startup snapshot active; runtime EVPN mutation disabled"
        );
    }

    #[test]
    fn model_snapshot_matches_owned_tables() {
        let ip_vrfs = IpVrfTable::new();
        assert!(ip_vrfs.is_empty());
        // Exercise the concrete table type in this module without
        // needing a full IP-VRF fixture. The runtime model shares it
        // and reports through the same table API.
        assert!(IpVrfId::new(5000).is_ok());

        let model =
            EvpnRuntimeModel::startup(EvpnInstanceTable::new(), ip_vrfs, vec![segment(&[100])]);
        let snapshot = model.snapshot();

        assert_eq!(snapshot.lifecycle, EvpnRuntimeLifecycle::Active);
        assert_eq!(snapshot.mutation_state, EvpnRuntimeMutationState::Disabled);
        assert_eq!(snapshot.ethernet_segments_count, 1);
        assert_eq!(snapshot.ethernet_segment_member_vnis_count, 1);
    }

    #[test]
    fn no_op_candidate_keeps_generation_preview_but_has_no_changes() {
        let model = EvpnRuntimeModel::startup(
            instance_table(vec![instance(100, "65000:100", "65000:100")]),
            ip_vrf_table(vec![ip_vrf("blue", 5000, "65000:5000", "65000:5000", 5000)]),
            vec![segment(&[100])],
        );
        let candidate = EvpnRuntimeCandidate::from_model(&model);
        let plan = model.plan_candidate(&candidate);

        assert_eq!(plan.current_generation.as_u64(), 1);
        assert_eq!(plan.proposed_generation.as_u64(), 2);
        assert!(plan.is_noop());
        assert_eq!(model.generation().as_u64(), 1);
        assert_eq!(model.snapshot().evpn_instances_count, 1);
    }

    #[test]
    fn plan_classifies_l2_add_delete_redefine_and_unchanged() {
        let current = EvpnRuntimeModel::startup(
            instance_table(vec![
                instance(100, "65000:100", "65000:100"),
                instance(200, "65000:200", "65000:200"),
                instance(300, "65000:300", "65000:300"),
            ]),
            IpVrfTable::new(),
            Vec::new(),
        );
        let candidate = EvpnRuntimeCandidate::new(
            instance_table(vec![
                instance(100, "65000:100", "65000:101"),
                instance(300, "65000:300", "65000:300"),
                instance(400, "65000:400", "65000:400"),
            ]),
            IpVrfTable::new(),
            Vec::new(),
        );

        let plan = current.plan_candidate(&candidate);

        assert!(!plan.is_noop());
        assert_eq!(plan.evpn_instances.added, vec![400]);
        assert_eq!(plan.evpn_instances.deleted, vec![200]);
        assert_eq!(plan.evpn_instances.redefined, vec![100]);
        assert_eq!(plan.evpn_instances.unchanged, vec![300]);
    }

    #[test]
    fn plan_tracks_ip_vrf_and_ethernet_segment_changes() {
        let esi_a = EthernetSegmentIdentifier::new([3, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let esi_b = EthernetSegmentIdentifier::new([3, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        let current = EvpnRuntimeModel::startup(
            instance_table(vec![instance(100, "65000:100", "65000:100")]),
            ip_vrf_table(vec![ip_vrf("blue", 5000, "65000:5000", "65000:5000", 5000)]),
            vec![segment_with_esi(esi_a.octets(), &[100])],
        );
        let candidate = EvpnRuntimeCandidate::new(
            instance_table(vec![instance(100, "65000:100", "65000:100")]),
            ip_vrf_table(vec![
                ip_vrf("blue", 5000, "65000:5000", "65000:5001", 5000),
                ip_vrf("green", 6000, "65000:6000", "65000:6000", 6000),
            ]),
            vec![
                segment_with_esi(esi_a.octets(), &[100, 200]),
                segment_with_esi(esi_b.octets(), &[100]),
            ],
        );

        let plan = current.plan_candidate(&candidate);

        assert_eq!(plan.ip_vrfs.added, vec!["green".to_string()]);
        assert!(plan.ip_vrfs.deleted.is_empty());
        assert_eq!(plan.ip_vrfs.redefined, vec!["blue".to_string()]);
        assert_eq!(plan.ethernet_segments.added, vec![esi_b]);
        assert!(plan.ethernet_segments.deleted.is_empty());
        assert_eq!(plan.ethernet_segments.redefined, vec![esi_a]);
    }

    #[derive(Default)]
    struct RecordingConverger {
        calls: usize,
        fail: Option<EvpnRuntimeConvergeError>,
        observed_current_generation: Vec<u64>,
        observed_added_vnis: Vec<Vec<u32>>,
        observed_candidate_counts: Vec<usize>,
    }

    impl EvpnRuntimeConverger for RecordingConverger {
        fn converge(
            &mut self,
            current: &EvpnRuntimeModel,
            candidate: &EvpnRuntimeCandidate,
            plan: &EvpnRuntimePlan,
        ) -> Result<(), EvpnRuntimeConvergeError> {
            self.calls += 1;
            self.observed_current_generation
                .push(current.generation().as_u64());
            self.observed_added_vnis
                .push(plan.evpn_instances.added.clone());
            self.observed_candidate_counts
                .push(candidate.instances().len());
            if let Some(error) = &self.fail {
                return Err(error.clone());
            }
            Ok(())
        }
    }

    #[test]
    fn coordinator_startup_enables_idle_mutation_state() {
        let coordinator =
            EvpnRuntimeCoordinator::new(EvpnInstanceTable::new(), IpVrfTable::new(), Vec::new());

        let snapshot = coordinator.snapshot();

        assert_eq!(snapshot.generation.as_u64(), 1);
        assert_eq!(snapshot.lifecycle, EvpnRuntimeLifecycle::Active);
        assert_eq!(snapshot.mutation_state, EvpnRuntimeMutationState::Idle);
        assert_eq!(snapshot.message, COORDINATOR_IDLE_MESSAGE);
    }

    #[test]
    fn coordinator_noop_candidate_does_not_call_converger_or_advance_generation() {
        let mut coordinator = EvpnRuntimeCoordinator::new(
            instance_table(vec![instance(100, "65000:100", "65000:100")]),
            IpVrfTable::new(),
            Vec::new(),
        );
        let candidate = EvpnRuntimeCandidate::from_model(coordinator.model());
        let mut converger = RecordingConverger {
            fail: Some(EvpnRuntimeConvergeError::new("should not be called")),
            ..RecordingConverger::default()
        };

        let report = coordinator
            .apply_candidate(candidate, &mut converger)
            .expect("no-op candidate should not require convergence");

        assert_eq!(report.outcome, EvpnRuntimeApplyOutcome::Noop);
        assert_eq!(report.outcome.as_str(), "noop");
        assert!(report.plan.is_noop());
        assert_eq!(report.committed_generation.as_u64(), 1);
        assert_eq!(coordinator.snapshot().generation.as_u64(), 1);
        assert_eq!(
            coordinator.snapshot().mutation_state,
            EvpnRuntimeMutationState::Idle
        );
        assert!(coordinator.last_failed_plan().is_none());
        assert!(coordinator.last_converge_error().is_none());
        assert_eq!(converger.calls, 0);
    }

    #[test]
    fn coordinator_commits_candidate_only_after_converger_accepts_plan() {
        let mut coordinator = EvpnRuntimeCoordinator::new(
            instance_table(vec![instance(100, "65000:100", "65000:100")]),
            IpVrfTable::new(),
            Vec::new(),
        );
        let candidate = EvpnRuntimeCandidate::new(
            instance_table(vec![
                instance(100, "65000:100", "65000:100"),
                instance(200, "65000:200", "65000:200"),
            ]),
            IpVrfTable::new(),
            Vec::new(),
        );
        let mut converger = RecordingConverger::default();

        let report = coordinator
            .apply_candidate(candidate, &mut converger)
            .expect("accepted convergence should commit the candidate");

        assert_eq!(report.outcome, EvpnRuntimeApplyOutcome::Committed);
        assert_eq!(report.outcome.as_str(), "committed");
        assert_eq!(report.committed_generation.as_u64(), 2);
        assert_eq!(report.plan.evpn_instances.added, vec![200]);
        assert_eq!(coordinator.model().generation().as_u64(), 2);
        assert_eq!(coordinator.model().instances().len(), 2);
        assert_eq!(
            coordinator.snapshot().mutation_state,
            EvpnRuntimeMutationState::Idle
        );
        assert_eq!(
            coordinator.snapshot().message,
            COORDINATOR_COMMITTED_MESSAGE
        );
        assert_eq!(converger.calls, 1);
        assert_eq!(converger.observed_current_generation, vec![1]);
        assert_eq!(converger.observed_added_vnis, vec![vec![200]]);
        assert_eq!(converger.observed_candidate_counts, vec![2]);
        assert!(coordinator.last_failed_plan().is_none());
        assert!(coordinator.last_converge_error().is_none());
    }

    #[test]
    fn coordinator_failure_keeps_prior_generation_and_surfaces_failed_state() {
        let mut coordinator = EvpnRuntimeCoordinator::new(
            instance_table(vec![instance(100, "65000:100", "65000:100")]),
            IpVrfTable::new(),
            Vec::new(),
        );
        let candidate = EvpnRuntimeCandidate::new(
            instance_table(vec![
                instance(100, "65000:100", "65000:100"),
                instance(200, "65000:200", "65000:200"),
            ]),
            IpVrfTable::new(),
            Vec::new(),
        );
        let mut converger = RecordingConverger {
            fail: Some(EvpnRuntimeConvergeError::new("IMET command queue closed")),
            ..RecordingConverger::default()
        };

        let error = coordinator
            .apply_candidate(candidate, &mut converger)
            .expect_err("failed convergence should reject the candidate");

        assert_eq!(
            error.converge_error().message(),
            "IMET command queue closed"
        );
        assert_eq!(error.plan().evpn_instances.added, vec![200]);
        assert_eq!(coordinator.model().generation().as_u64(), 1);
        assert_eq!(coordinator.model().instances().len(), 1);
        assert_eq!(
            coordinator.snapshot().lifecycle,
            EvpnRuntimeLifecycle::Degraded
        );
        assert_eq!(
            coordinator.snapshot().mutation_state,
            EvpnRuntimeMutationState::Failed
        );
        assert_eq!(coordinator.snapshot().message, COORDINATOR_FAILED_MESSAGE);
        assert_eq!(
            coordinator
                .last_failed_plan()
                .expect("failed plan retained")
                .evpn_instances
                .added,
            vec![200]
        );
        assert_eq!(
            coordinator
                .last_converge_error()
                .expect("converge error retained")
                .message(),
            "IMET command queue closed"
        );
        assert_eq!(converger.calls, 1);
    }
}
